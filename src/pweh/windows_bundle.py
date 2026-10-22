"""등록된 Windows 번들의 정적 검증. 실행·다운로드·환경 탐색은 하지 않는다.

source와 설치본의 byte pin은 같으며 설치 권한만 구분한다. 경로별 fd와 관찰 신원을
대조하지만 동시 writer를 영구 차단하거나 일반 파일 syscall을 강제 중단하지는 않는다.
"""
from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass, field
from functools import wraps
import hashlib
import json
import math
import os
from pathlib import Path
import re
import stat
import time

from . import safeio
from .errors import PwehError

MAX_SECONDS = 45.0
MAX_FILES = 10000
MAX_ENTRIES = 20000
MAX_FILE_BYTES = 64 << 20
MAX_TOTAL_BYTES = 512 << 20
MAX_MANIFEST_BYTES = 2 << 20
MAX_REGISTRY_BYTES = 64 << 10
MAX_RECEIPT_BYTES = 4096
MAX_DEPTH = 32
MAX_PATH_CHARS = 1024
_CHUNK = 1 << 20
_TOOLS = frozenset({"openocd", "sigrok"})
_ID = re.compile(r"[a-z0-9][a-z0-9.-]{0,79}\Z")
_SHA = re.compile(r"[0-9a-f]{64}\Z")
_RESERVED = re.compile(r"(?:CON|PRN|AUX|NUL|CLOCK\$|CONIN\$|CONOUT\$|COM[1-9¹²³]|LPT[1-9¹²³])\Z", re.I)
_TOKEN = object()
KNOWN_LIMITATIONS = frozenset({
    "authenticode_unverified", "system_dll_resolution_unverified", "supplier_checksum_unavailable",
    "python34_signature_decoder_unsupported", "msvcr100_not_bundled", "optional_dlls_inside_python_zip",
    "dependency_licenses_incomplete", "python_zip_crc_unverified", "nsis_installation_semantics_unverified",
})
ERROR_CODES = frozenset({
    "bundle_invalid_argument", "bundle_registry_invalid", "bundle_release_unregistered", "bundle_missing",
    "bundle_receipt_invalid", "bundle_tree_invalid", "bundle_changed", "bundle_limit", "bundle_timeout",
    "bundle_io_failed", "bundle_cancel_failed", "cancelled",
})


class WindowsBundleError(PwehError):
    """입력 경로·JSON 값·OS 오류를 포함하지 않는 닫힌 오류."""

    def __init__(self, code: str = "bundle_tree_invalid"):
        code = code if code in ERROR_CODES else "bundle_tree_invalid"
        super().__init__("Windows 번들의 등록 자료 또는 파일 검증을 완료하지 못했습니다.", code=code)


def _fail(code="bundle_tree_invalid"):
    raise WindowsBundleError(code) from None


def _boundary(fn):
    @wraps(fn)
    def wrapped(*args, **kwargs):
        try:
            return fn(*args, **kwargs)
        except WindowsBundleError:
            raise
        except Exception:
            _fail("bundle_io_failed")
    return wrapped


class _Budget:
    def __init__(self, deadline, cancel=None):
        if type(deadline) not in (int, float) or (cancel is not None and not callable(cancel)):
            _fail("bundle_invalid_argument")
        try:
            value = float(deadline)
        except (OverflowError, ValueError):
            _fail("bundle_invalid_argument")
        if not math.isfinite(value):
            _fail("bundle_invalid_argument")
        self.end = min(value, time.monotonic() + MAX_SECONDS)
        self.cancel = cancel
        self.check()

    def check(self):
        if self.cancel is not None:
            try:
                answer = self.cancel()
            except Exception:
                _fail("bundle_cancel_failed")
            if type(answer) is not bool:
                _fail("bundle_cancel_failed")
            if answer:
                _fail("cancelled")
        if time.monotonic() >= self.end:
            _fail("bundle_timeout")


@dataclass(frozen=True)
class BundleFile:
    path: str
    size: int
    sha256: str


@dataclass(frozen=True)
class RegisteredManifest:
    tool: str
    release_id: str
    manifest_sha256: str
    digest_basis: str
    entrypoint: str
    search_dirs: tuple[str, ...]
    files: tuple[BundleFile, ...]
    total_bytes: int
    known_limitations: tuple[str, ...]
    receipt_bytes: bytes
    _token: object = field(default=None, repr=False, compare=False)


@dataclass(frozen=True)
class BundleReceipt:
    tool: str
    release_id: str
    manifest_sha256: str


@dataclass(frozen=True)
class VerifiedWindowsBundle:
    tool: str
    release_id: str
    manifest_sha256: str
    digest_basis: str
    root: Path
    release_root: Path | None
    entrypoint: Path
    search_dirs: tuple[Path, ...]
    files: tuple[BundleFile, ...]
    files_checked: int
    bytes_checked: int
    known_limitations: tuple[str, ...]
    _snapshots: tuple = field(repr=False, compare=False)
    _release_snapshot: tuple | None = field(repr=False, compare=False)
    _token: object = field(default=None, repr=False, compare=False)


def _canonical(value):
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False) + "\n").encode("utf-8")


def _obj(value, keys, code):
    if type(value) is not dict or set(value) != set(keys):
        _fail(code)
    return value


def _integer(value, maximum, code, minimum=0):
    if type(value) is not int or not minimum <= value <= maximum:
        _fail(code)
    return value


def _text(value, maximum, code):
    if type(value) is not str or not value or len(value) > maximum:
        _fail(code)
    if any(ord(c) < 32 or 127 <= ord(c) <= 159 or 0xD800 <= ord(c) <= 0xDFFF for c in value):
        _fail(code)
    return value


def _identifier(value, code):
    if type(value) is not str or _ID.fullmatch(value) is None:
        _fail(code)
    return value


def _sha(value, code):
    if type(value) is not str or _SHA.fullmatch(value) is None:
        _fail(code)
    return value


def _relative(value, code):
    _text(value, MAX_PATH_CHARS, code)
    parts = value.split("/")
    if len(parts) > MAX_DEPTH:
        _fail(code)
    for part in parts:
        if (not part or part in (".", "..") or part.endswith((".", " "))
                or any(c in part for c in '\\:<>"|?*')
                or _RESERVED.fullmatch(part.split(".", 1)[0].rstrip(" "))):
            _fail(code)
    return value


def _json(raw, maximum, budget, code):
    if type(raw) is not bytes or len(raw) > maximum:
        _fail(code)
    # JSON 해석 전 구조 깊이를 제한한다. 문자열 안의 괄호는 세지 않는다.
    depth = 0
    quoted = escaped = False
    for index, byte in enumerate(raw):
        if index % 4096 == 0:
            budget.check()
        if quoted:
            if escaped:
                escaped = False
            elif byte == 92:
                escaped = True
            elif byte == 34:
                quoted = False
        elif byte == 34:
            quoted = True
        elif byte in (91, 123):
            depth += 1
            if depth > 16:
                _fail(code)
        elif byte in (93, 125):
            depth -= 1
            if depth < 0:
                _fail(code)

    def pairs(rows):
        result = {}
        for key, value in rows:
            if key in result:
                _fail(code)
            result[key] = value
        return result

    def number(value):
        if len(value) > 19:
            _fail(code)
        return int(value)

    def bad_number(value):
        _fail(code)

    try:
        doc = json.loads(raw.decode("utf-8", "strict"), object_pairs_hook=pairs,
                         parse_int=number, parse_float=bad_number, parse_constant=bad_number)
    except (ValueError, UnicodeError, RecursionError):
        _fail(code)
    todo, nodes = [doc], 0
    while todo:
        budget.check()
        value = todo.pop()
        nodes += 1
        if nodes > 100000:
            _fail(code)
        if isinstance(value, dict):
            todo.extend(value.keys())
            todo.extend(value.values())
        elif isinstance(value, list):
            todo.extend(value)
        elif isinstance(value, str) and any(0xD800 <= ord(c) <= 0xDFFF for c in value):
            _fail(code)
    return doc


def _read_registry_bytes():
    return safeio.read_regular(Path(__file__).parent / "data/windows-bundles.json",
                               max_bytes=MAX_REGISTRY_BYTES, reject_hardlinks=True)


def _read_registered_manifest_bytes(relative_name):
    return safeio.read_regular(Path(__file__).parent / "data" / relative_name,
                               max_bytes=MAX_MANIFEST_BYTES, reject_hardlinks=True)


def _registered(tool, release_id, budget):
    code = "bundle_registry_invalid"
    if type(tool) is not str or tool not in _TOOLS:
        _fail("bundle_invalid_argument")
    if release_id is not None:
        _identifier(release_id, "bundle_invalid_argument")
    try:
        raw_index = _read_registry_bytes()
        budget.check()
        index = _obj(_json(raw_index, MAX_REGISTRY_BYTES, budget, code), ("schema_version", "tools"), code)
        _integer(index["schema_version"], 1, code, 1)
        all_tools = _obj(index["tools"], _TOOLS, code)
        selected = None
        for name in sorted(_TOOLS):
            budget.check()
            group = _obj(all_tools[name], ("preferred_release_id", "releases"), code)
            preferred = _identifier(group["preferred_release_id"], code)
            rows = group["releases"]
            if type(rows) is not list or not 1 <= len(rows) <= 16:
                _fail(code)
            seen = set()
            for row in rows:
                _obj(row, ("release_id", "manifest", "sha256"), code)
                rid = _identifier(row["release_id"], code)
                if rid in seen or row["manifest"] != f"windows-bundles/{name}-{rid}.json":
                    _fail(code)
                seen.add(rid)
                _sha(row["sha256"], code)
                if name == tool and rid == (release_id if release_id is not None else preferred):
                    selected = row
            if preferred not in seen:
                _fail(code)
        if selected is None:
            _fail("bundle_release_unregistered")
        raw = _read_registered_manifest_bytes(selected["manifest"])
        budget.check()
    except WindowsBundleError:
        raise
    except Exception:
        _fail(code)
    if type(raw) is not bytes or len(raw) > MAX_MANIFEST_BYTES or hashlib.sha256(raw).hexdigest() != selected["sha256"]:
        _fail(code)
    doc = _obj(_json(raw, MAX_MANIFEST_BYTES, budget, code),
               ("schema_version", "tool", "release_id", "platform", "source", "payload", "files", "known_limitations"), code)
    _integer(doc["schema_version"], 1, code, 1)
    if doc["tool"] != tool or doc["release_id"] != selected["release_id"] or doc["platform"] != "windows-amd64":
        _fail(code)
    source = _obj(doc["source"], ("artifact_url", "artifact_name", "artifact_size", "artifact_sha256",
                                "digest_basis", "checksum_metadata", "extractor"), code)
    for key, maximum in (("artifact_url", 2048), ("artifact_name", 255)):
        _text(source[key], maximum, code)
    if not source["artifact_url"].startswith("https://") or "/" in source["artifact_name"] or "\\" in source["artifact_name"]:
        _fail(code)
    _integer(source["artifact_size"], MAX_TOTAL_BYTES, code, 1)
    _sha(source["artifact_sha256"], code)
    checksum = source["checksum_metadata"]
    if checksum is not None:
        _obj(checksum, ("repository", "ref", "path"), code)
        for key in checksum:
            _text(checksum[key], 2048, code)
        if not checksum["repository"].startswith("https://"):
            _fail(code)
        _relative(checksum["path"], code)
    extractor = source["extractor"]
    if extractor is not None:
        _obj(extractor, ("version", "artifact_url", "artifact_size", "artifact_sha256", "executable_sha256"), code)
        _text(extractor["version"], 64, code)
        if not _text(extractor["artifact_url"], 2048, code).startswith("https://"):
            _fail(code)
        _integer(extractor["artifact_size"], MAX_TOTAL_BYTES, code, 1)
        for key in ("artifact_sha256", "executable_sha256"):
            _sha(extractor[key], code)
    if tool == "openocd":
        if source["digest_basis"] != "supplier-checksum" or checksum is None or extractor is not None:
            _fail(code)
    elif source["digest_basis"] != "first-acquisition" or checksum is not None or extractor is None:
        _fail(code)
    payload = _obj(doc["payload"], ("archive_root", "recipe", "entrypoint", "search_dirs", "python_zip",
                                   "file_count", "total_bytes", "excluded"), code)
    if tool == "openocd":
        if payload["recipe"] != "zip-strip-fixed-root-v1" or not isinstance(payload["archive_root"], str) or not payload["archive_root"].endswith("/"):
            _fail(code)
        _relative(payload["archive_root"][:-1], code)
    elif payload["recipe"] != "nsis-selected-v1" or payload["archive_root"] != "":
        _fail(code)
    excluded = _obj(payload["excluded"], ("installer_plugins", "usb_driver_installers", "example_captures", "uninstaller"), code)
    for count in excluded.values():
        _integer(count, MAX_ENTRIES, code)
    rows = doc["files"]
    if type(rows) is not list or not 1 <= len(rows) <= MAX_FILES:
        _fail(code)
    files, paths, directories, folded = [], set(), set(), {}
    total = 0
    for row in rows:
        budget.check()
        _obj(row, ("path", "size", "sha256"), code)
        path = _relative(row["path"], code)
        size = _integer(row["size"], MAX_FILE_BYTES, code)
        _sha(row["sha256"], code)
        if path in paths or (files and files[-1].path >= path):
            _fail(code)
        paths.add(path)
        pieces = path.split("/")
        directories.update("/".join(pieces[:n]) for n in range(1, len(pieces)))
        files.append(BundleFile(path, size, row["sha256"]))
        total += size
    if paths & directories or len(paths | directories) > MAX_ENTRIES or total > MAX_TOTAL_BYTES:
        _fail(code)
    for path in paths | directories:
        budget.check()
        key = path.casefold()
        if key in folded and folded[key] != path:
            _fail(code)
        folded[key] = path
    _integer(payload["file_count"], MAX_FILES, code, 1)
    _integer(payload["total_bytes"], MAX_TOTAL_BYTES, code)
    if payload["file_count"] != len(files) or payload["total_bytes"] != total:
        _fail(code)
    entry = _relative(payload["entrypoint"], code)
    if entry not in paths or not entry.endswith(".exe"):
        _fail(code)
    search = payload["search_dirs"]
    if type(search) is not list or len(search) > 16 or any(type(x) is not str for x in search):
        _fail(code)
    if len(set(search)) != len(search) or any(x not in directories for x in search):
        _fail(code)
    if payload["python_zip"] is not None and (type(payload["python_zip"]) is not str or payload["python_zip"] not in paths):
        _fail(code)
    limitations = doc["known_limitations"]
    if (type(limitations) is not list or len(limitations) > len(KNOWN_LIMITATIONS)
            or any(type(x) is not str or x not in KNOWN_LIMITATIONS for x in limitations)
            or len(set(limitations)) != len(limitations)):
        _fail(code)
    receipt = {"schema_version": 1, "tool": tool, "release_id": selected["release_id"], "manifest_sha256": selected["sha256"]}
    budget.check()
    return RegisteredManifest(tool, selected["release_id"], selected["sha256"], source["digest_basis"],
                              entry, tuple(search), tuple(files), total, tuple(limitations), _canonical(receipt), _TOKEN)


@_boundary
def load_registered_manifest(tool, release_id=None, *, deadline, cancel=None):
    """패키지의 등록 사슬만 읽는다. payload나 외부 실행기를 조회하지 않는다."""
    return _registered(tool, release_id, _Budget(deadline, cancel))


def _local_root(value):
    if not isinstance(value, (str, Path)):
        _fail("bundle_invalid_argument")
    raw = os.fspath(value)
    _text(raw, 4096, "bundle_invalid_argument")
    if not raw.startswith("/") or len(os.fsencode(raw)) > 4096 or any(x == ".." for x in raw.split("/")):
        _fail("bundle_invalid_argument")
    return Path(raw)


@_boundary
def managed_release_root(tools_root, manifest):
    """관리 경로만 계산한다. 생성·조회·환경 탐색은 하지 않는다."""
    if type(manifest) is not RegisteredManifest or manifest._token is not _TOKEN:
        _fail("bundle_invalid_argument")
    return _local_root(tools_root) / "windows-bundles" / manifest.tool / (manifest.release_id + "-" + manifest.manifest_sha256)


def _identity(st):
    return (st.st_dev, st.st_ino, st.st_mode, st.st_nlink, st.st_size, st.st_mtime_ns, st.st_ctime_ns)


def _open_root(value, budget):
    root = _local_root(value)
    budget.check()
    # 이름이 있는 dangling alias는 선택 설치 없음이 아니다. walk의 ENOENT와 구분한다.
    try:
        os.lstat(root)
        named = True
    except FileNotFoundError:
        named = False
    try:
        fd = safeio._walk_directory(str(root), deadline=budget.end)
    except FileNotFoundError:
        _fail("bundle_tree_invalid" if named else "bundle_missing")
    except safeio.UnsafeFile:
        budget.check()
        _fail("bundle_tree_invalid")
    try:
        real = safeio.fd_real_path(fd)
        if real is None:
            _fail("bundle_io_failed")
        real = _local_root(real)
        budget.check()
        return real, fd
    except BaseException:
        os.close(fd)
        raise


def _directory(fd, name, before, budget):
    budget.check()
    if not stat.S_ISDIR(before.st_mode):
        _fail("bundle_tree_invalid")
    child = os.open(name, safeio.DIR_FLAGS, dir_fd=fd)
    try:
        if _identity(os.fstat(child)) != _identity(before):
            _fail("bundle_changed")
        return child
    except BaseException:
        os.close(child)
        raise


def _file(fd, name, before, budget):
    budget.check()
    if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
        _fail("bundle_tree_invalid")
    opened = os.open(name, safeio.READ_FLAGS, dir_fd=fd)
    try:
        if _identity(os.fstat(opened)) != _identity(before):
            _fail("bundle_changed")
        return opened
    except BaseException:
        os.close(opened)
        raise


def _hash(fd, expected, budget):
    h, left = hashlib.sha256(), expected.size
    while left:
        budget.check()
        data = os.read(fd, min(_CHUNK, left))
        if not data:
            _fail("bundle_changed")
        h.update(data)
        left -= len(data)
    budget.check()
    if os.read(fd, 1) or h.hexdigest() != expected.sha256:
        _fail("bundle_tree_invalid")


def _walk(fd, manifest, budget, *, installed=False, expected=None, hash_files=True):
    files = {row.path: row for row in manifest.files}
    dirs = {""}
    for name in files:
        pieces = name.split("/")
        dirs.update("/".join(pieces[:n]) for n in range(1, len(pieces)))
    snapshots = {}
    count = 0

    def visit(current, prefix):
        nonlocal count
        budget.check()
        initial = _identity(os.fstat(current))
        if installed and stat.S_IMODE(initial[2]) != 0o555:
            _fail("bundle_tree_invalid")
        if expected is not None and expected.get(prefix) != initial:
            _fail("bundle_changed")
        snapshots[prefix] = initial
        with os.scandir(current) as iterator:
            for item in iterator:
                budget.check()
                count += 1
                if count > MAX_ENTRIES:
                    _fail("bundle_limit")
                name = item.name
                path = prefix + "/" + name if prefix else name
                _relative(path, "bundle_tree_invalid")
                st = os.stat(name, dir_fd=current, follow_symlinks=False)
                if path in dirs:
                    child = _directory(current, name, st, budget)
                    try:
                        visit(child, path)
                    finally:
                        os.close(child)
                elif path in files:
                    row = files[path]
                    identity = _identity(st)
                    if st.st_size != row.size:
                        _fail("bundle_tree_invalid")
                    if installed and stat.S_IMODE(st.st_mode) != (0o555 if path == manifest.entrypoint else 0o444):
                        _fail("bundle_tree_invalid")
                    if expected is not None and expected.get(path) != identity:
                        _fail("bundle_changed")
                    opened = _file(current, name, st, budget)
                    try:
                        if hash_files:
                            _hash(opened, row, budget)
                        if _identity(os.fstat(opened)) != identity:
                            _fail("bundle_changed")
                    finally:
                        os.close(opened)
                    snapshots[path] = identity
                else:
                    _fail("bundle_tree_invalid")
                if _identity(os.stat(name, dir_fd=current, follow_symlinks=False)) != _identity(st):
                    _fail("bundle_changed")
        if _identity(os.fstat(current)) != initial:
            _fail("bundle_changed")
        budget.check()

    try:
        visit(fd, "")
    except FileNotFoundError:
        _fail("bundle_changed" if expected is not None else "bundle_tree_invalid")
    if set(snapshots) != set(files) | dirs:
        _fail("bundle_tree_invalid")
    return snapshots


def _check_root(root, identity, budget):
    budget.check()
    try:
        fd = safeio._walk_directory(str(root), follow_links=False, deadline=budget.end)
    except (OSError, PwehError):
        budget.check()
        _fail("bundle_changed")
    try:
        if _identity(os.fstat(fd)) != identity:
            _fail("bundle_changed")
    finally:
        os.close(fd)


def _verified(root, fd, manifest, budget, *, release_root=None, release_snapshot=None):
    snapshots = _walk(fd, manifest, budget, installed=release_root is not None)
    _walk(fd, manifest, budget, installed=release_root is not None, expected=snapshots, hash_files=False)
    _check_root(root, snapshots[""], budget)
    return VerifiedWindowsBundle(manifest.tool, manifest.release_id, manifest.manifest_sha256,
                                 manifest.digest_basis, root, release_root, root / manifest.entrypoint,
                                 tuple(root / p for p in manifest.search_dirs), manifest.files, len(manifest.files),
                                 manifest.total_bytes, manifest.known_limitations, tuple(sorted(snapshots.items())),
                                 release_snapshot, _TOKEN)


@_boundary
def verify_payload(payload_root, tool, release_id=None, *, deadline, cancel=None):
    """receipt 없는 source payload를 exact tree/hash와 신원으로 검증한다."""
    budget = _Budget(deadline, cancel)
    manifest = _registered(tool, release_id, budget)
    root, fd = _open_root(payload_root, budget)
    try:
        return _verified(root, fd, manifest, budget)
    finally:
        os.close(fd)


def _receipt(fd, tool, budget):
    code = "bundle_receipt_invalid"
    if type(tool) is not str or tool not in _TOOLS:
        _fail("bundle_invalid_argument")
    try:
        st = os.stat("release.json", dir_fd=fd, follow_symlinks=False)
        if not stat.S_ISREG(st.st_mode) or st.st_nlink != 1 or st.st_size > MAX_RECEIPT_BYTES:
            _fail(code)
        opened = _file(fd, "release.json", st, budget)
        try:
            raw = os.read(opened, MAX_RECEIPT_BYTES + 1)
            if len(raw) != st.st_size or _identity(os.fstat(opened)) != _identity(st):
                _fail("bundle_changed")
        finally:
            os.close(opened)
        if _identity(os.stat("release.json", dir_fd=fd, follow_symlinks=False)) != _identity(st):
            _fail("bundle_changed")
    except FileNotFoundError:
        _fail(code)
    doc = _obj(_json(raw, MAX_RECEIPT_BYTES, budget, code),
               ("schema_version", "tool", "release_id", "manifest_sha256"), code)
    _integer(doc["schema_version"], 1, code, 1)
    if doc["tool"] != tool:
        _fail(code)
    _identifier(doc["release_id"], code)
    _sha(doc["manifest_sha256"], code)
    manifest = _registered(tool, doc["release_id"], budget)
    if doc["manifest_sha256"] != manifest.manifest_sha256:
        _fail(code)
    return BundleReceipt(tool, manifest.release_id, manifest.manifest_sha256), manifest, _identity(st)


@_boundary
def read_release_receipt(release_root, tool, *, deadline):
    """receipt의 등록 결속만 확인한다. payload 검증 성공으로 쓰지 않는다."""
    budget = _Budget(deadline)
    root, fd = _open_root(release_root, budget)
    try:
        initial = _identity(os.fstat(fd))
        receipt, _, _ = _receipt(fd, tool, budget)
        _check_root(root, initial, budget)
        return receipt
    finally:
        os.close(fd)


@_boundary
def verify_release(release_root, tool, *, deadline, cancel=None):
    """설치본의 정확 release 자식·receipt·payload·고정 권한을 검증한다."""
    budget = _Budget(deadline, cancel)
    root, fd = _open_root(release_root, budget)
    try:
        initial = _identity(os.fstat(fd))
        if stat.S_IMODE(initial[2]) != 0o555:
            _fail("bundle_tree_invalid")
        names = set()
        with os.scandir(fd) as iterator:
            for item in iterator:
                budget.check()
                names.add(item.name)
                if len(names) > 2:
                    _fail("bundle_tree_invalid")
        if names != {"release.json", "payload"}:
            _fail("bundle_receipt_invalid" if "release.json" not in names else "bundle_tree_invalid")
        _, manifest, receipt_st = _receipt(fd, tool, budget)
        if stat.S_IMODE(receipt_st[2]) != 0o444:
            _fail("bundle_receipt_invalid")
        payload_st = os.stat("payload", dir_fd=fd, follow_symlinks=False)
        payload = _directory(fd, "payload", payload_st, budget)
        try:
            result = _verified(root / "payload", payload, manifest, budget, release_root=root,
                               release_snapshot=(initial, receipt_st))
        finally:
            os.close(payload)
        if (_identity(os.stat("release.json", dir_fd=fd, follow_symlinks=False)) != receipt_st
                or _identity(os.stat("payload", dir_fd=fd, follow_symlinks=False)) != _identity(payload_st)):
            _fail("bundle_changed")
        _check_root(root, initial, budget)
        return result
    except FileNotFoundError:
        _fail("bundle_tree_invalid")
    finally:
        os.close(fd)


def _bundle(value):
    if type(value) is not VerifiedWindowsBundle or value._token is not _TOKEN:
        _fail("bundle_invalid_argument")


@contextmanager
def open_verified_file(bundle, relative_path, *, deadline, cancel=None):
    """최초 관찰과 같은 파일 fd를 빌려준다. caller는 닫거나 이름으로 다시 열지 않는다."""
    handles = []
    try:
        _bundle(bundle)
        budget = _Budget(deadline, cancel)
        _relative(relative_path, "bundle_invalid_argument")
        if relative_path not in {row.path for row in bundle.files}:
            _fail("bundle_invalid_argument")
        expected = dict(bundle._snapshots)
        root, fd = _open_root(bundle.root, budget)
        handles.append(fd)
        if root != bundle.root or _identity(os.fstat(fd)) != expected[""]:
            _fail("bundle_changed")
        parts = relative_path.split("/")
        checks = []
        prefix = ""
        for part in parts[:-1]:
            prefix = prefix + "/" + part if prefix else part
            st = os.stat(part, dir_fd=fd, follow_symlinks=False)
            if _identity(st) != expected[prefix]:
                _fail("bundle_changed")
            child = _directory(fd, part, st, budget)
            handles.append(child)
            checks.append((fd, part, child, expected[prefix]))
            fd = child
        st = os.stat(parts[-1], dir_fd=fd, follow_symlinks=False)
        if _identity(st) != expected[relative_path]:
            _fail("bundle_changed")
        opened = _file(fd, parts[-1], st, budget)
        handles.append(opened)
        checks.append((fd, parts[-1], opened, expected[relative_path]))
        try:
            yield opened
        finally:
            budget.check()
            for parent, name, child, identity in checks:
                if (_identity(os.fstat(child)) != identity
                        or _identity(os.stat(name, dir_fd=parent, follow_symlinks=False)) != identity):
                    _fail("bundle_changed")
            _check_root(root, expected[""], budget)
    except WindowsBundleError:
        raise
    except FileNotFoundError:
        _fail("bundle_changed")
    except Exception:
        _fail("bundle_io_failed")
    finally:
        close_failed = False
        for fd in reversed(handles):
            try:
                os.close(fd)
            except OSError:
                close_failed = True
        if close_failed:
            _fail("bundle_io_failed")


@_boundary
def revalidate_bundle(bundle, *, deadline, cancel=None):
    """전체 tree/hash와 최초 관찰 신원을 다시 비교한다. 갱신 snapshot으로 바꾸지 않는다."""
    _bundle(bundle)
    budget = _Budget(deadline, cancel)
    if bundle.release_root is None:
        fresh = verify_payload(bundle.root, bundle.tool, bundle.release_id, deadline=budget.end, cancel=cancel)
    else:
        fresh = verify_release(bundle.release_root, bundle.tool, deadline=budget.end, cancel=cancel)
    if (fresh.manifest_sha256 != bundle.manifest_sha256 or fresh._snapshots != bundle._snapshots
            or fresh.root != bundle.root or fresh._release_snapshot != bundle._release_snapshot):
        _fail("bundle_changed")
    budget.check()
