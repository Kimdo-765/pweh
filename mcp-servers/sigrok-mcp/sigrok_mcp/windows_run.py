"""sigrok 정보 조회의 고정 사본·환경·계획. Windows 프로그램을 직접 실행하지 않는다.

소유 owner가 child 종료를 확인한 뒤에만 release_run을 호출한다. 이름이 바뀌거나
실행 중 미등록 파일이 생기면 임의로 지우지 않고 내부 handle을 남긴다.
"""
from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import math
import os
from pathlib import Path
import re
import stat
import threading
import time
import uuid

from pweh import safeio, windows_bundle as WB
from pweh.errors import DeviceError
from pweh.wininterop import validate_windows_path

RELEASE_ID = "sigrok-cli-0.7.2-win64-selected"
MAX_ENV_BYTES = 256 << 10
MAX_ENV_ITEMS = 1024
MAX_PATH_BYTES = 8192
_TOKEN = object()
_LOCK = threading.Lock()
_RUNS: dict[Path, _Record] = {}
_ENV_KEY = re.compile(r"[A-Za-z_][A-Za-z0-9_]*\Z")
# 무장치 수용 시험에서 관찰한 빈 경로만 미리 만든다. 실행 후 추가 항목을 허용하지 않는다.
_ENV_DIRS = ("empty", "empty/Microsoft", "empty/Microsoft/Windows", "empty/Microsoft/Windows/Caches")


class WindowsRunError(DeviceError):
    """부분 생성 handle은 내부에만 보존하고 경로·하위 예외는 공개하지 않는다."""
    code = "sigrok_run_failed"

    def __init__(self, code="sigrok_run_failed", prepared_run=None):
        super().__init__("sigrok Windows 실행 사본 또는 입력 검증을 완료하지 못했습니다.", code=code)
        self.prepared_run = prepared_run


def _fail(code="sigrok_run_invalid"):
    raise WindowsRunError(code) from None


def _end(deadline):
    if type(deadline) not in (int, float):
        _fail()
    try:
        value = float(deadline)
    except (OverflowError, ValueError):
        _fail()
    if not math.isfinite(value):
        _fail()
    end = min(value, time.monotonic() + 45.0)
    _tick(end)
    return end


def _tick(end, cancel=None):
    if cancel is not None:
        try:
            answer = cancel()
        except BaseException:
            _fail("sigrok_run_cancel_failed")
        if type(answer) is not bool:
            _fail("sigrok_run_cancel_failed")
        if answer:
            _fail("sigrok_run_cancelled")
    if time.monotonic() >= end:
        _fail("sigrok_run_timeout")


def _identity(st):
    return st.st_dev, st.st_ino, st.st_mode, st.st_nlink, st.st_size, st.st_mtime_ns, st.st_ctime_ns


def _inode(st):
    return st.st_dev, st.st_ino, stat.S_IFMT(st.st_mode)


def _local(value):
    if not isinstance(value, Path):
        _fail()
    raw = str(value)
    if (not value.is_absolute() or raw.startswith("//") or ".." in value.parts
            or len(os.fsencode(raw)) > MAX_PATH_BYTES or "\\" in raw
            or any(ord(c) < 32 or 127 <= ord(c) <= 159 for c in raw)):
        _fail()
    return value


@dataclass
class _Entry:
    path: str
    fd: int | None
    observed: object | None


@dataclass
class _Record:
    root: Path
    parent_fd: int
    parent_stat: object
    entries: dict[str, _Entry] = field(default_factory=dict)
    prepared: object = None
    sealed: bool = False
    tainted: bool = False
    released: bool = False
    lock: object = field(default_factory=threading.Lock)
    token: object = field(default=_TOKEN, repr=False)


@dataclass(frozen=True)
class PreparedRun:
    """등록 payload와 고정 환경 트리. empty 이름은 기존 내부 API와의 호환을 유지한다."""
    root: Path
    payload: Path
    empty: Path
    image: Path
    windows_image: str
    env_items: tuple[tuple[str, str], ...]
    source_bundle: WB.VerifiedWindowsBundle
    copy_bundle: WB.VerifiedWindowsBundle
    _record: object = field(repr=False, compare=False)

    @property
    def cwd(self):
        return self.empty


@dataclass(frozen=True)
class SigrokCommandPlan:
    argv: tuple[str, ...]
    launch: object
    cwd: Path
    env_items: tuple[tuple[str, str], ...]


def _record(value):
    if type(value) is PreparedRun:
        record = value._record
        if type(record) is not _Record or record.prepared is not value:
            _fail()
    elif type(value) is _Record:
        record = value
    else:
        _fail()
    if record.token is not _TOKEN:
        _fail()
    if not record.released:
        with _LOCK:
            if _RUNS.get(record.root) is not record:
                _fail()
    return record


def _parent(entry, record):
    parent, _, name = entry.path.rpartition("/")
    if not entry.path:
        return record.parent_fd, record.root.name
    return record.entries[parent].fd, name


def _directory(record, path, end, cancel):
    _tick(end, cancel)
    parent, _, name = path.rpartition("/")
    pfd = record.parent_fd if not path else record.entries[parent].fd
    name = record.root.name if not path else name
    os.mkdir(name, 0o700, dir_fd=pfd)
    # mkdir 뒤 open 실패도 소유 경로를 잊지 않는다. inode 미확인은 삭제하지 않는다.
    entry = _Entry(path, None, None)
    record.entries[path] = entry
    entry.observed = os.stat(name, dir_fd=pfd, follow_symlinks=False)
    entry.fd = os.open(name, safeio.DIR_FLAGS, dir_fd=pfd)
    if (_inode(os.fstat(entry.fd)) != _inode(entry.observed)
            or _inode(os.stat(name, dir_fd=pfd, follow_symlinks=False)) != _inode(entry.observed)
            or not stat.S_ISDIR(entry.observed.st_mode)):
        _fail("sigrok_run_changed")


def _file(record, row, source, end, cancel):
    path = "payload/" + row.path
    parent, _, name = path.rpartition("/")
    pfd = record.entries[parent].fd
    with WB.open_verified_file(source, row.path, deadline=min(end, time.monotonic() + 45), cancel=cancel) as src:
        fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=pfd)
        entry = _Entry(path, fd, None)
        record.entries[path] = entry
        try:
            entry.observed = os.fstat(fd)
            digest, total = hashlib.sha256(), 0
            while total < row.size:
                _tick(end, cancel)
                chunk = os.read(src, min(1 << 20, row.size - total))
                if not chunk:
                    _fail("sigrok_run_changed")
                digest.update(chunk)
                view = memoryview(chunk)
                while view:
                    _tick(end, cancel)
                    count = os.write(fd, view)
                    if count <= 0:
                        _fail("sigrok_run_failed")
                    view = view[count:]
                total += len(chunk)
            if os.read(src, 1) or digest.hexdigest() != row.sha256:
                _fail("sigrok_run_changed")
            os.fchmod(fd, 0o555 if row.path == "sigrok-cli.exe" else 0o444)
            os.fsync(fd)
        finally:
            # write/chmod 실패로 생긴 자기 inode도 부분 handle에 남긴다.
            entry.observed = os.fstat(fd)
            os.close(fd)
            entry.fd = None


def _ambient(values):
    if type(values) is not tuple or len(values) > MAX_ENV_ITEMS:
        _fail("sigrok_run_limit")
    env, seen, total = {}, set(), 0
    for pair in values:
        if type(pair) is not tuple or len(pair) != 2:
            _fail()
        key, value = pair
        if (type(key) is not str or type(value) is not str or _ENV_KEY.fullmatch(key) is None
                or len(key) > 256 or "\x00" in value):
            _fail()
        try:
            total += len(key.encode("utf-8")) + len(value.encode("utf-8")) + 2
        except UnicodeError:
            _fail()
        if total > MAX_ENV_BYTES:
            _fail("sigrok_run_limit")
        lower = key.lower()
        if lower in seen:
            _fail()
        seen.add(lower)
        if (lower.startswith(("python", "sigrok", "xdg_", "ld_"))
                or lower in {"wslenv", "home", "userprofile", "appdata", "localappdata"}):
            continue
        env[key] = value
    return env


def _environment(record, converter, ambient, end, cancel):
    if not callable(converter):
        _fail()
    env = _ambient(ambient)
    cache, reverse = {}, {}

    def convert(path):
        if path not in cache:
            _tick(end, cancel)
            try:
                raw = converter(path, min(end, time.monotonic() + 30))
                if type(raw) is bytes:
                    if len(raw) > MAX_PATH_BYTES:
                        _fail("sigrok_run_limit")
                    raw = raw.decode("utf-8", "strict")
                if type(raw) is not str or len(raw.encode("utf-8")) > MAX_PATH_BYTES:
                    _fail("sigrok_run_converter")
                if raw.endswith("\r\n"):
                    raw = raw[:-2]
                elif raw.endswith("\n"):
                    raw = raw[:-1]
                value = validate_windows_path(raw)
            except BaseException:
                _fail("sigrok_run_converter")
            _tick(end, cancel)
            key = value.replace("/", "\\")
            if len(key) > 1 and key[1] == ":":
                key = key[0].upper() + key[1:]
            if key in reverse and reverse[key] != path:
                _fail("sigrok_run_converter")
            cache[path], reverse[key] = value, path
        return cache[path]

    root = record.root
    image = convert(root / "payload/sigrok-cli.exe")
    empty = convert(root / "empty")
    fixed = {key: empty for key in ("HOME", "USERPROFILE", "APPDATA", "LOCALAPPDATA", "XDG_DATA_HOME",
                                    "XDG_CONFIG_HOME", "XDG_CACHE_HOME")}
    fixed.update({"XDG_DATA_DIRS": convert(root / "payload/share"),
                  "SIGROKDECODE_DIR": convert(root / "payload/share/libsigrokdecode/decoders"),
                  "SIGROK_FIRMWARE_DIR": convert(root / "payload/share/sigrok-firmware"),
                  "PYTHONHOME": convert(root / "payload"),
                  "PYTHONPATH": convert(root / "payload/python34.zip"),
                  "PYTHONNOUSERSITE": "1", "PYTHONDONTWRITEBYTECODE": "1"})
    env.update(fixed)
    # 값은 이미 Windows 표기다. /p 또는 /l로 다시 경로 변환하지 않는다.
    env["WSLENV"] = ":".join(key + "/w" for key in fixed)
    if sum(len(k.encode("utf-8")) + len(v.encode("utf-8")) + 2 for k, v in env.items()) > MAX_ENV_BYTES:
        _fail("sigrok_run_limit")
    return image, tuple(sorted(env.items()))


def _check_names(record, end, cancel=None, *, sealed=False):
    _tick(end, cancel)
    pfd = safeio._walk_directory(str(record.root.parent), follow_links=False, deadline=end)
    try:
        parent_stat = os.fstat(pfd)
        if (_inode(parent_stat) != _inode(record.parent_stat)
                or parent_stat.st_uid != os.getuid() or stat.S_IMODE(parent_stat.st_mode) != 0o700):
            _fail("sigrok_run_changed")
    finally:
        os.close(pfd)
    expected = {}
    for path in record.entries:
        if path:
            parent, _, name = path.rpartition("/")
            expected.setdefault(parent, set()).add(name)
    for path, entry in record.entries.items():
        _tick(end, cancel)
        if entry.observed is None:
            _fail("sigrok_run_changed")
        pfd, name = _parent(entry, record)
        current = os.stat(name, dir_fd=pfd, follow_symlinks=False)
        if _inode(current) != _inode(entry.observed):
            _fail("sigrok_run_changed")
        if stat.S_ISDIR(current.st_mode):
            if entry.fd is None or _inode(os.fstat(entry.fd)) != _inode(current):
                _fail("sigrok_run_changed")
            if current.st_mode != entry.observed.st_mode:
                _fail("sigrok_run_changed")
            names = set()
            with os.scandir(entry.fd) as rows:
                for row in rows:
                    _tick(end, cancel)
                    if row.name not in expected.get(path, set()):
                        _fail("sigrok_run_changed")
                    names.add(row.name)
            if names != expected.get(path, set()):
                _fail("sigrok_run_changed")
            if sealed and _identity(current) != _identity(entry.observed):
                _fail("sigrok_run_changed")
        elif (current.st_nlink != 1 or _identity(current) != _identity(entry.observed)
              or not stat.S_ISREG(current.st_mode)):
            _fail("sigrok_run_changed")


def prepare_run(bundle, parent, *, path_converter, ambient_env, deadline, cancel=None):
    """기존0700 parent 아래 등록 사본·고정 환경 트리를 만든다. 실패도 부분 handle을 갖는다."""
    record, pfd = None, None
    try:
        end = _end(deadline)
        _tick(end, cancel)
        _ambient(ambient_env)
        if type(bundle) is not WB.VerifiedWindowsBundle or bundle.tool != "sigrok" or bundle.release_id != RELEASE_ID:
            _fail()
        if (bundle.entrypoint != bundle.root / "sigrok-cli.exe"
                or bundle.search_dirs != (bundle.root / "share/libsigrokdecode/decoders", bundle.root / "share/sigrok-firmware")
                or not {"sigrok-cli.exe", "python34.dll", "python34.zip"} <= {row.path for row in bundle.files}):
            _fail()
        WB.revalidate_bundle(bundle, deadline=min(end, time.monotonic() + 45), cancel=cancel)
        parent = _local(parent)
        if parent == bundle.root or bundle.root in parent.parents:
            _fail()
        pfd = safeio._walk_directory(str(parent), follow_links=False, deadline=end)
        observed = os.fstat(pfd)
        if observed.st_uid != os.getuid() or stat.S_IMODE(observed.st_mode) != 0o700:
            _fail()
        root = parent / ("sigrok-info-" + uuid.uuid4().hex)
        record = _Record(root, pfd, observed)
        pfd = None
        with _LOCK:
            _RUNS[root] = record
        _directory(record, "", end, cancel)
        _directory(record, "payload", end, cancel)
        for path in _ENV_DIRS:
            _directory(record, path, end, cancel)
        dirs = {"/".join(row.path.split("/")[:n]) for row in bundle.files
                for n in range(1, len(row.path.split("/")))}
        for path in sorted(dirs, key=lambda v: (v.count("/"), v)):
            _directory(record, "payload/" + path, end, cancel)
        for row in bundle.files:
            _file(record, row, bundle, end, cancel)
        for path, entry in record.entries.items():
            if path == "payload" or (path.startswith("payload/") and entry.fd is not None):
                os.fchmod(entry.fd, 0o555)
                entry.observed = os.fstat(entry.fd)
        _check_names(record, end, cancel)
        WB.revalidate_bundle(bundle, deadline=min(end, time.monotonic() + 45), cancel=cancel)
        copied = WB.verify_payload(root / "payload", "sigrok", RELEASE_ID,
                                   deadline=min(end, time.monotonic() + 45), cancel=cancel)
        image, env_items = _environment(record, path_converter, ambient_env, end, cancel)
        # converter 실행을 포함한 준비 동안 바뀐 사본·부모는 최초 관찰로 승격하지 않는다.
        WB.revalidate_bundle(copied, deadline=min(end, time.monotonic() + 45), cancel=cancel)
        _check_names(record, end, cancel)
        for entry in record.entries.values():
            if entry.fd is not None:
                entry.observed = os.fstat(entry.fd)
        record.sealed = True
        prepared = PreparedRun(root, root / "payload", root / "empty", copied.entrypoint, image,
                               env_items, bundle, copied, record)
        record.prepared = prepared
        return prepared
    except BaseException as exc:
        if pfd is not None:
            os.close(pfd)
        code = exc.code if type(exc) is WindowsRunError else "sigrok_run_failed"
        raise WindowsRunError(code, record) from None


def plan_command(prepared, mode="version"):
    """두 고정 정보 명령의 local argv와 Windows launch만 만든다."""
    record = _record(prepared)
    if record.released or record.tainted or type(prepared) is not PreparedRun:
        _fail()
    if type(mode) is not str or mode not in ("version", "list"):
        _fail()
    from pweh.wininterop_sigrok import SigrokLaunch
    tail = ("--version",) if mode == "version" else ("--list-supported",)
    return SigrokCommandPlan((str(prepared.image), *tail), SigrokLaunch(prepared.windows_image, tail),
                             prepared.cwd, prepared.env_items)


def revalidate_run(prepared, *, deadline, cancel=None):
    """각 child 전후 원본·사본·이름을 다시 확인한다. source 실패가 사본 삭제를 요구하지 않는다."""
    record = _record(prepared)
    try:
        end = _end(deadline)
        if type(prepared) is not PreparedRun or record.released or record.tainted:
            _fail("sigrok_run_changed")
        WB.revalidate_bundle(prepared.source_bundle, deadline=min(end, time.monotonic() + 45), cancel=cancel)
        WB.revalidate_bundle(prepared.copy_bundle, deadline=min(end, time.monotonic() + 45), cancel=cancel)
        _check_names(record, end, cancel, sealed=True)
    except BaseException as exc:
        code = exc.code if type(exc) is WindowsRunError else "sigrok_run_changed"
        raise WindowsRunError(code, record) from None


def release_run(prepared, *, deadline):
    """child 부재를 확인한 owner 전용. 기록한 동일 inode만 정리하고 알 수 없는 항목은 남긴다."""
    record = None
    acquired = False
    try:
        end = _end(deadline)
        record = _record(prepared)
        acquired = record.lock.acquire(timeout=max(0, end - time.monotonic()))
        if not acquired:
            return False
        if record.released:
            return True
        if record.tainted:
            return False
        if record.sealed:
            WB.revalidate_bundle(record.prepared.copy_bundle, deadline=min(end, time.monotonic() + 45))
        _check_names(record, end, sealed=record.sealed)
        # 여기부터는 오직 소유 항목의 역순 제거다. 중간 실패는 남은 항목부터 재개한다.
        record.sealed = False
        for path in sorted(tuple(record.entries), key=lambda v: (v.count("/"), len(v)), reverse=True):
            _tick(end)
            entry = record.entries[path]
            pfd, name = _parent(entry, record)
            current = os.stat(name, dir_fd=pfd, follow_symlinks=False)
            if _inode(current) != _inode(entry.observed):
                _fail("sigrok_run_changed")
            if path:
                # 다른 사람의 parent는 그대로 두고 만든 디렉터리 fd만 정리 가능하게 한다.
                os.fchmod(pfd, 0o700)
                parent_path = path.rpartition("/")[0]
                record.entries[parent_path].observed = os.fstat(pfd)
            if stat.S_ISDIR(current.st_mode):
                if os.listdir(entry.fd):
                    _fail("sigrok_run_changed")
                os.rmdir(name, dir_fd=pfd)
                if entry.fd is not None:
                    os.close(entry.fd)
                    entry.fd = None
            else:
                if _identity(current) != _identity(entry.observed) or current.st_nlink != 1:
                    _fail("sigrok_run_changed")
                if entry.fd is not None:
                    os.close(entry.fd)
                    entry.fd = None
                os.unlink(name, dir_fd=pfd)
            del record.entries[path]
        os.close(record.parent_fd)
        record.parent_fd = -1
        record.released = True
        with _LOCK:
            if _RUNS.get(record.root) is record:
                del _RUNS[record.root]
        return True
    except BaseException:
        # 모르는 추가 파일/변조는 자기 것이라는 이유만으로 삭제하지 않는다.
        return False
    finally:
        if acquired:
            record.lock.release()
