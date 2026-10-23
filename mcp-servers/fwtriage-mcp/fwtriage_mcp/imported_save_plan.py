"""가져온 원시 세이브의 로컬 계획 사본과 manifest를 같은 FD로 결속한다."""
from __future__ import annotations

import hashlib
import json
import math
import os
import re
import stat
import time
from pathlib import Path

from pweh import espfmt, safeio, schemas
from pweh.errors import PwehError
from pweh.evidence import under_any_case_protected
from pweh.safety.attestations import canonical_json
from . import saves

MAX_INPUT_BYTES = 8 << 20
MAX_MANIFEST_BYTES = 64 << 10
CHUNK = 64 << 10
FINAL_SECONDS = 5.0
SCHEMA = "pweh.imported-save-plan/v1"
PROFILE = "raw-save-local-plan-v1"
FLAGS = ("device_association_verified", "independent_backup_verified", "write_address_verified",
         "write_ready", "device_written", "game_acceptance_verified")
_CODES = frozenset({"imported_save_input_invalid", "imported_save_input_limit", "imported_save_input_changed",
                    "imported_save_no_changes", "imported_save_failed", "imported_save_cleanup_incomplete",
                    "cancelled", "time_limit"})


def _error(code):
    return PwehError("가져온 세이브의 로컬 계획을 완료하지 못했습니다.", code=code)


def _tick(deadline, cancel):
    if cancel is not None:
        try:
            stopped = cancel()
        except Exception:
            raise _error("imported_save_failed") from None
        if stopped:
            raise _error("cancelled")
    if time.monotonic() >= deadline:
        raise _error("time_limit")


def _projection(case, artifact_id: str) -> dict:
    rows = case.load().get("artifacts", [])
    if type(rows) is not list:
        raise _error("imported_save_input_invalid")
    matches = [row for row in rows if type(row) is dict and row.get("id") == artifact_id]
    if len(matches) != 1:
        raise _error("imported_save_input_invalid")
    row = matches[0]
    projected = {key: row.get(key) for key in ("id", "path", "is_dir", "size", "sha256")}
    size, path, digest = projected["size"], projected["path"], projected["sha256"]
    if projected["is_dir"] is not False or type(size) is not int or size < 1:
        raise _error("imported_save_input_invalid")
    if size > MAX_INPUT_BYTES:
        raise _error("imported_save_input_limit")
    if type(digest) is not str or re.fullmatch(r"[0-9a-f]{64}", digest) is None:
        raise _error("imported_save_input_invalid")
    if type(path) is not str or not path or len(os.fsencode(path)) > safeio.PATH_MAX_BYTES:
        raise _error("imported_save_input_invalid")
    if sum(type(item) is dict and item.get("path") == path for item in rows) != 1:
        raise _error("imported_save_input_invalid")
    parts = path.split("/")
    if (len(parts) > safeio.PATH_MAX_STEPS or any(p in ("", ".", "..") or "\x00" in p for p in parts)
            or parts[0] in ("forensics", "emu")):
        raise _error("imported_save_input_invalid")
    return projected


def _file_seal(value) -> tuple:
    return (value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns,
            value.st_ctime_ns, value.st_mode, value.st_nlink)


def _dir_seal(value) -> tuple:
    return value.st_dev, value.st_ino, value.st_mode, value.st_uid


class _Directories:
    """기준 root와 각 하위 부모를 고정한다. 하위 링크를 따라가지 않는다."""

    def __init__(self, case, deadline: float, cancel):
        self.case = case
        self.fds = []
        self.edges = []
        _tick(deadline, cancel)
        fd = safeio._walk_directory(str(case.dir), deadline=deadline)
        self.fds.append(fd)
        try:
            self.root = fd
            self.root_seal = _dir_seal(os.fstat(fd))
            self.check(deadline, cancel)
        except Exception:
            if not self.close():
                raise _error("imported_save_cleanup_incomplete") from None
            raise

    def descend(self, parts: list[str], deadline: float, cancel) -> int:
        fd = self.root
        for name in parts:
            _tick(deadline, cancel)
            before = os.stat(name, dir_fd=fd, follow_symlinks=False)
            if not stat.S_ISDIR(before.st_mode):
                raise _error("imported_save_input_invalid")
            child = os.open(name, safeio.DIR_FLAGS, dir_fd=fd)
            self.fds.append(child)
            after = os.fstat(child)
            if _dir_seal(before) != _dir_seal(after):
                raise _error("imported_save_input_changed")
            self.edges.append((fd, name, child, _dir_seal(after)))
            fd = child
        self.check(deadline, cancel)
        return fd

    def check(self, deadline: float, cancel) -> None:
        _tick(deadline, cancel)
        current = os.stat(self.case.dir, follow_symlinks=False)
        if (not stat.S_ISDIR(current.st_mode) or _dir_seal(current) != self.root_seal
                or _dir_seal(os.fstat(self.root)) != self.root_seal):
            raise _error("imported_save_input_changed")
        for parent, name, child, seal in self.edges:
            _tick(deadline, cancel)
            named = os.stat(name, dir_fd=parent, follow_symlinks=False)
            if (not stat.S_ISDIR(named.st_mode) or _dir_seal(named) != seal
                    or _dir_seal(os.fstat(child)) != seal):
                raise _error("imported_save_input_changed")

    def close(self) -> bool:
        ok = True
        for fd in reversed(self.fds):
            try:
                os.close(fd)
            except OSError:
                ok = False
        self.fds.clear()
        return ok


def _check_file(fd: int, parent: int, name: str, seal: tuple) -> None:
    try:
        actual = os.fstat(fd)
        named = os.stat(name, dir_fd=parent, follow_symlinks=False)
    except OSError:
        raise _error("imported_save_input_changed") from None
    if (not stat.S_ISREG(actual.st_mode) or actual.st_nlink != 1
            or _file_seal(actual) != seal or _file_seal(named) != seal):
        raise _error("imported_save_input_changed")


def _read_fd(fd: int, size: int, deadline: float, cancel, *, collect: bool = False):
    """처음 확인한 크기만 64KiB 이하 pread로 읽는다. 같은 FD를 다시 선택하지 않는다."""
    digest = hashlib.sha256()
    blocks = []
    offset = 0
    while offset < size:
        _tick(deadline, cancel)
        block = os.pread(fd, min(CHUNK, size - offset), offset)
        if not block:
            raise _error("imported_save_input_changed")
        digest.update(block)
        if collect:
            blocks.append(block)
        offset += len(block)
    _tick(deadline, cancel)
    return digest.hexdigest(), b"".join(blocks) if collect else None


def _finite(value):
    try:
        return type(value) in (int, float) and math.isfinite(value)
    except (OverflowError, ValueError):
        return False


def _arguments(offset, length, edits, purpose, unlock_source, online_capable, checksum):
    """파일 절대 좌표를 엄격히 확인한 뒤 helper용 선택 상대 좌표를 만든다."""
    bad = "imported_save_input_invalid"
    if (type(offset) is not int or type(length) is not int or not 0 <= offset < offset + length <= MAX_INPUT_BYTES
            or type(edits) is not list or not 1 <= len(edits) <= 16
            or type(purpose) is not str or purpose not in ("score", "progress", "in-device-unlock")
            or type(unlock_source) is not str or unlock_source not in ("in-device", "owned-tag")
            or type(online_capable) is not str or online_capable not in ("no", "unknown")):
        raise _error(bad)
    normalized, spans = [], []
    for row in edits:
        if type(row) is not dict or set(row) != {"offset", "encoding", "value"}:
            raise _error(bad)
        pos, enc, value = row["offset"], row["encoding"], row["value"]
        if type(pos) is not int or type(enc) is not str or enc not in saves.ENCODINGS or type(value) is not int:
            raise _error(bad)
        try:
            width = len(saves.encode_value(value, enc))
        except saves.SaveFormatError:
            raise _error(bad) from None
        if not offset <= pos < pos + width <= offset + length:
            raise _error(bad)
        normalized.append({"offset": pos - offset, "encoding": enc, "value": value})
        spans.append((pos, pos + width))
    ordered = sorted(spans)
    if any(a[1] > b[0] for a, b in zip(ordered, ordered[1:])):
        raise _error(bad)
    cs = None
    if checksum is not None:
        if type(checksum) is not dict or set(checksum) != {"algorithm", "endian", "location", "range"}:
            raise _error(bad)
        alg, endian, pos, rng = (checksum[k] for k in ("algorithm", "endian", "location", "range"))
        if (type(alg) is not str or alg not in saves.CHECKSUM_ALGORITHMS or type(pos) is not int
                or type(rng) is not list or len(rng) != 2 or any(type(v) is not int for v in rng)):
            raise _error(bad)
        width = saves.CHECKSUM_ALGORITHMS[alg]["width"]
        if ((width == 1 and endian is not None) or
                (width != 1 and (type(endian) is not str or endian not in ("le", "be")))
                or not offset <= pos < pos + width <= offset + length
                or not offset <= rng[0] < rng[1] <= offset + length
                or rng[0] < pos + width and pos < rng[1]
                or any(a < pos + width and pos < b for a, b in spans)):
            raise _error(bad)
        cs = {"algorithm": alg, "endian": endian, "location": pos - offset,
              "range": [rng[0] - offset, rng[1] - offset]}
    return normalized, cs


def _provenance(ledger, case, source, deadline, cancel):
    entries = ledger.entries(case, max_bytes=16 << 20, max_entries=10000,
                             deadline=deadline, check=lambda: _tick(deadline, cancel))
    latest = None
    for row in entries:
        _tick(deadline, cancel)
        if row.get("path") == source["path"]:
            latest = row
    # kind를 먼저 거르면 같은 경로의 더 나중 device-read/patch-plan을 숨기게 된다.
    if (latest is None or latest.get("kind") != "imported-unattested"
            or latest.get("case_id") != case.id or type(latest.get("seq")) is not int or latest["seq"] < 1):
        raise _error("imported_save_input_invalid")
    if (type(latest.get("size")) is not int or latest["size"] != source["size"]
            or latest.get("sha256") != source["sha256"]):
        raise _error("imported_save_input_changed")
    return {"kind": latest["kind"], "seq": latest["seq"],
            "record_sha256": hashlib.sha256(canonical_json(latest).encode("utf-8")).hexdigest()}


def _plan_bytes(data, offset, length, edits, checksum):
    """계산은 기존 helper 한 번에 맡기고 허용된 숫자·좌표만 독립 대조한다."""
    selected = data[offset:offset + length]
    try:
        changed, rows = saves.apply_raw_edits(selected, edits, checksum=checksum)
    except saves.SaveFormatError:
        raise _error("imported_save_input_invalid") from None
    def require(condition):
        if not condition:
            raise _error("imported_save_failed")
    require(type(changed) is bytes and len(changed) == length and type(rows) is list
            and len(rows) == len(edits) + (checksum is not None))
    projected, spans = [], []
    for planned, actual in zip(edits, rows):
        pos, enc, value = (planned[k] for k in ("offset", "encoding", "value"))
        encoded = saves.encode_value(value, enc)
        before = saves.decode_value(selected, pos, enc)
        inside = None if checksum is None else pos < checksum["range"][1] and checksum["range"][0] < pos + len(encoded)
        expected = {"offset": pos, "encoding": enc, "before_value": before, "after_value": value}
        require(type(actual) is dict and all(type(actual.get(k)) is type(v) and actual.get(k) == v for k, v in expected.items()))
        require(actual.get("in_checksum_range") is inside and changed[pos:pos + len(encoded)] == encoded)
        projected.append({**expected, "offset": pos + offset, "in_checksum_range": inside})
        spans.append((pos, pos + len(encoded)))
    cs = None
    if checksum is not None:
        actual = rows[-1].get("checksum") if type(rows[-1]) is dict else None
        require(type(actual) is dict)
        require(all(type(actual.get(k)) is type(v) and actual.get(k) == v for k, v in checksum.items()))
        alg, endian, pos = (checksum[k] for k in ("algorithm", "endian", "location"))
        width = saves.CHECKSUM_ALGORITHMS[alg]["width"]
        order = "big" if endian == "be" else "little"
        before = int.from_bytes(selected[pos:pos + width], order)
        after = int.from_bytes(changed[pos:pos + width], order)
        require(type(actual.get("before")) is int and actual["before"] == before
                and type(actual.get("after")) is int and actual["after"] == after)
        cs = {**checksum, "location": pos + offset, "range": [v + offset for v in checksum["range"]],
              "before": before, "after": after, "original_rule_reproduced": True, "patched_rule_reproduced": True}
        spans.append((pos, pos + width))
    cursor = 0
    for start, end in sorted(spans):
        require(changed[cursor:start] == selected[cursor:start])
        cursor = end
    require(changed[cursor:] == selected[cursor:])
    result = data[:offset] + changed + data[offset + length:]
    require(len(result) == len(data) and result[:offset] == data[:offset]
            and result[offset + length:] == data[offset + length:])
    if result == data:
        raise _error("imported_save_no_changes")
    return result, projected, cs


class _Output:
    """자신이 만든 디렉터리와 두 inode만 소유한다. 불명확한 이름은 보존한다."""

    def __init__(self, directories):
        self.dirs = directories
        self.parent = self.fd = self.name = self.identity = None
        self.files = {}

    def prepare(self, deadline, cancel):
        self.parent = self.dirs.descend(["patches"], deadline, cancel)
        for number in range(1, 65):
            _tick(deadline, cancel)
            name = f"imported-save-plan-{number:03d}"
            try:
                os.mkdir(name, 0o700, dir_fd=self.parent)
            except FileExistsError:
                continue
            self.name = name
            self.identity = os.stat(name, dir_fd=self.parent, follow_symlinks=False)
            self.fd = os.open(name, safeio.DIR_FLAGS, dir_fd=self.parent)
            self.check(deadline, cancel)
            return
        raise _error("imported_save_failed")

    def path(self, name):
        return f"patches/{self.name}/{name}"

    def check(self, deadline, cancel):
        self.dirs.check(deadline, cancel)
        named = os.stat(self.name, dir_fd=self.parent, follow_symlinks=False)
        if (self.identity is None or not stat.S_ISDIR(named.st_mode)
                or _dir_seal(named) != _dir_seal(self.identity)
                or self.fd is not None and _dir_seal(os.fstat(self.fd)) != _dir_seal(self.identity)):
            raise _error("imported_save_input_changed")
        if self.fd is not None:
            names = set()
            with os.scandir(self.fd) as it:
                for item in it:
                    _tick(deadline, cancel)
                    names.add(item.name)
                    if len(names) > 2:
                        raise _error("imported_save_input_changed")
            if names != set(self.files):
                raise _error("imported_save_input_changed")

    def write(self, name, data, deadline, cancel):
        self.check(deadline, cancel)
        fd = os.open(name, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                     0o600, dir_fd=self.fd)
        row = self.files[name] = {"fd": fd, "identity": None}
        row["identity"] = os.fstat(fd)
        position = 0
        while position < len(data):
            _tick(deadline, cancel)
            n = os.write(fd, data[position:position + CHUNK])
            if n <= 0:
                raise _error("imported_save_failed")
            position += n
        os.fchmod(fd, 0o444)
        os.fsync(fd)
        row.update(seal=_file_seal(os.fstat(fd)), size=len(data), sha256=hashlib.sha256(data).hexdigest())
        _check_file(fd, self.fd, name, row["seal"])
        if _read_fd(fd, row["size"], deadline, cancel)[0] != row["sha256"]:
            raise _error("imported_save_input_changed")
        self.check(deadline, cancel)

    def seals(self, deadline, cancel):
        self.check(deadline, cancel)
        for name, row in self.files.items():
            _check_file(row["fd"], self.fd, name, row["seal"])

    def cleanup(self):
        if self.name is None:
            return True
        try:
            self.check(float("inf"), None)
            for name, row in self.files.items():
                named = os.stat(name, dir_fd=self.fd, follow_symlinks=False)
                if (row["identity"] is None or not stat.S_ISREG(named.st_mode) or named.st_nlink != 1
                        or not safeio.same_file(named, row["identity"])
                        or not safeio.same_file(os.fstat(row["fd"]), row["identity"])):
                    return False
            for name in tuple(self.files):
                os.unlink(name, dir_fd=self.fd)
            # FD 기록은 close가 독립적으로 모두 정리할 때까지 유지한다.
            named = os.stat(self.name, dir_fd=self.parent, follow_symlinks=False)
            if not safeio.same_file(named, self.identity):
                return False
            os.rmdir(self.name, dir_fd=self.parent)
            return True
        except Exception:
            return False

    def close(self):
        ok = True
        for fd in [*(row["fd"] for row in self.files.values()), self.fd]:
            if fd is not None:
                try:
                    os.close(fd)
                except OSError:
                    ok = False
        return ok


def plan_imported_save(S, case, artifact_id: str, *, offset: int, length: int, edits: list[dict],
                       purpose: str, unlock_source: str, online_capable: str, checksum: dict | None,
                       max_seconds: int | float, deadline: float, cancel) -> dict:
    """로컬 planned 사본만 만든다. 유한 helper/OS 호출 중 즉시 취소는 보장하지 않는다."""
    directories = output = None
    input_fd = None
    committed = report = None
    failure = None
    warnings = []
    try:
        if (type(artifact_id) is not str or re.fullmatch(r"A-[0-9]{4,8}", artifact_id) is None
                or not _finite(max_seconds) or not 0 < max_seconds <= 30 or not _finite(deadline)
                or cancel is not None and not callable(cancel)):
            raise _error("imported_save_input_invalid")
        deadline = min(deadline, time.monotonic() + max_seconds)
        _tick(deadline, cancel)
        normalized, cs = _arguments(offset, length, edits, purpose, unlock_source, online_capable, checksum)
        source = _projection(case, artifact_id)
        if offset + length > source["size"]:
            raise _error("imported_save_input_invalid")
        directories = _Directories(case, deadline, cancel)
        parts = source["path"].split("/")
        parent = directories.descend(parts[:-1], deadline, cancel)
        input_fd, initial = safeio.open_regular(parts[-1], dir_fd=parent, reject_hardlinks=True)
        input_seal = _file_seal(initial)
        if initial.st_size != source["size"]:
            raise _error("imported_save_input_changed")
        real = safeio.fd_real_path(input_fd)
        if real is None:
            raise _error("imported_save_input_invalid")
        try:
            relative = Path(real).relative_to(case.dir)
        except ValueError:
            raise _error("imported_save_input_invalid") from None
        if (not relative.parts or relative.parts[0] in ("forensics", "emu")
                or under_any_case_protected(real, case.dir.parent) is not None):
            raise _error("imported_save_input_invalid")
        directories.check(deadline, cancel)
        _check_file(input_fd, parent, parts[-1], input_seal)
        actual_hash, data = _read_fd(input_fd, source["size"], deadline, cancel, collect=True)
        if actual_hash != source["sha256"]:
            raise _error("imported_save_input_changed")
        _check_file(input_fd, parent, parts[-1], input_seal)
        ledger = S.rt().provenance
        provenance = _provenance(ledger, case, source, deadline, cancel)
        for blob in (data, data[offset:offset + length]):
            _tick(deadline, cancel)
            if S._looks_like_nvs(blob) or espfmt.parse_partition_table(blob, data_len=len(blob))["found"]:
                raise _error("imported_save_input_invalid")
        _tick(deadline, cancel)
        patched, projected, result_cs = _plan_bytes(data, offset, length, normalized, cs)
        _tick(deadline, cancel)
        report = {"schema": SCHEMA, "profile": PROFILE, "stage": "planned",
                  "source": {"kind": "case-artifact", "artifact_id": artifact_id, "size": source["size"],
                             "sha256": actual_hash, "import_provenance": provenance},
                  "params": {"offset": offset, "length": length, "purpose": purpose, "unlock_source": unlock_source,
                             "online_capable": online_capable, "max_seconds": max_seconds},
                  "edits": projected, "checksum": result_cs,
                  "output": {"name": "planned.bin", "size": len(patched), "sha256": hashlib.sha256(patched).hexdigest()},
                  **{flag: False for flag in FLAGS}}
        schemas.validate("imported-save-plan", report)
        encoded = json.dumps(report, ensure_ascii=True, separators=(",", ":"), allow_nan=False).encode("ascii") + b"\n"
        if len(encoded) > MAX_MANIFEST_BYTES:
            raise _error("imported_save_failed")
        output = _Output(directories)
        output.prepare(deadline, cancel)
        output.write("planned.bin", patched, deadline, cancel)
        output.write("manifest.json", encoded, deadline, cancel)
        output.seals(deadline, cancel)
        _tick(deadline, cancel)
        final_end = time.monotonic() + FINAL_SECONDS
        manifest = output.files["manifest.json"]
        manifest_path, patch_path = output.path("manifest.json"), output.path("planned.bin")

        def check(entry):
            directories.check(final_end, cancel)
            if _projection(case, artifact_id) != source:
                raise _error("imported_save_input_changed")
            _check_file(input_fd, parent, parts[-1], input_seal)
            if _read_fd(input_fd, source["size"], final_end, cancel)[0] != actual_hash:
                raise _error("imported_save_input_changed")
            output.seals(final_end, cancel)
            for row in output.files.values():
                if _read_fd(row["fd"], row["size"], final_end, cancel)[0] != row["sha256"]:
                    raise _error("imported_save_input_changed")
            if _provenance(ledger, case, source, final_end, cancel) != provenance:
                raise _error("imported_save_input_changed")
            directories.check(final_end, cancel)
            _check_file(input_fd, parent, parts[-1], input_seal)
            output.seals(final_end, cancel)
            if any(type(entry.get(k)) is not type(v) or entry.get(k) != v for k, v in (
                    ("path", manifest_path), ("size", manifest["size"]), ("sha256", manifest["sha256"]), ("is_dir", False))):
                raise _error("imported_save_input_changed")
            _tick(final_end, cancel)

        def on_commit(entry):
            nonlocal committed
            committed = dict(entry)

        case.register_artifact(manifest_path, kind="triage-report", producer="fwtriage-mcp",
                               extra={"type": "imported-save-plan"}, sha256=manifest["sha256"],
                               check=check, on_commit=on_commit, deadline=final_end, replace_existing=False)
        if committed is None:
            raise _error("imported_save_failed")
    except Exception as exc:
        if committed is not None:
            warnings.append("post_commit_callback_failed")
        else:
            code = getattr(exc, "code", "imported_save_failed")
            if type(code) is not str:
                code = "imported_save_failed"
            if code in ("lock_timeout", "artifact_timeout"):
                code = "time_limit"
            elif code == "provenance_bounded_limit":
                code = "imported_save_input_limit"
            elif code == "provenance_bounded_changed":
                code = "imported_save_input_changed"
            elif code.startswith("provenance_") or isinstance(exc, (safeio.UnsafeFile, FileNotFoundError)):
                code = "imported_save_input_invalid"
            failure = code if code in _CODES else "imported_save_failed"
    finally:
        if committed is None and output is not None and not output.cleanup():
            failure = "imported_save_cleanup_incomplete"
        closed = output.close() if output is not None else True
        if input_fd is not None:
            try:
                os.close(input_fd)
            except OSError:
                closed = False
        if directories is not None:
            closed = directories.close() and closed
        if not closed:
            if committed is not None:
                warnings.append("output_close_unconfirmed")
            else:
                failure = "imported_save_cleanup_incomplete"
    if failure is not None:
        raise _error(failure) from None
    return {"ok": True, "stage": "planned", "report": report,
            "analysis": {"path": manifest_path, "sha256": manifest["sha256"], "size": manifest["size"],
                         "artifact_id": committed["id"]},
            "patch": {"path": patch_path, "size": len(patched), "sha256": report["output"]["sha256"]},
            "warnings": warnings}
