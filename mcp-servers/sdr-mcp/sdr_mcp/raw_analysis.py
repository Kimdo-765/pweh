"""등록 RAW 파일 하나를 같은 FD로 검사하고 닫힌 보고서만 케이스에 보존한다."""
from __future__ import annotations

import hashlib
import json
import math
import os
import re
import stat
import time
from pathlib import Path

from pweh import rf_formats, safeio, schemas
from pweh.errors import PwehError
from pweh.evidence import under_any_case_protected

MAX_INPUT_BYTES = 1 << 20
MAX_OUTPUT_BYTES = 128 << 10
CHUNK = 64 << 10
FINAL_SECONDS = 5.0
PROFILE = rf_formats.PROFILE
_CODES = frozenset({"rf_raw_input_invalid", "rf_raw_input_limit", "rf_raw_input_changed",
                    "rf_raw_failed", "rf_raw_cleanup_incomplete", "cancelled", "time_limit"})
_FLAGS = ("input_completeness_verified", "capture_verified", "device_association_verified",
          "authorization_assessed", "decoded", "transmitted")


def _error(code: str) -> PwehError:
    """입력 내용·경로·원래 예외를 오류에 담지 않는다."""
    return PwehError("등록 RAW 파일 분석을 완료하지 못했습니다.", code=code)


def _tick(deadline: float, cancel) -> None:
    if cancel is not None:
        try:
            stopped = cancel()
        except Exception:
            raise _error("rf_raw_failed") from None
        if stopped:
            raise _error("cancelled")
    if time.monotonic() >= deadline:
        raise _error("time_limit")


def _projection(case, artifact_id: str) -> dict:
    rows = case.load().get("artifacts", [])
    if type(rows) is not list:
        raise _error("rf_raw_input_invalid")
    matches = [row for row in rows if type(row) is dict and row.get("id") == artifact_id]
    if len(matches) != 1:
        raise _error("rf_raw_input_invalid")
    row = matches[0]
    projected = {key: row.get(key) for key in ("id", "path", "is_dir", "size", "sha256")}
    size, path, digest = projected["size"], projected["path"], projected["sha256"]
    if projected["is_dir"] is not False or type(size) is not int or size < 0:
        raise _error("rf_raw_input_invalid")
    if size > MAX_INPUT_BYTES:
        raise _error("rf_raw_input_limit")
    if type(digest) is not str or re.fullmatch(r"[0-9a-f]{64}", digest) is None:
        raise _error("rf_raw_input_invalid")
    if type(path) is not str or not path or len(os.fsencode(path)) > safeio.PATH_MAX_BYTES:
        raise _error("rf_raw_input_invalid")
    parts = path.split("/")
    if (len(parts) > safeio.PATH_MAX_STEPS or any(p in ("", ".", "..") or "\x00" in p for p in parts)
            or parts[0] in ("forensics", "emu")):
        raise _error("rf_raw_input_invalid")
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
                raise _error("rf_raw_cleanup_incomplete") from None
            raise

    def descend(self, parts: list[str], deadline: float, cancel) -> int:
        fd = self.root
        for name in parts:
            _tick(deadline, cancel)
            before = os.stat(name, dir_fd=fd, follow_symlinks=False)
            if not stat.S_ISDIR(before.st_mode):
                raise _error("rf_raw_input_invalid")
            child = os.open(name, safeio.DIR_FLAGS, dir_fd=fd)
            self.fds.append(child)
            after = os.fstat(child)
            if _dir_seal(before) != _dir_seal(after):
                raise _error("rf_raw_input_changed")
            self.edges.append((fd, name, child, _dir_seal(after)))
            fd = child
        self.check(deadline, cancel)
        return fd

    def check(self, deadline: float, cancel) -> None:
        _tick(deadline, cancel)
        current = os.stat(self.case.dir, follow_symlinks=False)
        if (not stat.S_ISDIR(current.st_mode) or _dir_seal(current) != self.root_seal
                or _dir_seal(os.fstat(self.root)) != self.root_seal):
            raise _error("rf_raw_input_changed")
        for parent, name, child, seal in self.edges:
            _tick(deadline, cancel)
            named = os.stat(name, dir_fd=parent, follow_symlinks=False)
            if (not stat.S_ISDIR(named.st_mode) or _dir_seal(named) != seal
                    or _dir_seal(os.fstat(child)) != seal):
                raise _error("rf_raw_input_changed")

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
        raise _error("rf_raw_input_changed") from None
    if (not stat.S_ISREG(actual.st_mode) or actual.st_nlink != 1
            or _file_seal(actual) != seal or _file_seal(named) != seal):
        raise _error("rf_raw_input_changed")


def _read_fd(fd: int, size: int, deadline: float, cancel, *, collect: bool = False):
    """처음 확인한 크기만 64KiB 이하 pread로 읽는다. 같은 FD를 다시 선택하지 않는다."""
    digest = hashlib.sha256()
    blocks = []
    offset = 0
    while offset < size:
        _tick(deadline, cancel)
        block = os.pread(fd, min(CHUNK, size - offset), offset)
        if not block:
            raise _error("rf_raw_input_changed")
        digest.update(block)
        if collect:
            blocks.append(block)
        offset += len(block)
    _tick(deadline, cancel)
    return digest.hexdigest(), b"".join(blocks) if collect else None


def _validate_relations(report: dict, size: int) -> None:
    """직접 호출한 순수 parser 결과와 저장 봉투의 수치 연결만 대조한다."""
    item = report["inspection"]
    cov, stats = item["coverage"], item["statistics"]
    def require(condition):
        if not condition:
            raise _error("rf_raw_failed")
    def integers(value, key=""):
        if type(value) is dict:
            for name, child in value.items():
                integers(child, name)
        elif type(value) is list:
            for child in value:
                integers(child)
        elif type(value) is bool:
            require(key in _FLAGS + ("eof_validated", "analysis_complete"))
        elif isinstance(value, (int, float)):
            require(type(value) is int)
    integers(item)
    require(report["status"] == item["status"] and report["params"]["profile"] == item["profile"] == PROFILE)
    require(report["source"]["size"] == cov["input_bytes"] == size)
    accepted, remaining = cov["accepted_prefix_bytes"], cov["remaining_bytes"]
    require(accepted + remaining == size)
    require(cov["remaining_range"] == ({"offset": accepted, "length": remaining} if remaining else None))
    count = stats["pulse_count"]
    require(stats["positive"]["count"] == (count + 1) // 2 and stats["negative"]["count"] == count // 2)
    require(sum(stats[s]["sum_us"] for s in ("positive", "negative")) == stats["declared_duration_us"])
    for sign in ("positive", "negative"):
        row = stats[sign]
        if row["count"] == 0:
            require(row["min_us"] is None and row["max_us"] is None and row["sum_us"] == 0)
        else:
            require(0 < row["min_us"] <= row["max_us"])
            require(row["count"] * row["min_us"] <= row["sum_us"] <= row["count"] * row["max_us"])
    lines = stats["raw_data_lines_accepted"]
    require(lines <= count <= lines * 512 and lines <= cov["lines_accepted"] <= cov["lines_seen"])
    complete = item["status"] == "complete"
    require(cov["analysis_complete"] is complete and cov["eof_validated"] is complete)
    require(cov["statistics_scope"] == ("whole_profile" if complete else "accepted_prefix"))
    require(all(cov[key] is False for key in _FLAGS))
    if complete:
        require(item["stop"] is None and count > 0 and remaining == 0 and accepted == size)
    else:
        stop = item["stop"]
        require(stop is not None and stop["offset"] == accepted)
        code = stop["code"]
        expected = ("partial" if code in rf_formats.STOP_CODES[:7] else
                    "unsupported" if code in rf_formats.STOP_CODES[7:13] else "malformed")
        require(item["status"] == expected)


def analyze_registered_raw(case, artifact_id: str, *, profile: str, deadline: float,
                           max_seconds: int | float, cancel) -> dict:
    """등록된 RAW bytes를 검사한다. 입력/출력 FD와 정리는 이 worker만 소유한다."""
    directories = None
    input_fd = output_fd = None
    output_parent = output_name = output_identity = None
    committed = None
    report = None
    output_size = output_hash = output_path = None
    failure = None
    warnings = []
    try:
        try:
            finite_deadline = type(deadline) in (int, float) and math.isfinite(deadline)
        except (ValueError, OverflowError):
            finite_deadline = False
        if (type(artifact_id) is not str or re.fullmatch(r"A-[0-9]{4,8}", artifact_id) is None
                or type(profile) is not str or profile != PROFILE
                or type(max_seconds) not in (int, float) or not 0 < max_seconds <= 5
                or not finite_deadline
                or cancel is not None and not callable(cancel)):
            raise _error("rf_raw_input_invalid")
        _tick(deadline, cancel)
        source = _projection(case, artifact_id)
        _tick(deadline, cancel)
        directories = _Directories(case, deadline, cancel)
        parts = source["path"].split("/")
        parent = directories.descend(parts[:-1], deadline, cancel)
        input_fd, initial = safeio.open_regular(parts[-1], dir_fd=parent, reject_hardlinks=True)
        if initial.st_size != source["size"]:
            raise _error("rf_raw_input_changed")
        real = safeio.fd_real_path(input_fd)
        if real is None:
            raise _error("rf_raw_input_invalid")
        try:
            relative = Path(real).relative_to(case.dir)
        except ValueError:
            raise _error("rf_raw_input_invalid") from None
        if (not relative.parts or relative.parts[0] in ("forensics", "emu")
                or under_any_case_protected(real, case.dir.parent) is not None):
            raise _error("rf_raw_input_invalid")
        input_seal = _file_seal(initial)
        directories.check(deadline, cancel)
        _check_file(input_fd, parent, parts[-1], input_seal)
        actual_hash, data = _read_fd(input_fd, source["size"], deadline, cancel, collect=True)
        if actual_hash != source["sha256"]:
            raise _error("rf_raw_input_changed")
        directories.check(deadline, cancel)
        _check_file(input_fd, parent, parts[-1], input_seal)
        inspection = rf_formats.inspect_sub_raw(data, deadline=deadline, cancel=cancel)
        # 지난 작업 마감은 코어의 timepartial에 남긴다. 최종 단계는 한 번 정한 별도 마감이다.
        final_end = time.monotonic() + FINAL_SECONDS
        directories.check(final_end, cancel)
        _check_file(input_fd, parent, parts[-1], input_seal)
        report = {"schema": "pweh.rf-raw-analysis/v1", "status": inspection["status"],
                  "source": {"kind": "case-artifact", "artifact_id": artifact_id,
                             "size": len(data), "sha256": actual_hash},
                  "params": {"profile": profile, "max_seconds": max_seconds}, "inspection": inspection}
        schemas.validate("rf-raw-analysis", report)
        _validate_relations(report, len(data))
        encoded = json.dumps(report, ensure_ascii=True, separators=(",", ":"), allow_nan=False).encode("ascii")
        if len(encoded) > MAX_OUTPUT_BYTES:
            raise _error("rf_raw_failed")
        output_size, output_hash = len(encoded), hashlib.sha256(encoded).hexdigest()
        output_parent = directories.descend(["analysis"], final_end, cancel)
        for sequence in range(1, 10001):
            _tick(final_end, cancel)
            name = f"rf-raw-{sequence:03d}.json"
            try:
                fd = os.open(name, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                             0o600, dir_fd=output_parent)
            except FileExistsError:
                continue
            output_fd, output_name = fd, name
            output_identity = os.fstat(fd)
            output_path = f"analysis/{name}"
            break
        if output_fd is None:
            raise _error("rf_raw_failed")
        position = 0
        while position < output_size:
            _tick(final_end, cancel)
            written = os.write(output_fd, encoded[position:position + CHUNK])
            if written <= 0:
                raise _error("rf_raw_failed")
            position += written
        os.fchmod(output_fd, 0o444)
        os.fsync(output_fd)
        output_seal = _file_seal(os.fstat(output_fd))
        directories.check(final_end, cancel)
        _check_file(output_fd, output_parent, output_name, output_seal)

        def check(entry):
            directories.check(final_end, cancel)
            if _projection(case, artifact_id) != source:
                raise _error("rf_raw_input_changed")
            _check_file(input_fd, parent, parts[-1], input_seal)
            if _read_fd(input_fd, source["size"], final_end, cancel)[0] != actual_hash:
                raise _error("rf_raw_input_changed")
            _check_file(input_fd, parent, parts[-1], input_seal)
            _check_file(output_fd, output_parent, output_name, output_seal)
            if _read_fd(output_fd, output_size, final_end, cancel)[0] != output_hash:
                raise _error("rf_raw_input_changed")
            if any(type(entry.get(key)) is not type(value) or entry.get(key) != value for key, value in
                   (("path", output_path), ("size", output_size), ("sha256", output_hash), ("is_dir", False))):
                raise _error("rf_raw_input_changed")
            directories.check(final_end, cancel)
            _check_file(input_fd, parent, parts[-1], input_seal)
            _check_file(output_fd, output_parent, output_name, output_seal)
            _tick(final_end, cancel)

        def on_commit(entry):
            nonlocal committed
            # 원자 metadata 게시 뒤 첫 동작. 이후 취소/감사 오류로 출력을 삭제하지 않는다.
            committed = dict(entry)

        case.register_artifact(output_path, kind="other", producer="pweh-sdr",
                               extra={"type": "rf-raw-analysis"}, sha256=output_hash,
                               check=check, on_commit=on_commit, deadline=final_end, replace_existing=False)
        if committed is None:
            raise _error("rf_raw_failed")
    except Exception as exc:
        if committed is not None:
            warnings.append("post_commit_callback_failed")
        else:
            code = getattr(exc, "code", "rf_raw_failed")
            if code in ("lock_timeout", "artifact_timeout"):
                code = "time_limit"
            elif isinstance(exc, safeio.UnsafeFile):
                code = "rf_raw_input_invalid"
            failure = code if code in _CODES else "rf_raw_failed"
    finally:
        if committed is None and output_fd is not None:
            try:
                # 다른 이름/부모로 바뀐 출력은 보존한다. 자기 inode 하나만 지운다.
                directories.check(float("inf"), None)
                named = os.stat(output_name, dir_fd=output_parent, follow_symlinks=False)
                if not safeio.same_file(named, output_identity) or not safeio.same_file(os.fstat(output_fd), output_identity):
                    raise _error("rf_raw_cleanup_incomplete")
                os.unlink(output_name, dir_fd=output_parent)
            except Exception:
                failure = "rf_raw_cleanup_incomplete"
        close_ok = True
        for fd in (output_fd, input_fd):
            if fd is not None:
                try:
                    os.close(fd)
                except OSError:
                    close_ok = False
        if directories is not None:
            close_ok = directories.close() and close_ok
        if not close_ok:
            if committed is not None:
                warnings.append("output_close_unconfirmed")
            else:
                failure = "rf_raw_cleanup_incomplete"
    if failure is not None:
        raise _error(failure) from None
    return {"ok": True, "report": report,
            "analysis": {"path": output_path, "sha256": output_hash, "size": output_size,
                         "artifact_id": committed["id"]}, "warnings": warnings}
