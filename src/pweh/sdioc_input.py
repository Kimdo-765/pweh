"""SD 경로 대조의 입력 보고서: 제한된 JSON, 목록 custody와 일반 펌웨어 색인 결속.

실제 EV 내용은 읽지 않는다. 호출자가 검증한 opened/entries를 받고 생성 JSON 두 개의 fd만 소유한다.
펌웨어 artifact 색인은 보호된 생성 증명이 아니며, 두 입력의 장치 관계도 증명하지 않는다.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import math
import os
import re
import stat
import time
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from typing import Any

from . import evidence as E, safeio
from .case import Case
from .errors import PwehError, ValidationFailed

MAX_REPORT_BYTES = 16 << 20
MAX_TOTAL_BYTES = 32 << 20
MAX_DEPTH = 32
MAX_NODES = 100_000
MAX_CONTAINERS = 20_000
MAX_STRUCTURAL = 200_000
MAX_STRING_BYTES = 256 << 10
MAX_STRINGS_BYTES = 8 << 20
MAX_NUMBER_BYTES = 128
_FW_PATH = re.compile(r"analysis/sd-surface-[0-9]{3,9}\.json")
_ART_ID = re.compile(r"A-[0-9]{4,8}")
_SHA = re.compile(r"[0-9a-f]{64}")
_FW_KEYS = frozenset({"schema", "tool", "case_id", "sd_paths_referenced", "mount_points", "sd_paths_total",
                      "sd_paths_truncated", "timed_out", "checks", "phases", "limitations", "stats", "inputs_analyzed"})
_LIST_KEYS = frozenset({"schema", "evidence_id", "params", "volumes", "call", "archive"})


def _invalid() -> ValidationFailed:
    return ValidationFailed("SD 대조 입력 보고서의 형식 또는 출처가 유효하지 않습니다.", code="sdioc_input_invalid")


def _limit() -> ValidationFailed:
    return ValidationFailed("SD 대조 입력 보고서의 크기·구조 상한을 넘었습니다.", code="sdioc_input_limit",
                            hint="forensics_fs_list에서 partition 또는 max_entries를 줄여 전체 목록을 다시 만드세요. "
                                 "잘린 목록의 coverage는 그대로 유지됩니다.")


def _changed() -> ValidationFailed:
    return ValidationFailed("SD 대조 입력 보고서 또는 부모 디렉터리가 변경되었습니다.", code="sdioc_input_changed")


def _check(deadline: float, cancel: Callable[[], bool], *, timed: bool = True) -> None:
    if cancel():
        raise PwehError("SD 대조 입력 처리가 취소되었습니다.", code="cancelled")
    if timed and time.monotonic() >= deadline:
        raise PwehError("SD 대조 입력 검증 시간 상한에 도달했습니다.", code="timeout")


def _preflight(raw: bytes, check: Callable[[], None]) -> None:
    """문자열/escape를 구분해 파서가 객체를 만들기 전에 구조 복잡도를 제한한다."""
    if not raw or len(raw) > MAX_REPORT_BYTES:
        raise _limit()
    stack: list[int] = []
    nodes = containers = structural = strings = 0
    i = 0
    checkpoint = 0
    while i < len(raw):
        if i >= checkpoint:
            check()
            checkpoint = i + 4096
        c = raw[i]
        if c in b" \t\r\n":
            i += 1
            continue
        if c == 34:
            nodes += 1  # 객체 key도 메모리를 차지한다.
            start = i + 1
            i += 1
            while i < len(raw) and raw[i] != 34:
                if i >= checkpoint:
                    check()
                    checkpoint = i + 4096
                if i - start > MAX_STRING_BYTES or strings + i - start > MAX_STRINGS_BYTES:
                    raise _limit()
                c = raw[i]
                if c < 32:
                    raise _invalid()
                if c == 92:
                    i += 1
                    if i >= len(raw):
                        raise _invalid()
                    if raw[i] == 117:
                        if i + 4 >= len(raw) or any(x not in b"0123456789abcdefABCDEF" for x in raw[i + 1:i + 5]):
                            raise _invalid()
                        i += 4
                    elif raw[i] not in b'"\\/bfnrt':
                        raise _invalid()
                i += 1
            if i >= len(raw):
                raise _invalid()
            size = i - start
            strings += size
            if size > MAX_STRING_BYTES or strings > MAX_STRINGS_BYTES:
                raise _limit()
            i += 1
        elif c in b"{}[],:":
            structural += 1
            if c in b"{[":
                containers += 1
                nodes += 1
                stack.append(c)
                if len(stack) > MAX_DEPTH:
                    raise _limit()
            elif c in b"}]":
                if not stack or stack.pop() != (123 if c == 125 else 91):
                    raise _invalid()
            i += 1
        elif c in b"-0123456789":
            nodes += 1
            start = i
            while i < len(raw) and raw[i] in b"-+0123456789.eE":
                i += 1
                if i - start > MAX_NUMBER_BYTES:
                    raise _limit()
            # 정확한 숫자 문법은 json.loads가 검증한다.
        else:
            literal = next((v for v in (b"true", b"false", b"null") if raw.startswith(v, i)), None)
            if literal is None:
                raise _invalid()
            nodes += 1
            i += len(literal)
        if nodes > MAX_NODES or containers > MAX_CONTAINERS or structural > MAX_STRUCTURAL:
            raise _limit()
    if stack:
        raise _invalid()
    check()


def load_json(raw: bytes, *, deadline: float, cancel: Callable[[], bool]) -> dict[str, Any]:
    """전체 raw bytes의 제한 검사 뒤 strict JSON을 읽는다. 원문은 예외에 넣지 않는다."""
    check = lambda: _check(deadline, cancel)
    try:
        _preflight(raw, check)

        def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
            result = {}
            for n, (key, value) in enumerate(items):
                if n % 256 == 0:
                    check()
                if key in result:
                    raise _invalid()
                result[key] = value
            return result

        def finite(value: str) -> float:
            result = float(value)
            if not math.isfinite(result):
                raise _invalid()
            return result

        def constant(value: str) -> Any:
            raise _invalid()

        text = raw.decode("utf-8", "strict")
        check()
        obj = json.loads(text, object_pairs_hook=pairs, parse_float=finite, parse_constant=constant)
        del text
        check()
        if not isinstance(obj, dict):
            raise _invalid()
        # escape로 만들어진 lone surrogate도 거부한다. 순회 스택은 컨테이너 깊이만큼이다.
        todo: list[Iterator[Any]] = [iter((obj,))]
        count = 0
        while todo:
            value = next(todo[-1], _END)
            if value is _END:
                todo.pop()
                continue
            count += 1
            if count % 256 == 0:
                check()
            if count > MAX_NODES:
                raise _limit()
            if isinstance(value, str):
                value.encode("utf-8", "strict")
            elif isinstance(value, dict):
                todo.append((v for pair in value.items() for v in pair))
            elif isinstance(value, list):
                todo.append(iter(value))
        check()
        return obj
    except (ValueError, UnicodeError, RecursionError, MemoryError):
        raise _invalid() from None


_END = object()


def _identity(st: os.stat_result) -> tuple[int, ...]:
    return st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns, st.st_ctime_ns, st.st_mode, st.st_nlink


def _dir_at(root_fd: int, parts: tuple[str, ...]) -> int:
    fd = os.dup(root_fd)
    try:
        for part in parts:
            new = os.open(part, safeio.DIR_FLAGS, dir_fd=fd)
            os.close(fd)
            fd = new
        return fd
    except BaseException:
        os.close(fd)
        raise


@dataclass
class _Report:
    parts: tuple[str, ...]
    name: str
    parent: int
    fd: int
    seal: os.stat_result
    readonly: bool
    sha256: str = ""

    def check(self, root_fd: int) -> None:
        parent = _dir_at(root_fd, self.parts)
        try:
            if not safeio.same_file(os.fstat(parent), os.fstat(self.parent)):
                raise _changed()
            named = os.stat(self.name, dir_fd=parent, follow_symlinks=False)
            held = os.fstat(self.fd)
            if (not stat.S_ISREG(named.st_mode) or _identity(named) != _identity(self.seal)
                    or _identity(held) != _identity(self.seal) or held.st_nlink != 1
                    or (self.readonly and held.st_mode & 0o222)):
                raise _changed()
        finally:
            os.close(parent)

    def close(self) -> None:
        for fd in (self.fd, self.parent):
            with contextlib.suppress(OSError):
                os.close(fd)


def _open_report(root: int, path: str, *, readonly: bool) -> _Report:
    parts = tuple(path.split("/"))
    parent = _dir_at(root, parts[:-1])
    fd = None
    try:
        fd, seal = safeio.open_regular(parts[-1], dir_fd=parent, reject_hardlinks=True)
        if not 0 < seal.st_size <= MAX_REPORT_BYTES:
            raise _limit()
        if readonly and seal.st_mode & 0o222:
            raise _invalid()
        return _Report(parts[:-1], parts[-1], parent, fd, seal, readonly)
    except BaseException:
        if fd is not None:
            os.close(fd)
        os.close(parent)
        raise


def _read_report(report: _Report, root: int, *, deadline: float, cancel: Callable[[], bool],
                 expected_sha: str | None = None) -> dict[str, Any]:
    data = bytearray()
    digest = hashlib.sha256()
    while len(data) < report.seal.st_size:
        _check(deadline, cancel)
        chunk = os.pread(report.fd, min(64 << 10, report.seal.st_size - len(data)), len(data))
        if not chunk:
            raise _changed()
        digest.update(chunk)
        data.extend(chunk)
    report.check(root)
    report.sha256 = digest.hexdigest()
    if expected_sha is not None and report.sha256 != expected_sha:
        raise _invalid()
    raw = bytes(data)
    del data
    return load_json(raw, deadline=deadline, cancel=cancel)


def _list_event(entries: list[dict[str, Any]], ev: str, path: str, check: Callable[[], None]) -> dict[str, Any]:
    matches = []
    for n, entry in enumerate(entries):
        if n % 256 == 0:
            check()
        if (entry.get("event") == "list" and entry.get("evidence_id") == ev
                and isinstance(entry.get("data"), dict) and entry["data"].get("result_path") == path):
            matches.append(entry)
            if len(matches) > 1:
                raise _invalid()
    if len(matches) != 1:
        raise _invalid()
    entry = matches[0]
    if (type(entry.get("seq")) is not int or not 1 <= entry["seq"] <= len(entries)
            or entries[entry["seq"] - 1] is not entry or not _sha(entry["data"].get("result_sha256"))):
        raise _invalid()
    return entry


def _sha(value: Any) -> bool:
    return isinstance(value, str) and _SHA.fullmatch(value) is not None


@dataclass
class Inputs:
    """호출 동안 유지하는 보고서 fd와 출처. check_entries는 검증된 보관 기록만 받는다."""

    case: Case
    root: int
    reports: list[_Report]
    firmware: dict[str, Any]
    listing: dict[str, Any]
    source: dict[str, Any]
    deadline: float
    cancel: Callable[[], bool]
    _event: tuple[str, str, int, str, str]

    def check(self) -> None:
        """시간 상한으로 비교가 partial이어도 저장할 수 있게 취소와 입력 신원만 확인한다."""
        _check(self.deadline, self.cancel, timed=False)
        try:
            current = safeio.open_dir_chain(self.case.dir)
            try:
                if not safeio.same_file(os.fstat(current), os.fstat(self.root)):
                    raise _changed()
            finally:
                os.close(current)
            for report in self.reports:
                report.check(self.root)
        except (OSError, safeio.UnsafeFile):
            raise _changed() from None

    def check_entries(self, entries: list[dict[str, Any]]) -> None:
        """같은 커밋 잠금에서 검증된 list 사건을 재대조한다. 로그 재읽기·중첩 잠금은 없다."""
        _check(self.deadline, self.cancel, timed=False)
        ev, path, seq, digest, sha = self._event
        entry = _list_event(entries, ev, path, lambda: _check(self.deadline, self.cancel, timed=False))
        if entry["seq"] != seq or E.entry_hash(entry) != digest or entry["data"]["result_sha256"] != sha:
            raise _invalid()


@contextlib.contextmanager
def open_inputs(case: Case, opened: E.OpenedEvidence, *, firmware_result_path: str, fs_list_path: str,
                entries: list[dict[str, Any]], deadline: float, cancel: Callable[[], bool]) -> Iterator[Inputs]:
    """검증한 EV와 같은 case의 생성 JSON을 유지한다. context 밖에서는 보고서 fd를 쓰지 않는다."""
    ev = opened.evidence_id
    if (not isinstance(ev, str) or E.EV_RE.fullmatch(ev) is None
            or not isinstance(firmware_result_path, str) or _FW_PATH.fullmatch(firmware_result_path) is None
            or not isinstance(fs_list_path, str)
            or re.fullmatch(r"forensics/analysis/fs-list-" + re.escape(ev) + r"-[0-9]{3,9}\.json", fs_list_path) is None):
        raise _invalid()
    if opened.record.get("case_id") != case.id or not _sha(opened.intake.get("hashes", {}).get("sha256")):
        raise _invalid()
    root = None
    reports: list[_Report] = []
    try:
        _check(deadline, cancel)
        event = _list_event(entries, ev, fs_list_path, lambda: _check(deadline, cancel))
        if event.get("case_id") != case.id:
            raise _invalid()
        expected = (ev, fs_list_path, event["seq"], E.entry_hash(event), event["data"]["result_sha256"])
        root = safeio.open_dir_chain(case.dir)
        # 일반 case 색인도 같은 제한 검사로 읽는다. 생성 증명이 아닌 관찰 시점의 색인이다.
        meta = _open_report(root, "case.json", readonly=False)
        try:
            metadata = _read_report(meta, root, deadline=deadline, cancel=cancel)
        finally:
            meta.close()
        artifacts = metadata.get("artifacts")
        if metadata.get("id") != case.id or not isinstance(artifacts, list):
            raise _invalid()
        matches = []
        for n, artifact in enumerate(artifacts):
            if n % 256 == 0:
                _check(deadline, cancel)
            if not isinstance(artifact, dict):
                raise _invalid()
            if artifact.get("path") == firmware_result_path:
                matches.append(artifact)
                if len(matches) > 1:
                    raise _invalid()
        if len(matches) != 1:
            raise _invalid()
        artifact = matches[0]
        if (artifact.get("kind") != "triage-report" or artifact.get("producer") != "fwtriage-mcp"
                or artifact.get("is_dir") is not False or not isinstance(artifact.get("id"), str)
                or _ART_ID.fullmatch(artifact["id"]) is None or not _sha(artifact.get("sha256"))
                or type(artifact.get("size")) is not int or not 0 < artifact["size"] <= MAX_REPORT_BYTES):
            raise _invalid()
        count = 0
        for n, candidate in enumerate(artifacts):
            if n % 256 == 0:
                _check(deadline, cancel)
            if candidate.get("id") == artifact["id"]:
                count += 1
        if count != 1:
            raise _invalid()
        artifact = {k: artifact[k] for k in ("id", "size", "sha256")}
        del metadata, artifacts, matches
        for path, readonly in ((firmware_result_path, False), (fs_list_path, True)):
            reports.append(_open_report(root, path, readonly=readonly))
        if sum(r.seal.st_size for r in reports) > MAX_TOTAL_BYTES:
            raise _limit()
        if reports[0].seal.st_size != artifact["size"]:
            raise _invalid()
        firmware = _read_report(reports[0], root, deadline=deadline, cancel=cancel, expected_sha=artifact["sha256"])
        if (firmware.get("schema") != "pweh.fwtriage.sd-surface/v1"
                or firmware.get("tool") != "fw_sd_surface" or firmware.get("case_id") != case.id
                or not isinstance(firmware.get("producer"), str)
                or re.fullmatch(r"fwtriage-mcp [0-9][A-Za-z0-9.+_-]{0,63}", firmware["producer"]) is None):
            raise _invalid()
        firmware = {k: v for k, v in firmware.items() if k in _FW_KEYS}
        listing = _read_report(reports[1], root, deadline=deadline, cancel=cancel, expected_sha=expected[4])
        if (listing.get("schema") != "pweh.forensics.fs-list/v1"
                or listing.get("evidence_id") != ev or "archive" in listing
                or ("evidence_sha256" in listing and listing["evidence_sha256"] != opened.intake["hashes"]["sha256"])):
            raise _invalid()
        listing = {k: v for k, v in listing.items() if k in _LIST_KEYS}
        source = {"kind": "evidence", "evidence_id": ev, "evidence_sha256": opened.intake["hashes"]["sha256"],
                  "firmware": {"path": firmware_result_path, "sha256": reports[0].sha256, "size": reports[0].seal.st_size,
                               "artifact_id": artifact["id"], "origin_basis": "case-artifact-index"},
                  "listing": {"path": fs_list_path, "sha256": reports[1].sha256, "size": reports[1].seal.st_size,
                              "custody_seq": expected[2], "custody_hash": expected[3], "origin_basis": "evidence-custody-list"}}
        inputs = Inputs(case, root, reports, firmware, listing, source, deadline, cancel, expected)
        inputs.check()
        _check(deadline, cancel)
    except (OSError, safeio.UnsafeFile):
        for report in reports:
            report.close()
        if root is not None:
            os.close(root)
        raise _invalid() from None
    except BaseException:
        for report in reports:
            report.close()
        if root is not None:
            os.close(root)
        raise
    try:
        yield inputs
    finally:
        for report in reports:
            report.close()
        with contextlib.suppress(OSError):
            os.close(root)
