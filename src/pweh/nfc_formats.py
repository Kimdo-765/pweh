"""Flipper v4 파일 선언의 제한된 NFC 구조·페이지 diff. 장치나 파일을 열지 않는다."""
from __future__ import annotations

import json
import math
import re
import time
from dataclasses import dataclass, fields
from typing import Callable

from .errors import PwehError

__all__ = ["NfcLimits", "inspect_nfc", "diff_nfc"]

_LIMITATIONS = ("file_claims_only", "physical_read_not_verified",
                "password_pack_readback_not_observable", "no_tag_authorization_inferred")
_MODELS = {"NTAG213": ("ntag213", 45), "NTAG215": ("ntag215", 135),
           "NTAG216": ("ntag216", 231)}
_COMMON = {"Filetype", "Version", "Device type", "UID", "ATQA", "SAK"}
_NTAG = {"Data format version", "NTAG/Ultralight type", "Signature", "Mifare version",
         "Pages total", "Pages read", *(f"Counter {n}" for n in range(3)),
         *(f"Tearing {n}" for n in range(3))}
_HEX = re.compile(r"[0-9a-fA-F]{2}(?:[ \t]+[0-9a-fA-F]{2})*")
_DECIMAL = re.compile(r"[0-9]+")
_clock = time.monotonic


@dataclass(frozen=True)
class NfcLimits:
    """각 상한은 기본값 이하 양의 정수다. 출력은 최소 4096 bytes다."""

    max_input_bytes: int = 1 << 20
    max_lines: int = 4096
    max_line_bytes: int = 8192
    max_pages: int = 512
    max_changes: int = 512
    max_output_bytes: int = 64 << 10


class _Stop(Exception):
    """원문을 보유하지 않는 내부 판정."""

    def __init__(self, status: str, reason: str):
        self.status, self.reason = status, reason
        super().__init__(reason)


def _error(code: str) -> PwehError:
    return PwehError("NFC 구조 검사 요청을 완료하지 못했습니다.", code=code)


def _size(value: object) -> int:
    return len(json.dumps(value, ensure_ascii=True, separators=(",", ":"), allow_nan=False))


class _Control:
    def __init__(self, deadline: float, cancel: Callable[[], bool] | None):
        self.deadline, self.cancel = deadline, cancel

    def check(self) -> None:
        # 사용자 callback 예외는 except 밖에서 새 고정 오류로 바꿔 context도 남기지 않는다.
        failed = False
        cancelled = False
        if self.cancel is not None:
            try:
                answer = self.cancel()
                if type(answer) is bool:
                    cancelled = answer
                else:
                    failed = True
            except Exception:
                failed = True
        if failed:
            raise _error("callback_error")
        if cancelled:
            raise _error("cancelled")
        if _clock() >= self.deadline:
            raise _Stop("partial", "time_limit")


def _arguments(inputs: tuple[bytes, ...], limits: NfcLimits, deadline: float,
               cancel: Callable[[], bool] | None) -> _Control:
    if any(type(data) is not bytes for data in inputs):
        raise _error("invalid_input")
    if type(limits) is not NfcLimits:
        raise _error("invalid_limits")
    ceiling = NfcLimits()
    for field in fields(limits):
        value = getattr(limits, field.name)
        if type(value) is not int or not 0 < value <= getattr(ceiling, field.name):
            raise _error("invalid_limits")
    if limits.max_output_bytes < 4096:
        raise _error("invalid_limits")
    finite = False
    if type(deadline) in (int, float):
        try:
            finite = math.isfinite(deadline)
        except OverflowError:
            pass
    if not finite:
        raise _error("invalid_deadline")
    if cancel is not None and not callable(cancel):
        raise _error("callback_error")
    return _Control(min(deadline, _clock() + 5.0), cancel)


def _number(value: str, width: int, maximum: int) -> int:
    if not 0 < len(value) <= width or not _DECIMAL.fullmatch(value):
        raise _Stop("malformed", "invalid_decimal")
    number = int(value)
    if number > maximum:
        raise _Stop("malformed", "number_out_of_range")
    return number


def _hex(value: str, lengths: tuple[int, ...]) -> bytes:
    # 행 상한 뒤에도 토큰 수 상한을 확인하여 큰 임시 bytes를 만들지 않는다.
    if not _HEX.fullmatch(value):
        raise _Stop("malformed", "invalid_hex")
    tokens = value.split()
    if len(tokens) not in lengths:
        raise _Stop("malformed", "invalid_hex_length")
    return bytes(int(token, 16) for token in tokens)


class _Parsed:
    """raw 값은 이 private 객체에서만 보유하고 repr/공개 결과로 내보내지 않는다."""

    def __init__(self, size: int):
        self.profile = "unknown"
        self.status = "partial"
        self.device: str | None = None
        self.seen: set[str] = set()
        self.uid: bytes | None = None
        self.pages: dict[int, bytes] = {}
        self.counters: dict[int, int] = {}
        self.expected: int | None = None
        self.total: int | None = None
        self.read: int | None = None
        self.full = False
        self.coverage = {"input_bytes": size, "consumed_bytes": 0, "unexamined_bytes": size,
                         "lines_examined": 0, "input_exhausted": False, "missing_pages_count": None,
                         "duplicate_pages_count": 0, "invalid_page_records": 0,
                         "unknown_fields_count": 0, "read_mapping": "unknown", "truncated_reasons": []}

    def reason(self, reason: str) -> None:
        if reason not in self.coverage["truncated_reasons"]:
            self.coverage["truncated_reasons"].append(reason)

    def public(self) -> dict:
        return {"status": self.status, "profile": self.profile,
                "summary": {"uid_length": len(self.uid) if self.uid is not None else None,
                            "declared_total_pages": self.total, "declared_read_pages": self.read,
                            "stored_valid_pages": len(self.pages), "full_declared_pages": self.full},
                "coverage": dict(self.coverage, truncated_reasons=list(self.coverage["truncated_reasons"]))}

    def scalar(self, key: str, value: str) -> None:
        if key in self.seen:
            raise _Stop("malformed", "duplicate_field")
        self.seen.add(key)
        if key == "Filetype":
            if value != "Flipper NFC device":
                raise _Stop("unsupported", "unsupported_filetype")
        elif key == "Version":
            if _number(value, 10, 0xffffffff) != 4:
                raise _Stop("unsupported", "unsupported_version")
        elif key == "Device type":
            if value not in ("ISO14443-3A", "NTAG/Ultralight"):
                raise _Stop("unsupported", "unsupported_family")
            self.device = "iso" if value == "ISO14443-3A" else "ntag"
            if self.device == "iso":
                self.profile = "iso14443-3a"
        elif key == "UID":
            self.uid = _hex(value, (4, 7, 10))
        elif key == "ATQA":
            _hex(value, (2,))  # v4 MSB 텍스트 순서를 바꾸지 않는다.
        elif key == "SAK":
            _hex(value, (1,))
        elif key == "Data format version":
            if _number(value, 10, 0xffffffff) != 2:
                raise _Stop("unsupported", "unsupported_data_version")
        elif key == "NTAG/Ultralight type":
            if value not in _MODELS:
                raise _Stop("unsupported", "unsupported_layout")
            self.profile, self.expected = _MODELS[value]
        elif key == "Signature":
            _hex(value, (32,))
        elif key == "Mifare version":
            _hex(value, (8,))
        elif key == "Pages total":
            self.total = _number(value, 3, 512)
        elif key == "Pages read":
            self.read = _number(value, 3, 512)
        elif key.startswith("Counter "):
            self.counters[int(key[-1])] = _number(value, 10, 0xffffffff)
        elif key.startswith("Tearing "):
            _hex(value, (1,))
        elif key == "Failed authentication attempts":
            _number(value, 10, 0xffffffff)

    def line(self, line: str, limits: NfcLimits, control: _Control) -> None:
        for index, char in enumerate(line):
            if index % 2048 == 0:
                control.check()
            if (ord(char) < 32 and char != "\t") or 127 <= ord(char) <= 159 or char == "\ufeff":
                raise _Stop("malformed", "invalid_control")
        line = line.strip(" \t")
        if not line or line.startswith("#"):
            return
        if ":" not in line:
            raise _Stop("malformed", "invalid_field")
        key, value = (part.strip(" \t") for part in line.split(":", 1))
        if not key or not key.isascii():
            raise _Stop("malformed", "invalid_key")
        if key.startswith("Page "):
            try:
                index = _number(key[5:], 3, 511)
                if index in self.pages:
                    self.coverage["duplicate_pages_count"] += 1
                    raise _Stop("malformed", "duplicate_page")
                if len(self.pages) >= limits.max_pages:
                    raise _Stop("partial", "page_limit")
                self.pages[index] = _hex(value, (4,))
            except _Stop as stop:
                if stop.status == "malformed":
                    self.coverage["invalid_page_records"] += 1
                raise
        elif key in _COMMON or key in _NTAG or key == "Failed authentication attempts":
            self.scalar(key, value)
        elif key.startswith(("Counter ", "Tearing ")):
            raise _Stop("malformed", "invalid_field_index")
        else:
            self.coverage["unknown_fields_count"] += 1
            self.reason("unknown_field")

    def finish(self) -> None:
        if not _COMMON <= self.seen:
            raise _Stop("malformed", "missing_required_fields")
        if self.device == "iso":
            self.profile = "iso14443-3a"
            self.coverage["read_mapping"] = "not_applicable"
            if self.pages or self.seen & _NTAG or "Failed authentication attempts" in self.seen:
                raise _Stop("malformed", "unexpected_page_fields")
        else:
            if not _NTAG <= self.seen:
                raise _Stop("malformed", "missing_required_fields")
            if self.total != self.expected:
                raise _Stop("malformed", "claimed_total_mismatch")
            if self.read > self.total:
                raise _Stop("malformed", "read_out_of_range")
            outside = sum(index >= self.total for index in self.pages)
            if outside:
                self.coverage["invalid_page_records"] += outside
                raise _Stop("malformed", "page_out_of_range")
            missing = self.total - len(self.pages)
            self.coverage["missing_pages_count"] = missing
            if missing:
                raise _Stop("malformed", "missing_pages")
            if len(self.uid) != 7:
                self.reason("claimed_uid_length_mismatch")
            if self.read < self.total:
                self.reason("partial_read_mapping_unknown")
            if not self.coverage["truncated_reasons"]:
                self.full = True
                self.coverage["read_mapping"] = "all_declared"
        self.status = "partial" if self.coverage["truncated_reasons"] else "ok"


def _parse(data: bytes, limits: NfcLimits, control: _Control) -> _Parsed:
    parsed = _Parsed(len(data))
    consumed = 0
    try:
        control.check()
        if len(data) > limits.max_input_bytes:
            raise _Stop("partial", "input_limit")
        while consumed < len(data):
            control.check()
            if parsed.coverage["lines_examined"] >= limits.max_lines:
                raise _Stop("partial", "line_limit")
            search = consumed
            while True:
                control.check()
                bound = min(len(data), search + 4096, consumed + limits.max_line_bytes + 2)
                newline = data.find(b"\n", search, bound)
                if newline >= 0:
                    end, content_end = newline + 1, newline
                    if content_end > consumed and data[content_end - 1] == 13:
                        content_end -= 1
                    break
                if bound == len(data):
                    end = content_end = bound
                    break
                if bound == consumed + limits.max_line_bytes + 2:
                    raise _Stop("partial", "line_bytes_limit")
                search = bound
            if content_end - consumed > limits.max_line_bytes:
                raise _Stop("partial", "line_bytes_limit")
            raw = data[consumed:content_end]
            if consumed == 0 and raw.startswith(b"\xef\xbb\xbf"):
                raw = raw[3:]
            text = None
            try:
                text = raw.decode("utf-8", errors="strict")
            except UnicodeError:
                pass
            if text is None:
                consumed = end
                parsed.coverage["lines_examined"] += 1
                raise _Stop("malformed", "invalid_utf8")
            try:
                parsed.line(text, limits, control)
            except _Stop as stop:
                if stop.status != "partial":
                    consumed = end
                    parsed.coverage["lines_examined"] += 1
                raise
            consumed = end
            parsed.coverage["lines_examined"] += 1
        parsed.coverage["input_exhausted"] = True
        control.check()
        parsed.finish()
    except _Stop as stop:
        parsed.status = stop.status
        parsed.reason(stop.reason)
    parsed.coverage["consumed_bytes"] = consumed
    parsed.coverage["unexamined_bytes"] = len(data) - consumed
    return parsed


def _report(operation: str, parsed: _Parsed) -> dict:
    return {"schema_version": 1, "operation": operation, **parsed.public(),
            "limitations": list(_LIMITATIONS)}


def _region(page: int, byte: int, total: int) -> str:
    if page < 2 or page == 2 and byte < 2:
        return "manufacturer"
    if page == 2:
        return "static_lock"
    if page == 3:
        return "capability_container"
    if page < total - 5:
        return "user_data"
    if page == total - 5:
        return "dynamic_lock" if byte < 3 else "reserved"
    if page < total - 2:
        return "configuration"
    if page == total - 2 or byte < 2:
        return "credential_storage"
    return "reserved"


def _output(report: dict, limits: NfcLimits, control: _Control) -> dict:
    """큰 목록을 재직렬화하지 않고 상수 크기 봉투와 항목별 비용만 계산한다."""
    summary = report["summary"]
    changes = summary.get("changes", [])
    if "changes" in summary:
        summary["changes"] = []
    try:
        control.check()
        # 사유와 최종 count 폭 변화 공간을 미리 예약한다.
        remaining = limits.max_output_bytes - _size(report) - 512
        kept: list[dict] = []
        for item in changes:
            control.check()
            cost = _size(item) + int(bool(kept))
            if cost > remaining:
                report["coverage"]["changes_complete"] = False
                _output_reason(report, "output_limit")
                break
            remaining -= cost
            kept.append(item)
        if "changes" in summary:
            summary["changes"] = kept
            summary["changes_returned"] = len(kept)
            summary["changes_omitted"] = summary["changed_pages_count"] - len(kept) if summary["changed_pages_count"] is not None else None
        control.check()
    except _Stop:
        _output_reason(report, "time_limit")
        if "changes" in summary:
            summary["changes"] = []
            summary["changes_returned"] = 0
            summary["changes_omitted"] = summary["changed_pages_count"]
            report["coverage"]["changes_complete"] = False
    # 시간 만료에도 고정 크기 종결 결과를 반환한다. 입력을 다시 해석하지 않는다.
    if _size(report) > limits.max_output_bytes:
        raise _error("invalid_limits")
    return report


def _output_reason(report: dict, reason: str) -> None:
    coverage = report["coverage"]
    if reason not in coverage["truncated_reasons"]:
        coverage["truncated_reasons"].append(reason)
    if report["status"] == "ok":
        report["status"] = "partial"


def inspect_nfc(data: bytes, *, deadline: float, cancel: Callable[[], bool] | None = None,
                limits: NfcLimits = NfcLimits()) -> dict:
    """불변 bytes의 제한된 v4 구조만 검사한다. UID·페이지·비밀 원문은 반환하지 않는다."""
    control = _arguments((data,), limits, deadline, cancel)
    parsed = _parse(data, limits, control)
    return _output(_report("inspect", parsed), limits, control)


def diff_nfc(before: bytes, after: bytes, *, deadline: float, cancel: Callable[[], bool] | None = None,
             limits: NfcLimits = NfcLimits()) -> dict:
    """완전한 동일 claimed layout 두 파일의 저장 변화 위치만 비교한다."""
    control = _arguments((before, after), limits, deadline, cancel)
    left, right = _parse(before, limits, control), _parse(after, limits, control)
    statuses = {left.status, right.status}
    status = next((value for value in ("malformed", "partial", "unsupported") if value in statuses), "ok")
    summary = {"before": left.public(), "after": right.public(),
               "same_uid_claim": left.uid == right.uid if left.uid is not None and right.uid is not None
               and left.status != "malformed" and right.status != "malformed"
               and left.coverage["input_exhausted"] and right.coverage["input_exhausted"] else None,
               "device_association_verified": False, "comparison_basis": "stored_bytes_only",
               "pages_compared": 0, "stored_pages_equal": None, "changed_pages_count": None,
               "changes": [], "changes_returned": 0, "changes_omitted": None, "counter_fields_changed": None}
    coverage = {"input_bytes": len(before) + len(after),
                "consumed_bytes": left.coverage["consumed_bytes"] + right.coverage["consumed_bytes"],
                "unexamined_bytes": left.coverage["unexamined_bytes"] + right.coverage["unexamined_bytes"],
                "comparison_complete": False, "changes_complete": False,
                "changed_pages_count_is_lower_bound": False, "truncated_reasons": []}
    report = {"schema_version": 1, "operation": "diff", "status": status,
              "profile": left.profile if left.profile == right.profile else "unknown",
              "summary": summary, "coverage": coverage, "limitations": list(_LIMITATIONS)}
    if left.profile == "iso14443-3a" or right.profile == "iso14443-3a":
        if status == "ok":
            report["status"] = "unsupported"
        coverage["truncated_reasons"].append("no_page_layout")
    elif not left.full or not right.full:
        coverage["truncated_reasons"].append("ineligible_page_comparison")
    elif left.profile != right.profile or left.total != right.total:
        report["status"] = "unsupported"
        coverage["truncated_reasons"].append("layout_mismatch")
    else:
        summary["changed_pages_count"] = 0
        try:
            control.check()
            summary["counter_fields_changed"] = left.counters != right.counters
            for page in range(left.total):
                control.check()
                one, two = left.pages[page], right.pages[page]
                if one != two:
                    summary["changed_pages_count"] += 1
                    if len(summary["changes"]) < limits.max_changes:
                        regions = list(dict.fromkeys(_region(page, index, left.total)
                                                     for index in range(4) if one[index] != two[index]))
                        summary["changes"].append({"page": page, "regions": regions})
                summary["pages_compared"] += 1
            coverage["comparison_complete"] = True
            coverage["changes_complete"] = len(summary["changes"]) == summary["changed_pages_count"]
            summary["stored_pages_equal"] = summary["changed_pages_count"] == 0
            if not coverage["changes_complete"]:
                _output_reason(report, "change_limit")
        except _Stop:
            coverage["changed_pages_count_is_lower_bound"] = True
            _output_reason(report, "time_limit")
    return _output(report, limits, control)
