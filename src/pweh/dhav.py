"""선택 bytes의 제한된 DHAV record 경계 후보. 본문 의미·시각·checksum은 해석하지 않는다."""

from __future__ import annotations

from dataclasses import dataclass, fields
import math
import struct
import time
from typing import Callable

from .errors import PwehError, ValidationFailed

SCHEMA = "pweh.dhav-candidates/v1"
PROFILE = "dhav-record-framing-v1"
RANGE_PROFILE = "dhav-record-ev-range-v1"
REJECTIONS = ("unsupported_record_type", "length_below_header_and_footer", "empty_payload",
              "footer_missing", "footer_length_mismatch")
INCOMPLETE = ("truncated_header", "record_beyond_selection")
LIMIT_REASONS = ("probe_limit", "candidate_limit", "structure_byte_limit", "output_limit", "time_limit")
REASONS = (*LIMIT_REASONS, "record_framing_incomplete", "selection_uncertain", "container_listing_incomplete")
LIMITATIONS = ("record_framing_subset_only", "payload_semantics_unexamined", "extension_fields_unexamined",
               "header_checksum_unverified", "original_file_boundary_unknown", "no_media_type_confirmation",
               "no_playback_time_or_encryption_validation")
RANGE_LIMITATIONS = ("explicit_evidence_range_only", "outside_range_unexamined")
FALSE_FIELDS = ("payload_semantics_examined", "extension_fields_examined", "checksum_verified", "media_decoded",
                "playback_verified", "recording_time_verified", "encryption_assessed",
                "original_file_boundary_verified", "complete_recording")
_TYPES = {0xF0: "type_f0", 0xFC: "type_fc", 0xFD: "type_fd"}
_WINDOW = 65536
_ENVELOPE_RESERVE = 4096
_ROW_RESERVE = 512


@dataclass(frozen=True)
class DhavLimits:
    """기본 상한을 낮출 수만 있다. 출력 봉투를 위해 최소8192bytes를 둔다."""

    max_input_bytes: int = 64 << 20
    max_anchor_probes: int = 1024
    max_candidates: int = 128
    max_structure_bytes: int = 1 << 20
    max_output_bytes: int = 1 << 20


class _Limit(Exception):
    def __init__(self, reason: str):
        self.reason = reason


def _new(size: int) -> dict:
    return {"schema": SCHEMA, "profile": PROFILE, "status": "unsupported",
            **dict.fromkeys(FALSE_FIELDS, False),
            "summary": {"anchors_observed": 0, "anchors_rejected": 0, "incomplete_anchors": 0,
                        "supported_anchors": 0, "candidates_reported": 0, "candidates_omitted": 0,
                        "anchor_rejections": dict.fromkeys(REJECTIONS, 0),
                        "anchor_incomplete": dict.fromkeys(INCOMPLETE, 0)},
            "coverage": {"input_bytes": size, "search_positions_total": max(0, size - 3),
                         "search_positions_examined": 0, "unexamined_positions": None,
                         "pending_anchor_offset": None, "search_complete": True,
                         "candidate_checks_complete": True, "candidate_list_complete": True,
                         "anchor_probes": 0, "structure_bytes_read": 0, "selection_uncertain": False,
                         "container_examined": False, "reasons": []},
            "candidates": [], "limitations": list(LIMITATIONS)}


class _Scanner:
    def __init__(self, data: bytes, limits: DhavLimits, deadline: float,
                 cancel: Callable[[], bool] | None):
        self.data, self.limits, self.deadline, self.cancel = data, limits, deadline, cancel
        self.report = _new(len(data))
        self.summary, self.cov, self.rows = (self.report[key] for key in ("summary", "coverage", "candidates"))

    def check(self, *, timing: bool = True) -> None:
        if self.cancel is not None:
            try:
                cancelled = self.cancel()
            except Exception:
                raise PwehError("DHAV 후보 검사의 취소 상태를 확인하지 못했습니다.",
                                code="dhav_candidates_failed") from None
            if type(cancelled) is not bool:
                raise PwehError("DHAV 후보 검사의 취소 상태를 확인하지 못했습니다.",
                                code="dhav_candidates_failed") from None
            if cancelled:
                raise PwehError("DHAV 후보 검사가 취소되었습니다.", code="cancelled") from None
        if timing and time.monotonic() >= self.deadline:
            raise _Limit("time_limit")

    def read(self, offset: int, size: int) -> bytes:
        # 원본 전체/payload는 복사하지 않는다. type·길이·extension 길이·footer만 읽는다.
        self.check()
        if self.cov["structure_bytes_read"] + size > self.limits.max_structure_bytes:
            raise _Limit("structure_byte_limit")
        self.cov["structure_bytes_read"] += size
        return self.data[offset:offset + size]

    def probe(self, offset: int) -> tuple[str, str | dict]:
        self.check()
        if self.cov["anchor_probes"] >= self.limits.max_anchor_probes:
            raise _Limit("probe_limit")
        self.cov["anchor_probes"] += 1
        remaining = len(self.data) - offset
        if remaining < 5:
            return "incomplete", "truncated_header"
        kind = _TYPES.get(self.read(offset + 4, 1)[0])
        if kind is None:
            return "rejected", "unsupported_record_type"
        if remaining < 24:
            return "incomplete", "truncated_header"
        length = struct.unpack("<I", self.read(offset + 12, 4))[0]
        extension = self.read(offset + 22, 1)[0]
        header = 24 + extension
        if length < header + 8:
            return "rejected", "length_below_header_and_footer"
        if length == header + 8:
            return "rejected", "empty_payload"
        if length > remaining:
            return "incomplete", "record_beyond_selection"
        footer = self.read(offset + length - 8, 8)
        if footer[:4] != b"dhav":
            return "rejected", "footer_missing"
        if struct.unpack_from("<I", footer, 4)[0] != length:
            return "rejected", "footer_length_mismatch"
        return "supported", {"index": len(self.rows), "offset": offset, "record_length": length,
                             "header_length": header, "extension_length": extension,
                             "payload_length": length - header - 8, "record_type": kind,
                             "footer_length_matches": True, "confidence": "possible"}

    def scan(self) -> dict:
        position, total = 0, self.cov["search_positions_total"]
        pending, reasons = None, set()
        self.check(timing=False)
        try:
            while position < total:
                self.check()
                # 시작 위치 창의 끝3bytes를 겹쳐 창을 가르는 DHAV도 한 번만 관찰한다.
                end = min(total, position + _WINDOW - 3)
                found = self.data.find(b"DHAV", position, end + 3)
                if found < 0:
                    position = end
                    continue
                position = pending = found
                self.summary["anchors_observed"] += 1
                outcome, result = self.probe(position)
                self.check()
                if outcome == "supported":
                    stop = None
                    if len(self.rows) >= self.limits.max_candidates:
                        stop = "candidate_limit"
                    elif _ENVELOPE_RESERVE + (len(self.rows) + 1) * _ROW_RESERVE > self.limits.max_output_bytes:
                        stop = "output_limit"
                    # 완전 검증했지만 출력하지 못한 후보는 미완료 pending과 구별한다.
                    self.summary["supported_anchors"] += 1
                    if stop is not None:
                        self.summary["candidates_omitted"] += 1
                        position += 1
                        pending = None
                        raise _Limit(stop)
                    self.rows.append(result)
                    self.summary["candidates_reported"] += 1
                elif outcome == "rejected":
                    self.summary["anchors_rejected"] += 1
                    self.summary["anchor_rejections"][result] += 1
                else:
                    self.summary["incomplete_anchors"] += 1
                    self.summary["anchor_incomplete"][result] += 1
                    reasons.add("record_framing_incomplete")
                position += 1
                pending = None
        except _Limit as stop:
            reasons.add(stop.reason)
            self.cov["unexamined_positions"] = {"start": position, "count": total - position,
                                                "reason": stop.reason}
        self.cov["pending_anchor_offset"] = pending
        self.cov["search_positions_examined"] = position
        self.cov["search_complete"] = position == total
        self.cov["candidate_checks_complete"] = pending is None and self.summary["incomplete_anchors"] == 0
        self.cov["candidate_list_complete"] = (self.cov["search_complete"] and self.cov["candidate_checks_complete"]
                                                and self.summary["candidates_omitted"] == 0)
        self.cov["reasons"] = [reason for reason in REASONS if reason in reasons]
        if reasons:
            self.report["status"] = "partial"
        elif self.rows:
            self.report["status"] = "ok"
        self.check(timing=False)
        return self.report


def scan_dhav_candidates(data: bytes, *, limits: DhavLimits = DhavLimits(), deadline: float,
                         cancel: Callable[[], bool] | None = None) -> dict:
    """고정 DHAV subset의 경계 후보만 반환한다. 원시 식별자·본문·개별 hash는 내보내지 않는다."""
    if type(data) is not bytes or type(limits) is not DhavLimits:
        raise ValidationFailed("DHAV 후보 검사 입력 형식이 올바르지 않습니다.") from None
    defaults = DhavLimits()
    for field in fields(defaults):
        value = getattr(limits, field.name)
        low = 8192 if field.name == "max_output_bytes" else 1
        if type(value) is not int or not low <= value <= getattr(defaults, field.name):
            raise ValidationFailed("DHAV 후보 검사 상한이 올바르지 않습니다.") from None
    finite = False
    if type(deadline) in (int, float):
        try:
            finite = math.isfinite(deadline)
        except OverflowError:
            pass
    if not finite:
        raise ValidationFailed("DHAV 후보 검사 deadline이 올바르지 않습니다.") from None
    if cancel is not None and not callable(cancel):
        raise ValidationFailed("DHAV 후보 검사 취소 함수가 올바르지 않습니다.") from None
    if len(data) > limits.max_input_bytes:
        raise ValidationFailed("DHAV 후보 검사 입력 크기 상한을 넘었습니다.") from None
    return _Scanner(data, limits, min(deadline, time.monotonic() + 45), cancel).scan()


def _integer(value, cap: int, low: int = 0) -> int:
    if type(value) is not int or not low <= value <= cap:
        raise ValueError()
    return value


def _require(value: bool) -> None:
    if not value:
        raise ValueError()


def validate_dhav_accounting(report: dict) -> None:
    """닫힌 shape는 schema가 검사한다. 여기서는 선택 출처 없이 유한한 수치·완료 관계만 본다."""
    try:
        _require(type(report) is dict)
        summary, cov, rows = report["summary"], report["coverage"], report["candidates"]
        _require(type(summary) is dict and type(cov) is dict and type(rows) is list and len(rows) <= 128)
        observed = _integer(summary["anchors_observed"], 1025)
        rejected = _integer(summary["anchors_rejected"], 1024)
        incomplete = _integer(summary["incomplete_anchors"], 1024)
        supported = _integer(summary["supported_anchors"], 1024)
        reported = _integer(summary["candidates_reported"], 128)
        omitted = _integer(summary["candidates_omitted"], 1)
        _require(type(summary["anchor_rejections"]) is dict and type(summary["anchor_incomplete"]) is dict)
        _require(rejected == sum(_integer(summary["anchor_rejections"][r], 1024) for r in REJECTIONS))
        _require(incomplete == sum(_integer(summary["anchor_incomplete"][r], 1024) for r in INCOMPLETE))
        size = _integer(cov["input_bytes"], 64 << 20)
        total = _integer(cov["search_positions_total"], 64 << 20)
        cursor = _integer(cov["search_positions_examined"], total)
        probes = _integer(cov["anchor_probes"], 1024)
        _integer(cov["structure_bytes_read"], 1 << 20)
        _require(total == max(0, size - 3))
        pending = cov["pending_anchor_offset"]
        if pending is not None:
            _require(_integer(pending, max(0, size - 4)) == cursor < total)
        _require(supported == reported + omitted and reported == len(rows))
        _require(observed == rejected + incomplete + supported + int(pending is not None))
        _require(observed - int(pending is not None) <= probes <= observed)
        for name in ("search_complete", "candidate_checks_complete", "candidate_list_complete",
                     "selection_uncertain", "container_examined"):
            _require(type(cov[name]) is bool)
        _require(cov["container_examined"] is False and all(report[name] is False for name in FALSE_FIELDS))
        _require(cov["search_complete"] == (cursor == total))
        _require(cov["candidate_checks_complete"] == (pending is None and incomplete == 0))
        _require(cov["candidate_list_complete"] == (cursor == total and pending is None
                                                   and incomplete == 0 and omitted == 0))
        reasons = cov["reasons"]
        _require(type(reasons) is list and len(reasons) <= len(REASONS))
        _require(all(type(reason) is str and reason in REASONS for reason in reasons))
        _require(reasons == [reason for reason in REASONS if reason in reasons])
        _require(("record_framing_incomplete" in reasons) == (incomplete > 0))
        _require(("selection_uncertain" in reasons) == cov["selection_uncertain"])
        limited = [reason for reason in LIMIT_REASONS if reason in reasons]
        unexamined = cov["unexamined_positions"]
        if cursor == total:
            _require(unexamined is None and not limited)
        else:
            _require(type(unexamined) is dict and len(limited) == 1)
            _require(_integer(unexamined["start"], total) == cursor)
            _require(_integer(unexamined["count"], total, 1) == total - cursor)
            _require(unexamined["reason"] == limited[0])
        _require(bool(omitted) == bool(set(limited) & {"candidate_limit", "output_limit"}))
        if omitted:
            _require(pending is None)
        previous = -1
        for index, row in enumerate(rows):
            _require(type(row) is dict and _integer(row["index"], 127) == index)
            offset = _integer(row["offset"], size)
            length = _integer(row["record_length"], 64 << 20, 33)
            header = _integer(row["header_length"], 279, 24)
            extension = _integer(row["extension_length"], 255)
            payload = _integer(row["payload_length"], 64 << 20, 1)
            _require(previous < offset < cursor and length <= size - offset)
            _require(header == 24 + extension and length == header + payload + 8)
            _require(row["footer_length_matches"] is True)
            previous = offset
        expected = "partial" if reasons else "ok" if rows else "unsupported"
        _require(report["status"] == expected)
    except (KeyError, TypeError, ValueError, OverflowError):
        raise ValidationFailed("DHAV 후보 보고서의 수치 또는 완료 관계가 올바르지 않습니다.") from None
