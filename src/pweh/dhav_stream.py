"""열린 EV의 bounded DHAV 검색. record bytes의 SHA와 추출 권위는 후속 구간 검사에 둔다."""

from __future__ import annotations

from dataclasses import dataclass, fields
import math
import struct
import time
from typing import Callable

from .dhav import FALSE_FIELDS, REJECTIONS, LIMITATIONS as _RECORD_LIMITATIONS
from .errors import PwehError, ValidationFailed

SCHEMA = "pweh.dhav-scan/v1"
PROFILE = "dhav-stream-framing-v1"
INCOMPLETE = ("truncated_header", "record_beyond_evidence")
LIMIT_REASONS = ("scan_byte_limit", "probe_limit", "candidate_limit", "structure_byte_limit", "output_limit", "time_limit")
REASONS = (*LIMIT_REASONS, "record_framing_incomplete", "record_size_limit")
LIMITATIONS = (*_RECORD_LIMITATIONS, "evidence_bytes_only", "allocation_state_unexamined",
               "record_bytes_not_hashed", "range_revalidation_required_before_extract", "intake_hash_not_reverified")
MAX_EVIDENCE_SIZE = (1 << 63) - 1
MAX_SCAN_BYTES = 1 << 30
MAX_RECORD_BYTES = 64 << 20
_WINDOW = 65536
_ENVELOPE = 4096
_ROW = 512
_TYPES = {0xF0: "type_f0", 0xFC: "type_fc", 0xFD: "type_fd"}


@dataclass(frozen=True)
class DhavScanLimits:
    """운영 기본 상한을 낮출 수만 있다. 검색 read 예산은 별도 명시 인자로 받는다."""

    max_anchor_probes: int = 1024
    max_candidates: int = 128
    max_structure_bytes: int = 1 << 20
    max_output_bytes: int = 1 << 20


class _Limit(Exception):
    def __init__(self, reason: str):
        self.reason = reason


def _integer(value, low: int, high: int) -> int:
    if type(value) is not int or not low <= value <= high:
        raise ValueError()
    return value


def _new(size: int, start: int, scan_bytes: int) -> dict:
    return {"schema": SCHEMA, "profile": PROFILE, "status": "unsupported",
            **dict.fromkeys(FALSE_FIELDS, False),
            "summary": {"anchors_observed": 0, "anchors_rejected": 0, "incomplete_anchors": 0,
                        "oversize_anchors": 0, "candidates_reported": 0,
                        "anchor_rejections": dict.fromkeys(REJECTIONS, 0),
                        "anchor_incomplete": dict.fromkeys(INCOMPLETE, 0)},
            "coverage": {"evidence_size": size, "start_offset": start, "max_scan_bytes": scan_bytes,
                         "search_positions_total": max(0, size - 3),
                         "positions_before_start": min(start, max(0, size - 3)),
                         "search_positions_examined": 0, "unexamined_positions": None,
                         "pending_anchor_offset": None, "next_offset": None,
                         "search_complete": True, "whole_evidence_search_complete": start == 0,
                         "candidate_checks_complete": True, "candidate_list_complete": True,
                         "anchor_probes": 0, "search_bytes_read": 0, "search_read_calls": 0,
                         "structure_bytes_read": 0, "structure_read_calls": 0,
                         "total_bytes_read": 0, "reasons": []},
            "candidates": [], "limitations": list(LIMITATIONS)}


class _Scanner:
    def __init__(self, read_at, size, start, scan_bytes, limits, deadline, cancel):
        self.read_at, self.size, self.start = read_at, size, start
        self.scan_bytes, self.limits, self.deadline, self.cancel = scan_bytes, limits, deadline, cancel
        self.report = _new(size, start, scan_bytes)
        self.summary, self.cov, self.rows = (self.report[key] for key in ("summary", "coverage", "candidates"))

    def check(self, *, timing=True):
        if self.cancel is not None:
            try:
                cancelled = self.cancel()
            except Exception:
                raise PwehError("DHAV 검색의 취소 상태를 확인하지 못했습니다.", code="dhav_scan_failed") from None
            if type(cancelled) is not bool:
                raise PwehError("DHAV 검색의 취소 상태를 확인하지 못했습니다.", code="dhav_scan_failed") from None
            if cancelled:
                raise PwehError("DHAV 검색이 취소되었습니다.", code="cancelled") from None
        if timing and time.monotonic() >= self.deadline:
            raise _Limit("time_limit")

    def read(self, offset, size, *, structure=True):
        self.check()
        if not 0 <= offset <= self.size or not 1 <= size <= min(_WINDOW, self.size - offset):
            raise ValidationFailed("DHAV 검색 읽기 범위가 올바르지 않습니다.") from None
        name = "structure" if structure else "search"
        cap = self.limits.max_structure_bytes if structure else self.scan_bytes
        if self.cov[name + "_bytes_read"] + size > cap:
            raise _Limit("structure_byte_limit" if structure else "scan_byte_limit")
        try:
            result = self.read_at(offset, size)
        except Exception:
            raise PwehError("DHAV 검색 입력을 읽지 못했습니다.", code="dhav_scan_read_failed") from None
        if type(result) is not bytes or len(result) != size:
            raise PwehError("DHAV 검색 입력을 읽지 못했습니다.", code="dhav_scan_read_failed") from None
        self.cov[name + "_bytes_read"] += size
        self.cov[name + "_read_calls"] += 1
        self.cov["total_bytes_read"] += size
        return result

    def probe(self, offset):
        self.check()
        if self.cov["anchor_probes"] >= self.limits.max_anchor_probes:
            raise _Limit("probe_limit")
        # 출력할 수 없는 다음 anchor는 probe 전 pending으로 남겨 재개 때 누락하지 않는다.
        if len(self.rows) >= self.limits.max_candidates:
            raise _Limit("candidate_limit")
        if _ENVELOPE + (len(self.rows) + 1) * _ROW > self.limits.max_output_bytes:
            raise _Limit("output_limit")
        self.cov["anchor_probes"] += 1
        remaining = self.size - offset
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
            return "incomplete", "record_beyond_evidence"
        if length > MAX_RECORD_BYTES:
            return "oversize", None
        footer = self.read(offset + length - 8, 8)
        if footer[:4] != b"dhav":
            return "rejected", "footer_missing"
        if struct.unpack_from("<I", footer, 4)[0] != length:
            return "rejected", "footer_length_mismatch"
        return "supported", {"index": len(self.rows), "offset": offset, "record_length": length,
                             "header_length": header, "extension_length": extension,
                             "payload_length": length - header - 8, "record_type": kind,
                             "footer_length_matches": True, "confidence": "possible"}

    def scan(self):
        total = self.cov["search_positions_total"]
        cursor = self.cov["positions_before_start"]
        read_position, end = self.start, min(self.size, self.start + self.scan_bytes)
        carry, pending, stop_reason, reasons = b"", None, None, set()
        self.check(timing=False)
        try:
            while cursor < total:
                self.check()
                if read_position >= end:
                    raise _Limit("scan_byte_limit")
                chunk = self.read(read_position, min(_WINDOW, end - read_position), structure=False)
                base = read_position - len(carry)
                window = carry + chunk
                read_position += len(chunk)
                positions_end = min(total, read_position - 3)
                while cursor < positions_end:
                    self.check()
                    found = window.find(b"DHAV", cursor - base, positions_end - base + 3)
                    if found < 0:
                        cursor = positions_end
                        break
                    cursor = pending = base + found
                    self.summary["anchors_observed"] += 1
                    outcome, result = self.probe(cursor)
                    self.check()
                    if outcome == "supported":
                        self.rows.append(result)
                        self.summary["candidates_reported"] += 1
                    elif outcome == "rejected":
                        self.summary["anchors_rejected"] += 1
                        self.summary["anchor_rejections"][result] += 1
                    elif outcome == "incomplete":
                        self.summary["incomplete_anchors"] += 1
                        self.summary["anchor_incomplete"][result] += 1
                        reasons.add("record_framing_incomplete")
                    else:
                        self.summary["oversize_anchors"] += 1
                        reasons.add("record_size_limit")
                    cursor += 1
                    pending = None
                carry = window[-3:]
        except _Limit as stop:
            stop_reason = stop.reason
            reasons.add(stop.reason)
        if cursor < total:
            self.cov["unexamined_positions"] = {"start": cursor, "count": total - cursor, "reason": stop_reason}
            self.cov["next_offset"] = cursor
        self.cov["pending_anchor_offset"] = pending
        self.cov["search_positions_examined"] = cursor - self.cov["positions_before_start"]
        self.cov["search_complete"] = cursor == total
        self.cov["whole_evidence_search_complete"] = self.start == 0 and cursor == total
        self.cov["candidate_checks_complete"] = (pending is None and self.summary["incomplete_anchors"] == 0
                                                   and self.summary["oversize_anchors"] == 0)
        self.cov["candidate_list_complete"] = self.cov["search_complete"] and self.cov["candidate_checks_complete"]
        self.cov["reasons"] = [reason for reason in REASONS if reason in reasons]
        if reasons:
            self.report["status"] = "partial"
        elif self.rows:
            self.report["status"] = "ok"
        self.check(timing=False)
        return self.report


def scan_dhav_stream(read_at, *, evidence_size: int, start_offset: int = 0,
                     max_scan_bytes: int = MAX_SCAN_BYTES, limits: DhavScanLimits = DhavScanLimits(),
                     deadline: float, cancel: Callable[[], bool] | None = None) -> dict:
    """작은 read callback으로 EV 전체 후보 시작점을 검색한다. source/params는 어댑터가 결속한다."""
    try:
        _integer(evidence_size, 1, MAX_EVIDENCE_SIZE)
        _integer(start_offset, 0, evidence_size)
        _integer(max_scan_bytes, 4, MAX_SCAN_BYTES)
        if not callable(read_at) or type(limits) is not DhavScanLimits:
            raise ValueError()
        defaults = DhavScanLimits()
        for field in fields(defaults):
            _integer(getattr(limits, field.name), 8192 if field.name == "max_output_bytes" else 1,
                     getattr(defaults, field.name))
        if type(deadline) not in (int, float) or not math.isfinite(deadline):
            raise ValueError()
        if cancel is not None and not callable(cancel):
            raise ValueError()
    except (ValueError, OverflowError, TypeError):
        raise ValidationFailed("DHAV 검색 입력·상한·deadline이 올바르지 않습니다.") from None
    return _Scanner(read_at, evidence_size, start_offset, max_scan_bytes, limits,
                    min(deadline, time.monotonic() + 45), cancel).scan()


def validate_dhav_scan_accounting(report: dict) -> None:
    """shape는 schema가 닫는다. 여기서는 원문 없는 유한한 수치·재개·완료 관계만 대조한다."""
    try:
        def require(value):
            if not value:
                raise ValueError()
        require(type(report) is dict)
        s, c, rows = (report[k] for k in ("summary", "coverage", "candidates"))
        require(type(s) is dict and type(c) is dict and type(rows) is list and len(rows) <= 128)
        n = _integer(c["evidence_size"], 1, MAX_EVIDENCE_SIZE)
        start = _integer(c["start_offset"], 0, n)
        budget = _integer(c["max_scan_bytes"], 4, MAX_SCAN_BYTES)
        total = _integer(c["search_positions_total"], 0, MAX_EVIDENCE_SIZE)
        before = _integer(c["positions_before_start"], 0, total)
        examined = _integer(c["search_positions_examined"], 0, total)
        require(total == max(0, n - 3) and before == min(start, total))
        cursor = before + examined
        require(cursor <= total)
        observed = _integer(s["anchors_observed"], 0, 1025)
        rejected = _integer(s["anchors_rejected"], 0, 1024)
        incomplete = _integer(s["incomplete_anchors"], 0, 1024)
        oversized = _integer(s["oversize_anchors"], 0, 1024)
        reported = _integer(s["candidates_reported"], 0, 128)
        require(rejected == sum(_integer(s["anchor_rejections"][k], 0, 1024) for k in REJECTIONS))
        require(incomplete == sum(_integer(s["anchor_incomplete"][k], 0, 1024) for k in INCOMPLETE))
        pending = c["pending_anchor_offset"]
        if pending is not None:
            require(_integer(pending, 0, total - 1) == cursor)
        require(observed == rejected + incomplete + oversized + reported + int(pending is not None))
        require(reported == len(rows))
        probes = _integer(c["anchor_probes"], 0, 1024)
        require(observed - int(pending is not None) <= probes <= observed)
        search = _integer(c["search_bytes_read"], 0, min(budget, n - start))
        structure = _integer(c["structure_bytes_read"], 0, 1 << 20)
        search_calls = _integer(c["search_read_calls"], 0, (budget + _WINDOW - 1) // _WINDOW)
        structure_calls = _integer(c["structure_read_calls"], 0, 4096)
        require(c["total_bytes_read"] == _integer(c["total_bytes_read"], 0, budget + (1 << 20)) == search + structure)
        require((search == 0) == (search_calls == 0) and search_calls <= search <= search_calls * _WINDOW)
        require((structure == 0) == (structure_calls == 0) and structure_calls <= structure <= structure_calls * 8)
        require(structure_calls <= probes * 4)
        # 확정된 분류별 최소 read를 대조한다. 짧은 header는 type을 읽기 전/후 둘 다 가능하다.
        rejection = s["anchor_rejections"]
        length_rejected = rejection["length_below_header_and_footer"] + rejection["empty_payload"]
        footer_rejected = rejection["footer_missing"] + rejection["footer_length_mismatch"]
        beyond = s["anchor_incomplete"]["record_beyond_evidence"]
        short = s["anchor_incomplete"]["truncated_header"]
        known_calls = (4 * (reported + footer_rejected) + 3 * (oversized + length_rejected + beyond)
                       + rejection["unsupported_record_type"])
        known_bytes = (14 * (reported + footer_rejected) + 6 * (oversized + length_rejected + beyond)
                       + rejection["unsupported_record_type"])
        require(known_calls <= structure_calls <= known_calls + short + 4 * int(pending is not None))
        require(known_bytes <= structure <= known_bytes + short + 14 * int(pending is not None))
        require(examined <= max(0, search - 3))
        if pending is not None:
            require(pending + 4 <= start + search)
        reasons = c["reasons"]
        require(type(reasons) is list and reasons == [r for r in REASONS if r in reasons])
        require(("record_framing_incomplete" in reasons) == (incomplete > 0))
        require(("record_size_limit" in reasons) == (oversized > 0))
        stop = [r for r in LIMIT_REASONS if r in reasons]
        require(len(stop) <= 1)
        if cursor == total:
            require(c["unexamined_positions"] is None and c["next_offset"] is None and not stop)
        else:
            require(len(stop) == 1)
            u = c["unexamined_positions"]
            require(type(u) is dict and _integer(u["start"], 0, total) == cursor
                    and _integer(u["count"], 1, total) == total - cursor and u["reason"] == stop[0])
            require(_integer(c["next_offset"], 0, n) == cursor)
        for name in ("search_complete", "whole_evidence_search_complete", "candidate_checks_complete", "candidate_list_complete"):
            require(type(c[name]) is bool)
        checks = pending is None and incomplete == 0 and oversized == 0
        require(c["search_complete"] == (cursor == total))
        require(c["whole_evidence_search_complete"] == (start == 0 and cursor == total))
        require(c["candidate_checks_complete"] == checks)
        require(c["candidate_list_complete"] == (cursor == total and checks))
        require(report["status"] == ("partial" if reasons else "ok" if rows else "unsupported"))
        require(all(report[name] is False for name in FALSE_FIELDS))
        previous = -1
        for index, row in enumerate(rows):
            require(type(row) is dict and _integer(row["index"], 0, 127) == index)
            offset = _integer(row["offset"], start, n - 1)
            length = _integer(row["record_length"], 33, MAX_RECORD_BYTES)
            extension = _integer(row["extension_length"], 0, 255)
            header = _integer(row["header_length"], 24, 279)
            payload = _integer(row["payload_length"], 1, MAX_RECORD_BYTES - 32)
            require(previous < offset < cursor and offset + length <= n)
            require(header == 24 + extension and length == header + payload + 8)
            require(row["footer_length_matches"] is True and row["confidence"] == "possible"
                    and row["record_type"] in _TYPES.values())
            previous = offset
        if "source" in report:
            require(_integer(report["source"]["evidence_size"], 1, MAX_EVIDENCE_SIZE) == n)
        if "params" in report:
            require(_integer(report["params"]["start_offset"], 0, n) == start
                    and _integer(report["params"]["max_scan_bytes"], 4, MAX_SCAN_BYTES) == budget)
    except (KeyError, TypeError, ValueError, OverflowError):
        raise ValidationFailed("DHAV 검색 보고서의 수치·완료 회계가 올바르지 않습니다.") from None
