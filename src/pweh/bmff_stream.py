"""열린 EV에서 ftyp 시작점과 제한된 연속 박스 prefix를 관찰한다."""
from __future__ import annotations

from dataclasses import dataclass, fields
import math
import time
from typing import Callable

from . import media_candidates as B
from .errors import PwehError, ValidationFailed

SCHEMA = "pweh.bmff-scan/v1"
PROFILE = "ftyp-stream-prefix-v1"
MAX_EVIDENCE_SIZE = (1 << 63) - 1
MAX_SCAN_BYTES = 1 << 30
MAX_PREFIX_BYTES = 64 << 20
FALSE_FIELDS = ("media_decoded", "playback_verified", "recording_time_verified", "encryption_assessed",
                "format_conformance_assessed", "original_file_boundary_verified", "physical_carving_performed",
                "relations_assessed")
REJECTIONS = tuple("box_beyond_evidence" if r == "box_beyond_selection" else r for r in B.REJECTIONS)
LIMIT_REASONS = ("scan_byte_limit", *B.LIMIT_REASONS)
CHAIN_LIMITS = ("box_limit", "structure_byte_limit", "time_limit", "prefix_size_limit")
REASONS = (*LIMIT_REASONS, "prefix_size_limit", "candidate_framing_partial")
END_REASONS = tuple({"selection_end": "evidence_end", "box_beyond_selection": "box_beyond_evidence"}.get(r, r)
                    for r in B.END_REASONS) + ("prefix_size_limit",)
LIMITATIONS = ("top_level_framing_only", "payload_semantics_unexamined", "original_file_boundary_unknown",
               "candidate_relations_unexamined", "no_media_type_confirmation", "no_playback_time_or_encryption_validation",
               "evidence_bytes_only", "allocation_state_unexamined", "prefix_bytes_not_hashed",
               "range_revalidation_required_before_extract", "intake_hash_not_reverified")
_WINDOW, _ENVELOPE, _ROW = 65536, 4096, 1024
_Limit = B._Limit


@dataclass(frozen=True)
class BmffScanLimits:
    """한 호출에서 공유하는 기본 상한. 모든 값은 낮출 수만 있다."""

    max_anchor_probes: int = 1024
    max_candidates: int = 128
    max_boxes_per_candidate: int = 1024
    max_boxes_total: int = 8192
    max_brands_per_anchor: int = 64
    max_brands_total: int = 4096
    max_structure_bytes: int = 1 << 20
    max_output_bytes: int = 1 << 20


def _integer(value, low: int, high: int) -> int:
    if type(value) is not int or not low <= value <= high:
        raise ValueError()
    return value


def _new(size: int, start: int, scan_bytes: int) -> dict:
    return {"schema": SCHEMA, "profile": PROFILE, "status": "unsupported", **dict.fromkeys(FALSE_FIELDS, False),
            "summary": {"anchors_observed": 0, "anchors_rejected": 0, "oversize_anchors": 0,
                        "candidates_reported": 0, "chain_limited_candidates": 0,
                        "anchor_rejections": dict.fromkeys(REJECTIONS, 0)},
            "coverage": {"evidence_size": size, "start_offset": start, "max_scan_bytes": scan_bytes,
                         "search_positions_total": max(0, size - 7),
                         "positions_before_start": min(start, max(0, size - 7)),
                         "search_positions_examined": 0, "unexamined_positions": None,
                         "pending_anchor_offset": None, "next_offset": None,
                         "search_complete": True, "whole_evidence_search_complete": start == 0,
                         "candidate_checks_complete": True, "candidate_list_complete": True,
                         "anchor_probes": 0, "boxes_examined": 0, "brand_slots_examined": 0,
                         "search_bytes_read": 0, "search_read_calls": 0,
                         "structure_bytes_read": 0, "structure_read_calls": 0,
                         "total_bytes_read": 0, "reasons": []},
            "candidates": [], "limitations": list(LIMITATIONS)}


class _Engine(B._Scanner):
    """기존 구조 검사에 stream의 동일 시간·취소 예산만 연결한다."""

    def __init__(self, owner):
        self.owner = owner
        limits = B.BmffCandidateLimits(**{f.name: getattr(owner.limits, f.name) for f in fields(owner.limits)})
        super().__init__(b"", limits, owner.deadline, None, input_size=owner.size,
                         read_at=owner.read, max_prefix_bytes=MAX_PREFIX_BYTES)

    def check(self, *, timing=True):
        self.owner.check(timing=timing)


class _Scanner:
    def __init__(self, read_at, size, start, scan_bytes, limits, deadline, cancel):
        self.read_at, self.size, self.start = read_at, size, start
        self.scan_bytes, self.limits, self.deadline, self.cancel = scan_bytes, limits, deadline, cancel
        self.report = _new(size, start, scan_bytes)
        self.summary, self.cov, self.rows = (self.report[k] for k in ("summary", "coverage", "candidates"))
        self.engine = _Engine(self)
        self.reasons: set[str] = set()

    def check(self, *, timing=True):
        if self.cancel is not None:
            try:
                cancelled = self.cancel()
            except Exception:
                raise PwehError("BMFF 검색의 취소 상태를 확인하지 못했습니다.", code="bmff_scan_failed") from None
            if type(cancelled) is not bool:
                raise PwehError("BMFF 검색의 취소 상태를 확인하지 못했습니다.", code="bmff_scan_failed") from None
            if cancelled:
                raise PwehError("BMFF 검색이 취소되었습니다.", code="cancelled") from None
        if timing and time.monotonic() >= self.deadline:
            raise _Limit("time_limit")

    def read(self, offset, count, *, structure=True):
        self.check()
        if (type(offset) is not int or type(count) is not int or not 0 <= offset <= self.size
                or not 1 <= count <= min(_WINDOW, self.size - offset)):
            raise ValidationFailed("BMFF 검색 읽기 범위가 올바르지 않습니다.") from None
        name = "structure" if structure else "search"
        cap = self.limits.max_structure_bytes if structure else self.scan_bytes
        if self.cov[name + "_bytes_read"] + count > cap:
            raise _Limit("structure_byte_limit" if structure else "scan_byte_limit")
        try:
            result = self.read_at(offset, count)
        except Exception:
            raise PwehError("BMFF 검색 입력을 읽지 못했습니다.", code="bmff_scan_read_failed") from None
        if type(result) is not bytes or len(result) != count:
            raise PwehError("BMFF 검색 입력을 읽지 못했습니다.", code="bmff_scan_read_failed") from None
        self.cov[name + "_bytes_read"] += count
        self.cov[name + "_read_calls"] += 1
        self.cov["total_bytes_read"] += count
        self.check(timing=False)
        return result

    def reserve(self):
        self.check()
        if self.engine.cov["anchor_probes"] >= self.limits.max_anchor_probes:
            raise _Limit("probe_limit")
        if len(self.rows) >= self.limits.max_candidates:
            raise _Limit("candidate_limit")
        if _ENVELOPE + (len(self.rows) + 1) * _ROW > self.limits.max_output_bytes:
            raise _Limit("output_limit")

    def append(self):
        original = self.engine.rows[-1]
        row = {key: original[key] for key in ("index", "offset", "validated_prefix_length", "boxes_validated",
               "box_counts", "known_brands", "end_reason", "framing_status", "confidence", "complete_recording")}
        row["end_reason"] = {"selection_end": "evidence_end", "box_beyond_selection": "box_beyond_evidence"}.get(
            row["end_reason"], row["end_reason"])
        self.rows.append(row)
        self.summary["candidates_reported"] += 1
        if row["framing_status"] == "partial":
            self.reasons.add("candidate_framing_partial")
        if row["end_reason"] in CHAIN_LIMITS:
            self.summary["chain_limited_candidates"] += 1
        if row["end_reason"] == "prefix_size_limit":
            self.reasons.add("prefix_size_limit")

    def scan(self):
        total = self.cov["search_positions_total"]
        cursor = self.cov["positions_before_start"]
        read_position, end = self.start, min(self.size, self.start + self.scan_bytes)
        carry, pending, stop_reason = b"", None, None
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
                positions_end = min(total, read_position - 7)
                while cursor < positions_end:
                    self.check()
                    found = window.find(b"ftyp", cursor - base + 4, positions_end - base + 7)
                    if found < 0:
                        cursor = positions_end
                        break
                    cursor = pending = base + found - 4
                    self.summary["anchors_observed"] += 1
                    self.reserve()
                    old_rows = len(self.engine.rows)
                    old_rejected = self.engine.summary["anchors_rejected"]
                    try:
                        self.engine.anchor(cursor)
                    except B._PrefixTooLarge:
                        self.summary["oversize_anchors"] += 1
                        self.reasons.add("prefix_size_limit")
                    except _Limit:
                        if len(self.engine.rows) > old_rows:
                            # bytes 경로의 row+pending 의미는 그대로 두고 stream에서만 구분한다.
                            self.append()
                            cursor += 1
                            pending = None
                        raise
                    else:
                        if len(self.engine.rows) > old_rows:
                            self.append()
                        elif self.engine.summary["anchors_rejected"] > old_rejected:
                            self.summary["anchors_rejected"] += 1
                    cursor += 1
                    pending = None
                carry = window[-7:]
        except _Limit as stop:
            stop_reason = stop.reason
            self.reasons.add(stop.reason)
        if cursor < total:
            self.cov["unexamined_positions"] = {"start": cursor, "count": total - cursor, "reason": stop_reason}
            self.cov["next_offset"] = cursor
        self.cov["pending_anchor_offset"] = pending
        self.cov["search_positions_examined"] = cursor - self.cov["positions_before_start"]
        self.cov["search_complete"] = cursor == total
        self.cov["whole_evidence_search_complete"] = self.start == 0 and cursor == total
        checks = pending is None and self.summary["oversize_anchors"] == self.summary["chain_limited_candidates"] == 0
        self.cov["candidate_checks_complete"] = checks
        self.cov["candidate_list_complete"] = cursor == total and checks
        for key in ("anchor_probes", "boxes_examined", "brand_slots_examined"):
            self.cov[key] = self.engine.cov[key]
        self.summary["anchor_rejections"] = {
            ("box_beyond_evidence" if k == "box_beyond_selection" else k): v
            for k, v in self.engine.summary["anchor_rejections"].items()}
        self.cov["reasons"] = [r for r in REASONS if r in self.reasons]
        if self.reasons:
            self.report["status"] = "partial"
        elif self.rows:
            self.report["status"] = "ok"
        self.check(timing=False)
        return self.report


def scan_bmff_stream(read_at, *, evidence_size: int, start_offset: int = 0,
                     max_scan_bytes: int = MAX_SCAN_BYTES, limits: BmffScanLimits = BmffScanLimits(),
                     deadline: float, cancel: Callable[[], bool] | None = None) -> dict:
    """작은 reader로 EV 후보 시작점을 검색한다. source/params는 호출자가 결속한다."""
    try:
        _integer(evidence_size, 1, MAX_EVIDENCE_SIZE)
        _integer(start_offset, 0, evidence_size)
        _integer(max_scan_bytes, 8, MAX_SCAN_BYTES)
        if not callable(read_at) or type(limits) is not BmffScanLimits:
            raise ValueError()
        defaults = BmffScanLimits()
        for field in fields(defaults):
            _integer(getattr(limits, field.name), 8192 if field.name == "max_output_bytes" else 1,
                     getattr(defaults, field.name))
        if type(deadline) not in (int, float) or not math.isfinite(deadline):
            raise ValueError()
        if cancel is not None and not callable(cancel):
            raise ValueError()
    except (ValueError, TypeError, OverflowError):
        raise ValidationFailed("BMFF 검색 입력·상한·deadline이 올바르지 않습니다.") from None
    try:
        return _Scanner(read_at, evidence_size, start_offset, max_scan_bytes, limits,
                        min(deadline, time.monotonic() + 45), cancel).scan()
    except PwehError:
        raise
    except Exception:
        raise PwehError("BMFF 검색을 완료하지 못했습니다.", code="bmff_scan_failed") from None


def validate_bmff_scan_accounting(report: dict) -> None:
    """닫힌 shape는 schema가 검사하고, 여기서는 exact 수치와 재개·분류 관계를 검사한다."""
    try:
        def require(value):
            if not value:
                raise ValueError()
        require(type(report) is dict)
        s, c, rows = (report[k] for k in ("summary", "coverage", "candidates"))
        require(type(s) is dict and type(c) is dict and type(rows) is list and len(rows) <= 128)
        n = _integer(c["evidence_size"], 1, MAX_EVIDENCE_SIZE)
        start = _integer(c["start_offset"], 0, n)
        budget = _integer(c["max_scan_bytes"], 8, MAX_SCAN_BYTES)
        total = _integer(c["search_positions_total"], 0, MAX_EVIDENCE_SIZE)
        before = _integer(c["positions_before_start"], 0, total)
        examined = _integer(c["search_positions_examined"], 0, total)
        require(total == max(0, n - 7) and before == min(start, total))
        cursor = before + examined
        require(cursor <= total)
        observed = _integer(s["anchors_observed"], 0, 1025)
        rejected = _integer(s["anchors_rejected"], 0, 1024)
        oversized = _integer(s["oversize_anchors"], 0, 1024)
        reported = _integer(s["candidates_reported"], 0, 128)
        limited = _integer(s["chain_limited_candidates"], 0, reported)
        require(rejected == sum(_integer(s["anchor_rejections"][k], 0, 1024) for k in REJECTIONS))
        pending = c["pending_anchor_offset"]
        if pending is not None:
            require(_integer(pending, 0, total - 1) == cursor)
        require(observed == rejected + oversized + reported + int(pending is not None) and reported == len(rows))
        probes = _integer(c["anchor_probes"], 0, 1024)
        boxes = _integer(c["boxes_examined"], 0, 8192)
        brands = _integer(c["brand_slots_examined"], 0, 4096)
        require(observed - int(pending is not None) <= probes <= observed)
        require(observed - int(pending is not None) <= boxes <= probes * 1024)
        require(reported <= brands <= probes * 64)
        search = _integer(c["search_bytes_read"], 0, min(budget, n - start))
        structure = _integer(c["structure_bytes_read"], 0, 1 << 20)
        search_calls = _integer(c["search_read_calls"], 0, (budget + _WINDOW - 1) // _WINDOW)
        structure_calls = _integer(c["structure_read_calls"], 0, 2 * 8192 + 4096)
        require(_integer(c["total_bytes_read"], 0, budget + (1 << 20)) == search + structure)
        require((search == 0) == (search_calls == 0) and search_calls <= search <= search_calls * _WINDOW)
        require((structure == 0) == (structure_calls == 0)
                and structure_calls * 4 <= structure <= structure_calls * 8)
        require(structure_calls <= boxes * 2 + brands + 1)
        require(structure >= 4 * brands and structure_calls >= brands)
        require(examined <= max(0, search - 7))
        if pending is not None:
            require(pending + 8 <= start + search)
        reasons = c["reasons"]
        require(type(reasons) is list and len(reasons) <= len(REASONS)
                and reasons == [r for r in REASONS if r in reasons])
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
        if stop and stop[0] in ("probe_limit", "candidate_limit", "output_limit", "brand_limit"):
            require(pending is not None)
        if stop == ["scan_byte_limit"]:
            require(pending is None and search == min(budget, n - start))
        for name in ("search_complete", "whole_evidence_search_complete", "candidate_checks_complete", "candidate_list_complete"):
            require(type(c[name]) is bool)
        checks = pending is None and oversized == limited == 0
        require(c["search_complete"] == (cursor == total))
        require(c["whole_evidence_search_complete"] == (start == 0 and cursor == total))
        require(c["candidate_checks_complete"] == checks)
        require(c["candidate_list_complete"] == (cursor == total and checks))
        require(report["status"] == ("partial" if reasons else "ok" if rows else "unsupported"))
        require(all(report[name] is False for name in FALSE_FIELDS))
        previous, row_boxes, row_limited, row_partial, row_capped = -1, 0, 0, 0, 0
        for index, row in enumerate(rows):
            require(type(row) is dict and _integer(row["index"], 0, 127) == index)
            offset = _integer(row["offset"], start, n - 1)
            length = _integer(row["validated_prefix_length"], 16, MAX_PREFIX_BYTES)
            count = _integer(row["boxes_validated"], 1, 1024)
            counts = row["box_counts"]
            require(type(counts) is dict and count == sum(_integer(counts[k], 0, 1024) for k in B.BOX_KINDS))
            require(counts["ftyp"] == 1 and length >= 16 + 8 * (count - 1))
            known = row["known_brands"]
            require(type(known) is list and 1 <= len(known) <= len(B.BRANDS)
                    and known == [b for b in B.BRANDS if b in known])
            end = row["end_reason"]
            require(end in END_REASONS and row["framing_status"] == ("complete" if end in ("evidence_end", "next_ftyp") else "partial"))
            require(previous < offset < cursor and offset + length <= n)
            if end == "evidence_end":
                require(offset + length == n)
            else:
                require(offset + length < n)
            if end in CHAIN_LIMITS and end != "prefix_size_limit":
                require(stop == [end] and index == len(rows)-1 and pending is None and cursor == offset+1)
            require(row["confidence"] == "possible" and row["complete_recording"] is False)
            row_boxes += count
            row_limited += end in CHAIN_LIMITS
            row_partial += row["framing_status"] == "partial"
            row_capped += end == "prefix_size_limit"
            previous = offset
        require(row_boxes + rejected + oversized <= boxes and row_limited == limited)
        require(("candidate_framing_partial" in reasons) == (row_partial > 0))
        require(("prefix_size_limit" in reasons) == (oversized + row_capped > 0))
        if "source" in report:
            require(_integer(report["source"]["evidence_size"], 1, MAX_EVIDENCE_SIZE) == n)
        if "params" in report:
            require(_integer(report["params"]["start_offset"], 0, n) == start
                    and _integer(report["params"]["max_scan_bytes"], 8, MAX_SCAN_BYTES) == budget)
    except (KeyError, TypeError, ValueError, OverflowError):
        raise ValidationFailed("BMFF 검색 보고서의 수치·완료 회계가 올바르지 않습니다.") from None
