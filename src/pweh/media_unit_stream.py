"""EV의 작은 reader로 기존 네 subset을 검사한다. 파일 경계·본문 의미는 판정하지 않는다."""

from __future__ import annotations

from dataclasses import dataclass, fields
import json
import math
import re
import time
from typing import Callable

from . import media_units as U
from .errors import PwehError, ValidationFailed

SCHEMA = "pweh.media-unit-scan/v1"
PROFILES = {key: value[:-3] + "-stream-v1" for key, value in U.FILE_PROFILES.items()}
FALSE_FIELDS = (*U.FALSE_FIELDS, "physical_carving_performed")
LIMITATIONS = (*U.LIMITATIONS, "evidence_bytes_only", "allocation_state_unexamined",
               "unit_bytes_not_hashed", "range_revalidation_required_before_extract", "intake_hash_not_reverified")
LIMIT_REASONS = ("scan_byte_limit", *U.LIMIT_REASONS, "structure_byte_limit")
REASONS = (*LIMIT_REASONS, "selection_size_limit", "unit_framing_incomplete", "candidate_prefix_partial")
INCOMPLETE = ("truncated_header", "unit_beyond_evidence", "open_tail")
MAX_EVIDENCE_SIZE = (1 << 63) - 1
MAX_SCAN_BYTES = 1 << 30
MAX_SELECTION_BYTES = 64 << 20
_WINDOW = 65536
_ENVELOPE, _ROW = 8192, 1024
_NEEDLES = {"jpeg": b"\xff\xd8", "avc-annexb": b"\0\0\1", "mpeg2-ps": b"\0\0\1\xba", "xm": b"\0\0\1"}


@dataclass(frozen=True)
class MediaUnitScanLimits:
    """낮추기만 가능한 호출 전체 예산. 물리 읽기와 논리 검사를 분리한다."""

    max_anchor_probes: int = 1024
    max_candidates: int = 128
    max_structure_steps: int = 8192
    max_structure_bytes: int = 128 << 20
    max_structure_work_bytes: int = 128 << 20
    max_output_bytes: int = 1 << 20


def _new(size, start, scan_bytes, format):
    summary = U._new(0, format)["summary"]
    summary["anchor_incomplete"] = dict.fromkeys(INCOMPLETE, 0)
    summary["selection_limited_anchors"] = 0
    total = max(0, size - len(_NEEDLES[format]) + 1)
    return {"schema": SCHEMA, "profile": PROFILES[format], "format": format, "status": "unsupported",
            **dict.fromkeys(FALSE_FIELDS, False), "summary": summary,
            "coverage": {"evidence_size": size, "start_offset": start, "max_scan_bytes": scan_bytes,
                         "search_positions_total": total, "positions_before_start": min(start, total),
                         "search_positions_examined": 0, "unexamined_positions": None,
                         "pending_anchor_offset": None, "next_offset": None, "search_complete": False,
                         "whole_evidence_search_complete": False, "candidate_checks_complete": False,
                         "candidate_list_complete": False, "anchor_probes": 0, "structure_steps": 0,
                         "search_bytes_read": 0, "search_read_calls": 0, "structure_bytes_read": 0,
                         "structure_read_calls": 0, "structure_work_bytes": 0, "total_bytes_read": 0,
                         "reasons": []}, "candidates": [], "limitations": list(LIMITATIONS)}


class _Engine(U._Scanner):
    """parser는 한 벌만 사용하고 예산·실제 읽기는 호출 전체 owner에 연결한다."""

    def __init__(self, owner):
        self.owner = owner
        super().__init__(b"", owner.format, U.MediaUnitLimits(), owner.deadline, None,
                         input_size=owner.size, read_at=owner.read, max_selection_bytes=MAX_SELECTION_BYTES)
        self.cache_start, self.cache = 0, b""

    def check(self, timing=True):
        self.owner.check(timing=timing)

    def charge(self, size, *, search=False):
        self.owner.charge(size)

    def step(self):
        self.owner.check()
        if self.owner.cov["structure_steps"] >= self.owner.limits.max_structure_steps:
            raise U._Stop("step_limit")
        self.owner.cov["structure_steps"] += 1

    def fetch(self, start, size):
        # 1B fill/escape 검사를 매번 외부 I/O로 바꾸지 않는다. cache hit도 charge는 먼저 한다.
        relative = start - self.cache_start
        if 0 <= relative and relative + size <= len(self.cache):
            return self.cache[relative:relative + size]
        available = self.owner.limits.max_structure_bytes - self.owner.cov["structure_bytes_read"]
        end = min(self.size, self.selection_start + self.max_selection_bytes)
        count = max(size, min(max(size, 4096), end - start, available))
        self.cache = self.owner.read(start, count)
        self.cache_start = start
        return self.cache[:size]


class _Scanner:
    def __init__(self, read_at, format, size, start, scan_bytes, limits, deadline, cancel):
        self.read_at, self.format, self.size, self.start = read_at, format, size, start
        self.scan_bytes, self.limits, self.deadline, self.cancel = scan_bytes, limits, deadline, cancel
        self.report = _new(size, start, scan_bytes, format)
        self.summary, self.cov, self.rows = (self.report[k] for k in ("summary", "coverage", "candidates"))
        self.engine = _Engine(self)

    def check(self, *, timing=True):
        if self.cancel is not None:
            try:
                cancelled = self.cancel()
            except Exception:
                raise PwehError("미디어 단위 검색의 취소 상태를 확인하지 못했습니다.", code="media_unit_scan_failed") from None
            if type(cancelled) is not bool:
                raise PwehError("미디어 단위 검색의 취소 상태를 확인하지 못했습니다.", code="media_unit_scan_failed") from None
            if cancelled:
                raise PwehError("미디어 단위 검색이 취소되었습니다.", code="cancelled") from None
        if timing and time.monotonic() >= self.deadline:
            raise U._Stop("time_limit")

    def charge(self, count):
        self.check()
        if self.cov["structure_work_bytes"] + count > self.limits.max_structure_work_bytes:
            raise U._Stop("work_byte_limit")
        self.cov["structure_work_bytes"] += count

    def read(self, offset, count, *, structure=True):
        self.check()
        if (type(offset) is not int or type(count) is not int or not 0 <= offset <= self.size
                or not 1 <= count <= min(_WINDOW, self.size - offset)):
            raise ValidationFailed("미디어 단위 검색 읽기 범위가 올바르지 않습니다.") from None
        name = "structure" if structure else "search"
        cap = self.limits.max_structure_bytes if structure else self.scan_bytes
        if self.cov[name + "_bytes_read"] + count > cap:
            raise U._Stop("structure_byte_limit" if structure else "scan_byte_limit")
        try:
            result = self.read_at(offset, count)
        except Exception:
            raise PwehError("미디어 단위 검색 입력을 읽지 못했습니다.", code="media_unit_scan_read_failed") from None
        if type(result) is not bytes or len(result) != count:
            raise PwehError("미디어 단위 검색 입력을 읽지 못했습니다.", code="media_unit_scan_read_failed") from None
        self.cov[name + "_bytes_read"] += count
        self.cov[name + "_read_calls"] += 1
        self.cov["total_bytes_read"] += count
        self.check(timing=False)
        return result

    def reserve(self):
        self.check()
        if self.cov["anchor_probes"] >= self.limits.max_anchor_probes:
            raise U._Stop("probe_limit")
        if len(self.rows) >= self.limits.max_candidates:
            raise U._Stop("candidate_limit")
        if _ENVELOPE + (len(self.rows) + 1) * _ROW > self.limits.max_output_bytes:
            raise U._Stop("output_limit")

    def probe(self, offset):
        self.reserve()
        self.cov["anchor_probes"] += 1
        try:
            original, end = self.engine.probe_unit(offset)
            self.check()
        except U._Result as result:
            self.check()
            key, total = {"rejected": ("anchor_rejections", "anchors_rejected"),
                          "unsupported": ("anchor_unsupported", "unsupported_anchors"),
                          "incomplete": ("anchor_incomplete", "incomplete_anchors")}[result.group]
            reason = "unit_beyond_evidence" if result.reason == "unit_beyond_selection" else result.reason
            self.summary[key][reason] += 1
            self.summary[total] += 1
        except U._SelectionLimit:
            self.check()
            self.summary["selection_limited_anchors"] += 1
        else:
            row = dict(original)
            row.update(index=len(self.rows), selection_offset=offset, selection_length=end - offset)
            if row["end_reason"] == "selection_end":
                row["end_reason"] = "evidence_end"
            self.rows.append(row)
            self.summary["candidates_reported"] += 1
            self.summary["closed_candidates" if row["framing_status"] == "closed" else "prefix_candidates"] += 1

    def scan(self):
        needle = _NEEDLES[self.format]
        length = len(needle)
        total = self.cov["search_positions_total"]
        cursor, pointer, pending = min(self.start, total), self.start, None
        carry, reasons = b"", set()
        carry_size = 3 if self.format == "avc-annexb" else length - 1
        self.check(timing=False)
        try:
            while cursor < total:
                self.check()
                left = self.scan_bytes - self.cov["search_bytes_read"]
                if not left:
                    raise U._Stop("scan_byte_limit")
                count = min(_WINDOW, self.size - pointer, left)
                if count <= 0:
                    raise U._Stop("scan_byte_limit")
                data = carry + self.read(pointer, count, structure=False)
                base = pointer - len(carry)
                pointer += count
                available_end = min(total, pointer - length + 1)
                local = max(0, cursor - base)
                while True:
                    self.check()
                    at = data.find(needle, local)
                    if at < 0:
                        break
                    raw = base + at
                    if raw >= available_end:
                        break
                    canonical = raw
                    if self.format == "avc-annexb" and raw:
                        if at:
                            previous = data[at - 1]
                        else:
                            self.charge(1)
                            previous = self.read(raw - 1, 1)[0]
                        if previous == 0:
                            canonical -= 1
                    local = at + 1
                    if canonical < cursor:
                        continue
                    cursor = pending = canonical
                    self.summary["anchors_observed"] += 1
                    self.probe(cursor)
                    cursor += 1
                    pending = None
                    if cursor == total:
                        break
                # tail000 뒤 다음창01의 canonical4B 시작은 아직 처리하지 않았다.
                safe_end = available_end
                if self.format == "avc-annexb" and pointer < self.size and data.endswith(b"\0\0\0"):
                    safe_end = min(safe_end, pointer - 3)
                cursor = max(cursor, safe_end)
                carry = data[-carry_size:]
        except U._Stop as stop:
            reasons.add(stop.reason)
            self.cov["unexamined_positions"] = {"start": cursor, "count": total - cursor, "reason": stop.reason}
        self.cov["search_positions_examined"] = cursor - self.cov["positions_before_start"]
        self.cov["pending_anchor_offset"] = pending
        self.cov["next_offset"] = None if cursor == total else cursor
        self.cov["search_complete"] = cursor == total
        self.cov["whole_evidence_search_complete"] = self.start == 0 and cursor == total
        checks = pending is None and not self.summary["incomplete_anchors"] and not self.summary["selection_limited_anchors"]
        self.cov["candidate_checks_complete"] = checks
        self.cov["candidate_list_complete"] = checks and cursor == total
        for key, reason in (("incomplete_anchors", "unit_framing_incomplete"),
                            ("selection_limited_anchors", "selection_size_limit"),
                            ("prefix_candidates", "candidate_prefix_partial")):
            if self.summary[key]:
                reasons.add(reason)
        self.cov["reasons"] = [reason for reason in REASONS if reason in reasons]
        self.report["status"] = "partial" if reasons else "ok" if self.rows else "unsupported"
        self.check(timing=False)
        if len(json.dumps(self.report, ensure_ascii=True, separators=(",", ":")).encode()) + 1 > self.limits.max_output_bytes:
            raise PwehError("미디어 단위 검색 결과의 크기 상한을 넘었습니다.", code="media_unit_scan_failed") from None
        return self.report


def scan_media_unit_stream(read_at, *, format: str, evidence_size: int, start_offset: int = 0,
                           max_scan_bytes: int = MAX_SCAN_BYTES, limits: MediaUnitScanLimits = MediaUnitScanLimits(),
                           deadline: float, cancel: Callable[[], bool] | None = None) -> dict:
    """작은 reader로 EV 시작점을 검색한다. source/params는 호출자가 결속한다."""
    try:
        _int(evidence_size, MAX_EVIDENCE_SIZE, 1)
        _int(start_offset, evidence_size)
        _int(max_scan_bytes, MAX_SCAN_BYTES, 4)
        _require(type(format) is str and format in U.FORMATS and callable(read_at) and type(limits) is MediaUnitScanLimits)
        for field in fields(limits):
            _int(getattr(limits, field.name), getattr(MediaUnitScanLimits(), field.name),
                 8192 if field.name == "max_output_bytes" else 1)
        _require(type(deadline) in (int, float) and math.isfinite(deadline))
        _require(cancel is None or callable(cancel))
    except (TypeError, ValueError, OverflowError):
        raise ValidationFailed("미디어 단위 검색 입력·상한·deadline이 올바르지 않습니다.") from None
    try:
        return _Scanner(read_at, format, evidence_size, start_offset, max_scan_bytes, limits,
                        min(deadline, time.monotonic() + 45), cancel).scan()
    except PwehError:
        raise
    except Exception:
        raise PwehError("미디어 단위 검색을 완료하지 못했습니다.", code="media_unit_scan_failed") from None


def _int(value, cap, low=0):
    if type(value) is not int or not low <= value <= cap:
        raise ValueError()
    return value


def _require(condition):
    if not condition:
        raise ValueError()


def validate_media_unit_scan_accounting(report: dict) -> None:
    """순수 또는 완전 봉투의 닫힌 수치·위치·완료 관계를 검사한다. 파일/본문을 읽지 않는다."""
    try:
        _validate(report)
    except (KeyError, TypeError, ValueError, OverflowError):
        raise ValidationFailed("미디어 단위 검색 보고서의 수치 또는 완료 관계가 올바르지 않습니다.") from None


def _validate(report):
    _require(type(report) is dict)
    full = "source" in report or "params" in report
    root = {"schema", "profile", "format", "status", "summary", "coverage", "candidates", "limitations", *FALSE_FIELDS}
    _require(set(report) == root | ({"source", "params"} if full else set()))
    format = report["format"]
    _require(type(format) is str and format in U.FORMATS and report["schema"] == SCHEMA)
    _require(report["profile"] == PROFILES[format] and report["limitations"] == list(LIMITATIONS))
    _require(all(report[name] is False for name in FALSE_FIELDS))
    summary, cov, rows = (report[key] for key in ("summary", "coverage", "candidates"))
    template = _new(1, 0, 4, format)
    _require(type(summary) is dict and set(summary) == set(template["summary"]))
    _require(type(cov) is dict and set(cov) == set(template["coverage"]))
    _require(type(rows) is list and len(rows) <= 128)
    observed = _int(summary["anchors_observed"], 1025)
    completed = _int(summary["selection_limited_anchors"], 1024)
    for total_key, map_key, names in (("anchors_rejected", "anchor_rejections", U.REJECTIONS),
                                     ("unsupported_anchors", "anchor_unsupported", U.UNSUPPORTED),
                                     ("incomplete_anchors", "anchor_incomplete", INCOMPLETE)):
        values = summary[map_key]
        _require(type(values) is dict and set(values) == set(names))
        total = _int(summary[total_key], 1024)
        _require(total == sum(_int(values[name], 1024) for name in names))
        completed += total
    reported = _int(summary["candidates_reported"], 128)
    closed, prefix = (_int(summary[key], 128) for key in ("closed_candidates", "prefix_candidates"))
    _require(reported == len(rows) == closed + prefix)
    completed += reported
    _int(completed, 1024)
    size = _int(cov["evidence_size"], MAX_EVIDENCE_SIZE, 1)
    start = _int(cov["start_offset"], size)
    scan_bytes = _int(cov["max_scan_bytes"], MAX_SCAN_BYTES, 4)
    total = _int(cov["search_positions_total"], size)
    _require(total == max(0, size - len(_NEEDLES[format]) + 1))
    before = _int(cov["positions_before_start"], total)
    _require(before == min(start, total))
    cursor = before + _int(cov["search_positions_examined"], total - before)
    probes = _int(cov["anchor_probes"], 1024)
    _int(cov["structure_steps"], 8192)
    work = _int(cov["structure_work_bytes"], 128 << 20)
    search = _int(cov["search_bytes_read"], min(scan_bytes, size - start))
    structure = _int(cov["structure_bytes_read"], 128 << 20)
    for name, amount in (("search", search), ("structure", structure)):
        calls = _int(cov[name + "_read_calls"], amount)
        _require(calls <= amount <= calls * _WINDOW)
    _require(_int(cov["total_bytes_read"], MAX_SCAN_BYTES + (128 << 20)) == search + structure)
    _require(cursor - before <= search and (work > 0 or structure == 0))
    pending = cov["pending_anchor_offset"]
    if pending is not None:
        _require(_int(pending, total - 1) == cursor)
    _require(observed == completed + int(pending is not None) and completed <= probes <= observed)
    for name in ("search_complete", "whole_evidence_search_complete", "candidate_checks_complete", "candidate_list_complete"):
        _require(type(cov[name]) is bool)
    checks = pending is None and not summary["incomplete_anchors"] and not summary["selection_limited_anchors"]
    _require(cov["search_complete"] == (cursor == total))
    _require(cov["whole_evidence_search_complete"] == (start == 0 and cursor == total))
    _require(cov["candidate_checks_complete"] == checks and cov["candidate_list_complete"] == (checks and cursor == total))
    reasons = cov["reasons"]
    _require(type(reasons) is list and len(reasons) <= len(REASONS))
    _require(all(type(reason) is str and reason in REASONS for reason in reasons))
    _require(reasons == [reason for reason in REASONS if reason in reasons])
    for key, reason in (("incomplete_anchors", "unit_framing_incomplete"),
                        ("selection_limited_anchors", "selection_size_limit"), ("prefix_candidates", "candidate_prefix_partial")):
        _require((reason in reasons) == (summary[key] > 0))
    limited = [reason for reason in LIMIT_REASONS if reason in reasons]
    unexamined = cov["unexamined_positions"]
    if cursor == total:
        _require(unexamined is None and cov["next_offset"] is None and not limited)
    else:
        _require(type(unexamined) is dict and set(unexamined) == {"start", "count", "reason"} and len(limited) == 1)
        _require(_int(unexamined["start"], total) == cursor and _int(unexamined["count"], total, 1) == total - cursor)
        _require(unexamined["reason"] == limited[0] and _int(cov["next_offset"], total - 1) == cursor)
    if any(reason in reasons for reason in ("probe_limit", "candidate_limit", "output_limit", "step_limit")):
        _require(pending is not None)
    previous, actual_prefix = -1, 0
    row_keys = {"index", "offset", "length", "format", "unit", "unit_subtype", "boundary_kind", "framing_status",
                "end_reason", "confidence", "selection_offset", "selection_length"}
    for index, row in enumerate(rows):
        _require(type(row) is dict and set(row) == row_keys and _int(row["index"], 127) == index)
        offset = _int(row["offset"], size - 1)
        length = _int(row["length"], MAX_SELECTION_BYTES, U.MIN_UNIT_BYTES[format])
        selected = _int(row["selection_length"], MAX_SELECTION_BYTES, U.MIN_SELECTED_BYTES[format])
        _require(_int(row["selection_offset"], size - 1) == offset and length <= selected and offset + selected <= size)
        _require(previous < offset < cursor and offset >= before)
        _require(row["format"] == format and row["unit"] == U._UNITS[format] and row["confidence"] == "possible")
        subtype, framing, boundary, end = (row[key] for key in ("unit_subtype", "framing_status", "boundary_kind", "end_reason"))
        if format == "jpeg":
            _require((subtype, framing, boundary, end) == ("baseline", "closed", "eoi", "eoi") and selected == length)
        elif format == "avc-annexb":
            _require(subtype in tuple("nal_" + str(i) for i in range(1, 13)))
            _require((framing, boundary, end) == ("closed", "next_nal", "next_nal") and selected >= length + 4)
            _require(length in (4, 5) if subtype in ("nal_10", "nal_11") else length >= 5)
        elif format == "xm":
            _require(subtype in ("type_fc", "type_fe", "type_fd", "type_fa", "type_f9"))
            _require((framing, boundary, end) == ("closed", "declared_length", "declared_length") and selected == length)
            if subtype in ("type_fc", "type_fe"):
                _require(length >= 17)
        else:
            _require(subtype == "mpeg2_pack")
            if framing == "closed":
                _require(boundary in ("next_pack", "program_end") and end == boundary)
                _require(length + 14 <= selected <= length + 21 if boundary == "next_pack" else selected == length + 4)
            else:
                _require(framing == "prefix" and boundary == "validated_prefix")
                _require(end in ("evidence_end", "truncated_packet", "unsupported_packet", "invalid_packet", "zero_length_packet"))
                actual_prefix += 1
                if end == "evidence_end":
                    _require(length == selected and offset + selected == size)
                elif end == "truncated_packet":
                    _require(offset + selected == size)
                else:
                    _require(selected >= length + (6 if end == "zero_length_packet" else 4))
        previous = offset
    _require(actual_prefix == prefix and report["status"] == ("partial" if reasons else "ok" if rows else "unsupported"))
    if full:
        source, params = report["source"], report["params"]
        _require(type(source) is dict and set(source) == {"kind", "evidence_id", "evidence_sha256", "evidence_size"})
        _require(type(params) is dict and set(params) == {"format", "start_offset", "max_scan_bytes", "max_seconds"})
        _require(source["kind"] == "evidence" and _int(source["evidence_size"], MAX_EVIDENCE_SIZE, 1) == size)
        _require(type(source["evidence_id"]) is str and re.fullmatch(r"EV-[0-9]{4,6}", source["evidence_id"]) is not None)
        _require(type(source["evidence_sha256"]) is str and re.fullmatch(r"[0-9a-f]{64}", source["evidence_sha256"]) is not None)
        _require(params["format"] == format and _int(params["start_offset"], size) == start)
        _require(_int(params["max_scan_bytes"], MAX_SCAN_BYTES, 4) == scan_bytes)
        seconds = params["max_seconds"]
        _require(type(seconds) in (int, float) and math.isfinite(seconds) and 0 < seconds <= 45)
