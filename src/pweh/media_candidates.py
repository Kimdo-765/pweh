"""선택 bytes 안의 ftyp 시작 연속 박스 후보만 찾는다. 본문·원본 경계는 해석하지 않는다."""
from __future__ import annotations

import math
import struct
import time
from dataclasses import dataclass, fields
from typing import Callable

from .errors import PwehError, ValidationFailed

SCHEMA = "pweh.media-candidates/v1"
PROFILE = "ftyp-contiguous-top-level-v1"
BOX_KINDS = ("ftyp", "moov", "mdat", "moof", "styp", "free", "skip", "wide", "uuid")
BRANDS = ("isom", "iso2", "iso3", "iso4", "iso5", "iso6", "mp41", "mp42", "quicktime")
REJECTIONS = ("size_zero", "truncated_extended_header", "size_below_header", "box_beyond_selection",
              "invalid_ftyp_shape", "unknown_brand")
LIMIT_REASONS = ("probe_limit", "candidate_limit", "box_limit", "brand_limit", "structure_byte_limit",
                 "output_limit", "time_limit")
REASONS = (*LIMIT_REASONS, "candidate_framing_partial", "selection_uncertain", "container_listing_incomplete")
END_REASONS = ("selection_end", "next_ftyp", "size_zero", "truncated_header", "truncated_extended_header",
               "truncated_uuid_header", "size_below_header", "box_beyond_selection", "unknown_next_type",
               "unsupported_wide_shape", "box_limit", "structure_byte_limit", "time_limit")
LIMITATIONS = ("top_level_framing_only", "payloads_unexamined", "original_file_boundary_unknown",
               "reported_candidates_only_relations", "no_media_type_confirmation",
               "no_playback_time_or_encryption_validation")
_KINDS = {name.encode("ascii"): name for name in BOX_KINDS}
_BRANDS = {name.encode("ascii"): name for name in BRANDS if name != "quicktime"}
_BRANDS[b"qt  "] = "quicktime"
_WINDOW = 65536
# 고정 봉투의 모든 수치 증가/종결 사유와, 관계 배열이 비어 있는 최장 row의 상계다.
# 실제 직렬화 길이보다 보수적으로 예약하여 중간 행 삭제·반복 전체 직렬화를 피한다.
_ENVELOPE_RESERVE = 4096
_ROW_RESERVE = 1024


@dataclass(frozen=True)
class BmffCandidateLimits:
    """기본 상한을 낮출 수만 있다. 고정 종결 봉투 때문에 출력 최소값은 8192다."""

    max_input_bytes: int = 64 << 20
    max_anchor_probes: int = 1024
    max_candidates: int = 128
    max_boxes_per_candidate: int = 1024
    max_boxes_total: int = 8192
    max_brands_per_anchor: int = 64
    max_brands_total: int = 4096
    max_structure_bytes: int = 1 << 20
    max_output_bytes: int = 1 << 20


class _Limit(Exception):
    def __init__(self, reason: str):
        self.reason = reason


class _PrefixTooLarge(Exception):
    """stream 전용: 첫 ftyp조차 prefix 상한에 들어오지 않는다."""


def _new(size: int) -> dict:
    return {"schema": SCHEMA, "profile": PROFILE, "status": "unsupported",
            "media_decoded": False, "playback_verified": False, "recording_time_verified": False,
            "encryption_assessed": False, "format_conformance_assessed": False,
            "original_file_boundary_verified": False, "physical_carving_performed": False,
            "summary": {"anchors_observed": 0, "anchors_rejected": 0, "supported_anchors": 0,
                        "candidates_reported": 0, "candidates_omitted": 0,
                        "anchor_rejections": dict.fromkeys(REJECTIONS, 0)},
            "coverage": {"input_bytes": size, "search_positions_total": max(0, size - 7),
                         "search_positions_examined": 0, "unexamined_positions": None,
                         "pending_anchor_offset": None, "search_complete": True,
                         "candidate_checks_complete": True, "candidate_list_complete": True,
                         "anchor_probes": 0, "boxes_examined": 0, "brand_slots_examined": 0,
                         "structure_bytes_read": 0, "relations_scope": "reported_candidates",
                         "relation_pairs_total": 0, "relation_pairs_examined": 0,
                         "relations_complete": True, "selection_uncertain": False,
                         "container_examined": False, "reasons": []},
            "candidates": [], "limitations": list(LIMITATIONS)}


class _Scanner:
    def __init__(self, data: bytes, limits: BmffCandidateLimits, deadline: float,
                 cancel: Callable[[], bool] | None, *, input_size: int | None = None,
                 read_at: Callable[[int, int], bytes] | None = None,
                 max_prefix_bytes: int | None = None):
        self.data, self.limits, self.deadline, self.cancel = data, limits, deadline, cancel
        # 공개 bytes 경로는 원래 입력·읽기·결과를 유지한다. stream은 검증한 내부 reader만 준다.
        self.input_size = len(data) if input_size is None else input_size
        self.read_at, self.max_prefix_bytes = read_at, max_prefix_bytes
        self.report = _new(self.input_size)
        self.cov = self.report["coverage"]
        self.summary = self.report["summary"]
        self.rows = self.report["candidates"]
        self.cost = _ENVELOPE_RESERVE
        self.header_attempts = 0

    def check(self, *, timing: bool = True) -> None:
        if self.cancel is not None:
            failed = False
            try:
                cancelled = self.cancel()
                failed = type(cancelled) is not bool
            except Exception:
                failed = True
            if failed:
                raise PwehError("미디어 후보 검사의 취소 상태를 확인하지 못했습니다.",
                                code="media_candidates_failed")
            if cancelled:
                raise PwehError("미디어 후보 검사가 취소되었습니다.", code="cancelled")
        if timing and time.monotonic() >= self.deadline:
            raise _Limit("time_limit")

    def reason(self, value: str) -> None:
        if value not in self.cov["reasons"]:
            self.cov["reasons"].append(value)

    def read(self, offset: int, count: int) -> bytes:
        # 이 함수는 작은 header/brand만 받는다. 전체 후보나 payload의 사본을 만들지 않는다.
        self.check()
        if self.cov["structure_bytes_read"] + count > self.limits.max_structure_bytes:
            raise _Limit("structure_byte_limit")
        if self.read_at is not None:
            result = self.read_at(offset, count)
            self.cov["structure_bytes_read"] += count
            return result
        self.cov["structure_bytes_read"] += count
        return self.data[offset:offset + count]

    def header(self, offset: int, *, anchor: bool = False) -> tuple[str | None, int, int, str | None]:
        self.check()
        if (self.cov["boxes_examined"] >= self.limits.max_boxes_total
                or self.header_attempts >= self.limits.max_boxes_per_candidate):
            raise _Limit("box_limit")
        self.cov["boxes_examined"] += 1
        self.header_attempts += 1
        remaining = self.input_size - offset
        if remaining < 8:
            return None, 0, 0, "truncated_header"
        raw = self.read(offset, 8)
        length = struct.unpack_from(">I", raw)[0]
        kind, header = _KINDS.get(raw[4:8]), 8
        if not anchor and kind == "ftyp":
            return kind, 0, header, "next_ftyp"
        if kind is None:
            return None, 0, header, "unknown_next_type"
        if length == 0:
            return kind, 0, header, "size_zero"
        if length == 1:
            if remaining < 16:
                return kind, 0, header, "truncated_extended_header"
            length = struct.unpack(">Q", self.read(offset + 8, 8))[0]
            header = 16
        if kind == "uuid":
            header += 16
            if remaining < header:
                return kind, 0, header, "truncated_uuid_header"
            # UUID의 값은 읽거나 반환하지 않고 필요한 header 길이만 확인한다.
        if length < header:
            return kind, 0, header, "size_below_header"
        if length > remaining:
            return kind, 0, header, "box_beyond_selection"
        if kind == "wide" and (header != 8 or length != 8):
            return kind, 0, header, "unsupported_wide_shape"
        return kind, length, header, None

    def anchor(self, offset: int) -> None:
        if self.cov["anchor_probes"] >= self.limits.max_anchor_probes:
            raise _Limit("probe_limit")
        self.check()
        self.cov["anchor_probes"] += 1
        self.header_attempts = 0
        _, length, header, failure = self.header(offset, anchor=True)
        known: set[str] = set()
        if failure is None:
            if self.max_prefix_bytes is not None and length > self.max_prefix_bytes:
                raise _PrefixTooLarge()
            payload = length - header
            if payload < 8 or (payload - 8) % 4:
                failure = "invalid_ftyp_shape"
            else:
                slots = 1 + (payload - 8) // 4
                for slot in range(slots):
                    self.check()
                    if (slot >= self.limits.max_brands_per_anchor
                            or self.cov["brand_slots_examined"] >= self.limits.max_brands_total):
                        raise _Limit("brand_limit")
                    at = offset + header + (0 if slot == 0 else 8 + (slot - 1) * 4)
                    brand = _BRANDS.get(self.read(at, 4))
                    self.cov["brand_slots_examined"] += 1
                    if brand is not None:
                        known.add(brand)
                if not known:
                    failure = "unknown_brand"
        if failure is not None:
            self.summary["anchor_rejections"][failure] += 1
            self.summary["anchors_rejected"] += 1
            return
        self.summary["supported_anchors"] += 1
        if len(self.rows) >= self.limits.max_candidates:
            raise _Limit("candidate_limit")
        if self.cost + _ROW_RESERVE > self.limits.max_output_bytes:
            raise _Limit("output_limit")
        self.cost += _ROW_RESERVE
        row = {"index": len(self.rows), "offset": offset, "validated_prefix_length": length,
               "boxes_validated": 1, "box_counts": dict.fromkeys(BOX_KINDS, 0),
               "known_brands": [name for name in BRANDS if name in known],
               "end_reason": "selection_end", "framing_status": "complete",
               "overlap_with_reported": [], "contained_by_reported": [],
               "confidence": "possible", "complete_recording": False}
        row["box_counts"]["ftyp"] = 1
        self.rows.append(row)
        cursor = offset + length
        try:
            while cursor < self.input_size:
                kind, size, _, failure = self.header(cursor)
                if failure is not None:
                    row["end_reason"] = failure
                    if failure != "next_ftyp":
                        row["framing_status"] = "partial"
                        self.reason("candidate_framing_partial")
                    return
                if self.max_prefix_bytes is not None and cursor + size - offset > self.max_prefix_bytes:
                    row["end_reason"], row["framing_status"] = "prefix_size_limit", "partial"
                    return
                row["boxes_validated"] += 1
                row["box_counts"][kind] += 1
                cursor += size
                row["validated_prefix_length"] = cursor - offset
        except _Limit as stop:
            row["end_reason"], row["framing_status"] = stop.reason, "partial"
            raise

    def relations(self) -> None:
        self.cov["relation_pairs_total"] = len(self.rows) * (len(self.rows) - 1) // 2
        try:
            for i, left in enumerate(self.rows):
                for j in range(i + 1, len(self.rows)):
                    self.check()
                    right = self.rows[j]
                    a, b = left["offset"], left["offset"] + left["validated_prefix_length"]
                    c, d = right["offset"], right["offset"] + right["validated_prefix_length"]
                    additions = []
                    if max(a, c) < min(b, d):
                        additions += [(left["overlap_with_reported"], j), (right["overlap_with_reported"], i)]
                        if a <= c and d <= b:
                            additions.append((right["contained_by_reported"], i))
                        if c <= a and b <= d:
                            additions.append((left["contained_by_reported"], j))
                    extra = sum(len(str(value)) + int(bool(array)) for array, value in additions)
                    if self.cost + extra > self.limits.max_output_bytes:
                        raise _Limit("output_limit")
                    self.cost += extra
                    for array, value in additions:
                        array.append(value)
                    self.cov["relation_pairs_examined"] += 1
        except _Limit as stop:
            self.cov["relations_complete"] = False
            self.reason(stop.reason)

    def scan(self) -> dict:
        position, total = 0, self.cov["search_positions_total"]
        pending = None
        self.check(timing=False)
        try:
            while position < total:
                self.check()
                # 65536-byte 창의 뒤 3 bytes는 다음 header 위치 창과 겹친다.
                end = min(total, position + _WINDOW - 3)
                found = self.data.find(b"ftyp", position + 4, end + 7)
                if found < 0:
                    position = end
                    continue
                position = found - 4
                pending = position
                self.summary["anchors_observed"] += 1
                self.anchor(position)
                position += 1
                pending = None
        except _Limit as stop:
            self.reason(stop.reason)
            self.cov["search_complete"] = False
            self.cov["pending_anchor_offset"] = pending
            self.cov["candidate_checks_complete"] = pending is None
            self.cov["unexamined_positions"] = {"start": position, "count": total - position,
                                                "reason": stop.reason}
        self.cov["search_positions_examined"] = position
        self.summary["candidates_reported"] = len(self.rows)
        self.summary["candidates_omitted"] = self.summary["supported_anchors"] - len(self.rows)
        self.cov["candidate_list_complete"] = (self.cov["search_complete"]
            and self.cov["candidate_checks_complete"] and self.summary["candidates_omitted"] == 0)
        self.relations()
        if self.cov["reasons"]:
            self.report["status"] = "partial"
        elif self.rows:
            self.report["status"] = "ok"
        return self.report


def scan_bmff_candidates(data: bytes, *, limits: BmffCandidateLimits = BmffCandidateLimits(),
                         deadline: float, cancel: Callable[[], bool] | None = None) -> dict:
    """연속 박스 prefix 후보를 제한적으로 관찰한다. 파일·fd·장치는 열지 않는다."""
    if type(data) is not bytes or type(limits) is not BmffCandidateLimits:
        raise ValidationFailed("미디어 후보 검사 입력 형식이 올바르지 않습니다.")
    defaults = BmffCandidateLimits()
    for field in fields(defaults):
        value = getattr(limits, field.name)
        low = 8192 if field.name == "max_output_bytes" else 1
        if type(value) is not int or not low <= value <= getattr(defaults, field.name):
            raise ValidationFailed("미디어 후보 검사 상한이 올바르지 않습니다.")
    finite = False
    if type(deadline) in (float, int):
        try:
            finite = math.isfinite(deadline)
        except OverflowError:
            pass
    if not finite:
        raise ValidationFailed("미디어 후보 검사 deadline이 올바르지 않습니다.")
    if cancel is not None and not callable(cancel):
        raise ValidationFailed("미디어 후보 검사 취소 함수가 올바르지 않습니다.")
    if len(data) > limits.max_input_bytes:
        raise ValidationFailed("미디어 후보 검사 입력 크기 상한을 넘었습니다.")
    return _Scanner(data, limits, min(deadline, time.monotonic() + 45), cancel).scan()
