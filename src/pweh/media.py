"""완전한 선택 bytes의 BMFF 박스 경계만 관찰한다. 미디어 본문은 해독하지 않는다."""
from __future__ import annotations

import json
import math
import struct
import time
from dataclasses import dataclass, fields
from typing import Callable

from .errors import PwehError, ValidationFailed

SCHEMA = "pweh.media-inventory/v1"
MAX_INPUT_BYTES = 64 << 20
MAX_OUTPUT_BYTES = 1 << 20
BOX_KINDS = ("ftyp", "styp", "moov", "mdat", "free", "skip", "wide", "uuid", "trak", "mdia",
             "minf", "stbl", "edts", "dinf", "mvex", "moof", "traf", "meta", "udta", "unknown")
BRANDS = ("isom", "iso2", "iso3", "iso4", "iso5", "iso6", "mp41", "mp42", "quicktime", "unknown")
REASONS = ("truncated_base_header", "truncated_extended_header", "truncated_uuid_header",
           "size_below_header", "box_beyond_parent", "unsupported_nested_size_zero", "invalid_ftyp_shape",
           "box_limit", "depth_limit", "brand_limit", "range_limit", "output_limit", "time_limit",
           "multiple_ftyp", "unsupported_wide_shape", "selection_uncertain", "container_listing_incomplete")
RANGE_REASONS = ("box_header", "brand_table", "leaf_payload", "unknown_payload", "metadata_payload",
                 "unsupported_context", *REASONS[:13])
LIMITATIONS = ("box_framing_only", "opaque_payloads_unexamined", "no_format_conformance_validation",
               "no_media_type_confirmation", "no_sample_or_playback_validation", "no_time_or_codec_analysis",
               "no_encryption_assessment", "selected_file_only", "unknown_identifiers_not_returned")
CONTAINER_REASONS = ("time", "unsupported_archive_compression", "incomplete_archive", "max_metadata",
                     "max_entries", "invalid_archive", "unsupported_archive", "trailing_data_unexamined",
                     "trailing_data", "unsupported_sparse", "steps", "max_depth", "max_dir_slots",
                     "max_total_slots", "max_path_chars", "beyond_image", "dir_chain_broken", "dir_unreadable",
                     "dir_unvalidated", "unknown_container_limit")
_KINDS = {kind.encode("ascii"): kind for kind in BOX_KINDS if kind != "unknown"}
_BRANDS = {brand.encode("ascii"): brand for brand in BRANDS if brand not in ("quicktime", "unknown")}
_BRANDS[b"qt  "] = "quicktime"
_CHILDREN = {None: ("moov", "moof"), "moov": ("trak", "mvex"), "trak": ("mdia", "edts"),
             "mdia": ("minf",), "minf": ("stbl", "dinf"), "moof": ("traf",),
             "mvex": (), "edts": (), "stbl": (), "dinf": (), "traf": ()}


@dataclass(frozen=True)
class MediaLimits:
    """기본 상한보다 낮출 수만 있다. 출력 상한은 고정 봉투를 위해 최소 4096이다."""

    max_input_bytes: int = MAX_INPUT_BYTES
    max_boxes: int = 4096
    max_depth: int = 8
    max_brands_per_box: int = 64
    max_brands_total: int = 256
    max_ranges: int = 8193
    max_output_bytes: int = MAX_OUTPUT_BYTES


class _Stop(Exception):
    def __init__(self, reason: str, offset: int):
        self.reason, self.offset = reason, offset


def _size(value: object) -> int:
    return len(json.dumps(value, ensure_ascii=True, separators=(",", ":"), allow_nan=False).encode("ascii"))


def _new(size: int) -> dict:
    return {"schema": SCHEMA, "status": "unsupported", "format": "unknown", "profile": "mp4-quicktime-box-v1",
            "framing_status": "complete", "recognition": "empty" if not size else "unbranded",
            "media_decoded": False, "playback_verified": False, "recording_time_verified": False,
            "encryption_assessed": False, "format_conformance_assessed": False,
            "brands": {"tables": [], "known": [], "slots_examined": 0, "unknown_count": 0,
                       "unknown_distinct_count": 0}, "boxes": [],
            "observations": {"top_level_ftyp": False, "top_level_moov": False, "top_level_mdat": False,
                             "top_level_moof": False, "top_level_styp": False,
                             "initialization_context": "not-assessed"},
            "summary": {"boxes_seen": 0, "boxes_reported": 0, "unknown_box_count": 0,
                        "unknown_type_distinct_count": 0, "max_depth_seen": 0},
            "coverage": {"input_bytes": size, "header_bytes": 0, "skipped_payload_bytes": 0,
                         "unexamined_bytes": 0, "structure_complete": True, "container_examined": False,
                         "selection_uncertain": False, "reasons": [], "ranges": []},
            "limitations": list(LIMITATIONS)}


class _Parser:
    def __init__(self, data: bytes, limits: MediaLimits, deadline: float, cancel: Callable[[], bool] | None):
        self.data, self.limits, self.deadline, self.cancel = data, limits, deadline, cancel
        self.report = _new(len(data))
        self.unknown_types: set[bytes] = set()
        self.unknown_brands: set[bytes] = set()
        self.slots = 0
        self.cost = _size(self.report)
        self.reserve = min(32768, limits.max_output_bytes // 2)

    def check(self, offset: int, *, deadline: bool = True) -> None:
        if self.cancel is not None:
            try:
                cancelled = self.cancel()
                if type(cancelled) is not bool:
                    raise ValueError
            except Exception:
                raise PwehError("미디어 구조 검사의 취소 상태를 확인하지 못했습니다.",
                                code="media_inventory_failed") from None
            if cancelled:
                raise PwehError("미디어 구조 검사가 취소되었습니다.", code="cancelled")
        if deadline and time.monotonic() >= self.deadline:
            raise _Stop("time_limit", offset)

    def reason(self, reason: str) -> None:
        if reason not in self.report["coverage"]["reasons"]:
            self.report["coverage"]["reasons"].append(reason)

    def range_plan(self, additions: list[dict]) -> tuple[list[dict], int, bool]:
        ranges = self.report["coverage"]["ranges"]
        tail = [dict(ranges[-1])] if ranges else []
        cost = -_size(tail[0]) if tail else 0
        replaced = bool(tail)
        for item in additions:
            if not item["length"]:
                continue
            if tail and all(tail[-1][k] == item[k] for k in ("kind", "reason")):
                assert tail[-1]["offset"] + tail[-1]["length"] == item["offset"]
                tail[-1]["length"] += item["length"]
            else:
                tail.append(dict(item))
        cost += sum(_size(item) for item in tail) + len(tail) - int(replaced)
        return tail, cost, replaced

    def emit(self, box: dict, ranges: list[dict], table: dict | None = None) -> None:
        old = self.report["coverage"]["ranges"]
        tail, range_cost, replaced = self.range_plan(ranges)
        count = len(old) - int(replaced) + len(tail)
        end = ranges[-1]["offset"] + ranges[-1]["length"]
        if count + int(end < len(self.data)) > self.limits.max_ranges:
            raise _Stop("range_limit", box["offset"])
        cost = _size(box) + 1 + range_cost + (_size(table) + 1 if table is not None else 0)
        if self.cost + cost + self.reserve > self.limits.max_output_bytes:
            raise _Stop("output_limit", box["offset"])
        self.cost += cost
        if replaced:
            old[-1:] = tail
        else:
            old.extend(tail)
        self.report["boxes"].append(box)
        if table is not None:
            self.report["brands"]["tables"].append(table)

    def brands(self, start: int, header: int, end: int, index: int) -> tuple[dict, int, str | None]:
        if end - start - header < 8 or (end - start - header - 8) % 4:
            raise _Stop("invalid_ftyp_shape", start)
        table = {"box_index": index, "major": None, "compatible": [], "compatible_count": 0,
                 "unknown_count": 0, "unknown_distinct_count": 0, "slots_examined": 0, "complete": False}
        unknown: set[bytes] = set()
        prefix = start + header
        total = 1 + (end - prefix - 8) // 4
        for slot in range(total):
            try:
                self.check(prefix)
            except _Stop as stop:
                return table, prefix, stop.reason
            if slot >= self.limits.max_brands_per_box or self.slots >= self.limits.max_brands_total:
                return table, prefix, "brand_limit"
            offset = start + header if slot == 0 else start + header + 8 + (slot - 1) * 4
            raw = self.data[offset:offset + 4]
            brand = _BRANDS.get(raw, "unknown")
            if slot == 0:
                table["major"] = brand
            else:
                table["compatible_count"] += 1
                if brand not in table["compatible"]:
                    table["compatible"].append(brand)
            self.slots += 1
            table["slots_examined"] += 1
            if brand == "unknown":
                table["unknown_count"] += 1
                unknown.add(raw)
                table["unknown_distinct_count"] = len(unknown)
                self.unknown_brands.add(raw)
            prefix = offset + (8 if slot == 0 else 4)
        table["complete"] = True
        return table, prefix, None

    @staticmethod
    def span(start: int, end: int, kind: str, reason: str) -> dict:
        return {"offset": start, "length": end - start, "kind": kind, "reason": reason}

    def parse(self) -> dict:
        cursor, size = 0, len(self.data)
        # 각 frame은 끝, 부모 record index, 그 부모의 kind다. 검증한 frame만 쌓는다.
        stack: list[tuple[int, int | None, str | None]] = [(size, None, None)]
        boxes = self.report["boxes"]
        try:
            self.check(0)
            while stack:
                parent_end, parent_index, parent_kind = stack[-1]
                if cursor == parent_end:
                    if parent_index is not None:
                        boxes[parent_index]["children_complete"] = True
                    stack.pop()
                    continue
                self.check(cursor)
                if len(boxes) >= self.limits.max_boxes:
                    raise _Stop("box_limit", cursor)
                depth = len(stack)
                if depth > self.limits.max_depth:
                    raise _Stop("depth_limit", cursor)
                remaining = parent_end - cursor
                if remaining < 8:
                    raise _Stop("truncated_base_header", cursor)
                small = struct.unpack_from(">I", self.data, cursor)[0]
                raw = self.data[cursor + 4:cursor + 8]
                kind, header, length = _KINDS.get(raw, "unknown"), 8, small
                if small == 1:
                    if remaining < 16:
                        raise _Stop("truncated_extended_header", cursor)
                    length = struct.unpack_from(">Q", self.data, cursor + 8)[0]
                    header = 16
                elif small == 0:
                    if parent_index is not None:
                        raise _Stop("unsupported_nested_size_zero", cursor)
                    length = remaining
                if kind == "uuid":
                    header += 16
                    if remaining < header:
                        raise _Stop("truncated_uuid_header", cursor)
                if length < header:
                    raise _Stop("size_below_header", cursor)
                if length > remaining:
                    raise _Stop("box_beyond_parent", cursor)
                end = cursor + length
                self.report["summary"]["boxes_seen"] += 1
                children = kind in _CHILDREN.get(parent_kind, ())
                brand_table = kind == "ftyp" and parent_index is None
                box = {"index": len(boxes), "parent_index": parent_index, "kind": kind,
                       "offset": cursor, "size": length, "header_size": header, "depth": depth,
                       "handling": "children" if children else "brand-table" if brand_table else "skipped",
                       "children_complete": False if children else None}
                table, stop_reason = None, None
                brand_snapshot = set(self.unknown_brands) if brand_table else None
                if brand_table:
                    table, prefix, stop_reason = self.brands(cursor, header, end, box["index"])
                    ranges = [self.span(cursor, prefix, "header", "brand_table")]
                    next_cursor = prefix
                else:
                    ranges = [self.span(cursor, cursor + header, "header", "box_header")]
                    next_cursor = cursor + header if children else end
                    if not children and length > header:
                        reason = "unknown_payload" if kind == "unknown" else (
                            "metadata_payload" if kind in ("uuid", "meta", "udta") else (
                                "unsupported_context" if kind in _CHILDREN or kind == "ftyp" else "leaf_payload"))
                        ranges.append(self.span(cursor + header, end, "skipped", reason))
                try:
                    self.emit(box, ranges, table)
                except _Stop:
                    if brand_snapshot is not None:
                        self.unknown_brands = brand_snapshot
                    raise
                if kind == "unknown":
                    self.unknown_types.add(raw)
                if kind == "wide" and length != 8:
                    self.reason("unsupported_wide_shape")
                if parent_index is None and "top_level_" + kind in self.report["observations"]:
                    self.report["observations"]["top_level_" + kind] = True
                cursor = next_cursor
                if stop_reason:
                    raise _Stop(stop_reason, cursor)
                if children:
                    stack.append((end, box["index"], kind))
        except _Stop as stop:
            cursor = stop.offset
            self.reason(stop.reason)
            self.report["framing_status"] = "partial"
            self.report["coverage"]["structure_complete"] = False
            if cursor < size:
                tail, _, replaced = self.range_plan([self.span(cursor, size, "unexamined", stop.reason)])
                ranges = self.report["coverage"]["ranges"]
                if replaced:
                    ranges[-1:] = tail
                else:
                    ranges.extend(tail)
        self.check(cursor, deadline=False)
        return self.finish()

    def finish(self) -> dict:
        report, cov = self.report, self.report["coverage"]
        tables, boxes = report["brands"]["tables"], report["boxes"]
        # 예산으로 반환하지 못한 ftyp의 관찰값을 summary에 섞지 않는다.
        known = {b for table in tables for b in (table["major"], *table["compatible"]) if b not in (None, "unknown")}
        report["brands"].update(known=[b for b in BRANDS if b in known],
                                slots_examined=sum(t["slots_examined"] for t in tables),
                                unknown_count=sum(t["unknown_count"] for t in tables))
        report["brands"]["unknown_distinct_count"] = len(self.unknown_brands)
        obs = report["observations"]
        if cov["input_bytes"]:
            report["recognition"] = ("allowed_brand" if known else "unknown_brand" if tables else
                                     "fragment_candidate" if obs["top_level_moof"] else "unbranded")
        obs["initialization_context"] = "moov-observed" if obs["top_level_moov"] else (
            "unavailable" if obs["top_level_moof"] else "not-assessed")
        if len(tables) > 1:
            self.reason("multiple_ftyp")
        report["format"] = "iso-bmff" if known else "unknown"
        report["status"] = "partial" if cov["reasons"] else "ok" if known else "unsupported"
        report["summary"].update(boxes_reported=len(boxes), unknown_box_count=sum(b["kind"] == "unknown" for b in boxes),
                                 unknown_type_distinct_count=len(self.unknown_types),
                                 max_depth_seen=max((b["depth"] for b in boxes), default=0))
        for kind, key in (("header", "header_bytes"), ("skipped", "skipped_payload_bytes"),
                          ("unexamined", "unexamined_bytes")):
            cov[key] = sum(r["length"] for r in cov["ranges"] if r["kind"] == kind)
        if len(cov["ranges"]) > self.limits.max_ranges or _size(report) > self.limits.max_output_bytes:
            raise PwehError("미디어 구조 결과의 고정 출력 상한을 지키지 못했습니다.", code="media_inventory_failed")
        return report


def inventory_isobmff(data: bytes, *, limits: MediaLimits = MediaLimits(), deadline: float,
                      cancel: Callable[[], bool] | None = None) -> dict:
    """선택 bytes의 제한된 박스 경계를 반환한다. deadline 만료는 partial, 취소는 오류다."""
    if type(data) is not bytes or type(limits) is not MediaLimits:
        raise ValidationFailed("미디어 구조 검사는 완전한 bytes와 정해진 상한만 받습니다.")
    maximum = MediaLimits()
    for field in fields(limits):
        value = getattr(limits, field.name)
        minimum = 4096 if field.name == "max_output_bytes" else 1
        if type(value) is not int or not minimum <= value <= getattr(maximum, field.name):
            raise ValidationFailed("미디어 구조 검사 상한이 허용 범위를 벗어났습니다.")
    if len(data) > limits.max_input_bytes:
        raise PwehError("선택 파일이 미디어 구조 검사 입력 상한을 넘습니다.", code="input_too_large")
    if (type(deadline) not in (int, float) or not math.isfinite(deadline)
            or cancel is not None and not callable(cancel)):
        raise ValidationFailed("미디어 구조 검사 시간·취소 인자가 올바르지 않습니다.")
    return _Parser(data, limits, deadline, cancel).parse()
