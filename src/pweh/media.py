"""선택 bytes의 BMFF 경계와 제한된 timing·PSSH·보호 선언을 관찰한다. 미디어는 해독하지 않는다."""
from __future__ import annotations

import json
import math
import struct
import time
from dataclasses import dataclass, fields
from typing import Callable

from .errors import PwehError, ValidationFailed

SCHEMA = "pweh.media-inventory/v1"
PROFILE = "mp4-quicktime-protection-declarations-v1"
MAX_INPUT_BYTES = 64 << 20
MAX_OUTPUT_BYTES = 1 << 20
BOX_KINDS = ("ftyp", "styp", "moov", "mdat", "free", "skip", "wide", "uuid", "trak", "mdia",
             "minf", "stbl", "edts", "dinf", "mvex", "moof", "traf", "meta", "udta",
             "mvhd", "mdhd", "pssh", "stsd", "encv", "enca", "sinf", "schm", "schi", "tenc", "unknown")
BRANDS = ("isom", "iso2", "iso3", "iso4", "iso5", "iso6", "mp41", "mp42", "quicktime", "unknown")
DECLARATION_ISSUES = ("unsupported_declaration_version", "unsupported_declaration_flags",
                      "truncated_declaration_fields", "zero_timescale", "pssh_length_mismatch")
PROTECTION_ISSUES = ("stsd_entry_count_mismatch", "unsupported_sample_entry", "unsupported_audio_entry_version",
                     "unsupported_protection_shape", "unsupported_protection_scheme", "unsupported_protection_value")
REASONS = ("truncated_base_header", "truncated_extended_header", "truncated_uuid_header",
           "size_below_header", "box_beyond_parent", "unsupported_nested_size_zero", "invalid_ftyp_shape",
           "box_limit", "depth_limit", "brand_limit", "range_limit", "output_limit", "time_limit",
           "multiple_ftyp", "unsupported_wide_shape", "selection_uncertain", "container_listing_incomplete",
           *DECLARATION_ISSUES, *PROTECTION_ISSUES)
RANGE_REASONS = ("box_header", "brand_table", "leaf_payload", "unknown_payload", "metadata_payload",
                 "unsupported_context", "declaration_fields", "declaration_identifiers", "declaration_payload",
                 *REASONS[:13], "stsd_entry_count_mismatch")
LIMITATIONS = ("box_framing_and_selected_declarations_only", "opaque_payloads_unexamined",
               "no_format_conformance_validation", "no_media_type_confirmation", "no_sample_or_playback_validation",
               "no_absolute_time_or_codec_analysis", "no_encryption_assessment", "selected_file_only",
               "unknown_identifiers_not_returned", "declared_duration_not_playback_duration",
               "pssh_structure_not_encryption_proof", "sample_protection_prefixes_only",
               "full_tenc_and_constant_iv_unexamined", "sample_auxiliary_and_groups_unexamined",
               "protection_declarations_not_encryption_proof")
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
_STBL_PATH = ("moov", "trak", "mdia", "minf", "stbl")
_PROTECTION_KEYS = ("tables", "entries", "schemes", "track_defaults")
_PROTECTION_ROW_ISSUES = (*DECLARATION_ISSUES[:3], *PROTECTION_ISSUES)


@dataclass(frozen=True)
class MediaLimits:
    """기본 상한보다 낮출 수만 있다. 출력 상한은 고정 봉투를 위해 최소 4096이다."""

    max_input_bytes: int = MAX_INPUT_BYTES
    max_boxes: int = 4096
    max_depth: int = 10
    max_brands_per_box: int = 64
    max_brands_total: int = 256
    max_ranges: int = 8193
    max_output_bytes: int = MAX_OUTPUT_BYTES


class _Stop(Exception):
    def __init__(self, reason: str, offset: int):
        self.reason, self.offset = reason, offset


@dataclass
class _Frame:
    """검증한 부모와 stsd의 남은 직접 entry 수만 보존한다."""

    end: int
    parent_index: int | None
    kind: str | None
    table_index: int | None = None
    remaining: int | None = None


def _protection_context(kind: str, chain: tuple[str, ...]) -> str | None:
    if chain == (*_STBL_PATH, "stsd"):
        return "entries"
    if kind == "stsd" and chain == _STBL_PATH:
        return "tables"
    if len(chain) >= 7 and chain[:6] == (*_STBL_PATH, "stsd") and chain[6] in ("encv", "enca"):
        suffix = chain[7:]
        if kind == "sinf" and not suffix or kind == "schi" and suffix == ("sinf",):
            return "container"
        if kind == "schm" and suffix == ("sinf",):
            return "schemes"
        if kind == "tenc" and suffix == ("sinf", "schi"):
            return "track_defaults"
    return None


def _size(value: object) -> int:
    return len(json.dumps(value, ensure_ascii=True, separators=(",", ":"), allow_nan=False).encode("ascii"))


def _new(size: int) -> dict:
    return {"schema": SCHEMA, "status": "unsupported", "format": "unknown", "profile": PROFILE,
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
            "declarations": {"scope": "mvhd-mdhd-pssh-sample-protection-selected-contexts", "status": "complete",
                             "timing": [], "pssh": [],
                             "protection": {"scope": "stsd-encv-enca-sinf-schm-tenc-prefixes", "status": "complete",
                                            "tables": [], "entries": [], "schemes": [], "track_defaults": [],
                                            "coverage": {"traversal_complete": True, "fields_complete": True, "reasons": []},
                                            "full_tenc_examined": False, "sample_auxiliary_examined": False,
                                            "identifiers_returned": False},
                             "coverage": {"traversal_complete": True, "fields_complete": True, "reasons": []},
                             "absolute_times_returned": False, "sample_entries_examined": False,
                             "sample_encryption_examined": False},
            "limitations": list(LIMITATIONS)}


class _Parser:
    def __init__(self, data: bytes, limits: MediaLimits, deadline: float, cancel: Callable[[], bool] | None):
        self.data, self.limits, self.deadline, self.cancel = data, limits, deadline, cancel
        self.report = _new(len(data))
        self.unknown_types: set[bytes] = set()
        self.unknown_brands: set[bytes] = set()
        self.slots = 0
        self.protection_reasons: list[str] = []
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

    def emit(self, box: dict, ranges: list[dict], table: dict | None = None,
             declaration: dict | None = None, protection: tuple[str, dict] | None = None) -> None:
        old = self.report["coverage"]["ranges"]
        tail, range_cost, replaced = self.range_plan(ranges)
        count = len(old) - int(replaced) + len(tail)
        end = ranges[-1]["offset"] + ranges[-1]["length"]
        if count + int(end < len(self.data)) > self.limits.max_ranges:
            raise _Stop("range_limit", box["offset"])
        cost = _size(box) + 1 + range_cost + (_size(table) + 1 if table is not None else 0)
        if declaration is not None:
            cost += _size(declaration) + 1
        if protection is not None:
            key, row = protection
            row_cost = _size(row)
            if key == "tables" and row["entries_declared"] is not None:
                # 부모의 마지막 판정은 각 row의 최대형 비용 안에 들어야 한다.
                final = {**row, "entries_reported": 4096, "entries_complete": False,
                         "status": "malformed", "issues": ["stsd_entry_count_mismatch"]}
                row_cost = max(row_cost, _size(final))
            cost += row_cost + 1
        if self.cost + cost + self.reserve > self.limits.max_output_bytes:
            raise _Stop("output_limit", box["offset"])
        # 선언 row·상자·읽은 범위는 같은 경계에서 게시한다. 중간 만료는 leaf 전체를 미검사로 남긴다.
        if declaration is not None or protection is not None:
            self.check(box["offset"])
        self.cost += cost
        if replaced:
            old[-1:] = tail
        else:
            old.extend(tail)
        self.report["boxes"].append(box)
        if table is not None:
            self.report["brands"]["tables"].append(table)
        if declaration is not None:
            key = "pssh" if box["kind"] == "pssh" else "timing"
            self.report["declarations"][key].append(declaration)
            for issue in declaration["issues"]:
                self.reason(issue)
        if protection is not None:
            key, row = protection
            self.report["declarations"]["protection"][key].append(row)
            for issue in row["issues"]:
                self.protection_reason(issue)

    def protection_reason(self, reason: str) -> None:
        self.reason(reason)
        if reason not in self.protection_reasons:
            self.protection_reasons.append(reason)

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

    def declaration_context(self, kind: str, parent_index: int | None) -> bool:
        """이미 게시한 부모 사슬이 지원하는 정확한 계층인지 확인한다."""
        if kind not in ("mvhd", "mdhd", "pssh"):
            return False
        ancestors = []
        while parent_index is not None:
            parent = self.report["boxes"][parent_index]
            ancestors.append(parent["kind"])
            parent_index = parent["parent_index"]
        chain = tuple(reversed(ancestors))
        return (chain == ("moov",) if kind == "mvhd" else
                chain == ("moov", "trak", "mdia") if kind == "mdhd" else
                chain in (("moov",), ("moof",)))

    def protection_context(self, kind: str, parent_index: int | None) -> str | None:
        chain = []
        while parent_index is not None:
            parent = self.report["boxes"][parent_index]
            chain.append(parent["kind"])
            parent_index = parent["parent_index"]
        return _protection_context(kind, tuple(reversed(chain)))

    def declaration(self, box: dict, end: int) -> tuple[dict, list[dict]]:
        """고정 필드만 임시 해석한다. 상자 끝을 넘기거나 식별자·본문을 복사하지 않는다."""
        start, kind = box["offset"], box["kind"]
        payload = start + box["header_size"]
        row = {"box_index": box["index"], "parent_index": box["parent_index"], "version": None,
               "status": "complete", "issues": []}
        if kind != "pssh":
            row.update(kind=kind, creation_time_state="unread", modification_time_state="unread",
                       timescale=None, duration_units=None, duration_state="unread")
        ranges = [self.span(start, payload, "header", "box_header")]

        def add(left: int, right: int, category: str, reason: str) -> None:
            if left < right:
                ranges.append(self.span(left, right, category, reason))

        def read(offset: int, fmt: str) -> int:
            self.check(start)
            return struct.unpack_from(fmt, self.data, offset)[0]

        def issue(reason: str) -> None:
            row["status"] = "unsupported" if reason.startswith("unsupported_") else "malformed"
            row["issues"] = [reason]

        # 짧은 FullBox조차 다른 상자에서 빌려 읽지 않는다.
        if end - payload < 4:
            issue("truncated_declaration_fields")
            add(payload, end, "skipped", "declaration_payload")
            return row, ranges
        fullbox = read(payload, ">I")
        version, flags = fullbox >> 24, fullbox & 0xffffff
        ranges[0] = self.span(start, payload + 4, "header", "declaration_fields")
        row["version"] = version if version in (0, 1) else None
        if version not in (0, 1) or flags:
            issue("unsupported_declaration_version" if version not in (0, 1) else
                  "unsupported_declaration_flags")
            add(payload + 4, end, "skipped", "declaration_payload")
            return row, ranges

        if kind != "pssh":
            prefix = 20 if version == 0 else 32
            if end - payload < prefix:
                issue("truncated_declaration_fields")
                add(payload + 4, end, "skipped", "declaration_payload")
                return row, ranges
            width, fmt = (4, ">I") if version == 0 else (8, ">Q")
            row["creation_time_state"] = "nonzero" if read(payload + 4, fmt) else "zero"
            row["modification_time_state"] = "nonzero" if read(payload + 4 + width, fmt) else "zero"
            row["timescale"] = read(payload + 4 + width * 2, ">I")
            duration = read(payload + 8 + width * 2, fmt)
            indeterminate = duration == (1 << (width * 8)) - 1
            row["duration_units"] = None if indeterminate else duration
            row["duration_state"] = "indeterminate" if indeterminate else "declared" if duration else "zero"
            ranges[0] = self.span(start, payload + prefix, "header", "declaration_fields")
            add(payload + prefix, end, "skipped", "declaration_payload")
            if row["timescale"] == 0:
                issue("zero_timescale")
            return row, ranges

        # SystemID와 KID는 경계 산술만 수행한다. count에 비례한 읽기·반복·할당은 없다.
        if end - payload < (24 if version == 0 else 28):
            issue("truncated_declaration_fields")
            add(payload + 4, end, "skipped", "declaration_payload")
            return row, ranges
        add(payload + 4, payload + 20, "skipped", "declaration_identifiers")
        data_size_at = payload + 20
        if version == 1:
            count = read(payload + 20, ">I")
            add(payload + 20, payload + 24, "header", "declaration_fields")
            # 남은 실제 byte 수로 먼저 제한해 검증하지 못한 가상 범위를 만들지 않는다.
            if count > (end - payload - 28) // 16:
                issue("pssh_length_mismatch")
                add(payload + 24, end, "skipped", "declaration_identifiers")
                return row, ranges
            data_size_at = payload + 24 + count * 16
            add(payload + 24, data_size_at, "skipped", "declaration_identifiers")
        data_size = read(data_size_at, ">I")
        add(data_size_at, data_size_at + 4, "header", "declaration_fields")
        add(data_size_at + 4, end, "skipped", "declaration_payload")
        if data_size != end - data_size_at - 4:
            issue("pssh_length_mismatch")
        return row, ranges

    def protection(self, box: dict, end: int, key: str) -> tuple[dict, list[dict], int | None]:
        """고정 보호 필드와 임시 범위만 만든다. prefix 바깥 내용은 복사하지 않는다."""
        start, kind = box["offset"], box["kind"]
        p = start + box["header_size"]
        length = end - p
        row = {"box_index": box["index"], "status": "complete", "issues": []}
        ranges = [self.span(start, p, "header", "box_header")]

        def span(left, right, category="skipped", reason="declaration_payload"):
            if left < right:
                ranges.append(self.span(left, right, category, reason))

        def read(at, fmt):
            self.check(start)
            return struct.unpack_from(fmt, self.data, at)[0]

        def issue(reason):
            row["status"] = "unsupported" if reason.startswith("unsupported_") else "malformed"
            row["issues"].append(reason)

        if key == "tables":
            row.update(version=None, entries_declared=None, entries_reported=0, entries_complete=False)
        elif key == "entries":
            row.update(parent_index=box["parent_index"], kind=kind if kind in ("encv", "enca") else "other",
                       prefix_kind="unread")
            if kind not in ("encv", "enca"):
                row["prefix_kind"] = "unsupported"
                issue("unsupported_sample_entry")
                span(p, end, reason="unsupported_context")
                return row, ranges, None
            if kind == "encv":
                if length < 78:
                    issue("truncated_declaration_fields")
                    span(p, end)
                    return row, ranges, None
                row["prefix_kind"] = "visual"
                span(p, p + 78)
                return row, ranges, p + 78
            if length < 10:
                issue("truncated_declaration_fields")
                span(p, end)
                return row, ranges, None
            version = read(p + 8, ">H")
            span(p, p + 8)
            span(p + 8, p + 10, "header", "declaration_fields")
            if version != 0:
                row["prefix_kind"] = "unsupported"
                issue("unsupported_audio_entry_version")
                span(p + 10, end)
                return row, ranges, None
            if length < 28:
                issue("truncated_declaration_fields")
                span(p + 10, end)
                return row, ranges, None
            row["prefix_kind"] = "audio-v0"
            span(p + 10, p + 28)
            return row, ranges, p + 28
        else:
            parent = self.report["boxes"][box["parent_index"]]
            if key == "track_defaults":
                parent = self.report["boxes"][parent["parent_index"]]
            row.update(parent_index=box["parent_index"], entry_index=parent["parent_index"], version=None)
            row["scheme_type" if key == "schemes" else "default_is_protected_state"] = "unread"

        if length < 4:
            issue("truncated_declaration_fields")
            span(p, end)
            return row, ranges, None
        fullbox = read(p, ">I")
        version, flags = fullbox >> 24, fullbox & 0xffffff
        allowed = (0, 1) if key == "track_defaults" else (0,)
        row["version"] = version if version in allowed else None
        ranges[0] = self.span(start, p + 4, "header", "declaration_fields")
        if version not in allowed or flags:
            issue("unsupported_declaration_version" if version not in allowed else "unsupported_declaration_flags")
            issue("unsupported_protection_shape")
            span(p + 4, end)
            return row, ranges, None
        minimum = 8 if key == "tables" else 12 if key == "schemes" else 24
        if length < minimum:
            issue("truncated_declaration_fields")
            span(p + 4, end)
            return row, ranges, None
        if key == "tables":
            row["entries_declared"] = read(p + 4, ">I")
            ranges[0] = self.span(start, p + 8, "header", "declaration_fields")
            return row, ranges, p + 8
        if key == "schemes":
            if length != 12:
                issue("unsupported_protection_shape")
                span(p + 4, end)
                return row, ranges, None
            scheme = read(p + 4, ">I")
            row["scheme_type"] = {0x63656e63: "cenc", 0x63626373: "cbcs"}.get(scheme, "other")
            ranges[0] = self.span(start, p + 8, "header", "declaration_fields")
            span(p + 8, end)
            if row["scheme_type"] == "other":
                issue("unsupported_protection_scheme")
        else:
            value = read(p + 6, ">B")
            row["default_is_protected_state"] = "zero" if value == 0 else "one" if value == 1 else "other"
            span(p + 4, p + 6)
            span(p + 6, p + 7, "header", "declaration_fields")
            span(p + 7, end)
            if value not in (0, 1):
                issue("unsupported_protection_value")
        return row, ranges, None

    def parse(self) -> dict:
        cursor, size = 0, len(self.data)
        stack = [_Frame(size, None, None)]
        boxes = self.report["boxes"]
        protection = self.report["declarations"]["protection"]
        try:
            self.check(0)
            while stack:
                frame = stack[-1]
                parent_end, parent_index, parent_kind = frame.end, frame.parent_index, frame.kind
                if frame.table_index is not None and (cursor == parent_end or frame.remaining == 0):
                    self.check(cursor)
                    stsd = protection["tables"][frame.table_index]
                    if cursor != parent_end or frame.remaining != 0:
                        stsd.update(status="malformed", issues=["stsd_entry_count_mismatch"])
                        self.protection_reason("stsd_entry_count_mismatch")
                        raise _Stop("stsd_entry_count_mismatch", cursor)
                    stsd["entries_complete"] = True
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
                declaration_context = self.declaration_context(kind, parent_index)
                protection_key = self.protection_context(kind, parent_index)
                if protection_key is not None:
                    children = protection_key == "container"
                box = {"index": len(boxes), "parent_index": parent_index, "kind": kind,
                       "offset": cursor, "size": length, "header_size": header, "depth": depth,
                       "handling": "children" if children else "brand-table" if brand_table else
                                   "declaration" if declaration_context else "skipped",
                       "children_complete": False if children else None}
                table, stop_reason, declaration, protection_row = None, None, None, None
                brand_snapshot = set(self.unknown_brands) if brand_table else None
                if protection_key is not None and protection_key != "container":
                    protection_row, ranges, child_start = self.protection(box, end, protection_key)
                    children = child_start is not None
                    box.update(handling="children" if children else "declaration",
                               children_complete=False if children else None)
                    next_cursor = child_start if children else end
                elif brand_table:
                    table, prefix, stop_reason = self.brands(cursor, header, end, box["index"])
                    ranges = [self.span(cursor, prefix, "header", "brand_table")]
                    next_cursor = prefix
                elif declaration_context:
                    declaration, ranges = self.declaration(box, end)
                    next_cursor = end
                else:
                    ranges = [self.span(cursor, cursor + header, "header", "box_header")]
                    next_cursor = cursor + header if children else end
                    if not children and length > header:
                        reason = "unknown_payload" if kind == "unknown" else (
                            "metadata_payload" if kind in ("uuid", "meta", "udta") else (
                                "unsupported_context" if kind in _CHILDREN or kind in
                                ("ftyp", "mvhd", "mdhd", "pssh", "stsd", "encv", "enca", "sinf", "schm", "schi", "tenc")
                                else "leaf_payload"))
                        ranges.append(self.span(cursor + header, end, "skipped", reason))
                try:
                    self.emit(box, ranges, table, declaration,
                              (protection_key, protection_row) if protection_row is not None else None)
                except _Stop:
                    if brand_snapshot is not None:
                        self.unknown_brands = brand_snapshot
                    raise
                if protection_key == "entries":
                    frame.remaining -= 1
                    protection["tables"][frame.table_index]["entries_reported"] += 1
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
                    table_index = len(protection["tables"]) - 1 if protection_key == "tables" else None
                    remaining_entries = protection_row["entries_declared"] if table_index is not None else None
                    stack.append(_Frame(end, box["index"], kind, table_index, remaining_entries))
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
        declarations = report["declarations"]
        protection = declarations["protection"]
        protection_fields = all(row["status"] == "complete" for key in _PROTECTION_KEYS for row in protection[key])
        protection_reasons = list(self.protection_reasons)
        for reason in cov["reasons"]:
            if reason in REASONS[:13] and reason not in protection_reasons:
                protection_reasons.append(reason)
        protection["coverage"].update(traversal_complete=cov["structure_complete"],
                                      fields_complete=protection_fields, reasons=protection_reasons)
        protection["status"] = "complete" if cov["structure_complete"] and protection_fields else "partial"
        declarations["sample_entries_examined"] = any(row["prefix_kind"] in ("visual", "audio-v0")
                                                       for row in protection["entries"])
        fields_complete = all(row["status"] == "complete" for key in ("timing", "pssh")
                              for row in declarations[key]) and protection_fields
        declarations["coverage"].update(
            traversal_complete=cov["structure_complete"], fields_complete=fields_complete,
            reasons=[r for r in cov["reasons"] if r in (*REASONS[:13], *DECLARATION_ISSUES, *PROTECTION_ISSUES)])
        declarations["status"] = "complete" if cov["structure_complete"] and fields_complete else "partial"
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
        validate_media_protection_accounting(report)
        return report


def _protection_keys(value, names: str) -> None:
    if type(value) is not dict or set(value) != set(names.split()):
        raise ValueError


def _protection_uint(value, lower=0, upper=4095) -> int:
    if type(value) is not int or not lower <= value <= upper:
        raise ValueError
    return value


def _protection_list(value, maximum=4096) -> list:
    if type(value) is not list or len(value) > maximum:
        raise ValueError
    return value


def _protection_issues(row, allowed) -> list:
    issues = _protection_list(row["issues"], len(allowed))
    if (any(type(issue) is not str or issue not in allowed for issue in issues)
            or len(set(issues)) != len(issues)):
        raise ValueError
    status = "complete" if not issues else "unsupported" if all(r.startswith("unsupported_") for r in issues) else "malformed"
    if row["status"] != status:
        raise ValueError
    return issues


def _validate_media_protection(report: dict) -> None:
    if type(report) is not dict or report.get("profile") != PROFILE:
        raise ValueError
    boxes = _protection_list(report["boxes"])
    declarations, global_cov = report["declarations"], report["coverage"]
    _protection_keys(declarations, "scope status timing pssh protection coverage absolute_times_returned "
                                   "sample_entries_examined sample_encryption_examined")
    if (declarations["scope"] != "mvhd-mdhd-pssh-sample-protection-selected-contexts"
            or declarations["absolute_times_returned"] is not False or declarations["sample_encryption_examined"] is not False
            or type(global_cov["structure_complete"]) is not bool):
        raise ValueError
    chains = []
    for index, box in enumerate(boxes):
        _protection_keys(box, "index parent_index kind offset size header_size depth handling children_complete")
        if _protection_uint(box["index"]) != index or type(box["kind"]) is not str or box["kind"] not in BOX_KINDS:
            raise ValueError
        start = _protection_uint(box["offset"], 0, MAX_INPUT_BYTES)
        size = _protection_uint(box["size"], 8, MAX_INPUT_BYTES)
        header = _protection_uint(box["header_size"], 8, 32)
        depth = _protection_uint(box["depth"], 1, 10)
        if header not in (8, 16, 24, 32) or size < header or start + size > global_cov["input_bytes"]:
            raise ValueError
        parent_index = box["parent_index"]
        if parent_index is None:
            chain = ()
            if depth != 1:
                raise ValueError
        else:
            parent_index = _protection_uint(parent_index, 0, index - 1)
            parent = boxes[parent_index]
            chain = (*chains[parent_index], parent["kind"])
            if (parent["handling"] != "children" or depth != parent["depth"] + 1
                    or start < parent["offset"] + parent["header_size"]
                    or start + size > parent["offset"] + parent["size"]):
                raise ValueError
        if box["handling"] == "children":
            if type(box["children_complete"]) is not bool or global_cov["structure_complete"] and not box["children_complete"]:
                raise ValueError
        elif box["handling"] not in ("declaration", "skipped", "brand-table") or box["children_complete"] is not None:
            raise ValueError
        chains.append(chain)
    protection = declarations["protection"]
    _protection_keys(protection, "scope status tables entries schemes track_defaults coverage full_tenc_examined "
                                "sample_auxiliary_examined identifiers_returned")
    if (protection["scope"] != "stsd-encv-enca-sinf-schm-tenc-prefixes"
            or any(protection[k] is not False for k in ("full_tenc_examined", "sample_auxiliary_examined", "identifiers_returned"))):
        raise ValueError
    by_key = {key: {} for key in _PROTECTION_KEYS}
    seen, observed_issues = set(), set()
    for key in _PROTECTION_KEYS:
        previous = -1
        for row in _protection_list(protection[key]):
            common = "box_index status issues"
            extra = {"tables": "version entries_declared entries_reported entries_complete",
                     "entries": "parent_index kind prefix_kind",
                     "schemes": "parent_index entry_index version scheme_type",
                     "track_defaults": "parent_index entry_index version default_is_protected_state"}[key]
            _protection_keys(row, common + " " + extra)
            index = _protection_uint(row["box_index"], 0, len(boxes) - 1)
            if index in seen or index <= previous:
                raise ValueError
            previous = index
            seen.add(index)
            box = boxes[index]
            if _protection_context(box["kind"], chains[index]) != key:
                raise ValueError
            issues = _protection_issues(row, _PROTECTION_ROW_ISSUES)
            observed_issues.update(issues)
            if key != "tables":
                if _protection_uint(row["parent_index"], 0, index - 1) != box["parent_index"]:
                    raise ValueError
            if key == "entries":
                expected = box["kind"] if box["kind"] in ("encv", "enca") else "other"
                if row["kind"] != expected:
                    raise ValueError
                prefix = row["prefix_kind"]
                if expected == "other":
                    if prefix != "unsupported" or issues != ["unsupported_sample_entry"]:
                        raise ValueError
                elif not issues:
                    if prefix != ("visual" if expected == "encv" else "audio-v0"):
                        raise ValueError
                elif issues == ["unsupported_audio_entry_version"] and expected == "enca":
                    if prefix != "unsupported":
                        raise ValueError
                elif issues != ["truncated_declaration_fields"] or prefix != "unread":
                    raise ValueError
                if (box["handling"] == "children") is not (prefix in ("visual", "audio-v0")):
                    raise ValueError
            else:
                allowed = (0, 1) if key == "track_defaults" else (0,)
                if row["version"] is not None and (type(row["version"]) is not int or row["version"] not in allowed):
                    raise ValueError
                if key == "tables":
                    declared = row["entries_declared"]
                    _protection_uint(row["entries_reported"], 0, 4096)
                    if type(row["entries_complete"]) is not bool:
                        raise ValueError
                    if declared is not None:
                        _protection_uint(declared, 0, 0xffffffff)
                        if (row["version"] != 0 or box["handling"] != "children"
                                or issues not in ([], ["stsd_entry_count_mismatch"])):
                            raise ValueError
                    elif row["entries_reported"] or row["entries_complete"] or box["handling"] != "declaration":
                        raise ValueError
                else:
                    if box["handling"] != "declaration":
                        raise ValueError
                    parent = boxes[box["parent_index"]]
                    if key == "track_defaults":
                        parent = boxes[parent["parent_index"]]
                    if _protection_uint(row["entry_index"], 0, index - 1) != parent["parent_index"]:
                        raise ValueError
                    field = "scheme_type" if key == "schemes" else "default_is_protected_state"
                    value = row[field]
                    choices = ("cenc", "cbcs") if key == "schemes" else ("zero", "one")
                    other_issue = "unsupported_protection_scheme" if key == "schemes" else "unsupported_protection_value"
                    if value in choices:
                        if issues or row["version"] is None:
                            raise ValueError
                    elif value == "other":
                        if issues != [other_issue] or row["version"] is None:
                            raise ValueError
                    elif value != "unread" or not issues:
                        raise ValueError
                # 아직 선언값을 못 읽은 variant는 정해진 실패 조합만 갖는다.
                unread = row["entries_declared"] is None if key == "tables" else row[field] == "unread"
                if unread:
                    valid = (["truncated_declaration_fields"],
                             ["unsupported_declaration_version", "unsupported_protection_shape"],
                             ["unsupported_declaration_flags", "unsupported_protection_shape"])
                    if issues not in valid and not (key == "schemes" and issues == ["unsupported_protection_shape"]):
                        raise ValueError
                    if "unsupported_declaration_version" in issues and row["version"] is not None:
                        raise ValueError
                    if "unsupported_declaration_flags" in issues and row["version"] is None:
                        raise ValueError
            by_key[key][index] = row
    if len(seen) > len(boxes):
        raise ValueError
    expected = {i for i, box in enumerate(boxes) if _protection_context(box["kind"], chains[i]) in _PROTECTION_KEYS}
    if seen != expected:
        raise ValueError
    for index, row in by_key["entries"].items():
        table = by_key["tables"].get(row["parent_index"])
        if table is None or table["entries_declared"] is None:
            raise ValueError
    for key in ("schemes", "track_defaults"):
        for row in by_key[key].values():
            entry = by_key["entries"].get(row["entry_index"])
            if entry is None or entry["prefix_kind"] not in ("visual", "audio-v0"):
                raise ValueError
    counts = dict.fromkeys(by_key["tables"], 0)
    for row in by_key["entries"].values():
        counts[row["parent_index"]] += 1
    for index, row in by_key["tables"].items():
        if row["entries_reported"] != counts[index]:
            raise ValueError
        declared = row["entries_declared"]
        if declared is not None:
            if (row["entries_reported"] > declared or row["entries_complete"] is not boxes[index]["children_complete"]
                    or row["entries_complete"] and (counts[index] != declared or row["issues"])):
                raise ValueError
    # 자식은 실제로 검사한 prefix 뒤에서만 시작한다. 부모 box header 안쪽만으로는 부족하다.
    for box in boxes:
        parent_index = box["parent_index"]
        if parent_index in by_key["tables"]:
            prefix = 8
        elif parent_index in by_key["entries"]:
            prefix = 78 if boxes[parent_index]["kind"] == "encv" else 28
        else:
            continue
        parent = boxes[parent_index]
        if box["offset"] < parent["offset"] + parent["header_size"] + prefix:
            raise ValueError
    global_reasons = _protection_list(global_cov["reasons"], len(REASONS))
    if (any(type(r) is not str or r not in REASONS for r in global_reasons)
            or len(set(global_reasons)) != len(global_reasons) or not observed_issues.issubset(global_reasons)):
        raise ValueError
    fields_complete = all(row["status"] == "complete" for key in _PROTECTION_KEYS for row in protection[key])
    _check_protection_coverage(protection, global_cov["structure_complete"], fields_complete,
                               observed_issues | (set(global_reasons) & set(REASONS[:13])))
    timing_rows = [row for key in ("timing", "pssh") for row in _protection_list(declarations[key])]
    if len(timing_rows) + len(seen) > len(boxes):
        raise ValueError
    for row in timing_rows:
        if type(row) is not dict:
            raise ValueError
        index = _protection_uint(row["box_index"], 0, len(boxes) - 1)
        if index in seen or boxes[index]["handling"] != "declaration":
            raise ValueError
        kind = row.get("kind", "pssh")
        chain = chains[index]
        if (boxes[index]["kind"] != kind or row["parent_index"] != boxes[index]["parent_index"]
                or not (chain == ("moov",) if kind == "mvhd" else
                        chain == ("moov", "trak", "mdia") if kind == "mdhd" else
                        kind == "pssh" and chain in (("moov",), ("moof",)))):
            raise ValueError
        seen.add(index)
        _protection_issues(row, DECLARATION_ISSUES)
    if declarations["sample_entries_examined"] is not any(row["prefix_kind"] in ("visual", "audio-v0")
                                                           for row in protection["entries"]):
        raise ValueError
    _check_protection_coverage(declarations, global_cov["structure_complete"],
                               fields_complete and all(r["status"] == "complete" for r in timing_rows),
                               set(global_reasons) & set((*REASONS[:13], *DECLARATION_ISSUES, *PROTECTION_ISSUES)))


def _check_protection_coverage(section, traversal, fields_complete, reasons):
    cov = section["coverage"]
    _protection_keys(cov, "traversal_complete fields_complete reasons")
    actual = _protection_list(cov["reasons"], len(REASONS))
    if (any(type(r) is not str for r in actual) or len(set(actual)) != len(actual) or set(actual) != reasons
            or cov["traversal_complete"] is not traversal or cov["fields_complete"] is not fields_complete
            or section["status"] != ("complete" if traversal and fields_complete else "partial")):
        raise ValueError


def validate_media_protection_accounting(report: dict) -> None:
    """새 profile의 상자·선언 관계만 검사한다. source/params·원문 재파싱·I/O는 다루지 않는다."""
    try:
        _validate_media_protection(report)
    except (ValueError, KeyError, TypeError, IndexError, OverflowError):
        raise ValidationFailed("미디어 보호 선언 보고서의 관계가 올바르지 않습니다.") from None


def inventory_isobmff(data: bytes, *, limits: MediaLimits = MediaLimits(), deadline: float,
                      cancel: Callable[[], bool] | None = None) -> dict:
    """선택 bytes의 박스 경계·제한 선언을 반환한다. deadline 만료는 partial, 취소는 오류다."""
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
