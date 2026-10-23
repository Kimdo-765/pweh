"""선택 bytes의 네 고정 미디어 subset 경계만 검사한다. 디코딩·본문 의미 해석은 없다."""

from __future__ import annotations

from dataclasses import dataclass, fields
import json
import math
import time
from typing import Callable

from .errors import PwehError, ValidationFailed

SCHEMA = "pweh.media-unit-candidates/v1"
FORMATS = ("jpeg", "avc-annexb", "mpeg2-ps", "xm")
FILE_PROFILES = dict(zip(FORMATS, ("jpeg-baseline-marker-v1", "avc-annexb-delimited-nal-v1",
                                  "mpeg2-ps-bounded-pack-prefix-v1", "xm-length-delimited-frame-v1")))
RANGE_PROFILES = {key: value[:-3] + "-ev-range-v1" for key, value in FILE_PROFILES.items()}
RESIDUAL_PROFILES = {key: value[:-3] + "-exfat-residual-v1" for key, value in FILE_PROFILES.items()}
MIN_UNIT_BYTES = dict(zip(FORMATS, (28, 4, 24, 9)))
MIN_SELECTED_BYTES = dict(zip(FORMATS, (28, 8, 24, 9)))
FALSE_FIELDS = ("media_decoded", "playback_verified", "recording_time_verified", "encryption_assessed",
                "format_conformance_assessed", "original_file_boundary_verified", "complete_recording",
                "payload_semantics_examined")
REJECTIONS = ("invalid_header", "invalid_length", "invalid_sequence", "invalid_escape", "empty_payload")
UNSUPPORTED = ("unsupported_variant", "unsupported_extension", "multiple_scans", "zero_length_packet")
INCOMPLETE = ("truncated_header", "unit_beyond_selection", "open_tail")
LIMIT_REASONS = ("probe_limit", "candidate_limit", "step_limit", "work_byte_limit", "output_limit", "time_limit")
REASONS = (*LIMIT_REASONS, "unit_framing_incomplete", "candidate_prefix_partial",
           "selection_uncertain", "container_listing_incomplete")
LIMITATIONS = ("structural_candidates_only", "format_subset_only", "original_file_boundary_unknown",
               "complete_recording_unverified", "candidate_overlap_unclassified", "payload_semantics_unexamined")
RANGE_LIMITATIONS = ("explicit_evidence_range_only", "outside_range_unexamined")
RESIDUAL_LIMITATIONS = ("exfat_valid_data_length_residual_only", "logical_offsets_not_evidence_offsets",
                        "no_original_recording_or_deletion_verification")
_UNITS = dict(zip(FORMATS, ("jpeg_codestream", "avc_nal", "mpeg2_ps_pack_prefix", "xm_frame")))
_PS_PREFIX = ("selection_end", "truncated_packet", "unsupported_packet", "invalid_packet", "zero_length_packet")
_WINDOW = 65536
_ENVELOPE = 4096
_ROW = 512


@dataclass(frozen=True)
class MediaUnitLimits:
    """운영 기본 상한 이하로만 줄일 수 있는 전체 호출 예산."""

    max_input_bytes: int = 64 << 20
    max_anchor_probes: int = 1024
    max_candidates: int = 128
    max_structure_steps: int = 8192
    max_work_bytes: int = 128 << 20
    max_output_bytes: int = 1 << 20


class _Stop(Exception):
    def __init__(self, reason: str):
        self.reason = reason


class _Result(Exception):
    def __init__(self, group: str, reason: str):
        self.group, self.reason = group, reason


def _reject(reason="invalid_header"):
    raise _Result("rejected", reason)


def _unsupported(reason="unsupported_variant"):
    raise _Result("unsupported", reason)


def _incomplete(reason="truncated_header"):
    raise _Result("incomplete", reason)


def _new(size: int, format: str) -> dict:
    return {"schema": SCHEMA, "profile": FILE_PROFILES[format], "format": format, "status": "unsupported",
            **dict.fromkeys(FALSE_FIELDS, False),
            "summary": {"anchors_observed": 0, "anchors_rejected": 0, "unsupported_anchors": 0,
                        "incomplete_anchors": 0, "candidates_reported": 0, "closed_candidates": 0,
                        "prefix_candidates": 0, "anchor_rejections": dict.fromkeys(REJECTIONS, 0),
                        "anchor_unsupported": dict.fromkeys(UNSUPPORTED, 0),
                        "anchor_incomplete": dict.fromkeys(INCOMPLETE, 0)},
            "coverage": {"input_bytes": size, "search_positions_total": size, "search_positions_examined": 0,
                         "unexamined_positions": None, "pending_anchor_offset": None, "search_complete": True,
                         "candidate_checks_complete": True, "candidate_list_complete": True, "anchor_probes": 0,
                         "structure_steps": 0, "search_bytes_charged": 0, "structure_bytes_charged": 0,
                         "work_bytes_charged": 0, "selection_uncertain": False, "container_examined": False,
                         "reasons": []}, "candidates": [], "limitations": list(LIMITATIONS)}


class _Scanner:
    def __init__(self, data, format, limits, deadline, cancel):
        self.data, self.size, self.format = data, len(data), format
        self.limits, self.deadline, self.cancel = limits, deadline, cancel
        self.report = _new(self.size, format)
        self.cov, self.summary, self.rows = (self.report[k] for k in ("coverage", "summary", "candidates"))

    def check(self, timing=True):
        if self.cancel is not None:
            try:
                value = self.cancel()
            except Exception:
                raise PwehError("미디어 단위 후보 검사의 취소 상태를 확인하지 못했습니다.",
                                code="media_unit_candidates_failed") from None
            if type(value) is not bool:
                raise PwehError("미디어 단위 후보 검사의 취소 상태를 확인하지 못했습니다.",
                                code="media_unit_candidates_failed") from None
            if value:
                raise PwehError("미디어 단위 후보 검사가 취소되었습니다.", code="cancelled") from None
        if timing and time.monotonic() >= self.deadline:
            raise _Stop("time_limit")

    def charge(self, size, *, search=False):
        self.check()
        if self.cov["work_bytes_charged"] + size > self.limits.max_work_bytes:
            raise _Stop("work_byte_limit")
        self.cov["search_bytes_charged" if search else "structure_bytes_charged"] += size
        self.cov["work_bytes_charged"] += size

    def step(self):
        self.check()
        if self.cov["structure_steps"] >= self.limits.max_structure_steps:
            raise _Stop("step_limit")
        self.cov["structure_steps"] += 1

    def read(self, start, size):
        if start < 0 or size < 0 or start + size > self.size:
            _incomplete()
        self.charge(size)
        return self.data[start:start + size]

    def find(self, needle, start, end, *, search=False):
        """작은 창만 예약하며 marker 사이 긴 본문을 Python byte 루프로 순회하지 않는다."""
        while start < end:
            stop = min(end, start + _WINDOW - len(needle) + 1)
            read_end = min(end, stop + len(needle) - 1)
            self.charge(read_end - start, search=search)
            found = self.data.find(needle, start, read_end)
            if found >= 0:
                return found
            start = stop
        return -1

    def row(self, start, end, subtype, boundary, *, framing="closed", reason=None):
        return {"index": len(self.rows), "offset": start, "length": end - start, "format": self.format,
                "unit": _UNITS[self.format], "unit_subtype": subtype, "boundary_kind": boundary,
                "framing_status": framing, "end_reason": reason or boundary, "confidence": "possible"}

    def anchor(self, start, end):
        needle = b"\xff\xd8" if self.format == "jpeg" else b"\0\0\1\xba" if self.format == "mpeg2-ps" else b"\0\0\1"
        found = self.find(needle, start, end, search=True)
        if found >= 0 and self.format == "avc-annexb" and found > 0:
            if self.read(found - 1, 1) == b"\0":
                found -= 1
                if found < start:
                    # 앞 호출에서 처리한4byte prefix의 내부3byte 위치다. 같은 위치로 돌아가지 않는다.
                    return self.anchor(found + 4, end)
        return found

    def jpeg(self, start):
        pos, frame, scanned, entropy, restart, rst = start + 2, None, False, 0, 0, 0
        while True:
            self.step()
            if pos >= self.size:
                _incomplete("open_tail")
            if scanned:
                found = self.find(b"\xff", pos, self.size)
                if found < 0:
                    _incomplete("open_tail")
                entropy += found - pos
                pos = found
            if self.read(pos, 1) != b"\xff":
                _reject("invalid_sequence")
            marker_start = pos
            # fill byte가 많아도 동일 step에서 유한 창으로 검사한다.
            pos += 1
            while pos < self.size and self.read(pos, 1)[0] == 0xff:
                pos += 1
            code = self.read(pos, 1)[0]
            pos += 1
            if scanned and code == 0:
                if pos - marker_start != 2:
                    _reject("invalid_escape")
                entropy += 1
                continue
            if 0xd0 <= code <= 0xd7:
                if not scanned or not restart or code != 0xd0 + rst:
                    _reject("invalid_sequence")
                rst = (rst + 1) % 8
                continue
            if code == 0xd9:
                if not scanned or entropy == 0:
                    _reject("empty_payload" if scanned else "invalid_sequence")
                return self.row(start, pos, "baseline", "eoi")
            if code == 0xda and scanned:
                _unsupported("multiple_scans")
            if scanned:
                _unsupported("unsupported_extension")
            if code in (0xd8, 0, 1):
                _reject("invalid_sequence")
            if code != 0xc0 and (0xc0 <= code <= 0xcf and code not in (0xc4, 0xc8, 0xcc)):
                _unsupported()
            if code not in (0xc0, 0xc4, 0xdb, 0xdd, 0xda, 0xfe) and not 0xe0 <= code <= 0xef:
                _unsupported("unsupported_extension")
            length = int.from_bytes(self.read(pos, 2), "big")
            if length < 2:
                _reject("invalid_length")
            end = pos + length
            if end > self.size:
                _incomplete("unit_beyond_selection")
            if code == 0xc0:
                if frame is not None:
                    _reject("invalid_sequence")
                if length < 11:
                    _reject("invalid_length")
                head = self.read(pos + 2, 6)
                count = head[5]
                if not 1 <= count <= 4:
                    _unsupported()
                if length != 8 + count * 3:
                    _reject("invalid_length")
                if head[0] != 8 or not int.from_bytes(head[3:5], "big"):
                    _reject()
                if not int.from_bytes(head[1:3], "big"):
                    _unsupported("unsupported_extension")
                body = self.read(pos + 8, count * 3)
                frame = set()
                for i in range(0, len(body), 3):
                    ident, hv, tq = body[i:i + 3]
                    if ident in frame or not 1 <= hv >> 4 <= 4 or not 1 <= hv & 15 <= 4 or tq > 3:
                        _reject()
                    frame.add(ident)
            elif code == 0xdd:
                if length != 4:
                    _reject("invalid_length")
                restart = int.from_bytes(self.read(pos + 2, 2), "big")
            elif code == 0xda:
                if frame is None:
                    _reject("invalid_sequence")
                count = self.read(pos + 2, 1)[0]
                if count != len(frame) or length != 6 + 2 * count:
                    _reject("invalid_length")
                body = self.read(pos + 3, count * 2 + 3)
                ids = set()
                for i in range(0, count * 2, 2):
                    ident, ht = body[i:i + 2]
                    if ident not in frame or ident in ids or ht >> 4 > 1 or ht & 15 > 1:
                        _reject()
                    ids.add(ident)
                if body[-3:] != b"\x00\x3f\x00":
                    _reject()
                scanned = True
            pos = end

    def nal_header(self, pos):
        head = self.read(pos, 1)[0]
        kind, ref = head & 31, (head >> 5) & 3
        if head & 0x80:
            _reject()
        if not 1 <= kind <= 12:
            _unsupported()
        if (kind in (5, 7, 8) and not ref) or (kind in (6, 9, 10, 11, 12) and ref):
            _reject()
        return kind

    def avc(self, start):
        self.step()
        prefix = 4 if self.read(start, 3) == b"\0\0\0" else 3
        hpos = start + prefix
        kind = self.nal_header(hpos)
        pos = hpos + 1
        end = None
        while pos < self.size:
            # 00 00만 찾으므로 escape/경계 검사도 marker 수만큼만 수행한다.
            pair = self.find(b"\0\0", pos, self.size)
            if pair < 0:
                break
            self.step()
            if pair + 2 >= self.size:
                _incomplete("open_tail")
            third = self.read(pair + 2, 1)[0]
            if third in (0, 1):
                end = pair
                break
            if third == 2:
                _reject("invalid_escape")
            if third == 3:
                if pair + 3 < self.size and self.read(pair + 3, 1)[0] > 3:
                    _reject("invalid_escape")
                pos = pair + 3
            else:
                pos = pair + 2
        if end is None:
            _incomplete("open_tail")
        # 최초 종료0부터 delimiter까지 모두0이어야 한다. 다른 자료를 건너뛰지 않는다.
        nxt = end
        while nxt < self.size and self.read(nxt, 1) == b"\0":
            nxt += 1
        if nxt >= self.size:
            _incomplete("open_tail")
        if self.read(nxt, 1) != b"\1" or nxt - end < 2:
            _reject("invalid_escape")
        self.nal_header(nxt + 1)
        payload = end - (hpos + 1)
        if kind in (10, 11):
            if payload:
                _reject("invalid_length")
        elif not payload:
            _reject("empty_payload")
        return self.row(start, end, "nal_" + str(kind), "next_nal")

    def pack(self, pos):
        data = self.read(pos, 14)
        if data[:4] != b"\0\0\1\xba":
            _reject()
        if data[4] >> 6 != 1:
            _unsupported()
        if not (data[4] & 4 and data[6] & 4 and data[8] & 4 and data[9] & 1):
            _reject()
        if data[12] & 3 != 3 or data[13] & 0xf8 != 0xf8:
            _reject()
        if not ((data[10] << 14) | (data[11] << 6) | (data[12] >> 2)):
            _reject()
        stuffing = data[13] & 7
        if self.read(pos + 14, stuffing) != b"\xff" * stuffing:
            _reject()
        return pos + 14 + stuffing

    def ps(self, start):
        self.step()
        pos, media = self.pack(start), False
        while True:
            self.step()
            if pos == self.size:
                if media:
                    return self.row(start, pos, "mpeg2_pack", "validated_prefix", framing="prefix", reason="selection_end")
                _incomplete("open_tail")
            try:
                code = self.read(pos, 4)
                if code == b"\0\0\1\xba":
                    self.pack(pos)
                    if not media:
                        _reject("empty_payload")
                    return self.row(start, pos, "mpeg2_pack", "next_pack")
                if code == b"\0\0\1\xb9":
                    if not media:
                        _reject("empty_payload")
                    return self.row(start, pos, "mpeg2_pack", "program_end")
                if code[:3] != b"\0\0\1":
                    _reject()
                stream = code[3]
                is_media = stream == 0xbd or 0xc0 <= stream <= 0xef
                if stream not in (0xbb, 0xbc, 0xbe) and not is_media:
                    _unsupported("unsupported_extension")
                length = int.from_bytes(self.read(pos + 4, 2), "big")
                if is_media and not length:
                    _unsupported("zero_length_packet")
                end = pos + 6 + length
                if end > self.size:
                    _incomplete("unit_beyond_selection")
                if stream in (0xbb, 0xbc) and length < (6 if stream == 0xbb else 10):
                    _reject("invalid_length")
                if is_media:
                    if length < 4:
                        _reject("empty_payload")
                    head = self.read(pos + 6, 3)
                    if head[0] & 0xc0 != 0x80 or head[1] >> 6 == 1:
                        _reject()
                    if head[0] & 0x30 or head[1] & 0x3f:
                        _unsupported("unsupported_extension")
                    header_size, ptsdts = head[2], head[1] >> 6
                    needed = 10 if ptsdts == 3 else 5 if ptsdts == 2 else 0
                    if header_size < needed or length <= 3 + header_size:
                        _reject("invalid_length")
                    header = self.read(pos + 9, header_size)
                    for n, flag in ((0, 3 if ptsdts == 3 else 2), (5, 1)):
                        if n >= needed:
                            break
                        part = header[n:n + 5]
                        if part[0] >> 4 != flag or any(not part[k] & 1 for k in (0, 2, 4)):
                            _reject()
                    if header[needed:] != b"\xff" * (header_size - needed):
                        _reject()
                    media = True
                pos = end
            except _Result as result:
                if not media:
                    raise
                reason = ("truncated_packet" if result.group == "incomplete" else
                          "zero_length_packet" if result.reason == "zero_length_packet" else
                          "unsupported_packet" if result.group == "unsupported" else "invalid_packet")
                return self.row(start, pos, "mpeg2_pack", "validated_prefix", framing="prefix", reason=reason)

    def xm(self, start):
        self.step()
        kind = self.read(start + 3, 1)[0]
        if kind not in (0xfc, 0xfe, 0xfd, 0xfa, 0xf9):
            _unsupported()
        header_size = 16 if kind in (0xfc, 0xfe) else 8
        head = self.read(start, header_size)
        if kind != 0xfd:
            allowed = (1, 2) if kind == 0xfc else (0,) if kind == 0xfe else (14,) if kind == 0xfa else (1,)
            if head[4] & 15 not in allowed:
                _unsupported()
        length = int.from_bytes(head[12:16] if header_size == 16 else head[4:8] if kind == 0xfd else head[6:8], "little")
        if not length:
            _reject("empty_payload")
        end = start + header_size + length
        if end > self.size:
            _incomplete("unit_beyond_selection")
        return self.row(start, end, "type_" + format(kind, "02x"), "declared_length")

    def scan(self):
        position, pending, reasons = 0, None, set()
        parser = {"jpeg": self.jpeg, "avc-annexb": self.avc, "mpeg2-ps": self.ps, "xm": self.xm}[self.format]
        self.check(False)
        try:
            while position < self.size:
                # 글로벌 찾기를 작은 창으로 나누어 완료prefix를 실제로 진전시킨다.
                end = min(self.size, position + _WINDOW - 4)
                found = self.anchor(position, min(self.size, end + 4))
                if found < 0 or found >= end:
                    position = end
                    continue
                position = pending = found
                self.summary["anchors_observed"] += 1
                self.check()
                if self.cov["anchor_probes"] >= self.limits.max_anchor_probes:
                    raise _Stop("probe_limit")
                if len(self.rows) >= self.limits.max_candidates:
                    raise _Stop("candidate_limit")
                if _ENVELOPE + (len(self.rows) + 1) * _ROW > self.limits.max_output_bytes:
                    raise _Stop("output_limit")
                self.cov["anchor_probes"] += 1
                try:
                    row = parser(position)
                    self.check()
                except _Result as result:
                    group, reason = result.group, result.reason
                    key, total = {"rejected": ("anchor_rejections", "anchors_rejected"),
                                  "unsupported": ("anchor_unsupported", "unsupported_anchors"),
                                  "incomplete": ("anchor_incomplete", "incomplete_anchors")}[group]
                    self.check()
                    self.summary[key][reason] += 1
                    self.summary[total] += 1
                else:
                    self.rows.append(row)
                    self.summary["candidates_reported"] += 1
                    self.summary["closed_candidates" if row["framing_status"] == "closed" else "prefix_candidates"] += 1
                position += 1
                pending = None
        except _Stop as stop:
            reasons.add(stop.reason)
            self.cov["unexamined_positions"] = {"start": position, "count": self.size - position, "reason": stop.reason}
        self.cov["search_positions_examined"] = position
        self.cov["pending_anchor_offset"] = pending
        self.cov["search_complete"] = position == self.size
        self.cov["candidate_checks_complete"] = pending is None and not self.summary["incomplete_anchors"]
        self.cov["candidate_list_complete"] = self.cov["search_complete"] and self.cov["candidate_checks_complete"]
        if self.summary["incomplete_anchors"]:
            reasons.add("unit_framing_incomplete")
        if self.summary["prefix_candidates"]:
            reasons.add("candidate_prefix_partial")
        self.cov["reasons"] = [reason for reason in REASONS if reason in reasons]
        self.report["status"] = "partial" if reasons else "ok" if self.rows else "unsupported"
        self.check(False)
        # 예약식은 현재고정row상한보다크다. 수정후에도 실제출력크기를확인한다.
        if len(json.dumps(self.report, ensure_ascii=True, separators=(",", ":")).encode()) + 1 > self.limits.max_output_bytes:
            raise PwehError("미디어 단위 후보 결과의 크기 상한을 넘었습니다.", code="media_unit_candidates_failed") from None
        return self.report


def scan_media_unit_candidates(data: bytes, *, format: str, limits: MediaUnitLimits = MediaUnitLimits(),
                               deadline: float, cancel: Callable[[], bool] | None = None) -> dict:
    """한 고정format의 구조후보와 검사범위를 반환한다. 내용/재생/암호화는 판정하지 않는다."""
    if type(data) is not bytes or type(format) is not str or format not in FORMATS or type(limits) is not MediaUnitLimits:
        raise ValidationFailed("미디어 단위 후보 검사 입력 형식이 올바르지 않습니다.") from None
    for field in fields(MediaUnitLimits):
        value = getattr(limits, field.name)
        if type(value) is not int or not (8192 if field.name == "max_output_bytes" else 1) <= value <= getattr(MediaUnitLimits(), field.name):
            raise ValidationFailed("미디어 단위 후보 검사 상한이 올바르지 않습니다.") from None
    try:
        finite = type(deadline) in (int, float) and math.isfinite(deadline)
    except OverflowError:
        finite = False
    if not finite or (cancel is not None and not callable(cancel)) or len(data) > limits.max_input_bytes:
        raise ValidationFailed("미디어 단위 후보 검사의 크기·시간·취소 인자가 올바르지 않습니다.") from None
    return _Scanner(data, format, limits, min(deadline, time.monotonic() + 45), cancel).scan()


def validate_media_unit_accounting(report: dict) -> None:
    """닫힌schema와 별도로 exact숫자·관계·완료등식을 검사한다. 원시자료/파일을 읽지 않는다."""
    try:
        _validate(report)
    except (KeyError, TypeError, ValueError, OverflowError):
        raise ValidationFailed("미디어 단위 후보 보고서의 수치 또는 완료 관계가 올바르지 않습니다.") from None


def _int(value, cap, low=0):
    if type(value) is not int or not low <= value <= cap:
        raise ValueError()
    return value


def _require(condition):
    if not condition:
        raise ValueError()


def _validate(report):
    _require(type(report) is dict and report["schema"] == SCHEMA)
    format = report["format"]
    _require(type(format) is str and format in FORMATS)
    is_range = report["profile"] == RANGE_PROFILES[format]
    is_residual = report["profile"] == RESIDUAL_PROFILES[format]
    _require(is_range or is_residual or report["profile"] == FILE_PROFILES[format])
    suffix = RESIDUAL_LIMITATIONS if is_residual else RANGE_LIMITATIONS if is_range else ()
    _require(report["limitations"] == list(LIMITATIONS) + list(suffix))
    if is_residual:
        _require("source" in report and "params" in report)
    summary, cov, rows = report["summary"], report["coverage"], report["candidates"]
    _require(type(summary) is dict and type(cov) is dict and type(rows) is list and len(rows) <= 128)
    observed = _int(summary["anchors_observed"], 1025)
    completed = 0
    for total_key, map_key, names in (("anchors_rejected", "anchor_rejections", REJECTIONS),
                                     ("unsupported_anchors", "anchor_unsupported", UNSUPPORTED),
                                     ("incomplete_anchors", "anchor_incomplete", INCOMPLETE)):
        total = _int(summary[total_key], 1024)
        values = summary[map_key]
        _require(type(values) is dict and len(values) == len(names) and set(values) == set(names))
        _require(total == sum(_int(values[name], 1024) for name in names))
        completed += total
    reported = _int(summary["candidates_reported"], 128)
    closed = _int(summary["closed_candidates"], 128)
    prefix = _int(summary["prefix_candidates"], 128)
    _require(reported == len(rows) == closed + prefix)
    completed += reported
    size = _int(cov["input_bytes"], 64 << 20)
    total = _int(cov["search_positions_total"], 64 << 20)
    cursor = _int(cov["search_positions_examined"], total)
    _require(total == size)
    probes = _int(cov["anchor_probes"], 1024)
    _int(cov["structure_steps"], 8192)
    work = _int(cov["work_bytes_charged"], 128 << 20)
    _require(work == _int(cov["search_bytes_charged"], 128 << 20)
             + _int(cov["structure_bytes_charged"], 128 << 20))
    pending = cov["pending_anchor_offset"]
    if pending is not None:
        _require(_int(pending, max(0, size - 1)) == cursor < total)
    _require(observed == completed + int(pending is not None))
    _require(completed <= probes <= observed)
    for name in ("search_complete", "candidate_checks_complete", "candidate_list_complete", "selection_uncertain", "container_examined"):
        _require(type(cov[name]) is bool)
    _require(cov["container_examined"] is False and all(report[key] is False for key in FALSE_FIELDS))
    checks = pending is None and summary["incomplete_anchors"] == 0
    _require(cov["search_complete"] == (cursor == total))
    _require(cov["candidate_checks_complete"] == checks)
    _require(cov["candidate_list_complete"] == (checks and cursor == total))
    reasons = cov["reasons"]
    _require(type(reasons) is list and len(reasons) <= len(REASONS))
    _require(all(type(reason) is str and reason in REASONS for reason in reasons))
    _require(reasons == [reason for reason in REASONS if reason in reasons])
    _require(("unit_framing_incomplete" in reasons) == (summary["incomplete_anchors"] > 0))
    _require(("candidate_prefix_partial" in reasons) == (prefix > 0))
    _require(("selection_uncertain" in reasons) == cov["selection_uncertain"])
    limited = [reason for reason in LIMIT_REASONS if reason in reasons]
    unexamined = cov["unexamined_positions"]
    if cursor == total:
        _require(unexamined is None and not limited)
    else:
        _require(type(unexamined) is dict and len(limited) == 1)
        _require(_int(unexamined["start"], total) == cursor)
        _require(_int(unexamined["count"], total, 1) == total - cursor)
        _require(unexamined["reason"] == limited[0])
    if any(name in reasons for name in ("probe_limit", "candidate_limit", "output_limit", "step_limit")):
        _require(pending is not None)
    previous, actual_prefix = -1, 0
    for index, row in enumerate(rows):
        _require(type(row) is dict and _int(row["index"], 127) == index)
        offset = _int(row["offset"], size)
        length = _int(row["length"], 64 << 20, MIN_UNIT_BYTES[format])
        _require(previous < offset < cursor and offset + length <= size)
        _require(row["format"] == format and row["unit"] == _UNITS[format] and row["confidence"] == "possible")
        subtype, framing, boundary, end = (row[k] for k in ("unit_subtype", "framing_status", "boundary_kind", "end_reason"))
        if format == "jpeg":
            _require((subtype, framing, boundary, end) == ("baseline", "closed", "eoi", "eoi"))
        elif format == "avc-annexb":
            _require(subtype in tuple("nal_" + str(i) for i in range(1, 13)))
            _require((framing, boundary, end) == ("closed", "next_nal", "next_nal"))
            _require(offset + length + 4 <= size)
            if subtype not in ("nal_10", "nal_11"):
                _require(length >= 5)
            else:
                _require(length in (4, 5))
        elif format == "xm":
            _require(subtype in ("type_fc", "type_fe", "type_fd", "type_fa", "type_f9"))
            _require((framing, boundary, end) == ("closed", "declared_length", "declared_length"))
            if subtype in ("type_fc", "type_fe"):
                _require(length >= 17)
        else:
            _require(subtype == "mpeg2_pack")
            if framing == "closed":
                _require(boundary in ("next_pack", "program_end") and end == boundary)
                _require(offset + length + (14 if boundary == "next_pack" else 4) <= size)
            else:
                _require(framing == "prefix" and boundary == "validated_prefix" and end in _PS_PREFIX)
                actual_prefix += 1
                if end == "selection_end":
                    _require(offset + length == size)
        previous = offset
    _require(actual_prefix == prefix)
    if rows:
        _require(size >= MIN_SELECTED_BYTES[format])
    _require(report["status"] == ("partial" if reasons else "ok" if rows else "unsupported"))
    _require(("source" in report) == ("params" in report))
    if "source" in report:
        source, params = report["source"], report["params"]
        _require(type(source) is dict and type(params) is dict and params["format"] == format)
        _require(_int(source["selected_size"], 64 << 20) == size)
        seconds = params["max_seconds"]
        _require(type(seconds) in (int, float) and math.isfinite(seconds) and 0 < seconds <= 45)
        _require(type(source["complete"]) is bool and source["complete"] is True)
        for name in ("partition",):
            if params[name] is not None:
                _int(params[name], 0x7fffffff)
            if source[name] is not None:
                _int(source[name], 0x7fffffff)
        if is_range:
            _require(set(params) == {"format", "partition", "method", "max_seconds", "offset", "length"})
            _require(source["method"] == "byte-range" and source["container"] == "file")
            _require(params["partition"] is None and params["method"] == "auto")
            offset = _int(source["offset"], (1 << 63) - 1)
            _require(offset == _int(params["offset"], (1 << 63) - 1))
            _require(size == _int(params["length"], 64 << 20, 1))
            _require(offset + size <= _int(source["evidence_size"], (1 << 63) - 1, 1))
        elif is_residual:
            _require(set(params) == {"format", "partition", "method", "max_seconds", "region"})
            _require(set(source) == {"kind", "evidence_id", "evidence_sha256", "container", "member_selected",
                                     "selected_sha256", "selected_size", "complete", "method", "confidence",
                                     "partition", "ref", "deleted", "parent_deleted", "container_truncated",
                                     "container_truncated_reasons", "region", "data_length", "valid_data_length"})
            _require(source["region"] == params["region"] == "residual")
            _require(source["container"] == "filesystem" and source["member_selected"] is True)
            _require(_int(source["partition"], 4096, 1) == _int(params["partition"], 4096, 1))
            _require(source["method"] in ("chain", "nofatchain", "contiguous", "skip-allocated", "stale-chain"))
            _require(params["method"] in ("auto", source["method"]))
            dl, vdl = _int(source["data_length"], (1 << 63) - 1, 1), _int(source["valid_data_length"], (1 << 63) - 1)
            _require(0 <= vdl < dl and 1 <= size == dl - vdl <= 64 << 20)
        else:
            _require(set(params) == {"format", "partition", "method", "max_seconds"})
            _require(source["method"] != "byte-range" and "offset" not in source and "evidence_size" not in source)
