"""선택한 작은 UTF-8 텍스트의 비밀값 후보 검사. 파일·기기·원문 출력은 다루지 않는다."""
from __future__ import annotations

import json
import math
import re
import time
import unicodedata
from dataclasses import dataclass, fields
from typing import Callable

from .errors import PwehError, ValidationFailed
from .safety.redact import CREDENTIAL_PATTERN_IDS, credential_spans

SCHEMA = "pweh.secrets-scan/v1"
RULE_PACK = "pweh-credential-spans-v1"
PATTERN_IDS = CREDENTIAL_PATTERN_IDS
KINDS = ("password", "token", "authorization", "url-password")
REASONS = ("line_too_long", "line_limit", "hit_limit", "range_limit", "output_limit", "time_limit",
           "selection_uncertain", "container_listing_incomplete", "unsupported_media", "invalid_utf8",
           "unsupported_encoding", "unsupported_unicode")
CONTAINER_REASONS = ("time", "cancelled", "unsupported_archive_compression", "incomplete_archive",
                     "max_metadata", "max_entries", "invalid_archive", "unsupported_archive",
                     "trailing_data_unexamined", "trailing_data", "unsupported_sparse", "unknown_container_limit")
LIMITATIONS = ("heuristic_candidates_only", "utf8_only", "single_selected_file_only", "no_multiline_secrets",
               "no_hash_cracking", "no_authentication", "no_media_decoding", "no_plaintext_output")
RANGE_PROFILE = "utf8-masked-secrets-ev-range-v1"
RANGE_REASONS = (*REASONS, "selection_boundary")
RANGE_LIMITATIONS = tuple("single_explicit_ev_range_only" if s == "single_selected_file_only" else s
                          for s in LIMITATIONS) + ("selection_boundary_lines_unexamined",
                                                   "no_outside_range_read", "no_whole_evidence_assessment")
_DIGEST_RX = re.compile(r"sha256:[0-9a-f]{16}\Z")
_NEWLINE = re.compile(rb"\r\n|\r|\n")


@dataclass(frozen=True)
class ScanLimits:
    """상한은 낮출 수만 있다. 출력에는 어댑터의 고정 출처 필드 공간도 남긴다."""

    max_bytes: int = 4 << 20
    max_line_bytes: int = 16 << 10
    max_lines: int = 100_000
    max_hits: int = 200
    max_ranges: int = 1024
    max_output_bytes: int = 1 << 20


@dataclass(frozen=True)
class SelectionBoundary:
    """열린 EV의 선택 시작·끝이 실제 EV 경계인지 어댑터가 전달한다."""

    prefix_complete: bool
    suffix_complete: bool


class _Deadline(Exception):
    pass


def _media(data: bytes) -> bool:
    """해독 없이 잘 알려진 미디어/이미지 헤더만 거부한다. 완전한 형식 식별기는 아니다."""
    signatures = (b"\x89PNG\r\n\x1a\n", b"\xff\xd8\xff", b"GIF87a", b"GIF89a", b"RIFF", b"RIFX",
                  b"RF64", b"\x1aE\xdf\xa3", b"OggS", b"fLaC", b"ID3", b"DHAV", b"FORM",
                  b"II*\x00", b"MM\x00*", b"\x00\x00\x01", b"\x00\x00\x00\x01")
    return (data.startswith(signatures) or data[4:8] in (b"ftyp", b"moov", b"mdat", b"moof")
            or (len(data) >= 2 and data[0] == 255 and data[1] & 0xe0 == 0xe0)
            or (len(data) >= 377 and data[0] == data[188] == data[376] == 0x47))


def _lines(data: bytes, start: int):
    """줄 목록을 만들지 않고 줄 내용 끝과 framing 끝을 순서대로 낸다."""
    pos = start
    for match in _NEWLINE.finditer(data, start):
        yield pos, match.start(), match.end()
        pos = match.end()
    if pos < len(data):
        yield pos, len(data), len(data)


def _new_report(size: int, limits: ScanLimits, xor_key: int | None) -> dict:
    return {
        "schema": SCHEMA, "status": "ok",
        "params": {"xor_key": xor_key, "max_hits": limits.max_hits, "decoder": "utf-8"},
        "rules": {"pack": RULE_PACK, "pattern_ids": list(PATTERN_IDS)},
        "coverage": {"input_bytes": size, "read_bytes": size, "scanned_bytes": 0, "framing_bytes": 0,
                     "unscanned_bytes": 0, "scanned_ranges": [], "unscanned_ranges": [],
                     "lines_seen": 0, "lines_scanned": 0, "lines_skipped": 0, "analysis_complete": False,
                     "container_examined": False, "selection_uncertain": False, "hits_are_lower_bound": False,
                     "reasons": []},
        "matches": [], "summary": {"hits": 0, "by_kind": dict.fromkeys(KINDS, 0), "unique_digest_count": 0},
        "limitations": list(LIMITATIONS),
    }


def _reason(report: dict, reason: str) -> None:
    if reason not in report["coverage"]["reasons"]:
        report["coverage"]["reasons"].append(reason)


def _unscanned(report: dict, start: int, end: int, reason: str) -> None:
    _reason(report, reason)
    if start == end:
        return
    cov = report["coverage"]
    rows = cov["unscanned_ranges"]
    if rows and rows[-1]["offset"] + rows[-1]["length"] == start and rows[-1]["reason"] == reason:
        rows[-1]["length"] += end - start
    else:
        rows.append({"offset": start, "length": end - start, "reason": reason})
    cov["unscanned_bytes"] += end - start


def _scanned(report: dict, start: int, content_end: int, end: int) -> None:
    cov = report["coverage"]
    rows = cov["scanned_ranges"]
    if rows and rows[-1]["offset"] + rows[-1]["length"] == start:
        rows[-1]["length"] += end - start
        rows[-1]["framing_bytes"] += end - content_end
    elif end > start:
        rows.append({"offset": start, "length": end - start, "framing_bytes": end - content_end})
    cov["scanned_bytes"] += content_end - start
    cov["framing_bytes"] += end - content_end
    cov["lines_scanned"] += 1


def _whole_unscanned(report: dict, reason: str) -> None:
    cov = report["coverage"]
    cov.update(scanned_bytes=0, framing_bytes=0, unscanned_bytes=0, scanned_ranges=[], unscanned_ranges=[],
               lines_scanned=0, lines_skipped=cov["lines_seen"])
    _unscanned(report, 0, cov["input_bytes"], reason)


def _finish(report: dict, limits: ScanLimits) -> dict:
    cov = report["coverage"]
    # 출력 한도는 원문 없는 고정 객체에도 적용한다. 공간 부족 시 검사 완료를 주장하지 않는다.
    budget = limits.max_output_bytes - 1536
    if len(json.dumps(report, ensure_ascii=True, separators=(",", ":")).encode()) > budget:
        _whole_unscanned(report, "output_limit")
        while report["matches"] and len(json.dumps(report, separators=(",", ":")).encode()) > budget - 256:
            report["matches"].pop()
    counts = dict.fromkeys(KINDS, 0)
    digests = set()
    for hit in report["matches"]:
        counts[hit["kind"]] += 1
        if hit["digest"] is not None:
            digests.add(hit["digest"])
    report["summary"] = {"hits": len(report["matches"]), "by_kind": counts, "unique_digest_count": len(digests)}
    cov["analysis_complete"] = not cov["reasons"]
    cov["hits_are_lower_bound"] = bool(cov["reasons"])
    if report["status"] != "unsupported":
        report["status"] = "ok" if cov["analysis_complete"] else "partial"
    if len(json.dumps(report, separators=(",", ":")).encode()) > budget:
        raise ValidationFailed("비밀값 검사 결과의 고정 필드를 담을 공간이 부족합니다.")
    return report


def _validate(data: bytes, limits: ScanLimits, xor_key: int | None, deadline: float) -> None:
    if not isinstance(limits, ScanLimits):
        raise ValidationFailed("비밀값 검사 한도가 올바르지 않습니다.")
    defaults = ScanLimits()
    for field in fields(limits):
        value = getattr(limits, field.name)
        minimum = 4096 if field.name == "max_output_bytes" else 2 if field.name == "max_ranges" else 1
        if type(value) is not int or not minimum <= value <= getattr(defaults, field.name):
            raise ValidationFailed("비밀값 검사 한도가 허용 범위 밖입니다.")
    if type(data) is not bytes or len(data) > limits.max_bytes:
        raise ValidationFailed("완전한 입력 bytes가 비밀값 검사 크기 한도 안에 있어야 합니다.")
    if xor_key is not None and (type(xor_key) is not int or xor_key != 144):
        raise ValidationFailed("XOR 보기는 null 또는 정수 144만 허용합니다.")
    if type(deadline) not in (int, float) or not math.isfinite(deadline):
        raise ValidationFailed("비밀값 검사 마감 시각이 올바르지 않습니다.")


def scan_secrets(data: bytes, *, digest: Callable[[bytes], str], xor_key: int | None = None,
                 limits: ScanLimits = ScanLimits(), deadline: float, cancel: Callable[[], bool],
                 boundary: SelectionBoundary | None = None) -> dict:
    """전체 입력을 검증한 뒤 좌표·고정 마스킹·솔트 지문만 반환한다.

    source와 max_seconds는 검증된 선택 파일을 가진 어댑터가 추가한다. bytes offset은
    XOR 전후 길이가 같은 선택 파일 기준이다. 취소는 보고서가 아닌 고정 오류다.
    """
    _validate(data, limits, xor_key, deadline)
    if boundary is not None and (type(boundary) is not SelectionBoundary
            or type(boundary.prefix_complete) is not bool or type(boundary.suffix_complete) is not bool):
        raise ValidationFailed("비밀값 검사의 선택 경계가 올바르지 않습니다.")
    if not callable(digest) or not callable(cancel):
        raise ValidationFailed("비밀값 검사의 지문·취소 콜백이 필요합니다.")
    end_time = min(deadline, time.monotonic() + 45)
    report = _new_report(len(data), limits, xor_key)
    if boundary is not None:
        report["profile"] = RANGE_PROFILE
        report["params"].update(prefix_complete=boundary.prefix_complete, suffix_complete=boundary.suffix_complete)
        report["limitations"] = list(RANGE_LIMITATIONS)
    cov = report["coverage"]
    position = 0

    def checkpoint() -> None:
        if cancel():
            raise PwehError("비밀값 검사가 취소되었습니다.", code="cancelled")
        if time.monotonic() >= end_time:
            raise _Deadline()

    try:
        checkpoint()
        view = data
        if xor_key is not None:
            table = bytes(v ^ xor_key for v in range(256))
            chunks = []
            for pos in range(0, len(data), 65536):
                checkpoint()
                chunks.append(data[pos:pos + 65536].translate(table))
            view = b"".join(chunks)
        unsupported = None
        if view.startswith((b"\xff\xfe", b"\xfe\xff")):
            unsupported = "unsupported_encoding"
        elif _media(data) or _media(view):
            unsupported = "unsupported_media"
        else:
            try:
                decoded = view.decode("utf-8", "strict")
            except UnicodeDecodeError:
                unsupported = "invalid_utf8"
            else:
                for i, char in enumerate(decoded):
                    if i % 4096 == 0:
                        checkpoint()
                    code = ord(char)
                    if (code < 32 and char not in "\t\r\n") or 127 <= code <= 159 or unicodedata.category(char) in ("Cs", "Co", "Cn"):
                        unsupported = "unsupported_unicode"
                        break
                del decoded
        checkpoint()
        if unsupported:
            report["status"] = "unsupported"
            _whole_unscanned(report, unsupported)
            return _finish(report, limits)
        position = 3 if view.startswith(b"\xef\xbb\xbf") else 0
        cov["framing_bytes"] = position
        for start, content_end, end in _lines(view, position):
            position = start
            checkpoint()
            if cov["lines_seen"] >= limits.max_lines:
                _unscanned(report, start, len(data), "line_limit")
                position = len(data)
                break
            if len(report["matches"]) >= limits.max_hits:
                _unscanned(report, start, len(data), "hit_limit")
                position = len(data)
                break
            cov["lines_seen"] += 1
            too_long = content_end - start > limits.max_line_bytes
            edge = boundary is not None and ((cov["lines_seen"] == 1 and not boundary.prefix_complete)
                    or (content_end == end == len(view) and not boundary.suffix_complete))
            skip_reason = "selection_boundary" if edge else "line_too_long" if too_long else None
            rows = cov["unscanned_ranges"] if skip_reason else cov["scanned_ranges"]
            merges = bool(rows and rows[-1]["offset"] + rows[-1]["length"] == start
                          and (skip_reason is None or rows[-1]["reason"] == skip_reason))
            if len(cov["scanned_ranges"]) + len(cov["unscanned_ranges"]) + (not merges) > limits.max_ranges - 1:
                cov["lines_skipped"] += 1
                _unscanned(report, start, len(data), "range_limit")
                position = len(data)
                break
            if skip_reason:
                cov["lines_skipped"] += 1
                _unscanned(report, start, end, skip_reason)
                position = end
                continue
            line = view[start:content_end].decode("utf-8")
            spans = credential_spans(line, check=checkpoint)
            offsets = [0]
            for char in line:
                offsets.append(offsets[-1] + len(char.encode("utf-8")))
            hits: dict[tuple[int, int], dict] = {}
            for span in spans:
                checkpoint()
                a, b = start + offsets[span.start], start + offsets[span.end]
                key = (a, b)
                if key not in hits:
                    hits[key] = {"pattern_ids": [], "kind": span.kind, "line": cov["lines_seen"], "offset": a,
                                 "length": b - a, "masked": "<masked>", "value_complete": span.value_complete,
                                 "digest": None, "confidence": "possible"}
                hit = hits[key]
                hit["pattern_ids"].append(span.pattern_id)
                # 같은 좌표라도 열린 quote/XML의 불확실성을 token 규칙으로 덮지 않는다.
                hit["value_complete"] = hit["value_complete"] and span.value_complete
                if span.kind == "authorization":
                    hit["kind"] = span.kind
            incomplete = False
            for (a, b), hit in sorted(hits.items()):
                checkpoint()
                if len(report["matches"]) >= limits.max_hits:
                    incomplete = True
                    break
                if hit["value_complete"]:
                    try:
                        value_digest = digest(view[a:b])
                    except Exception:
                        raise PwehError("비밀값 지문을 계산할 수 없습니다.", code="secret_digest_failed") from None
                    if type(value_digest) is not str or _DIGEST_RX.fullmatch(value_digest) is None:
                        raise PwehError("비밀값 지문 형식이 올바르지 않습니다.", code="secret_digest_failed")
                    hit["digest"] = value_digest
                report["matches"].append(hit)
            checkpoint()
            if incomplete:
                cov["lines_skipped"] += 1
                _unscanned(report, start, len(data), "hit_limit")
                position = len(data)
                break
            _scanned(report, start, content_end, end)
            position = end
        checkpoint()
    except _Deadline:
        if cov["lines_seen"] > cov["lines_scanned"] + cov["lines_skipped"]:
            cov["lines_skipped"] += 1
        _unscanned(report, position, len(data), "time_limit")
    except PwehError as exc:
        if exc.code == "cancelled":
            raise PwehError("비밀값 검사가 취소되었습니다.", code="cancelled") from None
        if exc.code == "secret_digest_failed":
            raise PwehError("비밀값 지문을 계산할 수 없습니다.", code="secret_digest_failed") from None
        raise PwehError("비밀값 검사 중 내부 오류가 발생했습니다.", code="secrets_scan_failed") from None
    except Exception:
        raise PwehError("비밀값 검사 중 내부 오류가 발생했습니다.", code="secrets_scan_failed") from None
    return _finish(report, limits)


def _range_keys(value, names: str) -> None:
    if type(value) is not dict or set(value) != set(names.split()):
        raise ValueError


def _range_uint(value, low: int, high: int) -> int:
    if type(value) is not int or not low <= value <= high:
        raise ValueError
    return value


def _range_list(value, maximum: int) -> list:
    if type(value) is not list or len(value) > maximum:
        raise ValueError
    return value


def _validate_range_accounting(report: dict) -> None:
    """닫힌 schema 뒤에도 JSON 숫자의 exact 형과 동적 관계를 독립 확인한다."""
    _range_keys(report, "schema profile status source params rules coverage matches summary limitations")
    if report["schema"] != SCHEMA or report["profile"] != RANGE_PROFILE or report["limitations"] != list(RANGE_LIMITATIONS):
        raise ValueError
    source, params, cov = report["source"], report["params"], report["coverage"]
    _range_keys(source, "kind evidence_id evidence_sha256 evidence_size offset length selected_sha256 selected_size complete")
    if source["kind"] != "evidence" or source["complete"] is not True:
        raise ValueError
    for key, pattern in (("evidence_id", r"EV-[0-9]{4,6}"), ("evidence_sha256", r"[0-9a-f]{64}"),
                         ("selected_sha256", r"[0-9a-f]{64}")):
        if type(source[key]) is not str or re.fullmatch(pattern, source[key]) is None:
            raise ValueError
    size = _range_uint(source["length"], 1, 4 << 20)
    ev_size = _range_uint(source["evidence_size"], 1, (1 << 63) - 1)
    offset = _range_uint(source["offset"], 0, (1 << 63) - 1)
    if _range_uint(source["selected_size"], 1, 4 << 20) != size or offset + size > ev_size:
        raise ValueError
    _range_keys(params, "xor_key max_hits decoder max_seconds prefix_complete suffix_complete")
    if params["xor_key"] is not None and (type(params["xor_key"]) is not int or params["xor_key"] != 144):
        raise ValueError
    max_hits = _range_uint(params["max_hits"], 1, 200)
    seconds = params["max_seconds"]
    if (params["decoder"] != "utf-8" or type(seconds) not in (int, float) or not math.isfinite(seconds)
            or not 0 < seconds <= 45 or params["prefix_complete"] is not (offset == 0)
            or params["suffix_complete"] is not (offset + size == ev_size)):
        raise ValueError
    _range_keys(report["rules"], "pack pattern_ids")
    if report["rules"] != {"pack": RULE_PACK, "pattern_ids": list(PATTERN_IDS)}:
        raise ValueError
    _range_keys(cov, "input_bytes read_bytes scanned_bytes framing_bytes unscanned_bytes scanned_ranges unscanned_ranges "
                     "lines_seen lines_scanned lines_skipped analysis_complete container_examined selection_uncertain "
                     "hits_are_lower_bound reasons")
    for key in ("input_bytes", "read_bytes", "scanned_bytes", "framing_bytes", "unscanned_bytes"):
        _range_uint(cov[key], 0, size)
    if (cov["input_bytes"] != size or cov["read_bytes"] != size
            or cov["scanned_bytes"] + cov["framing_bytes"] + cov["unscanned_bytes"] != size):
        raise ValueError
    reasons = _range_list(cov["reasons"], len(RANGE_REASONS))
    if (any(type(r) is not str or r not in RANGE_REASONS for r in reasons) or len(set(reasons)) != len(reasons)
            or "selection_uncertain" in reasons or "container_listing_incomplete" in reasons):
        raise ValueError
    if (cov["analysis_complete"] is not (not reasons) or cov["hits_are_lower_bound"] is not bool(reasons)
            or cov["selection_uncertain"] is not False or cov["container_examined"] is not False):
        raise ValueError
    unsupported = any(r in reasons for r in ("unsupported_media", "invalid_utf8", "unsupported_encoding", "unsupported_unicode"))
    if report["status"] != ("unsupported" if unsupported else "partial" if reasons else "ok"):
        raise ValueError
    if "selection_boundary" in reasons and params["prefix_complete"] and params["suffix_complete"]:
        raise ValueError
    for key in ("lines_seen", "lines_scanned", "lines_skipped"):
        _range_uint(cov[key], 0, 100_000)
    if cov["lines_seen"] != cov["lines_scanned"] + cov["lines_skipped"]:
        raise ValueError
    scanned_rows = _range_list(cov["scanned_ranges"], 1024)
    unscanned_rows = _range_list(cov["unscanned_ranges"], 1024)
    if len(scanned_rows) + len(unscanned_rows) > 1024:
        raise ValueError
    ranges, boundaries = [], []
    scanned = framing = unscanned = 0
    for rows, examined in ((scanned_rows, True), (unscanned_rows, False)):
        previous = -1
        for row in rows:
            _range_keys(row, "offset length framing_bytes" if examined else "offset length reason")
            start = _range_uint(row["offset"], 0, size)
            length = _range_uint(row["length"], 1, size)
            end = start + length
            if start < previous or end > size:
                raise ValueError
            previous = end
            ranges.append((start, end))
            if examined:
                frame = _range_uint(row["framing_bytes"], 0, length)
                scanned += length - frame
                framing += frame
            else:
                if type(row["reason"]) is not str or row["reason"] not in reasons:
                    raise ValueError
                unscanned += length
                if row["reason"] == "selection_boundary":
                    boundaries.append((start, end))
    # 선두 BOM만 범위 행 밖의 framing이다. 줄 끝 framing은 scanned 행 안에 포함된다.
    bom = cov["framing_bytes"] - framing
    if bom not in (0, 3) or scanned != cov["scanned_bytes"] or unscanned != cov["unscanned_bytes"]:
        raise ValueError
    pos = bom
    for start, end in sorted(ranges):
        if start != pos:
            raise ValueError
        pos = end
    if pos != size:
        raise ValueError
    hits = _range_list(report["matches"], max_hits)
    counts, digests = dict.fromkeys(KINDS, 0), set()
    previous = (-1, -1)
    previous_line = 0
    for hit in hits:
        _range_keys(hit, "pattern_ids kind line offset length masked value_complete digest confidence")
        ids = _range_list(hit["pattern_ids"], len(PATTERN_IDS))
        if (not ids or any(type(p) is not str or p not in PATTERN_IDS for p in ids) or len(set(ids)) != len(ids)
                or type(hit["kind"]) is not str or hit["kind"] not in KINDS
                or hit["masked"] != "<masked>" or hit["confidence"] != "possible"
                or type(hit["value_complete"]) is not bool):
            raise ValueError
        start = _range_uint(hit["offset"], 0, size)
        length = _range_uint(hit["length"], 1, 16 << 10)
        line = _range_uint(hit["line"], 1, cov["lines_seen"])
        if (start + length > size or (start, length) <= previous or line < previous_line
                or any(start < b and start + length > a for a, b in boundaries)):
            raise ValueError
        previous, previous_line = (start, length), line
        digest = hit["digest"]
        if hit["value_complete"]:
            if type(digest) is not str or _DIGEST_RX.fullmatch(digest) is None:
                raise ValueError
            digests.add(digest)
        elif digest is not None:
            raise ValueError
        counts[hit["kind"]] += 1
    _range_keys(report["summary"], "hits by_kind unique_digest_count")
    _range_keys(report["summary"]["by_kind"], " ".join(KINDS))
    for value in (*report["summary"]["by_kind"].values(), report["summary"]["hits"], report["summary"]["unique_digest_count"]):
        _range_uint(value, 0, 200)
    if report["summary"] != {"hits": len(hits), "by_kind": counts, "unique_digest_count": len(digests)}:
        raise ValueError
    if unsupported and (hits or cov["lines_seen"] or cov["unscanned_bytes"] != size):
        raise ValueError


def validate_secrets_range_accounting(report: dict) -> None:
    """새 full range 보고서의 회계만 검사한다. 원문 재검색·해시·파일 I/O는 하지 않는다."""
    try:
        _validate_range_accounting(report)
    except (ValueError, KeyError, TypeError, OverflowError):
        raise ValidationFailed("비밀값 구간 검사 보고서의 회계가 올바르지 않습니다.") from None
