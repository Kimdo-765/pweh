"""정지 그림의 바깥 구조를 제한된 크기로 검사한다(해독·실행·파일 열기 없음).

JPEG 의 APP 안 썸네일과 entropy-coded scan 을 구분하고, PNG 는 청크 경계와 CRC 를
따라간다. 숨은 데이터 표지는 후보이며, 시그니처만으로 내장 파일을 확정하지 않는다.
"""

from __future__ import annotations

import hashlib
import struct
import zlib

MAX_METADATA_BYTES = 256 * 1024
MAX_TEXT_BYTES = 64 * 1024
MAX_CHUNKS = 100000


def _text(raw: bytes, encoding: str = "utf-8") -> str:
    return raw.decode(encoding, "replace")


def _inflate(raw: bytes, limit: int) -> bytes:
    """출력 상한을 지키고 끝까지 풀린 zlib 스트림만 받는다."""
    obj = zlib.decompressobj()
    out = obj.decompress(raw, limit + 1)
    if len(out) > limit or obj.unconsumed_tail or not obj.eof:
        raise ValueError("metadata_limit_or_invalid_compression")
    return out


def _signatures(sample: bytes, offset: int) -> list[dict]:
    """압축 이미지 데이터 바깥의 한정된 표본에서 내장 파일 표지를 찾는다."""
    candidates = []
    for magic, kind in ((b"PK\x03\x04", "zip"), (b"%PDF-", "pdf"), (b"\x7fELF", "elf"),
                        (b"\x89PNG\r\n\x1a\n", "png"), (b"\xff\xd8\xff", "jpeg"),
                        (b"\x1f\x8b", "gzip")):
        pos = sample.find(magic)
        if pos >= 0:
            candidates.append({"offset": offset + pos, "signature": kind, "confidence": "possible"})
    return candidates


def _trailing(data: bytes, end: int | None) -> dict:
    if end is None:
        return {"end_offset": None, "trailing_bytes": None, "trailing_sha256": None,
                "embedded_candidates": []}
    tail = memoryview(data)[end:]
    # 원본 크기가 제한돼 있어도 응답 개수와 검색량을 별도로 제한한다.
    sample = tail[:1024 * 1024].tobytes()
    return {"end_offset": end, "trailing_bytes": len(tail),
            "trailing_sha256": hashlib.sha256(tail).hexdigest() if tail else None,
            "embedded_candidates": _signatures(sample, end), "trailing_scan_bytes": len(sample)}


def inspect_png(data: bytes) -> dict:
    """PNG 청크·CRC·텍스트를 확인한다. 압축 텍스트는 누적 상한 안에서만 푼다."""
    out = {"format": "PNG", "status": "ok", "errors": [], "warnings": [],
           "text": [], "xmp": [], "animated": False, "chunks": 0, "dimensions": None}
    pos, end, budget = 8, None, MAX_METADATA_BYTES
    embedded, scan_budget = [], 1024 * 1024
    first = True
    while pos + 12 <= len(data) and out["chunks"] < MAX_CHUNKS:
        length = struct.unpack_from(">I", data, pos)[0]
        kind = data[pos + 4:pos + 8]
        stop = pos + 12 + length
        if stop > len(data):
            out["errors"].append("chunk_beyond_input")
            break
        raw = data[pos + 8:pos + 8 + length]
        actual = zlib.crc32(raw, zlib.crc32(kind)) & 0xffffffff
        if actual != struct.unpack_from(">I", data, pos + 8 + length)[0]:
            out["errors"].append("chunk_crc_mismatch")
        out["chunks"] += 1
        if first:
            if kind != b"IHDR" or length != 13:
                out["errors"].append("invalid_ihdr")
            else:
                out["dimensions"] = list(struct.unpack_from(">II", raw))
            first = False
        if kind == b"acTL":
            out["animated"] = True
        if kind not in (b"IDAT", b"IHDR", b"IEND") and scan_budget and len(embedded) < 32:
            sample = raw[:scan_budget]
            embedded.extend(_signatures(sample, pos + 8))
            scan_budget -= len(sample)
        if kind in (b"tEXt", b"zTXt", b"iTXt"):
            try:
                if len(out["text"]) >= 512:
                    raise ValueError("metadata_entry_limit")
                keyword, body = raw.split(b"\0", 1)
                if not 1 <= len(keyword) <= 79:
                    raise ValueError("invalid_text_keyword")
                cap = min(budget, MAX_TEXT_BYTES)
                if cap <= 0:
                    raise ValueError("metadata_limit")
                if kind == b"zTXt":
                    if not body or body[0] != 0:
                        raise ValueError("invalid_compression_method")
                    text = _inflate(body[1:], cap)
                elif kind == b"iTXt":
                    if len(body) < 2 or body[0] not in (0, 1) or body[1] != 0:
                        raise ValueError("invalid_itxt")
                    compressed = body[0]
                    _lang, _translated, body = body[2:].split(b"\0", 2)
                    text = _inflate(body, cap) if compressed else body
                else:
                    text = body
                if len(text) > cap:
                    raise ValueError("metadata_limit")
                budget -= len(text)
                entry = {"keyword": _text(keyword, "latin-1"),
                         "text": _text(text, "utf-8" if kind == b"iTXt" else "latin-1"),
                         "chunk": kind.decode("ascii"), "offset": pos}
                out["text"].append(entry)
                if keyword == b"XML:com.adobe.xmp":
                    out["xmp"].append(entry["text"])
            except (ValueError, zlib.error) as exc:
                out["warnings"].append(str(exc)[:100])
        if kind == b"IEND":
            if length:
                out["errors"].append("invalid_iend")
            end = stop
            break
        pos = stop
    if end is None:
        out["errors"].append("missing_iend_or_chunk_limit")
    out["errors"] = sorted(set(out["errors"]))
    out["warnings"] = sorted(set(out["warnings"]))
    if out["errors"] or out["warnings"]:
        out["status"] = "partial"
    out.update(_trailing(data, end))
    out["embedded_candidates"] = (embedded + out["embedded_candidates"])[:32]
    return out


def inspect_jpeg(data: bytes) -> dict:
    """JPEG 마커와 scan 을 따라 주 이미지 EOI 를 찾는다(APP 속 EOI 는 무시)."""
    out = {"format": "JPEG", "status": "ok", "errors": [], "warnings": [],
           "xmp": [], "comments": [], "segments": 0}
    pos, end, in_scan, budget = 2, None, False, MAX_METADATA_BYTES
    embedded, scan_budget = [], 1024 * 1024
    while pos < len(data) and out["segments"] < MAX_CHUNKS:
        if in_scan:
            marker_at = data.find(b"\xff", pos)
            if marker_at < 0:
                break
            pos = marker_at
        if data[pos] != 0xff:
            out["errors"].append("invalid_marker")
            break
        while pos < len(data) and data[pos] == 0xff:
            pos += 1
        if pos >= len(data):
            break
        marker = data[pos]
        pos += 1
        if in_scan and (marker == 0 or 0xd0 <= marker <= 0xd7):
            continue
        was_in_scan = in_scan
        in_scan = False
        out["segments"] += 1
        if marker == 0xd9:
            end = pos
            break
        if marker in (0, 0xd8) or 0xd0 <= marker <= 0xd7:
            out["errors"].append("unexpected_marker")
            break
        if marker == 1:
            in_scan = was_in_scan
            continue
        if pos + 2 > len(data):
            break
        length = struct.unpack_from(">H", data, pos)[0]
        if length < 2 or pos + length > len(data):
            out["errors"].append("segment_beyond_input")
            break
        raw = data[pos + 2:pos + length]
        if 0xe0 <= marker <= 0xef and scan_budget and len(embedded) < 32:
            sample = raw[:scan_budget]
            embedded.extend(_signatures(sample, pos + 2))
            scan_budget -= len(sample)
        if marker == 0xe1 and raw.startswith(b"http://ns.adobe.com/xap/1.0/\0"):
            text = raw.split(b"\0", 1)[1]
            cap = min(budget, MAX_TEXT_BYTES)
            if len(out["xmp"]) < 64:
                out["xmp"].append(_text(text[:cap]))
            else:
                out["warnings"].append("metadata_entry_limit")
            budget -= min(len(text), cap)
            if len(text) > cap:
                out["warnings"].append("metadata_limit")
        elif marker == 0xfe:
            cap = min(budget, MAX_TEXT_BYTES)
            if len(out["comments"]) < 256:
                out["comments"].append(_text(raw[:cap]))
            else:
                out["warnings"].append("metadata_entry_limit")
            budget -= min(len(raw), cap)
            if len(raw) > cap:
                out["warnings"].append("metadata_limit")
        pos += length
        in_scan = marker == 0xda or (marker == 0xdc and was_in_scan)
    if end is None:
        out["errors"].append("missing_eoi_or_segment_limit")
    out["errors"] = sorted(set(out["errors"]))
    out["warnings"] = sorted(set(out["warnings"]))
    if out["errors"] or out["warnings"]:
        out["status"] = "partial"
    out.update(_trailing(data, end))
    out["embedded_candidates"] = (embedded + out["embedded_candidates"])[:32]
    return out


def inspect_structure(data: bytes) -> dict:
    """지원하는 PNG·JPEG 바깥 구조만 검사한다. 다른 형식의 EOF 는 미확인이다."""
    if data.startswith(b"\x89PNG\r\n\x1a\n"):
        return inspect_png(data)
    if data.startswith(b"\xff\xd8"):
        return inspect_jpeg(data)
    return {"status": "unsupported", "format": None, "errors": [], "warnings": [],
            **_trailing(data, None)}
