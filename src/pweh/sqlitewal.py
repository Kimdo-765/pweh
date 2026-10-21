"""SQLite WAL을 실행 없이 검증한다. overlay는 원본 bytes의 위치만 보관한다."""

from __future__ import annotations

import struct


def _checksum(data, state, endian):
    """공식 WAL rolling checksum. 저장 필드는 big endian, 계산 word는 magic 기준이다."""
    s0, s1 = state
    for a, b in struct.iter_unpack(endian + "II", data):
        s0 = (s0 + a + s1) & 0xFFFFFFFF
        s1 = (s1 + b + s0) & 0xFFFFFFFF
    return s0, s1


def inspect_wal(data: bytes | None, page_size: int, budget):
    """검증된 마지막 commit까지 page 위치를 반환하며 불완전한 tail을 분리한다."""
    result = {"status": "absent", "frames_valid": 0, "commit_frame": None,
              "db_pages": None, "uncommitted_frames": 0, "warnings": [],
              "association": "provided-pair"}
    if data is None:
        return result, {}, []
    result["status"] = "invalid"
    if len(data) < 32:
        result["warnings"].append("wal_header_truncated")
        return result, {}, []
    magic, version, size, sequence, salt1, salt2, c0, c1 = struct.unpack(">8I", data[:32])
    if magic not in (0x377F0682, 0x377F0683) or version != 3007000 or size != page_size:
        result["warnings"].append("wal_header_invalid_or_page_size_mismatch")
        return result, {}, []
    endian = "<" if magic == 0x377F0682 else ">"
    state = _checksum(memoryview(data)[:24], (0, 0), endian)
    if state != (c0, c1):
        result["warnings"].append("wal_header_checksum_mismatch")
        return result, {}, []
    result.update(status="ok", sequence=sequence, page_size=size)
    frames, offset, last_commit = [], 32, 0
    while offset + 24 + size <= len(data):
        budget.check()
        if len(frames) >= budget.limits.max_pages:
            budget.reason("max_wal_frames")
            result["warnings"].append("max_wal_frames")
            break
        number, commit_size, s1, s2, f0, f1 = struct.unpack_from(">6I", data, offset)
        if number == 0 or number > 0xFFFFFFFE or (s1, s2) != (salt1, salt2):
            result["warnings"].append("wal_frame_invalid_or_salt_mismatch")
            break
        state2 = _checksum(memoryview(data)[offset:offset + 8], state, endian)
        state2 = _checksum(memoryview(data)[offset + 24:offset + 24 + size], state2, endian)
        if state2 != (f0, f1):
            result["warnings"].append("wal_frame_checksum_mismatch")
            break
        if commit_size and (commit_size > 0xFFFFFFFE or number > commit_size):
            result["warnings"].append("wal_commit_size_invalid")
            break
        state = state2
        frames.append({"page": number, "offset": offset + 24, "frame": len(frames) + 1,
                       "commit_size": commit_size})
        if commit_size:
            last_commit = len(frames)
        offset += 24 + size
    if offset != len(data):
        result["warnings"].append("wal_tail_unvalidated")
    result.update(frames_valid=len(frames), commit_frame=last_commit or None,
                  db_pages=frames[last_commit - 1]["commit_size"] if last_commit else None,
                  uncommitted_frames=len(frames) - last_commit)
    overlay = {}
    for frame in frames[:last_commit]:
        budget.check()
        if frame["page"] <= result["db_pages"]:
            overlay[frame["page"]] = frame
    if result["warnings"]:
        result["status"] = "partial"
    result["note"] = "WAL 내부 검증은 DB와의 결속 증명이 아닙니다. 같은 EV에서 지정한 쌍입니다."
    return result, overlay, frames


def inspect_journal(data: bytes | None, page_size: int, budget):
    """rollback journal은 구조만 확인한다. 자동 replay나 hot 상태 확정은 하지 않는다."""
    if data is None:
        return {"status": "absent"}
    out = {"status": "unknown", "replayed": False, "size": len(data),
           "note": "journal의 hot 여부와 DB의 최종 commit 상태를 파일 내용만으로 확정하지 않습니다."}
    if len(data) < 28 or data[:8] != bytes.fromhex("d9d505f920a163d7"):
        out["reason"] = "journal_header_absent_or_truncated"
        return out
    records, nonce, initial_pages, sector, size = struct.unpack_from(">5I", data, 8)
    out.update(records_declared=records, initial_pages=initial_pages, sector_size=sector,
               page_size=size, records_valid=0)
    if size != page_size or not 512 <= sector <= 65536 or sector & (sector - 1):
        out["reason"] = "journal_header_invalid"
        return out
    # 여러 header/super-journal 형식은 아직 해석하지 않는다.
    count = (len(data) - sector) // (page_size + 8) if records == 0xFFFFFFFF else records
    offset = sector
    for _ in range(min(max(0, count), budget.limits.max_pages)):
        budget.check()
        if offset + page_size + 8 > len(data):
            out["reason"] = "journal_record_truncated"
            break
        page = int.from_bytes(data[offset:offset + 4], "big")
        payload = memoryview(data)[offset + 4:offset + 4 + page_size]
        checksum = nonce
        for index in range(page_size - 200, 0, -200):
            checksum = (checksum + payload[index]) & 0xFFFFFFFF
        stored = int.from_bytes(data[offset + 4 + page_size:offset + page_size + 8], "big")
        if not 0 < page <= initial_pages or checksum != stored:
            out["reason"] = "journal_record_invalid"
            break
        out["records_valid"] += 1
        offset += page_size + 8
    out["status"] = "observed"
    out["coverage"] = "first_header_only"
    return out
