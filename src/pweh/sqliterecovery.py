"""삭제 확정이 아닌 SQLite 잔여 record 후보. 소유 table을 추측하지 않는다."""
from __future__ import annotations

import hashlib

from .sqliteparse import BudgetStop, ParseError, _u16, _u32, decode_record, varint


def recover_candidates(reader, frames, wal_info, budget):
    """검증된 WAL의 과거 frame과 freelist/freeblock에서 제한된 후보만 찾는다."""
    out = {"status": "ok", "candidates": [], "warnings": [],
           "coverage": {"freelist_pages": 0, "wal_pages": 0, "freeblocks": 0,
                        "scanned_bytes": 0, "attempts": 0},
           "note": "historical/uncommitted/residual은 삭제 확정이나 삭제 시각이 아닙니다. table 소유는 미확인입니다."}
    seen_candidates = set()

    def charge(size):
        budget.take("recovery_bytes", size, budget.limits.max_recovery_bytes)
        out["coverage"]["scanned_bytes"] += size

    def add(payload, origin, kind, state, rowid=None, layout="intact-cell"):
        budget.check()
        out["coverage"]["attempts"] += 1
        if out["coverage"]["attempts"] > budget.limits.max_cells:
            budget.reason("max_recovery_attempts")
            raise BudgetStop("max_recovery_attempts")
        if len(out["candidates"]) >= budget.limits.max_candidates:
            budget.reason("max_candidates")
            raise BudgetStop("max_candidates")
        if len(payload) > budget.limits.max_payload_bytes:
            return
        # 임의 bytes의 구조 후보는 해석할 때마다 누적 payload 예산에 넣는다.
        budget.take("payload_bytes", len(payload), budget.limits.max_total_payload_bytes)
        try:
            values, fields = decode_record(payload, reader.header["encoding"], budget)
        except ParseError:
            return
        if len(values) < 2 or not any(isinstance(v, str) and v for v in values):
            return
        if any(not f.get("decode_valid", True) for f in fields):
            return
        digest = hashlib.sha256(payload).hexdigest()
        key = (origin["kind"], origin["offset"], digest)
        if key in seen_candidates:
            return
        seen_candidates.add(key)
        item = {"record_ref": f"recovery:{origin['kind']}:{origin['offset']}",
                "recovery_kind": kind, "record_state": state,
                "table": None, "table_assignment": "unknown", "confidence": "possible",
                "rowid": rowid, "raw_values": values, "fields": fields,
                "complete_bytes": layout == "intact-cell", "layout": layout,
                "missing_fields": [] if layout == "intact-cell" else ["cell_prefix", "rowid", "table"],
                "origin": {**origin, "length": len(payload), "payload_sha256": digest}}
        budget.store(item)
        out["candidates"].append(item)

    def intact_leaf(page, origin, kind, state):
        start = 100 if origin["page"] == 1 else 0
        if page[start] != 13:
            return
        count = _u16(page, start + 3)
        content = _u16(page, start + 5) or 65536
        if start + 8 + 2 * count > content or not content <= reader.usable:
            return
        intervals, candidates = [], []
        for index in range(count):
            budget.check()
            try:
                offset = _u16(page, start + 8 + index * 2)
                if not content <= offset < reader.usable:
                    return
                size, cur = varint(page, offset, reader.usable)
                rowid, cur = varint(page, cur, reader.usable)
                # 과거 overflow를 현재 page와 합치지 않는다.
                if size > reader.usable - 35 or cur + size > reader.usable:
                    out["warnings"].append("historical_overflow_not_reconstructed")
                    continue
                intervals.append((offset, cur + size))
                candidates.append((cur, size, rowid - (1 << 64) if rowid >= 1 << 63 else rowid))
            except ParseError:
                return
        intervals.sort()
        if any(intervals[i][1] > intervals[i + 1][0] for i in range(len(intervals) - 1)):
            return
        for cur, size, rowid in candidates:
            add(bytes(page[cur:cur + size]), {**origin, "offset": origin["offset"] + cur}, kind, state, rowid)

    def residual_scan(data, origin, kind):
        # 온전한 record header가 보이는 경우만 후보다. 덮인 header/rowid는 복원하지 않는다.
        for offset in range(max(0, len(data) - 3)):
            budget.check()
            if out["coverage"]["attempts"] >= budget.limits.max_cells:
                budget.reason("max_recovery_attempts")
                raise BudgetStop("max_recovery_attempts")
            out["coverage"]["attempts"] += 1
            try:
                hsize, cur = varint(data, offset)
                if not 3 <= hsize <= 128 or offset + hsize > len(data):
                    continue
                total, count, has_text = hsize, 0, False
                while cur < offset + hsize:
                    serial, cur = varint(data, cur, offset + hsize)
                    if serial in (10, 11):
                        raise ParseError("reserved_serial")
                    size = (0, 1, 2, 3, 4, 6, 8, 8, 0, 0)[serial] if serial < 10 else (serial - 12) // 2
                    total += size
                    count += 1
                    has_text |= serial >= 15 and serial % 2 == 1
                    if total > budget.limits.max_payload_bytes or offset + total > len(data):
                        raise ParseError("residual_range")
                if 2 <= count <= 64 and has_text:
                    add(bytes(data[offset:offset + total]), {**origin, "offset": origin["offset"] + offset},
                        kind, "residual", layout="record-header-only")
            except ParseError:
                continue

    try:
        # current overlay에 남은 마지막 frame은 제외하고 과거/미commit frame만 본다.
        current_frames = {item["frame"] for item in reader.overlay.values()}
        commit = wal_info.get("commit_frame") or 0
        for frame in frames:
            budget.check()
            if frame["frame"] in current_frames:
                continue
            charge(reader.page_size)
            page = memoryview(reader.wal)[frame["offset"]:frame["offset"] + reader.page_size]
            origin = {"kind": "wal", "page": frame["page"], "frame": frame["frame"], "offset": frame["offset"]}
            intact_leaf(page, origin, "wal-frame", "historical" if frame["frame"] <= commit else "uncommitted")
            out["coverage"]["wal_pages"] += 1
        next_trunk, visited, leaves = reader.header["freelist_trunk"], set(), []
        while next_trunk:
            budget.check()
            if next_trunk in visited or next_trunk in reader.claimed or next_trunk in reader.overflow_seen:
                raise ParseError("freelist_cycle_or_live_crosslink")
            visited.add(next_trunk)
            page, origin = reader.page(next_trunk)
            charge(reader.page_size)
            count = _u32(page, 4)
            if count > (reader.usable - 8) // 4:
                raise ParseError("freelist_leaf_count_invalid")
            for i in range(count):
                leaf = _u32(page, 8 + i * 4)
                if not 1 <= leaf <= reader.pages or leaf in visited or leaf in reader.claimed or leaf in reader.overflow_seen:
                    raise ParseError("freelist_leaf_invalid_or_live_crosslink")
                visited.add(leaf)
                leaves.append(leaf)
            next_trunk = _u32(page, 0)
        if len(visited) != reader.header["freelist_pages"]:
            out["warnings"].append("freelist_declared_count_mismatch")
        for number in leaves:
            page, origin = reader.page(number)
            charge(reader.page_size)
            intact_leaf(page, origin, "freelist-leaf", "residual")
            # intact cell로 찾지 못한 부분도 별도 record-header 후보로 표시한다.
            residual_scan(page[:reader.usable], origin, "freelist-bytes")
            out["coverage"]["freelist_pages"] += 1
        for number in list(reader.claimed):
            page, origin = reader.page(number)
            start = 100 if number == 1 else 0
            free = _u16(page, start + 1)
            visited_free = set()
            while free:
                budget.check()
                if free in visited_free or free + 4 > reader.usable:
                    raise ParseError("freeblock_invalid")
                visited_free.add(free)
                next_free, length = _u16(page, free), _u16(page, free + 2)
                if length < 4 or free + length > reader.usable:
                    raise ParseError("freeblock_invalid")
                charge(length)
                residual_scan(page[free + 4:free + length], {**origin, "offset": origin["offset"] + free + 4}, "freeblock")
                out["coverage"]["freeblocks"] += 1
                free = next_free
    except (ParseError, BudgetStop) as exc:
        out["status"] = "partial"
        out["warnings"].append(str(exc))
    out["warnings"] = list(dict.fromkeys(out["warnings"]))
    if out["warnings"]:
        out["status"] = "partial"
    return out
