"""펌웨어 파일 안의 raw GPT/LP 배치와 bounded extent 분할. sparse 확장은 하지 않는다."""

from __future__ import annotations

import hashlib
import struct
from pathlib import Path
from typing import Any

from pweh.errors import ValidationFailed
from pweh.fs.volume import detect_partitions
from pweh.fsutil import atomic_write_json

from .androidformats import LP_GEOMETRY_MAGIC, MAX_EXTENTS, MAX_METADATA, MAX_PARTITIONS, SPARSE_MAGIC, fail, geometry, rd, tick
from .common import Ctl, PRODUCER, claim_numbered_dir, safe_label, safe_name, sanitize


class BufferSource:
    """이미 열린 firmware buffer를 GPT 해석기에 주는 보기. 경로를 열지 않는다."""

    def __init__(self, buf: Any, size: int, ctl: Ctl) -> None:
        self.buf, self.size, self.ctl, self.base_offset = buf, size, ctl, 0

    def read(self, offset: int, size: int) -> bytes:
        tick(self.ctl)
        return rd(self.buf, offset, size, self.size)

    def read_clamped(self, offset: int, size: int) -> bytes:
        if offset < 0 or offset >= self.size:
            return b""
        return self.read(offset, min(size, self.size - offset))


def _name(raw: bytes) -> str:
    name, sep, tail = raw.partition(b"\0")
    if not name or (sep and any(tail)) or any(c not in b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_" for c in name):
        fail("invalid_lp_name", "LP 이름은 비어 있지 않은 ASCII 영숫자와 밑줄이어야 합니다.")
    return name.decode("ascii")


def _metadata(buf: Any, off: int, limit: int, geo: dict[str, Any], ctl: Ctl) -> dict[str, Any]:
    h0 = rd(buf, off, 128, limit)
    magic, major, minor, hs = struct.unpack_from("<I2HI", h0)
    if magic != 0x414C5030 or major != 10 or minor > 2 or hs != (256 if minor >= 2 else 128):
        fail("invalid_lp_header", "LP metadata magic/version/header 크기가 잘못됐습니다.")
    h = rd(buf, off, hs, limit)
    if hashlib.sha256(h[:12] + bytes(32) + h[44:]).digest() != h[12:44]:
        fail("lp_header_checksum", "LP metadata header SHA256이 맞지 않습니다.")
    ts = struct.unpack_from("<I", h, 44)[0]
    if hs + ts > geo["metadata_max_size"] or ts > MAX_METADATA:
        fail("invalid_lp_tables", "LP tables가 metadata slot 범위를 넘습니다.")
    tables = rd(buf, off + hs, ts, limit)
    if hashlib.sha256(tables).digest() != h[48:80]:
        fail("lp_tables_checksum", "LP tables SHA256이 맞지 않습니다.")
    parsed: dict[str, list[bytes]] = {}
    ranges = []
    for i, (name, expected, cap) in enumerate((("partitions", 52, MAX_PARTITIONS), ("extents", 24, MAX_EXTENTS), ("groups", 48, 128), ("devices", 64, 16))):
        p, count, es = struct.unpack_from("<3I", h, 80 + i * 12)
        end = p + count * es
        if es != expected or count > cap or end > ts:
            fail("invalid_lp_table", "LP table entry 크기·수·범위가 잘못됐거나 상한을 넘습니다.")
        if count:
            if any(p < b and end > a for a, b in ranges):
                fail("overlapping_lp_tables", "LP metadata tables가 서로 겹칩니다.")
            ranges.append((p, end))
        parsed[name] = []
        for j in range(count):
            if j % 256 == 0:
                tick(ctl)
            parsed[name].append(tables[p + j * es:p + (j + 1) * es])
    if not parsed["devices"] or not parsed["groups"]:
        fail("invalid_lp_table", "LP에는 block device와 group이 필요합니다.")
    devices = []
    for b in parsed["devices"]:
        first, alignment, alignment_offset, size = struct.unpack_from("<QIIQ", b)
        flags = struct.unpack_from("<I", b, 60)[0]
        if size % 512 or first * 512 > size or flags & ~1:
            fail("invalid_lp_device", "LP block device 범위/flags가 잘못됐습니다.")
        devices.append({"name": _name(b[24:60]), "first_logical_sector": first, "size": size,
                        "alignment": alignment, "alignment_offset": alignment_offset, "flags": flags})
    if 12288 + 2 * geo["metadata_max_size"] * geo["slot_count"] > devices[0]["first_logical_sector"] * 512:
        fail("lp_metadata_overlap", "LP metadata 영역과 partition 데이터 영역이 겹칩니다.")
    groups = []
    for b in parsed["groups"]:
        flags, maximum = struct.unpack_from("<IQ", b, 36)
        if flags & ~1:
            fail("invalid_lp_group", "알 수 없는 LP group flags입니다.")
        groups.append({"name": _name(b[:36]), "flags": flags, "maximum_size": maximum})
    extents = []
    for b in parsed["extents"]:
        sectors, target, data, source = struct.unpack("<QIQI", b)
        if not sectors or target not in (0, 1) or (target == 1 and (data or source)) or (target == 0 and source >= len(devices)):
            fail("invalid_lp_extent", "LP extent type·크기·device index가 잘못됐습니다.")
        if sectors * 512 % geo["logical_block_size"] or (target == 0 and data * 512 % geo["logical_block_size"]):
            fail("unaligned_lp_extent", "LP extent가 logical block 크기에 맞지 않습니다.")
        if target == 0:
            dev = devices[source]
            if data < dev["first_logical_sector"] or (data + sectors) * 512 > dev["size"]:
                fail("invalid_lp_extent", "LP extent가 block device 데이터 범위를 넘습니다.")
        extents.append({"size": sectors * 512, "target_type": "linear" if target == 0 else "zero",
                        "source_index": source if target == 0 else None, "source_offset": data * 512 if target == 0 else None})
    parts, names, used_extents, physical = [], set(), set(), []
    group_bytes = [0] * len(groups)
    for b in parsed["partitions"]:
        tick(ctl)
        name = _name(b[:36])
        attr, first, count, group = struct.unpack_from("<4I", b, 36)
        if name in names or attr & ~(15 if minor >= 1 else 3) or first + count > len(extents) or group >= len(groups):
            fail("invalid_lp_partition", "LP partition 이름·attribute·extent/group index가 잘못됐습니다.")
        names.add(name)
        mapping, logical = [], 0
        for i in range(first, first + count):
            if i % 256 == 0:
                tick(ctl)
            if i in used_extents:
                fail("overlapping_lp_extents", "LP extent 항목이 여러 partition에 중복 사용됩니다.")
            used_extents.add(i)
            e = dict(extents[i])
            e["logical_offset"] = logical
            mapping.append(e)
            logical += e["size"]
            if e["target_type"] == "linear":
                physical.append((e["source_index"], e["source_offset"], e["source_offset"] + e["size"]))
        group_bytes[group] += logical
        parts.append({"name": name, "raw_name": name, "offset": None, "size": logical, "attributes": attr,
                      "ro": bool(attr & 1), "group": groups[group]["name"], "mapping": mapping})
    physical.sort()
    for prev, cur in zip(physical, physical[1:]):
        if prev[0] == cur[0] and cur[1] < prev[2]:
            fail("overlapping_lp_extents", "LP 물리 extent가 서로 겹칩니다.")
    for g, total in zip(groups, group_bytes):
        if g["maximum_size"] and total > g["maximum_size"]:
            fail("invalid_lp_group_size", "LP partition 합계가 group 최대 크기를 넘습니다.")
    return {"partitions": parts, "block_devices": devices, "groups": groups,
            "header_version": f"{major}.{minor}", "header_flags": struct.unpack_from("<I", h, 128)[0] if minor >= 2 else 0,
            "metadata_sha256": hashlib.sha256(h + tables).hexdigest(),
            "validation": {"geometry_sha256": True, "header_sha256": True, "tables_sha256": True, "extents": True},
            "metadata_bytes": hs + ts}


def lp_layout(buf: Any, size: int, ctl: Ctl, *, slot: int = 0, base: int = 0) -> dict[str, Any]:
    warnings: list[str] = []
    metadata_only = bytes(buf[base:base + 4]) == LP_GEOMETRY_MAGIC
    geos, errors = [], []
    for copy, off in (("primary", base if metadata_only else base + 4096), ("backup", base + 8192)):
        if metadata_only and copy == "backup":
            continue
        try:
            geos.append((copy, geometry(buf, off, size)))
        except ValidationFailed as exc:
            errors.append(f"{copy} geometry: {exc}")
    if not geos:
        fail("invalid_lp_geometry", " / ".join(errors))
    selected_geo, geo = geos[0]
    warnings.extend(errors)
    if len(geos) == 2 and geos[0][1] != geos[1][1]:
        warnings.append("유효한 primary/backup geometry가 다릅니다. primary를 선택했습니다.")
    if type(slot) is not int or slot < 0 or slot >= geo["slot_count"]:
        fail("invalid_lp_slot", "lp_slot이 metadata slot 범위를 넘습니다.")
    choices, errors = [], []
    positions = [("primary", base + 4096)] if metadata_only else [
        ("primary", base + 12288 + slot * geo["metadata_max_size"]),
        ("backup", base + 12288 + (geo["slot_count"] + slot) * geo["metadata_max_size"])]
    for copy, off in positions:
        try:
            choices.append((copy, off, _metadata(buf, off, size, geo, ctl)))
        except ValidationFailed as exc:
            errors.append(f"{copy} metadata: {exc}")
    if not choices:
        fail("invalid_lp_metadata", " / ".join(errors))
    copy, off, parsed = choices[0]
    warnings.extend(errors)
    if len(choices) == 2 and choices[0][2]["metadata_sha256"] != choices[1][2]["metadata_sha256"]:
        warnings.append("유효한 primary/backup metadata가 다릅니다. primary를 선택했습니다(active slot 판단 아님).")
    for p in parsed["partitions"]:
        if p["attributes"] & 2:
            if slot > 1:
                fail("unsupported_lp_slot_suffix", "slot suffix는 0=_a, 1=_b만 지원합니다.")
            p["name"] += "_a" if slot == 0 else "_b"
        if metadata_only:
            p.update(status="skipped", reason="metadata_only")
        elif p["attributes"] & 8:
            p.update(status="skipped", reason="disabled")
        elif any(e["source_index"] not in (None, 0) for e in p["mapping"]):
            p.update(status="skipped", reason="missing_source")
        elif any(e["source_offset"] is not None and base + e["source_offset"] + e["size"] > size for e in p["mapping"]):
            p.update(status="skipped", reason="beyond_image")
        elif not p["size"]:
            p.update(status="skipped", reason="empty_partition")
        for e in p["mapping"]:
            if e["source_index"] == 0:
                e["source_offset"] += base
    return {"source": "lp", "address_space": "file", "sector_size": 512, "metadata_slot": slot,
            "selected_copy": copy, "selected_geometry": selected_geo, "metadata_offset": off,
            "geometry": geo, "metadata_only": metadata_only, "warnings": warnings, **parsed}


def android_layout(buf: Any, size: int, ctl: Ctl, *, selector: str = "auto", slot: int = 0) -> dict[str, Any] | None:
    head = bytes(buf[:4])
    if head == SPARSE_MAGIC:
        fail("sparse_carve_unsupported", "sparse-wrapped GPT/LP 분할은 지원하지 않습니다. fw_identify의 구조 정보만 제공합니다.")
    lp = head == LP_GEOMETRY_MAGIC or any(bytes(buf[o:o + 4]) == LP_GEOMETRY_MAGIC for o in (4096, 8192))
    gpt = any(bytes(buf[o:o + 8]) == b"EFI PART" for o in (512, 4096, size - 512, size - 4096))
    if size >= 512 and bytes(buf[510:512]) == b"\x55\xaa":
        gpt = gpt or any(buf[446 + i * 16 + 4] == 0xEE for i in range(4))
    if selector == "lp" or (selector == "auto" and lp):
        return lp_layout(buf, size, ctl, slot=slot)
    if selector == "gpt" or (selector == "auto" and gpt):
        detected = detect_partitions(BufferSource(buf, size, ctl))
        g = detected.get("gpt") or {}
        header = g.get(g.get("used")) or {}
        if detected.get("scheme") != "gpt" or not (header.get("header_crc_ok") and header.get("my_lba_ok") and g.get("entries_crc_ok")):
            fail("invalid_gpt", "추출에 필요한 GPT header/entries CRC와 위치 검증을 통과하지 못했습니다.")
        ss = detected["sector_size"]
        usable = (header["first_usable_lba"] * ss, (header["last_usable_lba"] + 1) * ss)
        disk_sectors = size // ss
        # CRC는 구조의 정합성을 보장하지 않는다. 양쪽 유효 header의 예약 영역도 검사한다.
        headers = [h for name in ("primary", "backup") if (h := g.get(name)) and h.get("header_crc_ok") and h.get("my_lba_ok")]
        reserves = [(0, ss)]
        for h in headers:
            count = h["num_entries"]
            table_sectors = (count * h["entry_size"] + ss - 1) // ss
            start, end = h["entries_lba"] * ss, (h["entries_lba"] + table_sectors) * ss
            if not count or start < ss or end > size or not (1 <= h["alt_lba"] < disk_sectors):
                fail("invalid_gpt_metadata", "GPT metadata의 개수·주소가 입력 범위를 벗어납니다.")
            for lba in (h["my_lba"], h["alt_lba"]):
                if start < (lba + 1) * ss and end > lba * ss:
                    fail("overlapping_gpt_metadata", "GPT entry 배열이 header와 겹칩니다.")
                reserves.append((lba * ss, (lba + 1) * ss))
            reserves.append((start, end))
        if usable[0] >= usable[1] or usable[1] > size or any(usable[0] < b and usable[1] > a for a, b in reserves):
            fail("overlapping_gpt_metadata", "GPT usable 영역이 header·entry 배열 예약 영역과 겹치거나 범위를 벗어납니다.")
        entries = detected["partitions"]
        if len(entries) > MAX_PARTITIONS:
            fail("partition_limit", "GPT partition 수가 128개 상한을 넘습니다.")
        parts, intervals = [], []
        for p in entries:
            tick(ctl)
            off, n = p["start_offset"], p["size_bytes"]
            if off < header["first_usable_lba"] * detected["sector_size"] or off + n > (header["last_usable_lba"] + 1) * detected["sector_size"] or off + n > size or n <= 0:
                fail("invalid_gpt_partition", "GPT partition이 usable/입력 범위를 넘습니다.")
            intervals.append((off, off + n))
            parts.append({"name": p.get("gpt_name") or f"partition{p['index']}", "offset": off, "size": n,
                          "mapping": [{"logical_offset": 0, "size": n, "target_type": "linear", "source_index": 0, "source_offset": off}]})
        intervals.sort()
        if any(b[0] < a[1] for a, b in zip(intervals, intervals[1:])):
            fail("overlapping_gpt_partitions", "GPT partition이 서로 겹칩니다.")
        return {"source": "gpt", "address_space": "file", "sector_size": detected["sector_size"],
                "selected_copy": g["used"], "validation": {"header_crc32": True, "entries_crc32": True, "ranges": True},
                "partitions": parts, "warnings": [w["message"] for w in detected.get("warnings", [])]}
    return None


def check_output_budget(parts: list[dict[str, Any]], size: int, maximum: int) -> None:
    total = 0
    for p in parts:
        if p.get("status") == "skipped":
            continue
        n = p.get("size")
        off = p.get("offset")
        if off is not None:
            n = max(0, min(n if n is not None else size - off, size - off))
        total += n or 0
    if total > maximum:
        raise ValidationFailed("파티션 출력 합계가 max_output_bytes를 넘습니다.",
                               data={"reason": "max_output_bytes", "planned_bytes": total, "max_output_bytes": maximum})


def carve_android(case: Any, src: Path, buf: Any, size: int, layout: dict[str, Any], *, label: str, ctl: Ctl, probe: bool, source_sha256: str) -> dict[str, Any]:
    from .signatures import probe_at

    out = claim_numbered_dir(case.subdir("extract"), safe_label(label, "parts"))
    results = []
    for i, part in enumerate(layout["partitions"]):
        tick(ctl)
        entry = {"index": i, **part}
        if part.get("status") == "skipped":
            results.append(entry)
            continue
        dest = out / f"{i:02d}-{safe_name(part['name'])}.bin"
        digest = hashlib.sha256()
        try:
            with open(dest, "xb") as fp:
                for e in part["mapping"]:
                    pos = 0
                    while pos < e["size"]:
                        tick(ctl)
                        n = min(4 << 20, e["size"] - pos)
                        data = bytes(n) if e["target_type"] == "zero" else rd(buf, e["source_offset"] + pos, n, size)
                        fp.write(data)
                        digest.update(data)
                        pos += n
            entry.update(status="carved", path=case.rel(dest), file=case.rel(dest), bytes=part["size"], sha256=digest.hexdigest())
            if part.get("offset") is not None:
                entry["offset_hex"] = hex(part["offset"])
            if probe and part["mapping"] and part["mapping"][0]["target_type"] == "linear":
                first = part["mapping"][0]
                found = probe_at(buf, first["source_offset"], first["source_offset"] + first["size"], ctl)
                if found is not None:
                    entry["content"] = {"kind": found.kind, "description": found.description, "size": found.size}
            art = case.register_artifact(dest, kind="partition", producer=PRODUCER,
                                         description=f"{part['name']} ({part['size']} bytes) from {case.rel(src)}",
                                         extra={"source": case.rel(src), "source_sha256": source_sha256,
                                                "layout_source": layout["source"], "mapping": part["mapping"]})
            entry["artifact_id"] = art.get("id")
            results.append(entry)
        except BaseException:
            dest.unlink(missing_ok=True)
            raise
    shown = {k: v for k, v in layout.items() if k not in ("partitions", "warnings")}
    index = {"schema": "pweh.fwtriage.carve-index/v1", "source": case.rel(src), "source_sha256": source_sha256,
             "source_size": size, "layout": shown, "partitions": results, "warnings": layout["warnings"]}
    index_path = out / "index.json"
    atomic_write_json(index_path, sanitize(index))
    case.register_artifact(index_path, kind="triage-report", producer=PRODUCER, description="Android 파티션 분할 색인")
    return {"output_dir": case.rel(out), "index_path": case.rel(index_path), "partitions": results,
            "layout": shown, "warnings": layout["warnings"]}
