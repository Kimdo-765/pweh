"""파티션 감지 (MBR + 확장 파티션의 EBR 사슬, GPT, superfloppy, none).

- MBR: 주 파티션 4개(상태 바이트 0x00/0x80), 확장 파티션(0x05/0x0F/0x85)의 EBR 사슬은 방문 집합과 개수 상한(128)으로
  순환을 막는다. 논리 파티션 번호는 Linux 처럼 5 부터. LBA 단위는 기본 512 바이트이고, 512 로는 어떤 파티션에서도
  파일 시스템이 안 보이는데 4096 으로는 보이면 4096 으로 추정한다(경고).
- GPT(UEFI 사양): 보호 MBR(0xEE) → LBA1 헤더. 512, 4096 바이트 섹터를 차례로 시도한다. 헤더 CRC32(헤더 크기만큼,
  CRC 필드 0), 항목 배열 CRC32 를 확인하고 백업 헤더(AlternateLBA 또는 마지막 LBA)도 확인한다. 주 헤더가 깨졌고 백업이
  멀쩡하면 백업을 쓴다(경고). CRC 가 틀려도 법의학적으로 볼 수 있게 항목은 해석하고 경고를 붙인다.
- superfloppy: LBA0 에 FAT/exFAT/NTFS 부트 섹터가 있으면 파티션 표가 없는 볼륨이다. mkfs.fat --mbr 처럼 부트 코드
  자리에 파티션 표 비슷한 바이트가 있어도 superfloppy 로 보고 경고한다.
- 각 파티션: 번호, 시작/크기(바이트·섹터), 형식 ID/이름, GPT 이름/GUID, 부팅 가능, fs_hint(부트 섹터 냄새 맡기),
  정렬(SD 협회 권장 4 MiB 경계 등), 경고(겹침, 이미지 끝 너머, CRC 불일치).
"""

from __future__ import annotations

import struct
import uuid
import zlib
from typing import Any

from .common import FsError, Limits, Warnings, decode_utf16le, guard
from .exfat import probe_exfat_boot_sector
from .fat import probe_fat_boot_sector
from .reader import SliceReader

__all__ = ["detect_partitions", "sniff_fs", "partition_source", "MBR_TYPES", "GPT_TYPES"]

MBR_TYPES = {
    0x01: "FAT12", 0x04: "FAT16 (<32M)", 0x05: "Extended (CHS)", 0x06: "FAT16", 0x07: "NTFS/exFAT/HPFS",
    0x0B: "FAT32 (CHS)", 0x0C: "FAT32 (LBA)", 0x0E: "FAT16 (LBA)", 0x0F: "Extended (LBA)", 0x11: "Hidden FAT12",
    0x14: "Hidden FAT16 (<32M)", 0x16: "Hidden FAT16", 0x17: "Hidden NTFS/exFAT", 0x1B: "Hidden FAT32",
    0x1C: "Hidden FAT32 (LBA)", 0x1E: "Hidden FAT16 (LBA)", 0x27: "Windows recovery (hidden NTFS)",
    0x82: "Linux swap", 0x83: "Linux", 0x85: "Linux extended", 0x8E: "Linux LVM", 0xA5: "FreeBSD",
    0xA6: "OpenBSD", 0xA8: "Apple UFS", 0xAF: "Apple HFS/HFS+", 0xDA: "Non-FS data", 0xEE: "GPT protective",
    0xEF: "EFI System (FAT)", 0xFD: "Linux RAID autodetect",
}
EXTENDED_TYPES = frozenset({0x05, 0x0F, 0x85})

GPT_TYPES = {
    "C12A7328-F81F-11D2-BA4B-00A0C93EC93B": "EFI System",
    "EBD0A0A2-B9E5-4433-87C0-68B6B72699C7": "Microsoft basic data",
    "E3C9E316-0B5C-4DB8-817D-F92DF00215AE": "Microsoft reserved",
    "DE94BBA4-06D1-4D40-A16A-BFD50179D6AC": "Windows recovery",
    "0FC63DAF-8483-4772-8E79-3D69D8477DE4": "Linux filesystem",
    "0657FD6D-A4AB-43C4-84E5-0933C84B4F4F": "Linux swap",
    "E6D6D379-F507-44C2-A23C-238F2A3DF928": "Linux LVM",
    "A19D880F-05FC-4D3B-A006-743F0F84911E": "Linux RAID",
    "933AC7E1-2EB4-4F13-B844-0E14E2AEF915": "Linux /home",
    "4F68BCE3-E8CD-4DB1-96E7-FBCAF984B709": "Linux root (x86-64)",
    "B921B045-1DF0-41C3-AF44-4C6F280D3FAE": "Linux root (ARM64)",
    "21686148-6449-6E6F-744E-656564454649": "BIOS boot",
    "48465300-0000-11AA-AA11-00306543ECAC": "Apple HFS+",
    "7C3457EF-0000-11AA-AA11-00306543ECAC": "Apple APFS",
}

MAX_LOGICAL = 128
MAX_GPT_ARRAY = 4 << 20  # 항목 배열을 읽을 최대 바이트 (보통 16 KiB)
MAX_OVERLAP_REPORT = 32


def _guid(b: bytes) -> str:
    return str(uuid.UUID(bytes_le=bytes(b))).upper()


def _sniff_head(head: bytes) -> str | None:
    if len(head) < 512:
        return None
    name = bytes(head[3:11])
    if name == b"EXFAT   ":
        return "exfat" if probe_exfat_boot_sector(head) else "exfat-invalid"
    if name == b"NTFS    ":
        return "ntfs"
    p = probe_fat_boot_sector(head)
    if p:
        return str(p["fat_type"])
    return None


@guard
def sniff_fs(src: Any, offset: int = 0, length: int | None = None) -> str | None:
    """구간 시작의 파일 시스템 냄새: fat12/fat16/fat32/exfat/exfat-invalid/ntfs/ext2/ext3/ext4/f2fs/squashfs/luks/
    zeroed/unknown, 읽을 수 없으면 None."""
    if offset < 0 or offset >= src.size:
        return None
    avail = src.size - offset if length is None else max(0, min(length, src.size - offset))
    if avail < 512:
        return None
    head = src.read(offset, min(avail, 4096))
    hint = _sniff_head(head)
    if hint:
        return hint
    if head[0:4] in (b"hsqs", b"sqsh"):
        return "squashfs"
    if head[0:6] == b"LUKS\xba\xbe":
        return "luks"
    if avail >= 2048:
        sb = src.read(offset + 1024, 1024)
        if struct.unpack_from("<H", sb, 56)[0] == 0xEF53:
            compat, incompat, ro_compat = struct.unpack_from("<III", sb, 92)
            if incompat & (0x0040 | 0x0080 | 0x0200) or ro_compat & 0x0008:
                return "ext4"
            return "ext3" if compat & 0x0004 else "ext2"
        if struct.unpack_from("<I", sb, 0)[0] == 0xF2F52010:
            return "f2fs"
    if not any(head):
        return "zeroed"
    return "unknown"


def partition_source(src: Any, part: dict[str, Any]) -> SliceReader:
    """파티션 dict → 그 구간을 0 부터 읽는 SliceReader (이미지 끝을 넘으면 잘린 보기)."""
    try:
        start = int(part["start_offset"])
        size = int(part["size_bytes"])
    except (KeyError, TypeError, ValueError):
        raise FsError("파티션 정보에 start_offset/size_bytes 가 없습니다.", reason="bad_argument") from None
    if start < 0 or size < 0:
        raise FsError("파티션 시작/크기가 음수입니다.", reason="bad_argument")
    return SliceReader(src, start, size, label=f"partition {part.get('index')}")


def _mbr_entries(sec: bytes) -> list[dict[str, Any]]:
    out = []
    for i in range(4):
        e = sec[446 + 16 * i:446 + 16 * (i + 1)]
        status, ptype = e[0], e[4]
        lba, n = struct.unpack_from("<II", e, 8)
        out.append({"slot": i + 1, "status": status, "type": ptype, "lba": lba, "sectors": n})
    return out


def _alignment(start: int) -> dict[str, Any]:
    if start <= 0:
        return {"aligned_to": None, "aligned_4mib": start == 0}
    low = start & -start
    return {"aligned_to": min(low, 1 << 30), "aligned_4mib": start % (4 << 20) == 0}


class _Builder:
    def __init__(self, src: Any, limits: Limits) -> None:
        self.src = src
        self.limits = limits
        self.w = Warnings(limits.max_warnings)
        self._sniffed: dict[tuple[int, int], str | None] = {}

    def sniff(self, start: int, length: int) -> str | None:
        """같은 구간을 가리키는 항목이 많아도(조작된 GPT) 부트 섹터는 한 번만 읽는다."""
        key = (start, length)
        if key not in self._sniffed:
            if len(self._sniffed) >= 4096:
                self._sniffed.clear()
            self._sniffed[key] = sniff_fs(self.src, start, length)
        return self._sniffed[key]

    def part(self, *, index: int, scheme: str, role: str, start_lba: int, nsect: int, ss: int, type_id: Any,
             type_name: str | None, slot: int | None = None, bootable: bool = False, **extra: Any) -> dict[str, Any]:
        start = start_lba * ss
        length = nsect * ss
        size = self.src.size
        pw: list[dict[str, Any]] = []
        if start >= size:
            pw.append({"code": "partition_beyond_image", "message": "파티션 시작이 이미지 끝 너머입니다."})
        elif start + length > size:
            pw.append({"code": "partition_truncated", "message": "파티션 끝이 이미지 끝 너머입니다(잘린 이미지)."})
        if nsect == 0:
            pw.append({"code": "partition_empty", "message": "크기가 0 인 파티션입니다."})
        p: dict[str, Any] = {
            "index": index,
            "scheme": scheme,
            "role": role,
            "slot": slot,
            "sector_size": ss,
            "start_lba": start_lba,
            "size_sectors": nsect,
            "end_lba": start_lba + nsect - 1 if nsect else start_lba,
            "start_offset": start,
            "size_bytes": length,
            "end_offset": start + length,
            "available_bytes": max(0, min(length, size - start)),
            "type_id": type_id,
            "type_name": type_name,
            "bootable": bootable,
            "fs_hint": self.sniff(start, length) if start < size and nsect else None,
            "alignment": _alignment(start),
            "warnings": pw,
        }
        p.update(extra)
        return p


def _overlaps(parts: list[dict[str, Any]], w: Warnings) -> None:
    """겹치는 파티션 쌍을 MAX_OVERLAP_REPORT 개까지 경고한다 (정렬 뒤 선형 — 같은 구간 수만 개여도 제곱 시간이 되지 않는다).

    정렬한 뒤 각 구간은 뒤따르는 구간 중 겹치는 것만 본다. 겹치지 않는 첫 구간에서 안쪽 반복을 끝내고, 보고 상한에 닿으면 모두 끝낸다
    — 안쪽 반복의 총 횟수는 '보고한 쌍 + 구간 수' 를 넘지 않는다.
    """
    items = sorted((p["start_offset"], p["end_offset"], p["index"]) for p in parts if p["size_bytes"] > 0)
    reported = 0
    for i in range(len(items)):
        if reported >= MAX_OVERLAP_REPORT:
            break
        for j in range(i + 1, len(items)):
            if items[j][0] >= items[i][1]:
                break
            w.add("partition_overlap", f"파티션 {items[i][2]} 와 {items[j][2]} 가 겹칩니다.", a=items[i][2], b=items[j][2])
            reported += 1
            if reported >= MAX_OVERLAP_REPORT:
                break


def _read_gpt_header(src: Any, lba: int, ss: int) -> dict[str, Any] | None:
    off = lba * ss
    if lba < 1 or off + ss > src.size:
        return None
    h = src.read(off, ss)
    if h[0:8] != b"EFI PART":
        return None
    rev, hsize, hcrc, _res, my_lba, alt_lba, first_usable, last_usable = struct.unpack_from("<IIIIQQQQ", h, 8)
    entries_lba, num, esize, ecrc = struct.unpack_from("<QIII", h, 72)
    hdr: dict[str, Any] = {
        "lba": lba, "revision": f"0x{rev:08x}", "header_size": hsize, "header_crc": hcrc, "my_lba": my_lba,
        "alt_lba": alt_lba, "first_usable_lba": first_usable, "last_usable_lba": last_usable,
        "disk_guid": _guid(h[56:72]), "entries_lba": entries_lba, "num_entries": num, "entry_size": esize,
        "entries_crc": ecrc,
    }
    if 92 <= hsize <= ss:
        tmp = bytearray(h[:hsize])
        tmp[16:20] = b"\x00\x00\x00\x00"
        hdr["header_crc_ok"] = (zlib.crc32(bytes(tmp)) & 0xFFFFFFFF) == hcrc
    else:
        hdr["header_crc_ok"] = False
        hdr["header_size_invalid"] = True
    hdr["my_lba_ok"] = my_lba == lba
    return hdr


def _read_gpt_entries(src: Any, hdr: dict[str, Any], ss: int, w: Warnings, which: str) -> tuple[list[dict[str, Any]], bool | None]:
    num, esize = hdr["num_entries"], hdr["entry_size"]
    if esize < 128 or esize % 8 or esize > 4096:
        w.add("gpt_entry_size_invalid", f"{which} GPT 항목 크기 {esize} 가 잘못됐습니다.")
        return [], False
    total = num * esize
    want = min(total, MAX_GPT_ARRAY)
    if total > MAX_GPT_ARRAY:
        w.add("gpt_entry_array_too_large", f"{which} GPT 항목 배열이 너무 큽니다({num}×{esize}) — 앞부분만 읽고 CRC 는 확인하지 않습니다.")
    off = hdr["entries_lba"] * ss
    data = src.read_clamped(off, want) if 0 < off < src.size else b""
    crc_ok: bool | None
    if len(data) == total:
        crc_ok = (zlib.crc32(data) & 0xFFFFFFFF) == hdr["entries_crc"]
    else:
        crc_ok = None
        if total <= MAX_GPT_ARRAY:
            w.add("gpt_entries_unreadable", f"{which} GPT 항목 배열을 다 읽을 수 없습니다(이미지 끝).")
    out: list[dict[str, Any]] = []
    for i in range(len(data) // esize):
        e = data[i * esize:(i + 1) * esize]
        if not any(e[0:16]):
            continue
        first, last, attrs = struct.unpack_from("<QQQ", e, 32)
        raw_name = bytes(e[56:128])
        end = len(raw_name)
        for k in range(0, len(raw_name) - 1, 2):
            if raw_name[k] == 0 and raw_name[k + 1] == 0:
                end = k
                break
        name, lossy = decode_utf16le(raw_name[:end])
        out.append({"entry": i, "type_guid": _guid(e[0:16]), "unique_guid": _guid(e[16:32]), "first_lba": first,
                    "last_lba": last, "attributes": attrs, "name": name, "name_lossy": lossy})
    return out, crc_ok


def _gpt_attr_flags(attrs: int, type_guid: str) -> list[str]:
    flags = []
    if attrs & 1:
        flags.append("required")
    if attrs & 2:
        flags.append("no_block_io")
    if attrs & 4:
        flags.append("legacy_bios_bootable")
    if type_guid == "EBD0A0A2-B9E5-4433-87C0-68B6B72699C7":
        for bit, name in ((60, "read_only"), (61, "shadow_copy"), (62, "hidden"), (63, "no_drive_letter")):
            if attrs >> bit & 1:
                flags.append(name)
    return flags


def _try_gpt(b: _Builder, ss: int) -> dict[str, Any] | None:
    src, w = b.src, b.w
    prim = _read_gpt_header(src, 1, ss)
    last_lba = src.size // ss - 1
    cand_backup = last_lba
    if prim and prim["header_crc_ok"] and 1 < prim["alt_lba"] <= last_lba:
        cand_backup = prim["alt_lba"]
    back = _read_gpt_header(src, cand_backup, ss) if cand_backup > 1 else None
    if back is None and cand_backup != last_lba and last_lba > 1:
        back = _read_gpt_header(src, last_lba, ss)
    if prim is None and back is None:
        return None
    lw = Warnings(b.limits.max_warnings)
    if prim is None:
        lw.add("gpt_primary_missing", "주 GPT 헤더(LBA1)가 없습니다 — 백업 헤더를 씁니다.")
    elif not prim["header_crc_ok"]:
        lw.add("gpt_header_crc_mismatch", "주 GPT 헤더 CRC32 가 맞지 않습니다.", stored=f"0x{prim['header_crc']:08x}")
    elif not prim["my_lba_ok"]:
        lw.add("gpt_header_my_lba", "주 GPT 헤더의 MyLBA 가 1 이 아닙니다.")
    if back is None:
        lw.add("gpt_backup_missing", "백업 GPT 헤더를 찾지 못했습니다(이미지가 잘렸거나 지워짐).")
    elif not back["header_crc_ok"]:
        lw.add("gpt_backup_header_crc_mismatch", "백업 GPT 헤더 CRC32 가 맞지 않습니다.")
    use, used = prim, "primary"
    if not (prim and prim["header_crc_ok"]) and back and back["header_crc_ok"]:
        use, used = back, "backup"
        if prim is not None:
            lw.add("gpt_using_backup", "주 GPT 헤더가 손상돼 백업 헤더의 항목을 씁니다.")
    if use is None:
        use, used = back, "backup"
    assert use is not None
    entries, ecrc = _read_gpt_entries(src, use, ss, lw, "주" if used == "primary" else "백업")
    if ecrc is False:
        lw.add("gpt_entries_crc_mismatch", f"{'주' if used == 'primary' else '백업'} GPT 항목 배열 CRC32 가 맞지 않습니다.")
        other = back if used == "primary" else prim
        if other is not None and other["header_crc_ok"]:
            oe, ocrc = _read_gpt_entries(src, other, ss, Warnings(0), "")
            if ocrc:
                lw.add("gpt_entries_from_other", "다른 헤더의 항목 배열은 CRC 가 맞아 그쪽 항목을 씁니다.")
                entries, used = oe, ("backup" if used == "primary" else "primary")
                ecrc = True
    backup_entries_crc = None
    if back is not None and used == "primary" and back["header_crc_ok"]:
        _be, backup_entries_crc = _read_gpt_entries(src, back, ss, Warnings(0), "")
        if backup_entries_crc is False:
            lw.add("gpt_backup_entries_crc_mismatch", "백업 GPT 항목 배열 CRC32 가 맞지 않습니다.")
        if prim and back["entries_crc"] != prim["entries_crc"]:
            lw.add("gpt_backup_differs", "주/백업 GPT 항목 배열의 CRC 값이 서로 다릅니다.")
    parts: list[dict[str, Any]] = []
    for i, e in enumerate(entries):
        if e["last_lba"] < e["first_lba"]:
            lw.add("gpt_entry_inverted", f"GPT 항목 {e['entry']} 의 끝 LBA 가 시작보다 작습니다(건너뜀).")
            continue
        nsect = e["last_lba"] - e["first_lba"] + 1
        p = b.part(index=len(parts) + 1, scheme="gpt", role="primary", start_lba=e["first_lba"], nsect=nsect, ss=ss,
                   type_id=e["type_guid"], type_name=GPT_TYPES.get(e["type_guid"], "unknown"), slot=e["entry"] + 1,
                   bootable=bool(e["attributes"] & 4), gpt_name=e["name"], gpt_guid=e["unique_guid"],
                   gpt_attributes=f"0x{e['attributes']:016x}",
                   gpt_attribute_flags=_gpt_attr_flags(e["attributes"], e["type_guid"]))
        if e["first_lba"] < use["first_usable_lba"] or e["last_lba"] > use["last_usable_lba"]:
            p["warnings"].append({"code": "gpt_outside_usable", "message": "파티션이 GPT 사용 가능 범위 밖에 있습니다."})
        parts.append(p)
    summary = {
        "sector_size": ss,
        "used": used,
        "disk_guid": use["disk_guid"],
        "primary": prim,
        "backup": back,
        "entries_crc_ok": ecrc,
        "backup_entries_crc_ok": backup_entries_crc,
    }
    return {"summary": summary, "partitions": parts, "warnings": lw}


@guard
def detect_partitions(src: Any, *, limits: Limits | None = None) -> dict[str, Any]:
    """이미지의 파티션 구조. 반환: {scheme, sector_size, image_size, partitions:[…], mbr, gpt, warnings…}."""
    lim = limits or Limits()
    b = _Builder(src, lim)
    w = b.w
    out: dict[str, Any] = {"scheme": "none", "sector_size": 512, "image_size": src.size, "partitions": [],
                           "mbr": None, "gpt": None}

    def finish() -> dict[str, Any]:
        _overlaps(out["partitions"], w)
        out.update(w.export())
        return out

    if src.size < 512:
        w.add("image_too_small", "이미지가 512 바이트보다 작습니다.")
        return finish()
    sec0 = src.read(0, 512)
    sig = sec0[510:512] == b"\x55\xaa"
    vbr = _sniff_head(sec0)
    if vbr:
        out["scheme"] = "superfloppy"
        ss = 512
        fs_size = src.size
        if vbr.startswith("fat"):
            p = probe_fat_boot_sector(sec0) or {}
            ss = p.get("bytes_per_sector", 512)
            fs_size = p.get("total_sectors", 0) * ss
        elif vbr == "exfat":
            p = probe_exfat_boot_sector(sec0) or {}
            ss = p.get("bytes_per_sector", 512)
            fs_size = p.get("volume_length", 0) * ss
        elif vbr == "ntfs":
            ss = struct.unpack_from("<H", sec0, 11)[0] or 512
            fs_size = struct.unpack_from("<Q", sec0, 40)[0] * ss
        out["sector_size"] = ss
        nsect = (fs_size or src.size) // ss if ss else 0
        out["partitions"].append(b.part(index=1, scheme="superfloppy", role="volume", start_lba=0, nsect=nsect, ss=ss,
                                        type_id=None, type_name="superfloppy (파티션 표 없음)"))
        fake = [e for e in _mbr_entries(sec0) if e["type"] and e["sectors"]]
        if fake and sig:
            w.add("superfloppy_partition_like_bytes",
                  "LBA0 의 부트 섹터 안에 파티션 표 비슷한 바이트가 있습니다(예: mkfs.fat --mbr). 볼륨으로 해석합니다.",
                  entries=[{"type": f"0x{e['type']:02x}", "lba": e["lba"], "sectors": e["sectors"]} for e in fake])
        return finish()
    entries = _mbr_entries(sec0) if sig else []
    used = [e for e in entries if e["type"] != 0 and e["sectors"] > 0]
    protective = any(e["type"] == 0xEE for e in used)
    gpt = None
    for ss in (512, 4096):
        gpt = _try_gpt(b, ss)
        if gpt is not None:
            break
    if sig:
        out["mbr"] = {"disk_signature": f"0x{struct.unpack_from('<I', sec0, 440)[0]:08x}",
                      "entries": [dict(e, type_name=MBR_TYPES.get(e["type"])) for e in entries]}
    if gpt is not None and (protective or not used):
        out["scheme"] = "gpt"
        out["sector_size"] = gpt["summary"]["sector_size"]
        out["gpt"] = gpt["summary"]
        out["partitions"] = gpt["partitions"]
        w.extend(gpt["warnings"])
        if not protective:
            w.add("gpt_without_protective_mbr", "보호 MBR(0xEE) 없이 GPT 가 있습니다.")
        elif len(used) > 1:
            w.add("hybrid_mbr", "보호 MBR 에 0xEE 말고도 파티션이 있습니다(하이브리드 MBR). GPT 를 기준으로 합니다.")
        return finish()
    if protective:
        w.add("protective_mbr_without_gpt", "보호 MBR(0xEE)이 있는데 GPT 헤더를 찾지 못했습니다 — MBR 항목만 봅니다.")
    if gpt is not None:
        w.add("stale_gpt_present", "MBR 파티션이 있는데 GPT 헤더도 남아 있습니다(예전 GPT 흔적). MBR 을 기준으로 합니다.",
              gpt_disk_guid=gpt["summary"]["disk_guid"])
        out["gpt"] = dict(gpt["summary"], ignored=True)
    if not used:
        if not sig:
            w.add("no_signature", "LBA0 에 MBR/부트 서명 0x55AA 가 없고 GPT 도 없습니다.")
        else:
            w.add("mbr_empty", "MBR 에 파티션이 없습니다.")
        return finish()
    out["scheme"] = "mbr"
    for e in used:
        if e["status"] not in (0x00, 0x80):
            w.add("mbr_bad_status", f"MBR 항목 {e['slot']} 의 상태 바이트가 이상합니다: 0x{e['status']:02x}")
    # 섹터 크기: 512 로 안 보이고 4096 으로 보이면 4096
    ss = 512
    primaries = [e for e in used if e["type"] not in EXTENDED_TYPES and e["type"] != 0xEE]
    if primaries:
        seen512 = any(sniff_fs(src, e["lba"] * 512) not in (None, "unknown", "zeroed") for e in primaries)
        if not seen512:
            seen4k = any(sniff_fs(src, e["lba"] * 4096) not in (None, "unknown", "zeroed") for e in primaries)
            if seen4k:
                ss = 4096
                w.add("mbr_sector_size_4096", "512 바이트 LBA 로는 파일 시스템이 보이지 않고 4096 으로는 보여 4096 바이트 섹터로 해석합니다.")
    out["sector_size"] = ss
    parts: list[dict[str, Any]] = []
    for e in used:
        if e["type"] in EXTENDED_TYPES:
            continue
        parts.append(b.part(index=e["slot"], scheme="mbr", role="primary", start_lba=e["lba"], nsect=e["sectors"],
                            ss=ss, type_id=f"0x{e['type']:02x}", type_name=MBR_TYPES.get(e["type"], "unknown"),
                            slot=e["slot"], bootable=e["status"] == 0x80))
    exts = [e for e in used if e["type"] in EXTENDED_TYPES]
    if len(exts) > 1:
        w.add("multiple_extended", "확장 파티션이 둘 이상입니다(사양 밖) — 모두 따라갑니다.")
    logical_index = 5
    extended_info = []
    for ext in exts:
        extended_info.append({"slot": ext["slot"], "start_lba": ext["lba"], "size_sectors": ext["sectors"],
                              "type_id": f"0x{ext['type']:02x}"})
        logical_index = _walk_ebr(b, ext, ss, parts, logical_index)
    if out["mbr"] is not None:
        out["mbr"]["extended"] = extended_info
    out["partitions"] = parts
    return finish()


def _walk_ebr(b: _Builder, ext: dict[str, Any], ss: int, parts: list[dict[str, Any]], index: int) -> int:
    src, w = b.src, b.w
    ext_start = ext["lba"]
    ext_end = ext["lba"] + ext["sectors"]
    cur = ext_start
    visited: set[int] = set()
    count = 0
    while True:
        if cur in visited:
            w.add("ebr_loop", "EBR 사슬이 순환합니다 — 멈춥니다.", lba=cur)
            break
        if count >= MAX_LOGICAL:
            w.add("ebr_too_many", f"논리 파티션이 {MAX_LOGICAL} 개를 넘습니다 — 멈춥니다.")
            break
        visited.add(cur)
        if (cur + 1) * ss > src.size:
            w.add("ebr_beyond_image", "EBR 이 이미지 끝 너머에 있습니다.", lba=cur)
            break
        sec = src.read(cur * ss, 512)
        if sec[510:512] != b"\x55\xaa":
            w.add("ebr_bad_signature", "EBR 서명 0x55AA 가 없습니다 — 멈춥니다.", lba=cur)
            break
        ents = _mbr_entries(sec)
        log, link = ents[0], ents[1]
        if any(e["type"] for e in ents[2:]):
            w.add("ebr_extra_entries", "EBR 의 3·4번째 항목이 비어 있지 않습니다(무시).", lba=cur)
        if log["type"] and log["sectors"]:
            start = cur + log["lba"]
            p = b.part(index=index, scheme="mbr", role="logical", start_lba=start, nsect=log["sectors"], ss=ss,
                       type_id=f"0x{log['type']:02x}", type_name=MBR_TYPES.get(log["type"], "unknown"),
                       bootable=log["status"] == 0x80, ebr_lba=cur)
            if start + log["sectors"] > ext_end or start < ext_start:
                p["warnings"].append({"code": "logical_outside_extended", "message": "논리 파티션이 확장 파티션 밖에 있습니다."})
            parts.append(p)
            index += 1
        count += 1
        if link["type"] in EXTENDED_TYPES and link["sectors"]:
            nxt = ext_start + link["lba"]
            if not ext_start <= nxt < ext_end:
                w.add("ebr_link_outside", "다음 EBR 링크가 확장 파티션 밖을 가리킵니다 — 멈춥니다.", lba=nxt)
                break
            cur = nxt
            continue
        break
    return index
