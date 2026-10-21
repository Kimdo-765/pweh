"""Android 펌웨어의 bounded 구조 해석. 파일 시스템·서명 검증·코드 실행은 하지 않는다.

형식 근거: AOSP libsparse/sparse_format.h, mkbootimg/include/bootimg/bootimg.h,
libavb/avb_vbmeta_image.h, liblp/metadata_format.h, f2fs-tools/include/f2fs_fs.h.
"""

from __future__ import annotations

import hashlib
import re
import struct
from typing import Any

from pweh.errors import ValidationFailed
from pweh.safety.redact import redact_line

from .common import Ctl

SPARSE_MAGIC = b"\x3a\xff\x26\xed"
LP_GEOMETRY_MAGIC = b"gDla"
LP_HEADER_MAGIC = b"0PLA"
MAX_METADATA = 16 << 20
MAX_EXTENTS = 65536
MAX_PARTITIONS = 128


def fail(reason: str, message: str) -> None:
    raise ValidationFailed(message, data={"reason": reason})


def tick(ctl: Ctl) -> None:
    if ctl.expired():
        fail("android_time_budget", "Android 구조 해석 시간 예산을 넘었습니다.")


def rd(buf: Any, off: int, size: int, limit: int) -> bytes:
    if off < 0 or size < 0 or size > MAX_METADATA or off + size > limit:
        fail("android_bounds", "Android 구조가 입력 범위 또는 읽기 상한을 넘습니다.")
    data = bytes(buf[off:off + size])
    if len(data) != size:
        fail("android_bounds", "Android 구조를 끝까지 읽지 못했습니다.")
    return data


def align(n: int, page: int) -> int:
    return ((n + page - 1) // page) * page


def text(data: bytes) -> str:
    return mask_text(data.split(b"\0", 1)[0].decode("utf-8", "replace"))


def mask_text(value: str) -> str:
    return "\n".join(redact_line(line, None)[0] for line in value.splitlines())


def _permissive(data: bytes) -> bool:
    return re.search(rb"\bandroidboot\.selinux\s*=\s*[\"']?permissive\b", data) is not None


def hash_buffer(buf: Any, size: int, ctl: Ctl) -> str:
    """원본 지문 계산도 동일 작업의 시간·취소 예산으로 묶는다."""
    digest = hashlib.sha256()
    for off in range(0, size, 4 << 20):
        tick(ctl)
        digest.update(rd(buf, off, min(4 << 20, size - off), size))
    return digest.hexdigest()


def sparse_info(buf: Any, start: int, limit: int, ctl: Ctl) -> dict[str, Any]:
    h = rd(buf, start, 28, limit)
    magic, major, minor, hs, cs, block, blocks, chunks, crc = struct.unpack("<I4H4I", h)
    if magic != 0xED26FF3A or major != 1:
        fail("unsupported_sparse_version", "지원하는 Android sparse major version은 1입니다.")
    if hs < 28 or cs < 12 or block == 0 or block % 4 or chunks > 262144:
        fail("invalid_sparse_header", "sparse 헤더 크기·블록 크기·청크 수가 잘못됐거나 상한을 넘습니다.")
    pos, logical = start + hs, 0
    if pos > limit:
        fail("android_bounds", "sparse 확장 헤더가 이미지 끝을 넘습니다.")
    counts = {"raw": 0, "fill": 0, "dont_care": 0, "crc32": 0}
    for _ in range(chunks):
        tick(ctl)
        typ, _reserved, count, total = struct.unpack("<2H2I", rd(buf, pos, 12, limit))
        if total < cs or pos + total > limit:
            fail("invalid_sparse_chunk", "sparse 청크가 입력 범위를 넘거나 헤더보다 작습니다.")
        payload = total - cs
        if typ == 0xCAC1:
            valid, kind = payload == count * block, "raw"
        elif typ == 0xCAC2:
            valid, kind = payload == 4, "fill"
        elif typ == 0xCAC3:
            valid, kind = payload == 0, "dont_care"
        elif typ == 0xCAC4:
            valid, kind = payload == 4 and count == 0, "crc32"
        else:
            fail("unsupported_sparse_chunk", "알 수 없는 sparse 청크 형식입니다.")
        if not valid:
            fail("invalid_sparse_chunk", "sparse 청크 payload 길이와 블록 수가 맞지 않습니다.")
        counts[kind] += 1
        logical += count
        if logical > blocks:
            fail("invalid_sparse_size", "sparse 청크의 논리 크기 합계가 헤더를 넘습니다.")
        pos += total
    if logical != blocks:
        fail("invalid_sparse_size", "sparse 논리 블록 합계가 헤더와 다릅니다.")
    return {"kind": "android-sparse", "size": pos - start, "version": f"{major}.{minor}",
            "block_size": block, "expanded_size": blocks * block, "chunks": counts,
            "image_checksum": f"0x{crc:08x}", "expanded_crc_status": "not-checked",
            "structure_valid": True, "carve_supported": False}


def boot_info(buf: Any, start: int, limit: int, ctl: Ctl) -> dict[str, Any]:
    h = rd(buf, start, 48, limit)
    if h[:8] != b"ANDROID!":
        fail("not_android_boot", "Android boot 매직이 아닙니다.")
    version = struct.unpack_from("<I", h, 40)[0]
    sizes = {0: 1632, 1: 1648, 2: 1660, 3: 1580, 4: 1584}
    if version not in sizes:
        fail("unsupported_boot_version", "지원하는 boot header version은 0~4입니다.")
    h = rd(buf, start, sizes[version], limit)
    kernel = struct.unpack_from("<I", h, 8)[0]
    ramdisk = struct.unpack_from("<I", h, 16 if version < 3 else 12)[0]
    page = struct.unpack_from("<I", h, 36)[0] if version < 3 else 4096
    if page < sizes[version] or page > 65536 or page & (page - 1):
        fail("invalid_boot_page", "boot page 크기가 잘못됐습니다.")
    if version in (1, 2) and struct.unpack_from("<I", h, 1644)[0] != sizes[version]:
        fail("invalid_boot_header", "boot header_size와 version이 맞지 않습니다.")
    if version >= 3 and struct.unpack_from("<I", h, 20)[0] != sizes[version]:
        fail("invalid_boot_header", "boot header_size와 version이 맞지 않습니다.")
    sections, pos = [], page
    for name, length in (("kernel", kernel), ("ramdisk", ramdisk)):
        sections.append({"name": name, "offset": pos, "size": length})
        pos += align(length, page)
    if version < 3:
        second = struct.unpack_from("<I", h, 24)[0]
        sections.append({"name": "second", "offset": pos, "size": second})
        pos += align(second, page)
        if version >= 1:
            dtbo, dtbo_off = struct.unpack_from("<IQ", h, 1632)
            if dtbo and dtbo_off != pos:
                fail("invalid_boot_section", "recovery DTBO offset이 section 배치와 다릅니다.")
            sections.append({"name": "recovery_dtbo", "offset": pos, "size": dtbo})
            pos += align(dtbo, page)
        if version == 2:
            dtb = struct.unpack_from("<I", h, 1648)[0]
            sections.append({"name": "dtb", "offset": pos, "size": dtb})
            pos += align(dtb, page)
        raw_cmdline = h[64:576].split(b"\0", 1)[0] + h[608:1632].split(b"\0", 1)[0]
        cmdline = text(raw_cmdline)
    else:
        raw_cmdline = h[44:1580].split(b"\0", 1)[0]
        cmdline = text(raw_cmdline)
        if version == 4:
            sig = struct.unpack_from("<I", h, 1580)[0]
            sections.append({"name": "boot_signature", "offset": pos, "size": sig})
            pos += align(sig, page)
    return {"kind": "android-boot", "size": pos, "header_version": version, "page_size": page,
            "sections": sections, "cmdline": cmdline, "selinux_permissive": _permissive(raw_cmdline), "kernel_size": kernel, "ramdisk_size": ramdisk,
            "role_hint": "init_boot-candidate" if version == 4 and kernel == 0 and ramdisk else "boot",
            "truncated": start + pos > limit, "signature_status": "not-verified", "structure_valid": True}


def vendor_boot_info(buf: Any, start: int, limit: int, ctl: Ctl) -> dict[str, Any]:
    h = rd(buf, start, 16, limit)
    version, page = struct.unpack_from("<II", h, 8)
    if h[:8] != b"VNDRBOOT" or version not in (3, 4):
        fail("unsupported_vendor_boot", "지원하는 vendor_boot version은 3/4입니다.")
    hs = 2112 if version == 3 else 2128
    h = rd(buf, start, hs, limit)
    if page < 512 or page > 65536 or page & (page - 1) or struct.unpack_from("<I", h, 2096)[0] != hs:
        fail("invalid_vendor_boot", "vendor_boot page/header 크기가 잘못됐습니다.")
    ramdisk = struct.unpack_from("<I", h, 24)[0]
    dtb = struct.unpack_from("<I", h, 2100)[0]
    pos = align(hs, page)
    sections = []
    for name, length in (("vendor_ramdisk", ramdisk), ("dtb", dtb)):
        sections.append({"name": name, "offset": pos, "size": length})
        pos += align(length, page)
    entries, bootconfig, raw_bootconfig = [], None, b""
    table_complete = True
    if version == 4:
        table_size, count, es, config_size = struct.unpack_from("<4I", h, 2112)
        if count > 4096 or table_size > MAX_METADATA or (count and es != 108) or count * es != table_size:
            fail("invalid_vendor_table", "vendor ramdisk table 크기·항목 수가 잘못됐습니다.")
        sections.append({"name": "vendor_ramdisk_table", "offset": pos, "size": table_size})
        table_complete = start + pos + table_size <= limit
        if table_complete:
            for i in range(count):
                tick(ctl)
                entry = rd(buf, start + pos + i * es, es, limit)
                n, off, typ = struct.unpack_from("<3I", entry)
                if off + n > ramdisk:
                    fail("invalid_vendor_extent", "vendor ramdisk 항목이 ramdisk 범위를 넘습니다.")
                if len(entries) < 32:
                    entries.append({"name": text(entry[12:44]), "offset": off, "size": n, "type": typ})
        pos += align(table_size, page)
        sections.append({"name": "bootconfig", "offset": pos, "size": config_size})
        if config_size <= (1 << 20) and start + pos + config_size <= limit:
            raw_bootconfig = rd(buf, start + pos, config_size, limit)
            bootconfig = text(raw_bootconfig)
        pos += align(config_size, page)
    return {"kind": "android-vendor-boot", "size": pos, "header_version": version, "page_size": page,
            "sections": sections, "cmdline": text(h[28:2076]), "bootconfig": bootconfig,
            "selinux_permissive": _permissive(h[28:2076].split(b"\0", 1)[0]) or _permissive(raw_bootconfig),
            "ramdisk_entries": entries, "ramdisk_table_complete": table_complete,
            "truncated": start + pos > limit, "structure_valid": True}


def vbmeta_info(buf: Any, start: int, limit: int, ctl: Ctl) -> dict[str, Any]:
    h = rd(buf, start, 256, limit)
    if h[:4] != b"AVB0":
        fail("not_vbmeta", "AVB0 매직이 아닙니다.")
    major, minor = struct.unpack_from(">II", h, 4)
    auth, aux, algorithm = struct.unpack_from(">QQI", h, 12)
    if major > 1 or auth % 64 or aux % 64:
        fail("invalid_vbmeta", "지원하지 않는 AVB version 또는 잘못된 블록 크기입니다.")
    for p, bound in ((32, auth), (48, auth), (64, aux), (80, aux), (96, aux)):
        off, n = struct.unpack_from(">QQ", h, p)
        if off + n > bound:
            fail("invalid_vbmeta_bounds", "AVB 항목이 auth/aux 블록 범위를 넘습니다.")
    total = 256 + auth + aux
    flags = struct.unpack_from(">I", h, 120)[0]
    return {"kind": "android-vbmeta", "size": total, "required_version": f"{major}.{minor}",
            "algorithm": algorithm, "flags": flags, "hashtree_disabled": bool(flags & 1),
            "verification_disabled": bool(flags & 2), "unknown_flags": flags & ~3,
            "rollback_index": struct.unpack_from(">Q", h, 112)[0],
            "release_string": text(h[128:176]), "signature_status": "not-verified",
            "truncated": start + total > limit, "structure_valid": True}


def avb_footer_info(buf: Any, start: int, limit: int, ctl: Ctl) -> dict[str, Any]:
    h = rd(buf, start, 64, limit)
    major, minor, original, off, length = struct.unpack_from(">IIQQQ", h, 4)
    if h[:4] != b"AVBf" or major != 1 or original > off or length < 256 or off + length > start:
        fail("invalid_avb_footer", "AVB footer version/상대 범위가 잘못됐습니다.")
    return {"kind": "android-avb-footer", "size": 64, "version": f"{major}.{minor}",
            "original_image_size": original, "vbmeta_relative_offset": off, "vbmeta_size": length,
            "signature_status": "not-verified", "structure_valid": True}


def f2fs_info(buf: Any, start: int, limit: int, ctl: Ctl) -> dict[str, Any]:
    h = rd(buf, start + 1024, 128, limit)
    magic, major, minor, ls, spb, lb, lseg = struct.unpack_from("<I2H4I", h)
    blocks = struct.unpack_from("<Q", h, 36)[0]
    if magic != 0xF2F52010 or not (9 <= ls <= lb and 12 <= lb <= 14 and ls + spb == lb and 0 < lseg < 32 and blocks > 0):
        fail("invalid_f2fs", "F2FS superblock 기하 정보가 잘못됐습니다.")
    return {"kind": "f2fs", "size": blocks << lb, "version": f"{major}.{minor}",
            "block_size": 1 << lb, "block_count": blocks, "checksum_status": "not-checked",
            "filesystem_supported": False, "truncated": start + (blocks << lb) > limit, "structure_valid": True}


def geometry(buf: Any, offset: int, limit: int) -> dict[str, Any]:
    h = rd(buf, offset, 52, limit)
    magic, size = struct.unpack_from("<II", h)
    if magic != 0x616C4467 or size != 52:
        fail("invalid_lp_geometry", "LP geometry magic/크기가 잘못됐습니다.")
    digest = hashlib.sha256(h[:8] + bytes(32) + h[40:]).digest()
    if digest != h[8:40]:
        fail("lp_geometry_checksum", "LP geometry SHA256이 맞지 않습니다.")
    meta, slots, block = struct.unpack_from("<3I", h, 40)
    if not (128 <= meta <= MAX_METADATA and meta % 512 == 0 and 1 <= slots <= 16 and 512 <= block <= (1 << 20) and block % 512 == 0):
        fail("invalid_lp_geometry", "LP metadata 크기·slot 수·block 크기가 잘못됐거나 상한을 넘습니다.")
    return {"metadata_max_size": meta, "slot_count": slots, "logical_block_size": block,
            "sha256": hashlib.sha256(h).hexdigest(), "checksum_ok": True}
