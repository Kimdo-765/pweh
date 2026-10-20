"""ESP32 계열 합성 이미지 빌더 (fwtriage espfmt 테스트용, 실제 기기·덤프 없이).

- 파티션 테이블 (MD5 포함/제외)
- 앱·2단계 부트로더 이미지 (esp_app_desc_t / esp_bootloader_desc_t, 체크섬, SHA256)
- NVS 파티션 (v1/v2, 여러 페이지, 네임스페이스, 모든 기본 타입, 문자열, BLOB v1, 여러 조각 BLOB_DATA+BLOB_IDX,
  지운 옛 값, 손상 엔트리)
- ELF32 (esptool elf2image 오라클 입력 — espfmt.image_to_elf 와 독립적으로 손으로 만든다)
- 조립된 플래시 (부트로더 + 0x8000 파티션 테이블 + 0x9000 NVS + 0x10000 앱)

NVS CRC 는 기본값으로 반드시 espfmt.nvs_crc32 를 쓴다 (규약 정의는 라이브러리 한 곳). crc_fn 인자는 규약 불일치
시험용으로만 바꾼다. 체크섬·이미지 배치는 라이브러리 코드를 쓰지 않고 따로 계산한다 (오라클 독립성).
값은 모두 합성이다 (MAC 은 f4:12:fa:12:34:56 같은 예시만, 실제 기기 식별자 없음).
"""

from __future__ import annotations

import hashlib
import struct
import sys
from functools import reduce
from operator import xor
from pathlib import Path
from typing import Any, Callable

REPO = Path(__file__).resolve().parents[2]
if str(REPO / "mcp-servers" / "fwtriage-mcp") not in sys.path:
    sys.path.insert(0, str(REPO / "mcp-servers" / "fwtriage-mcp"))

from fwtriage_mcp.espfmt import nvs_crc32  # noqa: E402

SYNTH_MAC = bytes.fromhex("f412fa123456")  # 합성 MAC f4:12:fa:12:34:56

CHIP_ESP32, CHIP_S2, CHIP_C3, CHIP_S3, CHIP_C2, CHIP_C6, CHIP_H2, CHIP_P4, CHIP_C61, CHIP_C5 = 0, 2, 5, 9, 12, 13, 16, 18, 20, 23
EM_XTENSA, EM_RISCV = 94, 243
SHF_WRITE, SHF_ALLOC, SHF_EXECINSTR = 1, 2, 4


# ---------------------------------------------------------------------------
# 파티션 테이블
# ---------------------------------------------------------------------------

def pt_entry(label: str, ptype: int, subtype: int, offset: int, size: int, flags: int = 0) -> bytes:
    return struct.pack("<2sBBII16sI", b"\xAA\x50", ptype, subtype, offset, size, label.encode(), flags)


def build_partition_table(entries: list[tuple], *, md5: bool = True, pad_to: int = 0xC00) -> bytes:
    """entries: (label, type, subtype, offset, size[, flags]). MD5 엔트리는 앞 엔트리 바이트 전체의 MD5."""
    body = b"".join(pt_entry(*e) for e in entries)
    if md5:
        body += b"\xEB\xEB" + b"\xFF" * 14 + hashlib.md5(body).digest()
    return body + b"\xFF" * max(0, pad_to - len(body))


DEFAULT_PARTITIONS = [
    ("nvs", 0x01, 0x02, 0x9000, 0x6000),
    ("phy_init", 0x01, 0x01, 0xF000, 0x1000),
    ("factory", 0x00, 0x00, 0x10000, 0x30000),
]


# ---------------------------------------------------------------------------
# 앱 / 부트로더 이미지
# ---------------------------------------------------------------------------

def build_app_desc(*, version: str = "1.4.2", project_name: str = "toy-arcade", time: str = "12:34:56", date: str = "Oct 20 2026",
                   idf_ver: str = "v5.3.1", secure_version: int = 0, app_elf_sha256: bytes = b"\0" * 32,
                   min_efuse: int = 0, max_efuse: int = 99, mmu_page_size_log2: int = 0) -> bytes:
    """esp_app_desc_t (256 바이트)."""
    return struct.pack("<II8s32s32s16s16s32s32sHHB3s72s", 0xABCD5432, secure_version, b"\0" * 8, version.encode(),
                       project_name.encode(), time.encode(), date.encode(), idf_ver.encode(), app_elf_sha256, min_efuse,
                       max_efuse, mmu_page_size_log2, b"\0" * 3, b"\0" * 72)


def build_bootloader_desc(*, version: int = 1, idf_ver: str = "v5.3.1", date_time: str = "Oct 20 2026 12:34:56") -> bytes:
    """esp_bootloader_desc_t (80 바이트, 매직 0x50)."""
    return struct.pack("<B3sI32s24s16s", 0x50, b"\0" * 3, version, idf_ver.encode(), date_time.encode(), b"\0" * 16)


def xor_checksum(segments: list[tuple[int, bytes]]) -> int:
    return reduce(xor, (b for _, d in segments for b in d), 0xEF)


def build_app_image(*, chip_id: int, entry: int, segments: list[tuple[int, bytes]], spi_mode: int = 2, spi_speed: int = 0xF,
                    spi_size: int = 2, hash_appended: bool = True, min_rev: int = 0, min_rev_full: int = 0,
                    max_rev_full: int = 99, wp_pin: int = 0xEE, pad_segments: bool = True) -> bytes:
    """ESP32 계열 이미지: 8바이트 헤더 + 16바이트 확장 헤더 + 세그먼트 + (pos%16==15 까지 0 채움) 체크섬 + 선택 SHA256."""
    segs = [(a, d + b"\0" * (-len(d) % 4) if pad_segments else d) for a, d in segments]
    body = bytearray(struct.pack("<BBBBI", 0xE9, len(segs), spi_mode, (spi_size << 4) | spi_speed, entry))
    body += struct.pack("<BBBBHBHH4sB", wp_pin, 0, 0, 0, chip_id, min_rev, min_rev_full, max_rev_full, b"\0" * 4,
                        1 if hash_appended else 0)
    for addr, d in segs:
        body += struct.pack("<II", addr, len(d)) + d
    while len(body) % 16 != 15:
        body.append(0)
    body.append(xor_checksum(segs))
    if hash_appended:
        body += hashlib.sha256(bytes(body)).digest()
    return bytes(body)


def s3_app_image(*, hash_appended: bool = True, app_desc: bytes | None = None, extra: bytes = b"") -> bytes:
    """ESP32-S3 앱: DROM(app_desc+rodata), IROM(text), DRAM, IRAM(엔트리), RTC."""
    desc = build_app_desc() if app_desc is None else app_desc
    rodata = desc + b"SAVE_SLOT_%d\0HISCORE\0" + bytes(range(64)) + extra
    return build_app_image(chip_id=CHIP_S3, entry=0x40378A10, hash_appended=hash_appended, segments=[
        (0x3C000020, rodata),
        (0x42000020, b"\x36\x41\x00" + bytes(range(1, 0x7D))),
        (0x3FC90000, b"\x11" * 0x40),
        (0x40378000, b"\x36\x41\x00\x1d\xf0" + b"\x00" * 0xA0B + b"\x36\x41\x00\x1d\xf0\x00\x00\x00"),
        (0x600FE000, b"\x22" * 0x20),
    ])


def c3_app_image(*, hash_appended: bool = True) -> bytes:
    """ESP32-C3 앱: DROM(app_desc), IROM(text), DRAM, IRAM(엔트리), RTC."""
    text = struct.pack("<II", 0x00150513, 0x00008067) * 8  # addi a0,a0,1 ; ret
    return build_app_image(chip_id=CHIP_C3, entry=0x40380000, hash_appended=hash_appended, segments=[
        (0x3C000020, build_app_desc(project_name="toy-c3") + b"rodata-c3\0\0\0"),
        (0x42000020, text),
        (0x3FC8A000, b"\x33" * 0x30),
        (0x40380000, text),
        (0x50000000, b"\x44" * 0x10),
    ])


def s3_bootloader_image() -> bytes:
    """ESP32-S3 2단계 부트로더: DRAM(첫 세그먼트가 esp_bootloader_desc_t), IRAM 두 개 (플래시 세그먼트 없음)."""
    return build_app_image(chip_id=CHIP_S3, entry=0x403C98D0, segments=[
        (0x3FCD5820, build_bootloader_desc() + b"\x55" * 0x30),
        (0x403CC710, b"\x36\x41\x00\x1d\xf0\x00\x00\x00" * 4),
        (0x403C9700, b"\x36\x41\x00\x1d\xf0\x00\x00\x00" * 0x60),
    ])


# ---------------------------------------------------------------------------
# NVS
# ---------------------------------------------------------------------------

NVS_TYPES = {"U8": (0x01, 1, False), "I8": (0x11, 1, True), "U16": (0x02, 2, False), "I16": (0x12, 2, True),
             "U32": (0x04, 4, False), "I32": (0x14, 4, True), "U64": (0x08, 8, False), "I64": (0x18, 8, True)}
NVS_SZ, NVS_BLOB, NVS_BLOB_DATA, NVS_BLOB_IDX = 0x21, 0x41, 0x42, 0x48
PAGE_ACTIVE, PAGE_FULL, PAGE_FREEING, PAGE_CORRUPT = 0xFFFFFFFE, 0xFFFFFFFC, 0xFFFFFFF8, 0xFFFFFFF0
ES_ERASED, ES_WRITTEN, ES_EMPTY = 0, 2, 3


class NvsImage:
    """NVS 파티션 합성기 (ESP-IDF nvs_flash 형식으로 알려진 배치).

    엔트리 32 바이트: ns, type, span, chunk_index, crc32(바이트 0..4 + 8..32), key[16], data[8].
    페이지: 상태 u32, seq u32, 버전(0xFF=v1, 0xFE=v2), 0xFF 19 바이트, CRC32(바이트 4..28); 비트맵 32 바이트(엔트리당 2비트);
    엔트리 126 개. CRC 는 crc_fn (기본 espfmt.nvs_crc32).
    """

    def __init__(self, *, version: int = 2, crc_fn: Callable[[bytes], int] | None = None, first_seq: int = 0) -> None:
        self.version = version
        self.crc = crc_fn or nvs_crc32
        self.pages: list[dict[str, Any]] = []
        self.ns: dict[str, int] = {}
        self.records: list[dict[str, Any]] = []
        self._next_seq = first_seq
        self.new_page()

    # -- 페이지 -----------------------------------------------------------------
    def new_page(self, *, seq: int | None = None) -> int:
        s = self._next_seq if seq is None else seq
        self._next_seq = max(self._next_seq, s) + 1
        self.pages.append({"seq": s, "entries": bytearray(b"\xFF" * (126 * 32)), "states": [ES_EMPTY] * 126, "next": 0, "state": None})
        return len(self.pages) - 1

    def _alloc(self, span: int) -> tuple[int, int]:
        pg = self.pages[-1]
        if pg["next"] + span > 126:
            self.new_page()
            pg = self.pages[-1]
        e = pg["next"]
        pg["next"] += span
        return len(self.pages) - 1, e

    def set_page_state(self, page: int, state: int) -> None:
        self.pages[page]["state"] = state

    # -- 엔트리 -----------------------------------------------------------------
    def _entry(self, ns: int, typ: int, span: int, chunk: int, key: str, data8: bytes) -> bytearray:
        kb = key.encode()
        assert len(kb) <= 15 and len(data8) == 8
        ent = bytearray(struct.pack("<BBBBI16s", ns, typ, span, chunk, 0, kb) + data8)
        struct.pack_into("<I", ent, 4, self.crc(bytes(ent[0:4] + ent[8:32])))
        return ent

    def _write(self, ns: int, typ: int, chunk: int, key: str, data8: bytes, payload: bytes = b"", **meta: Any) -> dict[str, Any]:
        span = 1 + (len(payload) + 31) // 32
        p, e = self._alloc(span)
        pg = self.pages[p]
        ent = self._entry(ns, typ, span, chunk, key, data8)
        pg["entries"][32 * e:32 * e + 32] = ent
        if payload:
            padded = payload + b"\xFF" * (-len(payload) % 32)
            pg["entries"][32 * (e + 1):32 * (e + 1) + len(padded)] = padded
        for j in range(e, e + span):
            pg["states"][j] = ES_WRITTEN
        rec = {"ns": ns, "type": typ, "key": key, "page": p, "entry": e, "span": span, "chunk": chunk, **meta}
        self.records.append(rec)
        return rec

    def namespace(self, name: str) -> int:
        if name not in self.ns:
            idx = len(self.ns) + 1
            self._write(0, 0x01, 0xFF, name, bytes([idx]) + b"\xFF" * 7, namespace_def=True)
            self.ns[name] = idx
        return self.ns[name]

    def put(self, ns: str, key: str, type_name: str, value: int) -> dict[str, Any]:
        typ, width, signed = NVS_TYPES[type_name]
        data8 = value.to_bytes(width, "little", signed=signed) + b"\xFF" * (8 - width)
        return self._write(self.namespace(ns), typ, 0xFF, key, data8, value=value)

    def put_str(self, ns: str, key: str, s: str) -> dict[str, Any]:
        raw = s.encode() + b"\0"
        return self._write(self.namespace(ns), NVS_SZ, 0xFF, key, struct.pack("<HHI", len(raw), 0xFFFF, self.crc(raw)), raw, value=s)

    def put_blob(self, ns: str, key: str, data: bytes, *, chunk_size: int | None = None, chunk_start: int = 0,
                 page_break: bool = False) -> list[dict[str, Any]]:
        """v1: BLOB 한 항목. v2: BLOB_DATA 조각들(chunk_index = chunk_start + i) + BLOB_IDX(chunk 0xFF)."""
        nsi = self.namespace(ns)
        if self.version == 1:
            return [self._write(nsi, NVS_BLOB, 0xFF, key, struct.pack("<HHI", len(data), 0xFFFF, self.crc(data)), data, value=data)]
        size = chunk_size or len(data) or 1
        chunks = [data[i:i + size] for i in range(0, len(data), size)] or [b""]
        recs = []
        for c, part in enumerate(chunks):
            if page_break and c:
                self.new_page()
            recs.append(self._write(nsi, NVS_BLOB_DATA, chunk_start + c, key, struct.pack("<HHI", len(part), 0xFFFF, self.crc(part)),
                                    part, value=part))
        recs.append(self._write(nsi, NVS_BLOB_IDX, 0xFF, key, struct.pack("<IBBH", len(data), len(chunks), chunk_start, 0xFFFF)))
        return recs

    def erase(self, rec: dict[str, Any]) -> None:
        pg = self.pages[rec["page"]]
        for j in range(rec["entry"], rec["entry"] + rec["span"]):
            pg["states"][j] = ES_ERASED

    def corrupt(self, rec: dict[str, Any], byte: int = 25) -> None:
        """엔트리 바이트 하나를 뒤집는다 (CRC 는 그대로 → CRC 불일치)."""
        pg = self.pages[rec["page"]]
        pg["entries"][32 * rec["entry"] + byte] ^= 0x5A

    def raw_entry(self, page: int, entry: int, raw: bytes, state: int = ES_WRITTEN) -> None:
        """임의 바이트 엔트리 (span 이상 등 구조 오류 시험용)."""
        pg = self.pages[page]
        pg["entries"][32 * entry:32 * entry + 32] = raw
        pg["states"][entry] = state
        pg["next"] = max(pg["next"], entry + 1)

    def make_entry(self, ns: int, typ: int, span: int, chunk: int, key: str, data8: bytes) -> bytes:
        return bytes(self._entry(ns, typ, span, chunk, key, data8))

    # -- 출력 -------------------------------------------------------------------
    def page_bytes(self, i: int) -> bytes:
        pg = self.pages[i]
        state = pg["state"]
        if state is None:
            state = PAGE_ACTIVE if i == len(self.pages) - 1 else PAGE_FULL
        hdr = bytearray(struct.pack("<II", state, pg["seq"]) + bytes([0xFE if self.version == 2 else 0xFF]) + b"\xFF" * 19 + b"\0" * 4)
        struct.pack_into("<I", hdr, 28, self.crc(bytes(hdr[4:28])))
        bitmap = bytearray(b"\xFF" * 32)
        for j, st in enumerate(pg["states"]):
            sh = (j % 4) * 2
            bitmap[j // 4] = (bitmap[j // 4] & ~(3 << sh) & 0xFF) | (st << sh)
        return bytes(hdr) + bytes(bitmap) + bytes(pg["entries"])

    def build(self, *, total_pages: int | None = None, physical_order: list[int] | None = None) -> bytes:
        order = physical_order if physical_order is not None else list(range(len(self.pages)))
        out = b"".join(self.page_bytes(i) for i in order)
        total = total_pages if total_pages is not None else len(order)
        return out + b"\xFF" * (4096 * max(0, total - len(order)))

    def offset_of(self, rec: dict[str, Any], physical_order: list[int] | None = None) -> int:
        order = physical_order if physical_order is not None else list(range(len(self.pages)))
        return 4096 * order.index(rec["page"]) + 64 + 32 * rec["entry"]


def rich_nvs(*, version: int = 2, crc_fn: Callable[[bytes], int] | None = None) -> tuple[NvsImage, dict[str, Any]]:
    """모든 기본 타입·문자열·BLOB·지운 옛 값·Wi-Fi 비밀값을 담은 여러 페이지 NVS (손상 엔트리 없음)."""
    nv = NvsImage(version=version, crc_fn=crc_fn)
    r: dict[str, Any] = {}
    old = nv.put("game", "hiscore", "U32", 1200)
    nv.erase(old)  # 옛 값(지움) — 이력
    r["hiscore_old"] = old
    r["hiscore"] = nv.put("game", "hiscore", "U32", 98765)
    r["lives"] = nv.put("game", "lives", "U8", 3)
    r["level"] = nv.put("game", "level", "I8", -2)
    r["coins"] = nv.put("game", "coins", "U16", 65000)
    r["temp"] = nv.put("game", "temp", "I16", -12345)
    r["unlock"] = nv.put("game", "unlock_bits", "U32", 0x0000_00F5)
    r["delta"] = nv.put("game", "delta", "I32", -2_000_000_000)
    r["playtime"] = nv.put("game", "playtime_ms", "U64", 0x1_2345_6789)
    r["epoch"] = nv.put("game", "epoch", "I64", -(1 << 40))
    r["player"] = nv.put_str("game", "player", "PLAYER-ONE 플레이어")
    r["empty_str"] = nv.put_str("game", "motd", "")
    r["long_str"] = nv.put_str("game", "credits", "C" * 70)  # span 4
    r["save_blob"] = nv.put_blob("game", "slot0", bytes(range(200)) * 2, chunk_size=150, page_break=True)  # v2: 3 조각, 페이지 넘김
    r["ssid"] = nv.put_str("nvs.net80211", "sta.ssid", "toy-net")
    r["pswd"] = nv.put_str("nvs.net80211", "sta.pswd", "not-a-real-pass")
    r["api_token"] = nv.put_str("cloud", "api_token", "tok-synthetic-0000")
    r["mac"] = nv.put_blob("cloud", "mac", SYNTH_MAC)
    nv.new_page()
    r["max_u64"] = nv.put("game", "max_u64", "U64", (1 << 64) - 1)
    return nv, r


def dense_nvs(npages: int, *, secret_keys: bool = False, seq0: int = 0) -> bytes:
    """자원 한도 시험용 빽빽한 NVS: 모든 페이지 active, 비트맵 전부 written, 126 엔트리 모두 CRC 가 맞는 U8 항목.

    페이지 0 의 엔트리 0 은 네임스페이스 정의('app' = 1). 키는 k{page}_{entry} (secret_keys 면 pass{page}_{entry}),
    값은 (entry + seq0) & 0xFF, 페이지 seq 는 seq0 + page. (I2a 리뷰의 gen.dense_nvs 와 같은 모양)
    """
    out = bytearray()
    for p in range(npages):
        hdr = bytearray(struct.pack("<II", PAGE_ACTIVE, seq0 + p) + b"\xFE" + b"\xFF" * 19 + b"\0" * 4)
        struct.pack_into("<I", hdr, 28, nvs_crc32(bytes(hdr[4:28])))
        ents = bytearray()
        for i in range(126):
            if p == 0 and i == 0:
                ns, key, data = 0, b"app", bytes([1]) + b"\xFF" * 7
            else:
                ns, key = 1, (f"pass{p}_{i}" if secret_keys else f"k{p}_{i}").encode()
                data = bytes([(i + seq0) & 0xFF]) + b"\xFF" * 7
            ent = bytearray(struct.pack("<BBBBI16s", ns, 0x01, 1, 0xFF, 0, key) + data)
            struct.pack_into("<I", ent, 4, nvs_crc32(bytes(ent[0:4] + ent[8:32])))
            ents += ent
        out += hdr + b"\xAA" * 32 + ents  # 비트맵 0b10 = written
    return bytes(out)


def corrupted_nvs() -> tuple[NvsImage, dict[str, Any]]:
    """rich_nvs + 엔트리 하나(CRC 불일치)."""
    nv, r = rich_nvs()
    r["bad"] = nv.put("game", "bad_entry", "U16", 7)
    nv.corrupt(r["bad"])
    return nv, r


# ---------------------------------------------------------------------------
# ELF (elf2image 오라클 입력)
# ---------------------------------------------------------------------------

def build_esp_elf(*, machine: int, entry: int, sections: list[tuple[str, int, bytes, int]], e_flags: int = 0) -> bytes:
    """섹션마다 같은 범위의 PT_LOAD 를 갖는 ELF32 LE ET_EXEC. sections: (name, addr, data, sh_flags).

    elf2image 는 기본적으로 섹션(sh_addr≠0, PROGBITS)을 읽으므로 섹션 헤더·.shstrtab 을 꼭 넣는다.
    """
    n = len(sections)
    phoff = 52
    off = phoff + 32 * n
    offs: list[int] = []
    for _name, addr, data, _f in sections:
        off = (off + 3) & ~3
        off += addr & 3
        offs.append(off)
        off += len(data)
    shstr = bytearray(b"\0")
    name_offs: list[int] = []
    for name, *_rest in sections:
        name_offs.append(len(shstr))
        shstr += name.encode() + b"\0"
    shstr_name = len(shstr)
    shstr += b".shstrtab\0"
    shstr_off = off
    off += len(shstr)
    shoff = (off + 3) & ~3
    shnum = n + 2
    out = bytearray(shoff + 40 * shnum)
    out[0:52] = b"\x7fELF" + bytes([1, 1, 1, 0]) + bytes(8) + struct.pack(
        "<HHIIIIIHHHHHH", 2, machine, 1, entry, phoff, shoff, e_flags, 52, 32, n, 40, shnum, n + 1)
    for i, (_name, addr, data, shf) in enumerate(sections):
        pf = 4 | (2 if shf & SHF_WRITE else 0) | (1 if shf & SHF_EXECINSTR else 0)
        struct.pack_into("<8I", out, phoff + 32 * i, 1, offs[i], addr, addr, len(data), len(data), pf, 4)
        out[offs[i]:offs[i] + len(data)] = data
        struct.pack_into("<10I", out, shoff + 40 * (i + 1), name_offs[i], 1, shf, addr, offs[i], len(data), 0, 0, 4, 0)
    out[shstr_off:shstr_off + len(shstr)] = shstr
    struct.pack_into("<10I", out, shoff + 40 * (n + 1), shstr_name, 3, 0, 0, shstr_off, len(shstr), 0, 0, 1, 0)
    return bytes(out)


def _pattern(seed: int, n: int) -> bytes:
    return bytes((seed * 31 + i * 7 + (i >> 8)) & 0xFF for i in range(n))


def esp_elf_sections(chip: str) -> tuple[int, int, int, list[tuple[str, int, bytes, int]]]:
    """(machine, e_flags, entry, sections) — esptool 메모리 맵의 올바른 주소에 둔 S3(Xtensa)/C3(RISC-V) 합성 ELF.

    .flash.appdesc 는 0x3C000020 (이미지 오프셋 0x20) 에 두고 app_elf_sha256(+0x90) 은 0 으로 남긴다 → elf2image 가
    ELF 의 SHA256 을 이미지 오프셋 0xB0 에 써 넣는다. 플래시 섹션은 서로 다른 64 KB 페이지에 둔다.
    """
    desc = build_app_desc(project_name=f"elf-{chip}", version="2.0.0")
    ro = _pattern(1, 0x1E0)
    if chip == "s3":
        text = b"\x36\x41\x00\x1d\xf0\x00\x00\x00" * 0x40  # entry a1,32 ; retw.n
        return EM_XTENSA, 0x300, 0x40378000, [
            (".flash.appdesc", 0x3C000020, desc, SHF_ALLOC),
            (".flash.rodata", 0x3C000120, ro, SHF_ALLOC),
            (".flash.text", 0x42010020, _pattern(2, 0x400), SHF_ALLOC | SHF_EXECINSTR),
            (".dram0.data", 0x3FC90000, _pattern(3, 0x12000), SHF_ALLOC | SHF_WRITE),  # 64 KB 채움보다 커서 elf2image 가 둘로 나눈다
            (".iram0.text", 0x40378000, text + _pattern(4, 0x6000), SHF_ALLOC | SHF_EXECINSTR),
            (".rtc.text", 0x600FE000, _pattern(5, 0x40), SHF_ALLOC | SHF_EXECINSTR),
            (".rtc.data", 0x50000000, _pattern(6, 0x20), SHF_ALLOC | SHF_WRITE),
        ]
    if chip == "c3":
        text = struct.pack("<II", 0x00150513, 0x00008067) * 0x20  # addi a0,a0,1 ; ret
        return EM_RISCV, 0x1, 0x40380000, [
            (".flash.appdesc", 0x3C000020, desc, SHF_ALLOC),
            (".flash.rodata", 0x3C000120, ro, SHF_ALLOC),
            (".flash.text", 0x42010020, text + _pattern(7, 0x300), SHF_ALLOC | SHF_EXECINSTR),
            (".dram0.data", 0x3FC90000, _pattern(8, 0x3000), SHF_ALLOC | SHF_WRITE),
            (".iram0.text", 0x40380000, text + _pattern(9, 0x5000), SHF_ALLOC | SHF_EXECINSTR),
            (".rtc.text", 0x50000000, _pattern(10, 0x40), SHF_ALLOC | SHF_EXECINSTR | SHF_WRITE),
        ]
    raise ValueError(chip)


def esp_elf(chip: str) -> bytes:
    machine, eflags, entry, sections = esp_elf_sections(chip)
    return build_esp_elf(machine=machine, entry=entry, sections=sections, e_flags=eflags)


# ---------------------------------------------------------------------------
# 조립된 플래시
# ---------------------------------------------------------------------------

BOOTLOADER_OFFSET = {CHIP_ESP32: 0x1000, CHIP_S2: 0x1000, CHIP_S3: 0x0, CHIP_C3: 0x0}


def build_esp_flash(*, chip_id: int = CHIP_S3, bootloader: bytes | None = None, nvs: bytes | None = None, app: bytes | None = None,
                    flash_size: int = 0x40000, table_offset: int = 0x8000,
                    partitions: list[tuple] | None = None) -> tuple[bytes, dict[str, Any]]:
    """부트로더(S3·C3 는 0x0) + 파티션 테이블(0x8000) + NVS(0x9000, 6 페이지) + phy_init(0xF000) + 앱(0x10000)."""
    parts = partitions if partitions is not None else DEFAULT_PARTITIONS
    img = bytearray(b"\xFF" * flash_size)
    bl = bootloader if bootloader is not None else s3_bootloader_image()
    bl_off = BOOTLOADER_OFFSET.get(chip_id, 0)
    img[bl_off:bl_off + len(bl)] = bl
    table = build_partition_table(parts)
    img[table_offset:table_offset + len(table)] = table
    layout = {"bootloader": bl_off, "table": table_offset, "partitions": {p[0]: (p[3], p[4]) for p in parts}}
    if nvs is not None and "nvs" in layout["partitions"]:
        o, sz = layout["partitions"]["nvs"]
        assert len(nvs) <= sz
        img[o:o + len(nvs)] = nvs
    if app is not None and "factory" in layout["partitions"]:
        o, sz = layout["partitions"]["factory"]
        assert len(app) <= sz
        img[o:o + len(app)] = app
    return bytes(img), layout
