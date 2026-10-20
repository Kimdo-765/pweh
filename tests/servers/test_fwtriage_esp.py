"""fwtriage espfmt(ESP32 계열 형식) 테스트: 칩 영역, 파티션 테이블, 앱/부트로더 이미지, ELF 변환, NVS.

- 단위 테스트는 tests/fwtriage/esp_builders.py 의 합성 이미지만 쓴다 (기기·덤프 없음, 식별자는 합성 값).
- external 오라클:
  1. esptool v5 image-info — 합성 앱/부트로더 이미지의 체크섬·SHA256·세그먼트·앱 설명을 parse_app_image 와 대조.
  2. esptool v5 elf2image — 손으로 만든 S3(Xtensa)/C3(RISC-V) ELF 를 이미지로 만들고, parse_app_image → image_to_elf
     로 되돌린 ELF 의 주소별 바이트가 원래 ELF 의 PT_LOAD 내용과 같은지 (elf2image 는 세그먼트를 합치고 채움
     세그먼트를 넣으므로 개수가 아니라 주소→바이트를 비교한다).
  3. readelf — 생성 ELF 를 표준 도구가 읽는지.
- REA(external + slow): image_to_elf 결과를 REA open_binary(ghidra)에 넣어 본 결과를 고정한다.
- 파티션 테이블과 NVS 에는 로컬 오라클이 없다 (ESP-IDF·gen_esp32part·nvs_partition_gen·nvs_tool 미설치, 다운로드 금지).
  이 둘은 ESP-IDF 형식 지식으로 만든 합성 이미지로만 검사하므로 실제 덤프로 다시 확인해야 한다
  (특히 NVS CRC 규약 — parse_nvs 의 crc_summary 가 그 확인 수단이다).
"""

from __future__ import annotations

import hashlib
import os
import random
import re
import shutil
import struct
import subprocess
import sys
import threading
import time
import tracemalloc
import zlib
from pathlib import Path
from typing import Any

import pytest

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "mcp-servers" / "fwtriage-mcp"))

from fwtriage.builders import find_tool  # noqa: E402
from fwtriage.esp_builders import (  # noqa: E402
    CHIP_C3,
    CHIP_S3,
    DEFAULT_PARTITIONS,
    PAGE_CORRUPT,
    PAGE_FREEING,
    SYNTH_MAC,
    NvsImage,
    build_app_desc,
    build_app_image,
    build_esp_flash,
    build_partition_table,
    c3_app_image,
    corrupted_nvs,
    dense_nvs,
    esp_elf,
    esp_elf_sections,
    rich_nvs,
    s3_app_image,
    s3_bootloader_image,
    xor_checksum,
)
from fwtriage_mcp import elfinfo, espfmt  # noqa: E402
from fwtriage_mcp.common import Cancelled, Ctl  # noqa: E402
from fwtriage_mcp.espfmt import EspFormatError, NvsError  # noqa: E402

PF_X, PF_W, PF_R = 1, 2, 4


# ---------------------------------------------------------------------------
# 도우미
# ---------------------------------------------------------------------------

def _elf_loads(elf: bytes) -> list[dict[str, Any]]:
    """elfinfo(저장소 ELF 파서)로 PT_LOAD 목록: vaddr, 데이터, 플래그."""
    e = elfinfo._Elf(elf, len(elf))
    return [{"vaddr": p["vaddr"], "data": elf[p["offset"]:p["offset"] + p["filesz"]], "flags": p["flags"]}
            for p in e.phdrs() if p["type"] == elfinfo.PT_LOAD]


def _read_addr(loads: list[dict[str, Any]], addr: int, n: int) -> bytes:
    """PT_LOAD 들에서 [addr, addr+n) 을 이어 읽는다 (빈틈이 있으면 실패)."""
    out = bytearray()
    cur, end = addr, addr + n
    while cur < end:
        seg = next((x for x in loads if x["vaddr"] <= cur < x["vaddr"] + len(x["data"])), None)
        assert seg is not None, f"0x{cur:x} 가 어느 PT_LOAD 에도 없음"
        take = min(end, seg["vaddr"] + len(seg["data"])) - cur
        k = cur - seg["vaddr"]
        out += seg["data"][k:k + take]
        cur += take
    return bytes(out)


def _seg_bytes(img: bytes, s: dict[str, Any]) -> bytes:
    return img[s["file_offset"]:s["file_offset"] + s["size"]]


# ---------------------------------------------------------------------------
# 칩 정보 / 주소 영역
# ---------------------------------------------------------------------------

ALL_CHIPS = {0: ("ESP32", "xtensa"), 2: ("ESP32-S2", "xtensa"), 9: ("ESP32-S3", "xtensa"), 5: ("ESP32-C3", "riscv"),
             12: ("ESP32-C2", "riscv"), 13: ("ESP32-C6", "riscv"), 16: ("ESP32-H2", "riscv"), 18: ("ESP32-P4", "riscv"),
             23: ("ESP32-C5", "riscv"), 20: ("ESP32-C61", "riscv")}


def test_chip_info_known_and_unknown():
    for cid, (name, arch) in ALL_CHIPS.items():
        ci = espfmt.chip_info(cid)
        assert (ci["chip_id"], ci["name"], ci["arch"]) == (cid, name, arch)
        assert ci["e_machine"] == (94 if arch == "xtensa" else 243)
        regs = ci["regions"]
        assert regs and all(set(r) == {"name", "start", "end", "kind", "flash", "exec", "write"} for r in regs)
        assert all(r["start"] < r["end"] for r in regs)
        assert all(a["end"] <= b["start"] for a, b in zip(regs, regs[1:])), f"{name}: 영역이 정렬·비겹침이 아님"
        kinds = {r["kind"] for r in regs}
        assert "padding" in kinds and kinds & {"flash-text", "flash"}
        for r in regs:
            assert r["flash"] == r["kind"].startswith("flash")
    assert [espfmt.chip_info(c)["e_flags"] for c in (0, 2, 9, 5, 12, 13, 16, 18, 20, 23)] == [0x300] * 3 + [0x1] * 4 + [0x3, 0x1, 0x1]
    assert espfmt.chip_info(0x1C) == {"chip_id": 0x1C, "name": "unknown(0x1c)", "arch": "unknown", "e_machine": 0, "e_flags": 0,
                                      "regions": []}
    # 반환값은 사본 (호출자가 바꿔도 다음 호출에 영향 없음)
    espfmt.chip_info(9)["regions"][0]["name"] = "X"
    assert espfmt.chip_info(9)["regions"][0]["name"] == "PADDING"


@pytest.mark.parametrize("chip,addr,name,kind", [
    (9, 0x3C000020, "DROM", "flash-rodata"),
    (9, 0x3D800000, "DROM", "flash-rodata"),  # MEMORY_MAP 의 EXTRAM_DATA 창이지만 DROM_MAP 안 (esptool is_flash_addr)
    (9, 0x42000020, "IROM", "flash-text"),
    (9, 0x43FFFFFF, "IROM", "flash-text"),
    (9, 0x3FC90000, "DRAM", "dram"),
    (9, 0x40378000, "IRAM", "iram"),
    (9, 0x600FE000, "RTC_IRAM/RTC_DRAM", "rtc-text"),
    (9, 0x50000000, "RTC_DATA", "rtc-data"),
    (9, 0x40000100, "IROM_MASK", "rom-text"),
    (9, 0x00000000, "PADDING", "padding"),
    (0, 0x400D0020, "IROM", "flash-text"),
    (0, 0x40000000, "IROM_MASK", "rom-text"),  # esptool 은 ESP32 마스크 ROM 도 IROM 이라 부르지만 여기선 구분
    (0, 0x40078000, "CACHE_APP", "iram"),
    (0, 0x3FFB0000, "DRAM", "dram"),
    (0, 0x3F400020, "DROM", "flash-rodata"),
    (0, 0x400C0000, "RTC_IRAM", "rtc-text"),
    (2, 0x40080020, "IROM", "flash-text"),
    (2, 0x3F000020, "DROM", "flash-rodata"),
    (5, 0x3C000020, "DROM", "flash-rodata"),
    (5, 0x42000020, "IROM", "flash-text"),
    (5, 0x4037C000, "IRAM", "iram"),
    (5, 0x50000000, "RTC_IRAM/RTC_DRAM", "rtc-text"),
    (12, 0x42000020, "IROM", "flash-text"),
    (13, 0x42000020, "IROM/DROM", "flash"),
    (13, 0x40800000, "IRAM/DRAM", "sram"),
    (16, 0x42800020, "IROM/DROM", "flash"),
    (18, 0x40000020, "IROM/DROM", "flash"),
    (18, 0x4FF00000, "IRAM/DRAM", "sram"),
    (20, 0x43800000, "IROM/DROM", "flash"),
    (23, 0x42000020, "IROM/DROM", "flash"),
])
def test_classify_address(chip, addr, name, kind):
    r = espfmt.classify_address(chip, addr)
    assert r is not None and (r["name"], r["kind"]) == (name, kind)
    assert r["start"] <= addr < r["end"]


def test_classify_address_misses():
    assert espfmt.classify_address(9, 0x12345678) is None
    assert espfmt.classify_address(9, 0x44000000) is None  # 끝 주소는 미포함
    assert espfmt.classify_address(0x1C, 0x42000020) is None
    assert espfmt.classify_address(9, "0x42000020") is None  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# 파티션 테이블 (로컬 오라클 없음)
# ---------------------------------------------------------------------------

def _flash(**kw: Any) -> tuple[bytes, dict[str, Any]]:
    nv, _r = rich_nvs()
    return build_esp_flash(nvs=nv.build(total_pages=6), app=s3_app_image(), **kw)


def test_partition_table_default_offset_md5_ok():
    img, _layout = _flash()
    t = espfmt.parse_partition_table(img)
    assert t["found"] and t["offset"] == 0x8000 and t["errors"] == [] and t["warnings"] == []
    assert t["md5"]["present"] and t["md5"]["ok"] and t["md5"]["stored"] == t["md5"]["computed"]
    assert t["md5"]["computed"] == hashlib.md5(img[0x8000:0x8000 + 3 * 32]).hexdigest()
    assert [e["label"] for e in t["entries"]] == ["nvs", "phy_init", "factory"]
    nvs = espfmt.find_partition(t, "nvs")
    assert nvs is t["entries"][0]
    assert (nvs["index"], nvs["type"], nvs["type_name"], nvs["subtype"], nvs["subtype_name"]) == (0, 1, "data", 2, "nvs")
    assert (nvs["offset"], nvs["size"], nvs["end"], nvs["flags"]) == (0x9000, 0x6000, 0xF000, 0)
    assert nvs["write_class"] == "nvs" and nvs["write_blockers"] == [] and not nvs["encrypted"] and not nvs["readonly"] and nvs["notes"]
    assert espfmt.find_partition(t, "factory")["write_class"] == "not-a-save"
    assert espfmt.find_partition(t, "phy_init")["write_class"] == "not-a-save"
    assert espfmt.find_partition(t, "nope") is None and espfmt.find_partition({}, "nvs") is None
    assert t["nvs_keys_present"] is False
    assert espfmt.parse_partition_table(img, 0x8000)["entries"] == t["entries"]
    assert espfmt.parse_partition_table(bytearray(img))["entries"] == t["entries"]
    assert espfmt.parse_partition_table(memoryview(img))["entries"] == t["entries"]


def test_partition_md5_bad_and_absent():
    tab = bytearray(build_partition_table(DEFAULT_PARTITIONS))
    tab[0x20 + 6] ^= 0x01  # 두 번째 엔트리 오프셋(바이트 4..8) 0xF000 → 0x1F000 (정렬은 유지)
    t = espfmt.parse_partition_table(bytes(tab))
    assert t["found"] and t["offset"] == 0 and t["md5"]["present"] and t["md5"]["ok"] is False
    assert t["md5"]["stored"] != t["md5"]["computed"] and any("MD5" in e for e in t["errors"])
    assert espfmt.find_partition(t, "phy_init")["offset"] == 0x1F000
    t2 = espfmt.parse_partition_table(build_partition_table(DEFAULT_PARTITIONS, md5=False))
    assert t2["found"] and t2["md5"] == {"present": False, "ok": None, "stored": None, "computed": None}
    assert t2["errors"] == [] and len(t2["entries"]) == 3


def test_partition_write_classes():
    parts = [
        ("nvs", 1, 0x02, 0x9000, 0x6000), ("otadata", 1, 0x00, 0xF000, 0x2000), ("phy", 1, 0x01, 0x11000, 0x1000),
        ("coredump", 1, 0x03, 0x12000, 0x1000), ("efuse", 1, 0x05, 0x13000, 0x1000), ("undef", 1, 0x06, 0x14000, 0x1000),
        ("custom_d", 1, 0x40, 0x15000, 0x1000), ("fat", 1, 0x81, 0x16000, 0x1000), ("spiffs", 1, 0x82, 0x17000, 0x1000),
        ("littlefs", 1, 0x83, 0x18000, 0x1000), ("httpd", 1, 0x80, 0x19000, 0x1000), ("weird_d", 1, 0x07, 0x1A000, 0x1000),
        ("ctype", 0x40, 0x00, 0x1B000, 0x1000), ("ctype2", 0xFE, 0x12, 0x1C000, 0x1000), ("factory", 0, 0x00, 0x20000, 0x10000),
        ("ota_0", 0, 0x10, 0x30000, 0x10000), ("ota_15", 0, 0x1F, 0x40000, 0x10000), ("test", 0, 0x20, 0x50000, 0x10000),
        ("bootldr", 2, 0x00, 0x60000, 0x1000), ("ptable", 3, 0x00, 0x61000, 0x1000), ("unk_type", 0x10, 0x00, 0x62000, 0x1000),
    ]
    t = espfmt.parse_partition_table(build_partition_table(parts))
    assert t["found"] and t["errors"] == [] and t["warnings"] == []
    got = {e["label"]: (e["type_name"], e["subtype_name"], e["write_class"]) for e in t["entries"]}
    assert got == {
        "nvs": ("data", "nvs", "nvs"),
        "otadata": ("data", "ota", "not-a-save"),
        "phy": ("data", "phy", "not-a-save"),
        "coredump": ("data", "coredump", "not-a-save"),
        "efuse": ("data", "efuse", "not-a-save"),
        "undef": ("data", "undefined", "raw-user-data"),
        "custom_d": ("data", "custom(0x40)", "raw-user-data"),
        "fat": ("data", "fat", "filesystem-analysis-only"),
        "spiffs": ("data", "spiffs", "filesystem-analysis-only"),
        "littlefs": ("data", "littlefs", "filesystem-analysis-only"),
        "httpd": ("data", "esphttpd", "filesystem-analysis-only"),
        "weird_d": ("data", "unknown(0x07)", "not-a-save"),
        "ctype": ("custom(0x40)", "custom(0x00)", "raw-user-data"),
        "ctype2": ("custom(0xfe)", "custom(0x12)", "raw-user-data"),
        "factory": ("app", "factory", "not-a-save"),
        "ota_0": ("app", "ota_0", "not-a-save"),
        "ota_15": ("app", "ota_15", "not-a-save"),
        "test": ("app", "test", "not-a-save"),
        "bootldr": ("bootloader", "primary", "not-a-save"),
        "ptable": ("partition_table", "primary", "not-a-save"),
        "unk_type": ("unknown(0x10)", "unknown(0x00)", "not-a-save"),
    }
    assert all(e["notes"] and e["write_blockers"] == [] for e in t["entries"])
    assert "파일 시스템" in espfmt.find_partition(t, "spiffs")["notes"][0]


def test_partition_nvs_blockers():
    parts = [("nvs", 1, 2, 0x9000, 0x6000), ("nvs_keys", 1, 4, 0xF000, 0x1000), ("enc_nvs", 1, 2, 0x10000, 0x3000, 0x1),
             ("ro_nvs", 1, 2, 0x13000, 0x3000, 0x2), ("enc_raw", 1, 0x40, 0x16000, 0x1000, 0x1), ("factory", 0, 0, 0x20000, 0x10000, 0x1)]
    t = espfmt.parse_partition_table(build_partition_table(parts))
    assert t["nvs_keys_present"] is True
    find = lambda lbl: espfmt.find_partition(t, lbl)  # noqa: E731
    assert len(find("nvs")["write_blockers"]) == 1 and "nvs_keys" in find("nvs")["write_blockers"][0]
    enc = find("enc_nvs")
    assert enc["encrypted"] and len(enc["write_blockers"]) == 2 and any("encrypted" in b for b in enc["write_blockers"])
    ro = find("ro_nvs")
    assert ro["readonly"] and not ro["encrypted"] and len(ro["write_blockers"]) == 1 and any("readonly" in n for n in ro["notes"])
    assert find("enc_raw")["write_blockers"] and "encrypted" in find("enc_raw")["write_blockers"][0]
    assert find("factory")["encrypted"] and find("factory")["write_blockers"] == []
    assert (find("nvs_keys")["subtype_name"], find("nvs_keys")["write_class"]) == ("nvs_keys", "not-a-save")
    # nvs_keys 가 없으면 encrypted 만 막는다
    t2 = espfmt.parse_partition_table(build_partition_table([("nvs", 1, 2, 0x9000, 0x6000, 0x1)]))
    assert t2["nvs_keys_present"] is False and len(t2["entries"][0]["write_blockers"]) == 1


def test_partition_warnings_overlap_misaligned_range_duplicates():
    parts = [("nvs", 1, 2, 0x9000, 0x6000), ("nvs", 1, 0x81, 0xE000, 0x2000), ("app", 0, 0, 0x18000, 0x10000),
             ("data_mis", 1, 0x06, 0x30800, 0x1000), ("huge", 1, 0x40, 0x100000, 0x400000), ("in_table", 1, 0x06, 0x8000, 0x1000)]
    flash, _ = build_esp_flash(partitions=parts)
    t = espfmt.parse_partition_table(flash)
    assert t["found"] and t["offset"] == 0x8000 and t["errors"] == []
    w = t["warnings"]
    assert "중복 레이블 'nvs' (엔트리 0, 1)" in w
    assert "파티션 겹침: 'nvs'(0x9000–0xf000) ↔ 'nvs'(0xe000–0x10000)" in w
    assert any(x.startswith("'app': 오프셋 0x18000 가 0x10000 정렬이 아님") for x in w)
    assert "'data_mis': 오프셋 0x30800 가 0x1000 정렬이 아님" in w
    assert any(x.startswith("'huge': 0x100000+0x400000 가 데이터 끝(0x40000)을 넘음") for x in w)
    assert any(x.startswith("'in_table': 파티션 테이블 섹터") for x in w)
    # 독립 테이블 이미지(오프셋 0)에서는 범위 검사를 하지 않는다
    t2 = espfmt.parse_partition_table(build_partition_table(parts))
    assert t2["offset"] == 0 and not any("데이터 끝" in x or "테이블 섹터" in x for x in t2["warnings"])


def test_partition_non_default_offset_and_standalone():
    flash, _ = build_esp_flash(table_offset=0xA000, partitions=[("nvs", 1, 2, 0xB000, 0x5000), ("factory", 0, 0, 0x10000, 0x30000)])
    t = espfmt.parse_partition_table(flash)
    assert t["found"] and t["offset"] == 0xA000 and [e["label"] for e in t["entries"]] == ["nvs", "factory"]
    assert any("0xa000" in x for x in t["warnings"])
    miss = espfmt.parse_partition_table(flash, 0x8000)
    assert miss["found"] is False and miss["errors"] and miss["entries"] == []
    assert espfmt.parse_partition_table(flash, 0xA000)["entries"] == t["entries"]
    tab = build_partition_table(DEFAULT_PARTITIONS)
    t3 = espfmt.parse_partition_table(tab)
    assert t3["found"] and t3["offset"] == 0 and t3["warnings"] == []


def test_partition_garbage_and_truncated_inputs():
    rnd = random.Random(1234)
    for data in (b"", b"\xAA", b"\xAA\x50", b"\xFF" * 0x10000, bytes(0x10000), rnd.randbytes(0x20000)):
        t = espfmt.parse_partition_table(data)
        assert t["found"] is False and t["entries"] == [] and t["errors"]
    # AA50 이지만 레이블이 쓰레기면 테이블로 보지 않는다
    bad_label = b"\xAA\x50\x01\x02" + struct.pack("<II", 0x9000, 0x6000) + b"\x01\x02junk\xfe" + b"\xff" * 9 + bytes(4)
    assert espfmt.parse_partition_table(bad_label + b"\xFF" * 32)["found"] is False
    # 끝 표시 없이 잘린 테이블
    rows = b"".join(build_partition_table([p], md5=False, pad_to=0) for p in DEFAULT_PARTITIONS)
    t = espfmt.parse_partition_table(rows)
    assert t["found"] and len(t["entries"]) == 3 and any("끝 표시" in x for x in t["warnings"])
    # 중간의 알 수 없는 엔트리
    t = espfmt.parse_partition_table(rows[:32] + b"\x12\x34" + bytes(30) + b"\xFF" * 64)
    assert len(t["entries"]) == 1 and any("알 수 없는 엔트리" in e for e in t["errors"])
    assert espfmt.parse_partition_table(rows, offset=-5)["found"] is False
    # 오프셋을 지정하면 레이블이 ASCII 가 아니어도 읽는다 (자동 탐색만 레이블을 검사)
    odd = build_partition_table([("세이브", 1, 2, 0x9000, 0x6000)])
    assert espfmt.parse_partition_table(odd)["found"] is False
    t = espfmt.parse_partition_table(odd, 0)
    assert t["found"] and t["entries"][0]["label"] == "세이브" and any("출력 불가" in w for w in t["warnings"])
    assert espfmt.parse_partition_table(rows, offset=0x10_0000)["found"] is False


STOCK_LAYOUT = [("nvs", 1, 2, 0x9000, 0x6000), ("phy_init", 1, 1, 0xF000, 0x1000), ("factory", 0, 0, 0x10000, 0x100000)]  # ESP-IDF 기본 single factory


def test_partition_stock_layout_4mib_no_false_truncation():
    flash, _ = build_esp_flash(app=s3_app_image(), flash_size=0x400000, partitions=STOCK_LAYOUT)
    assert espfmt.parse_partition_table(flash)["warnings"] == []
    head = flash[:0x101000]  # 탐색용으로 파일 앞부분만 읽은 경우
    stale = espfmt.parse_partition_table(head)
    assert any("'factory'" in w and "데이터 끝(0x101000)" in w for w in stale["warnings"])  # data_len 없이는 앞부분 길이로 오해
    t = espfmt.parse_partition_table(head, data_len=len(flash))
    assert t["found"] and t["offset"] == 0x8000 and t["warnings"] == [] and t["errors"] == []
    assert t["entries"] == espfmt.parse_partition_table(flash)["entries"]
    t2 = espfmt.parse_partition_table(head, data_len=0x80000)  # 진짜로 잘린 덤프는 여전히 경고
    assert [w for w in t2["warnings"] if "데이터 끝" in w] == [
        "'factory': 0x10000+0x100000 가 데이터 끝(0x80000)을 넘음 (덤프가 잘렸거나 플래시 크기 불일치)"]


def test_partition_explicit_offset_with_base_offset():
    flash, _ = build_esp_flash(app=s3_app_image(), flash_size=0x400000, partitions=STOCK_LAYOUT)
    full = espfmt.parse_partition_table(flash)
    window = flash[0x8000:0x8000 + 0xC00 + 32]  # 서버가 큰 파일에서 테이블 근처만 읽는 경우
    t = espfmt.parse_partition_table(window, 0x8000, base_offset=0x8000, data_len=len(flash))
    assert t["found"] and t["offset"] == 0x8000 and t["entries"] == full["entries"] and t["md5"]["ok"]
    assert t["warnings"] == [] and t["errors"] == []
    nolen = espfmt.parse_partition_table(window, 0x8000, base_offset=0x8000)  # 크기를 모르면 끝 넘음 검사는 생략
    assert nolen["entries"] == full["entries"] and nolen["warnings"] == []
    auto = espfmt.parse_partition_table(window, base_offset=0x8000, data_len=len(flash))
    assert auto["found"] and auto["offset"] == 0x8000
    before = espfmt.parse_partition_table(window, 0x7000, base_offset=0x8000)
    assert before["found"] is False and any("base_offset 앞" in e for e in before["errors"])
    assert espfmt.parse_partition_table(window, 0x8010, base_offset=0x8000)["found"] is False  # 엔트리 중간 (매직 아님)
    assert espfmt.parse_partition_table(window, 0x8020, base_offset=0x8000)["offset"] == 0x8020  # 지정 오프셋은 매직만 본다
    # 기본이 아닌 위치(0xA000), 창이 그 앞에서 시작 (4K 경계 / 경계 아님)
    flash2, _ = build_esp_flash(table_offset=0xA000, flash_size=0x400000,
                                partitions=[("nvs", 1, 2, 0xB000, 0x5000), ("factory", 0, 0, 0x10000, 0x100000)])
    for base in (0x9000, 0x9800):
        t3 = espfmt.parse_partition_table(flash2[base:0xC000], base_offset=base, data_len=len(flash2))
        assert t3["found"] and t3["offset"] == 0xA000 and [e["label"] for e in t3["entries"]] == ["nvs", "factory"]
        assert t3["warnings"] == ["파티션 테이블이 기본 위치(0x8000)가 아닌 0xa000 에 있음 (CONFIG_PARTITION_TABLE_OFFSET 변경)"]
    bad_md5 = bytearray(window)
    bad_md5[0x20 + 6] ^= 0x01
    t4 = espfmt.parse_partition_table(bytes(bad_md5), 0x8000, base_offset=0x8000, data_len=len(flash))
    assert t4["md5"]["ok"] is False  # MD5 는 data 안 위치 기준으로 계산
    for bad in ({"base_offset": -1}, {"base_offset": "0x8000"}, {"data_len": -5}, {"data_len": True}):
        with pytest.raises(ValueError):
            espfmt.parse_partition_table(window, **bad)


# ---------------------------------------------------------------------------
# 앱 / 부트로더 이미지
# ---------------------------------------------------------------------------

def test_app_image_s3_fields_and_integrity():
    img = s3_app_image()
    p = espfmt.parse_app_image(img)
    assert p["ok"] and p["errors"] == [] and p["warnings"] == []
    assert (p["chip_id"], p["chip"], p["arch"], p["e_machine"], p["entry"], p["offset"]) == (9, "ESP32-S3", "xtensa", 94, 0x40378A10, 0)
    assert (p["spi_mode"], p["spi_mode_name"], p["spi_speed"], p["spi_speed_name"], p["spi_size"], p["spi_size_name"]) == \
        (2, "dio", 0xF, "80m", 2, "4MB")
    assert p["hash_appended"] is True and (p["min_chip_rev_full"], p["max_chip_rev_full"], p["wp_pin"]) == (0, 99, 0xEE)
    assert p["segment_count"] == 5 and p["segments_complete"] is True
    assert [(s["region"], s["kind"]) for s in p["segments"]] == [
        ("DROM", "flash-rodata"), ("IROM", "flash-text"), ("DRAM", "dram"), ("IRAM", "iram"), ("RTC_IRAM/RTC_DRAM", "rtc-text")]
    s0 = p["segments"][0]
    assert (s0["header_offset"], s0["file_offset"]) == (24, 32) and img[32:36] == struct.pack("<I", 0xABCD5432)
    for a, b in zip(p["segments"], p["segments"][1:]):
        assert b["header_offset"] == a["file_offset"] + a["size"]
    want_ck = xor_checksum([(s["load_addr"], _seg_bytes(img, s)) for s in p["segments"]])
    assert p["checksum"] == {"stored": want_ck, "computed": want_ck, "ok": True}
    assert p["sha256"] == {"present": True, "stored": hashlib.sha256(img[:-32]).hexdigest(),
                           "computed": hashlib.sha256(img[:-32]).hexdigest(), "ok": True}
    assert p["image_size"] == len(img) and (len(img) - 33) % 16 == 15
    assert p["app_desc"] == {"magic_ok": True, "secure_version": 0, "version": "1.4.2", "project_name": "toy-arcade",
                             "time": "12:34:56", "date": "Oct 20 2026", "idf_ver": "v5.3.1", "app_elf_sha256": "00" * 32,
                             "min_efuse_blk_rev_full": 0, "max_efuse_blk_rev_full": 99, "mmu_page_size": None, "segment": 0}
    assert p["image_type"] == "app" and p["bootloader_desc"] is None


def test_app_image_corruptions():
    img = s3_app_image()
    p = espfmt.parse_app_image(img)
    seg = p["segments"][1]
    b1 = bytearray(img)
    b1[seg["file_offset"] + 3] ^= 0xFF  # 세그먼트 데이터
    q = espfmt.parse_app_image(bytes(b1))
    assert not q["ok"] and q["checksum"]["ok"] is False and q["sha256"]["ok"] is False
    assert q["checksum"]["computed"] == p["checksum"]["computed"] ^ 0xFF and q["checksum"]["stored"] == p["checksum"]["stored"]
    assert any("체크섬" in e for e in q["errors"]) and any("SHA256" in e for e in q["errors"])
    b2 = bytearray(img)
    b2[len(img) - 33] ^= 1  # 체크섬 바이트 — SHA256 범위에 체크섬 바이트가 들어간다
    q = espfmt.parse_app_image(bytes(b2))
    assert q["checksum"]["ok"] is False and q["sha256"]["ok"] is False
    b3 = bytearray(img)
    b3[-1] ^= 1  # 덧붙은 SHA256 만
    q = espfmt.parse_app_image(bytes(b3))
    assert q["checksum"]["ok"] is True and q["sha256"]["ok"] is False and not q["ok"]
    b4 = bytearray(img)
    b4[5] ^= 0x10  # 헤더(엔트리) — 체크섬 밖, SHA256 안
    q = espfmt.parse_app_image(bytes(b4))
    assert q["checksum"]["ok"] is True and q["sha256"]["ok"] is False and q["entry"] == 0x40378A10 ^ 0x1000


def test_app_image_c3_without_hash():
    img = c3_app_image(hash_appended=False)
    p = espfmt.parse_app_image(img)
    assert p["ok"] and p["warnings"] == [] and p["hash_appended"] is False
    assert p["sha256"] == {"present": False, "stored": None, "computed": None, "ok": None}
    assert p["image_size"] == len(img) and len(img) % 16 == 0
    assert (p["chip"], p["arch"], p["e_machine"]) == ("ESP32-C3", "riscv", 243)
    assert [s["kind"] for s in p["segments"]] == ["flash-rodata", "flash-text", "dram", "iram", "rtc-text"]
    assert p["app_desc"]["project_name"] == "toy-c3" and p["image_type"] == "app"


def test_bootloader_image():
    p = espfmt.parse_app_image(s3_bootloader_image())
    assert p["ok"] and p["warnings"] == [] and p["image_type"] == "bootloader" and p["app_desc"] is None
    assert p["bootloader_desc"] == {"magic_ok": True, "version": 1, "idf_ver": "v5.3.1", "date_time": "Oct 20 2026 12:34:56",
                                    "segment": 0}
    assert [s["kind"] for s in p["segments"]] == ["dram", "iram", "iram"]
    assert p["sha256"]["ok"] and p["checksum"]["ok"]


def test_app_desc_magic_missing_and_unified_flash():
    img = build_app_image(chip_id=CHIP_S3, entry=0x40378000,
                          segments=[(0x3C000020, b"\0" * 0x100), (0x40378000, b"\x36\x41\x00\x1d\xf0\0\0\0")])
    p = espfmt.parse_app_image(img)
    assert p["ok"] and p["app_desc"]["magic_ok"] is False and p["app_desc"]["version"] is None and p["image_type"] == "unknown"
    assert any("0xABCD5432" in w for w in p["warnings"])
    # C6 통합 플래시 창: appdesc 로 시작하는 세그먼트만 rodata
    c6 = build_app_image(chip_id=13, entry=0x40800000, segments=[
        (0x42010020, build_app_desc(project_name="c6") + b"ro" * 8), (0x42000020, b"\x13\x05\x15\x00" * 8),
        (0x40800000, b"\x67\x80\x00\x00" * 4)])
    q = espfmt.parse_app_image(c6)
    assert q["ok"] and [(s["region"], s["kind"]) for s in q["segments"]] == [
        ("IROM/DROM", "flash-rodata"), ("IROM/DROM", "flash-text"), ("IRAM/DRAM", "sram")]
    assert q["app_desc"]["project_name"] == "c6"
    names = elfinfo.parse_elf(espfmt.image_to_elf(c6, q), 10 ** 6)["sections"]["names"]
    assert names == [".flash.rodata", ".flash.text", ".iram0.text", ".shstrtab"]


def test_app_image_truncated_and_garbage_bounded():
    img = s3_app_image()
    for cut in (0, 1, 8, 23, 24, 30, 32, 100, 400, len(img) - 40, len(img) - 33):
        p = espfmt.parse_app_image(img[:cut])
        assert p["ok"] is False and p["errors"], cut
    p = espfmt.parse_app_image(img[:len(img) - 10])  # SHA256 만 잘림
    assert p["checksum"]["ok"] is True and p["sha256"]["ok"] is None and any("SHA256" in e for e in p["errors"])
    p = espfmt.parse_app_image(img[:450])  # 첫 세그먼트(0x20–0x178)는 온전, 둘째에서 잘림
    assert p["segments_complete"] is False and len(p["segments"]) == 1
    rnd = random.Random(7)
    t0 = time.monotonic()
    for _ in range(300):
        blob = bytearray(rnd.randbytes(rnd.randrange(0, 4096)))
        if blob:
            blob[0] = 0xE9
        if len(blob) > 24:
            blob[23] = rnd.choice((0, 1))
            blob[12:14] = rnd.choice((b"\x09\x00", b"\x05\x00", b"\x00\x00"))
        p = espfmt.parse_app_image(bytes(blob))
        assert isinstance(p["errors"], list) and isinstance(p["segments"], list)
    hdr = struct.pack("<BBBBI", 0xE9, 255, 2, 0x2F, 0x40378000) + struct.pack("<BBBBHBHH4sB", 0xEE, 0, 0, 0, 9, 0, 0, 99, bytes(4), 0)
    p = espfmt.parse_app_image(hdr + struct.pack("<II", 0x3C000020, 0xFFFFFFFF) + bytes(64))
    assert not p["ok"] and p["segments_complete"] is False and p["segments"] == []
    assert any("세그먼트 수 255" in e for e in p["errors"]) and any("길이 0xffffffff" in e for e in p["errors"])
    p = espfmt.parse_app_image(hdr + struct.pack("<II", 0x3FC90000, 0) * 255 + bytes(16))
    assert len(p["segments"]) == 255 and p["segments_complete"] and not p["ok"]
    assert time.monotonic() - t0 < 20
    assert any("ESP8266 v2" in e for e in espfmt.parse_app_image(b"\xEA" + bytes(40))["errors"])
    esp8266 = struct.pack("<BBBBI", 0xE9, 1, 0, 0x20, 0x40100004) + struct.pack("<II", 0x40100000, 8) + b"\x01" * 8 + bytes(8)
    assert any("ESP8266 v1" in e for e in espfmt.parse_app_image(esp8266)["errors"])
    bad_hash = bytearray(img)
    bad_hash[23] = 7
    assert any("hash_appended" in e for e in espfmt.parse_app_image(bytes(bad_hash))["errors"])
    assert any("매직" in e for e in espfmt.parse_app_image(b"\x7fELF" + bytes(40))["errors"])
    assert espfmt.parse_app_image(img, -1)["ok"] is False and espfmt.parse_app_image(img, len(img))["ok"] is False


def test_unknown_chip_id_structure_only():
    img = build_app_image(chip_id=0x1C, entry=0x42000020, segments=[(0x42000020, b"\x13\x00\x00\x00" * 4)])
    p = espfmt.parse_app_image(img)
    assert p["ok"] and p["chip"] == "unknown(0x1c)" and p["arch"] == "unknown" and p["e_machine"] == 0
    assert p["segments"][0]["region"] is None and p["segments"][0]["kind"] == "unknown"
    assert any("chip_id" in w for w in p["warnings"])
    with pytest.raises(EspFormatError, match="아키텍처"):
        espfmt.image_to_elf(img, p)


# ---------------------------------------------------------------------------
# ELF 변환 (저장소 elfinfo 로 확인)
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("chip", ["s3", "c3"])
def test_image_to_elf_loadable_by_elfinfo(chip):
    img = s3_app_image() if chip == "s3" else c3_app_image()
    p = espfmt.parse_app_image(img)
    elf = espfmt.image_to_elf(img, p)
    info = elfinfo.parse_elf(elf, len(elf))
    assert (info["class"], info["endianness"], info["type"]) == (32, "little", "EXEC")
    assert info["machine"] == ("xtensa" if chip == "s3" else "riscv") and info["entry"] == f"0x{p['entry']:x}"
    assert info["flags"]["raw"] == f"0x{(0x300 if chip == 's3' else 0x1):08x}"
    assert info["warnings"] == [] and info["static"] is True and info["interpreter"] is None
    assert info["sections"]["names"] == [".flash.rodata", ".flash.text", ".dram0.data", ".iram0.text", ".rtc.text", ".shstrtab"]
    loads = _elf_loads(elf)
    assert [(x["vaddr"], len(x["data"])) for x in loads] == [(s["load_addr"], s["size"]) for s in p["segments"]]
    assert all(x["data"] == _seg_bytes(img, s) for x, s in zip(loads, p["segments"]))
    assert [x["flags"] for x in loads] == [PF_R, PF_R | PF_X, PF_R | PF_W, PF_R | PF_W | PF_X, PF_R | PF_W | PF_X]
    shdrs = elfinfo._Elf(elf, len(elf)).shdrs()
    prog = [s for s in shdrs if s["type"] == 1]
    phdrs = [ph for ph in elfinfo._Elf(elf, len(elf)).phdrs() if ph["type"] == elfinfo.PT_LOAD]
    assert [(s["addr"], s["size"], s["offset"]) for s in prog] == [(ph["vaddr"], ph["filesz"], ph["offset"]) for ph in phdrs]
    assert all(ph["offset"] % 4 == ph["vaddr"] % 4 for ph in phdrs)


def test_image_to_elf_padding_and_repeated_names():
    img = build_app_image(chip_id=CHIP_S3, entry=0x40378000, segments=[
        (0x3C000020, build_app_desc()), (0x3FC90000, b"\1" * 16), (0x3FC91000, b"\2" * 16), (0x00000000, bytes(64)),
        (0x40378000, b"\x36\x41\x00\x1d\xf0\0\0\0"), (0x3FC92000, b"\3" * 8), (0x12345678, b"\4" * 4), (0x3FC93000, b"")])
    p = espfmt.parse_app_image(img)
    assert p["ok"] and p["segments"][3]["kind"] == "padding" and p["segments"][6]["kind"] == "unknown"
    assert any("알려진 영역 밖" in w for w in p["warnings"])
    elf = espfmt.image_to_elf(img, p)
    names = elfinfo.parse_elf(elf, len(elf))["sections"]["names"]
    assert names == [".flash.rodata", ".dram0.data", ".dram0.data_1", ".iram0.text", ".dram0.data_2", ".unknown", ".shstrtab"]
    loads = _elf_loads(elf)
    assert len(loads) == 6 and all(x["vaddr"] >= 0x10000 for x in loads)  # 채움·길이 0 세그먼트는 뺀다
    assert loads[-1]["vaddr"] == 0x12345678 and loads[-1]["flags"] == PF_R | PF_W | PF_X


def test_image_to_elf_refusals_and_tampered_image():
    img = s3_app_image()
    p = espfmt.parse_app_image(img)
    with pytest.raises(EspFormatError):
        espfmt.image_to_elf(img[:100], p)  # 세그먼트가 data 밖
    with pytest.raises(EspFormatError, match="끝까지"):
        espfmt.image_to_elf(img[:300], espfmt.parse_app_image(img[:300]))
    with pytest.raises(EspFormatError):
        espfmt.image_to_elf(img, {**p, "chip_id": 0x1C})
    with pytest.raises(EspFormatError):
        espfmt.image_to_elf(img, {"segments": "x"})
    with pytest.raises(EspFormatError, match="세그먼트가 없음"):
        espfmt.image_to_elf(img, {**p, "segments": []})
    with pytest.raises(EspFormatError):
        espfmt.image_to_elf(img, {**p, "entry": None})
    # 체크섬·SHA 가 틀린(수정된) 이미지도 세그먼트가 온전하면 변환한다
    b = bytearray(img)
    b[p["segments"][1]["file_offset"]] ^= 1
    q = espfmt.parse_app_image(bytes(b))
    assert not q["ok"] and q["segments_complete"]
    assert _elf_loads(espfmt.image_to_elf(bytes(b), q))[1]["data"] == _seg_bytes(bytes(b), q["segments"][1])


# ---------------------------------------------------------------------------
# NVS (로컬 오라클 없음)
# ---------------------------------------------------------------------------

def test_nvs_crc32_convention_constant():
    # 규약을 실수로 바꾸면 여기서 드러난다 (실제 기기로는 아직 검증되지 않은 규약)
    assert espfmt.nvs_crc32(b"123456789") == 0xD202D277 == zlib.crc32(b"123456789", 0xFFFFFFFF)
    assert espfmt.nvs_crc32(b"") == 0xFFFFFFFF
    assert espfmt.nvs_crc32(bytearray(b"abc")) == espfmt.nvs_crc32(b"abc")


def test_parse_nvs_values_v2():
    nv, r = rich_nvs()
    data = nv.build(total_pages=6)
    n = espfmt.parse_nvs(data)
    assert n["errors"] == [] and n["warnings"] == [] and n["duplicates"] == []
    assert n["page_size"] == 4096 and n["versions_seen"] == [2]
    assert n["namespaces"] == {1: "game", 2: "nvs.net80211", 3: "cloud"}
    # written 헤더 25 (네임스페이스 3 + 데이터 22), 데이터 CRC 10 (SZ 6 + BLOB_DATA 4), 지운 엔트리는 세지 않는다
    assert n["crc_summary"] == {"page_header": {"ok": 4, "bad": 0}, "entry": {"ok": 25, "bad": 0}, "data": {"ok": 10, "bad": 0}}
    assert "zlib.crc32" in n["crc_convention"] and "검증되지 않음" in n["crc_convention"]
    assert [(p["state_name"], p["seq"], p["version"], p["header_crc"]["ok"]) for p in n["pages"]] == [
        ("full", 0, 2, True), ("full", 1, 2, True), ("full", 2, 2, True), ("active", 3, 2, True),
        ("empty", 0xFFFFFFFF, None, None), ("empty", 0xFFFFFFFF, None, None)]
    live = {(it["namespace"], it["key"], it["type_name"]): it for it in n["items"] if it["live"]}
    want = {("game", "hiscore", "U32"): 98765, ("game", "lives", "U8"): 3, ("game", "level", "I8"): -2,
            ("game", "coins", "U16"): 65000, ("game", "temp", "I16"): -12345, ("game", "unlock_bits", "U32"): 0xF5,
            ("game", "delta", "I32"): -2_000_000_000, ("game", "playtime_ms", "U64"): 0x1_2345_6789,
            ("game", "epoch", "I64"): -(1 << 40), ("game", "max_u64", "U64"): (1 << 64) - 1,
            ("game", "player", "SZ"): "PLAYER-ONE 플레이어", ("game", "motd", "SZ"): "", ("game", "credits", "SZ"): "C" * 70,
            ("nvs.net80211", "sta.ssid", "SZ"): "toy-net", ("nvs.net80211", "sta.pswd", "SZ"): "not-a-real-pass",
            ("cloud", "api_token", "SZ"): "tok-synthetic-0000"}
    for k, v in want.items():
        assert live[k]["value"] == v, k
    sizes = {k: live[k]["size"] for k in want}
    assert sizes[("game", "lives", "U8")] == 1 and sizes[("game", "epoch", "I64")] == 8 and sizes[("game", "motd", "SZ")] == 1
    assert live[("game", "credits", "SZ")]["span"] == 4 and live[("game", "player", "SZ")]["data_crc_ok"] is True
    assert live[("game", "hiscore", "U32")]["data_crc_ok"] is None and live[("game", "hiscore", "U32")]["chunk_index"] == 0xFF
    # 오프셋은 이미지 안의 엔트리 위치
    for rec in nv.records:
        if rec.get("namespace_def"):
            continue
        it = next(i for i in n["items"] if i["page"] == rec["page"] and i["entry"] == rec["entry"])
        assert it["offset"] == nv.offset_of(rec) and data[it["offset"] + 1] == it["type"] and it["key"] == rec["key"]
    # v2 BLOB: 세 페이지에 걸친 조각 + 인덱스
    chunks = sorted((it for it in n["items"] if it["key"] == "slot0" and it["type_name"] == "BLOB_DATA"), key=lambda i: i["chunk_index"])
    assert [c["chunk_index"] for c in chunks] == [0, 1, 2] and len({c["page"] for c in chunks}) == 3
    assert all(c["live"] and c["data_crc_ok"] for c in chunks)
    idx = next(it for it in n["items"] if it["key"] == "slot0" and it["type_name"] == "BLOB_IDX")
    assert (idx["chunk_count"], idx["chunk_start"], idx["size"], idx["value"]) == (3, 0, 400, None)
    blobs = {b["key"]: b for b in n["blobs"]}
    assert blobs["slot0"]["value"] == bytes(range(200)) * 2 and blobs["slot0"]["complete"]
    assert (blobs["slot0"]["size"], blobs["slot0"]["chunks"], blobs["slot0"]["namespace"]) == (400, 3, "game")
    assert blobs["mac"]["value"] == SYNTH_MAC and blobs["mac"]["complete"] and blobs["mac"]["namespace"] == "cloud"
    # 비밀값 표시
    assert live[("nvs.net80211", "sta.pswd", "SZ")]["secret"] and live[("cloud", "api_token", "SZ")]["secret"]
    assert live[("nvs.net80211", "sta.ssid", "SZ")]["secret"]  # nvs.net80211 의 값은 모두 가린다 (세이브가 아님)
    assert not live[("game", "credits", "SZ")]["secret"]  # 게임 값(코인 수)은 가리지 않는다
    assert not live[("game", "hiscore", "U32")]["secret"]


def test_parse_nvs_erased_history_and_include_erased():
    nv, _r = rich_nvs()
    data = nv.build()
    n = espfmt.parse_nvs(data)
    hs = [it for it in n["items"] if it["key"] == "hiscore"]
    assert [(h["state"], h["live"], h["value"], h["crc"]["ok"]) for h in hs] == [("erased", False, 1200, True), ("written", True, 98765, True)]
    n2 = espfmt.parse_nvs(data, include_erased=False)
    assert all(it["state"] == "written" for it in n2["items"]) and len(n2["items"]) == len(n["items"]) - 1
    # 여러 엔트리에 걸친 문자열의 지운 옛 값
    nv2 = NvsImage()
    old = nv2.put_str("g", "name", "first-name-long-enough-to-span-two-entries-xx")
    nv2.erase(old)
    nv2.put_str("g", "name", "second")
    m = espfmt.parse_nvs(nv2.build())
    assert [(it["state"], it["live"], it["value"]) for it in m["items"] if it["key"] == "name"] == [
        ("erased", False, "first-name-long-enough-to-span-two-entries-xx"), ("written", True, "second")]
    assert m["pages"][0]["erased"] == 3 and m["pages"][0]["written"] == 1 + 2


def test_parse_nvs_crc_summary_one_bad_entry():
    nv, _r = corrupted_nvs()
    n = espfmt.parse_nvs(nv.build())
    assert n["crc_summary"]["entry"] == {"ok": 25, "bad": 1} and n["crc_summary"]["page_header"] == {"ok": 4, "bad": 0}
    bad = [it for it in n["items"] if it["key"] == "bad_entry"]
    assert len(bad) == 1 and bad[0]["state"] == "written" and bad[0]["crc"]["ok"] is False and bad[0]["live"] is False
    assert bad[0]["crc"]["stored"] != bad[0]["crc"]["computed"]
    assert any("CRC 불일치" in e for e in n["pages"][bad[0]["page"]]["errors"])
    assert not any("모두 불일치" in w for w in n["warnings"])
    assert sum(1 for it in n["items"] if it["live"]) == 25 - 3  # 나머지는 그대로 live


def test_parse_nvs_seq_order_duplicates_and_page_states():
    nv = NvsImage()
    nv.put("g", "score", "U32", 10)  # 페이지 0 (seq 0)
    nv.new_page()
    nv.put("g", "score", "U32", 20)  # 페이지 1 (seq 1) — 옛 값을 지우지 못한 채 중단된 상황
    n = espfmt.parse_nvs(nv.build(physical_order=[1, 0]))  # seq 1 페이지가 물리적으로 앞
    sc = [it for it in n["items"] if it["key"] == "score"]
    live = [it for it in sc if it["live"]]
    assert len(sc) == 2 and len(live) == 1 and (live[0]["value"], live[0]["page"], live[0]["page_seq"]) == (20, 0, 1)
    assert len(n["duplicates"]) == 1
    d = n["duplicates"][0]
    assert (d["namespace"], d["key"], d["type_name"], d["count"], d["chunk_index"]) == ("g", "score", "U32", 2, 0xFF)
    assert sorted(e["page_seq"] for e in d["entries"]) == [0, 1] and any("live 후보" in w for w in n["warnings"])
    # freeing 페이지는 살아 있고, corrupt 페이지의 항목은 live 가 아니다
    nv2 = NvsImage()
    nv2.put("g", "a", "U8", 1)
    nv2.new_page()
    nv2.put("g", "b", "U8", 2)
    nv2.new_page()
    nv2.put("g", "c", "U8", 3)
    nv2.set_page_state(0, PAGE_FREEING)
    nv2.set_page_state(1, PAGE_CORRUPT)
    m = espfmt.parse_nvs(nv2.build())
    assert {it["key"]: it["live"] for it in m["items"]} == {"a": True, "b": False, "c": True}
    assert [p["state_name"] for p in m["pages"]] == ["freeing", "corrupt", "active"]


def test_parse_nvs_blob_rewrite_chunk_start_0x80():
    """ESP-IDF 는 BLOB 을 다시 쓸 때 조각 번호 시작(chunk_start)을 0x00 ↔ 0x80 으로 번갈아 쓴다."""
    old_val, new_val = bytes(range(90)), b"N" * 70
    # A. 정상 재기록: 옛 인덱스·조각은 지워지고 새 버전(0x80~)만 written
    nv = NvsImage()
    old = nv.put_blob("game", "slot", old_val, chunk_size=40)
    for rec in old:
        nv.erase(rec)
    nv.put_blob("game", "slot", new_val, chunk_size=30, chunk_start=0x80)
    n = espfmt.parse_nvs(nv.build())
    assert len(n["blobs"]) == 1
    b = n["blobs"][0]
    assert (b["value"], b["complete"], b["chunk_start"], b["chunks"], b["size"]) == (new_val, True, 0x80, 3, 70)
    assert not any("BLOB_IDX 가 없는" in w for w in n["warnings"]) and n["duplicates"] == []
    erased = [it for it in n["items"] if it["key"] == "slot" and it["state"] == "erased"]
    assert sorted(it["chunk_index"] for it in erased if it["type_name"] == "BLOB_DATA") == [0, 1, 2]
    assert any(it["type_name"] == "BLOB_IDX" for it in erased) and not any(it["live"] for it in erased)
    live_chunks = sorted(it["chunk_index"] for it in n["items"] if it["live"] and it["type_name"] == "BLOB_DATA")
    assert live_chunks == [0x80, 0x81, 0x82]
    # B. 중단된 재기록: 옛 인덱스·조각이 지워지지 않고 남음
    nv2 = NvsImage()
    nv2.put_blob("game", "slot", old_val, chunk_size=40)
    nv2.put_blob("game", "slot", new_val, chunk_size=30, chunk_start=0x80)
    m = espfmt.parse_nvs(nv2.build())
    assert [(d["key"], d["type_name"], d["count"]) for d in m["duplicates"]] == [("slot", "BLOB_IDX", 2)]
    assert len(m["blobs"]) == 1 and m["blobs"][0]["value"] == new_val and m["blobs"][0]["chunk_start"] == 0x80
    idx_live = [it for it in m["items"] if it["type_name"] == "BLOB_IDX" and it["live"]]
    assert len(idx_live) == 1 and idx_live[0]["chunk_start"] == 0x80
    assert any("BLOB_IDX 가 없는 BLOB_DATA 조각 3개" in w for w in m["warnings"])
    # 키 단위 비교는 조립값으로: A 와 B 는 같은 값
    assert espfmt.nvs_item_diff([n, m])["unchanged_count"] == 1


def test_parse_nvs_v1_blob():
    nv, _r = rich_nvs(version=1)
    n = espfmt.parse_nvs(nv.build())
    assert n["versions_seen"] == [1] and n["errors"] == [] and n["blobs"] == []
    blob = [it for it in n["items"] if it["key"] == "slot0"]
    assert len(blob) == 1 and blob[0]["type_name"] == "BLOB" and blob[0]["value"] == bytes(range(200)) * 2
    assert blob[0]["data_crc_ok"] is True and blob[0]["span"] == 1 + 400 // 32 + 1 and blob[0]["live"]
    mac = next(it for it in n["items"] if it["key"] == "mac")
    assert mac["type_name"] == "BLOB" and mac["value"] == SYNTH_MAC


def test_parse_nvs_structural_errors_bounded():
    nv = NvsImage()
    nv.put("g", "ok", "U8", 1)
    nv.raw_entry(0, 100, nv.make_entry(1, 0x21, 50, 0xFF, "huge", struct.pack("<HHI", 1000, 0xFFFF, 0)))  # span 이 페이지 밖
    nv.pages[0]["states"][110] = 1  # 비정상 상태 비트 0b01
    data = nv.build()
    n = espfmt.parse_nvs(data)
    huge = [it for it in n["items"] if it["key"] == "huge"]
    assert len(huge) == 1 and huge[0]["live"] is False and huge[0]["crc"]["ok"] is True
    errs = n["pages"][0]["errors"]
    assert any("span 50" in e for e in errs) and any("0b01" in e for e in errs)
    assert next(it for it in n["items"] if it["key"] == "ok")["live"]
    with pytest.raises(NvsError, match="구조 오류"):
        espfmt.nvs_set_primitives(data, [{"namespace": "g", "key": "ok", "value": 2}])
    # 크기가 span 용량보다 큰 SZ
    nv2 = NvsImage()
    nv2.raw_entry(0, 0, nv2.make_entry(0, 0x01, 1, 0xFF, "g", b"\x01" + b"\xFF" * 7))
    nv2.raw_entry(0, 1, nv2.make_entry(1, 0x21, 2, 0xFF, "big", struct.pack("<HHI", 100, 0xFFFF, 0)))
    nv2.raw_entry(0, 2, b"A" * 32)
    m = espfmt.parse_nvs(nv2.build())
    big = next(it for it in m["items"] if it["key"] == "big")
    assert big["live"] is False and big["data_crc_ok"] is False and any("용량" in e for e in m["pages"][0]["errors"])


def test_parse_nvs_garbage_and_odd_sizes():
    rnd = random.Random(99)
    for data in (b"", b"\xFF" * 100, b"\xFF" * 4096 * 3, bytes(4096 * 2), rnd.randbytes(4096 * 8), rnd.randbytes(5000)):
        n = espfmt.parse_nvs(data)
        assert isinstance(n["items"], list) and isinstance(n["pages"], list)
    assert espfmt.parse_nvs(b"")["errors"]
    n = espfmt.parse_nvs(b"\xFF" * (4096 * 2 + 10))
    assert any("배수" in w for w in n["warnings"]) and [p["state_name"] for p in n["pages"]] == ["empty", "empty"] and n["items"] == []
    n = espfmt.parse_nvs(bytes(4096))
    assert n["pages"][0]["state_name"] == "invalid" and n["pages"][0]["errors"] and n["items"] == []
    pg = bytearray(b"\xFF" * 4096)
    pg[100] = 0
    assert any("빈 페이지" in e for e in espfmt.parse_nvs(bytes(pg))["pages"][0]["errors"])
    t0 = time.monotonic()
    for _ in range(40):  # 상태만 그럴듯한 쓰레기 페이지
        page = bytearray(rnd.randbytes(4096))
        struct.pack_into("<I", page, 0, 0xFFFFFFFE)
        n = espfmt.parse_nvs(bytes(page))
        assert n["crc_summary"]["page_header"]["bad"] == 1
    assert time.monotonic() - t0 < 20
    big = espfmt.parse_nvs(rnd.randbytes(4096) * 64)
    assert len(big["warnings"]) <= 101 and all(len(p["errors"]) <= 31 for p in big["pages"])


# I2a 적대적 리뷰(out_a4.txt)의 목록. 비밀 키는 namespace='app', 게임 세이브 값은 namespace='game' 으로 본다.
SECRET_KEYS = [
    "wifi_password", "wifi_pass", "sta_pass", "wifipass", "wifiPass", "staPass", "WiFiPass", "mqttpass", "mqttPass", "userpass",
    "adminpass", "rootpass", "pass", "password", "passwd", "pwd", "wifi_pwd", "mqtt_pw", "wifi_pw", "ap_pw", "pw", "pin", "wps_pin",
    "psk", "wpa_psk", "wifi_key", "wpa_key", "wep_key", "aes_key", "enc_key", "hmac_key", "tls_key", "client_key", "dev_key",
    "apiKey", "api_key", "apikey", "authToken", "auth_token", "refresh_token", "access_token", "idToken", "fcmToken", "usertoken",
    "devtoken", "token", "jwt", "client_secret", "secret", "private_key_pem", "privkey", "priv_key", "prv_key", "cert_key",
    "license_key", "activation_key", "unlock_key", "credentials", "cred", "creditcard", "card_no", "cvv", "otp_seed",
    "sta.pmk", "ap.pmk", "sta.pswd", "ap.passwd", "serial_key",
]
GAME_CLEAR_KEYS = [  # 세이브 분석이 비교해야 하는 값 — 가리면 안 된다
    "credits", "credit", "tokens", "token_count", "tok_cnt", "stage_passed", "pass_count", "passes", "secret_level",
    "secrets_found", "secret_lvl", "pwr_up", "hiscore", "keys_found", "key_count", "keyitems", "pin_count", "bypass", "compass",
    "passage", "bypass_count", "coins", "secretLevel", "tokenCount", "stagePassed", "passCount", "secretsFound",
]
GAME_OVERMASKED_KEYS = ["stage_pass", "password_lvl", "passcode_lv", "boss_pass", "cred_count"]  # 안전한 쪽의 과잉 마스킹 — 허용
KNOWN_MISSES = ["lic"]  # 알려진 누락 (너무 짧고 모호한 이름)


@pytest.mark.parametrize("key", SECRET_KEYS)
def test_secret_hint_secret_keys(key):
    assert espfmt.secret_hint("app", key) is True


@pytest.mark.parametrize("key", GAME_CLEAR_KEYS)
def test_secret_hint_game_values_not_masked(key):
    assert espfmt.secret_hint("game", key) is False


@pytest.mark.parametrize("key", GAME_OVERMASKED_KEYS + KNOWN_MISSES)
def test_secret_hint_documented_limits(key):
    # 정규식이 바뀌어 이 목록이 달라지면 의도한 변경인지 확인하고 목록을 갱신한다
    assert espfmt.secret_hint("game", key) is (key in GAME_OVERMASKED_KEYS)


@pytest.mark.parametrize("ns,key,expected", [
    # nvs.net80211 은 키와 무관하게 늘 비밀 (Wi-Fi 설정은 세이브가 아니다)
    ("nvs.net80211", "sta.pswd", True), ("nvs.net80211", "ap.passwd", True), ("nvs.net80211", "sta.pmk", True),
    ("nvs.net80211", "sta.ssid", True), ("nvs.net80211", "sta.authmode", True), ("nvs.net80211", "opmode", True),
    # 네임스페이스 이름을 모를 때(None)는 Wi-Fi 키 모양(pswd|pass|psk|pmk)이면 비밀
    (None, "sta.pmk", True), (None, "ap.pmk", True), (None, "sta.pswd", True), (None, "ap.passwd", True),
    (None, "sta.ssid", False), (None, "hiscore", False),
    # 다른 네임스페이스에서도 pmk 는 정규식으로 잡힌다
    ("other", "sta.pmk", True), ("other", "sta.ssid", False),
    # camelCase 펼치기와 대문자
    ("app", "mqttPass", True), ("app", "WiFiPass", True), ("app", "idToken", True), ("app", "APIKey", True), ("app", "WIFIPASS", True),
    ("app", "MQTT_PW", True), ("cloud", "API_KEY", True),
    # pin/pw 는 단어 경계에서만
    ("app", "pin1", True), ("app", "wps.pin", True), ("app", "pincode", True), ("app", "spin", False), ("app", "pinball", False),
    ("app", "opinion", False), ("app", "pw2", True), ("app", "pwr", False),
    # 앞선 기대값
    ("cloud", "client_secret", True), ("cloud", "secret_key", True), ("x", "credit_card", True), ("x", "creds", True),
    ("x", "credential", True), ("game", "Password", True), ("game", "credits", False),
    (None, None, False), ("game", None, False), (None, "", False),
])
def test_secret_hint_rules(ns, key, expected):
    assert espfmt.secret_hint(ns, key) is expected


PMK = bytes(range(0xA0, 0xC0))  # 32 바이트 PMK 모양 (합성 값)


def _wifi_nvs(variant: str) -> bytes:
    """game + nvs.net80211(sta.pmk/ap.pmk BLOB, sta.ssid, sta.authmode). variant 로 네임스페이스 정의를 망가뜨린다."""
    nv = NvsImage()
    nv.put("game", "hiscore", "U32", 1)
    if variant == "shadow":
        # nvs.net80211 이 받을 번호(2)를 다른 이름 'settings' 가 먼저 정의 (손상·악성 이미지)
        nv._write(0, 0x01, 0xFF, "settings", bytes([2]) + b"\xFF" * 7, namespace_def=True)
    nv.put_blob("nvs.net80211", "sta.pmk", PMK)
    nv.put_blob("nvs.net80211", "ap.pmk", PMK[::-1])
    nv.put_str("nvs.net80211", "sta.ssid", "toy-net")
    nv.put("nvs.net80211", "sta.authmode", "U8", 3)
    defn = next(r for r in nv.records if r.get("namespace_def") and r["key"] == "nvs.net80211")
    if variant == "corrupt-def":
        nv.corrupt(defn, byte=30)  # 정의 엔트리 데이터 필드의 미사용 바이트 → CRC 불일치 (이름·번호는 남음)
    elif variant == "lost-def":
        nv.corrupt(defn, byte=1)  # 타입 바이트까지 깨짐 → 정의로 쓸 수 없어 번호 2 의 이름을 모름
    return nv.build(total_pages=3)


@pytest.mark.parametrize("variant", ["baseline", "corrupt-def", "shadow", "lost-def"])
def test_nvs_wifi_namespace_never_unmasked(variant):
    n = espfmt.parse_nvs(_wifi_nvs(variant))
    items = {it["key"]: it for it in n["items"] if it["live"] and it["type_name"] != "BLOB_DATA"}
    blobs = {b["key"]: b for b in n["blobs"]}
    assert blobs["sta.pmk"]["value"] == PMK and blobs["ap.pmk"]["value"] == PMK[::-1]
    # 어떤 경우에도 PMK 는 가린다 (항목·조각·조립 BLOB 모두)
    assert blobs["sta.pmk"]["secret"] and blobs["ap.pmk"]["secret"]
    assert all(it["secret"] for it in n["items"] if it["key"] in ("sta.pmk", "ap.pmk"))
    assert items["hiscore"]["secret"] is False and items["hiscore"]["namespace"] == "game"
    w = " | ".join(n["warnings"])
    if variant == "lost-def":
        # 이름을 모르면 키 모양 규칙만: pmk 는 가리고 ssid/authmode 는 이름 없이는 판단 못 함
        assert 2 not in n["namespaces"] and items["sta.ssid"]["namespace"] is None and "이름을 모르는 네임스페이스 번호: [2]" in w
        assert items["sta.ssid"]["secret"] is False and items["sta.authmode"]["secret"] is False
    else:
        assert n["namespaces"][2] == "nvs.net80211"
        assert all(items[k]["secret"] for k in ("sta.ssid", "sta.authmode"))  # 네임스페이스 전체를 가린다
        if variant == "corrupt-def":
            assert "CRC 가 깨진 엔트리뿐" in w and n["crc_summary"]["entry"]["bad"] == 1
        if variant == "shadow":
            assert "정의가 여럿 ['settings', 'nvs.net80211'] — 'nvs.net80211' 로 봄" in w


def test_nvs_set_primitives_refuses_conflicting_namespace():
    data = _wifi_nvs("shadow")
    with pytest.raises(NvsError, match="정의가 여럿"):
        espfmt.nvs_set_primitives(data, [{"namespace": "nvs.net80211", "key": "sta.authmode", "value": 0}])
    with pytest.raises(NvsError, match="정의가 여럿"):
        espfmt.nvs_set_primitives(data, [{"namespace": "settings", "key": "sta.authmode", "value": 0}])
    new, changes = espfmt.nvs_set_primitives(data, [{"namespace": "game", "key": "hiscore", "value": 7}])  # 충돌 없는 네임스페이스는 된다
    assert changes[0]["after"] == 7 and len(new) == len(data)


class _BudgetCtl:
    """expired() 가 after 번 호출된 뒤부터 True (시간 예산 초과 흉내). check() 는 아무것도 안 함."""

    def __init__(self, after: int) -> None:
        self.after = after
        self.calls = 0

    def check(self) -> None:
        return None

    def expired(self) -> bool:
        self.calls += 1
        return self.calls > self.after


def test_parse_nvs_max_items_caps_items_blobs_duplicates():
    data = dense_nvs(4)  # 4 페이지 × 126 엔트리, 첫 엔트리는 네임스페이스 정의 → 데이터 항목 503개
    full = espfmt.parse_nvs(data)
    assert len(full["items"]) == full["items_total"] == 503 and full["truncated"] is False and full["notes"] == []
    n = espfmt.parse_nvs(data, max_items=100)
    assert len(n["items"]) == 100 and n["items_total"] == 503 and n["truncated"] is True and n["items"] == full["items"][:100]
    assert any("max_items" in x for x in n["notes"]) and n["crc_summary"] == full["crc_summary"]
    assert n["crc_summary"]["entry"] == {"ok": 504, "bad": 0}
    assert espfmt.parse_nvs(data, max_items=None)["items"] == full["items"]
    assert espfmt.parse_nvs(data, max_items=0)["items"] == []
    for bad in (-1, True, 1.5):
        with pytest.raises(ValueError):
            espfmt.parse_nvs(data, max_items=bad)
    nv = NvsImage()
    for i in range(5):
        nv.put_blob("g", f"b{i}", bytes([i]) * 10)
    m = espfmt.parse_nvs(nv.build(), max_items=2)
    assert len(m["blobs"]) == 2 and m["truncated"] and any("BLOB 5개 중" in x for x in m["notes"])
    dup = dense_nvs(1, seq0=0) + dense_nvs(1, seq0=1)  # 같은 키 125개가 두 페이지에 (새 seq 가 live)
    d = espfmt.parse_nvs(dup, max_items=10)
    assert len(d["duplicates"]) == 10 and any("중복 125건 중" in x for x in d["notes"])
    live = [it for it in espfmt.parse_nvs(dup)["items"] if it["live"]]
    assert len(live) == 125 and all(it["page_seq"] == 1 for it in live)


def test_parse_nvs_ctl_time_budget_and_cancel():
    data = dense_nvs(8)
    n = espfmt.parse_nvs(data, ctl=_BudgetCtl(after=3))  # 3 페이지를 읽고 예산 초과
    assert n["truncated"] and len(n["pages"]) == 3 and n["items_total"] == 3 * 126 - 1
    assert any("시간 예산 초과" in x and "3 페이지까지만" in x for x in n["notes"])
    ev = threading.Event()
    ev.set()
    with pytest.raises(Cancelled):
        espfmt.parse_nvs(data, ctl=Ctl(ev))  # 취소는 예외로
    assert espfmt.parse_nvs(data, ctl=Ctl(max_seconds=120)) == espfmt.parse_nvs(data)  # 예산 안이면 ctl 이 없을 때와 같다
    progress: list[tuple] = []
    espfmt.parse_nvs(dense_nvs(70), ctl=Ctl(progress=lambda *a: progress.append(a)))
    assert progress and progress[0][1] == 70


def test_nvs_item_diff_ctl_and_truncated_inputs():
    a, b = espfmt.parse_nvs(dense_nvs(2, seq0=0)), espfmt.parse_nvs(dense_nvs(2, seq0=1))
    full = espfmt.nvs_item_diff([a, b])
    assert full["truncated"] is False and full["notes"] == [] and len(full["changed"]) == 251
    d = espfmt.nvs_item_diff([a, b], ctl=_BudgetCtl(after=1))  # 둘째 스냅샷을 모으기 전에 예산 초과
    assert d["truncated"] and d["changed"] == [] and any("시간 예산 초과" in x for x in d["notes"])
    big_a, big_b = espfmt.parse_nvs(dense_nvs(140, seq0=0)), espfmt.parse_nvs(dense_nvs(140, seq0=1))  # 키 17,639개
    d2 = espfmt.nvs_item_diff([big_a, big_b], ctl=_BudgetCtl(after=2))  # 키 비교 도중(16K 번째) 예산 초과
    assert d2["truncated"] and 0 < len(d2["changed"]) < 140 * 126 - 1 and any("까지만 비교함" in x for x in d2["notes"])
    t = espfmt.parse_nvs(dense_nvs(2), max_items=5)
    d3 = espfmt.nvs_item_diff([t, b], labels=["cut", "full"])
    assert d3["truncated"] and any("스냅샷 cut" in x for x in d3["notes"])
    ev = threading.Event()
    ev.set()
    with pytest.raises(Cancelled):
        espfmt.nvs_item_diff([a, b], ctl=Ctl(ev))


def test_parse_nvs_dense_resource_bounds():
    data = dense_nvs(256, secret_keys=True)  # 1 MiB, 엔트리 32,256개 모두 CRC 정상 (서버 입력 상한 수준)
    tracemalloc.start()
    try:
        t0 = time.monotonic()
        n = espfmt.parse_nvs(data)
        elapsed = time.monotonic() - t0
        _cur, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    assert n["items_total"] == 256 * 126 - 1 and n["crc_summary"]["entry"]["bad"] == 0 and n["truncated"] is False
    assert all(it["secret"] for it in n["items"])  # pass{p}_{i} 키는 모두 가린다
    # 측정(이 저장소, 2026-10): tracemalloc 아래 약 0.4 초, 최고 46 MiB. 넉넉한 상한으로 퇴행만 잡는다.
    assert peak < 160 * 2**20, peak
    assert elapsed < 30, elapsed


def _snapshot(**vals: Any) -> dict[str, Any]:
    nv = NvsImage()
    for k, v in vals.items():
        if k == "slot":
            nv.put_blob("game", "slot", v[0], chunk_size=v[1])
        elif k == "pswd":
            nv.put_str("nvs.net80211", "sta.pswd", v)
        elif k == "name":
            nv.put_str("game", "name", v)
        else:
            nv.put("game", k, "U8" if k != "hiscore" else "U32", v)
    return espfmt.parse_nvs(nv.build())


def test_nvs_item_diff():
    s1 = _snapshot(hiscore=100, lives=3, name="AAA", slot=(b"x" * 50, 20), pswd="pw-one", old_flag=1)
    s2 = _snapshot(hiscore=500, lives=3, name="AAA", slot=(b"y" * 50, 25), pswd="pw-two", stage=4)
    d = espfmt.nvs_item_diff([s1, s2], labels=["before", "after"])
    assert d["labels"] == ["before", "after"] and d["snapshot_count"] == 2 and d["unchanged_count"] == 2
    ch = {(c["namespace"], c["key"], c["type_name"]): c for c in d["changed"]}
    assert set(ch) == {("game", "hiscore", "U32"), ("game", "slot", "BLOB"), ("nvs.net80211", "sta.pswd", "SZ")}
    assert ch[("game", "hiscore", "U32")]["values"] == [100, 500] and not ch[("game", "hiscore", "U32")]["secret"]
    assert ch[("game", "slot", "BLOB")]["values"] == [b"x" * 50, b"y" * 50]
    assert ch[("nvs.net80211", "sta.pswd", "SZ")]["secret"] is True
    assert [(a["key"], a["values"]) for a in d["added"]] == [("stage", [None, 4])]
    assert [(r["key"], r["values"]) for r in d["removed"]] == [("old_flag", [1, None])]
    # 같은 BLOB 을 다른 조각 크기로 저장해도 조립값이 같으면 unchanged
    s3 = _snapshot(hiscore=900, lives=3, name="AAA", slot=(b"y" * 50, 10), pswd="pw-two")
    d2 = espfmt.nvs_item_diff([s2, s3])
    assert d2["labels"] == ["#0", "#1"] and "slot" not in {c["key"] for c in d2["changed"]}
    # 세 스냅샷: 중간에만 있었던 키는 changed
    d3 = espfmt.nvs_item_diff([s1, s2, s3])
    ch3 = {c["key"]: c["values"] for c in d3["changed"]}
    assert ch3["hiscore"] == [100, 500, 900] and ch3["stage"] == [None, 4, None]
    assert espfmt.nvs_item_diff([s1])["unchanged_count"] == 6 and espfmt.nvs_item_diff([])["unchanged_count"] == 0
    with pytest.raises(ValueError):
        espfmt.nvs_item_diff([s1, s2], labels=["only-one"])


def test_nvs_set_primitives_success():
    nv, r = rich_nvs()
    data = nv.build(total_pages=6)
    edits = [{"namespace": "game", "key": "hiscore", "value": 999_999}, {"namespace": "game", "key": "lives", "value": 9},
             {"namespace": "game", "key": "level", "value": -128}, {"namespace": "game", "key": "epoch", "value": (1 << 63) - 1},
             {"namespace": "game", "key": "max_u64", "value": 0}]
    new, changes = espfmt.nvs_set_primitives(data, edits)
    assert isinstance(new, bytes) and len(new) == len(data)
    widths = {"U32": 4, "U8": 1, "I8": 1, "I64": 8, "U64": 8}
    allowed: set[int] = set()
    for c in changes:
        allowed |= set(range(c["offset"] + 4, c["offset"] + 8)) | set(range(c["offset"] + 24, c["offset"] + 24 + widths[c["type_name"]]))
    assert {i for i in range(len(data)) if data[i] != new[i]} <= allowed
    off = nv.offset_of(r["lives"])
    assert new[off + 25:off + 32] == b"\xFF" * 7  # 타입 폭 밖의 0xFF 는 그대로
    c0 = changes[0]
    assert {k: c0[k] for k in ("page", "entry", "offset", "namespace", "key", "type_name", "before", "after")} == {
        "page": 0, "entry": r["hiscore"]["entry"], "offset": nv.offset_of(r["hiscore"]), "namespace": "game", "key": "hiscore",
        "type_name": "U32", "before": 98765, "after": 999_999}
    o = c0["offset"]
    assert c0["crc_after"] == espfmt.nvs_crc32(new[o:o + 4] + new[o + 8:o + 32]) == struct.unpack_from("<I", new, o + 4)[0]
    assert c0["crc_before"] == struct.unpack_from("<I", data, o + 4)[0] != c0["crc_after"]
    n = espfmt.parse_nvs(new)
    live = {it["key"]: it["value"] for it in n["items"] if it["live"]}
    assert (live["hiscore"], live["lives"], live["level"], live["epoch"], live["max_u64"]) == (999_999, 9, -128, (1 << 63) - 1, 0)
    assert live["coins"] == 65000 and n["crc_summary"]["entry"]["bad"] == 0 and n["errors"] == []
    assert [(it["state"], it["value"]) for it in n["items"] if it["key"] == "hiscore"][0] == ("erased", 1200)
    ba = bytearray(data)
    new2, _ = espfmt.nvs_set_primitives(ba, edits)
    assert bytes(ba) == data and new2 == new
    assert espfmt.nvs_set_primitives(memoryview(data), edits)[0] == new


@pytest.mark.parametrize("edit,match", [
    ({"namespace": "game", "key": "nope", "value": 1}, "키 'game/nope' 없음"),
    ({"namespace": "nope", "key": "hiscore", "value": 1}, "네임스페이스 'nope' 없음"),
    ({"namespace": "game", "key": "player", "value": 1}, "기본 정수 타입이 아님"),
    ({"namespace": "game", "key": "slot0", "value": 1}, "live 항목이 4개"),
    ({"namespace": "game", "key": "lives", "value": 256}, "범위"),
    ({"namespace": "game", "key": "lives", "value": -1}, "범위"),
    ({"namespace": "game", "key": "level", "value": 128}, "범위"),
    ({"namespace": "game", "key": "temp", "value": -32769}, "범위"),
    ({"namespace": "game", "key": "max_u64", "value": 1 << 64}, "범위"),
    ({"namespace": "game", "key": "lives", "value": True}, "정수"),
    ({"namespace": "game", "key": "lives", "value": 1.5}, "정수"),
    ({"namespace": "game", "key": "lives", "value": "3"}, "정수"),
    ({"namespace": 1, "key": "lives", "value": 3}, "문자열"),
    ("not-a-dict", "dict"),
])
def test_nvs_set_primitives_refusals_change_nothing(edit, match):
    nv, _r = rich_nvs()
    data = nv.build()
    ba = bytearray(data)
    with pytest.raises(NvsError, match=match):
        espfmt.nvs_set_primitives(ba, [{"namespace": "game", "key": "coins", "value": 1}, edit])  # 앞의 정상 수정도 적용되지 않는다
    assert bytes(ba) == data


def test_nvs_set_primitives_refuses_unsafe_images():
    nv, _r = rich_nvs()
    data = nv.build()
    ok_edit = [{"namespace": "game", "key": "lives", "value": 5}]
    with pytest.raises(NvsError, match="비었"):
        espfmt.nvs_set_primitives(data, [])
    with pytest.raises(NvsError, match="두 번"):
        espfmt.nvs_set_primitives(data, ok_edit * 2)
    # live 가 아님: 지운 값만 있는 키
    nv2 = NvsImage()
    gone = nv2.put("g", "gone", "U8", 1)
    nv2.erase(gone)
    nv2.put("g", "keep", "U8", 2)
    with pytest.raises(NvsError, match="live 항목이 없음"):
        espfmt.nvs_set_primitives(nv2.build(), [{"namespace": "g", "key": "gone", "value": 3}])
    # 중복 written 후보
    nv3 = NvsImage()
    nv3.put("g", "score", "U32", 10)
    nv3.new_page()
    nv3.put("g", "score", "U32", 20)
    with pytest.raises(NvsError, match="후보가 2개"):
        espfmt.nvs_set_primitives(nv3.build(), [{"namespace": "g", "key": "score", "value": 30}])
    # 손상 엔트리가 하나 있는 이미지
    nv4, _ = corrupted_nvs()
    with pytest.raises(NvsError, match="일부만 불일치") as ei:
        espfmt.nvs_set_primitives(nv4.build(), ok_edit)
    assert "엔트리 ok=25 bad=1" in str(ei.value)
    # 빈 NVS
    with pytest.raises(NvsError, match="검증할 CRC"):
        espfmt.nvs_set_primitives(b"\xFF" * 4096 * 3, ok_edit)


def test_nvs_set_primitives_refuses_crc_convention_mismatch():
    # 다른 CRC 규약(초기값 0 의 표준 CRC-32)으로 만든 이미지: 구조는 같지만 CRC 가 모두 어긋난다
    nv, _r = rich_nvs(crc_fn=lambda b: zlib.crc32(b) & 0xFFFFFFFF)
    data = nv.build()
    n = espfmt.parse_nvs(data)
    assert n["crc_summary"]["entry"]["ok"] == 0 and n["crc_summary"]["page_header"]["ok"] == 0
    assert any("규약" in w for w in n["warnings"]) and not any(it["live"] for it in n["items"])
    ba = bytearray(data)
    with pytest.raises(NvsError, match="CRC 규약") as ei:
        espfmt.nvs_set_primitives(ba, [{"namespace": "game", "key": "lives", "value": 5}])
    assert "모두 불일치" in str(ei.value) and bytes(ba) == data


# ---------------------------------------------------------------------------
# 조립된 플래시 (부트로더 + 테이블 + NVS + 앱)
# ---------------------------------------------------------------------------

def test_composed_flash_end_to_end():
    nv, _r = rich_nvs()
    nvs_img = nv.build(total_pages=6)
    app = s3_app_image()
    flash, layout = build_esp_flash(nvs=nvs_img, app=app)
    t = espfmt.parse_partition_table(flash)
    assert t["found"] and t["offset"] == 0x8000 and t["warnings"] == []
    bl = espfmt.parse_app_image(flash, layout["bootloader"])
    assert bl["ok"] and bl["image_type"] == "bootloader"
    nvs_e = espfmt.find_partition(t, "nvs")
    n = espfmt.parse_nvs(flash[nvs_e["offset"]:nvs_e["end"]])
    assert n["crc_summary"]["entry"]["bad"] == 0 and len(n["pages"]) == 6
    assert next(it["value"] for it in n["items"] if it["key"] == "hiscore" and it["live"]) == 98765
    app_e = espfmt.find_partition(t, "factory")
    p = espfmt.parse_app_image(flash, app_e["offset"])
    assert p["ok"] and p["offset"] == 0x10000 and p["segments"][0]["file_offset"] == 0x10000 + 32 and p["image_size"] == len(app)
    assert espfmt.image_to_elf(flash, p) == espfmt.image_to_elf(app, espfmt.parse_app_image(app))
    new_nvs, _ = espfmt.nvs_set_primitives(flash[nvs_e["offset"]:nvs_e["end"]], [{"namespace": "game", "key": "hiscore", "value": 1}])
    assert len(new_nvs) == nvs_e["size"]


# ---------------------------------------------------------------------------
# external: esptool v5 오라클, readelf
# ---------------------------------------------------------------------------

ESPTOOL = find_tool("PWEH_ESPTOOL", "esptool")


def _esptool(*args: str, timeout: int = 180) -> tuple[int, str]:
    if not ESPTOOL:
        pytest.skip("esptool 없음 (~/pweh-tools/bin/esptool — scripts/install.sh)")
    env = dict(os.environ, COLUMNS="300", NO_COLOR="1", TERM="dumb")
    res = subprocess.run([ESPTOOL, *args], capture_output=True, text=True, timeout=timeout, env=env, stdin=subprocess.DEVNULL)
    return res.returncode, re.sub(r"\x1b\[[0-9;]*m", "", res.stdout + res.stderr)


@pytest.fixture(scope="module")
def esptool_v5() -> str:
    rc, text = _esptool("version")
    m = re.search(r"esptool v?(\d+)\.(\d+)", text)
    if rc != 0 or not m or int(m.group(1)) < 5:
        pytest.skip(f"esptool v5 가 아님 (image-info/elf2image 철자): {text[:200]}")
    return text


def _parse_image_info(text: str) -> dict[str, Any]:
    def grab(label: str) -> str | None:
        m = re.search(rf"^{label}:\s+(.*?)\s*$", text, re.M)
        return m.group(1) if m else None

    out: dict[str, Any] = {}
    m = re.search(r"Entry point:\s+0x([0-9a-fA-F]+)", text)
    out["entry"] = int(m.group(1), 16) if m else None
    out["segments_n"] = int(re.search(r"^Segments:\s+(\d+)", text, re.M).group(1))
    out["chip_id"] = int(re.search(r"Chip ID:\s+(\d+)", text).group(1))
    m = re.search(r"Checksum:\s+0x([0-9a-fA-F]+)\s+\((valid|invalid - calculated 0x([0-9a-fA-F]+))\)", text)
    out["checksum_stored"] = int(m.group(1), 16)
    out["checksum_valid"] = m.group(2) == "valid"
    out["checksum_calc"] = int(m.group(3), 16) if m.group(3) else out["checksum_stored"]
    m = re.search(r"Validation hash:\s+([0-9a-f]{64})\s+\((valid|invalid)\)", text)
    out["hash"], out["hash_valid"] = (m.group(1), m.group(2) == "valid") if m else (None, None)
    for key, label in (("project_name", "Project name"), ("version", "App version"), ("elf_sha", "ELF file SHA256"),
                       ("idf_ver", "ESP-IDF"), ("secure_version", "Secure version"), ("compile_time", "Compile time"),
                       ("bl_version", "Bootloader version"), ("flash_size", "Flash size"), ("flash_freq", "Flash freq"),
                       ("flash_mode", "Flash mode")):
        out[key] = grab(label)
    out["segments"] = [(int(i), int(ln, 16), int(a, 16), int(f, 16), {t.strip() for t in types.split(",")})
                       for i, ln, a, f, types in re.findall(r"^\s*(\d+)\s+0x([0-9a-f]+)\s+0x([0-9a-f]+)\s+0x([0-9a-f]+)\s+(\S.*?)\s*$",
                                                            text, re.M)]
    return out


def _corrupt_segment(img: bytes) -> bytes:
    p = espfmt.parse_app_image(img)
    b = bytearray(img)
    b[p["segments"][1]["file_offset"] + 2] ^= 0xFF
    return bytes(b)


@pytest.mark.external
@pytest.mark.parametrize("kind", ["s3-app", "c3-app-nohash", "s3-bootloader", "s3-app-corrupt", "c3-app"])
def test_esptool_image_info_oracle(tmp_path, esptool_v5, kind):
    img = {"s3-app": s3_app_image, "c3-app-nohash": lambda: c3_app_image(hash_appended=False), "s3-bootloader": s3_bootloader_image,
           "s3-app-corrupt": lambda: _corrupt_segment(s3_app_image()), "c3-app": c3_app_image}[kind]()
    path = tmp_path / f"{kind}.bin"
    path.write_bytes(img)
    rc, text = _esptool("image-info", str(path))
    assert rc == 0, text
    info = _parse_image_info(text)
    p = espfmt.parse_app_image(img)
    assert (info["entry"], info["segments_n"], info["chip_id"]) == (p["entry"], len(p["segments"]), p["chip_id"])
    assert [(i, ln, a, f) for i, ln, a, f, _t in info["segments"]] == [
        (s["index"], s["size"], s["load_addr"], s["header_offset"]) for s in p["segments"]]
    for (_i, _ln, _a, _f, types), s in zip(info["segments"], p["segments"]):
        assert set(s["region"].split("/")) <= types, (s, types)  # 우리 영역 이름은 esptool 메모리 종류 안에 있다
    assert (info["checksum_valid"], info["checksum_stored"], info["checksum_calc"]) == (
        p["checksum"]["ok"], p["checksum"]["stored"], p["checksum"]["computed"])
    if p["hash_appended"]:
        assert (info["hash"], info["hash_valid"]) == (p["sha256"]["computed"], p["sha256"]["ok"])
    else:
        assert info["hash"] is None
    assert (info["flash_size"], info["flash_freq"], info["flash_mode"]) == (p["spi_size_name"], p["spi_speed_name"], p["spi_mode_name"].upper())
    if p["image_type"] == "app":
        d = p["app_desc"]
        assert (info["project_name"], info["version"], info["idf_ver"], info["elf_sha"]) == (d["project_name"], d["version"], d["idf_ver"],
                                                                                             d["app_elf_sha256"])
        assert info["secure_version"] == str(d["secure_version"]) and info["compile_time"] == f"{d['date']} {d['time']}"
    else:
        b = p["bootloader_desc"]
        assert (info["bl_version"], info["idf_ver"], info["compile_time"]) == (str(b["version"]), b["idf_ver"], b["date_time"])
    if kind == "s3-app-corrupt":
        assert info["checksum_valid"] is False and info["hash_valid"] is False and not p["ok"]
    else:
        assert info["checksum_valid"] and p["ok"]


@pytest.mark.external
@pytest.mark.parametrize("chip", ["s3", "c3"])
def test_esptool_elf2image_roundtrip(tmp_path, esptool_v5, chip):
    elf_in = esp_elf(chip)
    _machine, _eflags, entry, sections = esp_elf_sections(chip)
    src = tmp_path / f"in-{chip}.elf"
    src.write_bytes(elf_in)
    out = tmp_path / f"out-{chip}.bin"
    rc, text = _esptool("--chip", f"esp32{chip}", "elf2image", "--flash-mode", "dio", "--flash-freq", "80m", "--flash-size", "4MB",
                        "-o", str(out), str(src))
    assert rc == 0 and out.is_file(), text
    img = out.read_bytes()
    p = espfmt.parse_app_image(img)
    assert p["ok"], p["errors"]
    assert (p["chip_id"], p["entry"], p["spi_mode_name"], p["spi_speed_name"], p["spi_size_name"]) == (
        CHIP_S3 if chip == "s3" else CHIP_C3, entry, "dio", "80m", "4MB")
    assert p["checksum"]["ok"] and p["sha256"]["ok"] and p["image_type"] == "app"
    elf_sha = hashlib.sha256(elf_in).digest()
    assert p["app_desc"]["project_name"] == f"elf-{chip}" and p["app_desc"]["app_elf_sha256"] == elf_sha.hex()
    if chip == "s3":  # 큰 DRAM 섹션이 IROM 의 64 KB 맞춤 채움으로 쓰여 이어진 두 조각으로 나뉜다 (0 주소 채움 없음)
        dram = [s for s in p["segments"] if s["region"] == "DRAM"]
        assert len(dram) == 2 and dram[0]["load_addr"] + dram[0]["size"] == dram[1]["load_addr"]
        assert not any(s["kind"] == "padding" for s in p["segments"])
    else:  # RAM 섹션이 모자라 load_addr 0 채움 세그먼트가 들어간다
        assert any(s["kind"] == "padding" and s["load_addr"] == 0 for s in p["segments"])
    elf_out = espfmt.image_to_elf(img, p)
    loads_out = _elf_loads(elf_out)
    loads_in = _elf_loads(elf_in)
    assert len(loads_in) == len(sections) and all(x["vaddr"] >= 0x10000 for x in loads_out)
    sha_addr = 0x3C000020 + 0x90  # esp_app_desc_t.app_elf_sha256 — elf2image 가 이미지 오프셋 0xB0 에 써 넣음
    for x in loads_in:
        want = bytearray(x["data"])
        if x["vaddr"] <= sha_addr < x["vaddr"] + len(want):
            k = sha_addr - x["vaddr"]
            want[k:k + 32] = elf_sha
        assert _read_addr(loads_out, x["vaddr"], len(want)) == bytes(want), hex(x["vaddr"])
    for x in loads_out:  # 출력에 원래 ELF 밖의 바이트가 없다
        _read_addr(loads_in, x["vaddr"], len(x["data"]))
    assert sum(len(x["data"]) for x in loads_out) == sum(len(x["data"]) for x in loads_in)
    by_addr = {x["vaddr"]: x["flags"] for x in loads_out}
    assert by_addr[0x42010020] == PF_R | PF_X and by_addr[0x3C000020] == PF_R
    # esptool 자신도 자기 이미지를 같은 값으로 본다
    rc, text = _esptool("image-info", str(out))
    info = _parse_image_info(text)
    assert rc == 0 and info["checksum_valid"] and info["hash_valid"] and info["elf_sha"] == elf_sha.hex()
    assert [(a, ln) for _i, ln, a, _f, _t in info["segments"]] == [(s["load_addr"], s["size"]) for s in p["segments"]]


@pytest.mark.external
@pytest.mark.parametrize("chip", ["s3", "c3"])
def test_readelf_reads_generated_elf(tmp_path, chip):
    readelf = shutil.which("readelf")
    if not readelf:
        pytest.skip("readelf 없음")
    img = s3_app_image() if chip == "s3" else c3_app_image()
    p = espfmt.parse_app_image(img)
    path = tmp_path / f"{chip}.elf"
    path.write_bytes(espfmt.image_to_elf(img, p))
    res = subprocess.run([readelf, "-W", "-h", "-l", "-S", str(path)], capture_output=True, text=True, timeout=60)
    assert res.returncode == 0 and "Error" not in res.stderr and "Warning" not in res.stderr, res.stderr
    assert ("Tensilica Xtensa" if chip == "s3" else "RISC-V") in res.stdout
    assert re.search(rf"Entry point address:\s+0x{p['entry']:x}\b", res.stdout)
    assert len(re.findall(r"^\s+LOAD\s", res.stdout, re.M)) == len(p["segments"])
    for s in p["segments"]:
        assert f"0x{s['load_addr']:08x}" in res.stdout


# ---------------------------------------------------------------------------
# REA (Ghidra 기반 MCP 서버) — external + slow
# ---------------------------------------------------------------------------

@pytest.mark.external
@pytest.mark.slow
async def test_rea_open_binary_esp_elf(workspace):
    """image_to_elf 결과를 REA open_binary(provider ghidra) 에 넣어 본다 — 관찰된 동작(2026-10, REA + Ghidra 12.1.4)을 고정한다.

    - S3(Xtensa, e_machine 94): REA 자체 ELF 검사(dist/domain/binaryTarget.js 의 elfArchitecture)에 94 가 없어
      Ghidra 에 가기 전에 "unsupported ELF architecture" 로 거부된다. (Ghidra 12.1.4 자체는 Xtensa ELF opinion 이 있다.)
    - C3(RISC-V, e_flags 0x1 = RVC + soft-float ilp32): REA 의 Ghidra RISC-V 경로(GhidraRiscvProfile.js)가
      EF_RISCV_FLOAT_ABI_DOUBLE 선언만 받아서 거부된다. ESP32-C3 는 실제로 soft-float 이므로 image_to_elf 는 0x1 을 유지한다.
    - 진단 전용: C3 ELF 의 e_flags 만 0x5(double-float)로 바꾼 사본은 열리고 엔트리 함수가 디컴파일된다
      → ELF 배치 자체는 REA/Ghidra 가 적재할 수 있다. 이 사본은 ABI 를 거짓으로 선언하므로 제품 코드에는 쓰지 않는다.
    REA 가 바뀌어 이 단언이 깨지면 설계 §3.5 의 디컴파일 경로 판단을 다시 할 것.
    """
    from e2e.agent_flow import McpHub, Recorder, rea_available

    ok, why = rea_available()
    if not ok:
        pytest.skip(f"REA 를 쓸 수 없음: {why}")
    case_dir = workspace["cases_dir"] / "esp-elf-rea" / "analysis"
    case_dir.mkdir(parents=True)
    paths = {}
    for chip, img in (("s3", s3_app_image()), ("c3", c3_app_image())):
        paths[chip] = case_dir / f"app-{chip}.elf"
        paths[chip].write_bytes(espfmt.image_to_elf(img, espfmt.parse_app_image(img)))
    diag = bytearray(paths["c3"].read_bytes())
    assert struct.unpack_from("<I", diag, 36)[0] == 0x1
    struct.pack_into("<I", diag, 36, 0x5)  # 진단 전용 사본 (위 docstring)
    paths["c3-diag"] = case_dir / "app-c3-diag-eflags5.elf"
    paths["c3-diag"].write_bytes(bytes(diag))
    async with McpHub(Recorder(), rea=True, rea_cwd=workspace["root"]) as hub:
        if not hub.has_rea:
            pytest.skip(f"REA 기동 실패: {hub.rea_error}")
        s3 = await hub.call("rea", "open_binary", path=str(paths["s3"]), provider_id="ghidra", _allow_error=True)
        c3 = await hub.call("rea", "open_binary", path=str(paths["c3"]), provider_id="ghidra", _allow_error=True)
        dg = await hub.call("rea", "open_binary", path=str(paths["c3-diag"]), provider_id="ghidra", _allow_error=True)
        procs = code = None
        if not dg.get("_error"):
            procs = await hub.call("rea", "list_procedures", _allow_error=True)
            code = await hub.call("rea", "procedure_pseudo_code", procedure="entry", _allow_error=True)
            await hub.call("rea", "close_binary", _allow_error=True)
    # Xtensa: REA 가 형식 단계에서 거부 (Ghidra 미도달)
    assert "unsupported ELF architecture" in (s3.get("_error") or ""), f"REA 가 Xtensa ELF 를 받아들이게 됨 — 갱신 필요: {s3}"
    # RISC-V soft-float: REA 의 Ghidra RISC-V 경로가 double-float 선언만 받음
    err = c3.get("_error") or ""
    assert "EF_RISCV_FLOAT_ABI_DOUBLE" in err and "architecture_unsupported" in err, f"REA 의 RISC-V soft-float 처리 변경 — 갱신 필요: {c3}"
    # 진단: ELF 배치는 적재·디컴파일 가능
    assert not dg.get("_error") and dg.get("architecture") == "riscv", dg
    assert any(p.get("address") == "0x40380000" for p in (procs or {}).get("normalized_result") or []), procs
    assert "param_1 + 1" in str((code or {}).get("normalized_result")), code
