"""ESP32 계열 펌웨어 형식 라이브러리 (순수 Python, 표준 라이브러리만).

공통 코어다: pweh-fwtriage 의 fw_esp_* 도구와 pweh-emu(칩 판정·NVS 비밀값 수집)가 함께 쓴다. pweh-fwtriage 에서 옮겨 왔고,
``fwtriage_mcp.espfmt`` 는 같은 객체를 다시 내보내는 shim 으로 남아 있다(설계 docs/design/emulation.md 결정 D1).

다루는 형식
- 칩 정보·주소 영역 (chip_info, classify_address): chip id 와 주소 창은 esptool v5.4.0 targets/*.py
  (IMAGE_CHIP_ID, IROM_MAP_*/DROM_MAP_*, MEMORY_MAP) 에서 옮겼다. MEMORY_MAP 의 포괄 영역(BYTE_ACCESSIBLE,
  MEM_INTERNAL)은 빼고, 같은 범위를 가리키는 두 이름(RTC_IRAM/RTC_DRAM 등)은 "A/B" 한 영역으로 합쳤다.
  플래시 창은 esptool 이 is_flash_addr 에 쓰는 IROM_MAP/DROM_MAP 을 따른다. 영역끼리 겹치지 않는다.
- 파티션 테이블 (parse_partition_table): ESP-IDF gen_esp32part.py 형식 — 32바이트 엔트리, MD5 엔트리, 0xFF 끝 표시.
- 앱/2단계 부트로더 이미지 (parse_app_image): esptool bin_image.py 의 ESP32FirmwareImage 형식.
- ELF 변환 (image_to_elf): 디컴파일러(REA/Ghidra 등)에 넣을 ELF32 ET_EXEC.
- NVS (parse_nvs, nvs_item_diff, nvs_set_primitives): ESP-IDF nvs_flash 페이지·엔트리 형식.

영역 kind (세그먼트 kind 도 같은 어휘)
  flash-text / flash-rodata  플래시 매핑 코드 / 상수 (IROM / DROM)
  flash                      코드·상수 창이 하나인 칩(C6·H2·C5·C61·P4). 세그먼트는 esp_app_desc_t 로 시작하면
                             flash-rodata, 아니면 flash-text 로 나눈다 (ESP-IDF 는 rodata 를 appdesc 로 시작한다)
  iram / dram / sram         내부 RAM 코드 / 데이터 / 코드·데이터 통합(IRAM/DRAM 이 같은 범위인 칩)
  rtc-text / rtc-data        RTC(LP) 메모리 (코드 실행 가능 / 데이터 전용)
  extram                     외부 RAM 데이터 창
  rom-text / rom-data        마스크 ROM (이미지 세그먼트가 여기 있으면 비정상)
  internal                   esptool MEM_INTERNAL2
  padding                    0x0–0x10000 (elf2image 가 넣는 load_addr 0 채움 세그먼트) — ELF 변환에서 뺀다
  unknown                    어느 영역에도 없음 (세그먼트만)

모든 파서는 순수 함수(파일·케이스 입출력 없음)이고, 깨진 입력에 예외를 던지지 않고 errors/warnings 목록으로 알린다.
예외: image_to_elf (EspFormatError), nvs_set_primitives (NvsError), 잘못된 인자 타입(TypeError/ValueError).
정수는 정수로 돌려준다 (16진 표시는 도구 계층에서 한다). 다이제스트(MD5/SHA256)는 16진 문자열이다.

검증 상태
- 앱 이미지·ELF: 테스트에서 esptool image-info / elf2image 를 오라클로 대조한다.
- 파티션 테이블·NVS: 로컬 오라클이 없다 (ESP-IDF 미설치, 다운로드 금지). NVS CRC 규약은 nvs_crc32 한 곳에서
  정의하고, parse_nvs 의 crc_summary 로 실제 덤프에서 규약이 맞는지 바로 드러나게 했다.
- Xtensa e_flags(0x300)는 binutils 기본값으로 알려진 값이고 로컬에서 확인하지 못했다. RISC-V e_flags 는
  zig cc 로 rv32imc(0x1, soft-float) / rv32imafc ilp32f(0x3) 를 확인했다.
"""

from __future__ import annotations

import hashlib
import re
import struct
import zlib
from typing import Any

__all__ = [
    "EspFormatError",
    "NvsError",
    "chip_info",
    "classify_address",
    "PARTITION_TABLE_DEFAULT_OFFSET",
    "PARTITION_TABLE_MAX_LEN",
    "parse_partition_table",
    "find_partition",
    "parse_app_image",
    "image_to_elf",
    "NVS_PAGE_SIZE",
    "NVS_DEFAULT_MAX_ITEMS",
    "nvs_crc32",
    "parse_nvs",
    "secret_hint",
    "nvs_item_diff",
    "nvs_set_primitives",
]


class EspFormatError(ValueError):
    """ESP 이미지를 변환할 수 없음 (image_to_elf)."""


class NvsError(ValueError):
    """NVS 수정 거부 (nvs_set_primitives). 이 예외가 나면 아무것도 바뀌지 않았다."""


def _as_bytes(data: Any) -> bytes:
    if isinstance(data, bytes):
        return data
    if isinstance(data, (bytearray, memoryview)):
        return bytes(data)
    raise TypeError(f"bytes/bytearray/memoryview 가 필요함 ({type(data).__name__})")


def _cstr(raw: bytes) -> str:
    """NUL 로 끝나는 고정 길이 문자열."""
    return raw.split(b"\0", 1)[0].decode("utf-8", "backslashreplace")


def _hexid(v: Any) -> str:
    try:
        return f"0x{int(v):x}"
    except (TypeError, ValueError):
        return repr(v)


def _cap(msgs: list[str], limit: int = 100) -> list[str]:
    """메시지 폭주 방지 (쓰레기 입력)."""
    if len(msgs) <= limit:
        return msgs
    return msgs[:limit] + [f"…(+{len(msgs) - limit}건 생략)"]


# ---------------------------------------------------------------------------
# 칩 정보 / 주소 영역
# ---------------------------------------------------------------------------

# kind → (flash, exec, write)
_KIND_ATTRS: dict[str, tuple[bool, bool, bool]] = {
    "padding": (False, False, False),
    "flash-text": (True, True, False),
    "flash-rodata": (True, False, False),
    "flash": (True, True, False),
    "iram": (False, True, True),
    "dram": (False, False, True),
    "sram": (False, True, True),
    "rtc-text": (False, True, True),
    "rtc-data": (False, False, True),
    "extram": (False, False, True),
    "rom-text": (False, True, False),
    "rom-data": (False, False, False),
    "internal": (False, False, True),
    "unknown": (False, True, True),  # 모르는 주소: 디컴파일러가 코드로도 볼 수 있게 RWX
}

# (name, start, end(미포함), kind). 출처: esptool v5.4.0 targets/<chip>.py. 시작 주소 순, 겹침 없음.
_REGIONS_ESP32: tuple[tuple[str, int, int, str], ...] = (
    ("PADDING", 0x00000000, 0x00010000, "padding"),
    ("DROM", 0x3F400000, 0x3F800000, "flash-rodata"),
    ("EXTRAM_DATA", 0x3F800000, 0x3FC00000, "extram"),
    ("RTC_DRAM", 0x3FF80000, 0x3FF82000, "rtc-data"),
    ("DRAM", 0x3FFAE000, 0x40000000, "dram"),
    ("IROM_MASK", 0x40000000, 0x40070000, "rom-text"),  # esptool MEMORY_MAP 은 이 마스크 ROM 도 "IROM" 이라 부른다
    ("CACHE_PRO", 0x40070000, 0x40078000, "iram"),
    ("CACHE_APP", 0x40078000, 0x40080000, "iram"),  # 2단계 부트로더 iram_loader_seg 가 여기
    ("IRAM", 0x40080000, 0x400A0000, "iram"),
    ("DIRAM_IRAM", 0x400A0000, 0x400BFFFC, "iram"),
    ("RTC_IRAM", 0x400C0000, 0x400C2000, "rtc-text"),
    ("IROM", 0x400D0000, 0x40400000, "flash-text"),
    ("RTC_DATA", 0x50000000, 0x50002000, "rtc-data"),
)
_REGIONS_ESP32S2: tuple[tuple[str, int, int, str], ...] = (
    ("PADDING", 0x00000000, 0x00010000, "padding"),
    ("DROM", 0x3F000000, 0x3F3F0000, "flash-rodata"),  # DROM_MAP (MEMORY_MAP 의 DROM 은 EXTRAM_DATA 와 겹친다)
    ("EXTRAM_DATA", 0x3F500000, 0x3FF80000, "extram"),
    ("RTC_DRAM", 0x3FF9E000, 0x3FFA0000, "rtc-data"),
    ("DRAM", 0x3FFB0000, 0x40000000, "dram"),
    ("IROM_MASK", 0x40000000, 0x4001A100, "rom-text"),
    ("IRAM", 0x40020000, 0x40070000, "iram"),
    ("RTC_IRAM", 0x40070000, 0x40072000, "rtc-text"),
    ("IROM", 0x40080000, 0x40B80000, "flash-text"),  # IROM_MAP
    ("RTC_DATA", 0x50000000, 0x50002000, "rtc-data"),
)
_REGIONS_ESP32S3: tuple[tuple[str, int, int, str], ...] = (
    ("PADDING", 0x00000000, 0x00010000, "padding"),
    ("DROM", 0x3C000000, 0x3E000000, "flash-rodata"),  # DROM_MAP (MEMORY_MAP 의 EXTRAM_DATA 0x3D000000– 포함)
    ("DRAM", 0x3FC88000, 0x3FD00000, "dram"),
    ("IROM_MASK", 0x40000000, 0x4001A100, "rom-text"),
    ("IRAM", 0x40370000, 0x403E0000, "iram"),
    ("IROM", 0x42000000, 0x44000000, "flash-text"),  # IROM_MAP
    ("RTC_DATA", 0x50000000, 0x50002000, "rtc-data"),
    ("RTC_IRAM/RTC_DRAM", 0x600FE000, 0x60100000, "rtc-text"),
)
_REGIONS_ESP32C3: tuple[tuple[str, int, int, str], ...] = (
    ("PADDING", 0x00000000, 0x00010000, "padding"),
    ("DROM", 0x3C000000, 0x3C800000, "flash-rodata"),
    ("DRAM", 0x3FC80000, 0x3FCE0000, "dram"),
    ("DROM_MASK", 0x3FF00000, 0x3FF20000, "rom-data"),
    ("IROM_MASK", 0x40000000, 0x40060000, "rom-text"),
    ("IRAM", 0x4037C000, 0x403E0000, "iram"),
    ("IROM", 0x42000000, 0x42800000, "flash-text"),
    ("RTC_IRAM/RTC_DRAM", 0x50000000, 0x50002000, "rtc-text"),
    ("MEM_INTERNAL2", 0x600FE000, 0x60100000, "internal"),
)
_REGIONS_ESP32C2: tuple[tuple[str, int, int, str], ...] = (
    ("PADDING", 0x00000000, 0x00010000, "padding"),
    ("DROM", 0x3C000000, 0x3C400000, "flash-rodata"),
    ("DRAM", 0x3FCA0000, 0x3FCE0000, "dram"),
    ("DROM_MASK", 0x3FF00000, 0x3FF50000, "rom-data"),
    ("IROM_MASK", 0x40000000, 0x40090000, "rom-text"),
    ("IRAM", 0x4037C000, 0x403C0000, "iram"),
    ("IROM", 0x42000000, 0x42400000, "flash-text"),
)
# ESP32-H2 는 esptool 에서 C6 의 MEMORY_MAP/IROM_MAP/DROM_MAP 을 그대로 물려받는다.
_REGIONS_ESP32C6: tuple[tuple[str, int, int, str], ...] = (
    ("PADDING", 0x00000000, 0x00010000, "padding"),
    ("IROM_MASK", 0x40000000, 0x4004AC00, "rom-text"),
    ("DROM_MASK", 0x4004AC00, 0x40050000, "rom-data"),
    ("IRAM/DRAM", 0x40800000, 0x40880000, "sram"),
    ("IROM/DROM", 0x42000000, 0x43000000, "flash"),  # MEMORY_MAP 의 IROM·DROM 이 같은 범위 (통합 플래시 창)
    ("RTC_IRAM/RTC_DRAM", 0x50000000, 0x50004000, "rtc-text"),
    ("MEM_INTERNAL2", 0x600FE000, 0x60100000, "internal"),
)
_REGIONS_ESP32C5: tuple[tuple[str, int, int, str], ...] = (
    ("PADDING", 0x00000000, 0x00010000, "padding"),
    ("IROM_MASK", 0x40000000, 0x4003A000, "rom-text"),
    ("DROM_MASK", 0x4003A000, 0x40040000, "rom-data"),
    ("IRAM/DRAM", 0x40800000, 0x40860000, "sram"),
    ("IROM/DROM", 0x42000000, 0x44000000, "flash"),
    ("RTC_IRAM/RTC_DRAM", 0x50000000, 0x50004000, "rtc-text"),
    ("MEM_INTERNAL2", 0x600FE000, 0x60100000, "internal"),
)
# ESP32-C61: esptool 은 IROM_MAP/DROM_MAP 을 C6 에서 물려받지만(0x42000000–0x43000000) MEMORY_MAP 은
# 0x42000000–0x44000000 이다. 여기서는 MEMORY_MAP 을 따른다.
_REGIONS_ESP32C61: tuple[tuple[str, int, int, str], ...] = (
    ("PADDING", 0x00000000, 0x00010000, "padding"),
    ("IROM_MASK", 0x40000000, 0x4004AC00, "rom-text"),
    ("DROM_MASK", 0x4004AC00, 0x40050000, "rom-data"),
    ("IRAM/DRAM", 0x40800000, 0x40860000, "sram"),
    ("IROM/DROM", 0x42000000, 0x44000000, "flash"),
    ("RTC_IRAM/RTC_DRAM", 0x50000000, 0x50004000, "rtc-text"),
    ("MEM_INTERNAL2", 0x600FE000, 0x60100000, "internal"),
)
_REGIONS_ESP32P4: tuple[tuple[str, int, int, str], ...] = (
    ("PADDING", 0x00000000, 0x00010000, "padding"),
    ("IROM/DROM", 0x40000000, 0x4C000000, "flash"),
    ("IROM_MASK/DROM_MASK", 0x4FC00000, 0x4FC20000, "rom-text"),
    ("IRAM/DRAM", 0x4FF00000, 0x4FFA0000, "sram"),
    ("RTC_IRAM/RTC_DRAM", 0x50108000, 0x50110000, "rtc-text"),
    ("MEM_INTERNAL2", 0x600FE000, 0x60100000, "internal"),
)

_XTENSA_EFLAGS = 0x300  # EF_XTENSA_XT_INSN | EF_XTENSA_XT_LIT (binutils 기본값으로 알려짐, 로컬 미검증)
_RV32_SOFT = 0x1  # EF_RISCV_RVC, soft-float(ilp32) — ESP-IDF 의 rv32imc/rv32imac
_RV32_SINGLE = 0x3  # EF_RISCV_RVC | EF_RISCV_FLOAT_ABI_SINGLE — ESP32-P4 (rv32imafc, ilp32f)

# chip_id → (이름, 아키텍처, e_flags, 영역). chip_id 는 esptool IMAGE_CHIP_ID.
_CHIPS: dict[int, tuple[str, str, int, tuple[tuple[str, int, int, str], ...]]] = {
    0: ("ESP32", "xtensa", _XTENSA_EFLAGS, _REGIONS_ESP32),
    2: ("ESP32-S2", "xtensa", _XTENSA_EFLAGS, _REGIONS_ESP32S2),
    5: ("ESP32-C3", "riscv", _RV32_SOFT, _REGIONS_ESP32C3),
    9: ("ESP32-S3", "xtensa", _XTENSA_EFLAGS, _REGIONS_ESP32S3),
    12: ("ESP32-C2", "riscv", _RV32_SOFT, _REGIONS_ESP32C2),
    13: ("ESP32-C6", "riscv", _RV32_SOFT, _REGIONS_ESP32C6),
    16: ("ESP32-H2", "riscv", _RV32_SOFT, _REGIONS_ESP32C6),
    18: ("ESP32-P4", "riscv", _RV32_SINGLE, _REGIONS_ESP32P4),
    20: ("ESP32-C61", "riscv", _RV32_SOFT, _REGIONS_ESP32C61),
    23: ("ESP32-C5", "riscv", _RV32_SOFT, _REGIONS_ESP32C5),
}
_E_MACHINE = {"xtensa": 94, "riscv": 243}

# 플래시 헤더 이름표 (esptool cmds.py FLASH_MODES, targets FLASH_SIZES/FLASH_FREQUENCY)
_SPI_MODES = {0: "qio", 1: "qout", 2: "dio", 3: "dout"}
_SPI_SIZES = {0: "1MB", 1: "2MB", 2: "4MB", 3: "8MB", 4: "16MB", 5: "32MB", 6: "64MB", 7: "128MB"}
_FREQ_ESP32 = {0xF: "80m", 0x0: "40m", 0x1: "26m", 0x2: "20m"}
_FREQ_80_40_20 = {0xF: "80m", 0x0: "40m", 0x2: "20m"}
_SPI_FREQS: dict[int, dict[int, str]] = {
    0: _FREQ_ESP32, 2: _FREQ_ESP32, 5: _FREQ_ESP32, 9: _FREQ_ESP32, 18: _FREQ_ESP32,
    12: {0xF: "60m", 0x0: "30m", 0x1: "20m", 0x2: "15m"},
    13: {0x0: "80m/40m", 0x2: "20m"},  # esptool: C6 은 ROM 분주 문제로 80m 도 0x0 으로 쓴다
    16: {0xF: "48m", 0x0: "24m", 0x1: "16m", 0x2: "12m"},
    20: _FREQ_80_40_20, 23: _FREQ_80_40_20,
}


def _region_dict(r: tuple[str, int, int, str]) -> dict[str, Any]:
    name, start, end, kind = r
    flash, ex, wr = _KIND_ATTRS[kind]
    return {"name": name, "start": start, "end": end, "kind": kind, "flash": flash, "exec": ex, "write": wr}


def chip_info(chip_id: int) -> dict[str, Any]:
    """chip id(이미지 확장 헤더의 값) → 이름·아키텍처·ELF e_machine/e_flags·주소 영역 목록.

    모르는 id 는 name='unknown(0x..)', arch='unknown', e_machine=0, regions=[] 이다.
    """
    spec = _CHIPS.get(chip_id) if isinstance(chip_id, int) else None
    if spec is None:
        return {"chip_id": chip_id, "name": f"unknown({_hexid(chip_id)})", "arch": "unknown", "e_machine": 0, "e_flags": 0, "regions": []}
    name, arch, eflags, regions = spec
    return {"chip_id": chip_id, "name": name, "arch": arch, "e_machine": _E_MACHINE[arch], "e_flags": eflags,
            "regions": [_region_dict(r) for r in regions]}


def classify_address(chip_id: int, addr: int) -> dict[str, Any] | None:
    """addr 를 담은 영역 dict (chip_info 의 regions 원소와 같은 모양), 없으면 None."""
    spec = _CHIPS.get(chip_id) if isinstance(chip_id, int) else None
    if spec is None or not isinstance(addr, int):
        return None
    for r in spec[3]:
        if r[1] <= addr < r[2]:
            return _region_dict(r)
    return None


# ---------------------------------------------------------------------------
# 파티션 테이블
# ---------------------------------------------------------------------------

PARTITION_TABLE_DEFAULT_OFFSET = 0x8000
PARTITION_TABLE_MAX_LEN = 0xC00  # ESP-IDF MAX_PARTITION_LENGTH (95 엔트리 + MD5)
_PT_SCAN_LIMIT = 0x100000
_PT_MAGIC = b"\xAA\x50"
_PT_MD5_MAGIC = b"\xEB\xEB" + b"\xFF" * 14
_PT_ENTRY = struct.Struct("<2sBBII16sI")
_PT_FLAG_ENCRYPTED = 0x1
_PT_FLAG_READONLY = 0x2

_PT_TYPES = {0x00: "app", 0x01: "data", 0x02: "bootloader", 0x03: "partition_table"}
_PT_SUBTYPES: dict[int, dict[int, str]] = {
    0x00: {0x00: "factory", 0x20: "test", **{0x10 + i: f"ota_{i}" for i in range(16)}},
    0x01: {0x00: "ota", 0x01: "phy", 0x02: "nvs", 0x03: "coredump", 0x04: "nvs_keys", 0x05: "efuse", 0x06: "undefined",
           0x80: "esphttpd", 0x81: "fat", 0x82: "spiffs", 0x83: "littlefs"},
    0x02: {0x00: "primary", 0x01: "ota"},
    0x03: {0x00: "primary", 0x01: "ota"},
}
_PT_FS_SUBTYPES = (0x80, 0x81, 0x82, 0x83)

_PT_NOT_A_SAVE_NOTES = {
    (0x01, 0x00): "OTA 선택 데이터 (otadata) — 세이브 아님",
    (0x01, 0x01): "RF 보정 데이터 (phy_init) — 세이브 아님",
    (0x01, 0x03): "코어 덤프 영역 — 세이브 아님 (충돌 시 메모리 내용이 남을 수 있음)",
    (0x01, 0x04): "NVS 암호화 키 파티션 — 키 값은 비밀, 내보내지 않는다",
    (0x01, 0x05): "가상 eFuse 영역 — 세이브 아님",
}


def _pt_label_ok(raw: bytes) -> bool:
    """레이블: 출력 가능한 ASCII 뒤에 NUL 만 (gen_esp32part 는 16s 로 NUL 채움)."""
    head, sep, tail = raw.partition(b"\0")
    if any(c < 0x20 or c > 0x7E for c in head):
        return False
    return not sep or tail.count(0) == len(tail)


def _pt_looks_like_table(buf: bytes, off: int) -> bool:
    if off < 0 or off + 32 > len(buf) or buf[off:off + 2] != _PT_MAGIC:
        return False
    return _pt_label_ok(buf[off + 12:off + 28])


def _pt_names(ptype: int, subtype: int) -> tuple[str, str]:
    if ptype in _PT_TYPES:
        type_name = _PT_TYPES[ptype]
    elif 0x40 <= ptype <= 0xFE:
        type_name = f"custom(0x{ptype:02x})"
    else:
        type_name = f"unknown(0x{ptype:02x})"
    sub = _PT_SUBTYPES.get(ptype, {}).get(subtype)
    if sub is None:
        custom = (ptype == 0x01 and 0x40 <= subtype <= 0xFE) or 0x40 <= ptype <= 0xFE
        sub = f"custom(0x{subtype:02x})" if custom else f"unknown(0x{subtype:02x})"
    return type_name, sub


def _pt_write_class(ptype: int, subtype: int) -> str:
    if ptype == 0x01:
        if subtype == 0x02:
            return "nvs"
        if subtype in _PT_FS_SUBTYPES:
            return "filesystem-analysis-only"
        if subtype == 0x06 or 0x40 <= subtype <= 0xFE:
            return "raw-user-data"
        return "not-a-save"
    if 0x40 <= ptype <= 0xFE:
        return "raw-user-data"
    return "not-a-save"


def _pt_class_note(ptype: int, subtype: int, wclass: str) -> str:
    if wclass == "nvs":
        return "NVS — 키 단위 분석·패치 후보 (parse_nvs)"
    if wclass == "filesystem-analysis-only":
        return "파일 시스템(fat/spiffs/littlefs/esphttpd) — 파일 시스템 수준 해석 전까지 분석만, 원시 패치 대상 아님"
    if wclass == "raw-user-data":
        return "원시 사용자 데이터 — 형식을 먼저 해석해야 함 (raw-region 패치 후보)"
    if ptype == 0x00:
        return "앱 펌웨어 이미지 (parse_app_image) — 세이브 아님"
    if ptype in (0x02, 0x03):
        return "부트로더/파티션 테이블 영역 — 세이브 아님"
    return _PT_NOT_A_SAVE_NOTES.get((ptype, subtype), "알 수 없는 종류 — 세이브로 취급하지 않음")


def parse_partition_table(data: bytes | bytearray | memoryview, offset: int | None = None, *, data_len: int | None = None,
                          base_offset: int = 0) -> dict[str, Any]:
    """ESP-IDF 파티션 테이블 해석.

    - base_offset: data 가 파일(플래시)의 어느 절대 오프셋에서 시작하는지 (기본 0). 큰 파일에서 테이블 근처만 읽어 넘길 때 쓴다
      (예: data = 파일[off : off+0xC20], base_offset=off). 결과의 offset 과 메시지의 위치는 모두 절대 오프셋이다.
    - offset: 테이블의 절대 오프셋 (data 안 위치 = offset - base_offset). 지정하면 그 위치의 AA50 매직만 확인한다.
      None 이면 절대 0x8000 → 0x1000 단위 다른 절대 오프셋(data 앞쪽 min(len, 0x100000) 안) → data 시작(테이블만 담은 이미지) 순으로 찾는다.
    - data_len: 실제 파일(플래시) 크기 — "데이터 끝을 넘음" 검사의 기준. None 이면 base_offset 이 0 일 때 len(data),
      base_offset 이 0 이 아니면 크기를 모르므로 그 검사를 하지 않는다. 범위 검사는 테이블이 절대 오프셋 0 보다 뒤에 있을 때
      (전체 플래시 이미지)만 한다.
    엔트리 write_class: 'nvs' | 'filesystem-analysis-only' | 'raw-user-data' | 'not-a-save'.
    """
    buf = _as_bytes(data)
    if isinstance(base_offset, bool) or not isinstance(base_offset, int) or base_offset < 0:
        raise ValueError(f"base_offset 는 0 이상의 정수여야 함: {base_offset!r}")
    if data_len is not None and (isinstance(data_len, bool) or not isinstance(data_len, int) or data_len < 0):
        raise ValueError(f"data_len 은 0 이상의 정수 또는 None 이어야 함: {data_len!r}")
    warnings: list[str] = []
    errors: list[str] = []
    out: dict[str, Any] = {
        "found": False, "offset": None, "entries": [],
        "md5": {"present": False, "ok": None, "stored": None, "computed": None},
        "nvs_keys_present": False, "warnings": warnings, "errors": errors,
    }
    if offset is None:
        # 후보는 data 안 위치(local). 절대 0x8000 → 절대 0x1000 경계 → data 시작
        cands: list[int] = []
        l8 = PARTITION_TABLE_DEFAULT_OFFSET - base_offset
        if l8 >= 0:
            cands.append(l8)
        first = (-base_offset) % 0x1000 or 0x1000
        cands += [o for o in range(first, min(len(buf), _PT_SCAN_LIMIT), 0x1000) if o != l8]
        cands.append(0)
        local = next((o for o in cands if _pt_looks_like_table(buf, o)), None)
        if local is None:
            errors.append(f"파티션 테이블을 찾지 못함 (절대 0x8000, 0x1000 정렬 오프셋 0x{base_offset:x}~0x{base_offset + min(len(buf), _PT_SCAN_LIMIT):x}, "
                          f"data 시작 0x{base_offset:x} 에 AA50 엔트리 없음)")
            return out
    else:
        local = offset - base_offset if isinstance(offset, int) and not isinstance(offset, bool) else -1
        if local < 0 or buf[local:local + 2] != _PT_MAGIC:
            # 오프셋을 지정하면 매직만 본다 (레이블 검사는 자동 탐색의 오탐 방지용)
            where = " (data 시작 base_offset 앞)" if isinstance(offset, int) and local < 0 else ""
            errors.append(f"오프셋 {_hexid(offset)} 에 파티션 테이블(AA50 엔트리)이 없음{where}")
            return out
    table_off = base_offset + local
    out["found"] = True
    out["offset"] = table_off
    if table_off != PARTITION_TABLE_DEFAULT_OFFSET and table_off != 0:
        warnings.append(f"파티션 테이블이 기본 위치(0x8000)가 아닌 0x{table_off:x} 에 있음 (CONFIG_PARTITION_TABLE_OFFSET 변경)")

    entries: list[dict[str, Any]] = []
    end_limit = min(len(buf), local + PARTITION_TABLE_MAX_LEN)
    pos = local
    terminated = False
    md5_seen = False
    while pos + 32 <= end_limit:
        raw = buf[pos:pos + 32]
        if raw[:2] == _PT_MAGIC:
            if md5_seen:
                warnings.append(f"0x{base_offset + pos:x}: MD5 엔트리 뒤에 파티션 엔트리가 있음")
            _magic, ptype, subtype, poff, psize, label_raw, flags = _PT_ENTRY.unpack(raw)
            type_name, subtype_name = _pt_names(ptype, subtype)
            wclass = _pt_write_class(ptype, subtype)
            entries.append({
                "index": len(entries), "label": _cstr(label_raw), "type": ptype, "type_name": type_name,
                "subtype": subtype, "subtype_name": subtype_name, "offset": poff, "size": psize, "end": poff + psize,
                "flags": flags, "encrypted": bool(flags & _PT_FLAG_ENCRYPTED), "readonly": bool(flags & _PT_FLAG_READONLY),
                "write_class": wclass, "write_blockers": [], "notes": [_pt_class_note(ptype, subtype, wclass)],
            })
            if not _pt_label_ok(label_raw):
                warnings.append(f"엔트리 {len(entries) - 1}: 레이블에 출력 불가 문자")
        elif raw[:16] == _PT_MD5_MAGIC:
            stored = raw[16:32]
            computed = hashlib.md5(buf[local:pos], usedforsecurity=False).digest()  # 무결성 확인용 (보안 용도 아님)
            ok = stored == computed
            out["md5"] = {"present": True, "ok": ok, "stored": stored.hex(), "computed": computed.hex()}
            if not ok:
                errors.append(f"파티션 테이블 MD5 불일치 (저장 {stored.hex()}, 계산 {computed.hex()}) — 부트로더가 거부할 수 있음")
            md5_seen = True
        elif raw == b"\xFF" * 32:
            terminated = True
            break
        else:
            errors.append(f"0x{base_offset + pos:x}: 알 수 없는 엔트리 (매직 {raw[:2].hex()}) — 여기서 해석을 멈춤")
            terminated = True
            break
        pos += 32
    if not terminated:
        warnings.append("테이블이 0xFF 끝 표시 없이 끝남 (잘렸거나 최대 길이 0xC00 초과)")
    if not entries:
        errors.append("파티션 엔트리가 없음")
    out["entries"] = entries

    nvs_keys = any(e["type"] == 0x01 and e["subtype"] == 0x04 for e in entries)
    out["nvs_keys_present"] = nvs_keys
    embedded = table_off > 0
    total = data_len if data_len is not None else (len(buf) if base_offset == 0 else None)
    labels: dict[str, int] = {}
    for e in entries:
        if e["label"] in labels:
            warnings.append(f"중복 레이블 '{e['label']}' (엔트리 {labels[e['label']]}, {e['index']})")
        else:
            labels[e["label"]] = e["index"]
        if e["encrypted"] and e["write_class"] in ("nvs", "raw-user-data"):
            e["write_blockers"].append("encrypted 플래그 — 플래시 암호화된 파티션 (덤프 값은 암호문, 평문 패치 불가)")
        if e["write_class"] == "nvs":
            if nvs_keys:
                e["write_blockers"].append("nvs_keys 파티션 있음 — NVS 암호화 사용 가능성 높음 (평문 패치 불가)")
            if e["size"] % 0x1000:
                warnings.append(f"'{e['label']}': NVS 크기 0x{e['size']:x} 가 페이지(0x1000)의 배수가 아님")
            if e["readonly"]:
                e["notes"].append("readonly 플래그 — 앱이 쓰지 않는 NVS(공장 데이터 등)일 수 있음")
        if e["flags"] & ~(_PT_FLAG_ENCRYPTED | _PT_FLAG_READONLY):
            warnings.append(f"'{e['label']}': 알 수 없는 플래그 비트 0x{e['flags']:08x}")
        align = 0x10000 if e["type"] == 0x00 else 0x1000
        if e["offset"] % align:
            warnings.append(f"'{e['label']}': 오프셋 0x{e['offset']:x} 가 0x{align:x} 정렬이 아님"
                            + (" (MMU 페이지 크기를 바꾼 칩은 예외일 수 있음)" if e["type"] == 0x00 else ""))
        if e["size"] == 0:
            warnings.append(f"'{e['label']}': 크기 0")
        if embedded:
            if total is not None and e["end"] > total:
                warnings.append(f"'{e['label']}': 0x{e['offset']:x}+0x{e['size']:x} 가 데이터 끝(0x{total:x})을 넘음 (덤프가 잘렸거나 플래시 크기 불일치)")
            if e["offset"] < table_off + 0x1000 and e["end"] > table_off:
                warnings.append(f"'{e['label']}': 파티션 테이블 섹터(0x{table_off:x}–0x{table_off + 0x1000:x})와 겹침")
    for i, a in enumerate(entries):
        for b in entries[i + 1:]:
            if a["size"] and b["size"] and a["offset"] < b["end"] and b["offset"] < a["end"]:
                warnings.append(f"파티션 겹침: '{a['label']}'(0x{a['offset']:x}–0x{a['end']:x}) ↔ '{b['label']}'(0x{b['offset']:x}–0x{b['end']:x})")
    out["warnings"] = _cap(warnings)
    out["errors"] = _cap(errors)
    return out


def find_partition(table: dict[str, Any], label: str) -> dict[str, Any] | None:
    """parse_partition_table 결과에서 레이블이 정확히 같은 첫 엔트리."""
    for e in (table or {}).get("entries") or []:
        if e.get("label") == label:
            return e
    return None


# ---------------------------------------------------------------------------
# 앱 / 2단계 부트로더 이미지
# ---------------------------------------------------------------------------

_ESP_IMAGE_MAGIC = 0xE9
_ESP8266_V2_MAGIC = 0xEA
_CHECKSUM_MAGIC = 0xEF
_APP_DESC_MAGIC = 0xABCD5432
_APP_DESC = struct.Struct("<II8s32s32s16s16s32s32sHHB3s72s")  # esp_app_desc_t (256 바이트)
_BOOTLOADER_DESC_MAGIC = 0x50
_BOOTLOADER_DESC = struct.Struct("<B3sI32s24s16s")  # esp_bootloader_desc_t (80 바이트)
_MAX_SEGMENTS = 16  # ESP-IDF ESP_IMAGE_MAX_SEGMENTS, esptool verify()
_MAX_SEGMENT_LEN = 0x1000000  # esptool save_segment 의 16 MB 한도
_FLASH_KINDS = ("flash-text", "flash-rodata", "flash")


def _xor_bytes(b: bytes) -> int:
    """모든 바이트의 XOR (큰 정수를 반씩 접어 C 속도로 계산)."""
    n = len(b)
    if n == 0:
        return 0
    x = int.from_bytes(b, "little")
    while n > 1:
        half = (n + 1) // 2
        x = (x & ((1 << (8 * half)) - 1)) ^ (x >> (8 * half))
        n = half
    return x & 0xFF


def _parse_app_desc(buf: bytes, seg: dict[str, Any], warnings: list[str]) -> dict[str, Any]:
    raw = buf[seg["file_offset"]:seg["file_offset"] + min(seg["size"], _APP_DESC.size)]
    if len(raw) < _APP_DESC.size:
        warnings.append(f"esp_app_desc_t 가 {len(raw)} 바이트뿐 (256 필요) — 나머지는 0 으로 보고 해석")
        raw = raw + b"\0" * (_APP_DESC.size - len(raw))
    (magic, secure_version, _r1, version, project, time_, date, idf_ver, elf_sha, min_efuse, max_efuse, mmu_log2, _r3,
     _r2) = _APP_DESC.unpack(raw)
    return {
        "magic_ok": magic == _APP_DESC_MAGIC, "secure_version": secure_version, "version": _cstr(version),
        "project_name": _cstr(project), "time": _cstr(time_), "date": _cstr(date), "idf_ver": _cstr(idf_ver),
        "app_elf_sha256": elf_sha.hex(), "min_efuse_blk_rev_full": min_efuse, "max_efuse_blk_rev_full": max_efuse,
        "mmu_page_size": (1 << mmu_log2) if mmu_log2 else None, "segment": seg["index"],
    }


def _parse_bootloader_desc(buf: bytes, seg: dict[str, Any]) -> dict[str, Any]:
    raw = buf[seg["file_offset"]:seg["file_offset"] + _BOOTLOADER_DESC.size]
    magic, _r1, version, idf_ver, date_time, _r2 = _BOOTLOADER_DESC.unpack(raw)
    return {"magic_ok": magic == _BOOTLOADER_DESC_MAGIC, "version": version, "idf_ver": _cstr(idf_ver),
            "date_time": _cstr(date_time), "segment": seg["index"]}


def _esp8266_like(buf: bytes, offset: int) -> bool:
    """ESP8266 v1 이미지(확장 헤더 없음)면 오프셋 8 에 첫 세그먼트 헤더(DRAM/IRAM 주소)가 온다."""
    load = struct.unpack_from("<I", buf, offset + 8)[0]
    return 0x3FFE8000 <= load < 0x40000000 or 0x40100000 <= load < 0x40108000


def parse_app_image(data: bytes | bytearray | memoryview, offset: int = 0) -> dict[str, Any]:
    """ESP32 계열 앱 또는 2단계 부트로더 이미지(매직 0xE9 + 16바이트 확장 헤더) 해석.

    - segments[].file_offset 은 data 안의 절대 위치(세그먼트 데이터 시작), header_offset 은 그 8바이트 앞
      (esptool image-info 의 "File offs" 는 이미지 시작 기준 header_offset 이다).
    - 체크섬 바이트 위치(이미지 시작 기준 pos % 16 == 15)와 SHA256 범위(이미지 시작~체크섬 바이트)는 offset 기준이다.
    - segments_complete=False 면 세그먼트를 끝까지 읽지 못한 것이다 (image_to_elf 가 거부한다).
    - 모든 읽기는 len(data) 안으로 제한되고 세그먼트 수는 최대 255 이므로 쓰레기 입력에도 끝난다.
    """
    buf = _as_bytes(data)
    warnings: list[str] = []
    errors: list[str] = []
    out: dict[str, Any] = {
        "ok": False, "offset": offset, "image_type": "unknown", "chip_id": None, "chip": None, "arch": None, "e_machine": None,
        "entry": None, "segment_count": None, "spi_mode": None, "spi_mode_name": None, "spi_speed": None, "spi_speed_name": None,
        "spi_size": None, "spi_size_name": None, "wp_pin": None, "spi_pin_drv": None, "min_chip_rev": None,
        "min_chip_rev_full": None, "max_chip_rev_full": None, "hash_appended": None, "segments": [], "segments_complete": False,
        "checksum": {"stored": None, "computed": None, "ok": None},
        "sha256": {"present": False, "stored": None, "computed": None, "ok": None},
        "image_size": None, "app_desc": None, "bootloader_desc": None, "warnings": warnings, "errors": errors,
    }
    n = len(buf)
    if not isinstance(offset, int) or offset < 0 or offset + 24 > n:
        errors.append(f"오프셋 {_hexid(offset)} 에서 이미지 헤더(24바이트)를 읽을 수 없음 (데이터 0x{n:x} 바이트)")
        return out
    magic = buf[offset]
    if magic == _ESP8266_V2_MAGIC:
        errors.append("ESP8266 v2 이미지(매직 0xEA) — ESP32 계열 형식이 아니라 해석하지 않음")
        return out
    if magic != _ESP_IMAGE_MAGIC:
        errors.append(f"매직 0x{magic:02x} — ESP 이미지(0xE9)가 아님")
        return out
    seg_count, spi_mode, speed_size, entry = struct.unpack_from("<BBBI", buf, offset + 1)
    wp_pin, drv0, drv1, drv2, chip_id, min_rev, min_rev_full, max_rev_full = struct.unpack_from("<BBBBHBHH", buf, offset + 8)
    hash_byte = buf[offset + 23]
    if hash_byte not in (0, 1) or chip_id not in _CHIPS:
        if _esp8266_like(buf, offset):
            errors.append("ESP8266 v1 이미지로 보임 (16바이트 확장 헤더 없음, 오프셋 8 에 세그먼트 헤더) — ESP32 계열 형식이 아니라 해석하지 않음")
            return out
        if hash_byte not in (0, 1):
            errors.append(f"확장 헤더의 hash_appended 0x{hash_byte:02x} (0/1 이어야 함) — ESP32 계열 이미지가 아니거나 손상")
            return out
        warnings.append(f"알 수 없는 chip_id {chip_id} — 구조만 해석 (주소 영역·ELF 변환 불가)")
    info = chip_info(chip_id)
    out.update({
        "chip_id": chip_id, "chip": info["name"], "arch": info["arch"], "e_machine": info["e_machine"], "entry": entry,
        "segment_count": seg_count, "spi_mode": spi_mode, "spi_mode_name": _SPI_MODES.get(spi_mode),
        "spi_speed": speed_size & 0x0F, "spi_speed_name": _SPI_FREQS.get(chip_id, {}).get(speed_size & 0x0F),
        "spi_size": speed_size >> 4, "spi_size_name": _SPI_SIZES.get(speed_size >> 4), "wp_pin": wp_pin,
        "spi_pin_drv": [drv0, drv1, drv2], "min_chip_rev": min_rev, "min_chip_rev_full": min_rev_full,
        "max_chip_rev_full": max_rev_full, "hash_appended": hash_byte == 1,
    })
    if spi_mode not in _SPI_MODES:
        warnings.append(f"알 수 없는 SPI 모드 {spi_mode}")
    if seg_count == 0:
        warnings.append("세그먼트가 0개")
    if seg_count > _MAX_SEGMENTS:
        errors.append(f"세그먼트 수 {seg_count} > {_MAX_SEGMENTS} (ESP-IDF 최대) — 손상 또는 다른 형식")

    segs: list[dict[str, Any]] = []
    pos = offset + 24
    complete = True
    for i in range(seg_count):
        if pos + 8 > n:
            errors.append(f"세그먼트 {i} 헤더가 데이터 끝을 넘음 (0x{pos:x})")
            complete = False
            break
        load_addr, size = struct.unpack_from("<II", buf, pos)
        if size >= _MAX_SEGMENT_LEN or pos + 8 + size > n:
            errors.append(f"세그먼트 {i} 길이 0x{size:x} (0x{pos + 8:x}부터) 가 데이터 끝(0x{n:x})을 넘거나 16 MB 이상")
            complete = False
            break
        region = classify_address(chip_id, load_addr)
        segs.append({"index": i, "load_addr": load_addr, "size": size, "header_offset": pos, "file_offset": pos + 8,
                     "region": region["name"] if region else None, "kind": region["kind"] if region else "unknown",
                     "_region_end": region["end"] if region else None})
        pos += 8 + size

    # 통합 플래시 창: esp_app_desc_t 로 시작하는 세그먼트는 rodata, 나머지는 text 로 본다
    for s in segs:
        if s["kind"] == "flash":
            starts_desc = s["size"] >= 4 and struct.unpack_from("<I", buf, s["file_offset"])[0] == _APP_DESC_MAGIC
            s["kind"] = "flash-rodata" if starts_desc else "flash-text"
    for s in segs:
        end = s.pop("_region_end")
        if s["region"] is None and info["regions"]:
            warnings.append(f"세그먼트 {s['index']} 주소 0x{s['load_addr']:08x} 가 {info['name']} 의 알려진 영역 밖")
        elif end is not None and s["load_addr"] + s["size"] > end:
            warnings.append(f"세그먼트 {s['index']} (0x{s['load_addr']:08x}+0x{s['size']:x}) 가 영역 {s['region']} 경계를 넘음")
        if s["kind"] in ("rom-text", "rom-data"):
            warnings.append(f"세그먼트 {s['index']} 가 마스크 ROM 영역({s['region']})에 있음 — 비정상")
    real = [s for s in segs if s["kind"] != "padding" and s["size"]]
    for i, a in enumerate(real):
        for b in real[i + 1:]:
            if a["load_addr"] < b["load_addr"] + b["size"] and b["load_addr"] < a["load_addr"] + a["size"]:
                warnings.append(f"세그먼트 {a['index']}·{b['index']} 의 적재 주소 범위가 겹침")
    out["segments"] = segs
    out["segments_complete"] = complete

    if complete:
        rel = pos - offset
        cks_pos = pos + (15 - rel % 16)
        if cks_pos >= n:
            errors.append(f"체크섬 바이트 위치 0x{cks_pos:x} 가 데이터 끝을 넘음 (잘린 이미지)")
        else:
            computed = _CHECKSUM_MAGIC
            for s in segs:
                computed ^= _xor_bytes(buf[s["file_offset"]:s["file_offset"] + s["size"]])
            stored = buf[cks_pos]
            ok = stored == computed
            out["checksum"] = {"stored": stored, "computed": computed, "ok": ok}
            if not ok:
                errors.append(f"체크섬 불일치 (저장 0x{stored:02x}, 계산 0x{computed:02x})")
            image_end = cks_pos + 1
            if hash_byte == 1:
                digest = hashlib.sha256(buf[offset:image_end]).digest()
                if image_end + 32 > n:
                    out["sha256"] = {"present": True, "stored": None, "computed": digest.hex(), "ok": None}
                    errors.append("덧붙은 SHA256 이 데이터 끝을 넘음 (잘린 이미지)")
                    out["image_size"] = image_end - offset
                else:
                    sha_stored = buf[image_end:image_end + 32]
                    sok = sha_stored == digest
                    out["sha256"] = {"present": True, "stored": sha_stored.hex(), "computed": digest.hex(), "ok": sok}
                    if not sok:
                        errors.append("덧붙은 SHA256 불일치")
                    out["image_size"] = image_end + 32 - offset
            else:
                out["image_size"] = image_end - offset

    # esp_app_desc_t: 첫 세그먼트, 아니면 (esptool 처럼) 첫 DROM(flash-rodata) 세그먼트
    app_desc = None
    cands = segs[:1] + [s for s in segs[1:] if s["kind"] == "flash-rodata"][:1]
    for s in cands:
        if s["size"] >= 4 and struct.unpack_from("<I", buf, s["file_offset"])[0] == _APP_DESC_MAGIC:
            app_desc = _parse_app_desc(buf, s, warnings)
            break
    if app_desc is None and any(s["kind"] in _FLASH_KINDS for s in segs):
        app_desc = {"magic_ok": False, "secure_version": None, "version": None, "project_name": None, "time": None,
                    "date": None, "idf_ver": None, "app_elf_sha256": None, "min_efuse_blk_rev_full": None,
                    "max_efuse_blk_rev_full": None, "mmu_page_size": None, "segment": None}
        warnings.append("플래시 매핑 세그먼트가 있는데 esp_app_desc_t 매직(0xABCD5432)이 없음")
    out["app_desc"] = app_desc
    if app_desc is None or not app_desc["magic_ok"]:
        for s in segs[:1] + [s for s in segs if s["kind"] in ("dram", "sram")]:
            if s["size"] >= _BOOTLOADER_DESC.size and buf[s["file_offset"]] == _BOOTLOADER_DESC_MAGIC:
                out["bootloader_desc"] = _parse_bootloader_desc(buf, s)
                break
    if app_desc and app_desc["magic_ok"]:
        out["image_type"] = "app"
    elif out["bootloader_desc"]:
        out["image_type"] = "bootloader"
    if complete and entry and real and not any(s["load_addr"] <= entry < s["load_addr"] + s["size"] for s in real):
        warnings.append(f"엔트리 0x{entry:08x} 가 어느 세그먼트에도 없음")
    out["warnings"] = _cap(warnings)
    out["errors"] = _cap(errors)
    out["ok"] = not errors
    return out


# ---------------------------------------------------------------------------
# ELF 변환
# ---------------------------------------------------------------------------

_KIND_SECTION = {
    "flash-text": ".flash.text", "flash-rodata": ".flash.rodata", "flash": ".flash.text",
    "iram": ".iram0.text", "sram": ".iram0.text", "dram": ".dram0.data",
    "rtc-text": ".rtc.text", "rtc-data": ".rtc.data", "extram": ".ext_ram.data",
    "rom-text": ".rom.text", "rom-data": ".rom.rodata", "internal": ".internal.data", "unknown": ".unknown",
}
_PF_X, _PF_W, _PF_R = 1, 2, 4
_SHF_WRITE, _SHF_ALLOC, _SHF_EXECINSTR = 1, 2, 4


def image_to_elf(data: bytes | bytearray | memoryview, parsed: dict[str, Any]) -> bytes:
    """parse_app_image 결과의 세그먼트로 ELF32 LE ET_EXEC 를 만든다.

    - 세그먼트마다 PT_LOAD 하나 (p_vaddr=p_paddr=load_addr) 와 같은 범위의 SHT_PROGBITS 섹션 하나 + .shstrtab.
      플래그: 플래시 코드 R+X, 플래시 상수 R, RAM 데이터 RW, IRAM/RTC 코드/통합 SRAM RWX, 모르는 주소 RWX.
      섹션 이름은 kind 로 (.flash.text, .flash.rodata, .iram0.text, .dram0.data, .rtc.text …), 겹치면 _1, _2 … 를 붙인다.
    - padding 세그먼트(load_addr 0–0x10000, elf2image 채움)와 길이 0 세그먼트는 뺀다.
    - e_machine 94(Xtensa)/243(RISC-V), e_entry=entry, e_flags=chip_info 의 값.
    - 체크섬·SHA 불일치(ok=False)는 막지 않는다 (수정된 이미지도 디컴파일 대상). 세그먼트를 끝까지 못 읽었거나
      (segments_complete=False) 범위가 data 밖이거나 아키텍처를 모르면 EspFormatError.
    """
    buf = _as_bytes(data)
    if not isinstance(parsed, dict) or not isinstance(parsed.get("segments"), list):
        raise EspFormatError("parse_app_image 결과(dict, segments 목록)가 필요함")
    if parsed.get("segments_complete") is False:
        raise EspFormatError("세그먼트를 끝까지 읽지 못한 이미지 — ELF 로 바꾸지 않음: " + "; ".join(parsed.get("errors") or [])[:300])
    chip_id = parsed.get("chip_id")
    info = chip_info(chip_id) if isinstance(chip_id, int) else None
    if not info or not info["e_machine"]:
        raise EspFormatError(f"아키텍처를 알 수 없는 칩(chip_id={chip_id!r}) — e_machine 을 정할 수 없음")
    entry = parsed.get("entry")
    if not isinstance(entry, int) or not 0 <= entry <= 0xFFFFFFFF:
        raise EspFormatError(f"엔트리 주소가 올바르지 않음: {entry!r}")
    segs: list[dict[str, Any]] = []
    for s in parsed["segments"]:
        try:
            addr, size, fo, kind = int(s["load_addr"]), int(s["size"]), int(s["file_offset"]), str(s.get("kind") or "unknown")
        except (KeyError, TypeError, ValueError) as exc:
            raise EspFormatError(f"세그먼트 항목이 올바르지 않음: {exc}") from None
        if kind == "padding" or size == 0:
            continue
        if fo < 0 or fo + size > len(buf) or not 0 <= addr <= 0xFFFFFFFF or addr + size > 0x100000000:
            raise EspFormatError(f"세그먼트 {s.get('index')} 범위(파일 0x{fo:x}+0x{size:x}, 주소 0x{addr:x})가 올바르지 않음")
        segs.append({"addr": addr, "size": size, "fo": fo, "kind": kind if kind in _KIND_ATTRS else "unknown"})
    if not segs:
        raise EspFormatError("ELF 로 옮길 세그먼트가 없음")

    nseg = len(segs)
    phoff = 52
    off = phoff + 32 * nseg
    shstr = bytearray(b"\0")
    used: dict[str, int] = {}
    for s in segs:
        off = (off + 15) & ~15
        off += s["addr"] & 3  # p_offset ≡ p_vaddr (mod 4)
        s["off"] = off
        off += s["size"]
        base = _KIND_SECTION[s["kind"]]
        cnt = used.get(base, 0)
        used[base] = cnt + 1
        s["name_off"] = len(shstr)
        shstr += (base if cnt == 0 else f"{base}_{cnt}").encode() + b"\0"
    shstr_name = len(shstr)
    shstr += b".shstrtab\0"
    shstr_off = off
    off += len(shstr)
    shoff = (off + 3) & ~3
    shnum = nseg + 2
    out = bytearray(shoff + 40 * shnum)
    ident = b"\x7fELF" + bytes([1, 1, 1, 0]) + bytes(8)  # ELFCLASS32, ELFDATA2LSB, EV_CURRENT, SYSV
    out[0:52] = ident + struct.pack("<HHIIIIIHHHHHH", 2, info["e_machine"], 1, entry, phoff, shoff, info["e_flags"],
                                    52, 32, nseg, 40, shnum, nseg + 1)
    for i, s in enumerate(segs):
        _flash, ex, wr = _KIND_ATTRS[s["kind"]]
        pflags = _PF_R | (_PF_W if wr else 0) | (_PF_X if ex else 0)
        shflags = _SHF_ALLOC | (_SHF_WRITE if wr else 0) | (_SHF_EXECINSTR if ex else 0)
        struct.pack_into("<8I", out, phoff + 32 * i, 1, s["off"], s["addr"], s["addr"], s["size"], s["size"], pflags, 4)
        out[s["off"]:s["off"] + s["size"]] = buf[s["fo"]:s["fo"] + s["size"]]
        struct.pack_into("<10I", out, shoff + 40 * (i + 1), s["name_off"], 1, shflags, s["addr"], s["off"], s["size"], 0, 0, 4, 0)
    out[shstr_off:shstr_off + len(shstr)] = shstr
    struct.pack_into("<10I", out, shoff + 40 * (nseg + 1), shstr_name, 3, 0, 0, shstr_off, len(shstr), 0, 0, 1, 0)
    return bytes(out)


# ---------------------------------------------------------------------------
# NVS
# ---------------------------------------------------------------------------

NVS_PAGE_SIZE = 4096
_NVS_ENTRIES = 126
_NVS_FIRST_ENTRY = 64
_ES_ERASED, _ES_ILLEGAL, _ES_WRITTEN, _ES_EMPTY = 0, 1, 2, 3

_NVS_PAGE_STATES = {0xFFFFFFFF: "empty", 0xFFFFFFFE: "active", 0xFFFFFFFC: "full", 0xFFFFFFF8: "freeing",
                    0xFFFFFFF0: "corrupt", 0x00000000: "invalid"}
_NVS_LIVE_PAGE_STATES = ("active", "full", "freeing")
_NVS_PARSED_PAGE_STATES = ("active", "full", "freeing", "corrupt")

# type → (이름, 바이트 폭, 부호)
_NVS_PRIM: dict[int, tuple[str, int, bool]] = {
    0x01: ("U8", 1, False), 0x11: ("I8", 1, True), 0x02: ("U16", 2, False), 0x12: ("I16", 2, True),
    0x04: ("U32", 4, False), 0x14: ("I32", 4, True), 0x08: ("U64", 8, False), 0x18: ("I64", 8, True),
}
_NVS_SZ, _NVS_BLOB, _NVS_BLOB_DATA, _NVS_BLOB_IDX = 0x21, 0x41, 0x42, 0x48
_NVS_VARLEN = (_NVS_SZ, _NVS_BLOB, _NVS_BLOB_DATA)
_NVS_TYPE_NAMES: dict[int, str] = {**{t: v[0] for t, v in _NVS_PRIM.items()},
                                   _NVS_SZ: "SZ", _NVS_BLOB: "BLOB", _NVS_BLOB_DATA: "BLOB_DATA", _NVS_BLOB_IDX: "BLOB_IDX"}

_NVS_CRC_CONVENTION = (
    "nvs_crc32(x) = zlib.crc32(x, 0xFFFFFFFF) & 0xFFFFFFFF — 페이지 헤더는 바이트 4..28, 엔트리는 바이트 0..4 + 8..32, "
    "SZ/BLOB 데이터는 페이로드 dataSize 바이트. ESP-IDF nvs_partition_gen.py/nvs_parser.py 와 같은 규약으로 알고 있으나 "
    "실제 기기 덤프로는 검증되지 않음 — crc_summary 의 ok/bad 로 확인할 것"
)


def nvs_crc32(data: bytes) -> int:
    """NVS CRC32 — 이 저장소에서 NVS CRC 규약을 정의하는 유일한 곳.

    zlib.crc32(data, 0xFFFFFFFF) & 0xFFFFFFFF. ESP-IDF 의 nvs_partition_gen.py 가 쓰는 계산
    (C 쪽 esp_rom_crc32_le(0xffffffff, …) 와 같은 값)으로 알고 있지만, 실제 기기 덤프나 ESP-IDF 도구로
    검증하지 못했다 (로컬 오라클 없음, 다운로드 금지). parse_nvs 의 crc_summary 가 페이지 헤더·엔트리·데이터
    CRC 의 일치/불일치 수를 세므로, 실제 덤프에서 규약이 틀리면 bad 가 몰려서 바로 드러난다.
    nvs_set_primitives 는 쓰기 전에 이 규약이 입력 이미지와 맞는지 스스로 확인한다.
    """
    return zlib.crc32(bytes(data), 0xFFFFFFFF) & 0xFFFFFFFF


def _nvs_entry_crc(ent: bytes) -> int:
    return nvs_crc32(ent[0:4] + ent[8:32])


def _nvs_type_name(t: int) -> str:
    return _NVS_TYPE_NAMES.get(t, f"unknown(0x{t:02x})")


# ---------------------------------------------------------------------------
# 비밀값 힌트
# ---------------------------------------------------------------------------

# I2a 적대적 리뷰에서 검증한 정규식 (누락 41→1, 과잉 7→5). 키를 camelCase 경계에서 '_' 로 펼치고 소문자로 바꾼 뒤 적용한다
# (mqttPass → mqtt_pass, idToken → id_token). 게임 세이브 값은 피한다: credits/tokens(게임 화폐), token_count, pass_count,
# stage_passed, secret_level, secrets_found, bypass, compass, passage, pin_count, hiscore …
# 남는 과잉 마스킹(stage_pass, boss_pass, password_lvl, passcode_lv, cred_count)은 안전한 쪽이라 허용하고, 알려진 누락은 'lic' 하나.
_SECRET_B = r"(?:^|[_.\-\d])"
_SECRET_E = r"(?=$|[_.\-\d])"
_SECRET_RX = re.compile(
    r"(?<!com)(?<!by)pass(?!(?:ed|es|age|ing)|_?(?:count|cnt|num|lvl|lv|level|stage|rank))"
    rf"|pswd|pwd|{_SECRET_B}pw{_SECRET_E}|{_SECRET_B}pin(?:_?code)?(?=$|[.\-\d])|psk|pmk|api_?key|priv|prv_?key"
    r"|secret(?!s?_?(?:level|lvl|stage|room|area|found|count|cnt|ending|item))|token(?!s|_?(?:count|cnt|num))|jwt|cred(?!it)"
    r"|credit_?card|card_?no|cvv"
    rf"|(?:wifi|wpa|wep|aes|enc|hmac|tls|client|dev|device|master|session|license|licence|activation|serial|unlock|cert|otp)"
    rf"_?(?:key|seed){_SECRET_E}"
)
_WIFI_SECRET_RX = re.compile(r"pswd|pass|psk|pmk", re.I)
_WIFI_NAMESPACE = "nvs.net80211"
_CAMEL_RX = re.compile(r"(?<=[a-z0-9])(?=[A-Z])")


def _secret_norm(key: str) -> str:
    """camelCase 경계에 '_' 를 넣고 소문자로 (mqttPass → mqtt_pass, WiFiPass → wi_fi_pass)."""
    return _CAMEL_RX.sub("_", key).lower()


def secret_hint(namespace: str | None, key: str | None) -> bool:
    """비밀값으로 보이는 NVS 키인지 (표시·내보내기에서 마스킹하라는 힌트).

    - namespace 가 'nvs.net80211' 이면 항상 True — 그 네임스페이스의 값(ssid·authmode 포함)은 세이브가 아니고 Wi-Fi 설정이다.
    - namespace 를 모를 때(None, 정의 엔트리 손상 등)는 키에 pswd|pass|psk|pmk 가 있으면 True (Wi-Fi 키가 이름 없이 남은 경우).
    - 그 밖에는 _SECRET_RX(비밀번호·PIN·PSK/PMK·API 키·개인키·토큰·JWT·자격증명·카드·각종 *_key/*_seed)를 펼친 키에 적용.
    과잉 마스킹은 안전한 쪽이라 일부 허용한다 (모듈 주석의 목록).
    """
    k = key or ""
    if namespace == _WIFI_NAMESPACE:
        return True
    if namespace is None and _WIFI_SECRET_RX.search(k):
        return True
    return bool(_SECRET_RX.search(_secret_norm(k)))


# ---------------------------------------------------------------------------
# NVS 내부 레코드와 스캔
# ---------------------------------------------------------------------------

def _tick(ctl: Any) -> bool:
    """취소면 예외(ctl.check/ctl.expired 가 던짐), 시간 예산을 넘겼으면 True. ctl 이 없으면 False (saves.py 와 같은 규약)."""
    if ctl is None:
        return False
    expired = getattr(ctl, "expired", None)
    if callable(expired):
        return bool(expired())
    check = getattr(ctl, "check", None)
    if callable(check):
        check()
    return False


def _report(ctl: Any, done: float, total: float | None, message: str) -> None:
    fn = getattr(ctl, "progress", None) if ctl is not None else None
    if callable(fn):
        try:
            fn(done, total, message)
        except Exception:  # pragma: no cover - 진행률 보고 실패는 무시
            pass


class _NvsRec:
    """NVS 항목 헤더 엔트리 하나 (큰 이미지에서 메모리를 줄이려고 dict 대신 __slots__)."""

    __slots__ = ("page", "seq", "entry", "offset", "ns", "key", "typ", "span", "chunk", "state", "cstored", "ccomp",
                 "value", "size", "dcrc_ok", "page_state", "page_hdr_ok", "struct_ok", "overflow", "ccount", "cstart")

    def __init__(self) -> None:
        self.value: Any = None
        self.size: int | None = None
        self.dcrc_ok: bool | None = None
        self.struct_ok = True
        self.overflow = False
        self.ccount: int | None = None
        self.cstart: int | None = None

    @property
    def crc_ok(self) -> bool:
        return self.cstored == self.ccomp


def _nvs_record(buf: bytes, pinfo: dict[str, Any], i: int, ent: bytes, state: str, trust_span: bool) -> _NvsRec:
    """엔트리 하나(항목 헤더)를 내부 레코드로. trust_span=False 면 페이로드를 읽지 않는다 (CRC 불량·span 이상)."""
    r = _NvsRec()
    r.page, r.seq, r.entry = pinfo["index"], pinfo["seq"], i
    r.offset = pinfo["offset"] + _NVS_FIRST_ENTRY + 32 * i
    r.ns, r.typ, r.span, r.chunk = ent[0], ent[1], ent[2], ent[3]
    r.key = _cstr(ent[8:24])
    r.state = state
    r.cstored = struct.unpack_from("<I", ent, 4)[0]
    r.ccomp = _nvs_entry_crc(ent)
    r.page_state = pinfo["state_name"]
    r.page_hdr_ok = bool(pinfo["header_crc"]["ok"])
    d = ent[24:32]
    if r.typ in _NVS_PRIM:
        _name, width, signed = _NVS_PRIM[r.typ]
        r.value = int.from_bytes(d[:width], "little", signed=signed)
        r.size = width
    elif r.typ in _NVS_VARLEN:
        size, _reserved, dcrc = struct.unpack_from("<HHI", d)
        r.size = size
        if trust_span:
            start = r.offset + 32
            cap = 32 * (r.span - 1)
            if size > cap:
                r.struct_ok = False
                r.overflow = True
                r.dcrc_ok = False
                payload = buf[start:start + cap]
            else:
                payload = buf[start:start + size]  # 페이로드 복사본은 이것 하나 (항목 dict 는 같은 객체를 가리킨다)
                r.dcrc_ok = nvs_crc32(payload) == dcrc
            if r.typ == _NVS_SZ:
                raw = payload[:-1] if payload.endswith(b"\0") else payload
                r.value = raw.decode("utf-8", "backslashreplace")
            else:
                r.value = payload
    elif r.typ == _NVS_BLOB_IDX:
        total, ccount, cstart, _reserved = struct.unpack_from("<IBBH", d)
        r.size, r.ccount, r.cstart = total, ccount, cstart
    else:
        r.value = bytes(d)
        r.size = 8
    return r


def _nvs_eligible(r: _NvsRec) -> bool:
    """ESP-IDF 가 실제로 읽을 수 있는 항목: written, 엔트리·데이터 CRC 정상, 구조 정상, 살아 있는 페이지(헤더 CRC 정상)."""
    return (r.state == "written" and r.cstored == r.ccomp and r.struct_ok and r.dcrc_ok is not False
            and r.page_state in _NVS_LIVE_PAGE_STATES and r.page_hdr_ok)


def _nvs_resolve_namespaces(records: list[_NvsRec], warnings: list[str]) -> tuple[dict[int, str], dict[int, list[str]], dict[int, int]]:
    """네임스페이스 정의 엔트리(ns 0, U8, 값 = 번호 1..254)로 번호 → 이름.

    신뢰도: 0 = ESP-IDF 가 읽는 정의(written·CRC 정상·살아 있는 페이지), 1 = CRC 는 맞지만 지웠거나 죽은 페이지, 2 = CRC 불일치.
    한 번호에 이름이 여럿이면 경고하고 가장 믿을 만한 이름을 쓰되, 그중 'nvs.net80211' 이 있으면 신뢰도와 무관하게 그 이름을 쓴다
    (손상·덮어쓴 정의 때문에 Wi-Fi 값이 마스킹에서 빠지지 않게 — 과잉 마스킹 쪽이 안전).
    반환: (이름, 충돌 {번호: [이름…]}, 선택한 이름의 신뢰도).
    """
    cands: dict[int, list[tuple[int, str]]] = {}
    for r in records:
        if r.ns != 0 or r.typ != 0x01 or not isinstance(r.value, int) or not 1 <= r.value <= 254:
            continue
        tier = 0 if _nvs_eligible(r) else (1 if r.cstored == r.ccomp else 2)
        cands.setdefault(r.value, []).append((tier, r.key))
    names: dict[int, str] = {}
    conflicts: dict[int, list[str]] = {}
    tiers: dict[int, int] = {}
    for idx in sorted(cands):
        ordered = sorted(cands[idx], key=lambda t: t[0])  # 안정 정렬: 신뢰도, 같으면 물리 순서
        uniq = list(dict.fromkeys(name for _t, name in ordered))
        if _WIFI_NAMESPACE in uniq:
            chosen = _WIFI_NAMESPACE
            tier = min(t for t, name in ordered if name == _WIFI_NAMESPACE)
        else:
            tier, chosen = ordered[0]
        names[idx], tiers[idx] = chosen, tier
        if len(uniq) > 1:
            conflicts[idx] = uniq
            warnings.append(f"네임스페이스 번호 {idx} 의 정의가 여럿 {uniq} — '{chosen}' 로 봄"
                            + (" (Wi-Fi 값 마스킹 우선)" if chosen == _WIFI_NAMESPACE else ""))
        if tier == 1:
            warnings.append(f"네임스페이스 {idx}('{chosen}') 의 정의는 지웠거나 죽은 페이지의 엔트리뿐")
        elif tier == 2:
            warnings.append(f"네임스페이스 {idx}('{chosen}') 의 정의는 CRC 가 깨진 엔트리뿐 — 이름이 틀릴 수 있음")
    return names, conflicts, tiers


def _nvs_scan(buf: bytes, ctl: Any = None) -> dict[str, Any]:
    """페이지·엔트리를 훑어 내부 레코드와 CRC 집계를 만든다 (parse_nvs / nvs_set_primitives 공용).

    ctl 이 있으면 페이지마다 확인한다: 취소면 예외, 시간 예산을 넘기면 그 페이지에서 멈추고 timed_out=True.
    """
    warnings: list[str] = []
    errors: list[str] = []
    structural: list[str] = []
    notes: list[str] = []
    pages: list[dict[str, Any]] = []
    records: list[_NvsRec] = []
    summary = {"page_header": {"ok": 0, "bad": 0}, "entry": {"ok": 0, "bad": 0}, "data": {"ok": 0, "bad": 0}}
    npages, rem = divmod(len(buf), NVS_PAGE_SIZE)
    timed_out = False
    if rem:
        warnings.append(f"길이 {len(buf)} 가 페이지(4096)의 배수가 아님 — 마지막 {rem} 바이트는 무시")
    if npages == 0:
        errors.append("NVS 페이지가 없음 (4096 바이트 미만)")
    for p in range(npages):
        if _tick(ctl):
            timed_out = True
            notes.append(f"시간 예산 초과 — {npages} 페이지 중 {p} 페이지까지만 해석함 (live·중복·BLOB 판정이 불완전할 수 있음)")
            break
        if (p & 0x3F) == 0:
            _report(ctl, p, npages, "NVS 페이지")
        base = p * NVS_PAGE_SIZE
        state, seq = struct.unpack_from("<II", buf, base)
        vraw = buf[base + 8]
        stored = struct.unpack_from("<I", buf, base + 28)[0]
        sname = _NVS_PAGE_STATES.get(state, "unknown")
        bitmap = buf[base + 32:base + 64]
        states = [(bitmap[i >> 2] >> ((i & 3) * 2)) & 3 for i in range(_NVS_ENTRIES)]
        perr: list[str] = []
        pinfo: dict[str, Any] = {
            "index": p, "offset": base, "state": state, "state_name": sname, "seq": seq, "version": None, "version_raw": vraw,
            "header_crc": {"stored": stored, "computed": None, "ok": None},
            "written": states.count(_ES_WRITTEN), "erased": states.count(_ES_ERASED), "empty": states.count(_ES_EMPTY),
            "illegal": states.count(_ES_ILLEGAL), "errors": perr,
        }
        pages.append(pinfo)
        if sname == "empty":
            if buf.count(b"\xff", base, base + NVS_PAGE_SIZE) != NVS_PAGE_SIZE:
                msg = "상태는 빈 페이지(0xFFFFFFFF)인데 데이터가 있음 — ESP-IDF 는 이 페이지를 손상으로 본다"
                perr.append(msg)
                structural.append(f"page {p}: {msg}")
            continue
        computed = nvs_crc32(buf[base + 4:base + 28])
        hok = computed == stored
        pinfo["header_crc"] = {"stored": stored, "computed": computed, "ok": hok}
        summary["page_header"]["ok" if hok else "bad"] += 1
        pinfo["version"] = {0xFF: 1, 0xFE: 2}.get(vraw)
        if pinfo["version"] is None:
            perr.append(f"알 수 없는 페이지 버전 바이트 0x{vraw:02x}")
        if not hok:
            perr.append(f"페이지 헤더 CRC 불일치 (저장 0x{stored:08x}, 계산 0x{computed:08x}) — ESP-IDF 는 이 페이지를 쓰지 않는다")
        if sname not in _NVS_PARSED_PAGE_STATES:
            msg = f"페이지 상태 0x{state:08x}({sname}) — 엔트리를 해석하지 않음"
            perr.append(msg)
            structural.append(f"page {p}: {msg}")
            continue
        i = 0
        while i < _NVS_ENTRIES:
            st = states[i]
            if st == _ES_EMPTY:
                i += 1
                continue
            if st == _ES_ILLEGAL:
                msg = f"엔트리 {i}: 비정상 상태 비트(0b01)"
                perr.append(msg)
                structural.append(f"page {p}: {msg}")
                i += 1
                continue
            eoff = base + _NVS_FIRST_ENTRY + 32 * i
            ent = buf[eoff:eoff + 32]
            typ, span = ent[1], ent[2]
            cok = struct.unpack_from("<I", ent, 4)[0] == _nvs_entry_crc(ent)
            if st == _ES_ERASED:
                # 지운 항목: CRC 가 맞고 span 이 페이지 안이며 span 전체가 지움 상태일 때만 항목 헤더로 본다 (이력)
                if (cok and typ in _NVS_TYPE_NAMES and 1 <= span <= _NVS_ENTRIES - i
                        and all(states[j] == _ES_ERASED for j in range(i + 1, i + span))):
                    records.append(_nvs_record(buf, pinfo, i, ent, "erased", trust_span=True))
                    i += span
                else:
                    i += 1
                continue
            summary["entry"]["ok" if cok else "bad"] += 1
            if not cok:
                rec = _nvs_record(buf, pinfo, i, ent, "written", trust_span=False)
                perr.append(f"엔트리 {i}: CRC 불일치 (저장 0x{rec.cstored:08x}, 계산 0x{rec.ccomp:08x}) — "
                            "ESP-IDF 는 이 엔트리를 지운다 (span 을 믿지 않고 한 칸씩 진행)")
                if typ in _NVS_TYPE_NAMES:
                    records.append(rec)
                i += 1
                continue
            if span < 1 or i + span > _NVS_ENTRIES:
                msg = f"엔트리 {i}: span {span} 이 페이지 범위를 넘음"
                perr.append(msg)
                structural.append(f"page {p}: {msg}")
                rec = _nvs_record(buf, pinfo, i, ent, "written", trust_span=False)
                rec.struct_ok = False
                records.append(rec)
                i += 1
                continue
            rec = _nvs_record(buf, pinfo, i, ent, "written", trust_span=True)
            if typ in _NVS_VARLEN:
                bad = [j for j in range(i + 1, i + span) if states[j] != _ES_WRITTEN]
                if bad:
                    msg = f"엔트리 {i}: 데이터 엔트리 {bad[0]} 의 상태가 written 이 아님 — ESP-IDF 는 이 항목을 지운다"
                    perr.append(msg)
                    structural.append(f"page {p}: {msg}")
                    rec.struct_ok = False
                if rec.overflow:
                    msg = f"엔트리 {i}: 데이터 크기 {rec.size} 가 span {span} 의 용량({32 * (span - 1)})보다 큼"
                    perr.append(msg)
                    structural.append(f"page {p}: {msg}")
                else:
                    summary["data"]["ok" if rec.dcrc_ok else "bad"] += 1
                    if not rec.dcrc_ok:
                        perr.append(f"엔트리 {i}: 데이터 CRC 불일치 ({_nvs_type_name(typ)} '{rec.key}')")
            elif typ not in _NVS_TYPE_NAMES:
                perr.append(f"엔트리 {i}: 알 수 없는 타입 0x{typ:02x} (CRC 는 맞음)")
            elif span != 1:
                perr.append(f"엔트리 {i}: {_nvs_type_name(typ)} 인데 span {span}")
            records.append(rec)
            i += span
        pinfo["errors"] = _cap(perr, 30)

    namespaces, ns_conflicts, ns_tiers = _nvs_resolve_namespaces(records, warnings)
    # live: 같은 (번호, 키, chunk, 타입) 의 ESP-IDF 가 읽는 후보 중 가장 새 것. 단일 후보는 int 하나만 들고, 중복만 목록으로.
    best: dict[tuple[int, str, int, int], int] = {}
    dups: dict[tuple[int, str, int, int], list[int]] = {}
    for k, r in enumerate(records):
        if r.ns == 0 or not _nvs_eligible(r):
            continue
        g = (r.ns, r.key, r.chunk, r.typ)
        prev = best.get(g)
        if prev is None:
            best[g] = k
            continue
        dups.setdefault(g, [prev]).append(k)
        q = records[prev]
        if (r.seq, r.page, r.entry) > (q.seq, q.page, q.entry):
            best[g] = k
    live = set(best.values())
    unresolved = sorted({r.ns for r in records if r.ns != 0 and r.ns not in namespaces})
    if unresolved:
        warnings.append(f"이름을 모르는 네임스페이스 번호: {unresolved[:20]}")
    return {"pages": pages, "records": records, "summary": summary, "structural": structural, "warnings": warnings,
            "errors": errors, "notes": notes, "timed_out": timed_out, "namespaces": namespaces, "ns_conflicts": ns_conflicts,
            "ns_tiers": ns_tiers, "best": best, "dups": dups, "live": live}


def _nvs_item(r: _NvsRec, namespaces: dict[int, str], live: bool) -> dict[str, Any]:
    ns_name = namespaces.get(r.ns)
    item = {"page": r.page, "entry": r.entry, "offset": r.offset, "ns_index": r.ns, "namespace": ns_name, "key": r.key,
            "type": r.typ, "type_name": _nvs_type_name(r.typ), "span": r.span, "chunk_index": r.chunk, "state": r.state,
            "crc": {"stored": r.cstored, "computed": r.ccomp, "ok": r.cstored == r.ccomp}, "value": r.value, "size": r.size,
            "data_crc_ok": r.dcrc_ok, "live": live, "secret": secret_hint(ns_name, r.key), "page_seq": r.seq}
    if r.typ == _NVS_BLOB_IDX:
        item["chunk_count"] = r.ccount
        item["chunk_start"] = r.cstart
    return item


NVS_DEFAULT_MAX_ITEMS = 200_000


def parse_nvs(data: bytes | bytearray | memoryview, *, include_erased: bool = True, ctl: Any = None,
              max_items: int | None = NVS_DEFAULT_MAX_ITEMS) -> dict[str, Any]:
    """NVS 파티션 이미지 해석 (파티션 영역만 넘긴다; 길이는 4096 의 배수가 정상).

    - items: 데이터 항목(네임스페이스 정의 엔트리 제외). live = 같은 (네임스페이스, 키, chunk_index, 타입) 중
      ESP-IDF 가 읽을 수 있는(written, CRC 정상, 살아 있는 페이지) 가장 새 항목 (페이지 seq 가 큰 쪽, 같으면 뒤 엔트리).
      CRC 가 틀린 written 엔트리는 live 가 아니고 span 을 믿지 않는다 (ESP-IDF 와 같이 한 칸씩 진행).
    - blobs: v2 BLOB_IDX + BLOB_DATA 조각을 chunk_start 기준으로 이어 붙인 값.
    - duplicates: live 후보(written·CRC 정상)가 둘 이상인 (네임스페이스, 키, chunk) — 어느 값이 쓰일지 모호.
    - crc_summary: 페이지 헤더(빈 페이지 제외)·written 엔트리·SZ/BLOB 데이터 CRC 의 ok/bad 수 (규약 확인용).
    - 네임스페이스 번호에 정의가 여럿이면 경고하고, 그중 'nvs.net80211' 이 있으면 그 이름으로 본다 (Wi-Fi 값 마스킹 우선).
    자원 한도: ctl(fwtriage Ctl 과 같은 덕 타입)이 있으면 페이지마다 취소(예외)·시간 예산을 확인한다. 예산을 넘기면 거기까지만
    해석한다. items·blobs·duplicates 는 각각 max_items 개까지만 담는다(None 이면 무제한). 어느 쪽이든 truncated=True 와
    notes 에 이유를 남긴다. items_total 은 한도와 무관한 (해석한 범위의) 전체 항목 수.
    """
    if max_items is not None and (isinstance(max_items, bool) or not isinstance(max_items, int) or max_items < 0):
        raise ValueError(f"max_items 는 0 이상의 정수 또는 None 이어야 함: {max_items!r}")
    buf = _as_bytes(data)
    scan = _nvs_scan(buf, ctl)
    warnings = list(scan["warnings"])
    errors = list(scan["errors"])
    notes = list(scan["notes"])
    truncated = bool(scan["timed_out"])
    recs: list[_NvsRec] = scan["records"]
    live = scan["live"]
    namespaces = scan["namespaces"]
    summary = scan["summary"]
    limit = max_items if max_items is not None else float("inf")
    items: list[dict[str, Any]] = []
    total = 0
    stopped = False
    for k, r in enumerate(recs):
        if r.ns == 0 or (r.state == "erased" and not include_erased):
            continue
        total += 1
        if stopped or len(items) >= limit:
            continue
        if (len(items) & 0x3FFF) == 0x3FFF and _tick(ctl):
            stopped = truncated = True
            notes.append(f"시간 예산 초과 — items 를 {len(items)}개까지만 만듦")
            continue
        items.append(_nvs_item(r, namespaces, k in live))
    if total > limit:
        truncated = True
        notes.append(f"항목 {total}개 중 앞의 {max_items}개만 items 에 담음 (max_items) — crc_summary 는 전체 기준")

    data_chunks: dict[tuple[int, str, int], int] = {}
    for k in live:
        r = recs[k]
        if r.typ == _NVS_BLOB_DATA:
            data_chunks[(r.ns, r.key, r.chunk)] = k
    used: set[int] = set()
    blobs: list[dict[str, Any]] = []
    blob_total = 0
    for k in sorted(live):
        r = recs[k]
        if r.typ != _NVS_BLOB_IDX:
            continue
        blob_total += 1
        ccount, cstart = r.ccount or 0, r.cstart or 0
        parts: list[bytes] = []
        missing: list[int] = []
        for c in range(ccount):
            j = data_chunks.get((r.ns, r.key, cstart + c))
            if j is None:
                missing.append(cstart + c)
                continue
            used.add(j)
            parts.append(recs[j].value or b"")
        if len(blobs) >= limit:
            continue
        value = b"".join(parts)  # 조각이 하나면 같은 객체 (복사 없음)
        ns_name = namespaces.get(r.ns)
        complete = not missing and len(value) == r.size
        if not complete:
            warnings.append(f"BLOB '{ns_name}/{r.key}' 불완전 (조각 없음 {missing[:8]}, 길이 {len(value)}/{r.size})")
        blobs.append({"namespace": ns_name, "key": r.key, "size": r.size, "chunks": ccount, "chunk_start": cstart, "value": value,
                      "complete": complete, "missing_chunks": missing, "secret": secret_hint(ns_name, r.key)})
    if blob_total > limit:
        truncated = True
        notes.append(f"BLOB {blob_total}개 중 앞의 {max_items}개만 blobs 에 담음 (max_items)")
    orphans = sorted(k for k in data_chunks.values() if k not in used)
    if orphans:
        warnings.append(f"BLOB_IDX 가 없는 BLOB_DATA 조각 {len(orphans)}개 (예: '{recs[orphans[0]].key}' chunk {recs[orphans[0]].chunk})")

    duplicates: list[dict[str, Any]] = []
    for (ns_idx, key, chunk, typ), idxs in scan["dups"].items():
        if len(duplicates) >= limit:
            break
        duplicates.append({"ns_index": ns_idx, "namespace": namespaces.get(ns_idx), "key": key, "chunk_index": chunk,
                           "type_name": _nvs_type_name(typ), "count": len(idxs),
                           "entries": [{"page": recs[k].page, "entry": recs[k].entry, "offset": recs[k].offset,
                                        "page_seq": recs[k].seq} for k in idxs]})
    if scan["dups"]:
        warnings.append(f"같은 키의 live 후보가 여럿인 항목 {len(scan['dups'])}개 (가장 새 것을 live 로 표시)")
        if len(scan["dups"]) > limit:
            truncated = True
            notes.append(f"중복 {len(scan['dups'])}건 중 앞의 {max_items}건만 duplicates 에 담음 (max_items)")
    checked = summary["entry"]["ok"] + summary["entry"]["bad"] + summary["page_header"]["ok"] + summary["page_header"]["bad"]
    good = summary["entry"]["ok"] + summary["page_header"]["ok"]
    if checked >= 2 and good == 0:
        warnings.append("검사한 CRC 가 모두 불일치 — 손상보다는 CRC 규약(nvs_crc32)이 이 이미지와 다를 가능성이 큼")
    versions = sorted({p["version"] for p in scan["pages"] if p["version"] is not None})
    return {
        "page_size": NVS_PAGE_SIZE, "pages": scan["pages"], "namespaces": dict(sorted(namespaces.items())), "items": items,
        "items_total": total, "blobs": blobs, "crc_summary": summary, "crc_convention": _NVS_CRC_CONVENTION,
        "versions_seen": versions, "duplicates": duplicates, "truncated": truncated, "notes": notes,
        "warnings": _cap(warnings), "errors": _cap(errors),
    }


def _nvs_key_values(parsed: dict[str, Any]) -> dict[tuple[Any, Any, str], tuple[Any, bool]]:
    """(네임스페이스, 키, 타입 이름) → (값, secret). v2 BLOB 은 조립한 값을 'BLOB' 으로 (v1 BLOB 과 같은 이름)."""
    vals: dict[tuple[Any, Any, str], tuple[Any, bool]] = {}
    for it in parsed.get("items") or []:
        if not it.get("live") or it.get("type") in (_NVS_BLOB_DATA, _NVS_BLOB_IDX):
            continue
        tname = "BLOB" if it.get("type") == _NVS_BLOB else str(it.get("type_name"))
        vals[(it.get("namespace"), it.get("key"), tname)] = (it.get("value"), bool(it.get("secret")))
    for b in parsed.get("blobs") or []:
        vals[(b.get("namespace"), b.get("key"), "BLOB")] = (b.get("value"), secret_hint(b.get("namespace"), b.get("key")))
    return vals


def nvs_item_diff(parsed_list: list[dict[str, Any]], labels: list[str] | None = None, ctl: Any = None) -> dict[str, Any]:
    """순서 있는 NVS 스냅샷(parse_nvs 결과 목록)의 live 항목을 키 단위로 비교한다.

    키 = (네임스페이스, 키, 타입 이름). v2 BLOB 은 조각이 아니라 조립한 값으로 비교한다.
    - added: 첫 스냅샷에 없고 마지막에 있음 / removed: 첫 스냅샷에 있고 마지막에 없음
    - changed: 그 밖에 값(또는 있고 없음)이 스냅샷 사이에 다름 / unchanged_count: 모든 스냅샷에 같은 값
    각 원소: {namespace, key, type_name, values: [스냅샷별 값 또는 None], secret}.
    ctl 이 있으면 스냅샷마다·키 16K 개마다 취소(예외)·시간 예산을 확인하고, 예산을 넘기면 거기까지의 결과에 truncated=True·notes.
    입력 스냅샷 중 truncated 인 것이 있어도 truncated=True (비교가 불완전할 수 있음).
    """
    if labels is None:
        labels = [f"#{i}" for i in range(len(parsed_list))]
    if len(labels) != len(parsed_list):
        raise ValueError(f"labels 길이({len(labels)})가 스냅샷 수({len(parsed_list)})와 다름")
    notes: list[str] = []
    truncated = False
    for lab, p in zip(labels, parsed_list):
        if p.get("truncated"):
            truncated = True
            notes.append(f"스냅샷 {lab} 의 parse_nvs 결과가 잘림(truncated) — 비교가 불완전할 수 있음")
    out: dict[str, Any] = {"labels": list(labels), "snapshot_count": len(parsed_list), "changed": [], "added": [], "removed": [],
                           "unchanged_count": 0, "truncated": truncated, "notes": notes}
    maps: list[dict[tuple[Any, Any, str], tuple[Any, bool]]] = []
    for lab, p in zip(labels, parsed_list):
        if _tick(ctl):
            out["truncated"] = True
            notes.append(f"시간 예산 초과 — 스냅샷 {lab} 부터 값을 모으지 못해 비교하지 않음")
            return out
        maps.append(_nvs_key_values(p))
    keys = sorted(set().union(*[set(m) for m in maps]) if maps else set(), key=lambda t: (str(t[0]), str(t[1]), t[2]))
    changed: list[dict[str, Any]] = out["changed"]
    added: list[dict[str, Any]] = out["added"]
    removed: list[dict[str, Any]] = out["removed"]
    unchanged = 0
    for n, key in enumerate(keys):
        if n and (n & 0x3FFF) == 0 and _tick(ctl):
            out["truncated"] = True
            notes.append(f"시간 예산 초과 — 키 {len(keys)}개 중 {n}개까지만 비교함")
            break
        got = [m.get(key) for m in maps]
        values = [g[0] if g is not None else None for g in got]
        present = [g is not None for g in got]
        if all(present) and all(v == values[0] for v in values[1:]):
            unchanged += 1
            continue
        entry = {"namespace": key[0], "key": key[1], "type_name": key[2], "values": values,
                 "secret": any(g[1] for g in got if g is not None)}
        if not present[0] and present[-1]:
            added.append(entry)
        elif present[0] and not present[-1]:
            removed.append(entry)
        else:
            changed.append(entry)
    out["unchanged_count"] = unchanged
    return out


def nvs_set_primitives(data: bytes | bytearray | memoryview, edits: list[dict[str, Any]]) -> tuple[bytes, list[dict[str, Any]]]:
    """이미 있는 live 기본 정수 항목(U8..I64)의 값을 바꾼 NVS 이미지를 만든다 (I2b 용, 아직 도구로 노출 안 함).

    edits: [{namespace, key, value: int}]. 바뀌는 것은 각 엔트리의 데이터 필드 중 타입 폭만큼의 바이트와 엔트리 CRC 뿐이다
    (데이터 필드의 나머지 바이트·다른 엔트리·페이지 헤더는 그대로). 반환: (같은 길이의 새 이미지, 변경 목록).

    쓰기 전 자기 검증 — 하나라도 어긋나면 NvsError 를 내고 아무것도 바꾸지 않는다:
    - CRC 규약: 빈 페이지가 아닌 모든 페이지 헤더 CRC, 모든 written 엔트리 CRC, SZ/BLOB 데이터 CRC 가 nvs_crc32 재계산과 같아야 한다.
    - 구조 오류(span 이상, 비정상 상태 비트, 알 수 없는 페이지 상태 등)가 없어야 한다.
    - 각 수정: 네임스페이스가 살아 있는 정의 하나로만 정해지고(번호 충돌 없음), 키가 있고, live 이고, 같은 키의 written 후보가
      하나뿐이고, 기본 정수 타입이고, 값이 타입 범위 안.
    """
    buf = _as_bytes(data)
    scan = _nvs_scan(buf)
    s = scan["summary"]
    if s["page_header"]["bad"] or s["entry"]["bad"] or s["data"]["bad"]:
        allbad = (s["page_header"]["ok"] + s["entry"]["ok"]) == 0
        raise NvsError(
            "CRC 검증 실패 — 아무것도 바꾸지 않음. "
            f"페이지 헤더 ok={s['page_header']['ok']} bad={s['page_header']['bad']}, "
            f"엔트리 ok={s['entry']['ok']} bad={s['entry']['bad']}, 데이터 ok={s['data']['ok']} bad={s['data']['bad']}. "
            + ("모두 불일치: CRC 규약(nvs_crc32 = zlib.crc32(x, 0xFFFFFFFF))이 이 이미지와 맞지 않는다."
               if allbad else "일부만 불일치: 손상된 엔트리/페이지가 있다 (또는 규약 차이). 손상된 이미지에는 쓰지 않는다.")
        )
    if scan["structural"]:
        raise NvsError(f"NVS 구조 오류 {len(scan['structural'])}건 — 아무것도 바꾸지 않음: " + "; ".join(scan["structural"][:5]))
    if s["page_header"]["ok"] + s["entry"]["ok"] == 0:
        raise NvsError("검증할 CRC 가 하나도 없음 (빈 NVS) — 규약을 확인할 수 없어 바꾸지 않음")
    if not isinstance(edits, list) or not edits:
        raise NvsError("edits 가 비었거나 목록이 아님")
    recs: list[_NvsRec] = scan["records"]
    live = scan["live"]
    namespaces = scan["namespaces"]
    conflicts = scan["ns_conflicts"]
    plan: list[tuple[int, int]] = []
    targets: set[int] = set()
    for n, e in enumerate(edits):
        if not isinstance(e, dict):
            raise NvsError(f"edits[{n}]: dict 가 아님")
        ns, key, value = e.get("namespace"), e.get("key"), e.get("value")
        if not isinstance(ns, str) or not isinstance(key, str):
            raise NvsError(f"edits[{n}]: namespace/key 는 문자열이어야 함")
        if isinstance(value, bool) or not isinstance(value, int):
            raise NvsError(f"edits[{n}]: value 는 정수여야 함 ({type(value).__name__})")
        clash = [i for i, names in conflicts.items() if ns in names]
        if clash:
            raise NvsError(f"edits[{n}]: 네임스페이스 '{ns}' 의 번호 {clash} 에 정의가 여럿 {conflicts[clash[0]]} — 모호해서 바꾸지 않음")
        ns_idx = [i for i, name in namespaces.items() if name == ns]
        if not ns_idx:
            raise NvsError(f"edits[{n}]: 네임스페이스 '{ns}' 없음")
        dead = [i for i in ns_idx if scan["ns_tiers"].get(i) != 0]
        if dead:
            raise NvsError(f"edits[{n}]: 네임스페이스 '{ns}' 의 정의가 살아 있지 않음 (지웠거나 죽은 페이지) — 기기가 이 이름을 찾지 못한다")
        cands = [k for k, r in enumerate(recs) if r.ns in ns_idx and r.key == key]
        if not cands:
            raise NvsError(f"edits[{n}]: 키 '{ns}/{key}' 없음")
        live_c = [k for k in cands if k in live]
        if not live_c:
            raise NvsError(f"edits[{n}]: '{ns}/{key}' 에 live 항목이 없음 (지워졌거나 CRC/페이지 불량)")
        if len(live_c) > 1:
            raise NvsError(f"edits[{n}]: '{ns}/{key}' 의 live 항목이 {len(live_c)}개 (타입이나 네임스페이스 번호가 다른 중복) — 모호")
        k = live_c[0]
        r = recs[k]
        group = scan["dups"].get((r.ns, r.key, r.chunk, r.typ))
        if group:
            raise NvsError(f"edits[{n}]: '{ns}/{key}' 의 written 후보가 {len(group)}개 (중복 엔트리) — 기기가 어느 값을 읽을지 모호")
        if r.typ not in _NVS_PRIM:
            raise NvsError(f"edits[{n}]: '{ns}/{key}' 는 기본 정수 타입이 아님 ({_nvs_type_name(r.typ)})")
        tname, width, signed = _NVS_PRIM[r.typ]
        lo, hi = ((-(1 << (8 * width - 1)), (1 << (8 * width - 1)) - 1) if signed else (0, (1 << (8 * width)) - 1))
        if not lo <= value <= hi:
            raise NvsError(f"edits[{n}]: 값 {value} 이 {tname} 범위 [{lo}, {hi}] 밖")
        if k in targets:
            raise NvsError(f"edits[{n}]: '{ns}/{key}' 를 두 번 수정함")
        targets.add(k)
        plan.append((k, value))

    out = bytearray(buf)
    changes: list[dict[str, Any]] = []
    for k, value in plan:
        r = recs[k]
        off = r.offset
        tname, width, signed = _NVS_PRIM[r.typ]
        out[off + 24:off + 24 + width] = value.to_bytes(width, "little", signed=signed)
        crc_before = struct.unpack_from("<I", out, off + 4)[0]
        crc_after = _nvs_entry_crc(bytes(out[off:off + 32]))
        struct.pack_into("<I", out, off + 4, crc_after)
        changes.append({"page": r.page, "entry": r.entry, "offset": off, "namespace": namespaces.get(r.ns),
                        "key": r.key, "type_name": tname, "before": r.value, "after": value,
                        "crc_before": crc_before, "crc_after": crc_after})
    result = bytes(out)
    # 자기 검증: 바꾼 뒤에도 CRC·구조가 온전하고 값이 그대로 읽혀야 한다
    check = _nvs_scan(result)
    cs = check["summary"]
    if cs["page_header"]["bad"] or cs["entry"]["bad"] or cs["data"]["bad"] or check["structural"]:
        raise NvsError("내부 오류: 수정한 이미지의 재검증 실패 — 결과를 버림")
    by_off = {r.offset: (i, r) for i, r in enumerate(check["records"])}
    for c in changes:
        hit = by_off.get(c["offset"])
        if hit is None or hit[0] not in check["live"] or hit[1].value != c["after"]:
            raise NvsError(f"내부 오류: '{c['namespace']}/{c['key']}' 가 새 값으로 읽히지 않음 — 결과를 버림")
    return result, changes
