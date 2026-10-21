"""JTAG IDCODE 해석과 JEP106 제조사 코드(선별 목록).

IEEE 1149.1 Device Identification Register::

    31..28 Version | 27..12 Part Number | 11..1 Manufacturer Identity | 0 = 1

Manufacturer Identity 11비트 = 상위 4비트(continuation 코드 개수 = bank-1) + 하위 7비트(JEP106 ID, 패리티 제외).
따라서 IDCODE 로 표현할 수 있는 bank 는 1–16 뿐이다.

제조사 목록은 JEDEC JEP106(BP, 2026-09) 기준으로 임베디드 SoC/MCU/FPGA/CPU IP 업체 위주로 **선별한 사실 정보**다
(전체 표를 포함하지 않는다). 목록에 없으면 bank/ID/원시 코드만 돌려준다.

선택 기능: OpenOCD 스크립트 디렉터리(설정 tools.openocd_scripts 또는 PWEH_OPENOCD_SCRIPTS)가 있으면
같은 IDCODE 를 기대값(_CPUTAPID, -expected-id 등)으로 쓰는 cfg 파일을 찾아 다음 단계(openocd_start) 힌트로 준다.
"""

from __future__ import annotations

import os
import re
import threading
from pathlib import Path
from typing import Any

# (bank(1-based), 7-bit id) → 제조사 이름
JEP106_SUBSET: dict[tuple[int, int], str] = {
    # bank 1
    (1, 0x01): "AMD",
    (1, 0x07): "Hitachi",
    (1, 0x09): "Intel",
    (1, 0x0E): "Freescale (Motorola)",
    (1, 0x10): "NEC",
    (1, 0x15): "NXP (Philips)",
    (1, 0x17): "Texas Instruments",
    (1, 0x1A): "Zilog",
    (1, 0x1F): "Atmel",
    (1, 0x20): "STMicroelectronics",
    (1, 0x21): "Lattice Semiconductor",
    (1, 0x29): "Microchip Technology",
    (1, 0x2C): "Micron Technology",
    (1, 0x2D): "SK Hynix",
    (1, 0x2F): "Actel (Microsemi/Microchip)",
    (1, 0x34): "Cypress",
    (1, 0x36): "LSI Logic",
    (1, 0x41): "Infineon (Siemens)",
    (1, 0x42): "Macronix",
    (1, 0x45): "SanDisk",
    (1, 0x48): "Apple",
    (1, 0x49): "Xilinx (AMD)",
    (1, 0x4E): "Samsung",
    (1, 0x5A): "Winbond",
    (1, 0x65): "Analog Devices",
    (1, 0x6E): "Altera (Intel)",
    (1, 0x70): "Qualcomm",
    (1, 0x71): "Sony",
    (1, 0x7C): "Dialog Semiconductor",
    # bank 2
    (2, 0x01): "Cirrus Logic",
    (2, 0x0E): "Imagination Technologies",
    (2, 0x1C): "Eon Silicon Devices",
    (2, 0x1D): "ISSI",
    (2, 0x3F): "Broadcom",
    (2, 0x4B): "Maxim Integrated",
    # bank 3
    (3, 0x21): "Silicon Laboratories",
    (3, 0x27): "MIPS Technologies",
    (3, 0x44): "Nordic Semiconductor (Nordic VLSI)",
    # bank 4
    (4, 0x10): "Agere Systems",
    (4, 0x24): "QuickLogic",
    (4, 0x4C): "Cavium Networks",
    (4, 0x69): "Marvell",
    (4, 0x6B): "NVIDIA",
    # bank 5
    (5, 0x23): "Renesas Electronics",
    (5, 0x26): "MediaTek",
    (5, 0x2D): "Mindspeed",
    (5, 0x38): "Faraday Technology",
    (5, 0x3B): "ARM Ltd",
    (5, 0x52): "Ceva",
    (5, 0x58): "ARC International",
    (5, 0x66): "Synopsys",
    (5, 0x71): "Toshiba",
    (5, 0x72): "Tensilica (Cadence)",
    # bank 6
    (6, 0x67): "Spansion",
    # bank 7
    (7, 0x04): "Faraday Technology",
    (7, 0x1E): "Andes Technology",
    (7, 0x20): "Achronix Semiconductor",
    (7, 0x32): "Montage Technology",
    (7, 0x48): "GigaDevice Semiconductor",
    (7, 0x76): "Holtek Semiconductor",
    # bank 8
    (8, 0x09): "Lantiq",
    (8, 0x0C): "ZTE Microelectronics",
    (8, 0x21): "Shanghai Fudan Microelectronics",
    (8, 0x36): "HiSilicon Technologies",
    (8, 0x51): "GigaDevice Semiconductor (Beijing)",
    # bank 9
    (9, 0x09): "Silicon Motion",
    (9, 0x0D): "Gowin Semiconductor",
    (9, 0x19): "Phytium",
    (9, 0x2D): "Nuvoton",
    (9, 0x4C): "Shenzhen Pango Microsystems",
    (9, 0x57): "Socionext",
    (9, 0x68): "Boya Microelectronics",
    (9, 0x79): "Realtek",
    # bank 10
    (10, 0x05): "Puya Semiconductor",
    (10, 0x09): "SiFive",
    (10, 0x0A): "Spreadtrum Communications",
    (10, 0x1E): "Allwinner Technology",
    (10, 0x20): "XMC",
    (10, 0x3B): "Artery Technology",
    (10, 0x5E): "Zbit Semiconductor",
    # bank 11
    (11, 0x36): "Nuclei System Technology",
    (11, 0x3C): "Efinix",
    (11, 0x75): "Arm Technology (China)",
    # bank 12
    (12, 0x19): "Allegro Microsystems",
    (12, 0x2D): "Shenzhen Goodix Technology",
    (12, 0x37): "C-SKY Microsystems (XuanTie)",
    (12, 0x62): "Pingtouge (T-Head) Semiconductor",
    # bank 13
    (13, 0x12): "Espressif Systems",
    (13, 0x2C): "Beijing ESWIN Computing",
    (13, 0x2F): "Unisoc",
    (13, 0x66): "Rockchip Electronics",
    (13, 0x6A): "Himax Technologies",
    (13, 0x7A): "Shanghai Zhaoxin Semiconductor",
    (13, 0x7E): "StarFive Technology",
    # bank 14
    (14, 0x15): "Shenzhen Sipeed Technology",
    (14, 0x25): "Ingenic Semiconductor",
    (14, 0x48): "Sunplus Technology",
    (14, 0x6F): "Qorvo",
    # bank 15
    (15, 0x49): "CEC Huada Electronic Design",
    (15, 0x6D): "Novatek Microelectronics",
}

# 잘 알려진 (제조사 11비트, part) → 설명. 보수적으로 확실한 것만.
KNOWN_PARTS: dict[tuple[int, int], str] = {
    (0x23B, 0xBA00): "ARM CoreSight JTAG-DP (ADIv5 디버그 포트; Cortex-A/R/M 계열 SoC 에서 흔함)",
    (0x23B, 0xBA01): "ARM CoreSight SW-DP (SWD 디버그 포트)",
    (0x23B, 0xBA02): "ARM CoreSight SW-DP v2 (SWD 디버그 포트)",
    (0x23B, 0xBB11): "ARM Cortex-M0 SW-DP",
    (0x23B, 0xBC11): "ARM Cortex-M0+ SW-DP",
    (0x787, 0x7926): "ARM926EJ-S 코어 TAP",
    (0x787, 0xF0F0): "ARM7TDMI 계열 코어 TAP",
    (0x787, 0xF1F0): "ARM7TDMI 계열 코어 TAP",
}

LEGACY_ARM_MFR = 0x787


def decode_idcode(value: int) -> dict[str, Any]:
    """32비트 IDCODE 를 필드로 나누고 제조사를 해석한다."""
    value &= 0xFFFFFFFF
    version = (value >> 28) & 0xF
    part = (value >> 12) & 0xFFFF
    mfr = (value >> 1) & 0x7FF
    bank = (mfr >> 7) + 1
    code = mfr & 0x7F
    notes: list[str] = []
    plausible = True
    if value & 1 != 1 or value == 0xFFFFFFFF:
        plausible = False
        notes.append("bit0 이 1 이 아니거나 0xFFFFFFFF — IEEE 1149.1 IDCODE 가 아님")
    name = JEP106_SUBSET.get((bank, code))
    if mfr == LEGACY_ARM_MFR:
        name = "ARM Ltd (레거시 IDCODE)"
        notes.append(
            "제조사 코드 0x787 은 ARM7/ARM9 계열 코어가 쓰는 레거시 값이다 "
            "(JEP106 에서는 이후 bank 16 의 다른 업체에 배정됨)."
        )
    if code in (0x00, 0x7F):
        plausible = False
        notes.append("JEP106 규격상 무효한 제조사 ID(0x00/0x7F) — 오탐(잡음) 가능성이 높음")
    elif name is None:
        notes.append("선별 목록에 없는 제조사 코드 — 전체 JEP106 표(예: OpenOCD 출력)로 확인 필요")
    desc = KNOWN_PARTS.get((mfr, part))
    out: dict[str, Any] = {
        "idcode": f"0x{value:08X}",
        "version": version,
        "part_number": f"0x{part:04X}",
        "manufacturer_id": f"0x{mfr:03X}",
        "jep106": {"bank": bank, "continuation_codes": bank - 1, "id": f"0x{code:02X}"},
        "manufacturer": name,
        "plausible": plausible,
    }
    if desc:
        out["description"] = desc
    if notes:
        out["notes"] = notes
    return out


# ---------------------------------------------------------------------------
# OpenOCD 스크립트 힌트 (선택)
# ---------------------------------------------------------------------------

_ID_LINE_RE = re.compile(r"(?i)(tapid|expected-id|cputapid|_tap_id|bstapid|idcode)[^\n]*?(0x[0-9a-f]{8})")
_INDEX: dict[str, dict[int, list[str]]] = {}
_INDEX_LOCK = threading.Lock()


def _build_index(scripts_dir: Path) -> dict[int, list[str]]:
    index: dict[int, list[str]] = {}
    for sub in ("target", "cpu", "fpga", "cpld", "chip", "board"):
        base = scripts_dir / sub
        if not base.is_dir():
            continue
        for p in sorted(base.rglob("*.cfg")):
            try:
                text = p.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            seen: set[int] = set()
            for m in _ID_LINE_RE.finditer(text):
                try:
                    val = int(m.group(2), 16)
                except ValueError:
                    continue
                if val in (0, 0xFFFFFFFF) or val in seen:
                    continue
                seen.add(val)
                index.setdefault(val, []).append(str(p.relative_to(scripts_dir)))
    return index


def openocd_target_hints(value: int, scripts_dir: str | os.PathLike[str] | None, limit: int = 8) -> dict[str, Any] | None:
    """같은 IDCODE(정확히, 그다음 버전 니블 무시)를 기대값으로 쓰는 OpenOCD cfg 파일 목록."""
    if not scripts_dir:
        return None
    sd = Path(scripts_dir).expanduser()
    if not sd.is_dir():
        return None
    key = str(sd.resolve())
    with _INDEX_LOCK:
        index = _INDEX.get(key)
        if index is None:
            index = _build_index(sd)
            _INDEX[key] = index
    value &= 0xFFFFFFFF
    exact = sorted(index.get(value, []), key=lambda s: (not s.startswith("target/"), s))
    loose: list[str] = []
    if not exact:
        for k, files in index.items():
            if (k & 0x0FFFFFFF) == (value & 0x0FFFFFFF):
                loose.extend(files)
        loose = sorted(set(loose), key=lambda s: (not s.startswith("target/"), s))
    files = exact or loose
    if not files:
        return {"scripts_dir": key, "match": "none", "count": 0, "configs": []}
    out = {
        "scripts_dir": key,
        "match": "exact" if exact else "version-insensitive",
        "count": len(files),
        "configs": files[:limit],
    }
    if len(files) > limit:
        out["note"] = "많은 cfg 가 같은 IDCODE 를 쓴다(예: 범용 ARM CoreSight DAP). SoC 를 특정하지 못하므로 보드/칩 표기로 좁혀야 한다."
    return out
