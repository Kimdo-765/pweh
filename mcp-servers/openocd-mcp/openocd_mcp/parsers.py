"""OpenOCD 명령 출력 파서.

형식 근거 (추측 금지 — 모두 1차 출처 확인):
- 소스: openocd-org/openocd e5888bda3 (xPack 0.12.0-7 의 실체) 의 포맷 문자열
  * ``scan_chain``      src/jtag/tcl.c   ``"%2u %-18s     %c     0x%08x %s %5u 0x%02x  0x%02x"``
  * ``targets``         src/target/target.c ``"%2d%c %-18s %-10s %-6s %-18s %s"``
  * ``reg``             src/target/target.c ``"(%i) %s (/%u): 0x%s%s"`` / ``"(%i) %s (/%u)"`` / ``"%s (/%i): 0x%s"``
  * ``md[bhwd]``        src/target/target.c target_handle_md_output (줄당 32바이트, ``0x%8.8llx: `` + 값 + 공백)
  * ``read_memory``     ``"0x%llx"`` 공백 구분 (0 패딩 없음), 실패 시 ``failed to read memory`` 가 뒤에 붙음
  * ``flash banks``     src/flash/nor/tcl.c ``"#%d : %s (%s) at 0x%8.8llx, size 0x%8.8x, buswidth %u, chipwidth %u"``
  * ``flash info``      헤더 ``"#%u : %s at ..."`` + 섹터 ``"\\t#%3i: 0x%8.8x (0x%x %ukB) %s"``
  * ``flash list``      xPack/master 는 여러 줄 dict, 0.12.0 은 한 줄 dict(10진) — Tcl 리스트로 해석
  * 로그 ``JTAG tap: %s %16.16s: 0x%08x (mfg: 0x%3.3x (%s), part: 0x%4.4x, ver: 0x%1.1x)`` (src/jtag/core.c)
- 실측: ~/pweh-tools/INSTALL_REPORT.md, verify/results/openocd_*.jsonl, docs/references/openocd-tcl-rpc.md

0.11/0.12.0 은 결과 끝 개행을 남기고, capture 로그가 앞에 섞일 수 있으므로 모든 파서는
헤더/행 패턴을 줄 단위로 찾고 나머지 줄은 무시한다.
"""

from __future__ import annotations

import re
from typing import Any

from .tcl import TclParseError, split_list

# ---------------------------------------------------------------------------
# version
# ---------------------------------------------------------------------------

_VERSION_RE = re.compile(
    r"(?P<vendor>\S+\s+)?Open On-Chip Debugger\s+v?(?P<ver>\d+\.\d+\.\d+)(?P<rest>\S*)(?:\s+\((?P<date>[^)]*)\))?"
)


def parse_version(text: str) -> dict[str, Any]:
    """``version`` / ``openocd --version`` 출력 해석."""
    out: dict[str, Any] = {"raw": (text or "").strip().splitlines()[0] if (text or "").strip() else ""}
    m = _VERSION_RE.search(text or "")
    if not m:
        out["parsed"] = False
        return out
    major, minor, patch = (int(x) for x in m.group("ver").split("."))
    rest = m.group("rest") or ""
    out.update(
        {
            "parsed": True,
            "vendor": (m.group("vendor") or "").strip() or None,
            "version": m.group("ver"),
            "major": major,
            "minor": minor,
            "patch": patch,
            "dev": "+dev" in rest,
            "suffix": rest or None,
            "build_date": m.group("date"),
        }
    )
    dm = re.search(r"\+dev-(\d+)-g([0-9a-f]+)", rest)
    if dm:
        out["dev_count"] = int(dm.group(1))
        out["git"] = dm.group(2)
    return out


# ---------------------------------------------------------------------------
# IDCODE
# ---------------------------------------------------------------------------

# OpenOCD src/helper/jep106.inc (JEP106BM) 에서 그대로 옮긴 일부 항목: (bank, id) → 이름.
# OpenOCD 로그(``mfg: 0x23b (ARM Ltd)``)가 있으면 그쪽 이름을 우선한다.
JEP106_SUBSET: dict[tuple[int, int], str] = {
    (0, 0x01): "AMD",
    (0, 0x09): "Intel",
    (0, 0x0E): "Freescale (Motorola)",
    (0, 0x15): "NXP (Philips)",
    (0, 0x17): "Texas Instruments",
    (0, 0x1F): "Atmel",
    (0, 0x20): "STMicroelectronics",
    (0, 0x21): "Lattice Semi.",
    (0, 0x29): "Microchip Technology",
    (0, 0x34): "Cypress",
    (0, 0x41): "Infineon (Siemens)",
    (0, 0x49): "Xilinx",
    (0, 0x4E): "Samsung",
    (0, 0x6E): "Altera",
    (0, 0x70): "Qualcomm",
    (1, 0x3F): "Broadcom",
    (2, 0x27): "MIPS Technologies",
    (3, 0x4C): "Cavium Networks",
    (3, 0x69): "Marvell Semiconductors",
    (4, 0x23): "Renesas Electronics",
    (4, 0x26): "MediaTek",
    (4, 0x3B): "ARM Ltd",
    (6, 0x1E): "Andes Technology Corporation",
    (7, 0x36): "HiSilicon Technologies",
    (8, 0x79): "Realtek",
    (9, 0x09): "SiFive Inc",
    (9, 0x1E): "Allwinner Technology",
    (12, 0x12): "Espressif Systems (Shanghai) Co Ltd",
    (12, 0x66): "Rockchip Electronics Co Ltd",
    (13, 0x25): "Ingenic Semiconductor Co Ltd",
    (14, 0x6D): "Novatek Microelectronics Corp",
}


def decode_idcode(idcode: int) -> dict[str, Any]:
    """IEEE 1149.1 IDCODE 필드 분해: version[31:28] part[27:12] manufacturer[11:1] 1[0]."""
    idcode &= 0xFFFFFFFF
    mfg = (idcode >> 1) & 0x7FF
    bank, jid = mfg >> 7, mfg & 0x7F
    valid = bool(idcode & 1) and idcode not in (0x00000000, 0xFFFFFFFF) and 1 <= jid <= 126
    out: dict[str, Any] = {
        "valid": valid,
        "version": (idcode >> 28) & 0xF,
        "part": f"0x{(idcode >> 12) & 0xFFFF:04x}",
        "manufacturer_code": f"0x{mfg:03x}",
        "jep106_bank": bank,
        "jep106_id": f"0x{jid:02x}",
    }
    if valid:
        name = JEP106_SUBSET.get((bank, jid))
        if name:
            out["manufacturer"] = name
    if idcode == 0:
        out["note"] = "IDCODE 0x00000000 — 체인 탐색 실패/BYPASS 전용 TAP/init 전 상태일 수 있음"
    elif idcode == 0xFFFFFFFF:
        out["note"] = "IDCODE 0xffffffff — TDO 가 계속 1 (타깃 없음/전원·배선 문제)"
    elif not idcode & 1:
        out["note"] = "LSB 가 0 — 유효한 IDCODE 가 아님 (BYPASS 레지스터를 읽었을 수 있음)"
    return out


def _idcode_matches(idcode: int, expected: str) -> bool:
    """scan_chain 의 Expected 열(``0x*ba00477`` 처럼 버전 니블 와일드카드 가능)과 비교."""
    e = expected.lower()
    if e.startswith("0x*"):
        try:
            return (idcode & 0x0FFFFFFF) == (int(e[3:], 16) & 0x0FFFFFFF)
        except ValueError:
            return False
    try:
        return idcode == int(e, 16)
    except ValueError:
        return False


# ---------------------------------------------------------------------------
# scan_chain
# ---------------------------------------------------------------------------

_SCAN_ROW = re.compile(
    r"^\s*(?P<idx>\d+)\s+(?P<name>\S+)\s+(?P<en>[Yn])\s+(?P<idcode>0x[0-9a-fA-F]{8})\s+"
    r"(?P<expected>0x[0-9a-fA-F*]{8})\s+(?P<irlen>\d+)\s+(?P<ircap>0x[0-9a-fA-F]+)\s+(?P<irmask>0x[0-9a-fA-F]+)\s*$"
)
_SCAN_CONT = re.compile(r"^\s{20,}(?P<expected>0x[0-9a-fA-F*]{8})\s*$")


def parse_scan_chain(text: str) -> list[dict[str, Any]]:
    taps: list[dict[str, Any]] = []
    for line in (text or "").splitlines():
        m = _SCAN_ROW.match(line)
        if m:
            idcode = int(m.group("idcode"), 16)
            taps.append(
                {
                    "index": int(m.group("idx")),
                    "tap_name": m.group("name"),
                    "enabled": m.group("en") == "Y",
                    "idcode": m.group("idcode").lower(),
                    "expected": m.group("expected").lower(),
                    "expected_ids": [m.group("expected").lower()],
                    "irlen": int(m.group("irlen")),
                    "ircap": m.group("ircap").lower(),
                    "irmask": m.group("irmask").lower(),
                    "decoded": decode_idcode(idcode),
                }
            )
            continue
        c = _SCAN_CONT.match(line)
        if c and taps:
            taps[-1]["expected_ids"].append(c.group("expected").lower())
    for tap in taps:
        idv = int(tap["idcode"], 16)
        exps = [e for e in tap["expected_ids"] if e not in ("0x00000000",)]
        tap["expected_configured"] = bool(exps)
        tap["mismatch"] = bool(exps) and not any(_idcode_matches(idv, e) for e in exps)
    return taps


# ---------------------------------------------------------------------------
# targets
# ---------------------------------------------------------------------------

_TARGET_ROW = re.compile(
    r"^\s*(?P<idx>\d+)(?P<cur>\*)?\s+(?P<name>\S+)\s+(?P<type>\S+)\s+(?P<endian>\S+)\s+(?P<tap>\S+)\s+(?P<state>\S.*?)\s*$"
)


def parse_targets(text: str) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    seen_header = False
    for line in (text or "").splitlines():
        if "TargetName" in line and "Endian" in line:
            seen_header = True
            continue
        if line.startswith("--"):
            continue
        if not seen_header:
            continue
        m = _TARGET_ROW.match(line)
        if m:
            rows.append(
                {
                    "index": int(m.group("idx")),
                    "current": bool(m.group("cur")),
                    "name": m.group("name"),
                    "type": m.group("type"),
                    "endian": m.group("endian"),
                    "tap_name": m.group("tap"),
                    "state": m.group("state"),
                }
            )
    return rows


def parse_target_names(text: str) -> list[str]:
    """``target names`` 결과 → 타깃 이름 목록.

    실측(xPack 0.12.0-7): 이름마다 한 줄(command_print, 끝 개행은 봉투가 제거) — ``dummy.cpu\\ncpu0``.
    0.12.0 이하 릴리스: Jim 리스트(공백 구분, 특수 문자가 든 이름은 ``{…}``).
    여러 줄이면 줄마다 이름 하나(공백이 든 이름도 통째로), 한 줄이면 Tcl 리스트로 해석한다(이름이 하나면 두 형식이 같다).
    한계: 줄 단위 형식에서 타깃이 하나뿐이고 그 이름에 공백이 있으면 낱말로 나뉜다 — 호출하는 쪽은 이름 형식(공백 없음)을
    검사하고, 명령 이름과 겹치는 낱말은 접두로 쓰지 않는다(``guard.target_name_conflict``).
    """
    lines = [ln.strip() for ln in (text or "").split("\n")]
    lines = [ln for ln in lines if ln]
    if len(lines) != 1:
        return lines
    try:
        return split_list(lines[0])
    except TclParseError:
        return lines


def current_target(rows: list[dict[str, Any]], name: str | None = None) -> dict[str, Any] | None:
    if name:
        for r in rows:
            if r["name"] == name:
                return r
        return None
    for r in rows:
        if r.get("current"):
            return r
    return rows[0] if len(rows) == 1 else None


# ---------------------------------------------------------------------------
# reg
# ---------------------------------------------------------------------------

_REG_CACHE = re.compile(r"^===== (?P<cache>.*?)\s*$")
_REG_LINE = re.compile(r"^\((?P<num>\d+)\) (?P<name>.+?) \(/(?P<bits>\d+)\)(?:: 0x(?P<value>[0-9a-fA-F]+))?(?P<dirty> \(dirty\))?\s*$")
_REG_SINGLE = re.compile(r"^(?P<name>\S.*?) \(/(?P<bits>\d+)\): 0x(?P<value>[0-9a-fA-F]+)\s*$")


def parse_reg_list(text: str) -> list[dict[str, Any]]:
    """``reg`` (인자 없음) 출력 → 레지스터 목록 (캐시 값이 없으면 value=None)."""
    regs: list[dict[str, Any]] = []
    cache = None
    for line in (text or "").splitlines():
        cm = _REG_CACHE.match(line)
        if cm:
            cache = cm.group("cache")
            continue
        m = _REG_LINE.match(line)
        if m:
            regs.append(
                {
                    "number": int(m.group("num")),
                    "name": m.group("name"),
                    "bits": int(m.group("bits")),
                    "value": ("0x" + m.group("value").lower()) if m.group("value") is not None else None,
                    "dirty": bool(m.group("dirty")),
                    "cache": cache,
                }
            )
    return regs


def parse_reg_single(text: str) -> dict[str, Any] | None:
    """``reg <name>`` 출력 → {name, bits, value}. 로그 줄이 앞에 있을 수 있으므로 마지막 일치 줄."""
    found = None
    for line in (text or "").splitlines():
        m = _REG_SINGLE.match(line.strip())
        if m:
            found = {"name": m.group("name"), "bits": int(m.group("bits")), "value": "0x" + m.group("value").lower()}
    return found


# ---------------------------------------------------------------------------
# 메모리
# ---------------------------------------------------------------------------

_MD_LINE = re.compile(r"^(?P<addr>0x[0-9a-fA-F]+): (?P<vals>(?:[0-9a-fA-F]+ ?)+)\s*$")


def parse_md(text: str) -> list[tuple[int, int]]:
    """``mdw/mdh/mdb/mdd`` 출력 → [(주소, 값)] (값은 타깃 엔디언으로 해석된 정수)."""
    out: list[tuple[int, int]] = []
    width = None
    for line in (text or "").splitlines():
        m = _MD_LINE.match(line.strip())
        if not m:
            continue
        base = int(m.group("addr"), 16)
        vals = m.group("vals").split()
        if not vals:
            continue
        w = len(vals[0]) // 2
        if width is None:
            width = w
        for i, v in enumerate(vals):
            out.append((base + i * w, int(v, 16)))
    return out


_READ_FAIL_MARKERS = ("read_memory: failed to read memory", "failed to read memory")


def parse_read_memory(text: str) -> tuple[list[int], str | None]:
    """``read_memory`` 출력 → (값 목록, 오류 문자열 또는 None).

    실패하면 OpenOCD 가 이미 읽은 값 뒤에 공백 없이 ``failed to read memory`` 를 붙이므로
    (``0x1 0x2failed ...`` — 'fa' 가 16진수로 잘못 읽히지 않도록) 표지 앞에서 자른다.
    """
    t = text or ""
    err = None
    for marker in _READ_FAIL_MARKERS:
        idx = t.find(marker)
        if idx >= 0:
            err = t[idx:].strip()
            t = t[:idx]
            break
    vals: list[int] = []
    for tok in t.split():
        if re.fullmatch(r"0x[0-9a-fA-F]+", tok):
            vals.append(int(tok, 16))
        elif re.fullmatch(r"\d+", tok):  # mem2array/array get 등 10진
            vals.append(int(tok))
        else:
            err = err or f"예상하지 못한 토큰: {tok[:40]!r}"
            break
    return vals, err


def values_to_bytes(values: list[int], width_bytes: int, endian: str = "little") -> bytes:
    """타깃 엔디언 정수 값 목록 → 메모리 순서 바이트열."""
    order = "big" if str(endian).lower().startswith("b") else "little"
    mask = (1 << (8 * width_bytes)) - 1
    return b"".join((v & mask).to_bytes(width_bytes, order) for v in values)


# ---------------------------------------------------------------------------
# flash
# ---------------------------------------------------------------------------

_FLASH_BANK = re.compile(
    r"^#(?P<num>\d+)\s*:\s*(?P<name>\S+)\s+\((?P<driver>[^)]*)\)\s+at\s+(?P<base>0x[0-9a-fA-F]+),\s*size\s+(?P<size>0x[0-9a-fA-F]+),"
    r"\s*buswidth\s+(?P<bus>\d+),\s*chipwidth\s+(?P<chip>\d+)"
)
_FLASH_INFO_HDR = re.compile(
    r"^#(?P<num>\d+)\s*:\s*(?P<driver>\S+)\s+at\s+(?P<base>0x[0-9a-fA-F]+),\s*size\s+(?P<size>0x[0-9a-fA-F]+),"
    r"\s*buswidth\s+(?P<bus>\d+),\s*chipwidth\s+(?P<chip>\d+)"
)
_FLASH_SECTOR = re.compile(r"^\s*#\s*(?P<idx>\d+):\s+(?P<off>0x[0-9a-fA-F]+)\s+\((?P<size>0x[0-9a-fA-F]+)\s+(?P<kb>\d+)kB\)\s*(?P<prot>.*?)\s*$")


def parse_flash_banks(text: str) -> list[dict[str, Any]]:
    banks: list[dict[str, Any]] = []
    for line in (text or "").splitlines():
        m = _FLASH_BANK.match(line.strip())
        if m:
            base, size = int(m.group("base"), 16), int(m.group("size"), 16)
            banks.append(
                {
                    "bank": int(m.group("num")),
                    "name": m.group("name"),
                    "driver": m.group("driver"),
                    "base": f"0x{base:08x}",
                    "base_int": base,
                    "size": size,
                    "size_hex": f"0x{size:x}",
                    "bus_width": int(m.group("bus")),
                    "chip_width": int(m.group("chip")),
                }
            )
    return banks


def parse_flash_info(text: str) -> dict[str, Any] | None:
    lines = (text or "").splitlines()
    hdr_idx = None
    info: dict[str, Any] = {}
    for i, line in enumerate(lines):
        m = _FLASH_INFO_HDR.match(line.strip())
        if m:
            base, size = int(m.group("base"), 16), int(m.group("size"), 16)
            info = {
                "bank": int(m.group("num")),
                "driver": m.group("driver"),
                "base": f"0x{base:08x}",
                "base_int": base,
                "size": size,
                "size_hex": f"0x{size:x}",
                "bus_width": int(m.group("bus")),
                "chip_width": int(m.group("chip")),
                "sectors": [],
            }
            hdr_idx = i
            break
    if hdr_idx is None:
        return None
    extra: list[str] = []
    for line in lines[hdr_idx + 1 :]:
        m = _FLASH_SECTOR.match(line)
        if m:
            info["sectors"].append(
                {
                    "index": int(m.group("idx")),
                    "offset": int(m.group("off"), 16),
                    "size": int(m.group("size"), 16),
                    "protection": m.group("prot") or None,
                }
            )
        elif line.strip():
            extra.append(line.rstrip())
    if extra:
        info["driver_info"] = "\n".join(extra)
    return info


def _to_int(v: str) -> int | None:
    try:
        return int(str(v).strip(), 0)
    except (TypeError, ValueError):
        return None


def parse_flash_list(text: str) -> list[dict[str, Any]]:
    """``flash list`` → [{name, driver, base, size, bus_width, chip_width, target}] (버전별 형식 모두)."""
    out: list[dict[str, Any]] = []
    try:
        elems = split_list((text or "").strip())
    except TclParseError:
        return out
    for el in elems:
        try:
            kv = split_list(el)
        except TclParseError:
            continue
        if len(kv) < 2 or len(kv) % 2:
            continue
        d = dict(zip(kv[0::2], kv[1::2]))
        row: dict[str, Any] = {}
        for k in ("name", "driver", "target"):
            if k in d:
                row[k] = d[k]
        for k in ("base", "size", "bus_width", "chip_width"):
            if k in d:
                row[k] = _to_int(d[k])
        if row:
            out.append(row)
    return out


_DUMPED = re.compile(r"dumped (\d+) bytes")
_WROTE_FILE = re.compile(r"wrote (\d+) bytes to file")


def parse_dumped_bytes(text: str) -> int | None:
    m = _DUMPED.search(text or "")
    return int(m.group(1)) if m else None


def parse_read_bank_bytes(text: str) -> int | None:
    m = _WROTE_FILE.search(text or "")
    return int(m.group(1)) if m else None


def parse_verify_bank(text: str) -> bool | None:
    t = text or ""
    if "contents match" in t:
        return True
    if "contents differ" in t:
        return False
    return None


# ---------------------------------------------------------------------------
# OpenOCD 로그
# ---------------------------------------------------------------------------

_LOG_TAP = re.compile(
    r"JTAG tap: (?P<tap>\S+)\s+(?P<msg>tap/device found|UNEXPECTED|expected \d+ of \d+): 0x(?P<id>[0-9a-fA-F]{8}) "
    r"\(mfg: 0x(?P<mfg>[0-9a-fA-F]+) \((?P<mname>.*)\), part: 0x(?P<part>[0-9a-fA-F]+), ver: 0x(?P<ver>[0-9a-fA-F]+)\)"
)
_LOG_AUTO = re.compile(r'AUTO (?P<tap>\S+) - use "(?P<cmd>jtag newtap [^"]+)"')
_LOG_EXAM = re.compile(r"(?:\[(?P<target>[^\]]+)\] )?Examination (?P<res>succeed|failed)")
_LOG_LISTEN = re.compile(r"Listening on port (?P<port>\d+) for (?P<svc>\w+) connections")


def parse_log_taps(text: str) -> list[dict[str, Any]]:
    """OpenOCD 로그의 ``JTAG tap: ...`` 줄 → TAP 검출 정보 (제조사 이름 포함)."""
    out = []
    for m in _LOG_TAP.finditer(text or ""):
        out.append(
            {
                "tap_name": m.group("tap"),
                "event": m.group("msg"),
                "idcode": "0x" + m.group("id").lower(),
                "manufacturer_code": "0x" + m.group("mfg").lower(),
                "manufacturer": m.group("mname"),
                "part": "0x" + m.group("part").lower(),
                "version": int(m.group("ver"), 16),
            }
        )
    return out


def parse_log_summary(text: str) -> dict[str, Any]:
    """기동 로그 요약: TAP 검출, AUTO 힌트, 타깃 검사 결과, 열린 포트, Error/Warn 줄."""
    t = text or ""
    errors, warnings = [], []
    for line in t.splitlines():
        if line.startswith("Error: "):
            errors.append(line[7:].strip())
        elif line.startswith("Warn : "):
            warnings.append(line[7:].strip())
    return {
        "taps": parse_log_taps(t),
        "auto_newtap_suggestions": [{"tap": m.group("tap"), "command": m.group("cmd")} for m in _LOG_AUTO.finditer(t)],
        "examination": [{"target": m.group("target"), "result": m.group("res")} for m in _LOG_EXAM.finditer(t)],
        "listening": {m.group("svc"): int(m.group("port")) for m in _LOG_LISTEN.finditer(t)},
        "errors": errors,
        "warnings": warnings,
    }


# (정규식, 코드, 설명, 조치 힌트) — 메시지 문자열은 OpenOCD 소스에서 확인한 것만 사용
_DIAG_RULES: list[tuple[re.Pattern[str], str, str, str]] = [
    (re.compile(r"JTAG scan chain interrogation failed: all ones"), "jtag_all_ones",
     "스캔체인 응답이 전부 1 (TDO 가 계속 High)",
     "타깃 전원/GND 공통 연결, TDO 배선, VREF(1.8V/3.3V) 레벨, 핀 순서를 확인하세요. 카메라 SoC 는 JTAG 이 퓨즈로 꺼져 있거나 "
     "다른 기능(SDIO/GPIO)으로 먹스되어 있을 수 있습니다."),
    (re.compile(r"JTAG scan chain interrogation failed: all zeroes"), "jtag_all_zeroes",
     "스캔체인 응답이 전부 0 (TDO 가 계속 Low)",
     "TAP 이 리셋(TRST/SRST)에 묶여 있거나 TDO 가 GND 에 단락/잘못된 핀일 수 있습니다. TRST 배선과 reset_config 를 확인하세요."),
    (re.compile(r"IR capture error; saw 0x[0-9a-fA-F]+ not 0x[0-9a-fA-F]+"), "ir_capture_error",
     "IR 캡처 값 불일치",
     "jtag newtap 의 -irlen/-ircapture/-irmask 가 실제 칩과 다르거나 신호 품질 문제입니다. adapter speed 를 낮추고(예: 100~500kHz) "
     "target cfg 없이 자동 탐색(AUTO 힌트)으로 irlen 을 확인하세요."),
    (re.compile(r"UNEXPECTED: 0x[0-9a-fA-F]{8}"), "idcode_mismatch",
     "IDCODE 가 cfg 의 -expected-id 와 다름",
     "다른 칩용 target cfg 를 쓰고 있을 가능성이 큽니다. scan_chain 의 실제 IDCODE 로 cfg 를 고르거나 작성하세요."),
    (re.compile(r"unable to open ftdi device|LIBUSB_ERROR_ACCESS|libusb_open\(\) failed"), "usb_open_failed",
     "USB 프로브를 열 수 없음",
     "프로브 연결, vid/pid, USB 권한(udev 규칙)을 확인하세요. WSL2 는 usbipd 로 USB 장치를 리눅스에 붙여야 합니다."),
    (re.compile(r"No J-Link device found"), "jlink_not_found", "J-Link 를 찾을 수 없음",
     "J-Link 연결/드라이버(udev)와 WSL2 usbipd 연결을 확인하세요."),
    (re.compile(r"ST-LINK open failed|^Error: open failed", re.M), "stlink_open_failed", "ST-Link 를 열 수 없음",
     "ST-Link 연결과 권한을 확인하세요. (ST-Link 는 주로 STM32 SWD 용이며 카메라 SoC 에는 부적합)"),
    (re.compile(r"couldn't bind \w+ to socket on port \d+: Address already in use"), "port_in_use",
     "포트가 이미 사용 중", "다른 OpenOCD 가 실행 중입니다. openocd_attach 로 붙거나 다른 tcl_port 를 쓰세요."),
    (re.compile(r"Can't find \S+"), "cfg_not_found", "설정 파일을 찾을 수 없음",
     "cfg 경로를 확인하세요 (openocd_list_configs 로 검색 가능, scripts 디렉터리 기준 상대 경로 예: interface/ftdi/tigard.cfg)."),
    (re.compile(r"The specified adapter driver was not found|Debug Adapter has to be specified"), "adapter_driver",
     "어댑터 드라이버 문제", "interface cfg 를 확인하세요 (이 OpenOCD 빌드에 해당 드라이버가 없을 수 있음)."),
    (re.compile(r"session transport was not selected|doesn't support '\w+' transport|No transport named"), "transport",
     "트랜스포트 선택 문제", "transport 인자(jtag/swd)를 어댑터가 지원하는 값으로 지정하세요."),
    (re.compile(r"Error connecting DP: cannot read IDR"), "swd_dp_error", "SWD DP 연결 실패",
     "SWDIO/SWCLK 배선, 전원, 속도를 확인하세요."),
    (re.compile(r"Examination failed"), "examine_failed", "타깃(코어) 검사 실패",
     "TAP 은 보이지만 코어 디버그에 접근하지 못했습니다. 잘못된 target cfg, 디버그 잠금(보안 퓨즈), 코어 전원/클럭 꺼짐, "
     "JTAG 먹스 변경 등을 의심하세요. scan_chain 으로 TAP 을 먼저 확인하세요."),
    (re.compile(r"timed out while waiting for target halted"), "halt_timeout", "halt 시간 초과",
     "코어가 리셋에 묶였거나 디버그가 비활성일 수 있습니다. reset halt 를 시도하거나 U-Boot 단계에서 다시 시도하세요."),
    (re.compile(r"\bnot halted\b", re.I), "target_not_halted", "타깃이 halt 상태가 아님",
     "메모리/레지스터 접근 전에 openocd_halt 를 호출하세요 (Cortex-A 는 mem_ap 타깃을 쓰면 halt 없이 읽을 수 있음)."),
    (re.compile(r"Target not examined yet|\bnot examined\b"), "target_not_examined", "타깃이 아직 검사되지 않음",
     "init/examine 이 실패했습니다. 기동 로그의 Error 줄과 scan_chain 결과를 확인하세요."),
    (re.compile(r"Failed to read memory at 0x[0-9a-fA-F]+"), "memory_read_failed", "메모리 읽기 실패",
     "주소가 매핑되지 않았거나(버스 오류) 코어가 실행 중/MMU 문제일 수 있습니다. 주소 범위를 확인하세요."),
    (re.compile(r"doesn't support (read|write)_memory"), "memory_unsupported", "타깃이 메모리 접근을 지원하지 않음",
     "이 타깃 유형(예: testee)은 메모리 접근이 없습니다."),
]


def diagnose(text: str) -> list[dict[str, str]]:
    """OpenOCD 로그/오류 텍스트에서 알려진 문제 패턴을 찾아 조치 힌트를 만든다."""
    out: list[dict[str, str]] = []
    seen: set[str] = set()
    t = text or ""
    for rx, code, msg, hint in _DIAG_RULES:
        m = rx.search(t)
        if m and code not in seen:
            seen.add(code)
            out.append({"code": code, "message": msg, "evidence": m.group(0)[:200], "hint": hint})
    return out


__all__ = [
    "JEP106_SUBSET",
    "current_target",
    "decode_idcode",
    "diagnose",
    "parse_dumped_bytes",
    "parse_flash_banks",
    "parse_flash_info",
    "parse_flash_list",
    "parse_log_summary",
    "parse_log_taps",
    "parse_md",
    "parse_read_bank_bytes",
    "parse_read_memory",
    "parse_reg_list",
    "parse_reg_single",
    "parse_scan_chain",
    "parse_targets",
    "parse_verify_bank",
    "parse_version",
    "values_to_bytes",
]
