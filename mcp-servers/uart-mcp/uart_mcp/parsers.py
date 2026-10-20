"""U-Boot / BusyBox 콘솔 출력 파서 (순수 함수, 벤더 변형에 관대하게).

형식 근거: docs/references/uboot-and-boot-console.md (§3 md, §4 crc32, §5 sf, §6 printenv, §11 리눅스 쪽, §15 정규식)
와 pweh.mocktarget 의 녹화 로그(tests/mock-targets/recorded/).
"""

from __future__ import annotations

import base64
import binascii
import re
from typing import Any, Iterable

from pweh.errors import ValidationFailed
from pweh.formats import parse_md_b_line, parse_md_b_output, parse_mtdparts, parse_proc_mtd

from .textutil import normalize_newlines, render_text, visible_line

MiB = 1024 * 1024


def _lines(text: str) -> list[str]:
    return [visible_line(ln) for ln in normalize_newlines(text).split("\n")]


# ---------------------------------------------------------------------------
# 크기 문자열
# ---------------------------------------------------------------------------
_SIZE_RE = re.compile(r"^\s*([\d.]+)\s*([KMGT]?)(i?B|Bytes?)?\s*$", re.I)


def parse_print_size(text: str | None) -> int | None:
    """U-Boot print_size()/HiSilicon ultohstr() 표기 → 바이트. '16 MiB', '64 KiB', '256 Bytes', '16MB', '64K', '16M'."""
    if not text:
        return None
    m = _SIZE_RE.match(str(text))
    if not m:
        return None
    try:
        num = float(m.group(1))
    except ValueError:
        return None
    mult = {"": 1, "K": 1024, "M": MiB, "G": 1024 * MiB, "T": 1024 * 1024 * MiB}[m.group(2).upper()]
    return int(num * mult)


# ---------------------------------------------------------------------------
# U-Boot: printenv
# ---------------------------------------------------------------------------
ENV_SIZE_RE = re.compile(r"^Environment size: (\d+)/(\d+) bytes")
_ENV_LINE_RE = re.compile(r"^([^=\s]+)=(.*)$")


def parse_printenv(text: str) -> dict[str, Any]:
    """printenv 출력 → {env, order, size_used, size_total, complete, errors}.

    값에 줄바꿈이 있으면 다음 줄(= 이 없는 줄)을 이어 붙인다. 'Environment size' 줄이 있어야 complete=True.
    """
    env: dict[str, str] = {}
    order: list[str] = []
    errors: list[str] = []
    used = total = None
    last: str | None = None
    for line in _lines(text):
        if not line.strip():
            last = None
            continue
        m = ENV_SIZE_RE.match(line.strip())
        if m:
            used, total = int(m.group(1)), int(m.group(2))
            last = None
            continue
        if line.startswith("## Error") or line.startswith("Unknown command"):
            errors.append(line.strip())
            continue
        m = _ENV_LINE_RE.match(line)
        if m:
            k, v = m.group(1), m.group(2)
            if k not in env:
                order.append(k)
            env[k] = v
            last = k
        elif last is not None:
            env[last] += "\n" + line
    return {"env": env, "order": order, "size_used": used, "size_total": total, "complete": used is not None, "errors": errors}


_LOAD_CMD_RE = re.compile(r"\b(sf|nand|mmc)\s+read\s+(0x[0-9a-fA-F]+|[0-9a-fA-F]+)\s+(0x[0-9a-fA-F]+|[0-9a-fA-F]+)\s+(0x[0-9a-fA-F]+|[0-9a-fA-F]+)")
_BOOTM_RE = re.compile(r"\bboot[mz]\s+(0x[0-9a-fA-F]+|[0-9a-fA-F]+)\b")


def _hexint(s: str | None) -> int | None:
    if s is None:
        return None
    s = str(s).strip()
    try:
        return int(s, 16)
    except ValueError:
        return None


def env_load_regions(env: dict[str, str]) -> list[tuple[str, int, int | None]]:
    """env 에서 RAM 적재 영역 후보 (이름, 주소, 길이|None). bootcmd 의 `sf read <addr> <off> <len>` 은 벤더가 실제로 쓰는 영역이다."""
    out: list[tuple[str, int, int | None]] = []
    bootcmd = env.get("bootcmd") or ""
    for m in _LOAD_CMD_RE.finditer(bootcmd):
        addr, length = _hexint(m.group(2)), _hexint(m.group(4))
        if addr is not None:
            if m.group(1) == "mmc" and length is not None:
                length *= 512
            out.append((f"bootcmd {m.group(1)} read", addr, length))
    for key in ("loadaddr", "kernel_addr_r", "kernel_addr", "baseaddr", "fileaddr"):
        v = _hexint(env.get(key))
        if v is not None:
            out.append((f"env {key}", v, None))
    m = _BOOTM_RE.search(bootcmd)
    if m and _hexint(m.group(1)) is not None:
        out.append(("bootcmd bootm", _hexint(m.group(1)), None))  # type: ignore[arg-type]
    return out


def env_load_addresses(env: dict[str, str]) -> list[tuple[str, int]]:
    """env 에서 RAM 적재 주소 후보 (bootcmd 의 sf read 주소, loadaddr, bootm …)."""
    seen: set[int] = set()
    out: list[tuple[str, int]] = []
    for name, addr, _ in env_load_regions(env):
        if addr not in seen:
            seen.add(addr)
            out.append((name, addr))
    return out


def env_mtdparts(env: dict[str, str]) -> str | None:
    if env.get("mtdparts"):
        v = env["mtdparts"].strip()
        return v if v.startswith("mtdparts=") else f"mtdparts={v}"
    m = re.search(r"(mtdparts=\S+)", env.get("bootargs") or "")
    return m.group(1) if m else None


def partitions_from_mtdparts(mtdparts: str | None, total_size: int | None = None) -> list[dict[str, Any]]:
    if not mtdparts:
        return []
    try:
        parts = parse_mtdparts(mtdparts, total_size)
    except ValidationFailed:
        return []
    out = []
    for p in parts:
        out.append({"name": p["name"], "offset": p["offset"], "size": p["size"], "offset_hex": f"0x{p['offset']:x}",
                    "size_hex": None if p["size"] is None else f"0x{p['size']:x}", "device": p["device"], "ro": p["ro"]})
    return out


# ---------------------------------------------------------------------------
# U-Boot: bdinfo / version / help / sf probe
# ---------------------------------------------------------------------------
_BDI_RE = re.compile(r"^\s*(->\s*)?([A-Za-z_][A-Za-z0-9_ #/.()-]*?)\s*=\s*(.*?)\s*$")


def _bdi_value(v: str) -> int | str:
    m = re.match(r"^(0x[0-9a-fA-F]+)$", v)
    if m:
        return int(m.group(1), 16)
    m = re.match(r"^(\d+)\s*bps$", v)
    if m:
        return int(m.group(1))
    return v


def parse_bdinfo(text: str) -> dict[str, Any]:
    """bdinfo → {raw{}, banks[], dram_start, dram_size, relocaddr, reloc_off, sp_start, irq_sp, tlb_addr, boot_params, ...}.

    ARM(2010/2016: 'DRAM bank = N' + '-> start' + '-> size'), MIPS(memstart/memsize), 최신 메인라인 형식을 모두 받는다.
    """
    raw: dict[str, Any] = {}
    banks: list[dict[str, Any]] = []
    cur: dict[str, Any] | None = None
    for line in _lines(text):
        m = _BDI_RE.match(line)
        if not m:
            continue
        sub, key, val = bool(m.group(1)), m.group(2).strip(), m.group(3)
        norm = re.sub(r"[^a-z0-9]+", "_", key.lower()).strip("_")
        value = _bdi_value(val)
        if norm == "dram_bank":
            cur = {"bank": value}
            banks.append(cur)
            continue
        if sub and cur is not None and norm in ("start", "size"):
            cur[norm] = value
            continue
        raw[norm] = value
    out: dict[str, Any] = {"raw": raw, "banks": banks}
    good_banks = [b for b in banks if isinstance(b.get("start"), int) and isinstance(b.get("size"), int) and b["size"] > 0]
    if good_banks:
        out["dram_start"] = good_banks[0]["start"]
        out["dram_size"] = sum(b["size"] for b in good_banks if b["start"] >= good_banks[0]["start"])
    elif isinstance(raw.get("memstart"), int) and isinstance(raw.get("memsize"), int):
        out["dram_start"], out["dram_size"] = raw["memstart"], raw["memsize"]
    elif isinstance(raw.get("dram_start"), int) and isinstance(raw.get("dram_size"), int):
        out["dram_start"], out["dram_size"] = raw["dram_start"], raw["dram_size"]
    for src, dst in (("relocaddr", "relocaddr"), ("reloc_off", "reloc_off"), ("sp_start", "sp_start"), ("irq_sp", "irq_sp"),
                     ("tlb_addr", "tlb_addr"), ("boot_params", "boot_params"), ("arch_number", "arch_number"),
                     ("baudrate", "baudrate"), ("flashstart", "flash_start"), ("flashsize", "flash_size"),
                     ("fdt_blob", "fdt_blob"), ("new_fdt", "new_fdt")):
        if src in raw:
            out[dst] = raw[src]
    return out


def parse_version(text: str) -> dict[str, Any]:
    lines = [ln.strip() for ln in _lines(text) if ln.strip()]
    ver = next((ln for ln in lines if ln.startswith("U-Boot")), None)
    out: dict[str, Any] = {"version": ver, "toolchain": [ln for ln in lines if ln is not ver and not ln.startswith("Unknown command")]}
    if ver:
        m = re.search(r"U-Boot (?:SPL )?(\d{4}\.\d{2}[^\s(]*)", ver)
        out["base_version"] = m.group(1) if m else None
        m = re.search(r"\(([^)]*)\)", ver)
        out["build"] = m.group(1) if m else None
        m = re.search(r"\)\s*(\S+)\s*$", ver)
        out["tag"] = m.group(1) if m else None
    return out


# U-Boot _do_help: printf("%-*s- %s\n", CONFIG_SYS_HELP_CMD_WIDTH(8), name, usage) → 8자 이상 이름은 공백 없이
# 'printenv- print environment variables', 'tftpboot- boot image …' 처럼 붙는다.
_HELP_RE = re.compile(r"^([A-Za-z0-9_?.]+)\s*-\s+(\S.*)$")


def parse_help(text: str) -> dict[str, Any]:
    commands: dict[str, str] = {}
    for line in _lines(text):
        m = _HELP_RE.match(line.strip())
        if m:
            commands[m.group(1)] = m.group(2).strip()
    return {"commands": sorted(commands), "descriptions": commands}


def uboot_resolve_command(name: str, commands: Iterable[str]) -> str | None:
    """U-Boot find_cmd_tbl 규칙: 정확히 같은 이름, 아니면 유일한 접두어(약어, 예: 'tftp' → 'tftpboot'). 없으면 None."""
    cmds = list(commands)
    base = name.split(".", 1)[0]
    if base in cmds:
        return base
    cands = [c for c in cmds if c.startswith(base)]
    return cands[0] if len(cands) == 1 else None


def uboot_has(commands: Iterable[str], names: Iterable[str]) -> tuple[dict[str, bool | None], dict[str, str]]:
    """help 목록 기준 명령 사용 가능 여부. help 를 파싱하지 못했으면(목록이 비면) None(모름). 약어로만 되는 것은 via 에."""
    cmds = list(commands)
    has: dict[str, bool | None] = {}
    via: dict[str, str] = {}
    for n in names:
        if not cmds:
            has[n] = None
            continue
        full = uboot_resolve_command(n, cmds)
        has[n] = full is not None
        if full is not None and full != n:
            via[n] = full
    return has, via


_SF_DETECTED_RE = re.compile(r"SF: Detected ([^\s,]+)(.*)$")


def parse_sf_probe(text: str) -> dict[str, Any]:
    out: dict[str, Any] = {"ok": False}
    errors = []
    for line in _lines(text):
        s = line.strip()
        if not s:
            continue
        m = _SF_DETECTED_RE.search(s)
        if m:
            out["ok"] = True
            out["model"] = m.group(1)
            rest = m.group(2)
            for key, rx in (("page_size", r"page size ([\d.]+ ?[KMG]?i?B(?:ytes)?)"), ("erase_size", r"erase size ([\d.]+ ?[KMG]?i?B(?:ytes)?)"),
                            ("total", r"total ([\d.]+ ?[KMG]?i?B(?:ytes)?)")):
                mm = re.search(rx, rest)
                if mm:
                    out[key] = mm.group(1)
            if out.get("total"):
                out["size_bytes"] = parse_print_size(out["total"])
            mm = re.search(r"manufacturer id: ([0-9a-fA-F]+)", rest)
            if mm:
                out["manufacturer_id"] = mm.group(1)
            continue
        m = re.search(r"(\d+) KiB (\S+) at (\d+):(\d+) is now current device", s)
        if m:
            out["ok"] = True
            out["size_bytes"] = int(m.group(1)) * 1024
            out["device"] = m.group(2)
            out["bus_cs"] = f"{m.group(3)}:{m.group(4)}"
            continue
        m = re.search(r"the manufacturer ([0-9a-fA-F]+)", s)
        if m:
            out["manufacturer_id"] = m.group(1)
            continue
        if re.search(r"Failed to initialize|No SPI flash|Unknown command|Usage|Invalid|ERROR", s, re.I):
            errors.append(s)
    if errors:
        out["errors"] = errors
    return out


# ---------------------------------------------------------------------------
# crc32 / md5sum
# ---------------------------------------------------------------------------
CRC32_RE = re.compile(r"(?i)crc32 for ([0-9a-f]{8,16}) \.\.\. ([0-9a-f]{8,16}) ==> ([0-9a-f]{8})")


def parse_crc32(text: str) -> dict[str, int] | None:
    """대소문자 무관 (`CRC32 for` 2010.06/hash.c 단일 경로, `crc32 for` multi-hash 경로 모두)."""
    m = CRC32_RE.search(text)
    if not m:
        return None
    return {"start": int(m.group(1), 16), "end": int(m.group(2), 16), "crc32": int(m.group(3), 16)}


MD5_RE = re.compile(r"(?m)^\s*([0-9a-fA-F]{32})\s+(\S+)?")


def parse_md5sum(text: str) -> str | None:
    m = MD5_RE.search(normalize_newlines(text))
    return m.group(1).lower() if m else None


# ---------------------------------------------------------------------------
# md.b (코어 파서 + 추가 검증)
# ---------------------------------------------------------------------------


def parse_md_b(text: str, start: int, length: int) -> tuple[bytes, list[str]]:
    """md.b 출력 → (data, problems). 코어 parse_md_b_output 으로 주소 연속성/바이트 수를 검증한다.

    추가 검증: 줄마다 바이트 수가 일정해야 한다(첫 줄 폭, U-Boot 는 16). 코어 파서는 마지막 줄의 남는 토큰을 잘라 버리므로
    ASCII 열 앞 공백이 빠져 ASCII 문자가 16진 토큰처럼 붙은 줄(17바이트)도 통과시킨다 → 형식 오류로 보고(재시도)한다.
    \\r\\r\\n·\\r\\n 줄 끝과 2010.06 의 패딩 없는 마지막 짧은 줄은 그대로 받는다.
    """
    clean = normalize_newlines(text)
    data, problems = parse_md_b_output(clean, start, length)
    width: int | None = None
    expected = start
    end = start + length
    for raw in clean.split("\n"):
        ml = parse_md_b_line(raw)
        if ml is None or ml.address != expected:
            continue
        want = min(width or len(ml.data), end - expected)
        if width is None and len(ml.data) < end - expected:
            width = len(ml.data)
            want = width
        if len(ml.data) != want:
            problems.append(f"줄 바이트 수 이상 @0x{ml.address:x}: {len(ml.data)} (예상 {want})")
            break
        expected += len(ml.data)
        if expected >= end:
            break
    return data, problems


# ---------------------------------------------------------------------------
# BusyBox hexdump -C / base64
# ---------------------------------------------------------------------------
_HD_LINE_RE = re.compile(r"^([0-9a-fA-F]{8,16})  (.*?)\s*\|(.*)\|\s*$")
_HD_END_RE = re.compile(r"^([0-9a-fA-F]{8,16})\s*$")


def parse_hexdump_c(text: str, expected_len: int | None = None) -> tuple[bytes, list[str]]:
    """BusyBox ``hexdump -C`` 출력 → (data, problems).

    ``*`` 반복 줄 접기와 끝 주소 줄을 처리한다. BusyBox dump.c 는 마지막 짧은 블록이 앞 블록의 앞부분과 같으면
    그것도 ``*`` 로 접고 끝 주소를 짧은 블록의 시작으로 찍는다 — expected_len 을 알면 그 경우를 복원한다.
    """
    out = bytearray()
    problems: list[str] = []
    prev: bytes | None = None
    star = False
    leading_star = False
    end_addr: int | None = None
    for line in _lines(text):
        s = line.rstrip()
        if not s:
            continue
        if s == "*":
            if prev is None:
                leading_star = True
                problems.append("'*' 앞에 데이터 줄이 없음")
            star = True
            continue
        m = _HD_END_RE.match(s)
        if m:
            end_addr = int(m.group(1), 16)
            continue
        m = _HD_LINE_RE.match(s)
        if not m:
            continue
        addr = int(m.group(1), 16)
        toks = m.group(2).split()
        if not toks or len(toks) > 16 or any(len(t) != 2 or not all(c in "0123456789abcdefABCDEF" for c in t) for t in toks):
            problems.append(f"깨진 줄 @0x{addr:x}: {s[:60]!r}")
            continue
        data = bytes(int(t, 16) for t in toks)
        if star:
            if prev is None or (addr - len(out)) % len(prev) != 0 or addr < len(out):
                problems.append(f"'*' 뒤 주소 불일치 @0x{addr:x}")
                return bytes(out), problems
            while len(out) < addr:
                out += prev
            star = False
        if addr != len(out):
            problems.append(f"주소 불연속: 예상 0x{len(out):x}, 실제 0x{addr:x}")
            return bytes(out), problems
        if prev is not None and len(prev) != 16:
            problems.append(f"짧은 줄 뒤에 데이터가 이어짐 @0x{addr:x}")
            return bytes(out), problems
        out += data
        prev = data
    if leading_star and prev is None and end_addr is None and not out and expected_len is not None and 0 < expected_len < 16:
        # BusyBox dump.c get(): 비교 버퍼(savp)가 0 으로 초기화돼 있어 입력 전체가 16바이트 미만의 0 이면 '*' 한 줄만 찍고
        # (address==0 이라) 끝 주소 줄도 없다. 그 경우만 0 바이트로 복원한다 (호출자가 md5 로 검증).
        return b"\x00" * expected_len, []
    if star:
        if prev is None or end_addr is None:
            problems.append("'*' 뒤에 끝 주소가 없음 (출력이 잘림)")
        else:
            while len(out) + len(prev) <= end_addr:
                out += prev
            if len(out) != end_addr:
                problems.append(f"'*' 복원 후 길이 불일치: {len(out)} != 0x{end_addr:x}")
            elif expected_len is not None and 0 < expected_len - end_addr < len(prev):
                # BusyBox 버그: 마지막 짧은 블록(= prev 의 앞부분)을 접고 끝 주소를 그 시작으로 출력
                out += prev[: expected_len - end_addr]
                end_addr = expected_len
    if end_addr is None:
        problems.append("끝 주소 줄이 없음 (출력이 잘렸을 수 있음)")
    elif not star and len(out) != end_addr:
        problems.append(f"끝 주소 불일치: 데이터 {len(out)}, 끝 주소 0x{end_addr:x}")
    if expected_len is not None and len(out) != expected_len:
        problems.append(f"바이트 수 불일치: 예상 {expected_len}, 실제 {len(out)}")
    return bytes(out), problems


_B64_LINE_RE = re.compile(r"^[A-Za-z0-9+/]*={0,2}$")


def parse_base64(text: str, expected_len: int | None = None, line_width: int = 76) -> tuple[bytes, list[str]]:
    """BusyBox ``base64`` 출력(76자 줄) → (data, problems). 줄 길이·문자 집합을 검사한다."""
    problems: list[str] = []
    rows = [ln.strip() for ln in _lines(text) if ln.strip()]
    good: list[str] = []
    for i, row in enumerate(rows):
        if not _B64_LINE_RE.match(row):
            problems.append(f"base64 가 아닌 줄 {i}: {row[:60]!r}")
            continue
        good.append(row)
    for i, row in enumerate(good[:-1]):
        if len(row) != line_width:
            problems.append(f"줄 {i} 길이 {len(row)} != {line_width} (문자 손실 의심)")
            break
    joined = "".join(good)
    try:
        data = base64.b64decode(joined, validate=True) if joined else b""
    except (binascii.Error, ValueError) as exc:
        problems.append(f"base64 디코딩 실패: {exc}")
        data = b""
    if expected_len is not None and len(data) != expected_len:
        problems.append(f"바이트 수 불일치: 예상 {expected_len}, 실제 {len(data)}")
    return data, problems


# ---------------------------------------------------------------------------
# Linux 셸
# ---------------------------------------------------------------------------


def parse_uname(text: str) -> dict[str, Any]:
    line = next((ln.strip() for ln in _lines(text) if ln.strip()), "")
    toks = line.split()
    out: dict[str, Any] = {"raw": line or None}
    if len(toks) >= 3 and toks[0] in ("Linux",) :
        out["sysname"], out["nodename"], out["release"] = toks[0], toks[1], toks[2]
        if toks[-1] == "GNU/Linux" and len(toks) >= 2:
            out["machine"] = toks[-2]
        else:
            out["machine"] = toks[-1]
    return out


def parse_cpuinfo(text: str) -> dict[str, Any]:
    fields: dict[str, str] = {}
    processors = 0
    for line in _lines(text):
        if ":" not in line:
            continue
        k, v = line.split(":", 1)
        k = k.strip()
        v = v.strip()
        if k.lower() == "processor":
            processors += 1
        if k and k not in fields:
            fields[k] = v
    model = fields.get("model name") or fields.get("Processor") or fields.get("cpu model") or fields.get("system type")
    return {"fields": fields, "model": model, "processors": processors or None,
            "hardware": fields.get("Hardware") or fields.get("system type"),
            "isa": fields.get("isa"), "features": fields.get("Features")}


def parse_mounts(text: str) -> list[dict[str, Any]]:
    out = []
    for line in _lines(text):
        s = line.strip()
        m = re.match(r"^(\S+) on (\S+) type (\S+) \(([^)]*)\)", s)
        if m:
            out.append({"device": m.group(1), "mountpoint": m.group(2), "type": m.group(3), "options": m.group(4),
                        "rw": "rw" in m.group(4).split(",")})
            continue
        m = re.match(r"^(\S+) (/\S*) (\S+) (\S+) \d+ \d+$", s)
        if m:
            out.append({"device": m.group(1), "mountpoint": m.group(2), "type": m.group(3), "options": m.group(4),
                        "rw": "rw" in m.group(4).split(",")})
    return out


def parse_ps(text: str) -> list[dict[str, Any]]:
    lines = [ln.rstrip() for ln in _lines(text) if ln.strip()]
    hdr_idx = next((i for i, ln in enumerate(lines) if re.match(r"^\s*PID\s", ln, re.I)), None)
    if hdr_idx is None:
        return []
    header = lines[hdr_idx].split()
    ncol = len(header)
    out = []
    for ln in lines[hdr_idx + 1:]:
        parts = ln.split(None, ncol - 1)
        if len(parts) < 2 or not parts[0].isdigit():
            continue
        row: dict[str, Any] = {}
        for i, name in enumerate(header):
            if i < len(parts):
                row[name.lower()] = parts[i]
        row["pid"] = int(parts[0])
        cmd = row.get("command") or row.get("cmd") or (parts[-1] if parts else "")
        row["command"] = cmd
        out.append(row)
    return out


def parse_netstat(text: str) -> list[dict[str, Any]]:
    out = []
    for line in _lines(text):
        m = re.match(r"^(tcp6?|udp6?|raw6?)\s+\d+\s+\d+\s+(\S+)\s+(\S+)\s*(\S*)", line.strip())
        if not m:
            continue
        proto, local, foreign, state = m.groups()
        entry = {"proto": proto, "local": local, "foreign": foreign, "state": state or None}
        mm = re.search(r":(\d+)$", local)
        if mm:
            entry["port"] = int(mm.group(1))
        if proto.startswith("udp") or state == "LISTEN":
            out.append(entry)
    return out


def parse_busybox_list(text: str) -> dict[str, Any]:
    t = normalize_newlines(text)
    version = None
    m = re.search(r"(BusyBox v[\d.]+[^\n]*?)(?: multi-call binary\.?)?\s*$", t.split("\n", 1)[0] if t else "")
    for ln in t.split("\n"):
        mm = re.search(r"(BusyBox v\d[\w.\-]*(?: \([^)]*\))?)", ln)
        if mm:
            version = mm.group(1)
            break
    applets: list[str] = []
    if "Currently defined functions:" in t:
        body = t.split("Currently defined functions:", 1)[1]
        for tok in re.split(r"[\s,]+", body):
            tok = tok.strip()
            if tok and re.fullmatch(r"[\w.\[\]-]+", tok):
                applets.append(tok)
    elif m:
        pass
    return {"version": version, "applets": applets}


def parse_id(text: str) -> dict[str, Any]:
    m = re.search(r"uid=(\d+)\(([^)]*)\)", text)
    if not m:
        return {}
    out: dict[str, Any] = {"uid": int(m.group(1)), "user": m.group(2)}
    m = re.search(r"gid=(\d+)\(([^)]*)\)", text)
    if m:
        out["gid"], out["group"] = int(m.group(1)), m.group(2)
    return out


def proc_mtd(text: str) -> list[dict[str, Any]]:
    rows = parse_proc_mtd(normalize_newlines(text))
    for r in rows:
        r["size_hex"] = f"0x{r['size']:x}"
        r["offset_estimate_hex"] = f"0x{r['offset_estimate']:x}"
    return rows


def is_not_found(text: str, command: str | None = None) -> bool:
    t = normalize_newlines(text)
    if command:
        return bool(re.search(rf"(?:^|\n)-?\w*sh: {re.escape(command)}: (?:not found|Permission denied)", t)) or \
            bool(re.search(rf"applet not found|{re.escape(command)}: not found", t))
    return bool(re.search(r": not found|applet not found", t))


# ---------------------------------------------------------------------------
# 부팅 로그 요약
# ---------------------------------------------------------------------------


def flash_size_from_facts(facts: dict[str, Any] | None) -> int | None:
    """부팅 로그 facts 에서 플래시 크기: 'SPI Nor total size: 16MB'(HiSilicon), 'Block:64KB Chip:16MB', '16384 KiB hi_fmc at 0:0 …'(2010.06),
    'SF: Detected … total 16 MiB'(2016.11). Ingenic 'SF: Detected BY25Q128AS' 처럼 크기가 없으면 None."""
    facts = facts or {}
    if facts.get("flash_total_mb"):
        try:
            return int(facts["flash_total_mb"]) * MiB
        except (TypeError, ValueError):
            pass
    if facts.get("flash_chip"):
        size = parse_print_size(facts["flash_chip"])
        if size:
            return size
    if facts.get("flash_current_kib"):
        return int(facts["flash_current_kib"]) * 1024
    m = re.search(r"total ([\d.]+ ?[KMG]i?B)", str(facts.get("flash_detected") or ""))
    if m:
        return parse_print_size(m.group(1))
    return None


# ---------------------------------------------------------------------------
# SD 카드 이벤트 (uart_capture_boot 의 sd_events — 설계: docs/design/sd-forensics.md §2·§5.1)
# ---------------------------------------------------------------------------
#: sd_events 에 담는 줄 수 상한 (종류별 개수는 상한과 관계없이 모두 센다)
SD_EVENT_MAX = 60
SD_EVENT_TEXT_MAX = 160
#: 분류할 줄 길이 상한 (더 긴 줄은 건너뛴다 — 정규식 비용을 줄 하나당 유한하게)
SD_LINE_MAX = 4096
_SD_CARD_WORD = r"(?:micro[ _-]?)?(?:sd|tf)[ _-]?card|sdcard|tfcard"
_SD_DEV = r"(?:mmcblk\d+(?:p\d+)?|sd[a-z]\d*)"
#: 카드 마운트 경로 (/mnt/tftpboot 같은 이름은 제외)
_SD_PATH = r"(?:/mnt/(?:sd\w*|mmc\w*|tf(?:card)?\d*)\b|/media/mmcblk\w*|/sdcard\b)"
#: (종류, 정규식). 한 줄이 여러 규칙에 맞을 수 있다 — 목록 순서가 우선순위다(앞의 종류가 그 줄의 kind, 나머지는 also).
#: 내장 저장소(eMMC)·SDIO(Wi-Fi 모듈) 줄은 카드 이벤트로 세지 않는다. 판단은 줄 단위의 후보다 — 벤더 드라이버 문구는 기기마다 다르다.
#: 정규식은 모두 길이가 묶인 반복만 쓴다(줄 길이 상한과 함께 줄 하나의 비용이 유한하다).
SD_EVENT_RULES: list[tuple[str, re.Pattern[str]]] = [
    ("sdio", re.compile(r"\bmmc\d+: new (?:[\w ]{0,40} )?SDIO card\b", re.I)),
    ("emmc", re.compile(r"\bmmc\d+: new (?:[\w ]{0,40} )?MMC card\b|\bmmcblk\d+(?:boot\d|rpmb)\b|\bbooting from emmc\b", re.I)),
    # 부정이 먼저다: '카드 없음' 문구가 감지로 세지지 않게
    ("card-absent", re.compile(
        rf"\b(?:no|without)\s+(?:{_SD_CARD_WORD})\b"
        rf"|\b(?:{_SD_CARD_WORD})\b[^\n]{{0,24}}?\b(?:not|isn't|doesn't)\s+(?:be\s+)?(?:present|found|exists?|detected|inserted|mounted|ready)\b"
        rf"|\b(?:{_SD_CARD_WORD})\b[^\n]{{0,24}}?\b(?:absent|missing)\b"
        r"|\bcard did not respond to voltage select\b|\bMMC: no card present\b|\bno mmc device at slot\b"
        r"|\bunable to (?:find|detect) (?:the )?(?:sd|tf|mmc) ?card\b", re.I)),
    ("update", re.compile(
        r"\b(?:sd|tf|card|mmc)[ _-]?(?:update|upgrade)\w{0,8}\b|\bhiupdate\b|\bdo_auto_update\b|\bau_check\w{0,24}"
        rf"|\b(?:{_SD_CARD_WORD})\b[^\n]{{0,40}}?\b(?:update|upgrade|upgrading|updating|firmware)\b"
        rf"|\b(?:update|upgrade)\w{{0,8}}\b[^\n]{{0,40}}?{_SD_PATH}"
        r"|\bauto[ _-]?(?:update|upgrade)\b[^\n]{0,40}?\b(?:sd|tf|mmc|card)\b", re.I)),
    ("script", re.compile(rf"\b(?:autorun|autoexec)\w{{0,16}}(?:\.sh)?\b|{_SD_PATH}/\S{{0,200}}?\.sh\b", re.I)),
    ("uboot-script", re.compile(
        r"\breading (?:boot\.scr|uEnv\.txt|boot\.cmd)\b|\bUnable to read file (?:boot\.scr|uEnv\.txt)\b"
        r"|\b(?:fat|ext[24])?load mmc\b[^\n]{0,60}?\b(?:boot\.scr|uEnv\.txt|boot\.cmd)\b", re.I)),
    ("uboot-mmc", re.compile(
        r"\bfatload mmc\b|\bext[24]load mmc\b|\bload mmc\b|\bmmc rescan\b|\bmmc\d+(?:\(part \d+\))? is current device\b"
        r"|\bswitch to partitions #\d+, OK\b|\bLoading Environment from (?:FAT|EXT4)\b|\bNo partition table - mmc\b", re.I)),
    ("fs-error", re.compile(
        rf"\b(?:FAT|exFAT|EXT[234])-fs \({_SD_DEV}\)[^\n]{{0,200}}?(?:not properly unmounted|error|corrupt|run fsck|invalid|bad )"
        rf"|\bexfat[^\n]{{0,20}}\({_SD_DEV}\)[^\n]{{0,200}}?(?:error|corrupt|dirty)", re.I)),
    ("fs-mount", re.compile(rf"\b(?:FAT|exFAT|EXT[234]|F2FS)-fs \({_SD_DEV}\)|\bexfat[^\n]{{0,20}}\({_SD_DEV}\)"
                            rf"|\bmount\b[^\n]{{0,200}}?(?:/dev/mmcblk\d|{_SD_PATH})", re.I)),
    ("card-removed", re.compile(rf"\bmmc\d+: card [0-9a-f]+ removed\b|\b(?:{_SD_CARD_WORD})\b[^\n]{{0,30}}?\b(?:removed|plug(?:ged)?[ _-]?out|eject(?:ed)?)\b", re.I)),
    ("card-detected", re.compile(
        r"\bmmc\d+: new (?:[\w ]{0,40} )?SD(?:HC|XC|UC)? card at address\b"
        rf"|\b(?:{_SD_CARD_WORD})\b[^\n]{{0,30}}?\b(?:inserted|insert|plug(?:ged)?[ _-]?in|detected|found|present|mounted|ready)\b"
        rf"|\b(?:inserted|detected)\b[^\n]{{0,12}}\b(?:{_SD_CARD_WORD})\b", re.I)),
    ("partition", re.compile(r"\bmmcblk\d+: p\d+")),
    ("block-device", re.compile(r"\bmmcblk\d+: mmc\d+:[0-9a-f]+ ")),
    ("card-other", re.compile(rf"\b(?:{_SD_CARD_WORD})\b", re.I)),
]
#: 카드 이벤트로 세지 않는 종류 (내장 저장소·Wi-Fi 모듈)
_SD_NOT_CARD = frozenset({"sdio", "emmc"})
#: 카드 감지 핀·인터럽트 설정 줄 (카드가 있든 없든 찍힌다 — 감지·부재로 세지 않는다)
_SD_HW_CONFIG_RX = re.compile(r"\b(?:card[ _-]?)?(?:cd|detect(?:ion)?)[ _-]?(?:gpios?|pin|irq|interrupt|int)\b|\bgpio\s*[A-Z]?\d+\b", re.I)
#: sd_note 를 내는 종류 (카드 업데이트·자동 실행·카드 스크립트 읽기)
SD_NOTE_KINDS = ("update", "script", "uboot-script")
_SD_DEV_RX = re.compile(r"\b(mmcblk\d+(?:p\d+)?)\b")
_SD_HOST_NEW_RX = re.compile(r"\bmmc(\d+): new\b", re.I)
_SD_BLK_HOST_RX = re.compile(r"\bmmcblk(\d+): mmc(\d+):")
_SD_FS_RX = re.compile(rf"\b(FAT|exFAT|EXT[234]|F2FS)-fs \(({_SD_DEV})\)|\b(exfat)[^\n]{{0,20}}\(({_SD_DEV})\)", re.I)


def classify_sd_line(line: str) -> list[str]:
    """부팅 로그 한 줄이 맞는 SD 관련 종류들 (우선순위 순, 없으면 빈 목록). 줄 하나만 본다(eMMC 장치 추적은 sd_events).

    eMMC·SDIO 줄은 ['emmc']·['sdio'] 만 돌려준다. '카드 없음' 문구면 card-detected 를 빼고, 카드 감지 핀·인터럽트 설정 줄이면
    card-detected·card-absent 를 뺀다. 'card-other' 는 다른 종류가 없을 때만 남긴다.
    """
    s = line.strip()
    if not s or len(s) > SD_LINE_MAX:
        return []
    kinds = [kind for kind, rx in SD_EVENT_RULES if rx.search(s)]
    if not kinds:
        return []
    if kinds[0] in _SD_NOT_CARD:
        return kinds[:1]
    if "card-absent" in kinds and "card-detected" in kinds:
        kinds.remove("card-detected")
    if _SD_HW_CONFIG_RX.search(s):
        kinds = [k for k in kinds if k not in ("card-detected", "card-absent")] or ["card-other"]
    if len(kinds) > 1 and "card-other" in kinds:
        kinds.remove("card-other")
    return kinds


def sd_events(lines: Iterable[str], *, max_events: int = SD_EVENT_MAX) -> dict[str, Any]:
    """부팅 로그 줄들 → SD 카드 관련 줄 목록과 요약.

    반환: ``events``(line: 1부터 센 줄 번호 = 저장한 발췌 파일의 줄, kind: 그 줄의 대표 종류, also: 함께 맞은 종류, text — 최대 max_events 개)와
    ``summary``(card_detected: 카드 감지 줄이 보였는가 — false 는 '카드 없음'이 아니라 '감지 줄을 못 봤다'는 뜻, card_absent: '카드 없음' 줄이 보였는가,
    counts: 종류별 줄 수(also 포함, 상한과 관계없이 모두), devices: mmcblk 장치 이름, filesystems: 장치·파일 시스템, events_total, truncated,
    long_lines_skipped: SD_LINE_MAX 를 넘어 분류하지 않은 줄 수).
    eMMC·SDIO 줄은 counts 의 emmc·sdio 로만 센다. 커널이 'mmcN: new … MMC card'(eMMC)로 알린 호스트의 mmcblk 장치 줄(파티션·마운트·오류)도
    eMMC 로 센다. 그 밖의 mmcblk 줄은 SD 와 eMMC 를 구분할 수 없어 후보로 남는다.
    """
    events: list[dict[str, Any]] = []
    counts: dict[str, int] = {}
    devices: list[str] = []
    filesystems: list[dict[str, str]] = []
    emmc_hosts: set[str] = set()
    blk_host: dict[str, str] = {}
    total = 0
    long_lines = 0
    for i, line in enumerate(lines, 1):
        s = line.strip()
        if len(s) > SD_LINE_MAX:
            long_lines += 1  # 분류하지 않은 줄 — 조용히 버리지 않고 센다
            continue
        kinds = classify_sd_line(s)
        if not kinds:
            continue
        hm = _SD_HOST_NEW_RX.search(s)
        if hm and kinds[0] in _SD_NOT_CARD:
            emmc_hosts.add(hm.group(1))
        bm = _SD_BLK_HOST_RX.search(s)
        if bm:
            blk_host[bm.group(1)] = bm.group(2)
        devs = [m.group(1) for m in _SD_DEV_RX.finditer(s)]
        if kinds[0] not in _SD_NOT_CARD and devs:
            hosts = {blk_host.get(re.match(r"mmcblk(\d+)", d).group(1)) for d in devs}  # type: ignore[union-attr]
            if hosts and None not in hosts and hosts <= emmc_hosts:
                kinds = ["emmc"]
        for k in kinds:
            counts[k] = counts.get(k, 0) + 1
        if kinds[0] in _SD_NOT_CARD:
            continue
        total += 1
        if len(events) < max_events:
            ev: dict[str, Any] = {"line": i, "kind": kinds[0], "text": s if len(s) <= SD_EVENT_TEXT_MAX else s[:SD_EVENT_TEXT_MAX] + "…"}
            if len(kinds) > 1:
                ev["also"] = kinds[1:]
            events.append(ev)
        for d in devs:
            if d not in devices and len(devices) < 16:
                devices.append(d)
        fm = _SD_FS_RX.search(s)
        if fm:
            fs, dev = (fm.group(1), fm.group(2)) if fm.group(1) else (fm.group(3), fm.group(4))
            ent = {"device": dev, "fs": fs.lower()}
            if ent not in filesystems and len(filesystems) < 16:
                filesystems.append(ent)
    return {
        "events": events,
        "summary": {
            "card_detected": counts.get("card-detected", 0) > 0,
            "card_absent": counts.get("card-absent", 0) > 0,
            "counts": counts,
            "devices": devices,
            "filesystems": filesystems,
            "events_total": total,
            "truncated": total > len(events),
            "long_lines_skipped": long_lines,
        },
    }


def summarize_boot_text(text: str, profile: Any) -> dict[str, Any]:
    """부팅 로그 전체 → 부팅 정보 (uart_capture_boot)."""
    from .tracker import extract_facts_from_line

    facts: dict[str, Any] = {}
    stages: list[str] = []
    autoboot = None
    flash_warnings = []
    lines = _lines(text)

    def stage(name: str) -> None:
        if not stages or stages[-1] != name:
            stages.append(name)

    for line in lines:
        s = line.strip()
        if not s:
            continue
        extract_facts_from_line(s, facts)
        if re.search(r"U-Boot SPL|^U-Boot \d{4}\.\d{2}|^DRAM:|System startup", s):
            stage("uboot")
        if autoboot is None and any(p.search(s) for p in profile.autoboot):
            autoboot = s
            stage("autoboot")
        if re.search(r"Starting kernel|Uncompressing Linux|Linux version \d|Booting Linux", s):
            stage("kernel")
        if re.search(r"Freeing .*memory|init started:|BusyBox v|Please press Enter", s):
            stage("userspace")
        if any(p.search(s) for p in profile.markers.get("flash_write_warning", [])):
            flash_warnings.append(s)
    tail = lines[-1] if lines else ""
    login_prompt = facts.get("login_prompt")
    shell_prompt = None
    uboot_prompt = None
    if tail.strip():
        if any(p.search(tail) for p in profile.login_prompts):
            login_prompt = tail
            stage("login")
        elif "Please press Enter to activate this console" in tail:
            stage("askfirst")
        elif any(p.search(tail) for p in profile.uboot_prompts) and "kernel" not in stages:
            uboot_prompt = tail
            stage("uboot-prompt")
        elif any(p.search(tail) for p in profile.linux_prompts):
            shell_prompt = tail
            stage("shell")
    for line in lines:
        if login_prompt is None and any(p.search(line.strip()) for p in profile.login_prompts) and line.strip().endswith(":"):
            login_prompt = line.strip()
    bootdelay = None
    raw_text = normalize_newlines(text)
    for p in profile.autoboot:
        m = p.search(raw_text)
        if m:
            # 카운트다운은 \b\b\b 로 숫자를 덮어쓰므로 보이는 줄이 아니라 원시 텍스트에서 첫 숫자를 읽는다
            mm = re.match(r"[^\d\n\x08]{0,24}?(\d+)", raw_text[m.end():m.end() + 40])
            if mm:
                bootdelay = int(mm.group(1))
            first = raw_text[m.start():].split("\n", 1)[0].split("\x08", 1)[0]
            autoboot = visible_line(first).strip() or autoboot
            break
    cmdline = facts.get("cmdline")
    mtdparts = None
    if cmdline:
        m = re.search(r"(mtdparts=\S+)", cmdline)
        mtdparts = m.group(1) if m else None
    console = None
    if cmdline:
        m = re.search(r"console=(\S+)", cmdline)
        console = m.group(1) if m else None
    flash_size = None
    if facts.get("flash_total_mb"):
        flash_size = int(facts["flash_total_mb"]) * MiB
    elif facts.get("flash_chip"):
        flash_size = parse_print_size(facts["flash_chip"])
    elif facts.get("flash_current_kib"):
        flash_size = facts["flash_current_kib"] * 1024
    sd = sd_events(lines)
    return {
        "uboot_version": facts.get("uboot_version"),
        "spl_version": facts.get("spl_version"),
        "autoboot_message": autoboot,
        "bootdelay": bootdelay,
        "kernel_version": facts.get("kernel_version"),
        "cmdline": cmdline,
        "mtdparts": mtdparts,
        "partitions": partitions_from_mtdparts(mtdparts, flash_size) or [
            {"name": p["name"], "offset": p["offset"], "size": p["size"]} for p in facts.get("mtd_parts", [])],
        "kernel_mtd_table": facts.get("mtd_parts", []),
        "console": console,
        "login_prompt": login_prompt,
        "shell_prompt": shell_prompt,
        "uboot_prompt": uboot_prompt,
        "dram": facts.get("dram"),
        "flash": {k: facts.get(k) for k in ("flash_detected", "flash_name", "flash_chip", "flash_block", "flash_device") if facts.get(k)} | (
            {"size_bytes": flash_size} if flash_size else {}),
        "rootfs_type": facts.get("rootfs"),
        "busybox": facts.get("busybox"),
        "board": facts.get("board"),
        "env_bad_crc": bool(facts.get("env_bad_crc")),
        "kernel_panic": facts.get("kernel_panic"),
        "flash_write_warnings": flash_warnings,
        "sd_events": sd["events"],
        "sd_summary": sd["summary"],
        "stages": stages,
        "facts": {k: v for k, v in facts.items() if k not in ("mtd_parts",)},
    }


# ---------------------------------------------------------------------------
# safe_ram_addr 제안
# ---------------------------------------------------------------------------
STACK_MARGIN = 1 * MiB
LOW_RESERVE = 1 * MiB


def _int_or_none(v: Any) -> int | None:
    if isinstance(v, int):
        return v
    if isinstance(v, str):
        return _hexint(v.replace("0x", "").replace("0X", "")) if re.fullmatch(r"(0[xX])?[0-9a-fA-F]+", v.strip()) else None
    return None


def propose_safe_ram(bdinfo: dict[str, Any] | None, env: dict[str, str] | None, facts: dict[str, Any] | None,
                     need: int = 0x10000) -> dict[str, Any]:
    """DRAM 안에서 U-Boot 자신(relocaddr/malloc/gd/스택)과 하위 1 MiB 를 피한 RAM 작업 영역과 시작 주소를 제안한다."""
    bdinfo = bdinfo or {}
    facts = facts or {}
    notes: list[str] = []
    start = _int_or_none(bdinfo.get("dram_start"))
    size = _int_or_none(bdinfo.get("dram_size"))
    if start is None or not size:
        return {"safe_ram_addr": None, "reason": "bdinfo 에서 DRAM 시작/크기를 찾지 못함 — safe_ram_addr 을 제안할 수 없습니다 (수동 지정 필요)."}
    end = start + size
    owned: list[tuple[str, int]] = []
    for key in ("relocaddr", "sp_start", "irq_sp", "tlb_addr"):
        v = _int_or_none(bdinfo.get(key))
        if v is not None and start <= v < end:
            owned.append((f"bdinfo {key}", v))
    bp = _int_or_none(bdinfo.get("boot_params"))
    if bp is not None and start + size // 8 <= bp < end:
        owned.append(("bdinfo boot_params", bp))
    for key in ("relocaddr", "sp_addr", "gd_addr", "malloc_addr", "boot_params_addr"):
        v = _int_or_none(facts.get(key))
        if v is not None and start <= v < end:
            owned.append((f"부팅 로그 {key}", v))
    if owned:
        lowest_name, lowest = min(owned, key=lambda kv: kv[1])
        ceiling = max(start, lowest - STACK_MARGIN)
        confidence = "high" if any(n.endswith(("sp_start", "sp_addr")) for n, _ in owned) else "medium"
        basis = f"U-Boot 영역 최저 주소 {lowest_name}=0x{lowest:x} − 스택 여유 {STACK_MARGIN // 1024} KiB"
    else:
        ceiling = start + size // 2
        confidence = "low"
        basis = "U-Boot 영역 정보(relocaddr/sp/malloc)가 없어 DRAM 위쪽 절반을 U-Boot 영역으로 가정"
        notes.append("bdinfo 에 relocaddr/sp 가 없습니다. 부팅 로그(uart_capture_boot)를 확보하면 더 정확해집니다.")
    floor = start + LOW_RESERVE
    if ceiling - floor < need:
        return {"safe_ram_addr": None, "reason": f"사용 가능한 RAM 창이 너무 작습니다 (0x{floor:x}–0x{ceiling:x})",
                "dram": {"start": f"0x{start:x}", "size": size}}
    chosen = None
    window_end = ceiling
    for name, addr, length in env_load_regions(env or {}):
        a = (addr + 0xFFF) & ~0xFFF
        if floor <= a and a + need <= ceiling:
            chosen = (name, a)
            break
        if confidence == "low" and length and a == addr and floor <= a and need <= length and a + length <= end:
            # U-Boot 영역 정보가 없을 때: 벤더 bootcmd 가 실제로 쓰는 적재 영역은 U-Boot 실행 중 비어 있다는 증거
            chosen = (name + " (벤더 적재 영역)", a)
            window_end = a + length if a >= ceiling else max(ceiling, a + length)
            notes.append(f"U-Boot 영역 정보가 없어 벤더 bootcmd 적재 영역(0x{a:x}+0x{length:x})을 사용합니다.")
            break
    if chosen is None:
        for name, a in (("DRAM+6MiB (OpenIPC 관례)", start + 0x600000), ("DRAM+2MiB", start + 0x200000)):
            if floor <= a and a + need <= ceiling:
                chosen = (name, a)
                break
    if chosen is None:
        chosen = ("DRAM+1MiB", floor)
    ceiling = window_end
    name, addr = chosen
    return {
        "safe_ram_addr": f"0x{addr:x}",
        "source": name,
        "ram_window": {"start": f"0x{addr:x}", "end": f"0x{ceiling:x}", "size": ceiling - addr},
        "max_bytes": ceiling - addr,
        "dram": {"start": f"0x{start:x}", "size": size, "end": f"0x{end:x}"},
        "avoid": [{"what": n, "address": f"0x{v:x}"} for n, v in sorted(owned, key=lambda kv: kv[1])],
        "basis": basis,
        "confidence": confidence,
        "notes": notes,
    }


def chars_per_byte(method: str) -> float:
    """덤프 방식별 콘솔 문자 수 / 데이터 바이트 (docs/references §13.1)."""
    return {"md.b": 79 / 16, "hexdump": 80 / 16, "base64": 78 / 57, "md5": 0.0}.get(method, 5.0)


def render(text: str) -> str:
    return render_text(text)


def flatten(items: Iterable[Any]) -> list[Any]:
    return [x for it in items for x in (it if isinstance(it, (list, tuple)) else [it])]
