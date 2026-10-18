"""임베디드 펌웨어/부트로더 형식 파서 (uart-mcp, fwtriage-mcp, mocktarget 공용).

- mtdparts 문자열 (커널 cmdline / U-Boot env)
- /proc/mtd 표
- uImage(legacy) 헤더 (0x27051956)
- U-Boot 환경 변수 블록 (CRC32 + key=value\\0 … \\0\\0, redundant 플래그 바이트 포함 여부)
- U-Boot md.b 출력 줄
- U-Boot crc32 출력 줄
"""

from __future__ import annotations

import re
import struct
import zlib
from dataclasses import dataclass
from typing import Any, Iterable

from .errors import ValidationFailed

# ---------------------------------------------------------------------------
# mtdparts
# ---------------------------------------------------------------------------

_MEMPARSE_RE = re.compile(r"^(0[xX][0-9a-fA-F]+|0[0-7]*|[1-9][0-9]*)([kKmMgGtTpPeE]?)$")
_MEMPARSE_SHIFT = {"": 0, "k": 10, "m": 20, "g": 30, "t": 40, "p": 50, "e": 60}


def memparse(token: str) -> int:
    """Linux 커널 memparse() 와 같은 규칙: 기수 자동(0x=16진, 선행 0=8진), 접미사 K/M/G/T/P/E (대소문자 무관)."""
    m = _MEMPARSE_RE.match(token.strip())
    if not m:
        raise ValidationFailed(f"크기/오프셋을 해석할 수 없습니다: {token!r}")
    return int(m.group(1), 0 if not (len(m.group(1)) > 1 and m.group(1)[0] == "0" and m.group(1)[1] not in "xX") else 8) << _MEMPARSE_SHIFT[m.group(2).lower()]


_PART_RE = re.compile(
    r"^(?P<size>-|(?:0[xX][0-9a-fA-F]+|\d+)[kKmMgGtTpPeE]?)(?:@(?P<offset>(?:0[xX][0-9a-fA-F]+|\d+)[kKmMgGtTpPeE]?))?"
    r"(?:\((?P<name>[^)]*)\))?(?P<flags>(?:ro|lk|slc|a)*)$"
)


def parse_mtdparts(text: str, total_size: int | None = None) -> list[dict[str, Any]]:
    """``mtdparts=dev1:256k(boot),64k(env),-(rootfs);dev2:...`` 파싱 (Linux drivers/mtd/parsers/cmdlinepart.c 규칙).

    - 'mtdparts=' 접두어는 있어도 없어도 된다. bootargs 전체 문자열을 넘기면 mtdparts 토큰만 찾는다.
    - 크기/오프셋은 memparse 규칙 (0x=16진, 선행 0=8진, K/M/G/T/P/E).
    - '-' 크기는 나머지 전체 (total_size 가 없으면 size=None). '-' 파티션 뒤에 또 파티션이 오면 오류.
    - 이름 없는 파티션은 커널처럼 'Partition_NNN' (장치 내 번호).
    - total_size 가 주어지면 장치 끝을 넘는 파티션은 잘라내고(truncated=True), 크기 0 파티션은 건너뛴다.
    - 반환: [{device, name, offset, size, ro, truncated?}] (offset/size 는 바이트, size None 가능)
    """
    s = text.strip()
    m = re.search(r"mtdparts=(\S+)", s)
    if m:
        s = m.group(1)
    elif " " in s:
        raise ValidationFailed("mtdparts 문자열을 찾을 수 없습니다.", data={"text": text[:200]})
    parts: list[dict[str, Any]] = []
    for devspec in [d for d in s.split(";") if d]:
        if ":" not in devspec:
            raise ValidationFailed(f"mtdparts 장치 구분자(:)가 없습니다: {devspec!r}")
        device, plist = devspec.split(":", 1)
        offset = 0
        index = 0
        fill_seen = False
        for item in plist.split(","):
            item = item.strip()
            if not item:
                continue
            if fill_seen:
                raise ValidationFailed(f"'-'(나머지 전체) 파티션 뒤에 다른 파티션이 올 수 없습니다: {item!r}")
            pm = _PART_RE.match(item)
            if not pm:
                raise ValidationFailed(f"mtdparts 파티션 항목을 해석할 수 없습니다: {item!r}")
            if pm.group("offset"):
                offset = memparse(pm.group("offset"))
            size_s = pm.group("size")
            truncated = False
            if size_s == "-":
                fill_seen = True
                size = (total_size - offset) if total_size is not None else None
            else:
                size = memparse(size_s)
                if total_size is not None and offset + size > total_size:
                    size = max(0, total_size - offset)
                    truncated = True
            name = pm.group("name") if pm.group("name") else f"Partition_{index:03d}"
            index += 1
            if size == 0:
                continue
            entry: dict[str, Any] = {
                "device": device,
                "name": name,
                "offset": offset,
                "size": size,
                "ro": "ro" in (pm.group("flags") or ""),
            }
            if truncated:
                entry["truncated"] = True
            parts.append(entry)
            if size is None:
                continue  # '-' 이고 전체 크기를 모름: 뒤에 항목이 더 있으면 다음 반복에서 오류
            offset += size
    return parts


# ---------------------------------------------------------------------------
# /proc/mtd
# ---------------------------------------------------------------------------

_PROC_MTD_RE = re.compile(r'^(mtd\d+):\s+([0-9a-fA-F]+)\s+([0-9a-fA-F]+)\s+"([^"]*)"', re.M)


def parse_proc_mtd(text: str) -> list[dict[str, Any]]:
    """``mtd0: 00040000 00010000 "boot"`` 형식 → [{dev, size, erasesize, name, offset}] (offset 은 누적 추정)."""
    out = []
    offset = 0
    for m in _PROC_MTD_RE.finditer(text):
        size = int(m.group(2), 16)
        out.append({"dev": m.group(1), "size": size, "erasesize": int(m.group(3), 16), "name": m.group(4), "offset_estimate": offset})
        offset += size
    return out


# ---------------------------------------------------------------------------
# uImage
# ---------------------------------------------------------------------------

UIMAGE_MAGIC = 0x27051956
_UIMAGE_OS = {0: "invalid", 1: "openbsd", 2: "netbsd", 3: "freebsd", 4: "4_4bsd", 5: "linux", 6: "svr4", 7: "esix", 8: "solaris", 9: "irix", 10: "sco", 11: "dell", 12: "ncr", 13: "lynxos", 14: "vxworks", 15: "psos", 16: "qnx", 17: "u-boot", 18: "rtems", 19: "artos", 20: "unity", 21: "integrity", 22: "ose", 23: "plan9", 24: "openrtos", 25: "arm-trusted-firmware", 26: "tee", 27: "opensbi", 28: "efi"}
_UIMAGE_ARCH = {0: "invalid", 1: "alpha", 2: "arm", 3: "x86", 4: "ia64", 5: "mips", 6: "mips64", 7: "ppc", 8: "s390", 9: "sh", 10: "sparc", 11: "sparc64", 12: "m68k", 13: "nios", 14: "microblaze", 15: "nios2", 16: "blackfin", 17: "avr32", 18: "st200", 19: "sandbox", 20: "nds32", 21: "openrisc", 22: "arm64", 23: "arc", 24: "x86_64", 25: "xtensa", 26: "riscv"}
_UIMAGE_TYPE = {0: "invalid", 1: "standalone", 2: "kernel", 3: "ramdisk", 4: "multi", 5: "firmware", 6: "script", 7: "filesystem", 8: "flat_dt"}
_UIMAGE_COMP = {0: "none", 1: "gzip", 2: "bzip2", 3: "lzma", 4: "lzo", 5: "lz4", 6: "zstd"}


def parse_uimage_header(data: bytes, *, verify_data: bool = True) -> dict[str, Any]:
    """legacy uImage 64바이트 헤더 파싱 + 헤더/데이터 CRC 검증."""
    if len(data) < 64:
        raise ValidationFailed("uImage 헤더보다 데이터가 짧습니다 (64바이트 미만).")
    (magic, hcrc, ts, size, load, ep, dcrc, os_, arch, typ, comp) = struct.unpack(">IIIIIIIBBBB", data[:32])
    name = data[32:64].split(b"\0", 1)[0].decode("latin-1", "replace")
    if magic != UIMAGE_MAGIC:
        raise ValidationFailed(f"uImage 매직이 아닙니다: 0x{magic:08x}")
    hdr = bytearray(data[:64])
    hdr[4:8] = b"\0\0\0\0"
    header_crc_ok = (zlib.crc32(bytes(hdr)) & 0xFFFFFFFF) == hcrc
    data_crc_ok = None
    if verify_data and len(data) >= 64 + size:
        data_crc_ok = (zlib.crc32(data[64 : 64 + size]) & 0xFFFFFFFF) == dcrc
    return {
        "magic": f"0x{magic:08x}",
        "header_crc": f"0x{hcrc:08x}",
        "header_crc_ok": header_crc_ok,
        "timestamp": ts,
        "data_size": size,
        "load_address": f"0x{load:08x}",
        "entry_point": f"0x{ep:08x}",
        "data_crc": f"0x{dcrc:08x}",
        "data_crc_ok": data_crc_ok,
        "os": _UIMAGE_OS.get(os_, str(os_)),
        "arch": _UIMAGE_ARCH.get(arch, str(arch)),
        "type": _UIMAGE_TYPE.get(typ, str(typ)),
        "compression": _UIMAGE_COMP.get(comp, str(comp)),
        "name": name,
        "total_size": 64 + size,
    }


def build_uimage_header(payload: bytes, *, name: str, load: int, entry: int, arch: str = "arm", os_name: str = "linux",
                        image_type: str = "kernel", comp: str = "none", timestamp: int = 0) -> bytes:
    """테스트/시뮬레이터용 uImage 헤더 생성 (mkimage 와 같은 레이아웃)."""
    inv = lambda d, v: next(k for k, x in d.items() if x == v)  # noqa: E731
    dcrc = zlib.crc32(payload) & 0xFFFFFFFF
    nm = name.encode("latin-1")[:32].ljust(32, b"\0")
    hdr = struct.pack(">IIIIIIIBBBB", UIMAGE_MAGIC, 0, timestamp, len(payload), load, entry, dcrc,
                      inv(_UIMAGE_OS, os_name), inv(_UIMAGE_ARCH, arch), inv(_UIMAGE_TYPE, image_type), inv(_UIMAGE_COMP, comp)) + nm
    hcrc = zlib.crc32(hdr) & 0xFFFFFFFF
    return hdr[:4] + struct.pack(">I", hcrc) + hdr[8:]


# ---------------------------------------------------------------------------
# U-Boot environment
# ---------------------------------------------------------------------------

COMMON_ENV_SIZES = (0x1000, 0x2000, 0x4000, 0x8000, 0x10000, 0x20000, 0x40000)


def parse_env_payload(payload: bytes) -> dict[str, str]:
    """env 데이터 영역(key=value\\0 … \\0\\0)을 딕셔너리로."""
    return _parse_env_payload(payload)


def _parse_env_payload(payload: bytes) -> dict[str, str]:
    end = payload.find(b"\0\0")
    body = payload[: end if end >= 0 else len(payload)]
    env: dict[str, str] = {}
    for item in body.split(b"\0"):
        if not item or b"=" not in item:
            continue
        k, v = item.split(b"=", 1)
        try:
            env[k.decode("latin-1")] = v.decode("utf-8", "replace")
        except Exception:  # pragma: no cover
            continue
    return env


def parse_uboot_env(block: bytes) -> dict[str, Any] | None:
    """env 블록(정확한 크기)을 파싱. CRC 가 맞으면 {redundant, env, crc} 아니면 None.

    비중복: [crc32 LE 4B][data size-4]
    중복(redundant): [crc32 LE 4B][flags 1B][data size-5]
    """
    if len(block) < 8:
        return None
    crc_plain = zlib.crc32(block[4:]) & 0xFFFFFFFF
    crc_redund = zlib.crc32(block[5:]) & 0xFFFFFFFF
    # 리틀엔디언 CRC 가 일반적이고, 빅엔디언 CPU 나 `mkenvimage -b` 이미지는 빅엔디언 CRC 를 쓴다
    for endian, fmt in (("little", "<I"), ("big", ">I")):
        stored = struct.unpack(fmt, block[:4])[0]
        if crc_plain == stored:
            return {"redundant": False, "crc": f"0x{stored:08x}", "crc_endian": endian, "size": len(block), "env": _parse_env_payload(block[4:])}
        if crc_redund == stored:
            return {"redundant": True, "flags": block[4], "crc": f"0x{stored:08x}", "crc_endian": endian, "size": len(block), "env": _parse_env_payload(block[5:])}
    return None


def find_uboot_env(blob: bytes, sizes: Iterable[int] = COMMON_ENV_SIZES, align: int = 0x1000, max_hits: int = 8) -> list[dict[str, Any]]:
    """덤프 전체에서 CRC 가 맞는 env 블록을 찾는다 (align 경계에서 시작한다고 가정)."""
    hits: list[dict[str, Any]] = []
    n = len(blob)
    hint = re.compile(rb"(bootcmd|bootargs|bootdelay|baudrate)=")
    for off in range(0, n, align):
        # 빠른 필터: 시작 부근에 흔한 변수 이름이 있어야 함
        if not hint.search(blob, off + 4, min(n, off + 4 + 2048)):
            continue
        for size in sizes:
            if off + size > n:
                continue
            res = parse_uboot_env(blob[off : off + size])
            if res and res["env"]:
                hits.append({"offset": off, **res})
                break
        if len(hits) >= max_hits:
            break
    return hits


def build_uboot_env(env: dict[str, str], size: int = 0x10000, redundant: bool = False, flags: int = 1, big_endian: bool = False) -> bytes:
    """테스트/시뮬레이터용 env 블록 생성 (mkenvimage 와 같은 레이아웃, big_endian=True 는 `mkenvimage -b`)."""
    data = b"".join(f"{k}={v}".encode("utf-8") + b"\0" for k, v in env.items()) + b"\0"
    hdr = 5 if redundant else 4
    if len(data) > size - hdr:
        raise ValidationFailed("env 데이터가 블록 크기보다 큽니다.")
    payload = data.ljust(size - hdr, b"\0")
    fmt = ">I" if big_endian else "<I"
    crc = zlib.crc32(payload) & 0xFFFFFFFF
    if redundant:
        return struct.pack(fmt, crc) + bytes([flags]) + payload
    return struct.pack(fmt, crc) + payload


# ---------------------------------------------------------------------------
# U-Boot md.b / crc32 출력
# ---------------------------------------------------------------------------

MD_LINE_RE = re.compile(r"^\s*([0-9a-fA-F]{8,16}):((?:\s[0-9a-fA-F]{2}){1,64})(?:\s{2,}.*)?$")
# 카메라 U-Boot 다수(2010.06 cmd_mem.c, 2013.07/2016.11 hash.c 의 multi_hash()==0 경로)는 대문자 'CRC32 for' 를 출력한다
CRC32_LINE_RE = re.compile(r"crc32 for ([0-9a-f]+) \.\.\. ([0-9a-f]+) ==> ([0-9a-f]{8})", re.IGNORECASE)


@dataclass
class MdLine:
    address: int
    data: bytes


def parse_md_b_line(line: str) -> MdLine | None:
    m = MD_LINE_RE.match(line.rstrip("\r\n"))
    if not m:
        return None
    hexbytes = m.group(2).split()
    return MdLine(int(m.group(1), 16), bytes(int(h, 16) for h in hexbytes))


def parse_md_b_output(text: str, start: int, length: int) -> tuple[bytes, list[str]]:
    """md.b 출력 전체를 검증하며 바이트로 복원. (data, 문제 목록). 문제가 있으면 data 길이가 length 보다 짧을 수 있다."""
    problems: list[str] = []
    expected = start
    out = bytearray()
    for raw in text.splitlines():
        ml = parse_md_b_line(raw)
        if ml is None:
            continue
        if ml.address != expected:
            problems.append(f"주소 불연속: 예상 0x{expected:x}, 실제 0x{ml.address:x}")
            if ml.address < expected:
                continue  # 중복 줄은 무시
            break
        remaining = start + length - expected
        chunk = ml.data[:remaining]
        out += chunk
        expected += len(chunk)
        if expected >= start + length:
            break
    if len(out) != length:
        problems.append(f"바이트 수 불일치: 예상 {length}, 실제 {len(out)}")
    return bytes(out), problems


def parse_crc32_line(text: str) -> dict[str, Any] | None:
    m = CRC32_LINE_RE.search(text)
    if not m:
        return None
    return {"start": int(m.group(1), 16), "end": int(m.group(2), 16), "crc32": int(m.group(3), 16)}


def crc32(data: bytes) -> int:
    return zlib.crc32(data) & 0xFFFFFFFF


def format_md_b(address: int, data: bytes, width_digits: int = 8) -> str:
    """U-Boot print_buffer(width=1, linelen=16) 와 같은 형식 (시뮬레이터/테스트용)."""
    lines = []
    for i in range(0, len(data), 16):
        chunk = data[i : i + 16]
        hexpart = "".join(f" {b:02x}" for b in chunk)
        pad = "   " * (16 - len(chunk))
        asc = "".join(chr(b) if 0x20 <= b < 0x7F else "." for b in chunk)
        lines.append(f"{address + i:0{width_digits}x}:{hexpart}{pad}    {asc}")
    return "\n".join(lines)
