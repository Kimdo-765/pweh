"""U-Boot / BusyBox 출력 형식 재현 함수.

각 함수는 원본 C 코드의 printf 포맷을 그대로 옮긴 것이다 (출처 주석 참고).
"""

from __future__ import annotations

import base64 as _b64


def c_hash_x(value: int) -> str:
    """C 의 ``%#x``: 0 이면 ``0``, 아니면 ``0x`` 접두어."""
    return "0" if value == 0 else f"0x{value:x}"


def print_size(size: int, suffix: str = "") -> str:
    """U-Boot lib/display_options.c ``print_size`` (2010.06~2016.11 동일)."""
    names = "EPTGMK"
    d = 10 * len(names)
    c = ""
    for ch in names:
        if size >> d:
            c = ch
            break
        d -= 10
    if not c:
        return f"{size} Bytes{suffix}"
    n = size >> d
    f = size & ((1 << d) - 1)
    m = 0
    if f:
        m = (10 * f + (1 << (d - 1))) >> d
        if m >= 10:
            m -= 10
            n += 1
    text = f"{n}"
    if m:
        text += f".{m}"
    return f"{text} {c}iB{suffix}"


def ultohstr(size: int) -> str:
    """HiSilicon lib/vsprintf.c ``ultohstr`` ("256K", "64K", "16M")."""
    fmts = ["{}", "{}K", "{}M", "{}G", "{}T", "{}T"]
    ix = 0
    while ix < 5 and not (size & 0x3FF) and size:
        size >>= 10
        ix += 1
    return fmts[ix].format(size)


def print_buffer_lines(addr: int, data: bytes, width: int, *, pad_last: bool, little: bool = True,
                       linelen_bytes: int = 16) -> list[str]:
    """U-Boot ``print_buffer(addr, data, width, count, linelen=16/width)``.

    - 각 줄: ``%08lx:`` + 값들(`` %0{2w}x``) + 네 칸 공백 + ASCII(0x20~0x7e 외는 '.').
    - md.w / md.l 값은 CPU 바이트 순서(리틀 엔디언)로 읽은 정수이며 ASCII 는 메모리 순서 그대로다.
    - pad_last: 2011 이후 버전은 짧은 마지막 줄을 공백으로 채워 ASCII 열을 맞춘다. 2010.06 은 채우지 않는다.
    """
    lines = []
    linelen = max(1, linelen_bytes // width)
    count = len(data) // width
    pos = 0
    order = "little" if little else "big"
    while count:
        this = min(linelen, count)
        chunk = data[pos : pos + this * width]
        parts = [f"{(addr + pos) & 0xFFFFFFFF:08x}:"]
        for i in range(this):
            v = int.from_bytes(chunk[i * width : (i + 1) * width], order)
            parts.append(f" {v:0{width * 2}x}")
        if pad_last and this < linelen:
            parts.append(" " * ((width * 2 + 1) * (linelen - this)))
        asc = "".join(chr(b) if 0x20 <= b < 0x7F else "." for b in chunk)
        parts.append("    " + asc)
        lines.append("".join(parts))
        pos += this * width
        count -= this
    return lines


def hexdump_canonical(data: bytes, *, start: int = 0, squeeze: bool = True) -> str:
    """BusyBox ``hexdump -C`` (util-linux/hexdump.c + libbb/dump.c) 출력 전체.

    - 줄: ``%08x`` + 2칸 + 8바이트(공백 구분) + 2칸 + 8바이트 + 2칸 + ``|ASCII|``
    - 바로 앞에 출력한 16바이트 줄과 같은 줄이 이어지면 첫 번째 반복 위치에 ``*`` 한 줄만 출력 (-v 없을 때).
    - 마지막 부분 줄은 16바이트 폭에 맞춰 공백으로 채우고 ASCII 는 있는 바이트만.
    - 마지막에 전체 길이(끝 주소)를 ``%08x`` 로 한 줄. 입력이 비어 있으면 아무것도 출력하지 않는다.
    - 마지막 부분 블록이 직전 블록의 앞부분과 같으면 그것도 ``*`` 로 생략되며, 이때 끝 주소는 그 블록의 시작이다
      (dump.c get() 의 동작을 그대로 재현).
    """
    out: list[str] = []
    n = len(data)
    if n == 0:
        return ""
    BLOCK = 16
    savp = bytes(BLOCK)  # 처음에는 0으로 초기화된 버퍼와 비교 (xzalloc)
    vflag = "FIRST" if squeeze else "ALL"
    pos = 0
    eaddress = None
    final_addr = None
    while pos < n:
        block = data[pos : pos + BLOCK]
        if len(block) == BLOCK:
            if vflag in ("ALL", "FIRST") or block != savp:
                if vflag in ("DUP", "FIRST"):
                    vflag = "WAIT"
                out.append(_hexdump_line(start + pos, block))
                savp = block
                pos += BLOCK
                continue
            if vflag == "WAIT":
                out.append("*")
            vflag = "DUP"
            pos += BLOCK
            continue
        # 마지막 부분 블록
        if vflag != "ALL" and block == savp[: len(block)]:
            if vflag != "DUP":
                out.append("*")
            final_addr = start + pos
            pos = n
            break
        eaddress = start + pos + len(block)
        out.append(_hexdump_line(start + pos, block))
        pos = n
    if final_addr is None:
        final_addr = eaddress if eaddress is not None else start + n
    if eaddress is None and final_addr - start == 0:
        # dump.c display(): eaddress 미설정이고 address==0 이면 끝 주소 줄을 출력하지 않는다
        return "\n".join(out) + ("\n" if out else "")
    out.append(f"{final_addr & 0xFFFFFFFF:08x}")
    return "\n".join(out) + "\n"


def _hexdump_line(addr: int, block: bytes) -> str:
    cells = []
    for i in range(16):
        if i < len(block):
            cells.append(f"{block[i]:02x}")
        else:
            cells.append("  ")
    left = " ".join(cells[:8])
    right = " ".join(cells[8:])
    asc = "".join(chr(b) if 0x20 <= b < 0x7F else "." for b in block)
    return f"{addr & 0xFFFFFFFF:08x}  {left}  {right}  |{asc}|"


def busybox_base64(data: bytes) -> str:
    """BusyBox ``base64`` (coreutils/uudecode.c): 57바이트마다 76자 줄 + ``\\n``."""
    lines = []
    for i in range(0, len(data), 57):
        lines.append(_b64.b64encode(data[i : i + 57]).decode("ascii"))
    return "".join(line + "\n" for line in lines)


def make_human_readable_str(val: int, block_size: int = 1, display_unit: int = 0) -> str:
    """BusyBox libbb/human_readable.c."""
    units = ["", "K", "M", "G", "T", "P", "E", "Z", "Y"]
    if val == 0:
        return "0"
    if block_size > 1:
        val *= block_size
    frac = 0
    u = 0
    fmt_frac = False
    if display_unit:
        val += display_unit // 2
        val //= display_unit
        return f"{val}"
    while val >= 1024:
        fmt_frac = True
        u += 1
        frac = ((val % 1024) * 10 + 1024 // 2) // 1024
        val //= 1024
    if frac >= 10:
        val += 1
        frac = 0
    if fmt_frac:
        return f"{val}.{frac}{units[u]}"
    return f"{val}"


def smart_ulltoa5(ul: int) -> str:
    """BusyBox libbb/human_readable.c ``smart_ulltoa5`` (ps 의 VSZ 열, 5자, scale=" mgtpezy")."""
    scale = " mgtpezy"
    idx = 0
    if ul > 99999:
        ul *= 10
        while True:
            ul //= 1024
            idx += 1
            if ul < 100000:
                break
    u, v = divmod(ul, 10)
    digits = "0123456789"
    lead = " 123456789"
    buf = [" "] * 5
    if not idx:
        fmt = lead
        buf[0] = lead[u // 1000 % 10]
        if buf[0] != " ":
            fmt = digits
        buf[1] = fmt[u // 100 % 10]
        if buf[1] != " ":
            fmt = digits
        buf[2] = fmt[u // 10 % 10]
        if buf[2] != " ":
            fmt = digits
        buf[3] = fmt[u % 10]
        buf[4] = digits[v]
    else:
        fmt = lead
        if u >= 100:
            buf[0] = lead[u // 1000 % 10]
            if buf[0] != " ":
                fmt = digits
            buf[1] = fmt[u // 100 % 10]
            if buf[1] != " ":
                fmt = digits
            v = u % 10
            u = u // 10
            buf[2] = fmt[u % 10]
        else:
            buf[0] = lead[u // 10 % 10]
            if buf[0] != " ":
                fmt = digits
            buf[1] = fmt[u % 10]
            buf[2] = "."
        buf[3] = digits[v]
        buf[4] = scale[idx]
    return "".join(buf)


__all__ = [
    "busybox_base64",
    "c_hash_x",
    "hexdump_canonical",
    "make_human_readable_str",
    "print_buffer_lines",
    "print_size",
    "smart_ulltoa5",
    "ultohstr",
]
