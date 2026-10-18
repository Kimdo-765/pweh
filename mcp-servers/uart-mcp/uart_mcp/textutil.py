"""UART 텍스트 처리 유틸리티 (순수 함수).

- 수신 바이트 → 사람이/에이전트가 읽을 텍스트 (CRLF 정규화, 백스페이스·ANSI 처리)
- 로그용 이스케이프 (제어 문자를 ``\\xNN`` 으로 보이게)
- 인터럽트 키 별칭 해석 ("ctrl-c", "space" ...)
"""

from __future__ import annotations

import codecs
import re
from typing import Iterable

from pweh.errors import ValidationFailed

# ANSI CSI / OSC 시퀀스 (색상, 커서 이동, 줄 지우기)
ANSI_RE = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]|\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)|\x1b[@-Z\\-_]")

KEY_ALIASES: dict[str, str] = {
    "ctrl-c": "\x03",
    "ctrl+c": "\x03",
    "^c": "\x03",
    "ctrlc": "\x03",
    "space": " ",
    "spc": " ",
    "enter": "\r",
    "cr": "\r",
    "return": "\r",
    "lf": "\n",
    "esc": "\x1b",
    "escape": "\x1b",
    "ctrl-u": "\x15",
    "^u": "\x15",
    "ctrl-d": "\x04",
    "^d": "\x04",
}

KEY_NAMES: dict[str, str] = {"\x03": "ctrl-c", " ": "space", "\r": "enter", "\n": "lf", "\x1b": "esc", "\x15": "ctrl-u", "\x04": "ctrl-d"}

LINE_ENDINGS: dict[str, str] = {"\r": "\r", "\n": "\n", "\r\n": "\r\n", "cr": "\r", "lf": "\n", "crlf": "\r\n"}


def escape_for_log(text: str) -> str:
    """제어 문자를 눈에 보이게 바꾼다 (로그/이벤트용). 일반 문자는 그대로."""
    out: list[str] = []
    for ch in text:
        o = ord(ch)
        if ch == "\r":
            out.append("\\r")
        elif ch == "\n":
            out.append("\\n")
        elif ch == "\t":
            out.append("\\t")
        elif ch == "\\":
            out.append("\\\\")
        elif o < 0x20 or o == 0x7F:
            out.append(f"\\x{o:02x}")
        else:
            out.append(ch)
    return "".join(out)


def key_display(key: str) -> str:
    return KEY_NAMES.get(key) or escape_for_log(key)


def decode_keys(keys: Iterable[str]) -> list[str]:
    """인터럽트 키 목록 해석. 별칭("ctrl-c", "space"), 백슬래시 이스케이프("\\x03"), 리터럴 문자열을 받는다."""
    out: list[str] = []
    for k in keys:
        if not isinstance(k, str) or k == "":
            raise ValidationFailed(f"잘못된 키: {k!r}", hint="예: [\"ctrl-c\"], [\"\\u0003\", \" \"], [\"\\\\x03\"]")
        alias = KEY_ALIASES.get(k.strip().lower())
        if alias is not None and k.strip():
            out.append(alias)
            continue
        if "\\" in k:
            try:
                k = codecs.decode(k, "unicode_escape")
            except UnicodeDecodeError as exc:
                raise ValidationFailed(f"키 이스케이프를 해석할 수 없습니다: {k!r} ({exc})")
        if len(k) > 32:
            raise ValidationFailed(f"키 문자열이 너무 깁니다 (최대 32자): {k!r}")
        out.append(k)
    if not out:
        raise ValidationFailed("키 목록이 비어 있습니다.")
    return out


def normalize_line_ending(value: str) -> str:
    le = LINE_ENDINGS.get(value) if isinstance(value, str) else None
    if le is None:
        le = LINE_ENDINGS.get(str(value).strip().lower())
    if le is None:
        raise ValidationFailed(f"잘못된 line_ending: {value!r}", hint="\"\\r\"(기본, U-Boot 권장) / \"\\n\" / \"\\r\\n\" 또는 cr/lf/crlf")
    return le


def visible_line(line: str) -> str:
    """한 줄을 터미널에 보이는 모양으로: ANSI 제거, CR 덮어쓰기(마지막 비어 있지 않은 조각), 백스페이스 적용, 제어 문자 제거."""
    if not line:
        return ""
    s = ANSI_RE.sub("", line)
    if "\r" in s:
        parts = [p for p in s.split("\r") if p != ""]
        s = parts[-1] if parts else ""
    if "\b" in s or "\x7f" in s:
        buf: list[str] = []
        for ch in s:
            if ch in ("\b", "\x7f"):
                if buf:
                    buf.pop()
            else:
                buf.append(ch)
        s = "".join(buf)
    if any(ord(c) < 0x20 and c != "\t" for c in s):
        s = "".join(c for c in s if ord(c) >= 0x20 or c == "\t")
    return s


def normalize_newlines(text: str) -> str:
    """CRLF/CRCRLF → LF (나머지 문자는 그대로)."""
    if "\r" not in text:
        return text
    text = re.sub(r"\r+\n", "\n", text)
    return text


def render_text(text: str) -> str:
    """명령 출력용 렌더링: 줄마다 visible_line 적용 (백스페이스·ANSI·CR 덮어쓰기 처리)."""
    text = normalize_newlines(text)
    return "\n".join(visible_line(ln) for ln in text.split("\n"))


def decode_bytes(data: bytes) -> str:
    return data.decode("utf-8", "replace")


def utf8_safe_cut(data: bytes) -> int:
    """data 끝에 잘린 UTF-8 다중 바이트 문자가 있으면 그 앞까지의 길이를 돌려준다."""
    n = len(data)
    if n == 0:
        return 0
    # 끝에서 최대 3바이트 안에 시작 바이트가 있는지 본다
    for back in range(1, min(4, n) + 1):
        b = data[n - back]
        if b & 0xC0 == 0x80:  # continuation
            continue
        if b & 0x80 == 0:  # ASCII
            return n
        need = 2 if b & 0xE0 == 0xC0 else 3 if b & 0xF0 == 0xE0 else 4 if b & 0xF8 == 0xF0 else 1
        if back < need:
            return n - back
        return n
    return n


def printable_ratio(data: bytes) -> float:
    if not data:
        return 0.0
    good = sum(1 for b in data if 0x20 <= b < 0x7F or b in (0x09, 0x0A, 0x0D))
    return good / len(data)


def clip(text: str, limit: int) -> tuple[str, bool]:
    if limit and len(text) > limit:
        return text[:limit], True
    return text, False


def slugify(text: str, maxlen: int = 24, default: str = "uart") -> str:
    s = re.sub(r"[^A-Za-z0-9]+", "-", text or "").strip("-").lower()
    return (s[:maxlen].strip("-") or default) if s else default


def fmt_hex(value: int | None) -> str | None:
    return None if value is None else f"0x{value:x}"


def parse_int(value: int | str | None, *, name: str = "value", allow_none: bool = False) -> int | None:
    """정수 또는 '0x10000'/'64k'/'16M' 같은 문자열."""
    if value is None:
        if allow_none:
            return None
        raise ValidationFailed(f"{name} 가 필요합니다.")
    if isinstance(value, bool):
        raise ValidationFailed(f"{name} 는 정수여야 합니다: {value!r}")
    if isinstance(value, int):
        return value
    from pweh.fsutil import parse_size

    try:
        return parse_size(str(value))
    except Exception as exc:  # noqa: BLE001
        raise ValidationFailed(f"{name} 를 해석할 수 없습니다: {value!r} ({exc})")
