"""자격증명 패턴과 알려진 비밀값 가림 (코어) — 펌웨어 에뮬레이션 콘솔(pweh-emu)과 fwtriage 가 함께 쓰는 정의.

- ``CRED_RX``·``QUOTED_CRED_RX``·``NON_VALUES``: fwtriage ``rootfs.py`` 에서 그대로 옮겼다(결정 D2).
  fwtriage 는 이 이름들을 여기서 가져다 쓰므로 fwtriage 출력은 바뀌지 않는다. 바꾸면 fwtriage 결과도 바뀐다.
- ``CONSOLE_CRED_RX``: 콘솔용 추가 패턴. 공백으로 구분한 ``password xxx``·``psk: x``, 닫는 따옴표가 아직 없는 값,
  ``Authorization: Bearer|Basic …``, 맨 ``Bearer <토큰>``, JWT(``eyJ….….…``), 닫는 태그 없는 XML 값, 긴 URL 자격증명.
- ``CONSOLE_KEY_RX``: 콘솔 키 규칙. 자격증명 키 다음에 ``=``·``:``(앞뒤 공백 허용)나 공백이 오면 **줄 끝까지** 가린다.
  키: ``pass(word|wd|phrase|key|code)?``·``pwd``·``psk``·``secret``·``token``·``api[_-]?key``·``access[_-]?key``·``auth[_-]?key``·``private[_-]?key``·``auth``.
  ``password incorrect`` 같은 과잉 마스킹은 받아들인다(안전한 쪽). 키 앞에 식별자가 붙어도 맞는다(``wifi_password=``·``mqttpass:``).
- :class:`KnownSecrets`: 펌웨어에서 미리 거둔 비밀값(NVS 등)의 정확 일치. 원문, 대·소문자 hex, 공백 구분 hex 를 찾는다.
- :func:`redact_line`: 상태 없는 한 줄 마스킹. :class:`ConsoleRedactor`: PEM 개인키 블록·ESP ``Stack memory:`` 블록 상태를 든 콘솔용.

마스킹 규칙(설계 docs/design/emulation.md §6.4):
1. ANSI 시퀀스를 지운 글이 표시 글이다. 패턴은 표시 글의 **정규화 사본**에 적용한다.
   정규화 사본에서는 :func:`pweh.console.is_printable_char` 가 아닌 글자(Cf·C0·C1·DEL·서로게이트·사용자 정의·이체 선택자 …)를 뺀다.
   그래서 ``pass\\u200bword=`` 처럼 쪼갠 키도 맞는다. 찾은 구간은 표시 글로 되돌려 바꾼다.
2. 알려진 비밀 → ``⟪비밀 N바이트⟫``(N = 비밀값 바이트 수).
3. 패턴 값 → 코어 :func:`pweh.safety.masking.mask_secret`. 구간은 **값 토큰의 끝까지** 늘린다.
   - 따옴표 없는 값: 다음 공백이나 ``" ' < > { } ; ,  & |`` 앞까지.
   - 따옴표 값: 닫는 따옴표 앞까지, 닫히지 않았으면 줄 끝까지.
   그래서 64자·256자 상한을 넘는 값도 남김없이 가린다.
4. 키 규칙과 ``Authorization:`` 값처럼 줄 끝까지 가리는 구간, 그리고 여러 일치가 겹친 구간은 길이만 보인다(``<가림 N자>``).
   넓힌 구간에서 앞뒤 글자를 보이면 짧은 비밀이 통째로 드러날 수 있기 때문이다.
5. ``open_tail=True``(줄 끝이 아직 오지 않은 열린 줄):
   - 글 끝에 닿은 자격증명 값은 길이만 보인다(``<가림 N자>``).
   - 끝부분이 알려진 비밀(어느 형태든)의 앞부분일 수 있으면 ``⟪보류 N자⟫`` 로 가린다.
   - 값이 아직 없는 키(``Password:``)는 그대로 보인다.
6. 가리지 않은 부분은 :func:`pweh.console.escape_controls` 로 이스케이프한다. 반환 글은 늘 표시 가능한 글자만 담는다.

성능: 펌웨어가 정한 줄(최대 16 KiB)에 적용하므로, 여기서 새로 정의한 패턴은 모두 반복에 상한이 있고 중첩된 무한 반복이 없다.
값의 시작은 앞이 토큰 글자가 아닌 곳으로만 잡는다(같은 글자 연속에서 시작 후보가 하나뿐이게).
옮긴 ``CRED_RX``·``QUOTED_CRED_RX`` 의 ``\\s*`` 는 중첩되지 않는다. 시험이 16 KiB 적대적 줄에서 패턴마다 50 ms 이하인지 확인한다.

이 모듈은 비밀값·콘솔 글을 로그에 쓰지 않는다.
"""

from __future__ import annotations

import re
import string
from typing import Iterable

from ..console import decode_console, escape_controls, is_printable_char, strip_ansi
from .masking import mask_secret

# ---------------------------------------------------------------------------
# fwtriage rootfs.py 에서 그대로 옮긴 정의 (결정 D2 — 바꾸면 fwtriage 출력이 바뀐다)
# ---------------------------------------------------------------------------

CRED_RX: list[tuple[str, re.Pattern[str]]] = [
    ("builtin-config-password", re.compile(r"(?i)(?<![\w.-])(?P<key>[\w.-]{0,32}?(?:pass(?:word|wd)?|pwd|secret|psk|passphrase|rootpw))\b[\"']?\s*[=:]\s*(?P<q>[\"']?)(?P<val>[^\s\"'<>{};,&|]{3,64})(?P=q)")),
    ("builtin-xml-password", re.compile(r"(?i)<(?P<key>pass(?:word)?|pwd|psk|passphrase)>(?P<val>[^<\s]{1,64})</")),
    ("builtin-url-credential", re.compile(r"\b(?:ftp|http|https|rtsp|tftp|smb|mysql|postgres|mqtt)://(?P<key>[^/\s:@'\"]{1,64}):(?P<val>[^/\s@'\"]{1,64})@")),
]
NON_VALUES: frozenset[str] = frozenset({"true", "false", "yes", "no", "on", "off", "none", "null", "nil", "required", "optional", "sufficient", "requisite", "include", "enable", "enabled", "disable", "disabled", "string", "char", "int", "text", "type", "hidden", "input", "value"})

#: 따옴표로 감싼(공백 포함) 비밀번호 값 — CRED_RX 는 공백 없는 값만 잡는다. 길이 상한으로 선형 시간
QUOTED_CRED_RX = re.compile(
    r"(?i)(?<![\w.-])(?P<key>[\w.-]{0,32}?(?:pass(?:word|wd)?|pwd|secret|psk|passphrase|rootpw))\b[\"']?\s{0,8}[=:]\s{0,8}(?P<q>[\"'])(?P<val>[^\"'\n]{1,256})(?P=q)")

# ---------------------------------------------------------------------------
# 콘솔용 추가 패턴
# ---------------------------------------------------------------------------

#: 계약의 키 목록에 BLE 짝짓기 passkey·passcode 를 더했다(pass 묶음의 상위 집합 — 더 가리는 쪽)
_CONSOLE_KEYS = r"pass(?:word|wd|phrase|key|code)?|pwd|psk|secret|token|api[_-]?key|access[_-]?key|auth[_-]?key|private[_-]?key|auth"

#: 콘솔 키 규칙: 키 + (선택적 닫는 따옴표) + (공백* [=:] 공백* | 공백 1–4개 뒤 공백 아닌 글자). 일치 끝부터 줄 끝까지 가린다
CONSOLE_KEY_RX = re.compile(
    r"(?i)(?:" + _CONSOLE_KEYS + r")[\"']?(?:\s{0,16}[=:\uff1a\uff1d]\s{0,16}|\s{1,4}(?=\S))")

CONSOLE_CRED_RX: list[tuple[str, re.Pattern[str]]] = [
    # 공백 구분 키-값과 짧은 값: "password hunter2", "psk: ab" (값은 = 나 : 로 시작하지 않는다 — "key = v" 는 다른 규칙이 맡는다)
    ("console-space-password", re.compile(
        r"(?i)(?<![\w.-])(?P<key>[\w.-]{0,32}?(?:pass(?:word|wd|phrase)?|pwd|secret|psk|rootpw|token))\b[\"']?"
        r"(?:\s{1,8}|\s{0,8}:\s{0,8})(?P<val>[^\s\"'<>{};,&|=:][^\s\"'<>{};,&|]{0,63})")),
    # 여는 따옴표만 있는 값(256자를 넘거나 줄이 끝날 때까지 닫히지 않음) — 구간은 닫는 따옴표나 줄 끝까지
    ("console-quoted-value", re.compile(
        r"(?i)(?<![\w.-])(?P<key>[\w.-]{0,32}?(?:pass(?:word|wd|phrase)?|pwd|secret|psk|rootpw|token|api[_-]?key|access[_-]?key|auth[_-]?key|private[_-]?key))\b[\"']?"
        r"\s{0,8}[=:]\s{0,8}(?P<q>[\"'])(?P<val>[^\"'\n]{1,256})")),
    # HTTP Authorization 머리글 — 방식 이름은 두고 나머지는 줄 끝까지
    ("console-authorization", re.compile(
        r"(?i)(?<![\w-])(?:proxy-)?authorization[\"']?\s{0,8}[=:]\s{0,8}"
        r"(?:(?:bearer|basic|digest|token|negotiate|ntlm)\s{1,8})?(?P<val>\S[^\n]{0,8191})")),
    # 머리글 없이 찍힌 Bearer/Basic 토큰(16자 이상의 토큰 글자)
    ("console-bearer", re.compile(
        r"(?i)(?<![\w-])(?:bearer|basic)\s{1,8}(?P<val>[A-Za-z0-9._~+/-]{16,4096}={0,2})")),
    # JWT: 세 부분. 한 줄 상한(16 KiB)까지 머리·몸을 받아 긴 부분도 통째로 빠지지 않게 한다.
    ("console-jwt", re.compile(
        r"(?<![A-Za-z0-9_-])(?P<val>eyJ[A-Za-z0-9_-]{2,16384}\.[A-Za-z0-9_-]{2,16384}\.[A-Za-z0-9_-]{0,4096})")),
    # 닫는 태그가 없거나 64자를 넘는 XML 값
    ("console-xml-secret", re.compile(
        r"(?i)<(?P<key>pass(?:word|wd|phrase)?|pwd|psk|secret|token|api[_-]?key|auth[_-]?key)>(?P<val>[^<\s]{1,64})")),
    # URL 자격증명: 값의 앞부분만 찾고 실제 @·경계까지 늘린다. 닫는 @ 를 패턴에 요구하면 긴 값 전체가 빠진다.
    ("console-url-credential", re.compile(
        r"(?i)\b(?:ftp|ftps|sftp|http|https|rtsp|rtsps|tftp|smb|mysql|postgres|postgresql|mqtt|mqtts|ws|wss|amqp|amqps|redis|telnet|ssh)://"
        r"(?P<key>[^/\s:@'\"]{1,16384}):(?P<val>[^/\s@'\"]{1,1024})")),
]

#: 패턴마다 (이름, 정규식, 구간 끝 방식, fwtriage 값 제외 규칙 적용 여부).
#: 끝 방식: token = 값 토큰 끝까지(따옴표 그룹 q 가 있으면 닫는 따옴표·줄 끝까지), fixed = 일치한 값 그대로, eol = 줄 끝까지,
#: url = 사용자 정보의 @·경계까지(열린 URL 은 끝까지 보류)
_PATTERNS: list[tuple[str, re.Pattern[str], str, bool]] = (
    [(name, rx, "fixed" if name == "builtin-url-credential" else "token", True) for name, rx in CRED_RX]
    + [("builtin-quoted-password", QUOTED_CRED_RX, "token", True)]
    + [
        (name, rx,
         {"console-authorization": "eol", "console-url-credential": "url"}.get(name, "token"),
         name not in ("console-authorization", "console-bearer", "console-jwt"))
        for name, rx in CONSOLE_CRED_RX
    ]
)

#: 자격증명 패턴이 맞을 수 있는 줄인지 먼저 본다(모든 패턴의 필수 글자를 담은 상위 집합)
_CRED_HINT_RX = re.compile(r"(?i)pass|pwd|psk|secret|token|key|auth|rootpw|://|bearer|basic|eyj")
#: 따옴표 없는 값 토큰을 끝내는 글자: 공백과 " ' < > { } ; , & |
_TOKEN_STOP_RX = re.compile(r"[\s\"'<>{};,&|]")
_URL_VALUE_STOP_RX = re.compile(r"[/\s@'\"]")

# ---------------------------------------------------------------------------
# 블록 검출 (ConsoleRedactor)
# ---------------------------------------------------------------------------

#: PEM 개인키 블록 — 머리줄 다음 줄부터 END 줄까지, 또는 이만큼의 줄까지 가린다
PEM_MAX_LINES = 256
_PEM_BEGIN_RX = re.compile(r"-----BEGIN (?:[A-Z0-9]{1,24} ){0,4}PRIVATE KEY-----", re.I)
_PEM_END_RX = re.compile(r"-----END [A-Z0-9 ]{0,64}-----", re.I)
#: ESP-IDF 패닉의 "Stack memory:" 머리줄과 리틀 엔디언 워드 줄(주소: 0x워드 ×1–8)
_STACK_HEADER_RX = re.compile(r"\s{0,8}stack memory:\s{0,8}", re.I)
_STACK_LINE_RX = re.compile(r"\s{0,4}[0-9a-fA-F]{8}:((?:\s{1,4}0[xX][0-9a-fA-F]{8}){1,8})\s{0,4}")
_STACK_WORD_RX = re.compile(r"0[xX]([0-9a-fA-F]{8})")
#: 아직 다 오지 않은 워드 줄(열린 줄)의 모양
_STACK_PREFIX_RX = re.compile(
    r"\s{0,4}[0-9a-fA-F]{1,8}(?::(?:\s{1,4}0[xX][0-9a-fA-F]{8}){0,7}(?:\s{1,4}(?:0(?:[xX][0-9a-fA-F]{0,8})?)?)?)?\s{0,4}")
#: 스택 블록의 디코드한 바이트를 이만큼까지 든다(넘으면 앞을 버린다)
_STACK_BUF_MAX = 64 << 10

PEM_LINE_TOKEN = "⟪개인키 줄⟫"
STACK_PENDING_TOKEN = "⟪스택 줄 받는 중⟫"

_ASCII_LOWER = str.maketrans(string.ascii_uppercase, string.ascii_lowercase)

# ---------------------------------------------------------------------------
# 알려진 비밀값
# ---------------------------------------------------------------------------

#: 바늘이 이보다 많으면 str.find 를 바늘마다 부르는 대신 앞 4글자 색인으로 한 번 훑는다
_FIND_MAX_NEEDLES = 32


def _low_entropy(b: bytes) -> bool:
    """흔한 바이트열(모두 같은 바이트 0x00…·0xFF…, 8바이트 미만인데 서로 다른 바이트가 3개 미만)이면 True."""
    distinct = len(set(b))
    return distinct <= 1 or (len(b) < 8 and distinct < 3)


#: 출력 가능한 ASCII 와 탭 밖의 글자 (없으면 정규화할 것이 없다)
_UNSAFE_RX = re.compile(r"[^\t\x20-\x7e]")


def _kept(text: str) -> str:
    """정규화: 표시 가능한 글자(탭 포함)만 남긴다."""
    if _UNSAFE_RX.search(text) is None:
        return text
    return "".join(c for c in text if is_printable_char(c))


class _NeedleSet:
    """같은 글(원문 또는 ASCII 소문자 사본)에서 찾는 바늘 묶음."""

    def __init__(self, needles: Iterable[tuple[str, int]]) -> None:
        best: dict[str, int] = {}
        for text, nbytes in needles:
            if text:
                best[text] = max(best.get(text, 0), nbytes)
        self.items: list[tuple[str, int]] = sorted(best.items(), key=lambda kv: (-len(kv[0]), kv[0]))
        self.short = [(t, nb) for t, nb in self.items if len(t) < 4]  # 다중 바이트 문자로 된 값 등
        self.index: dict[str, list[tuple[str, int]]] | None = None
        long_items = [(t, nb) for t, nb in self.items if len(t) >= 4]
        if len(long_items) > _FIND_MAX_NEEDLES:
            idx: dict[str, list[tuple[str, int]]] = {}
            for t, nb in long_items:
                idx.setdefault(t[:4], []).append((t, nb))
            self.index = idx
        self.long = long_items

    def matches(self, text: str) -> list[tuple[int, int, int]]:
        """(시작, 끝, 비밀 바이트 수) — 겹치는 일치도 모두."""
        out: list[tuple[int, int, int]] = []
        if not self.items or not text:
            return out
        find_list = self.short if self.index is not None else self.items
        for t, nb in find_list:
            i = text.find(t)
            while i != -1:
                out.append((i, i + len(t), nb))
                i = text.find(t, i + 1)
        if self.index is not None and len(text) >= 4:
            get = self.index.get
            for i in range(len(text) - 3):
                cands = get(text[i:i + 4])
                if cands:
                    for t, nb in cands:
                        if text.startswith(t, i):
                            out.append((i, i + len(t), nb))
        return out

    def prefix_tail(self, text: str) -> int:
        """글 끝 L 글자가 어떤 바늘의 (온전하지 않은) 앞부분과 같을 때의 가장 큰 L."""
        if not text or not self.items:
            return 0
        last = text[-1]
        n = len(text)
        best = 0
        for t, _nb in self.items:
            lim = len(t) - 1
            if lim <= best:
                continue
            j = t.rfind(last, 0, lim)
            while j != -1 and j + 1 > best:
                if j + 1 <= n and text.endswith(t[: j + 1]):
                    best = j + 1
                    break
                j = t.rfind(last, 0, j)
        return best


class KnownSecrets:
    """미리 거둔 비밀값의 정확 일치(설계 §5.3-8 의 NVS 비밀값 등). 값은 메모리에만 두고 개수만 밖에 알린다.

    - 값: bytes(문자열이면 UTF-8). 끝의 NUL 은 뗀다. ``min_len`` 바이트보다 짧은 값과 흔한 값(:func:`_low_entropy` —
      모두 같은 바이트, 8바이트 미만인데 서로 다른 바이트가 3개 미만)은 버린다. 콘솔의 ``0xffffffff`` 같은 글을 가리지 않게 한다.
    - ``max_len`` 보다 긴 값은 ``max_len`` 조각으로 나눠 조각마다 찾는다(마지막 조각이 짧으면 끝에서 ``max_len``).
    - 같은 값은 한 번만, 최대 ``max_values`` 개.
    - 찾는 형태:
      - 원문: 콘솔 디코드와 같은 UTF-8 surrogateescape 글. 제어 문자가 섞인 값은 그것을 뺀 정규화 형태도 찾는다.
      - ``min_hex_len`` 바이트 이상인 값만 hex 와 공백 구분 hex(``de ad be ef``)도 찾는다. 대소문자는 가리지 않는다.
        ASCII 만 소문자로 바꾼 사본에서 찾으므로 위치가 어긋나지 않는다.
    """

    def __init__(
        self,
        values: Iterable[bytes],
        *,
        min_len: int = 4,
        min_hex_len: int = 6,
        max_values: int = 256,
        max_len: int = 256,
    ) -> None:
        self.min_len = max(1, int(min_len))
        self.min_hex_len = max(1, int(min_hex_len))
        self.max_values = max(0, int(max_values))
        self.max_len = max(self.min_len, int(max_len))
        kept: list[bytes] = []
        seen: set[bytes] = set()
        for v in values:
            if isinstance(v, str):
                b = v.encode("utf-8")
            elif isinstance(v, (bytes, bytearray, memoryview)):
                b = bytes(v)
            else:
                raise TypeError(f"알려진 비밀값은 bytes 나 str 이어야 합니다 (받은 형식: {type(v).__name__}).")
            b = b.rstrip(b"\x00")
            if len(b) > self.max_len:
                pieces = [b[i:i + self.max_len] for i in range(0, len(b), self.max_len)]
                if len(pieces[-1]) < self.min_len:
                    pieces[-1] = b[-self.max_len:]
            else:
                pieces = [b]
            for p in pieces:
                if len(kept) >= self.max_values:
                    break
                if len(p) < self.min_len or _low_entropy(p) or p in seen:
                    continue
                seen.add(p)
                kept.append(p)
        self._values: tuple[bytes, ...] = tuple(kept)
        raw: list[tuple[str, int]] = []
        hexes: list[tuple[str, int]] = []
        for b in kept:
            t = decode_console(b)
            raw.append((t, len(b)))
            tn = _kept(t)
            if tn != t and len(tn.encode("utf-8", "surrogateescape")) >= self.min_len \
                    and not _low_entropy(tn.encode("utf-8", "surrogateescape")):
                raw.append((tn, len(b)))
            if len(b) >= self.min_hex_len:
                hexes.append((b.hex(), len(b)))
                hexes.append((" ".join(f"{x:02x}" for x in b), len(b)))
        self._raw = _NeedleSet(raw)
        self._hex = _NeedleSet(hexes)
        self.max_value_len = max((len(b) for b in kept), default=0)

    @property
    def count(self) -> int:
        """쓰는 비밀값 수(버린 값 제외)."""
        return len(self._values)

    def __len__(self) -> int:
        return len(self._values)

    def __repr__(self) -> str:  # 값을 보이지 않는다
        return f"KnownSecrets(count={self.count})"

    def _matches(self, text: str) -> list[tuple[int, int, int]]:
        out = self._raw.matches(text)
        if self._hex.items:
            out.extend(self._hex.matches(text.translate(_ASCII_LOWER)))
        return out

    def spans(self, text: str) -> list[tuple[int, int]]:
        """text 안에서 비밀값(원문·hex·공백 구분 hex)이 있는 구간. 정렬하고 겹친 구간은 합친다."""
        return _merge([(a, b) for a, b, _nb in self._matches(text)])

    def prefix_tail(self, text: str) -> int:
        """text 끝 L 글자가 비밀값(어느 형태든)의 앞부분일 수 있을 때의 가장 큰 L(없으면 0)."""
        if not text or not self._values:
            return 0
        best = self._raw.prefix_tail(text)
        if self._hex.items:
            best = max(best, self._hex.prefix_tail(text.translate(_ASCII_LOWER)))
        return best

    def count_in_bytes(self, buf: bytes, *, start: int = 0, new_from: int = 0) -> int:
        """buf[start:] 에서 원시 바이트 비밀값이 나타나는 수(끝이 new_from 을 넘는 것만 — 이어 붙인 버퍼에서 새 일치만 셀 때)."""
        n = 0
        for v in self._values:
            i = buf.find(v, start)
            while i != -1:
                if i + len(v) > new_from:
                    n += 1
                i = buf.find(v, i + 1)
        return n


def _merge(spans: list[tuple[int, int]]) -> list[tuple[int, int]]:
    out: list[tuple[int, int]] = []
    for a, b in sorted(spans):
        if out and a < out[-1][1]:
            if b > out[-1][1]:
                out[-1] = (out[-1][0], b)
        else:
            out.append((a, b))
    return out


# ---------------------------------------------------------------------------
# 한 줄 마스킹
# ---------------------------------------------------------------------------


def _normalize(disp: str) -> tuple[str, list[int] | None]:
    """정규화 사본과 위치 표(정규화 글의 i 번째 글자 → 표시 글의 위치). 빼는 글자가 없으면 (disp, None)."""
    if _UNSAFE_RX.search(disp) is None:
        return disp, None
    idx = [i for i, c in enumerate(disp) if is_printable_char(c)]
    if len(idx) == len(disp):
        return disp, None
    return "".join(disp[i] for i in idx), idx


def _to_disp(a: int, b: int, idx: list[int] | None) -> tuple[int, int]:
    if idx is None:
        return a, b
    return idx[a], idx[b - 1] + 1


def _skip_value(val: str) -> bool:
    """fwtriage mask_credentials 와 같은 제외: 값이 아닌 낱말·경로·변수·자리표시·이미 가린 값."""
    return (not val or val.lower() in NON_VALUES or val.startswith(("$", "%", "`", "@", "{", "/"))
            or set(val) <= {"*", "x", "X", "#"})


def _value_end(norm: str, m: re.Match[str], mode: str, memo: list[int], rlen: int) -> int:
    """값 구간의 끝(정규화 좌표). rlen = 끝 공백을 뺀 줄 길이.
    memo = [토큰 시작, 토큰 끝] — 같은 토큰 안의 일치는 다시 훑지 않는다(선형 시간)."""
    start = m.start("val")
    q = m.groupdict().get("q")
    if q:
        close = norm.find(q, start)
        return close if close != -1 else max(rlen, m.end("val"))
    if mode == "fixed":
        return m.end("val")
    if mode == "eol":
        return max(m.end("val"), rlen)
    if mode == "url":
        stop = _URL_VALUE_STOP_RX.search(norm, m.end("val"))
        return stop.start() if stop is not None else len(norm)
    pos = m.end("val")
    if memo[0] <= pos <= memo[1]:
        return memo[1]
    stop = _TOKEN_STOP_RX.search(norm, pos)
    end = stop.start() if stop is not None else len(norm)
    memo[0], memo[1] = pos, end
    return end


def _find_spans(disp: str, norm: str, idx: list[int] | None, known: KnownSecrets | None,
                open_tail: bool) -> list[tuple[int, int, str, int]]:
    """마스킹 구간(표시 글 좌표): (시작, 끝, 종류 secret|value|eol|hold, 비밀 바이트 수)."""
    spans: list[tuple[int, int, str, int]] = []
    nlen = len(norm)
    if known is not None and known.count:
        for a, b, nb in known._matches(norm):
            spans.append((*_to_disp(a, b, idx), "secret", nb))
        if idx is not None:  # 제어 문자가 섞인(이진) 비밀은 표시 글에서 원문 그대로 찾는다
            for a, b, nb in known._raw.matches(disp):
                spans.append((a, b, "secret", nb))
        if open_tail and nlen:
            hold = known.prefix_tail(norm)
            if hold:
                spans.append((*_to_disp(nlen - hold, nlen, idx), "hold", 0))
    if nlen and _CRED_HINT_RX.search(norm) is not None:
        rlen = len(norm.rstrip())
        m = CONSOLE_KEY_RX.search(norm)
        if m is not None and rlen > m.end():
            spans.append((*_to_disp(m.end(), rlen, idx), "eol", 0))
        memo = [-1, -1]
        for _name, rx, mode, check in _PATTERNS:
            for mm in rx.finditer(norm):
                if check and _skip_value(mm.group("val")):
                    continue
                a = mm.start("val")
                b = _value_end(norm, mm, mode, memo, rlen)
                if b <= a:
                    continue
                if mode == "url" and not (b < nlen and norm[b] == "@") and not (open_tail and b == nlen):
                    continue  # 닫힌 일반 URL 의 host:port 는 자격증명이 아니다
                kind = "eol" if mode == "eol" or (open_tail and b >= nlen) else "value"
                spans.append((*_to_disp(a, b, idx), kind, 0))
    return spans


def _token(seg: str, a: int, b: int, parts: list[tuple[int, int, str, int]]) -> str:
    """합친 구간 [a, b) 의 표시. 값 하나가 구간 전체를 덮을 때만 mask_secret(앞뒤 몇 글자) — 넓힌 구간은 길이만."""
    kept = _kept(seg)
    n = len(kept)
    kinds = {p[2] for p in parts}
    if kinds == {"secret"}:
        return f"⟪비밀 {max(p[3] for p in parts)}바이트⟫"
    if kinds == {"hold"}:
        return f"⟪보류 {n}자⟫"
    if kinds == {"value"} and any(p[0] == a and p[1] == b for p in parts):
        return mask_secret(kept)  # 여러 패턴이 같은 값을 찾았거나 한 값 안에 다른 일치가 든 경우
    return f"<가림 {n}자>"


def _render(disp: str, spans: list[tuple[int, int, str, int]]) -> tuple[str, int]:
    if not spans:
        return escape_controls(disp), 0
    groups: list[list] = []
    for s in sorted(spans, key=lambda s: (s[0], -s[1])):
        if groups and s[0] < groups[-1][1]:
            g = groups[-1]
            g[1] = max(g[1], s[1])
            g[2].append(s)
        else:
            groups.append([s[0], s[1], [s]])
    out: list[str] = []
    last = 0
    for a, b, parts in groups:
        out.append(escape_controls(disp[last:a]))
        out.append(_token(disp[a:b], a, b, parts))
        last = b
    out.append(escape_controls(disp[last:]))
    return "".join(out), len(groups)


def _mask_line(disp: str, known: KnownSecrets | None, open_tail: bool,
               norm_idx: tuple[str, list[int] | None] | None = None) -> tuple[str, int]:
    """ANSI 를 지운 한 줄의 기본 마스킹(비밀값·키 규칙·패턴). 블록 규칙은 없다."""
    norm, idx = norm_idx if norm_idx is not None else _normalize(disp)
    return _render(disp, _find_spans(disp, norm, idx, known, open_tail))


def redact_line(text: str, known: KnownSecrets | None, *, open_tail: bool = False) -> tuple[str, int]:
    """상태 없는 한 줄 마스킹 → (마스킹·이스케이프한 글, 가린 곳 수).

    :class:`ConsoleRedactor` 의 한 줄짜리 규칙을 모두 쓴다: 알려진 비밀, 키 규칙, 패턴, 같은 줄의 PEM 본문, 스택 워드 줄.
    여러 줄 블록 상태는 없다. 서버가 stderr 꼬리·힌트·펌웨어에서 온 짧은 글(파티션 이름 등)에 쓴다.
    """
    return ConsoleRedactor(known)._process(text, commit=False, open_tail=open_tail)


class ConsoleRedactor:
    """콘솔 줄 마스킹(상태 있음). :class:`pweh.console.LineTranscript` 가 완성된 줄마다 차례로 부른다. 스레드 안전하지 않다.

    - 한 줄 규칙은 :func:`redact_line` 과 같다(모듈 설명).
    - PEM: ``-----BEGIN … PRIVATE KEY-----`` 머리줄의 표식은 보이고, 같은 줄의 뒷부분은 ``⟪개인키 N자⟫`` 이다.
      다음 줄부터 END 줄까지, 또는 ``PEM_MAX_LINES``(256) 줄까지 모든 줄이 ``⟪개인키 줄⟫`` 이다.
      END 줄은 END 표식 앞부분을 가리고 표식과 그 뒤를 보인다.
    - ESP 스택: ``^[0-9a-f]{8}: (0x[0-9a-f]{8} ?){1,8}$`` 모양의 워드 줄은 ``⟪스택 N워드⟫`` 이다. ``Stack memory:`` 머리줄이 없어도 같다.
      이어진 워드 줄(머리줄 뒤에서 시작)의 리틀 엔디언 바이트를 이어 붙여 알려진 비밀값을 찾고 센다(:attr:`stack_secret_hits`, 반환 수).
      MEPC·레지스터·백트레이스 줄은 워드 줄 모양이 아니라 그대로 남는다.
    - ``open_tail=True`` 는 상태를 바꾸지 않는 미리보기다. 열린 줄을 볼 때 쓰며, 지금의 블록 상태는 따른다
      (PEM 블록 안의 열린 줄은 ``⟪개인키 줄⟫``). 다 오지 않은 스택 워드 줄은 ``⟪스택 줄 받는 중⟫`` 이다.
    - 같은 줄이 이어지면(블록 밖) 앞 결과를 다시 쓴다(반복이 쏟아질 때의 비용).
    """

    def __init__(self, known: KnownSecrets | None = None) -> None:
        self.known = known
        self.stack_secret_hits = 0
        self.reset()

    def reset(self) -> None:
        """블록 상태를 처음으로 되돌린다(비밀값과 누적 수는 그대로)."""
        self._in_pem = False
        self._pem_lines = 0
        self._in_stack = False
        self._stack_buf = bytearray()
        self._cache_line: str | None = None
        self._cache_out: tuple[str, int] | None = None

    @property
    def in_block(self) -> str | None:
        """지금 들어가 있는 블록: ``"pem"`` | ``"stack"`` | None."""
        if self._in_pem:
            return "pem"
        if self._in_stack:
            return "stack"
        return None

    def redact(self, line: str, *, open_tail: bool = False) -> tuple[str, int]:
        """한 줄(줄 끝 문자 없음)을 마스킹한다 → (표시 글, 가린 곳 수). ``open_tail=False`` 면 블록 상태를 갱신한다."""
        if open_tail:
            return self._process(line, commit=False, open_tail=True)
        if (self._cache_out is not None and line == self._cache_line
                and not self._in_pem and not self._in_stack):
            return self._cache_out
        self._cache_line = None
        self._cache_out = None
        return self._process(line, commit=True, open_tail=False)

    # ------------------------------------------------------------------
    def _process(self, line: str, *, commit: bool, open_tail: bool) -> tuple[str, int]:
        disp = strip_ansi(line)
        norm, idx = _normalize(disp)
        if self._in_pem:
            return self._pem_body(disp, norm, idx, commit, open_tail)
        if "-----" in norm:
            b = _PEM_BEGIN_RX.search(norm)
            if b is not None:
                return self._pem_begin(disp, norm, idx, b, commit, open_tail)
        if len(norm) <= 40 and _STACK_HEADER_RX.fullmatch(norm):
            if commit:
                self._in_stack = True
                self._stack_buf.clear()
            return _mask_line(disp, self.known, open_tail, (norm, idx))
        if ":" in norm[:16]:
            sm = _STACK_LINE_RX.fullmatch(norm)
            if sm is not None:
                words = _STACK_WORD_RX.findall(sm.group(1))
                hits = self._stack_feed(words) if commit else 0
                if commit:
                    self._in_stack = True
                return f"⟪스택 {len(words)}워드⟫", 1 + hits
        if open_tail and (self._in_stack or ": 0x" in norm) and _STACK_PREFIX_RX.fullmatch(norm):
            return STACK_PENDING_TOKEN, 1
        if commit and self._in_stack:
            self._in_stack = False
            self._stack_buf.clear()
        out = _mask_line(disp, self.known, open_tail, (norm, idx))
        if commit:
            self._cache_line = line
            self._cache_out = out
        return out

    def _stack_feed(self, words: list[str]) -> int:
        buf = self._stack_buf
        prev = len(buf)
        for w in words:
            buf += int(w, 16).to_bytes(4, "little")
        known = self.known
        if known is None or not known.count:
            if len(buf) > _STACK_BUF_MAX:
                del buf[: len(buf) - 1024]
            return 0
        hits = known.count_in_bytes(bytes(buf), start=max(0, prev - known.max_value_len + 1), new_from=prev)
        self.stack_secret_hits += hits
        if len(buf) > _STACK_BUF_MAX:
            del buf[: len(buf) - max(known.max_value_len, 1024)]
        return hits

    def _inline_body(self, seg: str) -> tuple[str, int]:
        body = _kept(seg)
        if body.strip():
            return f"⟪개인키 {len(body)}자⟫", 1
        return escape_controls(seg), 0

    def _pem_body(self, disp: str, norm: str, idx: list[int] | None, commit: bool, open_tail: bool) -> tuple[str, int]:
        e = _PEM_END_RX.search(norm)
        if e is None:
            if commit:
                self._pem_lines += 1
                if self._pem_lines >= PEM_MAX_LINES:
                    self._in_pem = False
                    self._pem_lines = 0
            return PEM_LINE_TOKEN, 1
        if commit:
            self._in_pem = False
            self._pem_lines = 0
        da, db = _to_disp(e.start(), e.end(), idx)
        out: list[str] = []
        count = 0
        if da:
            t, c = self._inline_body(disp[:da])
            out.append(t)
            count += c
        out.append(escape_controls(disp[da:db]))
        if db < len(disp):
            t, c = _mask_line(disp[db:], self.known, open_tail)
            out.append(t)
            count += c
        return "".join(out), count

    def _pem_begin(self, disp: str, norm: str, idx: list[int] | None, b: re.Match[str], commit: bool,
                   open_tail: bool) -> tuple[str, int]:
        da, db = _to_disp(b.start(), b.end(), idx)
        out: list[str] = []
        count = 0
        if da:
            t, c = _mask_line(disp[:da], self.known, False)
            out.append(t)
            count += c
        out.append(escape_controls(disp[da:db]))
        e = _PEM_END_RX.search(norm, b.end())
        if e is not None:  # 한 줄에 본문과 END 가 함께 (문자열 안의 \n 이스케이프 등)
            ea, eb = _to_disp(e.start(), e.end(), idx)
            if ea > db:
                t, c = self._inline_body(disp[db:ea])
                out.append(t)
                count += c
            out.append(escape_controls(disp[ea:eb]))
            if eb < len(disp):
                t, c = _mask_line(disp[eb:], self.known, open_tail)
                out.append(t)
                count += c
            return "".join(out), count
        if db < len(disp):
            t, c = self._inline_body(disp[db:])
            out.append(t)
            count += c
        if commit:
            self._in_pem = True
            self._pem_lines = 0
        return "".join(out), count


__all__ = [
    "CONSOLE_CRED_RX",
    "CONSOLE_KEY_RX",
    "CRED_RX",
    "ConsoleRedactor",
    "KnownSecrets",
    "NON_VALUES",
    "PEM_LINE_TOKEN",
    "PEM_MAX_LINES",
    "QUOTED_CRED_RX",
    "STACK_PENDING_TOKEN",
    "redact_line",
]
