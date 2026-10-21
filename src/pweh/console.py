"""콘솔 배관 (코어) — 원시 콘솔 바이트를 마스킹한 줄 기록으로 바꾼다. 프로세스와는 무관하다.

펌웨어 에뮬레이션(pweh-emu)이 쓴다. 에이전트에게 가는 콘솔 글은 모두 :class:`LineTranscript` 가 만든 기록에서 나온다.
이 기록은 생산자 쪽(감독 스레드)에서 줄 단위로 마스킹해 둔 것이다(설계 docs/design/emulation.md §6.4).
읽는 쪽에서 조각마다 마스킹하면 두 번의 읽기에 걸친 비밀이 반씩 드러나기 때문이다.

- :func:`strip_ansi`: CSI·OSC·DCS 계열 문자열·2바이트 ESC(중간 바이트가 있는 것 포함) 시퀀스를 지운다.
- :func:`escape_controls`: 보이는 글자가 아닌 모든 코드 포인트를 ``\\xNN``·``\\uNNNN``·``\\UNNNNNNNN`` 으로 바꾼다.
  - 남기는 것: 출력 가능한 ASCII(0x20–0x7E), 탭, 범주 L*·M*·N*·P*·S*·Zs 의 비 ASCII 글자.
  - M* 가운데 이체 선택자(U+FE00–FE0F, U+E0100–E01EF)와 결합 문자 결합자(U+034F)는 이스케이프한다.
  - 그래서 다음은 모두 이스케이프된다: C* 전부(Cc, Cf, Co 사용자 정의 영역, Cs 짝 없는 서로게이트 = 잘못된 UTF-8 바이트, Cn 미할당), Zl, Zp.
    Cf 에는 bidi 제어, 폭 없는 글자(U+200B–200F·U+2060–2064·U+FEFF), 태그 문자(U+E0000–E007F)가 들어 있다.
  - 사람에게는 보이지 않지만 언어 모델은 읽는 글자로 지시를 숨기거나 자격증명 키를 쪼개지 못하게 한다.
- :func:`utf8_safe_cut`: 끝에 잘린 UTF-8 다중 바이트 문자가 있으면 그 앞까지의 길이를 돌려준다.
- :func:`is_printable_char`: :func:`escape_controls` 가 그대로 두는 글자인지(탭 포함). 마스킹의 정규화 사본도 같은 기준이다.
- :class:`LineTranscript`: 원시 바이트를 줄 레코드로 만든다(마스킹·반복 접기). 커서는 원시 바이트 오프셋이고 레코드 경계에만 놓인다.
"""

from __future__ import annotations

import bisect
import logging
import re
import threading
import unicodedata
from typing import TYPE_CHECKING, Any, Callable, Sequence

if TYPE_CHECKING:  # pragma: no cover - 형식 힌트 전용 (실행 시 순환 import 를 만들지 않는다)
    from .safety.redact import ConsoleRedactor

log = logging.getLogger("pweh.console")

#: ANSI/VT 이스케이프 시퀀스. 모든 반복에 상한이 있다(펌웨어가 정한 줄에 적용하므로 시간이 길이에 비례해야 한다)
_ANSI_RX = re.compile(
    r"\x1b\[[0-?]{0,64}[ -/]{0,16}[@-~]"  # CSI (색·커서 이동·줄 지우기)
    r"|\x1b\][^\x07\x1b]{0,4096}(?:\x07|\x1b\\)"  # OSC (창 제목·클립보드 등) — BEL 또는 ST 로 끝남
    r"|\x1b[PX^_][^\x1b]{0,4096}\x1b\\"  # DCS·SOS·PM·APC 문자열 — ST 로 끝남
    r"|\x1b[ -/]{1,4}[0-~]"  # 중간 바이트가 있는 ESC (ESC ( B 문자 집합 지정 등)
    r"|\x1b[0-~]"  # 2바이트 ESC (ESC 7·ESC c·ESC = …, 끝나지 않은 CSI·OSC 의 머리)
)
#: 출력 가능한 ASCII 와 탭 밖의 글자 — 없으면 빠른 길(이스케이프·정규화가 필요 없다)
_UNSAFE_RX = re.compile(r"[^\t\x20-\x7e]")


def strip_ansi(text: str) -> str:
    """ANSI/VT 이스케이프 시퀀스(CSI, OSC, DCS·SOS·PM·APC, 2바이트 ESC)를 지운다. 다른 글자는 그대로 둔다."""
    if "\x1b" not in text:
        return text
    return _ANSI_RX.sub("", text)


def is_printable_char(ch: str) -> bool:
    """:func:`escape_controls` 가 그대로 두는 글자면 True 다(탭 포함, 모듈 설명의 허용 목록)."""
    o = ord(ch)
    if 0x20 <= o <= 0x7E or o == 0x09:
        return True
    if o < 0xA0:  # C0 · DEL · C1
        return False
    if o == 0x034F or 0xFE00 <= o <= 0xFE0F or 0xE0100 <= o <= 0xE01EF:  # 결합 문자 결합자 · 이체 선택자
        return False
    cat = unicodedata.category(ch)
    return cat[0] in "LMNPS" or cat == "Zs"


def _escape_char(ch: str) -> str:
    o = ord(ch)
    if o <= 0xFF:
        return f"\\x{o:02x}"
    if o <= 0xFFFF:
        return f"\\u{o:04x}"
    return f"\\U{o:08x}"


def escape_controls(text: str) -> str:
    """보이는 글자가 아닌 모든 코드 포인트를 이스케이프한다(허용 목록은 모듈 설명).

    형식은 코드 포인트 기준이다: U+00FF 이하는 ``\\xNN``, U+FFFF 이하는 ``\\uNNNN``, 그 위는 ``\\UNNNNNNNN``.
    예: ESC → ``\\x1b``, 폭 없는 공백 → ``\\u200b``, 태그 문자 → ``\\U000e0041``.
    잘못된 UTF-8 바이트는 surrogateescape 서로게이트(U+DC80–DCFF)라 ``\\udcNN`` 이 된다.
    백슬래시는 출력 가능한 ASCII 라 그대로 둔다(펌웨어가 찍은 글자 ``\\x1b`` 와 이스케이프가 같아 보일 수 있다).
    """
    if not text or _UNSAFE_RX.search(text) is None:
        return text
    return "".join(ch if is_printable_char(ch) else _escape_char(ch) for ch in text)


def utf8_safe_cut(data: bytes) -> int:
    """data 끝에 잘린 UTF-8 다중 바이트 문자가 있으면 그 앞까지의 길이를, 아니면 ``len(data)`` 를 돌려준다."""
    n = len(data)
    if n == 0:
        return 0
    for back in range(1, min(4, n) + 1):  # 끝에서 최대 4바이트 안에서 시작 바이트를 찾는다
        b = data[n - back]
        if b & 0xC0 == 0x80:  # 이어지는 바이트
            continue
        if b & 0x80 == 0:  # ASCII
            return n
        need = 2 if b & 0xE0 == 0xC0 else 3 if b & 0xF0 == 0xE0 else 4 if b & 0xF8 == 0xF0 else 1
        if back < need:
            return n - back
        return n
    return n


def decode_console(data: bytes) -> str:
    """콘솔 바이트 → 글. UTF-8 + surrogateescape 라 잘못된 바이트가 U+DC80–DCFF 로 1:1 보존된다.

    알려진 비밀값의 원문 형태(``pweh.safety.redact.KnownSecrets``)도 같은 방식으로 디코드해야 이진 비밀이 맞는다.
    """
    return data.decode("utf-8", "surrogateescape")


#: 반복 접기 표시
COLLAPSE_SUFFIX = "  ⟪위 줄 ×{n}⟫"
CONTINUATION_SUFFIX = "  ⟪위 줄 ×{n} 더⟫"
#: max_chars 보다 긴 레코드를 자를 때 붙이는 표시
_CLIP_MARK = "…⟪줄 잘림⟫"
#: 마스킹이 예외로 실패한 줄 대신 보이는 표시
MASK_FAILED_TOKEN = "⟪마스킹 실패로 숨긴 줄⟫"


def _strip_cr(line: bytes) -> bytes:
    """줄 앞뒤의 CR 을 뗀다(CRLF·CRCRLF 줄 끝과 LF CR 순서로 찍는 펌웨어의 줄 머리 CR). 줄 가운데 CR 은 남겨 이스케이프된다."""
    return line.strip(b"\r")


class _Record:
    """줄 레코드. raw_start·raw_end 는 원시 바이트 오프셋(줄 끝 ``\\n`` 포함)."""

    __slots__ = ("raw_start", "raw_end", "text", "repeat", "frozen", "cont", "t_first", "t_last", "size")

    def __init__(self, raw_start: int, raw_end: int, text: str, now: float, *, cont: bool = False) -> None:
        self.raw_start = raw_start
        self.raw_end = raw_end
        self.text = text
        self.repeat = 1
        self.frozen = False
        self.cont = cont
        self.t_first = now
        self.t_last = now
        self.size = len(text) if text.isascii() else len(text.encode("utf-8", "surrogatepass"))

    def render(self) -> str:
        if self.cont:
            return self.text + CONTINUATION_SUFFIX.format(n=self.repeat)
        if self.repeat > 1:
            return self.text + COLLAPSE_SUFFIX.format(n=self.repeat)
        return self.text


def _clip(text: str, max_chars: int) -> str:
    """max_chars 글자 안으로 자른다(자른 표시 포함 — 표시보다 작은 한도면 표시 없이)."""
    if len(text) <= max_chars:
        return text
    if max_chars > len(_CLIP_MARK):
        return text[: max_chars - len(_CLIP_MARK)] + _CLIP_MARK
    return text[:max_chars]


def _literals(until: str | Sequence[str] | None) -> list[str]:
    if until is None:
        return []
    if isinstance(until, str):
        return [until] if until else []
    return [u for u in until if isinstance(u, str) and u]


def _find_literal(hay: str, lits: list[str], folded: list[str] | None) -> str | None:
    """hay 에서 가장 앞에 나오는 리터럴(같은 위치면 목록 순서가 앞선 것). 정규식은 쓰지 않는다(GIL 을 오래 잡지 않게)."""
    if folded is not None:
        hay = hay.casefold()
        cands = folded
    else:
        cands = lits
    best: tuple[int, int] | None = None
    for k, lit in enumerate(cands):
        i = hay.find(lit)
        if i != -1 and (best is None or i < best[0]):
            best = (i, k)
    return None if best is None else lits[best[1]]


class LineTranscript:
    """원시 콘솔 바이트 → 마스킹한 줄 레코드(반복 접기). 스레드 안전하다(메서드마다 내부 잠금).

    **줄과 레코드**
    - ``\\n`` 에서 줄을 끊고 줄 앞뒤의 ``\\r`` 를 뗀다(줄 가운데 ``\\r`` 는 ``\\x0d`` 로 이스케이프되어 보인다).
    - ``max_line_bytes`` 를 넘도록 ``\\n`` 이 없으면 그 길이에서(UTF-8 문자 경계) 강제로 끊는다. 끊긴 조각은 완성된 줄로 다룬다 —
      그 경계에 걸친 비밀은 가리지 못한다(설계 §6.7 의 한계).
    - 완성된 줄은 UTF-8(surrogateescape)로 디코드한 뒤 ``redactor.redact(line)`` 으로 마스킹·이스케이프해 레코드가 된다.
      ``redactor`` 는 :class:`pweh.safety.redact.ConsoleRedactor` 다. PEM·스택 블록 상태가 있으므로 줄은 들어온 순서대로 한 번씩 넘긴다.
    - 반복 접기: 마스킹한 글이 바로 앞 레코드와 같으면 새 레코드를 만들지 않고 앞 레코드의 ``repeat`` 를 늘린다.
      그러면 그 레코드의 원시 범위가 이어진 줄까지 늘어난다. 서로 다른 원문이 같은 글로 가려져도(``⟪스택 8워드⟫``) 접힌다.
    - **동결**: :meth:`read`·:meth:`tail` 이 돌려준 레코드는 동결된다. 그 뒤에 오는 같은 줄은 새 '이어짐' 레코드에 쌓인다.
      그래서 반복이 쏟아지는 동안에도 다음 읽기의 커서가 앞으로 나아간다.
    - 표시(정확한 형식):
      - ``repeat == 1`` 인 레코드는 글 그대로.
      - 처음 전달되는 접힌 레코드는 ``"<글>  ⟪위 줄 ×N⟫"`` 이다. N 은 이 레코드가 나타내는 줄 수(처음 줄 포함)다.
      - 이어짐 레코드는 ``"<글>  ⟪위 줄 ×k 더⟫"`` 이다. k 는 동결된 앞 레코드 뒤에 더 온 같은 줄 수다(k ≥ 1, 이 레코드가 나타내는 줄 수).

    **커서**
    - 커서는 원시 바이트 오프셋이고 레코드 경계에만 놓인다.
    - 레코드 중간을 가리키는 ``since`` 는 그 레코드의 시작으로 **내려** 맞춘다(``cursor_start`` 가 요청보다 앞일 수 있다).
      중간부터 자르면 키(``password=``) 없이 값만 남아 마스킹 없이 나갈 수 있기 때문이다.
    - 열린 줄(아직 ``\\n`` 이 없음) 안이나 그 뒤를 가리키면 열린 줄의 시작으로 맞춘다.
    - ``since=None`` 이면 이 기록의 에이전트 커서를 쓴다. 에이전트 커서는 직전 :meth:`read`·:meth:`tail` 의 ``cursor_end`` 이고 처음에는 0 이다.
    - 메모리 한도로 밀려난 앞부분을 가리키면 남은 가장 오래된 레코드부터 주고, 밀려난 바이트 수를 ``lost_bytes`` 와 ``note`` 로 알린다.

    **열린 줄**
    - 마지막 바이트가 온 뒤 ``open_quiet_s`` 동안 조용하면 열린 줄을 ``pending_line`` 으로 보인다. 앞의 모든 레코드를 이 읽기에서
      다 넘긴 경우(``more`` 가 False)에만 보인다. 마스킹은 ``redact(…, open_tail=True)`` 이다: 끝에 닿은 자격증명 값은 길이만,
      알려진 비밀의 앞부분일 수 있는 끝은 ``⟪보류 N자⟫``, 값이 아직 없는 키(``Password:``)는 그대로.
    - 커서는 열린 줄의 시작에 머문다. ``pending_raw_end`` 는 보인 열린 줄이 덮는 원시 오프셋이다(끝의 잘린 UTF-8 바이트 제외).
      서버는 이 값을 '이미 보인 끝'으로 써서, 프롬프트에서 기다릴 때 새 바이트 없이 바로 돌아오지 않게 한다.

    **until** (리터럴만 — 정규식 없음): 이 읽기에서 넘긴 레코드의 마스킹한 글(접기 표시 제외)과 보인 열린 줄에서 ``str.find`` 로 찾는다.
    ``until_ignore_case`` 면 양쪽을 ``casefold`` 한다. 가장 앞선 줄에서 가장 앞에 나온 리터럴이 ``match`` 다.

    **반환** (:meth:`read`·:meth:`tail` 같은 모양): ``text``(레코드 표시를 ``\\n`` 으로 이음), ``cursor_start``, ``cursor_end``,
    ``more``(넘기지 못한 완성 레코드가 남음), ``pending_line``(str | None), ``pending_raw_end``(int | None), ``lines``(넘긴 레코드 수),
    ``collapsed``(접혀 따로 보이지 않은 줄 수 = 넘긴 레코드의 repeat 합 − lines), ``lost_bytes``, ``matched``, ``match``.
    필요할 때만 ``note``(밀려난 바이트·잘린 줄 안내)가 붙는다.
    ``max_chars`` 는 ``text`` 의 글자 수 상한이다. 첫 레코드가 그보다 길어도 진행이 멈추지 않도록 잘라서 넘기고 커서를 그 뒤로 옮긴다.
    잘라 넘긴 레코드는 ``note`` 로 알린다(그 커서와 더 큰 ``max_chars`` 로 다시 읽으면 전부 보인다).

    **메모리 한도**: 레코드 수 ``max_records`` 와 표시 글 바이트 합 ``max_text_bytes`` 를 넘으면 가장 오래된 레코드부터 버린다.
    버린 원시 바이트는 :attr:`dropped_bytes` 로 센다.

    ``sink`` 를 주면 레코드가 더 바뀌지 않게 될 때(다음 레코드가 생김, 또는 :meth:`close`) ``sink(표시 글, raw_start, raw_end, t_first, t_last)``
    를 한 번 부른다. 사람용 마스킹 기록 파일(transcript.masked.txt)을 쓰는 데 쓴다. 이 콜백은 내부 잠금을 쥔 채 불린다.
    시간 값은 모두 호출자가 준 ``now``(보통 ``time.monotonic()``)다.

    **서버에서 기다릴 때**: :meth:`read` 는 넘긴 레코드를 동결하므로 기다리는 동안 되풀이해 부르지 않는다.
    :attr:`raw_total` 이 기준 오프셋(``max(since, 직전 cursor_end, 직전 pending_raw_end)``)을 넘거나
    :meth:`find_until` 이 리터럴을 찾을 때까지 기다린 뒤 :meth:`read` 를 한 번 부른다. 확인만 하려면 ``read(…, peek=True)`` 도 된다.
    마스킹이 예외로 실패한 줄은 ``MASK_FAILED_TOKEN`` 으로 숨긴다(원문을 내보내지 않고 감독 스레드도 멈추지 않는다).
    """

    def __init__(
        self,
        redactor: ConsoleRedactor,
        *,
        max_records: int = 20000,
        max_text_bytes: int = 4 << 20,
        max_line_bytes: int = 16 << 10,
        sink: Callable[[str, int, int, float, float], None] | None = None,
    ) -> None:
        if max_records < 1 or max_text_bytes < 1 or max_line_bytes < 4:
            raise ValueError("LineTranscript 한도는 양수여야 합니다 (max_line_bytes ≥ 4).")
        self._redactor = redactor
        self._max_records = int(max_records)
        self._max_text_bytes = int(max_text_bytes)
        self._max_line_bytes = int(max_line_bytes)
        self._sink = sink
        self._lock = threading.RLock()
        self._recs: list[_Record] = []
        self._head = 0  # 버린 레코드는 앞에서부터 머리 위치만 옮긴다(가끔 압축)
        self._text_bytes = 0
        self._raw_total = 0
        self._open = bytearray()
        self._open_start = 0
        self._last_feed: float | None = None
        self._closed = False
        self._cursor = 0
        self._dropped_bytes = 0
        self._dropped_records = 0
        self._masked_total = 0
        self._lines_total = 0
        self._pending_cache: tuple[str, int] | None = None

    # ------------------------------------------------------------------
    # 상태
    # ------------------------------------------------------------------
    @property
    def raw_total(self) -> int:
        """지금까지 받은 원시 바이트 수(열린 줄과 버린 레코드 포함)."""
        with self._lock:
            return self._raw_total

    @property
    def closed(self) -> bool:
        with self._lock:
            return self._closed

    @property
    def dropped_bytes(self) -> int:
        """메모리 한도로 버린 레코드의 원시 바이트 합."""
        with self._lock:
            return self._dropped_bytes

    @property
    def masked_total(self) -> int:
        """마스킹한 곳의 수(redactor 가 센 값의 합)."""
        with self._lock:
            return self._masked_total

    @property
    def lines_total(self) -> int:
        """지금까지 완성된 줄 수(접힌 줄 포함)."""
        with self._lock:
            return self._lines_total

    @property
    def last_feed(self) -> float | None:
        """마지막으로 바이트를 받은 시각(``feed`` 의 ``now``)."""
        with self._lock:
            return self._last_feed

    def _live(self) -> int:
        return len(self._recs) - self._head

    def _oldest_start(self) -> int:
        return self._recs[self._head].raw_start if self._live() else self._open_start

    # ------------------------------------------------------------------
    # 쓰기 (감독 스레드)
    # ------------------------------------------------------------------
    def feed(self, data: bytes, now: float) -> None:
        """원시 바이트를 더한다. 완성된 줄은 바로 마스킹해 레코드가 된다. :meth:`close` 뒤의 바이트는 무시한다."""
        if not data:
            return
        with self._lock:
            if self._closed:
                return
            self._raw_total += len(data)
            self._last_feed = now
            self._open += data
            self._pending_cache = None
            self._drain(now)

    def _drain(self, now: float) -> None:
        buf = self._open
        n = len(buf)
        mlb = self._max_line_bytes
        pos = 0
        while pos < n:
            nl = buf.find(b"\n", pos, min(n, pos + mlb + 1))
            if nl != -1:
                self._commit(_strip_cr(bytes(buf[pos:nl])), self._open_start + pos, self._open_start + nl + 1, now)
                pos = nl + 1
            elif n - pos > mlb:
                piece = bytes(buf[pos:pos + mlb])
                cut = utf8_safe_cut(piece) or mlb
                self._commit(piece[:cut], self._open_start + pos, self._open_start + pos + cut, now)
                pos += cut
            else:
                break
        if pos:
            del buf[:pos]
            self._open_start += pos

    def _mask(self, line: bytes, open_tail: bool) -> tuple[str, int]:
        """redactor 호출. 마스킹이 실패하면 줄을 숨긴다(닫힌 쪽으로 실패 — 원문을 내보내지도, 감독 스레드를 멈추지도 않는다)."""
        try:
            return self._redactor.redact(decode_console(line), open_tail=open_tail)
        except Exception as exc:  # noqa: BLE001
            log.error("콘솔 줄 마스킹 실패 — 줄을 숨김 (%s)", type(exc).__name__)
            return MASK_FAILED_TOKEN, 1

    def _commit(self, line: bytes, raw_start: int, raw_end: int, now: float, *, open_tail: bool = False) -> None:
        masked, count = self._mask(line, open_tail)
        self._masked_total += count
        self._lines_total += 1
        last = self._recs[-1] if self._live() else None
        if last is not None and last.text == masked:
            if not last.frozen:
                last.repeat += 1
                last.raw_end = raw_end
                last.t_last = now
                return
            rec = _Record(raw_start, raw_end, masked, now, cont=True)
        else:
            rec = _Record(raw_start, raw_end, masked, now)
        if last is not None:
            self._emit(last)
        self._recs.append(rec)
        self._text_bytes += rec.size
        self._enforce_caps()

    def _emit(self, rec: _Record) -> None:
        if self._sink is None:
            return
        try:
            self._sink(rec.render(), rec.raw_start, rec.raw_end, rec.t_first, rec.t_last)
        except Exception:  # noqa: BLE001 - 기록 파일 실패가 콘솔 처리를 멈추지 않게 (내용은 로그에 쓰지 않는다)
            log.warning("마스킹 기록 sink 실패", exc_info=False)

    def _enforce_caps(self) -> None:
        while (self._live() > self._max_records or self._text_bytes > self._max_text_bytes) and self._live() > 1:
            r = self._recs[self._head]
            self._recs[self._head] = None  # type: ignore[call-overload] - 메모리를 바로 놓는다
            self._head += 1
            self._text_bytes -= r.size
            self._dropped_bytes += r.raw_end - r.raw_start
            self._dropped_records += 1
        if self._head > 1024 and self._head * 2 > len(self._recs):
            del self._recs[: self._head]
            self._head = 0

    def close(self, now: float) -> None:
        """세션 끝: 열린 줄을 마지막 레코드로 마감한다(끝에 걸친 값·비밀 앞부분은 ``open_tail`` 규칙으로 가린다).

        이후의 :meth:`feed` 는 무시하고 ``pending_line`` 은 더 없다. 두 번 불러도 된다.
        """
        with self._lock:
            if self._closed:
                return
            if self._open:
                data = bytes(self._open)
                self._commit(_strip_cr(data), self._open_start, self._open_start + len(data), now, open_tail=True)
                self._open_start += len(data)
                self._open = bytearray()
            self._closed = True
            self._pending_cache = None
            if self._live():
                self._emit(self._recs[-1])

    # ------------------------------------------------------------------
    # 읽기 (도구 스레드)
    # ------------------------------------------------------------------
    def _locate(self, pos: int) -> tuple[int, int]:
        """pos 를 레코드 경계로 내려 맞춘다 → (레코드 인덱스, 경계 오프셋). 열린 줄 이후면 (레코드 수, 열린 줄 시작)."""
        recs = self._recs
        lo = self._head
        if lo >= len(recs) or pos >= recs[-1].raw_end:
            return len(recs), self._open_start
        j = bisect.bisect_right(recs, pos, lo, len(recs), key=lambda r: r.raw_start) - 1
        if j < lo:
            j = lo
        r = recs[j]
        if pos < r.raw_end:
            return j, r.raw_start
        return j + 1, r.raw_end  # pragma: no cover - 레코드는 빈틈없이 이어지므로 위에서 끝난다

    def _pending(self, now: float, open_quiet_s: float) -> tuple[str, int] | None:
        """조용한 열린 줄의 (마스킹한 글, 덮는 원시 끝 오프셋). 보일 것이 없으면 None."""
        if self._closed or not self._open or self._last_feed is None:
            return None
        if now - self._last_feed < open_quiet_s:
            return None
        if self._pending_cache is not None:
            return self._pending_cache
        data = bytes(self._open)
        cut = utf8_safe_cut(data)
        if cut <= 0:
            return None
        raw = _strip_cr(data[:cut])
        if not raw:
            return None
        masked, _count = self._mask(raw, True)
        self._pending_cache = (masked, self._open_start + cut)
        return self._pending_cache

    def _shape(
        self,
        delivered: list[_Record],
        parts: list[str],
        start: int,
        more: bool,
        lost: int,
        notes: list[str],
        pending: tuple[str, int] | None,
        max_chars: int,
        lits: list[str],
        ignore_case: bool,
        peek: bool,
    ) -> dict[str, Any]:
        cursor_end = delivered[-1].raw_end if delivered else start
        pending_line: str | None = None
        pending_end: int | None = None
        pending_full: str | None = None
        if pending is not None and not more:
            pending_full, pending_end = pending
            pending_line = pending_full
            if len(pending_line) > max_chars:
                pending_line = _clip(pending_line, max_chars)
                notes.append("열린 줄이 max_chars 보다 길어 앞부분만 보였습니다.")
        if not peek:
            for r in delivered:
                r.frozen = True
            self._cursor = cursor_end
        match: str | None = None
        if lits:
            folded = [lit.casefold() for lit in lits] if ignore_case else None
            for r in delivered:
                match = _find_literal(r.text, lits, folded)
                if match is not None:
                    break
            if match is None and pending_full is not None:
                match = _find_literal(pending_full, lits, folded)
        out: dict[str, Any] = {
            "text": "\n".join(parts),
            "cursor_start": start,
            "cursor_end": cursor_end,
            "more": more,
            "pending_line": pending_line,
            "pending_raw_end": pending_end,
            "lines": len(delivered),
            "collapsed": sum(r.repeat for r in delivered) - len(delivered),
            "lost_bytes": lost,
            "matched": match is not None,
            "match": match,
        }
        if notes:
            out["note"] = " ".join(notes)
        return out

    def read(
        self,
        since: int | None,
        max_chars: int,
        *,
        open_quiet_s: float,
        now: float,
        until: str | Sequence[str] | None = None,
        until_ignore_case: bool = False,
        peek: bool = False,
    ) -> dict[str, Any]:
        """since(레코드 경계로 내려 맞춤, None = 에이전트 커서)부터 max_chars 글자까지. 반환 모양은 클래스 설명.

        ``peek=True`` 면 레코드를 동결하지 않고 에이전트 커서도 옮기지 않는다(기다림 중 확인용).
        """
        max_chars = max(1, int(max_chars))
        lits = _literals(until)
        with self._lock:
            req = self._cursor if since is None else max(0, int(since))
            lost = 0
            notes: list[str] = []
            oldest = self._oldest_start()
            if req < oldest:
                lost = oldest - req
                req = oldest
                notes.append(
                    f"요청한 커서 앞의 {lost} 바이트는 메모리 기록 한도로 밀려나 이 도구로 다시 볼 수 없습니다"
                    "(사람용 마스킹 기록 파일에는 남아 있을 수 있음)."
                )
            idx, start = self._locate(req)
            parts: list[str] = []
            delivered: list[_Record] = []
            used = 0
            j = idx
            while j < len(self._recs):
                r = self._recs[j]
                s = r.render()
                add = len(s) + (1 if parts else 0)
                if parts and used + add > max_chars:
                    break
                if not parts and len(s) > max_chars:
                    s = _clip(s, max_chars)
                    add = len(s)
                    notes.append(
                        f"첫 줄이 max_chars({max_chars})보다 길어 잘라 보였습니다. 전부 보려면 since_cursor={r.raw_start} 와 "
                        "더 큰 max_chars 로 다시 읽으세요."
                    )
                parts.append(s)
                delivered.append(r)
                used += add
                j += 1
            more = j < len(self._recs)
            pending = self._pending(now, open_quiet_s) if not more else None
            return self._shape(delivered, parts, start, more, lost, notes, pending, max_chars, lits, until_ignore_case, peek)

    def tail(self, max_chars: int, *, now: float, open_quiet_s: float = 0.2) -> dict[str, Any]:
        """끝에서 max_chars 글자 안에 드는 레코드(최소 1개)와 조용한 열린 줄. 넘긴 레코드는 동결하고 에이전트 커서를 끝으로 옮긴다."""
        max_chars = max(1, int(max_chars))
        with self._lock:
            parts_rev: list[str] = []
            recs_rev: list[_Record] = []
            used = 0
            notes: list[str] = []
            j = len(self._recs) - 1
            while j >= self._head:
                r = self._recs[j]
                s = r.render()
                add = len(s) + (1 if parts_rev else 0)
                if parts_rev and used + add > max_chars:
                    break
                if not parts_rev and len(s) > max_chars:
                    s = _clip(s, max_chars)
                    add = len(s)
                    notes.append(f"마지막 줄이 max_chars({max_chars})보다 길어 잘라 보였습니다.")
                parts_rev.append(s)
                recs_rev.append(r)
                used += add
                j -= 1
            delivered = recs_rev[::-1]
            parts = parts_rev[::-1]
            start = delivered[0].raw_start if delivered else self._open_start
            pending = self._pending(now, open_quiet_s)
            return self._shape(delivered, parts, start, False, 0, notes, pending, max_chars, [], False, False)

    def find_until(
        self,
        until: str | Sequence[str],
        *,
        since: int | None = None,
        until_ignore_case: bool = False,
        open_quiet_s: float,
        now: float,
    ) -> str | None:
        """since(내려 맞춤, None = 에이전트 커서) 이후의 모든 레코드와 조용한 열린 줄에서 리터럴을 찾는다. 상태를 바꾸지 않는다.

        기다리는 동안 맞는 것이 생겼는지 볼 때 쓴다(:meth:`read` 는 넘긴 레코드를 동결하므로 되풀이해 부르지 않는다).
        """
        lits = _literals(until)
        if not lits:
            return None
        folded = [lit.casefold() for lit in lits] if until_ignore_case else None
        with self._lock:
            req = self._cursor if since is None else max(0, int(since))
            idx, _start = self._locate(max(req, self._oldest_start()))
            for j in range(idx, len(self._recs)):
                hit = _find_literal(self._recs[j].text, lits, folded)
                if hit is not None:
                    return hit
            pending = self._pending(now, open_quiet_s)
            if pending is not None:
                return _find_literal(pending[0], lits, folded)
            return None


__all__ = [
    "COLLAPSE_SUFFIX",
    "CONTINUATION_SUFFIX",
    "LineTranscript",
    "MASK_FAILED_TOKEN",
    "decode_console",
    "escape_controls",
    "is_printable_char",
    "strip_ansi",
    "utf8_safe_cut",
]
