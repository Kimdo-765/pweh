"""JTAGulator 시리얼 메뉴 프로토콜: 상수, 장치 상태 판별, 펌웨어 입력 해석 규칙, 순열 계산.

근거: grandideastudio/jtagulator 펌웨어 소스(tag 1.12, 1.11.1, 1.10)와 docs/references/jtagulator-protocol.md.
지원 범위는 FW 1.10 – 1.12 이다 (그 미만은 대화 순서·문구가 달라 자동 조작을 거부한다).

이 모듈은 순수 함수만 담는다 (I/O 없음). 드라이버·안전 분류기·파서가 공유한다.
시뮬레이터(sim.py)는 일부러 이 모듈을 import 하지 않는다 — 문자열 오타가 양쪽에 함께 숨지 않게 하기 위함.
"""

from __future__ import annotations

import codecs
import math
import re
from dataclasses import dataclass

from pweh.errors import ValidationFailed

# ---------------------------------------------------------------------------
# 하드웨어/펌웨어 상수 (JTAGulatorCon.spin, JTAGulator.spin CON 섹션)
# ---------------------------------------------------------------------------

MAX_CHAN = 24  # CH0..CH23
MAX_LEN_CMD = 12  # 명령/값 입력 줄 최대 길이 (StrInMax)
MAX_LEN_UART_USER = 34  # UART 스캔 문자열 입력 줄 최대 길이 ("\x" + 32 hex)
MAX_LEN_UART_TX = 16  # UART 스캔 프로브 최대 바이트 수
MIN_SUPPORTED_FW = (1, 10)
VTARGET_MIN_TENTHS = 14  # 1.4 V (FW 1.7+)
VTARGET_MAX_TENTHS = 33  # 3.3 V

# UART_Scan 이 시도하는 보드레이트 표 (BaudRate DAT)
BAUD_TABLE: tuple[int, ...] = (
    300, 600, 1200, 1800, 2400, 3600, 4800, 7200, 9600, 14400, 19200, 28800,
    31250, 38400, 57600, 76800, 115200, 153600, 230400, 250000, 307200,
)

# UART_Scan_TXD 의 Best Fit 표 (UART_Best_Fit)
BEST_FIT_RANGES: tuple[tuple[int, int, int], ...] = (
    (2280, 2520, 2400), (3420, 3780, 3600), (4560, 5040, 4800), (6840, 7560, 7200),
    (9120, 10080, 9600), (13680, 15120, 14400), (18240, 20160, 19200), (27360, 30240, 28800),
    (30241, 32813, 31250), (36480, 40320, 38400), (54720, 60480, 57600), (72960, 80640, 76800),
    (109440, 120960, 115200), (145920, 161280, 153600), (218880, 241920, 230400),
    (241921, 262500, 250000), (291840, 322560, 307200), (328320, 362880, 345600),
    (437760, 483840, 460800), (875520, 949248, 921600), (949249, 988800, 960000),
    (988801, 1050000, 1000000), (1140000, 1260000, 1200000), (1425000, 1575000, 1500000),
)

# 스캔 종류별: 찾아야 하는 핀 수(r), 메뉴, 메뉴 명령 키, 최소 채널 수
SCAN_SPECS: dict[str, dict[str, object]] = {
    "idcode": {"menu": "jtag", "key": "I", "pins": 3, "label": "IDCODE"},
    "bypass": {"menu": "jtag", "key": "B", "pins": 4, "label": "BYPASS"},
    "jtag": {"menu": "jtag", "key": "J", "pins": 4, "label": "JTAG combined"},
    "uart": {"menu": "uart", "key": "U", "pins": 2, "label": "UART"},
    "uart_txd": {"menu": "uart", "key": "T", "pins": 1, "label": "UART TXD"},
}

MENU_PREFIX_TO_NAME = {"": "main", "JTAG": "jtag", "UART": "uart", "GPIO": "gpio", "SWD": "swd"}
MENU_ENTER_KEY = {"jtag": "J", "uart": "U", "gpio": "G", "swd": "S"}

# 송신 키
KEY_ABORT_SCAN = "\n"  # 실행 중 스캔 중단: LF 1바이트 (스캔이 이미 끝났다면 줄 입력이 LF 를 버려 부작용 없음)
KEY_START_SCAN = " "  # "Press spacebar to begin" 에는 공백 1바이트만
RESYNC_FIRST = "\x18"  # Ctrl-X: 패스스루/영속 모드 종료, 스캔·스페이스바 대기 취소, 부팅 키 대기 해제
RESYNC_SECOND = "\x18\r"  # 값 프롬프트였다면 잘못된 입력으로 취소, 메뉴였다면 무효 명령

# ---------------------------------------------------------------------------
# 수신 버퍼 '끝'에서 대기 상태를 판별하는 정규식 (원시 텍스트, latin-1 디코딩)
# ---------------------------------------------------------------------------

RE_MENU_PROMPT = re.compile(r"\r\n\n(?P<menu>JTAG|UART|GPIO|SWD)?> \Z")
RE_MENU_PROMPT_ANY = re.compile(r"\r\n\n(?P<menu>JTAG|UART|GPIO|SWD)?> ")
RE_VALUE_PROMPT = re.compile(r"\n(?P<label>[^\r\n]*?) ?\[(?P<default>[^\r\n]*)\]: \Z")
RE_VOLTAGE_PROMPT = re.compile(
    r"Enter new target I/O voltage \((?P<min>\d\.\d) - (?P<max>\d\.\d), 0 for off\): \Z"
)
RE_SPACE_PROMPT = re.compile(r"Press spacebar to begin \(any other key(?: besides Enter)? to abort\)\.\.\.\Z")
RE_SCAN_STARTED = re.compile(r"JTAGulating! Press any key to abort\.\.\.\r\n")
RE_BANNER = re.compile(r"Welcome to JTAGulator\. Press 'H' for available commands\.")
RE_VERSION = re.compile(r"JTAGulator FW (?P<ver>\d+(?:\.\d+)+)")
RE_GENERIC_PROMPT = re.compile(r"\n(?P<text>[^\r\n]{1,240}?(?::|\?|\.\.\.) ?)\Z")
RE_PERSISTENT_EXIT = re.compile(r"(?P<mode>OpenOCD|Logic analyzer) mode complete\.")
RE_PASSTHRU_EXIT = re.compile(r"UART passthrough complete\.")

STARTED_MARKER = "JTAGulating! Press any key to abort..."

# 값 프롬프트 label → 정규화한 종류. (FW 1.10–1.12 문구 변형 포함)
VALUE_PROMPT_KINDS: dict[str, str] = {
    "Enter starting channel": "start_channel",
    "Enter ending channel": "end_channel",
    "Are any pins already known?": "pins_known",
    "Enter TDI pin": "pin_tdi",
    "Enter TDO pin": "pin_tdo",
    "Enter TCK pin": "pin_tck",
    "Enter TMS pin": "pin_tms",
    "Enter TXD pin": "pin_txd",
    "Enter RXD pin": "pin_rxd",
    "Bring channels LOW before each permutation?": "pins_low",  # FW 1.11+
    "Bring channels LOW between each permutation?": "pins_low",  # FW 1.10
    "Enter length of time for channels to remain LOW (in ms, 1 - 1000)": "pins_low_ms",
    "Enter length of time after channels return HIGH before proceeding (in ms, 1 - 1000)": "pins_high_ms",
    "Enter text string to output (prefix with \\x for hex)": "uart_text",
    "Enter delay before checking for target response (in ms, 0 - 1000)": "uart_delay",
    "Ignore non-printable characters?": "uart_printable",
    "Ignore non-standard baud rates?": "uart_ignore_nonstandard",
}

# 이 서버가 답하지 않지만 의미를 아는 값 프롬프트. 답하면 위험한 명령(GPIO W, 핀 매퍼, 패스스루)으로 이어진다.
DANGEROUS_VALUE_PROMPTS: dict[str, str] = {
    "Enter value to output (in hex)": "GPIO W: 24채널 전부를 이 값으로 구동",
    "Enter EXTEST instruction (in hex)": "핀 매퍼(EXTEST): 타깃 칩의 실제 핀을 구동",
    "Fill Boundary Scan Register with HIGH or LOW?": "핀 매퍼(EXTEST): 타깃 칩의 실제 핀을 구동",
    "Pause after successful detection?": "핀 매퍼(EXTEST): 타깃 칩의 실제 핀을 구동",
    "Ignore single-bit Data Registers?": "IR/DR discovery: 알 수 없는 JTAG 명령어를 모두 실행",
    "Enter baud rate": "UART 패스스루: 이후 입력이 분류 없이 타깃 콘솔로 전달",
    "Enable local echo?": "UART 패스스루: 이후 입력이 분류 없이 타깃 콘솔로 전달",
}

# 의미를 알고 답해도 무해한(설정만 바꾸는) 값 프롬프트 — 서버는 쓰지 않지만 분류기에서 INTERACT 로 본다
BENIGN_VALUE_PROMPTS = {
    "Is TCK already known?",
    "Enter SWDIO pin",
    "Enter SWCLK pin",
}


@dataclass(frozen=True)
class DeviceContext:
    """수신 버퍼 끝에서 판별한 장치 대기 상태."""

    state: str  # menu | value | voltage | space | scanning | unknown
    menu: str | None = None  # main | jtag | uart | gpio | swd (state == menu)
    label: str | None = None  # 값 프롬프트 문구 (state == value)
    kind: str | None = None  # 정규화한 값 프롬프트 종류
    default: str | None = None  # 값 프롬프트의 [현재값]
    vmin: float | None = None  # 전압 프롬프트가 알려 준 범위
    vmax: float | None = None
    text: str = ""  # 마지막 줄(진단용)

    def describe(self) -> str:
        if self.state == "menu":
            return f"메뉴 프롬프트({self.menu})"
        if self.state == "value":
            return f"값 프롬프트 '{self.label}'"
        if self.state == "voltage":
            return "전압 입력 프롬프트"
        if self.state == "space":
            return "스캔 시작 대기(스페이스바)"
        if self.state == "scanning":
            return "스캔 실행 중"
        return f"알 수 없는 상태 (마지막 줄: {self.text[-80:]!r})"


def detect_context(tail: str) -> DeviceContext:
    """수신 텍스트의 끝부분으로 현재 장치가 무엇을 기다리는지 판별한다.

    프롬프트 판별은 버퍼 '끝'에서만 한다(뒤에 다른 출력이 붙었으면 그 프롬프트는 이미 지나간 것).
    스캔 실행 중은 마지막 'JTAGulating!' 표식 뒤에 메뉴 프롬프트가 없으면 참이다.
    """
    m = RE_MENU_PROMPT.search(tail)
    if m:
        return DeviceContext("menu", menu=MENU_PREFIX_TO_NAME[m.group("menu") or ""], text=m.group(0).strip())
    m = RE_VOLTAGE_PROMPT.search(tail)
    if m:
        return DeviceContext("voltage", vmin=float(m.group("min")), vmax=float(m.group("max")), text=m.group(0))
    m = RE_VALUE_PROMPT.search(tail)
    if m:
        label = m.group("label").strip()
        return DeviceContext(
            "value", label=label, kind=VALUE_PROMPT_KINDS.get(label), default=m.group("default"), text=m.group(0).strip()
        )
    if RE_SPACE_PROMPT.search(tail):
        return DeviceContext("space", text="Press spacebar to begin ...")
    i = tail.rfind(STARTED_MARKER)
    if i >= 0:
        last_menu = -1
        for mm in RE_MENU_PROMPT_ANY.finditer(tail):
            last_menu = mm.start()
        if last_menu < i:
            return DeviceContext("scanning", text=tail[-80:])
    m = RE_GENERIC_PROMPT.search(tail)
    last_line = tail.replace("\r", "").split("\n")[-1] if tail else ""
    return DeviceContext("unknown", text=(m.group("text") if m else last_line))


# ---------------------------------------------------------------------------
# 펌웨어 입력 해석 (PropSerial.StrInMax, Get_Decimal_Pin, Get_Pin)
# ---------------------------------------------------------------------------


def effective_line(keys: str, maxlen: int = MAX_LEN_CMD) -> tuple[str, bool]:
    """StrInMax 동작을 흉내 내 (장치가 받아들일 줄 내용, CR 로 끝났는지)를 반환.

    BS(0x08)는 앞 글자를 지우고, LF 는 버리고, maxlen 을 넘는 글자는 버린다. 첫 CR 에서 줄이 끝난다.
    """
    buf: list[str] = []
    for ch in keys:
        if ch == "\r":
            return "".join(buf), True
        if ch == "\x08":
            if buf:
                buf.pop()
            continue
        if ch == "\n":
            continue
        if len(buf) < maxlen:
            buf.append(ch)
    return "".join(buf), False


def dec_pin(s: str) -> int:
    """Get_Decimal_Pin: 빈 줄 -1, 숫자만 누적('.'·',' 무시), 그 밖의 글자 -3."""
    if s == "":
        return -1
    v = 0
    for ch in s:
        if "0" <= ch <= "9":
            v = v * 10 + (ord(ch) - 48)
        elif ch in ".,":
            continue
        else:
            return -3
    return v


def get_pin(s: str) -> int:
    """Get_Pin: 빈 줄 -1, 'X' 한 글자 -2(모름), 'X'로 시작하는 2글자 이상 -3, 나머지는 dec_pin."""
    if s == "":
        return -1
    if s[0] in "Xx":
        return -2 if len(s) == 1 else -3
    return dec_pin(s)


def voltage_tenths(answer: str) -> int:
    """전압 프롬프트 답을 펌웨어처럼 해석 (0.1 V 단위 정수). 정수 2·3 은 2.0·3.0 으로 본다(FW 1.5+)."""
    v = dec_pin(answer)
    if v == 2:
        v = 20
    elif v == 3:
        v = 30
    return v


# ---------------------------------------------------------------------------
# 순열 / 소요 시간 하한
# ---------------------------------------------------------------------------


def permutations(n: int, r: int) -> int:
    """n! / (n-r)! (펌웨어 Display_Permutations 와 같은 계산)."""
    if r <= 0:
        return 1
    if n < r:
        return 0
    return math.perm(n, r)


# 하한 추정의 근거 (실측이 아님):
#  - JTAG 클럭은 최대 25 kHz (CHANGES 1.9). IDCODE 1순열 = Get_Device_IDs(1) ≈ 47 TCK.
#  - BYPASS 1순열 = Detect_Devices 가 IR 체인에 1024비트 + DR 64비트 이상 시프트 ≈ 1100 TCK.
#  - UART 1순열 = 보드레이트 21개 × (cog 준비 10 ms + 응답 대기 delay ms + 첫 바이트 대기 20 ms) + 프로브 송신 시간.
JTAG_TCK_HZ_MAX = 25_000
TCK_PER_PERM = {"idcode": 47, "jtag": 47, "bypass": 1100}


def lower_bound_seconds(
    kind: str,
    perms: int,
    *,
    pins_low: bool = False,
    pins_low_ms: int = 100,
    pins_high_ms: int = 100,
    uart_delay_ms: int = 10,
    probe_len: int = 1,
) -> float | None:
    """스캔 소요 시간의 '하한' 추정(초). 펌웨어 코드와 문서화된 클럭 상한으로 계산한 값이며 실측이 아니다."""
    if kind == "uart_txd":
        return None
    extra = (pins_low_ms + pins_high_ms) / 1000.0 if pins_low else 0.0
    if kind in TCK_PER_PERM:
        per = TCK_PER_PERM[kind] / JTAG_TCK_HZ_MAX
    elif kind == "uart":
        per = 0.0
        for baud in BAUD_TABLE:
            per += (10 + uart_delay_ms + 20) / 1000.0 + (10.0 * probe_len) / baud
    else:
        return None
    return round(perms * (per + extra), 1)


def best_fit_baud(measured: int) -> int | None:
    for lo, hi, val in BEST_FIT_RANGES:
        if lo <= measured <= hi:
            return val
    return None


# ---------------------------------------------------------------------------
# 입력값 검증/정규화 (펌웨어 범위와 같게 — 대화 도중 'Value out of range!' 가 나지 않도록)
# ---------------------------------------------------------------------------


def parse_fw_version(text: str | None) -> tuple[int, ...] | None:
    if not text:
        return None
    try:
        return tuple(int(x) for x in str(text).split("."))
    except ValueError:
        return None


def fw_supported(version: str | None) -> bool:
    v = parse_fw_version(version)
    return v is not None and v >= MIN_SUPPORTED_FW


def normalize_volts(volts: float | int | str) -> str:
    """전압 인자를 펌웨어 입력 문자열로 정규화: 0 → '0', 1.4~3.3 (0.1 V 단위) → '3.3'.

    반올림하지 않는다 — 1.85 처럼 0.1 V 단위가 아니면 거부한다(의도와 다른 전압 인가 방지).
    """
    try:
        v = float(str(volts).strip().lower().rstrip("v"))
    except (TypeError, ValueError):
        raise ValidationFailed(f"전압 값을 해석할 수 없습니다: {volts!r}", hint="예: 3.3, 1.8, 2.5 또는 0(끄기)")
    if not math.isfinite(v):
        raise ValidationFailed(f"전압 값이 유효하지 않습니다: {volts!r}")
    if v == 0:
        return "0"
    tenths = round(v * 10)
    if abs(v * 10 - tenths) > 1e-6:
        raise ValidationFailed(
            f"JTAGulator 전압은 0.1 V 단위만 설정할 수 있습니다 (받은 값: {volts!r}).",
            hint="측정한 타깃 I/O 전압에 가장 가까운 0.1 V 값을 사람이 정해 다시 요청하세요. 임의로 반올림하지 않습니다.",
        )
    if not VTARGET_MIN_TENTHS <= tenths <= VTARGET_MAX_TENTHS:
        raise ValidationFailed(
            f"JTAGulator 타깃 I/O 전압 범위는 1.4–3.3 V 입니다 (받은 값: {volts!r}).",
            hint="1.4 V 미만(예: 1.2 V) 타깃은 JTAGulator 레벨 변환기(TXS0108E) 규격 밖이라 사용할 수 없습니다. 5 V 타깃은 지원하지 않습니다.",
        )
    return f"{tenths // 10}.{tenths % 10}"


_PORT_URL_SCHEMES = ("socket://", "rfc2217://", "loop://")


def validate_port(port: str) -> str:
    """jtagulator_connect 의 port 검증: 장치 절대경로(/dev/ttyUSB0, /dev/serial/by-id/...), Windows COMn,
    또는 원격 시리얼 URL(socket://, rfc2217://, 테스트용 loop://)만 허용한다.

    pyserial 의 다른 URL 처리기는 막는다 — ``spy://...?file=<경로>`` 는 호스트의 임의 파일에 기록하고,
    ``hwgrep://<정규식>`` 은 어떤 장치가 열릴지 정할 수 없어(대상 콘솔 어댑터일 수 있음) 재동기화 키가 엉뚱한 장치로 갈 수 있다.
    """
    p = (port or "").strip()
    if not p:
        raise ValidationFailed("port 가 비어 있습니다.", hint="예: /dev/ttyUSB0 또는 socket://127.0.0.1:7777")
    if any(c in p for c in "\x00\r\n"):
        raise ValidationFailed(f"port 에 제어 문자가 있습니다: {port!r}")
    if "://" in p:
        if not p.lower().startswith(_PORT_URL_SCHEMES):
            raise ValidationFailed(
                f"지원하지 않는 포트 URL 입니다: {p!r}",
                hint="장치 경로(/dev/ttyUSB0) 또는 socket://host:port, rfc2217://host:port 만 사용할 수 있습니다.",
            )
        return p
    if p.startswith("/") or re.fullmatch(r"COM\d{1,3}", p, re.I):
        return p
    raise ValidationFailed(
        f"포트는 장치 절대경로여야 합니다: {p!r}",
        hint="예: /dev/ttyUSB0, /dev/serial/by-id/usb-FTDI_..., 원격이면 socket://host:port",
    )


def validate_channels(kind: str, start_channel: int, end_channel: int) -> tuple[int, int]:
    pins = int(SCAN_SPECS[kind]["pins"])  # type: ignore[arg-type]
    try:
        s, e = int(start_channel), int(end_channel)
    except (TypeError, ValueError):
        raise ValidationFailed("start_channel/end_channel 은 정수여야 합니다.")
    if not 0 <= s <= MAX_CHAN - 1:
        raise ValidationFailed(f"start_channel 은 0–{MAX_CHAN - 1} 이어야 합니다 (받은 값: {s}).")
    if e > MAX_CHAN - 1 or e < s + pins - 1:
        raise ValidationFailed(
            f"end_channel 은 {s + pins - 1}–{MAX_CHAN - 1} 이어야 합니다 (이 스캔은 채널이 최소 {pins}개 필요, 받은 값: {e}).",
            hint="채널 번호는 JTAGulator 보드의 CH0–CH23 이며, 후보 테스트포인트를 CH0 부터 차례로 연결하는 것을 권장합니다.",
        )
    return s, e


def validate_known_pins(
    known: dict[str, int] | None, allowed: tuple[str, ...], start: int, end: int, total_pins: int
) -> dict[str, int]:
    """알려진 핀 검증: 이름은 allowed 중, 값은 start..end, 서로 달라야 하고, 모두 알면 스캔할 필요가 없다."""
    if not known:
        return {}
    if not isinstance(known, dict):
        raise ValidationFailed("known_pins 는 {핀이름: 채널} 객체여야 합니다. 예: {\"tdo\": 2, \"tck\": 0}")
    out: dict[str, int] = {}
    for k, v in known.items():
        name = str(k).strip().lower()
        if name not in allowed:
            raise ValidationFailed(f"알 수 없는 핀 이름: {k!r}", hint=f"허용: {', '.join(allowed)}")
        if v is None:
            continue
        try:
            ch = int(v)
        except (TypeError, ValueError):
            raise ValidationFailed(f"known_pins.{name} 는 채널 번호(정수)여야 합니다.")
        if not start <= ch <= end:
            raise ValidationFailed(f"known_pins.{name}={ch} 가 스캔 채널 범위 {start}–{end} 밖입니다.")
        out[name] = ch
    if len(set(out.values())) != len(out):
        raise ValidationFailed("known_pins 의 채널 번호가 서로 겹칩니다 (펌웨어: 'Pin numbers must be unique!').")
    if len(out) >= total_pins:
        raise ValidationFailed("모든 핀을 이미 알고 있으면 이 스캔은 필요 없습니다.")
    return out


def validate_ms(name: str, value: int, lo: int, hi: int) -> int:
    try:
        v = int(value)
    except (TypeError, ValueError):
        raise ValidationFailed(f"{name} 는 정수(ms)여야 합니다.")
    if not lo <= v <= hi:
        raise ValidationFailed(f"{name} 는 {lo}–{hi} ms 여야 합니다 (받은 값: {v}).")
    return v


def decode_text_escapes(text: str) -> str:
    """백슬래시 이스케이프(\\r \\n \\t \\xHH \\\\)를 해석한다.

    에이전트가 JSON 에서 '\\\\r'(백슬래시+r 두 글자)처럼 이중 이스케이프하는 실수를 흡수한다. 백슬래시가 없으면 그대로.
    """
    if not isinstance(text, str):
        raise ValidationFailed("text 는 문자열이어야 합니다.")
    if "\\" not in text:
        return text
    try:
        return codecs.decode(text.encode("latin-1", "backslashreplace"), "unicode_escape")
    except (UnicodeDecodeError, ValueError) as exc:
        raise ValidationFailed(
            f"text 의 이스케이프를 해석할 수 없습니다: {text!r} ({exc})",
            hint="CR 은 '\\r', LF 는 '\\n', 임의 바이트는 '\\x03' 처럼 쓰세요. 백슬래시 자체는 '\\\\'.",
        ) from exc


def uart_probe_answer(text: str) -> tuple[str, bytes]:
    """UART 스캔 프로브 문자열을 펌웨어 입력으로 변환: 항상 '\\x' hex 형식.

    - ASCII 입력은 펌웨어가 CR 을 자동으로 붙이고, 빈 줄은 '이전 값 유지'라서 모호하다.
      hex 형식은 정확히 그 바이트만 보낸다(CR 자동 추가 없음).
    - 기본값 '\\r' → '\\x0D'. 최대 16바이트.
    """
    if not isinstance(text, str):
        raise ValidationFailed("text 는 문자열이어야 합니다.")
    try:
        data = text.encode("latin-1")
    except UnicodeEncodeError:
        raise ValidationFailed("text 에는 0x00–0xFF 범위의 문자만 쓸 수 있습니다 (예: '\\r', 'help\\r').")
    if not 1 <= len(data) <= MAX_LEN_UART_TX:
        raise ValidationFailed(
            f"text 는 1–{MAX_LEN_UART_TX} 바이트여야 합니다 (받은 길이: {len(data)}).",
            hint="JTAGulator 펌웨어가 프로브 문자열을 최대 16바이트까지만 받습니다.",
        )
    return "\\x" + data.hex().upper(), data


def decode_uart_text_answer(line: str) -> bytes | None:
    """펌웨어가 UART 문자열 프롬프트 답을 해석하는 방식: '\\x'+hex 면 그 바이트, 아니면 ASCII + CR. 무효면 None."""
    if line.startswith("\\x"):
        hexpart = line[2:]
        if not hexpart or len(line) % 2 != 0 or not re.fullmatch(r"[0-9A-Fa-f]+", hexpart):
            return None
        data = bytes.fromhex(hexpart)
        return data if len(data) <= MAX_LEN_UART_TX else None
    if line == "":
        return None  # '이전 값 유지' — 장치에 남아 있는 이전 문자열을 알 수 없으므로 확정 불가로 본다
    if any(not (0x20 <= ord(c) <= 0x7E) for c in line) or len(line) > MAX_LEN_UART_TX:
        return None
    return line.encode("latin-1") + b"\r"
