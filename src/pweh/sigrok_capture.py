"""유한 OLS Windows 캡처의 닫힌 명령 계약. 파일·포트·환경을 조회하지 않는다."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import re

from .errors import PwehError, ValidationFailed
from .ports import parse_win_com
from .wininterop import validate_windows_path


PROFILE_ID = "ols-capture-v1"
DRIVER = "ols"
OUTPUT_NAME = "capture.sr"
MIN_RATE = 10
MAX_RATE = 100_000_000
MIN_SAMPLES = 4
MAX_SAMPLES = 8_388_608
MAX_CHANNELS = 32
_RENAME = re.compile(r"[A-Za-z][A-Za-z0-9_]{0,31}\Z")
_INDEX = re.compile(r"(?:0|[1-9][0-9]?)\Z")
_DECIMAL = re.compile(r"[1-9][0-9]{0,8}\Z")
_PROFILE = {
    "profile_id": PROFILE_ID, "driver": DRIVER, "mode": "capture",
    "argv": ["--driver=ols:conn={conn}", "--dont-scan", "--config=samplerate={rate}",
             "--channels={channels}", "--samples={samples}", "--output-format=srzip",
             "--output-file={output}"],
    "rate": [MIN_RATE, MAX_RATE], "samples": [MIN_SAMPLES, MAX_SAMPLES, 4],
    "channels": "explicit-contiguous-zero-based-1-to-32-ascii-rename",
    "output_name": OUTPUT_NAME, "unitsize": 4, "serialcomm": "115200/8n1",
    "probe_reset_count": 5, "trigger": "fixed-stage-zero", "demux": False,
}
PROFILE_SHA256 = hashlib.sha256(
    (json.dumps(_PROFILE, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n").encode("ascii")
).hexdigest()
del _PROFILE


def _invalid() -> ValidationFailed:
    return ValidationFailed("고정 OLS 캡처 입력 또는 출력 경로가 올바르지 않습니다.",
                            code="sigrok_capture_invalid")


@dataclass(frozen=True)
class CaptureChannel:
    """승인된 채널 번호와 제한된 이름. 숫자 기본 이름은 자기 번호와 같아야 한다."""

    index: int
    name: str

    def __post_init__(self) -> None:
        if (type(self.index) is not int or not 0 <= self.index < MAX_CHANNELS
                or type(self.name) is not str or not 1 <= len(self.name) <= 32
                or (self.name != str(self.index) and not _RENAME.fullmatch(self.name))):
            raise _invalid()

    def to_dict(self) -> dict[str, int | str]:
        return {"index": self.index, "name": self.name}


def _channels(value: tuple[CaptureChannel, ...]) -> None:
    if (type(value) is not tuple or not 1 <= len(value) <= MAX_CHANNELS
            or any(type(ch) is not CaptureChannel for ch in value)):
        raise _invalid()
    for i, ch in enumerate(value):
        ch.__post_init__()
        if ch.index != i:
            raise _invalid()
    if len({ch.name for ch in value}) != len(value):
        raise _invalid()


def normalize_channels(value: object) -> tuple[CaptureChannel, ...]:
    """확장 전 크기를 제한한 숫자 범위/rename을 0번부터 연속인 frozen tuple로 만든다."""
    if type(value) is str:
        if not 1 <= len(value) <= 2048:
            raise _invalid()
        items = value.split(",")
    elif type(value) in (list, tuple):
        if not 1 <= len(value) <= MAX_CHANNELS:
            raise _invalid()
        items = value
    else:
        raise _invalid()
    if not 1 <= len(items) <= MAX_CHANNELS:
        raise _invalid()
    channels: dict[int, CaptureChannel] = {}
    for item in items:
        if type(item) is int and 0 <= item < MAX_CHANNELS:
            item = str(item)
        if type(item) is not str or not 1 <= len(item) <= 40:
            raise _invalid()
        item = item.strip()
        if "=" in item:
            src, name = item.split("=", 1)
            if not _INDEX.fullmatch(src):
                raise _invalid()
            selected = (CaptureChannel(int(src), name),)
        elif "-" in item:
            start, stop = item.split("-", 1)
            if not _INDEX.fullmatch(start) or not _INDEX.fullmatch(stop):
                raise _invalid()
            a, b = int(start), int(stop)
            if not 0 <= a < b < MAX_CHANNELS:
                raise _invalid()
            selected = tuple(CaptureChannel(i, str(i)) for i in range(a, b + 1))
        else:
            if not _INDEX.fullmatch(item):
                raise _invalid()
            selected = (CaptureChannel(int(item), item),)
        for ch in selected:
            if ch.index in channels:
                raise _invalid()
            channels[ch.index] = ch
    result = tuple(channels[i] for i in sorted(channels))
    _channels(result)
    return result


def _output(value: str) -> str:
    try:
        result = validate_windows_path(value)
    except (PwehError, TypeError, ValueError, UnicodeError):
        raise _invalid() from None
    if result.replace("/", "\\").rsplit("\\", 1)[-1] != OUTPUT_NAME:
        raise _invalid()
    return result


@dataclass(frozen=True)
class CaptureCommand:
    """요청 의미만 보유한다. 출력 directory 신원은 별도 owner가 결속한다."""

    profile_id: str
    conn: str
    samplerate_hz: int
    samples: int
    channels: tuple[CaptureChannel, ...]

    def __post_init__(self) -> None:
        if (type(self.profile_id) is not str or self.profile_id != PROFILE_ID
                or type(self.conn) is not str or not 4 <= len(self.conn) <= 7
                or type(self.samplerate_hz) is not int or not MIN_RATE <= self.samplerate_hz <= MAX_RATE
                or type(self.samples) is not int or not MIN_SAMPLES <= self.samples <= MAX_SAMPLES
                or self.samples % 4):
            raise _invalid()
        number = parse_win_com(self.conn)
        if number is None:
            raise _invalid()
        _channels(self.channels)
        object.__setattr__(self, "conn", f"COM{number}")

    @property
    def expected_reported_rate_hz(self) -> int:
        """tagged OLS 비DEMUX divider의 계산값이며 실제 clock 측정은 아니다."""
        return MAX_RATE // (MAX_RATE // self.samplerate_hz)

    @property
    def profile_sha256(self) -> str:
        return PROFILE_SHA256

    def approval_identity(self) -> dict:
        """런타임 UUID/출력 경로 없는 안정적인 승인 입력의 독립 사본."""
        return {"profile_id": PROFILE_ID, "profile_sha256": PROFILE_SHA256,
                "driver": DRIVER, "mode": "capture", "conn": self.conn,
                "samplerate_hz": self.samplerate_hz, "samples": self.samples,
                "channels": [ch.to_dict() for ch in self.channels]}

    def argv_tail(self, output_windows: str) -> tuple[str, ...]:
        """순서/값을 고정하며 output 경로의 문법만 확인한다."""
        output = _output(output_windows)
        channels = ",".join(str(ch.index) if ch.name == str(ch.index)
                            else f"{ch.index}={ch.name}" for ch in self.channels)
        return (f"--driver=ols:conn={self.conn}", "--dont-scan",
                f"--config=samplerate={self.samplerate_hz}", f"--channels={channels}",
                f"--samples={self.samples}", "--output-format=srzip", f"--output-file={output}")


@dataclass(frozen=True)
class ParsedCaptureInvocation:
    """역해석한 요청과 정확한 Windows 출력 철자. 파일 소유 증명은 아니다."""

    command: CaptureCommand
    output_windows: str


def from_argv_tail(tail: tuple[str, ...]) -> ParsedCaptureInvocation:
    """옵션 별칭/순서 변경/추가 인자와 비정규 숫자 표기를 거부한다."""
    prefixes = ("--driver=ols:conn=", "--config=samplerate=", "--channels=",
                "--samples=", "--output-file=")
    if (type(tail) is not tuple or len(tail) != 7
            or any(type(arg) is not str or len(arg) > 8192 for arg in tail)
            or tail[1] != "--dont-scan" or tail[5] != "--output-format=srzip"):
        raise _invalid()
    values = []
    for arg, prefix in zip((tail[0], tail[2], tail[3], tail[4], tail[6]), prefixes):
        if not arg.startswith(prefix):
            raise _invalid()
        values.append(arg[len(prefix):])
    conn, rate, channels, samples, output = values
    if not _DECIMAL.fullmatch(rate) or not _DECIMAL.fullmatch(samples):
        raise _invalid()
    command = CaptureCommand(PROFILE_ID, conn, int(rate), int(samples), normalize_channels(channels))
    if command.argv_tail(output) != tail:
        raise _invalid()
    return ParsedCaptureInvocation(command, output)
