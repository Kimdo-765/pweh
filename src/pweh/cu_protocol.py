"""고정 CU Ultra 프로필의 순수 프레임·조회·NTAG21x 응답 검사.

공식 소스 pin의 wire 사실을 독립 구현한다. 포트·시간·파일 I/O와 RF 실행은 없으며
펌웨어 버전 응답은 자기 보고다. 512B는 이 제품의 상한이지 CU 전체 프로토콜의 상한이 아니다.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
import hashlib
import json

from .errors import PwehError

PROFILE = "cu-ntag21x-v2.2.0-v1"
FIRMWARE_COMMIT = "f349dbeeaa315776b272ae8fb851cc4042d55f07"
FIRMWARE_VERSION = "2.2"
FIRMWARE_GIT_VERSION = "v2.2.0"
MAX_DATA_BYTES = 512
MAX_FRAME_BYTES = 522
MAX_BUFFER_BYTES = 1044

_RECIPE = {
    "profile": PROFILE, "firmware_commit": FIRMWARE_COMMIT,
    "model": "chameleon-ultra", "app_version": FIRMWARE_VERSION,
    "git_version": FIRMWARE_GIT_VERSION, "reader_mode": True,
    "queries": [1000, 1017, 1033, 1002], "scan_command": 2000, "raw_command": 2010,
    "rf_timeout_ms": 100, "crc_append": True, "crc_check": True,
    "uid_length": 7, "atqa_msb": "0044", "sak": "00", "ats_length": 0,
    "versions": ["0004040201000f03", "0004040201001103", "0004040201001303"],
    "probe_read_pages": [0, 1], "page_attribution_bytes": 4, "total_pages": [45, 135, 231],
}
PROFILE_SHA256 = hashlib.sha256(json.dumps(
    _RECIPE, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False,
).encode("utf-8")).hexdigest()
_MESSAGES = {
    "cu_protocol_invalid": "CU 고정 프로토콜의 입력 또는 응답 구조가 올바르지 않습니다.",
    "cu_model_unsupported": "관찰한 모델이 CU Ultra 고정 프로필과 맞지 않습니다.",
    "cu_firmware_unsupported": "관찰한 펌웨어가 CU 고정 프로필과 맞지 않습니다.",
    "cu_reader_required": "CU의 현재 reader 모드를 확인하지 못했습니다.",
    "nfc_scan_invalid": "고정 NFC 조회 응답의 구조를 확인하지 못했습니다.",
    "nfc_family_unsupported": "관찰한 태그가 허용된 NTAG21x 계열과 맞지 않습니다.",
}


class CuProtocolError(PwehError):
    """장치 원문·식별값·callback 문구를 담지 않는 고정 오류."""


def _error(code: str = "cu_protocol_invalid") -> None:
    raise CuProtocolError(_MESSAGES[code], code=code) from None


def _u16(value: int) -> bool:
    return type(value) is int and 0 <= value <= 0xffff


@dataclass(frozen=True, repr=False)
class CuFrame:
    """원문 data는 내부에서만 소비하며 repr로 출력하지 않는다."""

    command: int
    status: int
    data: bytes

    def __post_init__(self) -> None:
        if (not _u16(self.command) or not _u16(self.status)
                or type(self.data) is not bytes or len(self.data) > MAX_DATA_BYTES):
            _error()


@dataclass(frozen=True)
class CuDevice:
    """허용한 고정 모델·버전·reader 주장만 보유한다."""

    model: str
    app_version: str
    git_version: str
    reader_mode: bool

    def __post_init__(self) -> None:
        if (type(self.model) is not str or self.model != "chameleon-ultra"
                or type(self.app_version) is not str or self.app_version != FIRMWARE_VERSION
                or type(self.git_version) is not str or self.git_version != FIRMWARE_GIT_VERSION
                or self.reader_mode is not True):
            _error()


@dataclass(frozen=True, repr=False)
class CuScanIdentity:
    """NTAG 후보의 내부 식별값. ATS 부재는 검사한 뒤 보관하지 않는다."""

    uid: bytes
    atqa_msb: bytes
    sak: bytes

    def __post_init__(self) -> None:
        if (type(self.uid) is not bytes or len(self.uid) != 7
                or type(self.atqa_msb) is not bytes or self.atqa_msb != b"\x00\x44"
                or type(self.sak) is not bytes or self.sak != b"\x00"):
            _error("nfc_scan_invalid")


class NtagFamily(Enum):
    """고정 세 계열만 허용하며 숫자·문자열을 암묵 변환하지 않는다."""

    NTAG213 = 213
    NTAG215 = 215
    NTAG216 = 216

    @property
    def family(self) -> str:
        return {213: "ntag213", 215: "ntag215", 216: "ntag216"}[self.value]

    @property
    def pages_total(self) -> int:
        return {213: 45, 215: 135, 216: 231}[self.value]

    @property
    def mifare_version(self) -> bytes:
        return bytes.fromhex({213: "0004040201000f03", 215: "0004040201001103",
                              216: "0004040201001303"}[self.value])


class CuQuery(Enum):
    """자료가 없는 다섯 고정 조회. 설정·쓰기·임의 RAW 명령은 없다."""

    APP_VERSION = 1000
    GIT_VERSION = 1017
    DEVICE_MODEL = 1033
    DEVICE_MODE = 1002
    SCAN_14A = 2000


def _encode(command: int, data: bytes) -> bytes:
    # 외부 serializer를 제공하지 않고 검증한 고정 builder에서만 사용한다.
    if not _u16(command) or type(data) is not bytes or len(data) > MAX_DATA_BYTES:
        _error()
    header = b"\x11\xef" + command.to_bytes(2, "big") + b"\x00\x00" + len(data).to_bytes(2, "big")
    framed = header + bytes((-sum(header) & 255,)) + data
    return framed + bytes((-sum(framed) & 255,))


def build_cu_query(query: CuQuery) -> bytes:
    """exact enum에 해당하는 빈 DATA 조회만 만든다."""
    if type(query) is not CuQuery:
        _error()
    return _encode(query.value, b"")


def build_ntag_version(*, keep_field: bool) -> bytes:
    """GET_VERSION 한 명령. keep_field는 호출자 내부의 종료 phase다."""
    if type(keep_field) is not bool:
        _error()
    return _encode(2010, bytes((0xfc if keep_field else 0xf4,)) + b"\x00\x64\x00\x08\x60")


def build_ntag_read(family: NtagFamily, page: int, *, last: bool) -> bytes:
    """허용 계열의 시작 page 하나만 읽으며 RF CRC는 CU 옵션이 처리한다."""
    if (type(family) is not NtagFamily or type(page) is not int
            or not 0 <= page < family.pages_total or type(last) is not bool):
        _error()
    return _encode(2010, bytes((0xe4 if last else 0xec,)) + b"\x00\x64\x00\x10\x30" + bytes((page,)))


class CuDecoder:
    """고정 상한의 순차 decoder. 손상 뒤 재동기화·reset은 없다."""

    def __init__(self) -> None:
        self._buffer = bytearray()
        self._terminal = False

    @property
    def buffered_bytes(self) -> int:
        return len(self._buffer)

    @property
    def terminal(self) -> bool:
        return self._terminal

    def abort(self) -> None:
        """owner 실패를 terminal로 고정하고 원문 조각을 버린다."""
        self._buffer.clear()
        self._terminal = True

    def eof(self) -> None:
        """빈 buffer도 연결 종료이며 성공 응답으로 취급하지 않는다."""
        self.abort()
        _error()

    def feed(self, data: bytes) -> tuple[CuFrame, ...]:
        """완전 frame 최대2개만 반환하며 오류 때 앞 frame도 부분 반환하지 않는다."""
        if (self._terminal or type(data) is not bytes
                or len(data) + len(self._buffer) > MAX_BUFFER_BYTES):
            self.abort()
            _error()
        self._buffer.extend(data)
        result: list[CuFrame] = []
        try:
            while self._buffer:
                buf = self._buffer
                if buf[0] != 0x11 or (len(buf) >= 2 and buf[1] != 0xef):
                    _error()
                if len(buf) < 9:
                    break
                if sum(buf[:9]) & 255:
                    _error()
                size = int.from_bytes(buf[6:8], "big")
                if size > MAX_DATA_BYTES:
                    _error()
                end = size + 10
                if len(buf) < end:
                    break
                if len(result) == 2 or sum(buf[:end]) & 255:
                    _error()
                result.append(CuFrame(int.from_bytes(buf[2:4], "big"),
                                      int.from_bytes(buf[4:6], "big"), bytes(buf[9:end - 1])))
                del buf[:end]
        except CuProtocolError:
            self.abort()
            raise
        return tuple(result)


def _response(frame: CuFrame, command: int, status: int, *, code: str) -> bytes:
    if type(frame) is not CuFrame or frame.command != command or frame.status != status:
        _error(code)
    return frame.data


def parse_cu_device(replies: tuple[CuFrame, ...]) -> CuDevice:
    """네 고정 조회의 순서·구조를 모두 확인한 뒤 프로필 주장을 대조한다."""
    if type(replies) is not tuple or len(replies) != 4:
        _error()
    payloads = tuple(_response(frame, command, 0x68, code="cu_protocol_invalid")
                     for frame, command in zip(replies, (1000, 1017, 1033, 1002)))
    app, git, model, mode = payloads
    if (len(app) != 2 or not 1 <= len(git) <= 64 or b"\x00" in git
            or len(model) != 1 or len(mode) != 1):
        _error()
    try:
        version = git.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        _error()
    if model != b"\x00":
        _error("cu_model_unsupported")
    if app != b"\x02\x02" or version != FIRMWARE_GIT_VERSION:
        _error("cu_firmware_unsupported")
    if mode != b"\x01":
        _error("cu_reader_required")
    return CuDevice("chameleon-ultra", FIRMWARE_VERSION, FIRMWARE_GIT_VERSION, True)


def parse_cu_scan(frame: CuFrame) -> CuScanIdentity:
    """한 완전 scan 레코드만 허용하며 ATQA를 비교용 MSB 순서로 바꾼다."""
    data = _response(frame, 2000, 0, code="nfc_scan_invalid")
    if not data or data[0] not in (4, 7, 10):
        _error("nfc_scan_invalid")
    uid_size = data[0]
    fixed_size = 1 + uid_size + 2 + 1 + 1
    if len(data) < fixed_size or len(data) != fixed_size + data[fixed_size - 1]:
        _error("nfc_scan_invalid")
    atqa, sak = data[1 + uid_size:3 + uid_size], data[3 + uid_size:4 + uid_size]
    if uid_size != 7 or atqa != b"\x44\x00" or sak != b"\x00" or data[fixed_size - 1] != 0:
        _error("nfc_family_unsupported")
    return CuScanIdentity(data[1:1 + uid_size], atqa[::-1], sak)


def parse_ntag_version(frame: CuFrame) -> NtagFamily:
    """CRC가 제거된 정확8B GET_VERSION을 세 고정 계열과 대조한다."""
    data = _response(frame, 2010, 0, code="nfc_scan_invalid")
    if len(data) != 8:
        _error("nfc_scan_invalid")
    for family in NtagFamily:
        if data == family.mifare_version:
            return family
    _error("nfc_family_unsupported")
