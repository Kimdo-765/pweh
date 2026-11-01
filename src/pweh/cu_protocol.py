"""고정 CU Ultra 프로필의 순수 프레임·조회·NTAG21x 응답 검사.

공식 소스 pin의 wire 사실을 독립 구현한다. 포트·시간·파일 I/O와 RF 실행은 없으며
펌웨어 버전 응답은 자기 보고다. 512B는 이 제품의 상한이지 CU 전체 프로토콜의 상한이 아니다.

reader 프로필은 닫힌 두 행이다. 실제 장치 경로(live)는 ``LIVE``(v2.3.0) 하나만 쓰고,
원장·snapshot 검증기는 ``KNOWN``의 정확한 이름 조회 뒤 전체 값 일치를 요구한다.
v2.2.0 행은 기존 기록의 검증 전용이며 연결에 쓰지 않는다.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
import hashlib
import json
from types import MappingProxyType

from .errors import PwehError

MAX_DATA_BYTES = 512
MAX_FRAME_BYTES = 522
MAX_BUFFER_BYTES = 1044
READER_FIELDS = ("profile", "profile_sha256", "firmware_commit", "app_version", "git_version")

# v2.2.0 recipe: 이전 증분의 _RECIPE canonical JSON을 byte 그대로 고정한 literal이다.
# 기존 scan 사실·snapshot·원장 extra가 이 hash에 결속되어 있으므로 절대 고치지 않는다.
_LEGACY_V220_RECIPE = (
    '{"app_version":"2.2","atqa_msb":"0044","ats_length":0,"crc_append":true,"crc_check":true,'
    '"firmware_commit":"f349dbeeaa315776b272ae8fb851cc4042d55f07","git_version":"v2.2.0",'
    '"model":"chameleon-ultra","page_attribution_bytes":4,"probe_read_pages":[0,1],'
    '"profile":"cu-ntag21x-v2.2.0-v1","queries":[1000,1017,1033,1002],"raw_command":2010,'
    '"reader_mode":true,"rf_timeout_ms":100,"sak":"00","scan_command":2000,"total_pages":[45,135,'
    '231],"uid_length":7,"versions":["0004040201000f03","0004040201001103","0004040201001303"]}'
)
_LEGACY_V220_SHA256 = "d7e590dce5e5f9723cbff12aa0fcea46d5a9550e392a33cf7b0de5102dffd73c"
# v2.3.0 recipe: GET_VERSION(f4) 단독 activation 뒤 READ0(fc)부터 새 activation으로 읽는
# 전계 동작과 버전 거부 분류를 hash에 포함한다.
_V230_RECIPE = (
    '{"activations":{"probe":[["version"],["first_read","last_read"]],"read":[["version"],'
    '["first_read","read","last_read"]]},"app_version":"2.3","atqa_msb":"0044","ats_length":0,'
    '"crc_append":true,"crc_check":true,'
    '"firmware_commit":"4e1a5b267b9ed33559e0e2c9dad61d61eaf64ba1","git_version":"v2.3.0",'
    '"model":"chameleon-ultra","page_attribution_bytes":4,"probe_read_pages":[0,1],'
    '"profile":"cu-ntag21x-v2.3.0-v1","queries":[1000,1017,1033,1002],"raw_command":2010,'
    '"raw_options":{"first_read":"fc","last_read":"e4","read":"ec","version":"f4"},'
    '"reader_mode":true,"rf_timeout_ms":100,"sak":"00","scan_command":2000,"total_pages":[45,135,'
    '231],"uid_length":7,"version_refusals":["00-empty","00-other8","01-empty","03-empty"],'
    '"versions":["0004040201000f03","0004040201001103","0004040201001303"]}'
)
_V230_SHA256 = "95132f6c6e6609854cf32af0f1644eb409147cf21060ba97e7eb3dee4d783eb5"
# 고정 builder가 만들 수 있는 명령 ID 전체. 이 밖의 ID는 encoder 단계에서 거부한다.
_ALLOWED_COMMANDS = frozenset((1000, 1017, 1033, 1002, 2000, 2010))
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


def _canonical(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False)


@dataclass(frozen=True)
class CuReaderProfile:
    """닫힌 reader 프로필 한 행. recipe는 변경할 수 없는 canonical JSON 문자열로만 보관한다."""

    profile: str
    profile_sha256: str
    firmware_commit: str
    app_version: str
    app_wire: bytes
    git_version: str
    recipe: str

    def __post_init__(self) -> None:
        texts = ("profile", "profile_sha256", "firmware_commit", "app_version", "git_version", "recipe")
        valid = all(type(getattr(self, key)) is str for key in texts) and type(self.app_wire) is bytes
        decoded = None
        if valid:
            try:
                decoded = json.loads(self.recipe)
            except ValueError:
                valid = False
        if valid:
            valid = (type(decoded) is dict and _canonical(decoded) == self.recipe
                     and hashlib.sha256(self.recipe.encode("ascii")).hexdigest() == self.profile_sha256
                     and decoded.get("profile") == self.profile
                     and decoded.get("firmware_commit") == self.firmware_commit
                     and decoded.get("app_version") == self.app_version
                     and decoded.get("git_version") == self.git_version
                     and len(self.app_wire) == 2
                     and self.app_version == f"{self.app_wire[0]}.{self.app_wire[1]}")
        if not valid:
            _error()

    def reader(self) -> dict:
        """snapshot의 5개 reader 값. 호출마다 새 dict를 반환한다."""
        return {"profile": self.profile, "profile_sha256": self.profile_sha256,
                "firmware_commit": self.firmware_commit, "app_version": self.app_version,
                "git_version": self.git_version}


def _frozen_profile(recipe: str, sha256: str, app_wire: bytes) -> CuReaderProfile:
    """기록된 hash와 다른 recipe는 import 단계에서 명시적으로 거부한다."""
    if (type(recipe) is not str or type(sha256) is not str or not recipe.isascii()
            or hashlib.sha256(recipe.encode("ascii")).hexdigest() != sha256):
        raise RuntimeError("CU 고정 reader recipe가 기록된 hash와 다릅니다.")
    decoded = json.loads(recipe)
    if type(decoded) is not dict or _canonical(decoded) != recipe:
        raise RuntimeError("CU 고정 reader recipe가 canonical JSON이 아닙니다.")
    return CuReaderProfile(decoded["profile"], sha256, decoded["firmware_commit"],
                           decoded["app_version"], app_wire, decoded["git_version"], recipe)


LEGACY_V220 = _frozen_profile(_LEGACY_V220_RECIPE, _LEGACY_V220_SHA256, b"\x02\x02")
V230 = _frozen_profile(_V230_RECIPE, _V230_SHA256, b"\x02\x03")
LIVE = V230
KNOWN = MappingProxyType({LEGACY_V220.profile: LEGACY_V220, V230.profile: V230})
if (len(KNOWN) != 2 or LEGACY_V220.profile != "cu-ntag21x-v2.2.0-v1"
        or V230.profile != "cu-ntag21x-v2.3.0-v1" or KNOWN[LIVE.profile] is not LIVE):
    raise RuntimeError("CU reader 프로필 집합이 고정 두 행과 다릅니다.")


def known_reader_profile(name: object) -> CuReaderProfile | None:
    """정확한 str 이름 하나만 조회한다. 접두사·정규식·버전·hash로 추론하지 않는다.

    호출자는 반환한 행과 기록의 나머지 값 전체가 같은지 따로 확인해야 한다.
    """
    if type(name) is not str:
        return None
    return KNOWN.get(name)


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
    """허용한 고정 모델·live 버전·reader 주장만 보유한다."""

    model: str
    app_version: str
    git_version: str
    reader_mode: bool

    def __post_init__(self) -> None:
        if (type(self.model) is not str or self.model != "chameleon-ultra"
                or type(self.app_version) is not str or self.app_version != LIVE.app_version
                or type(self.git_version) is not str or self.git_version != LIVE.git_version
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
    if (not _u16(command) or command not in _ALLOWED_COMMANDS
            or type(data) is not bytes or len(data) > MAX_DATA_BYTES):
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
    """GET_VERSION 한 명령. f4(auto-select, keep=0) 단독 activation만 만든다.

    keep_field=True(fc)는 GET_VERSION 실패 뒤 HF field를 켜 둔 채 남기는 결함 recipe이므로 거부한다.
    인자는 호출부가 field 유지 의도를 명시하게 하려고 남기며 False만 허용한다.
    """
    if type(keep_field) is not bool or keep_field:
        _error()
    return _encode(2010, b"\xf4\x00\x64\x00\x08\x60")


def build_ntag_read(family: NtagFamily, page: int, *, last: bool, select: bool = False) -> bytes:
    """허용 계열의 시작 page 하나만 읽으며 RF CRC는 CU 옵션이 처리한다.

    page0은 새 activation의 첫 READ이므로 select(fc: auto-select+keep)가 필수이고,
    select는 page0이면서 마지막이 아닐 때만 허용한다. 나머지는 ec(유지)·e4(마지막) 두 가지다.
    """
    if (type(family) is not NtagFamily or type(page) is not int
            or not 0 <= page < family.pages_total or type(last) is not bool
            or type(select) is not bool or select != (page == 0) or (select and last)):
        _error()
    option = 0xfc if select else 0xe4 if last else 0xec
    return _encode(2010, bytes((option,)) + b"\x00\x64\x00\x10\x30" + bytes((page,)))


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
    """네 고정 조회의 순서·구조를 모두 확인한 뒤 live 프로필 주장과 정확히 대조한다.

    APP 2.3은 공식 release와 이후 dev build가 같으므로 GIT 문자열 전체 일치만 둘을 구별한다.
    """
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
    if app != LIVE.app_wire or version != LIVE.git_version:
        _error("cu_firmware_unsupported")
    if mode != b"\x01":
        _error("cu_reader_required")
    return CuDevice("chameleon-ultra", LIVE.app_version, LIVE.git_version, True)


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
    """keep=0 단독 GET_VERSION 응답을 닫힌 표로 분류한다.

    CRC가 제거된 정확8B의 세 NXP 값만 계속한다. 같은 UID7/ATQA/SAK의 다른 태그가
    보이는 잘 형성된 응답(HF 성공의 빈 payload=4bit NAK, 0x01 timeout, 0x03 CRC 오류,
    다른 8B version)은 nfc_family_unsupported이며 호출자는 이 태그에 READ를 보내지 않는다.
    그 밖의 명령·상태·길이 조합은 nfc_scan_invalid다.
    """
    if type(frame) is not CuFrame or frame.command != 2010:
        _error("nfc_scan_invalid")
    data = frame.data
    if frame.status == 0 and len(data) == 8:
        for family in NtagFamily:
            if data == family.mifare_version:
                return family
        _error("nfc_family_unsupported")
    if frame.status in (0x00, 0x01, 0x03) and not data:
        _error("nfc_family_unsupported")
    _error("nfc_scan_invalid")
