"""고정 CU Ultra 프로필의 순수 프레임·조회·NTAG21x 응답 검사.

공식 소스 pin의 wire 사실을 독립 구현한다. 포트·시간·파일 I/O와 RF 실행은 없으며
펌웨어 버전 응답은 자기 보고다. 512B는 이 제품의 상한이지 CU 전체 프로토콜의 상한이 아니다.

reader 프로필은 닫힌 두 행이다. 실제 장치 경로(live)는 ``LIVE``(v2.3.0) 하나만 쓰고,
원장·snapshot 검증기는 ``KNOWN``의 정확한 이름 조회 뒤 전체 값 일치를 요구한다.
v2.2.0 행은 기존 기록의 검증 전용이며 연결에 쓰지 않는다.

HF 식별 프로필 ``IDENTIFY``(``cu-hf14a-identify-v2.3.0-v1``)는 reader 프로필 집합 밖의 별도 행이다.
scan 기록·GET_VERSION 응답의 닫힌 분류표와 §6.2 정책을 recipe에 담아 hash로 고정하며
원장·snapshot 검증(``KNOWN``)에는 쓰지 않는다. 장치 상태 조회는 별도 enum ``CuStatusQuery``로
1025/1018/2200 세 getter만 만들며 ``CuQuery``의 다섯 조회는 바꾸지 않는다.

LF 식별 프로필 ``LF_IDENTIFY``(``cu-lf125-identify-v2.3.0-v1``)도 reader 프로필 집합 밖의 별도 행이다.
125 kHz 고정 scan 일곱 개(``CuLfScan``)의 순서·payload·성공 길이·§6.2 정책을 recipe에 담아 hash로 고정한다.
T55xx/EM4x05·쓰기·스니프·emulator 명령은 만들 수 없다. 근거는 docs/references/cu-lf-identify.md 에 행마다 적는다.
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
# HF 식별 recipe: mode→scan2000→(Type 2 후보만) f4 GET_VERSION 한 번의 명령과 닫힌 분류표·정책을 고정한다.
# 각 표의 근거는 docs/references/cu-hf-identify.md 에 행마다 적는다. READ·인증 명령은 없다.
_IDENTIFY_RECIPE = (
    '{"app_version":"2.3","authentication":false,"commands":[1002,2000,2010],"crc_append":true,'
    '"crc_check":true,"digest_domain":"pweh.cu-hf-identify/v1",'
    '"firmware_commit":"4e1a5b267b9ed33559e0e2c9dad61d61eaf64ba1","git_version":"v2.3.0",'
    '"iso14443_4_sak_bit":"20","model":"chameleon-ultra","page_reads":false,'
    '"policies":{"iso14443_4":"refused","mifare_classic_1k":"attestation_required",'
    '"mifare_classic_2k":"refused","mifare_classic_4k":"refused",'
    '"mifare_classic_mini":"attestation_required","mifare_classic_tnp3xxx":"attestation_required",'
    '"mifare_plus_sl2":"refused","multiple":"not_applicable","none":"not_applicable",'
    '"ntag213":"allowed","ntag215":"allowed","ntag216":"allowed","other":"not_applicable",'
    '"type2_other_version":"attestation_required","type2_version_unreadable":"attestation_required",'
    '"ultralight_ev1_mf0ul11":"attestation_required","ultralight_ev1_mf0ul21":"attestation_required",'
    '"ultralight_ev1_mf0ulh11":"attestation_required",'
    '"ultralight_ev1_mf0ulh21":"attestation_required",'
    '"ultralight_or_ultralight_c":"attestation_required"},"profile":"cu-hf14a-identify-v2.3.0-v1",'
    '"raw_command":2010,"raw_options":{"version":"f4"},"reader_mode":true,"rf_timeout_ms":100,'
    '"sak_classes":{"01":"mifare_classic_tnp3xxx","08":"mifare_classic_1k","09":"mifare_classic_mini",'
    '"10":"mifare_plus_sl2","11":"mifare_plus_sl2","18":"mifare_classic_4k","19":"mifare_classic_2k"},'
    '"scan_command":2000,"scan_statuses":{"01":"none","04":"multiple"},"type2":{"atqa_msb":"0044",'
    '"ats_length":0,"sak":"00","uid_length":7},'
    '"version_fallbacks":{"00-empty":"ultralight_or_ultralight_c","00-other8":"type2_other_version",'
    '"01-empty":"ultralight_or_ultralight_c","03-empty":"type2_version_unreadable"},'
    '"versions":{"0004030101000b03":"ultralight_ev1_mf0ul11",'
    '"0004030101000e03":"ultralight_ev1_mf0ul21","0004030201000b03":"ultralight_ev1_mf0ulh11",'
    '"0004030201000e03":"ultralight_ev1_mf0ulh21","0004040201000f03":"ntag213",'
    '"0004040201001103":"ntag215","0004040201001303":"ntag216"}}'
)
_IDENTIFY_SHA256 = "d420c720c19ab0f4923879f7d53917a82fb4775f8115e98360ea17f3cf27d90b"
# 고정 builder가 만들 수 있는 명령 ID 전체. 이 밖의 ID는 encoder 단계에서 거부한다.
# 1025 배터리·1018 활성 slot·2200 HF14A 설정은 상태 조회 전용 getter다(hook·RF 없음).
# 3000/3002/3010/3004/3014/3019/3021은 LF 식별 전용 125 kHz scan이다(reader mode hook만, 쓰기·인증 없음).
_ALLOWED_COMMANDS = frozenset((1000, 1017, 1033, 1002, 2000, 2010, 1025, 1018, 2200,
                               3000, 3002, 3010, 3004, 3014, 3019, 3021))
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

# HF 식별 프로필은 reader 프로필 집합에 넣지 않는다. 같은 live firmware 사실에만 결속한다.
IDENTIFY = _frozen_profile(_IDENTIFY_RECIPE, _IDENTIFY_SHA256, b"\x02\x03")
HF_POLICY_VALUES = ("allowed", "attestation_required", "refused", "not_applicable")


def _identify_tables(profile: CuReaderProfile) -> tuple:
    """recipe 하나에서 실행 표를 만들고 표끼리의 닫힌 관계를 import 단계에서 확인한다."""
    r = json.loads(profile.recipe)
    policies = r["policies"]
    families = frozenset(policies)
    scan = {int(key, 16): value for key, value in r["scan_statuses"].items()}
    saks = {int(key, 16): value for key, value in r["sak_classes"].items()}
    versions = {bytes.fromhex(key): value for key, value in r["versions"].items()}
    fallbacks = dict(r["version_fallbacks"])
    type2 = r["type2"]
    targets = set(scan.values()) | set(saks.values()) | set(versions.values()) | set(fallbacks.values())
    valid = (profile.profile == "cu-hf14a-identify-v2.3.0-v1" and profile.profile not in KNOWN
             and (profile.firmware_commit, profile.app_version, profile.git_version, profile.app_wire)
             == (LIVE.firmware_commit, LIVE.app_version, LIVE.git_version, LIVE.app_wire)
             and r["model"] == "chameleon-ultra" and r["reader_mode"] is True
             and r["commands"] == [1002, 2000, 2010] and r["scan_command"] == 2000
             and r["raw_command"] == 2010 and r["raw_options"] == {"version": "f4"}
             and r["page_reads"] is False and r["authentication"] is False
             and r["iso14443_4_sak_bit"] == "20" and set(scan) == {0x01, 0x04}
             and type2 == {"uid_length": 7, "atqa_msb": "0044", "sak": "00", "ats_length": 0}
             and all(len(key) == 8 for key in versions) and not any(sak & 0x20 for sak in saks)
             and set(fallbacks) == {"00-empty", "00-other8", "01-empty", "03-empty"}
             and targets | {"iso14443_4", "other"} == families
             and set(policies.values()) <= set(HF_POLICY_VALUES)
             and r["digest_domain"] == "pweh.cu-hf-identify/v1")
    if not valid:
        raise RuntimeError("CU HF 식별 recipe의 분류표가 닫힌 관계와 다릅니다.")
    return (MappingProxyType(dict(policies)), MappingProxyType(scan), MappingProxyType(saks),
            MappingProxyType(versions), MappingProxyType(fallbacks), r["digest_domain"].encode("ascii"))


(HF_POLICIES, _HF_SCAN_STATUSES, _HF_SAK_CLASSES, _HF_VERSIONS, _HF_VERSION_FALLBACKS,
 HF_DIGEST_DOMAIN) = _identify_tables(IDENTIFY)
HF_FAMILIES = frozenset(HF_POLICIES)
# version 바이트 없이 끝나는 GET_VERSION fallback 계열. 정확8B 응답의 계열과 겹치지 않는다.
_HF_EMPTY_FAMILIES = frozenset(value for key, value in _HF_VERSION_FALLBACKS.items() if key.endswith("-empty"))
if _HF_EMPTY_FAMILIES & (set(_HF_VERSIONS.values()) | {_HF_VERSION_FALLBACKS["00-other8"]}):
    raise RuntimeError("CU HF 식별 recipe의 빈 응답 계열이 version 계열과 겹칩니다.")
# scan 단계의 닫힌 분류. type2만 GET_VERSION 단계로 넘어가며 최종 family가 아니다.
HF_SCAN_CLASSES = frozenset(set(_HF_SCAN_STATUSES.values()) | set(_HF_SAK_CLASSES.values())
                            | {"type2", "iso14443_4", "other"})


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


@dataclass(frozen=True, repr=False)
class CuHfScan:
    """HF scan 한 응답의 닫힌 분류. 원시 식별값은 내부 지문 계산에만 쓰고 repr로 내보내지 않는다.

    none·multiple은 레코드가 없으므로 식별값이 모두 None이다.
    """

    scan_class: str
    uid: bytes | None
    atqa_msb: bytes | None
    sak: int | None
    ats_length: int | None

    def __post_init__(self) -> None:
        empty = self.scan_class in ("none", "multiple")
        valid = type(self.scan_class) is str and self.scan_class in HF_SCAN_CLASSES
        if valid and empty:
            valid = self.uid is None and self.atqa_msb is None and self.sak is None and self.ats_length is None
        elif valid:
            valid = (type(self.uid) is bytes and len(self.uid) in (4, 7, 10)
                     and type(self.atqa_msb) is bytes and len(self.atqa_msb) == 2
                     and type(self.sak) is int and 0 <= self.sak <= 0xff
                     and type(self.ats_length) is int and 0 <= self.ats_length <= 0xff)
        if not valid:
            _error("nfc_scan_invalid")


@dataclass(frozen=True, repr=False)
class CuHfVersion:
    """Type 2 후보의 GET_VERSION 분류. version은 정확8B 응답일 때만 보관한다."""

    family: str
    version: bytes | None

    def __post_init__(self) -> None:
        valid = (type(self.family) is str and self.family in HF_FAMILIES
                 and (self.version is None or (type(self.version) is bytes and len(self.version) == 8)))
        if valid:
            if self.version is None:
                # 빈 payload fallback(4bit NAK·timeout·CRC 오류)의 계열만 version 없이 만들 수 있다.
                valid = self.family in _HF_EMPTY_FAMILIES
            else:
                valid = self.family == _HF_VERSIONS.get(self.version, _HF_VERSION_FALLBACKS["00-other8"])
        if not valid:
            _error("nfc_scan_invalid")


def classify_cu_scan(frame: CuFrame) -> CuHfScan:
    """2000 응답 하나를 닫힌 scan 분류표로 나눈다. 판정 순서는 recipe와 같다.

    status0x01·0x04의 빈 payload는 각각 none(깨끗한 ATQA 없음)·multiple(firmware 충돌 상태)이다.
    서로 다른 ATQA의 카드 여러 장도 firmware에서 0x01이 되므로 none은 "카드 없음"의 증명이 아니다.
    status0x00은 레코드 정확 하나만 받는다. SAK bit0x20 → iso14443_4, 정확 SAK 다섯 값 →
    Classic 계열, 정확 SAK 0x10/0x11 → mifare_plus_sl2, UID7·ATQA0044·SAK00·ATS0 → type2,
    그 밖의 잘 형성된 레코드 → other.
    ATQA는 Type 2 문을 제외하고 계열 판정에 쓰지 않는다. 다른 상태·길이는 nfc_scan_invalid다.
    """
    if type(frame) is not CuFrame or frame.command != 2000:
        _error("nfc_scan_invalid")
    data = frame.data
    if frame.status in _HF_SCAN_STATUSES:
        if data:
            _error("nfc_scan_invalid")
        return CuHfScan(_HF_SCAN_STATUSES[frame.status], None, None, None, None)
    if frame.status != 0 or not data or data[0] not in (4, 7, 10):
        _error("nfc_scan_invalid")
    uid_size = data[0]
    fixed_size = 1 + uid_size + 2 + 1 + 1
    if len(data) < fixed_size or len(data) != fixed_size + data[fixed_size - 1]:
        _error("nfc_scan_invalid")
    uid = data[1:1 + uid_size]
    atqa = data[1 + uid_size:3 + uid_size][::-1]
    sak = data[3 + uid_size]
    ats_length = data[fixed_size - 1]
    if sak & 0x20:
        scan_class = "iso14443_4"
    elif sak in _HF_SAK_CLASSES:
        scan_class = _HF_SAK_CLASSES[sak]
    elif (uid_size, atqa, sak, ats_length) == (7, b"\x00\x44", 0x00, 0):
        scan_class = "type2"
    else:
        scan_class = "other"
    return CuHfScan(scan_class, uid, atqa, sak, ats_length)


def classify_type2_version(frame: CuFrame) -> CuHfVersion:
    """keep=0 단독 GET_VERSION 응답을 닫힌 표로 분류한다. READ로 계열을 더 나누지 않는다.

    status0x00 정확8B는 NXP 정확 값이면 그 계열, 아니면 type2_other_version이다.
    status0x00(3B 미만 응답=4bit NAK)·0x01(timeout)의 빈 payload는 GET_VERSION에 답하지 않은
    ultralight_or_ultralight_c다. status0x03은 3B 이상 응답이 왔지만 CRC가 틀린 경우라
    (원조 UL·UL C는 GET_VERSION에 3B 이상 답하지 않는다) 계열을 정하지 않은 type2_version_unreadable이다.
    그 밖의 명령·상태·길이 조합은 nfc_scan_invalid다.
    """
    if type(frame) is not CuFrame or frame.command != 2010:
        _error("nfc_scan_invalid")
    data = frame.data
    if frame.status == 0 and len(data) == 8:
        return CuHfVersion(_HF_VERSIONS.get(data, _HF_VERSION_FALLBACKS["00-other8"]), data)
    if frame.status in (0x00, 0x01, 0x03) and not data:
        return CuHfVersion(_HF_VERSION_FALLBACKS[f"{frame.status:02x}-empty"], None)
    _error("nfc_scan_invalid")


class CuStatusQuery(Enum):
    """장치 상태의 고정 getter 세 개. CuQuery와 분리해 reader recipe를 바꾸지 않는다."""

    BATTERY_INFO = 1025
    ACTIVE_SLOT = 1018
    HF14A_CONFIG = 2200


STATUS_QUERIES = (CuStatusQuery.BATTERY_INFO, CuStatusQuery.ACTIVE_SLOT, CuStatusQuery.HF14A_CONFIG)


def build_cu_status_query(query: CuStatusQuery) -> bytes:
    """exact enum에 해당하는 빈 DATA getter만 만든다."""
    if type(query) is not CuStatusQuery:
        _error()
    return _encode(query.value, b"")


@dataclass(frozen=True)
class CuDeviceStatus:
    """세 getter의 검증한 값. 배터리 percent는 전압 곡선 추정이다."""

    battery_mv: int
    battery_percent: int
    active_slot: int
    hf14a_config_default: bool

    def __post_init__(self) -> None:
        if (type(self.battery_mv) is not int or not 0 <= self.battery_mv <= 0xffff
                or type(self.battery_percent) is not int or not 0 <= self.battery_percent <= 100
                or type(self.active_slot) is not int or not 0 <= self.active_slot <= 7
                or type(self.hf14a_config_default) is not bool):
            _error()


def parse_cu_status(replies: tuple[CuFrame, ...]) -> CuDeviceStatus:
    """1025·1018·2200 순서의 일반 성공 응답 셋을 정확 길이로 검사한다.

    1025는 mV u16 BE와 percent u8, 1018은 0부터 센 slot 하나(0..7), 2200은 forcebcc·forcecl2·
    forcecl3·forcerats 네 값(각 0..2)이다. 네 값이 모두0일 때만 기본 설정이다.
    """
    if type(replies) is not tuple or len(replies) != 3:
        _error()
    battery, slot, config = tuple(_response(frame, query.value, 0x68, code="cu_protocol_invalid")
                                  for frame, query in zip(replies, STATUS_QUERIES))
    if (len(battery) != 3 or len(slot) != 1 or len(config) != 4
            or battery[2] > 100 or slot[0] > 7 or any(value > 2 for value in config)):
        _error()
    return CuDeviceStatus(int.from_bytes(battery[:2], "big"), battery[2], slot[0], config == b"\x00" * 4)


# LF 125 kHz 식별 recipe: mode1002 뒤 고정 순서 scan 일곱 개를 첫 감지(0x40)에서 멈추며 보낸다.
# 명령·payload·성공 길이·EM410x tag_type 표·§6.2 정책을 고정하며 각 값의 근거(firmware 줄)는
# docs/references/cu-lf-identify.md 에 행마다 적는다. T55xx·EM4x05·쓰기·스니프·emulator 명령은 없다.
# "id_derived_outputs":"none" — 125 kHz 출입 ID(24–40비트)는 케이스 솔트 지문도 전수 대입으로 되돌릴 수 있으므로
# 원시 ID와 그 지문·조각 같은 ID 파생 값을 결과·로그·예외·승인 action에 하나도 내지 않는다(설계 §6.2 거부(ID 마스킹)).
# 계열·EM410x 변형마다 고정인 길이는 개별 ID에서 나온 값이 아니다.
_LF_IDENTIFY_RECIPE = (
    '{"app_version":"2.3","authentication":false,"commands":[1002,3000,3002,3010,3004,3014,3019,'
    '3021],"em410x_lengths":{"101":7,"102":7,"103":7,'
    '"104":15},"em410x_variants":{"101":"em410x_16","102":"em410x_32","103":"em410x_64",'
    '"104":"em410x_electra"},"firmware_commit":"4e1a5b267b9ed33559e0e2c9dad61d61eaf64ba1",'
    '"git_version":"v2.3.0","hid_format_returned":false,"id_derived_outputs":"none","id_returned":false,'
    '"lf_field_off_by_firmware":true,"model":"chameleon-ultra","policies":{"em410x":"refused",'
    '"hidprox":"refused","ioprox":"refused","jablotron":"refused","none":"not_applicable",'
    '"pac":"refused","pyramid":"refused","viking":"refused"},"profile":"cu-lf125-identify-v2.3.0-v1",'
    '"reader_mode":true,"scans":[{"command":3000,"family":"em410x","found_length":null,'
    '"name":"em410x_scan","payload":""},{"command":3002,"family":"hidprox","found_length":16,'
    '"name":"hidprox_scan","payload":"00"},{"command":3010,"family":"ioprox","found_length":16,'
    '"name":"ioprox_scan","payload":"00"},{"command":3004,"family":"viking","found_length":4,'
    '"name":"viking_scan","payload":""},{"command":3014,"family":"pac","found_length":8,'
    '"name":"pac_scan","payload":""},{"command":3019,"family":"jablotron","found_length":5,'
    '"name":"jablotron_scan","payload":""},{"command":3021,"family":"pyramid","found_length":16,'
    '"name":"pyramid_scan","payload":""}],"statuses":{"found":"40","mode_error":"66",'
    '"not_found":"41"},"stop_at_first_found":true,"tag_writes":false}'
)
_LF_IDENTIFY_SHA256 = "fefb6e77a90e0c5ebf255f378619313db848a26460efffdd19a86f599f582535"
LF_IDENTIFY = _frozen_profile(_LF_IDENTIFY_RECIPE, _LF_IDENTIFY_SHA256, b"\x02\x03")
LF_POLICY_VALUES = ("refused", "not_applicable")


class CuLfScan(Enum):
    """고정 LF scan 일곱 개. 값은 firmware data_cmd.h 의 명령 ID이고 정의 순서가 송신 순서다(숫자 순서가 아니다)."""

    EM410X = 3000
    HIDPROX = 3002
    IOPROX = 3010
    VIKING = 3004
    PAC = 3014
    JABLOTRON = 3019
    PYRAMID = 3021


@dataclass(frozen=True)
class CuLfScanSpec:
    """recipe 한 행의 실행 값. payload는 고정 바이트이고 found_length None은 EM410x tag_type 표를 따른다."""

    name: str
    payload: bytes
    family: str
    found_length: int | None


def _lf_tables(profile: CuReaderProfile) -> tuple:
    """recipe 하나에서 LF 실행 표를 만들고 표끼리의 닫힌 관계를 import 단계에서 확인한다."""
    r = json.loads(profile.recipe)
    order = tuple(CuLfScan)
    rows = r["scans"]
    policies = r["policies"]
    variants = {int(key): value for key, value in r["em410x_variants"].items()}
    lengths = {int(key): value for key, value in r["em410x_lengths"].items()}
    specs = {}
    valid = (type(rows) is list and len(rows) == len(order) == 7
             and all(type(row) is dict and set(row) == {"name", "command", "payload", "family", "found_length"}
                     for row in rows))
    if valid:
        specs = {scan: CuLfScanSpec(row["name"], bytes.fromhex(row["payload"]), row["family"], row["found_length"])
                 for scan, row in zip(order, rows)}
        families = [spec.family for spec in specs.values()]
        valid = (profile.profile == "cu-lf125-identify-v2.3.0-v1" and profile.profile not in KNOWN
                 and profile.profile != IDENTIFY.profile
                 and (profile.firmware_commit, profile.app_version, profile.git_version, profile.app_wire)
                 == (LIVE.firmware_commit, LIVE.app_version, LIVE.git_version, LIVE.app_wire)
                 and r["model"] == "chameleon-ultra" and r["reader_mode"] is True
                 and [row["command"] for row in rows] == [scan.value for scan in order]
                 and r["commands"] == [CuQuery.DEVICE_MODE.value] + [scan.value for scan in order]
                 and r["statuses"] == {"found": "40", "not_found": "41", "mode_error": "66"}
                 and r["stop_at_first_found"] is True and r["lf_field_off_by_firmware"] is True
                 and r["id_returned"] is False and r["hid_format_returned"] is False
                 and r["authentication"] is False and r["tag_writes"] is False
                 and len(set(families)) == 7 and "none" not in families
                 and len({spec.name for spec in specs.values()}) == 7
                 and all(spec.payload in (b"", b"\x00") for spec in specs.values())
                 and specs[CuLfScan.EM410X].found_length is None
                 and all(type(spec.found_length) is int and 1 <= spec.found_length <= 16
                         for scan, spec in specs.items() if scan is not CuLfScan.EM410X)
                 and set(variants) == set(lengths) == {101, 102, 103, 104}
                 and lengths == {101: 7, 102: 7, 103: 7, 104: 15}
                 and len(set(variants.values())) == 4
                 and all(value.startswith("em410x_") for value in variants.values())
                 and set(policies) == set(families) | {"none"}
                 and all(policies[family] == "refused" for family in families)
                 and policies["none"] == "not_applicable"
                 and set(policies.values()) <= set(LF_POLICY_VALUES)
                 and r.get("id_derived_outputs") == "none" and "digest_domain" not in r)
    if not valid:
        raise RuntimeError("CU LF 식별 recipe의 분류표가 닫힌 관계와 다릅니다.")
    return (MappingProxyType(specs), MappingProxyType(dict(policies)), MappingProxyType(variants),
            MappingProxyType(lengths))


LF_SCAN_SPECS, LF_POLICIES, _EM410X_VARIANTS, _EM410X_LENGTHS = _lf_tables(LF_IDENTIFY)
LF_SCAN_ORDER = tuple(CuLfScan)
LF_FAMILIES = frozenset(LF_POLICIES)
LF_VARIANTS = frozenset(_EM410X_VARIANTS.values())
LF_SCAN_NAMES = MappingProxyType({scan: spec.name for scan, spec in LF_SCAN_SPECS.items()})
# EM410x 변형별 ID 길이(tag_type 2B를 뺀 값). 응답 길이 검사에만 쓰며 ID 파생 값은 만들지 않는다.
_EM410X_ID_LENGTHS = MappingProxyType({_EM410X_VARIANTS[key]: value - 2 for key, value in _EM410X_LENGTHS.items()})
_LF_FOUND, _LF_NOT_FOUND, _LF_MODE_ERROR = 0x40, 0x41, 0x66


def build_lf_scan(scan: CuLfScan) -> bytes:
    """exact enum에 해당하는 고정 LF scan 한 frame만 만든다. 3002·3010은 1B 0x00, 나머지는 빈 DATA다."""
    if type(scan) is not CuLfScan:
        _error()
    return _encode(scan.value, LF_SCAN_SPECS[scan].payload)


@dataclass(frozen=True, repr=False)
class CuLfReply:
    """LF scan 한 응답의 닫힌 분류. 원시 ID는 계열별 정확 길이 검사에만 메모리에 잠시 두며
    공개 투영·지문·로그·repr로 내보내지 않는다.

    not found이면 family·variant·ID가 모두 None이다. variant는 EM410x tag_type에서만 정한다.
    """

    scan: CuLfScan
    found: bool
    family: str | None
    variant: str | None
    id_bytes: bytes | None

    def __post_init__(self) -> None:
        valid = type(self.scan) is CuLfScan and type(self.found) is bool
        if valid and not self.found:
            valid = self.family is None and self.variant is None and self.id_bytes is None
        elif valid:
            spec = LF_SCAN_SPECS[self.scan]
            valid = (type(self.family) is str and self.family == spec.family and type(self.id_bytes) is bytes)
            if valid and self.scan is CuLfScan.EM410X:
                valid = (type(self.variant) is str and self.variant in _EM410X_ID_LENGTHS
                         and len(self.id_bytes) == _EM410X_ID_LENGTHS[self.variant])
            elif valid:
                valid = self.variant is None and len(self.id_bytes) == spec.found_length
        if not valid:
            _error("nfc_scan_invalid")


def classify_lf_scan(scan: CuLfScan, frame: CuFrame) -> CuLfReply:
    """보낸 scan의 응답 하나를 닫힌 표로 나눈다.

    0x41 빈 payload → 미감지(다음 scan으로 계속). 0x66 빈 payload → reader mode 아님(cu_reader_required).
    0x40은 정확한 성공 길이만 받는다. EM410x는 tag_type 101–104와 그 tag_type의 길이(7 또는 Electra 15)가
    모두 맞아야 한다. 그 밖의 명령·상태·길이 조합은 nfc_scan_invalid다.
    """
    if type(scan) is not CuLfScan or type(frame) is not CuFrame or frame.command != scan.value:
        _error("nfc_scan_invalid")
    data = frame.data
    if frame.status == _LF_MODE_ERROR and not data:
        _error("cu_reader_required")
    if frame.status == _LF_NOT_FOUND and not data:
        return CuLfReply(scan, False, None, None, None)
    if frame.status != _LF_FOUND:
        _error("nfc_scan_invalid")
    spec = LF_SCAN_SPECS[scan]
    if scan is CuLfScan.EM410X:
        tag_type = int.from_bytes(data[:2], "big") if len(data) >= 2 else None
        if tag_type not in _EM410X_VARIANTS or len(data) != _EM410X_LENGTHS[tag_type]:
            _error("nfc_scan_invalid")
        return CuLfReply(scan, True, spec.family, _EM410X_VARIANTS[tag_type], data[2:])
    if len(data) != spec.found_length:
        _error("nfc_scan_invalid")
    return CuLfReply(scan, True, spec.family, None, data)
