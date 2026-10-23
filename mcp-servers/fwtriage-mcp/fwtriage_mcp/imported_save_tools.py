"""가져온 세이브의 로컬 계획 전용 strict MCP 입구."""

from __future__ import annotations

import re
import threading
import time
from typing import Annotated, Literal

from mcp.server.mcpserver.utilities.func_metadata import FuncMetadata
from pydantic import BeforeValidator, ConfigDict, Field, StrictFloat, StrictInt, StrictStr, ValidationError
from pydantic_core import PydanticCustomError
from typing_extensions import TypedDict

from pweh.case import CASE_ID_RE
from pweh.errors import PwehError
from pweh.mcpkit import ANN_LOCAL_WRITE, run_blocking_cancellable, safe_tool

from . import saves

_MAX = 8 << 20
_TOOL = "fw_plan_imported_save"
_ERRORS = {
    "imported_save_input_invalid": "가져온 세이브 입력이 허용된 형식이나 범위가 아닙니다.",
    "imported_save_input_limit": "가져온 세이브 입력의 크기 또는 항목 한도를 넘었습니다.",
    "imported_save_input_changed": "가져온 세이브 입력 또는 출처가 변경되었습니다.",
    "imported_save_no_changes": "가져온 세이브 계획에 변경된 바이트가 없습니다.",
    "imported_save_failed": "가져온 세이브 계획을 완료하지 못했습니다.",
    "imported_save_cleanup_incomplete": "가져온 세이브 계획 출력의 정리를 확인하지 못했습니다.",
    "cancelled": "가져온 세이브 계획이 취소되었습니다.",
    "time_limit": "가져온 세이브 계획의 시간 한도에 닿았습니다.",
    "authorization_required": "케이스의 소유 또는 서면 허가 확인이 필요합니다.",
    "not_found": "요청한 케이스를 찾지 못했습니다.",
    "case_error": "가져온 세이브 계획의 케이스를 확인하지 못했습니다.",
    "config_error": "가져온 세이브 계획의 실행 설정을 확인하지 못했습니다.",
    "safety_denied": "현재 정책에서 가져온 세이브 계획을 허용하지 않습니다.",
}


def _invalid():
    return PwehError(_ERRORS["imported_save_input_invalid"], code="imported_save_input_invalid")


def _fixed_error(exc):
    code = getattr(exc, "code", None)
    if type(code) is not str or code not in _ERRORS:
        code = "imported_save_failed"
    return PwehError(_ERRORS[code], code=code)


def _edits(value):
    if type(value) is not list or not 1 <= len(value) <= 16:
        raise ValueError("imported_save_input_invalid")
    if any(type(row) is not dict or set(row) != {"offset", "encoding", "value"} for row in value):
        raise ValueError("imported_save_input_invalid")
    return value


def _checksum(value):
    if type(value) is not dict or set(value) != {"algorithm", "endian", "location", "range"}:
        raise ValueError("imported_save_input_invalid")
    return value


def _range(value):
    if type(value) is not list or len(value) != 2 or any(type(n) is not int for n in value):
        raise ValueError("imported_save_input_invalid")
    return value


Encoding = Literal["u8", "i8", "u16le", "u16be", "i16le", "i16be", "u32le", "u32be", "i32le", "i32be",
                   "bcd2le", "bcd2be", "bcd4le", "bcd4be"]
Algorithm = Literal["sum8", "negsum8", "notsum8", "xor8", "crc8", "crc8-maxim", "sum16", "sum16le", "sum16be",
                    "fletcher16", "crc16-ccitt-false", "crc16-xmodem", "crc16-kermit", "crc16-x25", "crc16-modbus",
                    "crc16-arc", "sum32", "sum32le", "sum32be", "adler32", "crc32", "crc32-jamcrc", "crc32-mpeg2", "crc32-bzip2"]
Offset = Annotated[StrictInt, Field(ge=0, lt=_MAX)]
RangeValue = Annotated[list[Annotated[StrictInt, Field(ge=0, le=_MAX)]], BeforeValidator(_range), Field(min_length=2, max_length=2)]
Seconds = Annotated[StrictInt | StrictFloat, Field(gt=0, le=30)]


class EditInput(TypedDict):
    __pydantic_config__ = ConfigDict(strict=True, extra="forbid", hide_input_in_errors=True)
    offset: Offset
    encoding: Encoding
    value: Annotated[StrictInt, Field(ge=-(1 << 31), le=(1 << 32) - 1)]


class ChecksumInput(TypedDict):
    __pydantic_config__ = ConfigDict(strict=True, extra="forbid", hide_input_in_errors=True)
    algorithm: Algorithm
    endian: Literal["le", "be"] | None
    location: Offset
    range: RangeValue


Edits = Annotated[list[EditInput], BeforeValidator(_edits), Field(min_length=1, max_length=16)]
Checksum = Annotated[ChecksumInput, BeforeValidator(_checksum)]


def _arguments(case_id, artifact_id, offset, length, edits, purpose, unlock_source, online_capable, checksum, max_seconds):
    """원 JSON 타입과 범위를 검사한 뒤 worker용 작은 사본을 만든다."""
    if (type(case_id) is not str or len(case_id) > 80 or CASE_ID_RE.fullmatch(case_id) is None
            or type(artifact_id) is not str or re.fullmatch(r"A-[0-9]{4,8}", artifact_id) is None
            or type(offset) is not int or type(length) is not int
            or not 0 <= offset < _MAX or not 1 <= length <= _MAX or offset + length > _MAX
            or type(purpose) is not str or purpose not in ("score", "progress", "in-device-unlock")
            or type(unlock_source) is not str or unlock_source not in ("in-device", "owned-tag")
            or type(online_capable) is not str or online_capable not in ("no", "unknown")
            or type(max_seconds) not in (int, float) or not 0 < max_seconds <= 30):
        raise _invalid()
    try:
        _edits(edits)
        copied, spans = [], []
        for row in edits:
            off, enc, value = row["offset"], row["encoding"], row["value"]
            if type(off) is not int or type(enc) is not str or enc not in saves.ENCODINGS or type(value) is not int:
                raise _invalid()
            width = saves.encoding_width(enc)
            saves.encode_value(value, enc)
            if not offset <= off < off + width <= offset + length:
                raise _invalid()
            if any(off < end and start < off + width for start, end in spans):
                raise _invalid()
            spans.append((off, off + width))
            copied.append({"offset": off, "encoding": enc, "value": value})
        cs = None
        if checksum is not None:
            _checksum(checksum)
            _range(checksum["range"])
            alg, endian, loc = checksum["algorithm"], checksum["endian"], checksum["location"]
            if type(alg) is not str or alg not in saves.CHECKSUM_ALGORITHMS or type(loc) is not int:
                raise _invalid()
            width = saves.CHECKSUM_ALGORITHMS[alg]["width"]
            if (width == 1 and endian is not None) or (width > 1 and (type(endian) is not str or endian not in ("le", "be"))):
                raise _invalid()
            start, end = checksum["range"]
            if not (offset <= start < end <= offset + length and offset <= loc < loc + width <= offset + length):
                raise _invalid()
            if loc < end and start < loc + width or any(loc < b and a < loc + width for a, b in spans):
                raise _invalid()
            cs = {"algorithm": alg, "endian": endian, "location": loc, "range": [start, end]}
        return copied, cs
    except (ValueError, TypeError, KeyError, OverflowError):
        raise _invalid() from None


class _ImportedMetadata(FuncMetadata):
    """새 도구의 배열·객체 원 타입을 보존하고 오류 위치의 원문을 버린다."""

    def validate_arguments(self, arguments_to_validate: dict) -> dict:
        try:
            return self.arg_model.model_validate(arguments_to_validate).model_dump_one_level()
        except ValidationError:
            raise ValidationError.from_exception_data(
                "ImportedSaveInput", [{"type": PydanticCustomError("imported_save_input_invalid", _ERRORS["imported_save_input_invalid"]),
                                       "loc": (), "input": None}], hide_input=True,
            ) from None


def _configure_input(server):
    try:
        tool = server._tool_manager.get_tool(_TOOL)
        old = tool.fn_metadata
        model = old.arg_model
        model.model_config.update(strict=True, extra="forbid", hide_input_in_errors=True)
        model.model_rebuild(force=True)
        tool.fn_metadata = _ImportedMetadata(arg_model=model, output_schema=old.output_schema,
                                             output_model=old.output_model, wrap_output=old.wrap_output)
        tool.parameters = model.model_json_schema(by_alias=True)
        if tool.parameters.get("additionalProperties") is not False:
            raise RuntimeError
    except Exception:
        raise RuntimeError("가져온 세이브 도구의 입력 검증 설정을 완료하지 못했습니다.") from None


def register_imported_save_tools(server, S) -> None:
    @server.tool(description=(
        "케이스에 가져온 일반 세이브 파일의 로컬 변경 계획을 만든다. artifact_id로 등록 파일 하나를 고르고 "
        "기존 imported-unattested 출처·같은 FD의 SHA와 크기를 확인한다. 입력은 1바이트~8MiB, 선택 offset/length와 "
        "편집·체크섬 좌표는 파일 기준 정수다. edits는 offset/encoding/value의1~16개 객체이며 정수·BCD 인코딩을 사용한다. "
        "checksum은 null 또는 algorithm/endian/location/range 객체로 원래 규칙을 재현한 뒤 다시 계산한다. "
        "purpose는 score/progress/in-device-unlock, unlock_source는 in-device/owned-tag, online_capable은 no/unknown만 허용한다. "
        "처리 예산 max_seconds는0초 초과30초 이하(기본30), 등록 직전 최종 무결성 검증은 별도 최대5초다. "
        "patches/imported-save-plan-NNN/의 planned.bin과 manifest.json을 만들고 manifest 하나만 아티팩트로 등록한다. "
        "의도한 편집 전후 정수값은 보고하며 원본 경로·바이트/hex는 반환하지 않는다. stage는 planned이며 "
        "실기 연결·독립 백업·쓰기 주소·write-ready·장치 쓰기·게임 수용은 검증하지 않는다. "
        "새 출처/증명·운영 patch-plan·쓰기 명령을 만들지 않는다."
    ), annotations=ANN_LOCAL_WRITE)
    @safe_tool
    async def fw_plan_imported_save(
        case_id: Annotated[StrictStr, Field(max_length=80, pattern=CASE_ID_RE.pattern)],
        artifact_id: Annotated[StrictStr, Field(pattern=r"^A-[0-9]{4,8}$", max_length=10)],
        offset: Offset, length: Annotated[StrictInt, Field(ge=1, le=_MAX)], edits: Edits,
        purpose: Literal["score", "progress", "in-device-unlock"],
        unlock_source: Literal["in-device", "owned-tag"], online_capable: Literal["no", "unknown"],
        checksum: Checksum | None = None, max_seconds: Seconds = 30,
    ) -> dict:
        cancelled = threading.Event()
        try:
            copied, cs = _arguments(case_id, artifact_id, offset, length, edits, purpose,
                                    unlock_source, online_capable, checksum, max_seconds)

            def work():
                deadline = time.monotonic() + max_seconds
                try:
                    if cancelled.is_set():
                        raise PwehError(_ERRORS["cancelled"], code="cancelled")
                    from .imported_save_plan import plan_imported_save
                    case = S.rt().case(case_id, hardware=True)
                    return plan_imported_save(S, case, artifact_id, offset=offset, length=length, edits=copied,
                        purpose=purpose, unlock_source=unlock_source, online_capable=online_capable,
                        checksum=cs, max_seconds=max_seconds, deadline=deadline, cancel=cancelled.is_set)
                except Exception as exc:
                    raise _fixed_error(exc) from None

            return await run_blocking_cancellable(work, on_cancel=cancelled.set)
        except Exception as exc:
            raise _fixed_error(exc) from None

    _configure_input(server)
