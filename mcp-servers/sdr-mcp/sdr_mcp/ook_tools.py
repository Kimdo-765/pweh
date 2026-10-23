"""등록 RAW 파일의 제한된 OOK 변환 입구와 원문 없는 SDK 검증."""

from __future__ import annotations

import re
import threading
import time

from mcp.server.mcpserver.utilities.func_metadata import FuncMetadata
from pydantic import StrictFloat, StrictInt, StrictStr, ValidationError
from pydantic_core import PydanticCustomError

from pweh.case import CASE_ID_RE
from pweh.errors import PwehError
from pweh.mcpkit import ANN_LOCAL_WRITE, run_blocking_cancellable, safe_tool

_ERRORS = {
    "rf_ook_input_invalid": "OOK 변환 입력이 허용된 형식이나 범위가 아닙니다.",
    "rf_ook_input_limit": "OOK 변환 입력이 고정 크기 한도를 넘었습니다.",
    "rf_ook_input_changed": "OOK 변환 입력의 등록 또는 파일 무결성이 변경되었습니다.",
    "rf_ook_not_convertible": "RAW 입력이 지원하는 완전한 OOK 변환 조건에 맞지 않습니다.",
    "rf_ook_failed": "OOK 변환을 완료하지 못했습니다.",
    "rf_ook_cleanup_incomplete": "OOK 변환 출력의 정리를 확인하지 못했습니다.",
    "cancelled": "OOK 변환이 취소되었습니다.",
    "time_limit": "OOK 변환의 시간 한도에 닿았습니다.",
    "authorization_required": "케이스의 소유 또는 서면 허가 확인이 필요합니다.",
    "not_found": "요청한 케이스 또는 등록 파일을 찾지 못했습니다.",
    "case_error": "OOK 변환의 케이스를 확인하지 못했습니다.",
    "config_error": "OOK 변환의 실행 설정을 확인하지 못했습니다.",
    "safety_denied": "현재 정책에서 OOK 변환을 허용하지 않습니다.",
}


class _OokMetadata(FuncMetadata):
    """추가 키·값·입력 위치를 SDK 검증 오류에 남기지 않는다."""

    def validate_arguments(self, arguments_to_validate: dict) -> dict:
        try:
            return super().validate_arguments(arguments_to_validate)
        except ValidationError:
            raise ValidationError.from_exception_data(
                "OokInput", [{"type": PydanticCustomError(
                    "rf_ook_input_invalid", _ERRORS["rf_ook_input_invalid"]),
                    "loc": (), "input": None}], hide_input=True,
            ) from None


def _configure_input(instance) -> None:
    """새 변환 도구만 strict 모델에 연결하고 설정 실패 시 등록을 중단한다."""
    try:
        tool = instance._tool_manager.get_tool("sdr_import_flipper_sub")
        if tool is None:
            raise RuntimeError
        metadata = tool.fn_metadata
        model = metadata.arg_model
        model.model_config.update(strict=True, extra="forbid", hide_input_in_errors=True)
        model.model_rebuild(force=True)
        tool.fn_metadata = _OokMetadata(
            arg_model=model, output_schema=metadata.output_schema,
            output_model=metadata.output_model, wrap_output=metadata.wrap_output,
        )
        tool.parameters = model.model_json_schema(by_alias=True)
        if tool.parameters.get("additionalProperties") is not False:
            raise RuntimeError
    except Exception:
        raise RuntimeError("OOK 도구의 비공개 입력 검증 설정을 완료하지 못했습니다.") from None


def _fixed_error(exc: Exception) -> PwehError:
    code = getattr(exc, "code", None)
    if type(code) is not str or code not in _ERRORS:
        code = "rf_ook_failed"
    return PwehError(_ERRORS[code], code=code)


def _arguments(case_id, artifact_id, max_seconds) -> None:
    if (type(case_id) is not str or len(case_id) > 80 or CASE_ID_RE.fullmatch(case_id) is None
            or type(artifact_id) is not str or re.fullmatch(r"A-[0-9]{4,8}", artifact_id) is None
            or type(max_seconds) not in (int, float) or not 0 < max_seconds <= 5):
        raise PwehError(_ERRORS["rf_ook_input_invalid"], code="rf_ook_input_invalid")


def register_ook_tools(server, namespace) -> None:
    """기존 SDR 도구·Runtime을 옮기지 않고 로컬 변환 하나를 등록한다."""

    @server.tool(description=(
        "케이스에 등록된 Flipper Sub-GHz RAW 파일 하나를 오프라인 OOK 텍스트로 변환한다. "
        "artifact_id는 같은 케이스 A-id이며 소유/허가 확인이 필요하다. forensics/·emu/ 입력은 받지 않는다. "
        "최대1MiB 입력을 기존 strict RAW 프로필로 먼저 검사하고 complete인 OOK270/OOK650만 허용한다. "
        "짝수 duration을 순서대로 최대1200쌍으로 옮기며 각 크기는1..2147483647이다. "
        "홀수·FSK·partial 입력은 거부하며 gap·packet 경계를 추론하지 않는다. "
        "max_seconds는0초 초과5초 이하(기본5), 케이스 선택·읽기·검사·변환은 같은 예산을 쓰며 "
        "최종 무결성 검증·등록은 별도 최대5초다. analysis/rf-ook-NNN/의 converted.ook와 manifest.json을 "
        "0444로 저장하고 manifest만 등록한다. 출력은 최대64KiB이며 예약은001..064다. "
        "반환에는 집계·선언·입출력 SHA와 실제 등록 영수증만 있고 원문 경로·주석·duration 배열은 없다. "
        "집계는 익명성 보장이 아니며 캡처 완전성·기기 연관성·전파 허가·decoder 호환을 검증하지 않는다. "
        "RF 수신·송신·재생·프로토콜 해독·외부 decoder 실행은 하지 않는다."
    ), annotations=ANN_LOCAL_WRITE)
    @safe_tool
    async def sdr_import_flipper_sub(
        case_id: StrictStr, artifact_id: StrictStr,
        max_seconds: StrictInt | StrictFloat = 5,
    ) -> dict:
        try:
            _arguments(case_id, artifact_id, max_seconds)
            cancelled = threading.Event()

            def work() -> dict:
                deadline = time.monotonic() + max_seconds
                try:
                    if cancelled.is_set():
                        raise PwehError(_ERRORS["cancelled"], code="cancelled")
                    from .ook_conversion import convert_registered_sub

                    case = namespace["rt"]().case(case_id, hardware=True)
                    return convert_registered_sub(
                        case, artifact_id, max_seconds=max_seconds,
                        deadline=deadline, cancel=cancelled.is_set,
                    )
                except Exception as exc:
                    raise _fixed_error(exc) from None

            return await run_blocking_cancellable(work, on_cancel=cancelled.set)
        except Exception as exc:
            raise _fixed_error(exc) from None

    namespace["sdr_import_flipper_sub"] = sdr_import_flipper_sub
    _configure_input(server)
