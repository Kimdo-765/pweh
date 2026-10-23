"""sdr-mcp: 케이스 등록 RAW 파일의 제한된 오프라인 검사 입구."""

from __future__ import annotations

import re
import threading
import time
from typing import Literal

from mcp.server.mcpserver.utilities.func_metadata import FuncMetadata
from pydantic import StrictFloat, StrictInt, StrictStr, ValidationError
from pydantic_core import PydanticCustomError

from pweh.case import CASE_ID_RE
from pweh.errors import PwehError
from pweh.mcpkit import ANN_LOCAL_WRITE, create_server, run_blocking_cancellable, safe_tool
from pweh.rf_formats import PROFILE
from pweh.runtime import Runtime, get_runtime

SERVER_NAME = "sdr-mcp"
_ERRORS = {
    "rf_raw_input_invalid": "RAW 분석 입력이 허용된 형식이나 범위가 아닙니다.",
    "rf_raw_input_limit": "RAW 분석 입력이 고정 크기 한도를 넘었습니다.",
    "rf_raw_input_changed": "RAW 분석 입력의 등록 또는 파일 무결성이 변경되었습니다.",
    "rf_raw_failed": "RAW 분석을 완료하지 못했습니다.",
    "rf_raw_cleanup_incomplete": "RAW 분석 출력의 정리를 확인하지 못했습니다.",
    "cancelled": "RAW 분석이 취소되었습니다.",
    "time_limit": "RAW 분석의 시간 한도에 닿았습니다.",
    "authorization_required": "케이스의 소유 또는 서면 허가 확인이 필요합니다.",
    "not_found": "요청한 케이스 또는 등록 파일을 찾지 못했습니다.",
    "case_error": "RAW 분석의 케이스를 확인하지 못했습니다.",
    "config_error": "RAW 분석의 실행 설정을 확인하지 못했습니다.",
    "safety_denied": "현재 정책에서 RAW 분석을 허용하지 않습니다.",
}


class _RawMetadata(FuncMetadata):
    """이 도구의 SDK 오류에서 임의 추가 키·값·원문 예외를 제거한다."""

    def validate_arguments(self, arguments_to_validate: dict) -> dict:
        try:
            # scalar JSON 문자열의 SDK 기본 동작은 유지한다.
            return super().validate_arguments(arguments_to_validate)
        except ValidationError:
            raise ValidationError.from_exception_data(
                "RAWInput", [{"type": PydanticCustomError(
                    "rf_raw_input_invalid", _ERRORS["rf_raw_input_invalid"]),
                    "loc": (), "input": None}], hide_input=True,
            ) from None


def _configure_input(instance) -> None:
    """비공개 검증 설정 실패는 등록 실패로 처리하며 기본 모델로 되돌리지 않는다."""
    try:
        tool = instance._tool_manager.get_tool("sdr_analyze")
        if tool is None:
            raise RuntimeError
        metadata = tool.fn_metadata
        model = metadata.arg_model
        model.model_config.update(strict=True, extra="forbid", hide_input_in_errors=True)
        model.model_rebuild(force=True)
        tool.fn_metadata = _RawMetadata(
            arg_model=model, output_schema=metadata.output_schema,
            output_model=metadata.output_model, wrap_output=metadata.wrap_output,
        )
        tool.parameters = model.model_json_schema(by_alias=True)
        if tool.parameters.get("additionalProperties") is not False:
            raise RuntimeError
    except Exception:
        raise RuntimeError("RAW 도구의 비공개 입력 검증 설정을 완료하지 못했습니다.") from None


def rt() -> Runtime:
    return get_runtime(SERVER_NAME)


def _fixed_error(exc: Exception) -> PwehError:
    code = getattr(exc, "code", None)
    if type(code) is not str or code not in _ERRORS:
        code = "rf_raw_failed"
    return PwehError(_ERRORS[code], code=code)


def _arguments(case_id, artifact_id, profile, max_seconds) -> None:
    if (type(case_id) is not str or len(case_id) > 80 or CASE_ID_RE.fullmatch(case_id) is None
            or type(artifact_id) is not str or re.fullmatch(r"A-[0-9]{4,8}", artifact_id) is None
            or type(profile) is not str or profile != PROFILE
            or type(max_seconds) not in (int, float) or not 0 < max_seconds <= 5):
        # 범위 비교가 NaN/Inf·거대한 int도 float 변환 없이 거부한다.
        raise PwehError(_ERRORS["rf_raw_input_invalid"], code="rf_raw_input_invalid")


server = create_server(
    SERVER_NAME, title="PWEH 오프라인 RAW 분석",
    instructions=(
        "허가된 케이스에 등록된 파일 하나를 명시 RAW profile로 오프라인 검사한다. "
        "case_import_file의 artifact_id → sdr_analyze → flipper-rf-analysis의 rf-analysis 요약 순서다. "
        "입력은 최대1 MiB, 작업 최대5초와 결과 생성 뒤 최종 저장 최대5초의 협력 예산이다. "
        "선언·수용 줄 통계·입력 SHA만 기록하며 원시 pulse/주석을 반환하지 않는다. "
        "complete는 지원 파일 문법의 완료다. RF 수신·송신·재생·프로토콜 해독이나 "
        "실제 캡처·기기·전파 허가를 검증하지 않는다. 장치·포트·외부 프로세스를 실행하지 않는다."
    ),
)


@server.tool(description=(
    "케이스에 등록된 일반 파일 하나를 오프라인 RAW 프로필로 검사한다. "
    "artifact_id는 같은 케이스 A-id이며 profile='flipper-subghz-raw-v1-strict'를 반드시 지정한다. "
    "소유/허가 확인이 필요하며 forensics/·emu/ 입력은 받지 않는다. 최대1 MiB, "
    "max_seconds는0초 초과5초 이하(기본5)이며 입력 선택·읽기·SHA·검사가 같은 예산을 사용한다. "
    "결과 생성 뒤 최종 무결성 검증·저장은 별도 최대5초의 협력 예산이다. "
    "complete/partial/malformed/unsupported와 수용한 완전한 줄의 집계·선언·입력 SHA를 반환하고 "
    "analysis/rf-raw-NNN.json을0444로 저장·등록한다. 원문 경로·pulse·주석·키는 반환하지 않는다. "
    "complete는 파일 문법 범위의 완료이며 실제 캡처 완전성·기기 연관성·전파 허가의 확인이 아니다. "
    "집계는 익명성 보장이 아니며 RF 수신/송신/재생·외부 decoder 실행은 하지 않는다."
), annotations=ANN_LOCAL_WRITE)
@safe_tool
async def sdr_analyze(
    case_id: StrictStr, artifact_id: StrictStr,
    profile: Literal["flipper-subghz-raw-v1-strict"],
    max_seconds: StrictInt | StrictFloat = 5,
) -> dict:
    cancelled = threading.Event()
    try:
        _arguments(case_id, artifact_id, profile, max_seconds)

        def work() -> dict:
            try:
                deadline = time.monotonic() + max_seconds
                if cancelled.is_set():
                    raise PwehError(_ERRORS["cancelled"], code="cancelled")
                from .raw_analysis import analyze_registered_raw

                case = rt().case(case_id, hardware=True)
                return analyze_registered_raw(
                    case, artifact_id, profile=profile, deadline=deadline,
                    max_seconds=max_seconds, cancel=cancelled.is_set,
                )
            except Exception as exc:
                raise _fixed_error(exc) from None

        return await run_blocking_cancellable(work, on_cancel=cancelled.set)
    except Exception as exc:
        raise _fixed_error(exc) from None


_configure_input(server)


def main() -> None:
    server.run()


if __name__ == "__main__":
    main()
