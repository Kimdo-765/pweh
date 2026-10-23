"""play-mcp: 호출자가 공급한 숫자 표본의 합의 계산과 케이스 저장."""

from __future__ import annotations

import threading
import time
from typing import Annotated, Literal

from mcp.server.mcpserver.utilities.func_metadata import FuncMetadata
from pydantic import BeforeValidator, ConfigDict, Field, StrictFloat, StrictInt, StrictStr, ValidationError
from pydantic_core import PydanticCustomError
from typing_extensions import TypedDict

from pweh.case import CASE_ID_RE
from pweh.errors import PwehError
from pweh.mcpkit import ANN_LOCAL_WRITE, create_server, run_blocking_cancellable, safe_tool
from pweh.runtime import Runtime, get_runtime
from pweh.vision_sequence import MAX_TIMESTAMP, MAX_VALUE, MIN_VALUE, NumericObservation, NumericPolicy

SERVER_NAME = "play-mcp"
_ERRORS = {
    "numeric_input_invalid": "숫자 관찰 입력이 허용된 형식이나 범위가 아닙니다.",
    "numeric_output_invalid": "숫자 관찰 결과의 계약을 확인하지 못했습니다.",
    "numeric_analysis_failed": "숫자 관찰 분석을 완료하지 못했습니다.",
    "invalid_policy": "숫자 관찰 정책이 허용된 범위가 아닙니다.",
    "invalid_observation": "숫자 관찰의 값 또는 시간 순서가 올바르지 않습니다.",
    "observation_limit": "숫자 관찰 개수가 상한을 넘었습니다.",
    "cleanup_incomplete": "숫자 관찰 출력의 정리를 확인하지 못했습니다.",
    "time_limit": "숫자 관찰 분석의 시간 한도에 닿았습니다.",
    "cancelled": "숫자 관찰 분석이 취소되었습니다.",
    "authorization_required": "케이스의 소유 또는 서면 허가 확인이 필요합니다.",
    "not_found": "요청한 케이스를 찾지 못했습니다.",
    "case_error": "숫자 관찰 분석의 케이스를 확인하지 못했습니다.",
    "config_error": "숫자 관찰 분석의 실행 설정을 확인하지 못했습니다.",
    "safety_denied": "현재 정책에서 숫자 관찰 분석을 허용하지 않습니다.",
}


def _invalid() -> PwehError:
    return PwehError(_ERRORS["numeric_input_invalid"], code="numeric_input_invalid")


def _number(value, low, high) -> bool:
    return type(value) in (int, float) and low <= value <= high


def _observation_list(value):
    # 원소 해석 전에 원 요청의 컨테이너 타입과 개수를 검사한다.
    if type(value) is not list or len(value) > 256:
        raise ValueError("numeric_input_invalid")
    for row in value:
        if type(row) is not dict or set(row) != {"timestamp", "value", "confidence"}:
            raise ValueError("numeric_input_invalid")
    return value


def _policy_dict(value):
    if type(value) is not dict:
        raise ValueError("numeric_input_invalid")
    return value


Timestamp = Annotated[StrictInt | StrictFloat, Field(ge=0, le=MAX_TIMESTAMP)]
Confidence = Annotated[StrictInt | StrictFloat, Field(ge=0, le=1)]
PolicyInteger = Annotated[StrictInt, Field(ge=1, le=256)]


class ObservationInput(TypedDict):
    __pydantic_config__ = ConfigDict(strict=True, extra="forbid", hide_input_in_errors=True)
    timestamp: Timestamp
    value: Annotated[StrictInt, Field(ge=MIN_VALUE, le=MAX_VALUE)] | None
    confidence: Confidence


class PolicyInput(TypedDict, total=False):
    __pydantic_config__ = ConfigDict(strict=True, extra="forbid", hide_input_in_errors=True)
    window_size: PolicyInteger
    votes_required: PolicyInteger
    min_valid: PolicyInteger
    min_confidence: Confidence
    ttl_seconds: Annotated[StrictInt | StrictFloat, Field(gt=0, le=86400)]


Observations = Annotated[list[ObservationInput], BeforeValidator(_observation_list), Field(max_length=256)]
Policy = Annotated[PolicyInput, BeforeValidator(_policy_dict)]


class _NumericMetadata(FuncMetadata):
    """배열·객체 JSON 문자열을 변환하지 않고 오류의 원문 위치도 제거한다."""

    def validate_arguments(self, arguments_to_validate: dict) -> dict:
        try:
            # SDK pre_parse_json을 생략하여 원 배열/객체와 그것을 담은 문자열을 구분한다.
            return self.arg_model.model_validate(arguments_to_validate).model_dump_one_level()
        except ValidationError:
            raise ValidationError.from_exception_data(
                "NumericInput", [{"type": PydanticCustomError("numeric_input_invalid", _ERRORS["numeric_input_invalid"]),
                                  "loc": (), "input": None}], hide_input=True,
            ) from None


def _configure_input(instance) -> None:
    """비공개 SDK 연결 실패는 고정 등록 오류로 종료한다."""
    try:
        tool = instance._tool_manager.get_tool("vision_validate")
        if tool is None:
            raise RuntimeError
        old = tool.fn_metadata
        model = old.arg_model
        model.model_config.update(strict=True, extra="forbid", hide_input_in_errors=True)
        model.model_rebuild(force=True)
        tool.fn_metadata = _NumericMetadata(arg_model=model, output_schema=old.output_schema,
                                            output_model=old.output_model, wrap_output=old.wrap_output)
        tool.parameters = model.model_json_schema(by_alias=True)
        if tool.parameters.get("additionalProperties") is not False:
            raise RuntimeError
    except Exception:
        raise RuntimeError("숫자 도구의 비공개 입력 검증 설정을 완료하지 못했습니다.") from None


def rt() -> Runtime:
    return get_runtime(SERVER_NAME)


def _fixed_error(exc: Exception) -> PwehError:
    code = getattr(exc, "code", None)
    if type(code) is not str or code not in _ERRORS:
        code = "numeric_analysis_failed"
    return PwehError(_ERRORS[code], code=code)


def _arguments(case_id, input_kind, observations, now, policy):
    if (type(case_id) is not str or len(case_id) > 80 or CASE_ID_RE.fullmatch(case_id) is None
            or type(input_kind) is not str or input_kind != "numeric-observations"
            or not _number(now, 0, MAX_TIMESTAMP)):
        raise _invalid()
    try:
        _observation_list(observations)
    except ValueError:
        raise _invalid() from None
    settings = {"window_size": 5, "votes_required": 3, "min_valid": 3,
                "min_confidence": 0.8, "ttl_seconds": 2.0}
    if policy is not None:
        if type(policy) is not dict or set(policy) - set(settings):
            raise _invalid()
        settings.update(policy)
    size = settings["window_size"]
    if (type(size) is not int or not 1 <= size <= 256
            or any(type(settings[k]) is not int or not 1 <= settings[k] <= size
                   for k in ("votes_required", "min_valid"))
            or not _number(settings["min_confidence"], 0, 1)
            or not _number(settings["ttl_seconds"], 0, 86400) or settings["ttl_seconds"] == 0):
        raise _invalid()
    result = []
    previous = None
    for row in observations:
        stamp, value, confidence = row["timestamp"], row["value"], row["confidence"]
        if (not _number(stamp, 0, MAX_TIMESTAMP) or stamp > now
                or (previous is not None and stamp <= previous)
                or (value is not None and (type(value) is not int or not MIN_VALUE <= value <= MAX_VALUE))
                or not _number(confidence, 0, 1)):
            raise _invalid()
        result.append(NumericObservation(stamp, value, confidence))
        previous = stamp
    return tuple(result), NumericPolicy(**settings)


server = create_server(SERVER_NAME, title="PWEH 공급 숫자 관찰 분석", instructions=(
    "호출자가 공급한 숫자 표본을 같은 공급 monotonic seconds 축의 now로 평가한다. "
    "소유/허가 케이스에서 vision_validate 후 numeric-observation-analysis의 numeric-analysis 요약을 기록한다. "
    "stable은 숫자 합의이며 실제 프레임 신선도·게임 의미·입력 실행을 검증하지 않는다. "
    "OCR·프레임·장치·외부 프로세스·자동 플레이는 사용하지 않는다."
))


@server.tool(description=(
    "호출자가 공급한 숫자 표본의 시간 창 합의를 계산한다. input_kind='numeric-observations'가 필수다. "
    "observations는 timestamp/value/confidence를 가진 객체0~256개이며 now와 timestamp는 같은 공급 monotonic seconds 축의0~2**53이다. "
    "시각은 엄격 증가하고 now 이하, value는 null 또는 int64, confidence는0~1이다. bool·문자열을 숫자로 변환하지 않는다. "
    "policy 기본값은 window_size=5, votes_required=3, min_valid=3, min_confidence=0.8, ttl_seconds=2.0이며 생략 필드만 채운다. "
    "최근 M→TTL→유효 투표 순으로 stable/unknown/stale를 계산한다. 소유/허가 확인과 worker 시작부터 저장까지 고정5초 예산을 사용한다. "
    "표본 원문은 저장하지 않고 canonical 입력 SHA·공급 now·정책·합의 value·범위 통계를 analysis/numeric-observations-NNN.json에0444로 저장한다. "
    "입력 digest는 취득 출처나 익명성 증명이 아니다. frame_freshness_verified/game_semantics_verified/action_generated는 항상false이며 "
    "화면·OCR·시계 취득·장치·입력 명령·자동 플레이를 실행하지 않는다."
), annotations=ANN_LOCAL_WRITE)
@safe_tool
async def vision_validate(
    case_id: Annotated[StrictStr, Field(max_length=80, pattern=CASE_ID_RE.pattern)],
    input_kind: Literal["numeric-observations"], observations: Observations,
    now: Timestamp, policy: Policy | None = None,
) -> dict:
    cancelled = threading.Event()
    try:
        snapshot, settings = _arguments(case_id, input_kind, observations, now, policy)

        def work() -> dict:
            deadline = time.monotonic() + 5
            try:
                if cancelled.is_set():
                    raise PwehError(_ERRORS["cancelled"], code="cancelled")
                from .numeric_validation import validate_supplied_numeric
                case = rt().case(case_id, hardware=True)
                return validate_supplied_numeric(case, snapshot, now=now, policy=settings,
                                                 deadline=deadline, cancel=cancelled.is_set)
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
