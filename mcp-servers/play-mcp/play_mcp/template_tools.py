"""등록된 image-hints PNG 두 영역의 비교 도구."""

from __future__ import annotations

import re
import threading
import time
from typing import Annotated

from pydantic import BeforeValidator, Field, StrictInt, StrictStr

from pweh.case import CASE_ID_RE
from pweh.errors import PwehError
from pweh.mcpkit import ANN_LOCAL_WRITE, run_blocking_cancellable, safe_tool


_ERRORS = {
    "template_input_invalid": "저장 PNG 비교 입력이 허용된 형식이나 범위가 아닙니다.",
    "template_input_limit": "저장 PNG 비교 입력이 크기 한도를 넘었습니다.",
    "template_input_changed": "저장 PNG 비교 입력의 동일성을 확인하지 못했습니다.",
    "template_output_invalid": "저장 PNG 비교 결과의 계약을 확인하지 못했습니다.",
    "template_failed": "저장 PNG 비교를 완료하지 못했습니다.",
    "template_cleanup_incomplete": "저장 PNG 비교 출력의 정리를 확인하지 못했습니다.",
    "time_limit": "저장 PNG 비교의 시간 한도에 닿았습니다.",
    "cancelled": "저장 PNG 비교가 취소되었습니다.",
    "authorization_required": "케이스의 소유 또는 서면 허가 확인이 필요합니다.",
    "not_found": "요청한 케이스 또는 등록 자료를 찾지 못했습니다.",
    "case_error": "저장 PNG 비교의 케이스를 확인하지 못했습니다.",
    "config_error": "저장 PNG 비교의 실행 설정을 확인하지 못했습니다.",
    "safety_denied": "현재 정책에서 저장 PNG 비교를 허용하지 않습니다.",
}
_ARTIFACT = re.compile(r"A-[0-9]{4,8}")


def _fixed_error(exc: Exception) -> PwehError:
    code = getattr(exc, "code", None)
    if type(code) is not str or code not in _ERRORS:
        code = "template_failed"
    return PwehError(_ERRORS[code], code=code)


def _roi(value):
    # SDK의 배열 문자열 변환 없이 원 요청의 배열과 정수를 검사한다.
    if (type(value) is not list or len(value) != 4
            or any(type(n) is not int for n in value)
            or any(not 0 <= n <= 1600 for n in value[:2])
            or any(not 1 <= n <= 1600 for n in value[2:])):
        raise ValueError("template_input_invalid")
    return value


Roi = Annotated[list[StrictInt], BeforeValidator(_roi), Field(min_length=4, max_length=4)]
ArtifactId = Annotated[StrictStr, Field(pattern=r"^A-[0-9]{4,8}$", max_length=10)]
PreviewIndex = Annotated[StrictInt, Field(ge=0, le=1)]
Threshold = Annotated[StrictInt, Field(ge=0, le=255)]


def _arguments(case_id, reference_artifact_id, reference_preview_index, reference_roi,
               candidate_artifact_id, candidate_preview_index, candidate_roi, max_mean_error):
    try:
        if (type(case_id) is not str or len(case_id) > 80 or CASE_ID_RE.fullmatch(case_id) is None
                or any(type(a) is not str or _ARTIFACT.fullmatch(a) is None
                       for a in (reference_artifact_id, candidate_artifact_id))
                or any(type(i) is not int or i not in (0, 1)
                       for i in (reference_preview_index, candidate_preview_index))
                or type(max_mean_error) is not int or not 0 <= max_mean_error <= 255):
            raise ValueError
        _roi(reference_roi)
        _roi(candidate_roi)
        if reference_roi[2:] != candidate_roi[2:]:
            raise ValueError
        return tuple(reference_roi), tuple(candidate_roi)
    except (ValueError, TypeError):
        raise PwehError(_ERRORS["template_input_invalid"], code="template_input_invalid") from None


def register_template_tools(server, S) -> None:
    """서버 namespace의 runtime만 소비하여 비교 도구 하나를 등록한다."""

    @server.tool(description=(
        "같은 소유/허가 케이스에 등록된 image-hints JSON 보고서의 정규화 PNG 두 영역을 비교한다. "
        "두 artifact_id는 PNG가 아닌 보고서 JSON의 등록 ID이며 preview_index는 0 또는 1이다. "
        "각 roi는 저장 PNG 픽셀의 [x,y,width,height] 정수 배열이고 두 영역의 크기는 같아야 한다. "
        "RGB 절대차 합계·표본 수·평균과 max_mean_error(정수0~255) 이하 여부를 반환한다. "
        "리사이즈·정렬 없이 같은 위치의 RGB 값을 비교하며 matched=false도 정상 결과다. "
        "케이스 확인부터 입력 읽기·비교·최종 검증·저장까지 고정5초 예산을 쓴다. "
        "분석 JSON은 analysis/template-match-NNN.json에0444로 등록하며 원 픽셀·OCR·시각은 반환하지 않는다. "
        "프레임 신선도·게임 의미·입력 실행은 검증하지 않으며 image-template-analysis 요약에 기록한다."
    ), annotations=ANN_LOCAL_WRITE)
    @safe_tool
    async def vision_template_match(
        case_id: Annotated[StrictStr, Field(max_length=80, pattern=CASE_ID_RE.pattern)],
        reference_artifact_id: ArtifactId, reference_preview_index: PreviewIndex, reference_roi: Roi,
        candidate_artifact_id: ArtifactId, candidate_preview_index: PreviewIndex, candidate_roi: Roi,
        max_mean_error: Threshold,
    ) -> dict:
        cancelled = threading.Event()
        try:
            reference, candidate = _arguments(
                case_id, reference_artifact_id, reference_preview_index, reference_roi,
                candidate_artifact_id, candidate_preview_index, candidate_roi, max_mean_error,
            )

            def work() -> dict:
                deadline = time.monotonic() + 5
                try:
                    if cancelled.is_set():
                        raise PwehError(_ERRORS["cancelled"], code="cancelled")
                    from .template_analysis import match_registered_previews
                    case = S["rt"]().case(case_id, hardware=True)
                    return match_registered_previews(
                        case, reference_artifact_id, reference_preview_index, reference,
                        candidate_artifact_id, candidate_preview_index, candidate, max_mean_error,
                        deadline=deadline, cancel_event=cancelled,
                    )
                except Exception as exc:
                    raise _fixed_error(exc) from None

            return await run_blocking_cancellable(work, on_cancel=cancelled.set)
        except Exception as exc:
            raise _fixed_error(exc) from None
