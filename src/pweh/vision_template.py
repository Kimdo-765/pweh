"""저장 PNG의 같은 크기 RGB ROI를 비교하는 순수 정수 연산."""

from __future__ import annotations

import math
import time

from .errors import PwehError

PROFILE = "stored-png-roi-rgb-mae-v1"
OP = "template-match-v1"
MAX_PNG_BYTES = 1 << 20
MAX_DIMENSION = 1600
MAX_OUTPUT_BYTES = 1 << 16
_CHUNK_BYTES = 1 << 16
_MESSAGES = {
    "template_input_invalid": "저장 PNG 비교 입력이 허용 범위와 맞지 않습니다.",
    "template_failed": "저장 PNG 비교 결과를 확인하지 못했습니다.",
    "time_limit": "저장 PNG 비교 시간이 만료됐습니다.",
    "cancelled": "저장 PNG 비교가 취소됐습니다.",
}


def _error(code: str) -> PwehError:
    return PwehError(_MESSAGES[code], code=code)


def _tick(deadline: float) -> None:
    try:
        valid = type(deadline) in (int, float) and math.isfinite(deadline)
    except OverflowError:
        valid = False
    if not valid:
        raise _error("template_input_invalid") from None
    if time.monotonic() >= deadline:
        raise _error("time_limit") from None


def _geometry(size: tuple, roi: tuple) -> None:
    if (type(size) is not tuple or len(size) != 2
            or any(type(n) is not int or not 1 <= n <= MAX_DIMENSION for n in size)
            or type(roi) is not tuple or len(roi) != 4
            or any(type(n) is not int for n in roi)
            or not 0 <= roi[0] <= MAX_DIMENSION or not 0 <= roi[1] <= MAX_DIMENSION
            or not 1 <= roi[2] <= MAX_DIMENSION or not 1 <= roi[3] <= MAX_DIMENSION
            or roi[0] + roi[2] > size[0] or roi[1] + roi[3] > size[1]):
        raise _error("template_input_invalid") from None


def _threshold(value: int) -> None:
    if type(value) is not int or not 0 <= value <= 255:
        raise _error("template_input_invalid") from None


def _validate_result(result: dict, *, width: int, height: int, max_mean_error: int) -> None:
    """worker의 숫자 결과를 부모가 원래 요청의 정수식으로 다시 대조한다."""
    if (type(result) is not dict
            or set(result) != {"sum_abs", "samples", "mean_abs_error", "matched"}
            or type(result["samples"]) is not int or result["samples"] != width * height * 3
            or type(result["sum_abs"]) is not int
            or not 0 <= result["sum_abs"] <= 255 * result["samples"]
            or type(result["mean_abs_error"]) is not float
            or not math.isfinite(result["mean_abs_error"])
            or result["mean_abs_error"] != result["sum_abs"] / result["samples"]
            or type(result["matched"]) is not bool
            or result["matched"] != (result["sum_abs"] <= max_mean_error * result["samples"])):
        raise _error("template_failed") from None


def compare_rgb_bytes(reference: bytes, candidate: bytes, *, width: int, height: int,
                      max_mean_error: int, deadline: float) -> dict:
    """RGB 절대 차이를 정수로 합산한다. 입력·결과에 파일 경로나 색 변환은 없다."""
    _tick(deadline)
    _geometry((width, height), (0, 0, width, height))
    _threshold(max_mean_error)
    samples = width * height * 3
    if (type(reference) is not bytes or type(candidate) is not bytes
            or len(reference) != samples or len(candidate) != samples):
        raise _error("template_input_invalid") from None
    total = 0
    for offset in range(0, samples, _CHUNK_BYTES):
        _tick(deadline)
        total += sum(abs(a - b) for a, b in zip(reference[offset:offset + _CHUNK_BYTES],
                                               candidate[offset:offset + _CHUNK_BYTES]))
        _tick(deadline)
    return {"sum_abs": total, "samples": samples, "mean_abs_error": total / samples,
            "matched": total <= max_mean_error * samples}
