"""완전히 검사한 strict Flipper RAW를 고정 OOK 쌍으로 옮긴다. 파일·RF·decoder I/O는 없다."""

from __future__ import annotations

from dataclasses import dataclass
import math
import re
import time
from typing import Callable

from . import rf_formats
from .errors import PwehError
from .rf_formats import inspect_sub_raw

PROFILE = "flipper-raw-ook-v1"
SCHEMA = "pweh.rf-ook-conversion/v1"
SOURCE_PROFILE = rf_formats.PROFILE
FORMAT = "rtl433-ook-text-v1"
MAX_PAIRS = 1200
MAX_OUTPUT_BYTES = 65536
FALSE_FIELDS = (
    "input_completeness_verified", "capture_verified", "device_association_verified", "authorization_assessed",
    "decoded", "transmitted", "packet_boundaries_verified", "decoder_compatibility_verified",
)
LIMITATIONS = (
    "strict_complete_raw_only", "ook_presets_only", "ordered_duration_pairs_only", "no_gap_or_packet_inference",
    "no_capture_or_device_verification", "no_protocol_decoding", "no_receiver_or_transmission",
    "decoder_execution_not_performed", "aggregate_statistics_are_not_anonymization",
)
_PRESETS = rf_formats.PRESETS[:2]
_I32 = (1 << 31) - 1
_HEADER = b";pulse data\n;version 1\n;timescale 1us\n"
_TRAILER = b";end\n"
_ID = re.compile(r"A-[0-9]{4,8}")
_SHA = re.compile(r"[0-9a-f]{64}")
_PATH = re.compile(r"analysis/rf-ook-([0-9]{3})/converted\.ook")


@dataclass(frozen=True, repr=False)
class OokConversion:
    """파생 파일 작성용 bytes와 선언·집계만 보유한다. 공개 직렬화 API는 없다."""

    ook_bytes: bytes
    declared_preset: str
    declared_frequency_hz: int
    duration_count: int
    pair_count: int
    total_duration_us: int


def _error(code: str = "rf_ook_failed") -> PwehError:
    messages = {
        "rf_ook_input_invalid": "OOK 변환 입력이나 마감 시각이 허용 범위가 아닙니다.",
        "rf_ook_input_limit": "OOK 변환의 고정 입력·출력 상한을 넘었습니다.",
        "rf_ook_not_convertible": "이 RAW 입력은 고정 OOK 변환 조건을 만족하지 않습니다.",
        "rf_ook_failed": "OOK 변환 결과나 취소 상태를 확인하지 못했습니다.",
        "cancelled": "OOK 변환이 취소되었습니다.",
        "time_limit": "OOK 변환의 처리 시간이 끝났습니다.",
    }
    return PwehError(messages[code], code=code)


def _integer(value: object, lower: int, upper: int) -> bool:
    return type(value) is int and lower <= value <= upper


def _finite(value: object) -> bool:
    if type(value) not in (int, float):
        return False
    try:
        return math.isfinite(value)
    except OverflowError:
        return False


def _require(condition: bool) -> None:
    if not condition:
        raise _error()


def _object(value: object, keys: tuple[str, ...] | set[str]) -> dict:
    _require(type(value) is dict and set(value) == set(keys))
    return value


def _check(end: float, cancel: Callable[[], bool] | None) -> None:
    if cancel is not None:
        try:
            value = cancel()
            if type(value) is not bool:
                raise ValueError
        except Exception:
            raise _error() from None
        if value:
            raise _error("cancelled")
    if time.monotonic() >= end:
        raise _error("time_limit")


def _inspection(data: bytes, end: float, cancel: Callable[[], bool] | None) -> tuple[str, int, tuple[int, ...]]:
    try:
        report = inspect_sub_raw(data, deadline=end, cancel=cancel)
    except PwehError as exc:
        code = "cancelled" if exc.code == "cancelled" else "rf_ook_failed"
        raise _error(code) from None
    except Exception:
        raise _error() from None
    try:
        _require(type(report) is dict and report["schema"] == rf_formats.SCHEMA and report["profile"] == SOURCE_PROFILE)
        status = report["status"]
        _require(type(status) is str and status in ("complete", "partial", "malformed", "unsupported"))
        if status != "complete":
            stop = report["stop"]
            if type(stop) is dict and stop.get("code") == "time_limit":
                raise _error("time_limit")
            raise _error("rf_ook_not_convertible")
        cov, stats, meta = report["coverage"], report["statistics"], report["metadata"]
        _require(type(cov) is dict and type(stats) is dict and type(meta) is dict and report["stop"] is None)
        for name, expected in (("input_bytes", len(data)), ("accepted_prefix_bytes", len(data)), ("remaining_bytes", 0)):
            _require(type(cov[name]) is int and cov[name] == expected)
        _require(cov["remaining_range"] is None and cov["eof_validated"] is True and
                 cov["analysis_complete"] is True and cov["statistics_scope"] == "whole_profile")
        preset, frequency = meta["declared_preset"], meta["declared_frequency_hz"]
        _require(type(preset) is str and _integer(frequency, 0, (1 << 32) - 1))
        if preset not in _PRESETS:
            raise _error("rf_ook_not_convertible")
        count = stats["pulse_count"]
        _require(_integer(count, 0, rf_formats.RawLimits().max_pulses))
        if count > 2 * MAX_PAIRS:
            raise _error("rf_ook_input_limit")
        if count < 2 or count % 2:
            raise _error("rf_ook_not_convertible")
        positive, negative = stats["positive"], stats["negative"]
        _require(type(positive) is dict and type(negative) is dict)
        for row in (positive, negative):
            _require(type(row["count"]) is int and row["count"] == count // 2 and
                     _integer(row["sum_us"], row["count"], row["count"] * (1 << 31)))
        total = stats["declared_duration_us"]
        lines = stats["raw_data_lines_accepted"]
        _require(type(total) is int and total == positive["sum_us"] + negative["sum_us"] and
                 _integer(lines, 1, 8192))
        return preset, frequency, (count, positive["sum_us"], negative["sum_us"], total, lines)
    except (KeyError, TypeError, ValueError, AttributeError, OverflowError):
        raise _error() from None


def convert_sub_raw_to_ook(data: bytes, *, deadline: float,
                          cancel: Callable[[], bool] | None = None) -> OokConversion:
    """기존 전체 strict 검사 한 번 뒤 같은 bytes를 bounded 재순회한다. 부분 변환은 반환하지 않는다."""
    if type(data) is not bytes or not _finite(deadline) or cancel is not None and not callable(cancel):
        raise _error("rf_ook_input_invalid")
    end = min(float(deadline), time.monotonic() + 5.0)
    if len(data) > 1 << 20:
        raise _error("rf_ook_input_limit")
    _check(end, cancel)
    preset, frequency, expected = _inspection(data, end, cancel)
    output = bytearray(_HEADER)
    position = 3 if data.startswith(b"\xef\xbb\xbf") else 0
    lines = raw_lines = count = positive_sum = negative_sum = 0
    mark: int | None = None
    while position < len(data):
        _check(end, cancel)
        _require(lines < 8192)
        stop = min(len(data), position + 8192 + 2)
        lf = data.find(b"\n", position, stop)
        content_end, frame_end = (lf, lf + 1) if lf >= 0 else (stop, stop)
        if lf >= 0 and content_end > position and data[content_end - 1] == 13:
            content_end -= 1
        _require(content_end - position <= 8192)
        raw = data[position:content_end]
        position, lines = frame_end, lines + 1
        if not raw.strip(b" \t") or raw.lstrip(b" \t").startswith(b"#"):
            continue
        key, colon, value = raw.partition(b":")
        if key != b"RAW_Data":
            continue
        _require(bool(colon))
        value = value.strip(b" \t")
        _require(bool(value))
        raw_lines += 1
        cursor = line_count = 0
        while cursor < len(value):
            _check(end, cancel)
            _require(line_count < 512)
            token_end = cursor
            while token_end < len(value) and value[token_end] not in (32, 9):
                _require(token_end - cursor < 11)
                token_end += 1
            token = value[cursor:token_end]
            digits = token[1:] if token.startswith(b"-") else token
            _require(bool(digits) and all(48 <= byte <= 57 for byte in digits))
            number = int(token)
            if not 1 <= abs(number) <= _I32 or (number > 0) != (count % 2 == 0):
                raise _error("rf_ook_not_convertible")
            if count >= 2 * MAX_PAIRS:
                raise _error("rf_ook_input_limit")
            if number > 0:
                mark = number
                positive_sum += number
            else:
                _require(mark is not None)
                row = f"{mark} {-number}\n".encode("ascii")
                if len(output) + len(row) + len(_TRAILER) > MAX_OUTPUT_BYTES:
                    raise _error("rf_ook_input_limit")
                output.extend(row)
                negative_sum -= number
                mark = None
            count, line_count = count + 1, line_count + 1
            cursor = token_end
            while cursor < len(value) and value[cursor] in (32, 9):
                cursor += 1
    _require(mark is None and count % 2 == 0 and
             (count, positive_sum, negative_sum, positive_sum + negative_sum, raw_lines) == expected)
    output.extend(_TRAILER)
    _require(43 + 4 * (count // 2) <= len(output) <= 43 + 22 * (count // 2))
    _check(end, cancel)
    return OokConversion(bytes(output), preset, frequency, count, count // 2, positive_sum + negative_sum)


def _text(value: object, pattern: re.Pattern[str]) -> bool:
    return type(value) is str and pattern.fullmatch(value) is not None


def validate_ook_accounting(report: dict) -> None:
    """schema 뒤 full manifest의 exact 값·관계만 검사한다. bytes·SHA 진위 검사는 worker 책임이다."""
    root = _object(report, {"schema", "profile", "status", "source", "params", "metadata", "conversion", "output",
                            "limitations", *FALSE_FIELDS})
    _require(root["schema"] == SCHEMA and type(root["schema"]) is str and root["profile"] == PROFILE and
             type(root["profile"]) is str and root["status"] == "complete" and type(root["status"]) is str)
    _require(all(root[field] is False for field in FALSE_FIELDS))
    _require(type(root["limitations"]) is list and len(root["limitations"]) == len(LIMITATIONS) and
             all(type(value) is str and value == expected for value, expected in zip(root["limitations"], LIMITATIONS)))
    source = _object(root["source"], ("kind", "artifact_id", "size", "sha256"))
    _require(type(source["kind"]) is str and source["kind"] == "case-artifact" and
             _text(source["artifact_id"], _ID) and _text(source["sha256"], _SHA) and
             _integer(source["size"], 1, 1 << 20))
    params = _object(root["params"], ("source_profile", "max_seconds"))
    _require(type(params["source_profile"]) is str and params["source_profile"] == SOURCE_PROFILE and
             _finite(params["max_seconds"]) and 0 < params["max_seconds"] <= 5)
    meta = _object(root["metadata"], ("declared_preset", "declared_frequency_hz"))
    _require(type(meta["declared_preset"]) is str and meta["declared_preset"] in _PRESETS and
             _integer(meta["declared_frequency_hz"], 0, (1 << 32) - 1))
    conversion = _object(root["conversion"], ("format", "unit", "pairing", "duration_count", "pair_count", "total_duration_us"))
    for name, value in (("format", FORMAT), ("unit", "us"), ("pairing", "positive-negative")):
        _require(type(conversion[name]) is str and conversion[name] == value)
    count, pairs, total = (conversion[name] for name in ("duration_count", "pair_count", "total_duration_us"))
    _require(_integer(pairs, 1, MAX_PAIRS) and _integer(count, 2, MAX_PAIRS * 2) and count == 2 * pairs)
    _require(_integer(total, count, count * _I32))
    out = _object(root["output"], ("path", "size", "sha256"))
    _require(_text(out["path"], _PATH) and _text(out["sha256"], _SHA))
    match = _PATH.fullmatch(out["path"])
    _require(1 <= int(match.group(1)) <= 64)
    _require(_integer(out["size"], 47, 26443) and 43 + 4 * pairs <= out["size"] <= 43 + 22 * pairs)
