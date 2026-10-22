"""Flipper RAW bytes의 제한 문법과 집계만 검사한다. 파일·RF·디코더는 다루지 않는다."""
from __future__ import annotations

import json
import math
import time
from dataclasses import dataclass, fields
from typing import Callable

from .errors import PwehError, ValidationFailed

SCHEMA = "pweh.rf-raw-inspection/v1"
PROFILE = "flipper-subghz-raw-v1-strict"
FILETYPE = "Flipper SubGhz RAW File"
PRESETS = (
    "FuriHalSubGhzPresetOok270Async", "FuriHalSubGhzPresetOok650Async",
    "FuriHalSubGhzPreset2FSKDev238Async", "FuriHalSubGhzPreset2FSKDev12KAsync",
    "FuriHalSubGhzPreset2FSKDev476Async",
)
STOP_CODES = (
    "input_limit", "line_limit", "line_length_limit", "pulse_limit", "duration_limit",
    "step_limit", "time_limit", "unsupported_encoding", "unsupported_filetype",
    "unsupported_version", "unsupported_preset", "unsupported_protocol", "unsupported_field",
    "invalid_utf8", "invalid_line_ending", "unexpected_bom", "control_character",
    "field_syntax", "empty_value", "duplicate_field", "metadata_order", "metadata_incomplete",
    "integer_syntax", "integer_width", "integer_range", "zero_duration", "first_negative",
    "sign_not_alternating", "line_pulse_count", "missing_header", "missing_metadata", "missing_raw_data",
)
LIMITATIONS = (
    "strict_profile_only", "file_declarations_only", "accepted_lines_only",
    "no_capture_completeness_verification", "no_device_or_authorization_verification",
    "no_protocol_decoding", "no_raw_pulse_output", "no_replay_or_transmission",
    "aggregate_statistics_are_not_anonymization",
)
_ORDER = (b"Filetype", b"Version", b"Frequency", b"Preset", b"Protocol")
_META_KEYS = ("filetype", "version", "declared_frequency_hz", "declared_preset", "protocol")
_PRESET_BYTES = {p.encode("ascii"): p for p in PRESETS}


@dataclass(frozen=True)
class RawLimits:
    """기본 ceiling보다 낮출 수만 있다. 줄당 512개는 별도의 고정 문법이다."""

    max_bytes: int = 1 << 20
    max_line_bytes: int = 8192
    max_lines: int = 8192
    max_pulses: int = 65536
    max_duration_us: int = (1 << 63) - 1
    max_steps: int = 100000
    max_runtime_ms: int = 5000
    max_output_bytes: int = 65536


class _Stop(Exception):
    def __init__(self, status: str, code: str):
        self.status, self.code = status, code


def _stop(status: str, code: str) -> None:
    raise _Stop(status, code)


def _stats() -> dict:
    return {"count": 0, "min_us": None, "max_us": None, "sum_us": 0}


def _add(stats: dict, magnitude: int) -> None:
    stats["count"] += 1
    stats["sum_us"] += magnitude
    stats["min_us"] = magnitude if stats["min_us"] is None else min(stats["min_us"], magnitude)
    stats["max_us"] = magnitude if stats["max_us"] is None else max(stats["max_us"], magnitude)


def _new(size: int) -> dict:
    return {
        "schema": SCHEMA, "status": "partial", "profile": PROFILE,
        "metadata": dict.fromkeys(_META_KEYS),
        "statistics": {"pulse_count": 0, "declared_duration_us": 0, "raw_data_lines_accepted": 0,
                       "positive": _stats(), "negative": _stats()},
        "coverage": {"input_bytes": size, "accepted_prefix_bytes": 0, "remaining_bytes": size,
                     "remaining_range": {"offset": 0, "length": size} if size else None,
                     "lines_seen": 0, "lines_accepted": 0, "steps_used": 0,
                     "eof_validated": False, "analysis_complete": False,
                     "statistics_scope": "accepted_prefix", "input_completeness_verified": False,
                     "capture_verified": False, "device_association_verified": False,
                     "authorization_assessed": False, "decoded": False, "transmitted": False},
        "stop": None, "limitations": list(LIMITATIONS),
    }


def _validate(data: bytes, limits: RawLimits, deadline: float, cancel: object) -> float:
    invalid = "RAW 검사 입력·한도·마감 시각이 허용 범위가 아닙니다."
    if type(data) is not bytes or type(limits) is not RawLimits:
        raise ValidationFailed(invalid)
    maximum = RawLimits()
    for field in fields(limits):
        value = getattr(limits, field.name)
        minimum = 4096 if field.name == "max_output_bytes" else 1
        if type(value) is not int or not minimum <= value <= getattr(maximum, field.name):
            raise ValidationFailed(invalid)
    if type(deadline) not in (int, float) or cancel is not None and not callable(cancel):
        raise ValidationFailed(invalid)
    try:
        end = float(deadline)
    except (OverflowError, ValueError):
        raise ValidationFailed(invalid) from None
    if not math.isfinite(end):
        raise ValidationFailed(invalid)
    return end


class _Inspector:
    def __init__(self, data: bytes, limits: RawLimits, deadline: float,
                 cancel: Callable[[], bool] | None):
        self.data, self.limits, self.cancel = data, limits, cancel
        self.deadline = min(deadline, time.monotonic() + limits.max_runtime_ms / 1000)
        self.report = _new(len(data))
        self.cov, self.stats = self.report["coverage"], self.report["statistics"]
        self.pos, self.stage = 0, 0
        self.line: int | None = None
        self.last_positive: bool | None = None

    def check(self, *, deadline: bool = True) -> None:
        if self.cancel is not None:
            try:
                cancelled = self.cancel()
                if type(cancelled) is not bool:
                    raise ValueError
            except Exception:
                raise PwehError("RAW 검사의 취소 상태를 확인하지 못했습니다.", code="rf_raw_failed") from None
            if cancelled:
                raise PwehError("RAW 검사가 취소되었습니다.", code="cancelled")
        if deadline and time.monotonic() >= self.deadline:
            _stop("partial", "time_limit")

    def step(self) -> None:
        self.check()
        if self.cov["steps_used"] >= self.limits.max_steps:
            _stop("partial", "step_limit")
        self.cov["steps_used"] += 1

    def read_line(self) -> tuple[bytes, int]:
        # LF를 찾는 한 번의 검색도 줄 상한+CRLF로 제한한다.
        end = min(len(self.data), self.pos + self.limits.max_line_bytes + 2)
        lf = self.data.find(b"\n", self.pos, end)
        content_end = lf if lf >= 0 else end
        frame_end = lf + 1 if lf >= 0 else end
        if lf >= 0 and content_end > self.pos and self.data[content_end - 1] == 13:
            content_end -= 1
        if content_end - self.pos > self.limits.max_line_bytes:
            _stop("partial", "line_length_limit")
        raw = self.data[self.pos:content_end]
        try:
            text = raw.decode("utf-8", "strict")
        except UnicodeDecodeError:
            _stop("malformed", "invalid_utf8")
        for index, char in enumerate(text):
            if index % 4096 == 0:
                self.check()
            cp = ord(char)
            if cp == 13:
                _stop("malformed", "invalid_line_ending")
            if cp == 0xfeff:
                _stop("malformed", "unexpected_bom")
            if cp < 32 and cp != 9 or 127 <= cp <= 159:
                _stop("malformed", "control_character")
        return raw, frame_end

    def number(self, token: bytes, *, signed: bool) -> int:
        self.step()
        if len(token) > (11 if signed else 10):
            _stop("malformed", "integer_width")
        digits = token[1:] if signed and token.startswith(b"-") else token
        if not digits or any(ch < 48 or ch > 57 for ch in digits):
            _stop("malformed", "integer_syntax")
        value = int(token)
        low, high = (-(1 << 31), (1 << 31) - 1) if signed else (0, (1 << 32) - 1)
        if not low <= value <= high:
            _stop("malformed", "integer_range")
        return value

    def raw_data(self, value: bytes) -> tuple[dict, bool]:
        local = {"positive": _stats(), "negative": _stats()}
        count, duration, cursor = 0, 0, 0
        last = self.last_positive
        while cursor < len(value):
            self.check()
            end = cursor
            while end < len(value) and value[end] not in (32, 9):
                end += 1
            if count >= 512:
                _stop("malformed", "line_pulse_count")
            if self.stats["pulse_count"] + count >= self.limits.max_pulses:
                _stop("partial", "pulse_limit")
            number = self.number(value[cursor:end], signed=True)
            if number == 0:
                _stop("malformed", "zero_duration")
            positive = number > 0
            if last is None and not positive:
                _stop("malformed", "first_negative")
            if last is not None and positive == last:
                _stop("malformed", "sign_not_alternating")
            magnitude = abs(number)
            if self.stats["declared_duration_us"] + duration + magnitude > self.limits.max_duration_us:
                _stop("partial", "duration_limit")
            _add(local["positive" if positive else "negative"], magnitude)
            count, duration, last = count + 1, duration + magnitude, positive
            cursor = end
            while cursor < len(value) and value[cursor] in (32, 9):
                cursor += 1
        return local, bool(last)

    def parse_line(self, raw: bytes) -> tuple[str, object]:
        if not raw.strip(b" \t") or raw.lstrip(b" \t").startswith(b"#"):
            return "ignored", None
        key, colon, value = raw.partition(b":")
        if (not colon or not key or key[0] in range(48, 58)
                or any(not (65 <= c <= 90 or 97 <= c <= 122 or 48 <= c <= 57 or c == 95) for c in key)):
            _stop("malformed", "field_syntax")
        value = value.strip(b" \t")
        if not value:
            _stop("malformed", "empty_value")
        if key == b"RAW_Data":
            if self.stage != len(_ORDER):
                _stop("malformed", "metadata_incomplete")
            return "raw", self.raw_data(value)
        if key not in _ORDER:
            _stop("unsupported", "unsupported_field")
        index = _ORDER.index(key)
        if index < self.stage:
            _stop("malformed", "duplicate_field")
        if index != self.stage:
            _stop("malformed", "metadata_order")
        if key == b"Filetype":
            if value != FILETYPE.encode("ascii"):
                _stop("unsupported", "unsupported_filetype")
            result = FILETYPE
        elif key in (b"Version", b"Frequency"):
            result = self.number(value, signed=False)
            if key == b"Version" and result != 1:
                _stop("unsupported", "unsupported_version")
        elif key == b"Preset":
            result = _PRESET_BYTES.get(value)
            if result is None:
                _stop("unsupported", "unsupported_preset")
        else:
            if value != b"RAW":
                _stop("unsupported", "unsupported_protocol")
            result = "RAW"
        return "metadata", result

    def commit_line(self, kind: str, result: object, end: int) -> None:
        # metadata와 RAW 통계를 같은 줄의 검사가 끝난 뒤에만 공개 객체로 옮긴다.
        if kind == "metadata":
            self.report["metadata"][_META_KEYS[self.stage]] = result
            self.stage += 1
        elif kind == "raw":
            local, self.last_positive = result
            for sign in ("positive", "negative"):
                delta, saved = local[sign], self.stats[sign]
                if delta["count"]:
                    saved["count"] += delta["count"]
                    saved["sum_us"] += delta["sum_us"]
                    saved["min_us"] = delta["min_us"] if saved["min_us"] is None else min(saved["min_us"], delta["min_us"])
                    saved["max_us"] = delta["max_us"] if saved["max_us"] is None else max(saved["max_us"], delta["max_us"])
            self.stats["pulse_count"] = sum(self.stats[s]["count"] for s in ("positive", "negative"))
            self.stats["declared_duration_us"] = sum(self.stats[s]["sum_us"] for s in ("positive", "negative"))
            self.stats["raw_data_lines_accepted"] += 1
        self.pos = end
        self.cov["lines_accepted"] += 1

    def run(self) -> dict:
        try:
            self.check()
            if len(self.data) > self.limits.max_bytes:
                _stop("partial", "input_limit")
            if self.data.startswith((b"\xff\xfe", b"\xfe\xff", b"\x00\x00\xfe\xff")):
                _stop("unsupported", "unsupported_encoding")
            if self.data.startswith(b"\xef\xbb\xbf"):
                self.pos = 3
            while self.pos < len(self.data):
                self.line = self.cov["lines_accepted"] + 1
                self.check()
                if self.cov["lines_seen"] >= self.limits.max_lines:
                    _stop("partial", "line_limit")
                self.step()
                self.cov["lines_seen"] += 1
                raw, end = self.read_line()
                kind, result = self.parse_line(raw)
                self.check()
                self.commit_line(kind, result, end)
            self.line = None
            self.check()
            if self.stage == 0:
                _stop("malformed", "missing_header")
            if self.stage != len(_ORDER):
                _stop("malformed", "missing_metadata")
            if not self.stats["pulse_count"]:
                _stop("malformed", "missing_raw_data")
            self.report["status"] = "complete"
            self.cov.update(eof_validated=True, analysis_complete=True, statistics_scope="whole_profile")
        except _Stop as stop:
            self.report["status"] = stop.status
            self.report["stop"] = {"code": stop.code, "line": self.line, "offset": self.pos}
        self.check(deadline=False)
        remaining = len(self.data) - self.pos
        self.cov.update(accepted_prefix_bytes=self.pos, remaining_bytes=remaining,
                        remaining_range={"offset": self.pos, "length": remaining} if remaining else None)
        encoded = json.dumps(self.report, ensure_ascii=True, separators=(",", ":"), allow_nan=False)
        if len(encoded.encode("ascii")) > self.limits.max_output_bytes:
            raise PwehError("RAW 검사 결과의 고정 출력 상한을 지키지 못했습니다.", code="rf_raw_failed")
        return self.report


def inspect_sub_raw(data: bytes, *, deadline: float, cancel: Callable[[], bool] | None = None,
                    limits: RawLimits = RawLimits()) -> dict:
    """완전한 bytes를 strict RAW 프로필로 검사한다. 시간 한도는 partial, 취소는 고정 오류다.

    통계는 수용한 완전한 줄만 포함한다. complete는 파일 문법 범위의 완료이며 실제
    캡처의 완전성·기기·대상·허가·재생 가능성을 검증했다는 뜻이 아니다.
    """
    end = _validate(data, limits, deadline, cancel)
    return _Inspector(data, limits, end, cancel).run()
