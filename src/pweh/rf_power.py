"""고정 rtl_power CSV의 선언과 보고된 전력 열을 검사한다. 파일·수신·해독은 없다."""
from __future__ import annotations

from dataclasses import dataclass, fields
import heapq
import json
import math
import re
import time
from typing import Callable

from .errors import PwehError, ValidationFailed

PROFILE = "rtl-power-blog-v1.4.0-csv"
SCHEMA = "pweh.rf-power-inspection/v1"
FALSE_FIELDS = ("input_completeness_verified", "capture_verified", "device_association_verified",
                "authorization_assessed", "decoded", "transmitted", "frequency_centers_verified",
                "power_calibration_verified")
LIMITATIONS = ("strict_profile_only", "accepted_rows_only", "reported_columns_not_fft_bins",
               "trailing_value_recomputed_by_producer", "row_times_not_returned_or_verified",
               "no_frequency_center_verification", "no_power_calibration_verification",
               "no_capture_completeness_verification", "no_device_or_authorization_verification",
               "no_protocol_decoding", "no_replay_or_transmission", "aggregate_statistics_are_not_anonymization")
_PARTIAL = ("input_limit", "line_limit", "line_length_limit", "value_limit", "step_limit", "time_limit", "truncated_row")
_UNSUPPORTED = ("empty_input", "unsupported_encoding", "unsupported_field", "nonfinite_value")
_MALFORMED = ("invalid_line_ending", "control_character", "field_count", "date_syntax", "time_syntax",
              "number_syntax", "number_range")
STOP_CODES = _PARTIAL + _UNSUPPORTED + _MALFORMED
_STATUS = {code: status for status, codes in (("partial", _PARTIAL), ("unsupported", _UNSUPPORTED),
                                           ("malformed", _MALFORMED)) for code in codes}
_I32, _I64 = (1 << 31) - 1, (1 << 63) - 1
_EXPONENT = re.compile(rb"[+-]?(?:[0-9]+(?:\.[0-9]*)?|\.[0-9]+)[eE][+-]?[0-9]+\Z")
_DATE = re.compile(rb"[0-9]{4}-[0-9]{2}-[0-9]{2}\Z")
_TIME = re.compile(rb"[0-9]{2}:[0-9]{2}:[0-9]{2}\Z")


@dataclass(frozen=True)
class PowerLimits:
    """기본 ceiling 이하로만 낮추는 한 호출의 예산."""

    max_bytes: int = 1 << 20
    max_line_bytes: int = 64 << 10
    max_rows: int = 4096
    max_values: int = 131072
    max_steps: int = 262144
    max_runtime_ms: int = 5000
    max_peaks: int = 32
    max_output_bytes: int = 60 << 10


class _Stop(Exception):
    def __init__(self, code: str):
        self.code = code


def _fail() -> PwehError:
    return PwehError("전력 CSV 검사 결과 또는 취소 상태를 확인하지 못했습니다.", code="rf_power_failed")


def _arguments(data, limits, deadline, cancel):
    try:
        if type(data) is not bytes or type(limits) is not PowerLimits:
            raise ValueError
        ceiling = PowerLimits()
        for field in fields(limits):
            value = getattr(limits, field.name)
            low = 16 << 10 if field.name == "max_output_bytes" else 1
            if type(value) is not int or not low <= value <= getattr(ceiling, field.name):
                raise ValueError
        if type(deadline) not in (int, float) or not math.isfinite(deadline):
            raise ValueError
        if cancel is not None and not callable(cancel):
            raise ValueError
        return float(deadline)
    except (ValueError, TypeError, OverflowError):
        raise ValidationFailed("전력 CSV 입력·한도·마감 시각이 허용 범위가 아닙니다.",
                               code="rf_power_input_invalid") from None


def _new(size):
    return {"schema": SCHEMA, "profile": PROFILE, "status": "partial",
            "statistics": {"rows_accepted": 0, "values_accepted": 0, "finite_values": 0,
                           "negative_infinity_values": 0, "low_hz_min": None, "high_hz_max": None,
                           "step_centi_hz_min": None, "step_centi_hz_max": None,
                           "power_centi_db_min": None, "power_centi_db_max": None},
            "peaks": [],
            "coverage": {"input_bytes": size, "accepted_prefix_bytes": 0, "remaining_bytes": size,
                         "remaining_range": {"offset": 0, "length": size} if size else None,
                         "rows_seen": 0, "rows_accepted": 0, "steps_used": 0, "peak_candidates_omitted": 0,
                         "eof_validated": False, "analysis_complete": False, "statistics_scope": "accepted_prefix",
                         **dict.fromkeys(FALSE_FIELDS, False)},
            "stop": None, "limitations": list(LIMITATIONS)}


def _keep(heap, item, cap):
    if len(heap) < cap:
        heapq.heappush(heap, item)
    elif item > heap[0]:
        heapq.heapreplace(heap, item)


class _Inspector:
    def __init__(self, data, limits, deadline, cancel):
        self.data, self.limits, self.cancel = data, limits, cancel
        self.deadline = min(deadline, time.monotonic() + limits.max_runtime_ms / 1000)
        self.report = _new(len(data))
        self.cov, self.stats = self.report["coverage"], self.report["statistics"]
        self.pos, self.heap = 0, []

    def check(self, *, timing=True):
        if self.cancel is not None:
            try:
                value = self.cancel()
                if type(value) is not bool:
                    raise ValueError
            except Exception:
                raise _fail() from None
            if value:
                raise PwehError("전력 CSV 검사가 취소되었습니다.", code="cancelled") from None
        if timing and time.monotonic() >= self.deadline:
            raise _Stop("time_limit")

    def step(self):
        self.check()
        if self.cov["steps_used"] >= self.limits.max_steps:
            raise _Stop("step_limit")
        self.cov["steps_used"] += 1

    def line(self):
        # 전체 파일 find 대신 최대4096B씩 찾아 시간·취소를 확인한다.
        end = min(len(self.data), self.pos + self.limits.max_line_bytes + 2)
        cursor, lf = self.pos, -1
        while cursor < end:
            self.check()
            stop = min(end, cursor + 4096)
            lf = self.data.find(b"\n", cursor, stop)
            if lf >= 0:
                break
            cursor = stop
        content_end = lf if lf >= 0 else end
        if lf >= 0 and content_end > self.pos and self.data[content_end - 1] == 13:
            content_end -= 1
        if content_end - self.pos > self.limits.max_line_bytes:
            raise _Stop("line_length_limit")
        raw = self.data[self.pos:content_end]
        for at in range(0, len(raw), 4096):
            self.check()
            part = raw[at:at + 4096]
            if any(byte >= 128 for byte in part):
                raise _Stop("unsupported_encoding")
            if 13 in part:
                raise _Stop("invalid_line_ending")
            if any(byte < 32 or byte == 127 for byte in part):
                raise _Stop("control_character")
        if lf < 0:
            raise _Stop("truncated_row")
        return raw, lf + 1

    def number(self, token, *, decimal=False, signed=False):
        self.step()
        if signed and token == b"-inf":
            return None
        if (token.lower() in (b"nan", b"+nan", b"-nan", b"inf", b"+inf", b"-inf",
                              b"infinity", b"+infinity", b"-infinity")
                or _EXPONENT.fullmatch(token)):
            raise _Stop("nonfinite_value")
        if not token or len(token) > (32 if decimal else 10):
            raise _Stop("number_syntax")
        digits = token[1:] if signed and token.startswith(b"-") else token
        if decimal:
            if len(digits) < 4 or digits[-3:-2] != b".":
                raise _Stop("number_syntax")
            whole, fraction = digits[:-3], digits[-2:]
            if not whole or any(c < 48 or c > 57 for c in whole + fraction):
                raise _Stop("number_syntax")
            value = int(whole) * 100 + int(fraction)
            cap = _I64 if signed else 280000000
            if value > cap or not signed and value == 0:
                raise _Stop("number_range")
            return -value if token.startswith(b"-") else value
        if any(c < 48 or c > 57 for c in digits):
            raise _Stop("number_syntax")
        value = int(digits)
        if value > _I32:
            raise _Stop("number_range")
        return value

    def row(self, raw):
        tokens = [token.strip(b" ") for token in raw.split(b",")]
        first = tokens[0]
        if (b'"' in raw or first.startswith(b"#")
                or first and (65 <= first[0] <= 90 or 97 <= first[0] <= 122)):
            raise _Stop("unsupported_field")
        if len(tokens) < 8:
            raise _Stop("field_count")
        day, clock = tokens[:2]
        if not _DATE.fullmatch(day) or not (1 <= int(day[5:7]) <= 12 and 1 <= int(day[8:]) <= 31):
            raise _Stop("date_syntax")
        if not _TIME.fullmatch(clock) or not (int(clock[:2]) <= 23 and int(clock[3:5]) <= 59 and int(clock[6:]) <= 60):
            raise _Stop("time_syntax")
        low, high = self.number(tokens[2]), self.number(tokens[3])
        step = self.number(tokens[4], decimal=True)
        samples = self.number(tokens[5])
        if low >= high or samples == 0:
            raise _Stop("number_range")
        count = finite = 0
        pmin = pmax = None
        heap = []
        row_index = self.stats["rows_accepted"]
        for index, token in enumerate(tokens[6:]):
            self.check()
            if self.stats["values_accepted"] + count >= self.limits.max_values:
                raise _Stop("value_limit")
            power = self.number(token, decimal=True, signed=True)
            count += 1
            if power is not None:
                finite += 1
                pmin = power if pmin is None else min(pmin, power)
                pmax = power if pmax is None else max(pmax, power)
                _keep(heap, (power, -row_index, -index, low, high, step, samples), self.limits.max_peaks)
        self.check()
        # 실패 행의 값·최댓값·선언 metadata는 전역 상태에 섞이지 않는다.
        stats = self.stats
        stats["rows_accepted"] += 1
        stats["values_accepted"] += count
        stats["finite_values"] += finite
        stats["negative_infinity_values"] += count - finite
        for key, value, choose in (("low_hz_min", low, min), ("high_hz_max", high, max),
                                   ("step_centi_hz_min", step, min), ("step_centi_hz_max", step, max),
                                   ("power_centi_db_min", pmin, min), ("power_centi_db_max", pmax, max)):
            if value is not None:
                stats[key] = value if stats[key] is None else choose(stats[key], value)
        for item in heap:
            _keep(self.heap, item, self.limits.max_peaks)

    def inspect(self):
        try:
            self.check()
            if len(self.data) > self.limits.max_bytes:
                raise _Stop("input_limit")
            if not self.data:
                raise _Stop("empty_input")
            while self.pos < len(self.data):
                self.check()
                if self.stats["rows_accepted"] >= self.limits.max_rows:
                    raise _Stop("line_limit")
                self.cov["rows_seen"] += 1
                raw, end = self.line()
                self.row(raw)
                self.pos = end
            self.report["status"] = "complete"
            self.cov["eof_validated"] = self.cov["analysis_complete"] = True
        except _Stop as stop:
            self.report["status"] = _STATUS[stop.code]
            self.report["stop"] = {"code": stop.code, "offset": self.pos,
                                   "row_index": self.stats["rows_accepted"]}
        cov = self.cov
        cov["accepted_prefix_bytes"] = self.pos
        cov["remaining_bytes"] = len(self.data) - self.pos
        cov["remaining_range"] = {"offset": self.pos, "length": cov["remaining_bytes"]} if cov["remaining_bytes"] else None
        cov["rows_accepted"] = self.stats["rows_accepted"]
        self.report["peaks"] = [
            {"row_index": -item[1], "value_index": -item[2], "low_hz": item[3], "high_hz": item[4],
             "step_centi_hz": item[5], "samples": item[6], "power_centi_db": item[0]}
            for item in sorted(self.heap, reverse=True)]
        cov["peak_candidates_omitted"] = self.stats["finite_values"] - len(self.heap)
        # 시간 partial은 bounded 조립 뒤에도 유지하며 취소는 끝까지 검사한다.
        self.check(timing=False)
        validate_power_accounting(self.report)
        if len(json.dumps(self.report, ensure_ascii=True, separators=(",", ":"), allow_nan=False).encode()) + 1 > self.limits.max_output_bytes:
            raise _fail()
        self.check(timing=False)
        return self.report


def inspect_power_csv(data: bytes, *, limits: PowerLimits = PowerLimits(), deadline: float,
                      cancel: Callable[[], bool] | None = None) -> dict:
    """한정 CSV를 원자 행 단위로 수용하고 정수 전력 순위를 돌려준다."""
    end = _arguments(data, limits, deadline, cancel)
    return _Inspector(data, limits, end, cancel).inspect()


def validate_power_accounting(report: dict) -> None:
    """원시 CSV를 다시 읽지 않고 exact 수치·상태·순위 관계만 검사한다."""
    try:
        _accounting(report)
    except (KeyError, TypeError, ValueError, OverflowError):
        raise _fail() from None


def _accounting(r):
    def require(value):
        if not value:
            raise ValueError

    def obj(value, keys):
        require(type(value) is dict and len(value) == len(keys) and set(value) == set(keys))

    def integer(value, low=0, high=1 << 20):
        require(type(value) is int and low <= value and (high is None or value <= high))
        return value

    obj(r, ("schema", "profile", "status", "statistics", "peaks", "coverage", "stop", "limitations"))
    require(r["schema"] == SCHEMA and r["profile"] == PROFILE)
    require(type(r["limitations"]) is list and r["limitations"] == list(LIMITATIONS))
    s, c, peaks = r["statistics"], r["coverage"], r["peaks"]
    obj(s, ("rows_accepted", "values_accepted", "finite_values", "negative_infinity_values", "low_hz_min",
            "high_hz_max", "step_centi_hz_min", "step_centi_hz_max", "power_centi_db_min", "power_centi_db_max"))
    obj(c, ("input_bytes", "accepted_prefix_bytes", "remaining_bytes", "remaining_range", "rows_seen", "rows_accepted",
            "steps_used", "peak_candidates_omitted", "eof_validated", "analysis_complete", "statistics_scope", *FALSE_FIELDS))
    size, accepted, remaining = integer(c["input_bytes"], high=None), integer(c["accepted_prefix_bytes"]), integer(c["remaining_bytes"], high=None)
    require(accepted + remaining == size)
    if remaining:
        obj(c["remaining_range"], ("offset", "length"))
        require(integer(c["remaining_range"]["offset"]) == accepted and integer(c["remaining_range"]["length"], 1, None) == remaining)
    else:
        require(c["remaining_range"] is None)
    rows, values = integer(s["rows_accepted"], high=4096), integer(s["values_accepted"], high=131072)
    finite = integer(s["finite_values"], high=131072)
    require(values == finite + integer(s["negative_infinity_values"], high=131072) and values >= rows * 2)
    require((rows == 0) == (values == 0) and (rows == 0) == (accepted == 0))
    require(integer(c["rows_accepted"], high=4096) == rows)
    seen = integer(c["rows_seen"], high=4096)
    require(seen in (rows, rows + 1))
    steps = integer(c["steps_used"], high=262144)
    require(steps >= values + 4 * rows)
    if seen == rows:
        require(steps == values + 4 * rows)
    declarations = ("low_hz_min", "high_hz_max", "step_centi_hz_min", "step_centi_hz_max")
    if not rows:
        require(all(s[key] is None for key in declarations))
    else:
        require(integer(s["low_hz_min"], 0, _I32) < integer(s["high_hz_max"], 1, _I32))
        require(integer(s["step_centi_hz_min"], 1, 280000000) <= integer(s["step_centi_hz_max"], 1, 280000000))
    require(type(peaks) is list and len(peaks) <= min(32, finite))
    if not finite:
        require(s["power_centi_db_min"] is None and s["power_centi_db_max"] is None and not peaks)
    else:
        require(integer(s["power_centi_db_min"], -_I64, _I64) <= integer(s["power_centi_db_max"], -_I64, _I64) and bool(peaks))
    require(integer(c["peak_candidates_omitted"], high=131072) == finite - len(peaks))
    previous, coordinates, metadata = None, set(), {}
    for p in peaks:
        obj(p, ("row_index", "value_index", "low_hz", "high_hz", "step_centi_hz", "samples", "power_centi_db"))
        row = integer(p["row_index"], 0, rows - 1)
        index = integer(p["value_index"], 0, values - 2 * (rows - 1) - 1)
        power = integer(p["power_centi_db"], s["power_centi_db_min"], s["power_centi_db_max"])
        low, high = integer(p["low_hz"], s["low_hz_min"], _I32), integer(p["high_hz"], 1, s["high_hz_max"])
        require(low < high)
        step = integer(p["step_centi_hz"], s["step_centi_hz_min"], s["step_centi_hz_max"])
        samples = integer(p["samples"], 1, _I32)
        key = (-power, row, index)
        require(previous is None or previous < key)
        require((row, index) not in coordinates)
        current = (low, high, step, samples)
        require(row not in metadata or metadata[row] == current)
        metadata[row] = current
        coordinates.add((row, index))
        previous = key
    if finite:
        require(peaks[0]["power_centi_db"] == s["power_centi_db_max"])
        if finite == len(peaks):
            require(peaks[-1]["power_centi_db"] == s["power_centi_db_min"])
    require(c["statistics_scope"] == "accepted_prefix" and all(c[key] is False for key in FALSE_FIELDS))
    require(type(c["analysis_complete"]) is bool and type(c["eof_validated"]) is bool)
    if r["status"] == "complete":
        require(r["stop"] is None and c["analysis_complete"] and c["eof_validated"] and remaining == 0)
        require(rows >= 1 and seen == rows and steps == values + rows * 4)
    else:
        stop = r["stop"]
        obj(stop, ("code", "offset", "row_index"))
        require(type(stop["code"]) is str and stop["code"] in STOP_CODES and r["status"] == _STATUS[stop["code"]])
        require(integer(stop["offset"]) == accepted and integer(stop["row_index"], high=4096) == rows)
        require(c["analysis_complete"] is False and c["eof_validated"] is False)
        require(remaining > 0 or size == 0 and stop["code"] in ("empty_input", "time_limit"))
        if stop["code"] == "empty_input":
            require(size == 0 and seen == steps == 0)
        if stop["code"] == "input_limit":
            require(accepted == seen == steps == 0)
