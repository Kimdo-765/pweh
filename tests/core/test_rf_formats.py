"""합성 RAW bytes의 문법·통계·한도·원문 비노출 회귀. 파일·RF 실행은 없다."""
from __future__ import annotations

import builtins
import dataclasses
import json
import socket
import subprocess
import time

import pytest

from pweh import rf_formats as R
from pweh.errors import PwehError, ValidationFailed


def header(*, preset=R.PRESETS[0], frequency="123456789", version="1", protocol="RAW", newline=b"\n"):
    return newline.join([
        b"Filetype: Flipper SubGhz RAW File", b"Version: " + version.encode(),
        b"Frequency: " + frequency.encode(), b"Preset: " + preset.encode(),
        b"Protocol: " + protocol.encode(),
    ]) + newline


def sample(*lines, newline=b"\n", final=True, **kw):
    values = lines or ("100 -200 300 -400",)
    result = header(newline=newline, **kw) + newline.join(b"RAW_Data: " + v.encode() for v in values)
    return result + (newline if final else b"")


def inspect(data, **kw):
    return R.inspect_sub_raw(data, deadline=kw.pop("deadline", time.monotonic() + 30), **kw)


def invariant(report, data, *, limits=R.RawLimits()):
    assert set(report) == {"schema", "status", "profile", "metadata", "statistics", "coverage", "stop", "limitations"}
    assert report["schema"] == "pweh.rf-raw-inspection/v1"
    assert report["profile"] == "flipper-subghz-raw-v1-strict"
    assert report["status"] in {"complete", "partial", "malformed", "unsupported"}
    assert set(report["metadata"]) == {"filetype", "version", "declared_frequency_hz", "declared_preset", "protocol"}
    meta = report["metadata"]
    assert meta["filetype"] in (None, "Flipper SubGhz RAW File")
    assert meta["version"] in (None, 1)
    assert meta["protocol"] in (None, "RAW")
    assert meta["declared_preset"] is None or meta["declared_preset"] in R.PRESETS
    if meta["declared_frequency_hz"] is not None:
        assert type(meta["declared_frequency_hz"]) is int and 0 <= meta["declared_frequency_hz"] <= 0xffffffff
    cov = report["coverage"]
    assert set(cov) == {
        "input_bytes", "accepted_prefix_bytes", "remaining_bytes", "remaining_range", "lines_seen",
        "lines_accepted", "steps_used", "eof_validated", "analysis_complete", "statistics_scope",
        "input_completeness_verified", "capture_verified", "device_association_verified",
        "authorization_assessed", "decoded", "transmitted",
    }
    assert cov["input_bytes"] == len(data)
    assert cov["accepted_prefix_bytes"] + cov["remaining_bytes"] == len(data)
    assert 0 <= cov["lines_accepted"] <= cov["lines_seen"] <= limits.max_lines
    assert 0 <= cov["steps_used"] <= limits.max_steps
    assert cov["remaining_range"] == ({"offset": cov["accepted_prefix_bytes"], "length": cov["remaining_bytes"]}
                                      if cov["remaining_bytes"] else None)
    for flag in ("input_completeness_verified", "capture_verified", "device_association_verified",
                 "authorization_assessed", "decoded", "transmitted"):
        assert cov[flag] is False
    stats = report["statistics"]
    assert set(stats) == {"pulse_count", "declared_duration_us", "raw_data_lines_accepted", "positive", "negative"}
    for sign in ("positive", "negative"):
        row = stats[sign]
        assert set(row) == {"count", "min_us", "max_us", "sum_us"}
        assert type(row["count"]) is int and row["count"] >= 0
        if row["count"]:
            assert 0 < row["min_us"] <= row["max_us"] <= 1 << 31
            assert row["min_us"] * row["count"] <= row["sum_us"] <= row["max_us"] * row["count"]
        else:
            assert row == {"count": 0, "min_us": None, "max_us": None, "sum_us": 0}
    assert stats["pulse_count"] == stats["positive"]["count"] + stats["negative"]["count"] <= limits.max_pulses
    assert stats["declared_duration_us"] == stats["positive"]["sum_us"] + stats["negative"]["sum_us"] <= limits.max_duration_us
    assert stats["raw_data_lines_accepted"] <= cov["lines_accepted"]
    complete = report["status"] == "complete"
    assert cov["analysis_complete"] is complete and cov["eof_validated"] is complete
    assert cov["statistics_scope"] == ("whole_profile" if complete else "accepted_prefix")
    if complete:
        assert report["stop"] is None and not cov["remaining_bytes"]
    else:
        assert set(report["stop"]) == {"code", "line", "offset"}
        assert report["stop"]["code"] in R.STOP_CODES
        assert report["stop"]["offset"] == cov["accepted_prefix_bytes"]
        assert report["stop"]["line"] is None or type(report["stop"]["line"]) is int
    assert len(json.dumps(report, ensure_ascii=True, separators=(",", ":")).encode()) <= limits.max_output_bytes


@pytest.mark.parametrize("preset", R.PRESETS)
@pytest.mark.parametrize("newline,final,bom", [(b"\n", True, False), (b"\r\n", True, True), (b"\n", False, False)])
def test_supported_profile_exact_statistics(preset, newline, final, bom):
    data = (b"\xef\xbb\xbf" if bom else b"") + sample("100 -200 300", "-400 500", preset=preset, newline=newline, final=final)
    report = inspect(data)
    assert report["status"] == "complete"
    assert report["statistics"] == {
        "pulse_count": 5, "declared_duration_us": 1500, "raw_data_lines_accepted": 2,
        "positive": {"count": 3, "min_us": 100, "max_us": 500, "sum_us": 900},
        "negative": {"count": 2, "min_us": 200, "max_us": 400, "sum_us": 600},
    }
    invariant(report, data)


def test_comments_spacing_and_single_positive():
    data = "\ufeff# PWEH 합성 주석\r\n\t  \r\n".encode() + sample(" \t0012  \t", final=False)
    data = data.replace(b"Version: 1", b"Version:\t0001 ")
    report = inspect(data)
    assert report["status"] == "complete"
    assert report["statistics"]["pulse_count"] == 1
    assert report["statistics"]["positive"]["sum_us"] == 12
    assert "합성" not in json.dumps(report, ensure_ascii=False)
    invariant(report, data)


@pytest.mark.parametrize("frequency", ["0", "4294967295", "0000000123"])
def test_frequency_is_uint32_declaration_not_rf_permission(frequency):
    data = sample("2147483647 -2147483648", frequency=frequency)
    report = inspect(data)
    assert report["status"] == "complete"
    assert report["metadata"]["declared_frequency_hz"] == int(frequency)
    assert report["statistics"]["declared_duration_us"] == 4294967295
    invariant(report, data)


@pytest.mark.parametrize("data,status,code", [
    (b"", "malformed", "missing_header"),
    (b"\xef\xbb\xbf# SYNTHETIC\n", "malformed", "missing_header"),
    (b"Filetype:\n", "malformed", "empty_value"),
    (b"Filetype: Flipper SubGhz Key File\n", "unsupported", "unsupported_filetype"),
    (header(version="2"), "unsupported", "unsupported_version"),
    (header(version="x"), "malformed", "integer_syntax"),
    (header(protocol="BinRAW"), "unsupported", "unsupported_protocol"),
    (header(preset="FuriHalSubGhzPresetCustom"), "unsupported", "unsupported_preset"),
    (header(preset="SYNTHETIC_SECRET_PRESET"), "unsupported", "unsupported_preset"),
    (header() + b"Key: SYNTHETIC_SECRET\n", "unsupported", "unsupported_field"),
    (header() + b"SyntheticField2: SYNTHETIC_SECRET\n", "unsupported", "unsupported_field"),
    (header() + b"File_name: SYNTHETIC_SECRET\n", "unsupported", "unsupported_field"),
    (b"RAW_Data: 1 -2\n", "malformed", "metadata_incomplete"),
    (b"Version: 1\n", "malformed", "metadata_order"),
    (b"Filetype: Flipper SubGhz RAW File\n", "malformed", "missing_metadata"),
    (header(), "malformed", "missing_raw_data"),
    (header() + b"Version: 1\n", "malformed", "duplicate_field"),
    (sample() + b"Frequency: 123456789\n", "malformed", "duplicate_field"),
    (header() + b"RAW_Data:\n", "malformed", "empty_value"),
    (header() + b"RAW_Data 1 -2\n", "malformed", "field_syntax"),
    (header() + b" RAW_Data: 1 -2\n", "malformed", "field_syntax"),
    (header() + b"RAW_Data : 1 -2\n", "malformed", "field_syntax"),
    (header() + b"raw_data: 1 -2\n", "unsupported", "unsupported_field"),
    (b"\xff\xfe\x00\x00", "unsupported", "unsupported_encoding"),
    (b"\x00\x00\xfe\xff", "unsupported", "unsupported_encoding"),
    (b"\xfe\xff", "unsupported", "unsupported_encoding"),
    (header() + b"# \xffSYNTHETIC_SECRET\n", "malformed", "invalid_utf8"),
    (header() + b"# \x00SYNTHETIC_SECRET\n", "malformed", "control_character"),
    (header() + b"# \x7fSYNTHETIC_SECRET\n", "malformed", "control_character"),
    (header() + "# \u0085SYNTHETIC_SECRET\n".encode(), "malformed", "control_character"),
    (header() + b"# \xef\xbb\xbf\n", "malformed", "unexpected_bom"),
    (header() + b"RAW_Data: 1\r", "malformed", "invalid_line_ending"),
    (header() + b"# x\ry\n", "malformed", "invalid_line_ending"),
])
def test_malformed_vs_unsupported_without_raw_errors(data, status, code):
    report = inspect(data)
    assert report["status"] == status
    assert report["stop"]["code"] == code
    assert "SYNTHETIC_SECRET" not in json.dumps(report)
    invariant(report, data)


@pytest.mark.parametrize("tokens,code", [
    ("0", "zero_duration"), ("-0", "zero_duration"), ("-1", "sign_not_alternating"),
    ("1 2", "sign_not_alternating"), ("1 -2 -3", "sign_not_alternating"),
    ("+1", "integer_syntax"), ("-", "integer_syntax"), ("1x", "integer_syntax"),
    ("1.0", "integer_syntax"), ("1e2", "integer_syntax"), ("0x10", "integer_syntax"),
    ("1_000", "integer_syntax"), ("١", "integer_syntax"),
    ("2147483648", "integer_range"), ("1 -2147483649", "integer_range"),
    ("111111111111", "integer_width"), ("1 # SYNTHETIC_SECRET", "integer_syntax"),
])
def test_bad_pulse_line_is_atomic(tokens, code):
    prefix = sample("7 -9")
    data = prefix + b"RAW_Data: " + tokens.encode() + b"\nRAW_Data: 15 -17\n"
    report = inspect(data)
    assert report["status"] == "malformed"
    assert report["stop"]["code"] == code
    assert report["coverage"]["accepted_prefix_bytes"] == len(prefix)
    assert report["statistics"] == inspect(prefix)["statistics"]
    assert "SYNTHETIC_SECRET" not in json.dumps(report)
    invariant(report, data)


@pytest.mark.parametrize("value,code", [("-1", "integer_syntax"), ("+1", "integer_syntax"),
    ("1e2", "integer_syntax"), ("4294967296", "integer_range"), ("00000000001", "integer_width")])
def test_unsigned_fields_are_strict(value, code):
    data = sample(frequency=value)
    report = inspect(data)
    assert report["status"] == "malformed" and report["stop"]["code"] == code
    assert report["metadata"]["declared_frequency_hz"] is None
    invariant(report, data)


def test_sign_state_continues_across_lines_and_comments():
    prefix = sample("1", final=True)
    data = prefix + b"# SYNTHETIC\nRAW_Data: 2 -3\n"
    report = inspect(data)
    assert report["stop"]["code"] == "sign_not_alternating"
    assert report["statistics"]["pulse_count"] == 1
    invariant(report, data)


def test_first_pulse_must_be_positive():
    data = sample("-1 2")
    report = inspect(data)
    assert report["status"] == "malformed" and report["stop"]["code"] == "first_negative"
    assert report["statistics"]["pulse_count"] == 0
    assert report["coverage"]["accepted_prefix_bytes"] == len(header())
    invariant(report, data)


def test_line_512_is_grammar_not_partial_budget():
    line = " ".join("1" if i % 2 == 0 else "-1" for i in range(512))
    good, bad = sample(line), sample(line + " 1")
    assert inspect(good)["status"] == "complete"
    report = inspect(bad)
    assert report["status"] == "malformed" and report["stop"]["code"] == "line_pulse_count"
    assert report["statistics"]["pulse_count"] == 0
    invariant(report, bad)


@pytest.mark.parametrize("name,cap,code", [
    ("max_pulses", 2, "pulse_limit"), ("max_duration_us", 3, "duration_limit"),
    ("max_steps", 10, "step_limit"),
])
def test_global_limits_rollback_whole_raw_line(name, cap, code):
    prefix = sample("1 -2")  # header 7 steps + RAW line 3 steps
    data = prefix + b"RAW_Data: 3 -4\n"
    limits = dataclasses.replace(R.RawLimits(), **{name: cap})
    report = inspect(data, limits=limits)
    assert report["status"] == "partial" and report["stop"]["code"] == code
    assert report["statistics"]["pulse_count"] == 2
    assert report["coverage"]["accepted_prefix_bytes"] == len(prefix)
    assert inspect(prefix, limits=limits)["status"] == "complete"
    invariant(report, data, limits=limits)


@pytest.mark.parametrize("name,cap,code", [("max_pulses", 3, "pulse_limit"),
    ("max_duration_us", 6, "duration_limit"), ("max_steps", 13, "step_limit")])
def test_limit_inside_next_line_never_commits_prefix_tokens(name, cap, code):
    prefix = sample("1 -2")
    data = prefix + b"RAW_Data: 3 -4 5\n"
    limits = dataclasses.replace(R.RawLimits(), **{name: cap})
    report = inspect(data, limits=limits)
    assert report["status"] == "partial" and report["stop"]["code"] == code
    assert report["statistics"]["pulse_count"] == 2
    assert report["coverage"]["accepted_prefix_bytes"] == len(prefix)
    invariant(report, data, limits=limits)


def test_input_size_limit_does_not_decode_prefix():
    data = sample()
    exact = dataclasses.replace(R.RawLimits(), max_bytes=len(data))
    assert inspect(data, limits=exact)["status"] == "complete"
    for too_long in (data + b"\n", b"\xff" * ((1 << 20) + 1)):
        limits = exact if len(too_long) < 1 << 20 else R.RawLimits()
        report = inspect(too_long, limits=limits)
        assert report["status"] == "partial" and report["stop"]["code"] == "input_limit"
        assert report["coverage"]["accepted_prefix_bytes"] == report["coverage"]["lines_seen"] == 0
        invariant(report, too_long, limits=limits)


@pytest.mark.parametrize("newline,final", [(b"\n", True), (b"\r\n", True), (b"\n", False)])
def test_line_length_exact_and_plus_one(newline, final):
    prefix = sample()
    comment = b"#" + b"s" * 127
    exact = prefix + comment + (newline if final else b"")
    limits = dataclasses.replace(R.RawLimits(), max_line_bytes=128)
    assert inspect(exact, limits=limits)["status"] == "complete"
    bad = prefix + comment + b"s" + (newline if final else b"")
    report = inspect(bad, limits=limits)
    assert report["status"] == "partial" and report["stop"]["code"] == "line_length_limit"
    assert report["coverage"]["accepted_prefix_bytes"] == len(prefix)
    invariant(report, bad, limits=limits)


def test_line_count_exact_and_plus_one():
    exact = sample()
    limits = dataclasses.replace(R.RawLimits(), max_lines=6)
    assert inspect(exact, limits=limits)["status"] == "complete"
    report = inspect(exact + b"\n", limits=limits)
    assert report["stop"]["code"] == "line_limit"
    invariant(report, exact + b"\n", limits=limits)


def test_default_maximum_pulses_remain_bounded_and_exact():
    line = " ".join("1" if i % 2 == 0 else "-1" for i in range(512))
    data = sample(*([line] * 128))
    report = inspect(data)
    assert report["status"] == "complete"
    assert report["statistics"]["pulse_count"] == 65536
    assert report["statistics"]["declared_duration_us"] == 65536
    invariant(report, data)


@pytest.mark.parametrize("deadline", [True, None, "5", float("inf"), float("-inf"), float("nan"), 10 ** 400])
def test_invalid_deadline_fixed_error(deadline):
    with pytest.raises(ValidationFailed) as error:
        inspect(sample(), deadline=deadline)
    assert error.value.message == "RAW 검사 입력·한도·마감 시각이 허용 범위가 아닙니다."


@pytest.mark.parametrize("value", [True, 0, -1, 1.0, None, 10 ** 400])
@pytest.mark.parametrize("field", dataclasses.fields(R.RawLimits()))
def test_limits_only_lower_integer_ceilings(field, value):
    limits = dataclasses.replace(R.RawLimits(), **{field.name: value})
    with pytest.raises(ValidationFailed):
        inspect(sample(), limits=limits)


@pytest.mark.parametrize("field", dataclasses.fields(R.RawLimits()))
def test_increased_limits_refused(field):
    defaults = R.RawLimits()
    with pytest.raises(ValidationFailed):
        inspect(sample(), limits=dataclasses.replace(defaults, **{field.name: getattr(defaults, field.name) + 1}))


def test_limits_frozen_and_output_floor():
    limits = R.RawLimits()
    with pytest.raises(dataclasses.FrozenInstanceError):
        limits.max_pulses = 10
    with pytest.raises(ValidationFailed):
        inspect(sample(), limits=dataclasses.replace(limits, max_output_bytes=4095))
    small = dataclasses.replace(limits, max_output_bytes=4096)
    invariant(inspect(sample(), limits=small), sample(), limits=small)


@pytest.mark.parametrize("data", ["RAW_Data: 1", bytearray(b"RAW_Data: 1"), memoryview(b"x"), None, 1])
def test_only_immutable_bytes(data):
    with pytest.raises(ValidationFailed):
        inspect(data)


def test_exact_limits_class_and_callback_validation():
    class SubLimits(R.RawLimits):
        pass
    with pytest.raises(ValidationFailed):
        inspect(sample(), limits=SubLimits())
    with pytest.raises(ValidationFailed):
        inspect(sample(), cancel=True)


class Clock:
    def __init__(self):
        self.now = 0.0

    def __call__(self):
        return self.now


@pytest.mark.parametrize("requested,ceiling", [(100.0, 5.0), (0.1, 0.1)])
def test_effective_deadline_is_capped(monkeypatch, requested, ceiling):
    clock = Clock()
    monkeypatch.setattr(R.time, "monotonic", clock)
    calls = 0
    def cancel():
        nonlocal calls
        calls += 1
        if calls == 2:
            clock.now = ceiling
        return False
    data = sample()
    report = inspect(data, deadline=requested, cancel=cancel)
    assert report["status"] == "partial" and report["stop"]["code"] == "time_limit"
    assert report["coverage"]["accepted_prefix_bytes"] == 0
    invariant(report, data)


def test_lower_runtime_ceiling(monkeypatch):
    clock = Clock()
    monkeypatch.setattr(R.time, "monotonic", clock)
    calls = 0
    def cancel():
        nonlocal calls
        calls += 1
        if calls > 1:
            clock.now = .001
        return False
    limits = dataclasses.replace(R.RawLimits(), max_runtime_ms=1)
    report = inspect(sample(), deadline=100.0, cancel=cancel, limits=limits)
    assert report["status"] == "partial" and report["stop"]["code"] == "time_limit"


def test_past_deadline_and_eof_without_more_bytes(monkeypatch):
    monkeypatch.setattr(R.time, "monotonic", lambda: 5.0)
    report = inspect(sample(), deadline=5)
    assert report["status"] == "partial" and not report["statistics"]["pulse_count"]
    for data, code in ((b"", "missing_header"), (header(), "missing_raw_data")):
        report = inspect(data, deadline=10)
        assert report["stop"]["code"] == code
        assert report["coverage"]["remaining_bytes"] == 0
        invariant(report, data)


def test_deadline_mid_line_rolls_back_and_malformed_is_not_overwritten(monkeypatch):
    clock = Clock()
    monkeypatch.setattr(R.time, "monotonic", clock)
    real_number = R._Inspector.number
    def number(self, token, *, signed):
        value = real_number(self, token, signed=signed)
        if token == b"30":
            clock.now = 5
        return value
    monkeypatch.setattr(R._Inspector, "number", number)
    prefix = sample("1 -2")
    data = prefix + b"RAW_Data: 30 -40\n"
    report = inspect(data, deadline=100)
    assert report["status"] == "partial" and report["stop"]["code"] == "time_limit"
    assert report["coverage"]["accepted_prefix_bytes"] == len(prefix)
    assert report["statistics"]["pulse_count"] == 2
    invariant(report, data)
    clock.now = 0
    report = inspect(prefix + b"RAW_Data: 30 0\n", deadline=100)
    assert report["stop"]["code"] == "time_limit"  # 아직 보지 않은 0의 오류를 추정하지 않는다.
    clock.now = 0
    real_stop = R._stop
    def stop(status, code):
        if status == "malformed":
            clock.now = 5
        real_stop(status, code)
    monkeypatch.setattr(R, "_stop", stop)
    report = inspect(prefix + b"RAW_Data: 0\n", deadline=100)
    assert report["status"] == "malformed" and report["stop"]["code"] == "zero_duration"


@pytest.mark.parametrize("at", [1, 5, 20, 30])
def test_cancellation_is_fixed_error_at_multiple_phases(at):
    calls = 0
    def cancel():
        nonlocal calls
        calls += 1
        return calls >= at
    with pytest.raises(PwehError) as error:
        inspect(sample(*(["1 -2"] * 20)), cancel=cancel)
    assert error.value.code == "cancelled"
    assert error.value.to_dict() == {"code": "cancelled", "message": "RAW 검사가 취소되었습니다."}


@pytest.mark.parametrize("result", [0, 1, None, "SYNTHETIC_SECRET"])
def test_cancel_non_bool_fixed_error(result):
    with pytest.raises(PwehError) as error:
        inspect(sample(), cancel=lambda: result)
    assert error.value.code == "rf_raw_failed"
    assert "SYNTHETIC_SECRET" not in str(error.value)


def test_cancel_exception_is_not_exposed():
    def cancel():
        raise RuntimeError("SYNTHETIC_SECRET_CALLBACK")
    with pytest.raises(PwehError) as error:
        inspect(sample(), cancel=cancel)
    assert error.value.code == "rf_raw_failed"
    assert "SYNTHETIC_SECRET" not in str(error.value)
    assert error.value.__suppress_context__ is True


def test_eof_cancellation_before_return(monkeypatch):
    cancelled = False
    real_commit = R._Inspector.commit_line
    def commit(self, kind, result, end):
        nonlocal cancelled
        real_commit(self, kind, result, end)
        if end == len(self.data):
            cancelled = True
    monkeypatch.setattr(R._Inspector, "commit_line", commit)
    with pytest.raises(PwehError) as error:
        inspect(sample(), cancel=lambda: cancelled)
    assert error.value.code == "cancelled"


def test_metadata_is_not_committed_after_deadline(monkeypatch):
    clock = Clock()
    monkeypatch.setattr(R.time, "monotonic", clock)
    real_parse = R._Inspector.parse_line
    def parse(self, raw):
        result = real_parse(self, raw)
        if raw.startswith(b"Frequency:"):
            clock.now = 5
        return result
    monkeypatch.setattr(R._Inspector, "parse_line", parse)
    data = sample()
    report = inspect(data, deadline=100)
    assert report["stop"]["code"] == "time_limit"
    assert report["metadata"]["version"] == 1
    assert report["metadata"]["declared_frequency_hz"] is None
    assert report["coverage"]["accepted_prefix_bytes"] == data.index(b"Frequency:")
    invariant(report, data)


def test_no_io_dependencies(monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError("외부 I/O가 발생했습니다.")
    monkeypatch.setattr(builtins, "open", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)
    monkeypatch.setattr(socket, "socket", forbidden)
    report = inspect(sample())
    assert report["status"] == "complete"


def test_reports_do_not_share_mutable_state():
    one = inspect(sample())
    one["metadata"]["declared_preset"] = "SYNTHETIC_SECRET"
    one["statistics"]["positive"]["count"] = 999
    one["limitations"].append("SYNTHETIC_SECRET")
    two = inspect(sample())
    assert "SYNTHETIC_SECRET" not in json.dumps(two)
    invariant(two, sample())
