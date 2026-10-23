"""고정 CSV 문법·원자 행·정수 순위를 실제 수신 없이 검사한다."""
from dataclasses import fields, replace
import json
import time

import pytest

from pweh import rf_power as P
from pweh.errors import PwehError, ValidationFailed


def row(*powers, low="100", high="200", step="0.33", samples="3",
        date="2026-02-31", clock="23:59:60", newline=b"\n"):
    """producer 실행 대신 독립 문법 fixture를 만든다."""
    values = (date, clock, low, high, step, samples, *(powers or ("-12.34", "-56.78")))
    return b", ".join(str(v).encode("ascii") for v in values) + newline


def inspect(data, **kwargs):
    return P.inspect_power_csv(data, deadline=time.monotonic() + 5, **kwargs)


def test_integer_statistics_and_trailing_columns_are_preserved():
    data = row("-12.34", "-12.34", newline=b"\r\n") + row("-inf", "-0.00", "1.23", clock="00:00:00")
    r = inspect(data)
    assert r["status"] == "complete" and r["stop"] is None
    assert r["statistics"] == {
        "rows_accepted": 2, "values_accepted": 5, "finite_values": 4,
        "negative_infinity_values": 1, "low_hz_min": 100, "high_hz_max": 200,
        "step_centi_hz_min": 33, "step_centi_hz_max": 33,
        "power_centi_db_min": -1234, "power_centi_db_max": 123,
    }
    assert [(p["power_centi_db"], p["row_index"], p["value_index"]) for p in r["peaks"]] == [
        (123, 1, 2), (0, 1, 1), (-1234, 0, 0), (-1234, 0, 1)]
    c = r["coverage"]
    assert c["accepted_prefix_bytes"] == c["input_bytes"] == len(data)
    assert c["remaining_bytes"] == 0 and c["remaining_range"] is None
    assert c["steps_used"] == 13 and c["statistics_scope"] == "accepted_prefix"
    assert all(c[key] is False for key in P.FALSE_FIELDS)
    encoded = json.dumps(r)
    assert "2026-02-31" not in encoded and "23:59:60" not in encoded


def test_all_negative_infinity_is_complete_and_has_no_peaks():
    r = inspect(row("-inf", "-inf"))
    assert r["status"] == "complete" and r["peaks"] == []
    assert r["statistics"]["negative_infinity_values"] == 2
    assert r["statistics"]["power_centi_db_min"] is None
    assert r["coverage"]["peak_candidates_omitted"] == 0


def test_declared_width_is_not_used_to_invent_bin_count():
    r = inspect(row("1.11", "2.22", "3.33", low="0", high="2147483647", step="0.01", samples="2147483647"))
    assert r["status"] == "complete" and r["statistics"]["values_accepted"] == 3
    assert r["peaks"][0]["samples"] == 2147483647


def test_extreme_integer_powers_and_step_fit_small_output():
    values = ("92233720368547758.07", "-92233720368547758.07") * 16
    r = inspect(row(*values, step="2800000.00"), limits=replace(P.PowerLimits(), max_output_bytes=16384))
    assert r["statistics"]["power_centi_db_max"] == (1 << 63) - 1
    assert r["statistics"]["power_centi_db_min"] == -((1 << 63) - 1)
    assert len(r["peaks"]) == 32
    assert len(json.dumps(r, ensure_ascii=True, separators=(",", ":")).encode()) + 1 <= 16384


def test_top32_ties_keep_earlier_row_and_value_including_inf_positions():
    data = row("-inf", *("7.00" for _ in range(20))) + row(*( "7.00" for _ in range(20)))
    r = inspect(data)
    assert [(p["row_index"], p["value_index"]) for p in r["peaks"]] == (
        [(0, n) for n in range(1, 21)] + [(1, n) for n in range(12)])
    assert r["coverage"]["peak_candidates_omitted"] == 8 and r["status"] == "complete"


def test_later_stronger_values_replace_heap_and_negative_values_sort():
    r = inspect(row(*(f"-{n}.00" for n in range(40))) + row("1.00", "2.00"))
    assert [p["power_centi_db"] for p in r["peaks"]] == [200, 100] + [-n * 100 for n in range(30)]
    assert r["statistics"]["power_centi_db_min"] == -3900


@pytest.mark.parametrize("data,status,code", [
    (b"", "unsupported", "empty_input"),
    (b"\xef\xbb\xbf" + row(), "unsupported", "unsupported_encoding"),
    (b"\xff\xfe2\x000\x002\x006\x00\n", "unsupported", "unsupported_encoding"),
    (b"# PRIVATE_ROW\n", "unsupported", "unsupported_field"),
    (b"date,time,low,high,step,samples,power,power\n", "unsupported", "unsupported_field"),
    (b'"PRIVATE_ROW"\n', "unsupported", "unsupported_field"),
    (b"\n", "malformed", "field_count"),
    (b"2026-01-01,00:00:00,1,2,1.00,1,0.00\n", "malformed", "field_count"),
    (row(date="2026-13-01"), "malformed", "date_syntax"),
    (row(date="2026-00-01"), "malformed", "date_syntax"),
    (row(date="2026-01-00"), "malformed", "date_syntax"),
    (row(date="2026-01-32"), "malformed", "date_syntax"),
    (row(date="26-01-01"), "malformed", "date_syntax"),
    (row(clock="24:00:00"), "malformed", "time_syntax"),
    (row(clock="00:60:00"), "malformed", "time_syntax"),
    (row(clock="00:00:61"), "malformed", "time_syntax"),
    (row(clock="0:00:00"), "malformed", "time_syntax"),
    (row().replace(b", ", b",\t", 1), "malformed", "control_character"),
    (row().replace(b", ", b",\x00", 1), "malformed", "control_character"),
    (row().replace(b", ", b",\x7f", 1), "malformed", "control_character"),
    (row().replace(b", ", b",\r", 1), "malformed", "invalid_line_ending"),
    (row(newline=b""), "partial", "truncated_row"),
    (row(newline=b"\r"), "malformed", "invalid_line_ending"),
])
def test_fixed_grammar_status_and_no_raw_echo(data, status, code):
    r = inspect(data)
    assert r["status"] == status and r["stop"] == {"code": code, "offset": 0, "row_index": 0}
    assert r["statistics"]["rows_accepted"] == 0 and r["peaks"] == []
    assert r["coverage"]["remaining_bytes"] == len(data)
    assert "PRIVATE_ROW" not in json.dumps(r)


@pytest.mark.parametrize("field,value,code", [
    ("low", "-1", "number_syntax"), ("low", "+1", "number_syntax"),
    ("low", "00000000000", "number_syntax"), ("low", "200", "number_range"),
    ("high", "2147483648", "number_range"), ("samples", "0", "number_range"),
    ("samples", "2147483648", "number_range"), ("step", "0.00", "number_range"),
    ("step", "2800000.01", "number_range"), ("step", "-1.00", "number_syntax"),
    ("step", "1.0", "number_syntax"), ("step", "1", "number_syntax"),
    ("step", "1.000", "number_syntax"), ("step", ".01", "number_syntax"),
    ("step", "+1.00", "number_syntax"), ("step", "1e2", "nonfinite_value"),
    ("samples", "1e2", "nonfinite_value"), ("high", "inf", "nonfinite_value"),
])
def test_metadata_numeric_rejections(field, value, code):
    r = inspect(row(**{field: value}))
    assert r["stop"]["code"] == code and r["statistics"]["rows_accepted"] == 0


@pytest.mark.parametrize("value,code", [
    ("+1.00", "number_syntax"), (".00", "number_syntax"), ("1.", "number_syntax"),
    ("1.0", "number_syntax"), ("1.000", "number_syntax"), ("", "number_syntax"),
    ("0" * 30 + ".00", "number_syntax"), ("92233720368547758.08", "number_range"),
    ("-92233720368547758.08", "number_range"), ("NaN", "nonfinite_value"),
    ("nan", "nonfinite_value"), ("+inf", "nonfinite_value"), ("-INF", "nonfinite_value"),
    ("Infinity", "nonfinite_value"), ("-infinity", "nonfinite_value"),
    ("1e2", "nonfinite_value"), ("-1.20E-3", "nonfinite_value"),
])
def test_power_numeric_rejections_are_row_atomic(value, code):
    first = row("-1.00", "-2.00")
    r = inspect(first + row("999.99", value, low="1", high="999", step="2.00"))
    assert r["stop"] == {"code": code, "offset": len(first), "row_index": 1}
    assert r["coverage"]["rows_seen"] == 2 and r["statistics"]["values_accepted"] == 2
    assert r["statistics"]["power_centi_db_max"] == -100
    assert r["statistics"]["low_hz_min"] == 100 and r["statistics"]["high_hz_max"] == 200
    assert r["statistics"]["step_centi_hz_max"] == 33
    assert [p["power_centi_db"] for p in r["peaks"]] == [-100, -200]


@pytest.mark.parametrize("field,cap,code,accepted,seen,steps", [
    ("max_bytes", 1, "input_limit", 0, 0, 0),
    ("max_line_bytes", 1, "line_length_limit", 0, 1, 0),
    ("max_rows", 1, "line_limit", 1, 1, 6),
    ("max_values", 3, "value_limit", 1, 2, 11),
    ("max_steps", 8, "step_limit", 1, 2, 8),
])
def test_lower_limits_preserve_exact_accepted_prefix(field, cap, code, accepted, seen, steps):
    data = row() * 2
    r = inspect(data, limits=replace(P.PowerLimits(), **{field: cap}))
    assert r["status"] == "partial" and r["stop"]["code"] == code
    assert r["statistics"]["rows_accepted"] == accepted
    assert r["coverage"]["rows_seen"] == seen and r["coverage"]["steps_used"] == steps
    assert r["coverage"]["accepted_prefix_bytes"] == accepted * len(row())


@pytest.mark.parametrize("newline", [b"\n", b"\r\n"])
def test_line_exact_ceiling_and_first_excess_byte(newline):
    base = row(newline=newline)
    data = b" " * (65536 - (len(base) - len(newline))) + base
    assert inspect(data)["status"] == "complete"
    r = inspect(b" " + data)
    assert r["stop"]["code"] == "line_length_limit" and r["coverage"]["accepted_prefix_bytes"] == 0


def test_input_exact_ceiling_and_first_excess_byte():
    base = row()
    data = (b" " * (65536 - len(base)) + base) * 16
    assert len(data) == 1 << 20 and inspect(data)["status"] == "complete"
    r = inspect(data + b"x")
    assert r["stop"]["code"] == "input_limit" and r["coverage"]["input_bytes"] == (1 << 20) + 1


def test_row_ceiling_and_extra_row_not_started():
    data = row() * 4096
    assert inspect(data)["status"] == "complete"
    r = inspect(data + row())
    assert r["stop"]["code"] == "line_limit" and r["coverage"]["rows_seen"] == 4096


def test_value_ceiling_and_next_row_atomic():
    data = row(*(["0.00"] * 4096)) * 32
    r = inspect(data)
    assert r["status"] == "complete" and r["statistics"]["values_accepted"] == 131072
    r = inspect(data + row("99.00", "99.00"))
    assert r["stop"]["code"] == "value_limit" and r["statistics"]["values_accepted"] == 131072
    assert r["statistics"]["power_centi_db_max"] == 0
    assert r["coverage"]["steps_used"] == 131072 + 32 * 4 + 4


def test_lower_peak_cap_keeps_complete():
    r = inspect(row("0.00", "9.00", "8.00"), limits=replace(P.PowerLimits(), max_peaks=1))
    assert r["status"] == "complete" and len(r["peaks"]) == 1
    assert r["coverage"]["peak_candidates_omitted"] == 2


@pytest.mark.parametrize("data", [b"", row()])
def test_expired_deadline_returns_time_partial(data):
    r = P.inspect_power_csv(data, deadline=time.monotonic() - 1)
    assert r["status"] == "partial" and r["stop"]["code"] == "time_limit"
    assert r["coverage"]["rows_seen"] == r["coverage"]["steps_used"] == 0


def test_time_stop_in_row_does_not_publish_its_values(monkeypatch):
    now = [0.0]
    monkeypatch.setattr(P.time, "monotonic", lambda: now[0])
    original = P._Inspector.number
    def number(self, *args, **kwargs):
        result = original(self, *args, **kwargs)
        if self.cov["steps_used"] == 11:
            now[0] = 10.0
        return result
    monkeypatch.setattr(P._Inspector, "number", number)
    first = row()
    r = P.inspect_power_csv(first + row("999.99", "0.00"), deadline=5)
    assert r["stop"] == {"code": "time_limit", "offset": len(first), "row_index": 1}
    assert r["statistics"]["power_centi_db_max"] == -1234
    assert r["coverage"]["steps_used"] == 11


def test_runtime_cap_is_not_extended_by_far_caller_deadline(monkeypatch):
    calls = [0]
    def clock():
        calls[0] += 1
        return 0 if calls[0] == 1 else 2
    monkeypatch.setattr(P.time, "monotonic", clock)
    r = P.inspect_power_csv(row(), deadline=10000, limits=replace(P.PowerLimits(), max_runtime_ms=1))
    assert r["stop"]["code"] == "time_limit" and r["coverage"]["rows_seen"] == 0


@pytest.mark.parametrize("cancel,code", [(lambda: True, "cancelled"), (lambda: 1, "rf_power_failed"), (lambda: None, "rf_power_failed")])
def test_cancel_is_exception_never_stored_partial(cancel, code):
    with pytest.raises(PwehError) as exc:
        inspect(row(), cancel=cancel)
    assert exc.value.code == code and exc.value.__cause__ is None


def test_callback_failure_is_fixed_and_has_no_chain():
    def cancel():
        raise RuntimeError("SYNTHETIC_PRIVATE_CALLBACK")
    with pytest.raises(PwehError) as exc:
        inspect(row(), cancel=cancel)
    assert exc.value.code == "rf_power_failed" and exc.value.__suppress_context__
    assert "SYNTHETIC_PRIVATE" not in str(exc.value)


def test_cancel_is_checked_after_time_partial():
    calls = [0]
    def cancel():
        calls[0] += 1
        return calls[0] > 1
    with pytest.raises(PwehError, match="취소") as exc:
        P.inspect_power_csv(row(), deadline=-1, cancel=cancel)
    assert exc.value.code == "cancelled"


class IntSubclass(int):
    pass


@pytest.mark.parametrize("field", [f.name for f in fields(P.PowerLimits)])
@pytest.mark.parametrize("value", [0, -1, True, 1.0, IntSubclass(1)])
def test_limits_reject_non_exact_or_empty_values(field, value):
    with pytest.raises(ValidationFailed) as exc:
        inspect(row(), limits=replace(P.PowerLimits(), **{field: value}))
    assert exc.value.code == "rf_power_input_invalid"


@pytest.mark.parametrize("field", [f.name for f in fields(P.PowerLimits)])
def test_limits_cannot_exceed_fixed_ceiling(field):
    with pytest.raises(ValidationFailed):
        inspect(row(), limits=replace(P.PowerLimits(), **{field: getattr(P.PowerLimits(), field) + 1}))


@pytest.mark.parametrize("deadline", [True, "123", None, float("nan"), float("inf"), -(float("inf")), 10 ** 1000, IntSubclass(1)])
def test_invalid_deadline_is_fixed(deadline):
    with pytest.raises(ValidationFailed) as exc:
        P.inspect_power_csv(row(), deadline=deadline)
    assert exc.value.code == "rf_power_input_invalid"


@pytest.mark.parametrize("data", [bytearray(b"a"), memoryview(b"a"), "SYNTHETIC_PRIVATE_INPUT", None])
def test_input_must_be_exact_bytes(data):
    with pytest.raises(ValidationFailed) as exc:
        inspect(data)
    assert exc.value.code == "rf_power_input_invalid" and "SYNTHETIC_PRIVATE" not in str(exc.value)


def test_bad_callback_and_limits_contract():
    with pytest.raises(ValidationFailed):
        inspect(row(), cancel=True)
    with pytest.raises(ValidationFailed):
        inspect(row(), limits={})
    with pytest.raises(ValidationFailed):
        inspect(row(), limits=replace(P.PowerLimits(), max_output_bytes=16383))


def test_pure_parser_does_not_open_files_or_start_processes(monkeypatch):
    def refuse(*args, **kwargs):
        pytest.fail("순수 검사에서 I/O를 호출했습니다")
    monkeypatch.setattr("builtins.open", refuse)
    monkeypatch.setattr("subprocess.Popen", refuse)
    monkeypatch.setattr("socket.socket", refuse)
    assert inspect(row())["status"] == "complete"
