"""합성 strict RAW의 순수 OOK 변환·완료 입구·닫힌 manifest 회계 시험."""

from copy import deepcopy
from dataclasses import FrozenInstanceError, fields
from types import SimpleNamespace
import time

import pytest

from pweh import rf_formats as R
from pweh import rf_ook as O
from pweh.errors import PwehError

HEADER = b";pulse data\n;version 1\n;timescale 1us\n"
TRAILER = b";end\n"


def sample(*rows, preset=R.PRESETS[0], frequency="123456789", newline=b"\n", final=True, bom=False):
    lines = [b"Filetype: Flipper SubGhz RAW File", b"Version: 1", b"Frequency: " + frequency.encode(),
             b"Preset: " + preset.encode(), b"Protocol: RAW"]
    lines.extend(b"RAW_Data: " + value.encode() for value in (rows or ("100 -200",)))
    return (b"\xef\xbb\xbf" if bom else b"") + newline.join(lines) + (newline if final else b"")


def convert(data, **kwargs):
    return O.convert_sub_raw_to_ook(data, deadline=kwargs.pop("deadline", time.monotonic() + 5), **kwargs)


def failure(call, code):
    with pytest.raises(PwehError) as caught:
        call()
    assert caught.value.code == code
    assert caught.value.data == {} and caught.value.hint is None
    assert "PRIVATE" not in str(caught.value) and "PRIVATE" not in repr(caught.value.to_dict())
    assert caught.value.__cause__ is None


def report(*, pairs=1, count=None, total=None, size=None, path="analysis/rf-ook-001/converted.ook"):
    return {
        "schema": "pweh.rf-ook-conversion/v1", "profile": "flipper-raw-ook-v1", "status": "complete",
        "source": {"kind": "case-artifact", "artifact_id": "A-0001", "size": 200, "sha256": "a" * 64},
        "params": {"source_profile": "flipper-subghz-raw-v1-strict", "max_seconds": 5},
        "metadata": {"declared_preset": "FuriHalSubGhzPresetOok270Async", "declared_frequency_hz": 123456789},
        "conversion": {"format": "rtl433-ook-text-v1", "unit": "us", "pairing": "positive-negative",
                       "duration_count": pairs * 2 if count is None else count, "pair_count": pairs,
                       "total_duration_us": pairs * 2 if total is None else total},
        "output": {"path": path, "size": 43 + pairs * 4 if size is None else size, "sha256": "b" * 64},
        "input_completeness_verified": False, "capture_verified": False, "device_association_verified": False,
        "authorization_assessed": False, "decoded": False, "transmitted": False,
        "packet_boundaries_verified": False, "decoder_compatibility_verified": False,
        "limitations": ["strict_complete_raw_only", "ook_presets_only", "ordered_duration_pairs_only",
                        "no_gap_or_packet_inference", "no_capture_or_device_verification", "no_protocol_decoding",
                        "no_receiver_or_transmission", "decoder_execution_not_performed",
                        "aggregate_statistics_are_not_anonymization"],
    }


def mutate(obj, path, value):
    target = obj
    for key in path[:-1]:
        target = target[key]
    target[path[-1]] = value
    return obj


@pytest.mark.parametrize("preset", R.PRESETS[:2])
@pytest.mark.parametrize("newline,final,bom", [(b"\n", True, False), (b"\n", False, True),
                                             (b"\r\n", True, True), (b"\r\n", False, False)])
def test_exact_conversion_bytes_and_six_fields(preset, newline, final, bom):
    data = sample("00100\t-000200 300", "-400", preset=preset, newline=newline, final=final, bom=bom)
    got = convert(data)
    assert type(got) is O.OokConversion
    assert tuple(field.name for field in fields(got)) == (
        "ook_bytes", "declared_preset", "declared_frequency_hz", "duration_count", "pair_count", "total_duration_us")
    assert got.ook_bytes == HEADER + b"100 200\n300 400\n" + TRAILER
    assert (got.declared_preset, got.declared_frequency_hz, got.duration_count, got.pair_count,
            got.total_duration_us) == (preset, 123456789, 4, 2, 1000)
    assert not hasattr(got, "to_dict") and "100 200" not in repr(got)
    with pytest.raises(FrozenInstanceError):
        got.ook_bytes = b"PRIVATE"


@pytest.mark.parametrize("frequency", ["0", "4294967295", "0000000123"])
def test_frequency_remains_a_uint32_declaration(frequency):
    got = convert(sample(frequency=frequency))
    assert got.declared_frequency_hz == int(frequency)
    assert got.ook_bytes == HEADER + b"100 200\n" + TRAILER
    assert b";freq" not in got.ook_bytes


def test_mark_crosses_raw_rows_comments_and_blank_lines():
    data = sample("100").replace(b"Version: 1", b"Version:\t0001 ")
    data += b"# PRIVATE RAW_Data: 999 -999\n \t# RAW_Data: 55 -66\n\t \nRAW_Data: -200\n"
    got = convert(data)
    assert got.ook_bytes == HEADER + b"100 200\n" + TRAILER
    assert (got.duration_count, got.pair_count, got.total_duration_us) == (2, 1, 300)
    assert b"PRIVATE" not in got.ook_bytes and "PRIVATE" not in repr(got)


def test_one_pair_minimum_and_token_width_normalization():
    got = convert(sample("00000000001 -0000000001"))
    assert got.ook_bytes == HEADER + b"1 1\n" + TRAILER and len(got.ook_bytes) == 47
    assert got.total_duration_us == 2


@pytest.mark.parametrize("pairs,magnitude", [(1200, 1), (1200, 2147483647), (1, 2147483647)])
def test_maximum_pairs_and_magnitude(pairs, magnitude):
    tokens = [str(magnitude), str(-magnitude)] * pairs
    rows = [" ".join(tokens[index:index + 512]) for index in range(0, len(tokens), 512)]
    got = convert(sample(*rows))
    expected_pair = f"{magnitude} {magnitude}\n".encode()
    assert got.ook_bytes == HEADER + expected_pair * pairs + TRAILER
    assert got.duration_count == pairs * 2 and got.pair_count == pairs
    assert got.total_duration_us == pairs * 2 * magnitude
    assert len(got.ook_bytes) == 43 + len(expected_pair) * pairs
    if pairs == 1200 and magnitude == 2147483647:
        assert len(got.ook_bytes) == 26443 and got.total_duration_us == 5_153_960_752_800


def test_same_immutable_object_default_inspector_once(monkeypatch):
    data = sample()
    calls = []
    original = O.inspect_sub_raw

    def spy(raw, **kwargs):
        assert raw is data
        assert set(kwargs) == {"deadline", "cancel"}
        calls.append(kwargs)
        return original(raw, **kwargs)

    monkeypatch.setattr(O, "inspect_sub_raw", spy)
    start = time.monotonic()
    got = convert(data, deadline=start + 20)
    assert got.pair_count == 1 and len(calls) == 1
    assert start < calls[0]["deadline"] <= time.monotonic() + 5
    assert calls[0]["deadline"] < start + 6


@pytest.mark.parametrize("data", [b"", b"# PRIVATE\n", sample("1"), sample("1 -2 3"),
                                  sample("1 -2147483648"), sample("0 -1"), sample("1 2"), sample("-1 2"),
                                  sample("+1 -2"), sample("1 -0"), sample("1 -2") + b"Other: PRIVATE\n",
                                  sample("1 -2").replace(b"RAW_Data:", b" RAW_Data:"),
                                  sample("1 -2").replace(b"RAW_Data:", b"Raw_Data:"),
                                  sample("1 -2").replace(b"RAW_Data:", b"RAW_Data :"),
                                  sample("1 -2").replace(b"Protocol: RAW", b"Protocol: BinRAW"),
                                  sample("1 -2").replace(b"Version: 1", b"Version: 2"),
                                  sample("1 -2") + b"# PRIVATE\rBAD\n",
                                  sample("1 -2") + b"# \xffPRIVATE\n"])
def test_incomplete_malformed_or_nonconvertible_has_no_result(data):
    failure(lambda: convert(data), "rf_ook_not_convertible")


@pytest.mark.parametrize("preset", [*R.PRESETS[2:], "PRIVATE_UNKNOWN"])
def test_non_ook_preset_is_rejected(preset):
    failure(lambda: convert(sample(preset=preset)), "rf_ook_not_convertible")


def test_1201_pairs_and_odd_excess_are_input_limit():
    tokens = ["1", "-2"] * 1201
    for values in (tokens, tokens[:-1]):
        rows = [" ".join(values[index:index + 512]) for index in range(0, len(values), 512)]
        failure(lambda: convert(sample(*rows)), "rf_ook_input_limit")


def test_existing_inspector_non_time_partial_is_not_convertible():
    failure(lambda: convert(sample() + b"#" + b"x" * 8192), "rf_ook_not_convertible")
    failure(lambda: convert(sample() + b"\n" * 8192), "rf_ook_not_convertible")


@pytest.mark.parametrize("data", [None, bytearray(b"PRIVATE"), memoryview(b"PRIVATE"), "PRIVATE", [1], True])
def test_input_exact_bytes(data):
    failure(lambda: convert(data), "rf_ook_input_invalid")


@pytest.mark.parametrize("deadline", [True, False, None, "PRIVATE", float("nan"), float("inf"), float("-inf"), 1 << 10000])
def test_deadline_exact_finite(deadline):
    failure(lambda: convert(sample(), deadline=deadline), "rf_ook_input_invalid")


def test_oversize_input_is_refused_before_inspector(monkeypatch):
    monkeypatch.setattr(O, "inspect_sub_raw", lambda *args, **kwargs: pytest.fail("검사기를 호출하면 안 됨"))
    failure(lambda: convert(bytes((1 << 20) + 1)), "rf_ook_input_limit")


@pytest.mark.parametrize("cancel", [1, False, "PRIVATE", [], {}])
def test_cancel_must_be_callable(cancel):
    failure(lambda: convert(sample(), cancel=cancel), "rf_ook_input_invalid")


@pytest.mark.parametrize("value", [None, 0, 1, "PRIVATE", [], {}])
def test_cancel_result_must_be_exact_bool(value):
    failure(lambda: convert(sample(), cancel=lambda: value), "rf_ook_failed")


def test_cancel_exception_is_fixed():
    def cancelled():
        raise RuntimeError("PRIVATE")

    failure(lambda: convert(sample(), cancel=cancelled), "rf_ook_failed")
    failure(lambda: convert(sample(), cancel=lambda: True), "cancelled")
    failure(lambda: convert(sample(), deadline=time.monotonic() - 1), "time_limit")


@pytest.mark.parametrize("stage", ["second-pass", "final-check"])
@pytest.mark.parametrize("kind", ["cancel", "time", "callback"])
def test_second_pass_and_final_tick_never_return_partial(monkeypatch, stage, kind):
    original = O.inspect_sub_raw
    enabled, checks = False, 0
    now = time.monotonic()
    trigger = 1 if stage == "second-pass" else 9  # metadata5 + RAW행1 + token2 + 최종1.

    def inspected(data, **kwargs):
        nonlocal enabled
        result = original(data, **kwargs)
        enabled = True
        return result

    def cancelled():
        nonlocal checks
        if enabled:
            checks += 1
        if enabled and checks >= trigger:
            if kind == "callback":
                raise RuntimeError("PRIVATE")
            return kind == "cancel"
        return False

    def clock():
        return now + (10 if enabled and checks >= trigger and kind == "time" else 0)

    monkeypatch.setattr(O, "inspect_sub_raw", inspected)
    monkeypatch.setattr(O, "time", SimpleNamespace(monotonic=clock))
    code = {"cancel": "cancelled", "time": "time_limit", "callback": "rf_ook_failed"}[kind]
    failure(lambda: convert(sample(), deadline=now + 4, cancel=cancelled), code)
    assert checks == trigger


@pytest.mark.parametrize("error", [RuntimeError("PRIVATE"), PwehError("PRIVATE", code="rf_raw_failed"),
                                   PwehError("PRIVATE", code="validation_failed"),
                                   PwehError("PRIVATE", code="cancelled")])
def test_inspector_exceptions_are_sanitized(monkeypatch, error):
    def inspect(*args, **kwargs):
        raise error

    monkeypatch.setattr(O, "inspect_sub_raw", inspect)
    failure(lambda: convert(sample()), "cancelled" if getattr(error, "code", None) == "cancelled" else "rf_ook_failed")


@pytest.mark.parametrize("path,value", [
    (("status",), "PRIVATE"), (("stop",), {}), (("profile",), "other"),
    (("coverage", "input_bytes"), True), (("coverage", "accepted_prefix_bytes"), 0),
    (("coverage", "remaining_bytes"), 1), (("coverage", "remaining_range"), {}),
    (("coverage", "eof_validated"), 1), (("coverage", "analysis_complete"), False),
    (("coverage", "statistics_scope"), "accepted_prefix"),
    (("metadata", "declared_frequency_hz"), True),
    (("statistics", "pulse_count"), 2.0), (("statistics", "positive", "count"), True),
    (("statistics", "negative", "count"), 0), (("statistics", "declared_duration_us"), 999),
    (("statistics", "raw_data_lines_accepted"), 2),
])
def test_inspector_contract_mismatch_is_fixed_failure(monkeypatch, path, value):
    data = sample()
    inspected = R.inspect_sub_raw(data, deadline=time.monotonic() + 5)
    mutate(inspected, path, value)
    monkeypatch.setattr(O, "inspect_sub_raw", lambda *args, **kwargs: inspected)
    failure(lambda: convert(data), "rf_ook_failed")


def test_second_pass_compares_signed_sums_not_only_total(monkeypatch):
    data = sample()
    inspected = R.inspect_sub_raw(data, deadline=time.monotonic() + 5)
    inspected["statistics"]["positive"]["sum_us"] += 1
    inspected["statistics"]["negative"]["sum_us"] -= 1
    monkeypatch.setattr(O, "inspect_sub_raw", lambda *args, **kwargs: inspected)
    failure(lambda: convert(data), "rf_ook_failed")


def test_inspector_time_partial_is_fixed_time_limit(monkeypatch):
    inspected = R.inspect_sub_raw(sample(), deadline=time.monotonic() - 1)
    assert inspected["status"] == "partial" and inspected["stop"]["code"] == "time_limit"
    monkeypatch.setattr(O, "inspect_sub_raw", lambda *args, **kwargs: inspected)
    failure(lambda: convert(sample()), "time_limit")


def test_second_pass_defensive_bounds_and_no_metadata_search(monkeypatch):
    data = sample()
    inspected = R.inspect_sub_raw(data, deadline=time.monotonic() + 5)
    # 첫 pass 계약 위조를 합성 주입해 2차 token/line 제한과 통계 결속을 독립 확인한다.
    def check_mutation(raw, code):
        fake = deepcopy(inspected)
        fake["coverage"].update(input_bytes=len(raw), accepted_prefix_bytes=len(raw))
        monkeypatch.setattr(O, "inspect_sub_raw", lambda *args, **kwargs: fake)
        failure(lambda: convert(raw), code)

    check_mutation(data.replace(b"100 -200", b"000000000001 -200"), "rf_ook_failed")
    check_mutation(data.replace(b"100 -200", b"100 -200 " + b"1 -1 " * 256), "rf_ook_failed")
    check_mutation(data.replace(b"RAW_Data:", b"Other:"), "rf_ook_failed")
    check_mutation(data + b"#" + b"x" * 8192, "rf_ook_failed")
    check_mutation(data + b"\n" * 8192, "rf_ook_failed")


def test_output_cap_guard_has_no_partial_result(monkeypatch):
    monkeypatch.setattr(O, "MAX_OUTPUT_BYTES", 46)
    failure(lambda: convert(sample("1 -1")), "rf_ook_input_limit")


@pytest.mark.parametrize("pairs,total,size", [(1, 2, 47), (1, 4294967294, 65),
                                            (1200, 2400, 4843), (1200, 5_153_960_752_800, 26443)])
@pytest.mark.parametrize("directory", [1, 64])
def test_manifest_relationship_extremes(pairs, total, size, directory):
    value = report(pairs=pairs, total=total, size=size, path=f"analysis/rf-ook-{directory:03d}/converted.ook")
    assert O.validate_ook_accounting(value) is None


@pytest.mark.parametrize("pairs,count,total,size", [(0, 0, 0, 43), (1201, 2402, 2402, 4847),
                                                  (1, 3, 3, 47), (2, 2, 4, 51), (1, 2, 1, 47),
                                                  (1, 2, 4294967295, 65), (1, 2, 2, 46),
                                                  (1, 2, 2, 66), (2, 4, 4, 47), (1200, 2400, 2400, 26444)])
def test_manifest_bad_relationships(pairs, count, total, size):
    failure(lambda: O.validate_ook_accounting(report(pairs=pairs, count=count, total=total, size=size)), "rf_ook_failed")


@pytest.mark.parametrize("path", [("source", "size"), ("metadata", "declared_frequency_hz"),
                                 ("conversion", "duration_count"), ("conversion", "pair_count"),
                                 ("conversion", "total_duration_us"), ("output", "size")])
@pytest.mark.parametrize("value", [True, False, 1.0, "PRIVATE", None, -1, 1 << 1000])
def test_manifest_exact_integer_fields(path, value):
    failure(lambda: O.validate_ook_accounting(mutate(report(), path, value)), "rf_ook_failed")


@pytest.mark.parametrize("value", [True, False, 0, -1, 5.01, float("nan"), float("inf"), None, "PRIVATE", 1 << 1000])
def test_manifest_processing_seconds(value):
    failure(lambda: O.validate_ook_accounting(mutate(report(), ("params", "max_seconds"), value)), "rf_ook_failed")


@pytest.mark.parametrize("value", [0.0001, 1, 5.0])
def test_manifest_processing_seconds_valid(value):
    assert O.validate_ook_accounting(mutate(report(), ("params", "max_seconds"), value)) is None


@pytest.mark.parametrize("path,value", [
    (("schema",), "pweh.rf-raw-analysis/v1"), (("profile",), R.PROFILE), (("status",), "partial"),
    (("source", "kind"), "evidence"), (("source", "artifact_id"), "A-001"),
    (("source", "artifact_id"), "A-000000001"), (("source", "artifact_id"), "A-0001\n"),
    (("source", "artifact_id"), " A-0001"), (("source", "sha256"), "A" * 64),
    (("source", "sha256"), "a" * 64 + "\n"), (("source", "sha256"), "a" * 63),
    (("params", "source_profile"), "other"), (("metadata", "declared_preset"), R.PRESETS[2]),
    (("metadata", "declared_preset"), "PRIVATE"), (("conversion", "format"), "other"),
    (("conversion", "unit"), "ns"), (("conversion", "pairing"), "negative-positive"),
    (("output", "path"), "analysis/rf-ook-000/converted.ook"),
    (("output", "path"), "analysis/rf-ook-065/converted.ook"),
    (("output", "path"), "analysis/rf-ook-001/converted.ook\n"),
    (("output", "path"), "analysis/rf-ook-01/converted.ook"),
    (("output", "path"), "analysis/rf-ook-001/other.ook"),
    (("output", "sha256"), "b" * 64 + "\n"),
    (("limitations",), []), (("limitations",), tuple(report()["limitations"])),
])
def test_manifest_closed_values_and_end_of_string(path, value):
    failure(lambda: O.validate_ook_accounting(mutate(report(), path, value)), "rf_ook_failed")


@pytest.mark.parametrize("flag", O.FALSE_FIELDS)
@pytest.mark.parametrize("value", [True, 0, None])
def test_manifest_false_flags_are_exact(flag, value):
    failure(lambda: O.validate_ook_accounting(mutate(report(), (flag,), value)), "rf_ook_failed")


@pytest.mark.parametrize("path", [(), ("source",), ("params",), ("metadata",), ("conversion",), ("output",)])
@pytest.mark.parametrize("change", ["add", "remove", "not-dict"])
def test_manifest_exact_objects(path, change):
    value = report()
    target = value
    for part in path:
        target = target[part]
    if change == "add":
        target["PRIVATE"] = "PRIVATE"
    elif change == "remove":
        target.pop(next(iter(target)))
    elif not path:
        value = None
    else:
        mutate(value, path, [])
    failure(lambda: O.validate_ook_accounting(value), "rf_ook_failed")


def test_manifest_limits_constants_and_independent_declarations():
    value = report()
    assert O.FALSE_FIELDS == ("input_completeness_verified", "capture_verified", "device_association_verified",
                             "authorization_assessed", "decoded", "transmitted", "packet_boundaries_verified",
                             "decoder_compatibility_verified")
    assert list(O.LIMITATIONS) == value["limitations"]
    assert O.SOURCE_PROFILE == R.PROFILE and O.MAX_PAIRS == 1200 and O.MAX_OUTPUT_BYTES == 65536
    value["limitations"][0], value["limitations"][1] = value["limitations"][1], value["limitations"][0]
    failure(lambda: O.validate_ook_accounting(value), "rf_ook_failed")
