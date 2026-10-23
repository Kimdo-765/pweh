"""독립 최소 보고서로 닫힌 schema와 수치 관계 검사를 구분한다."""
from copy import deepcopy
import json
from pathlib import Path

from jsonschema import Draft202012Validator
import pytest

from pweh import rf_power as P
from pweh.errors import PwehError


SCHEMA = json.loads((Path(__file__).resolve().parents[2] / "src/pweh/schemas/rf-power-analysis.schema.json").read_text())
VALIDATOR = Draft202012Validator(SCHEMA)


def inspection():
    """실제 parser를 호출하지 않은 두 값의 완전한 fixture."""
    return {
        "schema": "pweh.rf-power-inspection/v1", "profile": "rtl-power-blog-v1.4.0-csv", "status": "complete",
        "statistics": {"rows_accepted": 1, "values_accepted": 2, "finite_values": 2,
                       "negative_infinity_values": 0, "low_hz_min": 100, "high_hz_max": 200,
                       "step_centi_hz_min": 33, "step_centi_hz_max": 33,
                       "power_centi_db_min": -5678, "power_centi_db_max": -1234},
        "peaks": [{"row_index": 0, "value_index": 0, "low_hz": 100, "high_hz": 200,
                   "step_centi_hz": 33, "samples": 3, "power_centi_db": -1234},
                  {"row_index": 0, "value_index": 1, "low_hz": 100, "high_hz": 200,
                   "step_centi_hz": 33, "samples": 3, "power_centi_db": -5678}],
        "coverage": {"input_bytes": 60, "accepted_prefix_bytes": 60, "remaining_bytes": 0,
                     "remaining_range": None, "rows_seen": 1, "rows_accepted": 1, "steps_used": 6,
                     "peak_candidates_omitted": 0, "eof_validated": True, "analysis_complete": True,
                     "statistics_scope": "accepted_prefix", "input_completeness_verified": False,
                     "capture_verified": False, "device_association_verified": False,
                     "authorization_assessed": False, "decoded": False, "transmitted": False,
                     "frequency_centers_verified": False, "power_calibration_verified": False},
        "stop": None,
        "limitations": ["strict_profile_only", "accepted_rows_only", "reported_columns_not_fft_bins",
                        "trailing_value_recomputed_by_producer", "row_times_not_returned_or_verified",
                        "no_frequency_center_verification", "no_power_calibration_verification",
                        "no_capture_completeness_verification", "no_device_or_authorization_verification",
                        "no_protocol_decoding", "no_replay_or_transmission", "aggregate_statistics_are_not_anonymization"],
    }


def stopped(status="partial", code="truncated_row"):
    r = inspection()
    r["status"] = status
    r["coverage"].update(input_bytes=61, remaining_bytes=1, remaining_range={"offset": 60, "length": 1},
                         rows_seen=2, analysis_complete=False, eof_validated=False)
    r["stop"] = {"code": code, "offset": 60, "row_index": 1}
    return r


def empty():
    r = inspection()
    r["status"] = "unsupported"
    r["statistics"] = {key: (0 if key in ("rows_accepted", "values_accepted", "finite_values", "negative_infinity_values") else None)
                       for key in r["statistics"]}
    r["peaks"] = []
    r["coverage"].update(input_bytes=0, accepted_prefix_bytes=0, rows_seen=0, rows_accepted=0, steps_used=0,
                         eof_validated=False, analysis_complete=False)
    r["stop"] = {"code": "empty_input", "offset": 0, "row_index": 0}
    return r


def envelope(r=None):
    r = r or inspection()
    return {"schema": "pweh.rf-power-analysis/v1", "status": r["status"],
            "source": {"kind": "case-artifact", "artifact_id": "A-0001", "size": r["coverage"]["input_bytes"], "sha256": "a" * 64},
            "params": {"profile": "rtl-power-blog-v1.4.0-csv", "max_seconds": 5}, "inspection": r}


def put(root, path, value):
    current = root
    for key in path[:-1]:
        current = current[key]
    current[path[-1]] = value


def test_schema_is_valid_and_independent_four_states_validate():
    Draft202012Validator.check_schema(SCHEMA)
    for r in (inspection(), stopped(), stopped("malformed", "number_syntax"), empty(),
              stopped("unsupported", "nonfinite_value")):
        VALIDATOR.validate(envelope(r))
        P.validate_power_accounting(r)


@pytest.mark.parametrize("path,value", [
    (("schema",), "pweh.rf-raw-analysis/v1"),
    (("status",), "partial"),
    (("source", "kind"), "evidence"),
    (("source", "artifact_id"), "A-0001\n"),
    (("source", "artifact_id"), "A-001"),
    (("source", "artifact_id"), "A-000000001"),
    (("source", "sha256"), "a" * 64 + "\n"),
    (("source", "sha256"), "A" * 64),
    (("source", "size"), (1 << 20) + 1),
    (("source", "size"), True),
    (("params", "profile"), "other-profile"),
    (("params", "max_seconds"), 0),
    (("params", "max_seconds"), 5.01),
    (("params", "max_seconds"), True),
    (("inspection", "schema"), "other"),
    (("inspection", "profile"), "other"),
    (("inspection", "status"), "ok"),
    (("inspection", "statistics", "rows_accepted"), 4097),
    (("inspection", "statistics", "values_accepted"), 131073),
    (("inspection", "statistics", "low_hz_min"), None),
    (("inspection", "statistics", "step_centi_hz_min"), 0),
    (("inspection", "statistics", "step_centi_hz_max"), 280000001),
    (("inspection", "statistics", "power_centi_db_max"), 1 << 63),
    (("inspection", "peaks"), []),
    (("inspection", "peaks", 0, "row_index"), 4096),
    (("inspection", "peaks", 0, "value_index"), 131072),
    (("inspection", "peaks", 0, "samples"), 0),
    (("inspection", "peaks", 0, "high_hz"), 2147483648),
    (("inspection", "coverage", "steps_used"), 262145),
    (("inspection", "coverage", "rows_seen"), 4097),
    (("inspection", "coverage", "statistics_scope"), "whole_profile"),
    (("inspection", "coverage", "eof_validated"), False),
    (("inspection", "coverage", "analysis_complete"), False),
    (("inspection", "coverage", "remaining_range"), {"offset": 60, "length": 1}),
    (("inspection", "stop"), {"code": "time_limit", "offset": 0, "row_index": 0}),
    (("inspection", "limitations"), []),
])
def test_schema_closed_values(path, value):
    r = envelope()
    put(r, path, value)
    assert not VALIDATOR.is_valid(r)


@pytest.mark.parametrize("path", [(), ("source",), ("params",), ("inspection",),
                                  ("inspection", "statistics"), ("inspection", "coverage"),
                                  ("inspection", "peaks", 0)])
def test_schema_rejects_unknown_fields(path):
    r = envelope()
    current = r
    for key in path:
        current = current[key]
    current["private_value"] = "SYNTHETIC_PRIVATE"
    assert not VALIDATOR.is_valid(r)


@pytest.mark.parametrize("flag", P.FALSE_FIELDS)
def test_schema_rejects_any_upgraded_claim(flag):
    r = envelope()
    r["inspection"]["coverage"][flag] = True
    assert not VALIDATOR.is_valid(r)


@pytest.mark.parametrize("status,code", [("partial", "number_range"), ("malformed", "time_limit"),
                                         ("unsupported", "field_count"), ("partial", "output_limit")])
def test_schema_status_cannot_hide_stop_meaning(status, code):
    assert not VALIDATOR.is_valid(envelope(stopped(status, code)))


def test_schema_partial_and_empty_closed_null_rules():
    for key in ("analysis_complete", "eof_validated"):
        r = stopped()
        r["coverage"][key] = True
        assert not VALIDATOR.is_valid(envelope(r))
    r = stopped()
    r["stop"] = None
    assert not VALIDATOR.is_valid(envelope(r))
    r = empty()
    r["statistics"]["low_hz_min"] = 0
    assert not VALIDATOR.is_valid(envelope(r))
    r = empty()
    r["statistics"]["power_centi_db_min"] = 0
    assert not VALIDATOR.is_valid(envelope(r))
    r = envelope(stopped())
    r["inspection"]["stop"]["original"] = "private"
    assert not VALIDATOR.is_valid(r)


def test_inspection_input_limit_can_preserve_size_beyond_public_source_cap():
    r = empty()
    r["status"] = "partial"
    size = (1 << 20) + 1
    r["coverage"].update(input_bytes=size, remaining_bytes=size, remaining_range={"offset": 0, "length": size})
    r["stop"]["code"] = "input_limit"
    validator = Draft202012Validator({"$ref": "#/$defs/inspection", "$defs": SCHEMA["$defs"]})
    validator.validate(r)
    P.validate_power_accounting(r)
    assert not VALIDATOR.is_valid(envelope(r))


@pytest.mark.parametrize("path,value", [
    (("coverage", "input_bytes"), 61), (("coverage", "accepted_prefix_bytes"), 59),
    (("coverage", "remaining_bytes"), 1), (("coverage", "rows_accepted"), 0),
    (("coverage", "rows_seen"), 0), (("coverage", "rows_seen"), 2),
    (("coverage", "steps_used"), 5), (("coverage", "steps_used"), 7),
    (("coverage", "peak_candidates_omitted"), 1),
    (("statistics", "values_accepted"), 3), (("statistics", "finite_values"), 3),
    (("statistics", "negative_infinity_values"), 1),
    (("statistics", "low_hz_min"), 101), (("statistics", "high_hz_max"), 199),
    (("statistics", "step_centi_hz_min"), 34), (("statistics", "step_centi_hz_max"), 32),
    (("statistics", "power_centi_db_min"), -5679), (("statistics", "power_centi_db_max"), -1233),
    (("peaks", 0, "row_index"), 1), (("peaks", 0, "value_index"), 2),
    (("peaks", 1, "value_index"), 0), (("peaks", 1, "samples"), 4),
    (("peaks", 1, "low_hz"), 101), (("peaks", 1, "high_hz"), 199),
    (("peaks", 0, "power_centi_db"), -100),
    (("limitations",), []), (("coverage", "analysis_complete"), 1),
    (("coverage", "decoded"), 0), (("status",), "SYNTHETIC_PRIVATE_STATUS"),
])
def test_accounting_rejects_relational_mutations(path, value):
    r = inspection()
    put(r, path, value)
    with pytest.raises(PwehError) as exc:
        P.validate_power_accounting(r)
    assert exc.value.code == "rf_power_failed" and "SYNTHETIC_PRIVATE" not in str(exc.value)


@pytest.mark.parametrize("path", [("coverage", "input_bytes"), ("coverage", "steps_used"),
                                  ("statistics", "rows_accepted"), ("peaks", 0, "row_index"),
                                  ("peaks", 0, "samples"), ("peaks", 0, "power_centi_db")])
@pytest.mark.parametrize("cast", [float, bool])
def test_accounting_requires_exact_int_even_when_schema_number_is_integral(path, cast):
    r = inspection()
    value = r
    for key in path:
        value = value[key]
    put(r, path, cast(value))
    with pytest.raises(PwehError):
        P.validate_power_accounting(r)


def test_accounting_rank_order_coordinate_and_prefix_seal():
    for mutate in (lambda r: r["peaks"].reverse(),
                   lambda r: r["peaks"].append(deepcopy(r["peaks"][0])),
                   lambda r: r["peaks"][0].update(value_index=True)):
        r = inspection()
        mutate(r)
        with pytest.raises(PwehError):
            P.validate_power_accounting(r)
    for path, value in [(("stop", "offset"), 0), (("stop", "row_index"), 0),
                        (("coverage", "remaining_range", "offset"), 0),
                        (("coverage", "remaining_range", "length"), 2)]:
        r = stopped()
        put(r, path, value)
        with pytest.raises(PwehError):
            P.validate_power_accounting(r)


@pytest.mark.parametrize("value", [None, [], {}, {"private": "SYNTHETIC_PRIVATE"}])
def test_accounting_invalid_envelope_is_fixed(value):
    with pytest.raises(PwehError) as exc:
        P.validate_power_accounting(value)
    assert exc.value.code == "rf_power_failed" and exc.value.__suppress_context__


def test_actual_parser_all_statuses_match_independent_schema():
    from .test_rf_power import row, inspect
    for data in (row(), row(newline=b""), row(clock="99:99:99"), b"", row("NaN", "0.00"), row("-inf", "-inf")):
        r = inspect(data)
        VALIDATOR.validate(envelope(r))
