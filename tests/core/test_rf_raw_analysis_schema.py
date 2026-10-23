"""RAW 코어를 재실행하지 않고 보고서·요약의 닫힌 공개 schema를 검사한다."""

from __future__ import annotations

import copy

import pytest
from jsonschema import Draft202012Validator

from pweh import schemas
from pweh.errors import ValidationFailed

PROFILE = "flipper-subghz-raw-v1-strict"
FLAGS = ("input_completeness_verified", "capture_verified", "device_association_verified",
         "authorization_assessed", "decoded", "transmitted")
LIMITATIONS = ["strict_profile_only", "file_declarations_only", "accepted_lines_only",
              "no_capture_completeness_verification", "no_device_or_authorization_verification",
              "no_protocol_decoding", "no_raw_pulse_output", "no_replay_or_transmission",
              "aggregate_statistics_are_not_anonymization"]


def report(status="complete"):
    """공개 필드 이름·숫자를 독립적으로 만든 합성 fixture."""
    inspection = {
        "schema": "pweh.rf-raw-inspection/v1", "status": status, "profile": PROFILE,
        "metadata": {"filetype": "Flipper SubGhz RAW File", "version": 1,
                     "declared_frequency_hz": 315000000, "declared_preset": "FuriHalSubGhzPresetOok270Async",
                     "protocol": "RAW"},
        "statistics": {"pulse_count": 4, "declared_duration_us": 1000, "raw_data_lines_accepted": 1,
                       "positive": {"count": 2, "min_us": 100, "max_us": 300, "sum_us": 400},
                       "negative": {"count": 2, "min_us": 200, "max_us": 400, "sum_us": 600}},
        "coverage": {"input_bytes": 200, "accepted_prefix_bytes": 200, "remaining_bytes": 0,
                     "remaining_range": None, "lines_seen": 6, "lines_accepted": 6, "steps_used": 12,
                     "eof_validated": True, "analysis_complete": True, "statistics_scope": "whole_profile",
                     **{key: False for key in FLAGS}},
        "stop": None, "limitations": LIMITATIONS,
    }
    if status != "complete":
        inspection["stop"] = {"code": {"partial": "time_limit", "malformed": "missing_raw_data",
                                         "unsupported": "unsupported_field"}[status], "line": None, "offset": 200}
        inspection["coverage"].update(eof_validated=False, analysis_complete=False, statistics_scope="accepted_prefix")
    return {"schema": "pweh.rf-raw-analysis/v1", "status": status,
            "source": {"kind": "case-artifact", "artifact_id": "A-0001", "size": 200, "sha256": "a" * 64},
            "params": {"profile": PROFILE, "max_seconds": 5}, "inspection": inspection}


def summary(status="complete"):
    return {"schema": "pweh.rf-analysis/v1", "mode": "offline-raw",
            "raw_results": [{"input_artifact_id": "A-0001", "analysis_path": "analysis/rf-raw-001.json",
                             "report_sha256": "a" * 64, "status": status, "pulse_count": 4}],
            **{key: False for key in FLAGS}}


def set_at(value, path, replacement):
    current = value
    for part in path[:-1]:
        current = current[part]
    current[path[-1]] = replacement


@pytest.mark.parametrize("name", ["rf-raw-analysis", "rf-analysis"])
def test_schema_is_valid_and_mapping_is_optional(name):
    Draft202012Validator.check_schema(schemas.load(name))
    assert schemas.SKILL_DATA_SCHEMAS["flipper-rf-analysis"] == "rf-analysis"


@pytest.mark.parametrize("status", ["complete", "partial", "malformed", "unsupported"])
def test_four_parser_states_remain_valid_results(status):
    schemas.validate("rf-raw-analysis", report(status))
    schemas.validate("rf-analysis", summary(status))


@pytest.mark.parametrize("path", [(), ("source",), ("params",), ("inspection",),
    ("inspection", "metadata"), ("inspection", "statistics"), ("inspection", "statistics", "positive"),
    ("inspection", "statistics", "negative"), ("inspection", "coverage"), ("inspection", "stop")])
def test_no_raw_fields_can_be_added(path):
    value = report("partial")
    node = value
    for part in path:
        node = node[part]
    node["private_source_name"] = "PRIVATE"
    with pytest.raises(ValidationFailed):
        schemas.validate("rf-raw-analysis", value)


@pytest.mark.parametrize(("path", "value"), [
    (("schema",), "pweh.rf-raw-inspection/v1"), (("status",), "ok"),
    (("source", "kind"), "evidence"), (("source", "artifact_id"), "../../a"),
    (("source", "size"), -1), (("source", "size"), (1 << 20) + 1),
    (("source", "sha256"), "A" * 64), (("params", "profile"), "guess"),
    (("params", "max_seconds"), True), (("params", "max_seconds"), 0),
    (("params", "max_seconds"), 5.001), (("params", "max_seconds"), "5"),
    (("inspection", "status"), "partial"), (("inspection", "profile"), "other"),
    (("inspection", "metadata", "version"), 2), (("inspection", "metadata", "protocol"), "PRIVATE"),
    (("inspection", "metadata", "declared_preset"), "PRIVATE"),
    (("inspection", "metadata", "declared_frequency_hz"), 2 ** 32),
    (("inspection", "metadata", "filetype"), None),
    (("inspection", "statistics", "pulse_count"), 65537),
    (("inspection", "statistics", "positive", "max_us"), 2 ** 31),
    (("inspection", "statistics", "negative", "max_us"), 2 ** 31 + 1),
    (("inspection", "statistics", "declared_duration_us"), 2 ** 63),
    (("inspection", "coverage", "lines_seen"), 8193),
    (("inspection", "coverage", "steps_used"), 100001),
    (("inspection", "coverage", "eof_validated"), False),
    (("inspection", "coverage", "remaining_range"), {"offset": 200, "length": 1}),
    (("inspection", "limitations"), []),
])
def test_report_rejects_wrong_types_and_bounds(path, value):
    doc = report()
    set_at(doc, path, value)
    with pytest.raises(ValidationFailed):
        schemas.validate("rf-raw-analysis", doc)


@pytest.mark.parametrize("status,code", [("partial", "unsupported_field"), ("partial", "invalid_utf8"),
    ("unsupported", "time_limit"), ("malformed", "unsupported_preset")])
def test_stop_code_matches_parser_state(status, code):
    doc = report(status)
    doc["inspection"]["stop"]["code"] = code
    with pytest.raises(ValidationFailed):
        schemas.validate("rf-raw-analysis", doc)


@pytest.mark.parametrize("flag", FLAGS)
def test_inspection_and_summary_never_upgrade_verification(flag):
    doc = report()
    doc["inspection"]["coverage"][flag] = True
    with pytest.raises(ValidationFailed):
        schemas.validate("rf-raw-analysis", doc)
    doc = summary()
    doc[flag] = True
    with pytest.raises(ValidationFailed):
        schemas.validate("rf-analysis", doc)


def test_empty_malformed_input_is_reportable():
    doc = report("malformed")
    doc["source"]["size"] = 0
    inspection = doc["inspection"]
    inspection["metadata"] = dict.fromkeys(inspection["metadata"])
    inspection["statistics"] = {"pulse_count": 0, "declared_duration_us": 0, "raw_data_lines_accepted": 0,
                                **{sign: {"count": 0, "min_us": None, "max_us": None, "sum_us": 0}
                                   for sign in ("positive", "negative")}}
    inspection["coverage"].update(input_bytes=0, accepted_prefix_bytes=0, lines_seen=0, lines_accepted=0, steps_used=0)
    inspection["stop"] = {"code": "missing_header", "line": None, "offset": 0}
    schemas.validate("rf-raw-analysis", doc)


@pytest.mark.parametrize("count", [0, 129])
def test_summary_result_count_is_bounded(count):
    doc = summary()
    doc["raw_results"] *= count
    with pytest.raises(ValidationFailed):
        schemas.validate("rf-analysis", doc)


@pytest.mark.parametrize("key,value", [
    ("input_artifact_id", "A-1"), ("analysis_path", "dumps/secret.sub"),
    ("analysis_path", "analysis/../rf-raw-001.json"), ("report_sha256", "a" * 63),
    ("status", "confirmed"), ("pulse_count", True), ("pulse_count", 0),
    ("raw", "PRIVATE"),
])
def test_summary_rows_have_only_references_and_closed_status(key, value):
    doc = summary()
    doc["raw_results"][0][key] = value
    with pytest.raises(ValidationFailed):
        schemas.validate("rf-analysis", doc)


@pytest.mark.parametrize("root", ["source", "params", "inspection"])
def test_report_required_fields_cannot_be_dropped(root):
    for key in report()[root]:
        doc = copy.deepcopy(report())
        del doc[root][key]
        with pytest.raises(ValidationFailed):
            schemas.validate("rf-raw-analysis", doc)
