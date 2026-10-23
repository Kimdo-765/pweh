"""전력 CSV 요약의 경계와 기존 RAW 분기의 호환성을 검사한다."""

from __future__ import annotations

import copy

import pytest
from jsonschema import Draft202012Validator

from pweh import schemas
from pweh.errors import ValidationFailed


FLAGS = ("input_completeness_verified", "capture_verified", "device_association_verified",
         "authorization_assessed", "decoded", "transmitted")


def summary(status="complete"):
    return {
        "schema": "pweh.rf-analysis/v1", "mode": "offline-power",
        "power_results": [{"input_artifact_id": "A-0001",
                           "analysis_path": "analysis/rf-power-001.json",
                           "report_sha256": "a" * 64, "status": status,
                           "rows_accepted": 1, "values_accepted": 2}],
        **{key: False for key in FLAGS},
    }


@pytest.mark.parametrize("status", ["complete", "partial", "malformed", "unsupported"])
def test_power_states_preserve_status(status):
    Draft202012Validator.check_schema(schemas.load("rf-analysis"))
    schemas.validate("rf-analysis", summary(status))


@pytest.mark.parametrize("status", ["partial", "malformed", "unsupported"])
def test_noncomplete_can_have_no_accepted_rows(status):
    doc = summary(status)
    doc["power_results"][0].update(rows_accepted=0, values_accepted=0)
    schemas.validate("rf-analysis", doc)


@pytest.mark.parametrize("key,value", [
    ("input_artifact_id", "A-1"), ("input_artifact_id", "A-0001\n"),
    ("analysis_path", "analysis/rf-raw-001.json"),
    ("analysis_path", "analysis/rf-power-001.json\n"),
    ("analysis_path", "analysis/../rf-power-001.json"),
    ("report_sha256", "a" * 64 + "\n"), ("report_sha256", "A" * 64),
    ("status", "confirmed"), ("rows_accepted", True), ("rows_accepted", "1"),
    ("rows_accepted", 0), ("rows_accepted", 4097),
    ("values_accepted", True), ("values_accepted", 1), ("values_accepted", 131073),
    ("raw", "PRIVATE"), ("frequency_centers_verified", False),
])
def test_power_rows_are_closed_and_bounded(key, value):
    doc = summary()
    doc["power_results"][0][key] = value
    with pytest.raises(ValidationFailed):
        schemas.validate("rf-analysis", doc)


@pytest.mark.parametrize("flag", FLAGS)
def test_summary_does_not_upgrade_verification(flag):
    doc = summary()
    doc[flag] = True
    with pytest.raises(ValidationFailed):
        schemas.validate("rf-analysis", doc)


@pytest.mark.parametrize("count", [0, 129])
def test_power_result_count_is_bounded(count):
    doc = summary()
    doc["power_results"] *= count
    with pytest.raises(ValidationFailed):
        schemas.validate("rf-analysis", doc)


def test_raw_and_power_cannot_be_mixed():
    power = summary()
    raw = copy.deepcopy(power)
    raw["mode"] = "offline-raw"
    raw["raw_results"] = [{"input_artifact_id": "A-0001",
                           "analysis_path": "analysis/rf-raw-001.json",
                           "report_sha256": "a" * 64, "status": "complete", "pulse_count": 4}]
    del raw["power_results"]
    schemas.validate("rf-analysis", raw)
    for doc, key, rows in ((power, "raw_results", raw["raw_results"]),
                           (raw, "power_results", power["power_results"])):
        doc[key] = rows
        with pytest.raises(ValidationFailed):
            schemas.validate("rf-analysis", doc)


def test_required_power_fields_cannot_be_dropped():
    for path in [(), ("power_results", 0)]:
        original = summary()
        node = original if not path else original["power_results"][0]
        for key in node:
            doc = copy.deepcopy(original)
            del (doc if not path else doc["power_results"][0])[key]
            with pytest.raises(ValidationFailed):
                schemas.validate("rf-analysis", doc)
