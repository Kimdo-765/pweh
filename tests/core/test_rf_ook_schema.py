"""변환기를 실행하지 않는 독립 OOK manifest·요약 schema와 관계 시험."""

from __future__ import annotations

import copy
import hashlib
import json

import pytest
from jsonschema import Draft202012Validator

from pweh import rf_ook, schemas
from pweh.errors import PwehError, ValidationFailed

FLAGS = ("input_completeness_verified", "capture_verified", "device_association_verified",
         "authorization_assessed", "decoded", "transmitted", "packet_boundaries_verified",
         "decoder_compatibility_verified")
LIMITATIONS = ["strict_complete_raw_only", "ook_presets_only", "ordered_duration_pairs_only",
               "no_gap_or_packet_inference", "no_capture_or_device_verification", "no_protocol_decoding",
               "no_receiver_or_transmission", "decoder_execution_not_performed",
               "aggregate_statistics_are_not_anonymization"]


def report():
    """100/-200 한 쌍의 독립 공개 fixture이며 실제 변환 결과를 복사하지 않는다."""
    return {"schema": "pweh.rf-ook-conversion/v1", "profile": "flipper-raw-ook-v1", "status": "complete",
        "source": {"kind": "case-artifact", "artifact_id": "A-0001", "size": 200, "sha256": "a" * 64},
        "params": {"source_profile": "flipper-subghz-raw-v1-strict", "max_seconds": 5},
        "metadata": {"declared_preset": "FuriHalSubGhzPresetOok270Async", "declared_frequency_hz": 315000000},
        "conversion": {"format": "rtl433-ook-text-v1", "unit": "us", "pairing": "positive-negative",
                       "duration_count": 2, "pair_count": 1, "total_duration_us": 300},
        "output": {"path": "analysis/rf-ook-001/converted.ook", "size": 51, "sha256": "b" * 64},
        **{flag: False for flag in FLAGS}, "limitations": list(LIMITATIONS)}


def summary(number=1):
    return {"schema": "pweh.rf-analysis/v1", "mode": "offline-ook", "conversion_results": [{
        "input_artifact_id": "A-0001", "analysis_path": f"analysis/rf-ook-{number:03}/manifest.json",
        "report_sha256": "a" * 64, "output_path": f"analysis/rf-ook-{number:03}/converted.ook",
        "output_sha256": "b" * 64, "pair_count": 1}], **{flag: False for flag in FLAGS}}


def at(value, path):
    for key in path:
        value = value[key]
    return value


def set_at(value, path, replacement):
    at(value, path[:-1])[path[-1]] = replacement


@pytest.mark.parametrize("name", ["rf-ook-conversion", "rf-analysis"])
def test_draft_and_independent_normal_fixtures(name):
    Draft202012Validator.check_schema(schemas.load(name))
    schemas.validate(name, report() if name == "rf-ook-conversion" else summary())
    rf_ook.validate_ook_accounting(report())
    assert tuple(FLAGS) == rf_ook.FALSE_FIELDS
    assert tuple(LIMITATIONS) == rf_ook.LIMITATIONS


def test_existing_raw_and_power_branches_are_exactly_preserved():
    branches = schemas.load("rf-analysis")["oneOf"]
    assert len(branches) == 3
    # 이전 두 schema 객체의 독립 고정 지문: 새 profile의 제약을 역적용하지 않는다.
    expected = ["2f13dcaad1f9f27002269c86682f3b3ea90f3143a3a496686aecedbdf154db67",
                "6d13c79bca5e5dab2ded5e5f3590159f1f49ebacf13f1555bbc7709536643e85"]
    assert [hashlib.sha256(json.dumps(x, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
            for x in branches[:2]] == expected


@pytest.mark.parametrize("path", [(), ("source",), ("params",), ("metadata",), ("conversion",), ("output",)])
def test_manifest_every_object_is_closed_and_every_key_required(path):
    good = report()
    for key in at(good, path):
        changed = copy.deepcopy(good)
        del at(changed, path)[key]
        with pytest.raises(ValidationFailed):
            schemas.validate("rf-ook-conversion", changed)
    at(good, path)["raw_private_field"] = "RAW_SECRET"
    with pytest.raises(ValidationFailed):
        schemas.validate("rf-ook-conversion", good)


@pytest.mark.parametrize(("path", "replacement"), [
    (("schema",), "pweh.rf-raw-analysis/v1"), (("profile",), "guess"), (("status",), "partial"),
    (("source", "kind"), "evidence"), (("source", "artifact_id"), "A-001"),
    (("source", "artifact_id"), "A-123456789"), (("source", "artifact_id"), "A-0001\n"),
    (("source", "size"), 0), (("source", "size"), 1048577), (("source", "size"), True),
    (("source", "sha256"), "A" * 64), (("source", "sha256"), "a" * 64 + "\n"),
    (("params", "source_profile"), "flipper-raw-ook-v1"), (("params", "max_seconds"), 0),
    (("params", "max_seconds"), 5.01), (("params", "max_seconds"), True),
    (("metadata", "declared_preset"), "FuriHalSubGhzPreset2FSKDev238Async"),
    (("metadata", "declared_frequency_hz"), -1), (("metadata", "declared_frequency_hz"), 2 ** 32),
    (("metadata", "declared_frequency_hz"), False), (("conversion", "format"), "raw"),
    (("conversion", "unit"), "ns"), (("conversion", "pairing"), "inferred"),
    (("conversion", "duration_count"), 1), (("conversion", "duration_count"), 2401),
    (("conversion", "pair_count"), 0), (("conversion", "pair_count"), 1201),
    (("conversion", "pair_count"), True), (("conversion", "total_duration_us"), 1),
    (("conversion", "total_duration_us"), 5153960752801), (("output", "size"), 46),
    (("output", "size"), 26444), (("output", "size"), True),
    (("output", "path"), "analysis/rf-ook-000/converted.ook"),
    (("output", "path"), "analysis/rf-ook-065/converted.ook"),
    (("output", "path"), "analysis/rf-ook-001/converted.ook\n"),
    (("output", "path"), "analysis/rf-ook-001/manifest.json"),
    (("output", "sha256"), "b" * 64 + "\n"),
])
def test_manifest_invalid_types_ranges_profiles_and_paths(path, replacement):
    value = report()
    set_at(value, path, replacement)
    with pytest.raises(ValidationFailed):
        schemas.validate("rf-ook-conversion", value)


@pytest.mark.parametrize("flag", FLAGS)
@pytest.mark.parametrize("replacement", [True, 0, None])
def test_false_claims_are_exact(flag, replacement):
    for name, value in (("rf-ook-conversion", report()), ("rf-analysis", summary())):
        value[flag] = replacement
        with pytest.raises(ValidationFailed):
            schemas.validate(name, value)


@pytest.mark.parametrize("index", range(9))
def test_limitations_are_ordered_and_closed(index):
    value = report()
    value["limitations"][index] = "unknown"
    with pytest.raises(ValidationFailed):
        schemas.validate("rf-ook-conversion", value)


@pytest.mark.parametrize(("path", "replacement"), [
    (("source", "size"), 200.0), (("metadata", "declared_frequency_hz"), 315000000.0),
    (("conversion", "pair_count"), 1.0), (("output", "size"), 51.0),
    (("conversion", "duration_count"), 3), (("conversion", "total_duration_us"), 2 * 2147483647 + 1),
    (("output", "size"), 66),
])
def test_schema_then_semantic_checker_enforces_exact_numbers_and_relations(path, replacement):
    value = report()
    set_at(value, path, replacement)
    schemas.validate("rf-ook-conversion", value)
    with pytest.raises(PwehError) as caught:
        rf_ook.validate_ook_accounting(value)
    assert caught.value.code == "rf_ook_failed"


@pytest.mark.parametrize("number", [1, 64])
def test_directory_endpoints_and_manifest_bounds(number):
    value = report()
    value["output"]["path"] = f"analysis/rf-ook-{number:03}/converted.ook"
    schemas.validate("rf-ook-conversion", value)
    rf_ook.validate_ook_accounting(value)
    schemas.validate("rf-analysis", summary(number))


@pytest.mark.parametrize(("analysis", "output"), [(1, 2), (2, 1), (0, 0), (65, 65), (1, 64)])
def test_summary_directory_pairs_cannot_be_mixed(analysis, output):
    value = summary(analysis)
    value["conversion_results"][0]["output_path"] = f"analysis/rf-ook-{output:03}/converted.ook"
    with pytest.raises(ValidationFailed):
        schemas.validate("rf-analysis", value)


@pytest.mark.parametrize("field", ["input_artifact_id", "analysis_path", "report_sha256", "output_path", "output_sha256"])
def test_summary_newline_is_rejected(field):
    value = summary()
    value["conversion_results"][0][field] += "\n"
    with pytest.raises(ValidationFailed):
        schemas.validate("rf-analysis", value)


@pytest.mark.parametrize("mode", ["offline-raw", "offline-power"])
def test_summary_cannot_relabel_or_merge_old_modes(mode):
    value = summary()
    value["mode"] = mode
    with pytest.raises(ValidationFailed):
        schemas.validate("rf-analysis", value)
    value = summary()
    value["raw_results" if mode == "offline-raw" else "power_results"] = []
    with pytest.raises(ValidationFailed):
        schemas.validate("rf-analysis", value)


@pytest.mark.parametrize("count", [0, 129])
def test_summary_result_count_is_bounded(count):
    value = summary()
    value["conversion_results"] *= count
    with pytest.raises(ValidationFailed):
        schemas.validate("rf-analysis", value)


def test_summary_row_required_keys_and_extra_fields():
    good = summary()
    for key in good["conversion_results"][0]:
        value = copy.deepcopy(good)
        del value["conversion_results"][0][key]
        with pytest.raises(ValidationFailed):
            schemas.validate("rf-analysis", value)
    for path in [(), ("conversion_results", 0)]:
        value = copy.deepcopy(good)
        at(value, path)["private"] = "RAW_SECRET"
        with pytest.raises(ValidationFailed):
            schemas.validate("rf-analysis", value)
