"""공급 숫자 보고서와 요약의 닫힌 필드·상태 조합을 독립 fixture로 검사한다."""

from __future__ import annotations

import copy

import pytest
from jsonschema import Draft202012Validator

from pweh import schemas
from pweh.errors import ValidationFailed

FLAGS = ("frame_freshness_verified", "game_semantics_verified", "action_generated")
REASONS = {"no_observations": "unknown", "no_recent_observations": "stale",
           "insufficient_valid": "unknown", "tied_votes": "unknown",
           "insufficient_votes": "unknown", "vote_consensus": "stable"}


def report(reason="vote_consensus"):
    counts = {
        "no_observations": (0, 0, 0, 0, 0, 0, None),
        "no_recent_observations": (3, 3, 0, 0, 0, 0, 7),
        "insufficient_valid": (1, 1, 1, 0, 0, 0, 0),
        "tied_votes": (4, 4, 4, 4, 2, 2, 0),
        "insufficient_votes": (3, 3, 3, 3, 2, 1, 0),
        "vote_consensus": (3, 3, 3, 3, 3, 1, 0),
    }[reason]
    evidence = dict(zip(("received_count", "window_count", "recent_count", "valid_count", "winning_votes",
                         "tied_leaders", "latest_age_seconds"), counts))
    return {
        "schema": "pweh.numeric-validation/v1", "profile": "supplied-numeric-observations-v1",
        "source": {"kind": "supplied-observations", "input_kind": "numeric-observations", "observation_count": counts[0],
                   "canonicalization": "pweh-numeric-json-v1", "canonical_size": 300, "canonical_sha256": "a" * 64},
        "params": {"now": 10},
        "analysis": {"schema": "pweh.numeric-observations/v1", "status": REASONS[reason], "reason": reason,
                     "value": -7 if reason == "vote_consensus" else None, "evidence": evidence,
                     "policy": {"window_size": 5, "votes_required": 3, "min_valid": 3, "min_confidence": 0.8, "ttl_seconds": 2.0},
                     **{k: False for k in FLAGS}},
        "limitations": ["user_time_axis_only", "input_digest_not_acquisition_provenance", "raw_observations_not_stored"],
    }


def summary(reason="vote_consensus"):
    return {"schema": "pweh.numeric-analysis/v1", "mode": "supplied-numeric-observations",
            "results": [{"artifact_id": "A-0001", "analysis_path": "analysis/numeric-observations-001.json",
                         "report_sha256": "a" * 64, "status": REASONS[reason], "reason": reason,
                         "observation_count": report(reason)["source"]["observation_count"]}],
            **{k: False for k in FLAGS}}


def replace(doc, path, value):
    node = doc
    for key in path[:-1]:
        node = node[key]
    node[path[-1]] = value


@pytest.mark.parametrize("name", ["numeric-validation", "numeric-analysis"])
def test_schema_and_optional_skill_mapping(name):
    Draft202012Validator.check_schema(schemas.load(name))
    assert schemas.SKILL_DATA_SCHEMAS["numeric-observation-analysis"] == "numeric-analysis"


@pytest.mark.parametrize("reason", REASONS)
def test_six_reasons_are_valid_completed_results(reason):
    schemas.validate("numeric-validation", report(reason))
    schemas.validate("numeric-analysis", summary(reason))


@pytest.mark.parametrize("path", [(), ("source",), ("params",), ("analysis",),
                                  ("analysis", "evidence"), ("analysis", "policy")])
def test_report_rejects_extra_raw_field(path):
    doc = report()
    node = doc
    for key in path:
        node = node[key]
    node["PRIVATE_RAW"] = "PRIVATE_VALUE"
    with pytest.raises(ValidationFailed):
        schemas.validate("numeric-validation", doc)


@pytest.mark.parametrize("path,value", [
    (("profile",), "other"), (("source", "kind"), "device-read"),
    (("source", "canonicalization"), "rfc8785"), (("source", "canonical_sha256"), "A" * 64),
    (("source", "canonical_size"), 0), (("source", "canonical_size"), 65537),
    (("source", "observation_count"), True), (("source", "observation_count"), 257),
    (("source", "observation_count"), 0), (("params", "now"), -1), (("params", "now"), 2**53 + 1),
    (("params", "now"), "10"), (("analysis", "schema"), "other"), (("analysis", "status"), "unknown"),
    (("analysis", "value"), None), (("analysis", "value"), True), (("analysis", "value"), 2**63),
    (("analysis", "value"), -(2**63)-1), (("analysis", "reason"), "other"),
    (("analysis", "evidence", "latest_age_seconds"), None),
    (("analysis", "evidence", "winning_votes"), 257), (("analysis", "evidence", "tied_leaders"), 2),
    (("analysis", "policy", "window_size"), 0), (("analysis", "policy", "votes_required"), 257),
    (("analysis", "policy", "min_valid"), True), (("analysis", "policy", "min_confidence"), 1.1),
    (("analysis", "policy", "ttl_seconds"), 0), (("analysis", "policy", "ttl_seconds"), 86401),
    (("limitations",), []),
])
def test_report_types_ranges_and_fixed_relations(path, value):
    doc = report()
    replace(doc, path, value)
    with pytest.raises(ValidationFailed):
        schemas.validate("numeric-validation", doc)


@pytest.mark.parametrize("reason", REASONS)
def test_summary_state_reason_and_zero_count_are_coupled(reason):
    doc = summary(reason)
    doc["results"][0]["status"] = "stale" if REASONS[reason] != "stale" else "stable"
    with pytest.raises(ValidationFailed):
        schemas.validate("numeric-analysis", doc)
    doc = summary(reason)
    doc["results"][0]["observation_count"] = 1 if reason == "no_observations" else 0
    with pytest.raises(ValidationFailed):
        schemas.validate("numeric-analysis", doc)


@pytest.mark.parametrize("flag", FLAGS)
@pytest.mark.parametrize("value", [True, 0, "false"])
def test_verification_flags_cannot_be_upgraded_or_coerced(flag, value):
    for name, doc, target in (("numeric-validation", report(), "analysis"), ("numeric-analysis", summary(), None)):
        (doc[target] if target else doc)[flag] = value
        with pytest.raises(ValidationFailed):
            schemas.validate(name, doc)


@pytest.mark.parametrize("field,value", [
    ("artifact_id", "../../a"), ("analysis_path", "analysis/other-001.json"),
    ("report_sha256", "A" * 64), ("observation_count", 257), ("value", 7), ("now", 3),
])
def test_summary_has_only_six_result_fields(field, value):
    doc = summary()
    doc["results"][0][field] = value
    with pytest.raises(ValidationFailed):
        schemas.validate("numeric-analysis", doc)


@pytest.mark.parametrize("length", [0, 129])
def test_summary_count_is_bounded(length):
    doc = summary()
    doc["results"] = [copy.deepcopy(doc["results"][0]) for _ in range(length)]
    with pytest.raises(ValidationFailed):
        schemas.validate("numeric-analysis", doc)
