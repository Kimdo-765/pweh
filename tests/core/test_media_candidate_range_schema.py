"""EV 구간 분기의 폐쇄 shape와 기존 후보·prefix 저장물 호환을 독립 자료로 확인한다."""

from __future__ import annotations

import copy

import pytest

from pweh import schemas
from pweh.errors import ValidationFailed


OLD_LIMITATIONS = ["top_level_framing_only", "payloads_unexamined", "original_file_boundary_unknown",
                    "reported_candidates_only_relations", "no_media_type_confirmation",
                    "no_playback_time_or_encryption_validation"]
NEW_LIMITATIONS = OLD_LIMITATIONS + ["explicit_evidence_range_only", "outside_range_unexamined"]


def old_report():
    """코어 호출이나 range 분기 치환 없이 표현한 기존16바이트 후보 보고서."""
    return {
        "schema": "pweh.media-candidates/v1", "profile": "ftyp-contiguous-top-level-v1", "status": "ok",
        "media_decoded": False, "playback_verified": False, "recording_time_verified": False,
        "encryption_assessed": False, "format_conformance_assessed": False,
        "original_file_boundary_verified": False, "physical_carving_performed": False,
        "summary": {"anchors_observed": 1, "anchors_rejected": 0, "supported_anchors": 1,
                    "candidates_reported": 1, "candidates_omitted": 0, "anchor_rejections": {
                        "size_zero": 0, "truncated_extended_header": 0, "size_below_header": 0,
                        "box_beyond_selection": 0, "invalid_ftyp_shape": 0, "unknown_brand": 0}},
        "coverage": {"input_bytes": 16, "search_positions_total": 9, "search_positions_examined": 9,
                     "unexamined_positions": None, "pending_anchor_offset": None,
                     "search_complete": True, "candidate_checks_complete": True, "candidate_list_complete": True,
                     "anchor_probes": 1, "boxes_examined": 1, "brand_slots_examined": 1, "structure_bytes_read": 12,
                     "relations_scope": "reported_candidates", "relation_pairs_total": 0,
                     "relation_pairs_examined": 0, "relations_complete": True,
                     "selection_uncertain": False, "container_examined": False, "reasons": []},
        "candidates": [{"index": 0, "offset": 0, "validated_prefix_length": 16, "boxes_validated": 1,
                        "box_counts": {"ftyp": 1, "moov": 0, "mdat": 0, "moof": 0, "styp": 0,
                                       "free": 0, "skip": 0, "wide": 0, "uuid": 0},
                        "known_brands": ["isom"], "end_reason": "selection_end", "framing_status": "complete",
                        "overlap_with_reported": [], "contained_by_reported": [],
                        "confidence": "possible", "complete_recording": False}],
        "limitations": list(OLD_LIMITATIONS),
        "source": {"kind": "evidence", "evidence_id": "EV-0001", "evidence_sha256": "1" * 64,
                   "container": "file", "member_selected": False, "selected_sha256": "2" * 64,
                   "selected_size": 16, "complete": True, "method": "whole-file", "confidence": "high",
                   "partition": None, "ref": None, "deleted": None, "parent_deleted": None,
                   "container_truncated": None, "container_truncated_reasons": []},
        "params": {"partition": None, "method": "auto", "max_seconds": 1.5},
    }


def range_report():
    report = old_report()
    report["profile"] = "ftyp-contiguous-ev-range-v1"
    report["limitations"] = list(NEW_LIMITATIONS)
    report["source"].update(method="byte-range", evidence_size=128 << 20, offset=4096)
    report["params"].update(offset=4096, length=16)
    return report


def prefix(report):
    """기존 prefix shape는 source 외 새 field/profile 없이 유지한다."""
    return {
        "schema": "pweh.media-prefix-extract/v1", "method": "media_candidate_prefix", "status": "ok",
        "evidence_id": "EV-0001", "evidence_sha256": "1" * 64, "source": copy.deepcopy(report["source"]),
        "analysis": {"path": "forensics/analysis/media-candidates-EV-0001-001.json", "sha256": "4" * 64,
                     "size": 4000, "custody_seq": 2, "custody_hash": "5" * 64},
        "candidate": copy.deepcopy(report["candidates"][0]), "source_status": "ok",
        "source_coverage": copy.deepcopy(report["coverage"]), "effective_selection_uncertain": False,
        "effective_container_listing_incomplete": False,
        "files": [{"file": "candidate-000.bin", "size": 16, "sha256": "3" * 64, "complete": True}],
        "bytes_total": 16, "media_decoded": False, "playback_verified": False,
        "recording_time_verified": False, "encryption_assessed": False, "format_conformance_assessed": False,
        "original_file_boundary_verified": False, "complete_recording": False,
    }


def validate(report, manifest=False):
    schemas.validate("media-prefix-extract" if manifest else "media-candidates", prefix(report) if manifest else report)


@pytest.mark.parametrize("manifest", [False, True])
@pytest.mark.parametrize("kind", ["file", "filesystem", "tar", "zip"])
def test_independent_old_sources_keep_exact_contract(manifest, kind):
    report = old_report()
    if kind == "filesystem":
        report["source"].update(container=kind, member_selected=True, method="chain", partition=1,
                                ref="root/0", deleted=False, parent_deleted=False)
        report["params"]["partition"] = 1
    elif kind in {"tar", "zip"}:
        report["source"].update(container=kind, member_selected=True, method="archive-member", ref="arc:0",
                                deleted=False, container_truncated=False)
    validate(report, manifest)


@pytest.mark.parametrize("manifest", [False, True])
def test_range_source_is_same_eighteen_fields_in_both_schemas(manifest):
    report = range_report()
    assert len(report["source"]) == 18 and len(report["params"]) == 5
    validate(report, manifest)


@pytest.mark.parametrize("manifest", [False, True])
@pytest.mark.parametrize("field,value", [("offset", None), ("evidence_size", None),
                                         ("offset", 0), ("evidence_size", 16), ("method", "byte-range")])
def test_old_source_cannot_receive_range_fields_or_method(manifest, field, value):
    report = old_report()
    report["source"][field] = value
    with pytest.raises(ValidationFailed):
        validate(report, manifest)


@pytest.mark.parametrize("manifest", [False, True])
@pytest.mark.parametrize("field,value", [
    ("evidence_size", 0), ("evidence_size", 2**63), ("evidence_size", True),
    ("offset", -1), ("offset", 2**63), ("offset", False),
    ("selected_size", 0), ("selected_size", (64 << 20) + 1),
    ("method", "whole-file"), ("method", "archive-member"), ("container", "filesystem"),
    ("member_selected", True), ("complete", False), ("confidence", "medium"),
    ("partition", 1), ("ref", "root/0"), ("deleted", False), ("parent_deleted", False),
    ("container_truncated", False), ("container_truncated_reasons", ["max_entries"]),
    ("size", 16), ("length", 16), ("path", "private-synthetic-path"),
])
def test_range_source_is_closed_and_bounded(manifest, field, value):
    report = range_report()
    report["source"][field] = value
    with pytest.raises(ValidationFailed):
        validate(report, manifest)


@pytest.mark.parametrize("manifest", [False, True])
@pytest.mark.parametrize("field", ["offset", "evidence_size", "method", "complete", "selected_sha256"])
def test_range_source_requires_identity_fields(manifest, field):
    report = range_report()
    del report["source"][field]
    with pytest.raises(ValidationFailed):
        validate(report, manifest)


@pytest.mark.parametrize("mutation", [
    "old-profile", "old-limits", "old-source", "old-params", "missing-offset", "missing-length",
    "params-ref", "params-bad-method", "params-partition", "params-length-zero", "params-offset-huge",
])
def test_candidate_profile_and_params_cannot_mix(mutation):
    report = range_report()
    if mutation.startswith("old-"):
        key = {"old-profile": "profile", "old-limits": "limitations", "old-source": "source", "old-params": "params"}[mutation]
        report[key] = old_report()[key]
    elif mutation.startswith("missing-"):
        del report["params"][mutation.removeprefix("missing-")]
    else:
        field, value = {
            "params-ref": ("ref", "arc:0"), "params-bad-method": ("method", "chain"),
            "params-partition": ("partition", 1), "params-length-zero": ("length", 0),
            "params-offset-huge": ("offset", 2**63),
        }[mutation]
        report["params"][field] = value
    with pytest.raises(ValidationFailed):
        validate(report)


@pytest.mark.parametrize("key", ["offset", "length"])
@pytest.mark.parametrize("value", [None, 0, 16])
def test_old_params_do_not_gain_optional_range_keys(key, value):
    report = old_report()
    report["params"][key] = value
    with pytest.raises(ValidationFailed):
        validate(report)


def test_small_range_can_be_reported_but_not_a_prefix_source():
    report = range_report()
    report["source"]["selected_size"] = 1
    report["params"]["length"] = 1
    report["status"] = "unsupported"
    report["candidates"] = []
    report["summary"].update(anchors_observed=0, supported_anchors=0, candidates_reported=0)
    report["coverage"].update(input_bytes=1, search_positions_total=0, search_positions_examined=0,
                              anchor_probes=0, boxes_examined=0, brand_slots_examined=0, structure_bytes_read=0)
    validate(report)
    manifest = prefix(range_report())
    manifest["source"]["selected_size"] = 1
    with pytest.raises(ValidationFailed):
        schemas.validate("media-prefix-extract", manifest)


def test_prefix_does_not_add_an_unbound_profile_or_params():
    for field, value in (("profile", "ftyp-contiguous-ev-range-v1"), ("params", range_report()["params"])):
        manifest = prefix(range_report())
        manifest[field] = value
        with pytest.raises(ValidationFailed):
            schemas.validate("media-prefix-extract", manifest)
