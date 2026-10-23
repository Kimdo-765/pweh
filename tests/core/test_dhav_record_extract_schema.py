"""독립 manifest로 DHAV record 추출의 닫힌 형태와 상태·출처 분기를 확인한다."""

from __future__ import annotations

import copy
import itertools

import pytest

from pweh.errors import ValidationFailed
from pweh.schemas import validate


def manifest(*, ranged=False):
    """제품 scanner/loader를 쓰지 않는 최소33bytes 구조 후보 fixture."""
    result = {
        "schema": "pweh.dhav-record-extract/v1", "method": "dhav_record", "status": "ok",
        "evidence_id": "EV-0001", "evidence_sha256": "a" * 64,
        "source": {"kind": "evidence", "evidence_id": "EV-0001", "evidence_sha256": "a" * 64,
            "container": "file", "member_selected": False, "selected_sha256": "b" * 64,
            "selected_size": 33, "complete": True, "method": "whole-file", "confidence": "high",
            "partition": None, "ref": None, "deleted": None, "parent_deleted": None,
            "container_truncated": None, "container_truncated_reasons": []},
        "analysis": {"path": "forensics/analysis/dhav-candidates-EV-0001-001.json", "sha256": "c" * 64,
                     "size": 2048, "custody_seq": 2, "custody_hash": "d" * 64},
        "candidate": {"index": 0, "offset": 0, "record_length": 33, "header_length": 24,
            "extension_length": 0, "payload_length": 1, "record_type": "type_f0",
            "footer_length_matches": True, "confidence": "possible"},
        "source_status": "ok",
        "source_coverage": {"input_bytes": 33, "search_positions_total": 30,
            "search_positions_examined": 30, "unexamined_positions": None,
            "pending_anchor_offset": None, "search_complete": True, "candidate_checks_complete": True,
            "candidate_list_complete": True, "anchor_probes": 1, "structure_bytes_read": 14,
            "selection_uncertain": False, "container_examined": False, "reasons": []},
        "effective_selection_uncertain": False, "effective_container_listing_incomplete": False,
        "files": [{"file": "record-000.bin", "size": 33, "sha256": "e" * 64, "complete": True}],
        "bytes_total": 33, "payload_semantics_examined": False, "extension_fields_examined": False,
        "checksum_verified": False, "media_decoded": False, "playback_verified": False,
        "recording_time_verified": False, "encryption_assessed": False,
        "original_file_boundary_verified": False, "complete_recording": False,
    }
    if ranged:
        result["source"].update(method="byte-range", offset=100, evidence_size=233)
    return result


def valid(result):
    validate("dhav-record-extract", result)


@pytest.mark.parametrize("ranged", [False, True])
def test_two_closed_source_branches(ranged):
    result = manifest(ranged=ranged)
    valid(result)
    assert len(result["source"]) == (18 if ranged else 16)
    assert "profile" not in result and "params" not in result and "summary" not in result


@pytest.mark.parametrize("kind", ["type_f0", "type_fc", "type_fd"])
def test_three_record_types_and_extension255(kind):
    result = manifest()
    result["candidate"].update(record_type=kind, header_length=279, extension_length=255,
                               record_length=288)
    result["source"]["selected_size"] = 288
    result["source_coverage"].update(input_bytes=288, search_positions_total=285,
                                      search_positions_examined=285)
    result["files"][0]["size"] = result["bytes_total"] = 288
    valid(result)


@pytest.mark.parametrize("upstream,uncertain,incomplete", list(itertools.product([False, True], repeat=3)))
def test_status_is_exact_upstream_or_effective_flags(upstream, uncertain, incomplete):
    result = manifest()
    result["source_status"] = "partial" if upstream else "ok"
    if upstream:
        result["source_coverage"]["reasons"] = ["record_framing_incomplete"]
        result["source_coverage"].update(candidate_checks_complete=False, candidate_list_complete=False)
    result["effective_selection_uncertain"] = uncertain
    result["effective_container_listing_incomplete"] = incomplete
    result["status"] = "partial" if upstream or uncertain or incomplete else "ok"
    valid(result)
    result["status"] = "ok" if result["status"] == "partial" else "partial"
    with pytest.raises(ValidationFailed):
        valid(result)


@pytest.mark.parametrize("key,value", [
    ("reasons", ["selection_uncertain"]), ("selection_uncertain", True),
    ("search_complete", False), ("candidate_checks_complete", False), ("candidate_list_complete", False),
    ("pending_anchor_offset", 0),
    ("unexamined_positions", {"start": 0, "count": 30, "reason": "time_limit"}),
])
def test_original_ok_requires_complete_original_coverage(key, value):
    result = manifest()
    result["source_coverage"][key] = value
    result["effective_selection_uncertain"] = True
    result["status"] = "partial"  # fresh 불확실성이 원래 모순을 가리지 못한다.
    with pytest.raises(ValidationFailed):
        valid(result)


def test_original_partial_keeps_nonempty_original_reasons():
    result = manifest()
    result.update(source_status="partial", status="partial")
    with pytest.raises(ValidationFailed):
        valid(result)


def filesystem(result):
    result["source"].update(container="filesystem", member_selected=True, partition=1,
                            ref="root/3", method="chain", deleted=False, parent_deleted=False)
    return result


@pytest.mark.parametrize("where,key,value", [
    ("source", "deleted", True), ("source", "parent_deleted", True),
    ("source", "parent_deleted", None), ("source", "confidence", "low"),
    ("source_coverage", "selection_uncertain", True),
])
def test_original_selection_uncertainty_cannot_be_downgraded(where, key, value):
    result = filesystem(manifest())
    result[where][key] = value
    result.update(source_status="partial", status="partial")
    result["source_coverage"].update(selection_uncertain=True, reasons=["selection_uncertain"])
    result["effective_selection_uncertain"] = True
    valid(result)
    result["effective_selection_uncertain"] = False
    with pytest.raises(ValidationFailed):
        valid(result)


@pytest.mark.parametrize("source_flag", [False, True])
def test_listing_incomplete_is_never_downgraded(source_flag):
    result = manifest()
    result["source"].update(container="zip", member_selected=True, method="archive-member", ref="arc:0",
                            deleted=False, container_truncated=source_flag,
                            container_truncated_reasons=["max_entries"] if source_flag else [])
    result.update(source_status="partial", status="partial", effective_container_listing_incomplete=True)
    result["source_coverage"]["reasons"] = ["container_listing_incomplete"]
    valid(result)
    result["effective_container_listing_incomplete"] = False
    with pytest.raises(ValidationFailed):
        valid(result)


@pytest.mark.parametrize("path,value", [
    (("method",), "media_candidate_prefix"), (("schema",), "pweh.media-prefix-extract/v1"),
    (("candidate", "record_length"), 32), (("candidate", "record_length"), (64 << 20) + 1),
    (("candidate", "extension_length"), 256), (("candidate", "header_length"), 23),
    (("candidate", "payload_length"), 0), (("candidate", "index"), 128),
    (("candidate", "offset"), (64 << 20) - 32), (("candidate", "record_type"), "type_f1"),
    (("candidate", "footer_length_matches"), False), (("candidate", "confidence"), "confirmed"),
    (("source", "selected_size"), 32), (("source", "selected_size"), (64 << 20) + 1),
    (("files", 0, "file"), "candidate-000.bin"), (("files", 0, "size"), 32),
    (("files", 0, "complete"), False), (("bytes_total",), 32),
    (("analysis", "size"), (1 << 20) + 1), (("analysis", "custody_seq"), 0),
    (("analysis", "path"), "forensics/analysis/media-candidates-EV-0001-001.json"),
])
def test_fixed_subset_and_file_bounds(path, value):
    result, owner = manifest(), None
    owner = result
    for key in path[:-1]:
        owner = owner[key]
    owner[path[-1]] = value
    with pytest.raises(ValidationFailed):
        valid(result)


@pytest.mark.parametrize("key", ["payload_semantics_examined", "extension_fields_examined", "checksum_verified",
    "media_decoded", "playback_verified", "recording_time_verified", "encryption_assessed",
    "original_file_boundary_verified", "complete_recording"])
def test_all_nine_claims_are_false(key):
    result = manifest()
    result[key] = True
    with pytest.raises(ValidationFailed):
        valid(result)


@pytest.mark.parametrize("path", [(), ("source",), ("analysis",), ("candidate",), ("source_coverage",),
                                   ("files", 0)])
def test_no_raw_extension_fields(path):
    result, owner = manifest(), None
    owner = result
    for key in path:
        owner = owner[key]
    owner["raw"] = "SYNTHETIC_PRIVATE_NAME_TIME_BODY"
    with pytest.raises(ValidationFailed):
        valid(result)


@pytest.mark.parametrize("field", ["profile", "params", "summary", "format_conformance_assessed"])
def test_no_new_manifest_profile_params_or_bmff_claim(field):
    result = manifest()
    result[field] = {}
    with pytest.raises(ValidationFailed):
        valid(result)


@pytest.mark.parametrize("key", list(manifest()))
def test_all_manifest_fields_required(key):
    result = manifest()
    del result[key]
    with pytest.raises(ValidationFailed):
        valid(result)


@pytest.mark.parametrize("mutation", ["missing-offset", "missing-evidence-size", "old-method", "extra-range",
                                     "empty", "files-empty", "files-two"])
def test_no_mixed_source_or_multiple_files(mutation):
    result = manifest(ranged=mutation in {"missing-offset", "missing-evidence-size", "old-method"})
    if mutation.startswith("missing-"):
        del result["source"]["offset" if mutation == "missing-offset" else "evidence_size"]
    elif mutation == "old-method":
        result["source"]["method"] = "whole-file"
    elif mutation == "extra-range":
        result["source"]["offset"] = 0
    elif mutation == "empty":
        filesystem(result)["source"].update(method="empty", selected_size=0)
    elif mutation == "files-empty":
        result["files"] = []
    else:
        result["files"].append(copy.deepcopy(result["files"][0]))
    with pytest.raises(ValidationFailed):
        valid(result)
