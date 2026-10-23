"""독립 합성 manifest의 형식·출처·원래 불확실성 보존을 검사한다."""
from __future__ import annotations

import copy
import itertools

import pytest
from pweh.errors import ValidationFailed
from pweh.schemas import validate

FORMATS = ("jpeg", "avc-annexb", "mpeg2-ps", "xm")
PROFILES = dict(zip(FORMATS, ("jpeg-baseline-marker-v1", "avc-annexb-delimited-nal-v1",
                            "mpeg2-ps-bounded-pack-prefix-v1", "xm-length-delimited-frame-v1")))


def manifest(*, format="xm", ranged=False, prefix=False):
    unit, subtype, length, boundary = {
        "jpeg": ("jpeg_codestream", "baseline", 28, "eoi"),
        "avc-annexb": ("avc_nal", "nal_10", 4, "next_nal"),
        "mpeg2-ps": ("mpeg2_ps_pack_prefix", "mpeg2_pack", 24, "next_pack"),
        "xm": ("xm_frame", "type_fd", 9, "declared_length"),
    }[format]
    size = length + (4 if format == "avc-annexb" else 0)
    profile = PROFILES[format]
    result = {
        "schema": "pweh.media-unit-extract/v1", "method": "media_unit", "status": "ok",
        "format": format, "source_profile": profile[:-3] + "-ev-range-v1" if ranged else profile,
        "evidence_id": "EV-0001", "evidence_sha256": "a" * 64,
        "source": {"kind": "evidence", "evidence_id": "EV-0001", "evidence_sha256": "a" * 64,
            "container": "file", "member_selected": False, "selected_sha256": "b" * 64,
            "selected_size": size, "complete": True, "method": "whole-file", "confidence": "high",
            "partition": None, "ref": None, "deleted": None, "parent_deleted": None,
            "container_truncated": None, "container_truncated_reasons": []},
        "analysis": {"path": "forensics/analysis/media-unit-candidates-EV-0001-001.json", "sha256": "c" * 64,
                     "size": 2048, "custody_seq": 2, "custody_hash": "d" * 64},
        "candidate": {"index": 0, "offset": 0, "length": length, "format": format, "unit": unit,
            "unit_subtype": subtype, "boundary_kind": boundary, "framing_status": "closed",
            "end_reason": boundary, "confidence": "possible"},
        "source_status": "ok",
        "source_coverage": {"input_bytes": size, "search_positions_total": size,
            "search_positions_examined": size, "unexamined_positions": None,
            "pending_anchor_offset": None, "search_complete": True, "candidate_checks_complete": True,
            "candidate_list_complete": True, "anchor_probes": 1, "structure_steps": 2,
            "search_bytes_charged": size, "structure_bytes_charged": size, "work_bytes_charged": 2 * size,
            "selection_uncertain": False, "container_examined": False, "reasons": []},
        "effective_selection_uncertain": False, "effective_container_listing_incomplete": False,
        "files": [{"file": "unit-000.bin", "size": length, "sha256": "e" * 64, "complete": True}],
        "bytes_total": length, "payload_semantics_examined": False, "format_conformance_assessed": False,
        "media_decoded": False, "playback_verified": False, "recording_time_verified": False,
        "encryption_assessed": False, "original_file_boundary_verified": False, "complete_recording": False,
    }
    if ranged:
        result["source"].update(method="byte-range", offset=100, evidence_size=100 + size)
    if prefix:
        result.update(status="partial", source_status="partial")
        result["candidate"].update(boundary_kind="validated_prefix", end_reason="selection_end", framing_status="prefix")
        result["source_coverage"]["reasons"] = ["candidate_prefix_partial"]
    return result


def valid(value):
    validate("media-unit-extract", value)


@pytest.mark.parametrize("format,ranged", list(itertools.product(FORMATS, (False, True))))
def test_eight_exact_format_source_profile_branches(format, ranged):
    value = manifest(format=format, ranged=ranged)
    valid(value)
    assert len(value["source"]) == (18 if ranged else 16)
    assert len(value["candidate"]) == 10
    for other in FORMATS:
        if other == format:
            continue
        bad = copy.deepcopy(value)
        bad["format"] = other
        with pytest.raises(ValidationFailed):
            valid(bad)
    bad = copy.deepcopy(value)
    bad["source_profile"] = PROFILES[format] if ranged else PROFILES[format][:-3] + "-ev-range-v1"
    with pytest.raises(ValidationFailed):
        valid(bad)


@pytest.mark.parametrize("format", FORMATS)
def test_prefix_is_only_ps_and_cannot_claim_source_ok(format):
    value = manifest(format=format, prefix=True)
    if format != "mpeg2-ps":
        with pytest.raises(ValidationFailed):
            valid(value)
        return
    valid(value)
    for end in ("selection_end", "truncated_packet", "unsupported_packet", "invalid_packet", "zero_length_packet"):
        value["candidate"]["end_reason"] = end
        valid(value)
    value["source_status"] = "ok"
    value["source_coverage"]["reasons"] = []
    with pytest.raises(ValidationFailed):
        valid(value)


@pytest.mark.parametrize("upstream,uncertain,incomplete", list(itertools.product((False, True), repeat=3)))
def test_status_is_exact_union_of_saved_and_effective_uncertainty(upstream, uncertain, incomplete):
    value = manifest()
    value["source_status"] = "partial" if upstream else "ok"
    if upstream:
        value["source_coverage"].update(reasons=["unit_framing_incomplete"], candidate_checks_complete=False,
                                        candidate_list_complete=False)
    value["effective_selection_uncertain"] = uncertain
    value["effective_container_listing_incomplete"] = incomplete
    value["status"] = "partial" if upstream or uncertain or incomplete else "ok"
    valid(value)
    value["status"] = "partial" if value["status"] == "ok" else "ok"
    with pytest.raises(ValidationFailed):
        valid(value)


@pytest.mark.parametrize("where,key,value", [
    ("source", "deleted", True), ("source", "parent_deleted", True), ("source", "parent_deleted", None),
    ("source", "confidence", "low"), ("source_coverage", "selection_uncertain", True),
])
def test_saved_uncertainty_cannot_be_removed(where, key, value):
    result = manifest()
    result["source"].update(container="filesystem", member_selected=True, partition=1, ref="root/3",
                            method="chain", deleted=False, parent_deleted=False)
    result[where][key] = value
    result.update(source_status="partial", status="partial", effective_selection_uncertain=True)
    result["source_coverage"].update(selection_uncertain=True, reasons=["selection_uncertain"])
    valid(result)
    result["effective_selection_uncertain"] = False
    with pytest.raises(ValidationFailed):
        valid(result)


@pytest.mark.parametrize("section", [None, "source", "candidate", "source_coverage", "analysis", "files"])
def test_closed_objects_reject_raw_fields(section):
    value = manifest()
    target = value if section is None else value[section][0] if section == "files" else value[section]
    target["private_original"] = "SYNTHETIC_PRIVATE_MEDIA_SCHEMA"
    with pytest.raises(ValidationFailed):
        valid(value)


@pytest.mark.parametrize("section,key,value", [
    ("candidate", "length", True), ("candidate", "length", 0), ("candidate", "index", -1),
    ("candidate", "index", 128), ("candidate", "offset", False), ("candidate", "unit_subtype", "type_f0"),
    ("candidate", "end_reason", "selection_end"), ("candidate", "framing_status", "prefix"),
    ("candidate", "confidence", "confirmed"), ("source", "selected_size", 8),
    ("source", "evidence_size", 99), ("source", "offset", 1), ("analysis", "path", "forensics/analysis/dhav-candidates-EV-0001-001.json"),
    ("analysis", "custody_seq", False), ("source_coverage", "structure_steps", 8193),
    ("source_coverage", "work_bytes_charged", 134217729), ("source_coverage", "reasons", ["unknown"]),
])
def test_bad_shapes_and_declared_bounds(section, key, value):
    result = manifest()
    result[section][key] = value
    with pytest.raises(ValidationFailed):
        valid(result)


@pytest.mark.parametrize("key", ["payload_semantics_examined", "format_conformance_assessed", "media_decoded",
    "playback_verified", "recording_time_verified", "encryption_assessed", "original_file_boundary_verified", "complete_recording"])
def test_no_verification_claim_can_be_enabled(key):
    result = manifest()
    result[key] = True
    with pytest.raises(ValidationFailed):
        valid(result)


@pytest.mark.parametrize("format,subtype,size,accepted", [
    ("avc-annexb", "nal_10", 4, True), ("avc-annexb", "nal_11", 5, True),
    ("avc-annexb", "nal_10", 6, False), ("avc-annexb", "nal_1", 4, False),
    ("avc-annexb", "nal_1", 5, True), ("xm", "type_fc", 16, False),
    ("xm", "type_fc", 17, True), ("xm", "type_fe", 16, False),
    ("xm", "type_fe", 17, True),
])
def test_subtype_specific_minimum_and_header_only_bounds(format, subtype, size, accepted):
    value = manifest(format=format)
    value["candidate"].update(unit_subtype=subtype, length=size)
    value["files"][0]["size"] = value["bytes_total"] = size
    selected = size + (4 if format == "avc-annexb" else 0)
    value["source"]["selected_size"] = selected
    value["source_coverage"].update(input_bytes=selected, search_positions_total=selected,
                                     search_positions_examined=selected, search_bytes_charged=selected,
                                     structure_bytes_charged=selected, work_bytes_charged=2 * selected)
    if accepted:
        valid(value)
    else:
        with pytest.raises(ValidationFailed):
            valid(value)
