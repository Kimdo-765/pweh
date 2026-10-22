"""독립 합성 보고서로 옛 상자 profile과 새 선언 profile의 폐쇄 경계를 확인한다."""

from __future__ import annotations

import copy

import pytest

from pweh import schemas
from pweh.errors import ValidationFailed


OLD_LIMITATIONS = [
    "box_framing_only", "opaque_payloads_unexamined", "no_format_conformance_validation",
    "no_media_type_confirmation", "no_sample_or_playback_validation", "no_time_or_codec_analysis",
    "no_encryption_assessment", "selected_file_only", "unknown_identifiers_not_returned",
]
NEW_LIMITATIONS = [
    "box_framing_and_selected_declarations_only", "opaque_payloads_unexamined",
    "no_format_conformance_validation", "no_media_type_confirmation", "no_sample_or_playback_validation",
    "no_absolute_time_or_codec_analysis", "no_encryption_assessment", "selected_file_only",
    "unknown_identifiers_not_returned", "declared_duration_not_playback_duration",
    "pssh_structure_not_encryption_proof", "sample_encryption_boxes_unexamined",
]


def old_report():
    """새 코어나 새 결과의 profile 치환에 의존하지 않는 기존 v1 저장물."""
    return {
        "schema": "pweh.media-inventory/v1", "status": "unsupported", "format": "unknown",
        "profile": "mp4-quicktime-box-v1", "framing_status": "complete", "recognition": "unbranded",
        "media_decoded": False, "playback_verified": False, "recording_time_verified": False,
        "encryption_assessed": False, "format_conformance_assessed": False,
        "brands": {"tables": [], "known": [], "slots_examined": 0, "unknown_count": 0,
                   "unknown_distinct_count": 0},
        "boxes": [{"index": 0, "parent_index": None, "kind": "unknown", "offset": 0,
                   "size": 12, "header_size": 8, "depth": 1, "handling": "skipped",
                   "children_complete": None}],
        "observations": {"top_level_ftyp": False, "top_level_moov": False, "top_level_mdat": False,
                         "top_level_moof": False, "top_level_styp": False,
                         "initialization_context": "not-assessed"},
        "summary": {"boxes_seen": 1, "boxes_reported": 1, "unknown_box_count": 1,
                    "unknown_type_distinct_count": 1, "max_depth_seen": 1},
        "coverage": {"input_bytes": 12, "header_bytes": 8, "skipped_payload_bytes": 4,
                     "unexamined_bytes": 0, "structure_complete": True, "container_examined": False,
                     "selection_uncertain": False, "reasons": [], "ranges": [
                         {"offset": 0, "length": 8, "kind": "header", "reason": "box_header"},
                         {"offset": 8, "length": 4, "kind": "skipped", "reason": "unknown_payload"}]},
        "limitations": list(OLD_LIMITATIONS),
        "source": {"kind": "evidence", "evidence_id": "EV-0001", "evidence_sha256": "a" * 64,
                   "container": "file", "member_selected": False, "selected_sha256": "b" * 64,
                   "selected_size": 12, "complete": True, "method": "whole-file", "confidence": "high",
                   "partition": None, "ref": None, "deleted": None, "parent_deleted": None,
                   "container_truncated": None, "container_truncated_reasons": []},
        "params": {"partition": None, "method": "auto", "max_seconds": 45},
    }


def new_report():
    """규격상 prefix만 갖춘 movie와 PSSH의 독립 선언 보고서."""
    result = old_report()
    result.update(profile="mp4-quicktime-declarations-v1", limitations=list(NEW_LIMITATIONS))
    result["boxes"] = [
        {"index": 0, "parent_index": None, "kind": "moov", "offset": 0, "size": 68,
         "header_size": 8, "depth": 1, "handling": "children", "children_complete": True},
        {"index": 1, "parent_index": 0, "kind": "mvhd", "offset": 8, "size": 28,
         "header_size": 8, "depth": 2, "handling": "declaration", "children_complete": None},
        {"index": 2, "parent_index": 0, "kind": "pssh", "offset": 36, "size": 32,
         "header_size": 8, "depth": 2, "handling": "declaration", "children_complete": None},
    ]
    result["observations"].update(top_level_moov=True, initialization_context="moov-observed")
    result["summary"].update(boxes_seen=3, boxes_reported=3, unknown_box_count=0,
                             unknown_type_distinct_count=0, max_depth_seen=2)
    result["coverage"].update(input_bytes=68, header_bytes=52, skipped_payload_bytes=16, ranges=[
        {"offset": 0, "length": 16, "kind": "header", "reason": "box_header"},
        {"offset": 16, "length": 20, "kind": "header", "reason": "declaration_fields"},
        {"offset": 36, "length": 8, "kind": "header", "reason": "box_header"},
        {"offset": 44, "length": 4, "kind": "header", "reason": "declaration_fields"},
        {"offset": 48, "length": 16, "kind": "skipped", "reason": "declaration_identifiers"},
        {"offset": 64, "length": 4, "kind": "header", "reason": "declaration_fields"},
    ])
    result["source"]["selected_size"] = 68
    result["declarations"] = {
        "scope": "mvhd-mdhd-pssh-selected-contexts", "status": "complete",
        "timing": [{"box_index": 1, "parent_index": 0, "kind": "mvhd", "version": 0,
                    "status": "complete", "creation_time_state": "nonzero", "modification_time_state": "zero",
                    "timescale": 1000, "duration_units": 2000, "duration_state": "declared", "issues": []}],
        "pssh": [{"box_index": 2, "parent_index": 0, "version": 0, "status": "complete", "issues": []}],
        "coverage": {"traversal_complete": True, "fields_complete": True, "reasons": []},
        "absolute_times_returned": False, "sample_entries_examined": False, "sample_encryption_examined": False,
    }
    return result


def change(report, path, value):
    node = report
    for key in path[:-1]:
        node = node[key]
    node[path[-1]] = copy.deepcopy(value)


@pytest.mark.parametrize("factory", [old_report, new_report])
def test_independent_old_and_new_reports_are_accepted(factory):
    schemas.validate("media-inventory", factory())


@pytest.mark.parametrize("mutation", [
    (("boxes", 0, "kind"), "mvhd"), (("boxes", 0, "kind"), "mdhd"),
    (("boxes", 0, "kind"), "pssh"), (("boxes", 0, "handling"), "declaration"),
    (("coverage", "ranges", 0, "reason"), "declaration_fields"),
    (("coverage", "ranges", 1, "reason"), "declaration_identifiers"),
    (("coverage", "ranges", 1, "reason"), "declaration_payload"),
    (("coverage", "reasons"), ["zero_timescale"]), (("limitations",), NEW_LIMITATIONS),
    (("declarations",), new_report()["declarations"]),
])
def test_old_profile_rejects_every_new_vocabulary(mutation):
    report = old_report()
    change(report, *mutation)
    with pytest.raises(ValidationFailed):
        schemas.validate("media-inventory", report)


@pytest.mark.parametrize("mutation", [
    (("profile",), "mp4-quicktime-box-v1"), (("limitations",), OLD_LIMITATIONS),
    (("declarations", "absolute_times_returned"), True),
    (("declarations", "sample_entries_examined"), True),
    (("declarations", "sample_encryption_examined"), True),
    (("declarations", "scope"), "all-file"), (("declarations", "creation_time"), 123456789),
    (("declarations", "timing", 0, "creation_time"), 123456789),
    (("declarations", "timing", 0, "duration_seconds"), 2),
    (("declarations", "timing", 0, "kind"), "tkhd"),
    (("declarations", "timing", 0, "version"), 2),
    (("declarations", "timing", 0, "duration_units"), 4294967295),
    (("declarations", "timing", 0, "timescale"), True),
    (("declarations", "timing", 0, "timescale"), 0),
    (("declarations", "timing", 0, "duration_state"), "zero"),
    (("declarations", "pssh", 0, "system_id"), "private-id"),
    (("declarations", "pssh", 0, "kid_count"), 1),
    (("declarations", "pssh", 0, "data_size"), 0),
    (("declarations", "pssh", 0, "sha256"), "a" * 64),
    (("declarations", "pssh", 0, "status"), "encrypted"),
    (("declarations", "pssh", 0, "parent_index"), None),
    (("declarations", "coverage", "reasons"), ["selection_uncertain"]),
    (("declarations", "coverage", "reasons"), ["multiple_ftyp"]),
    (("declarations", "coverage", "fields_complete"), False),
    (("declarations", "coverage", "traversal_complete"), False),
    (("encryption_assessed",), True), (("recording_time_verified",), True),
])
def test_new_profile_is_closed_and_does_not_mix_meanings(mutation):
    report = new_report()
    change(report, *mutation)
    with pytest.raises(ValidationFailed):
        schemas.validate("media-inventory", report)


@pytest.mark.parametrize("missing", ["declarations", "scope", "timing", "pssh", "coverage",
                                     "absolute_times_returned", "sample_entries_examined",
                                     "sample_encryption_examined"])
def test_new_profile_requires_complete_declaration_section(missing):
    report = new_report()
    del (report if missing == "declarations" else report["declarations"])[missing]
    with pytest.raises(ValidationFailed):
        schemas.validate("media-inventory", report)


@pytest.mark.parametrize("version,duration,state", [
    (0, 0, "zero"), (0, None, "indeterminate"), (0, 4294967294, "declared"),
    (1, 0, "zero"), (1, None, "indeterminate"), (1, 18446744073709551614, "declared"),
])
def test_duration_width_and_indeterminate_semantics(version, duration, state):
    report = new_report()
    report["declarations"]["timing"][0].update(version=version, duration_units=duration, duration_state=state)
    schemas.validate("media-inventory", report)


@pytest.mark.parametrize("kind,issue,status,version", [
    ("timing", "unsupported_declaration_version", "unsupported", None),
    ("timing", "unsupported_declaration_flags", "unsupported", 1),
    ("timing", "truncated_declaration_fields", "malformed", None),
    ("timing", "zero_timescale", "malformed", 0),
    ("pssh", "unsupported_declaration_version", "unsupported", None),
    ("pssh", "unsupported_declaration_flags", "unsupported", 1),
    ("pssh", "truncated_declaration_fields", "malformed", None),
    ("pssh", "pssh_length_mismatch", "malformed", 1),
])
def test_declaration_failure_keeps_complete_framing(kind, issue, status, version):
    report = new_report()
    row = report["declarations"][kind][0]
    row.update(status=status, version=version, issues=[issue])
    if kind == "timing":
        if issue == "zero_timescale":
            row["timescale"] = 0
        else:
            row.update(creation_time_state="unread", modification_time_state="unread", timescale=None,
                       duration_units=None, duration_state="unread")
    report["status"] = report["declarations"]["status"] = "partial"
    report["coverage"]["reasons"] = [issue]
    report["declarations"]["coverage"].update(fields_complete=False, reasons=[issue])
    schemas.validate("media-inventory", report)
    assert report["framing_status"] == "complete"


@pytest.mark.parametrize("profile", ["mp4-quicktime-box-v1", "mp4-quicktime-declarations-v1"])
def test_existing_source_constraints_remain_shared(profile):
    report = old_report() if profile.endswith("box-v1") else new_report()
    report["source"]["parent_deleted"] = False
    with pytest.raises(ValidationFailed):
        schemas.validate("media-inventory", report)
