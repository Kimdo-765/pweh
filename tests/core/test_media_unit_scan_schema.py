"""스트리밍 보고서의 독립 회계 fixture와 닫힌 저장 봉투를 검사한다."""
from __future__ import annotations

import copy
import json
import time

import pytest

from pweh import media_unit_stream as M, schemas
from pweh.errors import ValidationFailed

FORMATS = ("jpeg", "avc-annexb", "mpeg2-ps", "xm")
PROFILES = dict(zip(FORMATS, ("jpeg-baseline-marker-stream-v1", "avc-annexb-delimited-nal-stream-v1",
                            "mpeg2-ps-bounded-pack-prefix-stream-v1", "xm-length-delimited-frame-stream-v1")))
FALSE_FIELDS = ("media_decoded", "playback_verified", "recording_time_verified", "encryption_assessed",
                "format_conformance_assessed", "original_file_boundary_verified", "complete_recording",
                "payload_semantics_examined", "physical_carving_performed")
LIMITATIONS = ["structural_candidates_only", "format_subset_only", "original_file_boundary_unknown",
              "complete_recording_unverified", "candidate_overlap_unclassified", "payload_semantics_unexamined",
              "evidence_bytes_only", "allocation_state_unexamined", "unit_bytes_not_hashed",
              "range_revalidation_required_before_extract", "intake_hash_not_reverified"]


def report(format="jpeg"):
    """scanner와 무관한 유한한 회계 표본. 단위 바이트 내용은 이 시험 범위 밖이다."""
    length, selected, unit, subtype, end = {
        "jpeg": (28, 28, "jpeg_codestream", "baseline", "eoi"),
        "avc-annexb": (4, 8, "avc_nal", "nal_10", "next_nal"),
        "mpeg2-ps": (24, 28, "mpeg2_ps_pack_prefix", "mpeg2_pack", "program_end"),
        "xm": (9, 9, "xm_frame", "type_fd", "declared_length"),
    }[format]
    total = 65 - {"jpeg": 2, "avc-annexb": 3, "mpeg2-ps": 4, "xm": 3}[format]
    return {
        "schema": "pweh.media-unit-scan/v1", "profile": PROFILES[format], "format": format,
        "status": "ok", **dict.fromkeys(FALSE_FIELDS, False), "limitations": list(LIMITATIONS),
        "source": {"kind": "evidence", "evidence_id": "EV-0001", "evidence_sha256": "a" * 64, "evidence_size": 64},
        "params": {"format": format, "start_offset": 0, "max_scan_bytes": 1 << 30, "max_seconds": 45},
        "summary": {
            "anchors_observed": 1, "anchors_rejected": 0, "unsupported_anchors": 0, "incomplete_anchors": 0,
            "selection_limited_anchors": 0, "candidates_reported": 1, "closed_candidates": 1, "prefix_candidates": 0,
            "anchor_rejections": dict.fromkeys(("invalid_header", "invalid_length", "invalid_sequence", "invalid_escape", "empty_payload"), 0),
            "anchor_unsupported": dict.fromkeys(("unsupported_variant", "unsupported_extension", "multiple_scans", "zero_length_packet"), 0),
            "anchor_incomplete": dict.fromkeys(("truncated_header", "unit_beyond_evidence", "open_tail"), 0)},
        "coverage": {
            "evidence_size": 64, "start_offset": 0, "max_scan_bytes": 1 << 30, "search_positions_total": total,
            "positions_before_start": 0, "search_positions_examined": total, "unexamined_positions": None,
            "pending_anchor_offset": None, "next_offset": None, "search_complete": True,
            "whole_evidence_search_complete": True, "candidate_checks_complete": True, "candidate_list_complete": True,
            "anchor_probes": 1, "structure_steps": 1, "search_bytes_read": 64, "search_read_calls": 1,
            "structure_bytes_read": 8, "structure_read_calls": 1, "structure_work_bytes": 8,
            "total_bytes_read": 72, "reasons": []},
        "candidates": [{"index": 0, "offset": 4, "length": length, "format": format, "unit": unit,
                        "unit_subtype": subtype, "boundary_kind": end, "framing_status": "closed",
                        "end_reason": end, "confidence": "possible", "selection_offset": 4, "selection_length": selected}],
    }


def put(data, path, value):
    keys = path.split(".")
    node = data
    for key in keys[:-1]:
        node = node[int(key)] if isinstance(node, list) else node[key]
    key = int(keys[-1]) if isinstance(node, list) else keys[-1]
    node[key] = value


def check(data):
    schemas.validate("media-unit-scan", data)
    M.validate_media_unit_scan_accounting(data)
    return data


@pytest.mark.parametrize("format", FORMATS)
def test_independent_closed_report_and_pure_envelope(format):
    data = check(report(format))
    assert len(data) == 19 and len(data["coverage"]) == 22 and len(data["summary"]) == 11
    assert len(data["candidates"][0]) == 12
    for field in ("source", "params"):
        mixed = copy.deepcopy(data)
        del mixed[field]
        with pytest.raises(ValidationFailed):
            M.validate_media_unit_scan_accounting(mixed)
    pure = {key: value for key, value in data.items() if key not in ("source", "params")}
    M.validate_media_unit_scan_accounting(pure)
    assert schemas.errors("media-unit-scan", pure)


@pytest.mark.parametrize("path", ("", "source", "params", "summary", "coverage", "candidates.0",
                                  "summary.anchor_rejections", "summary.anchor_unsupported", "summary.anchor_incomplete"))
def test_all_objects_reject_extra_private_fields_and_missing_keys(path):
    data = report()
    node = data
    for key in path.split(".") if path else ():
        node = node[int(key)] if isinstance(node, list) else node[key]
    for key in tuple(node):
        original = node.pop(key)
        assert schemas.errors("media-unit-scan", data), (path, key)
        node[key] = original
    node["RAW_PRIVATE_SENTINEL"] = "RAW_PRIVATE_SENTINEL"
    assert schemas.errors("media-unit-scan", data)


@pytest.mark.parametrize("path,value", [
    ("profile", "jpeg-baseline-marker-v1"), ("profile", "jpeg-baseline-marker-ev-range-v1"),
    ("schema", "pweh.media-unit-candidates/v1"), ("format", "auto"), ("params.format", "xm"),
    ("source.kind", "file"), ("source.evidence_id", "EV-123"), ("source.evidence_id", "EV-0001\n"),
    ("source.evidence_id", "EV-0001\r"), ("source.evidence_sha256", "A" * 64),
    ("source.evidence_sha256", "a" * 64 + "\n"), ("source.evidence_size", 1 << 63),
    ("params.max_scan_bytes", 3), ("params.max_scan_bytes", (1 << 30) + 1), ("params.start_offset", -1),
    ("params.max_seconds", 0), ("params.max_seconds", 45.01), ("status", "complete"),
    ("candidates.0.format", "xm"), ("candidates.0.index", 128), ("candidates.0.selection_length", (64 << 20) + 1),
    ("candidates.0.confidence", "confirmed"), ("candidates.0.end_reason", "selection_end"),
    ("coverage.reasons", ["selection_uncertain"]), ("coverage.reasons", ["container_listing_incomplete"]),
    ("summary.anchors_observed", 1026), ("coverage.anchor_probes", 1025),
    ("summary.selection_limited_anchors", 1025), ("coverage.structure_work_bytes", (128 << 20) + 1),
    ("limitations", list(reversed(LIMITATIONS))), ("coverage.search_complete", 1),
])
def test_schema_rejects_wrong_profiles_values_and_privacy_claims(path, value):
    data = report()
    put(data, path, value)
    assert schemas.errors("media-unit-scan", data)


@pytest.mark.parametrize("field", FALSE_FIELDS)
def test_false_assertions_cannot_be_promoted(field):
    data = report()
    data[field] = True
    assert schemas.errors("media-unit-scan", data)


@pytest.mark.parametrize("path", (
    "source.evidence_size", "params.start_offset", "params.max_scan_bytes",
    "summary.anchors_observed", "summary.anchors_rejected", "summary.unsupported_anchors",
    "summary.incomplete_anchors", "summary.selection_limited_anchors", "summary.candidates_reported",
    "summary.closed_candidates", "summary.prefix_candidates", "summary.anchor_rejections.invalid_header",
    "summary.anchor_unsupported.unsupported_variant", "summary.anchor_incomplete.open_tail",
    "coverage.evidence_size", "coverage.start_offset", "coverage.max_scan_bytes", "coverage.search_positions_total",
    "coverage.positions_before_start", "coverage.search_positions_examined", "coverage.anchor_probes",
    "coverage.structure_steps", "coverage.search_bytes_read", "coverage.search_read_calls",
    "coverage.structure_bytes_read", "coverage.structure_read_calls", "coverage.structure_work_bytes",
    "coverage.total_bytes_read", "candidates.0.index", "candidates.0.offset", "candidates.0.length",
    "candidates.0.selection_offset", "candidates.0.selection_length",
))
@pytest.mark.parametrize("value", (True, 1.0, -1))
def test_semantic_requires_exact_integer_for_every_numeric_location(path, value):
    data = report()
    put(data, path, value)
    with pytest.raises(ValidationFailed) as caught:
        M.validate_media_unit_scan_accounting(data)
    assert not caught.value.data


@pytest.mark.parametrize("path,value", [
    ("source.evidence_size", 65), ("params.start_offset", 1), ("params.max_scan_bytes", 64),
    ("coverage.search_positions_total", 64), ("coverage.positions_before_start", 1),
    ("coverage.search_positions_examined", 62), ("coverage.search_complete", False),
    ("coverage.whole_evidence_search_complete", False), ("coverage.candidate_checks_complete", False),
    ("coverage.candidate_list_complete", False), ("coverage.total_bytes_read", 71),
    ("coverage.search_read_calls", 0), ("coverage.structure_read_calls", 9),
    ("coverage.structure_work_bytes", 0), ("summary.anchors_observed", 2),
    ("summary.anchor_rejections.invalid_header", 1), ("summary.closed_candidates", 0),
    ("coverage.anchor_probes", 0), ("candidates.0.index", 1), ("candidates.0.selection_offset", 5),
    ("candidates.0.selection_length", 29), ("candidates.0.offset", 63),
    ("coverage.next_offset", 63), ("coverage.pending_anchor_offset", 4),
])
def test_semantic_rejects_independent_cross_field_mutations(path, value):
    data = report()
    put(data, path, value)
    with pytest.raises(ValidationFailed):
        M.validate_media_unit_scan_accounting(data)


@pytest.mark.parametrize("probes", (0, 1))
def test_pending_before_reservation_and_during_probe(probes):
    data = report()
    data["status"] = "partial"
    data["candidates"] = []
    data["summary"].update(candidates_reported=0, closed_candidates=0)
    data["coverage"].update(search_positions_examined=4, pending_anchor_offset=4, next_offset=4,
                            unexamined_positions={"start": 4, "count": 59, "reason": "time_limit"},
                            search_complete=False, whole_evidence_search_complete=False,
                            candidate_checks_complete=False, candidate_list_complete=False,
                            anchor_probes=probes, reasons=["time_limit"])
    check(data)


def test_selection_limit_completes_search_but_not_anchor_checks():
    data = report()
    data["status"] = "partial"
    data["candidates"] = []
    data["summary"].update(candidates_reported=0, closed_candidates=0, selection_limited_anchors=1)
    data["coverage"].update(candidate_checks_complete=False, candidate_list_complete=False,
                            reasons=["selection_size_limit"])
    check(data)


def test_ps_evidence_end_is_prefix_even_with_four_completion_flags():
    data = report("mpeg2-ps")
    row = data["candidates"][0]
    row.update(offset=40, selection_offset=40, selection_length=24, framing_status="prefix",
               boundary_kind="validated_prefix", end_reason="evidence_end")
    data["summary"].update(closed_candidates=0, prefix_candidates=1)
    data["coverage"]["reasons"] = ["candidate_prefix_partial"]
    data["status"] = "partial"
    check(data)
    row["selection_offset"] = row["offset"] = 39
    with pytest.raises(ValidationFailed):
        M.validate_media_unit_scan_accounting(data)


@pytest.mark.parametrize("format", FORMATS)
def test_zero_domain_and_explicit_end_do_not_claim_prior_search(format):
    data = report(format)
    data["status"] = "unsupported"
    data["candidates"] = []
    data["summary"].update(anchors_observed=0, candidates_reported=0, closed_candidates=0)
    data["source"]["evidence_size"] = 1
    data["params"]["start_offset"] = 1
    data["coverage"].update(evidence_size=1, start_offset=1, search_positions_total=0,
                            search_positions_examined=0, whole_evidence_search_complete=False,
                            anchor_probes=0, structure_steps=0, search_bytes_read=0, search_read_calls=0,
                            structure_bytes_read=0, structure_read_calls=0, structure_work_bytes=0, total_bytes_read=0)
    check(data)


def test_last_observation_may_be_pending_beyond_probe_cap():
    data = report()
    data["status"] = "partial"
    data["candidates"] = []
    data["summary"].update(anchors_observed=1025, anchors_rejected=1024, candidates_reported=0, closed_candidates=0)
    data["summary"]["anchor_rejections"]["invalid_header"] = 1024
    data["source"]["evidence_size"] = 2048
    data["coverage"].update(evidence_size=2048, search_positions_total=2047, search_bytes_read=2048,
                            total_bytes_read=2056, anchor_probes=1024, search_positions_examined=1024,
                            next_offset=1024, pending_anchor_offset=1024,
                            unexamined_positions={"start": 1024, "count": 1023, "reason": "probe_limit"},
                            search_complete=False, whole_evidence_search_complete=False,
                            candidate_checks_complete=False, candidate_list_complete=False, reasons=["probe_limit"])
    check(data)


def test_128_rows_and_absolute_large_evidence_offsets():
    data = report("xm")
    n, start = (1 << 63) - 1, (1 << 63) - 1 - 2048
    data["source"]["evidence_size"] = n
    data["params"]["start_offset"] = start
    data["candidates"] = [{**data["candidates"][0], "index": i, "offset": start + i * 10,
                           "selection_offset": start + i * 10} for i in range(128)]
    data["summary"].update(anchors_observed=128, candidates_reported=128, closed_candidates=128)
    data["coverage"].update(evidence_size=n, start_offset=start, search_positions_total=n-2,
                            positions_before_start=start, search_positions_examined=2046,
                            search_bytes_read=2048, total_bytes_read=2056,
                            whole_evidence_search_complete=False, anchor_probes=128)
    check(data)
    data["candidates"].append(dict(data["candidates"][-1]))
    assert schemas.errors("media-unit-scan", data)


@pytest.mark.parametrize("format,data", [
    ("jpeg", bytes.fromhex("ffd8ffc0000b080001000101011100ffda0008010100003f0001ffd9")),
    ("avc-annexb", b"\0\0\1\x0a\0\0\1\x0b"),
    ("mpeg2-ps", bytes.fromhex("000001ba440004000401000007f8000001e0000480000001000001b9")),
    ("xm", b"\0\0\1\xfd\x01\0\0\0x"),
])
def test_actual_scanner_output_uses_same_closed_schema(format, data):
    # 시간은 실행 중에만 고정한다. 실제 parser 출력에도 독립 저장 봉투를 적용한다.
    result = M.scan_media_unit_stream(lambda o, n: data[o:o+n], format=format, evidence_size=len(data),
                                      deadline=time.monotonic() + 5)
    result["source"] = {"kind": "evidence", "evidence_id": "EV-0001", "evidence_sha256": "a"*64, "evidence_size": len(data)}
    result["params"] = {"format": format, "start_offset": 0, "max_scan_bytes": 1 << 30, "max_seconds": 5}
    check(result)
    assert result["summary"]["candidates_reported"] >= 1
    assert not schemas.errors("media-unit-scan", json.loads(json.dumps(result)))
    assert schemas.errors("media-unit-candidates", result)
