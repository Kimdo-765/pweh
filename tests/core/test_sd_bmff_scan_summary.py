"""스트리밍 BMFF 요약은 완료 주장을 대신하지 않는 닫힌 보고서 참조다."""

import pytest

from pweh import schemas


def summary():
    return {
        "mode": "security", "security": {},
        "privacy": {"audio_decoded": False, "face_plate_processing": False,
                    "uploads": False, "recording_content_viewed": False},
    }


def result():
    return {
        "evidence_id": "EV-0001",
        "analysis_path": "forensics/analysis/bmff-scan-EV-0001-001.json",
        "sha256": "a" * 64, "status": "partial", "evidence_size": 2**32,
        "candidates_reported": 2,
    }


def test_scan_summary_keeps_old_summary_and_candidate_reference():
    data = summary()
    schemas.validate("sd-forensics", data)
    data["dhav_candidate_results"] = [{
        "evidence_id": "EV-0001",
        "analysis_path": "forensics/analysis/dhav-candidates-EV-0001-001.json",
        "sha256": "b" * 64, "status": "ok", "selected_size": 33,
        "candidates_reported": 1,
    }]
    data["dhav_scan_results"] = [{**result(), "analysis_path": "forensics/analysis/dhav-scan-EV-0001-001.json"}]
    data["bmff_scan_results"] = [result()]
    schemas.validate("sd-forensics", data)


@pytest.mark.parametrize("status,size,count", [
    ("unsupported", 1, 0), ("partial", 2**32, 0), ("ok", 2**63 - 1, 128),
])
def test_scan_summary_accepts_evidence_size_independent_of_search_budget(status, size, count):
    data = summary()
    data["bmff_scan_results"] = [{**result(), "status": status, "evidence_size": size,
                                 "candidates_reported": count}]
    schemas.validate("sd-forensics", data)


@pytest.mark.parametrize("field,value", [
    ("selected_size", 33), ("offset", 100), ("validated_prefix_length", 16), ("next_offset", 100),
    ("whole_evidence_search_complete", True), ("complete_recording", True), ("relations_assessed", True),
    ("path", "private-name"), ("recording_time", "private-time"), ("channel", 1),
    ("prefix_sha256", "b" * 64), ("raw_header", "private-header"),
    ("analysis_path", "forensics/analysis/media-candidates-EV-0001-001.json"),
    ("analysis_path", "forensics/analysis/dhav-scan-EV-0001-001.json"),
    ("analysis_path", "forensics/analysis/bmff-scan-EV-0001-01.json"),
    ("analysis_path", "forensics/analysis/bmff-scan-EV-0001-1234567890.json"),
    ("analysis_path", "forensics/recovered/dhav-record-001/record-000.bin"),
    ("evidence_id", "EV-123"), ("evidence_id", "EV-1234567"),
    ("evidence_size", 0), ("evidence_size", -1), ("evidence_size", True),
    ("evidence_size", 1.5), ("evidence_size", 2**63),
    ("sha256", "invalid"), ("sha256", "A" * 64),
    ("status", "complete"), ("status", "recovered"),
    ("candidates_reported", -1), ("candidates_reported", 129), ("candidates_reported", True),
])
def test_scan_summary_rejects_private_fields_bad_references_and_completion_claims(field, value):
    data = summary()
    data["bmff_scan_results"] = [{**result(), field: value}]
    assert schemas.errors("sd-forensics", data)


@pytest.mark.parametrize("field", tuple(result()))
def test_scan_summary_requires_six_fields(field):
    row = result()
    del row[field]
    data = {**summary(), "bmff_scan_results": [row]}
    assert schemas.errors("sd-forensics", data)


def test_scan_summary_generated_reference_and_array_boundary():
    row = {**result(), "evidence_id": "EV-123456",
           "analysis_path": "forensics/analysis/bmff-scan-EV-123456-123456789.json"}
    data = {**summary(), "bmff_scan_results": [row] * 100}
    schemas.validate("sd-forensics", data)
    data["bmff_scan_results"].append(row)
    assert schemas.errors("sd-forensics", data)
