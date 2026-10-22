"""DHAV 요약은 닫힌 보고서 참조만 받고 원문·복구 성공 주장을 싣지 않는다."""

import pytest

from pweh import schemas


def _summary():
    return {
        "mode": "security", "security": {},
        "privacy": {"audio_decoded": False, "face_plate_processing": False,
                    "uploads": False, "recording_content_viewed": False},
    }


def _result():
    return {
        "evidence_id": "EV-0001",
        "analysis_path": "forensics/analysis/dhav-candidates-EV-0001-001.json",
        "sha256": "a" * 64, "status": "partial", "selected_size": 1024,
        "candidates_reported": 2,
    }


def test_dhav_summary_preserves_old_summary_and_independent_bmff_reference():
    data = _summary()
    schemas.validate("sd-forensics", data)
    data["media_candidate_results"] = [{
        **_result(), "analysis_path": "forensics/analysis/media-candidates-EV-0001-001.json",
    }]
    data["dhav_candidate_results"] = [_result()]
    schemas.validate("sd-forensics", data)


@pytest.mark.parametrize("status,count,size", [
    ("unsupported", 0, 0), ("partial", 0, 24), ("partial", 1, 33), ("ok", 128, 67108864),
])
def test_dhav_summary_accepts_closed_status_and_limits(status, count, size):
    data = _summary()
    data["dhav_candidate_results"] = [{
        **_result(), "status": status, "candidates_reported": count, "selected_size": size,
    }]
    schemas.validate("sd-forensics", data)


@pytest.mark.parametrize("field,value", [
    ("path", "synthetic-private-name"), ("offset", 10), ("record_length", 33),
    ("channel", 1), ("record_type", "type_f0"), ("payload_hash", "a" * 64),
    ("recording_time", "synthetic-private-time"), ("raw_header", "private-header"),
    ("complete_recording", True), ("checksum_verified", True), ("media_decoded", True),
    ("analysis_path", "forensics/recovered/record-001/video.dav"),
    ("analysis_path", "forensics/analysis/media-candidates-EV-0001-001.json"),
    ("analysis_path", "forensics/analysis/dhav-candidates-EV-0001-01.json"),
    ("analysis_path", "forensics/analysis/dhav-candidates-EV-0001-1234567890.json"),
    ("sha256", "invalid"), ("sha256", "A" * 64),
    ("status", "recovered"), ("status", "playable"), ("status", "encrypted"),
    ("candidates_reported", 129), ("candidates_reported", -1), ("candidates_reported", True),
    ("selected_size", True), ("selected_size", 67108865), ("selected_size", -1),
    ("evidence_id", "EV-123"), ("evidence_id", "EV-1234567"),
])
def test_dhav_summary_rejects_private_fields_unverified_claims_and_bad_references(field, value):
    data = _summary()
    row = _result()
    row[field] = value
    data["dhav_candidate_results"] = [row]
    assert schemas.errors("sd-forensics", data)


@pytest.mark.parametrize("field", tuple(_result()))
def test_dhav_summary_requires_all_six_fields(field):
    data = _summary()
    row = _result()
    del row[field]
    data["dhav_candidate_results"] = [row]
    assert schemas.errors("sd-forensics", data)


def test_dhav_summary_generated_identifiers_and_array_boundary():
    data = _summary()
    row = {**_result(), "evidence_id": "EV-123456",
           "analysis_path": "forensics/analysis/dhav-candidates-EV-123456-123456789.json"}
    data["dhav_candidate_results"] = [row] * 100
    schemas.validate("sd-forensics", data)
    data["dhav_candidate_results"].append(row)
    assert schemas.errors("sd-forensics", data)
