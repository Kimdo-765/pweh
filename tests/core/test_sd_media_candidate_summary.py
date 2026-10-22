"""SD 요약의 후보 참조는 원시 내용·위치·녹화 복구 판정을 담지 않는다."""

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
        "analysis_path": "forensics/analysis/media-candidates-EV-0001-001.json",
        "sha256": "a" * 64, "status": "partial", "selected_size": 1024,
        "candidates_reported": 2,
    }


def test_candidate_summary_keeps_existing_summary_and_inventory_independent():
    data = _summary()
    schemas.validate("sd-forensics", data)
    data["media_inventory_results"] = [{
        "evidence_id": "EV-0001",
        "analysis_path": "forensics/analysis/media-inventory-EV-0001-001.json",
        "sha256": "b" * 64, "status": "ok", "selected_size": 1024, "boxes_reported": 2,
    }]
    data["media_candidate_results"] = [_result()]
    schemas.validate("sd-forensics", data)


@pytest.mark.parametrize("status,count,size", [
    ("unsupported", 0, 0), ("partial", 0, 1024), ("ok", 128, 67108864),
])
def test_candidate_summary_accepts_closed_status_and_limits(status, count, size):
    data = _summary()
    row = _result()
    row.update(status=status, candidates_reported=count, selected_size=size)
    data["media_candidate_results"] = [row]
    schemas.validate("sd-forensics", data)


@pytest.mark.parametrize("field,value", [
    ("path", "synthetic-private-name"), ("offset", 0), ("payload_hash", "a" * 64),
    ("recording_time", "synthetic-private-time"), ("uuid", "synthetic-private-id"),
    ("complete_recording", True), ("physical_carving_performed", True),
    ("analysis_path", "forensics/recovered/candidate-001/recording.mp4"),
    ("analysis_path", "forensics/analysis/media-inventory-EV-0001-001.json"),
    ("analysis_path", "forensics/analysis/media-candidates-EV-0001-01.json"),
    ("analysis_path", "forensics/analysis/media-candidates-EV-0001-1234567890.json"),
    ("sha256", "invalid"), ("sha256", "A" * 64),
    ("status", "recovered"), ("status", "playable"), ("status", "encrypted"),
    ("candidates_reported", 129), ("candidates_reported", -1), ("candidates_reported", True),
    ("selected_size", True), ("selected_size", 67108865), ("selected_size", -1),
    ("evidence_id", "EV-123"), ("evidence_id", "EV-1234567"),
])
def test_candidate_summary_rejects_private_content_and_unverified_claims(field, value):
    data = _summary()
    row = _result()
    row[field] = value
    data["media_candidate_results"] = [row]
    assert schemas.errors("sd-forensics", data)


@pytest.mark.parametrize("field", tuple(_result()))
def test_candidate_summary_requires_every_reference_field(field):
    data = _summary()
    row = _result()
    del row[field]
    data["media_candidate_results"] = [row]
    assert schemas.errors("sd-forensics", data)


def test_candidate_summary_array_and_generated_id_bounds():
    data = _summary()
    row = _result()
    row["evidence_id"] = "EV-123456"
    row["analysis_path"] = "forensics/analysis/media-candidates-EV-123456-123456789.json"
    data["media_candidate_results"] = [row] * 100
    schemas.validate("sd-forensics", data)
    data["media_candidate_results"].append(row)
    assert schemas.errors("sd-forensics", data)
