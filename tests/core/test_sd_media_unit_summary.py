"""미디어 단위 요약은 형식·결과 참조만 남기고 원문과 재생 주장을 받지 않는다."""

import pytest

from pweh import schemas


def summary():
    return {"mode": "security", "security": {},
            "privacy": {"audio_decoded": False, "face_plate_processing": False,
                        "uploads": False, "recording_content_viewed": False}}


def result():
    return {"evidence_id": "EV-0001",
            "analysis_path": "forensics/analysis/media-unit-candidates-EV-0001-001.json",
            "sha256": "a" * 64, "status": "partial", "format": "mpeg2-ps",
            "selected_size": 24, "candidates_reported": 1}


def test_unit_summary_preserves_existing_summary_and_other_candidates():
    data = summary()
    schemas.validate("sd-forensics", data)
    data["dhav_candidate_results"] = [{
        "evidence_id": "EV-0001", "analysis_path": "forensics/analysis/dhav-candidates-EV-0001-001.json",
        "sha256": "b" * 64, "status": "ok", "selected_size": 33, "candidates_reported": 1}]
    data["media_unit_candidate_results"] = [result()]
    schemas.validate("sd-forensics", data)


@pytest.mark.parametrize("format", ["jpeg", "avc-annexb", "mpeg2-ps", "xm"])
@pytest.mark.parametrize("status,size,count", [
    ("unsupported", 0, 0), ("partial", 8, 1), ("ok", 64 << 20, 128)])
def test_unit_summary_accepts_format_and_bounded_reference(format, status, size, count):
    if status == "partial":
        size = {"jpeg": 28, "avc-annexb": 8, "mpeg2-ps": 24, "xm": 9}[format]
    row = {**result(), "format": format, "status": status, "selected_size": size, "candidates_reported": count}
    schemas.validate("sd-forensics", {**summary(), "media_unit_candidate_results": [row]})


@pytest.mark.parametrize("field,value", [
    ("format", "auto"), ("format", "h264"), ("format", "JPEG"), ("format", True),
    ("selected_size", -1), ("selected_size", (64 << 20) + 1), ("selected_size", True),
    ("selected_size", 1.5), ("candidates_reported", 129), ("candidates_reported", -1),
    ("candidates_reported", True), ("status", "recovered"), ("status", "complete"),
    ("sha256", "A" * 64), ("evidence_id", "EV-123"),
    ("analysis_path", "forensics/analysis/media-candidates-EV-0001-001.json"),
    ("analysis_path", "forensics/analysis/media-unit-candidates-EV-0001-01.json"),
    ("analysis_path", "forensics/recovered/media-unit-001/unit-000.bin"),
    ("unit_subtype", "nal_10"), ("offset", 0), ("length", 4),
    ("path", "private-name"), ("raw_header", "private-header"), ("recording_time", "private-time"),
    ("playback_verified", True), ("complete_recording", True), ("unit_sha256", "b" * 64),
])
def test_unit_summary_rejects_raw_fields_bad_references_and_completion_claims(field, value):
    data = {**summary(), "media_unit_candidate_results": [{**result(), field: value}]}
    assert schemas.errors("sd-forensics", data)


@pytest.mark.parametrize("field", tuple(result()))
def test_unit_summary_requires_seven_fields(field):
    row = result()
    del row[field]
    assert schemas.errors("sd-forensics", {**summary(), "media_unit_candidate_results": [row]})


def test_unit_summary_reference_and_array_limits():
    row = {**result(), "evidence_id": "EV-123456",
           "analysis_path": "forensics/analysis/media-unit-candidates-EV-123456-123456789.json"}
    data = {**summary(), "media_unit_candidate_results": [row] * 100}
    schemas.validate("sd-forensics", data)
    data["media_unit_candidate_results"].append(row)
    assert schemas.errors("sd-forensics", data)
