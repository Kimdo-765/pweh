"""새 stream 요약은 원보고서의 여섯 참조 필드만 허용한다."""
import pytest

from pweh import schemas


def summary():
    return {"mode": "security", "security": {}, "privacy": {
        "audio_decoded": False, "face_plate_processing": False, "uploads": False, "recording_content_viewed": False}}


def result():
    return {"evidence_id": "EV-0001", "analysis_path": "forensics/analysis/media-unit-scan-EV-0001-001.json",
            "sha256": "a"*64, "status": "partial", "format": "avc-annexb", "candidates_reported": 1}


@pytest.mark.parametrize("format", ("jpeg", "avc-annexb", "mpeg2-ps", "xm"))
@pytest.mark.parametrize("status,count", (("ok", 128), ("partial", 1), ("unsupported", 0)))
def test_new_reference_coexists_with_unchanged_summary(format, status, count):
    value = summary()
    schemas.validate("sd-forensics", value)
    value["media_unit_scan_results"] = [{**result(), "format": format, "status": status, "candidates_reported": count}]
    value["media_unit_candidate_results"] = [{"evidence_id": "EV-0001",
        "analysis_path": "forensics/analysis/media-unit-candidates-EV-0001-001.json",
        "sha256": "b"*64, "status": "partial", "format": "avc-annexb", "selected_size": 8, "candidates_reported": 1}]
    schemas.validate("sd-forensics", value)


@pytest.mark.parametrize("key", tuple(result()))
def test_exact_six_fields_are_required(key):
    row = result()
    del row[key]
    assert schemas.errors("sd-forensics", {**summary(), "media_unit_scan_results": [row]})


@pytest.mark.parametrize("key,value", [
    ("evidence_id", "EV-0001\n"), ("evidence_id", "EV-0001\r"), ("evidence_id", "EV-123"),
    ("analysis_path", "forensics/analysis/media-unit-scan-EV-0001-001.json\n"),
    ("analysis_path", "forensics/analysis/media-unit-candidates-EV-0001-001.json"),
    ("analysis_path", "forensics/analysis/media-unit-scan-EV-0001-01.json"),
    ("analysis_path", "forensics/recovered/media-unit-001/unit-000.bin"),
    ("sha256", "A"*64), ("sha256", "a"*64+"\n"), ("status", "complete"),
    ("format", "auto"), ("format", "JPEG"), ("format", True),
    ("candidates_reported", 129), ("candidates_reported", -1), ("candidates_reported", True),
    ("candidates_reported", 1.5), ("evidence_size", 1024), ("selected_size", 8),
    ("selection_offset", 0), ("selection_length", 8), ("next_offset", None),
    ("search_complete", True), ("whole_evidence_search_complete", True),
    ("unit_subtype", "nal_10"), ("raw_header", "RAW_PRIVATE"), ("recording_time", "RAW_PRIVATE"),
    ("unit_sha256", "b"*64), ("complete_recording", True),
])
def test_summary_rejects_wrong_refs_raw_values_and_extra_claims(key, value):
    assert schemas.errors("sd-forensics", {**summary(), "media_unit_scan_results": [{**result(), key: value}]})


def test_reference_array_upper_bound_and_empty_optional_array():
    schemas.validate("sd-forensics", {**summary(), "media_unit_scan_results": []})
    row = {**result(), "evidence_id": "EV-123456",
           "analysis_path": "forensics/analysis/media-unit-scan-EV-123456-123456789.json"}
    data = {**summary(), "media_unit_scan_results": [row]*100}
    schemas.validate("sd-forensics", data)
    data["media_unit_scan_results"].append(row)
    assert schemas.errors("sd-forensics", data)
