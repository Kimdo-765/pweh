"""현재 할당 요약은 결과 참조와 서로 다른 두 완료 상태를 보존한다."""

import pytest

from pweh import schemas


def summary():
    return {"mode": "evidence", "custody_ok": True,
            "evidence": [{"evidence_id": "EV-0001", "status": "ok", "sha256": "a" * 64}],
            "legal": {"site_type": "home", "role": "owner", "legal_basis": "합성 자료 시험"},
            "privacy": {
        "audio_decoded": False, "face_plate_processing": False,
        "uploads": False, "recording_content_viewed": False}}


def result():
    return {"evidence_id": "EV-0001",
            "analysis_path": "forensics/analysis/allocation-window-EV-0001-001.json",
            "sha256": "a" * 64, "status": "partial",
            "window_complete": True, "allocation_complete": False}


def test_existing_summary_remains_valid():
    schemas.validate("sd-forensics", summary())


@pytest.mark.parametrize("status,window,allocation", [
    ("ok", True, True), ("partial", True, False), ("partial", False, False)])
def test_summary_keeps_unknown_and_unexamined_distinct(status, window, allocation):
    row = {**result(), "status": status, "window_complete": window,
           "allocation_complete": allocation}
    schemas.validate("sd-forensics", {**summary(), "allocation_window_results": [row]})


@pytest.mark.parametrize("status,window,allocation", [
    ("ok", False, True), ("ok", True, False), ("ok", False, False),
    ("partial", True, True), ("partial", False, True)])
def test_summary_rejects_contradictory_completion(status, window, allocation):
    row = {**result(), "status": status, "window_complete": window,
           "allocation_complete": allocation}
    assert schemas.errors("sd-forensics", {**summary(), "allocation_window_results": [row]})


@pytest.mark.parametrize("field,value", [
    ("evidence_id", "EV-123"), ("sha256", "A" * 64),
    ("evidence_id", "EV-0001\n"),
    ("analysis_path", "forensics/analysis/allocation-window-EV-0001-001.json\n"),
    ("analysis_path", "forensics/analysis/dhav-candidates-EV-0001-001.json"),
    ("analysis_path", "forensics/recovered/allocation-window-EV-0001-001.json"),
    ("status", "unsupported"), ("status", "recovered"),
    ("window_complete", 1), ("allocation_complete", "false"),
    ("filename", "private-name"), ("offset", 4096),
    ("file_ownership_verified", True), ("historical_allocation_verified", True),
    ("playback_verified", True), ("raw_metadata", "private-value")])
def test_summary_rejects_foreign_paths_raw_values_and_claims(field, value):
    row = {**result(), field: value}
    assert schemas.errors("sd-forensics", {**summary(), "allocation_window_results": [row]})


@pytest.mark.parametrize("field", tuple(result()))
def test_summary_requires_six_reference_fields(field):
    row = result()
    del row[field]
    assert schemas.errors("sd-forensics", {**summary(), "allocation_window_results": [row]})


def test_summary_bounds_references():
    row = {**result(), "evidence_id": "EV-123456",
           "analysis_path": "forensics/analysis/allocation-window-EV-123456-123456789.json"}
    data = {**summary(), "allocation_window_results": [row] * 100}
    schemas.validate("sd-forensics", data)
    data["allocation_window_results"].append(row)
    assert schemas.errors("sd-forensics", data)
