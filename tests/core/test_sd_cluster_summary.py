"""클러스터 요약은 결과 참조와 참조 지도·할당의 서로 다른 완료 상태를 보존한다."""

import pytest

from pweh import schemas


def summary():
    return {"mode": "evidence", "custody_ok": True,
            "evidence": [{"evidence_id": "EV-0001", "status": "ok", "sha256": "a" * 64}],
            "legal": {"site_type": "home", "role": "owner", "legal_basis": "합성 자료 시험"},
            "privacy": {"audio_decoded": False, "face_plate_processing": False,
                        "uploads": False, "recording_content_viewed": False}}


def result():
    return {"evidence_id": "EV-0001",
            "analysis_path": "forensics/analysis/cluster-report-EV-0001-001.json",
            "sha256": "a" * 64, "status": "partial",
            "reference_map_complete": False, "allocation_complete": True}


def test_existing_summary_remains_valid():
    schemas.validate("sd-forensics", summary())


@pytest.mark.parametrize("status,reference,allocation", [
    ("ok", True, True), ("partial", True, True), ("partial", True, False),
    ("partial", False, True), ("partial", False, False)])
def test_summary_keeps_reference_allocation_and_row_limits_distinct(status, reference, allocation):
    row = {**result(), "status": status, "reference_map_complete": reference,
           "allocation_complete": allocation}
    schemas.validate("sd-forensics", {**summary(), "cluster_report_results": [row]})


@pytest.mark.parametrize("reference,allocation", [(False, True), (True, False), (False, False)])
def test_ok_requires_both_phases_complete(reference, allocation):
    row = {**result(), "status": "ok", "reference_map_complete": reference,
           "allocation_complete": allocation}
    assert schemas.errors("sd-forensics", {**summary(), "cluster_report_results": [row]})


@pytest.mark.parametrize("field,value", [
    ("evidence_id", "EV-123"), ("evidence_id", "EV-0001\n"),
    ("evidence_id", "EV-1234567"), ("sha256", "A" * 64),
    ("sha256", "a" * 64 + "\n"), ("sha256", "a" * 63),
    ("analysis_path", "forensics/analysis/cluster-report-EV-0001-001.json\n"),
    ("analysis_path", "forensics/analysis/allocation-window-EV-0001-001.json"),
    ("analysis_path", "forensics/recovered/cluster-report-EV-0001-001.json"),
    ("analysis_path", "forensics/analysis/cluster-report-EV-0001-01.json"),
    ("analysis_path", "forensics/analysis/cluster-report-EV-0001-1234567890.json"),
    ("status", "unsupported"), ("status", "recovered"),
    ("reference_map_complete", 1), ("reference_map_complete", "false"),
    ("allocation_complete", 0), ("allocation_complete", None),
    ("filename", "private-name"), ("offset", 4096),
    ("orphan_files_verified", True), ("file_ownership_verified", True),
    ("historical_allocation_verified", True), ("raw_metadata", "private-value")])
def test_summary_rejects_foreign_paths_raw_values_and_claims(field, value):
    row = {**result(), field: value}
    assert schemas.errors("sd-forensics", {**summary(), "cluster_report_results": [row]})


@pytest.mark.parametrize("field", tuple(result()))
def test_summary_requires_six_reference_fields(field):
    row = result()
    del row[field]
    assert schemas.errors("sd-forensics", {**summary(), "cluster_report_results": [row]})


def test_summary_bounds_references():
    row = {**result(), "evidence_id": "EV-123456",
           "analysis_path": "forensics/analysis/cluster-report-EV-123456-123456789.json"}
    data = {**summary(), "cluster_report_results": [row] * 100}
    schemas.validate("sd-forensics", data)
    data["cluster_report_results"].append(row)
    assert schemas.errors("sd-forensics", data)
