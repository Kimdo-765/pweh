"""SD 요약의 이름 대조 참조는 원문이나 침해 확정 판정을 받지 않는다."""

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
        "evidence_id": "EV-0001", "analysis_path": "forensics/analysis/sd-ioc-scan-EV-0001-001.json",
        "sha256": "a" * 64, "status": "partial", "matches_total": 2, "partition": 1,
        "firmware_result_path": "analysis/sd-surface-001.json",
        "fs_list_path": "forensics/analysis/fs-list-EV-0001-001.json",
    }


def test_sd_ioc_summary_preserves_old_summary_and_bounded_reference():
    data = _summary()
    schemas.validate("sd-forensics", data)
    data["ioc_scan_results"] = [_result()]
    schemas.validate("sd-forensics", data)


@pytest.mark.parametrize("field,value", [
    ("card_path", "synthetic-private-name"), ("excerpt", "synthetic-private-text"),
    ("analysis_path", "forensics/images/EV-0001/image.raw"),
    ("firmware_result_path", "analysis/../sd-surface-001.json"),
    ("fs_list_path", "forensics/analysis/arbitrary.json"),
    ("sha256", "invalid"), ("status", "compromised"), ("status", "safe"),
    ("matches_total", 201), ("matches_total", -1), ("partition", True),
    ("partition", 0), ("evidence_id", "EV-1234567"),
])
def test_sd_ioc_summary_rejects_raw_names_and_false_contract(field, value):
    data = _summary()
    result = _result()
    result[field] = value
    data["ioc_scan_results"] = [result]
    assert schemas.errors("sd-forensics", data)
