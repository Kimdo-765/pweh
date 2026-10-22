"""목록 자동 검사 요약의 참조·미검사 범위·원문 비노출 계약을 확인한다."""

from copy import deepcopy

import pytest

from pweh import schemas


def _summary():
    return {
        "mode": "security", "security": {},
        "privacy": {"audio_decoded": False, "face_plate_processing": False,
                    "uploads": False, "recording_content_viewed": False,
                    "secret_plaintext_returned": False},
    }


def _result():
    return {
        "evidence_id": "EV-0001",
        "analysis_path": "forensics/analysis/secrets-survey-EV-0001-001.json",
        "analysis_sha256": "a" * 64,
        "fs_list_path": "forensics/analysis/fs-list-EV-0001-001.json",
        "status": "partial", "files_scheduled": 32, "files_read_complete": 30,
        "eligible_files_unread": 5, "hits": 2, "scanned_bytes": 200,
        "unscanned_read_bytes": 100, "whole_card_examined": False,
        "reasons": ["file_limit", "read_failed"],
    }


def test_old_summary_and_survey_reference_are_accepted():
    data = _summary()
    schemas.validate("sd-forensics", data)
    data["secret_survey_results"] = [_result()]
    schemas.validate("sd-forensics", data)


@pytest.mark.parametrize("field,value", [
    ("plaintext", "SYNTHETIC_ONLY_SECRET"), ("filename", "private.conf"),
    ("analysis_path", "forensics/images/EV-0001/private.conf"),
    ("fs_list_path", "forensics/recovered/private.conf"),
    ("analysis_sha256", "invalid"), ("status", "safe"),
    ("files_scheduled", 33), ("files_read_complete", -1),
    ("eligible_files_unread", 200001), ("hits", 201),
    ("scanned_bytes", 16777217), ("unscanned_read_bytes", -1),
    ("whole_card_examined", True), ("reasons", ["secret-free"]),
    ("reasons", ["time_limit", "time_limit"]),
])
def test_survey_summary_rejects_content_scope_and_invalid_bounds(field, value):
    data = _summary()
    result = deepcopy(_result())
    result[field] = value
    data["secret_survey_results"] = [result]
    assert schemas.errors("sd-forensics", data)


def test_survey_summary_keeps_plaintext_privacy_false():
    data = _summary()
    data["secret_survey_results"] = [_result()]
    data["privacy"]["secret_plaintext_returned"] = True
    assert schemas.errors("sd-forensics", data)
