"""기존 SD 요약과 원문 없는 선택 비밀값 검사 참조의 호환성을 확인한다."""

from copy import deepcopy

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
        "analysis_path": "forensics/analysis/secrets-scan-EV-0001-001.json",
        "analysis_sha256": "a" * 64, "status": "partial", "hits": 2,
        "scanned_bytes": 200, "unscanned_bytes": 100, "reasons": ["hit_limit"],
    }


def test_sd_secret_summary_keeps_old_summary_and_masked_reference():
    data = _summary()
    schemas.validate("sd-forensics", data)
    data["secret_scan_results"] = [_result()]
    data["privacy"]["secret_plaintext_returned"] = False
    schemas.validate("sd-forensics", data)


@pytest.mark.parametrize("field,value", [
    ("plaintext", "synthetic-secret"), ("path", "config.txt"),
    ("analysis_path", "forensics/images/EV-0001/config.txt"),
    ("analysis_sha256", "invalid"), ("status", "safe"),
    ("hits", 201), ("scanned_bytes", -1), ("unscanned_bytes", 4194305),
    ("reasons", ["untrusted free text"]), ("reasons", ["synthetic_secret"]),
])
def test_sd_secret_summary_rejects_content_and_false_contract(field, value):
    data = _summary()
    result = deepcopy(_result())
    result[field] = value
    data["secret_scan_results"] = [result]
    assert schemas.errors("sd-forensics", data)


def test_sd_secret_summary_forbids_plaintext_return_claim():
    data = _summary()
    data["privacy"]["secret_plaintext_returned"] = True
    assert schemas.errors("sd-forensics", data)
