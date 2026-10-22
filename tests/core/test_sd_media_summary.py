"""SD 요약의 미디어 구조 참조는 내용·시각·복구 성공 판정을 담지 않는다."""

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
        "evidence_id": "EV-0001", "analysis_path": "forensics/analysis/media-inventory-EV-0001-001.json",
        "sha256": "a" * 64, "status": "partial", "selected_size": 1024, "boxes_reported": 4,
    }


def test_sd_media_summary_preserves_old_summary_and_structural_reference():
    data = _summary()
    schemas.validate("sd-forensics", data)
    data["media_inventory_results"] = [_result()]
    schemas.validate("sd-forensics", data)


@pytest.mark.parametrize("field,value", [
    ("path", "synthetic-private-name"), ("codec", "unverified-codec"),
    ("recording_time", "synthetic-private-time"), ("uuid", "synthetic-private-id"),
    ("analysis_path", "forensics/images/EV-0001/recording.bin"),
    ("sha256", "invalid"), ("status", "playable"), ("status", "encrypted"),
    ("boxes_reported", 4097), ("boxes_reported", -1), ("selected_size", True),
    ("selected_size", 67108865), ("selected_size", -1), ("evidence_id", "EV-1234567"),
])
def test_sd_media_summary_rejects_content_and_unverified_claims(field, value):
    data = _summary()
    result = _result()
    result[field] = value
    data["media_inventory_results"] = [result]
    assert schemas.errors("sd-forensics", data)
