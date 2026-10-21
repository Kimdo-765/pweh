"""정지 그림 요약의 근거 분리·증거 해시·기존 SD 요약 호환 계약."""

from copy import deepcopy

import pytest

from pweh import schemas
from pweh.errors import ValidationFailed


def _summary():
    return {
        "images": [{
            "source": {"kind": "evidence", "evidence_id": "EV-0001", "evidence_sha256": "1" * 64},
            "input_sha256": "2" * 64,
            "analysis_path": "forensics/analysis/image-hints-EV-0001-001.json",
            "analysis_sha256": "3" * 64,
            "status": "partial",
        }],
        "visual_observations": [],
        "hints": [{"hypothesis": "문구는 설정 안내의 후보", "evidence": ["ocr.text"],
                   "confidence": "possible", "unverified": ["그림 표시를 확인하지 못함"]}],
        "limitations": ["클라이언트 이미지 표시 미확인"],
        "safety": {"video_processed": False, "audio_processed": False, "external_ocr": False, "urls_followed": False},
    }


def test_image_summary_allows_text_only_evidence_and_separate_visual_evidence():
    value = _summary()
    schemas.validate("image-hints", value)
    value["visual_observations"] = [{"analysis_path": value["images"][0]["analysis_path"],
                                     "preview_sha256": "4" * 64, "crop": [0, 0, 100, 80],
                                     "observation": "사각 기판과 네 개의 패드가 보임", "confidence": "likely"}]
    schemas.validate("image-hints", value)


@pytest.mark.parametrize("field", ["evidence_id", "evidence_sha256"])
def test_image_summary_requires_intake_identity_separate_from_member_hash(field):
    value = _summary()
    del value["images"][0]["source"][field]
    with pytest.raises(ValidationFailed):
        schemas.validate("image-hints", value)


@pytest.mark.parametrize("field", ["video_processed", "audio_processed", "external_ocr", "urls_followed"])
def test_image_summary_rejects_out_of_scope_processing(field):
    value = _summary()
    value["safety"][field] = True
    with pytest.raises(ValidationFailed):
        schemas.validate("image-hints", value)


def test_sd_summary_distinguishes_still_images_from_recordings_and_keeps_old_shape():
    old = {"mode": "security", "security": {}, "privacy": {
        "audio_decoded": False, "face_plate_processing": False, "uploads": False,
        "recording_content_viewed": False,
    }}
    schemas.validate("sd-forensics", old)
    new = deepcopy(old)
    new["privacy"].update(still_image_content_viewed=True, still_image_ocr_returned=True)
    schemas.validate("sd-forensics", new)
    new["privacy"]["recording_content_viewed"] = True
    with pytest.raises(ValidationFailed):
        schemas.validate("sd-forensics", new)
