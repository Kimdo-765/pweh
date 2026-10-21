"""Android 요약은 허용한 폰 내용과 범위 밖 처리를 구분한다."""

import copy

import pytest

from pweh.schemas import validate
from pweh.errors import ValidationFailed


VALUE = {"evidence": [{"evidence_id": "EV-0001", "sha256": "0" * 64, "status": "ok", "storage": "copy"}],
         "analyses": [], "coverage": {"limitations": [], "unexamined": []},
         "privacy": {"phone_content_returned": True, "still_image_content_returned": False, "video_processed": False,
                     "audio_processed": False, "external_uploads": False, "credentials_used": False, "sql_executed": False}}


def test_authorized_phone_content_summary():
    validate("android-forensics", VALUE)


@pytest.mark.parametrize("key", ["video_processed", "audio_processed", "external_uploads", "credentials_used", "sql_executed"])
def test_out_of_scope_processing_is_not_a_valid_summary(key):
    value = copy.deepcopy(VALUE)
    value["privacy"][key] = True
    with pytest.raises(ValidationFailed):
        validate("android-forensics", value)
