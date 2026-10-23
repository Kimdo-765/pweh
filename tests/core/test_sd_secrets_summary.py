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


@pytest.mark.parametrize("reasons", [
    ["selection_boundary"], ["selection_boundary", "hit_limit"],
    ["time_limit", "selection_boundary"], ["line_too_long", "selection_boundary"],
])
def test_range_reason_uses_existing_eight_fields_and_coexists_with_file_result(reasons):
    data = _summary()
    data["secret_scan_results"] = [_result(), {**_result(), "hits": 0,
        "scanned_bytes": 0, "unscanned_bytes": 4 << 20, "reasons": reasons}]
    data["privacy"]["secret_plaintext_returned"] = False
    schemas.validate("sd-forensics", data)
    assert len(data["secret_scan_results"][1]) == 8


@pytest.mark.parametrize("field", tuple(_result()))
def test_range_summary_keeps_every_existing_required_field(field):
    row = {**_result(), "reasons": ["selection_boundary"]}
    del row[field]
    assert schemas.errors("sd-forensics", {**_summary(), "secret_scan_results": [row]})


@pytest.mark.parametrize("field,value", [
    ("offset", 128), ("length", 1024), ("profile", "utf8-masked-secrets-ev-range-v1"),
    ("selected_sha256", "b" * 64), ("selected_size", 1024), ("evidence_size", 8 << 20),
    ("prefix_complete", False), ("suffix_complete", False), ("source", {}),
    ("sha256", "b" * 64), ("key", "RAW_PRIVATE"), ("url", "RAW_PRIVATE"),
    ("plaintext", "RAW_PRIVATE"), ("whole_evidence_examined", True),
    ("reasons", ["selection_boundary", "selection_boundary"]),
    ("reasons", ["selection_boundary", "RAW_PRIVATE"]),
    ("reasons", ["selection_boundary\n"]),
])
def test_range_summary_rejects_new_source_keys_plaintext_and_unknown_reasons(field, value):
    row = {**_result(), "reasons": ["selection_boundary"], field: value}
    assert schemas.errors("sd-forensics", {**_summary(), "secret_scan_results": [row]})


def test_range_summary_preserves_existing_array_and_counter_caps():
    row = {**_result(), "hits": 200, "scanned_bytes": 0, "unscanned_bytes": 4 << 20,
           "reasons": ["selection_boundary"]}
    data = {**_summary(), "secret_scan_results": [row] * 200}
    schemas.validate("sd-forensics", data)
    data["secret_scan_results"].append(row)
    assert schemas.errors("sd-forensics", data)
    for key, value in (("hits", 201), ("scanned_bytes", (4 << 20) + 1),
                       ("unscanned_bytes", (4 << 20) + 1)):
        assert schemas.errors("sd-forensics", {**_summary(), "secret_scan_results": [{**row, key: value}]})
