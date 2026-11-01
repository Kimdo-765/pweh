"""nfc-analysis 요약의 CU 식별 mode(cu-hf-identify) 계약. 기존 scan-bound-offline 요약은 그대로 유효해야 한다."""
import copy
import json
from pathlib import Path

import pytest

from pweh import cu_protocol as CU
from pweh import schemas

SCHEMA = json.loads((Path(__file__).resolve().parents[2] / "src/pweh/schemas/nfc-analysis.schema.json").read_text(encoding="utf-8"))
FLAGS = {"physical_same_tag_verified": False, "tag_content_written": False, "authentication_attempted": False,
         "emulation_performed": False}
IDENT = {"operation": "cu-identify", "profile": CU.IDENTIFY.profile, "family": "ultralight_or_ultralight_c",
         "policy": "attestation_required", "uid_length": 7, "ats_present": False, "get_version_sent": True,
         "page_reads_sent": False, "identity_digest": "sha256:" + "0" * 16}
STATUS = {"battery_mv": 4000, "battery_percent": 80, "battery_percent_is_estimate": True, "active_slot": 0, "mode": "reader",
          "hf14a_config_default": True, "app_version": CU.LIVE.app_version, "git_version": CU.LIVE.git_version,
          "model": "chameleon-ultra"}
TAG = {"tag_ref": "NT-" + "0" * 32, "scan_ref": "NS-" + "0" * 32, "family": "ntag213", "identity_digest": "sha256:" + "0" * 16}


def summary(**over):
    base = {"schema": "pweh.nfc-analysis/v1", "mode": "cu-hf-identify", "tags": [], "results": [],
            "identifications": [copy.deepcopy(IDENT)], "device_status": copy.deepcopy(STATUS), **FLAGS}
    base.update(over)
    return base


def test_identify_only_summary_is_valid_with_and_without_status():
    schemas.validate("nfc-analysis", summary())
    no_status = summary(); no_status.pop("device_status")
    schemas.validate("nfc-analysis", no_status)
    none_row = dict(IDENT, family="none", policy="not_applicable", uid_length=None, ats_present=None,
                    get_version_sent=False, identity_digest=None)
    schemas.validate("nfc-analysis", summary(identifications=[none_row]))


def test_existing_scan_bound_summary_rules_are_unchanged():
    schemas.validate("nfc-analysis", {"schema": "pweh.nfc-analysis/v1", "mode": "scan-bound-offline",
                                      "tags": [TAG], "results": [], **FLAGS})
    for bad in ({"tags": []}, {"tags": [TAG], "identifications": [IDENT]}):
        doc = {"schema": "pweh.nfc-analysis/v1", "mode": "scan-bound-offline", "tags": [TAG], "results": [], **FLAGS, **bad}
        with pytest.raises(Exception):
            schemas.validate("nfc-analysis", doc)


@pytest.mark.parametrize("mutate", [
    lambda d: d.pop("identifications"),
    lambda d: d.update(identifications=[]),
    lambda d: d["identifications"][0].update(page_reads_sent=True),
    lambda d: d["identifications"][0].update(family="mifare_ultralight_guess"),
    lambda d: d["identifications"][0].update(policy="allowed_by_user"),
    lambda d: d["identifications"][0].update(profile="cu-ntag21x-v2.3.0-v1"),
    lambda d: d["identifications"][0].update(identity_digest="04A1B2C3D4E5F6"),
    lambda d: d["identifications"][0].update(uid="04A1B2C3D4E5F6"),
    lambda d: d["device_status"].update(battery_percent=101),
    lambda d: d["device_status"].update(git_version="v2.3.0-14-g4c5bc2c"),
    lambda d: d["device_status"].update(ble_pin="123456"),
    lambda d: d.update(mode="cu-identify-guess"),
])
def test_identify_summary_rejects_invented_or_raw_values(mutate):
    doc = summary()
    mutate(doc)
    with pytest.raises(Exception):
        schemas.validate("nfc-analysis", doc)


def test_schema_constants_follow_the_frozen_profiles():
    item = SCHEMA["properties"]["identifications"]["items"]["properties"]
    assert set(item["family"]["enum"]) == set(CU.HF_FAMILIES)
    assert set(item["policy"]["enum"]) == set(CU.HF_POLICIES.values())
    assert item["profile"]["const"] == CU.IDENTIFY.profile
    status = SCHEMA["properties"]["device_status"]["properties"]
    assert (status["app_version"]["const"], status["git_version"]["const"]) == (CU.LIVE.app_version, CU.LIVE.git_version)
