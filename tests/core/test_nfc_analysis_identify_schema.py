"""nfc-analysis 요약의 CU 식별 mode(cu-hf-identify·cu-lf-identify) 계약. 기존 scan-bound-offline 요약은 그대로 유효해야 한다."""
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


# --- LF 125 kHz 식별(cu-lf-identify) -------------------------------------------------------------
LF_IDENT = {"operation": "cu-lf-identify", "profile": CU.LF_IDENTIFY.profile, "family": "em410x",
            "variant": "em410x_64", "policy": "refused", "scans_sent": ["em410x_scan"],
            "identity_digest": None, "id_returned": False}
LF_NONE = {"operation": "cu-lf-identify", "profile": CU.LF_IDENTIFY.profile, "family": "none", "variant": None,
           "policy": "not_applicable", "identity_digest": None, "id_returned": False,
           "scans_sent": ["em410x_scan", "hidprox_scan", "ioprox_scan", "viking_scan", "pac_scan",
                          "jablotron_scan", "pyramid_scan"]}


LF_ORDER = [CU.LF_SCAN_NAMES[scan] for scan in CU.LF_SCAN_ORDER]


def lf_found(family, variant=None):
    """감지 계열 항목: scans_sent는 고정 순서에서 그 계열 scan까지의 앞부분이다."""
    scan = next(s for s in CU.LF_SCAN_ORDER if CU.LF_SCAN_SPECS[s].family == family)
    return dict(LF_IDENT, family=family, variant=variant, scans_sent=LF_ORDER[:CU.LF_SCAN_ORDER.index(scan) + 1])


def lf_summary(**over):
    base = {"schema": "pweh.nfc-analysis/v1", "mode": "cu-lf-identify", "tags": [], "results": [],
            "lf_identifications": [copy.deepcopy(LF_IDENT)], **FLAGS}
    base.update(over)
    return base


def test_lf_identify_summary_is_valid_alone_with_status_and_with_hf_rows():
    schemas.validate("nfc-analysis", lf_summary())
    schemas.validate("nfc-analysis", lf_summary(lf_identifications=[copy.deepcopy(LF_NONE)]))
    schemas.validate("nfc-analysis", lf_summary(device_status=copy.deepcopy(STATUS)))
    schemas.validate("nfc-analysis", lf_summary(identifications=[copy.deepcopy(IDENT)]))
    for family in ("hidprox", "ioprox", "viking", "pac", "jablotron", "pyramid"):
        schemas.validate("nfc-analysis", lf_summary(lf_identifications=[lf_found(family)]))


def test_hf_identify_summary_may_also_carry_lf_rows():
    doc = summary(lf_identifications=[copy.deepcopy(LF_IDENT), copy.deepcopy(LF_NONE)])
    schemas.validate("nfc-analysis", doc)


def test_scan_bound_summary_rejects_lf_rows():
    doc = {"schema": "pweh.nfc-analysis/v1", "mode": "scan-bound-offline", "tags": [TAG], "results": [], **FLAGS,
           "lf_identifications": [copy.deepcopy(LF_IDENT)]}
    with pytest.raises(Exception):
        schemas.validate("nfc-analysis", doc)


@pytest.mark.parametrize("mutate", [
    lambda d: d.pop("lf_identifications"),
    lambda d: d.update(lf_identifications=[]),
    lambda d: d["lf_identifications"][0].update(id_returned=True),
    lambda d: d["lf_identifications"][0].update(operation="cu-identify"),
    lambda d: d["lf_identifications"][0].update(profile=CU.IDENTIFY.profile),
    lambda d: d["lf_identifications"][0].update(family="indala"),
    lambda d: d["lf_identifications"][0].update(policy="attestation_required"),
    lambda d: d["lf_identifications"][0].update(policy="allowed"),
    lambda d: d["lf_identifications"][0].update(identity_digest="5AA51337C0"),
    lambda d: d["lf_identifications"][0].update(em410x_id="5AA51337C0"),
    lambda d: d["lf_identifications"][0].update(facility_code=123),
    lambda d: d["lf_identifications"][0].update(scans_sent=[]),
    lambda d: d["lf_identifications"][0].update(scans_sent=["em4x05_scan"]),
    lambda d: d["lf_identifications"][0].update(scans_sent=["em410x_scan", "em410x_scan"]),
    lambda d: d["lf_identifications"][0].update(variant=None),
    lambda d: d["lf_identifications"][0].update(variant="em410x"),
    lambda d: d["lf_identifications"][0].update(family="hidprox"),
    lambda d: d["lf_identifications"][0].pop("variant"),
    lambda d: d.update(mode="cu-lf-guess"),
    # §6.2 정책은 family로 정해진다: 감지는 refused, none은 not_applicable.
    lambda d: d["lf_identifications"][0].update(policy="not_applicable"),
    lambda d: d.update(lf_identifications=[dict(LF_NONE, policy="refused")]),
    lambda d: d.update(lf_identifications=[dict(lf_found("viking"), policy="not_applicable")]),
    # LF는 ID 파생 출력이 없다: identity_digest는 모든 계열에서 null이며 키는 빠질 수 없다.
    lambda d: d["lf_identifications"][0].update(identity_digest="sha256:" + "1" * 16),
    lambda d: d.update(lf_identifications=[dict(LF_NONE, identity_digest="sha256:" + "2" * 16)]),
    lambda d: d.update(lf_identifications=[dict(lf_found("pyramid"), identity_digest="sha256:" + "3" * 16)]),
    lambda d: d["lf_identifications"][0].update(identity_digest=""),
    lambda d: d["lf_identifications"][0].update(identity_digest=0),
    lambda d: d["lf_identifications"][0].update(identity_digest=False),
    lambda d: d["lf_identifications"][0].pop("identity_digest"),
    # scans_sent는 고정 순서의 앞부분이고 마지막이 그 계열 scan이다(none은 일곱 개 전부).
    lambda d: d.update(lf_identifications=[dict(lf_found("viking"), scans_sent=["viking_scan"])]),
    lambda d: d.update(lf_identifications=[dict(lf_found("hidprox"), scans_sent=["em410x_scan"])]),
    lambda d: d.update(lf_identifications=[dict(lf_found("hidprox"), scans_sent=LF_ORDER[:3])]),
    lambda d: d.update(lf_identifications=[dict(lf_found("viking"), scans_sent=["em410x_scan", "ioprox_scan",
                                                                              "hidprox_scan", "viking_scan"])]),
    lambda d: d["lf_identifications"][0].update(scans_sent=LF_ORDER[:2]),
    lambda d: d.update(lf_identifications=[dict(LF_NONE, scans_sent=LF_ORDER[:6])]),
    lambda d: d.update(lf_identifications=[dict(LF_NONE, scans_sent=["pyramid_scan"])]),
    lambda d: d.update(lf_identifications=[dict(LF_NONE, scans_sent=LF_ORDER + ["pyramid_scan"])]),
    lambda d: d.update(lf_identifications=[dict(LF_NONE, variant="em410x_16")]),
])
def test_lf_summary_rejects_invented_or_raw_values(mutate):
    doc = lf_summary()
    mutate(doc)
    with pytest.raises(Exception):
        schemas.validate("nfc-analysis", doc)


def test_lf_schema_constants_follow_the_frozen_profile():
    item = SCHEMA["properties"]["lf_identifications"]["items"]["properties"]
    assert set(item["family"]["enum"]) == set(CU.LF_FAMILIES)
    assert set(item["policy"]["enum"]) == set(CU.LF_POLICIES.values())
    assert set(item["variant"]["enum"]) - {None} == set(CU.LF_VARIANTS)
    assert item["profile"]["const"] == CU.LF_IDENTIFY.profile
    assert item["scans_sent"]["items"]["enum"] == [CU.LF_SCAN_NAMES[scan] for scan in CU.LF_SCAN_ORDER]
    assert [row["const"] for row in item["scans_sent"]["prefixItems"]] == LF_ORDER
    rules = SCHEMA["properties"]["lf_identifications"]["items"]["allOf"]
    lengths = {rule["if"]["properties"]["family"]["const"]: rule["then"]["properties"]["scans_sent"]["minItems"]
               for rule in rules if "scans_sent" in rule.get("then", {}).get("properties", {})}
    # 계열별 scans_sent 길이는 recipe의 scan 순서에서 그 계열 scan의 위치다(none은 전부).
    assert lengths == {**{CU.LF_SCAN_SPECS[scan].family: index + 1 for index, scan in enumerate(CU.LF_SCAN_ORDER)},
                       "none": len(CU.LF_SCAN_ORDER)}
    assert {CU.LF_POLICIES[family] for family in CU.LF_FAMILIES - {"none"}} == {"refused"}
    assert CU.LF_POLICIES["none"] == "not_applicable"


def test_lf_summary_accepts_every_family_with_its_exact_prefix():
    for scan in CU.LF_SCAN_ORDER:
        family = CU.LF_SCAN_SPECS[scan].family
        variants = sorted(CU.LF_VARIANTS) if family == "em410x" else [None]
        for variant in variants:
            schemas.validate("nfc-analysis", lf_summary(lf_identifications=[lf_found(family, variant)]))
    schemas.validate("nfc-analysis", lf_summary(lf_identifications=[copy.deepcopy(LF_NONE)]))
    assert SCHEMA["properties"]["mode"]["enum"] == ["scan-bound-offline", "cu-hf-identify", "cu-lf-identify"]


def lf_rows_for_every_family():
    rows = []
    for scan in CU.LF_SCAN_ORDER:
        family = CU.LF_SCAN_SPECS[scan].family
        for variant in (sorted(CU.LF_VARIANTS) if family == "em410x" else [None]):
            rows.append(lf_found(family, variant))
    return rows + [copy.deepcopy(LF_NONE)]


def test_lf_identity_digest_is_null_only_for_every_family():
    """감지 계열(모두 refused)과 none 모두 identity_digest는 null만 받고 지문 문자열은 거부한다."""
    item = SCHEMA["properties"]["lf_identifications"]["items"]
    assert item["properties"]["identity_digest"] == {"type": "null"} and "identity_digest" in item["required"]
    # family 조건 규칙은 policy만 정하고 identity_digest를 다시 넓히지 않는다.
    assert all("identity_digest" not in rule.get(branch, {}).get("properties", {})
               for rule in item["allOf"] for branch in ("then", "else"))
    rows = lf_rows_for_every_family()
    assert {row["family"] for row in rows} == set(CU.LF_FAMILIES)
    for row in rows:
        assert row["identity_digest"] is None
        schemas.validate("nfc-analysis", lf_summary(lf_identifications=[row]))
        with pytest.raises(Exception):
            schemas.validate("nfc-analysis", lf_summary(lf_identifications=[dict(row, identity_digest="sha256:" + "a" * 16)]))
    # HF 식별 항목의 지문 규칙은 그대로다(문자열 지문 허용).
    schemas.validate("nfc-analysis", summary())
