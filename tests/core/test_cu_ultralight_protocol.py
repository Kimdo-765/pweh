"""장치 없이 Ultralight 계열 고정 프로필(UL_READ)·READ builder·응답 분류의 닫힌 경계를 검사한다.

기대값은 구현의 표를 읽지 않고 이 파일에 독립으로 다시 적는다. 근거는 MF0ICU1 Rev 3.9 §7.5.2,
MF0ICU2 Rev 3.5 §7.5.7·§9.2, MF0ULX1 Rev 3.3 §8.5.6·§8.6.1·§10.2와 공식 v2.3.0 rc522.c·app_cmd.c다.
"""
from __future__ import annotations

import copy
from dataclasses import FrozenInstanceError, replace
import hashlib
import importlib.util
import json
from pathlib import Path
import struct
import sys
from types import MappingProxyType

import pytest

from pweh import cu_protocol as C

UL_READ_SHA256 = "fde75c1da05251b816628e491b9e554d556857f455b39dc439df46a78225b728"
QUESTIONS_SHA256 = "dc25a3def996c4057831e39976a03c307c19a782949f9b7be179349f7085ec39"
LEGACY_V220_SHA256 = "d7e590dce5e5f9723cbff12aa0fcea46d5a9550e392a33cf7b0de5102dffd73c"
V230_SHA256 = "95132f6c6e6609854cf32af0f1644eb409147cf21060ba97e7eb3dee4d783eb5"
IDENTIFY_SHA256 = "d420c720c19ab0f4923879f7d53917a82fb4775f8115e98360ea17f3cf27d90b"
LF_IDENTIFY_SHA256 = "fefb6e77a90e0c5ebf255f378619313db848a26460efffdd19a86f599f582535"
ALLOWED_COMMANDS = {1000, 1017, 1033, 1002, 2000, 2010, 1025, 1018, 2200,
                    3000, 3002, 3010, 3004, 3014, 3019, 3021}
# (계열, GET_VERSION 8B 또는 None, 전체 페이지, 마지막 READ 시작 page, 보류 페이지)
FAMILIES = {
    "ultralight_ev1_mf0ul11": ("0004030101000b03", 20, 0x11, (0x12, 0x13)),
    "ultralight_ev1_mf0ulh11": ("0004030201000b03", 20, 0x11, (0x12, 0x13)),
    "ultralight_ev1_mf0ul21": ("0004030101000e03", 41, 0x26, (0x27, 0x28)),
    "ultralight_ev1_mf0ulh21": ("0004030201000e03", 41, 0x26, (0x27, 0x28)),
    "ultralight_or_ultralight_c": (None, 48, 0x2b, (0x2c, 0x2d, 0x2e, 0x2f)),
}


def wire(command, status=0, data=b""):
    """제품 encoder를 호출하지 않는 합성 frame 생성기."""
    header = struct.pack(">BBHHH", 0x11, 0xef, command, status, len(data))
    body = header + bytes(((256 - sum(header)) % 256,)) + data
    return body + bytes(((256 - sum(body)) % 256,))


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False)


def ul_recipe():
    """구현의 literal을 읽지 않고 UL recipe를 독립 dict로 다시 적는다."""
    families = {}
    for family, (version, total, last, withheld) in FAMILIES.items():
        row = {"pages_total": total, "last_target": last, "version": version}
        if version is None:
            row["version_replies"] = ["00-empty", "01-empty"]
            row["withheld"] = {"key_never_readable": list(withheld)}
        else:
            row["withheld"] = {"pwd_pack_readback_zero": list(withheld)}
        families[family] = row
    return {
        "profile": "cu-ultralight-v2.3.0-v1", "app_version": "2.3", "git_version": "v2.3.0",
        "firmware_commit": "4e1a5b267b9ed33559e0e2c9dad61d61eaf64ba1", "model": "chameleon-ultra",
        "reader_mode": True, "authentication": False, "commands": [1002, 2000, 2010],
        "crc_append": True, "crc_check": True, "digest_domain": "pweh.nfc-ultralight-tag/v1",
        "families": families,
        "identify_profile": "cu-hf14a-identify-v2.3.0-v1", "identify_profile_sha256": IDENTIFY_SHA256,
        "min_retained_pages": 3,
        "never_sent_opcodes": ["1a", "1b", "39", "3a", "3c", "3e", "4b", "a0", "a2"],
        "overlap_check": True, "page_attribution_bytes": 4, "policy": "attestation_required",
        "policy_profile": "ultralight-attested-v1", "raw_command": 2010,
        "raw_options": {"version": "f4", "read": "f4"}, "read_activation": "per_page", "read_opcode": "30",
        "rf_timeout_ms": 100, "scan_page_reads": 0,
        "stop": {"nak_ends_read": True, "nak_min_page": 3,
                 "ready_after": ["end_of_targets", "nak_with_rollover", "nak_without_rollover"]},
        "tag_ownership": {"binding_scope": "case", "decided_via": ["cli-tty", "elicitation"],
                          "kind": "tag-ownership", "question_ids": ["owned_tag"],
                          "questions_sha256": QUESTIONS_SHA256},
        "type2": {"uid_length": 7, "atqa_msb": "0044", "sak": "00", "ats_length": 0},
        "uid_check": ["uid7", "bcc0", "bcc1"],
    }


def profile_from(recipe):
    encoded = canonical(recipe)
    return C._frozen_profile(encoded, hashlib.sha256(encoded.encode()).hexdigest(), b"\x02\x03")


def failure(call, code):
    with pytest.raises(C.CuProtocolError) as caught:
        call()
    assert caught.value.code == code and caught.value.data == {}
    return caught.value


def test_ul_recipe_is_independently_pinned_and_outside_reader_registry():
    encoded = canonical(ul_recipe())
    assert hashlib.sha256(encoded.encode()).hexdigest() == UL_READ_SHA256 == C.UL_READ.profile_sha256
    assert C.UL_READ.recipe == encoded and C.UL_READ.profile == "cu-ultralight-v2.3.0-v1"
    assert (C.UL_READ.firmware_commit, C.UL_READ.app_version, C.UL_READ.git_version, C.UL_READ.app_wire) == (
        C.LIVE.firmware_commit, C.LIVE.app_version, C.LIVE.git_version, C.LIVE.app_wire)
    # NTAG 원장·snapshot 검증의 reader 집합은 그대로 두 행이며 UL 프로필을 이름으로 찾을 수 없다.
    assert len(C.KNOWN) == 2 and set(C.KNOWN) == {"cu-ntag21x-v2.2.0-v1", "cu-ntag21x-v2.3.0-v1"}
    assert C.UL_READ.profile not in C.KNOWN and C.known_reader_profile(C.UL_READ.profile) is None
    assert C.UL_READ.profile not in (C.IDENTIFY.profile, C.LF_IDENTIFY.profile)
    with pytest.raises(FrozenInstanceError):
        C.UL_READ.profile_sha256 = "0" * 64


def test_existing_profile_hashes_and_command_set_are_literal_pins():
    assert C.LEGACY_V220.profile_sha256 == LEGACY_V220_SHA256
    assert C.V230.profile_sha256 == V230_SHA256 and C.LIVE is C.V230
    assert C.IDENTIFY.profile_sha256 == IDENTIFY_SHA256
    assert C.LF_IDENTIFY.profile_sha256 == LF_IDENTIFY_SHA256
    assert set(C._ALLOWED_COMMANDS) == ALLOWED_COMMANDS and type(C._ALLOWED_COMMANDS) is frozenset
    for row, sha in ((C.LEGACY_V220, LEGACY_V220_SHA256), (C.V230, V230_SHA256),
                     (C.IDENTIFY, IDENTIFY_SHA256), (C.LF_IDENTIFY, LF_IDENTIFY_SHA256)):
        assert hashlib.sha256(row.recipe.encode("ascii")).hexdigest() == sha


def test_families_equal_identify_ultralight_subset_and_tables_are_closed():
    subset = {family for family, policy in C.HF_POLICIES.items()
              if policy == "attestation_required" and family.startswith("ultralight")}
    assert C.UL_FAMILIES == frozenset(FAMILIES) == subset and len(subset) == 5
    # Classic·type2_other_version·type2_version_unreadable은 UL 계열이 아니다.
    for other in ("mifare_classic_1k", "type2_other_version", "type2_version_unreadable", "ntag213"):
        assert other not in C.UL_FAMILIES
    assert type(C.UL_SPECS) is MappingProxyType and set(C.UL_SPECS) == set(FAMILIES)
    for family, (version, total, last, withheld) in FAMILIES.items():
        spec = C.UL_SPECS[family]
        assert spec.family == family and spec.pages_total == total and spec.last_target == last
        assert spec.version == (None if version is None else bytes.fromhex(version))
        assert spec.withheld_pages == frozenset(withheld) == frozenset(range(last + 1, total))
        assert max(range(last + 1)) < 0x2c
        if version is not None:
            assert C._HF_VERSIONS[spec.version] == family
    assert C.UL_DIGEST_DOMAIN == b"pweh.nfc-ultralight-tag/v1" != C.HF_DIGEST_DOMAIN
    assert C.UL_POLICY_PROFILE == "ultralight-attested-v1"
    assert dict(C.UL_OWNERSHIP) == {"kind": "tag-ownership", "binding_scope": "case",
                                    "decided_via": ("cli-tty", "elicitation"), "question_ids": ("owned_tag",),
                                    "questions_sha256": QUESTIONS_SHA256}
    with pytest.raises(TypeError):
        C.UL_SPECS["ntag213"] = C.UL_SPECS["ultralight_ev1_mf0ul11"]
    with pytest.raises(FrozenInstanceError):
        C.UL_SPECS["ultralight_ev1_mf0ul11"].last_target = 0x13


def _set(path, value):
    def mutate(recipe):
        node = recipe
        for key in path[:-1]:
            node = node[key]
        if value is _DELETE:
            del node[path[-1]]
        else:
            node[path[-1]] = value
    return mutate


_DELETE = object()
EV1 = "ultralight_ev1_mf0ul11"
EV21 = "ultralight_ev1_mf0ul21"
LEGACY = "ultralight_or_ultralight_c"
MUTATIONS = {
    "profile-name": _set(("profile",), "cu-ultralight-v2.3.0-v2"),
    "firmware-commit": _set(("firmware_commit",), "f349dbeeaa315776b272ae8fb851cc4042d55f07"),
    "model": _set(("model",), "chameleon-lite"),
    "reader-mode": _set(("reader_mode",), False),
    "commands-extra": _set(("commands",), [1002, 2000, 2010, 2016]),
    "commands-missing": _set(("commands",), [1002, 2000]),
    "raw-command": _set(("raw_command",), 2011),
    "read-option-fc": _set(("raw_options", "read"), "fc"),
    "read-option-ec": _set(("raw_options", "read"), "ec"),
    "read-option-e4": _set(("raw_options", "read"), "e4"),
    "version-option": _set(("raw_options", "version"), "fc"),
    "raw-options-extra": _set(("raw_options", "first_read"), "fc"),
    "activation-chain": _set(("read_activation",), "keep_chain"),
    "read-opcode": _set(("read_opcode",), "3a"),
    "authentication": _set(("authentication",), True),
    "scan-page-reads": _set(("scan_page_reads",), 2),
    "scan-page-reads-bool": _set(("scan_page_reads",), False),
    "crc-check": _set(("crc_check",), False),
    "rf-timeout": _set(("rf_timeout_ms",), 200),
    "attribution": _set(("page_attribution_bytes",), 16),
    "identify-profile": _set(("identify_profile",), "cu-hf14a-identify-v2.3.0-v2"),
    "identify-sha": _set(("identify_profile_sha256",), "0" * 64),
    "type2": _set(("type2", "sak"), "01"),
    "digest-domain-identify": _set(("digest_domain",), "pweh.cu-hf-identify/v1"),
    "digest-domain-other": _set(("digest_domain",), "pweh.nfc-ultralight-tag/v2"),
    "family-missing": _set(("families", EV1), _DELETE),
    "family-type2-other": _set(("families", "type2_other_version"),
                               {"pages_total": 20, "last_target": 17, "version": "0004040101000b03",
                                "withheld": {"pwd_pack_readback_zero": [18, 19]}}),
    "family-ntag": _set(("families", "ntag213"),
                        {"pages_total": 20, "last_target": 17, "version": "0004040201000f03",
                         "withheld": {"pwd_pack_readback_zero": [18, 19]}}),
    "ev1-version-ntag": _set(("families", EV1, "version"), "0004040201000f03"),
    "ev1-version-swapped": _set(("families", EV1, "version"), "0004030201000b03"),
    "ev1-version-null": _set(("families", EV1, "version"), None),
    "ev1-version-short": _set(("families", EV1, "version"), "0004030101000b"),
    "ev1-extra-key": _set(("families", EV1, "version_replies"), ["00-empty"]),
    "legacy-version": _set(("families", LEGACY, "version"), "0004030101000b03"),
    "legacy-replies-one": _set(("families", LEGACY, "version_replies"), ["00-empty"]),
    "legacy-replies-crc": _set(("families", LEGACY, "version_replies"), ["00-empty", "01-empty", "03-empty"]),
    "legacy-replies-missing": _set(("families", LEGACY, "version_replies"), _DELETE),
    "pages-total": _set(("families", EV1, "pages_total"), 45),
    "last-target-key-page": lambda r: (r["families"][LEGACY].update(last_target=0x2c),
                                       r["families"][LEGACY].update(withheld={"key_never_readable": [45, 46, 47]})),
    "withheld-short": _set(("families", EV1, "withheld"), {"pwd_pack_readback_zero": [19]}),
    "withheld-long": _set(("families", EV1, "withheld"), {"pwd_pack_readback_zero": [17, 18, 19]}),
    "withheld-unsorted": _set(("families", EV21, "withheld"), {"pwd_pack_readback_zero": [40, 39]}),
    "withheld-legacy-short": _set(("families", LEGACY, "withheld"), {"key_never_readable": [44, 45, 46]}),
    "withheld-empty": _set(("families", EV1, "withheld"), {}),
    "never-sent-read": _set(("never_sent_opcodes",), ["1a", "1b", "30", "39", "3a", "3c", "3e", "4b", "a0", "a2"]),
    "never-sent-version": _set(("never_sent_opcodes",), ["1a", "1b", "39", "3a", "3c", "3e", "4b", "60", "a0", "a2"]),
    "never-sent-missing-pwd-auth": _set(("never_sent_opcodes",), ["1a", "39", "3a", "3c", "3e", "4b", "a0", "a2"]),
    "never-sent-missing-write": _set(("never_sent_opcodes",), ["1a", "1b", "39", "3a", "3c", "3e", "4b", "a0"]),
    "policy": _set(("policy",), "allowed"),
    "policy-profile": _set(("policy_profile",), "ntag21x-only-v1"),
    "min-retained": _set(("min_retained_pages",), 2),
    "nak-min-page": _set(("stop", "nak_min_page"), 2),
    "ready-after": _set(("stop", "ready_after"), ["end_of_targets", "nak_with_rollover"]),
    "nak-ends-read": _set(("stop", "nak_ends_read"), False),
    "overlap-check": _set(("overlap_check",), False),
    "uid-check-bcc1": _set(("uid_check",), ["uid7", "bcc0"]),
    "ownership-kind-purpose": _set(("tag_ownership", "kind"), "tag-purpose"),
    "ownership-cli-only": _set(("tag_ownership", "decided_via"), ["cli-tty"]),
    "ownership-extra-question": _set(("tag_ownership", "question_ids"), ["owned_tag", "not_credential"]),
    "ownership-connection": _set(("tag_ownership", "binding_scope"), "connection"),
    "ownership-sha": _set(("tag_ownership", "questions_sha256"), "x"),
    "ownership-missing": _set(("tag_ownership",), _DELETE),
    "families-list": _set(("families",), []),
    # 계열 행의 페이지 기하는 datasheet와 묶인다(EV1 storage byte 0x0b→20, 0x0e→41, 원조 UL/UL C→48과 이유 이름).
    "layout-ev1-ul11-as-legacy": lambda r: r["families"][EV1].update(
        pages_total=48, last_target=43, withheld={"pwd_pack_readback_zero": [44, 45, 46, 47]}),
    "layout-ev1-ul21-as-ul11": lambda r: r["families"][EV21].update(
        pages_total=20, last_target=17, withheld={"pwd_pack_readback_zero": [18, 19]}),
    "layout-legacy-ev1-reason": _set(("families", LEGACY, "withheld"), {"pwd_pack_readback_zero": [44, 45, 46, 47]}),
    "layout-ev1-legacy-reason": _set(("families", EV1, "withheld"), {"key_never_readable": [18, 19]}),
    "layout-ev1-two-reasons": _set(("families", EV1, "withheld"), {"pwd_pack_readback_zero": [18],
                                                                    "key_never_readable": [19]}),
    "layout-legacy-as-ul21": lambda r: r["families"][LEGACY].update(
        pages_total=41, last_target=38, withheld={"key_never_readable": [39, 40]}),
}


@pytest.mark.parametrize("name", sorted(MUTATIONS))
def test_every_import_time_relation_is_checked(name):
    recipe = ul_recipe()
    # 변형 전 recipe는 같은 검사를 통과한다(변형이 검사 대상 관계만 깬다는 기준).
    assert set(C._ul_tables(profile_from(copy.deepcopy(recipe)))[0]) == set(FAMILIES)
    MUTATIONS[name](recipe)
    with pytest.raises(RuntimeError, match="Ultralight"):
        C._ul_tables(profile_from(recipe))


def test_ul_scan_profile_registry_is_closed_and_disjoint_from_reader_registry():
    # UL scan 사실 검증 집합은 live UL_READ 한 행이며 NTAG reader 집합과 겹치지 않는다.
    assert type(C.UL_KNOWN) is MappingProxyType and set(C.UL_KNOWN) == {"cu-ultralight-v2.3.0-v1"}
    assert C.UL_KNOWN["cu-ultralight-v2.3.0-v1"] is C.UL_READ and not set(C.UL_KNOWN) & set(C.KNOWN)
    assert C.UL_KNOWN["cu-ultralight-v2.3.0-v1"].profile_sha256 == UL_READ_SHA256
    assert C.known_ul_profile("cu-ultralight-v2.3.0-v1") is C.UL_READ
    for name in ("cu-ultralight-v2.3.0-v2", "CU-ULTRALIGHT-V2.3.0-V1", "cu-ultralight-v2.3.0-v1 ", "cu-ntag21x-v2.3.0-v1",
                 "cu-hf14a-identify-v2.3.0-v1", None, 1, ["cu-ultralight-v2.3.0-v1"]):
        assert C.known_ul_profile(name) is None
    assert C.known_reader_profile("cu-ultralight-v2.3.0-v1") is None
    with pytest.raises(TypeError):
        C.UL_KNOWN["cu-ultralight-v2.3.0-v2"] = C.UL_READ


@pytest.mark.parametrize("change", ["in_reader_registry", "other_domain", "other_policy", "missing_live", "name_key"])
def test_ul_scan_profile_registry_relations_are_checked(monkeypatch, change):
    assert C._ul_known_valid()
    recipe = ul_recipe()
    recipe["profile"] = "cu-ultralight-v2.3.0-v2"
    if change == "other_domain":
        recipe["digest_domain"] = "pweh.nfc-ultralight-tag/v2"
    elif change == "other_policy":
        recipe["policy_profile"] = "ultralight-attested-v2"
    other = profile_from(recipe)
    rows = {C.UL_READ.profile: C.UL_READ, other.profile: other}
    if change == "in_reader_registry":
        monkeypatch.setattr(C, "KNOWN", MappingProxyType({**C.KNOWN, other.profile: other}))
    elif change == "missing_live":
        rows = {other.profile: other}
    elif change == "name_key":
        rows = {C.UL_READ.profile: C.UL_READ, "cu-ultralight-v2.3.0-v3": other}
    monkeypatch.setattr(C, "UL_KNOWN", MappingProxyType(rows))
    assert not C._ul_known_valid()


def test_ul_profile_in_reader_registry_is_rejected(monkeypatch):
    monkeypatch.setattr(C, "KNOWN", MappingProxyType({**C.KNOWN, C.UL_READ.profile: C.UL_READ}))
    with pytest.raises(RuntimeError):
        C._ul_tables(C.UL_READ)


@pytest.mark.parametrize("old,new", [
    ('"read":"f4"', '"read":"fc"'),
    ('"last_target":43', '"last_target":44'),
    ('"key_never_readable":[44,45,46,47]', '"key_never_readable":[45,46,47]'),
    ('["owned_tag"]', '["owned_tag","console_toy_tag"]'),
])
def test_import_fails_explicitly_when_ul_literal_is_altered(tmp_path, old, new):
    source = Path(C.__file__).read_text(encoding="utf-8")
    start = source.index("_UL_READ_RECIPE = (")
    end = source.index("_UL_READ_SHA256")
    assert source[start:end].count(old) == 1
    altered = source[:start] + source[start:end].replace(old, new) + source[end:]
    path = tmp_path / "cu_protocol_ul_tampered.py"
    path.write_text(altered, encoding="utf-8")
    spec = importlib.util.spec_from_file_location("pweh._cu_ul_tampered", path, submodule_search_locations=None)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    try:
        with pytest.raises(RuntimeError, match="hash"):
            spec.loader.exec_module(module)
    finally:
        sys.modules.pop(spec.name, None)
    assert sys.modules["pweh.cu_protocol"] is C


@pytest.mark.parametrize("family", sorted(FAMILIES))
def test_builder_accepts_every_target_page_with_exact_per_page_f4_wire(family):
    version, total, last, withheld = FAMILIES[family]
    spec = C.UL_SPECS[family]
    for page in range(last + 1):
        frame = C.build_ul_read(spec, page)
        # option f4(activate|wait|append_crc|auto_select|check_crc, keep=0)·RF 100ms·16bit·READ pp.
        assert frame == wire(2010, 0, bytes((0xf4, 0x00, 0x64, 0x00, 0x10, 0x30, page)))
        assert frame[9] == 0xf4 and frame[9] & 0x08 == 0
    for page in (*withheld, last + 1, total, 0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0xff, -1, 256):
        failure(lambda: C.build_ul_read(spec, page), "cu_protocol_invalid")


@pytest.mark.parametrize("page", [True, False, 1.0, "1", None, b"\x01"])
def test_builder_page_is_exact_int(page):
    failure(lambda: C.build_ul_read(C.UL_SPECS[EV1], page), "cu_protocol_invalid")


def test_builder_rejects_foreign_or_copied_specs_and_has_no_option_argument():
    spec = C.UL_SPECS[LEGACY]
    copied = replace(spec)
    assert copied == spec and copied is not spec
    forged = C.CuUlSpec(LEGACY, None, 48, 0x2f, ())
    for value in (copied, forged, C.NtagFamily.NTAG213, LEGACY, None):
        failure(lambda: C.build_ul_read(value, 0), "cu_protocol_invalid")
    with pytest.raises(TypeError):
        C.build_ul_read(spec, 0, keep_field=True)  # type: ignore[call-arg]
    with pytest.raises(TypeError):
        C.build_ul_read(spec, 0, option=0xfc)  # type: ignore[call-arg]
    # 어떤 page에서도 keep=1(fc/ec/e4)·다른 opcode를 만들지 않는다.
    frames = [C.build_ul_read(s, p) for s in C.UL_SPECS.values() for p in range(s.last_target + 1)]
    assert {f[9] for f in frames} == {0xf4} and {f[14] for f in frames} == {0x30}
    assert max(f[15] for f in frames) == 0x2b


def test_get_version_reuses_existing_keep0_builder():
    assert C.build_ntag_version(keep_field=False) == wire(2010, 0, bytes.fromhex("f40064000860"))
    failure(lambda: C.build_ntag_version(keep_field=True), "cu_protocol_invalid")


@pytest.mark.parametrize("status,data,kind", [
    (0x00, bytes(range(16)), "data"),
    (0x00, b"", "nak"),
    (0x01, b"", "rf_error"),
    (0x02, b"", "rf_error"),
    (0x03, b"", "rf_error"),
    (0x07, b"", "rf_error"),
    (0x00, b"\x0a", "rf_error"),
    (0x00, bytes(4), "rf_error"),
    (0x00, bytes(15), "rf_error"),
    (0x00, bytes(17), "rf_error"),
    (0x00, bytes(18), "rf_error"),
    (0x01, bytes(16), "rf_error"),
    (0x03, bytes(16), "rf_error"),
])
def test_read_reply_classification(status, data, kind):
    reply = C.classify_ul_read(C.CuFrame(2010, status, data))
    assert reply.kind == kind and reply.status == status
    assert (reply.data == data) if kind == "data" else reply.data is None
    assert data.hex() not in repr(reply) or not data


@pytest.mark.parametrize("value", [C.CuFrame(2000, 0, bytes(16)), C.CuFrame(1002, 0x68, b"\x01"),
                                   wire(2010, 0, bytes(16)), None, "data"])
def test_read_classifier_requires_exact_raw_frame(value):
    failure(lambda: C.classify_ul_read(value), "nfc_scan_invalid")


@pytest.mark.parametrize("kind,data,status", [
    ("data", None, 0), ("data", bytes(15), 0), ("data", bytes(16), 1), ("nak", b"", 0), ("nak", None, 1),
    ("rf_error", bytes(16), 1), ("other", None, 0), ("data", bytearray(16), 0),
])
def test_read_reply_constructor_is_closed(kind, data, status):
    failure(lambda: C.CuUlReply(kind, data, status), "nfc_scan_invalid")


@pytest.mark.parametrize("kwargs", [
    {"family": 1}, {"version": b"\x00" * 7}, {"pages_total": "20"}, {"last_target": 17.0},
    {"withheld": [("pwd_pack_readback_zero", (18, 19))]}, {"withheld": (("r", [18, 19]),)},
])
def test_spec_constructor_is_closed(kwargs):
    base = dict(family=EV1, version=bytes.fromhex("0004030101000b03"), pages_total=20, last_target=17,
                withheld=(("pwd_pack_readback_zero", (18, 19)),))
    base.update(kwargs)
    failure(lambda: C.CuUlSpec(**base), "cu_protocol_invalid")
