"""장치 없이 합성 wire로 CU HF 식별 분류표·식별 recipe·상태 getter 경계를 검사한다.

분류 기대값은 구현의 표를 읽지 않고 이 파일에 독립으로 다시 적는다. 근거는
docs/references/cu-hf-identify.md 의 표(NXP AN10833 Rev 3.9·MF0ULX1 Rev 3.3·NTAG213_215_216 Rev 3.2,
공식 v2.3.0 firmware)와 같다.
"""
from __future__ import annotations

from dataclasses import FrozenInstanceError, replace
import hashlib
import importlib.util
import json
from pathlib import Path
import struct
import sys

import pytest

from pweh import cu_protocol as C

UID7 = b"SYNTH07"
UID4 = b"SYN4"
UID10 = b"SYNTHETIC0"
IDENTIFY_SHA256 = "d420c720c19ab0f4923879f7d53917a82fb4775f8115e98360ea17f3cf27d90b"
POLICIES = {
    "ntag213": "allowed", "ntag215": "allowed", "ntag216": "allowed",
    "ultralight_ev1_mf0ul11": "attestation_required", "ultralight_ev1_mf0ulh11": "attestation_required",
    "ultralight_ev1_mf0ul21": "attestation_required", "ultralight_ev1_mf0ulh21": "attestation_required",
    "ultralight_or_ultralight_c": "attestation_required", "type2_other_version": "attestation_required",
    "type2_version_unreadable": "attestation_required",
    "mifare_classic_mini": "attestation_required", "mifare_classic_1k": "attestation_required",
    "mifare_classic_tnp3xxx": "attestation_required",
    "mifare_classic_2k": "refused", "mifare_classic_4k": "refused", "mifare_plus_sl2": "refused",
    "iso14443_4": "refused",
    "none": "not_applicable", "multiple": "not_applicable", "other": "not_applicable",
}
# NXP 정확 GET_VERSION 값(CRC 제거 8B). MF0ULX1 Table 15, NTAG213_215_216 Table 28.
VERSIONS = {
    "0004030101000b03": "ultralight_ev1_mf0ul11", "0004030201000b03": "ultralight_ev1_mf0ulh11",
    "0004030101000e03": "ultralight_ev1_mf0ul21", "0004030201000e03": "ultralight_ev1_mf0ulh21",
    "0004040201000f03": "ntag213", "0004040201001103": "ntag215", "0004040201001303": "ntag216",
}


def wire(command, status=0, data=b""):
    """제품 encoder를 호출하지 않는 합성 frame 생성기."""
    header = struct.pack(">BBHHH", 0x11, 0xef, command, status, len(data))
    body = header + bytes(((256 - sum(header)) % 256,)) + data
    return body + bytes(((256 - sum(body)) % 256,))


def record(uid=UID7, atqa=b"\x44\x00", sak=0x00, ats=b""):
    return bytes((len(uid),)) + uid + atqa + bytes((sak,)) + bytes((len(ats),)) + ats


def failure(call, code):
    with pytest.raises(C.CuProtocolError) as caught:
        call()
    assert caught.value.code == code and caught.value.data == {}
    return caught.value


def identify_recipe():
    """구현의 literal을 읽지 않고 식별 recipe를 독립 dict로 다시 적는다."""
    return {
        "profile": "cu-hf14a-identify-v2.3.0-v1",
        "firmware_commit": "4e1a5b267b9ed33559e0e2c9dad61d61eaf64ba1",
        "model": "chameleon-ultra", "app_version": "2.3", "git_version": "v2.3.0", "reader_mode": True,
        "commands": [1002, 2000, 2010], "scan_command": 2000, "raw_command": 2010,
        "raw_options": {"version": "f4"}, "rf_timeout_ms": 100, "crc_append": True, "crc_check": True,
        "scan_statuses": {"01": "none", "04": "multiple"},
        "iso14443_4_sak_bit": "20",
        "sak_classes": {"01": "mifare_classic_tnp3xxx", "08": "mifare_classic_1k", "09": "mifare_classic_mini",
                        "10": "mifare_plus_sl2", "11": "mifare_plus_sl2",
                        "18": "mifare_classic_4k", "19": "mifare_classic_2k"},
        "type2": {"uid_length": 7, "atqa_msb": "0044", "sak": "00", "ats_length": 0},
        "versions": dict(VERSIONS),
        "version_fallbacks": {"00-empty": "ultralight_or_ultralight_c", "00-other8": "type2_other_version",
                              "01-empty": "ultralight_or_ultralight_c", "03-empty": "type2_version_unreadable"},
        "policies": dict(POLICIES),
        "page_reads": False, "authentication": False,
        "digest_domain": "pweh.cu-hf-identify/v1",
    }


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False)


def test_identify_recipe_is_independently_pinned_and_outside_reader_registry():
    encoded = canonical(identify_recipe())
    assert hashlib.sha256(encoded.encode()).hexdigest() == IDENTIFY_SHA256 == C.IDENTIFY.profile_sha256
    assert C.IDENTIFY.recipe == encoded and C.IDENTIFY.profile == "cu-hf14a-identify-v2.3.0-v1"
    assert (C.IDENTIFY.firmware_commit, C.IDENTIFY.app_version, C.IDENTIFY.git_version) == (
        C.LIVE.firmware_commit, C.LIVE.app_version, C.LIVE.git_version)
    # 원장·snapshot 검증용 reader 집합은 그대로 두 행이며 식별 프로필을 이름으로 찾을 수 없다.
    assert set(C.KNOWN) == {"cu-ntag21x-v2.2.0-v1", "cu-ntag21x-v2.3.0-v1"}
    assert C.known_reader_profile(C.IDENTIFY.profile) is None
    assert C.IDENTIFY.profile_sha256 not in (C.LEGACY_V220.profile_sha256, C.V230.profile_sha256)
    with pytest.raises(FrozenInstanceError):
        C.IDENTIFY.profile_sha256 = "0" * 64


def test_family_and_policy_tables_are_closed_and_match_section_6_2():
    assert dict(C.HF_POLICIES) == POLICIES and C.HF_FAMILIES == frozenset(POLICIES)
    assert C.HF_SCAN_CLASSES == frozenset({"none", "multiple", "type2", "iso14443_4", "other",
        "mifare_classic_mini", "mifare_classic_1k", "mifare_classic_4k", "mifare_classic_2k",
        "mifare_classic_tnp3xxx", "mifare_plus_sl2"})
    assert "type2" not in C.HF_FAMILIES
    with pytest.raises(TypeError):
        C.HF_POLICIES["mifare_classic_4k"] = "allowed"


@pytest.mark.parametrize("old,new", [
    ('"08":"mifare_classic_1k"', '"08":"mifare_classic_4k"'),
    ('"mifare_classic_4k":"refused"', '"mifare_classic_4k":"allowed"'),
    ('"page_reads":false', '"page_reads":true'),
])
def test_import_fails_explicitly_when_identify_literal_is_altered(tmp_path, old, new):
    source = Path(C.__file__).read_text(encoding="utf-8")
    start = source.index("_IDENTIFY_RECIPE = (")
    end = source.index("_IDENTIFY_SHA256")
    assert source[start:end].count(old) == 1
    altered = source[:start] + source[start:end].replace(old, new) + source[end:]
    path = tmp_path / "cu_protocol_identify_tampered.py"
    path.write_text(altered, encoding="utf-8")
    spec = importlib.util.spec_from_file_location("pweh._cu_identify_tampered", path,
                                                  submodule_search_locations=None)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    try:
        with pytest.raises(RuntimeError, match="hash"):
            spec.loader.exec_module(module)
    finally:
        sys.modules.pop(spec.name, None)
    assert sys.modules["pweh.cu_protocol"] is C


@pytest.mark.parametrize("data,expected", [
    # AN10833 Rev 3.9 Fig. 1·Table 4: 정확 SAK. UID 크기·ATQA는 Classic 판정에 쓰지 않는다.
    (record(UID4, b"\x04\x00", 0x09), "mifare_classic_mini"),
    (record(UID4, b"\x04\x00", 0x08), "mifare_classic_1k"),
    (record(UID7, b"\x44\x00", 0x08), "mifare_classic_1k"),
    (record(UID4, b"\x02\x00", 0x18), "mifare_classic_4k"),
    (record(UID7, b"\x42\x00", 0x18), "mifare_classic_4k"),
    (record(UID4, b"\x04\x00", 0x19), "mifare_classic_2k"),
    (record(UID4, b"\x04\x00", 0x01), "mifare_classic_tnp3xxx"),
    # Table 4: MIFARE Plus SL2 2K 10h·4K 11h. §6.2의 Plus 거부 행이다.
    (record(UID4, b"\x04\x00", 0x10), "mifare_plus_sl2"),
    (record(UID4, b"\x02\x00", 0x11), "mifare_plus_sl2"),
    (record(UID7, b"\x44\x00", 0x10), "mifare_plus_sl2"),
    # Table 4·SAK coding: bit 0x20 = ISO/IEC 14443-4 (SmartMX 0x28/0x38 포함). ATS 유무와 무관하다.
    # firmware가 돌려주는 ATS는 CRC만 뺀 값이라 첫 바이트가 TL이다(rc522.c L816-L823).
    (record(UID7, b"\x44\x03", 0x20, b"\x06\x75\x77\x81\x02\x80"), "iso14443_4"),
    (record(UID4, b"\x04\x00", 0x20), "iso14443_4"),
    (record(UID4, b"\x04\x00", 0x28, b"\x01"), "iso14443_4"),
    (record(UID4, b"\x02\x00", 0x38), "iso14443_4"),
    (record(UID10, b"\x44\x00", 0x60), "iso14443_4"),
    (record(UID4, b"\x04\x00", 0x21), "iso14443_4"),
    # Type 2 문: 네 조건이 모두 맞아야 GET_VERSION 단계로 간다.
    (record(UID7, b"\x44\x00", 0x00), "type2"),
    (record(UID4, b"\x44\x00", 0x00), "other"),
    (record(UID10, b"\x44\x00", 0x00), "other"),
    (record(UID7, b"\x00\x44", 0x00), "other"),
    (record(UID7, b"\x04\x00", 0x00), "other"),
    (record(UID7, b"\x44\x00", 0x00, b"\x01"), "other"),
    # 표에 없는 값(RFU bit 0x02, 0x40/0x80 단독, Plus SL2 값에 다른 bit가 섞인 값 등)은 추측하지 않는다.
    (record(UID4, b"\x04\x00", 0x12), "other"),
    (record(UID4, b"\x04\x00", 0x90), "other"),
    (record(UID4, b"\x04\x00", 0x02), "other"),
    (record(UID4, b"\x04\x00", 0x04), "other"),
    (record(UID7, b"\x44\x00", 0x40), "other"),
    (record(UID4, b"\x04\x00", 0x88), "other"),
    (record(UID4, b"\x04\x00", 0x89), "other"),
])
def test_scan_record_classes(data, expected):
    scan = C.classify_cu_scan(C.CuFrame(2000, 0, data))
    assert scan.scan_class == expected
    assert scan.uid == data[1:1 + data[0]] and scan.atqa_msb == data[1 + data[0]:3 + data[0]][::-1]
    assert scan.sak == data[3 + data[0]] and scan.ats_length == data[4 + data[0]]
    assert scan.uid.hex() not in repr(scan) and "SYN" not in repr(scan)


@pytest.mark.parametrize("status,expected", [(0x01, "none"), (0x04, "multiple")])
def test_no_tag_and_collision_statuses_are_classified_without_identity(status, expected):
    scan = C.classify_cu_scan(C.CuFrame(2000, status, b""))
    assert scan.scan_class == expected
    assert (scan.uid, scan.atqa_msb, scan.sak, scan.ats_length) == (None, None, None, None)


@pytest.mark.parametrize("status,data", [
    (0x01, record()), (0x04, record()), (0x04, b"\x00"),
    # SAK 없음·BCC 오류·긴 ATS는 RF/anticollision 오류이며 분류로 추측하지 않고 terminal로 둔다.
    (0x02, b""), (0x05, b""), (0x08, b""), (0x03, b""), (0x06, b""), (0x07, b""),
    (0x60, b""), (0x66, b""), (0x67, b""), (0x68, b""), (0x68, record()),
    (0x00, b""), (0x00, b"\x00"), (0x00, b"\x05" + b"x" * 9), (0x00, record()[:-1]),
    (0x00, record() + b"x"), (0x00, record() * 2), (0x00, record(UID4, b"\x04\x00", 0x08) * 2),
    (0x00, record(ats=b"xy")[:-1]),
])
def test_other_scan_status_or_shape_is_malformed(status, data):
    failure(lambda: C.classify_cu_scan(C.CuFrame(2000, status, data)), "nfc_scan_invalid")


@pytest.mark.parametrize("value", [None, {"command": 2000, "status": 1, "data": b""},
                                   C.CuFrame(2010, 1, b""), C.CuFrame(1002, 0x68, b"\x01")])
def test_scan_classifier_requires_exact_scan_frame(value):
    failure(lambda: C.classify_cu_scan(value), "nfc_scan_invalid")


@pytest.mark.parametrize("version,family", sorted(VERSIONS.items()))
def test_exact_nxp_versions_and_single_bit_changes(version, family):
    raw = bytes.fromhex(version)
    result = C.classify_type2_version(C.CuFrame(2010, 0, raw))
    assert (result.family, result.version) == (family, raw)
    for index in range(8):
        changed = bytearray(raw)
        changed[index] ^= 0x80
        other = C.classify_type2_version(C.CuFrame(2010, 0, bytes(changed)))
        assert other.family == "type2_other_version" and other.version == bytes(changed)


@pytest.mark.parametrize("data", [b"\x00" * 8, bytes.fromhex("0004040101000b03"), bytes.fromhex("0004030101001103"),
                                  bytes.fromhex("0004030201010b03"), b"\xff" * 8])
def test_other_well_formed_eight_bytes_fall_back(data):
    # NTAG210/212·Ultralight AES·Ultralight Nano 등 이 표에 근거가 없는 값은 모두 같은 fallback이다.
    assert C.classify_type2_version(C.CuFrame(2010, 0, data)).family == "type2_other_version"


@pytest.mark.parametrize("status", [0x00, 0x01])
def test_no_get_version_response_is_ultralight_or_ultralight_c(status):
    # 0x00 빈 payload = 3B 미만 응답(4bit NAK), 0x01 = timeout. 원조 UL·UL C에는 GET_VERSION이 없다.
    result = C.classify_type2_version(C.CuFrame(2010, status, b""))
    assert (result.family, result.version) == ("ultralight_or_ultralight_c", None)


def test_crc_error_reply_is_unreadable_not_ultralight():
    # firmware는 check CRC 아래 3B 이상을 받았을 때만 0x03을 낸다(rc522.c L1639-L1658).
    # 응답이 있었으므로 GET_VERSION이 없는 원조 UL·UL C의 근거가 아니며 계열을 정하지 않는다.
    result = C.classify_type2_version(C.CuFrame(2010, 0x03, b""))
    assert (result.family, result.version) == ("type2_version_unreadable", None)
    assert C.HF_POLICIES["type2_version_unreadable"] == "attestation_required"


@pytest.mark.parametrize("status,data", [
    (0x00, b"\x0a"), (0x00, b"x" * 7), (0x00, b"x" * 9), (0x00, b"x" * 16), (0x01, b"\x00" * 8),
    (0x03, b"\x00"), (0x02, b""), (0x04, b""), (0x05, b""), (0x06, b""), (0x07, b""), (0x08, b""),
    (0x60, b""), (0x66, b""), (0x67, b""), (0x68, b""), (0x68, bytes.fromhex("0004040201000f03")),
])
def test_other_version_shapes_are_malformed(status, data):
    failure(lambda: C.classify_type2_version(C.CuFrame(2010, status, data)), "nfc_scan_invalid")


@pytest.mark.parametrize("value", [None, C.CuFrame(2000, 0, b"\x00" * 8), C.CuFrame(2011, 0, b"\x00" * 8)])
def test_version_classifier_requires_exact_raw_frame(value):
    failure(lambda: C.classify_type2_version(value), "nfc_scan_invalid")


@pytest.mark.parametrize("kwargs", [
    {"scan_class": "type2", "uid": None, "atqa_msb": None, "sak": None, "ats_length": None},
    {"scan_class": "none", "uid": UID7, "atqa_msb": b"\x00\x44", "sak": 0, "ats_length": 0},
    {"scan_class": "ntag213", "uid": UID7, "atqa_msb": b"\x00\x44", "sak": 0, "ats_length": 0},
    {"scan_class": "other", "uid": b"12345", "atqa_msb": b"\x00\x44", "sak": 0, "ats_length": 0},
    {"scan_class": "other", "uid": UID7, "atqa_msb": b"\x44", "sak": 0, "ats_length": 0},
    {"scan_class": "other", "uid": UID7, "atqa_msb": b"\x00\x44", "sak": True, "ats_length": 0},
    {"scan_class": "other", "uid": bytearray(UID7), "atqa_msb": b"\x00\x44", "sak": 0, "ats_length": 0},
])
def test_scan_value_constructor_is_closed(kwargs):
    failure(lambda: C.CuHfScan(**kwargs), "nfc_scan_invalid")


@pytest.mark.parametrize("family,version", [
    ("ntag213", None), ("ntag213", bytes.fromhex("0004040201001103")), ("type2_other_version", None),
    ("ultralight_or_ultralight_c", bytes.fromhex("0004040201000f03")), ("type2", None),
    ("type2_version_unreadable", bytes.fromhex("0004040201000f03")), ("mifare_plus_sl2", None),
    ("ntag213", bytes.fromhex("0004040201000f")),
])
def test_version_value_constructor_is_closed(family, version):
    failure(lambda: C.CuHfVersion(family, version), "nfc_scan_invalid")


@pytest.mark.parametrize("query,command", [(C.CuStatusQuery.BATTERY_INFO, 1025),
                                           (C.CuStatusQuery.ACTIVE_SLOT, 1018),
                                           (C.CuStatusQuery.HF14A_CONFIG, 2200)])
def test_status_getters_have_independent_golden_wire(query, command):
    packet = C.build_cu_status_query(query)
    assert packet == wire(command)
    frame, = C.CuDecoder().feed(packet)
    assert frame == C.CuFrame(command, 0, b"")
    assert tuple(C.STATUS_QUERIES) == (C.CuStatusQuery.BATTERY_INFO, C.CuStatusQuery.ACTIVE_SLOT,
                                       C.CuStatusQuery.HF14A_CONFIG)
    # 기존 reader 조회 enum은 바꾸지 않는다.
    assert tuple(q.value for q in C.CuQuery) == (1000, 1017, 1033, 1002, 2000)


@pytest.mark.parametrize("query", [None, 1025, "BATTERY_INFO", C.CuQuery.DEVICE_MODE, C.CuQuery.SCAN_14A])
def test_status_builder_rejects_other_values(query):
    failure(lambda: C.build_cu_status_query(query), "cu_protocol_invalid")


def status_replies(battery=b"\x0f\x3c\x3d", slot=b"\x02", config=b"\x00\x00\x00\x00"):
    return (C.CuFrame(1025, 0x68, battery), C.CuFrame(1018, 0x68, slot), C.CuFrame(2200, 0x68, config))


def test_status_parse_values_and_zero_based_slot():
    status = C.parse_cu_status(status_replies())
    assert (status.battery_mv, status.battery_percent, status.active_slot, status.hf14a_config_default) == (
        3900, 61, 2, True)
    # 부팅 직후 첫 측정 전에는 mV·percent가 0일 수 있다(형식상 유효).
    boot = C.parse_cu_status(status_replies(battery=b"\x00\x00\x00", slot=b"\x07"))
    assert (boot.battery_mv, boot.battery_percent, boot.active_slot) == (0, 0, 7)
    full = C.parse_cu_status(status_replies(battery=b"\xff\xff\x64", slot=b"\x00"))
    assert (full.battery_mv, full.battery_percent, full.active_slot) == (65535, 100, 0)
    for config in (b"\x01\x00\x00\x00", b"\x00\x02\x00\x00", b"\x00\x00\x01\x00", b"\x00\x00\x00\x02"):
        assert C.parse_cu_status(status_replies(config=config)).hf14a_config_default is False


@pytest.mark.parametrize("position,data", [
    (0, b""), (0, b"\x0f\x3c"), (0, b"\x0f\x3c\x3d\x04"), (0, b"\x0f\x3c\x65"), (0, b"\x0f\x3c\xff"),
    (1, b""), (1, b"\x08"), (1, b"\xff"), (1, b"\x00\x00"),
    (2, b""), (2, b"\x00\x00\x00"), (2, b"\x00" * 5), (2, b"\x03\x00\x00\x00"), (2, b"\x00\x00\x00\xff"),
])
def test_status_lengths_and_ranges_are_strict(position, data):
    replies = list(status_replies())
    replies[position] = replace(replies[position], data=data)
    failure(lambda: C.parse_cu_status(tuple(replies)), "cu_protocol_invalid")


@pytest.mark.parametrize("position", range(3))
@pytest.mark.parametrize("field,value", [("status", 0x00), ("status", 0x66), ("status", 0x67),
                                         ("status", 0x60), ("command", 1002)])
def test_status_each_envelope_checked(position, field, value):
    replies = list(status_replies())
    replies[position] = replace(replies[position], **{field: value})
    failure(lambda: C.parse_cu_status(tuple(replies)), "cu_protocol_invalid")


@pytest.mark.parametrize("kind", ["list", "missing", "extra", "reordered"])
def test_status_order_and_exact_tuple(kind):
    original = status_replies()
    values = {"list": list(original), "missing": original[:2], "extra": original + original[:1],
              "reordered": tuple(reversed(original))}
    failure(lambda: C.parse_cu_status(values[kind]), "cu_protocol_invalid")


@pytest.mark.parametrize("field,value", [("battery_mv", -1), ("battery_mv", 65536), ("battery_percent", 101),
                                         ("battery_percent", True), ("active_slot", 8), ("active_slot", -1),
                                         ("hf14a_config_default", 1)])
def test_status_value_constructor_is_closed(field, value):
    values = dict(battery_mv=3900, battery_percent=61, active_slot=0, hf14a_config_default=True)
    values[field] = value
    failure(lambda: C.CuDeviceStatus(**values), "cu_protocol_invalid")
