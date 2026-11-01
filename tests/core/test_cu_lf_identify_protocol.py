"""장치 없이 합성 wire로 CU LF 125 kHz 식별 recipe·고정 scan frame·응답 분류 경계를 검사한다.

기대값은 구현의 표를 읽지 않고 이 파일에 독립으로 다시 적는다. 근거는 docs/references/cu-lf-identify.md 의 표
(공식 v2.3.0 firmware 4e1a5b267b9ed33559e0e2c9dad61d61eaf64ba1 의 app_cmd.c·lf_reader_main.c·lf_*_data.c·tag_base_type.h)와 같다.
"""
from __future__ import annotations

from dataclasses import FrozenInstanceError
import hashlib
import importlib.util
import json
from pathlib import Path
import struct
import sys

import pytest

from pweh import cu_protocol as C

LF_SHA256 = "fefb6e77a90e0c5ebf255f378619313db848a26460efffdd19a86f599f582535"
# 송신 순서(숫자 순서가 아니다)와 명령·payload·0x40 성공 길이. EM410x 길이는 tag_type 표를 따른다.
ORDER = [3000, 3002, 3010, 3004, 3014, 3019, 3021]
SCANS = [
    ("em410x_scan", 3000, "", "em410x", None),
    ("hidprox_scan", 3002, "00", "hidprox", 16),
    ("ioprox_scan", 3010, "00", "ioprox", 16),
    ("viking_scan", 3004, "", "viking", 4),
    ("pac_scan", 3014, "", "pac", 8),
    ("jablotron_scan", 3019, "", "jablotron", 5),
    ("pyramid_scan", 3021, "", "pyramid", 16),
]
POLICIES = {"em410x": "refused", "hidprox": "refused", "ioprox": "refused", "viking": "refused",
            "pac": "refused", "jablotron": "refused", "pyramid": "refused", "none": "not_applicable"}
# tag_base_type.h L37-L41: 101 EM410X_16, 102 _32, 103 _64, 104 ELECTRA. 100(TAG_TYPE_EM410X)은 scan이 내지 않는다.
VARIANTS = {101: "em410x_16", 102: "em410x_32", 103: "em410x_64", 104: "em410x_electra"}
EM_ID = b"SYN05"
ELECTRA_ID = b"SYN05" + b"EPILOG08"


def wire(command, status=0, data=b""):
    """제품 encoder를 호출하지 않는 합성 frame 생성기."""
    header = struct.pack(">BBHHH", 0x11, 0xef, command, status, len(data))
    body = header + bytes(((256 - sum(header)) % 256,)) + data
    return body + bytes(((256 - sum(body)) % 256,))


def failure(call, code):
    with pytest.raises(C.CuProtocolError) as caught:
        call()
    assert caught.value.code == code and caught.value.data == {}
    return caught.value


def lf_recipe():
    """구현의 literal을 읽지 않고 LF 식별 recipe를 독립 dict로 다시 적는다."""
    return {
        "profile": "cu-lf125-identify-v2.3.0-v1",
        "firmware_commit": "4e1a5b267b9ed33559e0e2c9dad61d61eaf64ba1",
        "model": "chameleon-ultra", "app_version": "2.3", "git_version": "v2.3.0", "reader_mode": True,
        "commands": [1002] + ORDER,
        "scans": [{"name": name, "command": command, "payload": payload, "family": family, "found_length": length}
                  for name, command, payload, family, length in SCANS],
        "statuses": {"found": "40", "not_found": "41", "mode_error": "66"},
        "stop_at_first_found": True,
        "em410x_variants": {str(key): value for key, value in VARIANTS.items()},
        "em410x_lengths": {"101": 7, "102": 7, "103": 7, "104": 15},
        "policies": dict(POLICIES),
        "id_returned": False, "hid_format_returned": False, "authentication": False, "tag_writes": False,
        "lf_field_off_by_firmware": True,
        # 125 kHz 출입 ID는 솔트 지문도 전수 대입으로 되돌릴 수 있으므로 ID 파생 출력이 없다(지문 domain도 없다).
        "id_derived_outputs": "none",
    }


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False)


def test_lf_recipe_is_independently_pinned_and_outside_reader_registry():
    encoded = canonical(lf_recipe())
    assert hashlib.sha256(encoded.encode()).hexdigest() == LF_SHA256 == C.LF_IDENTIFY.profile_sha256
    assert C.LF_IDENTIFY.recipe == encoded and C.LF_IDENTIFY.profile == "cu-lf125-identify-v2.3.0-v1"
    assert (C.LF_IDENTIFY.firmware_commit, C.LF_IDENTIFY.app_version, C.LF_IDENTIFY.git_version) == (
        C.LIVE.firmware_commit, C.LIVE.app_version, C.LIVE.git_version)
    # reader 집합·기존 프로필 셋은 그대로이며 LF 프로필을 이름으로 찾을 수 없다.
    assert set(C.KNOWN) == {"cu-ntag21x-v2.2.0-v1", "cu-ntag21x-v2.3.0-v1"}
    assert C.known_reader_profile(C.LF_IDENTIFY.profile) is None
    assert C.LF_IDENTIFY.profile_sha256 not in (C.LEGACY_V220.profile_sha256, C.V230.profile_sha256,
                                                C.IDENTIFY.profile_sha256)
    assert C.IDENTIFY.profile_sha256 == "d420c720c19ab0f4923879f7d53917a82fb4775f8115e98360ea17f3cf27d90b"
    assert C.V230.profile_sha256 == "95132f6c6e6609854cf32af0f1644eb409147cf21060ba97e7eb3dee4d783eb5"
    assert C.LEGACY_V220.profile_sha256 == "d7e590dce5e5f9723cbff12aa0fcea46d5a9550e392a33cf7b0de5102dffd73c"
    with pytest.raises(FrozenInstanceError):
        C.LF_IDENTIFY.profile_sha256 = "0" * 64


def test_lf_tables_are_closed_and_match_section_6_2():
    assert dict(C.LF_POLICIES) == POLICIES and C.LF_FAMILIES == frozenset(POLICIES)
    # §6.2: 125 kHz 출입 계열은 모두 거부(ID 마스킹). 장난감·동물·시험 태그 증명 예외는 이 증분에 없다.
    assert {value for key, value in C.LF_POLICIES.items() if key != "none"} == {"refused"}
    assert C.LF_VARIANTS == frozenset(VARIANTS.values())
    assert [scan.value for scan in C.LF_SCAN_ORDER] == ORDER
    assert [C.LF_SCAN_NAMES[scan] for scan in C.LF_SCAN_ORDER] == [row[0] for row in SCANS]
    # LF는 ID 파생 출력이 없다: 지문 domain 상수가 없고 recipe가 그 사실을 고정한다. HF 식별 domain은 그대로다.
    assert not hasattr(C, "LF_DIGEST_DOMAIN")
    recipe = json.loads(C.LF_IDENTIFY.recipe)
    assert recipe["id_derived_outputs"] == "none" and "digest_domain" not in recipe
    assert C.HF_DIGEST_DOMAIN == b"pweh.cu-hf-identify/v1"
    with pytest.raises(TypeError):
        C.LF_POLICIES["em410x"] = "allowed"


@pytest.mark.parametrize("old,new", [
    ('"em410x":"refused"', '"em410x":"allowed"'),
    ('"command":3002,"family":"hidprox","found_length":16,"name":"hidprox_scan","payload":"00"',
     '"command":3002,"family":"hidprox","found_length":16,"name":"hidprox_scan","payload":""'),
    ('"tag_writes":false', '"tag_writes":true'),
    ('"id_derived_outputs":"none"', '"id_derived_outputs":"digest"'),
])
def test_import_fails_explicitly_when_lf_literal_is_altered(tmp_path, old, new):
    source = Path(C.__file__).read_text(encoding="utf-8")
    start = source.index("_LF_IDENTIFY_RECIPE = (")
    end = source.index("_LF_IDENTIFY_SHA256")
    block = source[start:end]
    # literal은 여러 줄로 나뉘므로 줄 이음을 지운 문자열에서 찾고 같은 위치를 바꾼다.
    joined = "".join(part.strip()[1:-1] for part in block.splitlines()[1:-1])
    assert joined == C.LF_IDENTIFY.recipe and joined.count(old) == 1
    altered = source[:start] + '_LF_IDENTIFY_RECIPE = (\n    ' + repr(joined.replace(old, new)) + '\n)\n' + source[end:]
    path = tmp_path / "cu_protocol_lf_tampered.py"
    path.write_text(altered, encoding="utf-8")
    spec = importlib.util.spec_from_file_location("pweh._cu_lf_tampered", path, submodule_search_locations=None)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    try:
        with pytest.raises(RuntimeError, match="hash"):
            spec.loader.exec_module(module)
    finally:
        sys.modules.pop(spec.name, None)
    assert sys.modules["pweh.cu_protocol"] is C


@pytest.mark.parametrize("change", [
    {"id_derived_outputs": "digest"},
    {"id_derived_outputs": "none", "digest_domain": "pweh.cu-lf-identify/v1"},
    {"digest_domain": "pweh.cu-lf-identify/v1"},
])
def test_rehashed_recipe_with_id_derived_output_is_rejected(change):
    """hash를 함께 고쳐도 지문 domain이나 ID 파생 출력을 되살린 recipe는 분류표 검사가 막는다."""
    recipe = lf_recipe()
    recipe.update(change)
    if "id_derived_outputs" not in change:
        recipe.pop("id_derived_outputs")
    encoded = canonical(recipe)
    profile = C._frozen_profile(encoded, hashlib.sha256(encoded.encode()).hexdigest(), b"\x02\x03")
    with pytest.raises(RuntimeError, match="닫힌 관계"):
        C._lf_tables(profile)
    # 같은 경로로 만든 원래 recipe는 통과하므로 위 거부는 바꾼 키 때문이다.
    original = canonical(lf_recipe())
    assert C._lf_tables(C._frozen_profile(original, LF_SHA256, b"\x02\x03"))[0] == C.LF_SCAN_SPECS


@pytest.mark.parametrize("name,command,payload,family,length", SCANS)
def test_each_lf_scan_has_independent_golden_wire(name, command, payload, family, length):
    scan = C.CuLfScan(command)
    packet = C.build_lf_scan(scan)
    assert packet == wire(command, 0, bytes.fromhex(payload))
    frame, = C.CuDecoder().feed(packet)
    assert frame == C.CuFrame(command, 0, bytes.fromhex(payload))
    assert C.LF_SCAN_NAMES[scan] == name and C.LF_SCAN_SPECS[scan].family == family


@pytest.mark.parametrize("value", [None, 3000, "EM410X", C.CuQuery.DEVICE_MODE, C.CuStatusQuery.BATTERY_INFO])
def test_lf_builder_rejects_other_values(value):
    failure(lambda: C.build_lf_scan(value), "cu_protocol_invalid")


def test_forbidden_lf_ids_cannot_be_encoded():
    # T55xx 복제·블록 쓰기, EM4x05(LOGIN), 스니프, 원시 ADC, ioProx 변환, emulator ID 명령(data_cmd.h).
    for command in (3001, 3003, 3005, 3006, 3007, 3008, 3009, 3011, 3012, 3013, 3015, 3016, 3018, 3020,
                    3030, 3031, 3032, *range(5000, 5014)):
        failure(lambda: C._encode(command, b""), "cu_protocol_invalid")


@pytest.mark.parametrize("command", ORDER)
def test_not_found_is_classified_without_identity(command):
    reply = C.classify_lf_scan(C.CuLfScan(command), C.CuFrame(command, 0x41, b""))
    assert (reply.found, reply.family, reply.variant, reply.id_bytes) == (False, None, None, None)


@pytest.mark.parametrize("tag_type,variant", sorted(VARIANTS.items()))
def test_em410x_variants_and_exact_lengths(tag_type, variant):
    ident = ELECTRA_ID if tag_type == 104 else EM_ID
    data = tag_type.to_bytes(2, "big") + ident
    reply = C.classify_lf_scan(C.CuLfScan.EM410X, C.CuFrame(3000, 0x40, data))
    assert (reply.found, reply.family, reply.variant, reply.id_bytes) == (True, "em410x", variant, ident)
    assert ident.hex() not in repr(reply) and "SYN" not in repr(reply)


@pytest.mark.parametrize("command,length,family", [(3002, 16, "hidprox"), (3010, 16, "ioprox"), (3004, 4, "viking"),
                                                   (3014, 8, "pac"), (3019, 5, "jablotron"), (3021, 16, "pyramid")])
def test_other_found_families_need_exact_length(command, length, family):
    data = bytes(range(0x30, 0x30 + length))
    reply = C.classify_lf_scan(C.CuLfScan(command), C.CuFrame(command, 0x40, data))
    assert (reply.found, reply.family, reply.variant, reply.id_bytes) == (True, family, None, data)
    assert data.hex() not in repr(reply)
    for bad in (data[:-1], data + b"\0", b""):
        failure(lambda: C.classify_lf_scan(C.CuLfScan(command), C.CuFrame(command, 0x40, bad)), "nfc_scan_invalid")


@pytest.mark.parametrize("data", [
    # tag_type 범위 밖(100은 scan이 내지 않는 기본 type, 105 이상은 표에 없다).
    b"\x00\x64" + EM_ID, b"\x00\x69" + EM_ID, b"\x00\x00" + EM_ID, b"\x01\x65" + EM_ID,
    # Electra 길이 불일치와 일반 변형의 Electra 길이.
    b"\x00\x68" + EM_ID, b"\x00\x65" + ELECTRA_ID, b"\x00\x67" + EM_ID + b"\0",
    b"\x00\x68" + ELECTRA_ID + b"\0", b"\x00\x65", b"\x00", b"",
])
def test_em410x_tag_type_or_length_mismatch_is_malformed(data):
    failure(lambda: C.classify_lf_scan(C.CuLfScan.EM410X, C.CuFrame(3000, 0x40, data)), "nfc_scan_invalid")


@pytest.mark.parametrize("command", ORDER)
def test_mode_error_is_reader_required(command):
    failure(lambda: C.classify_lf_scan(C.CuLfScan(command), C.CuFrame(command, 0x66, b"")), "cu_reader_required")


@pytest.mark.parametrize("command", ORDER)
@pytest.mark.parametrize("status,data", [
    (0x41, b"\x00"), (0x66, b"\x00"), (0x42, b""), (0x00, b""), (0x01, b""), (0x60, b""), (0x67, b""),
    (0x68, b""), (0x68, b"\x00" * 16), (0x00, b"\x00" * 16),
])
def test_other_status_or_shape_is_malformed(command, status, data):
    failure(lambda: C.classify_lf_scan(C.CuLfScan(command), C.CuFrame(command, status, data)), "nfc_scan_invalid")


@pytest.mark.parametrize("scan,frame", [
    (C.CuLfScan.EM410X, C.CuFrame(3002, 0x41, b"")), (C.CuLfScan.HIDPROX, C.CuFrame(3000, 0x41, b"")),
    (C.CuLfScan.PYRAMID, C.CuFrame(2000, 0x41, b"")), (3000, C.CuFrame(3000, 0x41, b"")),
    (C.CuLfScan.EM410X, None), (C.CuLfScan.EM410X, {"command": 3000, "status": 0x41, "data": b""}),
])
def test_classifier_requires_exact_scan_and_frame(scan, frame):
    failure(lambda: C.classify_lf_scan(scan, frame), "nfc_scan_invalid")


@pytest.mark.parametrize("kwargs", [
    {"scan": C.CuLfScan.EM410X, "found": False, "family": "em410x", "variant": None, "id_bytes": None},
    {"scan": C.CuLfScan.EM410X, "found": True, "family": "em410x", "variant": None, "id_bytes": EM_ID},
    {"scan": C.CuLfScan.EM410X, "found": True, "family": "em410x", "variant": "em410x_electra", "id_bytes": EM_ID},
    {"scan": C.CuLfScan.EM410X, "found": True, "family": "hidprox", "variant": "em410x_16", "id_bytes": EM_ID},
    {"scan": C.CuLfScan.VIKING, "found": True, "family": "viking", "variant": "em410x_16", "id_bytes": b"1234"},
    {"scan": C.CuLfScan.VIKING, "found": True, "family": "viking", "variant": None, "id_bytes": b"123"},
    {"scan": C.CuLfScan.VIKING, "found": True, "family": "viking", "variant": None, "id_bytes": bytearray(b"1234")},
    {"scan": C.CuLfScan.VIKING, "found": 1, "family": "viking", "variant": None, "id_bytes": b"1234"},
    {"scan": 3004, "found": True, "family": "viking", "variant": None, "id_bytes": b"1234"},
])
def test_reply_constructor_is_closed(kwargs):
    failure(lambda: C.CuLfReply(**kwargs), "nfc_scan_invalid")
