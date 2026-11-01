"""장치 없이 독립 합성 wire로 고정 CU 프레임·계열·terminal 경계를 검사한다."""
from __future__ import annotations

from dataclasses import FrozenInstanceError, replace
from enum import Enum, IntEnum
import hashlib
import importlib.util
import json
from pathlib import Path
import struct
import sys
import traceback

import pytest

from pweh import cu_protocol as C

PRIVATE = "SYNTHETIC_CU_PRIVATE"
UID = b"SYNTH01"
# 공식 v2.3.0에서 새로 생겼거나 남아 있는 인증·쓰기·키·BLE PIN·고정 식별자·모드·field 직접 제어 명령.
DENIED = frozenset((1001, 1011, 1012, 1031, 1034, 2016, 2018, 2019, 2021, 2022, 2100, 2101, 3021))
LEGACY_READER = {"profile": "cu-ntag21x-v2.2.0-v1",
                 "profile_sha256": "d7e590dce5e5f9723cbff12aa0fcea46d5a9550e392a33cf7b0de5102dffd73c",
                 "firmware_commit": "f349dbeeaa315776b272ae8fb851cc4042d55f07",
                 "app_version": "2.2", "git_version": "v2.2.0"}
LIVE_READER = {"profile": "cu-ntag21x-v2.3.0-v1",
               "profile_sha256": "95132f6c6e6609854cf32af0f1644eb409147cf21060ba97e7eb3dee4d783eb5",
               "firmware_commit": "4e1a5b267b9ed33559e0e2c9dad61d61eaf64ba1",
               "app_version": "2.3", "git_version": "v2.3.0"}


def wire(command=2010, status=0, data=b""):
    """제품 encoder를 호출하지 않는 합성 응답 생성기."""
    header = struct.pack(">BBHHH", 0x11, 0xef, command, status, len(data))
    body = header + bytes(((256 - sum(header)) % 256,)) + data
    return body + bytes(((256 - sum(body)) % 256,))


def failure(call, code="cu_protocol_invalid", decoder=None):
    with pytest.raises(C.CuProtocolError) as caught:
        call()
    exc = caught.value
    assert exc.code == code and exc.data == {}
    assert PRIVATE not in str(exc) + json.dumps(exc.to_dict()) + "".join(traceback.format_exception(exc))
    if decoder is not None:
        assert decoder.terminal is True and decoder.buffered_bytes == 0
        with pytest.raises(C.CuProtocolError, match="cu_protocol_invalid"):
            decoder.feed(b"")
    return exc


def device_replies(app=b"\x02\x03", git=b"v2.3.0"):
    return (C.CuFrame(1000, 0x68, app), C.CuFrame(1017, 0x68, git),
            C.CuFrame(1033, 0x68, b"\x00"), C.CuFrame(1002, 0x68, b"\x01"))


def scan_data(uid=UID, atqa=b"\x44\x00", sak=b"\x00", ats=b""):
    return bytes((len(uid),)) + uid + atqa + sak + bytes((len(ats),)) + ats


def canonical(recipe):
    return json.dumps(recipe, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False)


def legacy_recipe():
    # 구현의 literal을 읽지 않고 이전 증분의 _RECIPE를 독립 dict로 다시 적는다.
    return {
        "profile": "cu-ntag21x-v2.2.0-v1",
        "firmware_commit": "f349dbeeaa315776b272ae8fb851cc4042d55f07",
        "model": "chameleon-ultra", "app_version": "2.2", "git_version": "v2.2.0",
        "reader_mode": True, "queries": [1000, 1017, 1033, 1002], "scan_command": 2000,
        "raw_command": 2010, "rf_timeout_ms": 100, "crc_append": True, "crc_check": True,
        "uid_length": 7, "atqa_msb": "0044", "sak": "00", "ats_length": 0,
        "versions": ["0004040201000f03", "0004040201001103", "0004040201001303"],
        "probe_read_pages": [0, 1], "page_attribution_bytes": 4, "total_pages": [45, 135, 231],
    }


def live_recipe():
    recipe = legacy_recipe()
    recipe.update(
        profile="cu-ntag21x-v2.3.0-v1", firmware_commit="4e1a5b267b9ed33559e0e2c9dad61d61eaf64ba1",
        app_version="2.3", git_version="v2.3.0",
        raw_options={"version": "f4", "first_read": "fc", "read": "ec", "last_read": "e4"},
        activations={"probe": [["version"], ["first_read", "last_read"]],
                     "read": [["version"], ["first_read", "read", "last_read"]]},
        version_refusals=["00-empty", "00-other8", "01-empty", "03-empty"])
    return recipe


@pytest.mark.parametrize("row,recipe,reader,wire", [
    ("LEGACY_V220", legacy_recipe, LEGACY_READER, b"\x02\x02"),
    ("V230", live_recipe, LIVE_READER, b"\x02\x03"),
])
def test_both_profile_recipes_are_independently_pinned(row, recipe, reader, wire):
    profile = getattr(C, row)
    encoded = canonical(recipe())
    assert hashlib.sha256(encoded.encode()).hexdigest() == reader["profile_sha256"]
    assert profile.recipe == encoded and profile.app_wire == wire
    assert profile.reader() == reader and profile.reader() is not profile.reader()
    assert (profile.profile, profile.profile_sha256, profile.firmware_commit,
            profile.app_version, profile.git_version) == tuple(reader[key] for key in C.READER_FIELDS)
    with pytest.raises(FrozenInstanceError):
        profile.profile_sha256 = "0" * 64
    assert (C.MAX_DATA_BYTES, C.MAX_FRAME_BYTES, C.MAX_BUFFER_BYTES) == (512, 522, 1044)


def test_registry_is_closed_live_is_v230_and_bare_pins_removed():
    assert C.LIVE is C.V230 and C.LIVE.profile == "cu-ntag21x-v2.3.0-v1"
    assert dict(C.KNOWN) == {"cu-ntag21x-v2.2.0-v1": C.LEGACY_V220, "cu-ntag21x-v2.3.0-v1": C.V230}
    with pytest.raises(TypeError):
        C.KNOWN["cu-ntag21x-v2.4.0-v1"] = C.V230
    for name in ("PROFILE", "PROFILE_SHA256", "FIRMWARE_COMMIT", "FIRMWARE_VERSION",
                 "FIRMWARE_GIT_VERSION", "_RECIPE"):
        assert not hasattr(C, name)


@pytest.mark.parametrize("name", [None, 1, b"cu-ntag21x-v2.3.0-v1", ["cu-ntag21x-v2.3.0-v1"],
    {"cu-ntag21x-v2.3.0-v1": 1}, "", "cu-ntag21x-v2.3.0", "cu-ntag21x-v2.3.0-v", "cu-ntag21x-v2.3.0-v1 ",
    " cu-ntag21x-v2.3.0-v1", "cu-ntag21x-v2.3.0-v1\n", "CU-NTAG21X-V2.3.0-V1", "cu-ntag21x-v2.3.1-v1",
    "cu-ntag21x-v2.2.0-v2", "cu-ntag21x-v2.3.0-14-g4c5bc2c-v1", "cu-ntag21x", "cu-ntag21x-v2",
    LIVE_READER["profile_sha256"], LEGACY_READER["firmware_commit"], "v2.3.0", "2.3"])
def test_known_profile_lookup_is_exact_str_key_only(name):
    assert C.known_reader_profile(name) is None


def test_known_profile_lookup_rejects_str_subclass_and_returns_exact_rows():
    class Name(str):
        def __eq__(self, other):
            return True

        __hash__ = str.__hash__

    assert C.known_reader_profile(Name("cu-ntag21x-v2.3.0-v1")) is None
    assert C.known_reader_profile("cu-ntag21x-v2.3.0-v1") is C.V230
    assert C.known_reader_profile("cu-ntag21x-v2.2.0-v1") is C.LEGACY_V220


@pytest.mark.parametrize("field,value", [
    ("profile", "cu-ntag21x-v2.3.0-v1"), ("profile_sha256", LIVE_READER["profile_sha256"]),
    ("firmware_commit", LIVE_READER["firmware_commit"]), ("app_version", "2.3"),
    ("app_wire", b"\x02\x03"), ("git_version", "v2.3.0"), ("recipe", canonical(live_recipe())),
    ("recipe", canonical(legacy_recipe()) + " "), ("profile_sha256", None), ("app_wire", bytearray(b"\x02\x02")),
])
def test_profile_rows_cannot_be_cross_paired(field, value):
    failure(lambda: replace(C.LEGACY_V220, **{field: value}))
    # 반대 방향은 같은 field에 legacy 값을 넣는다. 나머지 값과 맞지 않으면 생성하지 않는다.
    swapped = {"profile": "cu-ntag21x-v2.2.0-v1", "profile_sha256": LEGACY_READER["profile_sha256"],
               "firmware_commit": LEGACY_READER["firmware_commit"], "app_version": "2.2",
               "app_wire": b"\x02\x02", "git_version": "v2.2.0",
               "recipe": canonical(legacy_recipe())}[field]
    failure(lambda: replace(C.V230, **{field: swapped}))


def test_frozen_profile_helper_rejects_tampered_or_noncanonical_recipe():
    text = canonical(legacy_recipe())
    sha = LEGACY_READER["profile_sha256"]
    assert C._frozen_profile(text, sha, b"\x02\x02") == C.LEGACY_V220
    for bad_text, bad_sha in ((text.replace('"2.2"', '"2.3"'), sha), (text + " ", sha), (text, "0" * 64),
                              (json.dumps(legacy_recipe(), sort_keys=True), None)):
        with pytest.raises(RuntimeError):
            C._frozen_profile(bad_text, bad_sha, b"\x02\x02")
    pretty = json.dumps(legacy_recipe(), sort_keys=True)
    with pytest.raises(RuntimeError):
        C._frozen_profile(pretty, hashlib.sha256(pretty.encode()).hexdigest(), b"\x02\x02")


@pytest.mark.parametrize("old,new", [
    ('"app_version":"2.2"', '"app_version":"2.3"'),
    ('"rf_timeout_ms":100', '"rf_timeout_ms":101'),
    ('"profile":"cu-ntag21x-v2.2.0-v1"', '"profile":"cu-ntag21x-v2.3.0-v1"'),
])
def test_import_fails_explicitly_when_legacy_recipe_literal_is_altered(tmp_path, old, new):
    source = Path(C.__file__).read_text(encoding="utf-8")
    start = source.index("_LEGACY_V220_RECIPE = (")
    end = source.index("_LEGACY_V220_SHA256")
    assert source[start:end].count(old) == 1
    altered = source[:start] + source[start:end].replace(old, new) + source[end:]
    path = tmp_path / "cu_protocol_tampered.py"
    path.write_text(altered, encoding="utf-8")
    # 원본 모듈을 reload하지 않고 별도 이름으로 실행해 enum·오류 class 동일성을 보존한다.
    spec = importlib.util.spec_from_file_location("pweh._cu_protocol_tampered", path,
                                                  submodule_search_locations=None)
    module = importlib.util.module_from_spec(spec)
    # dataclass 처리는 실행 중 모듈 등록을 요구한다. 별도 이름만 잠시 두고 반드시 제거한다.
    sys.modules[spec.name] = module
    try:
        with pytest.raises(RuntimeError, match="hash"):
            spec.loader.exec_module(module)
    finally:
        sys.modules.pop(spec.name, None)
    assert spec.name not in sys.modules and sys.modules["pweh.cu_protocol"] is C
    assert C.LEGACY_V220.profile_sha256 == LEGACY_READER["profile_sha256"]


@pytest.mark.parametrize("query,expected", [
    (C.CuQuery.APP_VERSION, "11ef03e8000000001500"),
    (C.CuQuery.GIT_VERSION, "11ef03f9000000000400"),
    (C.CuQuery.DEVICE_MODEL, "11ef040900000000f300"),
    (C.CuQuery.DEVICE_MODE, "11ef03ea000000001300"),
    (C.CuQuery.SCAN_14A, "11ef07d0000000002900"),
])
def test_fixed_queries_have_independent_golden_wire(query, expected):
    assert C.build_cu_query(query) == bytes.fromhex(expected)
    frame, = C.CuDecoder().feed(bytes.fromhex(expected))
    assert frame == C.CuFrame(query.value, 0, b"")


class OtherQuery(Enum):
    APP = 1000


class NumberQuery(IntEnum):
    APP = 1000


@pytest.mark.parametrize("query", [None, True, False, 1000, "APP_VERSION", "1000", b"1000",
                                  OtherQuery.APP, NumberQuery.APP, C.NtagFamily.NTAG213])
def test_query_rejects_bare_numbers_and_other_enums(query):
    failure(lambda: C.build_cu_query(query))


def test_version_options_and_crc_are_fixed():
    # GET_VERSION은 f4(keep=0) 단독 activation 하나만 만들 수 있다. owner 시험이 실제 송신 option을 따로 고정한다.
    expected = "11ef07da0000000619f4006400086040"
    assert C.build_ntag_version(keep_field=False) == bytes.fromhex(expected)
    frame, = C.CuDecoder().feed(bytes.fromhex(expected))
    assert frame.command == 2010 and frame.status == 0
    assert frame.data == b"\xf4\x00\x64\x00\x08\x60"


def test_version_never_builds_keep_field_fc_frame():
    # fc GET_VERSION은 실패 시 HF field를 켜 둔 채 남기는 결함 recipe다. builder 수준에서 막는다.
    failure(lambda: C.build_ntag_version(keep_field=True))


@pytest.mark.parametrize("family,total,version", [
    (C.NtagFamily.NTAG213, 45, "0004040201000f03"),
    (C.NtagFamily.NTAG215, 135, "0004040201001103"),
    (C.NtagFamily.NTAG216, 231, "0004040201001303"),
])
def test_family_properties_and_all_read_boundaries(family, total, version):
    assert family.family == "ntag" + str(family.value)
    assert family.pages_total == total and family.mifare_version == bytes.fromhex(version)
    assert not isinstance(family, int)
    packet = C.build_ntag_read(family, 0, last=False, select=True)
    assert packet == wire(2010, 0, b"\xfc\x00\x64\x00\x10\x30\x00")
    for page in (1, 2, total - 1):
        for last in (False, True):
            packet = C.build_ntag_read(family, page, last=last)
            expected = bytes((0xe4 if last else 0xec,)) + b"\x00\x64\x00\x10\x30" + bytes((page,))
            assert packet == wire(2010, 0, expected)
            frame, = C.CuDecoder().feed(packet)
            assert frame.data == expected and len(frame.data) == 7
    failure(lambda: C.build_ntag_read(family, total, last=True))
    # page0은 새 activation의 첫 READ이므로 선택 없이 만들 수 없다.
    failure(lambda: C.build_ntag_read(family, 0, last=False))
    failure(lambda: C.build_ntag_read(family, 0, last=True))
    failure(lambda: C.build_ntag_read(family, 0, last=True, select=True))
    for page in (1, total - 1):
        failure(lambda: C.build_ntag_read(family, page, last=False, select=True))
        failure(lambda: C.build_ntag_read(family, page, last=True, select=True))
    with pytest.raises(AttributeError):
        family.pages_total = 1


def test_read_phase_has_distinct_probe_and_fullread_admission_wire():
    # 제품 encoder를 쓰지 않고 손으로 계산한 golden wire. READ0은 새 선택(fc)이다.
    assert C.build_ntag_read(C.NtagFamily.NTAG213, 0, last=False, select=True) == bytes.fromhex(
        "11ef07da0000000718fc00640010300060")
    assert C.build_ntag_read(C.NtagFamily.NTAG213, 1, last=True) == bytes.fromhex(
        "11ef07da0000000718e400640010300177")
    assert C.build_ntag_read(C.NtagFamily.NTAG213, 1, last=False) == bytes.fromhex(
        "11ef07da0000000718ec0064001030016f")
    assert C.build_ntag_version(keep_field=False) == bytes.fromhex("11ef07da0000000619f4006400086040")


@pytest.mark.parametrize("value", [None, 0, 1, 1.0, "true", b"true", [], object()])
def test_phase_options_are_exact_bools(value):
    failure(lambda: C.build_ntag_version(keep_field=value))
    failure(lambda: C.build_ntag_read(C.NtagFamily.NTAG213, 1, last=value))
    failure(lambda: C.build_ntag_read(C.NtagFamily.NTAG213, 0, last=False, select=value))


@pytest.mark.parametrize("value", [None, True, False, -1, 1.0, 230.0, "0", b"0", 256, 10 ** 400])
def test_page_is_exact_bounded_int(value):
    failure(lambda: C.build_ntag_read(C.NtagFamily.NTAG216, value, last=False))


@pytest.mark.parametrize("value", [None, True, 213, "ntag213", "NTAG213", OtherQuery.APP])
def test_read_family_is_closed_enum(value):
    failure(lambda: C.build_ntag_read(value, 0, last=False))


@pytest.mark.parametrize("data", [b"", b"\x11\xef\x00", bytes(range(256)) * 2])
def test_decoder_every_split_and_single_byte_stream(data):
    packet = wire(2010, 0xffff, data)
    expected = C.CuFrame(2010, 0xffff, data)
    for split in range(len(packet) + 1):
        decoder = C.CuDecoder()
        first = decoder.feed(packet[:split])
        second = decoder.feed(packet[split:])
        assert first + second == (expected,)
        assert decoder.buffered_bytes == 0 and not decoder.terminal
    decoder = C.CuDecoder()
    frames = tuple(frame for byte in packet for frame in decoder.feed(bytes((byte,))))
    assert frames == (expected,) and decoder.buffered_bytes == 0


def test_decoder_two_max_frames_and_partial_tail():
    one = wire(2010, 0, bytes(range(256)) * 2)
    decoder = C.CuDecoder()
    assert len(one) == C.MAX_FRAME_BYTES
    assert len(decoder.feed(one + one)) == 2 and decoder.buffered_bytes == 0
    short = wire(1002, 0x68, b"\x01")
    decoder = C.CuDecoder()
    assert len(decoder.feed(short + short + short[:8])) == 2
    assert decoder.buffered_bytes == 8 and not decoder.terminal
    assert decoder.feed(b"") == () and decoder.buffered_bytes == 8
    assert decoder.feed(short[8:]) == (C.CuFrame(1002, 0x68, b"\x01"),)


def test_third_complete_frame_is_terminal_and_never_partially_returned():
    decoder = C.CuDecoder()
    packet = wire()
    failure(lambda: decoder.feed(packet * 3), decoder=decoder)


@pytest.mark.parametrize("data", [None, bytearray(b"x"), memoryview(b"x"), PRIVATE, 1, True,
                                 b"x" * 1045])
def test_decoder_exact_bytes_and_feed_cap(data):
    decoder = C.CuDecoder()
    failure(lambda: decoder.feed(data), decoder=decoder)


def test_buffer_plus_feed_cap_checked_before_parsing_or_allocation():
    decoder = C.CuDecoder()
    decoder.feed(b"\x11")
    failure(lambda: decoder.feed(b"x" * 1044), decoder=decoder)


def test_overlarge_declared_data_fails_at_header_without_waiting_for_body():
    decoder = C.CuDecoder()
    packet = wire(2010, 0, b"x" * 513)
    failure(lambda: decoder.feed(packet[:9]), decoder=decoder)


@pytest.mark.parametrize("position", [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12])
def test_every_wire_section_is_checked(position):
    packet = bytearray(wire(2010, 0, b"abc"))
    packet[position] ^= 1
    decoder = C.CuDecoder()
    failure(lambda: decoder.feed(bytes(packet)), decoder=decoder)


@pytest.mark.parametrize("first,second", [(0, 1), (1, 8), (8, 9)])
def test_total_lrc_cannot_hide_independently_corrupt_headers(first, second):
    packet = bytearray(wire(2010, 0, b"abc"))
    packet[first] = (packet[first] + 1) % 256
    packet[second] = (packet[second] - 1) % 256
    assert sum(packet) % 256 == 0
    decoder = C.CuDecoder()
    failure(lambda: decoder.feed(bytes(packet)), decoder=decoder)


@pytest.mark.parametrize("bad", [b"junk", b"\x00", b"\x11\x00", wire() + b"junk",
                               wire() + wire() + b"\x00"])
def test_no_junk_skip_resynchronization_or_prefix_success(bad):
    decoder = C.CuDecoder()
    failure(lambda: decoder.feed(bad), decoder=decoder)


@pytest.mark.parametrize("partial", [b"", b"\x11", wire(2010, 0, b"abc")[:-1]])
def test_eof_is_always_terminal_and_abort_is_idempotent(partial):
    decoder = C.CuDecoder()
    assert decoder.feed(partial) == ()
    failure(decoder.eof, decoder=decoder)
    assert decoder.abort() is None and decoder.abort() is None
    assert decoder.terminal and decoder.buffered_bytes == 0
    failure(decoder.eof, decoder=decoder)


def test_decoder_status_properties_are_read_only():
    decoder = C.CuDecoder()
    with pytest.raises(AttributeError):
        decoder.buffered_bytes = 4
    with pytest.raises(AttributeError):
        decoder.terminal = False
    decoder.abort()
    failure(lambda: decoder.feed(wire()), decoder=decoder)


@pytest.mark.parametrize("field,value", [
    ("command", -1), ("command", 65536), ("command", True), ("command", 1.0),
    ("command", NumberQuery.APP), ("command", PRIVATE), ("status", -1), ("status", 65536),
    ("status", False), ("status", 0.0), ("data", bytearray(b"x")), ("data", memoryview(b"x")),
    ("data", PRIVATE), ("data", None), ("data", b"x" * 513),
])
def test_frame_rejects_invalid_types_without_raw_error(field, value):
    values = {"command": 1, "status": 0, "data": b""}
    values[field] = value
    failure(lambda: C.CuFrame(**values))


def test_private_frames_identity_and_device_are_frozen():
    frame = C.CuFrame(0, 65535, PRIVATE.encode())
    identity = C.CuScanIdentity(UID, b"\x00\x44", b"\x00")
    assert PRIVATE not in repr(frame) and UID.decode() not in repr(identity)
    with pytest.raises(FrozenInstanceError):
        frame.data = b"other"
    with pytest.raises(FrozenInstanceError):
        identity.uid = b"other01"
    device = C.parse_cu_device(device_replies())
    assert (device.model, device.app_version, device.git_version, device.reader_mode) == (
        "chameleon-ultra", "2.3", "v2.3.0", True)
    with pytest.raises(FrozenInstanceError):
        device.reader_mode = False


@pytest.mark.parametrize("field,value", [("model", PRIVATE), ("model", 0), ("app_version", "2.2"),
                                       ("app_version", "2.4"), ("git_version", "v2.2.0"),
                                       ("git_version", "v2.3.0-14-g4c5bc2c"), ("git_version", "v2.3.0-dirty"),
                                       ("reader_mode", 1), ("reader_mode", False)])
def test_device_constructor_is_closed(field, value):
    assert C.CuDevice("chameleon-ultra", "2.3", "v2.3.0", True).git_version == "v2.3.0"
    values = dict(model="chameleon-ultra", app_version="2.3", git_version="v2.3.0", reader_mode=True)
    values[field] = value
    failure(lambda: C.CuDevice(**values))


@pytest.mark.parametrize("field,value", [("uid", b"1234"), ("uid", "1234567"),
                                       ("uid", bytearray(UID)), ("atqa_msb", b"\x44\x00"),
                                       ("atqa_msb", bytearray(b"\x00\x44")), ("sak", b"\x08"),
                                       ("sak", 0), ("sak", b"")])
def test_identity_constructor_cannot_add_unvalidated_shapes(field, value):
    values = dict(uid=UID, atqa_msb=b"\x00\x44", sak=b"\x00")
    values[field] = value
    failure(lambda: C.CuScanIdentity(**values), "nfc_scan_invalid")


@pytest.mark.parametrize("kind", ["list", "generator", "dict", "missing", "extra", "reordered", "duplicate"])
def test_device_query_order_and_exact_tuple(kind):
    original = device_replies()
    values = {
        "list": list(original), "generator": iter(original), "dict": dict(enumerate(original)),
        "missing": original[:3], "extra": original + original[:1],
        "reordered": tuple(reversed(original)), "duplicate": original[:3] + original[:1],
    }
    failure(lambda: C.parse_cu_device(values[kind]))


@pytest.mark.parametrize("position", range(4))
@pytest.mark.parametrize("field,value", [("command", 65535), ("status", 0), ("status", 0x69)])
def test_device_each_envelope_checked(position, field, value):
    replies = list(device_replies())
    replies[position] = replace(replies[position], **{field: value})
    failure(lambda: C.parse_cu_device(tuple(replies)))


@pytest.mark.parametrize("position,data,code", [
    (0, b"", "cu_protocol_invalid"), (0, b"\x02", "cu_protocol_invalid"),
    (0, b"\x02\x03\x00", "cu_protocol_invalid"), (0, b"\x02\x02", "cu_firmware_unsupported"),
    (0, b"\x03\x02", "cu_firmware_unsupported"), (0, b"\x03\x03", "cu_firmware_unsupported"),
    (0, b"\x02\x04", "cu_firmware_unsupported"),
    (1, b"", "cu_protocol_invalid"), (1, b"v2.3.0\x00", "cu_protocol_invalid"),
    (1, b"\xff" + PRIVATE.encode(), "cu_protocol_invalid"), (1, b"x" * 65, "cu_protocol_invalid"),
    (1, b"v2.2.0", "cu_firmware_unsupported"), (1, b"v2.3.0-14-g4c5bc2c", "cu_firmware_unsupported"),
    (1, b"v2.3.0-dirty", "cu_firmware_unsupported"), (1, b"v2.3.0\n", "cu_firmware_unsupported"),
    (1, b" v2.3.0", "cu_firmware_unsupported"), (1, b"V2.3.0", "cu_firmware_unsupported"),
    (1, b"2.3.0", "cu_firmware_unsupported"), (1, b"v2.3.1", "cu_firmware_unsupported"),
    (1, b"v2.3", "cu_firmware_unsupported"), (1, b"v2.3.0-0-g4e1a5b2", "cu_firmware_unsupported"),
    (1, b"x" * 64, "cu_firmware_unsupported"), (1, "설명".encode(), "cu_firmware_unsupported"),
    (2, b"", "cu_protocol_invalid"), (2, b"\x00\x00", "cu_protocol_invalid"),
    (2, b"\x01", "cu_model_unsupported"), (2, b"\xff", "cu_model_unsupported"),
    (3, b"", "cu_protocol_invalid"), (3, b"\x01\x00", "cu_protocol_invalid"),
    (3, b"\x00", "cu_reader_required"), (3, b"\x02", "cu_reader_required"),
    (3, b"\xff", "cu_reader_required"),
])
def test_device_structure_vs_closed_claim_errors(position, data, code):
    replies = list(device_replies())
    replies[position] = replace(replies[position], data=data)
    failure(lambda: C.parse_cu_device(tuple(replies)), code)


def test_scan_complete_record_normalizes_only_atqa():
    identity = C.parse_cu_scan(C.CuFrame(2000, 0, scan_data()))
    assert identity == C.CuScanIdentity(UID, b"\x00\x44", b"\x00")
    assert identity.uid == UID


@pytest.mark.parametrize("data", [b"", b"\x00", b"\x01x\x44\x00\x00\x00",
                                 scan_data()[:-1], scan_data() + b"x", scan_data() * 2,
                                 scan_data()[:-1] + b"\x02x", b"\xff" + PRIVATE.encode()])
def test_scan_malformed_or_extra_record_is_not_family_unknown(data):
    failure(lambda: C.parse_cu_scan(C.CuFrame(2000, 0, data)), "nfc_scan_invalid")


@pytest.mark.parametrize("data", [scan_data(uid=b"1234"), scan_data(uid=b"1234567890"),
                                 scan_data(atqa=b"\x00\x44"), scan_data(atqa=b"\x04\x00"),
                                 scan_data(sak=b"\x08"), scan_data(sak=b"\x20"),
                                 scan_data(ats=b"x"), scan_data(ats=b"x" * 255)])
def test_scan_well_formed_other_family_is_unsupported(data):
    failure(lambda: C.parse_cu_scan(C.CuFrame(2000, 0, data)), "nfc_family_unsupported")


@pytest.mark.parametrize("family", tuple(C.NtagFamily))
def test_only_three_exact_get_version_values(family):
    frame = C.CuFrame(2010, 0, family.mifare_version)
    assert C.parse_ntag_version(frame) is family
    for index in range(8):
        changed = bytearray(family.mifare_version)
        changed[index] ^= 0x80
        failure(lambda: C.parse_ntag_version(replace(frame, data=bytes(changed))), "nfc_family_unsupported")


@pytest.mark.parametrize("data", [b"\x0a", b"x" * 7, b"x" * 9,
                                 C.NtagFamily.NTAG213.mifare_version + b"\x00\x00"])
def test_version_requires_crc_stripped_exact_eight_bytes(data):
    failure(lambda: C.parse_ntag_version(C.CuFrame(2010, 0, data)), "nfc_scan_invalid")


@pytest.mark.parametrize("status,data", [
    (0x00, b""),  # MF0ICU1/UL-C의 4bit NAK: check_crc 아래 HF 성공·빈 payload
    (0x01, b""),  # 응답 없음(timeout) 또는 선택 뒤 태그 이탈
    (0x03, b""),  # CRC 오류
    (0x00, bytes.fromhex("0004030101000b03")),  # Ultralight EV1 MF0UL11
    (0x00, bytes.fromhex("0004030101000e03")),  # Ultralight EV1 MF0UL21
    (0x00, bytes.fromhex("0004040201000f04")),
])
def test_well_formed_other_tag_version_is_fixed_family_refusal(status, data):
    failure(lambda: C.parse_ntag_version(C.CuFrame(2010, status, data)), "nfc_family_unsupported")


@pytest.mark.parametrize("status,data", [
    (0x01, b"\x00" * 8), (0x03, b"\x00"), (0x01, C.NtagFamily.NTAG213.mifare_version),
    (0x02, b""), (0x04, b""), (0x05, b""), (0x07, b""), (0x08, b""), (0x60, b""), (0x66, b""),
    (0x67, b""), (0x68, b""), (0x68, C.NtagFamily.NTAG213.mifare_version),
])
def test_other_version_status_or_length_is_malformed_not_family(status, data):
    failure(lambda: C.parse_ntag_version(C.CuFrame(2010, status, data)), "nfc_scan_invalid")


@pytest.mark.parametrize("parser,command,data", [(C.parse_cu_scan, 2000, scan_data()),
                                               (C.parse_ntag_version, 2010, b"\x00" * 8)])
@pytest.mark.parametrize("field,value", [("command", 0), ("command", 2011),
                                         ("status", 0x68), ("status", 1)])
def test_hf_and_general_success_cannot_be_interchanged(parser, command, data, field, value):
    frame = replace(C.CuFrame(command, 0, data), **{field: value})
    failure(lambda: parser(frame), "nfc_scan_invalid")


def test_semantic_parsers_reject_frame_subclasses_and_lookalikes():
    class Child(C.CuFrame):
        pass

    for value in (None, {"command": 2000, "status": 0, "data": scan_data()}, Child(2000, 0, scan_data())):
        failure(lambda: C.parse_cu_scan(value), "nfc_scan_invalid")
        failure(lambda: C.parse_ntag_version(value), "nfc_scan_invalid")
    replies = device_replies()
    failure(lambda: C.parse_cu_device((Child(1000, 0x68, b"\x02\x03"),) + replies[1:]))


def test_no_public_arbitrary_encoder_or_read_response_parser():
    assert not hasattr(C, "encode") and not hasattr(C, "build_raw")
    assert not hasattr(C, "parse_ntag_read")
    assert tuple(query.value for query in C.CuQuery) == (1000, 1017, 1033, 1002, 2000)


def every_builder_wire():
    yield from (C.build_cu_query(query) for query in C.CuQuery)
    yield from (C.build_cu_status_query(query) for query in C.CuStatusQuery)
    yield C.build_ntag_version(keep_field=False)
    for family in C.NtagFamily:
        for page in range(family.pages_total):
            for last in (False, True):
                for select in (False, True):
                    try:
                        yield C.build_ntag_read(family, page, last=last, select=select)
                    except C.CuProtocolError:
                        pass


def test_whitelist_is_closed_and_denies_new_v230_and_control_commands():
    commands, options, version_options, select_payloads = set(), set(), set(), set()
    for packet in every_builder_wire():
        frame, = C.CuDecoder().feed(packet)
        commands.add(frame.command)
        if frame.command == 2010:
            options.add(frame.data[0])
            if frame.data[1:] == b"\x00\x64\x00\x08\x60":
                version_options.add(frame.data[0])
            if frame.data[0] == 0xfc:
                select_payloads.add(frame.data[1:])
    # 상태 조회 getter 1025/1018/2200은 이번 증분에서 의도적으로 허용 목록에 더했다.
    assert commands == {1000, 1017, 1033, 1002, 2000, 2010, 1025, 1018, 2200}
    assert not commands & DENIED
    assert options == {0xf4, 0xfc, 0xec, 0xe4}
    # GET_VERSION은 f4뿐이고, fc(auto-select+keep)는 page0 READ(0x30 0x00)에만 쓰인다.
    assert version_options == {0xf4}
    assert select_payloads == {b"\x00\x64\x00\x10\x30\x00"}
    # BLE PIN·식별자·slot 별명/정보·long-press·battery-ex·설정 변경은 상태 조회에서도 만들 수 없다.
    for command in sorted(DENIED) + [1035, 2201, 1008, 1019, 1038, 1041, 1042, 1043]:
        failure(lambda: C._encode(command, b""))
        assert command not in {query.value for query in C.CuQuery}
        assert command not in {query.value for query in C.CuStatusQuery}
