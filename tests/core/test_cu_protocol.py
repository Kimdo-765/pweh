"""장치 없이 독립 합성 wire로 고정 CU 프레임·계열·terminal 경계를 검사한다."""
from __future__ import annotations

from dataclasses import FrozenInstanceError, replace
from enum import Enum, IntEnum
import hashlib
import json
import struct
import traceback

import pytest

from pweh import cu_protocol as C

PRIVATE = "SYNTHETIC_CU_PRIVATE"
UID = b"SYNTH01"


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


def device_replies():
    return (C.CuFrame(1000, 0x68, b"\x02\x02"), C.CuFrame(1017, 0x68, b"v2.2.0"),
            C.CuFrame(1033, 0x68, b"\x00"), C.CuFrame(1002, 0x68, b"\x01"))


def scan_data(uid=UID, atqa=b"\x44\x00", sak=b"\x00", ats=b""):
    return bytes((len(uid),)) + uid + atqa + sak + bytes((len(ats),)) + ats


def test_profile_recipe_is_pinned_and_canonical():
    # 구현의 dict를 읽지 않고 별도 고정 recipe로 B/C가 소비할 hash를 검증한다.
    recipe = {
        "profile": "cu-ntag21x-v2.2.0-v1",
        "firmware_commit": "f349dbeeaa315776b272ae8fb851cc4042d55f07",
        "model": "chameleon-ultra", "app_version": "2.2", "git_version": "v2.2.0",
        "reader_mode": True, "queries": [1000, 1017, 1033, 1002], "scan_command": 2000,
        "raw_command": 2010, "rf_timeout_ms": 100, "crc_append": True, "crc_check": True,
        "uid_length": 7, "atqa_msb": "0044", "sak": "00", "ats_length": 0,
        "versions": ["0004040201000f03", "0004040201001103", "0004040201001303"],
        "probe_read_pages": [0, 1], "page_attribution_bytes": 4, "total_pages": [45, 135, 231],
    }
    encoded = json.dumps(recipe, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode()
    assert C.PROFILE_SHA256 == hashlib.sha256(encoded).hexdigest()
    assert C.PROFILE_SHA256 == "d7e590dce5e5f9723cbff12aa0fcea46d5a9550e392a33cf7b0de5102dffd73c"
    assert (C.PROFILE, C.FIRMWARE_COMMIT, C.FIRMWARE_VERSION, C.FIRMWARE_GIT_VERSION) == (
        recipe["profile"], recipe["firmware_commit"], "2.2", "v2.2.0")
    assert (C.MAX_DATA_BYTES, C.MAX_FRAME_BYTES, C.MAX_BUFFER_BYTES) == (512, 522, 1044)


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


@pytest.mark.parametrize("keep,expected", [
    (True, "11ef07da0000000619fc006400086038"),
    (False, "11ef07da0000000619f4006400086040"),
])
def test_version_options_and_crc_are_fixed(keep, expected):
    assert C.build_ntag_version(keep_field=keep) == bytes.fromhex(expected)
    frame, = C.CuDecoder().feed(bytes.fromhex(expected))
    assert frame.command == 2010 and frame.status == 0
    assert frame.data == bytes((0xfc if keep else 0xf4,)) + b"\x00\x64\x00\x08\x60"


@pytest.mark.parametrize("family,total,version", [
    (C.NtagFamily.NTAG213, 45, "0004040201000f03"),
    (C.NtagFamily.NTAG215, 135, "0004040201001103"),
    (C.NtagFamily.NTAG216, 231, "0004040201001303"),
])
def test_family_properties_and_all_read_boundaries(family, total, version):
    assert family.family == "ntag" + str(family.value)
    assert family.pages_total == total and family.mifare_version == bytes.fromhex(version)
    assert not isinstance(family, int)
    for page in (0, 1, total - 1):
        for last in (False, True):
            packet = C.build_ntag_read(family, page, last=last)
            expected = bytes((0xe4 if last else 0xec,)) + b"\x00\x64\x00\x10\x30" + bytes((page,))
            assert packet == wire(2010, 0, expected)
            frame, = C.CuDecoder().feed(packet)
            assert frame.data == expected and len(frame.data) == 7
    failure(lambda: C.build_ntag_read(family, total, last=True))
    with pytest.raises(AttributeError):
        family.pages_total = 1


def test_read_phase_has_distinct_probe_and_fullread_admission_wire():
    assert C.build_ntag_read(C.NtagFamily.NTAG213, 0, last=False) == bytes.fromhex(
        "11ef07da0000000718ec00640010300070")
    assert C.build_ntag_read(C.NtagFamily.NTAG213, 1, last=True) == bytes.fromhex(
        "11ef07da0000000718e400640010300177")
    assert C.build_ntag_read(C.NtagFamily.NTAG213, 1, last=False) == bytes.fromhex(
        "11ef07da0000000718ec0064001030016f")


@pytest.mark.parametrize("value", [None, 0, 1, 1.0, "true", b"true", [], object()])
def test_phase_options_are_exact_bools(value):
    failure(lambda: C.build_ntag_version(keep_field=value))
    failure(lambda: C.build_ntag_read(C.NtagFamily.NTAG213, 0, last=value))


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
        "chameleon-ultra", "2.2", "v2.2.0", True)
    with pytest.raises(FrozenInstanceError):
        device.reader_mode = False


@pytest.mark.parametrize("field,value", [("model", PRIVATE), ("model", 0), ("app_version", "2.3"),
                                       ("git_version", "v2.2.0-dirty"), ("reader_mode", 1),
                                       ("reader_mode", False)])
def test_device_constructor_is_closed(field, value):
    values = dict(model="chameleon-ultra", app_version="2.2", git_version="v2.2.0", reader_mode=True)
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
    (0, b"\x02\x02\x00", "cu_protocol_invalid"), (0, b"\x02\x03", "cu_firmware_unsupported"),
    (0, b"\x03\x02", "cu_firmware_unsupported"),
    (1, b"", "cu_protocol_invalid"), (1, b"v2.2.0\x00", "cu_protocol_invalid"),
    (1, b"\xff" + PRIVATE.encode(), "cu_protocol_invalid"), (1, b"x" * 65, "cu_protocol_invalid"),
    (1, b"v2.2.0-dirty", "cu_firmware_unsupported"), (1, b"v2.2.0\n", "cu_firmware_unsupported"),
    (1, b"2.2.0", "cu_firmware_unsupported"), (1, b"v2.2.1", "cu_firmware_unsupported"),
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


@pytest.mark.parametrize("data", [b"", b"\x0a", b"x" * 7, b"x" * 9,
                                 C.NtagFamily.NTAG213.mifare_version + b"\x00\x00"])
def test_version_requires_crc_stripped_exact_eight_bytes(data):
    failure(lambda: C.parse_ntag_version(C.CuFrame(2010, 0, data)), "nfc_scan_invalid")


@pytest.mark.parametrize("parser,command,data", [(C.parse_cu_scan, 2000, scan_data()),
                                               (C.parse_ntag_version, 2010, b"\x00" * 8)])
@pytest.mark.parametrize("field,value", [("command", 0), ("status", 0x68), ("status", 1)])
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
    failure(lambda: C.parse_cu_device((Child(1000, 0x68, b"\x02\x02"),) + replies[1:]))


def test_no_public_arbitrary_encoder_or_read_response_parser():
    assert not hasattr(C, "encode") and not hasattr(C, "build_raw")
    assert not hasattr(C, "parse_ntag_read")
    assert tuple(query.value for query in C.CuQuery) == (1000, 1017, 1033, 1002, 2000)
