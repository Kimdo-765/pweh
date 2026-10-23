"""기존 framing 위의 내부 bus payload를 독립 LE 기대값으로 확인한다."""

from dataclasses import FrozenInstanceError, replace
import struct

import pytest

from pweh import espprobe_bus_wire as W
from pweh import espprobe_protocol as P
from pweh.errors import PwehError


def binding(**changes):
    return replace(W.BusWireBinding(0x12345678, 0x87654321, 3, 5, 1000, b"PRIVATE_BOOT_TAG"), **changes)


def frame(*, type=P.RSP, op=W.READ_BEGIN, payload=b"\x00\x00", **changes):
    return P.Frame(type=type, op=op, seq=7, session=binding().session, payload=payload, **changes)


def assert_error(call, code):
    with pytest.raises(PwehError) as caught:
        call()
    assert caught.value.code == code
    assert caught.value.data == {} and caught.value.hint is None
    assert "PRIVATE" not in str(caught.value)
    assert caught.value.__cause__ is None


def probe_payload(**changes):
    args = dict(generation=binding().usb_session, jedec=b"\xef\x40\x18", sr1=0x5A, facts=7, capacity=1 << 32)
    args.update(changes)
    return struct.pack("<HI3sBBQ", 0, *args.values())


def data_payload(*, generation=None, pass_index=0, offset=123, size=None, data=b"PRIVATE_DATA"):
    return struct.pack("<IBIH", binding().usb_session if generation is None else generation,
                       pass_index, offset, len(data) if size is None else size) + data


def done_payload(*, generation=None, passes=2, offset=123, length=256):
    return struct.pack("<IBII", binding().usb_session if generation is None else generation, passes, offset, length)


@pytest.mark.parametrize("kind", ["spi", "i2c"])
@pytest.mark.parametrize("passes", [1, 2])
@pytest.mark.parametrize("offset,length", [(0, 1), (0, 0xFFFFFFFF), (1, 0xFFFFFFFF), (0xFFFFFFFF, 1)])
def test_begin_fixed_payload(kind, passes, offset, length):
    wire = W.build_read_begin(binding(), W.BusReadPlan(kind, offset, length, passes), seq=0xFFFFFFFF)
    got = P.decode(wire)
    assert got == P.Frame(type=P.REQ, op=0x11, seq=0xFFFFFFFF, session=0x12345678,
                          payload=struct.pack("<IBBBII", 0x87654321, int(kind == "i2c"), 0, passes, offset, length))
    assert wire == P.encode(got)


def test_probe_golden_and_stateless_builders():
    expected = P.Frame(type=P.REQ, op=0x10, seq=4, session=0x12345678, payload=b"\x21\x43\x65\x87")
    assert P.decode(W.build_spi_probe(binding(), seq=4)) == expected
    assert W.build_spi_probe(binding(), seq=4) == W.build_spi_probe(binding(), seq=4)
    assert P.decode(W.build_spi_probe(binding(), seq=1)).seq == 1


@pytest.mark.parametrize("credit", range(5))
def test_heartbeat_golden_and_ack(credit):
    wire = W.build_bus_heartbeat(binding(), seq=6, credit=credit)
    got = P.decode(wire)
    assert got == P.Frame(type=P.HB, op=0, seq=6, session=binding().session, credit=credit)
    assert W.parse_bus_frame(got, binding()) == W.BusHeartbeat(6, credit)


@pytest.mark.parametrize("abort,op", [(False, P.BYE), (True, P.ABORT)])
def test_cleanup_fixed_op(abort, op):
    assert P.decode(W.build_bus_cleanup(binding(), seq=8, abort=abort)) == P.Frame(
        type=P.REQ, op=op, seq=8, session=binding().session)


@pytest.mark.parametrize("name,value", [
    ("session", 0), ("session", True), ("session", 1.0), ("session", -1), ("session", 1 << 32),
    ("usb_session", 0), ("usb_session", False), ("usb_session", 1 << 32),
    ("hello_seq", 0), ("hello_seq", True), ("hello_seq", 1 << 32),
    ("last_hb_seq", -1), ("last_hb_seq", False), ("last_hb_seq", 1 << 32),
    ("hb_ms", 999), ("hb_ms", 1000.0), ("hb_ms", True),
    ("boot_id", b"PRIVATE"), ("boot_id", b"x" * 17), ("boot_id", bytearray(16)), ("boot_id", "x" * 16),
])
def test_binding_exact_fields(name, value):
    bad = binding(**{name: value})
    for call in (lambda: W.build_spi_probe(bad, seq=4),
                 lambda: W.build_read_begin(bad, W.BusReadPlan("spi", 0, 1), seq=4),
                 lambda: W.build_bus_heartbeat(bad, seq=6, credit=0),
                 lambda: W.build_bus_cleanup(bad, seq=8),
                 lambda: W.parse_bus_frame(frame(), bad)):
        assert_error(call, "espprobe_bus_invalid")


@pytest.mark.parametrize("bad", [None, {}, (), object()])
def test_binding_exact_class(bad):
    assert_error(lambda: W.build_spi_probe(bad, seq=4), "espprobe_bus_invalid")


@pytest.mark.parametrize("name,value", [
    ("kind", "PRIVATE_RAW"), ("kind", 0), ("kind", b"spi"),
    ("offset", True), ("offset", -1), ("offset", 1.0), ("offset", 1 << 32),
    ("length", False), ("length", 0), ("length", -1), ("length", 1.0), ("length", 1 << 32),
    ("passes", False), ("passes", True), ("passes", 1.0), ("passes", 0), ("passes", 3),
])
def test_plan_exact_fields(name, value):
    plan = replace(W.BusReadPlan("spi", 0, 1), **{name: value})
    assert_error(lambda: W.build_read_begin(binding(), plan, seq=4), "espprobe_bus_invalid")


def test_plan_sum_and_class():
    for plan in (W.BusReadPlan("spi", 0xFFFFFFFF, 2), None, {}, ("spi", 0, 1)):
        assert_error(lambda: W.build_read_begin(binding(), plan, seq=4), "espprobe_bus_invalid")


@pytest.mark.parametrize("seq", [False, True, 1.0, 0, -1, 1 << 32, "PRIVATE", None])
def test_builder_sequence_exact(seq):
    for call in (lambda: W.build_spi_probe(binding(), seq=seq),
                 lambda: W.build_read_begin(binding(), W.BusReadPlan("spi", 0, 1), seq=seq),
                 lambda: W.build_bus_heartbeat(binding(), seq=seq, credit=0),
                 lambda: W.build_bus_cleanup(binding(), seq=seq)):
        assert_error(call, "espprobe_bus_invalid")


@pytest.mark.parametrize("credit", [-1, 5, 65536, True, False, 1.0, "PRIVATE", None])
def test_builder_credit_exact(credit):
    assert_error(lambda: W.build_bus_heartbeat(binding(), seq=6, credit=credit), "espprobe_bus_invalid")


@pytest.mark.parametrize("abort", [0, 1, 0.0, "PRIVATE", None])
def test_builder_abort_exact(abort):
    assert_error(lambda: W.build_bus_cleanup(binding(), seq=8, abort=abort), "espprobe_bus_invalid")


@pytest.mark.parametrize("op", [P.RELEASE, P.BYE, P.ABORT, W.READ_BEGIN])
def test_success_response(op):
    assert W.parse_bus_frame(frame(op=op), binding()) == W.BusResponse(op, 7, 0)


@pytest.mark.parametrize("op", [0, P.RELEASE, P.BYE, P.ABORT, W.SPI_PROBE, W.READ_BEGIN])
@pytest.mark.parametrize("status", range(1, 9))
def test_error_response_is_typed_not_raised(op, status):
    got = W.parse_bus_frame(frame(op=op, flags=1, payload=struct.pack("<H", status)), binding())
    assert got == W.BusResponse(op, 7, status)


@pytest.mark.parametrize("facts", range(8))
@pytest.mark.parametrize("capacity", [0, 1, 1 << 32, (1 << 64) - 1])
def test_probe_payload_unsigned_widths(facts, capacity):
    got = W.parse_bus_frame(frame(op=W.SPI_PROBE, payload=probe_payload(facts=facts, capacity=capacity)), binding())
    assert got == W.BusResponse(W.SPI_PROBE, 7, 0, W.BusSpiInfo(b"\xef\x40\x18", 0x5A, facts, capacity))


@pytest.mark.parametrize("pass_index", [0, 1])
@pytest.mark.parametrize("length", [1, 32, 255, 256])
def test_opaque_data_and_u32_last_byte(pass_index, length):
    opaque = bytes(range(256))[:length]
    offset = (1 << 32) - length
    got = W.parse_bus_frame(frame(type=P.DATA, op=W.READ_BEGIN,
                                 payload=data_payload(pass_index=pass_index, offset=offset, data=opaque)), binding())
    assert got == W.BusData(7, pass_index, offset, opaque)


@pytest.mark.parametrize("passes", [1, 2])
@pytest.mark.parametrize("offset,length", [(0, 1), (1, 0xFFFFFFFF), (0xFFFFFFFF, 1)])
def test_done_payload(passes, offset, length):
    got = W.parse_bus_frame(frame(type=P.EVT, op=W.READ_DONE,
                                 payload=done_payload(passes=passes, offset=offset, length=length)), binding())
    assert got == W.BusDone(7, passes, offset, length)


@pytest.mark.parametrize("name,value", [
    ("version", 0), ("version", True), ("version", 1.0), ("type", True), ("type", 0), ("type", 6),
    ("op", True), ("op", -1), ("op", 256), ("flags", True), ("flags", 2), ("flags", 0.0),
    ("seq", True), ("seq", 0), ("seq", 1.0), ("seq", 1 << 32),
    ("session", True), ("session", 0), ("session", 99), ("session", 1 << 32),
    ("credit", True), ("credit", -1), ("credit", 65536), ("credit", 1),
    ("payload", "PRIVATE"), ("payload", bytearray(b"\0\0")), ("payload", b"X" * 4097),
])
def test_frame_exact_header(name, value):
    bad = replace(frame(), **{name: value})
    assert_error(lambda: W.parse_bus_frame(bad, binding()), "espprobe_bus_protocol")


@pytest.mark.parametrize("bad", [None, {}, b"PRIVATE", (), object()])
def test_frame_exact_class(bad):
    assert_error(lambda: W.parse_bus_frame(bad, binding()), "espprobe_bus_protocol")


@pytest.mark.parametrize("bad", [
    frame(type=P.REQ), frame(type=P.DATA), frame(type=P.EVT), frame(op=0), frame(op=0x77),
    frame(flags=1), frame(payload=b""), frame(payload=b"\0"), frame(payload=b"\0\0X"),
    frame(payload=b"\1\0"), frame(flags=1, payload=b"\x09\0"), frame(flags=1, payload=b"\x01\0X"),
    frame(flags=1, payload=b"\xff\xff"), frame(op=W.SPI_PROBE),
    frame(op=W.SPI_PROBE, payload=probe_payload(generation=0)),
    frame(op=W.SPI_PROBE, payload=probe_payload(facts=8)),
    frame(op=W.SPI_PROBE, payload=probe_payload(facts=255)),
    frame(op=W.SPI_PROBE, payload=probe_payload() + b"X"),
    frame(op=W.SPI_PROBE, payload=probe_payload()[:-1]),
    frame(op=W.READ_BEGIN, payload=probe_payload()),
    frame(type=P.HB, op=0, payload=b"X"), frame(type=P.HB, op=1, payload=b""),
    frame(type=P.HB, op=0, payload=b"", credit=5), frame(type=P.HB, op=0, payload=b"", flags=1),
    frame(type=P.DATA, op=W.READ_DONE, payload=data_payload()),
    frame(type=P.DATA, op=W.READ_BEGIN, payload=data_payload(generation=0)),
    frame(type=P.DATA, op=W.READ_BEGIN, payload=data_payload(pass_index=2)),
    frame(type=P.DATA, op=W.READ_BEGIN, payload=data_payload(size=1)),
    frame(type=P.DATA, op=W.READ_BEGIN, payload=data_payload(data=b"")),
    frame(type=P.DATA, op=W.READ_BEGIN, payload=data_payload(data=b"X" * 257)),
    frame(type=P.DATA, op=W.READ_BEGIN, payload=data_payload(offset=0xFFFFFFFF, data=b"xx")),
    frame(type=P.DATA, op=W.READ_BEGIN, payload=data_payload() + b"X"),
    frame(type=P.DATA, op=W.READ_BEGIN, payload=data_payload(), credit=1),
    frame(type=P.EVT, op=W.READ_BEGIN, payload=done_payload()),
    frame(type=P.EVT, op=W.READ_DONE, payload=done_payload(generation=0)),
    frame(type=P.EVT, op=W.READ_DONE, payload=done_payload(passes=0)),
    frame(type=P.EVT, op=W.READ_DONE, payload=done_payload(passes=3)),
    frame(type=P.EVT, op=W.READ_DONE, payload=done_payload(length=0)),
    frame(type=P.EVT, op=W.READ_DONE, payload=done_payload(offset=0xFFFFFFFF, length=2)),
    frame(type=P.EVT, op=W.READ_DONE, payload=done_payload() + b"X"),
    frame(type=P.EVT, op=W.READ_DONE, payload=done_payload()[:-1]),
])
def test_closed_payloads(bad):
    assert_error(lambda: W.parse_bus_frame(bad, binding()), "espprobe_bus_protocol")


def test_subclasses_are_not_exact_inputs():
    class Binding(W.BusWireBinding):
        pass

    class Plan(W.BusReadPlan):
        pass

    class Frame(P.Frame):
        pass

    assert_error(lambda: W.build_spi_probe(Binding(1, 1, 1, 0, 1000, bytes(16)), seq=2), "espprobe_bus_invalid")
    assert_error(lambda: W.build_read_begin(binding(), Plan("spi", 0, 1), seq=4), "espprobe_bus_invalid")
    assert_error(lambda: W.parse_bus_frame(Frame(type=2, op=17, seq=7, session=binding().session), binding()),
                 "espprobe_bus_protocol")


@pytest.mark.parametrize("value,field", [
    (binding(), "session"), (W.BusReadPlan("spi", 0, 1), "length"),
    (W.BusSpiInfo(b"TAG", 0, 0, 0), "sr1"), (W.BusResponse(17, 7, 0), "status"),
    (W.BusHeartbeat(7, 0), "credit"), (W.BusData(7, 0, 0, b"PRIVATE"), "data"),
    (W.BusDone(7, 2, 0, 1), "length"),
])
def test_frozen_types(value, field):
    with pytest.raises(FrozenInstanceError):
        setattr(value, field, None)
    assert not hasattr(value, "to_dict")
    assert "PRIVATE" not in repr(value)


def test_decoder_roundtrip_does_not_consume_host_sequence():
    # 프레임 순서/중복 판단은 collector와 C 상태기계의 책임이다.
    data = frame(type=P.DATA, op=W.READ_BEGIN, payload=data_payload())
    decoded = P.decode(P.encode(data))
    assert W.parse_bus_frame(decoded, binding()) == W.parse_bus_frame(decoded, binding())
    assert W.parse_bus_frame(replace(decoded, seq=1), binding()).seq == 1
