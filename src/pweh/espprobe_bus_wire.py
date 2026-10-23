"""내부 bus 시험의 고정 payload codec. 실제 전송·시각·장치 권한은 다루지 않는다."""

from __future__ import annotations

import struct
from dataclasses import dataclass

from . import espprobe_protocol as P
from .errors import PwehError

SPI_PROBE, READ_BEGIN, READ_DONE = 0x10, 0x11, 0x12


@dataclass(frozen=True, repr=False)
class BusWireBinding:
    session: int
    usb_session: int
    hello_seq: int
    last_hb_seq: int
    hb_ms: int
    boot_id: bytes


@dataclass(frozen=True)
class BusReadPlan:
    kind: str
    offset: int
    length: int
    passes: int = 2


@dataclass(frozen=True, repr=False)
class BusSpiInfo:
    jedec: bytes
    sr1: int
    facts: int
    capacity: int


@dataclass(frozen=True)
class BusResponse:
    op: int
    seq: int
    status: int
    info: BusSpiInfo | None = None


@dataclass(frozen=True)
class BusHeartbeat:
    seq: int
    credit: int


@dataclass(frozen=True, repr=False)
class BusData:
    seq: int
    pass_index: int
    offset: int
    data: bytes


@dataclass(frozen=True)
class BusDone:
    seq: int
    passes: int
    offset: int
    length: int


def _error(code: str = "espprobe_bus_invalid") -> PwehError:
    return PwehError("내부 bus 메시지를 확인할 수 없습니다.", code=code)


def _uint(value: object, bits: int, *, positive: bool = False) -> bool:
    return type(value) is int and (1 if positive else 0) <= value < 1 << bits


def _binding(binding: BusWireBinding) -> None:
    if (type(binding) is not BusWireBinding or
            not all(_uint(getattr(binding, key), 32, positive=True)
                    for key in ("session", "usb_session", "hello_seq")) or
            not _uint(binding.last_hb_seq, 32) or type(binding.hb_ms) is not int or
            binding.hb_ms != 1000 or type(binding.boot_id) is not bytes or len(binding.boot_id) != 16):
        raise _error()


def _plan(plan: BusReadPlan) -> None:
    if (type(plan) is not BusReadPlan or type(plan.kind) is not str or plan.kind not in ("spi", "i2c") or
            not _uint(plan.offset, 32) or not _uint(plan.length, 32, positive=True) or
            type(plan.passes) is not int or plan.passes not in (1, 2) or
            plan.offset + plan.length > 1 << 32):
        raise _error()


def _build(binding: BusWireBinding, seq: int, op: int, payload: bytes, *, heartbeat: bool = False,
           credit: int = 0) -> bytes:
    _binding(binding)
    if not _uint(seq, 32, positive=True):
        raise _error()
    try:
        return P.encode(P.Frame(type=P.HB if heartbeat else P.REQ, op=op, seq=seq,
                                session=binding.session, payload=payload, credit=credit))
    except (P.ProtocolError, struct.error):
        raise _error() from None


def build_spi_probe(binding: BusWireBinding, *, seq: int) -> bytes:
    """고정 SPI 식별 요청 한 개를 만든다."""
    _binding(binding)
    return _build(binding, seq, SPI_PROBE, struct.pack("<I", binding.usb_session))


def build_read_begin(binding: BusWireBinding, plan: BusReadPlan, *, seq: int) -> bytes:
    """핀·속도·명령을 포함하지 않는 고정 읽기 계획을 만든다."""
    _binding(binding)
    _plan(plan)
    payload = struct.pack("<IBBBII", binding.usb_session, 0 if plan.kind == "spi" else 1,
                          0, plan.passes, plan.offset, plan.length)
    return _build(binding, seq, READ_BEGIN, payload)


def build_bus_heartbeat(binding: BusWireBinding, *, seq: int, credit: int) -> bytes:
    """credit의 누적·잔여 검사는 실제 bus 상태기계가 수행한다."""
    if not _uint(credit, 16) or credit > 4:
        raise _error()
    return _build(binding, seq, 0, b"", heartbeat=True, credit=credit)


def build_bus_cleanup(binding: BusWireBinding, *, seq: int, abort: bool = False) -> bytes:
    """BYE 또는 ABORT만 만들며 임의 opcode는 받지 않는다."""
    if type(abort) is not bool:
        raise _error()
    return _build(binding, seq, P.ABORT if abort else P.BYE, b"")


def parse_bus_frame(frame: P.Frame, binding: BusWireBinding) -> BusResponse | BusHeartbeat | BusData | BusDone:
    """canonical codec 뒤의 고정 payload·세대를 확인한다. 순서·계획 결속은 caller 책임이다."""
    _binding(binding)
    try:
        if type(frame) is not P.Frame:
            raise ValueError
        # 직접 만든 Frame도 codec과 동일한 exact 정수/헤더 검사를 거친다.
        P.encode(frame)
        if frame.session != binding.session:
            raise ValueError
        raw = frame.payload
        if frame.type == P.HB:
            if frame.op != 0 or frame.flags or raw or frame.credit > 4:
                raise ValueError
            return BusHeartbeat(frame.seq, frame.credit)
        if frame.credit:
            raise ValueError
        if frame.type == P.RSP:
            if frame.op not in (0, P.RELEASE, P.BYE, P.ABORT, SPI_PROBE, READ_BEGIN) or len(raw) < 2:
                raise ValueError
            status = struct.unpack_from("<H", raw)[0]
            if status:
                if status > 8 or frame.flags != 1 or len(raw) != 2:
                    raise ValueError
                return BusResponse(frame.op, frame.seq, status)
            if frame.flags or frame.op == 0:
                raise ValueError
            if frame.op == SPI_PROBE:
                if len(raw) != 19:
                    raise ValueError
                generation, jedec, sr1, facts, capacity = struct.unpack_from("<I3sBBQ", raw, 2)
                if generation != binding.usb_session or facts & ~7:
                    raise ValueError
                return BusResponse(frame.op, frame.seq, 0, BusSpiInfo(jedec, sr1, facts, capacity))
            if len(raw) != 2:
                raise ValueError
            return BusResponse(frame.op, frame.seq, 0)
        if frame.flags:
            raise ValueError
        if frame.type == P.DATA and frame.op == READ_BEGIN and len(raw) >= 12:
            generation, pass_index, offset, length = struct.unpack_from("<IBIH", raw)
            if (generation != binding.usb_session or pass_index > 1 or not 1 <= length <= 256 or
                    len(raw) != 11 + length or offset + length > 1 << 32):
                raise ValueError
            return BusData(frame.seq, pass_index, offset, raw[11:])
        if frame.type == P.EVT and frame.op == READ_DONE and len(raw) == 13:
            generation, passes, offset, length = struct.unpack("<IBII", raw)
            if (generation != binding.usb_session or passes not in (1, 2) or length == 0 or
                    offset + length > 1 << 32):
                raise ValueError
            return BusDone(frame.seq, passes, offset, length)
        raise ValueError
    except (P.ProtocolError, ValueError, struct.error, TypeError, AttributeError):
        raise _error("espprobe_bus_protocol") from None
