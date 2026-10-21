"""직렬 helper v1 wire. bounded framing과 필드 검증만 하며 I/O가 없다."""
from __future__ import annotations

import struct
from dataclasses import dataclass

MAX_PAYLOAD = 16384
MAX_WRITE = MAX_PAYLOAD - 8
MAX_RX = MAX_PAYLOAD - 4


class ProtocolError(ValueError):
    """프레임 오류 뒤에는 재동기화하지 않는다."""


@dataclass(frozen=True)
class Frame:
    type: str
    payload: bytes


def encode(kind: str, payload: bytes) -> bytes:
    """고정 envelope만 만든다. 방향별 필드는 validate가 검사한다."""
    if kind not in "HOBLKPSDQosAE" or not isinstance(payload, bytes) or len(payload) > MAX_PAYLOAD:
        raise ProtocolError("프레임 type/크기 오류")
    return kind.encode("ascii") + struct.pack("<H", len(payload)) + payload


def _check(condition: bool, message: str = "프레임 필드 오류") -> None:
    if not condition:
        raise ProtocolError(message)


def _framing(baud: int, bits: int, parity: int, stop: int) -> None:
    _check(50 <= baud <= 20_000_000 and 5 <= bits <= 8 and parity <= 4 and stop <= 2)


def validate(frame: Frame, direction: str) -> dict:
    """정확한 길이·예약값·숫자 범위를 확인하고 dispatcher용 dict로 해석한다."""
    k, p = frame.type, frame.payload
    _check(direction in ("host", "helper"))
    if direction == "host":
        lengths = {"O": 14, "B": 12, "L": 6, "K": 9, "P": 9, "S": 4, "Q": 4}
        _check(k in lengths or k == "D", "host 방향 type 오류")
        _check(9 <= len(p) <= MAX_PAYLOAD if k == "D" else len(p) == lengths[k], "요청 길이 오류")
        rid = struct.unpack_from("<I", p)[0]
        _check(rid > 0)
        out = {"id": rid}
        if k in ("O", "B"):
            baud, bits, parity, stop = struct.unpack_from("<IBBB", p, 4)
            _framing(baud, bits, parity, stop)
            _check(p[-1] == 0)
            if k == "O":
                _check(p[11] in (0, 1) and p[12] in (0, 1))
            out.update(baud=baud, bits=bits, parity=parity, stop=stop)
        elif k == "L":
            _check(p[4] in (0, 1, 255) and p[5] in (0, 1, 255) and p[4:6] != b"\xff\xff")
        elif k in ("K", "P"):
            mode, duration = struct.unpack_from("<BI", p, 4)
            _check(mode <= 2)
            _check(1 <= duration <= 5000 if k == "P" or mode == 2 else duration == 0)
        elif k == "D":
            duration = struct.unpack_from("<I", p, 4)[0]
            _check(1 <= duration <= 30000)
            out.update(timeout_ms=duration, data=p[8:])
        return out
    lengths = {"H": 32, "o": 14, "A": 22, "s": 22, "E": 14}
    _check(k in lengths or k == "D", "helper 방향 type 오류")
    _check(5 <= len(p) <= MAX_PAYLOAD if k == "D" else len(p) == lengths[k], "응답 길이 오류")
    if k == "H":
        major, minor, v0, v1, v2, mode = struct.unpack_from("<HHBBBB", p)
        maximum, reserved = struct.unpack_from("<HH", p, 28)
        _check(mode <= 2 and maximum == MAX_PAYLOAD and reserved == 0)
        return {"protocol": (major, minor), "version": (v0, v1, v2), "mode": mode,
                "source_commit": p[8:28].hex(), "max_payload": maximum}
    if k == "D":
        epoch = struct.unpack_from("<I", p)[0]
        _check(epoch > 0)
        return {"epoch": epoch, "data": p[4:]}
    rid = struct.unpack_from("<I", p)[0]
    _check(rid > 0 or k == "E")
    if k == "A":
        kind, status, winerr, transferred, epoch, queued = struct.unpack_from("<BBIIII", p, 4)
        _check(chr(kind) in "BLKPDQ" and status == 0 and winerr == 0)
        _check(transferred == 0 or chr(kind) == "D")
        _check(queued == 0 if chr(kind) == "Q" else True)
        return {"id": rid, "request_type": chr(kind), "status": status, "winerr": winerr,
                "transferred": transferred, "epoch": epoch, "tx_pending": queued}
    if k == "E":
        kind, status, winerr, transferred = struct.unpack_from("<BBII", p, 4)
        _check(1 <= status <= 9)
        _check((rid == 0 and kind == 0) or (rid > 0 and chr(kind) in "OBLKPSDQ"))
        _check(transferred == 0 or chr(kind) == "D")
        return {"id": rid, "request_type": chr(kind) if kind else "", "status": status,
                "winerr": winerr, "transferred": transferred}
    status, winerr, modem = struct.unpack_from("<BIB", p, 4)
    _check(status <= 9 and modem <= 15 and (status != 0 or winerr == 0))
    out = {"id": rid, "status": status, "winerr": winerr, "modem": modem}
    if k == "o":
        out["epoch"] = struct.unpack_from("<I", p, 10)[0]
        _check(out["epoch"] == (1 if status == 0 else 0))
    else:
        out.update(zip(("comm_errors", "rx_pending", "tx_pending"), struct.unpack_from("<III", p, 10)))
    return out


class Decoder:
    """한 프레임만 버퍼에 보유하며 EOF의 반 프레임도 오류로 처리한다."""
    def __init__(self, direction: str = "helper"):
        if direction not in ("host", "helper"):
            raise ValueError("방향 오류")
        self.direction = direction
        self.buffer = bytearray()

    def feed(self, data: bytes) -> list[Frame]:
        if not isinstance(data, bytes) or len(data) > 1 << 20:
            raise ProtocolError("입력 청크 상한")
        out = []
        offset = 0
        while offset < len(data):
            need = 3 if len(self.buffer) < 3 else 3 + int.from_bytes(self.buffer[1:3], "little")
            _check(need <= MAX_PAYLOAD + 3, "payload 크기 상한")
            n = min(need - len(self.buffer), len(data) - offset)
            self.buffer.extend(data[offset:offset + n]); offset += n
            if len(self.buffer) < 3:
                continue
            size = int.from_bytes(self.buffer[1:3], "little")
            _check(size <= MAX_PAYLOAD, "payload 크기 상한")
            if len(self.buffer) == size + 3:
                frame = Frame(chr(self.buffer[0]), bytes(self.buffer[3:]))
                validate(frame, self.direction)
                self.buffer.clear(); out.append(frame)
        return out

    def eof(self) -> None:
        _check(not self.buffer, "프레임 중간 EOF")
