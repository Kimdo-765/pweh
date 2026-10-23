"""I5 시험 전용 peer/helper. Linux stdin/stdout만 사용하고 포트를 열지 않는다.

등록 릴리스의 필드는 부모 시험이 FAKE_CONFIG에 복사한다. 운영 codec/admission 또는
sim EXPECTED를 import하지 않고 두 framing을 독립 struct/CRC로 처리한다.
"""
import json
import os
import re
import select
import signal
import struct
import sys
import zlib

CONFIG = globals().get("FAKE_CONFIG", {})
SOURCE_COMMIT = "1" * 40
TOKEN = 0x12345678
HEADER = struct.Struct("<BBBBIIHH")


def encode(typ, op, seq, session, payload=b""):
    raw = HEADER.pack(1, typ, op, 0, seq, session, len(payload), 0) + payload
    raw += struct.pack("<I", zlib.crc32(raw))
    parts, position, code = bytearray(b"\0"), 0, 1
    for value in raw:
        if value == 0:
            parts[position] = code
            position, code = len(parts), 1
            parts.append(0)
        else:
            parts.append(value)
            code += 1
            if code == 255:
                parts[position] = code
                position, code = len(parts), 1
                parts.append(0)
    parts[position] = code
    return bytes(parts) + b"\0"


def decode(wire):
    if not 2 <= len(wire) <= 4134 or wire[-1] != 0:
        raise ValueError("synthetic_wire")
    raw, pos = bytearray(), 0
    data = wire[:-1]
    while pos < len(data):
        code = data[pos]
        pos += 1
        if not code or pos + code - 1 > len(data):
            raise ValueError("synthetic_cobs")
        raw.extend(data[pos:pos + code - 1])
        pos += code - 1
        if code < 255 and pos < len(data):
            raw.append(0)
    if len(raw) < 20 or zlib.crc32(raw[:-4]) != struct.unpack_from("<I", raw, len(raw) - 4)[0]:
        raise ValueError("synthetic_crc")
    version, typ, op, flags, seq, session, length, credit = HEADER.unpack_from(raw)
    if version != 1 or flags or credit or not seq or length > 4096 or len(raw) != length + 20:
        raise ValueError("synthetic_header")
    return typ, op, seq, session, bytes(raw[16:-4])


def hello(fields, nonce):
    values = {1: nonce}
    for tag, name in ((2, "fw_name"), (3, "fw_version"), (4, "build_profile"),
                      (5, "board"), (6, "git_commit"), (9, "idf_version")):
        values[tag] = fields[name].encode("ascii")
    values[7] = bytes.fromhex(fields["image_sha256"])
    values[8] = bytes.fromhex(fields["app_elf_sha256"])
    values[10] = struct.pack("<BHIHB", 1, fields["chip_revision"], 0, 0, 3)
    values[11] = bytes.fromhex(fields["base_mac"])
    values[12] = struct.pack("<HH", fields["usb_vid"], fields["usb_pid"])
    values[13] = fields["usb_product"].encode("ascii")
    values[14] = fields["base_mac"].upper().encode("ascii")
    values[15] = b"\xa5" * 16
    values[16] = struct.pack("<I", 1)
    values[17] = struct.pack("<H", 1)
    values[18] = struct.pack("<H", 1)
    values.update({19: bytes(4), 20: struct.pack("<HHH", 4096, 1000, 0),
                   21: bytes(24), 22: b"\xff", 23: b"\0", 24: b"", 25: b"\0",
                   26: bytes(4), 27: struct.pack("<I", TOKEN)})
    return bytes(2) + b"".join(struct.pack("<HH", tag, len(value)) + value
                               for tag, value in sorted(values.items()))


class Peer:
    """허용한 네 명령만 받는 유한 합성 peer. log에는 원시 프레임을 넣지 않는다."""

    def __init__(self, fields, *, fault="", record=None):
        self.fields, self.fault = fields, fault
        self.record = record or (lambda *_args, **_kwargs: None)
        self.buffer = bytearray()
        self.active = False
        self.cleanup = None
        self.cleanup_count = 0
        self.frames = []

    def feed(self, data):
        self.buffer.extend(data)
        if len(self.buffer) > 16384:
            raise ValueError("synthetic_buffer")
        replies = []
        while b"\0" in self.buffer:
            stop = self.buffer.index(0) + 1
            wire = bytes(self.buffer[:stop])
            del self.buffer[:stop]
            typ, op, seq, session, payload = decode(wire)
            self.frames.append((typ, op, seq, session, payload))
            self.record("probe", type=typ, op=op, seq=seq)
            if typ == 1 and op == 1 and seq == 1 and session == 0 and not self.active:
                if len(payload) != 20 or payload[:4] != struct.pack("<HH", 1, 16):
                    raise ValueError("synthetic_nonce")
                self.active = True
                nonce = payload[4:]
                if self.fault == "wrong-nonce":
                    nonce = bytes(value ^ 255 for value in nonce)
                replies.append(encode(2, 1, seq, TOKEN, hello(self.fields, nonce)))
            elif typ == 5 and op == 0 and session == TOKEN and not payload and self.active:
                if self.fault != "drop-hb":
                    replies.append(encode(5, 0, seq, TOKEN + (self.fault == "wrong-hb-token")))
            elif typ == 1 and op in (2, 3) and seq == 2 and session == TOKEN and not payload:
                if self.cleanup is not None and self.cleanup != wire:
                    raise ValueError("synthetic_cleanup_changed")
                self.cleanup = wire
                self.cleanup_count += 1
                self.active = False
                if self.fault != "drop-cleanup" and not (self.fault == "drop-first-cleanup" and self.cleanup_count == 1):
                    replies.append(encode(2, op, seq, TOKEN, b"\0\0"))
            else:
                raise ValueError("synthetic_request")
        return b"".join(replies)


def main():
    args = sys.argv[1:]
    if (len(args) != 4 or args[:2] != ["--port", "COM4096"] or args[2] != "--token"
            or re.fullmatch(r"[0-9a-f]{32}", args[3]) is None):
        return 2
    signal.alarm(25)

    def record(event, **fields):
        if CONFIG.get("log"):
            with open(CONFIG["log"], "a", encoding="utf-8") as stream:
                stream.write(json.dumps({"event": event, **fields}, sort_keys=True) + "\n")

    def send(kind, payload):
        raw = kind.encode("ascii") + struct.pack("<H", len(payload)) + payload
        fragment = CONFIG.get("fragment", 16387)
        for start in range(0, len(raw), fragment):
            part = raw[start:start + fragment]
            while part:
                part = part[os.write(1, part):]

    def ack(rid, kind, count=0):
        send("A", struct.pack("<IBBIIII", rid, ord(kind), 0, 0, count, 1, 0))

    def opened(rid):
        record("opened")
        send("o", struct.pack("<IBIBI", rid, 0, 0, 0, 1))

    peer = Peer(CONFIG["peer"], fault=CONFIG.get("fault", ""), record=record)
    record("hello")
    send("H", struct.pack("<HHBBBB20sHH", 1, 0, 0, 1, 0, 0,
                           bytes.fromhex(SOURCE_COMMIT), 16384, 0))
    incoming, last, pending, is_open = bytearray(), 0, None, False
    while True:
        if pending is not None and os.path.isfile(CONFIG["open_release"]):
            opened(pending)
            pending, is_open = None, True
        if not select.select([0], [], [], .01)[0]:
            continue
        data = os.read(0, 16387)
        if not data:
            return 0
        incoming.extend(data)
        if len(incoming) > 32774:
            return 3
        while len(incoming) >= 3:
            length = struct.unpack_from("<H", incoming, 1)[0]
            if length > 16384:
                return 3
            if len(incoming) < length + 3:
                break
            kind, payload = chr(incoming[0]), bytes(incoming[3:3 + length])
            del incoming[:3 + length]
            if len(payload) < 4:
                return 3
            rid = struct.unpack_from("<I", payload)[0]
            if not last < rid:
                return 3
            last = rid
            record("helper", kind=kind)
            if kind == "Q" and len(payload) == 4:
                if CONFIG.get("fault") != "drop-quit-ack":
                    ack(rid, kind)
                record("closed")
                return 0
            if kind == "O" and len(payload) == 14 and not is_open and pending is None:
                values = struct.unpack_from("<IBBBBBB", payload, 4)
                if values != (115200, 8, 0, 0, 0, 0, 0):
                    return 3
                record("open", baud=values[0], bits=values[1], dtr=values[4], rts=values[5])
                if CONFIG.get("open_release"):
                    pending = rid
                else:
                    opened(rid)
                    is_open = True
            elif kind == "D" and 9 <= len(payload) <= 16384 and is_open:
                timeout_ms = struct.unpack_from("<I", payload, 4)[0]
                if not 1 <= timeout_ms <= 5000:
                    return 3
                record("write", timeout_ms=timeout_ms, count=len(payload) - 8)
                response = peer.feed(payload[8:])
                if response:
                    send("D", struct.pack("<I", 1) + response)
                ack(rid, kind, len(payload) - 8)
            else:
                return 3


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, KeyError, struct.error):
        raise SystemExit(4)
