"""espprobe v1의 bounded wire codec. 포트·장치 I/O와 허용 연산 정책은 포함하지 않는다."""

from __future__ import annotations

import struct
import zlib
from dataclasses import dataclass
from typing import Mapping

MAX_PAYLOAD = 4096
MAX_DECODED = 4116
MAX_ENCODED = 4133
MAX_WIRE = 4134
HEADER = struct.Struct("<BBBBIIHH")
REQ, RSP, EVT, DATA, HB = range(1, 6)
HELLO, RELEASE, BYE, ABORT = range(1, 5)
RESET_REASONS = ("unknown", "power-on", "software", "panic", "watchdog", "brownout", "deep-sleep", "external")
RELEASE_REASONS = ("none", "boot", "request-release", "bye", "abort", "heartbeat-timeout", "usb-reset",
                   "usb-detach", "usb-suspend", "dtr-fall", "transport-error", "internal-error",
                   "sequence-exhausted", "clock-error", "host-close")


class ProtocolError(ValueError):
    """원문 payload를 포함하지 않는 프로토콜 오류."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(f"espprobe protocol: {code}")


def _uint(value: int, bits: int) -> int:
    if type(value) is not int or not 0 <= value < 1 << bits:
        raise ProtocolError("integer_range")
    return value


@dataclass(frozen=True, kw_only=True)
class Frame:
    version: int = 1
    type: int
    op: int
    flags: int = 0
    seq: int
    session: int
    payload: bytes = b""
    credit: int = 0


def _raw(frame: Frame) -> bytes:
    for name, bits in (("version", 8), ("type", 8), ("op", 8), ("flags", 8), ("seq", 32), ("session", 32), ("credit", 16)):
        _uint(getattr(frame, name), bits)
    if frame.version != 1 or frame.type not in range(1, 6) or frame.seq == 0:
        raise ProtocolError("header")
    if frame.flags & ~1 or (frame.flags and frame.type != RSP):
        raise ProtocolError("flags")
    if type(frame.payload) is not bytes or len(frame.payload) > MAX_PAYLOAD:
        raise ProtocolError("payload_size")
    raw = HEADER.pack(frame.version, frame.type, frame.op, frame.flags, frame.seq, frame.session, len(frame.payload), frame.credit) + frame.payload
    return raw + struct.pack("<I", zlib.crc32(raw))


def _cobs_encode(raw: bytes) -> bytes:
    out = bytearray(b"\x00")
    position, code = 0, 1
    for byte in raw:
        if byte == 0:
            out[position] = code
            position = len(out)
            out.append(0)
            code = 1
        else:
            out.append(byte)
            code += 1
            if code == 255:
                out[position] = code
                position = len(out)
                out.append(0)
                code = 1
    out[position] = code
    return bytes(out)


def encode(frame: Frame) -> bytes:
    """정확히 한 프레임과 끝 delimiter를 만든다."""
    return _cobs_encode(_raw(frame)) + b"\x00"


def decode(wire: bytes) -> Frame:
    """단일 canonical wire frame을 검증한다. 잘린/이어붙인 입력은 거부한다."""
    if type(wire) is not bytes or not 2 <= len(wire) <= MAX_WIRE or wire[-1] != 0 or 0 in wire[:-1]:
        raise ProtocolError("wire_size_or_delimiter")
    encoded, raw, pos = wire[:-1], bytearray(), 0
    while pos < len(encoded):
        code = encoded[pos]
        pos += 1
        if pos + code - 1 > len(encoded):
            raise ProtocolError("cobs_length")
        raw.extend(encoded[pos:pos + code - 1])
        pos += code - 1
        if code < 255 and pos < len(encoded):
            raw.append(0)
        if len(raw) > MAX_DECODED:
            raise ProtocolError("decoded_size")
    if len(raw) < 20:
        raise ProtocolError("decoded_size")
    version, typ, op, flags, seq, session, length, credit = HEADER.unpack_from(raw)
    if length > MAX_PAYLOAD or length + 20 != len(raw):
        raise ProtocolError("length")
    if zlib.crc32(raw[:-4]) != struct.unpack_from("<I", raw, len(raw) - 4)[0]:
        raise ProtocolError("crc")
    frame = Frame(version=version, type=typ, op=op, flags=flags, seq=seq, session=session, payload=bytes(raw[16:-4]), credit=credit)
    if encode(frame) != wire:
        raise ProtocolError("noncanonical")
    return frame


class StreamDecoder:
    """오류 뒤 delimiter까지 버리는 고정 상한 수신기."""

    def __init__(self) -> None:
        self.buffer = bytearray()
        self.discarding = False
        self.errors = 0

    def reset(self) -> None:
        self.buffer.clear()
        self.discarding = False

    def feed(self, chunk: bytes) -> list[Frame]:
        if type(chunk) is not bytes or len(chunk) > 16384:
            raise ProtocolError("chunk_size")
        frames = []
        for byte in chunk:
            if byte == 0:
                if self.buffer and not self.discarding:
                    try:
                        frames.append(decode(bytes(self.buffer) + b"\x00"))
                    except ProtocolError:
                        self.errors = min(self.errors + 1, (1 << 64) - 1)
                self.reset()
            elif not self.discarding:
                if len(self.buffer) == MAX_ENCODED:
                    self.buffer.clear()
                    self.discarding = True
                    self.errors = min(self.errors + 1, (1 << 64) - 1)
                else:
                    self.buffer.append(byte)
        return frames


def encode_tlvs(items: Mapping[int, bytes]) -> bytes:
    if len(items) > 64:
        raise ProtocolError("tlv_count")
    out = bytearray()
    for tag in sorted(items):
        _uint(tag, 16)
        value = items[tag]
        if not tag or type(value) is not bytes or len(value) > MAX_PAYLOAD or len(out) + len(value) + 4 > MAX_PAYLOAD:
            raise ProtocolError("tlv_size")
        out += struct.pack("<HH", tag, len(value)) + value
    return bytes(out)


def decode_tlvs(payload: bytes) -> dict[int, bytes]:
    if type(payload) is not bytes or len(payload) > MAX_PAYLOAD:
        raise ProtocolError("tlv_size")
    result, pos, previous = {}, 0, 0
    while pos < len(payload):
        if len(payload) - pos < 4 or len(result) == 64:
            raise ProtocolError("tlv_bounds")
        tag, length = struct.unpack_from("<HH", payload, pos)
        pos += 4
        if tag <= previous or length > len(payload) - pos:
            raise ProtocolError("tlv_order_or_length")
        result[tag] = payload[pos:pos + length]
        previous, pos = tag, pos + length
    return result


def _ascii(value: str, maximum: int) -> bytes:
    if type(value) is not str or not 1 <= len(value) <= maximum or any(not 32 <= ord(c) <= 126 for c in value):
        raise ProtocolError("hello_string")
    return value.encode("ascii")


def _hex(value: str, size: int) -> bytes:
    if type(value) is not str or len(value) != size * 2 or any(c not in "0123456789abcdef" for c in value):
        raise ProtocolError("hello_hex")
    return bytes.fromhex(value)


def encode_hello(fields: Mapping) -> bytes:
    """typed HELLO를 status0+TLV로 만든다. 정책/enum도 decode와 대조한다."""
    try:
        values = {1: _hex(fields["nonce"], 16)}
        for tag, name, maximum in ((2, "fw_name", 32), (3, "fw_version", 32), (4, "build_profile", 32), (5, "board", 48), (6, "git_commit", 40), (9, "idf_version", 32)):
            values[tag] = _ascii(fields[name], maximum)
        values[7], values[8] = _hex(fields["image_sha256"], 32), _hex(fields["app_elf_sha256"], 32)
        chip = fields["chip"]
        known = (1 if chip["model"] != "unknown" else 0) | (2 if chip["revision"] is not None else 0) | (4 if chip["psram_bytes"] is not None else 0) | (8 if chip["flash_voltage_mv"] is not None else 0)
        model = {"unknown": 0, "esp32s3": 1}[chip["model"]]
        values[10] = struct.pack("<BHIHB", model, _uint(0 if chip["revision"] is None else chip["revision"], 16), _uint(0 if chip["psram_bytes"] is None else chip["psram_bytes"], 32), _uint(0 if chip["flash_voltage_mv"] is None else chip["flash_voltage_mv"], 16), known)
        values[11] = _hex(fields["base_mac"], 6)
        usb = fields["usb"]
        values[12] = struct.pack("<HH", _uint(usb["vid"], 16), _uint(usb["pid"], 16))
        values[13], values[14] = _ascii(usb["product"], 32), _ascii(usb["serial"], 12)
        values[15] = _hex(fields["boot_id"], 16)
        values[16] = struct.pack("<I", _uint(fields["usb_session"], 32))
        values[17], values[18] = struct.pack("<H", RESET_REASONS.index(fields["reset_reason"])), struct.pack("<H", RELEASE_REASONS.index(fields["last_release_reason"]))
        if fields["caps"] != [] or fields["tx_caps"] != [] or fields["pins_allowed"] != {"H0": [], "H1": [], "H1a": []} or fields["pclk_pad"] is not None or fields["pin_drive"] is not None or fields["spi_read_opcodes"] != [] or fields["radio"] != "none":
            raise ProtocolError("hello_policy")
        limits = fields["limits"]
        values.update({19: bytes(4), 20: struct.pack("<HHH", _uint(limits["max_payload"], 16), _uint(limits["hb_ms"], 16), _uint(limits["max_credit"], 16)), 21: bytes(24), 22: b"\xff", 23: b"\x00", 24: b"", 25: b"\x00", 26: bytes(4), 27: struct.pack("<I", _uint(fields["session_token"], 32))})
        result = bytes(2) + encode_tlvs(values)
        decode_hello(result)
        return result
    except (KeyError, TypeError, ValueError, struct.error) as exc:
        if isinstance(exc, ProtocolError):
            raise
        raise ProtocolError("hello_fields") from None


def decode_hello(payload: bytes) -> dict:
    """HELLO status/TLV를 검증하고 JSON 친화적인 필드로 변환한다."""
    if type(payload) is not bytes or not 2 <= len(payload) <= MAX_PAYLOAD or payload[:2] != bytes(2):
        raise ProtocolError("hello_status")
    values = decode_tlvs(payload[2:])
    if not set(range(1, 28)).issubset(values) or any(t & 0x8000 for t in values if t > 27):
        raise ProtocolError("hello_tags")
    for tag, length in {1:16,7:32,8:32,10:10,11:6,12:4,14:12,15:16,16:4,17:2,18:2,19:4,20:6,21:24,22:1,23:1,24:0,25:1,26:4,27:4}.items():
        if len(values[tag]) != length:
            raise ProtocolError("hello_length")
    result = {}
    for tag, name, maximum in ((2,"fw_name",32),(3,"fw_version",32),(4,"build_profile",32),(5,"board",48),(6,"git_commit",40),(9,"idf_version",32)):
        try:
            value = values[tag].decode("ascii")
        except UnicodeDecodeError:
            raise ProtocolError("hello_string") from None
        _ascii(value, maximum)
        result[name] = value
    _hex(result["git_commit"], 20)
    for tag, name in ((1,"nonce"),(7,"image_sha256"),(8,"app_elf_sha256"),(11,"base_mac"),(15,"boot_id")):
        result[name] = values[tag].hex()
    model, revision, psram, voltage, known = struct.unpack("<BHIHB", values[10])
    if model not in (0,1) or known & ~15 or bool(known & 1) != bool(model) or any(not known & bit and value for bit,value in ((2,revision),(4,psram),(8,voltage))):
        raise ProtocolError("hello_chip")
    result["chip"] = {"model": "esp32s3" if model else "unknown", "revision": revision if known & 2 else None, "psram_bytes": psram if known & 4 else None, "flash_voltage_mv": voltage if known & 8 else None}
    try:
        product, serial = values[13].decode("ascii"), values[14].decode("ascii")
        _ascii(product, 32)
    except UnicodeDecodeError:
        raise ProtocolError("hello_usb") from None
    if serial != result["base_mac"].upper():
        raise ProtocolError("hello_usb_serial")
    vid,pid = struct.unpack("<HH", values[12])
    result["usb"] = {"vid":vid,"pid":pid,"product":product,"serial":serial}
    result["usb_session"],result["session_token"] = struct.unpack("<I",values[16])[0],struct.unpack("<I",values[27])[0]
    if not result["usb_session"] or not result["session_token"]:
        raise ProtocolError("hello_session")
    try:
        result["reset_reason"] = RESET_REASONS[struct.unpack("<H",values[17])[0]]
        result["last_release_reason"] = RELEASE_REASONS[struct.unpack("<H",values[18])[0]]
    except IndexError:
        raise ProtocolError("hello_reason") from None
    maximum,hb,credit = struct.unpack("<HHH",values[20])
    if maximum != 4096 or not 250 <= hb <= 3000 or credit or any(values[19]+values[21]+values[23]+values[25]+values[26]) or values[22] != b"\xff":
        raise ProtocolError("hello_policy")
    result.update(caps=[],tx_caps=[],pins_allowed={"H0":[],"H1":[],"H1a":[]},pclk_pad=None,pin_drive=None,spi_read_opcodes=[],radio="none",limits={"max_payload":maximum,"hb_ms":hb,"max_credit":credit})
    return result
