"""명세의 숫자로 해석하는 in-process probe-hello 모델. 포트·socket·파일을 열지 않는다."""

from __future__ import annotations

import secrets
import struct
from collections import OrderedDict

from pweh.espprobe_protocol import Frame, ProtocolError, decode, decode_tlvs, encode, encode_hello


class ProbeSimulator:
    """실기 transport 없이 HELLO/HB/정리 상태를 시험한다. 단일 소유자가 직렬 호출한다."""

    def __init__(self, name: str = "sim://probe-hello", hb_ms: int = 1000) -> None:
        if name != "sim://probe-hello" or type(hb_ms) is not int or not 250 <= hb_ms <= 3000:
            raise ValueError("지원하는 in-process simulator 이름/heartbeat 범위가 아닙니다.")
        self.name, self.hb_ms = name, hb_ms
        self.closed, self.session, self.usb_session, self.now_ms = False, 0, 1, 0
        self.boot_id = secrets.token_hex(16)
        self.deadline_ms = None
        self.last_release_reason = "boot"
        self.last_req_seq = self.last_hb_seq = self._hello_seq = self._token = 0
        self._hello_request = self._hello_response = b""
        self._cache: OrderedDict[int, tuple[bytes, bytes]] = OrderedDict()
        self._tombstone: tuple[bytes, bytes] | None = None
        self._counters = dict.fromkeys(("rx_frames", "tx_frames", "invalid_frames", "replay_hits", "requests_executed", "heartbeats_accepted", "release_count", "hal_bus_calls"), 0)

    def _count(self, name: str) -> None:
        self._counters[name] = min((1 << 64) - 1, self._counters[name] + 1)

    def _release(self, reason: str) -> None:
        if self.session:
            self.session, self.deadline_ms = 0, None
            self.last_release_reason = reason
            self._cache.clear()
            self._count("release_count")

    def advance(self, ms: int) -> bytes:
        if type(ms) is not int or ms < 0 or self.now_ms + ms >= 1 << 64:
            self._release("clock-error")
            self.closed = True
            raise ValueError("simulator clock 범위 오류")
        self.now_ms += ms
        if self.session and self.now_ms >= self.deadline_ms:
            self._release("heartbeat-timeout")
        return b""

    def _emit(self, wire: bytes) -> bytes:
        self._count("tx_frames")
        return wire

    def _response(self, request: Frame, status: int, payload: bytes = b"", *, session: int | None = None) -> bytes:
        return encode(Frame(type=2, op=request.op, flags=1 if status else 0, seq=request.seq,
                            session=request.session if session is None else session, payload=struct.pack("<H", status) + payload))

    def _hello(self, request: Frame, nonce: bytes) -> bytes:
        # 모델 정책은 driver의 opcode/기대값 상수를 import하지 않는다.
        fields = {"fw_name":"PWEH espprobe", "fw_version":"0.1.0", "build_profile":"probe-hello",
                  "board":"esp32s3-devkitc1-hello", "git_commit":"0"*40,
                  "image_sha256":"11"*32, "app_elf_sha256":"22"*32, "idf_version":"simulator",
                  "chip":{"model":"esp32s3","revision":0,"psram_bytes":None,"flash_voltage_mv":None},
                  "base_mac":"020000000001", "usb":{"vid":12346,"pid":16386,"product":"PWEH espprobe","serial":"020000000001"},
                  "boot_id":self.boot_id, "usb_session":self.usb_session, "reset_reason":"power-on",
                  "last_release_reason":self.last_release_reason, "caps":[],
                  "limits":{"max_payload":4096,"hb_ms":self.hb_ms,"max_credit":0},
                  "pins_allowed":{"H0":[],"H1":[],"H1a":[]}, "pclk_pad":None,"pin_drive":None,
                  "spi_read_opcodes":[],"radio":"none","tx_caps":[],"session_token":self.session,"nonce":nonce.hex()}
        return encode(Frame(type=2, op=1, seq=request.seq, session=self.session, payload=encode_hello(fields)))

    def exchange(self, wire: bytes) -> bytes:
        self.advance(0)
        if self.closed:
            return b""
        try:
            request = decode(wire)
        except ProtocolError:
            self._count("invalid_frames")
            return b""
        self._count("rx_frames")
        if request.type not in (1, 5):
            self._count("invalid_frames")
            return b""
        if request.credit or request.flags:
            return self._emit(self._response(request, 1))
        if request.type == 5:
            if request.op or request.payload:
                return self._emit(self._response(request, 7))
            if not self.session or request.session != self.session:
                return self._emit(self._response(request, 3 if not self.session else 4))
            if request.seq <= self.last_hb_seq:
                return b""
            if self.now_ms > (1 << 64) - 1 - self.hb_ms:
                self._release("clock-error")
                return b""
            self.last_hb_seq, self.deadline_ms = request.seq, self.now_ms + self.hb_ms
            self._count("heartbeats_accepted")
            return self._emit(wire)
        if request.op == 1:
            if request.session:
                return self._emit(self._response(request, 4))
            try:
                values = decode_tlvs(request.payload)
                if set(values) != {1} or len(values[1]) != 16:
                    raise ProtocolError("nonce")
            except ProtocolError:
                return self._emit(self._response(request, 7))
            if self.session:
                if wire == self._hello_request:
                    self._count("replay_hits")
                    return self._emit(self._hello_response)
                return self._emit(self._response(request, 5 if request.seq == self._hello_seq else 6))
            if request.seq <= self._hello_seq:
                return self._emit(self._response(request, 3))
            if self._token == 0xffffffff or self.now_ms > (1 << 64) - 1 - self.hb_ms:
                return self._emit(self._response(request, 3))
            self._token += 1
            self.session = self._token
            self.last_req_seq = self._hello_seq = request.seq
            self.last_hb_seq = 0
            self.deadline_ms = self.now_ms + self.hb_ms
            self._cache.clear()
            self._tombstone = None
            self._hello_request, self._hello_response = wire, self._hello(request, values[1])
            self._count("requests_executed")
            return self._emit(self._hello_response)
        if not self.session:
            if self._tombstone and wire == self._tombstone[0]:
                self._count("replay_hits")
                return self._emit(self._tombstone[1])
            return self._emit(self._response(request, 3))
        if request.session != self.session:
            return self._emit(self._response(request, 4))
        if request.seq in self._cache:
            prior, response = self._cache[request.seq]
            if wire == prior:
                self._count("replay_hits")
                return self._emit(response)
            return self._emit(self._response(request, 5))
        if request.seq <= self.last_req_seq:
            return self._emit(self._response(request, 8))
        self.last_req_seq = request.seq
        if request.op in (2, 3, 4):
            if request.payload:
                response = self._response(request, 7)
            else:
                response = self._response(request, 0)
                self._count("requests_executed")
                self._release({2:"request-release",3:"bye",4:"abort"}[request.op])
                self._tombstone = (wire, response)
                return self._emit(response)
        else:
            response = self._response(request, 2)
        self._cache[request.seq] = (wire, response)
        if len(self._cache) > 4:
            self._cache.popitem(last=False)
        return self._emit(response)

    def transport_event(self, event: str) -> None:
        """단위 시험용 lifecycle 주입. MCP 입력으로 노출하지 않는다."""
        if event not in ("usb-reset", "usb-detach", "usb-suspend", "dtr-fall", "transport-error", "internal-error"):
            raise ValueError("지원하지 않는 synthetic event")
        self._release(event)
        if event in ("usb-reset", "usb-detach"):
            if self.usb_session == 0xffffffff:
                self.closed = True
            else:
                self.usb_session += 1
            self._hello_seq = 0
            self._hello_request = self._hello_response = b""
            self._cache.clear()
            self._tombstone = None

    def snapshot(self) -> dict:
        return {"name":self.name,"state":"active" if self.session else "released","closed":self.closed,
                "session":self.session,"boot_id":self.boot_id,"usb_session":self.usb_session,"now_ms":self.now_ms,
                "deadline_ms":self.deadline_ms,"last_release_reason":self.last_release_reason,
                "last_req_seq":self.last_req_seq,"last_hb_seq":self.last_hb_seq,"counters":dict(self._counters)}

    def close(self) -> None:
        self._release("host-close")
        self.closed = True
        self._cache.clear()
        self._tombstone = None
        self._hello_request = self._hello_response = b""
