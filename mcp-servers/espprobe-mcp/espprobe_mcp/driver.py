"""서버 내부 시뮬레이터만 사용하는 제한된 HELLO/HB 드라이버.

실제 포트·소켓·외부 프로세스 전송 계층은 없다. 모델과 별도의 기대값으로 HELLO를 검증하며,
상태의 만료를 먼저 적용한 뒤 요청한다. 종료·스케줄 지연 뒤 자동 재접속하지 않는다.
"""

from __future__ import annotations

import copy
import json
import os
import re
import secrets
import threading
import time
from typing import Any, Callable

from pweh.errors import Busy, NotFound, PwehError, ValidationFailed
from pweh.espprobe_protocol import Frame, ProtocolError, decode, decode_hello, encode, encode_tlvs
from pweh.fsutil import new_id, utcnow_iso
from pweh.safeio import atomic_write_at, open_dir_chain

from .sim import ProbeSimulator

PORT = "sim://probe-hello"
MAX_SESSIONS = 16
MAX_LIFETIME_SECONDS = 600.0

# 이 값은 모델에서 가져오지 않는다. 실제 릴리스 allowlist와도 별개의 합성 시험 계약이다.
EXPECTED = {
    "fw_name": "PWEH espprobe", "fw_version": "0.1.0", "build_profile": "probe-hello",
    "board": "esp32s3-devkitc1-hello", "git_commit": "0" * 40,
    "image_sha256": "11" * 32, "app_elf_sha256": "22" * 32, "idf_version": "simulator",
    "chip": {"model": "esp32s3", "revision": 0, "psram_bytes": None, "flash_voltage_mv": None},
    "base_mac": "020000000001",
    "usb": {"vid": 0x303A, "pid": 0x4002, "product": "PWEH espprobe", "serial": "020000000001"},
    "caps": [], "limits": {"max_payload": 4096, "hb_ms": 1000, "max_credit": 0},
    "pins_allowed": {"H0": [], "H1": [], "H1a": []}, "pclk_pad": None, "pin_drive": None,
    "spi_read_opcodes": [], "radio": "none", "tx_caps": [], "reset_reason": "power-on",
    "last_release_reason": "boot",
}


def verify_hello(frame: Frame, nonce: bytes) -> dict[str, Any]:
    """형식·세션·nonce·정책을 모두 확인한다. 합성 hash는 실제 펌웨어 증명이 아니다."""
    if (frame.type, frame.op, frame.flags, frame.seq, frame.credit) != (2, 1, 0, 1, 0) or not frame.session:
        raise ProtocolError("hello-envelope")
    hello = decode_hello(frame.payload)
    if any(hello.get(key) != value for key, value in EXPECTED.items()):
        raise ProtocolError("hello-policy")
    if hello.get("nonce") != nonce.hex() or hello.get("session_token") != frame.session:
        raise ProtocolError("hello-binding")
    if not isinstance(hello.get("boot_id"), str) or not re.fullmatch(r"[0-9a-f]{32}", hello["boot_id"]):
        raise ProtocolError("hello-boot-id")
    generation = hello.get("usb_session")
    if type(generation) is not int or not 1 <= generation <= 0xFFFFFFFF:
        raise ProtocolError("hello-usb-session")
    return hello


class SimSession:
    """고정 크기 모델과 한 HB worker. 케이스에는 시작·자가시험·종료 요약만 쓴다."""

    def __init__(self, case: Any, *, clock: Callable[[], float] = time.monotonic,
                 factory: Callable[..., Any] = ProbeSimulator, start_worker: bool = True):
        self.case = case
        self.id = new_id("espprobe-sim-", 6)
        self.path = case.path("probe", self.id + ".json")
        self.lock = threading.RLock()
        self.stop = threading.Event()
        self.worker: threading.Thread | None = None
        self.clock = clock
        self.started_clock = self.last_clock = clock()
        self.elapsed_ms = 0
        self.started_at = utcnow_iso()
        self.finished_at: str | None = None
        self.host_stop_reason: str | None = None
        self.record_error: str | None = None
        self.req_seq = 1
        self.hb_seq = 0
        self.self_tests = 0
        self.model = factory(name=PORT, hb_ms=1000)
        self.nonce = secrets.token_bytes(16)
        try:
            request = Frame(type=1, op=1, seq=1, session=0, payload=encode_tlvs({1: self.nonce}))
            reply = decode(self.model.exchange(encode(request)))
            self.hello = verify_hello(reply, self.nonce)
            self.session = reply.session
            self._record()
            if start_worker:
                self.worker = threading.Thread(target=self._heartbeat_loop, name="pweh-espprobe-sim", daemon=True)
                self.worker.start()
        except BaseException:
            self.model.close()
            raise

    def _record(self) -> None:
        doc = self._view()
        doc.update({"schema": "pweh.espprobe-simulator/v1", "hello": self.hello})
        path = self.case.path("probe", self.id + ".json")
        # 세션 동안 경로가 바뀔 수 있다. 확인한 디렉터리 fd 아래에서만 원자적으로 쓴다.
        fd = open_dir_chain(self.case.dir.parent, (self.case.id, "probe"), create=True)
        try:
            atomic_write_at(fd, path.name, (json.dumps(doc, ensure_ascii=False, indent=2) + "\n").encode())
        finally:
            os.close(fd)
        self.case.register_artifact(self.case.path("probe", path.name), kind="other", producer="espprobe-mcp",
                                    description="합성 HELLO/HB 시뮬레이터 결과; 실제 기기 검증 아님")

    def _view(self) -> dict[str, Any]:
        return {"case_id": self.case.id, "session_id": self.id, "port": PORT,
                "simulator_only": True, "hardware_verified": False,
                "started_at": self.started_at, "finished_at": self.finished_at,
                "elapsed_ms": self.elapsed_ms, "max_lifetime_seconds": MAX_LIFETIME_SECONDS,
                "host_stop_reason": self.host_stop_reason, "record_error": self.record_error,
                "self_tests": self.self_tests, "model": self.model.snapshot(),
                "artifact": "probe/" + self.id + ".json"}

    def _finish(self, reason: str) -> None:
        self.stop.set()
        self.model.close()
        if self.finished_at is None:
            self.finished_at = utcnow_iso()
            self.host_stop_reason = reason
            try:
                self._record()
            except Exception as exc:
                self.record_error = type(exc).__name__

    def _advance(self) -> bool:
        if self.stop.is_set():
            return False
        now = self.clock()
        if not self.last_clock <= now or not now < float("inf"):
            self._finish("clock-error")
            return False
        self.last_clock = now
        elapsed = int((now - self.started_clock) * 1000)
        self.model.advance(elapsed - self.elapsed_ms)
        self.elapsed_ms = elapsed
        if now - self.started_clock >= MAX_LIFETIME_SECONDS:
            self._finish("maximum-lifetime")
        elif self.model.snapshot()["state"] != "active":
            self._finish("model-released")
        return not self.stop.is_set()

    def _hb(self) -> None:
        if self.hb_seq == 0xFFFFFFFF:
            raise ProtocolError("sequence-exhausted")
        self.hb_seq += 1
        wire = encode(Frame(type=5, op=0, seq=self.hb_seq, session=self.session))
        if self.model.exchange(wire) != wire:
            raise ProtocolError("heartbeat-ack")

    def _heartbeat_loop(self) -> None:
        while not self.stop.wait(self.hello["limits"]["hb_ms"] / 3000.0):
            with self.lock:
                try:
                    if not self._advance():
                        return
                    self._hb()
                except Exception:
                    self._finish("heartbeat-error")
                    return

    def view(self) -> dict[str, Any]:
        with self.lock:
            self._advance()
            return copy.deepcopy(self._view())

    def self_test(self) -> dict[str, Any]:
        with self.lock:
            self.case.require_authorization()
            if not self._advance():
                raise PwehError("시뮬레이터 세션이 해제되었습니다. 새 connect가 필요합니다.", code="espprobe_released")
            try:
                if any(self.hello.get(key) != value for key, value in EXPECTED.items()):
                    raise ProtocolError("hello-policy")
                self._hb()
                self.self_tests += 1
                self._record()
            except Exception:
                self._finish("self-test-error")
                raise
            return {**self._view(), "checks": {"hello_policy": "passed", "heartbeat_roundtrip": "passed"},
                    "note": "호스트·모델 프로토콜 시험입니다. 핀·USB·실기 하트비트 검증은 포함하지 않습니다."}

    def close(self, *, op: int = 3) -> dict[str, Any]:
        with self.lock:
            if self._advance():
                try:
                    self.req_seq += 1
                    response = decode(self.model.exchange(encode(Frame(type=1, op=op, seq=self.req_seq,
                                                                       session=self.session))))
                    if (response.type, response.op, response.seq, response.flags, response.session,
                        response.payload) != (2, op, self.req_seq, 0, self.session, b"\0\0"):
                        raise ProtocolError("release-ack")
                except Exception:
                    self._finish("close-protocol-error")
                else:
                    self._finish("release" if op == 2 else "disconnect")
            result = copy.deepcopy(self._view())
        if self.worker is not None and self.worker is not threading.current_thread():
            self.worker.join(timeout=2.0)
        return result


class SessionManager:
    """모델 세션은 프로세스 내부에만 존재하며 수명·개수 상한을 가진다."""

    def __init__(self) -> None:
        self.lock = threading.RLock()
        self.sessions: dict[str, SimSession] = {}

    def connect(self, case: Any, port: str) -> dict[str, Any]:
        if port != PORT:
            raise ValidationFailed("I5 1a는 sim://probe-hello만 지원합니다. 실제 포트 전송 계층은 없습니다.")
        case.require_authorization()
        with self.lock:
            old = self.sessions.get(case.id)
            if old is not None:
                if old.view()["model"]["state"] == "active":
                    raise Busy("이 케이스의 시뮬레이터가 이미 연결되어 있습니다.")
                old.close()
                del self.sessions[case.id]
            if len(self.sessions) >= MAX_SESSIONS:
                for key, previous in list(self.sessions.items()):
                    if previous.view()["model"]["state"] != "active":
                        previous.close()
                        del self.sessions[key]
            if len(self.sessions) >= MAX_SESSIONS:
                raise Busy("시뮬레이터 세션 상한(16개)에 도달했습니다.")
            session = SimSession(case)
            self.sessions[case.id] = session
            return {**session.view(), "hello": copy.deepcopy(session.hello)}

    def get(self, case_id: str) -> SimSession:
        with self.lock:
            if case_id not in self.sessions:
                raise NotFound("이 케이스에 열린 espprobe 시뮬레이터가 없습니다.")
            return self.sessions[case_id]

    def status(self, case_id: str | None = None) -> list[dict[str, Any]]:
        with self.lock:
            return [item.view() for key, item in self.sessions.items() if case_id is None or key == case_id]

    def disconnect(self, case_id: str) -> dict[str, Any]:
        with self.lock:
            item = self.sessions.pop(case_id, None)
            if item is None:
                return {"case_id": case_id, "disconnected": True, "already_disconnected": True,
                        "simulator_only": True, "hardware_verified": False}
            return {**item.close(), "disconnected": True}

    def close_all(self) -> None:
        with self.lock:
            for item in self.sessions.values():
                item.close()
            self.sessions.clear()
