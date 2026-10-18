"""openocd-mcp TCL RPC 클라이언트 단위 테스트 (프레이밍/시간 초과/재연결/알림/취소)."""

from __future__ import annotations

import socket
import threading
import time

import pytest

from openocd_mcp import tcl
from openocd_mcp.rpc import RequestCancelled, TclConnectionClosed, TclRpcClient
from pweh.errors import TimeoutExpired

from .fake_openocd import FakeOpenOCD


class ScriptedServer:
    """프레임마다 handler(frame, conn) 를 호출하는 단순 TCP 서버. handler 가 bytes 를 돌려주면 그대로 보낸다."""

    def __init__(self, handler):
        self.handler = handler
        self.sock = socket.socket()
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(8)
        self.port = self.sock.getsockname()[1]
        self.connections = 0
        self._stop = threading.Event()
        threading.Thread(target=self._accept, daemon=True).start()

    def _accept(self):
        self.sock.settimeout(0.2)
        while not self._stop.is_set():
            try:
                conn, _ = self.sock.accept()
            except (socket.timeout, OSError):
                continue
            self.connections += 1
            threading.Thread(target=self._serve, args=(conn,), daemon=True).start()

    def _serve(self, conn):
        buf = b""
        with conn:
            while not self._stop.is_set():
                try:
                    data = conn.recv(65536)
                except OSError:
                    return
                if not data:
                    return
                buf += data
                while b"\x1a" in buf:
                    frame, buf = buf.split(b"\x1a", 1)
                    out = self.handler(frame.decode(), conn)
                    if out == "CLOSE":
                        return
                    if out:
                        conn.sendall(out)

    def close(self):
        self._stop.set()
        self.sock.close()


@pytest.fixture
def fake():
    with FakeOpenOCD() as srv:
        yield srv


def test_basic_calls_and_reconnect_after_exit(fake):
    c = TclRpcClient("127.0.0.1", fake.port)
    r = c.call("version", timeout=5)
    assert r.ok and "xPack" in r.output
    r = c.call_raw("no_such_command", timeout=5)
    assert not r.ok and r.code == 1 and "invalid command name" in r.output
    r = c.call_raw("exit", timeout=5)  # catch 로 잡히지 않음: 빈 응답 후 연결 종료
    assert r.closed and r.code is None and not c.connected
    assert c.call("targets", timeout=5).ok  # 자동 재연결
    c.close()


def test_notifications_are_skipped(fake):
    c = TclRpcClient("127.0.0.1", fake.port)
    assert c.call_raw("tcl notifications on", timeout=5).ok
    r = c.call("halt", timeout=5)  # 같은 소켓에 'type target_event event halted' 알림이 먼저 온다
    assert r.ok and "target halted" in r.log
    assert c.call("targets", timeout=5).ok
    c.close()


def test_embedded_terminator_inside_braced_result():
    srv = ScriptedServer(lambda frame, conn: b"0 {a\x1ab c}\x1a")
    try:
        c = TclRpcClient("127.0.0.1", srv.port)
        r = c.call_raw("echo", timeout=5)
        assert r.ok and r.output == "a\x1ab c"
        c.close()
    finally:
        srv.close()


def test_timeout_then_reconnect():
    state = {"n": 0}

    def handler(frame, conn):
        state["n"] += 1
        if state["n"] == 1:
            return None  # 응답하지 않음
        return b"0 {ok}\x1a"

    srv = ScriptedServer(handler)
    try:
        c = TclRpcClient("127.0.0.1", srv.port)
        t0 = time.monotonic()
        with pytest.raises(TimeoutExpired):
            c.call_raw("slow", timeout=0.5)
        assert time.monotonic() - t0 < 3 and not c.connected
        assert c.call_raw("fast", timeout=5).output == "ok"
        assert srv.connections == 2
        c.close()
    finally:
        srv.close()


def test_stale_bytes_force_reconnect():
    def handler(frame, conn):
        if frame.endswith("first}} _pweh_r] $_pweh_r"):
            def late():
                time.sleep(0.2)
                conn.sendall(b"0 {LATE}\x1a")  # 늦게 도착한 엉뚱한 응답
            threading.Thread(target=late, daemon=True).start()
            return b"0 {one}\x1a"
        return b"0 {two}\x1a"

    srv = ScriptedServer(handler)
    try:
        c = TclRpcClient("127.0.0.1", srv.port)
        assert c.call_raw("first", timeout=5).output == "one"
        time.sleep(0.5)
        assert c.call_raw("second", timeout=5).output == "two"  # LATE 를 응답으로 오인하지 않음
        assert srv.connections == 2
        c.close()
    finally:
        srv.close()


def test_connection_closed_mid_response():
    def handler(frame, conn):
        conn.sendall(b"0 {partial")
        return "CLOSE"

    srv = ScriptedServer(handler)
    try:
        c = TclRpcClient("127.0.0.1", srv.port)
        with pytest.raises(TclConnectionClosed):
            c.call_raw("x", timeout=5)
        c.close()
    finally:
        srv.close()


def test_cancel_check_and_request_validation():
    srv = ScriptedServer(lambda frame, conn: None)
    try:
        c = TclRpcClient("127.0.0.1", srv.port)
        flag = {"cancel": False}
        threading.Timer(0.3, lambda: flag.__setitem__("cancel", True)).start()
        t0 = time.monotonic()
        with pytest.raises(RequestCancelled):
            c.call("dump_image", timeout=30, cancel_check=lambda: flag["cancel"])
        assert time.monotonic() - t0 < 3
        with pytest.raises(ValueError):
            c.call_raw("x" * (tcl.MAX_REQUEST_BYTES + 1), timeout=1)
        with pytest.raises(ValueError):
            c.call_raw("version\x1aversion", timeout=1)
        c.close()
    finally:
        srv.close()


def test_connect_refused_is_device_error():
    from pweh.errors import DeviceError

    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    c = TclRpcClient("127.0.0.1", port, connect_timeout=1)
    with pytest.raises(DeviceError):
        c.call("version", timeout=1)
