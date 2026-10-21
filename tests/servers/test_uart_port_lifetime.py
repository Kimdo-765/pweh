"""합성 transport로 UART 탐지·세션의 잠금 인계와 정리 수명을 고정한다."""
from __future__ import annotations

import asyncio
import threading
import time

import anyio
import pytest

from pweh import ports, portlock
from pweh.errors import DeviceError, PwehError
from pweh.safety import Risk
from uart_mcp import baud
from uart_mcp import server as U
from uart_mcp.session import UartSession


class FakeTransport:
    def __init__(self):
        self.closed = False
        self.allow_close = True
        self.close_count = 0
        self.rates = []
        self.reset_count = 0
        self.writes = []
        self.cleanup_errors = ()

    @property
    def baudrate(self):
        return self.rates[-1] if self.rates else 115200

    @baudrate.setter
    def baudrate(self, value):
        self.rates.append(value)
        if value == 57600:
            raise ValueError("합성 미지원 속도")

    def reset_input_buffer(self):
        self.reset_count += 1

    def read(self, count):
        time.sleep(0.001)
        return b""

    def write(self, data):
        self.writes.append(data)
        return len(data)

    def flush(self):
        pass

    def cancel_read(self):
        pass

    def close(self):
        self.close_count += 1
        if not self.allow_close:
            raise DeviceError("합성 close 실패", code="serial_close_unverified")
        self.closed = True

    def metadata(self):
        return {"closed": self.closed, "exclusive": "synthetic"}


@pytest.fixture
def anyio_backend():
    return "asyncio"


@pytest.fixture(autouse=True)
def cleanup():
    yield
    for row in list(U._CLEANUP_PENDING.values()):
        if row[1] is not None:
            row[1].allow_close = True
    for session in list(U._SESSIONS.values()):
        if session.ser is not None and hasattr(session.ser, "allow_close"):
            session.ser.allow_close = True
    U.shutdown_all("합성 수명 시험 종료")


def test_baud_changes_rate_without_reopen(monkeypatch):
    transport = FakeTransport()
    opened = []
    def opening(settings, **kwargs):
        opened.append(settings)
        return transport
    monkeypatch.setattr(baud, "open_serial", opening)
    result = baud.detect("loop://", [9600, 57600, 115200], 0.005, "none", early_stop=False)
    assert len(opened) == 1
    assert opened[0].dtr is False and opened[0].rts is False
    assert transport.rates == [9600, 57600, 115200]
    assert transport.reset_count == 2 and transport.close_count == 1
    assert result["tested"] == [9600, 115200] and result["errors"]


def test_baud_guard_refusal_closes_without_next_candidate(monkeypatch):
    transport = FakeTransport()
    def guard():
        if transport.rates:
            raise PwehError("합성 guard 거부", code="instrument_port_forbidden")
    monkeypatch.setattr(baud, "open_serial", lambda *a, **k: transport)
    with pytest.raises(PwehError, match="합성 guard"):
        baud.detect("loop://", [9600, 115200], 0.005, "none", before_io=guard)
    assert transport.rates == [9600] and transport.closed and transport.close_count == 1


def test_baud_read_error_is_not_reopen(monkeypatch):
    transport = FakeTransport()
    calls = []
    def read(count):
        raise DeviceError("합성 read 단절")
    def opening(*args, **kwargs):
        calls.append(1)
        return transport
    transport.read = read
    monkeypatch.setattr(baud, "open_serial", opening)
    with pytest.raises(DeviceError, match="read 단절"):
        baud.detect("loop://", [9600, 115200], 0.005, "none")
    assert calls == [1] and transport.closed and transport.rates == [9600]


@pytest.mark.anyio
async def test_cancel_before_worker_claim_prevents_late_open(workspace, auth, monkeypatch, isolated_ports):
    case = U.rt().cases.create(title="합성 늦은 worker", authorization=auth)
    captured = []
    async def late(fn, *, on_cancel):
        captured.append(fn)
        on_cancel()
        raise asyncio.CancelledError()
    monkeypatch.setattr(U, "run_blocking_cancellable", late)
    monkeypatch.setattr(baud, "detect", lambda *a, **k: pytest.fail("취소한 worker가 포트를 엶"))
    port = "socket://127.0.0.1:32170"
    with pytest.raises(asyncio.CancelledError):
        await U.uart_detect_baud(case.id, port, None, candidates=[9600], probe="none")
    assert isolated_ports["manager"].held_by("net-loopback:32170") is None
    assert captured[0]() is None
    assert not U._RESERVED


@pytest.mark.anyio
async def test_cancel_after_worker_claim_keeps_lease_until_close(workspace, auth, monkeypatch, isolated_ports):
    case = U.rt().cases.create(title="합성 실행 중 worker", authorization=auth)
    entered, release, finished = threading.Event(), threading.Event(), threading.Event()
    transport = FakeTransport()
    def detect(*args, **kwargs):
        kwargs["on_transport"](transport)
        entered.set()
        assert release.wait(5)
        assert kwargs["cancel"]()
        transport.close()
        return {"best": None, "tested": []}
    monkeypatch.setattr(baud, "detect", detect)
    port, key = "socket://127.0.0.1:32171", "net-loopback:32171"
    async def caller():
        try:
            await U.uart_detect_baud(case.id, port, None, candidates=[9600], probe="none")
        finally:
            finished.set()
    try:
        async with anyio.create_task_group() as group:
            group.start_soon(caller)
            with anyio.fail_after(5):
                while not entered.is_set():
                    await anyio.sleep(0.005)
            group.cancel_scope.cancel()
        assert finished.is_set()
        assert isolated_ports["manager"].held_by(key) is not None
        assert not transport.closed and U._RESERVED
    finally:
        release.set()
    with anyio.fail_after(5):
        while isolated_ports["manager"].held_by(key) is not None:
            await anyio.sleep(0.005)
    assert transport.closed and not U._RESERVED


def test_failed_close_keeps_orphan_until_matching_retry(isolated_ports):
    route = ports.resolve({"kind": "NATIVE_LINUX"}, "socket://127.0.0.1:32172", "serial-session")
    lease = isolated_ports["manager"].acquire((route.lock_key,), owner=portlock.PortOwner("uart-mcp", "case-a", route.ref))
    transport = FakeTransport()
    transport.allow_close = False
    U._RESERVED[route.lock_key] = "synthetic-detect"
    U._release_detect(lease, transport, route.lock_key, "synthetic-detect", "case-a")
    transport.allow_close = True
    U._retry_detect_cleanup("case-b", route.lock_key)
    assert not lease.closed and not transport.closed
    U._retry_detect_cleanup("case-a", route.lock_key)
    assert lease.closed and transport.closed and not U._RESERVED
    assert not U._CLEANUP_PENDING


@pytest.mark.anyio
async def test_unknown_url_reopen_does_not_inherit_last_command(workspace, auth, monkeypatch):
    case = U.rt().cases.create(title="합성 URL 명령 기억", authorization=auth)
    def opening(self):
        self.ser = FakeTransport()
        self.state = "open"
    monkeypatch.setattr(UartSession, "open", opening)
    first = await U.uart_open(case.id, "socket://127.0.0.1:32173", None)
    old = U._SESSIONS[first["session_id"]]
    old.last_command = "version"
    await U.uart_close(old.id)
    second = await U.uart_open(case.id, "socket://127.0.0.1:32173", None)
    new = U._SESSIONS[second["session_id"]]
    assert new.last_command is None and "inherited_last_command" not in second
    new.manual_context = "uboot"
    plan = new.plan(b"\r")
    assert plan.classification.risk == Risk.DESTRUCTIVE


@pytest.mark.anyio
async def test_disconnected_session_keeps_lease_until_explicit_close(workspace, auth, monkeypatch, isolated_ports):
    case = U.rt().cases.create(title="합성 disconnected 잠금", authorization=auth)
    def opening(self):
        self.ser = FakeTransport()
        self.state = "open"
    monkeypatch.setattr(UartSession, "open", opening)
    opened = await U.uart_open(case.id, "socket://127.0.0.1:32174", None)
    session = U._SESSIONS[opened["session_id"]]
    session._on_disconnect(DeviceError("합성 수신 단절"))
    assert session.ser.closed and session.state == "disconnected"
    assert isolated_ports["manager"].held_by(session.route.lock_key) is not None
    await U.uart_close(session.id)
    assert isolated_ports["manager"].held_by(session.route.lock_key) is None


@pytest.mark.anyio
async def test_open_failure_with_live_handle_preserves_session_cleanup(workspace, auth, monkeypatch, isolated_ports):
    from mcp.server.mcpserver.exceptions import ToolError
    from pweh.serialtransport import SerialOpenError
    from uart_mcp import session as session_module

    case = U.rt().cases.create(title="합성 UART open 정리 실패", authorization=auth)
    transport = FakeTransport()
    transport.allow_close = False
    def opening(*args, **kwargs):
        raise SerialOpenError(transport, OSError("합성 open 실패"))
    monkeypatch.setattr(session_module, "open_serial", opening)
    with pytest.raises(ToolError, match="serial_open_cleanup_failed"):
        await U.uart_open(case.id, "socket://127.0.0.1:32175", None)
    session = next(s for s in U._SESSIONS.values() if s.case_id == case.id)
    assert session.ser is transport and not session.lease.closed
    assert isolated_ports["manager"].held_by(session.route.lock_key)["state"] == "orphan"
    transport.allow_close = True
    await U.uart_close(session.id)
    assert session.lease.closed and transport.closed


@pytest.mark.anyio
@pytest.mark.parametrize("failed_log", ["event", "note"])
async def test_disconnect_log_failure_still_closes_physical_port(workspace, auth, monkeypatch, isolated_ports, failed_log):
    import os

    master, slave = os.openpty()
    case = U.rt().cases.create(title="합성 disconnected 기록 실패", authorization=auth)
    try:
        opened = await U.uart_open(case.id, os.ttyname(slave), None)
        session = U._SESSIONS[opened["session_id"]]
        def broken(*args, **kwargs):
            raise OSError("합성 로그 쓰기 실패")
        with monkeypatch.context() as scoped:
            scoped.setattr(session.logs, failed_log, broken)
            session._on_disconnect(DeviceError("합성 read 실패"))
        assert session.ser.closed and not session.lease.closed
        assert isolated_ports["manager"].held_by(session.route.lock_key)["state"] == "disconnected"
        await U.uart_close(session.id)
        assert session.lease.closed
    finally:
        U.shutdown_all()
        os.close(master)
        os.close(slave)


@pytest.mark.anyio
async def test_unstarted_reader_does_not_skip_uart_physical_close(workspace, auth, monkeypatch, isolated_ports):
    import os
    from types import SimpleNamespace
    from mcp.server.mcpserver.exceptions import ToolError
    from uart_mcp import session as session_module

    class Unstarted:
        def __init__(self, *args, **kwargs):
            pass
        def start(self):
            raise RuntimeError("합성 Thread.start 실패")
        def join(self, **kwargs):
            raise RuntimeError("cannot join thread before it is started")
    namespace = dict(vars(threading))
    namespace["Thread"] = Unstarted
    monkeypatch.setattr(session_module, "threading", SimpleNamespace(**namespace))
    master, slave = os.openpty()
    case = U.rt().cases.create(title="합성 UART reader 실패", authorization=auth)
    try:
        port = os.ttyname(slave)
        route, _ = U._resolve_port(U.rt(), port)
        with pytest.raises(ToolError, match="Thread.start"):
            await U.uart_open(case.id, port, None)
        assert isolated_ports["manager"].held_by(route.lock_key) is None
        assert not U._SESSIONS
        # TIOCEXCL과 pyserial flock이 모두 해제돼 다시 열 수 있어야 한다.
        import serial
        reopened = serial.Serial(port, exclusive=True)
        reopened.close()
    finally:
        os.close(master)
        os.close(slave)


@pytest.mark.anyio
@pytest.mark.parametrize("boundary", ["before", "during", "after", "close-error"])
async def test_raw_task_cancel_open_ownership(workspace, auth, monkeypatch, isolated_ports, boundary):
    """raw Task.cancel도 미완료 open의 lease를 풀거나 뒤늦은 핸들을 버리지 않는다."""
    from uart_mcp import session as session_module

    case = U.rt().cases.create(title="합성 UART raw 취소", authorization=auth)
    port, key = "socket://127.0.0.1:32181", "net-loopback:32181"
    entered, release = threading.Event(), threading.Event()
    transport, calls, delayed = FakeTransport(), [], []
    transport.allow_close = boundary != "close-error"
    original_run = U.run_blocking

    def opening(*args, **kwargs):
        calls.append(kwargs["lease"])
        if boundary in ("during", "close-error"):
            entered.set()
            assert release.wait(5)
        return transport

    async def blocking(fn, *args, **kwargs):
        if getattr(fn, "__name__", "") == "opening" and boundary == "before":
            delayed.append(fn)
            entered.set()
            await asyncio.Event().wait()
        result = await original_run(fn, *args, **kwargs)
        if getattr(fn, "__name__", "") == "opening" and boundary == "after":
            entered.set()
            await asyncio.Event().wait()
        return result

    monkeypatch.setattr(session_module, "open_serial", opening)
    monkeypatch.setattr(U, "run_blocking", blocking)
    task = asyncio.create_task(U.uart_open(case.id, port, None))
    try:
        with anyio.fail_after(5):
            while not entered.is_set():
                await anyio.sleep(0.005)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        if boundary == "before":
            assert not calls and isolated_ports["manager"].held_by(key) is None
            delayed[0]()
            assert not calls
        elif boundary in ("during", "close-error"):
            assert isolated_ports["manager"].held_by(key) is not None
            assert not transport.closed and key in U._RESERVED
            assert not any(s.case_id == case.id for s in U._SESSIONS.values())
        release.set()
        with anyio.fail_after(5):
            while key in U._RESERVED:
                await anyio.sleep(0.005)
        if boundary == "close-error":
            assert isolated_ports["manager"].held_by(key)["state"] == "orphan"
            session = next(s for s in U._SESSIONS.values() if s.case_id == case.id)
            assert session.ser is transport and not transport.closed
            transport.allow_close = True
            await U.uart_close(session.id)
        elif boundary != "before":
            assert transport.closed
        assert isolated_ports["manager"].held_by(key) is None
        assert not any(s.case_id == case.id for s in U._SESSIONS.values())
    finally:
        release.set()
        transport.allow_close = True
        if not task.done():
            task.cancel()
