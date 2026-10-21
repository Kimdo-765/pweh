"""JTAGulator 연결 발행 전후 오류에서도 물리 핸들·잠금의 정리 소유자를 보존한다."""
from __future__ import annotations

import pytest
from mcp.server.mcpserver.exceptions import ToolError

from pweh.errors import DeviceError
from pweh.serialtransport import SerialOpenError
from jtagulator_mcp import server as J


@pytest.fixture
def anyio_backend():
    return "asyncio"


class FailedTransport:
    def __init__(self):
        self.closed = False
        self.allow_close = False
        self.cleanup_errors = ()

    def close(self):
        if not self.allow_close:
            raise DeviceError("합성 정리 실패", code="serial_close_unverified")
        self.closed = True


@pytest.mark.anyio
async def test_unpublished_open_error_has_explicit_disconnect_cleanup(workspace, auth, monkeypatch, isolated_ports):
    case = J.rt().cases.create(title="합성 JTAG open 정리 실패", authorization=auth)
    transport = FailedTransport()
    def opening(*args, **kwargs):
        raise SerialOpenError(transport, OSError("합성 open 실패"))
    monkeypatch.setattr(J, "SerialLink", opening)
    key = "net-loopback:32176"
    try:
        with pytest.raises(ToolError, match="serial_open_cleanup_failed"):
            await J.jtagulator_connect(case.id, "socket://127.0.0.1:32176")
        assert not J._CONNS and not transport.closed
        assert isolated_ports["manager"].held_by(key)["state"] == "orphan"
        other = J.rt().cases.create(title="다른 합성 케이스", authorization=auth)
        with pytest.raises(ToolError, match="not_found"):
            await J.jtagulator_disconnect(other.id)
        assert not transport.closed
        with pytest.raises(ToolError, match="serial_close_unverified"):
            await J.jtagulator_disconnect(case.id)
        assert isolated_ports["manager"].held_by(key) is not None
        transport.allow_close = True
        result = await J.jtagulator_disconnect(case.id)
        assert result["ok"] and result["cleaned_pending"] == 1
        assert transport.closed and isolated_ports["manager"].held_by(key) is None
        assert not J._CLEANUP_PENDING
    finally:
        transport.allow_close = True
        J._shutdown_all()


@pytest.mark.anyio
@pytest.mark.parametrize("changed", ["none", "before-gate", "after-gate"])
async def test_wired_open_approval_and_fresh_identity(workspace, auth, monkeypatch, isolated_ports, changed):
    from dataclasses import replace
    from pweh import ports

    workspace["set_safety"](modify_policy="approve", approval_methods=["cli"])
    runtime = J.rt()
    case = runtime.cases.create(title="합성 reset 배선 승인", authorization=auth)
    current = ["synthetic-device-a"]
    original_resolve = ports.resolve
    def resolve(*args, **kwargs):
        return replace(original_resolve(*args, **kwargs), reset_risk="wired", device_id=current[0])
    monkeypatch.setattr(ports, "resolve", resolve)
    opened = []
    def opening(*args, **kwargs):
        opened.append(1)
        raise DeviceError("합성 open 도달", code="synthetic_open")
    monkeypatch.setattr(J, "SerialLink", opening)
    port, key = "socket://127.0.0.1:32177", "net-loopback:32177"
    first = await J.jtagulator_connect(case.id, port)
    assert first["status"] == "approval_required" and not opened
    assert isolated_ports["manager"].held_by(key) is None
    record = runtime.approvals.get(first["approval_id"])
    assert record["action"]["route"]["device_id"] == current[0]
    runtime.approvals.decide(record["id"], approve=True, code=record["code"], via="test")
    if changed == "before-gate":
        current[0] = "synthetic-device-b"
    elif changed == "after-gate":
        original_authorize = runtime.authorize
        async def authorize(**kwargs):
            decision = await original_authorize(**kwargs)
            current[0] = "synthetic-device-b"
            return decision
        monkeypatch.setattr(runtime, "authorize", authorize)
    if changed == "none":
        with pytest.raises(ToolError, match="synthetic_open"):
            await J.jtagulator_connect(case.id, port, approval_id=record["id"])
        assert opened == [1]
    elif changed == "after-gate":
        with pytest.raises(ToolError, match="route_changed"):
            await J.jtagulator_connect(case.id, port, approval_id=record["id"])
        assert not opened
    else:
        refused = await J.jtagulator_connect(case.id, port, approval_id=record["id"])
        assert not refused["ok"] and not opened
    assert isolated_ports["manager"].held_by(key) is None


@pytest.mark.anyio
async def test_reader_start_failure_closes_unpublished_jtag_transport(workspace, auth, monkeypatch, isolated_ports):
    import os
    import threading
    from types import SimpleNamespace
    from jtagulator_mcp import driver

    class Unstarted:
        def __init__(self, *args, **kwargs):
            pass
        def start(self):
            raise RuntimeError("합성 reader start 실패")
        def join(self, **kwargs):
            raise RuntimeError("cannot join thread before it is started")
    namespace = dict(vars(threading))
    namespace["Thread"] = Unstarted
    monkeypatch.setattr(driver, "threading", SimpleNamespace(**namespace))
    master, slave = os.openpty()
    case = J.rt().cases.create(title="합성 JTAG reader 실패", authorization=auth)
    try:
        port = os.ttyname(slave)
        route, _ = J._resolve_port(J.rt(), port)
        with pytest.raises(ToolError, match="수신 스레드"):
            await J.jtagulator_connect(case.id, port)
        assert isolated_ports["manager"].held_by(route.lock_key) is None
        assert not J._CONNS and not J._CLEANUP_PENDING
        import serial
        reopened = serial.Serial(port, exclusive=True)
        reopened.close()
    finally:
        J._shutdown_all()
        os.close(master)
        os.close(slave)


@pytest.mark.anyio
async def test_reader_log_failure_still_closes_jtag_transport(workspace, auth, monkeypatch, isolated_ports):
    import anyio
    from jtagulator_mcp.sim import JTAGulatorSim, SimConfig, SimTCPServer

    sim = JTAGulatorSim(SimConfig()).start()
    listener = SimTCPServer(sim)
    case = J.rt().cases.create(title="합성 JTAG 기록 실패", authorization=auth)
    try:
        await J.jtagulator_connect(case.id, listener.url)
        conn = J._CONNS[case.id]
        def broken(*args, **kwargs):
            raise OSError("합성 transcript 실패")
        with monkeypatch.context() as scoped:
            scoped.setattr(conn.transcript, "note", broken)
            listener.drop_client()
            with anyio.fail_after(5):
                while not conn.link.physical_closed or isolated_ports["manager"].held_by(conn.route.lock_key)["state"] != "disconnected":
                    await anyio.sleep(0.01)
        assert not conn.lease.closed
        await J.jtagulator_disconnect(case.id)
        assert conn.lease.closed
    finally:
        J._shutdown_all()
        listener.close()
        sim.stop()


@pytest.mark.anyio
@pytest.mark.parametrize("boundary", ["before", "during", "after", "close-error"])
async def test_raw_task_cancel_connect_ownership(workspace, auth, monkeypatch, isolated_ports, boundary):
    """생성 중 Link의 소유권은 raw 취소 뒤에도 worker의 정리까지 유지한다."""
    import asyncio
    import threading
    import anyio

    case = J.rt().cases.create(title="합성 JTAG raw 취소", authorization=auth)
    port, key = "socket://127.0.0.1:32182", "net-loopback:32182"
    entered, release = threading.Event(), threading.Event()
    transport, calls, delayed = FailedTransport(), [], []
    transport.allow_close = boundary != "close-error"
    original_run = J.run_blocking

    class Link:
        alive = True
        _ser = transport
        @property
        def physical_closed(self):
            return transport.closed
        def close(self):
            transport.close()
            self.alive = False

    class Driver:
        def __init__(self, link, **kwargs):
            self.link = link
        def resync(self, timeout):
            return {}
        def version(self):
            return {"firmware": "1.12", "supported": True, "lines": []}
        def close(self):
            self.link.close()

    def opening(*args, **kwargs):
        calls.append(kwargs["lease"])
        if boundary in ("during", "close-error"):
            entered.set()
            assert release.wait(5)
        return Link()

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

    monkeypatch.setattr(J, "SerialLink", opening)
    monkeypatch.setattr(J, "JTAGulatorDriver", Driver)
    monkeypatch.setattr(J, "run_blocking", blocking)
    task = asyncio.create_task(J.jtagulator_connect(case.id, port))
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
            assert not transport.closed and J._CONNECTING[key] == case.id
            assert case.id not in J._CONNS
        release.set()
        with anyio.fail_after(5):
            while key in J._CONNECTING:
                await anyio.sleep(0.005)
        if boundary == "close-error":
            assert isolated_ports["manager"].held_by(key)["state"] == "orphan"
            assert J._CONNS[case.id].link._ser is transport and not transport.closed
            transport.allow_close = True
            await J.jtagulator_disconnect(case.id)
        elif boundary != "before":
            assert transport.closed
        assert isolated_ports["manager"].held_by(key) is None
        assert case.id not in J._CONNS and case.id not in J._CASE_CONNECTING
    finally:
        release.set()
        transport.allow_close = True
        if not task.done():
            task.cancel()
        J._shutdown_all()
