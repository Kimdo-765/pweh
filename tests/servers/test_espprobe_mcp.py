"""시뮬레이터 MCP 왕복·수명·실제 전송 입구 부재. 모든 케이스는 합성이다."""

from __future__ import annotations

import json
import threading

import anyio
import pytest
from mcp import Client

from mcp_helpers import call, stdio_params
from pweh.case import CaseStore
from pweh.espprobe_protocol import Frame, ProtocolError, decode, encode, encode_hello

pytestmark = pytest.mark.anyio


@pytest.fixture
def anyio_backend():
    return "asyncio"


@pytest.fixture
def probe_case(workspace, auth):
    return CaseStore(workspace["cases_dir"]).create(title="합성 계측기 프로토콜", authorization=auth, case_id="probe-test")


@pytest.fixture
def srv(probe_case, monkeypatch):
    from espprobe_mcp import server
    from espprobe_mcp.driver import SessionManager
    monkeypatch.setattr(server, "manager", SessionManager())

    def forbidden(*_args, **_kwargs):
        raise AssertionError("시뮬레이터에서 실제 포트를 열려고 함")

    import serial
    monkeypatch.setattr(serial, "serial_for_url", forbidden)
    monkeypatch.setattr(serial, "Serial", forbidden)
    yield server
    server.manager.close_all()
    assert not any(t.name == "pweh-espprobe-sim" and t.is_alive() for t in threading.enumerate())


async def test_mcp_lifecycle_and_idle_heartbeat(probe_case, srv):
    async with Client(srv.server) as c:
        tools = {t.name for t in (await c.list_tools()).tools}
        assert tools == {"espprobe_version", "espprobe_connect", "espprobe_status", "espprobe_self_test",
                         "espprobe_release_all", "espprobe_disconnect"}
        connected = await call(c, "espprobe_connect", case_id=probe_case.id)
        assert connected["simulator_only"] and not connected["hardware_verified"], connected
        assert connected["hello"]["caps"] == []
        await anyio.sleep(1.1)  # 유휴 중 HB가 없으면 1초에 해제된다.
        tested = await call(c, "espprobe_self_test", case_id=probe_case.id)
        assert tested["checks"]["heartbeat_roundtrip"] == "passed", tested
        assert tested["model"]["counters"]["heartbeats_accepted"] >= 3
        assert tested["model"]["counters"]["hal_bus_calls"] == 0
        released = await call(c, "espprobe_release_all", case_id=probe_case.id)
        assert released["model"]["state"] == "released"
        again = await call(c, "espprobe_release_all", case_id=probe_case.id)
        assert again["model"]["counters"]["release_count"] == 1
        assert "espprobe_released" in (await call(c, "espprobe_self_test", case_id=probe_case.id))["_error"]
        done = await call(c, "espprobe_disconnect", case_id=probe_case.id)
        assert done["disconnected"]
        assert (await call(c, "espprobe_disconnect", case_id=probe_case.id))["already_disconnected"]
    saved = json.loads(probe_case.path(connected["artifact"]).read_text())
    assert saved["model"]["closed"] and saved["hardware_verified"] is False
    assert probe_case.artifacts()[0]["kind"] == "other"


@pytest.mark.parametrize("port", ["COM3", "/dev/ttyUSB0", "socket://127.0.0.1:9", "loop://", "sim://probe-hello?port=COM3"])
async def test_all_nonmodel_ports_refused(probe_case, srv, port):
    async with Client(srv.server) as c:
        result = await call(c, "espprobe_connect", case_id=probe_case.id, port=port)
        assert "validation_failed" in result["_error"]
        assert (await call(c, "espprobe_status"))["sessions"] == []


async def test_cleanup_after_authorization_revocation_and_lifespan(probe_case, srv):
    async with Client(srv.server) as c:
        await call(c, "espprobe_connect", case_id=probe_case.id)
        probe_case._update(lambda meta: meta.update(authorization={}))
        assert "authorization_required" in (await call(c, "espprobe_self_test", case_id=probe_case.id))["_error"]
        assert (await call(c, "espprobe_disconnect", case_id=probe_case.id))["disconnected"]
    assert not srv.manager.sessions


def test_missed_deadline_is_applied_before_next_hb(probe_case):
    from espprobe_mcp.driver import SimSession
    now = [0.0]
    session = SimSession(probe_case, clock=lambda: now[0], start_worker=False)
    now[0] = 1.0
    with pytest.raises(Exception, match="espprobe_released"):
        session.self_test()
    result = session.view()
    assert result["model"]["last_release_reason"] == "heartbeat-timeout"
    assert result["model"]["counters"]["heartbeats_accepted"] == 0
    session.close()


def test_maximum_lifetime_and_clock_rollback_release(probe_case, monkeypatch):
    from espprobe_mcp import driver
    monkeypatch.setattr(driver, "MAX_LIFETIME_SECONDS", 0.5)
    now = [10.0]
    session = driver.SimSession(probe_case, clock=lambda: now[0], start_worker=False)
    now[0] = 10.5
    assert session.view()["host_stop_reason"] == "maximum-lifetime"
    session.close()
    session = driver.SimSession(probe_case, clock=lambda: now[0], start_worker=False)
    now[0] = 10.0
    assert session.view()["host_stop_reason"] == "clock-error"
    session.close()


@pytest.mark.parametrize("field,value", [("image_sha256", "33" * 32), ("nonce", "00" * 16),
                                        ("usb", {"vid": 1, "pid": 2, "product": "x", "serial": "020000000001"})])
def test_host_rejects_mutated_hello_before_worker_or_artifact(probe_case, field, value):
    from espprobe_mcp.driver import SimSession
    from espprobe_mcp.sim import ProbeSimulator
    from pweh.espprobe_protocol import decode_hello

    class WrongHello(ProbeSimulator):
        def exchange(self, wire):
            response = super().exchange(wire)
            frame = decode(response)
            values = decode_hello(frame.payload)
            values[field] = value
            return encode(Frame(type=2, op=1, seq=1, session=frame.session, payload=encode_hello(values)))

    with pytest.raises(ProtocolError):
        SimSession(probe_case, factory=WrongHello)
    assert not probe_case.artifacts()


async def test_real_stdio_simulator_smoke(probe_case):
    async with Client(stdio_params("espprobe_mcp")) as c:
        result = await call(c, "espprobe_connect", case_id=probe_case.id)
        assert result["simulator_only"] and result["hello"]["idf_version"] == "simulator", result
        assert (await call(c, "espprobe_self_test", case_id=probe_case.id))["ok"]
        assert (await call(c, "espprobe_disconnect", case_id=probe_case.id))["disconnected"]


@pytest.mark.parametrize("during_write", [False, True])
def test_record_parent_replacement_never_writes_outside(probe_case, tmp_path, monkeypatch, during_write):
    from espprobe_mcp import driver
    session = driver.SimSession(probe_case, start_worker=False)
    outside = tmp_path / "outside"
    outside.mkdir()
    parent = probe_case.path("probe")

    def replace_parent():
        parent.rename(parent.with_name("probe-old"))
        parent.symlink_to(outside, target_is_directory=True)

    if during_write:
        original = driver.atomic_write_at

        def racing_write(*args, **kwargs):
            replace_parent()
            return original(*args, **kwargs)

        monkeypatch.setattr(driver, "atomic_write_at", racing_write)
    else:
        replace_parent()
    with pytest.raises(Exception):
        session.self_test()
    assert not list(outside.iterdir())
    assert session.view()["model"]["closed"]
    assert session.view()["artifact"] == "probe/" + session.id + ".json"
    session.close()
