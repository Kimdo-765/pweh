"""외부 실행 소비자의 route/lease 수명. 포트·PnP는 합성 provider만 사용한다."""
from __future__ import annotations

import json
import os
import stat
import threading
from dataclasses import replace
from types import SimpleNamespace

import anyio
import pytest
from mcp import Client

from mcp_helpers import call
from pweh import portlock, ports
from pweh.portidentity import PortIdentity
from servers.test_esp_mcp import fake as esp_fake, _wait_job
from servers.test_sigrok_mcp import fake as sigrok_fake

pytestmark = pytest.mark.anyio


@pytest.fixture
def anyio_backend():
    return "asyncio"


def fake_probe(*, identity=None, inode=100):
    return ports.PortProbe(stat=lambda p: SimpleNamespace(st_mode=stat.S_IFCHR | 0o600, st_dev=1,
                           st_ino=inode, st_rdev=os.makedev(166, 0)), realpath=lambda p: p, identity=identity)


def known(ref, *, serial="synthetic-probe", native=False):
    return PortIdentity(ref, status="known", present=True, backend="linux", usb_ancestor="synthetic-usb-parent",
                        vid="303a" if native else "10c4", pid="1001" if native else "ea60",
                        interface_number="00", serial=serial)


def busy(manager, key):
    with pytest.raises(Exception, match="busy"):
        manager.acquire([key], owner=portlock.PortOwner("synthetic", "test", "/dev/ttyACM0"))


async def test_esp_gate_holds_lease_and_denial_releases(esp_fake, auth, monkeypatch, isolated_ports):
    from esp_mcp import server as srv
    esp_fake.workspace["set_safety"](modify_policy="deny")
    r = srv.rt()
    case = r.cases.create(title="합성 gate lease", authorization=auth)
    gate = r.authorize
    entered, release = anyio.Event(), anyio.Event()
    result = []
    async def waiting(**kwargs):
        assert kwargs["action"]["route"] == {"backend": "posix-tty", "lock_key": "tty:166:0", "device_id": None}
        entered.set()
        await release.wait()
        return await gate(**kwargs)
    monkeypatch.setattr(r, "authorize", waiting)
    async with Client(srv.server) as c:
        async def run():
            result.append(await call(c, "esp_chip_info", case_id=case.id, port="/dev/ttyACM0"))
        async with anyio.create_task_group() as group:
            group.start_soon(run)
            with anyio.fail_after(10):
                await entered.wait()
            busy(isolated_ports["manager"], "tty:166:0")
            release.set()
    assert result[0]["status"] == "denied"
    assert isolated_ports["manager"].held_by("tty:166:0") is None
    assert not esp_fake.calls("flash-id")


@pytest.mark.parametrize("change", ["node", "identity", "scope"])
async def test_esp_fresh_binding_or_scope_change_never_spawns(esp_fake, auth, monkeypatch, isolated_ports, change):
    from esp_mcp import server as srv
    state = {"fresh": False}
    def identity(ref):
        return known(ref, serial="changed" if state["fresh"] and change == "identity" else "synthetic-probe", native=change == "scope")
    monkeypatch.setattr(srv, "_port_probe", lambda: fake_probe(identity=identity, inode=101 if state["fresh"] and change == "node" else 100))
    monkeypatch.setattr(ports, "probe_siblings", lambda route, **kw: ports.SiblingScope(
        ("tty:166:0", "tty:166:1") if state["fresh"] else ("tty:166:0",), route.identity.usb_ancestor, True, ()))
    r = srv.rt()
    case = r.cases.create(title="합성 변경 감지", authorization=auth)
    gate = r.authorize
    async def changed(**kwargs):
        result = await gate(**kwargs)
        state["fresh"] = True
        return result
    monkeypatch.setattr(r, "authorize", changed)
    async with Client(srv.server) as c:
        result = await call(c, "esp_chip_info", case_id=case.id, port="/dev/ttyACM0")
    assert "route_changed" in result.get("_error", ""), result
    assert not esp_fake.calls("flash-id")
    assert not list(case.subdir("uart").glob("esptool-chip-info-*.log"))
    assert isolated_ports["manager"].held_by("tty:166:0") is None
    assert isolated_ports["manager"].held_by("tty:166:1") is None


async def test_esp_incomplete_whole_device_is_pre_gate(esp_fake, auth, monkeypatch):
    from esp_mcp import server as srv
    monkeypatch.setattr(srv, "_port_probe", lambda: fake_probe(identity=lambda ref: known(ref, native=True)))
    monkeypatch.setattr(ports, "probe_siblings", lambda route, **kw: ports.SiblingScope(("tty:166:0",), route.identity.usb_ancestor, False, ("incomplete",)))
    r = srv.rt()
    case = r.cases.create(title="합성 불완전 scope", authorization=auth)
    monkeypatch.setattr(r, "authorize", lambda **kw: pytest.fail("불완전 scope에서 gate 실행"))
    async with Client(srv.server) as c:
        result = await call(c, "esp_chip_info", case_id=case.id, port="/dev/ttyACM0")
    assert "port_scope_unknown" in result.get("_error", ""), result
    assert not esp_fake.calls()


async def test_esp_windows_holder_unknown_refuses_before_version(esp_fake, auth, monkeypatch, isolated_ports):
    from esp_mcp import server as srv
    from esp_mcp import winproc
    r = srv.rt()
    case = r.cases.create(title="합성 Windows 조회 실패", authorization=auth)
    monkeypatch.setattr(winproc, "port_holders", lambda *a, **kw: None)
    async with Client(srv.server) as c:
        result = await call(c, "esp_chip_info", case_id=case.id, port="COM4096")
    assert "port_holder_unknown" in result.get("_error", ""), result
    assert not esp_fake.calls()
    assert isolated_ports["manager"].held_by("win:COM4096") is None


async def test_esp_read_gap_and_changed_read2_hold_same_lease(esp_fake, auth, monkeypatch, isolated_ports):
    from esp_mcp import server as srv
    state = {"fresh": False}
    monkeypatch.setattr(srv, "_port_probe", lambda: fake_probe(identity=lambda ref: known(ref, serial="changed" if state["fresh"] else "synthetic-probe")))
    r = srv.rt()
    case = r.cases.create(title="합성 두 읽기 lease", authorization=auth)
    original = srv.run_streaming
    entered, release = threading.Event(), threading.Event()
    def paused(*args, **kw):
        result = original(*args, **kw)
        entered.set()
        assert release.wait(10)
        return result
    monkeypatch.setattr(srv, "run_streaming", paused)
    try:
        async with Client(srv.server) as c:
            started = await call(c, "esp_read_flash_start", case_id=case.id, port="/dev/ttyACM0", size="4K")
            assert started.get("job_id"), started
            with anyio.fail_after(10):
                while not entered.is_set():
                    await anyio.sleep(.02)
            busy(isolated_ports["manager"], "tty:166:0")
            state["fresh"] = True
            release.set()
            done = await _wait_job(c, started["job_id"])
        assert done["status"] == "failed", done
        assert len(esp_fake.calls("read-flash")) == 1
        assert isolated_ports["manager"].held_by("tty:166:0") is None
    finally:
        release.set()


async def test_esp_unknown_cleanup_preserves_lease_and_token(esp_fake, auth, monkeypatch, isolated_ports):
    from esp_mcp import server as srv
    from esp_mcp import winproc
    r = srv.rt()
    case = r.cases.create(title="합성 종료 미확인", authorization=auth)
    original = srv.run_streaming
    def unknown(*args, **kw):
        return replace(original(*args, **kw), cleanup_verified=False, orphan_check_failed=True)
    monkeypatch.setattr(srv, "run_streaming", unknown)
    async with Client(srv.server) as c:
        started = await call(c, "esp_read_flash_start", case_id=case.id, port="COM4096", size="4K")
        assert started.get("job_id"), started
        done = await _wait_job(c, started["job_id"])
        assert done["status"] == "failed", done
        assert isolated_ports["manager"].held_by("win:COM4096")["state"] == "orphan"
        owner = next(case.subdir("dumps").glob("*.owner.partial"))
        record = json.loads(owner.read_text())
        assert record["windows_tokens"]
        monkeypatch.setattr(winproc, "query", lambda *a, **kw: (_ for _ in ()).throw(OSError("synthetic query failure")))
        again = await call(c, "esp_chip_info", case_id=case.id, port="COM4096")
        assert "busy" in again.get("_error", ""), again
        assert owner.exists()
        assert len(esp_fake.calls("read-flash")) == 1


@pytest.mark.parametrize("consumer", ["esp", "sigrok"])
async def test_job_registration_failure_closes_lease_and_reservation(consumer, esp_fake, sigrok_fake, auth, monkeypatch, isolated_ports):
    from esp_mcp import server as esp
    from sigrok_mcp import server as sig
    srv = esp if consumer == "esp" else sig
    monkeypatch.setattr(sig, "_port_probe", fake_probe)
    monkeypatch.setattr(sig, "device_users", lambda p: [])
    r = srv.rt()
    case = r.cases.create(title="합성 등록 실패", authorization=auth)
    monkeypatch.setattr(r.jobs, "start", lambda *a, **kw: (_ for _ in ()).throw(RuntimeError("synthetic start failure")))
    async with Client(srv.server) as c:
        if consumer == "esp":
            result = await call(c, "esp_read_flash_start", case_id=case.id, port="/dev/ttyACM0", size="4K")
        else:
            result = await call(c, "sigrok_capture", case_id=case.id, driver="ols", conn="/dev/ttyACM0", samples=100, background=True)
    assert "synthetic start failure" in result.get("_error", ""), result
    assert isolated_ports["manager"].held_by("tty:166:0") is None
    assert not list(case.subdir("dumps").glob("*.partial*"))
    assert not list(case.subdir("signals").glob("*.partial*"))


async def test_sigrok_serial_role_denies_but_usb_unaffected(sigrok_fake, auth, monkeypatch, isolated_ports):
    from sigrok_mcp import server as srv
    monkeypatch.setattr(srv, "_port_probe", fake_probe)
    monkeypatch.setattr(srv, "device_users", lambda p: [])
    r = srv.rt()
    case = r.cases.create(title="합성 serial role", authorization=auth)
    calls = []
    def reject(route):
        calls.append(route.lock_key)
        from pweh.errors import PwehError
        raise PwehError("합성 target 역할", code="port_role_conflict")
    monkeypatch.setattr(isolated_ports["roles"], "assert_probe_allowed", reject)
    async with Client(srv.server) as c:
        result = await call(c, "sigrok_scan", case_id=case.id, driver="ols", conn="/dev/ttyACM0")
        assert "port_role_conflict" in result.get("_error", ""), result
        result = await call(c, "sigrok_scan", driver="fx2lafw", conn="1.2")
        assert result.get("ok"), result
    assert calls == ["tty:166:0"]
    assert isolated_ports["manager"].held_by("tty:166:0") is None


async def test_posix_unknown_dump_reservation_survives_sweep_until_confirmed(esp_fake, auth, monkeypatch, isolated_ports):
    from esp_mcp import server as srv
    from pweh import procutil
    r = srv.rt()
    case = r.cases.create(title="합성 POSIX 예약 보존", authorization=auth)
    original = srv.run_streaming
    monkeypatch.setattr(srv, "run_streaming", lambda *a, **kw: replace(original(*a, **kw), cleanup_verified=False))
    async with Client(srv.server) as c:
        started = await call(c, "esp_read_flash_start", case_id=case.id, port="/dev/ttyACM0", size="4K")
        done = await _wait_job(c, started["job_id"])
    assert done["status"] == "failed", done
    owner = next(case.subdir("dumps").glob("*.owner.partial"))
    assert srv._reservation_state(owner)[0] == "live"
    assert not srv._sweep_dumps_dir(case.subdir("dumps"), case.id)
    assert owner.exists()
    with monkeypatch.context() as patch:
        patch.setattr(procutil, "process_group_empty", lambda *a, **kw: None)
        srv._reap_orphan_ports(("tty:166:0",))
    assert isolated_ports["manager"].held_by("tty:166:0")["state"] == "orphan"
    srv._reap_orphan_ports(("tty:166:0",))
    assert not owner.exists()
    assert isolated_ports["manager"].held_by("tty:166:0") is None


@pytest.mark.parametrize("consumer", ["esp", "sigrok"])
async def test_cancelled_caller_does_not_release_started_worker(consumer, esp_fake, sigrok_fake, auth, monkeypatch, isolated_ports):
    from esp_mcp import server as esp
    from sigrok_mcp import server as sig
    srv = esp if consumer == "esp" else sig
    monkeypatch.setattr(sig, "_port_probe", fake_probe)
    monkeypatch.setattr(sig, "device_users", lambda p: [])
    r = srv.rt()
    case = r.cases.create(title="합성 caller 취소", authorization=auth)
    entered, release = threading.Event(), threading.Event()
    original = srv.run_streaming if consumer == "esp" else srv.run_process
    def paused(*a, **kw):
        entered.set()
        assert release.wait(10)
        return original(*a, **kw)
    monkeypatch.setattr(srv, "run_streaming" if consumer == "esp" else "run_process", paused)
    scope = anyio.CancelScope()
    ended = anyio.Event()
    async def request():
        with scope:
            if consumer == "esp":
                await srv.esp_chip_info(case_id=case.id, port="/dev/ttyACM0")
            else:
                await srv.sigrok_scan(case_id=case.id, driver="ols", conn="/dev/ttyACM0")
        ended.set()
    try:
        async with anyio.create_task_group() as group:
            group.start_soon(request)
            with anyio.fail_after(10):
                while not entered.is_set():
                    await anyio.sleep(.02)
            scope.cancel()
            with anyio.fail_after(5):
                await ended.wait()
            busy(isolated_ports["manager"], "tty:166:0")
            release.set()
            with anyio.fail_after(10):
                while isolated_ports["manager"].held_by("tty:166:0"):
                    await anyio.sleep(.02)
    finally:
        release.set()


async def test_sigrok_native_serial_promotes_risk_and_com_is_unsupported(sigrok_fake, auth, monkeypatch, isolated_ports):
    from sigrok_mcp import server as srv
    from pweh.safety import Risk
    monkeypatch.setattr(srv, "_port_probe", lambda: fake_probe(identity=lambda ref: known(ref, native=True)))
    monkeypatch.setattr(srv, "device_users", lambda p: [])
    monkeypatch.setattr(ports, "probe_siblings", lambda route, **kw: ports.SiblingScope(("tty:166:0", "tty:166:1"), route.identity.usb_ancestor, True, ()))
    r = srv.rt()
    case = r.cases.create(title="합성 native 위험도", authorization=auth)
    gate = r.authorize
    seen = []
    async def inspect(**kwargs):
        seen.append(kwargs["classification"].risk)
        busy(isolated_ports["manager"], "tty:166:1")
        return await gate(**kwargs)
    monkeypatch.setattr(r, "authorize", inspect)
    async with Client(srv.server) as c:
        result = await call(c, "sigrok_scan", case_id=case.id, driver="ols", conn="/dev/ttyACM0")
        assert result.get("ok"), result
        refused = await call(c, "sigrok_scan", case_id=case.id, driver="ols", conn="COM4096")
        assert "validation_failed" in refused.get("_error", ""), refused
    assert seen == [Risk.MODIFY]
    assert isolated_ports["manager"].held_by("tty:166:1") is None


@pytest.mark.parametrize("consumer", ["esp", "sigrok"])
@pytest.mark.parametrize("cancel_after_create", [False, True])
async def test_raw_task_cancel_during_lease_factory_leaves_no_lease(consumer, cancel_after_create, workspace, auth, monkeypatch, isolated_ports):
    import asyncio
    from esp_mcp import server as esp
    from esp_mcp import ports as esp_ports
    from sigrok_mcp import server as sig
    srv = esp if consumer == "esp" else sig
    monkeypatch.setattr(srv, "_port_probe", fake_probe)
    monkeypatch.setattr(esp_ports, "path_exists", lambda p: True)
    monkeypatch.setattr(esp_ports, "realpath", lambda p: p)
    r = srv.rt()
    case = r.cases.create(title="합성 raw 취소 생성 경합", authorization=auth)
    factory_name = "_PortUse" if consumer == "esp" else "_serial_use"
    original = getattr(srv, factory_name)
    entered, release, finished = threading.Event(), threading.Event(), threading.Event()
    uses = []
    def delayed(*args):
        try:
            if cancel_after_create:
                uses.append(original(*args))
            entered.set()
            assert release.wait(10)
            if not cancel_after_create:
                uses.append(original(*args))
            return uses[0]
        finally:
            finished.set()
    monkeypatch.setattr(srv, factory_name, delayed)
    # 실제 backend/version/gate까지 갈 수 없는 생성 단계 취소만 재현한다.
    coroutine = (srv.esp_chip_info(case_id=case.id, port="/dev/ttyACM0") if consumer == "esp" else
                 srv.sigrok_scan(case_id=case.id, driver="ols", conn="/dev/ttyACM0"))
    task = asyncio.create_task(coroutine)
    try:
        with anyio.fail_after(5):
            while not entered.is_set():
                await anyio.sleep(.01)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        release.set()
        with anyio.fail_after(5):
            while not finished.is_set() or isolated_ports["manager"].held_by("tty:166:0"):
                await anyio.sleep(.01)
        assert len(uses) == 1 and uses[0].lease.closed
    finally:
        release.set()
