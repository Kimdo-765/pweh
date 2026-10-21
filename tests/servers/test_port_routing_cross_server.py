"""같은 합성 포트를 쓰는 서버 사이의 잠금과 승인 순서 회귀."""

from __future__ import annotations

import importlib
import os

import anyio
import pytest
from mcp import Client

from mcp_helpers import call
from pweh import portlock

pytestmark = pytest.mark.anyio


@pytest.fixture
def anyio_backend():
    return "asyncio"


@pytest.fixture
def synthetic_tty(workspace):
    from uart_mcp import server as uart
    from jtagulator_mcp import server as jtag

    master, slave = os.openpty()
    try:
        yield os.ttyname(slave)
    finally:
        uart.shutdown_all("합성 시험 종료")
        jtag._shutdown_all()
        os.close(master)
        os.close(slave)


def forbidden(*args, **kwargs):
    pytest.fail("점유된 포트의 승인 또는 장치 접근이 실행됨")


@pytest.mark.parametrize("module,tool,extra", [
    ("jtagulator_mcp", "jtagulator_connect", {}),
    ("esp_mcp", "esp_chip_info", {}),
    ("sigrok_mcp", "sigrok_scan", {"driver": "ols"}),
])
async def test_uart_lease_blocks_other_servers_before_gate(
    module, tool, extra, synthetic_tty, auth, monkeypatch, isolated_ports
):
    from uart_mcp import server as uart

    other = importlib.import_module(module + ".server")
    case = uart.rt().cases.create(title="합성 교차 서버 점유", authorization=auth)
    async with Client(uart.server) as uc, Client(other.server) as oc:
        opened = await call(uc, "uart_open", case_id=case.id, port=synthetic_tty)
        assert opened["ok"], opened
        key = opened["route"]["lock_key"]
        monkeypatch.setattr(other.rt(), "authorize", forbidden)
        # 백엔드 식별을 위해 포트를 먼저 열거나 실제 장치 프로그램을 실행하면 실패한다.
        for name in ("SerialLink", "run_streaming"):
            if hasattr(other, name):
                monkeypatch.setattr(other, name, forbidden)
        kwargs = {"conn" if module == "sigrok_mcp" else "port": synthetic_tty}
        refused = await call(oc, tool, case_id=case.id, **kwargs, **extra)
        assert "busy" in refused.get("_error", ""), refused
        owner = isolated_ports["manager"].held_by(key)
        assert owner["server"] == "uart-mcp" and owner["state"] == "open"
        assert (await call(uc, "uart_close", session_id=opened["session_id"]))["ok"]
        assert isolated_ports["manager"].held_by(key) is None


@pytest.mark.parametrize("policy,expected", [("deny", "denied"), ("approve", "approval_required")])
async def test_awaiting_approval_is_busy_and_gate_return_releases(
    policy, expected, synthetic_tty, workspace, auth, monkeypatch, isolated_ports
):
    from uart_mcp import server as uart
    from jtagulator_mcp import server as jtag

    workspace["set_safety"](modify_policy=policy, approval_methods=["cli"])
    runtime = uart.rt()
    case = runtime.cases.create(title="합성 승인 대기", authorization=auth)
    original = runtime.authorize
    entered, release = anyio.Event(), anyio.Event()
    results = []

    async def gate(**kwargs):
        entered.set()
        await release.wait()
        return await original(**kwargs)

    monkeypatch.setattr(runtime, "authorize", gate)
    monkeypatch.setattr(jtag.rt(), "authorize", forbidden)
    route, _ = uart._resolve_port(runtime, synthetic_tty)
    async with Client(uart.server) as uc, Client(jtag.server) as jc:
        async def opening():
            results.append(await call(uc, "uart_open", case_id=case.id, port=synthetic_tty, dtr=True))

        async with anyio.create_task_group() as group:
            group.start_soon(opening)
            with anyio.fail_after(5):
                await entered.wait()
            try:
                owner = isolated_ports["manager"].held_by(route.lock_key)
                assert owner["state"] == "awaiting_approval"
                refused = await call(jc, "jtagulator_connect", case_id=case.id, port=synthetic_tty)
                assert "busy" in refused.get("_error", ""), refused
            finally:
                release.set()
    assert results[0].get("status") == expected, results
    assert isolated_ports["manager"].held_by(route.lock_key) is None
    # 승인 거부 후 다음 소비자는 같은 OS 키를 다시 잡을 수 있다.
    lease = isolated_ports["manager"].acquire((route.lock_key,), owner=portlock.PortOwner("synthetic", case.id, synthetic_tty))
    lease.close()


async def test_unknown_loopback_aliases_keep_one_lock(workspace, auth, monkeypatch, isolated_ports):
    """IPv4/IPv6·socket/RFC2217 표기가 달라도 같은 리스너 포트는 경합한다."""
    from jtagulator_mcp import server as jtag

    case = jtag.rt().cases.create(title="합성 URL 별칭", authorization=auth)
    lease = isolated_ports["manager"].acquire(("net-loopback:32456",),
            owner=portlock.PortOwner("uart-mcp", case.id, "socket://127.0.0.2:32456"))
    monkeypatch.setattr(jtag.rt(), "authorize", forbidden)
    monkeypatch.setattr(jtag, "SerialLink", forbidden)
    try:
        async with Client(jtag.server) as client:
            result = await call(client, "jtagulator_connect", case_id=case.id, port="rfc2217://[::1]:32456")
        assert "busy" in result.get("_error", ""), result
    finally:
        lease.close()


async def test_cancel_during_gate_releases_unopened_lease(synthetic_tty, auth, monkeypatch, isolated_ports):
    from uart_mcp import server as uart

    runtime = uart.rt()
    case = runtime.cases.create(title="합성 승인 대기 취소", authorization=auth)
    entered = anyio.Event()

    async def gate(**kwargs):
        entered.set()
        await anyio.sleep_forever()

    async def opening():
        await uart.uart_open(case_id=case.id, port=synthetic_tty, ctx=None)

    monkeypatch.setattr(runtime, "authorize", gate)
    route, _ = uart._resolve_port(runtime, synthetic_tty)
    async with anyio.create_task_group() as group:
        group.start_soon(opening)
        with anyio.fail_after(5):
            await entered.wait()
        assert isolated_ports["manager"].held_by(route.lock_key)["state"] == "awaiting_approval"
        group.cancel_scope.cancel()
    assert isolated_ports["manager"].held_by(route.lock_key) is None
    assert not uart._RESERVED and not uart._SESSIONS
