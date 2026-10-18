"""jtagulator-mcp 게이트 회귀 테스트 (검토 단계).

- UART 스캔 프로브는 순열마다 반복 송신되므로 '줄 끝 없는 꼬리 + 다음 송신의 첫 줄' 이 한 줄로 실행될 수 있다
  (예: "_erase X\\rflash" → 두 번째 송신에서 "flash_erase X"). 수정 전에는 조각별로만 분류해 MODIFY 로 통과했다.
- jtagulator_connect 가 다른 프로세스(uart-mcp 는 exclusive 로 연다)가 쓰는 포트를 열어 재동기화 키
  (Ctrl-X, Ctrl-X+CR = U-Boot 빈 Enter)를 대상 콘솔에 보낼 수 있었다 → exclusive 로 열어 거부.
- spy:// (호스트 파일 기록), hwgrep:// (열릴 장치 불명) 같은 pyserial URL 처리기 거부.
"""

from __future__ import annotations

import errno
import os
import pty

import pytest
import serial
from mcp import Client

from jtagulator_mcp import protocol as P
from jtagulator_mcp.classify import classify_uart_probe
from jtagulator_mcp.sim import JTAGulatorSim, SimConfig, SimJTAGTarget, SimTCPServer, SimUARTTarget
from mcp_helpers import call
from pweh.errors import ValidationFailed
from pweh.runtime import get_runtime
from pweh.safety import Risk

pytestmark = pytest.mark.anyio

SERVER = "jtagulator-mcp"


@pytest.fixture
def anyio_backend():
    return "asyncio"


@pytest.fixture(autouse=True)
def _close_connections():
    yield
    from jtagulator_mcp import server as js

    js._shutdown_all()


def _case(auth) -> str:
    return get_runtime(SERVER).cases.create(title="jtagulator gate", authorization=auth).id


# ---------------------------------------------------------------------------
# 단위
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("probe", [b"_erase X\rflash", b"aveenv\rs", b"rase 0 1000\rsf e", b"\rsaveenv", b"saveenv"])
def test_probe_tail_joined_with_next_head_is_classified(probe):
    c = classify_uart_probe(probe)
    assert c.risk == Risk.DESTRUCTIVE, (probe, c)


@pytest.mark.parametrize("probe", [b"\r", b"help\r", b"\r\n", b"\n"])
def test_benign_probes_stay_low(probe):
    assert classify_uart_probe(probe).risk <= Risk.INTERACT, probe


def test_validate_port():
    for ok in ("/dev/ttyUSB0", "/dev/serial/by-id/usb-FTDI_FT232R-if00-port0", "socket://127.0.0.1:7777",
               "rfc2217://10.0.0.2:4000", "loop://", "COM3"):
        assert P.validate_port(ok) == ok
    for bad in ("spy:///dev/ttyUSB0?file=/home/u/.bashrc", "hwgrep://FTDI", "alt:///dev/ttyUSB0?class=PosixPollSerial",
                "ttyUSB0", "", "/dev/tty\x00USB0", "/dev/ttyUSB0\r/dev/ttyUSB1"):
        with pytest.raises(ValidationFailed):
            P.validate_port(bad)


# ---------------------------------------------------------------------------
# MCP
# ---------------------------------------------------------------------------


async def test_concatenating_probe_refused_before_gate(workspace, auth):
    from jtagulator_mcp.server import server

    workspace["set_safety"](destructive_policy="approve", approval_methods=["cli"])
    sim = JTAGulatorSim(SimConfig(jtag=SimJTAGTarget(tdi=3, tdo=2, tck=0, tms=1, idcodes=[0x4BA00477]),
                                  uart=SimUARTTarget(txd=6, rxd=7, baud=115200, response=b"\r\nlogin: "))).start()
    srv = SimTCPServer(sim)
    try:
        cid = _case(auth)
        async with Client(server) as c:
            assert (await call(c, "jtagulator_connect", case_id=cid, port=srv.url))["ok"]
            first = await call(c, "jtagulator_set_voltage", case_id=cid, volts=3.3)
            rt = get_runtime(SERVER)
            rt.approvals.decide(first["approval_id"], approve=True, code=rt.approvals.get(first["approval_id"])["code"], via="test")
            assert (await call(c, "jtagulator_set_voltage", case_id=cid, volts=3.3, approval_id=first["approval_id"]))["ok"]
            before = list(sim.events)
            r = await call(c, "jtagulator_uart_scan", case_id=cid, start_channel=4, end_channel=7, text="_erase X\\rflash")
            assert "_error" in r and "DESTRUCTIVE" in r["_error"], r  # 수정 전: MODIFY 로 스캔 시작
            assert sim.events == before  # 장치에 아무것도 보내지 않음
            assert rt.approvals.list("pending") == []  # 승인 경로도 만들지 않음
    finally:
        srv.close()
        sim.stop()


async def test_connect_rejects_dangerous_port_urls(workspace, auth, tmp_path):
    from jtagulator_mcp.server import server

    cid = _case(auth)
    spy_log = tmp_path / "spy.log"
    async with Client(server) as c:
        for port in (f"spy://loop://?file={spy_log}", "hwgrep://.*", "ttyUSB0"):
            r = await call(c, "jtagulator_connect", case_id=cid, port=port)
            assert "_error" in r, (port, r)
    assert not spy_log.exists()


async def test_connect_refuses_port_locked_by_another_session(workspace, auth):
    """uart-mcp 처럼 exclusive 로 열린 포트(대상 콘솔일 수 있음)에는 재동기화 키를 보내지 않는다."""
    from jtagulator_mcp.server import server

    master, slave = pty.openpty()
    name = os.ttyname(slave)
    holder = serial.serial_for_url(name, exclusive=True, do_not_open=True)
    holder.open()  # 다른 세션이 잡고 있는 콘솔 포트 흉내
    os.set_blocking(master, False)
    try:
        cid = _case(auth)
        async with Client(server) as c:
            r = await call(c, "jtagulator_connect", case_id=cid, port=name, timeout_seconds=3)
            assert "_error" in r and "열 수 없습니다" in r["_error"], r
        try:
            leaked = os.read(master, 4096)
        except OSError as exc:  # 읽을 바이트 없음
            assert exc.errno in (errno.EAGAIN, errno.EWOULDBLOCK, errno.EIO)
            leaked = b""
        assert leaked == b"", leaked  # 수정 전: Ctrl-X 와 Ctrl-X+CR 이 콘솔로 들어갔다
    finally:
        holder.close()
        os.close(master)
        os.close(slave)
