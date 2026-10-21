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
               "rfc2217://127.0.0.1:4000", "rfc2217://[::1]:4000", "socket://127.0.0.53:2000", "loop://"):
        assert P.validate_port(ok) == ok
    for bad in ("spy:///dev/ttyUSB0?file=/home/u/.bashrc", "hwgrep://FTDI", "alt:///dev/ttyUSB0?class=PosixPollSerial",
                "ttyUSB0", "", "/dev/tty\x00USB0", "/dev/ttyUSB0\r/dev/ttyUSB1"):
        with pytest.raises(ValidationFailed):
            P.validate_port(bad)


def test_validate_port_win_com(monkeypatch):
    """회귀(리뷰 F6): COM 이름은 COM1–COM4096(앞자리 0 없음, ASCII 숫자). 수정 전 `COM\\d{1,3}` 은 COM0·COM000·유니코드 숫자를
    받고 COM1000–4096 을 거부했으며, 리눅스에서는 pyserial 이 'COM3' 을 현재 디렉터리의 파일로 열려 했다."""
    import sys

    for bad in ("COM0", "COM000", "COM01", "COM007", "COM4097", "COM99999"):
        with pytest.raises(ValidationFailed, match="COM1–COM4096"):
            P.validate_port(bad)
    for not_com in ("COM٣", "COM１", "COM৩", "COM١٢"):  # ASCII 숫자가 아니면 COM 이름이 아니다(→ 장치 절대경로 아님)
        with pytest.raises(ValidationFailed):
            P.validate_port(not_com)
    # 문법 검사는 환경과 독립적이며 COM 사용 가능 여부는 gate 전 resolve가 판단한다.
    for name in ("COM3", "com12", "COM1000", "COM4096"):
        assert P.validate_port(name) == name.upper()
    with monkeypatch.context() as m:
        m.setattr(sys, "platform", "win32")
        assert P.validate_port("com3") == "COM3"
        assert P.validate_port("COM1000") == "COM1000"
        assert P.validate_port("COM4096") == "COM4096"
        for bad in ("COM0", "COM000", "COM4097", "COM٣"):
            with pytest.raises(ValidationFailed):
                P.validate_port(bad)


def test_port_key_collapses_aliases(tmp_path):
    keys = {P.port_key(u) for u in ("socket://127.0.0.1:7777", "SOCKET://127.0.0.2:7777", "rfc2217://[::1]:7777",
                                    "rfc2217://127.0.0.1:7777")}
    assert keys == {"net-loopback:7777"}
    target = tmp_path / "ttyUSB9"
    target.write_text("")
    (tmp_path / "usb-FTDI-if00").symlink_to(target)
    assert P.port_key(str(tmp_path / "usb-FTDI-if00")) == P.port_key(str(target))


@pytest.mark.parametrize("url", [
    "rfc2217://10.0.0.2:4000",           # 수정 전: 원격(LAN) URL 로 유효했다
    "socket://192.0.2.10:7777", "rfc2217://198.51.100.7:2217", "socket://[2001:db8::1]:7777",
    "socket://0.0.0.0:7777", "socket://[::]:7777",
    "socket://127.1:7777", "socket://2130706433:7777", "socket://0x7f.1:7777", "socket://0127.0.0.1:7777",
    "socket://127.0.0.1@192.0.2.1:7777", "socket://user@127.0.0.1:7777",
    "socket://[::1%25lo]:7777", "socket://[::ffff:127.0.0.1]:7777", "socket://localhost.:7777",
    "socket://127.0.0.1", "socket://127.0.0.1:0", "socket://127.0.0.1:7777?logging=debug",
])
def test_validate_port_remote_urls_loopback_only(url):
    with pytest.raises(ValidationFailed):
        P.validate_port(url)


def test_validate_port_normalizes_remote_url():
    assert P.validate_port(" SOCKET://127.0.0.1:7777 ") == "socket://127.0.0.1:7777"
    assert P.validate_port("RFC2217://[::1]:2217") == "rfc2217://[::1]:2217"


def test_serial_link_revalidates_before_opening(monkeypatch):
    """드라이버도 열기 전에 다시 검사한다 — LAN URL 은 socket 연결을 시도하지 않는다."""
    import socket

    from jtagulator_mcp.driver import SerialLink

    def boom(*a, **kw):
        raise AssertionError("LAN URL 로 접속을 시도함")

    monkeypatch.setattr(socket, "create_connection", boom)
    with pytest.raises(ValidationFailed):
        SerialLink("socket://192.0.2.10:7777")


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


async def test_connect_rejects_lan_remote_urls_before_gate(workspace, auth, monkeypatch):
    """LAN·와일드카드·별칭 호스트의 socket://·rfc2217:// 는 게이트 전에 validation_failed (D4). 접속·승인 요청도 없다."""
    import socket

    from jtagulator_mcp.server import server

    def boom(*a, **kw):
        raise AssertionError("LAN URL 로 접속을 시도함")

    monkeypatch.setattr(socket, "create_connection", boom)
    cid = _case(auth)
    async with Client(server) as c:
        for port in ("rfc2217://10.0.0.2:4000", "socket://192.0.2.10:7777", "socket://0.0.0.0:7777",
                     "socket://2130706433:7777", "socket://127.0.0.1@192.0.2.1:7777"):
            r = await call(c, "jtagulator_connect", case_id=cid, port=port)
            assert "[validation_failed]" in r.get("_error", ""), (port, r)
            assert "루프백" in r["_error"], r
        st = await call(c, "jtagulator_status", case_id=cid)
        assert st["connected"] is False and st["connections"] == [], st
    assert get_runtime(SERVER).approvals.list("pending") == []


async def test_connect_refuses_com_names_on_linux(workspace, auth, tmp_path, monkeypatch):
    """리눅스에서 COMn 은 게이트 전에 validation_failed — 현재 디렉터리의 'COM3' 파일을 열려 하지 않는다 (리뷰 F6)."""
    from jtagulator_mcp.server import server

    monkeypatch.chdir(tmp_path)
    (tmp_path / "COM3").write_text("")  # 수정 전이었다면 pyserial 이 이 일반 파일을 포트로 열려 했다
    cid = _case(auth)
    async with Client(server) as c:
        for port in ("COM3", "com3", "COM0", "COM000", "COM٣"):
            r = await call(c, "jtagulator_connect", case_id=cid, port=port, timeout_seconds=3)
            assert "[validation_failed]" in r.get("_error", ""), (port, r)
        st = await call(c, "jtagulator_status", case_id=cid)
        assert st["connected"] is False, st


async def test_connect_same_loopback_endpoint_is_one_port(workspace, auth, monkeypatch):
    """회귀(리뷰 F1): 같은 루프백 포트의 다른 표기(localhost·127.x·[::1]·rfc2217·대문자)는 한 포트다. 다른 케이스가 잡은
    끝점에는 재동기화 키를 보내기 전에 busy, 같은 케이스는 기존 연결을 재사용한다(두 번째 링크를 만들지 않음)."""
    import socket

    from pweh import ports
    from jtagulator_mcp.server import server

    monkeypatch.setattr(ports, "_getaddrinfo",
                        lambda h, p: [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", p or 0))])
    sim = JTAGulatorSim(SimConfig(jtag=SimJTAGTarget(tdi=3, tdo=2, tck=0, tms=1, idcodes=[0x4BA00477]))).start()
    srv = SimTCPServer(sim)
    try:
        case_a, case_b = _case(auth), _case(auth)
        async with Client(server) as c:
            assert (await call(c, "jtagulator_connect", case_id=case_a, port=srv.url))["ok"]
            assert srv.connections == 1
            before = list(sim.events)
            for alias in (f"socket://localhost:{srv.port}", f"SOCKET://127.0.0.1:{srv.port}", f"socket://127.0.0.2:{srv.port}",
                          f"socket://[::1]:{srv.port}", f"rfc2217://127.0.0.1:{srv.port}"):
                r = await call(c, "jtagulator_connect", case_id=case_b, port=alias, timeout_seconds=3)
                assert "[busy]" in r.get("_error", ""), (alias, r)
            assert srv.connections == 1 and sim.events == before  # 두 번째 링크도, 재동기화 키도 없다
            r = await call(c, "jtagulator_connect", case_id=case_a, port=f"socket://localhost:{srv.port}")
            assert r.get("ok") and r.get("reused") is True, r
            assert srv.connections == 1
    finally:
        srv.close()
        sim.stop()


async def test_concurrent_connects_to_one_endpoint(workspace, auth):
    """승인을 기다리는 사이에 다른 케이스가 같은 끝점에 연결하지 못한다(예약 + 다시 확인) — 하나만 연결, 나머지는 busy."""
    import anyio

    from jtagulator_mcp.server import server

    sim = JTAGulatorSim(SimConfig(jtag=SimJTAGTarget(tdi=3, tdo=2, tck=0, tms=1, idcodes=[0x4BA00477]))).start()
    srv = SimTCPServer(sim)
    try:
        cases = [_case(auth) for _ in range(3)]
        results: list = []
        async with Client(server) as c:
            async def one(cid: str, url: str) -> None:
                results.append(await call(c, "jtagulator_connect", case_id=cid, port=url, timeout_seconds=5))

            async with anyio.create_task_group() as tg:
                for cid, url in zip(cases, (srv.url, f"socket://localhost:{srv.port}", f"SOCKET://127.0.0.1:{srv.port}")):
                    tg.start_soon(one, cid, url)
        ok = [r for r in results if r.get("ok")]
        busy = [r for r in results if "[busy]" in r.get("_error", "")]
        assert len(ok) == 1 and len(busy) == 2, results
        assert srv.connections == 1
    finally:
        srv.close()
        sim.stop()


async def test_connect_refuses_port_locked_by_another_session(workspace, auth, isolated_ports):
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
            assert "serial_open_cleanup_failed" in r.get("_error", ""), r
            # pyserial open 내부 실패는 fd 회수 확인이 안 되므로 process 종료까지 잠금을 보존한다.
            from jtagulator_mcp import server as J
            lease, transport, _ = next(iter(J._CLEANUP_PENDING.values()))
            assert not lease.closed and not transport.closed
            assert "open_failed_handle_ownership_unknown" in transport.cleanup_errors
            isolated_ports["allow_orphans"] = True
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
