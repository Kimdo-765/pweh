"""uart-mcp 게이트 범위(gate-coverage) 회귀 테스트 — pweh.mocktarget 시뮬레이터 + in-memory MCP 클라이언트.

기기로 바이트를 쓰는 모든 경로 — uart_write(text/hex), uart_send_command, uart_sync, uboot_interrupt 키,
uboot_printenv/uboot_info/shell_identify 내부 명령, uboot_dump_start job 의 명령, shell_login, uart_detect_baud 프로브,
BREAK/DTR/RTS — 에 DESTRUCTIVE 로 분류돼야 하는 입력을 넣어 거부되고 MockDevice.destructive_events 가 비어 있는지 본다.

검토에서 찾아 고친 우회 (고치기 전에는 모두 파괴적 명령이 시뮬레이터에 도달했다):
- ``env run <var>``·``time <명령>`` 은 코어가 MODIFY 로만 본다 → 안쪽 명령 기준으로 분류 (기본 정책에서 sf erase 도달)
- U-Boot 에서 ``echo Linux version …`` 처럼 리눅스 증거를 되풀이 → 문맥이 linux-shell 로 바뀌어 U-Boot ``cp`` 가
  리눅스 기준(MODIFY)으로 통과 (기본 정책에서 cp 도달)
- 재부팅·autoboot 중단 키·명령 실행 중 ctrlc() 폴링으로 기기가 미완성 입력을 버림 → ``echo `` + ``saveenv`` 가
  ``echo saveenv``(INTERACT)로 분류되고 기기는 saveenv 실행 (기본 정책에서 플래시 env 기록)
- ``cmd\\r`` 다음 호출의 ``\\n`` (U-Boot 빈 줄 = 직전 명령 반복) 이 분류되지 않음 → 1회용 승인 재실행
- 승인 뒤 run 대상 env 값을 바꿔 같은 승인으로 다른 내용 실행
- 세션 전에 기기에서 실행된 명령을 모르는 상태의 빈 Enter(반복), 상위 비트 바이트, /dev/watchdog 덤프 경로
"""

from __future__ import annotations

import threading
import time

import pytest
import serial
from mcp import Client

from mcp_helpers import call
from mocktarget.helpers import Console, make_device
from pweh.runtime import get_runtime

pytestmark = pytest.mark.anyio

SERVER = "uart-mcp"
PIPE = {"hisilicon-like": "mock-hisilicon", "ingenic-like": "mock-ingenic", "hisilicon-legacy": "hisilicon-ipcam"}


@pytest.fixture
def anyio_backend():
    return "asyncio"


@pytest.fixture
def devices():
    made = []

    def factory(profile: str = "hisilicon-like", **kw):
        dev = make_device(profile, **kw)
        made.append(dev)
        return dev

    yield factory
    for d in made:
        crashed = d.crashed
        d.stop()
        assert crashed is None, crashed


@pytest.fixture(autouse=True)
def _close_sessions(workspace, devices):
    """세션을 기기보다 먼저 닫는다 (devices 보다 나중에 준비 → 먼저 정리)."""
    yield
    from uart_mcp import server as us

    us.shutdown_all("test teardown")


def make_case(auth, profile: str = "hisilicon-like") -> str:
    return get_runtime(SERVER).cases.create(title="UART 게이트 범위", authorization=auth, profile=PIPE[profile]).id


async def open_session(c, cid: str, dev, **kw) -> tuple[str, str]:
    path = dev.start_pty()
    r = await call(c, "uart_open", case_id=cid, port=path, **kw)
    assert r.get("ok"), r
    return r["session_id"], path


async def to_uboot(c, sid: str, dev, delay: float = 0.3, **kw) -> dict:
    t = threading.Timer(delay, dev.power_on)
    t.start()
    r = await call(c, "uboot_interrupt", session_id=sid, window_seconds=20, **kw)
    t.join()
    assert r.get("interrupted"), r
    return r


async def wait_job(c, job_id: str, timeout: float = 120.0) -> dict:
    deadline = time.monotonic() + timeout
    while True:
        st = await call(c, "uart_job_status", job_id=job_id, wait_seconds=5)
        assert "_error" not in st, st
        if st["status"] not in ("queued", "running", "cancelling"):
            return st
        assert time.monotonic() < deadline, st


async def session_row(c, sid: str) -> dict:
    return next(s for s in (await call(c, "uart_sessions"))["sessions"] if s["session_id"] == sid)


def approve(approval_id: str) -> None:
    r = get_runtime(SERVER)
    rec = r.approvals.get(approval_id)
    r.approvals.decide(approval_id, approve=True, code=rec["code"], via="test")


def rule(r: dict) -> str:
    return r["gate"]["classification"]["rule_id"]


def device_lines(dev) -> list[str]:
    return [e.get("line") or "" for e in dev.commands()]


# ---------------------------------------------------------------------------
# 간접 실행: env run / time
# ---------------------------------------------------------------------------


async def test_env_run_and_time_runners_are_refused(devices, auth):
    from uart_mcp.server import server

    dev = devices("hisilicon-like")  # hush 2016.11: env 명령(env run) 있음
    cid = make_case(auth)
    async with Client(server) as c:
        sid, _ = await open_session(c, cid, dev)
        await to_uboot(c, sid, dev)
        assert (await call(c, "uboot_printenv", session_id=sid))["tracked"]
        r = await call(c, "uart_send_command", session_id=sid, command="setenv x 'sf erase 0x0 0x10000'")
        assert r["ok"], r  # setenv 자체는 MODIFY (기본 허용) — 값은 추적된다
        for cmd in ("run x", "env run x", "en r x", "time sf erase 0x0 0x10000", "t saveenv"):
            r = await call(c, "uart_send_command", session_id=sid, command=cmd)
            assert r.get("status") == "denied", (cmd, r)
        r = await call(c, "uart_send_command", session_id=sid, command="setenv y 'env run x'")
        assert r["ok"], r
        for cmd in ("run y", "true && run y"):
            r = await call(c, "uart_send_command", session_id=sid, command=cmd)
            assert r.get("status") == "denied", (cmd, r)
        r = await call(c, "uart_write", session_id=sid, data="env run x\r")
        assert r.get("status") == "denied", r
        # 읽기 전용은 그대로
        r = await call(c, "uart_send_command", session_id=sid, command="printenv x")
        assert r["ok"] and "x=sf erase 0x0 0x10000" in r["output"], r
    assert dev.destructive_events == []
    assert not any("run x" in ln or "sf erase" in ln.split("'")[0] for ln in device_lines(dev) if not ln.startswith("setenv"))


# ---------------------------------------------------------------------------
# 문맥 오판: 우리 입력을 되풀이한 텍스트로 linux-shell 이 되지 않는다
# ---------------------------------------------------------------------------


async def test_parroted_linux_evidence_cannot_relax_uboot_classification(devices, auth):
    from uart_mcp.server import server

    dev = devices("hisilicon-like")
    cid = make_case(auth)
    async with Client(server) as c:
        sid, _ = await open_session(c, cid, dev)
        await to_uboot(c, sid, dev)
        for cmd in ("echo Linux version 9.9", "echo Starting kernel ...", 'echo "BusyBox v1.20.2" built-in shell',
                    "echo Please press Enter to activate this console."):
            r = await call(c, "uart_send_command", session_id=sid, command=cmd)
            assert r["ok"] and r["context"] == "uboot", (cmd, r)
        row = await session_row(c, sid)
        assert row["phase"] == "uboot" and row["auto_context"] == "uboot", row
        r = await call(c, "uart_send_command", session_id=sid, command="cp ${loadaddr} 0x42000000 0x10")
        assert r.get("status") == "denied" and rule(r) == "uboot.cp", r
        # 변수로 되풀이 검사를 피해도 학습한 U-Boot 프롬프트는 셸이 되지 않는다 (unknown = 두 분류기의 worst)
        r = await call(c, "uart_send_command", session_id=sid, command="setenv a Linux; echo $a version 9.9")
        assert r["ok"] and r["context"] in ("uboot", "unknown"), r
        r = await call(c, "uart_send_command", session_id=sid, command="cp ${loadaddr} 0x42000000 0x10")
        assert r.get("status") == "denied", r
        # 줄 끝 없이 친(에코만 보이는) askfirst/login 문구도 문맥을 바꾸지 않는다
        s = await call(c, "uart_sync", session_id=sid)
        assert s["evidence"] == "uboot" and s["context"] == "uboot"
        for typed in ("echo Please press Enter to activate this console.", "echo login: "):
            w = await call(c, "uart_write", session_id=sid, data=typed)
            assert w["ok"], w
            time.sleep(0.2)
            row = await session_row(c, sid)
            assert row["context"] == "uboot" and row["phase"] == "uboot", (typed, row)
            await call(c, "uart_sync", session_id=sid)
        r = await call(c, "uart_send_command", session_id=sid, command="printenv bootdelay")
        assert r["ok"] and "bootdelay=2" in r["output"]
    assert dev.destructive_events == []


# ---------------------------------------------------------------------------
# 기기가 미완성 입력을 버리는 경우 (재부팅·autoboot 중단 키·명령 실행 중)
# ---------------------------------------------------------------------------


async def test_pending_input_dropped_by_reboot_cannot_mask_command(devices, auth):
    from uart_mcp.server import server

    dev = devices("hisilicon-like", autoboot_floor=1.0)  # autoboot 카운트다운 동안 키를 칠 시간
    cid = make_case(auth)
    async with Client(server) as c:
        sid, _ = await open_session(c, cid, dev)
        await to_uboot(c, sid, dev)
        w = await call(c, "uart_write", session_id=sid, data="echo ")
        assert w["ok"] and w["pending_input"] == "echo ", w
        dev.power_cycle()  # 사람이 전원을 껐다 켬 → 기기 줄 버퍼는 사라진다
        r = await call(c, "uart_wait_for", session_id=sid, pattern=r"Hit any key to stop autoboot", timeout=20)
        assert r["matched"], r
        w = await call(c, "uart_write", session_id=sid, data=" ")  # autoboot 중단 키 — abortboot 가 소비한다
        assert w["ok"], w
        r = await call(c, "uart_wait_for", session_id=sid, pattern=r"hisilicon # $", timeout=15)
        assert r["matched"] and dev.wait_for_state("uboot", 5), (r, dev.state)
        row = await session_row(c, sid)
        assert row["pending_uncertain"], row
        r = await call(c, "uart_send_command", session_id=sid, command="saveenv")  # 조립기: 'echo  saveenv', 기기: 'saveenv'
        assert r.get("status") == "denied" and rule(r) == "uart.uncertain-input", r
        assert "uart_sync" in r.get("hint", "")
        s = await call(c, "uart_sync", session_id=sid)
        assert s["evidence"] == "uboot"
        r = await call(c, "uart_send_command", session_id=sid, command="printenv bootdelay")
        assert r["ok"] and "bootdelay=2" in r["output"], r
    assert dev.destructive_events == []
    assert "saveenv" not in device_lines(dev)


async def test_typeahead_while_command_runs_cannot_mask_command(devices, auth):
    from uart_mcp.server import server

    dev = devices("hisilicon-like", time_scale=0.05, pace_output=True)  # md.b 출력이 몇 초 걸린다
    cid = make_case(auth)
    async with Client(server) as c:
        sid, _ = await open_session(c, cid, dev)
        await to_uboot(c, sid, dev)
        r = await call(c, "uart_send_command", session_id=sid, command="md.b 0x42000000 0x40000", timeout=0.5)
        assert r["ok"] and r["timed_out"], r
        # 명령 실행 중에 보내는 줄은 앞부분이 ctrlc() 폴링에 먹힐 수 있다 → 거부
        r = await call(c, "uart_send_command", session_id=sid, command="printenv bootdelay")
        assert r.get("status") == "denied" and rule(r) == "uart.device-busy", r
        # 줄 끝 없는 입력은 보내지지만(실행 안 됨) 조립기에 uncertain 으로 남는다 — md.b 가 읽어 버린다
        w = await call(c, "uart_write", session_id=sid, data="echo ")
        assert w["ok"] and w["plan"]["risk"] == "observe", w
        row = await session_row(c, sid)
        assert row["device_ready"] is False and row["pending_uncertain"], row
        r = await call(c, "uart_wait_for", session_id=sid, pattern=r"^hisilicon # $", timeout=60)
        assert r["matched"], r
        r = await call(c, "uart_send_command", session_id=sid, command="saveenv")
        assert r.get("status") == "denied", r
        s = await call(c, "uart_sync", session_id=sid)
        assert s["evidence"] == "uboot"
        r = await call(c, "uart_send_command", session_id=sid, command="printenv bootdelay")
        assert r["ok"] and "bootdelay=2" in r["output"], r
    assert dev.destructive_events == []
    assert "saveenv" not in device_lines(dev)


async def test_multi_line_payload_tail_typed_while_first_line_runs_is_refused(devices, auth):
    from uart_mcp.server import server

    dev = devices("hisilicon-like")
    cid = make_case(auth)
    async with Client(server) as c:
        sid, _ = await open_session(c, cid, dev)
        await to_uboot(c, sid, dev)
        r = await call(c, "uart_write", session_id=sid, data="md.b 0x42000000 0x10\rxsaveenv\r")
        assert r.get("status") == "denied", r
        assert [ln["rule_id"] for ln in r["plan"]["lines"]] == ["uboot.md", "uart.device-busy"]
    assert dev.destructive_events == []


# ---------------------------------------------------------------------------
# 빈 줄(직전 명령 반복)
# ---------------------------------------------------------------------------


async def test_crlf_split_across_writes_needs_new_approval(workspace, devices, auth):
    from uart_mcp.server import server

    workspace["set_safety"](destructive_policy="approve", approval_methods=["cli"])
    dev = devices("hisilicon-like")
    cid = make_case(auth)
    async with Client(server) as c:
        sid, _ = await open_session(c, cid, dev)
        await to_uboot(c, sid, dev)
        cmd = "mw.b 0x42000000 0xa5 0x10"
        first = await call(c, "uart_send_command", session_id=sid, command=cmd)
        assert first["status"] == "approval_required", first
        approve(first["approval_id"])
        done = await call(c, "uart_send_command", session_id=sid, command=cmd, approval_id=first["approval_id"])
        assert done["ok"] and len(dev.destructive_events) == 1, done
        # 'mw…\r' 다음 호출의 '\n' 은 U-Boot 에서 빈 줄 = mw 반복 → 승인이 다시 필요
        for kw in ({"data": "\n"}, {"data": "0a", "encoding": "hex"}):
            lf = await call(c, "uart_write", session_id=sid, **kw)
            assert lf["status"] == "approval_required" and "repeat" in rule(lf), lf
            assert lf["plan"]["lines"][0].get("synthetic_empty_line")
        time.sleep(0.3)
        assert len(dev.destructive_events) == 1
        # 읽기 명령 뒤의 '\n' 은 그 명령의 반복으로 분류되어 허용된다
        r = await call(c, "uart_write", session_id=sid, data="printenv bootdelay\r")
        assert r["ok"], r
        r = await call(c, "uart_write", session_id=sid, data="\n")
        assert r["ok"] and "repeat" in r["plan"]["lines"][0]["rule_id"], r
    assert len(dev.destructive_events) == 1


async def test_bare_enter_with_unknown_device_history_is_refused(devices, auth):
    from uart_mcp.server import server

    dev = devices("hisilicon-legacy")  # 2010.06 simple 파서: Ctrl-C 뒤에도 직전 명령을 기억한다
    path = dev.start_pty()
    sp = serial.Serial(path, 115200, timeout=0.05)
    con = Console(sp, dev)
    dev.power_on()
    con.interrupt_autoboot()
    con.cmd("mw.b 0x82000000 0x11 0x10")  # 세션을 열기 전에 사람이 실행한 명령 (기기의 직전 명령으로 남음)
    sp.close()
    assert len(dev.destructive_events) == 1
    cid = make_case(auth, "hisilicon-legacy")
    async with Client(server) as c:
        r = await call(c, "uart_open", case_id=cid, port=path)
        assert r["ok"], r
        sid = r["session_id"]
        s = await call(c, "uart_sync", session_id=sid)
        assert s["evidence"] == "uboot"
        r = await call(c, "uart_write", session_id=sid, data="\r")
        assert r.get("status") == "denied" and rule(r) == "uart.repeat-unknown", r
        assert "uart_sync" in r.get("hint", "")
        r = await call(c, "uart_send_command", session_id=sid, command="")
        assert r.get("status") == "denied", r
        time.sleep(0.2)
        assert len(dev.destructive_events) == 1
        # 이 세션이 명령을 보낸 뒤에는 직전 명령을 안다 → 빈 Enter = 그 명령(읽기)의 반복
        r = await call(c, "uart_send_command", session_id=sid, command="printenv bootdelay")
        assert r["ok"], r
        r = await call(c, "uart_send_command", session_id=sid, command="")
        assert r["ok"] and "repeat" in r["classification"]["rule_id"], r
    assert len(dev.destructive_events) == 1


# ---------------------------------------------------------------------------
# 비트 폭
# ---------------------------------------------------------------------------


async def test_high_bit_and_seven_bit_bytes_are_classified_as_the_device_sees_them(devices, auth, isolated_ports):
    from uart_mcp.server import server

    dev = devices("hisilicon-like")
    cid = make_case(auth)
    hidden = bytes(ch | 0x80 for ch in b"saveenv\r").hex()  # 하위 7비트 = 'saveenv\r'
    async with Client(server) as c:
        sid, path = await open_session(c, cid, dev)
        await to_uboot(c, sid, dev)
        r = await call(c, "uart_write", session_id=sid, data=hidden, encoding="hex")
        assert r.get("status") == "denied" and rule(r).startswith("uart.high-bit"), r
        r = await call(c, "uart_send_command", session_id=sid, command="echo café")
        assert r.get("status") == "denied" and "ASCII" in r.get("hint", ""), r
        await call(c, "uart_close", session_id=sid)
        # PTY는 7비트 프레이밍을 거부한다. pyserial이 open 중 fd 참조를 잃을 수 있어 잠금을 보존한다.
        r = await call(c, "uart_open", case_id=cid, port=path, bytesize=7, parity="E")
        assert "serial_open_cleanup_failed" in r.get("_error", "") and "internal_error" not in r["_error"], r
        from uart_mcp import server as U
        orphan = next(s for s in U._SESSIONS.values() if s.case_id == cid and s.port == path)
        assert not orphan.lease.closed and not orphan.ser.closed
        assert "open_failed_handle_ownership_unknown" in orphan.ser.cleanup_errors
        isolated_ports["allow_orphans"] = True
        # 7비트(7E1) 세션 (socket:// 은 프레이밍을 전달하지 않음): 기기는 하위 7비트만 받는다 → 그 바이트로 분류
        host, port = dev.start_tcp()
        r = await call(c, "uart_open", case_id=cid, port=f"socket://{host}:{port}", bytesize=7, parity="E")
        assert r["ok"], r
        sid7 = r["session_id"]
        s = await call(c, "uart_sync", session_id=sid7)
        assert s["evidence"] == "uboot", s
        r = await call(c, "uart_write", session_id=sid7, data=hidden, encoding="hex")
        assert r.get("status") == "denied" and rule(r) == "uboot.saveenv", r
        r = await call(c, "uart_send_command", session_id=sid7, command="printenv bootdelay")
        assert r["ok"] and "bootdelay=2" in r["output"], r
    assert dev.destructive_events == []


# ---------------------------------------------------------------------------
# 승인 지문: 같은 줄이라도 실행 내용(env 값)이 바뀌면 다른 작업
# ---------------------------------------------------------------------------


async def test_approval_is_bound_to_run_target_value(workspace, devices, auth):
    from uart_mcp.server import server

    workspace["set_safety"](destructive_policy="approve", approval_methods=["cli"])
    dev = devices("hisilicon-like")
    cid = make_case(auth)
    orig = "mw.b 0x42000000 0xa5 0x10"
    async with Client(server) as c:
        sid, _ = await open_session(c, cid, dev)
        await to_uboot(c, sid, dev)
        assert (await call(c, "uboot_printenv", session_id=sid))["tracked"]
        assert (await call(c, "uart_send_command", session_id=sid, command=f"setenv x '{orig}'"))["ok"]
        first = await call(c, "uart_send_command", session_id=sid, command="run x")
        assert first["status"] == "approval_required", first
        ap = first["approval_id"]
        approve(ap)
        # 승인받은 뒤 x 의 내용을 바꾸면 같은 approval_id 로 실행할 수 없다
        assert (await call(c, "uart_send_command", session_id=sid, command="setenv x 'mw.b 0x42000000 0x5a 0x100'"))["ok"]
        swapped = await call(c, "uart_send_command", session_id=sid, command="run x", approval_id=ap)
        assert swapped.get("ok") is False and swapped.get("status") == "denied", swapped
        assert dev.destructive_events == []
        # 승인 당시의 값으로 되돌리면 그 승인으로 1회 실행된다
        assert (await call(c, "uart_send_command", session_id=sid, command=f"setenv x '{orig}'"))["ok"]
        done = await call(c, "uart_send_command", session_id=sid, command="run x", approval_id=ap)
        assert done["ok"], done
    assert len(dev.destructive_events) == 1 and dev.ram.read(0x42000000, 0x10) == b"\xa5" * 16


# ---------------------------------------------------------------------------
# 그 밖의 송신 경로: 내부 명령, 덤프 job, 인터럽트 키, 로그인, 덤프 경로, 신호·프로브
# ---------------------------------------------------------------------------


async def test_internal_commands_refuse_pending_input(devices, auth):
    from uart_mcp.server import server

    dev = devices("hisilicon-like")
    cid = make_case(auth)
    async with Client(server) as c:
        sid, _ = await open_session(c, cid, dev)
        await to_uboot(c, sid, dev)
        w = await call(c, "uart_write", session_id=sid, data="sf erase 0 10000; ")
        assert w["ok"] and w["pending_input"], w  # 줄 끝이 없어 아직 실행되지 않음
        for tool, kw in (("uboot_printenv", {}), ("uboot_info", {}), ("shell_login", {"username": "root"})):
            r = await call(c, tool, session_id=sid, **kw)
            assert "_error" in r and "uart_sync" in r["_error"], (tool, r)
        r = await call(c, "uart_send_command", session_id=sid, command="printenv")  # 'sf erase 0 10000; printenv'
        assert r.get("status") == "denied", r
        assert (await call(c, "uart_sync", session_id=sid))["evidence"] == "uboot"
        r = await call(c, "uboot_printenv", session_id=sid)
        assert r["ok"] and r["tracked"], r
    assert dev.destructive_events == []


async def test_dump_job_reclassifies_every_command(devices, auth, monkeypatch):
    """시작 전 검사를 통과한 뒤 job 이 보내려는 명령이 바뀌어도(여기서는 적재 명령이 sf erase 로) 송신마다 다시 분류해 멈춘다."""
    from uart_mcp import dumps
    from uart_mcp.server import server

    dev = devices("hisilicon-like")
    cid = make_case(auth)
    orig_load = dumps.UBootDumpSpec.load_line
    calls = {"n": 0}

    def tampered(self, off, n):
        calls["n"] += 1
        if calls["n"] <= self.chunks():  # 도구의 사전 검사(planned_lines)에는 원래 명령
            return orig_load(self, off, n)
        return f"sf erase 0x{off:x} 0x{n:x}"

    async with Client(server) as c:
        sid, _ = await open_session(c, cid, dev)
        await to_uboot(c, sid, dev)
        await call(c, "uboot_info", session_id=sid)
        monkeypatch.setattr(dumps.UBootDumpSpec, "load_line", tampered)
        st = await call(c, "uboot_dump_start", case_id=cid, session_id=sid, offset=0x50000, length=0x8000, chunk_size=0x4000,
                        output_name="tampered")
        assert st["ok"], st
        res = await wait_job(c, st["job_id"])
        assert res["status"] == "failed" and res["error"]["code"] == "job_command_denied", res
        # 세션은 계속 쓸 수 있다
        r = await call(c, "uart_send_command", session_id=sid, command="printenv bootdelay")
        assert r["ok"] and "bootdelay=2" in r["output"], r
    assert dev.destructive_events == []
    assert not any(ln.startswith("sf erase") for ln in device_lines(dev))


async def test_shell_dump_job_reclassifies_every_command(devices, auth, monkeypatch):
    """리눅스 셸 덤프 job 도 송신마다 다시 분류한다: 사전 검사 뒤 청크 명령이 'dd … of=/dev/mtd1' 로 바뀌면 멈춘다."""
    from uart_mcp import dumps
    from uart_mcp.server import server

    dev = devices("hisilicon-like")
    cid = make_case(auth)
    orig_dd = dumps.shell_dd
    calls = {"n": 0}

    def tampered(path, off, n, tail):
        calls["n"] += 1
        if calls["n"] <= 3:  # 도구의 사전 검사(representative_shell_lines: base64/hexdump/md5sum)에는 원래 명령
            return orig_dd(path, off, n, tail)
        return f"dd if=/dev/zero of={path} bs={n} count=1"

    async with Client(server) as c:
        sid, _ = await open_session(c, cid, dev)
        threading.Timer(0.2, dev.power_on).start()
        r = await call(c, "uart_wait_for", session_id=sid, pattern=r"Please press Enter to activate this console", timeout=40)
        assert r["matched"], r
        lg = dev.profile["linux"]["login"]
        li = await call(c, "shell_login", session_id=sid, username=lg["username"], password=lg.get("password"), timeout=20)
        assert li["logged_in"], li
        monkeypatch.setattr(dumps, "shell_dd", tampered)
        st = await call(c, "shell_dump_start", case_id=cid, session_id=sid, path="/dev/mtd1", chunk_size="16k", output_name="tampered-sh")
        assert st["ok"], st
        res = await wait_job(c, st["job_id"])
        assert res["status"] == "failed" and res["error"]["code"] == "job_command_denied", res
        r = await call(c, "uart_send_command", session_id=sid, command="cat /proc/mtd")  # 세션은 계속 쓸 수 있다
        assert r["ok"] and '"env"' in r["output"], r
    assert dev.destructive_events == []
    assert not any("of=/dev/mtd" in ln for ln in device_lines(dev))


async def test_dump_job_stops_when_authorization_is_revoked(devices, auth):
    """작업 도중 케이스 소유/허가 증명이 철회되면 다음 명령을 보내지 않고 멈춘다 (명령마다 다시 확인)."""
    from uart_mcp.server import server

    dev = devices("hisilicon-like", time_scale=0.05, pace_output=True)
    cid = make_case(auth)
    async with Client(server) as c:
        sid, _ = await open_session(c, cid, dev)
        await to_uboot(c, sid, dev)
        await call(c, "uboot_info", session_id=sid)
        st = await call(c, "uboot_dump_start", case_id=cid, session_id=sid, offset=0, length=0x100000, chunk_size=0x4000,
                        output_name="revoked")  # 64 청크 — 철회가 끝나기 전에 닿도록 넉넉히
        assert st["ok"], st
        deadline = time.monotonic() + 60
        while (await call(c, "uart_job_status", job_id=st["job_id"])).get("meta", {}).get("overall_done_bytes", 0) < 0x4000:
            assert time.monotonic() < deadline
            time.sleep(0.05)
        get_runtime(SERVER).cases.get(cid)._update(lambda meta: meta.update(authorization=None))  # noqa: SLF001 - 사람이 증명 철회
        n_before = len(dev.commands())
        res = await wait_job(c, st["job_id"])
        assert res["status"] == "failed" and res["error"]["code"] == "authorization_required", res
        assert len(dev.commands()) - n_before <= 3  # 철회 시점에 이미 보낸 명령(청크 하나의 sf read/md.b/crc32)까지만
        assert res["result"]["status"] == "failed" and res["result"]["completed_chunks"] < 64
    assert dev.destructive_events == []


async def test_uboot_interrupt_keys_are_gated(devices, auth):
    from uart_mcp.server import server

    dev = devices("hisilicon-like")
    cid = make_case(auth)
    async with Client(server) as c:
        sid, _ = await open_session(c, cid, dev)  # 전원 꺼짐 — 문맥 unknown
        for keys in (["saveenv\r"], ["sf erase 0 10000\r"], ["\x1b[A\r"], ["\x10\r"], ["ctrl-c", "env run x\r"]):
            r = await call(c, "uboot_interrupt", session_id=sid, keys=keys, window_seconds=1)
            assert r.get("status") == "denied", (keys, r)
        # Enter 만 쓰는 keyed autoboot 도 새 세션에서 동작한다 (Enter 는 새 부팅을 본 뒤에만, 보낼 때 다시 분류)
        r = await to_uboot(c, sid, dev, keys=["enter"])
        assert r["keys_used"] == ["enter"] and r["new_boot_seen"], r
        r = await call(c, "uart_send_command", session_id=sid, command="printenv bootdelay")
        assert r["ok"], r
    assert dev.destructive_events == []


async def test_login_path_never_types_into_uboot(devices, auth):
    from uart_mcp.server import server

    dev = devices("hisilicon-like")
    cid = make_case(auth)
    async with Client(server) as c:
        sid, _ = await open_session(c, cid, dev)
        await to_uboot(c, sid, dev)
        r = await call(c, "shell_login", session_id=sid, username="saveenv", password="x")
        assert r["status"] == "uboot_prompt" and r["logged_in"] is False, r
        # 줄 끝 없이 친 'echo login: ' 의 에코는 login 프롬프트가 아니고, 미완성 입력이 있으면 로그인 입력을 보내지 않는다
        w = await call(c, "uart_write", session_id=sid, data="echo login: ")
        assert w["ok"], w
        time.sleep(0.2)
        assert (await session_row(c, sid))["context"] == "uboot"
        r = await call(c, "shell_login", session_id=sid, username="saveenv")
        assert "_error" in r, r
        assert (await call(c, "uart_sync", session_id=sid))["evidence"] == "uboot"
    assert dev.destructive_events == []
    assert not any("saveenv" in ln for ln in device_lines(dev))


async def test_shell_dump_refuses_side_effect_device_paths(devices, auth):
    from uart_mcp.server import server

    dev = devices("hisilicon-like")
    cid = make_case(auth)
    async with Client(server) as c:
        sid, _ = await open_session(c, cid, dev)
        for path in ("/dev/watchdog", "/dev/watchdog0", "/dev/mem", "/dev/port", "/dev/ttyS0", "/dev/mtd0;reboot", "/dev/../dev/mtd0"):
            r = await call(c, "shell_dump_start", case_id=cid, session_id=sid, path=path)
            assert "_error" in r and "validation_failed" in r["_error"], (path, r)
    assert dev.destructive_events == []


async def test_signal_and_probe_tools_respect_modify_policy(workspace, devices, auth):
    from uart_mcp.server import server

    workspace["set_safety"](modify_policy="deny")
    dev = devices("hisilicon-like")
    cid = make_case(auth)
    async with Client(server) as c:
        sid, path = await open_session(c, cid, dev)
        r = await call(c, "uart_send_break", session_id=sid)
        assert r.get("status") == "denied" and rule(r) == "uart.break", r
        r = await call(c, "uart_set_signals", session_id=sid, dtr=True)
        assert r.get("status") == "denied" and rule(r) == "uart.signals", r
        await call(c, "uart_close", session_id=sid)
        r = await call(c, "uart_detect_baud", case_id=cid, port=path, candidates=[115200], listen_seconds=0.3)
        assert "port_role_conflict" in r.get("_error", ""), r
        # 이미 대상 콘솔로 확인한 포트는 정책보다 먼저 거부한다. 새 합성 끝점에서는 MODIFY 정책을 검사한다.
        unmarked = devices("hisilicon-like").start_pty()
        r = await call(c, "uart_detect_baud", case_id=cid, port=unmarked, candidates=[115200], listen_seconds=0.3)
        assert r.get("status") == "denied" and rule(r) == "uart.detect-baud.probe", r
        r = await call(c, "uart_detect_baud", case_id=cid, port=path, candidates=[115200], listen_seconds=0.3, probe="none")
        assert r["ok"], r
    assert dev.destructive_events == []


# ---------------------------------------------------------------------------
# 읽기 전용 흐름은 그대로 동작한다
# ---------------------------------------------------------------------------


async def test_readonly_workflows_still_work(devices, auth):
    from uart_mcp.server import server

    dev = devices("hisilicon-like")
    cid = make_case(auth)
    async with Client(server) as c:
        sid, path = await open_session(c, cid, dev)
        await to_uboot(c, sid, dev)
        # 프롬프트에서의 나눠 보내기는 한 줄로 조립돼 실행된다
        w1 = await call(c, "uart_write", session_id=sid, data="printenv boot")
        assert w1["ok"] and w1["pending_input"] == "printenv boot", w1
        w2 = await call(c, "uart_write", session_id=sid, data="delay\r")
        assert w2["ok"] and w2["plan"]["lines"][0]["line"] == "printenv bootdelay", w2
        r = await call(c, "uart_wait_for", session_id=sid, pattern=r"^bootdelay=2$", timeout=5)
        assert r["matched"], r
        # expect 로 일찍 끝난 명령 바로 뒤의 명령도 프롬프트를 잠깐 기다려 보낸다
        r = await call(c, "uart_send_command", session_id=sid, command="printenv bootcmd", expect=r"^bootcmd=")
        assert r["matched"], r
        r = await call(c, "uart_send_command", session_id=sid, command="version")
        assert r["ok"] and "U-Boot 2016.11" in r["output"], r
        assert (await call(c, "uboot_printenv", session_id=sid))["tracked"]
        info = await call(c, "uboot_info", session_id=sid)
        assert info["ok"] and info["safe_ram_addr"] == "0x42000000", info
        r = await call(c, "uart_send_command", session_id=sid, command="env run nosuch")  # 내용 모름 → 거부
        assert r.get("status") == "denied", r
        # 같은 포트를 다시 열면(예: setenv baudrate 뒤 새 속도) 직전 명령을 이어 받아 빈 Enter 가 그 반복으로 분류된다
        last = (await session_row(c, sid))["last_uboot_command"]
        assert last == "sf probe 0"
        await call(c, "uart_close", session_id=sid)
        r = await call(c, "uart_open", case_id=cid, port=path)
        assert r["ok"] and r["inherited_last_command"] == last, r
        sid2 = r["session_id"]
        e = await call(c, "uart_write", session_id=sid2, data="\r")
        assert e["ok"] and "repeat" in e["plan"]["lines"][0]["rule_id"], e
        r = await call(c, "uart_wait_for", session_id=sid2, pattern=r"hisilicon # $", timeout=5)
        assert r["matched"], r
        # 리눅스까지: 부팅 → 로그인 → 읽기 명령 (리눅스에서 CRLF 는 한 줄 끝)
        boot = await call(c, "uart_send_command", session_id=sid2, command="boot", timeout=30,
                          expect=r"Please press Enter to activate this console")
        assert boot["ok"] and boot["matched"], boot
        lg = dev.profile["linux"]["login"]
        li = await call(c, "shell_login", session_id=sid2, username=lg["username"], password=lg.get("password"))
        assert li["logged_in"], li
        r = await call(c, "uart_send_command", session_id=sid2, command="cat /proc/mtd")
        assert r["ok"] and '"env"' in r["output"], r
        w = await call(c, "uart_write", session_id=sid2, data="echo pweh-ok\r\n")
        assert w["ok"] and w["plan"]["lines"] == [{"line": "echo pweh-ok", "risk": "interact", "rule_id": "linux.echo"}], w
        r = await call(c, "uart_wait_for", session_id=sid2, pattern=r"^pweh-ok$", timeout=5)
        assert r["matched"], r
        ident = await call(c, "shell_identify", session_id=sid2)
        assert ident["ok"] and ident["mtd"], ident
    assert dev.destructive_events == []


async def test_relative_write_after_cd_into_system_dir_is_refused(devices, auth):
    """세션이 보낸 cd 를 추적한다: cd /usr/bin 뒤의 'cp /tmp/x md5sum' 은 시스템 경로 쓰기로 거부, cd /tmp 뒤 조회는 그대로."""
    from uart_mcp.server import server

    dev = devices("hisilicon-like")
    cid = make_case(auth)
    async with Client(server) as c:
        sid, _ = await open_session(c, cid, dev)
        threading.Timer(0.2, dev.power_on).start()
        r = await call(c, "uart_wait_for", session_id=sid, pattern=r"Please press Enter to activate this console", timeout=40)
        assert r["matched"], r
        lg = dev.profile["linux"]["login"]
        li = await call(c, "shell_login", session_id=sid, username=lg["username"], password=lg.get("password"), timeout=20)
        assert li["logged_in"], li
        r = await call(c, "uart_send_command", session_id=sid, command="cd /usr/bin")
        assert r["ok"], r
        assert (await session_row(c, sid))["linux_cwd"] == "/usr/bin"
        r = await call(c, "uart_send_command", session_id=sid, command="cp /tmp/x md5sum")
        assert r.get("status") == "denied" and rule(r) == "linux.write.system", r
        r = await call(c, "uart_send_command", session_id=sid, command="cd /tmp")
        assert r["ok"], r
        assert (await session_row(c, sid))["linux_cwd"] == "/tmp"
        r = await call(c, "uart_send_command", session_id=sid, command="cat /proc/mtd")
        assert r["ok"] and "mtd" in r["output"], r
    assert dev.destructive_events == []
    assert not any("md5sum" in ln for ln in device_lines(dev))
