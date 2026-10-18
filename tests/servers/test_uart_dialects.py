"""uart-mcp 정확성 회귀 테스트 — 시뮬레이터 세 방언(hisilicon-like 2016.11 hush, ingenic-like 2013.07, hisilicon-legacy 2010.06).

검토 단계에서 고친 문제마다 하나 이상의 테스트가 있다:
- uboot_interrupt: 이미 부팅 중인 기기의 이전 부팅 출력으로 판단하지 않음(새 부팅까지 대기), 리눅스에 키를 보내지 않음,
  커널 전 Password: = U-Boot 잠금(uboot_password)
- shell_login: U-Boot 일 수 있는 문맥 unknown 프롬프트를 셸로 단정하지 않음, username 없이 askfirst 활성화
- expect: 미완성 줄 끝에서 일찍 맞지 않음 (페이싱된 출력)
- 덤프: 방언별 바이트 일치(짧은 끝 청크), 취소→재개 기록(부분 결과 상태·실행 시간 합계), 재개 인자 불일치 즉시 거부,
  verify=double 의 double-read, 연결 끊김 시 failed 부분 결과, 셸 hexdump 의 16바이트 미만 0 끝 청크
- printenv/uboot_info: '-' 파티션 크기 채우기, help 기반 has(8자 이름·약어)
"""

from __future__ import annotations

import hashlib
import json
import os
import select
import threading
import time
import tty

import pytest
import serial
from mcp import Client

from mcp_helpers import call
from mocktarget.helpers import Console, make_device
from pweh.runtime import get_runtime

pytestmark = pytest.mark.anyio

SERVER = "uart-mcp"
PROFILES = ["hisilicon-like", "ingenic-like", "hisilicon-legacy"]
PIPE = {"hisilicon-like": "mock-hisilicon", "ingenic-like": "mock-ingenic", "hisilicon-legacy": "hisilicon-ipcam"}
PROMPT = {"hisilicon-like": "hisilicon # ", "ingenic-like": "isvp_t31# ", "hisilicon-legacy": "hisilicon # "}
ENV_PART = {"hisilicon-like": (0x40000, 0x10000), "ingenic-like": (0x40000, 0x10000), "hisilicon-legacy": (0x80000, 0x40000)}
MiB = 1 << 20


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
    yield
    from uart_mcp import server as us

    us.shutdown_all("test teardown")


def make_case(auth, profile: str = "hisilicon-like") -> str:
    return get_runtime(SERVER).cases.create(title="UART 방언 회귀", authorization=auth, profile=PIPE[profile]).id


async def open_session(c, cid: str, dev, *, tcp: bool = False, port: str | None = None) -> str:
    if port is None:
        if tcp:
            host, p = dev.start_tcp()
            port = f"socket://{host}:{p}"
        else:
            port = dev.start_pty()
    r = await call(c, "uart_open", case_id=cid, port=port)
    assert r.get("ok"), r
    return r["session_id"]


async def to_uboot(c, sid: str, dev, delay: float = 0.3) -> dict:
    t = threading.Timer(delay, dev.power_on)
    t.start()
    r = await call(c, "uboot_interrupt", session_id=sid, window_seconds=20)
    t.join()
    assert r.get("interrupted"), r
    return r


async def to_shell(c, sid: str, dev) -> dict:
    threading.Timer(0.2, dev.power_on).start()
    r = await call(c, "uart_wait_for", session_id=sid, pattern=r"Please press Enter to activate this console", timeout=40)
    assert r["matched"], r
    lg = dev.profile["linux"]["login"]
    r = await call(c, "shell_login", session_id=sid, username=lg["username"], password=lg.get("password"), timeout=20)
    assert r.get("logged_in"), r
    return r


async def wait_job(c, job_id: str, timeout: float = 180.0) -> dict:
    deadline = time.monotonic() + timeout
    while True:
        st = await call(c, "uart_job_status", job_id=job_id, wait_seconds=5)
        assert "_error" not in st, st
        if st["status"] not in ("queued", "running", "cancelling"):
            return st
        assert time.monotonic() < deadline, st


async def session_row(c, sid: str) -> dict:
    return next(s for s in (await call(c, "uart_sessions"))["sessions"] if s["session_id"] == sid)


def stop_in_uboot_elsewhere(dev) -> str:
    """사람이 다른 터미널로 U-Boot 에 멈춰 둔 기기 (세션은 부팅 로그도 U-Boot 증거도 보지 못한다). PTY 경로를 돌려준다."""
    path = dev.start_pty()
    sp = serial.Serial(path, 115200, timeout=0.05)
    con = Console(sp, dev)
    dev.power_on()
    con.interrupt_autoboot()
    sp.close()
    time.sleep(1.2)  # 아무도 읽지 않은 출력은 1초 뒤 버려진다 (닫힌 시리얼 포트)
    return path


class ScriptedConsole:
    """os.openpty 기반 가짜 콘솔: 테스트가 기기 출력을 바이트 단위로 쓰고, 세션이 보낸 바이트를 모은다."""

    def __init__(self) -> None:
        self.master, self.slave = os.openpty()
        tty.setraw(self.slave)
        self.path = os.ttyname(self.slave)
        self.rx = bytearray()
        self._stop = threading.Event()
        self._th = threading.Thread(target=self._pump, daemon=True)
        self._th.start()

    def _pump(self) -> None:
        while not self._stop.is_set():
            r, _, _ = select.select([self.master], [], [], 0.05)
            if r:
                try:
                    data = os.read(self.master, 4096)
                except OSError:
                    return
                self.rx += data

    def write(self, data: bytes) -> None:
        os.write(self.master, data)

    def wait_rx(self, needle: bytes, timeout: float = 5.0) -> bool:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if needle in self.rx:
                return True
            time.sleep(0.01)
        return False

    def close(self) -> None:
        self._stop.set()
        self._th.join(1.0)
        for fd in (self.master, self.slave):
            try:
                os.close(fd)
            except OSError:
                pass


# ---------------------------------------------------------------------------
# uboot_interrupt
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("profile", PROFILES)
async def test_interrupt_waits_for_new_boot_when_device_already_booting(devices, auth, profile):
    """회귀(review_todo): 호출 시점에 이미 리눅스로 부팅 중이고 사람이 0.5초 늦게 전원을 재투입 → 이전 부팅의 커널/로그인 출력으로
    0.3초 만에 kernel/linux 로 끝내지 말고, 새 부팅을 기다려 U-Boot 를 얻어야 한다."""
    from uart_mcp.server import server

    dev = devices(profile, time_scale=0.5)
    cid = make_case(auth, profile)
    async with Client(server) as c:
        sid = await open_session(c, cid, dev)
        dev.power_on()
        assert dev.wait_for_state("kernel-boot", 30)
        time.sleep(0.2)  # 세션이 커널 시작 줄을 처리할 시간 (호출 시점: 이전 부팅이 커널 로그를 내보내는 중)
        cycled = threading.Event()

        def late_power_cycle() -> None:
            # 이전 부팅의 askfirst 프롬프트가 호출 뒤에 나온 다음에야 사람이 전원을 재투입한다 (이전 코드는 여기서 linux 로 끝났다)
            if dev.wait_for_state("linux-login", 30):
                time.sleep(0.3)
                cycled.set()
                dev.power_cycle()

        t = threading.Thread(target=late_power_cycle, daemon=True)
        t.start()
        r = await call(c, "uboot_interrupt", session_id=sid, window_seconds=40)
        t.join(5)
        assert cycled.is_set()
        assert r["interrupted"] and r["outcome"] == "prompt" and r["new_boot_seen"] is True, r
        assert r["prompt"] == PROMPT[profile] and r["context"] == "uboot", r
        assert r["autoboot_message"] and r["autoboot_message"].startswith("Hit any key"), r
    assert dev.destructive_events == []


async def test_interrupt_without_power_cycle_keeps_quiet_and_explains(devices, auth):
    """새 부팅이 창 안에 없으면 window_expired + '새 부팅을 보지 못함' 설명. 리눅스가 도는 동안 키를 보내지 않는다(부팅 방해 없음)."""
    from uart_mcp.server import server

    dev = devices("hisilicon-like", time_scale=0.5)
    cid = make_case(auth)
    async with Client(server) as c:
        sid = await open_session(c, cid, dev)
        dev.power_on()
        assert dev.wait_for_state("kernel-boot", 30)
        time.sleep(0.2)  # 호출 시점: 이전 부팅이 커널 로그를 내보내는 중 (창 안에서 askfirst 까지 계속 출력)
        r = await call(c, "uboot_interrupt", session_id=sid, window_seconds=4)
        assert r["interrupted"] is False and r["outcome"] == "window_expired" and r["new_boot_seen"] is False, r
        assert "새 부팅" in r["explanation"] and "전원" in r["explanation"], r["explanation"]
        assert r["keys_sent"] == 0, r
    # 기기는 키 입력 없이 리눅스 askfirst 까지 그대로 부팅했다
    assert dev.state == "linux-login"
    assert dev.destructive_events == []


@pytest.mark.parametrize("profile", PROFILES)
async def test_interrupt_reports_uboot_password_lock(devices, auth, profile):
    """회귀: 커널 시작 전에 나온 Password: 는 부트로더 잠금 → outcome uboot_password (이전: linux 로 오진)."""
    from uart_mcp.server import server

    lock = {"uboot": {"autoboot": {"mode": "keyed", "prompt": "Password: ", "stop_str": "s3cret-not-sent"}}}
    dev = devices(profile, overrides=lock)
    cid = make_case(auth, profile)
    async with Client(server) as c:
        sid = await open_session(c, cid, dev)
        t = threading.Timer(0.3, dev.power_on)
        t.start()
        r = await call(c, "uboot_interrupt", session_id=sid, window_seconds=20)
        t.join()
        assert r["outcome"] == "uboot_password" and r["interrupted"] is False, r
        assert r["prompt"] == "Password: " and r["new_boot_seen"] is True, r
        assert "U-Boot" in r["explanation"] and "추측" in r["explanation"], r["explanation"]
        assert r["context"] == "password"
        sent = r["keys_sent"]
        # 잠금을 본 뒤에는 키를 보내지 않는다 → 기기는 스스로 커널로 부팅한다
        assert dev.wait_for_state(("kernel-boot", "linux-login"), 20)
        assert (await session_row(c, sid))["tx_bytes"] <= sent
    assert dev.destructive_events == []


async def test_shell_login_refuses_bootloader_password_prompt(devices, auth):
    """회귀: 커널 전 U-Boot Password: 잠금에 shell_login 이 리눅스 비밀번호를 보내던 문제 → uboot_password_prompt, 아무것도 보내지 않음."""
    from uart_mcp.server import server

    lock = {"uboot": {"autoboot": {"mode": "keyed", "prompt": "Password: ", "stop_str": "s3cret-not-sent"}}}
    dev = devices("hisilicon-like", time_scale=0.5, overrides=lock)  # 잠금 대기 = bootdelay(2) × 0.5초
    cid = make_case(auth)
    async with Client(server) as c:
        sid = await open_session(c, cid, dev)
        threading.Timer(0.2, dev.power_on).start()
        w = await call(c, "uart_wait_for", session_id=sid, pattern=r"Password: $", timeout=30)
        assert w["matched"], w
        before = (await session_row(c, sid))["tx_bytes"]
        lg = dev.profile["linux"]["login"]
        r = await call(c, "shell_login", session_id=sid, username=lg["username"], password=lg["password"], timeout=5)
        assert r["status"] == "uboot_password_prompt" and r["logged_in"] is False and r["steps"] == [], r
        assert (await session_row(c, sid))["tx_bytes"] == before
        assert dev.state == "uboot-autoboot"  # 잠금 프롬프트에서 아무 입력도 받지 않았다
        # 잠금 시간이 지나 리눅스로 부팅하면 정상 로그인
        w = await call(c, "uart_wait_for", session_id=sid, pattern=r"Please press Enter to activate this console", timeout=40)
        assert w["matched"], w
        r = await call(c, "shell_login", session_id=sid, username=lg["username"], password=lg["password"], timeout=20)
        assert r["logged_in"] and r["status"] == "ok", r
    assert dev.destructive_events == []


# ---------------------------------------------------------------------------
# shell_login
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("profile", PROFILES)
async def test_shell_login_does_not_promote_unknown_prompt(devices, auth, profile):
    """회귀: 증거 없는 U-Boot 프롬프트('hisilicon # ' 은 리눅스 정규식에도 맞음)에서 shell_login 이 already_logged_in 으로
    리눅스 phase 증거를 만들던 문제 → context_unknown, 아무것도 보내지 않고 문맥 유지. uart_sync 로 U-Boot 확정."""
    from uart_mcp.server import server

    dev = devices(profile)
    cid = make_case(auth, profile)
    path = stop_in_uboot_elsewhere(dev)
    async with Client(server) as c:
        sid = await open_session(c, cid, dev, port=path)
        dev.feed_input(b"\r")  # 빈 줄 → 새 프롬프트만 (U-Boot 증거 없음; 직전 명령도 없음)
        deadline = time.monotonic() + 5
        while (await session_row(c, sid))["prompt"] != PROMPT[profile]:
            assert time.monotonic() < deadline
            time.sleep(0.05)
        before = await session_row(c, sid)
        assert before["context"] == "unknown" and before["phase"] == "unknown", before
        r = await call(c, "shell_login", session_id=sid, username="root", password="x", timeout=5)
        assert r["ok"] is False and r["status"] == "context_unknown" and "uart_sync" in r["hint"], r
        after = await session_row(c, sid)
        assert after["context"] == "unknown" and after["phase"] == "unknown" and after["tx_bytes"] == before["tx_bytes"], after
        s = await call(c, "uart_sync", session_id=sid)
        assert s["evidence"] == "uboot" and s["context"] == "uboot", s
        r = await call(c, "shell_login", session_id=sid, username="root", password="x", timeout=5)
        assert r["status"] == "uboot_prompt", r
    assert not any(e.get("type") == "login" for e in dev.events)
    assert dev.destructive_events == []


async def test_shell_login_without_username_activates_console(devices, auth):
    """username 생략: askfirst Enter 만 보내고 login: 에서 username_required (실패로 세지 않음) → 계정을 주면 로그인."""
    from uart_mcp.server import server

    dev = devices("ingenic-like")
    cid = make_case(auth, "ingenic-like")
    async with Client(server) as c:
        sid = await open_session(c, cid, dev)
        threading.Timer(0.2, dev.power_on).start()
        r = await call(c, "uart_wait_for", session_id=sid, pattern=r"Please press Enter to activate this console", timeout=40)
        assert r["matched"], r
        r = await call(c, "shell_login", session_id=sid, timeout=10)
        assert r["status"] == "username_required" and r["logged_in"] is False and r["steps"] == ["askfirst-enter"], r
        assert r["prompt"] == "ingenic login: "
        lg = dev.profile["linux"]["login"]
        for _ in range(3):  # username_required 는 실패 횟수(3회 제한)에 들어가지 않는다
            again = await call(c, "shell_login", session_id=sid, timeout=5)
            assert again["status"] == "username_required", again
        r = await call(c, "shell_login", session_id=sid, username=lg["username"], password=lg["password"], timeout=20)
        assert r["logged_in"] and r["status"] == "ok" and r["user"] == lg["username"], r
        assert r["context"] == "linux-shell"
    assert dev.destructive_events == []


async def test_shell_login_askfirst_only_console(auth, workspace):
    """로그인 없는 콘솔(::askfirst:-/bin/sh): username 없이 Enter 한 번으로 셸 → ok, user=None (계정을 지어내지 않는다)."""
    from uart_mcp.server import server

    con = ScriptedConsole()
    try:
        cid = make_case(auth)
        async with Client(server) as c:
            sid = (await call(c, "uart_open", case_id=cid, port=con.path))["session_id"]
            con.write(b"init started: BusyBox v1.24.1\r\n\r\nPlease press Enter to activate this console. ")

            def shell_after_enter() -> None:
                if con.wait_rx(b"\r", 10):
                    con.write(b"\r\n\r\nBusyBox v1.24.1 built-in shell (ash)\r\n/ # ")

            th = threading.Thread(target=shell_after_enter, daemon=True)
            th.start()
            r = await call(c, "shell_login", session_id=sid, timeout=10)
            th.join(2)
            assert r["logged_in"] and r["status"] == "ok" and r["user"] is None and r["steps"] == ["askfirst-enter"], r
            assert r["context"] == "linux-shell" and r["prompt"] == "/ # "
            assert bytes(con.rx) == b"\r"  # Enter 한 번만 보냈다
    finally:
        from uart_mcp import server as us

        us.shutdown_all("test")
        con.close()


# ---------------------------------------------------------------------------
# expect: 미완성 줄
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("profile", PROFILES)
async def test_expect_dollar_waits_for_complete_line(devices, auth, profile):
    """회귀: expect='^bootargs=(.*)$' 가 페이싱된(64바이트씩 끊겨 오는) 출력의 미완성 줄에서 일찍 맞아 값이 잘리던 문제."""
    from uart_mcp.server import server

    dev = devices(profile)
    cid = make_case(auth, profile)
    async with Client(server) as c:
        sid = await open_session(c, cid, dev)
        await to_uboot(c, sid, dev)
        want = dev.uboot.env["bootargs"]
        assert len(want) > 128
        dev.time_scale = 1.0  # 실제 115200 baud 속도로 64바이트씩 내보낸다 (청크 사이 약 5.5ms)
        dev.pace_output = True
        for pattern in (r"^bootargs=(.*)$", r"^bootargs=(.*)"):
            r = await call(c, "uart_send_command", session_id=sid, command="printenv bootargs", expect=pattern, timeout=10)
            assert r["matched"] and r["match_kind"] == "expect", r
            assert r["groups"] == [want], (pattern, r["groups"], want)
            w = await call(c, "uart_wait_for", session_id=sid, pattern=r"^\S+ ?# $", timeout=5)  # 다음 명령 전에 프롬프트까지 소비
            assert w["matched"], w
    assert dev.destructive_events == []


async def test_wait_for_partial_line_then_rest(auth, workspace):
    """uart_wait_for: 'bootargs=abc' 만 온 상태에서 '$' 로 끝나는 정규식이 맞지 않고, 줄이 끝난 뒤 전체 값으로 맞는다."""
    from uart_mcp.server import server

    con = ScriptedConsole()
    try:
        cid = make_case(auth)
        async with Client(server) as c:
            sid = (await call(c, "uart_open", case_id=cid, port=con.path))["session_id"]
            con.write(b"bootargs=console=ttyAMA0,1152")
            threading.Timer(0.01, con.write, args=(b"00 mem=40M\r\n",)).start()
            r = await call(c, "uart_wait_for", session_id=sid, pattern=r"^bootargs=(.*)$", timeout=5, since_cursor=0)
            assert r["matched"] and r["groups"] == ["console=ttyAMA0,115200 mem=40M"], r
            # 줄 끝이 끝내 오지 않으면(프롬프트 같은 꼬리) 조용해진 뒤 받아들인다
            con.write(b"(none) login: ")
            r = await call(c, "uart_wait_for", session_id=sid, pattern=r"login: $", timeout=5)
            assert r["matched"] and r["match"] == "login: ", r
    finally:
        from uart_mcp import server as us

        us.shutdown_all("test")
        con.close()


# ---------------------------------------------------------------------------
# U-Boot 덤프
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("profile", PROFILES)
async def test_uboot_dump_per_dialect_short_tail_matches_flash(devices, auth, profile):
    """방언별 sf read 출력(빈 줄만/확인 줄/--->spend), 대문자 CRC32, 패딩 없는 md(legacy) — 5바이트 끝 청크까지 플래시와 같아야 한다."""
    from uart_mcp.server import server

    dev = devices(profile)
    cid = make_case(auth, profile)
    off, ln = 0x40000, 0x4005
    async with Client(server) as c:
        sid = await open_session(c, cid, dev)
        await to_uboot(c, sid, dev)
        await call(c, "uboot_printenv", session_id=sid)
        info = await call(c, "uboot_info", session_id=sid)
        assert info["ok"] and info["safe_ram_addr"], info
        st = await call(c, "uboot_dump_start", case_id=cid, session_id=sid, offset=off, length=ln, chunk_size=0x2000, output_name="tail")
        assert st["ok"] and st["chunks"] == 3, st
        res = await wait_job(c, st["job_id"])
        assert res["status"] == "succeeded", res
        out = res["result"]
        want = dev.flash.read(off, ln)
        case = get_runtime(SERVER).cases.get(cid)
        assert (case.dir / out["path"]).read_bytes() == want
        assert out["sha256"] == hashlib.sha256(want).hexdigest() and out["size"] == ln
        assert out["verification"]["method"] == "crc32-chunks" and out["chunks"]["retries"] == 0, out
        assert out["verification"]["full_range"]["match"] is True, out["verification"]
        assert out["duration_seconds_total"] == out["duration_seconds"] and out["runs"] == 1
        arts = {a["path"]: a for a in case.artifacts()}
        assert arts[out["path"]]["kind"] == "flash-dump" and arts[out["path"]]["sha256"] == out["sha256"]
        assert arts[out["metadata_path"]]["kind"] == "other"
        meta = json.loads((case.dir / out["metadata_path"]).read_text(encoding="utf-8"))
        assert [r["status"] for r in meta["runs"]] == ["succeeded"] and meta["duration_seconds_total"] >= 0
        assert all(ch["method"] == "crc32" for ch in meta["chunks"]["checks"])
    assert dev.destructive_events == []


@pytest.mark.parametrize("profile", PROFILES)
async def test_uboot_dump_cancel_resume_bookkeeping(devices, auth, profile):
    """취소 → 부분 결과 status=cancelled, state 의 실행 기록 → 다른 인자로 재개 시도는 즉시 거부 → 같은 인자로 재개 →
    바이트 일치, runs=2, duration_seconds_total = 실행 시간 합계."""
    from uart_mcp.server import server

    dev = devices(profile, time_scale=0.05, pace_output=True)
    cid = make_case(auth, profile)
    async with Client(server) as c:
        sid = await open_session(c, cid, dev)
        await to_uboot(c, sid, dev)
        await call(c, "uboot_info", session_id=sid)
        args = dict(case_id=cid, session_id=sid, offset=0, length=0x20000, chunk_size=0x4000, output_name="resume")
        st = await call(c, "uboot_dump_start", **args)
        assert st["ok"], st
        deadline = time.monotonic() + 60
        while True:
            js = await call(c, "uart_job_status", job_id=st["job_id"])
            if (js.get("meta") or {}).get("overall_done_bytes", 0) >= 0x4000:
                break
            assert js["status"] == "running" and time.monotonic() < deadline, js
            time.sleep(0.05)
        await call(c, "uart_job_cancel", job_id=st["job_id"])
        res = await wait_job(c, st["job_id"])
        assert res["status"] == "cancelled", res
        assert res["result"]["status"] == "cancelled", res["result"]  # 이전: 'running' 이 남았다
        case = get_runtime(SERVER).cases.get(cid)
        state = json.loads((case.dir / "dumps" / "resume.state.json").read_text(encoding="utf-8"))
        done = state["completed_chunks"]
        assert 1 <= done < 8 and res["result"]["completed_chunks"] == done
        assert state["runs"][-1]["status"] == "cancelled" and state["runs"][-1]["duration_seconds"] > 0, state["runs"]
        jobs_before = len((await call(c, "uart_jobs"))["jobs"])
        bad = await call(c, "uboot_dump_start", **{**args, "chunk_size": 0x2000})
        assert "_error" in bad and "다른 인자" in bad["_error"] and "chunk_size" in bad["_error"], bad
        assert len((await call(c, "uart_jobs"))["jobs"]) == jobs_before  # job 을 띄우지 않았다
        st2 = await call(c, "uboot_dump_start", **args)
        assert st2["ok"] and st2["resume_from_chunk"] == done, st2
        res2 = await wait_job(c, st2["job_id"])
        assert res2["status"] == "succeeded", res2
        out = res2["result"]
        assert out["chunks"]["resumed_from"] == done and out["runs"] == 2
        assert out["sha256"] == hashlib.sha256(dev.flash.read(0, 0x20000)).hexdigest()
        meta = json.loads((case.dir / out["metadata_path"]).read_text(encoding="utf-8"))
        assert [r["status"] for r in meta["runs"]] == ["cancelled", "succeeded"], meta["runs"]
        total = sum(r["duration_seconds"] for r in meta["runs"])
        assert abs(out["duration_seconds_total"] - total) < 0.05 and out["duration_seconds_total"] > out["duration_seconds"], out
        assert meta["duration_seconds_total"] == out["duration_seconds_total"]
    assert dev.destructive_events == []


async def test_uboot_dump_verify_double_records_double_read(devices, auth):
    from uart_mcp.server import server

    dev = devices("hisilicon-legacy")
    cid = make_case(auth, "hisilicon-legacy")
    async with Client(server) as c:
        sid = await open_session(c, cid, dev)
        await to_uboot(c, sid, dev)
        await call(c, "uboot_info", session_id=sid)
        st = await call(c, "uboot_dump_start", case_id=cid, session_id=sid, offset=0x80000, length=0x2000, chunk_size=0x1000,
                        verify="double", output_name="dbl")
        res = await wait_job(c, st["job_id"])
        assert res["status"] == "succeeded", res
        out = res["result"]
        assert out["verification"]["method"] == "double-read", out["verification"]  # 이전: size-only
        case = get_runtime(SERVER).cases.get(cid)
        meta = json.loads((case.dir / out["metadata_path"]).read_text(encoding="utf-8"))
        assert meta["verification"]["method"] == "double-read"
        assert all(ch["method"] == "double-read" for ch in meta["chunks"]["checks"])
        assert (case.dir / out["path"]).read_bytes() == dev.flash.read(0x80000, 0x2000)
    assert dev.destructive_events == []


async def test_uboot_dump_disconnect_leaves_failed_partial(devices, auth):
    """덤프 중 연결이 끊기면 job failed, 부분 결과 status=failed, state 의 실행 기록에 failed + 오류. 같은 이름으로 재개 가능 상태."""
    from uart_mcp.server import server

    dev = devices("hisilicon-like", time_scale=0.05, pace_output=True)
    cid = make_case(auth)
    async with Client(server) as c:
        sid = await open_session(c, cid, dev, tcp=True)
        await to_uboot(c, sid, dev)
        await call(c, "uboot_info", session_id=sid)
        st = await call(c, "uboot_dump_start", case_id=cid, session_id=sid, offset=0, length=0x20000, chunk_size=0x4000,
                        output_name="cut")
        assert st["ok"], st
        deadline = time.monotonic() + 60
        while (((await call(c, "uart_job_status", job_id=st["job_id"])).get("meta") or {}).get("overall_done_bytes", 0) < 0x4000):
            assert time.monotonic() < deadline
            time.sleep(0.05)
        dev.stop()  # USB 분리/네트워크 단절
        res = await wait_job(c, st["job_id"])
        assert res["status"] == "failed", res
        assert res["result"]["status"] == "failed" and res["result"]["completed_chunks"] >= 1, res["result"]
        case = get_runtime(SERVER).cases.get(cid)
        state = json.loads((case.dir / "dumps" / "cut.state.json").read_text(encoding="utf-8"))
        assert state["runs"][-1]["status"] == "failed" and state["runs"][-1].get("error"), state["runs"]
        assert (case.dir / "dumps" / "cut.bin.part").stat().st_size == state["completed_chunks"] * 0x4000


async def test_dump_start_rejects_mismatched_resume_state_immediately(devices, auth):
    """같은 output_name 의 진행 중 덤프가 다른 인자로 시작됐으면 job 을 띄우기 전에 거부 (U-Boot·셸 모두)."""
    from uart_mcp.server import server

    dev = devices("hisilicon-like")
    cid = make_case(auth)
    case = get_runtime(SERVER).cases.get(cid)
    ddir = case.subdir("dumps")
    (ddir / "u.state.json").write_text(json.dumps({"identity": {"method": "uboot-md", "source": "sf", "offset": 0, "length": 0x10000,
                                                                "chunk_size": 0x4000}, "completed_chunks": 1}), encoding="utf-8")
    (ddir / "u.bin.part").write_bytes(b"\0" * 0x4000)
    (ddir / "s.state.json").write_text(json.dumps({"identity": {"method": "linux-base64", "path": "/dev/mtd2", "offset": 0,
                                                                "length": 0x10000, "chunk_size": 0x4000}, "completed_chunks": 2}),
                                       encoding="utf-8")
    async with Client(server) as c:
        sid = await open_session(c, cid, dev)
        r = await call(c, "uboot_dump_start", case_id=cid, session_id=sid, offset=0, length=0x10000, chunk_size=0x8000,
                       ram_addr="0x42000000", output_name="u")
        assert "_error" in r and "chunk_size" in r["_error"], r
        r = await call(c, "shell_dump_start", case_id=cid, session_id=sid, path="/dev/mtd1", chunk_size=0x4000, output_name="s")
        assert "_error" in r and "path" in r["_error"], r
        r = await call(c, "shell_dump_start", case_id=cid, session_id=sid, path="/dev/mtd2", chunk_size=0x4000, method="hexdump",
                       output_name="s")
        assert "_error" in r and "method" in r["_error"], r
        assert (await call(c, "uart_jobs"))["jobs"] == []
        # resume=false 는 처음부터 받으므로 검사하지 않는다 (여기서는 셸 문맥이 아니어서 다른 이유로 거부된다)
        r = await call(c, "shell_dump_start", case_id=cid, session_id=sid, path="/dev/mtd1", chunk_size=0x4000, output_name="s",
                       resume=False)
        assert "_error" in r and "다른 인자" not in r["_error"], r


# ---------------------------------------------------------------------------
# printenv / uboot_info
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("profile", PROFILES)
async def test_printenv_partitions_and_info_has(devices, auth, profile):
    """'-' 파티션 크기: printenv(uboot_info 전)도 부팅 로그의 플래시 크기로 채운다. help 8자 이름('printenv-')·약어 has."""
    from uart_mcp.server import server

    dev = devices(profile)
    cid = make_case(auth, profile)
    async with Client(server) as c:
        sid = await open_session(c, cid, dev)
        await to_uboot(c, sid, dev)
        env = await call(c, "uboot_printenv", session_id=sid)
        parts = env["partitions"]
        assert parts and all(p["size"] for p in parts), parts
        assert parts[-1]["offset"] + parts[-1]["size"] == 16 * MiB, parts
        if profile == "ingenic-like":
            assert env["flash_size"] is None  # 'SF: Detected BY25Q128AS' 는 크기가 없다 (mtdparts 가 모두 명시 크기)
        else:
            assert env["flash_size"] == 16 * MiB and env["flash_size_source"] == "부팅 로그", env
        info = await call(c, "uboot_info", session_id=sid)
        has, via = info["has"], info["has_via"]
        for name in ("printenv", "setenv", "saveenv", "sf", "md", "crc32", "tftp"):
            assert has[name] is True, (name, has, info["commands"])
        assert has["nand"] is False and has["mmc"] is False and has["fatwrite"] is False
        expect_tftpboot = profile != "hisilicon-legacy"
        assert has["tftpboot"] is expect_tftpboot and has["tftpput"] is (profile == "ingenic-like"), has
        assert via == ({"tftp": "tftpboot"} if profile == "hisilicon-like" else {}), via
        assert info["partitions"] and info["partitions"][-1]["offset"] + info["partitions"][-1]["size"] == 16 * MiB
    assert dev.destructive_events == []


async def test_printenv_without_boot_log_then_info_fills_dash_partition(devices, auth):
    """부팅 로그를 못 본 세션: printenv 의 '-' 크기는 null(+note) → uboot_info(sf probe 크기) 의 partitions 는 채워진다."""
    from uart_mcp.server import server

    dev = devices("hisilicon-like")
    cid = make_case(auth)
    path = stop_in_uboot_elsewhere(dev)
    async with Client(server) as c:
        sid = await open_session(c, cid, dev, port=path)
        s = await call(c, "uart_sync", session_id=sid)
        assert s["context"] == "uboot", s
        env = await call(c, "uboot_printenv", session_id=sid)
        assert env["partitions"][-1]["name"] == "app" and env["partitions"][-1]["size"] is None and env["flash_size"] is None
        assert "uboot_info" in env["note"]
        info = await call(c, "uboot_info", session_id=sid)
        assert info["flash"]["size_bytes"] == 16 * MiB and info["flash"]["source"] == "sf probe"
        app = info["partitions"][-1]
        assert app["name"] == "app" and app["offset"] + app["size"] == 16 * MiB, info["partitions"]
        env2 = await call(c, "uboot_printenv", session_id=sid)
        assert env2["partitions"][-1]["size"] == app["size"] and env2["flash_size_source"] == "sf probe"
    assert dev.destructive_events == []


# ---------------------------------------------------------------------------
# 셸 덤프
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("profile,method,expected", [
    ("hisilicon-like", "hexdump", "linux-hexdump"),
    ("ingenic-like", "auto", "linux-hexdump"),  # ingenic 에는 base64 애플릿이 없다
    ("hisilicon-legacy", "auto", "linux-base64"),
    ("hisilicon-legacy", "hexdump", "linux-hexdump"),
])
async def test_shell_dump_odd_range_with_zero_tail(devices, auth, profile, method, expected):
    """회귀: BusyBox hexdump -C 는 16바이트 미만의 0 데이터를 '*' 한 줄로만 찍는다(끝 주소 없음) — 그 끝 청크에서 덤프 전체가
    실패하던 문제. 홀수 오프셋/길이(bs=1 dd)와 짧은 끝 청크까지 바이트가 같아야 한다."""
    from uart_mcp.server import server

    dev = devices(profile)
    cid = make_case(auth, profile)
    part_off, _ = ENV_PART[profile]
    off, ln, chunk = 0x10, 0x305, 0x100
    want = dev.flash.read(part_off + off, ln)
    assert want[-5:] == b"\0" * 5  # env 영역 끝부분은 0 으로 채워져 있다 (회귀 조건)
    async with Client(server) as c:
        sid = await open_session(c, cid, dev)
        await to_shell(c, sid, dev)
        st = await call(c, "shell_dump_start", case_id=cid, session_id=sid, path="/dev/mtd1", offset=off, length=ln, chunk_size=chunk,
                        method=method, output_name="odd")
        assert st["ok"], st
        res = await wait_job(c, st["job_id"])
        assert res["status"] == "succeeded", res
        out = res["result"]
        assert out["method"] == expected and out["verification"]["method"] == "md5-device", out
        assert out["sha256"] == hashlib.sha256(want).hexdigest() and out["chunks"]["retries"] == 0, out
        case = get_runtime(SERVER).cases.get(cid)
        assert (case.dir / out["path"]).read_bytes() == want
    assert dev.destructive_events == []
