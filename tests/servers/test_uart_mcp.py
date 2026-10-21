"""uart-mcp 서버 테스트: in-memory MCP 클라이언트(+ stdio 1개) ↔ pweh.mocktarget 카메라 시뮬레이터(PTY/TCP).

안전 게이트 오라클: MockDevice.destructive_events — 파괴적 명령이 기기에 도달하면 기록된다. 기본 정책(deny)에서는 항상 [].
"""

from __future__ import annotations

import hashlib
import json
import re
import threading
import time
from pathlib import Path

import pytest
import serial
from mcp import Client

from mcp_helpers import call, stdio_params
from mocktarget.helpers import Console, make_device
from pweh.runtime import get_runtime

pytestmark = pytest.mark.anyio

SERVER = "uart-mcp"
PIPE = {"hisilicon-like": "mock-hisilicon", "ingenic-like": "mock-ingenic", "hisilicon-legacy": "hisilicon-ipcam"}
ENV_PART = {"hisilicon-like": (0x40000, 0x10000), "ingenic-like": (0x40000, 0x10000), "hisilicon-legacy": (0x80000, 0x40000)}


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
    return get_runtime(SERVER).cases.create(title="UART 랩 테스트", authorization=auth, profile=PIPE[profile]).id


async def open_session(c, cid: str, dev, *, tcp: bool = False, **kw) -> str:
    if tcp:
        host, port = dev.start_tcp()
        url = f"socket://{host}:{port}"
    else:
        url = dev.start_pty()
    r = await call(c, "uart_open", case_id=cid, port=url, **kw)
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


def approve(approval_id: str) -> None:
    r = get_runtime(SERVER)
    rec = r.approvals.get(approval_id)
    r.approvals.decide(approval_id, approve=True, code=rec["code"], via="test")


# ---------------------------------------------------------------------------


CONTRACT_TOOLS = {
    "uart_list_ports", "uart_open", "uart_close", "uart_sessions", "uart_read", "uart_write", "uart_send_command", "uart_wait_for",
    "uart_set_context", "uart_send_break", "uart_set_signals", "uart_detect_baud", "uart_capture_boot", "uboot_interrupt",
    "uboot_printenv", "uboot_info", "uboot_dump_start", "shell_login", "shell_identify", "shell_dump_start",
    "uart_job_status", "uart_job_cancel", "uart_jobs",
}


async def test_tools_and_ports():
    from uart_mcp.server import server

    async with Client(server) as c:
        tools = {t.name for t in (await c.list_tools()).tools}
        assert CONTRACT_TOOLS <= tools, CONTRACT_TOOLS - tools
        r = await call(c, "uart_list_ports")
        assert r["ok"] and isinstance(r["ports"], list)
        r = await call(c, "uart_sessions")
        assert r["ok"] and r["sessions"] == []


async def test_open_requires_authorization(devices):
    from uart_mcp.server import server

    dev = devices()
    cid = get_runtime(SERVER).cases.create(title="no auth").id
    async with Client(server) as c:
        r = await call(c, "uart_open", case_id=cid, port=dev.start_pty())
        assert "_error" in r and "authorization" in r["_error"]


async def test_uboot_session_pty_read_send_logs(devices, auth):
    from uart_mcp.server import server

    dev = devices("hisilicon-like")
    cid = make_case(auth)
    async with Client(server) as c:
        sid = await open_session(c, cid, dev)
        r = await to_uboot(c, sid, dev)
        assert r["prompt"] == "hisilicon # " and r["autoboot_message"].startswith("Hit any key") and r["bootdelay"] == 2
        r = await call(c, "uart_send_command", session_id=sid, command="version")
        assert r["ok"] and r["matched"] and not r["timed_out"]
        assert "U-Boot 2016.11" in r["output"] and r["echo_found"] and not r["output"].lstrip().startswith("version")
        assert r["context"] == "uboot" and r["prompt"] == "hisilicon # "
        assert "hisilicon #" not in r["output"]
        # expect 정규식 (줄 단위 ^$, CRLF 무관)
        r = await call(c, "uart_send_command", session_id=sid, command="printenv bootdelay", expect=r"^bootdelay=(\d+)$")
        assert r["matched"] and r["groups"] == ["2"]
        # 커서 기반 읽기: 명령 사이에 온 출력도 잃지 않는다
        tail = await call(c, "uart_read", session_id=sid, tail=True, max_bytes=200)
        assert "hisilicon # " in tail["text"]
        full = await call(c, "uart_read", session_id=sid, since_cursor=0, max_bytes=1 << 20)
        assert "Hit any key to stop autoboot" in full["text"] and full["cursor_start"] == 0 and not full["more"]
        w = await call(c, "uart_wait_for", session_id=sid, pattern=r"DRAM:\s+(\d+) MiB", since_cursor=0, timeout=1)
        assert w["matched"] and w["groups"] == ["64"]
        nothing = await call(c, "uart_wait_for", session_id=sid, pattern=r"never-appears", timeout=0.3)
        assert nothing["timed_out"] and not nothing["matched"]
        sync = await call(c, "uart_sync", session_id=sid)
        assert sync["evidence"] == "uboot" and sync["context"] == "uboot"
        sess = (await call(c, "uart_sessions"))["sessions"][0]
        assert sess["context"] == "uboot" and sess["phase"] == "uboot" and sess["rx_bytes"] > 0
        # 로그 파일은 열려 있는 동안에도 보이고 아티팩트로 등록돼 있다
        case = get_runtime(SERVER).cases.get(cid)
        kinds = {a["kind"] for a in case.artifacts()}
        assert {"uart-log", "uart-raw", "uart-events"} <= kinds
        closed = await call(c, "uart_close", session_id=sid)
        assert closed["ok"] and len(closed["artifacts"]) == 3
    log_text = (case.dir / "uart" / f"{sid}.log").read_text(encoding="utf-8")
    assert " TX | version\\r" in log_text and " RX | U-Boot 2016.11" in log_text
    raw = (case.dir / "uart" / f"{sid}.raw").read_bytes()
    assert b"Hit any key to stop autoboot" in raw
    events = [json.loads(ln) for ln in (case.dir / "uart" / f"{sid}.events.jsonl").read_text(encoding="utf-8").splitlines()]
    assert any(e["type"] == "tx" and e.get("rule_id") == "uboot.version" for e in events)
    assert any(e["type"] == "context" and e["to"] == "uboot" for e in events)
    assert dev.destructive_events == []


@pytest.mark.parametrize("profile", ["hisilicon-like", "ingenic-like", "hisilicon-legacy"])
async def test_printenv_and_info_parsing(devices, auth, profile):
    from uart_mcp.server import server

    dev = devices(profile)
    cid = make_case(auth, profile)
    async with Client(server) as c:
        sid = await open_session(c, cid, dev)
        await to_uboot(c, sid, dev)
        env = await call(c, "uboot_printenv", session_id=sid)
        assert env["ok"] and env["complete"] and env["tracked"], env
        assert env["bootcmd"] == dev.uboot.env["bootcmd"]
        assert env["mtdparts"].startswith("mtdparts=")
        assert [p["name"] for p in env["partitions"]][:2] == ["boot", "env"]
        info = await call(c, "uboot_info", session_id=sid)
        assert info["ok"], info
        assert info["version"].startswith("U-Boot 20")
        assert info["has"]["md"] and info["has"]["crc32"] and info["has"]["sf"]
        assert info["flash"]["type"] == "spi-nor"
        expected_ram = {"hisilicon-like": "0x42000000", "ingenic-like": "0x80600000", "hisilicon-legacy": "0x82000000"}[profile]
        assert info["safe_ram_addr"] == expected_ram, info["safe_ram"]
        if profile == "hisilicon-like":
            assert info["flash"]["size_bytes"] == 16 << 20 and info["bdinfo"]["relocaddr"] == "0x43f9e000"
        elif profile == "hisilicon-legacy":
            assert info["flash"]["size_bytes"] == 16 << 20  # '16384 KiB hi_fmc …'
        else:
            # SF: Detected BY25Q128AS 는 크기가 없다 → 부팅 로그/mtdparts 로 보완
            assert info["flash"]["size_bytes"] == 16 << 20 or info["flash"].get("size_bytes_lower_bound") == 16 << 20
    assert dev.destructive_events == []


async def test_destructive_denied_by_default_never_reach_device(devices, auth):
    from uart_mcp.server import server

    dev = devices("hisilicon-like")
    cid = make_case(auth)
    async with Client(server) as c:
        sid = await open_session(c, cid, dev)
        await to_uboot(c, sid, dev)
        await call(c, "uboot_printenv", session_id=sid)
        for cmd in ("saveenv", "sf erase 0 10000", "mw.b 0x42000000 0xff 0x10", "run nosuchvar", "env save", "sav",
                    "echo " + "A" * 300):
            r = await call(c, "uart_send_command", session_id=sid, command=cmd)
            assert r.get("status") == "denied" and r["ok"] is False, (cmd, r)
        # 분할 쓰기: 'sa' 는 줄 끝이 없어 허용(실행 안 됨), 'veenv\r' 은 'saveenv' 로 조립되어 거부
        w1 = await call(c, "uart_write", session_id=sid, data="sa")
        assert w1["ok"] and w1["pending_input"] == "sa"
        w2 = await call(c, "uart_write", session_id=sid, data="veenv\r")
        assert w2["status"] == "denied" and w2["plan"]["lines"][0]["line"] == "saveenv"
        # 미완성 입력이 남은 채 이어 보내는 명령도 조립된 줄로 분류
        r = await call(c, "uart_send_command", session_id=sid, command="veenv")
        assert r["status"] == "denied"
        # 탭(자동완성)·ESC 가 섞인 줄은 DESTRUCTIVE
        r = await call(c, "uart_write", session_id=sid, data="\x15sav\t\r")
        assert r["status"] == "denied" and r["gate"]["classification"]["rule_id"] == "uart.uncertain-input"
        # Ctrl-C 로 줄을 비우면 정상 명령은 계속 동작
        s = await call(c, "uart_sync", session_id=sid)
        assert s["evidence"] == "uboot"
        r = await call(c, "uart_send_command", session_id=sid, command="printenv bootdelay")
        assert r["ok"] and "bootdelay=2" in r["output"]
        # 수동 문맥 지정으로 완화할 수 없다: U-Boot 프롬프트에서 linux-shell 로 지정해도 saveenv 는 거부
        sc = await call(c, "uart_set_context", session_id=sid, context="linux-shell")
        assert sc["warning"]
        r = await call(c, "uart_send_command", session_id=sid, command="saveenv")
        assert r["status"] == "denied", r
        await call(c, "uart_set_context", session_id=sid, context="auto")
        # 리눅스로 부팅 → 셸에서 파괴적 명령 거부
        boot = await call(c, "uart_send_command", session_id=sid, command="boot", timeout=30, expect=r"Please press Enter to activate this console")
        assert boot["ok"] and boot["matched"], boot
        lg = dev.profile["linux"]["login"]
        li = await call(c, "shell_login", session_id=sid, username=lg["username"], password=lg["password"])
        assert li["logged_in"], li
        for cmd in ("flash_erase /dev/mtd0 0 0", "dd if=/dev/zero of=/dev/mtd1", "echo x > /dev/mtdblock2", "fw_setenv bootdelay 0",
                    "saveenv", "sh -c 'flash_eraseall /dev/mtd3'"):
            r = await call(c, "uart_send_command", session_id=sid, command=cmd)
            assert r.get("status") == "denied", (cmd, r)
        r = await call(c, "uart_send_command", session_id=sid, command="cat /proc/mtd")
        assert r["ok"] and 'mtd1: 00010000 00010000 "env"' in r["output"]
        # expect 는 명령 에코 줄이 아니라 실제 출력에서 맞아야 한다
        r = await call(c, "uart_send_command", session_id=sid, command="echo pweh-marker-1", expect=r"^pweh-marker-1$")
        assert r["matched"] and r["output"].strip().endswith("pweh-marker-1") and r["output"].count("pweh-marker-1") == 1, r
        # 비밀번호는 로그·이벤트·감사 기록에 남지 않는다
        case = get_runtime(SERVER).cases.get(cid)
        pw = lg["password"]
        for f in (case.dir / "uart" / f"{sid}.log", case.dir / "uart" / f"{sid}.events.jsonl", case.dir / "audit.jsonl"):
            assert f"{pw}\\r" not in f.read_text(encoding="utf-8") and f'"{pw}"' not in f.read_text(encoding="utf-8"), f
        assert "******" in (case.dir / "uart" / f"{sid}.log").read_text(encoding="utf-8")
    assert dev.destructive_events == []
    assert not any("saveenv" in (e.get("line") or "") for e in dev.commands())
    # 안전 결정도 세션 이벤트 로그에 남는다 (거부된 줄은 tx 이벤트가 없다)
    events = [json.loads(ln) for ln in (case.dir / "uart" / f"{sid}.events.jsonl").read_text(encoding="utf-8").splitlines()]
    denied = [e for e in events if e["type"] == "safety" and e["status"] == "denied"]
    assert any(e["lines"] == ["saveenv"] and e["rule_id"] == "uboot.saveenv" for e in denied), denied[:3]
    assert any(e["lines"] == ["flash_erase /dev/mtd0 0 0"] for e in denied)
    assert not any(e["type"] == "tx" and any(ln.get("line") == "saveenv" for ln in e.get("lines", [])) for e in events)
    assert any(e["type"] == "safety" and e["tool"] == "uart_open" and e["allowed"] for e in events)
    assert any(e["type"] == "safety" and e["tool"] == "shell_login" and e["password"] == "<masked>" for e in events)


async def test_destructive_approval_flow_and_bare_enter_repeat(workspace, devices, auth):
    from uart_mcp.server import server

    workspace["set_safety"](destructive_policy="approve", approval_methods=["cli"])
    dev = devices("hisilicon-like")
    cid = make_case(auth)
    async with Client(server) as c:
        sid = await open_session(c, cid, dev)
        await to_uboot(c, sid, dev)
        cmd = "mw.b 0x42000000 0xa5 0x10"
        first = await call(c, "uart_send_command", session_id=sid, command=cmd)
        assert first["status"] == "approval_required" and first["approval_id"], first
        ap = first["approval_id"]
        pending = await call(c, "uart_send_command", session_id=sid, command=cmd, approval_id=ap)
        assert pending["status"] == "approval_required"  # 아직 사람이 승인하지 않음
        assert dev.destructive_events == []
        approve(ap)
        other = await call(c, "uart_send_command", session_id=sid, command="mw.b 0x42000000 0x5a 0x10", approval_id=ap)
        assert other.get("ok") is False  # 다른 명령에는 쓸 수 없다
        done = await call(c, "uart_send_command", session_id=sid, command=cmd, approval_id=ap)
        assert done["ok"] and done["matched"], done
        assert dev.ram.read(0x42000000, 0x10) == b"\xa5" * 16
        assert len(dev.destructive_events) == 1
        again = await call(c, "uart_send_command", session_id=sid, command=cmd, approval_id=ap)
        assert again.get("ok") is False  # 1회용
        # 빈 Enter = 직전 명령(mw) 반복 → 다시 승인 필요, 기기에 도달하지 않음
        bare = await call(c, "uart_send_command", session_id=sid, command="")
        assert bare["status"] == "approval_required" and "repeat" in bare["gate"]["classification"]["rule_id"], bare
        raw_enter = await call(c, "uart_write", session_id=sid, data="\r")
        assert raw_enter["status"] == "approval_required"
        assert len(dev.destructive_events) == 1


async def test_uboot_dump_small_reproduces_flash(devices, auth):
    from uart_mcp.server import server

    dev = devices("hisilicon-like")
    cid = make_case(auth)
    async with Client(server) as c:
        sid = await open_session(c, cid, dev)
        await to_uboot(c, sid, dev)
        await call(c, "uboot_printenv", session_id=sid)
        info = await call(c, "uboot_info", session_id=sid)
        assert info["safe_ram_addr"] == "0x42000000"
        st = await call(c, "uboot_dump_start", case_id=cid, session_id=sid, offset="0x50000", length="128k", chunk_size="16k")
        assert st["ok"] and st["status"] == "started", st
        busy = await call(c, "uart_send_command", session_id=sid, command="version")
        assert "_error" in busy and "busy" in busy["_error"]
        res = await wait_job(c, st["job_id"])
        assert res["status"] == "succeeded", res
        out = res["result"]
        want = dev.flash.read(0x50000, 0x20000)
        assert out["sha256"] == hashlib.sha256(want).hexdigest() and out["size"] == 0x20000
        assert out["verification"]["method"] == "crc32-chunks" and out["chunks"]["count"] == 8
        assert out["verification"]["full_range"]["match"] is True
        case = get_runtime(SERVER).cases.get(cid)
        meta = json.loads((case.dir / out["metadata_path"]).read_text(encoding="utf-8"))
        assert meta["method"] == "uboot-md" and meta["source"]["offset"] == 0x50000 and meta["source"]["partition"] is None
        assert meta["output"]["sha256"] == out["sha256"] and len(meta["chunks"]["checks"]) == 8
        assert all(ch["method"] == "crc32" for ch in meta["chunks"]["checks"])
        assert any(a["kind"] == "flash-dump" and a["path"] == out["path"] for a in case.artifacts())
        assert not (case.dir / "dumps" / f"{Path(out['path']).stem}.state.json").exists()
        # 같은 이름으로 다시 시작하면 완료본을 덮어쓰지 않는다
        again = await call(c, "uboot_dump_start", case_id=cid, session_id=sid, offset="0x50000", length="128k", chunk_size="16k")
        assert again.get("ok") is not True
        # 파티션 하나 (env) — 메타데이터에 파티션 이름
        st2 = await call(c, "uboot_dump_start", case_id=cid, session_id=sid, offset=0x40000, length=0x10000, chunk_size=0x8000,
                         output_name="env-part")
        res2 = await wait_job(c, st2["job_id"])
        assert res2["status"] == "succeeded", res2
        meta2 = json.loads((case.dir / "dumps" / "env-part.json").read_text(encoding="utf-8"))
        assert meta2["source"]["partition"] == "env"
        assert (case.dir / "dumps" / "env-part.bin").read_bytes() == dev.flash.read(0x40000, 0x10000)
    assert dev.destructive_events == []


async def test_uboot_dump_cancel_and_resume(devices, auth):
    from uart_mcp.server import server

    dev = devices("hisilicon-like", time_scale=0.05, pace_output=True)
    cid = make_case(auth)
    async with Client(server) as c:
        sid = await open_session(c, cid, dev)
        await to_uboot(c, sid, dev)
        await call(c, "uboot_info", session_id=sid)
        args = dict(case_id=cid, session_id=sid, offset=0, length=0x20000, chunk_size=0x4000, output_name="boot-resume")
        st = await call(c, "uboot_dump_start", **args)
        assert st["ok"], st
        deadline = time.monotonic() + 60
        while True:
            js = await call(c, "uart_job_status", job_id=st["job_id"])
            if (js.get("meta") or {}).get("overall_done_bytes", 0) >= 0x4000:
                break
            assert js["status"] == "running" and time.monotonic() < deadline, js
            time.sleep(0.05)
        cancel = await call(c, "uart_job_cancel", job_id=st["job_id"])
        assert cancel["ok"]
        res = await wait_job(c, st["job_id"])
        assert res["status"] == "cancelled", res
        case = get_runtime(SERVER).cases.get(cid)
        state = json.loads((case.dir / "dumps" / "boot-resume.state.json").read_text(encoding="utf-8"))
        done = state["completed_chunks"]
        assert 1 <= done < 8
        assert (case.dir / "dumps" / "boot-resume.bin.part").stat().st_size == done * 0x4000
        # 같은 인자로 다시 → 이어 받기
        st2 = await call(c, "uboot_dump_start", **args)
        assert st2["ok"] and st2["resume_from_chunk"] == done, st2
        res2 = await wait_job(c, st2["job_id"])
        assert res2["status"] == "succeeded", res2
        assert res2["result"]["chunks"]["resumed_from"] == done
        assert res2["result"]["sha256"] == hashlib.sha256(dev.flash.read(0, 0x20000)).hexdigest()
        # 취소 뒤에도 세션은 U-Boot 프롬프트로 돌아와 있다
        r = await call(c, "uart_send_command", session_id=sid, command="printenv bootdelay")
        assert r["ok"] and "bootdelay=2" in r["output"]
    assert dev.destructive_events == []


async def test_uboot_dump_retries_corrupted_chunks(devices, auth):
    from uart_mcp.server import server

    dev = devices("hisilicon-like")
    orig_write = dev.write
    seen = {"fmt": 0, "val": 0}

    def noisy_write(data):
        text = data if isinstance(data, str) else bytes(data).decode("latin-1")
        if "42001000: " in text:
            seen["fmt"] += 1
            if seen["fmt"] == 1:  # 파싱할 수 없는 줄 (첫 청크 첫 시도)
                text = re.sub(r"(42001000:) [0-9a-f]{2}", r"\1 zz", text, count=1)
        if "42002000: " in text:
            seen["val"] += 1
            if seen["val"] == 3:  # 형식은 맞지만 값이 틀린 줄 (둘째 청크 첫 시도) → crc32 불일치
                m = re.search(r"42002000: ([0-9a-f]{2})", text)
                flipped = f"{int(m.group(1), 16) ^ 0xFF:02x}"
                text = text[:m.start(1)] + flipped + text[m.end(1):]
        orig_write(text)

    dev.write = noisy_write  # type: ignore[method-assign]
    cid = make_case(auth)
    async with Client(server) as c:
        sid = await open_session(c, cid, dev)
        await to_uboot(c, sid, dev)
        await call(c, "uboot_info", session_id=sid)
        st = await call(c, "uboot_dump_start", case_id=cid, session_id=sid, offset=0x50000, length=0x8000, chunk_size=0x4000,
                        ram_addr="0x42000000", output_name="noisy")
        res = await wait_job(c, st["job_id"])
        assert res["status"] == "succeeded", res
        assert res["result"]["chunks"]["retries"] == 2, (seen, res.get("log_tail"))
        assert res["result"]["sha256"] == hashlib.sha256(dev.flash.read(0x50000, 0x8000)).hexdigest()
        log_tail = " ".join(res.get("log_tail") or [])
        assert "md.b 파싱 문제" in log_tail and "crc32 불일치" in log_tail


@pytest.mark.parametrize("profile,method", [("hisilicon-like", "linux-base64"), ("ingenic-like", "linux-hexdump")])
async def test_shell_identify_and_dump_mtd(devices, auth, profile, method):
    from uart_mcp.server import server

    dev = devices(profile)
    cid = make_case(auth, profile)
    async with Client(server) as c:
        sid = await open_session(c, cid, dev)
        await to_shell(c, sid, dev)
        ident = await call(c, "shell_identify", session_id=sid)
        assert ident["ok"], ident
        assert [m["name"] for m in ident["mtd"]][:2] == ["boot", "env"]
        assert ident["kernel_version"] and ident["arch"] and ident["user"]["uid"] == 0
        assert ident["mtdparts"] and len(ident["partitions"]) == len(ident["mtd"])
        assert any(p["port"] == 80 for p in ident["listening"])
        assert ident["has_base64"] is (profile == "hisilicon-like")
        off, size = ENV_PART[profile]
        st = await call(c, "shell_dump_start", case_id=cid, session_id=sid, path="/dev/mtd1", chunk_size="16k")
        assert st["ok"], st
        res = await wait_job(c, st["job_id"])
        assert res["status"] == "succeeded", res
        out = res["result"]
        assert out["method"] == method and out["verification"]["method"] == "md5-device"
        assert out["sha256"] == hashlib.sha256(dev.flash.read(off, size)).hexdigest()
        case = get_runtime(SERVER).cases.get(cid)
        meta = json.loads((case.dir / out["metadata_path"]).read_text(encoding="utf-8"))
        assert meta["source"]["device_path"] == "/dev/mtd1" and meta["source"]["partition"] == "env"
        assert any(a["kind"] == "partition" for a in case.artifacts())
    assert dev.destructive_events == []


async def test_detect_baud_via_pty_mismatch(devices, auth):
    from uart_mcp.server import server

    # U-Boot 는 env baudrate 로 콘솔 속도를 정하므로 env 도 57600 으로
    dev = devices("hisilicon-like", baud=57600, overrides={"uboot": {"env": {"baudrate": "57600"}}})
    path = dev.start_pty()
    # 사람이 따로 연 터미널로 U-Boot 에 멈춰 둔 상황
    sp = serial.Serial(path, 57600, timeout=0.05)
    con = Console(sp, dev)
    dev.power_on()
    con.interrupt_autoboot()
    sp.close()
    cid = make_case(auth)
    async with Client(server) as c:
        r = await call(c, "uart_detect_baud", case_id=cid, port=path, candidates=[115200, 57600, 38400], listen_seconds=0.6)
        assert r["ok"] and r["best"] == 57600, json.dumps(r, ensure_ascii=False)
        assert r["candidates"][0]["baudrate"] == 57600 and "<INTERRUPT>" in r["candidates"][0]["keyword_hits"]
        r2 = await call(c, "uart_open", case_id=cid, port=path, baudrate=57600)
        assert r2["ok"]
        busy = await call(c, "uart_detect_baud", case_id=cid, port=path, candidates=[115200])
        assert "_error" in busy and "busy" in busy["_error"]
        s = await call(c, "uart_sync", session_id=r2["session_id"])
        assert s["evidence"] == "uboot"


async def test_detect_baud_silent_device_hint(devices, auth):
    from uart_mcp.server import server

    dev = devices("hisilicon-like")
    path = dev.start_pty()  # 전원 꺼짐 → 아무 출력 없음
    cid = make_case(auth)
    async with Client(server) as c:
        r = await call(c, "uart_detect_baud", case_id=cid, port=path, candidates=[115200, 57600], listen_seconds=0.3, probe="none")
        assert r["ok"] and r["best"] is None and "TX/RX" in r["hint"]


async def test_capture_boot_summary_runs_off_the_event_loop(devices, auth, monkeypatch):
    """6차 #10: 부팅 로그 요약(sd_events 포함)은 워커 스레드에서 돈다 — 수 MiB 캡처의 요약이 uart 서버의 이벤트 루프를 막지 않는다."""
    import uart_mcp.server as srv

    real = srv.summarize_boot_text
    on_main: list[bool] = []

    def spy(*a, **kw):
        on_main.append(threading.current_thread() is threading.main_thread())
        return real(*a, **kw)

    monkeypatch.setattr(srv, "summarize_boot_text", spy)
    dev = devices("ingenic-like")
    cid = make_case(auth, "ingenic-like")
    async with Client(srv.server) as c:
        sid = await open_session(c, cid, dev)
        threading.Timer(0.3, dev.power_on).start()
        r = await call(c, "uart_capture_boot", session_id=sid, duration=40)
        assert r["ok"] and r["captured_bytes"] > 1000, r
    assert on_main == [False], on_main


async def test_capture_boot_parses_facts(devices, auth):
    from uart_mcp.server import server

    dev = devices("ingenic-like")
    cid = make_case(auth, "ingenic-like")
    async with Client(server) as c:
        sid = await open_session(c, cid, dev)
        threading.Timer(0.3, dev.power_on).start()
        r = await call(c, "uart_capture_boot", session_id=sid, duration=40)
        assert r["ok"] and r["captured_bytes"] > 1000, r
        assert r["stopped_by"].startswith("prompt:askfirst"), r["stopped_by"]
        assert r["uboot_version"].startswith("U-Boot 2013.07") and r["spl_version"]
        assert r["autoboot_message"].startswith("Hit any key") and r["bootdelay"] == 1
        assert r["kernel_version"].startswith("3.10.14")
        assert "mtdparts=jz_sfc:" in r["mtdparts"] and len(r["partitions"]) == 5
        assert r["console"].startswith("ttyS1")
        assert "kernel" in r["stages"] and r["stages"][-1] == "askfirst"
        # SD 카드 줄이 없는 부팅: sd_events 는 비어 있고 card_detected 는 false(감지 줄을 못 봤다는 뜻), 'MMC: msc: 0' 은 카드 이벤트가 아니다
        assert r["sd_events"] == [] and r["sd_summary"]["card_detected"] is False and "sd_note" not in r
        assert r["excerpt_path"].startswith("uart/")
        case = get_runtime(SERVER).cases.get(cid)
        assert (case.dir / r["excerpt_path"]).exists()
        assert r["context"] == "login"
        # 리눅스까지 부팅된 기기: uboot_interrupt 를 부르고 사람이 전원을 껐다 켬 (이전 프롬프트에 속지 않아야 함)
        t = threading.Timer(0.3, dev.power_cycle)
        t.start()
        ir = await call(c, "uboot_interrupt", session_id=sid, window_seconds=20)
        t.join()
        assert ir["interrupted"] and ir["prompt"] == "isvp_t31# " and ir["bootdelay"] == 1, ir
        assert ir["context"] == "uboot"


async def test_disconnect_handling_tcp(devices, auth):
    from uart_mcp.server import server

    dev = devices("hisilicon-like")
    cid = make_case(auth)
    async with Client(server) as c:
        sid = await open_session(c, cid, dev, tcp=True)
        await to_uboot(c, sid, dev)
        dev.stop()  # USB 분리/네트워크 단절과 같다
        deadline = time.monotonic() + 5
        while True:
            sess = (await call(c, "uart_sessions"))["sessions"][0]
            if sess["state"] == "disconnected":
                break
            assert time.monotonic() < deadline, sess
            time.sleep(0.05)
        r = await call(c, "uart_send_command", session_id=sid, command="version")
        assert "_error" in r and "disconnected" in r["_error"]
        rd = await call(c, "uart_read", session_id=sid, since_cursor=0)
        assert rd["ok"] and rd["state"] == "disconnected" and "hisilicon # " in rd["text"]
        closed = await call(c, "uart_close", session_id=sid)
        assert closed["ok"]
        case = get_runtime(SERVER).cases.get(cid)
        events = (case.dir / "uart" / f"{sid}.events.jsonl").read_text(encoding="utf-8")
        assert '"disconnected"' in events
        audit = (case.dir / "audit.jsonl").read_text(encoding="utf-8")
        assert "uart_disconnected" in audit


async def test_signals_break_and_context_tools(devices, auth):
    from uart_mcp.server import server

    dev = devices("hisilicon-like")
    cid = make_case(auth)
    async with Client(server) as c:
        sid = await open_session(c, cid, dev)
        await to_uboot(c, sid, dev)
        sig = await call(c, "uart_set_signals", session_id=sid, dtr=True)
        assert sig["ok"] is False and sig["status"] == "unsupported"  # PTY 는 모뎀 신호 없음
        sess = (await call(c, "uart_sessions"))["sessions"][0]
        assert sess["state"] == "open"  # 미지원은 연결 끊김이 아니다
        br = await call(c, "uart_send_break", session_id=sid, duration=0.05)
        assert br["ok"] and br["sysrq_window_seconds"] == 5.0
        bad = await call(c, "uart_set_context", session_id=sid, context="weird")
        assert "_error" in bad
        r = await call(c, "uart_set_context", session_id=sid, context="uboot", prompt="hisilicon # ")
        assert r["ok"] and r["context"] == "uboot"
        r = await call(c, "uart_set_context", session_id=sid, context="auto")
        assert r["manual_context"] is None


async def test_uart_open_dtr_rts_policy(workspace, devices, auth):
    from uart_mcp.server import server

    workspace["set_safety"](modify_policy="deny")
    dev = devices("hisilicon-like")
    cid = make_case(auth)
    path = dev.start_pty()
    async with Client(server) as c:
        r = await call(c, "uart_open", case_id=cid, port=path, dtr=True)
        assert r["status"] == "denied" and r["gate"]["classification"]["rule_id"] == "uart.open.signals"
        r = await call(c, "uart_open", case_id=cid, port=path)
        assert r["ok"]
        r2 = await call(c, "uart_open", case_id=cid, port=path)
        assert "_error" in r2 and "busy" in r2["_error"]


async def test_uart_refuses_dangerous_pyserial_urls_and_non_devices(workspace, devices, auth, tmp_path):
    """spy://(호스트 파일 쓰기)·hwgrep://(임의 포트 열기)와 일반 파일·상대 경로는 게이트 전에 validation_failed.

    INTERACT 변형(dtr=rts=False, probe='none')은 어떤 정책으로도 막히지 않으므로 포트 검증이 유일한 방어다.
    spy 는 do_not_open 이어도 포트 이름을 정하는 순간 파일을 쓰기로 연다 — 파일이 생기지 않아야 한다.
    """
    from uart_mcp.server import server

    spy_log = tmp_path / "spy.log"
    victim = tmp_path / "victim.txt"
    victim.write_text("keep me")
    cid = make_case(auth)
    async with Client(server) as c:
        for port in (f"spy://loop://?file={spy_log}", "hwgrep://.*", "HWGREP://ttyUSB", "alt://loop://?class=x",
                     str(victim), "ttyUSB0", "COM3"):
            r = await call(c, "uart_open", case_id=cid, port=port, baudrate=115200)
            assert "[validation_failed]" in r.get("_error", ""), (port, r)
            r = await call(c, "uart_detect_baud", case_id=cid, port=port, candidates=[115200], listen_seconds=0.2, probe="none")
            assert "[validation_failed]" in r.get("_error", ""), (port, r)
        assert not spy_log.exists()
        assert victim.read_text() == "keep me"
        sessions = await call(c, "uart_sessions")
        assert not sessions.get("sessions"), sessions
        # 허용 형식은 그대로: PTY 장치 경로와 socket://
        dev = devices()
        sid = await open_session(c, cid, dev)
        await call(c, "uart_close", session_id=sid)
        sid = await open_session(c, cid, dev, tcp=True)
        await call(c, "uart_close", session_id=sid)


def test_validate_port_unit(tmp_path):
    import os

    from pweh.errors import ValidationFailed
    from uart_mcp.session import open_serial, PortSettings, validate_port

    assert validate_port(" loop:// ") == "loop://"
    assert validate_port("socket://127.0.0.1:7777") == "socket://127.0.0.1:7777"
    assert validate_port("RFC2217://127.0.0.1:4000") == "rfc2217://127.0.0.1:4000"  # 스킴·호스트는 소문자 정규형
    assert validate_port("socket://[::1]:7777") == "socket://[::1]:7777"
    assert validate_port("/dev/ttyUSB-does-not-exist-0") == "/dev/ttyUSB-does-not-exist-0"  # 없는 장치는 열 때 DeviceError
    master, slave = os.openpty()
    try:
        assert validate_port(os.ttyname(slave)) == os.ttyname(slave)
    finally:
        os.close(master)
        os.close(slave)
    for bad in ("", "  ", "spy://x", "hwgrep://.*", "cp2110://0001:0002", "/dev/tty\x00USB0", str(tmp_path), "relative/path",
                # 원격 URL 은 루프백 호스트·포트가 있는 정규형만 (D4 — 수정 전에는 RFC2217://10.0.0.2:4000 이 유효했다)
                "RFC2217://10.0.0.2:4000", "socket://192.0.2.10:7777", "socket://0.0.0.0:7777", "socket://127.1:7777",
                "socket://user@127.0.0.1:7777", "socket://127.0.0.1", "rfc2217://127.0.0.1:2217?ign_set_control",
                # COM 이름 문법: COM1–COM4096, 앞자리 0 없음
                "COM0", "COM01", "COM4097", "COM99999"):
        with pytest.raises(ValidationFailed):
            validate_port(bad)
    # open_serial 도 직접 막는다 (작업 경로 방어)
    with pytest.raises(ValidationFailed):
        open_serial(PortSettings(port=f"spy://loop://?file={tmp_path / 's.log'}"))
    assert not (tmp_path / "s.log").exists()
    with pytest.raises(ValidationFailed):
        open_serial(PortSettings(port="socket://192.0.2.10:7777"))


def test_validate_port_win_com_bound(monkeypatch):
    """COM 이름은 COM1–COM4096(앞자리 0 없음). 범위 밖은 어느 플랫폼에서나 범위 오류, 범위 안은 Windows 가 아니면 거부."""
    import sys

    from pweh.errors import ValidationFailed
    from uart_mcp.session import validate_port

    for bad in ("COM0", "COM01", "COM007", "COM4097", "COM99999", "com10000"):
        with pytest.raises(ValidationFailed, match="COM1–COM4096"):
            validate_port(bad)
    for ok_name in ("COM1", "com12", "COM4096"):
        assert validate_port(ok_name) == ok_name.upper()  # 실제 환경 허용은 resolve 단계에서 확인한다.
    with monkeypatch.context() as m:  # 가짜 win32 는 이 블록 안에서만 (fixture 정리는 실제 플랫폼에서)
        m.setattr(sys, "platform", "win32")
        assert validate_port("com12") == "COM12"
        assert validate_port("COM1") == "COM1"
        assert validate_port("COM4096") == "COM4096"
        for bad in ("COM0", "COM01", "COM4097"):
            with pytest.raises(ValidationFailed, match="COM1–COM4096"):
                validate_port(bad)


async def test_uart_refuses_lan_remote_urls_before_gate(workspace, auth, monkeypatch):
    """socket://·rfc2217:// 는 루프백 호스트만 (D4). LAN·와일드카드·별칭·사용자 정보·질의 옵션 URL 은 게이트 전에
    validation_failed 이고 접속을 시도하지 않으며 승인 요청도 만들지 않는다."""
    import socket

    from uart_mcp.server import server

    def boom(*a, **kw):
        raise AssertionError("LAN URL 로 접속을 시도함")

    monkeypatch.setattr(socket, "create_connection", boom)
    workspace["set_safety"](modify_policy="approve", approval_methods=["cli"])  # 검증을 지나쳤다면 승인 요청이 생겼을 것
    cid = make_case(auth)
    async with Client(server) as c:
        for port in ("socket://192.0.2.10:7777", "rfc2217://10.0.0.2:4000", "socket://[2001:db8::1]:7777", "socket://0.0.0.0:7777",
                     "socket://2130706433:7777", "socket://127.0.0.1@192.0.2.1:7777", "rfc2217://127.0.0.1:2217?timeout=1"):
            r = await call(c, "uart_open", case_id=cid, port=port, baudrate=115200, dtr=True)
            assert "[validation_failed]" in r.get("_error", ""), (port, r)
            r = await call(c, "uart_detect_baud", case_id=cid, port=port, candidates=[115200], listen_seconds=0.2, probe="ctrl-c")
            assert "[validation_failed]" in r.get("_error", ""), (port, r)
        r = await call(c, "uart_open", case_id=cid, port="socket://192.0.2.10:7777")
        assert "루프백" in r["_error"] and "LAN" in r["_error"], r
        assert not (await call(c, "uart_sessions")).get("sessions")
    assert get_runtime(SERVER).approvals.list("pending") == []


async def test_uart_same_loopback_endpoint_is_one_port(workspace, devices, auth, monkeypatch):
    """회귀(리뷰 F1): 같은 루프백 포트의 다른 표기(localhost·127.x·[::1]·rfc2217·대문자)는 한 포트다. 첫 세션이 열린 동안
    두 번째 열기·보드레이트 탐지는 연결을 시도하기 전에 busy 이고, 세션 두 개로 'sa' + 'veenv\\r' 를 나눠 보내 saveenv 를
    조립하는 우회(수정 전: 기기에서 saveenv 실행)가 통하지 않는다."""
    import socket

    from pweh import ports
    from uart_mcp.server import server

    monkeypatch.setattr(ports, "_getaddrinfo",
                        lambda h, p: [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", p or 0))])
    assert get_runtime(SERVER).config.safety.destructive_policy == "deny"
    dev = devices("hisilicon-like")
    cid = make_case(auth)
    async with Client(server) as c:
        sid = await open_session(c, cid, dev, tcp=True)  # socket://127.0.0.1:P
        port = (await call(c, "uart_sessions"))["sessions"][0]["port"].rsplit(":", 1)[1]
        await to_uboot(c, sid, dev)
        attempts: list = []
        real_connect = socket.create_connection

        def spy(addr, *a, **kw):
            attempts.append(addr)
            return real_connect(addr, *a, **kw)

        monkeypatch.setattr(socket, "create_connection", spy)
        for alias in (f"socket://localhost:{port}", f"SOCKET://127.0.0.1:{port}", f"socket://127.0.0.2:{port}",
                      f"socket://[::1]:{port}", f"rfc2217://127.0.0.1:{port}", f"rfc2217://LocalHost:{port}"):
            r = await call(c, "uart_open", case_id=cid, port=alias)
            assert "[busy]" in r.get("_error", ""), (alias, r)
            assert "한 포트로" in r["_error"], r  # 힌트: 같은 루프백 포트의 다른 표기는 한 포트
            r = await call(c, "uart_detect_baud", case_id=cid, port=alias, candidates=[115200], listen_seconds=0.2, probe="none")
            assert "[busy]" in r.get("_error", ""), (alias, r)
        assert attempts == []  # 두 번째 연결은 시도조차 하지 않았다
        assert [s["session_id"] for s in (await call(c, "uart_sessions"))["sessions"]] == [sid]
        # 남은 경로는 한 세션 안에서 쪼개 보내는 것뿐이고, 그 세션의 줄 조립기가 saveenv 로 보고 거부한다
        w1 = await call(c, "uart_write", session_id=sid, data="sa")
        assert w1.get("ok") and w1.get("pending_input") == "sa", w1
        w2 = await call(c, "uart_write", session_id=sid, data="veenv\r")
        assert w2.get("status") == "denied", w2
        await call(c, "uart_sync", session_id=sid)
        time.sleep(0.3)
        await call(c, "uart_close", session_id=sid)
        # 닫은 뒤에는 별칭으로 다시 열 수 있고, localhost 는 확인한 루프백 주소로 바뀐다(연결 때 다시 풀지 않음)
        r = await call(c, "uart_open", case_id=cid, port=f"socket://localhost:{port}")
        assert r.get("ok") and r["port"] == f"socket://127.0.0.1:{port}", r
        await call(c, "uart_close", session_id=r["session_id"])
    assert dev.destructive_events == []


async def test_uart_open_normalizes_loopback_url(workspace, devices, auth):
    """대문자 스킴도 받아 정규형(socket://…)으로 돌려준다 — socket:// 전용 처리(보드레이트 note, 큰 읽기)가 적용된다."""
    from uart_mcp.server import server

    dev = devices("hisilicon-like")
    host, port = dev.start_tcp()
    cid = make_case(auth)
    async with Client(server) as c:
        r = await call(c, "uart_open", case_id=cid, port=f"SOCKET://{host}:{port}")
        assert r.get("ok"), r
        assert r["port"] == f"socket://{host}:{port}" and "note" in r, r
        await call(c, "uart_close", session_id=r["session_id"])


async def test_uart_mcp_stdio(workspace, devices, auth):
    dev = devices("hisilicon-like")
    host, port = dev.start_tcp()
    cid = make_case(auth)
    params = stdio_params("uart_mcp", env={"PWEH_CONFIG": str(workspace["config"])})
    async with Client(params, read_timeout_seconds=60) as c:
        tools = {t.name for t in (await c.list_tools()).tools}
        assert CONTRACT_TOOLS <= tools
        r = await call(c, "uart_open", case_id=cid, port=f"socket://{host}:{port}")
        assert r["ok"], r
        sid = r["session_id"]
        t = threading.Timer(0.5, dev.power_on)
        t.start()
        r = await call(c, "uboot_interrupt", session_id=sid, window_seconds=20)
        t.join()
        assert r["interrupted"], r
        r = await call(c, "uart_send_command", session_id=sid, command="printenv bootcmd")
        assert r["ok"] and r["output"].startswith("bootcmd=sf probe 0"), r
        r = await call(c, "uart_send_command", session_id=sid, command="saveenv")
        assert r["status"] == "denied"
        r = await call(c, "uart_close", session_id=sid)
        assert r["ok"]
    assert dev.destructive_events == []
