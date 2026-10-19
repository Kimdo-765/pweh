"""실제 OpenOCD (xPack 0.12.0-7, dummy 어댑터 + testee 타깃) 통합 테스트.

하드웨어 없이 동작하는 설정은 ~/pweh-tools/INSTALL_REPORT.md §2 에서 검증된 명령행을 그대로 쓴다.
주의: testee 타깃에서 resume / step / bp 는 OpenOCD 를 SIGSEGV 로 죽이고, reset 이후의 poll 도 죽인다 —
이 테스트는 그런 명령을 절대 보내지 않는다 (서버 도구도 내부적으로 poll 을 쓰지 않는다).
"""

from __future__ import annotations

import os
import socket
import subprocess
import time
from pathlib import Path

from pweh.toolsdir import tools_dir

import pytest
from mcp import Client

from mcp_helpers import call

pytestmark = [pytest.mark.anyio, pytest.mark.external]

TOOLS = tools_dir()
XPACK_SCRIPTS = TOOLS / "openocd" / "xpack-openocd-0.12.0-7" / "openocd" / "scripts"


@pytest.fixture
def anyio_backend():
    return "asyncio"


def _openocd_bin() -> str | None:
    for cand in (os.environ.get("PWEH_OPENOCD"), str(TOOLS / "bin" / "openocd")):
        if cand and Path(cand).is_file() and os.access(cand, os.X_OK):
            return cand
    return None


def _dummy_launcher() -> str | None:
    for cand in (os.environ.get("PWEH_OPENOCD_DUMMY"), str(TOOLS / "bin" / "openocd-dummy")):
        if cand and Path(cand).is_file() and os.access(cand, os.X_OK):
            return cand
    return None


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture(autouse=True)
def _cleanup_sessions():
    yield
    from openocd_mcp.session import REGISTRY

    REGISTRY.shutdown_all()


@pytest.fixture
def real_openocd(monkeypatch):
    from pweh.runtime import reset_runtimes

    binary = _openocd_bin()
    if not binary:
        pytest.skip("OpenOCD 가 없습니다 (PWEH_OPENOCD 또는 ~/pweh-tools/bin/openocd)")
    monkeypatch.setenv("PWEH_OPENOCD", binary)
    if XPACK_SCRIPTS.is_dir():
        monkeypatch.setenv("PWEH_OPENOCD_SCRIPTS", str(XPACK_SCRIPTS))
    reset_runtimes()
    return binary


def _new_case(auth) -> str:
    from pweh.runtime import get_runtime

    return get_runtime("openocd-mcp").cases.create(title="real openocd dummy", authorization=auth).id


async def test_real_openocd_dummy_lifecycle(workspace, auth, real_openocd):
    from openocd_mcp.server import server
    from pweh.runtime import get_runtime

    cid = _new_case(auth)
    case = get_runtime("openocd-mcp").cases.get(cid)
    # 회귀 방지: OpenOCD 는 상대 cfg 를 cwd 에서 먼저 찾는다. 케이스 jtag/ 에 손으로 쓴 같은 이름 파일이
    # 표준 cfg 를 가로채면 안 된다 (서버는 검증한 절대경로 + 실행 전용 빈 cwd 를 쓴다).
    shadow = case.dir / "jtag" / "interface" / "dummy.cfg"
    shadow.parent.mkdir(parents=True)
    shadow.write_text("echo SHADOWED-CFG-LOADED\nadapter driver dummy\n")
    async with Client(server) as c:
        r = await call(
            c, "openocd_start", case_id=cid, interface_cfg="interface/dummy.cfg", transport="jtag", adapter_speed_khz=1000,
            extra_commands=[
                "jtag newtap dummy cpu -irlen 4 -ircapture 0x1 -irmask 0x1 -ignore-bypass",
                "target create dummy.cpu testee -chain-position dummy.cpu",
            ],
            tcl_port=0, ready_timeout=30,
        )
        assert r["ok"], r
        assert r["health"] == "ok" and r["tcl_port"] > 0
        # semihosting 무력화 스크립트가 실행되었다: testee 에는 semihosting 이 없고(조용히 확인), 감쌀 핸들러도 없다
        assert r["semihosting"]["verified"] and r["semihosting"]["targets"] == {"dummy.cpu": "unsupported"}, r["semihosting"]
        assert r["semihosting"]["source"] == "rpc" and r["semihosting"]["phases"] == ["pre-init", "post-init", "verify"]
        assert r["semihosting_neutralized"] == [] and not any("PWEH-SEMIHOSTING" in w for w in r["warnings"])
        assert "Open On-Chip Debugger" in r["version"]
        assert r["startup"]["listening"].get("tcl") == r["tcl_port"]
        assert "telnet" not in r["startup"]["listening"] and "gdb" not in r["startup"]["listening"]
        assert any(t["tap_name"] == "dummy.cpu" for t in r["startup"]["taps"])
        assert {"target": "dummy.cpu", "result": "succeed"} in r["startup"]["examination"]
        argv = r["argv"]
        if XPACK_SCRIPTS.is_dir():
            assert "-s" in argv
        log_path = case.dir / r["log_path"]
        log_text = log_path.read_text(errors="replace")
        assert "Listening on port" in log_text
        assert "SHADOWED-CFG-LOADED" not in log_text
        f_args = [argv[i + 1] for i, a in enumerate(argv) if a == "-f"]
        assert f_args and all(os.path.isabs(x) for x in f_args), f_args

        sc = await call(c, "openocd_scan_chain", case_id=cid)
        assert sc["ok"] and sc["count"] == 1
        tap = sc["taps"][0]
        assert tap["tap_name"] == "dummy.cpu" and tap["enabled"] and tap["idcode"] == "0x00000000" and tap["irlen"] == 4
        assert tap["ircap"] == "0x01" and tap["irmask"] == "0x01" and tap["decoded"]["valid"] is False

        tg = await call(c, "openocd_targets", case_id=cid)
        assert tg["ok"] and tg["current"] == "dummy.cpu"
        t = tg["targets"][0]
        assert t["type"] == "testee" and t["endian"] == "little" and t["tap_name"] == "dummy.cpu"

        raw = await call(c, "openocd_command", case_id=cid, command="adapter name")
        assert raw["ok"] and raw["output"] == "dummy"
        nope = await call(c, "openocd_command", case_id=cid, command="this_command_does_not_exist")
        assert nope["ok"] is False and "invalid command name" in nope["error"]
        denied = await call(c, "openocd_command", case_id=cid, command="mww 0x0 0")
        assert denied["status"] == "denied"

        h = await call(c, "openocd_halt", case_id=cid)
        assert h["ok"] and h["state"] == "halted", h
        assert h["semihosting_check"]["status"] == "ok" and h["semihosting_check"]["targets"] == {"dummy.cpu": "unsupported"}, h

        # testee 는 메모리 접근을 지원하지 않는다 → 깔끔한 오류 (OpenOCD 는 살아 있어야 함)
        mem = await call(c, "openocd_read_memory", case_id=cid, address=0, count=1)
        assert mem["ok"] is False and "doesn't support read_memory" in mem["error"]
        assert any(d["code"] == "memory_unsupported" for d in mem["diagnosis"])
        dj = await call(c, "openocd_dump_memory_start", case_id=cid, address=0, length=4096, chunk_size=4096, retries=0)
        assert dj["ok"], dj
        deadline = time.monotonic() + 30
        while True:
            st = await call(c, "openocd_job_status", job_id=dj["job_id"], wait_seconds=2)
            if st["status"] not in ("queued", "running", "cancelling"):
                break
            assert time.monotonic() < deadline
        assert st["status"] == "failed" and "read_memory" in st["error"]["message"]

        regs = await call(c, "openocd_read_registers", case_id=cid)
        assert regs["ok"] and regs["count"] == 0  # testee 는 레지스터 캐시가 없다

        rs = await call(c, "openocd_reset", case_id=cid, mode="halt")
        assert rs["ok"], rs
        assert rs["semihosting_check"]["status"] == "ok", rs  # reset 뒤 재확인 (poll 을 쓰지 않아 testee 도 살아 있다)
        assert "JTAG scan chain interrogation failed" in rs["messages"]  # dummy 어댑터의 재검사 로그 (INSTALL_REPORT 실측)
        assert rs["targets"][0]["name"] == "dummy.cpu"

        st = await call(c, "openocd_status", case_id=cid)
        assert st["alive"] and st["process"]["running"] and st["targets"][0]["name"] == "dummy.cpu"
        assert st["semihosting"]["last_check"]["trigger"] == "openocd_reset" and st["semihosting_live"]["status"] == "reported"

        stop = await call(c, "openocd_stop", case_id=cid)
        assert stop["ok"] and stop["method"] == "shutdown" and stop["process"]["exit_code"] == 0, stop
        assert "shutdown command invoked" in "\n".join(stop["log_tail"])


async def test_real_openocd_attach_to_dummy_launcher(workspace, auth, real_openocd, tmp_path):
    from openocd_mcp.server import server

    launcher = _dummy_launcher()
    if not launcher:
        pytest.skip("PWEH_OPENOCD_DUMMY 런처가 없습니다")
    tcl, tel = _free_port(), _free_port()
    env = dict(os.environ, PWEH_OPENOCD_TCL_PORT=str(tcl), PWEH_OPENOCD_TELNET_PORT=str(tel))
    log = open(tmp_path / "launcher.log", "wb")
    proc = subprocess.Popen([launcher], env=env, stdout=log, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL, start_new_session=True)
    try:
        deadline = time.monotonic() + 15
        while True:
            try:
                socket.create_connection(("127.0.0.1", tcl), timeout=0.2).close()
                break
            except OSError:
                assert proc.poll() is None and time.monotonic() < deadline, (tmp_path / "launcher.log").read_text(errors="replace")
                time.sleep(0.1)
        cid = _new_case(auth)
        async with Client(server) as c:
            a = await call(c, "openocd_attach", case_id=cid, tcl_port=tcl)
            assert a["ok"] and a["mode"] == "attached" and a["targets"][0]["name"] == "dummy.cpu", a
            sc = await call(c, "openocd_scan_chain", case_id=cid)
            assert sc["taps"][0]["tap_name"] == "dummy.cpu"
            stop = await call(c, "openocd_stop", case_id=cid, shutdown_attached=True)
            assert stop["ok"] and stop["method"] == "shutdown-attached", stop
        proc.wait(timeout=10)
        assert proc.returncode == 0
    finally:
        if proc.poll() is None:
            proc.kill()
            proc.wait(timeout=5)
        log.close()
