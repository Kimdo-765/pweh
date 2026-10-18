"""점 없는 타깃 이름(mem_ap, cpu0) 회귀 테스트.

서버가 직접 만드는 ``<타깃> read_memory …`` / ``<타깃> mdw …`` 명령(openocd_read_memory, 덤프 작업, write_memory 확인 읽기)은
코어가 점(.) 있는 첫 단어만 타깃 접두로 보기 때문에 점 없는 타깃에서 '알 수 없는 명령'(MODIFY)이 되어 덤프 작업이 시작부터
거부되었다. 이제 실제 OpenOCD ``target names`` 목록에서 확인한 이름일 때만 접두를 떼고 분류한다.
에이전트가 쓴 원시 명령(openocd_command)의 분류는 느슨해지지 않는다.

실측 (xPack OpenOCD 0.12.0-7, dummy 어댑터 + testee 타깃):
- ``target names`` 는 이름마다 한 줄(``dummy.cpu\\ncpu0``), 0.12.0 이하 릴리스는 Jim 리스트(공백 구분)
- 점 없는 타깃 ``cpu0 read_memory 0 32 1`` 은 타깃 명령으로 디스패치된다
- ``target create mww …`` / ``target create reset …`` 은 허용되고 전역 명령을 가린다 (``time`` 같은 Jim 내장 명령만 거부)
  → 명령 이름과 겹치는 타깃은 버전에 따라 뜻이 달라질 수 있어 접두를 떼지 않고, 서버는 그 이름을 거부한다.
"""

from __future__ import annotations

import os
import time
from pathlib import Path

import pytest
from mcp import Client

from openocd_mcp import guard, parsers
from pweh.errors import SafetyDenied
from pweh.safety import Risk

from .fake_openocd import FakeOpenOCD, Target
from mcp_helpers import call

READ = "mem_ap read_memory 0x80000000 32 4"
VERIFIED_RULE = "openocd.target-verified:"


# ---------------------------------------------------------------------------
# 분류기 단위
# ---------------------------------------------------------------------------


def test_verified_target_read_is_classified_without_prefix():
    c = guard.classify_target_read(READ, trusted_targets={"mem_ap"})
    assert c.risk == Risk.INTERACT and c.rule_id.startswith(VERIFIED_RULE), c
    for cmd in ("cpu0 mdw 0x80000000 4", "cpu0 mdb phys 0x0 16", "cpu0 read_memory 0x0 8 4096 phys",
                "cpu0 read_memory 0xc0000000 64 2", "cam.ahb read_memory 0x0 32 1"):
        name = cmd.split()[0]
        c = guard.classify_target_read(cmd, trusted_targets={name})
        assert c.risk == Risk.INTERACT and c.rule_id.startswith(VERIFIED_RULE), (cmd, c)


def test_unverified_target_and_agent_text_keep_current_classification():
    assert guard.classify_target_read(READ, trusted_targets=set()).risk == Risk.MODIFY
    assert guard.classify_target_read(READ, trusted_targets={"cpu0"}).risk == Risk.MODIFY  # 다른 이름만 확인됨
    assert guard.classify_command(READ).risk == Risk.MODIFY  # openocd_command 경로: 그대로 '알 수 없는 명령'


@pytest.mark.parametrize(
    "cmd",
    [
        "mem_ap read_memory 0x80000000 32 4; mww 0 0",
        "mem_ap read_memory 0x80000000 32 4\nmww 0 0",
        "mem_ap read_memory [mww 0 0] 32 1",
        "mem_ap mww 0x80000000 0x1",
        "mem_ap write_memory 0x80000000 32 {0x1}",
    ],
)
def test_only_exact_server_read_forms_are_normalised(cmd):
    c = guard.classify_target_read(cmd, trusted_targets={"mem_ap"})
    assert c.risk == Risk.DESTRUCTIVE and not c.rule_id.startswith(VERIFIED_RULE), (cmd, c)


COLLIDING = ["mww", "reset", "halt", "flash", "shutdown", "load_image", "exec", "popen", "time", "stdout",
             "targets", "reg", "pld", "ocd_mww", "efuse_ap", "then", "123", "os.fork", "cam.dap"]


@pytest.mark.parametrize("name", COLLIDING)
def test_target_name_colliding_with_a_command_is_not_normalised(name):
    assert guard.target_name_conflict(name), name
    cmd = f"{name} read_memory 0x80000000 32 4"
    c = guard.classify_target_read(cmd, trusted_targets={name})
    raw = guard.classify_command(cmd)
    assert not c.rule_id.startswith(VERIFIED_RULE), (name, c)
    assert (c.risk, c.rule_id) == (raw.risk, raw.rule_id), (name, c, raw)


@pytest.mark.parametrize("name", ["mem_ap", "cpu0", "cam.ahb", "hi3516ev300.ahb", "core-1", "AP_0"])
def test_ordinary_target_names_do_not_conflict(name):
    assert guard.target_name_conflict(name) is None


def test_job_check_normalises_only_verified_targets(tmp_path):
    jtag = tmp_path / "jtag"
    jtag.mkdir()
    cmds = ["mem_ap read_memory 0x80000000 32 16384", "mem_ap read_memory 0x80000000 8 65536", "mem_ap mdw 0x80000000 4096",
            "mem_ap mdb 0x80000000 1"]
    out = guard.ensure_job_commands_safe(cmds, allowed_dirs=[jtag], trusted_targets={"mem_ap"})
    assert all(c.risk == Risk.INTERACT for c in out), out
    with pytest.raises(SafetyDenied):  # 확인되지 않은 이름: 기존대로 작업 거부
        guard.ensure_job_commands_safe(cmds[:1], allowed_dirs=[jtag])
    with pytest.raises(SafetyDenied):  # 명령 이름과 겹치는 이름은 확인돼도 접두를 떼지 않는다
        guard.ensure_job_commands_safe(["mww read_memory 0x80000000 32 4"], allowed_dirs=[jtag], trusted_targets={"mww"})
    with pytest.raises(SafetyDenied):  # 뒤에 붙인 문장은 따로 분류
        guard.ensure_job_commands_safe(["mem_ap read_memory 0x80000000 32 4; mww 0 0"], allowed_dirs=[jtag], trusted_targets={"mem_ap"})


@pytest.mark.parametrize(
    "cmd",
    ["mem_ap mww 0x80000000 0x1", "cpu0 mwb 0 1", "cpu0 mwh 0x0 1 4", "cpu0 load_image x.bin 0", "mem_ap array2mem v 32 0 1",
     "cpu0 program x.bin", "cpu0 dump_image /tmp/x 0 4"],
)
def test_agent_text_dotless_target_with_dangerous_subcommand_is_destructive(cmd):
    """에이전트가 쓴 'cpu0 mww …' 는 점 없는 타깃의 메모리 쓰기다 — 예전에는 '알 수 없는 명령'(MODIFY, 기본 허용)이었다."""
    c = guard.classify_command(cmd)
    assert c.risk == Risk.DESTRUCTIVE, (cmd, c)


@pytest.mark.parametrize(
    "cmd,risk",
    [
        ("mem_ap read_memory 0x80000000 32 4", Risk.MODIFY),  # 에이전트 경로는 느슨해지지 않음 (그대로)
        ("cpu0 arp_examine", Risk.MODIFY),
        ("ftdi layout_init 0x0008 0x000b", Risk.MODIFY),
        ("cortex_a dbginit", Risk.MODIFY),
        ("telnet port disabled", Risk.MODIFY),
    ],
)
def test_agent_text_unknown_commands_keep_their_risk(cmd, risk):
    assert guard.classify_command(cmd).risk == risk, cmd


@pytest.mark.parametrize(
    "text,names",
    [
        ("cam.cpu\nmem_ap", ["cam.cpu", "mem_ap"]),  # xPack/최신: 이름마다 한 줄 (실측)
        ("cam.cpu mem_ap", ["cam.cpu", "mem_ap"]),  # 0.12.0 이하 릴리스: Jim 리스트
        ("mem_ap", ["mem_ap"]),
        ("", []),
        ("{foo bar} mem_ap", ["foo bar", "mem_ap"]),
        ("foo bar\nmem_ap", ["foo bar", "mem_ap"]),  # 줄 단위 형식: 공백이 든 이름은 통째로 (foo 는 이름이 아님)
        ("a\r\nb\n", ["a", "b"]),
    ],
)
def test_parse_target_names(text, names):
    assert parsers.parse_target_names(text) == names


# ---------------------------------------------------------------------------
# MCP 수준 (가짜 OpenOCD)
# ---------------------------------------------------------------------------


@pytest.fixture
def anyio_backend():
    return "asyncio"


@pytest.fixture(autouse=True)
def _cleanup_sessions():
    yield
    from openocd_mcp.session import REGISTRY

    REGISTRY.shutdown_all()


@pytest.fixture
def fake():
    srv = FakeOpenOCD()
    srv.start()
    yield srv
    srv.stop()


def _new_case(auth, title="dotless target") -> str:
    from pweh.runtime import get_runtime

    return get_runtime("openocd-mcp").cases.create(title=title, authorization=auth).id


def _case(case_id: str):
    from pweh.runtime import get_runtime

    return get_runtime("openocd-mcp").cases.get(case_id)


def _add_target(fake: FakeOpenOCD, name: str) -> Target:
    """CPU 를 멈추지 않고 읽을 수 있는 MEM-AP 류 타깃 (가짜 장치는 cam.cpu 와 같은 메모리를 보여 준다)."""
    t = Target(name, "mem_ap", "cam.cpu", require_halt=False)
    fake.dev.targets.append(t)
    return t


def _names_queries(fake: FakeOpenOCD) -> int:
    return sum(1 for x in fake.dev.executed if x[:2] == ["target", "names"])


async def _wait_job(c, job_id: str, timeout: float = 30.0) -> dict:
    deadline = time.monotonic() + timeout
    while True:
        st = await call(c, "openocd_job_status", job_id=job_id, wait_seconds=1)
        assert "_error" not in st, st
        if st["status"] not in ("queued", "running", "cancelling"):
            return st
        assert time.monotonic() < deadline, st


@pytest.mark.anyio
async def test_dotless_target_read_memory_and_dump(workspace, auth, fake):
    from openocd_mcp.server import server

    # MODIFY 로 분류되면 거부되도록 해서, 서버가 만든 읽기가 INTERACT 로 분류됨을 확인한다
    workspace["set_safety"](modify_policy="deny")
    _add_target(fake, "mem_ap")
    region = fake.dev.regions[0]
    cid = _new_case(auth)
    async with Client(server) as c:
        assert (await call(c, "openocd_attach", case_id=cid, tcl_port=fake.port))["ok"]
        # cam.cpu 는 실행 중(halt 필요)이지만 mem_ap 타깃은 halt 없이 읽힌다
        mem = await call(c, "openocd_read_memory", case_id=cid, address="0x80000000", count=8, target="mem_ap")
        assert mem.get("ok"), mem
        assert mem["bytes_hex"] == bytes(region.data[:32]).hex()
        assert ["mem_ap", "read_memory", "0x80000000", "32", "8"] in fake.dev.executed
        queried = _names_queries(fake)
        assert queried == 1
        mb = await call(c, "openocd_read_memory", case_id=cid, address=0x80000001, count=3, width=8, target="mem_ap")
        assert mb.get("ok") and mb["bytes_hex"] == bytes(region.data[1:4]).hex(), mb
        assert _names_queries(fake) == queried  # 같은 세션(프로세스)에서는 목록을 캐시

        # 덤프 작업 (read_memory 방식: 청크마다 job 안에서 '<타깃> read_memory' 를 다시 검사, verify=재읽기 비교)
        r = await call(c, "openocd_dump_memory_start", case_id=cid, address=0x80000000, length=0x3000, chunk_size=0x1000,
                       target="mem_ap", method="read_memory", verify=True, output_name="ap-read")
        assert r.get("ok"), r
        assert r["classification"]["risk"] == "interact"
        st = await _wait_job(c, r["job_id"])
        assert st["status"] == "succeeded", st
        assert st["result"]["transfer"] == "read_memory"
        assert (_case(cid).dir / st["result"]["path"]).read_bytes() == bytes(region.data[:0x3000])

        # auto(dump_image) 방식도 시작된다 (계획 명령에 '<타깃> read_memory' 가 있어 수정 전에는 시작부터 거부)
        r2 = await call(c, "openocd_dump_memory_start", case_id=cid, address=0x80001000, length=0x2000, chunk_size=0x1000,
                        target="mem_ap", output_name="ap-auto")
        assert r2.get("ok"), r2
        st2 = await _wait_job(c, r2["job_id"])
        assert st2["status"] == "succeeded", st2
        assert (_case(cid).dir / st2["result"]["path"]).read_bytes() == bytes(region.data[0x1000:0x3000])

        # 에이전트가 쓴 같은 원시 명령은 느슨해지지 않는다 (MODIFY → 이 설정에서는 거부, OpenOCD 로 보내지 않음)
        before = len(fake.dev.executed)
        raw = await call(c, "openocd_command", case_id=cid, command=READ)
        assert raw.get("status") == "denied" and raw["gate"]["classification"]["risk"] == "modify", raw
        assert len(fake.dev.executed) == before


@pytest.mark.anyio
async def test_target_not_in_list_is_refused_and_list_refreshed_on_mismatch(workspace, auth, fake):
    from openocd_mcp.server import server
    from pweh.runtime import get_runtime

    _add_target(fake, "mem_ap")
    cid = _new_case(auth)
    async with Client(server) as c:
        assert (await call(c, "openocd_attach", case_id=cid, tcl_port=fake.port))["ok"]
        assert (await call(c, "openocd_read_memory", case_id=cid, address=0x80000000, count=1, target="mem_ap")).get("ok")
        for target in ("ghost", "ghost.cpu"):
            r = await call(c, "openocd_read_memory", case_id=cid, address=0x80000000, count=4, target=target)
            assert "_error" in r and target in r["_error"] and "mem_ap" in r["_error"], r  # 사용 가능한 이름 안내
            d = await call(c, "openocd_dump_memory_start", case_id=cid, address=0x80000000, length=0x1000, target=target,
                           method="read_memory", output_name=f"x-{target}")
            assert "_error" in d, d
            w = await call(c, "openocd_write_memory", case_id=cid, address=0x80000000, values=[1], target=target)
            assert "_error" in w, w  # 사람에게 승인을 묻기 전에 거부
        assert not any(x and x[0].startswith("ghost") for x in fake.dev.executed), fake.dev.executed
        assert not [j for j in get_runtime("openocd-mcp").jobs.list() if j.get("case_id") == cid]

        # 목록을 캐시한 뒤 생긴 타깃: 불일치하면 목록을 다시 조회해 받아들인다
        queried = _names_queries(fake)
        _add_target(fake, "cpu1")
        r = await call(c, "openocd_read_memory", case_id=cid, address=0x80000000, count=4, target="cpu1")
        assert r.get("ok"), r
        assert _names_queries(fake) == queried + 1


@pytest.mark.anyio
async def test_target_name_colliding_with_a_command_is_refused(workspace, auth, fake):
    """실제 xPack 은 'target create mww …' 를 받아 전역 mww 를 가린다 — 버전마다 뜻이 다를 수 있어 서버는 그런 이름을 쓰지 않는다."""
    from openocd_mcp.server import server

    for name in ("mww", "reset"):
        _add_target(fake, name)
    cid = _new_case(auth)
    async with Client(server) as c:
        assert (await call(c, "openocd_attach", case_id=cid, tcl_port=fake.port))["ok"]
        for name in ("mww", "reset"):
            r = await call(c, "openocd_read_memory", case_id=cid, address=0x80000000, count=4, target=name)
            assert "_error" in r and "쓸 수 없습니다" in r["_error"] and name in r["_error"], (name, r)
            d = await call(c, "openocd_dump_memory_start", case_id=cid, address=0x80000000, length=0x1000, target=name,
                           method="read_memory", output_name=f"c-{name}")
            assert "_error" in d and "쓸 수 없습니다" in d["_error"], (name, d)
        # 같은 이름을 dotless 타깃처럼 쓴 에이전트 원시 명령도 접두를 떼지 않는다 (mww = DESTRUCTIVE → 기본 거부)
        raw = await call(c, "openocd_command", case_id=cid, command="mww read_memory 0x80000000 32 4")
        assert raw.get("status") == "denied" and raw["gate"]["classification"]["risk"] == "destructive", raw
    assert not any(x and x[0] in ("mww", "reset") for x in fake.dev.executed), fake.dev.executed


@pytest.mark.anyio
async def test_write_memory_readback_on_dotless_target(workspace, auth, fake):
    from openocd_mcp.server import server
    from pweh.runtime import get_runtime

    # 확인 읽기가 MODIFY 로 분류되면 거부되도록 modify_policy=deny
    workspace["set_safety"](destructive_policy="approve", modify_policy="deny", approval_methods=["cli"])
    _add_target(fake, "mem_ap")
    cid = _new_case(auth)
    rt = get_runtime("openocd-mcp")
    async with Client(server) as c:
        assert (await call(c, "openocd_attach", case_id=cid, tcl_port=fake.port))["ok"]
        args = dict(case_id=cid, address=0x80000000, values=["0x11223344"], target="mem_ap")
        r1 = await call(c, "openocd_write_memory", **args)
        assert r1.get("status") == "approval_required" and r1["gate"]["classification"]["risk"] == "destructive", r1
        assert not any(x[:2] == ["mem_ap", "write_memory"] for x in fake.dev.executed)
        ap = r1["approval_id"]
        rt.approvals.decide(ap, approve=True, code=rt.approvals.get(ap)["code"], via="test")
        r2 = await call(c, "openocd_write_memory", **args, approval_id=ap)
        assert r2.get("ok") and r2.get("verified") is True, r2
        assert bytes(fake.dev.regions[0].data[:4]) == bytes.fromhex("44332211")


@pytest.mark.anyio
@pytest.mark.parametrize("profile", ["v0.12.0", "v0.11.0"])
async def test_dotless_target_with_jim_list_target_names(workspace, auth, profile):
    """0.12.0 이하 릴리스는 'target names' 를 Jim 리스트(공백 구분)로 돌려준다. 0.11 은 read_memory 가 없어 '<타깃> mdw' 로 대체."""
    from openocd_mcp.server import server

    workspace["set_safety"](modify_policy="deny")
    with FakeOpenOCD(profile=profile) as fk:
        _add_target(fk, "mem_ap")
        region = fk.dev.regions[0]
        cid = _new_case(auth, title=f"jim list {profile}")
        async with Client(server) as c:
            assert (await call(c, "openocd_attach", case_id=cid, tcl_port=fk.port))["ok"]
            mem = await call(c, "openocd_read_memory", case_id=cid, address=0x80000000, count=4, target="mem_ap")
            assert mem.get("ok") and mem["bytes_hex"] == bytes(region.data[:16]).hex(), mem
            assert mem["method"] == ("mdw" if profile == "v0.11.0" else "read_memory")
            r = await call(c, "openocd_dump_memory_start", case_id=cid, address=0x80000000, length=0x2000, chunk_size=0x1000,
                           target="mem_ap", method="read_memory", output_name="old-profile")
            assert r.get("ok"), r
            st = await _wait_job(c, r["job_id"])
            assert st["status"] == "succeeded", st
            assert st["result"]["transfer"] == ("md" if profile == "v0.11.0" else "read_memory")
            assert (_case(cid).dir / st["result"]["path"]).read_bytes() == bytes(region.data[:0x2000])


@pytest.mark.anyio
async def test_unavailable_target_list_loosens_nothing(workspace, auth, fake):
    """target names 를 얻지 못하면 접두를 떼지 않는다 (기존 분류 그대로: 점 없는 이름은 MODIFY)."""
    from openocd_mcp.server import server

    from .fake_openocd import CmdFail

    workspace["set_safety"](modify_policy="deny")
    _add_target(fake, "mem_ap")

    def failing_target(args, interp):
        raise CmdFail("target: command unavailable\n")

    fake.dev.c_target = failing_target  # type: ignore[method-assign]
    cid = _new_case(auth)
    async with Client(server) as c:
        assert (await call(c, "openocd_attach", case_id=cid, tcl_port=fake.port))["ok"]
        r = await call(c, "openocd_read_memory", case_id=cid, address=0x80000000, count=4, target="mem_ap")
        assert r.get("status") == "denied" and r["gate"]["classification"]["risk"] == "modify", r
        assert not any(x[:2] == ["mem_ap", "read_memory"] for x in fake.dev.executed)
        d = await call(c, "openocd_dump_memory_start", case_id=cid, address=0x80000000, length=0x1000, target="mem_ap",
                       method="read_memory", output_name="nolist")
        assert "_error" in d and "safety_denied" in d["_error"], d


# ---------------------------------------------------------------------------
# 실제 OpenOCD (xPack 0.12.0-7, dummy 어댑터 + 점 없는 testee 타깃)
# ---------------------------------------------------------------------------

_TOOLS = Path.home() / "pweh-tools"
_XPACK_SCRIPTS = _TOOLS / "openocd" / "xpack-openocd-0.12.0-7" / "openocd" / "scripts"


@pytest.mark.anyio
@pytest.mark.external
async def test_real_openocd_dotless_target(workspace, auth, monkeypatch):
    """실제 'target names'(줄 단위)로 확인한 점 없는 타깃 cpu0 에 '<타깃> read_memory' 가 전달되고, 덤프 작업도 시작된다.

    testee 타깃은 메모리 접근을 지원하지 않으므로 OpenOCD 의 'Target cpu0 doesn't support read_memory' 오류가
    곧 타깃으로 디스패치되었다는 증거다. 수정 전에는 덤프 작업이 계획 명령 검사(MODIFY)에서 시작부터 거부되었다.
    """
    from openocd_mcp.server import server
    from pweh.runtime import reset_runtimes

    binary = next((p for p in (os.environ.get("PWEH_OPENOCD"), str(_TOOLS / "bin" / "openocd"))
                   if p and Path(p).is_file() and os.access(p, os.X_OK)), None)
    if not binary:
        pytest.skip("OpenOCD 가 없습니다 (PWEH_OPENOCD 또는 ~/pweh-tools/bin/openocd)")
    monkeypatch.setenv("PWEH_OPENOCD", binary)
    if _XPACK_SCRIPTS.is_dir():
        monkeypatch.setenv("PWEH_OPENOCD_SCRIPTS", str(_XPACK_SCRIPTS))
    reset_runtimes()
    cid = _new_case(auth, title="real dotless")
    async with Client(server) as c:
        r = await call(
            c, "openocd_start", case_id=cid, interface_cfg="interface/dummy.cfg", transport="jtag", adapter_speed_khz=1000,
            extra_commands=[
                "jtag newtap dummy cpu -irlen 4 -ircapture 0x1 -irmask 0x1 -ignore-bypass",
                "target create dummy.cpu testee -chain-position dummy.cpu",
                "target create cpu0 testee -chain-position dummy.cpu",
            ],
            tcl_port=0, ready_timeout=30,
        )
        assert r["ok"], r
        mem = await call(c, "openocd_read_memory", case_id=cid, address=0, count=1, target="cpu0")
        assert mem["ok"] is False and "Target cpu0 doesn't support read_memory" in mem["error"], mem
        ghost = await call(c, "openocd_read_memory", case_id=cid, address=0, count=1, target="ghost")
        assert "_error" in ghost and "cpu0" in ghost["_error"] and "dummy.cpu" in ghost["_error"], ghost
        dj = await call(c, "openocd_dump_memory_start", case_id=cid, address=0, length=4096, chunk_size=4096, retries=0,
                        target="cpu0", method="read_memory", output_name="real-cpu0")
        assert dj.get("ok") and dj["classification"]["risk"] == "interact", dj
        st = await _wait_job(c, dj["job_id"])
        assert st["status"] == "failed" and "read_memory" in st["error"]["message"], st
        stop = await call(c, "openocd_stop", case_id=cid)
        assert stop["ok"], stop
