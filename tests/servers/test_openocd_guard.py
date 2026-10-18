"""openocd-mcp 안전 분류기(guard) 회귀 테스트 — 검토 단계에서 찾은 게이트 우회 형태.

각 우회 형태는 xPack OpenOCD 0.12.0-7 의 Jim Tcl 에서 본문이 실제로 실행됨을 확인했다(echo 를 표식으로 사용).
수정 전에는 아래 DESTRUCTIVE 형태들이 INTERACT/MODIFY 로 분류되어 기본 정책(modify 허용)에서 그대로 실행되었다.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest
from mcp import Client

from openocd_mcp import guard
from pweh.safety import Risk

from .fake_openocd import FakeOpenOCD
from mcp_helpers import call

# ---------------------------------------------------------------------------
# 분류기 단위
# ---------------------------------------------------------------------------

BYPASS_FORMS = [
    # 코어의 줄 단위 주석 제거(splitlines)가 Jim 과 달라 문장이 사라지던 형태
    'set x "\n# "; mww 0 0',
    "catch {\v# } ; mww 0 0",
    "set q 1\x1c# ; mww 0 0",
    "echo a\r# ; mww 0 0",
    # 중괄호 식 안의 명령 치환 (위 형태와 결합하면 코어가 놓침)
    "if {[catch {catch {\v#}; mww 0 0}]} {}",
    "while {[mww 0 0] ne {}} {break}",
    "if 1 then {echo a} elseif {[mww 0 0]} {echo b}",
    # 이중 치환: 중괄호 없는 식의 치환 결과를 expr 가 다시 해석
    'expr "\\x5bmww 0 0\\x5d"',
    "expr $x",
    "if $y {}",
    "while $cond {break}",
    "for {} $t {} {}",
    # 옵션 뒤 본문 / 하위 명령 본문 / 마지막 인자 본문
    'catch -error "mww 0 0"',
    'catch -error -- "mww 0 0"',
    "catch $opt {mww 0 0}",
    'dict for {k v} {a b} "mww 0 0"',
    'dict with dd "mww 0 0"',
    'dict update de a av "mww 0 0"',
    'loop i 0 1 "mww 0 0"',
    # OpenOCD 이벤트 핸들러 (나중에 reset init 등 MODIFY 동작이 실행)
    'cam.cpu configure -event reset-init "mww 0x20110000 1"',
    "cam.cpu configure -event reset-init {::mww 0 0}",
    "cam.cpu configure -event reset-init {m\\ww 0 0}",
    "cam.cpu configure -event reset-init $body",
    "cam.cpu configure -event reset-init [set b]",
    'jtag configure cam.cpu -event setup "mww 0 0"',
    'target create cam.cpu arm926ejs -chain-position cam.cpu -event reset-init "mww 0 0"',
    # 명령 접두를 받는 -command (lsort 는 비교마다 'mww a b' 를 호출)
    "lsort -command mww {0 0}",
    "lsearch -command mww {0x0} 0x0",
    "regsub -command mww abc b",
    "lsort -command $cmd {0 0}",
    # 알 수 없는 명령의 본문 인자 / 이벤트 루프 / 훅
    'stdout readable "mww 0 0"',
    "update",
    "vwait done",
    'xtrace {if 1 "mww 0 0"}',
    "curry mww 0",
    # 이 서버가 끈 telnet/GDB 명령 서버를 다시 열면 그 포트의 명령은 게이트를 거치지 않는다 (xPack 에서 telnet 명령 실행 확인)
    "telnet port 4444",
    "telnet_port 4444",
    "gdb port 3333",
    "gdb_port 3333",
    "gdb port $p",
    "cam.cpu configure -gdb-port 3333",
]


@pytest.mark.parametrize("cmd", BYPASS_FORMS)
def test_bypass_forms_are_destructive(cmd):
    c = guard.classify_command(cmd)
    assert c.risk == Risk.DESTRUCTIVE, (cmd, c)


@pytest.mark.parametrize(
    "cmd,risk",
    [
        # 흔한 안전한 형태는 기존 위험도를 유지해야 한다 (과잉 차단 방지)
        ("mdw 0x0 4", Risk.INTERACT),
        ('capture "mdw 0 4"', Risk.INTERACT),
        ('echo "hello world"', Risk.INTERACT),
        ("expr {1 + 2}", Risk.INTERACT),
        ("expr 1 + 2", Risk.INTERACT),
        ("if {[catch {halt}]} {echo x}", Risk.MODIFY),
        ("catch -noerror {halt}", Risk.MODIFY),
        ("cam.cpu configure -event reset-init {echo hi}", Risk.MODIFY),
        ("lsort -command {string compare} {b a}", Risk.MODIFY),
        ("targets cam.cpu; halt", Risk.MODIFY),
        ("jtag newtap cam cpu -irlen 4 -expected-id 0x07926f0f", Risk.MODIFY),
        ("telnet port disabled", Risk.MODIFY),  # 서버 자신이 쓰는 형태 (끄기)
        ("gdb port disabled", Risk.MODIFY),
        ("cam.cpu configure -gdb-port disabled", Risk.MODIFY),
    ],
)
def test_benign_forms_keep_their_risk(cmd, risk):
    assert guard.classify_command(cmd).risk == risk, cmd


def test_storing_a_dangerous_string_is_not_executing_it():
    # 변수에 담는 것만으로는 실행되지 않는다 — 이후 스크립트/식 위치에서 쓰면 그때 DESTRUCTIVE
    assert guard.classify_command('set x "\\x5bmww 0 0\\x5d"').risk < Risk.DESTRUCTIVE
    for use in ("eval $x", "catch $x", "if 1 $x", "expr $x", "uplevel #0 $x", "$x"):
        assert guard.classify_command(use).risk == Risk.DESTRUCTIVE, use


def test_job_safety_check_rejects_bypass_forms(tmp_path):
    jtag = tmp_path / "jtag"
    jtag.mkdir()
    from pweh.errors import SafetyDenied

    for cmd in ('set x "\n# "; mww 0 0', 'catch -error "mww 0 0"', "lsort -command mww {0 0}"):
        with pytest.raises(SafetyDenied):
            guard.ensure_job_commands_safe([cmd], allowed_dirs=[jtag])


# ---------------------------------------------------------------------------
# MCP 수준: 기본 정책 거부, 승인 시 정확히 1회
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


def _new_case(auth) -> str:
    from pweh.runtime import get_runtime

    return get_runtime("openocd-mcp").cases.create(title="guard", authorization=auth).id


HIDDEN_WRITE = 'set x "\n# "; mww 0x80000000 0x11223344'


@pytest.mark.anyio
async def test_hidden_write_denied_by_default(workspace, auth, fake):
    from openocd_mcp.server import server

    cid = _new_case(auth)
    before = bytes(fake.dev.regions[0].data[:8])
    async with Client(server) as c:
        assert (await call(c, "openocd_attach", case_id=cid, tcl_port=fake.port))["ok"]
        for cmd in (HIDDEN_WRITE, 'catch -error "mww 0x80000000 0x11223344"', "lsort -command mww {0x80000000 0x1}",
                    'cam.cpu configure -event reset-init "mww 0x80000000 1"'):
            r = await call(c, "openocd_command", case_id=cid, command=cmd)
            assert r.get("ok") is False and r.get("status") == "denied", (cmd, r)
        assert not any(x[0] in ("mww", "set") for x in fake.dev.executed), fake.dev.executed  # OpenOCD 로 보내지지 않음
        assert bytes(fake.dev.regions[0].data[:8]) == before


@pytest.mark.anyio
async def test_start_extra_commands_event_handler_denied(workspace, auth, tmp_path, monkeypatch):
    """openocd_start 의 extra_commands 에 넣은 따옴표 이벤트 핸들러도 같은 분류기로 막혀 프로세스가 뜨지 않는다."""
    from openocd_mcp.server import server
    from pweh.runtime import get_runtime, reset_runtimes

    fake_py = Path(__file__).resolve().parent / "fake_openocd.py"
    binp = tmp_path / "fakebin" / "openocd"
    binp.parent.mkdir()
    binp.write_text(f'#!/bin/sh\nexec "{sys.executable}" "{fake_py}" "$@"\n')
    binp.chmod(0o755)
    monkeypatch.setenv("PWEH_OPENOCD", str(binp))
    reset_runtimes()
    cid = _new_case(auth)
    async with Client(server) as c:
        for extra in (['cam.cpu configure -event reset-init "mww 0x80000000 1"'], ['set x "\n# "; mww 0 0'],
                      ["dict for {k v} {a b} \"mww 0 0\""], ["telnet port 4444"], ["gdb port 3333"]):
            r = await call(c, "openocd_start", case_id=cid, interface_cfg="interface/dummy.cfg", extra_commands=extra, tcl_port=0)
            assert r.get("status") == "denied" and r["gate"]["classification"]["risk"] == "destructive", (extra, r)
    jtag = get_runtime("openocd-mcp").cases.get(cid).dir / "jtag"
    assert not list(jtag.glob("openocd-*.log"))  # 프로세스가 뜨지 않음


@pytest.mark.anyio
async def test_hidden_write_runs_exactly_once_with_approval(workspace, auth, fake):
    from openocd_mcp.server import server
    from pweh.runtime import get_runtime

    workspace["set_safety"](destructive_policy="approve", approval_methods=["cli"])
    cid = _new_case(auth)
    async with Client(server) as c:
        assert (await call(c, "openocd_attach", case_id=cid, tcl_port=fake.port))["ok"]
        r1 = await call(c, "openocd_command", case_id=cid, command=HIDDEN_WRITE)
        assert r1["status"] == "approval_required" and r1["gate"]["classification"]["risk"] == "destructive", r1
        assert not any(x[0] == "mww" for x in fake.dev.executed)
        ap = r1["approval_id"]
        rt = get_runtime("openocd-mcp")
        rt.approvals.decide(ap, approve=True, code=rt.approvals.get(ap)["code"], via="test")
        r2 = await call(c, "openocd_command", case_id=cid, command=HIDDEN_WRITE, approval_id=ap)
        assert r2["ok"], r2
        assert bytes(fake.dev.regions[0].data[:4]) == bytes.fromhex("44332211")
        assert sum(1 for x in fake.dev.executed if x[0] == "mww") == 1
        r3 = await call(c, "openocd_command", case_id=cid, command=HIDDEN_WRITE, approval_id=ap)
        assert r3["ok"] is False and r3["status"] == "denied"  # 1회용
        assert sum(1 for x in fake.dev.executed if x[0] == "mww") == 1


@pytest.mark.anyio
async def test_flash_write_approval_bound_to_file_and_single_use(workspace, auth, fake, monkeypatch):
    """openocd_flash_write: 승인은 파일 sha256 에 묶이고(바뀌면 무효), 승인 직후 바뀌어도 실행하지 않으며, 정확히 1회만 실행된다."""
    from openocd_mcp.server import server
    from pweh.runtime import Runtime, get_runtime

    workspace["set_safety"](destructive_policy="approve", approval_methods=["cli"])
    cid = _new_case(auth)
    rt = get_runtime("openocd-mcp")
    img = rt.cases.get(cid).subdir("dumps") / "fw.bin"
    img.write_bytes(b"\x01" * 64)
    bank = fake.dev.banks[0]
    original = bytes(bank.data[:64])

    def written() -> int:
        return sum(1 for x in fake.dev.executed if x[:2] == ["flash", "write_image"])

    async with Client(server) as c:
        assert (await call(c, "openocd_attach", case_id=cid, tcl_port=fake.port))["ok"]
        args = dict(case_id=cid, path="dumps/fw.bin", address=0)
        r1 = await call(c, "openocd_flash_write", **args)
        assert r1["status"] == "approval_required", r1
        ap = r1["approval_id"]
        rt.approvals.decide(ap, approve=True, code=rt.approvals.get(ap)["code"], via="test")
        img.write_bytes(b"\x02" * 64)  # 승인 뒤 파일 교체 → 사람이 본 sha256 과 다름
        r2 = await call(c, "openocd_flash_write", **args, approval_id=ap)
        assert r2.get("ok") is False and r2["status"] == "denied", r2
        assert written() == 0 and bytes(bank.data[:64]) == original

        # 게이트 통과 직후(실행 전) 파일이 바뀌면 실행하지 않는다 (TOCTOU 재확인)
        r3 = await call(c, "openocd_flash_write", **args)
        ap3 = r3["approval_id"]
        rt.approvals.decide(ap3, approve=True, code=rt.approvals.get(ap3)["code"], via="test")
        orig_auth = Runtime.authorize

        async def swap_after_gate(self, **kw):
            d = await orig_auth(self, **kw)
            if kw.get("tool") == "openocd_flash_write" and kw.get("approval_id"):
                img.write_bytes(b"\x03" * 64)
            return d

        monkeypatch.setattr(Runtime, "authorize", swap_after_gate)
        r4 = await call(c, "openocd_flash_write", **args, approval_id=ap3)
        assert "_error" in r4 and "바뀌었습니다" in r4["_error"], r4
        monkeypatch.setattr(Runtime, "authorize", orig_auth)
        assert written() == 0 and bytes(bank.data[:64]) == original

        # 현재 내용으로 새 승인 → 정확히 1회 실행
        r5 = await call(c, "openocd_flash_write", **args)
        ap5 = r5["approval_id"]
        rt.approvals.decide(ap5, approve=True, code=rt.approvals.get(ap5)["code"], via="test")
        r6 = await call(c, "openocd_flash_write", **args, approval_id=ap5)
        assert r6["ok"] and r6["verify"]["ok"], r6
        assert bytes(bank.data[:64]) == b"\x03" * 64 and written() == 1
        r7 = await call(c, "openocd_flash_write", **args, approval_id=ap5)
        assert r7.get("ok") is False and r7["status"] == "denied" and written() == 1  # 1회용
