"""openocd_start 의 cfg 처리 회귀 테스트 (검토 단계).

- 사용자 cfg 를 앞 1 MiB 만 잘라 분류하던 문제 → 전체 분류, 상한 초과는 거부
- 승인이 cfg 경로에만 묶여 승인 뒤 내용이 바뀌어도 실행되던 문제 → sha256 을 승인 지문에 넣고 실행 직전 재확인
- 이름만 준 cfg 가 OpenOCD 기본 검색 위치(~/.openocd 등)에서 분류 없이 실행되던 문제 → 그 위치에서 찾으면 사용자 cfg 로 분류
- 신뢰 scripts 디렉터리를 모두 -s 로 넘겨 표준 cfg 의 source [find ...] 가 사용자 위치를 먼저 찾지 않게 함
"""

from __future__ import annotations

from pathlib import Path

import pytest
from mcp import Client

from openocd_mcp import process
from mcp_helpers import call

pytestmark = pytest.mark.anyio



@pytest.fixture
def anyio_backend():
    return "asyncio"


@pytest.fixture(autouse=True)
def _cleanup_sessions():
    yield
    from openocd_mcp.session import REGISTRY

    REGISTRY.shutdown_all()


def _write_fake_bin(path: Path) -> Path:
    # 서버는 연결 직후 semihosting 가드 확인(RPC)이 필수다 → 그 proc 에 답하도록 가르친 가짜 (test_openocd_semihosting.GUARDED_FAKE)
    from .test_openocd_semihosting import write_guarded_fake_bin

    return write_guarded_fake_bin(path)


@pytest.fixture
def fake_env(tmp_path, monkeypatch):
    """가짜 OpenOCD 실행 파일 + 격리된 HOME (사용자 홈의 ~/.openocd 등을 건드리지 않게)."""
    from pweh.runtime import reset_runtimes

    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.delenv("XDG_CONFIG_HOME", raising=False)
    monkeypatch.delenv("OPENOCD_SCRIPTS", raising=False)
    monkeypatch.delenv("PWEH_OPENOCD_SCRIPTS", raising=False)
    monkeypatch.delenv("FAKE_OPENOCD_MODE", raising=False)
    binp = _write_fake_bin(tmp_path / "fakebin" / "openocd")
    monkeypatch.setenv("PWEH_OPENOCD", str(binp))
    reset_runtimes()
    return {"home": home, "bin": binp}


def _new_case(auth) -> str:
    from pweh.runtime import get_runtime

    return get_runtime("openocd-mcp").cases.create(title="start gate", authorization=auth).id


def _logs(cid: str) -> list[Path]:
    from pweh.runtime import get_runtime

    return list((get_runtime("openocd-mcp").cases.get(cid).dir / "jtag").glob("openocd-*.log"))


# ---------------------------------------------------------------------------
# 단위: 검색 위치 / 해석 / 명령행
# ---------------------------------------------------------------------------


def test_openocd_search_dirs_order_and_exclude(tmp_path, monkeypatch):
    home = tmp_path / "home"
    for d in (home / ".config" / "openocd", home / ".openocd"):
        d.mkdir(parents=True)
    env_dir = tmp_path / "envscripts"
    env_dir.mkdir()
    xp = tmp_path / "xp"
    binp = _write_fake_bin(xp / "bin" / "openocd")
    (xp / "openocd" / "site").mkdir(parents=True)
    (xp / "openocd" / "scripts").mkdir(parents=True)
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.delenv("XDG_CONFIG_HOME", raising=False)
    monkeypatch.setenv("OPENOCD_SCRIPTS", str(env_dir))
    got = process.openocd_search_dirs(str(binp), exclude=[xp / "openocd" / "scripts"])
    assert got == [env_dir.resolve(), (home / ".config" / "openocd").resolve(), (home / ".openocd").resolve(),
                   (xp / "openocd" / "site").resolve()]
    xdg = tmp_path / "xdg"
    (xdg / "openocd").mkdir(parents=True)
    monkeypatch.setenv("XDG_CONFIG_HOME", str(xdg))
    assert (xdg / "openocd").resolve() in process.openocd_search_dirs(str(binp))


def test_resolve_cfg_untrusted_location_is_custom(tmp_path):
    scripts = tmp_path / "scripts"
    (scripts / "interface").mkdir(parents=True)
    (scripts / "interface" / "dummy.cfg").write_text("adapter driver dummy\n")
    user = tmp_path / "home" / ".openocd"
    user.mkdir(parents=True)
    (user / "mycam.cfg").write_text("flash erase_sector 0 0 last\n")
    (user / "interface").mkdir()
    (user / "interface" / "dummy.cfg").write_text("mww 0 0\n")
    ref = process.resolve_cfg("mycam.cfg", [scripts], [user])
    assert ref.kind == "custom" and ref.path == (user / "mycam.cfg").resolve() and ref.arg == str(ref.path)
    # 신뢰 scripts 에 있는 이름은 그대로 표준 (OpenOCD 도 -s 로 신뢰 디렉터리를 먼저 찾는다)
    assert process.resolve_cfg("interface/dummy.cfg", [scripts], [user]).kind == "standard"
    assert process.resolve_cfg("nowhere.cfg", [scripts], [user]).kind == "unresolved"


def test_build_argv_passes_trusted_dirs_as_search_dirs():
    iface = process.CfgRef("/opt/s/interface/dummy.cfg", "standard")
    argv = process.build_argv(
        "/opt/openocd", scripts_dir=Path("/opt/s"), interface=iface, transport=None, targets=[], extra_cfgs=[],
        adapter_speed_khz=None, extra_commands=[], tcl_port=0, search_dirs=[Path("/opt/s"), Path("/usr/share/openocd/scripts")],
    )
    assert argv[1:5] == ["-s", "/opt/s", "-s", "/usr/share/openocd/scripts"]  # 중복 제거, 순서 유지
    assert argv.index("-f") > 4


# ---------------------------------------------------------------------------
# MCP: openocd_start
# ---------------------------------------------------------------------------


async def test_large_custom_cfg_is_classified_whole_or_refused(workspace, auth, fake_env, tmp_path):
    from openocd_mcp.server import server

    cid = _new_case(auth)
    big = tmp_path / "big.cfg"
    big.write_text("#" * (1024 * 1024 + 10) + "\nflash erase_sector 0 0 last\n")  # 수정 전: 앞 1 MiB 만 분류 → 통과
    near = tmp_path / "near.cfg"
    near.write_text("# pad\n" * 150_000 + "adapter driver dummy\nflash erase_sector 0 0 last\n")  # 상한 안, 끝에 위험 명령
    async with Client(server) as c:
        r = await call(c, "openocd_start", case_id=cid, interface_cfg=str(big), tcl_port=0)
        assert "_error" in r and "너무 큽니다" in r["_error"], r
        r = await call(c, "openocd_start", case_id=cid, interface_cfg=str(near), tcl_port=0)
        assert r["status"] == "denied" and r["custom_cfgs"][0]["classification"]["risk"] == "destructive", r
    assert not _logs(cid)  # 프로세스가 뜨지 않음


async def test_unresolved_name_in_home_openocd_is_classified(workspace, auth, fake_env):
    from openocd_mcp.server import server

    user = fake_env["home"] / ".openocd"
    user.mkdir()
    (user / "mycam.cfg").write_text("adapter driver dummy\nflash erase_sector 0 0 last\n")
    cid = _new_case(auth)
    async with Client(server) as c:
        r = await call(c, "openocd_start", case_id=cid, interface_cfg="mycam.cfg", tcl_port=0)
        assert r["status"] == "denied", r  # 수정 전: unresolved 로 OpenOCD 에 그대로 넘겨 분류 없이 실행
        assert r["custom_cfgs"][0]["path"] == str((user / "mycam.cfg").resolve())
    assert not _logs(cid)


async def test_custom_cfg_approval_is_bound_to_content(workspace, auth, fake_env, tmp_path):
    from openocd_mcp.server import server
    from pweh.runtime import get_runtime

    workspace["set_safety"](destructive_policy="approve", approval_methods=["cli"])
    cid = _new_case(auth)
    cfg = tmp_path / "cam.cfg"
    cfg.write_text("adapter driver dummy\ncam.cpu configure -event reset-init {mww 0x20110000 1}\n")
    rt = get_runtime("openocd-mcp")
    async with Client(server) as c:
        r1 = await call(c, "openocd_start", case_id=cid, interface_cfg=str(cfg), tcl_port=0)
        assert r1["status"] == "approval_required" and r1["custom_cfgs"][0]["sha256"], r1
        ap = r1["approval_id"]
        rt.approvals.decide(ap, approve=True, code=rt.approvals.get(ap)["code"], via="test")
        # 승인 뒤 같은 경로의 내용을 바꾸면 승인을 쓸 수 없다 (사람이 본 내용과 다름)
        cfg.write_text("adapter driver dummy\ncam.cpu configure -event reset-init {mww 0x20110000 0xdead}\n")
        r2 = await call(c, "openocd_start", case_id=cid, interface_cfg=str(cfg), tcl_port=0, approval_id=ap)
        assert r2.get("ok") is False and r2["status"] == "denied", r2
        assert not _logs(cid)
        # 같은 내용으로 새로 승인받으면 정확히 1회 실행
        r3 = await call(c, "openocd_start", case_id=cid, interface_cfg=str(cfg), tcl_port=0)
        ap2 = r3["approval_id"]
        rt.approvals.decide(ap2, approve=True, code=rt.approvals.get(ap2)["code"], via="test")
        r4 = await call(c, "openocd_start", case_id=cid, interface_cfg=str(cfg), tcl_port=0, approval_id=ap2)
        assert r4["ok"], r4
        assert (await call(c, "openocd_stop", case_id=cid))["ok"]
        r5 = await call(c, "openocd_start", case_id=cid, interface_cfg=str(cfg), tcl_port=0, approval_id=ap2)
        assert r5.get("ok") is False and r5["status"] == "denied"  # 1회용
    assert len(_logs(cid)) == 1


async def test_custom_cfg_changed_after_authorization_is_not_spawned(workspace, auth, fake_env, tmp_path, monkeypatch):
    """분류·게이트 통과 직후(프로세스를 띄우기 전) cfg 가 바뀌면 실행하지 않는다 (TOCTOU)."""
    from openocd_mcp.server import server
    from pweh.runtime import Runtime

    cid = _new_case(auth)
    cfg = tmp_path / "cam.cfg"
    cfg.write_text("adapter driver dummy\njtag newtap cam cpu -irlen 4\n")  # MODIFY → 기본 정책 허용
    orig = Runtime.authorize

    async def swap_after_gate(self, **kw):
        decision = await orig(self, **kw)
        if kw.get("tool") == "openocd_start":
            cfg.write_text("adapter driver dummy\nflash erase_sector 0 0 last\n")
        return decision

    monkeypatch.setattr(Runtime, "authorize", swap_after_gate)
    async with Client(server) as c:
        r = await call(c, "openocd_start", case_id=cid, interface_cfg=str(cfg), tcl_port=0)
        assert "_error" in r and "바뀌었습니다" in r["_error"], r
    assert not _logs(cid)


async def test_binary_relative_scripts_dir_passed_as_search_dir(workspace, auth, tmp_path, monkeypatch):
    """scripts 디렉터리를 설정하지 않아도(실행 파일 기준으로 찾은) 신뢰 디렉터리를 -s 로 넘긴다."""
    from openocd_mcp.server import server
    from pweh.runtime import reset_runtimes

    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.delenv("PWEH_OPENOCD_SCRIPTS", raising=False)
    monkeypatch.delenv("OPENOCD_SCRIPTS", raising=False)
    monkeypatch.delenv("FAKE_OPENOCD_MODE", raising=False)
    xp = tmp_path / "xp"
    binp = _write_fake_bin(xp / "bin" / "openocd")
    scripts = xp / "openocd" / "scripts"
    (scripts / "interface").mkdir(parents=True)
    (scripts / "interface" / "dummy.cfg").write_text("adapter driver dummy\n")
    monkeypatch.setenv("PWEH_OPENOCD", str(binp))
    reset_runtimes()
    cid = _new_case(auth)
    async with Client(server) as c:
        r = await call(c, "openocd_start", case_id=cid, interface_cfg="interface/dummy.cfg", tcl_port=0)
        assert r["ok"], r
        argv = r["argv"]
        assert argv[1:3] == ["-s", str(scripts.resolve())], argv
        assert str((scripts / "interface" / "dummy.cfg").resolve()) in argv
        assert (await call(c, "openocd_stop", case_id=cid))["ok"]
