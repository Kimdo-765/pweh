"""pweh CLI 테스트 (승인 명령의 비대화형 거부 등)."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from pweh import cli
from pweh.runtime import get_runtime
from pweh.safety import Classification, Risk

REPO = Path(__file__).resolve().parents[2]


def _run(args, env_extra, input_text=None):
    import os

    env = dict(os.environ)
    env.update(env_extra)
    return subprocess.run([sys.executable, "-m", "pweh.cli", *args], capture_output=True, text=True, env=env, input=input_text, timeout=60)


def _pending(workspace):
    workspace["set_safety"](destructive_policy="approve", approval_methods=["cli"])
    rt = get_runtime("test")
    import anyio

    async def go():
        return await rt.authorize(tool="uart_send_command", action={"line": "sf erase 0 100"},
                                  classification=Classification(Risk.DESTRUCTIVE, "uboot.sf.erase", "sf erase", "sf erase 0 100"), case_id=None)

    return anyio.run(go)


def test_approve_refuses_without_tty(workspace):
    d = _pending(workspace)
    r = _run(["approve", d.approval_id], {"PWEH_CONFIG": str(workspace["config"])}, input_text="XXXX\n")
    assert r.returncode == 2
    assert "대화형 터미널" in r.stderr
    rec = get_runtime("test").approvals.get(d.approval_id)
    assert rec["status"] == "pending"


def test_approvals_list_hides_code(workspace):
    d = _pending(workspace)
    r = _run(["approvals", "--json"], {"PWEH_CONFIG": str(workspace["config"])})
    assert r.returncode == 0, r.stderr
    data = json.loads(r.stdout)
    assert data and data[0]["id"] == d.approval_id and "code" not in data[0]


def test_deny(workspace):
    d = _pending(workspace)
    r = _run(["deny", d.approval_id], {"PWEH_CONFIG": str(workspace["config"])})
    assert r.returncode == 0
    assert get_runtime("test").approvals.get(d.approval_id)["status"] == "denied"


def test_case_new_noninteractive(workspace):
    r = _run(["case", "new", "--title", "CLI 케이스", "--basis", "owned", "--owner", "나", "--statement", "내 기기", "--vendor", "Acme"],
             {"PWEH_CONFIG": str(workspace["config"])})
    assert r.returncode == 0, r.stderr
    out = json.loads(r.stdout)
    assert out["case"]["authorized"] is True


def test_mcp_config_outputs(workspace, tmp_path):
    servers = cli.build_mcp_servers(include_rea=True, tools_env=str(tmp_path / "missing-env.sh"))
    assert {"pweh-case", "pweh-uart", "pweh-openocd", "pweh-sigrok", "pweh-jtagulator", "pweh-fwtriage", "rea"} <= set(servers)
    assert servers["pweh-uart"]["command"].endswith("pweh-uart-mcp")
    assert servers["pweh-uart"]["env"]["PWEH_CONFIG"].endswith("orchestrator/pipeline-config.yaml")
    assert servers["rea"]["args"] == ["--mcp"]
    r = _run(["mcp-config", "--client", "codex", "--no-rea"], {"PWEH_CONFIG": str(workspace["config"])})
    assert "[mcp_servers.pweh-uart]" in r.stdout and "tool_timeout_sec" in r.stdout


def test_skills_install_to_dir(tmp_path):
    dest = tmp_path / "skills"
    rc = cli.main(["skills", "install", "--target", f"dir:{dest}"])
    assert rc == 0
    # SKILL.md 가 있는 Skill 은 링크되고, 없는 것은 missing-source 로 보고
    for name in cli.SKILL_NAMES:
        link = dest / name
        if (REPO / "skills" / name / "SKILL.md").exists():
            assert link.is_symlink() and (link / "SKILL.md").exists()


def test_skill_names_cover_every_skill_in_the_repo():
    """SKILL_NAMES(설치·doctor 가 쓰는 목록)는 skills/ 아래 SKILL.md 가 있는 Skill 전부와 같다 — 새 Skill 을 빠뜨리지 않는다."""
    on_disk = {d.name for d in (REPO / "skills").iterdir() if (d / "SKILL.md").is_file()}
    assert set(cli.SKILL_NAMES) == on_disk and len(cli.SKILL_NAMES) == len(set(cli.SKILL_NAMES))


def test_approve_on_tty_with_code_approves_once(workspace):
    """사람이 대화형 터미널(PTY)에서 확인 코드를 입력하면 승인되고, 같은 요청은 다시 승인할 수 없다."""
    import os
    import pty
    import select
    import time

    d = _pending(workspace)
    code = get_runtime("test").approvals.get(d.approval_id)["code"]
    env = dict(os.environ)
    env["PWEH_CONFIG"] = str(workspace["config"])
    pid, fd = pty.fork()
    if pid == 0:  # pragma: no cover - 자식 프로세스
        os.execvpe(sys.executable, [sys.executable, "-m", "pweh.cli", "approve", d.approval_id], env)
    out = b""
    deadline = time.time() + 30
    while "입력>".encode() not in out and time.time() < deadline:
        ready, _, _ = select.select([fd], [], [], 0.5)
        if ready:
            try:
                out += os.read(fd, 4096)
            except OSError:
                break
    assert "입력>".encode() in out, out.decode("utf-8", "replace")
    os.write(fd, (code + "\n").encode())
    while time.time() < deadline:
        ready, _, _ = select.select([fd], [], [], 0.5)
        if ready:
            try:
                chunk = os.read(fd, 4096)
            except OSError:
                break
            if not chunk:
                break
            out += chunk
    _, status = os.waitpid(pid, 0)
    os.close(fd)
    assert os.waitstatus_to_exitcode(status) == 0, out.decode("utf-8", "replace")
    assert get_runtime("test").approvals.get(d.approval_id)["status"] == "approved"
    again = _run(["approve", d.approval_id], {"PWEH_CONFIG": str(workspace["config"])}, input_text=code + "\n")
    assert again.returncode != 0


def test_doctor_tool_version_detects_broken_tools(tmp_path):
    """doctor 는 실행 파일이 있어도 버전 확인이 실패하면(Traceback, 형식 불일치) 실패로 본다."""
    from pweh.cli import _tool_version

    def tool(name: str, body: str) -> str:
        f = tmp_path / name
        f.write_text("#!/bin/sh\n" + body + "\n")
        f.chmod(0o755)
        return str(f)

    ok, ver = _tool_version([tool("good", "echo 'binwalk 3.1.0'"), "--version"], r"^binwalk \d")
    assert ok and ver == "binwalk 3.1.0"
    # unsquashfs 4.5 의 -version 은 종료 코드 1 이지만 정상
    sq = tool("sq", "echo 'unsquashfs version 4.5 (2021/07/22)'; exit 1")
    assert _tool_version([sq, "-version"], r"^unsquashfs version \d", (0, 1))[0]
    assert not _tool_version([sq, "-version"], r"^unsquashfs version \d")[0]
    ok, why = _tool_version([tool("tb", "echo 'Traceback (most recent call last):' >&2; echo 'OSError: libmagic.so.1' >&2; exit 1"), "--version"], r"^\d+\.\d+")
    assert not ok and "libmagic" in why
    assert not _tool_version([tool("junk", "echo hello"), "--version"], r"^\d+\.\d+")[0]
    assert not _tool_version([str(tmp_path / "missing"), "--version"], r".")[0]



# ---------------------------------------------------------------------------
# pweh env / doctor 환경 절 (합성 보고서·가짜 probe — 실제 호스트를 읽지 않는다)
# ---------------------------------------------------------------------------


def _fake_report(name="wsl2-interop-bridged", **kw):
    from core.hostenv_fixtures import FIXTURES, detect, wsl2

    probe = wsl2(**kw) if kw else FIXTURES[name]()
    return detect(probe)


def test_env_checks_wsl2_section_hides_ghost_ports_and_uses_mode_hints():
    from pweh import hostenv

    rep = _fake_report()
    local = [{"device": f"/dev/ttyS{i}", "hwid": "n/a", "vid": None} for i in range(8)]
    win = [{"port": "COM3", "service": "usbser"}, {"port": "COM7", "service": "silabser"}]
    checks = cli.env_checks(rep, local_ports=local, windows_ports=win, listeners=[{"proto": "tcp", "port": 8080}])
    by = {c["check"]: c for c in checks}
    assert checks[0]["check"] == "env" and by["env"]["detail"].startswith("WSL2 (WSL 9.9.9.9, 6.99.0.1-microsoft-standard-WSL2)")
    assert by["env:interop"]["ok"] is True and "WSLInterop enabled" in by["env:interop"]["detail"] and "참고 값" in by["env:interop"]["detail"]
    assert by["env:uac"]["ok"] is True
    assert "bridged" in by["env:networking"]["detail"] and "8080/tcp" in by["env:networking"]["detail"]
    usb = by["env:usbipd"]
    assert usb["ok"] is None and "--host-ip <Windows LAN IP>" in usb["detail"] and "세션 동안만" in usb["detail"]
    assert "usbipd list → usbipd bind" not in json.dumps(checks, ensure_ascii=False)  # 옛 usbipd 전용 안내는 없다
    assert by["serial:backend"]["detail"].endswith("가짜 /dev/ttyS* 8개 숨김, Windows COM 2개")
    assert by["serial:ports"]["detail"] == "COM3 (usbser), COM7 (silabser)" and by["serial:ports"]["ok"] is True
    assert not any("/dev/ttyS0" in c["detail"] for c in checks)
    lines = cli.route_lines(hostenv.recommend_routes(rep))
    assert lines[0].startswith("route:serial") and "목표: Windows COM 을 pweh-serial-helper.exe 가 연다" in lines[0] and "[P2]" in lines[0]
    assert any(line.startswith("route:esptool") and "esptool.exe" in line and "[현행]" in line for line in lines)


def test_env_checks_flags_uac_off_autobind_and_no_ports_hint():
    rep = _fake_report(info={"major": 10, "minor": 0, "build": 1, "enable_lua": 0, "elevated": True}, usbipd=True, autobind=1, mode="consomme")
    checks = cli.env_checks(rep, local_ports=[], windows_ports=[])
    by = {c["check"]: c for c in checks}
    assert by["env:uac"]["ok"] is False and "High IL" in by["env:uac"]["detail"] and "UAC 꺼짐" in by["env:uac"]["detail"]
    assert by["env:usbipd"]["ok"] is False and "AutoBind" in by["env:usbipd"]["detail"]
    assert "consomme" in by["env:networking"]["detail"] and "127.0.0.1" in by["env:networking"]["detail"]
    assert by["serial:ports"]["ok"] is None and "COMn" in by["serial:ports"]["hint"] and "방법 A" in by["serial:ports"]["hint"]


@pytest.mark.parametrize("name,expect", [
    ("wsl1", "env:usbipd"),
    ("wsl2-no-interop", "env:interop"),
    ("native-linux-brltty", "env:brltty"),
    ("container-on-wsl-kernel", "env:container"),
    ("windows-native", "env:platform"),
])
def test_env_checks_per_kind(name, expect):
    rep = _fake_report(name)
    by = {c["check"]: c for c in cli.env_checks(rep)}
    assert expect in by and "serial:ports" not in by  # 휘발 목록을 주지 않으면 포트 줄은 없다
    if name == "wsl2-no-interop":
        assert by["env:interop"]["ok"] is False and "wsl.conf" in by["env:interop"]["hint"]
        assert by["env:uac"]["ok"] is None
    if name == "native-linux-brltty":
        assert by["env:brltty"]["ok"] is False and "root" in by["env:brltty"]["hint"]
    if name == "windows-native":
        assert by["env:platform"]["ok"] is False and "WSL2" in by["env:platform"]["hint"]
    if name == "wsl1":
        assert "WSL1" in by["env:usbipd"]["detail"]


def test_env_command_json_and_text(workspace, monkeypatch, capsys):
    """pweh env --json: 같은 프로세스에서 기본 probe 를 가짜로 바꿔 실행한다(실제 호스트를 읽지 않는다)."""
    from core.hostenv_fixtures import wsl2
    from pweh import hostenv

    probe = wsl2(mode="nat")
    monkeypatch.setattr(hostenv, "_default_probe", lambda: probe)
    monkeypatch.delenv("PWEH_ESPTOOL_WIN", raising=False)
    assert cli.main(["env", "--json"]) == 0
    out = json.loads(capsys.readouterr().out)
    assert set(out) == {"report", "routes"}
    assert out["report"]["schema"] == "pweh.hostenv/v1" and out["report"]["kind"] == "WSL2_INTEROP"
    assert out["report"]["wsl"]["networking_mode"] == "nat"
    assert [r["device"] for r in out["routes"]][:2] == ["serial", "esptool"]
    calls = len(probe.calls)
    assert cli.main(["env"]) == 0  # 같은 probe → 캐시 사용
    text = capsys.readouterr().out
    assert "env:interop" in text and "route:serial" in text and "추천 경로" in text
    assert len(probe.calls) == calls
    assert cli.main(["env", "--refresh", "--json"]) == 0
    capsys.readouterr()
    assert len(probe.calls) > calls


def test_esptool_win_check_honours_disable_and_interop():
    """F5: hostenv.disable: [windows_tools] 면 doctor 는 Windows esptool.exe 를 실행하지 않는다. interop 이 없어도 실행하지 않는다."""
    from core.hostenv_fixtures import detect, wsl2

    calls = []

    def fake_version(cmd, expect, ok_codes=(0,), timeout=20.0):
        calls.append(cmd)
        return True, "esptool v9.9.9"

    rep = detect(wsl2(), config={"hostenv": {"disable": ["windows_tools"]}})
    row = cli.esptool_win_check(rep, version=fake_version)
    assert row["check"] == "tool:esptool.exe" and row["ok"] is None and "hostenv.disable" in row["detail"] and calls == []
    rep = detect(wsl2(interop_state="off"))
    row = cli.esptool_win_check(rep, version=fake_version)
    assert row["ok"] is None and "interop" in row["detail"] and calls == []
    rep = detect(wsl2())
    row = cli.esptool_win_check(rep, version=fake_version)
    assert row["ok"] is True and "esptool v9.9.9" in row["detail"] and "(출처: pweh-tools)" in row["detail"]
    assert calls == [[rep["windows"]["tools"]["esptool_win"]["path"], "version"]]
    rep = detect(wsl2(esptool=False), config={"tools": {"esptool_win": "/nonexistent/esptool.exe"}})
    row = cli.esptool_win_check(rep, version=fake_version)
    assert row["ok"] is False and "없음" in row["detail"] and len(calls) == 1
    row = cli.esptool_win_check(detect(wsl2(esptool=False)), version=fake_version)
    assert row["ok"] is None and row["detail"] == "없음 (선택)"
    assert cli.esptool_win_check({"kind": "NATIVE_LINUX", "windows": None})["detail"].startswith("해당 없음")


def test_env_checks_show_missing_c_drive_and_unrun_path_usbipd():
    from core.hostenv_fixtures import detect, wsl2

    p = wsl2(mount_style="none", c_mapped=False)
    by = {c["check"]: c for c in cli.env_checks(detect(p))}
    assert by["env:interop"]["ok"] is True and "smoke 못 함" in by["env:interop"]["detail"]
    assert by["env:drvfs"]["ok"] is None and "[automount]" in by["env:drvfs"]["hint"]
    q = wsl2()
    q.which_map["usbipd.exe"] = "/mnt/c/Tools/usbipd.exe"
    q.paths.add("/mnt/c/Tools/usbipd.exe")
    by = {c["check"]: c for c in cli.env_checks(detect(q))}
    assert "실행하지 않았다" in by["env:usbipd"]["detail"] and "/mnt/c/Tools/usbipd.exe" in by["env:usbipd"]["detail"]
