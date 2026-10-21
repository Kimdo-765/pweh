"""pweh CLI 테스트 (승인 명령의 비대화형 거부 등)."""

from __future__ import annotations

import json
import os
import shutil
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
    # REA 는 런처로 등록한다 (런처가 실행할 때 env.sh 를 불러와 rea --mcp 를 실행) — 설정에 PATH 를 적지 않는다
    assert servers["rea"]["command"] == str(cli.REPO_ROOT / "scripts" / "mcp-launch.sh") and servers["rea"]["args"] == ["rea"]
    assert all("PATH" not in s.get("env", {}) for s in servers.values())
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


# ---------------------------------------------------------------------------
# Codex: mcp-config --client codex (--write/--scope/--dry-run), codex-trust, mcp-check, doctor 의 Codex 줄
# 실제 사용자 Codex 홈·Windows 프로필·저장소의 .codex/ 는 건드리지 않는다 (REPO_ROOT·HOME·windows_profile 을 바꾼다)
# ---------------------------------------------------------------------------


@pytest.fixture
def codex_iso(tmp_path, monkeypatch):
    """임시 저장소(REPO_ROOT)·임시 HOME·가짜 Windows 프로필 없음. 반환: dict(repo, home, tools_env)."""
    import shutil

    from pweh import clientcfg

    repo = tmp_path / "repo"
    (repo / ".claude").mkdir(parents=True)
    shutil.copyfile(REPO / ".claude" / "settings.json", repo / ".claude" / "settings.json")
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setattr(cli, "REPO_ROOT", repo)
    monkeypatch.setenv("HOME", str(home))
    for k in ("CODEX_HOME", "USERPROFILE", clientcfg.WINDOWS_PROFILE_ENV, "PWEH_TOOLS_ENV", "PWEH_TOOLS_DIR", "PWEH_REA"):
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setattr(clientcfg, "windows_profile", lambda report=None: (None, "WSL 이 아님"))
    return {"repo": repo, "home": home, "tools_env": str(tmp_path / "missing-env.sh")}


def test_mcp_config_codex_preview_says_write_not_append(workspace):
    r = _run(["mcp-config", "--client", "codex", "--no-rea", "--tools-env", "/nonexistent/env.sh"], {"PWEH_CONFIG": str(workspace["config"])})
    assert r.returncode == 0, r.stderr
    head = r.stdout.splitlines()[:8]
    assert any("--write" in line for line in head) and ">>" not in r.stdout
    lines = r.stdout.splitlines()
    first_table = next(i for i, ln in enumerate(lines) if ln.startswith("["))
    assert lines.index("mcp_optional_startup_grace_ms = 15000") < first_table
    import tomlkit

    data = tomlkit.parse(r.stdout).unwrap()
    assert set(data["mcp_servers"]) == set(cli.SERVERS) and data["features"]["code_mode"]["direct_only_tool_namespaces"][0] == "mcp__pweh_case"


def test_cli_codex_write_project_dry_run_then_write(codex_iso, capsys):
    repo = codex_iso["repo"]
    assert cli.main(["mcp-config", "--client", "codex", "--write", "--dry-run", "--tools-env", codex_iso["tools_env"]]) == 0
    out = capsys.readouterr().out
    assert not (repo / ".codex").exists() and "+mcp_optional_startup_grace_ms = 15000" in out
    assert cli.main(["mcp-config", "--client", "codex", "--write", "--direct", "case", "--tools-env", codex_iso["tools_env"]]) == 0
    out = capsys.readouterr().out
    text = (repo / ".codex" / "config.toml").read_text(encoding="utf-8")
    assert f"작성: {repo}/.codex/config.toml (project)" in out and 'direct_only_tool_namespaces = [\n    "mcp__pweh_case",\n]' in text
    assert cli.main(["mcp-config", "--client", "codex", "--write", "--direct", "case", "--tools-env", codex_iso["tools_env"]]) == 0
    assert "변경 없음" in capsys.readouterr().out


def test_cli_codex_write_global_and_invalid_toml_refusal(codex_iso, tmp_path, monkeypatch, capsys):
    good, bad = tmp_path / "codex-good", tmp_path / "codex-bad"
    good.mkdir()
    bad.mkdir()
    (good / "config.toml").write_text('# 내 설정\nmodel = "m"\n\n[mcp_servers.notes]\ncommand = "n"\n', encoding="utf-8")
    (bad / "config.toml").write_text("[a]\nx = 1\n[a]\ny = 2\n", encoding="utf-8")
    base = ["mcp-config", "--client", "codex", "--write", "--scope", "global", "--tools-env", codex_iso["tools_env"]]
    assert cli.main([*base, "--codex-home", str(good), "--codex-home", str(bad)]) == 1
    err = capsys.readouterr().err
    assert "올바른 TOML" in err and "아무 파일도 쓰지 않았다" in err
    assert (good / "config.toml").read_text(encoding="utf-8").startswith("# 내 설정") and not list(good.glob("*.bak-pweh-*"))
    assert cli.main([*base, "--codex-home", str(good), "--dry-run"]) == 0
    assert "+[mcp_servers.pweh-case] # pweh-managed" in capsys.readouterr().out and not list(good.glob("*.bak-pweh-*"))
    assert cli.main([*base, "--codex-home", str(good), "--no-rea"]) == 0
    out = capsys.readouterr().out
    import tomlkit

    data = tomlkit.parse((good / "config.toml").read_text(encoding="utf-8")).unwrap()
    assert set(data["mcp_servers"]) == {"notes", *cli.SERVERS} and data["mcp_optional_startup_grace_ms"] == 15000
    assert "백업: " in out and len(list(good.glob("config.toml.bak-pweh-*"))) == 1
    # 찾은 홈이 없으면(codex 도 ~/.codex 도 없음) 쓰지 않고 1
    import shutil

    real_which = shutil.which
    monkeypatch.setattr(shutil, "which", lambda name, *a, **k: None if name == "codex" else real_which(name, *a, **k))
    assert cli.main(["mcp-config", "--client", "codex", "--write", "--scope", "global", "--tools-env", codex_iso["tools_env"]]) == 1
    assert "Codex 홈을 찾지 못했다" in capsys.readouterr().err and not (codex_iso["home"] / ".codex").exists()


def test_cli_codex_trust_non_tty_yes_and_check(codex_iso, tmp_path, capsys):
    import os

    import tomlkit

    home = tmp_path / "codex-home"
    home.mkdir()
    (home / "config.toml").write_text('model = "m"\n', encoding="utf-8")
    key = os.path.realpath(codex_iso["repo"])
    assert cli.main(["codex-trust", "--codex-home", str(home), "--check"]) == 1
    assert cli.main(["codex-trust", "--codex-home", str(home)]) == 0  # pytest 의 stdin 은 TTY 가 아니다 → 아무것도 하지 않음
    assert (home / "config.toml").read_text(encoding="utf-8") == 'model = "m"\n' and "--yes" in capsys.readouterr().out
    assert cli.main(["codex-trust", "--codex-home", str(home), "--dry-run"]) == 0
    assert f'+[projects."{key}"]' in capsys.readouterr().out and (home / "config.toml").read_text(encoding="utf-8") == 'model = "m"\n'
    assert cli.main(["codex-trust", "--codex-home", str(home), "--yes"]) == 0
    assert tomlkit.parse((home / "config.toml").read_text(encoding="utf-8")).unwrap() == {"model": "m", "projects": {key: {"trust_level": "trusted"}}}
    assert cli.main(["codex-trust", "--codex-home", str(home), "--check"]) == 0


def test_cli_mcp_check_json_real_pweh_case_and_failing(codex_iso, workspace, tmp_path, capsys):
    from pweh import clientcfg

    exe = REPO / ".venv" / "bin" / "pweh-case-mcp"
    if not exe.exists():
        pytest.skip("pweh-case-mcp 가 없다")
    bad = tmp_path / "bad-mcp"
    bad.write_text("#!/bin/sh\necho 'bad server' >&2\nexit 7\n")
    bad.chmod(0o755)
    case = {"command": str(exe), "args": [], "cwd": str(REPO), "env_vars": ["WSL_DISTRO_NAME"],
            "env": {"PWEH_CONFIG": str(workspace["config"]), "PWEH_CASES_DIR": str(workspace["cases_dir"]), "PWEH_STATE_DIR": str(workspace["state_dir"])}}
    proj = codex_iso["repo"] / ".codex" / "config.toml"
    proj.parent.mkdir()
    proj.write_text(clientcfg.render_project_config({"pweh-case": case, "pweh-uart": {"command": str(bad), "args": []}}, [], ["# 시험"]))
    assert cli.main(["mcp-check", "--client", "codex", "--json", "--timeout", "60"]) == 1
    rep = json.loads(capsys.readouterr().out)
    rows = {r["server"]: r for r in rep["clients"]["codex"]["servers"]}
    assert rep["ok"] is False and rep["clients"]["codex"]["source"] == str(proj)
    assert rows["pweh-case"]["ok"] is True and rows["pweh-case"]["tools"] > 10
    assert rows["pweh-uart"]["ok"] is False and "bad server" in " ".join(rows["pweh-uart"]["stderr_tail"])
    assert rows["pweh-esp"]["ok"] is None  # 설정에 없는 서버는 점검하지 않는다
    proj.write_text(clientcfg.render_project_config({"pweh-case": case}, [], ["# 시험"]))
    assert cli.main(["mcp-check", "--client", "codex", "--timeout", "60"]) == 0
    assert "결과: 1/1 정상" in capsys.readouterr().out


def test_doctor_codex_lines(codex_iso, tmp_path, monkeypatch, capsys):
    from pweh import clientcfg

    repo, home = codex_iso["repo"], codex_iso["home"]
    (home / ".codex").mkdir()
    profile = tmp_path / "c" / "Users" / "tester"
    (profile / ".codex").mkdir(parents=True)
    (profile / ".codex" / "config.toml").write_text("[desktop]\nrunCodexInWindowsSubsystemForLinux = false\n")
    monkeypatch.setattr(clientcfg, "windows_profile", lambda report=None: (profile, "시험"))
    (repo / "scripts").mkdir()  # REA 는 저장소의 런처로 등록된다 (생성값의 실행 파일이 있어야 '최신')
    shutil.copy2(REPO / "scripts" / "mcp-launch.sh", repo / "scripts" / "mcp-launch.sh")
    by = {c["check"]: c for c in cli.codex_doctor_checks()}
    assert by["codex:project-config"]["ok"] is False and by["codex:trust[cli]"]["ok"] is False
    assert by["codex:trust[desktop-wsl]"]["ok"] is None and "WSL 모드가 아님" in by["codex:trust[desktop-wsl]"]["detail"]
    assert "pweh mcp-check" in by["codex:mcp-check"]["hint"]
    assert cli.main(["mcp-config", "--client", "codex", "--write"]) == 0
    assert cli.main(["codex-trust", "--codex-home", str(home / ".codex"), "--yes"]) == 0
    capsys.readouterr()
    by = {c["check"]: c for c in cli.codex_doctor_checks()}
    assert by["codex:project-config"]["ok"] is True, by["codex:project-config"]
    assert by["codex:trust[cli]"]["ok"] is True


def test_codex_subcommands_parse_documented_forms():
    p = cli.build_parser()
    a = p.parse_args(["mcp-config", "--client", "codex", "--write", "--scope", "global", "--codex-home", "A", "--codex-home", "B",
                      "--dry-run", "--no-rea", "--direct", "case"])
    assert (a.scope, a.codex_home, a.dry_run, a.no_rea, a.direct) == ("global", ["A", "B"], True, True, "case")
    a = p.parse_args(["mcp-config", "--client", "codex"])  # 주지 않은 --direct·--no-rea 는 None (기존 프로젝트 설정의 값을 이어 쓴다)
    assert (a.scope, a.codex_home, a.dry_run, a.direct, a.write, a.no_rea) == ("project", None, False, None, False, None)
    assert p.parse_args(["mcp-config", "--client", "codex", "--rea"]).no_rea is False
    with pytest.raises(SystemExit):
        p.parse_args(["mcp-config", "--client", "codex", "--rea", "--no-rea"])
    assert p.parse_args(["mcp-check", "--optional", "rea", "--optional", "x"]).optional == ["rea", "x"]
    a = p.parse_args(["codex-trust", "--codex-home", "X", "--yes", "--dry-run", "--check"])
    assert (a.codex_home, a.yes, a.dry_run, a.check) == (["X"], True, True, True)
    a = p.parse_args(["mcp-check", "--client", "claude", "--deep", "--json", "--timeout", "5"])
    assert (a.client, a.deep, a.json, a.timeout) == ("claude", True, True, 5.0)
    assert p.parse_args(["mcp-check"]).client == "all"


def test_codex_config_never_stores_the_shell_path(codex_iso, tmp_path, monkeypatch, capsys):
    """리뷰 s9: 실행한 셸의 PATH(WSL 이면 Windows PATH 와 Windows 사용자 이름)를 미리 보기·diff·프로젝트 설정·사용자 설정 어디에도 남기지 않는다.
    REA 는 런처로 등록하고 어느 env.sh 를 불러올지만 env 에 고정한다 (Codex 는 환경을 비우고 띄운다 — 임시 HOME 인 --deep 에서도 같은 env.sh)."""
    fake_user = "FakeWinUser"
    monkeypatch.setenv("PATH", os.environ["PATH"] + f":/mnt/c/Users/{fake_user}/AppData/Local/Microsoft/WindowsApps")
    env_sh = tmp_path / "fake-tools-env.sh"
    env_sh.write_text('export PWEH_TOOLS_DIR="/opt/fake-tools"\nexport PATH="/opt/fake-tools/bin:$PATH"\n', encoding="utf-8")
    home = tmp_path / "codex-home"
    home.mkdir()
    base = ["mcp-config", "--client", "codex", "--tools-env", str(env_sh)]
    assert cli.main(base) == 0
    assert cli.main([*base, "--write", "--dry-run", "--codex-home", str(home)]) == 0
    assert cli.main([*base, "--write", "--codex-home", str(home)]) == 0
    assert cli.main([*base, "--write", "--scope", "global", "--codex-home", str(home)]) == 0
    printed = capsys.readouterr()
    proj = (codex_iso["repo"] / ".codex" / "config.toml").read_text(encoding="utf-8")
    user = (home / "config.toml").read_text(encoding="utf-8")
    for text in (printed.out, printed.err, proj, user):
        assert fake_user not in text and "/mnt/c/Users/" not in text
    import tomlkit

    rea = tomlkit.parse(proj).unwrap()["mcp_servers"]["rea"]
    assert rea["command"] == str(codex_iso["repo"] / "scripts" / "mcp-launch.sh") and rea["args"] == ["rea"]
    assert rea["env"]["PWEH_TOOLS_ENV"] == str(env_sh) and "PATH" not in rea["env"]
    assert tomlkit.parse(proj).unwrap()["mcp_servers"]["pweh-case"]["env"]["PWEH_TOOLS_DIR"] == "/opt/fake-tools"
    # PATH 가 달라져도(다른 셸) 다시 쓰지 않는다 — 사용자 설정이 매번 바뀌고 백업이 쌓이지 않게
    monkeypatch.setenv("PATH", "/usr/bin:/bin:/mnt/c/Users/Other/bin")
    assert cli.main([*base, "--write", "--scope", "global", "--codex-home", str(home)]) == 0
    assert "변경 없음" in capsys.readouterr().out and list(home.glob("config.toml.bak-pweh-*")) == []  # 새로 만든 파일 — 백업 없음


def test_codex_write_reuses_recorded_options(codex_iso, capsys):
    """주지 않은 --direct·--no-rea 는 기존 프로젝트 설정(# pweh-options)의 값을 이어 쓴다 (설치 스크립트를 다시 돌려도 기본값으로 돌아가지 않음).
    바꾸려면 직접 준다: --direct all, --rea."""
    import tomlkit

    path = codex_iso["repo"] / ".codex" / "config.toml"
    te = ["--tools-env", codex_iso["tools_env"]]
    assert cli.main(["mcp-config", "--client", "codex", "--write", "--direct", "case", "--no-rea", *te]) == 0
    first = path.read_bytes()
    capsys.readouterr()
    assert cli.main(["mcp-config", "--client", "codex", "--write", "--dry-run", *te]) == 0
    out = capsys.readouterr()
    assert "변경 없음" in out.out and "이어 씀: --direct case --no-rea" in out.err
    assert cli.main(["mcp-config", "--client", "codex", "--write", *te]) == 0
    assert path.read_bytes() == first
    data = tomlkit.parse(path.read_text(encoding="utf-8")).unwrap()
    assert "rea" not in data["mcp_servers"] and data["features"]["code_mode"]["direct_only_tool_namespaces"] == ["mcp__pweh_case"]
    assert cli.main(["mcp-config", "--client", "codex", "--write", "--rea", "--direct", "all", *te]) == 0
    data = tomlkit.parse(path.read_text(encoding="utf-8")).unwrap()
    assert "rea" in data["mcp_servers"] and len(data["features"]["code_mode"]["direct_only_tool_namespaces"]) == len(cli.SERVERS)
    assert not list(path.parent.glob("config.toml.bak-pweh-*"))  # pweh 가 쓴 그대로인 파일이라 백업하지 않는다


def _fake_venv(root: Path, *, scripts: bool) -> Path:
    """심볼릭 링크 python 이 있는 가상환경 모양 (install.sh --venv DIR). scripts 면 PWEH 콘솔 스크립트도 둔다."""
    venv = root / "venv-alt"
    (venv / "bin").mkdir(parents=True)
    (venv / "bin" / "python").symlink_to(os.path.realpath(sys.executable))
    if scripts:
        for script, _d in cli.SERVERS.values():
            p = venv / "bin" / script
            p.write_text("#!/bin/sh\nexit 0\n")
            p.chmod(0o755)
    return venv


def test_codex_commands_come_from_the_running_venv_not_the_resolved_python(codex_iso, tmp_path, monkeypatch, capsys):
    """install.sh --venv DIR: DIR/bin/python 은 /usr/bin/python3 을 가리키는 링크다. 풀지 않고 DIR/bin 의 서버를 쓴다
    (예전: /usr/bin/pweh-*-mcp, 또는 낡은 <저장소>/.venv/bin)."""
    venv = _fake_venv(tmp_path, scripts=True)
    stale = codex_iso["repo"] / ".venv" / "bin"
    stale.mkdir(parents=True)
    for script, _d in cli.SERVERS.values():
        (stale / script).write_text("#!/bin/sh\n")
    monkeypatch.setattr(sys, "executable", str(venv / "bin" / "python"))
    bindir, missing = cli.console_bindir()
    assert bindir == venv / "bin" and missing == []
    servers = cli.build_mcp_servers(include_rea=False, tools_env=codex_iso["tools_env"])
    assert {s["command"] for s in servers.values()} == {str(venv / "bin" / script) for script, _d in cli.SERVERS.values()}


def test_codex_write_refuses_when_server_executables_are_missing(codex_iso, tmp_path, monkeypatch, capsys):
    """서버 실행 파일이 어디에도 없으면(pweh 를 설치하지 않은 가상환경) --write 는 쓰지 않고 1. 미리 보기·--dry-run 은 경고만."""
    venv = _fake_venv(tmp_path, scripts=False)
    monkeypatch.setattr(sys, "executable", str(venv / "bin" / "python"))
    monkeypatch.setattr(cli, "_bindir_candidates", lambda: [venv / "bin", codex_iso["repo"] / ".venv" / "bin"])
    te = ["--tools-env", codex_iso["tools_env"]]
    assert cli.main(["mcp-config", "--client", "codex", "--write", *te]) == 1
    err = capsys.readouterr().err
    assert "실행 파일이 없다" in err and str(venv / "bin" / "pweh-case-mcp") in err and "아무것도 쓰지 않았다" in err
    assert not (codex_iso["repo"] / ".codex").exists()
    assert cli.main(["mcp-config", "--client", "codex", "--write", "--dry-run", *te]) == 0
    assert "경고: PWEH 서버 실행 파일이 없다" in capsys.readouterr().err
