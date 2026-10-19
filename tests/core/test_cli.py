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

