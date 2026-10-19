"""scripts/install.sh (원클릭 설치) 와 외부 도구 위치 규칙(pweh.toolsdir) 테스트.

네트워크를 쓰지 않는다. 실제 설치는 사람이 돌리거나 깨끗한 컨테이너에서 검증한다 (docs/mcp-setup.md §1).
"""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
SCRIPT = REPO / "scripts" / "install.sh"
COMPONENTS = ["python", "sigrok", "openocd", "squashfs", "uboot", "zig", "jdk", "ghidra", "unblob", "extractors", "erofs", "binwalk", "rea", "esptool"]


def _run(*args: str, env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
    e = dict(os.environ)
    e.update(env or {})
    return subprocess.run(["bash", str(SCRIPT), *args], capture_output=True, text=True, env=e, timeout=120)


def _wsl_interop() -> bool:
    """install.sh 의 wsl_interop() 과 같은 판정: binfmt_misc 의 WSLInterop* 등록이 켜져 있다."""
    for f in Path("/proc/sys/fs/binfmt_misc").glob("WSLInterop*"):
        try:
            if f.read_text().split("\n", 1)[0] == "enabled":
                return True
        except OSError:
            continue
    return False


def _fake_esptool(path: Path, version: str, crlf: bool = False) -> None:
    """`esptool version` 처럼 두 줄("esptool vX" / "X")을 출력하는 가짜 실행 파일. Windows 판은 CRLF 로 출력한다."""
    nl = "\\r\\n" if crlf else "\\n"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(f"#!/bin/sh\nprintf 'esptool v{version}{nl}{version}{nl}'\n")
    path.chmod(0o755)


def test_script_syntax_and_executable():
    assert os.access(SCRIPT, os.X_OK)
    assert subprocess.run(["bash", "-n", str(SCRIPT)]).returncode == 0


def test_list_names_every_component_and_creates_nothing(tmp_path):
    prefix = tmp_path / "tools"
    r = _run("--list", "--prefix", str(prefix))
    assert r.returncode == 0, r.stderr
    names = [line.split()[0] for line in r.stdout.splitlines() if line.strip()]
    assert names == COMPONENTS
    assert "[minimal]" in r.stdout and "[선택]" in r.stdout
    esptool = next(line for line in r.stdout.splitlines() if line.split()[:1] == ["esptool"])
    assert "[선택]" in esptool and "[minimal]" not in esptool and "방법 A" in esptool
    assert not prefix.exists()  # --list 는 디렉터리를 만들지 않는다


def test_help_and_bad_arguments():
    r = _run("--help")
    assert r.returncode == 0 and "--seed" in r.stdout and "--no-link" in r.stdout
    assert "지원: Linux x86_64" in r.stdout and "set -Eeuo" not in r.stdout  # 머리 주석 전체, 코드는 빼고
    assert _run("--prefix").returncode == 2  # 값이 필요한 옵션
    assert _run("--no-such-option").returncode == 2
    bad = _run("--only", "ghidra,nonexistent", "--list")
    assert bad.returncode == 2 and "nonexistent" in bad.stderr


def test_check_on_empty_prefix_reports_missing_and_installs_nothing(tmp_path):
    prefix = tmp_path / "tools"
    r = _run("--check", "--prefix", str(prefix), "--venv", str(tmp_path / "novenv"), "--no-link")
    assert r.returncode == 1, r.stdout + r.stderr
    for c in COMPONENTS:
        if c == "rea":
            continue  # 이미 설치된 REA(~/.local/bin/rea 등)가 있으면 ✓ 일 수 있다
        assert f"✗ {c}" in r.stdout, (c, r.stdout)
    assert not (prefix / "env.sh").exists()
    assert not any((prefix / d).exists() for d in ("sigrok", "openocd", "ghidra", "jdk", "zig", "unblob"))
    assert not (tmp_path / "novenv").exists()
    assert not (REPO / ".pweh" / "tools-env.path").exists() or (REPO / ".pweh" / "tools-env.path").read_text().strip() != str(prefix / "env.sh")


def test_minimal_selects_only_minimal_components(tmp_path):
    r = _run("--check", "--minimal", "--prefix", str(tmp_path / "t"), "--venv", str(tmp_path / "v"), "--no-link")
    shown = [line.split()[1] for line in r.stdout.splitlines() if line.strip().startswith(("✓", "✗"))]
    assert shown == ["python", "sigrok", "openocd", "squashfs", "uboot"]


def test_pinned_artifacts_have_sha256():
    text = SCRIPT.read_text(encoding="utf-8")
    for var in ("OPENOCD", "ZIG", "JDK", "GHIDRA", "SASQUATCH", "NODE", "UNBLOB", "PIP", "RUSTUP", "ESPTOOL", "ESPTOOL_WIN"):
        line = next(ln for ln in text.splitlines() if ln.startswith(f"{var}_SHA="))
        value = line.split("=", 1)[1].split()[0]
        assert len(value) == 64 and all(c in "0123456789abcdef" for c in value), line
        assert f'fetch "${var}_URL"' in text, f"{var}_URL 을 해시와 함께 받는 곳이 없음"
    # 해시 없이 받아 실행하는 부트스트랩·떠다니는 버전을 쓰지 않는다 (주석은 빼고 코드만 본다)
    code = "\n".join(ln.split("   #")[0] for ln in text.splitlines() if not ln.lstrip().startswith("#"))
    assert "get-pip" not in code and "bootstrap.pypa.io" not in code
    assert "--default-toolchain stable" not in code and "rustup/dist/" not in code
    assert "rea setup" not in text.replace("`rea setup` 은 실행하지 않는다", "")
    assert "sudo " not in "\n".join(ln for ln in text.splitlines() if not ln.lstrip().startswith("#") and "관리자" not in ln)


def test_refuses_unrelated_or_unsafe_prefix(tmp_path):
    """다른 용도의 비어 있지 않은 디렉터리나 따옴표가 든 경로에는 아무것도 만들지 않고 거부한다 (네트워크 전에 끝남)."""
    other = tmp_path / "home-like"
    other.mkdir()
    (other / "notes.txt").write_text("keep")
    r = _run("--only", "zig", "--prefix", str(other), "--venv", str(tmp_path / "v"), "--no-link")
    assert r.returncode == 2 and "pweh-tools" in r.stderr, r.stderr
    assert sorted(x.name for x in other.iterdir()) == ["notes.txt"]

    quoted = tmp_path / "it's"
    r = _run("--only", "zig", "--prefix", str(quoted), "--venv", str(tmp_path / "v"), "--no-link")
    assert r.returncode == 2 and not quoted.exists(), r.stderr


def test_esptool_optional_linux_and_windows_builds(tmp_path):
    """esptool 은 선택 구성요소다. Linux 판은 항상, Windows 판(방법 A)은 WSL interop 에서만 확인하고 env.sh 에 따로 export 한다.

    가짜 실행 파일로 확인하므로 네트워크 없이 돈다 (이미 설치된 것으로 보이면 설치 모드도 내려받지 않는다).
    WSL 에서도 가짜 esptool.exe 는 MZ 실행 파일이 아니라 interop 을 거치지 않고 셸 스크립트로 실행된다.
    """
    prefix = tmp_path / "tools"
    common = ("--prefix", str(prefix), "--venv", str(tmp_path / "v"), "--no-link")
    r = _run("--check", "--only", "esptool", *common)
    assert r.returncode == 0 and "✗ esptool" in r.stdout, r.stdout + r.stderr  # 없어도 --check 는 실패가 아니다
    assert not prefix.exists()

    linux = prefix / "bin" / "esptool"
    win = prefix / "esptool-win" / "esptool-windows-amd64" / "esptool.exe"
    _fake_esptool(linux, "5.4.0")
    r = _run("--check", "--only", "esptool", *common)
    assert ("✓ esptool" in r.stdout) == (not _wsl_interop()), r.stdout  # WSL interop 이면 Windows 판도 있어야 한다

    _fake_esptool(win, "5.4.0", crlf=True)
    r = _run("--check", "--only", "esptool", *common)
    assert r.returncode == 0 and "✓ esptool  esptool 5.4.0" in r.stdout, r.stdout + r.stderr

    (prefix / ".state").mkdir()  # 설치 모드가 pweh-tools 디렉터리로 알아보도록
    r = _run("--only", "esptool", *common)
    assert r.returncode == 0 and "esptool: 이미 설치됨" in r.stdout, r.stdout + r.stderr
    env = (prefix / "env.sh").read_text()
    assert f"export PWEH_ESPTOOL='{linux}'" in env
    assert (f"export PWEH_ESPTOOL_WIN='{win}'" in env) == _wsl_interop(), env

    _fake_esptool(linux, "4.8.1")  # 고정 버전이 아니면 설치된 것으로 보지 않는다
    r = _run("--check", "--only", "esptool", *common)
    assert r.returncode == 0 and "✗ esptool" in r.stdout, r.stdout


# --- pweh.toolsdir ----------------------------------------------------------

def test_toolsdir_precedence(tmp_path, monkeypatch):
    from pweh import toolsdir

    monkeypatch.delenv("PWEH_TOOLS_ENV", raising=False)
    monkeypatch.delenv("PWEH_TOOLS_DIR", raising=False)
    monkeypatch.setattr(toolsdir, "POINTER", tmp_path / "no-pointer")
    assert toolsdir.tools_env() == Path.home() / "pweh-tools" / "env.sh"
    assert toolsdir.tools_dir() == Path.home() / "pweh-tools"

    pointer = tmp_path / "tools-env.path"
    pointer.write_text(str(tmp_path / "alt" / "env.sh") + "\n")
    monkeypatch.setattr(toolsdir, "POINTER", pointer)
    assert toolsdir.tools_env() == Path.home() / "pweh-tools" / "env.sh"  # 가리키는 env.sh 가 없으면(지운 시험 위치) 무시
    (tmp_path / "alt").mkdir()
    (tmp_path / "alt" / "env.sh").write_text("")
    assert toolsdir.tools_env() == tmp_path / "alt" / "env.sh"
    assert toolsdir.tools_dir() == tmp_path / "alt"

    monkeypatch.setenv("PWEH_TOOLS_DIR", str(tmp_path / "dir"))
    assert toolsdir.tools_dir() == tmp_path / "dir"
    assert toolsdir.tools_env() == tmp_path / "dir" / "env.sh"

    monkeypatch.setenv("PWEH_TOOLS_ENV", str(tmp_path / "explicit.sh"))
    assert toolsdir.tools_env() == tmp_path / "explicit.sh"


@pytest.mark.parametrize("var", ["PWEH_TOOLS_ENV", "PWEH_TOOLS_DIR"])
def test_launcher_follows_tools_location(tmp_path, var):
    """scripts/mcp-launch.sh 도 같은 규칙으로 env.sh 를 찾는다 (env.sh 에서 표시를 남기고 알 수 없는 서버 이름으로 종료)."""
    alt = tmp_path / "alt"
    alt.mkdir()
    marker = tmp_path / "sourced"
    (alt / "env.sh").write_text(f"touch '{marker}'\n")
    value = str(alt / "env.sh") if var == "PWEH_TOOLS_ENV" else str(alt)
    env = {k: v for k, v in os.environ.items() if k not in ("PWEH_TOOLS_ENV", "PWEH_TOOLS_DIR")}
    env[var] = value
    r = subprocess.run(["bash", str(REPO / "scripts" / "mcp-launch.sh"), "no-such-server"], capture_output=True, text=True, env=env, timeout=30)
    assert r.returncode == 2 and marker.exists(), r.stderr
