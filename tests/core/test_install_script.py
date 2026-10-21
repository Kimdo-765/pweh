"""scripts/install.sh (원클릭 설치) 와 외부 도구 위치 규칙(pweh.toolsdir) 테스트.

네트워크를 쓰지 않는다. 실제 설치는 사람이 돌리거나 깨끗한 컨테이너에서 검증한다 (docs/mcp-setup.md §1).
단계(mcp, skills, verify)는 임시 디렉터리에 복사한 저장소 골격과 인자를 기록하는 가짜 pweh 로 시험한다:
실제 pweh·Codex 홈·~/.claude* 는 건드리지 않고, HOME·CODEX_HOME 도 임시 디렉터리다.
"""

from __future__ import annotations

import json
import os
import pty
import re
import select
import shutil
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
SCRIPT = REPO / "scripts" / "install.sh"
COMPONENTS = ["python", "sigrok", "openocd", "squashfs", "uboot", "zig", "jdk", "ghidra", "unblob", "extractors", "erofs", "binwalk", "rea", "esptool",
              "qemu_esp", "simavr", "tesseract", "zbar"]
STEPS = ["mcp", "skills", "verify"]


def _run(*args: str, env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
    e = dict(os.environ)
    e.update(env or {})
    return subprocess.run(["bash", str(SCRIPT), *args], capture_output=True, text=True, env=e, timeout=120, stdin=subprocess.DEVNULL)


def _wsl_interop() -> bool:
    """install.sh 의 wsl_interop() 과 같은 판정(pweh.hostenv 의 감지 규칙에서 smoke 와 hostenv.disable 을 뺀 것): 컨테이너가 아니고,
    WSLInterop 또는 WSLInterop-late 첫 줄이 enabled 이고, /init 이 있고, 고정 위치의 wslpath 로 `wslpath -w /` 가 성공한다."""
    if Path("/.dockerenv").exists() or Path("/run/.containerenv").exists() or os.environ.get("container"):
        return False
    try:
        virt = subprocess.run(["systemd-detect-virt", "-c"], capture_output=True, text=True, timeout=10).stdout.strip()
    except (OSError, subprocess.SubprocessError):
        virt = ""
    if virt not in ("", "none", "wsl") or not Path("/init").exists():
        return False
    enabled = False
    for name in ("WSLInterop", "WSLInterop-late"):
        try:
            enabled = enabled or (Path("/proc/sys/fs/binfmt_misc") / name).read_text().split("\n", 1)[0] == "enabled"
        except OSError:
            continue
    wp = next((p for p in ("/usr/bin/wslpath", "/bin/wslpath") if os.access(p, os.X_OK)), None)
    if not enabled or not wp:
        return False
    try:
        return subprocess.run([wp, "-w", "/"], capture_output=True, timeout=10).returncode == 0
    except (OSError, subprocess.SubprocessError):
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
    assert names == COMPONENTS + STEPS  # 단계도 --only/--skip 으로 고르므로 목록에 보인다 (구성요소 다음, 실행 순서대로)
    assert "[minimal]" in r.stdout and "[선택]" in r.stdout
    esptool = next(line for line in r.stdout.splitlines() if line.split()[:1] == ["esptool"])
    assert "[선택]" in esptool and "[minimal]" not in esptool and "방법 A" in esptool
    for emu in ("qemu_esp", "simavr", "tesseract", "zbar"):  # 선택 구성요소, --minimal 밖 (DESC 가 없으면 set -u 로 --list 가 멈춘다)
        line = next(ln for ln in r.stdout.splitlines() if ln.split()[:1] == [emu])
        assert line.endswith("[선택]") and "[minimal]" not in line, line
    for step in STEPS:
        line = next(ln for ln in r.stdout.splitlines() if ln.split()[:1] == [step])
        assert line.endswith("[단계]") and "[minimal]" not in line, line
    assert not prefix.exists()  # --list 는 디렉터리를 만들지 않는다


def test_help_and_bad_arguments():
    r = _run("--help")
    assert r.returncode == 0 and "--seed" in r.stdout and "--no-link" in r.stdout
    assert "지원: Linux x86_64" in r.stdout and "set -Eeuo" not in r.stdout  # 머리 주석 전체, 코드는 빼고
    for opt in ("--only mcp,skills,verify", "--dry-run", "--no-mcp", "--no-verify", "--codex-trust", "--no-codex-trust",
                "--codex-global", "--codex-home DIR", "--cursor", "pweh mcp-check", "config.toml.bak-pweh-"):
        assert opt in r.stdout, opt
    assert _run("--prefix").returncode == 2  # 값이 필요한 옵션
    assert _run("--codex-home").returncode == 2
    assert _run("--no-such-option").returncode == 2
    bad = _run("--only", "ghidra,nonexistent", "--list")
    assert bad.returncode == 2 and "nonexistent" in bad.stderr
    both = _run("--codex-trust", "--no-codex-trust", "--list")  # 동의와 거절을 함께 줄 수 없다
    assert both.returncode == 2 and "함께 쓸 수 없습니다" in both.stderr
    assert _run("--codex-trust", "--codex-trust", "--list").returncode == 0


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
    for var in ("OPENOCD", "ZIG", "JDK", "GHIDRA", "SASQUATCH", "NODE", "UNBLOB", "PIP", "RUSTUP", "ESPTOOL", "ESPTOOL_WIN", "QEMU_XTENSA", "QEMU_RISCV32"):
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


# --- 펌웨어 에뮬레이션 구성요소 (qemu_esp, simavr) --------------------------------

QEMU_VERSION_LINE = "QEMU emulator version 9.2.2 (esp_develop_9.2.2_20260417)"
SIMAVR_COMMIT = "5b08da60497f7564f50941f74a549fe2851db030"
AVR_RUN_SRC = REPO / "native" / "emu" / "pweh_avr_run.c"


def _shell_value(text: str, name: str) -> str:
    m = re.search(rf'^{name}="?([^"\n]*?)"?(?:\s+#.*)?$', text, re.M)
    assert m, name
    return m.group(1)


def _emu_code() -> str:
    """install.sh 의 qemu_esp·simavr 함수 부분(주석 줄 제외)."""
    text = SCRIPT.read_text(encoding="utf-8")
    start = text.index("# 펌웨어 에뮬레이션 (pweh-emu, mcp-servers/emu-mcp)")
    section = text[start:text.index("# env.sh", start)]
    return "\n".join(ln.split("   #")[0] for ln in section.splitlines() if not ln.lstrip().startswith("#"))


def _avr_run_source_version() -> str:
    m = re.search(r'^#define PWEH_AVR_RUN_VERSION "([^"]+)"', AVR_RUN_SRC.read_text(encoding="utf-8"), re.M)
    assert m
    return m.group(1)


def test_emulation_components_are_optional_and_pinned():
    text = SCRIPT.read_text(encoding="utf-8")
    assert _shell_value(text, "ALL_COMPONENTS").split()[13:16] == ["esptool", "qemu_esp", "simavr"]
    assert {"qemu_esp", "simavr"} <= set(_shell_value(text, "OPTIONAL_COMPONENTS").split())
    assert not {"qemu_esp", "simavr"} & set(_shell_value(text, "MINIMAL_COMPONENTS").split())
    assert re.search(r"^\s*\[qemu_esp\]=", text, re.M) and re.search(r"^\s*\[simavr\]=", text, re.M)   # set -u: DESC 가 꼭 있어야 한다
    # QEMU: 정확한 릴리스 asset 만 (sha256 은 test_pinned_artifacts_have_sha256)
    assert _shell_value(text, "QEMU_ESP_TAG") == "esp-develop-9.2.2-20260417"
    assert _shell_value(text, "QEMU_ESP_VER") == "esp_develop_9.2.2_20260417"
    for arch in ("XTENSA", "RISCV32"):
        assert _shell_value(text, f"QEMU_{arch}_URL").startswith("https://github.com/espressif/qemu/releases/download/${QEMU_ESP_TAG}/")
    # simavr: erofs 처럼 커밋 고정 (해시를 고정해 받는 목록이 아니다)
    assert _shell_value(text, "SIMAVR_COMMIT") == SIMAVR_COMMIT
    assert _shell_value(text, "SIMAVR_GIT") == "https://github.com/buserror/simavr.git"
    assert "SIMAVR_SHA" not in text and 'fetch "$SIMAVR' not in text
    code = _emu_code()
    assert 'git -C "$src" fetch -q --depth 1 "$SIMAVR_GIT" "$SIMAVR_COMMIT"' in code
    assert '[ "$(git -C "$src" rev-parse HEAD)" = "$SIMAVR_COMMIT" ]' in code
    assert "checkout -q FETCH_HEAD" in code


def test_emulation_components_have_no_private_libraries_links_or_risky_build_flags():
    text = SCRIPT.read_text(encoding="utf-8")
    code = _emu_code()
    # 런타임 라이브러리를 개인 경로에 받지 않는다 (관리자 안내만): LD_LIBRARY_PATH 배관·래퍼·배포판 패키지 풀기 없음
    assert "PWEH_QEMU_ESP_LIBDIR" not in text
    assert not re.search(r"LD_LIBRARY_PATH=|export LD_LIBRARY_PATH|make_wrapper|deb_fetch_extract", code)
    assert "libgcrypt20 libglib2.0-0 libpixman-1-0 libsdl2-2.0-0 libslirp0" in code and "ldd" in code
    # 공유 bin 디렉터리에 링크하지 않는다 (서버는 env.sh 의 절대 경로만)
    assert not re.search(r"\bln\s", code)
    # 검사는 설정 파일·기본 장치 없이, 시간 제한·터미널 입력 없이
    assert 'timeout 20 "$1" -no-user-config -nodefaults -version </dev/null' in code
    # simavr: 라이브러리만(run_avr 없음), libelf·libdwarf 끔, V=1·-DNDEBUG 없음, -Wl,--wrap 없음 (GDB 는 소스의 빈 함수)
    assert "C_LIBELF= LD_LIBELF= C_LIBDWARF= LD_LIBDWARF=" in code
    assert not re.search(r"\bV=1\b|-DNDEBUG|--wrap|run_avr|make install", code)
    makes = [ln.strip() for ln in code.splitlines() if ln.strip().startswith("make -C")]
    assert makes and all(ln.endswith(("obj config", '"$obj/libsimavr.a"')) for ln in makes), makes
    assert 'ZIG_GLOBAL_CACHE_DIR=' in code and "$PREFIX/_build/zig-cache" in code   # ~/.cache/zig 를 쓰지 않는다
    assert 'mv -f "$out" "$AVR_RUN"' in code   # 임시 이름으로 빌드·확인한 뒤 바꾼다
    for name in ("socket", "bind", "listen", "accept", "connect"):
        assert name in code   # 빌드 직후·--check 의 소켓 함수 검사
    # env.sh: 확인을 통과한 절대 경로만
    assert "export PWEH_QEMU_XTENSA='$QEMU_XTENSA_BIN'" in text and "export PWEH_QEMU_RISCV32='$QEMU_RISCV32_BIN'" in text
    assert "export PWEH_AVR_RUN='$AVR_RUN'" in text


def _fake_qemu(path: Path, version_line: str) -> None:
    """설정 파일·기본 장치 없이 -version 을 물을 때만 버전을 내는 가짜 QEMU (검사가 정확히 그 인자로 부르는지도 확인)."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text('#!/bin/sh\n[ "$*" = "-no-user-config -nodefaults -version" ] || exit 9\n'
                    f"printf '%s\\nCopyright (c) 2003-2024 Fabrice Bellard and the QEMU Project developers\\n' '{version_line}'\n")
    path.chmod(0o755)


def test_qemu_esp_check_install_and_env(tmp_path):
    """qemu_esp 는 선택 구성요소다. 두 실행 파일이 고정 버전일 때만 설치된 것으로 보고 env.sh 에 절대 경로로만 알린다 (네트워크 없음)."""
    prefix = tmp_path / "tools"
    common = ("--prefix", str(prefix), "--venv", str(tmp_path / "v"), "--no-link")
    r = _run("--check", "--only", "qemu_esp", *common)
    assert r.returncode == 0 and "✗ qemu_esp" in r.stdout, r.stdout + r.stderr  # 없어도 --check 는 실패가 아니다
    assert not prefix.exists()

    xt = prefix / "qemu-esp" / "xtensa" / "qemu" / "bin" / "qemu-system-xtensa"
    rv = prefix / "qemu-esp" / "riscv32" / "qemu" / "bin" / "qemu-system-riscv32"
    _fake_qemu(xt, QEMU_VERSION_LINE)
    assert "✗ qemu_esp" in _run("--check", "--only", "qemu_esp", *common).stdout   # 둘 다 있어야 한다
    _fake_qemu(rv, QEMU_VERSION_LINE)
    r = _run("--check", "--only", "qemu_esp", *common)
    assert r.returncode == 0 and "✓ qemu_esp  Espressif QEMU 9.2.2 (esp_develop_9.2.2_20260417)" in r.stdout, r.stdout + r.stderr

    (prefix / ".state").mkdir()  # 설치 모드가 pweh-tools 디렉터리로 알아보도록
    r = _run("--only", "qemu_esp", *common)
    assert r.returncode == 0 and "qemu_esp: 이미 설치됨" in r.stdout, r.stdout + r.stderr
    env = (prefix / "env.sh").read_text()
    assert f"export PWEH_QEMU_XTENSA='{xt}'" in env and f"export PWEH_QEMU_RISCV32='{rv}'" in env
    assert str(prefix / "qemu-esp") not in env.split("export PATH")[0]   # PATH 에는 넣지 않는다
    assert "LD_LIBRARY_PATH=" not in env and "PWEH_AVR_RUN" not in env
    assert not (prefix / "bin" / "qemu-system-xtensa").exists()

    _fake_qemu(rv, "QEMU emulator version 9.2.2 (esp_develop_9.2.2_20250101)")   # 다른 빌드는 받지 않는다
    assert "✗ qemu_esp" in _run("--check", "--only", "qemu_esp", *common).stdout


def _fake_runner(tmp_path: Path, out: Path, version_line: str, *, socket: bool = False) -> None:
    """--version 만 아는 가짜 pweh_avr_run (ELF — 설치 스크립트가 nm 으로 소켓 함수를 검사하므로 셸 스크립트로는 안 된다)."""
    src = tmp_path / "fake_runner.c"
    use = "if (argc > 99) return socket(2, 1, 0);" if socket else ""
    src.write_text("#include <stdio.h>\n#include <string.h>\n#include <sys/socket.h>\n"
                   "int main(int argc, char **argv) {\n"
                   f'  {use}\n  if (argc == 2 && !strcmp(argv[1], "--version")) {{ puts("{version_line}"); return 0; }}\n'
                   "  return 2;\n}\n")
    out.parent.mkdir(parents=True, exist_ok=True)
    subprocess.run(["cc", "-O0", str(src), "-o", str(out)], check=True, capture_output=True, timeout=120)


@pytest.mark.skipif(not (shutil.which("cc") and shutil.which("nm")), reason="가짜 실행기를 만들 cc 와 검사할 nm 이 필요")
def test_simavr_check_requires_source_version_commit_and_no_sockets(tmp_path):
    """simavr 는 선택 구성요소다. pweh_avr_run --version 이 저장소 소스의 PWEH_AVR_RUN_VERSION 과 고정 simavr 커밋을 보이고
    소켓 함수가 링크되지 않았을 때만 설치된 것으로 본다 (아니면 다시 빌드). 네트워크·빌드 없이 가짜 ELF 로 확인한다."""
    prefix = tmp_path / "tools"
    common = ("--prefix", str(prefix), "--venv", str(tmp_path / "v"), "--no-link")
    runner = prefix / "simavr" / "bin" / "pweh_avr_run"
    good = f"pweh_avr_run {_avr_run_source_version()} simavr {SIMAVR_COMMIT}"
    r = _run("--check", "--only", "simavr", *common)
    assert r.returncode == 0 and "✗ simavr" in r.stdout, r.stdout + r.stderr

    _fake_runner(tmp_path, runner, good)
    r = _run("--check", "--only", "simavr", *common)
    assert r.returncode == 0 and f"✓ simavr  {good}" in r.stdout, r.stdout + r.stderr
    (prefix / ".state").mkdir()
    r = _run("--only", "simavr", *common)
    assert r.returncode == 0 and "simavr: 이미 설치됨" in r.stdout, r.stdout + r.stderr
    env = (prefix / "env.sh").read_text()
    assert f"export PWEH_AVR_RUN='{runner}'" in env and str(prefix / "simavr") not in env.split("export PATH")[0]

    for line, sock in ((f"pweh_avr_run 0.0-old simavr {SIMAVR_COMMIT}", False),   # 저장소 소스가 바뀌면 다시 빌드
                       (f"pweh_avr_run {_avr_run_source_version()} simavr {'0' * 40}", False),   # 다른 simavr 커밋
                       (good, True)):                                                         # GDB 서버 코드(소켓 함수)
        _fake_runner(tmp_path, runner, line, socket=sock)
        assert "✗ simavr" in _run("--check", "--only", "simavr", *common).stdout, (line, sock)
    runner.write_text(f"#!/bin/sh\necho '{good}'\n")   # 기호 표를 읽을 수 없는 파일은 확인하지 못한 것으로 본다
    assert "✗ simavr" in _run("--check", "--only", "simavr", *common).stdout


# --- 단계: mcp, skills, verify (가짜 pweh) ----------------------------------

# 가짜 pweh: 받은 인자와 표준 입력이 터미널인지 기록하고 STUB_* 환경변수대로 흉내 낸다. 시험의 임시 디렉터리만 쓴다.
# 설정을 쓸 때는 pweh 처럼 있던 파일을 <이름>.bak-pweh-<UTC 시각> 으로 백업하고, 쓴 파일과 백업을 "작성:"·"백업:" 으로 알린다.
STUB = r'''#!@PYTHON@
import json
import os
import shutil
import sys
import time
from pathlib import Path

args = sys.argv[1:]
env = os.environ
with open(env["STUB_LOG"], "a", encoding="utf-8") as f:
    f.write(json.dumps({"argv": args, "stdin_tty": os.isatty(0), "pweh_config": env.get("PWEH_CONFIG"), "cwd": os.getcwd()}) + "\n")
repo = Path(env["STUB_REPO"])
state = Path(env["STUB_STATE"])
cmd = args[0] if args else ""
if cmd in env.get("STUB_UNSUPPORTED", "").split(","):
    print(f"usage: pweh ...\npweh: error: argument cmd: invalid choice: '{cmd}'", file=sys.stderr)
    sys.exit(2)


def opt(name):
    return args[args.index(name) + 1] if name in args else None


def homes():
    hs = [args[i + 1] for i, a in enumerate(args) if a == "--codex-home"]
    if not hs and env.get("CODEX_HOME"):
        hs = [env["CODEX_HOME"]]
    return [Path(h) for h in hs]


def edit(cfg, text):
    real = Path(os.path.realpath(cfg)) if cfg.is_symlink() else cfg  # pweh 처럼 링크가 가리키는 파일을 백업하고 고친다
    real.parent.mkdir(parents=True, exist_ok=True)
    old = real.read_text() if real.exists() else ""
    if real.exists() and env.get("STUB_NO_BACKUP") != "1":
        stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime()) + "-" + str(time.monotonic_ns())
        bak = real.with_name(real.name + ".bak-pweh-" + stamp)
        shutil.copy2(real, bak)
        print(f"백업: {bak}")
    real.write_text(old + text)
    print(f"작성: {cfg} (explicit)" + (f" → 실제 파일 {real}" if real != cfg else ""))


if cmd == "mcp-config":
    client = opt("--client")
    if client == "claude":
        print((repo / ".mcp.json").read_text())
    elif client == "cursor":
        launch = "${workspaceFolder}/scripts/mcp-launch.sh"
        print(json.dumps({"mcpServers": {"pweh-case": {"command": launch, "args": ["pweh-case-mcp"]},
                                         "rea": {"command": launch, "args": ["rea"]}}}, indent=2))
    elif "--dry-run" in args:
        target = repo / ".codex" / "config.toml"
        if env.get("STUB_CODEX_PATH_ONLY") == "1":  # pweh 처럼: 셸의 PATH 가 달라 rea env 의 PATH 줄만 바뀜
            print(f"바뀔 파일: {target}\n--- {target} (현재)\n+++ {target} (pweh)\n@@ -1,3 +1,3 @@\n [mcp_servers.rea.env]\n"
                  '-PATH = "/a/bin:/usr/bin"\n+PATH = "/b/bin:/usr/bin"\n REA_GHIDRA_STARTUP_TIMEOUT_MS = "600000"')
        elif env.get("STUB_CODEX_CURRENT") != "1":
            print(f"--- {target}\n+++ {target}\n@@ -0,0 +1 @@\n+[mcp_servers.pweh-case]")
    else:
        rc = int(env.get("STUB_CODEX_WRITE_RC", "0"))
        if rc:
            print("config.toml 이 올바른 TOML 이 아니라 쓰지 않음", file=sys.stderr)
            sys.exit(rc)
        if opt("--scope") == "global":
            for h in homes():
                edit(h / "config.toml", '\n[mcp_servers.pweh-case]\ncommand = "x"\n')
        else:
            target = repo / ".codex" / "config.toml"
            target.parent.mkdir(exist_ok=True)
            target.write_text("# pweh mcp-config 생성물\n")
            print(f"작성: {target}")
            for h in homes():  # pweh 처럼 신뢰 항목이 없는 홈을 안내한다 (쓰지 않은 파일의 경로가 출력에 섞인다)
                print(f"참고: Codex 는 이 저장소를 신뢰할 때만 프로젝트 설정을 읽는다. 신뢰 항목이 없는 홈: {h / 'config.toml'} (cli)")
    sys.exit(0)
if cmd == "codex-trust":
    trusted = env.get("STUB_TRUSTED") == "1" or (state / "trusted").exists()
    if "--check" in args:
        print("cli: " + ("trusted" if trusted else "신뢰 항목 없음"))
        sys.exit(int(env.get("STUB_TRUST_CHECK_RC", "0" if trusted else "1")))
    if "--dry-run" in args:
        for h in homes() or [Path(env["HOME"]) / ".codex"]:
            print(f"--- {h / 'config.toml'}\n+++ {h / 'config.toml'}\n+[projects.\"{repo}\"]\n+trust_level = \"trusted\"")
        sys.exit(0)
    if "--yes" in args:
        for h in homes():
            edit(h / "config.toml", f'\n[projects."{repo}"]\ntrust_level = "trusted"\n')
        state.mkdir(parents=True, exist_ok=True)
        (state / "trusted").touch()
        sys.exit(0)
    print("대화형 터미널이 아니라 아무것도 하지 않음")
    sys.exit(0)
if cmd == "skills":
    dest = repo / {"claude-project": ".claude/skills", "agents": ".agents/skills"}[opt("--target")]
    dest.mkdir(parents=True, exist_ok=True)
    results = []
    for src in sorted((repo / "skills").iterdir()):
        link = dest / src.name
        if link.is_symlink() and link.resolve() == src.resolve():
            results.append({"skill": src.name, "status": "already-installed", "path": str(link)})
        elif link.exists() or link.is_symlink():
            results.append({"skill": src.name, "status": "exists (use --force)", "path": str(link)})
        else:
            link.symlink_to(os.path.relpath(src, dest), target_is_directory=True)
            results.append({"skill": src.name, "status": "installed", "path": str(link)})
    print(json.dumps({"dest": str(dest), "results": results}, ensure_ascii=False, indent=2))
    sys.exit(0)
if cmd == "doctor":
    print("pweh 0.0 doctor (가짜)")
    sys.exit(0)
if cmd == "mcp-check":  # pweh 처럼: STUB_MCPCHECK_FAIL 의 서버가 실패, --optional 서버의 실패는 종료 코드에 넣지 않음
    optional = [args[i + 1] for i, a in enumerate(args) if a == "--optional"]
    failing = [n for n in env.get("STUB_MCPCHECK_FAIL", "").split(",") if n]
    print("[OK ] codex:pweh-case  0.5s  도구 12")
    for n in failing:
        print(f"[!! ] codex:{n}  initialize 중에 서버가 끝남 (종료 코드 1)" + ("  (선택 서버 — 종료 코드에 넣지 않음)" if n in optional else ""))
    hard = [n for n in failing if n not in optional]
    soft = [n for n in failing if n in optional]
    print("결과: …" + (" — 실패가 있다" if hard else "") + (f" — 선택 서버 실패 {len(soft)}개 (종료 코드에 넣지 않음: {', '.join(soft)})" if soft else ""))
    sys.exit(int(env.get("STUB_MCPCHECK_RC", "1" if hard else "0")))
print("가짜 pweh: 모르는 인자", args, file=sys.stderr)
sys.exit(2)
'''
SKILLS = ("pweh-start", "uart-shell-acquisition")


class FakeRepo:
    """임시 디렉터리의 저장소 골격(install.sh 복사본, .mcp.json, .claude/settings.json, skills/)과 가짜 pweh 가 든 가상환경.

    install.sh 는 자기 위치로 저장소를 정하므로 저장소에 쓰는 것(.codex/, .agents/, .cursor/)도 모두 임시 디렉터리에 남는다.
    """

    def __init__(self, root: Path):
        self.root = root
        self.repo = root / "repo"
        (self.repo / "scripts").mkdir(parents=True)
        shutil.copy2(SCRIPT, self.repo / "scripts" / "install.sh")
        servers = {n: {"type": "stdio", "command": "bash", "args": ["-c", f"exec scripts/mcp-launch.sh {n}"]} for n in ("pweh-case", "rea")}
        (self.repo / ".mcp.json").write_text(json.dumps({"mcpServers": servers}, indent=2) + "\n")
        (self.repo / ".claude").mkdir()
        (self.repo / ".claude" / "settings.json").write_text(json.dumps({"enabledMcpjsonServers": list(servers)}) + "\n")
        for name in SKILLS:
            (self.repo / "skills" / name).mkdir(parents=True)
            (self.repo / "skills" / name / "SKILL.md").write_text(f"---\nname: {name}\n---\n")
        (self.repo / "orchestrator").mkdir()
        (self.repo / "orchestrator" / "pipeline-config.yaml").write_text("# 시험\n")
        self.venv = root / "venv"
        (self.venv / "bin").mkdir(parents=True)
        stub = self.venv / "bin" / "pweh"
        stub.write_text(STUB.replace("@PYTHON@", sys.executable))
        stub.chmod(0o755)
        # REA(선택 구성요소)가 있는 것으로 둔다 — 호스트에 rea 가 있든 없든 mcp-check 인자가 같게 (없는 경우는 시험이 PWEH_REA 를 비운다)
        self.fake_rea = root / "fake-bin" / "rea"
        self.fake_rea.parent.mkdir()
        self.fake_rea.write_text("#!/bin/sh\necho 6.5.0\n")
        self.fake_rea.chmod(0o755)
        self.home = root / "home"
        self.home.mkdir()
        self.prefix = root / "tools"
        self.log = root / "pweh-calls.jsonl"
        drop = ("CODEX_HOME", "PWEH_TOOLS_DIR", "PWEH_TOOLS_ENV", "PWEH_REA", "USERPROFILE", "WSLENV", "PWEH_CONFIG")
        self.env = {k: v for k, v in os.environ.items() if k not in drop and not k.startswith("STUB_")}
        self.env.update(HOME=str(self.home), TMPDIR=str(root), STUB_LOG=str(self.log), STUB_REPO=str(self.repo),
                        STUB_STATE=str(root / "stub-state"), PWEH_REA=str(self.fake_rea))

    def cmd(self, *args: str) -> list[str]:
        return ["bash", str(self.repo / "scripts" / "install.sh"), "--prefix", str(self.prefix), "--venv", str(self.venv), "--no-link", *args]

    def run(self, *args: str, env: dict[str, str] | None = None, cwd: Path | None = None) -> subprocess.CompletedProcess[str]:
        e = dict(self.env)
        e.update(env or {})
        return subprocess.run(self.cmd(*args), capture_output=True, text=True, env=e, timeout=120, stdin=subprocess.DEVNULL, cwd=cwd)

    def records(self) -> list[dict]:
        return [json.loads(ln) for ln in self.log.read_text().splitlines()] if self.log.exists() else []

    def calls(self) -> list[list[str]]:
        return [r["argv"] for r in self.records()]

    def link_skills(self) -> None:
        for d in (".claude/skills", ".agents/skills"):
            (self.repo / d).mkdir(parents=True, exist_ok=True)
            for name in SKILLS:
                (self.repo / d / name).symlink_to(Path("../../skills") / name, target_is_directory=True)


def _tree(*roots: Path) -> dict[str, tuple[int, int]]:
    """경로 → (크기, mtime_ns). 아무것도 바뀌지 않았는지 볼 때 쓴다."""
    out = {}
    for root in roots:
        for p in [root, *root.rglob("*")]:
            st = p.lstat()
            out[str(p)] = (st.st_size, st.st_mtime_ns)
    return out


def _writes(calls: list[list[str]]) -> list[list[str]]:
    """설정을 바꿀 수 있는 호출 (--dry-run 이 없는 --write, --yes, skills install)."""
    return [c for c in calls if ("--write" in c and "--dry-run" not in c) or "--yes" in c or c[:2] == ["skills", "install"]]


@pytest.fixture
def fake(tmp_path):
    return FakeRepo(tmp_path)


def test_steps_only_noninteractive_default(fake):
    """--only mcp,skills,verify: 도구를 설치하지 않고 단계만. 대화형이 아니면 Codex 신뢰는 확인만 하고 묻지도 바꾸지도 않는다."""
    r = fake.run("--only", "mcp,skills,verify")
    out = r.stdout + r.stderr
    assert r.returncode == 0, out
    assert fake.calls() == [
        ["mcp-config", "--client", "claude"],
        ["mcp-config", "--client", "codex", "--write"],
        ["codex-trust", "--check"],
        ["skills", "install", "--target", "claude-project"],
        ["skills", "install", "--target", "agents"],
        ["doctor"],
        ["mcp-check", "--client", "all"],
    ], out
    assert not any(rec["stdin_tty"] for rec in fake.records())  # pweh 는 스스로 묻지 않는다 (입력은 /dev/null)
    assert "대화형 터미널이 아니라 묻지 않았고 아무것도 바꾸지 않았습니다" in out and "--codex-trust" in out
    assert "[y/N]" not in out
    # 도구는 다시 설치하지 않고 env.sh·<prefix>·저장소 포인터도 만들지 않는다
    assert not fake.prefix.exists() and not (fake.repo / ".pweh").exists()
    assert "단계만 실행합니다" in out
    # Codex 프로젝트 설정 (가짜 pweh 가 씀) 과 Skill 링크, 끝의 요약과 되돌리는 방법
    cfg = fake.repo / ".codex" / "config.toml"
    assert cfg.is_file()
    real = os.path.realpath(cfg)  # 요약은 실제 경로로 보여 준다
    assert f"씀    {real}   (생성물, git 제외)" in out and f"되돌리기: rm {real}" in out
    for d in (".claude/skills", ".agents/skills"):
        for name in SKILLS:
            link = fake.repo / d / name
            assert link.is_symlink() and link.resolve() == (fake.repo / "skills" / name).resolve()
            assert f"        {link}" in out
    assert "Skill 링크 4개를 새로 만듦" in out
    assert re.search(r"mcp\s+완료 — Claude ✓, Codex 설정 씀, 신뢰 안 함 — 대화형이 아님", out), out
    assert re.search(r"verify\s+완료 — doctor, mcp-check ✓", out), out

    # 다시 실행해도 같다: 링크는 이미 있음, 설정은 pweh 가 다시 씀
    r2 = fake.run("--only", "skills")
    assert r2.returncode == 0 and "개를 새로 만듦" not in r2.stdout and "agents: ✓ 2/2 링크됨" in r2.stdout, r2.stdout
    # mcp 를 다시 실행해 내용이 그대로면 (실제 pweh 는 "변경 없음") 바꾼 파일로 요약하지 않는다
    r3 = fake.run("--only", "mcp")
    out3 = r3.stdout + r3.stderr
    assert r3.returncode == 0 and re.search(r"mcp\s+완료 — Claude ✓, Codex 설정 최신", out3), out3
    assert "바꾼 파일과 되돌리는 방법" not in out3 and cfg.is_file()


def test_steps_only_keeps_existing_tools_dir_and_logs_there(fake):
    """이미 있는 pweh-tools 는 그대로 둔다 (env.sh 를 다시 쓰지 않음). 로그 디렉터리가 있으면 거기에 로그를 남긴다."""
    (fake.prefix / "_logs").mkdir(parents=True)
    (fake.prefix / "env.sh").write_text("# 기존 env.sh\n")
    r = fake.run("--only", "skills")
    assert r.returncode == 0, r.stdout + r.stderr
    assert (fake.prefix / "env.sh").read_text() == "# 기존 env.sh\n"
    logs = list((fake.prefix / "_logs").glob("install-*.log"))
    assert len(logs) == 1 and "skills install --target agents" in logs[0].read_text()
    assert sorted(p.name for p in fake.prefix.iterdir()) == ["_logs", "env.sh"]


def test_codex_trust_flag_passes_yes_and_homes(fake, tmp_path):
    """--codex-trust 는 묻지 않고 --yes. --codex-home 은 Codex 설정과 신뢰의 모든 호출에 같게 넘긴다.
    공백이 든 홈(Windows 프로필 같은)도 요약에 백업과 되돌리는 명령이 나오고, 쓰지 않은 파일을 알린 줄은 요약에 다시 보이지 않는다."""
    h1 = tmp_path / "cli-home"
    h2 = tmp_path / "mnt" / "c" / "Users" / "Test User" / ".codex"  # 가짜 Windows 프로필 경로
    for h in (h1, h2):
        h.mkdir(parents=True)
        (h / "config.toml").write_text('model = "x"\n')
    homes = ["--codex-home", str(h1), "--codex-home", str(h2)]
    r = fake.run("--only", "mcp", "--codex-trust", *homes)
    out = r.stdout + r.stderr
    assert r.returncode == 0, out
    assert fake.calls() == [
        ["mcp-config", "--client", "claude"],
        ["mcp-config", "--client", "codex", "--write", *homes],
        ["codex-trust", "--check", *homes],
        ["codex-trust", "--yes", *homes],
        ["codex-trust", "--check", *homes],
    ], out
    assert "[y/N]" not in out
    summary = out.split("바꾼 파일과 되돌리는 방법", 1)[1]
    assert "참고:" in out and "참고:" not in summary
    for h in (h1, h2):
        cfg = Path(os.path.realpath(h / "config.toml"))
        (bak,) = cfg.parent.glob("config.toml.bak-pweh-*")
        assert bak.read_text() == 'model = "x"\n' and "trust_level" in cfg.read_text()
        assert f"씀    {cfg}" in out and f"백업: {bak}" in out
        q = lambda p: str(p).replace(" ", "\\ ")  # printf %q
        assert f"되돌리기: cp -p {q(bak)} {q(cfg)}" in out, out
        assert f"작성: {cfg}" in out  # pweh 출력 그대로도 남는다
    assert f'[projects."{os.path.realpath(fake.repo)}"]' in out and "백업은 지우지 않았습니다" in out
    assert re.search(r"mcp\s+완료 — .*신뢰 더함", out), out


def test_codex_global_scope_and_earliest_backup(fake, tmp_path):
    """--codex-global: Codex 홈에 직접 등록하고 신뢰는 묻지 않는다. 등록과 신뢰가 같은 파일을 두 번 바꾸면
    되돌리기는 처음 백업(이 스크립트를 돌리기 전 상태)을 가리킨다."""
    home = tmp_path / "codex-home"
    home.mkdir()
    (home / "config.toml").write_text("# 사용자 설정\n")
    r = fake.run("--only", "mcp", "--codex-global", "--codex-home", str(home))
    assert r.returncode == 0, r.stdout + r.stderr
    assert fake.calls() == [
        ["mcp-config", "--client", "claude"],
        ["mcp-config", "--client", "codex", "--write", "--scope", "global", "--codex-home", str(home)],
    ]
    assert "필요 없음 (--codex-global" in r.stdout and not (fake.repo / ".codex").exists()

    (home / "config.toml").write_text("# 사용자 설정\n")
    for b in home.glob("config.toml.bak-pweh-*"):
        b.unlink()
    fake.log.unlink()
    r = fake.run("--only", "mcp", "--codex-global", "--codex-trust", "--codex-home", str(home))
    out = r.stdout + r.stderr
    assert r.returncode == 0, out
    assert ["codex-trust", "--yes", "--codex-home", str(home)] in fake.calls()
    backups = sorted(home.glob("config.toml.bak-pweh-*"))
    assert len(backups) == 2
    undo = re.findall(r"되돌리기: cp -p (\S+) (\S+)", out)
    assert len(undo) == 1 and undo[0][1] == os.path.realpath(home / "config.toml"), out
    assert Path(undo[0][0]).read_text() == "# 사용자 설정\n"  # 처음 백업 = 돌리기 전 상태


def test_summary_resolves_symlinked_config(fake, tmp_path):
    """Codex 홈의 config.toml 이 dotfiles 링크면 pweh 는 링크가 가리키는 파일을 백업하고 고친다.
    요약의 되돌리기는 그 실제 파일을 가리키고, 링크를 지우라고 하지 않는다."""
    dot = tmp_path / "dotfiles" / "codex.toml"
    dot.parent.mkdir()
    dot.write_text("# dotfiles\n")
    home = tmp_path / "codex-home"
    home.mkdir()
    (home / "config.toml").symlink_to(dot)
    r = fake.run("--only", "mcp", "--codex-trust", "--codex-home", str(home))
    out = r.stdout + r.stderr
    assert r.returncode == 0, out
    (bak,) = dot.parent.glob("codex.toml.bak-pweh-*")
    assert bak.read_text() == "# dotfiles\n" and (home / "config.toml").is_symlink()
    assert f"되돌리기: cp -p {os.path.realpath(bak)} {os.path.realpath(dot)}" in out, out
    assert f"rm {home / 'config.toml'}" not in out and f"rm {os.path.realpath(dot)}" not in out


def test_summary_new_file_and_unbacked_change(fake, tmp_path):
    """새로 만든 파일은 rm 으로 되돌리고, 백업 없이 바뀐 기존 파일은 지우라고 하지 않는다 (호출 전후 내용 비교)."""
    new_home, old_home = tmp_path / "new-home", tmp_path / "old-home"
    new_home.mkdir()
    old_home.mkdir()
    (old_home / "config.toml").write_text("# 사용자 설정\n")
    r = fake.run("--only", "mcp", "--codex-global", "--codex-home", str(new_home), "--codex-home", str(old_home),
                 env={"STUB_NO_BACKUP": "1"})
    out = r.stdout + r.stderr
    assert r.returncode == 0, out
    created, changed = os.path.realpath(new_home / "config.toml"), os.path.realpath(old_home / "config.toml")
    assert f"씀    {created}   (새로 만든 파일)" in out and f"되돌리기: rm {created}" in out
    assert f"씀    {changed}   (있던 파일 — 이번 출력에서 백업을 찾지 못함" in out and f"rm {changed}" not in out


def test_no_mcp_no_verify_and_skip(fake):
    r = fake.run("--only", "mcp,skills,verify", "--no-codex-trust", "--no-verify")
    assert r.returncode == 0, r.stdout + r.stderr
    calls = fake.calls()
    assert not any(c[0] == "codex-trust" for c in calls) and not any(c[0] in ("doctor", "mcp-check") for c in calls)
    assert "건너뜀 (--no-codex-trust)" in r.stdout
    fake.log.unlink()
    r = fake.run("--only", "mcp,skills,verify", "--no-mcp")
    assert r.returncode == 0 and not any(c[0] in ("mcp-config", "codex-trust") for c in fake.calls())
    fake.log.unlink()
    r = fake.run("--only", "mcp,skills,verify", "--skip", "verify,skills")
    assert r.returncode == 0 and {c[0] for c in fake.calls()} == {"mcp-config", "codex-trust"}


def test_dry_run_changes_nothing(fake):
    """--dry-run: 구성요소·skills·verify 는 하지 않고 바뀔 내용만. --codex-trust 가 있어도 --yes 는 부르지 않는다."""
    (fake.repo / ".cursor").mkdir()
    (fake.repo / ".cursor" / "mcp.json").write_text(json.dumps({"mcpServers": {"mine": {"command": "x"}}}) + "\n")
    before = _tree(fake.repo, fake.home)
    r = fake.run("--dry-run", "--codex-trust", "--cursor")
    out = r.stdout + r.stderr
    assert r.returncode == 0, out
    calls = fake.calls()
    assert calls == [
        ["mcp-config", "--client", "claude"],
        ["mcp-config", "--client", "codex", "--write", "--dry-run"],
        ["codex-trust", "--dry-run"],
        ["mcp-config", "--client", "cursor"],
    ], out
    assert _writes(calls) == []
    assert _tree(fake.repo, fake.home) == before and not fake.prefix.exists()
    assert "dry-run: 아무것도 설치하거나 바꾸지 않고" in out and "dry-run 이라 설치하지 않고 env.sh 도 쓰지 않음" in out
    assert f"+++ {fake.repo / '.codex' / 'config.toml'}" in out and '+trust_level = "trusted"' in out
    assert '+    "pweh-case": {' in out  # Cursor 에 더해질 항목
    assert "설치할 때 만들 링크: pweh-start uart-shell-acquisition" in out
    assert re.search(r"verify\s+dry-run — 건너뜀", out), out
    assert "바꾼 파일과 되돌리는 방법" not in out


def test_check_runs_only_read_only_calls(fake):
    fake.link_skills()
    current = {"STUB_CODEX_CURRENT": "1", "STUB_TRUSTED": "1"}
    before = _tree(fake.repo, fake.home)
    r = fake.run("--check", "--only", "mcp,skills,verify", env=current)
    out = r.stdout + r.stderr
    assert r.returncode == 0, out
    for name in ("mcp:claude", "mcp:codex", "mcp:codex-trust", "skills:claude-project", "skills:agents", "verify"):
        assert f"✓ {name}  " in out, (name, out)
    assert fake.calls() == [
        ["mcp-config", "--client", "claude"],
        ["mcp-config", "--client", "codex", "--write", "--dry-run"],
        ["codex-trust", "--check"],
        ["mcp-check", "--client", "all"],
    ]

    r = fake.run("--check", "--only", "mcp,skills,verify")  # 설정이 오래되고 신뢰가 없다
    out = r.stdout + r.stderr
    assert r.returncode == 1, out
    assert "✗ mcp:codex  Codex 설정이 없거나 오래됨" in out and f"+++ {fake.repo / '.codex' / 'config.toml'}" in out
    assert "✗ mcp:codex-trust  이 저장소를 신뢰하지 않는 Codex 홈이 있음" in out and "--codex-trust" in out
    r = fake.run("--check", "--only", "mcp", "--no-codex-trust", env={"STUB_CODEX_CURRENT": "1"})
    assert r.returncode == 0 and "- mcp:codex-trust  점검하지 않음" in r.stdout, r.stdout
    r = fake.run("--check", "--only", "mcp", "--codex-global", env={"STUB_CODEX_CURRENT": "1"})
    assert r.returncode == 0 and "- mcp:codex-trust  필요 없음" in r.stdout, r.stdout
    assert ["mcp-config", "--client", "codex", "--write", "--scope", "global", "--dry-run"] in fake.calls()

    # 서버 env 의 PATH 줄만 다르면 (실행한 셸마다 다른 값 — pweh doctor 도 뺀다) 최신으로 본다
    r = fake.run("--check", "--only", "mcp", "--no-codex-trust", env={"STUB_CODEX_PATH_ONLY": "1"})
    assert r.returncode == 0 and "✓ mcp:codex  " in r.stdout and "PATH 만 지금 셸과 다름" in r.stdout, r.stdout

    (fake.repo / ".agents" / "skills" / "pweh-start").unlink()
    r = fake.run("--check", "--only", "skills")
    assert r.returncode == 1 and "✗ skills:agents  1/2 링크됨 — 빠진 Skill: pweh-start" in r.stdout, r.stdout

    assert _writes(fake.calls()) == []
    after = _tree(fake.repo, fake.home)
    assert after == {k: v for k, v in before.items() if not k.endswith(".agents/skills/pweh-start")} | {
        str(fake.repo / ".agents" / "skills"): after[str(fake.repo / ".agents" / "skills")]}
    assert not fake.prefix.exists()


def _run_tty(fake: FakeRepo, args: list[str], answer: bytes | None, env: dict[str, str] | None = None,
             stdout_tty: bool = False) -> tuple[int, str, str, bool]:
    """표준 입력·표준 오류(stdout_tty 면 표준 출력도)를 가상 터미널에 붙여 install.sh 를 돌린다.
    질문([y/N])이 나오면 answer 를 보낸다 (None 이면 EOF)."""
    master, slave = pty.openpty()
    e = dict(fake.env)
    e.update(env or {})
    p = subprocess.Popen(fake.cmd(*args), stdin=slave, stdout=slave if stdout_tty else subprocess.PIPE, stderr=slave, env=e)
    os.close(slave)
    out: list[bytes] = []
    reader = threading.Thread(target=lambda: out.append(p.stdout.read() if p.stdout else b""))
    reader.start()
    tty, sent, deadline = bytearray(), False, time.monotonic() + 60
    while time.monotonic() < deadline:
        ready, _, _ = select.select([master], [], [], 0.1)
        if ready:
            try:
                data = os.read(master, 4096)
            except OSError:  # 프로세스가 끝나 터미널이 닫힘
                break
            if not data:
                break
            tty += data
        if not sent and b"[y/N]" in tty:
            os.write(master, b"\x04" if answer is None else answer + b"\n")
            sent = True
        if not ready and p.poll() is not None:
            break
    p.wait(timeout=60)
    reader.join(timeout=60)
    os.close(master)
    return p.returncode, out[0].decode() if out else "", tty.decode(errors="replace"), sent


@pytest.mark.parametrize("answer,agreed", [(b"y", True), (b"n", False), (b"", False), (None, False)])
def test_trust_prompt_on_tty(fake, tmp_path, answer, agreed):
    """대화형 터미널이면 바뀔 내용을 보여 주고 묻는다. y 일 때만 --yes 로 바꾸고, n·빈 입력·EOF 는 바꾸지 않는다."""
    home = tmp_path / "codex-home"
    home.mkdir()
    (home / "config.toml").write_text("# 사용자 설정\n")
    rc, out, tty, sent = _run_tty(fake, ["--only", "mcp"], answer, env={"CODEX_HOME": str(home)})
    assert sent, tty + out
    assert rc == 0, out
    # 표준 출력이 파이프(시험)라 바뀔 내용은 묻는 화면(터미널)에 질문보다 먼저 보인다
    assert f"+++ {home / 'config.toml'}" in tty and tty.index("+++ ") < tty.index("신뢰 항목을 더할까요?")
    assert f"+++ {home / 'config.toml'}" not in out and "바뀔 내용은 묻는 화면에 보여 줌" in out
    calls = fake.calls()
    assert calls[:4] == [
        ["mcp-config", "--client", "claude"],
        ["mcp-config", "--client", "codex", "--write"],
        ["codex-trust", "--check"],
        ["codex-trust", "--dry-run"],
    ]
    assert not any(rec["stdin_tty"] for rec in fake.records())  # 터미널은 이 스크립트만 쓴다
    if agreed:
        assert calls[4:] == [["codex-trust", "--yes"], ["codex-trust", "--check"]]
        assert "trust_level" in (home / "config.toml").read_text() and "Codex 신뢰: ✓ 더함" in out
        summary = out.split("바꾼 파일과 되돌리는 방법", 1)[1]
        assert "되돌리기: cp -p" in summary
        assert "참고:" in out and "참고:" not in summary  # 쓰지 않은 파일을 알린 줄은 요약에 다시 보이지 않는다
    else:
        assert len(calls) == 4 and (home / "config.toml").read_text() == "# 사용자 설정\n"
        assert not list(home.glob("*.bak-pweh-*")) and "신뢰 안 함 — 거절" in out


def test_trust_prompt_when_stdout_is_terminal_too(fake, tmp_path):
    """보통의 터미널 실행(표준 출력도 터미널): 바뀔 내용은 표준 출력으로 질문보다 먼저 보이고, y 면 --yes."""
    home = tmp_path / "codex-home"
    home.mkdir()
    (home / "config.toml").write_text("# 사용자 설정\n")
    rc, _out, tty, sent = _run_tty(fake, ["--only", "mcp"], b"y", env={"CODEX_HOME": str(home)}, stdout_tty=True)
    assert sent and rc == 0, tty
    assert tty.index(f"+++ {home / 'config.toml'}") < tty.index("신뢰 항목을 더할까요?") < tty.index("Codex 신뢰: ✓ 더함")
    assert "바뀔 내용은 묻는 화면에 보여 줌" not in tty
    assert ["codex-trust", "--yes"] in fake.calls() and "trust_level" in (home / "config.toml").read_text()


def test_trust_not_asked_when_already_trusted_or_unknown(fake):
    r = fake.run("--only", "mcp", env={"STUB_TRUSTED": "1"})
    assert r.returncode == 0 and "Codex 신뢰: ✓" in r.stdout and fake.calls()[-1] == ["codex-trust", "--check"]
    fake.log.unlink()
    r = fake.run("--only", "mcp", "--codex-trust", env={"STUB_TRUST_CHECK_RC": "3"})  # 확인할 수 없으면 동의가 있어도 바꾸지 않는다
    assert r.returncode == 1 and not any("--yes" in c for c in fake.calls()), r.stdout
    assert "codex-trust --check 실패 (종료 코드 3)" in r.stdout


def test_missing_pweh_fails_without_writing(fake, tmp_path):
    before = _tree(fake.repo, fake.home)
    r = fake.run("--only", "mcp,skills,verify", "--venv", str(tmp_path / "novenv"))
    out = r.stdout + r.stderr
    assert r.returncode == 1, out
    assert f"pweh 가 없습니다 ({tmp_path / 'novenv' / 'bin' / 'pweh'})" in out
    assert "Claude Code: ✓" in out  # Claude 확인은 pweh 없이도 한다
    assert fake.calls() == [] and _tree(fake.repo, fake.home) == before and not (tmp_path / "novenv").exists()


def test_unsupported_pweh_subcommands_are_reported(fake):
    """가상환경의 pweh 가 codex-trust·mcp-check 를 모르면(다른 판) 알리고 실패로 센다. 묻지 않는다."""
    r = fake.run("--only", "mcp,verify", "--codex-trust", env={"STUB_UNSUPPORTED": "codex-trust,mcp-check"})
    out = r.stdout + r.stderr
    assert r.returncode == 1, out
    assert out.count("pweh 가 이 명령·옵션을 모릅니다") == 2 and "invalid choice" in out
    assert not any("--yes" in c for c in fake.calls()) and (fake.repo / ".codex" / "config.toml").is_file()


def test_codex_config_failure_skips_trust(fake):
    r = fake.run("--only", "mcp", "--codex-trust", env={"STUB_CODEX_WRITE_RC": "1"})
    out = r.stdout + r.stderr
    assert r.returncode == 1 and "올바른 TOML 이 아니라" in out, out
    assert not any(c[0] == "codex-trust" for c in fake.calls()) and "설정을 쓰지 못해 묻지 않고 건너뜀" in out


def test_mcp_check_failure_policy(fake, tmp_path):
    """mcp-check 실패는 실패다. REA 가 설치되지 않았으면(선택 구성요소) rea 서버만 선택 서버로 넘겨(--optional rea) 그 실패만 경고로 본다.
    다른 PWEH 서버가 실패하면 REA 가 없어도 실패다 (예전: REA 가 없으면 어느 서버의 실패든 경고로 낮춤)."""
    no_rea = {"PWEH_REA": "", "PATH": "/usr/bin:/bin"}
    r = fake.run("--only", "verify", env={**no_rea, "STUB_MCPCHECK_FAIL": "rea"})
    assert r.returncode == 0 and "REA 가 설치되지 않아 경고로만 봄" in r.stdout, r.stdout
    assert ["mcp-check", "--client", "all", "--optional", "rea"] in fake.calls()
    assert re.search(r"verify\s+완료 — doctor, mcp-check 경고 — REA 없음", r.stdout), r.stdout
    r = fake.run("--only", "verify", env={**no_rea, "STUB_MCPCHECK_FAIL": "pweh-esp"})  # REA 가 없어도 PWEH 서버 실패는 실패
    assert r.returncode == 1 and "pweh mcp-check 실패 (종료 코드 1)" in r.stdout, r.stdout
    r = fake.run("--only", "verify", env={**no_rea, "STUB_MCPCHECK_FAIL": "rea,pweh-esp"})
    assert r.returncode == 1, r.stdout
    r = fake.run("--check", "--only", "verify", env={**no_rea, "STUB_MCPCHECK_FAIL": "pweh-esp"})
    assert r.returncode == 1 and "✗ verify  pweh mcp-check 실패" in r.stdout, r.stdout
    r = fake.run("--check", "--only", "verify", env={**no_rea, "STUB_MCPCHECK_FAIL": "rea"})
    assert r.returncode == 0 and "- verify  pweh mcp-check: PWEH 서버는 정상, rea 서버만 뜨지 않음" in r.stdout, r.stdout
    # REA 가 있으면 rea 도 선택 서버가 아니다
    fake.log.unlink()
    r = fake.run("--only", "verify", env={"STUB_MCPCHECK_FAIL": "rea"})
    assert r.returncode == 1 and fake.calls()[-1] == ["mcp-check", "--client", "all"], r.stdout


def test_verify_runs_doctor_with_the_repo_config_from_any_cwd(fake, tmp_path):
    """다른 디렉터리에서 설치 스크립트를 돌려도 pweh 는 저장소 설정(PWEH_CONFIG)으로 돈다 — 그곳에 cases/·.pweh/state 를 만들지 않게.
    이미 PWEH_CONFIG 를 정했으면 그대로 둔다."""
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    r = fake.run("--only", "verify", cwd=elsewhere)
    assert r.returncode == 0, r.stdout
    cfg = str(fake.repo / "orchestrator" / "pipeline-config.yaml")
    assert {rec["argv"][0]: rec["pweh_config"] for rec in fake.records()} == {"doctor": cfg, "mcp-check": cfg}
    assert sorted(p.name for p in elsewhere.iterdir()) == []
    fake.log.unlink()
    mine = tmp_path / "mine.yaml"
    mine.write_text("# 내 설정\n")
    fake.run("--only", "verify", env={"PWEH_CONFIG": str(mine)})
    assert {rec["pweh_config"] for rec in fake.records()} == {str(mine)}


def test_python_component_requires_tomlkit(tmp_path):
    """이 변경 전에 만든 가상환경(tomlkit 없음)은 '이미 설치됨'이 아니다 → 다시 실행하면 pip install 을 다시 한다."""
    venv = tmp_path / "old-venv"
    (venv / "bin").mkdir(parents=True)
    py = venv / "bin" / "python"
    py.write_text('#!/bin/sh\ncase "$*" in *tomlkit*) exit 1 ;; esac\nexit 0\n')  # tomlkit 만 import 못 하는 가짜
    py.chmod(0o755)
    r = _run("--check", "--only", "python", "--prefix", str(tmp_path / "t"), "--venv", str(venv), "--no-link", env={"HOME": str(tmp_path)})
    assert r.returncode == 1 and "✗ python" in r.stdout, r.stdout


def test_missing_python_module_gets_a_reinstall_hint(fake):
    """이전 판 가상환경의 pweh 가 ModuleNotFoundError·'tomlkit 이 없다'로 끝나면 다시 설치하라고 알린다. --check 의 trust 는 '확인하지 못함'."""
    stub = fake.venv / "bin" / "pweh"
    stub.write_text("#!/bin/sh\necho 'pweh: [pweh_error] tomlkit 이 없다 (No module named tomlkit)' >&2\nexit 1\n")
    r = fake.run("--only", "mcp")
    assert r.returncode == 1 and "./scripts/install.sh --only python --force" in r.stdout, r.stdout
    stub.write_text("#!/bin/sh\necho 'ModuleNotFoundError: No module named x' >&2\nexit 2\n")
    r = fake.run("--check", "--only", "mcp")
    assert r.returncode == 1 and "✗ mcp:codex-trust  확인하지 못함" in r.stdout and "--only python --force" in r.stdout, r.stdout


def test_codex_home_value_must_not_be_another_option(fake):
    r = fake.run("--only", "mcp", "--codex-home", "--dry-run")
    assert r.returncode == 2 and "다른 옵션처럼 보임" in r.stderr and fake.calls() == [], r.stderr


def test_cursor_merge_keeps_user_entries(fake):
    """--cursor: PWEH 항목만 바꾸고(옛 pweh-* 는 뺌) 다른 서버와 사용자가 따로 둔 rea 는 그대로. 바꾸기 전에 백업."""
    cur = fake.repo / ".cursor" / "mcp.json"
    cur.parent.mkdir()
    original = {"mcpServers": {"mine": {"command": "my-server"}, "pweh-old": {"command": "old"}, "rea": {"command": "my-rea"}}}
    cur.write_text(json.dumps(original, indent=2) + "\n")
    r = fake.run("--only", "mcp", "--cursor", "--no-codex-trust")
    out = r.stdout + r.stderr
    assert r.returncode == 0, out
    merged = json.loads(cur.read_text())["mcpServers"]
    assert sorted(merged) == ["mine", "pweh-case", "rea"] and merged["rea"] == {"command": "my-rea"}
    (bak,) = cur.parent.glob("mcp.json.bak-pweh-*")
    assert json.loads(bak.read_text()) == original
    assert f"되돌리기: cp -p {os.path.realpath(bak)} {os.path.realpath(cur)}" in out and "사용자가 따로 둔 rea 항목은 그대로 둠" in out
    r = fake.run("--only", "mcp", "--cursor", "--no-codex-trust")
    assert r.returncode == 0 and "Cursor: ✓ 최신" in r.stdout and len(list(cur.parent.glob("mcp.json.bak-pweh-*"))) == 1
    r = fake.run("--check", "--only", "mcp", "--cursor", "--no-codex-trust", env={"STUB_CODEX_CURRENT": "1"})
    assert r.returncode == 0 and "✓ mcp:cursor" in r.stdout, r.stdout

    cur.write_text("{ 깨진 JSON")
    r = fake.run("--only", "mcp", "--cursor", "--no-codex-trust")
    assert r.returncode == 1 and "올바른 JSON 이 아니라 바꾸지 않음" in r.stdout and cur.read_text() == "{ 깨진 JSON"


def test_claude_inconsistency_is_reported_not_fixed(fake):
    settings = fake.repo / ".claude" / "settings.json"
    settings.write_text(json.dumps({"enabledMcpjsonServers": ["pweh-case"]}) + "\n")
    r = fake.run("--check", "--only", "mcp", "--no-codex-trust", env={"STUB_CODEX_CURRENT": "1"})
    assert r.returncode == 1 and "✗ mcp:claude  enabledMcpjsonServers 에 없는 서버: rea" in r.stdout, r.stdout
    r = fake.run("--only", "mcp", "--no-codex-trust")
    assert r.returncode == 1 and "이 스크립트는 고치지 않습니다" in r.stdout, r.stdout
    assert json.loads(settings.read_text()) == {"enabledMcpjsonServers": ["pweh-case"]}  # 저장소 파일을 바꾸지 않는다


def test_skill_conflict_is_reported_not_forced(fake):
    own = fake.repo / ".agents" / "skills" / "pweh-start"
    own.mkdir(parents=True)
    (own / "SKILL.md").write_text("내 것\n")
    r = fake.run("--only", "skills")
    assert r.returncode == 1, r.stdout
    assert "같은 이름의 다른 파일·디렉터리가 있어 링크하지 않음" in r.stdout and "--force (기존 것을 지움)" in r.stdout
    assert (own / "SKILL.md").read_text() == "내 것\n" and not any("--force" in c for c in fake.calls())


def test_real_repo_claude_registration_is_consistent(tmp_path):
    """이 저장소의 .mcp.json 서버가 모두 .claude/settings.json 의 enabledMcpjsonServers 에 있다 (pweh 없이 읽기만)."""
    r = _run("--check", "--only", "mcp", "--prefix", str(tmp_path / "t"), "--venv", str(tmp_path / "novenv"), "--no-link",
             env={"HOME": str(tmp_path)})
    assert "✓ mcp:claude  .mcp.json 의 서버" in r.stdout, r.stdout
    assert r.returncode == 1 and "✗ mcp:codex  확인하지 못함" in r.stdout  # pweh 가 없으니 Codex 는 확인하지 못함


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


def test_emu_binary_candidates(tmp_path):
    """pweh-emu 실행 파일 후보: 설정 → 환경 변수 → 도구 디렉터리의 고정 위치 (install.sh 가 두는 곳과 같다). 같은 경로는 한 번만."""
    from pweh.toolsdir import EMU_BINARY_RELPATHS, emu_binary_candidates

    assert emu_binary_candidates("qemu-system-xtensa", " /cfg/qemu-system-xtensa ", "/env/qemu-system-xtensa", tmp_path) == [
        ("/cfg/qemu-system-xtensa", "config"), ("/env/qemu-system-xtensa", "env"),
        (str(tmp_path / "qemu-esp" / "xtensa" / "qemu" / "bin" / "qemu-system-xtensa"), "pweh-tools")]
    # 설정 기본값은 ${PWEH_…:-} 라 보통 환경 변수와 같은 값이다
    assert emu_binary_candidates("pweh_avr_run", "/x/pweh_avr_run", "/x/pweh_avr_run", None) == [("/x/pweh_avr_run", "config")]
    assert emu_binary_candidates("qemu-system-riscv32", "", None, tmp_path) == [
        (str(tmp_path / "qemu-esp" / "riscv32" / "qemu" / "bin" / "qemu-system-riscv32"), "pweh-tools")]
    assert emu_binary_candidates("pweh_avr_run", None, "  ", None) == []
    for bad in ("qemu-system-avr", "qemu-system-arm", "simavr", "run_avr"):
        with pytest.raises(ValueError):
            emu_binary_candidates(bad, None, None, tmp_path)
    text = SCRIPT.read_text(encoding="utf-8")
    for var, name in (("QEMU_XTENSA_BIN", "qemu-system-xtensa"), ("QEMU_RISCV32_BIN", "qemu-system-riscv32"), ("AVR_RUN", "pweh_avr_run")):
        assert f'{var}="$PREFIX/{EMU_BINARY_RELPATHS[name]}"' in text, var


def test_emulator_tool_keys_in_config(monkeypatch):
    """tools.qemu_xtensa / qemu_riscv32 / avr_run: 기본값·저장소 설정 모두 ${PWEH_…:-} (비면 빈 문자열, safety 키가 아님)."""
    import yaml

    from pweh.config import DEFAULTS, load_config

    keys = {"qemu_xtensa": "PWEH_QEMU_XTENSA", "qemu_riscv32": "PWEH_QEMU_RISCV32", "avr_run": "PWEH_AVR_RUN"}
    repo_cfg = yaml.safe_load((REPO / "orchestrator" / "pipeline-config.yaml").read_text(encoding="utf-8"))
    for key, env in keys.items():
        assert DEFAULTS["tools"][key] == f"${{{env}:-}}"
        assert repo_cfg["tools"][key] == f"${{{env}:-}}"
        assert key not in repo_cfg["safety"] and key not in DEFAULTS["safety"]
        monkeypatch.delenv(env, raising=False)
    monkeypatch.setenv("PWEH_QEMU_XTENSA", "/opt/q/qemu-system-xtensa")
    cfg = load_config(REPO / "orchestrator" / "pipeline-config.yaml")
    assert cfg.tools["qemu_xtensa"] == "/opt/q/qemu-system-xtensa"
    assert cfg.tools["qemu_riscv32"] == "" and cfg.tools["avr_run"] == ""


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
