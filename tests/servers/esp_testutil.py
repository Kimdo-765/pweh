"""esp-mcp 테스트 공용 도우미: 가짜 esptool 생성, 가짜 Windows 프로세스 목록, 실제 Windows esptool.exe 탐지, 케이스 생성, 로그 읽기."""

from __future__ import annotations

import json
import os
import signal
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Iterable

from pweh.toolsdir import tools_dir

HERE = Path(__file__).resolve().parent
REPO_ROOT = HERE.parents[1]
FAKE_SRC = HERE / "esp_fake_esptool.py"
VENV_PY = REPO_ROOT / ".venv" / "bin" / "python"

AUTH = {"basis": "owned", "owner": "테스트 랩", "statement": "이 ESP32-S3 보드는 제가 직접 구매한 제 소유 기기입니다."}


def make_fake_esptool(dirpath: Path, name: str = "esptool") -> Path:
    """venv python shebang 을 붙인 가짜 esptool 실행 파일 (name 이 .exe 로 끝나면 Windows 빌드 흉내)."""
    py = VENV_PY if VENV_PY.exists() else Path(sys.executable)
    dirpath.mkdir(parents=True, exist_ok=True)
    exe = dirpath / name
    exe.write_text(f"#!{py}\n" + FAKE_SRC.read_text(encoding="utf-8"), encoding="utf-8")
    exe.chmod(0o755)
    return exe


def read_log(path: Path) -> list[dict[str, Any]]:
    if not Path(path).exists():
        return []
    return [json.loads(line) for line in Path(path).read_text(encoding="utf-8").splitlines() if line.strip()]


def fake_unc(path: Any) -> str:
    """테스트용 wslpath -w 흉내: /a/b → \\\\wsl.localhost\\Ubuntu\\a\\b."""
    return "\\\\wsl.localhost\\Ubuntu" + os.path.abspath(os.fspath(path)).replace("/", "\\")


def interop_enabled() -> bool:
    try:
        first = Path("/proc/sys/fs/binfmt_misc/WSLInterop").read_text().splitlines()[:1]
    except OSError:
        return False
    return bool(first) and first[0].strip() == "enabled"


def real_windows_esptool() -> str | None:
    """실제 Windows esptool.exe (PWEH_ESPTOOL_WIN → <도구 디렉터리>/esptool-win/…, scripts/install.sh --only esptool). interop 으로 version 이 동작해야 한다."""
    if not interop_enabled():
        return None
    cands = [os.environ.get("PWEH_ESPTOOL_WIN"), str(tools_dir() / "esptool-win" / "esptool-windows-amd64" / "esptool.exe")]
    for cand in cands:
        if not cand or not os.path.isfile(cand) or not os.access(cand, os.X_OK):
            continue
        try:
            out = subprocess.run([cand, "version"], stdin=subprocess.DEVNULL, capture_output=True, timeout=120, cwd="/mnt/c" if os.path.isdir("/mnt/c") else None)
        except (OSError, subprocess.SubprocessError):
            continue
        if out.returncode == 0 and b"esptool v" in out.stdout:
            return cand
    return None


def real_linux_esptool() -> str | None:
    """실제 리눅스 esptool (PWEH_ESPTOOL → <도구 디렉터리>/bin/esptool)."""
    for cand in (os.environ.get("PWEH_ESPTOOL"), str(tools_dir() / "bin" / "esptool")):
        if cand and os.path.isfile(cand) and os.access(cand, os.X_OK):
            return cand
    return None


def make_case(title: str = "esp test", authorized: bool = True, case_id: str | None = None) -> str:
    from pweh.runtime import get_runtime

    case = get_runtime("esp-mcp").cases.create(title=title, authorization=AUTH if authorized else None, case_id=case_id)
    return case.id


def case_dir(case_id: str) -> Path:
    from pweh.runtime import get_runtime

    return get_runtime("esp-mcp").cases.get(case_id).dir


def pid_alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:  # pragma: no cover
        return True
    try:
        stat = Path(f"/proc/{pid}/stat").read_text()
        return stat.split(")")[-1].split()[0] != "Z"
    except OSError:
        return False


# ---------------------------------------------------------------------------
# 가짜 Windows 프로세스 목록 (가짜 esptool.exe 는 리눅스 프로세스다)
# ---------------------------------------------------------------------------


def _win_quote(arg: str) -> str:
    if arg and not any(c in arg for c in ' \t"'):
        return arg
    out, bs = ['"'], 0
    for c in arg:
        if c == "\\":
            bs += 1
            continue
        if c == '"':
            out.append("\\" * (2 * bs + 1) + '"')
        else:
            out.append("\\" * bs + c)
        bs = 0
    out.append("\\" * (2 * bs) + '"')
    return "".join(out)


class FakeWinProcs:
    """winproc.query/terminate 대체: /proc 에서 argv 에 이미지 이름(예 esptool.exe)이 든 리눅스 프로세스를 Windows 프로세스처럼 보여 준다.

    terminate 는 SIGKILL(TerminateProcess 처럼 즉시)이다. deny=True 면 아무것도 끝내지 않는다(접근 거부 흉내).
    """

    def __init__(self) -> None:
        self.deny = False
        self.terminated: list[int] = []
        self.queries = 0

    @staticmethod
    def _uptime() -> float:
        return float(Path("/proc/uptime").read_text().split()[0])

    def query(self, image: str):
        from esp_mcp.winproc import WinProc

        self.queries += 1
        hz = os.sysconf("SC_CLK_TCK")
        up = self._uptime()
        out = []
        for d in Path("/proc").iterdir():
            if not d.name.isdigit():
                continue
            try:
                argv = [a.decode("utf-8", "replace") for a in (d / "cmdline").read_bytes().split(b"\0") if a]
                fields = (d / "stat").read_text().rsplit(")", 1)[-1].split()
            except OSError:
                continue
            if not argv or fields[0] == "Z":
                continue
            idx = next((i for i, a in enumerate(argv[:3]) if os.path.basename(a).lower() == image.lower()), None)
            if idx is None:
                continue
            win_argv = argv[idx:]
            age = up - int(fields[19]) / hz
            out.append(WinProc(pid=int(d.name), ppid=int(fields[1]), name=image, age_s=age,
                               command_line=" ".join(_win_quote(a) for a in win_argv)))
        return out

    def terminate(self, pids: Iterable[int]) -> None:
        for pid in pids:
            if self.deny:
                continue
            self.terminated.append(int(pid))
            try:
                os.kill(int(pid), signal.SIGKILL)
            except ProcessLookupError:
                pass


def kill_fake_processes(image: str = "esptool.exe") -> list[int]:
    """테스트 정리: 남은 가짜 esptool.exe 리눅스 프로세스를 끝낸다."""
    f = FakeWinProcs()
    pids = [p.pid for p in f.query(image)]
    for pid in pids:
        try:
            os.kill(pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
    return pids


# ---------------------------------------------------------------------------
# 실제 Windows 쪽 확인 (external 테스트 전용 — 읽기 전용 CIM 질의와 %TEMP% 목록)
# ---------------------------------------------------------------------------

_PS_MEI = ("$ErrorActionPreference='SilentlyContinue';[Console]::OutputEncoding=[System.Text.Encoding]::UTF8;"
           "Get-ChildItem -Directory -Path $env:TEMP -Filter '_MEI*' | ForEach-Object { $_.Name }")


def windows_mei_dirs() -> set[str]:
    from esp_mcp import ports

    rc, out, _err = ports.run_powershell(_PS_MEI)
    return {x.strip() for x in out.splitlines() if x.strip().startswith("_MEI")}


def remove_windows_mei_dirs(names: Iterable[str]) -> None:
    """테스트가 남긴 %TEMP%\\_MEI<번호> 만 지운다 (이름을 정확히 준 것만)."""
    from esp_mcp import ports

    safe = [n for n in names if n.startswith("_MEI") and n[4:].isdigit()]
    if not safe:
        return
    script = "$ErrorActionPreference='SilentlyContinue';" + ";".join(
        f"Remove-Item -LiteralPath (Join-Path $env:TEMP '{n}') -Recurse -Force" for n in safe)
    ports.run_powershell(script)


def windows_esptool_procs(token: str | None = None) -> list[Any]:
    from esp_mcp import winproc

    procs = winproc.query("esptool.exe")
    return [p for p in procs if token is None or token in p.command_line]


def wait_until(pred, timeout: float, interval: float = 0.2) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if pred():
            return True
        time.sleep(interval)
    return pred()
