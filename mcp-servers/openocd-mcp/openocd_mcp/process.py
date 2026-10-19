"""OpenOCD 프로세스 관리: 실행 파일/버전 탐색, cfg 해석, 명령행 조립, 기동/준비 대기/종료.

명령행 순서 (docs/references/openocd-tcl-rpc.md §6, INSTALL_REPORT.md 실측):
  [-s scripts] → 포트 명령(이식형: ``if {[catch {tcl port N}]} {tcl_port N}``, telnet/gdb disabled)
  → -f interface → transport select → -f target... → -f extra... → adapter speed → extra -c ...
  → -c <semihosting 무력화: 핸들러 감싸기> → -c init → -c <semihosting 무력화: init 직후 확인·끄기>

- 포트 명령을 맨 앞에 두는 이유: cfg 파일 안의 ``init`` 이후에는 포트를 바꿀 수 없다.
- 명시적 ``-c init`` 을 (semihosting 확인 앞) 끝에 두면 init 이 서버 시작 전에 끝나므로 "Listening on port N for tcl
  connections" 줄이 init 과 그 뒤 ``-c`` 가 모두 끝난 뒤에 찍힌다. 그래도 준비 판정은 그 줄 + ``version`` 왕복 성공으로 한다.
- semihosting 무력화(:mod:`.semihosting`): 표준 cfg 의 이벤트 핸들러(예: ESP32 계열 ``examine-end``)가 켜는 semihosting 을
  init 전에 감싸 두고, init 직후 TCL 서버가 연결을 받기 전에 타깃마다 꺼졌는지 확인한다. 결과는 로그 표식으로 남는다.
- 로그는 파이프가 아닌 파일(케이스 jtag/openocd-<n>.log)로 보낸다 (파이프가 차서 OpenOCD 가 멈추는 일 방지).
- start_new_session=True 로 별도 프로세스 그룹 → 종료 시 그룹 전체에 시그널.
"""

from __future__ import annotations

import atexit
import logging
import os
import re
import shutil
import signal
import socket
import subprocess
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from pweh.errors import NotFound, ToolMissing, ValidationFailed

from . import semihosting
from .parsers import parse_version

log = logging.getLogger("pweh.openocd")

TRANSPORTS = ("jtag", "swd", "swim", "hla_jtag", "hla_swd", "dapdirect_jtag", "dapdirect_swd")
_LISTEN_TCL = re.compile(r"Listening on port (\d+) for tcl connections")

# ---------------------------------------------------------------------------
# 실행 파일 / 버전 / scripts 디렉터리
# ---------------------------------------------------------------------------


def find_openocd(configured: str | None) -> str:
    """설정(tools.openocd = ${PWEH_OPENOCD:-openocd}) → 절대경로 또는 PATH 탐색."""
    cand = (configured or "").strip() or os.environ.get("PWEH_OPENOCD") or "openocd"
    cand = os.path.expanduser(cand)
    if os.path.sep in cand:
        if os.path.isfile(cand) and os.access(cand, os.X_OK):
            return cand
    else:
        found = shutil.which(cand)
        if found:
            return found
    raise ToolMissing(
        f"OpenOCD 실행 파일을 찾을 수 없습니다: {cand}",
        hint="환경변수 PWEH_OPENOCD 를 절대경로로 지정하거나(예: ~/pweh-tools/env.sh 의 PWEH_OPENOCD), "
        "pipeline-config.yaml 의 tools.openocd 를 설정하세요. (xPack OpenOCD 0.12.0-7 로 검증됨)",
    )


_VERSION_CACHE: dict[tuple[str, float], dict[str, Any]] = {}


def openocd_version(binary: str, timeout: float = 15.0) -> dict[str, Any]:
    """``openocd --version`` (stderr 로 출력됨) 해석. 결과는 실행 파일 mtime 기준으로 캐시."""
    try:
        mtime = os.path.getmtime(binary)
    except OSError:
        mtime = 0.0
    key = (binary, mtime)
    if key in _VERSION_CACHE:
        return _VERSION_CACHE[key]
    try:
        proc = subprocess.run(
            [binary, "--version"], stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            timeout=timeout, check=False,
        )
        text = proc.stdout.decode("utf-8", errors="replace")
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {"parsed": False, "raw": "", "error": str(exc)}
    info = parse_version(text)
    _VERSION_CACHE[key] = info
    return info


def scripts_dirs(configured: str | None, binary: str | None) -> list[Path]:
    """알려진 OpenOCD scripts 디렉터리 후보 (존재하는 것만, 우선순위 순)."""
    out: list[Path] = []

    def add(p: str | os.PathLike[str] | None) -> None:
        if not p:
            return
        pp = Path(os.path.expanduser(str(p)))
        try:
            pp = pp.resolve()
        except OSError:
            return
        if pp.is_dir() and pp not in out:
            out.append(pp)

    add(configured)
    add(os.environ.get("PWEH_OPENOCD_SCRIPTS"))
    if binary:
        try:
            real = Path(binary).resolve()
            add(real.parent.parent / "openocd" / "scripts")  # xPack 레이아웃
            add(real.parent.parent / "share" / "openocd" / "scripts")
        except OSError:
            pass
    add("/usr/local/share/openocd/scripts")
    add("/usr/share/openocd/scripts")
    return out


def openocd_search_dirs(binary: str | None, *, exclude: list[Path] | None = None) -> list[Path]:
    """OpenOCD 가 기본으로 더 찾아보는(신뢰하지 않는) 스크립트 디렉터리 — OpenOCD 의 검색 순서 그대로.

    src/helper/options.c add_default_dirs() (xPack 0.12.0-7 에서 ``-d3`` 로 확인): ``$OPENOCD_SCRIPTS`` →
    ``$XDG_CONFIG_HOME/openocd`` (없으면 ``~/.config/openocd``) → ``~/.openocd`` → ``<실행파일>/../<pkgdata>/site`` →
    ``<실행파일>/../<pkgdata>/scripts``. 앞의 넷은 사용자가 쓸 수 있는 위치라, 여기서 찾은 cfg 는 표준이 아니라 사용자 cfg 로
    보고 내용을 분류해야 한다 (그렇지 않으면 ``~/.openocd/x.cfg`` 를 이름만으로 넘겨 분류 없이 실행할 수 있었다).
    exclude 에 있는(신뢰하는 scripts) 디렉터리는 뺀다.
    """
    cands: list[Path] = []
    env_scripts = os.environ.get("OPENOCD_SCRIPTS")
    if env_scripts:
        cands.append(Path(os.path.expanduser(env_scripts)))
    xdg = os.environ.get("XDG_CONFIG_HOME")
    home = os.environ.get("HOME") or os.path.expanduser("~")
    if xdg:
        cands.append(Path(xdg) / "openocd")
    elif home:
        cands.append(Path(home) / ".config" / "openocd")
    if home:
        cands.append(Path(home) / ".openocd")
    if binary:
        try:
            real = Path(binary).resolve()
            for pkg in (real.parent.parent / "openocd", real.parent.parent / "share" / "openocd"):
                cands += [pkg / "site", pkg / "scripts"]
        except OSError:
            pass
    skip = set()
    for d in exclude or []:
        try:
            skip.add(Path(d).resolve())
        except OSError:
            continue
    out: list[Path] = []
    for c in cands:
        try:
            r = c.resolve()
        except OSError:
            continue
        if r.is_dir() and r not in skip and r not in out:
            out.append(r)
    return out


@dataclass
class CfgRef:
    arg: str  # -f 에 넘길 값
    kind: str  # standard | custom | unresolved
    path: Path | None = None

    def to_dict(self) -> dict[str, Any]:
        return {"arg": self.arg, "kind": self.kind, "path": str(self.path) if self.path else None}


def resolve_cfg(name: str, dirs: list[Path], untrusted: list[Path] | None = None) -> CfgRef:
    """cfg 인자 해석.

    OpenOCD 의 find_file(src/helper/configuration.c)은 상대 경로를 **현재 작업 디렉터리에서 먼저** 찾고 그 다음
    -s/기본 scripts 디렉터리를 찾는다 (xPack 실측: cwd 의 interface/dummy.cfg 가 표준 파일을 가렸다). 그래서
    - 절대경로/``./``/``../``/``~`` → 사용자 파일(custom): 내용을 분류기로 검사한다.
    - scripts 디렉터리에서 찾은 표준 파일은 **검증한 절대경로**를 -f 로 넘긴다 (cwd 의 같은 이름 파일이 가로채지 못하게).
    - scripts 에 없고 서버의 현재 디렉터리 기준으로 존재하는 상대 경로 → custom (절대경로 + 내용 분류).
    - OpenOCD 가 더 찾아보는 사용자 쓰기 가능 위치(``untrusted``: ``$OPENOCD_SCRIPTS``, ``~/.config/openocd``, ``~/.openocd``,
      site — :func:`openocd_search_dirs`)에서 찾으면 OpenOCD 와 같은 순서로 고른 파일을 custom(절대경로 + 내용 분류)으로 본다.
    - 어디에도 없으면 OpenOCD 자체 기본 검색 경로에 맡긴다(unresolved). OpenOCD 는 비어 있는 전용 cwd 에서 실행되고
      위 위치에도 없으므로 OpenOCD 도 찾지 못해 시작이 실패한다.
    """
    if not isinstance(name, str) or not name.strip():
        raise ValidationFailed("cfg 이름이 비었습니다")
    raw = name.strip()
    if any(c in raw for c in "\x00\n\r\x1a"):
        raise ValidationFailed(f"cfg 이름에 제어문자가 있습니다: {raw!r}")
    if raw.startswith(("/", "./", "../", "~")):
        p = Path(os.path.expanduser(raw)).resolve()
        if not p.is_file():
            raise NotFound(f"cfg 파일이 없습니다: {p}")
        return CfgRef(arg=str(p), kind="custom", path=p)
    for d in dirs:
        cand = (d / raw).resolve()
        try:
            cand.relative_to(d)
        except ValueError:
            continue  # ../ 로 scripts 밖을 가리킴 → standard 아님
        if cand.is_file():
            return CfgRef(arg=str(cand), kind="standard", path=cand)
    local = Path(raw).resolve()
    if local.is_file():
        return CfgRef(arg=str(local), kind="custom", path=local)
    for d in untrusted or []:
        cand = (d / raw).resolve()
        if cand.is_file():
            return CfgRef(arg=str(cand), kind="custom", path=cand)
    if ".." in Path(raw).parts:
        raise NotFound(f"cfg 파일이 없습니다: {raw}")
    return CfgRef(arg=raw, kind="unresolved", path=None)


# ---------------------------------------------------------------------------
# 명령행 조립
# ---------------------------------------------------------------------------


def port_commands(tcl_port: int) -> list[str]:
    """0.11/0.12.0(``tcl_port``)과 0.12.0+dev/master(``tcl port``) 모두에서 동작하는 이식형 포트 명령."""
    return [
        f"if {{[catch {{tcl port {int(tcl_port)}}}]}} {{tcl_port {int(tcl_port)}}}",
        "if {[catch {telnet port disabled}]} {telnet_port disabled}",
        "if {[catch {gdb port disabled}]} {gdb_port disabled}",
    ]


def build_argv(
    binary: str,
    *,
    scripts_dir: Path | None,
    interface: CfgRef,
    transport: str | None,
    targets: list[CfgRef],
    extra_cfgs: list[CfgRef],
    adapter_speed_khz: int | None,
    extra_commands: list[str],
    tcl_port: int,
    debug_level: int | None = None,
    search_dirs: list[Path] | None = None,
    semihosting_guard: bool = True,
) -> list[str]:
    """OpenOCD 명령행 조립.

    search_dirs: 신뢰하는 scripts 디렉터리 목록. 모두 ``-s`` 로 넘겨, 표준 cfg 안의 ``source [find ...]`` 가 OpenOCD 의
    기본 검색 순서(``$OPENOCD_SCRIPTS`` → ``~/.config/openocd`` → ``~/.openocd`` → site → 내장 scripts)에서 사용자 쓰기 가능
    위치의 같은 이름 파일보다 신뢰 디렉터리를 먼저 찾게 한다 (xPack 실측: ``-s`` 없이는 ``~/.openocd/mem_helper.tcl`` 이
    표준 target cfg 의 ``source [find mem_helper.tcl]`` 을 가로챘다).

    semihosting_guard: 모든 cfg·extra_commands 뒤(init 직전)에 :data:`semihosting.PRE_INIT_SCRIPT`, init 바로 뒤에
    :data:`semihosting.POST_INIT_SCRIPT` 를 넣는다. 그리고 ``-f`` 하나하나와 extra_commands 하나하나 뒤에
    :data:`semihosting.EARLY_CHECK_SCRIPT` 를 넣는다: cfg 나 시작 명령이 init 을 먼저 실행했으면 그 자리에서 semihosting 을 끄고
    OpenOCD 를 오류로 끝내, 뒤따르는 시작 명령이 semihosting 이 켜진 채 실행되지 않게 한다. 끄는 경로는 테스트용이며 서버는 항상 켠다.
    """
    argv = [binary]
    if debug_level is not None:
        argv.append(f"-d{int(debug_level)}")
    seen: list[str] = []
    for d in ([scripts_dir] if scripts_dir is not None else []) + list(search_dirs or []):
        s = str(d)
        if s not in seen:
            seen.append(s)
            argv += ["-s", s]
    for c in port_commands(tcl_port):
        argv += ["-c", c]
    early = ["-c", semihosting.EARLY_CHECK_SCRIPT] if semihosting_guard else []
    argv += ["-f", interface.arg, *early]
    if transport:
        argv += ["-c", f"transport select {transport}"]
    for t in targets:
        argv += ["-f", t.arg, *early]
    for e in extra_cfgs:
        argv += ["-f", e.arg, *early]
    if adapter_speed_khz is not None:
        k = int(adapter_speed_khz)
        argv += ["-c", f"if {{[catch {{adapter speed {k}}}]}} {{adapter_khz {k}}}"]
    for cmd in extra_commands:
        argv += ["-c", cmd, *early]
    if semihosting_guard:
        argv += ["-c", semihosting.PRE_INIT_SCRIPT]
    argv += ["-c", "init"]
    if semihosting_guard:
        argv += ["-c", semihosting.POST_INIT_SCRIPT]
    return argv


def port_in_use(host: str, port: int, timeout: float = 0.3) -> bool:
    if port <= 0:
        return False
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


# ---------------------------------------------------------------------------
# 프로세스
# ---------------------------------------------------------------------------

_OWNED: dict[int, "OpenOcdProcess"] = {}
_OWNED_LOCK = threading.Lock()


@dataclass
class OpenOcdProcess:
    popen: subprocess.Popen[bytes] | None
    argv: list[str]
    log_path: Path
    started_at: float = field(default_factory=time.time)
    adopted_pid: int | None = None  # 서버 재시작 전 띄운 프로세스를 입양한 경우
    cwd: Path | None = None  # 이 실행 전용(빈) 작업 디렉터리
    _log_fh: Any = None

    @property
    def pid(self) -> int | None:
        if self.popen is not None:
            return self.popen.pid
        return self.adopted_pid

    def poll(self) -> int | None:
        if self.popen is not None:
            return self.popen.poll()
        if self.adopted_pid is not None:
            return None if pid_alive(self.adopted_pid) else -1
        return -1

    @property
    def alive(self) -> bool:
        return self.poll() is None

    def returncode_info(self) -> dict[str, Any]:
        rc = self.poll()
        if rc is None:
            return {"running": True}
        out: dict[str, Any] = {"running": False, "exit_code": rc}
        if rc < 0:
            try:
                out["signal"] = signal.Signals(-rc).name
            except ValueError:
                out["signal"] = str(-rc)
        return out

    def _signal_group(self, sig: int) -> None:
        pid = self.pid
        if pid is None:
            return
        try:
            os.killpg(os.getpgid(pid), sig)
        except (ProcessLookupError, PermissionError, OSError):
            try:
                os.kill(pid, sig)
            except (ProcessLookupError, PermissionError, OSError):
                pass

    def wait(self, timeout: float) -> bool:
        """timeout 안에 종료되면 True."""
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if not self.alive:
                return True
            time.sleep(0.05)
        return not self.alive

    def terminate(self, grace: float = 3.0) -> str:
        """SIGTERM → (grace) → SIGKILL. 사용한 방법을 반환."""
        if not self.alive:
            self._close_log()
            return "already-exited"
        self._signal_group(signal.SIGTERM)
        if self.wait(grace):
            self._close_log()
            return "sigterm"
        self._signal_group(signal.SIGKILL)
        self.wait(2.0)
        self._close_log()
        return "sigkill"

    def _close_log(self) -> None:
        if self._log_fh is not None:
            try:
                self._log_fh.close()
            except OSError:
                pass
            self._log_fh = None
        with _OWNED_LOCK:
            if self.pid is not None:
                _OWNED.pop(self.pid, None)

    def mark_exited(self) -> None:
        if not self.alive:
            self._close_log()

    def cleanup_cwd(self) -> None:
        """종료 후 전용 작업 디렉터리가 비어 있으면 지운다 (무언가 남았으면 증거로 보존)."""
        if self.cwd is not None and not self.alive:
            try:
                self.cwd.rmdir()
            except OSError:
                pass


def pid_alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    # 좀비는 죽은 것으로 본다
    try:
        stat = Path(f"/proc/{pid}/stat").read_text()
        if ") Z " in stat or stat.split(") ")[-1].startswith("Z"):
            return False
    except OSError:
        pass
    return True


def pid_cmdline(pid: int) -> list[str]:
    try:
        raw = Path(f"/proc/{pid}/cmdline").read_bytes()
    except OSError:
        return []
    return [p.decode("utf-8", errors="replace") for p in raw.split(b"\x00") if p]


def spawn(argv: list[str], *, cwd: Path, log_path: Path) -> OpenOcdProcess:
    log_path.parent.mkdir(parents=True, exist_ok=True)
    fh = open(log_path, "ab", buffering=0)
    try:
        popen = subprocess.Popen(
            argv, cwd=str(cwd), stdin=subprocess.DEVNULL, stdout=fh, stderr=subprocess.STDOUT, start_new_session=True,
            close_fds=True,
        )
    except OSError as exc:
        fh.close()
        raise ToolMissing(f"OpenOCD 를 실행할 수 없습니다: {exc}", hint=f"실행 파일: {argv[0]}") from exc
    proc = OpenOcdProcess(popen=popen, argv=list(argv), log_path=log_path, cwd=cwd, _log_fh=fh)
    with _OWNED_LOCK:
        _OWNED[popen.pid] = proc
    return proc


@dataclass
class ReadyResult:
    ready: bool
    port: int | None
    reason: str
    elapsed: float
    errors: list[str]


def wait_ready(proc: OpenOcdProcess, *, log_offset: int, timeout: float, error_grace: float = 8.0) -> ReadyResult:
    """로그에서 "Listening on port N for tcl connections" 를 기다린다.

    실패: 프로세스 종료, 시간 초과, 또는 Error: 줄이 나온 뒤 error_grace 초 안에 준비되지 않음.
    (Error: 줄이 있어도 서버가 뜨면 성공으로 보고, 오류는 진단 정보로 돌려준다 — 배선 진단에 필요)
    """
    t0 = time.monotonic()
    deadline = t0 + timeout
    first_error_at: float | None = None
    errors: list[str] = []
    while True:
        text = read_log_since(proc.log_path, log_offset)
        errors = [ln[7:].strip() for ln in text.splitlines() if ln.startswith("Error: ")]
        m = _LISTEN_TCL.search(text)
        if m:
            return ReadyResult(True, int(m.group(1)), "listening", time.monotonic() - t0, errors)
        rc = proc.poll()
        if rc is not None:
            # 종료 직전에 찍힌 로그를 한 번 더 읽는다
            time.sleep(0.05)
            text = read_log_since(proc.log_path, log_offset)
            errors = [ln[7:].strip() for ln in text.splitlines() if ln.startswith("Error: ")]
            return ReadyResult(False, None, f"process-exited({rc})", time.monotonic() - t0, errors)
        now = time.monotonic()
        if errors and first_error_at is None:
            first_error_at = now
        if first_error_at is not None and now - first_error_at > error_grace:
            return ReadyResult(False, None, "errors-without-listening", now - t0, errors)
        if now > deadline:
            return ReadyResult(False, None, "timeout", now - t0, errors)
        time.sleep(0.05)


def read_log_since(path: Path, offset: int, max_bytes: int = 4 * 1024 * 1024) -> str:
    try:
        with open(path, "rb") as fh:
            fh.seek(offset)
            data = fh.read(max_bytes)
    except OSError:
        return ""
    return data.decode("utf-8", errors="replace")


def read_log_tail_text(path: Path | None, max_bytes: int = 512 * 1024) -> str:
    """로그 파일 끝부분 텍스트 (긴 세션에서도 최근 오류를 보기 위해)."""
    if path is None:
        return ""
    try:
        size = path.stat().st_size
        with open(path, "rb") as fh:
            fh.seek(max(0, size - max_bytes))
            data = fh.read()
    except OSError:
        return ""
    text = data.decode("utf-8", errors="replace")
    if size > max_bytes and "\n" in text:
        text = text.split("\n", 1)[1]  # 잘린 첫 줄 제거
    return text


def log_size(path: Path) -> int:
    try:
        return path.stat().st_size
    except OSError:
        return 0


def tail_lines(path: Path | None, n: int = 40, max_bytes: int = 256 * 1024) -> list[str]:
    """로그 파일 마지막 n 줄 (큰 파일도 끝부분만 읽는다)."""
    if path is None:
        return []
    try:
        size = path.stat().st_size
        with open(path, "rb") as fh:
            fh.seek(max(0, size - max_bytes))
            data = fh.read()
    except OSError:
        return []
    lines = data.decode("utf-8", errors="replace").splitlines()
    if size > max_bytes and lines:
        lines = lines[1:]  # 잘린 첫 줄 제거
    n = max(0, min(int(n), 2000))
    return lines[-n:] if n else []


def _cleanup_owned() -> None:
    """서버 프로세스 종료 시 우리가 띄운 OpenOCD 를 정리 (프로브 점유/고아 프로세스 방지)."""
    with _OWNED_LOCK:
        procs = list(_OWNED.values())
    for p in procs:
        try:
            if p.alive:
                log.info("terminating OpenOCD pid=%s at exit", p.pid)
                p.terminate(grace=2.0)
        except Exception:  # pragma: no cover - 종료 경로
            pass


atexit.register(_cleanup_owned)


__all__ = [
    "CfgRef",
    "OpenOcdProcess",
    "ReadyResult",
    "TRANSPORTS",
    "build_argv",
    "find_openocd",
    "log_size",
    "openocd_search_dirs",
    "openocd_version",
    "pid_alive",
    "pid_cmdline",
    "port_commands",
    "port_in_use",
    "read_log_since",
    "read_log_tail_text",
    "resolve_cfg",
    "scripts_dirs",
    "spawn",
    "tail_lines",
    "wait_ready",
]
