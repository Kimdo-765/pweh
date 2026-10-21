"""esptool 실행 래퍼: 실행 파일 탐색, 버전 감지(캐시), 실행 환경 중립화, 스트리밍 실행(취소·시간 초과), 출력 파서, 오류 매핑.

- 리눅스 esptool: 설정 ``tools.esptool``(= ``${PWEH_ESPTOOL:-esptool}``) → PATH 의 ``esptool`` / ``esptool.py``.
- Windows esptool.exe(방법 A): 설정 ``tools.esptool_win``(= ``${PWEH_ESPTOOL_WIN:-}``) → ``~/pweh-tools/esptool-win/…/esptool.exe``.
  WSL interop 으로 리눅스 파일시스템의 .exe 를 그대로 실행한다(포트는 ``COMn``, 출력 경로는 ``wslpath -w`` 로 바꾼 경로).
- 모든 실행은 인자 리스트 + 새 세션(프로세스 그룹) + stdin=/dev/null 이다(MCP stdio 채널을 상속하지 않음).
- 실행 환경(``child_env``): 실행마다 새 작업 디렉터리(run dir)에 빈 ``[esptool]`` 설정(``esptool.cfg``)을 쓰고
  ``ESPTOOL_CFGFILE`` 로 가리킨다. 이 환경변수는 esptool 의 설정 파일 탐색(현재 디렉터리 → ``~/.config/esptool``,
  Windows 는 ``%USERPROFILE%\\AppData\\Local\\esptool`` → 홈)보다 앞선다. 리눅스 백엔드는 ``ESPTOOL_*`` 를 모두 지우고
  HOME 도 run dir 로 바꾼다. Windows exe 는 Windows 쪽 사용자 환경변수를 그대로 물려받으므로(interop — 리눅스 쪽에서
  지울 수 없음) 기본값을 바꾸는 ``ESPTOOL_*`` 를 중립값으로 정해 WSLENV 로 넘긴다(경로는 ``/p`` 로 Windows 경로가 된다).
  서버가 만든 것이 아닌 설정 파일을 읽었다는 줄(``Loaded custom configuration from …``)이 보이면 바로 멈추고 오류로 다룬다
  (``ConfigWatch`` — esptool 5.3.1 이하는 설정의 custom_reset_sequence 를 코드로 실행한다).
- 취소·시간 초과·서버 종료: 리눅스 백엔드는 프로세스 그룹을 SIGTERM → SIGKILL 한다. Windows 백엔드는 그것만으로는 끝나지
  않는다 — esptool.exe 는 PyInstaller onefile 이라 interop 프로세스를 죽이면 부트로더만 끝나고 자식(실제 esptool)은 COM
  포트를 잡은 채 계속 돌며, 부트로더가 지우지 못한 ``%TEMP%\\_MEI*`` 가 남는다(실측). 그래서 명령줄 표식(``winproc.WinMatch``)
  으로 Windows 프로세스를 찾아 **자식부터** 끝내고(부트로더가 _MEI 를 지우고 스스로 끝남), 남은 것이 없는지 확인한다.
  끝까지 남은 PID 는 ``RunResult.orphans`` 에 담는다.
- stdout 과 stderr 를 하나로 합쳐 읽는다: esptool v5 는 오류(``ERROR: A fatal error occurred: …``)를 stderr 로,
  v4 는 stdout 으로 내보낸다. 진행률은 v4 가 ``N (P %)`` + 백스페이스, v5.0~5.3 이 ``\\r…[===>  ]  P%  a/b bytes...``,
  v5.4+(esp-pylib) 가 비대화형 출력에서 ``Reading from 0x… <막대>  P% a/b [t]`` 를 한 줄씩 쓰므로
  ``\\r``·``\\n``·``\\b`` 로 나눠 파싱한다. 출력 형식은 esptool 4.8.1 / 4.12.0 / 5.0.2 / 5.3.1 / 5.4.0 / 5.6.0 소스 기준이다.
- Windows esptool.exe 의 출력은 Windows ANSI 코드 페이지(예: 한국어 cp949)로 나온다. PyInstaller 로 얼린 파이썬은
  PYTHONIOENCODING·PYTHONUTF8 을 무시하므로(실측) 조각마다 엄격한 UTF-8 로 풀고, 실패하면 ANSI 코드 페이지로 푼다.
- esptool 은 read-flash 결과 파일을 **모든 데이터를 받은 뒤에만** 쓴다(중간 파일 없음). 그래서 정상 종료하지 않은 읽기에는
  esptool 이 쓴 부분 데이터가 없다. 단 Windows 자식 프로세스가 남아 있으면 나중에 파일을 쓸 수 있으므로 orphans 를 확인한다.
"""

from __future__ import annotations

import atexit
import codecs
import logging
import os
import re
import shutil
import signal
import subprocess
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Iterable, Sequence

from pweh.errors import PwehError, TimeoutExpired, ToolMissing
from pweh import procutil
from pweh.toolsdir import esptool_win_candidates

from . import winproc
from .policy import CONNECT_ATTEMPTS_DEFAULT, norm_name
from .winproc import WinMatch

log = logging.getLogger("pweh.esp")

INSTALL_HINT = (
    "esptool 을 찾을 수 없다. (1) `scripts/install.sh --only esptool` 로 ~/pweh-tools 에 설치한 뒤 `. ~/pweh-tools/env.sh` 를 "
    "source 한 셸에서 MCP 서버를 다시 시작하거나, (2) 방법 A(WSL): Espressif 공식 Windows 빌드(esptool-vX.Y.Z-windows-amd64.zip)의 "
    "esptool.exe 경로를 PWEH_ESPTOOL_WIN(또는 pipeline-config.yaml 의 tools.esptool_win)에, 리눅스 esptool 은 PWEH_ESPTOOL "
    "(tools.esptool)에 지정한다. 리눅스 파일시스템에 푼 .exe 는 `chmod +x` 가 필요하다."
)

# ---------------------------------------------------------------------------
# 실행 환경 (설정 파일·환경변수 중립화)
# ---------------------------------------------------------------------------

#: 하위 프로세스 환경에서 지우는 변수 (기본값을 바꾸거나 출력 형식을 바꾸는 것)
_STRIP_ENV_PREFIXES = ("ESPTOOL_",)
_STRIP_ENV = ("FORCE_COLOR", "TTY_COMPATIBLE", "TTY_INTERACTIVE", "CLICOLOR_FORCE", "ESPRESSIF_IDE_WS", "ESP_IDE_WS",
              "PYTHONHOME", "PYTHONPATH", "PYTHONSTARTUP", "PYTHONSAFEPATH", "PYTHONINSPECT")
#: run dir 에 쓰는 빈 설정 파일 (ESPTOOL_CFGFILE 이 가리킴)
CONFIG_NAME = "esptool.cfg"
EMPTY_CONFIG = "[esptool]\n"
#: 모든 esptool 버전이 받는 ESPTOOL_STUB_VERSION 값 (4.x·5.0~5.2 의 기본값. version 조회에 쓴다)
STUB_VERSION_ANY = "1"


def prepare_run_dir(run_dir: str | os.PathLike[str]) -> str:
    """run dir 에 빈 ``[esptool]`` 설정 파일을 쓰고 그 경로를 돌려준다."""
    path = os.path.join(os.fspath(run_dir), CONFIG_NAME)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(EMPTY_CONFIG)
    return path


def stub_version_for(major: int | None, minor: int | None) -> str:
    """ESPTOOL_STUB_VERSION 중립값: esptool 5.3 이상은 "2"(새 esp-flasher-stub, 그 버전들의 기본값), 그 밖은 "1".

    "1" 은 4.x·5.0~5.2 의 기본(레거시 스텁)이고 모든 버전의 선택지에 있다. 4.8.1 의 "2" 는 실험용 스텁이라 고르지 않는다.
    레거시 스텁도 이 서버의 명령(flash-id·get-security-info·read-flash + --after no-reset-stub)으로는 플래시를 쓰지 않는다.
    """
    if major is not None and (major > 5 or (major == 5 and (minor or 0) >= 3)):
        return "2"
    return STUB_VERSION_ANY


def neutral_esptool_env(config_path: str, stub_version: str) -> dict[str, str]:
    """esptool 기본값을 정하는 환경변수의 중립값 (명시 인자로 덮어쓰는 것도 Windows 쪽 값이 끼어들지 않게 같이 정한다).

    - ESPTOOL_CFGFILE: 서버가 만든 빈 설정 (설정 파일 탐색보다 앞선다)
    - ESPTOOL_STUB_VERSION: stub_version_for (숨은 --stub-version 의 기본값. 레거시 스텁 강제를 막는다)
    - ESPTOOL_OPEN_PORT_ATTEMPTS=1 (기본. 0 이면 포트 열기를 끝없이 재시도한다)
    - ESPTOOL_FS=keep (read-flash 의 --flash-size 기본값)
    - ESPTOOL_ENV_FPGA=0 (1 이면 FPGA 용 긴 시간 초과)
    - ESPTOOL_CHIP/BAUD/BEFORE/AFTER/CONNECT_ATTEMPTS: esptool 기본값 (서버는 항상 명시 인자로 준다. click 이 기본값도 검사하므로
      Windows 쪽에 잘못된 값이 있으면 version 조회부터 실패하는 것을 막는다)
    빈 값은 WSLENV 로 넘어가지 않아(실측) Windows 쪽 값을 지울 수 없으므로 모두 비어 있지 않은 값이다.
    ESP_IDE_WS(IDE 웹소켓 로그 미러)는 비어 있지 않은 중립값이 없어 덮어쓰지 않는다 — esp-pylib 은 연결 실패를 조용히 무시하고 기기 동작은 바꾸지 않는다.
    """
    return {
        "ESPTOOL_CFGFILE": config_path,
        "ESPTOOL_STUB_VERSION": stub_version,
        "ESPTOOL_OPEN_PORT_ATTEMPTS": "1",
        "ESPTOOL_FS": "keep",
        "ESPTOOL_ENV_FPGA": "0",
        "ESPTOOL_CHIP": "auto",
        "ESPTOOL_BAUD": "115200",
        "ESPTOOL_BEFORE": "default-reset",
        "ESPTOOL_AFTER": "hard-reset",
        "ESPTOOL_CONNECT_ATTEMPTS": str(CONNECT_ATTEMPTS_DEFAULT),
    }


def child_env(*, windows: bool, run_dir: str | os.PathLike[str], stub_version: str = STUB_VERSION_ANY) -> dict[str, str]:
    """esptool 하위 프로세스 환경 (run dir 에는 prepare_run_dir 로 빈 설정을 미리 써 둔다).

    - 공통: ESPTOOL_*·강제 컬러·IDE 웹소켓·PYTHONPATH 류 제거 → neutral_esptool_env, NO_COLOR=1.
    - 리눅스: HOME=run dir (홈 설정 탐색 차단), PYTHONIOENCODING=utf-8, PYTHONUNBUFFERED=1.
    - Windows: WSLENV 를 새로 만들어 NO_COLOR·TTY_COMPATIBLE=0·TTY_INTERACTIVE=0 과 ESPTOOL_* 중립값만 넘긴다(ESPTOOL_CFGFILE/p).
      PYTHONIOENCODING·PYTHONUNBUFFERED 는 넘기지 않는다(얼린 파이썬이 무시함. rich 는 줄마다 flush 한다).
    """
    run_dir = os.fspath(run_dir)
    env = {k: v for k, v in os.environ.items() if not k.startswith(_STRIP_ENV_PREFIXES) and k not in _STRIP_ENV}
    neutral = neutral_esptool_env(os.path.join(run_dir, CONFIG_NAME), stub_version)
    env.update(neutral)
    env["NO_COLOR"] = "1"
    if windows:
        # WSL_INTEROP / WSL_DISTRO_NAME 은 물려받은 값을 지우지 않을 뿐 interop 에 필요하지 않다 (WSL_INTEROP 이 없어도 interop 은
        # 기본 소켓으로 동작하고, WSL_DISTRO_NAME 은 표시용). WSLENV 는 새로 만든다(물려받은 전달 목록을 쓰지 않음).
        env["TTY_COMPATIBLE"] = "0"
        env["TTY_INTERACTIVE"] = "0"
        names = ["NO_COLOR", "TTY_COMPATIBLE", "TTY_INTERACTIVE"]
        names += [f"{k}/p" if k == "ESPTOOL_CFGFILE" else k for k in neutral]
        env["WSLENV"] = ":".join(names)
    else:
        env["HOME"] = run_dir
        env["PYTHONIOENCODING"] = "utf-8"
        env["PYTHONUNBUFFERED"] = "1"
    return env


_CUSTOM_CFG_RE = re.compile(r"^Loaded custom configuration from (.+?)(\s+\(set with ESPTOOL_CFGFILE\))?\s*$")


def _norm_cfg_path(p: str) -> str:
    return p.strip().strip('"').replace("/", "\\").rstrip("\\").lower()


class ConfigWatch:
    """esptool 이 서버가 만든 빈 설정이 아닌 설정 파일을 읽었는지 줄 단위로 본다 (OutputCollector(on_line=…))."""

    def __init__(self, allowed: Iterable[str]) -> None:
        self.allowed = [p for p in allowed if p]
        self._allowed_norm = {_norm_cfg_path(p) for p in self.allowed}
        self.loaded: list[str] = []
        self.foreign: str | None = None

    def line(self, text: str) -> None:
        m = _CUSTOM_CFG_RE.match(text.strip())
        if not m:
            return
        path = m.group(1).strip()
        self.loaded.append(path)
        if self.foreign is None and _norm_cfg_path(path) not in self._allowed_norm:
            self.foreign = path


# ---------------------------------------------------------------------------
# 실행 파일 탐색
# ---------------------------------------------------------------------------


def _is_exe(p: str) -> bool:
    return os.path.isfile(p) and os.access(p, os.X_OK)


def locate_linux_esptool(configured: str | None) -> str:
    """리눅스 esptool 실행 파일 경로 (설정값 → PATH 의 esptool / esptool.py). 없으면 ToolMissing."""
    tried: list[str] = []
    cands: list[str] = []
    for c in (configured, os.environ.get("PWEH_ESPTOOL"), "esptool", "esptool.py"):
        c = (c or "").strip()
        if c and c not in cands:
            cands.append(c)
    for cand in cands:
        cand = os.path.expanduser(cand)
        tried.append(cand)
        if os.sep in cand:
            if _is_exe(cand):
                return os.path.abspath(cand)
        else:
            found = shutil.which(cand)
            if found and _is_exe(found):
                return found
    raise ToolMissing(f"리눅스 esptool 실행 파일이 없습니다 (시도: {', '.join(tried)})", hint=INSTALL_HINT)


def windows_exe_candidates(configured: str | None, tools_dir: Path | None) -> list[tuple[str, str]]:
    """(경로, 출처) 후보. 출처: config | env | pweh-tools. 규칙은 코어 ``pweh.toolsdir.esptool_win_candidates`` 하나다(doctor·pweh env 와 같음)."""
    return esptool_win_candidates(configured, os.environ.get("PWEH_ESPTOOL_WIN"), tools_dir)


def exe_image(path: str) -> str:
    """Windows 프로세스 이미지 이름 (Win32_Process.Name) = 실행 파일 이름."""
    return str(path).replace("\\", "/").rsplit("/", 1)[-1]


# ---------------------------------------------------------------------------
# 프로세스 실행 (스트리밍)
# ---------------------------------------------------------------------------


@dataclass
class RunResult:
    argv: list[str]
    returncode: int | None
    timed_out: bool = False
    idle_timed_out: bool = False
    cancelled: bool = False
    duration_s: float = 0.0
    output_bytes: int = 0
    pid: int | None = None
    #: 끝내려 했지만 끝까지 남은 Windows esptool.exe PID (방법 A)
    orphans: list[int] = field(default_factory=list)
    #: Windows 프로세스가 남았는지 확인하지 못함 (powershell 실패)
    orphan_check_failed: bool = False
    cleanup_verified: bool = True
    start_ticks: int | None = None
    process_token: int | None = None  # 실행 객체별 내부 세대, PID 재사용과 분리

    @property
    def ok(self) -> bool:
        return self.cleanup_verified and self.returncode == 0 and not (self.timed_out or self.idle_timed_out or self.cancelled)


def kill_process_group(proc: subprocess.Popen, grace_s: float = 2.0) -> bool:
    """소유한 POSIX 그룹의 신원·종료를 확인하고 마지막에 리더를 거둔다."""
    with _CLEANUP_LOCK:
        if getattr(proc, "_pweh_cleanup_verified", False):
            return True
        ticks, pidfd = _CHILD_IDS.get(id(proc), (None, None))
        if ticks is None:
            return False
        procutil.kill_process_group(proc.pid, grace=grace_s, expect_start_ticks=ticks, pidfd=pidfd)
        if procutil.process_group_empty(proc.pid, expect_start_ticks=ticks) is not True:
            return False
        proc.wait(timeout=5)
        if pidfd is not None:
            os.close(pidfd)
        _CHILD_IDS.pop(id(proc), None)
        proc._pweh_cleanup_verified = True
        return True


#: 방법 A 종료 시간 (테스트에서 줄인다)
WIN_CHILD_WAIT_S = 5.0  # 부트로더만 있고 자식이 아직 없을 때(압축 푸는 중) 자식을 기다리는 시간
WIN_BOOT_EXIT_S = 5.0  # 자식을 끝낸 뒤 부트로더가 _MEI 를 지우고 끝나기를 기다리는 시간
WIN_SETTLE_S = 10.0  # 남은 Windows 프로세스가 없어질 때까지 다시 끝내며 확인하는 시간
WIN_AGE_SLACK_S = 5.0  # 이번 실행보다 이만큼 먼저 생긴 프로세스까지 이번 실행의 것으로 본다


def stop_windows_run(proc: subprocess.Popen, match: WinMatch, started: float, *, quick: bool = False) -> tuple[list[int], bool]:
    """방법 A 종료: (1) PyInstaller 자식(실제 esptool)을 먼저 끝냄 → 부트로더가 _MEI 를 지우고 스스로 끝나기를 기다림
    → (2) 리눅스 interop 프로세스 그룹 종료(남은 부트로더) → (3) 표식이 맞는 Windows 프로세스가 없어질 때까지 다시 끝내며 확인.

    반환: (끝까지 남은 PID, 확인 성공 여부). started 는 이 실행을 띄운 time.monotonic() 값.
    """
    scale = 0.4 if quick else 1.0

    def find() -> list[winproc.WinProc]:
        limit = time.monotonic() - started + WIN_AGE_SLACK_S
        return [p for p in winproc.query(match.image) if match.matches(p) and (p.age_s is None or p.age_s <= limit)]

    verified = True
    try:
        procs = find()
        if not procutil.child_exited(proc.pid):
            deadline = time.monotonic() + WIN_CHILD_WAIT_S * scale
            while procs and not winproc.children_first(procs)[0] and not procutil.child_exited(proc.pid) and time.monotonic() < deadline:
                time.sleep(0.3)
                procs = find()
            kids, _rest = winproc.children_first(procs)
            if kids:
                winproc.terminate([p.pid for p in kids])
                boot_deadline = time.monotonic() + WIN_BOOT_EXIT_S * scale
                while not procutil.child_exited(proc.pid) and time.monotonic() < boot_deadline:
                    time.sleep(0.05)
    except Exception:  # noqa: BLE001 - 조회 실패해도 리눅스 쪽은 끝낸다
        log.warning("Windows esptool.exe 조회/종료 실패", exc_info=True)
        verified = False
    verified = kill_process_group(proc, grace_s=0.5 if quick else 2.0) and verified
    if not verified:
        return [], False
    # 막 띄운 실행이면 Windows 프로세스가 interop 종료 직후에 나타날 수 있어 '없음'을 두 번 확인한다
    need_empty = 2 if time.monotonic() - started < 5.0 else 1
    empty = 0
    deadline = time.monotonic() + WIN_SETTLE_S * scale
    while True:
        try:
            rem = find()
        except Exception:  # noqa: BLE001
            log.warning("Windows esptool.exe 확인 실패", exc_info=True)
            return [], False
        if not rem:
            empty += 1
            if empty >= need_empty:
                return [], True
            time.sleep(1.0)
            continue
        empty = 0
        if time.monotonic() >= deadline:
            return sorted(p.pid for p in rem), True
        kids, rest = winproc.children_first(rem)
        winproc.terminate([p.pid for p in kids] + [p.pid for p in rest])
        time.sleep(0.5)


# PID를 거둔 뒤에도 Windows settle이 남을 수 있으므로 id(Popen) 세대로 보관한다.
_LIVE: dict[int, tuple[subprocess.Popen, WinMatch | None, float]] = {}
_LIVE_LOCK = threading.Lock()
_CHILD_IDS: dict[int, tuple[int | None, int | None]] = {}
_CLEANUP_LOCK = threading.Lock()


def _kill_all_live() -> None:
    """서버 종료 시 남은 esptool 프로세스 정리 (새 세션이라 자동으로 죽지 않음. Windows 는 자식부터)."""
    with _LIVE_LOCK:
        items = list(_LIVE.values())
    for proc, match, started in items:
        verified = False
        if match is not None:
            try:
                remaining, verified = stop_windows_run(proc, match, started, quick=True)
                verified = verified and not remaining
            except Exception:  # pragma: no cover
                kill_process_group(proc, grace_s=0.5)
        else:
            verified = kill_process_group(proc, grace_s=0.5)
        if verified:
            with _LIVE_LOCK:
                _LIVE.pop(id(proc), None)


atexit.register(_kill_all_live)


def live_process_count() -> int:
    with _LIVE_LOCK:
        return len(_LIVE)  # 리더 종료 뒤에도 미확인 자식은 live 소유 기록을 유지한다


def cleanup_owned(pid: int, *, process_token: int | None = None) -> bool:
    """이 runner가 보존한 실행만 정리한다. 임의 PID를 종료하지 않는다."""
    with _LIVE_LOCK:
        matches = [(token, item) for token, item in _LIVE.items()
                   if item[0].pid == pid and (process_token is None or token == process_token)]
    if not matches:
        return True
    if len(matches) != 1:
        return False
    token, (proc, match, started) = matches[0]
    if match is not None:
        remaining, verified = stop_windows_run(proc, match, started, quick=True)
        verified = verified and not remaining
    else:
        verified = kill_process_group(proc, grace_s=0.5)
    if verified:
        with _LIVE_LOCK:
            _LIVE.pop(token, None)
    return verified


class _WindowsDecoder:
    """Windows esptool.exe 출력 디코더: 조각마다 엄격한 UTF-8(조각 경계의 미완성 문자는 다음 조각으로), 실패하면 ANSI 코드 페이지."""

    def __init__(self) -> None:
        self._utf8 = codecs.getincrementaldecoder("utf-8")("strict")
        self._ansi: str | None = None

    def _ansi_codec(self) -> str:
        if self._ansi is None:
            try:
                self._ansi = winproc.windows_ansi_encoding()
            except Exception:  # noqa: BLE001
                self._ansi = "latin-1"
        return self._ansi

    def decode(self, data: bytes, final: bool = False) -> str:
        pending = self._utf8.getstate()[0]
        try:
            return self._utf8.decode(data, final)
        except UnicodeDecodeError:
            self._utf8.reset()
            return (pending + data).decode(self._ansi_codec(), "replace")


def run_streaming(
    argv: Sequence[str],
    *,
    timeout: float,
    on_text: Callable[[str], None],
    cancel: Callable[[], bool] | None = None,
    idle_timeout: float | None = None,
    cwd: str | os.PathLike[str] | None = None,
    env: dict[str, str] | None = None,
    poll_s: float = 0.1,
    missing_hint: str = INSTALL_HINT,
    win_match: WinMatch | None = None,
    windows_output: bool = False,
    process_state: dict[str, Any] | None = None,
) -> RunResult:
    """stdout+stderr 를 합쳐 읽으며 텍스트 조각을 on_text 로 넘긴다(펌프 스레드에서 호출).

    timeout(전체)·idle_timeout(출력 없이 지난 시간)·cancel 이면 끝낸다: win_match 가 있으면(Windows esptool.exe)
    stop_windows_run 으로 Windows 자식부터, 없으면 프로세스 그룹을 SIGTERM → SIGKILL.
    windows_output(또는 win_match) 이면 출력을 UTF-8 → Windows ANSI 코드 페이지 순서로 푼다.
    """
    argv = [str(a) for a in argv]
    t0 = time.monotonic()
    try:
        proc = subprocess.Popen(
            argv,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            cwd=str(cwd) if cwd else None,
            env=env,
            start_new_session=True,
            close_fds=True,
        )
    except FileNotFoundError as exc:
        raise ToolMissing(f"실행 파일을 실행할 수 없습니다: {argv[0]} ({exc})", hint=missing_hint)
    except PermissionError as exc:
        raise ToolMissing(f"실행 권한이 없습니다: {argv[0]} ({exc})", hint=missing_hint + " (chmod +x 확인)")
    except OSError as exc:  # interop 비활성(Exec format error) 등
        raise ToolMissing(f"실행 실패: {argv[0]} ({exc})", hint=missing_hint)
    with _LIVE_LOCK:
        _LIVE[id(proc)] = (proc, win_match, t0)
        st = procutil.proc_stat(proc.pid)
        _CHILD_IDS[id(proc)] = (st[1] if st else None, procutil.open_pidfd(proc.pid))
    start_ticks = _CHILD_IDS[id(proc)][0]
    if process_state is not None:
        process_state.update(pid=proc.pid, start_ticks=start_ticks, process_token=id(proc), cleanup_verified=False)
    last_out = [time.monotonic()]
    total = [0]
    orphans: list[int] = []
    check_failed = [False]
    cleanup_verified = [False]
    windows = windows_output or win_match is not None

    def pump() -> None:
        assert proc.stdout is not None
        fd = proc.stdout.fileno()
        dec: Any = _WindowsDecoder() if windows else codecs.getincrementaldecoder("utf-8")(errors="replace")
        while True:
            try:
                chunk = os.read(fd, 65536)
            except OSError:
                break
            if not chunk:
                break
            total[0] += len(chunk)
            last_out[0] = time.monotonic()
            try:
                on_text(dec.decode(chunk))
            except Exception:  # pragma: no cover - 파서 오류가 프로세스 관리를 막지 않게
                log.exception("esptool output handler failed")
        try:
            tail = dec.decode(b"", final=True)
            if tail:
                on_text(tail)
        except Exception:  # pragma: no cover
            pass

    def stop() -> None:
        if win_match is not None:
            rem, ok = stop_windows_run(proc, win_match, t0)
            orphans[:] = rem
            check_failed[0] = not ok
            cleanup_verified[0] = ok and not rem
        else:
            cleanup_verified[0] = kill_process_group(proc)

    th = threading.Thread(target=pump, name="pweh-esptool-out", daemon=True)
    timed_out = idle_out = cancelled = False
    try:
        th.start()
        while True:
            if procutil.child_exited(proc.pid):
                break
            time.sleep(poll_s)
            now = time.monotonic()
            if cancel is not None and cancel():
                cancelled = True
                stop()
                break
            if now - t0 > timeout:
                timed_out = True
                stop()
                break
            if idle_timeout and now - last_out[0] > idle_timeout:
                idle_out = True
                stop()
                break
    except BaseException:
        stop()
        raise
    finally:
        if not cleanup_verified[0]:
            stop()
        if process_state is not None:
            process_state.update(cleanup_verified=cleanup_verified[0], orphans=list(orphans),
                                 orphan_check_failed=check_failed[0])
        if th.ident is not None:
            th.join(timeout=5.0)
        if cleanup_verified[0]:
            with _LIVE_LOCK:
                _LIVE.pop(id(proc), None)
        try:
            if proc.stdout is not None:
                proc.stdout.close()
        except OSError:
            pass
    return RunResult(argv=argv, returncode=proc.returncode, timed_out=timed_out, idle_timed_out=idle_out,
                     cancelled=cancelled, duration_s=time.monotonic() - t0, output_bytes=total[0], pid=proc.pid,
                     orphans=list(orphans), orphan_check_failed=check_failed[0],
                     cleanup_verified=cleanup_verified[0], start_ticks=start_ticks, process_token=id(proc))


# ---------------------------------------------------------------------------
# 출력 수집 (진행률 분리)
# ---------------------------------------------------------------------------

_ANSI_RE = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]|\x1b[()][0-9A-Za-z]|\x1b[=>]")
#: v4: "4096 (0 %)"
_PROG_V4 = re.compile(r"^(\d+) \((\d{1,3}) %\)$")
#: v5: "Reading from 0x00001000 … 12.5% …"
_PROG_V5 = re.compile(r"Reading from (0x[0-9A-Fa-f]+)\b.*?(\d{1,3}(?:\.\d+)?)\s?%")
#: v5.0~5.3 접미사 "4096/4194304 bytes..."
_PROG_V5_BYTES = re.compile(r"(\d+)/(\d+) bytes")
#: v5.4+ 접미사 "1.20MB/4.00MB"
_PROG_V5_HUMAN = re.compile(r"(\d+(?:\.\d+)?)(B|kB|MB|GB)/(\d+(?:\.\d+)?)(B|kB|MB|GB)")
_UNIT = {"B": 1, "kB": 1024, "MB": 1024**2, "GB": 1024**3}


@dataclass
class Progress:
    percent: float
    done: int | None = None
    total: int | None = None
    address: int | None = None


class OutputCollector:
    """esptool 출력 조각을 받아 진행률 줄과 일반 줄로 나눈다(스레드 하나에서만 feed). on_line 은 일반 줄마다 불린다."""

    def __init__(self, on_progress: Callable[[Progress], None] | None = None, *, log_every_pct: float = 5.0,
                 max_lines: int = 20000, on_line: Callable[[str], None] | None = None) -> None:
        self._buf = ""
        self.lines: list[str] = []
        self.log_lines: list[str] = []
        self.progress: Progress | None = None
        self.progress_lines = 0
        self._on_progress = on_progress
        self._on_line = on_line
        self._log_every = log_every_pct
        self._last_logged_pct = -1e9
        self._max_lines = max_lines
        self.dropped = 0

    def feed(self, text: str) -> None:
        self._buf += text
        parts = re.split(r"[\r\n\b]+", self._buf)
        self._buf = parts.pop()  # 마지막은 미완성 조각
        for seg in parts:
            self._segment(seg)
        # 백스페이스로만 이어지는 v4 진행률이 무한히 쌓이지 않게
        if len(self._buf) > 65536:
            self._segment(self._buf)
            self._buf = ""

    def close(self) -> None:
        if self._buf:
            self._segment(self._buf)
            self._buf = ""

    def _segment(self, seg: str) -> None:
        s = _ANSI_RE.sub("", seg).replace("\x00", "").rstrip()
        if not s.strip():
            return
        prog = parse_progress(s)
        if prog is not None:
            self.progress = prog
            self.progress_lines += 1
            if self._on_progress is not None:
                try:
                    self._on_progress(prog)
                except Exception:  # pragma: no cover
                    log.debug("on_progress failed", exc_info=True)
            if prog.percent - self._last_logged_pct >= self._log_every or prog.percent >= 100.0:
                self._last_logged_pct = prog.percent
                self._add_log(s.strip())
            return
        if self._on_line is not None:
            try:
                self._on_line(s)
            except Exception:  # pragma: no cover
                log.debug("on_line failed", exc_info=True)
        if len(self.lines) < self._max_lines:
            self.lines.append(s)
        else:
            self.dropped += 1
        self._add_log(s)

    def _add_log(self, s: str) -> None:
        if len(self.log_lines) < self._max_lines:
            self.log_lines.append(s)

    @property
    def text(self) -> str:
        return "\n".join(self.lines)

    def log_text(self) -> str:
        out = "\n".join(self.log_lines)
        if self.dropped:
            out += f"\n…({self.dropped} 줄 생략)…"
        return out


def parse_progress(s: str) -> Progress | None:
    t = s.strip()
    m = _PROG_V4.match(t)
    if m:
        return Progress(percent=float(m.group(2)), done=int(m.group(1)))
    m = _PROG_V5.search(t)
    if m:
        p = Progress(percent=min(100.0, float(m.group(2))), address=int(m.group(1), 16))
        mb = _PROG_V5_BYTES.search(t)
        if mb:
            p.done, p.total = int(mb.group(1)), int(mb.group(2))
        else:
            mh = _PROG_V5_HUMAN.search(t)
            if mh:
                p.done = int(float(mh.group(1)) * _UNIT[mh.group(2)])
                p.total = int(float(mh.group(3)) * _UNIT[mh.group(4)])
        return p
    return None


# ---------------------------------------------------------------------------
# 버전 감지 (경로·mtime·크기별 캐시)
# ---------------------------------------------------------------------------

_VERSION_RE = re.compile(r"esptool(?:\.py)?\s+v(\d+)\.(\d+)(?:\.(\d+))?(\S*)")
_VERSION_CACHE: dict[tuple[Any, ...], dict[str, Any]] = {}
_VERSION_LOCK = threading.Lock()


def _file_key(path: str) -> tuple[Any, ...]:
    try:
        st = os.stat(path)
        return (os.path.realpath(path), st.st_mtime_ns, st.st_size)
    except OSError:
        return (path, 0, 0)


def parse_version_output(text: str) -> dict[str, Any] | None:
    m = _VERSION_RE.search(text)
    if not m:
        # 'version' 출력의 둘째 줄(숫자만)
        m2 = re.search(r"^\s*(\d+)\.(\d+)(?:\.(\d+))?\s*$", text, re.M)
        if not m2:
            return None
        major, minor, patch = int(m2.group(1)), int(m2.group(2)), int(m2.group(3) or 0)
        return {"version": f"{major}.{minor}.{patch}", "major": major, "minor": minor}
    major, minor, patch = int(m.group(1)), int(m.group(2)), int(m.group(3) or 0)
    ver = f"{major}.{minor}" + (f".{m.group(3)}" if m.group(3) is not None else "") + (m.group(4) or "")
    return {"version": ver, "major": major, "minor": minor}


def detect_version(path: str, *, windows: bool, run_dir: str | os.PathLike[str], timeout: float = 60.0,
                   use_cache: bool = True) -> dict[str, Any]:
    """``<esptool> version`` 실행 → {version, major, minor, raw}. 실패하면 PwehError. run_dir 은 prepare_run_dir 를 거친 빈 디렉터리."""
    key = (_file_key(path), windows)
    if use_cache:
        with _VERSION_LOCK:
            if key in _VERSION_CACHE:
                return dict(_VERSION_CACHE[key])
    col = OutputCollector()
    match = WinMatch(image=exe_image(path), sequences=(("version",),)) if windows else None
    res = run_streaming([path, "version"], timeout=timeout, on_text=col.feed, cwd=run_dir,
                        env=child_env(windows=windows, run_dir=run_dir, stub_version=STUB_VERSION_ANY),
                        win_match=match, windows_output=windows)
    col.close()
    text = col.text
    if res.timed_out:
        raise TimeoutExpired(f"{path} version 이 {timeout:.0f}초 안에 끝나지 않았습니다.",
                             hint="Windows esptool.exe 첫 실행은 압축 해제로 느릴 수 있다. 다시 시도하라.")
    info = parse_version_output(text)
    if not res.cleanup_verified or res.returncode != 0 or info is None:
        raise PwehError(
            f"esptool 버전을 확인할 수 없습니다 (rc={res.returncode}): {text.strip()[:300]}",
            code="esp_version_failed",
            hint=("WSL interop 이 꺼져 있거나(.exe 실행 불가) 실행 파일이 esptool 이 아닐 수 있다. " + INSTALL_HINT),
            data={"output": text[-2000:]},
        )
    info["raw"] = text[-500:]
    with _VERSION_LOCK:
        _VERSION_CACHE[key] = dict(info)
    return info


def clear_cache() -> None:
    with _VERSION_LOCK:
        _VERSION_CACHE.clear()


# ---------------------------------------------------------------------------
# argv 조립 (버전별 명령/모드 이름)
# ---------------------------------------------------------------------------


def versioned(name: str, major: int | None) -> str:
    """v5 는 하이픈(read-flash, no-reset-stub), v4 와 버전 미상은 밑줄(read_flash, no_reset_stub — v5 도 경고와 함께 받는다)."""
    n = norm_name(name)
    return n if (major is not None and major >= 5) else n.replace("-", "_")


def build_argv(
    exe: str,
    *,
    major: int | None,
    chip: str,
    port: str,
    baud: int,
    before: str,
    after: str,
    no_stub: bool,
    command: str,
    args: Sequence[str] = (),
    connect_attempts: int = CONNECT_ATTEMPTS_DEFAULT,
) -> list[str]:
    argv = [exe, "--chip", chip, "--port", port, "--baud", str(int(baud)),
            "--before", versioned(before, major), "--after", versioned(after, major)]
    if no_stub:
        argv.append("--no-stub")
    argv += ["--connect-attempts", str(int(connect_attempts)), versioned(command, major), *[str(a) for a in args]]
    return argv


def info_win_match(exe: str, port: str, command: str, major: int | None) -> WinMatch:
    """정보 명령의 Windows 프로세스 표식: ``--port COMn`` + 명령 이름 (같은 포트의 호출은 서버가 한 번에 하나만 돌린다)."""
    return WinMatch(image=exe_image(exe), sequences=(("--port", port), (versioned(command, major),)))


def output_win_match(exe: str, output_token: str) -> WinMatch:
    """read-flash 의 Windows 프로세스 표식: 서버가 예약한 UNC 출력 경로 (유일)."""
    return WinMatch(image=exe_image(exe), sequences=((output_token,),))


# ---------------------------------------------------------------------------
# 출력 파서 (v4 / v5 공통)
# ---------------------------------------------------------------------------

_FLASH_SIZES = {"256KB": 256 * 1024, "512KB": 512 * 1024, "1MB": 1 << 20, "2MB": 2 << 20, "4MB": 4 << 20, "8MB": 8 << 20,
                "16MB": 16 << 20, "32MB": 32 << 20, "64MB": 64 << 20, "128MB": 128 << 20, "256MB": 256 << 20}

#: JEDEC 제조사 ID (ESP 모듈에 흔한 것, 추정용)
JEDEC_VENDORS = {
    "c8": "GigaDevice", "ef": "Winbond", "20": "XMC (또는 Micron)", "68": "BoyaMicro", "85": "Puya", "c2": "Macronix",
    "0b": "XTX", "5e": "Zbit", "9d": "ISSI", "a1": "Fudan Micro", "1c": "EON", "46": "FM (Fudan)?", "01": "Spansion/Infineon",
}

_MAC_RE = re.compile(r"[0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5,7}")  # 6 바이트 MAC 또는 8 바이트 EUI-64
_MAC_EXT_RE = re.compile(r"[0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){1,7}")  # C6/H2/C5 의 MAC_EXT 는 보통 2 바이트(ff:fe)
_MAC6_RE = re.compile(r"[0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5}")


def flash_size_bytes(text: str | None) -> int | None:
    if not text:
        return None
    return _FLASH_SIZES.get(text.strip().upper())


def _line_value(text: str, label: str) -> str | None:
    """'Label:  value' (v5 정렬 형식과 v4 'Label: value' 공통)."""
    m = re.search(r"^\s*" + re.escape(label) + r":\s*(.+?)\s*$", text, re.M)
    return m.group(1) if m else None


def parse_connect(text: str) -> dict[str, Any]:
    """연결 배너: 칩 종류/설명/리비전, 기능, 수정 진동자, USB 모드, MAC, Secure Download Mode, 스텁 여부, 설정 파일.

    MAC: ``mac`` 은 esptool 이 'MAC:' 로 찍은 값(C6/H2/C5 는 8 바이트 EUI-64), ``base_mac`` 은 항상 6 바이트 MAC
    ('BASE MAC:' 이 있으면 그 값, 없으면 6 바이트 'MAC:'), ``mac_ext`` 는 'MAC_EXT:'(2~8 바이트).
    """
    out: dict[str, Any] = {
        "chip": None, "chip_description": None, "chip_revision": None, "features": [], "crystal_mhz": None,
        "usb_mode": None, "mac": None, "base_mac": None, "mac_ext": None, "secure_download_mode": False,
        "stub": False, "stub_reused": False, "legacy_stub": False, "detected_chip": None, "connected": False,
        "baud_changed_to": None, "custom_config": None, "custom_config_via_env": False,
    }
    m = re.search(r"^Detecting chip type\.\.\.\s*(ESP\S+)", text, re.M)
    if m:
        out["detected_chip"] = m.group(1)
    m = re.search(r"^Connected to (ESP\S+) on (.+?):\s*$", text, re.M)  # v5
    if m:
        out["chip"] = m.group(1)
        out["connected"] = True
    desc = _line_value(text, "Chip type")  # v5
    if desc is None:
        m = re.search(r"^Chip is (.+?)\s*$", text, re.M)  # v4
        desc = m.group(1) if m else None
    if desc:
        out["connected"] = True
        if desc.endswith("in Secure Download Mode"):
            out["secure_download_mode"] = True
            out["chip"] = out["chip"] or desc.replace("in Secure Download Mode", "").strip()
        else:
            out["chip_description"] = desc
            mm = re.match(r"(ESP[\w-]+)", desc)
            if mm and not out["chip"]:
                out["chip"] = mm.group(1)
            mr = re.search(r"\(revision (v[\d.]+)\)", desc)
            if mr:
                out["chip_revision"] = mr.group(1)
    if out["chip"] is None and out["detected_chip"]:
        out["chip"] = out["detected_chip"]
    feats = _line_value(text, "Features")
    if feats:
        out["features"] = [f.strip() for f in feats.split(",") if f.strip()]
    m = re.search(r"^(?:Crystal frequency:\s*|Crystal is )(\d+)\s*MHz", text, re.M)
    if m:
        out["crystal_mhz"] = int(m.group(1))
    usb = _line_value(text, "USB mode")
    if usb:
        out["usb_mode"] = usb
    for key, label, rx in (("mac", "MAC", _MAC_RE), ("base_mac", "BASE MAC", _MAC6_RE), ("mac_ext", "MAC_EXT", _MAC_EXT_RE)):
        v = _line_value(text, label)
        if v and rx.fullmatch(v):
            out[key] = v.lower()
    if out["base_mac"] is None and out["mac"] and _MAC6_RE.fullmatch(out["mac"]):
        out["base_mac"] = out["mac"]
    out["stub_reused"] = bool(re.search(r"^(?:Stub flasher is already running|Stub is already running)", text, re.M))
    out["stub"] = out["stub_reused"] or bool(re.search(r"^(?:Stub flasher running\.|Stub running\.\.\.)", text, re.M))
    out["legacy_stub"] = "Using the deprecated legacy stub flasher" in text
    m = re.search(r"^Changing baud rate to (\d+)", text, re.M)
    if m and re.search(r"^Changed\.", text, re.M):
        out["baud_changed_to"] = int(m.group(1))
    for line in text.splitlines():
        mc = _CUSTOM_CFG_RE.match(line.strip())
        if mc:
            out["custom_config"] = mc.group(1).strip()
            out["custom_config_via_env"] = bool(mc.group(2))
            break
    return out


def parse_flash_id(text: str) -> dict[str, Any] | None:
    man = _line_value(text, "Manufacturer")
    dev = _line_value(text, "Device")
    if man is None and dev is None:
        return None
    size = _line_value(text, "Detected flash size")
    out: dict[str, Any] = {
        "manufacturer_id": man.lower() if man else None,
        "manufacturer": JEDEC_VENDORS.get((man or "").lower()),
        "device_id": dev.lower() if dev else None,
        "size": None if (size is None or size == "Unknown") else size,
        "size_bytes": flash_size_bytes(size),
        "type_efuse": _line_value(text, "Flash type set in eFuse"),
        "voltage": None,
        "voltage_source": None,
    }
    m = re.search(r"^Flash voltage set by (.+?)(?::| to) ([\d.]+V)\s*$", text, re.M)
    if m:
        out["voltage_source"], out["voltage"] = m.group(1), m.group(2)
    return out


#: ROM 보안 정보 플래그 비트 (esptool loader.get_security_info 의 SECURITY_INFO_FLAG_MAP, 모든 칩 공통)
SECURITY_FLAG_BITS = {
    "SECURE_BOOT_EN": 1 << 0,
    "SECURE_BOOT_AGGRESSIVE_REVOKE": 1 << 1,
    "SECURE_DOWNLOAD_ENABLE": 1 << 2,
    "SECURE_BOOT_KEY_REVOKE0": 1 << 3,
    "SECURE_BOOT_KEY_REVOKE1": 1 << 4,
    "SECURE_BOOT_KEY_REVOKE2": 1 << 5,
    "SOFT_DIS_JTAG": 1 << 6,
    "HARD_DIS_JTAG": 1 << 7,
    "DIS_USB": 1 << 8,
    "DIS_DOWNLOAD_DCACHE": 1 << 9,
    "DIS_DOWNLOAD_ICACHE": 1 << 10,
}


def parse_security_info(text: str) -> dict[str, Any] | None:
    m = re.search(r"^Flags:\s*(0x[0-9a-fA-F]+)", text, re.M)
    if not m:
        return None
    flags = int(m.group(1), 16)
    parsed = {k: bool(flags & bit) for k, bit in SECURITY_FLAG_BITS.items()}
    out: dict[str, Any] = {"flags": flags, "flags_hex": f"0x{flags:08x}", "parsed_flags": parsed}
    kp = re.search(r"^Key Purposes:\s*\(([^)]*)\)", text, re.M)
    out["key_purposes_raw"] = [int(x) for x in re.findall(r"\d+", kp.group(1))] if kp else None
    out["key_blocks"] = [{"block": b, "purpose": p} for b, p in re.findall(r"^\s+(BLOCK_KEY\d+) - (\S+)\s*$", text, re.M)]
    cid = _line_value(text, "Chip ID")
    out["chip_id"] = int(cid) if cid and cid.isdigit() else None
    api = _line_value(text, "API Version")
    out["api_version"] = int(api) if api and api.isdigit() else None
    sb = _line_value(text, "Secure Boot")
    out["secure_boot"] = (sb == "Enabled") if sb in ("Enabled", "Disabled") else parsed["SECURE_BOOT_EN"]
    out["secure_boot_aggressive_revoke"] = bool(re.search(r"^Secure Boot Aggressive key revocation: Enabled", text, re.M))
    out["revoked_keys"] = [int(x) for x in re.findall(r"Secure Boot Key(\d) is Revoked", text)]
    fe = _line_value(text, "Flash Encryption")
    m = re.search(r"^(?:SPI Boot Crypt Count \((\w+)\)|Flash Crypt Count \((\w+)\)):\s*(0x[0-9a-fA-F]+)", text, re.M)
    crypt = int(m.group(3), 16) if m else None
    out["crypt_cnt"] = crypt
    out["crypt_cnt_field"] = (m.group(1) or m.group(2)) if m else None
    if fe in ("Enabled", "Disabled"):
        out["flash_encryption"] = fe == "Enabled"
    else:
        out["flash_encryption"] = bool(crypt is not None and bin(crypt).count("1") % 2 == 1)
    out["download_dcache_disabled"] = bool(re.search(r"^Dcache in UART download mode: Disabled", text, re.M)) or parsed["DIS_DOWNLOAD_DCACHE"]
    out["download_icache_disabled"] = bool(re.search(r"^Icache in UART download mode: Disabled", text, re.M)) or parsed["DIS_DOWNLOAD_ICACHE"]
    jtag = _line_value(text, "JTAG")
    out["jtag_hard_disabled"] = jtag == "Permanently Disabled" or parsed["HARD_DIS_JTAG"]
    out["jtag_soft_disabled"] = jtag == "Software Access Disabled" or parsed["SOFT_DIS_JTAG"]
    out["usb_disabled"] = _line_value(text, "USB Access") == "Disabled" or parsed["DIS_USB"]
    out["secure_download_mode"] = parsed["SECURE_DOWNLOAD_ENABLE"]
    out["raw_fields"] = _security_block_fields(text)
    return out


_BLOCK_END_RE = re.compile(r"^(?:Hard resetting|Staying in|Soft resetting|Exiting immediately|ERROR:|A fatal error|WARNING:)")


def _security_block_fields(text: str) -> dict[str, str]:
    """'Security Information:' 블록의 'Label: value' 줄을 그대로 (들여쓴 BLOCK_KEY 줄과 구분선 제외)."""
    lines = text.splitlines()
    try:
        start = next(i for i, ln in enumerate(lines) if ln.strip() == "Security Information:")
    except StopIteration:
        return {}
    fields: dict[str, str] = {}
    for ln in lines[start + 1:]:
        if _BLOCK_END_RE.match(ln.strip()):
            break
        if ln[:1].isspace() or set(ln.strip()) <= {"="}:
            continue
        m = re.match(r"^([A-Za-z][^:]{0,80}):\s*(.*?)\s*$", ln)
        if m and len(fields) < 40:
            fields[m.group(1)] = m.group(2)
    return fields


#: 원조 ESP32 / ESP8266 (get-security-info 를 지원하지 않는 칩). ESP32-S0WD 는 원조 ESP32 계열이다.
_CLASSIC_CHIP_RE = re.compile(r"^(?:ESP8266|ESP8285|ESP32(?:$|-(?:D0WD|D2WD|S0WD|U4WD|PICO|MINI)))", re.I)
#: get-security-info 미지원 응답: 새 스텁 0xFF00, ROM UnsupportedCommandError(0x14) — v5 / v4 문구
_SECINFO_NOT_IMPL_RE = re.compile(
    r"Failed to get security info \(result was [0-9A-Fa-f]+: Command not implemented\)|"
    r"\(0x14\) is not supported|Invalid \(unsupported\) command 0x14", re.I)
_SECINFO_FAILED_RE = re.compile(r"Failed to get security info", re.I)


def is_classic_chip(chip: str | None) -> bool:
    return bool(chip and _CLASSIC_CHIP_RE.match(chip.strip()))


def security_info_unsupported(text: str, chip: str | None) -> bool:
    """get-security-info 를 칩(원조 ESP32/ESP8266)이 지원하지 않아 실패했는지."""
    if _SECINFO_NOT_IMPL_RE.search(text):
        return True
    return bool(_SECINFO_FAILED_RE.search(text)) and is_classic_chip(chip)


def parse_read_flash(text: str) -> dict[str, Any]:
    out: dict[str, Any] = {"bytes_read": None, "address": None, "seconds": None, "kbit_s": None, "detected_flash_size": None}
    m = re.search(r"Read (\d+) bytes (?:from|at) (0x[0-9A-Fa-f]+) in ([\d.]+) seconds(?: \(([\d.]+) kbit/s\))?", text)
    if m:
        out["bytes_read"] = int(m.group(1))
        out["address"] = int(m.group(2), 16)
        out["seconds"] = float(m.group(3))
        out["kbit_s"] = float(m.group(4)) if m.group(4) else None
    sizes = re.findall(r"^(?:Detected|Auto-detected) flash size:\s*(\S+)", text, re.M | re.I)
    if sizes:
        out["detected_flash_size"] = sizes[-1]
    return out


def output_warnings(text: str) -> list[str]:
    """esptool 경고/주의 줄 (v5 'WARNING:'/'NOTE:', v5.0~5.3 'Warning:'/'Note:', v4 'WARNING:')."""
    out = []
    for line in text.splitlines():
        s = line.strip()
        if re.match(r"^(WARNING|Warning|NOTE|Note|HINT):", s) and len(out) < 30:
            out.append(s[:400])
    return out


# ---------------------------------------------------------------------------
# 오류 매핑
# ---------------------------------------------------------------------------

#: 부트 스트랩 핀 안내 (docs/safety.md §2.7 과 같은 문구)
BOOT_PIN_KO = "BOOT(부트 스트랩 핀: ESP32·S2·S3 는 GPIO0, C3·C6·H2 는 GPIO9 — 그 밖은 데이터시트)"

_HINT_PORT_WIN = (
    "esp_list_ports 로 포트를 다시 확인하라. Windows(방법 A): usbipd 로 장치를 WSL 에 attach 한 동안에는 Windows 에서 COM 포트가 사라진다"
    "(usbipd detach 후 다시 시도하거나 리눅스 /dev/ttyACM0 를 쓴다). 리눅스: /dev/ttyACM*·/dev/ttyUSB* 는 usbipd attach 후에만 보인다. "
    "ESP32-S3 네이티브 USB 는 리셋 때 다시 열거되며 번호가 바뀔 수 있다."
)
_HINT_BUSY = (
    "다른 프로그램이 포트를 잡고 있다: 시리얼 모니터(Arduino IDE/idf.py monitor/PuTTY/Tera Term), 다른 esptool, uart-mcp 세션을 닫아라. "
    "WSL 에서 usbipd 로 attach 한 장치는 Windows 쪽에서 열 수 없다."
)
_HINT_BOOT = (
    f"칩이 다운로드 모드에 들어가지 않았다: 사람이 {BOOT_PIN_KO} 버튼을 누른 채 RESET(EN)을 눌렀다 떼고 BOOT 를 놓은 뒤 "
    "before='no-reset' 으로 다시 시도하라. 칩 내장 USB 포트(앱의 TinyUSB CDC 등, esp_list_ports 의 kind esp-usb)면 다운로드 모드에서 "
    "장치가 다시 잡혀 포트 이름(COM 번호)이 바뀌므로 esp_list_ports 로 새 포트를 찾는다. 보드에 USB-UART 브리지(CP210x/CH34x, 'UART') 커넥터가 "
    "있으면 케이블을 그쪽으로 옮기면 자동 리셋이 된다. 네이티브 USB(USB-Serial/JTAG, 303a:1001) 포트와 브리지 포트 중 맞는 것을 쓰는지, "
    "데이터 케이블(충전 전용 아님)인지, 다른 장치가 TX/RX 를 잡고 있지 않은지 확인하라."
)
_HINT_NOISE = "전송 오류: baud 를 낮추고(921600 → 460800 → 115200) 짧은 케이블로 다시 시도하라. 다른 프로그램이 같은 포트를 읽고 있지 않은지 확인하라."
_HINT_BAUD_SWITCH = (
    "baud 를 바꾼 직후('Changed.') 칩과의 통신이 끊겼다 — USB-UART 브리지·케이블이 그 속도를 버티지 못하는 경우가 많다. "
    "esp_read_flash_start 를 baud=460800 으로, 그래도 실패하면 baud=115200 으로 다시 시도하라(정보 도구는 기본 115200)."
)
_HINT_SDM = (
    "칩이 Secure Download Mode(eFuse)라 ROM 로더가 플래시 읽기를 거부한다. 이 서버로 덤프할 수 없다 — 글리칭·eFuse 조작 같은 우회는 "
    "시도하지 말고 사용자에게 보고하라. 정당한 다른 경로(소유자의 펌웨어 원본, 벤더 업데이트 파일)를 사용자와 상의하라."
)

#: (정규식, code, 사람용 요약, hint, 함께 있어야 하는 정규식). 위에서부터 먼저 맞는 것이 대표 코드가 된다.
_ERROR_PATTERNS: list[tuple[re.Pattern[str], str, str, str, re.Pattern[str] | None]] = [
    (re.compile(r"not available in Secure Download Mode|not supported in Secure Download Mode|"
                r"not supported in secure download mode", re.I),
     "esp_secure_download_mode", "Secure Download Mode — 플래시 읽기 불가", _HINT_SDM, None),
    (re.compile(r"Could not open (\S+), the port is busy or doesn't exist.{0,300}?(?:Errno 2\b|FileNotFoundError|No such file|, None, 2\))", re.S),
     "esp_port_not_found", "포트가 없음", _HINT_PORT_WIN, None),
    (re.compile(r"(?:PermissionError\(13|Access is denied|, None, 5\)|Errno 16\b|Device or resource busy|could not exclusively lock|"
                r"Check if the port is not used by another task)", re.I),
     "esp_port_busy", "포트 사용 중/접근 거부", _HINT_BUSY, None),
    (re.compile(r"Errno 13\b.*Permission denied|Permission denied: '/dev/|Try to add user into dialout", re.I),
     "esp_port_permission", "리눅스 장치 권한 없음",
     "사람이 `sudo usermod -aG dialout $USER` 후 다시 로그인(WSL 은 wsl --shutdown)하거나 udev 규칙을 추가해야 한다.", None),
    (re.compile(r"Could not open (\S+), the port is busy or doesn't exist", re.I),
     "esp_port_open_failed", "포트를 열 수 없음", _HINT_PORT_WIN + " " + _HINT_BUSY, None),
    (re.compile(r"could not open port|FileNotFoundError|No such file or directory: '/dev/", re.I),
     "esp_port_not_found", "포트가 없음", _HINT_PORT_WIN, None),
    (re.compile(r"Wrong boot mode detected", re.I), "esp_wrong_boot_mode", "다운로드 모드가 아닌 일반 부팅 감지", _HINT_BOOT, None),
    (re.compile(r"getting no sync reply|serial TX path seems to be down", re.I),
     "esp_tx_path_down", "다운로드 모드는 보이지만 응답 동기화 실패",
     "칩→호스트 방향은 되지만 호스트→칩(TX→RX) 경로가 끊긴 것 같다: 배선(어댑터 TX → 칩 RX), 레벨, 다른 장치 간섭을 확인하라.", None),
    # baud 를 바꾼 뒤('Changed.') 끊김: 921600 을 못 버티는 USB-UART 브리지 (esptool 5.4.0 실측 문구)
    (re.compile(r"No more data to read from the serial port|Serial data stream stopped|No serial data received", re.I),
     "esp_baud_switch_failed", "baud 변경 직후 통신 끊김", _HINT_BAUD_SWITCH, re.compile(r"^Changed\.", re.M)),
    (re.compile(r"No serial data received", re.I), "esp_no_serial_data", "칩 응답 없음", _HINT_BOOT, None),
    (re.compile(r"This chip is (ESP[^\s,]+),? not (ESP[^\s.,]+)", re.I), "esp_wrong_chip", "chip 인자와 실제 칩이 다름",
     "chip='auto' 로 다시 시도하거나 메시지의 칩 이름을 chip 으로 준다.", None),
    (re.compile(r"Digest mismatch", re.I), "esp_digest_mismatch", "스텁 전송 MD5 불일치(전송 손상)", _HINT_NOISE, None),
    (re.compile(r"Corrupt data, expected|Read more than expected|Invalid head of packet|Possible serial noise|Invalid SLIP escape|"
                r"Packet content transfer stopped|Serial data stream stopped|Timed out waiting for packet|Expected digest, got", re.I),
     "esp_serial_noise", "직렬 전송 오류", _HINT_NOISE, None),
    (re.compile(r"Detecting flash size failed|Could not auto-detect flash size", re.I), "esp_flash_size_unknown", "플래시 크기 자동 감지 실패",
     "size 를 명시하라 (esp_chip_info 의 flash.size 또는 모듈 데이터시트, 예: '4MB'/'8MB'/'16MB').", None),
    (re.compile(r"greater than detected flash size|Can't access flash regions larger than", re.I),
     "esp_size_exceeds_flash", "요청 범위가 감지된 플래시 크기를 넘음", "offset/size 를 감지된 크기(esp_chip_info 의 flash.size) 안으로 줄여라.", None),
    (re.compile(r"ROM does not support function", re.I), "esp_rom_unsupported", "ROM 로더가 지원하지 않는 기능",
     "ESP8266 ROM 은 read-flash 를 지원하지 않는다(그 밖의 ESP32 계열 ROM 은 읽을 수 있다) — no_stub=false(기본)로 다시 시도하라.", None),
    (re.compile(r"Failed to start stub\b|Failed to (?:run|upload) stub|Stub flasher JSON", re.I), "esp_stub_failed", "플래셔 스텁 실행 실패",
     "보드를 RESET(또는 USB 재연결)한 뒤 다시 시도하라.", None),
    (re.compile(r"The chip stopped responding", re.I), "esp_chip_stopped", "칩이 응답을 멈춤",
     "전원/케이블 상태를 확인하고 보드를 RESET 한 뒤 낮은 baud 로 다시 시도하라.", None),
    (re.compile(r"Guru Meditation Error detected|Fatal exception \(\d+\)", re.I), "esp_app_running", "앱이 실행 중(패닉 출력 감지)", _HINT_BOOT, None),
    (re.compile(r"invalid choice|Invalid value for|No such command|No such option|unrecognized arguments|Usage: ", re.I),
     "esp_invalid_argument", "esptool 이 인자를 모름(버전 차이)",
     "esp_version 으로 esptool 버전을 확인하라. 오래된 esptool 은 새 칩 이름/옵션을 모를 수 있다 (v4.8 이상 권장).", None),
    (re.compile(r"WinError 121|WinError 31|WinError 1167|semaphore timeout|device is not connected|Input/output error|Errno 5\b", re.I),
     "esp_port_io_error", "포트 I/O 오류(장치 분리/재열거)", "USB 케이블을 다시 연결하고 esp_list_ports 로 포트를 다시 확인하라.", None),
    (re.compile(r"Failed to connect to", re.I), "esp_connect_failed", "연결 실패", _HINT_BOOT, None),
]


def detect_problems(text: str) -> list[dict[str, str]]:
    """알려진 실패 패턴 (경고 줄은 제외 — v4 의 'WARNING: Stub loader is not supported in Secure Download Mode' 같은 정상 경고)."""
    body = "\n".join(ln for ln in text.splitlines() if not re.match(r"\s*(?:WARNING|Warning|NOTE|Note):", ln))
    found: list[dict[str, str]] = []
    seen: set[str] = set()
    for rx, code, summary, hint, requires in _ERROR_PATTERNS:
        if code in seen:
            continue
        if requires is not None and not requires.search(body):
            continue
        m = rx.search(body)
        if m:
            seen.add(code)
            found.append({"code": code, "summary": summary, "hint": hint, "match": m.group(0)[:300]})
    return found


_TRACEBACK_LAST_RE = re.compile(r"^(?:[A-Za-z_]\w*\.)*([A-Za-z_]\w*(?:Error|Exception|Exit)): (.+)$")


def fatal_message(text: str) -> str | None:
    """'A fatal error occurred: …'(v4/v5) 또는 'A serial exception error occurred: …' 와 이어지는 줄.

    없으면 파이썬 traceback 의 마지막 'X: msg' 줄 (esptool 4.x 는 Secure Download Mode 거부가 RuntimeError 계열이라 traceback 으로 끝난다).
    """
    lines = text.splitlines()
    for i, line in enumerate(lines):
        m = re.search(r"A (?:fatal|serial exception) error occurred:\s*(.*)$", line)
        if m:
            msg = [m.group(1).strip()]
            for nxt in lines[i + 1:i + 6]:
                s = nxt.strip()
                if not s or s.startswith(("For troubleshooting", "Note: This error originates")):
                    break
                msg.append(s)
            return " ".join(x for x in msg if x)[:800]
    if "Traceback (most recent call last):" in text:
        for line in reversed(lines):
            m = _TRACEBACK_LAST_RE.match(line.strip())
            if m:
                return f"{m.group(1)}: {m.group(2)}"[:800]
    return None


class EsptoolFailed(PwehError):
    code = "esp_failed"


def foreign_config_error(path: str, ours: Sequence[str], what: str, *, log_path: str | None = None) -> PwehError:
    """서버가 만든 빈 설정이 아닌 esptool 설정 파일을 읽은 실행 → 오류 (실행은 바로 멈춘다)."""
    where = f" (로그: {log_path})" if log_path else ""
    return EsptoolFailed(
        f"{what}: esptool 이 서버가 지정하지 않은 설정 파일을 읽어 실행을 멈췄다: {path}{where}",
        code="esp_foreign_config",
        hint=("서버는 실행마다 빈 [esptool] 설정을 만들어 ESPTOOL_CFGFILE 로 지정한다. 다른 설정(custom_reset_sequence·timeout 등)은 "
              "리셋 순서와 동작을 바꿀 수 있고 esptool 5.3.1 이하는 custom_reset_sequence 를 코드로 실행한다. 사람이 그 파일의 [esptool] "
              "섹션을 확인·제거하거나 파일을 옮긴 뒤 다시 시도한다."),
        data={"config": path, "expected": list(ours), "log_path": log_path},
    )


def raise_for_result(res: RunResult, text: str, what: str, *, log_path: str | None = None, timeout_hint: str | None = None) -> None:
    """esptool 실행 결과가 실패면 매핑된 코드/힌트로 PwehError 를 던진다."""
    where = f" (로그: {log_path})" if log_path else ""
    if not res.cleanup_verified or res.orphan_check_failed:
        raise PwehError(f"{what}: 하위 프로세스 종료 미확인{where}", code="process_cleanup_unverified")
    if res.cancelled:
        raise PwehError(f"{what}: 취소됨{where}", code="cancelled", data={"log_path": log_path})
    if res.timed_out or res.idle_timed_out:
        kind = "출력 없이 너무 오래 멈춤" if res.idle_timed_out else "시간 초과"
        raise TimeoutExpired(
            f"{what}: esptool {kind}({res.duration_s:.0f}초)으로 종료함{where}",
            hint=timeout_hint or "timeout_s 를 늘리거나 baud 를 확인하라. 칩이 다운로드 모드가 아니면 연결 재시도가 계속된다.",
            data={"log_path": log_path, "problems": detect_problems(text)},
        )
    if res.returncode == 0:
        return
    probs = detect_problems(text)
    fatal = fatal_message(text)
    if probs:
        p = probs[0]
        msg = f"{what} 실패 — {p['summary']}: {fatal or p['match']}{where}"
        raise EsptoolFailed(msg, code=p["code"], hint=p["hint"],
                            data={"returncode": res.returncode, "problems": probs, "log_path": log_path, "output_tail": text[-3000:]})
    tail = " | ".join(ln.strip() for ln in text.strip().splitlines()[-4:])
    raise EsptoolFailed(f"{what} 실패 (rc={res.returncode}): {fatal or tail or '출력 없음'}{where}",
                        hint="로그 파일을 확인하라. 칩 연결·다운로드 모드·포트 번호를 점검한다.",
                        data={"returncode": res.returncode, "log_path": log_path, "output_tail": text[-3000:]})


__all__ = [
    "BOOT_PIN_KO",
    "CONFIG_NAME",
    "ConfigWatch",
    "EMPTY_CONFIG",
    "EsptoolFailed",
    "INSTALL_HINT",
    "JEDEC_VENDORS",
    "OutputCollector",
    "Progress",
    "RunResult",
    "SECURITY_FLAG_BITS",
    "STUB_VERSION_ANY",
    "build_argv",
    "child_env",
    "clear_cache",
    "detect_problems",
    "detect_version",
    "exe_image",
    "fatal_message",
    "flash_size_bytes",
    "foreign_config_error",
    "info_win_match",
    "is_classic_chip",
    "kill_process_group",
    "live_process_count",
    "locate_linux_esptool",
    "neutral_esptool_env",
    "output_warnings",
    "output_win_match",
    "parse_connect",
    "parse_flash_id",
    "parse_progress",
    "parse_read_flash",
    "parse_security_info",
    "parse_version_output",
    "prepare_run_dir",
    "raise_for_result",
    "run_streaming",
    "security_info_unsupported",
    "stop_windows_run",
    "stub_version_for",
    "versioned",
    "windows_exe_candidates",
]
