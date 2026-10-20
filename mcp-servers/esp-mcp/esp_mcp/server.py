"""esp-mcp: Espressif(ESP32 계열) 칩을 esptool 로 **읽기 전용** 분석하는 MCP 서버 (등록 이름 pweh-esp).

방법 A (WSL 권장): Windows 에 연결된 보드를 usbipd 없이 그대로 쓴다. 서버가 WSL interop 으로 Windows 용 esptool.exe 를
``--port COM3`` 으로 실행하고, 결과 파일 경로는 ``wslpath -w`` 로 바꿔 케이스 ``dumps/`` 에 바로 저장한다.
리눅스 백엔드: usbipd 로 WSL 에 attach 한 ``/dev/ttyACM0``·``/dev/ttyUSB0`` 를 리눅스 esptool 로 다룬다.

도구:
- ``esp_version()``        두 백엔드의 esptool 경로·버전·interop 상태 (기기 미접촉)
- ``esp_list_ports()``     Windows COM 포트(PnP, powershell)와 리눅스 시리얼 포트 + 알려진 USB ID 주석 (포트를 열지 않음)
- ``esp_chip_info``        flash-id: 칩 종류/리비전·기능·수정 진동자·MAC·USB 모드·플래시 제조사/크기 → ``uart/esptool-chip-info-NNN.log``
- ``esp_security_info``    get-security-info: Secure Boot·플래시 암호화·Secure Download Mode·JTAG·키 용도 → ``uart/esptool-security-info-NNN.log``
- ``esp_read_flash_start`` read-flash 작업(job): 두 번 읽어 sha256 비교(기본) → ``dumps/<name>.bin`` (+ ``.read2.bin``, ``.json``)
- ``esp_job_status`` / ``esp_job_cancel`` / ``esp_jobs``

안전:
- 하드웨어 도구는 케이스 소유/허가 증명(``rt().case(case_id, hardware=True)``)이 필요하고, 서버가 검증한 인자로 argv 를 직접 조립해
  ``policy.classify_esptool_argv`` 로 분류한 뒤 ``rt().authorize`` 를 거친다. 연결(리셋·스텁)은 MODIFY(기본 허용).
- 쓰기·삭제·eFuse·RAM 실행·임의 메모리 접근·알 수 없는 명령/옵션, FLASH_BEGIN 을 보내는 ``--after no-reset``·``soft-reset`` 은
  DESTRUCTIVE 로 분류되어 게이트에 넘기지 않고 바로 거부한다. 사용자의 ``after='no-reset'`` 은 ``no-reset-stub`` 으로 바꿔 실행한다.
- esptool 은 실행마다 새 작업 디렉터리에서 서버가 만든 빈 설정(ESPTOOL_CFGFILE)과 중립 환경변수로 돈다(esptool_cli.child_env).
  다른 설정 파일을 읽으면 바로 멈추고 ``esp_foreign_config`` 오류를 낸다.
- 백그라운드 읽기 작업은 esptool 을 띄우기 직전마다 argv 를 다시 분류하고 소유/허가 증명과 dumps/ 실제 경로(심볼릭 링크로
  바뀌지 않았는지)를 다시 확인한다.
- 같은 포트는 한 번에 한 작업만 쓴다(포트 잠금 + job 배타 키 — 서버 프로세스 안에서 유효). 리눅스 포트는 다른 프로세스가 열고
  있으면, Windows 포트는 그 COM 포트를 인자로 받은 esptool.exe 가 남아 있으면 거부한다.
- 취소·시간 초과·서버 종료 때 Windows esptool.exe 는 PyInstaller 자식부터 끝내고 남은 것이 없는지 확인한다(남으면 PID 를 담은
  ``esp_orphan_process`` 오류). 덤프 중에는 숨은 예약 파일(``dumps/.<name>.readN.partial`` + 소유 표식 ``.<name>.owner.partial``)만
  두고, 최종 파일(``<name>.bin``/``.read2.bin``/``.json``)은 끝날 때 O_EXCL 로 만든다(기존 증거를 덮어쓰지 않음).
  서버 시작 때 주인 프로세스가 죽은 예약 파일을 지우고, 죽은 프로세스의 'running' 작업 기록을 'abandoned' 로 고친다.
  SIGTERM 을 받으면 작업을 취소해 정리한 뒤 끝난다.
- 출처 원장(``pweh.provenance``, ``<state_dir>/provenance/<case>.jsonl``): 끝까지 성공한 덤프의 읽기 파일(1차·2차)은 device-read,
  ``esp_chip_info``·``esp_security_info`` 결과는 device-fact 로 기록한다(실패·취소 때 보존한 1차 읽기는 기록하지 않음). 기록 실패는
  결과를 막지 않고 응답의 ``provenance.recorded=false`` 와 경고로 알린다.
"""

from __future__ import annotations

import contextlib
import functools
import json
import logging
import math
import os
import re
import shutil
import signal
import socket
import stat
import tempfile
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Iterator

import anyio
import anyio.to_thread

from pweh.case import CASE_ID_RE, Case
from pweh.errors import Busy, CaseError, PwehError, SafetyDenied, ToolMissing, ValidationFailed
from pweh.fsutil import atomic_write_json, atomic_write_text, human_size, sha256_file, utcnow_iso
from pweh.jobs import ACTIVE_STATES
from pweh.mcpkit import (
    ANN_DEVICE,
    ANN_READ_ONLY,
    Context,
    create_server,
    gate_response,
    register_job_tools,
    safe_tool,
)
from pweh import hostenv
from pweh.procutil import pid_alive
from pweh.runtime import Runtime, get_runtime
from pweh.safety import Classification, GateDecision, Risk
from pweh.toolsdir import tools_dir

from . import esptool_cli, ports, winproc
from .esptool_cli import (
    BOOT_PIN_KO,
    INSTALL_HINT,
    ConfigWatch,
    EsptoolFailed,
    OutputCollector,
    Progress,
    RunResult,
    build_argv,
    child_env,
    detect_problems,
    detect_version,
    exe_image,
    fatal_message,
    flash_size_bytes,
    foreign_config_error,
    info_win_match,
    locate_linux_esptool,
    output_warnings,
    output_win_match,
    parse_connect,
    parse_flash_id,
    parse_read_flash,
    parse_security_info,
    prepare_run_dir,
    raise_for_result,
    run_streaming,
    security_info_unsupported,
    stub_version_for,
    windows_exe_candidates,
)
from .policy import (
    classify_esptool_argv,
    display_argv,
    stub_safe_after,
    validate_after,
    validate_baud,
    validate_before,
    validate_chip,
    validate_no_stub,
    validate_offset,
    validate_output_name,
    validate_size,
    validate_verify,
)
from .winproc import WinMatch

SERVER_NAME = "esp-mcp"
PRODUCER = "esp-mcp"
log = logging.getLogger("pweh.esp")

INFO_BAUD_DEFAULT = 115200
READ_BAUD_DEFAULT = 921600
#: 수동 다운로드 모드(before='no-reset') 이중 읽기의 1차 읽기 baud — esptool 은 연결을 늘 115200 으로 동기화한다
SYNC_BAUD = 115200
INFO_TIMEOUT_S = 50.0  # 일부 클라이언트(Codex 등) 기본 도구 타임아웃 60초 고려
MAX_INFO_TIMEOUT_S = 600.0
READ_IDLE_TIMEOUT_S = 180.0  # 출력(연결 점·진행률) 없이 이만큼 지나면 멈춘 것으로 본다
MAX_READ_TIMEOUT_S = 6 * 3600.0
ASSUMED_ALL_BYTES = 32 * 1024 * 1024  # size='all' 의 시간 상한 계산용 (ESP32-S3 최대 32MB 플래시)
DEFAULT_DUMP_NAME = "esp-flash"
#: 내용을 읽을 수 없는 소유 표식은 이보다 오래되면 낡은 것으로 본다(다른 프로세스가 막 만드는 중일 수 있음)
UNREADABLE_OWNER_GRACE_S = 600.0
SHUTDOWN_TIMEOUT_S = 30.0

server = create_server(
    SERVER_NAME,
    title="PWEH ESP32 (esptool, 읽기 전용)",
    instructions=(
        "Espressif(ESP32 계열) 칩을 esptool 로 읽기 전용 분석하는 서버. 방법 A(WSL 권장): Windows 에 연결된 보드를 usbipd 없이 "
        "Windows 용 esptool.exe 로 다룬다 — port='COM3' 처럼 Windows COM 포트를 그대로 준다(리눅스 백엔드는 usbipd attach 후 '/dev/ttyACM0'). "
        "순서: esp_version(백엔드·버전 확인) → esp_list_ports(COM 포트와 USB ID: 303a:1001 = ESP 내장 USB-Serial/JTAG) → "
        "사용자에게 소유/허가 확인 후 case_create → esp_chip_info(case_id, port) → esp_security_info(case_id, port) → "
        "esp_read_flash_start(case_id, port, size='all', verify='double') → esp_job_status(job_id, wait_seconds=30) 로 폴링 → "
        "dumps/<name>.bin + .read2.bin + .json(sha256, 이중 읽기 비교). 연결할 때마다 칩이 리셋되어 ROM 다운로드 모드로 들어간다"
        "(MODIFY, 기본 허용). 플래시 쓰기·삭제·eFuse·RAM 실행 명령은 이 서버에 없고 요청하면 거부된다. after='no-reset' 은 "
        "no-reset-stub 으로 바꿔 실행한다(no-reset 은 FLASH_BEGIN 을 보내 레거시 스텁이 플래시 상태 레지스터를 다시 쓸 수 있음). "
        f"연결 실패(No serial data, Wrong boot mode)면 사람에게 {BOOT_PIN_KO} 버튼을 누른 채 RESET 을 눌렀다 떼도록 요청하고 "
        "before='no-reset' 으로 재시도한다. Secure Download Mode 면 플래시를 읽을 수 없으며 우회를 시도하지 않는다. "
        "플래시 암호화가 켜져 있으면 덤프는 암호문이다. 원조 ESP32/ESP8266 은 esp_security_info 가 status='unsupported'(보안 상태 미확인)다. "
        "결과 요약은 firmware-dump 스키마 형식(method 'esptool-read-flash', dumps/<name>.json 참고)으로 case_record_step 에 기록한다."
    ),
)


def rt() -> Runtime:
    return get_runtime(SERVER_NAME)


async def _offload(fn: Callable[..., Any], *args: Any, **kwargs: Any) -> Any:
    return await anyio.to_thread.run_sync(functools.partial(fn, *args, **kwargs))


async def _run_cancellable(fn: Callable[..., Any], *args: Any, **kwargs: Any) -> Any:
    """블로킹 함수를 워커 스레드에서 실행. 요청이 취소되면 cancel 이벤트를 세워 esptool 프로세스를 종료시킨다."""
    ev = threading.Event()
    try:
        return await anyio.to_thread.run_sync(functools.partial(fn, *args, cancel_event=ev, **kwargs), abandon_on_cancel=True)
    except anyio.get_cancelled_exc_class():
        ev.set()
        raise


# ---------------------------------------------------------------------------
# 백엔드 (esptool 실행 파일 + 버전)
# ---------------------------------------------------------------------------


@dataclass
class Backend:
    name: str  # windows | linux
    exe: str
    source: str
    version: str | None
    major: int | None
    minor: int | None = None

    @property
    def windows(self) -> bool:
        return self.name == "windows"

    @property
    def stub_version(self) -> str:
        return stub_version_for(self.major, self.minor)


def _configured(name: str) -> str | None:
    v = str(rt().config.tools.get(name) or "").strip()
    return os.path.expanduser(v) if v else None


def _esp_state_dir() -> Path:
    d = rt().config.state_dir / "esp-mcp"
    d.mkdir(parents=True, exist_ok=True)
    return d


@dataclass
class RunDir:
    """esptool 을 실행할 빈 작업 디렉터리와 그 안의 빈 [esptool] 설정."""

    path: str
    config: str
    windows: bool

    def allowed_configs(self) -> list[str]:
        """esptool 이 읽어도 되는 설정 파일 경로 (리눅스 경로 + Windows exe 가 보는 wslpath -w 경로)."""
        out = [self.config]
        if self.windows:
            try:
                out.append(ports.to_windows_path(self.config))
            except PwehError:  # pragma: no cover - 변환 실패면 리눅스 경로만 (그럼 다른 경로로 보고 멈춘다)
                log.warning("설정 파일 경로를 Windows 경로로 바꿀 수 없음: %s", self.config)
        return out


@contextlib.contextmanager
def _run_dir(windows: bool = False) -> Iterator[RunDir]:
    """매번 새로 만드는 작업 디렉터리 + 빈 [esptool] 설정 (esptool 은 현재 디렉터리·홈의 esptool.cfg/setup.cfg/tox.ini 를 읽는다)."""
    d = tempfile.mkdtemp(prefix="run-", dir=str(_esp_state_dir()))
    try:
        cfg = prepare_run_dir(d)
        yield RunDir(path=d, config=cfg, windows=windows)
    finally:
        shutil.rmtree(d, ignore_errors=True)


def _find_windows_exe() -> tuple[str, str]:
    if "windows_tools" in hostenv.disabled_keys(rt().config):
        raise ToolMissing(
            "설정 hostenv.disable 에 windows_tools 가 있어 Windows 용 esptool.exe(방법 A, port='COMn')를 쓰지 않습니다.",
            hint="리눅스 백엔드(usbipd attach 뒤 port='/dev/ttyACM0')를 쓰거나, 사람이 pipeline-config.yaml 의 hostenv.disable 을 고친다.",
        )
    st = ports.interop_status()
    if not st["interop"]:
        raise ToolMissing(
            f"Windows 백엔드(COM 포트)를 쓸 수 없습니다: {st['reason']}",
            hint="WSL 의 interop 이 켜져 있어야 Windows 용 esptool.exe 를 실행할 수 있다. 리눅스 백엔드는 usbipd attach 후 /dev/ttyACM0 를 쓴다.",
        )
    tried: list[str] = []
    for cand, source in windows_exe_candidates(_configured("esptool_win"), tools_dir()):
        path = cand
        if len(cand) > 2 and cand[1] == ":" and cand[2] in "\\/":
            try:
                path = ports.to_linux_path(cand)
            except PwehError:
                tried.append(cand)
                continue
        path = os.path.expanduser(path)
        tried.append(path)
        if not os.path.isfile(path):
            if source != "pweh-tools":
                raise ToolMissing(f"설정된 Windows esptool.exe 가 없습니다: {path} (출처: {source})", hint=INSTALL_HINT)
            continue
        if not path.lower().endswith(".exe"):
            raise ToolMissing(f"Windows esptool 경로는 .exe 여야 합니다: {path}", hint=INSTALL_HINT)
        if not os.access(path, os.X_OK):
            raise ToolMissing(f"실행 권한이 없습니다: {path}", hint=f"사람이 `chmod +x {path}` 를 실행하거나 /mnt/c 아래의 esptool.exe 를 지정하라.")
        return os.path.abspath(path), source
    raise ToolMissing(f"Windows 용 esptool.exe 를 찾을 수 없습니다 (시도: {', '.join(tried) or '없음'})", hint=INSTALL_HINT)


def _resolve_backend(spec: ports.PortSpec) -> Backend:
    if spec.backend == "windows":
        exe, source = _find_windows_exe()
    else:
        exe, source = locate_linux_esptool(_configured("esptool")), "config/PATH"
    with _run_dir(spec.backend == "windows") as rd:
        info = detect_version(exe, windows=spec.backend == "windows", run_dir=rd.path)
    return Backend(name=spec.backend, exe=exe, source=source, version=info.get("version"), major=info.get("major"),
                   minor=info.get("minor"))


def _backend_report(kind: str) -> dict[str, Any]:
    out: dict[str, Any] = {"available": False, "path": None, "version": None, "major": None, "source": None, "error": None}
    try:
        if kind == "windows":
            st = ports.interop_status()
            out["wsl"], out["interop"] = st["wsl"], st["interop"]
            exe, source = _find_windows_exe()
        else:
            exe, source = locate_linux_esptool(_configured("esptool")), "config/PATH"
        out["path"], out["source"] = exe, source
        with _run_dir(kind == "windows") as rd:
            info = detect_version(exe, windows=kind == "windows", run_dir=rd.path)
        out.update(available=True, version=info.get("version"), major=info.get("major"))
        if info.get("major") is not None and info["major"] < 4:
            out["warning"] = "esptool v4 미만은 지원하지 않는다 (v4.8 이상 권장)"
    except PwehError as exc:
        out["error"] = str(exc)
    return out


# ---------------------------------------------------------------------------
# 공통 헬퍼
# ---------------------------------------------------------------------------

_PORT_LOCKS: dict[str, threading.Lock] = {}
_PORT_LOCKS_GUARD = threading.Lock()


def _port_key(spec: ports.PortSpec) -> str:
    return f"esp-port:{spec.lock_key}"


def _port_lock(key: str) -> threading.Lock:
    with _PORT_LOCKS_GUARD:
        lk = _PORT_LOCKS.get(key)
        if lk is None:
            lk = _PORT_LOCKS[key] = threading.Lock()
        return lk


def _orphan_hint(pids: list[int], port: str) -> str:
    one = pids[0] if pids else "<PID>"
    return (f"방법 A 의 esptool.exe 는 PyInstaller onefile 이라 부모(interop) 프로세스를 끝내도 자식이 COM 포트를 잡은 채 남을 수 있다. "
            f"사람이 Windows 작업 관리자에서 esptool.exe(PID {', '.join(map(str, pids)) or '?'})를 끝내거나 Windows 터미널에서 "
            f"`taskkill /F /PID {one}` 를 실행한 뒤(또는 보드를 다시 연결한 뒤) 다시 시도하라. 그동안 {port} 를 쓰는 esp 호출은 busy 로 거부된다.")


def _check_port_free(spec: ports.PortSpec, backend: Backend | None = None) -> None:
    key = _port_key(spec)
    for j in rt().jobs.list(active_only=True):
        if (j.get("meta") or {}).get("exclusive_key") == key:
            raise Busy(f"같은 포트({spec.port})를 쓰는 작업이 실행 중입니다: {j['job_id']}",
                       hint="esp_job_status 로 진행 상황을 확인하거나 esp_job_cancel 로 취소하라.")
    if _port_lock(key).locked():
        raise Busy(f"포트 {spec.port} 를 다른 esp 도구 호출이 사용 중입니다.", hint="잠시 뒤 다시 시도하라.")
    if spec.backend == "linux":
        users = ports.device_users(spec.resolved or spec.port)
        if users:
            raise Busy(
                f"{spec.port} 를 다른 프로세스(pid {', '.join(map(str, users[:5]))})가 열고 있습니다 — 시리얼 모니터나 uart-mcp 세션일 수 있어 거부한다.",
                hint="그 프로그램(또는 uart_close)을 닫은 뒤 다시 시도하라.",
            )
        return
    images = ([exe_image(backend.exe)] if backend else []) + ["esptool.exe"]
    holders = winproc.port_holders(spec.port, images)
    if holders is None:
        log.warning("Windows esptool.exe 가 %s 를 잡고 있는지 확인하지 못함 (powershell 실패)", spec.port)
        return
    if holders:
        pids = [p.pid for p in holders]
        raise Busy(
            f"Windows 에서 esptool.exe(PID {', '.join(map(str, pids))})가 {spec.port} 를 인자로 받아 실행 중입니다 — 이전 esp 작업의 "
            "취소·시간 초과·서버 종료 뒤 남은 프로세스이거나 다른 esptool 일 수 있어 거부한다.",
            hint=_orphan_hint(pids, spec.port),
            data={"pids": pids},
        )


def _orphan_error(res: RunResult, what: str, port: str, log_rel: str | None) -> PwehError:
    pids = list(res.orphans)
    where = f" (로그: {log_rel})" if log_rel else ""
    return PwehError(
        f"{what}: esptool 을 끝냈지만 Windows esptool.exe(PID {', '.join(map(str, pids))})가 아직 남아 있다{where}",
        code="esp_orphan_process", hint=_orphan_hint(pids, port), data={"pids": pids, "log_path": log_rel},
    )


def _policy_denied(tool: str, action: dict[str, Any], cls: Classification, case_id: str | None) -> dict[str, Any]:
    """정책상 무조건 거부 (게이트/승인 경로 없음). 감사 로그에 남긴다."""
    msg = (
        f"안전 정책에 의해 거부됨: {cls.reason} (규칙={cls.rule_id}). 이 서버는 Espressif 칩의 읽기 전용 분석"
        "(flash-id/get-security-info/read-flash)만 하며 쓰기·삭제·eFuse·RAM 실행은 범위 밖이다. 우회하지 말고 사용자에게 보고하라."
    )
    decision = GateDecision(False, "denied", cls, "deny", via="esp-policy", message=msg)
    try:
        rt().audit({"event": "safety_decision", "tool": tool, "action": action, **decision.to_dict()}, case_id)
    except Exception:  # pragma: no cover
        log.exception("audit failed")
    return gate_response(decision)


def _clamp_timeout(value: Any, default: float, *, minimum: float = 5.0, maximum: float = MAX_INFO_TIMEOUT_S) -> float:
    if value is None:
        return default
    try:
        v = float(value)
    except (TypeError, ValueError):
        raise ValidationFailed(f"timeout_s 는 숫자여야 합니다: {value!r}")
    if not math.isfinite(v) or v < minimum:
        raise ValidationFailed(f"timeout_s 는 {minimum:.0f}초 이상이어야 합니다: {value!r}")
    return min(v, maximum)


def _reserve(path: Path, content: bytes = b"") -> bool:
    try:
        fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o644)
    except FileExistsError:
        return False
    try:
        if content:
            os.write(fd, content)
    finally:
        os.close(fd)
    return True


def _reserve_numbered(directory: Path, prefix: str, ext: str) -> Path:
    for n in range(1, 100000):
        p = directory / f"{prefix}-{n:03d}{ext}"
        if _reserve(p):
            return p
    raise CaseError(f"로그 파일 이름을 만들 수 없습니다: {prefix}{ext}")


def _unlink(p: Path | None) -> None:
    if p is None:
        return
    try:
        p.unlink()
    except FileNotFoundError:
        pass
    except OSError:  # pragma: no cover
        log.warning("파일 삭제 실패: %s", p)


def _write_log(path: Path, *, argv: list[str], backend: Backend, port: str, res: RunResult | None, col: OutputCollector,
               started_at: str, note: str | None = None) -> None:
    status = "취소됨" if res and res.cancelled else ("시간 초과" if res and (res.timed_out or res.idle_timed_out) else "")
    head = [
        "# esp-mcp esptool 로그",
        f"# 시작: {started_at}  종료: {utcnow_iso()}",
        f"# 백엔드: {backend.name}  esptool: {backend.version} ({backend.exe})",
        f"# 포트: {port}",
        f"# 명령: {' '.join(display_argv(argv))}",
    ]
    if res is not None:
        head.append(f"# 종료 코드: {res.returncode}  소요: {res.duration_s:.1f}s  출력: {res.output_bytes} bytes"
                    + (f"  ({status})" if status else "") + (f"  진행률 줄 {col.progress_lines}개는 {5}% 단위로만 남김" if col.progress_lines else ""))
        if res.orphans:
            head.append(f"# 끝까지 남은 Windows esptool.exe: PID {', '.join(map(str, res.orphans))}")
        if res.orphan_check_failed:
            head.append("# Windows esptool.exe 가 남았는지 확인하지 못함 (powershell 실패)")
    if note:
        head.append(f"# 메모: {note}")
    atomic_write_text(path, "\n".join(head) + "\n\n" + col.log_text() + "\n")


def _register_log(case: Case, path: Path, command: str, port: str) -> dict[str, Any] | None:
    try:
        return case.register_artifact(path, kind="other", producer=PRODUCER, description=f"esptool {command} 로그 ({port})",
                                      extra={"type": "esptool-log", "command": command, "port": port})
    except PwehError:  # pragma: no cover
        return None


def _common_args(port: Any, chip: Any, baud: Any, before: Any, no_stub: Any, baud_default: int) -> tuple[ports.PortSpec, str, int, str, bool]:
    spec = ports.validate_port(port)
    chip_v = validate_chip(chip)
    no_stub_v = validate_no_stub(no_stub, chip_v)  # no_stub=True 는 ESP8266 이 아닌 칩을 명시해야 함 (ESP8266 ROM 연결 = FLASH_BEGIN)
    return spec, chip_v, validate_baud(baud, baud_default), validate_before(before), no_stub_v


def _after_note(requested: str, effective: str) -> str | None:
    if requested == effective:
        return None
    return (f"after='{requested}' 를 '{effective}' 로 바꿔 실행했다: --after no-reset 은 스텁 세션을 끝낼 때 FLASH_BEGIN 을 보내 "
            "레거시 스텁(esptool 4.8~5.2 기본)이 SPI 플래시 상태 레지스터를 다시 쓸 수 있다(비휘발성). no-reset-stub 은 아무 명령도 "
            "보내지 않고 칩을 다운로드 모드(스텁)에 그대로 둔다(ROM 세션이면 no-reset 과 같은 동작).")


# ---------------------------------------------------------------------------
# 덤프 예약 파일 (숨은 .partial + 소유 표식) — 주인 프로세스 확인과 낡은 예약 정리
# ---------------------------------------------------------------------------

#: 이 프로세스가 지금 쓰고 있는 예약의 소유 표식 경로
_ACTIVE_RESERVATIONS: set[str] = set()
#: 예약 만들기·풀기·정리를 이 프로세스 안에서 한 줄로 세운다 (정리가 막 만든 예약을 지우지 않게)
_RESERVE_LOCK = threading.RLock()
_RES_FILE_RE = re.compile(r"^\.(?P<stem>.+)\.(?P<kind>owner|meta|read\d+)\.partial$")


def _boot_id() -> str | None:
    try:
        return Path("/proc/sys/kernel/random/boot_id").read_text(encoding="ascii").strip() or None
    except OSError:
        return None


def _proc_stat(pid: int) -> tuple[str, int] | None:
    """(상태 문자, 시작 시각 clock tick) — /proc/<pid>/stat 의 3번째·22번째 필드."""
    try:
        raw = Path(f"/proc/{pid}/stat").read_text(encoding="ascii", errors="replace")
    except OSError:
        return None
    fields = raw.rsplit(")", 1)[-1].split()
    try:
        return fields[0], int(fields[19])
    except (IndexError, ValueError):
        return None


def _owner_record(job_id: str | None = None) -> dict[str, Any]:
    st = _proc_stat(os.getpid())
    return {"server": SERVER_NAME, "pid": os.getpid(), "start_ticks": st[1] if st else None, "boot_id": _boot_id(),
            "host": socket.gethostname(), "created_at": utcnow_iso(), "job_id": job_id}


def _owner_alive(rec: dict[str, Any]) -> bool:
    """소유 기록의 프로세스가 아직 살아 있는지 (다른 호스트면 확인할 수 없으니 살아 있다고 본다)."""
    if rec.get("host") and rec["host"] != socket.gethostname():
        return True
    bid = _boot_id()
    if rec.get("boot_id") and bid and rec["boot_id"] != bid:
        return False
    try:
        pid = int(rec.get("pid"))
    except (TypeError, ValueError):
        return False
    if not pid_alive(pid):  # 0 이하·범위 밖(OverflowError)·없음·좀비는 False, 권한 없음(EPERM)은 True
        return False
    st = _proc_stat(pid)
    if st is not None:
        if st[0] == "Z":
            return False
        if rec.get("start_ticks") is not None and st[1] != rec["start_ticks"]:
            return False  # PID 재사용
    return True


def _reservation_state(sidecar: Path) -> tuple[str, dict[str, Any] | None]:
    """소유 표식 → ('live' | 'held' | 'stale', 기록). held = 주인은 끝났지만 남은 Windows esptool.exe 가 아직 파일을 쓸 수 있음.

    Windows 백엔드 예약은 첫 esptool.exe 를 띄우기 전에 출력 경로(``windows_tokens``)를 소유 표식에 적는다. 서버가 SIGKILL 로
    죽어 남은 PID 를 적지 못했어도, 명령줄에 그 경로가 있는 esptool.exe 가 살아 있으면 held 다. 확인하지 못하면(powershell
    실패) 역시 held(지우지 않음)로 본다.
    """
    try:
        rec = json.loads(sidecar.read_text(encoding="utf-8"))
        if not isinstance(rec, dict):
            raise ValueError("not an object")
    except (OSError, ValueError):
        try:
            age = time.time() - sidecar.stat().st_mtime
        except OSError:
            return "stale", None
        return ("live" if age < UNREADABLE_OWNER_GRACE_S else "stale"), None
    mine = rec.get("pid") == os.getpid() and rec.get("host", socket.gethostname()) == socket.gethostname()
    if mine:
        with _RESERVE_LOCK:
            if str(sidecar) in _ACTIVE_RESERVATIONS:
                return "live", rec
    elif _owner_alive(rec):
        return "live", rec
    images = [str(i) for i in rec.get("windows_images") or [] if i] or ["esptool.exe"]
    wpids = [int(p) for p in rec.get("windows_pids") or [] if str(p).isdigit()]
    if wpids:
        alive = winproc.pids_alive(wpids, images)
        if alive is None or alive:
            return "held", rec
    tokens = [t for t in rec.get("windows_tokens") or [] if isinstance(t, str) and t]
    if tokens:
        holders = winproc.token_holders(tokens, images)
        if holders is None or holders:
            if holders:
                log.warning("주인 서버는 끝났지만 예약 파일에 쓰는 Windows esptool.exe 가 남아 있음 (PID %s): %s — 정리하지 않는다",
                            ", ".join(str(h.pid) for h in holders), sidecar)
            return "held", rec
    return "stale", rec


def _sweep_dumps_dir(dumps: Path, case_id: str | None = None) -> list[dict[str, Any]]:
    """dumps/ 의 낡은 예약 파일 정리: 소유 표식이 없거나 주인 프로세스가 끝난 것(남은 Windows esptool.exe 가 없을 때)."""
    removed: list[dict[str, Any]] = []
    with _RESERVE_LOCK:
        try:
            entries = [e for e in os.scandir(dumps) if e.name.startswith(".") and e.name.endswith(".partial")]
        except OSError:
            return []
        groups: dict[str, dict[str, Any]] = {}
        for e in entries:
            m = _RES_FILE_RE.match(e.name)
            if not m:
                continue
            g = groups.setdefault(m.group("stem"), {"owner": None, "data": []})
            if m.group("kind") == "owner":
                g["owner"] = Path(e.path)
            else:
                g["data"].append(Path(e.path))
        for stem, g in sorted(groups.items()):
            sidecar: Path | None = g["owner"]
            rec = None
            if sidecar is None:
                reason = "소유 표식 없음"
            else:
                state, rec = _reservation_state(sidecar)
                if state != "stale":
                    continue
                reason = "주인 프로세스가 끝남"
            files = []
            for p in [*g["data"], *([sidecar] if sidecar else [])]:
                try:
                    size = p.stat().st_size
                except OSError:
                    size = None
                files.append({"name": p.name, "size": size})
            for p in g["data"]:
                _unlink(p)
            _unlink(sidecar)
            removed.append({"stem": stem, "reason": reason, "files": files,
                            "owner": {k: rec.get(k) for k in ("pid", "job_id", "created_at")} if rec else None})
    if removed and case_id:
        try:
            rt().audit({"event": "esp_stale_reservations_removed", "dumps": str(dumps), "removed": removed}, case_id)
        except Exception:  # pragma: no cover
            log.exception("audit failed")
    return removed


def _mark_abandoned_jobs(case_dir: Path) -> list[str]:
    """죽은 서버 프로세스가 남긴 'running' 작업 기록(jobs/<id>.json)을 'abandoned' 로 고친다 (이 서버의 작업만)."""
    marked: list[str] = []
    jobs_dir = case_dir / "jobs"
    if not jobs_dir.is_dir():
        return marked
    for jf in sorted(jobs_dir.glob("*.json")):
        try:
            rec = json.loads(jf.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        if not isinstance(rec, dict) or rec.get("server") != SERVER_NAME or rec.get("status") not in ACTIVE_STATES:
            continue
        owner = (rec.get("meta") or {}).get("owner")
        if not isinstance(owner, dict) or owner.get("pid") == os.getpid() or _owner_alive(owner):
            continue
        rec["status"] = "abandoned"
        rec["finished_at"] = rec.get("finished_at") or utcnow_iso()
        rec["message"] = ("서버 프로세스가 작업 도중 끝나 작업이 중단됨(abandoned) — 결과 파일은 만들지 않았다. 같은 덤프를 다시 시작하라. "
                          + (rec.get("message") or ""))[:500]
        try:
            atomic_write_json(jf, rec)
            marked.append(str(rec.get("job_id") or jf.stem))
        except OSError:  # pragma: no cover
            log.warning("작업 기록 갱신 실패: %s", jf)
    return marked


def _startup_sweep() -> dict[str, Any]:
    """서버 시작 때: 모든 케이스의 낡은 덤프 예약 정리 + 죽은 프로세스의 작업 기록을 abandoned 로."""
    out: dict[str, Any] = {"removed": 0, "abandoned": []}
    cases_dir = Path(rt().config.cases_dir)
    if not cases_dir.is_dir():
        return out
    for d in sorted(cases_dir.iterdir()):
        try:
            if d.is_symlink() or not d.is_dir() or not CASE_ID_RE.match(d.name):
                continue
            dumps = d / "dumps"
            if dumps.is_dir() and not dumps.is_symlink():
                out["removed"] += len(_sweep_dumps_dir(dumps.resolve(), d.name))
            marked = _mark_abandoned_jobs(d)
            if marked:
                out["abandoned"] += marked
                rt().audit({"event": "esp_jobs_abandoned", "jobs": marked}, d.name)
        except Exception:  # noqa: BLE001 - 한 케이스의 문제로 시작을 막지 않는다
            log.warning("시작 정리 실패: %s", d, exc_info=True)
    return out


# ---------------------------------------------------------------------------
# 정보 도구
# ---------------------------------------------------------------------------


@server.tool(
    description=(
        "esptool 백엔드 확인 (기기 미접촉, OBSERVE). backends.windows(방법 A: WSL interop 으로 Windows 용 esptool.exe 실행, port='COMn') 와 "
        "backends.linux(usbipd 로 attach 한 /dev/ttyACM0·/dev/ttyUSB0 를 리눅스 esptool 로)에 대해 {available, path, source, version, major, "
        "interop, error} 와 recommended, hints 를 돌려준다. 설치: scripts/install.sh --only esptool 또는 PWEH_ESPTOOL_WIN/PWEH_ESPTOOL."
    ),
    annotations=ANN_READ_ONLY,
)
@safe_tool
async def esp_version() -> dict[str, Any]:
    win = await _offload(_backend_report, "windows")
    lin = await _offload(_backend_report, "linux")
    hints = [
        "방법 A(WSL 권장): 보드를 Windows 에 연결한 그대로 port='COM3' 처럼 Windows COM 포트를 준다. usbipd 가 필요 없고, 덤프는 "
        "wslpath 로 바꾼 경로로 케이스 dumps/ 에 바로 저장된다.",
        "리눅스 백엔드: Windows 에서 usbipd bind/attach --wsl 로 장치를 WSL 에 붙인 뒤 port='/dev/ttyACM0'(ESP 내장 USB) 또는 "
        "'/dev/ttyUSB0'(USB-UART 브리지). attach 하는 동안 Windows 에서는 그 COM 포트가 사라진다.",
        "설치: scripts/install.sh --only esptool (Windows esptool.exe 와 리눅스 esptool) 또는 PWEH_ESPTOOL_WIN=/절대/경로/esptool.exe, "
        "PWEH_ESPTOOL=/절대/경로/esptool 을 지정하고 MCP 서버를 다시 시작한다.",
    ]
    recommended = "windows" if win["available"] else ("linux" if lin["available"] else None)
    return {"ok": True, "backends": {"windows": win, "linux": lin}, "recommended": recommended, "hints": hints}


@server.tool(
    description=(
        "시리얼 포트 목록 (포트를 열지 않음, OBSERVE). windows{available, ports, note}: Windows 의 COM 포트(powershell.exe 로 Win32_PnPEntity 조회 — "
        "port, name, vid, pid, serial_number, usb_id, kind, description_ko), linux{ports, hidden_legacy_ports}: pyserial 목록(+ in_use_by 다른 프로세스 PID). "
        "알려진 USB ID 주석: 303a:1001 = ESP 내장 USB-Serial/JTAG, 303a:0009 = ESP32-S3 ROM USB-OTG 다운로드 모드, 10c4:ea60 = CP210x, "
        "1a86:7523 = CH340, 1a86:55d3 = CH343, 1a86:55d4 = CH9102, 0403:6001/6010/6014/6015 = FTDI. WSL interop/powershell 이 없으면 리눅스 목록과 note 만."
    ),
    annotations=ANN_READ_ONLY,
)
@safe_tool
async def esp_list_ports() -> dict[str, Any]:
    win = await _offload(ports.list_windows_ports)
    lin_all = await _offload(ports.list_linux_ports, ports.device_users)
    lin = [p for p in lin_all if p.get("hwid") not in ("n/a", None) or p.get("vid")]
    hidden = len(lin_all) - len(lin)
    out: dict[str, Any] = {
        "ok": True,
        "windows": win,
        "linux": {"ports": lin, "hidden_legacy_ports": hidden},
        "count": len(win.get("ports") or []) + len(lin),
    }
    hints = []
    every = (win.get("ports") or []) + lin
    jtag = [p["port"] for p in every if p.get("kind") == "esp-usb-serial-jtag"]
    otg = [p["port"] for p in every if p.get("kind") == "esp-usb-otg-rom"]
    app_usb = [p["port"] for p in every if p.get("kind") == "esp-usb"]
    if jtag:
        hints.append(f"ESP 내장 USB-Serial/JTAG 포트: {', '.join(jtag)} — esptool 이 USB-JTAG 리셋으로 다운로드 모드에 넣는다"
                     "(before='default-reset' 또는 'usb-reset').")
    if otg:
        hints.append(f"ROM USB-OTG 다운로드 모드 포트: {', '.join(otg)} — 칩(ESP32-S2/S3)이 이미 ROM USB-OTG 다운로드 모드다. "
                     "before='no-reset', after='no-reset'(서버가 no-reset-stub 으로 바꿔 실행)으로 부르고, 끝나면 사람이 RESET 을 눌러 일반 부팅한다.")
    if app_usb:
        hints.append(f"앱이 칩 내장 USB 로 만든 포트: {', '.join(app_usb)} (TinyUSB CDC — 예: MicroPython 303a:4001). esptool 의 자동 리셋(DTR/RTS)이 "
                     "듣지 않는 경우가 많다. 보드에 'UART' 커넥터(USB-UART 브리지)가 있으면 사람에게 케이블을 그쪽으로 옮기게 하고(자동 리셋), "
                     "없으면 BOOT 를 누른 채 RESET 하게 한 뒤 esp_list_ports 로 새 포트를 찾는다(다운로드 모드에서는 303a:1001 등으로 다시 잡혀 "
                     "COM 번호가 바뀐다) → before='no-reset'.")
    if win.get("ports"):
        hints.append("방법 A: Windows 포트는 port='COMn' 그대로 esp_chip_info / esp_read_flash_start 에 준다.")
    if not out["count"]:
        hints.append("포트가 없다: 보드의 USB 케이블(데이터용)을 연결하고, Windows 장치 관리자의 '포트(COM & LPT)' 를 확인하라. "
                     "WSL 에 usbipd 로 attach 했다면 리눅스 쪽(/dev/ttyACM*)에만 보인다.")
    out["hints"] = hints
    return out


async def _run_info_command(
    *,
    tool: str,
    command: str,
    log_prefix: str,
    case_id: str,
    port: Any,
    chip: Any,
    baud: Any,
    before: Any,
    after: Any,
    no_stub: Any,
    timeout_s: Any,
    approval_id: str | None,
    ctx: Any,
) -> dict[str, Any]:
    """flash-id / get-security-info 공통 실행. 게이트에 막히면 {"gate": ...} 를 돌려준다."""
    r = rt()
    case = r.case(case_id, hardware=True)
    spec, chip_v, baud_v, before_v, no_stub_v = _common_args(port, chip, baud, before, no_stub, INFO_BAUD_DEFAULT)
    timeout = _clamp_timeout(timeout_s, INFO_TIMEOUT_S)
    backend: Backend = await _offload(_resolve_backend, spec)
    after_req = validate_after(after, backend.major, backend.minor)
    after_v = stub_safe_after(after_req)
    argv = build_argv(backend.exe, major=backend.major, chip=chip_v, port=spec.port, baud=baud_v, before=before_v,
                      after=after_v, no_stub=no_stub_v, command=command)
    cls = classify_esptool_argv(argv, port=spec.port, esptool_major=backend.major, esptool_minor=backend.minor)
    action = {"command": command, "port": spec.port, "chip": chip_v, "baud": baud_v, "before": before_v, "after": after_v,
              "no_stub": no_stub_v}
    if after_req != after_v:
        action["after_requested"] = after_req
    if cls.risk >= Risk.DESTRUCTIVE:
        return {"gate": _policy_denied(tool, action, cls, case.id)}
    await _offload(_check_port_free, spec, backend)
    decision = await r.authorize(tool=tool, action=action, classification=cls, case_id=case.id, approval_id=approval_id, ctx=ctx)
    if not decision.allowed:
        return {"gate": gate_response(decision)}
    log_path = _reserve_numbered(case.subdir("uart"), log_prefix, ".log")
    started = utcnow_iso()

    def work(cancel_event: threading.Event) -> tuple[RunResult, OutputCollector, ConfigWatch]:
        lock = _port_lock(_port_key(spec))
        if not lock.acquire(blocking=False):
            raise Busy(f"포트 {spec.port} 를 다른 esp 작업이 사용 중입니다.", hint="esp_jobs 로 확인하라.")
        try:
            again = classify_esptool_argv(argv, port=spec.port, esptool_major=backend.major, esptool_minor=backend.minor)
            if again.risk != Risk.MODIFY or again.rule_id != cls.rule_id:
                raise SafetyDenied(f"실행 직전 재분류에서 거부됨: {again.reason}", data={"classification": again.to_dict()})
            with _run_dir(backend.windows) as rd:
                watch = ConfigWatch(rd.allowed_configs())
                col = OutputCollector(on_line=watch.line)
                match = info_win_match(backend.exe, spec.port, command, backend.major) if backend.windows else None
                res = run_streaming(argv, timeout=timeout, on_text=col.feed,
                                    cancel=lambda: cancel_event.is_set() or watch.foreign is not None, cwd=rd.path,
                                    env=child_env(windows=backend.windows, run_dir=rd.path, stub_version=backend.stub_version),
                                    win_match=match)
            col.close()
            return res, col, watch
        finally:
            lock.release()

    try:
        res, col, watch = await _run_cancellable(work)
    except BaseException:
        _unlink(log_path)
        raise
    _write_log(log_path, argv=argv, backend=backend, port=spec.port, res=res, col=col, started_at=started)
    art = _register_log(case, log_path, command, spec.port)
    text = col.text
    log_rel = case.rel(log_path)
    r.audit({"event": f"esp_{command.replace('-', '_')}", "port": spec.port, "backend": backend.name, "returncode": res.returncode,
             "log": log_rel, "duration_s": round(res.duration_s, 2), "orphans": res.orphans or None,
             "foreign_config": watch.foreign}, case.id)
    if res.orphans:
        raise _orphan_error(res, f"{tool}({command})", spec.port, log_rel)
    if watch.foreign:
        raise foreign_config_error(watch.foreign, watch.allowed, f"{tool}({command})", log_path=log_rel)
    return {"case": case, "spec": spec, "backend": backend, "argv": argv, "cls": cls, "res": res, "text": text,
            "log_path": log_rel, "artifact": art, "after": after_v, "after_requested": after_req, "no_stub": no_stub_v,
            "baud": baud_v}


def _base_result(run: dict[str, Any]) -> dict[str, Any]:
    spec: ports.PortSpec = run["spec"]
    backend: Backend = run["backend"]
    out = {
        "backend": backend.name,
        "port": spec.port,
        "esptool_version": backend.version,
        "esptool_path": backend.exe,
        "log_path": run["log_path"],
        "command": display_argv(run["argv"]),
        "duration_s": round(run["res"].duration_s, 2),
        "after": run["after"],
        "classification": run["cls"].to_dict(),
    }
    if run.get("after_requested") and run["after_requested"] != run["after"]:
        out["after_requested"] = run["after_requested"]
    return out


def _connect_notes(conn: dict[str, Any], run: dict[str, Any]) -> tuple[list[str], list[str]]:
    warnings = output_warnings(run["text"])
    notes: list[str] = []
    if conn.get("custom_config") and not conn.get("custom_config_via_env"):
        warnings.append(f"esptool 이 설정 파일을 읽음: {conn['custom_config']}")
    if conn.get("usb_mode") == "USB-Serial/JTAG":
        notes.append("ESP 내장 USB-Serial/JTAG 로 연결됨: 리셋 때 USB 가 다시 열거될 수 있다(Windows COM 번호가 바뀌면 esp_list_ports 로 다시 확인).")
    if conn.get("stub_reused"):
        notes.append("칩에서 이미 돌고 있던 플래셔 스텁에 다시 연결했다(이전 호출의 after=no-reset-stub).")
    if conn.get("legacy_stub"):
        notes.append("esptool 이 레거시 스텁을 썼다(이 칩용 새 스텁이 없음). 이 서버는 --after no-reset·soft-reset 을 쓰지 않으므로 스텁을 "
                     "빠져나가는 FLASH_BEGIN(레거시 스텁의 상태 레지스터 쓰기)은 보내지 않는다.")
    mapped = _after_note(run.get("after_requested") or run["after"], run["after"])
    if mapped:
        notes.append(mapped)
    after = run["after"]
    if after == "hard-reset":
        notes.append("끝난 뒤 hard-reset 으로 앱이 다시 실행되었다.")
    elif after == "watchdog-reset":
        notes.append("끝난 뒤 워치독 리셋으로 앱이 다시 실행되었다(지원하지 않는 칩은 hard-reset).")
    elif after == "no-reset-stub":
        notes.append("끝난 뒤 리셋하지 않음(after=no-reset-stub): 칩이 다운로드 모드(스텁을 썼다면 RAM 의 플래셔 스텁)에 머문다. "
                     "다음 호출은 before='no-reset' 으로 이어서 연결할 수 있다. 일반 부팅이 필요하면 사람이 RESET 을 누른다.")
        if conn.get("baud_changed_to") and conn["baud_changed_to"] > SYNC_BAUD:
            notes.append(f"칩이 {conn['baud_changed_to']} baud 로 남아 있다: esptool 은 before='no-reset' 연결을 115200 으로 동기화하므로 "
                         "USB-UART 브리지에서는 다음 연결이 맞지 않는다 — before='default-reset'(자동 리셋)을 쓰거나 사람이 BOOT+RESET 으로 "
                         "다시 다운로드 모드에 넣는다(네이티브 USB 는 영향 없음).")
    return warnings, notes


@server.tool(
    description=(
        "칩·플래시 정보 (esptool flash-id, MODIFY: DTR/RTS 또는 USB-Serial/JTAG 리셋으로 ROM 다운로드 모드 진입 + RAM 스텁, 플래시/eFuse 쓰기 없음, "
        "케이스 소유/허가 증명 필요). port: 'COM3'(방법 A, Windows esptool.exe) 또는 '/dev/ttyACM0'(리눅스 esptool). "
        "반환: chip, chip_description, chip_revision, features, crystal_mhz, usb_mode, mac, flash{manufacturer_id, manufacturer, device_id, size, "
        "size_bytes, type_efuse, voltage}, secure_download_mode, stub, log_path(uart/esptool-chip-info-NNN.log), backend, port, esptool_version, "
        "warnings, notes. Secure Download Mode 면 flash-id 가 거부되므로 status='secure_download_mode' 와 칩 종류만 돌려준다. "
        "연결 실패면 사람에게 BOOT 를 누른 채 RESET 을 누르게 하고 before='no-reset' 으로 다시 호출한다. "
        "modify_policy=approve 이면 approval_required → 사람이 pweh approve 후 approval_id 를 붙여 재호출."
    ),
    annotations=ANN_DEVICE,
)
@safe_tool
async def esp_chip_info(
    case_id: str,
    port: str,
    chip: str = "auto",
    baud: int | None = None,
    before: str = "default-reset",
    after: str = "hard-reset",
    no_stub: bool = False,
    timeout_s: float | None = None,
    approval_id: str | None = None,
    ctx: Context = None,  # type: ignore[assignment]
) -> dict[str, Any]:
    run = await _run_info_command(tool="esp_chip_info", command="flash-id", log_prefix="esptool-chip-info", case_id=case_id, port=port,
                                  chip=chip, baud=baud, before=before, after=after, no_stub=no_stub, timeout_s=timeout_s,
                                  approval_id=approval_id, ctx=ctx)
    if "gate" in run:
        return run["gate"]
    text, res = run["text"], run["res"]
    conn = parse_connect(text)
    flash = parse_flash_id(text)
    warnings, notes = _connect_notes(conn, run)
    out: dict[str, Any] = {"ok": True, "status": "ok", **_base_result(run)}
    out.update({k: conn[k] for k in ("chip", "chip_description", "chip_revision", "features", "crystal_mhz", "usb_mode", "mac",
                                     "base_mac", "mac_ext", "secure_download_mode", "stub", "detected_chip")})
    out["flash"] = flash
    if res.returncode != 0 or flash is None:
        probs = detect_problems(text)
        if conn["secure_download_mode"] and (not probs or probs[0]["code"] == "esp_secure_download_mode") and not (res.cancelled or res.timed_out):
            out["status"] = "secure_download_mode"
            out["read_flash_possible"] = False
            notes.insert(0, "칩이 Secure Download Mode 라 ROM 로더가 flash-id·read-flash 를 거부한다. esptool 로는 플래시를 읽을 수 없으며 "
                            "우회(글리칭·eFuse 조작)는 시도하지 않는다. esp_security_info 로 보안 설정을 확인하고 사용자에게 보고하라.")
            out["error"] = fatal_message(text)
            out.update(warnings=warnings, notes=notes)
            out["provenance"] = _record_fact("esp-chip-info", "esp_chip_info", run, conn, _chip_fact(out))
            return out
        raise_for_result(res, text, "esp_chip_info(flash-id)", log_path=run["log_path"])
        raise EsptoolFailed(f"flash-id 출력을 해석할 수 없습니다 (로그: {run['log_path']})", code="esp_bad_output",
                            hint="esptool 버전이 예상과 다를 수 있다. 로그를 확인하라.")
    if flash.get("size") is None:
        warnings.append("플래시 크기를 감지하지 못했다(Detected flash size: Unknown) — esp_read_flash_start 에 size 를 명시해야 한다.")
    if flash.get("manufacturer_id") in ("ff", "00"):
        warnings.append("플래시 ID 가 비정상(ff/00): SPI 플래시와 통신하지 못했다. 배선/전원/스트래핑을 확인하라.")
    out.update(warnings=warnings, notes=notes)
    out["next_steps"] = (f"esp_security_info(case_id='{run['case'].id}', port='{run['spec'].port}') 로 보안 설정을 확인한 뒤 "
                         f"esp_read_flash_start(case_id='{run['case'].id}', port='{run['spec'].port}', size='all') 로 덤프한다.")
    out["provenance"] = _record_fact("esp-chip-info", "esp_chip_info", run, conn, _chip_fact(out))
    return out


# ---------------------------------------------------------------------------
# 출처 원장 (pweh.provenance): 기기 사실(device-fact)과 덤프(device-read)
# ---------------------------------------------------------------------------

_CHIP_FACT_FIELDS = ("status", "chip", "chip_description", "chip_revision", "features", "crystal_mhz", "usb_mode", "mac", "base_mac",
                     "mac_ext", "secure_download_mode", "stub", "detected_chip", "read_flash_possible", "flash")


def _chip_fact(out: dict[str, Any]) -> dict[str, Any]:
    return {k: out.get(k) for k in _CHIP_FACT_FIELDS}


def _record_fact(fact_kind: str, tool: str, run: dict[str, Any], conn: dict[str, Any], data: dict[str, Any]) -> dict[str, Any]:
    """esp_chip_info·esp_security_info 결과를 출처 원장에 기기 사실로 기록한다 (계측기 플래시 전 백업·보안 상태 확인의 근거).

    기록 실패는 기기 결과를 막지 않는다. 원장에 없는 사실은 확인하는 쪽에서 '없음'으로 다뤄진다(fail closed).
    """
    spec: ports.PortSpec = run["spec"]
    backend: Backend = run["backend"]
    source = {"server": SERVER_NAME, "tool": tool, "port": spec.port, "backend": backend.name, "esptool_version": backend.version,
              "chip": conn.get("chip") or conn.get("detected_chip"), "mac": conn.get("mac"), "base_mac": conn.get("base_mac"),
              "usb_mode": conn.get("usb_mode"), "log_path": run.get("log_path")}
    try:
        entry = rt().provenance.record_device_fact(run["case"], fact_kind, data, source)
    except Exception as exc:  # noqa: BLE001 - 출처 기록 실패가 기기 결과를 막지 않게
        log.warning("출처 원장 기록 실패 (%s): %s", fact_kind, exc)
        return {"recorded": False, "kind": "device-fact", "fact_kind": fact_kind,
                "reason": f"{getattr(exc, 'code', type(exc).__name__)}: {exc}"[:300]}
    return {"recorded": True, "kind": "device-fact", "fact_kind": fact_kind, "seq": entry["seq"]}


def _record_dump_provenance(case: Case, plan: "DumpPlan", reads: list[dict[str, Any]], verification: dict[str, Any],
                            source: dict[str, Any], job_id: str | None) -> dict[str, Any]:
    """끝난 덤프의 읽기 파일(1차·2차)을 출처 원장에 device-read 로 기록한다.

    워커가 esptool 이 쓴 직후 계산한 sha256 을 넘겨, 공개한 파일이 그사이 바뀌었으면 기록하지 않는다.
    """
    src = {"server": SERVER_NAME, "tool": "esp_read_flash_start", "port": plan.port.port, "backend": plan.backend.name,
           "chip": source.get("chip") or plan.chip, "chip_description": source.get("chip_description"), "mac": source.get("mac"),
           "base_mac": source.get("base_mac"), "usb_mode": source.get("usb_mode"), "esptool_version": plan.backend.version,
           "verify": verification.get("method"), "match": verification.get("match")}
    recorded: list[dict[str, Any]] = []
    try:
        for i, rd in enumerate(reads):
            extra = {"role": "primary" if i == 0 else "verification-read", "read": rd.get("index"), "offset": plan.offset,
                     "length": rd.get("size"), "job_id": job_id, "after": rd.get("after"), "baud": rd.get("baud")}
            entry = rt().provenance.record_device_read(case, rd["path"], src, extra, sha256=rd["sha256"])
            recorded.append({"path": entry["path"], "seq": entry["seq"], "sha256": entry["sha256"]})
    except Exception as exc:  # noqa: BLE001 - 덤프 결과는 이미 공개됨, 출처 기록 실패만 알린다
        log.warning("출처 원장 기록 실패 (덤프): %s", exc)
        return {"recorded": False, "kind": "device-read", "entries": recorded,
                "reason": f"{getattr(exc, 'code', type(exc).__name__)}: {exc}"[:300]}
    return {"recorded": True, "kind": "device-read", "entries": recorded}


_SECURITY_NULL_FIELDS = (
    "secure_boot", "secure_boot_aggressive_revoke", "revoked_keys", "flash_encryption", "crypt_cnt", "crypt_cnt_field",
    "secure_download_mode", "read_flash_possible", "ciphertext_expected", "jtag_hard_disabled", "jtag_soft_disabled", "usb_disabled",
    "download_dcache_disabled", "download_icache_disabled", "key_blocks", "key_purposes_raw", "raw_fields", "flags_hex", "parsed_flags",
    "chip_id", "api_version",
)


@server.tool(
    description=(
        "보안 설정 조회 (esptool get-security-info, MODIFY: 리셋으로 ROM 다운로드 모드 진입, 쓰기 없음, 케이스 소유/허가 증명 필요). "
        "반환: status('ok' | 'unsupported'), secure_boot, flash_encryption(SPI_BOOT_CRYPT_CNT 홀수 비트=켜짐), crypt_cnt, secure_download_mode(플래그 비트 2), "
        "read_flash_possible, ciphertext_expected, jtag_hard_disabled/jtag_soft_disabled, usb_disabled, download_dcache/icache_disabled, "
        "key_blocks[{block, purpose}], flags_hex, parsed_flags, raw_fields(보안 블록의 'Label: value' 원문), chip_id, api_version, assessment, "
        "log_path(uart/esptool-security-info-NNN.log). "
        "Secure Download Mode 에서도 동작한다. read_flash_possible=false 면 덤프를 시도하지 말고 우회 없이 사용자에게 보고한다. "
        "원조 ESP32/ESP8266 은 이 명령을 지원하지 않아 ok=true, status='unsupported', 보안 필드·read_flash_possible 이 null(보안 상태 미확인)이다."
    ),
    annotations=ANN_DEVICE,
)
@safe_tool
async def esp_security_info(
    case_id: str,
    port: str,
    chip: str = "auto",
    baud: int | None = None,
    before: str = "default-reset",
    after: str = "hard-reset",
    no_stub: bool = False,
    timeout_s: float | None = None,
    approval_id: str | None = None,
    ctx: Context = None,  # type: ignore[assignment]
) -> dict[str, Any]:
    run = await _run_info_command(tool="esp_security_info", command="get-security-info", log_prefix="esptool-security-info",
                                  case_id=case_id, port=port, chip=chip, baud=baud, before=before, after=after, no_stub=no_stub,
                                  timeout_s=timeout_s, approval_id=approval_id, ctx=ctx)
    if "gate" in run:
        return run["gate"]
    text, res = run["text"], run["res"]
    conn = parse_connect(text)
    sec = parse_security_info(text)
    chip_name = conn["chip"] or conn["detected_chip"]
    finished = not (res.cancelled or res.timed_out or res.idle_timed_out)
    if (res.returncode != 0 and finished and sec is None and not conn["secure_download_mode"]
            and security_info_unsupported(text, chip_name or conn["chip_description"])):
        warnings, notes = _connect_notes(conn, run)
        notes.insert(0, "이 칩(원조 ESP32/ESP8266)은 get-security-info 를 지원하지 않아 보안 상태(Secure Boot·플래시 암호화·Secure Download Mode)를 "
                        "알 수 없다(미확인). Skill 은 보안 상태를 '미확인'으로 기록하고 진행한다 — 원조 ESP32 에는 Secure Download Mode 가 없어 "
                        "read-flash 를 시도할 수 있고, 플래시 암호화가 켜져 있으면 덤프는 암호문이다(정적 분석에서 확인).")
        out: dict[str, Any] = {"ok": True, "status": "unsupported", **_base_result(run), "chip": chip_name,
                               "chip_description": conn["chip_description"]}
        out.update({k: None for k in _SECURITY_NULL_FIELDS})
        out.update({
            "assessment": ["보안 상태 미확인: 이 칩은 get-security-info 를 지원하지 않는다(원조 ESP32/ESP8266)."],
            "error": fatal_message(text),
            "warnings": warnings,
            "notes": notes,
        })
        rt().audit({"event": "esp_security_summary", "port": run["spec"].port, "status": "unsupported", "chip": chip_name}, run["case"].id)
        out["provenance"] = _record_fact("esp-security-info", "esp_security_info", run, conn, _security_fact(out))
        return out
    if res.returncode != 0 or sec is None:
        raise_for_result(res, text, "esp_security_info(get-security-info)", log_path=run["log_path"])
        raise EsptoolFailed(f"get-security-info 출력을 해석할 수 없습니다 (로그: {run['log_path']})", code="esp_bad_output",
                            hint="esptool 버전이 예상과 다를 수 있다. 로그를 확인하라.")
    warnings, notes = _connect_notes(conn, run)
    sdm = bool(sec["secure_download_mode"] or conn["secure_download_mode"])
    fe = bool(sec["flash_encryption"])
    assessment: list[str] = []
    if sdm:
        assessment.append("Secure Download Mode 켜짐: ROM 로더가 플래시 읽기·레지스터 접근을 거부한다 → esptool 로 덤프 불가. 우회 시도 금지, 사용자에게 보고.")
    else:
        assessment.append("Secure Download Mode 꺼짐: esptool read-flash 로 덤프할 수 있다.")
    if fe:
        assessment.append("플래시 암호화 켜짐: 부트로더·파티션 테이블·앱 등 암호화 대상 영역은 암호문으로 읽힌다(키는 읽기 보호된 eFuse 에 있음) — "
                          "정적 분석은 지워진 영역과 암호화하지 않는 데이터 파티션(NVS 암호화를 따로 켜지 않은 NVS 등) 외에는 사실상 불가.")
    else:
        assessment.append("플래시 암호화 꺼짐: 덤프는 평문이다.")
    assessment.append("Secure Boot " + ("켜짐: 서명되지 않은 펌웨어는 부팅되지 않는다(읽기에는 영향 없음)." if sec["secure_boot"] else "꺼짐."))
    if sec["jtag_hard_disabled"]:
        assessment.append("JTAG 영구 비활성(eFuse).")
    elif sec["jtag_soft_disabled"]:
        assessment.append("JTAG 소프트웨어 비활성(HMAC 로 다시 켤 수 있는 설정).")
    if sec["usb_disabled"]:
        assessment.append("USB 비활성 플래그 켜짐.")
    out = {"ok": True, "status": "ok", **_base_result(run), "chip": chip_name}
    out.update({
        "secure_boot": sec["secure_boot"],
        "secure_boot_aggressive_revoke": sec["secure_boot_aggressive_revoke"],
        "revoked_keys": sec["revoked_keys"],
        "flash_encryption": fe,
        "crypt_cnt": sec["crypt_cnt"],
        "crypt_cnt_field": sec["crypt_cnt_field"],
        "secure_download_mode": sdm,
        "read_flash_possible": not sdm,
        "ciphertext_expected": fe,
        "jtag_hard_disabled": sec["jtag_hard_disabled"],
        "jtag_soft_disabled": sec["jtag_soft_disabled"],
        "usb_disabled": sec["usb_disabled"],
        "download_dcache_disabled": sec["download_dcache_disabled"],
        "download_icache_disabled": sec["download_icache_disabled"],
        "key_blocks": sec["key_blocks"],
        "key_purposes_raw": sec["key_purposes_raw"],
        "raw_fields": sec["raw_fields"],
        "flags_hex": sec["flags_hex"],
        "parsed_flags": sec["parsed_flags"],
        "chip_id": sec["chip_id"],
        "api_version": sec["api_version"],
        "assessment": assessment,
        "warnings": warnings,
        "notes": notes,
    })
    rt().audit({"event": "esp_security_summary", "port": run["spec"].port, "status": "ok", "secure_boot": sec["secure_boot"],
                "flash_encryption": fe, "secure_download_mode": sdm}, run["case"].id)
    out["provenance"] = _record_fact("esp-security-info", "esp_security_info", run, conn, _security_fact(out))
    return out


def _security_fact(out: dict[str, Any]) -> dict[str, Any]:
    """보안 사실(원장 data): status·chip + 보안 필드 전부 (unsupported 면 보안 필드는 null = 미확인)."""
    return {"status": out.get("status"), "chip": out.get("chip"), "chip_description": out.get("chip_description"),
            **{k: out.get(k) for k in _SECURITY_NULL_FIELDS}}


# ---------------------------------------------------------------------------
# 플래시 읽기 (job)
# ---------------------------------------------------------------------------


@dataclass
class ReadStep:
    index: int
    after: str  # 실제로 넘기는 --after
    baud: int
    timeout_s: float
    partial: Path  # esptool 이 쓰는 숨은 예약 파일 (dumps 실제 경로/.<stem>.readN.partial)
    argv: list[str]
    output_token: str  # argv 의 출력 경로 토큰 (리눅스 경로 또는 Windows 경로)
    output_map: dict[str, str]
    win_match: WinMatch | None = None
    log_path: Path | None = None


@dataclass
class DumpPlan:
    case_id: str
    case_dir: Path
    case_real: str  # 계획할 때의 realpath(케이스)
    dumps_dir: Path  # 케이스 dumps/ (계획할 때 경로)
    dumps_real: str  # 계획할 때의 realpath(dumps/) — 예약·최종 파일은 모두 이 디렉터리에 만든다
    stem: str
    owner_path: Path  # 소유 표식 .<stem>.owner.partial
    port: ports.PortSpec
    backend: Backend
    chip: str
    baud: int
    before: str
    after: str  # 마지막 읽기 뒤 실제로 넘기는 --after
    after_requested: str
    no_stub: bool
    offset: int
    size: int | str
    verify: str
    steps: list[ReadStep]
    exclusive_key: str
    plan_notes: list[str] = field(default_factory=list)

    @property
    def n_reads(self) -> int:
        return len(self.steps)

    @property
    def meta_partial(self) -> Path:
        return Path(self.dumps_real) / f".{self.stem}.meta.partial"

    def requested(self) -> dict[str, Any]:
        out = {"port": self.port.port, "chip": self.chip, "offset": self.offset, "size": self.size, "baud": self.baud,
               "verify": self.verify, "before": self.before, "after": self.after, "no_stub": self.no_stub}
        if self.after_requested != self.after:
            out["after_requested"] = self.after_requested
        return out


def _dump_names(dumps_dir: Path, stem: str, n_reads: int) -> list[Path]:
    names = [dumps_dir / f"{stem}.bin", dumps_dir / f"{stem}.json"]
    if n_reads == 2:
        names.append(dumps_dir / f"{stem}.read2.bin")
    return names


def _check_name_free(dumps_dir: Path, name: str, n_reads: int) -> None:
    taken = [p.name for p in _dump_names(dumps_dir, name, n_reads) if os.path.lexists(p)]
    if taken:
        raise CaseError(f"이미 같은 이름의 덤프 파일이 있습니다: {', '.join('dumps/' + t for t in taken)}",
                        hint="다른 output_name 을 쓰거나 생략(자동 번호)하라. 기존 증거는 덮어쓰지 않는다.")


def _reserve_dump(dumps_dir: Path, name: str | None, n_reads: int) -> tuple[str, list[Path], Path]:
    """숨은 예약 파일만 O_EXCL 로 선점한다: 소유 표식 ``.<stem>.owner.partial``(주인 PID 등) → ``.<stem>.readN.partial``.

    최종 파일(.bin/.read2.bin/.json)은 만들지 않는다(끝날 때 O_EXCL 로 만든다). 반환: (stem, 데이터 예약 경로들, 소유 표식).
    이름을 주면 그 이름만, 아니면 esp-flash, esp-flash-002 … 순서로 찾는다.
    """
    stems = [name] if name else [DEFAULT_DUMP_NAME] + [f"{DEFAULT_DUMP_NAME}-{n:03d}" for n in range(2, 100000)]
    with _RESERVE_LOCK:
        for stem in stems:
            finals = _dump_names(dumps_dir, stem, n_reads)
            if any(os.path.lexists(p) for p in finals):
                if name:
                    _check_name_free(dumps_dir, name, n_reads)
                continue
            owner = dumps_dir / f".{stem}.owner.partial"
            partials = [dumps_dir / f".{stem}.read{i}.partial" for i in range(1, n_reads + 1)]
            _ACTIVE_RESERVATIONS.add(str(owner))
            if not _reserve(owner, (json.dumps(_owner_record(), ensure_ascii=False) + "\n").encode("utf-8")):
                _ACTIVE_RESERVATIONS.discard(str(owner))
                if name:
                    raise Busy(f"같은 이름({name})의 덤프가 진행 중입니다(소유 표식 dumps/.{name}.owner.partial).",
                               hint="다른 output_name 을 쓰거나 esp_jobs 로 진행 중인 작업을 확인하라.")
                continue
            got: list[Path] = []
            ok = True
            for p in partials:
                if _reserve(p):
                    got.append(p)
                else:
                    ok = False
                    break
            if ok:
                return stem, partials, owner
            for p in got:
                _unlink(p)
            _unlink(owner)
            _ACTIVE_RESERVATIONS.discard(str(owner))
            if name:
                raise Busy(f"같은 이름({name})의 예약 파일이 남아 있습니다: dumps/.{name}.read*.partial",
                           hint="다른 output_name 을 쓰거나 esp_jobs 로 진행 중인 작업을 확인하라(낡은 예약은 서버 재시작 때 정리된다).")
    raise CaseError("덤프 파일 이름을 만들 수 없습니다.")


def _update_owner(owner: Path, *, only_if_active: bool = False, **fields: Any) -> None:
    """소유 표식 내용 갱신 (job_id, 남은 Windows PID 등).

    only_if_active: 이 프로세스가 아직 그 예약을 쓰는 중일 때만 (작업이 이미 예약을 풀었으면 소유 표식을 다시 만들지 않는다).
    """
    with _RESERVE_LOCK:
        if only_if_active and str(owner) not in _ACTIVE_RESERVATIONS:
            return
        try:
            rec = json.loads(owner.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            rec = _owner_record()
        rec.update(fields)
        try:
            atomic_write_json(owner, rec)
        except OSError:  # pragma: no cover
            log.warning("소유 표식 갱신 실패: %s", owner)


def _release_reservation(plan: DumpPlan, *, orphan_pids: list[int] | None = None) -> None:
    """예약 해제: 데이터 예약 → 소유 표식 순서로 지운다. 남은 Windows esptool.exe 가 있으면 파일을 남기고 소유 표식에 PID 를 적는다
    (그 프로세스가 나중에 예약 파일을 쓸 수 있으므로 — 정리는 그 PID 가 없어진 뒤 _sweep_dumps_dir 가 한다)."""
    with _RESERVE_LOCK:
        if orphan_pids:
            _update_owner(plan.owner_path, windows_pids=list(orphan_pids), windows_images=[exe_image(plan.backend.exe)],
                          released_at=utcnow_iso())
        else:
            for st in plan.steps:
                _unlink(st.partial)
            _unlink(plan.meta_partial)
            _unlink(plan.owner_path)
        _ACTIVE_RESERVATIONS.discard(str(plan.owner_path))


def _read_timeout(size: int | str, baud: int, no_stub: bool) -> float:
    nbytes = size if isinstance(size, int) else ASSUMED_ALL_BYTES
    rate = baud / 10.0 * (0.1 if no_stub else 0.25)  # 최악의 경우 처리량(바이트/초)
    return min(MAX_READ_TIMEOUT_S, 120.0 + nbytes / max(rate, 100.0))


def _size_token(size: int | str) -> str:
    return "ALL" if size == "all" else f"0x{int(size):x}"


def _output_token(spec: ports.PortSpec, partial: Path) -> tuple[str, dict[str, str]]:
    if spec.backend == "windows":
        win = ports.to_windows_path(partial)
        ports.check_windows_path(win)
        return win, {win: str(partial)}
    return str(partial), {str(partial): str(partial)}


def _within_real(path: str, base: str) -> bool:
    return path == base or path.startswith(base.rstrip("/") + "/")


def _recheck_dump_paths(plan: DumpPlan, step: ReadStep | None = None) -> None:
    """실행·공개 직전 경로 재확인: 케이스·dumps/ 의 realpath 가 계획 때와 같고 dumps/ 가 실제 디렉터리(심볼릭 링크 아님)이며,
    예약 파일이 (심볼릭 링크가 아닌) 일반 파일로 케이스 안에 있는지. 바뀌었으면 SafetyDenied."""
    if os.path.realpath(plan.case_dir) != plan.case_real:
        raise SafetyDenied(f"케이스 디렉터리의 실제 경로가 바뀌었다: {plan.case_dir} (계획: {plan.case_real})")
    try:
        st = os.lstat(plan.dumps_dir)
    except OSError:
        raise SafetyDenied(f"케이스 dumps/ 가 사라졌다: {plan.dumps_dir}")
    if stat.S_ISLNK(st.st_mode) or not stat.S_ISDIR(st.st_mode):
        raise SafetyDenied(f"케이스 dumps/ 가 실제 디렉터리가 아니다(심볼릭 링크로 바뀜?): {plan.dumps_dir}")
    if os.path.realpath(plan.dumps_dir) != plan.dumps_real:
        raise SafetyDenied(f"케이스 dumps/ 의 실제 경로가 바뀌었다: {os.path.realpath(plan.dumps_dir)} (계획: {plan.dumps_real})")
    if step is not None:
        try:
            pst = os.lstat(step.partial)
        except OSError:
            raise SafetyDenied(f"예약 파일이 사라졌다: {step.partial.name}")
        if stat.S_ISLNK(pst.st_mode) or not stat.S_ISREG(pst.st_mode):
            raise SafetyDenied(f"예약 파일이 일반 파일이 아니다(심볼릭 링크로 바뀜?): {step.partial.name}")
        if not _within_real(os.path.realpath(step.partial), plan.case_real):
            raise SafetyDenied(f"예약 파일의 실제 경로가 케이스 밖이다: {os.path.realpath(step.partial)}")


def _report_progress(jctx: Any, idx: int, n: int, p: Progress) -> None:
    frac = max(0.0, min(1.0, p.percent / 100.0))
    overall = ((idx - 1) + frac) / n
    extra = ""
    if p.done is not None and p.total:
        extra = f" ({human_size(p.done)}/{human_size(p.total)})"
    elif p.done is not None:
        extra = f" ({human_size(p.done)})"
    jctx.progress(round(overall * 1000), 1000, f"읽기 {idx}/{n}: {p.percent:.1f}%{extra}")


def _publish_exclusive(src: Path, dst: Path) -> None:
    """숨은 파일 src 를 최종 이름 dst 로 공개한다. dst 가 이미 있으면 FileExistsError (기존 증거를 덮어쓰지 않음).

    하드 링크(원자적, 내용이 다 찬 파일만 보임) → 하드 링크를 못 쓰는 파일시스템이면 O_EXCL 로 만들어 복사. 성공하면 src 를 지운다.
    """
    try:
        os.link(src, dst)
    except FileExistsError:
        raise
    except OSError:
        fd = os.open(dst, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o644)
        try:
            with os.fdopen(fd, "wb") as out, open(src, "rb") as inp:
                shutil.copyfileobj(inp, out, 1 << 20)
                out.flush()
                os.fsync(out.fileno())
        except BaseException:
            _unlink(dst)
            raise
    _unlink(src)


def _publish_reads(plan: DumpPlan, reads: list[dict[str, Any]], job_id: str | None, warnings: list[str]) -> str:
    """읽기 결과(숨은 .partial)를 최종 이름으로 공개하고 쓴 stem 을 돌려준다. 계획한 이름이 그사이 생겼으면 <stem>-<job_id> 로."""
    dumps = Path(plan.dumps_real)
    both = len(reads) == 2
    candidates = [plan.stem] + ([f"{plan.stem}-{job_id}"] if job_id else []) + [f"{plan.stem}-{os.getpid()}-{int(time.time())}"]
    for stem in candidates:
        targets = [dumps / f"{stem}.bin"] + ([dumps / f"{stem}.read2.bin"] if both else [])
        if any(os.path.lexists(t) for t in targets + [dumps / f"{stem}.json"]):
            continue
        done: list[tuple[Path, Path]] = []
        try:
            for rd, tgt in zip(reads, targets):
                _publish_exclusive(rd["partial"], tgt)
                done.append((rd["partial"], tgt))
        except FileExistsError:
            for src, tgt in reversed(done):  # 이번 시도에서 만든 것만 되돌린다 (우리가 방금 만든 파일)
                try:
                    os.rename(tgt, src)
                except OSError:  # pragma: no cover
                    log.warning("공개 되돌리기 실패: %s", tgt)
            continue
        for rd, tgt in zip(reads, targets):
            rd["path"] = tgt
        if stem != plan.stem:
            warnings.append(f"계획한 이름 dumps/{plan.stem}.bin 등이 덤프 도중 다른 곳에서 만들어져 dumps/{stem}.bin 으로 저장했다"
                            "(기존 파일은 덮어쓰지 않음).")
        return stem
    raise CaseError(f"덤프 결과를 공개할 이름을 찾을 수 없습니다: dumps/{plan.stem}.bin",
                    hint="예약 파일(dumps/.<name>.readN.partial)은 남겨 두었다. 사람이 확인하라.")


def _verification_detail(plan: DumpPlan, both: bool) -> str:
    md5 = "esptool 스텁은 읽기마다 전송 MD5 를 검증한다." if not plan.no_stub else "ROM 직접 읽기(--no-stub): 전송 MD5 검증 없음."
    if both:
        base = ("같은 영역을 두 번 읽어 sha256 비교 (1차는 --after no-reset-stub 으로 칩을 다운로드 모드에 둬 앱이 실행되지 않게 함"
                + (f", 수동 다운로드 모드라 1차는 {plan.steps[0].baud} baud" if plan.steps[0].baud != plan.baud else "") + "). ")
        return base + md5
    if not plan.no_stub:
        return "한 번만 읽음 (esptool 스텁의 전송 MD5 검증만 통과)" + (" — 요청한 이중 읽기를 끝내지 못함" if plan.verify == "double" else "")
    return "한 번만 읽음 — ROM 직접 읽기(--no-stub): 전송 MD5 검증 없음" + (" — 요청한 이중 읽기를 끝내지 못함" if plan.verify == "double" else "")


def _finalize_dump(plan: DumpPlan, reads: list[dict[str, Any]], *, status: str, notes: list[str], warnings: list[str],
                   started_at: str, t0: float, job_id: str | None) -> dict[str, Any]:
    """읽기 결과를 최종 이름으로 공개(O_EXCL) + 메타데이터(firmware-dump 스키마 모양) 작성 + 아티팩트 등록."""
    case = rt().cases.get(plan.case_id)
    _recheck_dump_paths(plan)
    stem = _publish_reads(plan, reads, job_id, warnings)
    dumps = Path(plan.dumps_real)
    primary = reads[0]
    both = len(reads) == 2
    if both:
        match = reads[0]["sha256"] == reads[1]["sha256"]
        verification = {"method": "double-read", "expected": reads[0]["sha256"], "actual": reads[1]["sha256"], "match": match,
                        "detail": _verification_detail(plan, True)}
        if not match:
            warnings.append("두 번 읽은 결과가 다르다 — 전송 오류(낮은 baud 로 다시 읽기)나 플래시 불안정(전원/배선)을 의심하라. 두 파일 모두 보존했다.")
    else:
        verification = {"method": "none", "expected": None, "actual": None, "match": None, "detail": _verification_detail(plan, False)}
    conn = primary.get("connect") or {}
    rf = primary.get("read") or {}
    flash_str = rf.get("detected_flash_size")
    source = {
        "type": "esptool",
        "device_path": plan.port.port,
        "chip": conn.get("chip"),
        "chip_description": conn.get("chip_description"),
        "mac": conn.get("mac"),
        "base_mac": conn.get("base_mac"),
        "usb_mode": conn.get("usb_mode"),
        "flash_size": flash_size_bytes(flash_str),
        "flash_size_str": flash_str,
        "offset": plan.offset,
        "length": primary["size"],
        "requested_size": plan.size,
        "flash_type": "spi-nor",
        "partition": None,
        "ram_addr": None,
    }
    tool = {
        "name": "esptool",
        "esptool_version": plan.backend.version,
        "backend": plan.backend.name,
        "esptool_path": plan.backend.exe,
        "argv": [r["argv"] for r in reads],
    }
    meta = {
        "schema": "pweh.esp-dump/v1",
        "method": "esptool-read-flash",
        "source": source,
        "output": {"path": case.rel(primary["path"]), "sha256": primary["sha256"], "size": primary["size"]},
        "verification": verification,
        "reads": [{k: (case.rel(v) if k == "path" else v) for k, v in r.items() if k not in ("connect", "read", "argv", "partial")}
                  for r in reads],
        "tool": tool,
        "baudrate": plan.baud,
        "status": status,
        "duration_seconds": round(time.monotonic() - t0, 2),
        "started_at": started_at,
        "finished_at": utcnow_iso(),
        "job_id": job_id,
        "notes": notes,
        "warnings": warnings,
    }
    meta_path = dumps / f"{stem}.json"
    atomic_write_json(plan.meta_partial, meta)
    try:
        _publish_exclusive(plan.meta_partial, meta_path)
    except FileExistsError:
        meta_path = dumps / f"{stem}-{job_id or os.getpid()}.json"
        warnings.append(f"메타데이터 이름 dumps/{stem}.json 이 그사이 생겨 {case.rel(meta_path)} 로 저장했다.")
        meta["warnings"] = warnings
        atomic_write_json(plan.meta_partial, meta)
        _publish_exclusive(plan.meta_partial, meta_path)
    art = case.register_artifact(primary["path"], kind="flash-dump", producer=PRODUCER,
                                 description=f"esptool 플래시 덤프 ({source['chip'] or plan.chip}, {plan.port.port}, 0x{plan.offset:x} +{primary['size']} 바이트)",
                                 extra={"metadata": case.rel(meta_path), "method": "esptool-read-flash", "role": "primary",
                                        "sha256": primary["sha256"]})
    arts = {"primary": art}
    if both:
        arts["read2"] = case.register_artifact(reads[1]["path"], kind="flash-dump", producer=PRODUCER,
                                               description="esptool 플래시 덤프 2차 읽기(이중 읽기 검증용)",
                                               extra={"metadata": case.rel(meta_path), "method": "esptool-read-flash",
                                                      "role": "verification-read", "primary": case.rel(primary["path"])})
    arts["metadata"] = case.register_artifact(meta_path, kind="other", producer=PRODUCER, description="esptool 덤프 메타데이터",
                                              extra={"type": "dump-metadata", "dump": case.rel(primary["path"])})
    # 출처 원장: 끝까지 성공한 덤프만 기기 읽기(device-read)로 기록한다. 실패·취소 때 보존한 1차 읽기는 기록하지 않는다(신뢰하지 않음).
    if status == "succeeded":
        provenance = _record_dump_provenance(case, plan, reads, verification, source, job_id)
        if not provenance["recorded"]:
            warnings.append(f"출처 원장에 덤프를 기록하지 못했다({provenance.get('reason')}) — 출처 확인이 필요한 작업에서 이 덤프는 "
                            "신뢰되지 않는다.")
    else:
        provenance = {"recorded": False, "kind": "device-read", "reason": f"status={status} (끝까지 성공한 덤프만 기록)"}
    rt().audit({"event": "esp_read_flash_completed", "status": status, "output": case.rel(primary["path"]), "sha256": primary["sha256"],
                "size": primary["size"], "match": verification["match"], "backend": plan.backend.name, "port": plan.port.port,
                "provenance_recorded": provenance["recorded"]}, plan.case_id)
    return {
        "ok": True,
        "provenance": provenance,
        "status": status,
        "path": case.rel(primary["path"]),
        "absolute_path": str(primary["path"]),
        "read2_path": case.rel(reads[1]["path"]) if both else None,
        "metadata_path": case.rel(meta_path),
        "size": primary["size"],
        "sha256": primary["sha256"],
        "sha256_read2": reads[1]["sha256"] if both else None,
        "match": verification["match"],
        "verification": verification,
        "source": source,
        "backend": plan.backend.name,
        "port": plan.port.port,
        "esptool_version": plan.backend.version,
        "log_paths": [r.get("log_path") for r in reads],
        "artifacts": arts,
        "warnings": warnings,
        "notes": notes,
        "summary_hint": {
            "method": "esptool-read-flash",
            "source": {k: source[k] for k in ("device_path", "flash_size", "offset", "length", "flash_type")},
            "output": meta["output"],
            "verification": {k: verification[k] for k in ("method", "expected", "actual", "match")},
            "baudrate": plan.baud,
        },
    }


_CONNECT_FAILURE_CODES = {"esp_no_serial_data", "esp_connect_failed", "esp_wrong_boot_mode", "esp_tx_path_down", "esp_serial_noise"}


def _read_flash_worker(plan: DumpPlan, jctx: Any) -> dict[str, Any]:
    """두(또는 한) 번 읽기. 실행 직전마다 소유/허가 증명·dumps/ 실제 경로·argv 분류를 다시 확인한다.

    esptool 은 read-flash 결과를 모든 데이터를 받은 뒤에만 파일로 쓰므로, 끝나지 않은 읽기(취소·실패)에는 부분 데이터가 없다 →
    그 읽기의 예약 파일은 지운다. 1차 읽기가 끝난 뒤 2차 읽기가 취소·실패하면 1차 결과를 검증 없음(verification.method='none')으로 보존한다.
    최종 파일은 끝날 때 O_EXCL 로 만든다. Windows esptool.exe 가 끝까지 남으면(orphans) 예약 파일을 남기고 PID 를 담은 오류로 끝난다.
    """
    r = rt()
    case = r.cases.get(plan.case_id)
    lock = _port_lock(plan.exclusive_key)
    if not lock.acquire(blocking=False):
        _release_reservation(plan)
        raise Busy(f"포트 {plan.port.port} 를 다른 esp 작업이 사용 중입니다.", hint="esp_jobs 로 확인하라.")
    started = utcnow_iso()
    t0 = time.monotonic()
    reads: list[dict[str, Any]] = []
    notes: list[str] = list(plan.plan_notes)
    warnings: list[str] = []
    n = plan.n_reads
    cancelled_at: int | None = None
    error: Exception | None = None
    orphans: list[int] = []
    check_failed = False
    try:
        for step in plan.steps:
            if jctx.cancelled:
                cancelled_at = step.index
                break
            r.case(plan.case_id, hardware=True)  # 도중에 소유/허가 증명이 철회되면 멈춘다
            _recheck_dump_paths(plan, step)
            cls = classify_esptool_argv(step.argv, port=plan.port.port, allowed_output_dir=plan.dumps_real,
                                        output_map=step.output_map, esptool_major=plan.backend.major,
                                        esptool_minor=plan.backend.minor)
            if cls.risk != Risk.MODIFY or cls.rule_id != "esp.read-flash":
                raise SafetyDenied(f"읽기 명령이 실행 직전 재분류에서 거부됨: {cls.reason}", data={"classification": cls.to_dict()})
            jctx.log(f"읽기 {step.index}/{n} 시작 (after={step.after}, baud={step.baud}): {' '.join(display_argv(step.argv))}")
            jctx.update_meta(read=step.index)
            t_step = utcnow_iso()
            with _run_dir(plan.backend.windows) as rd:
                watch = ConfigWatch(rd.allowed_configs())
                col = OutputCollector(on_progress=lambda p, i=step.index: _report_progress(jctx, i, n, p), on_line=watch.line)
                res = run_streaming(step.argv, timeout=step.timeout_s, idle_timeout=READ_IDLE_TIMEOUT_S, on_text=col.feed,
                                    cancel=lambda: jctx.cancelled or watch.foreign is not None, cwd=rd.path,
                                    env=child_env(windows=plan.backend.windows, run_dir=rd.path, stub_version=plan.backend.stub_version),
                                    win_match=step.win_match)
            col.close()
            check_failed = check_failed or res.orphan_check_failed
            step.log_path = _reserve_numbered(case.subdir("uart"), f"esptool-{plan.stem}-read{step.index}", ".log")
            _write_log(step.log_path, argv=step.argv, backend=plan.backend, port=plan.port.port, res=res, col=col, started_at=t_step,
                       note=f"read-flash {step.index}/{n}")
            _register_log(case, step.log_path, f"read-flash {step.index}/{n}", plan.port.port)
            log_rel = case.rel(step.log_path)
            if res.orphans:
                orphans = list(res.orphans)
                raise _orphan_error(res, f"read-flash {step.index}/{n}", plan.port.port, log_rel)
            if watch.foreign:
                raise foreign_config_error(watch.foreign, watch.allowed, f"read-flash {step.index}/{n}", log_path=log_rel)
            if res.cancelled:
                cancelled_at = step.index
                jctx.log(f"읽기 {step.index}/{n} 취소됨 (esptool 프로세스 종료"
                         + (", Windows esptool.exe 가 남지 않음을 확인" if plan.backend.windows and not res.orphan_check_failed else "") + ")")
                break
            text = col.text
            raise_for_result(res, text, f"read-flash {step.index}/{n}", log_path=log_rel,
                             timeout_hint="baud 를 확인하고(USB-UART 는 921600 이 불안정할 수 있음) timeout_s 를 늘려 다시 시도하라.")
            rf = parse_read_flash(text)
            pst = os.lstat(step.partial) if os.path.lexists(step.partial) else None
            if pst is not None and (stat.S_ISLNK(pst.st_mode) or not stat.S_ISREG(pst.st_mode)):
                raise SafetyDenied(f"예약 파일이 일반 파일이 아니다: {step.partial.name}")
            size = pst.st_size if pst is not None else 0
            expected = plan.size if isinstance(plan.size, int) else rf.get("bytes_read")
            if size <= 0 or (expected and size != expected) or (rf.get("bytes_read") and size != rf["bytes_read"]):
                raise EsptoolFailed(
                    f"read-flash {step.index}/{n}: 출력 파일 크기 {size} 가 예상({expected}, esptool 보고 {rf.get('bytes_read')})과 다름 (로그: {log_rel})",
                    code="esp_output_size_mismatch", hint="Windows 백엔드면 wslpath 경로에 쓸 수 있는지 확인하고 다시 시도하라.")
            if reads and size != reads[0]["size"]:
                raise EsptoolFailed(f"두 읽기의 크기가 다름: {reads[0]['size']} != {size} (로그: {log_rel})", code="esp_output_size_mismatch")
            sha = sha256_file(step.partial)
            conn = parse_connect(text)
            reads.append({"index": step.index, "partial": step.partial, "sha256": sha, "size": size, "after": step.after,
                          "baud": step.baud, "seconds": rf.get("seconds"), "kbit_s": rf.get("kbit_s"), "log_path": log_rel,
                          "started_at": t_step, "argv": display_argv(step.argv), "connect": conn, "read": rf})
            warnings.extend(w for w in output_warnings(text) if w not in warnings)
            if conn.get("custom_config") and not conn.get("custom_config_via_env"):
                warnings.append(f"esptool 이 설정 파일을 읽음: {conn['custom_config']}")
            jctx.log(f"읽기 {step.index}/{n} 완료: {size} 바이트 sha256={sha}")
    except Exception as exc:  # noqa: BLE001 - 정리 후 다시 던진다
        error = exc
    finally:
        lock.release()

    if check_failed:
        warnings.append("Windows esptool.exe 가 남았는지 확인하지 못했다(powershell 실패). esp_list_ports 가 동작하는지 확인하라.")
    if error is not None:
        failed_step = len(reads) + 1
        code = getattr(error, "code", "internal_error")
        message = getattr(error, "message", None) or f"{type(error).__name__}: {error}"
        r.audit({"event": "esp_read_flash_failed", "at_read": failed_step, "code": code, "message": str(message)[:500],
                 "kept_reads": len(reads), "orphans": orphans or None, **plan.requested()}, plan.case_id)
        try:
            if reads:
                notes.append(f"{failed_step}차 읽기 실패: {message} — 1차 읽기는 완료되어 보존했다(이중 읽기 검증 없음).")
                first = plan.steps[0]
                if failed_step == 2 and code in _CONNECT_FAILURE_CODES and first.after == "no-reset-stub" and first.baud > SYNC_BAUD:
                    notes.append(f"2차 연결 실패: 1차 읽기 뒤 칩이 스텁({first.baud} baud)에 남아 있었고 리셋(before='{plan.before}')이 듣지 "
                                 "않은 것 같다(자동 리셋 회로가 없는 보드). 수동 다운로드 모드면 사람이 BOOT+RESET 을 한 뒤 before='no-reset' 으로 "
                                 "다시 덤프하라(서버가 1차 읽기를 115200 baud 로 해 2차 연결을 맞춘다).")
                try:
                    jctx.set_partial(_finalize_dump(plan, reads, status="failed", notes=notes, warnings=warnings, started_at=started,
                                                    t0=t0, job_id=jctx.job.id))
                except Exception:  # pragma: no cover - 원래 오류를 우선한다
                    log.exception("부분 결과 정리 실패")
        finally:
            _release_reservation(plan, orphan_pids=orphans or None)
        raise error
    try:
        if cancelled_at is not None:
            msg = (f"읽기 {cancelled_at}/{n} 에서 취소됨. esptool 프로세스를 끝냈다"
                   + ("(Windows esptool.exe 는 PyInstaller 자식까지 끝나 남은 것이 없음을 확인)" if plan.backend.windows and not check_failed else "")
                   + ". esptool 은 모든 데이터를 받은 뒤에만 파일을 쓰므로 그 읽기의 부분 데이터는 없다(예약 파일 삭제). "
                   "칩이 다운로드 모드(스텁)에 남아 있을 수 있으니 일반 부팅이 필요하면 사람이 RESET 을 누른다.")
            r.audit({"event": "esp_read_flash_cancelled", "at_read": cancelled_at, "kept_reads": len(reads), **plan.requested()}, plan.case_id)
            if reads:
                notes.append(msg + " 1차 읽기는 완료되어 보존했다(이중 읽기 검증 없음).")
                return _finalize_dump(plan, reads, status="cancelled", notes=notes, warnings=warnings, started_at=started, t0=t0,
                                      job_id=jctx.job.id)
            return {"ok": False, "status": "cancelled", "message": msg, "kept": [], "removed_reservations": True}
        if n == 2:
            notes.append(f"1차 읽기는 --after no-reset-stub(칩을 다운로드 모드에 둬 앱이 실행되지 않게 — FLASH_BEGIN 을 보내는 no-reset 은 "
                         f"쓰지 않음), 2차 읽기 뒤 --after {plan.after}.")
        else:
            notes.append(f"한 번 읽기 (after={plan.after}).")
        return _finalize_dump(plan, reads, status="succeeded", notes=notes, warnings=warnings, started_at=started, t0=t0,
                              job_id=jctx.job.id)
    finally:
        _release_reservation(plan)


@server.tool(
    description=(
        "플래시 덤프 작업 시작 (esptool read-flash, job, MODIFY: 리셋으로 ROM 다운로드 모드 진입 + RAM 스텁, 플래시/eFuse 쓰기 없음, "
        "케이스 소유/허가 증명 필요). 방법 A: port='COM3' 이면 Windows esptool.exe 가 wslpath 로 바꾼 경로에 바로 쓴다. "
        "offset(정수/'0x..'), size('all'=감지 크기(offset=0 일 때만), 정수, '0x400000', '4M', '16MB', '512K'), output_name(생략 시 esp-flash, esp-flash-002 …), "
        "baud(기본 921600 — 오류가 나면 460800/115200), verify='double'(기본: 두 번 읽어 sha256 비교, 1차는 --after no-reset-stub 으로 칩을 "
        "다운로드 모드에 둬 앱이 실행되지 않게. before='no-reset'(수동 다운로드 모드)이면 1차는 115200 baud) | 'none'. after='no-reset' 은 "
        "no-reset-stub 으로 바꿔 실행한다. no_stub=True(ROM 직접 읽기, 전송 MD5 검증 없음)는 chip 을 ESP8266 이 아닌 칩으로 명시할 때만 "
        "받는다(auto·esp8266 은 validation_failed). "
        "결과: dumps/<name>.bin (+ dumps/<name>.read2.bin) + dumps/<name>.json(firmware-dump 스키마 모양 메타데이터, method 'esptool-read-flash'), "
        "flash-dump 아티팩트, 읽기별 로그 uart/esptool-<name>-readN-NNN.log. 최종 파일은 끝날 때 만들며 기존 파일은 덮어쓰지 않는다. 즉시 job_id 를 돌려주므로 "
        "esp_job_status(job_id, wait_seconds=30) 로 폴링(진행률 %)하고 esp_job_cancel 로 취소한다(취소된 읽기는 부분 데이터가 없어 삭제). "
        "불일치면 result.match=false + warnings (파일 보존). Secure Download Mode 면 esp_secure_download_mode 로 실패한다(우회 금지)."
    ),
    annotations=ANN_DEVICE,
)
@safe_tool
async def esp_read_flash_start(
    case_id: str,
    port: str,
    chip: str = "auto",
    offset: int | str = 0,
    size: int | str = "all",
    output_name: str | None = None,
    baud: int | None = READ_BAUD_DEFAULT,
    verify: str = "double",
    before: str = "default-reset",
    after: str = "hard-reset",
    no_stub: bool = False,
    timeout_s: float | None = None,
    approval_id: str | None = None,
    ctx: Context = None,  # type: ignore[assignment]
) -> dict[str, Any]:
    r = rt()
    case = r.case(case_id, hardware=True)
    spec, chip_v, baud_v, before_v, no_stub_v = _common_args(port, chip, baud, before, no_stub, READ_BAUD_DEFAULT)
    off = validate_offset(offset)
    size_v = validate_size(size)
    if size_v == "all" and off != 0:
        raise ValidationFailed("size='all' 은 offset=0 일 때만 쓸 수 있습니다.",
                               hint="esptool 은 감지한 플래시 크기를 넘는 읽기를 거부한다. offset 을 주려면 size 를 명시하라.")
    if isinstance(size_v, int) and off + size_v > 2**32:
        raise ValidationFailed("offset + size 가 32비트 주소 범위를 넘습니다.")
    name = validate_output_name(output_name)
    verify_v = validate_verify(verify)
    n_reads = 2 if verify_v == "double" else 1
    dumps_dir = case.subdir("dumps")
    try:
        dst = os.lstat(dumps_dir)
    except OSError:
        raise CaseError(f"케이스 dumps/ 를 확인할 수 없습니다: {dumps_dir}")
    if stat.S_ISLNK(dst.st_mode) or not stat.S_ISDIR(dst.st_mode):
        raise CaseError(f"케이스 dumps/ 가 실제 디렉터리가 아닙니다(심볼릭 링크): {dumps_dir}", hint="dumps/ 를 일반 디렉터리로 되돌려라.")
    case_real = os.path.realpath(case.dir)
    dumps_real = os.path.realpath(dumps_dir)
    if not _within_real(dumps_real, case_real):
        raise CaseError(f"케이스 dumps/ 의 실제 경로가 케이스 밖입니다: {dumps_real}")
    real_dumps = Path(dumps_real)
    await _offload(_sweep_dumps_dir, real_dumps, case.id)  # 죽은 프로세스가 남긴 예약 정리
    if name:
        _check_name_free(real_dumps, name, n_reads)
    backend: Backend = await _offload(_resolve_backend, spec)
    after_req = validate_after(after, backend.major, backend.minor)
    after_v = stub_safe_after(after_req)
    # 수동 다운로드 모드(before='no-reset')의 이중 읽기: 1차 뒤 칩(스텁 또는 ROM)이 바꾼 baud 로 남으면 2차 연결(115200 동기화)이
    # USB-UART 브리지에서 맞지 않으므로 1차는 115200 으로 읽는다(네이티브 USB 는 baud 와 무관해 손해 없음)
    read1_baud = min(baud_v, SYNC_BAUD) if (n_reads == 2 and before_v == "no-reset") else baud_v
    step_specs = []
    for i in range(1, n_reads + 1):
        s_after = "no-reset-stub" if (n_reads == 2 and i == 1) else after_v
        s_baud = read1_baud if i == 1 else baud_v
        s_timeout = (_clamp_timeout(timeout_s, 0.0, minimum=30.0, maximum=MAX_READ_TIMEOUT_S) if timeout_s is not None
                     else _read_timeout(size_v, s_baud, no_stub_v))
        step_specs.append((i, s_after, s_baud, s_timeout))
    action = {"command": "read-flash", "port": spec.port, "chip": chip_v, "offset": off, "size": size_v, "output_name": name,
              "baud": baud_v, "verify": verify_v, "before": before_v, "after": after_v, "no_stub": no_stub_v}
    if after_req != after_v:
        action["after_requested"] = after_req
    if n_reads == 2:
        action["read1_after"] = "no-reset-stub"
        if read1_baud != baud_v:
            action["read1_baud"] = read1_baud
    # 게이트 전 분류: 예약 전이라 계획 경로(리눅스)로 분류한다 (예약·Windows 경로 변환 후 다시 분류)
    planned = real_dumps / f".{name or DEFAULT_DUMP_NAME}.read1.partial"
    pre_argv = build_argv(backend.exe, major=backend.major, chip=chip_v, port=spec.port, baud=step_specs[0][2], before=before_v,
                          after=step_specs[0][1], no_stub=no_stub_v, command="read-flash",
                          args=[f"0x{off:x}", _size_token(size_v), str(planned)])
    cls = classify_esptool_argv(pre_argv, port=spec.port, allowed_output_dir=real_dumps, esptool_major=backend.major,
                                esptool_minor=backend.minor)
    if cls.risk >= Risk.DESTRUCTIVE:
        return _policy_denied("esp_read_flash_start", action, cls, case.id)
    await _offload(_check_port_free, spec, backend)
    exclusive_key = _port_key(spec)
    decision = await r.authorize(tool="esp_read_flash_start", action=action, classification=cls, case_id=case.id,
                                 approval_id=approval_id, ctx=ctx)
    if not decision.allowed:
        return gate_response(decision)

    stem, partials, owner = _reserve_dump(real_dumps, name, n_reads)
    plan_notes: list[str] = []
    mapped = _after_note(after_req, after_v)
    if mapped:
        plan_notes.append(mapped)
    if read1_baud != baud_v:
        plan_notes.append(f"수동 다운로드 모드(before='no-reset')의 이중 읽기라 1차 읽기는 {read1_baud} baud 로 했다: 1차 뒤 칩(스텁 또는 ROM)이 "
                          f"그 속도로 남아 있어야 2차 연결(esptool 은 115200 으로 동기화)이 맞는다. 2차 읽기는 {baud_v} baud.")
    handed_off = False
    plan: DumpPlan | None = None
    try:
        steps: list[ReadStep] = []
        for (i, s_after, s_baud, s_timeout), partial in zip(step_specs, partials):
            tok, omap = await _offload(_output_token, spec, partial)
            argv = build_argv(backend.exe, major=backend.major, chip=chip_v, port=spec.port, baud=s_baud, before=before_v,
                              after=s_after, no_stub=no_stub_v, command="read-flash",
                              args=[f"0x{off:x}", _size_token(size_v), tok])
            c2 = classify_esptool_argv(argv, port=spec.port, allowed_output_dir=real_dumps, output_map=omap,
                                       esptool_major=backend.major, esptool_minor=backend.minor)
            if c2.risk != Risk.MODIFY or c2.rule_id != "esp.read-flash":
                return _policy_denied("esp_read_flash_start", action, c2, case.id)
            steps.append(ReadStep(index=i, after=s_after, baud=s_baud, timeout_s=s_timeout, partial=partial, argv=argv,
                                  output_token=tok, output_map=omap,
                                  win_match=output_win_match(backend.exe, tok) if backend.windows else None))
        if backend.windows:
            # 첫 esptool.exe 를 띄우기 전에 출력 경로를 소유 표식에 적는다: 이 서버가 SIGKILL 로 죽어도 다음 서버의 정리가 남은
            # esptool.exe(명령줄에 이 경로)를 알아보고 예약을 지우지 않는다 (_reservation_state).
            _update_owner(owner, only_if_active=True, windows_tokens=[st.output_token for st in steps],
                          windows_images=[exe_image(backend.exe)])
        plan = DumpPlan(case_id=case.id, case_dir=case.dir, case_real=case_real, dumps_dir=dumps_dir, dumps_real=dumps_real, stem=stem,
                        owner_path=owner, port=spec, backend=backend, chip=chip_v, baud=baud_v, before=before_v, after=after_v,
                        after_requested=after_req, no_stub=no_stub_v, offset=off, size=size_v, verify=verify_v, steps=steps,
                        exclusive_key=exclusive_key, plan_notes=plan_notes)
        the_plan = plan

        def job_fn(jctx: Any) -> dict[str, Any]:
            return _read_flash_worker(the_plan, jctx)

        job = r.jobs.start("esp-read-flash", job_fn, description=f"esptool read-flash {spec.port} → dumps/{stem}.bin",
                           case_id=case.id, meta={"planned_path": f"dumps/{stem}.bin", "port": spec.port, "backend": backend.name,
                                                  "owner": _owner_record()},
                           exclusive_key=exclusive_key)
        handed_off = True
        _update_owner(owner, only_if_active=True, job_id=job.id)
    finally:
        if not handed_off:
            with _RESERVE_LOCK:
                for p in partials:
                    _unlink(p)
                _unlink(owner)
                _ACTIVE_RESERVATIONS.discard(str(owner))
    r.audit({"event": "esp_read_flash_started", "job_id": job.id, "output": f"dumps/{stem}.bin", "backend": backend.name, **plan.requested()},
            case.id)
    notes = list(plan_notes)
    if n_reads == 2:
        notes.insert(0, f"1차 읽기는 --after no-reset-stub(칩을 다운로드 모드에 둠), 2차 읽기 뒤 --after {after_v}.")
    if spec.backend == "windows":
        notes.append("Windows 백엔드: esptool.exe 가 wslpath 로 바꾼 경로(\\\\wsl.localhost\\…)에 직접 쓴다.")
    return {
        "ok": True,
        "status": "started",
        "job_id": job.id,
        "planned_path": f"dumps/{stem}.bin",
        "planned_read2_path": f"dumps/{stem}.read2.bin" if n_reads == 2 else None,
        "metadata_path": f"dumps/{stem}.json",
        "reads": n_reads,
        "backend": backend.name,
        "port": spec.port,
        "esptool_version": backend.version,
        "after": after_v,
        **({"after_requested": after_req} if after_req != after_v else {}),
        "read1_after": "no-reset-stub" if n_reads == 2 else None,
        "read1_baud": read1_baud if n_reads == 2 else None,
        "timeout_s_per_read": round(max(s[3] for s in step_specs), 1),
        "classification": cls.to_dict(),
        "notes": notes,
        "message": (f"백그라운드 덤프 시작. esp_job_status(job_id='{job.id}', wait_seconds=30) 로 폴링하라 "
                    f"(921600 baud 에서 4MB 는 보통 1~2분, 115200 이면 6분 이상)."),
    }


register_job_tools(server, rt, "esp")


# ---------------------------------------------------------------------------
# 서버 시작·종료
# ---------------------------------------------------------------------------


def _shutdown_cleanup() -> None:
    """실행 중인 작업을 취소하고(워커가 esptool 을 끝내고 예약을 정리) 남은 esptool 프로세스를 끝낸다."""
    try:
        rt().jobs.shutdown(timeout=SHUTDOWN_TIMEOUT_S)
    except Exception:  # pragma: no cover
        log.exception("작업 종료 실패")
    try:
        esptool_cli._kill_all_live()
    except Exception:  # pragma: no cover
        log.exception("esptool 프로세스 정리 실패")


def _install_sigterm_handler() -> None:
    """SIGTERM: 작업을 취소·정리한 뒤(별도 스레드, 최대 SHUTDOWN_TIMEOUT_S) 기본 동작으로 끝낸다. 두 번째 SIGTERM 은 바로 끝낸다."""

    def handler(signum: int, frame: Any) -> None:
        signal.signal(signal.SIGTERM, signal.SIG_DFL)
        log.warning("SIGTERM: 실행 중인 esp 작업을 취소·정리한 뒤 끝낸다")
        t = threading.Thread(target=_shutdown_cleanup, name="pweh-esp-shutdown", daemon=True)
        t.start()
        t.join(SHUTDOWN_TIMEOUT_S + 10.0)
        os.kill(os.getpid(), signal.SIGTERM)

    try:
        signal.signal(signal.SIGTERM, handler)
    except ValueError:  # pragma: no cover - 메인 스레드가 아님
        pass


def main() -> None:
    try:
        swept = _startup_sweep()
        if swept["removed"] or swept["abandoned"]:
            log.info("시작 정리: 낡은 덤프 예약 %d 개 삭제, abandoned 작업 %s", swept["removed"], swept["abandoned"])
    except Exception:  # noqa: BLE001
        log.warning("시작 정리 실패", exc_info=True)
    _install_sigterm_handler()
    try:
        server.run()
    finally:
        _shutdown_cleanup()


if __name__ == "__main__":
    main()
