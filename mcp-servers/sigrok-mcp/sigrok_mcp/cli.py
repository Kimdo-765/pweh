"""sigrok-cli 실행 래퍼와 출력 파서.

- 실행 파일: 설정 ``tools.sigrok_cli``(= ``${PWEH_SIGROK_CLI:-sigrok-cli}``) → 환경변수 ``PWEH_SIGROK_CLI`` → PATH.
- 모든 실행은 인자 리스트 + 타임아웃 + 새 세션(프로세스 그룹)으로 하고, 타임아웃/취소 시 그룹 전체를
  SIGTERM → SIGKILL 한다. stdin 은 항상 /dev/null (MCP stdio 채널을 절대 상속하지 않음).
- sigrok-cli 는 많은 사용자 오류에서 rc=1 이지만 rc=0 인데 실패인 경우도 있다(없는 채널 이름,
  SamplerateError 등) → ``stderr_problems`` 로 stderr 를 반드시 검사한다.
- 출력 형식은 sigrok-cli 0.7.2 / libsigrok 0.5.2 / libsigrokdecode 0.5.3 소스(show.c, decode.c,
  session.c)와 실측(docs/references/sigrok-cli.md)에 맞춘다. 기본 loglevel(2)을 고정한다.
"""

from __future__ import annotations

import atexit
import collections
import logging
import os
import re
import shutil
import signal
import subprocess
import threading
import time
from dataclasses import dataclass, field
from typing import Any, BinaryIO, Callable, Sequence

from pweh.errors import PwehError, TimeoutExpired, ToolMissing
from pweh import procutil

log = logging.getLogger("pweh.sigrok")

INSTALL_HINT = (
    "sigrok-cli 를 찾을 수 없다. (1) pweh-tools 를 쓰면 `. ~/pweh-tools/env.sh` 를 source 한 셸에서 MCP 서버를 다시 시작하거나 "
    "(2) 환경변수 PWEH_SIGROK_CLI=/절대/경로/sigrok-cli 또는 pipeline-config.yaml 의 tools.sigrok_cli 를 설정하거나 "
    "(3) `sudo apt install sigrok-cli` (Ubuntu 22.04+: sigrok-cli 0.7.2) 로 설치한다. "
    "참고: 보드레이트 추정(sigrok_estimate_baud)과 파일 정보(sigrok_file_info)는 sigrok-cli 없이도 동작한다."
)


# ---------------------------------------------------------------------------
# 실행 파일 탐색
# ---------------------------------------------------------------------------


def _is_exe(p: str) -> bool:
    return os.path.isfile(p) and os.access(p, os.X_OK)


def locate_sigrok_cli(configured: str | None) -> str:
    """설정값/환경변수/PATH 순으로 sigrok-cli 실행 파일 경로를 찾는다. 없으면 ToolMissing."""
    tried: list[str] = []
    candidates = []
    if configured:
        candidates.append(configured)
    env = os.environ.get("PWEH_SIGROK_CLI")
    if env and env not in candidates:
        candidates.append(env)
    if "sigrok-cli" not in candidates:
        candidates.append("sigrok-cli")
    for cand in candidates:
        cand = os.path.expanduser(cand.strip())
        if not cand:
            continue
        tried.append(cand)
        if os.sep in cand:
            if _is_exe(cand):
                return os.path.abspath(cand)
        else:
            found = shutil.which(cand)
            if found and _is_exe(found):
                return found
    raise ToolMissing(f"sigrok-cli 실행 파일이 없습니다 (시도: {', '.join(tried)})", hint=INSTALL_HINT)


def child_env() -> dict[str, str]:
    env = dict(os.environ)
    # libsigrokdecode 는 시스템 libpython 을 내장한다 → MCP 서버(venv)의 Python 환경 변수를 넘기지 않는다
    for k in ("PYTHONHOME", "PYTHONPATH", "PYTHONSTARTUP", "PYTHONSAFEPATH"):
        env.pop(k, None)
    env["LC_NUMERIC"] = "C"  # --show 의 %f 출력 소수점 고정
    return env


# ---------------------------------------------------------------------------
# 프로세스 실행
# ---------------------------------------------------------------------------


@dataclass
class CliResult:
    argv: list[str]
    returncode: int | None
    stdout: bytes
    stderr: str
    timed_out: bool = False
    cancelled: bool = False
    output_limit_hit: bool = False
    duration_s: float = 0.0
    stdout_bytes: int = 0
    stderr_bytes: int = 0
    pid: int | None = None
    cleanup_verified: bool = True
    start_ticks: int | None = None
    process_token: int | None = None  # 실행 객체별 내부 세대

    @property
    def stdout_text(self) -> str:
        return self.stdout.decode("utf-8", "replace")

    @property
    def ok(self) -> bool:
        return self.cleanup_verified and self.returncode == 0 and not (self.timed_out or self.cancelled or self.output_limit_hit)

    def summary(self, stderr_chars: int = 2000) -> dict[str, Any]:
        return {
            "returncode": self.returncode,
            "timed_out": self.timed_out,
            "cancelled": self.cancelled,
            "output_limit_hit": self.output_limit_hit,
            "cleanup_verified": self.cleanup_verified,
            "duration_s": round(self.duration_s, 3),
            "stdout_bytes": self.stdout_bytes,
            "stderr": tail_text(self.stderr, stderr_chars),
        }


def tail_text(text: str, n: int) -> str:
    if len(text) <= n:
        return text
    return "…(앞부분 생략)…\n" + text[-n:]


def kill_process_group(proc: subprocess.Popen, grace_s: float = 2.0) -> bool:
    """리더를 거두기 전에 신원 확인 종료, 그룹 부재 확인 뒤에만 reap한다."""
    with _CLEANUP_LOCK:
        return _finish_process_group(proc, grace_s)


def _finish_process_group(proc: subprocess.Popen, grace_s: float) -> bool:
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


# reap 뒤 같은 PID의 새 실행이 들어와도 옛 finally가 그 기록을 지우지 않는다.
_LIVE: dict[int, subprocess.Popen] = {}
_CHILD_IDS: dict[int, tuple[int | None, int | None]] = {}
_LIVE_LOCK = threading.Lock()
_CLEANUP_LOCK = threading.Lock()


def _kill_all_live() -> None:
    """서버 프로세스 종료 시 아직 실행 중인 sigrok-cli 프로세스 그룹을 정리 (새 세션이라 자동으로 죽지 않음)."""
    with _LIVE_LOCK:
        procs = list(_LIVE.values())
    for proc in procs:
        if kill_process_group(proc, grace_s=0.5):
            with _LIVE_LOCK:
                _LIVE.pop(id(proc), None)


atexit.register(_kill_all_live)


def live_process_count() -> int:
    with _LIVE_LOCK:
        return len(_LIVE)


def cleanup_owned(pid: int, *, process_token: int | None = None) -> bool:
    """자기 runner가 띄워 보존한 프로세스만 정리한다."""
    with _LIVE_LOCK:
        matches = [(token, proc) for token, proc in _LIVE.items()
                   if proc.pid == pid and (process_token is None or token == process_token)]
    if not matches:
        return True
    if len(matches) != 1:
        return False
    token, proc = matches[0]
    verified = kill_process_group(proc, grace_s=0.5)
    if verified:
        with _LIVE_LOCK:
            _LIVE.pop(token, None)
    return verified


def run_process(
    argv: Sequence[str],
    *,
    timeout: float,
    cancel: Callable[[], bool] | None = None,
    stdout_file: BinaryIO | None = None,
    stdout_limit: int = 8 * 1024 * 1024,
    stderr_limit: int = 128 * 1024,
    cwd: str | os.PathLike[str] | None = None,
    env: dict[str, str] | None = None,
    on_tick: Callable[[float], None] | None = None,
    poll_s: float = 0.1,
    process_state: dict[str, Any] | None = None,
) -> CliResult:
    """인자 리스트로 실행, 타임아웃/취소/출력 상한 시 프로세스 그룹 종료.

    stdout_file 을 주면 stdout 을 그 파일로 흘려 쓰고(상한 초과 시 종료), 아니면 메모리에 상한까지 보관한다.
    """
    argv = [str(a) for a in argv]
    t0 = time.monotonic()
    try:
        proc = subprocess.Popen(
            argv,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=str(cwd) if cwd else None,
            env=env,
            start_new_session=True,
            close_fds=True,
        )
    except FileNotFoundError as exc:
        raise ToolMissing(f"실행 파일을 실행할 수 없습니다: {argv[0]} ({exc})", hint=INSTALL_HINT)
    except PermissionError as exc:
        raise ToolMissing(f"실행 권한이 없습니다: {argv[0]} ({exc})", hint=INSTALL_HINT)
    with _LIVE_LOCK:
        _LIVE[id(proc)] = proc
        st = procutil.proc_stat(proc.pid)
        _CHILD_IDS[id(proc)] = (st[1] if st else None, procutil.open_pidfd(proc.pid))
    start_ticks = _CHILD_IDS[id(proc)][0]
    if process_state is not None:
        process_state.update(pid=proc.pid, start_ticks=start_ticks, process_token=id(proc), cleanup_verified=False)

    out_buf = bytearray()
    out_total = [0]
    limit_hit = threading.Event()
    err_head = bytearray()
    err_tail: collections.deque[bytes] = collections.deque()
    err_tail_len = [0]
    err_total = [0]

    def pump_stdout() -> None:
        assert proc.stdout is not None
        fd = proc.stdout.fileno()
        while True:
            try:
                chunk = os.read(fd, 65536)
            except OSError:
                break
            if not chunk:
                break
            before = out_total[0]
            out_total[0] += len(chunk)
            room = stdout_limit - before
            if room <= 0:
                limit_hit.set()
                continue  # 계속 읽어서 파이프가 막히지 않게 (곧 종료됨)
            part = chunk[:room]
            if stdout_file is not None:
                try:
                    stdout_file.write(part)
                except OSError:
                    limit_hit.set()
            else:
                out_buf.extend(part)
            if len(chunk) > room:
                limit_hit.set()

    def pump_stderr() -> None:
        assert proc.stderr is not None
        fd = proc.stderr.fileno()
        while True:
            try:
                chunk = os.read(fd, 65536)
            except OSError:
                break
            if not chunk:
                break
            err_total[0] += len(chunk)
            if len(err_head) < stderr_limit:
                take = chunk[: stderr_limit - len(err_head)]
                err_head.extend(take)
                chunk = chunk[len(take):]
            if chunk:
                err_tail.append(chunk)
                err_tail_len[0] += len(chunk)
                while err_tail_len[0] > 32 * 1024 and len(err_tail) > 1:
                    err_tail_len[0] -= len(err_tail.popleft())

    threads = [threading.Thread(target=pump_stdout, daemon=True), threading.Thread(target=pump_stderr, daemon=True)]
    timed_out = cancelled = False
    cleanup_verified = False
    try:
        for t in threads:
            t.start()
        while True:
            if procutil.child_exited(proc.pid):
                break
            time.sleep(poll_s)
            elapsed = time.monotonic() - t0
            if on_tick is not None:
                try:
                    on_tick(elapsed)
                except Exception:  # pragma: no cover - 진행률 콜백 오류는 무시
                    log.debug("on_tick failed", exc_info=True)
            if cancel is not None and cancel():
                cancelled = True
                break
            if elapsed > timeout:
                timed_out = True
                break
            if limit_hit.is_set():
                break
    except BaseException:
        raise
    finally:
        cleanup_verified = kill_process_group(proc)
        if process_state is not None:
            process_state["cleanup_verified"] = cleanup_verified
        for t in threads:
            if t.ident is not None:
                t.join(timeout=5.0)
        if cleanup_verified:
            with _LIVE_LOCK:
                _LIVE.pop(id(proc), None)
        for f in (proc.stdout, proc.stderr):
            try:
                if f is not None:
                    f.close()
            except OSError:
                pass
    stderr_bytes = bytes(err_head)
    if err_tail:
        dropped = err_total[0] - len(err_head) - err_tail_len[0]
        if dropped > 0:
            stderr_bytes += f"\n…({dropped} bytes 생략)…\n".encode()
        stderr_bytes += b"".join(err_tail)
    return CliResult(
        argv=argv,
        returncode=proc.returncode,
        stdout=bytes(out_buf),
        stderr=stderr_bytes.decode("utf-8", "replace"),
        timed_out=timed_out,
        cancelled=cancelled,
        output_limit_hit=limit_hit.is_set(),
        duration_s=time.monotonic() - t0,
        stdout_bytes=out_total[0],
        stderr_bytes=err_total[0],
        pid=proc.pid,
        cleanup_verified=cleanup_verified,
        start_ticks=start_ticks,
        process_token=id(proc),
    )


# ---------------------------------------------------------------------------
# stderr 판정
# ---------------------------------------------------------------------------

_FATAL_PATTERNS: list[tuple[re.Pattern[str], str, str | None]] = [
    (re.compile(r'cli: No channel with name "([^"]*)" found'), "no_channel",
     "디코더 채널 매핑에 지정한 이름이 입력 파일에 없다. sigrok 은 이때 조용히 기본 매핑(첫 채널)으로 디코드하므로 결과를 버렸다. sigrok_file_info 로 채널 이름을 확인하라."),
    (re.compile(r"Target channel \"[^\"]*\" not enabled"), "channel_disabled", None),
    (re.compile(r"SamplerateError|Cannot decode without samplerate"), "no_samplerate",
     "입력에 samplerate 가 없다. raw/csv 입력이면 input_format 에 samplerate=<정수Hz> 를 넣어라 (예: 'binary:numchannels=8:samplerate=1000000')."),
    (re.compile(r"Traceback \(most recent call last\)"), "decoder_exception", "디코더(Python) 예외가 발생했다. 디코더 옵션/채널/입력 samplerate 를 확인하라."),
    (re.compile(r"Unknown keyword: ([^\s.]+)"), "unknown_keyword", "입력/출력 모듈 옵션 이름이 틀렸다 (sigrok 은 경고만 하고 무시한다)."),
    (re.compile(r"No devices found\."), "no_device",
     "장치를 찾지 못했다. USB 연결, (WSL2 이면) usbipd attach, udev 권한, conn 값을 확인하라. sigrok_scan 으로 먼저 확인."),
    (re.compile(r"Driver (\S+) not found\."), "no_driver", "sigrok_list(kind='drivers') 로 드라이버 이름을 확인하라."),
    (re.compile(r"Failed to load protocol decoder|ModuleNotFoundError"), "no_decoder", "sigrok_list(kind='decoders') 로 디코더 ID 를 확인하라."),
    (re.compile(r"Unknown option or channel '([^']*)'"), "unknown_pd_option", "sigrok_decoder_help 로 옵션/채널 ID 를 확인하라 (0.5.3 uart 는 parity, data_bits, stop_bits)."),
    (re.compile(r"Annotation '([^']*)' not found"), "unknown_annotation", "sigrok_decoder_help 의 annotation_classes/rows 이름을 사용하라."),
    (re.compile(r"requires a (?:float )?number"), "bad_pd_value", None),
    (re.compile(r"Invalid (?:value|time|channel|trigger match|channel syntax|channel range)"), "invalid_argument", None),
    (re.compile(r"unknown channel '([^']*)'"), "invalid_argument", "채널 이름은 sigrok_scan 결과의 이름(예 fx2lafw 는 D0..D7)을 사용하라."),
    (re.compile(r"Trigger match '.' not supported by device|Device doesn't support any triggers"), "trigger_unsupported",
     "sigrok_device_info 의 triggers(지원 트리거 문자)를 확인하라."),
    (re.compile(r"Failed to set device option '([^']*)'"), "device_option_failed",
     "장치가 이 값을 지원하지 않는다 (예: 목록에 없는 samplerate). sigrok_device_info 로 지원 samplerate 를 확인하라."),
    (re.compile(r"(?i)LIBUSB_ERROR_ACCESS|Permission denied|Unable to open device|Failed to open potential device"), "usb_access",
     "USB 장치 권한 문제일 수 있다. 사람이 libsigrok udev 규칙(60-libsigrok.rules + 61-libsigrok-plugdev/uaccess.rules)을 설치하고 장치를 다시 꽂아야 한다."),
    (re.compile(r"Failed to open device\.|Failed to initialize|Failed to start session|Failed to configure"), "device_failed", None),
    (re.compile(r"sigrok-cli only supports one device for capturing"), "multiple_devices", "conn 으로 장치를 지정하라."),
    (re.compile(r"Not enough time at this samplerate"), "invalid_argument", "duration_ms 를 늘리거나 samplerate 를 높여라."),
    (re.compile(r"The device can store only (\d+) samples"), "too_many_samples", "samples/duration_ms 를 줄여라."),
    (re.compile(r"no input module found for this file"), "no_input_module", "input_format 을 지정하라 (예: 'vcd', 'binary:numchannels=8:samplerate=1000000')."),
    (re.compile(r"Not a regular file|Failed to load .*: No such file"), "input_missing", None),
    (re.compile(r"superfluous|Unknown option"), "invalid_argument", None),
]

_WARN_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"Device only sent (\d+) samples\."), "short_capture"),
    (re.compile(r"Skipping unknown token"), "vcd_unknown_token"),
    (re.compile(r"Inexact rounding of samplerate"), "inexact_samplerate"),
]


@dataclass
class StderrReport:
    errors: list[dict[str, Any]] = field(default_factory=list)
    warnings: list[dict[str, Any]] = field(default_factory=list)

    @property
    def fatal(self) -> bool:
        return bool(self.errors)

    def first_hint(self) -> str | None:
        for e in self.errors:
            if e.get("hint"):
                return e["hint"]
        return None

    def to_dict(self) -> dict[str, Any]:
        return {"errors": self.errors, "warnings": self.warnings}


def stderr_problems(stderr: str) -> StderrReport:
    rep = StderrReport()
    seen: set[tuple[str, str]] = set()
    for line in stderr.splitlines():
        line = line.strip()
        if not line:
            continue
        for rx, code, hint in _FATAL_PATTERNS:
            if rx.search(line):
                key = (code, line)
                if key not in seen:
                    seen.add(key)
                    item: dict[str, Any] = {"code": code, "line": line[:500]}
                    if hint:
                        item["hint"] = hint
                    rep.errors.append(item)
                break
        else:
            for rx, code in _WARN_PATTERNS:
                if rx.search(line):
                    key = (code, line)
                    if key not in seen and len(rep.warnings) < 50:
                        seen.add(key)
                        rep.warnings.append({"code": code, "line": line[:500]})
                    break
    return rep


def check_result(res: CliResult, what: str, *, allow_rc: Sequence[int] = (0,)) -> StderrReport:
    """실패면 PwehError(timeout 포함). 성공이면 stderr 보고서 반환."""
    if not res.cleanup_verified:
        raise PwehError(f"{what}: 하위 프로세스 종료를 확인하지 못했습니다.", code="process_cleanup_unverified", data=res.summary())
    if res.timed_out:
        raise TimeoutExpired(
            f"{what}: sigrok-cli 가 {res.duration_s:.1f}초 안에 끝나지 않아 종료했다.",
            hint="timeout_s 를 늘리거나(최대값 확인) 큰 작업은 background=true 로 실행하라.",
            data=res.summary(),
        )
    if res.cancelled:
        raise PwehError(f"{what}: 취소됨", code="cancelled", data=res.summary())
    rep = stderr_problems(res.stderr)
    if res.returncode not in allow_rc or rep.fatal:
        msg_lines = [e["line"] for e in rep.errors[:5]] or [ln for ln in res.stderr.strip().splitlines()[-5:]]
        raise PwehError(
            f"{what} 실패 (rc={res.returncode}): " + (" | ".join(msg_lines) if msg_lines else "stderr 없음"),
            code=f"sigrok_{rep.errors[0]['code']}" if rep.errors else "sigrok_failed",
            hint=rep.first_hint(),
            data={"stderr": tail_text(res.stderr, 3000), "argv": res.argv},
        )
    return rep


# ---------------------------------------------------------------------------
# 파서
# ---------------------------------------------------------------------------

_CLI_RE = re.compile(r"^sigrok-cli (\S+)\s*$", re.M)
_SR_RE = re.compile(r"^- libsigrok (\S+?)/(\S+) \(rt: (\S+?)/(\S+)\)\.\s*$", re.M)
_SRD_RE = re.compile(r"^- libsigrokdecode (\S+?)/(\S+) \(rt: (\S+?)/(\S+)\)\.\s*$", re.M)


def parse_version(text: str) -> dict[str, Any]:
    out: dict[str, Any] = {"sigrok_cli": None, "libsigrok": None, "libsigrokdecode": None, "libs": {}, "python": None}
    m = _CLI_RE.search(text)
    if m:
        out["sigrok_cli"] = m.group(1)
    for key, rx in (("libsigrok", _SR_RE), ("libsigrokdecode", _SRD_RE)):
        m = rx.search(text)
        if m:
            out[key] = {"version": m.group(1), "lib_version": m.group(2), "runtime_version": m.group(3), "runtime_lib_version": m.group(4)}
    section = None
    for line in text.splitlines():
        if line.startswith("- libsigrokdecode"):
            section = "libsigrokdecode"
        elif line.startswith("- libsigrok"):
            section = "libsigrok"
        elif section and line.startswith("  - "):
            item = line[4:].strip()
            if item.startswith("Host:"):
                out.setdefault("host", item[5:].strip().rstrip("."))
            elif item.startswith("SCPI backends:"):
                out["scpi_backends"] = [x.strip() for x in item[len("SCPI backends:"):].strip().rstrip(".").split(",") if x.strip()]
            else:
                name, _, ver = item.partition(" ")
                out["libs"].setdefault(section, {})[name] = ver.strip()
                if name == "Python":
                    out["python"] = ver.split("/")[0].strip()
    return out


_LIST_SECTIONS = {
    "Supported hardware drivers:": "drivers",
    "Supported input formats:": "input_formats",
    "Supported output formats:": "output_formats",
    "Supported transform modules:": "transforms",
    "Supported protocol decoders:": "decoders",
}
_LIST_ITEM_RE = re.compile(r"^  (\S+)\s+(.*?)\s*$")


def parse_supported(text: str) -> dict[str, list[dict[str, str]]]:
    out: dict[str, list[dict[str, str]]] = {v: [] for v in _LIST_SECTIONS.values()}
    cur: str | None = None
    for line in text.splitlines():
        if line.strip() in _LIST_SECTIONS and not line.startswith(" "):
            cur = _LIST_SECTIONS[line.strip()]
            continue
        if not line.strip():
            continue
        if cur is None:
            continue
        if line.startswith("  ") and not line.startswith("   "):
            m = _LIST_ITEM_RE.match(line)
            if m:
                out[cur].append({"id": m.group(1), "description": m.group(2)})
        # -l 3 이상의 디코더 설명 줄("  " + 20칸 공백)은 무시
    return out


_DEV_RE = re.compile(
    r"^(?P<driver>[^\s:]+)(?::conn=(?P<conn>\S+))? - (?P<desc>.*?)\s*"
    r"(?:with (?P<n>\d+) channels?: (?P<chans>.*))?$"
)


def parse_dev_line(line: str) -> dict[str, Any] | None:
    m = _DEV_RE.match(line.rstrip())
    if not m:
        return None
    desc = m.group("desc") or ""
    serial = None
    sm = re.search(r"\[S/N: ([^\]]*)\]", desc)
    if sm:
        serial = sm.group(1)
        desc = (desc[: sm.start()] + desc[sm.end():]).strip()
    chans = (m.group("chans") or "").split()
    return {
        "driver": m.group("driver"),
        "conn": m.group("conn"),
        "description": desc.strip(),
        "serial_number": serial,
        "channel_count": int(m.group("n")) if m.group("n") else len(chans),
        "channels": chans,
        "raw": line.rstrip(),
    }


def parse_scan(text: str) -> list[dict[str, Any]]:
    devices = []
    started = False
    for line in text.splitlines():
        if line.startswith("The following devices were found:"):
            started = True
            continue
        if not started or not line.strip():
            continue
        d = parse_dev_line(line)
        if d:
            devices.append(d)
    return devices


def _split_top_level(s: str) -> list[str]:
    """'a', 'b, c', 1.0 처럼 g_variant_print 로 찍힌 값 목록을 최상위 쉼표로 분리."""
    items, cur, quote, esc = [], [], False, False
    i = 0
    while i < len(s):
        ch = s[i]
        if quote:
            cur.append(ch)
            if esc:
                esc = False
            elif ch == "\\":
                esc = True
            elif ch == "'":
                quote = False
        elif ch == "'":
            quote = True
            cur.append(ch)
        elif ch == "," and s[i + 1: i + 2] == " ":
            items.append("".join(cur).strip())
            cur = []
            i += 1
        else:
            cur.append(ch)
        i += 1
    if cur:
        items.append("".join(cur).strip())
    return items


def _gvariant_value(tok: str) -> Any:
    tok = tok.strip()
    if len(tok) >= 2 and tok[0] == "'" and tok[-1] == "'":
        return tok[1:-1].replace("\\'", "'").replace("\\\\", "\\")
    for conv in (int, float):
        try:
            return conv(tok)
        except ValueError:
            pass
    return tok


def _parse_pd_option(line: str) -> dict[str, Any] | None:
    # "- baudrate: Baud rate (default 115200)" / "- parity: Parity ('none', ..., default 'none')"
    m = re.match(r"^- ([A-Za-z0-9_]+): (.*)\)$", line)
    if not m:
        return None
    key, rest = m.group(1), m.group(2)
    # 마지막 최상위 '(' 찾기 (설명 안의 괄호, 따옴표 고려)
    depth, quote, start = 0, False, -1
    for i in range(len(rest) - 1, -1, -1):
        ch = rest[i]
        if ch == "'":
            quote = not quote
        elif not quote:
            if ch == ")":
                depth += 1
            elif ch == "(":
                if depth == 0:
                    start = i
                    break
                depth -= 1
    if start < 0:
        return None
    desc = rest[:start].rstrip()
    inner = rest[start + 1:]
    items = _split_top_level(inner)
    default = None
    values = []
    for it in items:
        if it.startswith("default "):
            default = _gvariant_value(it[len("default "):])
        else:
            values.append(_gvariant_value(it))
    return {"id": key, "description": desc, "values": values, "default": default}


_PD_HEADERS = {
    "Possible decoder input IDs:": "inputs",
    "Possible decoder output IDs:": "outputs",
    "Decoder tags:": "tags",
    "Annotation classes:": "annotation_classes",
    "Annotation rows:": "annotation_rows",
    "Binary classes:": "binary_classes",
    "Required channels:": "required_channels",
    "Optional channels:": "optional_channels",
    "Options:": "options",
}


def parse_decoder_show(text: str) -> list[dict[str, Any]]:
    """``sigrok-cli -P <pd> --show`` 출력 파싱 (여러 디코더면 여러 개)."""
    decoders: list[dict[str, Any]] = []
    cur: dict[str, Any] | None = None
    section: str | None = None
    doc_lines: list[str] = []
    for raw in text.splitlines():
        line = raw.rstrip("\n")
        if line.startswith("ID: "):
            if cur is not None:
                if doc_lines:
                    cur["documentation"] = "\n".join(doc_lines).strip()
                decoders.append(cur)
            cur = {k: [] for k in _PD_HEADERS.values()}
            cur["id"] = line[4:].strip()
            section, doc_lines = None, []
            continue
        if cur is None:
            continue
        if section == "documentation":
            doc_lines.append(line)
            continue
        for prefix, key in (("Name: ", "name"), ("Long name: ", "longname"), ("Description: ", "description"), ("License: ", "license")):
            if line.startswith(prefix) and section is None:
                cur[key] = line[len(prefix):].strip()
                break
        else:
            if line in _PD_HEADERS:
                section = _PD_HEADERS[line]
                continue
            if line == "Documentation:":
                section = "documentation"
                continue
            if line == "None." or not section:
                continue
            if section in ("inputs", "outputs", "tags"):
                if line.startswith("- "):
                    cur[section].append(line[2:].strip())
            elif section in ("annotation_classes", "binary_classes"):
                m = re.match(r"^- (\S+): (.*)$", line)
                if m:
                    cur[section].append({"id": m.group(1), "description": m.group(2)})
            elif section == "annotation_rows":
                m = re.match(r"^- (\S+) \((.*)\): (.*)$", line)
                if m:
                    cur[section].append({"id": m.group(1), "description": m.group(2), "classes": [c.strip() for c in m.group(3).split(",") if c.strip()]})
            elif section in ("required_channels", "optional_channels"):
                m = re.match(r"^- (\S+) \((.*)\): (.*)$", line)
                if m:
                    cur[section].append({"id": m.group(1), "name": m.group(2), "description": m.group(3)})
            elif section == "options":
                opt = _parse_pd_option(line)
                if opt:
                    cur[section].append(opt)
    if cur is not None:
        if doc_lines:
            cur["documentation"] = "\n".join(doc_lines).strip()
        decoders.append(cur)
    return decoders


def parse_device_show(text: str) -> dict[str, Any]:
    """``sigrok-cli -d <drv> --show`` 출력 파싱."""
    out: dict[str, Any] = {
        "driver_functions": [], "scan_options": [], "device": None, "channel_groups": [],
        "options": [], "samplerates": None, "samplerate_range": None, "triggers": None,
        "max_samples": None, "current": {},
    }
    section = None
    for raw in text.splitlines():
        line = raw.rstrip()
        if not line:
            continue
        if line == "Driver functions:":
            section = "driver_functions"
            continue
        if line == "Scan options:":
            section = "scan_options"
            continue
        if line == "Channel groups:":
            section = "channel_groups"
            continue
        if line.startswith("Supported configuration options"):
            section = "options"
            continue
        if not line.startswith(" "):
            d = parse_dev_line(line)
            if d:
                out["device"] = d
                section = None
            continue
        s = line.strip()
        if section in ("driver_functions", "scan_options"):
            out[section].append(s)
        elif section == "channel_groups":
            m = re.match(r"^(.*?): channels? (.*)$", s)
            if m:
                out["channel_groups"].append({"name": m.group(1), "channels": m.group(2).split()})
        elif section == "options" or section == "samplerates":
            if line.startswith("      ") and section == "samplerates":
                val = s.replace(" (current)", "")
                out["samplerates"].append(val)
                if s.endswith("(current)"):
                    out["current"]["samplerate"] = val
                continue
            section = "options"
            if s.startswith("Supported triggers:"):
                out["triggers"] = s[len("Supported triggers:"):].split()
            elif s.startswith("Maximum number of samples:"):
                try:
                    out["max_samples"] = int(s.split(":", 1)[1].strip())
                except ValueError:
                    pass
            elif s.startswith("samplerate"):
                rm = re.match(r"^samplerate \((.*) - (.*) in steps of (.*)\)$", s)
                if rm:
                    out["samplerate_range"] = {"min": rm.group(1), "max": rm.group(2), "step": rm.group(3)}
                elif "supported samplerates" in s:
                    out["samplerates"] = []
                    section = "samplerates"
            else:
                key, _, rest = s.partition(":")
                key = key.strip()
                out["options"].append({"key": key, "values": rest.strip()})
                cm = re.search(r"(\S+) \(current\)", rest)
                if cm:
                    out["current"][key] = cm.group(1).rstrip(",")
    return out


def parse_input_props(text: str) -> dict[str, Any]:
    """``sigrok-cli -i <file> --show`` (입력 파일 요약) 파싱."""
    out: dict[str, Any] = {"samplerate": None, "channels": [], "unitsize": None, "logic_samples": None, "analog_samples": None,
                           "frames": None, "triggers": None}
    for line in text.splitlines():
        line = line.rstrip()
        m = re.match(r"^Samplerate: (\d+)$", line)
        if m:
            out["samplerate"] = int(m.group(1))
            continue
        m = re.match(r"^- (.*): (logic|analog)$", line)
        if m:
            out["channels"].append({"name": m.group(1), "type": m.group(2)})
            continue
        for prefix, key in (("Logic unitsize: ", "unitsize"), ("Logic sample count: ", "logic_samples"),
                            ("Analog sample count: ", "analog_samples"), ("Frame count: ", "frames"), ("Trigger count: ", "triggers")):
            if line.startswith(prefix):
                try:
                    out[key] = int(line[len(prefix):].strip())
                except ValueError:
                    pass
    return out


ANN_RE_SNUM = re.compile(r"^(?P<ss>\d+)-(?P<es>\d+) (?P<inst>[^: ]+): (?P<text>.*)$")
ANN_RE = re.compile(r"^(?P<inst>[^: ]+): (?P<text>.*)$")


def parse_annotation_line(line: str) -> dict[str, Any] | None:
    """주석 한 줄 → {ss, es, inst, text}. 텍스트는 strip 하지 않는다(공백 바이트 보존)."""
    line = line.rstrip("\r\n")
    m = ANN_RE_SNUM.match(line)
    if m:
        return {"ss": int(m.group("ss")), "es": int(m.group("es")), "inst": m.group("inst"), "text": m.group("text")}
    m = ANN_RE.match(line)
    if m:
        return {"ss": None, "es": None, "inst": m.group("inst"), "text": m.group("text")}
    return None


# ---------------------------------------------------------------------------
# 래퍼 객체 + 캐시
# ---------------------------------------------------------------------------

_CACHE: dict[tuple[Any, ...], Any] = {}
_CACHE_LOCK = threading.Lock()


class SigrokCli:
    """sigrok-cli 실행 파일 하나에 대한 래퍼. 캐시는 (경로, mtime, 크기) 로 구분한다."""

    def __init__(self, path: str) -> None:
        self.path = path
        try:
            st = os.stat(path)
            self._key: tuple[Any, ...] = (os.path.realpath(path), st.st_mtime_ns, st.st_size)
        except OSError:
            self._key = (path, 0, 0)

    @classmethod
    def from_config(cls, configured: str | None) -> "SigrokCli":
        return cls(locate_sigrok_cli(configured))

    def run(self, args: Sequence[str], *, timeout: float, **kw: Any) -> CliResult:
        argv = [self.path, *[str(a) for a in args]]
        log.info("sigrok-cli %s", " ".join(argv[1:])[:500])
        return run_process(argv, timeout=timeout, env=child_env(), **kw)

    def _cached(self, kind: str, extra: Any, fn: Callable[[], Any]) -> Any:
        key = (kind, extra, *self._key)
        with _CACHE_LOCK:
            if key in _CACHE:
                return _CACHE[key]
        val = fn()
        with _CACHE_LOCK:
            _CACHE[key] = val
        return val

    def version(self) -> dict[str, Any]:
        def fn() -> dict[str, Any]:
            res = self.run(["--version"], timeout=30)
            check_result(res, "sigrok-cli --version")
            info = parse_version(res.stdout_text)
            if not info.get("sigrok_cli"):
                raise PwehError("sigrok-cli --version 출력을 해석할 수 없습니다.", code="sigrok_bad_output", data={"stdout": res.stdout_text[:2000]})
            info["raw"] = res.stdout_text
            return info

        return self._cached("version", None, fn)

    def supported(self) -> dict[str, list[dict[str, str]]]:
        def fn() -> dict[str, list[dict[str, str]]]:
            res = self.run(["--list-supported"], timeout=60)
            check_result(res, "sigrok-cli -L")
            parsed = parse_supported(res.stdout_text)
            if not any(parsed.values()):
                raise PwehError("sigrok-cli -L 출력을 해석할 수 없습니다.", code="sigrok_bad_output", data={"stdout": res.stdout_text[:2000]})
            return parsed

        return self._cached("supported", None, fn)

    def decoder_info(self, decoder: str) -> dict[str, Any]:
        def fn() -> dict[str, Any]:
            res = self.run([f"--protocol-decoders={decoder}", "--show"], timeout=60)
            check_result(res, f"디코더 정보({decoder})")
            infos = parse_decoder_show(res.stdout_text)
            if not infos:
                raise PwehError(f"디코더 정보를 해석할 수 없습니다: {decoder}", code="sigrok_bad_output", data={"stdout": res.stdout_text[:2000]})
            return infos[0]

        return self._cached("decoder", decoder, fn)

    def input_props(self, path: str, input_format: str | None, timeout: float = 120.0) -> dict[str, Any]:
        args = [f"--input-file={path}"]
        if input_format:
            args.append(f"--input-format={input_format}")
        args.append("--show")
        res = self.run(args, timeout=timeout)
        check_result(res, "입력 파일 요약(-i --show)")
        return parse_input_props(res.stdout_text)


def clear_cache() -> None:
    with _CACHE_LOCK:
        _CACHE.clear()


__all__ = [
    "CliResult",
    "SigrokCli",
    "StderrReport",
    "check_result",
    "child_env",
    "clear_cache",
    "kill_process_group",
    "locate_sigrok_cli",
    "parse_annotation_line",
    "parse_decoder_show",
    "parse_dev_line",
    "parse_device_show",
    "parse_input_props",
    "parse_scan",
    "parse_supported",
    "parse_version",
    "run_process",
    "stderr_problems",
    "tail_text",
]
