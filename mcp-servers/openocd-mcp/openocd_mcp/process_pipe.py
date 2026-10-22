"""Linux 직접 자식용 내부 OpenOCD pipe 수명 primitive.

운영 server/session에는 연결하지 않는다. stdout은 RPC client, stderr는 한 drainer가
소유하며, WNOWAIT로 리더를 보존한 채 소유 그룹을 확인한 뒤 마지막으로 거둔다.
close의 deadline은 협력적 예산이며 커널 파일 I/O의 강제 중단을 뜻하지 않는다.
"""
from __future__ import annotations

import math
import os
import re
import select
import signal
import stat
import subprocess
import sys
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from pweh import procutil
from pweh.errors import DeviceError, TimeoutExpired, ValidationFailed

from .parsers import parse_version
from .rpc import RequestCancelled
from .rpc_pipe import TclPipeClient

_SLICE = 0.05
_STDERR_BYTES = 16 << 20
_LINE_BYTES = 16 << 10
_TAIL_BYTES = 512 << 10
_ERROR_LINES = 50
_ERROR_CHARS = 512
_MARKER = b"accepting 'tcl' connection from pipe"
_DEBUG_INFO = re.compile(rb"Info : [0-9]{1,10} [0-9]{1,10} [^\s:]{1,128}:[0-9]{1,10} [A-Za-z_][A-Za-z_0-9]{0,63}\(\): ")
_OWNED: dict[int, PipeOpenOcdProcess] = {}
_OWNED_LOCK = threading.Lock()


@dataclass(frozen=True)
class PipeCleanupResult:
    confirmed: bool
    method: str
    exit_code: int | None
    reason: str


@dataclass(frozen=True)
class PipeReadyResult:
    ready: bool
    transport: str
    reason: str
    elapsed: float
    version: dict | None
    errors: list[str]


class PipeSpawnError(DeviceError):
    """구성 실패 시에도 미확인 owner를 Python 참조로 보존한다(직렬화하지 않음)."""
    code = "pipe_spawn_failed"

    def __init__(self, owner: PipeOpenOcdProcess) -> None:
        super().__init__("pipe 자식 구성을 완료하지 못했습니다.")
        self.owner = owner


def _duration(value: float, *, allow_zero: bool = False) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValidationFailed("시간 예산은 유한한 양수여야 합니다.")
    try:
        parsed = float(value)
    except (OverflowError, ValueError):
        raise ValidationFailed("시간 예산은 유한한 양수여야 합니다.") from None
    if not math.isfinite(parsed) or parsed < 0 or (not allow_zero and parsed == 0):
        raise ValidationFailed("시간 예산은 유한한 양수여야 합니다.")
    return parsed


def _acquire(lock: threading.Lock, deadline: float) -> bool:
    while (remaining := deadline - time.monotonic()) > 0:
        if lock.acquire(timeout=min(_SLICE, remaining)):
            return True
    return False


def _close_stream(stream) -> bool:
    if stream is None:
        return True
    try:
        if not stream.closed:
            stream.close()
        return stream.closed is True
    except (OSError, ValueError):
        return False


def _open_log(path: Path):
    """준비된 내부 경로의 일반 로그만 연다. 과거 로그는 읽지 않는다."""
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        existing = path.lstat()
    except FileNotFoundError:
        existing = None
    if existing is not None and not stat.S_ISREG(existing.st_mode):
        raise ValidationFailed("pipe 로그는 일반 파일이어야 합니다.")
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise ValidationFailed("pipe 로그는 일반 파일이어야 합니다.")
        return os.fdopen(fd, "ab", buffering=0)
    except BaseException:
        os.close(fd)
        raise


def owned_process_count() -> int:
    """새 pipe registry의 보존 owner 수(기존 TCP registry와 독립)."""
    with _OWNED_LOCK:
        return len(_OWNED)


class PipeOpenOcdProcess:
    """직접 만든 한 실행 세대와 부분 정리 상태를 소유한다. poll/wait는 공개하지 않는다."""

    def __init__(self) -> None:
        self._proc: subprocess.Popen | None = None
        self._ticks: int | None = None
        self._pidfd: int | None = None
        self._client: TclPipeClient | None = None
        self._log = None
        self._thread: threading.Thread | None = None
        self._thread_started = False
        self._thread_done = threading.Event()
        self._drain_stop = threading.Event()
        self._closing = threading.Event()
        self._marker = threading.Event()
        self._diag_lock = threading.Lock()
        self._cleanup_lock = threading.Lock()
        self._ready_lock = threading.Lock()
        self._fatal: str | None = None
        self._tail = bytearray()
        self._errors: list[str] = []
        self._bytes_seen = 0
        self._logged_bytes = 0
        self._rpc_closed = False
        self._group_verified = False
        self._leader_reaped = False
        self._stderr_joined = False
        self._stderr_closed = False
        self._log_closed = False
        self._exit_code: int | None = None
        self._method = "stdin-eof"
        self._confirmed: PipeCleanupResult | None = None
        self._ready_result: PipeReadyResult | None = None

    @property
    def client(self) -> TclPipeClient:
        if self._client is None:
            raise DeviceError("pipe client가 구성되지 않았습니다.", code="pipe_not_configured")
        return self._client

    @property
    def fatal_reason(self) -> str | None:
        with self._diag_lock:
            return self._fatal

    def diagnostics(self) -> dict:
        """진단의 제한된 복사본. 실제 Popen이나 mutable 내부 buffer는 노출하지 않는다."""
        with self._diag_lock:
            return {"stderr_tail": bytes(self._tail).decode("utf-8", "replace"),
                    "errors": list(self._errors), "bytes_seen": self._bytes_seen,
                    "logged_bytes": self._logged_bytes, "fatal_reason": self._fatal}

    def _set_fatal(self, reason: str) -> None:
        if self._closing.is_set():
            return
        with self._diag_lock:
            if self._fatal is None:
                self._fatal = reason
        if self._client is not None:
            self._client.abort(reason)

    def _diagnostic_line(self, line: bytes) -> None:
        if line.endswith(b"\r"):
            line = line[:-1]
        message = line
        prefix = _DEBUG_INFO.match(line)
        if prefix:
            message = line[prefix.end():]
        elif line.startswith(b"Info : "):
            message = line[7:]
        if message == _MARKER:
            self._marker.set()
        if line.startswith((b"Error:", b"Error :")):
            with self._diag_lock:
                if len(self._errors) < _ERROR_LINES:
                    self._errors.append(line.decode("utf-8", "replace")[:_ERROR_CHARS])

    def _drain_stderr(self) -> None:
        pending = bytearray()
        try:
            fd = self._proc.stderr.fileno()
            while not self._drain_stop.is_set():
                readable, _, _ = select.select([fd], [], [], _SLICE)
                if not readable:
                    continue
                try:
                    chunk = os.read(fd, 32 << 10)
                except BlockingIOError:
                    continue
                if not chunk:
                    self._set_fatal("stderr_eof")
                    return
                with self._diag_lock:
                    allowance = max(0, _STDERR_BYTES - self._bytes_seen)
                    self._bytes_seen += len(chunk)
                    kept = chunk[:allowance]
                    self._tail.extend(kept)
                    if len(self._tail) > _TAIL_BYTES:
                        del self._tail[:-_TAIL_BYTES]
                if kept:
                    try:
                        view = memoryview(kept)
                        while view:
                            if self._drain_stop.is_set():
                                return
                            n = self._log.write(view)
                            if not isinstance(n, int) or n <= 0:
                                raise OSError("로그 쓰기 실패")
                            with self._diag_lock:
                                self._logged_bytes += n
                            view = view[n:]
                    except (OSError, ValueError):
                        self._set_fatal("stderr_log_error")
                        return
                if len(kept) != len(chunk):
                    self._set_fatal("stderr_limit")
                    return
                for part in chunk.splitlines(keepends=True):
                    # splitlines의 CR 단독도 marker로 인정하지 않는다. LF만 완결이다.
                    pending.extend(part)
                    complete = part.endswith(b"\n")
                    if len(pending) - int(complete) > _LINE_BYTES:
                        self._set_fatal("stderr_limit")
                        return
                    if complete:
                        self._diagnostic_line(bytes(pending[:-1]))
                        pending.clear()
        except Exception:
            self._set_fatal("stderr_read_error")
        finally:
            self._thread_done.set()

    def _child_state(self) -> str:
        if self._proc is None:
            return "unknown"
        try:
            result = os.waitid(os.P_PID, self._proc.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)
        except (OSError, ChildProcessError, OverflowError, ValueError):
            return "unknown"
        if result is None:
            return "running"
        return "exited_waitable" if result.si_pid == self._proc.pid else "unknown"

    def _identity_matches(self) -> bool:
        if self._proc is None or self._ticks is None:
            return False
        current = procutil.proc_stat(self._proc.pid)
        try:
            return (current is not None and current[1] == self._ticks
                    and os.getpgid(self._proc.pid) == self._proc.pid)
        except (OSError, OverflowError):
            return False

    def _observe_group(self, deadline: float) -> bool | None:
        if self._group_verified:
            return True
        state = self._child_state()
        if state == "unknown" or not self._identity_matches():
            return None
        if state == "running":
            return False
        empty = procutil.process_group_empty(self._proc.pid, expect_start_ticks=self._ticks, deadline=deadline)
        if not self._identity_matches() or self._child_state() != "exited_waitable":
            return None
        if empty is True:
            self._group_verified = True
        return empty

    def _wait_group(self, until: float, deadline: float) -> bool | None:
        while time.monotonic() < deadline:
            done = self._observe_group(deadline)
            if done is not False:
                return done
            remaining = min(until, deadline) - time.monotonic()
            if remaining <= 0:
                return False
            time.sleep(min(_SLICE, remaining))
        return False

    def _close_rpc(self, timeout: float) -> None:
        if self._rpc_closed or timeout <= 0:
            return
        try:
            if self._client is not None:
                self._rpc_closed = self._client.close(timeout=timeout) is True
            elif self._proc is not None:
                # client 생성자가 실패했으면 아직 owner가 두 스트림을 소유한다.
                a = _close_stream(self._proc.stdin)
                b = _close_stream(self._proc.stdout)
                self._rpc_closed = a and b
            else:
                self._rpc_closed = True
        except Exception:
            self._rpc_closed = False

    def close(self, *, grace: float = 2.0, timeout: float = 6.0) -> PipeCleanupResult:
        """한 deadline에서 EOF→TERM→KILL과 그룹·FD·thread·reap을 각각 확인한다."""
        timeout = _duration(timeout)
        grace = _duration(grace, allow_zero=True)
        deadline = time.monotonic() + timeout
        self._closing.set()
        if self._client is not None:
            self._client.abort("owner_close")
        if not _acquire(self._cleanup_lock, deadline):
            return PipeCleanupResult(False, "unverified", self._exit_code, "cleanup_busy")
        try:
            if self._confirmed is not None:
                return self._confirmed
            return self._close_locked(grace, deadline)
        finally:
            self._cleanup_lock.release()

    def _unverified(self, reason: str) -> PipeCleanupResult:
        return PipeCleanupResult(False, "unverified", self._exit_code, reason)

    def _close_locked(self, grace: float, deadline: float) -> PipeCleanupResult:
        self._close_rpc(min(0.2, max(0, deadline - time.monotonic()) / 4))
        if self._proc is not None and not self._group_verified:
            if self._ticks is None:
                # 아직 waitable한 직접 자식만 초기 identity 실패 뒤 다시 확인할 수 있다.
                if self._child_state() == "unknown":
                    return self._unverified("child_unknown")
                current = procutil.proc_stat(self._proc.pid)
                if current is not None:
                    self._ticks = current[1]
            if not self._identity_matches():
                return self._unverified("identity_unknown")
            done = self._wait_group(min(deadline, time.monotonic() + grace), deadline)
            if done is None:
                return self._unverified("group_unknown")
            for sig, method in ((signal.SIGTERM, "terminated"), (signal.SIGKILL, "killed")):
                if done is True:
                    break
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return self._unverified("cleanup_timeout")
                if self._child_state() == "unknown" or not self._identity_matches():
                    return self._unverified("identity_unknown")
                sent = procutil.signal_owned_group(self._proc.pid, sig, expect_start_ticks=self._ticks, pidfd=self._pidfd)
                if sent is not True:
                    return self._unverified("signal_unverified")
                self._method = method
                until = min(deadline, time.monotonic() + min(0.5, remaining / 2)) if sig == signal.SIGTERM else deadline
                done = self._wait_group(until, deadline)
                if done is None:
                    return self._unverified("group_unknown")
            if done is not True:
                return self._unverified("cleanup_timeout")
        elif self._proc is None:
            self._group_verified = self._leader_reaped = True
        self._drain_stop.set()
        if self._thread is None:
            self._stderr_joined = True
        elif self._thread is threading.current_thread():
            return self._unverified("drainer_running")
        else:
            try:
                if self._thread_started or self._thread.ident is not None:
                    remaining = max(0, deadline - time.monotonic())
                    self._thread.join(timeout=remaining)
                    self._stderr_joined = not self._thread.is_alive() and self._thread_done.is_set()
                else:
                    # 정상 Thread.start 실패는 ident/started가 모두 없다.
                    self._stderr_joined = not self._thread.is_alive()
            except RuntimeError:
                self._stderr_joined = False
        if not self._stderr_joined:
            return self._unverified("drainer_running")
        self._close_rpc(max(0, deadline - time.monotonic()))
        if not self._rpc_closed:
            return self._unverified("rpc_close_unverified")
        if time.monotonic() >= deadline:
            return self._unverified("cleanup_timeout")
        if not self._stderr_closed:
            self._stderr_closed = _close_stream(self._proc.stderr if self._proc else None)
        if not self._log_closed:
            self._log_closed = _close_stream(self._log)
        if not self._stderr_closed or not self._log_closed:
            return self._unverified("stream_close_unverified")
        if not self._leader_reaped:
            if time.monotonic() >= deadline:
                return self._unverified("cleanup_timeout")
            if self._child_state() != "exited_waitable" or not self._identity_matches():
                return self._unverified("child_unknown")
            try:
                pid, status = os.waitpid(self._proc.pid, os.WNOHANG)
            except (OSError, ChildProcessError):
                return self._unverified("reap_unverified")
            if pid != self._proc.pid:
                return self._unverified("reap_unverified")
            self._exit_code = os.waitstatus_to_exitcode(status)
            self._proc.returncode = self._exit_code
            self._leader_reaped = True
        if self._pidfd is not None:
            try:
                os.close(self._pidfd)
            except OSError:
                return self._unverified("pidfd_close_unverified")
            self._pidfd = None
        self._confirmed = PipeCleanupResult(True, self._method, self._exit_code, "confirmed")
        if self._proc is not None:
            with _OWNED_LOCK:
                if _OWNED.get(id(self._proc)) is self:
                    del _OWNED[id(self._proc)]
        return self._confirmed

    def wait_ready(self, *, timeout: float, cancel_check: Callable[[], bool] | None = None) -> PipeReadyResult:
        """version 한 번과 이번 stderr의 정확한 marker를 같은 deadline 안에서 확인한다."""
        timeout = _duration(timeout)
        if cancel_check is not None and not callable(cancel_check):
            raise ValidationFailed("cancel_check는 callable이어야 합니다.")
        started = time.monotonic()
        deadline = started + timeout
        version = None

        def result(ok: bool, reason: str) -> PipeReadyResult:
            return PipeReadyResult(ok, "pipe", reason, time.monotonic() - started, version,
                                   self.diagnostics()["errors"])

        def stopped() -> str | None:
            if cancel_check is not None and cancel_check():
                return "cancelled"
            if self._closing.is_set():
                return "closed"
            fatal = self.fatal_reason
            if fatal is not None:
                return fatal
            if self._client is not None and not self._client.connected:
                return "rpc_closed"
            state = self._child_state()
            if state != "running":
                return "child_exited" if state == "exited_waitable" else "child_unknown"
            if time.monotonic() >= deadline:
                return "timeout"
            return None

        while not self._ready_lock.acquire(blocking=False):
            reason = stopped()
            if reason:
                return result(False, reason)
            time.sleep(min(_SLICE, max(0, deadline - time.monotonic())))
        try:
            reason = stopped()
            if reason:
                return result(False, reason)
            if self._ready_result is not None:
                return self._ready_result
            try:
                reply = self.client.call("version", timeout=max(0, deadline - time.monotonic()), cancel_check=cancel_check)
                if reply.closed or reply.code != 0:
                    outcome = result(False, "version_reply_invalid")
                elif len(reply.output.encode("utf-8")) > 4096 or len(reply.log.encode("utf-8")) > 4096:
                    outcome = result(False, "version_limit")
                else:
                    version = parse_version(reply.output)
                    if not version.get("parsed"):
                        outcome = result(False, "version_unrecognized")
                    else:
                        while not self._marker.is_set() and not (reason := stopped()):
                            self._marker.wait(timeout=min(_SLICE, max(0, deadline - time.monotonic())))
                        reason = stopped()
                        outcome = result(not reason and self._marker.is_set(), reason or "ready")
            except RequestCancelled:
                outcome = result(False, "cancelled")
            except TimeoutExpired:
                outcome = result(False, "timeout")
            except Exception:
                outcome = result(False, self.fatal_reason or "version_rpc_failed")
            self._ready_result = outcome
            return outcome
        finally:
            self._ready_lock.release()


def spawn_pipe(argv: list[str], *, cwd: Path, log_path: Path, process_factory=None) -> PipeOpenOcdProcess:
    """내부 caller의 명시 argv만 Linux 새 세션에 띄운다. 실행 파일 탐색은 하지 않는다."""
    if not sys.platform.startswith("linux") or not all(hasattr(os, name) for name in ("waitid", "WNOWAIT", "WNOHANG")):
        raise procutil.UnsupportedPlatform("pipe 자식 소유권은 Linux WNOWAIT 환경만 지원합니다.")
    if (not isinstance(argv, (list, tuple)) or not argv or len(argv) > 1024
            or any(not isinstance(arg, str) or "\0" in arg for arg in argv)
            or sum(len(arg) for arg in argv) > (1 << 20) or not argv[0]):
        raise ValidationFailed("pipe argv 형식이 잘못되었습니다.")
    owner = PipeOpenOcdProcess()
    try:
        owner._log = _open_log(Path(log_path))
        factory = process_factory or subprocess.Popen
        proc = factory(list(argv), cwd=os.fspath(cwd), stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                       stderr=subprocess.PIPE, bufsize=0, text=False, shell=False,
                       close_fds=True, start_new_session=True)
        owner._proc = proc
        with _OWNED_LOCK:
            _OWNED[id(proc)] = owner
        current = procutil.proc_stat(proc.pid)
        if current is None or os.getpgid(proc.pid) != proc.pid:
            raise DeviceError("pipe 자식 신원을 확인하지 못했습니다.")
        owner._ticks = current[1]
        owner._pidfd = procutil.open_pidfd(proc.pid)
        owner._client = TclPipeClient(proc.stdin, proc.stdout, name="openocd-pipe")
        os.set_blocking(proc.stderr.fileno(), False)
        owner._thread = threading.Thread(target=owner._drain_stderr, name="openocd-pipe-stderr", daemon=True)
        owner._thread.start()
        owner._thread_started = True
        return owner
    except BaseException:
        try:
            owner.close(grace=0.1, timeout=2.0)
        except BaseException:
            # 정리 자체의 예상 밖 실패도 owner를 잃거나 성공으로 바꾸지 않는다.
            pass
        raise PipeSpawnError(owner) from None
