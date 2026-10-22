"""Windows sigrok 정보 명령 두 개의 사본·자식·고정 제어 호출 수명.

POSIX wrapper의 종료와 실제 Windows 세대 부재를 따로 확인한다. 미확인 owner는
강한 참조로 보존하고 후속 사본/CLI를 만들지 않는다. import는 외부 I/O를 하지 않는다.
"""
from __future__ import annotations

import base64
import math
import os
from pathlib import Path
import re
import select
import signal
import subprocess
import sys
import threading
import time
import uuid
from dataclasses import dataclass

from pweh import procutil, wininterop_sigrok as WI, windows_bundle as WB
from pweh.errors import DeviceError
from .cli import CliResult

STDOUT_BYTES = 8 << 20
STDERR_BYTES = 128 << 10
_LOCK = threading.Lock()
_OWNED = {}


class WindowsInfoError(DeviceError):
    """공개 data에는 원문을 넣지 않고 정리 owner만 내부 참조로 인계한다."""
    code = 'sigrok_windows_failed'

    def __init__(self, owner=None, *, code='sigrok_windows_failed'):
        super().__init__('Windows sigrok 정보 실행을 확인하지 못했습니다.', code=code)
        self.owner = owner


def _fail(code='sigrok_windows_failed', owner=None):
    raise WindowsInfoError(owner, code=code) from None


def _end(deadline, cap=30.0):
    now = time.monotonic()
    try:
        if type(deadline) not in (int, float):
            raise ValueError
        value = float(deadline)
        if not math.isfinite(value) or value <= now or value - now > cap:
            raise ValueError
    except (ValueError, OverflowError):
        _fail('sigrok_windows_timeout')
    return value


def _cap(end, seconds):
    return min(end, time.monotonic() + seconds)


def _tick(end, cancel=None):
    if cancel is not None:
        try:
            value = cancel()
            if type(value) is not bool:
                raise ValueError
        except Exception:
            _fail('sigrok_windows_failed')
        if value:
            _fail('sigrok_windows_cancelled')
    if time.monotonic() >= end:
        _fail('sigrok_windows_timeout')


def _path(path):
    if (not isinstance(path, Path) or not path.is_absolute() or '..' in path.parts
            or len(os.fspath(path).encode('utf-8')) > 8192):
        _fail()


def _acquire(lock, end):
    while (remaining := end - time.monotonic()) > 0:
        if lock.acquire(timeout=min(.05, remaining)):
            return True
    return False


def _close_stream(stream):
    if stream is None:
        return True
    try:
        stream.close()
        return stream.closed is True
    except Exception:
        return False


class _Control:
    def __init__(self, proc, cap):
        self.proc = proc
        self.ticks = None
        self.cap = cap
        self.output = bytearray()
        self.error_bytes = 0
        self.fault = False
        self.configured = False
        self.streams = {proc.stdout: True, proc.stderr: False}

    def configure(self):
        current = procutil.proc_stat(self.proc.pid)
        if self.ticks is None:
            self.ticks = current[1] if current else None
        if current is None or current[1] != self.ticks or os.getpgid(self.proc.pid) != self.proc.pid:
            return False
        for stream in self.streams:
            os.set_blocking(stream.fileno(), False)
        self.configured = True
        return True

    def settle(self, end):
        if not self.configured and not self.configure():
            return False
        while time.monotonic() < end:
            if self.streams:
                ready, _, _ = select.select(list(self.streams), [], [], min(.05, max(0, end - time.monotonic())))
                for stream in ready:
                    data = os.read(stream.fileno(), 65536)
                    if not data:
                        del self.streams[stream]
                    elif self.streams[stream]:
                        if len(self.output) + len(data) > self.cap:
                            self.fault = True
                        elif not self.fault:
                            self.output.extend(data)
                    else:
                        self.error_bytes += len(data)
                        if self.error_bytes > 65536:
                            self.fault = True
            else:
                try:
                    state = os.waitid(os.P_PID, self.proc.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)
                except (OSError, ChildProcessError):
                    return False
                if state is not None:
                    # 강제로 끝난 interop wrapper는 Windows 제어 호출 완료 증거가 아니다.
                    if state.si_code != os.CLD_EXITED:
                        return False
                    if procutil.process_group_empty(self.proc.pid, expect_start_ticks=self.ticks, deadline=end) is not True:
                        return False
                    rc = self.proc.wait(timeout=0)
                    self.fault |= rc != 0
                    return _close_stream(self.proc.stdout) and _close_stream(self.proc.stderr)
                time.sleep(min(.01, max(0, end - time.monotonic())))
        return False


def _script_cap(script, end):
    if script == WI.QUERY_SCRIPT:
        return 1 << 20
    prefix, suffix = WI.TERMINATE_SCRIPT_TEMPLATE.split("__REQUEST__")
    if type(script) is not str or not script.startswith(prefix) or not script.endswith(suffix):
        _fail("windows_control_invalid")
    encoded = script[len(prefix):-len(suffix)]
    if len(encoded) > 196608 or re.fullmatch(r"[A-Za-z0-9+/]+={0,2}", encoded) is None:
        _fail("windows_control_invalid")
    try:
        raw = base64.b64decode(encoded, validate=True)
        value = WI._json(raw, end, cap=147456)
        if type(value) is not dict or set(value) != {"pid", "image", "creation", "cmd", "wait_ms"}:
            _fail()
        identity = WI.SigrokIdentity(value["pid"], value["image"], value["creation"], value["cmd"])
        launch = WI.SigrokLaunch(identity.image, WI.split_command_line(identity.command_line, deadline=end)[1:])
        if not WI.matches_launch(identity, launch, deadline=end):
            _fail()
        if type(value["wait_ms"]) is not int or not 1 <= value["wait_ms"] <= 2000:
            _fail()
    except Exception:
        _fail("windows_control_invalid")
    return 1024


class FixedWindowsRunner:
    """고정 조회/종료만 실행한다. 미완료 제어 호출은 추가 생성 없이 보존한다."""
    def __init__(self, *, process_factory=None, powershell_provider=None):
        self._factory = process_factory or subprocess.Popen
        self._provider = powershell_provider
        self._lock = threading.Lock()
        self._pending = None

    @property
    def pending(self):
        return self._pending is not None

    def _settle(self, end):
        if self._pending is None:
            return True
        if not self._pending.settle(end):
            return False
        self._pending = None
        return True

    def settle(self, *, deadline):
        end = _end(deadline)
        if not _acquire(self._lock, end):
            return False
        try:
            return self._settle(end)
        except Exception:
            return False
        finally:
            self._lock.release()

    def _execute(self, argv, end, cap):
        if not _acquire(self._lock, end):
            _fail("windows_control_busy")
        try:
            if not self._settle(end):
                _fail("windows_control_pending")
            _tick(end)
            proc = self._factory(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                 stderr=subprocess.PIPE, shell=False, close_fds=True,
                                 start_new_session=True, bufsize=0, text=False)
            # constructor 중 pipe 설정 실패도 handle을 잃지 않게 먼저 등록한다.
            control = object.__new__(_Control)
            self._pending = control
            control.proc = proc
            _Control.__init__(control, proc, cap)
            if not control.settle(end):
                _fail("windows_control_pending")
            self._pending = None
            if control.fault:
                _fail("windows_control_failed")
            _tick(end)
            return bytes(control.output)
        except BaseException:
            _fail("windows_control_unknown")
        finally:
            self._lock.release()

    def __call__(self, script, deadline):
        end = _end(deadline)
        cap = _script_cap(script, end)
        try:
            if self._provider is None:
                from pweh.hostenv import powershell_path
                path = powershell_path()
            else:
                path = self._provider()
            if type(path) is not str or not Path(path).is_absolute():
                _fail()
            encoded = base64.b64encode(script.encode("utf-16le")).decode("ascii")
            return self._execute([path, "-NoLogo", "-NoProfile", "-NonInteractive", "-EncodedCommand", encoded], end, cap)
        except BaseException:
            _fail("windows_control_unknown")

    def convert_path(self, path: Path, deadline: float):
        end = _end(deadline)
        _path(path)
        return self._execute(["/usr/bin/wslpath", "-w", os.fspath(path)], end, 8192)


@dataclass(frozen=True)
class InfoCleanupResult:
    confirmed: bool
    reason: str


class _Execution:
    """한 실행 객체의 부분 상태. PID만으로 다음 실행과 합치지 않는다."""
    def __init__(self, plan, ordinal):
        self.plan, self.ordinal = plan, ordinal
        self.proc = None
        self.ticks = self.pidfd = None
        self.attempted = False
        self.streams = {}
        self.configured = False
        self.stdout = bytearray()
        self.stderr = bytearray()
        self.stdout_bytes = self.stderr_bytes = 0
        self.output_limit = False
        self.fault = False
        self.wrapper_done = self.windows_done = self.confirmed = False
        self.observed = None
        self.returncode = None
        self.timed_out = self.cancelled = False

    def configure(self):
        if self.proc is None:
            return True
        if not self.configured:
            current = procutil.proc_stat(self.proc.pid)
            if self.ticks is None and current:
                self.ticks = current[1]
            if current is None or current[1] != self.ticks or os.getpgid(self.proc.pid) != self.proc.pid:
                return False
            if self.pidfd is None:
                self.pidfd = procutil.open_pidfd(self.proc.pid)
            self.streams = {self.proc.stdout: True, self.proc.stderr: False}
            for stream in self.streams:
                os.set_blocking(stream.fileno(), False)
            self.configured = True
        return True

    def drain(self, end, *, wait=True):
        if not self.streams:
            return
        ready, _, _ = select.select(list(self.streams), [], [],
                                    min(.05, max(0, end - time.monotonic())) if wait else 0)
        for stream in ready:
            data = os.read(stream.fileno(), 65536)
            if not data:
                del self.streams[stream]
                continue
            output = self.streams[stream]
            if output:
                self.stdout_bytes += len(data)
                target, limit = self.stdout, STDOUT_BYTES
            else:
                self.stderr_bytes += len(data)
                target, limit = self.stderr, STDERR_BYTES
            # 초과 뒤에는 계속 drain하되 보존 bytes는 늘리지 않는다.
            if len(target) + len(data) > limit:
                self.output_limit = True
            elif not self.output_limit:
                target.extend(data)

    def exited(self):
        if self.proc is None:
            return True
        return os.waitid(os.P_PID, self.proc.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT) is not None

    def finish_wrapper(self, end):
        """리더를 거두기 전에 그룹을 닫는다. 실제 Windows 부재는 별도 단계다."""
        if self.wrapper_done:
            return True
        if self.proc is None:
            self.wrapper_done = True
            return True
        if not self.configure():
            return False
        signal_at = time.monotonic() + .1
        term_sent = kill_sent = False
        while time.monotonic() < end:
            self.drain(end)
            empty = procutil.process_group_empty(self.proc.pid, expect_start_ticks=self.ticks, deadline=end)
            if empty is True and self.exited():
                # 리더 PID를 유지한 채 마지막 stream까지 소유하여 EOF를 확인한다.
                if self.streams:
                    continue
                if not (_close_stream(self.proc.stdout) and _close_stream(self.proc.stderr)):
                    return False
                self.returncode = self.proc.wait(timeout=0)
                if self.pidfd is not None:
                    os.close(self.pidfd)
                    self.pidfd = None
                self.wrapper_done = True
                return True
            if not term_sent:
                if not procutil.signal_owned_group(self.proc.pid, signal.SIGTERM,
                                                   expect_start_ticks=self.ticks, pidfd=self.pidfd):
                    return False
                term_sent = True
            elif not kill_sent and time.monotonic() >= signal_at:
                if not procutil.signal_owned_group(self.proc.pid, signal.SIGKILL,
                                                   expect_start_ticks=self.ticks, pidfd=self.pidfd):
                    return False
                kill_sent = True
            if not self.streams:
                time.sleep(min(.01, max(0, end - time.monotonic())))
        return False


def owned_process_count():
    with _LOCK:
        return len(_OWNED)


class WindowsInfoOwner:
    """한 사본과 최대 두 세대의 수명. cleanup이 끝나기 전 다음 명령은 없다."""
    def __init__(self, bundle, end, *, process_factory, lifecycle, runner):
        self.token = uuid.uuid4().hex
        self.bundle, self.deadline = bundle, end
        self._factory = process_factory or subprocess.Popen
        self._lifecycle, self._runner = lifecycle, runner
        self._prepared = None
        self._preparing = True
        self._failed = False
        self._closed = False
        self._closing = threading.Event()
        self._operation = threading.Lock()
        self._executions = []
        self._modes = []
        self._preflight = None

    def metadata(self):
        """검증한 등록 식별자만 반환한다. 고유 사본의 경로/프로세스 신원은 제외한다."""
        return {"release_id": self.bundle.release_id, "manifest_sha256": self.bundle.manifest_sha256,
                "digest_basis": self.bundle.digest_basis, "known_limitations": list(self.bundle.known_limitations)}

    def _check(self, end, cancel):
        if self._closing.is_set():
            _fail('sigrok_windows_cancelled', self)
        _tick(end, cancel)

    def _finish(self, execution, end):
        if execution.confirmed:
            return True
        try:
            # 제어 조회의 이전 호출이 미완료이면 새 호출을 만들지 않는다.
            if self._runner is not None and not self._runner.settle(deadline=_cap(end, 30)):
                return False
            if not execution.finish_wrapper(end):
                return False
            if execution.attempted and not execution.windows_done:
                observed = self._lifecycle.observe(execution.plan.launch, deadline=_cap(end, 30))
                if execution.observed is not None and observed and observed != execution.observed:
                    return False
                if execution.observed is None:
                    execution.observed = observed or None
                # 빈 응답도 fresh 조회와 최종 complete 부재를 거쳐야 확정한다.
                if not self._lifecycle.terminate_and_confirm(execution.plan.launch, observed, deadline=_cap(end, 30)):
                    return False
                execution.windows_done = True
            execution.confirmed = True
            return True
        except Exception:
            return False

    def run(self, mode, *, deadline, cancel=None):
        end = min(_end(deadline, 90), self.deadline)
        if not _acquire(self._operation, end):
            _fail('sigrok_windows_busy', self)
        execution = None
        started = time.monotonic()
        error = None
        try:
            self._check(end, cancel)
            if (self._preparing or self._failed or self._closed or self._prepared is None
                    or mode not in ('version', 'list')
                    or (self._modes and self._modes != ['version'])
                    or (self._modes and mode != 'list')):
                _fail('sigrok_windows_failed', self)
            from . import windows_run as R
            R.revalidate_run(self._prepared, deadline=_cap(end, 45), cancel=cancel)
            plan = R.plan_command(self._prepared, mode=mode)
            if (type(plan.launch) is not WI.SigrokLaunch
                    or plan.launch.argv_tail != (('--version',) if mode == 'version' else ('--list-supported',))):
                _fail('sigrok_windows_failed', self)
            # 미소유 실행이 관찰되거나 조회 자체가 실패하면 사본 표식을 먼저 지우지 않는다.
            self._preflight = plan.launch
            if self._lifecycle.observe(plan.launch, deadline=_cap(end, 30)):
                _fail('sigrok_windows_cleanup_unknown', self)
            self._preflight = None
            # 외부 조회 동안 원본/사본이 바뀐 경우 생성 직전에 다시 차단한다.
            R.revalidate_run(self._prepared, deadline=_cap(end, 45), cancel=cancel)
            self._check(end, cancel)
            execution = _Execution(plan, len(self._executions))
            self._executions.append(execution)
            self._modes.append(mode)
            execution.attempted = True
            execution.proc = self._factory(list(plan.argv), cwd=plan.cwd, env=dict(plan.env_items),
                                           stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                           stderr=subprocess.PIPE, shell=False, close_fds=True,
                                           start_new_session=True, bufsize=0, text=False)
            if not execution.configure():
                _fail('sigrok_windows_failed', self)
            execution_end = _cap(end, 30 if mode == 'version' else 60)
            while True:
                self._check(execution_end, cancel)
                execution.drain(execution_end)
                if execution.output_limit:
                    _fail('sigrok_windows_output_limit', self)
                if execution.exited() and not execution.streams:
                    break
            # 정상 종료 역시 wrapper/group/실제 Windows의 별도 확인을 거친다.
        except BaseException as exc:
            self._failed = True
            error = exc.code if isinstance(exc, WindowsInfoError) else 'sigrok_windows_failed'
            if execution is not None:
                execution.timed_out = error == 'sigrok_windows_timeout'
                execution.cancelled = error == 'sigrok_windows_cancelled'
        try:
            if execution is not None and not self._finish(execution, time.monotonic() + 10):
                self._failed = True
                _fail('sigrok_windows_cleanup_unknown', self)
            if error is not None:
                _fail(error, self)
            from . import windows_run as R
            R.revalidate_run(self._prepared, deadline=_cap(end, 45), cancel=cancel)
            self._check(end, cancel)
            return CliResult(argv=list(execution.plan.argv), returncode=execution.returncode,
                             stdout=bytes(execution.stdout), stderr=bytes(execution.stderr).decode('utf-8', 'replace'),
                             duration_s=time.monotonic() - started, stdout_bytes=execution.stdout_bytes,
                             stderr_bytes=execution.stderr_bytes, pid=execution.proc.pid,
                             start_ticks=execution.ticks, process_token=id(execution), cleanup_verified=True)
        except BaseException as exc:
            self._failed = True
            code = exc.code if isinstance(exc, WindowsInfoError) else 'sigrok_windows_failed'
            _fail(code, self)
        finally:
            self._operation.release()

    def close(self, *, deadline):
        end = _end(deadline, 30)
        self._closing.set()
        if not _acquire(self._operation, end):
            return InfoCleanupResult(False, 'sigrok_windows_cleanup_unknown')
        try:
            if self._closed:
                return InfoCleanupResult(True, 'confirmed')
            if self._preparing:
                return InfoCleanupResult(False, 'sigrok_windows_cleanup_unknown')
            if self._runner is not None and not self._runner.settle(deadline=_cap(end, 30)):
                return InfoCleanupResult(False, 'sigrok_windows_cleanup_unknown')
            if self._preflight is not None:
                # 생성 전 발견한 프로세스는 소유하지 않으므로 종료하지 않고 부재만 기다린다.
                if self._lifecycle.observe(self._preflight, deadline=_cap(end, 30)):
                    return InfoCleanupResult(False, 'sigrok_windows_cleanup_unknown')
                self._preflight = None
            for execution in self._executions:
                if not self._finish(execution, end):
                    return InfoCleanupResult(False, 'sigrok_windows_cleanup_unknown')
            if self._prepared is not None:
                from . import windows_run as R
                if not R.release_run(self._prepared, deadline=_cap(end, 45)):
                    return InfoCleanupResult(False, 'sigrok_windows_cleanup_unknown')
                self._prepared = None
            self._closed = True
            with _LOCK:
                if _OWNED.get(self.token) is self:
                    del _OWNED[self.token]
            return InfoCleanupResult(True, 'confirmed')
        except Exception:
            return InfoCleanupResult(False, 'sigrok_windows_cleanup_unknown')
        finally:
            self._operation.release()


def prepare_info(bundle, parent, *, deadline, cancel=None, ambient_env=(), path_converter=None,
                 process_factory=None, lifecycle=None):
    """사본을 만들기 전에 등록한다. 이전 미확인 owner가 있으면 새 사본/CLI는 0개다."""
    end = _end(deadline, 90)
    if not sys.platform.startswith('linux') or type(bundle) is not WB.VerifiedWindowsBundle or bundle.tool != 'sigrok':
        _fail()
    _tick(end, cancel)
    with _LOCK:
        old = tuple(_OWNED.values())
    for previous in old:
        if not previous._failed and not previous._closing.is_set():
            _fail('sigrok_windows_busy')
        if not previous.close(deadline=_cap(end, 10)).confirmed:
            _fail('sigrok_windows_cleanup_unknown', previous)
    runner = FixedWindowsRunner() if lifecycle is None or path_converter is None else None
    lifecycle = lifecycle or WI.SigrokOwnedProcessProbe(runner=runner)
    converter = path_converter or runner.convert_path
    owner = WindowsInfoOwner(bundle, end, process_factory=process_factory, lifecycle=lifecycle, runner=runner)
    with _LOCK:
        if _OWNED:
            _fail('sigrok_windows_busy')
        _OWNED[owner.token] = owner
    owner._operation.acquire()
    try:
        from . import windows_run as R
        _tick(end, cancel)
        # 전달한 converter는 별도 30초 cap을 적용하며 전체 hard end를 늘리지 않는다.
        def convert(path, requested):
            return converter(path, _cap(min(end, requested), 30))
        owner._prepared = R.prepare_run(bundle, parent, path_converter=convert,
                                         ambient_env=ambient_env, deadline=end, cancel=cancel)
        owner._check(end, cancel)
        return owner
    except BaseException as exc:
        owner._failed = True
        partial = getattr(exc, 'prepared_run', None)
        if partial is not None:
            owner._prepared = partial
        code = exc.code if isinstance(exc, WindowsInfoError) else 'sigrok_windows_failed'
        _fail(code, owner)
    finally:
        owner._preparing = False
        owner._operation.release()
