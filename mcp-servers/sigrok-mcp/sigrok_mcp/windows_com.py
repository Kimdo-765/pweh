"""고정 OLS COM scan/show 한 실행의 사본·Windows 세대·wrapper 소유권.

장치 lease는 소비자가 보유한다. reserve 직후 lease에 이 owner를 결속하고
close 확정 뒤에만 해제한다. 정보 조회 owner/launch의 허용 범위는 바꾸지 않는다.
"""
from __future__ import annotations

import base64
import math
import os
from pathlib import Path
import re
import subprocess
import sys
import threading
import time
import uuid
from dataclasses import dataclass

from pweh import wininterop_sigrok_com as WI, windows_bundle as WB
from pweh.errors import DeviceError
from pweh.sigrok_com import ComCommand, from_argv_tail
from .cli import CliResult
from . import windows_run as R
# 두 private primitive는 argv/Windows 신원 정책을 판단하지 않는 pipe·wrapper 수명만 맡는다.
from .windows_runner import _Control, _Execution, _acquire, _cap, _path

_LOCK = threading.Lock()
_OWNED = {}
MAX_SECONDS = 120.0
CLI_MAX_SECONDS = 60.0
CLEANUP_SECONDS = 10.0


class WindowsComError(DeviceError):
    """원문 경로/출력 대신 내부 owner 참조만 보존한다."""
    code = 'sigrok_com_failed'

    def __init__(self, owner=None, *, code='sigrok_com_failed'):
        super().__init__('Windows OLS COM 실행 또는 정리를 확인하지 못했습니다.', code=code)
        self.owner = owner


def _fail(code='sigrok_com_failed', owner=None):
    raise WindowsComError(owner, code=code) from None


def _end(deadline, cap=30.0):
    now = time.monotonic()
    try:
        if type(deadline) not in (int, float):
            raise ValueError
        value = float(deadline)
        if not math.isfinite(value) or value <= now or value - now > cap:
            raise ValueError
    except (ValueError, OverflowError):
        _fail('sigrok_com_timeout')
    return value


def _tick(end, cancel=None):
    if cancel is not None:
        try:
            answer = cancel()
            if type(answer) is not bool:
                raise ValueError
        except Exception:
            _fail()
        if answer:
            _fail('sigrok_com_cancelled')
    if time.monotonic() >= end:
        _fail('sigrok_com_timeout')


def _error_code(exc):
    if isinstance(exc, WindowsComError):
        return exc.code
    code = getattr(exc, 'code', None)
    if code == 'sigrok_run_timeout':
        return 'sigrok_com_timeout'
    if code == 'sigrok_run_cancelled':
        return 'sigrok_com_cancelled'
    return 'sigrok_com_failed'


def _timeout(value, mode):
    if value is None:
        return 45.0 if mode == 'scan' else 60.0
    try:
        if type(value) not in (int, float):
            raise ValueError
        result = float(value)
        if not math.isfinite(result) or not 0 < result <= CLI_MAX_SECONDS:
            raise ValueError
    except (ValueError, OverflowError):
        _fail()
    return result


def _script_cap(script, end):
    if script == WI.QUERY_SCRIPT:
        return 1 << 20
    prefix, suffix = WI.TERMINATE_SCRIPT_TEMPLATE.split('__REQUEST__')
    if type(script) is not str or not script.startswith(prefix) or not script.endswith(suffix):
        _fail()
    encoded = script[len(prefix):-len(suffix)]
    if len(encoded) > 196608 or re.fullmatch(r'[A-Za-z0-9+/]+={0,2}', encoded) is None:
        _fail()
    try:
        value = WI._json(base64.b64decode(encoded, validate=True), end, cap=147456)
        if type(value) is not dict or set(value) != {'pid', 'image', 'creation', 'cmd', 'wait_ms'}:
            _fail()
        identity = WI.SigrokIdentity(value['pid'], value['image'], value['creation'], value['cmd'])
        command = from_argv_tail(WI.split_command_line(identity.command_line, deadline=end)[1:])
        if not WI.matches_launch(identity, WI.SigrokComLaunch(identity.image, command), deadline=end):
            _fail()
        if type(value['wait_ms']) is not int or not 1 <= value['wait_ms'] <= 2000:
            _fail()
    except Exception:
        _fail()
    return 1024


class FixedComRunner:
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
            _fail("sigrok_com_busy")
        try:
            if not self._settle(end):
                _fail("sigrok_com_cleanup_unknown")
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
                _fail("sigrok_com_cleanup_unknown")
            self._pending = None
            if control.fault:
                _fail("sigrok_com_failed")
            _tick(end)
            return bytes(control.output)
        except BaseException:
            _fail("sigrok_com_cleanup_unknown")
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
            _fail("sigrok_com_cleanup_unknown")

    def convert_path(self, path: Path, deadline: float):
        end = _end(deadline)
        _path(path)
        return self._execute(["/usr/bin/wslpath", "-w", os.fspath(path)], end, 8192)


@dataclass(frozen=True)
class ComCleanupResult:
    confirmed: bool
    reason: str


@dataclass(frozen=True)
class _ComPlan:
    argv: tuple[str, ...]
    launch: WI.SigrokComLaunch
    cwd: Path
    env_items: tuple[tuple[str, str], ...]


def owned_process_count():
    with _LOCK:
        return len(_OWNED)


class WindowsComOwner:
    """하나의 고정 명령·한 실행 세대. 외부 lease의 해제 판단은 close 결과만 쓴다."""
    def __init__(self, bundle, command, end, *, process_factory, lifecycle, runner, converter):
        self.token = uuid.uuid4().hex
        self.bundle, self.command, self.deadline = bundle, command, end
        self._factory = process_factory or subprocess.Popen
        self._lifecycle, self._runner, self._converter = lifecycle, runner, converter
        self._prepared = None
        self._prepare_started = False
        self._ready = False
        self._failed = False
        self._closed = False
        self._closing = threading.Event()
        self._operation = threading.Lock()
        self._execution = None
        self._run_started = False
        self._preflight = None

    def metadata(self):
        """등록 식별자와 고정 profile만. 사본 경로/Windows 신원은 공개하지 않는다."""
        return {"release_id": self.bundle.release_id, "manifest_sha256": self.bundle.manifest_sha256,
                "digest_basis": self.bundle.digest_basis, "known_limitations": list(self.bundle.known_limitations),
                **self.command.approval_identity()}

    def _check(self, end, cancel):
        if self._closing.is_set():
            _fail('sigrok_com_cancelled', self)
        _tick(end, cancel)

    def prepare(self, parent, *, ambient_env=(), deadline, cancel=None):
        end = min(_end(deadline, MAX_SECONDS), self.deadline)
        if not _acquire(self._operation, end):
            _fail('sigrok_com_busy', self)
        try:
            self._check(end, cancel)
            if self._prepare_started or self._failed or self._closed:
                _fail(owner=self)
            self._prepare_started = True
            def convert(path, requested):
                return self._converter(path, _cap(min(end, requested), 30))
            self._prepared = R.prepare_run(self.bundle, parent, path_converter=convert,
                                           ambient_env=ambient_env, deadline=_cap(end, 45), cancel=cancel)
            self._check(end, cancel)
            self._ready = True
        except BaseException as exc:
            self._failed = True
            partial = getattr(exc, 'prepared_run', None)
            if partial is not None:
                self._prepared = partial
            _fail(_error_code(exc), self)
        finally:
            self._operation.release()

    def _finish(self, execution, end):
        if execution.confirmed:
            return True
        try:
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
                if not self._lifecycle.terminate_and_confirm(execution.plan.launch, observed, deadline=_cap(end, 30)):
                    return False
                execution.windows_done = True
            execution.confirmed = True
            return True
        except Exception:
            return False

    def run(self, *, before_spawn, deadline, cancel=None, timeout_s=None):
        end = min(_end(deadline, MAX_SECONDS), self.deadline)
        timeout = _timeout(timeout_s, self.command.mode)
        if not callable(before_spawn):
            _fail(owner=self)
        if not _acquire(self._operation, end):
            _fail('sigrok_com_busy', self)
        execution = None
        started, error = time.monotonic(), None
        try:
            self._check(end, cancel)
            if not self._ready or self._failed or self._closed or self._run_started:
                _fail(owner=self)
            self._run_started = True
            R.revalidate_run(self._prepared, deadline=_cap(end, 45), cancel=cancel)
            launch = WI.SigrokComLaunch(self._prepared.windows_image, self.command)
            plan = _ComPlan((str(self._prepared.image), *self.command.argv_tail), launch,
                            self._prepared.cwd, self._prepared.env_items)
            self._preflight = launch
            if self._lifecycle.observe(launch, deadline=_cap(end, 30)):
                _fail('sigrok_com_cleanup_unknown', self)
            self._preflight = None
            # 조회 중 사본 교체를 차단한 뒤 마지막 장치 관찰은 고정 소비자 callback에 맡긴다.
            R.revalidate_run(self._prepared, deadline=_cap(end, 45), cancel=cancel)
            self._check(end, cancel)
            if before_spawn() is not None:
                _fail(owner=self)
            # route fresh 이후에는 새 전체 해시/Windows 조회로 시간을 늘리지 않는다.
            self._check(end, cancel)
            execution = _Execution(plan, 0)
            self._execution = execution
            execution.attempted = True
            execution_end = _cap(end, timeout)
            execution.proc = self._factory(list(plan.argv), cwd=plan.cwd, env=dict(plan.env_items),
                                           stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                           stderr=subprocess.PIPE, shell=False, close_fds=True,
                                           start_new_session=True, bufsize=0, text=False)
            if not execution.configure():
                _fail(owner=self)
            while True:
                self._check(execution_end, cancel)
                execution.drain(execution_end)
                if execution.output_limit:
                    _fail('sigrok_com_output_limit', self)
                if execution.exited() and not execution.streams:
                    break
        except BaseException as exc:
            self._failed = True
            error = _error_code(exc)
            if execution is not None:
                execution.timed_out = error == 'sigrok_com_timeout'
                execution.cancelled = error == 'sigrok_com_cancelled'
        try:
            if execution is not None and not self._finish(execution, time.monotonic() + CLEANUP_SECONDS):
                self._failed = True
                _fail('sigrok_com_cleanup_unknown', self)
            if error is not None:
                _fail(error, self)
            self._check(end, cancel)
            R.revalidate_run(self._prepared, deadline=_cap(end, 45), cancel=cancel)
            self._check(end, cancel)
            return CliResult(argv=list(execution.plan.argv), returncode=execution.returncode,
                             stdout=bytes(execution.stdout), stderr=bytes(execution.stderr).decode('utf-8', 'replace'),
                             duration_s=time.monotonic() - started, stdout_bytes=execution.stdout_bytes,
                             stderr_bytes=execution.stderr_bytes, pid=execution.proc.pid,
                             start_ticks=execution.ticks, process_token=id(execution), cleanup_verified=True)
        except BaseException as exc:
            self._failed = True
            _fail(_error_code(exc), self)
        finally:
            self._operation.release()

    def close(self, *, deadline):
        end = _end(deadline, CLEANUP_SECONDS)
        self._closing.set()
        if not _acquire(self._operation, end):
            return ComCleanupResult(False, 'sigrok_com_cleanup_unknown')
        try:
            if self._closed:
                return ComCleanupResult(True, 'confirmed')
            if self._runner is not None and not self._runner.settle(deadline=_cap(end, 30)):
                return ComCleanupResult(False, 'sigrok_com_cleanup_unknown')
            if self._preflight is not None:
                # spawn 전 발견한 실행은 소유하지 않으므로 terminate하지 않는다.
                if self._lifecycle.observe(self._preflight, deadline=_cap(end, 30)):
                    return ComCleanupResult(False, 'sigrok_com_cleanup_unknown')
                self._preflight = None
            if self._execution is not None and not self._finish(self._execution, end):
                return ComCleanupResult(False, 'sigrok_com_cleanup_unknown')
            if self._prepared is not None:
                if not R.release_run(self._prepared, deadline=_cap(end, 45)):
                    return ComCleanupResult(False, 'sigrok_com_cleanup_unknown')
                self._prepared = None
            self._closed = True
            with _LOCK:
                if _OWNED.get(self.token) is self:
                    del _OWNED[self.token]
            return ComCleanupResult(True, 'confirmed')
        except Exception:
            return ComCleanupResult(False, 'sigrok_com_cleanup_unknown')
        finally:
            self._operation.release()


def reserve_com_owner(bundle, command, *, deadline, process_factory=None, lifecycle=None, path_converter=None):
    """외부 I/O 없이 먼저 등록한다. 소비자가 lease에 결속한 뒤 prepare를 호출한다."""
    end = _end(deadline, MAX_SECONDS)
    if (not sys.platform.startswith('linux') or type(bundle) is not WB.VerifiedWindowsBundle
            or bundle.tool != 'sigrok' or type(command) is not ComCommand):
        _fail()
    runner = FixedComRunner() if lifecycle is None or path_converter is None else None
    lifecycle = lifecycle or WI.SigrokComProcessProbe(runner=runner)
    converter = path_converter or runner.convert_path
    owner = WindowsComOwner(bundle, command, end, process_factory=process_factory,
                            lifecycle=lifecycle, runner=runner, converter=converter)
    with _LOCK:
        _OWNED[owner.token] = owner
    return owner
