"""고정 OLS capture 한 실행의 사본·Windows 세대·wrapper 소유권.

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

from pweh import wininterop_sigrok_capture as WI, windows_bundle as WB
from pweh.errors import DeviceError
from pweh.sigrok_capture import CaptureCommand, from_argv_tail
from . import windows_run as R
from . import windows_capture_output as O
from .windows_capture_output import CaptureOutput, CapturePublication
# 두 private primitive는 argv/Windows 신원 정책을 판단하지 않는 pipe·wrapper 수명만 맡는다.
from .windows_runner import _Control, _Execution, _acquire, _cap, _path

_LOCK = threading.Lock()
_OWNED = {}
MAX_SECONDS = 420.0
CLI_MAX_SECONDS = 300.0
CLEANUP_SECONDS = 10.0


class WindowsCaptureError(DeviceError):
    """원문 경로/출력 대신 내부 owner 참조만 보존한다."""
    code = 'sigrok_capture_failed'

    def __init__(self, owner=None, *, code='sigrok_capture_failed'):
        super().__init__('Windows OLS COM 실행 또는 정리를 확인하지 못했습니다.', code=code)
        self.owner = owner


def _fail(code='sigrok_capture_failed', owner=None):
    raise WindowsCaptureError(owner, code=code) from None


def _end(deadline, cap=30.0):
    now = time.monotonic()
    try:
        if type(deadline) not in (int, float):
            raise ValueError
        value = float(deadline)
        if not math.isfinite(value) or value <= now or value - now > cap:
            raise ValueError
    except (ValueError, OverflowError):
        _fail('sigrok_capture_timeout')
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
            _fail('sigrok_capture_cancelled')
    if time.monotonic() >= end:
        _fail('sigrok_capture_timeout')


_ERROR_CODES = frozenset('sigrok_capture_' + suffix for suffix in (
    'failed', 'busy', 'cleanup_unknown', 'cancelled', 'timeout', 'output_limit', 'invalid',
    'output_changed', 'output_pending', 'bad_zip', 'unsupported', 'metadata_mismatch',
    'limit', 'io_failed', 'check_failed', 'publication_failed', 'artifact_exists',
    'post_commit_failed', 'empty_capture', 'no_output'))


def _error_code(exc):
    code = getattr(exc, 'code', None)
    if code in _ERROR_CODES:
        return code
    if code == 'sigrok_run_timeout':
        return 'sigrok_capture_timeout'
    if code == 'sigrok_run_cancelled':
        return 'sigrok_capture_cancelled'
    return 'sigrok_capture_failed'


def _timeout(value):
    if value is None:
        return 60.0
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
        invocation = from_argv_tail(WI.split_command_line(identity.command_line, deadline=end)[1:])
        if not WI.matches_launch(identity, WI.SigrokCaptureLaunch(identity.image, invocation.command, invocation.output_windows), deadline=end):
            _fail()
        if type(value['wait_ms']) is not int or not 1 <= value['wait_ms'] <= 2000:
            _fail()
    except Exception:
        _fail()
    return 1024


class FixedCaptureRunner:
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
            _fail("sigrok_capture_busy")
        try:
            if not self._settle(end):
                _fail("sigrok_capture_cleanup_unknown")
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
                _fail("sigrok_capture_cleanup_unknown")
            self._pending = None
            if control.fault:
                _fail("sigrok_capture_failed")
            _tick(end)
            return bytes(control.output)
        except BaseException:
            _fail("sigrok_capture_cleanup_unknown")
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
            _fail("sigrok_capture_cleanup_unknown")

    def convert_path(self, path: Path, deadline: float):
        end = _end(deadline)
        _path(path)
        return self._execute(["/usr/bin/wslpath", "-w", os.fspath(path)], end, 8192)


@dataclass(frozen=True)
class CaptureCleanupResult:
    confirmed: bool
    reason: str


@dataclass(frozen=True)
class _CapturePlan:
    argv: tuple[str, ...]
    launch: WI.SigrokCaptureLaunch
    cwd: Path
    env_items: tuple[tuple[str, str], ...]


def owned_process_count():
    with _LOCK:
        return len(_OWNED)


@dataclass(frozen=True)
class CaptureExit:
    """종료 확인 뒤 publisher에만 전달한다. stderr는 공개 JSON에 넣지 않는다."""
    returncode: int
    cancelled: bool
    timed_out: bool
    output_limit: bool
    duration_s: float
    post_deadline: float
    stderr: str


class WindowsCaptureOwner:
    """프로세스 종료와 출력 처분/사본 정리를 구별하는 capture 전용 단일 owner."""
    def __init__(self, bundle, command, end, *, process_factory, lifecycle, runner, converter):
        self.token = uuid.uuid4().hex
        self.bundle, self.command, self.deadline = bundle, command, end
        self._factory = process_factory or subprocess.Popen
        self._lifecycle, self._runner, self._converter = lifecycle, runner, converter
        self._prepared = self._output = self._execution = self._preflight = self._exit = None
        self._prepare_started = self._run_started = self._finalize_started = False
        self._ready = self._closed = self._failed = self._output_resolved = False
        self._publication = None
        self._closing = threading.Event()
        self._operation = threading.Lock()

    @property
    def processes_quiescent(self):
        return self._execution is not None and self._execution.confirmed and self._preflight is None

    @property
    def publication(self):
        return self._publication

    def metadata(self):
        return {'release_id': self.bundle.release_id, 'manifest_sha256': self.bundle.manifest_sha256,
                'digest_basis': self.bundle.digest_basis, 'known_limitations': list(self.bundle.known_limitations),
                **self.command.approval_identity()}

    def _check(self, end, cancel=None):
        if self._closing.is_set():
            _fail('sigrok_capture_cancelled', self)
        _tick(end, cancel)

    def prepare(self, parent, *, ambient_env=(), deadline, cancel=None):
        end = min(_end(deadline, MAX_SECONDS), self.deadline)
        if not _acquire(self._operation, end):
            _fail('sigrok_capture_busy', self)
        try:
            self._check(end, cancel)
            if self._prepare_started or self._closed or self._failed:
                _fail(owner=self)
            self._prepare_started = True
            def convert(path, requested):
                return self._converter(path, _cap(min(end, requested), 30))
            try:
                self._prepared = R.prepare_run(self.bundle, parent, path_converter=convert,
                                               ambient_env=ambient_env, deadline=_cap(end, 45), cancel=cancel)
            except BaseException as exc:
                self._prepared = getattr(exc, 'prepared_run', None)
                raise
            # 출력 생성에 실패해도 이 객체는 이미 use/registry에 결속되어 있다.
            self._output = O.OutputRecord(parent)
            self._output.prepare(deadline=_cap(end, 45), converter=convert, cancel=cancel)
            self.command.argv_tail(self._output.windows_path)
            R.revalidate_run(self._prepared, deadline=_cap(end, 45), cancel=cancel)
            self._output.check_empty(end)
            self._check(end, cancel)
            self._ready = True
        except BaseException as exc:
            self._failed = True
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
        timeout = _timeout(timeout_s)
        if not callable(before_spawn):
            _fail(owner=self)
        if not _acquire(self._operation, end):
            _fail('sigrok_capture_busy', self)
        execution, error = None, None
        started = time.monotonic()
        try:
            try:
                self._check(end, cancel)
                if not self._ready or self._failed or self._closed or self._run_started:
                    _fail(owner=self)
                self._run_started = True
                R.revalidate_run(self._prepared, deadline=_cap(end, 45), cancel=cancel)
                self._output.check_empty(end)
                launch = WI.SigrokCaptureLaunch(self._prepared.windows_image, self.command, self._output.windows_path)
                plan = _CapturePlan((str(self._prepared.image), *launch.argv_tail), launch,
                                    self._prepared.cwd, self._prepared.env_items)
                self._preflight = launch
                if self._lifecycle.observe(launch, deadline=_cap(end, 30)):
                    _fail('sigrok_capture_cleanup_unknown', self)
                self._preflight = None
                R.revalidate_run(self._prepared, deadline=_cap(end, 45), cancel=cancel)
                self._output.check_empty(end)
                self._check(end, cancel)
                if before_spawn() is not None:
                    _fail(owner=self)
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
                next_size_check = 0.0
                while True:
                    self._check(execution_end, cancel)
                    execution.drain(execution_end)
                    if execution.output_limit:
                        _fail('sigrok_capture_output_limit', self)
                    now = time.monotonic()
                    if now >= next_size_check:
                        if self._output.size_exceeded(execution_end):
                            _fail('sigrok_capture_output_limit', self)
                        next_size_check = now + .1
                    if execution.exited() and not execution.streams:
                        break
            except BaseException as exc:
                error = _error_code(exc)
                self._failed = True
                if execution is not None:
                    execution.timed_out = error == 'sigrok_capture_timeout'
                    execution.cancelled = error == 'sigrok_capture_cancelled'
                    execution.output_limit |= error == 'sigrok_capture_output_limit'
            # CLI loop를 떠날 때 한 번 기록한다. Windows/wrapper 정리도 이 후처리 예산을 소비한다.
            ended_at = time.monotonic()
            post_deadline = min(end, ended_at + 60)
            if execution is not None and not self._finish(execution, min(post_deadline, time.monotonic() + CLEANUP_SECONDS)):
                _fail('sigrok_capture_cleanup_unknown', self)
            if error is not None and (execution is None or error not in (
                    'sigrok_capture_cancelled', 'sigrok_capture_timeout', 'sigrok_capture_output_limit')):
                _fail(error, self)
            if execution is None:
                _fail(owner=self)
            finished = time.monotonic()
            self._exit = CaptureExit(execution.returncode, execution.cancelled, execution.timed_out,
                                     execution.output_limit, finished - started, post_deadline,
                                     bytes(execution.stderr).decode('utf-8', 'replace'))
            return self._exit
        except BaseException as exc:
            self._failed = True
            _fail(_error_code(exc), self)
        finally:
            self._operation.release()

    def _on_commit(self, receipt):
        # 원장 commit 후 통지는 새 I/O/취소 검사를 하지 않는다. 충돌 시 앞 기록은 보존한다.
        if (type(receipt) is not CapturePublication or receipt.disposition != 'published'
                or self._output is None or self._output.file_stat is None
                or receipt.size != self._output.file_stat.st_size):
            _fail('sigrok_capture_publication_failed', self)
        if self._publication is not None and self._publication != receipt:
            _fail('sigrok_capture_publication_failed', self)
        self._publication = receipt

    def finalize_output(self, publisher, *, deadline, cancel=None):
        end = min(_end(deadline, MAX_SECONDS), self.deadline,
                  self._exit.post_deadline if self._exit is not None else 0)
        if not callable(publisher):
            _fail(owner=self)
        if not _acquire(self._operation, end):
            _fail('sigrok_capture_busy', self)
        try:
            if not self.processes_quiescent or self._exit is None or self._finalize_started or self._closed:
                _fail(owner=self)
            self._finalize_started = True
            # 실행 후 취소는 publisher가 partial 전환/미게시 보존으로 판정한다.
            # 이미 처리한 취소나 새 취소가 같은 FD의 유한한 검사 자체를 막지 않게 한다.
            _tick(end)
            # 출력이 불변 사본의 예외가 되지 않게 종료 후에도 전체 tree를 검사한다.
            R.revalidate_run(self._prepared, deadline=_cap(end, 45), cancel=None)
            opened = self._output.open_final(end)
            if opened is None or opened[1] == 0:
                reason = 'missing' if opened is None else 'empty'
                self._publication = CapturePublication('no_output', reason=reason)
                self._output_resolved = True
                return self._publication
            fd, size = opened
            source = CaptureOutput(fd, size, lambda: self._output.check(end), self._on_commit)
            receipt = publisher(source, exit=self._exit, deadline=end, cancel=cancel)
            if (type(receipt) is not CapturePublication or receipt.size != size
                    or receipt.disposition not in ('published', 'invalid_output')):
                _fail('sigrok_capture_publication_failed', self)
            if receipt.disposition == 'published' and self._publication != receipt:
                _fail('sigrok_capture_publication_failed', self)
            if receipt.disposition == 'invalid_output' and self._publication is not None:
                _fail('sigrok_capture_publication_failed', self)
            self._output.check(end)
            self._publication = receipt
            self._output_resolved = True
            return receipt
        except BaseException as exc:
            self._failed = True
            # audit/late cancel로 반환을 못해도 이미 커밋된 출력은 기록을 유지한다.
            if self._publication is not None and self._publication.disposition == 'published':
                try:
                    self._output.check(end)
                    self._output_resolved = True
                except Exception:
                    pass
            _fail(_error_code(exc), self)
        finally:
            self._operation.release()

    def close(self, *, deadline):
        end = _end(deadline, CLEANUP_SECONDS)
        self._closing.set()
        if not _acquire(self._operation, end):
            return CaptureCleanupResult(False, 'sigrok_capture_cleanup_unknown')
        try:
            if self._closed:
                return CaptureCleanupResult(True, 'confirmed')
            if self._runner is not None and not self._runner.settle(deadline=_cap(end, 30)):
                return CaptureCleanupResult(False, 'sigrok_capture_cleanup_unknown')
            if self._preflight is not None:
                if self._lifecycle.observe(self._preflight, deadline=_cap(end, 30)):
                    return CaptureCleanupResult(False, 'sigrok_capture_cleanup_unknown')
                self._preflight = None
            if self._execution is not None and not self._finish(self._execution, end):
                return CaptureCleanupResult(False, 'sigrok_capture_cleanup_unknown')
            if self._output is not None and not self._output_resolved:
                if self._publication is not None and self._publication.disposition == 'published':
                    self._output.check(end)
                    self._output_resolved = True
                elif not self._output.created:
                    self._output_resolved = True
                else:
                    # 빈 디렉터리만 처분한다. 미게시 capture.sr가 있으면 열거나 삭제하지 않는다.
                    self._output.check_empty(end)
                    self._output_resolved = True
            if self._output is not None and not self._output.release(deadline=end, resolved=self._output_resolved):
                return CaptureCleanupResult(False, 'sigrok_capture_cleanup_unknown')
            if self._prepared is not None:
                if not R.release_run(self._prepared, deadline=_cap(end, 45)):
                    return CaptureCleanupResult(False, 'sigrok_capture_cleanup_unknown')
                self._prepared = None
            self._closed = True
            with _LOCK:
                if _OWNED.get(self.token) is self:
                    del _OWNED[self.token]
            return CaptureCleanupResult(True, 'confirmed')
        except Exception:
            return CaptureCleanupResult(False, 'sigrok_capture_cleanup_unknown')
        finally:
            self._operation.release()


def reserve_capture_owner(bundle, command, *, deadline, process_factory=None, lifecycle=None, path_converter=None):
    """먼저 strong registry에 결속한다. 파일/Windows/포트 접근은 prepare 이후다."""
    end = _end(deadline, MAX_SECONDS)
    if (not sys.platform.startswith('linux') or type(bundle) is not WB.VerifiedWindowsBundle
            or bundle.tool != 'sigrok' or type(command) is not CaptureCommand):
        _fail('sigrok_capture_invalid')
    runner = FixedCaptureRunner() if lifecycle is None or path_converter is None else None
    lifecycle = lifecycle or WI.SigrokCaptureProcessProbe(runner=runner)
    converter = path_converter or runner.convert_path
    owner = WindowsCaptureOwner(bundle, command, end, process_factory=process_factory,
                                lifecycle=lifecycle, runner=runner, converter=converter)
    with _LOCK:
        _OWNED[owner.token] = owner
    return owner
