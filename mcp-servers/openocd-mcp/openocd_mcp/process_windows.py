"""고정 Windows OpenOCD profile 실행의 pipe·제어 호출·일회 run 소유권.

POSIX wrapper 정리는 Windows 종료 확인과 별개다. 미확인 owner는 강한 참조로
보존하며, import만으로 Windows나 파일 시스템을 조회하지 않는다.
"""
from __future__ import annotations

import base64
import os
import re
import select
import stat
import subprocess
import sys
import threading
import time
import uuid
from dataclasses import dataclass, replace
from pathlib import Path

from pweh import procutil, safeio, wininterop as WI, windows_bundle as WB
from pweh.errors import DeviceError, ValidationFailed

from . import process_pipe as PP, windows_plan as WP

_LOCK = threading.Lock()
_OWNED: dict[str, WindowsOpenOcdOwner] = {}
_RUNS: dict[Path, _Run] = {}
_SECONDS = 30.0


class WindowsOwnerError(DeviceError):
    """원시 경로·명령줄·하위 예외를 공개하지 않는다."""
    code = "windows_owner_unknown"


def _fail(code="windows_owner_unknown"):
    raise WindowsOwnerError("Windows 실행 또는 정리를 확인하지 못했습니다.", code=code) from None


def _end(deadline):
    value = PP._duration(deadline)
    now = time.monotonic()
    if value <= now or value - now > _SECONDS:
        _fail("windows_deadline")
    return value


def _tick(end, cancel=None):
    if cancel is not None:
        try:
            value = cancel()
            if type(value) is not bool:
                _fail("windows_cancel_failed")
        except Exception:
            _fail("windows_cancel_failed")
        if value:
            _fail("windows_cancelled")
    if time.monotonic() >= end:
        _fail("windows_deadline")


def _key(st):
    return st.st_dev, st.st_ino, st.st_mode


@dataclass
class _Run:
    root: Path
    layout: WP.RunLayout | None
    parent_fd: int
    root_fd: int | None
    root_stat: object
    children: dict
    claimed: bool = False


class WindowsRunError(WindowsOwnerError):
    """부분 생성물의 미확인 정리 handle만 내부에 보존한다."""
    code = "windows_run_failed"

    def __init__(self, prepared_run):
        super().__init__("Windows 일회 실행 경로를 준비하지 못했습니다.")
        self.prepared_run = prepared_run


def prepare_windows_run(parent: Path, *, deadline: float) -> WP.RunLayout:
    """gate 뒤 worker가 부르는 배타 run 생성. 실패한 부분 경로도 이름을 재사용하지 않는다."""
    end = _end(deadline)
    parent_fd = None
    record = None
    name = "openocd-" + uuid.uuid4().hex
    root = Path(parent) / name
    try:
        parent_fd = WP._open_dir(Path(parent), end)
        os.mkdir(name, 0o700, dir_fd=parent_fd)
        # mkdir 이후 open/기록 자체의 실패도 조용히 잊지 않는다.
        record = _Run(root, None, parent_fd, None, None, {})
        with _LOCK:
            _RUNS[root] = record
        root_fd = os.open(name, safeio.DIR_FLAGS, dir_fd=parent_fd)
        record.root_fd = root_fd
        record.root_stat = os.fstat(root_fd)
        for child in ("cwd", "home", "config", "appdata"):
            _tick(end)
            os.mkdir(child, 0o700, dir_fd=root_fd)
            fd = os.open(child, safeio.DIR_FLAGS, dir_fd=root_fd)
            try:
                record.children[child] = os.fstat(fd)
            finally:
                os.close(fd)
        marker = "owner-" + uuid.uuid4().hex + ".cfg"
        fd = os.open(marker, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=root_fd)
        try:
            # write/snapshot 실패보다 먼저 O_EXCL로 만든 inode를 기록한다.
            record.children[marker] = os.fstat(fd)
            if os.write(fd, WP.OWNER_CONTENT) != len(WP.OWNER_CONTENT):
                _fail("windows_run_failed")
        finally:
            os.close(fd)
        snapshot = WP.observe_file(root / marker, max_bytes=len(WP.OWNER_CONTENT), deadline=end)
        layout = WP.RunLayout(root, root / "cwd", root / "home", root / "config", root / "appdata", snapshot)
        WP._layout(layout, end)
        record.layout = layout
        return layout
    except BaseException:
        if record is not None:
            try:
                if _release_run(record, end):
                    record = None
            except Exception:
                pass
        elif parent_fd is not None:
            os.close(parent_fd)
        raise WindowsRunError(record) from None


def _release_run(record, end):
    _tick(end)
    fd = record.root_fd
    if fd is None or record.root_stat is None:
        return False
    if _key(os.stat(record.root.name, dir_fd=record.parent_fd, follow_symlinks=False)) != _key(record.root_stat):
        return False
    if set(os.listdir(fd)) != set(record.children):
        return False
    for name, expected in record.children.items():
        _tick(end)
        current = os.stat(name, dir_fd=fd, follow_symlinks=False)
        if not safeio.same_file(current, expected):
            return False
        if stat.S_ISDIR(current.st_mode):
            child = os.open(name, safeio.DIR_FLAGS, dir_fd=fd)
            try:
                if os.listdir(child):
                    return False
            finally:
                os.close(child)
    for name in tuple(record.children):
        _tick(end)
        expected = record.children[name]
        if not safeio.same_file(os.stat(name, dir_fd=fd, follow_symlinks=False), expected):
            return False
        (os.rmdir if stat.S_ISDIR(expected.st_mode) else os.unlink)(name, dir_fd=fd)
        del record.children[name]
    if _key(os.stat(record.root.name, dir_fd=record.parent_fd, follow_symlinks=False)) != _key(record.root_stat):
        return False
    os.rmdir(record.root.name, dir_fd=record.parent_fd)
    os.close(record.root_fd)
    os.close(record.parent_fd)
    with _LOCK:
        if _RUNS.get(record.root) is record:
            del _RUNS[record.root]
    return True


def release_prepared_run(layout, *, deadline: float) -> bool:
    """spawn에 인계하기 전 실패한 run만 caller가 회수한다."""
    end = _end(deadline)
    with _LOCK:
        if type(layout) not in (WP.RunLayout, _Run):
            return False
        record = _RUNS.get(layout.root)
        if record is None or record.claimed or (record is not layout and record.layout != layout):
            return False
        record.claimed = True
    try:
        return _release_run(record, end)
    except Exception:
        return False
    finally:
        record.claimed = False


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
                    return PP._close_stream(self.proc.stdout) and PP._close_stream(self.proc.stderr)
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
        WI.WindowsIdentity(value["pid"], value["image"], value["creation"], value["cmd"])
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
        if not PP._acquire(self._lock, end):
            return False
        try:
            return self._settle(end)
        except Exception:
            return False
        finally:
            self._lock.release()

    def _execute(self, argv, end, cap):
        if not PP._acquire(self._lock, end):
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
        WP._path(path)
        return self._execute(["/usr/bin/wslpath", "-w", os.fspath(path)], end, 8192)


# 계획 생성 중에도 미완료 변환 호출을 버리지 않는다. import 시에는 실행하지 않는다.
_PATH_RUNNER = FixedWindowsRunner()


def convert_path(path: Path, deadline: float):
    """고정 wslpath 변환. 호출 미완료이면 다음 호출도 같은 소유 작업부터 확인한다."""
    return _PATH_RUNNER.convert_path(path, deadline)


@dataclass(frozen=True)
class WindowsCleanupResult:
    confirmed: bool
    reason: str
    wrapper_exit_code: int | None


class WindowsSpawnError(WindowsOwnerError):
    code = "windows_spawn_failed"

    def __init__(self, owner):
        super().__init__("Windows OpenOCD 실행 준비에 실패했습니다.")
        self.owner = owner


def owned_process_count():
    with _LOCK:
        return len(_OWNED)


class WindowsOpenOcdOwner:
    """Linux pipe owner를 wrapper 수명에만 합성하고 실제 Windows 종료를 별도 확인한다."""
    def __init__(self, plan, bundle, run, lifecycle, runner):
        self.token = uuid.uuid4().hex
        self.plan, self.bundle, self._run = plan, bundle, run
        self._lifecycle, self._runner = lifecycle, runner
        self._pipe = None
        self._closing = False
        self._confirmed = None
        self._run_released = False
        self._windows_absent = False
        self._spawn_attempted = False
        self._cleanup_lock = threading.Lock()
        with _LOCK:
            _OWNED[self.token] = self

    @property
    def client(self):
        if self._pipe is None:
            _fail("windows_not_configured")
        return self._pipe.client

    @property
    def fatal_reason(self):
        return self._pipe.fatal_reason if self._pipe else "windows_not_configured"

    def diagnostics(self):
        result = self._pipe.diagnostics() if self._pipe else {"stderr_tail": "", "errors": [], "fatal_reason": self.fatal_reason}
        result.update({"transport": "windows-pipe", "closing": self._closing,
                       "cleanup_confirmed": self._confirmed is not None,
                       "run_released": self._run_released,
                       "control_pending": self._runner.pending if self._runner else False})
        return result

    def wait_ready(self, *, timeout, cancel_check=None):
        if self._pipe is None:
            _fail("windows_not_configured")
        def checked_cancel():
            try:
                value = cancel_check()
                if type(value) is not bool:
                    _fail()
                return value
            except Exception:
                _fail("windows_cancel_failed")
        return replace(self._pipe.wait_ready(timeout=timeout,
                       cancel_check=checked_cancel if cancel_check is not None else None), transport="windows-pipe")

    def close(self, *, timeout=10.0):
        end = time.monotonic() + min(_SECONDS, PP._duration(timeout))
        self._closing = True
        if self._pipe is not None:
            try:
                self.client.abort("owner_close")
            except Exception:
                pass
        if not PP._acquire(self._cleanup_lock, end):
            return WindowsCleanupResult(False, "cleanup_busy", None)
        try:
            if self._confirmed is not None:
                return self._confirmed
            rc = None
            if self._pipe is not None:
                wrapper = self._pipe.close(grace=.1, timeout=max(.001, min(2.0, (end - time.monotonic()) / 2)))
                rc = wrapper.exit_code
                if not wrapper.confirmed:
                    return WindowsCleanupResult(False, "wrapper_cleanup_unknown", rc)
            elif self._spawn_attempted:
                return WindowsCleanupResult(False, "wrapper_cleanup_unknown", rc)
            if self._runner is not None and not self._runner.settle(deadline=end):
                return WindowsCleanupResult(False, "control_cleanup_unknown", rc)
            if not self._windows_absent and self._spawn_attempted:
                _tick(end)
                observed = self._lifecycle.observe(self.plan.launch, deadline=end)
                if not self._lifecycle.terminate_and_confirm(self.plan.launch, observed, deadline=end):
                    return WindowsCleanupResult(False, "windows_cleanup_unknown", rc)
                self._windows_absent = True
            if self._runner is not None and self._runner.pending:
                return WindowsCleanupResult(False, "control_cleanup_unknown", rc)
            self._confirmed = WindowsCleanupResult(True, "confirmed", rc)
            return self._confirmed
        except Exception:
            return WindowsCleanupResult(False, "windows_cleanup_unknown", None)
        finally:
            self._cleanup_lock.release()

    def release_run(self, *, deadline):
        end = _end(deadline)
        if not PP._acquire(self._cleanup_lock, end):
            return False
        try:
            if self._confirmed is None:
                return False
            if self._run_released:
                return True
            if not _release_run(self._run, end):
                return False
            self._run_released = True
            with _LOCK:
                if _OWNED.get(self.token) is self:
                    del _OWNED[self.token]
            return True
        except Exception:
            return False
        finally:
            self._cleanup_lock.release()


def spawn_windows(plan, *, bundle, log_path: Path, deadline: float, cancel_check=None,
                  profile_id="dummy-noinit-v1", before_spawn=None,
                  process_factory=None, lifecycle=None, path_converter=None):
    """두 고정 profile의 계획만 재확인하고 마지막 callback 뒤 즉시 실행한다."""
    end = _end(deadline)
    if not sys.platform.startswith("linux"):
        _fail("windows_wrapper_platform")
    if type(plan) is not WP.OpenOcdWindowsPlan or type(bundle) is not WB.VerifiedWindowsBundle:
        _fail("windows_input_invalid")
    with _LOCK:
        run = _RUNS.get(plan.layout.root)
        if run is None or run.claimed or run.layout != plan.layout:
            _fail("windows_run_unknown")
        run.claimed = True
    runner = FixedWindowsRunner() if lifecycle is None or path_converter is None else None
    lifecycle = lifecycle or WI.WindowsOwnedProcessProbe(runner=runner)
    converter = path_converter or runner.convert_path
    owner = WindowsOpenOcdOwner(plan, bundle, run, lifecycle, runner)
    try:
        from .dummy_profile import DUMMY_PROFILE
        from .tigard_profile import TIGARD_PROFILE
        if type(profile_id) is not str:
            _fail("windows_profile_invalid")
        if profile_id == DUMMY_PROFILE.profile_id:
            profile, builder = DUMMY_PROFILE, WP.build_dummy_plan
        elif profile_id == TIGARD_PROFILE.profile_id:
            profile, builder = TIGARD_PROFILE, WP.build_tigard_plan
            if not callable(before_spawn):
                _fail("windows_before_spawn_invalid")
        else:
            _fail("windows_profile_invalid")
        if before_spawn is not None and not callable(before_spawn):
            _fail("windows_before_spawn_invalid")
        _tick(end, cancel_check)
        if (bundle.tool != "openocd" or bundle.release_root is None
                or bundle.release_id != profile.release_id):
            _fail("windows_bundle_invalid")
        if plan.inputs.executable.path != bundle.entrypoint or plan.inputs.search_dirs != bundle.search_dirs:
            _fail("windows_bundle_invalid")
        WB.revalidate_bundle(bundle, deadline=end, cancel=cancel_check)
        fresh = builder(plan.inputs, plan.layout, ambient_env=plan.env_items,
                        path_converter=converter, deadline=end)
        if fresh != plan:
            _fail("windows_plan_changed")
        _tick(end, cancel_check)
        WP._path(Path(log_path))
        if Path(log_path).is_relative_to(plan.layout.root):
            _fail("windows_log_invalid")
        # Linux 객체는 pipe/drainer/wrapper 정리만 맡는다. 별도 Windows owner가 생성 전부터 보유한다.
        pipe = PP.PipeOpenOcdProcess()
        owner._pipe = pipe
        pipe._log = PP._open_log(Path(log_path))
        factory = process_factory or subprocess.Popen
        # 긴 재해시·경로 변환을 모두 끝낸 뒤 소비자가 scope/lease/guard를 마지막으로 확인한다.
        if before_spawn is not None and before_spawn() is not None:
            _fail("windows_before_spawn_invalid")
        _tick(end, cancel_check)
        owner._spawn_attempted = True
        pipe._proc = factory(list(plan.argv), env=dict(plan.env_items), cwd=plan.cwd,
                             stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                             bufsize=0, text=False, shell=False, close_fds=True, start_new_session=True)
        current = procutil.proc_stat(pipe._proc.pid)
        if current is None or os.getpgid(pipe._proc.pid) != pipe._proc.pid:
            _fail("windows_wrapper_unknown")
        pipe._ticks = current[1]
        pipe._pidfd = procutil.open_pidfd(pipe._proc.pid)
        pipe._client = PP.TclPipeClient(pipe._proc.stdin, pipe._proc.stdout, name="openocd-windows-pipe")
        os.set_blocking(pipe._proc.stderr.fileno(), False)
        pipe._thread = threading.Thread(target=pipe._drain_stderr, name="openocd-windows-stderr", daemon=True)
        pipe._thread.start()
        pipe._thread_started = True
        _tick(end, cancel_check)
        return owner
    except BaseException:
        # 취소 시에도 별도 긴 timeout을 만들지 않는다. 정리는 caller의 owner 경로로 인계한다.
        raise WindowsSpawnError(owner) from None
