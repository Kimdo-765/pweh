"""고정 rtl_power 계획과 명시 주입한 합성 Linux 자식의 수명을 다룬다.

실행물 탐색·기본 spawn·장치 수신·MCP 연결은 없다. factory는 신뢰된 시험 이음매이며,
자식을 만들면 그 handle을 반환해야 한다. 실제 수신을 제한하는 sandbox가 아니다.
"""
from __future__ import annotations

import math
import os
import select
import signal
import subprocess
import sys
import threading
import time
from dataclasses import dataclass, fields
from typing import Callable

from . import procutil
from .errors import PwehError

PROFILE = "rtl-power-fake-plan-v1"
MAX_STDOUT_BYTES = 1 << 20
MAX_STDERR_BYTES = 16 << 10
_SLICE = 0.02
_OWNED: dict[int, _FakeOwner] = {}
_OWNED_LOCK = threading.Lock()


class PowerFakeError(PwehError):
    """원문 없는 고정 오류. 정리 미확인일 때만 private owner를 보유한다."""


def _error(reason: str) -> PowerFakeError:
    return PowerFakeError("합성 전력 분석 실행을 완료하지 못했습니다.", code="rf_power_fake_" + reason)


@dataclass(frozen=True)
class PowerSweepRequest:
    """고정 계획의 정수 여섯 값. 물리 장치 식별·허가를 뜻하지 않는다."""

    device_index: int
    low_hz: int
    high_hz: int
    max_bin_hz: int
    integration_seconds: int
    duration_seconds: int


@dataclass(frozen=True)
class PowerPlan:
    """runner가 실행 직전에 같은 요청으로 재구성해 대조하는 닫힌 계획."""

    profile: str
    request: PowerSweepRequest
    argv_tail: tuple[str, ...]
    simulator_only: bool = True
    hardware_verified: bool = False


def build_power_plan(request: PowerSweepRequest) -> PowerPlan:
    """허용 정수만 10진 ASCII의 고정 아홉 인자로 바꾼다."""
    if type(request) is not PowerSweepRequest:
        raise _error("invalid") from None
    if any(type(getattr(request, f.name, None)) is not int for f in fields(request)):
        raise _error("invalid") from None
    if not (0 <= request.device_index <= 255
            and 1 <= request.low_hz < request.high_hz <= (1 << 31) - 1
            and 1 <= request.max_bin_hz <= min(2800000, request.high_hz - request.low_hz)
            and 1 <= request.integration_seconds <= request.duration_seconds <= 60):
        raise _error("invalid") from None
    return PowerPlan(PROFILE, request, ("-d", str(request.device_index), "-f",
        f"{request.low_hz}:{request.high_hz}:{request.max_bin_hz}", "-i",
        str(request.integration_seconds), "-e", str(request.duration_seconds), "-"))


def _deadline(value: object) -> float:
    try:
        if type(value) not in (int, float):
            raise ValueError
        result = float(value)
        if not math.isfinite(result):
            raise ValueError
    except (OverflowError, ValueError):
        raise _error("invalid") from None
    return result


def _check(deadline: float, cancel: Callable[[], bool] | None) -> None:
    if cancel is not None:
        try:
            value = cancel()
            if type(value) is not bool:
                raise ValueError
        except Exception:
            raise _error("failed") from None
        if value:
            raise _error("cancelled") from None
    if time.monotonic() >= deadline:
        raise _error("timeout") from None


def _close_stream(stream) -> bool:
    if stream is None:
        return True
    try:
        if stream.closed is not True:
            stream.close()
        return stream.closed is True
    except Exception:
        return False


class _FakeOwner:
    """한 자식 세대와 reader를 strong registry에 보존하고 bounded close만 재시도한다."""

    def __init__(self) -> None:
        self.proc = None
        self.ticks: int | None = None
        self.pidfd: int | None = None
        self.pidfd_identity: tuple[int, int, int] | None = None
        self.thread: threading.Thread | None = None
        self.thread_started = False
        self.done = threading.Event()
        self.stdout = bytearray()
        self.stdout_bytes = 0
        self.stderr_bytes = 0
        self.fatal: str | None = None
        self.group_confirmed = False
        self.reaped = False
        self.exit_code: int | None = None
        self.confirmed = False
        self._close_lock = threading.Lock()
        with _OWNED_LOCK:
            _OWNED[id(self)] = self

    def _child_state(self) -> str:
        try:
            pid = self.proc.pid
            if type(pid) is not int or pid <= 1 or pid in (os.getpid(), os.getpgrp()):
                return "unknown"
            result = os.waitid(os.P_PID, pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)
            if result is None:
                return "running"
            return "exited" if result.si_pid == pid else "unknown"
        except Exception:
            return "unknown"

    def _bind(self) -> bool:
        """초기 관찰 실패 뒤에도 waitable한 직접 자식에만 신원을 결속한다."""
        if self._child_state() == "unknown":
            return False
        try:
            current = procutil.proc_stat(self.proc.pid)
            if current is None or os.getpgid(self.proc.pid) != self.proc.pid:
                return False
            if self.ticks is None:
                self.ticks = current[1]
            return current[1] == self.ticks and self._child_state() != "unknown"
        except Exception:
            return False

    def start_reader(self) -> None:
        if not self._bind():
            raise _error("failed")
        self.pidfd = procutil.open_pidfd(self.proc.pid)
        if self.pidfd is not None:
            st = os.fstat(self.pidfd)
            self.pidfd_identity = (st.st_dev, st.st_ino, st.st_mode)
        for stream in (self.proc.stdout, self.proc.stderr):
            os.set_blocking(stream.fileno(), False)
        self.thread = threading.Thread(target=self._drain, name="pweh-power-fake", daemon=True)
        self.thread.start()
        self.thread_started = True

    def _drain(self) -> None:
        """두 pipe를 함께 읽되 stdout만 보존하고 초과 관찰은 cap+1에서 멈춘다."""
        try:
            streams = {self.proc.stdout.fileno(): "stdout", self.proc.stderr.fileno(): "stderr"}
            while streams:
                ready, _, _ = select.select(tuple(streams), (), (), _SLICE)
                for fd in ready:
                    name = streams[fd]
                    limit = MAX_STDOUT_BYTES if name == "stdout" else MAX_STDERR_BYTES
                    count = self.stdout_bytes if name == "stdout" else self.stderr_bytes
                    try:
                        chunk = os.read(fd, min(64 << 10, limit - count + 1))
                    except BlockingIOError:
                        continue
                    if not chunk:
                        del streams[fd]
                        continue
                    if name == "stdout":
                        self.stdout_bytes += len(chunk)
                        self.stdout.extend(chunk[:max(0, limit - count)])
                    else:
                        self.stderr_bytes += len(chunk)
                    if count + len(chunk) > limit:
                        self.fatal = "output_limit"
                        return
        except Exception:
            self.fatal = "failed"
        finally:
            self.done.set()

    def _observe_group(self, deadline: float) -> bool | None:
        if self.group_confirmed:
            return True
        if not self._bind():
            return None
        if self._child_state() == "running":
            return False
        found = procutil.process_group_empty(self.proc.pid, expect_start_ticks=self.ticks, deadline=deadline)
        if not self._bind() or self._child_state() != "exited":
            return None
        if found is True:
            self.group_confirmed = True
        return found

    def _wait_group(self, until: float) -> bool | None:
        while time.monotonic() < until:
            result = self._observe_group(until)
            if result is not False:
                return result
            time.sleep(min(_SLICE, max(0, until - time.monotonic())))
        return False

    def _close_pidfd(self) -> bool:
        if self.pidfd is None:
            return True
        try:
            st = os.fstat(self.pidfd)
        except OSError as exc:
            if exc.errno == 9:  # 이미 닫힌 FD만 확인하고 재사용된 FD는 닫지 않는다.
                self.pidfd = None
                return True
            return False
        identity = (st.st_dev, st.st_ino, st.st_mode)
        if self.pidfd_identity is None:
            self.pidfd_identity = identity
        if identity != self.pidfd_identity:
            return False
        try:
            os.close(self.pidfd)
        except OSError:
            return False
        self.pidfd = None
        return True

    def close(self, *, deadline: float) -> bool:
        """최대 5초 안에서 같은 child/group/reader/FD/reap만 정리한다. 재실행은 없다."""
        end = min(_deadline(deadline), time.monotonic() + 5)
        remaining = end - time.monotonic()
        if remaining <= 0 or not self._close_lock.acquire(timeout=remaining):
            return False
        try:
            if self.confirmed:
                return True
            try:
                return self._close_locked(end)
            except Exception:
                return False
        finally:
            self._close_lock.release()

    def _close_locked(self, end: float) -> bool:
        if self.proc is not None and not self.group_confirmed:
            result = self._observe_group(end)
            if result is None:
                return False
            for sig in (signal.SIGTERM, signal.SIGKILL):
                if result is True:
                    break
                if time.monotonic() >= end or not self._bind():
                    return False
                sent = procutil.signal_owned_group(self.proc.pid, sig, expect_start_ticks=self.ticks,
                                                  pidfd=self.pidfd)
                if sent is None:
                    return False
                result = self._wait_group(min(end, time.monotonic() + 0.2) if sig == signal.SIGTERM else end)
                if result is None:
                    return False
            if result is not True:
                return False
        if self.thread is not None:
            if self.thread is threading.current_thread():
                return False
            if self.thread_started or self.thread.ident is not None:
                self.thread.join(timeout=max(0, end - time.monotonic()))
                if self.thread.is_alive() or not self.done.is_set():
                    return False
            elif self.thread.is_alive():
                return False
        if self.proc is not None:
            for name in ("stdin", "stdout", "stderr"):
                if time.monotonic() >= end or not _close_stream(getattr(self.proc, name)):
                    return False
            if not self.reaped:
                if time.monotonic() >= end or not self._bind() or self._child_state() != "exited":
                    return False
                # poll/Popen.wait의 이미 거둔 자식=0 경로를 쓰지 않고 정확한 waitpid를 확인한다.
                pid, status = os.waitpid(self.proc.pid, os.WNOHANG)
                if pid != self.proc.pid:
                    return False
                self.exit_code = os.waitstatus_to_exitcode(status)
                self.proc.returncode = self.exit_code
                self.reaped = True
        if time.monotonic() >= end or not self._close_pidfd():
            return False
        self.confirmed = True
        with _OWNED_LOCK:
            if _OWNED.get(id(self)) is self:
                del _OWNED[id(self)]
        return True


def run_power_plan_fake(plan: PowerPlan, *, process_factory, deadline: float,
                        cancel: Callable[[], bool] | None = None) -> dict:
    """명시 factory의 합성 자식만 실행하고 정리 확정 뒤 원래 기한으로 CSV를 검사한다."""
    end = min(_deadline(deadline), time.monotonic() + 60)
    if (type(plan) is not PowerPlan or type(getattr(plan, "profile", None)) is not str
            or type(getattr(plan, "argv_tail", None)) is not tuple
            or len(plan.argv_tail) != 9
            or any(type(arg) is not str for arg in plan.argv_tail)
            or type(getattr(plan, "request", None)) is not PowerSweepRequest
            or type(getattr(plan, "simulator_only", None)) is not bool
            or type(getattr(plan, "hardware_verified", None)) is not bool
            or not callable(process_factory)
            or (cancel is not None and not callable(cancel))):
        raise _error("invalid") from None
    canonical = build_power_plan(plan.request)
    if plan != canonical:
        raise _error("invalid") from None
    if not sys.platform.startswith("linux") or not hasattr(os, "WNOWAIT"):
        raise _error("invalid") from None
    _check(end, cancel)
    owner = _FakeOwner()
    reason = None
    try:
        # handle을 인수한 다음에만 조회·pipe 설정·reader를 시작한다.
        owner.proc = process_factory(canonical.argv_tail, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                     stderr=subprocess.PIPE, bufsize=0, start_new_session=True, close_fds=True)
        owner.start_reader()
        while True:
            _check(end, cancel)
            if owner.fatal is not None:
                raise _error(owner.fatal)
            state = owner._child_state()
            if state == "unknown":
                raise _error("failed")
            if state == "exited":
                break
            time.sleep(min(_SLICE, max(0, end - time.monotonic())))
    except PowerFakeError as exc:
        reason = exc.code.removeprefix("rf_power_fake_")
    except BaseException:
        reason = "failed"
    if not owner.close(deadline=time.monotonic() + 5):
        error = _error("cleanup_unknown")
        error.owner = owner
        raise error from None
    if reason is not None:
        raise _error(reason) from None
    if owner.fatal is not None:
        raise _error(owner.fatal) from None
    if owner.exit_code != 0:
        raise _error("failed") from None
    _check(end, cancel)
    try:
        from .rf_power import inspect_power_csv
        inspection = inspect_power_csv(bytes(owner.stdout), deadline=end, cancel=cancel)
    except PwehError as exc:
        reason = "cancelled" if exc.code == "cancelled" else "failed"
        raise _error(reason) from None
    except Exception:
        raise _error("failed") from None
    if inspection.get("stop") is not None and inspection["stop"]["code"] == "time_limit":
        raise _error("timeout") from None
    _check(end, cancel)
    return {"simulator_only": True, "hardware_verified": False, "inspection": inspection,
            "stdout_bytes": owner.stdout_bytes, "stderr_bytes": owner.stderr_bytes}
