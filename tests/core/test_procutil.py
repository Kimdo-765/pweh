"""pweh.procutil.pid_alive (G9): POSIX 생존 확인, 좀비 = 끝남, 깨진 pid, 네이티브 Windows 에서 os.kill 금지."""

from __future__ import annotations

import errno
import os
import subprocess
import sys
import time
from pathlib import Path

import pytest

from pweh import procutil
from pweh.procutil import UnsupportedPlatform, pid_alive

HAS_PROC = Path("/proc/self/stat").exists()


def test_own_pid_is_alive():
    assert pid_alive(os.getpid()) is True


def test_reaped_child_is_dead():
    p = subprocess.Popen([sys.executable, "-c", "pass"])
    p.wait(timeout=30)
    assert pid_alive(p.pid) is False


@pytest.mark.skipif(not HAS_PROC, reason="/proc 가 없는 플랫폼 (좀비 판별 불가)")
def test_zombie_child_is_dead():
    p = subprocess.Popen([sys.executable, "-c", "pass"])
    try:
        deadline = time.monotonic() + 30
        while procutil._proc_state(p.pid) != "Z":  # 끝났지만 아직 거두지 않음
            assert time.monotonic() < deadline, procutil._proc_state(p.pid)
            time.sleep(0.02)
        assert pid_alive(p.pid) is False
    finally:
        p.wait(timeout=30)


@pytest.mark.parametrize("pid", [0, -1, -os.getpid(), True, False, None, "123", 1.0, 2**70])
def test_invalid_pids_are_false_without_group_signals(pid, monkeypatch):
    calls = []
    real_kill = os.kill

    def spy(p, sig):
        calls.append((p, sig))
        return real_kill(p, sig)

    monkeypatch.setattr(os, "kill", spy)
    assert pid_alive(pid) is False
    # 0 이하(프로세스 그룹·모든 프로세스)와 정수가 아닌 값에는 os.kill 을 부르지 않는다
    assert all(p > 0 for p, _ in calls), calls


def test_eperm_means_alive_and_esrch_means_dead(monkeypatch):
    def eperm(pid, sig):
        raise PermissionError(errno.EPERM, "Operation not permitted")

    monkeypatch.setattr(os, "kill", eperm)
    assert pid_alive(424242) is True

    def esrch(pid, sig):
        raise ProcessLookupError(errno.ESRCH, "No such process")

    monkeypatch.setattr(os, "kill", esrch)
    assert pid_alive(424242) is False


def test_never_calls_os_kill_on_native_windows(monkeypatch):
    def boom(pid, sig):
        raise AssertionError("Windows 에서 os.kill(pid, 0) 은 CTRL_C_EVENT 다")

    monkeypatch.setattr(os, "kill", boom)
    monkeypatch.setattr(sys, "platform", "win32")
    with pytest.raises(UnsupportedPlatform) as ei:
        pid_alive(os.getpid())
    assert ei.value.code == "unsupported_platform" and "WSL" in (ei.value.hint or "")
    assert pid_alive(0) is False  # 깨진 값은 플랫폼과 무관하게 False


def test_stat_state_parsing_uses_last_paren():
    assert procutil._stat_state(b"123 (evil) Z x) S 1 2 3") == "S"
    assert procutil._stat_state(b"123 (openocd) Z 1 2 3") == "Z"
    assert procutil._stat_state(b"123 (a b) X") == "X"
    assert procutil._stat_state(b"garbage") is None
    assert procutil._stat_state(b"123 (x)") is None


def test_unreadable_proc_falls_back_to_kill_result(monkeypatch):
    monkeypatch.setattr(procutil, "_proc_state", lambda pid: None)  # /proc 없음(macOS 등)
    assert pid_alive(os.getpid()) is True


def test_openocd_uses_core_pid_alive():
    from openocd_mcp import process

    assert process.pid_alive is pid_alive
