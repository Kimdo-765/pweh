"""새 pipe owner가 쓰는 Linux 신호/관찰 seam의 합성 실패 경계."""
from __future__ import annotations

import contextlib
import signal
import sys
from types import SimpleNamespace

import pytest

from pweh import procutil


@pytest.fixture
def group(monkeypatch):
    calls = []
    monkeypatch.setattr(procutil.sys, "platform", "linux")
    monkeypatch.setattr(procutil, "proc_stat", lambda pid: ("S", 10))
    monkeypatch.setattr(procutil.os, "getpgid", lambda pid: 424242)
    monkeypatch.setattr(procutil.os, "killpg", lambda pid, sig: calls.append((pid, sig)))
    return calls


def test_one_signal_has_no_wait_or_process_scan(group, monkeypatch):
    monkeypatch.setattr(procutil.time, "sleep", lambda *_: pytest.fail("신호 helper에서 대기"))
    monkeypatch.setattr(procutil.os, "scandir", lambda *_: pytest.fail("신호 helper에서 scan"))
    assert procutil.signal_owned_group(424242, signal.SIGTERM, expect_start_ticks=10) is True
    assert group == [(424242, signal.SIGTERM)]


@pytest.mark.parametrize("bad", [0, 1, -1, True, None, "424242"])
def test_invalid_group_never_signals(group, bad):
    assert procutil.signal_owned_group(bad, signal.SIGKILL, expect_start_ticks=10) is None
    assert group == []


@pytest.mark.parametrize("bad", [0, True, None, 9.5])
def test_invalid_ticks_never_signal(group, bad):
    assert procutil.signal_owned_group(424242, signal.SIGKILL, expect_start_ticks=bad) is None
    assert group == []


def test_identity_rechecked_immediately_before_signal(group, monkeypatch):
    samples = iter([("S", 10), ("S", 11)])
    monkeypatch.setattr(procutil, "proc_stat", lambda pid: next(samples))
    assert procutil.signal_owned_group(424242, signal.SIGTERM, expect_start_ticks=10) is None
    assert group == []


def test_permission_is_unknown_and_esrch_is_absent(group, monkeypatch):
    def denied(*_):
        raise PermissionError
    monkeypatch.setattr(procutil.os, "killpg", denied)
    assert procutil.signal_owned_group(424242, signal.SIGTERM, expect_start_ticks=10) is None
    def missing(*_):
        raise ProcessLookupError
    monkeypatch.setattr(procutil.os, "killpg", missing)
    assert procutil.signal_owned_group(424242, signal.SIGTERM, expect_start_ticks=10) is False


def test_unreadable_stat_not_absence_and_bad_pidfd_not_success(group, monkeypatch):
    monkeypatch.setattr(procutil, "proc_stat", lambda _: None)
    assert procutil.signal_owned_group(424242, signal.SIGTERM, expect_start_ticks=10) is None
    def missing(*_):
        raise ProcessLookupError
    monkeypatch.setattr(procutil.os, "getpgid", missing)
    assert procutil.signal_owned_group(424242, signal.SIGTERM, expect_start_ticks=10) is False
    assert group == []


def test_pidfd_only_probes_leader_and_group_receives_signal(group, monkeypatch):
    sent = []
    monkeypatch.setattr(procutil, "pidfd_signal", lambda fd, sig: sent.append((fd, sig)) or False)
    assert procutil.signal_owned_group(424242, signal.SIGKILL, expect_start_ticks=10, pidfd=7) is True
    assert sent == [(7, 0)] and group == [(424242, signal.SIGKILL)]


def test_unsupported_platform_never_signals(group, monkeypatch):
    monkeypatch.setattr(sys, "platform", "darwin")
    with pytest.raises(procutil.UnsupportedPlatform):
        procutil.signal_owned_group(424242, signal.SIGTERM, expect_start_ticks=10)
    assert group == []


@pytest.mark.parametrize("deadline", [True, float("nan"), float("inf"), "1", 10**400])
def test_group_deadline_validation(deadline):
    with pytest.raises(ValueError):
        procutil.process_group_empty(424242, expect_start_ticks=10, deadline=deadline)


def test_expired_deadline_does_not_observe_or_scan(monkeypatch):
    monkeypatch.setattr(procutil.time, "monotonic", lambda: 10.0)
    monkeypatch.setattr(procutil, "proc_stat", lambda _: pytest.fail("만료 뒤 신원 조회"))
    monkeypatch.setattr(procutil.os, "scandir", lambda _: pytest.fail("만료 뒤 scan"))
    assert procutil.process_group_empty(424242, expect_start_ticks=10, deadline=10) is None


def test_scan_respects_deadline_even_for_non_pid_entries(monkeypatch):
    clock = [10.0]
    monkeypatch.setattr(procutil.time, "monotonic", lambda: clock[0])
    monkeypatch.setattr(procutil, "proc_stat", lambda _: ("Z", 10))
    def entries():
        yield SimpleNamespace(name="cpuinfo")
        clock[0] += 0.2
        yield SimpleNamespace(name="meminfo")
        pytest.fail("deadline 뒤 순회 계속")
    monkeypatch.setattr(procutil.os, "scandir", lambda _: contextlib.nullcontext(entries()))
    assert procutil.process_group_empty(424242, expect_start_ticks=10, deadline=10.1) is None


def test_existing_two_second_cap_not_extended_by_caller(monkeypatch):
    clock = [10.0]
    monkeypatch.setattr(procutil.time, "monotonic", lambda: clock[0])
    monkeypatch.setattr(procutil, "proc_stat", lambda _: ("Z", 10))
    def entries():
        clock[0] += 2.1
        yield SimpleNamespace(name="cpuinfo")
    monkeypatch.setattr(procutil.os, "scandir", lambda _: contextlib.nullcontext(entries()))
    assert procutil.process_group_empty(424242, expect_start_ticks=10, deadline=100) is None
