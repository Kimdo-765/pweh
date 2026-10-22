"""Linux Python 합성 자식의 pipe 수명·미확인 소유권 보존 회귀."""
from __future__ import annotations

import os
import signal
import sys
import threading
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

from openocd_mcp import process_pipe as pp
from pweh import procutil
from pweh.errors import ValidationFailed

pytestmark = pytest.mark.skipif(not sys.platform.startswith("linux"), reason="Linux WNOWAIT 합성 수명")
FAKE = Path(__file__).with_name("fake_openocd_pipe.py")


def wait_for(check, timeout=5):
    deadline = time.monotonic() + timeout
    while not check():
        assert time.monotonic() < deadline, "합성 자식 준비 시간 초과"
        time.sleep(0.01)


@pytest.fixture
def owners(tmp_path):
    made = []
    baseline = pp.owned_process_count()
    def spawn(mode="ready", *extra, **kw):
        owner = pp.spawn_pipe([sys.executable, "-I", str(FAKE), "--mode", mode, *map(str, extra)],
                              cwd=tmp_path, log_path=tmp_path / f"pipe-{len(made)}.log", **kw)
        made.append(owner)
        return owner
    yield spawn
    for owner in made:
        result = owner.close(grace=0.05, timeout=4)
        assert result.confirmed, result
    assert pp.owned_process_count() == baseline


def test_normal_eof_closes_streams_thread_pidfd_and_registry(owners):
    owner = owners()
    assert owner.wait_ready(timeout=5).ready
    result = owner.close(timeout=3)
    assert result.confirmed and result.method == "stdin-eof" and result.exit_code == 0
    assert owner._leader_reaped and owner._group_verified and owner._thread_done.is_set()
    assert owner._pidfd is None and owner._log.closed
    assert all(s.closed for s in (owner._proc.stdin, owner._proc.stdout, owner._proc.stderr))
    assert id(owner._proc) not in pp._OWNED
    assert owner.close(timeout=0.1) == result


@pytest.mark.parametrize("mode,method,exitcode", [("term-only", "terminated", -signal.SIGTERM),
                                                ("kill-only", "killed", -signal.SIGKILL)])
def test_term_kill_are_followed_by_confirmation(owners, mode, method, exitcode):
    owner = owners(mode)
    assert owner.wait_ready(timeout=5).ready
    result = owner.close(grace=0.05, timeout=3)
    assert result.confirmed and result.method == method and result.exit_code == exitcode


def test_leader_exit_kept_waitable_until_pipe_holding_group_is_gone(owners, tmp_path, monkeypatch):
    pid_path = tmp_path / "synthetic-child.pid"
    owner = owners("leader-exit-child-holds", "--pid-file", pid_path)
    wait_for(lambda: pid_path.exists() and owner._child_state() == "exited_waitable")
    child = int(pid_path.read_text())
    assert owner._proc.returncode is None
    events = []
    real_empty, real_waitpid = procutil.process_group_empty, os.waitpid
    with monkeypatch.context() as m:
        def empty(*a, **kw):
            value = real_empty(*a, **kw)
            events.append(("group", value))
            return value
        def reap(pid, options):
            assert owner._child_state() == "exited_waitable"
            assert ("group", True) in events
            events.append(("reap", pid))
            return real_waitpid(pid, options)
        m.setattr(procutil, "process_group_empty", empty)
        m.setattr(os, "waitpid", reap)
        result = owner.close(grace=0.05, timeout=4)
    assert result.confirmed and result.method == "killed" and result.exit_code == 0
    assert not procutil.pid_alive(child)
    assert events[-1] == ("reap", owner._proc.pid)


def test_unknown_group_keeps_waitable_leader_registry_then_retries(owners, monkeypatch):
    owner = owners()
    assert owner.wait_ready(timeout=5).ready
    with monkeypatch.context() as m:
        m.setattr(procutil, "process_group_empty", lambda *a, **kw: None)
        result = owner.close(grace=0.1, timeout=1)
        assert not result.confirmed and result.reason == "group_unknown"
        assert pp._OWNED[id(owner._proc)] is owner
        assert owner._proc.returncode is None and not owner._leader_reaped
        assert owner._child_state() == "exited_waitable"
    assert owner.close(timeout=3).confirmed


@pytest.mark.parametrize("state", ["unknown", "different_pid"])
def test_unknown_waitid_never_signals_or_reaps(owners, monkeypatch, state):
    owner = owners()
    assert owner.wait_ready(timeout=5).ready
    with monkeypatch.context() as m:
        def observe(*a):
            if state == "unknown":
                raise ChildProcessError
            return SimpleNamespace(si_pid=owner._proc.pid + 1)
        m.setattr(os, "waitid", observe)
        m.setattr(procutil, "signal_owned_group", lambda *a, **kw: pytest.fail("미확인 자식 신호"))
        m.setattr(os, "waitpid", lambda *a: pytest.fail("미확인 자식 reap"))
        result = owner.close(grace=0.01, timeout=0.2)
        assert not result.confirmed and pp._OWNED[id(owner._proc)] is owner
    assert owner.close(timeout=3).confirmed


def test_identity_change_refuses_signal_and_preserves_owner(owners, monkeypatch):
    owner = owners("kill-only")
    assert owner.wait_ready(timeout=5).ready
    with monkeypatch.context() as m:
        m.setattr(procutil, "proc_stat", lambda _: ("S", owner._ticks + 1))
        m.setattr(procutil, "signal_owned_group", lambda *a, **kw: pytest.fail("신원 변경 후 신호"))
        assert owner.close(timeout=0.2).reason == "identity_unknown"
        assert pp._OWNED[id(owner._proc)] is owner
    assert owner.close(grace=0.01, timeout=3).confirmed


def test_client_close_unknown_does_not_transfer_stream_ownership(owners, monkeypatch):
    owner = owners("term-only")
    assert owner.wait_ready(timeout=5).ready
    with monkeypatch.context() as m:
        m.setattr(owner.client, "close", lambda **kw: False)
        result = owner.close(grace=0.01, timeout=2)
        assert result.reason == "rpc_close_unverified" and not result.confirmed
        assert owner._group_verified and not owner._leader_reaped
        assert not owner._proc.stdin.closed and not owner._proc.stdout.closed
        assert pp._OWNED[id(owner._proc)] is owner
    assert owner.close(timeout=2).confirmed


def test_after_reap_cleanup_retry_never_signals_new_generation(owners, monkeypatch):
    owner = owners()
    assert owner.wait_ready(timeout=5).ready
    fd = owner._pidfd
    assert fd is not None
    real_close = os.close
    with monkeypatch.context() as m:
        def fail_pidfd(value):
            if value == fd:
                raise OSError("합성 pidfd close 실패")
            return real_close(value)
        m.setattr(os, "close", fail_pidfd)
        result = owner.close(timeout=3)
        assert result.reason == "pidfd_close_unverified"
        assert owner._leader_reaped and owner._proc.returncode == 0
        assert pp._OWNED[id(owner._proc)] is owner
    with monkeypatch.context() as m:
        m.setattr(procutil, "proc_stat", lambda *_: pytest.fail("reap 뒤 신원 재사용"))
        m.setattr(procutil, "signal_owned_group", lambda *a, **kw: pytest.fail("reap 뒤 그룹 신호"))
        assert owner.close(timeout=1).confirmed


def test_old_cleanup_does_not_remove_other_registry_generation(owners):
    owner = owners()
    assert owner.wait_ready(timeout=5).ready
    token = id(owner._proc)
    replacement = object()
    pp._OWNED[token] = replacement
    try:
        assert owner.close(timeout=3).confirmed
        assert pp._OWNED[token] is replacement
    finally:
        del pp._OWNED[token]


def test_close_lock_deadline_keeps_owner(owners):
    owner = owners()
    assert owner.wait_ready(timeout=5).ready
    owner._cleanup_lock.acquire()
    try:
        result = owner.close(timeout=0.05)
        assert not result.confirmed and result.reason == "cleanup_busy"
        assert pp._OWNED[id(owner._proc)] is owner
    finally:
        owner._cleanup_lock.release()
    assert owner.close(timeout=3).confirmed


def test_concurrent_close_has_one_reap_and_same_result(owners, monkeypatch):
    owner = owners("kill-only")
    assert owner.wait_ready(timeout=5).ready
    results = []
    calls = []
    original = os.waitpid
    def reap(*a):
        calls.append(a)
        return original(*a)
    with monkeypatch.context() as m:
        m.setattr(os, "waitpid", reap)
        threads = [threading.Thread(target=lambda: results.append(owner.close(grace=0.05, timeout=4))) for _ in range(2)]
        for thread in threads: thread.start()
        for thread in threads: thread.join(timeout=5)
    assert all(not t.is_alive() for t in threads)
    assert len(results) == 2 and all(r.confirmed for r in results) and results[0] == results[1]
    assert len(calls) == 1


@pytest.mark.parametrize("failure", ["client", "thread", "thread_after_start"])
def test_spawn_configuration_failure_cleans_same_owner(tmp_path, monkeypatch, failure):
    baseline = pp.owned_process_count()
    with monkeypatch.context() as m:
        if failure == "client":
            m.setattr(pp, "TclPipeClient", lambda *a, **kw: (_ for _ in ()).throw(ValueError("합성 client")))
        else:
            original = threading.Thread.start
            def fail(self):
                if failure == "thread_after_start":
                    original(self)
                raise RuntimeError("합성 thread start")
            m.setattr(threading.Thread, "start", fail)
        with pytest.raises(pp.PipeSpawnError) as exc:
            pp.spawn_pipe([sys.executable, "-I", str(FAKE), "--mode", "ready"],
                          cwd=tmp_path, log_path=tmp_path / "failed.log")
    owner = exc.value.owner
    try:
        assert owner._confirmed is not None and owner._confirmed.confirmed
        assert all(s.closed for s in (owner._proc.stdin, owner._proc.stdout, owner._proc.stderr))
        assert owner._leader_reaped and pp.owned_process_count() == baseline
    finally:
        assert owner.close(timeout=3).confirmed
    assert "합성" not in str(exc.value) and exc.value.to_dict().get("owner") is None


def test_spawn_failure_unknown_retains_owner_on_exception(tmp_path, monkeypatch):
    with monkeypatch.context() as m:
        m.setattr(pp, "TclPipeClient", lambda *a, **kw: (_ for _ in ()).throw(ValueError()))
        m.setattr(procutil, "process_group_empty", lambda *a, **kw: None)
        with pytest.raises(pp.PipeSpawnError) as exc:
            pp.spawn_pipe([sys.executable, "-I", str(FAKE), "--mode", "ready"],
                          cwd=tmp_path, log_path=tmp_path / "unknown.log")
        owner = exc.value.owner
        assert owner._confirmed is None and pp._OWNED[id(owner._proc)] is owner
    assert owner.close(timeout=3).confirmed


@pytest.mark.parametrize("value", [True, 0, -1, float("nan"), float("inf"), 10**400])
def test_invalid_close_args_do_not_abort_healthy_client(owners, value):
    owner = owners()
    assert owner.wait_ready(timeout=5).ready
    with pytest.raises(ValidationFailed):
        owner.close(timeout=value)
    assert not owner._closing.is_set() and owner.client.connected


def test_non_linux_is_rejected_before_any_spawn(tmp_path, monkeypatch):
    with monkeypatch.context() as m:
        m.setattr(pp.sys, "platform", "darwin")
        with pytest.raises(procutil.UnsupportedPlatform):
            pp.spawn_pipe([sys.executable], cwd=tmp_path, log_path=tmp_path / "absent.log",
                          process_factory=lambda *a, **kw: pytest.fail("지원 전 spawn"))
    assert not (tmp_path / "absent.log").exists()


def test_spawn_cleanup_exception_still_exposes_owned_retry_handle(tmp_path, monkeypatch):
    with monkeypatch.context() as m:
        m.setattr(pp, "TclPipeClient", lambda *a, **kw: (_ for _ in ()).throw(ValueError()))
        m.setattr(pp.PipeOpenOcdProcess, "close", lambda *a, **kw: (_ for _ in ()).throw(OSError()))
        with pytest.raises(pp.PipeSpawnError) as exc:
            pp.spawn_pipe([sys.executable, "-I", str(FAKE), "--mode", "ready"],
                          cwd=tmp_path, log_path=tmp_path / "cleanup-failed.log")
        owner = exc.value.owner
        assert pp._OWNED[id(owner._proc)] is owner
    assert owner.close(timeout=3).confirmed
