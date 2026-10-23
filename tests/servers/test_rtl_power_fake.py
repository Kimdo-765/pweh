"""실제 Linux 합성 child→bounded 두 pipe→종료 확인→실제 power parser 연결."""
from __future__ import annotations

import gc
import json
import os
from pathlib import Path
import subprocess
import sys
import threading
import time
from types import SimpleNamespace
import weakref

import pytest

from pweh import rf_power as R, rtl_power_plan as P

from .fake_rtl_power import CSV, TAIL

pytestmark = pytest.mark.skipif(not sys.platform.startswith("linux") or not hasattr(os, "WNOWAIT"),
                               reason="WNOWAIT를 사용하는 Linux 합성 자식 시험")
FAKE = Path(__file__).with_name("fake_rtl_power.py")


def end(seconds=5):
    return time.monotonic() + seconds


@pytest.fixture
def lab():
    patch = pytest.MonkeyPatch()
    procs, gates = [], []
    baseline = dict(P._OWNED)
    plan = P.build_power_plan(P.PowerSweepRequest(0, 100000000, 101000000, 10000, 1, 2))

    def factory(mode="normal", hook=None):
        def make(tail, **kwargs):
            assert tail == TAIL
            assert kwargs == dict(stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                  bufsize=0, start_new_session=True, close_fds=True)
            proc = subprocess.Popen([sys.executable, "-I", str(FAKE), mode, *tail], **kwargs)
            procs.append(proc)
            if hook is not None:
                hook(proc)
            return proc
        return make

    def run(mode="normal", *, deadline=None, cancel=None, hook=None):
        return P.run_power_plan_fake(plan, process_factory=factory(mode, hook),
                                     deadline=end() if deadline is None else deadline, cancel=cancel)

    yield SimpleNamespace(plan=plan, procs=procs, patch=patch, gates=gates, run=run, factory=factory)
    patch.undo()
    for gate in gates:
        gate.set()
    for key, owner in tuple(P._OWNED.items()):
        if key not in baseline:
            assert owner.close(deadline=end())
    assert P._OWNED == baseline
    for proc in procs:
        assert proc.returncode is not None
        assert proc.stdout.closed and proc.stderr.closed
        with pytest.raises(ChildProcessError):
            os.waitid(os.P_PID, proc.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)


@pytest.mark.parametrize("mode", ["normal", "fragmented", "crlf", "stderr", "stderr-exact", "fork-writer"])
def test_real_parser_after_confirmed_group_reader_stream_reap(lab, mode):
    inspect = R.inspect_power_csv
    deadline = end()
    seen = []

    def checked(data, *, deadline, cancel=None):
        assert type(data) is bytes
        assert data == (CSV.replace(b"\n", b"\r\n") if mode == "crlf" else CSV)
        assert not P._OWNED and lab.procs[0].returncode == 0
        assert lab.procs[0].stdout.closed and lab.procs[0].stderr.closed
        with pytest.raises(ChildProcessError):
            os.waitid(os.P_PID, lab.procs[0].pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)
        seen.append(deadline)
        return inspect(data, deadline=deadline, cancel=cancel)

    lab.patch.setattr(R, "inspect_power_csv", checked)
    report = lab.run(mode, deadline=deadline)
    assert seen == [deadline]
    assert set(report) == {"simulator_only", "hardware_verified", "inspection", "stdout_bytes", "stderr_bytes"}
    assert report["simulator_only"] is True and report["hardware_verified"] is False
    result = report["inspection"]
    assert result["status"] == "complete" and result["statistics"]["values_accepted"] == 4
    assert [r["power_centi_db"] for r in result["peaks"]] == [-2025, -2250, -2400]
    assert report["stdout_bytes"] == len(CSV) + (2 if mode == "crlf" else 0)
    assert report["stderr_bytes"] == ({"stderr": 27, "stderr-exact": 16384}.get(mode, 0))
    public = json.dumps(report)
    assert "2026-01-01" not in public and "PRIVATE" not in public and str(FAKE) not in public


@pytest.mark.parametrize("mode,stop", [
    ("truncated", "truncated_row"), ("long-line", "line_length_limit"),
    ("stdout-exact", "line_length_limit"),
])
def test_only_normal_child_can_return_parser_partial(lab, mode, stop):
    report = lab.run(mode)
    assert report["inspection"]["status"] == "partial"
    assert report["inspection"]["stop"]["code"] == stop
    assert not P._OWNED and lab.procs[0].returncode == 0


@pytest.mark.parametrize("mode,code", [
    ("stdout-limit", "output_limit"), ("stderr-limit", "output_limit"),
    ("nonzero", "failed"), ("stall", "timeout"), ("ignore-term", "timeout"),
])
def test_runner_failure_never_becomes_csv_partial(lab, mode, code):
    lab.patch.setattr(R, "inspect_power_csv", lambda *a, **k: pytest.fail("실패 뒤 parser 호출"))
    with pytest.raises(P.PowerFakeError) as caught:
        lab.run(mode, deadline=end(.35) if code == "timeout" else end())
    assert caught.value.code == "rf_power_fake_" + code
    assert caught.value.data == {} and "PRIVATE" not in str(caught.value)
    assert not P._OWNED


def test_cancellation_while_running_and_callback_failure(lab):
    lab.patch.setattr(R, "inspect_power_csv", lambda *a, **k: pytest.fail("실패 뒤 parser 호출"))
    started = time.monotonic()
    with pytest.raises(P.PowerFakeError, match="rf_power_fake_cancelled"):
        lab.run("stall", cancel=lambda: time.monotonic() - started > .1)

    def broken():
        if lab.procs and lab.procs[-1].returncode is None:
            raise ValueError("PRIVATE callback body")
        return False

    with pytest.raises(P.PowerFakeError, match="rf_power_fake_failed") as caught:
        lab.run("stall", cancel=broken)
    assert "PRIVATE" not in str(caught.value) and not P._OWNED


def test_parser_time_partial_uses_original_end_and_is_runner_timeout(lab):
    inspect = R.inspect_power_csv
    deadline = end()

    def expired(data, *, deadline, cancel=None):
        assert not P._OWNED
        assert deadline == expected
        report = inspect(data, deadline=time.monotonic() - 1, cancel=cancel)
        assert report["stop"]["code"] == "time_limit"
        return report

    expected = deadline
    lab.patch.setattr(R, "inspect_power_csv", expired)
    with pytest.raises(P.PowerFakeError, match="rf_power_fake_timeout"):
        lab.run(deadline=deadline)


def test_processing_end_is_not_renewed_after_cleanup(lab):
    original_close = P._FakeOwner.close
    deadline = end(.3)

    def delayed(self, *, deadline):
        result = original_close(self, deadline=deadline)
        time.sleep(.35)
        return result

    lab.patch.setattr(P._FakeOwner, "close", delayed)
    lab.patch.setattr(R, "inspect_power_csv", lambda *a, **k: pytest.fail("만료 뒤 parser 호출"))
    with pytest.raises(P.PowerFakeError, match="rf_power_fake_timeout"):
        lab.run(deadline=deadline)
    assert not P._OWNED


def test_late_cancel_after_parser_remains_failure(lab):
    state = {"cancel": False}
    inspect = R.inspect_power_csv

    def late(data, **kwargs):
        result = inspect(data, **kwargs)
        state["cancel"] = True
        return result

    lab.patch.setattr(R, "inspect_power_csv", late)
    with pytest.raises(P.PowerFakeError, match="rf_power_fake_cancelled"):
        lab.run(cancel=lambda: state["cancel"])


def test_callback_cannot_replace_reconstructed_argv(lab):
    def callback():
        object.__setattr__(lab.plan, "argv_tail", ("PRIVATE", "--unexpected"))
        return False

    result = lab.run(cancel=callback)
    assert result["inspection"]["status"] == "complete"


def test_factory_exception_is_fixed_and_no_owner_retained(lab):
    def broken(*a, **k):
        raise OSError("PRIVATE executable")

    with pytest.raises(P.PowerFakeError, match="rf_power_fake_failed") as caught:
        P.run_power_plan_fake(lab.plan, process_factory=broken, deadline=end())
    assert caught.value.data == {} and "PRIVATE" not in repr(caught.value) and not P._OWNED


@pytest.mark.parametrize("which", [1, 2])
def test_pipe_setup_failure_still_owns_and_closes_child(lab, which):
    original = os.set_blocking
    count = 0

    def failing(fd, blocking):
        nonlocal count
        count += 1
        if count == which:
            raise OSError("PRIVATE setup")
        return original(fd, blocking)

    lab.patch.setattr(P.os, "set_blocking", failing)
    with pytest.raises(P.PowerFakeError, match="rf_power_fake_failed"):
        lab.run("stall")
    assert not P._OWNED


def test_thread_start_failure_cleans_up(lab):
    lab.patch.setattr(P.threading.Thread, "start", lambda self: (_ for _ in ()).throw(RuntimeError("PRIVATE start")))
    with pytest.raises(P.PowerFakeError, match="rf_power_fake_failed"):
        lab.run("stall")
    assert not P._OWNED


def test_reader_failure_closes_without_parser(lab):
    read = os.read

    def hook(proc):
        target = proc.stdout.fileno()

        def broken(fd, size):
            if fd == target:
                raise OSError("PRIVATE read")
            return read(fd, size)

        lab.patch.setattr(P.os, "read", broken)

    with pytest.raises(P.PowerFakeError, match="rf_power_fake_failed"):
        lab.run(hook=hook)
    assert not P._OWNED


def test_unknown_group_is_strongly_retained_and_explicit_retry_only(lab):
    lab.patch.setattr(P.procutil, "process_group_empty", lambda *a, **k: None)
    lab.patch.setattr(R, "inspect_power_csv", lambda *a, **k: pytest.fail("unknown 뒤 parser 호출"))
    with pytest.raises(P.PowerFakeError, match="rf_power_fake_cleanup_unknown") as caught:
        lab.run()
    owner = caught.value.owner
    assert P._OWNED[id(owner)] is owner and not owner.confirmed
    assert owner._child_state() == "exited" and owner.proc.returncode is None
    assert "owner" not in caught.value.to_dict() and "PRIVATE" not in str(caught.value)
    ref, token = weakref.ref(owner), id(owner)
    del caught, owner
    gc.collect()
    assert ref() is P._OWNED[token]
    lab.patch.undo()
    assert ref().close(deadline=end()) and token not in P._OWNED
    assert len(lab.procs) == 1


def test_identity_failure_sends_no_signal_until_explicit_retry(lab):
    original_stat = P.procutil.proc_stat
    signals = []
    lab.patch.setattr(P.procutil, "proc_stat", lambda pid: None)
    signal_group = P.procutil.signal_owned_group
    lab.patch.setattr(P.procutil, "signal_owned_group", lambda *a, **k: signals.append(a) or signal_group(*a, **k))
    with pytest.raises(P.PowerFakeError, match="rf_power_fake_cleanup_unknown") as caught:
        lab.run("stall")
    assert not signals and P._OWNED[id(caught.value.owner)] is caught.value.owner
    lab.patch.setattr(P.procutil, "proc_stat", original_stat)
    assert caught.value.owner.close(deadline=end())
    assert signals


def test_reader_delay_preserves_owner_until_join_confirmed(lab):
    gate = threading.Event()
    lab.gates.append(gate)
    drain, close = P._FakeOwner._drain, P._FakeOwner.close

    def delayed(self):
        gate.wait(3)
        drain(self)

    lab.patch.setattr(P._FakeOwner, "_drain", delayed)
    lab.patch.setattr(P._FakeOwner, "close", lambda self, *, deadline: close(self, deadline=min(deadline, end(.05))))
    with pytest.raises(P.PowerFakeError, match="rf_power_fake_cleanup_unknown") as caught:
        lab.run()
    owner = caught.value.owner
    assert owner.thread.is_alive() and not owner.proc.stdout.closed and not owner.reaped
    gate.set()
    lab.patch.undo()
    assert owner.close(deadline=end()) and owner.reaped


def test_stream_close_failure_is_retryable_not_success(lab):
    close = P._close_stream
    lab.patch.setattr(P, "_close_stream", lambda stream: False)
    with pytest.raises(P.PowerFakeError, match="rf_power_fake_cleanup_unknown") as caught:
        lab.run()
    owner = caught.value.owner
    assert owner.group_confirmed and not owner.reaped and not owner.proc.stdout.closed
    lab.patch.setattr(P, "_close_stream", close)
    assert owner.close(deadline=end()) and owner.close(deadline=end())
