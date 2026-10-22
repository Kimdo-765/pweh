"""고정 Windows 질의의 선택적 예산/취소 seam. 실제 프로세스·PnP는 실행하지 않는다."""
import io
import os
import signal
import subprocess
import traceback
from types import SimpleNamespace

import pytest

from pweh import hostenv, portidentity as I


@pytest.fixture
def fake(monkeypatch):
    state = SimpleNamespace(clock=100.0, calls=[], waits=[], kills=[], procs=[],
                            chunks=[b"synthetic", b""], read_hook=None, wait_hook=None, rc=0)
    monkeypatch.setattr(I.time, "monotonic", lambda: state.clock)
    monkeypatch.setattr(hostenv, "disabled_keys", lambda config: set())
    monkeypatch.setattr(hostenv, "powershell_path", lambda: "/synthetic/powershell.exe")
    original_read = os.read
    original_select = I.select.select

    class Proc:
        pid = 987654321
        returncode = None

        def __init__(self):
            rd, wr = os.pipe()
            os.close(wr)
            self.stdout = io.FileIO(rd, "rb")
            self.fd = rd

        def poll(self):
            return self.returncode

        def wait(self, timeout):
            state.waits.append(timeout)
            if state.wait_hook:
                state.wait_hook(self, timeout)
            if self.returncode is None:
                self.returncode = state.rc
            return self.returncode

    def launch(argv, **kwargs):
        state.calls.append((argv, kwargs))
        p = Proc()
        state.procs.append(p)
        return p

    def read(fd, n):
        if state.procs and fd == state.procs[-1].fd:
            if state.read_hook:
                state.read_hook()
            return state.chunks.pop(0)
        return original_read(fd, n)

    def select(r, w, x, timeout):
        if state.procs and r == [state.procs[-1].fd]:
            return r, [], []
        return original_select(r, w, x, timeout)

    def kill(pid, sig):
        assert pid == state.procs[-1].pid
        state.kills.append((pid, sig))
        state.procs[-1].returncode = -sig

    monkeypatch.setattr(I.subprocess, "Popen", launch)
    monkeypatch.setattr(I.os, "read", read)
    monkeypatch.setattr(I.select, "select", select)
    monkeypatch.setattr(I.os, "killpg", kill)
    yield state
    for p in state.procs:
        assert p.stdout.closed


def error(reason, fn):
    with pytest.raises(ValueError) as caught:
        fn()
    assert str(caught.value) == reason
    assert "PRIVATE" not in "".join(traceback.format_exception(caught.value))


def test_legacy_defaults_and_fixed_argv_environment(fake, monkeypatch):
    monkeypatch.setenv("PRIVATE_MODULE_PATH", "PRIVATE")
    monkeypatch.setenv("WSL_INTEROP", "/synthetic/interop")
    assert I._windows_output({}) == b"synthetic"
    argv, kw = fake.calls[0]
    assert argv == ["/synthetic/powershell.exe", "-NoProfile", "-NonInteractive", "-Command", I.PS_IDENTITIES]
    assert kw["stdin"] == subprocess.DEVNULL and kw["stderr"] == subprocess.DEVNULL
    assert kw["start_new_session"] and kw["bufsize"] == 0 and kw["cwd"] == "/"
    assert "PRIVATE_MODULE_PATH" not in kw["env"] and kw["env"]["WSL_INTEROP"] == "/synthetic/interop"
    assert fake.waits[-1] == 2 and not fake.kills


def test_explicit_scope_script_and_successful_cancel_checks(fake):
    checks = []
    def cancel():
        checks.append(1)
        return False
    assert I._windows_output(script=I.PS_USB_SCOPE, deadline=102, cancel=cancel) == b"synthetic"
    assert fake.calls[0][0][-1] == I.PS_USB_SCOPE and len(checks) >= 4
    assert all(0 <= value <= .1 for value in fake.waits[:-1])


@pytest.mark.parametrize("value", [None, True, "PRIVATE", float("nan"), float("inf"), 10**400])
def test_invalid_deadline_before_spawn(fake, value):
    if value is None:
        # 생략/None은 legacy 기본값이므로 별도 invalid sentinel을 사용한다.
        value = object()
    error("pnp_scope_input_limit", lambda: I._windows_output(deadline=value))
    assert fake.calls == []


@pytest.mark.parametrize("value", [100.0, 99.0])
def test_expired_deadline_before_spawn(fake, value):
    error("pnp_timeout_windows_child_unverified", lambda: I._windows_output(deadline=value))
    assert fake.calls == []


@pytest.mark.parametrize("kind,reason", [("true", "pnp_query_cancelled"), ("invalid", "pnp_query_callback_failed"),
                                       ("raise", "pnp_query_callback_failed"), ("nonbool", "pnp_query_callback_failed")])
def test_pre_spawn_cancel_is_closed(fake, kind, reason):
    def fail():
        raise ValueError("PRIVATE callback")
    callback = {"true": lambda: True, "invalid": 1, "raise": fail, "nonbool": lambda: 1}[kind]
    error(reason, lambda: I._windows_output(deadline=102, cancel=callback))
    assert not fake.calls


@pytest.mark.parametrize("deadline,end", [(None, 105.0), (120, 105.0), (101, 101.0)])
def test_shared_end_never_refreshes_during_read(fake, deadline, end):
    fake.read_hook = lambda: setattr(fake, "clock", end)
    error("pnp_timeout_windows_child_unverified", lambda: I._windows_output(deadline=deadline))
    assert fake.kills == [(fake.procs[0].pid, signal.SIGKILL)]
    assert fake.waits == [2]


def test_cancel_after_partial_read_discards_bytes_and_reaps(fake):
    cancelled = [False]
    fake.read_hook = lambda: cancelled.__setitem__(0, True)
    error("pnp_query_cancelled", lambda: I._windows_output(deadline=102, cancel=lambda: cancelled[0]))
    assert len(fake.calls) == 1 and fake.kills


def test_eof_wait_uses_cancel_and_same_deadline(fake):
    cancelled = [False]
    fake.chunks = [b""]
    def wait(p, timeout):
        if timeout != 2:
            cancelled[0] = True
            raise subprocess.TimeoutExpired("PRIVATE command", timeout)
    fake.wait_hook = wait
    error("pnp_query_cancelled", lambda: I._windows_output(deadline=101, cancel=lambda: cancelled[0]))
    assert fake.waits == [.1, 2] and fake.kills


def test_cancel_callback_cannot_spend_budget_then_return_success(fake):
    def cancel():
        fake.clock = 103
        return False
    error("pnp_timeout_windows_child_unverified", lambda: I._windows_output(deadline=102, cancel=cancel))
    assert not fake.calls


def test_output_limit_discards_entire_result(fake):
    fake.chunks = [b"x" * (I.MAX_OUTPUT + 1)]
    error("pnp_output_limit", lambda: I._windows_output(deadline=102))
    assert fake.kills


def test_nonzero_never_returns_partial_json(fake):
    fake.rc = 1
    fake.chunks = [b'{"PRIVATE":', b""]
    error("pnp_query_failed", lambda: I._windows_output(deadline=102))
    assert not fake.kills


def test_arbitrary_script_and_disabled_host_are_spawn_zero(fake, monkeypatch):
    untrusted_script = "PRIVATE command"
    error("pnp_script_not_allowed", lambda: I._windows_output(script=untrusted_script))
    monkeypatch.setattr(hostenv, "disabled_keys", lambda config: {"interop"})
    error("hostenv_disabled", lambda: I._windows_output(script=I.PS_USB_SCOPE))
    assert not fake.calls
