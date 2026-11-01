"""고정 Windows 질의의 상주 작업자 protocol·예산/취소 seam. 실제 PowerShell·PnP 는 실행하지 않는다.

`fake` 는 가짜 Popen/stdio 와 고정 시계로 결정적으로 검사하고, `pyworker` 는 같은 틀을 말하는
Linux Python 자식(진짜 process group·pipe·EOF)으로 직렬화·종료·fork 를 검사한다.
"""
import io
import os
import re
import signal
import subprocess
import sys
import threading
import time
import traceback
from types import SimpleNamespace

import pytest

from pweh import hostenv, portidentity as I

FRAME = b"OK 9\nsynthetic"
_REAL_START_REAPER = I._start_reaper


@pytest.fixture
def fake(monkeypatch):
    state = SimpleNamespace(clock=100.0, calls=[], waits=[], kills=[], procs=[], writes=[], reapers=[],
                            reply=lambda proc, line: [FRAME], read_hook=None, hang=False, unkillable=False,
                            broken=False, launch_error=None)
    monkeypatch.setattr(I.time, "monotonic", lambda: state.clock)
    monkeypatch.setattr(hostenv, "disabled_keys", lambda config: set())
    monkeypatch.setattr(hostenv, "powershell_path", lambda: "/synthetic/powershell.exe")
    monkeypatch.setattr(I, "_MANAGER", I._WorkerManager())
    monkeypatch.setattr(I, "_start_reaper", lambda manager: state.reapers.append(manager))
    original_read = os.read
    original_select = I.select.select

    class Stdin:
        def __init__(self, proc):
            self.proc, self.closed = proc, False

        def write(self, data):
            if self.closed:
                raise ValueError("PRIVATE closed")
            if state.broken or self.proc.returncode is not None:
                raise BrokenPipeError(32, "PRIVATE pipe")
            state.writes.append((self.proc.pid, bytes(data)))
            self.proc.out.extend(state.reply(self.proc, bytes(data)))
            return len(data)

        def close(self):
            if not self.closed:
                self.closed = True
                # 작업자는 stdin EOF 에 exit 0 한다(hang 이면 무시하는 작업자).
                if self.proc.returncode is None and not state.hang:
                    self.proc.returncode = 0
                    self.proc.out.append(b"")

    class Proc:
        def __init__(self):
            rd, wr = os.pipe()
            os.close(wr)
            self.stdout = io.FileIO(rd, "rb")
            self.fd = rd
            self.pid = 900001 + len(state.procs)
            self.returncode = None
            self.out = []  # 응답 조각, b"" 는 EOF
            self.eof = False
            self.stdin = Stdin(self)

        def poll(self):
            return self.returncode

        def wait(self, timeout):
            state.waits.append((self.pid, timeout))
            if self.returncode is None:
                raise subprocess.TimeoutExpired("PRIVATE command", timeout)
            return self.returncode

    def live(fd):
        for p in state.procs:
            if p.fd == fd and not p.stdout.closed:
                return p
        return None

    def launch(argv, **kwargs):
        state.calls.append((argv, kwargs))
        if state.launch_error is not None:
            raise state.launch_error
        p = Proc()
        state.procs.append(p)
        return p

    def read(fd, n):
        p = live(fd)
        if p is None:
            return original_read(fd, n)
        if state.read_hook:
            state.read_hook(p)
        if p.eof:
            return b""
        if not p.out:
            raise BlockingIOError()
        chunk = p.out.pop(0)
        if chunk == b"":
            p.eof = True
            return b""
        if len(chunk) > n:
            p.out.insert(0, chunk[n:])
            chunk = chunk[:n]
        return chunk

    def select(r, w, x, timeout):
        p = live(r[0]) if len(r) == 1 else None
        if p is None:
            return original_select(r, w, x, timeout)
        if p.out or p.eof:
            return r, [], []
        state.clock += timeout  # 기다린 시간만큼 고정 시계를 움직인다.
        return [], [], []

    def kill(pid, sig):
        p = next(p for p in state.procs if p.pid == pid)
        assert p.returncode is None and sig == signal.SIGKILL
        state.kills.append((pid, sig))
        if not state.unkillable:
            p.returncode = -sig
            p.out.append(b"")

    monkeypatch.setattr(I.subprocess, "Popen", launch)
    monkeypatch.setattr(I.os, "read", read)
    monkeypatch.setattr(I.select, "select", select)
    monkeypatch.setattr(I.os, "killpg", kill)
    yield state
    worker = I._MANAGER.worker
    if worker is not None:
        state.unkillable = False
        I._stop_proc(worker.proc)
    for p in state.procs:
        assert p.stdout.closed and p.stdin.closed


def error(reason, fn, *, exact=True):
    with pytest.raises(ValueError) as caught:
        fn()
    # 소비자(openocd windows_usb._reason 등)는 정확한 ValueError 의 고정 문자열만 사유로 쓴다.
    assert str(caught.value) == reason and (type(caught.value) is ValueError or not exact)
    assert "PRIVATE" not in "".join(traceback.format_exception(caught.value))


# --- 작업자 문자열: 고정 상수로만 만들고 두 토큰만 고른다 ---------------------------------------------

def test_worker_script_is_built_only_from_fixed_constants():
    lib = I._PS_CM_LIB
    assert I.PS_IDENTITIES.startswith(lib) and I.PS_USB_SCOPE.startswith(lib)
    assert I._PS_WORKER == (lib + "\n$SBI={" + I.PS_IDENTITIES[len(lib):] + "};\n$SBS={" + I.PS_USB_SCOPE[len(lib):]
                            + "};\n" + I._PS_WORKER_LOOP)
    assert I._build_worker_script() == I._PS_WORKER
    assert I._PS_WORKER.count(lib) == 1 and "$ErrorActionPreference='Stop'" in I._PS_WORKER


def test_worker_dispatch_allows_exactly_two_tokens():
    loop = I._PS_WORKER_LOOP
    ordinal = r"\[string\]::Equals\(\$l,'([^']*)',\[StringComparison\]::Ordinal\)"
    assert re.findall(ordinal, I._PS_WORKER) == ["IDENT", "SCOPE"]
    assert loop.count("[StringComparison]::") == 2 and "else{exit 3}" in loop and "if($null -eq $l){exit 0}" in loop
    # 문화권 비교 연산자(-ceq/-eq/-like/-match …)로 입력 줄을 토큰과 비교하지 않는다(NUL·soft hyphen 을 무시함).
    assert re.findall(r"-[a-z]+\s+\$l\b", loop) == ["-eq $l"] and not re.search(r"\$l\s+-[a-z]", loop)
    assert "-ceq" not in loop and "-like" not in loop and "-match" not in loop
    # 입력 줄은 읽기·null·두 토큰 비교에만 쓰인다(코드로 실행하거나 출력에 넣지 않는다).
    assert len(re.findall(r"\$l\b", I._PS_WORKER)) == 4 and loop.count("ReadLine()") == 1
    for use in ("$l=[Console]::In.ReadLine()", "$null -eq $l)", "Equals($l,'IDENT',", "Equals($l,'SCOPE',"):
        assert loop.count(use) == 1
    assert loop.count("& $") == 2 and "& $SBI" in loop and "& $SBS" in loop
    for bad in ("Invoke-Expression", "iex ", "ScriptBlock]::Create", "Add-Type", ".Invoke(", "& $l"):
        assert bad not in loop
    assert "'OK '+$p.Length" in loop and "$O.Flush()" in loop


# --- 기본 경로·allowlist·토큰 ----------------------------------------------------------------------

def test_legacy_defaults_and_fixed_argv_environment(fake, monkeypatch):
    monkeypatch.setenv("PRIVATE_MODULE_PATH", "PRIVATE")
    monkeypatch.setenv("WSL_INTEROP", "/synthetic/interop")
    assert I._windows_output({}) == b"synthetic"
    argv, kw = fake.calls[0]
    assert argv == ["/synthetic/powershell.exe", "-NoProfile", "-NonInteractive", "-Command", I._PS_WORKER]
    assert kw["stdin"] == subprocess.PIPE and kw["stdout"] == subprocess.PIPE and kw["stderr"] == subprocess.DEVNULL
    assert kw["start_new_session"] and kw["bufsize"] == 0 and kw["cwd"] == "/"
    assert "PRIVATE_MODULE_PATH" not in kw["env"] and kw["env"]["WSL_INTEROP"] == "/synthetic/interop"
    assert fake.writes == [(fake.procs[0].pid, b"IDENT\n")]
    assert not fake.kills and not fake.waits and I._MANAGER.worker.proc is fake.procs[0]
    assert fake.reapers == [I._MANAGER]


def test_explicit_scope_token_and_successful_cancel_checks(fake):
    checks = []

    def cancel():
        checks.append(1)
        return False
    assert I._windows_output(script=I.PS_USB_SCOPE, deadline=102, cancel=cancel) == b"synthetic"
    assert fake.writes == [(fake.procs[0].pid, b"SCOPE\n")] and len(checks) >= 4


def test_worker_reused_and_each_request_is_a_new_observation(fake):
    seen = []

    def reply(proc, line):
        seen.append(line)
        body = b'{"n":%d}' % len(seen)
        return [b"OK %d\n" % len(body) + body]
    fake.reply = reply
    out = [I._windows_output(script=s, deadline=102)
           for s in (I.PS_IDENTITIES, I.PS_USB_SCOPE, I.PS_IDENTITIES)]
    assert out == [b'{"n":1}', b'{"n":2}', b'{"n":3}']
    assert seen == [b"IDENT\n", b"SCOPE\n", b"IDENT\n"] and len(fake.calls) == 1 and not fake.kills


@pytest.mark.parametrize("value", [None, True, "PRIVATE", float("nan"), float("inf"), 10**400])
def test_invalid_deadline_before_spawn(fake, value):
    if value is None:
        # 생략/None은 legacy 기본값이므로 별도 invalid sentinel을 사용한다.
        value = object()
    error("pnp_scope_input_limit", lambda: I._windows_output(deadline=value), exact=False)
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


def test_cancel_callback_cannot_spend_budget_then_return_success(fake):
    def cancel():
        fake.clock = 103
        return False
    error("pnp_timeout_windows_child_unverified", lambda: I._windows_output(deadline=102, cancel=cancel))
    assert not fake.calls


@pytest.mark.parametrize("script", ["PRIVATE command", I.PS_IDENTITIES.encode(), [I.PS_USB_SCOPE], I._PS_WORKER, ""])
def test_arbitrary_script_is_spawn_zero(fake, script):
    error("pnp_script_not_allowed", lambda: I._windows_output(script=script))
    assert not fake.calls


def test_disabled_host_and_missing_backend_are_spawn_zero(fake, monkeypatch):
    monkeypatch.setattr(hostenv, "disabled_keys", lambda config: {"interop"})
    error("hostenv_disabled", lambda: I._windows_output(script=I.PS_USB_SCOPE))
    monkeypatch.setattr(hostenv, "disabled_keys", lambda config: set())
    monkeypatch.setattr(hostenv, "powershell_path", lambda: None)
    error("pnp_backend_unavailable", lambda: I._windows_output(script=I.PS_USB_SCOPE))
    assert not fake.calls


@pytest.mark.parametrize("kind", ["disabled", "backend"])
def test_disable_or_missing_backend_stops_live_worker(fake, monkeypatch, kind):
    """이미 뜬 작업자가 있어도 호출마다 disable 키·backend 를 다시 보고, 걸리면 그 유휴 작업자를 바로 내린다."""
    assert I._windows_output(deadline=102) == b"synthetic"
    pid = fake.procs[0].pid
    if kind == "disabled":
        monkeypatch.setattr(hostenv, "disabled_keys", lambda config: {"serial_helper"})
        error("hostenv_disabled", lambda: I._windows_output(deadline=102))
    else:
        monkeypatch.setattr(hostenv, "powershell_path", lambda: None)
        error("pnp_backend_unavailable", lambda: I._windows_output(deadline=102))
    assert fake.kills == [(pid, signal.SIGKILL)] and fake.waits == [(pid, 2.0)] and I._MANAGER.worker is None
    assert len(fake.writes) == 1 and len(fake.calls) == 1
    assert fake.procs[0].stdin.closed and fake.procs[0].stdout.closed


def test_disable_during_in_flight_request_leaves_that_worker(fake, monkeypatch):
    """lock 을 기다리지 않는다: 진행 중 요청(꺼지기 전 검사 통과)의 작업자는 건드리지 않고, 다음 꺼진 호출이 내린다."""
    disabled = set()
    monkeypatch.setattr(hostenv, "disabled_keys", lambda config: set(disabled))
    seen = []

    def hook(proc):
        if not seen:
            disabled.add("interop")
            seen.append(1)
            error("hostenv_disabled", lambda: I._windows_output(deadline=102))
    fake.read_hook = hook
    assert I._windows_output(deadline=102) == b"synthetic"
    assert not fake.kills and I._MANAGER.worker.proc is fake.procs[0]
    fake.read_hook = None
    error("hostenv_disabled", lambda: I._windows_output(deadline=102))
    assert fake.kills == [(fake.procs[0].pid, signal.SIGKILL)] and I._MANAGER.worker is None
    assert len(fake.writes) == 1 and len(fake.calls) == 1


def test_spawn_failure_is_fixed_code(fake):
    fake.launch_error = FileNotFoundError(2, "PRIVATE path")
    error("pnp_query_failed", lambda: I._windows_output(deadline=102))
    assert I._MANAGER.worker is None


# --- 진행 중 요청의 예산·취소·종료 ------------------------------------------------------------------

# 틀 전체가 읽기 한 번에 오는 경우(마지막 읽기 뒤 tick 만 막는다)와 두 번에 나눠 오는 경우.
READS = pytest.mark.parametrize("chunks", [[FRAME], [b"OK 9\nsyn", b"thetic"]], ids=["one-read", "two-reads"])


@READS
@pytest.mark.parametrize("deadline,end", [(None, 105.0), (120, 105.0), (101, 101.0)])
def test_shared_end_never_refreshes_during_read(fake, deadline, end, chunks):
    fake.reply = lambda proc, line: list(chunks)
    fake.read_hook = lambda proc: setattr(fake, "clock", end)
    error("pnp_timeout_windows_child_unverified", lambda: I._windows_output(deadline=deadline))
    pid = fake.procs[0].pid
    assert fake.kills == [(pid, signal.SIGKILL)] and fake.waits == [(pid, 2.0)]
    assert I._MANAGER.worker is None


def test_timeout_while_waiting_for_reply_kills_group(fake):
    fake.reply = lambda proc, line: []
    error("pnp_timeout_windows_child_unverified", lambda: I._windows_output(deadline=101))
    assert fake.kills == [(fake.procs[0].pid, signal.SIGKILL)] and fake.clock >= 101


@READS
def test_cancel_during_read_discards_bytes_and_reaps(fake, chunks):
    cancelled = [False]
    fake.reply = lambda proc, line: list(chunks)
    fake.read_hook = lambda proc: cancelled.__setitem__(0, True)
    error("pnp_query_cancelled", lambda: I._windows_output(deadline=102, cancel=lambda: cancelled[0]))
    pid = fake.procs[0].pid
    assert len(fake.calls) == 1 and fake.kills == [(pid, signal.SIGKILL)] and fake.waits == [(pid, 2.0)]
    assert I._MANAGER.worker is None


def test_cancel_while_waiting_for_reply_uses_same_deadline(fake):
    fake.reply = lambda proc, line: []
    checks = []

    def cancel():
        checks.append(fake.clock)
        return len(checks) > 5
    error("pnp_query_cancelled", lambda: I._windows_output(deadline=101, cancel=cancel))
    assert fake.kills and fake.waits == [(fake.procs[0].pid, 2.0)] and fake.clock < 101


@pytest.mark.parametrize("kind", ["raise", "nonbool"])
def test_callback_failure_mid_request_kills(fake, kind):
    def cancel():
        if fake.writes:  # 토큰을 보낸 뒤
            if kind == "raise":
                raise RuntimeError("PRIVATE callback")
            return "PRIVATE"
        return False
    fake.reply = lambda proc, line: []
    error("pnp_query_callback_failed", lambda: I._windows_output(deadline=102, cancel=cancel))
    assert fake.kills and I._MANAGER.worker is None


@pytest.mark.parametrize("chunks", [
    [b'OK 20\n{"PRIVATE":', b""],          # 틀 중간 EOF
    [b"OK 9\n", b""],                      # 머리만 오고 EOF
    [b""],                                 # 응답 전 EOF
])
def test_eof_mid_request_never_returns_partial_json(fake, chunks):
    fake.reply = lambda proc, line: list(chunks)
    error("pnp_query_failed", lambda: I._windows_output(deadline=102))
    assert fake.kills == [(fake.procs[0].pid, signal.SIGKILL)] and I._MANAGER.worker is None


def test_exit_mid_request_is_query_failed(fake):
    def reply(proc, line):
        proc.returncode = 1  # 본문의 throw 로 작업자가 끝남
        return [b'OK 20\n{"PRIVATE":', b""]
    fake.reply = reply
    error("pnp_query_failed", lambda: I._windows_output(deadline=102))
    assert not fake.kills and fake.waits == [(fake.procs[0].pid, 2.0)]


def test_write_to_dead_pipe_is_query_failed(fake):
    assert I._windows_output(deadline=102) == b"synthetic"
    fake.broken = True
    error("pnp_query_failed", lambda: I._windows_output(deadline=102))
    assert fake.kills == [(fake.procs[0].pid, signal.SIGKILL)] and I._MANAGER.worker is None


# --- 비동기화·상한: 다시 맞추지 않고 죽인다 ------------------------------------------------------------

@pytest.mark.parametrize("chunks", [
    [FRAME + b"!"],                         # 같은 조각 안의 남는 바이트
    [FRAME, b"!"],                          # 틀 뒤에 따로 온 바이트
    [FRAME + b"OK 9\nsynthetic"],           # 두 번째 틀
    [b"NO 9\nsynthetic"], [b"ok 9\nsynthetic"], [b"OK 09\nsynthetic"], [b"OK +9\nsynthetic"],
    [b"OK -1\n"], [b"OK 9 \nsynthetic"], [b" OK 9\nsynthetic"], [b"OK \n"], [b"OK 9\r\nsynthetic"],
    [b"OK 1e3\n"], ["OK ٩\n".encode()], [b"\nsynthetic"],
    [b"OK " + b"1" * 20], [b"X" * 17], [b"OK 0000000000000009\nsynthetic"],
])
def test_desync_or_bad_header_kills_with_fixed_code(fake, chunks):
    fake.reply = lambda proc, line: list(chunks)
    error("pnp_query_failed", lambda: I._windows_output(deadline=102))
    assert fake.kills == [(fake.procs[0].pid, signal.SIGKILL)] and I._MANAGER.worker is None


@pytest.mark.parametrize("declared", [I.MAX_OUTPUT + 1, 10**12])
def test_oversize_declared_length_is_output_limit(fake, declared):
    fake.reply = lambda proc, line: [b"OK %d\n" % declared, b"x" * 100]
    error("pnp_output_limit", lambda: I._windows_output(deadline=102))
    assert fake.kills and I._MANAGER.worker is None


def test_exact_output_limit_is_accepted_in_chunks(fake):
    body = b"x" * I.MAX_OUTPUT
    fake.reply = lambda proc, line: [b"OK %d\n" % len(body) + body]
    assert I._windows_output(deadline=102) == body
    assert not fake.kills and I._MANAGER.worker is not None


def test_empty_payload_frame_is_returned(fake):
    fake.reply = lambda proc, line: [b"OK 0\n"]
    assert I._windows_output(deadline=102) == b""


def test_reap_timeout_does_not_replace_error_code(fake):
    fake.unkillable = True
    fake.reply = lambda proc, line: [b"NO\n"]
    error("pnp_query_failed", lambda: I._windows_output(deadline=102))
    pid = fake.procs[0].pid
    assert fake.kills == [(pid, signal.SIGKILL)] and fake.waits == [(pid, 2.0)] and I._MANAGER.worker is None
    fake.procs[0].returncode = -9


# --- 다시 띄우기·재사용 전 검사 -------------------------------------------------------------------

def test_next_call_respawns_after_failure(fake):
    replies = iter([[b"NO\n"], [FRAME]])
    fake.reply = lambda proc, line: next(replies)
    error("pnp_query_failed", lambda: I._windows_output(deadline=102))
    assert I._windows_output(deadline=102) == b"synthetic"
    assert len(fake.calls) == 2 and fake.kills == [(fake.procs[0].pid, signal.SIGKILL)]
    assert I._MANAGER.worker.proc is fake.procs[1]


def test_stray_bytes_while_idle_force_fresh_worker(fake):
    assert I._windows_output(deadline=102) == b"synthetic"
    fake.procs[0].out.append(b"OK 9\nPRIVATE!!")  # 요청 없이 온 바이트: 다음 응답으로 읽지 않는다
    assert I._windows_output(deadline=102) == b"synthetic"
    assert len(fake.calls) == 2 and fake.kills == [(fake.procs[0].pid, signal.SIGKILL)]
    assert [w[0] for w in fake.writes] == [fake.procs[0].pid, fake.procs[1].pid]


def test_worker_exit_while_idle_respawns_quietly(fake):
    assert I._windows_output(deadline=102) == b"synthetic"
    fake.procs[0].returncode = 0
    fake.procs[0].out.append(b"")
    assert I._windows_output(deadline=102) == b"synthetic"
    assert len(fake.calls) == 2 and not fake.kills and fake.waits == [(fake.procs[0].pid, 2.0)]


def test_changed_spawn_environment_gets_fresh_worker(fake, monkeypatch):
    assert I._windows_output(deadline=102) == b"synthetic"
    monkeypatch.setenv("WSL_INTEROP", "/synthetic/other-interop")
    assert I._windows_output(deadline=102) == b"synthetic"
    assert len(fake.calls) == 2 and fake.calls[1][1]["env"]["WSL_INTEROP"] == "/synthetic/other-interop"


# --- 수명: 유휴 종료·lock·pid ---------------------------------------------------------------------

def test_idle_shutdown_closes_stdin_then_respawns(fake):
    assert I._windows_output(deadline=102) == b"synthetic"
    manager, proc = I._MANAGER, fake.procs[0]
    fake.clock += I._WORKER_IDLE_S - 1
    assert manager.reap_idle() is False and manager.worker.proc is proc
    fake.clock += 2
    assert manager.reap_idle() is True and manager.worker is None and not manager.reaper
    assert proc.stdin.closed and proc.returncode == 0 and not fake.kills
    assert fake.waits == [(proc.pid, I._WORKER_GRACE_S), (proc.pid, 2.0)]
    assert I._windows_output(deadline=fake.clock + 2) == b"synthetic"
    assert len(fake.calls) == 2 and fake.reapers == [manager, manager]


def test_idle_shutdown_kills_worker_that_ignores_eof(fake):
    assert I._windows_output(deadline=102) == b"synthetic"
    fake.hang = True
    fake.clock += I._WORKER_IDLE_S
    assert I._MANAGER.reap_idle() is True
    assert fake.kills == [(fake.procs[0].pid, signal.SIGKILL)] and fake.procs[0].returncode == -9


def test_idle_check_skips_busy_or_missing_worker(fake):
    manager = I._MANAGER
    manager.reaper = True
    assert manager.reap_idle() is True and manager.reaper is False  # 작업자 없음 → 감시 끝
    assert I._windows_output(deadline=102) == b"synthetic"
    fake.clock += I._WORKER_IDLE_S * 2
    with manager.lock:
        assert manager.reap_idle() is False  # 요청 중에는 내리지 않는다
    assert manager.worker is not None and not fake.kills


def test_used_time_refreshes_only_after_successful_request(fake):
    assert I._windows_output(deadline=102) == b"synthetic"
    fake.clock = 100 + I._WORKER_IDLE_S - 1
    assert I._windows_output(deadline=fake.clock + 2) == b"synthetic"
    fake.clock += 2
    assert I._MANAGER.reap_idle() is False


def test_lock_wait_counts_against_deadline_without_spawn(fake):
    def cancel():
        fake.clock += .5
        return False
    with I._MANAGER.lock:
        error("pnp_timeout_windows_child_unverified", lambda: I._windows_output(deadline=102, cancel=cancel))
    assert not fake.calls


def test_lock_waiter_cancel_is_noticed_promptly(fake):
    """lock 대기는 deadline 까지 한 번에 자지 않고 짧은 주기로 취소를 본다. 고정 시계는 멈춰 있으므로 실제 시간으로 잰다."""
    start = time.perf_counter()
    with I._MANAGER.lock:
        error("pnp_query_cancelled",
              lambda: I._windows_output(deadline=104, cancel=lambda: time.perf_counter() - start > 0.1))
    assert time.perf_counter() - start < 1.0
    assert not fake.calls and not fake.writes


def test_waiter_cancel_does_not_touch_in_flight_worker(fake):
    assert I._windows_output(deadline=102) == b"synthetic"
    checks = []
    with I._MANAGER.lock:
        error("pnp_query_cancelled",
              lambda: I._windows_output(deadline=102, cancel=lambda: checks.append(1) or len(checks) > 3))
    assert I._MANAGER.worker.proc is fake.procs[0] and not fake.kills and len(fake.writes) == 1


def test_pid_change_gets_new_lock_and_worker_without_killing_parent(fake, monkeypatch):
    assert I._windows_output(deadline=102) == b"synthetic"
    parent, proc = I._MANAGER, fake.procs[0]
    child_pid = parent.pid + 1
    monkeypatch.setattr(I, "_current_pid", lambda: child_pid)
    I._shutdown_worker()  # 자식의 atexit 은 부모의 작업자를 건드리지 않는다
    assert parent.worker.proc is proc and not proc.stdin.closed
    parent.lock.acquire()  # fork 순간 다른 thread 가 잡고 있던 lock
    try:
        assert I._windows_output(deadline=102) == b"synthetic"
    finally:
        parent.lock.release()
    assert I._MANAGER is not parent and I._MANAGER.pid == child_pid and I._MANAGER.lock is not parent.lock
    assert len(fake.calls) == 2 and I._MANAGER.worker.proc is fake.procs[1]
    # 부모 pipe 사본만 닫고 죽이거나 수거하지 않는다.
    assert proc.stdin.closed and proc.stdout.closed
    assert not fake.kills and all(w[0] != proc.pid for w in fake.waits)
    assert parent.worker is None


def test_after_fork_hook_abandons_without_kill(fake):
    assert I._windows_output(deadline=102) == b"synthetic"
    parent, proc = I._MANAGER, fake.procs[0]
    I._after_fork_in_child()
    assert I._MANAGER is not parent and I._MANAGER.worker is None
    assert proc.stdin.closed and proc.stdout.closed and not fake.kills and not fake.waits


def test_shutdown_kills_own_worker(fake):
    assert I._windows_output(deadline=102) == b"synthetic"
    I._shutdown_worker()
    pid = fake.procs[0].pid
    assert fake.kills == [(pid, signal.SIGKILL)] and fake.waits == [(pid, 2.0)] and I._MANAGER.worker is None


# --- 진짜 자식 프로세스(Linux Python 이 같은 틀을 말함): 직렬화·종료·fork --------------------------------

EMULATOR = r'''
import os, select, sys, time
mode = sys.argv[1]
def line():
    data = b""
    while not data.endswith(b"\n"):
        ch = os.read(0, 1)
        if not ch:
            if mode == "sticky":  # EOF 를 무시하는 작업자: SIGKILL 로만 끝난다
                time.sleep(60)
            sys.exit(0)
        data += ch
    return data[:-1]
while True:
    token = line()
    if token not in (b"IDENT", b"SCOPE"):
        sys.exit(3)
    if mode == "hang":
        time.sleep(60)
    if mode == "slow":
        time.sleep(0.3)
    body = b'{"token": "' + token + b'", "pid": ' + str(os.getpid()).encode() + b'}'
    if select.select([0], [], [], 0)[0]:
        body = b'"OVERLAP"'
    os.write(1, b"OK %d\n" % len(body) + body)
'''


@pytest.fixture
def pyworker(monkeypatch):
    state = SimpleNamespace(mode="ok", procs=[])
    monkeypatch.setattr(hostenv, "disabled_keys", lambda config: set())
    monkeypatch.setattr(hostenv, "powershell_path", lambda: "/synthetic/powershell.exe")
    monkeypatch.setattr(I, "_MANAGER", I._WorkerManager())
    monkeypatch.setattr(I, "_start_reaper", lambda manager: None)
    original = subprocess.Popen

    def launch(argv, **kwargs):
        assert argv == ["/synthetic/powershell.exe", "-NoProfile", "-NonInteractive", "-Command", I._PS_WORKER]
        p = original([sys.executable, "-I", "-c", EMULATOR, state.mode], **kwargs)
        state.procs.append(p)
        return p
    monkeypatch.setattr(I.subprocess, "Popen", launch)
    yield state
    worker = I._MANAGER.worker
    if worker is not None:
        I._stop_proc(worker.proc)
    for p in state.procs:
        if p.poll() is None:
            os.killpg(p.pid, signal.SIGKILL)
            p.wait(timeout=2)
        for stream in (p.stdin, p.stdout):
            stream.close()


def _json(raw):
    import json
    return json.loads(raw)


def test_real_child_reuse_and_roundtrip(pyworker):
    first = _json(I._windows_output(script=I.PS_USB_SCOPE))
    second = _json(I._windows_output(script=I.PS_IDENTITIES))
    assert first == {"token": "SCOPE", "pid": pyworker.procs[0].pid}
    assert second == {"token": "IDENT", "pid": pyworker.procs[0].pid} and len(pyworker.procs) == 1


def test_real_child_concurrent_callers_serialize(pyworker):
    pyworker.mode = "slow"
    results, errors = [], []

    def call():
        try:
            results.append(_json(I._windows_output(script=I.PS_USB_SCOPE)))
        except Exception as exc:  # pragma: no cover - 실패 진단용
            errors.append(exc)
    threads = [threading.Thread(target=call) for _ in range(4)]
    start = time.monotonic()
    for t in threads:
        t.start()
    for t in threads:
        t.join(10)
    assert not errors and len(results) == 4 and all(r != "OVERLAP" for r in results)
    assert time.monotonic() - start >= 4 * 0.3 and len(pyworker.procs) == 1


def test_real_child_lock_waiter_deadline_spares_in_flight_request(pyworker):
    pyworker.mode = "slow"
    I._windows_output(script=I.PS_USB_SCOPE)  # 작업자 준비
    done = []
    holder = threading.Thread(target=lambda: done.append(_json(I._windows_output(script=I.PS_USB_SCOPE))))
    holder.start()
    time.sleep(0.05)
    start = time.monotonic()
    error("pnp_timeout_windows_child_unverified",
          lambda: I._windows_output(script=I.PS_USB_SCOPE, deadline=time.monotonic() + 0.1))
    assert time.monotonic() - start < 0.3
    holder.join(5)
    assert done == [{"token": "SCOPE", "pid": pyworker.procs[0].pid}] and pyworker.procs[0].poll() is None


def test_real_child_timeout_kills_group_and_next_call_recovers(pyworker):
    pyworker.mode = "hang"
    start = time.monotonic()
    error("pnp_timeout_windows_child_unverified",
          lambda: I._windows_output(script=I.PS_USB_SCOPE, deadline=time.monotonic() + 0.3))
    assert time.monotonic() - start < 2.5
    assert pyworker.procs[0].returncode == -signal.SIGKILL and I._MANAGER.worker is None
    pyworker.mode = "ok"
    assert _json(I._windows_output(script=I.PS_USB_SCOPE))["pid"] == pyworker.procs[1].pid


def test_real_child_garbage_token_exits_and_next_call_recovers(pyworker):
    I._windows_output(script=I.PS_USB_SCOPE)
    proc = I._MANAGER.worker.proc
    with I._MANAGER.lock:
        proc.stdin.write(b"BOGUS\n")
    assert proc.wait(timeout=5) == 3
    assert _json(I._windows_output(script=I.PS_IDENTITIES)) == {"token": "IDENT", "pid": pyworker.procs[1].pid}


def test_real_child_idle_reaper_closes_stdin(pyworker, monkeypatch):
    monkeypatch.setattr(I, "_WORKER_IDLE_S", 0.2)
    monkeypatch.setattr(I, "_start_reaper", _REAL_START_REAPER)
    I._windows_output(script=I.PS_USB_SCOPE)
    proc = pyworker.procs[0]
    deadline = time.monotonic() + 5
    while (I._MANAGER.worker is not None or proc.poll() is None) and time.monotonic() < deadline:
        time.sleep(0.02)
    # 정상 종료(stdin EOF → exit 0)이며 SIGKILL 이 아니다.
    assert I._MANAGER.worker is None and proc.returncode == 0 and not I._MANAGER.reaper



@pytest.mark.skipif(not hasattr(os, "fork"), reason="fork 없음")
def test_real_fork_child_never_reuses_parent_pipes(pyworker):
    I._windows_output(script=I.PS_USB_SCOPE)
    proc = I._MANAGER.worker.proc
    fds = (proc.stdin.fileno(), proc.stdout.fileno())
    pid = os.fork()
    if pid == 0:  # pragma: no cover - 자식 프로세스
        ok = I._MANAGER.worker is None and I._MANAGER.pid == os.getpid()
        for fd in fds:
            try:
                os.fstat(fd)
                ok = False
            except OSError:
                pass
        I._shutdown_worker()
        os._exit(0 if ok else 1)
    _, status = os.waitpid(pid, 0)
    assert os.waitstatus_to_exitcode(status) == 0
    # 자식이 끝나도 부모 작업자는 그대로 쓰인다.
    assert _json(I._windows_output(script=I.PS_IDENTITIES))["pid"] == proc.pid and proc.poll() is None


_ATEXIT_CHILD = r'''
import subprocess, sys
from pweh import hostenv, portidentity as I
hostenv.powershell_path = lambda: "/synthetic/powershell.exe"
hostenv.disabled_keys = lambda config: set()
original = subprocess.Popen
def launch(argv, **kwargs):
    assert argv[-1] == I._PS_WORKER
    return original([sys.executable, "-I", "-c", sys.argv[1], "sticky"], **kwargs)
subprocess.Popen = launch
I._windows_output(script=I.PS_USB_SCOPE)
print(I._MANAGER.worker.proc.pid, flush=True)
'''


def test_real_atexit_kills_worker_that_ignores_eof():
    """서버가 정상 종료하면 atexit 이 작업자 process group 을 끝낸다(EOF 를 무시하는 작업자로 확인)."""
    out = subprocess.run([sys.executable, "-c", _ATEXIT_CHILD, EMULATOR], capture_output=True, timeout=30)
    assert out.returncode == 0, out.stderr.decode("utf-8", "replace")[-500:]
    pid = int(out.stdout.split()[-1])
    deadline = time.monotonic() + 3
    while os.path.exists(f"/proc/{pid}") and time.monotonic() < deadline:
        time.sleep(0.02)
    try:
        assert not os.path.exists(f"/proc/{pid}")
    finally:
        if os.path.exists(f"/proc/{pid}"):
            os.killpg(pid, signal.SIGKILL)
