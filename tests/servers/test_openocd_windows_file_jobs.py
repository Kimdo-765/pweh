"""내부 파일 job의 사용권·종료·게시 경계. 실제 파일/자식 통합은 별도 시험이 맡는다."""
from __future__ import annotations

import os
import threading
import time
from dataclasses import replace
from types import SimpleNamespace

import pytest

from openocd_mcp import process_windows as PW, windows_file_job as J, windows_output as O, windows_start as W
from openocd_mcp.rpc import RequestCancelled, TclConnectionClosed
from openocd_mcp.rpc_pipe import TclPipeClient
from openocd_mcp.session import OcdSession, REGISTRY
from openocd_mcp.tcl import TclReply
from pweh.errors import DeviceError, PwehError, TimeoutExpired
from pweh.jobs import Job, JobCancelled, JobContext
from pweh.portlock import PortOwner
from pweh.runtime import get_runtime


class Output:
    """출력 FD 검증을 가장하지 않고 job 호출 순서만 확인하는 좁은 합성 seam."""
    def __init__(self, env):
        self.env = env
        self.done = self.resumed_from = self.chunks = 0
        self.published = False
        self.hook = None
        self.receipt = None

    def create_chunk(self, index, slot, expected_size, *, deadline):
        assert index == self.chunks and expected_size > 0
        self.env.events.append(("create", slot, self.env.sess._uses))
        return SimpleNamespace(slot=slot, expected_size=expected_size)

    def command(self, operation, chunk, *, address_or_offset):
        self.env.events.append(("command", operation, address_or_offset))
        if self.hook:
            self.hook("command")
        return operation

    def accept_chunk(self, primary, second=None, *, deadline, cancel):
        assert not cancel()
        self.env.events.append(("accept", second is not None, self.env.sess._uses))
        if self.hook:
            self.hook("accept")
        self.done += primary.expected_size
        self.chunks += 1

    def publish(self, *, owner_confirmed, deadline, cancel, on_commit):
        assert owner_confirmed and self.env.owner.confirmed and self.env.sess._uses == 1
        assert not cancel()
        assert deadline <= self.env.deadline
        self.env.events.append(("publish", self.env.sess._uses))
        if self.hook:
            self.hook("publish")
        entry = {"id": "A-0001", "path": "jtag/internal.bin", "size": self.done, "sha256": "a" * 64}
        warnings = []
        try:
            on_commit(entry)
        except Exception:
            warnings.append("post_commit_callback_failed")
        self.published = True
        self.receipt = {"path": entry["path"], "metadata_path": "jtag/internal.json", "size": self.done,
                        "sha256": entry["sha256"], "artifact": entry,
                        "source": {"type": "memory", "address": 4096, "length": self.done},
                        "transfer": "dump_image", "chunks": self.chunks, "resumed_from": self.resumed_from,
                        "warnings": warnings}
        return self.receipt


@pytest.fixture
def env(workspace, auth, monkeypatch, isolated_ports):
    runtime = get_runtime("openocd-mcp")
    case = runtime.cases.create(title="합성 pipe 파일 job", authorization=auth)
    read_peer, write_fd = os.pipe()
    read_fd, write_peer = os.pipe()
    client = TclPipeClient(os.fdopen(write_fd, "wb", buffering=0), os.fdopen(read_fd, "rb", buffering=0))
    owner = SimpleNamespace(client=client, token="synthetic-file-job", confirmed=True, calls=0, releases=0)
    sess = OcdSession(case.id, "spawned", None, None, client, transport="windows-pipe", windows_owner=owner)
    sess.windows_lease = isolated_ports["manager"].acquire(
        ("win:COM4096",), owner=PortOwner("openocd-mcp", case.id, "합성 파일 job"))
    e = SimpleNamespace(runtime=runtime, case=case, client=client, owner=owner, sess=sess,
                        events=[], sent=[], deadline=time.monotonic() + 30, release_ok=True,
                        prepare_calls=0, send_hook=None, real_release_outputs=O.release_outputs)
    e.output = Output(e)
    REGISTRY.add(sess)
    with PW._LOCK:
        PW._OWNED[owner.token] = owner

    def close(*, timeout):
        assert 0 < timeout <= 10
        owner.calls += 1
        e.events.append(("physical", sess._uses))
        client.close(timeout=timeout)
        return SimpleNamespace(confirmed=owner.confirmed, reason="confirmed" if owner.confirmed else "unknown")

    def release(*, deadline):
        assert sess._uses == 0
        owner.releases += 1
        e.events.append(("release_run", sess._uses))
        return True

    owner.close, owner.release_run = close, release

    def release_outputs(actual, *, deadline):
        assert actual is owner and sess._uses == 0 and owner.confirmed
        e.events.append(("release_outputs", sess._uses))
        return e.release_ok

    def prepare(actual, spec, **kwargs):
        assert actual is owner and sess._uses == 1
        e.prepare_calls += 1
        e.events.append(("prepare", sess._uses))
        return e.output

    def send(command, *, timeout, cancel_check):
        assert 0 < timeout <= 900
        e.sent.append(command)
        if e.send_hook:
            return e.send_hook(command, cancel_check)
        return TclReply(0, "原文-C:/private-output")

    monkeypatch.setattr(O, "prepare_output", prepare)
    monkeypatch.setattr(O, "release_outputs", release_outputs)
    monkeypatch.setattr(W, "_save", lambda *a, **kw: None)
    monkeypatch.setattr(client, "call", send)
    monkeypatch.setattr(sess, "new_client", lambda *a, **kw: pytest.fail("새 client 생성"))
    yield e
    for row in runtime.jobs.list(active_only=True):
        runtime.jobs.cancel(row["job_id"])
        runtime.jobs.wait(row["job_id"], 3)
    owner.confirmed, e.release_ok = True, True
    if sess._uses == 0:
        W.close_session(sess, timeout=1)
    assert sess._uses == 0
    client.close(timeout=1)
    REGISTRY.remove(case.id)
    with PW._LOCK:
        PW._OWNED.pop(owner.token, None)
    os.close(read_peer)
    os.close(write_peer)


def spec(env, *, kind="memory", **kwargs):
    values = dict(case=env.case, kind=kind, output_name="internal", length=768, chunk_size=256,
                  address=4096 if kind == "memory" else None)
    if kind == "flash":
        values.update(bank=0, offset=256, bank_size=4096)
    values.update(kwargs)
    return O.PipeFileSpec(**values)


def start(env, value=None):
    return J.start_pipe_file_job(value or spec(env), env.sess, runtime=env.runtime, deadline=env.deadline)


def finish(env, job):
    env.runtime.jobs.wait(job.id, 3)
    assert job.status not in ("queued", "running", "cancelling")
    assert env.sess._uses == 0
    return job


def queued(env, monkeypatch):
    job = Job("job-queued", "memory-dump", "합성 대기", "openocd-mcp", env.case.id)
    ctx = JobContext(job, env.runtime.jobs)
    pending = []
    monkeypatch.setattr(env.runtime.jobs, "start", lambda kind, fn, **kw: (pending.append(fn), job)[1])
    return ctx, pending


@pytest.mark.parametrize("kind,verify,operations", [
    ("memory", False, ["dump_image"] * 3), ("memory", True, ["dump_image"] * 6),
    ("flash", False, ["read_bank"] * 3), ("flash", True, ["read_bank", "verify_bank"] * 3)])
def test_same_client_transfer_order_and_commit(env, kind, verify, operations):
    job = finish(env, start(env, spec(env, kind=kind, verify=verify)))
    assert job.status == "succeeded", job.error
    assert env.sent == operations
    assert env.output.done == 768 and env.output.chunks == 3 and env.output.published
    assert job._committed and job.result == job.meta["partial_result"] == env.output.receipt
    assert job.result["warnings"] == [] and env.sess.windows_lease.closed
    assert env.events.index(("physical", 1)) < env.events.index(("publish", 1))
    assert env.events.index(("publish", 1)) < env.events.index(("release_outputs", 0))
    assert env.events.index(("release_outputs", 0)) < env.events.index(("release_run", 0))
    assert REGISTRY.find(env.case.id) is None


@pytest.mark.parametrize("change", ["starting", "closing", "cleanup_pending", "terminal", "registry",
                                     "owner_registry", "client", "owner", "case", "transport"])
def test_unavailable_entry_creates_no_job(env, monkeypatch, change):
    value = spec(env)
    if change in ("starting", "closing", "cleanup_pending"):
        setattr(env.sess, change, True)
    elif change == "terminal":
        env.client.abort("owner_abort")
    elif change == "registry":
        REGISTRY.remove(env.case.id)
    elif change == "owner_registry":
        PW._OWNED.pop(env.owner.token)
    elif change == "client":
        env.owner.client = object()
    elif change == "owner":
        env.sess.windows_owner = None
    elif change == "case":
        value = replace(value, case=env.runtime.cases.create(title="다른 합성 케이스", authorization={
            "basis": "owned", "owner": "합성", "statement": "합성 소유 장치"}))
    else:
        env.sess.transport = "tcp"
    monkeypatch.setattr(env.runtime.jobs, "start", lambda *a, **kw: pytest.fail("미준비 job 등록"))
    try:
        with pytest.raises(PwehError):
            start(env, value)
        assert env.sess._uses == env.prepare_calls == 0
    finally:
        env.sess.starting = False
        env.sess.windows_owner, env.owner.client, env.sess.transport = env.owner, env.client, "windows-pipe"


@pytest.mark.parametrize("updates", [{"length": True}, {"chunk_size": 0}, {"output_name": "../x"},
                                      {"kind": "other"}, {"address": -1}])
def test_invalid_spec_fails_before_reservation(env, updates):
    with pytest.raises(PwehError, match="openocd_output_invalid"):
        start(env, replace(spec(env), **updates))
    assert env.sess._uses == 0 and not env.runtime.jobs.list()


@pytest.mark.parametrize("value", [True, float("inf"), float("nan"), -1, 10**1000])
def test_invalid_deadline_before_reservation(env, value):
    env.deadline = value
    with pytest.raises(PwehError):
        start(env)
    assert env.sess._uses == 0


@pytest.mark.parametrize("stop", ["cancel", "closing", "deadline"])
def test_queued_failure_preserves_unopened_output_session(env, monkeypatch, stop):
    ctx, pending = queued(env, monkeypatch)
    start(env)
    if stop == "cancel":
        ctx.job._cancel.set()
    elif stop == "closing":
        env.sess.begin_close()
    else:
        monkeypatch.setattr(J, "_remaining", lambda end: (_ for _ in ()).throw(TimeoutExpired("private")))
    with pytest.raises((JobCancelled, PwehError)):
        pending[0](ctx)
    assert env.sess._uses == env.prepare_calls == env.owner.calls == 0
    assert not env.sess.windows_lease.closed
    with pytest.raises(JobCancelled):
        pending[0](ctx)
    assert env.sess._uses == 0


@pytest.mark.parametrize("after_claim", [False, True])
def test_start_exception_returns_only_caller_owned_reservation(env, monkeypatch, after_claim):
    real = env.runtime.jobs.start
    entered, release = threading.Event(), threading.Event()
    pending, jobs = [], []
    prepare = O.prepare_output
    def paused(*a, **kw):
        entered.set()
        assert release.wait(3)
        return prepare(*a, **kw)
    monkeypatch.setattr(O, "prepare_output", paused)
    def fail(kind, fn, **kw):
        if after_claim:
            jobs.append(real(kind, fn, **kw))
            assert entered.wait(3)
        else:
            pending.append(fn)
        raise RuntimeError("synthetic-start-private")
    monkeypatch.setattr(env.runtime.jobs, "start", fail)
    try:
        with pytest.raises(RuntimeError):
            start(env)
        assert env.sess._uses == (1 if after_claim else 0)
    finally:
        release.set()
        for job in jobs:
            finish(env, job)
    if pending:
        with pytest.raises(JobCancelled):
            pending[0](JobContext(Job("job-late", "memory-dump", "대기", "openocd-mcp", env.case.id), env.runtime.jobs))
        assert env.owner.calls == 0


def test_thread_start_failure_returns_use(env, monkeypatch):
    monkeypatch.setattr(threading.Thread, "start", lambda self: (_ for _ in ()).throw(RuntimeError("private")))
    with pytest.raises(RuntimeError):
        start(env)
    assert env.sess._uses == 0 and env.runtime.jobs.list() == []


@pytest.mark.parametrize("error,code", [(TimeoutExpired("private"), "timeout"),
    (RequestCancelled(), "cancelled"), (TclConnectionClosed("private"), "openocd_pipe_terminal"),
    (RuntimeError("private"), "openocd_output_invalid"), (None, "openocd_output_invalid")])
def test_second_rpc_failure_never_retries(env, error, code):
    def send(command, cancel):
        if len(env.sent) == 2:
            if error is not None:
                raise error
            return TclReply(1, "raw-error-private")
        return TclReply(0, "")
    env.send_hook = send
    job = finish(env, start(env))
    assert job.status == ("cancelled" if code == "cancelled" else "failed")
    if job.error:
        assert job.error["code"] == code
        assert "private" not in str(job.to_dict())
    assert len(env.sent) == 2 and env.output.done == 256 and not env.output.published
    assert job.result["done"] == 256 and job.result["reason"] == code
    assert env.sess.windows_lease.closed


def test_command_preparation_spends_deadline_no_rpc(env, monkeypatch):
    clock = [100.0]
    env.deadline = 110.0
    monkeypatch.setattr(J, "time", SimpleNamespace(monotonic=lambda: clock[0]))
    def spend(stage):
        if stage == "command":
            clock[0] = 111.0
    env.output.hook = spend
    job = finish(env, start(env))
    assert job.error["code"] == "timeout" and env.sent == []


def test_prepare_failure_still_owns_cleanup(env, monkeypatch):
    def failed(*a, **kw):
        raise O.PipeOutputError("openocd_output_changed", output=object())
    monkeypatch.setattr(O, "prepare_output", failed)
    job = finish(env, start(env))
    assert job.error["code"] == "openocd_output_changed"
    assert env.owner.calls >= 1 and env.sess.windows_lease.closed and not env.sent


def test_physical_unknown_preserves_until_explicit_stop(env):
    env.owner.confirmed = False
    job = finish(env, start(env))
    assert job.error["code"] == "openocd_output_cleanup_unknown"
    assert env.owner.calls == 1 and env.owner.releases == 0 and not env.output.published
    assert env.sess.cleanup_pending and not env.sess.windows_lease.closed
    assert REGISTRY.get(env.case.id) is env.sess
    env.owner.confirmed = True
    assert W.close_session(env.sess, timeout=1)["ok"]
    assert env.owner.calls == 2 and env.sess.windows_lease.closed
    assert not env.output.published


def test_cancel_and_unknown_preserves_original_partial_reason(env):
    env.owner.confirmed = False
    env.send_hook = lambda *a: (_ for _ in ()).throw(RequestCancelled())
    job = finish(env, start(env))
    assert job.error["code"] == "openocd_output_cleanup_unknown"
    assert job.result["reason"] == "cancelled" and env.owner.calls == 1


def test_explicit_job_cancel_precedes_stop_pipe_abort(env, monkeypatch):
    ctx, pending = queued(env, monkeypatch)
    start(env)
    def stopped(command, cancel):
        ctx.job._cancel.set()
        env.sess.begin_close()
        env.client.abort("owner_close")
        raise TclConnectionClosed("private")
    env.send_hook = stopped
    with pytest.raises(JobCancelled):
        pending[0](ctx)
    assert ctx.job.meta["partial_result"]["reason"] == "cancelled"
    assert env.sess.windows_lease.closed and not env.output.published


@pytest.mark.parametrize("fault", ["audit", "output_close"])
def test_after_commit_fault_is_receipt_warning_success(env, monkeypatch, fault):
    if fault == "audit":
        monkeypatch.setattr(env.runtime, "audit", lambda *a, **kw: (_ for _ in ()).throw(RuntimeError("private")))
    else:
        env.release_ok = False
    job = finish(env, start(env))
    assert job.status == "succeeded" and job._committed and env.output.published
    assert job.result == job.meta["partial_result"]
    assert job.result["warnings"] == ["post_commit_callback_failed" if fault == "audit" else "output_close_unconfirmed"]
    assert "private" not in str(job.to_dict())
    if fault == "output_close":
        assert env.sess.cleanup_pending and not env.sess.windows_lease.closed and env.owner.releases == 0


def test_release_hook_never_runs_while_foreground_use_remains(env):
    env.sess.reserve_use()
    result = W.close_session(env.sess, timeout=.02)
    assert not result["ok"] and env.owner.releases == 0
    assert all(row[0] != "release_outputs" for row in env.events)
    env.sess.finish_use()
    assert W.close_session(env.sess, timeout=1)["ok"]


def test_stop_waiting_on_own_use_does_not_deadlock_worker(env):
    entered, release, stopped = threading.Event(), threading.Event(), []
    def send(command, cancel):
        entered.set()
        assert release.wait(3)
        if cancel():
            raise RequestCancelled()
        return TclReply(0, "")
    env.send_hook = send
    job = start(env)
    assert entered.wait(3)
    env.runtime.jobs.cancel(job.id)
    def stop():
        stopped.append(W.close_session(env.sess, timeout=2))
    thread = threading.Thread(target=stop)
    thread.start()
    deadline = time.monotonic() + 1
    while not env.sess.closing and time.monotonic() < deadline:
        time.sleep(.001)
    release.set()
    finish(env, job)
    thread.join(3)
    assert not thread.is_alive() and stopped[0]["ok"]
    assert job.status == "cancelled" and env.sess.windows_lease.closed


def test_complete_resume_has_no_rpc(env):
    env.output.done = env.output.resumed_from = 768
    job = finish(env, start(env))
    assert job.status == "succeeded" and not env.sent
    assert job.result["chunks"] == 0 and job.result["resumed_from"] == 768


def test_exclusive_busy_returns_only_second_reservation(env, monkeypatch):
    entered, release = threading.Event(), threading.Event()
    real = O.prepare_output
    def paused(*a, **kw):
        entered.set()
        assert release.wait(3)
        return real(*a, **kw)
    monkeypatch.setattr(O, "prepare_output", paused)
    job = start(env)
    assert entered.wait(3)
    try:
        with pytest.raises(PwehError, match="busy"):
            start(env, spec(env, output_name="second"))
        assert env.sess._uses == 1
    finally:
        release.set()
        finish(env, job)


def test_post_deadline_is_fixed_at_last_rpc_before_accept_and_close(env, monkeypatch):
    clock = [100.0]
    env.deadline = 300.0
    monkeypatch.setattr(J, "time", SimpleNamespace(monotonic=lambda: clock[0]))
    def spend(stage):
        if stage == "accept":
            clock[0] = 120.0
        if stage == "publish":
            assert clock[0] == 130.0
    env.output.hook = spend
    original_close = env.owner.close
    def close(**kw):
        clock[0] = 130.0
        return original_close(**kw)
    env.owner.close = close
    original_publish = env.output.publish
    def publish(**kw):
        assert kw["deadline"] == 160.0
        return original_publish(**kw)
    monkeypatch.setattr(env.output, "publish", publish)
    job = finish(env, start(env, spec(env, length=256)))
    assert job.status == "succeeded", job.error


def test_late_cancel_after_commit_does_not_undo_receipt(env, monkeypatch):
    def late(event, case_id):
        active = env.runtime.jobs.list(active_only=True)
        assert len(active) == 1
        job = env.runtime.jobs.cancel(active[0]["job_id"])
        assert job._committed and not job._cancel.is_set()
    monkeypatch.setattr(env.runtime, "audit", late)
    job = finish(env, start(env))
    assert job.status == "succeeded" and job.result["warnings"] == []


def test_empty_output_registry_keeps_existing_close_semantics(env):
    # 실제 release_outputs는 등록 record가 없으면 owner 형태와 무관하게 바로 True다.
    assert env.real_release_outputs(env.owner, deadline=time.monotonic() + 1)
