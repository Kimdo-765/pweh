"""내부 pipe job의 공유 client·사용권·stop 경합. Windows나 장치를 실행하지 않는다."""
from __future__ import annotations

import asyncio
import hashlib
import json
import os
from pathlib import Path
import sys
import threading
import time
from types import SimpleNamespace

import pytest
from mcp import Client

from mcp_helpers import call
from openocd_mcp import dumps, process_pipe, server as S, windows_start as W
from openocd_mcp.rpc_pipe import TclPipeClient
from openocd_mcp.session import OcdSession, REGISTRY
from pweh.errors import Busy, DeviceError, PwehError
from pweh.jobs import Job, JobCancelled, JobContext
from pweh.portlock import PortOwner

pytestmark = [pytest.mark.anyio, pytest.mark.skipif(not sys.platform.startswith("linux"), reason="Linux 합성 pipe 수명")]
FAKE = Path(__file__).with_name("fake_openocd_pipe_dump.py")


@pytest.fixture
def anyio_backend():
    return "asyncio"


def wait_for(check, timeout=5):
    end = time.monotonic() + timeout
    while not check():
        assert time.monotonic() < end, "합성 worker 완료 시간 초과"
        time.sleep(.01)


class LocalOwner:
    """Windows 소유권 확인을 모사하고, 실제 자식은 있을 때 Linux pipe만 정리한다."""
    def __init__(self, client, root, pipe=None):
        self.client, self.root, self.pipe = client, root, pipe
        self.confirmed = True
        self.release_ok = True
        self.released = False
        self.close_calls = 0
        self.release_calls = 0
        root.mkdir()

    def close(self, *, timeout):
        self.close_calls += 1
        if not self.confirmed:
            return SimpleNamespace(confirmed=False, reason="synthetic_unknown")
        if self.pipe is not None:
            result = self.pipe.close(grace=.02, timeout=timeout)
            return SimpleNamespace(confirmed=result.confirmed, reason=result.reason)
        return SimpleNamespace(confirmed=self.client.close(timeout=timeout), reason="confirmed")

    def release_run(self, *, deadline):
        self.release_calls += 1
        if not self.release_ok:
            return False
        assert self.confirmed and not self.client.connected
        self.root.rmdir()
        self.released = True
        return True


@pytest.fixture
def lab(workspace, auth, tmp_path, isolated_ports):
    runtime = S.rt()
    case = runtime.cases.create(title="합성 내부 pipe 덤프", authorization=auth)
    made = []
    baseline = process_pipe.owned_process_count()

    def make(mode=None, *, profile="dummy-noinit-v1", lease=False):
        index = len(made)
        peers = []
        requests = tmp_path / f"requests-{index}.txt"
        pipe = None
        if mode is None:
            reader, writer = os.pipe()
            output, output_writer = os.pipe()
            peers = [reader, output_writer]
            client = TclPipeClient(os.fdopen(writer, "wb", buffering=0), os.fdopen(output, "rb", buffering=0))
        else:
            pipe = process_pipe.spawn_pipe(
                [sys.executable, "-I", str(FAKE), "--mode", mode, "--requests-file", str(requests)],
                cwd=tmp_path, log_path=tmp_path / f"pipe-{index}.log")
            assert pipe.wait_ready(timeout=5).ready
            client = pipe.client
        owner = LocalOwner(client, tmp_path / f"run-{index}", pipe)
        sess = OcdSession(case_id=case.id, mode="spawned", host="", port=None, client=client,
                          transport="windows-pipe", windows_owner=owner, windows_profile=profile)
        if lease:
            sess.windows_lease = isolated_ports["manager"].acquire(
                ("win:COM4096",), owner=PortOwner("openocd-mcp", case.id, "synthetic"))
        REGISTRY.add(sess)
        result = SimpleNamespace(sess=sess, owner=owner, client=client, pipe=pipe, requests=requests)
        made.append((result, peers))
        return result

    yield SimpleNamespace(runtime=runtime, case=case, make=make)
    for job in runtime.jobs.list(active_only=True):
        runtime.jobs.cancel(job["job_id"])
        runtime.jobs.wait(job["job_id"], 3)
    for env, peers in made:
        env.owner.confirmed = env.owner.release_ok = True
        if not env.owner.released:
            assert W.close_session(env.sess, timeout=3)["stopped"]
        for fd in peers:
            os.close(fd)
        assert env.sess._uses == 0
        assert REGISTRY.find(env.sess.case_id) is not env.sess
    assert process_pipe.owned_process_count() == baseline


def spec_for(lab, **kwargs):
    values = dict(kind="memory", case=lab.case, out_dir=lab.case.subdir("jtag"), name="synthetic",
                  address=0x1000, length=768, chunk_size=256, method="read_memory", retries=3, chunk_timeout=.3)
    values.update(kwargs)
    return dumps.prepare(dumps.DumpSpec(**values))


def start(spec, sess):
    return S._start_dump_job(spec, sess, description="합성 공유 pipe", kind="memory-dump")


def context(lab):
    job = Job(id="job-synthetic-queued", kind="memory-dump", description="합성 대기", server=S.SERVER_NAME,
              case_id=lab.case.id)
    return JobContext(job, lab.runtime.jobs)


@pytest.mark.parametrize("verify", [False, True])
def test_complete_dump_borrows_exact_client_without_close(lab, monkeypatch, verify):
    env = lab.make("ready")
    spec = spec_for(lab, verify=verify)
    closed = []
    real_close = env.client.close
    monkeypatch.setattr(env.client, "close", lambda **kw: (closed.append(True), real_close(**kw))[1])
    monkeypatch.setattr(env.sess, "new_client", lambda **kw: pytest.fail("공유 pipe 재연결"))
    job = start(spec, env.sess)
    lab.runtime.jobs.wait(job.id, 5)
    assert job.status == "succeeded", job.error
    expected = bytes(range(256)) * 3
    assert spec.final.read_bytes() == expected
    assert job.result["sha256"] == hashlib.sha256(expected).hexdigest()
    assert job.result["size"] == len(expected) and job.result["chunks"] == 3
    assert job.result["retries"] == 0
    assert not spec.part.exists() and not spec.state.exists()
    metadata = json.loads(spec.meta.read_text())
    assert metadata["verification"]["reread"] is verify
    assert metadata["output"]["sha256"] == job.result["artifact"]["sha256"]
    assert env.sess.client is env.client and env.client.connected and env.sess._uses == 0
    assert closed == [] and env.owner.close_calls == 0
    assert env.client.call("version", timeout=1).ok
    assert env.requests.read_text().splitlines() == ["version"] + ["read_memory"] * (6 if verify else 3) + ["version"]


@pytest.mark.parametrize("mode", ["stall-second", "eof-second", "malformed-second", "utf8-second"])
def test_terminal_job_preserves_completed_chunk_and_shared_owner(lab, monkeypatch, mode):
    env = lab.make(mode)
    spec = spec_for(lab)
    monkeypatch.setattr(env.sess, "new_client", lambda **kw: pytest.fail("종료 pipe 재연결"))
    monkeypatch.setattr(env.sess, "died_after_disconnect", lambda: pytest.fail("종료 pipe TCP 상태 조회"))
    job = start(spec, env.sess)
    lab.runtime.jobs.wait(job.id, 5)
    assert job.status == "failed" and job.error["code"] == "openocd_pipe_terminal", job.error
    assert spec.part.read_bytes() == bytes(range(256))
    assert json.loads(spec.state.read_text())["done"] == 256
    assert job.error["data"]["done"] == 256 and not spec.final.exists()
    assert env.sess._uses == 0 and env.client.terminal_reason is not None
    assert env.requests.read_text().splitlines() == ["version", "read_memory", "read_memory"]
    assert env.owner.close_calls == 0 and env.owner.root.exists()
    assert REGISTRY.get(lab.case.id) is env.sess


def test_running_job_cancel_returns_reservation_and_preserves_partial(lab):
    env = lab.make("stall-second")
    spec = spec_for(lab, chunk_timeout=5)
    job = start(spec, env.sess)
    wait_for(lambda: env.requests.read_text().splitlines().count("read_memory") == 2)
    assert env.sess._uses == 1
    lab.runtime.jobs.cancel(job.id)
    lab.runtime.jobs.wait(job.id, 3)
    assert job.status == "cancelled" and env.sess._uses == 0
    assert spec.part.read_bytes() == bytes(range(256))
    assert job.meta["done"] == 256 and not spec.final.exists()
    assert env.client.terminal_reason == "cancelled" and env.owner.close_calls == 0


@pytest.mark.parametrize("method,kind", [("auto", "memory"), ("md", "memory"), ("dump_image", "memory"), ("read_memory", "flash")])
def test_borrowed_unsupported_method_refuses_before_registration(lab, monkeypatch, method, kind):
    env = lab.make()
    spec = spec_for(lab, method=method, kind=kind)
    monkeypatch.setattr(lab.runtime.jobs, "start", lambda *a, **kw: pytest.fail("미지원 job 등록"))
    with pytest.raises(DeviceError, match="openocd_pipe_job_unsupported"):
        start(spec, env.sess)
    assert env.sess._uses == 0


@pytest.mark.parametrize("state", ["starting", "closing", "cleanup_pending", "terminal", "wrong_client"])
def test_unavailable_session_refuses_before_registration(lab, monkeypatch, state):
    env = lab.make()
    if state == "terminal":
        env.client.abort("owner_abort")
    elif state == "wrong_client":
        env.sess.client = SimpleNamespace(connected=True)
    else:
        setattr(env.sess, state, True)
    monkeypatch.setattr(lab.runtime.jobs, "start", lambda *a, **kw: pytest.fail("미준비 job 등록"))
    try:
        with pytest.raises((Busy, DeviceError)):
            start(spec_for(lab), env.sess)
        assert env.sess._uses == 0
    finally:
        env.sess.starting = False
        env.sess.client = env.client


def test_queued_cancel_returns_use_once_without_runner(lab, monkeypatch):
    env = lab.make()
    queued = []
    ctx = context(lab)
    monkeypatch.setattr(lab.runtime.jobs, "start", lambda kind, fn, **kw: (queued.append(fn), ctx.job)[1])
    monkeypatch.setattr(S.dumps, "DumpRunner", lambda *a, **kw: pytest.fail("취소된 worker 실행"))
    start(spec_for(lab), env.sess)
    assert env.sess._uses == 1
    ctx.job._cancel.set()
    with pytest.raises(JobCancelled):
        queued[0](ctx)
    assert env.sess._uses == 0 and env.client.connected
    with pytest.raises(JobCancelled):
        queued[0](ctx)
    assert env.sess._uses == 0


@pytest.mark.parametrize("error", [RuntimeError, KeyboardInterrupt])
def test_start_failure_before_claim_returns_use_and_abandons_late_worker(lab, monkeypatch, error):
    env = lab.make()
    queued = []
    def failed(kind, fn, **kwargs):
        queued.append(fn)
        raise error("합성 시작 실패")
    monkeypatch.setattr(lab.runtime.jobs, "start", failed)
    monkeypatch.setattr(S.dumps, "DumpRunner", lambda *a, **kw: pytest.fail("포기 worker 실행"))
    with pytest.raises(error):
        start(spec_for(lab), env.sess)
    assert env.sess._uses == 0
    with pytest.raises(JobCancelled):
        queued[0](context(lab))
    assert env.sess._uses == 0 and env.client.connected


def test_real_thread_start_failure_rolls_back_job_and_reservation(lab, monkeypatch):
    env = lab.make()
    def failed(thread):
        raise RuntimeError("합성 Thread.start 실패")
    monkeypatch.setattr(threading.Thread, "start", failed)
    with pytest.raises(RuntimeError):
        start(spec_for(lab), env.sess)
    assert lab.runtime.jobs.list() == [] and env.sess._uses == 0


def test_start_failure_after_worker_claim_keeps_use_until_worker_finally(lab, monkeypatch):
    env = lab.make()
    entered, release = threading.Event(), threading.Event()
    real_start = lab.runtime.jobs.start
    jobs = []
    def running(*a, **kw):
        def run():
            entered.set()
            assert release.wait(5)
            return {"synthetic": True}
        return SimpleNamespace(run=run)
    monkeypatch.setattr(S.dumps, "DumpRunner", running)
    def failed(*a, **kw):
        job = real_start(*a, **kw)
        jobs.append(job)
        assert entered.wait(3)
        raise RuntimeError("합성 시작 이후 예외")
    monkeypatch.setattr(lab.runtime.jobs, "start", failed)
    try:
        with pytest.raises(RuntimeError):
            start(spec_for(lab), env.sess)
        assert env.sess._uses == 1
    finally:
        release.set()
        for job in jobs:
            lab.runtime.jobs.wait(job.id, 3)
    assert env.sess._uses == 0 and env.client.connected


def test_exclusive_busy_returns_only_second_reservation(lab, monkeypatch):
    env = lab.make()
    entered, release = threading.Event(), threading.Event()
    def running(*a, **kw):
        def run():
            entered.set()
            assert release.wait(5)
            return {"synthetic": True}
        return SimpleNamespace(run=run)
    monkeypatch.setattr(S.dumps, "DumpRunner", running)
    job = start(spec_for(lab), env.sess)
    try:
        assert entered.wait(3)
        with pytest.raises(PwehError, match="busy"):
            start(spec_for(lab, name="second"), env.sess)
        assert env.sess._uses == 1
    finally:
        release.set()
        lab.runtime.jobs.wait(job.id, 3)
    assert env.sess._uses == 0


@pytest.mark.parametrize("failure", [False, True])
def test_tcp_job_still_owns_and_closes_separate_client(lab, monkeypatch, failure):
    closed = []
    client = SimpleNamespace(close=lambda: closed.append(True))
    sess = SimpleNamespace(windows=False, new_client=lambda **kw: client, died_after_disconnect=lambda: False)
    def runner(spec, ctx, actual, **kw):
        assert actual is client and kw["borrowed_pipe"] is False
        def run():
            if failure:
                raise DeviceError("합성 TCP 실패")
            return {"synthetic": True}
        return SimpleNamespace(run=run)
    monkeypatch.setattr(S.dumps, "DumpRunner", runner)
    job = start(spec_for(lab), sess)
    lab.runtime.jobs.wait(job.id, 3)
    assert job.status == ("failed" if failure else "succeeded") and closed == [True]


async def test_public_stop_cancels_active_pipe_job_before_owner_close(lab):
    env = lab.make("stall-second", lease=True)
    spec = spec_for(lab, chunk_timeout=5)
    job = start(spec, env.sess)
    await asyncio.to_thread(wait_for, lambda: env.requests.read_text().splitlines().count("read_memory") == 2)
    async with Client(S.server) as client:
        out = await call(client, "openocd_stop", case_id=lab.case.id)
    lab.runtime.jobs.wait(job.id, 3)
    assert out["ok"] and out["cancelled_jobs"] == [job.id]
    assert job.status == "cancelled" and env.sess._uses == 0
    assert env.owner.released and env.sess.windows_lease.closed
    assert spec.part.read_bytes() == bytes(range(256)) and not spec.final.exists()


async def test_stop_before_job_registration_keeps_run_and_lease_until_worker_returns(lab, monkeypatch):
    env = lab.make(lease=True)
    queued = []
    ctx = context(lab)
    monkeypatch.setattr(lab.runtime.jobs, "start", lambda kind, fn, **kw: (queued.append(fn), ctx.job)[1])
    monkeypatch.setattr(S.dumps, "DumpRunner", lambda *a, **kw: pytest.fail("closing 뒤 첫 RPC"))
    real_close = W.close_session
    monkeypatch.setattr(W, "close_session", lambda sess: real_close(sess, timeout=.05))
    start(spec_for(lab), env.sess)
    async with Client(S.server) as client:
        out = await call(client, "openocd_stop", case_id=lab.case.id)
        assert out["cancelled_jobs"] == [] and out["cleanup_pending"] and out["reason"] == "worker_pending"
        assert env.sess._uses == 1 and env.owner.root.exists() and env.owner.release_calls == 0
        assert not env.sess.windows_lease.closed and REGISTRY.get(lab.case.id) is env.sess
        with pytest.raises(JobCancelled):
            queued[0](ctx)
        assert env.sess._uses == 0
        out = await call(client, "openocd_stop", case_id=lab.case.id)
        assert out["ok"] and env.owner.released and env.sess.windows_lease.closed


async def test_stop_retains_claimed_worker_until_its_finally(lab, monkeypatch):
    env = lab.make(lease=True)
    entered, release = threading.Event(), threading.Event()
    def running(spec, ctx, client, **kwargs):
        def run():
            entered.set()
            assert release.wait(5)
            ctx.check_cancelled()
            pytest.fail("stop 취소가 worker에 전달되지 않았습니다.")
        return SimpleNamespace(run=run)
    monkeypatch.setattr(S.dumps, "DumpRunner", running)
    real_close = W.close_session
    monkeypatch.setattr(W, "close_session", lambda sess: real_close(sess, timeout=.05))
    job = start(spec_for(lab), env.sess)
    try:
        assert entered.wait(3)
        async with Client(S.server) as client:
            out = await call(client, "openocd_stop", case_id=lab.case.id)
            assert out["cleanup_pending"] and out["cancelled_jobs"] == [job.id]
            assert job._cancel.is_set() and env.sess._uses == 1
            assert env.owner.root.exists() and env.owner.release_calls == 0
            assert not env.sess.windows_lease.closed and REGISTRY.get(lab.case.id) is env.sess
            release.set()
            await asyncio.to_thread(lab.runtime.jobs.wait, job.id, 3)
            assert job.status == "cancelled" and env.sess._uses == 0
            out = await call(client, "openocd_stop", case_id=lab.case.id)
            assert out["ok"] and env.owner.released and env.sess.windows_lease.closed
    finally:
        release.set()
        lab.runtime.jobs.wait(job.id, 3)


@pytest.mark.parametrize("unknown", ["physical", "run"])
async def test_unknown_cleanup_retains_registry_run_and_lease_until_retry(lab, unknown):
    env = lab.make("ready", lease=True)
    job = start(spec_for(lab), env.sess)
    lab.runtime.jobs.wait(job.id, 5)
    assert job.status == "succeeded"
    if unknown == "physical":
        env.owner.confirmed = False
    else:
        env.owner.release_ok = False
    async with Client(S.server) as client:
        out = await call(client, "openocd_stop", case_id=lab.case.id)
        assert not out["ok"] and out["cleanup_pending"]
        assert env.owner.root.exists() and not env.sess.windows_lease.closed
        assert REGISTRY.get(lab.case.id) is env.sess
        env.owner.confirmed = env.owner.release_ok = True
        out = await call(client, "openocd_stop", case_id=lab.case.id)
        assert out["ok"] and env.owner.released and env.sess.windows_lease.closed


async def test_stop_does_not_cancel_another_case_job(lab):
    env = lab.make()
    entered, release = threading.Event(), threading.Event()
    def other(ctx):
        entered.set()
        assert release.wait(5)
        ctx.check_cancelled()
        return {"synthetic": True}
    job = lab.runtime.jobs.start("synthetic", other, description="다른 합성 케이스", case_id="other-synthetic")
    try:
        assert entered.wait(3)
        async with Client(S.server) as client:
            out = await call(client, "openocd_stop", case_id=lab.case.id)
        assert out["ok"] and out["cancelled_jobs"] == [] and not job._cancel.is_set()
    finally:
        release.set()
        lab.runtime.jobs.wait(job.id, 3)
    assert job.status == "succeeded"


@pytest.mark.parametrize("profile", ["dummy-noinit-v1", "tigard-jtag-v1"])
@pytest.mark.parametrize("tool,kwargs", [
    ("openocd_dump_memory_start", {"address": 0, "length": 256, "method": "read_memory"}),
    ("openocd_flash_read_start", {"bank": 0}),
    ("openocd_flash_banks", {}),
    ("openocd_read_memory", {"address": 0, "count": 1}),
    ("openocd_halt", {"target": "synthetic.cpu"}),
    ("openocd_command", {"command": "read_memory 0 8 1"}),
])
async def test_public_windows_dump_and_target_guards_remain_closed(lab, monkeypatch, profile, tool, kwargs):
    env = lab.make(profile=profile)
    monkeypatch.setattr(env.client, "call", lambda *a, **kw: pytest.fail("공개 미지원 RPC"))
    monkeypatch.setattr(lab.runtime.jobs, "start", lambda *a, **kw: pytest.fail("공개 미지원 job"))
    async with Client(S.server) as client:
        out = await call(client, tool, case_id=lab.case.id, **kwargs)
    assert "[openocd_windows_unsupported]" in out.get("_error", ""), out
    assert env.sess._uses == 0
