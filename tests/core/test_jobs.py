"""작업 스레드 기동 실패와 리소스 등록 수명 회귀."""

from __future__ import annotations

import threading

import pytest

from pweh.errors import PwehError
from pweh.jobs import JobManager


@pytest.mark.parametrize("failure", ["constructor", "start"])
def test_start_failure_removes_only_unstarted_job(monkeypatch, failure):
    manager = JobManager("synthetic")
    previous = manager.start("previous", lambda ctx: {"done": True}, description="앞선 작업")
    previous._thread.join(timeout=2)
    assert not previous._thread.is_alive()
    original_thread = threading.Thread

    def fail(*args, **kwargs):
        raise RuntimeError("합성 기동 실패")

    class FailingThread(original_thread):
        start = fail

    with monkeypatch.context() as patch:
        patch.setattr(threading, "Thread", fail if failure == "constructor" else FailingThread)
        with pytest.raises(RuntimeError, match="합성 기동 실패"):
            manager.start("new", lambda ctx: {}, description="시작 실패", exclusive_key="port")

    assert [row["job_id"] for row in manager.list()] == [previous.id]
    retry = manager.start("retry", lambda ctx: {}, description="재시도", exclusive_key="port")
    retry._thread.join(timeout=2)
    assert retry.status == "succeeded"


def test_exception_after_thread_start_keeps_active_registration(monkeypatch):
    manager = JobManager("synthetic")
    entered = threading.Event()
    release = threading.Event()
    original_thread = threading.Thread

    def worker(ctx):
        entered.set()
        assert release.wait(timeout=5)
        return {"done": True}

    class StartedThread(original_thread):
        def start(self):
            super().start()
            assert entered.wait(timeout=2)
            raise RuntimeError("합성 시작 후 실패")

    job = None
    try:
        with monkeypatch.context() as patch:
            patch.setattr(threading, "Thread", StartedThread)
            with pytest.raises(RuntimeError, match="합성 시작 후 실패"):
                manager.start("new", worker, description="이미 시작함", exclusive_key="port")
        rows = manager.list(active_only=True)
        assert len(rows) == 1
        job = manager.get(rows[0]["job_id"])
        with pytest.raises(PwehError) as caught:
            manager.start("other", lambda ctx: {}, description="경합", exclusive_key="port")
        assert caught.value.code == "busy"
    finally:
        release.set()
        if job is not None:
            job._thread.join(timeout=2)
    assert job.status == "succeeded"
    assert manager.get(job.id) is job
