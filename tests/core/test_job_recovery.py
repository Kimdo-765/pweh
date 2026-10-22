"""저장 작업의 제한된 지연 확인: 실제 케이스·기기 없이 합성 기록과 자체 자식만 사용한다."""
from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys
import threading
import time

import pytest

from pweh import jobs as J, procutil, safeio
from pweh.errors import NotFound, PwehError, ValidationFailed

OWNER = {"server": "synthetic", "pid": 1234, "start_ticks": 42, "host": "synthetic-host",
         "boot_id": "synthetic-boot", "pid_ns": "synthetic-namespace"}


def record(root, *, job_id="job-a1", status="running", owner=OWNER, server="synthetic", case_id="synthetic", **extra):
    (root / "jobs").mkdir(parents=True, exist_ok=True)
    data = {"job_id": job_id, "case_id": case_id, "server": server, "status": status,
            "message": "합성 진행", "result": {"preserved": True}, "meta": {"owner": owner}, **extra}
    if owner is not None:
        data["owner"] = owner
    path = root / "jobs" / (job_id + ".json")
    path.write_text(json.dumps(data), encoding="utf-8")
    return path


def manager(state="terminated", reason="process_absent", **kw):
    return J.JobManager("synthetic", owner_probe=lambda _: (state, reason), **kw)


def test_dead_record_is_failed_once_private_owner_preserved_and_no_resume(tmp_path):
    path = record(tmp_path, eta_seconds=5)
    m = manager()
    row = m.saved(tmp_path, "synthetic", job_id="job-a1")["jobs"][0]
    assert row["status"] == "failed"
    assert row["recovery"]["previous_status"] == "running"
    assert row["recovery"]["resumable"] is False
    assert row["error"]["code"] == "job_owner_terminated"
    assert row["result"] == {"preserved": True}
    assert "owner" not in row and "owner" not in row["meta"] and "eta_seconds" not in row
    saved = path.read_bytes()
    assert json.loads(saved)["owner"] == OWNER
    assert m.saved(tmp_path, "synthetic", job_id="job-a1")["jobs"][0] == row
    assert path.read_bytes() == saved
    assert m.list() == []
    with pytest.raises(NotFound):
        m.cancel("job-a1")
    with pytest.raises(NotFound):
        m.wait("job-a1", .01)


@pytest.mark.parametrize("state,owner", [("alive", OWNER), ("unknown", OWNER), ("unknown", None)])
def test_live_unknown_and_legacy_remain_byte_identical(tmp_path, state, owner):
    path = record(tmp_path, owner=owner)
    before = path.read_bytes()
    row = manager(state).saved(tmp_path, "synthetic", job_id="job-a1")["jobs"][0]
    assert row["status"] == "running" and row["recovery"]["owner_state"] == state
    assert path.read_bytes() == before


@pytest.mark.parametrize("state", ["succeeded", "failed", "cancelled", "abandoned"])
def test_terminal_records_are_never_reclassified(tmp_path, state):
    path = record(tmp_path, status=state)
    before = path.read_bytes()
    m = J.JobManager("synthetic", owner_probe=lambda _: pytest.fail("terminal owner 조회"))
    assert m.saved(tmp_path, "synthetic")["jobs"][0]["status"] == state
    assert path.read_bytes() == before


def test_other_server_and_other_case_are_not_adopted(tmp_path):
    path = record(tmp_path, server="another-server")
    before = path.read_bytes()
    assert manager().saved(tmp_path, "synthetic")["jobs"] == []
    with pytest.raises(NotFound):
        manager().saved(tmp_path, "synthetic", job_id="job-a1")
    assert path.read_bytes() == before
    record(tmp_path, case_id="another-case")
    with pytest.raises(ValidationFailed):
        manager().saved(tmp_path, "synthetic", job_id="job-a1")


@pytest.mark.parametrize("field,value,expected", [
    ("host", "other-host", ("unknown", "different_host")),
    ("pid_ns", "other-ns", ("unknown", "different_pid_namespace")),
    ("boot_id", "other-boot", ("terminated", "boot_changed")),
    ("start_ticks", 41, ("terminated", "pid_reused")),
    ("start_ticks", None, ("unknown", "owner_incomplete")),
    ("pid", True, ("unknown", "owner_incomplete")),
])
def test_owner_identity_comparison(monkeypatch, field, value, expected):
    monkeypatch.setattr(procutil, "owner_record", lambda server: OWNER.copy())
    monkeypatch.setattr(procutil, "proc_stat", lambda pid: ("S", 42))
    assert J._owner_state({**OWNER, field: value}) == expected


@pytest.mark.parametrize("stat,alive,expected", [
    (("S", 42), True, ("alive", "identity_matches")),
    (("Z", 42), False, ("terminated", "process_exited")),
    (("X", 42), False, ("terminated", "process_exited")),
    (None, False, ("terminated", "process_absent")),
    (None, True, ("unknown", "start_identity_unavailable")),
])
def test_absent_zombie_and_permission_unknown(monkeypatch, stat, alive, expected):
    monkeypatch.setattr(procutil, "owner_record", lambda server: OWNER.copy())
    monkeypatch.setattr(procutil, "proc_stat", lambda pid: stat)
    monkeypatch.setattr(procutil, "pid_alive", lambda pid: alive)
    assert J._owner_state(OWNER) == expected


def test_probe_error_is_unknown(monkeypatch):
    def fail(_):
        raise PermissionError("합성 접근 거부")
    monkeypatch.setattr(procutil, "owner_record", fail)
    assert J._owner_state(OWNER) == ("unknown", "process_check_unavailable")


@pytest.mark.parametrize("kind", ["file-link", "directory-link", "fifo", "oversize", "malformed", "id-mismatch"])
def test_untrusted_records_fail_without_following_or_blocking(tmp_path, kind, monkeypatch):
    root = tmp_path / "case"
    path = record(root)
    before = path.read_bytes()
    outside = tmp_path / "outside.json"
    outside.write_bytes(before)
    if kind == "file-link":
        path.unlink()
        path.symlink_to(outside)
    elif kind == "directory-link":
        (root / "jobs").rename(tmp_path / "elsewhere")
        (root / "jobs").symlink_to(tmp_path / "elsewhere", target_is_directory=True)
    elif kind == "fifo":
        path.unlink()
        os.mkfifo(path)
    elif kind == "oversize":
        monkeypatch.setattr(J, "MAX_RECORD_BYTES", 10)
    elif kind == "malformed":
        path.write_text('{')
    else:
        d = json.loads(before)
        d["job_id"] = "job-other"
        path.write_text(json.dumps(d))
    with pytest.raises((PwehError, OSError)):
        manager().saved(root, "synthetic", job_id="job-a1")
    assert outside.read_bytes() == before


@pytest.mark.parametrize("bad", ["../job-a1", "job-../../x", "/job-a1", "job-a\x00b", "job-" + "a" * 81])
def test_job_id_cannot_escape_case(tmp_path, bad):
    with pytest.raises(ValidationFailed):
        manager().saved(tmp_path, "synthetic", job_id=bad)
    assert list(tmp_path.iterdir()) == []


def test_list_limits_and_unreadable_records_report_incomplete(tmp_path, monkeypatch):
    for n in range(5):
        record(tmp_path, job_id=f"job-{n}")
    monkeypatch.setattr(J, "MAX_SAVED_JOBS", 2)
    out = manager().saved(tmp_path, "synthetic")
    assert len(out["jobs"]) == 2 and out["recovery"]["truncated"]
    assert "scan_limit" in out["recovery"]["reasons"]
    monkeypatch.setattr(J, "MAX_SAVED_JOBS", 256)
    (tmp_path / "jobs" / "job-bad.json").write_text('{')
    out = manager().saved(tmp_path, "synthetic")
    assert "record_unreadable" in out["recovery"]["reasons"]


@pytest.mark.parametrize("limit", ["MAX_SCAN_ENTRIES", "MAX_SCAN_BYTES"])
def test_entry_and_total_input_limits_are_reported(tmp_path, monkeypatch, limit):
    first = record(tmp_path, job_id="job-1")
    record(tmp_path, job_id="job-2")
    monkeypatch.setattr(J, limit, 1 if limit == "MAX_SCAN_ENTRIES" else first.stat().st_size)
    out = manager("alive").saved(tmp_path, "synthetic")
    assert out["recovery"]["truncated"] and len(out["jobs"]) <= 1


def test_absent_directory_is_not_created_and_missing_record_is_not_found(tmp_path):
    assert manager().saved(tmp_path, "synthetic")["jobs"] == []
    assert list(tmp_path.iterdir()) == []
    (tmp_path / "jobs").mkdir()
    with pytest.raises(NotFound):
        manager().saved(tmp_path, "synthetic", job_id="job-missing")


def test_start_persists_owner_before_thread_runs_and_failure_is_terminal(tmp_path, monkeypatch):
    m = J.JobManager("synthetic", persist_dir=lambda job: tmp_path / "jobs", owner_provider=lambda server: OWNER.copy())
    def refuse_start(self):
        records = list((tmp_path / "jobs").glob("job-*.json"))
        assert len(records) == 1
        initial = json.loads(records[0].read_bytes())
        assert initial["status"] == "queued" and initial["owner"] == OWNER
        raise RuntimeError("합성 thread 시작 실패")
    monkeypatch.setattr(threading.Thread, "start", refuse_start)
    with pytest.raises(RuntimeError):
        m.start("synthetic", lambda ctx: None, description="합성 시작 실패", case_id="synthetic")
    final = json.loads(next((tmp_path / "jobs").glob("job-*.json")).read_bytes())
    assert final["status"] == "failed" and final["error"]["code"] == "job_start_failed"
    assert m.list() == []


def test_time_limit_does_not_mark_owner_dead(tmp_path, monkeypatch):
    path = record(tmp_path)
    before = path.read_bytes()
    monkeypatch.setattr(J, "RECOVERY_SECONDS", .005)
    def slow(_):
        time.sleep(.015)
        return "terminated", "process_absent"
    with pytest.raises(PwehError) as exc:
        J.JobManager("synthetic", owner_probe=slow).saved(tmp_path, "synthetic", job_id="job-a1")
    assert exc.value.code == "job_recovery_time" and path.read_bytes() == before


def test_final_persist_wins_before_recovery_reads_lock(tmp_path, monkeypatch):
    path = record(tmp_path)
    opened = threading.Event()
    released = threading.Event()
    original_lock = safeio.locked_at
    from contextlib import contextmanager
    @contextmanager
    def delayed_lock(*a, **kw):
        opened.set()
        assert released.wait(2)
        with original_lock(*a, **kw) as fd:
            yield fd
    monkeypatch.setattr(safeio, "locked_at", delayed_lock)
    out = []
    thread = threading.Thread(target=lambda: out.append(manager().saved(tmp_path, "synthetic")))
    thread.start()
    assert opened.wait(2)
    record(tmp_path, status="succeeded")
    before = path.read_bytes()
    released.set()
    thread.join(2)
    assert not thread.is_alive()
    assert out[0]["jobs"][0]["status"] == "succeeded" and path.read_bytes() == before


def test_live_job_from_another_manager_is_not_misclassified(tmp_path):
    release = threading.Event()
    entered = threading.Event()
    def wait_for_release(ctx):
        entered.set()
        return release.wait(3)
    running = J.JobManager("synthetic", persist_dir=lambda job: tmp_path / "jobs")
    job = running.start("synthetic", wait_for_release, description="합성 대기", case_id="synthetic")
    try:
        assert entered.wait(2)
        before = (tmp_path / "jobs" / (job.id + ".json")).read_bytes()
        row = J.JobManager("synthetic").saved(tmp_path, "synthetic", job_id=job.id)["jobs"][0]
        assert row["status"] in J.ACTIVE_STATES and row["recovery"]["owner_state"] == "alive"
        assert (tmp_path / "jobs" / (job.id + ".json")).read_bytes() == before
    finally:
        release.set()
        running.wait(job.id, 3)


def test_sigkill_of_owned_child_recovers_persisted_job(tmp_path):
    script = '''import sys,time
from pathlib import Path
from pweh.jobs import JobManager
root=Path(sys.argv[1])
m=JobManager("synthetic",persist_dir=lambda job:root/"jobs")
j=m.start("synthetic",lambda ctx: time.sleep(60),description="합성 자식",case_id="synthetic")
(root/"ready").write_text(j.id)
time.sleep(60)
'''
    child = subprocess.Popen([sys.executable, "-c", script, str(tmp_path)], stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    try:
        until = time.monotonic() + 5
        while not (tmp_path / "ready").exists() and child.poll() is None and time.monotonic() < until:
            time.sleep(.01)
        assert (tmp_path / "ready").exists()
        job_id = (tmp_path / "ready").read_text()
        child.kill()
        child.wait(3)
        out = J.JobManager("synthetic").saved(tmp_path, "synthetic", job_id=job_id)
        assert out["jobs"][0]["status"] == "failed"
        assert out["jobs"][0]["error"]["code"] == "job_owner_terminated"
    finally:
        if child.poll() is None:
            child.kill()
        child.communicate(timeout=3)


@pytest.mark.anyio
async def test_mcp_explicit_case_lazy_recovery_and_old_contract(workspace, auth):
    from mcp import Client
    from mcp_helpers import call
    from pweh.case import CaseStore
    from pweh.mcpkit import create_server, register_job_tools
    from pweh.runtime import Runtime
    case = CaseStore(workspace["cases_dir"]).create(title="합성 작업", authorization=auth, case_id="synthetic")
    path = record(case.dir)
    rt = Runtime("synthetic")
    rt.jobs._owner_probe = lambda _: ("terminated", "process_absent")
    server = create_server("synthetic-job-test", instructions="합성 저장 작업 시험")
    register_job_tools(server, lambda: rt, "test")
    async with Client(server) as client:
        assert (await call(client, "test_jobs"))["jobs"] == []
        result = await call(client, "test_job_status", job_id="job-a1", case_id=case.id, wait_seconds=50)
        assert result["status"] == "failed" and "owner" not in result
        assert json.loads(path.read_bytes())["status"] == "failed"
        assert (await call(client, "test_jobs", case_id=case.id, active_only=True))["jobs"] == []
        assert (await call(client, "test_jobs"))["jobs"] == []


@pytest.fixture
def anyio_backend():
    return "asyncio"
