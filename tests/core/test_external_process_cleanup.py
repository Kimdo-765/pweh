"""외부 CLI 소유 그룹의 reap 순서·미확인·스레드 시작 실패 회귀."""
from __future__ import annotations

import importlib
import os
import sys
import threading
from pathlib import Path

import pytest

from pweh import procutil


@pytest.fixture(params=["esp", "sigrok"])
def runner(request):
    mod = importlib.import_module("esp_mcp.esptool_cli" if request.param == "esp" else "sigrok_mcp.cli")
    def run(code, **kwargs):
        if request.param == "esp":
            kwargs.setdefault("on_text", lambda text: None)
            return mod.run_streaming([sys.executable, "-c", code], timeout=5, poll_s=.01, **kwargs)
        return mod.run_process([sys.executable, "-c", code], timeout=5, poll_s=.01, **kwargs)
    yield mod, run
    mod._kill_all_live()


def test_natural_leader_exit_cleans_pipe_writer_before_reap(runner, tmp_path):
    mod, run = runner
    pidpath = tmp_path / "synthetic-child.pid"
    # 같은 새 세션의 자식이 출력 pipe를 잡고 부모만 먼저 끝난다.
    code = ("import os,time; p=os.fork(); "
            f"open({str(pidpath)!r},'w').write(str(p)) if p else None; "
            "os._exit(0) if p else time.sleep(30)")
    result = run(code)
    child = int(pidpath.read_text())
    assert result.cleanup_verified and result.ok
    assert not procutil.pid_alive(child)
    assert not Path(f"/proc/{result.pid}").exists()
    assert mod.live_process_count() == 0


def test_output_thread_start_failure_still_cleans_own_child(runner, monkeypatch):
    mod, run = runner
    state = {}
    monkeypatch.setattr(threading.Thread, "start", lambda self: (_ for _ in ()).throw(RuntimeError("synthetic thread failure")))
    with pytest.raises(RuntimeError, match="synthetic thread failure"):
        run("import time; time.sleep(30)", process_state=state)
    assert state["cleanup_verified"]
    assert not procutil.pid_alive(state["pid"])
    assert mod.live_process_count() == 0


def test_unknown_group_cleanup_keeps_own_process_record(runner, monkeypatch):
    mod, run = runner
    original = procutil.process_group_empty
    monkeypatch.setattr(procutil, "process_group_empty", lambda *a, **kw: None)
    result = run("pass")
    assert not result.cleanup_verified and not result.ok
    assert mod.live_process_count() == 1
    assert Path(f"/proc/{result.pid}").exists()  # 미확인 때 리더를 거두지 않는다.
    monkeypatch.setattr(procutil, "process_group_empty", original)
    assert mod.cleanup_owned(result.pid)
    assert mod.live_process_count() == 0
    assert not Path(f"/proc/{result.pid}").exists()


def test_process_group_inspection_mismatch_and_unreadable_fail_closed(monkeypatch):
    monkeypatch.setattr(procutil, "proc_stat", lambda pid: ("S", 9))
    assert procutil.process_group_empty(123456, expect_start_ticks=8) is None
    monkeypatch.setattr(procutil, "proc_stat", lambda pid: None)
    monkeypatch.setattr(os, "scandir", lambda path: (_ for _ in ()).throw(PermissionError("synthetic")))
    assert procutil.process_group_empty(123456, expect_start_ticks=8) is None
    assert procutil.process_group_empty(123456, expect_start_ticks=None) is None


def test_reused_pid_new_generation_survives_old_cleanup(runner, monkeypatch):
    mod, _run = runner
    pid = 123456
    class FakeProcess:
        def __init__(self, ticks):
            self.pid, self.ticks, self.returncode = pid, ticks, None
        def wait(self, timeout):
            self.returncode = 0
            # reap 직후 같은 PID로 새 실행이 등록되는 경합을 합성한다.
            mod._LIVE[id(new)] = (new, None, 0.0) if mod.__name__.startswith("esp") else new
            mod._CHILD_IDS[id(new)] = (222, None)
            return 0
    old, new = FakeProcess(111), FakeProcess(222)
    mod._LIVE[id(old)] = (old, None, 0.0) if mod.__name__.startswith("esp") else old
    mod._CHILD_IDS[id(old)] = (111, None)
    monkeypatch.setattr(procutil, "kill_process_group", lambda *a, **kw: "exited")
    monkeypatch.setattr(procutil, "process_group_empty", lambda *a, **kw: True)
    try:
        assert mod.cleanup_owned(pid, process_token=id(old))
        assert id(old) not in mod._LIVE and id(old) not in mod._CHILD_IDS
        assert id(new) in mod._LIVE and mod._CHILD_IDS[id(new)] == (222, None)
        # 옛 token의 중복 회수도 새 세대를 끝내지 않는다.
        assert mod.cleanup_owned(pid, process_token=id(old))
        assert id(new) in mod._LIVE
    finally:
        mod._LIVE.pop(id(old), None)
        mod._LIVE.pop(id(new), None)
        mod._CHILD_IDS.pop(id(old), None)
        mod._CHILD_IDS.pop(id(new), None)
