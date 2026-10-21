"""pweh.procutil.pid_alive (G9): POSIX 생존 확인, 좀비 = 끝남, 깨진 pid, 네이티브 Windows 에서 os.kill 금지."""

from __future__ import annotations

import errno
import os
import signal
import subprocess
import sys
import time
from pathlib import Path

import pytest

from pweh import procutil
from pweh.procutil import UnsupportedPlatform, pid_alive

HAS_PROC = Path("/proc/self/stat").exists()


def test_own_pid_is_alive():
    assert pid_alive(os.getpid()) is True


def test_reaped_child_is_dead():
    p = subprocess.Popen([sys.executable, "-c", "pass"])
    p.wait(timeout=30)
    assert pid_alive(p.pid) is False


@pytest.mark.skipif(not HAS_PROC, reason="/proc 가 없는 플랫폼 (좀비 판별 불가)")
def test_zombie_child_is_dead():
    p = subprocess.Popen([sys.executable, "-c", "pass"])
    try:
        deadline = time.monotonic() + 30
        while procutil._proc_state(p.pid) != "Z":  # 끝났지만 아직 거두지 않음
            assert time.monotonic() < deadline, procutil._proc_state(p.pid)
            time.sleep(0.02)
        assert pid_alive(p.pid) is False
    finally:
        p.wait(timeout=30)


@pytest.mark.parametrize("pid", [0, -1, -os.getpid(), True, False, None, "123", 1.0, 2**70])
def test_invalid_pids_are_false_without_group_signals(pid, monkeypatch):
    calls = []
    real_kill = os.kill

    def spy(p, sig):
        calls.append((p, sig))
        return real_kill(p, sig)

    monkeypatch.setattr(os, "kill", spy)
    assert pid_alive(pid) is False
    # 0 이하(프로세스 그룹·모든 프로세스)와 정수가 아닌 값에는 os.kill 을 부르지 않는다
    assert all(p > 0 for p, _ in calls), calls


def test_eperm_means_alive_and_esrch_means_dead(monkeypatch):
    def eperm(pid, sig):
        raise PermissionError(errno.EPERM, "Operation not permitted")

    monkeypatch.setattr(os, "kill", eperm)
    assert pid_alive(424242) is True

    def esrch(pid, sig):
        raise ProcessLookupError(errno.ESRCH, "No such process")

    monkeypatch.setattr(os, "kill", esrch)
    assert pid_alive(424242) is False


def test_never_calls_os_kill_on_native_windows(monkeypatch):
    def boom(pid, sig):
        raise AssertionError("Windows 에서 os.kill(pid, 0) 은 CTRL_C_EVENT 다")

    monkeypatch.setattr(os, "kill", boom)
    monkeypatch.setattr(sys, "platform", "win32")
    with pytest.raises(UnsupportedPlatform) as ei:
        pid_alive(os.getpid())
    assert ei.value.code == "unsupported_platform" and "WSL" in (ei.value.hint or "")
    assert pid_alive(0) is False  # 깨진 값은 플랫폼과 무관하게 False


def test_stat_state_parsing_uses_last_paren():
    assert procutil._stat_state(b"123 (evil) Z x) S 1 2 3") == "S"
    assert procutil._stat_state(b"123 (openocd) Z 1 2 3") == "Z"
    assert procutil._stat_state(b"123 (a b) X") == "X"
    assert procutil._stat_state(b"garbage") is None
    assert procutil._stat_state(b"123 (x)") is None


def test_unreadable_proc_falls_back_to_kill_result(monkeypatch):
    monkeypatch.setattr(procutil, "_proc_state", lambda pid: None)  # /proc 없음(macOS 등)
    assert pid_alive(os.getpid()) is True


def test_openocd_uses_core_pid_alive():
    from openocd_mcp import process

    assert process.pid_alive is pid_alive


# ---------------------------------------------------------------------------
# 펌웨어 에뮬레이션용 추가: 소유 기록·신원·pidfd·프로세스 그룹 종료·/proc 훑기 (리눅스 /proc 필요)
# ---------------------------------------------------------------------------

linux_only = pytest.mark.skipif(not HAS_PROC or not hasattr(os, "pidfd_open"), reason="리눅스 /proc 와 pidfd 가 필요")


def _spawn(argv, **kw):
    """새 세션(그룹 리더)으로 띄운다. 테스트는 끝에 꼭 _reap 한다."""
    kw.setdefault("start_new_session", True)
    return subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, **kw)


def _reap(p):
    if p.poll() is None:
        try:
            os.killpg(p.pid, 9) if p.pid == os.getpgid(p.pid) else p.kill()
        except (ProcessLookupError, PermissionError):
            pass
    p.wait(timeout=30)


def _wait_state(pid, states, timeout=10.0):
    deadline = time.monotonic() + timeout
    while True:
        st = procutil.proc_stat(pid)
        if st is not None and st[0] in states:
            return st
        assert time.monotonic() < deadline, st
        time.sleep(0.01)


def _group_alive(pgid):
    return procutil._group_members(pgid, None)


@linux_only
def test_proc_stat_boot_id_pid_ns():
    st = procutil.proc_stat(os.getpid())
    assert st is not None and st[0] in "RS" and st[1] > 0
    assert procutil.proc_stat(os.getpid())[1] == st[1]
    for bad in (0, -1, True, None, "1", 2**70):
        assert procutil.proc_stat(bad) is None
    bid = procutil.boot_id()
    assert bid and len(bid) == 36 and bid.count("-") == 4
    ns = procutil.pid_ns()
    assert ns and ns.startswith("pid:[")


@linux_only
def test_owner_record_and_alive_branches(monkeypatch):
    rec = procutil.owner_record("emu-mcp", session_id="emu-001")
    assert {k: rec[k] for k in ("server", "pid", "session_id")} == {"server": "emu-mcp", "pid": os.getpid(), "session_id": "emu-001"}
    assert set(rec) >= {"start_ticks", "boot_id", "pid_ns", "host", "created_at"}
    assert rec["start_ticks"] == procutil.proc_stat(os.getpid())[1]
    with pytest.raises(ValueError):
        procutil.owner_record("emu-mcp", pid=1)
    assert procutil.owner_alive(rec) is True

    dead = subprocess.Popen([sys.executable, "-c", "pass"])
    dead.wait(timeout=30)
    gone = dict(rec, pid=dead.pid, start_ticks=None)
    assert procutil.owner_alive(gone) is False
    assert procutil.owner_alive(dict(gone, host="another-host")) is True  # 다른 호스트는 확인할 수 없다 → 살아 있음
    assert procutil.owner_alive(dict(gone, pid_ns="pid:[1]")) is True  # 다른 PID 네임스페이스 → 살아 있음
    assert procutil.owner_alive(dict(rec, boot_id="00000000-0000-0000-0000-000000000000")) is False  # 다른 부팅 → 죽음
    assert procutil.owner_alive(dict(rec, boot_id="00000000-0000-0000-0000-000000000000", pid_ns="pid:[1]")) is False
    assert procutil.owner_alive(dict(rec, start_ticks=rec["start_ticks"] + 1)) is False  # PID 재사용
    assert procutil.owner_alive(dict(rec, start_ticks=str(rec["start_ticks"]))) is True
    for bad in (None, True, 0, -5, "abc", 1.5):
        assert procutil.owner_alive(dict(rec, pid=bad)) is False, bad
    assert procutil.owner_alive("not a dict") is False  # type: ignore[arg-type]
    old = dict(rec)
    old.pop("pid_ns")  # 옛 기록(pid_ns 없음)도 읽는다
    assert procutil.owner_alive(old) is True

    z = subprocess.Popen([sys.executable, "-c", "pass"])
    try:
        zst = _wait_state(z.pid, "Z")
        assert procutil.owner_alive(dict(rec, pid=z.pid, start_ticks=zst[1])) is False  # 좀비 → 죽음
    finally:
        z.wait(timeout=30)


@linux_only
def test_proc_identity_of_a_session_leader(tmp_path):
    p = _spawn(["sleep", "60"], cwd=tmp_path)
    try:
        _wait_state(p.pid, "S")
        ident = procutil.proc_identity(p.pid)
        assert ident is not None
        assert ident["uid"] == os.getuid()
        assert os.path.realpath(ident["cwd"]) == os.path.realpath(tmp_path)
        assert os.path.realpath(ident["exe"]) == os.path.realpath(f"/proc/{p.pid}/exe")
        assert ident["pgid"] == p.pid == ident["sid"] and ident["ppid"] == os.getpid()
        assert ident["start_ticks"] == procutil.proc_stat(p.pid)[1]
        assert ident["state"] == "S" and ident["cmdline"] == ["sleep", "60"]
    finally:
        _reap(p)
    assert procutil.proc_identity(p.pid) is None
    assert procutil.proc_identity(0) is None


@linux_only
def test_proc_identity_refuses_pid_reused_during_reads(monkeypatch):
    before = procutil.proc_stat(os.getpid())
    monkeypatch.setattr(procutil, "proc_stat", lambda pid: ("S", before[1] + 1))
    assert procutil.proc_identity(os.getpid()) is None


@linux_only
def test_kill_process_group_rechecks_identity_after_grace(monkeypatch):
    """TERM 유예 중 원래 그룹이 사라지고 번호가 재사용되면 새 그룹에는 KILL 을 보내지 않는다."""
    pgid = os.getpid() + 100000
    current_ticks = [10]
    sent = []
    monkeypatch.setattr(procutil, "proc_stat", lambda pid: ("S", current_ticks[0]))
    monkeypatch.setattr(procutil.os, "getpgid", lambda pid: pgid)
    monkeypatch.setattr(procutil.os, "killpg", lambda group, sig: sent.append(sig))
    monkeypatch.setattr(procutil, "_group_members", lambda group, ticks: [pgid + 1])

    def reuse_after_term(group, ticks, timeout):
        current_ticks[0] += 1
        return False

    monkeypatch.setattr(procutil, "_wait_group_empty", reuse_after_term)
    assert procutil.kill_process_group(pgid, grace=0, expect_start_ticks=10) == "refused"
    assert sent == [signal.SIGTERM]


@linux_only
def test_kill_process_group_rechecks_identity_before_first_signal(monkeypatch):
    pgid = os.getpid() + 100000
    samples = iter([("S", 10), ("S", 11)])
    sent = []
    monkeypatch.setattr(procutil, "proc_stat", lambda pid: next(samples))
    monkeypatch.setattr(procutil.os, "getpgid", lambda pid: pgid)
    monkeypatch.setattr(procutil.os, "killpg", lambda group, sig: sent.append(sig))
    assert procutil.kill_process_group(pgid, expect_start_ticks=10) == "refused"
    assert sent == []


@linux_only
def test_pidfd_open_and_signal():
    p = _spawn(["sleep", "60"])
    fd = procutil.open_pidfd(p.pid)
    try:
        assert fd is not None
        assert procutil.pidfd_signal(fd, 0) is True
        assert procutil.pidfd_signal(fd, 15) is True
        assert p.wait(timeout=30) == -15
        assert procutil.pidfd_signal(fd, 0) is False  # 끝나고 거둔 프로세스 → ESRCH → False
    finally:
        os.close(fd)
        _reap(p)
    assert procutil.open_pidfd(p.pid) is None  # 없는 프로세스
    assert procutil.open_pidfd(0) is None and procutil.open_pidfd(True) is None


@linux_only
def test_kill_process_group_terminates_leader_with_identity_and_pidfd():
    p = _spawn(["sleep", "60"])
    fd = None
    try:
        st = _wait_state(p.pid, "S")
        fd = procutil.open_pidfd(p.pid)
        assert procutil.kill_process_group(p.pid, grace=5, expect_start_ticks=st[1], pidfd=fd) == "terminated"
        assert p.wait(timeout=30) == -15  # 거두는 것은 부모 — 헬퍼는 waitpid 하지 않는다(종료 코드가 남아 있다)
    finally:
        if fd is not None:
            os.close(fd)
        _reap(p)


@linux_only
def test_kill_process_group_escalates_to_sigkill():
    p = _spawn(["sh", "-c", 'trap "" TERM; sleep 60'])
    try:
        # sleep 은 trap 을 건 뒤에야 뜬다 — 그룹에 'sleep 60' 이 보일 때까지 기다린다(dash 가 마지막 명령을 exec 해도 맞다)
        deadline = time.monotonic() + 10
        while not any((procutil.proc_identity(m) or {}).get("cmdline") == ["sleep", "60"] for m in _group_alive(p.pid)):
            assert time.monotonic() < deadline
            time.sleep(0.02)
        t0 = time.monotonic()
        assert procutil.kill_process_group(p.pid, grace=0.5) == "killed"
        assert time.monotonic() - t0 < 10
        assert p.wait(timeout=30) == -9
        assert _group_alive(p.pid) == []
    finally:
        _reap(p)


@linux_only
def test_kill_process_group_reaches_grandchildren():
    p = _spawn(["sh", "-c", "sleep 60 & sleep 60 & wait"])
    try:
        st = _wait_state(p.pid, "S")
        deadline = time.monotonic() + 10
        while len(_group_alive(p.pid)) < 3:
            assert time.monotonic() < deadline
            time.sleep(0.02)
        assert procutil.kill_process_group(p.pid, grace=5, expect_start_ticks=st[1]) == "terminated"
        assert _group_alive(p.pid) == []
    finally:
        _reap(p)


@linux_only
def test_kill_process_group_refuses_wrong_targets():
    q = subprocess.Popen(["sleep", "60"])  # 새 세션이 아님 → 그룹 리더가 아님
    p = _spawn(["sleep", "60"])
    try:
        st = _wait_state(p.pid, "S")
        assert procutil.kill_process_group(q.pid) == "refused"
        assert procutil.kill_process_group(p.pid, expect_start_ticks=st[1] + 1) == "refused"  # 시작 시각 불일치
        assert procutil.pid_alive(q.pid) and procutil.pid_alive(p.pid)  # 신호를 받지 않았다
        for bad in (0, 1, -p.pid, True, os.getpid(), os.getpgrp()):
            assert procutil.kill_process_group(bad) == "refused", bad
    finally:
        _reap(q)
        _reap(p)


@linux_only
def test_kill_process_group_gone_and_exited():
    p = _spawn(["sh", "-c", "exit 0"])
    st = _wait_state(p.pid, "Z")
    try:
        assert procutil.kill_process_group(p.pid, expect_start_ticks=st[1]) == "exited"  # 좀비 리더, 살아 있는 구성원 없음
    finally:
        p.wait(timeout=30)
    assert procutil.kill_process_group(p.pid) == "gone"  # 거둔 뒤


@linux_only
def test_kill_process_group_with_reaped_leader_and_surviving_member():
    p = _spawn(["sh", "-c", "sleep 60 & exit 0"])
    p.wait(timeout=30)  # 리더는 거뒀고 백그라운드 sleep 이 같은 그룹에 남는다
    try:
        deadline = time.monotonic() + 10
        while not _group_alive(p.pid):
            assert time.monotonic() < deadline
            time.sleep(0.02)
        members = _group_alive(p.pid)
        # 리더를 거둔 뒤에는 getpgid(pgid) == pgid 를 확인할 수 없으므로 신호를 보내지 않는다(신원 확인 요구와 무관)
        assert procutil.kill_process_group(p.pid, expect_start_ticks=12345) == "refused"
        assert procutil.kill_process_group(p.pid, grace=5) == "refused"
        assert _group_alive(p.pid) == members and all(procutil.pid_alive(m) for m in members)
    finally:
        for pid in _group_alive(p.pid):
            os.kill(pid, 9)
        deadline = time.monotonic() + 10
        while _group_alive(p.pid) and time.monotonic() < deadline:
            time.sleep(0.02)
    assert procutil.kill_process_group(p.pid) == "gone"


@linux_only
def test_find_processes_by_uid_cwd_and_exe(tmp_path):
    other = tmp_path / "other"
    other.mkdir()
    p = _spawn(["sleep", "60"], cwd=tmp_path)
    try:
        _wait_state(p.pid, "S")
        exe = os.path.realpath(f"/proc/{p.pid}/exe")
        assert procutil.find_processes(uid=os.getuid(), cwd=tmp_path, exe_allow=[exe]) == [p.pid]
        assert procutil.find_processes(uid=os.getuid(), cwd=str(tmp_path) + "/.", exe_allow={exe}) == [p.pid]
        assert procutil.find_processes(uid=os.getuid(), cwd=other, exe_allow=[exe]) == []
        assert procutil.find_processes(uid=os.getuid(), cwd=tmp_path, exe_allow=[sys.executable]) == []
        assert procutil.find_processes(uid=os.getuid() + 1, cwd=tmp_path, exe_allow=[exe]) == []
        me = procutil.find_processes(uid=os.getuid(), cwd=os.getcwd(), exe_allow=[os.path.realpath(sys.executable)])
        assert os.getpid() not in me
    finally:
        _reap(p)
    assert procutil.find_processes(uid=os.getuid(), cwd=tmp_path, exe_allow=[exe]) == []


@linux_only
def test_find_processes_tolerates_deleted_executable(tmp_path):
    import shutil

    exe = tmp_path / "fake-emulator"
    shutil.copy2(os.path.realpath(shutil.which("sleep")), exe)
    os.chmod(exe, 0o755)
    p = _spawn([str(exe), "60"], cwd=tmp_path)
    try:
        _wait_state(p.pid, "S")
        exe.unlink()  # 설치를 바꾼 뒤의 옛 프로세스: /proc/<pid>/exe 가 '… (deleted)'
        assert os.readlink(f"/proc/{p.pid}/exe").endswith(" (deleted)")
        assert procutil.find_processes(uid=os.getuid(), cwd=tmp_path, exe_allow=[str(exe)]) == [p.pid]
        ident = procutil.proc_identity(p.pid)
        assert ident["exe"].endswith(" (deleted)")
    finally:
        _reap(p)
