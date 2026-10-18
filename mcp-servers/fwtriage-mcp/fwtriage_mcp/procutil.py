"""외부 프로세스 실행 (unsquashfs 등).

규칙:
- 인자 리스트만 사용 (셸 문자열 금지), stdin=DEVNULL (MCP stdio 프로토콜 바이트를 빼앗지 않게),
  stdout/stderr 는 파이프로 받아 상한까지만 보관 (fd 1 상속 금지 — 프로토콜 채널 오염 방지)
- start_new_session=True 로 새 프로세스 그룹을 만들고, 취소/시간 초과/서버 종료 시 그룹 전체를 종료
- LC_ALL=C 의 최소 환경
"""

from __future__ import annotations

import atexit
import logging
import os
import shutil
import signal
import subprocess
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from .common import Cancelled, Ctl

log = logging.getLogger("pweh.fwtriage")

_ACTIVE: set[subprocess.Popen] = set()
_ACTIVE_LOCK = threading.Lock()


def _kill_group(p: subprocess.Popen, grace: float = 1.0) -> None:
    if p.poll() is not None:
        return
    try:
        os.killpg(p.pid, signal.SIGTERM)
    except (ProcessLookupError, PermissionError):
        pass
    deadline = time.monotonic() + grace
    while time.monotonic() < deadline:
        if p.poll() is not None:
            break
        time.sleep(0.05)
    if p.poll() is None:
        try:
            os.killpg(p.pid, signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            pass
        try:
            p.wait(timeout=2)
        except subprocess.TimeoutExpired:  # pragma: no cover
            pass


def _kill_all() -> None:  # pragma: no cover - 프로세스 종료 시
    with _ACTIVE_LOCK:
        procs = list(_ACTIVE)
    for p in procs:
        _kill_group(p, grace=0.2)


atexit.register(_kill_all)


@dataclass
class ProcResult:
    argv: list[str]
    returncode: int | None
    stdout: bytes
    stderr: bytes
    timed_out: bool = False
    killed_reason: str | None = None
    stdout_truncated: bool = False
    stderr_truncated: bool = False
    elapsed: float = 0.0
    extra: dict[str, Any] = field(default_factory=dict)

    def stderr_tail(self, n: int = 20) -> list[str]:
        lines = self.stderr.decode("utf-8", "replace").splitlines()
        return lines[-n:]


def _reader(stream: Any, sink: list[bytes], cap: int, flag: list[bool]) -> None:
    total = 0
    try:
        while True:
            chunk = stream.read(65536)
            if not chunk:
                break
            if total < cap:
                take = chunk[: cap - total]
                sink.append(take)
                total += len(take)
                if len(take) < len(chunk):
                    flag[0] = True
            else:
                flag[0] = True
    except (OSError, ValueError):
        pass


def minimal_env() -> dict[str, str]:
    env = {
        "PATH": os.environ.get("PATH", "/usr/local/bin:/usr/bin:/bin"),
        "LC_ALL": "C",
        "LANG": "C",
        "HOME": os.environ.get("HOME", "/tmp"),
    }
    if os.environ.get("TMPDIR"):
        env["TMPDIR"] = os.environ["TMPDIR"]
    return env


def run_process(
    argv: list[str],
    *,
    ctl: Ctl,
    timeout: float,
    cwd: str | Path | None = None,
    max_stdout: int = 32 << 20,
    max_stderr: int = 1 << 20,
    on_poll: Callable[[], str | None] | None = None,
    poll_interval: float = 0.2,
    poll_every: float = 1.0,
) -> ProcResult:
    """프로세스를 실행하고 끝날 때까지 기다린다 (취소·시간 초과·on_poll 사유 발생 시 프로세스 그룹 종료)."""
    if not argv or not isinstance(argv, list) or not all(isinstance(a, str) for a in argv):
        raise ValueError("argv 는 문자열 리스트여야 합니다")
    t0 = time.monotonic()
    p = subprocess.Popen(
        argv,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        cwd=str(cwd) if cwd else None,
        env=minimal_env(),
        start_new_session=True,
        close_fds=True,
    )
    with _ACTIVE_LOCK:
        _ACTIVE.add(p)
    out: list[bytes] = []
    err: list[bytes] = []
    out_tr = [False]
    err_tr = [False]
    t_out = threading.Thread(target=_reader, args=(p.stdout, out, max_stdout, out_tr), daemon=True)
    t_err = threading.Thread(target=_reader, args=(p.stderr, err, max_stderr, err_tr), daemon=True)
    t_out.start()
    t_err.start()
    timed_out = False
    killed_reason = None
    cancelled = False
    last_poll = 0.0
    try:
        deadline = t0 + timeout
        while True:
            if p.poll() is not None:
                break
            if ctl.is_cancelled:
                cancelled = True
                _kill_group(p)
                break
            now = time.monotonic()
            if now > deadline:
                timed_out = True
                _kill_group(p)
                break
            if on_poll is not None and now - last_poll >= poll_every:
                last_poll = now
                reason = on_poll()
                if reason:
                    killed_reason = reason
                    _kill_group(p)
                    break
            time.sleep(poll_interval)
    finally:
        if p.poll() is None:
            _kill_group(p)
        t_out.join(timeout=3)
        t_err.join(timeout=3)
        for s in (p.stdout, p.stderr):
            try:
                if s:
                    s.close()
            except OSError:
                pass
        with _ACTIVE_LOCK:
            _ACTIVE.discard(p)
    if cancelled:
        raise Cancelled("작업이 취소되어 외부 프로세스를 종료했습니다.")
    return ProcResult(
        argv=argv,
        returncode=p.returncode,
        stdout=b"".join(out),
        stderr=b"".join(err),
        timed_out=timed_out,
        killed_reason=killed_reason,
        stdout_truncated=out_tr[0],
        stderr_truncated=err_tr[0],
        elapsed=round(time.monotonic() - t0, 3),
    )


def which_tool(candidates: list[str | None]) -> str | None:
    """후보(절대 경로 또는 이름) 중 실행 가능한 첫 번째."""
    for c in candidates:
        if not c:
            continue
        c = os.path.expanduser(c)
        if os.path.sep in c:
            if os.path.isfile(c) and os.access(c, os.X_OK):
                return c
        else:
            w = shutil.which(c)
            if w:
                return w
    return None


def tree_usage(root: Path, max_entries: int = 500000) -> tuple[int, int, int]:
    """(실제 디스크 사용 바이트(st_blocks*512), 논리 크기 합, 항목 수) — lstat, 링크 미추적."""
    used = 0
    logical = 0
    n = 0
    stack = [str(root)]
    while stack and n < max_entries:
        d = stack.pop()
        try:
            with os.scandir(d) as it:
                for e in it:
                    n += 1
                    try:
                        st = e.stat(follow_symlinks=False)
                    except OSError:
                        continue
                    used += getattr(st, "st_blocks", 0) * 512
                    logical += st.st_size
                    if e.is_dir(follow_symlinks=False):
                        stack.append(e.path)
        except OSError:
            continue
    return used, logical, n
