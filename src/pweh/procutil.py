"""프로세스 유틸 (코어) — port-routing 설계 G9.

- :func:`pid_alive`: PID 생존 확인. POSIX 는 ``os.kill(pid, 0)``(EPERM = 있음, ESRCH = 없음)에 리눅스 좀비 검사
  (``/proc/<pid>/stat`` 의 상태 Z·X = 끝난 것)를 더한다.
  네이티브 Windows 에서는 ``os.kill(pid, 0)`` 을 **부르지 않는다**. CPython 은 Windows 에서 signal 0 을 ``CTRL_C_EVENT`` 로 보고
  ``GenerateConsoleCtrlEvent`` 를 부르므로(TerminateProcess 가 아님) 생존 검사가 모든 pid 를 살아 있다고 보거나 OSError 를 낸다.
  OpenProcess·GetExitCodeProcess 로 이식(설계 §12)하기 전까지는 :class:`UnsupportedPlatform` 을 낸다
  (서버는 win32 에서 아예 시작하지 않는다 — ``pweh.mcpkit.create_server``).

P1의 ESP·sigrok 외부 실행기는 이 모듈로 그룹 종료를 위임하며 :func:`child_exited`의
WNOWAIT 관찰 뒤 :func:`process_group_empty`로 종료를 별도 확인한다. 기존 emu·OpenOCD
호출 경로와 :func:`kill_process_group`의 반환 문자열 의미는 유지한다(``killed``는 SIGKILL이 필요했다는 뜻).

펌웨어 에뮬레이션(pweh-emu, 설계 docs/design/emulation.md §6.2)용으로 더한 것 (리눅스 ``/proc`` 기준, esp_mcp 의 사본을 일반화):

- :func:`proc_stat`·:func:`boot_id`·:func:`pid_ns`·:func:`owner_record`·:func:`owner_alive`: 세션 파일의 소유 기록과 주인 생존 확인.
- :func:`proc_identity`: 고아 정리가 대상을 확인하는 데 쓰는 신원(uid·실행 파일·cwd·그룹·시작 시각·상태·명령줄).
- :func:`open_pidfd`·:func:`pidfd_signal`: PID 재사용과 경쟁하지 않는 신호(pidfd 는 그 프로세스만 가리킨다).
- :func:`kill_process_group`: 그룹 리더 확인 뒤 SIGTERM → 유예 → SIGKILL. 자식을 거두지(waitpid) 않는다 — 거두는 것은 부모의 몫이다
  (``subprocess.Popen`` 은 이미 거둔 자식의 종료 코드를 0 으로 본다).
- :func:`find_processes`: ``/proc`` 를 훑어 uid·cwd·실행 파일로 프로세스를 찾는다(exec 전 창의 고아 찾기).
"""

from __future__ import annotations

import errno
import math
import os
import signal
import socket
import sys
import time
from pathlib import Path
from typing import Any, Collection

from .errors import PwehError


class UnsupportedPlatform(PwehError):
    """이 플랫폼에서 안전하게 구현되지 않은 동작."""

    code = "unsupported_platform"


def _stat_state(raw: bytes) -> str | None:
    """``/proc/<pid>/stat`` 내용에서 상태 글자(R/S/D/Z/X/…)를 꺼낸다. comm 에 공백·괄호가 있어도 마지막 ')' 뒤를 본다."""
    _, sep, rest = raw.rpartition(b")")
    if not sep:
        return None
    fields = rest.split()
    if not fields:
        return None
    return fields[0].decode("ascii", "replace")


def _proc_state(pid: int) -> str | None:
    """리눅스 프로세스 상태 글자. ``/proc`` 가 없거나(macOS) 읽을 수 없으면 None."""
    try:
        raw = Path(f"/proc/{pid}/stat").read_bytes()
    except OSError:
        return None
    return _stat_state(raw)


def pid_alive(pid: int) -> bool:
    """PID 의 프로세스가 살아 있으면 True. 좀비(끝났지만 부모가 거두지 않음)는 끝난 것으로 본다.

    - bool·정수가 아닌 값·0 이하는 False 다. ``os.kill(0, 0)`` 은 자기 프로세스 그룹, 음수는 그룹·모든 프로세스에 대한
      검사라 상태 파일의 깨진 값이 '살아 있음'으로 보이기 때문이다. 플랫폼 pid 범위를 넘는 값(OverflowError)도 False.
    - EPERM(다른 사용자의 프로세스)은 True, ESRCH 는 False.
    - ``/proc`` 를 읽을 수 없으면 좀비 여부를 모르므로 ``os.kill`` 결과(살아 있음)를 따른다.
    - 네이티브 Windows(``sys.platform == "win32"``)는 :class:`UnsupportedPlatform` (``os.kill`` 을 부르지 않음).
    """
    if isinstance(pid, bool) or not isinstance(pid, int) or pid <= 0:
        return False
    if sys.platform == "win32":
        raise UnsupportedPlatform(
            "네이티브 Windows 에서는 PID 생존 확인을 지원하지 않습니다(os.kill(pid, 0) 은 Windows 에서 콘솔 Ctrl-C 이벤트가 됨).",
            hint="PWEH 서버는 WSL 안에서 실행하세요.",
        )
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True  # 프로세스는 있지만 신호를 보낼 권한이 없다
    except OverflowError:
        return False
    except OSError as exc:
        if exc.errno == errno.ESRCH:
            return False
        if exc.errno == errno.EPERM:
            return True
        raise
    return _proc_state(pid) not in ("Z", "X")


# ---------------------------------------------------------------------------
# 소유 기록·신원 (리눅스 /proc)
# ---------------------------------------------------------------------------


def _valid_pid(pid: Any) -> bool:
    return not isinstance(pid, bool) and isinstance(pid, int) and pid > 0


def _stat_fields(pid: int) -> list[str] | None:
    """``/proc/<pid>/stat`` 의 comm 뒤 필드들(0 = 상태 = 3번째 필드). 없거나 읽을 수 없으면 None."""
    if not _valid_pid(pid):
        return None
    try:
        raw = Path(f"/proc/{pid}/stat").read_bytes()
    except (OSError, OverflowError, ValueError):
        return None
    _, sep, rest = raw.rpartition(b")")
    if not sep:
        return None
    fields = rest.decode("ascii", "replace").split()
    return fields if len(fields) >= 20 else None


def proc_stat(pid: int) -> tuple[str, int] | None:
    """(상태 글자, 시작 시각 clock tick) — ``/proc/<pid>/stat`` 의 3번째·22번째 필드. 없거나 읽을 수 없으면 None."""
    f = _stat_fields(pid)
    if f is None:
        return None
    try:
        return f[0], int(f[19])
    except ValueError:
        return None


def boot_id() -> str | None:
    """이 커널 부팅의 id(``/proc/sys/kernel/random/boot_id``). 네임스페이스와 무관하다."""
    try:
        return Path("/proc/sys/kernel/random/boot_id").read_text(encoding="ascii").strip() or None
    except OSError:
        return None


def pid_ns() -> str | None:
    """이 프로세스의 PID 네임스페이스(``readlink /proc/self/ns/pid``, 예: ``pid:[4026531836]``)."""
    try:
        return os.readlink("/proc/self/ns/pid") or None
    except OSError:
        return None


def owner_record(server: str, **extra: Any) -> dict[str, Any]:
    """이 서버 프로세스의 소유 기록 ``{server, pid, start_ticks, boot_id, pid_ns, host, created_at, …extra}``.

    extra 는 기본 키를 덮어쓸 수 없다(덮어쓰려 하면 ValueError).
    """
    from .fsutil import utcnow_iso

    st = proc_stat(os.getpid())
    rec: dict[str, Any] = {
        "server": server,
        "pid": os.getpid(),
        "start_ticks": st[1] if st else None,
        "boot_id": boot_id(),
        "pid_ns": pid_ns(),
        "host": socket.gethostname(),
        "created_at": utcnow_iso(),
    }
    clash = sorted(set(rec) & set(extra))
    if clash:
        raise ValueError(f"owner_record 의 기본 키는 덮어쓸 수 없습니다: {clash}")
    rec.update(extra)
    return rec


def _as_int(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str) and value.strip().isdigit():
        return int(value.strip())
    return None


def owner_alive(rec: dict[str, Any]) -> bool:
    """소유 기록의 주인 프로세스가 살아 있는지.

    순서: 다른 호스트 → 살아 있음(확인할 수 없음). 다른 부팅(boot_id) → 죽음(재부팅이면 모든 네임스페이스가 끝났다).
    다른 PID 네임스페이스(둘 다 알 때) → 살아 있음(이 네임스페이스에서는 그 PID 를 볼 수 없다).
    그 밖에는 PID: 없음·좀비·깨진 값 → 죽음, ``start_ticks`` 가 기록과 다르면 PID 재사용 → 죽음.
    """
    if not isinstance(rec, dict):
        return False
    host = rec.get("host")
    if host and host != socket.gethostname():
        return True
    rbid, bid = rec.get("boot_id"), boot_id()
    if rbid and bid and rbid != bid:
        return False
    rns, ns = rec.get("pid_ns"), pid_ns()
    if rns and ns and rns != ns:
        return True
    pid = _as_int(rec.get("pid"))
    if pid is None or not pid_alive(pid):  # 0 이하·범위 밖·없음·좀비는 False, 권한 없음(EPERM)은 True
        return False
    st = proc_stat(pid)
    if st is not None:
        if st[0] in ("Z", "X"):
            return False
        want = rec.get("start_ticks")
        if want is not None and _as_int(want) != st[1]:
            return False
    return True


def _readlink(path: str) -> str | None:
    try:
        return os.readlink(path)
    except OSError:
        return None


def _real_uid(pid: int) -> int | None:
    try:
        text = Path(f"/proc/{pid}/status").read_text(encoding="ascii", errors="replace")
    except OSError:
        return None
    for line in text.splitlines():
        if line.startswith("Uid:"):
            parts = line.split()
            if len(parts) >= 2 and parts[1].isdigit():
                return int(parts[1])
    return None


def proc_identity(pid: int) -> dict[str, Any] | None:
    """고아 확인용 신원 ``{uid, exe, cwd, pgid, start_ticks, state, cmdline, ppid, sid}``. 프로세스가 없으면 None.

    - uid: ``/proc/<pid>/status`` 의 ``Uid:`` 실제 uid(``/proc/<pid>`` 소유자는 덤프 불가 프로세스면 root 라 쓰지 않는다).
    - exe·cwd: ``readlink`` 결과 그대로(지운 파일이면 ``" (deleted)"`` 접미). 권한이 없거나 좀비면 None.
    - cmdline: NUL 로 나눈 인자 목록(surrogateescape). 좀비·커널 스레드는 빈 목록.
    """
    f = _stat_fields(pid)
    if f is None:
        return None
    try:
        ppid, pgid, sid, start_ticks = int(f[1]), int(f[2]), int(f[3]), int(f[19])
    except ValueError:
        return None
    cmdline: list[str] = []
    try:
        raw = Path(f"/proc/{pid}/cmdline").read_bytes()
    except OSError:
        raw = b""
    if raw:
        parts = raw.split(b"\0")
        if parts and parts[-1] == b"":
            parts.pop()
        cmdline = [p.decode("utf-8", "surrogateescape") for p in parts]
    identity = {
        "uid": _real_uid(pid),
        "exe": _readlink(f"/proc/{pid}/exe"),
        "cwd": _readlink(f"/proc/{pid}/cwd"),
        "pgid": pgid,
        "start_ticks": start_ticks,
        "state": f[0],
        "cmdline": cmdline,
        "ppid": ppid,
        "sid": sid,
    }
    # /proc 의 여러 파일을 읽는 동안 PID 가 재사용되면 서로 다른 프로세스의 필드를 합치지 않는다.
    after = proc_stat(pid)
    if after is None or after[1] != start_ticks:
        return None
    return identity


# ---------------------------------------------------------------------------
# 신호: pidfd 와 프로세스 그룹
# ---------------------------------------------------------------------------


def open_pidfd(pid: int) -> int | None:
    """``os.pidfd_open(pid)`` (close-on-exec). 프로세스가 없거나 커널·파이썬이 지원하지 않으면 None."""
    if not _valid_pid(pid):
        return None
    fn = getattr(os, "pidfd_open", None)
    if fn is None:
        return None
    try:
        return fn(pid)
    except (OSError, OverflowError):
        return None


def pidfd_signal(pidfd: int, sig: int) -> bool:
    """pidfd 가 가리키는 프로세스에 신호. 보냈으면 True, 프로세스가 이미 끝났으면(ESRCH) False. 그 밖의 오류는 OSError 그대로."""
    try:
        signal.pidfd_send_signal(pidfd, sig)
    except ProcessLookupError:
        return False
    return True


def _group_members(pgid: int, leader_ticks: int | None) -> list[int]:
    """프로세스 그룹 pgid 의 살아 있는(좀비 아닌) 프로세스. 리더 PID 가 재사용됐으면(시작 시각이 다름) 그 프로세스는 뺀다."""
    out: list[int] = []
    try:
        names = os.listdir("/proc")
    except OSError:
        return out
    for name in names:
        if not name.isdigit():
            continue
        pid = int(name)
        f = _stat_fields(pid)
        if f is None or f[0] in ("Z", "X"):
            continue
        try:
            if int(f[2]) != pgid:
                continue
            if pid == pgid and leader_ticks is not None and int(f[19]) != leader_ticks:
                continue
        except ValueError:
            continue
        out.append(pid)
    return out


def _leader_gone(pgid: int, leader_ticks: int | None) -> bool:
    st = proc_stat(pgid)
    return st is None or st[0] in ("Z", "X") or (leader_ticks is not None and st[1] != leader_ticks)


def _signal_group(pgid: int, pidfd: int | None, sig: int, leader_ticks: int) -> bool:
    """매 신호 직전에도 리더 신원을 확인한다(유예 중 PID 재사용으로 새 그룹을 종료하지 않게)."""
    current = proc_stat(pgid)
    if current is None or current[1] != leader_ticks:
        return False
    try:
        if os.getpgid(pgid) != pgid:
            return False
    except ProcessLookupError:
        return False
    if pidfd is not None:
        try:
            pidfd_signal(pidfd, sig)
        except OSError:
            pass
    try:
        os.killpg(pgid, sig)
    except (ProcessLookupError, PermissionError):
        pass
    return True


def _wait_group_empty(pgid: int, leader_ticks: int | None, timeout: float) -> bool:
    deadline = time.monotonic() + max(0.0, timeout)
    while True:
        if _leader_gone(pgid, leader_ticks) and not _group_members(pgid, leader_ticks):
            return True
        if time.monotonic() >= deadline:
            return False
        time.sleep(0.02)


def kill_process_group(pgid: int, *, grace: float = 3.0, expect_start_ticks: int | None = None,
                       pidfd: int | None = None) -> str:
    """새 세션으로 띄운 프로세스 그룹을 끝낸다: SIGTERM → grace 초 → SIGKILL. 자식을 거두지 않는다(부모가 거둔다).

    신원은 처음과 각 신호 직전에 확인한다. 리더(PID = pgid)가 있어야 하고(좀비여도 됨) ``os.getpgid(pgid) == pgid``(그룹 리더)여야 하며,
    ``expect_start_ticks`` 를 주면 리더의 시작 시각이 같아야 한다. 신호는 pidfd(주면, 리더만 정확히)와 ``killpg``(그룹 전체)로 보낸다.
    리더를 이미 거뒀으면 그룹 리더 확인을 할 수 없으므로 신호를 보내지 않는다 — 호출자는 리더를 거두기 전에 부른다.
    그룹이 비었는지는 ``/proc`` 에서 pgid 가 같은 살아 있는(좀비 아닌) 프로세스를 찾아 판단한다(좀비 리더만 남아도 ``killpg(pgid, 0)`` 은 성공한다).

    반환:
    - ``"refused"``: 현재 신원을 확인할 수 없어 다음 신호를 보내지 않음 — pgid 가 1 이하·자기 그룹·자기 PID, 리더가 그룹 리더가 아님,
      시작 시각 불일치, 또는 리더는 이미 거둬졌는데 같은 그룹 번호의 살아 있는 프로세스가 남음. 유예 중 신원이 바뀌었으면 앞선 TERM 은 보냈을 수 있다.
    - ``"gone"``: 리더도 살아 있는 구성원도 없음.
    - ``"exited"``: 리더가 이미 끝났고(좀비) 살아 있는 구성원이 없음 — 신호 없음.
    - ``"terminated"``: SIGTERM 뒤 grace 안에 그룹이 비었다.
    - ``"killed"``: SIGKILL 이 필요했다.
    """
    if sys.platform == "win32":
        raise UnsupportedPlatform("네이티브 Windows 에서는 프로세스 그룹 종료를 지원하지 않습니다.", hint="PWEH 서버는 WSL 안에서 실행하세요.")
    if not _valid_pid(pgid) or pgid <= 1 or pgid == os.getpid() or pgid == os.getpgrp():
        return "refused"
    st = proc_stat(pgid)
    if st is None:
        # 리더를 이미 거뒀다: getpgid(pgid) == pgid 를 확인할 수 없으므로 신호를 보내지 않는다(남은 구성원이 있으면 refused)
        return "refused" if _group_members(pgid, None) else "gone"
    state, leader_ticks = st
    if expect_start_ticks is not None and leader_ticks != expect_start_ticks:
        return "refused"
    try:
        if os.getpgid(pgid) != pgid:
            return "refused"
    except ProcessLookupError:
        return "refused" if _group_members(pgid, None) else "gone"
    if state in ("Z", "X") and not _group_members(pgid, leader_ticks):
        return "exited"
    if not _signal_group(pgid, pidfd, signal.SIGTERM, leader_ticks):
        return "refused"
    if _wait_group_empty(pgid, leader_ticks, grace):
        return "terminated"
    if not _leader_gone(pgid, leader_ticks) or _group_members(pgid, leader_ticks):
        if not _signal_group(pgid, pidfd, signal.SIGKILL, leader_ticks):
            return "refused"
    _wait_group_empty(pgid, leader_ticks, max(2.0, min(grace, 10.0)))
    return "killed"


def child_exited(pid: int) -> bool:
    """직접 띄운 자식의 종료를 거두지 않고 관찰한다. 그룹 정리 뒤 부모가 wait해야 한다."""
    try:
        return os.waitid(os.P_PID, pid, os.WEXITED | os.WNOHANG | os.WNOWAIT) is not None
    except ChildProcessError:
        return True


def signal_owned_group(pgid: int, sig: int, *, expect_start_ticks: int,
                       pidfd: int | None = None) -> bool | None:
    """Linux 소유 그룹에 대기 없이 TERM/KILL 한 번을 보낸다(True/부재 False/미확인 None).

    호출자는 직접 자식 리더를 WNOWAIT로 보존하여 신원 확인과 신호 사이 PID 재사용을 막아야 한다.
    pidfd는 신호0으로 유효성만 확인하며, 그룹 신호의 성공은 종료 확인이 아니다.
    기존 kill_process_group의 유예·반환 문자열 계약은 바꾸지 않는다.
    """
    if not sys.platform.startswith("linux"):
        raise UnsupportedPlatform("소유 pipe 그룹 신호는 Linux에서만 지원합니다.")
    if (not _valid_pid(pgid) or pgid <= 1 or pgid in (os.getpid(), os.getpgrp())
            or not _valid_pid(expect_start_ticks)
            or isinstance(sig, bool) or not isinstance(sig, int) or sig not in (signal.SIGTERM, signal.SIGKILL)
            or (pidfd is not None and (type(pidfd) is not int or pidfd < 0))):
        return None
    current = proc_stat(pgid)
    if current is None:
        try:
            os.getpgid(pgid)
        except ProcessLookupError:
            return False
        except (OSError, OverflowError):
            pass
        return None  # 읽기 실패를 부재로 바꾸지 않는다.
    if current[1] != expect_start_ticks:
        return None
    try:
        if os.getpgid(pgid) != pgid:
            return None
        if pidfd is not None:
            # 좀비 리더의 pidfd가 이미 종료를 알리더라도 남은 그룹 구성원은 별도로 정리한다.
            pidfd_signal(pidfd, 0)
        after = proc_stat(pgid)
        if after is None or after[1] != expect_start_ticks:
            return None
        os.killpg(pgid, sig)
    except ProcessLookupError:
        return False
    except (OSError, OverflowError, ValueError):
        return None
    return True


def process_group_empty(pgid: int, *, expect_start_ticks: int | None,
                        deadline: float | None = None) -> bool | None:
    """소유한 그룹의 비좀비 구성원 부재를 확인한다(True/False/미확인 None).

    종료 신호의 결과 문자열과 별개다. PID 재사용·관찰 실패·상한은 부재로 판정하지 않는다.
    외부 실행 소비자는 리더를 거두기 전에 호출하고, 미확인이면 lease를 보존한다.
    deadline은 선택적인 monotonic 절대 시각이며 기존 2초 관찰 상한을 늘리지 않는다.
    """
    if deadline is not None:
        try:
            valid = not isinstance(deadline, bool) and isinstance(deadline, (int, float)) and math.isfinite(deadline)
        except OverflowError:
            valid = False
        if not valid:
            raise ValueError("그룹 관찰 deadline은 유한한 시각이어야 합니다.")
    started = time.monotonic()
    until = started + 2.0 if deadline is None else min(started + 2.0, deadline)
    if started >= until:
        return None
    if not _valid_pid(pgid) or pgid <= 1 or expect_start_ticks is None:
        return None
    leader = proc_stat(pgid)
    if leader is not None and leader[1] != expect_start_ticks:
        return None
    if time.monotonic() >= until:
        return None
    try:
        with os.scandir("/proc") as entries:
            count = 0
            for entry in entries:
                if time.monotonic() >= until:
                    return None
                if not entry.name.isdigit():
                    continue
                count += 1
                if count > 65536:
                    return None
                try:
                    raw = Path(entry.path, "stat").read_bytes()
                except FileNotFoundError:
                    continue  # 관찰 도중 끝난 프로세스
                except OSError:
                    return None
                _, sep, tail = raw.rpartition(b")")
                fields = tail.split()
                if not sep or len(fields) < 20:
                    return None
                try:
                    member = int(fields[2]) == pgid
                except ValueError:
                    return None
                if member and fields[0] not in (b"Z", b"X"):
                    return False
    except OSError:
        return None
    return True if time.monotonic() < until else None


def find_processes(*, uid: int, cwd: str | os.PathLike[str], exe_allow: Collection[str | os.PathLike[str]]) -> list[int]:
    """``/proc`` 를 훑어 같은 uid(실제 uid)이고, cwd 의 실제 경로가 같고, 실행 파일의 실제 경로가 허용 목록에 있는 프로세스(자기 제외, 좀비 제외).

    실행 파일 경로의 ``" (deleted)"`` 접미는 떼고 비교한다(설치를 바꾼 뒤에도 옛 프로세스를 찾게). 허용 목록도 실제 경로로 바꿔 비교한다.
    """
    target = os.path.realpath(os.fspath(cwd))
    allow = {os.path.realpath(os.fspath(p)) for p in exe_allow} | {os.fspath(p) for p in exe_allow}
    me = os.getpid()
    out: list[int] = []
    try:
        names = os.listdir("/proc")
    except OSError:
        return out
    for name in names:
        if not name.isdigit():
            continue
        pid = int(name)
        if pid == me:
            continue
        c = _readlink(f"/proc/{pid}/cwd")
        if c is None or os.path.realpath(c) != target:
            continue
        e = _readlink(f"/proc/{pid}/exe")
        if e is None:
            continue
        if e.endswith(" (deleted)"):
            e = e[: -len(" (deleted)")]
        if e not in allow and os.path.realpath(e) not in allow:
            continue
        st = proc_stat(pid)
        if st is None or st[0] in ("Z", "X"):
            continue
        if _real_uid(pid) != uid:
            continue
        out.append(pid)
    return sorted(out)


__all__ = [
    "UnsupportedPlatform",
    "boot_id",
    "child_exited",
    "find_processes",
    "kill_process_group",
    "open_pidfd",
    "owner_alive",
    "owner_record",
    "pid_alive",
    "pid_ns",
    "pidfd_signal",
    "proc_identity",
    "proc_stat",
    "process_group_empty",
]
