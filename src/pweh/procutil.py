"""프로세스 유틸 (코어) — port-routing 설계 G9.

- :func:`pid_alive`: PID 생존 확인. POSIX 는 ``os.kill(pid, 0)``(EPERM = 있음, ESRCH = 없음)에 리눅스 좀비 검사
  (``/proc/<pid>/stat`` 의 상태 Z·X = 끝난 것)를 더한다.
  네이티브 Windows 에서는 ``os.kill(pid, 0)`` 을 **부르지 않는다**. CPython 은 Windows 에서 signal 0 을 ``CTRL_C_EVENT`` 로 보고
  ``GenerateConsoleCtrlEvent`` 를 부르므로(TerminateProcess 가 아님) 생존 검사가 모든 pid 를 살아 있다고 보거나 OSError 를 낸다.
  OpenProcess·GetExitCodeProcess 로 이식(설계 §12)하기 전까지는 :class:`UnsupportedPlatform` 을 낸다
  (서버는 win32 에서 아예 시작하지 않는다 — ``pweh.mcpkit.create_server``).

프로세스 그룹 종료(``killpg``) 4곳을 여기로 모으는 일은 P1 이다.
"""

from __future__ import annotations

import errno
import os
import sys
from pathlib import Path

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


__all__ = ["UnsupportedPlatform", "pid_alive"]
