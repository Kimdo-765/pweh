"""케이스별 OpenOCD 세션 (프로세스 + TCL RPC 연결) 레지스트리.

세션은 MCP 서버 프로세스 메모리에 유지된다. 케이스 하나에 세션 하나.
- spawned : openocd_start 로 이 서버가 띄운 프로세스 (openocd_stop 이 종료시킨다)
- adopted : 서버 재시작 전에 이 케이스에서 띄운 프로세스를 openocd_attach 가 상태 파일로 찾아 입양
- attached: 외부에서 띄운 OpenOCD 에 연결만 함 (openocd_stop 은 기본적으로 연결만 끊는다)
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from pweh.errors import Busy, DeviceError, NotFound
from pweh.fsutil import utcnow_iso

from .process import OpenOcdProcess, read_log_since, tail_lines
from .parsers import diagnose
from .rpc import TclRpcClient


@dataclass
class OcdSession:
    case_id: str
    mode: str  # spawned | adopted | attached
    host: str
    port: int
    client: TclRpcClient
    proc: OpenOcdProcess | None = None
    log_path: Path | None = None
    log_offset: int = 0
    argv: list[str] = field(default_factory=list)
    version: dict[str, Any] = field(default_factory=dict)
    started_at: str = field(default_factory=utcnow_iso)
    started_mono: float = field(default_factory=time.monotonic)
    startup: dict[str, Any] = field(default_factory=dict)
    state_file: Path | None = None
    last_targets: list[dict[str, Any]] = field(default_factory=list)
    # 'target names' 로 확인한 타깃 이름 캐시 (세션 = OpenOCD 프로세스 시작/연결 단위). 요청한 이름이 없으면 다시 조회한다.
    target_names: frozenset[str] | None = None
    # --- semihosting 가드 (semihosting.py) -------------------------------------------------------------
    # 이 서버가 띄운(또는 입양한) OpenOCD 에 가드 proc 이 있어 RPC 로 확인·무력화할 수 있음 (attached 는 False)
    semihosting_managed: bool = False
    # disabled = 항상 끈다(기본) / enabled-by-approval = 사람이 승인한 명령이 켰음 → 끄지 않고 상태만 보고 (openocd_stop 까지)
    semihosting_policy: str = "disabled"
    # 세션의 OpenOCD 에서 가드가 찾은 'semihosting 을 켜는 proc' (호출은 DESTRUCTIVE 로 분류)
    semihost_procs: frozenset[str] = field(default_factory=frozenset)
    # 마지막 확인 결과 등 (openocd_status 가 보여 준다)
    semihosting: dict[str, Any] = field(default_factory=dict)
    # 명령이 시간 초과 등으로 끝을 확인하지 못해 아직 확인하지 못한 경우 → 다음 RPC 전에 먼저 확인한다
    semihosting_check_pending: bool = False
    # semihosting 을 끄지 못해 서버가 OpenOCD 를 종료한 경우의 기록
    semihosting_failsafe: dict[str, Any] | None = None

    @property
    def owned(self) -> bool:
        return self.mode in ("spawned", "adopted") and self.proc is not None

    def new_client(self, name: str) -> TclRpcClient:
        """백그라운드 작업용 별도 연결 (OpenOCD 는 다중 TCL 연결을 받는다)."""
        return TclRpcClient(self.host, self.port, name=name)

    def process_info(self) -> dict[str, Any] | None:
        if self.proc is None:
            return None
        info = {"pid": self.proc.pid, **self.proc.returncode_info()}
        return info

    def process_exited(self) -> bool:
        return self.proc is not None and not self.proc.alive

    def died_after_disconnect(self, wait: float = 1.5) -> bool:
        """연결이 끊겼을 때: 소유 프로세스가 (곧) 종료되는지 잠시 기다려 확인 (소켓이 프로세스 회수보다 먼저 닫히는 경쟁)."""
        if self.proc is None:
            return False
        return self.proc.wait(wait)

    def exit_error(self, context: str = "") -> DeviceError:
        """소유한 OpenOCD 프로세스가 죽었을 때의 표준 오류 (종료 코드 + 로그 꼬리 + 진단)."""
        info = self.process_info() or {}
        tail = tail_lines(self.log_path, 25)
        diag = diagnose("\n".join(tail))
        sig = info.get("signal")
        msg = f"OpenOCD 프로세스가 종료되었습니다 (exit_code={info.get('exit_code')}{', ' + sig if sig else ''})."
        if context:
            msg = f"{context}: {msg}"
        hint = "openocd_status 로 로그를 확인한 뒤 openocd_stop → openocd_start 로 다시 시작하세요."
        if sig == "SIGSEGV":
            hint = "OpenOCD 가 비정상 종료(SIGSEGV)했습니다. 해당 타깃/명령 조합의 OpenOCD 버그일 수 있습니다. " + hint
        return DeviceError(msg, hint=hint, data={"log_tail": tail, "diagnosis": diag})

    def run_log(self, max_bytes: int = 2 * 1024 * 1024) -> str:
        if self.log_path is None:
            return ""
        return read_log_since(self.log_path, self.log_offset, max_bytes=max_bytes)

    def describe(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "case_id": self.case_id,
            "mode": self.mode,
            "host": self.host,
            "tcl_port": self.port,
            "connected": self.client.connected,
            "version": self.version.get("raw") if self.version else None,
            "started_at": self.started_at,
            "uptime_seconds": round(time.monotonic() - self.started_mono, 1),
        }
        if self.proc is not None:
            out["process"] = self.process_info()
        if self.log_path is not None:
            out["log_path"] = str(self.log_path)
        return out


class SessionRegistry:
    def __init__(self) -> None:
        self._sessions: dict[str, OcdSession] = {}
        self._lock = threading.Lock()

    def find(self, case_id: str) -> OcdSession | None:
        with self._lock:
            return self._sessions.get(case_id)

    def get(self, case_id: str) -> OcdSession:
        s = self.find(case_id)
        if s is None:
            raise NotFound(
                f"케이스 {case_id} 에 OpenOCD 세션이 없습니다.",
                hint="openocd_start(프로세스 시작) 또는 openocd_attach(실행 중인 OpenOCD 에 연결)를 먼저 호출하세요.",
            )
        return s

    def add(self, sess: OcdSession) -> None:
        with self._lock:
            cur = self._sessions.get(sess.case_id)
            if cur is not None:
                raise Busy(
                    f"케이스 {sess.case_id} 에 이미 OpenOCD 세션이 있습니다 (mode={cur.mode}, port={cur.port}).",
                    hint="openocd_status 로 확인하고, 다시 시작하려면 openocd_stop 을 먼저 호출하세요.",
                )
            self._sessions[sess.case_id] = sess

    def remove(self, case_id: str) -> OcdSession | None:
        with self._lock:
            return self._sessions.pop(case_id, None)

    def all(self) -> list[OcdSession]:
        with self._lock:
            return list(self._sessions.values())

    def ports_in_use(self) -> set[tuple[str, int]]:
        with self._lock:
            return {(s.host, s.port) for s in self._sessions.values()}

    def shutdown_all(self) -> None:
        """테스트/종료용: 모든 세션을 닫고 소유 프로세스를 종료."""
        for s in self.all():
            try:
                s.client.close()
            except Exception:
                pass
            if s.owned and s.proc is not None and s.proc.alive:
                try:
                    s.proc.terminate(grace=2.0)
                except Exception:
                    pass
            self.remove(s.case_id)


REGISTRY = SessionRegistry()

__all__ = ["OcdSession", "REGISTRY", "SessionRegistry"]
