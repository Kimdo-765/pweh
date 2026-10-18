"""MCP 서버 프로세스별 런타임: 설정, 케이스 저장소, 안전 게이트, 작업 관리자, 감사 로그."""

from __future__ import annotations

import threading
from pathlib import Path
from typing import Any

from .audit import AuditLog
from .case import Case, CaseStore
from .config import PwehConfig, load_config
from .jobs import Job, JobManager
from .safety import ApprovalStore, Classification, GateDecision, SafetyGate


class Runtime:
    def __init__(self, server: str, config: PwehConfig | None = None) -> None:
        self.server = server
        self.config = config or load_config()
        self.cases = CaseStore(self.config.cases_dir)
        self.approvals = ApprovalStore(self.config.state_dir / "approvals", ttl_seconds=self.config.safety.approval_ttl_seconds)
        self.global_audit = AuditLog(self.config.state_dir / "audit.jsonl", server=server)
        self.gate = SafetyGate(self.config.safety, self.approvals, audit=self.audit)
        self.jobs = JobManager(server, persist_dir=self._job_dir)

    # ------------------------------------------------------------------
    def _job_dir(self, job: Job) -> Path | None:
        if not job.case_id:
            return self.config.state_dir / "jobs"
        try:
            return self.cases.get(job.case_id).subdir("jobs")
        except Exception:
            return self.config.state_dir / "jobs"

    def audit(self, event: dict[str, Any], case_id: str | None = None) -> None:
        ev = {"server": self.server, **event}
        if case_id:
            ev.setdefault("case_id", case_id)
        self.global_audit.write(ev)
        if case_id:
            try:
                self.cases.get(case_id).audit(ev)
            except Exception:
                pass

    def case(self, case_id: str, *, hardware: bool = False) -> Case:
        """케이스 로드. hardware=True 이면 소유/허가 증명이 필요하다(설정에 따라)."""
        case = self.cases.get(case_id)
        if hardware and self.config.safety.require_authorization:
            case.require_authorization()
        return case

    async def authorize(
        self,
        *,
        tool: str,
        action: dict[str, Any],
        classification: Classification,
        case_id: str | None,
        approval_id: str | None = None,
        ctx: Any = None,
        summary: str | None = None,
    ) -> GateDecision:
        return await self.gate.authorize(
            server=self.server,
            tool=tool,
            action=action,
            classification=classification,
            case_id=case_id,
            approval_id=approval_id,
            ctx=ctx,
            summary=summary,
        )


_RUNTIMES: dict[str, Runtime] = {}
_LOCK = threading.Lock()


def get_runtime(server: str) -> Runtime:
    with _LOCK:
        rt = _RUNTIMES.get(server)
        if rt is None:
            rt = Runtime(server)
            _RUNTIMES[server] = rt
        return rt


def reset_runtimes() -> None:
    """테스트용: 환경변수/설정을 바꾼 뒤 런타임을 다시 만들게 한다."""
    with _LOCK:
        for rt in _RUNTIMES.values():
            rt.jobs.shutdown(timeout=1.0)
        _RUNTIMES.clear()
