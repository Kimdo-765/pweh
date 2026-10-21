"""MCP 서버 프로세스별 런타임: 설정, 케이스 저장소, 안전 게이트, 사람 증명, 출처 원장, 비밀 마스킹, 작업 관리자, 감사 로그.

보호 상태(<state_dir>, 에이전트 수정 금지): ``approvals/``(승인), ``attestations/``(사람 증명), ``provenance/<case>.jsonl``(출처 원장),
``salts/<case>.key``(마스킹 솔트), ``custody/<case>.jsonl``(증거 고정점), ``case-ids/``(생성 예약), ``audit.jsonl``.
모두 처음 쓸 때 만든다(런타임 생성만으로는 아무것도 만들지 않는다).
"""

from __future__ import annotations

import logging
import os
import threading
from pathlib import Path
from typing import Any

from .audit import AuditLog
from .case import Case, CaseStore
from .config import PwehConfig, load_config
from .errors import PwehError
from .fsutil import atomic_write_json, utcnow_iso
from .jobs import Job, JobManager
from .provenance import ProvenanceLedger
from .safety import (
    ApprovalStore,
    AttestationDecision,
    AttestationStore,
    Attestor,
    Classification,
    GateDecision,
    SafetyGate,
    SecretMasker,
)

log = logging.getLogger("pweh.runtime")

#: 케이스의 증명 사본 파일 이름 (보고서용, 증거 아님)
ATTESTATION_MIRROR = "attestations.json"


class Runtime:
    def __init__(self, server: str, config: PwehConfig | None = None) -> None:
        self.server = server
        self.config = config or load_config()
        self.cases = CaseStore(self.config.cases_dir, state_dir=self.config.state_dir)
        self.approvals = ApprovalStore(self.config.state_dir / "approvals", ttl_seconds=self.config.safety.approval_ttl_seconds)
        self.global_audit = AuditLog(self.config.state_dir / "audit.jsonl", server=server)
        self.gate = SafetyGate(self.config.safety, self.approvals, audit=self.audit)
        # 사람 증명: pending 요청은 승인과 같은 TTL(safety.approval_ttl_seconds), 승인 뒤 유효 기간은 바인딩 범위별 코드 기본값
        self.attestations = AttestationStore(self.config.state_dir / "attestations",
                                             pending_ttl_seconds=self.config.safety.approval_ttl_seconds,
                                             on_change=self._mirror_attestations)
        self.attestor = Attestor(self.attestations, self.config.safety, audit=self.audit, server=server)
        self.provenance = ProvenanceLedger(self.config.state_dir / "provenance", attestations=self.attestations)
        self.salts = SecretMasker(self.config.state_dir / "salts")
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

    async def attest(
        self,
        kind: str,
        subject: dict[str, Any],
        binding: dict[str, Any],
        questions: list[dict[str, Any]],
        case_id: str | None = None,
        ctx: Any = None,
        summary: str | None = None,
        *,
        tool: str | None = None,
        valid_seconds: int | None = None,
    ) -> AttestationDecision:
        """사람 증명 확인·요청. 충족되면 ``decision.satisfied`` (``decision.record`` = 증명 레코드),
        아니면 ``attestation_response(decision)`` 를 그대로 반환한다 (status: attestation_required | denied).

        subject 는 서버 자신의 스캔·측정 결과로 만든다. 에이전트가 넘긴 ``attested_*`` 값이나 케이스 파일은 증거가 아니다
        (subject·binding 의 ``attested*`` 키는 무시된다). 사용 예::

            dec = await rt().attest("console-offline", {"console": serial}, {"scope": "case", "case_id": case.id},
                                    [{"id": "offline", "text": "콘솔의 네트워크를 끊었다", "type": "yesno", "expected": "yes"}],
                                    case.id, ctx, "콘솔 오프라인 확인", tool="input_connect")
            if not dec.satisfied:
                return attestation_response(dec)
        """
        return await self.attestor.attest(kind, subject, binding, questions, case_id, ctx, summary, tool=tool,
                                          valid_seconds=valid_seconds)

    def secret_digest(self, case_id: str, value: str | bytes) -> str:
        """비밀값의 케이스 솔트 다이제스트 ('sha256:<16 hex>'). 게이트 action·classification.matched 에는 원문 대신 이것을 쓴다."""
        return self.salts.digest(case_id, value)

    def _mirror_attestations(self, case_id: str | None) -> None:
        """케이스의 증명 사본(cases/<id>/attestations.json)을 권위 기록에서 다시 만든다. 보고서용 — 어떤 코드도 증거로 읽지 않는다."""
        if not case_id:
            return
        try:
            case = self.cases.get(case_id)
        except PwehError:
            return
        recs = self.attestations.list(case_id=case_id)
        doc = {
            "schema": "pweh.attestations-mirror/v1",
            "case_id": case_id,
            "generated_at": utcnow_iso(),
            "authoritative": False,
            "note": ("보고서용 읽기 전용 사본이다. 서버는 이 파일을 증거로 읽지 않는다 — 권위 기록은 .pweh/state/attestations/ "
                     "(사람이 `pweh attest <id>` 로 결정)이며, 이 파일을 고쳐도 아무 증명도 생기지 않는다."),
            "attestations": recs,
        }
        path = case.dir / ATTESTATION_MIRROR
        atomic_write_json(path, doc)
        try:
            os.chmod(path, 0o400)
        except OSError:  # pragma: no cover
            log.warning("증명 사본 권한 설정 실패: %s", path)


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
