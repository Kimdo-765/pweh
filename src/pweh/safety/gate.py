"""서버 측 안전 게이트.

모든 MCP 서버는 기기에 영향을 주는 작업 전에 반드시 ``SafetyGate.authorize`` 를 거친다.
클라이언트의 권한 프롬프트(예: Claude Code permissions)는 우회 모드에서 동작하지 않을 수 있으므로
최종 판단은 서버가 한다.

정책 (pipeline-config.yaml → safety):
  - OBSERVE / INTERACT : 항상 허용
  - MODIFY             : modify_policy (allow | approve | deny)
  - DESTRUCTIVE        : destructive_policy (deny | approve) — 기본 deny

approve 정책일 때 사람 확인 방법(approval_methods):
  - elicitation : MCP elicitation 으로 클라이언트 UI 에 확인 폼 표시 (클라이언트가 지원할 때)
  - cli         : 별도 터미널에서 ``pweh approve <id>`` (에이전트 밖에서의 승인)
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any, Callable

import anyio
from pydantic import BaseModel, Field

from ..config import SafetyConfig
from ..errors import SafetyDenied
from .approvals import ApprovalStore, action_fingerprint
from .risk import Classification, Risk

log = logging.getLogger("pweh.safety")

ELICITATION_TIMEOUT_S = 300.0


@dataclass
class GateDecision:
    allowed: bool
    status: str  # allowed | approval_required | denied
    classification: Classification
    policy: str  # allow | approve | deny
    via: str | None = None  # policy | elicitation | cli-approval
    approval_id: str | None = None
    message: str = ""

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "allowed": self.allowed,
            "status": self.status,
            "policy": self.policy,
            "classification": self.classification.to_dict(),
        }
        if self.via:
            out["via"] = self.via
        if self.approval_id:
            out["approval_id"] = self.approval_id
        if self.message:
            out["message"] = self.message
        return out


class _ApprovalForm(BaseModel):
    approve: bool = Field(description="이 작업을 실행하려면 true")
    code: str = Field(description="메시지에 표시된 4자리 확인 코드")


class SafetyGate:
    def __init__(
        self,
        safety: SafetyConfig,
        approvals: ApprovalStore,
        audit: Callable[[dict[str, Any], str | None], None] | None = None,
    ) -> None:
        self.safety = safety
        self.approvals = approvals
        self._audit = audit

    # ------------------------------------------------------------------
    def policy_for(self, risk: Risk) -> str:
        if risk <= Risk.INTERACT:
            return "allow"
        if risk == Risk.MODIFY:
            return self.safety.modify_policy
        return self.safety.destructive_policy

    def _emit(self, decision: GateDecision, *, server: str, tool: str, case_id: str | None, action: dict[str, Any]) -> GateDecision:
        if self._audit is not None:
            try:
                self._audit(
                    {
                        "event": "safety_decision",
                        "server": server,
                        "tool": tool,
                        "action": action,
                        **decision.to_dict(),
                    },
                    case_id,
                )
            except Exception:  # 감사 로그 실패가 작업을 막지 않도록
                log.exception("audit write failed")
        return decision

    def _deny_message(self, cls: Classification, policy_key: str) -> str:
        return (
            f"안전 정책에 의해 차단됨: 위험도={cls.risk.label}, 규칙={cls.rule_id}, 사유={cls.reason}. "
            f"현재 safety.{policy_key}=deny 입니다. 이 작업이 정말 필요하면 사람(운영자)이 직접 "
            f"orchestrator/pipeline-config.yaml 의 safety.{policy_key} 를 'approve' 로 바꾸고 MCP 서버를 재시작한 뒤 다시 시도해야 합니다. "
            f"에이전트는 설정을 스스로 변경하지 말고, 먼저 사용자에게 상황과 위험을 설명하세요."
        )

    async def authorize(
        self,
        *,
        server: str,
        tool: str,
        action: dict[str, Any],
        classification: Classification,
        case_id: str | None = None,
        approval_id: str | None = None,
        ctx: Any = None,
        summary: str | None = None,
    ) -> GateDecision:
        cls = classification
        policy = self.policy_for(cls.risk)
        emit = lambda d: self._emit(d, server=server, tool=tool, case_id=case_id, action=action)  # noqa: E731

        if policy == "allow":
            return emit(GateDecision(True, "allowed", cls, policy, via="policy"))

        policy_key = "modify_policy" if cls.risk == Risk.MODIFY else "destructive_policy"
        if policy == "deny":
            return emit(GateDecision(False, "denied", cls, policy, message=self._deny_message(cls, policy_key)))

        # policy == approve
        fingerprint = action_fingerprint(server, tool, case_id, action)
        summary = summary or f"{server}.{tool}: {cls.matched or cls.reason}"
        if approval_id:
            try:
                rec = self.approvals.consume(approval_id, fingerprint)
            except SafetyDenied as exc:
                status = "approval_required" if exc.code == "approval_pending" else "denied"
                return emit(GateDecision(False, status, cls, policy, approval_id=approval_id, message=str(exc)))
            return emit(GateDecision(True, "allowed", cls, policy, via=f"approval:{rec.get('decided_via')}", approval_id=approval_id))

        methods = list(self.safety.approval_methods)
        if "elicitation" in methods and ctx is not None and _client_supports_elicitation(ctx):
            outcome = await self._elicit(ctx, server=server, tool=tool, case_id=case_id, cls=cls, summary=summary, action=action)
            if outcome is not None:
                return emit(outcome)
            # elicitation 실패(오류/시간초과) → cli 로 폴백

        if "cli" in methods:
            rec = self.approvals.create(
                server=server, tool=tool, case_id=case_id, action=action,
                risk=cls.risk.label, rule_id=cls.rule_id, reason=cls.reason, summary=summary,
            )
            msg = (
                f"사람의 승인이 필요합니다 (위험도={cls.risk.label}, 규칙={cls.rule_id}, 사유={cls.reason}). "
                f"사용자에게 작업 내용과 위험을 설명하고, 사용자가 **별도 터미널**에서 "
                f"`pweh approve {rec['id']}` 를 실행해 확인 코드를 입력하도록 요청하세요. "
                f"승인 후 같은 인자에 approval_id=\"{rec['id']}\" 를 추가해 다시 호출하면 1회 실행됩니다 "
                f"(만료: {rec['expires_at']}). 에이전트가 승인 명령을 직접 실행하거나 승인 파일을 수정해서는 안 됩니다."
            )
            return emit(GateDecision(False, "approval_required", cls, policy, approval_id=rec["id"], message=msg))

        return emit(GateDecision(False, "denied", cls, policy, message="사용 가능한 승인 방법이 없어 거부되었습니다 (safety.approval_methods 확인)."))

    async def _elicit(
        self,
        ctx: Any,
        *,
        server: str,
        tool: str,
        case_id: str | None,
        cls: Classification,
        summary: str,
        action: dict[str, Any],
    ) -> GateDecision | None:
        import secrets

        code = "".join(secrets.choice("ACDEFGHJKLMNPQRTUVWXY34679") for _ in range(4))
        message = (
            "⚠️ 위험 작업 승인 요청\n"
            f"- 서버/도구: {server} / {tool}\n"
            f"- 케이스: {case_id or '-'}\n"
            f"- 위험도: {cls.risk.label.upper()} ({cls.rule_id})\n"
            f"- 내용: {cls.matched or summary}\n"
            f"- 사유: {cls.reason}\n\n"
            f"실행하려면 approve=true 와 확인 코드 {code} 를 입력하세요. 확실하지 않으면 거부하세요."
        )
        try:
            with anyio.fail_after(ELICITATION_TIMEOUT_S):
                result = await ctx.elicit(message=message, schema=_ApprovalForm)
        except Exception as exc:  # 클라이언트 미지원/오류/시간초과
            log.info("elicitation failed, falling back: %r", exc)
            return None
        action_name = getattr(result, "action", None)
        if action_name == "accept":
            data = getattr(result, "data", None)
            if data is not None and data.approve and data.code.strip().upper() == code:
                self.approvals.record_immediate(
                    dict(server=server, tool=tool, case_id=case_id, action=action, risk=cls.risk.label,
                         rule_id=cls.rule_id, reason=cls.reason, summary=summary),
                    via="elicitation",
                )
                return GateDecision(True, "allowed", cls, "approve", via="elicitation")
            return GateDecision(False, "denied", cls, "approve", message="사용자가 승인하지 않았거나 확인 코드가 틀렸습니다.")
        if action_name in ("decline", "cancel"):
            return GateDecision(False, "denied", cls, "approve", message=f"사용자가 승인 요청을 {action_name} 했습니다. 작업을 진행하지 마세요.")
        return None


def _client_supports_elicitation(ctx: Any) -> bool:
    try:
        caps = ctx.client_capabilities
    except Exception:
        return False
    return bool(caps is not None and getattr(caps, "elicitation", None) is not None)
