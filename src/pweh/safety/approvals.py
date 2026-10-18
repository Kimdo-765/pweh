"""사람 승인(approval) 저장소.

위험 작업(정책이 approve 인 경우)을 실행하려면 사람이 에이전트 밖에서 승인해야 한다.

흐름:
  1. 에이전트가 위험 도구를 호출 → 서버가 pending 승인 레코드를 만들고 approval_id 를 돌려줌
  2. 사람이 별도 터미널에서 ``pweh approve <approval_id>`` 실행 → 내용 확인 후 확인 코드 입력
  3. 에이전트가 같은 인자 + approval_id 로 다시 호출 → 서버가 지문(fingerprint)·만료·1회성 검증 후 실행

레코드는 ``<state_dir>/approvals/<id>.json`` 에 저장되어 MCP 서버 프로세스와 CLI 가 공유한다.
승인은 정확히 같은 작업(서버, 도구, 케이스, 정규화된 작업 내용)에만 1회 유효하다.
"""

from __future__ import annotations

import datetime as _dt
import getpass
import hashlib
import json
import os
import secrets
from pathlib import Path
from typing import Any

from ..errors import NotFound, PwehError, SafetyDenied
from ..fsutil import atomic_write_json, file_lock, read_json, utcnow, utcnow_iso

_CODE_ALPHABET = "ACDEFGHJKLMNPQRTUVWXY34679"  # 혼동 문자(0/O, 1/I, 5/S, 8/B, 2/Z) 제외


def action_fingerprint(server: str, tool: str, case_id: str | None, action: dict[str, Any]) -> str:
    payload = json.dumps(
        {"server": server, "tool": tool, "case_id": case_id, "action": action},
        sort_keys=True,
        ensure_ascii=False,
        separators=(",", ":"),
        default=str,
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _parse_ts(value: str | None) -> _dt.datetime | None:
    if not value:
        return None
    return _dt.datetime.fromisoformat(value.replace("Z", "+00:00"))


class ApprovalStore:
    def __init__(self, directory: Path, ttl_seconds: int = 900) -> None:
        self.dir = Path(directory)
        self.ttl = int(ttl_seconds)

    # -- 내부 ---------------------------------------------------------------
    def _path(self, approval_id: str) -> Path:
        if not approval_id or not all(c.isalnum() or c in "-_" for c in approval_id):
            raise PwehError(f"잘못된 approval_id: {approval_id!r}", code="bad_approval_id")
        return self.dir / f"{approval_id}.json"

    def _lock(self, approval_id: str):
        return file_lock(self.dir / f".{approval_id}.lock")

    def _expire_if_needed(self, rec: dict[str, Any]) -> dict[str, Any]:
        if rec.get("status") in ("pending", "approved"):
            exp = _parse_ts(rec.get("expires_at"))
            if exp is not None and utcnow() > exp:
                rec["status"] = "expired"
        return rec

    # -- 공개 API -------------------------------------------------------------
    def create(
        self,
        *,
        server: str,
        tool: str,
        case_id: str | None,
        action: dict[str, Any],
        risk: str,
        rule_id: str,
        reason: str,
        summary: str,
    ) -> dict[str, Any]:
        self.dir.mkdir(parents=True, exist_ok=True)
        approval_id = "ap-" + secrets.token_hex(5)
        code = "".join(secrets.choice(_CODE_ALPHABET) for _ in range(4))
        now = utcnow()
        rec = {
            "schema": "pweh.approval/v1",
            "id": approval_id,
            "code": code,
            "status": "pending",
            "created_at": now.isoformat(timespec="seconds").replace("+00:00", "Z"),
            "expires_at": (now + _dt.timedelta(seconds=self.ttl)).isoformat(timespec="seconds").replace("+00:00", "Z"),
            "server": server,
            "tool": tool,
            "case_id": case_id,
            "action": action,
            "fingerprint": action_fingerprint(server, tool, case_id, action),
            "risk": risk,
            "rule_id": rule_id,
            "reason": reason,
            "summary": summary,
            "decided_at": None,
            "decided_by": None,
            "decided_via": None,
            "consumed_at": None,
        }
        with self._lock(approval_id):
            atomic_write_json(self._path(approval_id), rec)
        return rec

    def get(self, approval_id: str) -> dict[str, Any]:
        rec = read_json(self._path(approval_id))
        if rec is None:
            raise NotFound(f"승인 요청을 찾을 수 없습니다: {approval_id}")
        return self._expire_if_needed(rec)

    def list(self, status: str | None = None) -> list[dict[str, Any]]:
        if not self.dir.exists():
            return []
        out = []
        for p in sorted(self.dir.glob("ap-*.json")):
            try:
                rec = self._expire_if_needed(read_json(p) or {})
            except (json.JSONDecodeError, OSError):
                continue
            if status is None or rec.get("status") == status:
                out.append(rec)
        out.sort(key=lambda r: r.get("created_at", ""))
        return out

    def decide(self, approval_id: str, *, approve: bool, code: str | None, via: str, by: str | None = None) -> dict[str, Any]:
        """사람의 결정을 기록한다. 승인 시 확인 코드가 일치해야 한다."""
        with self._lock(approval_id):
            rec = self.get(approval_id)
            if rec["status"] != "pending":
                raise PwehError(f"이미 처리되었거나 만료된 요청입니다 (status={rec['status']}).", code="approval_not_pending")
            if approve:
                if (code or "").strip().upper() != rec["code"]:
                    raise PwehError("확인 코드가 일치하지 않습니다.", code="approval_code_mismatch")
                rec["status"] = "approved"
                # 승인 후 TTL 동안 소비 가능
                rec["expires_at"] = (utcnow() + _dt.timedelta(seconds=self.ttl)).isoformat(timespec="seconds").replace("+00:00", "Z")
            else:
                rec["status"] = "denied"
            rec["decided_at"] = utcnow_iso()
            rec["decided_by"] = by or _whoami()
            rec["decided_via"] = via
            atomic_write_json(self._path(approval_id), rec)
            return rec

    def consume(self, approval_id: str, fingerprint: str) -> dict[str, Any]:
        """승인된 요청을 1회 소비. 지문/상태/만료가 맞지 않으면 SafetyDenied."""
        with self._lock(approval_id):
            rec = self.get(approval_id)
            status = rec.get("status")
            if status == "pending":
                raise SafetyDenied(
                    f"승인 요청 {approval_id} 은 아직 사람이 승인하지 않았습니다.",
                    code="approval_pending",
                    hint=f"사람이 별도 터미널에서 `pweh approve {approval_id}` 를 실행해야 합니다.",
                    data={"approval_id": approval_id},
                )
            if status != "approved":
                raise SafetyDenied(
                    f"승인 요청 {approval_id} 을 사용할 수 없습니다 (status={status}).",
                    code=f"approval_{status}",
                    hint="새 승인 요청이 필요하면 approval_id 없이 다시 호출하세요.",
                )
            if rec.get("fingerprint") != fingerprint:
                raise SafetyDenied(
                    "승인된 작업과 현재 요청한 작업이 다릅니다 (인자/세션/케이스가 바뀜).",
                    code="approval_mismatch",
                    hint="승인은 정확히 같은 작업에만 유효합니다. approval_id 없이 다시 호출해 새 승인을 받으세요.",
                )
            rec["status"] = "consumed"
            rec["consumed_at"] = utcnow_iso()
            atomic_write_json(self._path(approval_id), rec)
            return rec

    def record_immediate(self, rec_fields: dict[str, Any], *, via: str) -> dict[str, Any]:
        """elicitation 처럼 즉시 승인된 경우 감사 목적으로 consumed 레코드를 남긴다."""
        rec = self.create(**rec_fields)
        with self._lock(rec["id"]):
            rec["status"] = "consumed"
            rec["decided_at"] = utcnow_iso()
            rec["decided_by"] = "client-user"
            rec["decided_via"] = via
            rec["consumed_at"] = rec["decided_at"]
            atomic_write_json(self._path(rec["id"]), rec)
        return rec


def _whoami() -> str:
    try:
        user = getpass.getuser()
    except Exception:  # pragma: no cover
        user = "unknown"
    tty = None
    try:
        tty = os.ttyname(0)
    except OSError:
        pass
    return f"{user}@{tty}" if tty else user
