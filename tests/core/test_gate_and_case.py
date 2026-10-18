"""안전 게이트 / 승인 / 케이스 저장소 테스트."""

from __future__ import annotations

import json
from types import SimpleNamespace

import pytest

from pweh.config import load_config
from pweh.errors import AuthorizationRequired, SafetyDenied, ValidationFailed
from pweh.runtime import get_runtime
from pweh.safety import Classification, Risk

pytestmark = pytest.mark.anyio


@pytest.fixture
def anyio_backend():
    return "asyncio"


D = Classification(Risk.DESTRUCTIVE, "uboot.sf.erase", "sf erase", "sf erase 0 100")
M = Classification(Risk.MODIFY, "uboot.setenv", "setenv", "setenv a b")
I = Classification(Risk.INTERACT, "uboot.printenv", "printenv", "printenv")


async def test_default_policy(workspace):
    rt = get_runtime("test")
    assert (await rt.authorize(tool="t", action={"a": 1}, classification=I, case_id=None)).allowed
    assert (await rt.authorize(tool="t", action={"a": 1}, classification=M, case_id=None)).allowed
    d = await rt.authorize(tool="t", action={"a": 1}, classification=D, case_id=None)
    assert not d.allowed and d.status == "denied" and "destructive_policy" in d.message
    # 감사 로그 기록
    log = (workspace["state_dir"] / "audit.jsonl").read_text(encoding="utf-8").splitlines()
    assert any(json.loads(l)["status"] == "denied" for l in log)


async def test_cli_approval_flow(workspace):
    workspace["set_safety"](destructive_policy="approve", approval_methods=["cli"])
    rt = get_runtime("test")
    action = {"session": "s1", "line": "sf erase 0 100"}
    d1 = await rt.authorize(tool="uart_send_command", action=action, classification=D, case_id=None)
    assert d1.status == "approval_required" and d1.approval_id
    ap = d1.approval_id
    # 승인 전 재시도 → 여전히 approval_required
    d2 = await rt.authorize(tool="uart_send_command", action=action, classification=D, case_id=None, approval_id=ap)
    assert d2.status == "approval_required"
    # 잘못된 코드
    with pytest.raises(Exception):
        rt.approvals.decide(ap, approve=True, code="ZZZZ", via="test")
    rec = rt.approvals.get(ap)
    rt.approvals.decide(ap, approve=True, code=rec["code"], via="test")
    # 다른 작업에 승인 사용 불가
    d3 = await rt.authorize(tool="uart_send_command", action={**action, "line": "sf erase 0 200"}, classification=D, case_id=None, approval_id=ap)
    assert not d3.allowed and "다릅니다" in d3.message
    # 정확한 작업은 1회 허용
    d4 = await rt.authorize(tool="uart_send_command", action=action, classification=D, case_id=None, approval_id=ap)
    assert d4.allowed and d4.via.startswith("approval")
    # 재사용 불가
    d5 = await rt.authorize(tool="uart_send_command", action=action, classification=D, case_id=None, approval_id=ap)
    assert not d5.allowed


async def test_modify_policy_approve_and_deny(workspace):
    workspace["set_safety"](modify_policy="deny")
    rt = get_runtime("test")
    d = await rt.authorize(tool="t", action={}, classification=M, case_id=None)
    assert d.status == "denied" and "modify_policy" in d.message


class _FakeCtx:
    def __init__(self, action: str, approve: bool = True, code: str | None = None):
        self.client_capabilities = SimpleNamespace(elicitation=object())
        self._action = action
        self._approve = approve
        self._code = code
        self.messages = []

    async def elicit(self, message, schema):
        self.messages.append(message)
        code = self._code
        if code is None:
            import re

            code = re.search(r"확인 코드 ([A-Z0-9]{4})", message).group(1)
        return SimpleNamespace(action=self._action, data=schema(approve=self._approve, code=code))


async def test_elicitation_paths(workspace):
    workspace["set_safety"](destructive_policy="approve", approval_methods=["elicitation", "cli"])
    rt = get_runtime("test")
    ok = await rt.authorize(tool="t", action={"x": 1}, classification=D, case_id=None, ctx=_FakeCtx("accept"))
    assert ok.allowed and ok.via == "elicitation"
    wrong = await rt.authorize(tool="t", action={"x": 1}, classification=D, case_id=None, ctx=_FakeCtx("accept", code="AAAA"))
    assert not wrong.allowed
    declined = await rt.authorize(tool="t", action={"x": 1}, classification=D, case_id=None, ctx=_FakeCtx("decline"))
    assert declined.status == "denied"

    class Broken(_FakeCtx):
        async def elicit(self, message, schema):
            raise RuntimeError("client does not support")

    fb = await rt.authorize(tool="t", action={"x": 1}, classification=D, case_id=None, ctx=Broken("accept"))
    assert fb.status == "approval_required"  # cli 로 폴백


def test_case_store_and_authorization(workspace, auth):
    rt = get_runtime("test")
    with pytest.raises(ValidationFailed):
        rt.cases.create(title="x", authorization={"basis": "stolen", "owner": "a", "statement": "b"})
    case = rt.cases.create(title="no-auth")
    with pytest.raises(AuthorizationRequired):
        rt.case(case.id, hardware=True)
    case.set_authorization(auth)
    assert rt.case(case.id, hardware=True).is_authorized()
    # 경로 탈출 차단
    with pytest.raises(Exception):
        case.path("..", "..", "etc", "passwd")
    with pytest.raises(Exception):
        case.resolve_path("/etc/passwd")
    p = case.subdir("dumps") / "a.bin"
    p.write_bytes(b"\x00" * 16)
    art = case.register_artifact("dumps/a.bin", kind="flash-dump", producer="test")
    assert art["id"] == "A-0001" and art["size"] == 16 and len(art["sha256"]) == 64
    art2 = case.register_artifact(p, kind="flash-dump", producer="test")
    assert art2["id"] == "A-0001"  # 같은 경로 갱신
    with pytest.raises(ValidationFailed):
        rt.cases.create(title="bad id", case_id="../x")


def test_written_authorization_requires_document(workspace):
    rt = get_runtime("test")
    with pytest.raises(ValidationFailed):
        rt.cases.create(title="x", authorization={"basis": "written-authorization", "owner": "고객사", "statement": "허가함"})
    c = rt.cases.create(title="x", authorization={"basis": "written-authorization", "owner": "고객사", "statement": "허가함", "document_ref": "SOW-2026-01"})
    assert c.is_authorized()


def test_jobs_progress_and_cancel(workspace):
    import threading
    import time

    rt = get_runtime("test")
    started = threading.Event()

    def work(ctx):
        for i in range(100):
            started.set()
            ctx.check_cancelled()
            ctx.progress(i + 1, 100, f"{i + 1}/100")
            time.sleep(0.01)
        return {"done": True}

    job = rt.jobs.start("test", work, description="work")
    started.wait(2)
    rt.jobs.wait(job.id, 5)
    assert rt.jobs.get(job.id).status == "succeeded"
    assert rt.jobs.get(job.id).result == {"done": True}

    def slow(ctx):
        while True:
            ctx.check_cancelled()
            time.sleep(0.01)

    j2 = rt.jobs.start("slow", slow, description="slow", exclusive_key="port:/dev/x")
    with pytest.raises(Exception):
        rt.jobs.start("slow", slow, description="slow2", exclusive_key="port:/dev/x")
    rt.jobs.cancel(j2.id)
    rt.jobs.wait(j2.id, 5)
    assert rt.jobs.get(j2.id).status == "cancelled"


def test_job_partial_result_on_cancel(workspace):
    import time

    rt = get_runtime("test")

    def work(ctx):
        for i in range(1000):
            ctx.set_partial({"chunks_done": i})
            ctx.check_cancelled()
            time.sleep(0.01)

    job = rt.jobs.start("p", work, description="partial")
    time.sleep(0.1)
    rt.jobs.cancel(job.id)
    rt.jobs.wait(job.id, 5)
    j = rt.jobs.get(job.id)
    assert j.status == "cancelled" and j.result and j.result["chunks_done"] >= 1
