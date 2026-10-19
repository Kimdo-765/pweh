"""안전 게이트 / 승인 / 케이스 저장소 테스트."""

from __future__ import annotations

import json
import re
import shutil
from pathlib import Path
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


def test_case_id_cannot_end_with_dot(workspace):
    """케이스 id 는 '.' 으로 끝날 수 없다: Windows 경로 정규화가 요소 끝의 '.' 을 지워 다른 케이스(esp-lab.→esp-lab)를 가리키게 된다."""
    from pweh.case import CASE_ID_RE

    rt = get_runtime("test")
    for bad in ("esp-lab.", "esp-lab..", "a.", "x" * 79 + "."):
        assert not CASE_ID_RE.match(bad), bad
        with pytest.raises(ValidationFailed):
            rt.cases.create(title="bad id", case_id=bad)
    for good in ("esp-lab", "a", "a.b", "a_", "a-", "v1.2.3", "20261019-esp-test", "x" * 80):
        assert CASE_ID_RE.match(good), good
    assert not CASE_ID_RE.match("x" * 81) and not CASE_ID_RE.match(".a") and not CASE_ID_RE.match("a b")
    c = rt.cases.create(title="dot inside", case_id="esp-lab.v2")
    assert c.id == "esp-lab.v2" and rt.cases.exists("esp-lab.v2")
    auto = rt.cases.create(title="자동 id ...", target={"vendor": "Acme.", "model": "Cam."})
    assert CASE_ID_RE.match(auto.id) and not auto.id.endswith(".")


# ---------------------------------------------------------------------------
# 단계(phase) 레지스트리: 파이프라인 단계 + 선택 단계, 보고서 §4
# ---------------------------------------------------------------------------

EXAMPLES = Path(__file__).resolve().parents[2] / "examples"
_UART_DATA = {"port": "/dev/ttyUSB0", "baudrate": 115200, "console_type": "uboot", "access_level": "uboot"}


def test_optional_phase_registry_is_disjoint_and_labelled():
    from pweh.case import OPTIONAL_PHASES, PIPELINE_PHASES, tracks_phase
    from pweh.report import _PHASE_LABEL

    assert OPTIONAL_PHASES and len(set(OPTIONAL_PHASES)) == len(OPTIONAL_PHASES)
    assert not set(OPTIONAL_PHASES) & set(PIPELINE_PHASES), "선택 단계는 파이프라인 단계와 겹치지 않는다"
    for p in (*PIPELINE_PHASES, *OPTIONAL_PHASES):
        assert tracks_phase(p) and _PHASE_LABEL.get(p), f"보고서 라벨 없음: {p}"
    assert not tracks_phase("esp32-flash-dump"), "요약을 firmware-dump-via-uart 로 남기는 Skill 은 자기 단계가 없다"


def test_optional_phase_status_appears_only_once_recorded(workspace, auth):
    from pweh import schemas
    from pweh.case import PIPELINE_PHASES

    rt = get_runtime("test")
    case = rt.cases.create(title="SD 이미지", authorization=auth)
    phases = case.load()["phases"]
    # 새 케이스: 파이프라인 단계만 pending 이고 선택 단계 항목은 없다
    assert list(phases) == list(PIPELINE_PHASES) and all(e == {"status": "pending"} for e in phases.values())
    # summary 가 아닌 단계, 레지스트리에 없는 Skill 의 summary 는 단계 상태를 만들지 않는다
    case.record_step(skill="sd-card-forensics", step="intake", status="success", summary="접수")
    case.record_step(skill="not-a-registered-skill", step="summary", status="success", summary="x")
    assert set(case.load()["phases"]) == set(PIPELINE_PHASES)
    case.record_step(skill="sd-card-forensics", step="summary", status="partial", summary="이미지 해시 일치")
    phases = case.load()["phases"]
    assert phases["sd-card-forensics"]["status"] == "partial" and phases["sd-card-forensics"]["updated_at"]
    assert set(phases) == set(PIPELINE_PHASES) | {"sd-card-forensics"}, "다른 선택 단계는 여전히 없다"
    # 상태 대응은 파이프라인 단계와 같다 (success → done, in-progress → in-progress), 파이프라인 단계는 그대로
    case.record_step(skill="sd-card-forensics", step="summary", status="success", summary="완료")
    case.record_step(skill="flipper-rf-analysis", step="summary", status="in-progress", summary="진행 중")
    case.record_step(skill="uart-shell-acquisition", step="summary", status="blocked", summary="포트 없음", data=_UART_DATA)
    phases = case.load()["phases"]
    assert phases["sd-card-forensics"]["status"] == "done" and phases["flipper-rf-analysis"]["status"] == "in-progress"
    assert phases["uart-shell-acquisition"]["status"] == "blocked" and phases["firmware-dump-via-uart"] == {"status": "pending"}
    # case_set_phase(수동 갱신)로도 처음 생긴다
    case.set_phase("espprobe", "skipped", note="계측기 없음")
    assert case.load()["phases"]["espprobe"]["status"] == "skipped"
    schemas.validate("case", case.load(), label="case.json")


def test_report_renders_optional_phases_after_pipeline(workspace, auth):
    from pweh.report import render_report

    rt = get_runtime("test")
    case = rt.cases.create(title="혼합", authorization=auth)
    assert "선택 단계" not in render_report(case), "선택 단계가 없으면 아무것도 쓰지 않는다"
    case.record_step(skill="uart-shell-acquisition", step="summary", status="success", summary="U-Boot 획득", data=_UART_DATA)
    case.record_step(skill="other-skill", step="summary", status="success", summary="등록 안 된 Skill 요약")
    case.record_step(skill="sd-card-forensics", step="summary", status="partial", summary="이미지 해시 일치",
                     blockers=["FAT 해석 도구 없음"], artifacts=[])
    case.set_phase("flipper-rf-analysis", "in-progress")
    text = render_report(case)
    sec4 = text[text.index("## 4. 파이프라인 단계"): text.index("## 5.")]
    pipeline_table = sec4[: sec4.index("\n### ")]
    assert "| UART 셸/U-Boot 획득 | done |" in pipeline_table and "SD 카드 포렌식" not in pipeline_table
    marks = ("### UART 셸/U-Boot 획득 — success", "### 선택 단계", "| Flipper·RF 분석 | in-progress |", "| SD 카드 포렌식 | partial |",
             "#### SD 카드 포렌식 — partial", "이미지 해시 일치", "#### other-skill — success")
    pos = [sec4.index(m) for m in marks]
    assert pos == sorted(pos), "파이프라인 요약 → 선택 단계 표(레지스트리 순서) → 선택 단계 요약 → 그 밖의 Skill"
    assert "- 차단 요인: FAT 해석 도구 없음" in sec4
    assert "- FAT 해석 도구 없음" in text[text.index("## 10."):], "§10 한계도 선택 단계의 차단 요인을 모은다"


def _normalize_report(text: str) -> list[str]:
    out = []
    for line in text.splitlines():
        if "| `report.md` | report |" in line:  # write_report 가 렌더링 뒤에 등록하는 보고서 자신
            continue
        line = re.sub(r"보고서 생성: \S+", "보고서 생성: <ts>", line)
        out.append(re.sub(r"^- 도구: pweh \S+$", "- 도구: pweh <ver>", line))
    return out


@pytest.mark.parametrize("name", sorted(p.parent.parent.name for p in EXAMPLES.glob("*/case/report.md")))
def test_example_cases_validate_and_reports_render_unchanged(name, tmp_path):
    """examples/ 의 케이스를 지금 코드로 다시 그려도 report.md 가 같다(생성 시각·버전·보고서 자신의 아티팩트 행만 다름).
    case.json·단계 결과·요약 data·발견사항도 지금 스키마를 통과한다. 원본을 건드리지 않게 복사본에서 한다."""
    from pweh import schemas
    from pweh.case import Case
    from pweh.report import render_report

    case = Case(shutil.copytree(EXAMPLES / name / "case", tmp_path / name))
    schemas.validate("case", case.load(), label=f"{name} case.json")
    for st in case.steps(load=True):
        schemas.validate("step-result", st, label=f"{name} {st.get('skill')}/{st.get('step')}")
        data_schema = schemas.SKILL_DATA_SCHEMAS.get(st["skill"]) if st["step"] == "summary" else None
        if data_schema:
            schemas.validate(data_schema, st["data"], label=f"{name} {st['skill']} 요약 data")
    for f in case.findings():
        schemas.validate("finding", f, label=f"{name} {f.get('id')}")
    expected = (case.dir / "report.md").read_text(encoding="utf-8")
    assert _normalize_report(render_report(case)) == _normalize_report(expected)
