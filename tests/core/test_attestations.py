"""사람 증명(attestation) 저장소·서버 도우미(rt().attest)·CLI(`pweh attest`) 테스트.

음성 시험 위주: 증명은 서버가 (kind, subject, binding) 으로 상태 디렉터리의 레코드만 찾고, 에이전트가 넘긴 attested_* 값·
케이스 파일·사본·승인 id 는 어떤 경로로도 증거가 되지 않음을 확인한다. 모든 시험은 임시 작업공간(workspace fixture)에서 돈다.
"""

from __future__ import annotations

import datetime as dt
import json
import os
import re
import shutil
import signal
import subprocess
import sys
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

from pweh.config import load_config
from pweh.errors import NotFound, PwehError, ValidationFailed
from pweh.runtime import get_runtime
from pweh.safety import Classification, Risk, attestation_response
from pweh.safety import attestations as att_mod
from pweh.safety.attestations import ATTESTATION_KINDS, AttestationStore, attestation_fingerprint, register_kind

REPO = Path(__file__).resolve().parents[2]

pytestmark = pytest.mark.anyio


@pytest.fixture
def anyio_backend():
    return "asyncio"


Q = [
    {"id": "offline", "text": "콘솔의 네트워크(Wi-Fi·LAN)를 직접 끊었다", "type": "yesno", "expected": "yes"},
    {"id": "voltage", "text": "VTref 를 멀티미터로 잰 값(V)", "type": "value"},
]
ID_RE = re.compile(r"^att-[0-9a-f]{10}$")


def _case(rt, auth, cid: str = "att-case"):
    return rt.cases.create(title="증명 시험", authorization=auth, case_id=cid)


def _bind(cid: str) -> dict:
    return {"scope": "case", "case_id": cid}


def _approve(store: AttestationStore, att_id: str, **answers) -> dict:
    return store.decide(att_id, answers or {"offline": "yes", "voltage": "3.3"}, via="cli-tty", by="tester")


# ---------------------------------------------------------------------------
# 저장소
# ---------------------------------------------------------------------------


def test_runtime_creates_no_state_until_used(workspace):
    """런타임을 만들기만 해서는 attestations/·provenance/·salts/ 를 만들지 않는다(디렉터리는 처음 쓸 때)."""
    rt = get_runtime("test")
    assert rt.attestations.list() == [] and rt.attestations.require("wiring", {"plan": "x"}, _bind("c1")) is None
    for d in ("attestations", "provenance", "salts"):
        assert not (workspace["state_dir"] / d).exists(), d


def test_repo_pipeline_config_still_loads():
    """저장소의 orchestrator/pipeline-config.yaml 이 그대로 읽힌다 (safety 키 추가 없음, 디렉터리를 만들지 않음)."""
    cfg = load_config(REPO / "orchestrator" / "pipeline-config.yaml")
    assert cfg.path == (REPO / "orchestrator" / "pipeline-config.yaml").resolve()
    assert cfg.safety.destructive_policy in ("deny", "approve") and cfg.safety.modify_policy in ("allow", "approve", "deny")
    assert cfg.safety.approval_methods and cfg.safety.approval_ttl_seconds >= 30
    assert cfg.state_dir.name == "state" and cfg.cases_dir.name == "cases"


def test_request_reuse_decide_require(workspace, auth):
    rt = get_runtime("test")
    case = _case(rt, auth)
    st = rt.attestations
    rec = st.request("console-offline", {"console": "SN-1", "model": "X"}, _bind(case.id), Q, case.id, "콘솔 오프라인 확인",
                     server="test", tool="input_connect")
    assert ID_RE.match(rec["id"]) and rec["status"] == "pending" and rec["answers"] is None and rec["case_id"] == case.id
    assert rec["schema"] == "pweh.attestation/v1" and rec["kind"] == "console-offline"
    assert rec["fingerprint"] == attestation_fingerprint("console-offline", {"model": "X", "console": "SN-1"}, _bind(case.id))
    assert (workspace["state_dir"] / "attestations" / f"{rec['id']}.json").is_file()
    # 같은 지문(키 순서 무관)이면 pending 을 재사용한다
    again = st.request("console-offline", {"model": "X", "console": "SN-1"}, {"case_id": case.id, "scope": "case"}, Q, case.id)
    assert again["id"] == rec["id"] and len(st.list("pending")) == 1
    # pending 은 증거가 아니다
    assert st.require("console-offline", {"console": "SN-1", "model": "X"}, _bind(case.id)) is None
    out = st.decide(rec["id"], {"offline": "y", "voltage": " 3.31 "}, via="cli-tty", by="tester")
    assert out["status"] == "approved" and out["answers"] == {"offline": "yes", "voltage": "3.31"}
    assert out["decided_via"] == "cli-tty" and out["decided_by"] == "tester" and out["expires_at"]
    got = st.require("console-offline", {"console": "SN-1", "model": "X"}, _bind(case.id))
    assert got is not None and got["id"] == rec["id"] and got["answers"]["voltage"] == "3.31"
    # 소비하지 않는다: 몇 번을 찾아도 그대로 있다
    for _ in range(3):
        assert st.require("console-offline", {"console": "SN-1", "model": "X"}, _bind(case.id))["id"] == rec["id"]
    assert st.get(rec["id"])["status"] == "approved"
    with pytest.raises(PwehError) as ei:
        st.decide(rec["id"], {"offline": "yes", "voltage": "3.3"}, via="cli-tty")
    assert ei.value.code == "attestation_not_pending"
    with pytest.raises(NotFound):
        st.get("att-0000000000")


def test_decide_rules(workspace, auth):
    rt = get_runtime("test")
    case = _case(rt, auth)
    st = rt.attestations

    def new(subject):
        return st.request("wiring", subject, _bind(case.id), Q, case.id)["id"]

    # expected=yes 항목에 '아니오' → denied
    a = new({"plan": "p1"})
    assert st.decide(a, {"offline": "no", "voltage": "3.3"}, via="cli-tty")["status"] == "denied"
    # 값 항목이 비었음 → denied
    b = new({"plan": "p2"})
    out = st.decide(b, {"offline": True, "voltage": "   "}, via="elicitation")
    assert out["status"] == "denied" and any("voltage" in r for r in out["denied_reasons"])
    # 답이 하나도 없으면 denied
    c = new({"plan": "p3"})
    assert st.decide(c, {}, via="cli-tty")["status"] == "denied"
    # 사람의 경로가 아닌 via 는 거부하고 레코드는 pending 그대로
    d = new({"plan": "p4"})
    for via in ("agent", "cli", "policy", "approval:cli-tty", ""):
        with pytest.raises(ValidationFailed):
            st.decide(d, {"offline": "yes", "voltage": "3.3"}, via=via)
    assert st.get(d)["status"] == "pending"
    with pytest.raises(ValidationFailed):  # 모르는 질문의 답
        st.decide(d, {"offline": "yes", "voltage": "3.3", "extra": "x"}, via="cli-tty")
    with pytest.raises(ValidationFailed):  # yes/no 가 아닌 답
        st.decide(d, {"offline": "maybe", "voltage": "3.3"}, via="cli-tty")
    assert st.get(d)["status"] == "pending"
    # 기대값 없는 yes/no(정보 항목)는 '아니오'여도 승인을 막지 않는다
    info_q = [{"id": "online_capable", "text": "이 게임은 온라인 기능이 있다", "type": "yesno"},
              {"id": "ok", "text": "확인했다", "type": "yesno", "expected": "yes"}]
    e = st.request("console-offline", {"console": "info"}, _bind(case.id), info_q, case.id)["id"]
    out = st.decide(e, {"online_capable": "no", "ok": "yes"}, via="cli-tty")
    assert out["status"] == "approved" and out["answers"]["online_capable"] == "no"


def test_input_validation(workspace, auth):
    rt = get_runtime("test")
    case = _case(rt, auth)
    st = rt.attestations
    b = _bind(case.id)
    with pytest.raises(ValidationFailed):
        st.request("not-a-kind", {"a": 1}, b, Q, case.id)
    with pytest.raises(ValidationFailed):
        st.require("approval", {"a": 1}, b)  # 종류는 닫힌 집합
    for bad_binding in ({"scope": "global"}, {"scope": "case"}, {"scope": "connection", "case_id": case.id},
                        {"scope": "case", "case_id": ""}, {"scope": "case", "case_id": ["x"]}, "case"):
        with pytest.raises(ValidationFailed):
            st.request("wiring", {"a": 1}, bad_binding, Q, case.id)
    with pytest.raises(ValidationFailed):  # binding.case_id 와 case_id 가 다름
        st.request("wiring", {"a": 1}, _bind("other-case"), Q, case.id)
    bad_questions = (
        [],
        [{"id": "code", "text": "x", "type": "yesno"}],  # 예약된 id (elicitation 확인 코드)
        [{"id": "a", "text": "x", "type": "yesno"}, {"id": "a", "text": "y", "type": "yesno"}],
        [{"id": "Bad", "text": "x", "type": "yesno"}],
        [{"id": "a", "text": "x", "type": "choice"}],
        [{"id": "a", "text": "x", "type": "value", "expected": "yes"}],
        [{"id": "a", "text": "x", "type": "yesno", "expected": "no"}],
        [{"id": "a", "text": "", "type": "yesno"}],
        [{"id": "a", "text": "x", "type": "yesno", "default": "yes"}],
    )
    for qs in bad_questions:
        with pytest.raises(ValidationFailed):
            st.request("wiring", {"a": 1}, b, qs, case.id)
    for bad_subject in ("x", None, {"a": {1, 2}}, {"a": float("nan")}, {1: "x"}):
        with pytest.raises(ValidationFailed):
            st.request("wiring", bad_subject, b, Q, case.id)
    with pytest.raises(ValidationFailed):
        st.request("wiring", {"a": 1}, b, Q, case.id, valid_seconds=5)
    with pytest.raises(ValidationFailed):
        st.request("wiring", {"a": 1}, b, Q, "../escape")
    assert st.list() == []


def test_kinds_closed_set_and_code_only_extension():
    assert {"tag-purpose", "wiring", "console-offline", "payment-locked", "hdmi-source", "bridge-serial", "write-blocker",
            "provenance-import", "instrument-pin", "radio-target", "module-kc"} == set(ATTESTATION_KINDS)
    with pytest.raises(TypeError):
        ATTESTATION_KINDS["agent-made"] = "x"  # type: ignore[index]  # 읽기 전용 표
    with pytest.raises(ValidationFailed):
        register_kind("Bad Kind", "x")
    with pytest.raises(ValidationFailed):
        register_kind("wiring", "다른 설명")  # 이미 있는 종류의 뜻을 바꿀 수 없다
    register_kind("wiring", ATTESTATION_KINDS["wiring"])  # 같은 정의는 그대로


def test_wrong_kind_subject_or_binding_never_matches(workspace, auth):
    rt = get_runtime("test")
    case = _case(rt, auth)
    other = _case(rt, auth, "att-case-2")
    st = rt.attestations
    rec = st.request("wiring", {"plan_sha256": "aa" * 32, "harness": "H0"}, _bind(case.id), Q, case.id)
    _approve(st, rec["id"])
    assert st.require("wiring", {"plan_sha256": "aa" * 32, "harness": "H0"}, _bind(case.id))["id"] == rec["id"]
    assert st.require("instrument-pin", {"plan_sha256": "aa" * 32, "harness": "H0"}, _bind(case.id)) is None
    assert st.require("console-offline", {"plan_sha256": "aa" * 32, "harness": "H0"}, _bind(case.id)) is None
    assert st.require("wiring", {"plan_sha256": "bb" * 32, "harness": "H0"}, _bind(case.id)) is None
    assert st.require("wiring", {"plan_sha256": "aa" * 32}, _bind(case.id)) is None
    assert st.require("wiring", {"plan_sha256": "aa" * 32, "harness": "H0", "extra": 1}, _bind(case.id)) is None
    assert st.require("wiring", {"plan_sha256": "aa" * 32, "harness": "H0"}, _bind(other.id)) is None
    assert st.require("wiring", {"plan_sha256": "aa" * 32, "harness": "H0"},
                      {"scope": "connection", "connection_id": "conn-1", "case_id": case.id}) is None
    assert st.require("wiring", {"plan_sha256": "aa" * 32, "harness": "H0"}, {**_bind(case.id), "connection_id": "c1"}) is None


def test_revoked_expired_denied_never_satisfy(workspace, auth, monkeypatch):
    rt = get_runtime("test")
    case = _case(rt, auth)
    st = rt.attestations
    b = _bind(case.id)
    # 철회
    r1 = st.request("hdmi-source", {"source": "cap-1"}, b, Q, case.id)
    _approve(st, r1["id"])
    assert st.require("hdmi-source", {"source": "cap-1"}, b) is not None
    out = st.revoke(r1["id"], by="tester")
    assert out["status"] == "revoked" and out["revoked_by"] == "tester"
    assert st.require("hdmi-source", {"source": "cap-1"}, b) is None
    with pytest.raises(PwehError):
        st.revoke(r1["id"])
    with pytest.raises(PwehError):
        st.decide(r1["id"], {"offline": "yes", "voltage": "3.3"}, via="cli-tty")
    # 거부
    r2 = st.request("hdmi-source", {"source": "cap-2"}, b, Q, case.id)
    st.decide(r2["id"], {"offline": "no"}, via="cli-tty")
    assert st.require("hdmi-source", {"source": "cap-2"}, b) is None
    r3 = st.request("hdmi-source", {"source": "cap-3"}, b, Q, case.id)
    st.deny(r3["id"], via="elicitation", reason="decline")
    assert st.require("hdmi-source", {"source": "cap-3"}, b) is None
    # 만료: 승인 뒤 유효 기간이 지나면 쓸 수 없다
    r4 = st.request("hdmi-source", {"source": "cap-4"}, b, Q, case.id, valid_seconds=60)
    _approve(st, r4["id"])
    assert st.require("hdmi-source", {"source": "cap-4"}, b) is not None
    real_now = att_mod._now
    monkeypatch.setattr(att_mod, "_now", lambda: real_now() + dt.timedelta(seconds=61))
    assert st.require("hdmi-source", {"source": "cap-4"}, b) is None
    assert st.get(r4["id"])["status"] == "expired"
    # pending 도 만료되면(승인 TTL) 답할 수 없고, 같은 요청은 새 레코드를 만든다
    monkeypatch.setattr(att_mod, "_now", real_now)
    r5 = st.request("hdmi-source", {"source": "cap-5"}, b, Q, case.id)
    monkeypatch.setattr(att_mod, "_now", lambda: real_now() + dt.timedelta(seconds=rt.config.safety.approval_ttl_seconds + 5))
    assert st.get(r5["id"])["status"] == "expired"
    with pytest.raises(PwehError):
        _approve(st, r5["id"])
    r6 = st.request("hdmi-source", {"source": "cap-5"}, b, Q, case.id)
    assert r6["id"] != r5["id"] and r6["status"] == "pending"


def test_instrument_scope_lasts_until_revoked(workspace, auth, monkeypatch):
    rt = get_runtime("test")
    st = rt.attestations
    b = {"scope": "instrument", "instrument_id": "espprobe-f412fa123456"}
    rec = st.request("instrument-pin", {"usb_serial": "F4:12:FA:12:34:56"}, b, Q, None)
    out = _approve(st, rec["id"])
    assert out["expires_at"] is None and out["valid_seconds"] is None
    real_now = att_mod._now
    monkeypatch.setattr(att_mod, "_now", lambda: real_now() + dt.timedelta(days=400))
    assert st.require("instrument-pin", {"usb_serial": "F4:12:FA:12:34:56"}, b) is not None
    st.revoke(rec["id"])
    assert st.require("instrument-pin", {"usb_serial": "F4:12:FA:12:34:56"}, b) is None


# ---------------------------------------------------------------------------
# 음성 시험: 케이스 파일·사본·위조 레코드·승인 id
# ---------------------------------------------------------------------------


def test_case_files_and_mirror_are_never_proof(workspace, auth):
    rt = get_runtime("test")
    case = _case(rt, auth)
    st = rt.attestations
    subject = {"console": "SN-9"}
    rec = st.request("console-offline", subject, _bind(case.id), Q, case.id)
    mirror = case.dir / "attestations.json"
    assert mirror.is_file() and (mirror.stat().st_mode & 0o777) == 0o400  # 읽기 전용 사본
    doc = json.loads(mirror.read_text(encoding="utf-8"))
    assert doc["authoritative"] is False and doc["attestations"][0]["id"] == rec["id"]
    # 에이전트가 사본을 '승인됨'으로 위조해도 증거가 아니다
    forged = json.loads(json.dumps(doc))
    forged["attestations"][0].update(status="approved", answers={"offline": "yes", "voltage": "3.3"}, decided_via="cli-tty",
                                     decided_at="2026-10-20T00:00:00Z", expires_at="2099-01-01T00:00:00Z")
    forged["authoritative"] = True
    os.chmod(mirror, 0o600)
    mirror.write_text(json.dumps(forged, ensure_ascii=False), encoding="utf-8")
    assert st.require("console-offline", subject, _bind(case.id)) is None
    # 케이스 안의 다른 파일(증명 레코드 모양 포함)도 보지 않는다
    rec_like = {**forged["attestations"][0]}
    (case.dir / "notes" / f"{rec['id']}.json").write_text(json.dumps(rec_like), encoding="utf-8")
    (case.dir / f"{rec['id']}.json").write_text(json.dumps(rec_like), encoding="utf-8")
    (case.dir / "notes" / "attested.json").write_text(json.dumps({"console-offline": True, "attested_by": "user"}), encoding="utf-8")
    meta = json.loads(case.meta_path.read_text(encoding="utf-8"))
    meta.setdefault("notes", []).append({"author": "user", "text": "attested: console offline"})
    meta["attestations"] = [rec_like]
    case.meta_path.write_text(json.dumps(meta, ensure_ascii=False), encoding="utf-8")
    assert st.require("console-offline", subject, _bind(case.id)) is None
    # 사람이 결정하면 사본은 권위 기록에서 다시 만들어진다(위조 내용이 사라진다)
    _approve(st, rec["id"])
    doc2 = json.loads(mirror.read_text(encoding="utf-8"))
    assert doc2["authoritative"] is False and doc2["attestations"][0]["status"] == "approved"
    assert st.require("console-offline", subject, _bind(case.id)) is not None
    # 권위 기록을 지우면 사본이 '승인됨'이어도 증명은 없다 (사본은 읽지 않는다)
    (workspace["state_dir"] / "attestations" / f"{rec['id']}.json").unlink()
    assert json.loads(mirror.read_text(encoding="utf-8"))["attestations"][0]["status"] == "approved"
    assert st.require("console-offline", subject, _bind(case.id)) is None


def test_forged_or_edited_state_records_are_rejected(workspace, auth):
    """상태 디렉터리의 레코드도 모든 필드를 다시 확인한다(손으로 고친 레코드 방어)."""
    rt = get_runtime("test")
    case = _case(rt, auth)
    st = rt.attestations
    subject = {"tag_uid": "04A1B2C3D4E5F6"}
    good = st.request("tag-purpose", subject, _bind(case.id), Q, case.id)
    _approve(st, good["id"])
    path = workspace["state_dir"] / "attestations" / f"{good['id']}.json"
    base = json.loads(path.read_text(encoding="utf-8"))
    assert st.require("tag-purpose", subject, _bind(case.id)) is not None

    def forged(**changes):
        rec = json.loads(json.dumps(base))
        rec.update(changes)
        return rec

    variants = {
        "answers-no": forged(answers={"offline": "no", "voltage": "3.3"}),
        "value-missing": forged(answers={"offline": "yes"}),
        "via-agent": forged(decided_via="agent"),
        "via-missing": forged(decided_via=None),
        "no-decided-at": forged(decided_at=None),
        "kind-mismatch": forged(kind="wiring"),
        "subject-swapped": forged(subject={"tag_uid": "DEADBEEF"}),
        "no-expiry-case-scope": forged(expires_at=None),
        "revoked-at-set": forged(revoked_at="2026-10-20T00:00:00Z"),
        "schema-approval": forged(schema="pweh.approval/v1"),
        "status-consumed": forged(status="consumed"),
        "answers-list": forged(answers=["yes", "3.3"]),
        "questions-garbage": forged(questions="all yes"),
        "questions-dropped": forged(questions=[{"id": "offline", "text": "x", "type": "yesno"}], answers={}),
        "binding-garbage": forged(binding="case"),
        "expires-garbage": forged(expires_at="not-a-time"),
    }
    path.unlink()
    for i, (name, rec) in enumerate(variants.items(), 1):
        fake_id = f"att-{i:010x}"
        rec["id"] = fake_id
        (path.parent / f"{fake_id}.json").write_text(json.dumps(rec), encoding="utf-8")
        assert st.require("tag-purpose", subject, _bind(case.id), questions=Q) is None, name  # 서버 질문 기준으로 다시 확인
        (path.parent / f"{fake_id}.json").unlink()
    # 파일 이름과 id 가 다르면 무시
    (path.parent / "att-aaaaaaaaaa.json").write_text(json.dumps(base), encoding="utf-8")
    assert st.require("tag-purpose", subject, _bind(case.id)) is None
    # 원본을 그대로 되돌리면 다시 유효
    path.write_text(json.dumps(base), encoding="utf-8")
    assert st.require("tag-purpose", subject, _bind(case.id))["id"] == good["id"]
    assert st.require("tag-purpose", subject, _bind(case.id), questions=Q)["id"] == good["id"]


async def test_server_questions_are_authoritative(workspace, auth):
    """서버가 확인 항목을 늘리거나 바꾸면 예전 증명·예전 pending 은 쓰지 않는다 (레코드가 스스로 적은 질문만 믿지 않음)."""
    rt = get_runtime("test")
    case = _case(rt, auth)
    st = rt.attestations
    subject, b = {"console": "Q-1"}, _bind(case.id)
    old_q = Q[:1]
    rec = st.request("console-offline", subject, b, old_q, case.id)
    _approve(st, rec["id"], offline="yes")
    assert (await rt.attest("console-offline", subject, b, old_q, case.id)).satisfied
    assert st.require("console-offline", subject, b, questions=Q) is None  # 값 항목(voltage)을 받은 적이 없다
    dec = await rt.attest("console-offline", subject, b, Q, case.id)
    assert dec.status == "attestation_required" and dec.attestation_id != rec["id"]
    assert [q["id"] for q in st.get(dec.attestation_id)["questions"]] == ["offline", "voltage"]
    # 기대값을 바꾼 질문(정보 항목 → '예' 필요)도 다른 질문이다
    info_only = [{"id": "offline", "text": "콘솔을 오프라인으로 했나요?", "type": "yesno"}]
    rec2 = st.request("console-offline", {"console": "Q-2"}, b, info_only, case.id)
    st.decide(rec2["id"], {"offline": "no"}, via="cli-tty")
    assert st.require("console-offline", {"console": "Q-2"}, b, questions=info_only) is not None
    assert st.require("console-offline", {"console": "Q-2"}, b, questions=Q[:1]) is None
    # 더 약한 질문의 pending 은 더 강한 요청에 재사용하지 않는다
    weak = st.request("console-offline", {"console": "Q-3"}, b, info_only, case.id)
    strong = st.request("console-offline", {"console": "Q-3"}, b, Q, case.id)
    assert strong["id"] != weak["id"]
    assert st.request("console-offline", {"console": "Q-3"}, b, Q[:1], case.id)["id"] == strong["id"]  # 강한 pending 은 약한 요청을 덮는다


async def test_consumed_approval_id_is_never_an_attestation(workspace, auth):
    workspace["set_safety"](destructive_policy="approve", approval_methods=["cli"])
    rt = get_runtime("test")
    case = _case(rt, auth)
    cls = Classification(Risk.DESTRUCTIVE, "uboot.sf.erase", "sf erase", "sf erase 0 100")
    action = {"line": "sf erase 0 100"}
    d1 = await rt.authorize(tool="uart_send_command", action=action, classification=cls, case_id=case.id)
    ap = d1.approval_id
    rt.approvals.decide(ap, approve=True, code=rt.approvals.get(ap)["code"], via="test")
    d2 = await rt.authorize(tool="uart_send_command", action=action, classification=cls, case_id=case.id, approval_id=ap)
    assert d2.allowed and rt.approvals.get(ap)["status"] == "consumed"
    st = rt.attestations
    for fn in (lambda: st.get(ap), lambda: st.decide(ap, {}, via="cli-tty"), lambda: st.revoke(ap),
               lambda: st.deny(ap, via="cli-tty")):
        with pytest.raises(PwehError) as ei:
            fn()
        assert ei.value.code == "bad_attestation_id"
    # 승인 레코드 파일을 증명 디렉터리에 복사·이름 바꾸기 해도 증명이 아니다
    src = workspace["state_dir"] / "approvals" / f"{ap}.json"
    adir = workspace["state_dir"] / "attestations"
    adir.mkdir(parents=True, exist_ok=True)
    shutil.copy(src, adir / f"{ap}.json")
    shutil.copy(src, adir / "att-0123456789.json")
    approval_rec = json.loads(src.read_text(encoding="utf-8"))
    approval_rec["id"] = "att-0123456789"
    (adir / "att-0123456789.json").write_text(json.dumps(approval_rec), encoding="utf-8")
    assert st.list() == []
    with pytest.raises(PwehError) as ei:
        st.get("att-0123456789")
    assert ei.value.code == "attestation_invalid"
    for kind in ATTESTATION_KINDS:
        assert st.require(kind, {"line": "sf erase 0 100"}, _bind(case.id)) is None
        assert st.require(kind, action, _bind(case.id)) is None
    # 증명 도우미는 id 를 받지 않는다: 승인 id 를 subject 에 넣어도 새 증명 요청만 생긴다
    dec = await rt.attest("console-offline", {"console": "SN-1", "approval_id": ap}, _bind(case.id), Q, case.id)
    assert not dec.satisfied and dec.status == "attestation_required" and dec.attestation_id != ap
    with pytest.raises(TypeError):
        await rt.attest("console-offline", {"console": "SN-1"}, _bind(case.id), Q, case.id, approval_id=ap)  # type: ignore[call-arg]


# ---------------------------------------------------------------------------
# 서버 도우미 rt().attest
# ---------------------------------------------------------------------------


async def test_attest_helper_required_then_satisfied(workspace, auth):
    rt = get_runtime("test")
    case = _case(rt, auth)
    subject, binding = {"console": "SN-1"}, _bind(case.id)
    dec = await rt.attest("console-offline", subject, binding, Q, case.id, None, "콘솔 오프라인 확인", tool="input_connect")
    assert not dec.satisfied and dec.status == "attestation_required" and ID_RE.match(dec.attestation_id)
    resp = attestation_response(dec)
    assert resp["ok"] is False and resp["status"] == "attestation_required" and resp["attestation_id"] == dec.attestation_id
    assert resp["kind"] == "console-offline" and [q["id"] for q in resp["questions"]] == ["offline", "voltage"]
    assert f"pweh attest {dec.attestation_id}" in resp["how"] and "별도 터미널" in resp["how"]
    assert f"pweh attest {dec.attestation_id}" in resp["message"] and "subject" not in resp
    assert resp["summary"] == "콘솔 오프라인 확인"
    # 다시 불러도 같은 pending 을 쓴다
    dec2 = await rt.attest("console-offline", subject, binding, Q, case.id, None, "콘솔 오프라인 확인", tool="input_connect")
    assert dec2.attestation_id == dec.attestation_id and len(rt.attestations.list("pending")) == 1
    _approve(rt.attestations, dec.attestation_id)
    dec3 = await rt.attest("console-offline", subject, binding, Q, case.id, None, "콘솔 오프라인 확인", tool="input_connect")
    assert dec3.satisfied and dec3.status == "satisfied" and dec3.via == "existing" and dec3.record["id"] == dec.attestation_id
    assert dec3.record["answers"]["voltage"] == "3.3"
    events = [json.loads(line)["event"] for line in (case.dir / "audit.jsonl").read_text(encoding="utf-8").splitlines()]
    assert "attestation_requested" in events and "attestation_used" in events
    # 거부 뒤 다시 부르면 새 요청이 생기고 직전 결정이 응답에 실린다
    rt.attestations.revoke(dec.attestation_id)
    dec4 = await rt.attest("console-offline", subject, binding, Q, case.id)
    assert dec4.status == "attestation_required" and dec4.attestation_id != dec.attestation_id
    assert attestation_response(dec4)["previous"]["status"] == "revoked"


async def test_agent_attested_fields_are_ignored(workspace, auth):
    rt = get_runtime("test")
    case = _case(rt, auth)
    claim_subject = {"console": "SN-1", "attested": True, "attested_by": "user", "Attested_Offline": "yes"}
    claim_binding = {"scope": "case", "case_id": case.id, "attested": "yes"}
    dec = await rt.attest("console-offline", claim_subject, claim_binding, Q, case.id)
    assert not dec.satisfied and dec.status == "attestation_required"
    assert set(dec.ignored_agent_fields) == {"subject.attested", "subject.attested_by", "subject.Attested_Offline", "binding.attested"}
    assert set(attestation_response(dec)["ignored_agent_fields"]) == set(dec.ignored_agent_fields)
    rec = rt.attestations.get(dec.attestation_id)
    assert rec["subject"] == {"console": "SN-1"} and rec["binding"] == {"scope": "case", "case_id": case.id}
    assert rt.attestations.require("console-offline", claim_subject, claim_binding) is None
    # 같은 요청이다(주장 키는 지문에 들어가지 않음) → 사람이 승인해야만 충족된다
    plain = await rt.attest("console-offline", {"console": "SN-1"}, _bind(case.id), Q, case.id)
    assert plain.attestation_id == dec.attestation_id and not plain.satisfied
    _approve(rt.attestations, dec.attestation_id)
    assert (await rt.attest("console-offline", claim_subject, claim_binding, Q, case.id)).satisfied
    # 도우미에는 증명을 넘길 인자가 없다
    for bad in ({"attested": True}, {"attested_by": "user"}, {"answers": {"offline": "yes"}}):
        with pytest.raises(TypeError):
            await rt.attest("console-offline", {"console": "SN-2"}, _bind(case.id), Q, case.id, **bad)  # type: ignore[arg-type]
    assert rt.attestations.require("console-offline", {"console": "SN-2"}, _bind(case.id)) is None


class _Ctx:
    """가짜 MCP Context: elicitation 지원 + 정해진 답. schema 가 MCP 규격(원시 타입 필드만)인지도 확인한다."""

    def __init__(self, action: str = "accept", answers: dict | None = None, code: str | None = None, error: Exception | None = None):
        self.client_capabilities = SimpleNamespace(elicitation=object())
        self.action, self.answers, self.code, self.error = action, answers or {}, code, error
        self.messages: list[str] = []

    async def elicit(self, message, schema):
        from mcp.server.elicitation import render_elicitation_schema

        render_elicitation_schema(schema)  # 규격 밖 필드면 TypeError
        self.messages.append(message)
        if self.error is not None:
            raise self.error
        if self.action != "accept":
            return SimpleNamespace(action=self.action, data=None)
        code = self.code or re.search(r"확인 코드 ([A-Z0-9]{4})", message).group(1)
        fields = {f"q_{k}": v for k, v in self.answers.items()}  # 폼 필드 이름 = 'q_' + 질문 id
        return SimpleNamespace(action=self.action, data=schema(**{**fields, "code": code}))


async def test_attest_elicitation_paths(workspace, auth):
    workspace["set_safety"](approval_methods=["elicitation", "cli"])
    rt = get_runtime("test")
    case = _case(rt, auth)
    b = _bind(case.id)
    yes = {"offline": True, "voltage": "3.30"}
    ok = await rt.attest("console-offline", {"console": "E1"}, b, Q, case.id, _Ctx("accept", yes), "콘솔 E1")
    assert ok.satisfied and ok.via == "elicitation" and ok.record["decided_via"] == "elicitation"
    assert ok.record["decided_by"] == "client-user" and ok.record["answers"] == {"offline": "yes", "voltage": "3.30"}
    assert rt.attestations.require("console-offline", {"console": "E1"}, b)["id"] == ok.attestation_id
    no = await rt.attest("console-offline", {"console": "E2"}, b, Q, case.id, _Ctx("accept", {"offline": False, "voltage": "3.3"}))
    assert not no.satisfied and no.status == "denied" and rt.attestations.get(no.attestation_id)["status"] == "denied"
    wrong = await rt.attest("console-offline", {"console": "E3"}, b, Q, case.id, _Ctx("accept", yes, code="ZZZZ"))
    assert wrong.status == "denied" and rt.attestations.get(wrong.attestation_id)["status"] == "denied"
    declined = await rt.attest("console-offline", {"console": "E4"}, b, Q, case.id, _Ctx("decline"))
    assert declined.status == "denied" and "우회" in declined.message
    ctx = _Ctx(error=RuntimeError("client does not support"))
    fb = await rt.attest("console-offline", {"console": "E5"}, b, Q, case.id, ctx)
    assert fb.status == "attestation_required" and rt.attestations.get(fb.attestation_id)["status"] == "pending"
    assert "확인 코드" in ctx.messages[0] and "console-offline" in ctx.messages[0]
    # pydantic BaseModel 이름과 같은 질문 id 도 폼을 만들 수 있다
    odd_q = [{"id": "model_config", "text": "배선을 직접 확인했다", "type": "yesno", "expected": "yes"},
             {"id": "schema", "text": "잰 전압(V)", "type": "value"}]
    odd = await rt.attest("wiring", {"plan": "odd"}, b, odd_q, case.id, _Ctx("accept", {"model_config": True, "schema": "3.3"}))
    assert odd.satisfied and odd.record["answers"] == {"model_config": "yes", "schema": "3.3"}
    # elicitation 이 꺼져 있으면 ctx 가 있어도 cli 로만
    workspace["set_safety"](approval_methods=["cli"])
    rt = get_runtime("test")
    only_cli = await rt.attest("console-offline", {"console": "E6"}, b, Q, case.id, _Ctx("accept", yes))
    assert only_cli.status == "attestation_required"
    # 확인 방법이 하나도 없으면(elicitation 만 + 미지원 클라이언트) 레코드 없이 거부
    workspace["set_safety"](approval_methods=["elicitation"])
    rt = get_runtime("test")
    n_before = len(rt.attestations.list())
    none = await rt.attest("console-offline", {"console": "E7"}, b, Q, case.id, None)
    assert none.status == "denied" and none.attestation_id is None and len(rt.attestations.list()) == n_before


# ---------------------------------------------------------------------------
# CLI: pweh attest
# ---------------------------------------------------------------------------


def _cli_env(workspace) -> dict:
    env = dict(os.environ)
    env["PWEH_CONFIG"] = str(workspace["config"])
    env["USER"] = "pweh-tester"
    env.pop("PWEH_STATE_DIR", None)
    env.pop("PWEH_CASES_DIR", None)
    return env


def _run(args, workspace, input_text=None):
    return subprocess.run([sys.executable, "-m", "pweh.cli", *args], capture_output=True, text=True, env=_cli_env(workspace),
                          input=input_text, timeout=60)


def _pty_run(args, workspace, answers: list[str], timeout: float = 60.0, code: str | None = "auto") -> tuple[int, str]:
    """PTY 에서 pweh 를 실행하고 '답>' 프롬프트마다 answers 를 하나씩 보낸다. 반환: (종료 코드, 출력).

    '확인 코드>' 프롬프트에는 code="auto" 면 화면에 표시된 코드를 읽어 보내고(사람처럼), 문자열이면 그것을 보낸다(틀린 코드·빈 입력 시험).
    """
    import pty
    import select

    env = _cli_env(workspace)
    pid, fd = pty.fork()
    if pid == 0:  # pragma: no cover - 자식 프로세스
        os.execvpe(sys.executable, [sys.executable, "-m", "pweh.cli", *args], env)
    out = b""
    pending = list(answers)
    answered = 0
    marker = "답>".encode()
    code_marker = "확인 코드>".encode()
    codes_sent = 0
    deadline = time.time() + timeout
    eof = False
    while time.time() < deadline and not eof:
        ready, _, _ = select.select([fd], [], [], 0.5)
        if ready:
            try:
                chunk = os.read(fd, 4096)
            except OSError:
                chunk = b""
            if not chunk:
                eof = True
            out += chunk
        if out.count(marker) > answered and pending:
            os.write(fd, (pending.pop(0) + "\n").encode())
            answered += 1
        if out.count(code_marker) > codes_sent:
            if code == "auto":
                shown = re.findall(r"확인 코드를 그대로 입력하세요: ([A-Z0-9]{4})", out.decode("utf-8", "replace"))
                send = shown[-1] if shown else ""
            else:
                send = code or ""
            os.write(fd, (send + "\n").encode())
            codes_sent += 1
    if not eof:  # pragma: no cover - 멈춘 자식 정리
        os.kill(pid, signal.SIGKILL)
    _, status = os.waitpid(pid, 0)
    os.close(fd)
    return os.waitstatus_to_exitcode(status), out.decode("utf-8", "replace")


def test_cli_attest_refuses_without_tty(workspace, auth):
    rt = get_runtime("test")
    case = _case(rt, auth)
    pend = rt.attestations.request("console-offline", {"console": "SECRET-SN-77"}, _bind(case.id), Q, case.id)
    appr = rt.attestations.request("console-offline", {"console": "SN-2"}, _bind(case.id), Q, case.id)
    _approve(rt.attestations, appr["id"])
    for args, text in ((["attest", pend["id"]], "y\n3.3\n"), (["attest", "--list"], None), (["attest", "--list", "--all"], None),
                       (["attest", "--revoke", appr["id"]], "y\n")):
        r = _run(args, workspace, input_text=text)
        assert r.returncode == 2, (args, r.stdout, r.stderr)
        assert "대화형 터미널" in r.stderr and "에이전트" in r.stderr
        assert "SECRET-SN-77" not in r.stdout + r.stderr  # TTY 가 아니면 내용도 보여 주지 않는다
    assert rt.attestations.get(pend["id"])["status"] == "pending"
    assert rt.attestations.get(appr["id"])["status"] == "approved"


def test_cli_attest_tty_answers_record_human_decision(workspace, auth):
    rt = get_runtime("test")
    case = _case(rt, auth)
    rec = rt.attestations.request("console-offline", {"console": "SN-1"}, _bind(case.id), Q, case.id, "콘솔 오프라인 확인",
                                  server="input-mcp", tool="input_connect")
    # 잘못된 답은 다시 묻고(maybe), y 와 값으로 승인
    rc, out = _pty_run(["attest", rec["id"]], workspace, ["maybe", "y", "3.3"])
    assert rc == 0, out
    assert "console-offline" in out and "SN-1" in out and "콘솔의 네트워크" in out and "증명을 기록했습니다" in out
    assert "y 또는 n" in out
    got = get_runtime("test").attestations.get(rec["id"])
    assert got["status"] == "approved" and got["decided_via"] == "cli-tty" and got["decided_by"] == att_mod.os_user() != "pweh-tester"
    assert got["answers"] == {"offline": "yes", "voltage": "3.3"}
    assert get_runtime("test").attestations.require("console-offline", {"console": "SN-1"}, _bind(case.id))["id"] == rec["id"]
    audit = (case.dir / "audit.jsonl").read_text(encoding="utf-8")
    assert "attestation_decided" in audit and att_mod.os_user() in audit and "pweh-tester" not in audit
    # 이미 결정된 요청에는 답할 수 없다
    rc, out = _pty_run(["attest", rec["id"]], workspace, [])
    assert rc == 1 and "답할 수 없는 상태" in out
    # 목록 (TTY)
    rc, out = _pty_run(["attest", "--list", "--all"], workspace, [])
    assert rc == 0 and rec["id"] in out and "approved" in out
    # 철회 (TTY, 확인 y)
    rc, out = _pty_run(["attest", "--revoke", rec["id"]], workspace, ["y"])
    assert rc == 0 and "철회했습니다" in out, out
    got = get_runtime("test").attestations.get(rec["id"])
    assert got["status"] == "revoked" and got["revoked_by"] == att_mod.os_user()
    assert get_runtime("test").attestations.require("console-offline", {"console": "SN-1"}, _bind(case.id)) is None


def test_cli_attest_tty_no_and_cancel(workspace, auth):
    rt = get_runtime("test")
    case = _case(rt, auth)
    a = rt.attestations.request("console-offline", {"console": "N-1"}, _bind(case.id), Q, case.id)
    rc, out = _pty_run(["attest", a["id"]], workspace, ["n"])
    assert rc == 0 and "거부" in out, out
    assert get_runtime("test").attestations.get(a["id"])["status"] == "denied"
    b = rt.attestations.request("console-offline", {"console": "N-2"}, _bind(case.id), Q, case.id)
    rc, out = _pty_run(["attest", b["id"]], workspace, ["y", ""])  # 값 항목에서 빈 입력 → 취소
    assert rc == 1 and "취소" in out, out
    assert get_runtime("test").attestations.get(b["id"])["status"] == "pending"
    rc, out = _pty_run(["attest", "--revoke", b["id"]], workspace, [""])  # 철회 확인을 하지 않음
    assert rc == 1 and get_runtime("test").attestations.get(b["id"])["status"] == "pending"


def test_cli_attest_rejects_approval_ids_and_is_distinct_from_case_attest(workspace, auth):
    from pweh import cli

    rc, out = _pty_run(["attest", "ap-0123456789"], workspace, [])
    assert rc == 1 and "bad_attestation_id" in out, out
    parser = cli.build_parser()
    assert parser.parse_args(["attest", "att-0123456789"]).fn is cli.cmd_attest
    assert parser.parse_args(["attest", "--list"]).fn is cli.cmd_attest
    assert parser.parse_args(["attest", "--revoke", "att-0123456789"]).fn is cli.cmd_attest
    assert parser.parse_args(["case", "attest", "some-case"]).fn is cli.cmd_case_attest
    with pytest.raises(SystemExit):
        parser.parse_args(["attest", "--list", "--revoke", "att-0123456789"])


def test_cli_attest_needs_confirmation_code(workspace, auth):
    """답을 미리 흘려 넣는 것만으로는 승인되지 않는다: 승인이 될 답이면 화면의 무작위 확인 코드를 입력해야 기록된다(pweh approve 와 같은 수준).
    틀린 코드·빈 입력이면 아무것도 기록하지 않고 요청은 대기 상태로 남는다. 거부가 될 답('아니오')은 코드 없이 기록된다."""
    rt = get_runtime("test")
    case = _case(rt, auth)
    rec = rt.attestations.request("console-offline", {"console": "C-1"}, _bind(case.id), Q, case.id)
    rc, out = _pty_run(["attest", rec["id"]], workspace, ["y", "3.3"], code="ZZZZ")  # 알파벳에 Z 는 없다 → 늘 틀림
    assert rc == 1 and "확인 코드가 다르거나" in out, out
    assert get_runtime("test").attestations.get(rec["id"])["status"] == "pending"
    rc, out = _pty_run(["attest", rec["id"]], workspace, ["y", "3.3"], code="")
    assert rc == 1 and get_runtime("test").attestations.get(rec["id"])["status"] == "pending", out
    assert get_runtime("test").attestations.require("console-offline", {"console": "C-1"}, _bind(case.id)) is None
    rc, out = _pty_run(["attest", rec["id"]], workspace, ["y", "3.3"])  # 화면의 코드를 입력
    assert rc == 0 and "증명을 기록했습니다" in out, out
    assert get_runtime("test").attestations.get(rec["id"])["status"] == "approved"


def test_naive_timestamps_are_untrusted_and_do_not_break_the_store(workspace, auth):
    """시간대가 없는 시각을 가진 레코드(손으로 만든 것 등)는 신뢰하지 않고, 저장소 전체(require·list·request)를 멈추게 하지도 않는다."""
    from pweh.fsutil import atomic_write_json

    rt = get_runtime("test")
    case = _case(rt, auth)
    good = rt.attestations.request("console-offline", {"console": "SN-T"}, _bind(case.id), Q, case.id)
    _approve(rt.attestations, good["id"])
    adir = workspace["state_dir"] / "attestations"
    naive_ok = dict(rt.attestations.get(good["id"]), id="att-00000000ab", expires_at="2099-01-01T00:00:00")
    atomic_write_json(adir / "att-00000000ab.json", naive_ok)
    naive_pending = dict(rt.attestations.get(good["id"]), id="att-00000000ac", status="pending", answers=None,
                         decided_at=None, decided_by=None, decided_via=None, expires_at="2099-01-01T00:00:00")
    atomic_write_json(adir / "att-00000000ac.json", naive_pending)
    assert rt.attestations.require("console-offline", {"console": "SN-T"}, _bind(case.id))["id"] == good["id"]
    assert {"att-00000000ab", "att-00000000ac", good["id"]} <= {r["id"] for r in rt.attestations.list()}
    rt.attestations.revoke(good["id"], by="tester")
    assert rt.attestations.require("console-offline", {"console": "SN-T"}, _bind(case.id)) is None  # 시간대 없는 승인은 불신
    again = rt.attestations.request("console-offline", {"console": "SN-T"}, _bind(case.id), Q, case.id)
    assert again["id"] not in ("att-00000000ac", good["id"])  # 시간대 없는 pending 은 재사용하지 않는다
