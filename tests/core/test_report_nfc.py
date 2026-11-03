"""보고서 §8.2 NFC 분석 결과: Ultralight 분석 JSON 을 sha256·schema 대조 뒤 싣고 원시 값은 싣지 않는다."""
from __future__ import annotations

import copy
import hashlib
import json
import os
import time

import pytest

from pweh import nfc_cu_ul_snapshot as U
from pweh.runtime import get_runtime

UID = bytes.fromhex("04a1b2c3d4e5f6")
USER_VALUE = "c0ffee01"
OTP_VALUE = "f1f0ffff"
TAG_REF = "UT-" + "1" * 32


def _snapshot() -> dict:
    pages = [bytes((i, 0x55, 9, 0xa5)) for i in range(20)]
    pages[0] = UID[:3] + bytes((0x88 ^ UID[0] ^ UID[1] ^ UID[2],))
    pages[1] = UID[3:7]
    pages[2] = bytes((UID[3] ^ UID[4] ^ UID[5] ^ UID[6], 0x48, 0x00, 0xf0))
    pages[3] = bytes.fromhex(OTP_VALUE)
    pages[5] = bytes.fromhex(USER_VALUE)
    pages[9] = b"\x00" * 4
    pages[16] = bytes.fromhex("000000ff")
    pages[17] = bytes.fromhex("00050000")
    false = ["snapshot_atomic", "physical_same_tag_verified", "device_command_termination_verified",
             "rf_off_verified", "host_crc_verified", "tag_content_written", "authentication_attempted",
             "emulation_performed", "read_sig_sent", "read_cnt_sent"]
    return {"schema": "pweh.nfc-cu-ul-snapshot/v1", "profile": "cu-ultralight-pages-v1",
            "binding": {"ul_tag_ref": TAG_REF, "ul_scan_ref": "US-" + "2" * 32,
                        "ul_identity_digest": "sha256:" + "3" * 16, "scan_seq": 1, "scan_entry_sha256": "4" * 64,
                        "inventory_seq": 2, "inventory_entry_sha256": "5" * 64},
            "attestation": {"kind": "tag-ownership", "attestation_id": "att-0123456789"},
            "reader": {"profile": "cu-ultralight-v2.3.0-v1",
                       "profile_sha256": "fde75c1da05251b816628e491b9e554d556857f455b39dc439df46a78225b728",
                       "firmware_commit": "4e1a5b267b9ed33559e0e2c9dad61d61eaf64ba1", "app_version": "2.3",
                       "git_version": "v2.3.0"},
            "identity": {"family": "ultralight_ev1_mf0ul11", "uid": UID.hex(), "atqa_msb": "0044", "sak": "00",
                         "mifare_version": "0004030101000b03"},
            "pages_total": 20, "read_last_target": 17, "withheld_pages": {"pwd_pack_readback_zero": [18, 19]},
            "pages": [p.hex() if i < 18 else None for i, p in enumerate(pages)], "pages_observed": 18,
            "read_end": {"kind": "end_of_targets", "page": None}, "observed_variant": "ultralight_ev1_mf0ul11",
            "read_complete": True, "stop_reason": None, "activation_per_page": True,
            "unobserved_fields": ["signature", "counters", "tearing"], **{k: False for k in false}}


def _analysis(profile_v1: bool = False) -> bytes:
    data = (json.dumps(_snapshot(), sort_keys=True, separators=(",", ":")) + "\n").encode("ascii")
    snapshot = U.parse_cu_ul_snapshot(data, deadline=time.monotonic() + 5)
    inspection = U.inspect_cu_ul_snapshot(snapshot, deadline=time.monotonic() + 5)
    if profile_v1:
        inspection = copy.deepcopy(inspection)
        inspection["profile"] = "cu-ultralight-snapshot-analysis-v1"
        inspection["limitations"] = inspection["limitations"][:-1]
        del inspection["summary"]["fields"]
    report = {"schema": U.REPORT_SCHEMA, "operation": "inspect", "status": inspection["status"],
              "source": {"kind": "case-artifact", "tag_ref": TAG_REF, "scan_ref": "US-" + "2" * 32,
                         "scan_entry_sha256": "4" * 64, "inventory_entry_sha256": "5" * 64,
                         "tag_ownership_attestation_id": "att-0123456789",
                         "files": [{"artifact_id": "A-0001", "size": len(data), "sha256": "6" * 64,
                                    "provenance_kind": "device-read", "ledger_seq": 3,
                                    "ledger_entry_sha256": "7" * 64, "read_attestation_id": "att-0123456789"}]},
              "params": {"profile": inspection["profile"], "max_seconds": 5}, "inspection": inspection,
              "inventory_binding_verified": True, "physical_same_tag_verified": False}
    return (json.dumps(report, ensure_ascii=False, sort_keys=True) + "\n").encode("utf-8")


def _record(case, data: bytes, *, name: str = "analysis/nfc-ul-file-001.json", sha: str | None = None,
            write: bool = True, register: str | None = "pweh-nfc", operation: str = "inspect") -> None:
    """분석 파일을 두고(선택) pweh-nfc 처럼 등록한 뒤 nfc-analysis 요약에 넣는다."""
    digest = sha or hashlib.sha256(data).hexdigest()
    if write:
        path = case.path(name)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
    artifact_id = "A-9999"
    if register is not None:
        art = case.register_artifact(name, kind="other", producer=register, sha256=digest,
                                     extra={"type": "nfc-ul-file-analysis"} if register == "pweh-nfc" else None)
        artifact_id = art["id"]
    summary = {"schema": "pweh.nfc-analysis/v1", "mode": "scan-bound-offline",
               "tags": [{"tag_ref": TAG_REF, "scan_ref": "US-" + "2" * 32, "family": "ultralight_ev1_mf0ul11",
                         "ul_identity_digest": "sha256:" + "3" * 16, "tag_ownership_attestation_id": "att-0123456789"}],
               "results": [{"artifact_id": artifact_id, "path": name, "sha256": digest,
                            "operation": operation, "status": "ok", "tag_ref": TAG_REF}],
               "physical_same_tag_verified": False, "tag_content_written": False,
               "authentication_attempted": False, "emulation_performed": False}
    case.record_step(skill="nfc-behavior-analysis", step="summary", status="success", summary="UL 분석", data=summary)


def _section(text: str) -> str:
    return text[text.index("## 8.2 NFC 분석 결과"): text.index("## 9.")]


@pytest.fixture
def case(workspace, auth):
    return get_runtime("test").cases.create(title="NFC 보고서", authorization=auth)


def test_v2_fields_are_rendered_without_raw_values(case):
    from pweh.report import render_report

    assert "## 8.2 NFC 분석 결과" not in render_report(case)
    _record(case, _analysis())
    text = render_report(case)
    section = text[text.index("## 8.2 NFC 분석 결과"): text.index("## 9.")]
    assert "| 정적 잠금 (page 2) | 잠긴 사용자 page 12–15; OTP 잠금 아니오;" in section
    assert "32비트 중 25비트 켜짐" in section
    assert "기록 4–8, 10–15, 모두 0x00 9" in section
    assert "AUTH0=0xFF, 비밀번호 보호 꺼짐" in section and "VCTID=0x05" in section
    assert "보호 범위(PROT) 쓰기만" in section and "인증 실패 제한(AUTHLIM) 없음" in section
    for raw in (UID.hex(), USER_VALUE, OTP_VALUE):
        assert raw not in text
    limits = text[text.index("## 10."):]
    assert "NFC 분석 `analysis/nfc-ul-file-001.json` 한계:" in limits and "standard_fields_are_stored_values" in limits


def test_v1_analysis_says_fields_are_missing(case):
    from pweh.report import render_report

    _record(case, _analysis(profile_v1=True))
    text = render_report(case)
    assert "표준 필드 해석 없음(분석 프로필 v1)" in text and "| 정적 잠금" not in text


def test_hash_mismatch_links_fifo_and_bad_paths_are_not_rendered(case, tmp_path):
    from pweh.report import _load_nfc_result, render_report

    data = _analysis()
    # 등록 sha 와 요약 sha 는 같지만 파일 내용이 다르다.
    _record(case, data, sha="0" * 64)
    text = render_report(case)
    assert "- 싣지 않음: sha256 불일치" in text and "| 정적 잠금" not in text
    assert "NFC 분석 `analysis/nfc-ul-file-001.json` 을 보고서에 싣지 못함(sha256 불일치)." in text

    # 등록 뒤 파일을 케이스 밖·안 심볼릭 링크, 하드 링크, FIFO 로 바꿔도 열지 않고 보고서 생성은 계속된다.
    unsafe = "- 싣지 않음: 파일 없음, 링크이거나 일반 파일이 아님"
    outside = tmp_path / "outside.json"
    outside.write_bytes(data)
    inside = case.path("analysis/real.json")
    inside.parent.mkdir(parents=True, exist_ok=True)
    inside.write_bytes(data)
    swaps = {"002": lambda link: os.symlink(outside, link), "004": lambda link: os.symlink(inside, link),
             "005": lambda link: os.link(inside, link), "006": os.mkfifo}
    for number, swap in swaps.items():
        name = f"analysis/nfc-ul-file-{number}.json"
        _record(case, data, name=name)
        link = case.dir / name
        link.unlink()
        swap(link)
        assert unsafe in render_report(case), number

    tampered = json.loads(data)
    tampered["inspection"]["summary"]["fields"]["otp"]["bits_set"] = 99
    bad = (json.dumps(tampered) + "\n").encode()
    _record(case, bad, name="analysis/nfc-ul-file-003.json")
    assert "- 싣지 않음: schema 검증 실패" in render_report(case)

    # snapshot·경로 탈출은 정규식 단계에서 열지 않는다.
    case.path("nfc").mkdir(exist_ok=True)
    case.path("nfc/cu-ul-read-001.json").write_bytes(data)
    for rel in ("nfc/cu-ul-read-001.json", "analysis/../nfc/cu-ul-read-001.json", "/etc/passwd",
                "analysis/nfc-ul-file-001.json.bak"):
        assert _load_nfc_result(case, {"path": rel, "sha256": hashlib.sha256(data).hexdigest()}) == (
            None, "지원하지 않는 경로")


def test_unregistered_or_agent_registered_files_are_not_rendered_as_server_analysis(case):
    from pweh.report import render_report

    data = _analysis()
    for name, register in (("analysis/nfc-ul-file-001.json", None), ("analysis/nfc-ul-file-002.json", "agent"),
                           ("analysis/nfc-ul-file-003.json", "pweh-nfc-but-other")):
        _record(case, data, name=name, register=register)
        section = _section(render_report(case))
        assert "- 싣지 않음: pweh-nfc 가 등록한 분석 결과가 아님" in section and "| 정적 잠금" not in section


def test_render_failure_is_contained(case, monkeypatch):
    from pweh import report

    _record(case, _analysis())
    monkeypatch.setattr(report, "_nfc_ul_lines", lambda _report: (_ for _ in ()).throw(TypeError("x")))
    text = report.render_report(case)
    assert "- 싣지 않음: 표시 실패(값이 서로 맞지 않음)" in text and "## 10." in text


def _diff(change: bool, *, partial: bool = False) -> bytes:
    snapshot = _snapshot()
    before_bytes = (json.dumps(snapshot, sort_keys=True, separators=(",", ":")) + "\n").encode("ascii")
    after = copy.deepcopy(snapshot)
    if change:
        after["pages"][6] = "0badf00d"
    if partial:
        after.update(pages=[p if i < 16 else None for i, p in enumerate(after["pages"])], pages_observed=16,
                     read_end={"kind": "nak_without_rollover", "page": 16}, read_complete=False, stop_reason="tag_nak")
    after_bytes = (json.dumps(after, sort_keys=True, separators=(",", ":")) + "\n").encode("ascii")
    deadline = time.monotonic() + 5
    snaps = [U.parse_cu_ul_snapshot(b, deadline=deadline) for b in (before_bytes, after_bytes)]
    inspection = U.diff_cu_ul_snapshots(*snaps, deadline=deadline)
    files = [{"artifact_id": f"A-000{i + 1}", "size": len(b), "sha256": "6" * 64, "provenance_kind": "device-read",
              "ledger_seq": 3 + i, "ledger_entry_sha256": "7" * 64, "read_attestation_id": "att-0123456789"}
             for i, b in enumerate((before_bytes, after_bytes))]
    report = {"schema": U.REPORT_SCHEMA, "operation": "diff", "status": inspection["status"],
              "source": {"kind": "case-artifact", "tag_ref": TAG_REF, "scan_ref": "US-" + "2" * 32,
                         "scan_entry_sha256": "4" * 64, "inventory_entry_sha256": "5" * 64,
                         "tag_ownership_attestation_id": "att-0123456789", "files": files},
              "params": {"profile": inspection["profile"], "max_seconds": 5}, "inspection": inspection,
              "inventory_binding_verified": True, "physical_same_tag_verified": False}
    return (json.dumps(report, ensure_ascii=False, sort_keys=True) + "\n").encode("utf-8")


def test_diff_results_render_comparison_and_undecided_equality(case):
    from pweh.report import render_report

    _record(case, _diff(True), name="analysis/nfc-ul-diff-001.json", operation="diff")
    section = _section(render_report(case))
    assert "비교 18 page" in section and "바뀐 page 6" in section and "저장 page 동일 아니오" in section
    _record(case, _diff(False), name="analysis/nfc-ul-diff-002.json", operation="diff")
    assert "바뀐 page 없음" in _section(render_report(case)) and "저장 page 동일 예" in _section(render_report(case))
    _record(case, _diff(False, partial=True), name="analysis/nfc-ul-diff-003.json", operation="diff")
    section = _section(render_report(case))
    assert "읽기 끝 달라짐 예" in section and "저장 page 동일 판단 안 함" in section and "미관찰" not in section
    assert "0badf00d" not in render_report(case)
