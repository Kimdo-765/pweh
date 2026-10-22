"""합성 후보 JSON의 보관 기록 결속과 증거 목록 파생 산출물 판정."""

from __future__ import annotations

import copy
import hashlib
import json
import stat

import pytest
from mcp import Client

from core.test_evidence import _commit_intake
from mcp_helpers import call
from pweh import evidence as E
from pweh.case import CaseStore


@pytest.fixture
def anyio_backend():
    return "asyncio"


@pytest.fixture
def candidate_output(workspace, auth):
    from forensics_mcp import server as S

    case = CaseStore(workspace["cases_dir"]).create(
        title="합성 미디어 후보 보관", authorization=auth, case_id="candidate-custody")
    log = S.custody(case)
    ev = _commit_intake(case, log, b"synthetic candidate evidence\n")
    with E.open_checked(case, ev, log.entries()) as opened:
        # 후보 파서의 의미 검사는 별도 시험한다. 여기서는 공용 저장·목록 경로의 출처 결속을 검증한다.
        report = {
            "schema": "pweh.media-candidates/v1", "status": "unsupported",
            "source": {"kind": "evidence", "evidence_id": ev,
                       "evidence_sha256": opened.intake["hashes"]["sha256"]},
            "params": {"partition": None, "method": "auto", "max_seconds": 45},
            "candidates": [], "summary": {"candidates_reported": 0},
            "physical_carving_performed": False,
        }
        result = E.store_analysis(case, opened, report, event="media-candidates", custody_log=log)
    return case, log, result


@pytest.mark.anyio
async def test_candidate_report_is_recorded_by_existing_evidence_list(candidate_output):
    from forensics_mcp import server as S

    case, log, result = candidate_output
    analysis = result["analysis"]
    saved = case.dir / analysis["path"]
    assert stat.S_IMODE(saved.stat().st_mode) == 0o444
    assert saved.stat().st_size == analysis["size"]
    assert hashlib.sha256(saved.read_bytes()).hexdigest() == analysis["sha256"]
    assert log.entries()[-1]["event"] == "media-candidates"
    async with Client(S.server) as client:
        listed = await call(client, "forensics_evidence_list", case_id=case.id, write_files=False)
    assert listed.get("ok"), listed
    item, = listed["derived"]
    assert item["path"] == analysis["path"]
    assert item["kind"] == "media-candidates" and item["custody"] == "recorded"
    assert item["manifest_sha256"] == analysis["sha256"]
    assert item["evidence_id"] == "EV-0001" and item["custody_seq"] == analysis["custody_seq"]
    assert item["bytes"] == analysis["size"] and item["files"] == 1 and item["previews"] == []
    assert not (case.dir / "forensics/recovered").exists()
    assert all(entry["event"] != "extract" for entry in log.entries())


@pytest.mark.parametrize("mutation,expected", [("tamper", "mismatch"), ("missing", "missing")])
def test_candidate_report_tamper_or_removal_is_not_recorded(candidate_output, mutation, expected):
    from forensics_mcp import server as S

    case, log, result = candidate_output
    saved = case.dir / result["analysis"]["path"]
    if mutation == "missing":
        saved.unlink()
    else:
        raw = saved.read_bytes()
        saved.chmod(0o644)
        saved.write_bytes(raw.replace(b"unsupported", b"unsupported!", 1))
        saved.chmod(0o444)
    item, = S._derived_outputs(case, log.entries())
    assert item["kind"] == "media-candidates" and item["custody"] == expected


def test_unrecorded_candidate_json_does_not_supply_paths_or_content(candidate_output, monkeypatch):
    from forensics_mcp import server as S

    case, log, result = candidate_output
    path = case.dir / "forensics/analysis/media-candidates-EV-0001-999.json"
    private = "SYNTHETIC_PRIVATE_CANDIDATE_BODY"
    path.write_text(json.dumps({"source": {"path": private},
                                "previews": [{"path": private}], "candidates": [private]}))
    path.chmod(0o444)
    entries = log.entries()
    read = S.safeio.read_regular
    seen = []

    def limited_read(name, **kwargs):
        seen.append(name)
        assert name in {path.name, (case.dir / result["analysis"]["path"]).name}
        return read(name, **kwargs)

    monkeypatch.setattr(S.safeio, "read_regular", limited_read)
    outputs = {item["path"]: item for item in S._derived_outputs(case, entries)}
    planted = outputs[path.relative_to(case.dir).as_posix()]
    assert planted["custody"] == "unrecorded"
    assert "evidence_id" not in planted and "files" not in planted and "bytes" not in planted
    assert private not in json.dumps(outputs)
    assert len(seen) == 2


@pytest.mark.parametrize("changed", ["source", "intake"])
def test_candidate_matching_hash_still_requires_original_source_binding(candidate_output, changed):
    from forensics_mcp import server as S

    case, log, result = candidate_output
    entries = copy.deepcopy(log.entries())
    if changed == "source":
        entries[-1]["data"]["source"]["evidence_sha256"] = "0" * 64
    else:
        entries[0]["data"]["hashes"]["sha256"] = "0" * 64
    item, = S._derived_outputs(case, entries)
    assert item["manifest_sha256"] == result["analysis"]["sha256"]
    assert item["custody"] == "mismatch"


def test_candidate_custody_unknown_is_not_absence_or_recorded(candidate_output):
    from forensics_mcp import server as S

    case, _, result = candidate_output
    item, = S._derived_outputs(case, None)
    assert item["path"] == result["analysis"]["path"] and item["custody"] == "unknown"
