"""새 분석 사건도 증거 목록에서 실제 바이트와 custody 출처를 대조한다."""

from __future__ import annotations

import json
import os

import pytest
from mcp import Client

from core.test_evidence import _commit_intake
from mcp_helpers import call
from pweh import evidence as E
from pweh.case import CaseStore

pytestmark = pytest.mark.anyio


@pytest.fixture
def anyio_backend():
    return "asyncio"


@pytest.mark.parametrize("event", ["secrets-scan", "secrets-survey", "sd-ioc-scan", "media-inventory", "dhav-candidates", "dhav-scan", "media-unit-candidates"])
async def test_analysis_inventory_recorded_tampered_missing_and_unrecorded(workspace, auth, event):
    from forensics_mcp import server as S

    case = CaseStore(workspace["cases_dir"]).create(title="합성 분석 목록", authorization=auth, case_id="analysis-inventory")
    log = S.custody(case)
    ev = _commit_intake(case, log, b"synthetic source for analysis inventory\n")
    with E.open_checked(case, ev, log.entries()) as opened:
        report = {"status": "ok", "source": {"kind": "evidence", "evidence_id": ev,
                  "evidence_sha256": opened.intake["hashes"]["sha256"]}, "params": {}, "matches": []}
        result = E.store_analysis(case, opened, report, event=event, custody_log=log)
    rel = result["analysis"]["path"]
    saved = case.dir / rel

    async with Client(S.server) as client:
        response = await call(client, "forensics_evidence_list", case_id=case.id, write_files=False)
        assert response["ok"], response
        item, = [row for row in response["derived"] if row["path"] == rel]
        assert item["kind"] == event and item["custody"] == "recorded"
        assert item["evidence_id"] == ev and item["manifest_sha256"] == result["analysis"]["sha256"]

        saved.chmod(0o644)
        saved.write_bytes(saved.read_bytes() + b" ")
        saved.chmod(0o444)
        response = await call(client, "forensics_evidence_list", case_id=case.id, write_files=False)
        assert next(row for row in response["derived"] if row["path"] == rel)["custody"] == "mismatch"

        saved.unlink()
        response = await call(client, "forensics_evidence_list", case_id=case.id, write_files=False)
        assert next(row for row in response["derived"] if row["path"] == rel)["custody"] == "missing"

        planted = saved.with_name(f"{event}-EV-0001-999.json")
        planted.write_text(json.dumps(report), encoding="utf-8")
        response = await call(client, "forensics_evidence_list", case_id=case.id, write_files=False)
        assert next(row for row in response["derived"] if row["path"] == planted.relative_to(case.dir).as_posix())["custody"] == "unrecorded"


@pytest.mark.parametrize("mutation", ["source", "symlink", "hardlink"])
@pytest.mark.parametrize("event", ["secrets-scan", "secrets-survey", "sd-ioc-scan", "media-inventory", "dhav-candidates", "dhav-scan", "media-unit-candidates"])
def test_analysis_derived_output_rejects_false_source_or_links(workspace, auth, tmp_path, mutation, event):
    from forensics_mcp import server as S

    case = CaseStore(workspace["cases_dir"]).create(title="합성 분석 출처", authorization=auth, case_id="analysis-source")
    log = S.custody(case)
    ev = _commit_intake(case, log, b"synthetic evidence\n")
    with E.open_checked(case, ev, log.entries()) as opened:
        report = {"status": "ok", "source": {"kind": "evidence", "evidence_id": ev,
                  "evidence_sha256": opened.intake["hashes"]["sha256"]}, "params": {}}
        result = E.store_analysis(case, opened, report, event=event, custody_log=log)
    entries = log.entries()
    path = case.dir / result["analysis"]["path"]
    if mutation == "source":
        # 해시는 맞더라도 custody 쪽의 다른 출처와 같다고 주장하면 인정하지 않는다.
        entries[-1]["data"]["source"] = {**report["source"], "evidence_sha256": "0" * 64}
    elif mutation == "symlink":
        original = tmp_path / "original.json"
        path.rename(original)
        path.symlink_to(original)
    else:
        os.link(path, tmp_path / "alias.json")
    item, = S._image_hint_outputs(case, entries)
    assert item["kind"] == event and item["custody"] == "mismatch"
