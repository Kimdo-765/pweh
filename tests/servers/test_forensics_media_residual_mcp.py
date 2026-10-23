"""합성 exFAT residual 후보부터 기존 단일 추출·보관 기록까지 실제 MCP로 잇는다."""
from __future__ import annotations

import hashlib
import json
import stat
import threading
from types import SimpleNamespace

import pytest
from mcp import Client

from core.test_media_residual_extract_schema import KINDS
from mcp_helpers import call
from servers.test_forensics_media_candidates_mcp import box, intake
from servers.test_forensics_dhav_record_mcp import record
from servers.test_forensics_media_unit_extract_mcp import units, finished, wait_event
from servers.test_media_candidate_residual_selection import make_image, PRIVATE

pytestmark = pytest.mark.anyio
PREFIX = b"R" * 17
CANDIDATES = {"bmff": "forensics_media_candidates", "dhav": "forensics_dhav_candidates"}
EXTRACTORS = {"bmff": "forensics_extract_media_candidate", "dhav": "forensics_extract_dhav_candidate"}
PAYLOADS = {"bmff": "candidate-000.bin", "dhav": "record-000.bin"}
METHODS = {"bmff": "media_candidate_prefix", "dhav": "dhav_record"}


@pytest.fixture
def anyio_backend():
    return "asyncio"


@pytest.fixture
def mcase(workspace, auth):
    from pweh.case import CaseStore
    return CaseStore(workspace["cases_dir"]).create(title="합성 잔여 단위 추출", authorization=auth)


def unit(kind):
    if kind == "bmff":
        data = box(b"ftyp", b"isom\0\0\0\0") + box(b"mdat", b"SYNTHETIC")
        return data, data
    if kind == "dhav":
        data = record(payload=b"SYNTHETIC")
        return data, data
    return units()[kind]


def modules(kind):
    from forensics_mcp import media_prefix_output, media_prefix_tools, dhav_record_output, dhav_record_tools
    from forensics_mcp import media_unit_output, media_unit_extract_tools
    from pweh import media_candidate_input, dhav_candidate_input, media_unit_input
    return {"bmff": (media_prefix_output, "store_media_prefix", media_prefix_tools, media_candidate_input.CandidateInput),
            "dhav": (dhav_record_output, "store_dhav_record", dhav_record_tools, dhav_candidate_input.DhavCandidateInput)
            }.get(kind, (media_unit_output, "store_media_unit", media_unit_extract_tools,
                         media_unit_input.MediaUnitCandidateInput))


def extracts(case):
    from forensics_mcp import server as S
    return [row for row in S.custody(case).entries() if row["event"] == "extract"]


def no_output(case):
    assert extracts(case) == []
    assert list((case.dir / "forensics/recovered").glob("*")) == []


async def prepare(client, case, tmp_path, kind, *, mode="live", vdl=4075):
    data, expected = unit(kind)
    image = make_image(mode=mode, head=b"D" * vdl, tail=PREFIX + data)
    path = tmp_path / "synthetic-residual.img"
    path.write_bytes(image.blob)
    ev = await intake(client, case, path)
    listing = await call(client, "forensics_fs_list", case_id=case.id, evidence_id=ev)
    stored = json.loads((case.dir / listing["result_path"]).read_bytes())
    volume = next(v for v in stored["volumes"] if "walk" in v)
    entry = next(e for e in volume["walk"]["entries"] if not e["is_dir"])
    assert entry["ref"] == image.ref
    options = {} if kind in CANDIDATES else {"format": kind}
    report = await call(client, CANDIDATES.get(kind, "forensics_media_unit_candidates"),
                        case_id=case.id, evidence_id=ev, partition=volume["partition"]["index"],
                        ref=entry["ref"], region="residual", **options)
    assert report.get("ok"), report
    assert report["report"]["candidates"][0]["offset"] == len(PREFIX)
    return SimpleNamespace(ev=ev, report=report, image=image, expected=expected, kind=kind)


async def start(client, case, selected):
    return await call(client, EXTRACTORS.get(selected.kind, "forensics_extract_media_unit"),
                      case_id=case.id, evidence_id=selected.ev,
                      analysis_path=selected.report["analysis"]["path"], candidate_index=0)


@pytest.mark.parametrize("kind", KINDS)
@pytest.mark.parametrize("mode", ["live", "fragmented"])
async def test_six_formats_residual_selection_extract_and_custody(mcase, tmp_path, kind, mode, caplog):
    from forensics_mcp import server as S
    from pweh import schemas
    async with Client(S.server) as client:
        selected = await prepare(client, mcase, tmp_path, kind, mode=mode)
        job = await finished(client, await start(client, mcase, selected))
        assert job["status"] == "succeeded", job
        result = job["result"]
        manifest_path = mcase.dir / result["manifest"]
        value = json.loads(manifest_path.read_bytes())
        source = selected.report["report"]["source"]
        assert len(source) == 19 and value["source"] == source
        assert source["selected_sha256"] == hashlib.sha256(selected.image.tail).hexdigest()
        assert source["valid_data_length"] == len(selected.image.head)
        assert value["source_coverage"] == selected.report["report"]["coverage"]
        assert value["source_status"] == selected.report["report"]["status"]
        assert value["candidate"] == selected.report["report"]["candidates"][0]
        assert value["candidate"]["offset"] == len(PREFIX)
        assert source["method"] == ("chain" if mode == "fragmented" else "nofatchain")
        payload = mcase.dir / result["output_dir"] / PAYLOADS.get(kind, "unit-000.bin")
        assert payload.read_bytes() == selected.expected
        assert value["files"][0]["sha256"] == hashlib.sha256(selected.expected).hexdigest()
        assert stat.S_IMODE(payload.stat().st_mode) == stat.S_IMODE(manifest_path.stat().st_mode) == 0o444
        assert stat.S_IMODE(payload.parent.stat().st_mode) == 0o555
        schema = {"bmff": "media-prefix-extract", "dhav": "dhav-record-extract"}.get(kind, "media-unit-extract")
        schemas.validate(schema, value)
        event = extracts(mcase)[0]
        assert event["data"]["region"] == "residual"
        assert event["data"]["method"] == METHODS.get(kind, "media_unit")
        assert event["data"]["analysis"]["sha256"] == selected.report["analysis"]["sha256"]
        listed = await call(client, "forensics_evidence_list", case_id=mcase.id, write_files=False)
        derived = next(row for row in listed["derived"] if row["path"] == result["output_dir"])
        assert derived["custody"] == "recorded"
        tool = next(t for t in (await client.list_tools()).tools if t.name == EXTRACTORS.get(kind, "forensics_extract_media_unit"))
        assert set(tool.input_schema["properties"]) == {"case_id", "evidence_id", "analysis_path", "candidate_index"}
    assert PRIVATE not in json.dumps(job) + json.dumps(value) + json.dumps(event) + caplog.text
    if kind == "xm" and mode == "live":
        from case_mcp import server as C
        from core.test_sd_media_unit_summary import summary
        report = selected.report["report"]
        data = summary()
        data["media_unit_candidate_results"] = [{"evidence_id": selected.ev,
            "analysis_path": selected.report["analysis"]["path"], "sha256": selected.report["analysis"]["sha256"],
            "status": report["status"], "format": kind, "selected_size": source["selected_size"],
            "candidates_reported": report["summary"]["candidates_reported"]}]
        async with Client(C.server) as client:
            saved = await call(client, "case_record_step", case_id=mcase.id, skill="sd-card-forensics",
                               step="summary", status="success", summary="합성 잔여 단위 확인", data=data)
            assert saved.get("ok"), saved
            final = await call(client, "report_generate", case_id=mcase.id)
            assert final.get("ok"), final


@pytest.mark.parametrize("kind", ["bmff", "dhav", "xm"])
@pytest.mark.parametrize("mode", ["deleted", "parent"])
async def test_deleted_context_keeps_upstream_uncertainty(mcase, tmp_path, kind, mode):
    from forensics_mcp import server as S
    async with Client(S.server) as client:
        selected = await prepare(client, mcase, tmp_path, kind, mode=mode)
        job = await finished(client, await start(client, mcase, selected))
    assert job["status"] == "succeeded", job
    value = json.loads((mcase.dir / job["result"]["manifest"]).read_bytes())
    assert value["status"] == value["source_status"] == "partial"
    assert value["effective_selection_uncertain"] is True
    assert value["source"]["deleted" if mode == "deleted" else "parent_deleted"] is True
    assert value["source_coverage"] == selected.report["report"]["coverage"]


@pytest.mark.parametrize("kind", ["bmff", "dhav", "xm"])
async def test_zero_vdl_and_no_scanner_replay(mcase, tmp_path, monkeypatch, kind):
    from forensics_mcp import server as S
    from pweh import media_candidates, dhav, media_units
    async with Client(S.server) as client:
        selected = await prepare(client, mcase, tmp_path, kind, vdl=0)
        def forbidden(*args, **kwargs):
            pytest.fail("추출에서 이미 검증된 scanner를 다시 실행했습니다.")
        for module, name in ((media_candidates, "scan_bmff_candidates"), (dhav, "scan_dhav_candidates"),
                             (media_units, "scan_media_unit_candidates")):
            monkeypatch.setattr(module, name, forbidden)
        job = await finished(client, await start(client, mcase, selected))
    assert job["status"] == "succeeded", job
    assert (mcase.dir / job["result"]["output_dir"] / PAYLOADS.get(kind, "unit-000.bin")).read_bytes() == selected.expected


@pytest.mark.parametrize("kind", ["bmff", "dhav", "xm"])
@pytest.mark.parametrize("field,value", [("confidence", "medium"), ("valid_data_length", 0)])
async def test_fresh_residual_metadata_change_fails_whole_extract(mcase, tmp_path, monkeypatch, kind, field, value):
    from forensics_mcp import media_candidate_selection as selection, server as S
    original = selection.reselect_candidate_source
    def changed(*args, **kwargs):
        data, fresh = original(*args, **kwargs)
        fresh[field] = value
        return data, fresh
    async with Client(S.server) as client:
        selected = await prepare(client, mcase, tmp_path, kind)
        monkeypatch.setattr(selection, "reselect_candidate_source", changed)
        job = await finished(client, await start(client, mcase, selected))
    assert job["status"] == "failed", job
    no_output(mcase)


@pytest.mark.parametrize("kind", ["bmff", "dhav", "xm"])
@pytest.mark.parametrize("target", ["report", "evidence"])
async def test_final_same_fd_revalidation_refuses_changed_source(mcase, tmp_path, monkeypatch, kind, target):
    from forensics_mcp import server as S
    output, method, _, _ = modules(kind)
    original = getattr(output, method)
    async with Client(S.server) as client:
        selected = await prepare(client, mcase, tmp_path, kind)
        path = mcase.dir / selected.report["analysis"]["path"]
        if target == "evidence":
            with S._open_evidence_sync(mcase, selected.ev) as opened:
                path = mcase.dir / opened.intake["stored_path"]
        def changed(*args, **kwargs):
            path.chmod(0o644)
            with path.open("r+b") as stream:
                stream.write(b"X")
            path.chmod(0o444)
            return original(*args, **kwargs)
        monkeypatch.setattr(output, method, changed)
        job = await finished(client, await start(client, mcase, selected))
    assert job["status"] == "failed", job
    no_output(mcase)
    if target == "evidence":
        assert job["error"]["code"] == "integrity_failed"
        assert any(e["event"] == "integrity-failed" for e in S.custody(mcase).entries())


@pytest.mark.parametrize("kind", ["bmff", "dhav", "xm"])
async def test_cancel_before_custody_commit_cleans_residual_output(mcase, tmp_path, monkeypatch, kind):
    from forensics_mcp import server as S
    _, _, _, input_type = modules(kind)
    original = input_type.check_entries
    reached, release = threading.Event(), threading.Event()
    def blocked(self, entries):
        reached.set()
        assert release.wait(5)
        return original(self, entries)
    async with Client(S.server) as client:
        selected = await prepare(client, mcase, tmp_path, kind)
        monkeypatch.setattr(input_type, "check_entries", blocked)
        started = await start(client, mcase, selected)
        try:
            await wait_event(reached)
            await call(client, "forensics_job_cancel", job_id=started["job_id"])
        finally:
            release.set()
        job = await finished(client, started)
    assert job["status"] == "cancelled", job
    no_output(mcase)


@pytest.mark.parametrize("kind", ["bmff", "dhav", "xm"])
async def test_late_cancel_and_audit_failure_preserve_residual_receipt(mcase, tmp_path, monkeypatch, kind):
    from forensics_mcp import server as S
    _, _, tools, _ = modules(kind)
    reached, release = threading.Event(), threading.Event()
    def audit_failure(*args):
        reached.set()
        assert release.wait(5)
        raise RuntimeError(PRIVATE)
    async with Client(S.server) as client:
        selected = await prepare(client, mcase, tmp_path, kind)
        monkeypatch.setattr(tools, "_audit", audit_failure)
        started = await start(client, mcase, selected)
        try:
            await wait_event(reached)
            assert extracts(mcase)[0]["data"]["region"] == "residual"
            await call(client, "forensics_job_cancel", job_id=started["job_id"])
        finally:
            release.set()
        job = await finished(client, started)
    assert job["status"] == "succeeded", job
    assert (mcase.dir / job["result"]["output_dir"] / PAYLOADS.get(kind, "unit-000.bin")).read_bytes() == selected.expected
    assert PRIVATE not in json.dumps(job)
