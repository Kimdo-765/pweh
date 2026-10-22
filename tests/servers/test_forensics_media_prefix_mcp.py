"""합성 증거의 저장 후보 하나를 job으로 추출하는 공개 계약 시험."""

from __future__ import annotations

import asyncio
import copy
import hashlib
import io
import json
import os
import stat
import struct
import tarfile
import threading
import zipfile

import pytest
from mcp import Client

from fs.builders import exfat_small, fat32_small
from mcp_helpers import call

pytestmark = pytest.mark.anyio
PRIVATE = "PRIVATE_PREFIX_BODY_57a2"


def box(kind, data=b""):
    return struct.pack(">I4s", 8 + len(data), kind) + data


FIRST = box(b"ftyp", b"isom\0\0\0\0") + box(b"mdat", PRIVATE.encode())
SECOND = box(b"ftyp", b"mp42\0\0\0\0") + box(b"moov", b"synthetic")
DATA = PRIVATE.encode() + FIRST + SECOND


@pytest.fixture
def anyio_backend():
    return "asyncio"


@pytest.fixture
def pcase(workspace, auth):
    from pweh.case import CaseStore
    return CaseStore(workspace["cases_dir"]).create(
        title="합성 후보 prefix 추출", authorization=auth, case_id="prefixcase")


async def finished(client, started):
    assert started.get("job_id"), started
    for _ in range(50):
        job = await call(client, "forensics_job_status", job_id=started["job_id"], wait_seconds=1)
        if job["status"] in ("succeeded", "failed", "cancelled"):
            return job
    raise AssertionError("합성 작업 대기 시간 초과")


async def prepare(client, case, tmp_path, *, kind="file", data=DATA, deleted=False):
    selected = None
    if kind == "file":
        blob = data
    elif kind in ("fat", "exfat"):
        disk = fat32_small() if kind == "fat" else exfat_small()
        selected = "/" + PRIVATE + ".mp4"
        disk.add_file(selected, data)
        if deleted:
            disk.delete(selected)
        blob = disk.image()
    else:
        stream = io.BytesIO()
        selected = "private/" + PRIVATE + ".mp4"
        if kind == "tar":
            with tarfile.open(fileobj=stream, mode="w") as archive:
                member = tarfile.TarInfo(selected)
                member.size = len(data)
                archive.addfile(member, io.BytesIO(data))
        else:
            with zipfile.ZipFile(stream, "w", compression=zipfile.ZIP_DEFLATED) as archive:
                archive.writestr(selected, data)
        blob = stream.getvalue()
    path = tmp_path / (PRIVATE + ".bin")
    path.write_bytes(blob)
    intake = await call(client, "forensics_intake_start", case_id=case.id, image_path=str(path),
                        purpose="합성 후보 추출", legal_basis="소유한 합성 자료", site_type="home",
                        business_purpose="없음(합성)", role="owner")
    job = await finished(client, intake)
    assert job["status"] == "succeeded", job
    ev = job["result"]["evidence_id"]
    args = {"path": selected} if selected else {}
    if deleted:
        listing = await call(client, "forensics_fs_list", case_id=case.id, evidence_id=ev)
        report = json.loads((case.dir / listing["result_path"]).read_bytes())
        entry = next(e for v in report["volumes"] for e in v["walk"]["entries"] if not e["is_dir"])
        args = {"ref": entry["ref"]}
    result = await call(client, "forensics_media_candidates", case_id=case.id, evidence_id=ev, **args)
    assert result.get("ok"), result
    return ev, result


async def start(client, case, ev, report, index=0):
    return await call(client, "forensics_extract_media_candidate", case_id=case.id, evidence_id=ev,
                      analysis_path=report["analysis"]["path"], candidate_index=index)


def extracts(case):
    from forensics_mcp import server as S
    return [e for e in S.custody(case).entries() if e["event"] == "extract"]


async def wait_event(event):
    for _ in range(500):
        if event.is_set():
            return
        await asyncio.sleep(.01)
    raise AssertionError("합성 worker 경계 대기 시간 초과")


@pytest.mark.parametrize("kind", ["file", "fat", "exfat", "tar", "zip"])
@pytest.mark.parametrize("index,expected", [(0, FIRST), (1, SECOND)])
async def test_actual_mcp_exact_prefix_schema_and_metadata_only(pcase, tmp_path, kind, index, expected, caplog):
    from forensics_mcp import server as S
    from pweh import schemas
    async with Client(S.server) as client:
        ev, report = await prepare(client, pcase, tmp_path, kind=kind)
        job = await finished(client, await start(client, pcase, ev, report, index))
        assert job["status"] == "succeeded", job
        result = job["result"]
        manifest_path = pcase.dir / result["manifest"]
        manifest = json.loads(manifest_path.read_bytes())
        schemas.validate("media-prefix-extract", manifest)
        prefix_path = manifest_path.parent / "candidate-000.bin"
        assert prefix_path.read_bytes() == expected
        assert stat.S_IMODE(prefix_path.stat().st_mode) == 0o444
        assert stat.S_IMODE(manifest_path.stat().st_mode) == 0o444
        assert stat.S_IMODE(manifest_path.parent.stat().st_mode) == 0o555
        assert manifest["source"] == report["report"]["source"]
        assert manifest["source_coverage"] == report["report"]["coverage"]
        assert manifest["candidate"] == report["report"]["candidates"][index]
        assert manifest["analysis"] == report["analysis"]
        assert manifest["source_status"] == "ok" and manifest["status"] == "ok"
        assert manifest["effective_selection_uncertain"] is False
        assert manifest["effective_container_listing_incomplete"] is False
        assert manifest["files"] == [{"file": "candidate-000.bin", "size": len(expected),
                                      "sha256": hashlib.sha256(expected).hexdigest(), "complete": True}]
        assert result["bytes_total"] == len(expected)
        assert result["manifest_sha256"] == hashlib.sha256(manifest_path.read_bytes()).hexdigest()
        assert extracts(pcase)[-1]["data"]["method"] == "media_candidate_prefix"
        for key in ("media_decoded", "playback_verified", "recording_time_verified", "encryption_assessed",
                    "format_conformance_assessed", "original_file_boundary_verified", "complete_recording"):
            assert manifest[key] is False
        assert len(manifest_path.read_bytes()) <= 64 << 10
        public = json.dumps(result) + json.dumps(manifest) + json.dumps(extracts(pcase)) + caplog.text
        assert PRIVATE not in public and str(tmp_path) not in public
        tool = next(t for t in (await client.list_tools()).tools if t.name == "forensics_extract_media_candidate")
        assert set(tool.input_schema["properties"]) == {"case_id", "evidence_id", "analysis_path", "candidate_index"}
        assert tool.annotations.read_only_hint is False


@pytest.mark.parametrize("kind", ["fat", "exfat"])
async def test_deleted_source_partial_still_commits_whole_requested_prefix(pcase, tmp_path, kind):
    from forensics_mcp import server as S
    async with Client(S.server) as client:
        ev, report = await prepare(client, pcase, tmp_path, kind=kind, deleted=True)
        job = await finished(client, await start(client, pcase, ev, report))
    assert job["status"] == "succeeded", job
    result = job["result"]
    manifest = json.loads((pcase.dir / result["manifest"]).read_bytes())
    assert result["status"] == manifest["status"] == manifest["source_status"] == "partial"
    assert manifest["effective_selection_uncertain"] is True
    assert manifest["files"][0]["complete"] is True
    assert (pcase.dir / result["output_dir"] / "candidate-000.bin").read_bytes() == FIRST


async def test_partial_framing_copies_only_saved_prefix(pcase, tmp_path):
    from forensics_mcp import server as S
    async with Client(S.server) as client:
        ev, report = await prepare(client, pcase, tmp_path, data=FIRST + b"bad")
        assert report["report"]["status"] == "partial"
        job = await finished(client, await start(client, pcase, ev, report))
    assert job["status"] == "succeeded", job
    manifest = json.loads((pcase.dir / job["result"]["manifest"]).read_bytes())
    assert manifest["status"] == "partial"
    assert manifest["candidate"]["end_reason"] == "truncated_header"
    assert (pcase.dir / job["result"]["output_dir"] / "candidate-000.bin").read_bytes() == FIRST


@pytest.mark.parametrize("field,value,expected", [
    ("confidence", "medium", "effective_selection_uncertain"),
    ("parent_deleted", None, "effective_selection_uncertain"),
    ("container_truncated", True, "effective_container_listing_incomplete"),
])
async def test_fresh_uncertainty_never_overwrites_original_coverage(pcase, tmp_path, monkeypatch, field, value, expected):
    from forensics_mcp import media_candidate_selection as selection, server as S
    real = selection.reselect_candidate_source
    def less_certain(*args, **kwargs):
        data, fresh = real(*args, **kwargs)
        fresh[field] = value
        return data, fresh
    monkeypatch.setattr(selection, "reselect_candidate_source", less_certain)
    async with Client(S.server) as client:
        ev, report = await prepare(client, pcase, tmp_path, kind="fat")
        job = await finished(client, await start(client, pcase, ev, report))
    assert job["status"] == "succeeded", job
    manifest = json.loads((pcase.dir / job["result"]["manifest"]).read_bytes())
    assert manifest[expected] is True and manifest["status"] == "partial"
    assert manifest["source_status"] == "ok"
    assert manifest["source_coverage"] == report["report"]["coverage"]
    assert manifest["source"] == report["report"]["source"]


@pytest.mark.parametrize("value", [True, False, -1, 128, 1.0, "0", None, PRIVATE])
async def test_index_ingress_is_exact_and_private(pcase, value, caplog):
    from forensics_mcp import server as S
    async with Client(S.server) as client:
        result = await call(client, "forensics_extract_media_candidate", case_id=pcase.id, evidence_id="EV-0001",
                            analysis_path="forensics/analysis/media-candidates-EV-0001-001.json", candidate_index=value)
    assert result.get("_error"), result
    assert PRIVATE not in json.dumps(result) + caplog.text
    assert extracts(pcase) == []


@pytest.mark.parametrize("path", ["../" + PRIVATE, "/" + PRIVATE,
                                  "forensics/analysis/media-candidates-EV-0002-001.json",
                                  "forensics/analysis/media-inventory-EV-0001-001.json"])
async def test_generated_same_ev_path_only(pcase, path):
    from forensics_mcp import server as S
    async with Client(S.server) as client:
        result = await call(client, "forensics_extract_media_candidate", case_id=pcase.id, evidence_id="EV-0001",
                            analysis_path=path, candidate_index=0)
    assert result.get("_error"), result
    assert PRIVATE not in json.dumps(result)


@pytest.mark.parametrize("data,index", [(b"no candidate", 0), (DATA, 2)])
async def test_missing_saved_candidate_fails_job_without_output(pcase, tmp_path, data, index):
    from forensics_mcp import server as S
    async with Client(S.server) as client:
        ev, report = await prepare(client, pcase, tmp_path, data=data)
        job = await finished(client, await start(client, pcase, ev, report, index))
    assert job["status"] == "failed", job
    assert extracts(pcase) == []
    assert not list((pcase.dir / "forensics/recovered").glob("media-prefix-*"))


@pytest.mark.parametrize("point", ["report", "selection", "write"])
async def test_unexpected_worker_failure_is_fixed_and_has_no_traceback(pcase, tmp_path, monkeypatch, point, caplog):
    from pweh import media_candidate_input as inputs
    from forensics_mcp import media_candidate_selection as selection, media_prefix_output as output, server as S
    async with Client(S.server) as client:
        ev, report = await prepare(client, pcase, tmp_path)
        def failure(*args, **kwargs):
            raise RuntimeError(PRIVATE)
        module, name = {"report": (inputs, "open_media_candidate"),
                        "selection": (selection, "reselect_candidate_source"),
                        "write": (output, "store_media_prefix")}[point]
        monkeypatch.setattr(module, name, failure)
        job = await finished(client, await start(client, pcase, ev, report))
    assert job["status"] == "failed", job
    assert job["error"]["code"] == "media_prefix_failed"
    assert "traceback" not in job["error"]
    assert PRIVATE not in json.dumps(job) + caplog.text
    assert extracts(pcase) == []


async def test_cancel_preserves_worker_fd_until_exit_and_exclusive_key(pcase, tmp_path, monkeypatch):
    from forensics_mcp import media_candidate_selection as selection, server as S
    reached, release = threading.Event(), threading.Event()
    held = {}
    real = selection.reselect_candidate_source
    def blocked(opened, candidate_input, **kwargs):
        held["fd"] = opened.fd
        held["input"] = candidate_input
        reached.set()
        assert release.wait(5)
        return real(opened, candidate_input, **kwargs)
    monkeypatch.setattr(selection, "reselect_candidate_source", blocked)
    async with Client(S.server) as client:
        ev, report = await prepare(client, pcase, tmp_path)
        started = await start(client, pcase, ev, report)
        try:
            await wait_event(reached)
            second = await start(client, pcase, ev, report)
            assert "job_busy" in second.get("_error", ""), second
            assert S.rt().jobs.get(started["job_id"]).meta["exclusive_key"] == f"extract:{pcase.id}:{ev}"
            await call(client, "forensics_job_cancel", job_id=started["job_id"])
            os.fstat(held["fd"])
        finally:
            release.set()
        job = await finished(client, started)
    assert job["status"] == "cancelled", job
    with pytest.raises(OSError):
        os.fstat(held["fd"])
    assert extracts(pcase) == []


async def test_late_cancel_and_audit_failure_preserve_committed_result(pcase, tmp_path, monkeypatch):
    from forensics_mcp import media_prefix_tools as T, server as S
    reached, release = threading.Event(), threading.Event()
    def audit_failure(*args):
        reached.set()
        assert release.wait(5)
        raise RuntimeError(PRIVATE)
    async with Client(S.server) as client:
        ev, report = await prepare(client, pcase, tmp_path)
        monkeypatch.setattr(T, "_audit", audit_failure)
        started = await start(client, pcase, ev, report)
        try:
            await wait_event(reached)
            await call(client, "forensics_job_cancel", job_id=started["job_id"])
            assert len(extracts(pcase)) == 1
        finally:
            release.set()
        job = await finished(client, started)
    assert job["status"] == "succeeded", job
    assert (pcase.dir / job["result"]["output_dir"] / "candidate-000.bin").read_bytes() == FIRST
    assert PRIVATE not in json.dumps(job)


@pytest.mark.parametrize("replacement", [False, True])
async def test_final_custody_check_rejects_report_change_after_selection(pcase, tmp_path, monkeypatch, replacement):
    from forensics_mcp import media_prefix_output as output, server as S
    real = output.store_media_prefix
    async with Client(S.server) as client:
        ev, report = await prepare(client, pcase, tmp_path)
        report_path = pcase.dir / report["analysis"]["path"]
        def changed(*args, **kwargs):
            raw = report_path.read_bytes()
            if replacement:
                report_path.unlink()
                report_path.write_bytes(raw)
                report_path.chmod(0o444)
            else:
                report_path.chmod(0o644)
                report_path.write_bytes(raw[:-1] + b" ")
                report_path.chmod(0o444)
            return real(*args, **kwargs)
        monkeypatch.setattr(output, "store_media_prefix", changed)
        job = await finished(client, await start(client, pcase, ev, report))
    assert job["status"] == "failed", job
    assert extracts(pcase) == []
    assert not list((pcase.dir / "forensics/recovered").glob("media-prefix-*"))
    assert not [e for e in S.custody(pcase).entries() if e["event"] == "integrity-failed"]


async def test_worker_deadline_failure_does_not_publish_prefix(pcase, tmp_path, monkeypatch):
    from forensics_mcp import media_prefix_tools as T, server as S
    async with Client(S.server) as client:
        ev, report = await prepare(client, pcase, tmp_path)
        monkeypatch.setattr(T, "MAX_SECONDS", 0)
        job = await finished(client, await start(client, pcase, ev, report))
    assert job["status"] == "failed" and job["error"]["code"] == "time_limit", job
    assert extracts(pcase) == []


@pytest.mark.parametrize("mutation", ["extra", "source_extra", "true_flag", "effective_ok", "file", "negative", "bool"])
async def test_closed_manifest_rejects_contract_mutations(pcase, tmp_path, mutation):
    from forensics_mcp import server as S
    from pweh import schemas
    async with Client(S.server) as client:
        ev, report = await prepare(client, pcase, tmp_path)
        job = await finished(client, await start(client, pcase, ev, report))
    assert job["status"] == "succeeded", job
    manifest = json.loads((pcase.dir / job["result"]["manifest"]).read_bytes())
    bad = copy.deepcopy(manifest)
    if mutation == "extra":
        bad[PRIVATE] = PRIVATE
    elif mutation == "source_extra":
        bad["source"]["path"] = PRIVATE
    elif mutation == "true_flag":
        bad["playback_verified"] = True
    elif mutation == "effective_ok":
        bad["effective_selection_uncertain"] = True
    elif mutation == "file":
        bad["files"][0]["file"] = "../" + PRIVATE
    elif mutation == "negative":
        bad["candidate"]["offset"] = -1
    else:
        bad["candidate"]["offset"] = True
    assert schemas.errors("media-prefix-extract", bad)


@pytest.mark.parametrize("signal", ["selection", "container"])
async def test_manifest_cannot_clear_recorded_uncertainty(pcase, tmp_path, signal):
    from forensics_mcp import server as S
    from pweh import schemas
    async with Client(S.server) as client:
        ev, report = await prepare(client, pcase, tmp_path)
        job = await finished(client, await start(client, pcase, ev, report))
    assert job["status"] == "succeeded", job
    manifest = json.loads((pcase.dir / job["result"]["manifest"]).read_bytes())
    manifest["status"] = "partial"
    if signal == "selection":
        manifest["source_coverage"]["selection_uncertain"] = True
    else:
        manifest["source_coverage"]["reasons"].append("container_listing_incomplete")
    assert schemas.errors("media-prefix-extract", manifest)
