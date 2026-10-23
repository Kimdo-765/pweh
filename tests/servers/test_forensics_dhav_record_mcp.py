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
from types import SimpleNamespace

import pytest
from mcp import Client

from fs.builders import exfat_small, fat32_small
from mcp_helpers import call

pytestmark = pytest.mark.anyio
PRIVATE = "PRIVATE_PREFIX_BODY_57a2"


def record(kind=0xfc, payload=b"synthetic", extension=b""):
    """고정 framing만 가진 합성 record이며 실제 녹화 내용은 아니다."""
    size = 24 + len(extension) + len(payload) + 8
    header = bytearray(24)
    header[:4] = b"DHAV"
    header[4] = kind
    header[5:12] = b"PRIVATE"
    struct.pack_into("<I", header, 12, size)
    header[16:22] = b"SECRET"
    header[22] = len(extension)
    return bytes(header) + extension + payload + b"dhav" + struct.pack("<I", size)


FIRST = record(0xf0, PRIVATE.encode())
SECOND = record(0xfc, b"x")
THIRD = record(0xfd, PRIVATE.encode(), b"x" * 255)
DATA = PRIVATE.encode() + FIRST + SECOND + THIRD


@pytest.fixture
def anyio_backend():
    return "asyncio"


@pytest.fixture
def pcase(workspace, auth):
    from pweh.case import CaseStore
    return CaseStore(workspace["cases_dir"]).create(
        title="합성 후보 record 추출", authorization=auth, case_id="recordcase")


async def finished(client, started):
    assert started.get("job_id"), started
    for _ in range(50):
        job = await call(client, "forensics_job_status", job_id=started["job_id"], wait_seconds=1)
        if job["status"] in ("succeeded", "failed", "cancelled"):
            return job
    raise AssertionError("합성 작업 대기 시간 초과")


async def prepare(client, case, tmp_path, *, kind="file", data=DATA, deleted=False, parent_deleted=False, fragmented=False):
    selected = None
    if kind == "file":
        blob = data
    elif kind in ("fat", "exfat"):
        disk = fat32_small() if kind == "fat" else exfat_small()
        parent = "/private" if parent_deleted else ""
        if parent:
            disk.mkdir(parent)
        selected = parent + "/" + PRIVATE + ".mp4"
        options = {}
        if fragmented:
            count = (len(data) + disk.cs - 1) // disk.cs
            options["clusters"] = list(range(20, 20 + count * 3, 3))
            if kind == "exfat":
                options["contiguous"] = False
        disk.add_file(selected, data, **options)
        if parent_deleted:
            disk.delete(parent)
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
    if deleted or parent_deleted:
        listing = await call(client, "forensics_fs_list", case_id=case.id, evidence_id=ev)
        report = json.loads((case.dir / listing["result_path"]).read_bytes())
        entry = next(e for v in report["volumes"] for e in v["walk"]["entries"] if not e["is_dir"])
        args = {"ref": entry["ref"]}
    result = await call(client, "forensics_dhav_candidates", case_id=case.id, evidence_id=ev, **args)
    assert result.get("ok"), result
    return ev, result


async def start(client, case, ev, report, index=0):
    return await call(client, "forensics_extract_dhav_candidate", case_id=case.id, evidence_id=ev,
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
@pytest.mark.parametrize("index,expected", [(0, FIRST), (1, SECOND), (2, THIRD)])
async def test_actual_mcp_exact_record_schema_and_metadata_only(pcase, tmp_path, kind, index, expected, caplog):
    from forensics_mcp import server as S
    from pweh import schemas
    async with Client(S.server) as client:
        ev, report = await prepare(client, pcase, tmp_path, kind=kind)
        job = await finished(client, await start(client, pcase, ev, report, index))
        assert job["status"] == "succeeded", job
        result = job["result"]
        manifest_path = pcase.dir / result["manifest"]
        manifest = json.loads(manifest_path.read_bytes())
        schemas.validate("dhav-record-extract", manifest)
        record_path = manifest_path.parent / "record-000.bin"
        assert record_path.read_bytes() == expected
        assert stat.S_IMODE(record_path.stat().st_mode) == 0o444
        assert stat.S_IMODE(manifest_path.stat().st_mode) == 0o444
        assert stat.S_IMODE(manifest_path.parent.stat().st_mode) == 0o555
        assert manifest["source"] == report["report"]["source"]
        assert manifest["source_coverage"] == report["report"]["coverage"]
        assert manifest["candidate"] == report["report"]["candidates"][index]
        assert manifest["analysis"] == report["analysis"]
        assert manifest["source_status"] == "ok" and manifest["status"] == "ok"
        assert manifest["effective_selection_uncertain"] is False
        assert manifest["effective_container_listing_incomplete"] is False
        assert manifest["files"] == [{"file": "record-000.bin", "size": len(expected),
                                      "sha256": hashlib.sha256(expected).hexdigest(), "complete": True}]
        assert result["bytes_total"] == len(expected)
        assert result["manifest_sha256"] == hashlib.sha256(manifest_path.read_bytes()).hexdigest()
        assert extracts(pcase)[-1]["data"]["method"] == "dhav_record"
        for key in ("media_decoded", "playback_verified", "recording_time_verified", "encryption_assessed",
                    "payload_semantics_examined", "extension_fields_examined", "checksum_verified", "original_file_boundary_verified", "complete_recording"):
            assert manifest[key] is False
        assert len(manifest_path.read_bytes()) <= 64 << 10
        public = json.dumps(result) + json.dumps(manifest) + json.dumps(extracts(pcase)) + caplog.text
        assert PRIVATE not in public and "PRIVATE" not in public and "SECRET" not in public and str(tmp_path) not in public
        tool = next(t for t in (await client.list_tools()).tools if t.name == "forensics_extract_dhav_candidate")
        assert set(tool.input_schema["properties"]) == {"case_id", "evidence_id", "analysis_path", "candidate_index"}
        assert tool.annotations.read_only_hint is False


@pytest.mark.parametrize("kind", ["fat", "exfat"])
async def test_deleted_source_partial_still_commits_whole_requested_record(pcase, tmp_path, kind):
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
    assert (pcase.dir / result["output_dir"] / "record-000.bin").read_bytes() == FIRST


async def test_upstream_search_partial_preserves_saved_record(pcase, tmp_path, monkeypatch):
    from forensics_mcp import dhav_tools as T, server as S
    from pweh import dhav
    from dataclasses import replace
    real = dhav.scan_dhav_candidates
    # 첫 후보만 저장하도록 상한을 낮춰 실제 partial 보고서를 만든다.
    def limited(data, *, limits, **kwargs):
        return real(data, limits=replace(limits, max_candidates=1), **kwargs)
    monkeypatch.setattr(dhav, "scan_dhav_candidates", limited)
    async with Client(S.server) as client:
        ev, report = await prepare(client, pcase, tmp_path)
        assert report["report"]["status"] == "partial"
        job = await finished(client, await start(client, pcase, ev, report))
    assert job["status"] == "succeeded", job
    manifest = json.loads((pcase.dir / job["result"]["manifest"]).read_bytes())
    assert manifest["status"] == "partial" and manifest["source_status"] == "partial"
    assert manifest["source_coverage"] == report["report"]["coverage"]
    assert (pcase.dir / job["result"]["output_dir"] / "record-000.bin").read_bytes() == FIRST


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
        result = await call(client, "forensics_extract_dhav_candidate", case_id=pcase.id, evidence_id="EV-0001",
                            analysis_path="forensics/analysis/dhav-candidates-EV-0001-001.json", candidate_index=value)
    assert result.get("_error"), result
    assert PRIVATE not in json.dumps(result) + caplog.text
    assert extracts(pcase) == []


@pytest.mark.parametrize("path", ["../" + PRIVATE, "/" + PRIVATE,
                                  "forensics/analysis/dhav-candidates-EV-0002-001.json",
                                  "forensics/analysis/media-inventory-EV-0001-001.json"])
async def test_generated_same_ev_path_only(pcase, path):
    from forensics_mcp import server as S
    async with Client(S.server) as client:
        result = await call(client, "forensics_extract_dhav_candidate", case_id=pcase.id, evidence_id="EV-0001",
                            analysis_path=path, candidate_index=0)
    assert result.get("_error"), result
    assert PRIVATE not in json.dumps(result)


@pytest.mark.parametrize("data,index", [(b"no candidate", 0), (DATA, 3)])
async def test_missing_saved_candidate_fails_job_without_output(pcase, tmp_path, data, index):
    from forensics_mcp import server as S
    async with Client(S.server) as client:
        ev, report = await prepare(client, pcase, tmp_path, data=data)
        job = await finished(client, await start(client, pcase, ev, report, index))
    assert job["status"] == "failed", job
    assert extracts(pcase) == []
    assert not list((pcase.dir / "forensics/recovered").glob("dhav-record-*"))


@pytest.mark.parametrize("point", ["report", "selection", "write"])
async def test_unexpected_worker_failure_is_fixed_and_has_no_traceback(pcase, tmp_path, monkeypatch, point, caplog):
    from pweh import dhav_candidate_input as inputs
    from forensics_mcp import media_candidate_selection as selection, dhav_record_output as output, server as S
    async with Client(S.server) as client:
        ev, report = await prepare(client, pcase, tmp_path)
        def failure(*args, **kwargs):
            raise RuntimeError(PRIVATE)
        module, name = {"report": (inputs, "open_dhav_candidate"),
                        "selection": (selection, "reselect_candidate_source"),
                        "write": (output, "store_dhav_record")}[point]
        monkeypatch.setattr(module, name, failure)
        job = await finished(client, await start(client, pcase, ev, report))
    assert job["status"] == "failed", job
    assert job["error"]["code"] == "dhav_record_failed"
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
    from forensics_mcp import dhav_record_tools as T, server as S
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
    assert (pcase.dir / job["result"]["output_dir"] / "record-000.bin").read_bytes() == FIRST
    assert PRIVATE not in json.dumps(job)


@pytest.mark.parametrize("replacement", [False, True])
async def test_final_custody_check_rejects_report_change_after_selection(pcase, tmp_path, monkeypatch, replacement):
    from forensics_mcp import dhav_record_output as output, server as S
    real = output.store_dhav_record
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
        monkeypatch.setattr(output, "store_dhav_record", changed)
        job = await finished(client, await start(client, pcase, ev, report))
    assert job["status"] == "failed", job
    assert extracts(pcase) == []
    assert not list((pcase.dir / "forensics/recovered").glob("dhav-record-*"))
    assert not [e for e in S.custody(pcase).entries() if e["event"] == "integrity-failed"]


async def test_worker_deadline_failure_does_not_publish_record(pcase, tmp_path, monkeypatch):
    from forensics_mcp import dhav_record_tools as T, server as S
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
    assert schemas.errors("dhav-record-extract", bad)


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
    assert schemas.errors("dhav-record-extract", manifest)


@pytest.mark.parametrize("kind", ["fat", "exfat"])
async def test_noncontiguous_file_keeps_logical_offset(pcase, tmp_path, kind):
    from forensics_mcp import server as S
    expected = record(payload=b"z" * 1900)
    data = b"before" + expected + b"after"
    async with Client(S.server) as client:
        ev, report = await prepare(client, pcase, tmp_path, kind=kind, data=data, fragmented=True)
        job = await finished(client, await start(client, pcase, ev, report))
    assert job["status"] == "succeeded", job
    assert report["report"]["source"]["method"] == "chain"
    assert (pcase.dir / job["result"]["output_dir"] / "record-000.bin").read_bytes() == expected


@pytest.mark.parametrize("kind", ["fat", "exfat"])
async def test_deleted_parent_remains_uncertain(pcase, tmp_path, kind):
    from forensics_mcp import server as S
    async with Client(S.server) as client:
        ev, report = await prepare(client, pcase, tmp_path, kind=kind, parent_deleted=True)
        job = await finished(client, await start(client, pcase, ev, report))
    assert job["status"] == "succeeded", job
    manifest = json.loads((pcase.dir / job["result"]["manifest"]).read_bytes())
    assert manifest["source"]["parent_deleted"] is True
    assert manifest["status"] == "partial" and manifest["effective_selection_uncertain"] is True


@pytest.mark.parametrize("index", [0, 1])
async def test_overlapping_saved_records_are_selected_independently(pcase, tmp_path, index):
    from forensics_mcp import server as S
    inner = record(payload=b"nested")
    outer = record(payload=b"xx" + inner + b"yy")
    async with Client(S.server) as client:
        ev, report = await prepare(client, pcase, tmp_path, data=outer)
        assert len(report["report"]["candidates"]) == 2
        job = await finished(client, await start(client, pcase, ev, report, index))
    assert job["status"] == "succeeded", job
    assert (pcase.dir / job["result"]["output_dir"] / "record-000.bin").read_bytes() == (outer, inner)[index]
    assert len(extracts(pcase)) == 1


async def test_large_ev_range_reselect_is_bounded_relative_and_never_rescans(pcase, tmp_path, monkeypatch):
    from forensics_mcp import media_candidate_selection as selection, server as S
    from pweh import dhav
    size, offset = (64 << 20) + 8192, (32 << 20) + 123
    selected = b"local-padding" + record(payload=b"X" * 70000) + b"tail"
    expected = selected[13:-4]
    path = tmp_path / "synthetic-large-range.bin"
    with path.open("wb") as stream:
        stream.truncate(size)
        stream.seek(offset)
        stream.write(selected)
    async with Client(S.server) as client:
        intake = await call(client, "forensics_intake_start", case_id=pcase.id, image_path=str(path),
                            purpose="합성 구간 추출", legal_basis="소유한 합성 자료", site_type="home",
                            business_purpose="없음(합성)", role="owner")
        job = await finished(client, intake)
        assert job["status"] == "succeeded", job
        ev = job["result"]["evidence_id"]
        report = await call(client, "forensics_dhav_candidates", case_id=pcase.id, evidence_id=ev,
                            offset=offset, length=len(selected))
        assert report.get("ok"), report
        active = threading.local()
        reads, checks = [], []
        original_read, original_pread = selection.read_candidate_range, selection.os.pread
        original_check = selection.check_candidate_range
        def read(*args, **kwargs):
            active.reading = True
            try:
                return original_read(*args, **kwargs)
            finally:
                active.reading = False
        def pread(fd, count, at):
            if getattr(active, "reading", False):
                assert 0 < count <= 64 << 10
                assert offset <= at and at + count <= offset + len(selected)
                reads.append(count)
            return original_pread(fd, count, at)
        def check(*args, **kwargs):
            checks.append(kwargs.get("time_limit", True))
            return original_check(*args, **kwargs)
        def no_scanner(*args, **kwargs):
            pytest.fail("저장된 record 추출에서 scanner를 재실행했습니다.")
        monkeypatch.setattr(selection, "read_candidate_range", read)
        monkeypatch.setattr(selection.os, "pread", pread)
        monkeypatch.setattr(selection, "check_candidate_range", check)
        monkeypatch.setattr(dhav, "scan_dhav_candidates", no_scanner)
        job = await finished(client, await start(client, pcase, ev, report))
    assert job["status"] == "succeeded", job
    result = job["result"]
    manifest = json.loads((pcase.dir / result["manifest"]).read_bytes())
    assert (pcase.dir / result["output_dir"] / "record-000.bin").read_bytes() == expected
    assert len(manifest["source"]) == 18 and manifest["source"]["offset"] == offset
    assert manifest["source"]["evidence_size"] == size
    assert manifest["candidate"]["offset"] == 13
    assert manifest["source"]["selected_sha256"] == hashlib.sha256(selected).hexdigest()
    assert manifest["files"][0]["sha256"] == hashlib.sha256(expected).hexdigest()
    assert sum(reads) == len(selected) and checks and all(checks)


@pytest.mark.parametrize("field", ["case_id", "evidence_id", "analysis_path", "candidate_index"])
async def test_actual_sdk_private_inputs_are_hidden_before_case_access(field, monkeypatch, caplog):
    from forensics_mcp import server as S
    from pydantic import ValidationError
    async def forbidden(*args, **kwargs):
        pytest.fail("SDK 거부 전에 케이스에 접근했습니다.")
    monkeypatch.setattr(S, "_case", forbidden)
    args = {"case_id": "unused", "evidence_id": "EV-0001",
            "analysis_path": "forensics/analysis/dhav-candidates-EV-0001-001.json", "candidate_index": 0}
    args[field] = [PRIVATE] if field != "candidate_index" else PRIVATE
    model = S.server._tool_manager.get_tool("forensics_extract_dhav_candidate").fn_metadata.arg_model
    with pytest.raises(ValidationError) as error:
        model.model_validate(args)
    assert PRIVATE not in str(error.value)
    async with Client(S.server) as client:
        result = await client.call_tool("forensics_extract_dhav_candidate", args)
    assert result.is_error and PRIVATE not in result.model_dump_json() + caplog.text


@pytest.mark.parametrize("failure", ["missing", "rebuild"])
async def test_private_sdk_configuration_failure_blocks_registration(failure):
    from forensics_mcp.dhav_record_tools import register_dhav_record_tools
    def rebuild(**kwargs):
        raise RuntimeError(PRIVATE)
    model = SimpleNamespace(model_config={}, model_rebuild=rebuild)
    tool = None if failure == "missing" else SimpleNamespace(fn_metadata=SimpleNamespace(arg_model=model))
    server = SimpleNamespace(tool=lambda **kwargs: lambda fn: fn,
                             _tool_manager=SimpleNamespace(get_tool=lambda name: tool))
    with pytest.raises(RuntimeError) as error:
        register_dhav_record_tools(server, {})
    assert PRIVATE not in str(error.value)


@pytest.mark.parametrize("code,expected", [
    ("media_prefix_input_invalid", "dhav_record_input_invalid"),
    ("media_prefix_input_limit", "dhav_record_input_limit"),
    ("media_prefix_input_changed", "dhav_record_input_changed"),
    ("media_prefix_input_" + PRIVATE, "dhav_record_failed"),
    ("timeout", "time_limit"), ("cancelled", "cancelled"),
])
async def test_selection_error_aliases_are_exact_and_private(pcase, tmp_path, monkeypatch, code, expected, caplog):
    from forensics_mcp import media_candidate_selection as selection, server as S
    from pweh.errors import PwehError
    async with Client(S.server) as client:
        ev, report = await prepare(client, pcase, tmp_path)
        def failed(*args, **kwargs):
            raise PwehError(PRIVATE, code=code, data={PRIVATE: PRIVATE})
        monkeypatch.setattr(selection, "reselect_candidate_source", failed)
        job = await finished(client, await start(client, pcase, ev, report))
    if expected == "cancelled":
        assert job["status"] == "cancelled", job
    else:
        assert job["status"] == "failed" and job["error"]["code"] == expected, job
    assert PRIVATE not in json.dumps(job) + caplog.text
    assert extracts(pcase) == []


async def test_raw_awaiter_cancel_leaves_registered_worker_fd_and_exclusive_key(pcase, tmp_path, monkeypatch):
    from forensics_mcp import dhav_record_tools as T, media_candidate_selection as selection, server as S
    reached, release = threading.Event(), threading.Event()
    held, registered = {}, {}
    real_select, real_job = selection.reselect_candidate_source, S._run_job
    def blocked(opened, candidate_input, **kwargs):
        held["fd"] = opened.fd
        reached.set()
        assert release.wait(5)
        return real_select(opened, candidate_input, **kwargs)
    async def delayed_response(*args, **kwargs):
        registered.update(await real_job(*args, **kwargs))
        await asyncio.Event().wait()
    monkeypatch.setattr(selection, "reselect_candidate_source", blocked)
    async with Client(S.server) as client:
        ev, report = await prepare(client, pcase, tmp_path)
        monkeypatch.setattr(S, "_run_job", delayed_response)
        task = asyncio.create_task(T._extract_run(T._ServerAPI(vars(S)), case_id=pcase.id,
            evidence_id=ev, analysis_path=report["analysis"]["path"], candidate_index=0))
        try:
            await wait_event(reached)
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await task
            os.fstat(held["fd"])
            monkeypatch.setattr(S, "_run_job", real_job)
            second = await start(client, pcase, ev, report)
            assert "job_busy" in second.get("_error", ""), second
            assert not S.rt().jobs.get(registered["job_id"])._cancel.is_set()
        finally:
            release.set()
        job = await finished(client, registered)
    assert job["status"] == "succeeded", job
    with pytest.raises(OSError):
        os.fstat(held["fd"])
    assert len(extracts(pcase)) == 1


@pytest.mark.parametrize("mode,expected", [("recorded", "recorded"), ("tamper", "mismatch"),
                                           ("missing", "missing"), ("unrecorded", "unrecorded")])
async def test_record_manifest_uses_existing_derived_custody(pcase, tmp_path, mode, expected):
    from forensics_mcp import server as S
    async with Client(S.server) as client:
        ev, report = await prepare(client, pcase, tmp_path)
        job = await finished(client, await start(client, pcase, ev, report))
        assert job["status"] == "succeeded", job
        result = job["result"]
        path = pcase.dir / result["manifest"]
        target = result["output_dir"]
        if mode == "tamper":
            path.chmod(0o644)
            path.write_bytes(path.read_bytes() + b" ")
            path.chmod(0o444)
        elif mode == "missing":
            path.parent.chmod(0o755)
            path.unlink()
            (path.parent / "record-000.bin").unlink()
            path.parent.rmdir()
        elif mode == "unrecorded":
            other = path.parent.parent / "dhav-record-999"
            other.mkdir()
            (other / "manifest.json").write_bytes(path.read_bytes())
            (other / "manifest.json").chmod(0o444)
            other.chmod(0o555)
            target = other.relative_to(pcase.dir).as_posix()
        listed = await call(client, "forensics_evidence_list", case_id=pcase.id, write_files=False)
    item = next(item for item in listed["derived"] if item["path"] == target)
    assert item["custody"] == expected, item
    assert PRIVATE not in json.dumps(listed["derived"])


@pytest.mark.parametrize("direction", ["bmff_to_dhav", "dhav_to_bmff"])
async def test_dhav_and_bmff_stored_reports_are_not_interchangeable(pcase, tmp_path, direction):
    from forensics_mcp import server as S
    bmff = struct.pack(">I4s", 16, b"ftyp") + b"isom\0\0\0\0"
    async with Client(S.server) as client:
        ev, dhav_report = await prepare(client, pcase, tmp_path, data=bmff + DATA)
        bmff_report = await call(client, "forensics_media_candidates", case_id=pcase.id, evidence_id=ev)
        assert bmff_report.get("ok"), bmff_report
        if direction == "bmff_to_dhav":
            result = await start(client, pcase, ev, bmff_report)
        else:
            result = await call(client, "forensics_extract_media_candidate", case_id=pcase.id,
                                evidence_id=ev, analysis_path=dhav_report["analysis"]["path"], candidate_index=0)
    assert result.get("_error"), result
    assert extracts(pcase) == []


@pytest.mark.parametrize("field,value", [("selected_sha256", "0" * 64), ("offset", 1),
                                       ("evidence_size", True), ("selected_size", 1.0)])
async def test_range_source_fresh_mismatch_cannot_be_committed(pcase, tmp_path, monkeypatch, field, value):
    from forensics_mcp import media_candidate_selection as selection, server as S
    real = selection.reselect_candidate_source
    def altered(*args, **kwargs):
        data, fresh = real(*args, **kwargs)
        fresh[field] = value
        return data, fresh
    async with Client(S.server) as client:
        ev, _ = await prepare(client, pcase, tmp_path)
        report = await call(client, "forensics_dhav_candidates", case_id=pcase.id, evidence_id=ev,
                            offset=0, length=len(DATA))
        assert report.get("ok"), report
        monkeypatch.setattr(selection, "reselect_candidate_source", altered)
        job = await finished(client, await start(client, pcase, ev, report))
    assert job["status"] == "failed", job
    assert extracts(pcase) == []


async def test_range_final_fd_seal_rejects_ev_modification(pcase, tmp_path, monkeypatch):
    from forensics_mcp import dhav_record_output as output, server as S
    real = output.store_dhav_record
    async with Client(S.server) as client:
        ev, _ = await prepare(client, pcase, tmp_path)
        report = await call(client, "forensics_dhav_candidates", case_id=pcase.id, evidence_id=ev,
                            offset=0, length=len(DATA))
        assert report.get("ok"), report
        with S._open_evidence_sync(pcase, ev) as opened:
            path = pcase.dir / opened.intake["stored_path"]
        def changed(*args, **kwargs):
            path.chmod(0o644)
            with path.open("r+b") as stream:
                stream.write(b"x")
            path.chmod(0o444)
            return real(*args, **kwargs)
        monkeypatch.setattr(output, "store_dhav_record", changed)
        job = await finished(client, await start(client, pcase, ev, report))
    assert job["status"] == "failed" and job["error"]["code"] == "integrity_failed", job
    assert extracts(pcase) == []
    assert any(entry["event"] == "integrity-failed" for entry in S.custody(pcase).entries())


async def test_cancel_at_final_entries_callback_does_not_publish(pcase, tmp_path, monkeypatch):
    from pweh import dhav_candidate_input as inputs
    from forensics_mcp import server as S
    reached, release = threading.Event(), threading.Event()
    real = inputs.DhavCandidateInput.check_entries
    calls = []
    def blocked(candidate_input, entries):
        calls.append(1)
        reached.set()
        assert release.wait(5)
        return real(candidate_input, entries)
    async with Client(S.server) as client:
        ev, report = await prepare(client, pcase, tmp_path)
        monkeypatch.setattr(inputs.DhavCandidateInput, "check_entries", blocked)
        started = await start(client, pcase, ev, report)
        try:
            await wait_event(reached)
            await call(client, "forensics_job_cancel", job_id=started["job_id"])
        finally:
            release.set()
        job = await finished(client, started)
    assert job["status"] == "cancelled", job
    assert calls and extracts(pcase) == []
    assert not list((pcase.dir / "forensics/recovered").glob("dhav-record-*"))


async def test_manifest_output_budget_fails_before_writer(pcase, tmp_path, monkeypatch):
    from forensics_mcp import dhav_record_tools as T, dhav_record_output as output, server as S
    async with Client(S.server) as client:
        ev, report = await prepare(client, pcase, tmp_path)
        monkeypatch.setattr(T, "MAX_MANIFEST_BYTES", 64)
        def forbidden(*args, **kwargs):
            pytest.fail("manifest 한도 거부 전에 writer를 호출했습니다.")
        monkeypatch.setattr(output, "store_dhav_record", forbidden)
        job = await finished(client, await start(client, pcase, ev, report))
    assert job["status"] == "failed" and job["error"]["code"] == "output_limit", job
    assert extracts(pcase) == []
