"""저장된 미디어 단위의 같은 출처 재선택·단일 추출 공개 계약."""

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
import time
import zipfile
from types import SimpleNamespace

import pytest
from mcp import Client
from fs.builders import exfat_small, fat32_small
from mcp_helpers import call as _call

pytestmark = pytest.mark.anyio
PRIVATE = "PRIVATE_MEDIA_UNIT_a3fd7c"

async def call(client, name, **kwargs):
    if name == "forensics_media_unit_candidates":
        kwargs.setdefault("format", "xm")
    return await _call(client, name, **kwargs)


def record(kind=0xfd, payload=b"synthetic", extension=b""):
    """내용을 해독할 필요가 없는 합성 XM 길이 경계."""
    data = extension + payload
    return b"\0\0\1\xfd" + struct.pack("<I", len(data)) + data


def units():
    """네 형식의 최소 구조를 독립 바이트로 만든다."""
    jpeg = (b"\xff\xd8\xff\xc0\x00\x0b\x08\x00\x01\x00\x01\x01\x01\x11\x00"
            b"\xff\xda\x00\x08\x01\x01\x00\x00\x3f\x00X\xff\xd9")
    avc = b"\0\0\1\x0a\0\0\1\x0b"
    ps = bytes.fromhex("000001ba440004000401000007f8000001e0000480000058000001b9")
    return {"jpeg": (jpeg, jpeg), "avc-annexb": (avc, avc[:4]),
            "mpeg2-ps": (ps, ps[:-4]), "xm": (record(payload=b"X"), record(payload=b"X"))}

PREFIX = PRIVATE.encode() + b"\0"
FIRST = record(payload=PRIVATE.encode())
SECOND = record(payload=b"X")
THIRD = record(payload=PRIVATE.encode(), extension=b"X" * 255)
CONTENT = DATA = PREFIX + FIRST + SECOND + THIRD

@pytest.fixture
def anyio_backend():
    return "asyncio"


@pytest.fixture
def pcase(workspace, auth):
    from pweh.case import CaseStore
    return CaseStore(workspace["cases_dir"]).create(
        title="합성 후보 단위 추출", authorization=auth, case_id="unitcase")


async def finished(client, started):
    assert started.get("job_id"), started
    for _ in range(50):
        job = await call(client, "forensics_job_status", job_id=started["job_id"], wait_seconds=1)
        if job["status"] in ("succeeded", "failed", "cancelled"):
            return job
    raise AssertionError("합성 작업 대기 시간 초과")


async def prepare(client, case, tmp_path, *, kind="file", data=DATA, format="xm", deleted=False, parent_deleted=False, fragmented=False):
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
    result = await call(client, "forensics_media_unit_candidates", case_id=case.id, evidence_id=ev, format=format, **args)
    assert result.get("ok"), result
    return ev, result


async def start(client, case, ev, report, index=0):
    return await call(client, "forensics_extract_media_unit", case_id=case.id, evidence_id=ev,
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
    assert (pcase.dir / result["output_dir"] / "unit-000.bin").read_bytes() == FIRST


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
        result = await call(client, "forensics_extract_media_unit", case_id=pcase.id, evidence_id="EV-0001",
                            analysis_path="forensics/analysis/media-unit-candidates-EV-0001-001.json", candidate_index=value)
    assert result.get("_error"), result
    assert PRIVATE not in json.dumps(result) + caplog.text
    assert extracts(pcase) == []


@pytest.mark.parametrize("path", ["../" + PRIVATE, "/" + PRIVATE,
                                  "forensics/analysis/media-unit-candidates-EV-0002-001.json",
                                  "forensics/analysis/media-inventory-EV-0001-001.json"])
async def test_generated_same_ev_path_only(pcase, path):
    from forensics_mcp import server as S
    async with Client(S.server) as client:
        result = await call(client, "forensics_extract_media_unit", case_id=pcase.id, evidence_id="EV-0001",
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
    assert not list((pcase.dir / "forensics/recovered").glob("media-unit-*"))


@pytest.mark.parametrize("point", ["report", "selection", "write"])
async def test_unexpected_worker_failure_is_fixed_and_has_no_traceback(pcase, tmp_path, monkeypatch, point, caplog):
    from pweh import media_unit_input as inputs
    from forensics_mcp import media_candidate_selection as selection, media_unit_output as output, server as S
    async with Client(S.server) as client:
        ev, report = await prepare(client, pcase, tmp_path)
        def failure(*args, **kwargs):
            raise RuntimeError(PRIVATE)
        module, name = {"report": (inputs, "open_media_unit_candidate"),
                        "selection": (selection, "reselect_candidate_source"),
                        "write": (output, "store_media_unit")}[point]
        monkeypatch.setattr(module, name, failure)
        job = await finished(client, await start(client, pcase, ev, report))
    assert job["status"] == "failed", job
    assert job["error"]["code"] == "media_unit_failed"
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
    from forensics_mcp import media_unit_extract_tools as T, server as S
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
    assert (pcase.dir / job["result"]["output_dir"] / "unit-000.bin").read_bytes() == FIRST
    assert PRIVATE not in json.dumps(job)


@pytest.mark.parametrize("replacement", [False, True])
async def test_final_custody_check_rejects_report_change_after_selection(pcase, tmp_path, monkeypatch, replacement):
    from forensics_mcp import media_unit_output as output, server as S
    real = output.store_media_unit
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
        monkeypatch.setattr(output, "store_media_unit", changed)
        job = await finished(client, await start(client, pcase, ev, report))
    assert job["status"] == "failed", job
    assert extracts(pcase) == []
    assert not list((pcase.dir / "forensics/recovered").glob("media-unit-*"))
    assert not [e for e in S.custody(pcase).entries() if e["event"] == "integrity-failed"]


async def test_worker_deadline_failure_does_not_publish_record(pcase, tmp_path, monkeypatch):
    from forensics_mcp import media_unit_extract_tools as T, server as S
    async with Client(S.server) as client:
        ev, report = await prepare(client, pcase, tmp_path)
        monkeypatch.setattr(T, "MAX_SECONDS", 0)
        job = await finished(client, await start(client, pcase, ev, report))
    assert job["status"] == "failed" and job["error"]["code"] == "time_limit", job
    assert extracts(pcase) == []


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
    assert (pcase.dir / job["result"]["output_dir"] / "unit-000.bin").read_bytes() == expected


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


@pytest.mark.parametrize("field", ["case_id", "evidence_id", "analysis_path", "candidate_index"])
async def test_actual_sdk_private_inputs_are_hidden_before_case_access(field, monkeypatch, caplog):
    from forensics_mcp import server as S
    from pydantic import ValidationError
    async def forbidden(*args, **kwargs):
        pytest.fail("SDK 거부 전에 케이스에 접근했습니다.")
    monkeypatch.setattr(S, "_case", forbidden)
    args = {"case_id": "unused", "evidence_id": "EV-0001",
            "analysis_path": "forensics/analysis/media-unit-candidates-EV-0001-001.json", "candidate_index": 0}
    args[field] = [PRIVATE] if field != "candidate_index" else PRIVATE
    model = S.server._tool_manager.get_tool("forensics_extract_media_unit").fn_metadata.arg_model
    with pytest.raises(ValidationError) as error:
        model.model_validate(args)
    assert PRIVATE not in str(error.value)
    async with Client(S.server) as client:
        result = await client.call_tool("forensics_extract_media_unit", args)
    assert result.is_error and PRIVATE not in result.model_dump_json() + caplog.text


@pytest.mark.parametrize("failure", ["missing", "rebuild"])
async def test_private_sdk_configuration_failure_blocks_registration(failure):
    from forensics_mcp.media_unit_extract_tools import register_media_unit_extract_tools
    def rebuild(**kwargs):
        raise RuntimeError(PRIVATE)
    model = SimpleNamespace(model_config={}, model_rebuild=rebuild)
    tool = None if failure == "missing" else SimpleNamespace(fn_metadata=SimpleNamespace(arg_model=model))
    server = SimpleNamespace(tool=lambda **kwargs: lambda fn: fn,
                             _tool_manager=SimpleNamespace(get_tool=lambda name: tool))
    with pytest.raises(RuntimeError) as error:
        register_media_unit_extract_tools(server, {})
    assert PRIVATE not in str(error.value)


@pytest.mark.parametrize("code,expected", [
    ("media_prefix_input_invalid", "media_unit_input_invalid"),
    ("media_prefix_input_limit", "media_unit_input_limit"),
    ("media_prefix_input_changed", "media_unit_input_changed"),
    ("media_prefix_input_" + PRIVATE, "media_unit_failed"),
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
    from forensics_mcp import media_unit_extract_tools as T, media_candidate_selection as selection, server as S
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
            (path.parent / "unit-000.bin").unlink()
            path.parent.rmdir()
        elif mode == "unrecorded":
            other = path.parent.parent / "media-unit-999"
            other.mkdir()
            (other / "manifest.json").write_bytes(path.read_bytes())
            (other / "manifest.json").chmod(0o444)
            other.chmod(0o555)
            target = other.relative_to(pcase.dir).as_posix()
        listed = await call(client, "forensics_evidence_list", case_id=pcase.id, write_files=False)
    item = next(item for item in listed["derived"] if item["path"] == target)
    assert item["custody"] == expected, item
    assert PRIVATE not in json.dumps(listed["derived"])


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
        report = await call(client, "forensics_media_unit_candidates", case_id=pcase.id, evidence_id=ev,
                            offset=0, length=len(DATA))
        assert report.get("ok"), report
        monkeypatch.setattr(selection, "reselect_candidate_source", altered)
        job = await finished(client, await start(client, pcase, ev, report))
    assert job["status"] == "failed", job
    assert extracts(pcase) == []


async def test_range_final_fd_seal_rejects_ev_modification(pcase, tmp_path, monkeypatch):
    from forensics_mcp import media_unit_output as output, server as S
    real = output.store_media_unit
    async with Client(S.server) as client:
        ev, _ = await prepare(client, pcase, tmp_path)
        report = await call(client, "forensics_media_unit_candidates", case_id=pcase.id, evidence_id=ev,
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
        monkeypatch.setattr(output, "store_media_unit", changed)
        job = await finished(client, await start(client, pcase, ev, report))
    assert job["status"] == "failed" and job["error"]["code"] == "integrity_failed", job
    assert extracts(pcase) == []
    assert any(entry["event"] == "integrity-failed" for entry in S.custody(pcase).entries())


async def test_cancel_at_final_entries_callback_does_not_publish(pcase, tmp_path, monkeypatch):
    from pweh import media_unit_input as inputs
    from forensics_mcp import server as S
    reached, release = threading.Event(), threading.Event()
    real = inputs.MediaUnitCandidateInput.check_entries
    calls = []
    def blocked(candidate_input, entries):
        calls.append(1)
        reached.set()
        assert release.wait(5)
        return real(candidate_input, entries)
    async with Client(S.server) as client:
        ev, report = await prepare(client, pcase, tmp_path)
        monkeypatch.setattr(inputs.MediaUnitCandidateInput, "check_entries", blocked)
        started = await start(client, pcase, ev, report)
        try:
            await wait_event(reached)
            await call(client, "forensics_job_cancel", job_id=started["job_id"])
        finally:
            release.set()
        job = await finished(client, started)
    assert job["status"] == "cancelled", job
    assert calls and extracts(pcase) == []
    assert not list((pcase.dir / "forensics/recovered").glob("media-unit-*"))


async def test_manifest_output_budget_fails_before_writer(pcase, tmp_path, monkeypatch):
    from forensics_mcp import media_unit_extract_tools as T, media_unit_output as output, server as S
    async with Client(S.server) as client:
        ev, report = await prepare(client, pcase, tmp_path)
        monkeypatch.setattr(T, "MAX_MANIFEST_BYTES", 64)
        def forbidden(*args, **kwargs):
            pytest.fail("manifest 한도 거부 전에 writer를 호출했습니다.")
        monkeypatch.setattr(output, "store_media_unit", forbidden)
        job = await finished(client, await start(client, pcase, ev, report))
    assert job["status"] == "failed" and job["error"]["code"] == "output_limit", job
    assert extracts(pcase) == []



@pytest.mark.parametrize("format", ["jpeg", "avc-annexb", "mpeg2-ps", "xm"])
@pytest.mark.parametrize("kind", ["file", "fat", "exfat", "tar", "zip"])
async def test_actual_four_formats_extract_same_saved_unit(pcase, tmp_path, kind, format, caplog):
    from forensics_mcp import server as S
    from pweh import schemas
    from pweh.media_units import FALSE_FIELDS, FILE_PROFILES
    data, expected = units()[format]
    async with Client(S.server) as client:
        ev, report = await prepare(client, pcase, tmp_path, kind=kind, data=data, format=format)
        job = await finished(client, await start(client, pcase, ev, report))
    assert job["status"] == "succeeded", job
    result = job["result"]
    manifest_path = pcase.dir / result["manifest"]
    manifest = json.loads(manifest_path.read_bytes())
    schemas.validate("media-unit-extract", manifest)
    output = manifest_path.parent / "unit-000.bin"
    assert output.read_bytes() == expected
    assert manifest["format"] == format and manifest["source_profile"] == FILE_PROFILES[format]
    assert manifest["source"] == report["report"]["source"]
    assert manifest["source_coverage"] == report["report"]["coverage"]
    assert manifest["candidate"] == report["report"]["candidates"][0]
    assert manifest["analysis"] == report["analysis"]
    assert manifest["files"] == [{"file": "unit-000.bin", "size": len(expected),
        "sha256": hashlib.sha256(expected).hexdigest(), "complete": True}]
    assert manifest["bytes_total"] == len(expected)
    assert all(manifest[key] is False for key in FALSE_FIELDS)
    assert manifest["status"] == ("partial" if format == "avc-annexb" else "ok")
    assert stat.S_IMODE(output.stat().st_mode) == stat.S_IMODE(manifest_path.stat().st_mode) == 0o444
    assert stat.S_IMODE(manifest_path.parent.stat().st_mode) == 0o555
    assert PRIVATE not in json.dumps(job) + manifest_path.read_text() + json.dumps(extracts(pcase)) + caplog.text


@pytest.mark.parametrize("format", ["jpeg", "avc-annexb", "mpeg2-ps", "xm"])
async def test_range_replay_and_minimum_units_never_rescan(pcase, tmp_path, monkeypatch, format):
    from forensics_mcp import server as S
    from pweh import media_units
    data, expected = units()[format]
    async with Client(S.server) as client:
        ev, _ = await prepare(client, pcase, tmp_path, data=PREFIX + data + b"after", format=format)
        report = await call(client, "forensics_media_unit_candidates", case_id=pcase.id,
                            evidence_id=ev, format=format, offset=len(PREFIX), length=len(data))
        assert report.get("ok"), report
        def forbidden(*args, **kwargs):
            pytest.fail("저장된 후보를 추출하며 scanner를 다시 실행했습니다.")
        monkeypatch.setattr(media_units, "scan_media_unit_candidates", forbidden)
        job = await finished(client, await start(client, pcase, ev, report))
    assert job["status"] == "succeeded", job
    path = pcase.dir / job["result"]["manifest"]
    manifest = json.loads(path.read_bytes())
    assert (path.parent / "unit-000.bin").read_bytes() == expected
    assert manifest["source"]["offset"] == len(PREFIX)
    assert manifest["candidate"]["offset"] == 0
    assert manifest["source_profile"] == media_units.RANGE_PROFILES[format]


async def test_validated_ps_prefix_remains_partial_after_complete_byte_copy(pcase, tmp_path):
    from forensics_mcp import server as S
    data = units()["mpeg2-ps"][0][:-4]
    async with Client(S.server) as client:
        ev, report = await prepare(client, pcase, tmp_path, data=data, format="mpeg2-ps")
        job = await finished(client, await start(client, pcase, ev, report))
    assert job["status"] == "succeeded", job
    manifest = json.loads((pcase.dir / job["result"]["manifest"]).read_bytes())
    assert manifest["candidate"]["framing_status"] == "prefix"
    assert manifest["candidate"]["end_reason"] == "selection_end"
    assert manifest["status"] == manifest["source_status"] == "partial"
    assert manifest["files"][0]["complete"] is True
    assert manifest["complete_recording"] is False


@pytest.mark.parametrize("other", ["forensics_extract_media_candidate", "forensics_extract_dhav_candidate"])
async def test_new_report_cannot_enter_other_extractors(pcase, tmp_path, other):
    from forensics_mcp import server as S
    async with Client(S.server) as client:
        ev, report = await prepare(client, pcase, tmp_path)
        result = await call(client, other, case_id=pcase.id, evidence_id=ev,
                            analysis_path=report["analysis"]["path"], candidate_index=0)
    assert "_error" in result and extracts(pcase) == []
