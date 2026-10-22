"""선택 바이트의 후보 탐색·출처·고정 오류·취소·커밋 경계 MCP 시험."""

from __future__ import annotations

import asyncio
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
from mcp_helpers import call

pytestmark = pytest.mark.anyio
PRIVATE = "PWEH_PRIVATE_RECORD_7b9f_3c2a"


def record(kind=0xfc, payload=b"synthetic", extension=b""):
    """제조사 미디어가 아닌 고정 framing만 갖는 합성 record."""
    size = 24 + len(extension) + len(payload) + 8
    header = bytearray(24)
    header[:4] = b"DHAV"
    header[4] = kind
    header[5:12] = b"PRIVATE"
    struct.pack_into("<I", header, 12, size)
    header[16:22] = b"SECRET"
    header[22] = len(extension)
    return bytes(header) + extension + payload + b"dhav" + struct.pack("<I", size)


PREFIX = PRIVATE.encode() + b"\0"
FIRST = record(0xf0, PRIVATE.encode() + b"DHAV\xf1", PRIVATE.encode())
SECOND = record(0xfc)
THIRD = record(0xfd, PRIVATE.encode(), b"X" * 255)
CONTENT = PREFIX + FIRST + SECOND + THIRD


@pytest.fixture
def anyio_backend():
    return "asyncio"


@pytest.fixture
def mcase(workspace, auth):
    from pweh.case import CaseStore
    return CaseStore(workspace["cases_dir"]).create(
        title="합성 DHAV 후보 검사", authorization=auth, case_id="candidatecase")


async def intake(client, case, source):
    result = await call(client, "forensics_intake_start", case_id=case.id, image_path=str(source),
                        purpose="합성 DHAV 후보 검사", legal_basis="소유한 합성 자료", site_type="home",
                        business_purpose="없음(합성)", role="owner")
    assert result.get("job_id"), result
    for _ in range(50):
        job = await call(client, "forensics_job_status", job_id=result["job_id"], wait_seconds=1)
        if job["status"] in ("succeeded", "failed", "cancelled"):
            assert job["status"] == "succeeded", job
            return job["result"]["evidence_id"]
    raise AssertionError("합성 접수 시간 초과")


def packed(kind, data, *, deleted=False, parent_deleted=False):
    if kind in ("fat", "exfat"):
        disk = fat32_small() if kind == "fat" else exfat_small()
        parent = "/private" if parent_deleted else ""
        if parent:
            disk.mkdir(parent)
        path = parent + "/" + PRIVATE + ".mp4"
        disk.add_file(path, data)
        if deleted:
            disk.delete(path)
        if parent_deleted:
            disk.delete(parent)
        return disk.image(), path
    stream = io.BytesIO()
    path = "private/" + PRIVATE + ".mp4"
    if kind == "tar":
        with tarfile.open(fileobj=stream, mode="w") as archive:
            entry = tarfile.TarInfo(path)
            entry.size = len(data)
            archive.addfile(entry, io.BytesIO(data))
    else:
        with zipfile.ZipFile(stream, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            archive.writestr(path, data)
    return stream.getvalue(), path


async def prepare(case, tmp_path, *, kind="file", data=CONTENT, **kwargs):
    from forensics_mcp import server as S
    blob, path = (data, None) if kind == "file" else packed(kind, data, **kwargs)
    source = tmp_path / (PRIVATE + ".bin")
    source.write_bytes(blob)
    async with Client(S.server) as client:
        ev = await intake(client, case, source)
    return ev, path, blob


def analyses(case):
    return list((case.dir / "forensics/analysis").glob("dhav-candidates-*.json"))


async def invoke(case_id, ev, **kwargs):
    from forensics_mcp import dhav_tools as T, server as S
    args = dict(partition=None, ref=None, path=None, method="auto", max_seconds=45)
    args.update(kwargs)
    return await T._dhav_run(T._ServerAPI(vars(S)), case_id=case_id, evidence_id=ev, **args)


async def wait_event(event):
    for _ in range(500):
        if event.is_set():
            return
        await asyncio.sleep(.01)
    raise AssertionError("합성 워커 경계 대기 시간 초과")


def assert_coverage(report, data):
    coverage = report["coverage"]
    assert coverage["input_bytes"] == len(data)
    assert coverage["search_positions_total"] == max(0, len(data) - 3)
    assert coverage["search_positions_examined"] <= coverage["search_positions_total"]
    assert coverage["container_examined"] is False
    assert report["summary"]["candidates_reported"] == len(report["candidates"])
    for key in ("payload_semantics_examined", "extension_fields_examined", "checksum_verified",
                "media_decoded", "playback_verified", "recording_time_verified",
                "encryption_assessed", "original_file_boundary_verified", "complete_recording"):
        assert report[key] is False
    assert all(c["confidence"] == "possible" and c["footer_length_matches"] is True
               for c in report["candidates"])



@pytest.mark.parametrize("kind", ["file", "fat", "exfat", "tar", "zip"])
async def test_actual_mcp_selected_file_source_coverage_and_privacy(mcase, tmp_path, kind, caplog):
    from forensics_mcp import server as S
    ev, path, blob = await prepare(mcase, tmp_path, kind=kind)
    start = len(S.custody(mcase).entries())
    async with Client(S.server) as client:
        result = await call(client, "forensics_dhav_candidates", case_id=mcase.id, evidence_id=ev, path=path)
        assert result.get("ok"), result
        report, src = result["report"], result["report"]["source"]
        assert report["status"] == "ok"
        assert report["coverage"]["search_complete"] is True
        assert_coverage(report, CONTENT)
        assert src["evidence_sha256"] == hashlib.sha256(blob).hexdigest()
        assert src["selected_sha256"] == hashlib.sha256(CONTENT).hexdigest()
        assert src["selected_size"] == len(CONTENT) and src["complete"] is True
        assert src["member_selected"] is (kind != "file")
        assert src["container"] == ("filesystem" if kind in ("fat", "exfat") else kind)
        assert src["parent_deleted"] is (False if kind in ("fat", "exfat") else None)
        assert src["container_truncated"] is (False if kind in ("tar", "zip") else None)
        assert src["deleted"] is (None if kind == "file" else False)
        assert report["profile"] == "dhav-record-framing-v1"
        assert [c["offset"] for c in report["candidates"]] == [len(PREFIX), len(PREFIX) + len(FIRST), len(PREFIX) + len(FIRST) + len(SECOND)]
        assert [c["record_length"] for c in report["candidates"]] == [len(FIRST), len(SECOND), len(THIRD)]
        assert report["summary"]["anchor_rejections"]["unsupported_record_type"] == 1
        saved = mcase.dir / result["analysis"]["path"]
        assert stat.S_IMODE(saved.stat().st_mode) == 0o444
        assert result["analysis"]["sha256"] == hashlib.sha256(saved.read_bytes()).hexdigest()
        public = json.dumps(result) + saved.read_text() + json.dumps(S.custody(mcase).entries()[start:]) + caplog.text
        for hidden in (PRIVATE, "SECRET", str(tmp_path)):
            assert hidden not in public
        assert S.custody(mcase).entries()[-1]["event"] == "dhav-candidates"
        assert len(analyses(mcase)) == 1
        tool = next(t for t in (await client.list_tools()).tools if t.name == "forensics_dhav_candidates")
        assert tool.annotations.read_only_hint is False
        assert set(tool.input_schema["properties"]) == {
            "case_id", "evidence_id", "partition", "ref", "path", "method", "max_seconds", "offset", "length"}
        assert not list((mcase.dir / "forensics/recovered").glob("**/*"))
        if path:
            second = await call(client, "forensics_dhav_candidates", case_id=mcase.id, evidence_id=ev,
                                ref=src["ref"], partition=src["partition"])
            assert second.get("ok"), second
            assert second["report"]["source"] == src


@pytest.mark.parametrize("kind", ["fat", "exfat"])
@pytest.mark.parametrize("parent", [False, True])
@pytest.mark.parametrize("data", [CONTENT, b"no supported anchor"], ids=["records", "unsupported"])
async def test_deleted_file_or_parent_is_not_certain_candidate(mcase, tmp_path, kind, parent, data):
    from forensics_mcp import server as S
    ev, _, _ = await prepare(mcase, tmp_path, kind=kind, data=data,
                            deleted=not parent, parent_deleted=parent)
    async with Client(S.server) as client:
        listed = await call(client, "forensics_fs_list", case_id=mcase.id, evidence_id=ev)
        listing = json.loads((mcase.dir / listed["result_path"]).read_bytes())
        entry = next(e for v in listing["volumes"] for e in v["walk"]["entries"] if not e.get("is_dir"))
        result = await call(client, "forensics_dhav_candidates", case_id=mcase.id, evidence_id=ev, ref=entry["ref"])
        assert result.get("ok"), result
        report = result["report"]
        assert report["status"] == "partial"
        assert report["coverage"]["search_complete"] is True
        assert report["coverage"]["selection_uncertain"] is True
        assert report["source"]["parent_deleted"] is parent
        assert report["source"]["deleted"] is (not parent)
        assert report["source"]["container_truncated"] is None
        assert len(report["candidates"]) == (3 if data == CONTENT else 0)


@pytest.mark.parametrize("kind", ["fat", "exfat", "tar", "zip"])
async def test_empty_selected_file_is_unsupported_complete_read(mcase, tmp_path, kind):
    from forensics_mcp import server as S
    ev, path, _ = await prepare(mcase, tmp_path, kind=kind, data=b"")
    async with Client(S.server) as client:
        result = await call(client, "forensics_dhav_candidates", case_id=mcase.id, evidence_id=ev, path=path)
        assert result.get("ok"), result
        report = result["report"]
        assert report["status"] == "unsupported" and report["candidates"] == []
        assert report["source"]["selected_size"] == 0 and report["source"]["complete"] is True
        assert_coverage(report, b"")


@pytest.mark.parametrize("data", [b"not a record", b"DHAV\xf1", b"DHAV\x00"])
async def test_unsupported_or_fragment_never_implies_playback(mcase, tmp_path, data):
    from forensics_mcp import server as S
    ev, _, _ = await prepare(mcase, tmp_path, data=data)
    async with Client(S.server) as client:
        result = await call(client, "forensics_dhav_candidates", case_id=mcase.id, evidence_id=ev)
        assert result.get("ok"), result
        assert result["report"]["status"] == "unsupported"
        assert result["report"]["candidates"] == []
        assert_coverage(result["report"], data)
        assert PRIVATE not in json.dumps(result)


@pytest.mark.parametrize("change", [
    {"partition": True}, {"partition": 0}, {"partition": 4097}, {"partition": "1"},
    {"partition": 1}, {"method": "chain"}, {"method": "empty"}, {"method": PRIVATE},
    {"ref": "arc:0", "path": PRIVATE}, {"ref": PRIVATE}, {"ref": "arc:1000000"},
    {"path": ""}, {"path": PRIVATE + "\0"}, {"path": "a" * 32769},
    {"max_seconds": True}, {"max_seconds": "1"}, {"max_seconds": 0}, {"max_seconds": 46},
    {"max_seconds": float("nan")}, {"max_seconds": float("inf")}, {"max_seconds": 10 ** 400},
])
async def test_invalid_arguments_do_not_access_case(change, monkeypatch):
    from forensics_mcp import server as S
    from pweh.errors import PwehError
    async def forbidden(*args, **kwargs):
        pytest.fail("잘못된 인자의 케이스 접근")
    monkeypatch.setattr(S, "_case", forbidden)
    with pytest.raises(PwehError) as error:
        await invoke("unused", "EV-0001", **change)
    assert PRIVATE not in str(error.value)


async def test_sdk_errors_hide_invalid_and_missing_argument_inputs(mcase, caplog):
    from forensics_mcp import server as S
    async with Client(S.server) as client:
        for field in ("partition", "max_seconds", "method", "ref"):
            result = await call(client, "forensics_dhav_candidates", case_id=mcase.id,
                                evidence_id="EV-0001", **{field: PRIVATE})
            assert "_error" in result and PRIVATE not in json.dumps(result) + caplog.text
        missing = await call(client, "forensics_dhav_candidates", case_id=mcase.id, path=PRIVATE)
        assert "_error" in missing and PRIVATE not in json.dumps(missing) + caplog.text


@pytest.mark.parametrize("stage", ["read", "parse", "schema", "case"])
async def test_content_exceptions_have_fixed_errors(mcase, tmp_path, monkeypatch, caplog, stage):
    from forensics_mcp import dhav_tools as T, server as S
    from pweh import dhav as media
    ev, _, _ = await prepare(mcase, tmp_path)
    def fail(*args, **kwargs):
        raise ValueError(PRIVATE)
    async def afail(*args, **kwargs):
        raise ValueError(PRIVATE)
    if stage == "case":
        monkeypatch.setattr(S, "_case", afail)
    else:
        target, attr = {"read": (T.fsops, "read_selected_file"), "parse": (media, "scan_dhav_candidates"),
                        "schema": (T.schemas, "validate")}[stage]
        monkeypatch.setattr(target, attr, fail)
    async with Client(S.server) as client:
        result = await call(client, "forensics_dhav_candidates", case_id=mcase.id, evidence_id=ev)
        assert "dhav_candidates_failed" in result.get("_error", ""), result
        assert PRIVATE not in json.dumps(result) + caplog.text
        assert not analyses(mcase)


@pytest.mark.parametrize("change", [
    {"parent_deleted": None}, {"confidence": "low"},
    {"container_truncated": True, "container_truncated_reasons": [PRIVATE]},
])
@pytest.mark.parametrize("data", [CONTENT, b"DHAV\xf1"], ids=["records", "unsupported"])
async def test_uncertain_source_preserves_search_and_rejection_scope(mcase, tmp_path, monkeypatch, change, data):
    from forensics_mcp import dhav_tools as T, server as S
    ev, path, _ = await prepare(mcase, tmp_path, kind="fat", data=data)
    original = T.fsops.read_selected_file
    def read(*args, **kwargs):
        data, member = original(*args, **kwargs)
        member.update(**change, note=PRIVATE, requested_path=PRIVATE)
        return data, member
    monkeypatch.setattr(T.fsops, "read_selected_file", read)
    async with Client(S.server) as client:
        result = await call(client, "forensics_dhav_candidates", case_id=mcase.id, evidence_id=ev, path=path)
        assert result.get("ok"), result
        report = result["report"]
        assert report["status"] == "partial" and report["coverage"]["search_complete"] is True
        expected = "container_listing_incomplete" if "container_truncated" in change else "selection_uncertain"
        assert expected in report["coverage"]["reasons"]
        assert report["coverage"]["selection_uncertain"] is (expected == "selection_uncertain")
        if "container_truncated" in change:
            assert report["source"]["container_truncated_reasons"] == ["unknown_container_limit"]
        assert len(report["candidates"]) == (3 if data == CONTENT else 0)
        assert report["summary"]["anchor_rejections"]["unsupported_record_type"] == 1
        assert report["coverage"]["candidate_checks_complete"] is True
        assert report["coverage"]["candidate_list_complete"] is True
        assert PRIVATE not in json.dumps(result)


@pytest.mark.parametrize("change", [{"sha256": "0" * 64}, {"size": True}, {"complete": False},
                                    {"container": PRIVATE}, {"ref": PRIVATE}, {"confidence": PRIVATE}])
async def test_invalid_selection_metadata_cannot_commit(mcase, tmp_path, monkeypatch, change):
    from forensics_mcp import dhav_tools as T, server as S
    ev, _, _ = await prepare(mcase, tmp_path)
    original = T.fsops.read_selected_file
    def read(*args, **kwargs):
        data, member = original(*args, **kwargs)
        member.update(change)
        return data, member
    monkeypatch.setattr(T.fsops, "read_selected_file", read)
    async with Client(S.server) as client:
        result = await call(client, "forensics_dhav_candidates", case_id=mcase.id, evidence_id=ev)
        assert "_error" in result and PRIVATE not in json.dumps(result)
        assert not analyses(mcase)


async def test_parser_deadline_partial_is_saved(mcase, tmp_path, monkeypatch):
    from forensics_mcp import server as S
    from pweh import dhav as media
    ev, _, _ = await prepare(mcase, tmp_path)
    original = media.scan_dhav_candidates
    def parse(*args, **kwargs):
        kwargs["deadline"] = time.monotonic() - 1
        return original(*args, **kwargs)
    monkeypatch.setattr(media, "scan_dhav_candidates", parse)
    async with Client(S.server) as client:
        result = await call(client, "forensics_dhav_candidates", case_id=mcase.id, evidence_id=ev)
        assert result.get("ok"), result
        assert result["report"]["status"] == "partial"
        assert result["report"]["coverage"]["search_complete"] is False
        assert result["report"]["coverage"]["unexamined_positions"]["count"] == len(CONTENT) - 3
        assert len(analyses(mcase)) == 1


async def test_schema_rejects_raw_content_without_echo(mcase, tmp_path, monkeypatch, caplog):
    from forensics_mcp import server as S
    from pweh import dhav as media
    ev, _, _ = await prepare(mcase, tmp_path)
    original = media.scan_dhav_candidates
    def parse(*args, **kwargs):
        report = original(*args, **kwargs)
        report["raw_payload"] = PRIVATE
        return report
    monkeypatch.setattr(media, "scan_dhav_candidates", parse)
    async with Client(S.server) as client:
        result = await call(client, "forensics_dhav_candidates", case_id=mcase.id, evidence_id=ev)
        assert "_error" in result and PRIVATE not in json.dumps(result) + caplog.text
        assert not analyses(mcase)


@pytest.mark.parametrize("field", ["input_bytes", "candidates_reported"])
async def test_core_report_is_bound_to_selected_bytes_and_row_count(mcase, tmp_path, monkeypatch, field):
    from forensics_mcp import server as S
    from pweh import dhav as media
    ev, _, _ = await prepare(mcase, tmp_path)
    original = media.scan_dhav_candidates
    def parse(*args, **kwargs):
        report = original(*args, **kwargs)
        report["coverage" if field == "input_bytes" else "summary"][field] += 1
        return report
    monkeypatch.setattr(media, "scan_dhav_candidates", parse)
    async with Client(S.server) as client:
        result = await call(client, "forensics_dhav_candidates", case_id=mcase.id, evidence_id=ev)
        assert "validation_failed" in result.get("_error", ""), result
        assert not analyses(mcase)


async def test_incomplete_record_is_partial_without_payload_or_boundary_claim(mcase, tmp_path):
    from forensics_mcp import server as S
    data = PREFIX + record(payload=PRIVATE.encode())[:-1]
    ev, _, _ = await prepare(mcase, tmp_path, data=data)
    async with Client(S.server) as client:
        result = await call(client, "forensics_dhav_candidates", case_id=mcase.id, evidence_id=ev)
    assert result.get("ok"), result
    report = result["report"]
    assert report["candidates"] == [] and report["status"] == "partial"
    assert report["summary"]["anchor_incomplete"]["record_beyond_selection"] == 1
    assert report["coverage"]["search_complete"] is True
    assert report["coverage"]["candidate_checks_complete"] is False
    assert_coverage(report, data)
    assert PRIVATE not in json.dumps(result)


async def test_candidate_limit_is_partial_metadata_without_carved_output(mcase, tmp_path):
    from forensics_mcp import server as S
    data = record(payload=b"x") * 130
    ev, _, _ = await prepare(mcase, tmp_path, data=data)
    async with Client(S.server) as client:
        result = await call(client, "forensics_dhav_candidates", case_id=mcase.id, evidence_id=ev)
        assert result.get("ok"), result
        report = result["report"]
        assert report["status"] == "partial" and len(report["candidates"]) == 128
        assert report["coverage"]["search_complete"] is False
        assert report["coverage"]["candidate_list_complete"] is False
        assert "candidate_limit" in report["coverage"]["reasons"]
        assert report["coverage"]["unexamined_positions"]["count"] > 0
        assert_coverage(report, data)
        assert not list((mcase.dir / "forensics/recovered").glob("**/*"))
        assert S.custody(mcase).entries()[-1]["event"] == "dhav-candidates"


async def test_selection_and_scanner_share_deadline_cancel_and_bounded_report(mcase, tmp_path, monkeypatch):
    from forensics_mcp import dhav_tools as T, server as S
    from pweh import dhav as media
    ev, path, _ = await prepare(mcase, tmp_path, kind="zip")
    observed = {}
    original_read, original_scan = T.fsops.read_selected_file, media.scan_dhav_candidates
    def read(*args, **kwargs):
        observed.update(deadline=kwargs["deadline"], cancel=kwargs["cancel"])
        assert kwargs["max_bytes"] == 64 << 20 and kwargs["allow_empty"] is True
        return original_read(*args, **kwargs)
    def scan(*args, **kwargs):
        assert kwargs["deadline"] == observed["deadline"]
        assert kwargs["cancel"] == observed["cancel"]
        assert kwargs["limits"].max_output_bytes == (1 << 20) - (16 << 10)
        return original_scan(*args, **kwargs)
    monkeypatch.setattr(T.fsops, "read_selected_file", read)
    monkeypatch.setattr(media, "scan_dhav_candidates", scan)
    async with Client(S.server) as client:
        result = await call(client, "forensics_dhav_candidates", case_id=mcase.id, evidence_id=ev, path=path)
        assert result.get("ok"), result
        assert result["analysis"]["size"] <= 1 << 20


async def test_ev_change_before_commit_records_fixed_integrity_event(mcase, tmp_path, monkeypatch):
    from forensics_mcp import server as S
    from pweh import dhav as media
    ev, _, _ = await prepare(mcase, tmp_path)
    original = media.scan_dhav_candidates
    def parse(*args, **kwargs):
        report = original(*args, **kwargs)
        with S._open_evidence_sync(mcase, ev) as opened:
            target = mcase.dir / opened.intake["stored_path"]
        target.chmod(0o644)
        target.write_bytes(CONTENT + b"changed")
        target.chmod(0o444)
        return report
    monkeypatch.setattr(media, "scan_dhav_candidates", parse)
    start = len(S.custody(mcase).entries())
    async with Client(S.server) as client:
        result = await call(client, "forensics_dhav_candidates", case_id=mcase.id, evidence_id=ev)
        assert "integrity_failed" in result.get("_error", ""), result
        assert not analyses(mcase)
        events = S.custody(mcase).entries()[start:]
        assert events[-1]["event"] == "integrity-failed"
        assert PRIVATE not in json.dumps(events) + json.dumps(result)


@pytest.mark.parametrize("stage", ["read", "parse", "commit"])
async def test_raw_cancel_keeps_fd_worker_owned_and_does_not_commit(mcase, tmp_path, monkeypatch, stage):
    from forensics_mcp import dhav_tools as T, server as S
    from pweh import evidence as E
    from pweh import dhav as media
    ev, _, _ = await prepare(mcase, tmp_path)
    entered, release, finished = threading.Event(), threading.Event(), threading.Event()
    held = {}
    original_close = E.OpenedEvidence.close
    def close(opened):
        try:
            return original_close(opened)
        finally:
            if entered.is_set():
                finished.set()
    monkeypatch.setattr(E.OpenedEvidence, "close", close)
    original_read = T.fsops.read_selected_file
    def read(fd, **kwargs):
        held["fd"] = fd
        if stage == "read":
            entered.set()
            assert release.wait(5)
        return original_read(fd, **kwargs)
    monkeypatch.setattr(T.fsops, "read_selected_file", read)
    if stage != "read":
        target, attr = (media, "scan_dhav_candidates") if stage == "parse" else (E, "store_analysis")
        original = getattr(target, attr)
        def block(*args, **kwargs):
            entered.set()
            assert release.wait(5)
            return original(*args, **kwargs)
        monkeypatch.setattr(target, attr, block)
    task = asyncio.create_task(invoke(mcase.id, ev))
    try:
        await wait_event(entered)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        assert os.fstat(held["fd"]).st_size == len(CONTENT)
    finally:
        release.set()
    await wait_event(finished)
    with pytest.raises(OSError):
        os.fstat(held["fd"])
    assert not analyses(mcase)
    assert all(e["event"] != "dhav-candidates" for e in S.custody(mcase).entries())


async def test_cancel_after_committed_result_is_preserved(mcase, tmp_path, monkeypatch):
    from forensics_mcp import server as S
    from pweh import evidence as E
    ev, _, _ = await prepare(mcase, tmp_path)
    entered, release, finished = threading.Event(), threading.Event(), threading.Event()
    original = E.store_analysis
    def store(*args, **kwargs):
        result = original(*args, **kwargs)
        entered.set()
        try:
            assert release.wait(5)
            return result
        finally:
            finished.set()
    monkeypatch.setattr(E, "store_analysis", store)
    task = asyncio.create_task(invoke(mcase.id, ev))
    try:
        await wait_event(entered)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
    finally:
        release.set()
    await wait_event(finished)
    assert len(analyses(mcase)) == 1
    assert S.custody(mcase).entries()[-1]["event"] == "dhav-candidates"


async def test_audit_error_after_commit_is_fixed_and_preserved(mcase, tmp_path, monkeypatch, caplog):
    from forensics_mcp import server as S
    ev, _, _ = await prepare(mcase, tmp_path)
    def fail(*args, **kwargs):
        raise ValueError(PRIVATE)
    monkeypatch.setattr(S.rt(), "audit", fail)
    async with Client(S.server) as client:
        result = await call(client, "forensics_dhav_candidates", case_id=mcase.id, evidence_id=ev)
        assert result.get("ok") and result.get("warnings"), result
        assert PRIVATE not in json.dumps(result) + caplog.text
        assert len(analyses(mcase)) == 1


@pytest.mark.parametrize("lookup", ["missing", "rebuild"])
async def test_private_sdk_configuration_failure_is_not_silent(lookup):
    from forensics_mcp.dhav_tools import register_dhav_tools
    def rebuild(**kwargs):
        raise RuntimeError(PRIVATE)
    model = SimpleNamespace(model_config={}, model_rebuild=rebuild)
    registered = None if lookup == "missing" else SimpleNamespace(fn_metadata=SimpleNamespace(arg_model=model))
    server = SimpleNamespace(tool=lambda **kwargs: lambda fn: fn,
                             _tool_manager=SimpleNamespace(get_tool=lambda name: registered))
    with pytest.raises(RuntimeError) as error:
        register_dhav_tools(server, {})
    assert PRIVATE not in str(error.value)


async def test_exact_64mib_allowed_and_larger_file_has_no_candidate_success(mcase, tmp_path):
    from forensics_mcp import dhav_tools as T, server as S
    source = tmp_path / "synthetic-large.bin"
    header = bytearray(record(payload=b"x")[:24])
    struct.pack_into("<I", header, 12, T.MAX_FILE_BYTES)
    with source.open("wb") as stream:
        stream.write(header)
        stream.seek(T.MAX_FILE_BYTES - 8)
        stream.write(b"dhav" + struct.pack("<I", T.MAX_FILE_BYTES))
    async with Client(S.server) as client:
        ev = await intake(client, mcase, source)
        result = await call(client, "forensics_dhav_candidates", case_id=mcase.id, evidence_id=ev)
        assert result.get("ok") and result["report"]["source"]["selected_size"] == T.MAX_FILE_BYTES, result
        assert result["report"]["status"] == "ok"
        assert result["report"]["candidates"][0]["record_length"] == T.MAX_FILE_BYTES
        before = len(analyses(mcase))
        with source.open("ab") as stream:
            stream.write(b"x")
        ev = await intake(client, mcase, source)
        result = await call(client, "forensics_dhav_candidates", case_id=mcase.id, evidence_id=ev)
        assert "input_too_large" in result.get("_error", ""), result
        assert len(analyses(mcase)) == before


@pytest.mark.parametrize("data", [CONTENT, b"no supported anchor"], ids=["records", "unsupported"])
async def test_tar_incomplete_listing_ref_only_is_explicit(mcase, tmp_path, data):
    from forensics_mcp import server as S
    blob, path = packed("tar", data)
    data_end = 512 + ((len(data) + 511) // 512) * 512
    source = tmp_path / "partial.tar"
    source.write_bytes(blob[:data_end])
    async with Client(S.server) as client:
        ev = await intake(client, mcase, source)
        by_path = await call(client, "forensics_dhav_candidates", case_id=mcase.id, evidence_id=ev, path=path)
        assert "_error" in by_path and not analyses(mcase)
        result = await call(client, "forensics_dhav_candidates", case_id=mcase.id, evidence_id=ev, ref="arc:0")
        assert result.get("ok"), result
        report = result["report"]
        assert report["status"] == "partial" and report["coverage"]["search_complete"] is True
        assert report["source"]["container_truncated"] is True
        assert "incomplete_archive" in report["source"]["container_truncated_reasons"]
        assert "container_listing_incomplete" in report["coverage"]["reasons"]
        assert report["coverage"]["container_examined"] is False
        assert len(report["candidates"]) == (3 if data == CONTENT else 0)


async def test_bad_zip_crc_has_no_candidate_report(mcase, tmp_path):
    from forensics_mcp import server as S
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w", compression=zipfile.ZIP_STORED) as archive:
        archive.writestr(PRIVATE + ".mp4", CONTENT)
    blob = bytearray(stream.getvalue())
    at = blob.index(CONTENT)
    blob[at] ^= 1
    source = tmp_path / "crc.zip"
    source.write_bytes(blob)
    async with Client(S.server) as client:
        ev = await intake(client, mcase, source)
        result = await call(client, "forensics_dhav_candidates", case_id=mcase.id, evidence_id=ev, ref="arc:0")
        assert "invalid_selection" in result.get("_error", ""), result
        assert PRIVATE not in json.dumps(result) and not analyses(mcase)


@pytest.mark.parametrize("reason", ["incomplete_file", "cancelled", "time", "bad_ref", "budget-cancel", "budget-time"])
async def test_selection_errors_drop_raw_problem_details(mcase, tmp_path, monkeypatch, caplog, reason):
    from forensics_mcp import dhav_tools as T, server as S
    from pweh.fs import FsError
    ev, _, _ = await prepare(mcase, tmp_path)
    def fail(*args, **kwargs):
        if reason.startswith("budget-"):
            limit = "cancelled" if reason == "budget-cancel" else "time"
            raise FsError(PRIVATE, reason="budget_exceeded", data={"path": PRIVATE, "limit": limit})
        raise FsError(PRIVATE, reason=reason, data={"path": PRIVATE})
    monkeypatch.setattr(T.fsops, "read_selected_file", fail)
    async with Client(S.server) as client:
        result = await call(client, "forensics_dhav_candidates", case_id=mcase.id, evidence_id=ev)
        expected = {"incomplete_file": "invalid_selection", "cancelled": "cancelled",
                    "time": "time_limit", "bad_ref": "selection_failed",
                    "budget-cancel": "cancelled", "budget-time": "time_limit"}[reason]
        assert expected in result.get("_error", ""), result
        assert PRIVATE not in json.dumps(result) + caplog.text
        assert not analyses(mcase)


@pytest.mark.parametrize("field,value", [
    ("partition", PRIVATE), ("max_seconds", PRIVATE), ("offset", PRIVATE), ("length", PRIVATE),
    ("case_id", {"private": PRIVATE}), ("evidence_id", {"private": PRIVATE}),
    ("path", {"private": PRIVATE}), ("ref", {"private": PRIVATE}),
])
async def test_actual_sdk_validation_hides_inputs_and_never_opens_case(field, value, monkeypatch, caplog):
    from forensics_mcp import server as S
    from pydantic import ValidationError
    async def forbidden(*args, **kwargs):
        pytest.fail("SDK 입력 거부 전에 케이스에 접근했습니다.")
    monkeypatch.setattr(S, "_case", forbidden)
    args = {"case_id": "synthetic", "evidence_id": "EV-0001", field: value}
    model = S.server._tool_manager.get_tool("forensics_dhav_candidates").fn_metadata.arg_model
    with pytest.raises(ValidationError) as error:
        model.model_validate(args)
    assert PRIVATE not in str(error.value)
    async with Client(S.server) as client:
        result = await client.call_tool("forensics_dhav_candidates", args)
    assert result.is_error and PRIVATE not in result.model_dump_json() + caplog.text


@pytest.mark.parametrize("change", [
    {"offset": True, "length": 33}, {"offset": 0, "length": 33.0},
    {"offset": 0}, {"length": 33}, {"offset": -1, "length": 33},
    {"offset": 0, "length": 0}, {"offset": 0, "length": (64 << 20) + 1},
    {"offset": 2**63, "length": 33}, {"offset": 2**63 - 1, "length": 33},
    {"offset": 0, "length": 33, "path": PRIVATE},
    {"offset": 0, "length": 33, "ref": "arc:0"},
    {"offset": 0, "length": 33, "partition": 1},
    {"offset": 0, "length": 33, "method": "chain"},
])
async def test_range_invalid_arguments_have_no_case_access(change, monkeypatch):
    from forensics_mcp import server as S
    from pweh.errors import PwehError
    async def forbidden(*args, **kwargs):
        pytest.fail("잘못된 구간 인자의 케이스 접근")
    monkeypatch.setattr(S, "_case", forbidden)
    with pytest.raises(PwehError) as error:
        await invoke("unused", "EV-0001", **change)
    assert PRIVATE not in str(error.value)


async def test_large_ev_explicit_range_is_relative_and_final_sealed(mcase, tmp_path, monkeypatch):
    from forensics_mcp import dhav_tools as T, server as S
    R = T.selection
    size, offset = (64 << 20) + 8192, (32 << 20) + 123
    selected = CONTENT + b"x" * (64 << 10)
    source = tmp_path / "synthetic-large-range.bin"
    with source.open("wb") as stream:
        stream.truncate(size)
        stream.write(record())
        stream.seek(offset)
        stream.write(selected)
    async with Client(S.server) as client:
        ev = await intake(client, mcase, source)
        active = threading.local()
        reads, checks = [], []
        original_pread, original_read, original_check = R.os.pread, R.read_candidate_range, R.check_candidate_range
        def pread(fd, count, at):
            if getattr(active, "range", False):
                assert 0 < count <= 64 << 10
                assert offset <= at and at + count <= offset + len(selected)
                reads.append(count)
            return original_pread(fd, count, at)
        def read(*args, **kwargs):
            active.range = True
            try:
                return original_read(*args, **kwargs)
            finally:
                active.range = False
        def check(opened, source, **kwargs):
            checks.append(kwargs.get("time_limit", True))
            return original_check(opened, source, **kwargs)
        monkeypatch.setattr(R.os, "pread", pread)
        monkeypatch.setattr(R, "read_candidate_range", read)
        monkeypatch.setattr(R, "check_candidate_range", check)
        result = await call(client, "forensics_dhav_candidates", case_id=mcase.id, evidence_id=ev,
                            offset=offset, length=len(selected))
    assert result.get("ok"), result
    report, src = result["report"], result["report"]["source"]
    assert len(src) == 18 and src["offset"] == offset and src["evidence_size"] == size
    assert src["selected_size"] == len(selected) and src["selected_sha256"] == hashlib.sha256(selected).hexdigest()
    assert src["method"] == "byte-range" and src["complete"] is True and src["member_selected"] is False
    assert all(src[k] is None for k in ("partition", "ref", "deleted", "parent_deleted", "container_truncated"))
    assert report["profile"] == "dhav-record-ev-range-v1"
    assert report["limitations"][-2:] == ["explicit_evidence_range_only", "outside_range_unexamined"]
    assert report["params"] == {"partition": None, "method": "auto", "max_seconds": 45,
                                "offset": offset, "length": len(selected)}
    assert report["candidates"][0]["offset"] == len(PREFIX)
    assert len(report["candidates"]) == 3 and sum(reads) == len(selected) and len(reads) == 2
    assert checks[0] is True and checks.count(False) >= 3
    assert_coverage(report, selected)


@pytest.mark.parametrize("offset,length", [(len(CONTENT), 1), (len(CONTENT) - 1, 2)])
async def test_outside_ev_has_no_trimmed_success(mcase, tmp_path, offset, length):
    from forensics_mcp import server as S
    ev, _, _ = await prepare(mcase, tmp_path)
    async with Client(S.server) as client:
        result = await call(client, "forensics_dhav_candidates", case_id=mcase.id, evidence_id=ev,
                            offset=offset, length=length)
    assert "invalid_selection" in result.get("_error", "") and not analyses(mcase)


async def test_range_short_read_has_no_report(mcase, tmp_path, monkeypatch):
    from forensics_mcp import dhav_tools as T, server as S
    R = T.selection
    ev, _, _ = await prepare(mcase, tmp_path)
    active = threading.local()
    original_pread, original_read = R.os.pread, R.read_candidate_range
    def pread(fd, count, at):
        data = original_pread(fd, count, at)
        return data[:-1] if getattr(active, "range", False) else data
    def read(*args, **kwargs):
        active.range = True
        try:
            return original_read(*args, **kwargs)
        finally:
            active.range = False
    monkeypatch.setattr(R.os, "pread", pread)
    monkeypatch.setattr(R, "read_candidate_range", read)
    async with Client(S.server) as client:
        result = await call(client, "forensics_dhav_candidates", case_id=mcase.id, evidence_id=ev,
                            offset=0, length=len(CONTENT))
    assert "invalid_selection" in result.get("_error", "") and not analyses(mcase)


async def test_range_mutation_after_scan_fails_final_same_fd_seal(mcase, tmp_path, monkeypatch):
    from forensics_mcp import server as S
    from pweh import dhav
    ev, _, _ = await prepare(mcase, tmp_path, data=b"before" + CONTENT + b"after")
    with S._open_evidence_sync(mcase, ev) as opened:
        path = mcase.dir / opened.intake["stored_path"]
    original = dhav.scan_dhav_candidates
    def scan(*args, **kwargs):
        report = original(*args, **kwargs)
        path.chmod(0o644)
        with path.open("r+b") as stream:
            stream.seek(6)
            stream.write(b"X")
        path.chmod(0o444)
        return report
    monkeypatch.setattr(dhav, "scan_dhav_candidates", scan)
    async with Client(S.server) as client:
        result = await call(client, "forensics_dhav_candidates", case_id=mcase.id, evidence_id=ev,
                            offset=6, length=len(CONTENT))
    assert "integrity_failed" in result.get("_error", ""), result
    assert not analyses(mcase) and S.custody(mcase).entries()[-1]["event"] == "integrity-failed"


async def test_output_swap_at_final_check_preserves_foreign_file(mcase, tmp_path, monkeypatch):
    from forensics_mcp import server as S
    from pweh import evidence as E
    ev, _, _ = await prepare(mcase, tmp_path)
    original = E.recheck_opened
    def swap(*args, **kwargs):
        original(*args, **kwargs)
        path, = analyses(mcase)
        path.rename(tmp_path / "held-output.json")
        path.write_bytes(b"foreign replacement")
        path.chmod(0o444)
    monkeypatch.setattr(E, "recheck_opened", swap)
    async with Client(S.server) as client:
        result = await call(client, "forensics_dhav_candidates", case_id=mcase.id, evidence_id=ev)
    assert "_error" in result
    path, = analyses(mcase)
    assert path.read_bytes() == b"foreign replacement"
    assert not any(e["event"] == "dhav-candidates" for e in S.custody(mcase).entries())


@pytest.mark.parametrize("mutation,expected", [(None, "recorded"), ("tamper", "mismatch"), ("missing", "missing")])
async def test_actual_report_is_bound_in_derived_evidence_list(mcase, tmp_path, mutation, expected):
    from forensics_mcp import server as S
    ev, _, _ = await prepare(mcase, tmp_path)
    async with Client(S.server) as client:
        result = await call(client, "forensics_dhav_candidates", case_id=mcase.id, evidence_id=ev)
        assert result.get("ok"), result
        path = mcase.dir / result["analysis"]["path"]
        if mutation == "missing":
            path.unlink()
        elif mutation == "tamper":
            path.chmod(0o644)
            path.write_bytes(path.read_bytes() + b" ")
            path.chmod(0o444)
        listed = await call(client, "forensics_evidence_list", case_id=mcase.id, write_files=False)
        assert listed.get("ok"), listed
        item, = listed["derived"]
        assert item["kind"] == "dhav-candidates" and item["custody"] == expected


async def test_dhav_report_is_not_admitted_by_existing_bmff_prefix_tool(mcase, tmp_path):
    from forensics_mcp import server as S
    ev, _, _ = await prepare(mcase, tmp_path)
    async with Client(S.server) as client:
        result = await call(client, "forensics_dhav_candidates", case_id=mcase.id, evidence_id=ev)
        assert result.get("ok"), result
        refused = await call(client, "forensics_extract_media_candidate", case_id=mcase.id, evidence_id=ev,
                             analysis_path=result["analysis"]["path"], candidate_index=0)
    assert "_error" in refused and "job_id" not in refused
    assert not any(e["event"] == "extract" for e in S.custody(mcase).entries())
    assert not list((mcase.dir / "forensics/recovered").glob("**/*"))


async def test_adapter_checks_actual_json_bytes_after_schema(mcase, tmp_path, monkeypatch):
    from forensics_mcp import dhav_tools as T, server as S
    ev, _, _ = await prepare(mcase, tmp_path)
    original = json.dumps
    monkeypatch.setattr(T, "json", SimpleNamespace(dumps=lambda *a, **k: original(*a, **k) + " " * (1 << 20)))
    async with Client(S.server) as client:
        result = await call(client, "forensics_dhav_candidates", case_id=mcase.id, evidence_id=ev)
    assert "validation_failed" in result.get("_error", "") and not analyses(mcase)


@pytest.mark.parametrize("range_mode", [False, True])
async def test_actual_outer_deadline_expiry_after_scanner_partial_still_commits(mcase, tmp_path, monkeypatch, range_mode):
    from forensics_mcp import dhav_tools as T, server as S
    from pweh import dhav
    ev, _, _ = await prepare(mcase, tmp_path)
    now = [time.monotonic()]
    monkeypatch.setattr(T, "time", SimpleNamespace(monotonic=lambda: now[0]))
    original = dhav.scan_dhav_candidates
    def scan(*args, **kwargs):
        end = kwargs["deadline"]
        kwargs["deadline"] = time.monotonic() - 1
        report = original(*args, **kwargs)
        now[0] = end + 1
        return report
    monkeypatch.setattr(dhav, "scan_dhav_candidates", scan)
    params = {"offset": 0, "length": len(CONTENT)} if range_mode else {}
    async with Client(S.server) as client:
        result = await call(client, "forensics_dhav_candidates", case_id=mcase.id, evidence_id=ev, **params)
    assert result.get("ok"), result
    assert result["report"]["coverage"]["reasons"] == ["time_limit"]
    assert result["report"]["status"] == "partial" and len(analyses(mcase)) == 1


async def test_raw_cancel_during_range_read_keeps_fd_until_worker_finishes(mcase, tmp_path, monkeypatch):
    from forensics_mcp import dhav_tools as T, server as S
    from pweh import evidence as E
    ev, _, _ = await prepare(mcase, tmp_path)
    entered, release, finished = threading.Event(), threading.Event(), threading.Event()
    held = {}
    original_read, original_close = T.selection.read_candidate_range, E.OpenedEvidence.close
    def read(opened, *args, **kwargs):
        held["fd"] = opened.fd
        entered.set()
        assert release.wait(5)
        return original_read(opened, *args, **kwargs)
    def close(opened):
        try:
            return original_close(opened)
        finally:
            if entered.is_set():
                finished.set()
    monkeypatch.setattr(T.selection, "read_candidate_range", read)
    monkeypatch.setattr(E.OpenedEvidence, "close", close)
    task = asyncio.create_task(invoke(mcase.id, ev, offset=0, length=len(CONTENT)))
    try:
        await wait_event(entered)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        assert os.fstat(held["fd"]).st_size == len(CONTENT)
    finally:
        release.set()
    await wait_event(finished)
    with pytest.raises(OSError):
        os.fstat(held["fd"])
    assert not analyses(mcase)
    assert not any(e["event"] == "dhav-candidates" for e in S.custody(mcase).entries())
