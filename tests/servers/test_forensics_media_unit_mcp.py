"""네 형식의 선택 후보 MCP와 출처·입구 오류·커밋·취소 경계."""

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
def mcase(workspace, auth):
    from pweh.case import CaseStore
    return CaseStore(workspace["cases_dir"]).create(
        title="합성 미디어 단위 후보 검사", authorization=auth, case_id="candidatecase")


async def intake(client, case, source):
    result = await call(client, "forensics_intake_start", case_id=case.id, image_path=str(source),
                        purpose="합성 미디어 단위 후보 검사", legal_basis="소유한 합성 자료", site_type="home",
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
    return list((case.dir / "forensics/analysis").glob("media-unit-candidates-*.json"))


async def invoke(case_id, ev, **kwargs):
    from forensics_mcp import media_unit_tools as T, server as S
    args = dict(format="xm", partition=None, ref=None, path=None, method="auto", max_seconds=45)
    args.update(kwargs)
    return await T._media_unit_run(T._ServerAPI(vars(S)), case_id=case_id, evidence_id=ev, **args)


async def wait_event(event):
    for _ in range(500):
        if event.is_set():
            return
        await asyncio.sleep(.01)
    raise AssertionError("합성 워커 경계 대기 시간 초과")


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
            result = await call(client, "forensics_media_unit_candidates", case_id=mcase.id,
                                evidence_id="EV-0001", **{field: PRIVATE})
            assert "_error" in result and PRIVATE not in json.dumps(result) + caplog.text
        missing = await call(client, "forensics_media_unit_candidates", case_id=mcase.id, path=PRIVATE)
        assert "_error" in missing and PRIVATE not in json.dumps(missing) + caplog.text


@pytest.mark.parametrize("stage", ["read", "parse", "schema", "case"])
async def test_content_exceptions_have_fixed_errors(mcase, tmp_path, monkeypatch, caplog, stage):
    from forensics_mcp import media_unit_tools as T, server as S
    from pweh import media_units as media
    ev, _, _ = await prepare(mcase, tmp_path)
    def fail(*args, **kwargs):
        raise ValueError(PRIVATE)
    async def afail(*args, **kwargs):
        raise ValueError(PRIVATE)
    if stage == "case":
        monkeypatch.setattr(S, "_case", afail)
    else:
        target, attr = {"read": (T.fsops, "read_selected_file"), "parse": (media, "scan_media_unit_candidates"),
                        "schema": (T.schemas, "validate")}[stage]
        monkeypatch.setattr(target, attr, fail)
    async with Client(S.server) as client:
        result = await call(client, "forensics_media_unit_candidates", case_id=mcase.id, evidence_id=ev)
        assert "media_unit_candidates_failed" in result.get("_error", ""), result
        assert PRIVATE not in json.dumps(result) + caplog.text
        assert not analyses(mcase)


@pytest.mark.parametrize("change", [{"sha256": "0" * 64}, {"size": True}, {"complete": False},
                                    {"container": PRIVATE}, {"ref": PRIVATE}, {"confidence": PRIVATE}])
async def test_invalid_selection_metadata_cannot_commit(mcase, tmp_path, monkeypatch, change):
    from forensics_mcp import media_unit_tools as T, server as S
    ev, _, _ = await prepare(mcase, tmp_path)
    original = T.fsops.read_selected_file
    def read(*args, **kwargs):
        data, member = original(*args, **kwargs)
        member.update(change)
        return data, member
    monkeypatch.setattr(T.fsops, "read_selected_file", read)
    async with Client(S.server) as client:
        result = await call(client, "forensics_media_unit_candidates", case_id=mcase.id, evidence_id=ev)
        assert "_error" in result and PRIVATE not in json.dumps(result)
        assert not analyses(mcase)


async def test_parser_deadline_partial_is_saved(mcase, tmp_path, monkeypatch):
    from forensics_mcp import server as S
    from pweh import media_units as media
    ev, _, _ = await prepare(mcase, tmp_path)
    original = media.scan_media_unit_candidates
    def parse(*args, **kwargs):
        kwargs["deadline"] = time.monotonic() - 1
        return original(*args, **kwargs)
    monkeypatch.setattr(media, "scan_media_unit_candidates", parse)
    async with Client(S.server) as client:
        result = await call(client, "forensics_media_unit_candidates", case_id=mcase.id, evidence_id=ev)
        assert result.get("ok"), result
        assert result["report"]["status"] == "partial"
        assert result["report"]["coverage"]["search_complete"] is False
        assert result["report"]["coverage"]["unexamined_positions"]["count"] == len(CONTENT)
        assert len(analyses(mcase)) == 1


async def test_schema_rejects_raw_content_without_echo(mcase, tmp_path, monkeypatch, caplog):
    from forensics_mcp import server as S
    from pweh import media_units as media
    ev, _, _ = await prepare(mcase, tmp_path)
    original = media.scan_media_unit_candidates
    def parse(*args, **kwargs):
        report = original(*args, **kwargs)
        report["raw_payload"] = PRIVATE
        return report
    monkeypatch.setattr(media, "scan_media_unit_candidates", parse)
    async with Client(S.server) as client:
        result = await call(client, "forensics_media_unit_candidates", case_id=mcase.id, evidence_id=ev)
        assert "_error" in result and PRIVATE not in json.dumps(result) + caplog.text
        assert not analyses(mcase)


@pytest.mark.parametrize("field", ["input_bytes", "candidates_reported"])
async def test_core_report_is_bound_to_selected_bytes_and_row_count(mcase, tmp_path, monkeypatch, field):
    from forensics_mcp import server as S
    from pweh import media_units as media
    ev, _, _ = await prepare(mcase, tmp_path)
    original = media.scan_media_unit_candidates
    def parse(*args, **kwargs):
        report = original(*args, **kwargs)
        report["coverage" if field == "input_bytes" else "summary"][field] += 1
        return report
    monkeypatch.setattr(media, "scan_media_unit_candidates", parse)
    async with Client(S.server) as client:
        result = await call(client, "forensics_media_unit_candidates", case_id=mcase.id, evidence_id=ev)
        assert "validation_failed" in result.get("_error", ""), result
        assert not analyses(mcase)


async def test_selection_and_scanner_share_deadline_cancel_and_bounded_report(mcase, tmp_path, monkeypatch):
    from forensics_mcp import media_unit_tools as T, server as S
    from pweh import media_units as media
    ev, path, _ = await prepare(mcase, tmp_path, kind="zip")
    observed = {}
    original_read, original_scan = T.fsops.read_selected_file, media.scan_media_unit_candidates
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
    monkeypatch.setattr(media, "scan_media_unit_candidates", scan)
    async with Client(S.server) as client:
        result = await call(client, "forensics_media_unit_candidates", case_id=mcase.id, evidence_id=ev, path=path)
        assert result.get("ok"), result
        assert result["analysis"]["size"] <= 1 << 20


async def test_ev_change_before_commit_records_fixed_integrity_event(mcase, tmp_path, monkeypatch):
    from forensics_mcp import server as S
    from pweh import media_units as media
    ev, _, _ = await prepare(mcase, tmp_path)
    original = media.scan_media_unit_candidates
    def parse(*args, **kwargs):
        report = original(*args, **kwargs)
        with S._open_evidence_sync(mcase, ev) as opened:
            target = mcase.dir / opened.intake["stored_path"]
        target.chmod(0o644)
        target.write_bytes(CONTENT + b"changed")
        target.chmod(0o444)
        return report
    monkeypatch.setattr(media, "scan_media_unit_candidates", parse)
    start = len(S.custody(mcase).entries())
    async with Client(S.server) as client:
        result = await call(client, "forensics_media_unit_candidates", case_id=mcase.id, evidence_id=ev)
        assert "integrity_failed" in result.get("_error", ""), result
        assert not analyses(mcase)
        events = S.custody(mcase).entries()[start:]
        assert events[-1]["event"] == "integrity-failed"
        assert PRIVATE not in json.dumps(events) + json.dumps(result)


@pytest.mark.parametrize("stage", ["read", "parse", "commit"])
async def test_raw_cancel_keeps_fd_worker_owned_and_does_not_commit(mcase, tmp_path, monkeypatch, stage):
    from forensics_mcp import media_unit_tools as T, server as S
    from pweh import evidence as E
    from pweh import media_units as media
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
        target, attr = (media, "scan_media_unit_candidates") if stage == "parse" else (E, "store_analysis")
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
    assert all(e["event"] != "media-unit-candidates" for e in S.custody(mcase).entries())


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
    assert S.custody(mcase).entries()[-1]["event"] == "media-unit-candidates"


async def test_audit_error_after_commit_is_fixed_and_preserved(mcase, tmp_path, monkeypatch, caplog):
    from forensics_mcp import server as S
    ev, _, _ = await prepare(mcase, tmp_path)
    def fail(*args, **kwargs):
        raise ValueError(PRIVATE)
    monkeypatch.setattr(S.rt(), "audit", fail)
    async with Client(S.server) as client:
        result = await call(client, "forensics_media_unit_candidates", case_id=mcase.id, evidence_id=ev)
        assert result.get("ok") and result.get("warnings"), result
        assert PRIVATE not in json.dumps(result) + caplog.text
        assert len(analyses(mcase)) == 1


@pytest.mark.parametrize("lookup", ["missing", "rebuild"])
async def test_private_sdk_configuration_failure_is_not_silent(lookup):
    from forensics_mcp.media_unit_tools import register_media_unit_tools
    def rebuild(**kwargs):
        raise RuntimeError(PRIVATE)
    model = SimpleNamespace(model_config={}, model_rebuild=rebuild)
    registered = None if lookup == "missing" else SimpleNamespace(fn_metadata=SimpleNamespace(arg_model=model))
    server = SimpleNamespace(tool=lambda **kwargs: lambda fn: fn,
                             _tool_manager=SimpleNamespace(get_tool=lambda name: registered))
    with pytest.raises(RuntimeError) as error:
        register_media_unit_tools(server, {})
    assert PRIVATE not in str(error.value)


@pytest.mark.parametrize("reason", ["incomplete_file", "cancelled", "time", "bad_ref", "budget-cancel", "budget-time"])
async def test_selection_errors_drop_raw_problem_details(mcase, tmp_path, monkeypatch, caplog, reason):
    from forensics_mcp import media_unit_tools as T, server as S
    from pweh.fs import FsError
    ev, _, _ = await prepare(mcase, tmp_path)
    def fail(*args, **kwargs):
        if reason.startswith("budget-"):
            limit = "cancelled" if reason == "budget-cancel" else "time"
            raise FsError(PRIVATE, reason="budget_exceeded", data={"path": PRIVATE, "limit": limit})
        raise FsError(PRIVATE, reason=reason, data={"path": PRIVATE})
    monkeypatch.setattr(T.fsops, "read_selected_file", fail)
    async with Client(S.server) as client:
        result = await call(client, "forensics_media_unit_candidates", case_id=mcase.id, evidence_id=ev)
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
    model = S.server._tool_manager.get_tool("forensics_media_unit_candidates").fn_metadata.arg_model
    with pytest.raises(ValidationError) as error:
        model.model_validate(args)
    assert PRIVATE not in str(error.value)
    async with Client(S.server) as client:
        result = await client.call_tool("forensics_media_unit_candidates", args)
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


@pytest.mark.parametrize("offset,length", [(len(CONTENT), 1), (len(CONTENT) - 1, 2)])
async def test_outside_ev_has_no_trimmed_success(mcase, tmp_path, offset, length):
    from forensics_mcp import server as S
    ev, _, _ = await prepare(mcase, tmp_path)
    async with Client(S.server) as client:
        result = await call(client, "forensics_media_unit_candidates", case_id=mcase.id, evidence_id=ev,
                            offset=offset, length=length)
    assert "invalid_selection" in result.get("_error", "") and not analyses(mcase)


async def test_range_short_read_has_no_report(mcase, tmp_path, monkeypatch):
    from forensics_mcp import media_unit_tools as T, server as S
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
        result = await call(client, "forensics_media_unit_candidates", case_id=mcase.id, evidence_id=ev,
                            offset=0, length=len(CONTENT))
    assert "invalid_selection" in result.get("_error", "") and not analyses(mcase)


async def test_range_mutation_after_scan_fails_final_same_fd_seal(mcase, tmp_path, monkeypatch):
    from forensics_mcp import server as S
    from pweh import media_units as media
    ev, _, _ = await prepare(mcase, tmp_path, data=b"before" + CONTENT + b"after")
    with S._open_evidence_sync(mcase, ev) as opened:
        path = mcase.dir / opened.intake["stored_path"]
    original = media.scan_media_unit_candidates
    def scan(*args, **kwargs):
        report = original(*args, **kwargs)
        path.chmod(0o644)
        with path.open("r+b") as stream:
            stream.seek(6)
            stream.write(b"X")
        path.chmod(0o444)
        return report
    monkeypatch.setattr(media, "scan_media_unit_candidates", scan)
    async with Client(S.server) as client:
        result = await call(client, "forensics_media_unit_candidates", case_id=mcase.id, evidence_id=ev,
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
        result = await call(client, "forensics_media_unit_candidates", case_id=mcase.id, evidence_id=ev)
    assert "_error" in result
    path, = analyses(mcase)
    assert path.read_bytes() == b"foreign replacement"
    assert not any(e["event"] == "media-unit-candidates" for e in S.custody(mcase).entries())


@pytest.mark.parametrize("mutation,expected", [(None, "recorded"), ("tamper", "mismatch"), ("missing", "missing")])
async def test_actual_report_is_bound_in_derived_evidence_list(mcase, tmp_path, mutation, expected):
    from forensics_mcp import server as S
    ev, _, _ = await prepare(mcase, tmp_path)
    async with Client(S.server) as client:
        result = await call(client, "forensics_media_unit_candidates", case_id=mcase.id, evidence_id=ev)
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
        assert item["kind"] == "media-unit-candidates" and item["custody"] == expected


async def test_adapter_checks_actual_json_bytes_after_schema(mcase, tmp_path, monkeypatch):
    from forensics_mcp import media_unit_tools as T, server as S
    ev, _, _ = await prepare(mcase, tmp_path)
    original = json.dumps
    monkeypatch.setattr(T, "json", SimpleNamespace(dumps=lambda *a, **k: original(*a, **k) + " " * (1 << 20)))
    async with Client(S.server) as client:
        result = await call(client, "forensics_media_unit_candidates", case_id=mcase.id, evidence_id=ev)
    assert "validation_failed" in result.get("_error", "") and not analyses(mcase)


@pytest.mark.parametrize("range_mode", [False, True])
async def test_actual_outer_deadline_expiry_after_scanner_partial_still_commits(mcase, tmp_path, monkeypatch, range_mode):
    from forensics_mcp import media_unit_tools as T, server as S
    from pweh import media_units as media
    ev, _, _ = await prepare(mcase, tmp_path)
    now = [time.monotonic()]
    monkeypatch.setattr(T, "time", SimpleNamespace(monotonic=lambda: now[0]))
    original = media.scan_media_unit_candidates
    def scan(*args, **kwargs):
        end = kwargs["deadline"]
        kwargs["deadline"] = time.monotonic() - 1
        report = original(*args, **kwargs)
        now[0] = end + 1
        return report
    monkeypatch.setattr(media, "scan_media_unit_candidates", scan)
    params = {"offset": 0, "length": len(CONTENT)} if range_mode else {}
    async with Client(S.server) as client:
        result = await call(client, "forensics_media_unit_candidates", case_id=mcase.id, evidence_id=ev, **params)
    assert result.get("ok"), result
    assert result["report"]["coverage"]["reasons"] == ["time_limit"]
    assert result["report"]["status"] == "partial" and len(analyses(mcase)) == 1


async def test_raw_cancel_during_range_read_keeps_fd_until_worker_finishes(mcase, tmp_path, monkeypatch):
    from forensics_mcp import media_unit_tools as T, server as S
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
    assert not any(e["event"] == "media-unit-candidates" for e in S.custody(mcase).entries())



@pytest.mark.parametrize("format", ["jpeg", "avc-annexb", "mpeg2-ps", "xm"])
@pytest.mark.parametrize("kind", ["file", "fat", "exfat", "tar", "zip"])
async def test_actual_four_formats_source_and_privacy(mcase, tmp_path, format, kind, caplog):
    from forensics_mcp import server as S
    from pweh.media_units import FILE_PROFILES, FALSE_FIELDS
    data, unit = units()[format]
    ev, path, blob = await prepare(mcase, tmp_path, kind=kind, data=data)
    begin = len(S.custody(mcase).entries())
    async with Client(S.server) as client:
        result = await call(client, "forensics_media_unit_candidates", case_id=mcase.id,
                            evidence_id=ev, format=format, path=path)
        assert result.get("ok"), result
        report = result["report"]
        assert report["format"] == report["params"]["format"] == format
        assert report["profile"] == FILE_PROFILES[format]
        src = report["source"]
        assert len(src) == 16 and src["complete"] is True
        assert src["selected_size"] == len(data)
        assert src["selected_sha256"] == hashlib.sha256(data).hexdigest()
        assert src["evidence_sha256"] == hashlib.sha256(blob).hexdigest()
        assert report["summary"]["candidates_reported"] == len(report["candidates"]) == 1
        row, = report["candidates"]
        assert row["offset"] == 0 and row["length"] == len(unit)
        assert row["format"] == format and row["confidence"] == "possible"
        assert report["coverage"]["input_bytes"] == report["coverage"]["search_positions_total"] == len(data)
        assert all(report[key] is False for key in FALSE_FIELDS)
        assert report["status"] == ("partial" if format == "avc-annexb" else "ok")
        saved = mcase.dir / result["analysis"]["path"]
        assert stat.S_IMODE(saved.stat().st_mode) == 0o444
        assert hashlib.sha256(saved.read_bytes()).hexdigest() == result["analysis"]["sha256"]
        public = json.dumps(result) + saved.read_text() + json.dumps(S.custody(mcase).entries()[begin:]) + caplog.text
        assert PRIVATE not in public and str(tmp_path) not in public
        assert S.custody(mcase).entries()[-1]["event"] == "media-unit-candidates"
        tool = next(t for t in (await client.list_tools()).tools if t.name == "forensics_media_unit_candidates")
        assert tool.annotations.read_only_hint is False
        assert set(tool.input_schema["required"]) == {"case_id", "evidence_id", "format"}
        assert not list((mcase.dir / "forensics/recovered").glob("**/*"))


@pytest.mark.parametrize("format", ["jpeg", "avc-annexb", "mpeg2-ps", "xm"])
async def test_range_profiles_relative_coordinates_and_original_ev_hash(mcase, tmp_path, format):
    from forensics_mcp import server as S
    from pweh.media_units import RANGE_PROFILES
    data, unit = units()[format]
    blob = PREFIX + data + b"unexamined suffix"
    ev, _, _ = await prepare(mcase, tmp_path, data=blob)
    async with Client(S.server) as client:
        result = await call(client, "forensics_media_unit_candidates", case_id=mcase.id, evidence_id=ev,
                            format=format, offset=len(PREFIX), length=len(data))
    assert result.get("ok"), result
    report = result["report"]
    assert report["profile"] == RANGE_PROFILES[format]
    assert len(report["source"]) == 18 and len(report["params"]) == 6
    assert report["source"]["offset"] == len(PREFIX)
    assert report["source"]["evidence_size"] == len(blob)
    assert report["source"]["selected_sha256"] == hashlib.sha256(data).hexdigest()
    assert report["source"]["evidence_sha256"] == hashlib.sha256(blob).hexdigest()
    assert report["candidates"][0]["offset"] == 0
    assert report["candidates"][0]["length"] == len(unit)
    assert report["limitations"][-2:] == ["explicit_evidence_range_only", "outside_range_unexamined"]


@pytest.mark.parametrize("format", ["jpeg", "avc-annexb", "mpeg2-ps", "xm"])
@pytest.mark.parametrize("kind", ["fat", "exfat", "tar", "zip"])
async def test_empty_selection_is_stored_unsupported(mcase, tmp_path, format, kind):
    from forensics_mcp import server as S
    ev, path, _ = await prepare(mcase, tmp_path, kind=kind, data=b"")
    async with Client(S.server) as client:
        result = await call(client, "forensics_media_unit_candidates", case_id=mcase.id,
                            evidence_id=ev, format=format, path=path)
    assert result.get("ok"), result
    assert result["report"]["status"] == "unsupported"
    assert result["report"]["source"]["selected_size"] == 0
    assert result["report"]["source"]["complete"] is True
    assert result["report"]["candidates"] == []


@pytest.mark.parametrize("format", [None, True, 1, [], PRIVATE, "JPEG", "dhav", "bmff"])
async def test_format_has_no_implicit_guess_or_fallback(format, monkeypatch, caplog):
    from forensics_mcp import server as S
    async def forbidden(*args, **kwargs):
        pytest.fail("형식 검증 전 케이스 접근")
    monkeypatch.setattr(S, "_case", forbidden)
    async with Client(S.server) as client:
        result = await call(client, "forensics_media_unit_candidates", case_id="synthetic",
                            evidence_id="EV-0001", format=format)
    assert "_error" in result and PRIVATE not in json.dumps(result) + caplog.text


@pytest.mark.parametrize("change", [{"parent_deleted": None}, {"confidence": "low"},
    {"container_truncated": True, "container_truncated_reasons": [PRIVATE]}])
@pytest.mark.parametrize("data", [CONTENT, b"no supported anchor"])
async def test_uncertain_source_even_unsupported_is_partial(mcase, tmp_path, monkeypatch, change, data):
    from forensics_mcp import media_unit_tools as T, server as S
    ev, path, _ = await prepare(mcase, tmp_path, kind="fat", data=data)
    read = T.fsops.read_selected_file
    def altered(*args, **kwargs):
        selected, member = read(*args, **kwargs)
        member.update(change)
        return selected, member
    monkeypatch.setattr(T.fsops, "read_selected_file", altered)
    async with Client(S.server) as client:
        result = await call(client, "forensics_media_unit_candidates", case_id=mcase.id,
                            evidence_id=ev, path=path)
    assert result.get("ok"), result
    report = result["report"]
    assert report["status"] == "partial"
    expected = "container_listing_incomplete" if "container_truncated" in change else "selection_uncertain"
    assert expected in report["coverage"]["reasons"]
    assert report["coverage"]["search_complete"] is True
    assert len(report["candidates"]) == (3 if data == CONTENT else 0)
    assert PRIVATE not in json.dumps(result)
