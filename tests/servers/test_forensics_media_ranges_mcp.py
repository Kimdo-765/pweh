"""명시 EV 구간의 실제 후보 보고서·prefix·보관 기록 연결을 합성 자료로 확인한다."""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import stat
import struct
import threading
import time

import pytest
from mcp import Client

from mcp_helpers import call
from servers.test_forensics_media_candidates_mcp import (
    analyses, anyio_backend, assert_coverage, box, intake, invoke, mcase, prepare, wait_event,
)
from servers.test_forensics_media_prefix_mcp import finished

pytestmark = pytest.mark.anyio
PRIVATE = b"PRIVATE_EV_RANGE_BODY_a97f"
NOISE = b"selected-leading-noise"
FIRST = box(b"ftyp", b"isom\0\0\0\0") + box(b"mdat", PRIVATE)
SECOND = box(b"ftyp", b"mp42\0\0\0\0") + box(b"moov")
SELECTED = NOISE + FIRST + SECOND


async def candidates(client, case, ev, offset, length, **kwargs):
    return await call(client, "forensics_media_candidates", case_id=case.id, evidence_id=ev,
                      offset=offset, length=length, **kwargs)


async def extract(client, case, ev, report, index=0):
    started = await call(client, "forensics_extract_media_candidate", case_id=case.id, evidence_id=ev,
                         analysis_path=report["analysis"]["path"], candidate_index=index)
    return await finished(client, started)


def assert_range(result, offset, selected, evidence_size):
    from pweh import schemas
    assert result.get("ok"), result
    report = result["report"]
    schemas.validate("media-candidates", report)
    assert report["profile"] == "ftyp-contiguous-ev-range-v1"
    assert report["limitations"][-2:] == ["explicit_evidence_range_only", "outside_range_unexamined"]
    source = report["source"]
    assert len(source) == 18
    assert source["offset"] == offset and source["evidence_size"] == evidence_size
    assert source["selected_size"] == len(selected)
    assert source["selected_sha256"] == hashlib.sha256(selected).hexdigest()
    assert source["container"] == "file" and source["method"] == "byte-range"
    assert source["complete"] is True and source["confidence"] == "high"
    assert source["member_selected"] is False
    assert all(source[k] is None for k in ("partition", "ref", "deleted", "parent_deleted", "container_truncated"))
    assert source["container_truncated_reasons"] == []
    assert set(report["params"]) == {"partition", "method", "max_seconds", "offset", "length"}
    assert report["params"]["offset"] == offset and report["params"]["length"] == len(selected)
    assert report["coverage"]["selection_uncertain"] is False
    assert_coverage(report, selected)
    return report


async def test_large_ev_range_to_prefix_uses_same_relative_coordinates_and_custody(mcase, tmp_path, monkeypatch, caplog):
    from forensics_mcp import media_candidate_selection as R, server as S
    from pweh import schemas
    size, offset = (64 << 20) + 8192, (32 << 20) + 123
    image = tmp_path / (PRIVATE.decode() + ".bin")
    with image.open("wb") as stream:
        stream.truncate(size)
        stream.seek(0)
        stream.write(FIRST)  # 선택 밖의 유효한 anchor를 자동으로 찾아서는 안 된다.
        stream.seek(offset)
        stream.write(SELECTED)
    async with Client(S.server) as client:
        ev = await intake(client, mcase, image)
        before = len(S.custody(mcase).entries())
        active = threading.local()
        reads, ranges = [], []
        real_pread, real_read = R.os.pread, R.read_candidate_range
        def pread(fd, count, at):
            if getattr(active, "range", False):
                reads.append((count, at))
                assert 0 < count <= 64 << 10
                assert offset <= at and at + count <= offset + len(SELECTED)
            return real_pread(fd, count, at)
        def read(opened, start, length, **kwargs):
            ranges.append((start, length))
            active.range = True
            try:
                return real_read(opened, start, length, **kwargs)
            finally:
                active.range = False
        monkeypatch.setattr(R.os, "pread", pread)
        monkeypatch.setattr(R, "read_candidate_range", read)
        result = await candidates(client, mcase, ev, offset, len(SELECTED))
        report = assert_range(result, offset, SELECTED, size)
        assert report["status"] == "ok"
        assert [row["offset"] for row in report["candidates"]] == [len(NOISE), len(NOISE) + len(FIRST)]
        assert [row["validated_prefix_length"] for row in report["candidates"]] == [len(FIRST), len(SECOND)]
        job = await extract(client, mcase, ev, result)
        assert job["status"] == "succeeded", job
        output = job["result"]
        manifest_path = mcase.dir / output["manifest"]
        manifest = json.loads(manifest_path.read_bytes())
        schemas.validate("media-prefix-extract", manifest)
        assert manifest["source"] == report["source"]
        assert manifest["source_coverage"] == report["coverage"]
        assert manifest["candidate"] == report["candidates"][0]
        assert manifest["analysis"] == result["analysis"]
        assert manifest["files"][0]["sha256"] == hashlib.sha256(FIRST).hexdigest()
        assert manifest["files"][0]["sha256"] != report["source"]["selected_sha256"]
        payload = manifest_path.parent / "candidate-000.bin"
        assert payload.read_bytes() == FIRST
        assert stat.S_IMODE(payload.stat().st_mode) == stat.S_IMODE(manifest_path.stat().st_mode) == 0o444
        assert output["bytes_total"] == len(FIRST) and output["files"] == 1
        assert "profile" not in manifest and "params" not in manifest
        assert ranges == [(offset, len(SELECTED)), (offset, len(SELECTED))]
        assert sum(length for length, _ in reads) == 2 * len(SELECTED)
        events = S.custody(mcase).entries()[before:]
        assert [e["event"] for e in events] == ["media-candidates", "extract"]
        assert events[0]["data"]["source"] == report["source"]
        assert events[0]["data"]["params"] == report["params"]
        assert events[1]["data"]["method"] == "media_candidate_prefix"
        listed = await call(client, "forensics_evidence_list", case_id=mcase.id, write_files=False)
        assert listed.get("ok"), listed
        assert next(row for row in listed["derived"] if row["path"] == output["output_dir"])["custody"] == "recorded"
        old = await call(client, "forensics_media_candidates", case_id=mcase.id, evidence_id=ev)
        assert "input_too_large" in old.get("_error", ""), old
    public = json.dumps(result) + json.dumps(output) + json.dumps(manifest) + json.dumps(events) + caplog.text
    assert PRIVATE.decode() not in public and str(tmp_path) not in public


@pytest.mark.parametrize("offset", [0, 17])
async def test_exact_eof_or_entire_small_ev_remains_explicit_range(mcase, tmp_path, offset):
    from forensics_mcp import server as S
    data = b"x" * offset + FIRST
    ev, _, _ = await prepare(mcase, tmp_path, data=data)
    async with Client(S.server) as client:
        result = await candidates(client, mcase, ev, offset, len(FIRST), max_seconds=1.5)
        report = assert_range(result, offset, FIRST, len(data))
        assert report["params"]["max_seconds"] == 1.5
        assert report["candidates"][0]["end_reason"] == "selection_end"
        assert report["original_file_boundary_verified"] is False
        job = await extract(client, mcase, ev, result)
    assert job["status"] == "succeeded", job
    assert (mcase.dir / job["result"]["output_dir"] / "candidate-000.bin").read_bytes() == FIRST


@pytest.mark.parametrize("selected,status,reason", [
    (b"x", "unsupported", None), (FIRST[:7], "unsupported", None),
    (FIRST + struct.pack(">I4s", 0, b"mdat"), "partial", "size_zero"),
    (FIRST + b"cut", "partial", "truncated_header"),
])
async def test_range_boundaries_are_not_original_file_boundaries(mcase, tmp_path, selected, status, reason):
    from forensics_mcp import server as S
    offset = len(FIRST) + 5
    data = FIRST + b"noise" + selected + FIRST
    ev, _, _ = await prepare(mcase, tmp_path, data=data)
    async with Client(S.server) as client:
        result = await candidates(client, mcase, ev, offset, len(selected))
        report = assert_range(result, offset, selected, len(data))
        assert report["status"] == status
        if reason:
            row, = report["candidates"]
            assert row["offset"] == 0 and row["end_reason"] == reason
            assert row["validated_prefix_length"] == len(FIRST)
            job = await extract(client, mcase, ev, result)
            assert job["status"] == "succeeded", job
            assert job["result"]["status"] == "partial"
            assert (mcase.dir / job["result"]["output_dir"] / "candidate-000.bin").read_bytes() == FIRST
        else:
            assert report["candidates"] == []


@pytest.mark.parametrize("changes", [
    {"offset": True, "length": 16}, {"offset": 0, "length": 16.0},
    {"offset": PRIVATE.decode(), "length": 16}, {"offset": 2**63, "length": 16},
    {"offset": 0}, {"length": 16}, {"offset": 0, "length": 0},
    {"offset": 0, "length": 16, "path": PRIVATE.decode()},
])
async def test_public_range_invalid_arguments_do_not_access_case(monkeypatch, changes, caplog):
    from forensics_mcp import server as S
    async def forbidden(*args, **kwargs):
        pytest.fail("잘못된 구간 인자의 case 접근")
    monkeypatch.setattr(S, "_case", forbidden)
    async with Client(S.server) as client:
        result = await call(client, "forensics_media_candidates", case_id="unused", evidence_id="EV-0001", **changes)
    assert "_error" in result
    assert PRIVATE.decode() not in json.dumps(result) + caplog.text


@pytest.mark.parametrize("offset,length", [(len(FIRST), 1), (len(FIRST) - 1, 2), ((1 << 63) - 1, 1)])
async def test_outside_ev_never_trims_a_successful_selection(mcase, tmp_path, offset, length):
    from forensics_mcp import server as S
    ev, _, _ = await prepare(mcase, tmp_path, data=FIRST)
    async with Client(S.server) as client:
        result = await candidates(client, mcase, ev, offset, length)
    assert "_error" in result
    assert not analyses(mcase)


async def test_range_short_read_has_no_report_or_prefix_success(mcase, tmp_path, monkeypatch):
    from forensics_mcp import media_candidate_selection as R, server as S
    ev, _, _ = await prepare(mcase, tmp_path, data=SELECTED)
    active = threading.local()
    real_read, real_pread = R.read_candidate_range, R.os.pread
    def pread(fd, count, at):
        data = real_pread(fd, count, at)
        return data[:-1] if getattr(active, "range", False) else data
    def read(*args, **kwargs):
        active.range = True
        try:
            return real_read(*args, **kwargs)
        finally:
            active.range = False
    monkeypatch.setattr(R.os, "pread", pread)
    monkeypatch.setattr(R, "read_candidate_range", read)
    async with Client(S.server) as client:
        result = await candidates(client, mcase, ev, 0, len(SELECTED))
    assert "_error" in result and not analyses(mcase)
    assert not list((mcase.dir / "forensics/recovered").glob("**/*"))


async def test_changed_range_after_scan_fails_final_ev_seal(mcase, tmp_path, monkeypatch):
    from forensics_mcp import server as S
    from pweh import media_candidates as M
    ev, _, _ = await prepare(mcase, tmp_path, data=b"before" + SELECTED + b"after")
    with S._open_evidence_sync(mcase, ev) as opened:
        path = mcase.dir / opened.intake["stored_path"]
    real_scan = M.scan_bmff_candidates
    def scan(*args, **kwargs):
        report = real_scan(*args, **kwargs)
        path.chmod(0o644)
        with path.open("r+b") as stream:
            stream.seek(6)
            stream.write(b"X")
        path.chmod(0o444)
        return report
    monkeypatch.setattr(M, "scan_bmff_candidates", scan)
    async with Client(S.server) as client:
        result = await candidates(client, mcase, ev, 6, len(SELECTED))
    assert "integrity_failed" in result.get("_error", ""), result
    assert not analyses(mcase)
    assert S.custody(mcase).entries()[-1]["event"] == "integrity-failed"


async def test_range_parser_deadline_partial_is_bound_and_stored(mcase, tmp_path, monkeypatch):
    from forensics_mcp import server as S
    from pweh import media_candidates as M
    ev, _, _ = await prepare(mcase, tmp_path, data=SELECTED)
    real_scan = M.scan_bmff_candidates
    def scan(*args, **kwargs):
        kwargs["deadline"] = time.monotonic() - 1
        return real_scan(*args, **kwargs)
    monkeypatch.setattr(M, "scan_bmff_candidates", scan)
    async with Client(S.server) as client:
        result = await candidates(client, mcase, ev, 0, len(SELECTED))
    report = assert_range(result, 0, SELECTED, len(SELECTED))
    assert report["status"] == "partial" and report["coverage"]["reasons"] == ["time_limit"]
    assert len(analyses(mcase)) == 1


async def test_raw_cancel_keeps_range_fd_until_worker_finishes(mcase, tmp_path, monkeypatch):
    from forensics_mcp import media_candidate_selection as R, server as S
    from pweh import evidence as E
    ev, _, _ = await prepare(mcase, tmp_path, data=SELECTED)
    entered, release, closed = threading.Event(), threading.Event(), threading.Event()
    held = {}
    real_read, real_close = R.read_candidate_range, E.OpenedEvidence.close
    def read(opened, *args, **kwargs):
        held["fd"] = opened.fd
        entered.set()
        assert release.wait(5)
        return real_read(opened, *args, **kwargs)
    def close(opened):
        try:
            return real_close(opened)
        finally:
            if entered.is_set():
                closed.set()
    monkeypatch.setattr(R, "read_candidate_range", read)
    monkeypatch.setattr(E.OpenedEvidence, "close", close)
    task = asyncio.create_task(invoke(mcase.id, ev, offset=0, length=len(SELECTED)))
    try:
        await wait_event(entered)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        assert os.fstat(held["fd"]).st_size == len(SELECTED)
    finally:
        release.set()
    await wait_event(closed)
    with pytest.raises(OSError):
        os.fstat(held["fd"])
    assert not analyses(mcase)
    assert all(e["event"] != "media-candidates" for e in S.custody(mcase).entries())


async def test_omitted_range_keeps_old_candidate_and_inventory_contracts(mcase, tmp_path):
    from forensics_mcp import server as S
    ev, _, _ = await prepare(mcase, tmp_path, data=FIRST)
    async with Client(S.server) as client:
        old = await call(client, "forensics_media_candidates", case_id=mcase.id, evidence_id=ev)
        assert old.get("ok"), old
        assert old["report"]["profile"] == "ftyp-contiguous-top-level-v1"
        assert len(old["report"]["source"]) == 16 and len(old["report"]["params"]) == 3
        job = await extract(client, mcase, ev, old)
        assert job["status"] == "succeeded", job
        inventory = await call(client, "forensics_media_inventory", case_id=mcase.id, evidence_id=ev)
        assert inventory.get("ok"), inventory
        assert inventory["report"]["profile"] == "mp4-quicktime-protection-declarations-v1"
        assert len(inventory["report"]["source"]) == 16 and len(inventory["report"]["params"]) == 3
        tools = {tool.name: tool for tool in (await client.list_tools()).tools}
        assert {"offset", "length"} <= set(tools["forensics_media_candidates"].input_schema["properties"])
        assert not {"offset", "length"} & set(tools["forensics_media_inventory"].input_schema["properties"])
        assert set(tools["forensics_extract_media_candidate"].input_schema["properties"]) == {
            "case_id", "evidence_id", "analysis_path", "candidate_index"}
