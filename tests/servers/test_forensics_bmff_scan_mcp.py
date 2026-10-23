"""BMFF 검색·기존 구간/추출 연결 및 같은 fd·취소·커밋 경계 시험."""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import stat
import threading
import time
from types import SimpleNamespace

import pytest
from mcp import Client

from mcp_helpers import call
from servers.test_forensics_media_candidates_mcp import anyio_backend, box, intake, mcase, wait_event
from servers.test_forensics_media_prefix_mcp import finished

pytestmark = pytest.mark.anyio
PRIVATE = "SYNTHETIC_BMFF_STREAM_PRIVATE_9c73"
FTYP = box(b"ftyp", b"isom\0\0\0\0")
UNIT = FTYP + box(b"mdat", PRIVATE.encode())
DATA = b"prefix_" + UNIT


def analyses(case):
    return list((case.dir / "forensics/analysis").glob("bmff-scan-*.json"))


async def prepare(case, tmp_path, data=DATA):
    from forensics_mcp import server as S
    path = tmp_path / (PRIVATE + ".bin")
    path.write_bytes(data)
    async with Client(S.server) as client:
        return await intake(client, case, path)


async def invoke(case, ev, **changes):
    from forensics_mcp import bmff_scan_tools as T, server as S
    args = {"case_id": case.id, "evidence_id": ev, "start_offset": 0,
            "max_scan_bytes": 1 << 30, "max_seconds": 45}
    args.update(changes)
    return await T._bmff_scan_run(T._ServerAPI(vars(S)), **args)


def coverage(report, size, start=0):
    """검색 read-ahead와 판정 완료한 8바이트 header 위치를 분리한다."""
    c = report["coverage"]
    total = max(0, size - 7)
    rest = c["unexamined_positions"]
    assert c["evidence_size"] == size and c["search_positions_total"] == total
    assert c["positions_before_start"] == min(start, total)
    assert c["positions_before_start"] + c["search_positions_examined"] + (rest["count"] if rest else 0) == total
    assert c["next_offset"] == (rest["start"] if rest else None)
    assert c["search_complete"] is (rest is None)
    assert c["whole_evidence_search_complete"] is (start == 0 and rest is None)
    assert c["search_positions_examined"] <= max(0, c["search_bytes_read"] - 7)
    assert c["total_bytes_read"] == c["search_bytes_read"] + c["structure_bytes_read"]
    assert c["search_bytes_read"] <= report["params"]["max_scan_bytes"]
    assert c["structure_bytes_read"] <= 1 << 20
    summary = report["summary"]
    assert summary["candidates_reported"] == len(report["candidates"])
    assert summary["anchors_observed"] == sum(summary[k] for k in (
        "anchors_rejected", "oversize_anchors", "candidates_reported")) + int(c["pending_anchor_offset"] is not None)
    for key in ("media_decoded", "playback_verified", "recording_time_verified", "encryption_assessed",
                "format_conformance_assessed", "original_file_boundary_verified",
                "physical_carving_performed", "relations_assessed"):
        assert report[key] is False
    for row in report["candidates"]:
        assert row["confidence"] == "possible" and row["complete_recording"] is False
        assert 16 <= row["validated_prefix_length"] <= 64 << 20
        assert row["offset"] + row["validated_prefix_length"] <= size


async def test_actual_client_metadata_source_seal_privacy_and_registration(mcase, tmp_path, caplog):
    from forensics_mcp import server as S
    from pweh import schemas
    ev = await prepare(mcase, tmp_path)
    async with Client(S.server) as client:
        before = len(S.custody(mcase).entries())
        result = await call(client, "forensics_bmff_scan", case_id=mcase.id, evidence_id=ev)
        assert result.get("ok"), result
        report = result["report"]
        schemas.validate("bmff-scan", report)
        assert report["profile"] == "ftyp-stream-prefix-v1" and report["status"] == "ok"
        assert report["source"] == {"kind": "evidence", "evidence_id": ev,
                                    "evidence_sha256": hashlib.sha256(DATA).hexdigest(), "evidence_size": len(DATA)}
        assert report["params"] == {"start_offset": 0, "max_scan_bytes": 1 << 30, "max_seconds": 45}
        assert report["candidates"][0]["offset"] == 7
        coverage(report, len(DATA))
        saved = mcase.dir / result["analysis"]["path"]
        assert stat.S_IMODE(saved.stat().st_mode) == 0o444
        assert result["analysis"]["sha256"] == hashlib.sha256(saved.read_bytes()).hexdigest()
        events = S.custody(mcase).entries()[before:]
        assert [e["event"] for e in events] == ["bmff-scan"]
        assert events[0]["data"]["source"] == report["source"]
        visible = json.dumps(result) + saved.read_text() + json.dumps(events) + caplog.text
        for hidden in (PRIVATE, str(tmp_path)):
            assert hidden not in visible
        tool = next(t for t in (await client.list_tools()).tools if t.name == "forensics_bmff_scan")
        assert tool.annotations.read_only_hint is False
        assert set(tool.input_schema["properties"]) == {
            "case_id", "evidence_id", "start_offset", "max_scan_bytes", "max_seconds"}
        assert not list((mcase.dir / "forensics/recovered").glob("**/*"))


@pytest.mark.parametrize("delta", range(-7, 1))
async def test_header_crosses_each_64k_window_boundary(mcase, tmp_path, delta):
    from forensics_mcp import server as S
    offset = 65536 + delta
    data = b"x" * offset + UNIT
    ev = await prepare(mcase, tmp_path, data)
    async with Client(S.server) as client:
        result = await call(client, "forensics_bmff_scan", case_id=mcase.id, evidence_id=ev)
    assert result.get("ok"), result
    report = result["report"]
    assert [row["offset"] for row in report["candidates"]] == [offset]
    assert report["coverage"]["search_read_calls"] == 2
    assert report["coverage"]["search_bytes_read"] == len(data)
    coverage(report, len(data))


async def test_large_ev_chain_outside_search_budget_then_range_and_extract(mcase, tmp_path, monkeypatch):
    from forensics_mcp import server as S
    from pweh import bmff_stream as B
    size, offset, search_limit = (64 << 20) + 8192, 65534, 65542
    selected = FTYP + box(b"mdat", PRIVATE.encode() + b"x" * 8192)
    source = tmp_path / "synthetic-large-bmff.bin"
    with source.open("wb") as stream:
        stream.truncate(size)
        stream.seek(offset)
        stream.write(selected)
    reads = []
    original = B.scan_bmff_stream
    def scan(read_at, **kwargs):
        def observed(at, length):
            assert type(at) is int and type(length) is int
            assert 1 <= length <= 65536 and 0 <= at <= size - length
            reads.append((at, length))
            return read_at(at, length)
        return original(observed, **kwargs)
    monkeypatch.setattr(B, "scan_bmff_stream", scan)
    async with Client(S.server) as client:
        ev = await intake(client, mcase, source)
        result = await call(client, "forensics_bmff_scan", case_id=mcase.id, evidence_id=ev,
                            max_scan_bytes=search_limit)
        assert result.get("ok"), result
        report = result["report"]
        row, = report["candidates"]
        assert row["offset"] == offset and row["validated_prefix_length"] == len(selected)
        assert (offset + len(selected), 8) in reads
        assert offset + len(selected) > search_limit
        assert report["coverage"]["search_bytes_read"] == search_limit
        assert sum(length for _, length in reads) == report["coverage"]["total_bytes_read"]
        assert report["status"] == "partial" and report["coverage"]["next_offset"] == search_limit - 7
        coverage(report, size)
        # 검색 보고서는 추출 권위가 아니다. 선택 범위 전체 SHA를 새로 결속한다.
        rejected = await call(client, "forensics_extract_media_candidate", case_id=mcase.id, evidence_id=ev,
                              analysis_path=result["analysis"]["path"], candidate_index=0)
        assert "_error" in rejected and "job_id" not in rejected
        ranged = await call(client, "forensics_media_candidates", case_id=mcase.id, evidence_id=ev,
                            offset=row["offset"], length=row["validated_prefix_length"])
        assert ranged.get("ok"), ranged
        assert ranged["report"]["source"]["selected_sha256"] == hashlib.sha256(selected).hexdigest()
        assert ranged["report"]["candidates"][0]["offset"] == 0
        job = await finished(client, await call(client, "forensics_extract_media_candidate", case_id=mcase.id,
                             evidence_id=ev, analysis_path=ranged["analysis"]["path"], candidate_index=0))
        assert job["status"] == "succeeded", job
        result = job["result"]
        manifest = json.loads((mcase.dir / result["manifest"]).read_bytes())
        assert manifest["source"]["offset"] == offset
        assert (mcase.dir / result["output_dir"] / "candidate-000.bin").read_bytes() == selected
        assert manifest["files"][0]["sha256"] == hashlib.sha256(selected).hexdigest()
        assert [e["event"] for e in S.custody(mcase).entries()][-3:] == ["bmff-scan", "media-candidates", "extract"]
        listed = await call(client, "forensics_evidence_list", case_id=mcase.id, write_files=False)
        assert listed.get("ok"), listed
        assert len(listed["derived"]) == 3
        assert all(item["custody"] == "recorded" for item in listed["derived"])


async def test_budget_last_seven_bytes_resume_without_missing_or_duplicate_candidates(mcase, tmp_path):
    from forensics_mcp import server as S
    data = b"xxxxx" + UNIT + UNIT
    ev = await prepare(mcase, tmp_path, data)
    offset, found, first = 0, [], True
    async with Client(S.server) as client:
        for _ in range(40):
            result = await call(client, "forensics_bmff_scan", case_id=mcase.id, evidence_id=ev,
                                start_offset=offset, max_scan_bytes=11)
            assert result.get("ok"), result
            report = result["report"]
            coverage(report, len(data), offset)
            if first:
                assert report["candidates"] == [] and report["coverage"]["next_offset"] == 4
                first = False
            found.extend(c["offset"] for c in report["candidates"])
            end = report["coverage"]["next_offset"]
            assert report["coverage"]["whole_evidence_search_complete"] is False
            if end is None:
                break
            assert end > offset
            offset = end
        else:
            pytest.fail("유한 검색 재개가 끝나지 않았습니다.")
    assert found == [5, 5 + len(UNIT)]


@pytest.mark.parametrize("start", [1, len(DATA) - 7, len(DATA) - 6, len(DATA)])
async def test_start_suffix_or_eof_never_claims_whole_ev(mcase, tmp_path, start):
    from forensics_mcp import server as S
    ev = await prepare(mcase, tmp_path)
    async with Client(S.server) as client:
        result = await call(client, "forensics_bmff_scan", case_id=mcase.id, evidence_id=ev, start_offset=start)
    assert result.get("ok"), result
    coverage(result["report"], len(DATA), start)
    assert result["report"]["coverage"]["search_complete"] is True
    if start >= len(DATA) - 7:
        assert result["report"]["coverage"]["total_bytes_read"] == 0
        assert result["report"]["status"] == "unsupported"


@pytest.mark.parametrize("data", [b"x", b"ftyp", b"000ftyp", b"no supported anchor"])
async def test_small_or_anchor_free_ev_reports_complete_unsupported(mcase, tmp_path, data):
    from forensics_mcp import server as S
    ev = await prepare(mcase, tmp_path, data)
    async with Client(S.server) as client:
        result = await call(client, "forensics_bmff_scan", case_id=mcase.id, evidence_id=ev)
    assert result.get("ok"), result
    coverage(result["report"], len(data))
    assert result["report"]["status"] == "unsupported"


async def test_candidate_cap_keeps_pending_anchor_for_next_call(mcase, tmp_path):
    from forensics_mcp import server as S
    data = FTYP * 130
    ev = await prepare(mcase, tmp_path, data)
    async with Client(S.server) as client:
        first = await call(client, "forensics_bmff_scan", case_id=mcase.id, evidence_id=ev)
        assert first.get("ok"), first
        report = first["report"]
        coverage(report, len(data))
        assert len(report["candidates"]) == 128
        assert report["coverage"]["reasons"] == ["candidate_limit"]
        assert report["coverage"]["pending_anchor_offset"] == len(FTYP) * 128
        assert report["coverage"]["anchor_probes"] == 128
        second = await call(client, "forensics_bmff_scan", case_id=mcase.id, evidence_id=ev,
                            start_offset=report["coverage"]["next_offset"])
    assert second.get("ok"), second
    assert [row["offset"] for row in second["report"]["candidates"]] == [len(FTYP) * 128, len(FTYP) * 129]
    coverage(second["report"], len(data), len(FTYP) * 128)


async def test_parser_and_outer_deadline_expiry_commits_exact_partial(mcase, tmp_path, monkeypatch):
    from forensics_mcp import bmff_scan_tools as T, server as S
    from pweh import bmff_stream as B
    ev = await prepare(mcase, tmp_path)
    now = [time.monotonic()]
    monkeypatch.setattr(T, "time", SimpleNamespace(monotonic=lambda: now[0]))
    original = B.scan_bmff_stream
    def scan(*args, **kwargs):
        end = kwargs["deadline"]
        kwargs["deadline"] = time.monotonic() - 1
        result = original(*args, **kwargs)
        now[0] = end + 1
        return result
    monkeypatch.setattr(B, "scan_bmff_stream", scan)
    async with Client(S.server) as client:
        result = await call(client, "forensics_bmff_scan", case_id=mcase.id, evidence_id=ev)
    assert result.get("ok"), result
    report = result["report"]
    assert report["status"] == "partial" and report["coverage"]["reasons"] == ["time_limit"]
    assert report["coverage"]["total_bytes_read"] == 0 and report["coverage"]["next_offset"] == 0
    coverage(report, len(DATA))
    assert len(analyses(mcase)) == 1


@pytest.mark.parametrize("field,value", [
    ("start_offset", PRIVATE), ("start_offset", True), ("start_offset", 0.0),
    ("max_scan_bytes", PRIVATE), ("max_scan_bytes", False), ("max_scan_bytes", 8.0),
    ("max_seconds", PRIVATE), ("max_seconds", True),
    ("case_id", {"private": PRIVATE}), ("evidence_id", {"private": PRIVATE}),
])
async def test_sdk_rejects_exact_type_errors_without_input_or_case_access(field, value, monkeypatch, caplog):
    from forensics_mcp import server as S
    from pydantic import ValidationError
    async def forbidden(*args, **kwargs):
        pytest.fail("SDK 거부 인자가 케이스에 도달했습니다.")
    monkeypatch.setattr(S, "_case", forbidden)
    args = {"case_id": "synthetic", "evidence_id": "EV-0001", field: value}
    model = S.server._tool_manager.get_tool("forensics_bmff_scan").fn_metadata.arg_model
    with pytest.raises(ValidationError) as error:
        model.model_validate(args)
    assert PRIVATE not in str(error.value)
    async with Client(S.server) as client:
        result = await client.call_tool("forensics_bmff_scan", args)
    assert result.is_error and PRIVATE not in result.model_dump_json() + caplog.text


@pytest.mark.parametrize("changes", [
    {"start_offset": -1}, {"start_offset": 1 << 63}, {"max_scan_bytes": 0},
    {"max_scan_bytes": 7}, {"max_scan_bytes": (1 << 30) + 1},
    {"max_seconds": 0}, {"max_seconds": 46}, {"max_seconds": -1},
    {"evidence_id": PRIVATE},
])
async def test_value_bounds_are_rejected_before_case_lookup(changes, monkeypatch, caplog):
    from forensics_mcp import server as S
    async def forbidden(*args, **kwargs):
        pytest.fail("범위 밖 인자가 케이스에 도달했습니다.")
    monkeypatch.setattr(S, "_case", forbidden)
    args = {"case_id": "unused", "evidence_id": "EV-0001", **changes}
    async with Client(S.server) as client:
        result = await call(client, "forensics_bmff_scan", **args)
    assert "validation_failed" in result.get("_error", ""), result
    assert PRIVATE not in json.dumps(result) + caplog.text


async def test_start_beyond_actual_ev_is_rejected_without_report(mcase, tmp_path):
    from forensics_mcp import server as S
    ev = await prepare(mcase, tmp_path)
    async with Client(S.server) as client:
        result = await call(client, "forensics_bmff_scan", case_id=mcase.id, evidence_id=ev, start_offset=len(DATA) + 1)
    assert "validation_failed" in result.get("_error", "") and not analyses(mcase)


@pytest.mark.parametrize("failure", ["missing", "rebuild"])
async def test_sdk_private_validation_configuration_fails_closed(failure):
    from forensics_mcp.bmff_scan_tools import register_bmff_scan_tools
    def rebuild(**kwargs):
        raise RuntimeError(PRIVATE)
    model = SimpleNamespace(model_config={}, model_rebuild=rebuild)
    registered = None if failure == "missing" else SimpleNamespace(fn_metadata=SimpleNamespace(arg_model=model))
    server = SimpleNamespace(tool=lambda **kwargs: lambda fn: fn,
                             _tool_manager=SimpleNamespace(get_tool=lambda name: registered))
    with pytest.raises(RuntimeError) as error:
        register_bmff_scan_tools(server, {})
    assert PRIVATE not in str(error.value) and error.value.__suppress_context__ is True


@pytest.mark.parametrize("fault", ["raw", "count", "source_size", "parameter"])
async def test_malformed_core_output_is_not_published(mcase, tmp_path, monkeypatch, caplog, fault):
    from forensics_mcp import server as S
    from pweh import bmff_stream as D
    ev = await prepare(mcase, tmp_path)
    original = D.scan_bmff_stream
    def scan(*args, **kwargs):
        report = original(*args, **kwargs)
        if fault == "raw":
            report["payload"] = PRIVATE
        elif fault == "count":
            report["summary"]["candidates_reported"] += 1
        elif fault == "source_size":
            report["coverage"]["evidence_size"] += 1
        else:
            report["coverage"]["max_scan_bytes"] -= 1
        return report
    monkeypatch.setattr(D, "scan_bmff_stream", scan)
    async with Client(S.server) as client:
        result = await call(client, "forensics_bmff_scan", case_id=mcase.id, evidence_id=ev)
    assert "_error" in result and PRIVATE not in json.dumps(result) + caplog.text
    assert not analyses(mcase)


@pytest.mark.parametrize("fault", ["short", "raised", "mutate"])
async def test_read_callback_errors_and_mutation_remain_fatal(mcase, tmp_path, monkeypatch, caplog, fault):
    from forensics_mcp import bmff_scan_tools as T, server as S
    from pweh import bmff_stream as D
    ev = await prepare(mcase, tmp_path)
    with S._open_evidence_sync(mcase, ev) as opened:
        path = mcase.dir / opened.intake["stored_path"]
    active = threading.local()
    original_scan, original_pread = D.scan_bmff_stream, os.pread
    changed = False
    def pread(fd, count, offset):
        nonlocal changed
        if not getattr(active, "scan", False):
            return original_pread(fd, count, offset)
        if fault == "raised":
            raise OSError(PRIVATE)
        data = original_pread(fd, count, offset)
        if fault == "short":
            return data[:-1]
        if not changed:
            changed = True
            path.chmod(0o644)
            with path.open("r+b") as stream:
                stream.write(b"X")
            path.chmod(0o444)
        return data
    def scan(*args, **kwargs):
        active.scan = True
        try:
            return original_scan(*args, **kwargs)
        finally:
            active.scan = False
    monkeypatch.setattr(D, "scan_bmff_stream", scan)
    monkeypatch.setattr(T.os, "pread", pread)
    async with Client(S.server) as client:
        result = await call(client, "forensics_bmff_scan", case_id=mcase.id, evidence_id=ev)
    code = "integrity_failed" if fault == "mutate" else "bmff_scan_read_failed" if fault == "short" else "bmff_scan_failed"
    assert code in result.get("_error", ""), result
    assert PRIVATE not in json.dumps(result) + caplog.text and not analyses(mcase)
    if fault == "mutate":
        assert S.custody(mcase).entries()[-1]["event"] == "integrity-failed"


@pytest.mark.parametrize("offset,length", [(-1, 1), (True, 1), (0, False),
                                          (0, 0), (0, 65537), (len(DATA), 1)])
async def test_reader_rejects_invalid_request_before_pread(mcase, tmp_path, monkeypatch, offset, length):
    from forensics_mcp import server as S
    from pweh import bmff_stream as B
    from pweh.errors import PwehError
    ev = await prepare(mcase, tmp_path)
    def scan(read_at, **kwargs):
        try:
            read_at(offset, length)
        except Exception:
            # core가 자체 고정 오류로 닫아도 adapter는 원래 입구 오류를 보존한다.
            raise PwehError(PRIVATE, code="bmff_scan_failed") from None
        pytest.fail("범위 밖 callback이 성공했습니다.")
    monkeypatch.setattr(B, "scan_bmff_stream", scan)
    async with Client(S.server) as client:
        result = await call(client, "forensics_bmff_scan", case_id=mcase.id, evidence_id=ev)
    assert "validation_failed" in result.get("_error", "")
    assert PRIVATE not in json.dumps(result) and not analyses(mcase)


async def test_cancel_observed_inside_reader_keeps_original_reason(mcase, tmp_path, monkeypatch):
    from forensics_mcp import bmff_scan_tools as T, server as S
    from pweh import bmff_stream as B
    from pweh.errors import PwehError
    ev = await prepare(mcase, tmp_path)
    original = T._check
    active = threading.local()
    def check(cancelled, deadline, **kwargs):
        if getattr(active, "reading", False):
            cancelled.set()
        return original(cancelled, deadline, **kwargs)
    def scan(read_at, **kwargs):
        active.reading = True
        try:
            read_at(0, 8)
        except Exception:
            raise PwehError(PRIVATE, code="bmff_scan_failed") from None
        finally:
            active.reading = False
    monkeypatch.setattr(T, "_check", check)
    monkeypatch.setattr(B, "scan_bmff_stream", scan)
    async with Client(S.server) as client:
        result = await call(client, "forensics_bmff_scan", case_id=mcase.id, evidence_id=ev)
    assert "cancelled" in result.get("_error", "")
    assert PRIVATE not in json.dumps(result) and not analyses(mcase)


@pytest.mark.parametrize("fault", ["same_inode", "replacement", "hardlink"])
async def test_final_evidence_seal_rejects_changes_after_scan(mcase, tmp_path, monkeypatch, fault):
    from forensics_mcp import server as S
    from pweh import bmff_stream as D
    ev = await prepare(mcase, tmp_path)
    with S._open_evidence_sync(mcase, ev) as opened:
        path = mcase.dir / opened.intake["stored_path"]
    original = D.scan_bmff_stream
    def scan(*args, **kwargs):
        report = original(*args, **kwargs)
        if fault == "replacement":
            path.parent.chmod(0o755)
            path.rename(tmp_path / "held-evidence.bin")
            path.write_bytes(DATA)
            path.chmod(0o444)
        elif fault == "hardlink":
            os.link(path, tmp_path / "other-evidence-link.bin")
        else:
            path.chmod(0o644)
            with path.open("r+b") as stream:
                stream.write(b"X")
            path.chmod(0o444)
        return report
    monkeypatch.setattr(D, "scan_bmff_stream", scan)
    async with Client(S.server) as client:
        result = await call(client, "forensics_bmff_scan", case_id=mcase.id, evidence_id=ev)
    assert "integrity_failed" in result.get("_error", ""), result
    assert not analyses(mcase)
    assert S.custody(mcase).entries()[-1]["event"] == "integrity-failed"


async def test_output_name_replacement_is_preserved_and_not_committed(mcase, tmp_path, monkeypatch):
    from forensics_mcp import server as S
    from pweh import evidence as E
    ev = await prepare(mcase, tmp_path)
    original = E.recheck_opened
    def swap(*args, **kwargs):
        original(*args, **kwargs)
        output, = analyses(mcase)
        output.rename(tmp_path / "held-report.json")
        output.write_bytes(b"foreign replacement")
        output.chmod(0o444)
    monkeypatch.setattr(E, "recheck_opened", swap)
    async with Client(S.server) as client:
        result = await call(client, "forensics_bmff_scan", case_id=mcase.id, evidence_id=ev)
    assert "_error" in result
    output, = analyses(mcase)
    assert output.read_bytes() == b"foreign replacement"
    assert not any(e["event"] == "bmff-scan" for e in S.custody(mcase).entries())


@pytest.mark.parametrize("stage", ["read", "final_output"])
async def test_raw_task_cancel_keeps_fd_until_worker_and_prevents_commit(mcase, tmp_path, monkeypatch, stage):
    from forensics_mcp import bmff_scan_tools as T, server as S
    from pweh import bmff_stream as D, evidence as E
    ev = await prepare(mcase, tmp_path)
    entered, release, closed = threading.Event(), threading.Event(), threading.Event()
    held = {}
    original_check, original_close = T._check_opened, E.OpenedEvidence.close
    def check(opened):
        held["fd"] = opened.fd
        return original_check(opened)
    def close(opened):
        try:
            return original_close(opened)
        finally:
            if opened.fd == held.get("fd"):
                closed.set()
    monkeypatch.setattr(T, "_check_opened", check)
    monkeypatch.setattr(E.OpenedEvidence, "close", close)
    if stage == "read":
        original = D.scan_bmff_stream
        def scan(read_at, **kwargs):
            def block(offset, length):
                entered.set()
                assert release.wait(5)
                return read_at(offset, length)
            return original(block, **kwargs)
        monkeypatch.setattr(D, "scan_bmff_stream", scan)
    else:
        original = E._check_analysis_output
        def block(*args, **kwargs):
            result = original(*args, **kwargs)
            entered.set()
            assert release.wait(5)
            return result
        monkeypatch.setattr(E, "_check_analysis_output", block)
    task = asyncio.create_task(invoke(mcase, ev))
    try:
        await wait_event(entered)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        assert os.fstat(held["fd"]).st_size == len(DATA)
    finally:
        release.set()
    await wait_event(closed)
    with pytest.raises(OSError):
        os.fstat(held["fd"])
    assert not analyses(mcase)
    assert not any(e["event"] == "bmff-scan" for e in S.custody(mcase).entries())


async def test_cancel_after_commit_keeps_report_and_custody(mcase, tmp_path, monkeypatch):
    from forensics_mcp import server as S
    from pweh import evidence as E
    ev = await prepare(mcase, tmp_path)
    entered, release, closed = threading.Event(), threading.Event(), threading.Event()
    original_store, original_close = E.store_analysis, E.OpenedEvidence.close
    def store(*args, **kwargs):
        result = original_store(*args, **kwargs)
        entered.set()
        assert release.wait(5)
        return result
    def close(opened):
        try:
            return original_close(opened)
        finally:
            if entered.is_set():
                closed.set()
    monkeypatch.setattr(E, "store_analysis", store)
    monkeypatch.setattr(E.OpenedEvidence, "close", close)
    task = asyncio.create_task(invoke(mcase, ev))
    try:
        await wait_event(entered)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
    finally:
        release.set()
    await wait_event(closed)
    assert len(analyses(mcase)) == 1
    assert S.custody(mcase).entries()[-1]["event"] == "bmff-scan"


async def test_auxiliary_audit_failure_preserves_committed_report(mcase, tmp_path, monkeypatch, caplog):
    from forensics_mcp import server as S
    ev = await prepare(mcase, tmp_path)
    def fail(*args, **kwargs):
        raise ValueError(PRIVATE)
    monkeypatch.setattr(S.rt(), "audit", fail)
    async with Client(S.server) as client:
        result = await call(client, "forensics_bmff_scan", case_id=mcase.id, evidence_id=ev)
    assert result.get("ok") and result.get("warnings"), result
    assert PRIVATE not in json.dumps(result) + caplog.text
    assert len(analyses(mcase)) == 1 and S.custody(mcase).entries()[-1]["event"] == "bmff-scan"


@pytest.mark.parametrize("mutation,expected", [(None, "recorded"), ("tamper", "mismatch"), ("missing", "missing")])
async def test_saved_scan_is_checked_by_evidence_list(mcase, tmp_path, mutation, expected):
    from forensics_mcp import server as S
    ev = await prepare(mcase, tmp_path)
    async with Client(S.server) as client:
        result = await call(client, "forensics_bmff_scan", case_id=mcase.id, evidence_id=ev)
        assert result.get("ok"), result
        path = mcase.dir / result["analysis"]["path"]
        if mutation == "tamper":
            path.chmod(0o644)
            path.write_bytes(path.read_bytes() + b" ")
            path.chmod(0o444)
        elif mutation == "missing":
            path.unlink()
        listed = await call(client, "forensics_evidence_list", case_id=mcase.id, write_files=False)
    assert listed.get("ok"), listed
    item, = listed["derived"]
    assert item["kind"] == "bmff-scan" and item["custody"] == expected
