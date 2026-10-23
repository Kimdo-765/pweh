"""합성 증거의 할당 창·구간 후보·추출과 같은 FD/취소/커밋 연결 시험."""

from __future__ import annotations

import asyncio
import dataclasses
import hashlib
import json
import os
import stat
import threading
import time
from types import SimpleNamespace

import pytest
from mcp import Client

from fs.builders import exfat_small, fat12_small, fat16_small, fat32_small
from mcp_helpers import call
from servers.test_forensics_dhav_mcp import anyio_backend, intake, mcase, record, wait_event
from servers.test_forensics_dhav_record_mcp import finished

pytestmark = pytest.mark.anyio
PRIVATE = "SYNTHETIC_ALLOCATION_PRIVATE_91ab"
CLUSTER = 20


def image(kind="fat12", *, mismatch=False, missing_bitmap=False):
    """미디어 내용과 할당 표시를 독립 구성한다. 파일 소속을 만들지 않는다."""
    disk = {"fat12": fat12_small, "fat16": fat16_small,
            "fat32": fat32_small, "exfat": exfat_small}[kind]()
    disk.add_file("/" + PRIVATE + ".txt", b"")
    if kind == "exfat":
        disk.reserve([CLUSTER + 1])
        if missing_bitmap:
            disk.dirs["/"].slots = [s for s in disk.dirs["/"].slots if s[0] != 0x81]
    else:
        disk.set_fat(CLUSTER + 1, disk.eoc)
        disk.set_fat(CLUSTER + 2, {"fat12": 0xff7, "fat16": 0xfff7, "fat32": 0x0ffffff7}[kind])
        if mismatch:
            disk.set_fat_copy(1, CLUSTER, disk.eoc)
    content = record(payload=PRIVATE.encode())
    disk.write_clusters([CLUSTER], b"prefix_" + content)
    return SimpleNamespace(data=disk.image(), disk=disk, offset=disk.coff(CLUSTER),
                           length=disk.cs * 3, unit=content)


def analyses(case):
    return list((case.dir / "forensics/analysis").glob("allocation-window-*.json"))


async def prepare(case, tmp_path, kind="fat12", **kwargs):
    from forensics_mcp import server as S
    env = image(kind, **kwargs)
    path = tmp_path / (PRIVATE + ".img")
    path.write_bytes(env.data)
    async with Client(S.server) as client:
        env.ev = await intake(client, case, path)
    return env


async def invoke(case, env, **changes):
    from forensics_mcp import allocation_tools as T, server as S
    args = dict(case_id=case.id, evidence_id=env.ev, partition=1,
                offset=env.offset, length=env.length, max_seconds=45)
    args.update(changes)
    return await T._allocation_run(T._ServerAPI(vars(S)), **args)


async def query(client, case, env, **changes):
    args = dict(case_id=case.id, evidence_id=env.ev, partition=1,
                offset=env.offset, length=env.length)
    args.update(changes)
    return await call(client, "forensics_allocation_window", **args)


def accounting(report):
    """요청 창과 행 prefix의 산술을 코어 검증기와 독립 대조한다."""
    c, s, p = report["coverage"], report["summary"], report["params"]
    cursor = p["offset"]
    totals = dict.fromkeys(("unallocated", "allocated", "bad", "unknown"), 0)
    for row in report["rows"]:
        assert row["offset"] == cursor and row["length"] > 0
        cursor += row["length"]
        totals[row["state"]] += row["length"]
    assert cursor - p["offset"] == c["processed_bytes"] == sum(totals.values())
    assert c["processed_bytes"] + c["unexamined_bytes"] == p["length"] == c["requested_bytes"]
    assert c["next_offset"] == (cursor if c["unexamined_bytes"] else None)
    assert c["unexamined_offset"] == c["next_offset"]
    assert c["window_complete"] is (c["unexamined_bytes"] == 0)
    assert c["allocation_complete"] is (c["window_complete"] and totals["unknown"] == 0)
    assert (report["status"] == "ok") is c["allocation_complete"]
    assert s == {"rows_reported": len(report["rows"]),
                 **{kind + "_bytes": value for kind, value in totals.items()}}
    assert 0 <= c["metadata_bytes_read"] <= 4 << 20
    for key in ("whole_evidence_examined", "file_ownership_verified", "historical_allocation_verified",
                "media_decoded", "playback_verified", "payload_semantics_examined"):
        assert report[key] is False


@pytest.mark.parametrize("kind", ["fat12", "fat16", "fat32", "exfat"])
async def test_actual_client_report_source_storage_privacy_and_metadata_budget(mcase, tmp_path, monkeypatch, caplog, kind):
    from forensics_mcp import server as S
    from pweh import schemas
    from pweh.fs import allocation as A
    env = await prepare(mcase, tmp_path, kind)
    reads = []
    original = A.inspect_allocation_window
    def inspect(source, **kwargs):
        def read(at, count):
            assert 0 <= at <= source.size - count and 0 <= count <= 65536
            reads.append((at, count))
            return source.read(at, count)
        return original(dataclasses.replace(source, read=read), **kwargs)
    monkeypatch.setattr(A, "inspect_allocation_window", inspect)
    async with Client(S.server) as client:
        result = await query(client, mcase, env)
        assert result.get("ok"), result
        report = result["report"]
        schemas.validate("allocation-window", report)
        accounting(report)
        assert report["status"] == "ok" and report["geometry"]["fs_type"] == kind
        assert report["source"] == {"kind": "evidence", "evidence_id": env.ev,
                                    "evidence_sha256": hashlib.sha256(env.data).hexdigest(), "evidence_size": len(env.data)}
        assert report["params"] == {"partition": 1, "offset": env.offset, "length": env.length, "max_seconds": 45}
        assert [r["state"] for r in report["rows"]] == ["unallocated", "allocated", "unallocated" if kind == "exfat" else "bad"]
        assert sum(count for _, count in reads) == report["coverage"]["metadata_bytes_read"]
        # 정상 metadata는 명시 창의 payload를 읽지 않는다. 손상 pointer의 의미까지 주장하지 않는다.
        assert all(at + count <= env.offset or at >= env.offset + env.length for at, count in reads)
        path = mcase.dir / result["analysis"]["path"]
        assert stat.S_IMODE(path.stat().st_mode) == 0o444
        assert result["analysis"]["sha256"] == hashlib.sha256(path.read_bytes()).hexdigest()
        event = S.custody(mcase).entries()[-1]
        assert event["event"] == "allocation-window" and event["data"]["source"] == report["source"]
        visible = json.dumps(result) + path.read_text() + json.dumps(event) + caplog.text
        for hidden in (PRIVATE, "SECRET", str(tmp_path)):
            assert hidden not in visible
        listed = await call(client, "forensics_evidence_list", case_id=mcase.id, write_files=False)
        assert any(d["kind"] == "allocation-window" and d["custody"] == "recorded" for d in listed["derived"])
        tool = next(t for t in (await client.list_tools()).tools if t.name == "forensics_allocation_window")
        assert tool.annotations.read_only_hint is False
        assert set(tool.input_schema["properties"]) == {"case_id", "evidence_id", "partition", "offset", "length", "max_seconds"}


@pytest.mark.parametrize("kind,kwargs,reason", [
    ("fat16", {"mismatch": True}, "fat_copies_disagree"),
    ("exfat", {"missing_bitmap": True}, "bitmap_missing"),
])
async def test_actual_unknown_is_partial_even_when_window_complete(mcase, tmp_path, kind, kwargs, reason):
    from forensics_mcp import server as S
    env = await prepare(mcase, tmp_path, kind, **kwargs)
    async with Client(S.server) as client:
        result = await query(client, mcase, env, offset=env.offset + 3, length=env.disk.cs - 7)
    assert result.get("ok"), result
    report = result["report"]
    accounting(report)
    assert report["status"] == "partial"
    assert report["coverage"]["window_complete"] and not report["coverage"]["allocation_complete"]
    assert report["rows"] == [{"offset": env.offset + 3, "length": env.disk.cs - 7, "state": "unknown", "reason": reason}]


async def test_free_row_requires_independent_range_report_before_record_extraction(mcase, tmp_path):
    from forensics_mcp import server as S
    env = await prepare(mcase, tmp_path)
    async with Client(S.server) as client:
        result = await query(client, mcase, env)
        assert result.get("ok"), result
        row = result["report"]["rows"][0]
        assert row["state"] == "unallocated"
        rejected = await call(client, "forensics_extract_dhav_candidate", case_id=mcase.id, evidence_id=env.ev,
                              analysis_path=result["analysis"]["path"], candidate_index=0)
        assert "_error" in rejected and "job_id" not in rejected
        candidate = await call(client, "forensics_dhav_candidates", case_id=mcase.id, evidence_id=env.ev,
                               offset=row["offset"], length=row["length"])
        assert candidate.get("ok"), candidate
        source = candidate["report"]["source"]
        assert len(source) == 18 and source["offset"] == row["offset"]
        assert source["selected_sha256"] == hashlib.sha256(env.data[row["offset"]:row["offset"]+row["length"]]).hexdigest()
        assert candidate["report"]["candidates"][0]["offset"] == 7
        job = await finished(client, await call(client, "forensics_extract_dhav_candidate", case_id=mcase.id,
                             evidence_id=env.ev, analysis_path=candidate["analysis"]["path"], candidate_index=0))
        assert job["status"] == "succeeded", job
        output = job["result"]
        assert (mcase.dir / output["output_dir"] / "record-000.bin").read_bytes() == env.unit
        manifest = json.loads((mcase.dir / output["manifest"]).read_bytes())
        assert manifest["files"][0]["sha256"] == hashlib.sha256(env.unit).hexdigest()
        assert [e["event"] for e in S.custody(mcase).entries()][-3:] == ["allocation-window", "dhav-candidates", "extract"]


async def test_rows_limit_prefix_can_resume_and_expired_outer_time_does_not_discard_partial(mcase, tmp_path, monkeypatch):
    from forensics_mcp import allocation_tools as T, server as S
    from pweh.fs import allocation as A
    env = await prepare(mcase, tmp_path)
    original = A.inspect_allocation_window
    now = [time.monotonic()]
    monkeypatch.setattr(T, "time", SimpleNamespace(monotonic=lambda: now[0]))
    def inspect(source, **kwargs):
        kwargs["limits"] = dataclasses.replace(kwargs["limits"], rows=1)
        report = original(source, **kwargs)
        now[0] = kwargs["deadline"] + 1
        return report
    monkeypatch.setattr(A, "inspect_allocation_window", inspect)
    async with Client(S.server) as client:
        first = await query(client, mcase, env)
        assert first.get("ok"), first
        report = first["report"]
        accounting(report)
        assert report["status"] == "partial" and report["coverage"]["reasons"] == ["rows_limit"]
        assert report["coverage"]["next_offset"] == env.offset + env.disk.cs
        monkeypatch.setattr(A, "inspect_allocation_window", original)
        now[0] = time.monotonic()
        second = await query(client, mcase, env, offset=report["coverage"]["next_offset"],
                             length=report["coverage"]["unexamined_bytes"])
    assert second.get("ok"), second
    accounting(second["report"])
    assert second["report"]["status"] == "ok"


@pytest.mark.parametrize("when", ["before_geometry", "after_geometry"])
async def test_same_deadline_is_fatal_before_geometry_and_stored_partial_after(mcase, tmp_path, monkeypatch, when):
    from forensics_mcp import allocation_tools as T, server as S
    from pweh.fs import allocation as A
    env = await prepare(mcase, tmp_path)
    original, tables = A.inspect_allocation_window, A._fat_tables
    now = [time.monotonic()]
    monkeypatch.setattr(T, "time", SimpleNamespace(monotonic=lambda: now[0]))
    def expired_tables(vol, source):
        source.budget.deadline = time.monotonic() - 1
        return tables(vol, source)
    if when == "after_geometry":
        monkeypatch.setattr(A, "_fat_tables", expired_tables)
    def inspect(source, **kwargs):
        end = kwargs["deadline"]
        if when == "before_geometry":
            kwargs["deadline"] = time.monotonic() - 1
        result = original(source, **kwargs)
        now[0] = end + 1
        return result
    monkeypatch.setattr(A, "inspect_allocation_window", inspect)
    async with Client(S.server) as client:
        result = await query(client, mcase, env)
    if when == "before_geometry":
        assert "time_limit" in result.get("_error", "") and not analyses(mcase)
    else:
        assert result.get("ok"), result
        report = result["report"]
        accounting(report)
        assert report["status"] == "partial" and report["rows"] == []
        assert report["coverage"]["reasons"] == ["time_limit"]
        assert report["coverage"]["next_offset"] == env.offset and len(analyses(mcase)) == 1


@pytest.mark.parametrize("field,value", [
    ("partition", True), ("partition", 1.0), ("partition", PRIVATE),
    ("offset", False), ("offset", 0.0), ("offset", PRIVATE),
    ("length", True), ("length", 512.0), ("length", PRIVATE),
    ("max_seconds", True), ("max_seconds", PRIVATE),
    ("case_id", {"private": PRIVATE}), ("evidence_id", {"private": PRIVATE}),
])
async def test_sdk_types_hide_raw_input_before_case_lookup(field, value, monkeypatch, caplog):
    from forensics_mcp import server as S
    from pydantic import ValidationError
    async def forbidden(*args, **kwargs):
        pytest.fail("SDK 거부 입력이 케이스에 도달했습니다.")
    monkeypatch.setattr(S, "_case", forbidden)
    args = dict(case_id="synthetic", evidence_id="EV-0001", partition=1, offset=0, length=1)
    args[field] = value
    model = S.server._tool_manager.get_tool("forensics_allocation_window").fn_metadata.arg_model
    with pytest.raises(ValidationError) as error:
        model.model_validate(args)
    assert PRIVATE not in str(error.value)
    async with Client(S.server) as client:
        result = await client.call_tool("forensics_allocation_window", args)
    assert result.is_error and PRIVATE not in result.model_dump_json() + caplog.text


@pytest.mark.parametrize("changes", [
    {"partition": 0}, {"partition": 4097}, {"offset": -1}, {"offset": 1 << 63},
    {"length": 0}, {"length": (64 << 20) + 1}, {"max_seconds": 0},
    {"max_seconds": -1}, {"max_seconds": 46}, {"evidence_id": PRIVATE},
])
async def test_value_bounds_are_fixed_before_case_lookup(changes, monkeypatch, caplog):
    from forensics_mcp import server as S
    async def forbidden(*args, **kwargs):
        pytest.fail("범위 밖 입력이 케이스에 도달했습니다.")
    monkeypatch.setattr(S, "_case", forbidden)
    args = dict(case_id="synthetic", evidence_id="EV-0001", partition=1, offset=0, length=1)
    args.update(changes)
    async with Client(S.server) as client:
        result = await call(client, "forensics_allocation_window", **args)
    assert "validation_failed" in result.get("_error", "")
    assert PRIVATE not in json.dumps(result) + caplog.text


@pytest.mark.parametrize("seconds", [float("nan"), float("inf"), 10 ** 400])
async def test_direct_nonfinite_and_huge_time_rejected(seconds):
    from forensics_mcp.allocation_tools import _arguments
    from pweh.errors import ValidationFailed
    with pytest.raises(ValidationFailed):
        _arguments("EV-0001", 1, 0, 1, seconds)


@pytest.mark.parametrize("where", ["ev_end", "metadata", "partition"])
async def test_ev_and_partition_data_boundaries_reject_without_report(mcase, tmp_path, where):
    from forensics_mcp import server as S
    env = await prepare(mcase, tmp_path)
    changes = {"offset": len(env.data), "length": 1} if where == "ev_end" else {"offset": 0} if where == "metadata" else {"partition": 4096}
    async with Client(S.server) as client:
        result = await query(client, mcase, env, **changes)
    assert "_error" in result and not analyses(mcase)


@pytest.mark.parametrize("failure", ["missing", "rebuild"])
async def test_sdk_private_configuration_failure_is_fixed(failure):
    from forensics_mcp.allocation_tools import register_allocation_tools
    def rebuild(**kwargs):
        raise RuntimeError(PRIVATE)
    model = SimpleNamespace(model_config={}, model_rebuild=rebuild)
    registered = None if failure == "missing" else SimpleNamespace(fn_metadata=SimpleNamespace(arg_model=model))
    server = SimpleNamespace(tool=lambda **kwargs: lambda fn: fn,
                             _tool_manager=SimpleNamespace(get_tool=lambda name: registered))
    with pytest.raises(RuntimeError) as error:
        register_allocation_tools(server, {})
    assert PRIVATE not in str(error.value) and error.value.__suppress_context__


@pytest.mark.parametrize("fault", ["raw", "summary", "requested", "bool"])
async def test_invalid_core_report_is_not_committed(mcase, tmp_path, monkeypatch, caplog, fault):
    from forensics_mcp import server as S
    from pweh.fs import allocation as A
    env = await prepare(mcase, tmp_path)
    original = A.inspect_allocation_window
    def inspect(*args, **kwargs):
        report = original(*args, **kwargs)
        if fault == "raw":
            report["private"] = PRIVATE
        elif fault == "summary":
            report["summary"]["unallocated_bytes"] += 1
        elif fault == "requested":
            report["coverage"]["requested_bytes"] += 1
        else:
            report["rows"][0]["offset"] = True
        return report
    monkeypatch.setattr(A, "inspect_allocation_window", inspect)
    async with Client(S.server) as client:
        result = await query(client, mcase, env)
    assert "_error" in result and not analyses(mcase)
    assert PRIVATE not in json.dumps(result) + caplog.text


@pytest.mark.parametrize("fault", ["short", "raised", "mutate", "cancel"])
@pytest.mark.parametrize("swallow", [False, True, "partial"])
async def test_leaf_original_error_wins_even_if_core_returns_success(mcase, tmp_path, monkeypatch, caplog, fault, swallow):
    from forensics_mcp import allocation_tools as T, server as S
    from pweh.fs import allocation as A
    env = await prepare(mcase, tmp_path)
    with S._open_evidence_sync(mcase, env.ev) as opened:
        path = mcase.dir / opened.intake["stored_path"]
    active = threading.local()
    original_pread, original = os.pread, A.inspect_allocation_window
    def pread(fd, count, at):
        if not getattr(active, "fault", False):
            return original_pread(fd, count, at)
        if fault == "raised":
            raise OSError(PRIVATE)
        data = original_pread(fd, count, at)
        if fault == "short":
            return data[:-1]
        if fault == "mutate":
            path.chmod(0o644)
            with path.open("r+b") as stream:
                stream.write(b"X")
            path.chmod(0o444)
        return data
    def inspect(source, **kwargs):
        if swallow == "partial":
            kwargs["limits"] = dataclasses.replace(kwargs["limits"], rows=1)
        report = original(source, **kwargs)
        active.fault = True
        try:
            if fault == "cancel":
                kwargs["cancel"].__self__.set()
            try:
                source.read(0, 1)
            except Exception:
                if not swallow:
                    raise RuntimeError(PRIVATE) from None
            return report
        finally:
            active.fault = False
    monkeypatch.setattr(T.os, "pread", pread)
    monkeypatch.setattr(A, "inspect_allocation_window", inspect)
    async with Client(S.server) as client:
        result = await query(client, mcase, env)
    code = "integrity_failed" if fault == "mutate" else "cancelled" if fault == "cancel" else "allocation_read_failed"
    assert code in result.get("_error", ""), result
    assert not analyses(mcase) and PRIVATE not in json.dumps(result) + caplog.text
    if fault == "mutate":
        assert S.custody(mcase).entries()[-1]["event"] == "integrity-failed"


@pytest.mark.parametrize("fault", ["same_inode", "replacement", "hardlink"])
async def test_final_source_seal_rejects_changes_after_core(mcase, tmp_path, monkeypatch, fault):
    from forensics_mcp import server as S
    from pweh.fs import allocation as A
    env = await prepare(mcase, tmp_path)
    with S._open_evidence_sync(mcase, env.ev) as opened:
        path = mcase.dir / opened.intake["stored_path"]
    original = A.inspect_allocation_window
    def inspect(*args, **kwargs):
        report = original(*args, **kwargs)
        if fault == "replacement":
            path.parent.chmod(0o755)
            path.rename(tmp_path / "held-evidence.img")
            path.write_bytes(env.data)
            path.chmod(0o444)
        elif fault == "hardlink":
            os.link(path, tmp_path / "second-name.img")
        else:
            path.chmod(0o644)
            os.utime(path, ns=(path.stat().st_atime_ns, path.stat().st_mtime_ns + 1))
            path.chmod(0o444)
        return report
    monkeypatch.setattr(A, "inspect_allocation_window", inspect)
    async with Client(S.server) as client:
        result = await query(client, mcase, env)
    assert "integrity_failed" in result.get("_error", ""), result
    assert not analyses(mcase) and S.custody(mcase).entries()[-1]["event"] == "integrity-failed"


async def test_output_replacement_is_preserved_without_commit(mcase, tmp_path, monkeypatch):
    from forensics_mcp import server as S
    from pweh import evidence as E
    env = await prepare(mcase, tmp_path)
    original = E.recheck_opened
    def replace(*args, **kwargs):
        original(*args, **kwargs)
        output, = analyses(mcase)
        output.rename(tmp_path / "held-output.json")
        output.write_bytes(b"foreign output")
        output.chmod(0o444)
    monkeypatch.setattr(E, "recheck_opened", replace)
    async with Client(S.server) as client:
        result = await query(client, mcase, env)
    assert "_error" in result
    output, = analyses(mcase)
    assert output.read_bytes() == b"foreign output"
    assert not any(e["event"] == "allocation-window" for e in S.custody(mcase).entries())


@pytest.mark.parametrize("stage", ["read", "final_output"])
async def test_raw_cancel_retains_fd_until_worker_and_commits_nothing(mcase, tmp_path, monkeypatch, stage):
    from forensics_mcp import allocation_tools as T, server as S
    from pweh import evidence as E
    from pweh.fs import allocation as A
    env = await prepare(mcase, tmp_path)
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
        original = A.inspect_allocation_window
        def inspect(source, **kwargs):
            def read(at, count):
                entered.set()
                assert release.wait(5)
                return source.read(at, count)
            return original(dataclasses.replace(source, read=read), **kwargs)
        monkeypatch.setattr(A, "inspect_allocation_window", inspect)
    else:
        original = E._check_analysis_output
        def block(*args, **kwargs):
            result = original(*args, **kwargs)
            entered.set()
            assert release.wait(5)
            return result
        monkeypatch.setattr(E, "_check_analysis_output", block)
    task = asyncio.create_task(invoke(mcase, env))
    try:
        await wait_event(entered)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        assert os.fstat(held["fd"]).st_size == len(env.data)
    finally:
        release.set()
    await wait_event(closed)
    with pytest.raises(OSError):
        os.fstat(held["fd"])
    assert not analyses(mcase)
    assert not any(e["event"] == "allocation-window" for e in S.custody(mcase).entries())


async def test_cancel_after_commit_preserves_saved_report(mcase, tmp_path, monkeypatch):
    from forensics_mcp import server as S
    from pweh import evidence as E
    env = await prepare(mcase, tmp_path)
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
    task = asyncio.create_task(invoke(mcase, env))
    try:
        await wait_event(entered)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
    finally:
        release.set()
    await wait_event(closed)
    assert len(analyses(mcase)) == 1
    assert S.custody(mcase).entries()[-1]["event"] == "allocation-window"


async def test_postcommit_audit_failure_keeps_receipt(mcase, tmp_path, monkeypatch, caplog):
    from forensics_mcp import allocation_tools as T, server as S
    env = await prepare(mcase, tmp_path)
    def fail(*args):
        raise OSError(PRIVATE)
    monkeypatch.setattr(T, "_audit_commit", fail)
    async with Client(S.server) as client:
        result = await query(client, mcase, env)
    assert result.get("ok"), result
    assert len(analyses(mcase)) == 1 and result["warnings"]
    assert PRIVATE not in json.dumps(result) + caplog.text
