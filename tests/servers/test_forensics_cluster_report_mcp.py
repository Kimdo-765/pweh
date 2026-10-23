"""클러스터 참조 보고서의 실제 Client·같은 FD·독립 범위 추출 연결."""
from __future__ import annotations

import asyncio
import dataclasses
import hashlib
import json
import os
import stat
import threading
import time
from pathlib import Path
from types import SimpleNamespace

import pytest
from mcp import Client

from fs.builders import exfat_small, fat12_small, fat16_small, fat32_small, put_mbr
from mcp_helpers import call
from servers.test_forensics_dhav_mcp import anyio_backend, intake, mcase, record, wait_event
from servers.test_forensics_dhav_record_mcp import finished

pytestmark = pytest.mark.anyio
PRIVATE = "SYNTHETIC_CLUSTER_PRIVATE_48bc"
CLUSTER = 20


def image(kind="fat12", *, live=False, mismatch=False):
    """할당표는 같고 live 참조만 다른 입력을 독립 구성한다."""
    disk = {"fat12": fat12_small, "fat16": fat16_small,
            "fat32": fat32_small, "exfat": exfat_small}[kind]()
    disk.add_file("/" + PRIVATE + ".txt", b"ordinary data", clusters=[10])
    unit = record(payload=PRIVATE.encode())
    payload = b"prefix_" + unit
    if live:
        disk.add_file("/live.bin", payload, clusters=[CLUSTER])
    else:
        disk.reserve([CLUSTER])
        if kind != "exfat":
            disk.write_chain([CLUSTER])
        disk.write_clusters([CLUSTER], payload)
    if mismatch:
        disk.set_fat_copy(1, CLUSTER + 5, disk.eoc)
    return SimpleNamespace(data=disk.image(), disk=disk, offset=disk.coff(CLUSTER), length=disk.cs, unit=unit)


def analyses(case):
    return list((case.dir / "forensics/analysis").glob("cluster-report-*.json"))


async def prepare(case, tmp_path, kind="fat12", **kwargs):
    from forensics_mcp import server as S
    env = image(kind, **kwargs)
    path = tmp_path / (PRIVATE + ".img")
    path.write_bytes(env.data)
    async with Client(S.server) as client:
        env.ev = await intake(client, case, path)
    return env


async def invoke(case, env, **changes):
    from forensics_mcp import cluster_tools as T, server as S
    args = dict(case_id=case.id, evidence_id=env.ev, partition=1, max_seconds=45)
    args.update(changes)
    return await T._cluster_run(T._ServerAPI(vars(S)), **args)


async def query(client, case, env, **changes):
    args = dict(case_id=case.id, evidence_id=env.ev, partition=1)
    args.update(changes)
    return await call(client, "forensics_cluster_report", **args)


def accounting(report):
    """공개 관찰 수·완료도의 핵심 등식을 검증기와 별개로 확인한다."""
    c, n, g = report["coverage"], report["counts"], report["geometry"]
    assert c["allocation_clusters_examined"] == n["allocation_examined"]
    assert c["allocation_clusters_examined"] + c["allocation_clusters_unexamined"] == g["cluster_count"]
    assert c["rows_reported"] == len(report["rows"]) <= 128
    assert n["allocation_examined"] == n["allocated"] + n["free"] + (n["bad"] or 0)
    assert not c["reference_map_complete"] or c["reference_walk_complete"]
    full = all(c[k] for k in ("reference_walk_complete", "reference_map_complete", "allocation_complete", "rows_complete"))
    assert (report["status"] == "ok") is (full and c["reasons"] == [])
    if not (c["reference_map_complete"] and c["allocation_complete"]):
        assert n["allocated_without_live_reference"] is None
        assert not any(r["kind"] == "allocated-without-live-reference" for r in report["rows"])
    for r in report["rows"]:
        if r["offset"] is not None:
            assert r["offset"] == g["data_offset"] + (r["cluster"] - 2) * g["cluster_size"]
            assert r["length"] == r["clusters"] * g["cluster_size"]
    for key in ("whole_evidence_examined", "orphan_files_verified", "historical_allocation_verified",
                "file_ownership_verified", "media_decoded", "playback_verified", "payload_semantics_examined"):
        assert report[key] is False


@pytest.mark.parametrize("kind", ["fat12", "fat16", "fat32", "exfat"])
async def test_actual_source_storage_custody_and_metadata_bytes(mcase, tmp_path, monkeypatch, caplog, kind):
    from forensics_mcp import server as S
    from pweh import schemas
    from pweh.fs import cluster_report as A
    env = await prepare(mcase, tmp_path, kind)
    reads = []
    original = A.inspect_cluster_report
    def inspect(source, **kwargs):
        def read(at, count):
            assert 0 <= at <= source.size - count and 0 <= count <= 65536
            reads.append((at, count))
            return source.read(at, count)
        return original(dataclasses.replace(source, read=read), **kwargs)
    monkeypatch.setattr(A, "inspect_cluster_report", inspect)
    async with Client(S.server) as client:
        result = await query(client, mcase, env)
        assert result.get("ok"), result
        report = result["report"]
        schemas.validate("cluster-report", report)
        accounting(report)
        assert report["status"] == "ok" and report["geometry"]["fs_type"] == kind
        assert report["counts"]["allocated_without_live_reference"] == 1
        assert report["source"] == {"kind": "evidence", "evidence_id": env.ev,
            "evidence_sha256": hashlib.sha256(env.data).hexdigest(), "evidence_size": len(env.data)}
        assert report["params"] == {"partition": 1, "max_seconds": 45}
        assert sum(count for _, count in reads) == report["coverage"]["metadata_bytes_read"] <= 32 << 20
        assert all(at + count <= env.offset or at >= env.offset + env.length for at, count in reads)
        path = mcase.dir / result["analysis"]["path"]
        assert stat.S_IMODE(path.stat().st_mode) == 0o444
        assert len(path.read_bytes()) == result["analysis"]["size"] <= 1 << 20
        assert hashlib.sha256(path.read_bytes()).hexdigest() == result["analysis"]["sha256"]
        event = S.custody(mcase).entries()[-1]
        assert event["event"] == "cluster-report" and event["data"]["source"] == report["source"]
        assert PRIVATE not in json.dumps(result) + path.read_text() + json.dumps(event) + caplog.text
        listed = await call(client, "forensics_evidence_list", case_id=mcase.id, write_files=False)
        assert any(d["kind"] == "cluster-report" and d["custody"] == "recorded" for d in listed["derived"])
        tool = next(t for t in (await client.list_tools()).tools if t.name == "forensics_cluster_report")
        assert tool.annotations.read_only_hint is False
        assert set(tool.input_schema["properties"]) == {"case_id", "evidence_id", "partition", "max_seconds"}
        assert set(tool.input_schema["required"]) == {"case_id", "evidence_id", "partition"}
        assert tool.input_schema["additionalProperties"] is False


@pytest.mark.parametrize("kind", ["fat16", "exfat"])
async def test_same_allocation_but_different_live_references(mcase, tmp_path, kind):
    from forensics_mcp import server as S
    results, windows = [], []
    async with Client(S.server) as client:
        for live in (False, True):
            env = await prepare(mcase, tmp_path, kind, live=live)
            result = await query(client, mcase, env)
            assert result.get("ok"), result
            results.append(result["report"])
            window = await call(client, "forensics_allocation_window", case_id=mcase.id, evidence_id=env.ev,
                                partition=1, offset=env.offset, length=env.length)
            assert window.get("ok"), window
            windows.append(window["report"]["rows"])
    assert windows[0] == windows[1]
    assert [r["counts"]["allocated_without_live_reference"] for r in results] == [1, 0]
    assert all(r["status"] == "ok" for r in results)


async def test_report_summary_and_independent_range_record_extraction(mcase, tmp_path):
    from case_mcp import server as C
    from forensics_mcp import server as S
    from core.test_sd_cluster_summary import summary
    env = await prepare(mcase, tmp_path)
    async with Client(S.server) as client, Client(C.server) as cc:
        result = await query(client, mcase, env)
        assert result.get("ok"), result
        row, = [r for r in result["report"]["rows"] if r["kind"] == "allocated-without-live-reference"]
        assert row["offset"] == env.offset and row["length"] == env.length
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
        assert [e["event"] for e in S.custody(mcase).entries()][-3:] == ["cluster-report", "dhav-candidates", "extract"]
        data = summary()
        data["evidence"][0].update(evidence_id=env.ev, sha256=hashlib.sha256(env.data).hexdigest())
        coverage = result["report"]["coverage"]
        data["cluster_report_results"] = [{"evidence_id": env.ev, "analysis_path": result["analysis"]["path"],
            "sha256": result["analysis"]["sha256"], "status": result["report"]["status"],
            "reference_map_complete": coverage["reference_map_complete"], "allocation_complete": coverage["allocation_complete"]}]
        stored = await call(cc, "case_record_step", case_id=mcase.id, skill="sd-card-forensics", step="summary",
                            status="success", summary="합성 live 참조 검사", data=data, artifacts=[result["analysis"]["path"]])
        assert stored.get("ok"), stored
        got = await call(cc, "case_get_step_results", case_id=mcase.id)
        assert got["summaries"]["sd-card-forensics"]["data"] == data
        final = await call(cc, "report_generate", case_id=mcase.id)
        assert final.get("ok") and result["analysis"]["path"] in Path(final["path"]).read_text(), final


async def test_incomplete_allocation_is_not_orphan_evidence(mcase, tmp_path):
    from forensics_mcp import server as S
    env = await prepare(mcase, tmp_path, "fat16", mismatch=True)
    async with Client(S.server) as client:
        result = await query(client, mcase, env)
    assert result.get("ok"), result
    accounting(result["report"])
    assert result["report"]["status"] == "partial"
    assert result["report"]["counts"]["allocated_without_live_reference"] is None
    assert result["report"]["coverage"]["allocation_complete"] is False


@pytest.mark.parametrize("field,value", [
    ("partition", True), ("partition", 1.0), ("partition", PRIVATE),
    ("max_seconds", True), ("max_seconds", PRIVATE),
    ("case_id", {"private": PRIVATE}), ("evidence_id", {"private": PRIVATE}),
    (PRIVATE, {PRIVATE: PRIVATE}),
])
async def test_sdk_private_input_is_hidden_before_case_lookup(field, value, monkeypatch, caplog):
    from forensics_mcp import server as S
    async def forbidden(*args, **kwargs):
        pytest.fail("SDK 거부 입력이 케이스에 도달했습니다.")
    monkeypatch.setattr(S, "_case", forbidden)
    args = dict(case_id="synthetic", evidence_id="EV-0001", partition=1)
    args[field] = value
    async with Client(S.server) as client:
        result = await call(client, "forensics_cluster_report", **args)
    assert "validation_failed" in result.get("_error", ""), result
    assert PRIVATE not in json.dumps(result) + caplog.text


@pytest.mark.parametrize("changes", [
    {"partition": 0}, {"partition": 4097}, {"max_seconds": 0}, {"max_seconds": -1},
    {"max_seconds": 46}, {"evidence_id": PRIVATE}, {"evidence_id": "EV-0001\n"}, {"case_id": "../" + PRIVATE},
])
async def test_invalid_bounds_are_fixed_before_case_lookup(changes, monkeypatch, caplog):
    from forensics_mcp import server as S
    async def forbidden(*args, **kwargs):
        pytest.fail("범위 밖 입력이 케이스에 도달했습니다.")
    monkeypatch.setattr(S, "_case", forbidden)
    args = dict(case_id="synthetic", evidence_id="EV-0001", partition=1)
    args.update(changes)
    async with Client(S.server) as client:
        result = await call(client, "forensics_cluster_report", **args)
    assert "validation_failed" in result.get("_error", "")
    assert PRIVATE not in json.dumps(result) + caplog.text


@pytest.mark.parametrize("seconds", [float("nan"), float("inf"), 10 ** 400])
async def test_direct_nonfinite_time_is_fixed(seconds):
    from forensics_mcp.cluster_tools import _arguments
    from pweh.errors import ValidationFailed
    with pytest.raises(ValidationFailed):
        _arguments("synthetic", "EV-0001", 1, seconds)


@pytest.mark.parametrize("failure", ["missing", "rebuild", "schema"])
async def test_sdk_configuration_failure_does_not_register_success(failure):
    from forensics_mcp.cluster_tools import register_cluster_tools
    def fail(**kwargs):
        raise RuntimeError(PRIVATE)
    model = SimpleNamespace(model_config={}, model_rebuild=fail if failure == "rebuild" else lambda **kw: None,
                            model_json_schema=fail)
    old = SimpleNamespace(arg_model=model, output_schema=None, output_model=None, wrap_output=False)
    registered = None if failure == "missing" else SimpleNamespace(fn_metadata=old)
    server = SimpleNamespace(tool=lambda **kwargs: lambda fn: fn,
                             _tool_manager=SimpleNamespace(get_tool=lambda name: registered))
    with pytest.raises(RuntimeError) as error:
        register_cluster_tools(server, {})
    assert PRIVATE not in str(error.value) and error.value.__suppress_context__


@pytest.mark.parametrize("fault", ["raw", "count", "bool"])
async def test_invalid_core_report_is_not_committed(mcase, tmp_path, monkeypatch, caplog, fault):
    from forensics_mcp import server as S
    from pweh.fs import cluster_report as A
    env = await prepare(mcase, tmp_path)
    original = A.inspect_cluster_report
    def inspect(*args, **kwargs):
        report = original(*args, **kwargs)
        if fault == "raw":
            report[PRIVATE] = PRIVATE
        elif fault == "count":
            report["counts"]["allocation_examined"] += 1
        else:
            report["geometry"]["cluster_count"] = True
        return report
    monkeypatch.setattr(A, "inspect_cluster_report", inspect)
    async with Client(S.server) as client:
        result = await query(client, mcase, env)
    assert "_error" in result and not analyses(mcase), result
    assert PRIVATE not in json.dumps(result) + caplog.text


@pytest.mark.parametrize("fault", ["short", "raised", "mutate", "cancel"])
@pytest.mark.parametrize("swallow", [False, True, "partial"])
async def test_leaf_original_error_wins_even_if_core_returns_success(mcase, tmp_path, monkeypatch, caplog, fault, swallow):
    from forensics_mcp import cluster_tools as T, server as S
    from pweh.fs import cluster_report as A
    env = await prepare(mcase, tmp_path)
    with S._open_evidence_sync(mcase, env.ev) as opened:
        path = mcase.dir / opened.intake["stored_path"]
    active = threading.local()
    original_pread, original = os.pread, A.inspect_cluster_report
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
            kwargs["limits"] = dataclasses.replace(kwargs["limits"], scan_clusters=1)
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
    monkeypatch.setattr(A, "inspect_cluster_report", inspect)
    async with Client(S.server) as client:
        result = await query(client, mcase, env)
    code = "integrity_failed" if fault == "mutate" else "cancelled" if fault == "cancel" else "cluster_read_failed"
    assert code in result.get("_error", ""), result
    assert not analyses(mcase) and PRIVATE not in json.dumps(result) + caplog.text
    if fault == "mutate":
        assert S.custody(mcase).entries()[-1]["event"] == "integrity-failed"


@pytest.mark.parametrize("fault", ["same_inode", "replacement", "hardlink"])
async def test_final_source_seal_rejects_changes_after_core(mcase, tmp_path, monkeypatch, fault):
    from forensics_mcp import server as S
    from pweh.fs import cluster_report as A
    env = await prepare(mcase, tmp_path)
    with S._open_evidence_sync(mcase, env.ev) as opened:
        path = mcase.dir / opened.intake["stored_path"]
    original = A.inspect_cluster_report
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
    monkeypatch.setattr(A, "inspect_cluster_report", inspect)
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
    assert not any(e["event"] == "cluster-report" for e in S.custody(mcase).entries())


@pytest.mark.parametrize("stage", ["read", "final_output"])
async def test_raw_cancel_retains_fd_until_worker_and_commits_nothing(mcase, tmp_path, monkeypatch, stage):
    from forensics_mcp import cluster_tools as T, server as S
    from pweh import evidence as E
    from pweh.fs import cluster_report as A
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
        original = A.inspect_cluster_report
        def inspect(source, **kwargs):
            def read(at, count):
                entered.set()
                assert release.wait(5)
                return source.read(at, count)
            return original(dataclasses.replace(source, read=read), **kwargs)
        monkeypatch.setattr(A, "inspect_cluster_report", inspect)
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
    assert not any(e["event"] == "cluster-report" for e in S.custody(mcase).entries())


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
    assert S.custody(mcase).entries()[-1]["event"] == "cluster-report"


async def test_postcommit_audit_failure_keeps_receipt(mcase, tmp_path, monkeypatch, caplog):
    from forensics_mcp import cluster_tools as T, server as S
    env = await prepare(mcase, tmp_path)
    def fail(*args):
        raise OSError(PRIVATE)
    monkeypatch.setattr(T, "_audit_commit", fail)
    async with Client(S.server) as client:
        result = await query(client, mcase, env)
    assert result.get("ok"), result
    assert len(analyses(mcase)) == 1 and result["warnings"]
    assert PRIVATE not in json.dumps(result) + caplog.text


@pytest.mark.parametrize("when", ["before_geometry", "after_geometry"])
async def test_same_deadline_fatal_before_geometry_and_stored_partial_after(mcase, tmp_path, monkeypatch, when):
    from forensics_mcp import cluster_tools as T, server as S
    from pweh.fs import cluster_report as A
    from pweh.fs.fat import FatVolume
    env = await prepare(mcase, tmp_path)
    original, original_cluster = A.inspect_cluster_report, FatVolume.cluster_report
    now = [time.monotonic()]
    monkeypatch.setattr(T, "time", SimpleNamespace(monotonic=lambda: now[0]))
    if when == "after_geometry":
        def expired(vol, **kw):
            kw["budget"].deadline = time.monotonic() - 1
            return original_cluster(vol, **kw)
        monkeypatch.setattr(FatVolume, "cluster_report", expired)
    def inspect(source, **kw):
        end = kw["deadline"]
        if when == "before_geometry":
            kw["deadline"] = time.monotonic() - 1
        report = original(source, **kw)
        now[0] = end + 1
        return report
    monkeypatch.setattr(A, "inspect_cluster_report", inspect)
    async with Client(S.server) as client:
        result = await query(client, mcase, env)
    if when == "before_geometry":
        assert "time_limit" in result.get("_error", "") and not analyses(mcase), result
    else:
        assert result.get("ok"), result
        accounting(result["report"])
        assert result["report"]["status"] == "partial"
        assert "time_limit" in result["report"]["coverage"]["reasons"]
        assert result["report"]["counts"]["allocated_without_live_reference"] is None


async def test_async_case_time_is_included_without_new_worker_deadline(mcase, tmp_path, monkeypatch):
    from forensics_mcp import cluster_tools as T, server as S
    from pweh.fs import cluster_report as A
    env = await prepare(mcase, tmp_path)
    now = [time.monotonic()]
    start = now[0]
    original_case = S._case
    async def case(case_id):
        value = await original_case(case_id)
        now[0] = start + 46
        return value
    monkeypatch.setattr(T, "time", SimpleNamespace(monotonic=lambda: now[0]))
    monkeypatch.setattr(S, "_case", case)
    monkeypatch.setattr(A, "inspect_cluster_report", lambda *a, **kw: pytest.fail("만료 후 코어에 도달했습니다."))
    async with Client(S.server) as client:
        result = await query(client, mcase, env)
    assert "time_limit" in result.get("_error", "") and not analyses(mcase), result


async def test_first_read_error_is_not_replaced_by_later_cancel(mcase, tmp_path, monkeypatch, caplog):
    from forensics_mcp import cluster_tools as T, server as S
    from pweh.fs import cluster_report as A
    env = await prepare(mcase, tmp_path)
    active = threading.local()
    pread, original = os.pread, A.inspect_cluster_report
    def fail(fd, count, at):
        if getattr(active, "fault", False):
            raise OSError(PRIVATE)
        return pread(fd, count, at)
    def inspect(source, **kw):
        report = original(source, **kw)
        active.fault = True
        try:
            with pytest.raises(Exception):
                source.read(0, 1)
            kw["cancel"].__self__.set()
            with pytest.raises(Exception):
                source.read(0, 1)
            return report
        finally:
            active.fault = False
    monkeypatch.setattr(T.os, "pread", fail)
    monkeypatch.setattr(A, "inspect_cluster_report", inspect)
    async with Client(S.server) as client:
        result = await query(client, mcase, env)
    assert "cluster_read_failed" in result.get("_error", "") and "cancelled" not in result["_error"]
    assert PRIVATE not in json.dumps(result) + caplog.text and not analyses(mcase)


@pytest.mark.parametrize("code,expected", [
    ("cluster_report_invalid", "validation_failed"), ("cluster_report_unsupported", "unsupported_fs"),
    ("partition_unavailable", "partition_unavailable"), ("cluster_read_failed", "cluster_read_failed"),
    ("cluster_report_failed", "cluster_report_failed"), ("time_limit", "time_limit"),
    ("cancelled", "cancelled"), ("unexpected", "cluster_report_failed"),
])
async def test_core_errors_are_fixed_without_fs_diagnostics(mcase, tmp_path, monkeypatch, caplog, code, expected):
    from forensics_mcp import server as S
    from pweh.errors import PwehError
    from pweh.fs import cluster_report as A
    env = await prepare(mcase, tmp_path)
    def fail(*a, **kw):
        raise PwehError(PRIVATE, code=code, data={PRIVATE: PRIVATE}, hint=PRIVATE)
    monkeypatch.setattr(A, "inspect_cluster_report", fail)
    async with Client(S.server) as client:
        result = await query(client, mcase, env)
    assert expected in result.get("_error", ""), result
    assert PRIVATE not in json.dumps(result) + caplog.text and not analyses(mcase)


async def test_missing_partition_and_unsupported_filesystem_do_not_publish(mcase, tmp_path):
    from forensics_mcp import server as S
    env = await prepare(mcase, tmp_path)
    async with Client(S.server) as client:
        missing = await query(client, mcase, env, partition=4096)
        assert "partition_unavailable" in missing.get("_error", ""), missing
        path = tmp_path / "opaque.img"
        opaque = bytearray(1024)
        put_mbr(opaque, [(0x83, 1, 1)])
        path.write_bytes(opaque)
        evidence_id = await intake(client, mcase, path)
        unsupported = await call(client, "forensics_cluster_report", case_id=mcase.id,
                                 evidence_id=evidence_id, partition=1)
    assert "unsupported_fs" in unsupported.get("_error", ""), unsupported
    assert not analyses(mcase)
