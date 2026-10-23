"""미디어 단위 stream의 실제 MCP·재검증·추출과 FD/커밋 수명 경계."""

from __future__ import annotations

import asyncio
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

from mcp_helpers import call
from servers.test_forensics_media_candidates_mcp import wait_event
from servers.test_forensics_media_unit_mcp import anyio_backend, intake, mcase, units
from servers.test_forensics_media_unit_extract_mcp import finished

pytestmark = pytest.mark.anyio
PRIVATE = "SYNTHETIC_MEDIA_UNIT_SCAN_PRIVATE_4d27"
FORMATS = ("jpeg", "avc-annexb", "mpeg2-ps", "xm")
UNIT = b"\0\0\1\xfd" + len(PRIVATE).to_bytes(4, "little") + PRIVATE.encode()
DATA = b"xxxxxxx" + UNIT


def analyses(case):
    return list((case.dir / "forensics/analysis").glob("media-unit-scan-*.json"))


async def prepare(case, tmp_path, data=DATA):
    from forensics_mcp import server as S
    source = tmp_path / (PRIVATE + ".bin")
    source.write_bytes(data)
    async with Client(S.server) as client:
        return await intake(client, case, source)


async def query(client, case, ev, **changes):
    return await call(client, "forensics_media_unit_scan", **{
        "case_id": case.id, "evidence_id": ev, "format": "xm", **changes})


async def invoke(case, ev, **changes):
    from forensics_mcp import media_unit_scan_tools as T, server as S
    return await T._media_unit_scan_run(T._ServerAPI(vars(S)), **{
        "case_id": case.id, "evidence_id": ev, "format": "xm", "start_offset": 0,
        "max_scan_bytes": 1 << 30, "max_seconds": 45, **changes})


def accounting(report, size, start=0):
    """실제 adapter 봉투의 좌표·물리 읽기 합과 false 주장을 독립 확인한다."""
    c, s = report["coverage"], report["summary"]
    total = max(0, size - {"jpeg": 2, "avc-annexb": 3, "mpeg2-ps": 4, "xm": 3}[report["format"]] + 1)
    rest = c["unexamined_positions"]
    assert c["evidence_size"] == size and c["search_positions_total"] == total
    assert c["positions_before_start"] == min(start, total)
    assert c["positions_before_start"] + c["search_positions_examined"] + (rest["count"] if rest else 0) == total
    assert c["next_offset"] == (rest["start"] if rest else None)
    assert c["search_complete"] is (rest is None)
    assert c["whole_evidence_search_complete"] is (start == 0 and rest is None)
    assert c["total_bytes_read"] == c["search_bytes_read"] + c["structure_bytes_read"]
    assert c["search_bytes_read"] <= report["params"]["max_scan_bytes"]
    assert c["structure_bytes_read"] <= 128 << 20 and c["structure_work_bytes"] <= 128 << 20
    assert s["candidates_reported"] == s["closed_candidates"] + s["prefix_candidates"] == len(report["candidates"])
    assert s["anchors_observed"] == sum(s[key] for key in (
        "anchors_rejected", "unsupported_anchors", "incomplete_anchors", "selection_limited_anchors",
        "candidates_reported")) + int(c["pending_anchor_offset"] is not None)
    for field in ("media_decoded", "playback_verified", "recording_time_verified", "encryption_assessed",
                  "format_conformance_assessed", "original_file_boundary_verified", "complete_recording",
                  "payload_semantics_examined", "physical_carving_performed"):
        assert report[field] is False
    for row in report["candidates"]:
        assert row["selection_offset"] == row["offset"]
        assert 0 < row["length"] <= row["selection_length"] <= 64 << 20
        assert row["offset"] + row["selection_length"] <= size
        assert row["confidence"] == "possible"


def matching_row(scan, ranged):
    """stream 행 번호를 재사용하지 않고 새 선택의 좌표와 경계 의미로 찾는다."""
    source = ranged["source"]
    matches = [row for row in ranged["candidates"]
               if source["offset"] + row["offset"] == scan["offset"]
               and all(row[key] == scan[key] for key in (
                   "length", "format", "unit", "unit_subtype", "boundary_kind", "framing_status"))
               and row["end_reason"] == ("selection_end" if scan["end_reason"] == "evidence_end" else scan["end_reason"])]
    assert len(matches) == 1, (scan, ranged)
    return matches[0]


async def extract_row(client, case, ev, scan, expected):
    ranged = await call(client, "forensics_media_unit_candidates", case_id=case.id, evidence_id=ev,
                        format=scan["format"], offset=scan["selection_offset"], length=scan["selection_length"])
    assert ranged.get("ok"), ranged
    report = ranged["report"]
    assert len(report["source"]) == 18 and report["source"]["method"] == "byte-range"
    match = matching_row(scan, report)
    job = await finished(client, await call(client, "forensics_extract_media_unit", case_id=case.id,
                         evidence_id=ev, analysis_path=ranged["analysis"]["path"], candidate_index=match["index"]))
    assert job["status"] == "succeeded", job
    receipt = job["result"]
    assert (case.dir / receipt["output_dir"] / "unit-000.bin").read_bytes() == expected
    manifest = json.loads((case.dir / receipt["manifest"]).read_bytes())
    assert manifest["files"][0]["size"] == len(expected)
    assert manifest["files"][0]["sha256"] == hashlib.sha256(expected).hexdigest()
    assert manifest["source"] == report["source"]
    return ranged, match


async def test_actual_client_metadata_source_privacy_and_tool_contract(mcase, tmp_path, caplog):
    from forensics_mcp import server as S
    from pweh import schemas
    ev = await prepare(mcase, tmp_path)
    async with Client(S.server) as client:
        before = len(S.custody(mcase).entries())
        result = await query(client, mcase, ev)
        assert result.get("ok"), result
        report = result["report"]
        schemas.validate("media-unit-scan", report)
        assert report["schema"] == "pweh.media-unit-scan/v1" and report["status"] == "ok"
        assert report["profile"] == "xm-length-delimited-frame-stream-v1"
        assert report["source"] == {"kind": "evidence", "evidence_id": ev,
                                    "evidence_sha256": hashlib.sha256(DATA).hexdigest(), "evidence_size": len(DATA)}
        assert report["params"] == {"format": "xm", "start_offset": 0, "max_scan_bytes": 1 << 30, "max_seconds": 45}
        accounting(report, len(DATA))
        saved = mcase.dir / result["analysis"]["path"]
        assert stat.S_IMODE(saved.stat().st_mode) == 0o444
        assert hashlib.sha256(saved.read_bytes()).hexdigest() == result["analysis"]["sha256"]
        events = S.custody(mcase).entries()[before:]
        assert [e["event"] for e in events] == ["media-unit-scan"]
        assert events[0]["data"]["source"] == report["source"]
        visible = json.dumps(result) + saved.read_text() + json.dumps(events) + caplog.text
        assert PRIVATE not in visible and str(tmp_path) not in visible
        tool = next(t for t in (await client.list_tools()).tools if t.name == "forensics_media_unit_scan")
        assert tool.annotations.read_only_hint is False
        assert set(tool.input_schema["properties"]) == {
            "case_id", "evidence_id", "format", "start_offset", "max_scan_bytes", "max_seconds"}
        assert set(tool.input_schema["required"]) == {"case_id", "evidence_id", "format"}
        assert tool.input_schema["additionalProperties"] is False
        assert tool.input_schema["properties"]["start_offset"]["default"] == 0
        assert not list((mcase.dir / "forensics/recovered").glob("**/*"))


@pytest.mark.parametrize("format", FORMATS)
async def test_large_ev_boundary_witness_range_and_existing_extraction(mcase, tmp_path, monkeypatch, format):
    from forensics_mcp import server as S
    from pweh import media_unit_stream as U
    selected, expected = units()[format]
    size, offset = (64 << 20) + 8192, 65535
    search_limit = offset + 4
    source = tmp_path / "synthetic-large-unit.bin"
    with source.open("wb") as stream:
        stream.truncate(size)
        stream.seek(offset - 1)
        stream.write(b"X" + selected)
    reads = []
    original = U.scan_media_unit_stream
    def scan(read_at, **kwargs):
        def observed(at, length):
            assert type(at) is int and type(length) is int
            assert 1 <= length <= 65536 and 0 <= at <= size - length
            reads.append((at, length))
            return read_at(at, length)
        return original(observed, **kwargs)
    monkeypatch.setattr(U, "scan_media_unit_stream", scan)
    async with Client(S.server) as client:
        ev = await intake(client, mcase, source)
        result = await query(client, mcase, ev, format=format, max_scan_bytes=search_limit)
        assert result.get("ok"), result
        report = result["report"]
        scan, = [row for row in report["candidates"] if row["offset"] == offset]
        assert scan["length"] == len(expected) and scan["selection_length"] == len(selected)
        assert scan["offset"] + scan["selection_length"] > search_limit
        assert any(at + length > search_limit for at, length in reads)
        assert sum(length for _, length in reads) == report["coverage"]["total_bytes_read"]
        assert report["coverage"]["search_bytes_read"] == search_limit
        assert report["status"] == "partial"
        accounting(report, size)
        rejected = await call(client, "forensics_extract_media_unit", case_id=mcase.id, evidence_id=ev,
                              analysis_path=result["analysis"]["path"], candidate_index=scan["index"])
        assert "_error" in rejected and "job_id" not in rejected
        ranged, _ = await extract_row(client, mcase, ev, scan, expected)
        assert ranged["report"]["source"]["selected_sha256"] == hashlib.sha256(selected).hexdigest()
        if format == "avc-annexb":
            assert (scan["length"], scan["selection_length"]) == (4, 8)
            assert ranged["report"]["status"] == "partial"
        assert [e["event"] for e in S.custody(mcase).entries()][-3:] == ["media-unit-scan", "media-unit-candidates", "extract"]
        listed = await call(client, "forensics_evidence_list", case_id=mcase.id, write_files=False)
        assert len(listed["derived"]) == 3 and all(x["custody"] == "recorded" for x in listed["derived"])


async def test_stream_index_is_reselected_and_actual_summary_report_roundtrip(mcase, tmp_path):
    from case_mcp import server as C
    from forensics_mcp import server as S
    from core.test_sd_media_unit_summary import summary
    ev = await prepare(mcase, tmp_path, DATA + UNIT)
    async with Client(S.server) as client, Client(C.server) as cc:
        result = await query(client, mcase, ev)
        assert result.get("ok"), result
        scan = result["report"]["candidates"][1]
        assert scan["index"] == 1
        _, match = await extract_row(client, mcase, ev, scan, UNIT)
        assert match["index"] == 0
        data = summary()
        data["media_unit_scan_results"] = [{"evidence_id": ev, "analysis_path": result["analysis"]["path"],
            "sha256": result["analysis"]["sha256"], "status": result["report"]["status"],
            "format": result["report"]["format"], "candidates_reported": result["report"]["summary"]["candidates_reported"]}]
        stored = await call(cc, "case_record_step", case_id=mcase.id, skill="sd-card-forensics", step="summary",
                            status="success", summary="합성 미디어 단위 검색", data=data, artifacts=[result["analysis"]["path"]])
        assert stored.get("ok"), stored
        got = await call(cc, "case_get_step_results", case_id=mcase.id)
        assert got["summaries"]["sd-card-forensics"]["data"] == data
        final = await call(cc, "report_generate", case_id=mcase.id)
        assert final.get("ok") and result["analysis"]["path"] in Path(final["path"]).read_text(), final


@pytest.mark.parametrize("tail,reason", [(b"", "evidence_end"), (b"X", "truncated_packet"),
                                         (b"XY", "truncated_packet"), (b"XYZ", "truncated_packet")])
async def test_ps_evidence_end_partial_keeps_witness_and_prefix(mcase, tmp_path, tail, reason):
    from forensics_mcp import server as S
    expected = units()["mpeg2-ps"][1]
    data = b"prefix" + expected + tail
    ev = await prepare(mcase, tmp_path, data)
    async with Client(S.server) as client:
        result = await query(client, mcase, ev, format="mpeg2-ps")
        assert result.get("ok"), result
        scan, = result["report"]["candidates"]
        assert scan["end_reason"] == reason and scan["framing_status"] == "prefix"
        assert scan["selection_length"] == len(expected) + len(tail)
        assert result["report"]["status"] == "partial"
        ranged, _ = await extract_row(client, mcase, ev, scan, expected)
        assert ranged["report"]["status"] == "partial"


@pytest.mark.parametrize("format", FORMATS)
@pytest.mark.parametrize("data", [b"X", b"xxxxxxx"])
async def test_short_anchor_free_and_eof_are_complete_unsupported(mcase, tmp_path, format, data):
    from forensics_mcp import server as S
    ev = await prepare(mcase, tmp_path, data)
    async with Client(S.server) as client:
        for start in (0, len(data)):
            result = await query(client, mcase, ev, format=format, start_offset=start)
            assert result.get("ok"), result
            report = result["report"]
            accounting(report, len(data), start)
            assert report["status"] == "unsupported" and report["candidates"] == []
            if start == len(data):
                assert report["coverage"]["total_bytes_read"] == 0


async def test_small_search_budget_resumes_without_missing_or_duplicate_units(mcase, tmp_path):
    from forensics_mcp import server as S
    selected = units()["xm"][0]
    data = b"xxxxx" + selected * 2
    ev = await prepare(mcase, tmp_path, data)
    offset, found = 0, []
    async with Client(S.server) as client:
        for _ in range(len(data)):
            result = await query(client, mcase, ev, start_offset=offset, max_scan_bytes=7)
            assert result.get("ok"), result
            report = result["report"]
            accounting(report, len(data), offset)
            found.extend(row["offset"] for row in report["candidates"])
            resume = report["coverage"]["next_offset"]
            if resume is None:
                break
            assert resume > offset
            offset = resume
        else:
            pytest.fail("유한 검색 재개가 끝나지 않았습니다.")
    assert found == [5, 5 + len(selected)]


@pytest.mark.parametrize("field,value", [
    ("case_id", {"secret": PRIVATE}), ("evidence_id", [PRIVATE]), ("format", 1), ("format", {PRIVATE: 1}),
    ("start_offset", "0"), ("start_offset", True), ("start_offset", 0.0),
    ("max_scan_bytes", "4"), ("max_scan_bytes", False), ("max_scan_bytes", 4.0),
    ("max_seconds", "45"), ("max_seconds", True), (PRIVATE, PRIVATE),
])
async def test_strict_sdk_root_error_has_no_input_or_extra_key(field, value, monkeypatch, caplog):
    from forensics_mcp import server as S
    async def forbidden(*args, **kwargs):
        pytest.fail("SDK 거부 인자가 케이스에 도달했습니다.")
    monkeypatch.setattr(S, "_case", forbidden)
    args = {"case_id": "synthetic", "evidence_id": "EV-0001", "format": "xm", field: value}
    async with Client(S.server) as client:
        result = await client.call_tool("forensics_media_unit_scan", args)
    assert result.is_error and "validation_failed" in result.model_dump_json()
    assert PRIVATE not in result.model_dump_json() + caplog.text
    metadata = S.server._tool_manager.get_tool("forensics_media_unit_scan").fn_metadata
    from pydantic import ValidationError
    with pytest.raises(ValidationError) as error:
        metadata.validate_arguments(args)
    assert error.value.errors(include_input=False)[0]["loc"] == ()


@pytest.mark.parametrize("changes", [
    {"case_id": "../" + PRIVATE}, {"evidence_id": "EV-0001\n"}, {"format": "auto"}, {"format": "JPEG"},
    {"format": "xm\n"}, {"start_offset": -1}, {"start_offset": 1 << 63}, {"max_scan_bytes": 0},
    {"max_scan_bytes": 3}, {"max_scan_bytes": (1 << 30) + 1}, {"max_seconds": 0}, {"max_seconds": 46},
    {"max_seconds": -1}, {"max_seconds": 10**300},
])
async def test_invalid_values_fail_before_case_lookup(changes, monkeypatch, caplog):
    from forensics_mcp import server as S
    async def forbidden(*args, **kwargs):
        pytest.fail("범위 밖 인자가 케이스에 도달했습니다.")
    monkeypatch.setattr(S, "_case", forbidden)
    args = {"case_id": "synthetic", "evidence_id": "EV-0001", "format": "xm", **changes}
    async with Client(S.server) as client:
        result = await client.call_tool("forensics_media_unit_scan", args)
    assert result.is_error and "validation_failed" in result.model_dump_json()
    assert PRIVATE not in result.model_dump_json() + caplog.text


@pytest.mark.parametrize("missing", ["case_id", "evidence_id", "format"])
async def test_missing_required_input_is_private(missing, monkeypatch):
    from forensics_mcp import server as S
    async def forbidden(*args, **kwargs):
        pytest.fail("누락 인자가 케이스에 도달했습니다.")
    monkeypatch.setattr(S, "_case", forbidden)
    args = {"case_id": PRIVATE, "evidence_id": "EV-0001", "format": "xm"}
    del args[missing]
    async with Client(S.server) as client:
        result = await client.call_tool("forensics_media_unit_scan", args)
    assert result.is_error and PRIVATE not in result.model_dump_json()


@pytest.mark.parametrize("failure", ["missing", "rebuild"])
async def test_sdk_configuration_failure_is_closed(failure):
    from forensics_mcp.media_unit_scan_tools import register_media_unit_scan_tools
    def rebuild(**kwargs):
        raise RuntimeError(PRIVATE)
    model = SimpleNamespace(model_config={}, model_rebuild=rebuild)
    registered = None if failure == "missing" else SimpleNamespace(fn_metadata=SimpleNamespace(arg_model=model))
    server = SimpleNamespace(tool=lambda **kwargs: lambda fn: fn,
                             _tool_manager=SimpleNamespace(get_tool=lambda name: registered))
    with pytest.raises(RuntimeError) as error:
        register_media_unit_scan_tools(server, {})
    assert PRIVATE not in str(error.value) and error.value.__suppress_context__ is True


async def test_actual_size_rejects_outside_start_without_report(mcase, tmp_path):
    from forensics_mcp import server as S
    ev = await prepare(mcase, tmp_path)
    async with Client(S.server) as client:
        result = await query(client, mcase, ev, start_offset=len(DATA) + 1)
    assert "validation_failed" in result.get("_error", "") and not analyses(mcase)


async def test_preparation_deadline_is_not_restarted_after_case_lookup(mcase, tmp_path, monkeypatch):
    from forensics_mcp import media_unit_scan_tools as T, server as S
    ev = await prepare(mcase, tmp_path)
    now = [time.monotonic()]
    original = S._case
    async def delayed(*args, **kwargs):
        case = await original(*args, **kwargs)
        now[0] += 46
        return case
    monkeypatch.setattr(T, "time", SimpleNamespace(monotonic=lambda: now[0]))
    monkeypatch.setattr(S, "_case", delayed)
    async with Client(S.server) as client:
        result = await query(client, mcase, ev)
    assert "time_limit" in result.get("_error", "") and not analyses(mcase)


async def test_core_time_partial_survives_expired_outer_end(mcase, tmp_path, monkeypatch):
    from forensics_mcp import media_unit_scan_tools as T, server as S
    from pweh import media_unit_stream as U
    ev = await prepare(mcase, tmp_path)
    now = [time.monotonic()]
    monkeypatch.setattr(T, "time", SimpleNamespace(monotonic=lambda: now[0]))
    original = U.scan_media_unit_stream
    def scan(*args, **kwargs):
        original_end = kwargs["deadline"]
        kwargs["deadline"] = time.monotonic() - 1
        result = original(*args, **kwargs)
        now[0] = original_end + 1
        return result
    monkeypatch.setattr(U, "scan_media_unit_stream", scan)
    async with Client(S.server) as client:
        result = await query(client, mcase, ev)
    assert result.get("ok"), result
    report = result["report"]
    accounting(report, len(DATA))
    assert report["status"] == "partial" and report["coverage"]["reasons"] == ["time_limit"]
    assert report["coverage"]["total_bytes_read"] == 0 and report["coverage"]["next_offset"] == 0
    assert len(analyses(mcase)) == 1


@pytest.mark.parametrize("fault", ["raw", "count", "size", "start", "budget", "format", "profile", "selection"])
async def test_malformed_core_output_never_publishes(mcase, tmp_path, monkeypatch, caplog, fault):
    from forensics_mcp import server as S
    from pweh import media_unit_stream as U
    ev = await prepare(mcase, tmp_path)
    original = U.scan_media_unit_stream
    def scan(*args, **kwargs):
        result = original(*args, **kwargs)
        if fault == "raw":
            result["payload"] = PRIVATE
        elif fault == "count":
            result["summary"]["candidates_reported"] += 1
        elif fault in ("size", "start", "budget"):
            result["coverage"][{"size": "evidence_size", "start": "start_offset", "budget": "max_scan_bytes"}[fault]] += 1
        elif fault in ("format", "profile"):
            result[fault] = "jpeg" if fault == "format" else "xm-length-delimited-frame-v1"
        else:
            result["candidates"][0]["selection_length"] -= 1
        return result
    monkeypatch.setattr(U, "scan_media_unit_stream", scan)
    async with Client(S.server) as client:
        result = await query(client, mcase, ev)
    assert "_error" in result and not analyses(mcase)
    assert PRIVATE not in json.dumps(result) + caplog.text


@pytest.mark.parametrize("fault", ["source", "params", "type", "profile"])
async def test_validated_report_is_bound_to_actual_inputs(mcase, tmp_path, monkeypatch, fault):
    from forensics_mcp import server as S
    from pweh import media_unit_stream as U
    ev = await prepare(mcase, tmp_path)
    original = U.validate_media_unit_scan_accounting
    def validate(report):
        original(report)
        if fault == "source":
            report["source"]["evidence_sha256"] = "a" * 64
        elif fault == "params":
            report["params"]["max_scan_bytes"] -= 1
        elif fault == "type":
            report["params"]["start_offset"] = False
        else:
            report["profile"] = "xm-length-delimited-frame-v1"
    monkeypatch.setattr(U, "validate_media_unit_scan_accounting", validate)
    async with Client(S.server) as client:
        result = await query(client, mcase, ev)
    assert "validation_failed" in result.get("_error", "") and not analyses(mcase)


async def test_final_serialization_enforces_envelope_cap(mcase, tmp_path, monkeypatch):
    from forensics_mcp import media_unit_scan_tools as T, server as S
    from pweh import media_unit_stream as U
    ev = await prepare(mcase, tmp_path)
    original = U.validate_media_unit_scan_accounting
    def validate(report):
        original(report)
        # 입구의 최종 직렬화 상한은 schema/core 상한과 독립이다.
        monkeypatch.setattr(T, "MAX_REPORT_BYTES", 1)
    monkeypatch.setattr(U, "validate_media_unit_scan_accounting", validate)
    async with Client(S.server) as client:
        result = await query(client, mcase, ev)
    assert "validation_failed" in result.get("_error", "") and not analyses(mcase)


@pytest.mark.parametrize("behavior", ["raises", "returns", "partial"])
@pytest.mark.parametrize("fault", ["raised", "short", "type", "cancel", "integrity", "unrecorded_integrity"])
async def test_first_leaf_failure_survives_core_exception_or_result(mcase, tmp_path, monkeypatch, caplog, behavior, fault):
    from forensics_mcp import media_unit_scan_tools as T, server as S
    from pweh import evidence as E, media_unit_stream as U
    from pweh.errors import PwehError
    ev = await prepare(mcase, tmp_path)
    active = threading.local()
    preads = []
    original_scan, original_pread, original_check = U.scan_media_unit_stream, os.pread, T._check_opened
    def pread(fd, count, offset):
        if not getattr(active, "inject", False):
            return original_pread(fd, count, offset)
        preads.append((fd, count, offset))
        if fault == "raised":
            raise OSError(PRIVATE)
        value = original_pread(fd, count, offset)
        return value[:-1] if fault == "short" else bytearray(value) if fault == "type" else value
    def check(opened):
        if getattr(active, "inject", False) and "integrity" in fault:
            raise E.IntegrityProblem(PRIVATE, reason="source-changed", record=fault == "integrity")
        return original_check(opened)
    def scan(read_at, **kwargs):
        make = dict(kwargs)
        if behavior == "partial":
            make["deadline"] = time.monotonic() - 1
        report = original_scan(read_at, **make)
        active.inject = True
        try:
            if fault == "cancel":
                kwargs["cancel"].__self__.set()
            seen = []
            for _ in range(2):
                try:
                    read_at(0, 3)
                except Exception as exc:
                    seen.append(exc)
            assert len(seen) == 2 and seen[0] is seen[1]
            if behavior == "raises":
                raise PwehError(PRIVATE, code="media_unit_scan_failed") from None
            return report
        finally:
            active.inject = False
    monkeypatch.setattr(T.os, "pread", pread)
    monkeypatch.setattr(T, "_check_opened", check)
    monkeypatch.setattr(U, "scan_media_unit_stream", scan)
    async with Client(S.server) as client:
        result = await query(client, mcase, ev)
    code = "cancelled" if fault == "cancel" else "integrity_failed" if "integrity" in fault else "media_unit_scan_read_failed"
    assert code in result.get("_error", ""), result
    assert len(preads) == (1 if fault in ("raised", "short", "type") else 0)
    assert not analyses(mcase) and PRIVATE not in json.dumps(result) + caplog.text
    recorded = [x for x in S.custody(mcase).entries() if x["event"] == "integrity-failed"]
    assert len(recorded) == int(fault == "integrity")


@pytest.mark.parametrize("offset,length", [(-1, 1), (True, 1), (0, False), (0, 0),
                                          (0, 65537), (len(DATA), 1), (0.0, 1), (0, 1.0)])
async def test_bad_leaf_range_is_rejected_even_if_core_swallows_it(mcase, tmp_path, monkeypatch, offset, length):
    from forensics_mcp import server as S
    from pweh import media_unit_stream as U
    ev = await prepare(mcase, tmp_path)
    def scan(read_at, **kwargs):
        try:
            read_at(offset, length)
        except Exception:
            return {}  # latch를 검사하지 않으면 shape 오류로 원인이 사라진다.
        pytest.fail("잘못된 leaf 요청이 성공했습니다.")
    monkeypatch.setattr(U, "scan_media_unit_stream", scan)
    async with Client(S.server) as client:
        result = await query(client, mcase, ev)
    assert "validation_failed" in result.get("_error", "") and not analyses(mcase)


@pytest.mark.parametrize("fault", ["same_inode", "replacement", "hardlink"])
async def test_final_ev_seal_catches_source_change(mcase, tmp_path, monkeypatch, fault):
    from forensics_mcp import server as S
    from pweh import media_unit_stream as U
    ev = await prepare(mcase, tmp_path)
    with S._open_evidence_sync(mcase, ev) as opened:
        source = mcase.dir / opened.intake["stored_path"]
    original = U.scan_media_unit_stream
    def scan(*args, **kwargs):
        report = original(*args, **kwargs)
        if fault == "replacement":
            source.parent.chmod(0o755)
            source.rename(tmp_path / "held-ev.bin")
            source.write_bytes(DATA)
            source.chmod(0o444)
        elif fault == "hardlink":
            os.link(source, tmp_path / "other-link.bin")
        else:
            source.chmod(0o644)
            with source.open("r+b") as stream:
                stream.write(b"X")
            source.chmod(0o444)
        return report
    monkeypatch.setattr(U, "scan_media_unit_stream", scan)
    async with Client(S.server) as client:
        result = await query(client, mcase, ev)
    assert "integrity_failed" in result.get("_error", ""), result
    assert not analyses(mcase) and S.custody(mcase).entries()[-1]["event"] == "integrity-failed"


async def test_output_replacement_is_preserved_without_event(mcase, tmp_path, monkeypatch):
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
        result = await query(client, mcase, ev)
    assert "_error" in result
    output, = analyses(mcase)
    assert output.read_bytes() == b"foreign replacement"
    assert not any(e["event"] == "media-unit-scan" for e in S.custody(mcase).entries())


@pytest.mark.parametrize("stage", ["read", "final_output"])
async def test_raw_cancel_keeps_worker_fd_until_done_and_prevents_commit(mcase, tmp_path, monkeypatch, stage):
    from forensics_mcp import media_unit_scan_tools as T, server as S
    from pweh import evidence as E, media_unit_stream as U
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
        original = U.scan_media_unit_stream
        def scan(read_at, **kwargs):
            def block(offset, length):
                entered.set()
                assert release.wait(5)
                return read_at(offset, length)
            return original(block, **kwargs)
        monkeypatch.setattr(U, "scan_media_unit_stream", scan)
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
    assert not any(e["event"] == "media-unit-scan" for e in S.custody(mcase).entries())


async def test_cancel_after_commit_preserves_report_and_custody(mcase, tmp_path, monkeypatch):
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
    assert len(analyses(mcase)) == 1 and S.custody(mcase).entries()[-1]["event"] == "media-unit-scan"


@pytest.mark.parametrize("failure", ["audit", "index"])
async def test_postcommit_auxiliary_failure_preserves_receipt(mcase, tmp_path, monkeypatch, caplog, failure):
    from forensics_mcp import server as S
    from pweh.case import Case
    ev = await prepare(mcase, tmp_path)
    def fail(*args, **kwargs):
        raise ValueError(PRIVATE)
    if failure == "audit":
        monkeypatch.setattr(S.rt(), "audit", fail)
    else:
        monkeypatch.setattr(Case, "register_artifact", fail)
    async with Client(S.server) as client:
        result = await query(client, mcase, ev)
    assert result.get("ok") and len(result.get("warnings", [])) == 1, result
    assert PRIVATE not in json.dumps(result) + caplog.text
    assert len(analyses(mcase)) == 1 and S.custody(mcase).entries()[-1]["event"] == "media-unit-scan"


@pytest.mark.parametrize("mutation,expected", [(None, "recorded"), ("tamper", "mismatch"), ("missing", "missing")])
async def test_evidence_list_rechecks_saved_scan(mcase, tmp_path, mutation, expected):
    from forensics_mcp import server as S
    ev = await prepare(mcase, tmp_path)
    async with Client(S.server) as client:
        result = await query(client, mcase, ev)
        assert result.get("ok"), result
        output = mcase.dir / result["analysis"]["path"]
        if mutation == "tamper":
            output.chmod(0o644)
            output.write_bytes(output.read_bytes() + b" ")
            output.chmod(0o444)
        elif mutation == "missing":
            output.unlink()
        listed = await call(client, "forensics_evidence_list", case_id=mcase.id, write_files=False)
    assert listed.get("ok"), listed
    item, = listed["derived"]
    assert item["kind"] == "media-unit-scan" and item["custody"] == expected
