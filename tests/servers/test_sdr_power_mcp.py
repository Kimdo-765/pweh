"""실제 MCP 입구의 strict 입력·원문 비노출·전력 CSV 결과/요약 연결을 확인한다."""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import os
import stat
import threading
from pathlib import Path
from types import SimpleNamespace

import pytest
from mcp import Client

from mcp_helpers import call

pytestmark = pytest.mark.anyio
PROFILE = "rtl-power-blog-v1.4.0-csv"
PRIVATE = "SYNTHETIC_POWER_PRIVATE_c731"
VALID = b"2025-03-04, 05:06:07, 100, 200, 25.00, 4, -12.50, -11.25\n"
FLAGS = ("input_completeness_verified", "capture_verified", "device_association_verified",
         "authorization_assessed", "decoded", "transmitted")


@pytest.fixture
def anyio_backend():
    return "asyncio"


@pytest.fixture
def rcase(workspace, auth):
    from sdr_mcp import server as S
    return S.rt().cases.create(title="합성 전력 CSV", case_id="synthetic-power", authorization=auth)


def register(case, data=VALID, name=PRIVATE + ".csv", subdir="dumps"):
    path = case.dir / subdir / name
    path.parent.mkdir(exist_ok=True)
    path.write_bytes(data)
    return case.register_artifact(path, kind="other", producer="synthetic-test")


def args(case, art, **changes):
    out = {"case_id": case.id, "artifact_id": art["id"]}
    out.update(changes)
    return out


async def test_actual_client_import_analysis_summary_report(workspace, auth, tmp_path, caplog):
    from case_mcp import server as C
    from sdr_mcp import server as S
    from pweh import schemas

    source = tmp_path / (PRIVATE + ".csv")
    source.write_bytes(VALID)
    async with Client(C.server) as cc, Client(S.server) as client:
        created = await call(cc, "case_create", title="합성 전력 CSV 연결", case_id="power-public-flow", authorization=auth)
        assert created.get("ok"), created
        cid = created["case"]["id"]
        imported = await call(cc, "case_import_file", case_id=cid, source_path=str(source), kind="other")
        assert imported.get("ok"), imported
        case = C.rt().cases.get(cid)
        aid = imported["artifact"]["id"]
        audit = case.dir / "audit.jsonl"
        audit_start = audit.stat().st_size
        caplog.clear()
        result = await call(client, "sdr_peaks", case_id=cid, artifact_id=aid)
        assert set(result) == {"ok", "report", "analysis", "warnings"}, result
        assert result["ok"] is True and result["warnings"] == []
        report, analysis = result["report"], result["analysis"]
        assert report["status"] == "complete"
        assert report["source"] == {"kind": "case-artifact", "artifact_id": aid,
                                    "size": len(VALID), "sha256": hashlib.sha256(VALID).hexdigest()}
        assert report["params"] == {"profile": PROFILE, "max_seconds": 5}
        assert report["inspection"]["statistics"]["rows_accepted"] == 1
        assert report["inspection"]["statistics"]["values_accepted"] == 2
        assert report["inspection"]["statistics"]["power_centi_db_max"] == -1125
        assert [p["value_index"] for p in report["inspection"]["peaks"]] == [1, 0]
        assert all(report["inspection"]["coverage"][f] is False for f in (*FLAGS, "frequency_centers_verified", "power_calibration_verified"))
        schemas.validate("rf-power-analysis", report)
        saved = case.dir / analysis["path"]
        assert json.loads(saved.read_bytes()) == report
        assert stat.S_IMODE(saved.stat().st_mode) == 0o444
        assert saved.stat().st_size == analysis["size"]
        assert hashlib.sha256(saved.read_bytes()).hexdigest() == analysis["sha256"]
        entry = next(a for a in case.load()["artifacts"] if a["id"] == analysis["artifact_id"])
        assert entry["producer"] == "pweh-sdr" and entry["extra"] == {"type": "rf-power-analysis"}
        assert entry["path"] == analysis["path"] and entry["sha256"] == analysis["sha256"]
        visible = json.dumps(result) + saved.read_text() + audit.read_bytes()[audit_start:].decode() + caplog.text
        assert PRIVATE not in visible and str(tmp_path) not in visible
        assert "2025-03-04" not in visible and "05:06:07" not in visible

        summary = {"schema": "pweh.rf-analysis/v1", "mode": "offline-power", "power_results": [{
            "input_artifact_id": aid, "analysis_path": analysis["path"], "report_sha256": analysis["sha256"],
            "status": report["status"], "rows_accepted": 1, "values_accepted": 2}], **{flag: False for flag in FLAGS}}
        recorded = await call(cc, "case_record_step", case_id=cid, skill="flipper-rf-analysis", step="summary",
                              status="success", summary="등록 전력 CSV 문법과 집계 완료", data=summary,
                              artifacts=[analysis["path"]])
        assert recorded.get("ok"), recorded
        steps = await call(cc, "case_get_step_results", case_id=cid)
        assert steps["summaries"]["flipper-rf-analysis"]["data"] == summary
        assert "flipper-rf-analysis" not in steps["missing"]
        assert not any(name in steps["missing"] for name in ("numeric-observation-analysis", "game-play-automation"))
        final = await call(cc, "report_generate", case_id=cid)
        assert final.get("ok"), final
        text = Path(final["path"]).read_text()
        assert "Flipper·RF 분석" in text and analysis["path"] in text
        fetched = await call(cc, "schema_get", name="rf-analysis")
        assert fetched.get("ok") and fetched["schema"]["oneOf"][1]["properties"]["mode"]["const"] == "offline-power"


@pytest.mark.parametrize("data,status,code", [
    (VALID, "complete", None), (b"", "unsupported", "empty_input"),
    (b"x" * 65537 + b"\n", "partial", "line_length_limit"),
    (VALID.replace(b"-12.50", b"nan"), "unsupported", "nonfinite_value"),
    (VALID.replace(b"100", b"1x0"), "malformed", "number_syntax"),
])
async def test_four_parser_outcomes_are_saved_without_raw_content(rcase, data, status, code, caplog):
    from sdr_mcp import server as S
    art = register(rcase, data)
    caplog.clear()
    async with Client(S.server) as client:
        result = await call(client, "sdr_peaks", **args(rcase, art))
    assert result.get("ok"), result
    assert result["report"]["status"] == status
    stop = result["report"]["inspection"]["stop"]
    assert (stop["code"] if stop else None) == code
    assert PRIVATE not in json.dumps(result) + caplog.text
    assert (rcase.dir / result["analysis"]["path"]).is_file()


async def test_tools_list_has_only_explicit_offline_inputs(workspace):
    from sdr_mcp import server as S
    async with Client(S.server) as client:
        tools = (await client.list_tools()).tools
    assert sorted(t.name for t in tools) == ["sdr_analyze", "sdr_import_flipper_sub", "sdr_peaks"]
    tool = next(t for t in tools if t.name == "sdr_peaks")
    assert tool.annotations.read_only_hint is False
    assert tool.annotations.destructive_hint is False
    assert tool.annotations.open_world_hint is False
    schema = tool.input_schema
    assert set(schema["properties"]) == {"case_id", "artifact_id", "max_seconds"}
    assert set(schema["required"]) == {"case_id", "artifact_id"}
    assert schema["additionalProperties"] is False
    assert schema["properties"]["max_seconds"]["default"] == 5


@pytest.mark.parametrize("key,value", [
    ("case_id", None), ("case_id", 5), ("case_id", []), ("case_id", PRIVATE + "/../secret"),
    ("case_id", "x" * 81), ("case_id", "valid\n"), ("artifact_id", None), ("artifact_id", 1),
    ("artifact_id", "A-0001\n"), ("artifact_id", "A-1"), ("artifact_id", "A-000000001"), ("artifact_id", PRIVATE + "/a"),
    ("max_seconds", True), ("max_seconds", False), ("max_seconds", "5"),
    ("max_seconds", "[]"), ("max_seconds", "{}"), ("max_seconds", "null"),
    ("max_seconds", []), ("max_seconds", {PRIVATE: PRIVATE}), ("max_seconds", None),
    ("max_seconds", 0), ("max_seconds", -1), ("max_seconds", 5.001), ("max_seconds", 10 ** 300),
])
async def test_invalid_arguments_stop_before_runtime_and_hide_values(rcase, monkeypatch, caplog, key, value):
    from sdr_mcp import server as S
    def forbidden():
        pytest.fail("잘못된 입력이 runtime에 도달했습니다.")
    monkeypatch.setattr(S, "rt", forbidden)
    caplog.set_level(logging.INFO)
    async with Client(S.server) as client:
        result = await call(client, "sdr_peaks", **args(rcase, {"id": "A-0001"}, **{key: value}))
    assert "rf_power_input_invalid" in result.get("_error", ""), result
    assert PRIVATE not in json.dumps(result) + caplog.text


@pytest.mark.parametrize("value", [PRIVATE, {PRIVATE: [PRIVATE]}, [PRIVATE]])
async def test_extra_key_is_not_exposed_as_sdk_location(rcase, monkeypatch, caplog, value):
    from sdr_mcp import server as S
    monkeypatch.setattr(S, "rt", lambda: pytest.fail("추가 인자가 worker까지 도달했습니다."))
    caplog.set_level(logging.INFO)
    async with Client(S.server) as client:
        result = await call(client, "sdr_peaks", **args(rcase, {"id": "A-0001"}, **{PRIVATE: value}))
    assert "rf_power_input_invalid" in result.get("_error", ""), result
    assert PRIVATE not in json.dumps(result) + caplog.text
    assert "rejected arguments" in caplog.text


@pytest.mark.parametrize("missing", ["case_id", "artifact_id"])
async def test_required_field_failure_is_fixed(rcase, missing, caplog):
    from sdr_mcp import server as S
    given = args(rcase, {"id": "A-0001"})
    del given[missing]
    async with Client(S.server) as client:
        result = await call(client, "sdr_peaks", **given)
    assert "rf_power_input_invalid" in result.get("_error", ""), result


@pytest.mark.parametrize("value", [float("nan"), float("inf"), -float("inf"), 10 ** 400])
async def test_nonfinite_and_huge_numbers_use_fixed_direct_boundary(rcase, value):
    from sdr_mcp import server as S
    with pytest.raises(Exception) as caught:
        await S.sdr_peaks(**args(rcase, {"id": "A-0001"}, max_seconds=value))
    assert "rf_power_input_invalid" in str(caught.value)


@pytest.mark.parametrize("case_mode,code", [("missing", "not_found"), ("unauthorized", "authorization_required")])
async def test_case_and_authorization_meanings_survive_fixed_projection(workspace, case_mode, code):
    from sdr_mcp import server as S
    cid = PRIVATE
    if case_mode == "unauthorized":
        S.rt().cases.create(title="미확인 합성", case_id=cid)
    async with Client(S.server) as client:
        result = await call(client, "sdr_peaks", case_id=cid, artifact_id="A-0001")
    assert code in result.get("_error", ""), result
    assert PRIVATE not in json.dumps(result)


@pytest.mark.parametrize("code", ["rf_power_input_invalid", "rf_power_input_limit", "rf_power_input_changed",
    "rf_power_failed", "rf_power_cleanup_incomplete", "cancelled", "time_limit"])
async def test_worker_known_codes_are_preserved_without_details(rcase, monkeypatch, caplog, code):
    from sdr_mcp import power_analysis as A, server as S
    from pweh.errors import PwehError
    def fail(*a, **kw):
        raise PwehError(PRIVATE, code=code, hint=PRIVATE, data={PRIVATE: PRIVATE})
    monkeypatch.setattr(A, "analyze_registered_power", fail)
    async with Client(S.server) as client:
        result = await call(client, "sdr_peaks", **args(rcase, {"id": "A-0001"}))
    assert code in result.get("_error", ""), result
    assert PRIVATE not in json.dumps(result) + caplog.text


async def test_unexpected_worker_error_is_not_logged_or_echoed(rcase, monkeypatch, caplog):
    from sdr_mcp import power_analysis as A, server as S
    def fail(*a, **kw):
        raise RuntimeError(PRIVATE)
    monkeypatch.setattr(A, "analyze_registered_power", fail)
    async with Client(S.server) as client:
        result = await call(client, "sdr_peaks", **args(rcase, {"id": "A-0001"}))
    assert "rf_power_failed" in result.get("_error", ""), result
    assert PRIVATE not in json.dumps(result) + caplog.text


async def test_worker_deadline_includes_case_selection(rcase, monkeypatch):
    from sdr_mcp import power_analysis as A, server as S
    observed = []
    clock = [100.0]
    monkeypatch.setattr(S, "time", SimpleNamespace(monotonic=lambda: clock[0]))
    def case(cid, *, hardware):
        assert cid == rcase.id and hardware is True
        clock[0] = 102.0
        return rcase
    def analyze(selected, aid, **kw):
        observed.append(kw)
        assert selected is rcase and aid == "A-0001"
        assert kw["deadline"] == 103.5 and kw["max_seconds"] == 3.5
        assert kw["cancel"]() is False
        return {"ok": True}
    monkeypatch.setattr(S, "rt", lambda: SimpleNamespace(case=case))
    monkeypatch.setattr(A, "analyze_registered_power", analyze)
    assert await S.sdr_peaks(**args(rcase, {"id": "A-0001"}, max_seconds=3.5)) == {"ok": True}
    assert len(observed) == 1


async def test_raw_awaiter_cancel_keeps_fd_until_actual_worker_finishes(rcase, monkeypatch):
    from sdr_mcp import power_analysis as A, server as S
    entered, release, finished = threading.Event(), threading.Event(), threading.Event()
    art = register(rcase)
    original_open = A.safeio.open_regular
    original_worker = A.analyze_registered_power
    original_inspect = A.rf_power.inspect_power_csv
    held, seen = [], []

    def opening(*a, **kw):
        pair = original_open(*a, **kw)
        held.append(pair[0])
        return pair

    def inspect(*a, **kw):
        entered.set()
        assert release.wait(5)
        seen.append(kw["cancel"]())
        return original_inspect(*a, **kw)

    def analyze(*a, **kw):
        try:
            return original_worker(*a, **kw)
        finally:
            finished.set()

    monkeypatch.setattr(A.safeio, "open_regular", opening)
    monkeypatch.setattr(A.rf_power, "inspect_power_csv", inspect)
    monkeypatch.setattr(A, "analyze_registered_power", analyze)
    task = asyncio.create_task(S.sdr_peaks(**args(rcase, art)))
    try:
        assert await asyncio.to_thread(entered.wait, 5)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        assert not finished.is_set() and len(held) == 1
        assert os.fstat(held[0]).st_size == len(VALID)
    finally:
        release.set()
        assert await asyncio.to_thread(finished.wait, 5)
    assert seen == [True]
    with pytest.raises(OSError):
        os.fstat(held[0])
    assert len(rcase.artifacts()) == 1
    assert not list((rcase.dir / "analysis").glob("rf-power-*.json"))


async def test_offline_path_does_not_probe_or_launch(rcase, monkeypatch):
    from sdr_mcp import server as S
    from pweh import hostenv
    import serial
    import socket
    import subprocess
    art = register(rcase)
    async with Client(S.server) as client:
        def forbidden(*a, **kw):
            pytest.fail("오프라인 전력 CSV 입구가 외부 실행 또는 장치를 요청했습니다.")
        monkeypatch.setattr(subprocess, "Popen", forbidden)
        monkeypatch.setattr(subprocess, "run", forbidden)
        monkeypatch.setattr(socket, "create_connection", forbidden)
        monkeypatch.setattr(serial, "Serial", forbidden)
        monkeypatch.setattr(serial, "serial_for_url", forbidden)
        monkeypatch.setattr(hostenv, "detect", forbidden)
        result = await call(client, "sdr_peaks", **args(rcase, art))
    assert result.get("ok"), result


@pytest.mark.parametrize("failure", ["missing", "rebuild", "schema"])
async def test_private_sdk_configuration_fails_closed(workspace, monkeypatch, failure):
    from sdr_mcp import server as S
    original = S.server._tool_manager.get_tool("sdr_peaks")
    if failure == "missing":
        instance = SimpleNamespace(_tool_manager=SimpleNamespace(get_tool=lambda name: None))
    else:
        model = original.fn_metadata.arg_model
        def fail(*a, **kw):
            raise RuntimeError(PRIVATE)
        monkeypatch.setattr(model, "model_rebuild" if failure == "rebuild" else "model_json_schema", fail)
        instance = S.server
    with pytest.raises(RuntimeError) as caught:
        S._configure_power_input(instance)
    assert PRIVATE not in str(caught.value)
    assert "비공개 입력 검증 설정" in str(caught.value)
