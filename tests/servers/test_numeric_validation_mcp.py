"""실제 MCP의 공급 숫자 strict 입구·원문 비노출·케이스 결과/요약 연결."""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import stat
import threading
from pathlib import Path
from types import SimpleNamespace

import pytest
from mcp import Client

from mcp_helpers import call

pytestmark = pytest.mark.anyio
PRIVATE = "PRIVATE_NUMERIC_8b17"
FLAGS = ("frame_freshness_verified", "game_semantics_verified", "action_generated")


@pytest.fixture
def anyio_backend():
    return "asyncio"


@pytest.fixture
def ncase(workspace, auth):
    from play_mcp import server as S
    return S.rt().cases.create(title="공급 숫자 합성", case_id="numeric-synthetic", authorization=auth)


def rows(values=(7, 7, 7)):
    return [{"timestamp": i + 1, "value": value, "confidence": 1.0} for i, value in enumerate(values)]


def args(case, **changes):
    value = {"case_id": case.id, "input_kind": "numeric-observations", "observations": rows(), "now": 3}
    value.update(changes)
    return value


async def test_actual_client_analysis_summary_and_report(ncase, caplog):
    from case_mcp import server as C
    from play_mcp import server as S
    from pweh import schemas

    audit = ncase.dir / "audit.jsonl"
    before = audit.stat().st_size
    async with Client(S.server) as client, Client(C.server) as cc:
        result = await call(client, "vision_validate", **args(ncase))
        assert set(result) == {"ok", "report", "artifact_id", "analysis_path", "sha256", "size", "warnings"}, result
        assert result["ok"] and result["warnings"] == []
        report = result["report"]
        assert report["params"] == {"now": 3}
        assert report["analysis"]["status"] == "stable" and report["analysis"]["value"] == 7
        assert all(report["analysis"][flag] is False for flag in FLAGS)
        canonical = {"schema": "pweh.numeric-input/v1", "input_kind": "numeric-observations", "now": 3,
                     "observations": rows(), "policy": report["analysis"]["policy"]}
        data = json.dumps(canonical, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode()
        assert report["source"] == {"kind": "supplied-observations", "input_kind": "numeric-observations",
            "observation_count": 3, "canonicalization": "pweh-numeric-json-v1", "canonical_size": len(data),
            "canonical_sha256": hashlib.sha256(data).hexdigest()}
        schemas.validate("numeric-validation", report)
        path = ncase.dir / result["analysis_path"]
        assert json.loads(path.read_bytes()) == report
        assert stat.S_IMODE(path.stat().st_mode) == 0o444
        assert path.stat().st_size == result["size"] <= 65536
        assert hashlib.sha256(path.read_bytes()).hexdigest() == result["sha256"]
        artifact = next(a for a in ncase.load()["artifacts"] if a["id"] == result["artifact_id"])
        assert artifact["producer"] == "pweh-play" and artifact["extra"] == {"type": "numeric-validation"}
        assert artifact["path"] == result["analysis_path"] and artifact["sha256"] == result["sha256"]
        visible = json.dumps(result) + path.read_text() + audit.read_bytes()[before:].decode() + caplog.text
        assert '"observations":' not in visible and '"timestamp":' not in visible and '"confidence":' not in visible
        summary = {"schema": "pweh.numeric-analysis/v1", "mode": "supplied-numeric-observations",
            "results": [{"artifact_id": result["artifact_id"], "analysis_path": result["analysis_path"],
                         "report_sha256": result["sha256"], "status": "stable", "reason": "vote_consensus",
                         "observation_count": 3}], **{flag: False for flag in FLAGS}}
        recorded = await call(cc, "case_record_step", case_id=ncase.id, skill="numeric-observation-analysis", step="summary",
                              status="success", summary="공급 숫자의 합의 계산 완료", data=summary,
                              artifacts=[result["analysis_path"]])
        assert recorded.get("ok"), recorded
        steps = await call(cc, "case_get_step_results", case_id=ncase.id)
        assert steps["summaries"]["numeric-observation-analysis"]["data"] == summary
        assert "game-play-automation" not in steps["missing"]
        final = await call(cc, "report_generate", case_id=ncase.id)
        assert final.get("ok"), final
        assert result["analysis_path"] in Path(final["path"]).read_text()
        fetched = await call(cc, "schema_get", name="numeric-analysis")
        assert fetched.get("ok")


@pytest.mark.parametrize("observations,now,policy,status,reason", [
    ([], 0, None, "unknown", "no_observations"),
    (rows(), 10, None, "stale", "no_recent_observations"),
    (rows((None,)), 1, None, "unknown", "insufficient_valid"),
    (rows((1, 1, 2, 2)), 4, {"ttl_seconds": 10}, "unknown", "tied_votes"),
    (rows((1, 1, 2)), 3, None, "unknown", "insufficient_votes"),
    (rows((-7, -7, -7)), 3, None, "stable", "vote_consensus"),
])
async def test_all_six_outcomes_remain_valid_results(ncase, observations, now, policy, status, reason):
    from play_mcp import server as S
    async with Client(S.server) as client:
        result = await call(client, "vision_validate", **args(ncase, observations=observations, now=now, policy=policy))
    assert result.get("ok"), result
    assert result["report"]["analysis"]["status"] == status
    assert result["report"]["analysis"]["reason"] == reason


async def test_256_inputs_defaults_and_no_previous_value_cache(ncase):
    from play_mcp import server as S
    async with Client(S.server) as client:
        first = await call(client, "vision_validate", **args(ncase))
        explicit = await call(client, "vision_validate", **args(ncase, policy=first["report"]["analysis"]["policy"]))
        assert first["report"]["source"]["canonical_sha256"] == explicit["report"]["source"]["canonical_sha256"]
        largest = await call(client, "vision_validate", **args(ncase, observations=rows([0]*256), now=256))
        assert largest.get("ok") and largest["report"]["source"]["observation_count"] == 256
        for obs, now, status in (([], 0, "unknown"), (rows(), 10, "stale")):
            later = await call(client, "vision_validate", **args(ncase, observations=obs, now=now))
            assert later.get("ok") and later["report"]["analysis"]["status"] == status
            assert later["report"]["analysis"]["value"] is None


async def test_tools_list_exposes_only_supplied_numeric_input(workspace):
    from play_mcp import server as S
    async with Client(S.server) as client:
        tools = (await client.list_tools()).tools
    assert [t.name for t in tools] == ["vision_validate"]
    tool = tools[0]
    assert tool.annotations.read_only_hint is False and tool.annotations.open_world_hint is False
    schema = tool.input_schema
    assert set(schema["properties"]) == {"case_id", "input_kind", "observations", "now", "policy"}
    assert set(schema["required"]) == {"case_id", "input_kind", "observations", "now"}
    assert schema["additionalProperties"] is False
    assert schema["properties"]["input_kind"]["const"] == "numeric-observations"
    assert schema["properties"]["observations"]["maxItems"] == 256
    assert all(d["additionalProperties"] is False for d in schema["$defs"].values())


@pytest.mark.parametrize("key,value", [
    ("case_id", None), ("case_id", 1), ("case_id", PRIVATE + "/../x"), ("case_id", "x"*81),
    ("input_kind", None), ("input_kind", PRIVATE), ("now", True), ("now", "3"), ("now", -1),
    ("now", 2**53+1), ("observations", None), ("observations", {}), ("observations", PRIVATE),
    ("observations", "[]"), ("observations", json.dumps(rows())), ("observations", [PRIVATE]),
    ("observations", rows([1]*257)), ("policy", "{}"), ("policy", "null"), ("policy", []),
    ("policy", {"window_size": 1}), ("policy", {"window_size": 3.0}), ("policy", {"votes_required": True}),
    ("policy", {"min_valid": "3"}), ("policy", {"min_confidence": -0.1}),
    ("policy", {"ttl_seconds": 0}), ("policy", {"ttl_seconds": 86401}),
])
async def test_invalid_root_inputs_never_reach_runtime(ncase, monkeypatch, caplog, key, value):
    from play_mcp import server as S
    monkeypatch.setattr(S, "rt", lambda: pytest.fail("잘못된 입력이 runtime에 도달했습니다."))
    async with Client(S.server) as client:
        result = await call(client, "vision_validate", **args(ncase, **{key: value}))
    assert "numeric_input_invalid" in result.get("_error", ""), result
    assert PRIVATE not in json.dumps(result) + caplog.text


@pytest.mark.parametrize("key,value", [
    ("timestamp", True), ("timestamp", "1"), ("timestamp", 4), ("timestamp", -1),
    ("timestamp", 2**53+1), ("value", True), ("value", 1.0), ("value", PRIVATE),
    ("value", 2**63), ("value", -(2**63)-1), ("confidence", True), ("confidence", "1"),
    ("confidence", 1.01), ("confidence", -1),
])
async def test_invalid_nested_values_are_fixed_errors(ncase, monkeypatch, caplog, key, value):
    from play_mcp import server as S
    obs = rows()
    obs[0][key] = value
    monkeypatch.setattr(S, "rt", lambda: pytest.fail("잘못된 표본이 runtime에 도달했습니다."))
    async with Client(S.server) as client:
        result = await call(client, "vision_validate", **args(ncase, observations=obs))
    assert "numeric_input_invalid" in result.get("_error", ""), result
    assert PRIVATE not in json.dumps(result) + caplog.text


@pytest.mark.parametrize("where", ["root", "observation", "policy", "missing", "duplicate_time", "outside_window"])
async def test_nested_keys_and_full_sequence_validation(ncase, monkeypatch, caplog, where):
    from play_mcp import server as S
    given = args(ncase)
    if where == "root": given[PRIVATE] = {PRIVATE: PRIVATE}
    elif where == "observation": given["observations"][0][PRIVATE] = PRIVATE
    elif where == "policy": given["policy"] = {PRIVATE: PRIVATE}
    elif where == "missing": del given["observations"][0]["confidence"]
    elif where == "duplicate_time": given["observations"][1]["timestamp"] = 1
    else:
        given.update(observations=rows([7]*10), now=10)
        given["observations"][0]["value"] = PRIVATE
    monkeypatch.setattr(S, "rt", lambda: pytest.fail("검증하지 않은 입력이 runtime에 도달했습니다."))
    caplog.set_level(logging.INFO)
    async with Client(S.server) as client:
        result = await call(client, "vision_validate", **given)
    assert "numeric_input_invalid" in result.get("_error", ""), result
    assert PRIVATE not in json.dumps(result) + caplog.text


@pytest.mark.parametrize("field", ["case_id", "input_kind", "observations", "now"])
async def test_missing_required_arguments_are_fixed(ncase, field):
    from play_mcp import server as S
    given = args(ncase)
    del given[field]
    async with Client(S.server) as client:
        result = await call(client, "vision_validate", **given)
    assert "numeric_input_invalid" in result.get("_error", ""), result


@pytest.mark.parametrize("value", [float("nan"), float("inf"), -float("inf"), 10**400])
async def test_direct_nonfinite_and_huge_input_boundary(ncase, value):
    from play_mcp import server as S
    with pytest.raises(Exception) as caught:
        await S.vision_validate(**args(ncase, now=value))
    assert "numeric_input_invalid" in str(caught.value)


async def test_raw_metadata_preserves_numeric_types_and_rejects_json_containers(workspace):
    from play_mcp import server as S
    meta = S.server._tool_manager.get_tool("vision_validate").fn_metadata
    given = {"case_id": "synthetic", "input_kind": "numeric-observations", "now": 1,
             "observations": [{"timestamp": 1.0, "value": 0, "confidence": 1}], "policy": {"ttl_seconds": 2}}
    result = meta.validate_arguments(given)
    assert type(result["now"]) is int and type(result["observations"][0]["timestamp"]) is float
    assert type(result["observations"][0]["confidence"]) is int and type(result["policy"]["ttl_seconds"]) is int
    for key in ("observations", "policy"):
        with pytest.raises(Exception) as caught:
            meta.validate_arguments({**given, key: json.dumps(given[key])})
        assert "numeric_input_invalid" in str(caught.value)


@pytest.mark.parametrize("code", ["invalid_policy", "invalid_observation", "observation_limit", "numeric_input_invalid",
    "numeric_output_invalid", "numeric_analysis_failed", "cleanup_incomplete", "cancelled", "time_limit", "unexpected"])
async def test_worker_errors_are_projected_without_raw_details(ncase, monkeypatch, caplog, code):
    from play_mcp import numeric_validation as A, server as S
    from pweh.errors import PwehError
    def fail(*a, **kw):
        raise PwehError(PRIVATE, code=code, data={PRIVATE: PRIVATE}, hint=PRIVATE)
    monkeypatch.setattr(A, "validate_supplied_numeric", fail)
    async with Client(S.server) as client:
        result = await call(client, "vision_validate", **args(ncase))
    expected = "numeric_analysis_failed" if code == "unexpected" else code
    assert expected in result.get("_error", ""), result
    assert PRIVATE not in json.dumps(result) + caplog.text


@pytest.mark.parametrize("mode,code", [("missing", "not_found"), ("unauthorized", "authorization_required")])
async def test_authorization_meaning_survives_fixed_projection(workspace, mode, code):
    from play_mcp import server as S
    if mode == "unauthorized": S.rt().cases.create(title="미확인", case_id=PRIVATE)
    async with Client(S.server) as client:
        result = await call(client, "vision_validate", case_id=PRIVATE, input_kind="numeric-observations", observations=[], now=0)
    assert code in result.get("_error", ""), result
    assert PRIVATE not in json.dumps(result)


async def test_worker_first_deadline_includes_case_selection(ncase, monkeypatch):
    from play_mcp import numeric_validation as A, server as S
    from pweh.vision_sequence import NumericObservation, NumericPolicy
    clock = [100.0]
    monkeypatch.setattr(S, "time", SimpleNamespace(monotonic=lambda: clock[0]))
    def case(cid, *, hardware):
        assert cid == ncase.id and hardware is True
        clock[0] = 102.0
        return ncase
    def validate(selected, observations, **kw):
        assert selected is ncase and type(observations) is tuple
        assert all(type(o) is NumericObservation for o in observations)
        assert type(kw["policy"]) is NumericPolicy
        assert kw["deadline"] == 105.0 and kw["now"] == 3 and not kw["cancel"]()
        return {"ok": True}
    monkeypatch.setattr(S, "rt", lambda: SimpleNamespace(case=case))
    monkeypatch.setattr(A, "validate_supplied_numeric", validate)
    assert await S.vision_validate(**args(ncase)) == {"ok": True}


async def test_length_is_rejected_before_observation_construction(ncase, monkeypatch):
    from play_mcp import server as S
    def forbidden(*a, **kw):
        pytest.fail("입력 개수 검사 전에 원소 객체를 만들었습니다.")
    monkeypatch.setattr(S, "NumericObservation", forbidden)
    with pytest.raises(Exception) as caught:
        await S.vision_validate(**args(ncase, observations=rows([7]*257), now=257))
    assert "numeric_input_invalid" in str(caught.value)


async def test_offline_input_never_probes_or_launches(ncase, monkeypatch):
    from play_mcp import server as S
    from pweh import hostenv
    import serial
    import socket
    import subprocess
    async with Client(S.server) as client:
        def forbidden(*a, **kw):
            pytest.fail("공급 숫자 입구가 장치 또는 외부 실행을 요청했습니다.")
        monkeypatch.setattr(subprocess, "Popen", forbidden)
        monkeypatch.setattr(subprocess, "run", forbidden)
        monkeypatch.setattr(socket, "create_connection", forbidden)
        monkeypatch.setattr(serial, "Serial", forbidden)
        monkeypatch.setattr(serial, "serial_for_url", forbidden)
        monkeypatch.setattr(hostenv, "detect", forbidden)
        result = await call(client, "vision_validate", **args(ncase))
    assert result.get("ok"), result


async def test_raw_awaiter_cancel_sets_worker_event(ncase, monkeypatch):
    from play_mcp import numeric_validation as A, server as S
    entered, release, finished = threading.Event(), threading.Event(), threading.Event()
    seen = []
    def validate(*a, **kw):
        entered.set()
        try:
            assert release.wait(5)
            seen.append(kw["cancel"]())
            return {"ok": True}
        finally: finished.set()
    monkeypatch.setattr(A, "validate_supplied_numeric", validate)
    task = asyncio.create_task(S.vision_validate(**args(ncase)))
    try:
        assert await asyncio.to_thread(entered.wait, 5)
        task.cancel()
        with pytest.raises(asyncio.CancelledError): await task
        assert not finished.is_set()
    finally:
        release.set()
        assert await asyncio.to_thread(finished.wait, 5)
    assert seen == [True]


@pytest.mark.parametrize("failure", ["missing", "rebuild", "schema"])
async def test_metadata_registration_fails_closed(workspace, monkeypatch, failure):
    from play_mcp import server as S
    if failure == "missing":
        instance = SimpleNamespace(_tool_manager=SimpleNamespace(get_tool=lambda name: None))
    else:
        instance = S.server
        model = S.server._tool_manager.get_tool("vision_validate").fn_metadata.arg_model
        def fail(*a, **kw): raise RuntimeError(PRIVATE)
        monkeypatch.setattr(model, "model_rebuild" if failure == "rebuild" else "model_json_schema", fail)
    with pytest.raises(RuntimeError) as caught: S._configure_input(instance)
    assert "비공개 입력 검증" in str(caught.value) and PRIVATE not in str(caught.value)
