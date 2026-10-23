"""실제 Case/SDR Client의 OOK 변환·등록·요약과 strict 원문 비노출 종단."""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import stat
import threading
from pathlib import Path
from types import SimpleNamespace

import pytest
from mcp import Client

from mcp_helpers import call

pytestmark = pytest.mark.anyio
PRIVATE = "SYNTHETIC_OOK_PRIVATE_7ce9"
TOOL = "sdr_import_flipper_sub"
FLAGS = ("input_completeness_verified", "capture_verified", "device_association_verified",
         "authorization_assessed", "decoded", "transmitted", "packet_boundaries_verified",
         "decoder_compatibility_verified")
OOK_HEADER = b";pulse data\n;version 1\n;timescale 1us\n"


def raw(durations="100 -200", preset="Ook270", *, split=False, bom_crlf=False):
    data = ("Filetype: Flipper SubGhz RAW File\nVersion: 1\nFrequency: 315000000\n"
            f"Preset: FuriHalSubGhzPreset{preset}Async\nProtocol: RAW\n# {PRIVATE}\n")
    if split:
        data += "".join("RAW_Data: " + token + "\n" for token in durations.split())
    else:
        tokens = durations.split()
        # strict RAW의 줄당 512개 문법을 유지한 채 전체 pair 상한을 검사한다.
        data += "".join("RAW_Data: " + " ".join(tokens[n:n + 512]) + "\n"
                        for n in range(0, len(tokens), 512))
    return (b"\xef\xbb\xbf" + data.replace("\n", "\r\n").encode()) if bom_crlf else data.encode()


@pytest.fixture
def anyio_backend():
    return "asyncio"


@pytest.fixture
def rcase(workspace, auth):
    from sdr_mcp import server as S
    return S.rt().cases.create(title="합성 OOK 변환", case_id="synthetic-ook", authorization=auth)


def register(case, data=None, *, subdir="dumps", name=PRIVATE + ".sub"):
    path = case.dir / subdir / name
    path.parent.mkdir(exist_ok=True)
    path.write_bytes(raw() if data is None else data)
    return case.register_artifact(path, kind="other", producer="synthetic-test")


def args(case, art, **changes):
    return {"case_id": case.id, "artifact_id": art["id"], **changes}


def check_files(case, result, expected):
    from pweh import schemas
    assert set(result) == {"ok", "report", "analysis", "output", "warnings"}, result
    assert result["ok"] is True
    report, receipt, output = result["report"], result["analysis"], result["output"]
    schemas.validate("rf-ook-conversion", report)
    assert report["status"] == "complete" and all(report[k] is False for k in FLAGS)
    assert output == report["output"]
    manifest, converted = case.dir / receipt["path"], case.dir / output["path"]
    assert manifest.parent == converted.parent
    assert converted.read_bytes() == expected
    assert output["size"] == len(expected)
    assert output["sha256"] == hashlib.sha256(expected).hexdigest()
    encoded = manifest.read_bytes()
    assert json.loads(encoded) == report
    assert encoded == (json.dumps(report, sort_keys=True, ensure_ascii=True, separators=(",", ":")) + "\n").encode()
    assert receipt["size"] == len(encoded) and receipt["sha256"] == hashlib.sha256(encoded).hexdigest()
    assert stat.S_IMODE(manifest.stat().st_mode) == stat.S_IMODE(converted.stat().st_mode) == 0o444
    entry = next(item for item in case.artifacts() if item["id"] == receipt["artifact_id"])
    assert entry["path"] == receipt["path"] and entry["sha256"] == receipt["sha256"]
    assert entry["producer"] == "pweh-sdr" and entry["extra"] == {"type": "rf-ook-conversion"}
    assert not any(item["path"] == output["path"] for item in case.artifacts())


async def test_actual_import_case_get_conversion_summary_and_report(workspace, auth, tmp_path, caplog):
    from case_mcp import server as C
    from sdr_mcp import server as S

    source = tmp_path / (PRIVATE + ".sub")
    original = raw("1234567 -7654321")
    source.write_bytes(original)
    async with Client(C.server) as cc, Client(S.server) as client:
        created = await call(cc, "case_create", title="OOK 실제 공개 연결", case_id="ook-public-flow", authorization=auth)
        assert created.get("ok"), created
        cid = created["case"]["id"]
        imported = await call(cc, "case_import_file", case_id=cid, source_path=str(source), kind="other")
        assert imported.get("ok"), imported
        aid = imported["artifact"]["id"]
        listing = await call(cc, "case_get", case_id=cid, include_artifacts=True)
        assert aid in json.dumps(listing)
        case = C.rt().cases.get(cid)
        audit = case.dir / "audit.jsonl"
        audit_start = audit.stat().st_size
        caplog.clear()
        result = await call(client, TOOL, case_id=cid, artifact_id=aid)
        check_files(case, result, OOK_HEADER + b"1234567 7654321\n;end\n")
        assert result["warnings"] == []
        assert len(case.artifacts()) == 2
        report, receipt = result["report"], result["analysis"]
        assert report["source"] == {"kind": "case-artifact", "artifact_id": aid,
            "size": len(original), "sha256": hashlib.sha256(original).hexdigest()}
        assert report["params"] == {"source_profile": "flipper-subghz-raw-v1-strict", "max_seconds": 5}
        assert report["conversion"]["total_duration_us"] == 8888888
        assert report["metadata"] == {"declared_preset": "FuriHalSubGhzPresetOok270Async",
                                     "declared_frequency_hz": 315000000}
        visible = json.dumps(result) + (case.dir / receipt["path"]).read_text() + audit.read_bytes()[audit_start:].decode() + caplog.text
        assert PRIVATE not in visible and str(tmp_path) not in visible
        assert "1234567 -7654321" not in visible and "1234567 7654321" not in visible

        summary = {"schema": "pweh.rf-analysis/v1", "mode": "offline-ook", "conversion_results": [{
            "input_artifact_id": aid, "analysis_path": receipt["path"], "report_sha256": receipt["sha256"],
            "output_path": result["output"]["path"], "output_sha256": result["output"]["sha256"],
            "pair_count": report["conversion"]["pair_count"]}], **{flag: False for flag in FLAGS}}
        recorded = await call(cc, "case_record_step", case_id=cid, skill="flipper-rf-analysis", step="summary",
            status="success", summary="등록 RAW의 제한된 OOK 변환 완료", data=summary, artifacts=[receipt["path"]])
        assert recorded.get("ok"), recorded
        steps = await call(cc, "case_get_step_results", case_id=cid)
        assert steps["summaries"]["flipper-rf-analysis"]["data"] == summary
        final = await call(cc, "report_generate", case_id=cid)
        assert final.get("ok"), final
        assert receipt["path"] in Path(final["path"]).read_text()


@pytest.mark.parametrize("preset", ["Ook270", "Ook650"])
@pytest.mark.parametrize("style", ["plain", "split", "bom-crlf"])
async def test_supported_presets_and_cross_line_pairs(rcase, preset, style):
    from sdr_mcp import server as S
    art = register(rcase, raw(preset=preset, split=style == "split", bom_crlf=style == "bom-crlf"))
    async with Client(S.server) as client:
        result = await call(client, TOOL, **args(rcase, art))
    check_files(rcase, result, OOK_HEADER + b"100 200\n;end\n")
    assert result["report"]["conversion"]["pair_count"] == 1


async def test_actual_1200_pair_boundary(rcase):
    from sdr_mcp import server as S
    art = register(rcase, raw(" ".join(["1 -2"] * 1200)))
    async with Client(S.server) as client:
        result = await call(client, TOOL, **args(rcase, art))
    check_files(rcase, result, OOK_HEADER + b"1 2\n" * 1200 + b";end\n")
    assert result["report"]["conversion"] == {"format": "rtl433-ook-text-v1", "unit": "us",
        "pairing": "positive-negative", "duration_count": 2400, "pair_count": 1200, "total_duration_us": 3600}


@pytest.mark.parametrize(("data", "code"), [
    (raw("1"), "rf_ook_not_convertible"),
    (raw(preset="2FSKDev238"), "rf_ook_not_convertible"),
    (raw("1 -2147483648"), "rf_ook_not_convertible"),
    (raw(" ".join(["1 -2"] * 1201)), "rf_ook_input_limit"),
    (raw() + b"Unknown: field\n", "rf_ook_not_convertible"),
    (raw("1 -2 3"), "rf_ook_not_convertible"),
], ids=["odd-one", "fsk", "magnitude", "pair-limit", "unsupported-field", "odd-three"])
async def test_nonconvertible_has_no_outputs_or_registration(rcase, data, code, caplog):
    from sdr_mcp import server as S
    art = register(rcase, data)
    async with Client(S.server) as client:
        result = await call(client, TOOL, **args(rcase, art))
    assert code in result.get("_error", ""), result
    assert PRIVATE not in json.dumps(result) + caplog.text
    assert len(rcase.artifacts()) == 1
    assert not list((rcase.dir / "analysis").glob("rf-ook-*"))


async def test_tool_registration_is_strict_and_local_write(workspace):
    from sdr_mcp import server as S
    async with Client(S.server) as client:
        tools = {tool.name: tool for tool in (await client.list_tools()).tools}
    assert set(tools) == {"sdr_analyze", "sdr_peaks", TOOL}
    tool = tools[TOOL]
    assert set(tool.input_schema["properties"]) == {"case_id", "artifact_id", "max_seconds"}
    assert set(tool.input_schema["required"]) == {"case_id", "artifact_id"}
    assert tool.input_schema["properties"]["max_seconds"]["default"] == 5
    assert tool.input_schema["additionalProperties"] is False
    assert tool.annotations.read_only_hint is False and tool.annotations.open_world_hint is False
    assert tool.annotations.destructive_hint is False


@pytest.mark.parametrize(("key", "value"), [
    ("case_id", True), ("case_id", 7), ("case_id", "../" + PRIVATE), ("case_id", "x" * 81),
    ("case_id", "valid\n"), ("artifact_id", True), ("artifact_id", 3), ("artifact_id", "A-001"),
    ("artifact_id", "A-123456789"), ("artifact_id", "A-0001\n"), ("artifact_id", PRIVATE),
    ("max_seconds", True), ("max_seconds", "5"), ("max_seconds", 0), ("max_seconds", -1),
    ("max_seconds", 5.001), ("max_seconds", {PRIVATE: PRIVATE}), ("max_seconds", [PRIVATE]),
    (PRIVATE, PRIVATE),
])
async def test_sdk_and_direct_arguments_reject_before_runtime(rcase, monkeypatch, caplog, key, value):
    from sdr_mcp import server as S
    monkeypatch.setattr(S, "rt", lambda: pytest.fail("잘못된 입력에서 Runtime을 조회했습니다."))
    async with Client(S.server) as client:
        result = await call(client, TOOL, **args(rcase, {"id": "A-0001"}, **{key: value}))
    assert "rf_ook_input_invalid" in result.get("_error", ""), result
    assert PRIVATE not in json.dumps(result) + caplog.text


@pytest.mark.parametrize("key", ["case_id", "artifact_id"])
async def test_missing_fields_have_fixed_sdk_error(rcase, monkeypatch, key):
    from sdr_mcp import server as S
    monkeypatch.setattr(S, "rt", lambda: pytest.fail("필수 입력이 없는데 Runtime을 조회했습니다."))
    given = args(rcase, {"id": "A-0001"})
    del given[key]
    async with Client(S.server) as client:
        result = await call(client, TOOL, **given)
    assert "rf_ook_input_invalid" in result.get("_error", ""), result


@pytest.mark.parametrize("value", [float("nan"), float("inf"), -float("inf"), 10 ** 400])
async def test_direct_nonfinite_numbers_are_fixed(rcase, value):
    from sdr_mcp import server as S
    with pytest.raises(Exception) as caught:
        await S.sdr_import_flipper_sub(**args(rcase, {"id": "A-0001"}, max_seconds=value))
    assert "rf_ook_input_invalid" in str(caught.value)


@pytest.mark.parametrize(("mode", "code"), [("missing", "not_found"), ("unauthorized", "authorization_required")])
async def test_case_authorization_meaning_is_preserved(workspace, mode, code):
    from sdr_mcp import server as S
    if mode == "unauthorized":
        S.rt().cases.create(title="미확인 합성", case_id=PRIVATE)
    async with Client(S.server) as client:
        result = await call(client, TOOL, case_id=PRIVATE, artifact_id="A-0001")
    assert code in result.get("_error", ""), result
    assert PRIVATE not in json.dumps(result)


@pytest.mark.parametrize("subdir", ["forensics", "emu"])
async def test_protected_input_stays_rejected(rcase, subdir):
    from sdr_mcp import server as S
    art = register(rcase, subdir=subdir)
    async with Client(S.server) as client:
        result = await call(client, TOOL, **args(rcase, art))
    assert "rf_ook_input_invalid" in result.get("_error", ""), result


@pytest.mark.parametrize("code", ["rf_ook_input_invalid", "rf_ook_input_limit", "rf_ook_input_changed",
    "rf_ook_not_convertible", "rf_ook_failed", "rf_ook_cleanup_incomplete", "cancelled", "time_limit", "unknown_private_code"])
async def test_worker_errors_cannot_leak_original_details(rcase, monkeypatch, caplog, code):
    from sdr_mcp import ook_conversion as W, server as S
    from pweh.errors import PwehError
    def fail(*a, **kw):
        raise PwehError(PRIVATE, code=code, hint=PRIVATE, data={PRIVATE: PRIVATE})
    monkeypatch.setattr(W, "convert_registered_sub", fail)
    async with Client(S.server) as client:
        result = await call(client, TOOL, **args(rcase, {"id": "A-0001"}))
    assert (code if code != "unknown_private_code" else "rf_ook_failed") in result.get("_error", ""), result
    assert PRIVATE not in json.dumps(result) + caplog.text


async def test_deadline_precedes_case_selection_and_uses_dynamic_runtime(rcase, monkeypatch):
    from sdr_mcp import ook_conversion as W, ook_tools as O, server as S
    clock, observed = [100.0], []
    monkeypatch.setattr(O, "time", SimpleNamespace(monotonic=lambda: clock[0]))
    def case(cid, *, hardware):
        assert cid == rcase.id and hardware is True
        clock[0] = 102.0
        return rcase
    def convert(selected, aid, **kw):
        assert selected is rcase and aid == "A-0001"
        observed.append(kw)
        assert kw["deadline"] == 103.5 and kw["max_seconds"] == 3.5 and kw["cancel"]() is False
        return {"ok": True}
    monkeypatch.setattr(S, "rt", lambda: SimpleNamespace(case=case))
    monkeypatch.setattr(W, "convert_registered_sub", convert)
    assert await S.sdr_import_flipper_sub(**args(rcase, {"id": "A-0001"}, max_seconds=3.5)) == {"ok": True}
    assert len(observed) == 1


@pytest.mark.parametrize("warning", ["post_commit_callback_failed", "output_close_unconfirmed"])
async def test_committed_receipt_and_files_survive_warning(rcase, monkeypatch, warning):
    from sdr_mcp import ook_conversion as W, server as S
    art = register(rcase)
    if warning == "post_commit_callback_failed":
        original = type(rcase).register_artifact
        def after_commit(self, *a, **kw):
            original(self, *a, **kw)
            raise RuntimeError(PRIVATE)
        monkeypatch.setattr(type(rcase), "register_artifact", after_commit)
    else:
        original = W._Output.close
        def close(self):
            assert original(self)
            return False
        monkeypatch.setattr(W._Output, "close", close)
    async with Client(S.server) as client:
        result = await call(client, TOOL, **args(rcase, art))
    check_files(rcase, result, OOK_HEADER + b"100 200\n;end\n")
    assert result["warnings"] == [warning]
    assert PRIVATE not in json.dumps(result)


async def test_raw_awaiter_cancel_preserves_worker_owned_fd_until_exit(rcase, monkeypatch):
    from sdr_mcp import ook_conversion as W, server as S
    entered, release, finished = threading.Event(), threading.Event(), threading.Event()
    art = register(rcase)
    held, observed = [], []
    original_open, original_convert, original_worker = W.safeio.open_regular, W.rf_ook.convert_sub_raw_to_ook, W.convert_registered_sub
    def opening(*a, **kw):
        pair = original_open(*a, **kw)
        held.append(pair[0])
        return pair
    def convert(*a, **kw):
        entered.set()
        assert release.wait(5)
        observed.append(kw["cancel"]())
        return original_convert(*a, **kw)
    def work(*a, **kw):
        try:
            return original_worker(*a, **kw)
        finally:
            finished.set()
    monkeypatch.setattr(W.safeio, "open_regular", opening)
    monkeypatch.setattr(W.rf_ook, "convert_sub_raw_to_ook", convert)
    monkeypatch.setattr(W, "convert_registered_sub", work)
    task = asyncio.create_task(S.sdr_import_flipper_sub(**args(rcase, art)))
    try:
        assert await asyncio.to_thread(entered.wait, 5)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        assert not finished.is_set() and len(held) == 1
        assert os.fstat(held[0]).st_size == len(raw())
    finally:
        release.set()
        assert await asyncio.to_thread(finished.wait, 5)
    assert observed == [True]
    with pytest.raises(OSError):
        os.fstat(held[0])
    assert len(rcase.artifacts()) == 1 and not list((rcase.dir / "analysis").glob("rf-ook-*"))


async def test_conversion_is_offline_without_provenance_or_external_calls(rcase, monkeypatch):
    from sdr_mcp import server as S
    from pweh import hostenv
    import serial
    import socket
    import subprocess
    art = register(rcase)
    async with Client(S.server) as client:
        def forbidden(*a, **kw):
            pytest.fail("로컬 변환에서 장치·외부 실행·출처 증명을 호출했습니다.")
        for module, names in [(subprocess, ("Popen", "run")), (socket, ("create_connection",)),
                              (serial, ("Serial", "serial_for_url")), (hostenv, ("detect",))]:
            for name in names:
                monkeypatch.setattr(module, name, forbidden)
        for name in ("entries", "verify", "record_import"):
            monkeypatch.setattr(S.rt().provenance, name, forbidden)
        result = await call(client, TOOL, **args(rcase, art))
    assert result.get("ok"), result


@pytest.mark.parametrize("failure", ["missing", "rebuild", "schema"])
async def test_private_sdk_failure_is_fixed_and_fail_closed(workspace, monkeypatch, failure):
    from sdr_mcp import ook_tools as O, server as S
    if failure == "missing":
        instance = SimpleNamespace(_tool_manager=SimpleNamespace(get_tool=lambda name: None))
    else:
        model = S.server._tool_manager.get_tool(TOOL).fn_metadata.arg_model
        def fail(*a, **kw):
            raise RuntimeError(PRIVATE)
        monkeypatch.setattr(model, "model_rebuild" if failure == "rebuild" else "model_json_schema", fail)
        instance = S.server
    with pytest.raises(RuntimeError) as caught:
        O._configure_input(instance)
    assert PRIVATE not in str(caught.value) and "비공개 입력 검증 설정" in str(caught.value)
