"""저장 PNG 비교의 strict MCP 입구·실제 정규화 산출물·요약 연결."""

from __future__ import annotations

import asyncio
import copy
import hashlib
import io
import json
import stat
import threading
from pathlib import Path
from types import SimpleNamespace

import pytest
from mcp import Client

from mcp_helpers import call

pytestmark = pytest.mark.anyio
PRIVATE = "PRIVATE_TEMPLATE_4c12"
FLAGS = ("frame_freshness_verified", "game_semantics_verified", "action_generated")
FIELDS = ("case_id", "reference_artifact_id", "reference_preview_index", "reference_roi",
          "candidate_artifact_id", "candidate_preview_index", "candidate_roi", "max_mean_error")


@pytest.fixture
def anyio_backend():
    return "asyncio"


@pytest.fixture
def tcase(workspace, auth):
    from play_mcp import server as S
    return S.rt().cases.create(title="저장 PNG 합성 비교", case_id="template-synthetic", authorization=auth)


def args(case, **changes):
    value = dict(case_id=case.id, reference_artifact_id="A-0001", reference_preview_index=0,
                 reference_roi=[1, 2, 2, 3], candidate_artifact_id="A-0002", candidate_preview_index=0,
                 candidate_roi=[3, 4, 2, 3], max_mean_error=3)
    value.update(changes)
    return value


def tool():
    from play_mcp import server as S
    return S.server._tool_manager.get_tool("vision_template_match")


def png(color):
    from PIL import Image, PngImagePlugin
    out = io.BytesIO()
    meta = PngImagePlugin.PngInfo()
    meta.add_text("comment", PRIVATE)
    Image.new("RGB", (12, 10), color).save(out, format="PNG", pnginfo=meta)
    return out.getvalue()


async def normalize(cc, case, name, color):
    # 실제 case 도구/worker가 정규화·등록한 보고서 ID를 색인에서 찾는다.
    (case.dir / name).write_bytes(png(color))
    result = await call(cc, "case_image_hints", case_id=case.id, path=name,
                        ocr=False, qr=False, preview=True, crop=[1, 1, 8, 8])
    assert result.get("ok"), result
    assert "artifact_id" not in result["analysis"]
    listed = await call(cc, "case_get", case_id=case.id, include_artifacts=True)
    matches = [a for a in listed["artifacts"] if a["path"] == result["analysis"]["path"]
               and a["sha256"] == result["analysis"]["sha256"] and a["size"] == result["analysis"]["size"]
               and a["kind"] == "image-hints" and a["producer"] == "pweh-case"]
    assert len(matches) == 1
    return matches[0], result, listed["artifacts"]


async def test_actual_normalized_png_comparison_artifact_summary_and_report(tcase, caplog):
    from case_mcp import server as C
    from play_mcp import server as S
    from pweh import schemas

    async with Client(C.server) as cc, Client(S.server) as client:
        reference, rh, _ = await normalize(cc, tcase, PRIVATE + "-reference.png", (10, 20, 30))
        candidate, ch, listed = await normalize(cc, tcase, PRIVATE + "-candidate.png", (13, 24, 35))
        inputs = args(tcase, reference_artifact_id=reference["id"], candidate_artifact_id=candidate["id"],
                      candidate_preview_index=1)
        audit = tcase.dir / "audit.jsonl"
        audit_start = audit.stat().st_size
        result = await call(client, "vision_template_match", **inputs)
        assert set(result) == {"ok", "report", "artifact_id", "analysis_path", "sha256", "size", "warnings"}, result
        assert result["ok"] and result["warnings"] == []
        report = result["report"]
        assert report["result"] == {"samples": 18, "sum_abs": 72, "mean_abs_error": 4.0, "matched": False}
        assert all(report[key] is False for key in FLAGS)
        schemas.validate("template-match", report)
        for label, row, hint, index in (("reference", reference, rh, 0), ("candidate", candidate, ch, 1)):
            preview = hint["report"]["artifacts"]["previews"][index]
            pa = next(a for a in listed if a["path"] == preview["path"])
            expected = {"report": {"artifact_id": row["id"], "sha256": row["sha256"], "size": row["size"]},
                        "preview": {"index": index, "artifact_id": pa["id"], "sha256": pa["sha256"],
                                    "size": pa["size"], "width": preview["width"], "height": preview["height"],
                                    "role": preview["role"]}}
            assert report["sources"][label] == expected
            assert stat.S_IMODE((tcase.dir / preview["path"]).stat().st_mode) == 0o444
        path = tcase.dir / result["analysis_path"]
        assert json.loads(path.read_bytes()) == report
        assert stat.S_IMODE(path.stat().st_mode) == 0o444
        assert path.stat().st_size == result["size"] <= 64 << 10
        assert hashlib.sha256(path.read_bytes()).hexdigest() == result["sha256"]
        artifact = next(a for a in tcase.load()["artifacts"] if a["id"] == result["artifact_id"])
        assert artifact["extra"] == {"type": "template-match"} and artifact["producer"] == "pweh-play"
        assert artifact["path"] == result["analysis_path"] and artifact["sha256"] == result["sha256"]
        visible = json.dumps(result) + path.read_text() + audit.read_bytes()[audit_start:].decode() + caplog.text
        assert PRIVATE not in visible and "base64" not in json.dumps(report) and "timestamp" not in json.dumps(report)
        boundary = await call(client, "vision_template_match", **{**inputs, "max_mean_error": 4})
        assert boundary.get("ok") and boundary["report"]["result"]["matched"] is True, boundary
        identical = await call(client, "vision_template_match", **{**inputs,
            "candidate_artifact_id": reference["id"], "candidate_preview_index": 0,
            "candidate_roi": inputs["reference_roi"], "max_mean_error": 0})
        assert identical.get("ok") and identical["report"]["result"]["sum_abs"] == 0, identical
        assert identical["report"]["result"]["matched"] is True
        summary = {"schema": "pweh.template-analysis/v1", "results": [{
            "artifact_id": result["artifact_id"], "analysis_path": result["analysis_path"],
            "report_sha256": result["sha256"], "matched": False}], **{key: False for key in FLAGS}}
        schemas.validate("template-analysis", summary)
        recorded = await call(cc, "case_record_step", case_id=tcase.id, skill="image-template-analysis",
                              step="summary", status="success", summary="저장 PNG 차이 계산 완료",
                              data=summary, artifacts=[result["analysis_path"]])
        assert recorded.get("ok"), recorded
        steps = await call(cc, "case_get_step_results", case_id=tcase.id)
        assert steps["summaries"]["image-template-analysis"]["data"] == summary
        final = await call(cc, "report_generate", case_id=tcase.id)
        assert final.get("ok") and result["analysis_path"] in Path(final["path"]).read_text(), final
        assert (await call(cc, "schema_get", name="template-match")).get("ok")


async def test_tools_schema_is_closed_and_all_eight_fields_required(workspace):
    from play_mcp import server as S
    async with Client(S.server) as client:
        selected = next(t for t in (await client.list_tools()).tools if t.name == "vision_template_match")
    schema = selected.input_schema
    assert set(schema["properties"]) == set(schema["required"]) == set(FIELDS)
    assert schema["additionalProperties"] is False
    assert selected.annotations.read_only_hint is False and selected.annotations.open_world_hint is False


@pytest.mark.parametrize("field,value", [
    ("case_id", "../" + PRIVATE), ("case_id", True), ("case_id", "a" * 81),
    ("reference_artifact_id", PRIVATE), ("candidate_artifact_id", "A-0001\n"),
    ("reference_artifact_id", "A-001"), ("candidate_artifact_id", "A-123456789"),
    ("reference_preview_index", True), ("reference_preview_index", 1.0),
    ("candidate_preview_index", "0"), ("candidate_preview_index", 2), ("candidate_preview_index", -1),
    ("reference_roi", "[1,2,2,3]"), ("reference_roi", {PRIVATE: PRIVATE}),
    ("reference_roi", None), ("reference_roi", [1, 2, 2]), ("reference_roi", [1, 2, 2, 3, 4]),
    ("reference_roi", [True, 2, 2, 3]), ("reference_roi", [1.0, 2, 2, 3]),
    ("candidate_roi", [1, 2, "2", 3]), ("candidate_roi", [-1, 2, 2, 3]),
    ("candidate_roi", [1601, 2, 2, 3]), ("candidate_roi", [1, 2, 0, 3]),
    ("candidate_roi", [1, 2, 2, 1601]), ("candidate_roi", [1, 2, 3, 3]),
    ("max_mean_error", True), ("max_mean_error", 3.0), ("max_mean_error", "3"),
    ("max_mean_error", -1), ("max_mean_error", 256),
])
async def test_invalid_raw_sdk_arguments_do_not_reach_runtime(tcase, monkeypatch, caplog, field, value):
    from play_mcp import server as S
    monkeypatch.setattr(S, "rt", lambda: pytest.fail("불량 입력이 runtime에 도달했습니다."))
    async with Client(S.server) as client:
        result = await call(client, "vision_template_match", **args(tcase, **{field: value}))
    assert "template_input_invalid" in result.get("_error", ""), result
    assert PRIVATE not in json.dumps(result) + caplog.text


@pytest.mark.parametrize("field", FIELDS)
async def test_each_required_argument_missing_is_fixed(tcase, monkeypatch, field):
    from play_mcp import server as S
    given = args(tcase)
    del given[field]
    monkeypatch.setattr(S, "rt", lambda: pytest.fail("누락 입력이 runtime에 도달했습니다."))
    async with Client(S.server) as client:
        result = await call(client, "vision_template_match", **given)
    assert "template_input_invalid" in result.get("_error", ""), result


async def test_extra_raw_key_and_metadata_tuple_nonfinite_are_private(tcase, monkeypatch, caplog):
    from play_mcp import server as S
    monkeypatch.setattr(S, "rt", lambda: pytest.fail("추가 키 입력이 runtime에 도달했습니다."))
    async with Client(S.server) as client:
        result = await call(client, "vision_template_match", **args(tcase, **{PRIVATE: {PRIVATE: PRIVATE}}))
    assert "template_input_invalid" in result.get("_error", "") and PRIVATE not in json.dumps(result) + caplog.text
    meta = tool().fn_metadata
    for value in ((1, 2, 2, 3), [1, float("nan"), 2, 3], [1, float("inf"), 2, 3]):
        with pytest.raises(Exception) as caught:
            meta.validate_arguments(args(tcase, reference_roi=value))
        assert "template_input_invalid" in str(caught.value) and PRIVATE not in str(caught.value)


@pytest.mark.parametrize("code", ["template_input_invalid", "template_input_limit", "template_input_changed",
    "template_output_invalid", "template_failed", "template_cleanup_incomplete", "time_limit", "cancelled", "unexpected"])
async def test_worker_error_code_survives_without_original_details(tcase, monkeypatch, caplog, code):
    from play_mcp import server as S, template_analysis as B
    from pweh.errors import PwehError
    def fail(*a, **kw):
        raise PwehError(PRIVATE, code=code, data={PRIVATE: PRIVATE}, hint=PRIVATE)
    monkeypatch.setattr(B, "match_registered_previews", fail)
    async with Client(S.server) as client:
        result = await call(client, "vision_template_match", **args(tcase))
    assert ("template_failed" if code == "unexpected" else code) in result.get("_error", ""), result
    assert PRIVATE not in json.dumps(result) + caplog.text


@pytest.mark.parametrize("mode,code", [("missing", "not_found"), ("unauthorized", "authorization_required")])
async def test_case_authorization_is_checked_before_file_worker(workspace, monkeypatch, mode, code):
    from play_mcp import server as S, template_analysis as B
    if mode == "unauthorized":
        S.rt().cases.create(title="소유 미확인", case_id=PRIVATE)
    monkeypatch.setattr(B, "match_registered_previews", lambda *a, **kw: pytest.fail("허가 없는 입력을 읽었습니다."))
    async with Client(S.server) as client:
        result = await call(client, "vision_template_match", **args(SimpleNamespace(id=PRIVATE)))
    assert code in result.get("_error", "") and PRIVATE not in json.dumps(result), result


async def test_deadline_precedes_case_lookup_and_rois_are_frozen(tcase, monkeypatch):
    from play_mcp import server as S, template_tools as T, template_analysis as B
    clock = [100.0]
    monkeypatch.setattr(T, "time", SimpleNamespace(monotonic=lambda: clock[0]))
    def case(case_id, *, hardware):
        assert case_id == tcase.id and hardware is True
        clock[0] = 104.0
        return tcase
    def compare(selected, rid, ri, rr, cid, ci, cr, threshold, *, deadline, cancel_event):
        assert selected is tcase and type(rr) is tuple and type(cr) is tuple
        assert rr == (1, 2, 2, 3) and cr == (3, 4, 2, 3)
        assert deadline == 105 and threshold == 3 and not cancel_event.is_set()
        return {"ok": True}
    monkeypatch.setattr(S, "rt", lambda: SimpleNamespace(case=case))
    monkeypatch.setattr(B, "match_registered_previews", compare)
    assert await tool().fn(**args(tcase)) == {"ok": True}


async def test_raw_cancel_sets_same_worker_event_without_caller_close(tcase, monkeypatch):
    from play_mcp import template_analysis as B
    entered, release, finished = threading.Event(), threading.Event(), threading.Event()
    seen = []
    def compare(*a, **kw):
        entered.set()
        try:
            assert release.wait(5)
            seen.append(kw["cancel_event"].is_set())
            return {"ok": True}
        finally:
            finished.set()
    monkeypatch.setattr(B, "match_registered_previews", compare)
    task = asyncio.create_task(tool().fn(**args(tcase)))
    try:
        assert await asyncio.to_thread(entered.wait, 5)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        assert not finished.is_set()
    finally:
        release.set()
        assert await asyncio.to_thread(finished.wait, 5)
    assert seen == [True]


@pytest.mark.parametrize("warnings", [[], ["post_commit_callback_failed"], ["output_close_unconfirmed"],
                                    ["post_commit_callback_failed", "output_close_unconfirmed"]])
async def test_postcommit_receipt_and_warnings_are_preserved(tcase, monkeypatch, warnings):
    from play_mcp import server as S, template_analysis as B
    receipt = {"ok": True, "report": report_fixture(), "artifact_id": "A-0005",
               "analysis_path": "analysis/template-match-001.json", "sha256": "a" * 64, "size": 1600,
               "warnings": warnings}
    monkeypatch.setattr(B, "match_registered_previews", lambda *a, **kw: receipt)
    async with Client(S.server) as client:
        result = await call(client, "vision_template_match", **args(tcase))
    assert result == receipt


async def test_real_adapter_rejects_absent_artifact_before_png_worker(tcase, monkeypatch):
    from play_mcp import server as S
    from pweh import imagehints
    monkeypatch.setattr(imagehints, "match_png_rois", lambda *a, **kw: pytest.fail("등록 없는 PNG를 해독했습니다."))
    async with Client(S.server) as client:
        result = await call(client, "vision_template_match", **args(tcase))
    assert "template_input_invalid" in result.get("_error", ""), result
    assert not list((tcase.dir / "analysis").glob("template-match-*"))


def report_fixture():
    source = {"report": {"artifact_id": "A-0001", "sha256": "a" * 64, "size": 1000},
              "preview": {"index": 0, "artifact_id": "A-0002", "sha256": "b" * 64, "size": 100,
                          "width": 12, "height": 10, "role": "overview"}}
    return {"schema": "pweh.template-match/v1", "profile": "stored-png-roi-rgb-mae-v1",
            "sources": {"reference": copy.deepcopy(source), "candidate": copy.deepcopy(source)},
            "reference_roi": [1, 2, 2, 3], "candidate_roi": [3, 4, 2, 3], "max_mean_error": 3,
            "result": {"sum_abs": 72, "samples": 18, "mean_abs_error": 4.0, "matched": False},
            **{key: False for key in FLAGS}, "limitations": ["stored_preview_pixels_only",
                "equal_roi_dimensions_only", "rgb_mean_absolute_error_only", "no_frame_freshness_verification",
                "no_game_semantics_verification", "no_action_generation"]}


def change(doc, path, value):
    for key in path[:-1]:
        doc = doc[key]
    doc[path[-1]] = value


@pytest.mark.parametrize("path,value", [
    (("schema",), "pweh.image-hints/v1"), (("profile",), PRIVATE), ((PRIVATE,), PRIVATE),
    (("sources", "reference", PRIVATE), PRIVATE), (("sources", "candidate", "report", "path"), PRIVATE),
    (("sources", "reference", "report", "artifact_id"), "A-0001\n"),
    (("sources", "reference", "report", "sha256"), "a" * 64 + "\n"),
    (("sources", "reference", "report", "size"), (8 << 20) + 1),
    (("sources", "candidate", "preview", "size"), (1 << 20) + 1),
    (("sources", "candidate", "preview", "index"), 2),
    (("sources", "candidate", "preview", "width"), 1601),
    (("sources", "candidate", "preview", "role"), PRIVATE),
    (("reference_roi",), [0, 0, 0, 1]), (("candidate_roi",), [0, 0, 1, 1, 2]),
    (("max_mean_error",), True), (("max_mean_error",), 256),
    (("result", "samples"), 7680001), (("result", "sum_abs"), 1958400001),
    (("result", "mean_abs_error"), 256), (("result", "matched"), 1),
    (("frame_freshness_verified",), True), (("game_semantics_verified",), True),
    (("action_generated",), True), (("limitations",), []),
])
def test_report_schema_is_closed_and_bounded(path, value):
    from pweh import schemas
    doc = report_fixture()
    schemas.validate("template-match", doc)
    change(doc, path, value)
    with pytest.raises(Exception):
        schemas.validate("template-match", doc)


def test_summary_schema_closed_rows_and_endpoint_bounds():
    from pweh import schemas
    row = {"artifact_id": "A-0005", "analysis_path": "analysis/template-match-001.json",
           "report_sha256": "a" * 64, "matched": False}
    summary = {"schema": "pweh.template-analysis/v1", "results": [row], **{key: False for key in FLAGS}}
    schemas.validate("template-analysis", summary)
    schemas.validate("template-analysis", {**summary, "results": [row] * 128})
    for rows in ([], [row] * 129, [{**row, "matched": 0}], [{**row, "status": "ok"}],
                 [{**row, "analysis_path": row["analysis_path"] + "\n"}],
                 [{**row, "report_sha256": "A" * 64}], [{**row, "artifact_id": "A-0005\n"}]):
        with pytest.raises(Exception):
            schemas.validate("template-analysis", {**summary, "results": rows})
    for flag in FLAGS:
        with pytest.raises(Exception):
            schemas.validate("template-analysis", {**summary, flag: True})
