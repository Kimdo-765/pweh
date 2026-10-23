"""실제 Client의 가져온 세이브 계획·strict JSON·출처와 commit 경계를 확인한다."""

from __future__ import annotations

import asyncio
import copy
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
PRIVATE = "PRIVATE_IMPORTED_SAVE_4e21"
TOOL = "fw_plan_imported_save"
FLAGS = ("device_association_verified", "independent_backup_verified", "write_address_verified",
         "write_ready", "device_written", "game_acceptance_verified")


@pytest.fixture
def anyio_backend():
    return "asyncio"


@pytest.fixture
def scase(workspace, auth):
    from fwtriage_mcp import server as S
    return S.rt().cases.create(title="합성 로컬 계획", case_id="imported-save-test", authorization=auth)


def save():
    data = bytearray(64)
    data[0:4] = b"SAVE"
    data[4:6] = (7).to_bytes(2, "little")
    data[60:64] = sum(data[:60]).to_bytes(4, "little")
    return bytes(data)


def args(case, art="A-0001", **changes):
    out = {"case_id": case.id, "artifact_id": art, "offset": 0, "length": 64,
           "edits": [{"offset": 4, "encoding": "u16le", "value": 42}], "purpose": "score",
           "unlock_source": "in-device", "online_capable": "no",
           "checksum": {"algorithm": "sum32", "endian": "le", "location": 60, "range": [0, 60]}}
    out.update(changes)
    return out


async def imported(case, tmp_path, data=None):
    from case_mcp import server as C
    source = tmp_path / (PRIVATE + ".bin")
    source.write_bytes(save() if data is None else data)
    async with Client(C.server) as client:
        result = await call(client, "case_import_file", case_id=case.id, source_path=str(source), kind="other")
        assert result.get("ok"), result
        index = await call(client, "case_get", case_id=case.id, include_artifacts=True)
    art = next(a for a in index["artifacts"] if a["path"] == result["artifact"]["path"])
    return art


def direct():
    from fwtriage_mcp import server as S
    return S.server._tool_manager.get_tool(TOOL).fn


async def test_actual_import_plan_summary_report(workspace, auth, tmp_path, caplog):
    from case_mcp import server as C
    from fwtriage_mcp import server as S
    from pweh import schemas
    async with Client(C.server) as cc:
        created = await call(cc, "case_create", title="합성 저장 계획", case_id="save-client", authorization=auth)
        assert created.get("ok"), created
    case = S.rt().case("save-client")
    art = await imported(case, tmp_path)
    before = S.rt().provenance.entries(case)
    original = (case.dir / art["path"]).read_bytes()
    audit = case.dir / "audit.jsonl"
    audit_start = audit.stat().st_size
    async with Client(S.server) as client, Client(C.server) as cc:
        result = await call(client, TOOL, **args(case, art["id"]))
        assert result.get("ok"), result
        assert set(result) == {"ok", "stage", "report", "analysis", "patch", "warnings"}
        assert result["stage"] == "planned" and result["warnings"] == []
        report = result["report"]
        schemas.validate("imported-save-plan", report)
        assert all(report[k] is False for k in FLAGS)
        assert report["edits"] == [{"offset": 4, "encoding": "u16le", "before_value": 7,
                                     "after_value": 42, "in_checksum_range": True}]
        assert report["source"]["artifact_id"] == art["id"]
        assert set(report["source"]) == {"kind", "artifact_id", "size", "sha256", "import_provenance"}
        metadata = case.dir / result["analysis"]["path"]
        patch = case.dir / result["patch"]["path"]
        assert json.loads(metadata.read_bytes()) == report
        for path, item in ((metadata, result["analysis"]), (patch, result["patch"])):
            assert path.stat().st_size == item["size"]
            assert hashlib.sha256(path.read_bytes()).hexdigest() == item["sha256"]
            assert stat.S_IMODE(path.stat().st_mode) == 0o444
        after = patch.read_bytes()
        assert len(after) == 64 and after[:4] == original[:4] and after[6:60] == original[6:60]
        assert int.from_bytes(after[60:], "little") == sum(after[:60])
        assert (case.dir / art["path"]).read_bytes() == original
        assert {p.name for p in patch.parent.iterdir()} == {"planned.bin", "manifest.json"}
        new = [a for a in case.load()["artifacts"] if a["id"] != art["id"]]
        assert len(new) == 1 and new[0]["id"] == result["analysis"]["artifact_id"]
        assert new[0]["kind"] == "triage-report" and new[0]["producer"] == "fwtriage-mcp"
        assert new[0]["extra"] == {"type": "imported-save-plan"}
        assert S.rt().provenance.entries(case) == before
        assert PRIVATE not in json.dumps(result) + metadata.read_text() + audit.read_bytes()[audit_start:].decode() + caplog.text
        summary = {"device": {"kind": "other"}, "firmware": {"path": art["path"]}, "saves": [],
                   "unlock_conditions": [], "online_capable": "no", "patches": [],
                   "local_plans": [{"analysis_path": result["analysis"]["path"],
                        "report_sha256": result["analysis"]["sha256"], "patch_path": result["patch"]["path"],
                        "patch_sha256": result["patch"]["sha256"], "input_artifact_id": art["id"], "stage": "planned"}]}
        recorded = await call(cc, "case_record_step", case_id=case.id, skill="game-save-unlock-analysis",
                              step="summary", status="success", summary="로컬 계획 생성", data=summary,
                              artifacts=[result["analysis"]["path"]])
        assert recorded.get("ok"), recorded
        steps = await call(cc, "case_get_step_results", case_id=case.id)
        assert steps["summaries"]["game-save-unlock-analysis"]["data"] == summary
        final = await call(cc, "report_generate", case_id=case.id)
        assert final.get("ok"), final
        assert result["analysis"]["path"] in Path(final["path"]).read_text()


@pytest.mark.parametrize("mode", ["nonzero", "null", "bcd"])
async def test_absolute_range_and_optional_checksum(scase, tmp_path, mode):
    from fwtriage_mcp import server as S
    data = b"BEFORE00" + save() + b"AFTEREND" if mode == "nonzero" else save()
    given = args(scase)
    if mode == "nonzero":
        given.update(offset=8, edits=[{"offset": 12, "encoding": "u16le", "value": 42}],
                     checksum={"algorithm": "sum32", "endian": "le", "location": 68, "range": [8, 68]})
    else:
        given["checksum"] = None
        if mode == "bcd":
            data = data[:4] + b"\xfa\xff" + data[6:]
            given["edits"] = [{"offset": 4, "encoding": "bcd2le", "value": 42}]
    art = await imported(scase, tmp_path, data)
    given["artifact_id"] = art["id"]
    async with Client(S.server) as client:
        result = await call(client, TOOL, **given)
    assert result.get("ok"), result
    row = result["report"]["edits"][0]
    if mode == "nonzero":
        assert row["offset"] == 12 and result["report"]["checksum"]["location"] == 68
        output = (scase.dir / result["patch"]["path"]).read_bytes()
        assert output[:8] == data[:8] and output[-8:] == data[-8:]
    else:
        assert row["in_checksum_range"] is None and result["report"]["checksum"] is None
        if mode == "bcd": assert row["before_value"] is None


async def test_tools_list_has_only_eight_required_two_optional(workspace):
    from fwtriage_mcp import server as S
    async with Client(S.server) as client:
        tools = (await client.list_tools()).tools
    tool = next(t for t in tools if t.name == TOOL)
    schema = tool.input_schema
    assert set(schema["properties"]) == {"case_id", "artifact_id", "offset", "length", "edits", "purpose",
                                         "unlock_source", "online_capable", "checksum", "max_seconds"}
    assert set(schema["required"]) == set(schema["properties"]) - {"checksum", "max_seconds"}
    assert schema["additionalProperties"] is False
    assert tool.annotations.read_only_hint is False and tool.annotations.open_world_hint is False


BAD = [
    ("case_id", PRIVATE + "\n"), ("artifact_id", "A-0001\n"), ("artifact_id", "A-001"),
    ("offset", True), ("offset", 0.0), ("offset", "0"), ("offset", -1), ("offset", 8388608),
    ("length", 0), ("length", 8388609), ("length", False), ("length", "64"),
    ("edits", None), ("edits", []), ("edits", "[]"), ("edits", [{}]),
    ("edits", [{"offset": 4, "encoding": "u8", "value": 256}]),
    ("edits", [{"offset": 4, "encoding": "u16le", "value": True}]),
    ("edits", [{"offset": 4, "encoding": "u16le", "value": 1.0}]),
    ("edits", [{"offset": 4, "encoding": "u16le", "value": "42"}]),
    ("edits", [{"offset": 63, "encoding": "u16le", "value": 42}]),
    ("edits", [{"offset": 4, "encoding": "hex", "value": 42}]),
    ("edits", [{"offset": 4, "encoding": "bcd2le", "value": 10000}]),
    ("edits", [{"offset": 4, "encoding": "u16le", "value": 42, PRIVATE: PRIVATE}]),
    ("checksum", "null"), ("checksum", "{}"), ("checksum", {}),
    ("checksum", {"algorithm": "sum8", "endian": "le", "location": 60, "range": [0, 60]}),
    ("checksum", {"algorithm": "sum32", "endian": None, "location": 60, "range": [0, 60]}),
    ("checksum", {"algorithm": "sum32", "endian": "le", "location": 60, "range": "[0,60]"}),
    ("checksum", {"algorithm": "sum32", "endian": "le", "location": 60, "range": [False, 60]}),
    ("checksum", {"algorithm": "sum32", "endian": "le", "location": 60, "range": [0, 64]}),
    ("checksum", {"algorithm": "sum32", "endian": "le", "location": 60, "range": [0, 60], PRIVATE: PRIVATE}),
    ("purpose", PRIVATE), ("unlock_source", "sold-token"), ("online_capable", "yes"),
    ("max_seconds", 0), ("max_seconds", 31), ("max_seconds", "30"), ("max_seconds", True),
]


@pytest.mark.parametrize("field,value", BAD)
async def test_actual_client_strict_invalid_never_enters_runtime(scase, monkeypatch, caplog, field, value):
    from fwtriage_mcp import server as S
    given = args(scase, **{field: value})
    monkeypatch.setattr(S, "rt", lambda: pytest.fail("잘못된 입력이 runtime에 도달했습니다."))
    caplog.set_level(logging.INFO)
    async with Client(S.server) as client:
        result = await call(client, TOOL, **given)
    assert "imported_save_input_invalid" in result.get("_error", ""), result
    assert PRIVATE not in json.dumps(result) + caplog.text


@pytest.mark.parametrize("field", list(args(SimpleNamespace(id="case")))[:8])
async def test_missing_required_is_fixed(scase, field):
    from fwtriage_mcp import server as S
    given = args(scase)
    del given[field]
    async with Client(S.server) as client:
        result = await call(client, TOOL, **given)
    assert "imported_save_input_invalid" in result.get("_error", ""), result


async def test_extra_root_and_json_container_strings_use_root_error(scase, caplog):
    from fwtriage_mcp import server as S
    meta = S.server._tool_manager.get_tool(TOOL).fn_metadata
    for change in ({PRIVATE: PRIVATE}, {"edits": json.dumps(args(scase)["edits"])},
                   {"checksum": json.dumps(args(scase)["checksum"])}):
        given = args(scase, **change)
        with pytest.raises(Exception) as caught: meta.validate_arguments(given)
        assert caught.value.errors()[0]["loc"] == ()
        assert PRIVATE not in str(caught.value)
        async with Client(S.server) as client:
            result = await call(client, TOOL, **given)
        assert "imported_save_input_invalid" in result.get("_error", "")
        assert PRIVATE not in json.dumps(result) + caplog.text


@pytest.mark.parametrize("value", [float("nan"), float("inf"), -float("inf"), 10**400])
async def test_direct_nonfinite_seconds_rejected(scase, value):
    with pytest.raises(Exception) as caught: await direct()(**args(scase, max_seconds=value))
    assert "imported_save_input_invalid" in str(caught.value)


@pytest.mark.parametrize("change", [
    {"edits": [{"offset": 4, "encoding": "u16le", "value": 9}]*17},
    {"edits": [{"offset": 4, "encoding": "u16le", "value": 9}, {"offset": 5, "encoding": "u8", "value": 1}]},
    {"offset": 8388607, "length": 2},
    {"edits": [{"offset": 60, "encoding": "u8", "value": 9}]},
])
async def test_cross_field_invalid_before_runtime(scase, monkeypatch, change):
    from fwtriage_mcp import server as S
    monkeypatch.setattr(S, "rt", lambda: pytest.fail("관계 검사 전에 runtime에 도달했습니다."))
    async with Client(S.server) as client:
        result = await call(client, TOOL, **args(scase, **change))
    assert "imported_save_input_invalid" in result.get("_error", ""), result


@pytest.mark.parametrize("code", ["imported_save_input_invalid", "imported_save_input_limit", "imported_save_input_changed",
    "imported_save_no_changes", "imported_save_failed", "imported_save_cleanup_incomplete", "cancelled", "time_limit", "unexpected"])
async def test_worker_error_projection(scase, monkeypatch, caplog, code):
    from fwtriage_mcp import server as S, imported_save_plan as A
    from pweh.errors import PwehError
    def fail(*a, **kw): raise PwehError(PRIVATE, code=code, data={PRIVATE: PRIVATE}, hint=PRIVATE)
    monkeypatch.setattr(A, "plan_imported_save", fail)
    async with Client(S.server) as client:
        result = await call(client, TOOL, **args(scase))
    assert ("imported_save_failed" if code == "unexpected" else code) in result.get("_error", ""), result
    assert PRIVATE not in json.dumps(result) + caplog.text


@pytest.mark.parametrize("mode,code", [("missing", "not_found"), ("unauthorized", "authorization_required")])
async def test_case_error_projection(workspace, mode, code):
    from fwtriage_mcp import server as S
    if mode == "unauthorized": S.rt().cases.create(title="미확인", case_id=PRIVATE)
    async with Client(S.server) as client:
        result = await call(client, TOOL, **args(SimpleNamespace(id=PRIVATE)))
    assert code in result.get("_error", ""), result
    assert PRIVATE not in json.dumps(result)


async def test_deadline_starts_before_case_and_snapshot_is_detached(scase, monkeypatch):
    from fwtriage_mcp import server as S, imported_save_tools as B, imported_save_plan as A
    clock = [100.0]
    original = args(scase)
    monkeypatch.setattr(B, "time", SimpleNamespace(monotonic=lambda: clock[0]))
    def case(cid, *, hardware):
        assert hardware and cid == scase.id
        clock[0] = 103.0
        return scase
    def plan(ns, selected, aid, **kw):
        assert ns is S and selected is scase and aid == "A-0001"
        assert kw["deadline"] == 130 and not kw["cancel"]()
        assert kw["edits"] == original["edits"] and kw["edits"] is not original["edits"]
        assert kw["checksum"]["range"] == [0, 60] and kw["checksum"]["range"] is not original["checksum"]["range"]
        return {"ok": True}
    monkeypatch.setattr(S, "rt", lambda: SimpleNamespace(case=case))
    monkeypatch.setattr(A, "plan_imported_save", plan)
    assert await direct()(**original) == {"ok": True}


async def test_fake_producer_without_import_cannot_plan(scase):
    from fwtriage_mcp import server as S
    path = scase.dir / "dumps" / "fake.bin"
    path.write_bytes(save())
    art = scase.register_artifact(path, kind="other", producer="case-mcp", extra={"imported_from": PRIVATE})
    async with Client(S.server) as client:
        result = await call(client, TOOL, **args(scase, art["id"]))
    assert "imported_save_input_invalid" in result.get("_error", ""), result
    assert len(scase.load()["artifacts"]) == 1


async def test_no_provenance_verification_or_new_attestation(scase, tmp_path, monkeypatch):
    from fwtriage_mcp import server as S
    art = await imported(scase, tmp_path)
    ledger = S.rt().provenance
    before = ledger.entries(scase)
    def forbidden(*a, **kw): pytest.fail("로컬 계획이 출처 승격 또는 새 증명을 요청했습니다.")
    for method in ("verify", "facts", "record_import"):
        monkeypatch.setattr(ledger, method, forbidden)
    async with Client(S.server) as client:
        result = await call(client, TOOL, **args(scase, art["id"]))
    assert result.get("ok"), result
    assert ledger.entries(scase) == before


async def test_import_and_plan_are_not_operational_esp_inputs(scase, tmp_path):
    from fwtriage_mcp import server as S
    art = await imported(scase, tmp_path)
    async with Client(S.server) as client:
        result = await call(client, TOOL, **args(scase, art["id"]))
        assert result.get("ok"), result
        for path in (art["path"], result["patch"]["path"]):
            refused = await call(client, "fw_patch_build", case_id=scase.id, base_path=path,
                target={"type": "raw-region", "partition": "gamedata"}, edits=[{"offset": 4, "encoding": "u16le", "value": 42}],
                purpose="score", unlock_source="in-device", online_capable="no")
            assert "_error" in refused and "출처" in refused["_error"], refused
            verify = await call(client, "fw_verify_writeback", case_id=scase.id, patch_path=path, readback_path=path)
            assert "_error" in verify and "출처 원장" in verify["_error"], verify


async def test_raw_cancel_keeps_worker_fd_until_release(scase, tmp_path, monkeypatch):
    from fwtriage_mcp import imported_save_plan as A
    from pweh.errors import PwehError
    art = await imported(scase, tmp_path)
    entered, release, finished = threading.Event(), threading.Event(), threading.Event()
    descriptors = []
    def plan(S, case, artifact_id, **kw):
        fd = os.open(case.dir / art["path"], os.O_RDONLY)
        descriptors.append(fd)
        entered.set()
        try:
            assert release.wait(5)
            assert kw["cancel"]()
            raise PwehError("합성 취소", code="cancelled")
        finally:
            os.close(fd)
            finished.set()
    monkeypatch.setattr(A, "plan_imported_save", plan)
    task = asyncio.create_task(direct()(**args(scase, art["id"])))
    try:
        assert await asyncio.to_thread(entered.wait, 5)
        task.cancel()
        with pytest.raises(asyncio.CancelledError): await task
        assert not finished.is_set() and os.fstat(descriptors[0]).st_size == 64
    finally:
        release.set()
        assert await asyncio.to_thread(finished.wait, 5)
    assert len(scase.load()["artifacts"]) == 1


@pytest.mark.parametrize("failure", ["missing", "rebuild", "schema"])
async def test_metadata_registration_fails_closed(workspace, monkeypatch, failure):
    from fwtriage_mcp import imported_save_tools as B, server as S
    instance = S.server
    if failure == "missing":
        instance = SimpleNamespace(_tool_manager=SimpleNamespace(get_tool=lambda name: None))
    else:
        model = S.server._tool_manager.get_tool(TOOL).fn_metadata.arg_model
        def fail(*a, **kw): raise RuntimeError(PRIVATE)
        monkeypatch.setattr(model, "model_rebuild" if failure == "rebuild" else "model_json_schema", fail)
    with pytest.raises(RuntimeError) as caught: B._configure_input(instance)
    assert PRIVATE not in str(caught.value)


@pytest.mark.parametrize("mode", ["replace", "cancel", "late-cancel"])
async def test_actual_client_commit_input_seal_and_cancel(scase, tmp_path, monkeypatch, mode):
    from fwtriage_mcp import server as S, imported_save_tools as B
    from pweh.case import Case
    art = await imported(scase, tmp_path)
    cancelled = threading.Event()
    monkeypatch.setattr(B, "threading", SimpleNamespace(Event=lambda: cancelled))
    original = Case.register_artifact
    def register(self, path, **kw):
        if kw.get("extra") == {"type": "imported-save-plan"}:
            key = "on_commit" if mode == "late-cancel" else "check"
            callback = kw[key]
            def checked(entry):
                if mode == "late-cancel":
                    callback(entry)
                    cancelled.set()
                    return
                if mode == "replace":
                    source = self.dir / art["path"]
                    changed = source.with_suffix(".replaced")
                    changed.write_bytes(source.read_bytes())
                    changed.replace(source)
                else:
                    cancelled.set()
                callback(entry)
            kw[key] = checked
        return original(self, path, **kw)
    monkeypatch.setattr(Case, "register_artifact", register)
    async with Client(S.server) as client:
        result = await call(client, TOOL, **args(scase, art["id"]))
    if mode == "late-cancel":
        assert result.get("ok"), result
        assert len(scase.load()["artifacts"]) == 2
        assert (scase.dir / result["patch"]["path"]).exists()
    else:
        expected = "imported_save_input_changed" if mode == "replace" else "cancelled"
        assert expected in result.get("_error", ""), result
        assert len(scase.load()["artifacts"]) == 1
        assert not list((scase.dir / "patches").glob("imported-save-plan-*"))


@pytest.mark.parametrize("mode", ["audit", "close", "both"])
async def test_actual_client_postcommit_warning_preserves_receipt(scase, tmp_path, monkeypatch, caplog, mode):
    from fwtriage_mcp import server as S, imported_save_plan as A
    from pweh.case import Case
    art = await imported(scase, tmp_path)
    if mode in ("audit", "both"):
        def fail(self, event): raise RuntimeError(PRIVATE)
        monkeypatch.setattr(Case, "audit", fail)
    if mode in ("close", "both"):
        original = A._Output.close
        def close(self):
            assert original(self)
            return False
        monkeypatch.setattr(A._Output, "close", close)
    async with Client(S.server) as client:
        result = await call(client, TOOL, **args(scase, art["id"]))
    assert result.get("ok"), result
    expected = (["post_commit_callback_failed"] if mode in ("audit", "both") else [])
    expected += ["output_close_unconfirmed"] if mode in ("close", "both") else []
    assert result["warnings"] == expected
    assert len(scase.load()["artifacts"]) == 2
    assert (scase.dir / result["analysis"]["path"]).exists()
    assert (scase.dir / result["patch"]["path"]).exists()
    assert PRIVATE not in json.dumps(result) + caplog.text


async def test_metadata_raw_container_types_and_no_other_tool_override(workspace):
    from fwtriage_mcp import server as S, imported_save_tools as B
    meta = S.server._tool_manager.get_tool(TOOL).fn_metadata
    given = args(SimpleNamespace(id="synthetic"))
    valid = meta.validate_arguments(given)
    assert type(valid["offset"]) is int and type(valid["edits"]) is list
    for change in ({"edits": tuple(given["edits"])}, {"checksum": {**given["checksum"], "range": (0, 60)}},
                   {"max_seconds": float("nan")}, {"max_seconds": float("inf")}, {"max_seconds": 10**400}):
        with pytest.raises(Exception) as caught: meta.validate_arguments({**given, **change})
        assert "imported_save_input_invalid" in str(caught.value)
        assert caught.value.errors()[0]["loc"] == ()
    for name in ("fw_patch_build", "fw_verify_writeback", "fw_save_diff"):
        assert not isinstance(S.server._tool_manager.get_tool(name).fn_metadata, B._ImportedMetadata)
