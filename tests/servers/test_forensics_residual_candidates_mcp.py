"""실제 MCP의 residual 선택·출처·원문 비노출과 data 기본 호환 시험."""
from __future__ import annotations

import asyncio
import hashlib
import json
import threading
import time

import pytest
from mcp import Client

from core.test_media_residual_schema import KINDS, PROFILES, SUFFIX, sample, schema_name
from mcp_helpers import call
from servers.test_forensics_media_candidates_mcp import intake
from servers.test_media_candidate_residual_selection import make_image

pytestmark = pytest.mark.anyio
PRIVATE = "SYNTHETIC_RESIDUAL_PRIVATE_84d1"
TOOLS = {"bmff": "forensics_media_candidates", "dhav": "forensics_dhav_candidates"}


@pytest.fixture
def anyio_backend():
    return "asyncio"


@pytest.fixture
def mcase(workspace, auth):
    from pweh.case import CaseStore
    return CaseStore(workspace["cases_dir"]).create(
        title="합성 residual 후보", authorization=auth, case_id="residual-candidates")


def tool(kind):
    return TOOLS.get(kind, "forensics_media_unit_candidates")


def options(kind):
    return {} if kind in TOOLS else {"format": kind}


def analyses(case):
    return list((case.dir / "forensics/analysis").glob("*-candidates-*.json"))


async def prepare(case, tmp_path, kind="bmff", *, mode="live", head=b"D" * 5000, tail=None):
    from forensics_mcp import server as S
    image = make_image(mode=mode, head=head, tail=b"junk" + sample(kind) if tail is None else tail)
    source = tmp_path / "synthetic-residual.img"
    source.write_bytes(image.blob)
    async with Client(S.server) as client:
        ev = await intake(client, case, source)
    return ev, image


@pytest.mark.parametrize("kind", KINDS)
async def test_actual_client_default_data_and_residual_have_distinct_source_shapes(mcase, tmp_path, kind, caplog):
    from forensics_mcp import server as S
    ev, image = await prepare(mcase, tmp_path, kind)
    async with Client(S.server) as client:
        kwargs = dict(case_id=mcase.id, evidence_id=ev, partition=1, ref=image.ref, **options(kind))
        data = await call(client, tool(kind), **kwargs)
        explicit = await call(client, tool(kind), **kwargs, region="data")
        assert data.get("ok") and explicit.get("ok"), (data, explicit)
        assert data["report"] == explicit["report"]
        assert data["report"]["summary"]["candidates_reported"] == 0
        assert len(data["report"]["source"]) == 16
        assert "region" not in data["report"]["params"]
        result = await call(client, tool(kind), **kwargs, region="residual")
        assert result.get("ok"), result
        report, src = result["report"], result["report"]["source"]
        assert len(src) == 19 and src["region"] == "residual"
        assert src["valid_data_length"] == len(image.head)
        assert src["data_length"] == len(image.head) + len(image.tail)
        assert src["selected_size"] == len(image.tail)
        assert src["selected_sha256"] == hashlib.sha256(image.tail).hexdigest()
        assert src["evidence_sha256"] == hashlib.sha256(image.blob).hexdigest()
        assert src["method"] == "nofatchain" and src["parent_deleted"] is False
        assert report["profile"] == PROFILES[kind] and report["limitations"][-3:] == SUFFIX
        assert report["params"]["region"] == "residual" and report["params"]["method"] == "auto"
        assert report["candidates"][0]["offset"] == 4
        assert src["valid_data_length"] + 4 != image.builder.coff(image.rec.clusters[-1]) + 4
        assert "offset" not in src and "evidence_size" not in src
        saved = mcase.dir / result["analysis"]["path"]
        assert saved.read_bytes().endswith(b"\n")
        assert hashlib.sha256(saved.read_bytes()).hexdigest() == result["analysis"]["sha256"]
        entry = S.custody(mcase).entries()[-1]
        assert entry["event"] == schema_name(kind)
        assert entry["data"]["source"] == src and entry["data"]["params"] == report["params"]
        assert PRIVATE not in json.dumps(result) + saved.read_text() + json.dumps(entry) + caplog.text
        assert not list((mcase.dir / "forensics/recovered").glob("**/*"))
        registered = next(t for t in (await client.list_tools()).tools if t.name == tool(kind))
        assert registered.input_schema["properties"]["region"]["default"] == "data"


@pytest.mark.parametrize("kind", ["bmff", "dhav", "xm"])
@pytest.mark.parametrize("updates", [
    {"region": None}, {"region": True}, {"region": 1}, {"region": [PRIVATE]}, {"region": {PRIVATE: 1}},
    {"region": "other-" + PRIVATE}, {"partition": None}, {"partition": True}, {"partition": 1.0},
    {"partition": 0}, {"partition": 4097}, {"ref": None}, {"ref": "arc:1"},
    {"ref": "root/3\n"}, {"path": PRIVATE}, {"offset": 0, "length": 1},
    {"method": "fat-chain"}, {"method": "skip-claimed"},
])
async def test_residual_arguments_fail_before_case_or_evidence_access(mcase, monkeypatch, kind, updates):
    from forensics_mcp import server as S
    async def no_case(*args, **kwargs):
        pytest.fail("인자 거부 전에 케이스 접근")
    monkeypatch.setattr(S, "_case", no_case)
    kwargs = dict(case_id=mcase.id, evidence_id="EV-0001", partition=1, ref="root/3", region="residual", **options(kind))
    kwargs.update(updates)
    async with Client(S.server) as client:
        result = await call(client, tool(kind), **kwargs)
    assert "_error" in result and PRIVATE not in json.dumps(result)


@pytest.mark.parametrize("kind", ["bmff", "dhav", "xm"])
@pytest.mark.parametrize("reason,code", [
    ("unsupported_fs", "invalid_selection"), ("bad_argument", "invalid_selection"),
    ("incomplete_file", "invalid_selection"), ("max_bytes", "input_too_large"),
    ("bad_ref", "selection_failed"), ("cancelled", "cancelled"), ("time", "time_limit"),
])
async def test_residual_only_fs_errors_have_fixed_private_projection(mcase, tmp_path, monkeypatch, kind, reason, code, caplog):
    from forensics_mcp import fsops, server as S
    ev, image = await prepare(mcase, tmp_path, kind)
    def fail(*args, **kwargs):
        raise fsops.FsError(PRIVATE, reason=reason, data={"path": PRIVATE})
    monkeypatch.setattr(fsops, "read_selected_residual", fail)
    async with Client(S.server) as client:
        result = await call(client, tool(kind), case_id=mcase.id, evidence_id=ev, partition=1,
                            ref=image.ref, region="residual", **options(kind))
    assert code in result.get("_error", ""), result
    assert PRIVATE not in json.dumps(result) + caplog.text and not analyses(mcase)


@pytest.mark.parametrize("kind", KINDS)
async def test_selected_positive_but_short_residual_is_recorded_without_candidate(mcase, tmp_path, kind):
    from forensics_mcp import server as S
    ev, image = await prepare(mcase, tmp_path, kind, head=b"", tail=b"X")
    async with Client(S.server) as client:
        result = await call(client, tool(kind), case_id=mcase.id, evidence_id=ev, partition=1,
                            ref=image.ref, region="residual", **options(kind))
    assert result.get("ok"), result
    report = result["report"]
    assert report["status"] == "unsupported" and report["candidates"] == []
    assert report["source"]["valid_data_length"] == 0 and report["source"]["selected_size"] == 1


@pytest.mark.parametrize("kind", ["bmff", "dhav", "xm"])
@pytest.mark.parametrize("change", [{"partition": 2}, {"ref": "root/999"}, {"method": "chain"}])
async def test_residual_projection_must_match_explicit_selector(mcase, tmp_path, monkeypatch, kind, change):
    from forensics_mcp import fsops, server as S
    ev, image = await prepare(mcase, tmp_path, kind)
    original = fsops.read_selected_residual
    def changed(*args, **kwargs):
        data, member = original(*args, **kwargs)
        member.update(change)
        return data, member
    monkeypatch.setattr(fsops, "read_selected_residual", changed)
    async with Client(S.server) as client:
        result = await call(client, tool(kind), case_id=mcase.id, evidence_id=ev, partition=1,
                            ref=image.ref, region="residual", method="nofatchain", **options(kind))
    assert "validation_failed" in result.get("_error", "") and not analyses(mcase)


@pytest.mark.parametrize("kind", ["bmff", "dhav", "xm"])
async def test_residual_scanner_time_partial_retains_existing_final_seal_policy(mcase, tmp_path, monkeypatch, kind):
    from forensics_mcp import server as S
    from pweh import dhav, media_candidates, media_units
    module, name = ((media_candidates, "scan_bmff_candidates") if kind == "bmff" else
                    (dhav, "scan_dhav_candidates") if kind == "dhav" else
                    (media_units, "scan_media_unit_candidates"))
    original = getattr(module, name)
    def timed(*args, **kwargs):
        kwargs["deadline"] = time.monotonic() - 1
        return original(*args, **kwargs)
    ev, image = await prepare(mcase, tmp_path, kind)
    monkeypatch.setattr(module, name, timed)
    async with Client(S.server) as client:
        result = await call(client, tool(kind), case_id=mcase.id, evidence_id=ev, partition=1,
                            ref=image.ref, region="residual", **options(kind))
    assert result.get("ok"), result
    assert result["report"]["status"] == "partial"
    assert "time_limit" in result["report"]["coverage"]["reasons"]
    assert len(analyses(mcase)) == 1


@pytest.mark.parametrize("kind", ["bmff", "dhav", "xm"])
async def test_raw_awaiter_cancel_does_not_close_image_until_worker_returns(mcase, tmp_path, monkeypatch, kind):
    from forensics_mcp import fsops, server as S
    from forensics_mcp import media_candidate_tools as B, dhav_tools as D, media_unit_tools as U
    entered, release, done = threading.Event(), threading.Event(), threading.Event()
    original = fsops.read_selected_residual
    def blocked(img, **kwargs):
        entered.set()
        assert release.wait(5)
        try:
            return original(img, **kwargs)
        finally:
            done.set()
    ev, image = await prepare(mcase, tmp_path, kind)
    monkeypatch.setattr(fsops, "read_selected_residual", blocked)
    module, run = (B, B._candidates_run) if kind == "bmff" else (D, D._dhav_run) if kind == "dhav" else (U, U._media_unit_run)
    args = dict(case_id=mcase.id, evidence_id=ev, partition=1, ref=image.ref, path=None,
                method="auto", max_seconds=45, region="residual", **options(kind))
    task = asyncio.create_task(run(module._ServerAPI(vars(S)), **args))
    try:
        for _ in range(500):
            if entered.is_set():
                break
            await asyncio.sleep(.01)
        assert entered.is_set()
        task.cancel()
        await asyncio.sleep(.02)
        assert not done.is_set()
    finally:
        release.set()
    with pytest.raises(asyncio.CancelledError):
        await task
    for _ in range(500):
        if done.is_set():
            break
        await asyncio.sleep(.01)
    assert done.is_set() and not analyses(mcase)
