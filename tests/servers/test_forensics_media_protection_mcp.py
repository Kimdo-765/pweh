"""합성 보호 prefix의 실제 선택·마스킹·관계 검사·저장/요약 연결."""

from __future__ import annotations

import asyncio
import dataclasses
import hashlib
import json
import os
import stat
import struct
import threading
from pathlib import Path

import pytest
from mcp import Client

from mcp_helpers import call
from servers.test_forensics_media_mcp import (
    analyses, anyio_backend, assert_coverage, box, invoke, mcase, prepare, wait_event,
)

pytestmark = pytest.mark.anyio
PROFILE = "mp4-quicktime-protection-declarations-v1"
PRIVATE = b"PRIVATE_PROTECTION_7af6"
KID = b"PRIVATE_KEY_12345"
TAIL = b"https://private.invalid/constant-iv"


def schm(scheme=b"cenc", *, version=0, flags=0, payload=None):
    return box(b"schm", (bytes([version]) + flags.to_bytes(3, "big") + scheme + b"VERS")
               if payload is None else payload)


def tenc(state=1, *, version=0, flags=0, payload=None):
    fixed = bytes([version]) + flags.to_bytes(3, "big") + b"RS" + bytes([state, 8]) + KID + TAIL
    return box(b"tenc", fixed if payload is None else payload)


def sample(kind=b"encv", *, children=None, prefix=None):
    if prefix is None:
        prefix = ((PRIVATE * 4)[:78] if kind == b"encv" else
                  b"PRIVATE!" + b"\0\0" + (PRIVATE * 2)[:18])
    if children is None:
        children = box(b"sinf", schm() + box(b"schi", tenc()))
    return box(kind, prefix + children)


def content(entry=None, *, count=1, before=b""):
    table = box(b"stsd", b"\0\0\0\0" + count.to_bytes(4, "big")
                + (sample() if entry is None else entry))
    track = box(b"trak", box(b"mdia", box(b"minf", box(b"stbl", table))))
    return box(b"ftyp", b"isom\0\0\0\0") + box(b"moov", before + track) + box(b"mdat", PRIVATE)


def assert_report(report, data):
    from pweh import schemas
    from pweh.media import validate_media_protection_accounting
    schemas.validate("media-inventory", report)
    validate_media_protection_accounting(report)
    assert report["profile"] == PROFILE
    assert report["declarations"]["scope"] == "mvhd-mdhd-pssh-sample-protection-selected-contexts"
    assert_coverage(report, data)
    assert report["source"]["selected_sha256"] == hashlib.sha256(data).hexdigest()
    assert report["source"]["selected_size"] == len(data)
    protection = report["declarations"]["protection"]
    assert protection["full_tenc_examined"] is protection["sample_auxiliary_examined"] is protection["identifiers_returned"] is False
    rows = sum((protection[key] for key in ("tables", "entries", "schemes", "track_defaults")), [])
    assert len({row["box_index"] for row in rows}) == len(rows) <= len(report["boxes"])
    return protection


def assert_private(public):
    for value in (PRIVATE, KID, TAIL, b"VERS"):
        assert value.decode() not in public
        assert value.hex() not in public
        assert hashlib.sha256(value).hexdigest() not in public


@pytest.mark.parametrize("container", ["file", "fat", "exfat", "tar", "zip"])
@pytest.mark.parametrize("entry_kind", [b"encv", b"enca"])
async def test_actual_protection_selection_and_custody(mcase, tmp_path, container, entry_kind, caplog):
    from forensics_mcp import server as S
    data = content(sample(entry_kind))
    ev, path, evidence = await prepare(mcase, tmp_path, kind=container, data=data)
    before = len(S.custody(mcase).entries())
    async with Client(S.server) as client:
        result = await call(client, "forensics_media_inventory", case_id=mcase.id, evidence_id=ev, path=path)
    assert result.get("ok"), result
    report = result["report"]
    protection = assert_report(report, data)
    assert report["status"] == "ok" and protection["status"] == "complete"
    assert protection["coverage"] == {"traversal_complete": True, "fields_complete": True, "reasons": []}
    table, = protection["tables"]
    assert (table["entries_declared"], table["entries_reported"], table["entries_complete"]) == (1, 1, True)
    entry, = protection["entries"]
    assert entry["kind"] == entry_kind.decode()
    assert entry["prefix_kind"] == ("visual" if entry_kind == b"encv" else "audio-v0")
    assert protection["schemes"][0]["scheme_type"] == "cenc"
    assert protection["track_defaults"][0]["default_is_protected_state"] == "one"
    assert protection["schemes"][0]["entry_index"] == protection["track_defaults"][0]["entry_index"] == entry["box_index"]
    assert report["declarations"]["sample_entries_examined"] is True
    assert report["summary"]["max_depth_seen"] == 10
    assert report["source"]["evidence_sha256"] == hashlib.sha256(evidence).hexdigest()
    saved = mcase.dir / result["analysis"]["path"]
    assert saved.read_text().endswith("\n") and stat.S_IMODE(saved.stat().st_mode) == 0o444
    assert hashlib.sha256(saved.read_bytes()).hexdigest() == result["analysis"]["sha256"]
    events = S.custody(mcase).entries()[before:]
    assert [entry["event"] for entry in events] == ["media-inventory"]
    assert_private(json.dumps(result) + saved.read_text() + json.dumps(events) + caplog.text)


async def test_new_protection_connects_to_unchanged_six_field_summary(mcase, tmp_path):
    from case_mcp import server as C
    from forensics_mcp import server as S
    from core.test_sd_media_unit_summary import summary
    data = content()
    ev, path, _ = await prepare(mcase, tmp_path, data=data)
    async with Client(S.server) as client, Client(C.server) as cc:
        result = await call(client, "forensics_media_inventory", case_id=mcase.id, evidence_id=ev, path=path)
        assert result.get("ok"), result
        assert_report(result["report"], data)
        payload = summary()
        payload["media_inventory_results"] = [{"evidence_id": ev, "analysis_path": result["analysis"]["path"],
            "sha256": result["analysis"]["sha256"], "status": result["report"]["status"],
            "selected_size": result["report"]["source"]["selected_size"],
            "boxes_reported": result["report"]["summary"]["boxes_reported"]}]
        stored = await call(cc, "case_record_step", case_id=mcase.id, skill="sd-card-forensics", step="summary",
                            status="success", summary="합성 제한 보호 선언", data=payload, artifacts=[result["analysis"]["path"]])
        assert stored.get("ok"), stored
        got = await call(cc, "case_get_step_results", case_id=mcase.id)
        assert got["summaries"]["sd-card-forensics"]["data"] == payload
        final = await call(cc, "report_generate", case_id=mcase.id)
        assert final.get("ok") and result["analysis"]["path"] in Path(final["path"]).read_text(), final


@pytest.mark.parametrize("entry,issue", [
    (sample(prefix=b"x" * 77, children=b""), "truncated_declaration_fields"),
    (sample(b"enca", prefix=b"x" * 9, children=b""), "truncated_declaration_fields"),
    (sample(b"enca", prefix=b"\0" * 27, children=b""), "truncated_declaration_fields"),
    (sample(b"enca", prefix=b"\0" * 8 + b"\0\1" + b"x" * 18), "unsupported_audio_entry_version"),
    (sample(children=box(b"sinf", schm(b"PRIV"))), "unsupported_protection_scheme"),
    (sample(children=box(b"sinf", schm(version=1))), "unsupported_declaration_version"),
    (sample(children=box(b"sinf", schm(flags=1))), "unsupported_declaration_flags"),
    (sample(children=box(b"sinf", schm(payload=b"\0" * 13))), "unsupported_protection_shape"),
    (sample(children=box(b"sinf", box(b"schi", tenc(2)))), "unsupported_protection_value"),
    (sample(children=box(b"sinf", box(b"schi", tenc(payload=b"\0" * 23)))), "truncated_declaration_fields"),
    (sample(children=box(b"sinf", box(b"schi", tenc(flags=1)))), "unsupported_declaration_flags"),
])
async def test_representative_partial_protection_keeps_complete_box_framing(mcase, tmp_path, entry, issue):
    from forensics_mcp import server as S
    data = content(entry)
    ev, _, _ = await prepare(mcase, tmp_path, data=data)
    async with Client(S.server) as client:
        result = await call(client, "forensics_media_inventory", case_id=mcase.id, evidence_id=ev)
    assert result.get("ok"), result
    protection = assert_report(result["report"], data)
    assert result["report"]["status"] == "partial" and result["report"]["framing_status"] == "complete"
    assert protection["status"] == "partial" and protection["coverage"]["fields_complete"] is False
    assert protection["coverage"]["traversal_complete"] is True
    assert issue in protection["coverage"]["reasons"]


@pytest.mark.parametrize("count,entry,reported", [(0, sample(), 0), (2, sample(), 1), (4294967295, b"", 0)])
async def test_entry_count_mismatch_is_stored_without_resync(mcase, tmp_path, count, entry, reported):
    from forensics_mcp import server as S
    data = content(entry, count=count)
    ev, _, _ = await prepare(mcase, tmp_path, data=data)
    async with Client(S.server) as client:
        result = await call(client, "forensics_media_inventory", case_id=mcase.id, evidence_id=ev)
    assert result.get("ok"), result
    protection = assert_report(result["report"], data)
    table, = protection["tables"]
    assert table["entries_declared"] == count and table["entries_reported"] == reported
    assert table["status"] == "malformed" and table["entries_complete"] is False
    assert "stsd_entry_count_mismatch" in protection["coverage"]["reasons"]
    assert result["report"]["framing_status"] == "partial"


@pytest.mark.parametrize("kind", [b"sinf", b"tenc", b"stsd", b"mdat", b"PRIV"])
async def test_stsd_known_other_preserves_box_kind_and_never_scans_payload(mcase, tmp_path, kind):
    from forensics_mcp import server as S
    data = content(box(kind, sample()))
    ev, _, _ = await prepare(mcase, tmp_path, data=data)
    async with Client(S.server) as client:
        result = await call(client, "forensics_media_inventory", case_id=mcase.id, evidence_id=ev)
    assert result.get("ok"), result
    protection = assert_report(result["report"], data)
    entry, = protection["entries"]
    assert entry["kind"] == "other" and entry["prefix_kind"] == "unsupported"
    assert result["report"]["boxes"][entry["box_index"]]["kind"] == ("unknown" if kind == b"PRIV" else kind.decode())
    assert protection["schemes"] == protection["track_defaults"] == []
    assert result["report"]["declarations"]["sample_entries_examined"] is False


@pytest.mark.parametrize("payload", [box(b"tenc", b"\0" * 24), box(b"sinf", box(b"schi", tenc())),
                                    box(b"stsd", b"\0\0\0\0\0\0\0\1" + sample())])
async def test_wrong_context_never_becomes_protection_declaration(mcase, tmp_path, payload):
    from forensics_mcp import server as S
    data = box(b"ftyp", b"isom\0\0\0\0") + box(b"moov", payload) + box(b"mdat", sample())
    ev, _, _ = await prepare(mcase, tmp_path, data=data)
    async with Client(S.server) as client:
        result = await call(client, "forensics_media_inventory", case_id=mcase.id, evidence_id=ev)
    assert result.get("ok"), result
    protection = assert_report(result["report"], data)
    assert all(not protection[key] for key in ("tables", "entries", "schemes", "track_defaults"))
    assert result["report"]["declarations"]["sample_entries_examined"] is False


@pytest.mark.parametrize("kind,prefix", [(b"mvhd", b"\0"), (b"pssh", b"\0"),
                                      (b"mvhd", b"\xff\0\0\0"), (b"pssh", b"\0\0\0\1")])
async def test_timing_or_pssh_failure_does_not_leak_shared_issue_to_empty_protection(mcase, tmp_path, kind, prefix):
    from forensics_mcp import server as S
    data = box(b"ftyp", b"isom\0\0\0\0") + box(b"moov", box(kind, prefix))
    ev, _, _ = await prepare(mcase, tmp_path, data=data)
    async with Client(S.server) as client:
        result = await call(client, "forensics_media_inventory", case_id=mcase.id, evidence_id=ev)
    assert result.get("ok"), result
    protection = assert_report(result["report"], data)
    assert protection["status"] == "complete"
    assert protection["coverage"] == {"traversal_complete": True, "fields_complete": True, "reasons": []}
    assert result["report"]["declarations"]["status"] == "partial"


@pytest.mark.parametrize("limit,value,reason", [("max_depth", 9, "depth_limit"), ("max_boxes", 8, "box_limit")])
async def test_lowered_limits_keep_atomic_declared_prefix(mcase, tmp_path, monkeypatch, limit, value, reason):
    from forensics_mcp import server as S
    from pweh import media
    data = content()
    ev, _, _ = await prepare(mcase, tmp_path, data=data)
    original = media.inventory_isobmff
    def parse(*args, **kwargs):
        kwargs["limits"] = dataclasses.replace(kwargs["limits"], **{limit: value})
        return original(*args, **kwargs)
    monkeypatch.setattr(media, "inventory_isobmff", parse)
    async with Client(S.server) as client:
        result = await call(client, "forensics_media_inventory", case_id=mcase.id, evidence_id=ev)
    assert result.get("ok"), result
    protection = assert_report(result["report"], data)
    assert result["report"]["status"] == protection["status"] == "partial"
    assert protection["track_defaults"] == [] and reason in protection["coverage"]["reasons"]
    table, = protection["tables"]
    assert table["entries_reported"] == 1 and table["entries_complete"] is False
    assert table["status"] == "complete"


@pytest.mark.parametrize("mutation", ["raw", "kid", "wrong-entry", "wrong-count", "wrong-parent", "duplicate"])
async def test_schema_and_adapter_relations_reject_modified_report_without_store(mcase, tmp_path, monkeypatch, caplog, mutation):
    from forensics_mcp import server as S
    from pweh import media
    ev, _, _ = await prepare(mcase, tmp_path, data=content())
    original = media.inventory_isobmff
    def parse(*args, **kwargs):
        report = original(*args, **kwargs)
        protection = report["declarations"]["protection"]
        if mutation in ("raw", "kid"):
            protection["track_defaults"][0][mutation] = PRIVATE.decode()
        elif mutation == "wrong-entry":
            protection["schemes"][0]["entry_index"] = 0
        elif mutation == "wrong-count":
            protection["tables"][0]["entries_reported"] = 0
        elif mutation == "wrong-parent":
            protection["track_defaults"][0]["parent_index"] = protection["schemes"][0]["parent_index"]
        else:
            protection["schemes"].append(dict(protection["schemes"][0]))
        return report
    monkeypatch.setattr(media, "inventory_isobmff", parse)
    async with Client(S.server) as client:
        result = await call(client, "forensics_media_inventory", case_id=mcase.id, evidence_id=ev)
    assert "_error" in result, result
    assert PRIVATE.decode() not in json.dumps(result) + caplog.text
    assert not analyses(mcase)
    assert all(entry["event"] != "media-inventory" for entry in S.custody(mcase).entries())


async def test_cancel_during_protection_emit_retains_worker_fd_until_exit(mcase, tmp_path, monkeypatch):
    from forensics_mcp import media_tools as T, server as S
    from pweh import evidence as E, media
    data = content()
    ev, _, _ = await prepare(mcase, tmp_path, data=data)
    entered, release, closed = threading.Event(), threading.Event(), threading.Event()
    held = {}
    original_read, original_close, original_emit = T.fsops.read_selected_file, E.OpenedEvidence.close, media._Parser.emit
    def read(fd, **kwargs):
        held["fd"] = fd
        return original_read(fd, **kwargs)
    def close(opened):
        try:
            return original_close(opened)
        finally:
            if entered.is_set():
                closed.set()
    def emit(parser, record, *args, **kwargs):
        if record["kind"] == "tenc":
            entered.set()
            assert release.wait(5)
        return original_emit(parser, record, *args, **kwargs)
    monkeypatch.setattr(T.fsops, "read_selected_file", read)
    monkeypatch.setattr(E.OpenedEvidence, "close", close)
    monkeypatch.setattr(media._Parser, "emit", emit)
    task = asyncio.create_task(invoke(mcase.id, ev))
    try:
        await wait_event(entered)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        assert os.fstat(held["fd"]).st_size == len(data)
    finally:
        release.set()
    await wait_event(closed)
    with pytest.raises(OSError):
        os.fstat(held["fd"])
    assert not analyses(mcase)
    assert all(entry["event"] != "media-inventory" for entry in S.custody(mcase).entries())


async def test_after_commit_audit_failure_preserves_new_report(mcase, tmp_path, monkeypatch, caplog):
    from forensics_mcp import server as S
    data = content()
    ev, _, _ = await prepare(mcase, tmp_path, data=data)
    def fail(*args, **kwargs):
        raise ValueError(PRIVATE.decode())
    monkeypatch.setattr(S.rt(), "audit", fail)
    async with Client(S.server) as client:
        result = await call(client, "forensics_media_inventory", case_id=mcase.id, evidence_id=ev)
    assert result.get("ok") and result.get("warnings"), result
    assert_report(result["report"], data)
    assert len(analyses(mcase)) == 1
    assert S.custody(mcase).entries()[-1]["event"] == "media-inventory"
    assert_private(json.dumps(result) + caplog.text)
