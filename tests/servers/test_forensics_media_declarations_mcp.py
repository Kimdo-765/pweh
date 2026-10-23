"""제한된 BMFF 선언이 기존 선택·출처·custody·prefix 경계를 유지하는 MCP 시험."""

from __future__ import annotations

import asyncio
import dataclasses
import hashlib
import json
import os
import stat
import struct
import threading

import pytest
from mcp import Client

from mcp_helpers import call
from servers.test_forensics_media_mcp import (
    analyses, anyio_backend, assert_coverage, box, invoke, mcase, prepare, wait_event,
)
from servers.test_forensics_media_prefix_mcp import finished

pytestmark = pytest.mark.anyio
SYSTEM_ID = b"PRIVATE_SYSID_01"
KEY_ID = b"PRIVATE_KID__001"
SECRET = b"https://PRIVATE.invalid/license?key=hidden"
TIME0 = int.from_bytes(b"TME0", "big")
MOD0 = int.from_bytes(b"MOD0", "big")
TIME1 = int.from_bytes(b"TIME____", "big")
MOD1 = int.from_bytes(b"MODIFIED", "big")


def timing(kind=b"mvhd", *, version=0, flags=0, scale=1000, duration=5000):
    fixed = (struct.pack(">IIII", TIME0, MOD0, scale, duration) if version == 0
             else struct.pack(">QQIQ", TIME1, MOD1, scale, duration))
    return box(kind, bytes([version]) + flags.to_bytes(3, "big") + fixed + SECRET)


def pssh(version=0):
    keys = struct.pack(">I", 1) + KEY_ID if version == 1 else b""
    return box(b"pssh", bytes([version, 0, 0, 0]) + SYSTEM_ID + keys
               + struct.pack(">I", len(SECRET)) + SECRET)


def content(first=None):
    track = box(b"trak", box(b"mdia", timing(b"mdhd", version=1, scale=90000, duration=900000)))
    return (box(b"ftyp", b"isom\0\0\0\0")
            + box(b"moov", (timing() if first is None else first) + pssh() + track)
            + box(b"moof", pssh(1)) + box(b"mdat", SECRET + timing() + pssh()))


def assert_private(public):
    for value in (SYSTEM_ID, KEY_ID, SECRET, TIME0.to_bytes(4, "big"), MOD0.to_bytes(4, "big"),
                  TIME1.to_bytes(8, "big"), MOD1.to_bytes(8, "big")):
        assert value.decode() not in public
        assert value.hex() not in public
        assert hashlib.sha256(value).hexdigest() not in public
    for value in (TIME0, MOD0, TIME1, MOD1):
        assert str(value) not in public


def assert_declarations(report):
    from pweh import schemas
    schemas.validate("media-inventory", report)
    assert report["profile"] == "mp4-quicktime-protection-declarations-v1"
    declared = report["declarations"]
    assert declared["scope"] == "mvhd-mdhd-pssh-sample-protection-selected-contexts"
    assert declared["absolute_times_returned"] is False
    assert declared["sample_entries_examined"] is False
    assert declared["sample_encryption_examined"] is False
    all_rows = declared["timing"] + declared["pssh"]
    assert len({r["box_index"] for r in all_rows}) == len(all_rows) <= len(report["boxes"])
    for row in all_rows:
        parent = report["boxes"][row["box_index"]]
        assert parent["parent_index"] == row["parent_index"]
        assert parent["handling"] == "declaration"
    assert declared["coverage"]["traversal_complete"] == report["coverage"]["structure_complete"]


@pytest.mark.parametrize("kind", ["file", "fat", "exfat", "tar", "zip"])
async def test_actual_selection_new_declarations_and_existing_custody(mcase, tmp_path, kind, caplog):
    from forensics_mcp import server as S
    data = content()
    ev, path, source = await prepare(mcase, tmp_path, kind=kind, data=data)
    before = len(S.custody(mcase).entries())
    async with Client(S.server) as client:
        result = await call(client, "forensics_media_inventory", case_id=mcase.id, evidence_id=ev, path=path)
    assert result.get("ok"), result
    report = result["report"]
    assert report["status"] == "ok" and report["framing_status"] == "complete"
    assert_coverage(report, data)
    assert_declarations(report)
    declared = report["declarations"]
    assert declared["status"] == "complete" and declared["coverage"]["fields_complete"] is True
    assert [(r["kind"], r["version"], r["timescale"], r["duration_units"])
            for r in declared["timing"]] == [("mvhd", 0, 1000, 5000), ("mdhd", 1, 90000, 900000)]
    assert [r["version"] for r in declared["pssh"]] == [0, 1]
    assert report["source"]["evidence_sha256"] == hashlib.sha256(source).hexdigest()
    assert report["source"]["selected_sha256"] == hashlib.sha256(data).hexdigest()
    assert report["source"]["selected_size"] == len(data)
    saved = mcase.dir / result["analysis"]["path"]
    assert stat.S_IMODE(saved.stat().st_mode) == 0o444
    assert hashlib.sha256(saved.read_bytes()).hexdigest() == result["analysis"]["sha256"]
    events = S.custody(mcase).entries()[before:]
    assert [entry["event"] for entry in events] == ["media-inventory"]
    assert_private(json.dumps(result) + saved.read_text() + json.dumps(events) + caplog.text)


@pytest.mark.parametrize("kind,parent", [("fat", False), ("fat", True), ("exfat", False), ("exfat", True)])
async def test_deleted_source_does_not_change_declaration_bytes_coverage(mcase, tmp_path, kind, parent):
    from forensics_mcp import server as S
    ev, _, _ = await prepare(mcase, tmp_path, kind=kind, data=content(), deleted=not parent,
                              parent_deleted=parent)
    async with Client(S.server) as client:
        listing = await call(client, "forensics_fs_list", case_id=mcase.id, evidence_id=ev)
        stored = json.loads((mcase.dir / listing["result_path"]).read_bytes())
        entry = next(e for v in stored["volumes"] for e in v["walk"]["entries"] if not e.get("is_dir"))
        result = await call(client, "forensics_media_inventory", case_id=mcase.id, evidence_id=ev, ref=entry["ref"])
    assert result.get("ok"), result
    report = result["report"]
    assert report["status"] == "partial"
    assert report["coverage"]["selection_uncertain"] is True
    assert report["source"]["parent_deleted"] is parent
    assert report["declarations"]["status"] == "complete"
    assert report["declarations"]["coverage"] == {"traversal_complete": True,
                                                   "fields_complete": True, "reasons": []}
    assert_declarations(report)


async def test_incomplete_container_is_not_declaration_failure(mcase, tmp_path, monkeypatch):
    from forensics_mcp import media_tools as T, server as S
    ev, path, _ = await prepare(mcase, tmp_path, kind="tar", data=content())
    original = T.fsops.read_selected_file
    def read(*args, **kwargs):
        data, member = original(*args, **kwargs)
        member.update(container_truncated=True, container_truncated_reasons=["max_entries"])
        return data, member
    monkeypatch.setattr(T.fsops, "read_selected_file", read)
    async with Client(S.server) as client:
        result = await call(client, "forensics_media_inventory", case_id=mcase.id, evidence_id=ev, path=path)
    assert result.get("ok"), result
    report = result["report"]
    assert report["status"] == "partial"
    assert "container_listing_incomplete" in report["coverage"]["reasons"]
    assert report["declarations"]["status"] == "complete"
    assert report["declarations"]["coverage"]["reasons"] == []


@pytest.mark.parametrize("first,issue", [
    (timing(scale=0), "zero_timescale"),
    (timing(flags=1), "unsupported_declaration_flags"),
    (box(b"mvhd", b"\xff\0\0\0"), "unsupported_declaration_version"),
    (box(b"mvhd", b"\0\0\0\0too short"), "truncated_declaration_fields"),
    (box(b"pssh", b"\x01\0\0\0" + SYSTEM_ID + b"\xff" * 4 + b"\0" * 4), "pssh_length_mismatch"),
])
async def test_bad_declaration_stores_partial_with_complete_framing(mcase, tmp_path, first, issue):
    from forensics_mcp import server as S
    data = content(first)
    ev, _, _ = await prepare(mcase, tmp_path, data=data)
    async with Client(S.server) as client:
        result = await call(client, "forensics_media_inventory", case_id=mcase.id, evidence_id=ev)
    assert result.get("ok"), result
    report = result["report"]
    assert_declarations(report)
    assert report["status"] == "partial" and report["framing_status"] == "complete"
    assert report["declarations"]["status"] == "partial"
    assert report["declarations"]["coverage"] == {"traversal_complete": True,
                                                  "fields_complete": False, "reasons": [issue]}
    assert issue in report["coverage"]["reasons"]
    assert any(r["kind"] == "mdhd" and r["status"] == "complete" for r in report["declarations"]["timing"])
    assert_coverage(report, data)


@pytest.mark.parametrize("target,field", [("timing", "creation_time"), ("timing", "duration_seconds"),
                                         ("pssh", "system_id"), ("pssh", "payload_sha256")])
async def test_schema_failure_hides_unpromised_declaration_fields(mcase, tmp_path, monkeypatch, caplog, target, field):
    from forensics_mcp import server as S
    from pweh import media
    ev, _, _ = await prepare(mcase, tmp_path, data=content())
    original = media.inventory_isobmff
    def parse(*args, **kwargs):
        report = original(*args, **kwargs)
        report["declarations"][target][0][field] = SECRET.decode()
        return report
    monkeypatch.setattr(media, "inventory_isobmff", parse)
    async with Client(S.server) as client:
        result = await call(client, "forensics_media_inventory", case_id=mcase.id, evidence_id=ev)
    assert "_error" in result
    assert SECRET.decode() not in json.dumps(result) + caplog.text
    assert not analyses(mcase)
    assert all(entry["event"] != "media-inventory" for entry in S.custody(mcase).entries())


async def test_box_limit_keeps_only_atomic_prefix_rows(mcase, tmp_path, monkeypatch):
    from forensics_mcp import server as S
    from pweh import media
    data = content()
    ev, _, _ = await prepare(mcase, tmp_path, data=data)
    original = media.inventory_isobmff
    def parse(*args, **kwargs):
        kwargs["limits"] = dataclasses.replace(kwargs["limits"], max_boxes=3)
        return original(*args, **kwargs)
    monkeypatch.setattr(media, "inventory_isobmff", parse)
    async with Client(S.server) as client:
        result = await call(client, "forensics_media_inventory", case_id=mcase.id, evidence_id=ev)
    assert result.get("ok"), result
    report = result["report"]
    assert report["status"] == "partial" and report["framing_status"] == "partial"
    assert len(report["declarations"]["timing"]) == 1 and report["declarations"]["pssh"] == []
    assert report["declarations"]["coverage"] == {"traversal_complete": False,
                                                   "fields_complete": True, "reasons": ["box_limit"]}
    last = report["boxes"][-1]
    assert last["kind"] == "mvhd"
    assert report["coverage"]["ranges"][-1]["offset"] == last["offset"] + last["size"]
    assert_coverage(report, data)
    assert_declarations(report)


async def test_raw_cancel_at_declaration_emit_keeps_worker_fd_until_exit(mcase, tmp_path, monkeypatch):
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
        if record["kind"] == "mvhd":
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


async def test_new_inventory_never_becomes_prefix_input_and_candidates_remain_opaque(mcase, tmp_path):
    from forensics_mcp import server as S
    data = content()
    ev, _, _ = await prepare(mcase, tmp_path, data=data)
    async with Client(S.server) as client:
        inventory = await call(client, "forensics_media_inventory", case_id=mcase.id, evidence_id=ev)
        assert inventory.get("ok"), inventory
        rejected = await call(client, "forensics_extract_media_candidate", case_id=mcase.id, evidence_id=ev,
                              analysis_path=inventory["analysis"]["path"], candidate_index=0)
        assert "_error" in rejected and "job_id" not in rejected
        candidates = await call(client, "forensics_media_candidates", case_id=mcase.id, evidence_id=ev)
        assert candidates.get("ok"), candidates
        report = candidates["report"]
        assert report["profile"] == "ftyp-contiguous-top-level-v1" and "declarations" not in report
        assert len(report["candidates"]) == 1
        started = await call(client, "forensics_extract_media_candidate", case_id=mcase.id, evidence_id=ev,
                             analysis_path=candidates["analysis"]["path"], candidate_index=0)
        job = await finished(client, started)
    assert job["status"] == "succeeded", job
    result = job["result"]
    assert result["bytes_total"] == len(data) and result["files"] == 1
    manifest = json.loads((mcase.dir / result["manifest"]).read_bytes())
    assert "declarations" not in manifest and manifest["source"]["selected_sha256"] == hashlib.sha256(data).hexdigest()
    assert [e["event"] for e in S.custody(mcase).entries()][-3:] == ["media-inventory", "media-candidates", "extract"]
    assert_private(json.dumps(result) + json.dumps(manifest))
