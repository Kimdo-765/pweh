"""명시 텍스트 구간의 실제 MCP·마스킹·같은 fd와 커밋 경계 시험."""

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
from servers.test_forensics_secrets_mcp import (analyses, anyio_backend, event_wait, intake, invoke, scase)

pytestmark = pytest.mark.anyio
PRIVATE = "SYNTHETIC_RANGE_PRIVATE_68f5ac"
FIRST, MIDDLE, LAST = (PRIVATE + suffix for suffix in ("FIRST", "MIDDLE", "LAST"))
TEXT = ("password=" + FIRST + "\r\npassword=" + MIDDLE + "\npassword=" + LAST).encode()
OFFSET = 127
SOURCE_KEYS = {"kind", "evidence_id", "evidence_sha256", "evidence_size", "offset", "length",
               "selected_sha256", "selected_size", "complete"}


async def prepare(case, tmp_path, data=None, name=None):
    from forensics_mcp import server as S
    blob = b"X" * OFFSET + TEXT + b"Z" if data is None else data
    source = tmp_path / (name or (PRIVATE + ".bin"))
    source.write_bytes(blob)
    async with Client(S.server) as client:
        ev = await intake(client, case, source)
    return ev, blob


async def query(client, case, ev, **changes):
    return await call(client, "forensics_scan_secrets", **{
        "case_id": case.id, "evidence_id": ev, "offset": OFFSET, "length": len(TEXT), **changes})


def check_accounting(report, expected):
    from pweh.secretscan import validate_secrets_range_accounting
    validate_secrets_range_accounting(report)
    c = report["coverage"]
    assert c["input_bytes"] == c["read_bytes"] == len(expected)
    assert c["scanned_bytes"] + c["framing_bytes"] + c["unscanned_bytes"] == len(expected)
    assert c["lines_seen"] == c["lines_scanned"] + c["lines_skipped"]
    assert report["source"]["selected_sha256"] == hashlib.sha256(expected).hexdigest()
    assert report["source"]["selected_size"] == report["source"]["length"] == len(expected)
    assert not c["selection_uncertain"] and not c["container_examined"]


async def test_actual_large_ev_masked_source_and_summary_report(scase, tmp_path, caplog):
    from case_mcp import server as C
    from forensics_mcp import server as S
    from core.test_sd_secrets_summary import _summary
    ev, blob = await prepare(scase, tmp_path, b"X" * OFFSET + TEXT + b"Z" * (4 << 20))
    async with Client(S.server) as client, Client(C.server) as cc:
        before = len(S.custody(scase).entries())
        result = await query(client, scase, ev)
        assert result.get("ok"), result
        report, receipt = result["report"], result["analysis"]
        assert report["profile"] == "utf8-masked-secrets-ev-range-v1" and report["status"] == "partial"
        assert set(report["source"]) == SOURCE_KEYS
        assert report["source"] == {"kind": "evidence", "evidence_id": ev,
            "evidence_sha256": hashlib.sha256(blob).hexdigest(), "evidence_size": len(blob),
            "offset": OFFSET, "length": len(TEXT), "selected_sha256": hashlib.sha256(TEXT).hexdigest(),
            "selected_size": len(TEXT), "complete": True}
        assert report["params"] == {"xor_key": None, "max_hits": 200, "max_seconds": 45,
            "decoder": "utf-8", "prefix_complete": False, "suffix_complete": False}
        check_accounting(report, TEXT)
        assert report["coverage"]["reasons"] == ["selection_boundary"]
        assert report["coverage"]["lines_skipped"] == 2 and report["summary"]["hits"] == 1
        hit = report["matches"][0]
        assert hit["line"] == 2 and hit["offset"] == TEXT.index(MIDDLE.encode())
        assert hit["digest"] == S.rt().secret_digest(scase.id, MIDDLE)
        saved = scase.dir / receipt["path"]
        assert stat.S_IMODE(saved.stat().st_mode) == 0o444
        assert receipt["sha256"] == hashlib.sha256(saved.read_bytes()).hexdigest()
        entries = S.custody(scase).entries()[before:]
        assert len(entries) == 1 and entries[0]["event"] == "secrets-scan"
        assert entries[0]["data"]["source"] == report["source"]
        public = json.dumps(result) + saved.read_text() + json.dumps(entries) + caplog.text
        assert PRIVATE not in public and "password=" not in public
        data = _summary()
        data["secret_scan_results"] = [{"evidence_id": ev, "analysis_path": receipt["path"],
            "analysis_sha256": receipt["sha256"], "status": report["status"], "hits": report["summary"]["hits"],
            "scanned_bytes": report["coverage"]["scanned_bytes"],
            "unscanned_bytes": report["coverage"]["unscanned_bytes"], "reasons": report["coverage"]["reasons"]}]
        stored = await call(cc, "case_record_step", case_id=scase.id, skill="sd-card-forensics", step="summary",
                            status="success", summary="합성 텍스트 구간 검사", data=data, artifacts=[receipt["path"]])
        assert stored.get("ok"), stored
        got = await call(cc, "case_get_step_results", case_id=scase.id)
        assert got["summaries"]["sd-card-forensics"]["data"] == data
        final = await call(cc, "report_generate", case_id=scase.id)
        assert final.get("ok") and receipt["path"] in Path(final["path"]).read_text(), final


async def test_tool_contract_keeps_old_defaults_and_adds_only_pair(scase):
    from forensics_mcp import server as S
    async with Client(S.server) as client:
        tool = next(t for t in (await client.list_tools()).tools if t.name == "forensics_scan_secrets")
    schema = tool.input_schema
    assert schema["required"] == ["case_id", "evidence_id"]
    assert set(schema["properties"]) == {"case_id", "evidence_id", "partition", "ref", "path", "method",
                                          "xor_key", "max_hits", "max_seconds", "offset", "length"}
    for name in ("offset", "length"):
        assert schema["properties"][name]["default"] is None
        assert {r["type"] for r in schema["properties"][name]["anyOf"]} == {"integer", "null"}


@pytest.mark.parametrize("changes", [
    {"offset": None}, {"length": None}, {"offset": -1}, {"offset": 1 << 63}, {"length": 0},
    {"length": -1}, {"length": (4 << 20) + 1}, {"offset": (1 << 63) - 1},
    {"offset": True}, {"offset": 1.0}, {"offset": "1"}, {"length": False},
    {"length": 1.0}, {"length": "2"}, {"offset": []}, {"length": {PRIVATE: 1}},
    {"ref": "arc:0"}, {"path": PRIVATE}, {"partition": 1}, {"method": "chain"},
])
async def test_bad_range_arguments_reject_before_case_or_open(scase, monkeypatch, changes):
    from forensics_mcp import server as S
    from pweh.errors import PwehError
    monkeypatch.setattr(S.rt(), "case", lambda *a, **k: pytest.fail("잘못된 인자 뒤 케이스 조회"))
    with pytest.raises(PwehError) as exc:
        await invoke(scase, "EV-0001", **{"offset": OFFSET, "length": len(TEXT), **changes})
    assert exc.value.code == "validation_failed" and PRIVATE not in str(exc.value)


@pytest.mark.parametrize("key,value", [(k, v) for k in ("offset", "length")
    for v in (True, False, 1.0, "1", PRIVATE, [PRIVATE], {PRIVATE: PRIVATE})])
async def test_actual_sdk_strict_range_and_private_error(scase, monkeypatch, caplog, key, value):
    from forensics_mcp import server as S
    monkeypatch.setattr(S, "_open_evidence_sync", lambda *a: pytest.fail("SDK 거부 뒤 증거 열기"))
    async with Client(S.server) as client:
        result = await query(client, scase, "EV-0001", **{key: value})
    assert "_error" in result and PRIVATE not in json.dumps(result) + caplog.text


@pytest.mark.parametrize("offset,length", [(10, 1), (11, 1), (1, 10), ((1 << 63) - 2, 1)])
async def test_outside_actual_ev_is_not_partial(scase, tmp_path, offset, length):
    from forensics_mcp import server as S
    ev, _ = await prepare(scase, tmp_path, b"0123456789")
    async with Client(S.server) as client:
        result = await query(client, scase, ev, offset=offset, length=length)
    assert "validation_failed" in result.get("_error", "") and not analyses(scase)


@pytest.mark.parametrize("length", [1, 65536, 65537, 4 << 20])
async def test_selection_size_edges_and_whole_ev_flags(scase, tmp_path, length):
    from forensics_mcp import server as S
    line = b"x" * 1023 + b"\n"
    selected = (line * ((length + 1023) // 1024))[:length]
    ev, _ = await prepare(scase, tmp_path, selected)
    async with Client(S.server) as client:
        result = await query(client, scase, ev, offset=0, length=length)
    assert result.get("ok"), result
    check_accounting(result["report"], selected)
    assert result["report"]["status"] == "ok"
    assert result["report"]["params"]["prefix_complete"] is True
    assert result["report"]["params"]["suffix_complete"] is True


async def test_reader_uses_original_fd_bounded_exact_content_range(scase, tmp_path, monkeypatch):
    from forensics_mcp import secrets_tools as T, server as S
    selected = b"safe=none\n" * 14000
    ev, blob = await prepare(scase, tmp_path, b"X" * OFFSET + selected + b"Y" * (5 << 20))
    real_read, real_pread = T._read_secret_range, os.pread
    local = threading.local()
    inside, outside, held = [], [], {}
    def read(opened, *args, **kwargs):
        held["fd"] = opened.fd
        local.active = True
        try:
            return real_read(opened, *args, **kwargs)
        finally:
            local.active = False
    def pread(fd, count, offset):
        (inside if getattr(local, "active", False) else outside).append((fd, count, offset))
        return real_pread(fd, count, offset)
    monkeypatch.setattr(T, "_read_secret_range", read)
    monkeypatch.setattr(T.os, "pread", pread)
    monkeypatch.setattr(T.fsops, "read_selected_file", lambda *a, **k: pytest.fail("range에서 FS 선택"))
    async with Client(S.server) as client:
        result = await query(client, scase, ev, length=len(selected))
    assert result.get("ok"), result
    position = OFFSET
    for fd, count, offset in inside:
        assert fd == held["fd"] and offset == position and 1 <= count <= 65536
        assert count <= OFFSET + len(selected) - offset
        position += count
    assert position == OFFSET + len(selected) and len(inside) == 3
    # 원래 EV 앞뒤 지문은 내용 선택과 별개이며 그대로 수행한다.
    assert any(offset == 0 for _, _, offset in outside)
    assert any(offset == len(blob) - (1 << 20) for _, _, offset in outside)


@pytest.mark.parametrize("prefix,suffix,terminator,bom,xor", [
    (False, False, b"\n", False, False), (False, False, b"\r", False, False),
    (False, False, b"\r\n", True, False), (False, False, b"\n", False, True),
    (True, False, b"\n", False, False), (False, True, b"\n", False, False),
    (True, True, b"\n", True, False),
])
async def test_boundary_context_only_complete_interior_gets_digest(scase, tmp_path, monkeypatch,
                                                                  prefix, suffix, terminator, bom, xor):
    from forensics_mcp import server as S
    values = (FIRST.encode(), MIDDLE.encode(), LAST.encode())
    view = (b"\xef\xbb\xbf" if bom else b"") + terminator.join(b"password=" + v for v in values)
    selected = bytes(x ^ 144 for x in view) if xor else view
    head, tail = (b"" if prefix else b"X"), (b"" if suffix else b"Y")
    ev, _ = await prepare(scase, tmp_path, head + selected + tail)
    seen, real_digest = [], S.rt().secret_digest
    def digest(case_id, value):
        seen.append(value)
        return real_digest(case_id, value)
    monkeypatch.setattr(S.rt(), "secret_digest", digest)
    async with Client(S.server) as client:
        result = await query(client, scase, ev, offset=len(head), length=len(selected), xor_key=144 if xor else None)
    assert result.get("ok"), result
    expected = ([FIRST.encode()] if prefix else []) + [MIDDLE.encode()] + ([LAST.encode()] if suffix else [])
    assert seen == expected
    check_accounting(result["report"], selected)
    assert [m["line"] for m in result["report"]["matches"]] == ([1] if prefix else []) + [2] + ([3] if suffix else [])


@pytest.mark.parametrize("view", [b"password=" + FIRST.encode(), b"\n", b"\r\n", b"\xef\xbb\xbf"])
async def test_one_boundary_line_or_bom_never_invents_digest(scase, tmp_path, monkeypatch, view):
    from forensics_mcp import server as S
    ev, _ = await prepare(scase, tmp_path, b"X" + view + b"Y")
    monkeypatch.setattr(S.rt(), "secret_digest", lambda *a: pytest.fail("경계 줄의 지문 호출"))
    async with Client(S.server) as client:
        result = await query(client, scase, ev, offset=1, length=len(view))
    assert result.get("ok") and not result["report"]["matches"], result
    check_accounting(result["report"], view)


@pytest.mark.parametrize("selected,reason", [(b"\x80password=" + FIRST.encode(), "invalid_utf8"),
    (b"password=" + FIRST.encode() + b"\xe2\x82", "invalid_utf8"),
    (b"\x89PNG\r\n\x1a\npassword=" + FIRST.encode(), "unsupported_media"),
    (b"password=" + FIRST.encode() + b"\0", "unsupported_unicode")])
async def test_whole_selected_validation_precedes_boundary_skip(scase, tmp_path, monkeypatch, selected, reason):
    from forensics_mcp import server as S
    ev, _ = await prepare(scase, tmp_path, b"X" + selected + b"Y")
    monkeypatch.setattr(S.rt(), "secret_digest", lambda *a: pytest.fail("미지원 선택의 지문 호출"))
    async with Client(S.server) as client:
        result = await query(client, scase, ev, offset=1, length=len(selected))
    assert result.get("ok") and result["report"]["status"] == "unsupported", result
    assert result["report"]["coverage"]["reasons"] == [reason]
    check_accounting(result["report"], selected)


async def test_range_preserves_intake_media_name_denial(scase, tmp_path, monkeypatch, caplog):
    from forensics_mcp import secrets_tools as T, server as S
    ev, _ = await prepare(scase, tmp_path, name=PRIVATE + ".MP4")
    monkeypatch.setattr(T, "_read_secret_range", lambda *a, **k: pytest.fail("미디어 이름 거부 뒤 내용 읽기"))
    async with Client(S.server) as client:
        result = await query(client, scase, ev)
    assert "unsupported_media" in result.get("_error", "")
    assert PRIVATE not in json.dumps(result) + caplog.text and not analyses(scase)


@pytest.mark.parametrize("stage", ["reader", "scanner", "digest", "schema", "accounting", "final"])
async def test_raw_failures_have_fixed_public_errors(scase, tmp_path, monkeypatch, caplog, stage):
    from forensics_mcp import secrets_tools as T, server as S
    from pweh import secretscan
    ev, _ = await prepare(scase, tmp_path)
    def fail(*args, **kwargs):
        raise OSError(PRIVATE)
    target, attr = {"reader": (T, "_read_secret_range"), "scanner": (secretscan, "scan_secrets"),
        "digest": (S.rt(), "secret_digest"), "schema": (T.schemas, "validate"),
        "accounting": (secretscan, "validate_secrets_range_accounting"), "final": (T, "_check_secret_range")}[stage]
    if stage == "final":
        real = getattr(target, attr)
        def final(*args, **kwargs):
            if kwargs.get("time_limit") is False:
                fail()
            return real(*args, **kwargs)
        monkeypatch.setattr(target, attr, final)
    else:
        monkeypatch.setattr(target, attr, fail)
    async with Client(S.server) as client:
        result = await query(client, scase, ev)
    assert "secrets_scan_failed" in result.get("_error", "")
    assert PRIVATE not in json.dumps(result) + caplog.text and not analyses(scase)


@pytest.mark.parametrize("mutation", ["profile", "params", "source", "size", "float_size", "accounting"])
async def test_changed_core_envelope_rejected_before_store(scase, tmp_path, monkeypatch, mutation):
    from forensics_mcp import secrets_tools as T, server as S
    ev, _ = await prepare(scase, tmp_path)
    real = T.schemas.validate
    def validate(name, report):
        if name == "secrets-scan":
            if mutation == "profile":
                report["profile"] = PRIVATE
            elif mutation == "params":
                report["params"]["xor_key"] = 144
            elif mutation == "source":
                report["source"]["selected_sha256"] = "a" * 64
            elif mutation == "size":
                report["source"]["evidence_size"] += 1
            elif mutation == "float_size":
                report["source"]["evidence_size"] = float(report["source"]["evidence_size"])
            else:
                report["coverage"]["scanned_bytes"] += 1
        return real(name, report)
    monkeypatch.setattr(T.schemas, "validate", validate)
    async with Client(S.server) as client:
        result = await query(client, scase, ev)
    assert "validation_failed" in result.get("_error", "") and not analyses(scase)
    assert PRIVATE not in json.dumps(result)


@pytest.mark.parametrize("mode", ["short", "long", "not_bytes", "exception"])
async def test_reader_rejects_nonexact_pread_without_partial(scase, tmp_path, monkeypatch, mode):
    from forensics_mcp import secrets_tools as T, server as S
    from pweh.errors import PwehError
    ev, _ = await prepare(scase, tmp_path)
    with S._open_evidence_sync(scase, ev) as opened:
        def pread(*args):
            if mode == "exception":
                raise OSError(PRIVATE)
            return {"short": TEXT[:-1], "long": TEXT + b"X", "not_bytes": bytearray(TEXT)}[mode]
        monkeypatch.setattr(T.os, "pread", pread)
        with pytest.raises((PwehError, OSError)):
            T._read_secret_range(opened, ev, OFFSET, len(TEXT), deadline=time.monotonic() + 45,
                                  cancelled=threading.Event())
    assert not analyses(scase)


@pytest.mark.parametrize("when", [0, 1, 2, 3])
async def test_reader_cancel_at_each_chunk_boundary(scase, tmp_path, monkeypatch, when):
    from forensics_mcp import secrets_tools as T, server as S
    from pweh.errors import PwehError
    selected = b"x" * (65536 * 2 + 1)
    ev, _ = await prepare(scase, tmp_path, selected)
    cancelled, calls = threading.Event(), []
    real = os.pread
    with S._open_evidence_sync(scase, ev) as opened:
        if when == 0:
            cancelled.set()
        def read(fd, n, offset):
            calls.append((n, offset))
            data = real(fd, n, offset)
            if len(calls) == when:
                cancelled.set()
            return data
        monkeypatch.setattr(T.os, "pread", read)
        with pytest.raises(PwehError) as exc:
            T._read_secret_range(opened, ev, 0, len(selected), deadline=time.monotonic() + 45, cancelled=cancelled)
    assert exc.value.code == "cancelled" and len(calls) == when


async def test_reader_expired_deadline_sends_no_read(scase, tmp_path, monkeypatch):
    from forensics_mcp import secrets_tools as T, server as S
    from pweh.errors import PwehError
    ev, _ = await prepare(scase, tmp_path)
    with S._open_evidence_sync(scase, ev) as opened:
        monkeypatch.setattr(T.os, "pread", lambda *a: pytest.fail("만료 뒤 구간 읽기"))
        with pytest.raises(PwehError) as exc:
            T._read_secret_range(opened, ev, OFFSET, len(TEXT), deadline=time.monotonic() - 1,
                                  cancelled=threading.Event())
    assert exc.value.code == "time_limit"


@pytest.mark.parametrize("stage", ["read", "scan", "final"])
async def test_fd_content_or_size_change_never_commits(scase, tmp_path, monkeypatch, stage):
    from forensics_mcp import secrets_tools as T, server as S
    from pweh import secretscan
    ev, _ = await prepare(scase, tmp_path)
    held, changed = {}, []
    real_read = T._read_secret_range
    def alter():
        if changed:
            return
        changed.append(True)
        p = scase.dir / held["opened"].intake["stored_path"]
        p.chmod(0o644)
        with p.open("ab") as stream:
            stream.write(b"changed")
        p.chmod(0o444)
    def read(opened, *args, **kwargs):
        held["opened"] = opened
        if stage == "read":
            alter()
        return real_read(opened, *args, **kwargs)
    monkeypatch.setattr(T, "_read_secret_range", read)
    if stage == "scan":
        real_scan = secretscan.scan_secrets
        def scan(*args, **kwargs):
            report = real_scan(*args, **kwargs)
            alter()
            return report
        monkeypatch.setattr(secretscan, "scan_secrets", scan)
    if stage == "final":
        real_check = T._check_secret_range
        def check(*args, **kwargs):
            if kwargs.get("time_limit") is False:
                alter()
            return real_check(*args, **kwargs)
        monkeypatch.setattr(T, "_check_secret_range", check)
    async with Client(S.server) as client:
        result = await query(client, scase, ev)
    assert "integrity_failed" in result.get("_error", "") and not analyses(scase)
    assert S.custody(scase).entries()[-1]["event"] == "integrity-failed"


async def test_same_bytes_name_replacement_preserves_original_fd_but_final_denies(scase, tmp_path, monkeypatch):
    from forensics_mcp import secrets_tools as T, server as S
    from pweh import secretscan
    ev, blob = await prepare(scase, tmp_path)
    with S._open_evidence_sync(scase, ev) as opened:
        target = scase.dir / opened.intake["stored_path"]
    real = secretscan.scan_secrets
    def scan(*args, **kwargs):
        report = real(*args, **kwargs)
        target.parent.chmod(0o755)
        replacement = target.parent / "synthetic-replacement.bin"
        replacement.write_bytes(blob)
        replacement.chmod(0o444)
        os.replace(replacement, target)
        target.parent.chmod(0o555)
        return report
    monkeypatch.setattr(secretscan, "scan_secrets", scan)
    async with Client(S.server) as client:
        result = await query(client, scase, ev)
    assert "integrity_failed" in result.get("_error", "") and not analyses(scase)


async def test_core_time_partial_stores_without_resetting_deadline(scase, tmp_path, monkeypatch):
    from forensics_mcp import secrets_tools as T, server as S
    from pweh import secretscan
    ev, _ = await prepare(scase, tmp_path)
    clock = {"value": time.monotonic()}
    real_scan = secretscan.scan_secrets
    # 모듈의 시계 참조만 바꿔 다른 worker·SDK 시간에는 영향을 주지 않는다.
    fake_time = SimpleNamespace(monotonic=lambda: clock["value"])
    monkeypatch.setattr(T, "time", fake_time)
    monkeypatch.setattr(secretscan, "time", fake_time)
    def scan(*args, **kwargs):
        clock["value"] = kwargs["deadline"] + .01
        return real_scan(*args, **kwargs)
    monkeypatch.setattr(secretscan, "scan_secrets", scan)
    async with Client(S.server) as client:
        result = await query(client, scase, ev)
    assert result.get("ok") and result["report"]["status"] == "partial", result
    assert result["report"]["coverage"]["reasons"] == ["time_limit"]
    assert result["report"]["coverage"]["unscanned_bytes"] == len(TEXT)


@pytest.mark.parametrize("stage", ["read", "scan", "commit"])
async def test_raw_cancel_keeps_worker_fd_until_exit(scase, tmp_path, monkeypatch, stage):
    from forensics_mcp import secrets_tools as T, server as S
    from pweh import evidence as E, secretscan
    ev, _ = await prepare(scase, tmp_path)
    entered, release, finished = threading.Event(), threading.Event(), threading.Event()
    held = {}
    real_close, real_read = E.OpenedEvidence.close, T._read_secret_range
    def close(opened):
        try:
            return real_close(opened)
        finally:
            if opened.fd == held.get("fd"):
                finished.set()
    monkeypatch.setattr(E.OpenedEvidence, "close", close)
    def pause():
        entered.set()
        assert release.wait(5)
    def read(opened, *args, **kwargs):
        held["fd"] = opened.fd
        if stage == "read":
            pause()
        return real_read(opened, *args, **kwargs)
    monkeypatch.setattr(T, "_read_secret_range", read)
    if stage == "scan":
        real = secretscan.scan_secrets
        def scan(*args, **kwargs):
            pause()
            return real(*args, **kwargs)
        monkeypatch.setattr(secretscan, "scan_secrets", scan)
    if stage == "commit":
        real = E.store_analysis
        def store(*args, **kwargs):
            pause()
            return real(*args, **kwargs)
        monkeypatch.setattr(E, "store_analysis", store)
    task = asyncio.create_task(invoke(scase, ev, offset=OFFSET, length=len(TEXT)))
    try:
        await event_wait(entered)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        os.fstat(held["fd"])
    finally:
        release.set()
    await event_wait(finished)
    with pytest.raises(OSError):
        os.fstat(held["fd"])
    assert not analyses(scase)
    assert all(e["event"] != "secrets-scan" for e in S.custody(scase).entries())


async def test_last_output_check_cancel_is_precommit(scase, tmp_path, monkeypatch):
    from forensics_mcp import secrets_tools as T, server as S
    from pweh import evidence as E
    ev, _ = await prepare(scase, tmp_path)
    held = {}
    real_read, real_check = T._read_secret_range, E._check_analysis_output
    def read(*args, **kwargs):
        held["cancel"] = kwargs["cancelled"]
        return real_read(*args, **kwargs)
    def check(*args, **kwargs):
        real_check(*args, **kwargs)
        held["cancel"].set()
    monkeypatch.setattr(T, "_read_secret_range", read)
    monkeypatch.setattr(E, "_check_analysis_output", check)
    async with Client(S.server) as client:
        result = await query(client, scase, ev)
    assert "cancelled" in result.get("_error", "") and not analyses(scase)


@pytest.mark.parametrize("late", ["cancel", "audit", "index"])
async def test_commit_receipt_survives_late_cancel_or_aux_failure(scase, tmp_path, monkeypatch, late):
    from forensics_mcp import secrets_tools as T, server as S
    from pweh import evidence as E
    from pweh.case import Case
    ev, _ = await prepare(scase, tmp_path)
    held = {}
    real_read, real_audit = T._read_secret_range, S._audit_custody
    def read(*args, **kwargs):
        held["cancel"] = kwargs["cancelled"]
        return real_read(*args, **kwargs)
    def audit(*args, **kwargs):
        if late == "cancel":
            held["cancel"].set()
        elif late == "audit":
            raise RuntimeError(PRIVATE)
        return real_audit(*args, **kwargs)
    monkeypatch.setattr(T, "_read_secret_range", read)
    monkeypatch.setattr(S, "_audit_custody", audit)
    if late == "index":
        monkeypatch.setattr(Case, "register_artifact", lambda *a, **k: (_ for _ in ()).throw(RuntimeError(PRIVATE)))
    async with Client(S.server) as client:
        result = await query(client, scase, ev)
    assert result.get("ok") and len(analyses(scase)) == 1, result
    assert bool(result["warnings"]) is (late != "cancel")
    assert E.entry_hash(S.custody(scase).entries()[-1]) == result["analysis"]["custody_hash"]
    assert PRIVATE not in json.dumps(result)
