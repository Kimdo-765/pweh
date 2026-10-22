"""선택한 합성 텍스트의 MCP 검사·평문 차단·보관 기록 결속 시험."""

from __future__ import annotations

import asyncio
import hashlib
import io
import json
import os
import stat
import tarfile
import threading
import zipfile

import pytest
from mcp import Client

from fs.builders import exfat_small, fat32_small
from mcp_helpers import call

pytestmark = pytest.mark.anyio
SECRET = "SYNTHETIC_ONLY_PASSWORD_7b9f_3c2a"
CONTENT = ("password=" + SECRET + "\n").encode()


@pytest.fixture
def anyio_backend():
    return "asyncio"


@pytest.fixture
def scase(workspace, auth):
    from pweh.case import CaseStore
    return CaseStore(workspace["cases_dir"]).create(
        title="합성 선택 파일 검사", authorization=auth, case_id="secretcase")


async def intake(client, case, source):
    result = await call(client, "forensics_intake_start", case_id=case.id, image_path=str(source),
                        purpose="합성 텍스트 검사", legal_basis="소유한 합성 자료", site_type="home",
                        business_purpose="없음(합성)", role="owner")
    assert result.get("job_id"), result
    for _ in range(50):
        job = await call(client, "forensics_job_status", job_id=result["job_id"], wait_seconds=1)
        if job["status"] in ("succeeded", "failed", "cancelled"):
            assert job["status"] == "succeeded", job
            return job["result"]["evidence_id"]
    raise AssertionError("합성 접수 시간 초과")


def packed(kind, data, name="private.log", *, deleted=False):
    if kind in ("fat", "exfat"):
        disk = fat32_small() if kind == "fat" else exfat_small()
        disk.add_file("/" + name, data)
        if deleted:
            disk.delete("/" + name)
        return disk.image(), "/" + name
    out = io.BytesIO()
    name = "data/" + name
    if kind == "tar":
        with tarfile.open(fileobj=out, mode="w") as archive:
            entry = tarfile.TarInfo(name)
            entry.size = len(data)
            archive.addfile(entry, io.BytesIO(data))
    else:
        with zipfile.ZipFile(out, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            archive.writestr(name, data)
    return out.getvalue(), name


def analyses(case):
    return list((case.dir / "forensics/analysis").glob("secrets-scan-*.json"))


async def invoke(case, ev, **kwargs):
    """취소 시험은 MCP 포장을 거치지 않고 같은 실제 워커 입구를 쓴다."""
    from forensics_mcp import secrets_tools as T, server as S
    args = dict(partition=None, ref=None, path=None, method="auto", xor_key=None, max_hits=200, max_seconds=45)
    args.update(kwargs)
    return await T._scan_run(T._ServerAPI(vars(S)), case_id=case.id, evidence_id=ev, **args)


async def event_wait(event):
    for _ in range(400):
        if event.is_set():
            return
        await asyncio.sleep(.01)
    raise AssertionError("합성 워커 경계 대기 시간 초과")


async def test_direct_file_masked_report_digest_and_record(scase, tmp_path, caplog):
    from forensics_mcp import server as S
    source = tmp_path / (SECRET + ".log")
    source.write_bytes(CONTENT)
    async with Client(S.server) as client:
        ev = await intake(client, scase, source)
        start = len(S.custody(scase).entries())
        result = await call(client, "forensics_scan_secrets", case_id=scase.id, evidence_id=ev)
        assert result.get("ok"), result
        report = result["report"]
        assert report["status"] == "ok" and report["summary"]["hits"] > 0
        assert report["source"]["selected_sha256"] == report["source"]["evidence_sha256"] == hashlib.sha256(CONTENT).hexdigest()
        assert report["source"]["selected_size"] == len(CONTENT)
        assert any(m["digest"] == S.rt().secret_digest(scase.id, SECRET) for m in report["matches"])
        assert all(m["masked"] == "<masked>" and m["confidence"] == "possible" for m in report["matches"])
        saved = scase.dir / result["analysis"]["path"]
        assert stat.S_IMODE(saved.stat().st_mode) == 0o444
        assert saved.read_bytes() and hashlib.sha256(saved.read_bytes()).hexdigest() == result["analysis"]["sha256"]
        public = json.dumps(result) + saved.read_text() + json.dumps(S.custody(scase).entries()[start:]) + caplog.text
        for hidden in (SECRET, SECRET[:12], SECRET[-12:], str(source), source.name, "password="):
            assert hidden not in public
        assert S.custody(scase).entries()[-1]["event"] == "secrets-scan"
        tools = (await client.list_tools()).tools
        tool = next(t for t in tools if t.name == "forensics_scan_secrets")
        assert tool.annotations.read_only_hint is False


@pytest.mark.parametrize("kind", ["tar", "zip", "fat", "exfat"])
async def test_one_selected_file_and_distinct_source_hash(scase, tmp_path, kind):
    from forensics_mcp import server as S
    blob, path = packed(kind, CONTENT, "confidential.log")
    source = tmp_path / "card.bin"
    source.write_bytes(blob)
    async with Client(S.server) as client:
        ev = await intake(client, scase, source)
        result = await call(client, "forensics_scan_secrets", case_id=scase.id, evidence_id=ev, path=path)
        assert result.get("ok"), result
        src = result["report"]["source"]
        assert src["selected_sha256"] == hashlib.sha256(CONTENT).hexdigest()
        assert src["evidence_sha256"] == hashlib.sha256(blob).hexdigest()
        assert src["member_selected"] and src["complete"]
        assert src["ref"] and "path" not in src
        assert path not in json.dumps(result) and "confidential.log" not in json.dumps(result)
        second = await call(client, "forensics_scan_secrets", case_id=scase.id, evidence_id=ev, ref=src["ref"])
        assert second.get("ok") and second["report"]["matches"] == result["report"]["matches"]


@pytest.mark.parametrize("kind", ["fat", "exfat"])
async def test_deleted_input_is_uncertain_even_if_text_complete(scase, tmp_path, kind):
    from forensics_mcp import server as S
    blob, _ = packed(kind, CONTENT, deleted=True)
    source = tmp_path / "deleted.img"
    source.write_bytes(blob)
    async with Client(S.server) as client:
        ev = await intake(client, scase, source)
        listing = await call(client, "forensics_fs_list", case_id=scase.id, evidence_id=ev)
        saved = json.loads((scase.dir / listing["result_path"]).read_bytes())
        ref = next(e["ref"] for v in saved["volumes"] for e in v["walk"]["entries"] if e.get("deleted") and not e.get("is_dir"))
        result = await call(client, "forensics_scan_secrets", case_id=scase.id, evidence_id=ev, ref=ref)
        assert result.get("ok"), result
        assert result["report"]["status"] == "partial"
        assert result["report"]["source"]["deleted"]
        assert result["report"]["coverage"]["selection_uncertain"]
        assert "selection_uncertain" in result["report"]["coverage"]["reasons"]
        assert result["report"]["coverage"]["analysis_complete"]
        assert not result["report"]["coverage"]["hits_are_lower_bound"]


async def test_xor_is_explicit_and_long_line_partial(scase, tmp_path):
    from forensics_mcp import server as S
    source = tmp_path / "input.log"
    source.write_bytes(bytes(x ^ 144 for x in CONTENT))
    async with Client(S.server) as client:
        ev = await intake(client, scase, source)
        raw = await call(client, "forensics_scan_secrets", case_id=scase.id, evidence_id=ev)
        assert raw.get("ok") and raw["report"]["status"] == "unsupported", raw
        out = await call(client, "forensics_scan_secrets", case_id=scase.id, evidence_id=ev, xor_key=144)
        assert out.get("ok") and out["report"]["summary"]["hits"] > 0, out
        source.write_bytes(b"password=" + b"x" * 17000 + b"\n" + CONTENT)
        ev = await intake(client, scase, source)
        out = await call(client, "forensics_scan_secrets", case_id=scase.id, evidence_id=ev)
        assert out.get("ok") and out["report"]["status"] == "partial", out
        cov = out["report"]["coverage"]
        assert "line_too_long" in cov["reasons"] and cov["unscanned_bytes"] > 17000
        assert cov["scanned_bytes"] + cov["framing_bytes"] + cov["unscanned_bytes"] == cov["input_bytes"]


@pytest.mark.parametrize("arguments", [
    {"max_hits": True}, {"max_hits": 0}, {"max_hits": 201}, {"max_hits": "3"},
    {"max_seconds": True}, {"max_seconds": 0}, {"max_seconds": 46},
    {"max_seconds": float("nan")}, {"max_seconds": float("inf")}, {"max_seconds": 10 ** 400},
    {"xor_key": True}, {"xor_key": 0}, {"xor_key": "144"},
    {"ref": "arc:0", "path": "a.log"}, {"ref": "bad"}, {"path": ""}, {"path": "a\x00b"},
    {"partition": True}, {"partition": 1}, {"method": "contiguous"},
])
async def test_bad_arguments_do_not_open_evidence(scase, monkeypatch, arguments):
    from forensics_mcp import server as S
    from pweh.errors import PwehError
    monkeypatch.setattr(S, "_open_evidence_sync", lambda *a: pytest.fail("검증 실패 뒤 EV 접근"))
    with pytest.raises(PwehError):
        await invoke(scase, "EV-0001", **arguments)


async def test_mcp_strict_number_types(scase, tmp_path):
    from forensics_mcp import server as S
    source = tmp_path / "input.log"
    source.write_bytes(CONTENT)
    async with Client(S.server) as client:
        ev = await intake(client, scase, source)
        for args in ({"max_hits": True}, {"max_hits": "2"}, {"xor_key": True}, {"max_seconds": True}):
            out = await call(client, "forensics_scan_secrets", case_id=scase.id, evidence_id=ev, **args)
            assert "_error" in out, out
        assert not analyses(scase)


@pytest.mark.parametrize("kind", ["direct", "path", "ref"])
async def test_media_name_rejected_without_echoing_name(scase, tmp_path, kind):
    from forensics_mcp import server as S
    name = SECRET + ".MP4"
    if kind == "direct":
        blob, args = CONTENT, {}
    else:
        blob, path = packed("zip", CONTENT, name)
        args = {"path": path} if kind == "path" else {"ref": "arc:0"}
    source = tmp_path / (name if kind == "direct" else "archive.zip")
    source.write_bytes(blob)
    async with Client(S.server) as client:
        ev = await intake(client, scase, source)
        out = await call(client, "forensics_scan_secrets", case_id=scase.id, evidence_id=ev, **args)
        assert "unsupported_media" in out.get("_error", "") and SECRET not in json.dumps(out), out
        assert not analyses(scase)


async def test_oversize_and_ambiguous_member_are_not_partial_success(scase, tmp_path):
    from forensics_mcp import server as S
    source = tmp_path / "input.bin"
    source.write_bytes(CONTENT + b"a" * (4 << 20))
    async with Client(S.server) as client:
        ev = await intake(client, scase, source)
        out = await call(client, "forensics_scan_secrets", case_id=scase.id, evidence_id=ev)
        assert "_error" in out and not analyses(scase)
        with zipfile.ZipFile(source, "w") as archive:
            archive.writestr("one.log", CONTENT)
            with pytest.warns(UserWarning):
                archive.writestr("one.log", CONTENT)
        ev = await intake(client, scase, source)
        out = await call(client, "forensics_scan_secrets", case_id=scase.id, evidence_id=ev, path="one.log")
        assert "_error" in out and not analyses(scase)


@pytest.mark.parametrize("stage", ["read", "scan", "digest", "schema"])
async def test_content_exceptions_never_escape_to_mcp_or_log(scase, tmp_path, monkeypatch, caplog, stage):
    from forensics_mcp import secrets_tools as T, server as S
    from pweh import secretscan
    source = tmp_path / "input.log"
    source.write_bytes(CONTENT)
    async with Client(S.server) as client:
        ev = await intake(client, scase, source)
        def fail(*args, **kwargs):
            raise ValueError(SECRET)
        target, attr = {"read": (T.fsops, "read_selected_file"), "scan": (secretscan, "scan_secrets"),
                        "digest": (S.rt(), "secret_digest"), "schema": (T.schemas, "validate")}[stage]
        monkeypatch.setattr(target, attr, fail)
        out = await call(client, "forensics_scan_secrets", case_id=scase.id, evidence_id=ev)
        assert "secrets_scan_failed" in out.get("_error", ""), out
        assert SECRET not in json.dumps(out) + caplog.text
        assert not analyses(scase)


async def test_source_projection_discards_paths_and_unknown_container_reason(scase, tmp_path, monkeypatch):
    from forensics_mcp import secrets_tools as T, server as S
    source = tmp_path / "input.log"
    source.write_bytes(CONTENT)
    async with Client(S.server) as client:
        ev = await intake(client, scase, source)
        original = T.fsops.read_selected_file
        def read(*args, **kwargs):
            data, meta = original(*args, **kwargs)
            meta.update(path=SECRET + ".log", requested_path=SECRET, note=SECRET,
                        container_truncated=True, container_truncated_reasons=[SECRET])
            return data, meta
        monkeypatch.setattr(T.fsops, "read_selected_file", read)
        out = await call(client, "forensics_scan_secrets", case_id=scase.id, evidence_id=ev)
        assert out.get("ok"), out
        assert out["report"]["status"] == "partial" and SECRET not in json.dumps(out)
        assert out["report"]["source"]["container_truncated_reasons"] == ["unknown_container_limit"]
        assert out["report"]["coverage"]["analysis_complete"]
        assert not out["report"]["coverage"]["hits_are_lower_bound"]


async def test_schema_failure_never_echoes_invalid_result_value(scase, tmp_path, monkeypatch, caplog):
    from forensics_mcp import server as S
    from pweh import secretscan
    source = tmp_path / "input.log"
    source.write_bytes(CONTENT)
    async with Client(S.server) as client:
        ev = await intake(client, scase, source)
        original = secretscan.scan_secrets
        def scan(*args, **kwargs):
            result = original(*args, **kwargs)
            result["matches"][0]["masked"] = SECRET
            result["unsafe_excerpt"] = SECRET
            return result
        monkeypatch.setattr(secretscan, "scan_secrets", scan)
        out = await call(client, "forensics_scan_secrets", case_id=scase.id, evidence_id=ev)
        assert "validation_failed" in out.get("_error", ""), out
        assert SECRET not in json.dumps(out) + caplog.text
        assert not analyses(scase)


async def test_input_change_before_commit_records_integrity_failure(scase, tmp_path, monkeypatch):
    from forensics_mcp import server as S
    from pweh import secretscan
    source = tmp_path / "input.log"
    source.write_bytes(CONTENT)
    async with Client(S.server) as client:
        ev = await intake(client, scase, source)
        original = secretscan.scan_secrets
        def scan(*args, **kwargs):
            result = original(*args, **kwargs)
            with S._open_evidence_sync(scase, ev) as opened:
                target = scase.dir / opened.intake["stored_path"]
            target.chmod(0o644)
            target.write_bytes(CONTENT + b"changed")
            target.chmod(0o444)
            return result
        monkeypatch.setattr(secretscan, "scan_secrets", scan)
        out = await call(client, "forensics_scan_secrets", case_id=scase.id, evidence_id=ev)
        assert "integrity_failed" in out.get("_error", ""), out
        assert not analyses(scase)
        assert S.custody(scase).entries()[-1]["event"] == "integrity-failed"


@pytest.mark.parametrize("stage", ["read", "scan", "commit"])
async def test_raw_cancel_worker_keeps_fd_until_cleanup_and_never_commits(scase, tmp_path, monkeypatch, stage):
    from forensics_mcp import secrets_tools as T, server as S
    from pweh import evidence as E, secretscan
    source = tmp_path / "input.log"
    source.write_bytes(CONTENT)
    async with Client(S.server) as client:
        ev = await intake(client, scase, source)
    entered, release, finished = threading.Event(), threading.Event(), threading.Event()
    held = {}
    original_close = E.OpenedEvidence.close
    def close(opened):
        try:
            return original_close(opened)
        finally:
            if entered.is_set():
                finished.set()
    monkeypatch.setattr(E.OpenedEvidence, "close", close)
    original_read = T.fsops.read_selected_file
    def read(fd, **kwargs):
        held["fd"] = fd
        if stage == "read":
            entered.set()
            assert release.wait(5)
        return original_read(fd, **kwargs)
    monkeypatch.setattr(T.fsops, "read_selected_file", read)
    if stage == "scan":
        original = secretscan.scan_secrets
        def scan(*args, **kwargs):
            entered.set()
            assert release.wait(5)
            return original(*args, **kwargs)
        monkeypatch.setattr(secretscan, "scan_secrets", scan)
    if stage == "commit":
        original = E.store_analysis
        def store(*args, **kwargs):
            entered.set()
            assert release.wait(5)
            return original(*args, **kwargs)
        monkeypatch.setattr(E, "store_analysis", store)
    task = asyncio.create_task(invoke(scase, ev))
    try:
        await event_wait(entered)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        assert os.fstat(held["fd"]).st_size == len(CONTENT)
    finally:
        release.set()
    await event_wait(finished)
    with pytest.raises(OSError):
        os.fstat(held["fd"])
    assert not analyses(scase)
    assert all(e["event"] != "secrets-scan" for e in S.custody(scase).entries())


async def test_raw_cancel_after_custody_commit_preserves_result(scase, tmp_path, monkeypatch):
    from forensics_mcp import server as S
    from pweh import evidence as E
    source = tmp_path / "input.log"
    source.write_bytes(CONTENT)
    async with Client(S.server) as client:
        ev = await intake(client, scase, source)
    entered, release, finished = threading.Event(), threading.Event(), threading.Event()
    original = E.store_analysis
    def store(*args, **kwargs):
        result = original(*args, **kwargs)
        entered.set()
        try:
            assert release.wait(5)
            return result
        finally:
            finished.set()
    monkeypatch.setattr(E, "store_analysis", store)
    task = asyncio.create_task(invoke(scase, ev))
    try:
        await event_wait(entered)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
    finally:
        release.set()
    await event_wait(finished)
    assert len(analyses(scase)) == 1
    assert S.custody(scase).entries()[-1]["event"] == "secrets-scan"
