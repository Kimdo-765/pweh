"""합성 마운트 상태로 제자리 참조의 정책·전체 검증·취소 경계를 확인한다."""

from __future__ import annotations

import asyncio
import hashlib
import os
import stat
import threading
from types import SimpleNamespace

import pytest
from mcp import Client

from mcp_helpers import call

pytestmark = pytest.mark.anyio
LEGAL = dict(purpose="합성 참조 검사", legal_basis="소유자 합성 자료", site_type="home", business_purpose="없음(합성)", role="owner")


@pytest.fixture
def anyio_backend():
    return "asyncio"


@pytest.fixture
def reference(workspace, auth, tmp_path, monkeypatch):
    from forensics_mcp import server as S
    from pweh import evidence as E
    from pweh.case import CaseStore

    case = CaseStore(workspace["cases_dir"]).create(title="합성 참조", authorization=auth, case_id="reference")
    source = tmp_path / "mounted" / "large.img"
    source.parent.mkdir()
    source.write_bytes(b"A" * (4 << 20))
    S.rt().config.raw["forensics"] = {"reference_roots": [str(source.parent)]}
    mount = SimpleNamespace(f_flag=os.ST_RDONLY)
    monkeypatch.setattr(E.os, "fstatvfs", lambda fd: mount)
    return case, source, mount


async def wait(client, job_id):
    for _ in range(50):
        result = await call(client, "forensics_job_status", job_id=job_id, wait_seconds=1)
        if result["status"] in ("succeeded", "failed", "cancelled"):
            return result
    raise AssertionError("합성 참조 작업 시간 초과")


async def intake(client, case, source):
    out = await call(client, "forensics_intake_start", case_id=case.id, image_path=str(source), storage="reference", **LEGAL)
    assert out.get("job_id"), out
    job = await wait(client, out["job_id"])
    assert job["status"] == "succeeded", job
    return job["result"]


async def test_reference_keeps_source_and_rehashes_before_certificate(reference):
    from forensics_mcp import server as S
    case, source, _ = reference
    before = source.stat()
    async with Client(S.server) as client:
        result = await intake(client, case, source)
        assert result["storage_mode"] == "reference" and result["stored_path"] is None
        assert result["copy_verified"] is None
        assert result["hashes"]["sha256"] == hashlib.sha256(source.read_bytes()).hexdigest()
        assert not list((case.dir / "forensics/images").rglob("*.img"))
        assert any(a["kind"] == "evidence-reference" for a in case.artifacts())
        out = await call(client, "forensics_evidence_list", case_id=case.id)
        assert out.get("job_id"), out
        job = await wait(client, out["job_id"])
        assert job["status"] == "succeeded" and job["result"]["ok"], job
        assert job["result"]["items"][0]["last_verify"]["kind"] == "full-rehash"
        assert any(e["event"] == "verify" and e["data"].get("kind") == "reference-certificate"
                   for e in S.custody(case).entries())
        assert (case.dir / job["result"]["files"]["json"]).exists()
    after = source.stat()
    assert (before.st_ino, before.st_size, before.st_mtime_ns, stat.S_IMODE(before.st_mode)) == (
        after.st_ino, after.st_size, after.st_mtime_ns, stat.S_IMODE(after.st_mode))


@pytest.mark.parametrize("failure", ["readwrite", "removed_root", "missing"])
async def test_reference_policy_failure_is_not_permanent_integrity_failure(reference, failure):
    from forensics_mcp import server as S
    case, source, mount = reference
    async with Client(S.server) as client:
        result = await intake(client, case, source)
        ev = result["evidence_id"]
        if failure == "readwrite":
            mount.f_flag = 0
        elif failure == "removed_root":
            S.rt().config.raw["forensics"]["reference_roots"] = []
        else:
            source.rename(source.with_suffix(".away"))
        opened = await call(client, "forensics_partitions", case_id=case.id, evidence_id=ev)
        assert "reference_" in opened.get("_error", ""), opened
        out = await call(client, "forensics_evidence_list", case_id=case.id)
        job = await wait(client, out["job_id"])
        report = job["result"]
        assert not report["ok"] and not report["certificate_written"] and "files" not in report
        assert report["items"][0]["status"] == "unverified"
        assert not any(e["event"] == "integrity-failed" for e in S.custody(case).entries())


async def test_reference_certificate_detects_middle_change_despite_matching_fast_fingerprint(reference):
    from forensics_mcp import server as S
    case, source, _ = reference
    async with Client(S.server) as client:
        result = await intake(client, case, source)
        before = source.stat()
        with source.open("r+b") as stream:
            stream.seek(2 << 20)
            stream.write(b"changed")
        os.utime(source, ns=(before.st_atime_ns, before.st_mtime_ns))
        # 빠른 지문은 같지만 전체 재해시는 가운데의 변화를 찾아야 한다.
        with S._open_evidence_sync(case, result["evidence_id"]):
            pass
        out = await call(client, "forensics_evidence_list", case_id=case.id)
        job = await wait(client, out["job_id"])
        report = job["result"]
        assert not report["ok"] and "files" not in report
        assert report["items"][0]["status"] == "integrity-failed"
        assert any(e["event"] == "verify" and e["data"].get("result") == "mismatch" for e in S.custody(case).entries())


async def test_reference_list_cancel_does_not_write_certificate(reference, monkeypatch):
    from forensics_mcp import server as S
    case, source, _ = reference
    entered, release = threading.Event(), threading.Event()
    async with Client(S.server) as client:
        await intake(client, case, source)
        original = S.safeio.hash_fd
        def paused_hash(*args, **kwargs):
            entered.set()
            assert release.wait(5), "시험 재해시 해제 시간 초과"
            return original(*args, **kwargs)
        monkeypatch.setattr(S.safeio, "hash_fd", paused_hash)
        try:
            out = await call(client, "forensics_evidence_list", case_id=case.id)
            assert await asyncio.to_thread(entered.wait, 5)
            await call(client, "forensics_job_cancel", job_id=out["job_id"])
        finally:
            release.set()
        job = await wait(client, out["job_id"])
        assert job["status"] == "cancelled", job
        assert not (case.dir / "forensics/evidence-list.json").exists()
        assert not any(e["event"] == "evidence-list" for e in S.custody(case).entries())


async def test_reference_intake_requires_current_readonly_root(reference):
    from forensics_mcp import server as S
    case, source, mount = reference
    async with Client(S.server) as client:
        mount.f_flag = 0
        out = await call(client, "forensics_intake_start", case_id=case.id, image_path=str(source), storage="reference", **LEGAL)
        assert "reference_not_readonly" in out.get("_error", ""), out
        mount.f_flag = os.ST_RDONLY
        S.rt().config.raw["forensics"]["reference_roots"] = []
        out = await call(client, "forensics_intake_start", case_id=case.id, image_path=str(source), storage="reference", **LEGAL)
        assert "reference_not_allowed" in out.get("_error", ""), out
        assert not S.custody(case).entries()
