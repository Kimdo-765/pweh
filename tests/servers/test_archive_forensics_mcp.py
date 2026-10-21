"""합성 논리 TAR/ZIP 의 접수·목록·추출과 무결성 경계."""
import hashlib
import io
import json
import stat
import struct
import tarfile
import zipfile

import pytest
from mcp import Client
from mcp_helpers import call

pytestmark = pytest.mark.anyio


@pytest.fixture
def anyio_backend():
    return "asyncio"


@pytest.fixture
def acase(workspace, auth):
    from pweh.case import CaseStore
    return CaseStore(workspace["cases_dir"]).create(title="합성 아카이브", authorization=auth, case_id="archive")


async def wait(client, job):
    for _ in range(100):
        result = await call(client, "forensics_job_status", job_id=job, wait_seconds=1)
        if result["status"] in ("failed", "succeeded", "cancelled"):
            return result
    raise AssertionError("합성 작업 시간 초과")


async def intake(client, case, path):
    result = await call(client, "forensics_intake_start", case_id=case.id, image_path=str(path),
                        purpose="합성 자료 검사", legal_basis="소유자 제공 합성 자료", site_type="home", business_purpose="없음(합성)", role="owner")
    assert result.get("job_id"), result
    result = await wait(client, result["job_id"])
    assert result["status"] == "succeeded", result
    return result["result"]["evidence_id"]


def container(kind):
    data = b"synthetic record" * 1000
    out = io.BytesIO()
    if kind == "zip":
        with zipfile.ZipFile(out, "w", compression=zipfile.ZIP_DEFLATED) as arc:
            arc.writestr("app/data.txt", data)
            arc.writestr("../outside", b"forbidden")
    else:
        with tarfile.open(fileobj=out, mode="w") as arc:
            ti = tarfile.TarInfo("app/data.txt")
            ti.size, ti.mtime = len(data), 1700000000
            arc.addfile(ti, io.BytesIO(data))
            link = tarfile.TarInfo("linked")
            link.type, link.linkname = tarfile.SYMTYPE, "app/data.txt"
            arc.addfile(link)
    return out.getvalue(), data


@pytest.mark.parametrize("kind", ["tar", "zip"])
async def test_archive_list_extract_and_custody(acase, tmp_path, kind):
    from forensics_mcp import server as S
    blob, data = container(kind)
    src = tmp_path / f"synthetic.{kind}"
    src.write_bytes(blob)
    async with Client(S.server) as c:
        ev = await intake(c, acase, src)
        listed = await call(c, "forensics_fs_list", case_id=acase.id, evidence_id=ev)
        assert listed["format"] == kind and listed["members"] == 2, listed
        assert listed["sample"][0]["sha256"] == hashlib.sha256(data).hexdigest()
        assert listed["sample"][1]["sha256"] is None and listed["truncated"]
        raw = (acase.dir / listed["result_path"]).read_bytes()
        assert hashlib.sha256(raw).hexdigest() == listed["result_sha256"]
        result = await call(c, "forensics_extract", case_id=acase.id, evidence_id=ev, refs=["arc:0", "arc:1"], max_bytes="1M")
        job = await wait(c, result["job_id"])
        assert job["status"] == "succeeded", job
        extracted = job["result"]
        assert len(extracted["files"]) == 1 and extracted["truncated"]
        f = acase.dir / extracted["output_dir"] / extracted["files"][0]["file"]
        assert f.read_bytes() == data and stat.S_IMODE(f.stat().st_mode) == 0o444
        check = await call(c, "forensics_evidence_list", case_id=acase.id, write_files=False)
        assert check["derived"][0]["custody"] == "recorded"
        assert all(e["event"] in ("intake", "list", "extract") for e in S.custody(acase).entries())
    assert src.read_bytes() == blob


async def test_bad_crc_member_is_not_preserved(acase, tmp_path):
    from forensics_mcp import server as S
    blob, _ = container("zip")
    bad = bytearray(blob)
    cd = bad.index(b"PK\x01\x02")
    struct.pack_into("<I", bad, cd + 16, 1234)
    src = tmp_path / "crc.zip"
    src.write_bytes(bad)
    async with Client(S.server) as c:
        ev = await intake(c, acase, src)
        listed = await call(c, "forensics_fs_list", case_id=acase.id, evidence_id=ev)
        assert listed["sample"][0]["sha256"] is None and "crc_mismatch" in listed["truncated_reasons"]
        result = await call(c, "forensics_extract", case_id=acase.id, evidence_id=ev, refs=["arc:0"], max_bytes="1M")
        job = await wait(c, result["job_id"])
        assert job["status"] == "succeeded", job
        out = job["result"]
        assert out["files"] == [] and "crc_mismatch" in out["truncated_reasons"]
        assert [p.name for p in (acase.dir / out["output_dir"]).iterdir()] == ["manifest.json"]


async def test_archive_list_rechecks_ev_before_commit(acase, tmp_path, monkeypatch):
    from forensics_mcp import server as S
    blob, _ = container("tar")
    src = tmp_path / "change.tar"
    src.write_bytes(blob)
    async with Client(S.server) as c:
        ev = await intake(c, acase, src)
        original = S.fsops.archive_inventory
        def changed(*args, **kwargs):
            result = original(*args, **kwargs)
            record = S.E.load_record(acase, ev)
            copy = acase.dir / record["stored"]["path"]
            copy.chmod(0o644)
            copy.write_bytes(b"x" * len(blob))
            copy.chmod(0o444)
            return result
        monkeypatch.setattr(S.fsops, "archive_inventory", changed)
        out = await call(c, "forensics_fs_list", case_id=acase.id, evidence_id=ev)
        assert "_error" in out, out
        assert not list((acase.dir / "forensics/analysis").glob("fs-list-*.json"))
        assert S.custody(acase).entries()[-1]["event"] == "integrity-failed"
