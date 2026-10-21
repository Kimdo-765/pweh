"""합성 DB·아카이브의 실제 MCP 왕복과 증거/분석 출처 경계."""

from __future__ import annotations

import hashlib
import io
import json
import sqlite3
import stat
import tarfile
import zipfile

import pytest
from mcp import Client

from fs.builders import exfat_small, fat32_small
from mcp_helpers import call

pytestmark = pytest.mark.anyio
TEXT = "PWEH 합성 메시지"


@pytest.fixture
def anyio_backend():
    return "asyncio"


@pytest.fixture
def acase(workspace, auth):
    from pweh.case import CaseStore
    return CaseStore(workspace["cases_dir"]).create(title="합성 논리 증거", authorization=auth, case_id="android")


@pytest.fixture
def database(tmp_path):
    path = tmp_path / "source.db"
    with sqlite3.connect(path) as db:
        db.execute("CREATE TABLE sms (_id INTEGER PRIMARY KEY, thread_id INTEGER, address TEXT, date INTEGER, type INTEGER, body TEXT, read INTEGER)")
        db.execute("INSERT INTO sms VALUES (1, 1, '0000', 1700000000000, 1, ?, 0)", (TEXT,))
    return path.read_bytes()


async def intake(client, case, path):
    result = await call(client, "forensics_intake_start", case_id=case.id, image_path=str(path),
                        purpose="합성 앱 자료 검사", legal_basis="소유자 제공 합성 자료", site_type="home",
                        business_purpose="없음(합성)", role="owner")
    assert result.get("job_id"), result
    for _ in range(50):
        job = await call(client, "forensics_job_status", job_id=result["job_id"], wait_seconds=1)
        if job["status"] in ("succeeded", "failed", "cancelled"):
            assert job["status"] == "succeeded", job
            return job["result"]["evidence_id"]
    raise AssertionError("합성 접수 작업 시간 초과")


def container(kind, data):
    if kind in ("fat", "exfat"):
        builder = fat32_small() if kind == "fat" else exfat_small()
        builder.add_file("/sms.db", data)
        return builder.image(), "/sms.db"
    out = io.BytesIO()
    if kind == "tar":
        with tarfile.open(fileobj=out, mode="w") as archive:
            entry = tarfile.TarInfo("data/sms.db")
            entry.size, entry.mtime = len(data), 1700000000
            archive.addfile(entry, io.BytesIO(data))
    else:
        with zipfile.ZipFile(out, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            archive.writestr("data/sms.db", data)
    return out.getvalue(), "data/sms.db"


async def test_direct_db_inventory_content_timeline_and_custody(acase, database, tmp_path):
    from forensics_mcp import server as S
    src = tmp_path / "input.db"
    src.write_bytes(database)
    async with Client(S.server) as client:
        ev = await intake(client, acase, src)
        inventory = await call(client, "forensics_sqlite_inventory", case_id=acase.id, evidence_id=ev)
        assert inventory.get("ok"), inventory
        assert TEXT not in json.dumps(inventory, ensure_ascii=False)
        artifacts = await call(client, "forensics_android_artifacts", case_id=acase.id, evidence_id=ev, families=["sms"])
        assert artifacts.get("ok"), artifacts
        assert TEXT in json.dumps(artifacts["report"]["records"], ensure_ascii=False)
        source = artifacts["report"]["source"]
        assert source["evidence_sha256"] == source["sha256"] == hashlib.sha256(database).hexdigest()
        analysis = artifacts["analysis"]
        saved = acase.dir / analysis["path"]
        assert stat.S_IMODE(saved.stat().st_mode) == 0o444
        assert hashlib.sha256(saved.read_bytes()).hexdigest() == analysis["sha256"]
        assert TEXT not in json.dumps(S.custody(acase).entries(), ensure_ascii=False)
        timeline = await call(client, "forensics_timeline", case_id=acase.id, evidence_id=ev, analysis_paths=[analysis["path"]])
        assert timeline.get("ok"), timeline
        assert timeline["report"]["events"]
        assert "2023-11-14" in json.dumps(timeline["report"]["events"])
        listed = await call(client, "forensics_evidence_list", case_id=acase.id, write_files=False)
        assert all(d["custody"] == "recorded" for d in listed["derived"])
    assert src.read_bytes() == database


@pytest.mark.parametrize("kind", ["tar", "zip", "fat", "exfat"])
async def test_selected_member_source_hash_is_distinct_from_ev(acase, database, tmp_path, kind):
    from forensics_mcp.server import server
    blob, path = container(kind, database)
    src = tmp_path / "logical.bin"
    src.write_bytes(blob)
    async with Client(server) as client:
        ev = await intake(client, acase, src)
        result = await call(client, "forensics_android_artifacts", case_id=acase.id, evidence_id=ev, path=path, families=["sms"])
        assert result.get("ok"), result
        source = result["report"]["source"]
        assert source["sha256"] == hashlib.sha256(database).hexdigest()
        assert source["evidence_sha256"] == hashlib.sha256(blob).hexdigest()
        assert source["sha256"] != source["evidence_sha256"] and source["complete"]
        assert TEXT in json.dumps(result["report"]["records"], ensure_ascii=False)


async def test_timeline_refuses_unrecorded_other_ev_and_tampered_analysis(acase, database, tmp_path):
    from forensics_mcp.server import server
    src = tmp_path / "input.db"
    src.write_bytes(database)
    async with Client(server) as client:
        ev1, ev2 = await intake(client, acase, src), await intake(client, acase, src)
        analysis = await call(client, "forensics_android_artifacts", case_id=acase.id, evidence_id=ev1, families=["sms"])
        path = analysis["analysis"]["path"]
        for ev, selected in ((ev2, path), (ev1, "forensics/analysis/unrecorded.json"), (ev1, "forensics/analysis/../images/input.db")):
            out = await call(client, "forensics_timeline", case_id=acase.id, evidence_id=ev, analysis_paths=[selected])
            assert "_error" in out, out
        saved = acase.dir / path
        saved.chmod(0o644)
        saved.write_bytes(saved.read_bytes() + b" ")
        saved.chmod(0o444)
        out = await call(client, "forensics_timeline", case_id=acase.id, evidence_id=ev1, analysis_paths=[path])
        assert "_error" in out, out
        listed = await call(client, "forensics_evidence_list", case_id=acase.id, write_files=False)
        assert next(d for d in listed["derived"] if d["path"] == path)["custody"] == "mismatch"


async def test_sidecar_pair_and_input_limits_fail_before_parsing(acase, database, tmp_path):
    from forensics_mcp.server import server
    src = tmp_path / "logical.zip"
    with zipfile.ZipFile(src, "w") as archive:
        archive.writestr("db/sms.db", database)
        archive.writestr("other.db-wal", b"not a WAL")
    async with Client(server) as client:
        ev = await intake(client, acase, src)
        for arguments in ({"path": "db/sms.db", "wal_path": "other.db-wal"},
                          {"path": "db/sms.db", "ref": "arc:0"}, {"max_seconds": 0},
                          {"max_records": 10001}, {"families": ["arbitrary"]}):
            out = await call(client, "forensics_android_artifacts", case_id=acase.id, evidence_id=ev, **arguments)
            assert "_error" in out, (arguments, out)


async def test_analysis_cannot_commit_changed_ev(acase, database, tmp_path, monkeypatch):
    from forensics_mcp import server as S
    from pweh import sqliteparse
    src = tmp_path / "input.db"
    src.write_bytes(database)
    async with Client(S.server) as client:
        ev = await intake(client, acase, src)
        original = sqliteparse.analyze_sqlite
        def analyze(*args, **kwargs):
            report = original(*args, **kwargs)
            opened = S._open_evidence_sync(acase, ev)
            try:
                target = acase.dir / opened.intake["stored_path"]
            finally:
                opened.close()
            target.chmod(0o644)
            target.write_bytes(database + b"changed")
            target.chmod(0o444)
            return report
        monkeypatch.setattr(sqliteparse, "analyze_sqlite", analyze)
        out = await call(client, "forensics_sqlite_inventory", case_id=acase.id, evidence_id=ev)
        assert "_error" in out, out
        assert not list((acase.dir / "forensics/analysis").glob("sqlite-inventory-*.json"))
        assert S.custody(acase).entries()[-1]["event"] == "integrity-failed"


@pytest.mark.parametrize("builder", [fat32_small, exfat_small], ids=["fat32", "exfat"])
async def test_deleted_database_uncertainty_reaches_rows_and_timeline(acase, database, tmp_path, builder):
    from forensics_mcp import server as S
    disk = builder()
    disk.add_file("/sms.db", database)
    disk.delete("/sms.db")
    source = tmp_path / "deleted-db.img"
    source.write_bytes(disk.image())
    async with Client(S.server) as client:
        ev = await intake(client, acase, source)
        listed = await call(client, "forensics_fs_list", case_id=acase.id, evidence_id=ev)
        listing = json.loads((acase.dir / listed["result_path"]).read_bytes())
        entries = [e for v in listing["volumes"] for e in v["walk"]["entries"]]
        ref = next(e["ref"] for e in entries if e.get("deleted") and not e.get("is_dir"))
        for tool in ("forensics_sqlite_inventory", "forensics_android_artifacts"):
            kwargs = {"families": ["sms"]} if tool == "forensics_android_artifacts" else {}
            result = await call(client, tool, case_id=acase.id, evidence_id=ev, ref=ref, **kwargs)
            assert result.get("ok"), result
            report = result["report"]
            assert report["source"]["deleted"] and report["source"]["complete"]
            assert report["status"] == "partial", report
            assert report["coverage"]["selection_uncertain"] == ["database"]
            assert "selection_uncertain" in report["warnings"]
        assert report["records"] and report["events"]
        assert all(item["confidence"] == "possible" for item in report["records"] + report["events"])
        assert report["coverage"]["record_state_basis"] == "selected-database-snapshot"
        timeline = await call(client, "forensics_timeline", case_id=acase.id, evidence_id=ev,
                              analysis_paths=[result["analysis"]["path"]])
        assert timeline.get("ok"), timeline
        app_events = [event for event in timeline["report"]["events"] if event.get("analysis_ref")]
        assert app_events and all(event["confidence"] == "possible" for event in app_events)
        assert timeline["report"]["status"] == "partial"
