"""이미지 도구 어댑터: 합성 정지이미지·FAT/exFAT, 출처·MCP 콘텐츠·취소·보호 경계."""

from __future__ import annotations

import asyncio
import base64
import hashlib
import io
import json
import os
import stat
import threading
import time

import pytest
from mcp import Client

from fs.builders import exfat_small, fat32_small
from mcp_helpers import call, result_data

pytestmark = pytest.mark.anyio


@pytest.fixture
def anyio_backend():
    return "asyncio"


@pytest.fixture
def icase(workspace, auth):
    from pweh.case import CaseStore

    return CaseStore(workspace["cases_dir"]).create(title="합성 이미지", authorization=auth, case_id="images")


@pytest.fixture
def png():
    from PIL import Image

    out = io.BytesIO()
    Image.new("RGB", (48, 32), (11, 87, 153)).save(out, format="PNG")
    return out.getvalue()


@pytest.fixture
def worker(monkeypatch, png):
    from pweh import imagehints as I

    calls = []

    def analyze(data, **options):
        calls.append((data, options))
        previews = []
        if options.get("preview"):
            for role in (["overview", "crop"] if options.get("crop") else ["overview"]):
                previews.append({"role": role, "mime_type": "image/png", "data": png, "width": 48, "height": 32,
                                 "crop": options.get("crop") if role == "crop" else None, "sha256": hashlib.sha256(png).hexdigest()})
        return {"report": {"schema": "pweh.image-hints/v1", "status": "ok", "input": {"sha256": hashlib.sha256(data).hexdigest(), "size": len(data)},
                           "ocr": {"text": "합성 OCR 내용"}, "warnings": []}, "previews": previews}

    monkeypatch.setattr(I, "analyze_image", analyze)
    monkeypatch.setattr(I, "resolve_image_tools", lambda _: I.ImageToolSettings())
    return calls


async def intake(client, case, path):
    args = {"purpose": "합성 이미지 시험", "legal_basis": "소유자 본인 기기", "site_type": "home", "business_purpose": "없음(가정용)", "role": "owner"}
    out = await call(client, "forensics_intake_start", case_id=case.id, image_path=str(path), **args)
    assert out.get("job_id"), out
    for _ in range(100):
        job = await call(client, "forensics_job_status", job_id=out["job_id"], wait_seconds=1)
        if job["status"] in ("succeeded", "failed", "cancelled"):
            assert job["status"] == "succeeded", job
            return job["result"]["evidence_id"]
    raise AssertionError("접수 작업 시간 초과")


async def test_case_image_content_json_artifacts_and_source(icase, png, worker):
    from case_mcp.server import server

    source = icase.dir / "input.png"
    source.write_bytes(png)
    async with Client(server) as client:
        raw = await client.call_tool("case_image_hints", {"case_id": icase.id, "path": "input.png", "crop": [1, 2, 12, 10]})
    out = result_data(raw)
    assert out["ok"], out
    report = out["report"]
    assert report["source"]["kind"] == "case-file" and report["source"]["path"] == "input.png"
    assert report["input"]["sha256"] == hashlib.sha256(png).hexdigest()
    images = [c for c in raw.content if c.type == "image"]
    assert len(images) == 2 and all(base64.b64decode(c.data) == png for c in images)
    assert base64.b64encode(png).decode() not in json.dumps(raw.structured_content)
    analysis = icase.dir / out["analysis"]["path"]
    assert json.loads(analysis.read_bytes()) == report
    assert hashlib.sha256(analysis.read_bytes()).hexdigest() == out["analysis"]["sha256"]
    for item in [out["analysis"], *report["artifacts"]["previews"]]:
        path = icase.dir / item["path"]
        assert stat.S_IMODE(path.stat().st_mode) == 0o444
        assert hashlib.sha256(path.read_bytes()).hexdigest() == item["sha256"]
    assert source.read_bytes() == png
    assert 0 < worker[0][1]["max_seconds"] <= 45


async def test_case_refuses_protected_symlink_fifo_and_oversize(icase, png, worker, tmp_path):
    from case_mcp.server import server

    (icase.dir / "emu").mkdir()
    (icase.dir / "emu/raw.png").write_bytes(png)
    (icase.dir / "alias").symlink_to(icase.dir / "emu", target_is_directory=True)
    outside = tmp_path / "outside.png"
    outside.write_bytes(png)
    (icase.dir / "outside.png").symlink_to(outside)
    os.mkfifo(icase.dir / "pipe.png")
    with (icase.dir / "large.png").open("wb") as fp:
        fp.truncate((64 << 20) + 1)
    async with Client(server) as client:
        for path in ("emu/raw.png", "alias/raw.png", "outside.png", "pipe.png", "large.png"):
            out = await call(client, "case_image_hints", case_id=icase.id, path=path)
            assert "_error" in out, (path, out)
    assert not worker


async def test_case_actual_fd_rechecks_protected_path(icase, png, worker, monkeypatch):
    from case_mcp import server as S

    (icase.dir / "input.png").write_bytes(png)
    monkeypatch.setattr(S.safeio, "fd_real_path", lambda fd: icase.dir / "emu/raw.png")
    async with Client(S.server) as client:
        out = await call(client, "case_image_hints", case_id=icase.id, path="input.png")
    assert "_error" in out and "emu" in out["_error"]
    assert not worker


async def test_evidence_image_custody_and_preview_tampering(icase, png, worker, tmp_path):
    from forensics_mcp.server import custody, server

    source = tmp_path / "still.png"
    source.write_bytes(png)
    async with Client(server) as client:
        evid = await intake(client, icase, source)
        raw = await client.call_tool("forensics_image_hints", {"case_id": icase.id, "evidence_id": evid})
        out = result_data(raw)
        assert out["ok"], out
        src = out["report"]["source"]
        assert src["kind"] == "evidence" and src["evidence_id"] == evid and src["complete"]
        assert src["evidence_sha256"] == src["sha256"] == hashlib.sha256(png).hexdigest()
        event = custody(icase).entries()[-1]
        assert event["event"] == "image-hints" and event["seq"] == out["analysis"]["custody_seq"]
        assert "합성 OCR 내용" not in json.dumps(event, ensure_ascii=False)
        assert event["data"]["analysis"]["sha256"] == out["analysis"]["sha256"]
        listed = await call(client, "forensics_evidence_list", case_id=icase.id, write_files=False)
        assert listed["derived"][0]["custody"] == "recorded"
        preview = icase.dir / out["report"]["artifacts"]["previews"][0]["path"]
        preview.chmod(0o644)
        preview.write_bytes(b"changed")
        preview.chmod(0o444)
        listed = await call(client, "forensics_evidence_list", case_id=icase.id, write_files=False)
        assert listed["derived"][0]["custody"] == "mismatch"
        assert listed["derived"][0]["previews"][0]["match"] is False
        (icase.dir / out["analysis"]["path"]).unlink()
        listed = await call(client, "forensics_evidence_list", case_id=icase.id, write_files=False)
        assert listed["derived"][0]["custody"] == "missing"


@pytest.mark.parametrize("builder", [fat32_small, exfat_small], ids=["fat32", "exfat"])
async def test_member_selection_and_deleted_ref(icase, png, worker, tmp_path, builder):
    from forensics_mcp.server import server

    b = builder()
    b.add_file("/picture.png", png)
    b.add_file("/deleted.png", png)
    b.delete("/deleted.png")
    source = tmp_path / "card.img"
    source.write_bytes(b.image())
    async with Client(server) as client:
        evid = await intake(client, icase, source)
        out = await call(client, "forensics_image_hints", case_id=icase.id, evidence_id=evid, path="/picture.png", preview=False)
        assert out["ok"], out
        src = out["report"]["source"]
        assert src["member_selected"] and src["path"] == "/picture.png" and src["deleted"] is False
        assert src["sha256"] == hashlib.sha256(png).hexdigest() and src["sha256"] != src["evidence_sha256"]
        assert out["report"]["artifacts"]["previews"] == []
        listed = await call(client, "forensics_fs_list", case_id=icase.id, evidence_id=evid)
        # 목록 파일은 합성 fixture 만 포함한다. 삭제 항목 ref 는 기존 엔진의 검증 결과에서 가져온다.
        listing = json.loads((icase.dir / listed["result_path"]).read_bytes())
        entries = [e for v in listing["volumes"] for e in v["walk"]["entries"]]
        ref = next(e["ref"] for e in entries if e.get("deleted") and not e.get("is_dir"))
        out = await call(client, "forensics_image_hints", case_id=icase.id, evidence_id=evid, ref=ref)
        assert out["ok"] and out["report"]["source"]["deleted"], out
        assert out["report"]["source"]["method"] and out["report"]["source"]["confidence"]
        assert worker[-1][0] == png
        for args in ({"ref": ref, "path": "/picture.png"}, {"ref": "madeup/0"}, {"path": "/missing.png"}, {"path": "/"}):
            out = await call(client, "forensics_image_hints", case_id=icase.id, evidence_id=evid, **args)
            assert "_error" in out, out


async def test_evidence_integrity_failure_prevents_worker(icase, png, worker, tmp_path):
    from forensics_mcp.server import server

    source = tmp_path / "still.png"
    source.write_bytes(png)
    async with Client(server) as client:
        evid = await intake(client, icase, source)
        stored = icase.dir / f"forensics/images/{evid}/still.png"
        stored.chmod(0o644)
        stored.write_bytes(b"tampered")
        stored.chmod(0o444)
        out = await call(client, "forensics_image_hints", case_id=icase.id, evidence_id=evid)
        assert "integrity_failed" in out["_error"]
    assert not worker


async def test_incomplete_member_is_not_decoded(icase, png, worker, tmp_path):
    from forensics_mcp.server import server

    b = fat32_small()
    b.add_file("/broken.png", png, size=4096)
    source = tmp_path / "broken-card.img"
    source.write_bytes(b.image())
    async with Client(server) as client:
        evid = await intake(client, icase, source)
        out = await call(client, "forensics_image_hints", case_id=icase.id, evidence_id=evid, path="/broken.png")
        assert "불완전" in out["_error"], out
    assert not worker


async def test_source_changed_during_analysis_is_recorded_and_output_rolled_back(icase, png, worker, tmp_path, monkeypatch):
    from forensics_mcp.server import custody, server
    from pweh import imagehints as I

    source = tmp_path / "still.png"
    source.write_bytes(png)
    analyze = I.analyze_image
    async with Client(server) as client:
        evid = await intake(client, icase, source)
        stored = icase.dir / f"forensics/images/{evid}/still.png"

        def change(data, **options):
            result = analyze(data, **options)
            stored.chmod(0o644)
            stored.write_bytes(b"changed during decode")
            stored.chmod(0o444)
            return result

        monkeypatch.setattr(I, "analyze_image", change)
        out = await call(client, "forensics_image_hints", case_id=icase.id, evidence_id=evid)
        assert "integrity_failed" in out["_error"], out
    entries = custody(icase).entries()
    assert entries[-1]["event"] == "integrity-failed" and not any(e["event"] == "image-hints" for e in entries)
    assert not list((icase.dir / "forensics/analysis").glob("image-hints-*"))


async def test_unrecorded_manifest_paths_are_not_followed(icase, png, worker, tmp_path, monkeypatch):
    from forensics_mcp import server as S

    source = tmp_path / "still.png"
    source.write_bytes(png)
    async with Client(S.server) as client:
        await intake(client, icase, source)
        folder = icase.dir / "forensics/analysis"
        folder.mkdir(exist_ok=True)
        planted = folder / "image-hints-planted.json"
        planted.write_text(json.dumps({"artifacts": {"previews": [{"path": str(tmp_path / "outside.png")} ]}}))
        opened = []
        read = S.safeio.read_regular

        def tracked(path, **kwargs):
            opened.append(str(path))
            return read(path, **kwargs)

        monkeypatch.setattr(S.safeio, "read_regular", tracked)
        out = await call(client, "forensics_evidence_list", case_id=icase.id, write_files=False)
        assert out["derived"][0]["custody"] == "unrecorded", out
        assert str(tmp_path / "outside.png") not in opened


async def test_case_cancellation_sets_worker_event_no_outputs(icase, png, monkeypatch):
    from case_mcp import server as S
    from pweh import imagehints as I
    from pweh.errors import PwehError

    (icase.dir / "input.png").write_bytes(png)
    entered, finished = threading.Event(), threading.Event()

    def blocked(data, **options):
        entered.set()
        assert options["cancel_event"].wait(3)
        finished.set()
        raise PwehError("취소", code="cancelled")

    monkeypatch.setattr(I, "analyze_image", blocked)
    monkeypatch.setattr(I, "resolve_image_tools", lambda _: I.ImageToolSettings())
    task = asyncio.create_task(S.case_image_hints(icase.id, "input.png"))
    for _ in range(100):
        if entered.is_set():
            break
        await asyncio.sleep(0.01)
    assert entered.is_set()
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    for _ in range(100):
        if finished.is_set():
            break
        await asyncio.sleep(0.01)
    assert finished.is_set()
    assert not list((icase.dir / "analysis").glob("image-hints-*"))


async def test_real_worker_normalized_preview(icase, png, monkeypatch):
    from case_mcp.server import server
    from pweh import imagehints as I

    monkeypatch.setattr(I, "resolve_image_tools", lambda _: I.ImageToolSettings())
    (icase.dir / "input.png").write_bytes(png)
    async with Client(server) as client:
        raw = await client.call_tool("case_image_hints", {"case_id": icase.id, "path": "input.png", "ocr": False, "qr": False})
    out = result_data(raw)
    assert out["report"]["status"] == "ok", out
    assert any(c.type == "image" for c in raw.content)
