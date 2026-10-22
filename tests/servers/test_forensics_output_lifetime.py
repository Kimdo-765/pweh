"""합성 증거 요청의 취소·출력 교체를 실제 보관 기록 커밋 경계에서 확인한다."""

import asyncio
import os
import threading
import time
import zipfile

import anyio
import pytest
from mcp import Client

from mcp_helpers import call
from servers.test_forensics_fs import _fat_card, _intake, _wait, fcase, anyio_backend

pytestmark = pytest.mark.anyio


async def wait_event(event):
    with anyio.fail_after(5):
        while not event.is_set():
            await anyio.sleep(0.005)


@pytest.mark.parametrize("cancel_kind", ["task", "scope"])
@pytest.mark.parametrize("stage", ["partitions", "image_check", "list_walk", "list_write", "list_commit", "archive"])
async def test_cancel_releases_worker_and_uncommitted_output(fcase, tmp_path, monkeypatch, stage, cancel_kind):
    from forensics_mcp import server as S
    from pweh import evidence as E

    image = _fat_card(tmp_path)
    if stage == "archive":
        image = tmp_path / "logical.zip"
        with zipfile.ZipFile(image, "w") as archive:
            archive.writestr("note.txt", "합성 파일")
    started, closed, observed = (threading.Event() for _ in range(3))
    opened_fds = []
    real_open, real_close = S._open_evidence_sync, E.OpenedEvidence.close

    def tracked_open(*args, **kwargs):
        opened = real_open(*args, **kwargs)
        opened_fds.append(opened.fd)
        return opened

    def tracked_close(self):
        real_close(self)
        closed.set()

    def pause_until_cancel(check):
        started.set()
        end = time.monotonic() + 4
        while time.monotonic() < end:
            try:
                result = check()
            except S.JobCancelled:
                observed.set()
                raise
            if result:
                observed.set()
                return
            time.sleep(0.005)
        raise AssertionError("작업 스레드에 취소가 전달되지 않음")

    async with Client(S.server) as client:
        ev = await _intake(client, fcase, image)
        monkeypatch.setattr(S, "_open_evidence_sync", tracked_open)
        monkeypatch.setattr(E.OpenedEvidence, "close", tracked_close)
        if stage == "partitions":
            original = S.pfs.analyze_image

            def analyze(*args, **kwargs):
                pause_until_cancel(kwargs["budget"].cancel)
                return original(*args, **kwargs)

            monkeypatch.setattr(S.pfs, "analyze_image", analyze)
            operation = S.forensics_partitions
        elif stage in ("image_check", "list_walk"):
            original = S.fsops.iter_volumes

            def volumes(*args, **kwargs):
                pause_until_cancel(kwargs["cancel"])
                yield from original(*args, **kwargs)

            monkeypatch.setattr(S.fsops, "iter_volumes", volumes)
            operation = S.forensics_image_check if stage == "image_check" else S.forensics_fs_list
        elif stage in ("list_write", "archive"):
            original = S._HashingWriter.write

            def write(self, data):
                pause_until_cancel(self.check)
                return original(self, data)

            monkeypatch.setattr(S._HashingWriter, "write", write)
            operation = S.forensics_fs_list
        else:
            original = S._checked_evidence_event

            def commit(*args, **kwargs):
                pause_until_cancel(kwargs["check"])
                return original(*args, **kwargs)

            monkeypatch.setattr(S, "_checked_evidence_event", commit)
            operation = S.forensics_fs_list

        if cancel_kind == "task":
            task = asyncio.create_task(operation(case_id=fcase.id, evidence_id=ev))
            await wait_event(started)
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await task
        else:
            scope = anyio.CancelScope()

            async def run():
                with scope:
                    await operation(case_id=fcase.id, evidence_id=ev)

            async with anyio.create_task_group() as group:
                group.start_soon(run)
                await wait_event(started)
                scope.cancel()
        await wait_event(closed)
        assert observed.is_set()
        for fd in opened_fds:
            with pytest.raises(OSError):
                os.fstat(fd)
        analysis = fcase.dir / "forensics/analysis"
        assert not analysis.exists() or list(analysis.iterdir()) == []
        assert [e["event"] for e in E.CustodyLog(fcase).entries()] == ["intake"]


@pytest.mark.parametrize("container", ["fat", "zip"])
@pytest.mark.parametrize("output", ["list", "file", "manifest", "directory"])
@pytest.mark.parametrize("replacement", ["regular", "symlink", "hardlink"])
async def test_replaced_output_never_commits(fcase, tmp_path, monkeypatch, container, output, replacement):
    from forensics_mcp import server as S
    from pweh import evidence as E

    image = _fat_card(tmp_path)
    selection = "/record/20261001_110000.mp4"
    if container == "zip":
        image = tmp_path / "logical.zip"
        selection = "note.txt"
        with zipfile.ZipFile(image, "w") as archive:
            archive.writestr(selection, "합성 파일")
    victim = tmp_path / "outside.txt"
    victim.write_text("keep", encoding="utf-8")
    victim.chmod(0o444)
    replaced = []
    real_append = E.CustodyLog.append

    def swap_then_append(self, event, **kwargs):
        if event in ("list", "extract"):
            data = kwargs["data"]
            if event == "list":
                path = fcase.dir / data["result_path"]
            else:
                directory = fcase.dir / data["output_dir"]
                directory.chmod(0o755)
                path = directory / "manifest.json"
                if output == "file":
                    path = next(p for p in directory.iterdir() if p.name != "manifest.json")
                elif output == "directory":
                    directory.rename(directory.with_name(directory.name + "-moved"))
                    directory.mkdir()
                    (directory / "keep.txt").write_text("keep", encoding="utf-8")
                    replaced.append(directory / "keep.txt")
                    return real_append(self, event, **kwargs)
            path.unlink()
            if replacement == "regular":
                path.write_text("replacement", encoding="utf-8")
                path.chmod(0o444)
            elif replacement == "symlink":
                path.symlink_to(victim)
            else:
                os.link(victim, path)
            replaced.append(path)
        return real_append(self, event, **kwargs)

    async with Client(S.server) as client:
        ev = await _intake(client, fcase, image)
        monkeypatch.setattr(E.CustodyLog, "append", swap_then_append)
        if output == "list":
            result = await call(client, "forensics_fs_list", case_id=fcase.id, evidence_id=ev)
            assert "unsafe_file" in result.get("_error", ""), result
        else:
            job = await call(client, "forensics_extract", case_id=fcase.id, evidence_id=ev, paths=[selection])
            result = await _wait(client, job["job_id"])
            assert result["status"] == "failed" and result["error"]["code"] == "unsafe_file", result
    assert replaced and victim.read_text(encoding="utf-8") == "keep"
    if output == "directory":
        assert replaced[0].read_text(encoding="utf-8") == "keep", "교체된 다른 디렉터리는 정리하지 않는다"
    assert [e["event"] for e in E.CustodyLog(fcase).entries()] == ["intake"]


@pytest.mark.parametrize("container", ["fat", "zip"])
async def test_list_size_limit_removes_uncommitted_file(fcase, tmp_path, monkeypatch, container):
    from forensics_mcp import server as S
    from pweh import evidence as E

    image = _fat_card(tmp_path)
    if container == "zip":
        image = tmp_path / "logical.zip"
        with zipfile.ZipFile(image, "w") as archive:
            archive.writestr("note.txt", "합성 파일")
    async with Client(S.server) as client:
        ev = await _intake(client, fcase, image)
        monkeypatch.setattr(S, "LIST_MAX_OUTPUT_BYTES", 100)
        result = await call(client, "forensics_fs_list", case_id=fcase.id, evidence_id=ev)
        assert "output_limit" in result.get("_error", ""), result
    assert list((fcase.dir / "forensics/analysis").iterdir()) == []
    assert [e["event"] for e in E.CustodyLog(fcase).entries()] == ["intake"]
