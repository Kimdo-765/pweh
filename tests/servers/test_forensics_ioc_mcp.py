"""합성 펌웨어 보고서·FAT/exFAT 목록의 이름 대조 MCP와 출처/취소 경계 시험."""

from __future__ import annotations

import asyncio
import contextlib
import hashlib
import io
import json
import os
import stat
import tarfile
import threading
import time

import pytest
from mcp import Client

from fs.builders import exfat_small, fat32_small, put_mbr
from fwtriage.sd_builders import write_tree
from mcp_helpers import call

pytestmark = pytest.mark.anyio
PRIVATE = "PWEH_PRIVATE_SD_NAME_7b9f_3c2a"
CARD_FILE = PRIVATE + ".sh"


@pytest.fixture
def anyio_backend():
    return "asyncio"


@pytest.fixture
def icase(workspace, auth):
    from pweh.case import CaseStore
    return CaseStore(workspace["cases_dir"]).create(
        title="합성 SD 이름 대조", authorization=auth, case_id="ioccase")


async def intake(client, case, source):
    result = await call(client, "forensics_intake_start", case_id=case.id, image_path=str(source),
                        purpose="합성 이름 대조", legal_basis="소유한 합성 자료", site_type="home",
                        business_purpose="없음(합성)", role="owner")
    assert result.get("job_id"), result
    for _ in range(50):
        job = await call(client, "forensics_job_status", job_id=result["job_id"], wait_seconds=1)
        if job["status"] in ("succeeded", "failed", "cancelled"):
            assert job["status"] == "succeeded", job
            return job["result"]["evidence_id"]
    raise AssertionError("합성 접수 시간 초과")


async def prepare(case, tmp_path, *, kind="fat", deleted=False, match=True, max_entries=200000):
    """실제 생산자 도구로 합성 rootfs 결과와 카드 목록을 생성한다."""
    from forensics_mcp import server as S
    from fwtriage_mcp import server as F
    root = write_tree(case.dir / "extract" / "synthetic-root", {
        "etc/init.d/rcS": "#!/bin/sh\nmount -t vfat /dev/mmcblk0p1 /mnt/sdcard\n"
                         + "sh /mnt/sdcard/" + CARD_FILE + "\n"
                         + "sh /mnt/sdcard/second.sh\n",
    })
    async with Client(F.server) as client:
        firmware = await call(client, "fw_sd_surface", case_id=case.id, rootfs_dir=case.rel(root))
        assert firmware.get("ok"), firmware
    disk = fat32_small() if kind == "fat" else exfat_small()
    path = "/" + (CARD_FILE if match else "unrelated.txt")
    disk.add_file(path, b"SYNTHETIC FILE CONTENT MUST NOT BE READ BY IOC\n")
    disk.add_file("/second.sh" if match else "/other.txt", b"SECOND SYNTHETIC CONTENT\n")
    if deleted:
        disk.delete(path)
    source = tmp_path / "synthetic-card.img"
    source.write_bytes(disk.image())
    async with Client(S.server) as client:
        ev = await intake(client, case, source)
        listing = await call(client, "forensics_fs_list", case_id=case.id, evidence_id=ev,
                             max_entries=max_entries)
        assert listing.get("ok"), listing
    args = {"case_id": case.id, "evidence_id": ev,
            "firmware_result_path": firmware["result_path"], "fs_list_path": listing["result_path"]}
    return args


@pytest.fixture
async def prepared(icase, tmp_path):
    return await prepare(icase, tmp_path)


def analyses(case):
    return list((case.dir / "forensics/analysis").glob("sd-ioc-scan-*.json"))


async def invoke(args, **kwargs):
    """취소 시험은 실제 MCP와 같은 워커 입구를 직접 호출한다."""
    from forensics_mcp import ioc_tools as T, server as S
    values = {"partition": None, "max_matches": 200, "max_seconds": 45, **args, **kwargs}
    return await T._scan_run(T._ServerAPI(vars(S)), **values)


async def wait_event(event):
    for _ in range(500):
        if event.is_set():
            return
        await asyncio.sleep(.01)
    raise AssertionError("합성 워커 경계 대기 시간 초과")


@pytest.mark.parametrize("kind", ["fat", "exfat"])
async def test_real_reports_match_without_raw_paths_or_content(icase, tmp_path, kind, monkeypatch, caplog):
    from forensics_mcp import server as S, fsops
    args = await prepare(icase, tmp_path, kind=kind)
    monkeypatch.setattr(fsops, "read_selected_file", lambda *a, **k: pytest.fail("IoC가 카드 내용 읽기 시도"))
    start = len(S.custody(icase).entries())
    async with Client(S.server) as client:
        result = await call(client, "forensics_sd_ioc_scan", **args)
        assert result.get("ok"), result
        report = result["report"]
        assert report["summary"]["matches"] >= 2
        assert report["summary"]["by_kind"]["exact_live_name"] >= 2
        assert report["association_basis"] == "caller-selected-same-case"
        assert report["device_association_verified"] is False
        assert report["coverage"]["whole_card_examined"] is False
        assert all(m["confidence"] == "possible" for m in report["matches"])
        src = report["source"]
        assert src["evidence_id"] == args["evidence_id"]
        assert src["firmware"]["origin_basis"] == "case-artifact-index"
        assert src["listing"]["origin_basis"] == "evidence-custody-list"
        for key, path in (("firmware", args["firmware_result_path"]), ("listing", args["fs_list_path"])):
            blob = (icase.dir / path).read_bytes()
            assert src[key]["path"] == path and src[key]["sha256"] == hashlib.sha256(blob).hexdigest()
            assert src[key]["size"] == len(blob)
        saved = icase.dir / result["analysis"]["path"]
        assert stat.S_IMODE(saved.stat().st_mode) == 0o444
        assert result["analysis"]["sha256"] == hashlib.sha256(saved.read_bytes()).hexdigest()
        public = json.dumps(result) + saved.read_text() + json.dumps(S.custody(icase).entries()[start:]) + caplog.text
        for secret in (PRIVATE, "/mnt/sdcard", "SYNTHETIC FILE CONTENT", str(tmp_path), "second.sh"):
            assert secret not in public
        assert S.custody(icase).entries()[-1]["event"] == "sd-ioc-scan"
        assert len(analyses(icase)) == 1
        tool = next(t for t in (await client.list_tools()).tools if t.name == "forensics_sd_ioc_scan")
        assert tool.annotations.read_only_hint is False


@pytest.mark.parametrize("kind", ["fat", "exfat"])
async def test_deleted_name_and_match_limit_stay_candidates(icase, tmp_path, kind):
    from forensics_mcp import server as S
    args = await prepare(icase, tmp_path, kind=kind, deleted=True)
    async with Client(S.server) as client:
        result = await call(client, "forensics_sd_ioc_scan", **args)
        assert result.get("ok"), result
        assert result["report"]["summary"]["by_kind"]["deleted_name_candidate"] >= 1
        assert result["report"]["coverage"]["deleted_scope_complete"] is False
        limited = await call(client, "forensics_sd_ioc_scan", **args, max_matches=1)
        assert limited.get("ok") and limited["report"]["status"] == "partial", limited
        assert limited["report"]["summary"]["matches"] == 1


async def test_incomplete_list_and_firmware_unknown_are_not_complete(icase, tmp_path):
    from forensics_mcp import server as S
    args = await prepare(icase, tmp_path, max_entries=1)
    async with Client(S.server) as client:
        result = await call(client, "forensics_sd_ioc_scan", **args)
        assert result.get("ok") and result["report"]["status"] == "partial", result
        assert result["report"]["coverage"]["reasons"]
        assert result["report"]["coverage"]["whole_card_examined"] is False


async def test_no_names_only_means_no_match_in_examined_scope(icase, tmp_path):
    from forensics_mcp import server as S
    args = await prepare(icase, tmp_path, match=False)
    async with Client(S.server) as client:
        result = await call(client, "forensics_sd_ioc_scan", **args)
        assert result.get("ok"), result
        assert result["report"]["summary"]["matches"] == 0
        assert result["report"]["summary"]["result"] == "no_name_match_in_examined_scope"
        assert result["report"]["device_association_verified"] is False


@pytest.mark.parametrize("change", [
    {"max_matches": True}, {"max_matches": "3"}, {"max_matches": 0}, {"max_matches": 201},
    {"partition": True}, {"partition": 0}, {"partition": 4097},
    {"max_seconds": True}, {"max_seconds": 0}, {"max_seconds": 46},
    {"max_seconds": float("nan")}, {"max_seconds": float("inf")}, {"max_seconds": 10 ** 400},
    {"firmware_result_path": "/analysis/sd-surface-001.json"},
    {"firmware_result_path": "analysis/../analysis/sd-surface-001.json"},
    {"firmware_result_path": "analysis/" + PRIVATE + ".json"},
    {"fs_list_path": "forensics/analysis/fs-list-EV-0002-001.json"},
    {"fs_list_path": "forensics/analysis/fs-list-EV-0001-001.json\x00"},
])
async def test_bad_arguments_do_not_touch_case(change, monkeypatch):
    from forensics_mcp import server as S
    from pweh.errors import PwehError
    async def forbidden(*args, **kwargs):
        pytest.fail("잘못된 인자의 케이스 접근")
    monkeypatch.setattr(S, "_case", forbidden)
    args = {"case_id": "ioccase", "evidence_id": "EV-0001", "firmware_result_path": "analysis/sd-surface-001.json",
            "fs_list_path": "forensics/analysis/fs-list-EV-0001-001.json", **change}
    with pytest.raises(PwehError) as error:
        await invoke(args)
    assert PRIVATE not in str(error.value)


async def test_mcp_bad_argument_values_do_not_leak(icase, caplog):
    from forensics_mcp import server as S
    args = {"case_id": icase.id, "evidence_id": "EV-0001", "firmware_result_path": "analysis/sd-surface-001.json",
            "fs_list_path": "forensics/analysis/fs-list-EV-0001-001.json"}
    async with Client(S.server) as client:
        for field in ("firmware_result_path", "fs_list_path", "max_matches", "partition", "max_seconds"):
            result = await call(client, "forensics_sd_ioc_scan", **{**args, field: PRIVATE})
            assert "_error" in result, result
            assert PRIVATE not in json.dumps(result) + caplog.text
        incomplete = {k: v for k, v in args.items() if k != "evidence_id"}
        result = await call(client, "forensics_sd_ioc_scan", **{**incomplete, "firmware_result_path": PRIVATE})
        assert "_error" in result and PRIVATE not in json.dumps(result) + caplog.text


async def test_mcp_strict_types_and_selected_partition(prepared, icase):
    from forensics_mcp import server as S
    async with Client(S.server) as client:
        for change in ({"max_matches": True}, {"max_matches": "2"}, {"partition": True}, {"max_seconds": True}):
            result = await call(client, "forensics_sd_ioc_scan", **prepared, **change)
            assert "_error" in result, result
        result = await call(client, "forensics_sd_ioc_scan", **prepared, partition=1)
        assert result.get("ok") and result["report"]["selected_partition"] == 1, result


async def test_multiple_volumes_require_explicit_partition(prepared, icase, tmp_path):
    from forensics_mcp import server as S
    one, two = fat32_small(), exfat_small()
    for disk in (one, two):
        disk.add_file("/" + CARD_FILE, b"SYNTHETIC CONTENT")
    first, second = one.image(), two.image()
    start1, start2 = 2048, 2048 + len(first) // 512
    blob = bytearray((start2 * 512) + len(second))
    put_mbr(blob, [(0x0C, start1, len(first) // 512), (0x07, start2, len(second) // 512)])
    blob[start1 * 512:start2 * 512] = first
    blob[start2 * 512:] = second
    source = tmp_path / "two-volumes.img"
    source.write_bytes(blob)
    async with Client(S.server) as client:
        ev = await intake(client, icase, source)
        listing = await call(client, "forensics_fs_list", case_id=icase.id, evidence_id=ev)
        assert listing.get("ok"), listing
        args = {**prepared, "evidence_id": ev, "fs_list_path": listing["result_path"]}
        result = await call(client, "forensics_sd_ioc_scan", **args)
        assert "_error" in result, result
        assert not analyses(icase)
        result = await call(client, "forensics_sd_ioc_scan", **args, partition=2)
        assert result.get("ok") and result["report"]["selected_partition"] == 2, result
        assert result["report"]["summary"]["matches"] >= 1


async def test_archive_list_is_rejected(prepared, icase, tmp_path):
    from forensics_mcp import server as S
    source = tmp_path / "synthetic.tar"
    with tarfile.open(source, "w") as archive:
        item = tarfile.TarInfo(CARD_FILE)
        item.size = 1
        archive.addfile(item, io.BytesIO(b"x"))
    async with Client(S.server) as client:
        ev = await intake(client, icase, source)
        listing = await call(client, "forensics_fs_list", case_id=icase.id, evidence_id=ev)
        assert listing.get("ok"), listing
        result = await call(client, "forensics_sd_ioc_scan", **{**prepared, "evidence_id": ev, "fs_list_path": listing["result_path"]})
        assert "sdioc_input_invalid" in result.get("_error", ""), result
        assert PRIVATE not in json.dumps(result) and not analyses(icase)


@pytest.mark.parametrize("which", ["firmware", "listing"])
async def test_report_hash_mismatch_no_analysis(prepared, icase, which):
    from forensics_mcp import server as S
    path = icase.dir / prepared["firmware_result_path" if which == "firmware" else "fs_list_path"]
    path.chmod(0o644)
    path.write_bytes(path.read_bytes() + b" ")
    if which == "listing":
        path.chmod(0o444)
    async with Client(S.server) as client:
        result = await call(client, "forensics_sd_ioc_scan", **prepared)
        assert "_error" in result and PRIVATE not in json.dumps(result), result
        assert not analyses(icase)


@pytest.mark.parametrize("which", ["firmware", "listing"])
async def test_report_replacement_after_comparison_is_rejected(prepared, icase, monkeypatch, which):
    from forensics_mcp import server as S
    from pweh import sdioc
    original = sdioc.compare_sd_paths
    path = icase.dir / prepared["firmware_result_path" if which == "firmware" else "fs_list_path"]
    def compare(*args, **kwargs):
        result = original(*args, **kwargs)
        replacement = path.with_suffix(".replacement")
        replacement.write_bytes(path.read_bytes())
        replacement.chmod(0o444 if which == "listing" else 0o644)
        os.replace(replacement, path)
        return result
    monkeypatch.setattr(sdioc, "compare_sd_paths", compare)
    async with Client(S.server) as client:
        result = await call(client, "forensics_sd_ioc_scan", **prepared)
        assert "_error" in result, result
        assert not analyses(icase)
        assert all(e["event"] != "sd-ioc-scan" for e in S.custody(icase).entries())


@pytest.mark.parametrize("stage", ["load", "compare", "schema", "store"])
async def test_raw_content_exception_is_fixed_and_not_logged(prepared, icase, monkeypatch, caplog, stage):
    from forensics_mcp import server as S, ioc_tools as T
    from pweh import sdioc, sdioc_input, evidence as E
    target, attr = {"load": (sdioc_input, "open_inputs"), "compare": (sdioc, "compare_sd_paths"),
                    "schema": (T.schemas, "validate"), "store": (E, "store_analysis")}[stage]
    def fail(*args, **kwargs):
        raise ValueError(PRIVATE + " /mnt/sdcard/" + CARD_FILE)
    monkeypatch.setattr(target, attr, fail)
    async with Client(S.server) as client:
        result = await call(client, "forensics_sd_ioc_scan", **prepared)
        assert "sd_ioc_scan_failed" in result.get("_error", ""), result
        assert PRIVATE not in json.dumps(result) + caplog.text
        assert not analyses(icase)


async def test_invalid_core_report_never_exposes_schema_values(prepared, icase, monkeypatch, caplog):
    from forensics_mcp import server as S
    from pweh import sdioc
    original = sdioc.compare_sd_paths
    def compare(*args, **kwargs):
        report = original(*args, **kwargs)
        report[PRIVATE] = {"path": PRIVATE}
        return report
    monkeypatch.setattr(sdioc, "compare_sd_paths", compare)
    async with Client(S.server) as client:
        result = await call(client, "forensics_sd_ioc_scan", **prepared)
        assert "_error" in result and PRIVATE not in json.dumps(result) + caplog.text
        assert not analyses(icase)


async def test_comparison_deadline_partial_can_be_saved(prepared, icase, monkeypatch):
    from forensics_mcp import server as S
    from pweh import sdioc
    original = sdioc.compare_sd_paths
    def compare(*args, **kwargs):
        return original(*args, **{**kwargs, "deadline": time.monotonic() - 1})
    monkeypatch.setattr(sdioc, "compare_sd_paths", compare)
    async with Client(S.server) as client:
        result = await call(client, "forensics_sd_ioc_scan", **prepared)
        assert result.get("ok") and result["report"]["status"] == "partial", result
        assert len(analyses(icase)) == 1


async def test_audit_exception_after_commit_has_no_traceback(prepared, icase, monkeypatch, caplog):
    from forensics_mcp import server as S
    def fail(*args, **kwargs):
        raise ValueError(PRIVATE)
    monkeypatch.setattr(S.rt(), "audit", fail)
    async with Client(S.server) as client:
        result = await call(client, "forensics_sd_ioc_scan", **prepared)
        assert result.get("ok") and result["warnings"], result
        assert PRIVATE not in json.dumps(result) + caplog.text
        assert len(analyses(icase)) == 1


async def test_ev_change_before_commit_records_fixed_integrity_failure(prepared, icase, monkeypatch, caplog):
    from forensics_mcp import server as S
    from pweh import sdioc
    original = sdioc.compare_sd_paths
    with S._open_evidence_sync(icase, prepared["evidence_id"]) as opened:
        target = icase.dir / opened.intake["stored_path"]
    def compare(*args, **kwargs):
        report = original(*args, **kwargs)
        target.chmod(0o644)
        with target.open("r+b") as stream:
            stream.write(b"CHANGED")
        target.chmod(0o444)
        return report
    monkeypatch.setattr(sdioc, "compare_sd_paths", compare)
    start = len(S.custody(icase).entries())
    async with Client(S.server) as client:
        result = await call(client, "forensics_sd_ioc_scan", **prepared)
        assert "integrity_failed" in result.get("_error", ""), result
        events = S.custody(icase).entries()[start:]
        assert events[-1]["event"] == "integrity-failed"
        assert events[-1]["data"]["reason"] == "sd-ioc-integrity-check"
        assert not analyses(icase)
        assert PRIVATE not in json.dumps(result) + json.dumps(events) + caplog.text


async def test_case_authorization_checked_before_evidence(prepared, icase, monkeypatch):
    from forensics_mcp import server as S
    from pweh import evidence as E
    value = icase.load()
    value["authorization"] = None
    icase.meta_path.write_text(json.dumps(value))
    monkeypatch.setattr(E, "open_checked", lambda *a, **k: pytest.fail("허가 확인 전 EV 접근"))
    async with Client(S.server) as client:
        result = await call(client, "forensics_sd_ioc_scan", **prepared)
        assert "authorization_required" in result.get("_error", ""), result
        assert not analyses(icase)


@pytest.mark.parametrize("failure", ["missing", "rebuild"])
async def test_registration_privacy_configuration_fails_closed(failure):
    from types import SimpleNamespace
    from forensics_mcp.ioc_tools import register_ioc_tools
    def fail(**kwargs):
        raise ValueError(PRIVATE)
    model = SimpleNamespace(model_config={}, model_rebuild=fail)
    registered = None if failure == "missing" else SimpleNamespace(fn_metadata=SimpleNamespace(arg_model=model))
    server = SimpleNamespace(tool=lambda **kwargs: lambda fn: fn,
                             _tool_manager=SimpleNamespace(get_tool=lambda name: registered))
    with pytest.raises(RuntimeError) as error:
        register_ioc_tools(server, {})
    assert PRIVATE not in str(error.value)


@pytest.mark.parametrize("stage", ["load", "compare", "commit"])
async def test_raw_cancel_keeps_worker_fd_and_never_commits(prepared, icase, monkeypatch, stage):
    from forensics_mcp import server as S
    from pweh import evidence as E, sdioc, sdioc_input
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
    original_open = sdioc_input.open_inputs
    @contextlib.contextmanager
    def opened(case, ev, **kwargs):
        held["fd"] = ev.fd
        with original_open(case, ev, **kwargs) as inputs:
            held["inputs"] = inputs
            held["report_fds"] = [report.fd for report in inputs.reports]
            if stage == "load":
                entered.set()
                assert release.wait(5)
            yield inputs
    monkeypatch.setattr(sdioc_input, "open_inputs", opened)
    if stage in ("compare", "commit"):
        target, attr = (sdioc, "compare_sd_paths") if stage == "compare" else (E, "store_analysis")
        original = getattr(target, attr)
        def pause(*args, **kwargs):
            entered.set()
            assert release.wait(5)
            return original(*args, **kwargs)
        monkeypatch.setattr(target, attr, pause)
    task = asyncio.create_task(invoke(prepared))
    try:
        await wait_event(entered)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        assert os.fstat(held["fd"]).st_size > 0
        assert all(os.fstat(fd).st_size > 0 for fd in held["report_fds"])
    finally:
        release.set()
    await wait_event(finished)
    with pytest.raises(OSError):
        os.fstat(held["fd"])
    for fd in held["report_fds"]:
        with pytest.raises(OSError):
            os.fstat(fd)
    assert not analyses(icase)
    assert all(e["event"] != "sd-ioc-scan" for e in S.custody(icase).entries())


async def test_late_cancel_preserves_committed_result(prepared, icase, monkeypatch):
    from forensics_mcp import server as S
    from pweh import evidence as E
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
    task = asyncio.create_task(invoke(prepared))
    try:
        await wait_event(entered)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
    finally:
        release.set()
    await wait_event(finished)
    assert len(analyses(icase)) == 1
    assert S.custody(icase).entries()[-1]["event"] == "sd-ioc-scan"
