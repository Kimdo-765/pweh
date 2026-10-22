"""합성 카드의 자동 선정·fresh 재선택·마스킹·원자 기록·취소 연결 시험."""
from __future__ import annotations

import asyncio
import copy
import hashlib
import json
import os
import stat
import threading
import time
from types import SimpleNamespace

import pytest
from mcp import Client
from fs.builders import fat12_small, exfat_small, put_mbr
from mcp_helpers import call
from servers.test_forensics_secrets_mcp import scase, intake, event_wait, anyio_backend

pytestmark = pytest.mark.anyio
SECRET = "SYNTHETIC_SURVEY_PRIVATE_7b95"
CONTENT = ("password=" + SECRET + "\n").encode()
TOOL = "forensics_scan_secrets_from_list"


@pytest.mark.parametrize("tool", ["forensics_scan_secrets", TOOL])
@pytest.mark.parametrize("key,value", [
    ("partition", SECRET), ("xor_key", SECRET), ("max_seconds", SECRET),
    ("case_id", {"private": SECRET}), ("evidence_id", {"private": SECRET}),
])
async def test_sdk_invalid_arguments_hide_inputs_in_reply_and_log(tool, key, value, monkeypatch, caplog):
    from forensics_mcp import server as S

    async def forbidden(*args, **kwargs):
        pytest.fail("SDK 입력 거부 전에 케이스에 접근했습니다.")

    monkeypatch.setattr(S, "_case", forbidden)
    args = {"case_id": "synthetic", "evidence_id": "EV-0001"}
    if tool == TOOL:
        args["fs_list_path"] = "forensics/analysis/fs-list-EV-0001-001.json"
    args[key] = value
    async with Client(S.server) as client:
        reply = await client.call_tool(tool, args)
    assert reply.is_error
    assert SECRET not in reply.model_dump_json() + caplog.text


@pytest.mark.parametrize("tool,key", [
    (TOOL, "fs_list_path"), ("forensics_scan_secrets", "ref"),
    ("forensics_scan_secrets", "path"), ("forensics_scan_secrets", "method"),
    ("forensics_scan_secrets", "max_hits"),
])
async def test_sdk_tool_specific_invalid_arguments_hide_inputs(tool, key, monkeypatch, caplog):
    from forensics_mcp import server as S

    async def forbidden(*args, **kwargs):
        pytest.fail("SDK 입력 거부 전에 케이스에 접근했습니다.")

    monkeypatch.setattr(S, "_case", forbidden)
    args = {"case_id": "synthetic", "evidence_id": "EV-0001", key: {"private": SECRET}}
    async with Client(S.server) as client:
        reply = await client.call_tool(tool, args)
    assert reply.is_error
    assert SECRET not in reply.model_dump_json() + caplog.text


@pytest.mark.parametrize("tool", ["forensics_scan_secrets", TOOL])
@pytest.mark.parametrize("lookup", ["missing", "rebuild"])
async def test_private_sdk_configuration_failure_refuses_registration(tool, lookup):
    from forensics_mcp.secret_survey_tools import register_secret_survey_tools
    from forensics_mcp.secrets_tools import register_secrets_tools

    def rebuild(**kwargs):
        raise RuntimeError(SECRET)

    model = SimpleNamespace(model_config={}, model_rebuild=rebuild)
    registered = None if lookup == "missing" else SimpleNamespace(fn_metadata=SimpleNamespace(arg_model=model))
    server = SimpleNamespace(tool=lambda **kwargs: lambda fn: fn,
                             _tool_manager=SimpleNamespace(get_tool=lambda name: registered))
    register = register_secret_survey_tools if tool == TOOL else register_secrets_tools
    with pytest.raises(RuntimeError) as error:
        register(server, {})
    assert SECRET not in str(error.value)
    assert error.value.__suppress_context__


def analyses(case):
    return list((case.dir / "forensics/analysis").glob("secrets-survey-*.json"))


async def setup_card(client, case, tmp_path, *, kind="fat", deleted=False, vdl=False, extra=False):
    disk = exfat_small() if kind == "exfat" else fat12_small()
    options = {"data_length": len(CONTENT) + 64, "valid_data_length": len(CONTENT), "residual": b"R" * 64} if vdl else {}
    disk.add_file("/private-name.log", CONTENT, **options)
    if extra:
        disk.add_file("/secret-video.mp4", CONTENT)
        disk.add_file("/empty.cfg", b"")
        disk.add_file("/binary.cfg", b"\x00\xff\x00")
    if deleted:
        disk.delete("/private-name.log")
    path = tmp_path / "synthetic.img"
    path.write_bytes(disk.image())
    ev = await intake(client, case, path)
    listed = await call(client, "forensics_fs_list", case_id=case.id, evidence_id=ev)
    assert listed.get("ok"), listed
    return ev, listed["result_path"]


async def survey(client, case, ev, path, **kwargs):
    return await call(client, TOOL, case_id=case.id, evidence_id=ev, fs_list_path=path, **kwargs)


async def invoke(case, ev, path, **kwargs):
    from forensics_mcp import secret_survey_tools as T, server as S
    args = dict(partition=None, xor_key=None, max_seconds=45)
    args.update(kwargs)
    return await T._survey_run(T._ServerAPI(vars(S)), case_id=case.id, evidence_id=ev, fs_list_path=path, **args)


@pytest.mark.parametrize("kind,deleted,vdl", [("fat",False,False),("exfat",False,False),("fat",True,False),("exfat",True,False),("exfat",False,True)])
async def test_actual_list_selection_masking_and_custody(scase, tmp_path, kind, deleted, vdl, caplog):
    from forensics_mcp import server as S
    async with Client(S.server) as client:
        ev, path = await setup_card(client, scase, tmp_path, kind=kind, deleted=deleted, vdl=vdl)
        start = len(S.custody(scase).entries())
        out = await survey(client, scase, ev, path)
        assert out.get("ok"), out
        report = out["report"]
        assert report["coverage"]["files_read_complete"] == 1
        row = report["files"][0]
        assert row["source"]["selected_sha256"] == hashlib.sha256(CONTENT).hexdigest()
        assert row["source"]["selected_size"] == len(CONTENT)
        assert row["source"]["declared_size"] == len(CONTENT) + (64 if vdl else 0)
        assert row["source"]["residual_unexamined"] is vdl
        assert row["source"]["deleted"] is deleted
        assert report["coverage"]["whole_card_examined"] is False
        assert any(m["digest"] == S.rt().secret_digest(scase.id, SECRET) for m in row["scan"]["matches"])
        saved = scase.dir / out["analysis"]["path"]
        assert stat.S_IMODE(saved.stat().st_mode) == 0o444
        assert hashlib.sha256(saved.read_bytes()).hexdigest() == out["analysis"]["sha256"]
        public = json.dumps(out) + saved.read_text() + json.dumps(S.custody(scase).entries()[start:]) + caplog.text
        for raw in (SECRET, "private-name.log", "password=", str(tmp_path)):
            assert raw not in public
        assert S.custody(scase).entries()[-1]["event"] == "secrets-survey"
        tools = (await client.list_tools()).tools
        tool = next(t for t in tools if t.name == TOOL)
        assert set(tool.input_schema["properties"]) == {"case_id","evidence_id","fs_list_path","partition","xor_key","max_seconds"}


async def test_policy_exclusions_do_not_read_media_and_binary_is_unsupported(scase, tmp_path, monkeypatch):
    from forensics_mcp import secret_survey_tools as T, server as S
    calls = []
    original = T.read_survey_target
    def read(opened, target, **kw):
        calls.append(target.ref)
        return original(opened, target, **kw)
    monkeypatch.setattr(T, "read_survey_target", read)
    async with Client(S.server) as client:
        ev, path = await setup_card(client, scase, tmp_path, extra=True)
        out = await survey(client, scase, ev, path)
        assert out.get("ok"), out
        r = out["report"]
        assert r["selection"]["excluded"] == {"media_name":1,"empty_data":1,"file_too_large":0}
        assert len(calls) == 2 and r["coverage"]["files_scan_unsupported"] == 1
        assert r["status"] == "partial" and r["summary"]["hits"] > 0


async def test_all_listed_volumes_and_explicit_partition(scase, tmp_path):
    from forensics_mcp import server as S
    a, b = fat12_small(), exfat_small()
    a.add_file("/first.txt", CONTENT)
    b.add_file("/second.txt", b"token=SYNTHETIC_SECOND_TOKEN\n")
    aa, bb = a.image(), b.image()
    disk = bytearray(512 + len(aa) + len(bb))
    disk[512:512+len(aa)], disk[512+len(aa):] = aa, bb
    put_mbr(disk, [(1,1,len(aa)//512),(7,1+len(aa)//512,len(bb)//512)])
    p = tmp_path / "two.img"
    p.write_bytes(disk)
    async with Client(S.server) as client:
        ev = await intake(client, scase, p)
        listed = await call(client,"forensics_fs_list",case_id=scase.id,evidence_id=ev)
        out = await survey(client,scase,ev,listed["result_path"])
        assert out.get("ok"), out
        assert [f["target"]["partition"] for f in out["report"]["files"]] == [1,2]
        chosen = await survey(client,scase,ev,listed["result_path"],partition=2)
        assert chosen.get("ok"), chosen
        assert len(chosen["report"]["files"]) == 1
        assert chosen["report"]["files"][0]["target"]["partition"] == 2


@pytest.mark.parametrize("kwargs", [{"partition":True},{"partition":1.0},{"partition":0},{"xor_key":True},{"xor_key":144.0},{"xor_key":1},{"max_seconds":False},{"max_seconds":0},{"max_seconds":46},{"max_seconds":float("inf")},{"fs_list_path":"/private/SECRET"}])
async def test_invalid_arguments_never_open_case(kwargs, monkeypatch):
    from forensics_mcp import secret_survey_tools as T
    class NoCase:
        async def _case(self, *a):
            pytest.fail("잘못된 인자가 케이스를 열었습니다")
    args = dict(case_id="invalid", evidence_id="EV-0001", fs_list_path="forensics/analysis/fs-list-EV-0001-001.json",partition=None,xor_key=None,max_seconds=45)
    args.update(kwargs)
    with pytest.raises(Exception) as exc:
        await T._survey_run(NoCase(), **args)
    assert exc.value.code == "validation_failed" and "private" not in str(exc.value)


@pytest.mark.parametrize("reason", ["refs_unverifiable","metadata_unverifiable","incomplete_file","read_failed","time_limit"])
async def test_read_failures_are_closed_and_attempted(scase, tmp_path, monkeypatch, reason):
    from forensics_mcp import secret_survey_tools as T, server as S
    def read(*a, **kw):
        raise T.SurveyReadError(reason)
    monkeypatch.setattr(T,"read_survey_target",read)
    async with Client(S.server) as client:
        ev,path = await setup_card(client,scase,tmp_path)
        out = await survey(client,scase,ev,path)
        assert out.get("ok"), out
        r = out["report"]
        assert r["coverage"]["files_attempted"] == r["coverage"]["files_read_failed"] == 1
        assert r["coverage"]["read_complete_bytes"] == 0
        assert r["files"][0]["reason"] == reason and r["status"] == "partial"


@pytest.mark.parametrize("field,value", [("size",999),("first_cluster",999),("name","forged-name"),("deleted",True),("parent_deleted",True),("name_lossy",True)])
async def test_stored_metadata_mismatch_is_fatal(scase,tmp_path,monkeypatch,field,value):
    from forensics_mcp import secret_survey_tools as T, server as S
    original=T.read_survey_target
    def read(opened,target,**kw):
        listing=copy.deepcopy(kw["listing"])
        listing["volumes"][target.volume_index]["walk"]["entries"][target.entry_index][field]=value
        kw["listing"]=listing
        return original(opened,target,**kw)
    monkeypatch.setattr(T,"read_survey_target",read)
    async with Client(S.server) as client:
        ev,path=await setup_card(client,scase,tmp_path)
        out=await survey(client,scase,ev,path)
        assert "secret_survey_input_changed" in out.get("_error",""),out
        assert not analyses(scase)
        assert not any(e["event"] == "integrity-failed" for e in S.custody(scase).entries())


async def test_raw_worker_cancel_retains_fds_until_worker_exits(scase,tmp_path,monkeypatch):
    from forensics_mcp import secret_survey_tools as T, server as S
    entered,release,finished=threading.Event(),threading.Event(),threading.Event()
    original=T.read_survey_target
    held=[]
    def read(opened,*args,**kw):
        held.append(opened.fd)
        entered.set()
        assert release.wait(5)
        try:
            return original(opened,*args,**kw)
        finally:
            finished.set()
    monkeypatch.setattr(T,"read_survey_target",read)
    async with Client(S.server) as client:
        ev,path=await setup_card(client,scase,tmp_path)
        task=asyncio.create_task(invoke(scase,ev,path))
        await event_wait(entered)
        task.cancel()
        await asyncio.sleep(.02)
        assert os.fstat(held[0]).st_size > 0
        release.set()
        with pytest.raises(asyncio.CancelledError):
            await task
        await event_wait(finished)
        for _ in range(200):
            try: os.fstat(held[0])
            except OSError: break
            await asyncio.sleep(.01)
        else: pytest.fail("워커가 EV fd를 닫지 않았습니다")
        assert not analyses(scase)


async def test_exception_body_never_reaches_result_or_logs(scase,tmp_path,monkeypatch,caplog):
    from forensics_mcp import secret_survey_tools as T, server as S
    def read(*a,**kw):
        raise RuntimeError(SECRET)
    monkeypatch.setattr(T,"read_survey_target",read)
    async with Client(S.server) as client:
        ev,path=await setup_card(client,scase,tmp_path)
        out=await survey(client,scase,ev,path)
        assert "secret_survey_failed" in out.get("_error",""),out
        assert SECRET not in json.dumps(out)+caplog.text
        assert not analyses(scase)


async def test_explicit_xor144_uses_existing_scanner(scase,tmp_path):
    from forensics_mcp import server as S
    disk=fat12_small()
    disk.add_file("/coded.cfg",bytes(b ^ 144 for b in CONTENT))
    p=tmp_path/"xor.img"
    p.write_bytes(disk.image())
    async with Client(S.server) as client:
        ev=await intake(client,scase,p)
        listed=await call(client,"forensics_fs_list",case_id=scase.id,evidence_id=ev)
        out=await survey(client,scase,ev,listed["result_path"],xor_key=144)
        assert out.get("ok"),out
        assert out["report"]["summary"]["hits"] > 0
        assert out["report"]["files"][0]["scan"]["params"]["xor_key"] == 144


@pytest.mark.parametrize("mode",["file_limit","hit_limit"])
async def test_global_cutoff_never_reads_next_target(scase,tmp_path,monkeypatch,mode):
    from forensics_mcp import secret_survey_tools as T, server as S
    disk=fat12_small()
    total=33 if mode == "file_limit" else 5
    for i in range(total):
        disk.add_file(f"/file{i:02d}.txt", b"a\n" if mode == "file_limit" else CONTENT*50)
    p=tmp_path/"limits.img"
    p.write_bytes(disk.image())
    seen=[]
    original=T.read_survey_target
    def read(opened,target,**kw):
        seen.append(target.ref)
        return original(opened,target,**kw)
    monkeypatch.setattr(T,"read_survey_target",read)
    async with Client(S.server) as client:
        ev=await intake(client,scase,p)
        listed=await call(client,"forensics_fs_list",case_id=scase.id,evidence_id=ev)
        out=await survey(client,scase,ev,listed["result_path"])
        assert out.get("ok"),out
        report=out["report"]
        assert mode in report["coverage"]["reasons"]
        assert len(seen) == (32 if mode == "file_limit" else 4)
        if mode == "hit_limit":
            assert report["summary"]["hits"] == 200
        assert report["coverage"]["analysis_complete"] is False


async def test_completed_selection_timeout_records_exact_unattempted(scase,tmp_path,monkeypatch):
    from types import SimpleNamespace
    from forensics_mcp import secret_survey_tools as T, server as S
    from pweh import secret_survey as C
    original=C.plan_survey
    def plan(*a,**kw):
        out=original(*a,**kw)
        monkeypatch.setattr(T,"time",SimpleNamespace(monotonic=lambda:kw["deadline"]+1))
        return out
    monkeypatch.setattr(C,"plan_survey",plan)
    # 선정 직후 검사는 완료된 선정의 예산 종료를 partial로 넘기기 위해 시간만 생략해야 한다.
    async with Client(S.server) as client:
        ev,path=await setup_card(client,scase,tmp_path)
        out=await survey(client,scase,ev,path)
        assert out.get("ok"),out
        r=out["report"]
        assert r["coverage"]["files_attempted"] == 0
        assert r["coverage"]["files_unattempted"] == 1
        assert "time_limit" in r["coverage"]["reasons"]


async def test_scanner_time_partial_is_stored_after_shared_deadline(scase,tmp_path,monkeypatch):
    from forensics_mcp import secret_survey_tools as T, server as S
    from pweh import secretscan
    original=secretscan.scan_secrets
    def scan(data,**kw):
        kw["deadline"]=time.monotonic()-1
        return original(data,**kw)
    monkeypatch.setattr(secretscan,"scan_secrets",scan)
    async with Client(S.server) as client:
        ev,path=await setup_card(client,scase,tmp_path)
        out=await survey(client,scase,ev,path)
        assert out.get("ok"),out
        r=out["report"]
        assert r["coverage"]["files_read_complete"] == 1
        assert r["coverage"]["files_scanned_partial"] == 1
        assert r["files"][0]["scan"]["coverage"]["scanned_bytes"] == 0


async def test_cancellation_after_scan_before_commit_creates_no_report(scase,tmp_path,monkeypatch):
    from forensics_mcp import server as S
    from pweh import secretscan
    original=secretscan.scan_secrets
    def scan(*a,**kw):
        out=original(*a,**kw)
        kw["cancel"].__self__.set()
        return out
    monkeypatch.setattr(secretscan,"scan_secrets",scan)
    async with Client(S.server) as client:
        ev,path=await setup_card(client,scase,tmp_path)
        out=await survey(client,scase,ev,path)
        assert "cancelled" in out.get("_error",""),out
        assert not analyses(scase)


async def test_final_list_replacement_is_fatal_and_atomic(scase,tmp_path,monkeypatch):
    from forensics_mcp import server as S
    from pweh import secretscan
    async with Client(S.server) as client:
        ev,path=await setup_card(client,scase,tmp_path)
        original=secretscan.scan_secrets
        def scan(*a,**kw):
            out=original(*a,**kw)
            target=scase.dir/path
            replace=target.with_name("synthetic-replacement.json")
            replace.write_bytes(target.read_bytes())
            replace.chmod(0o444)
            os.replace(replace,target)
            return out
        monkeypatch.setattr(secretscan,"scan_secrets",scan)
        out=await survey(client,scase,ev,path)
        assert "secret_survey_input_changed" in out.get("_error",""),out
        assert not analyses(scase)
        assert not any(e["event"] == "secrets-survey" for e in S.custody(scase).entries())


async def test_commit_survives_late_cancel_and_auxiliary_audit_error(scase,tmp_path,monkeypatch,caplog):
    from forensics_mcp import secret_survey_tools as T, server as S
    original=T.read_survey_target
    stop=[]
    def read(*a,**kw):
        stop.append(kw["cancel"].__self__)
        return original(*a,**kw)
    monkeypatch.setattr(T,"read_survey_target",read)
    async with Client(S.server) as client:
        ev,path=await setup_card(client,scase,tmp_path)
        def audit(*a,**kw):
            stop[0].set()
            raise RuntimeError(SECRET)
        monkeypatch.setattr(S.rt(),"audit",audit)
        out=await survey(client,scase,ev,path)
        assert out.get("ok"),out
        assert len(analyses(scase)) == 1
        assert S.custody(scase).entries()[-1]["event"] == "secrets-survey"
        assert SECRET not in json.dumps(out)+caplog.text
        assert out.get("warnings"),out


@pytest.mark.parametrize("kind",["fat","exfat"])
async def test_deleted_parent_remains_uncertain(scase,tmp_path,kind):
    from forensics_mcp import server as S
    disk=fat12_small() if kind == "fat" else exfat_small()
    disk.mkdir("/gone")
    disk.add_file("/gone/config.log",CONTENT)
    disk.delete("/gone")
    p=tmp_path/"deleted-parent.img"
    p.write_bytes(disk.image())
    async with Client(S.server) as client:
        ev=await intake(client,scase,p)
        listed=await call(client,"forensics_fs_list",case_id=scase.id,evidence_id=ev)
        out=await survey(client,scase,ev,listed["result_path"])
        assert out.get("ok"),out
        r=out["report"]
        assert r["coverage"]["files_read_complete"] == 1
        assert r["files"][0]["source"]["parent_deleted"] is True
        assert r["coverage"]["selection_uncertain"] and r["status"] == "partial"
