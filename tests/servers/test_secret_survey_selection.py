"""전용 fresh reader의 항목 신원·단일 계획·fd 소유권·읽기 실패 경계."""
from __future__ import annotations

import contextlib
import copy
import os
import time
from types import SimpleNamespace

import pytest

from pweh.secret_survey import SurveyTarget
from pweh import evidence as E
from pweh.fs.common import FsError
from forensics_mcp import secret_survey_selection as R


@pytest.fixture
def selected(tmp_path, monkeypatch):
    path=tmp_path/"synthetic-evidence.bin"
    path.write_bytes(b"synthetic")
    fd=os.open(path,os.O_RDONLY)
    opened=SimpleNamespace(fd=fd,st=os.fstat(fd),intake={"size":9})
    entry={"ref":"c2/0","fs":"fat32","is_dir":False,"deleted":False,"name_lossy":False,
           "size":3,"first_cluster":4,"name":"private.txt","parent_deleted":False}
    partition={"index":1,"start_offset":0,"size_bytes":9}
    listing={"volumes":[{"partition":copy.deepcopy(partition),"walk":{"entries":[copy.deepcopy(entry)]}}]}
    target=SurveyTarget(0,0,1,"c2/0","fat32",3,3,False,False,False)
    state={"plan_calls":0,"iter_calls":0,"entry":entry,"partition":partition,
           "pd":{"complete":True,"method":"chain","confidence":"high"},"chunks":[b"abc"]}
    class Vol:
        def step_cap(self, limits):
            return 10000
        def content_plan(self,*a,**kw):
            state["plan_calls"]+=1
            return SimpleNamespace(size=3,to_dict=lambda **kw:state["pd"])
        def iter_plan(self,*a,**kw):
            state["iter_calls"]+=1
            yield from state["chunks"]
    vol=Vol()
    monkeypatch.setattr(R.fsops,"image_reader",lambda borrowed:contextlib.nullcontext(object()))
    monkeypatch.setattr(R.fsops,"open_partition_volume",lambda *a,**kw:(state["partition"],vol))
    monkeypatch.setattr(R.fsops,"resolve_targets",lambda *a,**kw:([state["entry"]],[]))
    def read(**kwargs):
        return R.read_survey_target(opened,target,listing=listing,deadline=time.monotonic()+20,
                                    cancel=kwargs.get("cancel",lambda:False))
    yield opened,listing,state,read,path,vol
    os.close(fd)


def test_one_plan_read_borrowed_fd_and_closed_source(selected):
    opened,listing,state,read,path,vol=selected
    data,source=read()
    assert data == b"abc"
    assert state["plan_calls"] == state["iter_calls"] == 1
    assert len(source) == 14 and source["parent_deleted"] is False
    assert "name" not in source and "path" not in source
    assert os.fstat(opened.fd).st_size == 9


@pytest.mark.parametrize("key,value",[("first_cluster",77),("name","different"),("deleted",True),("size",4),("fs","exfat")])
def test_fresh_identity_mismatch_does_not_plan(selected,key,value):
    opened,listing,state,read,path,vol=selected
    state["entry"][key]=value
    with pytest.raises(Exception) as exc: read()
    assert exc.value.code == "secret_survey_input_changed"
    assert state["plan_calls"] == 0


def test_unknown_parent_is_unexamined_not_false(selected):
    opened,listing,state,read,path,vol=selected
    state["entry"]["parent_deleted"]=None
    with pytest.raises(R.SurveyReadError) as exc: read()
    assert exc.value.reason == "metadata_unverifiable"
    assert state["plan_calls"] == 0


@pytest.mark.parametrize("patch",[{"complete":False},{"limit_reason":"steps"},{"status":"limit"},{"bytes_beyond_image":1}])
def test_partial_plan_never_reads_bytes(selected,patch):
    opened,listing,state,read,path,vol=selected
    state["pd"].update(patch)
    with pytest.raises(R.SurveyReadError) as exc: read()
    assert exc.value.reason == "incomplete_file" and state["iter_calls"] == 0


def test_short_read_is_incomplete(selected):
    opened,listing,state,read,path,vol=selected
    state["chunks"]=[b"ab"]
    with pytest.raises(R.SurveyReadError) as exc: read()
    assert exc.value.reason == "incomplete_file"


def test_os_read_failure_closed_and_original_fd_retained(selected,monkeypatch):
    opened,listing,state,read,path,vol=selected
    def broken(*a,**kw):
        raise OSError("SYNTHETIC_PRIVATE_VALUE")
    monkeypatch.setattr(vol,"iter_plan",broken)
    with pytest.raises(R.SurveyReadError) as exc: read()
    assert exc.value.reason == "read_failed" and "PRIVATE" not in str(exc.value)
    assert os.fstat(opened.fd).st_size == 9


def test_change_on_read_dominates_availability_failure(selected,monkeypatch):
    opened,listing,state,read,path,vol=selected
    def broken(*a,**kw):
        path.chmod(0o400)
        raise OSError("SYNTHETIC_PRIVATE_VALUE")
    monkeypatch.setattr(vol,"iter_plan",broken)
    with pytest.raises(E.IntegrityProblem) as exc: read()
    assert exc.value.reason == "source-changed"


@pytest.mark.parametrize("reason,expected",[("bad_ref","secret_survey_input_changed"),("not_found","secret_survey_input_changed"),("refs_unverifiable","secret_survey_read_failed")])
def test_ref_failure_mapping(selected,monkeypatch,reason,expected):
    opened,listing,state,read,path,vol=selected
    def fail(*a,**kw):
        raise FsError("SYNTHETIC_PRIVATE_NAME",reason=reason)
    monkeypatch.setattr(R.fsops,"resolve_targets",fail)
    with pytest.raises(Exception) as exc: read()
    assert exc.value.code == expected and "PRIVATE" not in str(exc.value)
    assert state["plan_calls"] == 0


@pytest.mark.parametrize("mode",["raise","badbool","cancel"])
def test_cancel_callback_fixed_and_no_plan(selected,mode):
    opened,listing,state,read,path,vol=selected
    def cancel():
        if mode == "raise": raise RuntimeError("SYNTHETIC_PRIVATE_VALUE")
        return True if mode == "cancel" else 1
    with pytest.raises(Exception) as exc: read(cancel=cancel)
    assert exc.value.code == ("cancelled" if mode == "cancel" else "secret_survey_callback_failed")
    assert "PRIVATE" not in str(exc.value) and state["plan_calls"] == 0
