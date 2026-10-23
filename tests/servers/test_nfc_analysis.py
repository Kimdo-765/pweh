"""NFC 파일 worker의 같은 FD·현재 증명·등록·정리 경계 시험."""
from __future__ import annotations

import copy
import json
import os
import threading
import time

import pytest
from pweh import schemas
from pweh.case import Case
from pweh.errors import PwehError
from nfc_mcp import analysis as A
from .test_nfc_mcp import env, ntag, register, attest, PRIVATE


def admission(env, row, *, cancel=None):
    return A.prepare_admission(env.runtime, env.case, (row['id'],), env.tag.tag_ref,
                               deadline=time.monotonic()+5, cancel=cancel)


def analyze(env, row, receipt, *, cancel=None, seconds=5):
    return A.analyze_files(env.runtime, env.case, (row['id'],), env.tag.tag_ref,
                           receipt, max_seconds=seconds, cancel=cancel)


@pytest.fixture
def prepared(env):
    row=register(env.case)
    receipt=admission(env,row)
    attest(env.runtime,env.case,row['sha256'])
    return env,row,receipt


@pytest.mark.parametrize('mode',['symlink','hardlink','directory','parent-link','forensics','emu','oversize'])
def test_invalid_input_selection_never_registers_analysis(env,mode):
    row=register(env.case)
    path=env.case.dir/row['path']
    if mode=='symlink':
        moved=path.with_suffix('.old');path.rename(moved);path.symlink_to(moved)
    elif mode=='hardlink': os.link(path,path.with_suffix('.hard'))
    elif mode=='directory': path.unlink();path.mkdir()
    elif mode=='parent-link':
        parent=path.parent;moved=parent.with_name('moved-nfc');parent.rename(moved);parent.symlink_to(moved,target_is_directory=True)
    elif mode in ('forensics','emu'):
        row=register(env.case,subdir=mode)
    else:
        path.write_bytes(b'x'*(A.MAX_INPUT_BYTES+1))
        row=env.case.register_artifact(path,kind='other',producer='synthetic')
    with pytest.raises(PwehError) as e: admission(env,row)
    assert e.value.code in ('nfc_input_invalid','nfc_input_changed','nfc_input_limit')
    assert PRIVATE not in str(e.value)
    assert not list((env.case.dir/'analysis').glob('nfc-*.json'))


def test_existing_device_read_cannot_be_promoted_to_import(env):
    row=register(env.case)
    env.runtime.provenance.record_device_read(env.case,row['path'],{'server':'synthetic','tool':'fixture'})
    before=env.runtime.provenance.entries(env.case)
    with pytest.raises(PwehError,match='NFC') as e: admission(env,row)
    assert e.value.code=='nfc_provenance_invalid'
    assert env.runtime.provenance.entries(env.case)==before


def test_admission_receipt_has_no_path_identity_bytes_or_fd(env):
    row=register(env.case); value=admission(env,row)
    assert vars(value)=={'artifacts':((row['id'],row['sha256']),),'binding':A._binding(env.tag),'warnings':(),
                         'mode':'imported-v4','required_attestation_sha256s':(row['sha256'],)}
    assert PRIVATE not in repr(value)
    for f in os.listdir('/proc/self/fd'):
        try: target=os.readlink('/proc/self/fd/'+f)
        except OSError: continue
        assert target!=str(env.case.dir/row['path'])


@pytest.mark.parametrize('kind',['content','artifact','revoke','latest','output','parent'])
def test_final_check_rejects_changes_and_never_posts(prepared,monkeypatch,kind):
    env,row,receipt=prepared
    original=Case.register_artifact
    replacement=None
    def mutate(case,path,**kw):
        nonlocal replacement
        if kw.get('producer')=='pweh-nfc':
            if kind=='content': (env.case.dir/row['path']).write_bytes(ntag(changed=True))
            elif kind=='artifact':
                data=case.load(); data['artifacts'][0]['sha256']='ff'*32;case.meta_path.write_text(json.dumps(data))
            elif kind=='revoke':
                from pweh.provenance import provenance_import_target,PROVENANCE_IMPORT_QUESTIONS
                rec=env.runtime.attestations.require(*provenance_import_target(case.id,row['sha256']),questions=list(PROVENANCE_IMPORT_QUESTIONS))
                env.runtime.attestations.revoke(rec['id'])
            elif kind=='latest': env.runtime.provenance.record_device_read(case,row['path'],{'server':'synthetic','tool':'fixture'})
            elif kind=='output':
                p=case.dir/path; p.rename(p.with_suffix('.old'));p.write_bytes(b'replacement');replacement=p
            else:
                p=case.dir/'analysis';p.rename(case.dir/'analysis-old');p.mkdir();replacement=p
        return original(case,path,**kw)
    monkeypatch.setattr(Case,'register_artifact',mutate)
    with pytest.raises(PwehError) as e: analyze(env,row,receipt)
    assert e.value.code in ('nfc_input_changed','nfc_provenance_invalid','nfc_provenance_required','nfc_cleanup_pending','nfc_failed')
    assert not any(a.get('producer')=='pweh-nfc' for a in env.case.load()['artifacts'])
    if replacement is not None: assert replacement.exists()
    else: assert not list((env.case.dir/'analysis').glob('nfc-*.json'))


def test_new_output_fstat_failure_closes_fd_and_preserves_unknown_identity(prepared,monkeypatch):
    env,row,receipt=prepared
    real_open,real_fstat,real_close=A.os.open,A.os.fstat,A.os.close
    state={'fd':None,'fired':False,'closed':False}
    def opened(path,flags,*a,**kw):
        fd=real_open(path,flags,*a,**kw)
        if isinstance(path,str) and path.startswith('nfc-file-') and flags & os.O_EXCL: state['fd']=fd
        return fd
    def fstat(fd):
        if fd==state['fd'] and not state['fired']:
            state['fired']=True
            raise OSError(PRIVATE)
        return real_fstat(fd)
    def close(fd):
        if fd==state['fd']: state['closed']=True
        return real_close(fd)
    monkeypatch.setattr(A.os,'open',opened);monkeypatch.setattr(A.os,'fstat',fstat);monkeypatch.setattr(A.os,'close',close)
    with pytest.raises(PwehError) as e: analyze(env,row,receipt)
    assert e.value.code=='nfc_cleanup_pending'
    assert state['fired'] and state['closed']
    assert len(list((env.case.dir/'analysis').glob('nfc-file-*.json')))==1
    assert not any(a.get('producer')=='pweh-nfc' for a in env.case.load()['artifacts'])


@pytest.mark.parametrize('mode',['audit','late-cancel','output-close'])
def test_postcommit_failure_preserves_result(prepared,monkeypatch,mode):
    env,row,receipt=prepared; cancelled=threading.Event()
    if mode=='audit':
        real=Case.audit
        def audit(case,event):
            if event.get('event')=='artifact_registered' and event.get('artifact',{}).get('producer')=='pweh-nfc':
                raise RuntimeError(PRIVATE)
            return real(case,event)
        monkeypatch.setattr(Case,'audit',audit)
    elif mode=='late-cancel':
        real=Case.register_artifact
        def register(case,path,**kw):
            if kw.get('producer')=='pweh-nfc':
                cb=kw['on_commit']
                def committed(entry): cb(entry);cancelled.set()
                kw['on_commit']=committed
            return real(case,path,**kw)
        monkeypatch.setattr(Case,'register_artifact',register)
    else:
        real=A.os.close
        def close(fd):
            try: path=os.readlink('/proc/self/fd/'+str(fd))
            except OSError: path=''
            real(fd)
            if '/analysis/nfc-file-' in path: raise OSError(PRIVATE)
        monkeypatch.setattr(A.os,'close',close)
    out=analyze(env,row,receipt,cancel=cancelled.is_set)
    assert out['ok'] and (env.case.dir/out['analysis']['path']).exists()
    assert out['warnings']==({'audit':['post_commit_callback_failed'],'late-cancel':[],
                              'output-close':['output_close_unconfirmed']}[mode])
    assert PRIVATE not in json.dumps(out)


@pytest.mark.parametrize('cancel',[lambda:True,lambda:'not bool'])
def test_cancel_and_callback_errors_fixed_without_output(prepared,cancel):
    env,row,receipt=prepared
    with pytest.raises(PwehError) as e: analyze(env,row,receipt,cancel=cancel)
    assert e.value.code in ('cancelled','nfc_failed')
    assert not list((env.case.dir/'analysis').glob('nfc-*.json'))


def test_cancel_before_commit_cleans_only_new_file(prepared,monkeypatch):
    env,row,receipt=prepared; event=threading.Event()
    real=Case.register_artifact
    def cancelled(case,path,**kw):
        if kw.get('producer')=='pweh-nfc': event.set()
        return real(case,path,**kw)
    monkeypatch.setattr(Case,'register_artifact',cancelled)
    with pytest.raises(PwehError) as e: analyze(env,row,receipt,cancel=event.is_set)
    assert e.value.code=='cancelled'
    assert not list((env.case.dir/'analysis').glob('nfc-*.json'))


def test_core_time_partial_is_saved_under_separate_final_budget(prepared,monkeypatch):
    env,row,receipt=prepared
    real=A.nfc_formats.inspect_nfc
    def timed(data,**kw):
        kw['deadline']=time.monotonic()-1
        return real(data,**kw)
    monkeypatch.setattr(A.nfc_formats,'inspect_nfc',timed)
    out=analyze(env,row,receipt)
    assert out['report']['status']=='partial'
    assert out['report']['inspection']['coverage']['truncated_reasons']==['time_limit']


def test_output_cap_refuses_before_creation(prepared,monkeypatch):
    env,row,receipt=prepared;monkeypatch.setattr(A,'MAX_OUTPUT_BYTES',1)
    with pytest.raises(PwehError) as e: analyze(env,row,receipt)
    assert e.value.code=='nfc_failed'
    assert not list((env.case.dir/'analysis').glob('nfc-*.json'))


@pytest.mark.parametrize('bad',[True,0,6,float('nan'),float('inf'),10**400,'5'])
def test_worker_seconds_exact_bounds(prepared,bad):
    env,row,receipt=prepared
    with pytest.raises(PwehError) as e: analyze(env,row,receipt,seconds=bad)
    assert e.value.code=='nfc_input_invalid'


@pytest.mark.parametrize('mutation',['extra','source-extra','inspection-extra','operation','file-count','numeric','sum'])
def test_closed_schema_and_exact_semantic_relations(prepared,mutation):
    env,row,receipt=prepared; report=analyze(env,row,receipt)['report'];report=copy.deepcopy(report)
    if mutation=='extra':report[PRIVATE]=PRIVATE
    elif mutation=='source-extra':report['source']['uid']=PRIVATE
    elif mutation=='inspection-extra':report['inspection']['summary']['counter']=1
    elif mutation=='operation':report['operation']='diff'
    elif mutation=='file-count':report['source']['files']*=2
    elif mutation=='numeric':report['inspection']['coverage']['lines_examined']=6.0
    else:report['inspection']['coverage']['consumed_bytes']-=1
    with pytest.raises(PwehError):
        schemas.validate('nfc-file-analysis',report)
        A._validate_relations(report,[row['size']])
