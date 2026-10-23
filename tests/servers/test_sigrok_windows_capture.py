"""Windows 유한 OLS 캡처의 공개 소비자·동일 fd 게시·job 수명 합성 시험."""
from __future__ import annotations
import asyncio
from dataclasses import replace
import hashlib
import io
import json
import os
import threading
import time
import zipfile
from pathlib import Path
from types import SimpleNamespace

import pytest
from mcp import Client
from mcp_helpers import call
from pweh.errors import PwehError
from sigrok_mcp import server as S, windows_capture_tools as W
from sigrok_mcp.windows_capture import CaptureExit, CaptureOutput, CapturePublication
from .test_sigrok_windows_com import env as com_env, PRIVATE
from .test_sigrok_mcp import fake, _wait_job

pytestmark=pytest.mark.anyio
@pytest.fixture
def anyio_backend(): return 'asyncio'


def srzip(command,samples=None,*,metadata_change=''):
    count=command.samples if samples is None else samples
    metadata='[global]\nsigrok version=0.5.2\n[device 1]\ncapturefile=logic-1\ntotal probes=32\nunitsize=4\ntotal analog=0\n'
    metadata+=f'samplerate={command.expected_reported_rate_hz} Hz\n'
    metadata+=''.join(f'probe{ch.index+1}={ch.name}\n' for ch in command.channels)+metadata_change
    buf=io.BytesIO()
    with zipfile.ZipFile(buf,'w',compression=zipfile.ZIP_DEFLATED) as z:
        z.writestr('version','2')
        z.writestr('metadata',metadata)
        z.writestr('logic-1-1',b''.join((i%4).to_bytes(4,'little') for i in range(count)))
    return buf.getvalue()


class Owner:
    def __init__(self,command,env):
        self.command,self.env=command,env
        self.confirmed=True
        self.processes_quiescent=False
        self.publication=None
        self.prepared=self.executed=self.closed=False
        self.release,self.entered,self.done=threading.Event(),threading.Event(),threading.Event()
        self.block=None
        self.failure=None
        self.samples=None
        self.data=None
        self.finalize_hook=None
        self.exit=CaptureExit(0,False,False,False,.01,time.monotonic()+60,'')
        self.fd=None
    def pause(self,stage):
        if self.block==stage:
            self.entered.set()
            assert self.release.wait(5),'합성 worker 해제 누락'
    def prepare(self,parent,*,ambient_env,deadline,cancel):
        assert self.env.manager._leases and isinstance(ambient_env,tuple)
        self.prepared=True
        self.pause('prepare')
        if self.env.prepare_hook: self.env.prepare_hook(self)
    def run(self,*,before_spawn,deadline,cancel,timeout_s):
        self.env.timeouts.append(timeout_s)
        self.pause('run')
        if self.failure: raise self.failure
        before_spawn()
        self.executed=True
        self.processes_quiescent=True
        if cancel(): self.exit=replace(self.exit,cancelled=True,returncode=-15)
        return self.exit
    def finalize_output(self,publisher,*,deadline,cancel):
        self.pause('finalize')
        if self.finalize_hook: self.finalize_hook()
        data=srzip(self.command,self.samples) if self.data is None else self.data
        if not data:
            self.publication=CapturePublication('no_output',reason='empty')
            return self.publication
        p=self.env.tmp/f'capture-{len(self.env.owners)}.sr'
        p.write_bytes(data)
        self.fd=os.open(p,os.O_RDONLY)
        def seal(st):
            # 읽기만으로 바뀌는 atime은 제외하고 내용/신원 변경은 ns 단위로 검사한다.
            return (st.st_dev,st.st_ino,st.st_mode,st.st_uid,st.st_nlink,
                    st.st_size,st.st_mtime_ns,st.st_ctime_ns)
        initial=seal(os.fstat(self.fd))
        def check():
            assert seal(os.fstat(self.fd))==initial
        def committed(receipt): self.publication=receipt
        source=CaptureOutput(self.fd,len(data),check,committed)
        result=publisher(source,exit=self.exit,deadline=deadline,cancel=cancel)
        if self.publication is None: self.publication=result
        assert self.publication==result
        return result
    def close(self,*,deadline):
        self.pause('close')
        self.closed=True
        if self.fd is not None:
            os.close(self.fd); self.fd=None
        self.done.set()
        return SimpleNamespace(confirmed=self.confirmed)

@pytest.fixture
def env(com_env,tmp_path,monkeypatch):
    state=com_env
    state.tmp=tmp_path
    def reserve(bundle,command,**kwargs):
        assert bundle is state.bundle and state.manager._leases
        owner=Owner(command,state)
        state.owners.append(owner)
        if state.owner_hook: state.owner_hook(owner)
        return owner
    monkeypatch.setattr(W,'_reserve',reserve)
    return state

async def invoke(client,env,**kwargs):
    args=dict(case_id=env.case.id,driver='ols',conn='COM7',backend='windows',samples=8,
              samplerate='1m',channels=['0','1'],background=False)
    args.update(kwargs)
    return await call(client,'sigrok_capture',**args)

async def test_sync_success_full_contract_and_same_bytes(env):
    async with Client(S.server) as c:
        out=await invoke(c,env)
        info=await call(c,'sigrok_file_info',case_id=env.case.id,input_path=out['path']) if 'path' in out else None
    assert out['ok'] and out['status']=='succeeded',out
    assert out['backend']=='windows' and out['classification']['risk']=='modify'
    assert out['samples']==8 and out['samplerate']==1_000_000 and out['channels']==['0','1']
    assert len(out['activity'])==2 and out['inspection']['crc_verified'] and out['next_steps']
    assert out['activity_complete'] and out['activity_samples']==8 and out['reason'] is None
    assert out['activity'][0]['high_ratio']==.5
    p=env.case.dir/out['path']
    assert p.stat().st_mode&0o777==0o444
    assert hashlib.sha256(p.read_bytes()).hexdigest()==out['sha256']==out['artifact']['sha256']
    assert info['total_samples']==8 and not out['cleanup_pending'] and not env.manager._leases
    assert env.timeouts==[60] and env.owners[0].publication.reason is None
    assert 'PRIVATE_SENTINEL' not in json.dumps(out)

@pytest.mark.parametrize('updates',[
    dict(driver='demo'),dict(conn='COM07'),dict(conn=None),dict(duration_ms=1),dict(triggers='0=r'),
    dict(capture_ratio=0),dict(samples=0),dict(samples=6),dict(samples=8388612),dict(samples=True),
    dict(samplerate=9),dict(samplerate=100000001),dict(channels=None),dict(channels=['1']),
    dict(channels=['0','2']),dict(timeout_s=0),dict(timeout_s=301),
    dict(backend='auto'),dict(output_name='../private'),
])
async def test_invalid_input_no_owner(env,updates):
    async with Client(S.server) as c: out=await invoke(c,env,**updates)
    assert '_error' in out and not env.owners and not env.manager._leases,out

async def test_approval_and_stable_binding(env):
    env.workspace['set_safety'](modify_policy='approve')
    async with Client(S.server) as c:
        pending=await invoke(c,env)
        assert pending['status']=='approval_required' and not env.owners
        aid=pending['approval_id']; record=S.rt().approvals.get(aid)
        assert record['risk']=='modify'
        S.rt().approvals.decide(aid,approve=True,code=record['code'],via='cli-tty')
        changed=await invoke(c,env,samples=12,approval_id=aid)
        assert not changed['ok'] and not env.owners
        out=await invoke(c,env,approval_id=aid)
        assert out['ok'],out
    assert not env.manager._leases

async def test_change_after_gate_rejected_before_spawn(env):
    env.prepare_hook=lambda owner:setattr(env,'serial','synthetic-replaced')
    async with Client(S.server) as c: out=await invoke(c,env)
    assert '_error' in out and not env.owners[0].executed and not env.case.artifacts()

@pytest.mark.parametrize('field,value,code',[
    ('returncode',7,'failed'),('stderr','Permission denied '+PRIVATE,'failed'),
    ('output_limit',True,'output_limit')])
async def test_failure_never_salvaged_as_success(env,field,value,code):
    env.owner_hook=lambda o:setattr(o,'exit',replace(o.exit,**{field:value}))
    async with Client(S.server) as c: out=await invoke(c,env)
    assert '[sigrok_capture_'+code+']' in out['_error'] and PRIVATE not in out['_error'],out
    assert not env.case.artifacts() and not env.manager._leases

@pytest.mark.parametrize('data,code',[(b'bad zip','bad_zip'),(b'','no_output')])
async def test_invalid_or_absent_output(env,data,code):
    env.owner_hook=lambda o:setattr(o,'data',data)
    async with Client(S.server) as c: out=await invoke(c,env)
    assert '[sigrok_capture_'+code+']' in out['_error'] and not env.case.artifacts(),out

async def test_zero_sample_verified_output_is_explicit_invalid(env):
    env.owner_hook=lambda o:setattr(o,'samples',0)
    async with Client(S.server) as c: out=await invoke(c,env)
    assert '[sigrok_capture_empty_capture]' in out['_error'],out
    assert env.owners[0].publication.reason=='empty_capture' and not env.case.artifacts()

@pytest.mark.parametrize('cause',['shortfall','timeout','cancelled'])
async def test_partial_output_contract(env,cause):
    def setup(o):
        o.samples=4
        if cause!='shortfall': o.exit=replace(o.exit,**{cause if cause=='cancelled' else 'timed_out':True,'returncode':-15})
    env.owner_hook=setup
    async with Client(S.server) as c: out=await invoke(c,env)
    assert out['partial'] and out['samples']==4 and out['path'].endswith('-partial.sr'),out
    assert out['status']==('partial' if cause=='shortfall' else cause)
    assert out['reason']==('sample_shortfall' if cause=='shortfall' else cause)
    assert out['ok'] is (cause=='shortfall') and not out['cleanup_pending']
    assert env.owners[0].publication.partial and len(env.case.artifacts())==1

async def test_quantized_rate_warning_is_not_sample_partial(env):
    async with Client(S.server) as c: out=await invoke(c,env,samplerate=3_000_000)
    assert out['ok'] and not out['partial'] and out['samplerate']==3_030_303,out
    assert 'rate_quantized' in out['warnings']

async def test_no_overwrite_existing_output(env):
    p=env.case.dir/'signals/chosen.sr';p.write_bytes(b'PWEH SYNTHETIC prior')
    async with Client(S.server) as c: out=await invoke(c,env,output_name='chosen')
    assert '[sigrok_capture_artifact_exists]' in out['_error'] and p.read_bytes()==b'PWEH SYNTHETIC prior'
    assert not env.case.artifacts()

async def test_audit_failure_after_commit_preserves_receipt_and_file(env,monkeypatch):
    from pweh.case import Case
    original=Case.audit
    def audit(self,event):
        if event.get('event')=='artifact_registered': raise OSError(PRIVATE)
        return original(self,event)
    monkeypatch.setattr(Case,'audit',audit)
    async with Client(S.server) as c: out=await invoke(c,env)
    assert not out['ok'] and out['status']=='failed' and out['artifact']['id'],out
    assert len(env.case.artifacts())==1 and (env.case.dir/out['path']).is_file()
    assert env.owners[0].publication.artifact_id==out['artifact']['id']
    assert PRIVATE not in json.dumps(out)

async def test_unknown_cleanup_preserves_committed_result_and_lease(env):
    env.owner_hook=lambda o:setattr(o,'confirmed',False)
    async with Client(S.server) as c: out=await invoke(c,env)
    assert out['cleanup_pending'] and out['error']['code']=='sigrok_capture_cleanup_unknown',out
    assert env.manager._leases and len(env.case.artifacts())==1

@pytest.mark.parametrize('stage',['prepare','run','finalize','close'])
async def test_raw_cancel_worker_retains_cleanup_ownership(env,stage):
    env.owner_hook=lambda o:setattr(o,'block',stage)
    task=asyncio.create_task(S.sigrok_capture.__wrapped__(case_id=env.case.id,driver='ols',conn='COM7',
        backend='windows',samples=8,samplerate='1m',channels=['0','1'],background=False))
    end=time.monotonic()+2
    while not env.owners and time.monotonic()<end: await asyncio.sleep(.005)
    owner=env.owners[0]
    assert await asyncio.to_thread(owner.entered.wait,2)
    task.cancel()
    with pytest.raises(asyncio.CancelledError): await task
    assert env.manager._leases and not owner.closed
    owner.release.set()
    assert await asyncio.to_thread(owner.done.wait,2)
    end=time.monotonic()+2
    while env.manager._leases and time.monotonic()<end: await asyncio.sleep(.005)
    assert not env.manager._leases

@pytest.mark.parametrize('shortfall',[False,True])
async def test_job_uses_same_worker_and_normal_commit(env,shortfall):
    if shortfall: env.owner_hook=lambda o:setattr(o,'samples',4)
    async with Client(S.server) as c:
        started=await invoke(c,env,background=True)
        assert started['status']=='started',started
        out=await _wait_job(c,started['job_id'])
    assert out['status']=='succeeded' and out['result']['partial'] is shortfall,out
    assert S.rt().jobs.get(started['job_id'])._committed
    assert len(env.case.artifacts())==1 and not env.manager._leases

async def test_job_normal_read_can_update_source_atime(env,monkeypatch):
    original=Path.write_bytes
    def write_with_old_atime(path,data):
        count=original(path,data)
        if path.parent==env.tmp and path.name=='capture-1.sr':
            # seal 전에 과거 atime을 두어 첫 실제 pread가 반드시 갱신하게 한다.
            os.utime(path,ns=(0,path.stat().st_mtime_ns))
        return count
    monkeypatch.setattr(Path,'write_bytes',write_with_old_atime)
    async with Client(S.server) as c:
        started=await invoke(c,env,background=True)
        out=await _wait_job(c,started['job_id'])
    if (env.tmp/'capture-1.sr').stat().st_atime_ns==0:
        pytest.skip('이 파일 시스템은 읽기 atime을 갱신하지 않음(noatime 등)')
    assert out['status']=='succeeded' and out['result']['partial'] is False,out
    assert S.rt().jobs.get(started['job_id'])._committed
    assert len(env.case.artifacts())==1 and not env.manager._leases

@pytest.mark.parametrize('change',['content','mtime'])
async def test_job_source_mutation_during_read_is_rejected(env,monkeypatch,change):
    original=os.pread
    changed=False
    def read_then_change(fd,count,offset):
        nonlocal changed
        data=original(fd,count,offset)
        if not changed and env.owners and fd==env.owners[0].fd:
            changed=True
            path=env.tmp/'capture-1.sr'
            if change=='mtime':
                st=path.stat()
                os.utime(path,ns=(st.st_atime_ns,st.st_mtime_ns+1))
            else:
                with path.open('r+b') as target:
                    target.write(b'X')
        return data
    monkeypatch.setattr(os,'pread',read_then_change)
    async with Client(S.server) as c:
        started=await invoke(c,env,background=True)
        out=await _wait_job(c,started['job_id'])
    assert changed and out['status']=='failed',out
    assert out['error']['code']=='sigrok_capture_check_failed'
    assert not env.case.artifacts() and not env.manager._leases

async def test_job_timeout_persists_partial_without_commit_mark(env):
    env.owner_hook=lambda o:setattr(o,'exit',replace(o.exit,timed_out=True,returncode=-15))
    async with Client(S.server) as c:
        started=await invoke(c,env,background=True)
        out=await _wait_job(c,started['job_id'])
    job=S.rt().jobs.get(started['job_id'])
    assert out['status']=='failed' and job.meta['partial_result']['path'],out
    assert not job._committed and len(env.case.artifacts())==1

async def test_job_cancel_partial_never_marked_committed(env):
    env.owner_hook=lambda o:setattr(o,'block','run')
    async with Client(S.server) as c:
        started=await invoke(c,env,background=True)
        end=time.monotonic()+2
        while not env.owners and time.monotonic()<end: await asyncio.sleep(.005)
        owner=env.owners[0]
        assert await asyncio.to_thread(owner.entered.wait,2)
        await call(c,'sigrok_job_cancel',job_id=started['job_id'])
        owner.release.set()
        out=await _wait_job(c,started['job_id'])
    job=S.rt().jobs.get(started['job_id'])
    assert out['status']=='cancelled' and not job._committed,out
    assert job.meta['partial_result']['artifact']['id'] and len(env.case.artifacts())==1

async def test_linux_ols_capture_modify_gate_and_approval(fake,auth,monkeypatch):
    from .test_external_port_lifecycle import fake_probe
    cid=S.rt().cases.create(title='합성 Linux OLS capture',authorization=auth).id
    fake.workspace['set_safety'](modify_policy='approve')
    monkeypatch.setattr(S,'_port_probe',lambda:fake_probe())
    monkeypatch.setattr(S,'device_users',lambda path:[])
    async with Client(S.server) as c:
        args=dict(case_id=cid,driver='ols',conn='/dev/ttySYNTHETIC',samples=64)
        pending=await call(c,'sigrok_capture',**args)
        assert pending['status']=='approval_required' and not fake.calls(),pending
        aid=pending['approval_id'];rec=S.rt().approvals.get(aid)
        assert rec['risk']=='modify'
        S.rt().approvals.decide(aid,approve=True,code=rec['code'],via='cli-tty')
        out=await call(c,'sigrok_capture',approval_id=aid,**args)
        assert out['ok'] and len(fake.calls())==1,out

@pytest.mark.parametrize('value',[float('inf'),float('nan'),10**400,True])
async def test_internal_timeout_nonfinite_strict(value):
    with pytest.raises(PwehError,match='sigrok_capture_invalid'): W._seconds(value)

@pytest.mark.parametrize('field,value',[('size',1),('is_dir',True),('sha256','b'*64),('path','signals/other.sr')])
async def test_final_entry_observation_must_equal_verified_fd(env,monkeypatch,field,value):
    from pweh.case import Case
    original=Case.register_artifact
    def register(self,*args,**kwargs):
        check=kwargs['check']
        def altered(entry): check(dict(entry,**{field:value}))
        return original(self,*args,**dict(kwargs,check=altered))
    monkeypatch.setattr(Case,'register_artifact',register)
    async with Client(S.server) as c: out=await invoke(c,env)
    assert '[sigrok_capture_check_failed]' in out['_error'],out
    assert not env.case.artifacts() and env.owners[0].publication is None

async def test_destination_name_swap_never_registers_replacement(env,monkeypatch):
    from pweh import safeio
    real=safeio.hash_fd
    def swap(*args,**kw):
        result=real(*args,**kw)
        path=env.case.dir/'signals/capture-ols.sr'
        path.rename(path.with_name('original.sr'))
        path.write_bytes(b'PWEH SYNTHETIC replacement')
        return result
    monkeypatch.setattr(safeio,'hash_fd',swap)
    async with Client(S.server) as c: out=await invoke(c,env)
    assert '[sigrok_capture_check_failed]' in out['_error'] and not env.case.artifacts(),out
    assert (env.case.dir/'signals/capture-ols.sr').read_bytes()==b'PWEH SYNTHETIC replacement'

async def test_job_start_failure_releases_unclaimed_lease(env,monkeypatch):
    def fail(*args,**kw): raise PwehError('합성 thread 시작 실패')
    monkeypatch.setattr(S.rt().jobs,'start',fail)
    async with Client(S.server) as c: out=await invoke(c,env,background=True)
    assert '_error' in out and not env.owners and not env.manager._leases

# 실제 owner/copy/Windows probe 대신 합성 lifecycle와 Linux 자식을 연결한다.
from .test_sigrok_windows_runner import setup as info_setup
from .test_sigrok_windows_capture_owner import setup as owner_setup

@pytest.mark.parametrize('mode',['success','timeout','cancelled','shortfall'])
async def test_public_real_owner_valid_zip_publication(env,owner_setup,monkeypatch,mode):
    from pweh.sigrok_capture import CaptureCommand, CaptureChannel, PROFILE_ID
    setup=owner_setup
    command=CaptureCommand(PROFILE_ID,'COM7',1_000_000,8,(CaptureChannel(0,'0'),CaptureChannel(1,'1')))
    data=srzip(command,4 if mode=='shortfall' else 8)
    code='from pathlib import Path;import time;Path(OUTPUT_PATH).write_bytes('+repr(data)+')'
    if mode in ('timeout','cancelled'): code+=';time.sleep(20)'
    monkeypatch.setattr(W.info,'_resolve_bundle',lambda *a,**kw:setup.bundle)
    monkeypatch.setattr(W.info,'_runtime_parent',lambda *a:setup.parent)
    def reserve(bundle,actual,**kwargs):
        assert actual==command and bundle is setup.bundle
        return setup.reserve(code=code,command=actual,**kwargs)
    monkeypatch.setattr(W,'_reserve',reserve)
    async with Client(S.server) as c:
        if mode=='cancelled':
            started=await invoke(c,env,background=True)
            end=time.monotonic()+3
            while time.monotonic()<end:
                if setup.owners and setup.owners[0]._output is not None and setup.owners[0]._output.path.exists(): break
                await asyncio.sleep(.005)
            assert setup.owners[0]._output.path.exists()
            await call(c,'sigrok_job_cancel',job_id=started['job_id'])
            job=await _wait_job(c,started['job_id'])
            assert job['status']=='cancelled',job
            out=S.rt().jobs.get(started['job_id']).meta['partial_result']
            assert not S.rt().jobs.get(started['job_id'])._committed
        else:
            out=await invoke(c,env,timeout_s=.3 if mode=='timeout' else 10)
    assert 'artifact' in out,out
    assert out['samples']==(4 if mode=='shortfall' else 8) and out['inspection']['crc_verified']
    assert out['status']==dict(success='succeeded',timeout='timeout',cancelled='cancelled',shortfall='partial')[mode],out
    assert out['cleanup_pending'] is False and not env.manager._leases
    assert len(setup.spawns)==1 and not list(setup.parent.iterdir())
    assert len(env.case.artifacts())==1 and PRIVATE not in json.dumps(out)

async def test_job_late_cancel_after_commit_does_not_downgrade(env):
    env.owner_hook=lambda o:setattr(o,'block','close')
    async with Client(S.server) as c:
        started=await invoke(c,env,background=True)
        end=time.monotonic()+2
        while not env.owners and time.monotonic()<end: await asyncio.sleep(.005)
        owner=env.owners[0]
        assert await asyncio.to_thread(owner.entered.wait,2)
        assert S.rt().jobs.get(started['job_id'])._committed
        await call(c,'sigrok_job_cancel',job_id=started['job_id'])
        owner.release.set()
        out=await _wait_job(c,started['job_id'])
    assert out['status']=='succeeded' and len(env.case.artifacts())==1,out

async def test_cancel_after_run_before_publication_is_partial_not_normal_commit(env):
    env.owner_hook=lambda o:setattr(o,'block','finalize')
    async with Client(S.server) as c:
        started=await invoke(c,env,background=True)
        end=time.monotonic()+2
        while not env.owners and time.monotonic()<end: await asyncio.sleep(.005)
        owner=env.owners[0]
        assert await asyncio.to_thread(owner.entered.wait,2)
        assert not owner.exit.cancelled
        await call(c,'sigrok_job_cancel',job_id=started['job_id'])
        owner.release.set()
        out=await _wait_job(c,started['job_id'])
    job=S.rt().jobs.get(started['job_id'])
    assert out['status']=='cancelled' and not job._committed
    assert job.meta['partial_result']['reason']=='cancelled' and len(env.case.artifacts())==1

async def test_new_cancel_at_final_entry_check_preserves_unpublished_output(env,monkeypatch):
    from pweh.case import Case
    original=Case.register_artifact
    env.owner_hook=lambda o:setattr(o,'confirmed',False)
    def register(self,*a,**kw):
        running=S.rt().jobs.list(active_only=True)
        assert len(running)==1
        S.rt().jobs.cancel(running[0]['job_id'])
        return original(self,*a,**kw)
    monkeypatch.setattr(Case,'register_artifact',register)
    async with Client(S.server) as c:
        started=await invoke(c,env,background=True)
        out=await _wait_job(c,started['job_id'])
    assert out['status']=='failed' and not S.rt().jobs.get(started['job_id'])._committed
    assert not env.case.artifacts() and env.owners[0].publication is None and env.manager._leases
    assert len(list((env.case.dir/'signals').glob('*.sr')))==1
