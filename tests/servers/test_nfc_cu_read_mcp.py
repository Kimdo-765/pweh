"""실제 CU fake Client의 snapshot job·출처 분기·비공개 페이지 경계."""
from __future__ import annotations

import asyncio
import copy
import hashlib
import json
import os
import stat
import threading
import time
from dataclasses import replace
from pathlib import Path

import pytest
from mcp import Client

from mcp_helpers import call
from nfc_mcp import server as S, analysis as A, cu_owner as O, cu_read as R
from pweh import cu_protocol as P, nfc_cu_snapshot as N, nfc_inventory as I, schemas
from pweh.case import Case
from pweh.errors import PwehError
from pweh.nfc_formats import _NfcFileIdentity
from pweh.safety.attestations import canonical_json
from .fake_cu import setup as cu_setup, FakeCu, UID, frame
from .test_nfc_mcp import ntag, register

pytestmark = pytest.mark.anyio
PRIVATE = 'CU_READ_CLIENT_PRIVATE_814'


@pytest.fixture
def anyio_backend():
    return 'asyncio'


async def prepare(client, env, monkeypatch, *, family=213, flipper=False):
    env.fake = FakeCu(family=family)
    monkeypatch.setattr(S, 'get_runtime', lambda name: env.runtime)
    connected = await call(client, 'nfc_cu_connect', case_id=env.case.id, port=env.port)
    assert connected.get('ok'), connected
    owner = O.get_cu_session(env.case.id, connected['session_id'])
    if flipper:
        identity = _NfcFileIdentity(UID, b'\0D', b'\0', P.NtagFamily(family).mifare_version, 'iso14443-3a')
        scan = I.record_flipper_scan(env.runtime, env.case, I.ScanObservation(
            'synthetic-flipper', owner._binding(), identity, 'a' * 64, 123, True, True, True),
            deadline=time.monotonic() + 5).to_dict()
    else:
        scan = await call(client, 'nfc_cu_scan', case_id=env.case.id, session_id=owner.session_id)
    assert scan.get('ok'), scan
    inv = await call(client, 'nfc_tag_inventory_add', case_id=env.case.id, scan_ref=scan['scan_ref'])
    assert inv.get('ok'), inv
    return owner, inv


async def read(client, env, owner, inv):
    started = await call(client, 'nfc_cu_read_start', case_id=env.case.id,
                         session_id=owner.session_id, tag_ref=inv['tag_ref'])
    assert started.get('ok'), started
    status = await call(client, 'nfc_job_status', job_id=started['job_id'], wait_seconds=5, case_id=env.case.id)
    assert status.get('ok') and status['status'] not in ('queued', 'running', 'cancelling'), status
    return status


async def parse(client, env, inv, job):
    return await call(client, 'nfc_parse_file', case_id=env.case.id,
                      artifact_id=job['result']['artifact']['artifact_id'], tag_ref=inv['tag_ref'])


async def disconnect(client, env, owner):
    return await call(client, 'nfc_cu_disconnect', case_id=env.case.id, session_id=owner.session_id)


def no_attest(monkeypatch, env):
    def forbidden(*args, **kwargs):
        pytest.fail('CU 전용 출처에서 import 또는 사람 증명 호출')
    monkeypatch.setattr(env.runtime, 'attest', forbidden)
    monkeypatch.setattr(env.runtime.attestations, 'require', forbidden)
    monkeypatch.setattr(env.runtime.provenance, 'record_import', forbidden)
    monkeypatch.setattr(env.runtime.provenance, 'verify', forbidden)


@pytest.mark.parametrize('family', [213, 215, 216])
@pytest.mark.parametrize('cu_setup', ['posix-tty', 'win-helper'], indirect=True)
async def test_actual_read_parse_diff_same_inventory_without_import_attestation(cu_setup, monkeypatch, caplog, family):
    env = cu_setup
    async with Client(S.server) as client:
        owner, inv = await prepare(client, env, monkeypatch, family=family)
        no_attest(monkeypatch, env)
        before = await read(client, env, owner, inv)
        assert before['status'] == 'succeeded', before
        receipt = before['result']
        assert receipt['registered'] and receipt['read_complete'] and receipt['status'] == 'ok'
        row = receipt['artifact']
        path = env.case.dir / row['path']
        data = path.read_bytes()
        assert stat.S_IMODE(path.stat().st_mode) == 0o444
        assert hashlib.sha256(data).hexdigest() == row['sha256'] and len(data) == row['size']
        snapshot = json.loads(data)
        schemas.validate('nfc-cu-snapshot', snapshot)
        assert snapshot['pages'][4] == env.fake.pages[4].hex()
        assert len(snapshot['pages']) == receipt['pages_total'] == P.NtagFamily(family).pages_total
        parsed = await parse(client, env, inv, before)
        assert parsed.get('ok'), parsed
        env.fake.pages[4] = b'\x12\x34\xab\xcd'
        after = await read(client, env, owner, inv)
        diff = await call(client, 'nfc_diff_dumps', case_id=env.case.id, tag_ref=inv['tag_ref'],
                          before_artifact_id=row['artifact_id'],
                          after_artifact_id=after['result']['artifact']['artifact_id'])
        assert diff.get('ok'), diff
        assert diff['report']['inspection']['summary']['changed_pages'] == [4]
        assert diff['report']['inspection']['summary']['stored_pages_equal'] is False
        for result in (parsed, diff):
            report = result['report']
            schemas.validate('nfc-file-analysis', report)
            assert report['params']['profile'] == N.ANALYSIS_PROFILE
            assert all(f['provenance_kind'] == 'device-read' and 'attestation_id' not in f for f in report['source']['files'])
            for f in report['source']['files']:
                entry = next(e for e in env.runtime.provenance.entries(env.case) if e['seq'] == f['ledger_seq'])
                assert f['ledger_entry_sha256'] == hashlib.sha256(canonical_json(entry).encode()).hexdigest()
                assert f['ledger_entry_sha256'] != f['sha256']
        listed = await call(client, 'nfc_jobs', case_id=env.case.id)
        assert {j['job_id'] for j in listed['jobs']} >= {before['job_id'], after['job_id']}
        stopped = await disconnect(client, env, owner)
        assert stopped['ok']
        # 완료된 snapshot 분석은 살아 있는 CU 세션을 필요로 하지 않는다.
        offline = await parse(client, env, inv, before)
        assert offline.get('ok'), offline
    visible = json.dumps([before, after, parsed, diff, listed, stopped, offline]) + caplog.text
    for secret in (UID.hex(), env.fake.pages[4].hex(), 'reader_binding', 'UNTRUSTED123', PRIVATE):
        assert secret not in visible


async def test_flipper_inventory_accepts_verified_cu_snapshot_and_summary(cu_setup, monkeypatch):
    from case_mcp import server as C
    env = cu_setup
    async with Client(S.server) as client:
        owner, inv = await prepare(client, env, monkeypatch, flipper=True)
        no_attest(monkeypatch, env)
        job = await read(client, env, owner, inv)
        out = await parse(client, env, inv, job)
        assert out.get('ok'), out
        summary = {'schema': 'pweh.nfc-analysis/v1', 'mode': 'scan-bound-offline',
            'tags': [{k: inv[k] for k in ('tag_ref', 'scan_ref', 'family', 'identity_digest')}],
            'results': [{'artifact_id': out['analysis']['artifact_id'], 'path': out['analysis']['path'],
                'sha256': out['analysis']['sha256'], 'operation': 'inspect', 'status': out['report']['status'],
                'tag_ref': inv['tag_ref']}],
            'physical_same_tag_verified': False, 'tag_content_written': False,
            'authentication_attempted': False, 'emulation_performed': False}
        schemas.validate('nfc-analysis', summary)
        async with Client(C.server) as case_client:
            saved = await call(case_client, 'case_record_step', case_id=env.case.id,
                skill='nfc-behavior-analysis', step='summary', status='success', summary='합성 CU snapshot 분석',
                data=summary, artifacts=[out['analysis']['path']])
            assert saved.get('ok'), saved
            report = await call(case_client, 'report_generate', case_id=env.case.id)
            assert report.get('ok'), report
        assert (await disconnect(client, env, owner))['ok']


@pytest.mark.parametrize('tool,args', [
    ('nfc_cu_read_start', {'case_id': 'synthetic-cu', 'session_id': 's', 'tag_ref': 'NT-' + 'a' * 32}),
    ('nfc_job_status', {'job_id': 'job-abcd'}), ('nfc_job_cancel', {'job_id': 'job-abcd'}),
    ('nfc_jobs', {})])
@pytest.mark.parametrize('mutation', ['extra', 'wrong_type', 'control'])
async def test_new_tools_sdk_error_has_no_original_input(workspace, monkeypatch, caplog, tool, args, mutation):
    monkeypatch.setattr(S, 'rt', lambda: pytest.fail('잘못된 SDK 입력 뒤 runtime 접근'))
    args = dict(args)
    if mutation == 'extra': args[PRIVATE] = PRIVATE
    elif tool == 'nfc_jobs': args['active_only'] = {PRIVATE: 1} if mutation == 'wrong_type' else PRIVATE
    else:
        key = 'tag_ref' if tool == 'nfc_cu_read_start' else 'job_id'
        args[key] = True if mutation == 'wrong_type' else 'job-' + PRIVATE + '\n'
    async with Client(S.server) as client:
        result = await call(client, tool, **args)
    assert 'nfc_input_invalid' in result.get('_error', ''), result
    assert PRIVATE not in json.dumps(result) + caplog.text


@pytest.mark.parametrize('value', [True, False, '1', -1, 50.01, float('inf'), float('-inf'), float('nan'), 10**400, [], None])
async def test_job_wait_uses_original_json_and_never_clamps(workspace, monkeypatch, value):
    monkeypatch.setattr(S, 'rt', lambda: pytest.fail('잘못된 wait 뒤 runtime 접근'))
    async with Client(S.server) as client:
        result = await call(client, 'nfc_job_status', job_id='job-a', wait_seconds=value)
    assert 'nfc_input_invalid' in result.get('_error', ''), result


@pytest.mark.parametrize('tool,kwargs', [('nfc_job_status', {'job_id':'job-a'}),
    ('nfc_job_cancel', {'job_id':'job-a'}), ('nfc_jobs', {})])
async def test_job_wrappers_remove_generic_exception_and_toolerror(workspace, monkeypatch, caplog, tool, kwargs):
    def fail(*args): raise RuntimeError(PRIVATE)
    monkeypatch.setattr(S, 'get_runtime', fail)
    async with Client(S.server) as client:
        result = await call(client, tool, **kwargs)
    assert 'nfc_failed' in result.get('_error', '')
    assert PRIVATE not in json.dumps(result) + caplog.text


@pytest.mark.parametrize('policy', ['approve', 'deny'])
async def test_gate_pending_denied_release_only_reserved_use(cu_setup, monkeypatch, policy):
    from pweh.runtime import get_runtime
    env = cu_setup
    async with Client(S.server) as client:
        owner, inv = await prepare(client, env, monkeypatch)
        old_runtime = env.runtime
        env.workspace['set_safety'](modify_policy=policy)
        configured = get_runtime('cu-test')
        # 세션의 runtime 동일성은 유지하면서 합성 정책 객체만 바꾼다.
        monkeypatch.setattr(old_runtime, 'authorize', configured.authorize)
        before = list(env.fake.commands)
        result = await call(client, 'nfc_cu_read_start', case_id=env.case.id,
                            session_id=owner.session_id, tag_ref=inv['tag_ref'])
        assert result['status'] == ('approval_required' if policy == 'approve' else 'denied'), result
        assert result['gate']['classification']['risk'] == 'modify'
        assert env.fake.commands == before and not owner._uses and owner.state == 'ready'
        assert not env.runtime.jobs.list() and not env.case.load()['artifacts']
        assert (await disconnect(client, env, owner))['ok']


@pytest.mark.parametrize('reason', ['time_limit', 'nfc_scan_invalid', 'cu_protocol_invalid'])
@pytest.mark.parametrize('after_all', [False, True])
async def test_validated_prefix_completion_is_not_page_count(cu_setup, monkeypatch, reason, after_all):
    env = cu_setup
    async with Client(S.server) as client:
        owner, inv = await prepare(client, env, monkeypatch)
        original = owner._read_page
        def page(use, family, number, end, **kw):
            if not after_all and number == 4:
                raise PwehError(PRIVATE, code=reason)
            data = original(use, family, number, end, **kw)
            if after_all and number == family.pages_total - 1:
                def failed(end): raise PwehError(PRIVATE, code=reason)
                monkeypatch.setattr(use, 'check', failed)
            return data
        monkeypatch.setattr(owner, '_read_page', page)
        job = await read(client, env, owner, inv)
        if reason == 'cu_protocol_invalid':
            assert job['status'] == 'failed' and job.get('result') is None, job
            assert not env.case.load()['artifacts']
        else:
            assert job['status'] == 'succeeded', job
            result = job['result']
            assert result['status'] == 'partial' and result['read_complete'] is False
            assert result['pages_observed'] == (45 if after_all else 4)
            out = await parse(client, env, inv, job)
            assert out.get('ok') and out['report']['status'] == 'partial', out
            assert out['report']['inspection']['coverage']['reasons'] == ['read_partial']
            assert out['report']['inspection']['coverage']['pages_unobserved'] == (0 if after_all else 41)
        assert PRIVATE not in json.dumps(job)
        assert (await disconnect(client, env, owner))['ok']


@pytest.mark.parametrize('mutation', ['latest-import', 'latest-other-kind', 'source', 'extra', 'binding',
    'version', 'registration', 'same-size', 'hardlink', 'unregistered-copy', 'imported-json'])
async def test_cu_source_branch_requires_latest_exact_ledger_and_inventory(cu_setup, monkeypatch, mutation):
    env = cu_setup
    async with Client(S.server) as client:
        owner, inv = await prepare(client, env, monkeypatch)
        job = await read(client, env, owner, inv)
        assert job['status'] == 'succeeded', job
        row = job['result']['artifact']
        path = env.case.dir / row['path']
        if mutation == 'latest-import':
            env.runtime.provenance.record_import(env.case, row['path'], {'server':'synthetic', 'tool':'fixture'})
        elif mutation == 'latest-other-kind':
            env.runtime.provenance.record_patch_plan(env.case, row['path'], {'server':'synthetic', 'tool':'fixture'},
                sha256=row['sha256'])
        elif mutation in ('source', 'extra', 'binding'):
            rec = next(e for e in env.runtime.provenance.entries(env.case) if e.get('path') == row['path'])
            extra, source = copy.deepcopy(rec['extra']), dict(rec['source'])
            if mutation == 'source': source['tool'] = 'synthetic-other'
            elif mutation == 'extra': extra['pages_observed'] = True
            else: extra['binding']['inventory_seq'] += 1
            env.runtime.provenance.record_device_read(env.case, row['path'], source, extra)
        elif mutation == 'version':
            entries = A._entries
            def changed(*a, **kw):
                rows = copy.deepcopy(entries(*a, **kw))
                for item in rows:
                    if item.get('fact_kind') == I.CU_SCAN_FACT:
                        item['data']['identity']['mifare_version'] = '0004040201001103'
                return rows
            monkeypatch.setattr(A, '_entries', changed)
        elif mutation == 'registration':
            data = env.case.load()
            next(a for a in data['artifacts'] if a['id'] == row['artifact_id'])['producer'] = 'synthetic'
            env.case.meta_path.write_text(json.dumps(data))
        elif mutation == 'same-size':
            data = path.read_bytes().replace(b'024200ff', b'034200ff', 1)
            os.chmod(path, 0o600); path.write_bytes(data); os.chmod(path, 0o444)
        elif mutation == 'hardlink': os.link(path, path.with_suffix('.linked'))
        elif mutation == 'unregistered-copy':
            target = env.case.dir / 'nfc/cu-read-999.json'
            target.write_bytes(path.read_bytes()); target.chmod(0o444)
            copied = env.case.register_artifact(target, kind='other', producer='pweh-nfc', extra={'type':'nfc-cu-snapshot'})
            job['result']['artifact']['artifact_id'] = copied['id']
        else:
            copied = register(env.case, path.read_bytes(), name='imported-snapshot.json')
            job['result']['artifact']['artifact_id'] = copied['id']
        count = len(env.runtime.provenance.entries(env.case))
        out = await parse(client, env, inv, job)
        assert not out.get('ok') and '_error' in out, out
        assert len(env.runtime.provenance.entries(env.case)) == count
        assert not any(a.get('extra', {}).get('type') == 'nfc-file-analysis' for a in env.case.load()['artifacts'])
        assert (await disconnect(client, env, owner))['ok']


async def test_mixed_diff_rejected_before_any_import_append(cu_setup, monkeypatch):
    env = cu_setup
    async with Client(S.server) as client:
        owner, inv = await prepare(client, env, monkeypatch)
        job = await read(client, env, owner, inv)
        legacy = register(env.case, ntag(uid=UID))
        no_attest(monkeypatch, env)
        for ids in ((legacy['id'], job['result']['artifact']['artifact_id']),
                    (job['result']['artifact']['artifact_id'], legacy['id'])):
            result = await call(client, 'nfc_diff_dumps', case_id=env.case.id, tag_ref=inv['tag_ref'],
                                before_artifact_id=ids[0], after_artifact_id=ids[1])
            assert 'nfc_source_mismatch' in result.get('_error', ''), result
        assert (await disconnect(client, env, owner))['ok']


@pytest.mark.parametrize('mutation', ['mode', 'required', 'list', 'binding-bool'])
async def test_admission_mode_and_attestation_tuple_are_revalidated(cu_setup, monkeypatch, mutation):
    env = cu_setup
    async with Client(S.server) as client:
        owner, inv = await prepare(client, env, monkeypatch)
        job = await read(client, env, owner, inv)
        row = job['result']['artifact']
        ids = (row['artifact_id'],)
        admission = A.prepare_admission(env.runtime, env.case, ids, inv['tag_ref'], deadline=time.monotonic() + 5)
        assert admission.mode == 'cu-snapshot' and admission.required_attestation_sha256s == ()
        assert set(vars(admission)) == {'artifacts','binding','warnings','mode','required_attestation_sha256s'}
        for fd in os.listdir('/proc/self/fd'):
            try: opened = os.readlink('/proc/self/fd/' + fd)
            except OSError: continue
            assert opened != str(env.case.dir / row['path'])
        if mutation == 'mode': admission = replace(admission, mode='imported-v4', required_attestation_sha256s=(row['sha256'],))
        elif mutation == 'required': admission = replace(admission, required_attestation_sha256s=(row['sha256'],))
        elif mutation == 'list': admission = replace(admission, required_attestation_sha256s=[])
        else: admission = replace(admission, binding=tuple(True if n == 2 else v for n,v in enumerate(admission.binding)))
        with pytest.raises(PwehError) as exc:
            A.analyze_files(env.runtime, env.case, ids, inv['tag_ref'], admission)
        assert exc.value.code in ('nfc_source_mismatch','nfc_input_invalid','nfc_input_changed')
        assert (await disconnect(client, env, owner))['ok']


@pytest.mark.parametrize('mutation', ['latest', 'registration', 'binding', 'content'])
async def test_cu_analysis_commit_rechecks_same_fd_latest_origin_and_bound(cu_setup, monkeypatch, mutation):
    env = cu_setup
    async with Client(S.server) as client:
        owner, inv = await prepare(client, env, monkeypatch)
        job = await read(client, env, owner, inv)
        row = job['result']['artifact']
        original = Case.register_artifact
        def changed(case, path, **kw):
            if kw.get('extra',{}).get('type') == 'nfc-file-analysis':
                if mutation == 'latest':
                    env.runtime.provenance.record_import(case, row['path'], {'server':'synthetic','tool':'fixture'})
                elif mutation == 'registration':
                    data=case.load(); next(a for a in data['artifacts'] if a['id']==row['artifact_id'])['extra']={}
                    case.meta_path.write_text(json.dumps(data))
                elif mutation == 'binding':
                    resolve=A._binding
                    monkeypatch.setattr(A,'_binding',lambda b: (*resolve(b)[:-1], 'f'*64))
                else:
                    file=case.dir/row['path']; data=file.read_bytes(); file.chmod(0o600)
                    file.write_bytes(data.replace(b'024200ff', b'034200ff',1));file.chmod(0o444)
            return original(case,path,**kw)
        monkeypatch.setattr(Case,'register_artifact',changed)
        result=await parse(client,env,inv,job)
        assert not result.get('ok'),result
        assert not list((env.case.dir/'analysis').glob('nfc-*.json'))
        assert (await disconnect(client,env,owner))['ok']


@pytest.mark.parametrize('failure', ['artifact-failed', 'after-ledger-cancel', 'after-artifact-cancel', 'audit'])
async def test_actual_job_exposes_only_real_ledger_and_artifact_receipts(cu_setup, monkeypatch, failure):
    env=cu_setup
    async with Client(S.server) as client:
        owner,inv=await prepare(client,env,monkeypatch)
        original=Case.register_artifact
        def changed(case,path,**kw):
            if kw.get('extra',{}).get('type')=='nfc-cu-snapshot':
                if failure=='artifact-failed': raise RuntimeError(PRIVATE)
                if failure=='after-ledger-cancel':
                    for job in env.runtime.jobs.list(active_only=True): env.runtime.jobs.cancel(job['job_id'])
                elif failure=='after-artifact-cancel':
                    callback=kw['on_commit']
                    def committed(row):
                        callback(row)
                        for job in env.runtime.jobs.list(active_only=True): env.runtime.jobs.cancel(job['job_id'])
                    kw['on_commit']=committed
            return original(case,path,**kw)
        monkeypatch.setattr(Case,'register_artifact',changed)
        if failure=='audit':
            audit=Case.audit
            def fail(case,event):
                if event.get('artifact',{}).get('extra',{}).get('type')=='nfc-cu-snapshot':raise RuntimeError(PRIVATE)
                return audit(case,event)
            monkeypatch.setattr(Case,'audit',fail)
        job=await read(client,env,owner,inv)
        receipt=job['result']; registered=failure in ('after-artifact-cancel','audit')
        assert receipt['registered'] is registered and receipt['ok'] is registered
        assert job['status']==('succeeded' if registered else 'cancelled' if failure=='after-ledger-cancel' else 'failed')
        assert (env.case.dir/receipt['artifact']['path']).exists()
        assert receipt['status']=='ok' and receipt['read_complete'] is True
        assert receipt['artifact']['artifact_id'] is not None if registered else receipt['artifact']['artifact_id'] is None
        if not registered:assert 'artifact_registration_incomplete' in receipt['warnings']
        assert PRIVATE not in json.dumps(job)
        assert (await disconnect(client,env,owner))['ok']


@pytest.mark.parametrize('action',['cancel','disconnect'])
async def test_public_cancel_and_disconnect_stop_only_same_session_job(cu_setup, monkeypatch, action):
    env=cu_setup; entered=threading.Event(); release=threading.Event(); others_done=threading.Event()
    async with Client(S.server) as client:
        owner,inv=await prepare(client,env,monkeypatch)
        other=[]
        for kind,cid,sid in [('nfc-cu-read',env.case.id,'different'),('other',env.case.id,owner.session_id),
                             ('nfc-cu-read','different-case',owner.session_id)]:
            other.append(env.runtime.jobs.start(kind,lambda j: others_done.wait(4),description='합성 독립 작업',case_id=cid,meta={'session_id':sid}))
        def blocked(size): entered.set();assert release.wait(3)
        env.fake.before_read=blocked
        started=await call(client,'nfc_cu_read_start',case_id=env.case.id,session_id=owner.session_id,tag_ref=inv['tag_ref'])
        for _ in range(300):
            if entered.is_set():break
            await asyncio.sleep(.005)
        assert entered.is_set()
        try:
            if action=='disconnect':
                task=asyncio.create_task(disconnect(client,env,owner))
                for _ in range(300):
                    if env.runtime.jobs.get(started['job_id'])._cancel.is_set():break
                    await asyncio.sleep(.005)
            else:
                out=await call(client,'nfc_job_cancel',job_id=started['job_id'])
                assert out.get('ok'),out
            assert env.runtime.jobs.get(started['job_id'])._cancel.is_set()
            assert all(not j._cancel.is_set() for j in other)
        finally:
            env.fake.before_read=None;release.set();others_done.set()
        if action=='disconnect': assert (await task)['ok']
        status=await call(client,'nfc_job_status',job_id=started['job_id'],wait_seconds=5)
        assert status['status']=='cancelled' and status.get('result') is None,status
        assert not env.case.load()['artifacts']
        if action=='cancel':assert (await disconnect(client,env,owner))['ok']
        for j in other:j._thread.join(1)


async def test_read_then_unknown_close_keeps_lease_for_explicit_retry(cu_setup, monkeypatch, isolated_ports):
    env=cu_setup
    async with Client(S.server) as client:
        owner,inv=await prepare(client,env,monkeypatch)
        job=await read(client,env,owner,inv)
        assert job['status']=='succeeded'
        env.fake.close_verified=False
        def revoked(*a,**kw):raise PwehError(PRIVATE,code='authorization_required')
        monkeypatch.setattr(env.runtime,'case',revoked)
        out=await disconnect(client,env,owner)
        assert not out['ok'] and isolated_ports['manager']._leases
        assert O.get_cu_session(env.case.id,owner.session_id) is owner
        env.fake.close_verified=True
        assert (await disconnect(client,env,owner))['ok']
    assert not isolated_ports['manager']._leases


def schema_fixture(operation='inspect'):
    """scanner를 호출하지 않는 새 profile의 독립 저장 봉투."""
    read={'pages_observed':45,'read_complete':True,'stop_reason':None}
    summary={'family':'ntag213','pages_total':45}
    if operation=='inspect':
        summary.update(**read,unobserved_fields=['signature','counters','tearing'])
        coverage={'input_bytes':4096,'consumed_bytes':4096,'unexamined_bytes':0,
                  'input_exhausted':True,'pages_unobserved':0,'reasons':[]}
    else:
        summary.update(before=dict(read),after=dict(read),pages_compared=45,before_only_pages=0,
            after_only_pages=0,neither_observed_pages=0,comparison_unexamined_pages=0,
            changed_pages=[],stored_pages_equal=True)
        coverage={'input_bytes':8192,'consumed_bytes':8192,'unexamined_bytes':0,
                  'comparison_complete':True,'changes_complete':True,'changed_pages_count_is_lower_bound':False,'reasons':[]}
    files=[{'artifact_id':'A-0001','size':4096,'sha256':'a'*64,'provenance_kind':'device-read',
            'ledger_seq':3,'ledger_entry_sha256':'b'*64}]
    if operation=='diff':files.append({**files[0],'artifact_id':'A-0002','ledger_seq':4})
    return {'schema':'pweh.nfc-file-analysis/v1','operation':operation,'status':'ok',
        'source':{'kind':'case-artifact','tag_ref':'NT-'+'a'*32,'scan_ref':'NS-'+'b'*32,
            'scan_entry_sha256':'c'*64,'inventory_entry_sha256':'d'*64,'files':files},
        'params':{'profile':'cu-ntag21x-snapshot-analysis-v1','max_seconds':5},
        'inspection':{'schema_version':1,'operation':operation,'status':'ok',
            'profile':'cu-ntag21x-snapshot-analysis-v1','summary':summary,'coverage':coverage,
            'limitations':['stored_page_responses_only','validated_prefix_pages_only',
                'signature_counters_tearing_unobserved','password_pack_readback_not_observable',
                'snapshot_not_atomic','physical_same_tag_not_verified','console_causality_not_verified',
                'no_tag_authorization_inferred']},
        'inventory_binding_verified':True,'physical_same_tag_verified':False}


@pytest.mark.parametrize('operation',['inspect','diff'])
@pytest.mark.parametrize('mutation',[None,'old-profile','old-row','old-inspection','attestation','unknown-key',
    'zero-size','big-size','hash-newline','status','read-stop','family-total','negative-page','fraction-page'])
def test_independent_schema_separates_old_and_cu_closed_profiles(operation,mutation):
    report=schema_fixture(operation)
    schemas.validate('nfc-file-analysis',report)
    row=report['source']['files'][0]; inspection=report['inspection'];summary=inspection['summary']
    if mutation is None:return
    if mutation=='old-profile':report['params']['profile']=A.PROFILE
    elif mutation=='old-row':row.pop('ledger_entry_sha256');row.update(provenance_kind='imported-unattested',attestation_id='att-'+'a'*10)
    elif mutation=='old-inspection':inspection['profile']='ntag213'
    elif mutation=='attestation':row['attestation_id']='att-'+'a'*10
    elif mutation=='unknown-key':inspection['reader_binding']={}
    elif mutation=='zero-size':row['size']=0
    elif mutation=='big-size':row['size']=65537
    elif mutation=='hash-newline':row['ledger_entry_sha256']+='\n'
    elif mutation=='status':report['status']='partial'
    elif mutation=='read-stop':(summary if operation=='inspect' else summary['before'])['stop_reason']='time_limit'
    elif mutation=='family-total':summary['pages_total']=135
    elif mutation=='negative-page':
        if operation=='inspect':summary['pages_observed']=-1
        else:summary['changed_pages']=[-1]
    else:
        if operation=='inspect':summary['pages_observed']=2.5
        else:summary['changed_pages']=[2.5]
    with pytest.raises(Exception):schemas.validate('nfc-file-analysis',report)


@pytest.mark.parametrize('operation',['inspect','diff'])
@pytest.mark.parametrize('mutation',['float','schema-bool','input-size','consumed','observed','complete','reasons','equal'])
def test_cu_accounting_rejects_false_equations_after_schema(operation,mutation):
    from types import SimpleNamespace
    report=schema_fixture(operation);inspection=report['inspection'];summary=inspection['summary'];cov=inspection['coverage']
    snapshots=[SimpleNamespace(input_size=4096,family='ntag213',pages_total=45,pages_observed=45,read_complete=True,stop_reason=None)]
    if operation=='diff':snapshots*=2
    A._validate_cu_relations(report,snapshots)
    if mutation=='float':cov['input_bytes']=float(cov['input_bytes'])
    elif mutation=='schema-bool':inspection['schema_version']=True
    elif mutation=='input-size':cov['input_bytes']+=1
    elif mutation=='consumed':cov['consumed_bytes']-=1
    elif mutation=='observed':
        if operation=='inspect':summary['pages_observed']=44
        else:summary['pages_compared']=44
    elif mutation=='complete':
        if operation=='inspect':summary['read_complete']=False
        else:cov['comparison_complete']=False
    elif mutation=='reasons':cov['reasons']=['read_partial']
    else:
        if operation=='inspect':cov['pages_unobserved']=1
        else:summary['stored_pages_equal']=None
    with pytest.raises(PwehError) as exc:A._validate_cu_relations(report,snapshots)
    assert exc.value.code=='nfc_failed'


async def test_partial_read_diff_does_not_claim_equal_complete_pages(cu_setup, monkeypatch):
    env=cu_setup
    async with Client(S.server) as client:
        owner,inv=await prepare(client,env,monkeypatch)
        first=await read(client,env,owner,inv)
        original=owner._read_page
        def stopped(use,family,page,end,**kw):
            if page==4:raise PwehError(PRIVATE,code='nfc_scan_invalid')
            return original(use,family,page,end,**kw)
        monkeypatch.setattr(owner,'_read_page',stopped)
        second=await read(client,env,owner,inv)
        result=await call(client,'nfc_diff_dumps',case_id=env.case.id,tag_ref=inv['tag_ref'],
            before_artifact_id=first['result']['artifact']['artifact_id'],
            after_artifact_id=second['result']['artifact']['artifact_id'])
        assert result.get('ok') and result['report']['status']=='partial',result
        inspection=result['report']['inspection'];summary=inspection['summary'];coverage=inspection['coverage']
        assert summary['pages_compared']==4 and summary['before_only_pages']==41
        assert summary['changed_pages']==[] and summary['stored_pages_equal'] is None
        assert coverage['comparison_complete'] is True and coverage['reasons']==['read_partial']
        assert (await disconnect(client,env,owner))['ok']


async def test_raw_cancellation_during_gate_releases_unclaimed_use(cu_setup, monkeypatch):
    env=cu_setup;entered=asyncio.Event()
    async with Client(S.server) as client:
        owner,inv=await prepare(client,env,monkeypatch)
        before=list(env.fake.commands)
        async def blocked(**kwargs):
            assert kwargs['action']['operation']=='ntag_read'
            assert kwargs['action']['session_id']==owner.session_id
            assert kwargs['action']['tag_ref']==inv['tag_ref']
            assert 'identity_digest' not in kwargs['action'] and 'reader_binding' not in kwargs['action']
            entered.set()
            await asyncio.Event().wait()
        monkeypatch.setattr(env.runtime,'authorize',blocked)
        task=asyncio.create_task(S.nfc_cu_read_start(env.case.id,owner.session_id,inv['tag_ref']))
        await asyncio.wait_for(entered.wait(),3)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):await task
        assert not owner._uses and owner.state=='ready'
        assert env.fake.commands==before and not env.runtime.jobs.list()
        assert (await disconnect(client,env,owner))['ok']
