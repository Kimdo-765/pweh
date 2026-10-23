"""합성 Flipper·NFC 실제 Client의 scan/증명/파일 결속 경계."""
from __future__ import annotations

import hashlib
import json
import os
import stat
import time
from types import SimpleNamespace

import pytest
from mcp import Client
from mcp_helpers import call
from pweh import nfc_formats as N, nfc_inventory as I, schemas
from pweh.provenance import PROVENANCE_IMPORT_QUESTIONS, provenance_import_target
from nfc_mcp import server as S, analysis as A
from flipper_mcp import server as F
from case_mcp import server as C
from .fake_flipper_nfc import setup, UID, probe_bytes, raw_body

pytestmark = pytest.mark.anyio
PRIVATE = 'NFC_PRIVATE_SENTINEL_639'


@pytest.fixture
def anyio_backend():
    return 'asyncio'


def ntag(model=213, *, uid=UID, read=None, changed=False):
    total = {213:45, 215:135, 216:231}[model]
    version = '00 04 04 02 01 00 ' + {213:'0F',215:'11',216:'13'}[model] + ' 03'
    text = probe_bytes(uid).decode().replace('ISO14443-3A', 'NTAG/Ultralight')
    text += '\n'.join(['Data format version: 2', f'NTAG/Ultralight type: NTAG{model}',
                       'Signature: ' + '00 ' * 31 + '00', 'Mifare version: ' + version]) + '\n'
    for i in range(3):
        text += f'Counter {i}: 781\nTearing {i}: 00\n'
    text += f'Pages total: {total}\nPages read: {total if read is None else read}\n'
    for i in range(total):
        text += f'Page {i}: ' + ('04 03 02 01' if changed and i == 4 else '00 00 00 00') + '\n'
    return text.encode() + ('# ' + PRIVATE + '\n').encode()


def register(case, data=None, name=None, subdir='nfc'):
    path = case.dir / subdir / (name or PRIVATE + '.nfc')
    path.parent.mkdir(exist_ok=True)
    path.write_bytes(ntag() if data is None else data)
    return case.register_artifact(path, kind='other', producer='synthetic-test')


def attest(runtime, case, sha, *, deny=False):
    kind, subject, binding = provenance_import_target(case.id, sha)
    rec = runtime.attestations.request(kind, subject, binding, list(PROVENANCE_IMPORT_QUESTIONS), case.id)
    runtime.attestations.decide(rec['id'], {'source_known':'no'} if deny else
        {'source_known':'yes', 'how_obtained':'격리 합성 fixture'}, via='cli-tty')
    return rec['id']


def bound(runtime, case, data=None):
    data = ntag() if data is None else data
    _, identity = N._inspect_nfc_bound(data, deadline=time.monotonic() + 5)
    scan = I.record_flipper_scan(runtime, case, I.ScanObservation(
        'synthetic-session', {'backend':'posix-tty','lock_key':'synthetic-key','device_id':'synthetic-device',
                              'scope_keys':['synthetic-key']}, identity,
        hashlib.sha256(probe_bytes()).hexdigest(), len(probe_bytes()), True, True, True),
        deadline=time.monotonic()+5)
    return I.add_inventory(runtime, case, scan.scan_ref, deadline=time.monotonic()+5)


@pytest.fixture
def env(workspace, auth):
    runtime = S.rt()
    case = runtime.cases.create(title='합성 NFC 파일', authorization=auth)
    tag = bound(runtime, case)
    return SimpleNamespace(runtime=runtime, case=case, tag=tag)


@pytest.mark.parametrize('model,version', [(213,'0f'),(215,'11'),(216,'13')])
async def test_actual_two_clients_scan_inventory_file_diff_summary(setup, model, version, caplog):
    env = setup
    env.fake.raw_body = raw_body(version=bytes.fromhex('000404020100'+version+'03'))
    async with Client(F.server) as fc, Client(S.server) as nc:
        assert (await call(fc,'flipper_connect',case_id=env.case.id,port=env.port)).get('ok')
        scan = await call(fc,'flipper_nfc_probe',case_id=env.case.id)
        assert scan.get('ok'), scan
        inv = await call(nc,'nfc_tag_inventory_add',case_id=env.case.id,scan_ref=scan['scan_ref'])
        assert inv.get('ok'), inv
        schemas.validate('nfc-scan', scan); schemas.validate('nfc-inventory', inv)
        one = register(env.case, ntag(model)); two = register(env.case, ntag(model,changed=True), 'after.nfc')
        for row in (one,two): attest(env.runtime,env.case,row['sha256'])
        start = (env.case.dir/'audit.jsonl').stat().st_size
        out = await call(nc,'nfc_parse_file',case_id=env.case.id,artifact_id=one['id'],tag_ref=inv['tag_ref'])
        diff = await call(nc,'nfc_diff_dumps',case_id=env.case.id,before_artifact_id=one['id'],
                          after_artifact_id=two['id'],tag_ref=inv['tag_ref'])
        assert out.get('ok'), out
        assert diff.get('ok'), diff
        for result, operation, size in ((out,'inspect',one['size']),(diff,'diff',one['size']+two['size'])):
            report = result['report']; schemas.validate('nfc-file-analysis',report)
            assert report['operation']==operation and report['status']=='ok'
            assert report['inspection']['coverage']['input_bytes']==size
            path = env.case.dir/result['analysis']['path']
            assert json.loads(path.read_bytes())==report and stat.S_IMODE(path.stat().st_mode)==0o444
            assert hashlib.sha256(path.read_bytes()).hexdigest()==result['analysis']['sha256']
            assert report['physical_same_tag_verified'] is False
        assert diff['report']['inspection']['summary']['changed_pages_count']==1
        assert diff['report']['inspection']['summary']['device_association_verified'] is False
        visible = json.dumps([scan,inv,out,diff])+caplog.text+(env.case.dir/'audit.jsonl').read_bytes()[start:].decode()
        for secret in (PRIVATE, UID.hex(), UID.hex(' ').upper(), 'Counter 0', 'Page 4', '00 04 04 02'):
            assert secret not in visible
        summary={'schema':'pweh.nfc-analysis/v1','mode':'scan-bound-offline',
            'tags':[{k:inv[k] for k in ('tag_ref','scan_ref','family','identity_digest')}],
            'results':[{'artifact_id':r['analysis']['artifact_id'],'path':r['analysis']['path'],
                'sha256':r['analysis']['sha256'],'operation':r['report']['operation'],'status':r['report']['status'],
                'tag_ref':inv['tag_ref']} for r in (out,diff)],
            'physical_same_tag_verified':False,'tag_content_written':False,'authentication_attempted':False,'emulation_performed':False}
        schemas.validate('nfc-analysis',summary)
        async with Client(C.server) as cc:
            saved = await call(cc, 'case_record_step', case_id=env.case.id, skill='nfc-behavior-analysis',
                               step='summary', status='success', summary='합성 scan 결속 파일 분석', data=summary,
                               artifacts=[r['analysis']['path'] for r in (out,diff)])
            assert saved.get('ok'),saved
        assert (await call(fc,'flipper_close',case_id=env.case.id))['lease_released']


@pytest.mark.parametrize('data', [probe_bytes(), ntag(read=12)])
async def test_partial_and_iso_core_semantics_preserved(env,data):
    one=register(env.case,data); attest(env.runtime,env.case,one['sha256'])
    async with Client(S.server) as client:
        out=await call(client,'nfc_parse_file',case_id=env.case.id,artifact_id=one['id'],tag_ref=env.tag.tag_ref)
        diff=await call(client,'nfc_diff_dumps',case_id=env.case.id,before_artifact_id=one['id'],after_artifact_id=one['id'],tag_ref=env.tag.tag_ref)
    assert out.get('ok'),out
    assert diff.get('ok'),diff
    assert diff['report']['inspection']['summary']['stored_pages_equal'] is None
    assert diff['report']['inspection']['summary']['pages_compared']==0
    if data==probe_bytes(): assert diff['report']['status']=='unsupported'
    else:
        assert out['report']['status']=='partial'
        assert out['report']['inspection']['coverage']['read_mapping']=='unknown'


async def test_pending_has_no_live_input_fd_and_diff_needs_each_sha(env,monkeypatch):
    one=register(env.case); two=register(env.case,ntag(changed=True),'after.nfc')
    attest(env.runtime,env.case,one['sha256'])
    original=env.runtime.attest
    async def inspect_wait(*args,**kwargs):
        for fd in os.listdir('/proc/self/fd'):
            try: target=os.readlink('/proc/self/fd/'+fd)
            except OSError: continue
            assert target != str(env.case.dir/one['path']) and target != str(env.case.dir/two['path'])
        return await original(*args,**kwargs)
    monkeypatch.setattr(env.runtime,'attest',inspect_wait)
    async with Client(S.server) as client:
        out=await call(client,'nfc_diff_dumps',case_id=env.case.id,before_artifact_id=one['id'],after_artifact_id=two['id'],tag_ref=env.tag.tag_ref)
    assert out['status']=='attestation_required',out
    assert not list((env.case.dir/'analysis').glob('nfc-*.json'))
    assert PRIVATE not in json.dumps(out)


@pytest.mark.parametrize('change', ['content','artifact','revoke','latest'])
async def test_changes_during_attestation_are_not_new_inputs(env,monkeypatch,change):
    one=register(env.case); aid=attest(env.runtime,env.case,one['sha256'])
    original=env.runtime.attest
    async def altered(*args,**kwargs):
        answer=await original(*args,**kwargs)
        if change=='content': (env.case.dir/one['path']).write_bytes(ntag(changed=True))
        elif change=='artifact':
            data=env.case.load(); data['artifacts'][0]['sha256']='00'*32; env.case.meta_path.write_text(json.dumps(data))
        elif change=='revoke': env.runtime.attestations.revoke(aid)
        else: env.runtime.provenance.record_device_read(env.case,one['path'],{'server':'synthetic','tool':'fixture'})
        return answer
    monkeypatch.setattr(env.runtime,'attest',altered)
    async with Client(S.server) as client:
        out=await call(client,'nfc_parse_file',case_id=env.case.id,artifact_id=one['id'],tag_ref=env.tag.tag_ref)
    assert not out.get('ok'),out
    assert any(code in out.get('_error','') for code in ('nfc_input_changed','nfc_provenance_required','nfc_provenance_invalid')),out
    assert not list((env.case.dir/'analysis').glob('nfc-*.json'))


@pytest.mark.parametrize('updates', [{'max_seconds':True},{'max_seconds':'5'},{'max_seconds':float('inf')},
    {'max_seconds':0},{'max_seconds':6},{'artifact_id':[]},{'tag_ref':PRIVATE},{PRIVATE:PRIVATE},{'uid':PRIVATE}])
async def test_strict_sdk_rejects_without_raw_input(env,updates,caplog):
    async with Client(S.server) as client:
        out=await call(client,'nfc_parse_file',**{'case_id':env.case.id,'artifact_id':'A-0001','tag_ref':env.tag.tag_ref,**updates})
    assert 'nfc_input_invalid' in out.get('_error',''),out
    assert PRIVATE not in json.dumps(out)+caplog.text


@pytest.mark.parametrize('which', ['absent','othercase','cache'])
async def test_no_valid_scan_never_opens_input(env,monkeypatch,which):
    tag='NT-'+'1'*32
    if which=='othercase':
        other=env.runtime.cases.create(title='다른 합성 케이스',authorization=env.case.load()['authorization'])
        tag=bound(env.runtime,other).tag_ref
    if which=='cache':
        cache=env.case.dir/'nfc'/'inventory.json'
        cache.unlink()
        cache.write_text(json.dumps(env.tag.to_dict()))
    monkeypatch.setattr(A,'_Inputs',lambda *a,**k:pytest.fail('유효 inventory 전 입력 열기'))
    async with Client(S.server) as client:
        out=await call(client,'nfc_parse_file',case_id=env.case.id,artifact_id='A-0001',tag_ref=tag)
    assert not out.get('ok'),out
    assert 'nfc_scan_' in out.get('_error','')


@pytest.mark.parametrize('data', [ntag(uid=b'OTHER01'),ntag().replace(b'00 44',b'00 04'),
    ntag().replace(b'01 00 0F 03',b'01 00 11 03'),b'bad '+PRIVATE.encode()])
async def test_identity_mismatch_precedes_attestation(env,data,monkeypatch):
    one=register(env.case,data)
    async def no_attest(*a,**k): pytest.fail('거부 파일의 사람 증명 요청')
    monkeypatch.setattr(env.runtime,'attest',no_attest)
    async with Client(S.server) as client:
        out=await call(client,'nfc_parse_file',case_id=env.case.id,artifact_id=one['id'],tag_ref=env.tag.tag_ref)
    assert not out.get('ok'),out
    assert PRIVATE not in json.dumps(out)


async def test_exact_six_tools_annotations_and_closed_sdk():
    async with Client(S.server) as client:
        tools=(await client.list_tools()).tools
    expected={'nfc_tag_inventory_add':{'case_id','scan_ref'},
              'nfc_parse_file':{'case_id','artifact_id','tag_ref','max_seconds'},
              'nfc_diff_dumps':{'case_id','before_artifact_id','after_artifact_id','tag_ref','max_seconds'},
              'nfc_cu_connect':{'case_id','port','approval_id'},
              'nfc_cu_scan':{'case_id','session_id','approval_id'},
              'nfc_cu_disconnect':{'case_id','session_id'}}
    assert {t.name for t in tools}==set(expected)
    for t in tools:
        assert set(t.input_schema['properties'])==expected[t.name]
        assert t.input_schema['additionalProperties'] is False
        assert t.annotations.read_only_hint is False
        assert t.annotations.destructive_hint is False
        assert t.annotations.open_world_hint is (t.name in {'nfc_cu_connect','nfc_cu_scan'})


@pytest.mark.parametrize('mode',['deny','expired','revoked'])
async def test_current_attestation_is_required(env,mode):
    one=register(env.case)
    aid=attest(env.runtime,env.case,one['sha256'],deny=mode=='deny')
    if mode=='revoked':env.runtime.attestations.revoke(aid)
    elif mode=='expired':
        # 합성 저장소가 쓰는 시계를 바꿔 만료를 재현한다.
        import pweh.safety.attestations as att
        original=att._now
        with pytest.MonkeyPatch.context() as mp:
            mp.setattr(att,'_now',lambda:original()+att._dt.timedelta(days=400))
            async with Client(S.server) as client:
                out=await call(client,'nfc_parse_file',case_id=env.case.id,artifact_id=one['id'],tag_ref=env.tag.tag_ref)
            assert out.get('status') in ('attestation_required','denied'),out
        return
    async with Client(S.server) as client:
        out=await call(client,'nfc_parse_file',case_id=env.case.id,artifact_id=one['id'],tag_ref=env.tag.tag_ref)
    assert out.get('status') in ('attestation_required','denied'),out
    assert not list((env.case.dir/'analysis').glob('nfc-*.json'))


async def test_raw_awaiter_cancel_leaves_worker_owning_fd_until_cleanup(env,monkeypatch):
    import asyncio,threading
    one=register(env.case);attest(env.runtime,env.case,one['sha256'])
    entered=threading.Event();release=threading.Event();finished=threading.Event();observed=[]
    real_read=A._read_fd
    def read(fd,size,deadline,cancel,**kw):
        path=os.readlink('/proc/self/fd/'+str(fd))
        if path==str(env.case.dir/one['path']) and not entered.is_set():
            entered.set()
            assert release.wait(5)
            observed.append(os.fstat(fd).st_size)
        return real_read(fd,size,deadline,cancel,**kw)
    real_prepare=A.prepare_admission
    def prepare(*a,**kw):
        try:return real_prepare(*a,**kw)
        finally:finished.set()
    monkeypatch.setattr(A,'_read_fd',read);monkeypatch.setattr(A,'prepare_admission',prepare)
    task=asyncio.create_task(S._analyze(env.case.id,(one['id'],),env.tag.tag_ref,5,None,'nfc_parse_file'))
    try:
        for _ in range(200):
            if entered.is_set():break
            await asyncio.sleep(.005)
        assert entered.is_set()
        task.cancel()
        with pytest.raises(asyncio.CancelledError):await task
        assert not finished.is_set()
    finally:release.set()
    for _ in range(200):
        if finished.is_set():break
        await asyncio.sleep(.005)
    assert finished.is_set() and observed==[one['size']]
    assert not list((env.case.dir/'analysis').glob('nfc-*.json'))


@pytest.mark.parametrize('approved',[False,True])
async def test_import_commit_close_warning_survives_pending_or_result(env,monkeypatch,approved):
    one=register(env.case)
    if approved: attest(env.runtime,env.case,one['sha256'])
    real=env.runtime.provenance.record_import
    class Receipt(dict):
        warnings=('provenance_close_unconfirmed',)
    def record(*args,**kwargs):return Receipt(real(*args,**kwargs))
    monkeypatch.setattr(env.runtime.provenance,'record_import',record)
    async with Client(S.server) as client:
        out=await call(client,'nfc_parse_file',case_id=env.case.id,artifact_id=one['id'],tag_ref=env.tag.tag_ref)
    assert out['warnings']==['provenance_close_unconfirmed'],out
    if approved:assert out['ok'] and (env.case.dir/out['analysis']['path']).exists()
    else:assert out['status']=='attestation_required'


def test_scan_inventory_fixed_close_warning_schema(env):
    inventory=env.tag.to_dict()
    inventory['warnings']=['provenance_close_unconfirmed','inventory_cache_write_failed']
    schemas.validate('nfc-inventory',inventory)
    scan=I.ScanRef(env.tag.scan_ref,env.tag.family,env.tag.identity_digest,
                   env.tag.scan_seq,env.tag.scan_entry_sha256,('provenance_close_unconfirmed',)).to_dict()
    schemas.validate('nfc-scan',scan)
    for value,name in ((scan,'nfc-scan'),(inventory,'nfc-inventory')):
        value['warnings'].append(PRIVATE)
        with pytest.raises(Exception):schemas.validate(name,value)
