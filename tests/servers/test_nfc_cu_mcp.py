"""합성 CU와 실제 Client의 gate·scan 사실·공통 파일 분석·정리 경계."""
from __future__ import annotations

import asyncio
import json
import threading
import time

import pytest
from mcp import Client

from mcp_helpers import call
from pweh import cu_protocol as C, nfc_inventory as I, schemas
from pweh.errors import PwehError
from pweh.runtime import get_runtime
from nfc_mcp import server as S, cu_tools as T, cu_owner as O
from .fake_cu import setup as cu_setup, FakeCu, UID, VERSIONS, frame
from .test_nfc_mcp import ntag, register, attest

pytestmark = pytest.mark.anyio
PRIVATE = 'CU_PRIVATE_SENTINEL_781'


@pytest.fixture
def anyio_backend():
    return 'asyncio'


async def wait_until(check):
    for _ in range(300):
        if check():
            return
        await asyncio.sleep(.005)
    pytest.fail('합성 CU worker 종료를 확인하지 못함')


@pytest.mark.parametrize('tool,valid', [
    ('nfc_cu_connect', {'port': 'COM81'}),
    ('nfc_cu_scan', {'session_id': 'a' * 32}),
    ('nfc_cu_disconnect', {'session_id': 'a' * 32}),
])
@pytest.mark.parametrize('mutation', ['extra', 'case', 'selector', 'approval', 'missing'])
async def test_sdk_errors_hide_raw_input_and_never_prepare(workspace, auth, monkeypatch, caplog, tool, valid, mutation):
    def forbidden(*a, **kw):
        pytest.fail('검증 실패 뒤 CU owner 접근')
    monkeypatch.setattr(O, 'prepare_cu_session', forbidden)
    monkeypatch.setattr(O, 'get_cu_session', forbidden)
    monkeypatch.setattr(O, 'close_cu_session', forbidden)
    args = {'case_id': 'synthetic-cu', **valid}
    if mutation == 'extra': args[PRIVATE] = PRIVATE
    elif mutation == 'case': args['case_id'] = True
    elif mutation == 'selector': args[next(iter(valid))] = {PRIVATE: PRIVATE}
    elif mutation == 'approval': args['approval_id'] = [PRIVATE]
    else: args.pop(next(iter(valid)))
    async with Client(S.server) as client:
        result = await call(client, tool, **args)
    assert 'nfc_input_invalid' in result.get('_error', ''), result
    assert PRIVATE not in json.dumps(result) + caplog.text


@pytest.mark.parametrize('tool,kwargs', [
    ('nfc_cu_connect', {'port': 'COM81\nPRIVATE'}),
    ('nfc_cu_connect', {'port': 'COM81', 'approval_id': '\x7fPRIVATE'}),
    ('nfc_cu_scan', {'session_id': 'PRIVATE\n'}),
    ('nfc_cu_disconnect', {'session_id': 'PRIVATE\x80'}),
])
async def test_control_characters_fail_fixed_before_runtime(workspace, monkeypatch, tool, kwargs):
    monkeypatch.setattr(S, 'rt', lambda: pytest.fail('잘못된 입력 뒤 runtime 접근'))
    async with Client(S.server) as client:
        out = await call(client, tool, case_id='synthetic-cu', **kwargs)
    assert 'nfc_input_invalid' in out.get('_error', '') and 'PRIVATE' not in str(out)


@pytest.mark.parametrize('code', ['cu_protocol_invalid', 'cu_model_unsupported', 'cu_firmware_unsupported',
    'cu_reader_required', 'cu_identity_unknown', 'route_changed', 'port_role_conflict', 'port_lock_busy', 'unknown'])
async def test_preparation_errors_are_fixed(workspace, auth, monkeypatch, caplog, code):
    case = S.rt().cases.create(title='합성 CU 오류', authorization=auth)
    def fail(*a, **kw): raise PwehError(PRIVATE, code=code, data={'raw': PRIVATE})
    monkeypatch.setattr(O, 'prepare_cu_session', fail)
    async with Client(S.server) as client:
        out = await call(client, 'nfc_cu_connect', case_id=case.id, port='COM81')
    assert (code if code != 'unknown' else 'nfc_failed') in out.get('_error', ''), out
    assert PRIVATE not in json.dumps(out) + caplog.text


@pytest.mark.parametrize('data', [
    {'workers_stopped': True, 'transport_closed': True, 'lease_closed': True, 'cleanup_confirmed': True,
     'device_command_termination_verified': False, 'rf_off_verified': True, 'reason': None},
    {'workers_stopped': 1, 'transport_closed': True, 'lease_closed': True, 'cleanup_confirmed': True,
     'device_command_termination_verified': False, 'rf_off_verified': False, 'reason': None},
    {'workers_stopped': True, 'transport_closed': False, 'lease_closed': False, 'cleanup_confirmed': True,
     'device_command_termination_verified': False, 'rf_off_verified': False, 'reason': None},
    {'workers_stopped': True, 'transport_closed': True, 'lease_closed': True, 'cleanup_confirmed': True,
     'device_command_termination_verified': False, 'rf_off_verified': False, 'reason': PRIVATE},
])
def test_cleanup_projection_rejects_unknown_or_false_success(data):
    class Result:
        def to_dict(self): return data
    with pytest.raises(PwehError) as exc:
        T._close_projection(Result())
    assert exc.value.code == 'cu_cleanup_unknown' and PRIVATE not in str(exc.value)


async def connect(client, env):
    result = await call(client, 'nfc_cu_connect', case_id=env.case.id, port=env.port)
    assert result.get('ok'), result
    return result, O.get_cu_session(env.case.id, result['session_id'])


async def scan(client, env, owner, **kwargs):
    return await call(client, 'nfc_cu_scan', case_id=env.case.id, session_id=owner.session_id, **kwargs)


async def close(client, env, owner):
    return await call(client, 'nfc_cu_disconnect', case_id=env.case.id, session_id=owner.session_id)


@pytest.mark.parametrize('model', [213, 215, 216])
@pytest.mark.parametrize('cu_setup', ['posix-tty', 'win-helper'], indirect=True)
async def test_actual_client_cu_scan_common_inventory_and_file_analysis(cu_setup, monkeypatch, model, caplog):
    env = cu_setup
    env.fake = FakeCu(family=model)
    monkeypatch.setattr(S, 'rt', lambda: env.runtime)
    async with Client(S.server) as client:
        connected, owner = await connect(client, env)
        assert connected['device'] == {'model': 'chameleon-ultra', 'app_version': '2.2',
            'git_version': 'v2.2.0', 'reader_mode': True, 'firmware_claim_verified': False}
        assert connected['profile'] == C.PROFILE and connected['rf_off_verified'] is False
        assert [c for c, _ in env.fake.commands] == [1000, 1017, 1033, 1002]
        assert env.opens[0].dtr is True and env.opens[0].rts is False
        result = await scan(client, env, owner)
        assert result.get('ok'), result
        schemas.validate('nfc-scan', result)
        assert result['family'] == f'ntag{model}' and result['read_requests'] == result['pages_retained'] == 2
        assert result['reader_crc_check_succeeded'] is True and result['host_crc_verified'] is False
        assert env.fake.commands[-5:] == [(1002, b''), (2000, b''),
            (2010, bytes.fromhex('fc0064000860')), (2010, bytes.fromhex('ec006400103000')),
            (2010, bytes.fromhex('e4006400103001'))]
        assert not owner._uses and env.fake.field is False
        entries = env.runtime.provenance.entries(env.case)
        assert len(entries) == 1 and entries[0]['fact_kind'] == I.CU_SCAN_FACT
        assert entries[0]['data']['reader_binding']['scope_keys'] == list(owner.keys)
        assert entries[0]['source'] == {'server': 'nfc-mcp', 'tool': 'nfc_cu_scan'}
        assert not env.case.load()['artifacts']
        inv = await call(client, 'nfc_tag_inventory_add', case_id=env.case.id, scan_ref=result['scan_ref'])
        assert inv.get('ok'), inv
        before = register(env.case, ntag(model, uid=UID), name='before.nfc')
        after = register(env.case, ntag(model, uid=UID, changed=True), name='after.nfc')
        pending = await call(client, 'nfc_parse_file', case_id=env.case.id,
                             artifact_id=before['id'], tag_ref=inv['tag_ref'])
        assert pending['status'] == 'attestation_required'
        for artifact in (before, after):
            attest(env.runtime, env.case, artifact['sha256'])
        parsed = await call(client, 'nfc_parse_file', case_id=env.case.id,
                            artifact_id=before['id'], tag_ref=inv['tag_ref'])
        diff = await call(client, 'nfc_diff_dumps', case_id=env.case.id,
                          before_artifact_id=before['id'], after_artifact_id=after['id'], tag_ref=inv['tag_ref'])
        assert parsed.get('ok') and diff.get('ok'), (parsed, diff)
        assert parsed['report']['source']['tag_ref'] == inv['tag_ref']
        assert (env.case.dir / parsed['analysis']['path']).is_file()
        assert (env.case.dir / diff['analysis']['path']).is_file()
        for item in env.runtime.provenance.entries(env.case):
            assert item['kind'] != 'device-read'
        stopped = await close(client, env, owner)
        assert stopped['ok'] and stopped['cleanup_confirmed']
        assert stopped['rf_off_verified'] is stopped['device_command_termination_verified'] is False
    public = json.dumps([connected, result, inv, pending, parsed, diff, stopped]) + caplog.text
    for value in (UID.hex(), UID.hex(' ').upper(), VERSIONS[model].hex(), PRIVATE, 'CU_SYNTHETIC', 'UNTRUSTED123'):
        assert value not in public


@pytest.mark.parametrize('stage', ['connect', 'scan'])
@pytest.mark.parametrize('policy', ['approve', 'deny'])
async def test_gate_no_wire_and_correct_reservation_cleanup(cu_setup, monkeypatch, isolated_ports, stage, policy):
    env = cu_setup
    monkeypatch.setattr(S, 'rt', lambda: env.runtime)
    async with Client(S.server) as client:
        owner = (await connect(client, env))[1] if stage == 'scan' else None
        before = list(env.fake.commands)
        env.workspace['set_safety'](modify_policy=policy)
        env.runtime = get_runtime('cu-test')
        result = (await scan(client, env, owner)) if owner else await call(client, 'nfc_cu_connect',
            case_id=env.case.id, port=env.port)
        assert result.get('status') == ('approval_required' if policy == 'approve' else 'denied'), result
        assert result['gate']['classification']['risk'] == 'modify'
        assert env.fake.commands == before and env.runtime.provenance.entries(env.case) == []
        if owner:
            assert not owner._uses and owner.state == 'ready' and isolated_ports['manager']._leases
            assert (await close(client, env, owner))['ok']
        else:
            assert not env.opens and not isolated_ports['manager']._leases and env.case.id not in O._REGISTRY


@pytest.mark.parametrize('stage', ['connect', 'scan'])
async def test_approval_retry_uses_fixed_profile_and_exact_scan_session(cu_setup, monkeypatch, stage):
    env = cu_setup
    monkeypatch.setattr(S, 'rt', lambda: env.runtime)
    async with Client(S.server) as client:
        owner = (await connect(client, env))[1] if stage == 'scan' else None
        env.workspace['set_safety'](modify_policy='approve')
        env.runtime = get_runtime('cu-test')
        pending = await scan(client, env, owner) if owner else await call(client, 'nfc_cu_connect',
            case_id=env.case.id, port=env.port)
        assert pending.get('status') == 'approval_required', pending
        aid = pending['approval_id']
        approval = env.runtime.approvals.get(aid)
        env.runtime.approvals.decide(aid, approve=True, code=approval['code'], via='cli-tty')
        if owner:
            action = T.approval_action(owner)
            assert action['session_id'] == owner.session_id
            assert action['nfc_profile_sha256'] == C.PROFILE_SHA256
            result = await scan(client, env, owner, approval_id=aid)
        else:
            result = await call(client, 'nfc_cu_connect', case_id=env.case.id, port=env.port, approval_id=aid)
            if result.get('ok'): owner = O.get_cu_session(env.case.id, result['session_id'])
        assert result.get('ok'), result
        assert (await close(client, env, owner))['ok']


@pytest.mark.parametrize('tool', ['nfc_cu_scan', 'nfc_cu_disconnect'])
@pytest.mark.parametrize('wrong', ['case', 'session'])
async def test_other_case_or_session_does_not_touch_owner(cu_setup, monkeypatch, auth, tool, wrong):
    env = cu_setup
    monkeypatch.setattr(S, 'rt', lambda: env.runtime)
    other = env.runtime.cases.create(title='합성 다른 케이스', authorization=auth)
    async with Client(S.server) as client:
        _, owner = await connect(client, env)
        before = list(env.fake.commands)
        result = await call(client, tool, case_id=other.id if wrong == 'case' else env.case.id,
                            session_id='0' * 32 if wrong == 'session' else owner.session_id)
        assert 'nfc_input_invalid' in result.get('_error', ''), result
        assert owner.state == 'ready' and not owner._uses and env.fake.commands == before
        assert (await close(client, env, owner))['ok']


async def test_disconnect_works_after_authorization_revocation(cu_setup, monkeypatch):
    env = cu_setup
    monkeypatch.setattr(S, 'rt', lambda: env.runtime)
    async with Client(S.server) as client:
        _, owner = await connect(client, env)
        def revoked(*a, **kw): raise PwehError(PRIVATE, code='authorization_required')
        monkeypatch.setattr(env.runtime, 'case', revoked)
        out = await scan(client, env, owner)
        assert 'authorization_required' in out.get('_error', '') and PRIVATE not in str(out)
        assert (await close(client, env, owner))['ok']


@pytest.mark.parametrize('fault', ['bcc', 'version', 'mode'])
async def test_probe_failure_does_not_create_scan_or_inventory(cu_setup, monkeypatch, fault):
    env = cu_setup
    monkeypatch.setattr(S, 'rt', lambda: env.runtime)
    async with Client(S.server) as client:
        _, owner = await connect(client, env)
        if fault == 'bcc': env.fake.pages[0] = bytes(4)
        elif fault == 'version': env.fake.version = bytes(8)
        else: env.fake.responses[1002] = frame(1002, b'\0')
        out = await scan(client, env, owner)
        assert not out.get('ok') and env.runtime.provenance.entries(env.case) == []
        assert not owner._uses and owner.state == 'terminal'
        if fault == 'mode': assert not any(c in (2000, 2010) for c, _ in env.fake.commands)
        elif fault == 'version': assert not any(c == 2010 and len(p) == 7 for c, p in env.fake.commands)
        assert (await close(client, env, owner))['ok']


async def test_scope_change_after_approval_is_not_next_tx(cu_setup, monkeypatch):
    env = cu_setup
    monkeypatch.setattr(S, 'rt', lambda: env.runtime)
    async with Client(S.server) as client:
        _, owner = await connect(client, env)
        authorize = env.runtime.authorize
        async def changed(**kwargs):
            result = await authorize(**kwargs)
            env.keys = tuple(sorted((*env.keys, 'new-sibling')))
            return result
        monkeypatch.setattr(env.runtime, 'authorize', changed)
        before = list(env.fake.commands)
        out = await scan(client, env, owner)
        assert 'route_changed' in out.get('_error', '') and env.fake.commands == before
        assert not env.runtime.provenance.entries(env.case)
        assert (await close(client, env, owner))['ok']


async def test_unknown_close_keeps_owner_and_lease_until_retry(cu_setup, monkeypatch, isolated_ports):
    env = cu_setup
    monkeypatch.setattr(S, 'rt', lambda: env.runtime)
    async with Client(S.server) as client:
        _, owner = await connect(client, env)
        env.fake.close_verified = False
        result = await close(client, env, owner)
        assert result['ok'] is False and result['reason'] == 'transport_close_unconfirmed'
        assert not result['transport_closed'] and not result['lease_closed']
        assert O.get_cu_session(env.case.id, owner.session_id) is owner
        assert isolated_ports['manager']._leases
        env.fake.close_verified = True
        assert (await close(client, env, owner))['ok']
    assert not isolated_ports['manager']._leases


async def test_raw_cancel_keeps_claimed_worker_and_lease_until_finish(cu_setup, monkeypatch, isolated_ports):
    env = cu_setup
    monkeypatch.setattr(S, 'rt', lambda: env.runtime)
    entered, release = threading.Event(), threading.Event()
    async with Client(S.server) as client:
        _, owner = await connect(client, env)
        def blocked(size):
            entered.set()
            assert release.wait(3)
        env.fake.before_read = blocked
        task = asyncio.create_task(S.nfc_cu_scan(env.case.id, owner.session_id))
        try:
            await wait_until(entered.is_set)
            task.cancel()
            with pytest.raises(asyncio.CancelledError): await task
            assert owner._uses and isolated_ports['manager']._leases and env.fake.cancel_calls
        finally:
            release.set()
        await wait_until(lambda: not owner._uses)
        assert not env.runtime.provenance.entries(env.case)
        assert (await close(client, env, owner))['ok']


async def test_fact_commit_preserves_late_cancel_and_close_warning(cu_setup, monkeypatch):
    env = cu_setup
    monkeypatch.setattr(S, 'rt', lambda: env.runtime)
    original = env.runtime.provenance.record_device_fact
    class Receipt(dict):
        warnings = ('provenance_close_unconfirmed',)
    async with Client(S.server) as client:
        _, owner = await connect(client, env)
        def committed(*a, **kw):
            value = original(*a, **kw)
            for use in tuple(owner._uses): use.cancel()
            return Receipt(value)
        monkeypatch.setattr(env.runtime.provenance, 'record_device_fact', committed)
        result = await scan(client, env, owner)
        assert result.get('ok'), result
        assert result['warnings'] == ['provenance_close_unconfirmed']
        assert env.runtime.provenance.entries(env.case)[0]['data']['scan_ref'] == result['scan_ref']
        assert not owner._uses
        assert (await close(client, env, owner))['ok']
