"""실제 MCP·합성 CLI의 고정 NFC 선택/정리/원장·취소 경계."""
from __future__ import annotations

import asyncio
import hashlib
import json
import threading
import time
from types import SimpleNamespace

import pytest
from mcp import Client

from mcp_helpers import call
from pweh import nfc_inventory as I
from pweh.errors import PwehError
from pweh.schemas import validate
from flipper_mcp import server as S, session as T, nfc as N
from .fake_flipper_nfc import setup, FakeNfc, UID, NFC_PROMPT, MOTD, probe_bytes, raw_body

pytestmark = pytest.mark.anyio
PRIVATE = 'PRIVATE_NFC_SENTINEL'


@pytest.fixture
def anyio_backend():
    return 'asyncio'


async def connect(client, env):
    out = await call(client, 'flipper_connect', case_id=env.case.id, port=env.port)
    assert out.get('ok'), out
    return T.get_session(env.case.id)


async def scan(client, env, **kw):
    return await call(client, 'flipper_nfc_probe', case_id=env.case.id, **kw)


def facts(env):
    return env.runtime.provenance.entries(env.case)


async def wait_until(check):
    for _ in range(200):
        if check():
            return
        await asyncio.sleep(.005)
    pytest.fail('합성 worker 종료를 확인하지 못함')


@pytest.mark.parametrize('model,value', [(213, '0f'), (215, '11'), (216, '13')])
@pytest.mark.parametrize('setup', ['posix-tty', 'win-helper'], indirect=True)
async def test_actual_client_scan_writes_only_bound_fact_after_cleanup(setup, model, value, caplog):
    env = setup
    version = bytes.fromhex('000404020100' + value + '03')
    env.fake.raw_body = raw_body(version=version)
    async with Client(S.server) as client:
        owner = await connect(client, env)
        out = await scan(client, env)
        assert out.get('ok'), out
        validate('nfc-scan', out)
        assert out['family'] == 'ntag' + str(model)
        assert out['inventory_eligible'] and out['scratch_cleanup_confirmed']
        for flag in ('page_read_performed', 'reselection_atomic', 'physical_same_tag_verified',
                     'device_command_termination_verified'):
            assert out[flag] is False
        assert len(env.fake.created) == len(env.fake.deleted) == 1 and env.fake.files == {}
        entries = facts(env)
        assert len(entries) == 1 and entries[0]['data']['scan_ref'] == out['scan_ref']
        data = entries[0]['data']
        assert data['probe_sha256'] == hashlib.sha256(env.fake.probe_data).hexdigest()
        assert data['reader_binding']['scope_keys'] == list(owner.keys)
        assert data['identity']['atqa_msb'] == '0044'
        assert entries[0]['source'] == {'server': 'flipper-mcp', 'tool': 'flipper_nfc_probe'}
        assert env.case.load()['artifacts'] == []
        assert not owner._uses and owner.cli.ready and owner.state == 'ready'
        info = await call(client, 'flipper_device_info', case_id=env.case.id)
        assert info.get('ok')
        assert (await call(client, 'flipper_close', case_id=env.case.id))['lease_released']
    visible = json.dumps(out) + caplog.text
    assert UID.hex() not in visible and UID.hex(' ').upper() not in visible
    assert version.hex() not in visible and env.fake.created[0] not in visible
    assert sum(cmd.startswith(b'raw ') for cmd in env.fake.commands) == 1
    assert sum(cmd.startswith(b'dump ') for cmd in env.fake.commands) == 1
    assert all(b'mfu' not in cmd and b'-k' not in cmd for cmd in env.fake.commands)
    dump = next(cmd for cmd in env.fake.commands if cmd.startswith(b'dump '))
    assert b'"' not in dump


@pytest.mark.parametrize('chunk', [1, 2, 4096])
async def test_split_and_coalesced_frames_and_partial_writes(setup, chunk):
    setup.fake.chunk, setup.fake.write_chunk = chunk, 3
    async with Client(S.server) as client:
        await connect(client, setup)
        assert (await scan(client, setup)).get('ok')
        await call(client, 'flipper_close', case_id=setup.case.id)


@pytest.mark.parametrize('updates', [{PRIVATE: PRIVATE}, {'command': 'raw'}, {'case_id': True},
    {'approval_id': []}, {'approval_id': PRIVATE * 20}])
async def test_fixed_sdk_error_has_no_input_or_location(setup, updates, caplog):
    async with Client(S.server) as client:
        out = await call(client, 'flipper_nfc_probe', **{'case_id': setup.case.id, **updates})
    assert 'nfc_input_invalid' in out.get('_error', ''), out
    assert PRIVATE not in json.dumps(out) + caplog.text
    assert not setup.opens and not setup.fake.writes


@pytest.mark.parametrize('policy', ['approve', 'deny'])
async def test_probe_gate_never_sends_and_keeps_connection_lease(setup, policy, isolated_ports):
    async with Client(S.server) as client:
        owner = await connect(client, setup)
        setup.workspace['set_safety'](modify_policy=policy)
        before = list(setup.fake.commands)
        out = await scan(client, setup)
        assert out['status'] == ('approval_required' if policy == 'approve' else 'denied')
        assert out['gate']['classification']['risk'] == 'modify'
        assert setup.fake.commands == before and not owner._uses
        assert isolated_ports['manager']._leases and owner.state == 'ready'
        await call(client, 'flipper_close', case_id=setup.case.id)


async def test_approval_binds_profile_and_scope_but_not_random_name(setup):
    async with Client(S.server) as client:
        owner = await connect(client, setup)
        setup.workspace['set_safety'](modify_policy='approve')
        action = N.approval_action(owner)
        assert action == N.approval_action(owner)
        assert action['nfc_profile_sha256'] == I.PROFILE_SHA256
        pending = await scan(client, setup)
        aid = pending['approval_id']
        record = S.rt().approvals.get(aid)
        S.rt().approvals.decide(aid, approve=True, code=record['code'], via='cli-tty')
        assert (await scan(client, setup, approval_id=aid)).get('ok')
        await call(client, 'flipper_close', case_id=setup.case.id)


@pytest.mark.parametrize('stage', ['scope', 'revoked', 'deadline'])
async def test_pre_io_failure_does_not_send_next_command(setup, monkeypatch, stage):
    async with Client(S.server) as client:
        owner = await connect(client, setup)
        before = list(setup.fake.commands)
        if stage == 'scope':
            setup.keys = tuple(sorted((*setup.keys, 'new-sibling')))
        elif stage == 'deadline':
            monkeypatch.setattr(N, 'PROBE_SECONDS', 0)
        else:
            original = owner.runtime.case
            def revoked(*args, **kwargs):
                raise PwehError(PRIVATE, code='authorization_required')
            monkeypatch.setattr(owner.runtime, 'case', revoked)
        out = await scan(client, setup)
        assert not out.get('ok') and setup.fake.commands == before and facts(setup) == []
        assert PRIVATE not in str(out)
        await call(client, 'flipper_close', case_id=setup.case.id)


async def test_preexisting_scratch_is_never_overwritten(setup, monkeypatch):
    async with Client(S.server) as client:
        await connect(client, setup)
        monkeypatch.setattr(N.uuid, 'uuid4', lambda: SimpleNamespace(hex='0' * 32))
        path = f'/ext/pweh/{setup.case.id}/probe-' + '0' * 32 + '.nfc'
        setup.fake.files[path] = b'KEEP'
        out = await scan(client, setup)
        assert 'nfc_input_changed' in out.get('_error', '')
        assert setup.fake.files[path] == b'KEEP' and not setup.fake.created and not setup.fake.deleted
        assert not facts(setup)
        await call(client, 'flipper_close', case_id=setup.case.id)


@pytest.mark.parametrize('uid,sak', [(b'abcd', b'\0'), (UID, b'\x08')])
async def test_probe_policy_denial_has_no_get_version_and_cleans_own_file(setup, uid, sak):
    setup.fake.probe_data = probe_bytes(uid, sak)
    async with Client(S.server) as client:
        await connect(client, setup)
        out = await scan(client, setup)
        assert 'nfc_family_unsupported' in out.get('_error', ''), out
        assert not any(cmd.startswith(b'raw ') for cmd in setup.fake.commands)
        assert not setup.fake.files and len(setup.fake.deleted) == 1 and not facts(setup)
        await call(client, 'flipper_close', case_id=setup.case.id)


@pytest.mark.parametrize('body,code,cleanup', [
    (raw_body(uid=b'CHANGED'), 'nfc_identity_mismatch', True),
    (raw_body(version=bytes(8)), 'nfc_family_unsupported', True),
    (raw_body(sak=b'\x08'), 'nfc_identity_mismatch', True),
    (raw_body().replace(b'ATQA: 4400', b'ATQA: 0044'), 'nfc_identity_mismatch', True),
    (raw_body()[:-3] + b'00 ', 'nfc_scan_invalid', False),
    (raw_body().replace(b'Tx: 60 F8 32 ', b'Tx: 60 00 00 '), 'nfc_scan_invalid', False),
    (raw_body() + b'\r\n' + PRIVATE.encode(), 'nfc_scan_invalid', False),
    (raw_body().split(b'Rx: ')[0] + b'Rx: 00 ', 'nfc_scan_invalid', False),
    (raw_body().replace(b'  ATQA:', b' ATQA:'), 'nfc_scan_invalid', False),
])
async def test_raw_rejections_never_create_fact(setup, body, code, cleanup, caplog):
    setup.fake.raw_body = body
    async with Client(S.server) as client:
        owner = await connect(client, setup)
        out = await scan(client, setup)
        assert code in out.get('_error', ''), out
        assert not facts(setup)
        assert bool(setup.fake.deleted) is cleanup
        assert owner.state == 'terminal'
        before = list(setup.fake.commands)
        assert not (await call(client, 'flipper_device_info', case_id=setup.case.id)).get('ok')
        assert setup.fake.commands == before
        await call(client, 'flipper_close', case_id=setup.case.id)
    assert PRIVATE not in json.dumps(out) + caplog.text


@pytest.mark.parametrize('stage', ['entry', 'dump', 'read', 'md5', 'remove', 'post-list', 'oversize', 'changed'])
async def test_scratch_or_wire_failure_never_publishes_scan(setup, stage):
    async with Client(S.server) as client:
        await connect(client, setup)
        if stage == 'entry':
            setup.fake.responses[b'nfc'] = b'nfc\r\nBAD\r\n>: '
        elif stage == 'dump':
            setup.fake.responses[b'dump '] = lambda c: c + b'\r\n' + NFC_PROMPT
        elif stage == 'read':
            setup.fake.responses[b'storage read '] = lambda c: c + b'\r\nSize: 1\r\nx\r\n\r\n>: '
        elif stage == 'md5':
            setup.fake.responses[b'storage md5 '] = lambda c: c + b'\r\n' + b'0' * 32 + b'\r\n\r\n>: '
        elif stage == 'remove':
            setup.fake.responses[b'storage remove '] = lambda c: c + b'\r\nStorage error: ' + PRIVATE.encode() + b'\r\n\r\n>: '
        elif stage == 'post-list':
            setup.fake.keep_scratch = True
        elif stage == 'oversize':
            setup.fake.probe_data = b'x' * 4097
        else:
            original = setup.fake.response
            def changed(command):
                result = original(command)
                if command.startswith(b'raw '):
                    setup.fake.files[setup.fake.created[0]] += b'x'
                return result
            setup.fake.response = changed
        out = await scan(client, setup)
        assert not out.get('ok') and not facts(setup), out
        assert PRIVATE not in str(out)
        assert not setup.case.load()['artifacts']
        await call(client, 'flipper_close', case_id=setup.case.id)


async def test_raw_cancel_keeps_worker_and_lease_until_reader_returns(setup, isolated_ports):
    entered, release = threading.Event(), threading.Event()
    async with Client(S.server) as client:
        owner = await connect(client, setup)
        def block(size):
            if setup.fake.nfc:
                entered.set()
                assert release.wait(5)
        setup.fake.before_read = block
        task = asyncio.create_task(S.flipper_nfc_probe(setup.case.id))
        assert await asyncio.to_thread(entered.wait, 2)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        assert owner._uses and isolated_ports['manager']._leases and not setup.fake.closed
        before = list(setup.fake.commands)
        release.set()
        await wait_until(lambda: not owner._uses)
        assert setup.fake.commands == before and owner.state == 'terminal' and not facts(setup)
        setup.fake.before_read = None
        await call(client, 'flipper_close', case_id=setup.case.id)


async def test_deadline_during_raw_sends_no_exit_or_cleanup(setup, monkeypatch):
    async with Client(S.server) as client:
        owner = await connect(client, setup)
        monkeypatch.setattr(N, 'TEXT_SECONDS', .03)
        setup.fake.responses[b'raw '] = lambda c: c + b'\r\n'
        out = await scan(client, setup)
        assert 'time_limit' in out.get('_error', ''), out
        assert setup.fake.commands[-1].startswith(b'raw ') and not setup.fake.deleted
        assert owner.state == 'terminal' and not facts(setup)
        await call(client, 'flipper_close', case_id=setup.case.id)


async def test_fact_commit_occurs_after_remote_cleanup_and_late_cancel_keeps_receipt(setup, monkeypatch):
    async with Client(S.server) as client:
        owner = await connect(client, setup)
        original = I.record_flipper_scan
        def commit(*args, **kwargs):
            assert setup.fake.deleted and not setup.fake.files
            result = original(*args, **kwargs)
            next(iter(owner._uses)).cancel()
            return result
        monkeypatch.setattr(I, 'record_flipper_scan', commit)
        out = await scan(client, setup)
        assert out.get('ok') and len(facts(setup)) == 1
        await call(client, 'flipper_close', case_id=setup.case.id)


async def test_unknown_exception_is_fixed_and_no_success_fact(setup, monkeypatch, caplog):
    async with Client(S.server) as client:
        await connect(client, setup)
        def failed(*args, **kwargs):
            raise RuntimeError(PRIVATE)
        monkeypatch.setattr(I, 'record_flipper_scan', failed)
        out = await scan(client, setup)
        assert not out.get('ok') and PRIVATE not in json.dumps(out) + caplog.text
        assert not facts(setup) and not setup.fake.files
        await call(client, 'flipper_close', case_id=setup.case.id)
