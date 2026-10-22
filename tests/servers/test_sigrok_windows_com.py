"""Windows OLS 공개 경계: 합성 owner/장치 신원만 사용한다."""
from __future__ import annotations

import asyncio
from dataclasses import replace
import json
import threading
import time
from types import SimpleNamespace

import pytest
from mcp import Client
from mcp_helpers import call
from pweh import ports
from pweh.errors import PwehError
from pweh.portidentity import PortIdentity
from sigrok_mcp import cli, server as S, windows_com_tools as W
from .test_sigrok_mcp import fake

pytestmark = pytest.mark.anyio

@pytest.fixture
def anyio_backend():
    return 'asyncio'

SCAN = b'The following devices were found:\nols - Synthetic with 2 channels: 0 1\n'
SHOW = b'''Driver functions:
  Logic analyzer
Scan options:
  conn
ols - Synthetic with 2 channels: 0 1
Supported configuration options:
    samplerate (1 Hz - 1 GHz in steps of 1 Hz)
    Supported triggers: 0 1 r f
    Maximum number of samples: 1024
'''
PRIVATE = r'C:\PRIVATE_SENTINEL\copy\sigrok-cli.exe'

class Owner:
    def __init__(self, command, fixture):
        self.command, self.fixture = command, fixture
        self.confirmed = True
        self.prepared = self.executed = self.closed = False
        self.close_count = 0
        self.block = None
        self.entered, self.release, self.done = threading.Event(), threading.Event(), threading.Event()
        self.result = cli.CliResult([PRIVATE, *command.argv_tail], 0, SCAN if command.mode == 'scan' else SHOW, '')
    def pause(self, stage):
        if self.block == stage:
            self.entered.set()
            assert self.release.wait(5), '합성 worker 해제 누락'
    def prepare(self, parent, *, ambient_env, deadline, cancel):
        assert self.fixture.manager._leases and isinstance(ambient_env, tuple)
        self.prepared = True
        self.pause('prepare')
        if self.fixture.prepare_hook:
            self.fixture.prepare_hook(self)
    def run(self, *, before_spawn, deadline, cancel, timeout_s):
        self.fixture.timeouts.append(timeout_s)
        self.pause('run')
        if cancel():
            raise PwehError(PRIVATE, code='sigrok_com_cancelled')
        before_spawn()
        self.executed = True
        if isinstance(self.result, Exception):
            raise self.result
        return self.result
    def close(self, *, deadline):
        assert 0 < deadline-time.monotonic() <= 10
        self.close_count += 1
        self.pause('close')
        self.closed = True
        self.done.set()
        return SimpleNamespace(confirmed=self.confirmed)

@pytest.fixture
def env(workspace, auth, tmp_path, monkeypatch, isolated_ports):
    case = S.rt().cases.create(title='합성 OLS COM', authorization=auth)
    bundle = SimpleNamespace(entrypoint=tmp_path/'original/sigrok-cli.exe',
        release_id='sigrok-cli-0.7.2-win64-selected', manifest_sha256='a'*64,
        digest_basis='first-acquisition-sha256', known_limitations=('signature-python34-syntax',))
    state = SimpleNamespace(case=case, workspace=workspace, bundle=bundle, owners=[], timeouts=[],
        manager=isolated_ports['manager'], prepare_hook=None, owner_hook=None, serial='synthetic-one')
    host = {'kind': 'WSL2_INTEROP', 'wsl': {'interop': {'usable': True}}}
    monkeypatch.setattr(S, '_port_environment', lambda: host)
    def identity(ref):
        return PortIdentity(ref, status='known', present=True, backend='windows',
            usb_ancestor='USB\\VID_10C4&PID_EA60\\'+state.serial, vid='10c4', pid='ea60',
            interface_number='00', serial=state.serial)
    monkeypatch.setattr(S, '_port_probe', lambda: ports.PortProbe(identity=identity))
    monkeypatch.setattr(W.info, '_environment', lambda cfg: host)
    monkeypatch.setattr(W.info, '_resolve_bundle', lambda cfg, **kw: bundle)
    monkeypatch.setattr(W.info, '_runtime_parent', lambda cfg: tmp_path)
    monkeypatch.setattr(S, '_cli', lambda: pytest.fail('Windows가 Linux CLI를 사용함'))
    def reserve(actual, command, **kw):
        assert actual is bundle and state.manager._leases
        owner = Owner(command, state)
        state.owners.append(owner)
        if state.owner_hook:
            state.owner_hook(owner)
        return owner
    monkeypatch.setattr(W, '_reserve', reserve)
    yield state
    for owner in state.owners:
        owner.release.set()
    for use in list(S._ORPHAN_PORTS):
        if use.lease._manager is state.manager:
            assert use.cleanup_owner is not None
            use.cleanup_owner.confirmed = True
            use.unverified = False
            use.finish()
            S._ORPHAN_PORTS.remove(use)

async def invoke(client, env, tool='sigrok_scan', **kwargs):
    args = dict(case_id=env.case.id, driver='ols', conn='COM7', backend='windows')
    args.update(kwargs)
    return await call(client, tool, **args)

@pytest.mark.parametrize('tool,mode,timeout', [('sigrok_scan','scan',45), ('sigrok_device_info','show',60)])
async def test_public_success_profile_route_and_closed_owner(env, tool, mode, timeout):
    async with Client(S.server) as c:
        out = await invoke(c, env, tool)
    assert out['ok'] and out['backend'] == 'windows', out
    assert out['classification']['risk'] == 'modify'
    assert out['route']['backend'] == 'win-exe'
    assert out['profile']['mode'] == mode and out['profile']['conn'] == 'COM7'
    assert out['bundle']['manifest_sha256'] == 'a'*64
    assert env.timeouts == [timeout] and env.owners[0].closed and env.owners[0].executed
    assert not env.manager._leases and 'PRIVATE_SENTINEL' not in json.dumps(out)
    device = out['devices'][0] if mode == 'scan' else out['device']
    assert device['conn'] is None and 'raw' not in device

@pytest.mark.parametrize('field,value,code', [
    ('cleanup_verified',False,'sigrok_com_cleanup_unknown'), ('cancelled',True,'sigrok_com_cancelled'),
    ('timed_out',True,'sigrok_com_timeout'), ('output_limit_hit',True,'sigrok_com_output_limit'),
    ('returncode',7,'sigrok_com_failed'), ('stderr','Permission denied '+PRIVATE,'sigrok_com_failed'),
    ('stdout',b'\xff','sigrok_com_bad_output'), ('stdout',b'garbage','sigrok_com_bad_output'),
])
@pytest.mark.parametrize('tool', ['sigrok_scan','sigrok_device_info'])
async def test_failure_priorities_and_private_output(env, field, value, code, tool):
    env.owner_hook = lambda owner: setattr(owner, 'result', replace(owner.result, **{field:value}))
    async with Client(S.server) as c:
        out = await invoke(c, env, tool)
    assert '['+code+']' in out.get('_error',''), out
    assert 'PRIVATE_SENTINEL' not in out['_error'] and env.owners[0].closed
    assert not env.manager._leases

@pytest.mark.parametrize('tool', ['sigrok_scan','sigrok_device_info'])
@pytest.mark.parametrize('updates', [dict(driver='demo'),dict(conn='1.2'),dict(conn='COM7 '),
    dict(conn='COM07'),dict(conn=None),dict(timeout_s=0),dict(timeout_s=-1),dict(timeout_s=61),dict(backend='auto')])
async def test_input_rejections_do_not_reserve(env, tool, updates):
    async with Client(S.server) as c:
        out = await invoke(c, env, tool, **updates)
    assert '_error' in out and not env.owners and not env.manager._leases, out

async def test_hard_output_policy_stays_denied(env):
    async with Client(S.server) as c:
        out = await invoke(c, env, driver='korad-kaxxxxp')
    assert out['status'] == 'denied' and not env.owners

async def test_gate_denial_precedes_owner_copy_and_spawn(env):
    env.workspace['set_safety'](modify_policy='deny')
    async with Client(S.server) as c:
        out = await invoke(c, env)
    assert out['status'] == 'denied' and not env.owners and not env.manager._leases

async def test_approval_same_arguments_consumed_once_and_fingerprint_bound(env):
    env.workspace['set_safety'](modify_policy='approve')
    async with Client(S.server) as c:
        pending = await invoke(c, env)
        assert pending['status'] == 'approval_required' and not env.owners and not env.manager._leases
        aid = pending['approval_id']
        record = S.rt().approvals.get(aid)
        S.rt().approvals.decide(aid, approve=True, code=record['code'], via='cli-tty')
        out = await invoke(c, env, approval_id=aid)
        assert out['ok'], out
        again = await invoke(c, env, approval_id=aid)
        assert not again['ok'] and len(env.owners) == 1

@pytest.mark.parametrize('change', ['route','bundle','mode'])
async def test_approved_action_cannot_change(env, change):
    env.workspace['set_safety'](modify_policy='approve')
    async with Client(S.server) as c:
        pending = await invoke(c, env)
        aid = pending['approval_id']
        rec = S.rt().approvals.get(aid)
        S.rt().approvals.decide(aid, approve=True, code=rec['code'], via='cli-tty')
        if change == 'route': env.serial = 'synthetic-two'
        if change == 'bundle': env.bundle.manifest_sha256 = 'b'*64
        out = await invoke(c, env, 'sigrok_device_info' if change == 'mode' else 'sigrok_scan', approval_id=aid)
    assert not out['ok'] and not env.owners and not env.manager._leases

async def test_change_during_prepare_rejected_by_last_fresh_check(env):
    env.prepare_hook = lambda owner: setattr(env, 'serial', 'synthetic-two')
    async with Client(S.server) as c:
        out = await invoke(c, env)
    assert '[route_changed]' in out['_error'] and not env.owners[0].executed and env.owners[0].closed

async def test_unknown_owner_retains_lease_until_exact_cleanup(env):
    env.owner_hook = lambda owner: setattr(owner, 'confirmed', False)
    async with Client(S.server) as c:
        out = await invoke(c, env)
        assert '[sigrok_com_cleanup_unknown]' in out['_error'] and env.manager._leases
        blocked = await invoke(c, env)
        assert '[busy]' in blocked['_error'] and len(env.owners) == 1
        env.owners[0].confirmed = True
        env.owner_hook = None
        retry = await invoke(c, env)
    assert retry['ok'] and len(env.owners) == 2 and not env.manager._leases

@pytest.mark.parametrize('stage', ['prepare','run','close'])
async def test_raw_cancel_leaves_worker_as_cleanup_owner(env, stage):
    env.owner_hook = lambda owner: setattr(owner, 'block', stage)
    task = asyncio.create_task(S.sigrok_scan.__wrapped__(case_id=env.case.id,driver='ols',conn='COM7',backend='windows'))
    end = time.monotonic()+2
    while not env.owners and time.monotonic()<end: await asyncio.sleep(.005)
    owner = env.owners[0]
    assert await asyncio.to_thread(owner.entered.wait, 2)
    task.cancel()
    with pytest.raises(asyncio.CancelledError): await task
    assert env.manager._leases and not owner.closed
    owner.release.set()
    assert await asyncio.to_thread(owner.done.wait, 2)
    end = time.monotonic()+2
    while env.manager._leases and time.monotonic()<end: await asyncio.sleep(.005)
    assert not env.manager._leases

@pytest.mark.parametrize('tool', ['sigrok_scan','sigrok_device_info','sigrok_capture'])
async def test_default_linux_and_capture_com_still_rejected(env, tool):
    args = dict(case_id=env.case.id,driver='ols',conn='COM7')
    if tool == 'sigrok_capture': args.update(samples=64,samplerate='1m')
    async with Client(S.server) as c: out = await call(c, tool, **args)
    assert '_error' in out and not env.owners

@pytest.mark.parametrize('stdout', [b'The following devices were found:\nBAD\n',
    SCAN+SCAN.split(b'\n')[1]+b'\n', SCAN.replace(b'ols -',b'ols:conn=COM8 -')])
async def test_scan_rejects_ignored_or_multiple_or_wrong_device_rows(env, stdout):
    env.owner_hook = lambda owner: setattr(owner, 'result', replace(owner.result, stdout=stdout))
    async with Client(S.server) as c: out = await invoke(c, env)
    assert '[sigrok_com_bad_output]' in out['_error'], out

@pytest.mark.parametrize('code', ['sigrok_com_timeout','sigrok_com_cancelled','sigrok_com_busy','sigrok_com_output_limit'])
async def test_owner_fixed_codes_preserved(env, code):
    env.owner_hook = lambda owner: setattr(owner, 'result', PwehError(PRIVATE,code=code,data={'raw':PRIVATE}))
    async with Client(S.server) as c: out = await invoke(c, env)
    assert '['+code+']' in out['_error'] and 'PRIVATE_SENTINEL' not in out['_error']

@pytest.mark.parametrize('tool', ['sigrok_scan','sigrok_device_info'])
async def test_no_device_and_mixed_fatal_are_distinct(env, tool):
    header = b'Driver functions:\n  Logic analyzer\nScan options:\n  conn\n'
    def response(owner):
        owner.result = replace(owner.result, returncode=1, stdout=header,
                               stderr='No devices found. '+PRIVATE)
    env.owner_hook = response
    async with Client(S.server) as c:
        out = await invoke(c, env, tool)
        if tool == 'sigrok_device_info':
            assert out['status'] == 'no_device' and not out['ok'], out
            assert 'PRIVATE_SENTINEL' not in json.dumps(out)
        else: assert '[sigrok_com_failed]' in out['_error']
        def mixed(owner):
            response(owner)
            owner.result.stderr += '\nPermission denied '+PRIVATE
        env.owner_hook = mixed
        out = await invoke(c, env, tool)
        assert '[sigrok_com_failed]' in out['_error']

async def test_target_role_blocks_before_owner(env, isolated_ports):
    route = ports.resolve(S._port_environment(), 'COM7', 'sigrok-serial', probe=S._port_probe(),config=S.rt().config)
    isolated_ports['roles'].mark_target(route, case_id=env.case.id,server='synthetic-uart')
    async with Client(S.server) as c: out = await invoke(c, env)
    assert '[port_role_conflict]' in out['_error'] and not env.owners and not env.manager._leases

@pytest.mark.parametrize('tool', ['sigrok_scan','sigrok_device_info'])
async def test_linux_explicit_ols_uses_modify_gate_and_approval_id(fake, auth, monkeypatch, tool):
    from .test_external_port_lifecycle import fake_probe
    cid = S.rt().cases.create(title='합성 Linux OLS gate',authorization=auth).id
    fake.workspace['set_safety'](modify_policy='approve')
    monkeypatch.setattr(S, '_port_probe', lambda: fake_probe())
    monkeypatch.setattr(S, 'device_users', lambda path: [])
    async with Client(S.server) as c:
        pending = await call(c,tool,case_id=cid,driver='ols',conn='/dev/ttySYNTHETIC')
        assert pending['status']=='approval_required' and not fake.calls(), pending
        aid = pending['approval_id']
        rec = S.rt().approvals.get(aid)
        assert rec['risk']=='modify'
        S.rt().approvals.decide(aid,approve=True,code=rec['code'],via='cli-tty')
        out = await call(c,tool,case_id=cid,driver='ols',conn='/dev/ttySYNTHETIC',approval_id=aid)
        assert out['ok'] and len(fake.calls())==1, out

# 동일 등록 데이터와 실제 Windows owner를 Linux 합성 자식에 연결한다.
from .test_sigrok_windows_runner import setup as info_setup
from .test_sigrok_windows_com_owner import setup as owner_setup

@pytest.mark.parametrize('tool,mode,stdout', [('sigrok_scan','scan',SCAN),('sigrok_device_info','show',SHOW)])
async def test_public_real_owner_registry_copy_child_and_cleanup(env, owner_setup, monkeypatch, tool, mode, stdout):
    setup = owner_setup
    monkeypatch.setattr(W.info,'_resolve_bundle',lambda cfg,**kw:setup.bundle)
    monkeypatch.setattr(W.info,'_runtime_parent',lambda cfg:setup.parent)
    def reserve(bundle,command,**kwargs):
        assert bundle is setup.bundle and env.manager._leases
        return setup.reserve(code='import os;os.write(1,'+repr(stdout)+')',mode=command.mode,conn=command.conn,
                             deadline=kwargs['deadline'])
    monkeypatch.setattr(W,'_reserve',reserve)
    async with Client(S.server) as c:
        out = await invoke(c,env,tool)
    assert out['ok'],out
    assert len(setup.spawns)==1 and setup.spawns[0][0][1:]==['--driver=ols:conn=COM7','--dont-scan','--'+mode]
    assert setup.life.calls and not list(setup.parent.iterdir()) and not env.manager._leases
    assert 'SYNTHETIC\\' not in json.dumps(out)

@pytest.mark.parametrize('stdout', [
    SHOW.replace(b'  Logic analyzer',b'  Logic analyzer\n  PRIVATE_SENTINEL'),
    SHOW.replace(b'  conn',b'  conn\n  PRIVATE_SENTINEL'),
    SHOW+b'PRIVATE_SENTINEL\n',
])
async def test_show_unknown_diagnostic_is_not_projected_as_information(env, stdout):
    env.owner_hook=lambda owner:setattr(owner,'result',replace(owner.result,stdout=stdout))
    async with Client(S.server) as c: out=await invoke(c,env,'sigrok_device_info')
    assert '[sigrok_com_bad_output]' in out['_error'] and 'PRIVATE_SENTINEL' not in out['_error']
