"""고정 Tigard 소비자. 합성 PnP graph·pipe만 쓰며 Windows/장치를 실행하지 않는다."""
from __future__ import annotations

import asyncio
import json
import threading
import time
from types import SimpleNamespace

import pytest
from mcp import Client
from mcp_helpers import call
from openocd_mcp import server as S, windows_start as W, windows_tigard as T, process_windows as PW, semihosting
from openocd_mcp.session import REGISTRY
from pweh import portlock
from pweh.errors import Busy, DeviceError
from pweh.runtime import get_runtime
from .test_openocd_tigard_profile import INTERFACE_BYTES
from .test_openocd_windows_dummy import FakeOwner, FakeClient

pytestmark = pytest.mark.anyio
PARENT = r'USB\VID_0403&PID_6010\SYNTHETIC'
MI = r'USB\VID_0403&PID_6010&MI_01\SYNTHETIC'

@pytest.fixture
def anyio_backend():
    return 'asyncio'


def document():
    nodes = [dict(instance_id=PARENT, parent=r'HTREE\ROOT\0', parent_state='ok', com=None, pnp_class='USB'),
             dict(instance_id=MI, parent=PARENT, parent_state='ok', com='COM31', pnp_class='Ports')]
    return dict(schema='pweh.pnp-usb-scope/v1', snapshots=[dict(present_count=2, nodes=nodes, errors=[]) for _ in range(2)])


class ClientStub(FakeClient):
    def __init__(self):
        super().__init__()
        self.guard_bad = False
        self.guard_target = False
    def call(self, cmd, **kw):
        reply = super().call(cmd, **kw)
        if cmd.startswith('pweh_semihosting_guard '):
            phase = cmd.rsplit(' ', 1)[-1]
            phases = ('pre-init', 'post-init', 'verify') if phase == 'verify' else (phase,)
            text = '\n'.join('PWEH-SEMIHOSTING done ' + x for x in phases)
            if self.guard_bad:
                text = 'PWEH-SEMIHOSTING done pre-init'
            if self.guard_target:
                text += '\nPWEH-SEMIHOSTING off unexpected.cpu'
            return type(reply)(0, text)
        return type(reply)(0, 'Open On-Chip Debugger 0.12.0' if cmd == 'version' else '')
    call_raw = call


@pytest.fixture
def env(workspace, auth, tmp_path, monkeypatch):
    r = get_runtime('openocd-mcp')
    case = r.cases.create(title='합성 Tigard', authorization=auth)
    root = tmp_path / 'bundle'
    scripts = root / 'openocd/scripts'
    (scripts / 'interface/ftdi').mkdir(parents=True)
    (scripts / 'interface/ftdi/tigard.cfg').write_bytes(INTERFACE_BYTES)
    exe = root / 'openocd/bin/openocd.exe'
    exe.parent.mkdir()
    exe.write_bytes(b'synthetic-not-executable')
    bundle = SimpleNamespace(root=root, entrypoint=exe, search_dirs=(scripts,),
        release_id='xpack-0.12.0-7-win32-x64', manifest_sha256='a'*64)
    state = SimpleNamespace(case=case, runtime=r, bundle=bundle, owners=[], doc=document(), phases=[],
                            guard_bad=False, guard_target=False, log='')
    monkeypatch.setattr(W, '_environment', lambda config: {'kind':'WSL2_INTEROP','wsl':{'interop':{'usable':True}}})
    monkeypatch.setattr(W, '_resolve_bundle', lambda *a: bundle)
    monkeypatch.setattr(W.windows_bundle, 'revalidate_bundle', lambda *a, **k: None)
    monkeypatch.setattr(W, '_path_converter', lambda p, deadline: 'C:/synthetic' + str(p))
    monkeypatch.setattr(T.windows_usb, '_read_scope', lambda *a, **k: json.dumps(state.doc).encode())
    def guard(runtime, scope, *, consumer, phase):
        state.phases.append(phase)
    monkeypatch.setattr(T.instrument_guard, 'guard_target_usb_scope', guard)
    def spawn(plan, **kw):
        assert kw['profile_id'] == 'tigard-jtag-v1'
        assert kw['before_spawn']() is None
        owner = FakeOwner(plan)
        owner.client = ClientStub()
        owner.client.guard_bad, owner.client.guard_target = state.guard_bad, state.guard_target
        kw['log_path'].write_text(state.log)
        state.owners.append(owner)
        return owner
    monkeypatch.setattr(PW, 'spawn_windows', spawn)
    state.spawn = spawn
    yield state
    for owner in state.owners:
        owner.confirmed = True
        owner.client.release.set()
    REGISTRY.shutdown_all()
    assert REGISTRY.find(case.id) is None


async def start(c, env, **extra):
    args=dict(case_id=env.case.id, backend='windows', windows_profile='tigard-jtag-v1',
              interface_cfg='interface/ftdi/tigard.cfg', tcl_port=0)
    args.update(extra)
    return await call(c, 'openocd_start', **args)


def conflict():
    return portlock.get_manager().acquire(('win:COM31',), owner=portlock.PortOwner('synthetic-other','other','COM31'))


async def test_public_single_client_guard_and_whole_lease(env):
    async with Client(S.server) as c:
        result=await start(c,env)
        assert result.get('ok'),result
        assert result['hardware_initialized'] and not result['target_communication_verified']
        assert not result['target_configured'] and result['targets']==[]
        assert result['semihosting']['mode']=='fixed-adapter-init'
        assert result['health']=='ok' and result['usb_scope']=='whole-device'
        sess=REGISTRY.get(env.case.id)
        assert sess.client.commands==[semihosting.VERIFY_CALL]
        with pytest.raises(Busy): conflict()
        for command in ('version','scan_chain','targets'):
            assert (await call(c,'openocd_command',case_id=env.case.id,command=command))['ok']
        status=await call(c,'openocd_status',case_id=env.case.id)
        assert status['target_communication_verified'] is False
        assert status['semihosting_live']['status']=='reported'
        assert semihosting.STATUS_CALL in sess.client.commands
        assert sess._uses==0 and env.phases[:2]==['preflight','before-spawn'] and 'rpc' in env.phases
        assert (await call(c,'openocd_stop',case_id=env.case.id))['ok']
        lease=conflict();lease.close()


async def test_init_ok_preserves_degraded_errors(env):
    env.log='Error: JTAG scan chain interrogation failed: all ones\nWarn : no enabled taps. AUTO PROBING MIGHT NOT WORK!!\n'
    async with Client(S.server) as c:
        out=await start(c,env)
        assert out['ok'] and out['health']=='degraded' and out['startup']['errors']
        assert out['warnings'] and out['target_communication_verified'] is False
        status=await call(c,'openocd_status',case_id=env.case.id)
        assert status['health']=='degraded' and status['startup']==out['startup']


@pytest.mark.parametrize('kwargs',[dict(target_cfg='target/synthetic.cfg'),dict(extra_commands=['init']),
    dict(adapter_speed_khz=1000),dict(transport='swd'),dict(tcl_port=6666),dict(ready_timeout=0)])
async def test_closed_inputs_before_scope_gate_run(env,kwargs):
    async with Client(S.server) as c:
        out=await start(c,env,**kwargs)
        assert not out.get('ok') and env.phases==[] and env.owners==[]
        assert not list((env.case.dir/'jtag').glob('openocd-*'))


@pytest.mark.parametrize('tool,args',[
    ('openocd_command',{'command':'adapter name'}),('openocd_command',{'command':'jtag names'}),
    ('openocd_command',{'command':semihosting.VERIFY_CALL}),('openocd_command',{'command':'version; targets'}),
    ('openocd_halt',{}),('openocd_read_registers',{}),('openocd_read_memory',{'address':0,'count':1}),
    ('openocd_flash_banks',{}),('openocd_dump_memory_start',{'address':0,'length':16}),
    ('openocd_flash_read_start',{'bank':0})])
async def test_unsupported_has_no_rpc_or_job(env,tool,args):
    async with Client(S.server) as c:
        assert (await start(c,env))['ok']
        before=list(env.owners[0].client.commands)
        out=await call(c,tool,case_id=env.case.id,**args)
        assert '[openocd_windows_unsupported]' in out.get('_error',''),out
        assert env.owners[0].client.commands==before and env.runtime.jobs.list()==[]


@pytest.mark.parametrize('field',['guard_bad','guard_target'])
async def test_guard_or_target0_failure_closes_and_releases(env,field):
    setattr(env,field,True)
    async with Client(S.server) as c:
        out=await start(c,env)
        assert '[openocd_tigard_guard_failed]' in out.get('_error',''),out
        assert REGISTRY.find(env.case.id) is None and env.owners[0].released
        lease=conflict();lease.close()


async def test_existing_com_lease_blocks_before_gate_spawn(env):
    lease=conflict()
    try:
        async with Client(S.server) as c:
            out=await start(c,env)
            assert not out.get('ok') and env.owners==[]
    finally: lease.close()


async def test_approval_holds_lease_and_changed_scope_never_spawns(env,monkeypatch):
    original=env.runtime.authorize
    actions=[]
    async def authorize(**kwargs):
        actions.append(kwargs['action'])
        with pytest.raises(Busy):conflict()
        assert not list((env.case.dir/'jtag').glob('openocd-*'))
        for snap in env.doc['snapshots']:
            snap['nodes'][1]['com']='COM32'
        return await original(**kwargs)
    monkeypatch.setattr(env.runtime,'authorize',authorize)
    async with Client(S.server) as c:
        out=await start(c,env)
        assert not out.get('ok') and not env.owners
        assert actions[0]['whole_device'] and actions[0]['profile_sha256']
        assert actions[0]['claim_keys'] and actions[0]['usb_scope_sha256']
        assert 'owner-' not in json.dumps(actions)
        lease=conflict();lease.close()


async def test_fresh_rpc_change_preserves_old_lease_and_stop_works(env):
    async with Client(S.server) as c:
        assert (await start(c,env))['ok']
        before=list(env.owners[0].client.commands)
        for snap in env.doc['snapshots']: snap['nodes'][1]['com']='COM32'
        out=await call(c,'openocd_command',case_id=env.case.id,command='version')
        assert not out.get('ok') and env.owners[0].client.commands==before
        with pytest.raises(Busy): conflict()
        assert (await call(c,'openocd_stop',case_id=env.case.id))['ok']


async def test_unknown_cleanup_retains_whole_lease_until_retry(env):
    async with Client(S.server) as c:
        assert (await start(c,env))['ok']
        env.owners[0].confirmed=False
        out=await call(c,'openocd_stop',case_id=env.case.id)
        assert out['cleanup_pending']
        with pytest.raises(Busy):conflict()
        env.owners[0].confirmed=True
        assert (await call(c,'openocd_stop',case_id=env.case.id))['ok']
        lease=conflict();lease.close()


async def test_raw_cancel_preflight_worker_holds_until_completion(env,monkeypatch):
    entered,release=threading.Event(),threading.Event()
    original=T.instrument_guard.guard_target_usb_scope
    def blocked(*a,**kw):
        if kw['phase']=='preflight':
            entered.set(); assert release.wait(5)
        return original(*a,**kw)
    monkeypatch.setattr(T.instrument_guard,'guard_target_usb_scope',blocked)
    task=asyncio.create_task(T.start(env.runtime,env.case,ctx=None,approval_id=None,ready_timeout=1,
        windows_profile='tigard-jtag-v1',interface_cfg='interface/ftdi/tigard.cfg',tcl_port=0))
    while not entered.is_set():await asyncio.sleep(.01)
    task.cancel()
    await asyncio.sleep(.03)
    with pytest.raises(Busy):conflict()
    assert not env.owners
    release.set()
    with pytest.raises(asyncio.CancelledError):await task
    for _ in range(100):
        if REGISTRY.find(env.case.id) is None:break
        await asyncio.sleep(.01)
    assert REGISTRY.find(env.case.id) is None
    lease=conflict();lease.close()


async def test_raw_cancel_foreground_use_blocks_lease_release(env):
    async with Client(S.server) as c:
        assert (await start(c,env))['ok']
        sess=REGISTRY.get(env.case.id)
        sess.client.block=True;sess.client.entered.clear()
        task=asyncio.create_task(W.call_session(sess,'version',timeout=5))
        while not sess.client.entered.is_set():await asyncio.sleep(.01)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):await task
        out=await asyncio.to_thread(W.close_session,sess,timeout=.05)
        assert out['cleanup_pending'] and sess._uses==1
        with pytest.raises(Busy):conflict()
        sess.client.release.set()
        for _ in range(100):
            if not sess._uses:break
            await asyncio.sleep(.01)
        assert (await asyncio.to_thread(W.close_session,sess))['ok']


async def test_gate_required_returns_without_run_and_releases(env,monkeypatch):
    from pweh.safety.gate import GateDecision
    async def gate(**kwargs):
        with pytest.raises(Busy):conflict()
        return GateDecision(False,'approval_required',kwargs['classification'],'approve',approval_id='synthetic-approval')
    monkeypatch.setattr(env.runtime,'authorize',gate)
    async with Client(S.server) as c:
        out=await start(c,env)
        assert out['status']=='approval_required' and env.owners==[]
        assert REGISTRY.find(env.case.id) is None
        assert not list((env.case.dir/'jtag').glob('openocd-*'))
        lease=conflict();lease.close()


async def test_internal_guard_rpc_uses_same_cancel_lifetime(env):
    async with Client(S.server) as c:
        assert (await start(c,env))['ok']
        sess=REGISTRY.get(env.case.id)
        sess.client.block=True;sess.client.entered.clear()
        task=asyncio.create_task(S._semihosting_live(sess))
        while not sess.client.entered.is_set():await asyncio.sleep(.01)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):await task
        assert sess._uses==1
        assert not (await asyncio.to_thread(W.close_session,sess,timeout=.05))['ok']
        with pytest.raises(Busy):conflict()
        sess.client.release.set()
        for _ in range(100):
            if not sess._uses:break
            await asyncio.sleep(.01)
        assert (await asyncio.to_thread(W.close_session,sess))['ok']


from .test_openocd_windows_process import setup as owner_setup
_REAL_SPAWN = PW.spawn_windows

@pytest.mark.parametrize('owner_setup',['tigard'],indirect=True)
async def test_public_real_owner_linux_pipe_and_registered_bundle(owner_setup,workspace,auth,tmp_path,monkeypatch):
    """등록 번들 검증·계획·실제 owner·단일 pipe까지 Linux 합성 자식에 연결한다."""
    import subprocess
    import sys
    from pathlib import Path
    r=get_runtime('openocd-mcp')
    case=r.cases.create(title='합성 실제 owner 연결',authorization=auth)
    source=Path(__file__).with_name('fake_openocd_pipe.py').read_text()
    source=source.replace('Path(__file__).with_name("fake_openocd.py")',
                          repr(str(Path(__file__).with_name('fake_openocd.py'))))
    needle='''            if name != "version" or values:
                raise TclError("unsupported fixture command")'''
    replacement='''            if name == "pweh_semihosting_guard" and len(values) == 1:
                phases = ("pre-init", "post-init", "verify") if values[0] == "verify" else (values[0],)
                return "\\n".join("PWEH-SEMIHOSTING done " + phase for phase in phases)
            if name in ("targets", "scan_chain") and not values:
                return ""
            if name != "version" or values:
                raise TclError("unsupported fixture command")'''
    assert needle in source
    child=tmp_path/'synthetic-child.py';child.write_text(source.replace(needle,replacement))
    monkeypatch.setattr(W,'_environment',lambda config:{'kind':'WSL2_INTEROP','wsl':{'interop':{'usable':True}}})
    monkeypatch.setattr(W,'_resolve_bundle',lambda *a:owner_setup.bundle)
    # case run은 fixture tmp 밖이므로 고정 합성 Windows 경로로만 변환한다.
    converter=lambda path,deadline:'C:/SYNTHETIC'+str(path)
    monkeypatch.setattr(W,'_path_converter',converter)
    monkeypatch.setattr(T.windows_usb,'_read_scope',lambda *a,**kw:json.dumps(document()).encode())
    def factory(argv,**kwargs):
        owner_setup.spawns.append(argv)
        return subprocess.Popen([sys.executable,'-I',str(child)],**kwargs)
    def spawn(plan,**kwargs):
        kwargs.update(process_factory=factory,lifecycle=owner_setup.life)
        owner=_REAL_SPAWN(plan,**kwargs)
        owner_setup.owners.append(owner)
        return owner
    monkeypatch.setattr(PW,'spawn_windows',spawn)
    try:
        async with Client(S.server) as c:
            out=await start(c,SimpleNamespace(case=case),ready_timeout=5)
            assert out.get('ok'),out
            assert len(owner_setup.spawns)==1
            for command in ('version','scan_chain','targets'):
                assert (await call(c,'openocd_command',case_id=case.id,command=command))['ok']
            assert (await call(c,'openocd_status',case_id=case.id))['semihosting_live']['status']=='reported'
            assert (await call(c,'openocd_stop',case_id=case.id))['ok']
            assert owner_setup.life.calls==['observe','terminate']
    finally:
        REGISTRY.shutdown_all()


async def test_status_guard_violation_closes_real_scope_without_public_modify(env):
    async with Client(S.server) as c:
        assert (await start(c,env))['ok']
        owner=env.owners[0]
        owner.client.guard_target=True
        out=await call(c,'openocd_status',case_id=env.case.id)
        assert out['semihosting_live']['status']=='reported'
        assert out['semihosting_failsafe']['stop_method']=='windows-confirmed'
        assert semihosting.CHECK_CALL in owner.client.commands
        assert REGISTRY.find(env.case.id) is None
        lease=conflict();lease.close()


async def test_fresh_spent_deadline_does_not_send(env,monkeypatch):
    from pweh.errors import TimeoutExpired
    async with Client(S.server) as c:
        assert (await start(c,env))['ok']
        sess=REGISTRY.get(env.case.id)
        before=list(sess.client.commands)
        monkeypatch.setattr(T,'fresh',lambda *a,**kw:time.sleep(.03))
        with pytest.raises(TimeoutExpired):await W.call_session(sess,'version',timeout=.01)
        assert sess.client.commands==before and sess._uses==0


async def test_verify_expired_deadline_sends_nothing(env):
    from pweh.errors import TimeoutExpired
    async with Client(S.server) as c:
        assert (await start(c,env))['ok']
        sess=REGISTRY.get(env.case.id)
        before=list(sess.client.commands)
        with pytest.raises(TimeoutExpired):T._verify_start(sess,deadline=time.monotonic()-1)
        assert sess.client.commands==before


async def test_spawn_spent_deadline_skips_wait_ready(env,monkeypatch):
    waited=[]
    def spawn(plan,**kwargs):
        owner=env.spawn(plan,**kwargs)
        owner.wait_ready=lambda **kw:waited.append(kw)
        time.sleep(.03)
        return owner
    monkeypatch.setattr(PW,'spawn_windows',spawn)
    async with Client(S.server) as c:
        out=await start(c,env,ready_timeout=.02)
        assert not out.get('ok') and waited==[]
        assert REGISTRY.find(env.case.id) is None
