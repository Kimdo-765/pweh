"""Windows dummy 소비자의 합성 수명·게이트 시험. Windows/USB/포트는 열지 않는다."""
from __future__ import annotations

import asyncio
import json
from pathlib import Path
import threading
import time
from types import SimpleNamespace

import pytest
from mcp import Client
from mcp_helpers import call
from openocd_mcp import server as S, windows_start as W, process_windows as PW
from openocd_mcp.session import REGISTRY
from openocd_mcp.tcl import TclReply
from pweh.runtime import get_runtime
from pweh.errors import DeviceError
from .test_openocd_dummy_profile import INTERFACE_BYTES

pytestmark = pytest.mark.anyio

@pytest.fixture
def anyio_backend():
    return 'asyncio'

class FakeClient:
    def __init__(self):
        self.connected = True
        self.commands = []
        self.entered = threading.Event()
        self.release = threading.Event()
        self.block = False
    def call(self, cmd, **kw):
        self.commands.append(cmd)
        self.entered.set()
        if self.block:
            assert self.release.wait(5), '합성 조회 해제 누락'
        return TclReply(0, {'version': 'Open On-Chip Debugger 0.12.0', 'adapter name': 'dummy',
            'targets': ' 0* tst.cpu testee little tst.cpu unknown', 'jtag names': 'tst.cpu'}.get(cmd, ''))
    call_raw = call

class FakeOwner:
    def __init__(self, plan):
        self.client = FakeClient()
        self.layout = plan.layout
        self.confirmed = True
        self.released = False
        self.close_calls = 0
    def wait_ready(self, **kwargs):
        return SimpleNamespace(ready=True, version={'raw': 'Open On-Chip Debugger 0.12.0'})
    def close(self, **kwargs):
        self.close_calls += 1
        self.client.connected = False
        return SimpleNamespace(confirmed=self.confirmed, reason='confirmed' if self.confirmed else 'windows_cleanup_unknown')
    def release_run(self, *, deadline):
        self.released = PW.release_prepared_run(self.layout, deadline=deadline)
        return self.released
    def diagnostics(self):
        return {'fatal_reason': None, 'cleanup_confirmed': self.confirmed}

@pytest.fixture
def env(workspace, auth, tmp_path, monkeypatch):
    r = get_runtime('openocd-mcp')
    case = r.cases.create(title='합성 Windows dummy', authorization=auth)
    root = tmp_path / 'bundle'
    scripts = root / 'openocd/scripts'
    (scripts / 'interface').mkdir(parents=True)
    (scripts / 'interface/dummy.cfg').write_bytes(INTERFACE_BYTES)
    exe = root / 'openocd/bin/openocd.exe'
    exe.parent.mkdir()
    exe.write_bytes(b'synthetic-not-executable')
    bundle = SimpleNamespace(root=root, entrypoint=exe, search_dirs=(scripts,),
        release_id='xpack-0.12.0-7-win32-x64', manifest_sha256='a'*64)
    monkeypatch.setattr(W, '_environment', lambda config: {'kind': 'WSL2_INTEROP', 'wsl': {'interop': {'usable': True}}})
    monkeypatch.setattr(W, '_resolve_bundle', lambda config, deadline: bundle)
    monkeypatch.setattr(W.windows_bundle, 'revalidate_bundle', lambda *a, **kw: None)
    monkeypatch.setattr(W, '_path_converter', lambda p, deadline: 'C:/synthetic' + str(p))
    owners = []
    def spawn(plan, **kw):
        owner = FakeOwner(plan)
        owners.append(owner)
        return owner
    monkeypatch.setattr(PW, 'spawn_windows', spawn)
    yield SimpleNamespace(case=case, runtime=r, bundle=bundle, owners=owners, spawn=spawn)
    for owner in owners:
        owner.confirmed = True
        owner.client.release.set()
    REGISTRY.shutdown_all()
    assert REGISTRY.find(case.id) is None

async def _start(client, env, **extra):
    args = dict(case_id=env.case.id, backend='windows', windows_profile='dummy-noinit-v1',
                interface_cfg='interface/dummy.cfg', tcl_port=0)
    args.update(extra)
    return await call(client, 'openocd_start', **args)

async def test_public_start_queries_status_stop_single_client(env):
    async with Client(S.server) as c:
        result = await _start(c, env)
        assert result.get('ok'), result
        assert result['transport'] == 'windows-pipe' and result['tcl_port'] is None
        assert result['hardware_initialized'] is False
        assert result['semihosting'] == W.SEMIHOSTING
        sess = REGISTRY.get(env.case.id)
        client = sess.client
        for command in sorted(W.QUERIES):
            query = await call(c, 'openocd_command', case_id=env.case.id, command=command)
            assert query['ok'], query
        assert (await call(c, 'openocd_targets', case_id=env.case.id))['ok']
        assert (await call(c, 'openocd_scan_chain', case_id=env.case.id))['ok']
        status = await call(c, 'openocd_status', case_id=env.case.id)
        assert status['active'] and status['hardware_initialized'] is False
        assert sess.client is client and set(client.commands) <= W.QUERIES
        assert len(env.owners) == 1 and sess._uses == 0
        stopped = await call(c, 'openocd_stop', case_id=env.case.id)
        assert stopped['ok'] and not stopped['cleanup_pending'] and env.owners[0].released
        previous = await call(c, 'openocd_status', case_id=env.case.id)
        assert previous['previous_runs'][0]['state'] == 'previous_owner_unverified'
        assert previous['previous_runs'][0]['still_running'] is None

@pytest.mark.parametrize('tool,args', [
    ('openocd_halt', {}), ('openocd_resume', {}), ('openocd_reset', {}),
    ('openocd_read_registers', {}), ('openocd_read_memory', {'address': 0, 'count': 1}),
    ('openocd_dump_memory_start', {'address': 0, 'length': 16}),
    ('openocd_flash_banks', {}), ('openocd_flash_read_start', {'bank': 0}),
    ('openocd_write_memory', {'address': 0, 'values': [0]}),
    ('openocd_flash_write', {'address': 0, 'path': 'not-opened.bin'}),
    *[('openocd_command', {'command': x}) for x in ['init', 'shutdown', 'version; targets',
      'adapter speed 1000', 'capture {version}', 'targets\ninit', 'target names', 'mdw 0', 'flash banks', ' version', 'version\n']],
])
async def test_unsupported_before_rpc_and_job(env, tool, args):
    async with Client(S.server) as c:
        assert (await _start(c, env))['ok']
        result = await call(c, tool, case_id=env.case.id, **args)
        assert '[openocd_windows_unsupported]' in result.get('_error', ''), result
        assert env.owners[0].client.commands == []
        assert env.runtime.jobs.list() == []

@pytest.mark.parametrize('kwargs', [dict(backend='auto'), dict(windows_profile='usb'), dict(tcl_port=6666),
    dict(extra_commands=['noinit']), dict(target_cfg='target/foo.cfg'), dict(ready_timeout=0),
    dict(ready_timeout=float('inf')), dict(ready_timeout=31), dict(backend='linux')])
async def test_closed_start_inputs_have_no_run(env, kwargs):
    async with Client(S.server) as c:
        result = await _start(c, env, **kwargs)
        assert not result.get('ok'), result
        assert env.owners == [] and REGISTRY.find(env.case.id) is None
        assert not list((env.case.dir / 'jtag').glob('openocd-*'))

async def test_unknown_cleanup_retains_session_run_until_explicit_retry(env):
    async with Client(S.server) as c:
        assert (await _start(c, env))['ok']
        owner = env.owners[0]
        owner.confirmed = False
        stopped = await call(c, 'openocd_stop', case_id=env.case.id)
        assert not stopped['ok'] and stopped['cleanup_pending']
        assert owner.layout.root.exists() and REGISTRY.find(env.case.id)
        assert not (await _start(c, env)).get('ok')
        REGISTRY.shutdown_all()
        assert REGISTRY.find(env.case.id) and not owner.released
        owner.confirmed = True
        assert (await call(c, 'openocd_stop', case_id=env.case.id))['ok']
        assert not owner.layout.root.exists()

async def test_gate_denial_never_creates_run_and_fingerprint_stable(env, monkeypatch):
    actions = []
    async def denied(**kw):
        actions.append(kw['action'])
        return SimpleNamespace(allowed=False, status='approval_required', approval_id='synthetic', message=None,
            to_dict=lambda: {'status': 'approval_required', 'allowed': False})
    monkeypatch.setattr(env.runtime, 'authorize', denied)
    async with Client(S.server) as c:
        for _ in range(2):
            assert (await _start(c, env))['status'] == 'approval_required'
        assert actions[0] == actions[1]
        assert actions[0]['profile_sha256'] and actions[0]['bundle_manifest_sha256'] == 'a'*64
        assert 'owner-' not in json.dumps(actions) and str(env.case.dir) not in json.dumps(actions)
        assert env.owners == [] and REGISTRY.find(env.case.id) is None
        assert not list((env.case.dir / 'jtag').glob('openocd-*'))

async def test_query_raw_cancel_keeps_use_until_worker_exits(env):
    async with Client(S.server) as c:
        assert (await _start(c, env))['ok']
        sess = REGISTRY.get(env.case.id)
        owner = env.owners[0]
        owner.client.block = True
        task = asyncio.create_task(W.call_session(sess, 'version', timeout=1))
        assert await asyncio.to_thread(owner.client.entered.wait, 2)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        assert sess._uses == 1
        result = await asyncio.to_thread(W.close_session, sess, timeout=.05)
        assert not result['ok'] and not owner.released and sess._uses == 1
        owner.client.release.set()
        end = time.monotonic() + 2
        while sess._uses and time.monotonic() < end:
            await asyncio.sleep(.01)
        assert sess._uses == 0
        assert (await call(c, 'openocd_stop', case_id=env.case.id))['ok']

async def test_start_raw_cancel_during_spawn_worker_owns_cleanup(env, monkeypatch):
    entered, release = threading.Event(), threading.Event()
    def spawn(plan, **kw):
        entered.set()
        assert release.wait(5)
        return env.spawn(plan, **kw)
    monkeypatch.setattr(PW, 'spawn_windows', spawn)
    task = asyncio.create_task(W.start(env.runtime, env.case, ctx=None, approval_id=None, ready_timeout=3,
        windows_profile='dummy-noinit-v1', interface_cfg='interface/dummy.cfg', tcl_port=0))
    assert await asyncio.to_thread(entered.wait, 2)
    sess = REGISTRY.get(env.case.id)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert sess._uses == 1 and sess.windows_layout.root.exists()
    release.set()
    end = time.monotonic() + 3
    while REGISTRY.find(env.case.id) and time.monotonic() < end:
        await asyncio.sleep(.01)
    assert REGISTRY.find(env.case.id) is None
    assert env.owners[0].released and sess._uses == 0

async def test_start_build_failure_releases_only_prepared_run(env, monkeypatch):
    monkeypatch.setattr(W.WP, 'build_dummy_plan', lambda *a, **kw: (_ for _ in ()).throw(DeviceError('합성 계획 실패')))
    async with Client(S.server) as c:
        result = await _start(c, env)
        assert not result.get('ok') and env.owners == []
        assert REGISTRY.find(env.case.id) is None
        assert not [p for p in (env.case.dir / 'jtag').glob('openocd-*') if p.is_dir()]

async def test_previous_windows_state_never_uses_pid_for_liveness(env, monkeypatch):
    jdir = env.case.subdir('jtag')
    (jdir / 'openocd-1.json').write_text(json.dumps({'transport': 'windows-pipe', 'pid': 1234, 'tcl_port': 1234}))
    monkeypatch.setattr(S.process, 'pid_alive', lambda *a: pytest.fail('Windows 과거 owner의 PID로 확인했다'))
    async with Client(S.server) as c:
        result = await call(c, 'openocd_status', case_id=env.case.id)
        assert result['previous_runs'][0]['still_running'] is None and result['hint'] is None

async def test_environment_disabled_after_gate_prevents_run(env, monkeypatch):
    original = env.runtime.authorize
    async def gate(**kwargs):
        result = await original(**kwargs)
        monkeypatch.setattr(W, '_environment', lambda config: {'kind': 'NATIVE_LINUX'})
        return result
    monkeypatch.setattr(env.runtime, 'authorize', gate)
    async with Client(S.server) as c:
        result = await _start(c, env)
        assert '[openocd_windows_unavailable]' in result.get('_error', ''), result
        assert env.owners == [] and REGISTRY.find(env.case.id) is None

async def test_gate_raw_cancel_removes_placeholder_without_run(env, monkeypatch):
    entered = asyncio.Event()
    async def gate(**kwargs):
        entered.set()
        await asyncio.Event().wait()
    monkeypatch.setattr(env.runtime, 'authorize', gate)
    task = asyncio.create_task(W.start(env.runtime, env.case, ctx=None, approval_id=None, ready_timeout=3,
        windows_profile='dummy-noinit-v1', interface_cfg='interface/dummy.cfg', tcl_port=0))
    await asyncio.wait_for(entered.wait(), 2)
    assert REGISTRY.find(env.case.id)._uses == 1
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert REGISTRY.find(env.case.id) is None and env.owners == []

async def test_query_cancel_before_worker_start_has_no_rpc(env, monkeypatch):
    async with Client(S.server) as c:
        assert (await _start(c, env))['ok']
        sess = REGISTRY.get(env.case.id)
        entered = asyncio.Event()
        saved = []
        async def pending(fn, **kwargs):
            saved.append(fn)
            entered.set()
            await asyncio.Event().wait()
        monkeypatch.setattr(W, 'run_blocking_cancellable', pending)
        task = asyncio.create_task(W.call_session(sess, 'version', timeout=1))
        await asyncio.wait_for(entered.wait(), 2)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        assert sess._uses == 0 and env.owners[0].client.commands == []
        with pytest.raises(DeviceError):
            saved[0]()  # 이미 caller가 회수한 늦은 worker는 전송하지 않는다.
        assert sess._uses == 0

async def test_spawn_error_retains_unknown_owner_and_run(env, monkeypatch):
    def spawn(plan, **kwargs):
        owner = env.spawn(plan, **kwargs)
        owner.confirmed = False
        raise PW.WindowsSpawnError(owner)
    monkeypatch.setattr(PW, 'spawn_windows', spawn)
    async with Client(S.server) as c:
        result = await _start(c, env)
        assert '[windows_spawn_failed]' in result.get('_error', ''), result
        sess = REGISTRY.get(env.case.id)
        assert sess.cleanup_pending and sess.windows_owner is env.owners[0]
        assert sess._uses == 0 and sess.windows_layout.root.exists()
        env.owners[0].confirmed = True
        assert (await call(c, 'openocd_stop', case_id=env.case.id))['ok']

async def test_partial_prepare_handle_preserved_until_cleanup_confirmed(env, monkeypatch):
    opaque = object()
    release_allowed = [False]
    class PartialFailure(DeviceError):
        prepared_run = opaque
    monkeypatch.setattr(PW, 'prepare_windows_run', lambda *a, **kw: (_ for _ in ()).throw(PartialFailure('합성 준비 실패')))
    calls = []
    def release(handle, **kw):
        calls.append(handle)
        return release_allowed[0]
    monkeypatch.setattr(PW, 'release_prepared_run', release)
    async with Client(S.server) as c:
        result = await _start(c, env)
        assert '_error' in result
        sess = REGISTRY.get(env.case.id)
        assert sess.windows_layout is opaque and sess.cleanup_pending and sess._uses == 0
        assert calls == [opaque]
        release_allowed[0] = True
        assert (await call(c, 'openocd_stop', case_id=env.case.id))['ok']
        assert calls == [opaque, opaque]

async def test_stop_raw_cancel_worker_keeps_cleanup_ownership(env, monkeypatch):
    async with Client(S.server) as c:
        assert (await _start(c, env))['ok']
        sess = REGISTRY.get(env.case.id)
        owner = env.owners[0]
        close = owner.close
        entered, release = threading.Event(), threading.Event()
        def blocked(**kwargs):
            entered.set()
            assert release.wait(5)
            return close(**kwargs)
        monkeypatch.setattr(owner, 'close', blocked)
        # 공개 함수의 raw Task.cancel 경계를 호출한다(MCP wrapper는 동일한 worker를 쓴다).
        task = asyncio.create_task(S.openocd_stop.__wrapped__(env.case.id, ctx=None))
        assert await asyncio.to_thread(entered.wait, 2)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        assert REGISTRY.find(env.case.id) is sess and not owner.released
        release.set()
        end = time.monotonic() + 3
        while REGISTRY.find(env.case.id) and time.monotonic() < end:
            await asyncio.sleep(.01)
        assert REGISTRY.find(env.case.id) is None and owner.released

async def test_anyio_scope_cancel_during_gate_cleans_placeholder(env, monkeypatch):
    import anyio
    entered = anyio.Event()
    async def gate(**kwargs):
        entered.set()
        await anyio.sleep_forever()
    monkeypatch.setattr(env.runtime, 'authorize', gate)
    async with anyio.create_task_group() as group:
        async def begin():
            await W.start(env.runtime, env.case, ctx=None, approval_id=None, ready_timeout=3,
                windows_profile='dummy-noinit-v1', interface_cfg='interface/dummy.cfg', tcl_port=0)
        group.start_soon(begin)
        await entered.wait()
        group.cancel_scope.cancel()
    assert REGISTRY.find(env.case.id) is None and env.owners == []
