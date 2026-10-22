"""Windows 정보 소비자의 MCP·오류·취소 경계. 실제 Windows/장치에는 접근하지 않는다."""
from __future__ import annotations

import asyncio
from dataclasses import replace
import json
from pathlib import Path
import subprocess
import sys
import threading
import time
from types import SimpleNamespace

import anyio
import pytest
from mcp import Client
from mcp_helpers import call
from pweh.errors import PwehError
from sigrok_mcp import cli, server as S, windows_info as W
from .test_sigrok_mcp import fake  # 기존 Linux 합성 fixture도 같은 시험에서 사용한다.
from .test_sigrok_windows_runner import setup as owner_setup

pytestmark = pytest.mark.anyio

@pytest.fixture
def anyio_backend():
    return 'asyncio'

VERSION = b'''sigrok-cli 0.7.2
Using libsigrok 0.5.2 (libsigrokdecode 0.5.3)
- libsigrok 0.5.2/4:0:0 (rt: 0.5.2/4:0:0).
- libsigrokdecode 0.5.3/4:0:0 (rt: 0.5.3/4:0:0).
  - Python 3.4.4/64-bit.
'''
SUPPORTED = b'''Supported hardware drivers:
  demo Demo device
  korad-kaxxxxp Output device
Supported input formats:
  vcd VCD
Supported output formats:
  csv CSV
Supported transform modules:
  scale Scale
Supported protocol decoders:
  uart UART
  spi SPI
'''
PRIVATE = r'C:\PRIVATE_SENTINEL\sigrok-copy\share\libsigrokdecode\decoders\signature\pd.py'
DECODER_ERROR = 'Traceback (most recent call last):\n  File "'+PRIVATE+'", line 138\nSyntaxError: invalid syntax\nFailed to load protocol decoder signature\n'

class FakeOwner:
    def __init__(self):
        self.results = {'version': cli.CliResult(['PRIVATE_SENTINEL', '--version'], 0, VERSION, ''),
                        'list': cli.CliResult(['PRIVATE_SENTINEL', '--list-supported'], 0, SUPPORTED, '')}
        self.modes = []
        self.deadlines = []
        self.close_called = False
        self.confirmed = True
        self.block_mode = None
        self.block_close = False
        self.entered, self.release, self.done = threading.Event(), threading.Event(), threading.Event()
    def run(self, mode, *, deadline, cancel):
        self.modes.append(mode)
        self.deadlines.append(deadline)
        if mode == self.block_mode:
            self.entered.set()
            assert self.release.wait(5), '합성 worker 해제 누락'
        result = self.results[mode]
        if isinstance(result, Exception):
            raise result
        return result
    def close(self, *, deadline):
        self.close_called = True
        if self.block_close:
            self.entered.set()
            assert self.release.wait(5), '합성 정리 해제 누락'
        self.done.set()
        return SimpleNamespace(confirmed=self.confirmed, reason='confirmed' if self.confirmed else 'unknown')

@pytest.fixture
def env(workspace, tmp_path, monkeypatch):
    bundle = SimpleNamespace(entrypoint=tmp_path/'original/sigrok-cli.exe',
        release_id='sigrok-cli-0.7.2-win64-selected', manifest_sha256='a'*64,
        digest_basis='first-acquisition-sha256', known_limitations=('signature-python34-syntax',))
    owner = FakeOwner()
    prepares = []
    resolves = []
    monkeypatch.setattr(W, '_environment', lambda config: {'kind': 'WSL2_INTEROP', 'wsl': {'interop': {'usable': True}}})
    def resolve(config, **kw):
        resolves.append(kw)
        return bundle
    monkeypatch.setattr(W, '_resolve_bundle', resolve)
    monkeypatch.setattr(W, '_runtime_parent', lambda config: tmp_path)
    def prepare(actual, parent, **kw):
        prepares.append((actual, parent, kw))
        assert actual is bundle and isinstance(kw['ambient_env'], tuple)
        return owner
    monkeypatch.setattr(W, '_prepare_info', prepare)
    old_cache = dict(cli._CACHE)
    yield SimpleNamespace(bundle=bundle, owner=owner, prepares=prepares, resolves=resolves)
    owner.release.set()
    assert cli._CACHE == old_cache

async def test_public_version_and_list_metadata_filters_no_cache(env):
    async with Client(S.server) as c:
        result = await call(c, 'sigrok_version', backend='windows')
        assert result['ok'] and result['status'] == 'ok', result
        assert result['backend'] == 'windows' and result['sigrok_cli'] == '0.7.2'
        assert result['counts'] == {'drivers': 2, 'input_formats': 1, 'output_formats': 1, 'transforms': 1, 'decoders': 2}
        assert result['path'] == str(env.bundle.entrypoint) and result['bundle']['manifest_sha256'] == 'a'*64
        assert result['list_complete'] is True and env.owner.close_called
        assert env.owner.modes == ['version', 'list'] and len(env.prepares) == 1
        rows = await call(c, 'sigrok_list', backend='windows', kind='drivers')
        assert rows['ok'] and rows['count'] == 2 and rows['items'][0]['capture_allowed']
        assert not rows['items'][1]['capture_allowed']
        assert 'Windows' in rows['note']
        one = await call(c, 'sigrok_list', backend='windows', kind='decoders', query='UART')
        assert [x['id'] for x in one['items']] == ['uart']
        all_rows = await call(c, 'sigrok_list', backend='windows', kind='all', query='SPI')
        assert [x['id'] for x in all_rows['decoders']] == ['spi'] and all_rows['drivers'] == []
        assert 'PRIVATE_SENTINEL' not in json.dumps([result, rows, one, all_rows])
        # 같은 공개 호출을 다시 실행하며 Linux 정보 캐시를 사용하지 않는다.
        await call(c, 'sigrok_version', backend='windows')
        assert len(env.prepares) == 5 and len(env.resolves) == 5

@pytest.mark.parametrize('kind', ['drivers', 'decoders', 'all', 'input-formats'])
async def test_decoder_only_version_partial_but_every_list_kind_fails(env, kind):
    env.owner.results['list'].stderr = DECODER_ERROR
    async with Client(S.server) as c:
        result = await call(c, 'sigrok_version', backend='windows')
        assert result['ok'] and result['status'] == 'partial'
        assert result['counts'] is None and result['list_complete'] is False
        assert result['problems'] == ['sigrok_decoder_exception', 'sigrok_no_decoder']
        assert 'PRIVATE_SENTINEL' not in json.dumps(result) and 'Traceback' not in json.dumps(result)
        failed = await call(c, 'sigrok_list', backend='windows', kind=kind, query='demo')
        assert '[sigrok_decoder_exception]' in failed['_error']
        assert 'PRIVATE_SENTINEL' not in failed['_error'] and 'Traceback' not in failed['_error']
        assert env.owner.close_called

@pytest.mark.parametrize('field,value,code', [
    ('cleanup_verified', False, 'sigrok_windows_cleanup_unknown'),
    ('cancelled', True, 'cancelled'), ('timed_out', True, 'timeout'),
    ('output_limit_hit', True, 'sigrok_windows_output_limit'),
    ('returncode', 7, 'sigrok_failed'), ('stdout', b'garbage', 'sigrok_bad_output'),
    ('stdout', b'\xff', 'sigrok_bad_output'),
    ('stderr', DECODER_ERROR+'Permission denied PRIVATE_SENTINEL', 'sigrok_failed'),
])
@pytest.mark.parametrize('mode,stage', [('version', 'version'), ('version', 'list'), ('list', 'list')])
async def test_failure_priority_never_turns_into_partial(env, mode, stage, field, value, code):
    current = env.owner.results[stage]
    if field != 'stderr':
        current = replace(current, stderr=DECODER_ERROR if stage == 'list' else '')
    env.owner.results[stage] = replace(current, **{field: value})
    async with Client(S.server) as c:
        result = await call(c, 'sigrok_'+mode, backend='windows')
        # list는 decoder fatal 자체를 반환한다. version 후속 목록에서만 validparse를 검사한다.
        if mode == 'list' and field == 'stdout':
            code = 'sigrok_decoder_exception'
        assert '['+code+']' in result.get('_error', ''), result
        assert 'PRIVATE_SENTINEL' not in result['_error'] and 'Traceback' not in result['_error']
        assert env.owner.close_called

@pytest.mark.parametrize('mode', ['version', 'list'])
async def test_cleanup_failure_overrides_valid_or_partial_output(env, mode):
    env.owner.confirmed = False
    env.owner.results['list'].stderr = DECODER_ERROR
    async with Client(S.server) as c:
        result = await call(c, 'sigrok_'+mode, backend='windows')
        assert '[sigrok_windows_cleanup_unknown]' in result['_error']
        assert 'PRIVATE_SENTINEL' not in result['_error']

@pytest.mark.parametrize('tool', ['sigrok_version', 'sigrok_list'])
@pytest.mark.parametrize('backend', ['auto', 'Windows', 'windows ', 'PRIVATE_SENTINEL'])
async def test_invalid_backend_no_owner_or_linux_fallback(env, monkeypatch, tool, backend):
    monkeypatch.setattr(S, '_cli', lambda: pytest.fail('Linux fallback'))
    async with Client(S.server) as c:
        result = await call(c, tool, backend=backend)
        assert '[validation_failed]' in result['_error'] and 'PRIVATE_SENTINEL' not in result['_error']
        assert env.prepares == [] and env.resolves == []

async def test_bundle_error_is_fixed_and_no_fallback(env, monkeypatch):
    def bad(*a, **kw):
        raise PwehError('PRIVATE_SENTINEL', code='bundle_tree_invalid', data={'path': PRIVATE})
    monkeypatch.setattr(W, '_resolve_bundle', bad)
    monkeypatch.setattr(S, '_cli', lambda: pytest.fail('Linux fallback'))
    async with Client(S.server) as c:
        result = await call(c, 'sigrok_version', backend='windows')
        assert '[bundle_tree_invalid]' in result['_error'] and 'PRIVATE_SENTINEL' not in result['_error']
        assert not env.prepares

async def test_prepare_exception_preserves_owner_for_cleanup(env, monkeypatch):
    class PreparationError(Exception):
        owner = env.owner
    monkeypatch.setattr(W, '_prepare_info', lambda *a, **kw: (_ for _ in ()).throw(PreparationError(PRIVATE)))
    async with Client(S.server) as c:
        result = await call(c, 'sigrok_version', backend='windows')
        assert '[sigrok_windows_failed]' in result['_error'] and 'PRIVATE_SENTINEL' not in result['_error']
        assert env.owner.close_called

async def test_raw_cancel_while_running_leaves_cleanup_with_worker(env):
    env.owner.block_mode = 'version'
    task = asyncio.create_task(S.sigrok_version.__wrapped__(backend='windows'))
    assert await asyncio.to_thread(env.owner.entered.wait, 2)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert not env.owner.close_called
    env.owner.release.set()
    assert await asyncio.to_thread(env.owner.done.wait, 2)
    assert env.owner.close_called and env.owner.modes == ['version']

async def test_raw_cancel_while_closing_does_not_abandon_owner(env):
    env.owner.block_close = True
    task = asyncio.create_task(S.sigrok_version.__wrapped__(backend='windows'))
    assert await asyncio.to_thread(env.owner.entered.wait, 2)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert env.owner.close_called and not env.owner.done.is_set()
    env.owner.release.set()
    assert await asyncio.to_thread(env.owner.done.wait, 2)

async def test_anyio_cancel_has_same_worker_cleanup(env):
    env.owner.block_mode = 'version'
    async with anyio.create_task_group() as group:
        async def invoke():
            await S.sigrok_version.__wrapped__(backend='windows')
        group.start_soon(invoke)
        assert await asyncio.to_thread(env.owner.entered.wait, 2)
        group.cancel_scope.cancel()
    assert not env.owner.close_called
    env.owner.release.set()
    assert await asyncio.to_thread(env.owner.done.wait, 2)

async def test_already_cancelled_worker_never_prepares(env):
    event = threading.Event()
    event.set()
    with pytest.raises(PwehError) as caught:
        W.run_info('version', S.rt().config, cancel_event=event)
    assert caught.value.code == 'cancelled' and env.prepares == [] and env.resolves == []

async def test_environment_not_available_never_prepares(env, monkeypatch):
    monkeypatch.setattr(W, '_environment', lambda c: {'kind': 'NATIVE_LINUX'})
    async with Client(S.server) as c:
        result = await call(c, 'sigrok_list', backend='windows')
        assert '[sigrok_windows_unavailable]' in result['_error']
        assert env.prepares == [] and env.resolves == []

async def test_linux_default_explicit_and_other_tools_never_use_windows(fake, monkeypatch):
    monkeypatch.setattr(W, 'run_info', lambda *a, **kw: pytest.fail('Windows worker 범위 밖 호출'))
    async with Client(S.server) as c:
        first = await call(c, 'sigrok_version')
        calls = len(fake.calls())
        second = await call(c, 'sigrok_version', backend='linux')
        assert first == second and len(fake.calls()) == calls
        assert 'backend' not in first and 'status' not in first
        default = await call(c, 'sigrok_list', kind='drivers', query='demo')
        explicit = await call(c, 'sigrok_list', kind='drivers', query='demo', backend='linux')
        assert default == explicit and len(fake.calls()) == calls
        assert (await call(c, 'sigrok_decoder_help', decoder='uart'))['ok']
        assert (await call(c, 'sigrok_scan'))['ok']

@pytest.mark.parametrize('existing', ['missing', 'valid', 'symlink', 'mode'])
def test_runtime_parent_fixed_location_and_no_existing_chmod(tmp_path, monkeypatch, existing):
    parent = tmp_path / 'runtime'
    paths = []
    def path(value):
        paths.append(value)
        return parent
    monkeypatch.setattr(W, 'Path', path)
    if existing == 'symlink':
        target = tmp_path / 'outside'
        target.mkdir(mode=0o700)
        parent.symlink_to(target, target_is_directory=True)
    elif existing in ('valid', 'mode'):
        parent.mkdir(mode=0o700 if existing == 'valid' else 0o755)
    if existing in ('symlink', 'mode'):
        with pytest.raises(PwehError):
            W._runtime_parent(None)
        if existing == 'mode':
            assert parent.stat().st_mode & 0o777 == 0o755
    else:
        assert W._runtime_parent(None) == parent
        assert parent.stat().st_mode & 0o777 == 0o700
    assert paths == [f'/tmp/pweh-sigrok-{W.os.getuid()}']

@pytest.mark.parametrize('owner_code,public_code', [
    ('sigrok_windows_timeout', 'timeout'), ('sigrok_windows_cancelled', 'cancelled'),
    ('sigrok_windows_busy', 'sigrok_windows_busy'),
    ('sigrok_windows_output_limit', 'sigrok_windows_output_limit'),
    ('sigrok_windows_cleanup_unknown', 'sigrok_windows_cleanup_unknown'),
])
@pytest.mark.parametrize('stage', ['prepare', 'version', 'list'])
async def test_owner_fixed_error_aliases_never_become_partial(env, monkeypatch, stage, owner_code, public_code):
    # owner의 실제 고정 오류형과 내부 소유 참조를 사용한다. 외부 실행은 없다.
    from sigrok_mcp.windows_runner import WindowsInfoError
    failure = WindowsInfoError(env.owner, code=owner_code)
    failure.message = PRIVATE  # 소비자가 알려진 code 외 원문을 복사하지 않는지 확인한다.
    if stage == 'prepare':
        monkeypatch.setattr(W, '_prepare_info', lambda *a, **kw: (_ for _ in ()).throw(failure))
    else:
        env.owner.results[stage] = failure
    async with Client(S.server) as c:
        result = await call(c, 'sigrok_version', backend='windows')
        assert '['+public_code+']' in result['_error']
        assert 'PRIVATE_SENTINEL' not in result['_error'] and env.owner.close_called


@pytest.mark.parametrize('decoder_failure', [False, True])
async def test_public_mcp_real_owner_synthetic_child_chain(workspace, owner_setup, monkeypatch, decoder_failure):
    """등록 사본·owner·공개 MCP를 연결하되 실행 자식은 합성 Linux Python뿐이다."""
    monkeypatch.setattr(W, '_environment', lambda c: {'kind': 'WSL2_INTEROP', 'wsl': {'interop': {'usable': True}}})
    monkeypatch.setattr(W, '_resolve_bundle', lambda *a, **kw: owner_setup.bundle)
    monkeypatch.setattr(W, '_runtime_parent', lambda c: owner_setup.parent)
    commands = []

    def factory(argv, **kwargs):
        command = argv[-1]
        commands.append(command)
        assert command in ('--version', '--list-supported')
        stdout = VERSION if command == '--version' else SUPPORTED
        stderr = DECODER_ERROR.encode() if decoder_failure and command == '--list-supported' else b''
        code = f'import os;os.write(1,{stdout!r});os.write(2,{stderr!r})'
        return subprocess.Popen([sys.executable, '-I', '-c', code], **kwargs)

    def prepare(bundle, parent, **kwargs):
        assert bundle is owner_setup.bundle and parent == owner_setup.parent
        return owner_setup.prepare(process_factory=factory, **kwargs)

    monkeypatch.setattr(W, '_prepare_info', prepare)
    async with Client(S.server) as client:
        result = await call(client, 'sigrok_version', backend='windows')
        assert result['ok'] and result['sigrok_cli'] == '0.7.2', result
        assert result['status'] == ('partial' if decoder_failure else 'ok')
        assert (result['counts'] is None) is decoder_failure
        listing = await call(client, 'sigrok_list', backend='windows', kind='drivers')
        if decoder_failure:
            assert '[sigrok_decoder_exception]' in listing['_error']
        else:
            assert listing['ok'] and listing['count'] == 2
        assert 'PRIVATE_SENTINEL' not in json.dumps([result, listing])
    assert commands == ['--version', '--list-supported', '--list-supported']
    assert not list(owner_setup.parent.iterdir())
