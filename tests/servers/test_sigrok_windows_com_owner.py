"""고정 COM owner는 합성 Linux 자식과 주입 Windows 관찰만 사용한다."""
import asyncio
import base64
import json
import os
import shutil
import subprocess
import sys
import threading
import time
import traceback
from types import SimpleNamespace

import pytest

from pweh import portlock, wininterop as O, wininterop_sigrok as I
from pweh.sigrok_com import ComCommand, PROFILE_ID
from sigrok_mcp import windows_com as C, windows_runner as W, windows_run as R
from .test_sigrok_windows_runner import setup as info_setup, end, control_factory

pytestmark = pytest.mark.skipif(not sys.platform.startswith('linux'), reason='Linux 합성 interop wrapper')


@pytest.fixture
def setup(info_setup):
    base = info_setup
    owners, spawns = [], []
    fixture = SimpleNamespace(bundle=base.bundle, parent=base.parent, life=base.life,
                              owners=owners, spawns=spawns, allow_preserved=False)
    def reserve(code="import os;os.write(1,b'SYNTHETIC OLS\\n')", *, mode='scan', conn='COM4096', **updates):
        def factory(argv, **kwargs):
            spawns.append((argv, kwargs))
            return subprocess.Popen([sys.executable, '-I', '-c', code], **kwargs)
        kwargs = dict(deadline=end(), lifecycle=base.life, path_converter=base.converter, process_factory=factory)
        kwargs.update(updates)
        owner = C.reserve_com_owner(base.bundle, ComCommand(PROFILE_ID, mode, conn), **kwargs)
        owners.append(owner)
        return owner
    def prepare(*args, **kwargs):
        owner = reserve(*args, **kwargs)
        owner.prepare(base.parent, deadline=owner.deadline)
        return owner
    fixture.reserve, fixture.prepare = reserve, prepare
    yield fixture
    base.life.unknown, base.life.present, base.life.confirm, base.life.on_observe = False, False, True, None
    for owner in owners:
        if owner.close(deadline=end()).confirmed:
            continue
        assert fixture.allow_preserved
        assert owner._execution is None or owner._execution.confirmed
        # 의도한 사본 손상 시험의 합성 기록만 직접 회수한다. 운영 release를 완화하지 않는다.
        record = owner._prepared._record if isinstance(owner._prepared, R.PreparedRun) else owner._prepared
        for entry in record.entries.values():
            if entry.fd is not None:
                os.close(entry.fd)
                entry.fd = None
        if record.parent_fd >= 0:
            os.close(record.parent_fd)
        R._RUNS.pop(record.root, None)
        C._OWNED.pop(owner.token, None)
        for path in record.root.rglob('*'):
            if path.is_dir():
                path.chmod(0o700)
        record.root.chmod(0o700)
        shutil.rmtree(record.root)
    assert not C._OWNED


def test_reserve_has_no_io_and_can_be_bound_before_copy(setup):
    owner = setup.reserve()
    assert C._OWNED[owner.token] is owner and C.owned_process_count() == 1
    assert not list(setup.parent.iterdir()) and not setup.life.calls and not setup.spawns
    assert owner.close(deadline=end()).confirmed
    assert owner.close(deadline=end()).confirmed and not C._OWNED


@pytest.mark.parametrize('mode', ['scan', 'show'])
def test_exact_single_command_and_last_fresh_callback(setup, monkeypatch, mode):
    owner = setup.prepare(mode=mode)
    seen = []
    original = R.revalidate_run
    def revalidate(*args, **kwargs):
        seen.append('revalidate')
        return original(*args, **kwargs)
    monkeypatch.setattr(R, 'revalidate_run', revalidate)
    factory = owner._factory
    def spawn(*args, **kwargs):
        assert seen[-1] == 'fresh'
        seen.append('spawn')
        return factory(*args, **kwargs)
    owner._factory = spawn
    result = owner.run(before_spawn=lambda: seen.append('fresh'), deadline=end())
    assert result.ok and result.stdout == b'SYNTHETIC OLS\n' and result.cleanup_verified
    assert setup.spawns[0][0][1:] == list(owner.command.argv_tail)
    assert setup.spawns[0][1]['shell'] is False and setup.spawns[0][1]['stdin'] == subprocess.DEVNULL
    assert owner._execution.confirmed
    with pytest.raises(C.WindowsComError):
        owner.run(before_spawn=lambda: None, deadline=end())
    assert len(setup.spawns) == 1
    root = owner._prepared.root
    assert str(root) not in json.dumps(owner.metadata())
    assert owner.close(deadline=end()).confirmed and not root.exists()


def test_reservations_are_separate_from_endpoint_lease(setup):
    one, two = setup.reserve(conn='COM1'), setup.reserve(conn='COM2')
    assert one.token != two.token and C.owned_process_count() == 2
    assert not list(setup.parent.iterdir())


@pytest.mark.parametrize('answer', [False, True, 'private'])
def test_before_spawn_requires_none(setup, answer):
    owner = setup.prepare()
    with pytest.raises(C.WindowsComError):
        owner.run(before_spawn=lambda: answer, deadline=end())
    assert not setup.spawns and owner.close(deadline=end()).confirmed


def test_callback_failure_is_closed_error_and_spawn_zero(setup):
    owner = setup.prepare()
    def callback():
        raise ValueError('SYNTHETIC_PRIVATE_ROUTE')
    with pytest.raises(C.WindowsComError) as exc:
        owner.run(before_spawn=callback, deadline=end())
    assert exc.value.owner is owner and not setup.spawns
    assert 'SYNTHETIC_PRIVATE_ROUTE' not in ''.join(traceback.format_exception(exc.value))


@pytest.mark.parametrize('unknown', [False, True])
def test_unowned_preflight_live_or_unknown_preserves_run_without_kill(setup, unknown):
    owner = setup.prepare()
    setup.life.unknown, setup.life.present = unknown, not unknown
    with pytest.raises(C.WindowsComError):
        owner.run(before_spawn=lambda: None, deadline=end())
    assert not setup.spawns and not owner.close(deadline=end()).confirmed
    assert owner._prepared.root.exists() and C._OWNED[owner.token] is owner
    assert all(kind != 'terminate' for kind, _, _ in setup.life.calls)
    setup.life.unknown = setup.life.present = False
    assert owner.close(deadline=end()).confirmed


@pytest.mark.parametrize('copy', [False, True])
def test_query_mutation_blocks_spawn_before_route_callback(setup, copy):
    owner = setup.prepare()
    target = owner._prepared.image if copy else setup.bundle.entrypoint
    def mutate():
        setup.life.on_observe = None
        target.chmod(0o755)
        target.write_bytes(b'private replacement')
    setup.life.on_observe = mutate
    callbacks = []
    with pytest.raises(C.WindowsComError):
        owner.run(before_spawn=lambda: callbacks.append(True), deadline=end())
    assert not setup.spawns and not callbacks
    if copy:
        setup.allow_preserved = True
        assert not owner.close(deadline=end()).confirmed
    else:
        assert owner.close(deadline=end()).confirmed


def test_unknown_windows_cleanup_keeps_owner_and_stops_reuse(setup):
    owner = setup.prepare()
    setup.life.confirm = False
    with pytest.raises(C.WindowsComError) as exc:
        owner.run(before_spawn=lambda: None, deadline=end())
    assert exc.value.code == 'sigrok_com_cleanup_unknown'
    assert owner._execution.wrapper_done and not owner._execution.confirmed
    assert not owner.close(deadline=end()).confirmed
    assert C._OWNED[owner.token] is owner and owner._prepared.root.exists()
    with pytest.raises(C.WindowsComError):
        owner.run(before_spawn=lambda: None, deadline=end())
    assert len(setup.spawns) == 1
    setup.life.confirm = True
    assert owner.close(deadline=end()).confirmed


def test_unknown_owner_keeps_bound_endpoint_lease_until_confirmed(setup, isolated_ports):
    manager = isolated_ports['manager']
    lease = manager.acquire(['win:COM4096'], owner=portlock.PortOwner('synthetic', 'sigrok', 'COM4096'))
    owner = setup.reserve()
    use = SimpleNamespace(cleanup_owner=owner, lease=lease, unverified=True)
    try:
        owner.prepare(setup.parent, deadline=end())
        setup.life.confirm = False
        with pytest.raises(C.WindowsComError):
            owner.run(before_spawn=lambda: None, deadline=end())
        lease.set_state('orphan')
        assert not use.cleanup_owner.close(deadline=end()).confirmed
        with pytest.raises(Exception, match='busy'):
            manager.acquire(['win:COM4096'], owner=portlock.PortOwner('synthetic', 'other', 'COM4096'))
        assert not lease.closed and use.cleanup_owner is C._OWNED[owner.token]
        setup.life.confirm = True
        assert owner.close(deadline=end()).confirmed
    finally:
        lease.close()
    assert manager.held_by('win:COM4096') is None


def test_configure_partial_failure_is_preserved_and_retried(setup, monkeypatch):
    owner = setup.prepare('import time;time.sleep(20)')
    original = W._Execution.configure
    monkeypatch.setattr(W._Execution, 'configure', lambda self: False)
    with pytest.raises(C.WindowsComError) as exc:
        owner.run(before_spawn=lambda: None, deadline=end())
    assert exc.value.code == 'sigrok_com_cleanup_unknown'
    assert owner._execution.proc is not None and not owner._execution.confirmed
    assert not owner.close(deadline=end(.1)).confirmed
    monkeypatch.setattr(W._Execution, 'configure', original)
    assert owner.close(deadline=end()).confirmed


@pytest.mark.parametrize('stream', [1, 2])
def test_bounded_output_failure_cleans_both_owners(setup, monkeypatch, stream):
    monkeypatch.setattr(W, 'STDOUT_BYTES', 32)
    monkeypatch.setattr(W, 'STDERR_BYTES', 32)
    owner = setup.prepare(f'import os;os.write({stream},b"x"*1024)')
    with pytest.raises(C.WindowsComError) as exc:
        owner.run(before_spawn=lambda: None, deadline=end())
    assert exc.value.code == 'sigrok_com_output_limit'
    assert owner._execution.confirmed
    assert len(owner._execution.stdout) <= 32 and len(owner._execution.stderr) <= 32


@pytest.mark.parametrize('code', [
    'import time;time.sleep(20)',
    'import signal,time;signal.signal(signal.SIGTERM,signal.SIG_IGN);time.sleep(20)',
    'import os,signal,time;p=os.fork();signal.signal(signal.SIGTERM,signal.SIG_IGN);os._exit(0) if p else time.sleep(20)',
])
def test_timeout_finishes_wrapper_group_and_windows_generation(setup, code):
    owner = setup.prepare(code)
    with pytest.raises(C.WindowsComError) as exc:
        owner.run(before_spawn=lambda: None, deadline=end(), timeout_s=.15)
    assert exc.value.code == 'sigrok_com_timeout'
    assert owner._execution.confirmed and owner._execution.proc.returncode is not None
    assert setup.life.calls[-1][0] == 'terminate'


def test_cancellation_after_spawn_finishes_child(setup):
    owner = setup.prepare('import time;time.sleep(20)')
    with pytest.raises(C.WindowsComError) as exc:
        owner.run(before_spawn=lambda: None, deadline=end(), cancel=lambda: bool(setup.spawns))
    assert exc.value.code == 'sigrok_com_cancelled' and owner._execution.confirmed


@pytest.mark.parametrize('raw_cancel', [False, True])
def test_partial_prepare_error_keeps_opaque_record(setup, monkeypatch, raw_cancel):
    original = R.prepare_run
    def partial(*args, **kwargs):
        prepared = original(*args, **kwargs)
        exc = asyncio.CancelledError() if raw_cancel else R.WindowsRunError('sigrok_run_failed', prepared)
        exc.prepared_run = prepared
        raise exc
    monkeypatch.setattr(R, 'prepare_run', partial)
    owner = setup.reserve()
    with pytest.raises(C.WindowsComError) as exc:
        owner.prepare(setup.parent, deadline=end())
    assert exc.value.owner is owner and C._OWNED[owner.token] is owner
    assert owner._prepared.root.exists() and owner.close(deadline=end()).confirmed


def test_close_cancels_active_operation_then_releases(setup):
    owner = setup.prepare('import time;time.sleep(20)')
    errors = []
    def run():
        try:
            owner.run(before_spawn=lambda: None, deadline=end())
        except C.WindowsComError as exc:
            errors.append(exc.code)
    thread = threading.Thread(target=run)
    thread.start()
    deadline = end()
    while not setup.spawns and time.monotonic() < deadline:
        time.sleep(.005)
    assert owner.close(deadline=end()).confirmed
    thread.join(2)
    assert not thread.is_alive() and errors == ['sigrok_com_cancelled']


def test_post_execution_unknown_tree_is_preserved(setup):
    owner = setup.prepare()
    def confirmation(*args, **kwargs):
        (owner._prepared.empty / 'private extra').write_bytes(b'private')
        return True
    setup.life.terminate_and_confirm = confirmation
    with pytest.raises(C.WindowsComError):
        owner.run(before_spawn=lambda: None, deadline=end())
    assert not owner.close(deadline=end()).confirmed
    setup.allow_preserved = True


@pytest.mark.parametrize('value', [0, -1, 61, float('inf'), float('nan'), True, '1', 10**400])
def test_invalid_cli_timeout_is_spawn_zero(setup, value):
    owner = setup.prepare()
    with pytest.raises(C.WindowsComError):
        owner.run(before_spawn=lambda: None, deadline=end(), timeout_s=value)
    assert not setup.spawns


def test_module_cap_uses_one_overall_deadline(setup, monkeypatch):
    seen = []
    original = R.revalidate_run
    def revalidate(prepared, *, deadline, cancel=None):
        assert deadline - time.monotonic() <= 45
        seen.append(deadline)
        return original(prepared, deadline=deadline, cancel=cancel)
    monkeypatch.setattr(R, 'revalidate_run', revalidate)
    overall = end(119)
    owner = setup.prepare(deadline=overall)
    assert owner.run(before_spawn=lambda: None, deadline=overall).ok
    assert seen and max(seen) <= overall
    assert all(deadline - time.monotonic() <= 30 for _, _, deadline in setup.life.calls)
    assert C._timeout(None, 'scan') == 45 and C._timeout(None, 'show') == 60


def request(tail):
    image = r'C:\synthetic\sigrok-cli.exe'
    row = dict(pid=12, image=image, creation='1000', cmd=subprocess.list2cmdline([image, *tail]), wait_ms=10)
    data = base64.b64encode(json.dumps(row).encode()).decode()
    return I.TERMINATE_SCRIPT_TEMPLATE.replace('__REQUEST__', data)


@pytest.mark.parametrize('mode', ['scan', 'show'])
def test_fixed_control_admission_is_separate_from_information(mode):
    tail = ComCommand(PROFILE_ID, mode, 'COM4096').argv_tail
    assert C._script_cap(request(tail), end()) == 1024
    with pytest.raises(W.WindowsInfoError):
        W._script_cap(request(tail), end())
    for bad in (('--version',), ('--list-supported',), ('--scan',), (*tail, '--output-file=private')):
        with pytest.raises(C.WindowsComError):
            C._script_cap(request(bad), end())


def test_control_only_fixed_queries_and_bounded_capture():
    calls = []
    runner = C.FixedComRunner(process_factory=control_factory('import os;os.write(1,b"{}")', calls),
                              powershell_provider=lambda: '/synthetic/powershell.exe')
    assert runner(I.QUERY_SCRIPT, end()) == b'{}'
    for bad in (O.QUERY_SCRIPT, 'Stop-Process -Id 1', I.QUERY_SCRIPT + '\n'):
        with pytest.raises(C.WindowsComError):
            runner(bad, end())
    assert len(calls) == 1 and not runner.pending
    assert base64.b64decode(calls[0][-1]).decode('utf-16le') == I.QUERY_SCRIPT


def test_pending_control_blocks_new_spawn_until_natural_completion(tmp_path):
    flag = tmp_path / 'finish'
    code = f'import pathlib,time,os\np=pathlib.Path({str(flag)!r})\nwhile not p.exists(): time.sleep(.01)\nos.write(1,b"{{}}")'
    calls = []
    runner = C.FixedComRunner(process_factory=control_factory(code, calls), powershell_provider=lambda: '/synthetic/powershell.exe')
    try:
        with pytest.raises(C.WindowsComError):
            runner(I.QUERY_SCRIPT, end(.1))
        with pytest.raises(C.WindowsComError):
            runner(I.QUERY_SCRIPT, end(.1))
        assert runner.pending and len(calls) == 1
    finally:
        flag.touch()
        assert runner.settle(deadline=end())
    assert not runner.pending


def test_control_path_output_overflow_is_not_a_partial_path():
    calls = []
    runner = C.FixedComRunner(process_factory=control_factory('import os;os.write(1,b"x"*9000)', calls))
    with pytest.raises(C.WindowsComError):
        runner.convert_path(__import__('pathlib').Path('/synthetic/path'), end())
    assert len(calls) == 1 and not runner.pending
