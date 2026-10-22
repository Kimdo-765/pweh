"""Windows 대신 합성 Linux 자식·주입 snapshot으로 시험하는 두 정보 명령 owner."""
import base64
from dataclasses import replace
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import threading
import time
import traceback
from types import SimpleNamespace

import pytest

from pweh import windows_bundle as B, wininterop_sigrok as WI
from sigrok_mcp import windows_runner as W, windows_run as R

pytestmark = pytest.mark.skipif(not sys.platform.startswith('linux'), reason='Linux 합성 interop wrapper')


def end(seconds=10):
    return time.monotonic() + seconds


def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':')) + '\n').encode()


class Lifecycle:
    def __init__(self):
        self.calls = []
        self.unknown = False
        self.present = False
        self.confirm = True
        self.on_observe = None

    def observe(self, launch, *, deadline):
        self.calls.append(('observe', launch, deadline))
        if self.on_observe:
            self.on_observe()
        if self.unknown:
            raise ValueError('SYNTHETIC_PRIVATE')
        if self.present:
            return (WI.SigrokIdentity(12, launch.image, '1000', subprocess.list2cmdline([launch.image, *launch.argv_tail])),)
        return ()

    def terminate_and_confirm(self, launch, observed, *, deadline):
        self.calls.append(('terminate', launch, deadline))
        return self.confirm


@pytest.fixture
def setup(tmp_path, monkeypatch):
    data = {'sigrok-cli.exe': b'SYNTHETIC NONEXECUTABLE', 'python34.dll': b'SYNTHETIC DLL',
            'python34.zip': b'SYNTHETIC ZIP', 'share/libsigrokdecode/decoders/example/pd.py': b'# synthetic',
            'share/sigrok-firmware/example.fw': b'synthetic'}
    rid = R.RELEASE_ID
    doc = {'schema_version': 1, 'tool': 'sigrok', 'release_id': rid, 'platform': 'windows-amd64',
           'source': {'artifact_url': 'https://example.invalid/synthetic.exe', 'artifact_name': 'synthetic.exe',
                      'artifact_size': 1, 'artifact_sha256': 'a' * 64, 'digest_basis': 'first-acquisition',
                      'checksum_metadata': None, 'extractor': {'version': '1', 'artifact_url': 'https://example.invalid/extractor.tar',
                        'artifact_size': 1, 'artifact_sha256': 'b' * 64, 'executable_sha256': 'c' * 64}},
           'payload': {'archive_root': '', 'recipe': 'nsis-selected-v1', 'entrypoint': 'sigrok-cli.exe',
                       'search_dirs': ['share/libsigrokdecode/decoders', 'share/sigrok-firmware'], 'python_zip': 'python34.zip',
                       'file_count': len(data), 'total_bytes': sum(map(len, data.values())),
                       'excluded': {'installer_plugins': 0, 'usb_driver_installers': 0, 'example_captures': 0, 'uninstaller': 0}},
           'files': [{'path': p, 'size': len(v), 'sha256': hashlib.sha256(v).hexdigest()} for p, v in sorted(data.items())],
           'known_limitations': ['authenticode_unverified']}
    raw = canonical(doc)
    index = json.loads(B._read_registry_bytes())
    index['tools']['sigrok'] = {'preferred_release_id': rid, 'releases': [
        {'release_id': rid, 'manifest': f'windows-bundles/sigrok-{rid}.json', 'sha256': hashlib.sha256(raw).hexdigest()}]}
    monkeypatch.setattr(B, '_read_registry_bytes', lambda: canonical(index))
    monkeypatch.setattr(B, '_read_registered_manifest_bytes', lambda _: raw)
    root = tmp_path / 'release'
    for name, value in data.items():
        target = root / 'payload' / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(value)
        target.chmod(0o555 if name.endswith('.exe') else 0o444)
    manifest = B.load_registered_manifest('sigrok', deadline=end())
    (root / 'release.json').write_bytes(manifest.receipt_bytes)
    (root / 'release.json').chmod(0o444)
    for directory in [p for p in root.rglob('*') if p.is_dir()] + [root]:
        directory.chmod(0o555)
    bundle = B.verify_release(root, 'sigrok', deadline=end())
    parent = tmp_path / 'runs'
    parent.mkdir(mode=0o700)
    life, owners, spawns = Lifecycle(), [], []
    def converter(path, deadline):
        assert deadline - time.monotonic() <= 30
        return 'C:\\SYNTHETIC\\' + '\\'.join(path.relative_to(tmp_path).parts)
    def prepare(code="import os;os.write(1,b'SYNTHETIC INFO\\n')", **updates):
        def factory(argv, **kwargs):
            spawns.append((argv, kwargs))
            return subprocess.Popen([sys.executable, '-I', '-c', code], **kwargs)
        kwargs = dict(deadline=end(), lifecycle=life, path_converter=converter, process_factory=factory)
        kwargs.update(updates)
        try:
            owner = W.prepare_info(bundle, parent, **kwargs)
        except W.WindowsInfoError as exc:
            if exc.owner is not None and exc.owner not in owners:
                owners.append(exc.owner)
            raise
        owners.append(owner)
        return owner
    fixture = SimpleNamespace(bundle=bundle, parent=parent, life=life, prepare=prepare, owners=owners,
                              spawns=spawns, converter=converter, allow_preserved=False)
    yield fixture
    life.unknown, life.present, life.confirm, life.on_observe = False, False, True, None
    for owner in owners:
        result = owner.close(deadline=end())
        if not result.confirmed:
            assert fixture.allow_preserved
            # 의도한 사본 손상 시험만 합성 FD/기록을 회수한다. 운영 정리 조건은 바꾸지 않는다.
            assert all(e.confirmed for e in owner._executions)
            record = owner._prepared._record if isinstance(owner._prepared, R.PreparedRun) else owner._prepared
            for entry in record.entries.values():
                if entry.fd is not None:
                    os.close(entry.fd)
                    entry.fd = None
            if record.parent_fd >= 0:
                os.close(record.parent_fd)
            R._RUNS.pop(record.root, None)
            W._OWNED.pop(owner.token, None)
            for path in record.root.rglob('*'):
                if path.is_dir():
                    path.chmod(0o700)
            record.root.chmod(0o700)
            shutil.rmtree(record.root)
    assert not W._OWNED


def test_same_copy_two_generations_cleanup_then_release(setup):
    owner = setup.prepare()
    root = owner._prepared.root
    first = owner.run('version', deadline=end())
    second = owner.run('list', deadline=end())
    assert first.ok and second.ok and first.stdout == b'SYNTHETIC INFO\n'
    assert first.process_token != second.process_token
    assert setup.spawns[0][0][0] == setup.spawns[1][0][0]
    assert [x[0][-1] for x in setup.spawns] == ['--version', '--list-supported']
    assert all(x[1]['stdin'] == subprocess.DEVNULL and x[1]['shell'] is False for x in setup.spawns)
    assert len(owner._executions) == 2 and all(e.confirmed for e in owner._executions)
    assert owner.close(deadline=end()).confirmed and not root.exists()
    assert owner.close(deadline=end()).confirmed
    assert str(root) not in json.dumps(owner.metadata())


@pytest.mark.parametrize('modes', [('list', 'version'), ('version', 'version'), ('version', 'list', 'list')])
def test_only_the_fixed_sequence_is_allowed(setup, modes):
    owner = setup.prepare()
    for mode in modes[:-1]:
        assert owner.run(mode, deadline=end()).ok
    with pytest.raises(W.WindowsInfoError):
        owner.run(modes[-1], deadline=end())
    assert len(setup.spawns) == len(modes) - 1


def test_active_owner_blocks_new_copy(setup):
    owner = setup.prepare()
    with pytest.raises(W.WindowsInfoError) as exc:
        setup.prepare()
    assert exc.value.code == 'sigrok_windows_busy'
    assert len(list(setup.parent.iterdir())) == 1 and not setup.spawns
    assert W._OWNED[owner.token] is owner


def test_unknown_windows_cleanup_blocks_second_and_new_request(setup):
    owner = setup.prepare()
    setup.life.confirm = False
    with pytest.raises(W.WindowsInfoError) as exc:
        owner.run('version', deadline=end())
    assert exc.value.code == 'sigrok_windows_cleanup_unknown'
    assert owner._executions[0].wrapper_done
    with pytest.raises(W.WindowsInfoError):
        owner.run('list', deadline=end())
    with pytest.raises(W.WindowsInfoError):
        setup.prepare()
    assert len(setup.spawns) == 1 and owner._prepared.root.exists()
    setup.life.confirm = True
    assert owner.close(deadline=end()).confirmed
    other = setup.prepare()
    assert other.run('list', deadline=end()).ok


@pytest.mark.parametrize('unknown', [False, True])
def test_preflight_existing_or_unknown_image_is_not_killed_or_released(setup, unknown):
    owner = setup.prepare()
    setup.life.unknown = unknown
    setup.life.present = not unknown
    with pytest.raises(W.WindowsInfoError):
        owner.run('version', deadline=end())
    assert not setup.spawns
    assert not owner.close(deadline=end()).confirmed
    assert owner._prepared.root.exists()
    assert all(kind != 'terminate' for kind, _, _ in setup.life.calls)
    setup.life.unknown = setup.life.present = False
    assert owner.close(deadline=end()).confirmed


@pytest.mark.parametrize('copy', [False, True])
def test_query_time_source_or_copy_change_is_spawn_zero(setup, copy):
    owner = setup.prepare()
    target = owner._prepared.image if copy else setup.bundle.entrypoint
    def mutate():
        setup.life.on_observe = None
        target.chmod(0o755)
        target.write_bytes(b'PRIVATE replacement bytes')
    setup.life.on_observe = mutate
    with pytest.raises(W.WindowsInfoError):
        owner.run('version', deadline=end())
    assert not setup.spawns
    if copy:
        setup.allow_preserved = True
        assert not owner.close(deadline=end()).confirmed
    else:
        assert owner.close(deadline=end()).confirmed


def test_new_file_after_execution_is_preserved_not_returned(setup):
    owner = setup.prepare()
    def confirmation(launch, observed, *, deadline):
        (owner._prepared.empty / 'PRIVATE unknown').write_bytes(b'private')
        return True
    setup.life.terminate_and_confirm = confirmation
    with pytest.raises(W.WindowsInfoError):
        owner.run('version', deadline=end())
    assert not owner.close(deadline=end()).confirmed
    setup.allow_preserved = True


@pytest.mark.parametrize('stream', [1, 2])
def test_stream_output_limit_is_fixed_and_cleaned(setup, monkeypatch, stream):
    monkeypatch.setattr(W, 'STDOUT_BYTES', 32)
    monkeypatch.setattr(W, 'STDERR_BYTES', 32)
    owner = setup.prepare(f'import os;os.write({stream},b"x"*1024)')
    with pytest.raises(W.WindowsInfoError) as exc:
        owner.run('version', deadline=end())
    assert exc.value.code == 'sigrok_windows_output_limit'
    assert owner._executions[0].confirmed
    assert len(owner._executions[0].stdout) <= 32 and len(owner._executions[0].stderr) <= 32


@pytest.mark.parametrize('code', [
    'import time;time.sleep(20)',
    'import signal,time;signal.signal(signal.SIGTERM,signal.SIG_IGN);time.sleep(20)',
    'import os,signal,time;p=os.fork();signal.signal(signal.SIGTERM,signal.SIG_IGN);os._exit(0) if p else time.sleep(20)',
])
def test_timeout_kills_owned_wrapper_group_before_windows_confirmation(setup, code):
    owner = setup.prepare(code)
    with pytest.raises(W.WindowsInfoError) as exc:
        owner.run('version', deadline=end(.15))
    assert exc.value.code == 'sigrok_windows_timeout'
    assert owner._executions[0].confirmed and owner._executions[0].proc.returncode is not None
    assert setup.life.calls[-1][0] == 'terminate'


def test_cancel_after_spawn_and_callback_failure_are_fixed(setup):
    owner = setup.prepare('import time;time.sleep(20)')
    with pytest.raises(W.WindowsInfoError) as exc:
        owner.run('version', deadline=end(), cancel=lambda: bool(setup.spawns))
    assert exc.value.code == 'sigrok_windows_cancelled' and owner._executions[0].confirmed
    assert owner.close(deadline=end()).confirmed
    other = setup.prepare()
    def broken():
        raise RuntimeError('SYNTHETIC_PRIVATE')
    with pytest.raises(W.WindowsInfoError) as exc:
        other.run('version', deadline=end(), cancel=broken)
    assert 'SYNTHETIC_PRIVATE' not in ''.join(traceback.format_exception(exc.value))


def test_prepare_partial_failure_keeps_owner_and_handle(setup, monkeypatch):
    original = R.prepare_run
    def partial(*args, **kwargs):
        prepared = original(*args, **kwargs)
        raise R.WindowsRunError('sigrok_run_failed', prepared)
    monkeypatch.setattr(R, 'prepare_run', partial)
    with pytest.raises(W.WindowsInfoError) as exc:
        setup.prepare()
    owner = exc.value.owner
    assert owner is W._OWNED[owner.token] and owner._prepared.root.exists()
    assert owner.close(deadline=end()).confirmed


def test_raw_async_cancel_during_preparation_preserves_strong_owner(setup, monkeypatch):
    import asyncio
    original = R.prepare_run
    def cancelled(*args, **kwargs):
        prepared = original(*args, **kwargs)
        failure = asyncio.CancelledError()
        failure.prepared_run = prepared
        raise failure
    monkeypatch.setattr(R, 'prepare_run', cancelled)
    with pytest.raises(W.WindowsInfoError) as exc:
        setup.prepare()
    assert W._OWNED[exc.value.owner.token] is exc.value.owner
    assert exc.value.owner.close(deadline=end()).confirmed


def test_close_cancels_active_run_and_waits_for_operation_owner(setup):
    owner = setup.prepare('import time;time.sleep(20)')
    errors = []
    def run():
        try:
            owner.run('version', deadline=end())
        except W.WindowsInfoError as exc:
            errors.append(exc.code)
    thread = threading.Thread(target=run)
    thread.start()
    deadline = end()
    while not setup.spawns and time.monotonic() < deadline:
        time.sleep(.005)
    assert owner.close(deadline=end()).confirmed
    thread.join(2)
    assert not thread.is_alive() and errors == ['sigrok_windows_cancelled']


def test_module_deadlines_are_capped_without_extending_whole_request(setup, monkeypatch):
    seen = []
    original = R.revalidate_run
    def check(prepared, *, deadline, cancel=None):
        seen.append(deadline)
        assert deadline - time.monotonic() <= 45
        return original(prepared, deadline=deadline, cancel=cancel)
    monkeypatch.setattr(R, 'revalidate_run', check)
    overall = end(89)
    owner = setup.prepare(deadline=overall)
    assert owner.run('version', deadline=overall).ok
    assert seen and max(seen) <= overall
    assert all(value - time.monotonic() <= 30 for _, _, value in setup.life.calls)


def test_nonzero_status_is_internal_result_not_cleanup_failure(setup):
    owner = setup.prepare('import os;os.write(2,b"decoder error");raise SystemExit(1)')
    result = owner.run('list', deadline=end())
    assert result.returncode == 1 and result.cleanup_verified and result.stderr == 'decoder error'


def control_factory(code, calls):
    def factory(argv, **kwargs):
        calls.append(argv)
        return subprocess.Popen([sys.executable, '-I', '-c', code], **kwargs)
    return factory


def test_control_allows_only_sigrok_fixed_script_and_no_openocd_queries():
    from pweh import wininterop as O
    calls = []
    runner = W.FixedWindowsRunner(process_factory=control_factory('import os;os.write(1,b"{}")', calls),
                                  powershell_provider=lambda: '/synthetic/powershell.exe')
    assert runner(WI.QUERY_SCRIPT, end()) == b'{}'
    for bad in (O.QUERY_SCRIPT, 'Stop-Process -Id 1', WI.QUERY_SCRIPT + '\n'):
        with pytest.raises(W.WindowsInfoError):
            runner(bad, end())
    assert len(calls) == 1 and not runner.pending
    assert calls[0][-2] == '-EncodedCommand'
    assert base64.b64decode(calls[0][-1]).decode('utf-16le') == WI.QUERY_SCRIPT


def test_control_fixed_termination_template_validates_identity():
    requests = []
    probe = WI.SigrokOwnedProcessProbe(runner=lambda script, deadline: requests.append(script) or b'{"complete":true,"items":[]}')
    launch = WI.SigrokLaunch(r'C:\synthetic\sigrok-cli.exe', ('--version',))
    row = {'pid': 12, 'image': launch.image, 'creation': '1000', 'cmd': subprocess.list2cmdline([launch.image, '--version']), 'wait_ms': 10}
    encoded = base64.b64encode(json.dumps(row).encode()).decode()
    assert W._script_cap(WI.TERMINATE_SCRIPT_TEMPLATE.replace('__REQUEST__', encoded), end()) == 1024
    row['cmd'] = subprocess.list2cmdline([launch.image, '--scan'])
    encoded = base64.b64encode(json.dumps(row).encode()).decode()
    with pytest.raises(W.WindowsInfoError):
        W._script_cap(WI.TERMINATE_SCRIPT_TEMPLATE.replace('__REQUEST__', encoded), end())
    row['image'] = r'C:\openocd.exe'
    encoded = base64.b64encode(json.dumps(row).encode()).decode()
    with pytest.raises(W.WindowsInfoError):
        W._script_cap(WI.TERMINATE_SCRIPT_TEMPLATE.replace('__REQUEST__', encoded), end())


def test_control_timeout_keeps_pending_and_prevents_second_spawn(tmp_path):
    flag = tmp_path / 'finish'
    code = f'import pathlib,time,os\np=pathlib.Path({str(flag)!r})\nwhile not p.exists(): time.sleep(.01)\nos.write(1,b"{{}}")'
    calls = []
    runner = W.FixedWindowsRunner(process_factory=control_factory(code, calls), powershell_provider=lambda: '/synthetic/powershell.exe')
    try:
        with pytest.raises(W.WindowsInfoError):
            runner(WI.QUERY_SCRIPT, end(.1))
        with pytest.raises(W.WindowsInfoError):
            runner(WI.QUERY_SCRIPT, end(.1))
        assert runner.pending and len(calls) == 1
    finally:
        flag.touch()
        assert runner.settle(deadline=end())
    assert not runner.pending


def test_control_output_overflow_never_returns_partial():
    calls = []
    runner = W.FixedWindowsRunner(process_factory=control_factory('import os;os.write(1,b"x"*9000)', calls))
    with pytest.raises(W.WindowsInfoError):
        runner.convert_path(Path('/synthetic/path'), end())
    assert not runner.pending and len(calls) == 1
