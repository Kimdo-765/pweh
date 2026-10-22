"""Windows/COM 대신 합성 등록 tree와 Linux 자식만 쓰는 출력 owner 시험."""
import asyncio
import base64
from dataclasses import replace
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import threading
import time
import traceback
from types import SimpleNamespace
import zipfile

import pytest

from pweh import portlock, safeio, wininterop_sigrok as I
from pweh.sigrok_capture import CaptureCommand, CaptureChannel, PROFILE_ID
from sigrok_mcp import windows_capture as C, windows_capture_output as O
from sigrok_mcp import windows_runner as W, windows_com as Q, windows_run as R
from .test_sigrok_windows_runner import setup as info_setup, end, control_factory

pytestmark = pytest.mark.skipif(not sys.platform.startswith('linux'), reason='Linux 합성 Windows wrapper')
COMMAND = CaptureCommand(PROFILE_ID, 'COM4096', 1_000_000, 4, (CaptureChannel(0, '0'),))


def archive():
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, 'w') as z:
        z.writestr('version', '2')
        z.writestr('metadata', '[global]\nsigrok version=0.5.2\n\n[device 1]\ncapturefile=logic-1\ntotal probes=1\nsamplerate=1 MHz\ntotal analog=0\nprobe1=0\nunitsize=4\n')
        z.writestr('logic-1-1', b'\0\0\0\0\1\0\0\0' * 2)
    return stream.getvalue()


@pytest.fixture
def setup(info_setup):
    base = info_setup
    owners, spawns = [], []
    base.owners = owners
    base.spawns = spawns
    # 가져온 fixture의 teardown에는 별도 owner 목록을 넘기지 않는다.
    def reserve(code=None, *, command=COMMAND, **updates):
        def factory(argv, **kwargs):
            spawns.append((argv, kwargs))
            path = owner._output.path
            program = code
            if program is None:
                program = 'from pathlib import Path;Path(' + repr(str(path)) + ').write_bytes(' + repr(archive()) + ')'
            else:
                program = program.replace('OUTPUT_PATH', repr(str(path)))
            return subprocess.Popen([sys.executable, '-I', '-c', program], **kwargs)
        kwargs = dict(deadline=end(), lifecycle=base.life, path_converter=base.converter, process_factory=factory)
        kwargs.update(updates)
        owner = C.reserve_capture_owner(base.bundle, command, **kwargs)
        owners.append(owner)
        return owner
    def prepare(*args, **kwargs):
        owner = reserve(*args, **kwargs)
        owner.prepare(base.parent, deadline=owner.deadline)
        return owner
    base.reserve, base.prepare = reserve, prepare
    base.allow_preserved = False
    yield base
    base.life.unknown, base.life.present, base.life.confirm, base.life.on_observe = False, False, True, None
    for owner in owners:
        if owner.close(deadline=end()).confirmed:
            continue
        assert base.allow_preserved, '의도한 pending 출력만 시험에서 직접 회수한다'
        assert owner._execution is None or owner._execution.confirmed
        output = owner._output
        if output is not None:
            for attr in ('fd', 'dir_fd', 'parent_fd'):
                fd = getattr(output, attr)
                if fd is not None:
                    os.close(fd)
                    setattr(output, attr, None)
            if output.root.exists():
                shutil.rmtree(output.root)
        if owner._prepared is not None and not R.release_run(owner._prepared, deadline=end()):
            record = owner._prepared._record if isinstance(owner._prepared, R.PreparedRun) else owner._prepared
            for entry in record.entries.values():
                if entry.fd is not None:
                    os.close(entry.fd)
                    entry.fd = None
            if record.parent_fd >= 0:
                os.close(record.parent_fd)
            R._RUNS.pop(record.root, None)
            for path in record.root.rglob('*'):
                if path.is_dir():
                    path.chmod(0o700)
            record.root.chmod(0o700)
            shutil.rmtree(record.root)
        C._OWNED.pop(owner.token, None)
    assert not C._OWNED
    # info_setup의 closure owners는 비었으며 정보 registry 역시 비어 있어야 한다.


def publish(source, *, exit, deadline, cancel):
    source.check()
    digest = safeio.hash_fd(source.fd, source.size, algorithms=('sha256',), check=source.check)['sha256']
    receipt = C.CapturePublication('published', 'signals/synthetic.sr', 'A-0001', source.size, digest,
                                   exit.cancelled or exit.timed_out,
                                   'cancelled' if exit.cancelled else 'timeout' if exit.timed_out else None)
    source.on_commit(receipt)
    return receipt


def run(owner, **kw):
    return owner.run(before_spawn=lambda: None, deadline=owner.deadline, **kw)


def test_reserve_is_io_free_and_close_is_idempotent(setup):
    owner = setup.reserve()
    assert C._OWNED[owner.token] is owner and not list(setup.parent.iterdir())
    assert not setup.spawns and not setup.life.calls and not owner.processes_quiescent
    assert owner.close(deadline=end()).confirmed and owner.close(deadline=end()).confirmed


def test_same_fd_publication_then_output_and_run_cleanup(setup):
    owner = setup.prepare()
    root, outroot = owner._prepared.root, owner._output.root
    assert outroot.parent == root.parent and outroot != root and not owner._output.path.exists()
    result = run(owner)
    assert owner.processes_quiescent and result.returncode == 0
    assert not owner.close(deadline=end()).confirmed  # 미게시 출력은 자동 삭제하지 않는다.
    receipt = owner.finalize_output(publish, deadline=end())
    assert receipt is owner.publication and receipt.size == len(archive())
    assert setup.spawns[0][0][1:] == list(COMMAND.argv_tail(owner._output.windows_path))
    assert owner.close(deadline=end()).confirmed and not root.exists() and not outroot.exists()


def test_core_inspection_uses_borrowed_fd_without_reopen(setup):
    from pweh.sigrok_srzip import inspect_capture_fd
    owner = setup.prepare()
    run(owner)
    inspections = []
    def checked(source, **kwargs):
        before = os.lseek(source.fd, 0, os.SEEK_CUR)
        inspections.append(inspect_capture_fd(source.fd, size=source.size, command=COMMAND,
                           deadline=kwargs['deadline'], check=source.check))
        assert os.lseek(source.fd, 0, os.SEEK_CUR) == before
        return publish(source, **kwargs)
    owner.finalize_output(checked, deadline=end())
    assert inspections[0].crc_verified and inspections[0].samples == 4


@pytest.mark.parametrize('code,reason', [('pass', 'missing'), ('from pathlib import Path;Path(OUTPUT_PATH).touch()', 'empty')])
def test_absent_or_empty_never_calls_publisher(setup, code, reason):
    owner = setup.prepare(code)
    run(owner)
    result = owner.finalize_output(lambda *a, **kw: pytest.fail('publisher'), deadline=end())
    assert result.disposition == 'no_output' and result.reason == reason
    assert owner.close(deadline=end()).confirmed


def test_writer_unlink_recreate_final_inode_is_selected(setup):
    owner = setup.prepare('from pathlib import Path;p=Path(OUTPUT_PATH);p.write_bytes(b"old");p.unlink();p.write_bytes(b"new output")')
    run(owner)
    receipt = owner.finalize_output(publish, deadline=end())
    assert receipt.sha256 == hashlib.sha256(b'new output').hexdigest()


@pytest.mark.parametrize('code', [
    'import os;os.symlink("private-missing",OUTPUT_PATH)',
    'import os;os.mkfifo(OUTPUT_PATH)',
    'from pathlib import Path;p=Path(OUTPUT_PATH);p.mkdir()',
    'from pathlib import Path;import os;p=Path(OUTPUT_PATH);p.write_bytes(b"private");os.link(p,p.with_name("extra"))',
    'from pathlib import Path;p=Path(OUTPUT_PATH);p.write_bytes(b"private");p.with_name("unknown.tmp").write_bytes(b"extra")',
])
def test_untrusted_output_type_or_unknown_names_preserved(setup, code):
    owner = setup.prepare(code)
    run(owner)
    with pytest.raises(C.WindowsCaptureError):
        owner.finalize_output(publish, deadline=end())
    assert not owner.close(deadline=end()).confirmed and owner._output.root.exists()
    setup.allow_preserved = True


@pytest.mark.parametrize('change', ['replace', 'modify', 'link'])
def test_check_detects_same_fd_name_or_content_change(setup, change):
    owner = setup.prepare()
    run(owner)
    def mutate(source, **kwargs):
        p = owner._output.path
        if change == 'replace':
            p.unlink(); p.write_bytes(archive())
        elif change == 'modify':
            p.write_bytes(b'x' * source.size)
        else:
            os.link(p, p.with_name('extra'))
        source.check()
        pytest.fail('changed output accepted')
    with pytest.raises(C.WindowsCaptureError):
        owner.finalize_output(mutate, deadline=end())
    assert owner.publication is None and not owner.close(deadline=end()).confirmed
    setup.allow_preserved = True


@pytest.mark.parametrize('unknown', [False, True])
def test_preflight_unknown_or_live_is_not_owned(setup, unknown):
    owner = setup.prepare()
    setup.life.unknown, setup.life.present = unknown, not unknown
    with pytest.raises(C.WindowsCaptureError):
        run(owner)
    assert not setup.spawns and not owner.close(deadline=end()).confirmed
    assert all(kind != 'terminate' for kind, _, _ in setup.life.calls)
    setup.life.unknown = setup.life.present = False
    assert owner.close(deadline=end()).confirmed


def test_unknown_windows_cleanup_prevents_output_open_and_publish(setup, monkeypatch):
    owner = setup.prepare()
    setup.life.confirm = False
    with pytest.raises(C.WindowsCaptureError) as exc:
        run(owner)
    assert exc.value.code == 'sigrok_capture_cleanup_unknown' and not owner.processes_quiescent
    monkeypatch.setattr(owner._output, 'open_final', lambda *a: pytest.fail('read before quiet'))
    with pytest.raises(C.WindowsCaptureError):
        owner.finalize_output(publish, deadline=end())
    assert not owner.close(deadline=end()).confirmed and owner._output.fd is None
    setup.life.confirm = True
    assert not owner.close(deadline=end()).confirmed  # 미검사 파일은 여전히 보존.
    setup.allow_preserved = True


def test_publisher_failure_preserves_output_and_is_not_retried(setup):
    owner = setup.prepare()
    run(owner)
    calls = []
    def fail(source, **kwargs):
        calls.append(source.fd)
        raise RuntimeError('SYNTHETIC_PRIVATE')
    with pytest.raises(C.WindowsCaptureError) as exc:
        owner.finalize_output(fail, deadline=end())
    assert 'SYNTHETIC_PRIVATE' not in ''.join(traceback.format_exception(exc.value))
    with pytest.raises(C.WindowsCaptureError):
        owner.finalize_output(publish, deadline=end())
    assert not owner.close(deadline=end()).confirmed and len(calls) == 1
    setup.allow_preserved = True


def test_commit_receipt_survives_postcommit_audit_failure(setup):
    owner = setup.prepare()
    run(owner)
    def committed(source, **kwargs):
        receipt = publish(source, **kwargs)
        source.on_commit(receipt)  # 같은 영수증 재통지는 무해하다.
        raise RuntimeError('SYNTHETIC_AUDIT')
    with pytest.raises(C.WindowsCaptureError):
        owner.finalize_output(committed, deadline=end())
    assert owner.publication.disposition == 'published'
    assert owner.close(deadline=end()).confirmed


def test_returned_publication_without_commit_is_not_authoritative(setup):
    owner = setup.prepare()
    run(owner)
    def no_commit(source, **kwargs):
        return C.CapturePublication('published', 'signals/synthetic.sr', 'A-0001', source.size, 'a' * 64)
    with pytest.raises(C.WindowsCaptureError):
        owner.finalize_output(no_commit, deadline=end())
    assert owner.publication is None and not owner.close(deadline=end()).confirmed
    setup.allow_preserved = True


def test_postcommit_source_change_preserves_receipt_and_output(setup):
    owner = setup.prepare()
    run(owner)
    def changed(source, **kwargs):
        receipt = publish(source, **kwargs)
        owner._output.path.write_bytes(b'changed')
        return receipt
    with pytest.raises(C.WindowsCaptureError):
        owner.finalize_output(changed, deadline=end())
    assert owner.publication.disposition == 'published' and not owner.close(deadline=end()).confirmed
    setup.allow_preserved = True


def test_explicit_bad_zip_disposition_is_required_for_removal(setup):
    owner = setup.prepare('from pathlib import Path;Path(OUTPUT_PATH).write_bytes(b"notzip")')
    run(owner)
    def invalid(source, **kwargs):
        source.check()
        return C.CapturePublication('invalid_output', size=source.size, reason='bad_zip')
    owner.finalize_output(invalid, deadline=end())
    assert owner.close(deadline=end()).confirmed


@pytest.mark.parametrize('reason', ['limit', 'unsupported', 'metadata_mismatch', 'timeout', 'cancelled'])
def test_incomplete_or_out_of_profile_inspection_is_preserved(setup, reason):
    owner = setup.prepare()
    run(owner)
    def fail(source, **kwargs):
        raise C.WindowsCaptureError(code='sigrok_capture_' + reason)
    with pytest.raises(C.WindowsCaptureError) as exc:
        owner.finalize_output(fail, deadline=end())
    assert exc.value.code == 'sigrok_capture_' + reason
    assert not owner.close(deadline=end()).confirmed
    setup.allow_preserved = True


@pytest.mark.parametrize('cancelled', [False, True])
def test_timeout_or_cancel_returns_exit_for_bounded_partial(setup, cancelled):
    code = 'from pathlib import Path;import time;Path(OUTPUT_PATH).write_bytes(b"partial");time.sleep(20)'
    owner = setup.prepare(code)
    # 취소는 자식이 출력 파일을 쓴 뒤 전달해 partial 신원을 검증한다.
    result = run(owner, timeout_s=.2, cancel=(lambda: owner._output.path.exists()) if cancelled else None)
    assert result.cancelled is cancelled and result.timed_out is (not cancelled)
    assert owner.processes_quiescent and result.post_deadline <= owner.deadline
    receipt = owner.finalize_output(publish, deadline=end())
    assert receipt.partial and owner.close(deadline=end()).confirmed


@pytest.mark.parametrize('cancelled', [False, True])
def test_latched_cancel_does_not_cancel_valid_partial_publication(setup, cancelled):
    code = 'from pathlib import Path;import time;Path(OUTPUT_PATH).write_bytes(' + repr(archive()) + ');time.sleep(20)'
    owner = setup.prepare(code)
    cancel = lambda: owner._output.path.exists()
    result = run(owner, timeout_s=.2, cancel=cancel if cancelled else None)
    assert result.cancelled is cancelled and result.timed_out is (not cancelled)
    calls = []
    def checked(source, **kwargs):
        from pweh.sigrok_srzip import inspect_capture_fd
        assert kwargs['cancel'] is cancel and cancel()
        inspected = inspect_capture_fd(source.fd, size=source.size, command=COMMAND,
                                        deadline=kwargs['deadline'], check=source.check)
        assert inspected.crc_verified and inspected.samples == 4
        calls.append(source.fd)
        return publish(source, **kwargs)
    receipt = owner.finalize_output(checked, deadline=end(), cancel=cancel)
    assert receipt.partial and len(calls) == 1 and owner.close(deadline=end()).confirmed


def test_post_deadline_is_fixed_before_cleanup_and_consumed_by_cleanup(setup, monkeypatch):
    owner = setup.prepare(deadline=end(200))
    original = owner._finish
    clock = {'offset': 0.0}
    stamps = []
    monkeypatch.setattr(C, 'time', SimpleNamespace(monotonic=lambda: time.monotonic() + clock['offset']))
    def finish(execution, deadline):
        stamps.append(C.time.monotonic())
        result = original(execution, deadline)
        clock['offset'] += 7.0  # 정리에 쓴 시간만큼 후처리 잔여 시간이 줄어야 한다.
        return result
    monkeypatch.setattr(owner, '_finish', finish)
    result = run(owner)
    assert stamps[0] + 59.9 <= result.post_deadline <= stamps[0] + 60
    assert result.post_deadline < C.time.monotonic() + 54
    monkeypatch.setattr(C, 'time', time)
    monkeypatch.setattr(owner, '_finish', original)
    owner.finalize_output(publish, deadline=end())
    assert owner.close(deadline=end()).confirmed


def test_new_cancel_after_normal_exit_reaches_publisher_partial_decision(setup):
    owner = setup.prepare()
    result = run(owner)
    assert not result.cancelled and not result.timed_out
    cancel = lambda: True
    def partial(source, **kwargs):
        assert kwargs['cancel'] is cancel and cancel()
        receipt = C.CapturePublication('published', 'signals/synthetic.sr', 'A-0001', source.size,
                                      safeio.hash_fd(source.fd, source.size, algorithms=('sha256',),
                                                     check=source.check)['sha256'], True, 'cancelled')
        source.on_commit(receipt)
        return receipt
    receipt = owner.finalize_output(partial, deadline=end(), cancel=cancel)
    assert receipt.partial and receipt.reason == 'cancelled'
    assert owner.close(deadline=end()).confirmed


def test_cleanup_cannot_extend_worker_hard_deadline(setup, monkeypatch):
    owner = setup.prepare(deadline=end(2))
    original = owner._finish
    observed = []
    def finish(execution, deadline):
        observed.append(deadline)
        return original(execution, deadline)
    monkeypatch.setattr(owner, '_finish', finish)
    result = run(owner)
    assert observed[0] <= result.post_deadline == owner.deadline
    owner.finalize_output(publish, deadline=owner.deadline)


def test_one_child_only_and_before_spawn_is_last_observation(setup, monkeypatch):
    owner = setup.prepare()
    calls = []
    original = R.revalidate_run
    def verify(*args, **kwargs):
        calls.append('verify'); return original(*args, **kwargs)
    monkeypatch.setattr(R, 'revalidate_run', verify)
    factory = owner._factory
    def spawn(*args, **kwargs):
        assert calls[-1] == 'fresh'; return factory(*args, **kwargs)
    owner._factory = spawn
    owner.run(before_spawn=lambda: calls.append('fresh'), deadline=end())
    owner.finalize_output(publish, deadline=end())
    with pytest.raises(C.WindowsCaptureError):
        run(owner)
    assert len(setup.spawns) == 1


def test_callback_failure_spawns_nothing_and_releases_empty_records(setup):
    owner = setup.prepare()
    def fail():
        raise ValueError('SYNTHETIC_PRIVATE')
    with pytest.raises(C.WindowsCaptureError):
        owner.run(before_spawn=fail, deadline=end())
    assert not setup.spawns and owner.close(deadline=end()).confirmed


@pytest.mark.parametrize('output', [False, True])
def test_query_mutation_blocks_spawn(setup, output):
    owner = setup.prepare()
    def mutate():
        setup.life.on_observe = None
        if output:
            owner._output.path.write_bytes(b'unknown')
        else:
            p = setup.bundle.entrypoint; p.chmod(0o755); p.write_bytes(b'changed')
    setup.life.on_observe = mutate
    with pytest.raises(C.WindowsCaptureError):
        run(owner)
    assert not setup.spawns
    if output:
        assert not owner.close(deadline=end()).confirmed
        setup.allow_preserved = True
    else:
        assert owner.close(deadline=end()).confirmed


@pytest.mark.parametrize('raw_cancel', [False, True])
def test_partial_output_prepare_error_is_bound_to_owner(setup, monkeypatch, raw_cancel):
    original = O.OutputRecord.prepare
    def fail(self, **kwargs):
        original(self, **kwargs)
        raise asyncio.CancelledError() if raw_cancel else RuntimeError('private')
    monkeypatch.setattr(O.OutputRecord, 'prepare', fail)
    owner = setup.reserve()
    with pytest.raises(C.WindowsCaptureError) as exc:
        owner.prepare(setup.parent, deadline=end())
    assert exc.value.owner is owner and C._OWNED[owner.token] is owner
    assert owner.close(deadline=end()).confirmed


@pytest.mark.parametrize('raw_cancel', [False, True])
def test_partial_copy_prepare_keeps_opaque_record(setup, monkeypatch, raw_cancel):
    original = R.prepare_run
    def fail(*args, **kwargs):
        prepared = original(*args, **kwargs)
        if raw_cancel:
            failure = asyncio.CancelledError()
            failure.prepared_run = prepared
            raise failure
        raise R.WindowsRunError('sigrok_run_failed', prepared)
    monkeypatch.setattr(R, 'prepare_run', fail)
    owner = setup.reserve()
    with pytest.raises(C.WindowsCaptureError) as exc:
        owner.prepare(setup.parent, deadline=end())
    assert exc.value.owner is owner and C._OWNED[owner.token] is owner
    assert owner._prepared.root.exists() and owner._output is None and not setup.spawns
    assert owner.close(deadline=end()).confirmed


def test_configure_partial_failure_keeps_child_until_retry(setup, monkeypatch):
    owner = setup.prepare('import time;time.sleep(20)')
    original = W._Execution.configure
    monkeypatch.setattr(W._Execution, 'configure', lambda self: False)
    with pytest.raises(C.WindowsCaptureError) as exc:
        run(owner)
    assert exc.value.code == 'sigrok_capture_cleanup_unknown'
    assert owner._execution.proc is not None and not owner.processes_quiescent
    assert not owner.close(deadline=end(.1)).confirmed
    monkeypatch.setattr(W._Execution, 'configure', original)
    assert owner.close(deadline=end()).confirmed


def test_unpublished_output_keeps_bound_lease_after_process_cleanup(setup, isolated_ports):
    manager = isolated_ports['manager']
    lease = manager.acquire(['win:COM4096'], owner=portlock.PortOwner('synthetic', 'sigrok', 'COM4096'))
    owner = setup.reserve()
    use = SimpleNamespace(cleanup_owner=owner, lease=lease)
    try:
        owner.prepare(setup.parent, deadline=end())
        run(owner)
        assert owner.processes_quiescent and not use.cleanup_owner.close(deadline=end()).confirmed
        lease.set_state('orphan')
        assert not lease.closed and C._OWNED[owner.token] is use.cleanup_owner
        with pytest.raises(Exception, match='busy'):
            manager.acquire(['win:COM4096'], owner=portlock.PortOwner('synthetic', 'other', 'COM4096'))
        owner.finalize_output(publish, deadline=end())
        assert owner.close(deadline=end()).confirmed
    finally:
        lease.close()
    assert manager.held_by('win:COM4096') is None


def test_output_parent_same_name_replacement_is_not_removed(setup):
    owner = setup.prepare()
    output = owner._output
    old = output.root.with_name(output.root.name + '-old')
    output.root.rename(old)
    output.root.mkdir()
    (output.root / 'private').write_bytes(b'replacement')
    with pytest.raises(C.WindowsCaptureError):
        run(owner)
    assert not owner.close(deadline=end()).confirmed
    assert (output.root / 'private').read_bytes() == b'replacement'
    setup.allow_preserved = True


def test_output_size_limit_is_not_parsed(setup, monkeypatch):
    monkeypatch.setattr(O, 'MAX_OUTPUT_BYTES', 64)
    owner = setup.prepare('from pathlib import Path;Path(OUTPUT_PATH).write_bytes(b"x"*100)')
    result = run(owner)
    assert result.output_limit
    with pytest.raises(C.WindowsCaptureError):
        owner.finalize_output(publish, deadline=end())
    assert not owner.close(deadline=end()).confirmed
    setup.allow_preserved = True


def test_prepare_normalizes_single_converter_newline(setup, info_setup):
    converter = info_setup.converter
    owner = setup.prepare(path_converter=lambda path, deadline: (converter(path, deadline)+'\r\n').encode())
    assert owner._output.windows_path.endswith('capture.sr')
    assert owner.close(deadline=end()).confirmed


def request(tail):
    image = r'C:\synthetic\sigrok-cli.exe'
    row = dict(pid=12, image=image, creation='1000', cmd=subprocess.list2cmdline([image, *tail]), wait_ms=10)
    encoded = base64.b64encode(json.dumps(row).encode()).decode()
    return I.TERMINATE_SCRIPT_TEMPLATE.replace('__REQUEST__', encoded)


def test_capture_control_and_existing_admissions_are_disjoint():
    tail = COMMAND.argv_tail(r'C:\synthetic\output\capture.sr')
    assert C._script_cap(request(tail), end()) == 1024
    for module, error in ((W, W.WindowsInfoError), (Q, Q.WindowsComError)):
        with pytest.raises(error):
            module._script_cap(request(tail), end())
    for bad in (('--version',), ('--list-supported',), ('--driver=ols:conn=COM1','--dont-scan','--scan'), tail+('--scan',)):
        with pytest.raises(C.WindowsCaptureError):
            C._script_cap(request(bad), end())


def test_capture_control_pending_blocks_additional_control_spawn(tmp_path):
    flag = tmp_path / 'finish'
    code = f'import pathlib,time,os\np=pathlib.Path({str(flag)!r})\nwhile not p.exists(): time.sleep(.01)\nos.write(1,b"{{}}")'
    calls = []
    runner = C.FixedCaptureRunner(process_factory=control_factory(code, calls),
                                  powershell_provider=lambda: '/synthetic/powershell.exe')
    try:
        with pytest.raises(C.WindowsCaptureError):
            runner(I.QUERY_SCRIPT, end(.1))
        with pytest.raises(C.WindowsCaptureError):
            runner(I.QUERY_SCRIPT, end(.1))
        assert runner.pending and len(calls) == 1
    finally:
        flag.touch()
        assert runner.settle(deadline=end())
    assert not runner.pending


@pytest.mark.parametrize('value', [True, 0, -1, 301, float('nan'), float('inf'), 10**400, '60'])
def test_timeout_input_is_bounded_without_spawning(setup, value):
    owner = setup.prepare()
    with pytest.raises(C.WindowsCaptureError):
        run(owner, timeout_s=value)
    assert not setup.spawns


def test_publication_closed_fields_reject_private_payload():
    for values in [dict(path='private/key'),dict(artifact_id='PRIVATE'),dict(size=True),dict(reason='private'),dict(sha256='private')]:
        good = dict(disposition='published', path='signals/synthetic.sr', artifact_id='A-0001',size=1,sha256='a'*64)
        good.update(values)
        with pytest.raises(O.CaptureOutputError):
            C.CapturePublication(**good)
