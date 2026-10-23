"""합성 read/MD5와 같은 FD 게시·취소·교체 경계를 확인한다."""
from __future__ import annotations

import hashlib
import json
import os
import stat
import sys
import threading
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'mcp-servers/flipper-mcp'))
from flipper_mcp import storage as O, session as S
from pweh.errors import PwehError
from pweh.jobs import JobCancelled
from .fake_flipper_cli import setup, PROMPT


class Job:
    def __init__(self):
        self.event = threading.Event()
        self.committed = False
        self.partial = None

    @property
    def cancelled(self):
        return self.event.is_set()

    def check_cancelled(self):
        if self.cancelled:
            raise JobCancelled()

    def mark_committed(self):
        self.committed = True
        self.event.clear()

    def set_partial(self, data):
        self.partial = data


def pull(setup, *, owner=None, job=None, name=None, path=None):
    owner = owner or setup.connect()
    job = job or Job()
    use = owner.reserve_use()
    assert use.claim()
    try:
        return O.pull(use, setup.case, path or f'/ext/pweh/{setup.case.id}/fixture.sub', name, job)
    finally:
        use.finish()


def output_files(case):
    return list((case.dir / 'flipper').glob('*'))


@pytest.mark.parametrize('payload', [b'', b'x', b'\x00\x03\xff\r\n>: \r\nSize: 5\r\n\x1b[31m', bytes(range(256)) * 4096])
def test_verified_pull_same_bytes_hashes_and_closed_metadata(setup, payload):
    setup.fake.payload, setup.fake.chunk = payload, 4096
    job = Job()
    result = pull(setup, job=job)
    artifact = result['artifact']
    data = (setup.case.dir / artifact['path']).read_bytes()
    assert data == payload and artifact['size'] == len(payload)
    assert artifact['sha256'] == hashlib.sha256(payload).hexdigest()
    assert stat.S_IMODE((setup.case.dir / artifact['path']).stat().st_mode) == 0o444
    assert result['transfer'] == {'declared_size': len(payload), 'received_size': len(payload),
        'complete': True, 'md5_match': True, 'device_md5': hashlib.md5(payload).hexdigest(),
        'host_md5': hashlib.md5(payload).hexdigest(), 'snapshot_atomic': False, 'device_file_origin_verified': False}
    assert job.committed and not job.cancelled and result['warnings'] == []
    registered = setup.case.artifacts()[0]
    assert registered['producer'] == 'flipper-mcp' and registered['kind'] == 'other'
    assert registered['extra']['type'] == 'flipper-storage-copy'
    assert registered['extra']['device_file_origin_verified'] is False
    assert 'PRIVATE_' not in json.dumps(result) + json.dumps(registered)
    assert max(setup.fake.read_sizes) <= 4096
    assert setup.fake.commands[-4:][0::2] == [b'loader info', b'loader info']


@pytest.mark.parametrize('chunk', [1, 2, 3, 7, 4096])
def test_read_fragmentation_and_partial_write(setup, chunk):
    setup.fake.chunk = chunk
    setup.fake.write_chunk = 2
    setup.fake.payload = bytes(range(256))
    assert pull(setup)['artifact']['size'] == 256


@pytest.mark.parametrize('name', ['../x', '/abs', 'x/y', 'x.', 'x y', '"x"', '한글', '\x03'])
def test_dest_validation_no_storage_tx(setup, name):
    owner = setup.connect()
    before = list(setup.fake.commands)
    with pytest.raises(PwehError):
        pull(setup, owner=owner, name=name)
    assert setup.fake.commands == before and setup.case.artifacts() == []


@pytest.mark.parametrize('kind', ['file', 'symlink', 'directory', 'hardlink'])
def test_existing_dest_never_overwritten(setup, kind):
    parent = setup.case.dir / 'flipper'
    parent.mkdir()
    dest = parent / 'taken.bin'
    if kind == 'file':
        dest.write_bytes(b'original')
    elif kind == 'symlink':
        dest.symlink_to('missing')
    elif kind == 'directory':
        dest.mkdir()
    else:
        (parent / 'original').write_bytes(b'original')
        os.link(parent / 'original', dest)
    owner = setup.connect()
    before = list(setup.fake.commands)
    with pytest.raises(PwehError):
        pull(setup, owner=owner, name='taken.bin')
    assert setup.fake.commands == before and setup.case.artifacts() == []
    assert dest.exists() or dest.is_symlink()


def test_md5_mismatch_no_artifact_or_retransmission(setup):
    setup.fake.responses[b'storage md5 '] = lambda command: command + b'\r\n' + b'0' * 32 + b'\r\n' + PROMPT
    with pytest.raises(PwehError) as caught:
        pull(setup)
    assert caught.value.code == 'flipper_checksum_mismatch'
    assert setup.case.artifacts() == [] and output_files(setup.case) == []
    assert sum(x.startswith(b'storage read ') for x in setup.fake.commands) == 1
    assert S.get_session(setup.case.id).state == 'terminal'


@pytest.mark.parametrize('body', [b'Size: 1048577\r\n', b'Size: 4294967296\r\n',
                                 b'Size: 2\r\nx\r\n' + PROMPT,
                                 b'Size: 1\r\nxy\r\n' + PROMPT,
                                 b'Size: 1\r\nxBAD' + PROMPT])
def test_invalid_read_terminal_no_md5_and_no_partial_artifact(setup, monkeypatch, body):
    monkeypatch.setattr(S, 'TEXT_SECONDS', .01)
    setup.fake.responses[b'storage read '] = lambda command: command + b'\r\n' + body
    with pytest.raises(PwehError):
        pull(setup)
    assert not any(c.startswith(b'storage md5 ') for c in setup.fake.commands)
    assert setup.case.artifacts() == [] and output_files(setup.case) == []


def test_mid_binary_cancel_has_only_fixed_partial_metadata(setup):
    setup.fake.chunk = 1
    job = Job()
    owner = setup.connect()
    def stop(size):
        if owner.cli.received_size and owner.cli.received_size >= 2:
            job.event.set()
    setup.fake.before_read = stop
    with pytest.raises(JobCancelled):
        pull(setup, owner=owner, job=job)
    assert not job.committed and job.partial == {'stage': 'read', 'received_size': 2}
    assert setup.case.artifacts() == [] and output_files(setup.case) == []
    assert owner.state == 'terminal'


def test_cancel_at_final_output_seal_aborts_before_registration(setup, monkeypatch):
    job = Job()
    original = setup.case.register_artifact
    def register(path, **kwargs):
        check = kwargs['check']
        original_check = O._Output.check
        calls = []
        def at_last(self, *args, **kw):
            original_check(self, *args, **kw)
            calls.append(1)
            if len(calls) == 2:
                job.event.set()
        with monkeypatch.context() as patch:
            patch.setattr(O._Output, 'check', at_last)
            return original(path, **kwargs)
    monkeypatch.setattr(setup.case, 'register_artifact', register)
    with pytest.raises(JobCancelled):
        pull(setup, job=job)
    assert setup.case.artifacts() == [] and output_files(setup.case) == [] and not job.committed


@pytest.mark.parametrize('field,value', [('size', 999), ('is_dir', True), ('path', 'analysis/other'), ('sha256', '0' * 64)])
def test_registration_entry_matches_fd_facts(setup, monkeypatch, field, value):
    original = setup.case.register_artifact
    def register(path, **kwargs):
        callback = kwargs['check']
        kwargs['check'] = lambda entry: callback({**entry, field: value})
        return original(path, **kwargs)
    monkeypatch.setattr(setup.case, 'register_artifact', register)
    with pytest.raises(PwehError):
        pull(setup)
    assert setup.case.artifacts() == [] and output_files(setup.case) == []


@pytest.mark.parametrize('mutation', ['same_size', 'replace_same_bytes', 'hardlink', 'parent'])
def test_output_seal_change_rejected_and_other_inode_not_removed(setup, monkeypatch, mutation):
    original = setup.case.register_artifact
    replacements = []
    def register(path, **kwargs):
        target = setup.case.dir / path
        if mutation == 'same_size':
            target.chmod(0o600)
            target.write_bytes(b'XXXXX')
            target.chmod(0o444)
        elif mutation == 'replace_same_bytes':
            other = target.with_name('replacement')
            other.write_bytes(target.read_bytes())
            other.chmod(0o444)
            other.replace(target)
            replacements.append(target)
        elif mutation == 'hardlink':
            os.link(target, target.with_name('second'))
            replacements.append(target)
        else:
            parent = target.parent
            parent.rename(parent.with_name('old-flipper'))
            parent.mkdir()
            target.write_bytes(b'replacement')
            replacements.append(target)
        return original(path, **kwargs)
    monkeypatch.setattr(setup.case, 'register_artifact', register)
    with pytest.raises(PwehError):
        pull(setup)
    assert setup.case.artifacts() == []
    assert all(path.exists() for path in replacements)


def test_committed_receipt_survives_audit_failure_and_late_cancel(setup, monkeypatch):
    job = Job()
    def failed_audit(data):
        job.event.set()
        raise RuntimeError('PRIVATE_AUDIT_SENTINEL')
    monkeypatch.setattr(setup.case, 'audit', failed_audit)
    result = pull(setup, job=job)
    assert result['ok'] and job.committed and len(setup.case.artifacts()) == 1
    assert (setup.case.dir / result['artifact']['path']).read_bytes() == setup.fake.payload
    assert result['warnings'] == ['post_commit_callback_or_audit_failed']
    assert 'PRIVATE_' not in json.dumps(result)


def test_output_close_failure_keeps_commit_receipt(setup, monkeypatch):
    original = O._Output.close
    def unconfirmed(self):
        original(self)
        return False
    monkeypatch.setattr(O._Output, 'close', unconfirmed)
    try:
        result = pull(setup)
        assert result['warnings'] == ['output_close_unconfirmed']
        assert len(setup.case.artifacts()) == 1
    finally:
        O._PENDING_OUTPUTS.clear()


def test_commit_deadline_is_not_reset_per_hash(setup, monkeypatch):
    monkeypatch.setattr(O, 'COMMIT_SECONDS', .001)
    original = O._hash_output
    def delayed(*args):
        time.sleep(.003)
        return original(*args)
    monkeypatch.setattr(O, '_hash_output', delayed)
    with pytest.raises(PwehError) as caught:
        pull(setup)
    assert caught.value.code == 'time_limit'
    assert setup.case.artifacts() == [] and output_files(setup.case) == []


def test_failed_transfer_removes_only_own_file_and_preserves_other_entry(setup):
    parent = setup.case.dir / 'flipper'
    parent.mkdir()
    unrelated = parent / 'unrelated'
    unrelated.write_bytes(b'keep')
    setup.fake.responses[b'storage md5 '] = lambda command: command + b'\r\n' + b'0' * 32 + b'\r\n' + PROMPT
    with pytest.raises(PwehError):
        pull(setup)
    assert output_files(setup.case) == [unrelated] and unrelated.read_bytes() == b'keep'


def test_created_file_snapshot_failure_is_preserved_as_unknown(setup, monkeypatch):
    original = O.os.fstat
    def fail_new_file(fd):
        info = original(fd)
        if stat.S_ISREG(info.st_mode) and stat.S_IMODE(info.st_mode) == 0o600:
            raise OSError('PRIVATE_STAT_ERROR')
        return info
    # 연결·lease 생성은 정상 완료한 뒤 출력 파일의 최초 snapshot만 실패시킨다.
    owner = setup.connect()
    monkeypatch.setattr(O.os, 'fstat', fail_new_file)
    with pytest.raises(PwehError) as caught:
        pull(setup, owner=owner)
    assert caught.value.code == 'flipper_cleanup_pending'
    assert len(output_files(setup.case)) == 1 and setup.case.artifacts() == []
    assert not any(c.startswith(b'storage read ') for c in setup.fake.commands)


def test_parent_symlink_rejected_before_remote_read(setup):
    elsewhere = setup.case.dir / 'other'
    elsewhere.mkdir()
    (setup.case.dir / 'flipper').symlink_to(elsewhere, target_is_directory=True)
    with pytest.raises(PwehError):
        pull(setup)
    assert list(elsewhere.iterdir()) == [] and setup.case.artifacts() == []
    assert not any(c.startswith(b'storage read ') for c in setup.fake.commands)
