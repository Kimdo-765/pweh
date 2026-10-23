"""device-read 선택 bounded 인자와 기존 기본 경로의 좁은 호환 회귀."""
from __future__ import annotations

import contextlib
import hashlib
import os
import time

import pytest

from pweh import provenance as P
from pweh.errors import PwehError
from pweh.runtime import get_runtime

SOURCE = {'server': 'synthetic', 'tool': 'synthetic-read'}


@pytest.fixture
def setup(workspace, auth):
    runtime = get_runtime('bounded-device-read-test')
    case = runtime.cases.create(title='합성 읽기', authorization=auth)
    path = case.dir / 'dumps' / 'read.bin'
    path.write_bytes(b'synthetic' * 20000)
    return runtime.provenance, case, path


def options(**kw):
    return {'max_bytes': 16 << 20, 'max_entries': 10000, 'deadline': time.monotonic() + 5, **kw}


def test_default_and_bounded_body_keep_original_contract(setup):
    ledger, case, path = setup
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    first = ledger.record_device_read(case, path, SOURCE, {'match': True}, sha256=digest, attestation_id='synthetic')
    second = ledger.record_device_read(case, path, SOURCE, {'match': True}, sha256=digest,
        attestation_id='synthetic', **options())
    assert {k: v for k, v in first.items() if k not in ('seq', 'ts', 'prev')} == {
        k: v for k, v in second.items() if k not in ('seq', 'ts', 'prev')}
    assert ledger.entries(case)[-1] == second


@pytest.mark.parametrize('key,value', [('max_bytes', 0), ('max_bytes', True), ('max_bytes', (16 << 20) + 1),
    ('max_entries', 0), ('max_entries', True), ('max_entries', 10001), ('deadline', True),
    ('deadline', float('inf')), ('deadline', float('nan')), ('deadline', 10 ** 400), ('check', True)])
def test_invalid_bound_rejects_before_file_hash(setup, monkeypatch, key, value):
    ledger, case, path = setup
    monkeypatch.setattr(ledger, '_file_body', lambda *a, **kw: pytest.fail('잘못된 한도 뒤 파일 열기'))
    with pytest.raises(P.ProvenanceError) as exc:
        ledger.record_device_read(case, path, SOURCE, **options(**{key: value}))
    assert exc.value.code == 'provenance_bounded_invalid'
    assert not ledger.ledger_path(case).exists()


@pytest.mark.parametrize('which', ['expired', 'cancel', 'sha', 'entries', 'bytes'])
def test_precommit_failures_do_not_append(setup, which):
    ledger, case, path = setup
    kw = options()
    if which == 'expired': kw['deadline'] = time.monotonic() - 1
    elif which == 'cancel':
        def cancel(): raise PwehError('합성 취소', code='cancelled')
        kw['check'] = cancel
    elif which == 'sha': kw['sha256'] = '0' * 64
    elif which == 'bytes': kw['max_bytes'] = 1
    else:
        def reject(entries):
            assert entries == []
            raise PwehError('합성 중단', code='synthetic-stop')
        kw['check_entries'] = reject
    with pytest.raises(PwehError): ledger.record_device_read(case, path, SOURCE, **kw)
    assert ledger.entries(case) == []


def test_checked_hash_chunks_and_same_lock_entry_callback(setup, monkeypatch):
    ledger, case, path = setup
    ledger.record_device_read(case, path, SOURCE)
    reads, checks, callbacks = [], [], []
    original = P.os.pread
    def read(fd, size, offset):
        reads.append(size)
        return original(fd, size, offset)
    monkeypatch.setattr(P.os, 'pread', read)
    result = ledger.record_device_read(case, path, SOURCE, **options(check=lambda: checks.append(1),
        check_entries=lambda entries: callbacks.append(entries)))
    assert result['seq'] == 2 and len(callbacks) == 1 and len(callbacks[0]) == 1
    assert len(reads) >= 4 and max(reads) <= 65536 and len(checks) >= 8


def test_post_append_lock_exit_retains_actual_receipt(setup, monkeypatch):
    ledger, case, path = setup
    original = ledger._lock
    @contextlib.contextmanager
    def failing(*a, **kw):
        with original(*a, **kw): yield
        raise OSError('합성 close 실패')
    monkeypatch.setattr(ledger, '_lock', failing)
    result = ledger.record_device_read(case, path, SOURCE, **options())
    assert result['seq'] == 1 and result.warnings == ('provenance_close_unconfirmed',)
    monkeypatch.setattr(ledger, '_lock', original)
    assert dict(result) == ledger.entries(case)[0]
    assert 'warnings' not in result


def test_entry_limit_is_checked_before_append(setup):
    ledger, case, path = setup
    ledger.record_device_read(case, path, SOURCE)
    before = ledger.ledger_path(case).read_bytes()
    with pytest.raises(P.ProvenanceError) as exc:
        ledger.record_device_read(case, path, SOURCE, **options(max_entries=1))
    assert exc.value.code == 'provenance_bounded_limit'
    assert ledger.ledger_path(case).read_bytes() == before
