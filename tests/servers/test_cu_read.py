"""합성 CU의 실제 사용권·snapshot FD·원장 FIRST 게시 경계."""
from __future__ import annotations

import copy
import hashlib
import json
import os
import threading
import time
from dataclasses import replace

import pytest

from nfc_mcp import cu_read as R, cu_owner as O
from pweh import cu_protocol as P, nfc_inventory as I, nfc_cu_snapshot as N
from pweh.errors import PwehError
from pweh.jobs import JobContext
from pweh.nfc_formats import _NfcFileIdentity
from pweh.safety.attestations import canonical_json
from .fake_cu import setup as setup, FakeCu, UID

PRIVATE = 'CU_READ_PRIVATE_SENTINEL'


def end():
    return time.monotonic() + 5


def admitted(env, *, family=213, flipper=False):
    env.fake = FakeCu(family=family)
    owner = env.connect()
    identity = _NfcFileIdentity(UID, b'\0D', b'\0', P.NtagFamily(family).mifare_version, 'iso14443-3a')
    if flipper:
        observation = I.ScanObservation('synthetic-flipper', owner._binding(), identity, 'a' * 64, 200,
                                        True, True, True)
        scan = I.record_flipper_scan(env.runtime, env.case, observation, deadline=end())
    else:
        use = owner.reserve_use()
        assert use.claim()
        try:
            probe = owner.probe_ntag(use, deadline=end())
        finally:
            use.finish()
        scan = I.record_cu_scan(env.runtime, env.case,
            I.CuScanObservation(probe.session_id, probe.reader_binding, identity, True, True, True), deadline=end())
    bound = I.add_inventory(env.runtime, env.case, scan.scan_ref, deadline=end())
    return owner, bound


def work(env, owner, bound, event=None):
    return R.prepare_cu_read(env.runtime, env.case, owner, bound, cancel_event=event or threading.Event())


def wait(job):
    job._thread.join(5)
    assert not job._thread.is_alive(), '합성 worker 종료 실패'
    return job


def launch(env, owner, bound, event=None):
    return wait(work(env, owner, bound, event).start())


def output(env, job):
    path = env.case.dir / job.result['artifact']['path']
    return path, json.loads(path.read_bytes())


def assert_empty(env, owner):
    assert len(env.runtime.provenance.entries(env.case)) == 2
    assert env.case.load()['artifacts'] == []
    assert list((env.case.dir / 'nfc').glob('cu-read-*')) == []
    assert not owner._uses


@pytest.mark.parametrize('family', [213, 215, 216])
@pytest.mark.parametrize('setup', ['posix-tty', 'win-helper'], indirect=True)
def test_actual_read_registers_only_snapshot_and_actual_receipts(setup, family):
    env = setup
    owner, bound = admitted(env, family=family)
    job = launch(env, owner, bound)
    assert job.status == 'succeeded', job.to_dict()
    result = job.result
    path, payload = output(env, job)
    snapshot = N.parse_cu_snapshot(path.read_bytes(), deadline=end())
    assert snapshot.pages == tuple(env.fake.pages)
    assert payload['pages'] == [page.hex() for page in env.fake.pages]
    assert b'UNTRUSTED123' not in path.read_bytes()
    assert dict(snapshot.binding) == R._binding(bound)
    assert path.stat().st_mode & 0o777 == 0o444
    row = env.runtime.provenance.entries(env.case)[-1]
    artifact = env.case.load()['artifacts'][-1]
    assert result['artifact'] == {'artifact_id': artifact['id'], 'path': str(path.relative_to(env.case.dir)),
        'size': path.stat().st_size, 'sha256': hashlib.sha256(path.read_bytes()).hexdigest()}
    assert result['provenance'] == {'kind': 'device-read', 'ledger_seq': row['seq'],
        'ledger_entry_sha256': hashlib.sha256(canonical_json(row).encode()).hexdigest()}
    assert row['source'] == R.SOURCE and row['attestation_id'] is None
    assert set(row['extra']) == {'snapshot_profile', 'reader_profile', 'reader_profile_sha256',
        'firmware_commit', 'session_id', 'reader_binding', 'binding', 'family', 'pages_total',
        'pages_observed', 'read_complete', 'stop_reason'}
    assert result['registered'] and result['status'] == 'ok' and result['warnings'] == []
    assert job._committed and not owner._uses and owner.state == 'ready'
    public = json.dumps(job.to_dict())
    for secret in (UID.hex(), env.fake.version.hex(), 'CU_SYNTHETIC', 'UNTRUSTED123', 'pages"'):
        assert secret not in public


def test_flipper_inventory_is_not_restricted_to_cu_origin(setup):
    owner, bound = admitted(setup, flipper=True)
    assert launch(setup, owner, bound).status == 'succeeded'


@pytest.mark.parametrize('reason', ['time_limit', 'nfc_scan_invalid'])
@pytest.mark.parametrize('observed', [3, 45])
def test_allowed_partial_preserves_original_completion_and_no_more_wire(setup, monkeypatch, reason, observed):
    env = setup
    owner, bound = admitted(env)
    original = owner.read_ntag
    def partial(use, expected, *, deadline):
        read = original(use, expected, deadline=deadline)
        owner._terminal()
        env.after_read = len(env.fake.commands)
        return replace(read, pages=read.pages[:observed] + (None,) * (read.total_pages - observed),
                       pages_observed=observed, read_complete=False, stop_reason=reason)
    monkeypatch.setattr(owner, 'read_ntag', partial)
    job = launch(env, owner, bound)
    assert job.status == 'succeeded', job.to_dict()
    assert job.result['status'] == 'partial' and not job.result['read_complete']
    assert job.result['pages_observed'] == observed and job.result['stop_reason'] == reason
    assert len(env.fake.commands) == env.after_read and owner.state == 'terminal'
    assert output(env, job)[1]['pages'][observed:] == [None] * (45 - observed)


@pytest.mark.parametrize('reason', ['cu_protocol_invalid', 'cancelled', 'nfc_identity_mismatch',
                                   'authorization_required', 'route_changed', 'unknown'])
def test_forbidden_partial_is_never_published(setup, monkeypatch, reason):
    owner, bound = admitted(setup)
    original = owner.read_ntag
    def partial(*args, **kw):
        read = original(*args, **kw)
        owner._terminal()
        return replace(read, read_complete=False, stop_reason=reason)
    monkeypatch.setattr(owner, 'read_ntag', partial)
    job = launch(setup, owner, bound)
    assert job.status == ('cancelled' if reason == 'cancelled' else 'failed')
    assert_empty(setup, owner)
    assert PRIVATE not in json.dumps(job.to_dict())


def test_gate_cancel_releases_reservation_and_late_cancel_does_not_touch_next_use(setup):
    owner, bound = admitted(setup)
    pending = work(setup, owner, bound)
    action = pending.action
    action['route']['device_id'] = 'changed'
    assert pending.action['route']['device_id'] != 'changed'
    assert action['operation'] == 'ntag_read' and action['pages_total'] == 45
    assert owner._uses
    pending.cancel()
    assert not owner._uses
    job = launch(setup, owner, bound)
    assert job.status == 'succeeded'
    current = owner.reserve_use()
    count = setup.fake.cancel_calls
    pending.cancel()
    assert setup.fake.cancel_calls == count
    current.cancel()


def test_job_cancel_before_claim_is_visible_and_releases_use(setup, monkeypatch):
    owner, bound = admitted(setup)
    original = setup.runtime.jobs.start
    def already_cancelled(kind, fn, **kw):
        def before(j):
            j.job._cancel.set()
            return fn(j)
        return original(kind, before, **kw)
    monkeypatch.setattr(setup.runtime.jobs, 'start', already_cancelled)
    job = launch(setup, owner, bound)
    assert job.status == 'cancelled'
    assert_empty(setup, owner)


def test_start_failure_before_worker_releases_use(setup, monkeypatch):
    owner, bound = admitted(setup)
    item = work(setup, owner, bound)
    def fail(*a, **kw): raise RuntimeError(PRIVATE)
    monkeypatch.setattr(setup.runtime.jobs, 'start', fail)
    with pytest.raises(PwehError) as exc: item.start()
    assert exc.value.code == 'nfc_failed' and PRIVATE not in str(exc.value)
    assert_empty(setup, owner)


@pytest.mark.parametrize('fault', ['failure', 'cancel'])
def test_ledger_first_failure_preserves_actual_unregistered_receipt(setup, monkeypatch, fault):
    owner, bound = admitted(setup)
    event = threading.Event()
    def reject(*args, **kw):
        if fault == 'cancel':
            event.set()
            kw['check']({})
        raise RuntimeError(PRIVATE)
    monkeypatch.setattr(setup.case, 'register_artifact', reject)
    job = launch(setup, owner, bound, event)
    assert job.status == ('cancelled' if fault == 'cancel' else 'failed')
    result = job.result
    assert not result['ok'] and not result['registered'] and result['artifact']['artifact_id'] is None
    assert result['warnings'] == ['artifact_registration_incomplete']
    assert not job._committed and len(setup.runtime.provenance.entries(setup.case)) == 3
    assert (setup.case.dir / result['artifact']['path']).is_file()
    assert setup.case.load()['artifacts'] == [] and not owner._uses
    assert PRIVATE not in json.dumps(job.to_dict())


@pytest.mark.parametrize('fault', ['audit', 'late_cancel', 'return_error'])
def test_artifact_commit_wins_over_late_errors(setup, monkeypatch, fault):
    owner, bound = admitted(setup)
    event = threading.Event()
    original = setup.case.register_artifact
    if fault == 'audit':
        monkeypatch.setattr(setup.case, 'audit', lambda e: (_ for _ in ()).throw(RuntimeError(PRIVATE)))
    else:
        def late(*a, **kw):
            callback = kw['on_commit']
            def committed(entry):
                callback(entry)
                event.set()
            kw['on_commit'] = committed
            out = original(*a, **kw)
            if fault == 'return_error': raise RuntimeError(PRIVATE)
            return out
        monkeypatch.setattr(setup.case, 'register_artifact', late)
    job = launch(setup, owner, bound, event)
    assert job.status == 'succeeded' and job._committed, job.to_dict()
    assert job.result['registered'] and len(setup.case.load()['artifacts']) == 1
    expected = [] if fault == 'late_cancel' else ['post_commit_callback_failed']
    assert job.result['warnings'] == expected and PRIVATE not in json.dumps(job.to_dict())


@pytest.mark.parametrize('mutation', ['content', 'name', 'parent', 'hardlink'])
def test_output_change_before_append_never_records_source(setup, monkeypatch, mutation):
    owner, bound = admitted(setup)
    original = setup.runtime.provenance.record_device_read
    def changed(case, path, *a, **kw):
        p = case.dir / path
        if mutation == 'content':
            os.chmod(p, 0o644)
            data = p.read_bytes()
            p.write_bytes(b'X' + data[1:])
            os.chmod(p, 0o444)
        elif mutation == 'name':
            data = p.read_bytes()
            p.rename(p.with_suffix('.old'))
            p.write_bytes(data)
            os.chmod(p, 0o444)
        elif mutation == 'parent':
            parent = p.parent
            parent.rename(parent.with_name('old-nfc'))
            parent.mkdir()
        else:
            os.link(p, p.with_suffix('.link'))
        return original(case, path, *a, **kw)
    monkeypatch.setattr(setup.runtime.provenance, 'record_device_read', changed)
    job = launch(setup, owner, bound)
    assert job.status == 'failed' and len(setup.runtime.provenance.entries(setup.case)) == 2
    assert setup.case.load()['artifacts'] == [] and not owner._uses


def test_same_lock_check_never_reopens_ledger_and_final_check_uses_fresh_entries(setup, monkeypatch):
    owner, bound = admitted(setup)
    ledger = setup.runtime.provenance
    original_append, original_entries = ledger._append, ledger.entries
    locked = [False]
    fresh = []
    def append(*a, **kw):
        callback = kw['check_entries']
        def locked_check(entries):
            locked[0] = True
            try: return callback(entries)
            finally: locked[0] = False
        kw['check_entries'] = locked_check
        return original_append(*a, **kw)
    def entries(*a, **kw):
        assert not locked[0]
        fresh.append(kw)
        return original_entries(*a, **kw)
    monkeypatch.setattr(ledger, '_append', append)
    monkeypatch.setattr(ledger, 'entries', entries)
    job = launch(setup, owner, bound)
    assert job.status == 'succeeded', job.to_dict()
    assert len(fresh) == 2
    assert all(kw['max_bytes'] == 16 << 20 and kw['max_entries'] == 10000 for kw in fresh)


@pytest.mark.parametrize('field', ['identity', 'scan_seq', 'inventory_seq', 'scan_entry_sha256', 'inventory_entry_sha256'])
def test_inventory_same_entries_helper_rejects_changed_binding_without_io(setup, monkeypatch, field):
    owner, bound = admitted(setup)
    entries = setup.runtime.provenance.entries(setup.case)
    value = getattr(bound, field)
    replacement = replace(value, uid=b'1234567') if field == 'identity' else value + 1 if type(value) is int else '0' * 64
    altered = replace(bound, **{field: replacement})
    monkeypatch.setattr(setup.runtime.provenance, 'entries', lambda *a, **kw: pytest.fail('중첩 원장 읽기'))
    I.check_inventory_entries(setup.runtime, setup.case, bound, entries, check=lambda: None)
    with pytest.raises(PwehError):
        I.check_inventory_entries(setup.runtime, setup.case, altered, entries, check=lambda: None)


@pytest.mark.parametrize('point', ['snapshot', 'write', 'append'])
def test_unknown_worker_exceptions_are_fixed_and_release_use(setup, monkeypatch, point):
    owner, bound = admitted(setup)
    def fail(*a, **kw): raise ValueError(PRIVATE)
    if point == 'snapshot': monkeypatch.setattr(R, '_snapshot', fail)
    elif point == 'write': monkeypatch.setattr(R._Output, 'write', fail)
    else: monkeypatch.setattr(setup.runtime.provenance, 'record_device_read', fail)
    job = launch(setup, owner, bound)
    assert job.status == 'failed' and PRIVATE not in json.dumps(job.to_dict())
    assert_empty(setup, owner)


@pytest.mark.parametrize('field,value', [('tag_ref', PRIVATE), ('scan_ref', PRIVATE),
    ('identity_digest', PRIVATE), ('scan_seq', True), ('inventory_seq', 0),
    ('scan_entry_sha256', PRIVATE), ('inventory_entry_sha256', PRIVATE), ('family', 'ntag216')])
def test_prepare_checks_private_bound_before_reserving(setup, field, value):
    owner, bound = admitted(setup)
    with pytest.raises(PwehError) as exc:
        work(setup, owner, replace(bound, **{field: value}))
    assert PRIVATE not in str(exc.value) and not owner._uses


def test_event_before_start_releases_pending_use_without_caller_cleanup(setup):
    owner, bound = admitted(setup)
    event = threading.Event()
    item = work(setup, owner, bound, event)
    event.set()
    with pytest.raises(PwehError) as exc: item.start()
    assert exc.value.code == 'cancelled' and not owner._uses


def test_started_worker_owns_use_even_when_jobs_start_raises_late(setup, monkeypatch):
    owner, bound = admitted(setup)
    entered, release = threading.Event(), threading.Event()
    original_read = owner.read_ntag
    def blocked(*a, **kw):
        entered.set()
        assert release.wait(3)
        return original_read(*a, **kw)
    monkeypatch.setattr(owner, 'read_ntag', blocked)
    original_start = setup.runtime.jobs.start
    jobs = []
    def late(*a, **kw):
        job = original_start(*a, **kw)
        jobs.append(job)
        assert entered.wait(3)
        raise RuntimeError(PRIVATE)
    monkeypatch.setattr(setup.runtime.jobs, 'start', late)
    item = work(setup, owner, bound)
    try:
        with pytest.raises(PwehError): item.start()
        assert owner._uses and setup.fake.is_open
    finally:
        release.set()
    assert wait(jobs[0]).status == 'cancelled'
    assert_empty(setup, owner)


def test_explicit_cancel_during_read_retains_use_until_worker_finishes(setup, monkeypatch):
    owner, bound = admitted(setup)
    entered, release = threading.Event(), threading.Event()
    original = owner.read_ntag
    def blocked(*a, **kw):
        entered.set()
        assert release.wait(3)
        return original(*a, **kw)
    monkeypatch.setattr(owner, 'read_ntag', blocked)
    item = work(setup, owner, bound)
    job = item.start()
    assert entered.wait(3)
    setup.runtime.jobs.cancel(job.id)
    item.cancel()
    assert owner._uses and setup.fake.is_open
    release.set()
    assert wait(job).status == 'cancelled'
    assert_empty(setup, owner)


@pytest.mark.parametrize('stage', ['wire', 'host'])
def test_deadline_is_constructed_once_at_worker_execution(setup, monkeypatch, stage):
    owner, bound = admitted(setup)
    monkeypatch.setattr(R, 'WIRE_SECONDS' if stage == 'wire' else 'HOST_SECONDS', 0)
    job = launch(setup, owner, bound)
    assert job.status == 'failed' and job.error['code'] == 'time_limit'
    assert_empty(setup, owner)


@pytest.mark.parametrize('stage', ['append', 'artifact'])
def test_cancel_inside_inventory_check_is_preserved_as_cancelled(setup, monkeypatch, stage):
    owner, bound = admitted(setup)
    event = threading.Event()
    ledger = setup.runtime.provenance
    if stage == 'append':
        original = ledger.record_device_read
        def before(*a, **kw):
            cb = kw['check_entries']
            def stop(entries):
                event.set()
                return cb(entries)
            kw['check_entries'] = stop
            return original(*a, **kw)
        monkeypatch.setattr(ledger, 'record_device_read', before)
    else:
        original = setup.case.register_artifact
        def before(*a, **kw):
            event.set()
            return original(*a, **kw)
        monkeypatch.setattr(setup.case, 'register_artifact', before)
    job = launch(setup, owner, bound, event)
    assert job.status == 'cancelled', job.to_dict()
    assert not owner._uses
    if stage == 'append': assert_empty(setup, owner)
    else: assert not job.result['registered'] and job.result['artifact']['artifact_id'] is None


@pytest.mark.parametrize('mutation', ['new_path_record', 'inventory'])
def test_artifact_final_uses_latest_path_without_kind_filter_and_current_binding(setup, monkeypatch, mutation):
    owner, bound = admitted(setup)
    original = setup.case.register_artifact
    ledger = setup.runtime.provenance
    def before(path, **kw):
        if mutation == 'new_path_record':
            ledger.record_import(setup.case, path, {'server': 'synthetic', 'tool': 'synthetic-import'})
        else:
            inv = ledger.entries(setup.case)[1]
            ledger.record_device_fact(setup.case, I.INVENTORY_FACT, inv['data'], inv['source'])
        return original(path, **kw)
    monkeypatch.setattr(setup.case, 'register_artifact', before)
    job = launch(setup, owner, bound)
    assert job.status == 'failed' and not job._committed
    assert not job.result['registered'] and job.result['artifact']['artifact_id'] is None
    assert job.result['provenance']['ledger_seq'] == 3
    assert len(ledger.entries(setup.case)) == 4
    assert setup.case.load()['artifacts'] == []


@pytest.mark.parametrize('change', ['content', 'name', 'hardlink', 'parent'])
def test_postledger_file_mutation_preserves_receipt_but_refuses_artifact(setup, monkeypatch, change):
    owner, bound = admitted(setup)
    original = setup.case.register_artifact
    def before(path, **kw):
        p = setup.case.dir / path
        if change == 'content':
            os.chmod(p, 0o644)
            content = p.read_bytes()
            p.write_bytes(b'X' + content[1:])
            os.chmod(p, 0o444)
        elif change == 'name':
            content = p.read_bytes()
            p.rename(p.with_suffix('.old'))
            p.write_bytes(content)
            os.chmod(p, 0o444)
        elif change == 'hardlink': os.link(p, p.with_suffix('.link'))
        else:
            p.parent.rename(p.parent.with_name('old-nfc'))
            p.parent.mkdir()
        return original(path, **kw)
    monkeypatch.setattr(setup.case, 'register_artifact', before)
    job = launch(setup, owner, bound)
    assert job.status == 'failed' and job.result['warnings'] == ['artifact_registration_incomplete']
    assert len(setup.runtime.provenance.entries(setup.case)) == 3
    assert setup.case.load()['artifacts'] == [] and not owner._uses


def test_append_path_conflict_is_not_silently_reused(setup, monkeypatch):
    owner, bound = admitted(setup)
    original = setup.runtime.provenance.record_device_read
    def conflicting(case, path, *a, **kw):
        setup.runtime.provenance.record_import(case, path, {'server': 'synthetic', 'tool': 'synthetic-import'})
        return original(case, path, *a, **kw)
    monkeypatch.setattr(setup.runtime.provenance, 'record_device_read', conflicting)
    job = launch(setup, owner, bound)
    assert job.status == 'failed' and job.result is None
    assert [e['kind'] for e in setup.runtime.provenance.entries(setup.case)] == [
        'device-fact', 'device-fact', 'imported-unattested']
    assert setup.case.load()['artifacts'] == []


@pytest.mark.parametrize('point', ['new_fd', 'output_close'])
def test_output_descriptor_failures_are_closed_or_warned_without_unowned_unlink(setup, monkeypatch, point):
    owner, bound = admitted(setup)
    if point == 'new_fd':
        original = R.os.fstat
        original_open = R.os.open
        selected = []
        def opened(name, flags, *a, **kw):
            fd = original_open(name, flags, *a, **kw)
            if type(name) is str and name.startswith('cu-read-') and flags & os.O_EXCL:
                selected.append(fd)
            return fd
        tripped = [False]
        def fstat(fd):
            value = original(fd)
            if not tripped[0] and fd in selected:
                tripped[0] = True
                raise OSError(PRIVATE)
            return value
        monkeypatch.setattr(R.os, 'open', opened)
        monkeypatch.setattr(R.os, 'fstat', fstat)
    else:
        original = R._Output.close
        def close(self):
            original(self)
            return False
        monkeypatch.setattr(R._Output, 'close', close)
    job = launch(setup, owner, bound)
    assert not owner._uses and PRIVATE not in json.dumps(job.to_dict())
    if point == 'new_fd':
        assert job.status == 'failed' and job.error['code'] == 'nfc_cleanup_pending'
        assert len(list((setup.case.dir / 'nfc').glob('cu-read-*'))) == 1
        assert len(setup.runtime.provenance.entries(setup.case)) == 2
    else:
        assert job.status == 'succeeded' and job.result['warnings'] == ['output_close_unconfirmed']


def test_ledger_close_warning_is_not_part_of_entry_hash(setup, monkeypatch):
    from pweh.provenance import _AppendReceipt
    owner, bound = admitted(setup)
    original = setup.runtime.provenance.record_device_read
    def warning(*a, **kw):
        return _AppendReceipt(original(*a, **kw), ('provenance_close_unconfirmed',))
    monkeypatch.setattr(setup.runtime.provenance, 'record_device_read', warning)
    job = launch(setup, owner, bound)
    assert job.status == 'succeeded'
    assert job.result['warnings'] == ['provenance_close_unconfirmed']
    assert job.result['provenance']['ledger_entry_sha256'] == R._entry_hash(
        setup.runtime.provenance.entries(setup.case)[-1])


@pytest.mark.parametrize('fault', ['duplicate', 'missing', 'wrong_source'])
def test_same_entries_helper_checks_uniqueness_source_and_missing_inventory(setup, fault):
    owner, bound = admitted(setup)
    entries = copy.deepcopy(setup.runtime.provenance.entries(setup.case))
    if fault == 'duplicate': entries.append(copy.deepcopy(entries[1]))
    elif fault == 'missing': entries.pop()
    else: entries[0]['source']['tool'] = 'invented'
    with pytest.raises(PwehError):
        I.check_inventory_entries(setup.runtime, setup.case, bound, entries, check=lambda: None)


def test_inventory_helper_ignores_non_authority_cache_warning(setup):
    owner, bound = admitted(setup)
    entries = setup.runtime.provenance.entries(setup.case)
    I.check_inventory_entries(setup.runtime, setup.case,
        replace(bound, warnings=('inventory_cache_write_failed',)), entries, check=lambda: None)
