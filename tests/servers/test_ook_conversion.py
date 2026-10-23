"""합성 등록 RAW와 출력 두 inode의 same-FD·단일 commit 수명을 검사한다."""
from __future__ import annotations

import copy
from dataclasses import replace
import hashlib
import json
import os
import stat
import sys
import threading
import time
import traceback
from pathlib import Path
from types import SimpleNamespace

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'mcp-servers/sdr-mcp'))
from sdr_mcp import ook_conversion as A
from pweh import schemas
from pweh.errors import PwehError
from pweh.runtime import get_runtime

PRIVATE = 'SYNTHETIC_OOK_PRIVATE'
OOK = b';pulse data\n;version 1\n;timescale 1us\n100 200\n300 400\n;end\n'


def raw(preset='270'):
    return (f'# {PRIVATE}\nFiletype: Flipper SubGhz RAW File\nVersion: 1\nFrequency: 123456789\n'
            f'Preset: FuriHalSubGhzPresetOok{preset}Async\nProtocol: RAW\nRAW_Data: 100 -200 300 -400\n').encode()


@pytest.fixture
def case(workspace, auth):
    return get_runtime('test').cases.create(title='합성 OOK 변환', authorization=auth)


def attach(case, data=None, relative=f'signals/{PRIVATE}.sub'):
    path = case.dir / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(raw() if data is None else data)
    return case.register_artifact(relative, kind='other', producer='synthetic'), path


def convert(case, entry, **kwargs):
    return A.convert_registered_sub(case, kwargs.pop('artifact_id', entry['id']),
        max_seconds=kwargs.pop('max_seconds', 5), deadline=kwargs.pop('deadline', time.monotonic() + 5),
        cancel=kwargs.pop('cancel', None), **kwargs)


def outputs(case):
    return list((case.dir / 'analysis').glob('rf-ook-*'))


def fail(case, entry, *, code=None, **kwargs):
    with pytest.raises(PwehError) as caught:
        convert(case, entry, **kwargs)
    err = caught.value
    if code:
        assert err.code == code
    assert err.data == {} and err.hint is None and err.__cause__ is None
    assert PRIVATE not in str(err.to_dict())
    assert 'RuntimeError: ' + PRIVATE not in ''.join(traceback.format_exception(err))
    return err


def update(case, **values):
    case._update(lambda meta: meta['artifacts'][0].update(values))


@pytest.mark.parametrize('preset', ['270', '650'])
def test_same_fd_conversion_receipts_and_single_manifest_artifact(case, preset):
    entry, path = attach(case, raw(preset))
    before = path.read_bytes()
    result = convert(case, entry)
    assert set(result) == {'ok', 'report', 'analysis', 'output', 'warnings'}
    assert result['ok'] and result['warnings'] == [] and result['output'] == result['report']['output']
    report, analysis, output = result['report'], result['analysis'], result['output']
    assert report['source'] == {'kind': 'case-artifact', 'artifact_id': entry['id'],
                                'size': len(before), 'sha256': hashlib.sha256(before).hexdigest()}
    assert report['conversion']['pair_count'] == 2 and report['conversion']['total_duration_us'] == 1000
    assert all(report[field] is False for field in A.rf_ook.FALSE_FIELDS)
    schemas.validate('rf-ook-conversion', report)
    manifest = case.dir / analysis['path']; converted = case.dir / output['path']
    assert converted.read_bytes() == OOK and output['size'] == len(OOK)
    assert hashlib.sha256(OOK).hexdigest() == output['sha256']
    encoded = (json.dumps(report, sort_keys=True, ensure_ascii=True, separators=(',', ':'), allow_nan=False) + '\n').encode()
    assert manifest.read_bytes() == encoded and analysis['size'] == len(encoded)
    assert hashlib.sha256(encoded).hexdigest() == analysis['sha256']
    assert manifest.parent == converted.parent and stat.S_IMODE(manifest.parent.stat().st_mode) == 0o700
    assert {p.name for p in manifest.parent.iterdir()} == {'manifest.json', 'converted.ook'}
    assert all(stat.S_IMODE(p.stat().st_mode) == 0o444 for p in (manifest, converted))
    arts = case.artifacts()
    assert len(arts) == 2 and arts[-1]['id'] == analysis['artifact_id']
    assert arts[-1]['producer'] == 'pweh-sdr' and arts[-1]['kind'] == 'other'
    assert arts[-1]['extra'] == {'type': 'rf-ook-conversion'} and arts[-1]['path'] == analysis['path']
    assert path.read_bytes() == before and PRIVATE not in json.dumps(result)


@pytest.mark.parametrize('kwargs', [
    {'artifact_id': 'A-0001\n'}, {'artifact_id': 'A-001'}, {'artifact_id': 1},
    {'max_seconds': True}, {'max_seconds': 0}, {'max_seconds': 6}, {'max_seconds': float('nan')},
    {'max_seconds': float('inf')}, {'max_seconds': 10 ** 500}, {'deadline': True},
    {'deadline': float('inf')}, {'deadline': float('nan')}, {'deadline': 10 ** 500}, {'cancel': 1},
])
def test_exact_worker_args_before_open(case, monkeypatch, kwargs):
    entry, _ = attach(case)
    monkeypatch.setattr(A.safeio, 'open_regular', lambda *a, **k: pytest.fail('입구 거부 뒤 open'))
    fail(case, entry, code='rf_ook_input_invalid', **kwargs)
    assert not outputs(case)


@pytest.mark.parametrize('key,value', [
    ('size', 0), ('size', True), ('size', 1.0), ('size', -1), ('sha256', 'A' * 64),
    ('sha256', 'a' * 64 + '\n'), ('sha256', None), ('is_dir', True), ('is_dir', 0),
    ('path', '/outside'), ('path', '../outside'), ('path', 'signals//a'), ('path', 'signals/./a'),
    ('path', 'signals/../a'), ('path', 'signals/\0a'), ('path', 'forensics/a'), ('path', 'emu/a'),
    ('path', 'x/' * 257 + 'a'), ('path', 'x' * 4097),
])
def test_projection_exact_fields(case, monkeypatch, key, value):
    entry, _ = attach(case)
    update(case, **{key: value})
    monkeypatch.setattr(A.safeio, 'open_regular', lambda *a, **k: pytest.fail('잘못된 색인 open'))
    fail(case, entry, code='rf_ook_input_invalid')


@pytest.mark.parametrize('shape', ['missing', 'duplicate_id', 'duplicate_path', 'not_list'])
def test_artifact_id_and_path_are_each_unique(case, shape):
    entry, _ = attach(case)
    def change(meta):
        if shape == 'missing': meta['artifacts'] = []
        elif shape == 'not_list': meta['artifacts'] = {}
        else:
            row = dict(meta['artifacts'][0])
            row.update({'path': 'signals/other'} if shape == 'duplicate_id' else {'id': 'A-9000'})
            meta['artifacts'].append(row)
    case._update(change)
    fail(case, entry, code='rf_ook_input_invalid')


def test_registered_size_over_limit_rejects_before_read(case, monkeypatch):
    entry, _ = attach(case)
    update(case, size=A.MAX_INPUT_BYTES + 1)
    monkeypatch.setattr(A.safeio, 'open_regular', lambda *a, **k: pytest.fail('한도 초과 open'))
    fail(case, entry, code='rf_ook_input_limit')


@pytest.mark.parametrize('kind', ['symlink', 'parent_link', 'hardlink', 'fifo', 'directory', 'missing'])
def test_links_and_nonregular_input_rejected(case, kind):
    entry, path = attach(case, relative='signals/nested/input.sub')
    if kind == 'parent_link':
        path.parent.rename(path.parent.with_name('moved'))
        path.parent.symlink_to(path.parent.with_name('moved'), target_is_directory=True)
    elif kind == 'hardlink': os.link(path, path.with_name('other'))
    else:
        path.unlink()
        if kind == 'symlink':
            other = path.with_name('other'); other.write_bytes(raw()); path.symlink_to(other)
        elif kind == 'fifo': os.mkfifo(path)
        elif kind == 'directory': path.mkdir()
    fail(case, entry)
    assert not outputs(case)


@pytest.mark.parametrize('real', [None, '/outside/PRIVATE', 'protected'])
def test_fd_containment_and_protected_guard(case, monkeypatch, real):
    entry, _ = attach(case)
    if real == 'protected':
        monkeypatch.setattr(A, 'under_any_case_protected', lambda *a: 'protected')
    else:
        monkeypatch.setattr(A.safeio, 'fd_real_path', lambda *a: real)
    fail(case, entry, code='rf_ook_input_invalid')


@pytest.mark.parametrize('field,value', [('ook_bytes', b'PRIVATE'), ('declared_preset', 'PRIVATE'),
    ('declared_frequency_hz', True), ('duration_count', 3), ('pair_count', 0), ('total_duration_us', 1001),
    ('ook_bytes', OOK.replace(b'100 200', b'0100 200')), ('ook_bytes', OOK.replace(b'100 200', b'100\t200')),
    ('ook_bytes', OOK.replace(b'100 200', b'100 0')), ('ook_bytes', OOK.replace(b';end\n', b';bad\n'))])
def test_forged_conversion_never_publishes(case, monkeypatch, field, value):
    entry, _ = attach(case)
    original = A.rf_ook.convert_sub_raw_to_ook
    monkeypatch.setattr(A.rf_ook, 'convert_sub_raw_to_ook',
                        lambda *a, **k: replace(original(*a, **k), **{field: value}))
    fail(case, entry, code='rf_ook_failed')
    assert not outputs(case)


@pytest.mark.parametrize('stage', ['schema', 'accounting', 'schema_mutation', 'accounting_mutation'])
def test_report_checks_cannot_change_manifest_binding(case, monkeypatch, stage):
    entry, _ = attach(case)
    def check(report):
        if 'mutation' in stage:
            report['source']['sha256'] = '0' * 64
        else: raise RuntimeError(PRIVATE)
    if stage.startswith('schema'):
        monkeypatch.setattr(A.schemas, 'validate', lambda name, report: check(report))
    else:
        monkeypatch.setattr(A.rf_ook, 'validate_ook_accounting', check)
    fail(case, entry, code='rf_ook_failed')
    assert not outputs(case)


@pytest.mark.parametrize('mutation', ['same_inode', 'replace_name', 'parent', 'root'])
def test_converter_return_detects_source_and_parent_changes(case, monkeypatch, mutation):
    entry, path = attach(case, relative='signals/nested/input.sub')
    original = A.rf_ook.convert_sub_raw_to_ook
    def changed(*args, **kwargs):
        value = original(*args, **kwargs)
        if mutation == 'same_inode': path.write_bytes(raw().replace(b'100 -200', b'101 -200'))
        elif mutation == 'replace_name': path.unlink(); path.write_bytes(raw())
        elif mutation == 'parent':
            path.parent.rename(path.parent.with_name('moved')); path.parent.mkdir()
        else:
            case.dir.rename(case.dir.with_name(case.id + '-moved')); case.dir.mkdir()
        return value
    monkeypatch.setattr(A.rf_ook, 'convert_sub_raw_to_ook', changed)
    fail(case, entry, code='rf_ook_input_changed')
    assert not outputs(case)


@pytest.mark.parametrize('target', ['index', 'input', 'ook', 'manifest'])
def test_final_index_and_same_fd_hashes_are_required(case, monkeypatch, target):
    entry, source = attach(case)
    original = case.register_artifact
    def register(relative, **kwargs):
        if target == 'index': update(case, sha256='0' * 64)
        else:
            path = source if target == 'input' else case.dir / relative
            if target == 'ook': path = path.with_name('converted.ook')
            data = path.read_bytes(); path.chmod(0o600); path.write_bytes(bytes([data[0] ^ 1]) + data[1:]); path.chmod(0o444)
            # stat 검사 없이도 held FD의 내용 SHA가 변경을 찾는다.
            monkeypatch.setattr(A, '_check_file', lambda *a: None)
        return original(relative, **kwargs)
    monkeypatch.setattr(case, 'register_artifact', register)
    fail(case, entry, code='rf_ook_input_changed')
    assert not outputs(case) and len(case.artifacts()) == 1


def test_output_final_rehash_mutating_input_is_caught(case, monkeypatch):
    entry, source = attach(case)
    original = A._read_fd
    counts = {}
    def read(fd, *args, **kwargs):
        value = original(fd, *args, **kwargs)
        path = os.readlink(f'/proc/self/fd/{fd}')
        counts[path] = counts.get(path, 0) + 1
        if path.endswith('converted.ook') and counts[path] == 2:
            source.write_bytes(raw().replace(b'100 -200', b'101 -200'))
        return value
    monkeypatch.setattr(A, '_read_fd', read)
    fail(case, entry, code='rf_ook_input_changed')
    assert not outputs(case)


def test_input_one_open_and_every_read_is_bounded_same_fd(case, monkeypatch):
    data = raw() + (b'#' + b'x' * 8000 + b'\n') * 18
    entry, _ = attach(case, data)
    original_open, original_read = A.safeio.open_regular, os.pread
    fds, reads = [], []
    def opened(*args, **kwargs):
        result = original_open(*args, **kwargs); fds.append(result[0]); return result
    def read(fd, size, offset):
        assert 0 < size <= 65536
        if fd in fds: reads.append((fd, size, offset))
        return original_read(fd, size, offset)
    monkeypatch.setattr(A.safeio, 'open_regular', opened)
    monkeypatch.setattr(A.os, 'pread', read)
    convert(case, entry)
    assert len(fds) == 1 and [item[2] for item in reads] == [0, 65536, 131072] * 2
    with pytest.raises(OSError): os.fstat(fds[0])


def test_output_slot_bound_and_existing_paths_are_untouched(case):
    entry, _ = attach(case)
    for number in range(1, 65):
        (case.dir / f'analysis/rf-ook-{number:03d}').mkdir()
    fail(case, entry, code='rf_ook_failed')
    assert len(outputs(case)) == 64
    (case.dir / 'analysis/rf-ook-064').rmdir()
    result = convert(case, entry)
    assert result['output']['path'] == 'analysis/rf-ook-064/converted.ook'


@pytest.mark.parametrize('filename', ['converted.ook', 'manifest.json'])
@pytest.mark.parametrize('stage', ['open', 'fstat', 'write', 'fsync', 'first_hash'])
def test_each_output_fd_failure_cleanup_and_unknown_identity(case, monkeypatch, filename, stage):
    entry, _ = attach(case)
    original_open, original_fstat = os.open, os.fstat
    original_write, original_sync, original_hash = os.write, os.fsync, A._read_fd
    target, tripped, closed = [], [], []
    def opened(path, *args, **kwargs):
        if path == filename and stage == 'open': raise OSError(PRIVATE)
        fd = original_open(path, *args, **kwargs)
        if path == filename: target.append(fd)
        return fd
    def should(fd, point):
        if fd in target and point == stage and not tripped:
            tripped.append(fd); return True
        return False
    def fstat(fd):
        if should(fd, 'fstat'): raise OSError(PRIVATE)
        return original_fstat(fd)
    def write(fd, data):
        if should(fd, 'write'): raise OSError(PRIVATE)
        return original_write(fd, data)
    def sync(fd):
        if should(fd, 'fsync'): raise OSError(PRIVATE)
        return original_sync(fd)
    def read(fd, *args, **kwargs):
        if should(fd, 'first_hash'): raise OSError(PRIVATE)
        return original_hash(fd, *args, **kwargs)
    original_close = os.close
    def close(fd):
        if fd in target: closed.append(fd)
        return original_close(fd)
    monkeypatch.setattr(A.os, 'open', opened); monkeypatch.setattr(A.os, 'fstat', fstat)
    monkeypatch.setattr(A.os, 'write', write); monkeypatch.setattr(A.os, 'fsync', sync)
    monkeypatch.setattr(A.os, 'close', close); monkeypatch.setattr(A, '_read_fd', read)
    fail(case, entry, code='rf_ook_cleanup_incomplete' if stage == 'fstat' else 'rf_ook_failed')
    assert len(case.artifacts()) == 1
    assert all(fd in closed for fd in target)
    if stage == 'fstat': assert (outputs(case)[0] / filename).exists()
    else: assert not outputs(case)


@pytest.mark.parametrize('value', [0, -1, True, None, 100000])
def test_invalid_write_result_is_not_retried_or_committed(case, monkeypatch, value):
    entry, _ = attach(case)
    original = os.write
    def write(fd, data):
        if os.readlink(f'/proc/self/fd/{fd}').endswith('converted.ook'): return value
        return original(fd, data)
    monkeypatch.setattr(A.os, 'write', write)
    fail(case, entry, code='rf_ook_failed')
    assert not outputs(case)


def test_partial_writes_and_parent_mtime_changes_are_supported(case, monkeypatch):
    entry, _ = attach(case)
    original = os.write
    def write(fd, data):
        if '/rf-ook-' in os.readlink(f'/proc/self/fd/{fd}'): return original(fd, data[:7])
        return original(fd, data)
    monkeypatch.setattr(A.os, 'write', write)
    original_register = case.register_artifact
    def register(*args, **kwargs):
        (case.dir / 'analysis/independent').write_bytes(b'other')
        return original_register(*args, **kwargs)
    monkeypatch.setattr(case, 'register_artifact', register)
    assert convert(case, entry)['output']['size'] == len(OOK)


@pytest.mark.parametrize('mutation', ['ook', 'manifest', 'directory', 'unknown'])
def test_replacements_and_unknown_entries_are_preserved(case, monkeypatch, mutation):
    entry, _ = attach(case)
    original = case.register_artifact
    preserved = []
    def register(relative, **kwargs):
        manifest = case.dir / relative
        if mutation == 'unknown': target = manifest.with_name('unknown')
        elif mutation == 'directory':
            manifest.parent.rename(manifest.parent.with_name('held'))
            manifest.parent.mkdir(); target = manifest
        else:
            target = manifest if mutation == 'manifest' else manifest.with_name('converted.ook')
            target.rename(target.with_suffix('.held'))
        target.write_bytes(PRIVATE.encode()); preserved.append(target)
        return original(relative, **kwargs)
    monkeypatch.setattr(case, 'register_artifact', register)
    fail(case, entry, code='rf_ook_cleanup_incomplete')
    assert preserved[0].read_bytes() == PRIVATE.encode() and len(case.artifacts()) == 1


@pytest.mark.parametrize('key,value', [('path', 'analysis/other'), ('size', True), ('size', 1),
                                     ('sha256', '0' * 64), ('is_dir', 0)])
def test_final_artifact_entry_has_exact_binding(case, monkeypatch, key, value):
    entry, _ = attach(case)
    original = case.register_artifact
    def register(*args, **kwargs):
        check = kwargs['check']
        kwargs['check'] = lambda row: check({**row, key: value})
        return original(*args, **kwargs)
    monkeypatch.setattr(case, 'register_artifact', register)
    fail(case, entry, code='rf_ook_input_changed')
    assert not outputs(case)


@pytest.mark.parametrize('when', ['before', 'read', 'conversion', 'output', 'check'])
def test_cancel_before_commit_removes_self_owned_outputs(case, monkeypatch, when):
    entry, _ = attach(case)
    stop = threading.Event()
    if when == 'before': stop.set()
    elif when == 'read':
        original = A._read_fd
        def read(*args, **kwargs):
            result = original(*args, **kwargs); stop.set(); return result
        monkeypatch.setattr(A, '_read_fd', read)
    elif when == 'conversion':
        original = A.rf_ook.convert_sub_raw_to_ook
        def converted(*args, **kwargs):
            result = original(*args, **kwargs); stop.set(); return result
        monkeypatch.setattr(A.rf_ook, 'convert_sub_raw_to_ook', converted)
    elif when == 'output':
        original = A._Output.write
        def write(self, *args, **kwargs):
            original(self, *args, **kwargs); stop.set()
        monkeypatch.setattr(A._Output, 'write', write)
    else:
        original = case.register_artifact
        def register(*args, **kwargs):
            stop.set(); return original(*args, **kwargs)
        monkeypatch.setattr(case, 'register_artifact', register)
    fail(case, entry, code='cancelled', cancel=stop.is_set)
    assert not outputs(case) and len(case.artifacts()) == 1


@pytest.mark.parametrize('value', [None, 1, 'PRIVATE', RuntimeError(PRIVATE)])
def test_cancel_callback_bad_type_or_exception_is_fixed(case, value):
    entry, _ = attach(case)
    def cancel():
        if isinstance(value, Exception): raise value
        return value
    fail(case, entry, code='rf_ook_failed', cancel=cancel)


def test_final_five_seconds_once_after_completed_processing(case, monkeypatch):
    entry, _ = attach(case)
    base = time.monotonic()
    clock = SimpleNamespace(now=base)
    monkeypatch.setattr(A, 'time', SimpleNamespace(monotonic=lambda: clock.now))
    original_write, original_register, original_read = A._Output.write, case.register_artifact, A._read_fd
    seen = []
    def write(self, *args, **kwargs):
        original_write(self, *args, **kwargs); clock.now += 0.25
    def read(fd, size, end, cancel, **kwargs):
        seen.append(end); return original_read(fd, size, end, cancel, **kwargs)
    def register(*args, **kwargs):
        assert kwargs['deadline'] == base + 5.5
        return original_register(*args, **kwargs)
    monkeypatch.setattr(A._Output, 'write', write); monkeypatch.setattr(A, '_read_fd', read)
    monkeypatch.setattr(case, 'register_artifact', register)
    convert(case, entry, deadline=base + 5)
    assert seen == [base + 5] * 3 + [base + 5.5] * 3


@pytest.mark.parametrize('phase', ['processing', 'final'])
def test_expired_budget_never_gets_new_final_time(case, monkeypatch, phase):
    entry, _ = attach(case)
    clock = SimpleNamespace(now=time.monotonic())
    monkeypatch.setattr(A, 'time', SimpleNamespace(monotonic=lambda: clock.now))
    if phase == 'processing':
        original = A._Output.write
        def write(self, *args, **kwargs):
            original(self, *args, **kwargs); clock.now += 10
        monkeypatch.setattr(A._Output, 'write', write)
    else:
        original = case.register_artifact
        def register(*args, **kwargs):
            clock.now = kwargs['deadline']; return original(*args, **kwargs)
        monkeypatch.setattr(case, 'register_artifact', register)
    fail(case, entry, code='time_limit')
    assert not outputs(case)


@pytest.mark.parametrize('code', ['lock_timeout', 'artifact_timeout', 'PRIVATE'])
def test_register_failure_is_fixed_and_precommit_clean(case, monkeypatch, code):
    entry, _ = attach(case)
    def register(*a, **k): raise PwehError(PRIVATE, code=code, data={'private': PRIVATE})
    monkeypatch.setattr(case, 'register_artifact', register)
    fail(case, entry, code='rf_ook_failed' if code == 'PRIVATE' else 'time_limit')
    assert not outputs(case)


@pytest.mark.parametrize('kind', ['cancel', 'audit', 'callback', 'close', 'both'])
def test_actual_receipt_first_preserves_two_outputs_after_commit(case, monkeypatch, kind):
    entry, _ = attach(case)
    stop = threading.Event()
    original = case.register_artifact
    def register(*args, **kwargs):
        committed = kwargs['on_commit']
        def after(row):
            committed(row)
            if kind == 'cancel': stop.set()
            if kind in ('callback', 'both'): raise RuntimeError(PRIVATE)
        kwargs['on_commit'] = after
        return original(*args, **kwargs)
    monkeypatch.setattr(case, 'register_artifact', register)
    if kind == 'audit':
        monkeypatch.setattr(case, 'audit', lambda *a: (_ for _ in ()).throw(RuntimeError(PRIVATE)))
    if kind in ('close', 'both'):
        original_close = A._Output.close
        def close(self): original_close(self); return False
        monkeypatch.setattr(A._Output, 'close', close)
    result = convert(case, entry, cancel=stop.is_set)
    expected = []
    if kind in ('audit', 'callback', 'both'): expected.append('post_commit_callback_failed')
    if kind in ('close', 'both'): expected.append('output_close_unconfirmed')
    assert result['warnings'] == expected and len(case.artifacts()) == 2
    assert (case.dir / result['analysis']['path']).is_file() and (case.dir / result['output']['path']).read_bytes() == OOK
    assert result['analysis']['artifact_id'] == case.artifacts()[-1]['id']


def test_worker_does_not_call_provenance_or_old_analysis(case, monkeypatch):
    entry, _ = attach(case)
    from sdr_mcp import raw_analysis, power_analysis
    from pweh import provenance
    def denied(*a, **k): pytest.fail('이번 변환 범위 밖 호출')
    for name in ('verify', 'record_import', 'record_device_read', 'entries'):
        if hasattr(provenance.ProvenanceLedger, name):
            monkeypatch.setattr(provenance.ProvenanceLedger, name, denied)
    monkeypatch.setattr(raw_analysis, 'analyze_registered_raw', denied)
    monkeypatch.setattr(power_analysis, 'analyze_registered_power', denied)
    assert convert(case, entry)['ok']
