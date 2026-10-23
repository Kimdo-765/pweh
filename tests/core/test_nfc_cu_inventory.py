"""합성 CU 사실의 독립 admission·기존 Flipper/inventory 호환·폐쇄 schema."""
from __future__ import annotations

import json
import time
from dataclasses import replace

import pytest

from pweh import cu_protocol as C, nfc_inventory as N, schemas
from pweh.errors import PwehError
from pweh.nfc_formats import _NfcFileIdentity
from .test_nfc_inventory import setup, end, observation as flipper_observation, rewrite


def observation(family=C.NtagFamily.NTAG213, **changes):
    identity = _NfcFileIdentity(b'SYNTH01', b'\0\x44', b'\0', family.mifare_version, 'iso14443-3a')
    value = N.CuScanObservation('synthetic-cu-session',
        {'backend': 'posix-tty', 'lock_key': 'tty:synthetic', 'device_id': 'synthetic-device',
         'scope_keys': ['tty:synthetic']}, identity, True, True, True)
    return replace(value, **changes)


def scan(runtime, case, family=C.NtagFamily.NTAG213, **kwargs):
    return N.record_cu_scan(runtime, case, observation(family), deadline=end(), **kwargs)


@pytest.mark.parametrize('family', list(C.NtagFamily))
def test_cu_fact_common_inventory_and_old_flipper_roundtrip(setup, family):
    runtime, case = setup
    ref = scan(runtime, case, family)
    bound = N.add_inventory(runtime, case, ref.scan_ref, deadline=end())
    assert type(ref) is N.CuScanRef and type(bound) is N.BoundTag
    assert N.resolve_inventory(runtime, case, bound.tag_ref, deadline=end()).to_dict() == bound.to_dict()
    N.match_file_identity(bound, replace(observation(family).identity, profile=family.family))
    assert N.add_inventory(runtime, case, ref.scan_ref, deadline=end()).tag_ref == bound.tag_ref
    old = N.record_flipper_scan(runtime, case, flipper_observation(family.family), deadline=end())
    old_bound = N.add_inventory(runtime, case, old.scan_ref, deadline=end())
    assert old_bound.identity_digest == bound.identity_digest
    assert old_bound.tag_ref != bound.tag_ref and type(old) is N.ScanRef
    for name, value in [('nfc-scan', ref.to_dict()), ('nfc-scan', old.to_dict()),
                        ('nfc-inventory', bound.to_dict())]:
        schemas.validate(name, value)
    entries = runtime.provenance.entries(case)
    data = entries[0]['data']
    assert entries[0]['fact_kind'] == N.CU_SCAN_FACT
    assert entries[0]['source'] == {'server': 'nfc-mcp', 'tool': 'nfc_cu_scan'}
    assert data['profile_sha256'] == C.PROFILE_SHA256 and data['firmware_commit'] == C.FIRMWARE_COMMIT
    assert data['read_requests'] == data['pages_retained'] == 2
    assert not ({'pages', 'probe_sha256', 'probe_size', 'scratch_cleanup_confirmed', 'version_crc_valid'} & data.keys())
    assert entries[1]['fact_kind'] == N.INVENTORY_FACT and len(entries) == 4
    public = json.dumps([ref.to_dict(), bound.to_dict(), old.to_dict()]) + repr(ref) + repr(bound) + repr(observation())
    for secret in ('SYNTH01', '53594e54483031', family.mifare_version.hex(), 'synthetic-device'):
        assert secret not in public
    assert old.to_dict()['page_read_performed'] is False
    assert 'rf_off_verified' not in old.to_dict()


@pytest.mark.parametrize('changes', [
    {'session_id': ''}, {'session_id': 'private\n'}, {'session_id': 'x' * 129},
    {'page_identity_match': False}, {'page_identity_match': 1},
    {'reader_crc_check_succeeded': False}, {'reader_crc_check_succeeded': 1},
    {'steps_complete': False}, {'steps_complete': 1}, {'reader_binding': {}},
    {'reader_binding': {'backend': 'posix-tty', 'lock_key': 'x', 'device_id': 'd', 'scope_keys': ['y']}},
])
def test_incomplete_observation_never_creates_fact(setup, changes):
    runtime, case = setup
    with pytest.raises(PwehError) as exc:
        N.record_cu_scan(runtime, case, observation(**changes), deadline=end())
    assert 'private' not in str(exc.value) and exc.value.data == {}
    assert runtime.provenance.entries(case) == []


@pytest.mark.parametrize('field,value', [('uid', b'1234'), ('uid', bytearray(b'SYNTH01')),
    ('atqa_msb', b'\x44\0'), ('atqa_msb', b'\0\0'), ('sak', b'\x08'),
    ('mifare_version', bytes(8)), ('mifare_version', None), ('profile', 'ntag213')])
def test_exact_cu_identity_is_checked_in_core(setup, field, value):
    runtime, case = setup
    item = observation()
    with pytest.raises(PwehError):
        N.record_cu_scan(runtime, case, replace(item, identity=replace(item.identity, **{field: value})), deadline=end())
    assert runtime.provenance.entries(case) == []


@pytest.mark.parametrize('which', ['flipper', 'mapping', 'none'])
def test_other_observation_types_cannot_be_cu_facts(setup, which):
    runtime, case = setup
    item = {'flipper': flipper_observation(), 'mapping': {}, 'none': None}[which]
    with pytest.raises(PwehError):
        N.record_cu_scan(runtime, case, item, deadline=end())
    assert runtime.provenance.entries(case) == []


@pytest.mark.parametrize('field,value', [
    ('profile', N.PROFILE), ('profile_sha256', '0' * 64), ('firmware_commit', N.FIRMWARE_COMMIT),
    ('firmware_claim_verified', True), ('reselection_atomic', 0), ('host_crc_verified', True),
    ('page_read_performed', False), ('page_identity_match', 1), ('reader_crc_check_succeeded', False),
    ('steps_complete', False), ('read_requests', 2.0), ('read_requests', True), ('read_requests', 3),
    ('pages_retained', True), ('pages_retained', 0), ('family', 'ntag216'),
    ('scratch_cleanup_confirmed', True), ('version_crc_valid', True), ('probe_size', 5),
])
def test_chain_valid_cu_data_forgery_rejected(setup, field, value):
    runtime, case = setup
    ref = scan(runtime, case)
    entries = runtime.provenance.entries(case)
    entries[0]['data'][field] = value
    rewrite(runtime, case, entries)
    with pytest.raises(PwehError):
        N.add_inventory(runtime, case, ref.scan_ref, deadline=end())


@pytest.mark.parametrize('mutation', ['source', 'kind', 'data_missing', 'ref_missing', 'atqa', 'same_ref', 'unknown_ref'])
def test_provider_dispatch_does_not_hide_invalid_or_duplicate_refs(setup, mutation):
    runtime, case = setup
    ref = scan(runtime, case)
    old = N.record_flipper_scan(runtime, case, flipper_observation(), deadline=end())
    entries = runtime.provenance.entries(case)
    if mutation == 'source': entries[0]['source']['tool'] = 'flipper_nfc_probe'
    elif mutation == 'kind': entries[0]['fact_kind'] = N.SCAN_FACT
    elif mutation == 'data_missing': entries[0]['data'] = None
    elif mutation == 'ref_missing': entries[0]['data'].pop('scan_ref')
    elif mutation == 'atqa': entries[0]['data']['identity']['atqa_msb'] = '0000'
    elif mutation == 'same_ref': entries[1]['data']['scan_ref'] = ref.scan_ref
    else: entries[1]['fact_kind'] = 'synthetic-unknown'
    rewrite(runtime, case, entries)
    with pytest.raises(PwehError):
        N.add_inventory(runtime, case, old.scan_ref, deadline=end())


def old_public_fixture():
    # CU 분기와 무관하게 이전 공개 shape를 독립 고정한다.
    return {'ok': True, 'schema': 'pweh.nfc-scan/v1', 'scan_ref': 'NS-' + 'a' * 32,
        'family': 'ntag213', 'identity_digest': 'sha256:' + 'b' * 16, 'uid_length': 7,
        'profile': 'flipper-ntag21x-admission-v1', 'inventory_eligible': True,
        'probe_identity_match': True, 'version_crc_valid': True, 'page_read_performed': False,
        'reselection_atomic': False, 'physical_same_tag_verified': False,
        'device_command_termination_verified': False, 'scratch_cleanup_confirmed': True, 'warnings': []}


def cu_public_fixture():
    out = old_public_fixture()
    for key in ('probe_identity_match', 'version_crc_valid', 'scratch_cleanup_confirmed'):
        out.pop(key)
    out.update(profile='cu-ntag21x-v2.2.0-v1', page_read_performed=True, read_requests=2,
        pages_retained=2, page_identity_match=True, reader_crc_check_succeeded=True,
        host_crc_verified=False, rf_off_verified=False)
    return out


@pytest.mark.parametrize('factory', [old_public_fixture, cu_public_fixture])
def test_independent_public_fixture_and_only_known_warning(factory):
    data = factory()
    schemas.validate('nfc-scan', data)
    data['warnings'] = ['provenance_close_unconfirmed']
    schemas.validate('nfc-scan', data)
    data['warnings'].append('private')
    with pytest.raises(PwehError): schemas.validate('nfc-scan', data)


@pytest.mark.parametrize('mutation', ['profile', 'both', 'missing', 'raw', 'false', 'count'])
@pytest.mark.parametrize('factory', [old_public_fixture, cu_public_fixture])
def test_old_new_schema_mixing_rejected(factory, mutation):
    data = factory()
    old = factory is old_public_fixture
    if mutation == 'profile': data['profile'] = C.PROFILE if old else N.PROFILE
    elif mutation == 'both': data['read_requests' if old else 'version_crc_valid'] = 2 if old else True
    elif mutation == 'missing': data.pop('page_read_performed')
    elif mutation == 'raw': data['uid'] = 'PRIVATE'
    elif mutation == 'false': data['physical_same_tag_verified'] = True
    else: data['uid_length'] = True
    with pytest.raises(PwehError): schemas.validate('nfc-scan', data)


@pytest.mark.parametrize('kwargs,code', [({'cancel': lambda: True}, 'cancelled'),
    ({'cancel': lambda: 1}, 'nfc_provenance_invalid')])
def test_precommit_cancel_and_invalid_callback_write_nothing(setup, kwargs, code):
    runtime, case = setup
    with pytest.raises(PwehError) as exc:
        scan(runtime, case, **kwargs)
    assert exc.value.code == code and runtime.provenance.entries(case) == []


def test_final_revalidation_rejects_other_provider_injected_ref(setup, monkeypatch):
    runtime, case = setup
    original = runtime.provenance.record_device_fact
    def changed(*args, **kwargs):
        check = kwargs['check_entries']
        kwargs['check_entries'] = lambda rows: check([{'data': {'scan_ref': 'NS-' + 'c' * 32}}])
        return original(*args, **kwargs)
    monkeypatch.setattr(runtime.provenance, 'record_device_fact', changed)
    with pytest.raises(PwehError): scan(runtime, case)
    assert runtime.provenance.entries(case) == []


def test_late_cancel_and_close_warning_keep_committed_receipt(setup, monkeypatch):
    runtime, case = setup
    cancelled = [False]
    original = runtime.provenance.record_device_fact
    class Receipt(dict):
        warnings = ('provenance_close_unconfirmed',)
    def committed(*args, **kwargs):
        entry = original(*args, **kwargs)
        cancelled[0] = True
        return Receipt(entry)
    monkeypatch.setattr(runtime.provenance, 'record_device_fact', committed)
    ref = scan(runtime, case, cancel=lambda: cancelled[0])
    schemas.validate('nfc-scan', ref.to_dict())
    assert ref.warnings == ('provenance_close_unconfirmed',)
    assert runtime.provenance.entries(case)[0]['data']['scan_ref'] == ref.scan_ref


def test_other_case_and_cache_cannot_supply_cu_scan(setup, auth):
    runtime, case = setup
    ref = scan(runtime, case)
    other = runtime.cases.create(title='합성 다른 CU', authorization=auth)
    (other.dir / 'nfc' / 'inventory.json').write_text(json.dumps(ref.to_dict()))
    with pytest.raises(PwehError): N.add_inventory(runtime, other, ref.scan_ref, deadline=end())
    assert runtime.provenance.entries(other) == []


def test_expired_and_invalid_deadline_have_no_fact(setup):
    runtime, case = setup
    for deadline in (time.monotonic() - 1, 10 ** 400, True):
        with pytest.raises(PwehError):
            N.record_cu_scan(runtime, case, observation(), deadline=deadline)
    assert runtime.provenance.entries(case) == []
