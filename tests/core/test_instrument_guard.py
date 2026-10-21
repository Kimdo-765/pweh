"""합성 전역 증명·식별·표지로 계측기 대상 접근 거부를 검증한다. 실제 PnP는 호출하지 않는다."""
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest

from pweh import instrument_guard as G
from pweh.errors import PwehError, ValidationFailed
from pweh.portidentity import PortIdentity
from pweh.safety.attestations import AttestationStore

MAC = '020000000001'


def pin(store, *, subject=None, binding=None, approve=True):
    subject = subject or {'schema': G.PIN_SCHEMA, 'base_mac': MAC,
                          'native_usb': {'serial': MAC, 'parent_instance': 'USB\\VID_303A&PID_4001\\' + MAC},
                          'boot_usb': [{'serial': 'rom-fixture', 'vid': '303a', 'pid': '1001'}],
                          'aux_usb': [{'vid': '10c4', 'pid': 'ea60', 'serial': 'aux-fixture', 'location_paths': ['usb/1-2']}]}
    rec = store.request('instrument-pin', subject, binding or {'scope': 'instrument', 'instrument_id': MAC}, G.PIN_QUESTIONS)
    if approve:
        rec = store.decide(rec['id'], {q['id']: 'yes' for q in G.PIN_QUESTIONS}, via='cli-tty', by='synthetic')
    return rec


def identity(serial=MAC, **kwargs):
    return PortIdentity('COM31', 'known', present=True, backend='windows', serial=serial, vid='303a', pid='4001', **kwargs)


@pytest.fixture
def env(tmp_path, monkeypatch):
    st = AttestationStore(tmp_path / 'state' / 'attestations')
    rt = SimpleNamespace(attestations=st, config={})
    tags = G.InstrumentTagStore(tmp_path / 'runtime')
    monkeypatch.setattr(G, 'InstrumentTagStore', lambda: tags)
    monkeypatch.setattr(G, 'probe_identity', lambda *a, **k: pytest.fail('실제 PnP fallback 금지'))
    return rt, st, tags


def test_empty_does_not_probe_or_create_tags(env):
    rt, st, tags = env
    assert G.guard_target_port(rt, 'COM31', consumer='esp') is None
    assert not st.dir.exists() and not tags.root.exists()
    pin(st, approve=False)
    assert G.guard_target_port(rt, 'COM31', consumer='esp') is None
    assert not tags.root.exists()


def test_revoked_is_not_active(env):
    rt, st, tags = env
    p = pin(st)
    st.revoke(p['id'], by='synthetic')
    assert G.guard_target_port(rt, 'COM31', consumer='uart') is None


def test_wrong_scope_and_tampered_pin_not_authority(env):
    import json
    rt, st, tags = env
    pin(st, binding={'scope': 'case', 'case_id': 'synthetic'})
    assert G.load_pins(st).state == 'empty'
    p = pin(st)
    f = st.dir / (p['id'] + '.json')
    data = json.loads(f.read_text()); data['fingerprint'] = '0' * 64
    f.write_text(json.dumps(data))
    assert G.load_pins(st).state == 'empty'


def test_valid_old_pin_blocks_as_unknown(env):
    rt, st, tags = env
    pin(st, subject={'base_mac': MAC})
    assert G.load_pins(st).state == 'unknown'
    with pytest.raises(PwehError, match='instrument_identity_unknown'):
        G.guard_target_port(rt, 'COM31', consumer='esp')


@pytest.mark.parametrize('s,role', [(identity(), 'instrument'), (identity('rom-fixture'), 'pinned-instrument-boot-or-rom'),
                                  (replace(identity('aux-fixture'), vid='10c4', pid='ea60'), 'instrument-aux')])
def test_native_boot_aux_global_match(env, s, role):
    rt, st, tags = env
    p = pin(st)
    d = G.classify_instrument(s, G.load_pins(st))
    assert d.code == 'instrument_port' and d.role == role and d.pin_ids == (p['id'],)


def test_native_parent_other_interface_and_pid(env):
    rt, st, tags = env
    p = pin(st)
    s = replace(identity(None, parent_instance=p['subject']['native_usb']['parent_instance']), pid='0009', interface_number='01')
    assert G.classify_instrument(s, G.load_pins(st)).code == 'instrument_port'


@pytest.mark.parametrize('s', [replace(identity(None), status='unknown'), replace(identity(), status='absent', serial=None),
                              replace(identity(None), vid='10c4', pid='ea60'),
                              PortIdentity('socket://127.0.0.1:9000', kind='forwarded')])
def test_unknown_is_not_non_pin(env, s):
    rt, st, tags = env
    pin(st)
    assert G.classify_instrument(s, G.load_pins(st)).code == 'instrument_identity_unknown'


def test_known_other_serial_allowed_and_location_denied(env):
    rt, st, tags = env
    pin(st)
    other = replace(identity('other-fixture'), vid='10c4', pid='ea60')
    assert G.classify_instrument(other, G.load_pins(st)).action == 'pass'
    assert G.classify_instrument(replace(other, location_paths=('usb/1-2',)), G.load_pins(st)).code == 'instrument_port'


@pytest.mark.parametrize('backend,expected', [('windows', 'deny'), ('linux', 'pass')])
@pytest.mark.parametrize('field', ['serial', 'location'])
def test_windows_aux_instance_identity_ignores_case_but_linux_usb_does_not(env, backend, expected, field):
    """Windows PnP 식별자 대소문자 변경은 다른 계측기를 뜻하지 않는다."""
    _, store, _ = env
    subject = {'schema': G.PIN_SCHEMA, 'base_mac': MAC, 'native_usb': {'serial': MAC},
               'aux_usb': [{'vid': '10c4', 'pid': 'ea60', 'serial': 'aux-fixture',
                            'location_paths': ['usb/1-2']}]}
    pin(store, subject=subject)
    current = replace(identity('AUX-FIXTURE' if field == 'serial' else 'other-fixture'),
                      backend=backend, serial_basis='instance-tail' if backend == 'windows' else 'usb-serial',
                      vid='10c4', pid='ea60', location_paths=('USB/1-2',) if field == 'location' else ())
    decision = G.classify_instrument(current, G.load_pins(store))
    assert decision.action == expected
    if expected == 'deny':
        assert decision.code == 'instrument_port' and decision.role == 'instrument-aux'


def test_guard_uses_fresh_authority_and_fake_provider(env, monkeypatch):
    rt, st, tags = env
    p = pin(st)
    calls = []
    def provider(*a, **k):
        calls.append(a); return identity()
    monkeypatch.setattr(G, 'probe_identity', provider)
    with pytest.raises(PwehError, match='instrument_port'):
        G.guard_target_port(rt, 'COM31', consumer='jtagulator')
    st.revoke(p['id'], by='synthetic')
    assert G.guard_target_port(rt, 'COM31', consumer='jtagulator') is None
    assert len(calls) == 1 and not tags.root.exists()


def test_demo_has_no_os_lookup_but_conn_is_not_demo(env):
    rt, st, tags = env
    pin(st)
    assert G.guard_target_port(rt, None, consumer='sigrok', driver='demo').kind == 'memory'


def test_aux_tag_is_deny_hint_not_authority(env):
    rt, st, tags = env
    p = pin(st)
    s = replace(identity('aux-fixture'), vid='10c4', pid='ea60')
    rec = tags.put_from_pin(s, p, attestations=st, role='instrument-aux')
    assert rec['role'] == 'instrument-aux' and tags.read()[0]['attestation_id'] == p['id']
    assert (tags.root.stat().st_mode & 0o777) == 0o700
    assert all((f.stat().st_mode & 0o777) == 0o600 for f in (tags.root / 'tags').iterdir())
    undecided = PortIdentity(s.endpoint_key)
    assert G.classify_instrument(undecided, G.load_pins(st), tags.read()).code == 'instrument_port'
    assert not tags.remove_if_stale(undecided, attestations=st)
    changed = replace(s, serial='another-fixture')
    assert tags.remove_if_stale(changed, attestations=st)
    assert tags.read() == ()
    with pytest.raises(ValidationFailed):
        tags.put_from_pin(changed, p, attestations=st, role='instrument-aux')


def test_tag_cannot_forge_aux_role_or_keep_revoked_authority(env):
    rt, st, tags = env
    p = pin(st)
    with pytest.raises(ValidationFailed):
        tags.put_from_pin(identity(), p, attestations=st, role='instrument-aux')
    tags.put_from_pin(identity(), p, attestations=st, role='instrument')
    st.revoke(p['id'], by='synthetic')
    assert G.classify_instrument(identity(), G.load_pins(st), tags.read()).action == 'pass'
    assert tags.remove_if_stale(identity(), attestations=st)


@pytest.mark.parametrize('fault', ['symlink', 'mode', 'large', 'invalid'])
def test_tags_fail_closed(env, fault, tmp_path):
    rt, st, tags = env
    p = pin(st)
    tags.put_from_pin(identity(), p, attestations=st, role='instrument')
    f = next((tags.root / 'tags').glob('*.json'))
    if fault == 'symlink':
        f.unlink(); f.symlink_to(tmp_path / 'missing')
    elif fault == 'mode':
        f.chmod(0o644)
    elif fault == 'large':
        f.write_bytes(b' ' * 16385)
    else:
        f.write_bytes(b'{}')
    with pytest.raises((OSError, ValueError)):
        tags.read()


def test_authority_limits_fail_closed(env):
    rt, st, tags = env
    st.dir.mkdir(parents=True)
    (st.dir / 'att-0000000000.json').write_bytes(b' ' * 65537)
    assert G.load_pins(st).state == 'unknown'


def test_observed_mac_secondary_denial(env):
    rt, st, tags = env
    pin(st)
    with pytest.raises(PwehError, match='instrument_port'):
        G.guard_observed_mac(rt, '02:00:00:00:00:01', consumer='esp')
