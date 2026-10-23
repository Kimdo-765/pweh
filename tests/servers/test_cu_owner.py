"""CU 고정 frame·페이지 귀속과 use/물리 close/lease 수명을 합성 검증한다."""
from __future__ import annotations

import json
import threading
import time
from dataclasses import replace

import pytest

from nfc_mcp import cu_owner as S
from pweh import portlock, serialtransport
from pweh.errors import PwehError
from pweh.nfc_formats import _NfcFileIdentity
from .fake_cu import setup, FakeCu, UID, VERSIONS, TOTALS, frame, scan_bytes


def operation(owner, method='probe_ntag', *args, deadline=None, cancel=None):
    use = owner.reserve_use(cancel=cancel)
    assert use.claim()
    try:
        return getattr(owner, method)(use, *args, deadline=deadline or time.monotonic() + 45)
    finally:
        use.finish()


def start(owner, *, deadline=None, cancel=None):
    use = owner.reserve_use(opening=True, cancel=cancel)
    assert use.claim()
    try:
        return owner.start(use, deadline=deadline if deadline is not None else time.monotonic() + 5)
    finally:
        use.finish()


def expected(family=213):
    return _NfcFileIdentity(UID, b'\x00\x44', b'\0', VERSIONS[family], 'iso14443-3a')


@pytest.mark.parametrize('setup', ['posix-tty', 'win-helper'], indirect=True)
def test_real_transport_fixed_start_and_close(setup):
    owner = setup.prepare()
    assert setup.opens == [] and setup.fake.writes == []
    assert S.get_cu_session(setup.case.id, owner.session_id) is owner
    assert owner.session_id not in json.dumps(owner.action)
    assert owner.action['scope_keys'] == list(setup.keys)
    assert owner.action['cdc_basis'] == 'observed-interface00'
    device = start(owner)
    assert type(owner._transport) is serialtransport.SerialTransport
    assert device.reader_mode and device.model == 'chameleon-ultra'
    assert device.app_version == '2.2' and device.git_version == 'v2.2.0'
    assert setup.fake.commands == [(1000, b''), (1017, b''), (1033, b''), (1002, b'')]
    settings = setup.opens[0]
    assert (settings.baudrate, settings.bytesize, settings.parity, settings.stopbits) == (115200, 8, 'N', 1)
    assert settings.dtr is True and settings.rts is False and settings.write_timeout == 2
    assert setup.fake.dtr is True and setup.fake.rts is False
    close = S.close_cu_session(owner.case_id, owner.session_id, deadline=time.monotonic() + 1)
    assert close.to_dict() == dict(workers_stopped=True, transport_closed=True, lease_closed=True,
        cleanup_confirmed=True, device_command_termination_verified=False, rf_off_verified=False, reason=None)
    assert owner.close(deadline=time.monotonic() + 1) == close
    assert owner.case_id not in S._REGISTRY


@pytest.mark.parametrize('field,value', [('vid', '1234'), ('pid', '1234'), ('interface_number', '01'),
    ('interface_number', None), ('status', 'unknown'), ('present', False), ('kind', 'unknown'), ('usb_ancestor', None)])
def test_non_native_or_unknown_identity_never_opens(setup, field, value):
    setup.route = replace(setup.route, identity=replace(setup.route.identity, **{field: value}))
    with pytest.raises(PwehError) as caught:
        setup.prepare()
    assert caught.value.code == 'cu_identity_unknown' and caught.value.data == {}
    assert setup.opens == [] and setup.fake.writes == []


@pytest.mark.parametrize('backend', ['loop', 'net-url', 'win-exe'])
def test_unsupported_backend_never_opens(setup, backend):
    setup.route = replace(setup.route, backend=backend)
    with pytest.raises(PwehError, match='CU'):
        setup.prepare()
    assert setup.opens == []


@pytest.mark.parametrize('setup', ['win-helper'], indirect=True)
@pytest.mark.parametrize('invalid', [None, 'second-com', 'wrong-parent', 'mi-parent'])
def test_windows_observed_single_cdc_parent_is_distinct_basis(setup, invalid):
    parent = setup.route.identity.usb_ancestor
    identity = replace(setup.route.identity, device_instance=parent, parent_instance=parent, interface_number=None)
    if invalid == 'second-com':
        setup.keys = tuple(sorted((*setup.keys, 'win:COM4097')))
    elif invalid == 'wrong-parent':
        identity = replace(identity, parent_instance='USB\\OTHER')
    elif invalid == 'mi-parent':
        parent = 'USB\\VID_6868&PID_8686&MI_00\\CU_SYNTHETIC'
        identity = replace(identity, device_instance=parent, parent_instance=parent, usb_ancestor=parent)
    setup.route = replace(setup.route, identity=identity)
    if invalid:
        with pytest.raises(PwehError) as caught:
            setup.prepare()
        assert caught.value.code == 'cu_identity_unknown' and setup.opens == []
    else:
        owner = setup.connect()
        assert owner.action['cdc_basis'] == 'observed-single-cdc-parent'
        assert owner.action['interface_number'] is None


def test_pending_owner_and_whole_sibling_lease_are_exclusive(setup):
    owner = setup.prepare()
    with pytest.raises(PwehError) as caught:
        setup.prepare()
    assert caught.value.code == 'busy'
    with pytest.raises(PwehError):
        portlock.get_manager().acquire(('synthetic-cu-sibling',), owner=portlock.PortOwner(
            server='other', case_id=setup.case.id, ref='synthetic'))
    assert setup.opens == []
    assert owner.close(deadline=time.monotonic() + 1).cleanup_confirmed
    lease = portlock.get_manager().acquire(('synthetic-cu-sibling',), owner=portlock.PortOwner(
        server='other', case_id=setup.case.id, ref='synthetic'))
    lease.close()


@pytest.mark.parametrize('command,data,code', [(1000, b'\x02\x01', 'cu_firmware_unsupported'),
    (1017, b'PRIVATE_VERSION', 'cu_firmware_unsupported'), (1033, b'\x01', 'cu_model_unsupported'),
    (1002, b'\x00', 'cu_reader_required'), (1000, b'bad', 'cu_protocol_invalid')])
def test_wrong_device_never_sends_rf(setup, command, data, code):
    setup.fake.responses[command] = frame(command, data)
    owner = setup.prepare()
    with pytest.raises(PwehError) as caught:
        start(owner)
    assert caught.value.code == code and 'PRIVATE_' not in str(caught.value)
    assert all(cmd < 2000 for cmd, _ in setup.fake.commands)
    assert owner.state == 'terminal' and not owner._lease.closed


@pytest.mark.parametrize('family', [213, 215, 216])
def test_probe_reads_two_first_pages_and_field_off_only_on_last(setup, family):
    setup.fake = FakeCu(family=family)
    owner = setup.connect()
    probe = operation(owner)
    assert probe.identity.uid == UID and probe.identity.atqa_msb == b'\x00\x44'
    assert probe.family.value == family
    assert probe.page_identity_match and probe.reader_crc_check_succeeded and probe.steps_complete
    assert probe.reader_binding == {**owner.route.approval_identity(), 'scope_keys': list(owner.keys)}
    assert not hasattr(probe, 'pages') and UID.hex() not in repr(probe)
    assert setup.fake.commands[4:] == [(1002, b''), (2000, b''),
        (2010, bytes.fromhex('fc0064000860')), (2010, bytes.fromhex('ec006400103000')),
        (2010, bytes.fromhex('e4006400103001'))]
    assert not setup.fake.field


@pytest.mark.parametrize('family', [213, 215, 216])
def test_internal_read_admits_again_and_attributes_only_first_four(setup, family):
    setup.fake = FakeCu(family=family, chunk=3, write_chunk=2)
    owner = setup.connect()
    result = operation(owner, 'read_ntag', expected(family))
    assert result.read_complete and result.stop_reason is None
    assert result.total_pages == result.pages_observed == TOTALS[family]
    assert result.pages == tuple(setup.fake.pages)
    assert not result.physical_same_tag_verified and not result.rf_off_verified
    reads = [data for cmd, data in setup.fake.commands if cmd == 2010 and len(data) == 7]
    assert len(reads) == TOTALS[family] and reads[1][0] == 0xec
    assert all(data[0] == 0xec for data in reads[:-1]) and reads[-1][0] == 0xe4
    assert [data[-1] for data in reads] == list(range(TOTALS[family]))
    assert max(setup.fake.read_sizes) <= 1044


@pytest.mark.parametrize('change', ['uid', 'version', 'untyped'])
def test_read_expected_inventory_mismatch_stops_before_pages(setup, change):
    owner = setup.connect()
    identity = expected()
    if change == 'uid':
        identity = replace(identity, uid=b'\x04' * 7)
    elif change == 'version':
        identity = expected(215)
    else:
        identity = {'uid': UID}
    with pytest.raises(PwehError) as caught:
        operation(owner, 'read_ntag', identity)
    assert caught.value.code in ('nfc_identity_mismatch', 'nfc_input_invalid')
    assert not any(cmd == 2010 and len(data) == 7 for cmd, data in setup.fake.commands)
    assert owner.state == 'terminal'


@pytest.mark.parametrize('scan', [b'', scan_bytes(uid=b'1234'), scan_bytes(atqa=b'\x04\x00'),
    scan_bytes(sak=b'\x08'), scan_bytes(ats=b'\x01'), scan_bytes() + scan_bytes()])
def test_scan_rejection_has_no_raw_version_or_read(setup, scan):
    owner = setup.connect()
    setup.fake.scan_data = scan
    with pytest.raises(PwehError):
        operation(owner)
    assert all(cmd != 2010 for cmd, _ in setup.fake.commands)


@pytest.mark.parametrize('version', [b'', b'\0', b'\0' * 8, VERSIONS[213] + b'\0\0'])
def test_version_rejection_has_no_pages(setup, version):
    owner = setup.connect()
    setup.fake.version = version
    with pytest.raises(PwehError):
        operation(owner)
    assert [data for cmd, data in setup.fake.commands if cmd == 2010] == [bytes.fromhex('fc0064000860')]


@pytest.mark.parametrize('page,content', [(0, b'BAD!'), (0, UID[:3] + b'\0'), (1, b'BAD!')])
def test_uid_bcc_mismatch_never_returns_probe(setup, page, content):
    owner = setup.connect()
    setup.fake.pages[page] = content
    with pytest.raises(PwehError) as caught:
        operation(owner)
    assert caught.value.code == 'nfc_identity_mismatch' and owner.state == 'terminal'


@pytest.mark.parametrize('data,status', [(b'', 0), (b'\0' * 15, 0), (b'\0' * 17, 0), (b'\0' * 16, 1)])
def test_read_invalid_response_stops_probe(setup, data, status):
    owner = setup.connect()
    setup.fake.responses[(2010, bytes.fromhex('ec006400103000'))] = frame(2010, data, status=status)
    with pytest.raises(PwehError) as caught:
        operation(owner)
    assert caught.value.code == 'nfc_scan_invalid'
    assert setup.fake.commands[-1][1][-1] == 0


@pytest.mark.parametrize('failure', ['response', 'cancel', 'timeout'])
def test_read_after_admission_keeps_unknown_pages_and_terminal(setup, monkeypatch, failure):
    owner = setup.connect()
    cancelled = threading.Event()
    key = (2010, bytes.fromhex('ec006400103003'))
    if failure == 'response':
        setup.fake.responses[key] = frame(2010, b'\0', status=0)
    elif failure == 'timeout':
        monkeypatch.setattr(S, 'COMMAND_SECONDS', .005)
        setup.fake.responses[key] = b''
    else:
        def stop(cmd, data):
            cancelled.set()
            return setup.fake.response(cmd, data)
        setup.fake.responses[key] = stop
    result = operation(owner, 'read_ntag', expected(), cancel=cancelled.is_set)
    assert result.pages_observed == 3 and result.pages[:3] == tuple(setup.fake.pages[:3])
    assert all(page is None for page in result.pages[3:])
    assert not result.read_complete and owner.state == 'terminal'
    assert result.stop_reason == {'response': 'nfc_scan_invalid', 'cancel': 'cancelled', 'timeout': 'time_limit'}[failure]
    before = list(setup.fake.commands)
    with pytest.raises(PwehError):
        owner.reserve_use()
    assert setup.fake.commands == before


@pytest.mark.parametrize('bad', ['lrc', 'wrong-command', 'two-frames', 'partial-tail', 'queued-extra', 'eof', 'read-error', 'write-error'])
def test_wire_fault_is_terminal_and_does_not_send_suffix(setup, bad):
    owner = setup.connect()
    answer = frame(1002, b'\1')
    if bad == 'lrc':
        answer = answer[:-1] + bytes((answer[-1] ^ 1,))
    elif bad == 'wrong-command':
        answer = frame(1000, b'\1')
    elif bad in ('two-frames', 'queued-extra'):
        answer += frame(1002, b'\1')
        setup.fake.chunk = 11 if bad == 'queued-extra' else 4096
    elif bad == 'partial-tail':
        answer += b'\x11'
        setup.fake.chunk = 4096
    elif bad == 'eof':
        answer = b''
        setup.fake.before_read = lambda size: setattr(setup.fake, 'is_open', False)
    elif bad == 'read-error':
        def failed(size):
            raise OSError('PRIVATE_READ_SENTINEL')
        setup.fake.before_read = failed
    elif bad == 'write-error':
        def failed(data):
            raise OSError('PRIVATE_WRITE_SENTINEL')
        setup.fake.before_write = failed
    setup.fake.responses[1002] = answer
    with pytest.raises(PwehError) as caught:
        operation(owner)
    assert 'PRIVATE_' not in str(caught.value) and caught.value.data == {}
    assert caught.value.__cause__ is None and owner.state == 'terminal'
    assert all(cmd != 2000 for cmd, _ in setup.fake.commands)


def test_idle_bytes_and_changed_mode_stop_before_scan(setup):
    owner = setup.connect()
    setup.fake.buffer[:] = b'PRIVATE_IDLE'
    before = len(setup.fake.writes)
    with pytest.raises(PwehError):
        operation(owner)
    assert len(setup.fake.writes) == before and owner.state == 'terminal'


def test_mode_is_rechecked_for_each_operation(setup):
    owner = setup.connect()
    setup.fake.responses[1002] = frame(1002, b'\0')
    with pytest.raises(PwehError) as caught:
        operation(owner)
    assert caught.value.code == 'cu_reader_required'
    assert all(cmd != 2000 for cmd, _ in setup.fake.commands)


@pytest.mark.parametrize('change', ['scope', 'route', 'role', 'guard', 'authorization', 'deadline'])
def test_fresh_failure_sends_no_next_frame(setup, monkeypatch, change):
    owner = setup.connect()
    def failed(*args, **kwargs):
        raise PwehError('PRIVATE_CALLBACK', code='authorization_required' if change == 'authorization' else 'instrument_port')
    if change == 'scope':
        setup.keys = tuple(sorted((*setup.keys, 'new-sibling')))
    elif change == 'route':
        setup.route = replace(setup.route, device_id='new-device')
    elif change == 'role':
        monkeypatch.setattr(S.portlock.get_role_store(), 'assert_probe_allowed', failed)
    elif change == 'guard':
        monkeypatch.setattr(S, 'guard_target_port', failed)
    elif change == 'authorization':
        monkeypatch.setattr(setup.runtime, 'case', failed)
    else:
        now = time.monotonic()
        monkeypatch.setattr(S, '_roles', lambda *a: monkeypatch.setattr(S.time, 'monotonic', lambda: now + 100))
    before = list(setup.fake.commands)
    with pytest.raises(PwehError) as caught:
        operation(owner)
    assert 'PRIVATE_' not in str(caught.value) and setup.fake.commands == before
    assert owner.state == 'terminal'


def test_reservation_cancel_and_finished_cancel_do_not_break_next_use(setup):
    owner = setup.connect()
    use = owner.reserve_use()
    with pytest.raises(PwehError) as caught:
        owner.reserve_use()
    assert caught.value.code == 'busy'
    use.cancel()
    assert not use.claim() and setup.fake.cancel_calls == 0
    current = owner.reserve_use()
    assert current.claim()
    use.cancel()
    assert setup.fake.cancel_calls == 0
    current.finish()
    assert operation(owner).steps_complete


def test_claimed_use_must_run_and_finish_in_same_worker(setup):
    owner = setup.connect()
    use = owner.reserve_use()
    assert use.claim()
    results = []
    def other():
        for fn in (lambda: use.check(time.monotonic() + 1), use.finish):
            try:
                fn()
            except PwehError as exc:
                results.append(exc.code)
    thread = threading.Thread(target=other)
    thread.start()
    thread.join(1)
    assert results == ['cu_protocol_invalid', 'cu_protocol_invalid']
    use.finish()


@pytest.mark.parametrize('deadline', [True, '5', float('nan'), float('inf'), 10 ** 400])
def test_invalid_deadlines_are_fixed_before_open(setup, deadline):
    owner = setup.prepare()
    with pytest.raises(PwehError) as caught:
        start(owner, deadline=deadline)
    assert caught.value.code == 'nfc_input_invalid' and setup.opens == []


@pytest.mark.parametrize('value', ['PRIVATE_CANCEL', 1, None])
def test_cancel_callback_exact_bool_and_no_raw_error(setup, value):
    owner = setup.connect()
    use = owner.reserve_use(cancel=lambda: value)
    with pytest.raises(PwehError) as caught:
        use.claim()
    assert caught.value.data == {} and 'PRIVATE_' not in str(caught.value)
    assert not owner._uses


def test_late_open_cancel_keeps_lease_until_worker_and_close(setup):
    entered, release = threading.Event(), threading.Event()
    owner = setup.prepare()
    use = owner.reserve_use(opening=True)
    setup.fake.before_open = lambda: (entered.set(), release.wait(2))
    errors = []
    def worker():
        assert use.claim()
        try:
            owner.start(use, deadline=time.monotonic() + 5)
        except PwehError as exc:
            errors.append(exc.code)
        finally:
            use.finish()
    thread = threading.Thread(target=worker)
    thread.start()
    try:
        assert entered.wait(1)
        use.cancel()
        pending = owner.close(deadline=time.monotonic() + .01)
        assert not pending.cleanup_confirmed and pending.reason == 'worker_pending'
        assert not owner._lease.closed and owner.case_id in S._REGISTRY
    finally:
        release.set()
        thread.join(2)
    assert errors == ['cancelled'] and setup.fake.writes == []
    assert owner.close(deadline=time.monotonic() + 1).cleanup_confirmed


def test_blocked_read_close_does_not_close_transport_or_release_lease(setup):
    owner = setup.connect()
    entered, release = threading.Event(), threading.Event()
    use = owner.reserve_use()
    setup.fake.before_read = lambda size: (entered.set(), release.wait(2))
    errors = []
    def worker():
        assert use.claim()
        try:
            owner.probe_ntag(use, deadline=time.monotonic() + 45)
        except PwehError as exc:
            errors.append(exc.code)
        finally:
            use.finish()
    thread = threading.Thread(target=worker)
    thread.start()
    try:
        assert entered.wait(1)
        pending = owner.close(deadline=time.monotonic() + .01)
        assert pending.reason == 'worker_pending' and not pending.lease_closed
        assert setup.fake.close_calls == 0 and setup.fake.cancel_calls > 0
    finally:
        release.set()
        thread.join(2)
    assert errors == ['cancelled'] and not any(cmd == 2000 for cmd, _ in setup.fake.commands)
    assert owner.close(deadline=time.monotonic() + 1).cleanup_confirmed


@pytest.mark.parametrize('setup', ['posix-tty', 'win-helper'], indirect=True)
def test_unconfirmed_physical_close_keeps_owner_and_whole_lease(setup):
    owner = setup.connect()
    setup.fake.close_verified = False
    result = owner.close(deadline=time.monotonic() + 1)
    assert result.reason == 'transport_close_unconfirmed' and not result.lease_closed
    assert S.get_cu_session(owner.case_id, owner.session_id) is owner
    with pytest.raises(PwehError):
        setup.prepare()
    setup.fake.close_verified = True
    assert owner.close(deadline=time.monotonic() + 1).cleanup_confirmed


def test_physical_closed_but_lease_close_failure_is_preserved(setup, monkeypatch):
    owner = setup.connect()
    original = owner._lease.close
    def failed():
        raise OSError('PRIVATE_LEASE_CLOSE')
    monkeypatch.setattr(owner._lease, 'close', failed)
    result = owner.close(deadline=time.monotonic() + 1)
    assert result.transport_closed and not result.lease_closed and result.reason == 'lease_close_unconfirmed'
    assert owner.case_id in S._REGISTRY
    monkeypatch.setattr(owner._lease, 'close', original)
    assert owner.close(deadline=time.monotonic() + 1).cleanup_confirmed


def test_partial_open_error_adopts_transport_and_preserves_unknown(setup, monkeypatch):
    owner = setup.prepare()
    setup.fake.is_open = True
    setup.fake.close_verified = False
    transport = serialtransport.SerialTransport(setup.fake)
    def failed(*a, **kw):
        raise serialtransport.SerialOpenError(transport, OSError('PRIVATE_OPEN'))
    monkeypatch.setattr(S.serialtransport, 'open_serial', failed)
    with pytest.raises(PwehError) as caught:
        start(owner)
    assert caught.value.code == 'cu_cleanup_unknown' and 'PRIVATE_' not in str(caught.value)
    assert owner._transport is transport and not owner._lease.closed
    assert not owner.close(deadline=time.monotonic() + 1).cleanup_confirmed
    setup.fake.close_verified = True
    assert owner.close(deadline=time.monotonic() + 1).cleanup_confirmed


def test_cleanup_thread_start_failure_is_retryable_without_lost_owner(setup, monkeypatch):
    owner = setup.connect()
    with monkeypatch.context() as local:
        local.setattr(threading.Thread, 'start', lambda self: (_ for _ in ()).throw(RuntimeError('PRIVATE_THREAD')))
        result = owner.close(deadline=time.monotonic() + 1)
    assert result.reason == 'cleanup_failed' and not result.cleanup_confirmed
    assert owner.case_id in S._REGISTRY and not owner._lease.closed
    assert owner.close(deadline=time.monotonic() + 1).cleanup_confirmed


def test_exact_case_and_session_lookup_never_closes_other_owner(setup):
    owner = setup.connect()
    for case_id, session_id in ((owner.case_id, 'other'), ('other', owner.session_id), (owner.case_id, True)):
        with pytest.raises(PwehError) as caught:
            S.close_cu_session(case_id, session_id, deadline=time.monotonic() + 1)
        assert caught.value.code == 'nfc_input_invalid'
    assert setup.fake.close_calls == 0 and not owner._lease.closed
