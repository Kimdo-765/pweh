"""등록 admission과 합성 raw로 persistent worker·HB·join/lease 경계를 검증한다."""
from __future__ import annotations

from dataclasses import asdict
import json
import threading
import time
from types import SimpleNamespace

import pytest

from espprobe_mcp import serial_owner as S
from pweh import espprobe_admission as A, espprobe_protocol as P
from pweh.errors import PwehError
from pweh.portlock import PortOwner
from pweh.serialtransport import SerialOpenError, SerialTransport
from core.test_espprobe_admission import make_inputs
from .fake_espprobe_serial import Peer, TOKEN, encode


def until(predicate, timeout=2):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        if predicate():
            return
        threading.Event().wait(.005)
    assert predicate()


class Raw:
    def __init__(self, admission, fault=''):
        release = admission.release
        fields = {key: getattr(release, key) for key in (
            'fw_name', 'fw_version', 'build_profile', 'board', 'git_commit', 'idf_version',
            'image_sha256', 'app_elf_sha256')}
        fields.update(base_mac=admission.base_mac, chip_revision=admission.chip_revision,
                      usb_vid=release.usb.vid, usb_pid=release.usb.pid, usb_product=release.usb.product)
        self.peer = Peer(fields, fault=fault)
        self.condition = threading.Condition()
        self.rx = bytearray()
        self.timeout, self.write_timeout = .05, 5.
        self.is_open, self.dtr, self.rts = False, True, True
        self.read_chunk, self.write_chunk = 7, 11
        self.open_calls = self.close_calls = self.write_calls = self.wakes = 0
        self.threads = set()
        self.closed_event = threading.Event()
        self.open_enter = threading.Event()
        self.open_gate = threading.Event()
        self.open_gate.set()
        self.close_enter = threading.Event()
        self.close_gate = threading.Event()
        self.close_gate.set()
        self.write_enter = threading.Event()
        self.write_gate = threading.Event()
        self.write_gate.set()
        self.close_fails = False
        self.after_write = None
        self.response_transform = lambda value: value

    def open(self):
        self.open_calls += 1
        self.threads.add(threading.get_ident())
        assert self.dtr is self.rts is False
        self.open_enter.set()
        assert self.open_gate.wait(4)
        self.is_open = True

    def close(self):
        self.close_calls += 1
        self.threads.add(threading.get_ident())
        self.close_enter.set()
        assert self.close_gate.wait(4)
        if self.close_fails:
            raise OSError('PRIVATE-CLOSE-COM4096')
        self.is_open = False
        self.closed_event.set()
        self.cancel_read()

    def cancel_read(self):
        with self.condition:
            self.wakes += 1
            self.condition.notify_all()

    def read(self, size):
        assert 0 < size <= 16384
        self.threads.add(threading.get_ident())
        with self.condition:
            if not self.rx and self.is_open:
                self.condition.wait(self.timeout)
            size = min(size, self.read_chunk, len(self.rx))
            result = bytes(self.rx[:size])
            del self.rx[:size]
            return result

    def write(self, data):
        self.threads.add(threading.get_ident())
        self.write_calls += 1
        assert 0 < self.write_timeout <= 5
        self.write_enter.set()
        assert self.write_gate.wait(4)
        part = data[:self.write_chunk]
        answer = self.response_transform(self.peer.feed(part))
        with self.condition:
            self.rx.extend(answer)
            self.condition.notify_all()
        if self.after_write:
            self.after_write()
        return len(part)


@pytest.fixture
def setup(monkeypatch, isolated_ports):
    contexts = []
    manager = isolated_ports['manager']

    def make(*, fault='', case_id=None):
        inputs = make_inputs(case_id=case_id or 'owner-' + str(len(contexts)), endpoint='COM4096')
        admission = A.validate_probe_admission(**inputs)
        lease = manager.acquire(admission.claim_keys, owner=PortOwner('probe-test', admission.case_id, 'synthetic'))
        raw = Raw(admission, fault)
        transport = SerialTransport(raw)
        owner = S.reserve_probe_owner(admission.case_id, admission, lease)
        events = []

        def before():
            events.append('before')
            lease.assert_held(admission.claim_keys)

        def after():
            events.append('after')
            lease.assert_held(admission.claim_keys)

        env = SimpleNamespace(owner=owner, raw=raw, transport=transport, lease=lease,
                              admission=admission, before=before, after=after, events=events)
        contexts.append(env)
        return env

    def opened(route, settings, *, lease, before_io, serial_factory=None, helper_factory=None):
        env = next(item for item in contexts if item.lease is lease)
        assert route is env.admission.route and serial_factory is helper_factory is None
        assert (settings.baudrate, settings.bytesize, settings.parity, settings.stopbits) == (115200, 8, 'N', 1)
        assert settings.timeout == .05 and settings.dtr is settings.rts is False
        before_io()
        env.raw.dtr, env.raw.rts = settings.dtr, settings.rts
        env.raw.open()
        return env.transport

    monkeypatch.setattr(S, 'open_serial', opened)
    env = make()
    env.make, env.opened, env.manager = make, opened, manager
    yield env
    for item in contexts:
        item.raw.open_gate.set()
        item.raw.write_gate.set()
        item.raw.close_gate.set()
        item.raw.close_fails = False
        item.owner.abort()
        result = item.owner.close(deadline=time.monotonic() + 2)
        assert result.cleanup_confirmed
        assert item.admission.case_id not in S._REGISTRY


def start(env, **kwargs):
    return env.owner.start(before_open=env.before, after_open=env.after,
                           deadline=kwargs.pop('deadline', time.monotonic() + 3), **kwargs)


def background(function):
    results = []

    def work():
        try:
            results.append(function())
        except BaseException as exc:
            results.append(exc)

    thread = threading.Thread(target=work)
    thread.start()
    return thread, results


def assert_locked(env):
    with pytest.raises(PwehError):
        env.manager.acquire(env.admission.claim_keys, owner=PortOwner('other', 'other', 'synthetic'))


@pytest.mark.parametrize('finish', ['release', 'close'])
def test_persistent_single_worker_and_fixed_wire(setup, finish):
    hello = start(setup)
    assert hello.session_token == TOKEN and setup.events == ['before', 'after']
    first = setup.owner.self_test(deadline=time.monotonic() + 2)
    second = setup.owner.self_test(deadline=time.monotonic() + 2)
    assert first.self_tests == 1 and second.self_tests == 2 and second.heartbeat_acked > first.heartbeat_acked
    assert_locked(setup)
    closed = getattr(setup.owner, finish)(deadline=time.monotonic() + 2)
    assert closed == S.ProbeCloseResult(True, True, True, True, True, None)
    assert setup.raw.open_calls == setup.raw.close_calls == 1 and len(setup.raw.threads) == 1
    frames = setup.raw.peer.frames
    assert frames[0][:4] == (P.REQ, P.HELLO, 1, 0)
    assert frames[-1][:4] == (P.REQ, P.RELEASE if finish == 'release' else P.BYE, 2, TOKEN)
    assert all(frame[0] == P.HB for frame in frames[1:-1])
    assert setup.owner.close(deadline=time.monotonic() + 1) == closed


def test_reserved_close_and_exact_admission_lease(setup):
    assert setup.owner.snapshot() == S.ProbeStatus('reserved', False, 0, 0, 0, None)
    with pytest.raises(S.ProbeOwnerError) as caught:
        S.reserve_probe_owner('wrong', setup.admission, setup.lease)
    assert caught.value.code == 'instrument_identity_unknown' and caught.value.data == {}
    with pytest.raises(S.ProbeOwnerError) as caught:
        S.reserve_probe_owner(setup.admission.case_id, setup.admission, setup.lease)
    assert caught.value.code == 'port_busy'
    assert setup.owner.close(deadline=time.monotonic() + 1).cleanup_confirmed
    assert setup.raw.open_calls == setup.raw.write_calls == 0


def test_wrong_lease_is_not_adopted(setup):
    lease = setup.manager.acquire(('win:COM4097',), owner=PortOwner('test', 'test', 'synthetic'))
    try:
        with pytest.raises(S.ProbeOwnerError) as caught:
            S.reserve_probe_owner(setup.admission.case_id, setup.admission, lease)
        assert caught.value.code == 'route_changed' and not lease.closed
    finally:
        lease.close()


@pytest.mark.parametrize('value', [None, True, '3', float('nan'), float('inf'), 10**400])
def test_deadline_invalid_no_open(setup, value):
    with pytest.raises(S.ProbeOwnerError):
        start(setup, deadline=value)
    assert setup.raw.open_calls == 0


@pytest.mark.parametrize('phase', ['before', 'after'])
@pytest.mark.parametrize('failure', ['exception', 'non-none', 'expired', 'cancel'])
def test_fresh_failure_sends_no_hello(setup, phase, failure):
    event = threading.Event()
    end = time.monotonic() + .1

    def callback():
        if failure == 'exception':
            raise PwehError('PRIVATE-COM4096', code='route_changed')
        if failure == 'non-none':
            return True
        if failure == 'expired':
            event.wait(.11)
        if failure == 'cancel':
            event.set()

    setattr(setup, phase, callback)
    with pytest.raises(S.ProbeOwnerError) as caught:
        start(setup, deadline=end, cancel=event.is_set)
    assert 'PRIVATE' not in str(caught.value) and caught.value.data == {}
    assert setup.raw.peer.frames == [] and setup.lease.closed
    assert setup.raw.open_calls == (phase == 'after')


def test_start_once_and_status_has_no_identity(setup):
    start(setup)
    with pytest.raises(S.ProbeOwnerError) as caught:
        start(setup)
    assert caught.value.code == 'port_busy' and setup.raw.open_calls == 1
    text = json.dumps(asdict(setup.owner.snapshot()))
    for secret in ('COM4096', setup.admission.base_mac, str(TOKEN), setup.admission.pin_id):
        assert secret not in text


def test_thread_start_failure_joins_no_unstarted_thread(setup, monkeypatch):
    original = threading.Thread.start

    def fail(thread):
        if thread.name == 'pweh-probe-serial':
            raise RuntimeError('PRIVATE-THREAD')
        return original(thread)

    monkeypatch.setattr(threading.Thread, 'start', fail)
    with pytest.raises(S.ProbeOwnerError):
        start(setup)
    assert setup.raw.open_calls == 0 and setup.lease.closed
    assert setup.owner._thread.ident is None


def test_abort_before_worker_claim_never_opens(setup, monkeypatch):
    entered, gate = threading.Event(), threading.Event()
    claim = setup.owner._handoff.claim_worker

    def delayed():
        entered.set()
        assert gate.wait(2)
        return claim()

    monkeypatch.setattr(setup.owner._handoff, 'claim_worker', delayed)
    thread, result = background(lambda: start(setup))
    assert entered.wait(1)
    setup.owner.abort()
    assert_locked(setup)
    gate.set()
    thread.join(2)
    assert not thread.is_alive() and isinstance(result[0], S.ProbeOwnerError)
    assert setup.raw.open_calls == 0 and setup.lease.closed


def test_late_open_cancel_keeps_lease_until_worker_closes(setup):
    setup.raw.open_gate.clear()
    thread, result = background(lambda: start(setup))
    assert setup.raw.open_enter.wait(1)
    setup.owner.abort()
    state = setup.owner.close(deadline=time.monotonic() + .05)
    assert not state.cleanup_confirmed and not state.workers_stopped
    assert_locked(setup)
    setup.raw.open_gate.set()
    thread.join(2)
    assert not thread.is_alive() and isinstance(result[0], S.ProbeOwnerError)
    assert setup.raw.peer.frames == [] and setup.raw.close_calls == 1 and setup.lease.closed


def test_late_write_cancel_sends_no_suffix_or_cleanup(setup):
    setup.raw.write_gate.clear()
    thread, result = background(lambda: start(setup))
    assert setup.raw.write_enter.wait(1)
    setup.owner.abort()
    assert not setup.owner.close(deadline=time.monotonic() + .05).cleanup_confirmed
    assert_locked(setup)
    setup.raw.write_gate.set()
    thread.join(2)
    assert not thread.is_alive() and isinstance(result[0], S.ProbeOwnerError)
    assert setup.raw.write_calls == 1 and setup.raw.peer.frames == [] and setup.lease.closed


def test_partial_open_error_adopts_transport_until_confirmed(setup, monkeypatch):
    setup.raw.is_open = True
    setup.raw.close_fails = True

    def fail(*args, **kwargs):
        raise SerialOpenError(setup.transport, RuntimeError('PRIVATE-OPEN'))

    monkeypatch.setattr(S, 'open_serial', fail)
    with pytest.raises(S.ProbeOwnerError) as caught:
        start(setup)
    assert caught.value.code == 'espprobe_cleanup_unknown' and caught.value.owner is setup.owner
    assert setup.owner.state == 'orphan' and not setup.lease.closed
    assert_locked(setup)
    setup.raw.close_fails = False
    assert setup.owner.close(deadline=time.monotonic() + 1).cleanup_confirmed


def test_protocol_ack_does_not_release_blocked_physical_close(setup):
    start(setup)
    setup.raw.close_gate.clear()
    first = setup.owner.close(deadline=time.monotonic() + .1)
    assert setup.raw.close_enter.is_set() and first.protocol_released
    assert not first.workers_stopped and not first.cleanup_confirmed and not setup.lease.closed
    assert_locked(setup)
    second = setup.owner.close(deadline=time.monotonic() + .05)
    assert not second.cleanup_confirmed and setup.raw.close_calls == 1
    setup.raw.close_gate.set()
    assert setup.owner.close(deadline=time.monotonic() + 1).cleanup_confirmed
    assert setup.raw.close_calls == 1


def test_close_failure_retry_same_handle_no_protocol_replay(setup):
    start(setup)
    setup.raw.close_fails = True
    first = setup.owner.release(deadline=time.monotonic() + .5)
    assert first.protocol_released and first.workers_stopped and not first.transport_closed
    assert not first.cleanup_confirmed and not setup.lease.closed
    assert_locked(setup)
    setup.raw.close_fails = False
    second = setup.owner.close(deadline=time.monotonic() + 1)
    assert second.cleanup_confirmed and setup.raw.peer.cleanup_count == 1 and setup.raw.open_calls == 1


def test_lease_close_failure_preserves_owner(setup, monkeypatch):
    start(setup)
    close = setup.lease.close

    def fail():
        raise OSError('PRIVATE-LEASE')

    monkeypatch.setattr(setup.lease, 'close', fail)
    first = setup.owner.close(deadline=time.monotonic() + 1)
    assert first.workers_stopped and first.transport_closed and not first.lease_closed
    assert setup.admission.case_id in S._REGISTRY
    assert_locked(setup)
    monkeypatch.setattr(setup.lease, 'close', close)
    assert setup.owner.close(deadline=time.monotonic() + 1).cleanup_confirmed
    assert setup.raw.close_calls == 1


@pytest.mark.parametrize('fault,expected', [('drop-first-cleanup', True), ('drop-cleanup', False)])
def test_cleanup_one_exact_retry_and_independent_physical_result(setup, fault, expected):
    setup.raw.peer.fault = fault
    start(setup)
    result = setup.owner.release(deadline=time.monotonic() + .25)
    if not result.cleanup_confirmed:
        result = setup.owner.close(deadline=time.monotonic() + 1)
    assert result.protocol_released is expected and result.cleanup_confirmed
    assert setup.raw.peer.cleanup_count == 2
    assert result.reason == (None if expected else 'espprobe_timeout')
    assert [frame[1] for frame in setup.raw.peer.frames if frame[0] == P.REQ][1:] == [P.RELEASE, P.RELEASE]


def test_wrong_hello_nonce_has_no_cleanup_tx(setup):
    setup.raw.peer.fault = 'wrong-nonce'
    with pytest.raises(S.ProbeOwnerError):
        start(setup)
    assert [frame[1] for frame in setup.raw.peer.frames] == [P.HELLO]
    assert setup.lease.closed


def test_policy_failure_valid_envelope_allows_one_bye(setup):
    setup.raw.peer.fields['fw_version'] = '0.0.0'
    with pytest.raises(S.ProbeOwnerError) as caught:
        start(setup)
    assert caught.value.code == 'firmware_not_pinned'
    assert [frame[1] for frame in setup.raw.peer.frames] == [P.HELLO, P.BYE]
    assert not setup.owner.snapshot().hello_verified


@pytest.mark.parametrize('bad', ['wrong-hb-token', 'crc', 'extra', 'evt', 'partial'])
def test_terminal_wire_never_resyncs_or_reconnects(setup, bad):
    start(setup)
    until(lambda: setup.owner.snapshot().heartbeat_acked >= 1)

    def mutate(value):
        if not value:
            return value
        if bad == 'crc':
            return value[:-2] + bytes((value[-2] ^ 1, 0))
        if bad == 'extra':
            return value + value
        if bad == 'evt':
            return encode(P.EVT, 0, 1, TOKEN)
        if bad == 'partial':
            return value[:-1]
        return value

    setup.raw.read_chunk = 16384
    setup.raw.response_transform = mutate
    if bad == 'wrong-hb-token':
        setup.raw.peer.fault = bad
    with pytest.raises(S.ProbeOwnerError):
        setup.owner.self_test(deadline=time.monotonic() + .3)
    result = setup.owner.close(deadline=time.monotonic() + 1)
    assert result.cleanup_confirmed and not result.protocol_released and setup.raw.open_calls == 1
    assert all(frame[0] == P.HB for frame in setup.raw.peer.frames[1:])


@pytest.mark.parametrize('cancel', [lambda: True, lambda: 'PRIVATE', lambda: 1])
def test_self_test_cancel_or_bad_callback_terminal(setup, cancel):
    start(setup)
    with pytest.raises(S.ProbeOwnerError) as caught:
        setup.owner.self_test(deadline=time.monotonic() + 1, cancel=cancel)
    assert caught.value.code in ('espprobe_cancelled', 'espprobe_protocol')
    assert setup.owner.close(deadline=time.monotonic() + 1).cleanup_confirmed


def test_hb_timeout_and_single_selftest_slot(setup):
    start(setup)
    until(lambda: setup.owner.snapshot().heartbeat_acked >= 1)
    setup.raw.peer.fault = 'drop-hb'
    thread, values = background(lambda: setup.owner.self_test(deadline=time.monotonic() + .2))
    until(lambda: setup.owner._test is not None)
    with pytest.raises(S.ProbeOwnerError) as caught:
        setup.owner.self_test(deadline=time.monotonic() + .2)
    assert caught.value.code == 'port_busy'
    thread.join(1)
    assert not thread.is_alive() and isinstance(values[0], S.ProbeOwnerError)
    assert values[0].code == 'espprobe_timeout'
    assert setup.owner.close(deadline=time.monotonic() + 1).cleanup_confirmed


def test_hb_sequence_exhaustion_and_saturated_status(setup):
    setup.owner._sent = setup.owner._acked = setup.owner._tests = S._MAX_COUNTER
    start(setup)
    assert setup.owner.self_test(deadline=time.monotonic() + 1).self_tests == S._MAX_COUNTER
    with setup.owner._condition:
        setup.owner._hb_seq = (1 << 32) - 1
        setup.owner._next_hb = time.monotonic()
    setup.raw.cancel_read()
    until(lambda: setup.owner.snapshot().terminal_reason is not None)
    status = setup.owner.snapshot()
    assert status.terminal_reason == 'espprobe_protocol'
    assert status.heartbeat_sent == status.heartbeat_acked == S._MAX_COUNTER


def test_clock_regression_terminal(setup, monkeypatch):
    start(setup)
    original = S._clock
    monkeypatch.setattr(S, '_clock', lambda: original() - 2)
    setup.raw.cancel_read()
    until(lambda: setup.owner.snapshot().terminal_reason is not None)
    monkeypatch.setattr(S, '_clock', original)
    assert setup.owner.snapshot().terminal_reason == 'espprobe_protocol'


def test_concurrent_clock_samples_are_serialized(setup, monkeypatch):
    sampled, release, second_started, second_sampled = (threading.Event() for _ in range(4))
    baseline, calls = time.monotonic(), []

    def clock():
        calls.append(threading.get_ident())
        if len(calls) == 1:
            sampled.set()
            assert release.wait(2)
            return baseline
        second_sampled.set()
        return baseline + .001

    monkeypatch.setattr(S, '_clock', clock)
    first, values1 = background(setup.owner._now)
    assert sampled.wait(1)

    def later():
        second_started.set()
        return setup.owner._now()

    second, values2 = background(later)
    assert second_started.wait(1)
    try:
        assert not second_sampled.wait(.05)
    finally:
        release.set()
        first.join(1)
        second.join(1)
    assert values1 == [baseline] and values2 == [baseline + .001]


def test_snapshot_never_sends_or_renews_lifetime(setup):
    before = setup.owner.snapshot()
    for _ in range(5):
        assert setup.owner.snapshot() == before
    assert setup.raw.open_calls == setup.raw.write_calls == 0


def test_completed_selftest_slot_is_counted_once(setup):
    end = time.monotonic() + 1
    setup.owner._test = {'target': 1, 'end': end, 'cancel': None, 'done': False}
    for sequence in (1, 2):
        frame = P.Frame(type=P.HB, op=0, seq=sequence, session=TOKEN)
        setup.owner._pending_hb, setup.owner._pending_end = frame, end
        setup.owner._hb_ack(frame)
    status = setup.owner.snapshot()
    assert status.heartbeat_acked == 2 and status.self_tests == 1
