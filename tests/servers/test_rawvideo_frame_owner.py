"""주입 source의 단일 producer·callback·유한 join 소유를 검사한다."""
from __future__ import annotations

from collections import deque
import sys
import threading
import traceback
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'mcp-servers/play-mcp'))
from play_mcp import frame_owner as O
from pweh.rawvideo_frames import FrameError, MAX_TIME_NS

PRIVATE = 'PRIVATE_RAWVIDEO_SOURCE'
KEYS = {'pixel_format', 'width', 'height', 'frame_bytes', 'bytes_accepted', 'frames_completed',
        'frames_taken', 'frames_dropped', 'pending_frames', 'tail_bytes', 'last_index',
        'last_receipt_ns', 'stop_reason', 'eof_observed', 'framing_complete', 'late_read_bytes',
        'worker_stopped', 'source_closed'}


class Clock:
    def __init__(self, value=100):
        self.value = value
        self.calls = []
        self.hook = None

    def __call__(self):
        self.calls.append(threading.get_ident())
        if self.hook:
            return self.hook()
        return self.value


class Source:
    """callback 실패/대기를 명시적으로 주입하는 메모리 source."""
    def __init__(self, script=()):
        self.script = deque(script)
        self.reads, self.wakes, self.closes, self.closed_reads = [], [], [], []
        self._closed = False
        self.read_hook = self.wake_hook = self.close_hook = self.closed_hook = None
        self.finished = threading.Event()

    def read(self, size, *, timeout_s):
        self.reads.append((size, timeout_s, threading.get_ident()))
        if self.read_hook:
            return self.read_hook(size, timeout_s)
        item = self.script.popleft() if self.script else b''
        if isinstance(item, Exception):
            raise item
        return item

    def cancel_read(self):
        self.wakes.append(threading.get_ident())
        if self.wake_hook:
            self.wake_hook()

    def close(self):
        self.closes.append(threading.get_ident())
        try:
            if self.close_hook:
                self.close_hook()
            else:
                self._closed = True
        finally:
            self.finished.set()

    @property
    def closed(self):
        self.closed_reads.append(threading.get_ident())
        return self.closed_hook() if self.closed_hook else self._closed


def start(source, *, clock=None, **kwargs):
    clock = clock or Clock()
    args = dict(width=1, height=1, source=source, deadline_ns=5_000_000_100, clock_ns=clock)
    args.update(kwargs)
    return O.start_frame_owner(**args)


def stopped(owner, source):
    assert source.finished.wait(3)
    owner._thread.join(3)
    assert not owner._thread.is_alive()
    snap = owner.snapshot()
    assert set(snap) == KEYS
    assert snap['bytes_accepted'] == snap['frames_completed'] * snap['frame_bytes'] + snap['tail_bytes']
    assert snap['frames_completed'] == snap['frames_taken'] + snap['frames_dropped'] + snap['pending_frames']
    assert PRIVATE not in str(snap)
    return snap


def cleanup(owner):
    result = owner.close()
    assert set(result) == {'confirmed', 'snapshot', 'error'} and set(result['snapshot']) == KEYS
    assert result['confirmed'] == (result['snapshot']['worker_stopped'] and result['snapshot']['source_closed'])
    assert result['error'] == (None if result['confirmed'] else 'frame_cleanup_incomplete')
    return result


def assert_fixed(call, code):
    with pytest.raises(FrameError) as caught:
        call()
    err = caught.value
    assert err.code == code and err.data == {} and err.__cause__ is None
    assert PRIVATE not in str(err.to_dict()) + ''.join(traceback.format_exception(err))


@pytest.mark.parametrize('key,value', [
    ('width', True), ('width', 0), ('width', 1601), ('width', 1.0), ('height', False),
    ('height', -1), ('height', '1'), ('height', 10 ** 1000),
    ('deadline_ns', True), ('deadline_ns', -1), ('deadline_ns', 1.0),
    ('deadline_ns', MAX_TIME_NS + 1), ('deadline_ns', None), ('clock_ns', None),
    ('clock_ns', 1), ('cancel', False), ('cancel', object()),
])
def test_exact_entry_rejects_without_source_or_callback_use(key, value):
    source, clock = Source(), Clock()
    args = dict(width=1, height=1, source=source, deadline_ns=1000, clock_ns=clock)
    args[key] = value
    assert_fixed(lambda: O.start_frame_owner(**args), 'frame_input_invalid')
    assert not source.reads and not source.closes and not source.wakes and not source.closed_reads and not clock.calls


@pytest.mark.parametrize('method', ['read', 'cancel_read', 'close'])
def test_source_methods_are_required_without_calling_closed(method):
    source = Source()
    setattr(source, method, None)
    assert_fixed(lambda: start(source), 'frame_input_invalid')
    assert source.closed_reads == []


def test_missing_closed_shape_and_raising_descriptor_are_fixed():
    class Missing:
        def read(self, *a, **k): pytest.fail('read')
        def cancel_read(self): pytest.fail('wake')
        def close(self): pytest.fail('close')
    assert_fixed(lambda: start(Missing()), 'frame_input_invalid')
    class Raising(Missing):
        closed = False
        @property
        def read(self): raise RuntimeError(PRIVATE)
    assert_fixed(lambda: start(Raising()), 'frame_input_invalid')


def test_thread_start_failure_does_not_transfer_source(monkeypatch):
    source = Source()
    def fail(self): raise RuntimeError(PRIVATE)
    monkeypatch.setattr(O.threading.Thread, 'start', fail)
    assert_fixed(lambda: start(source), 'frame_source_failed')
    assert source.reads == source.closes == source.wakes == source.closed_reads == []


@pytest.mark.parametrize('deadline', [0, 99, 100])
def test_elapsed_end_has_zero_accounting_without_queue(deadline):
    source = Source()
    owner = start(source, deadline_ns=deadline)
    snap = stopped(owner, source)
    assert snap['stop_reason'] == 'time_limit' and snap['bytes_accepted'] == snap['late_read_bytes'] == 0
    assert not source.reads and owner._queue is None
    assert not snap['worker_stopped'] and snap['source_closed']
    assert cleanup(owner)['confirmed']


def test_queue_not_yet_created_has_zero_snapshot_and_consumer_does_not_sample():
    entered, release = threading.Event(), threading.Event()
    source, clock = Source(), Clock()
    def sample():
        entered.set(); assert release.wait(3)
        return 100
    clock.hook = sample
    owner = start(source, clock=clock)
    assert entered.wait(3)
    try:
        for _ in range(3):
            snap = owner.snapshot()
            assert snap['stop_reason'] is None and snap['bytes_accepted'] == 0 and owner.take() is None
        assert len(clock.calls) == 1 and not source.reads and not source.closed_reads
        owner.cancel()
        assert len(clock.calls) == 1
    finally:
        release.set()
    snap = stopped(owner, source)
    assert snap['stop_reason'] == 'cancelled' and not source.reads
    assert cleanup(owner)['confirmed']


@pytest.mark.parametrize('bad', [None, True, 100.0, -1, MAX_TIME_NS + 1, RuntimeError(PRIVATE)])
def test_first_invalid_clock_closes_owned_source_without_read(bad):
    source, clock = Source(), Clock()
    def sample():
        if isinstance(bad, Exception): raise bad
        return bad
    clock.hook = sample
    owner = start(source, clock=clock)
    snap = stopped(owner, source)
    assert snap['stop_reason'] == 'clock_regression' and not source.reads
    assert len(source.closes) == len(source.closed_reads) == 1
    assert cleanup(owner)['confirmed']


@pytest.mark.parametrize('bad', [True, None, 1, 'PRIVATE', RuntimeError(PRIVATE)])
def test_initial_cancel_callback_exact_bool_or_failure(bad):
    source = Source()
    ids = []
    def cancel():
        ids.append(threading.get_ident())
        if isinstance(bad, Exception): raise bad
        return bad
    owner = start(source, cancel=cancel)
    snap = stopped(owner, source)
    assert snap['stop_reason'] == ('cancelled' if bad is True else 'source_failed')
    assert not source.reads and ids and all(i == owner._thread.ident for i in ids)
    assert cleanup(owner)['confirmed']


def test_none_poll_split_receipts_and_terminal_snapshot_are_independent_of_consumer():
    source, clock = Source([None, b'a', b'bc', b'de', b'f', b'']), Clock()
    def sample(): return 100 + len(clock.calls)
    clock.hook = sample
    owner = start(source, clock=clock)
    snap = stopped(owner, source)
    assert snap['stop_reason'] == 'eof' and snap['frames_completed'] == 2 and snap['frames_dropped'] == 1
    assert snap['last_receipt_ns'] == 111
    count = len(clock.calls)
    frame = owner.take()
    assert frame.index == 1 and frame.receipt_ns == 111 and frame.pixels == b'def'
    assert owner.take() is None and len(clock.calls) == count
    copy = owner.snapshot(); copy['bytes_accepted'] = -100
    assert owner.snapshot()['bytes_accepted'] == 6 and len(clock.calls) == count
    assert all(size <= 65536 and 0 < seconds <= 0.05 for size, seconds, _ in source.reads)
    assert all(i == owner._thread.ident for i in clock.calls + source.closes + source.closed_reads)
    assert cleanup(owner)['confirmed'] and len(clock.calls) == count


@pytest.mark.parametrize('value', [None, bytearray(b'abc'), 'abc', 3, True, memoryview(b'abc'), b'x' * 49])
def test_nonbytes_and_requested_size_overrun_are_atomic(value):
    # None은 허용 poll이므로 이어지는 잘못된 값으로 오류 경계를 확인한다.
    source = Source([value, object()] if value is None else [value])
    owner = start(source)
    snap = stopped(owner, source)
    assert snap['stop_reason'] == 'source_failed'
    assert snap['bytes_accepted'] == snap['late_read_bytes'] == 0
    assert cleanup(owner)['confirmed']


def test_read_exception_preserves_previous_frame_and_tail_without_raw_error():
    source = Source([b'abcd', RuntimeError(PRIVATE)])
    owner = start(source)
    snap = stopped(owner, source)
    assert snap['stop_reason'] == 'source_failed' and snap['bytes_accepted'] == 4 and snap['tail_bytes'] == 1
    assert owner.take().pixels == b'abc'
    assert cleanup(owner)['confirmed']


@pytest.mark.parametrize('bad', [99, True, None, RuntimeError(PRIVATE)])
def test_clock_failure_after_frame_uses_last_valid_sample(bad):
    source, clock = Source([b'abc', b'def']), Clock()
    def sample():
        if len(clock.calls) == 5:
            if isinstance(bad, Exception): raise bad
            return bad
        return 100
    clock.hook = sample
    owner = start(source, clock=clock)
    snap = stopped(owner, source)
    assert snap['stop_reason'] == 'clock_regression'
    assert snap['bytes_accepted'] == 3 and snap['last_receipt_ns'] == 100 and snap['late_read_bytes'] == 0
    assert owner.take().pixels == b'abc'
    cleanup(owner)


def test_time_limit_after_none_is_checked_without_another_read():
    source, clock = Source(), Clock()
    def read(size, timeout):
        clock.value = 200
        return None
    source.read_hook = read
    owner = start(source, clock=clock, deadline_ns=200)
    snap = stopped(owner, source)
    assert snap['stop_reason'] == 'time_limit' and snap['late_read_bytes'] == 0 and len(source.reads) == 1
    assert source.reads[0][1] == pytest.approx(100 / 1e9)
    cleanup(owner)


@pytest.mark.parametrize('data,expected_late', [(b'abc', 3), (b'', 0), (bytearray(b'abc'), 0), (b'x' * 49, 0)])
def test_late_time_return_never_becomes_eof_or_frame(data, expected_late):
    source, clock = Source(), Clock()
    def read(size, timeout):
        clock.value = 200
        return data
    source.read_hook = read
    owner = start(source, clock=clock, deadline_ns=200)
    snap = stopped(owner, source)
    assert snap['stop_reason'] == 'time_limit'
    assert snap['late_read_bytes'] == expected_late and not snap['eof_observed']
    assert snap['bytes_accepted'] == 0 and owner.take() is None
    cleanup(owner)


def test_worker_end_is_first_sample_plus_five_seconds_only():
    source, clock = Source(), Clock()
    def read(size, timeout):
        clock.value += 5_000_000_000
        return b'abc'
    source.read_hook = read
    owner = start(source, clock=clock, deadline_ns=MAX_TIME_NS)
    snap = stopped(owner, source)
    assert owner._end == 5_000_000_100 and snap['stop_reason'] == 'time_limit' and snap['late_read_bytes'] == 3
    cleanup(owner)


def test_time_near_max_integer_clamps_without_overflow():
    source, clock = Source(), Clock(MAX_TIME_NS - 1)
    owner = start(source, clock=clock, deadline_ns=MAX_TIME_NS)
    snap = stopped(owner, source)
    assert snap['stop_reason'] == 'eof' and owner._end == MAX_TIME_NS
    assert source.reads[0][1] == pytest.approx(1e-9)
    cleanup(owner)


@pytest.mark.parametrize('data,late', [(b'abc', 3), (b'', 0), (b'x' * 49, 0), ('PRIVATE', 0)])
def test_blocked_read_cancel_and_late_return(data, late):
    source = Source()
    entered, release = threading.Event(), threading.Event()
    def read(size, timeout):
        entered.set(); assert release.wait(3)
        return data
    source.read_hook = read
    owner = start(source)
    assert entered.wait(3)
    try:
        result = cleanup(owner)
        assert not result['confirmed'] and not result['snapshot']['worker_stopped']
        assert not source.closes
        owner.cancel(); owner.cancel()
        assert len(source.wakes) == 1
    finally:
        release.set()
    snap = stopped(owner, source)
    assert snap['stop_reason'] == 'cancelled' and snap['late_read_bytes'] == late
    assert snap['bytes_accepted'] == 0 and owner.take() is None and len(source.reads) == 1
    assert cleanup(owner)['confirmed'] and len(source.closes) == 1


def test_cancel_callback_after_read_counts_normal_bytes_once():
    source = Source([b'abc'])
    calls = []
    def cancel():
        calls.append(threading.get_ident())
        return len(calls) == 2
    owner = start(source, cancel=cancel)
    snap = stopped(owner, source)
    assert snap['stop_reason'] == 'cancelled' and snap['late_read_bytes'] == 3 and snap['bytes_accepted'] == 0
    assert len(source.reads) == 1 and all(i == owner._thread.ident for i in calls)
    cleanup(owner)


def test_blocked_source_close_is_never_retried_by_consumer(monkeypatch):
    source = Source([b'abc', b''])
    entered, release = threading.Event(), threading.Event()
    def close():
        entered.set(); assert release.wait(3)
        source._closed = True
    source.close_hook = close
    owner = start(source)
    assert entered.wait(3)
    real_join = owner._thread.join
    joins = []
    def join(timeout):
        joins.append(timeout)
        return real_join(timeout)
    monkeypatch.setattr(owner._thread, 'join', join)
    try:
        result = cleanup(owner)
        assert not result['confirmed'] and joins == [0.1]
        assert result['snapshot']['stop_reason'] == 'eof' and result['snapshot']['frames_dropped'] == 1
        assert source.closes == [owner._thread.ident] and source.closed_reads == []
    finally:
        release.set()
    assert source.finished.wait(3)
    real_join(3)
    assert cleanup(owner)['confirmed'] and joins == [0.1, 0.1]
    assert source.closes == source.closed_reads == [owner._thread.ident]


@pytest.mark.parametrize('closed_value', [True, False, 1, 'true', None, RuntimeError(PRIVATE)])
@pytest.mark.parametrize('raises', [False, True])
def test_close_return_not_evidence_closed_requires_exact_true(closed_value, raises):
    source = Source()
    def close():
        if raises: raise RuntimeError(PRIVATE)
        return True
    def closed():
        if isinstance(closed_value, Exception): raise closed_value
        return closed_value
    source.close_hook, source.closed_hook = close, closed
    owner = start(source)
    snap = stopped(owner, source)
    assert snap['stop_reason'] == 'eof' and snap['source_closed'] is (closed_value is True)
    result = cleanup(owner)
    assert result['confirmed'] is (closed_value is True)
    assert cleanup(owner)['confirmed'] is (closed_value is True)
    assert len(source.closes) == len(source.closed_reads) == 1


def test_cancel_read_exception_is_fixed_and_does_not_confirm_source():
    source = Source()
    entered, release = threading.Event(), threading.Event()
    def read(size, timeout):
        entered.set(); assert release.wait(3)
        return None
    def wake(): raise RuntimeError(PRIVATE)
    source.read_hook, source.wake_hook = read, wake
    owner = start(source)
    assert entered.wait(3)
    try:
        owner.cancel(); owner.cancel()
        assert len(source.wakes) == 1 and not owner.snapshot()['source_closed']
    finally:
        release.set()
    assert stopped(owner, source)['stop_reason'] == 'cancelled'
    assert cleanup(owner)['confirmed']


def test_callbacks_run_outside_condition_and_consumer_methods_do_not_invoke_clock():
    source, clock = Source([b'abc', b'']), Clock()
    gate, release = threading.Event(), threading.Event()
    holder = {}
    def sample():
        if not holder:
            gate.set(); assert release.wait(3)
        owner = holder['owner']
        assert owner._condition.acquire(blocking=False)
        owner._condition.release()
        owner.snapshot()
        return 100
    clock.hook = sample
    owner = start(source, clock=clock)
    assert gate.wait(3); holder['owner'] = owner; release.set()
    stopped(owner, source)
    calls = len(clock.calls)
    for _ in range(3):
        owner.snapshot(); owner.take()
    cleanup(owner); owner.cancel()
    assert len(clock.calls) == calls


def test_take_close_race_has_one_consumer_or_one_drop():
    source = Source([b'abc', b''])
    owner = start(source)
    stopped(owner, source)
    barrier = threading.Barrier(3)
    values = []
    def take(): barrier.wait(); values.append(owner.take())
    def close(): barrier.wait(); cleanup(owner)
    threads = [threading.Thread(target=take), threading.Thread(target=close)]
    for thread in threads: thread.start()
    barrier.wait()
    for thread in threads:
        thread.join(3); assert not thread.is_alive()
    snap = owner.snapshot()
    assert snap['frames_taken'] + snap['frames_dropped'] == 1 and snap['pending_frames'] == 0
    assert (values[0] is not None) == (snap['frames_taken'] == 1)


def test_close_during_callback_does_not_self_join_or_post_pending():
    source, clock = Source(), Clock()
    entered, release = threading.Event(), threading.Event()
    holder, results = {}, []
    def read(size, timeout):
        entered.set(); assert release.wait(3)
        results.append(holder['owner'].close())
        return b'abc'
    source.read_hook = read
    owner = start(source, clock=clock)
    assert entered.wait(3); holder['owner'] = owner; release.set()
    snap = stopped(owner, source)
    assert not results[0]['confirmed'] and not results[0]['snapshot']['worker_stopped']
    assert snap['stop_reason'] == 'cancelled' and snap['late_read_bytes'] == 3 and snap['pending_frames'] == 0
    assert cleanup(owner)['confirmed']
