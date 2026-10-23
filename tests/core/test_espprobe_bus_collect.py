"""주입된 바이트 transport와 대여 FD의 수집·종료 경계를 검사한다."""
from collections import deque
from dataclasses import FrozenInstanceError, replace
import hashlib
import os
import struct
import threading
import time

import pytest

from pweh import espprobe_bus_collect as C
from pweh import espprobe_bus_wire as W
from pweh import espprobe_protocol as P


class Clock:
    def __init__(self):
        self.now = 100.0

    def __call__(self):
        return self.now


def binding(**changes):
    return replace(W.BusWireBinding(17, 29, 3, 9, 1000, bytes(range(16))), **changes)


def expected(plan, *, flip=False):
    data = bytes((plan.offset + i) & 255 for i in range(plan.length))
    return (bytes([data[0] ^ 1]) + data[1:]) if flip else data


class MemoryTransport:
    """실제 payload codec과 독립된 고정 LE 응답을 만드는 시험용 peer."""
    def __init__(self, bound, plan, *, split=4096, partial=65536, flip=False):
        self.binding, self.plan = bound, plan
        self.split, self.partial, self.flip = split, partial, flip
        self.input = bytearray()
        self.pending = deque()
        self.requests = []
        self.reads = []
        self.writes = []
        self.closes = []
        self.close_results = deque([True])
        self.modify = lambda request, frames: frames
        self.after_read = None
        self.on_close = None
        self.idle = None
        self.cursor = 0
        self.begin_seq = None

    def frame(self, *, type=P.RSP, op=0x11, seq=0, payload=b'\x00\x00', **kwargs):
        return P.Frame(type=type, op=op, seq=seq, session=self.binding.session, payload=payload, **kwargs)

    def respond(self, request):
        if request.type == P.HB:
            frames = [self.frame(type=P.HB, op=0, seq=request.seq, payload=b'', credit=request.credit)]
            if request.credit:
                assert request.credit == 1 and self.begin_seq is not None
                index, start = divmod(self.cursor, self.plan.length)
                assert index in (0, 1)
                count = min(256 if self.plan.kind == 'spi' else 32, self.plan.length - start)
                data = expected(self.plan, flip=self.flip and index == 1)[start:start + count]
                raw = struct.pack('<IBIH', self.binding.usb_session, index, self.plan.offset + start, count) + data
                frames.append(self.frame(type=P.DATA, seq=self.begin_seq, payload=raw))
                self.cursor += count
                if self.cursor == self.plan.length * 2:
                    raw = struct.pack('<IBII', self.binding.usb_session, 2, self.plan.offset, self.plan.length)
                    frames.append(self.frame(type=P.EVT, op=0x12, seq=self.begin_seq, payload=raw))
            return frames
        assert request.type == P.REQ
        if request.op == 0x10:
            raw = struct.pack('<HI3sBBQ', 0, self.binding.usb_session, b'\xef\x40\x18', 0, 7, 1 << 32)
            return [self.frame(op=request.op, seq=request.seq, payload=raw)]
        if request.op == 0x11:
            usb, kind, reserved, passes, offset, length = struct.unpack('<IBBBII', request.payload)
            assert (usb, kind, reserved, passes, offset, length) == (
                self.binding.usb_session, int(self.plan.kind == 'i2c'), 0, 2, self.plan.offset, self.plan.length)
            self.begin_seq = request.seq
        else:
            assert request.op in (P.BYE, P.ABORT)
        return [self.frame(op=request.op, seq=request.seq)]

    def write(self, data, *, deadline):
        self.writes.append((data, deadline))
        size = min(self.partial, len(data))
        self.input.extend(data[:size])
        while b'\0' in self.input:
            end = self.input.index(0) + 1
            wire = bytes(self.input[:end])
            del self.input[:end]
            request = P.decode(wire)
            self.requests.append(request)
            frames = self.modify(request, self.respond(request))
            raw = frames if type(frames) is bytes else b''.join(P.encode(frame) for frame in frames)
            if raw:
                self.pending.append(raw)
        return size

    def read(self, max_bytes, *, deadline):
        self.reads.append((max_bytes, deadline))
        if not self.pending:
            return self.idle(deadline) if self.idle else b''
        raw = self.pending.popleft()
        count = min(max_bytes, self.split, len(raw))
        data = raw[:count]
        if count < len(raw):
            self.pending.appendleft(raw[count:])
        if self.after_read:
            self.after_read(data)
        return data

    def close(self, *, deadline):
        self.closes.append(deadline)
        if self.on_close:
            self.on_close()
        return self.close_results.popleft() if self.close_results else True


@pytest.fixture
def fds(tmp_path):
    values = tuple(os.open(tmp_path / name, os.O_CREAT | os.O_EXCL | os.O_RDWR, 0o600) for name in ('pass0', 'pass1'))
    yield values
    for fd in values:
        try:
            os.close(fd)
        except OSError:
            pass


def setup(fds, *, kind='spi', length=257, offset=19, bound=None, deadline=None, cancel=None, **kwargs):
    bound = bound or binding()
    plan = W.BusReadPlan(kind, offset, length)
    transport = MemoryTransport(bound, plan, **kwargs)
    owner = C.BusCollector(transport, bound, plan, fds, deadline=C._clock() + 30 if deadline is None else deadline,
                           cancel=cancel)
    return owner, transport


def incomplete(receipt, reason):
    assert not receipt.operation_complete and receipt.match is None
    assert receipt.reason == reason
    assert receipt.simulator_only and not receipt.hardware_verified and not receipt.device_sha256_verified
    assert 'PRIVATE' not in str(receipt.to_dict())


@pytest.mark.parametrize('kind,length', [('spi', 1), ('spi', 256), ('spi', 257), ('i2c', 1), ('i2c', 32), ('i2c', 33)])
@pytest.mark.parametrize('split,partial', [(4096, 65536), (1, 3), (17, 1)])
def test_two_pass_exact_bytes_and_immutable_receipt(fds, kind, length, split, partial):
    owner, transport = setup(fds, kind=kind, length=length, split=split, partial=partial)
    assert transport.writes == transport.reads == transport.closes == []
    receipt = owner.run()
    assert receipt.operation_complete and receipt.match is True and receipt.reason is None
    assert receipt.done_received and receipt.protocol_released and receipt.transport_closed
    digest = hashlib.sha256(expected(receipt.plan)).hexdigest()
    assert [(p.pass_index, p.received, p.stored, p.sha256) for p in receipt.pass_results] == [
        (0, length, length, digest), (1, length, length, digest)]
    assert all(os.pread(fd, length, 0) == expected(receipt.plan) for fd in fds)
    assert [r.op for r in transport.requests if r.type == P.REQ] == ([16, 17, P.BYE] if kind == 'spi' else [17, P.BYE])
    assert all(r.credit == 1 for r in transport.requests if r.type == P.HB)
    assert all(size == 4096 for size, _ in transport.reads)
    with pytest.raises(FrozenInstanceError):
        receipt.match = False
    public = receipt.to_dict()
    public['pass_results'][0]['stored'] = -1
    public['plan']['length'] = -1
    assert receipt.to_dict()['pass_results'][0]['stored'] == length
    assert receipt.plan.length == length and owner.receipt is receipt
    with pytest.raises(C.BusCollectError) as err:
        owner.run()
    assert err.value.code == 'espprobe_bus_invalid' and len(transport.closes) == 1


def test_mismatch_is_complete_observation_and_fds_stay_open(fds):
    owner, _ = setup(fds, flip=True)
    receipt = owner.run()
    assert receipt.operation_complete and receipt.match is False
    assert receipt.pass_results[0].sha256 != receipt.pass_results[1].sha256
    assert all(os.fstat(fd).st_size == receipt.plan.length for fd in fds)


@pytest.mark.parametrize('change', [
    {'binding': None}, {'binding': binding(session=True)}, {'binding': binding(hello_seq=0xfffffffd)},
    {'binding': binding(last_hb_seq=0xffffffff)}, {'plan': None}, {'plan': W.BusReadPlan('spi', 0, 1, 1)},
    {'plan': W.BusReadPlan('spi', 0, 1, True)}, {'plan': W.BusReadPlan('spi', 0, 0)},
    {'plan': W.BusReadPlan('spi', 0, (64 << 20) + 1)}, {'plan': W.BusReadPlan('i2c', 0xffffffff, 2)},
    {'plan': W.BusReadPlan('PRIVATE', 0, 1)}, {'deadline': True}, {'deadline': float('inf')},
    {'deadline': float('nan')}, {'deadline': 10 ** 1000}, {'cancel': True}, {'fds': (True, 3)},
    {'fds': []}, {'fds': (1,)}, {'transport': None},
])
def test_invalid_inputs_before_wire(fds, change):
    _, transport = setup(fds)
    args = dict(transport=transport, binding=binding(), plan=W.BusReadPlan('spi', 0, 1), fds=fds,
                deadline=time.monotonic() + 30, cancel=None)
    args.update(change)
    owner = C.BusCollector(args['transport'], args['binding'], args['plan'], args['fds'],
                           deadline=args['deadline'], cancel=args['cancel'])
    with pytest.raises(C.BusCollectError) as err:
        owner.run()
    assert err.value.code == 'espprobe_bus_invalid'
    assert err.value.owner is owner and err.value.data == {} and err.value.__cause__ is None
    assert owner.receipt is None and transport.requests == transport.closes == []


@pytest.mark.parametrize('kind', ['same', 'dup', 'closed', 'nonempty', 'readonly', 'append', 'directory', 'hardlink', 'pipe'])
def test_fd_admission(fds, tmp_path, kind):
    extra = None
    supplied = fds
    if kind == 'same':
        supplied = (fds[0], fds[0])
    elif kind == 'dup':
        extra = os.dup(fds[0]); supplied = (fds[0], extra)
    elif kind == 'closed':
        extra = os.dup(fds[0]); os.close(extra); supplied = (fds[0], extra); extra = None
    elif kind == 'nonempty':
        os.write(fds[0], b'PRIVATE')
    elif kind in ('readonly', 'append'):
        extra = os.open(tmp_path / 'pass0', os.O_RDONLY if kind == 'readonly' else os.O_RDWR | os.O_APPEND)
        supplied = (extra, fds[1])
    elif kind == 'directory':
        extra = os.open(tmp_path, os.O_RDONLY | os.O_DIRECTORY); supplied = (extra, fds[1])
    elif kind == 'hardlink':
        os.link(tmp_path / 'pass0', tmp_path / 'other')
    else:
        left, extra = os.pipe(); os.close(left); supplied = (extra, fds[1])
    owner, transport = setup(supplied)
    try:
        with pytest.raises(C.BusCollectError) as err:
            owner.run()
        assert err.value.code == 'espprobe_bus_invalid' and owner.receipt is None
        assert not transport.requests and not transport.closes
    finally:
        if extra is not None:
            os.close(extra)


def test_constructor_performs_no_external_io(monkeypatch):
    def fail(*args, **kwargs):
        pytest.fail('constructor I/O')
    monkeypatch.setattr(C, '_clock', fail)
    monkeypatch.setattr(C.os, 'fstat', fail)
    owner = C.BusCollector(None, None, None, None, deadline=None, cancel=fail)
    assert owner.receipt is None


@pytest.mark.parametrize('mode', ['seq', 'pass', 'offset', 'size', 'generation', 'session', 'before_ack', 'duplicate', 'early_done', 'done_seq', 'done_length', 'done_passes', 'extra_done'])
def test_invalid_ordering_and_coordinates_are_terminal(fds, mode):
    owner, transport = setup(fds, length=2)
    changed = False
    def modify(request, frames):
        nonlocal changed
        if request.type != P.HB or changed:
            return frames
        if mode.startswith('done') or mode == 'extra_done':
            if len(frames) != 3:
                return frames
            changed = True
            done = frames[-1]
            if mode == 'done_seq':
                frames[-1] = replace(done, seq=done.seq + 1)
            elif mode == 'extra_done':
                return frames + [done]
            else:
                usb, passes, offset, size = struct.unpack('<IBII', done.payload)
                frames[-1] = replace(done, payload=struct.pack('<IBII', usb, 1 if mode == 'done_passes' else passes,
                                                               offset, size + (mode == 'done_length')))
            return frames
        changed = True
        data = frames[1]
        usb, index, offset, size = struct.unpack_from('<IBIH', data.payload)
        body = data.payload[11:]
        if mode == 'before_ack': return [data, frames[0]]
        if mode == 'duplicate': return frames + [data]
        if mode == 'early_done': return [frames[0], transport.frame(type=P.EVT, op=18, seq=data.seq,
                                            payload=struct.pack('<IBII', usb, 2, offset, size))]
        if mode == 'seq': data = replace(data, seq=data.seq + 1)
        elif mode == 'session': data = replace(data, session=data.session + 1)
        else:
            usb += mode == 'generation'; index += mode == 'pass'; offset += mode == 'offset'
            if mode == 'size': size -= 1; body = body[:-1]
            data = replace(data, payload=struct.pack('<IBIH', usb, index, offset, size) + body)
        return [frames[0], data]
    transport.modify = modify
    result = owner.run()
    incomplete(result, 'espprobe_bus_protocol')
    assert not result.protocol_released and all(r.op != P.ABORT for r in transport.requests)
    assert all(p.sha256 is None for p in result.pass_results)


@pytest.mark.parametrize('mode', ['bare', 'crc_and_good', 'four_frames', 'partial_eof', 'bad_suffix'])
def test_strict_feed_never_resynchronizes(fds, mode):
    owner, transport = setup(fds)
    def modify(request, frames):
        if request.op != 16:
            return frames
        raw = P.encode(frames[0])
        if mode == 'bare': return b'\0' + raw
        if mode == 'four_frames': return raw * 4
        if mode == 'partial_eof': return raw[:5]
        if mode == 'bad_suffix': return raw + b'\1\0'
        bad = bytearray(raw); bad[-3] ^= 128
        return bytes(bad) + raw
    transport.modify = modify
    result = owner.run()
    incomplete(result, 'espprobe_bus_io' if mode == 'partial_eof' else 'espprobe_bus_protocol')
    assert len(transport.requests) == 1 and result.pass_results[0].received == 0


def test_partial_buffer_then_bare_delimiter_is_rejected(fds):
    owner, transport = setup(fds, split=4)
    transport.modify = lambda request, frames: b''.join(P.encode(f) for f in frames) + b'\0'
    incomplete(owner.run(), 'espprobe_bus_protocol')
    assert len(transport.requests) == 1


@pytest.mark.parametrize('value', [bytearray(b'PRIVATE'), 'PRIVATE', 1, True, b'x' * 4097, b''])
def test_invalid_read_results_are_fixed_terminal(fds, value):
    owner, transport = setup(fds)
    transport.read = lambda *a, **k: value
    result = owner.run()
    incomplete(result, 'espprobe_bus_io')
    assert len(transport.requests) == 1 and len(transport.closes) == 1


@pytest.mark.parametrize('value', [0, -1, True, 100000, None])
def test_invalid_wire_write_no_retry(fds, value):
    owner, transport = setup(fds)
    calls = []
    def write(*args, **kwargs):
        calls.append(1)
        return value
    transport.write = write
    incomplete(owner.run(), 'espprobe_bus_io')
    assert len(calls) == 1 and len(transport.closes) == 1


def test_partial_fd_write_and_received_stored_distinction(fds, monkeypatch):
    original = os.pwrite
    writes = []
    def write(fd, data, offset):
        writes.append((fd, offset, len(data)))
        if len(writes) == 2:
            raise OSError('PRIVATE_DISK')
        return original(fd, data[:3], offset)
    monkeypatch.setattr(C.os, 'pwrite', write)
    owner, transport = setup(fds, length=8)
    result = owner.run()
    incomplete(result, 'espprobe_bus_io')
    assert [(r.received, r.stored, r.sha256) for r in result.pass_results] == [(8, 3, None), (0, 0, None)]
    assert result.protocol_released and transport.requests[-1].op == P.ABORT


def test_partial_fd_writes_finish_normally(fds, monkeypatch):
    original = os.pwrite
    monkeypatch.setattr(C.os, 'pwrite', lambda fd, data, offset: original(fd, data[:3], offset))
    owner, _ = setup(fds, length=33)
    assert owner.run().operation_complete


@pytest.mark.parametrize('value', [0, -1, True, 1000, None])
def test_invalid_fd_write_result_preserves_received(fds, monkeypatch, value):
    monkeypatch.setattr(C.os, 'pwrite', lambda *a: value)
    owner, _ = setup(fds, length=8)
    result = owner.run()
    incomplete(result, 'espprobe_bus_io')
    assert result.pass_results[0].received == 8 and result.pass_results[0].stored == 0


@pytest.mark.parametrize('kind', ['size', 'mode', 'link', 'content'])
def test_output_mutation_before_final_hash(fds, tmp_path, kind):
    owner, transport = setup(fds)
    def mutate():
        if kind == 'size': os.ftruncate(fds[0], 0)
        elif kind == 'mode': os.fchmod(fds[0], 0o400)
        elif kind == 'link': os.link(tmp_path / 'pass0', tmp_path / 'other')
        else: os.pwrite(fds[0], b'x', 0)
    transport.on_close = mutate
    result = owner.run()
    incomplete(result, 'espprobe_bus_output_changed')
    assert result.done_received and result.protocol_released and result.transport_closed
    assert all(p.sha256 is None for p in result.pass_results)


def test_streaming_hash_cannot_substitute_same_fd_hash(fds, monkeypatch):
    owner, _ = setup(fds)
    monkeypatch.setattr(C.safeio, 'hash_fd', lambda *a, **k: {'sha256': '0' * 64})
    result = owner.run()
    incomplete(result, 'espprobe_bus_output_changed')
    assert all(p.sha256 is None for p in result.pass_results)


def test_unknown_close_requires_explicit_retry_without_receipt_mutation(fds, monkeypatch):
    owner, transport = setup(fds)
    transport.close_results = deque([False, True])
    monkeypatch.setattr(C.safeio, 'hash_fd', lambda *a, **k: pytest.fail('hash before physical close'))
    result = owner.run()
    incomplete(result, 'espprobe_bus_cleanup_unknown')
    assert result.protocol_released and not result.transport_closed and len(transport.closes) == 1
    state = result.to_dict(); writes, reads = len(transport.writes), len(transport.reads)
    assert owner.close(deadline=time.monotonic() + 5)
    assert len(transport.closes) == 2 and len(transport.writes) == writes and len(transport.reads) == reads
    assert owner.receipt is result and result.to_dict() == state
    assert owner.close(deadline=time.monotonic() + 5) and len(transport.closes) == 2


@pytest.mark.parametrize('mode', ['missing_done', 'bye_rejected', 'bye_eof'])
def test_done_bye_and_close_are_each_required_before_hash(fds, monkeypatch, mode):
    owner, transport = setup(fds, length=1)
    def modify(request, frames):
        if mode == 'missing_done': return [f for f in frames if f.type != P.EVT]
        if request.op == P.BYE:
            return [] if mode == 'bye_eof' else [replace(frames[0], flags=1, payload=b'\1\0')]
        return frames
    transport.modify = modify
    monkeypatch.setattr(C.safeio, 'hash_fd', lambda *a, **k: pytest.fail('unverified wire completion'))
    result = owner.run()
    incomplete(result, 'espprobe_bus_rejected' if mode == 'bye_rejected' else 'espprobe_bus_io')
    assert [(p.received, p.stored, p.sha256) for p in result.pass_results] == [(1, 1, None), (1, 1, None)]


def test_original_end_and_partial_verified_hash_survive_second_hash_timeout(fds, monkeypatch):
    clock = Clock(); monkeypatch.setattr(C, '_clock', clock)
    owner, transport = setup(fds, deadline=clock.now + 10)
    real = C.safeio.hash_fd
    calls = []
    def hash_fd(fd, length, **kwargs):
        assert kwargs['chunk'] == 65536 and kwargs['algorithms'] == ('sha256',)
        assert transport.closes and transport.requests[-1].op == P.BYE
        calls.append(fd)
        result = real(fd, length, **kwargs)
        if len(calls) == 2:
            clock.now = 110.0
        return result
    monkeypatch.setattr(C.safeio, 'hash_fd', hash_fd)
    result = owner.run()
    incomplete(result, 'time_limit')
    assert result.pass_results[0].sha256 == hashlib.sha256(expected(result.plan)).hexdigest()
    assert result.pass_results[1].sha256 is None and len(transport.closes) == 1


def test_final_cancel_after_hashes_keeps_verified_shas_but_not_match(fds, monkeypatch):
    event = threading.Event()
    owner, _ = setup(fds, cancel=event.is_set)
    real = owner._file_check
    after_hash = 0
    def check(index):
        nonlocal after_hash
        real(index)
        if all(owner._verified):
            after_hash += 1
            if after_hash == 2: event.set()
    monkeypatch.setattr(owner, '_file_check', check)
    result = owner.run()
    incomplete(result, 'cancelled')
    assert all(p.sha256 is not None for p in result.pass_results)


def test_final_seal_change_after_both_hashes_is_not_success(fds, monkeypatch):
    owner, _ = setup(fds)
    real = owner._file_check
    def check(index):
        if all(owner._verified) and index == 1:
            os.ftruncate(fds[1], 0)
        return real(index)
    monkeypatch.setattr(owner, '_file_check', check)
    incomplete(owner.run(), 'espprobe_bus_output_changed')


def test_terminal_hb_expiry_at_work_end_never_aborts(fds, monkeypatch):
    clock = Clock(); monkeypatch.setattr(C, '_clock', clock)
    owner, transport = setup(fds, deadline=101)
    transport.modify = lambda request, frames: [] if request.type == P.HB else frames
    def idle(end):
        clock.now = end
        return None
    transport.idle = idle
    incomplete(owner.run(), 'time_limit')
    assert transport.requests[-1].type == P.HB and all(r.op != P.ABORT for r in transport.requests)


def test_rsp_wait_uses_separate_credit_zero_heartbeat(fds, monkeypatch):
    clock = Clock(); monkeypatch.setattr(C, '_clock', clock)
    owner, transport = setup(fds)
    delayed = []
    def modify(request, frames):
        if request.op == 16:
            delayed.extend(frames); return []
        if request.type == P.HB and not request.credit:
            return frames + delayed
        return frames
    transport.modify = modify
    def idle(end):
        clock.now = end
        return None
    transport.idle = idle
    result = owner.run()
    assert result.operation_complete
    assert transport.requests[1].type == P.HB and transport.requests[1].credit == 0


def test_partial_tx_cancellation_sends_no_abort(fds):
    event = threading.Event()
    owner, transport = setup(fds, partial=1, cancel=event.is_set)
    original = transport.write
    def write(*args, **kwargs):
        value = original(*args, **kwargs)
        event.set()
        return value
    transport.write = write
    result = owner.run()
    incomplete(result, 'cancelled')
    assert len(transport.writes) == 1 and not transport.requests


@pytest.mark.parametrize('value', [None, 1, 'PRIVATE'])
def test_bad_cancel_result_during_valid_run_is_fixed(fds, value):
    active = False
    def cancel():
        return value if active else False
    owner, transport = setup(fds, cancel=cancel)
    def after_read(data):
        nonlocal active
        active = True
    transport.after_read = after_read
    incomplete(owner.run(), 'espprobe_bus_failed')
    assert len(transport.requests) == 1


@pytest.mark.parametrize('bad', [float('inf'), float('nan'), True, 99.0])
def test_clock_failure_after_admission_is_fixed(fds, monkeypatch, bad):
    clock = Clock(); monkeypatch.setattr(C, '_clock', clock)
    owner, transport = setup(fds)
    transport.after_read = lambda data: setattr(clock, 'now', bad)
    incomplete(owner.run(), 'espprobe_bus_failed')
    assert len(transport.requests) == 1


def test_original_failure_not_replaced_by_cleanup_failure(fds):
    owner, transport = setup(fds)
    transport.modify = lambda request, frames: [replace(frames[0], payload=b'\1\0', flags=1)]
    transport.close_results = deque([False])
    result = owner.run()
    incomplete(result, 'espprobe_bus_rejected')
    assert not result.protocol_released and not result.transport_closed and len(transport.closes) == 1


def test_run_close_ownership_and_callback_outside_lock(fds):
    owner, transport = setup(fds)
    entered, release = threading.Event(), threading.Event()
    real = transport.read
    def read(*args, **kwargs):
        if not entered.is_set():
            assert owner._lock.acquire(blocking=False)
            owner._lock.release()
            entered.set()
            assert release.wait(3)
        return real(*args, **kwargs)
    transport.read = read
    results = []
    thread = threading.Thread(target=lambda: results.append(owner.run()))
    thread.start()
    assert entered.wait(3)
    for call in (owner.run, lambda: owner.close(deadline=time.monotonic() + 3)):
        with pytest.raises(C.BusCollectError) as err:
            call()
        assert err.value.code == 'espprobe_bus_invalid'
    release.set(); thread.join(3)
    assert not thread.is_alive() and results[0].operation_complete


def test_work_end_capped_once_and_cleanup_budget_not_work_extension(fds, monkeypatch):
    clock = Clock(); monkeypatch.setattr(C, '_clock', clock)
    owner, transport = setup(fds, deadline=1000)
    result = owner.run()
    assert result.operation_complete and owner._end == 700
    assert all(end <= 700 for _, end in transport.writes + transport.reads)
    assert transport.closes == [105]


def test_late_cancel_after_success_does_not_rewrite_receipt(fds):
    event = threading.Event()
    owner, transport = setup(fds, cancel=event.is_set)
    result = owner.run(); state = result.to_dict()
    event.set()
    assert owner.close(deadline=time.monotonic() + 5)
    assert owner.receipt is result and result.to_dict() == state and len(transport.closes) == 1
