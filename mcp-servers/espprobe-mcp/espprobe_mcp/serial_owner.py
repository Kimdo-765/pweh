"""입장 사실을 받은 probe의 단일 직렬 worker·HB·물리 정리 수명. 공개 실포트 입구는 없다."""
from __future__ import annotations

import contextlib
import math
import secrets
import struct
import threading
import time
from dataclasses import dataclass

from pweh import espprobe_protocol as P
from pweh.errors import PwehError
from pweh.espprobe_admission import ProbeAdmission, verify_probe_hello
from pweh.mcpkit import run_blocking_cancellable
from pweh.portlock import LeaseHandoff, PortLease
from pweh.serialtransport import SerialOpenError, SerialSettings, open_serial

START_SECONDS = 5.0
TEST_SECONDS = 5.0
CLOSE_SECONDS = 10.0
LIFETIME_SECONDS = 600.0
_REGISTRY = {}
_LOCK = threading.RLock()
_MAX_COUNTER = (1 << 64) - 1
_CODES = frozenset((
    'firmware_not_pinned', 'instrument_identity_unknown', 'instrument_identity_mismatch',
    'route_changed', 'port_busy', 'espprobe_protocol', 'espprobe_timeout',
    'espprobe_cancelled', 'espprobe_cleanup_unknown',
))


class ProbeOwnerError(PwehError):
    """owner는 내부 정리 재시도용이며 data·문구에 입력 신원을 싣지 않는다."""

    def __init__(self, code='espprobe_protocol', owner=None):
        self.owner = owner
        super().__init__('계측기 직렬 작업을 완료하지 못했습니다.',
                         code=code if type(code) is str and code in _CODES else 'espprobe_protocol')


def _clock():
    return time.monotonic()


def _code(exc):
    code = getattr(exc, 'code', None)
    if code in ('port_lease_invalid', 'port_scope_changed'):
        return 'route_changed'
    if code == 'port_lock_busy':
        return 'port_busy'
    return code if type(code) is str and code in _CODES else 'espprobe_protocol'


def _end(deadline, maximum):
    try:
        valid = type(deadline) in (int, float) and math.isfinite(deadline)
    except (ValueError, OverflowError):
        valid = False
    if not valid:
        raise ProbeOwnerError()
    return min(deadline, _clock() + maximum)


def _cancelled(cancel):
    if cancel is None:
        return False
    try:
        value = cancel()
    except BaseException:
        raise ProbeOwnerError() from None
    if type(value) is not bool:
        raise ProbeOwnerError()
    return value


@dataclass(frozen=True)
class ProbeStatus:
    state: str
    hello_verified: bool
    heartbeat_sent: int
    heartbeat_acked: int
    self_tests: int
    terminal_reason: str | None


@dataclass(frozen=True)
class ProbeCloseResult:
    protocol_released: bool
    workers_stopped: bool
    transport_closed: bool
    lease_closed: bool
    cleanup_confirmed: bool
    reason: str | None


class ProbeSerialOwner:
    """I/O는 persistent worker 하나, join·lease 반환은 기다리는 caller가 담당한다."""

    def __init__(self, case_id, admission, lease):
        self._case_id, self._admission, self._lease = case_id, admission, lease
        self._condition = threading.Condition(threading.RLock())
        self._finalize_lock = threading.Lock()
        self._handoff = LeaseHandoff()
        self._stop = threading.Event()
        self._state, self._reason = 'reserved', None
        self._thread = self._retry_thread = self._transport = None
        self._launching = self._start_called = self._start_done = False
        self._hello = None
        self._sent = self._acked = self._tests = self._hb_seq = self._last_ack = 0
        self._pending_hb = None
        self._pending_end = self._next_hb = 0.0
        self._test = None
        self._cleanup_op = self._cleanup_end = None
        self._cleanup_token = 0
        self._protocol_released = False
        self._decoder = P.StreamDecoder()
        self._partial_end = None
        self._last_clock = _clock()

    @property
    def case_id(self):
        return self._case_id

    @property
    def state(self):
        with self._condition:
            return self._state

    def snapshot(self):
        with self._condition:
            return ProbeStatus(self._state, self._hello is not None, self._sent,
                               self._acked, self._tests, self._reason)

    def _now(self):
        with self._condition:
            # caller와 worker의 표본 채취부터 직렬화하여 정상 시계를 역행으로 오인하지 않는다.
            now = _clock()
            if not math.isfinite(now) or now < self._last_clock:
                raise ProbeOwnerError('espprobe_protocol', self)
            self._last_clock = now
        return now

    def _tick(self, deadline, cancel=None, *, stop=True):
        if stop and self._stop.is_set():
            raise ProbeOwnerError(self._reason or 'espprobe_cancelled', self)
        if _cancelled(cancel):
            raise ProbeOwnerError('espprobe_cancelled', self)
        now = self._now()
        if now >= deadline:
            raise ProbeOwnerError('espprobe_timeout', self)
        return now

    def _fail(self, code):
        with self._condition:
            if self._state == 'closed':
                return
            if self._reason is None:
                self._reason = code if code in _CODES else 'espprobe_protocol'
            self._state = 'terminal'
            self._stop.set()
            self._handoff.abandon_caller()
            self._condition.notify_all()

    def _wake(self):
        transport = self._transport
        if transport is not None:
            with contextlib.suppress(Exception):
                transport.cancel_read()

    def abort(self):
        """취소 latch와 read 깨우기만 한다. handle·lease·thread를 caller가 정리하지 않는다."""
        self._fail('espprobe_cancelled')
        self._wake()

    def _fresh(self, callback, deadline, cancel):
        self._tick(deadline, cancel)
        self._lease.assert_held(self._admission.claim_keys)
        if callback() is not None:
            raise ProbeOwnerError('route_changed', self)
        self._tick(deadline, cancel)
        self._lease.assert_held(self._admission.claim_keys)

    def _write(self, wire, deadline, cancel=None):
        position = 0
        while position < len(wire):
            now = self._tick(deadline, cancel)
            self._lease.assert_held(self._admission.claim_keys)
            self._transport.write_timeout = min(5.0, deadline - now)
            self._tick(deadline, cancel)
            count = self._transport.write(wire[position:])
            self._tick(deadline, cancel)
            if type(count) is not int or not 0 < count <= len(wire) - position:
                raise ProbeOwnerError('espprobe_protocol', self)
            position += count

    def _read(self, deadline, cancel=None):
        now = self._tick(deadline, cancel)
        if self._partial_end is not None and now >= self._partial_end:
            raise ProbeOwnerError('espprobe_timeout', self)
        self._transport.timeout = min(.05, deadline - now)
        chunk = self._transport.read(16384)
        now = self._tick(deadline, cancel)
        if type(chunk) is not bytes or len(chunk) > 16384:
            raise ProbeOwnerError('espprobe_protocol', self)
        if not chunk and not self._transport.is_open:
            raise ProbeOwnerError('espprobe_protocol', self)
        errors = self._decoder.errors
        frames = self._decoder.feed(chunk)
        if self._decoder.errors != errors or self._decoder.discarding:
            raise ProbeOwnerError('espprobe_protocol', self)
        if self._decoder.buffer:
            if self._partial_end is None or frames:
                self._partial_end = min(deadline, now + 1.0)
            if now >= self._partial_end:
                raise ProbeOwnerError('espprobe_timeout', self)
        else:
            self._partial_end = None
        return frames

    def _hello_cleanup_token(self, frame, nonce):
        # 전체 HELLO 정책이 틀려도 이 최소 envelope가 맞을 때만 제한된 BYE가 가능하다.
        try:
            if (frame.version != 1 or frame.type != P.RSP or frame.op != P.HELLO
                    or frame.seq != 1 or frame.flags or frame.credit or not frame.session
                    or frame.payload[:2] != b'\0\0'):
                return 0
            values = P.decode_tlvs(frame.payload[2:])
            if values.get(1) != nonce or values.get(27) != struct.pack('<I', frame.session):
                return 0
            return frame.session
        except Exception:
            return 0

    def _handshake(self, deadline, cancel):
        nonce = secrets.token_bytes(16)
        self._write(P.encode(P.Frame(type=P.REQ, op=P.HELLO, seq=1, session=0,
                                    payload=P.encode_tlvs({1: nonce}))), deadline, cancel)
        while True:
            frames = self._read(deadline, cancel)
            if not frames:
                continue
            if len(frames) != 1 or self._decoder.buffer:
                raise ProbeOwnerError('espprobe_protocol', self)
            self._cleanup_token = self._hello_cleanup_token(frames[0], nonce)
            try:
                hello = verify_probe_hello(frames[0], nonce=nonce, admission=self._admission)
            except Exception as exc:
                # 유효 envelope의 정책 실패에만 BYE 1회. 원래 실패 이유는 바꾸지 않는다.
                if self._cleanup_token and not self._stop.is_set():
                    with contextlib.suppress(Exception):
                        self._protocol_cleanup(P.BYE, min(deadline, self._now() + 1), attempts=1)
                raise ProbeOwnerError(_code(exc), self) from None
            self._tick(deadline, cancel)
            self._lease.set_state('open')
            with self._condition:
                self._hello = hello
                self._next_hb = self._now()
                self._state, self._start_done = 'active', True
                self._condition.notify_all()
            return

    def _hb_ack(self, frame):
        if self._pending_hb is None or frame != self._pending_hb:
            raise ProbeOwnerError('espprobe_protocol', self)
        self._tick(self._pending_end)
        with self._condition:
            self._last_ack = frame.seq
            self._acked = min(_MAX_COUNTER, self._acked + 1)
            self._pending_hb = None
            if self._test is not None and not self._test['done'] and frame.seq >= self._test['target']:
                self._tick(self._test['end'], self._test['cancel'])
                self._test['done'] = True
                self._tests = min(_MAX_COUNTER, self._tests + 1)
                self._condition.notify_all()

    def _active_loop(self, lifetime_end):
        while True:
            now = self._tick(lifetime_end)
            with self._condition:
                cleanup = self._cleanup_op
                test = self._test
            if cleanup is not None:
                self._protocol_cleanup(cleanup, self._cleanup_end)
                return
            if test is not None and not test['done']:
                self._tick(test['end'], test['cancel'])
            if self._pending_hb is not None:
                self._tick(self._pending_end)
            elif now >= self._next_hb:
                if self._hb_seq >= (1 << 32) - 1:
                    raise ProbeOwnerError('espprobe_protocol', self)
                self._hb_seq += 1
                frame = P.Frame(type=P.HB, op=0, seq=self._hb_seq, session=self._hello.session_token)
                self._pending_hb = frame
                self._pending_end = min(lifetime_end, now + self._hello.hb_ms / 1000)
                self._write(P.encode(frame), self._pending_end)
                with self._condition:
                    self._sent = min(_MAX_COUNTER, self._sent + 1)
                self._next_hb = now + self._hello.hb_ms / 3000
            end = min(lifetime_end, self._pending_end) if self._pending_hb is not None else lifetime_end
            if test is not None and not test['done']:
                end = min(end, test['end'])
            frames = self._read(end)
            if len(frames) > 1:
                raise ProbeOwnerError('espprobe_protocol', self)
            for frame in frames:
                self._hb_ack(frame)

    def _protocol_cleanup(self, op, deadline, *, attempts=2):
        wire = P.encode(P.Frame(type=P.REQ, op=op, seq=2, session=self._cleanup_token))
        expected = P.Frame(type=P.RSP, op=op, seq=2, session=self._cleanup_token, payload=b'\0\0')
        now = self._tick(deadline)
        retry_at = now + min(1.0, (deadline - now) / 2)
        self._write(wire, deadline)
        sent = 1
        while True:
            now = self._tick(deadline)
            if sent < attempts and now >= retry_at:
                self._write(wire, deadline)
                sent += 1
            frames = self._read(deadline)
            if len(frames) > 2:
                raise ProbeOwnerError('espprobe_protocol', self)
            acknowledged = False
            for frame in frames:
                if frame == expected and not acknowledged:
                    acknowledged = True
                elif frame.type == P.HB:
                    self._hb_ack(frame)
                else:
                    raise ProbeOwnerError('espprobe_protocol', self)
            if acknowledged:
                if self._decoder.buffer:
                    raise ProbeOwnerError('espprobe_protocol', self)
                with self._condition:
                    self._protocol_released = True
                    self._cleanup_token = 0
                return

    def _physical_close(self):
        transport = self._transport
        if transport is not None:
            with contextlib.suppress(BaseException):
                transport.close()
        with self._condition:
            self._condition.notify_all()

    def _worker(self, before_open, after_open, end, cancel, serial_factory, helper_factory):
        try:
            if not self._handoff.claim_worker():
                return
            lifetime_end = self._now() + LIFETIME_SECONDS
            self._tick(end, cancel)
            self._lease.set_state('opening')
            self._transport = open_serial(
                self._admission.route, SerialSettings(timeout=.05, write_timeout=min(5., end - self._now())),
                lease=self._lease, before_io=lambda: self._fresh(before_open, end, cancel),
                serial_factory=serial_factory, helper_factory=helper_factory)
            self._fresh(after_open, end, cancel)
            self._handshake(end, cancel)
            self._active_loop(lifetime_end)
        except BaseException as exc:
            if isinstance(exc, SerialOpenError):
                self._transport = exc.transport
            self._fail(_code(exc))
        finally:
            self._physical_close()
            with self._condition:
                self._start_done = True
                if self._state not in ('terminal', 'orphan', 'closed'):
                    self._state = 'releasing'
                self._condition.notify_all()

    def start(self, *, before_open, after_open, deadline, cancel=None,
              serial_factory=None, helper_factory=None):
        end = _end(deadline, START_SECONDS)
        if (not callable(before_open) or not callable(after_open)
                or cancel is not None and not callable(cancel)):
            raise ProbeOwnerError(owner=self)
        with self._condition:
            if self._state != 'reserved' or self._start_called:
                raise ProbeOwnerError('port_busy', self)
            self._start_called, self._launching, self._state = True, True, 'starting'
            self._thread = threading.Thread(target=self._worker, args=(before_open, after_open, end,
                cancel, serial_factory, helper_factory), daemon=True, name='pweh-probe-serial')
        try:
            try:
                self._thread.start()
            finally:
                with self._condition:
                    self._launching = False
                    self._condition.notify_all()
            with self._condition:
                while not self._start_done:
                    self._tick(end, cancel)
                    self._condition.wait(min(.05, end - self._now()))
                self._tick(end, cancel)
                if self._hello is None or self._state != 'active':
                    raise ProbeOwnerError(self._reason or 'espprobe_protocol', self)
                return self._hello
        except BaseException as exc:
            code = _code(exc)
            self._fail(code)
            self._wake()
            result = self.close(deadline=_clock() + CLOSE_SECONDS)
            raise ProbeOwnerError(code if result.cleanup_confirmed else 'espprobe_cleanup_unknown', self) from None

    def self_test(self, *, deadline, cancel=None):
        end = _end(deadline, TEST_SECONDS)
        if cancel is not None and not callable(cancel):
            raise ProbeOwnerError(owner=self)
        with self._condition:
            if self._state != 'active' or self._test is not None:
                raise ProbeOwnerError('port_busy', self)
            request = {'target': self._hb_seq + 1, 'end': end, 'cancel': cancel, 'done': False}
            self._test = request
            self._next_hb = min(self._next_hb, self._now())
        self._wake()
        try:
            with self._condition:
                while not request['done']:
                    self._tick(end, cancel)
                    if self._state != 'active':
                        raise ProbeOwnerError(self._reason or 'espprobe_protocol', self)
                    self._condition.wait(min(.05, end - self._now()))
                self._tick(end, cancel)
                return self.snapshot()
        except BaseException as exc:
            self._fail(_code(exc))
            self._wake()
            raise ProbeOwnerError(_code(exc), self) from None
        finally:
            with self._condition:
                if self._test is request:
                    self._test = None

    def _result(self, workers_stopped):
        with self._condition:
            transport_closed = self._transport is None or self._transport.closed is True
            lease_closed = self._lease.closed is True
            confirmed = workers_stopped and transport_closed and lease_closed
            return ProbeCloseResult(self._protocol_released, workers_stopped, transport_closed,
                lease_closed, confirmed, self._reason if confirmed else 'espprobe_cleanup_unknown')

    def _close(self, op, deadline):
        end = _end(deadline, CLOSE_SECONDS)
        with self._condition:
            if self._state == 'closed':
                return self._result(True)
            retry = (not self._launching and self._thread is not None
                     and self._thread.ident is not None and not self._thread.is_alive())
            if self._state == 'active' and self._cleanup_op is None:
                self._cleanup_op, self._cleanup_end, self._state = op, end, 'releasing'
            elif self._state in ('reserved', 'starting'):
                if self._state == 'starting':
                    self._fail('espprobe_cancelled')
                else:
                    self._state = 'releasing'
                    self._handoff.abandon_caller()
            self._condition.notify_all()
        self._wake()
        if not self._finalize_lock.acquire(timeout=max(0., end - _clock())):
            return self._result(False)
        try:
            with self._condition:
                while self._launching and _clock() < end:
                    self._condition.wait(min(.05, end - _clock()))
                launching = self._launching
            thread = self._thread
            if thread is not None and thread.ident is not None:
                thread.join(max(0., end - _clock()))
            stopped = not launching and (thread is None or thread.ident is None or not thread.is_alive())
            if stopped and retry and self._transport is not None and not self._transport.closed:
                # 이전 worker 종료를 확인한 명시 close에서만 같은 handle의 물리 close를 재시도한다.
                if self._retry_thread is None or not self._retry_thread.is_alive():
                    self._retry_thread = threading.Thread(target=self._physical_close,
                        daemon=True, name='pweh-probe-close')
                    try:
                        self._retry_thread.start()
                    except BaseException:
                        pass
            if self._retry_thread is not None and self._retry_thread.ident is not None:
                self._retry_thread.join(max(0., end - _clock()))
                stopped = stopped and not self._retry_thread.is_alive()
            physical = self._transport is None or self._transport.closed is True
            if stopped and physical:
                with contextlib.suppress(Exception):
                    self._lease.close()
            result = self._result(stopped)
            with self._condition:
                self._state = 'closed' if result.cleanup_confirmed else 'orphan'
            if result.cleanup_confirmed:
                with _LOCK:
                    if _REGISTRY.get(self._case_id) is self:
                        del _REGISTRY[self._case_id]
            elif not self._lease.closed:
                with contextlib.suppress(Exception):
                    self._lease.set_state('orphan')
            return result
        finally:
            self._finalize_lock.release()

    def release(self, *, deadline):
        return self._close(P.RELEASE, deadline)

    def close(self, *, deadline):
        return self._close(P.BYE, deadline)


def reserve_probe_owner(case_id, admission, lease):
    """입장 결과와 같은 전체 keys만 인수한다. 실패 전 lease는 caller 소유다."""
    if type(admission) is not ProbeAdmission or type(case_id) is not str or case_id != admission.case_id:
        raise ProbeOwnerError('instrument_identity_unknown')
    if not isinstance(lease, PortLease) or lease.keys != admission.claim_keys:
        raise ProbeOwnerError('route_changed')
    try:
        lease.assert_held(admission.claim_keys)
        with _LOCK:
            if case_id in _REGISTRY or len(_REGISTRY) >= 16:
                raise ProbeOwnerError('port_busy')
            owner = ProbeSerialOwner(case_id, admission, lease)
            _REGISTRY[case_id] = owner
            return owner
    except Exception as exc:
        raise ProbeOwnerError(_code(exc)) from None


async def start_probe_worker(owner, *, before_open, after_open, deadline, cancel=None):
    """취소된 awaiter와 persistent I/O worker의 소유를 분리한다."""
    return await run_blocking_cancellable(owner.start, before_open=before_open, after_open=after_open,
        deadline=deadline, cancel=cancel, on_cancel=owner.abort)
