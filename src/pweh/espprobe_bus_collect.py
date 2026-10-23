"""필수 주입 transport에서 두 pass를 대여 FD로 수집하는 내부 bounded owner."""
from __future__ import annotations

import fcntl
import hashlib
import math
import os
import stat
import threading
import time
from collections import deque
from dataclasses import dataclass

from . import espprobe_protocol as P, espprobe_bus_wire as W, safeio
from .errors import PwehError

MAX_PASS_BYTES = 64 << 20
MAX_SECONDS = 600.0
CLEANUP_SECONDS = 5.0
READ_BYTES = 4096
HASH_BYTES = 65536
_CODES = frozenset(('espprobe_bus_invalid', 'espprobe_bus_protocol', 'espprobe_bus_rejected',
    'espprobe_bus_io', 'espprobe_bus_output_changed', 'espprobe_bus_cleanup_unknown',
    'espprobe_bus_failed', 'cancelled', 'time_limit'))
_clock = time.monotonic


class BusCollectError(PwehError):
    """입구 거부의 고정 오류. owner는 내부 정리용이며 data로 공개하지 않는다."""
    def __init__(self, code, owner):
        super().__init__('I5 내부 두 패스 수집을 완료하지 못했습니다.',
                         code=code if code in _CODES else 'espprobe_bus_failed')
        self.owner = owner


@dataclass(frozen=True)
class _PassResult:
    pass_index: int
    received: int
    stored: int
    sha256: str | None


@dataclass(frozen=True)
class BusCollectReceipt:
    plan: W.BusReadPlan
    pass_results: tuple[_PassResult, _PassResult]
    done_received: bool
    operation_complete: bool
    match: bool | None
    reason: str | None
    protocol_released: bool
    transport_closed: bool
    simulator_only: bool = True
    hardware_verified: bool = False
    device_sha256_verified: bool = False

    def to_dict(self):
        """원문·FD·transport 없이 새 닫힌 projection을 만든다."""
        return {'plan': {'kind': self.plan.kind, 'offset': self.plan.offset,
                         'length': self.plan.length, 'passes': self.plan.passes},
            'pass_results': [{'pass_index': p.pass_index, 'received': p.received,
                              'stored': p.stored, 'sha256': p.sha256} for p in self.pass_results],
            'done_received': self.done_received, 'operation_complete': self.operation_complete,
            'match': self.match, 'reason': self.reason, 'protocol_released': self.protocol_released,
            'transport_closed': self.transport_closed, 'simulator_only': True,
            'hardware_verified': False, 'device_sha256_verified': False}


def _finite(value):
    try:
        return type(value) in (int, float) and math.isfinite(value)
    except OverflowError:
        return False


def _seal(st):
    return st.st_dev, st.st_ino, st.st_mode, st.st_nlink, st.st_size, st.st_mtime_ns, st.st_ctime_ns


class BusCollector:
    """단일 run의 transport·FD2 대여. 생성자는 외부 I/O를 하지 않는다."""
    def __init__(self, transport, binding, plan, pass_fds, *, deadline, cancel=None):
        self._transport, self._binding, self._plan, self._fds = transport, binding, plan, pass_fds
        self._deadline, self._cancel = deadline, cancel
        self._lock = threading.Lock()
        self._running = self._started = False
        self._receipt = None
        self._last_clock = None
        self._closed = self._released = self._done = self._terminal = False
        self._close_attempted = False
        self._decoder = P.StreamDecoder()
        self._queue = deque()
        self._received, self._stored, self._verified = [0, 0], [0, 0], [None, None]
        self._hashes = [hashlib.sha256(), hashlib.sha256()]
        self._seals = []
        self._pending_hb = None
        self._cleanup_end = None
        self._tx_partial = False

    @property
    def receipt(self):
        return self._receipt

    def _error(self, code, *, terminal=False):
        if terminal:
            self._terminal = True
        raise BusCollectError(code, self)

    def _now(self):
        try:
            value = _clock()
        except Exception:
            self._error('espprobe_bus_failed')
        if not _finite(value) or self._last_clock is not None and value < self._last_clock:
            self._error('espprobe_bus_failed')
        self._last_clock = value
        return value

    def _tick(self, end, *, cancel=True):
        if cancel and self._cancel is not None:
            try:
                value = self._cancel()
            except Exception:
                self._error('espprobe_bus_failed')
            if type(value) is not bool:
                self._error('espprobe_bus_failed')
            if value:
                self._error('cancelled')
        now = self._now()
        if cancel and self._pending_hb is not None and now >= self._pending_hb[2]:
            self._error('time_limit', terminal=True)
        if now >= end:
            self._error('time_limit')
        return now

    def _validate(self):
        if (type(self._binding) is not W.BusWireBinding or type(self._plan) is not W.BusReadPlan
                or type(self._fds) is not tuple or len(self._fds) != 2
                or any(type(fd) is not int or fd < 0 for fd in self._fds)
                or not _finite(self._deadline) or self._cancel is not None and not callable(self._cancel)
                or any(not callable(getattr(self._transport, name, None)) for name in ('read', 'write', 'close'))):
            self._error('espprobe_bus_invalid')
        if (type(self._plan.passes) is not int or self._plan.passes != 2
                or type(self._plan.length) is not int or not 1 <= self._plan.length <= MAX_PASS_BYTES):
            self._error('espprobe_bus_invalid')
        # 순수 builder 검증과 전체 REQ 여유를 첫 TX 전에 닫는다.
        seq = self._binding.hello_seq
        W.build_read_begin(self._binding, self._plan, seq=seq + 1)
        needed = 3 if self._plan.kind == 'spi' else 2
        W.build_bus_cleanup(self._binding, seq=seq + needed)
        W.build_bus_heartbeat(self._binding, seq=self._binding.last_hb_seq + 1, credit=1)
        if self._plan.kind == 'spi':
            W.build_spi_probe(self._binding, seq=seq + 1)
        self._req_seq, self._hb_seq = seq, self._binding.last_hb_seq
        self._chunk = 256 if self._plan.kind == 'spi' else 32
        for fd in self._fds:
            st = os.fstat(fd)
            flags = fcntl.fcntl(fd, fcntl.F_GETFL)
            if (not stat.S_ISREG(st.st_mode) or st.st_nlink != 1 or st.st_size != 0
                    or flags & os.O_ACCMODE != os.O_RDWR or flags & os.O_APPEND):
                self._error('espprobe_bus_invalid')
            self._seals.append(_seal(st))
        if self._seals[0][:2] == self._seals[1][:2]:
            self._error('espprobe_bus_invalid')
        now = self._now()
        self._end = min(self._deadline, now + MAX_SECONDS)
        self._period = self._binding.hb_ms / 3000
        self._next_hb = now + self._period
        self._tick(self._end)

    def _send(self, wire, end, *, cancel=True):
        if self._terminal:
            self._error('espprobe_bus_protocol')
        position = 0
        try:
            while position < len(wire):
                self._tick(end, cancel=cancel)
                try:
                    written = self._transport.write(wire[position:], deadline=end)
                except Exception:
                    self._error('espprobe_bus_io', terminal=True)
                if type(written) is not int or not 0 < written <= len(wire) - position:
                    self._error('espprobe_bus_io', terminal=True)
                position += written
                self._tx_partial = position < len(wire)
            return self._tick(end, cancel=cancel)
        except Exception:
            if self._tx_partial:
                self._terminal = True
            raise

    def _feed(self, data):
        if type(data) is not bytes or not 0 < len(data) <= READ_BYTES:
            self._error('espprobe_bus_io', terminal=True)
        pending = len(self._decoder.buffer)
        for byte in data:
            if byte == 0:
                if pending == 0:
                    self._error('espprobe_bus_protocol', terminal=True)
                pending = 0
            else:
                pending += 1
        errors = self._decoder.errors
        try:
            frames = self._decoder.feed(data)
            if self._decoder.errors != errors or self._decoder.discarding or len(frames) + len(self._queue) > 3:
                self._error('espprobe_bus_protocol', terminal=True)
            parsed = [W.parse_bus_frame(frame, self._binding) for frame in frames]
        except Exception:
            self._error('espprobe_bus_protocol', terminal=True)
        self._queue.extend(parsed)

    def _send_hb(self, credit):
        if self._pending_hb is not None or self._hb_seq == 0xffffffff:
            self._error('espprobe_bus_protocol', terminal=True)
        self._hb_seq += 1
        wire = W.build_bus_heartbeat(self._binding, seq=self._hb_seq, credit=credit)
        sent = self._send(wire, self._end)
        self._pending_hb = (self._hb_seq, credit, min(sent + self._binding.hb_ms / 1000, self._end))
        self._next_hb = sent + self._period

    def _next(self, *, end=None, cleanup=False):
        end = self._end if end is None else end
        while True:
            now = self._tick(end, cancel=not cleanup)
            if not cleanup and self._pending_hb is not None and now >= self._pending_hb[2]:
                self._error('time_limit', terminal=True)
            if self._queue:
                return self._queue.popleft()
            if not cleanup and self._pending_hb is None and now >= self._next_hb:
                self._send_hb(0)
                continue
            read_end = end
            if not cleanup:
                read_end = min(end, self._pending_hb[2] if self._pending_hb else self._next_hb)
            try:
                data = self._transport.read(READ_BYTES, deadline=read_end)
            except Exception:
                self._error('espprobe_bus_io', terminal=True)
            try:
                self._tick(end, cancel=not cleanup)
            except Exception:
                if data is not None:
                    self._terminal = True
                raise
            if data is None:
                continue
            if data == b'':
                self._error('espprobe_bus_io', terminal=True)
            self._feed(data)

    def _heartbeat(self, item):
        if type(item) is W.BusHeartbeat:
            if self._pending_hb is None or (item.seq, item.credit) != self._pending_hb[:2]:
                self._error('espprobe_bus_protocol', terminal=True)
            credit = item.credit
            self._pending_hb = None
            return credit
        if type(item) is W.BusResponse and item.op == 0:
            if self._pending_hb is None or item.seq != self._pending_hb[0]:
                self._error('espprobe_bus_protocol', terminal=True)
            self._pending_hb = None
            self._error('espprobe_bus_rejected')
        return None

    def _drain_hb(self):
        while self._pending_hb is not None:
            if self._heartbeat(self._next()) is None:
                self._error('espprobe_bus_protocol', terminal=True)

    def _quiet(self):
        if self._queue or self._decoder.buffer:
            self._error('espprobe_bus_protocol', terminal=True)

    def _request(self, op, wire, seq):
        self._quiet()
        self._send(wire, self._end)
        response = None
        while response is None or self._pending_hb is not None:
            item = self._next()
            if self._heartbeat(item) is not None:
                continue
            if type(item) is not W.BusResponse or item.op != op or item.seq != seq or response is not None:
                self._error('espprobe_bus_protocol', terminal=True)
            if item.status != 0:
                self._error('espprobe_bus_rejected')
            response = item
        self._quiet()
        return response

    def _file_check(self, index):
        try:
            st = os.fstat(self._fds[index])
        except OSError:
            self._error('espprobe_bus_output_changed')
        if _seal(st) != self._seals[index] or st.st_size != self._stored[index]:
            self._error('espprobe_bus_output_changed')

    def _store(self, index, data):
        self._received[index] += len(data)
        position = 0
        while position < len(data):
            self._tick(self._end)
            self._file_check(index)
            try:
                written = os.pwrite(self._fds[index], data[position:], self._stored[index])
            except OSError:
                self._error('espprobe_bus_io')
            if type(written) is not int or not 0 < written <= len(data) - position:
                self._error('espprobe_bus_io')
            self._stored[index] += written
            self._hashes[index].update(data[position:position + written])
            position += written
            st = os.fstat(self._fds[index])
            if _seal(st)[:4] != self._seals[index][:4] or st.st_size != self._stored[index]:
                self._error('espprobe_bus_output_changed')
            self._seals[index] = _seal(st)
        self._tick(self._end)
        self._file_check(index)

    def _collect(self):
        for index in range(2):
            while self._received[index] < self._plan.length:
                self._drain_hb()
                self._quiet()
                self._send_hb(1)
                accepted = False
                while True:
                    item = self._next()
                    credit = self._heartbeat(item)
                    if credit is not None:
                        if credit == 1:
                            accepted = True
                        continue
                    wanted = min(self._chunk, self._plan.length - self._received[index])
                    if (not accepted or type(item) is not W.BusData or item.seq != self._begin_seq
                            or item.pass_index != index or item.offset != self._plan.offset + self._received[index]
                            or len(item.data) != wanted):
                        self._error('espprobe_bus_protocol', terminal=True)
                    self._store(index, item.data)
                    break
        while True:
            item = self._next()
            if self._heartbeat(item) is not None:
                continue
            if (type(item) is not W.BusDone or item.seq != self._begin_seq or item.passes != 2
                    or item.offset != self._plan.offset or item.length != self._plan.length
                    or self._received != [self._plan.length] * 2 or self._stored != [self._plan.length] * 2):
                self._error('espprobe_bus_protocol', terminal=True)
            self._done = True
            break
        self._drain_hb()
        self._quiet()

    def _cleanup_deadline(self):
        if self._cleanup_end is None:
            try:
                now = self._now()
            except BusCollectError:
                now = self._last_clock if self._last_clock is not None else time.monotonic()
            self._cleanup_end = now + CLEANUP_SECONDS
        return self._cleanup_end

    def _physical_close(self, end):
        self._close_attempted = True
        try:
            value = self._transport.close(deadline=end)
            self._closed = type(value) is bool and value
        except Exception:
            self._closed = False
        return self._closed

    def _cleanup(self):
        end = self._cleanup_deadline()
        if self._pending_hb is not None and self._last_clock >= self._pending_hb[2]:
            self._terminal = True
        if (not self._closed and not self._released and not self._terminal and not self._tx_partial
                and not self._decoder.buffer and self._req_seq < 0xffffffff):
            try:
                self._req_seq += 1
                self._send(W.build_bus_cleanup(self._binding, seq=self._req_seq, abort=True), end, cancel=False)
                item = self._next(end=end, cleanup=True)
                if (type(item) is W.BusResponse and item.op == P.ABORT and item.seq == self._req_seq
                        and item.status == 0 and not self._queue and not self._decoder.buffer):
                    self._released = True
                else:
                    self._terminal = True
            except Exception:
                self._terminal = True
        if not self._closed and not self._close_attempted:
            self._physical_close(end)

    def _hash(self):
        for index, fd in enumerate(self._fds):
            self._tick(self._end)
            self._file_check(index)
            try:
                digest = safeio.hash_fd(fd, self._plan.length, algorithms=('sha256',), chunk=HASH_BYTES,
                                       check=lambda: self._tick(self._end))['sha256']
            except BusCollectError:
                raise
            except Exception:
                self._error('espprobe_bus_output_changed')
            self._file_check(index)
            self._tick(self._end)
            if digest != self._hashes[index].hexdigest():
                self._error('espprobe_bus_output_changed')
            self._verified[index] = digest
        for index in range(2):
            self._file_check(index)
        self._tick(self._end)

    def run(self):
        with self._lock:
            if self._running or self._started:
                raise BusCollectError('espprobe_bus_invalid', self)
            self._running = self._started = True
        admitted = False
        reason = None
        complete = False
        try:
            try:
                self._validate()
            except Exception as exc:
                code = getattr(exc, 'code', 'espprobe_bus_invalid')
                raise BusCollectError(code if code in _CODES else 'espprobe_bus_invalid', self) from None
            admitted = True
            if self._plan.kind == 'spi':
                self._req_seq += 1
                self._request(0x10, W.build_spi_probe(self._binding, seq=self._req_seq), self._req_seq)
            self._req_seq += 1
            self._begin_seq = self._req_seq
            self._request(0x11, W.build_read_begin(self._binding, self._plan, seq=self._req_seq), self._req_seq)
            self._collect()
            self._req_seq += 1
            self._request(P.BYE, W.build_bus_cleanup(self._binding, seq=self._req_seq), self._req_seq)
            self._released = True
            close_end = min(self._end, self._cleanup_deadline())
            if not self._physical_close(close_end):
                self._error('espprobe_bus_cleanup_unknown')
            self._hash()
            complete = True
        except Exception as exc:
            if not admitted:
                raise
            code = getattr(exc, 'code', 'espprobe_bus_failed')
            reason = code if code in _CODES else 'espprobe_bus_failed'
            self._cleanup()
        finally:
            if admitted:
                self._receipt = BusCollectReceipt(self._plan, tuple(_PassResult(i, self._received[i],
                    self._stored[i], self._verified[i]) for i in range(2)), self._done, complete,
                    self._verified[0] == self._verified[1] if complete else None, reason,
                    self._released, self._closed)
            with self._lock:
                self._running = False
        return self._receipt

    def close(self, *, deadline):
        with self._lock:
            if self._running:
                raise BusCollectError('espprobe_bus_invalid', self)
            self._running = True
        try:
            if not _finite(deadline):
                self._error('espprobe_bus_invalid')
            now = self._now()
            if now >= deadline:
                self._error('time_limit')
            if self._closed:
                return True
            return self._physical_close(min(deadline, now + CLEANUP_SECONDS))
        finally:
            with self._lock:
                self._running = False
