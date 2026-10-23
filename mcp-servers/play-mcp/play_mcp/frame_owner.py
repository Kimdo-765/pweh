"""고정 RGB24 합성 source의 단일 producer와 유한 종료 확인."""
from __future__ import annotations

import inspect
import threading
import time

from pweh.rawvideo_frames import (
    FrameError, RawFrameQueue, MAX_DIMENSION, MAX_RUNTIME_NS, MAX_TIME_NS,
    PIXEL_FORMAT,
)

JOIN_SECONDS = 0.1
POLL_SECONDS = 0.05
_MISSING = object()


def _integer(value, low, high):
    return type(value) is int and low <= value <= high


class FrameOwner:
    """source는 producer만 닫으며 미확정 worker와 source를 같은 객체에 보존한다."""
    def __init__(self, *, width, height, source, deadline_ns, cancel, clock_ns):
        self._width, self._height = width, height
        self._source, self._deadline = source, deadline_ns
        self._cancel_callback, self._clock = cancel, clock_ns
        self._condition = threading.Condition(threading.Lock())
        self._queue = None
        self._zero_stop = None
        self._last_ns = None
        self._end = None
        self._cancelled = self._closing = self._wake_requested = False
        self._wake_failed = False
        self._source_closed = self._worker_stopped = False
        self._late_read_bytes = 0
        self._thread = threading.Thread(target=self._produce, name='pweh-rawvideo-frames', daemon=True)

    def _snapshot_locked(self):
        if self._queue is None:
            result = {'pixel_format': PIXEL_FORMAT, 'width': self._width, 'height': self._height,
                'frame_bytes': self._width * self._height * 3, 'bytes_accepted': 0,
                'frames_completed': 0, 'frames_taken': 0, 'frames_dropped': 0, 'pending_frames': 0,
                'tail_bytes': 0, 'last_index': None, 'last_receipt_ns': None,
                'stop_reason': self._zero_stop, 'eof_observed': False, 'framing_complete': False}
        else:
            result = self._queue.snapshot()
        result.update(late_read_bytes=self._late_read_bytes, worker_stopped=self._worker_stopped,
                      source_closed=self._source_closed)
        return result

    def snapshot(self):
        """callback·clock을 호출하지 않고 원문 없는 수치의 복사본을 반환한다."""
        with self._condition:
            return self._snapshot_locked()

    def take(self):
        """완성 pending 하나를 원자적으로 소비한다."""
        with self._condition:
            return None if self._queue is None else self._queue.take()

    def _finish_locked(self, reason):
        if self._queue is None:
            if self._zero_stop is None:
                self._zero_stop = reason
        else:
            # 실패한 clock 값 대신 producer의 마지막 유효 표본만 사용한다.
            self._queue.finish(reason, at_ns=self._last_ns)

    def _finish(self, reason):
        with self._condition:
            self._finish_locked(reason)

    def _sample(self):
        try:
            now = self._clock()
        except Exception:
            self._finish('clock_regression')
            return None
        if (not _integer(now, 0, MAX_TIME_NS)
                or self._last_ns is not None and now < self._last_ns):
            self._finish('clock_regression')
            return None
        self._last_ns = now
        return now

    def _checkpoint(self):
        now = self._sample()
        if now is None:
            return None
        cancelled, invalid = False, False
        if self._cancel_callback is not None:
            try:
                cancelled = self._cancel_callback()
                invalid = type(cancelled) is not bool
            except Exception:
                invalid = True
        with self._condition:
            if self._cancelled or self._closing:
                self._finish_locked('cancelled')
            elif invalid:
                self._finish_locked('source_failed')
            elif cancelled:
                self._cancelled = True
                self._finish_locked('cancelled')
            elif now >= self._end:
                self._finish_locked('time_limit')
            if self._snapshot_locked()['stop_reason'] is not None:
                return None
        return now

    def _produce(self):
        try:
            started = self._sample()
            if started is None:
                return
            self._end = min(self._deadline, started + MAX_RUNTIME_NS, MAX_TIME_NS)
            if started >= self._end:
                self._finish('time_limit')
                return
            with self._condition:
                self._queue = RawFrameQueue(self._width, self._height, started_ns=started,
                                            deadline_ns=self._end)
            while True:
                now = self._checkpoint()
                if now is None:
                    return
                with self._condition:
                    if self._cancelled or self._closing:
                        self._finish_locked('cancelled')
                        return
                    size = self._queue.read_size
                if size == 0:
                    return
                try:
                    data = self._source.read(size, timeout_s=min(POLL_SECONDS, (self._end - now) / 1e9))
                except Exception:
                    self._finish('source_failed')
                    return
                receipt = self._checkpoint()
                valid = data is None or type(data) is bytes and len(data) <= size
                with self._condition:
                    if not valid:
                        self._finish_locked('source_failed')
                        return
                    if self._cancelled or self._closing:
                        self._finish_locked('cancelled')
                    stop = self._snapshot_locked()['stop_reason']
                    if receipt is None or stop is not None:
                        if type(data) is bytes and (stop in ('cancelled', 'time_limit') or self._closing):
                            self._late_read_bytes += len(data)
                        return
                    if data is None:
                        continue
                    if not data:
                        self._finish_locked('eof')
                        return
                    self._queue.feed(data, receipt_ns=receipt)
                    if self._queue.read_size == 0:
                        return
        except Exception:
            # 원문 예외는 worker 밖으로 전달하거나 stderr에 출력하지 않는다.
            self._finish('source_failed')
        finally:
            try:
                self._source.close()
            except Exception:
                pass
            try:
                closed = self._source.closed is True
            except Exception:
                closed = False
            with self._condition:
                self._source_closed = closed
                self._condition.notify_all()

    def cancel(self):
        """취소를 latch하고 한 번만 비차단 대기해제를 요청한다."""
        with self._condition:
            self._cancelled = True
            wake = not self._wake_requested
            self._wake_requested = True
        if wake:
            try:
                self._source.cancel_read()
            except Exception:
                with self._condition:
                    self._wake_failed = True

    def close(self):
        """pending을 폐기하고 기존 worker 종료만 한 번 최대 0.1초 확인한다."""
        with self._condition:
            self._closing = True
            self._cancelled = True
            if self._queue is not None:
                self._queue.discard_pending()
        self.cancel()
        if self._thread is not threading.current_thread():
            self._thread.join(JOIN_SECONDS)
            if not self._thread.is_alive():
                with self._condition:
                    self._worker_stopped = True
        with self._condition:
            result = self._snapshot_locked()
            confirmed = self._worker_stopped and self._source_closed
            return {'confirmed': confirmed, 'snapshot': result,
                    'error': None if confirmed else 'frame_cleanup_incomplete'}


def start_frame_owner(*, width, height, source, deadline_ns, cancel=None, clock_ns=time.monotonic_ns):
    """고정 geometry와 callback 형태를 확인한 뒤 source를 producer에 인계한다."""
    try:
        valid = (_integer(width, 1, MAX_DIMENSION) and _integer(height, 1, MAX_DIMENSION)
                 and _integer(deadline_ns, 0, MAX_TIME_NS) and callable(clock_ns)
                 and (cancel is None or callable(cancel))
                 and all(callable(getattr(source, name, None)) for name in ('read', 'cancel_read', 'close'))
                 and inspect.getattr_static(source, 'closed', _MISSING) is not _MISSING)
    except Exception:
        valid = False
    if not valid:
        raise FrameError('frame_input_invalid') from None
    owner = FrameOwner(width=width, height=height, source=source, deadline_ns=deadline_ns,
                       cancel=cancel, clock_ns=clock_ns)
    try:
        owner._thread.start()
    except Exception:
        raise FrameError('frame_source_failed') from None
    return owner
