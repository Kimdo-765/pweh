"""RGB24 owner 시험 전용 메모리 source·barrier. OS source/factory는 없다."""
from __future__ import annotations

from collections import deque
import threading


class ManualClock:
    """값 변경과 실제 callback 호출 thread 관찰을 분리한다."""

    def __init__(self, value=1_000_000):
        self.value = value
        self.calls = []
        self.lock = threading.Lock()

    def __call__(self):
        with self.lock:
            self.calls.append(threading.get_ident())
            return self.value

    def set(self, value):
        with self.lock:
            self.value = value


class MemorySource:
    """유한 script 또는 독립 byte 패턴만 반환하는 단일 producer fake."""

    def __init__(self, script=(), *, pattern_size=None, read_gate=None, close_gate=None,
                 wake_reads=True):
        self.script = deque(script)
        self.pattern_size = pattern_size
        self.pattern_offset = 0
        self.read_gate = read_gate
        self.close_gate = close_gate
        self.wake_reads = wake_reads
        self.read_entered = threading.Event()
        self.close_entered = threading.Event()
        self.closed_event = threading.Event()
        self.read_calls = []
        self.read_threads = []
        self.cancel_threads = []
        self.close_threads = []
        self.closed_threads = []
        self.returned = []
        self._closed = False

    def __repr__(self):
        return "RAWVIDEO_PRIVATE_SOURCE_SENTINEL"

    def read(self, max_bytes, *, timeout_s):
        assert type(max_bytes) is int and 1 <= max_bytes <= 65536
        assert 0 < timeout_s <= 0.05
        self.read_calls.append((max_bytes, timeout_s))
        self.read_threads.append(threading.get_ident())
        self.read_entered.set()
        if self.read_gate is not None:
            assert self.read_gate.wait(5), "시험 read gate 미해제"
        if self.pattern_size is not None:
            size = min(max_bytes, self.pattern_size - self.pattern_offset)
            value = bytes((self.pattern_offset + i) % 251 for i in range(size))
            self.pattern_offset += size
        elif self.script:
            value = self.script.popleft()
            if callable(value):
                value = value(self, max_bytes)
            elif type(value) is bytes and len(value) > max_bytes:
                self.script.appendleft(value[max_bytes:])
                value = value[:max_bytes]
        else:
            value = b""
        # 픽셀 사본을 로그로 쌓지 않는다. 비정상 값도 원문 대신 형/길이만 관찰한다.
        self.returned.append((type(value).__name__, len(value) if type(value) is bytes else None))
        return value

    def cancel_read(self):
        self.cancel_threads.append(threading.get_ident())
        if self.wake_reads and self.read_gate is not None:
            self.read_gate.set()

    def close(self):
        self.close_threads.append(threading.get_ident())
        self.close_entered.set()
        if self.close_gate is not None:
            assert self.close_gate.wait(5), "시험 close gate 미해제"
        self._closed = True
        self.closed_event.set()

    @property
    def closed(self):
        self.closed_threads.append(threading.get_ident())
        return self._closed

    def release_gates(self):
        for gate in (self.read_gate, self.close_gate):
            if gate is not None:
                gate.set()
