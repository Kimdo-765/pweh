"""OpenOCD 내부 pipe RPC: 단일 요청, 제한된 파싱, 재연결 없는 종료 상태.

프로세스 생성·기기 분류·허가는 호출자의 책임이다. 성공한 생성자가 두 binary
pipe stream의 소유권을 받으며, terminal 상태와 실제 close 확인은 구분한다.
"""

from __future__ import annotations

import io
import math
import os
import re
import select
import stat
import threading
import time
from dataclasses import dataclass
from typing import Callable

from pweh.errors import DeviceError, TimeoutExpired

from . import tcl
from .rpc import RequestCancelled, TclConnectionClosed

_TERM = b"\x1a"
_SLICE = 0.05
_READ_SIZE = 64 << 10
_OWNER_REASONS = frozenset({"owner_abort", "owner_close", "stderr_eof", "stderr_read_error", "stderr_limit", "stderr_log_error"})
_RC = re.compile(r"-?[0-9]{1,10}\Z")


@dataclass(frozen=True)
class PipeRpcLimits:
    """낮출 수만 있는 요청당 wire·프레임·파서 작업량 상한."""

    max_response_bytes: int = 64 << 20
    max_frames: int = 4096
    max_parse_bytes: int = 128 << 20
    max_notification_items: int = 64

    def __post_init__(self) -> None:
        for key, cap in (("max_response_bytes", 64 << 20), ("max_frames", 4096),
                         ("max_parse_bytes", 128 << 20), ("max_notification_items", 64)):
            value = getattr(self, key)
            if type(value) is not int or not 1 <= value <= cap:
                raise ValueError("pipe RPC 상한은 기본값 이하의 양의 정수여야 합니다")


def _seconds(value: float, *, zero: bool = False) -> float:
    if type(value) not in (int, float):
        raise ValueError("시간 제한은 유한한 숫자여야 합니다")
    try:
        result = float(value)
    except (ValueError, OverflowError):
        raise ValueError("시간 제한은 유한한 숫자여야 합니다") from None
    if not math.isfinite(result) or result < 0 or (result == 0 and not zero):
        raise ValueError("시간 제한은 유한한 양수여야 합니다")
    return result


class _CallbackFailure(DeviceError):
    """취소 callback 자체가 실패함. 원문 예외는 전달하지 않는다."""


class _Exchange:
    """한 요청 전체에 공유하는 시간·작업 예산과 수신 프레이밍."""

    def __init__(self, client: TclPipeClient, deadline: float, cancel: Callable[[], bool] | None):
        self.client = client
        self.deadline = deadline
        self.cancel = cancel
        self.sent = 0
        self.wire = 0
        self.frames = 0
        self.work = 0
        self.buf = bytearray()
        self.start = 0
        self.scan = 0

    def check(self) -> None:
        if not self.client.connected:
            raise TclConnectionClosed("OpenOCD pipe RPC가 종료 상태입니다")
        if self.cancel is not None:
            try:
                cancelled = bool(self.cancel())
            except Exception:
                raise _CallbackFailure("취소 확인 callback이 실패했습니다") from None
            if cancelled:
                raise RequestCancelled()
        if time.monotonic() >= self.deadline:
            raise TimeoutExpired("OpenOCD pipe RPC 시간 초과")

    def charge(self, count: int) -> None:
        self.check()
        self.work += count
        if self.work > self.client.limits.max_parse_bytes:
            self.client._fail("parse_limit")

    def feed(self, chunk: bytes) -> None:
        self.wire += len(chunk)
        if self.wire > self.client.limits.max_response_bytes:
            self.client._fail("response_limit")
        # 소비한 앞부분을 일정 크기 이상일 때만 압축한다.
        if self.start >= _READ_SIZE and self.start >= len(self.buf) // 2:
            self.charge(len(self.buf) - self.start)
            del self.buf[:self.start]
            self.scan -= self.start
            self.start = 0
        self.buf.extend(chunk)

    @property
    def pending(self) -> bool:
        return self.start < len(self.buf)

    def next_frame(self, *, expect_list: bool) -> tuple[str, list[str] | None, bool] | None:
        while True:
            self.check()
            index = self.buf.find(_TERM, self.scan)
            if index < 0:
                self.scan = len(self.buf)
                return None
            self.scan = index + 1
            self.frames += 1
            if self.frames > self.client.limits.max_frames:
                self.client._fail("frame_limit")
            size = index - self.start
            self.charge(size)  # 실제 후보 복사
            frame = bytes(memoryview(self.buf)[self.start:index])
            self.charge(size)  # strict UTF-8 해석
            try:
                text = frame.decode("utf-8", errors="strict")
            except UnicodeDecodeError:
                self.client._fail("utf8_error")
            notification_prefix = text.startswith("type target_")
            notification = tcl.is_notification(text)
            items = None
            if expect_list or notification:
                self.charge(size)
                try:
                    items = tcl.split_list(
                        text,
                        max_items=self.client.limits.max_notification_items if notification_prefix else 3,
                        checkpoint=self.check,
                    )
                except tcl.TclIncomplete:
                    if not expect_list:
                        self.start = index + 1
                        return text, None, False
                    # 이 후보의 종결자만 데이터로 유지하고 다음 새 구간부터 찾는다.
                    continue
                except tcl.TclItemLimit:
                    self.client._fail("item_limit")
                except tcl.TclParseError:
                    self.client._fail("frame_error")
            self.start = index + 1
            return text, items, notification


class TclPipeClient:
    """이미 열린 binary/unbuffered pipe 두 개의 RPC 수명을 소유한다."""

    def __init__(self, stdin, stdout, *, name: str = "pipe-rpc", limits: PipeRpcLimits = PipeRpcLimits()):
        if type(limits) is not PipeRpcLimits:
            raise ValueError("PipeRpcLimits가 필요합니다")
        if not isinstance(stdin, io.RawIOBase) or not isinstance(stdout, io.RawIOBase):
            raise ValueError("binary/unbuffered pipe stream이 필요합니다")
        original: list[tuple[int, bool]] = []
        try:
            write_fd, read_fd = stdin.fileno(), stdout.fileno()
            if write_fd == read_fd or not stdin.writable() or not stdout.readable():
                raise ValueError("서로 다른 송신·수신 pipe가 필요합니다")
            for fd in (write_fd, read_fd):
                if not stat.S_ISFIFO(os.fstat(fd).st_mode):
                    raise ValueError("pipe FD가 필요합니다")
                original.append((fd, os.get_blocking(fd)))
            for fd, _ in original:
                os.set_blocking(fd, False)
        except Exception:
            for fd, blocking in original:
                try:
                    os.set_blocking(fd, blocking)
                except OSError:
                    pass
            # 실패한 생성자는 stream 소유권을 받지 않는다.
            raise
        self._stdin, self._stdout = stdin, stdout
        self._write_fd, self._read_fd = write_fd, read_fd
        self.name = name
        self.limits = limits
        self._lock = threading.Lock()
        self._state_lock = threading.Lock()
        self._reason: str | None = None
        self._closed = [False, False]
        self.requests = 0
        self.last_error: str | None = None

    @property
    def connected(self) -> bool:
        return self._reason is None

    @property
    def terminal_reason(self) -> str | None:
        return self._reason

    def _terminal(self, reason: str) -> None:
        with self._state_lock:
            if self._reason is None:
                self._reason = reason
                self.last_error = reason

    def abort(self, reason: str = "owner_abort") -> None:
        """operation lock·I/O를 기다리지 않고 최초 terminal 이유만 기록한다."""
        self._terminal(reason if type(reason) is str and reason in _OWNER_REASONS else "owner_abort")

    def _fail(self, reason: str) -> None:
        self._terminal(reason)
        if reason in ("eof", "io_error"):
            raise TclConnectionClosed("OpenOCD pipe 연결 종료 (" + reason + ")") from None
        raise DeviceError("OpenOCD pipe RPC 오류 (" + reason + ")") from None

    def close(self, *, timeout: float = 1.0) -> bool:
        """stop 후 단일 I/O 소유권을 얻어 닫는다. 미확인 stream은 재시도용으로 보존한다."""
        deadline = time.monotonic() + _seconds(timeout, zero=True)
        self.abort("owner_close")
        while not self._lock.acquire(blocking=False):
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return False
            if self._lock.acquire(timeout=min(_SLICE, remaining)):
                break
        try:
            for index, stream in enumerate((self._stdin, self._stdout)):
                if not self._closed[index]:
                    try:
                        stream.close()
                    except Exception:
                        pass
                    self._closed[index] = stream.closed is True
            return all(self._closed)
        finally:
            self._lock.release()

    def _read(self, exchange: _Exchange, *, wait: bool) -> bool:
        """즉시 읽거나 짧게 기다린다. EOF는 빈 프레임과 달리 오류다."""
        exchange.check()
        try:
            ready, _, _ = select.select([self._read_fd], [], [],
                                        min(_SLICE, max(0.0, exchange.deadline - time.monotonic())) if wait else 0)
            if not ready:
                return False
            chunk = os.read(self._read_fd, _READ_SIZE)
        except (BlockingIOError, InterruptedError):
            return False
        except (OSError, ValueError):
            self._fail("io_error")
        if not chunk:
            self._fail("eof")
        exchange.feed(chunk)
        return True

    def _notifications_only(self, exchange: _Exchange) -> None:
        while True:
            result = exchange.next_frame(expect_list=True)
            if result is None:
                break
            if not result[2]:
                self._fail("stale_data")
        if exchange.pending:
            self._fail("stale_data")

    def _preflight(self, exchange: _Exchange) -> None:
        while self._read(exchange, wait=False):
            # 읽기 청크 경계의 partial 알림은 이어 읽되, 현재 읽을 데이터가 끝나면 거부한다.
            while True:
                result = exchange.next_frame(expect_list=True)
                if result is None:
                    break
                if not result[2]:
                    self._fail("stale_data")
        if exchange.pending:
            self._fail("stale_data")

    def _write(self, exchange: _Exchange, packet: bytes) -> None:
        view = memoryview(packet)
        while exchange.sent < len(packet):
            exchange.check()
            try:
                _, ready, _ = select.select([], [self._write_fd], [], min(_SLICE, max(0.0, exchange.deadline - time.monotonic())))
                if not ready:
                    continue
                count = os.write(self._write_fd, view[exchange.sent:])
            except (BlockingIOError, InterruptedError):
                continue
            except (OSError, ValueError):
                self._fail("io_error")
            if count <= 0:
                self._fail("io_error")
            exchange.sent += count
        self.requests += 1

    def _exchange(self, script: str, *, timeout: float, cancel_check: Callable[[], bool] | None,
                  expect_list: bool, envelope: str | None = None) -> tuple[str, list[str] | None]:
        duration = _seconds(timeout)
        deadline = time.monotonic() + duration
        if type(script) is not str or type(expect_list) is not bool:
            raise ValueError("문자열 명령과 bool expect_list가 필요합니다")
        if cancel_check is not None and not callable(cancel_check):
            raise ValueError("cancel_check는 callable이어야 합니다")
        tcl.validate_request(script)
        packet = script.encode("utf-8") + _TERM
        exchange = _Exchange(self, deadline, cancel_check)
        acquired = False
        try:
            while not acquired:
                exchange.check()
                acquired = self._lock.acquire(timeout=min(_SLICE, max(0.0, deadline - time.monotonic())))
            self._preflight(exchange)
            self._write(exchange, packet)
            while True:
                result = exchange.next_frame(expect_list=expect_list)
                if result is None:
                    self._read(exchange, wait=True)
                    continue
                text, items, notification = result
                if notification:
                    continue
                # 같은 read에 붙은 오염은 현재 응답도 실패시킨다.
                self._notifications_only(exchange)
                exchange.check()
                if text == "":
                    self._terminal("closed")
                elif envelope is not None:
                    if items is None or len(items) not in ((2, 3) if envelope == "data" else (2,)):
                        self._fail("frame_error")
                    code = items[0].strip()
                    if not _RC.fullmatch(code) or not -(1 << 31) <= int(code) < (1 << 31):
                        self._fail("frame_error")
                return text, items
        except RequestCancelled:
            if exchange.sent or exchange.pending:
                self._terminal("cancelled")
            raise
        except TimeoutExpired:
            if exchange.sent or exchange.pending:
                self._terminal("timeout")
            raise
        except _CallbackFailure:
            if exchange.sent or exchange.pending:
                self._terminal("callback_error")
            raise
        finally:
            if acquired:
                self._lock.release()

    def request(self, script: str, *, timeout: float, cancel_check: Callable[[], bool] | None = None,
                expect_list: bool = True) -> str:
        """한 요청을 보내고 프레임 문자열을 반환한다. 자동 재연결하지 않는다."""
        return self._exchange(script, timeout=timeout, cancel_check=cancel_check, expect_list=expect_list)[0]

    def _call(self, cmd: str, *, timeout: float, cancel_check: Callable[[], bool] | None, raw: bool) -> tcl.TclReply:
        if type(cmd) is not str:
            raise ValueError("문자열 명령이 필요합니다")
        tcl.validate_request(cmd)
        script = tcl.wrap_raw(cmd) if raw else tcl.wrap_data(cmd)
        frame, items = self._exchange(script, timeout=timeout, cancel_check=cancel_check,
                                      expect_list=True, envelope="raw" if raw else "data")
        if not frame:
            return tcl.TclReply(code=None, output="", raw="", closed=True,
                                notes=["빈 응답 (shutdown/exit 로 연결이 닫혔을 수 있음)"])
        assert items is not None
        return tcl.TclReply(code=int(items[0].strip()), output=items[1].rstrip("\n"),
                            log=items[2].rstrip("\n") if len(items) == 3 else "", raw=frame)

    def call(self, cmd: str, *, timeout: float, cancel_check: Callable[[], bool] | None = None) -> tcl.TclReply:
        """데이터 봉투의 결과와 capture 로그를 분리한다."""
        return self._call(cmd, timeout=timeout, cancel_check=cancel_check, raw=False)

    def call_raw(self, cmd: str, *, timeout: float, cancel_check: Callable[[], bool] | None = None) -> tcl.TclReply:
        """원시 봉투의 capture 결과를 반환한다."""
        return self._call(cmd, timeout=timeout, cancel_check=cancel_check, raw=True)

    def send_unwrapped(self, cmd: str, *, timeout: float, cancel_check: Callable[[], bool] | None = None) -> str:
        """봉투 없이 첫 종결자까지 받는다."""
        return self.request(cmd, timeout=timeout, cancel_check=cancel_check, expect_list=False)


__all__ = ["PipeRpcLimits", "TclPipeClient"]
