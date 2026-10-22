"""익명 pipe와 합성 peer만으로 RPC 예산·종료·Tcl 호환성을 검사한다."""

from __future__ import annotations

import io
import os
import select
import socket
import subprocess
import threading
import time
from contextlib import contextmanager

import pytest

from openocd_mcp import rpc_pipe, tcl
from openocd_mcp.rpc import RequestCancelled, TclConnectionClosed
from openocd_mcp.rpc_pipe import PipeRpcLimits, TclPipeClient
from pweh.errors import DeviceError, TimeoutExpired

TERM = b"\x1a"
NOTE = b"type target_event event halted\r\n\x1a"


@pytest.fixture(autouse=True)
def no_network_or_process(monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError("A1 시험은 네트워크와 자식을 만들지 않습니다")
    monkeypatch.setattr(socket, "create_connection", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)


class PipePeer:
    """독립 합성 bytes 응답을 주고 모든 FD·thread를 회수한다."""

    def __init__(self, handler, *, limits=PipeRpcLimits(), start=True):
        read_req, write_req = os.pipe()
        read_reply, write_reply = os.pipe()
        self.stdin = os.fdopen(write_req, "wb", buffering=0)
        self.stdout = os.fdopen(read_reply, "rb", buffering=0)
        self.read_req = os.fdopen(read_req, "rb", buffering=0)
        self.write_reply = os.fdopen(write_reply, "wb", buffering=0)
        os.set_blocking(read_req, False)
        os.set_blocking(write_reply, False)
        self.client = TclPipeClient(self.stdin, self.stdout, limits=limits)
        self.handler = handler
        self.requests = []
        self.request_seen = threading.Event()
        self.stop = threading.Event()
        self.errors = []
        self.thread = None
        if start:
            self.start()

    def start(self):
        self.thread = threading.Thread(target=self._run)
        self.thread.start()

    def send(self, data):
        view = memoryview(data)
        count = 0
        while count < len(data) and not self.stop.is_set():
            if not select.select([], [self.write_reply.fileno()], [], .02)[1]:
                continue
            try:
                count += os.write(self.write_reply.fileno(), view[count:])
            except BlockingIOError:
                pass

    def _run(self):
        pending = bytearray()
        try:
            while not self.stop.is_set():
                if not select.select([self.read_req.fileno()], [], [], .02)[0]:
                    continue
                data = os.read(self.read_req.fileno(), 65536)
                if not data:
                    return
                pending.extend(data)
                while TERM in pending:
                    index = pending.index(TERM)
                    frame = bytes(pending[:index])
                    del pending[:index + 1]
                    self.requests.append(frame)
                    self.request_seen.set()
                    result = self.handler(frame, self)
                    if result is not None:
                        self.send(result)
        except (BrokenPipeError, OSError, ValueError) as exc:
            if not self.stop.is_set():
                self.errors.append(type(exc).__name__)

    def close(self):
        self.stop.set()
        assert self.client.close(timeout=1)
        if self.thread is not None:
            self.thread.join(timeout=1)
            assert not self.thread.is_alive()
        self.read_req.close()
        self.write_reply.close()


@contextmanager
def peer(reply=b"0 {ok} {}\x1a", **kwargs):
    fixture = PipePeer(reply if callable(reply) else lambda *_: reply, **kwargs)
    try:
        yield fixture
    finally:
        fixture.close()


def assert_terminal(h, reason=None):
    assert not h.client.connected
    if reason is not None:
        assert h.client.terminal_reason == reason
    count = h.client.requests
    with pytest.raises(TclConnectionClosed):
        h.client.call("later", timeout=.2)
    assert h.client.requests == count


def threaded_call(client, **kwargs):
    result = []

    def run():
        try:
            result.append(client.call("waiting", timeout=2, **kwargs))
        except Exception as exc:
            result.append(exc)

    thread = threading.Thread(target=run)
    thread.start()
    return thread, result


def test_data_raw_and_tcl_error_keep_connection():
    replies = iter((b"0 {value\n} {log\n}\x1a", b"-4 {error\n}\x1a", b"0 legacy\x1a"))
    with peer(lambda *_: next(replies)) as h:
        result = h.client.call("version", timeout=1)
        assert (result.code, result.output, result.log) == (0, "value", "log")
        result = h.client.call_raw("unknown", timeout=1)
        assert result.code == -4 and result.output == "error" and h.client.connected
        assert h.client.call("legacy", timeout=1).output == "legacy"
        assert h.requests == [tcl.wrap_data("version").encode(), tcl.wrap_raw("unknown").encode(), tcl.wrap_data("legacy").encode()]
        assert h.client.requests == 3


@pytest.mark.parametrize("response,expected", [
    (b"0 {a\x1ab c} {}\x1a", "a\x1ab c"),
    (b'0 "a\x1ab c" {}\x1a', "a\x1ab c"),
    ("0 {한글🙂} {}\x1a".encode(), "한글🙂"),
    (b'0 "a\\n\\x41\\u0042" {}\x1a', "a\nAB"),
])
def test_split_reads_utf8_and_embedded_terminators(monkeypatch, response, expected):
    with peer(response) as h:
        real_read = os.read
        monkeypatch.setattr(os, "read", lambda fd, size: real_read(fd, min(size, 1) if fd == h.stdout.fileno() else size))
        assert h.client.call("x", timeout=1).output == expected


def test_notifications_before_after_and_idle():
    with peer(NOTE + b"0 {ok} {}\x1a" + NOTE) as h:
        assert h.client.call("first", timeout=1).ok
        h.send(NOTE + NOTE)
        assert h.client.call("second", timeout=1).ok
        assert h.client.connected


def test_notification_embedded_term_requires_complete_list():
    with peer(b"type target_event data {a\x1ab}\r\n\x1a0 ok {}\x1a") as h:
        assert h.client.call("first", timeout=1).ok


def test_empty_reply_is_closed_and_terminal():
    with peer(TERM) as h:
        result = h.client.call("exit", timeout=1)
        assert result.closed and result.code is None
        assert_terminal(h, "closed")


def test_unwrapped_first_terminator_does_not_require_list():
    with peer(b"{not a list\x1a") as h:
        assert h.client.send_unwrapped("raw", timeout=1) == "{not a list"


@pytest.mark.parametrize("response,reason", [
    (b"0 {x}trailer {}\x1a", "frame_error"),
    (b'0 "x"trailer {}\x1a', "frame_error"),
    (b"0\x1a", "frame_error"),
    (b"0 x y z\x1a", "item_limit"),
    (b"0 \xff {}\x1a", "utf8_error"),
    (b"hello world\x1a", "frame_error"),
    (b"1.0 x\x1a", "frame_error"),
    (b"+1 x\x1a", "frame_error"),
    ("١ x\x1a".encode(), "frame_error"),
    (b"99999999999 x\x1a", "frame_error"),
    (b"2147483648 x\x1a", "frame_error"),
    (b"-2147483649 x\x1a", "frame_error"),
    (b"0 ok {}\x1a0 late {}\x1a", "stale_data"),
    (b"0 ok {}\x1apartial", "stale_data"),
    (b"0 ok {}\x1atype target_event incomplete", "stale_data"),
    (b"type target_event data {bad}tail\r\n\x1a", "frame_error"),
])
def test_bad_reply_terminal_without_later_write(response, reason):
    with peer(response) as h:
        with pytest.raises(DeviceError):
            h.client.call("first", timeout=1)
        assert_terminal(h, reason)


@pytest.mark.parametrize("code", [b"2147483647", b"-2147483648", b"0000000000", b"-0", b"{ -1 }"])
def test_bounded_ascii_code_compatibility(code):
    with peer(code + b" ok\x1a") as h:
        assert h.client.call("x", timeout=1).code == int(code.strip(b"{} "))


def test_raw_three_items_rejected():
    with peer() as h:
        with pytest.raises(DeviceError):
            h.client.call_raw("x", timeout=1)
        assert_terminal(h, "frame_error")


@pytest.mark.parametrize("tail", [b"0 late {}\x1a", b"partial", b"type target_event x", b"type target_event {bad}x\r\n\x1a"])
def test_late_or_partial_bytes_rejected_before_write(tail):
    with peer() as h:
        assert h.client.call("first", timeout=1).ok
        h.send(tail)
        with pytest.raises(DeviceError):
            h.client.call("second", timeout=1)
        assert h.client.requests == 1
        assert not h.client.connected


@pytest.mark.parametrize("partial", [b"", b"0 {unfinished"])
def test_eof_without_frame_is_terminal(partial):
    def reply(_, h):
        h.send(partial)
        h.write_reply.close()
    with peer(reply) as h:
        with pytest.raises(TclConnectionClosed):
            h.client.call("x", timeout=1)
        assert_terminal(h, "eof")


@pytest.mark.parametrize("field,valid", [
    ("max_response_bytes", 64 << 20), ("max_frames", 4096),
    ("max_parse_bytes", 128 << 20), ("max_notification_items", 64),
])
def test_limits_lower_only_and_strict(field, valid):
    assert getattr(PipeRpcLimits(**{field: 1}), field) == 1
    for invalid in (False, True, 0, -1, 1.0, "1", None, valid + 1):
        with pytest.raises(ValueError):
            PipeRpcLimits(**{field: invalid})


@pytest.mark.parametrize("limit,size,success", [(9, 9, True), (8, 9, False)])
def test_wire_limit_exact_boundary(limit, size, success):
    response = b"0 ok {}\x1a"  # 8 바이트
    assert len(response) == size - 1
    response = b"0 ok  {}\x1a"
    assert len(response) == size
    with peer(response, limits=PipeRpcLimits(max_response_bytes=limit)) as h:
        if success:
            assert h.client.call("x", timeout=1).ok
        else:
            with pytest.raises(DeviceError):
                h.client.call("x", timeout=1)
            assert_terminal(h, "response_limit")


@pytest.mark.parametrize("frames,success", [(3, True), (2, False)])
def test_frame_budget_counts_notifications_and_embedded_terms(frames, success):
    with peer(NOTE + b"0 {a\x1ab} {}\x1a", limits=PipeRpcLimits(max_frames=frames)) as h:
        if success:
            assert h.client.call("x", timeout=1).output == "a\x1ab"
        else:
            with pytest.raises(DeviceError):
                h.client.call("x", timeout=1)
            assert_terminal(h, "frame_limit")


@pytest.mark.parametrize("work,success", [(21, True), (20, False)])
def test_parse_work_boundary(work, success):
    with peer(b"0 ok {}\x1a", limits=PipeRpcLimits(max_parse_bytes=work)) as h:
        if success:
            assert h.client.call("x", timeout=1).ok
        else:
            with pytest.raises(DeviceError):
                h.client.call("x", timeout=1)
            assert_terminal(h, "parse_limit")


def test_incomplete_reparse_counts_work():
    response = b"0 {a\x1ab\x1ac} {}\x1a"
    with peer(response, limits=PipeRpcLimits(max_parse_bytes=3 * (len(response) - 1))) as h:
        with pytest.raises(DeviceError):
            h.client.call("x", timeout=1)
        assert_terminal(h, "parse_limit")


def test_notification_item_bound():
    with peer(NOTE + b"0 ok {}\x1a", limits=PipeRpcLimits(max_notification_items=3)) as h:
        with pytest.raises(DeviceError):
            h.client.call("x", timeout=1)
        assert_terminal(h, "item_limit")


def test_many_short_notifications_are_bounded():
    with peer(NOTE * 1000, limits=PipeRpcLimits(max_frames=32)) as h:
        with pytest.raises(DeviceError):
            h.client.call("x", timeout=1)
        assert_terminal(h, "frame_limit")


def test_preflight_notifications_share_current_budget():
    with peer(limits=PipeRpcLimits(max_frames=2)) as h:
        h.send(NOTE + NOTE)
        with pytest.raises(DeviceError):
            h.client.call("x", timeout=1)
        assert_terminal(h, "frame_limit")


@pytest.mark.parametrize("timeout", [True, False, 0, -1, "1", None, float("nan"), float("inf"), 10 ** 400])
def test_invalid_timeout_does_not_write_or_poison(timeout):
    with peer() as h:
        with pytest.raises(ValueError):
            h.client.call("x", timeout=timeout)
        assert h.client.connected and h.client.requests == 0
        assert h.client.call("valid", timeout=1).ok


@pytest.mark.parametrize("command", ["bad\x1a", "bad\x00", "\ud800", "x" * (tcl.MAX_REQUEST_BYTES + 1), "x" * tcl.MAX_REQUEST_BYTES, None])
def test_invalid_original_or_final_envelope_keeps_client_healthy(command):
    with peer() as h:
        with pytest.raises(ValueError):
            h.client.call(command, timeout=1)
        assert h.client.requests == 0 and h.client.connected
        assert h.client.call("valid", timeout=1).ok


def test_lock_wait_timeout_and_cancel_only_affect_waiter():
    with peer(lambda *_: None) as h:
        thread, result = threaded_call(h.client)
        try:
            assert h.request_seen.wait(1)
            with pytest.raises(TimeoutExpired):
                h.client.call("waiting too", timeout=.04)
            with pytest.raises(RequestCancelled):
                h.client.call("cancelled waiter", timeout=1, cancel_check=lambda: True)
            assert h.client.connected and h.client.requests == 1
            h.send(b"0 first {}\x1a")
        finally:
            thread.join(timeout=1)
        assert not thread.is_alive() and result[0].output == "first"


def test_write_blocked_before_first_byte_timeout_preserves_connection():
    with peer(start=False) as h:
        while True:
            try:
                os.write(h.stdin.fileno(), b"x" * 4096)
            except BlockingIOError:
                break
        with pytest.raises(TimeoutExpired):
            h.client.call("x", timeout=.04)
        assert h.client.requests == 0 and h.client.connected
        while True:
            try:
                os.read(h.read_req.fileno(), 65536)
            except BlockingIOError:
                break
        h.start()
        assert h.client.call("ok", timeout=1).ok


def test_partial_write_timeout_is_terminal():
    with peer(start=False) as h:
        with pytest.raises(TimeoutExpired):
            h.client.call("x" * (1 << 20), timeout=.04)
        assert_terminal(h, "timeout")


def test_sent_request_cancel_and_deadline_terminal():
    with peer(lambda *_: None) as h:
        with pytest.raises(RequestCancelled):
            h.client.call("x", timeout=1, cancel_check=h.request_seen.is_set)
        assert_terminal(h, "cancelled")
    with peer(lambda *_: None) as h:
        with pytest.raises(TimeoutExpired):
            h.client.call("x", timeout=.04)
        assert_terminal(h, "timeout")


@pytest.mark.parametrize("after_send", [False, True])
def test_callback_exception_is_fixed_and_does_not_leak(after_send):
    with peer(lambda *_: None) as h:
        def callback():
            if not after_send or h.request_seen.is_set():
                raise RuntimeError("private callback payload")
            return False
        with pytest.raises(DeviceError) as error:
            h.client.call("x", timeout=1, cancel_check=callback)
        assert "private callback payload" not in str(error.value)
        assert h.client.connected is (not after_send)
        assert h.client.terminal_reason == ("callback_error" if after_send else None)


def test_close_interrupts_inflight_and_confirms_streams():
    with peer(lambda *_: None) as h:
        thread, result = threaded_call(h.client)
        assert h.request_seen.wait(1)
        assert h.client.close(timeout=1)
        thread.join(timeout=1)
        assert not thread.is_alive() and isinstance(result[0], TclConnectionClosed)
        assert h.stdin.closed and h.stdout.closed
        assert h.client.terminal_reason == "owner_close"
        assert h.client.close(timeout=0)


def test_close_false_keeps_streams_for_retry_and_abort_is_nonblocking():
    with peer() as h:
        h.client._lock.acquire()
        try:
            begin = time.monotonic()
            h.client.abort("stderr_limit")
            assert time.monotonic() - begin < .2
            assert not h.client.close(timeout=.02)
            assert not h.stdin.closed and not h.stdout.closed
            assert h.client.terminal_reason == "stderr_limit"
        finally:
            h.client._lock.release()
        assert h.client.close(timeout=.2)
        assert h.client.terminal_reason == "stderr_limit"


@pytest.mark.parametrize("reason", ["owner_close", "stderr_eof", "stderr_read_error", "stderr_limit", "stderr_log_error", "private string", []])
def test_abort_fixed_codes_and_first_reason(reason):
    with peer() as h:
        h.client.abort(reason)
        h.client.abort("owner_close")
        assert h.client.terminal_reason == (reason if isinstance(reason, str) and reason in rpc_pipe._OWNER_REASONS else "owner_abort")
        assert_terminal(h)


def test_constructor_failure_does_not_close_and_restores_flags(monkeypatch):
    r1, w1 = os.pipe()
    r2, w2 = os.pipe()
    streams = [os.fdopen(w1, "wb", buffering=0), os.fdopen(r2, "rb", buffering=0)]
    real = os.set_blocking
    calls = []
    def fail_second(fd, value):
        calls.append((fd, value))
        if len(calls) == 2:
            raise OSError("synthetic")
        real(fd, value)
    monkeypatch.setattr(os, "set_blocking", fail_second)
    try:
        with pytest.raises(OSError):
            TclPipeClient(*streams)
        assert all(not stream.closed for stream in streams)
        assert os.get_blocking(w1) and os.get_blocking(r2)
    finally:
        for stream in streams:
            stream.close()
        os.close(r1)
        os.close(w2)


def test_nonraw_streams_rejected_without_close():
    a, b = io.BytesIO(), io.BytesIO()
    with pytest.raises(ValueError):
        TclPipeClient(a, b)
    assert not a.closed and not b.closed


@pytest.mark.parametrize("text", [" " * 20000 + "x", "{" + "x" * 20000 + "}", '"' + "x" * 20000 + '"', "x" * 20000, "\\\n" + " " * 20000 + "x"])
def test_parser_checkpoints_cover_every_long_path(text):
    checks = []
    def checkpoint():
        checks.append(1)
        if len(checks) == 4:
            raise RequestCancelled()
    with pytest.raises(RequestCancelled):
        tcl.split_list(text, max_items=3, checkpoint=checkpoint)
    assert len(checks) == 4


@pytest.mark.parametrize("text", ["{", '"'])
def test_only_incomplete_quote_or_brace_is_reassemblable(text):
    with pytest.raises(tcl.TclIncomplete):
        tcl.split_list(text)
    assert not tcl.list_complete(text)


def test_bad_suffix_is_not_incomplete_and_item_limit_precedes_large_word():
    with pytest.raises(tcl.TclParseError) as exc:
        tcl.split_list("{x}bad")
    assert not isinstance(exc.value, tcl.TclIncomplete)
    with pytest.raises(tcl.TclItemLimit):
        tcl.split_list("x {" + "x" * 20000, max_items=1)


@pytest.mark.parametrize("text", [r"a {b c} d\ e", r'"a\n\x42\u0043" {raw\n}', r"\777 \U00110000", " ", ""])
def test_bounded_default_parser_semantics_agree(text):
    assert tcl.split_list(text, max_items=64, checkpoint=lambda: None) == tcl.split_list(text)


@pytest.mark.parametrize("response", [b"type target_event {partial\x1a", b"type target_event {partial\r\n\x1a"])
def test_unwrapped_notification_prefix_cannot_extend_first_frame(response):
    with peer(response) as h:
        assert h.client.send_unwrapped("raw", timeout=1) == response[:-1].decode()


def test_cancel_during_preflight_read_is_terminal_without_write(monkeypatch):
    with peer() as h:
        flag = threading.Event()
        real_read = os.read
        def read(fd, size):
            result = real_read(fd, size)
            if fd == h.stdout.fileno():
                flag.set()
            return result
        monkeypatch.setattr(os, "read", read)
        h.send(NOTE)
        with pytest.raises(RequestCancelled):
            h.client.call("x", timeout=1, cancel_check=flag.is_set)
        assert h.client.requests == 0
        assert_terminal(h, "cancelled")


@pytest.mark.parametrize("kind", ["cancel", "timeout"])
def test_parser_checkpoint_consumes_same_request_deadline(monkeypatch, kind):
    with peer(b"0 {" + b"x" * 20000 + b"} {}\x1a") as h:
        expired = threading.Event()
        original_parse = tcl.split_list
        monotonic = time.monotonic
        monkeypatch.setattr(rpc_pipe.time, "monotonic", lambda: monotonic() + (10 if kind == "timeout" and expired.is_set() else 0))
        checks = []
        def parse(text, **kwargs):
            check = kwargs["checkpoint"]
            def checkpoint():
                checks.append(1)
                if len(checks) == 4:
                    expired.set()
                check()
            return original_parse(text, **{**kwargs, "checkpoint": checkpoint})
        monkeypatch.setattr(tcl, "split_list", parse)
        with pytest.raises(RequestCancelled if kind == "cancel" else TimeoutExpired):
            h.client.call("x", timeout=1, cancel_check=lambda: kind == "cancel" and expired.is_set())
        assert len(checks) == 4
        assert h.client.terminal_reason == ("cancelled" if kind == "cancel" else "timeout")


def test_close_partial_failure_only_retries_unclosed_stream():
    class CloseOnce:
        def __init__(self, stream):
            self.stream = stream
            self.calls = 0
        @property
        def closed(self):
            return self.stream.closed
        def close(self):
            self.calls += 1
            if self.calls == 1:
                raise OSError("synthetic")
            self.stream.close()
    with peer() as h:
        flaky = CloseOnce(h.stdin)
        h.client._stdin = flaky
        assert not h.client.close(timeout=.2)
        assert not h.stdin.closed and h.stdout.closed
        assert h.client.close(timeout=.2)
        assert flaky.calls == 2
        assert h.client.close(timeout=.2)
        assert flaky.calls == 2


def test_idle_eof_is_rejected_before_new_write():
    with peer(start=False) as h:
        h.write_reply.close()
        with pytest.raises(TclConnectionClosed):
            h.client.call("x", timeout=1)
        assert h.client.requests == 0
        assert_terminal(h, "eof")


def test_many_incomplete_candidates_stop_at_frame_budget():
    with peer(b"0 {" + b"x\x1a" * 1000, limits=PipeRpcLimits(max_frames=12)) as h:
        with pytest.raises(DeviceError):
            h.client.call("x", timeout=1)
        assert_terminal(h, "frame_limit")


def test_consumed_buffer_compaction_keeps_pending_offsets():
    note = b"type target_event data {" + b"x" * 33000 + b"}\r\n\x1a"
    with peer(note * 3 + b"0 {ok} {}\x1a") as h:
        assert h.client.call("x", timeout=2).output == "ok"


def test_short_writes_and_interrupted_io_keep_packet_complete(monkeypatch):
    with peer() as h:
        write = os.write
        interrupted = [False]
        def partial(fd, data):
            if fd == h.stdin.fileno():
                if not interrupted[0]:
                    interrupted[0] = True
                    raise InterruptedError()
                return write(fd, data[:3])
            return write(fd, data)
        monkeypatch.setattr(os, "write", partial)
        assert h.client.call("version", timeout=1).ok
        assert h.requests == [tcl.wrap_data("version").encode()]


def test_nonpipe_raw_files_rejected_without_ownership(tmp_path):
    with open(tmp_path / "file", "w+b", buffering=0) as stream:
        with pytest.raises(ValueError):
            TclPipeClient(stream, stream)
        assert not stream.closed


@pytest.mark.parametrize("max_items", [0, -1, True, 1.0, "1"])
def test_parser_invalid_item_limit(max_items):
    with pytest.raises(ValueError):
        tcl.split_list("a", max_items=max_items)
