"""내부 Windows pipe 파일 job. 같은 client를 소비하고 확인된 종료 뒤에만 게시한다.

공개 Windows target/메모리/flash 도구를 연결하지 않는다. 실제 주소·bank의 권위는
이 함수가 만들지 않으며 기존 TCP 및 borrowed read_memory 경로와 분리한다.
"""
from __future__ import annotations

import math
import time

from pweh.errors import DeviceError, TimeoutExpired
from pweh.jobs import JobCancelled
from pweh.portlock import LeaseHandoff

from . import process_windows as PW, windows_output as O, windows_start as W
from .rpc import RequestCancelled, TclConnectionClosed
from .rpc_pipe import TclPipeClient
from .session import OcdSession, REGISTRY

_CODES = frozenset({"openocd_output_invalid", "openocd_output_changed", "openocd_output_limit",
                    "openocd_output_resume_invalid", "openocd_output_cleanup_unknown",
                    "openocd_pipe_terminal", "timeout", "cancelled"})


def _error(code="openocd_output_invalid"):
    return DeviceError("내부 pipe 파일 작업을 완료하지 못했습니다.", code=code)


def _code(exc):
    if isinstance(exc, (JobCancelled, RequestCancelled)):
        return "cancelled"
    if isinstance(exc, TimeoutExpired):
        return "timeout"
    if isinstance(exc, TclConnectionClosed):
        return "openocd_pipe_terminal"
    value = getattr(exc, "code", None)
    return value if type(value) is str and value in _CODES else "openocd_output_invalid"


def _remaining(end):
    left = end - time.monotonic()
    if left <= 0:
        raise _error("timeout")
    return left


def _session(sess, owner, client):
    if (REGISTRY.find(sess.case_id) is not sess or sess.windows_owner is not owner
            or sess.client is not client or owner.client is not client):
        raise _error("openocd_output_changed")
    with PW._LOCK:
        if PW._OWNED.get(owner.token) is not owner:
            raise _error("openocd_output_changed")


def _pending(sess):
    """소유권은 그대로 두며 명시 stop이 같은 owner의 정리를 다시 확인한다."""
    sess.cleanup_pending = True
    sess.cleanup_reason = "output_cleanup_unknown"
    if sess.windows_lease is not None and not sess.windows_lease.closed:
        try:
            sess.windows_lease.set_state("orphan")
        except Exception:
            pass
    W._save(sess, cleanup_confirmed=False)


class _Worker:
    def __init__(self, spec, sess, runtime, end, owner, client):
        self.spec, self.sess, self.runtime = spec, sess, runtime
        self.end, self.owner, self.client = end, owner, client
        self.output = None
        self.prepared = self.close_attempted = self.physical = False
        self.cleanup_end = self.post_end = None
        self.result = self.failure = None

    def check(self, j, *, closing=False):
        j.check_cancelled()
        if not closing and self.sess.closing:
            raise JobCancelled()
        _remaining(self.post_end if self.post_end is not None else self.end)
        if not closing:
            _session(self.sess, self.owner, self.client)
            if self.sess.starting or self.sess.cleanup_pending:
                raise _error()
            if not self.client.connected or self.client.terminal_reason is not None:
                raise _error("openocd_pipe_terminal")

    def send(self, j, operation, chunk, address, n):
        command = self.output.command(operation, chunk, address_or_offset=address)
        self.check(j)
        timeout = min(_remaining(self.end), max(30.0, min(900.0, n / 2048.0 + 30.0)))
        try:
            reply = self.client.call(command, timeout=timeout,
                                     cancel_check=lambda: j.cancelled or self.sess.closing)
        except (RequestCancelled, TimeoutExpired, TclConnectionClosed):
            raise
        except Exception:
            if self.client.terminal_reason is not None:
                raise _error("openocd_pipe_terminal") from None
            raise
        ended_at = time.monotonic()
        self.check(j)
        if reply.ok is not True:
            raise _error()
        return ended_at

    def close_owner(self, end):
        self.close_attempted = True
        self.cleanup_end = end
        self.sess.begin_close()
        try:
            self.physical = self.owner.close(timeout=min(10.0, _remaining(end))).confirmed is True
        except Exception:
            self.physical = False
        if not self.physical:
            _pending(self.sess)

    def partial(self, j):
        if self.output is not None:
            j.set_partial({"done": self.output.done, "length": self.spec.length,
                           "chunks": self.output.chunks, "resumed_from": self.output.resumed_from,
                           "reason": self.failure})

    def transfer(self, j):
        self.check(j)
        # 호출 자체가 부분 준비 소유권의 시작이다. 예외의 opaque output은 A registry가 보존한다.
        self.prepared = True
        self.output = O.prepare_output(self.owner, self.spec, deadline=self.end, cancel=lambda: j.cancelled)
        if self.output.done == self.spec.length:
            self.post_end = min(self.end, time.monotonic() + 60.0)
        while self.output.done < self.spec.length:
            self.check(j)
            n = min(self.spec.chunk_size, self.spec.length - self.output.done)
            index = self.output.chunks
            address = (self.spec.address if self.spec.kind == "memory" else self.spec.offset) + self.output.done
            first = self.output.create_chunk(index, "primary", n, deadline=self.end)
            ended_at = self.send(j, "dump_image" if self.spec.kind == "memory" else "read_bank", first, address, n)
            second = None
            if self.spec.verify:
                if self.spec.kind == "memory":
                    second = self.output.create_chunk(index, "second", n, deadline=self.end)
                    ended_at = self.send(j, "dump_image", second, address, n)
                else:
                    ended_at = self.send(j, "verify_bank", first, address, n)
            if self.output.done + n == self.spec.length:
                self.post_end = min(self.end, ended_at + 60.0)
            end = self.post_end if self.post_end is not None else self.end
            self.output.accept_chunk(first, second, deadline=end, cancel=lambda: j.cancelled)
            self.check(j)
            j.progress(self.output.done, self.spec.length, "내부 pipe 파일 읽기")
        self.check(j)
        self.close_owner(self.post_end)
        if not self.physical:
            raise _error("openocd_output_cleanup_unknown")
        self.check(j, closing=True)

        def committed(entry):
            j.mark_committed()
            j.set_partial({"artifact": dict(entry)})
            self.runtime.audit({"event": "openocd_pipe_file_committed", "artifact_id": entry["id"]}, self.spec.case.id)

        self.result = self.output.publish(owner_confirmed=True, deadline=self.post_end,
                                          cancel=lambda: j.cancelled, on_commit=committed)
        j.set_partial(self.result)

    def run(self, j):
        try:
            self.transfer(j)
        except Exception as exc:
            # 명시 stop이 job 취소 뒤 pipe를 먼저 닫아도 실제 취소 원인을 보존한다.
            self.failure = "cancelled" if j.cancelled else _code(exc)
        finally:
            try:
                if self.prepared and not self.close_attempted:
                    self.close_owner(time.monotonic() + 10.0)
                if self.result is None:
                    self.partial(j)
            except Exception:
                self.failure = "openocd_output_cleanup_unknown"
            finally:
                # close_session은 사용권0을 기다린다. worker는 자기 사용권을 먼저 반환한다.
                self.sess.finish_use()
            if self.prepared:
                cleaned = False
                if self.physical:
                    try:
                        cleaned = W.close_session(self.sess, timeout=min(10.0, _remaining(self.cleanup_end)))["ok"] is True
                    except Exception:
                        pass
                if not cleaned:
                    _pending(self.sess)
                    if self.result is not None:
                        if "output_close_unconfirmed" not in self.result["warnings"]:
                            self.result["warnings"].append("output_close_unconfirmed")
                        j.set_partial(self.result)
                    else:
                        self.failure = "openocd_output_cleanup_unknown"
        if self.result is not None:
            return self.result
        if self.failure == "cancelled":
            raise JobCancelled() from None
        raise _error(self.failure or "openocd_output_invalid") from None


def start_pipe_file_job(spec: O.PipeFileSpec, sess: OcdSession, *, runtime, deadline: float):
    """같은 pipe의 내부 파일 job을 예약한다. 공개 profile의 target/dump 허가가 아니다."""
    try:
        finite = type(deadline) in (int, float) and math.isfinite(deadline)
    except (ValueError, OverflowError):
        finite = False
    if not finite or not 0 < deadline - time.monotonic() <= 3600:
        raise _error()
    O._spec(spec)
    if (type(spec) is not O.PipeFileSpec or type(sess) is not OcdSession or not sess.windows
            or sess.mode != "spawned" or spec.case.id != sess.case_id
            or type(sess.client) is not TclPipeClient or sess.windows_owner is None
            or sess.starting or sess.closing or sess.cleanup_pending):
        raise _error()
    owner, client = sess.windows_owner, sess.client
    _session(sess, owner, client)
    if not client.connected or client.terminal_reason is not None:
        raise _error("openocd_pipe_terminal")
    sess.reserve_use()
    handoff = LeaseHandoff()

    def work(j):
        if not handoff.claim_worker():
            raise JobCancelled()
        return _Worker(spec, sess, runtime, deadline, owner, client).run(j)

    try:
        return runtime.jobs.start(
            "memory-dump" if spec.kind == "memory" else "flash-dump", work,
            description="내부 Windows pipe 파일 읽기", case_id=sess.case_id,
            meta={"output": f"{'jtag' if spec.kind == 'memory' else 'dumps'}/{spec.output_name}.bin",
                  "length": spec.length}, exclusive_key=f"openocd:{sess.case_id}")
    except BaseException:
        if handoff.abandon_caller():
            sess.finish_use()
        raise
