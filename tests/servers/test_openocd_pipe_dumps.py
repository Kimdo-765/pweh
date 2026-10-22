"""공유 pipe 덤프의 청크·종료·재시도 경계. Linux 합성 자식/익명 pipe만 사용한다."""

from __future__ import annotations

from contextlib import contextmanager
import hashlib
import json
from pathlib import Path
import socket
import sys
import threading
import time

import pytest

from openocd_mcp import dumps, process_pipe
from openocd_mcp.rpc import TclRpcClient
from openocd_mcp.rpc_pipe import PipeRpcLimits
from pweh.errors import DeviceError, ValidationFailed
from pweh.jobs import Job, JobCancelled, JobContext, JobManager
from pweh.runtime import get_runtime

from .test_openocd_pipe_rpc import peer

FAKE = Path(__file__).with_name("fake_openocd_pipe_dump.py").resolve()


@pytest.fixture
def dump_case(workspace, auth):
    return get_runtime("openocd-mcp").cases.create(title="합성 pipe 덤프", authorization=auth)


def _spec(case, **changes):
    values = dict(kind="memory", case=case, out_dir=case.dir / "jtag", name="pipe-memory",
                  address=0x80000000, length=768, chunk_size=256, method="read_memory",
                  chunk_timeout=0.25, retries=2)
    values.update(changes)
    return dumps.prepare(dumps.DumpSpec(**values))


def _job(case):
    job = Job(id="synthetic-pipe-dump", kind="openocd-memory-dump", description="합성 메모리",
              server="openocd-mcp", case_id=case.id)
    return JobContext(job, JobManager("openocd-mcp"))


def _runner(spec, context, client, **kwargs):
    return dumps.DumpRunner(spec, context, client, unknown_risk="destructive",
                            borrowed_pipe=True, **kwargs)


@pytest.fixture
def pipe_owner(tmp_path, monkeypatch):
    def no_network(*args, **kwargs):
        raise AssertionError("pipe 덤프 시험은 네트워크를 열지 않습니다")

    monkeypatch.setattr(socket, "socket", no_network)
    monkeypatch.setattr(socket, "create_connection", no_network)
    counter = 0

    @contextmanager
    def make(mode="ready"):
        nonlocal counter
        counter += 1
        requests = tmp_path / f"requests-{counter}.txt"
        owner = process_pipe.spawn_pipe(
            [sys.executable, "-I", str(FAKE), "--mode", mode, "--requests-file", str(requests)],
            cwd=tmp_path, log_path=tmp_path / f"stderr-{counter}.log",
        )
        try:
            assert owner.wait_ready(timeout=2).ready
            yield owner, requests
        finally:
            result = owner.close(grace=0.2, timeout=3)
            assert result.confirmed, result

    return make


def _requests(path):
    return path.read_text(encoding="ascii").splitlines()


def _forbidden(*args, **kwargs):
    raise AssertionError("종료된 pipe에서 재시도/프로세스 조회를 하면 안 됩니다")


@pytest.mark.parametrize("verify", [False, True])
@pytest.mark.parametrize("address,length", [(0x80000000, 768), (0x80000001, 769)])
def test_multichunk_verify_bytes_hash_artifact_and_borrowed_client(dump_case, pipe_owner, monkeypatch,
                                                                verify, address, length):
    spec = _spec(dump_case, address=address, length=length, verify=verify)
    jctx = _job(dump_case)
    with pipe_owner() as (owner, requests):
        client = owner.client
        closes = []
        commands = []
        original_close = client.close
        original_call = client.call

        def close(**kwargs):
            closes.append(True)
            return original_close(**kwargs)

        def call(command, **kwargs):
            commands.append(command)
            return original_call(command, **kwargs)

        monkeypatch.setattr(client, "close", close)
        monkeypatch.setattr(client, "call", call)
        result = _runner(spec, jctx, client).run()
        expected = bytes((address + i) & 255 for i in range(length))
        assert spec.final.read_bytes() == expected
        assert result["sha256"] == hashlib.sha256(expected).hexdigest()
        assert result["artifact"]["sha256"] == result["sha256"]
        assert result["transfer"] == "read_memory" and not result["transfer_switches"]
        assert result["size"] == length and result["retries"] == 0
        assert not spec.part.exists() and not spec.state.exists()
        meta = json.loads(spec.meta.read_text(encoding="utf-8"))
        assert meta["verification"]["match"] and meta["verification"]["reread"] is verify
        assert meta["chunks"]["count"] == (length + 255) // 256
        assert closes == [] and client is owner.client and client.connected
        assert client.call("version", timeout=1).ok
        expected_reads = ((length + 255) // 256) * (2 if verify else 1)
        assert _requests(requests) == ["version"] + ["read_memory"] * expected_reads + ["version"]
        expected_commands = []
        for offset in range(0, length, 256):
            size = min(256, length - offset)
            width = 32 if (address + offset) % 4 == 0 and size % 4 == 0 else 8
            command = f"read_memory 0x{address + offset:x} {width} {size // (width // 8)}"
            expected_commands.extend([command] * (2 if verify else 1))
        assert commands == expected_commands + ["version"]


@pytest.mark.parametrize("mode", ["stall-second", "eof-second", "malformed-second",
                                 "utf8-second", "oversize-second"])
def test_terminal_keeps_only_complete_chunk_and_never_retries(dump_case, pipe_owner, monkeypatch,
                                                             mode):
    spec = _spec(dump_case)
    jctx = _job(dump_case)
    with pipe_owner(mode) as (owner, requests):
        owner.client.limits = PipeRpcLimits(max_response_bytes=4096)
        runner = _runner(spec, jctx, owner.client, process_alive=_forbidden)
        with monkeypatch.context() as m:
            m.setattr(dumps.time, "sleep", _forbidden)
            with pytest.raises(DeviceError) as failure:
                runner.run()
        assert failure.value.code == "openocd_pipe_terminal"
        assert "PIPE_RAW_SENTINEL" not in str(failure.value)
        assert failure.value.data["done"] == 256
        assert runner.retries_used == 0 and runner.chunks == 1
        assert spec.part.read_bytes() == bytes(range(256))
        state = json.loads(spec.state.read_text(encoding="utf-8"))
        assert state["done"] == 256 and state["method"] == "read_memory"
        assert not spec.final.exists() and not spec.meta.exists()
        assert _requests(requests) == ["version", "read_memory", "read_memory"]
        assert not any("청크 실패" in row or "청크 시간 초과" in row for row in jctx.job.log)
        # terminal은 stream의 물리 close가 아니다. 소유자는 finally에서 별도로 종료한다.
        assert not owner.client._stdin.closed and not owner.client._stdout.closed


@pytest.mark.parametrize("cancelled", [False, True])
def test_preterminal_is_no_rpc_and_cancel_has_priority(dump_case, pipe_owner, monkeypatch, cancelled):
    spec = _spec(dump_case)
    jctx = _job(dump_case)
    with pipe_owner() as (owner, requests):
        owner.client.abort()
        monkeypatch.setattr(owner.client, "call", _forbidden)
        if cancelled:
            jctx.job._cancel.set()
        runner = _runner(spec, jctx, owner.client, process_alive=_forbidden)
        with pytest.raises(JobCancelled if cancelled else DeviceError) as failure:
            runner.run()
        if not cancelled:
            assert failure.value.code == "openocd_pipe_terminal"
        assert runner.retries_used == 0 and runner.chunks == 0
        assert _requests(requests) == ["version"]
        assert spec.part.read_bytes() == b""


def test_framed_unsupported_command_does_not_fall_back_to_md(dump_case, pipe_owner):
    spec = _spec(dump_case)
    with pipe_owner("unsupported-read") as (owner, requests):
        runner = _runner(spec, _job(dump_case), owner.client)
        with pytest.raises(DeviceError) as failure:
            runner.run()
        assert failure.value.code == "openocd_pipe_read_memory_unsupported"
        assert runner.method == "read_memory" and runner.method_switches == []
        assert runner.retries_used == 0 and owner.client.connected
        assert owner.client.call("version", timeout=1).ok
        assert _requests(requests) == ["version", "read_memory", "version"]


def test_real_operation_lock_timeout_can_retry_without_terminal(dump_case, pipe_owner, monkeypatch):
    spec = _spec(dump_case, length=256, chunk_timeout=0.03)
    with pipe_owner() as (owner, requests):
        client = owner.client
        original_call = client.call
        timeouts = []
        client._lock.acquire()

        def call(cmd, *, timeout, cancel_check):
            timeouts.append(timeout)
            try:
                return original_call(cmd, timeout=timeout, cancel_check=cancel_check)
            finally:
                if len(timeouts) == 1:
                    assert client.terminal_reason is None and client.requests == 1
                    client._lock.release()

        monkeypatch.setattr(client, "call", call)
        runner = _runner(spec, _job(dump_case), client)
        runner.run()
        assert runner.retries_used == 1 and client.connected
        assert timeouts == [0.03, 0.06]
        assert _requests(requests) == ["version", "read_memory"]


@pytest.mark.parametrize("reply", [b"0 {} {}\x1a", b"-4 {} {temporary failure}\x1a"])
def test_complete_framed_target_error_remains_bounded_retry(dump_case, monkeypatch, reply):
    spec = _spec(dump_case, length=256)
    good = b"0 {" + b" ".join(hex(i).encode() for i in range(64)) + b"} {}\x1a"
    responses = iter((reply, good))
    sleeps = []
    with peer(lambda *_: next(responses)) as h:
        runner = _runner(spec, _job(dump_case), h.client)
        with monkeypatch.context() as m:
            m.setattr(dumps.time, "sleep", sleeps.append)
            result = runner.run()
        assert result["retries"] == 1 and sleeps == [0.3]
        assert len(h.requests) == 2 and h.client.connected
        assert spec.final.read_bytes() == b"".join(i.to_bytes(4, "little") for i in range(64))


@pytest.mark.parametrize("endian", ["little", "big"])
def test_verify_mismatch_retries_complete_frames_and_preserves_endian(dump_case, monkeypatch, endian):
    spec = _spec(dump_case, length=256, verify=True, endian=endian)
    good = b"0 {" + b" ".join(hex(i + 0x10203040).encode() for i in range(64)) + b"} {}\x1a"
    wrong = b"0 {" + b" ".join([b"0"] * 64) + b"} {}\x1a"
    responses = iter((good, wrong, good, good))
    with peer(lambda *_: next(responses)) as h:
        runner = _runner(spec, _job(dump_case), h.client)
        with monkeypatch.context() as m:
            m.setattr(dumps.time, "sleep", lambda _: None)
            result = runner.run()
        assert result["retries"] == 1 and len(h.requests) == 4 and h.client.connected
        expected = b"".join((i + 0x10203040).to_bytes(4, endian) for i in range(64))
        assert spec.final.read_bytes() == expected


def test_empty_terminal_frame_is_not_a_retryable_target_error(dump_case):
    with peer(b"\x1a") as h:
        runner = _runner(_spec(dump_case), _job(dump_case), h.client)
        with pytest.raises(DeviceError) as failure:
            runner.run()
        assert failure.value.code == "openocd_pipe_terminal"
        assert runner.retries_used == 0 and len(h.requests) == 1


def test_cancel_during_pending_response_preserves_first_chunk(dump_case, pipe_owner):
    spec = _spec(dump_case, chunk_timeout=2)
    jctx = _job(dump_case)
    with pipe_owner("stall-second") as (owner, requests):
        runner = _runner(spec, jctx, owner.client, process_alive=_forbidden)
        outcome = []

        def run():
            try:
                outcome.append(runner.run())
            except Exception as exc:
                outcome.append(exc)

        worker = threading.Thread(target=run)
        worker.start()
        try:
            deadline = time.monotonic() + 2
            while _requests(requests).count("read_memory") < 2 and time.monotonic() < deadline:
                time.sleep(0.005)
            assert _requests(requests).count("read_memory") == 2
        finally:
            jctx.job._cancel.set()
            worker.join(timeout=3)
        assert not worker.is_alive() and len(outcome) == 1
        assert isinstance(outcome[0], JobCancelled)
        assert jctx.job.meta["done"] == 256 and spec.part.read_bytes() == bytes(range(256))
        assert runner.retries_used == 0 and owner.client.terminal_reason == "cancelled"
        assert _requests(requests) == ["version", "read_memory", "read_memory"]


@pytest.mark.parametrize("kind,method", [("memory", "auto"), ("memory", "dump_image"),
                                        ("memory", "md"), ("flash", "read_memory")])
def test_borrowed_runner_rejects_non_read_memory_before_io(dump_case, kind, method):
    spec = _spec(dump_case, kind=kind, method=method)
    with peer(start=False) as h:
        with pytest.raises(ValidationFailed):
            _runner(spec, _job(dump_case), h.client)
        assert h.requests == [] and not spec.part.exists() and not spec.state.exists()


def test_borrowed_runner_requires_actual_pipe_and_exact_bool(dump_case):
    spec = _spec(dump_case)
    tcp = TclRpcClient("127.0.0.1", 1)
    with pytest.raises(ValidationFailed):
        _runner(spec, _job(dump_case), tcp)
    with pytest.raises(ValidationFailed):
        dumps.DumpRunner(spec, _job(dump_case), tcp, unknown_risk="destructive", borrowed_pipe=1)
    assert not tcp.connected and tcp.requests == 0


def test_existing_tcp_unsupported_read_memory_still_falls_back_to_md(dump_case, monkeypatch):
    from openocd_mcp.tcl import TclReply

    spec = _spec(dump_case, length=256)
    tcp = TclRpcClient("127.0.0.1", 1)
    calls = []

    def call(cmd, **kwargs):
        calls.append(cmd)
        if cmd.startswith("read_memory"):
            return TclReply(code=1, output='', log='invalid command name "read_memory"')
        assert cmd == "mdw 0x80000000 64"
        return TclReply(code=0, output="0x80000000: " + " ".join(f"{i:08x}" for i in range(64)))

    monkeypatch.setattr(tcp, "call", call)
    runner = dumps.DumpRunner(spec, _job(dump_case), tcp, unknown_risk="destructive")
    result = runner.run()
    assert result["transfer"] == "md" and len(result["transfer_switches"]) == 1
    assert len(calls) == 2 and spec.final.read_bytes() == b"".join(i.to_bytes(4, "little") for i in range(64))
