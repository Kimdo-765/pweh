"""내부 pipe argv·준비 판정 시험. Linux 합성 자식만 실행한다."""

from __future__ import annotations

from contextlib import contextmanager
import math
from pathlib import Path
import socket
import sys
import time

import pytest

from openocd_mcp import process, semihosting
from pweh.errors import ValidationFailed

FAKE = Path(__file__).with_name("fake_openocd_pipe.py").resolve()


def _argv_inputs():
    return dict(
        scripts_dir=Path("/opt/pweh-scripts"),
        interface=process.CfgRef("interface/test.cfg", "standard"),
        transport="jtag",
        targets=[process.CfgRef("target/first.cfg", "standard"), process.CfgRef("target/second.cfg", "standard")],
        extra_cfgs=[process.CfgRef("board/test.cfg", "standard")],
        adapter_speed_khz=500,
        extra_commands=["jtag newtap sample cpu -irlen 4", "reset_config none"],
        debug_level=3,
        search_dirs=[Path("/opt/pweh-scripts"), Path("/opt/extra"), Path("/opt/extra")],
    )


@pytest.mark.parametrize("port", [0, 23456])
@pytest.mark.parametrize("guard", [False, True])
def test_tcp_full_argv_preserves_exact_order(port, guard):
    early = ["-c", semihosting.EARLY_CHECK_SCRIPT] if guard else []
    # 제품 helper끼리 비교하지 않고 TCP 계약의 전체 순서를 독립적으로 고정한다.
    expected = [
        "/opt/openocd", "-d3", "-s", "/opt/pweh-scripts", "-s", "/opt/extra",
        "-c", f"if {{[catch {{tcl port {port}}}]}} {{tcl_port {port}}}",
        "-c", "if {[catch {telnet port disabled}]} {telnet_port disabled}",
        "-c", "if {[catch {gdb port disabled}]} {gdb_port disabled}",
        "-f", "interface/test.cfg", *early,
        "-c", "transport select jtag",
        "-f", "target/first.cfg", *early, "-f", "target/second.cfg", *early,
        "-f", "board/test.cfg", *early,
        "-c", "if {[catch {adapter speed 500}]} {adapter_khz 500}",
        "-c", "jtag newtap sample cpu -irlen 4", *early,
        "-c", "reset_config none", *early,
    ]
    if guard:
        expected += ["-c", semihosting.PRE_INIT_SCRIPT]
    expected += ["-c", "init"]
    if guard:
        expected += ["-c", semihosting.POST_INIT_SCRIPT]
    assert process.build_argv("/opt/openocd", **_argv_inputs(), tcl_port=port, semihosting_guard=guard) == expected


@pytest.mark.parametrize("pipe", [False, True])
def test_minimal_argv_has_only_fixed_ports_interface_and_init(pipe):
    args = dict(
        scripts_dir=None, interface=process.CfgRef("interface/test.cfg", "standard"),
        transport=None, targets=[], extra_cfgs=[], adapter_speed_khz=None,
        extra_commands=[], semihosting_guard=False,
    )
    if pipe:
        actual = process.build_pipe_argv("/opt/openocd", **args)
        port_setup = "if {[catch {tcl port pipe}]} {tcl_port pipe}"
    else:
        actual = process.build_argv("/opt/openocd", **args, tcl_port=0)
        port_setup = "if {[catch {tcl port 0}]} {tcl_port 0}"
    assert actual == [
        "/opt/openocd", "-c", port_setup,
        "-c", "if {[catch {telnet port disabled}]} {telnet_port disabled}",
        "-c", "if {[catch {gdb port disabled}]} {gdb_port disabled}",
        "-f", "interface/test.cfg", "-c", "init",
    ]


def test_pipe_argv_preserves_each_guard_without_network_listener():
    argv = process.build_pipe_argv("/opt/openocd", **_argv_inputs())
    assert argv[:13] == [
        "/opt/openocd", "-d3", "-s", "/opt/pweh-scripts", "-s", "/opt/extra",
        "-c", "if {[catch {tcl port pipe}]} {tcl_port pipe}",
        "-c", "if {[catch {telnet port disabled}]} {telnet_port disabled}",
        "-c", "if {[catch {gdb port disabled}]} {gdb_port disabled}", "-f",
    ]
    for item in (
        "interface/test.cfg", "target/first.cfg", "target/second.cfg", "board/test.cfg",
        "jtag newtap sample cpu -irlen 4", "reset_config none",
    ):
        index = argv.index(item)
        assert argv[index + 1:index + 3] == ["-c", semihosting.EARLY_CHECK_SCRIPT]
    assert argv[-6:] == ["-c", semihosting.PRE_INIT_SCRIPT, "-c", "init", "-c", semihosting.POST_INIT_SCRIPT]
    assert not any("bindto" in token for token in argv)
    assert "tcl port 0" not in " ".join(argv)


@pytest.fixture
def pipe_owner(tmp_path, monkeypatch):
    from openocd_mcp import process_pipe

    def no_network(*args, **kwargs):
        raise AssertionError("pipe 시험은 socket을 열지 않습니다")

    monkeypatch.setattr(socket, "socket", no_network)
    monkeypatch.setattr(socket, "create_connection", no_network)
    counter = 0

    @contextmanager
    def make(mode, *, old_log=None):
        nonlocal counter
        counter += 1
        requests = tmp_path / f"requests-{counter}.txt"
        log = tmp_path / f"stderr-{counter}.log"
        if old_log is not None:
            log.write_bytes(old_log)
        owner = process_pipe.spawn_pipe(
            [sys.executable, "-I", str(FAKE), "--mode", mode, "--requests-file", str(requests)],
            cwd=tmp_path, log_path=log,
        )
        try:
            yield owner, requests, log
        finally:
            result = owner.close(grace=0.2, timeout=3)
            assert result.confirmed, result

    return make


def _count(path):
    return path.read_bytes().count(b"request\n") if path.exists() else 0


@pytest.mark.parametrize("mode", ["ready", "ready-bare", "ready-debug", "ready-crlf", "delayed-marker"])
def test_ready_requires_first_request_and_accepts_either_response_order(pipe_owner, mode):
    with pipe_owner(mode) as (owner, requests, _):
        result = owner.wait_ready(timeout=2)
        assert result.ready, result
        assert result.transport == "pipe" and result.version["parsed"]
        assert result.version["version"] == "0.12.0"
        assert owner.fatal_reason is None
        assert _count(requests) == 1
        # 준비에 쓴 같은 client가 계속 동작하며 별도 연결을 만들지 않는다.
        assert owner.client.call_raw("version", timeout=1).code == 0
        assert _count(requests) == 2


@pytest.mark.parametrize("mode", [
    "marker-only", "version-only", "false-marker", "unquoted-marker", "tcp-marker",
    "partial-marker", "debug-marker", "trailing-marker", "bad-version", "version-error",
    "oversize-version", "exit-after-marker",
])
def test_single_evidence_or_bad_version_never_ready(pipe_owner, mode):
    with pipe_owner(mode) as (owner, requests, _):
        result = owner.wait_ready(timeout=0.4)
        assert not result.ready, (mode, result)
        assert result.transport == "pipe" and result.reason
        assert _count(requests) == 1


def test_old_log_cannot_supply_missing_marker(pipe_owner):
    with pipe_owner("version-only", old_log=b"Info : accepting 'tcl' connection from pipe\n") as (owner, requests, _):
        result = owner.wait_ready(timeout=0.4)
        assert not result.ready
        assert _count(requests) == 1


@pytest.mark.parametrize("mode,expected", [("ready", True), ("version-only", False)])
def test_ready_recheck_does_not_repeat_version_or_respawn(pipe_owner, mode, expected):
    with pipe_owner(mode) as (owner, requests, _):
        first = owner.wait_ready(timeout=0.4)
        second = owner.wait_ready(timeout=0.4)
        assert first.ready is expected and second.ready is expected
        assert _count(requests) == 1
        assert owner.close(grace=0.2, timeout=3).confirmed
        assert not owner.wait_ready(timeout=0.4).ready
        assert _count(requests) == 1


def test_observed_exit_after_reply_is_not_ready(pipe_owner, monkeypatch):
    with pipe_owner("exit-after-version") as (owner, requests, _):
        call = owner.client.call
        observations = []

        def after_exit(*args, **kwargs):
            reply = call(*args, **kwargs)
            # private Popen을 reap하지 않고 stderr EOF 관측까지 시점을 고정한다.
            deadline = time.monotonic() + 1
            while owner.fatal_reason is None and time.monotonic() < deadline:
                time.sleep(0.005)
            observations.append(owner.fatal_reason is not None)
            return reply

        monkeypatch.setattr(owner.client, "call", after_exit)
        result = owner.wait_ready(timeout=2)
        assert not result.ready
        assert all(observations)
        assert _count(requests) == 1


@pytest.mark.parametrize("mode", ["stderr-line-limit", "stderr-total-limit"])
def test_stderr_limit_is_fatal_not_readiness(pipe_owner, mode):
    with pipe_owner(mode) as (owner, requests, log):
        result = owner.wait_ready(timeout=3)
        assert not result.ready
        assert owner.fatal_reason is not None
        assert _count(requests) == 1
        assert log.stat().st_size <= 16 << 20


def test_diagnostic_tail_is_bounded_and_snapshot_is_independent(pipe_owner):
    with pipe_owner("stderr-tail") as (owner, _, log):
        assert owner.wait_ready(timeout=2).ready
        snapshot = owner.diagnostics()
        assert 512 << 10 < snapshot["bytes_seen"] < 16 << 20
        assert len(snapshot["stderr_tail"].encode()) <= 512 << 10
        assert snapshot["logged_bytes"] == log.stat().st_size
        snapshot["errors"].append("caller mutation")
        assert owner.diagnostics()["errors"] == []


def test_diagnostic_errors_are_bounded(pipe_owner):
    with pipe_owner("stderr-errors") as (owner, _, _):
        result = owner.wait_ready(timeout=2)
        assert result.ready
        assert len(result.errors) == 50
        assert all(len(line) <= 512 for line in result.errors)


def test_cancel_after_request_keeps_single_request_and_requires_cleanup(pipe_owner):
    with pipe_owner("marker-only") as (owner, requests, _):
        start = time.monotonic()
        result = owner.wait_ready(timeout=2, cancel_check=lambda: _count(requests) == 1)
        assert not result.ready
        assert time.monotonic() - start < 1.5
        assert _count(requests) == 1


def test_cancel_before_request_sends_nothing(pipe_owner):
    with pipe_owner("ready") as (owner, requests, _):
        result = owner.wait_ready(timeout=1, cancel_check=lambda: True)
        assert not result.ready
        assert _count(requests) == 0


def test_missing_marker_uses_same_deadline_not_second_timeout(pipe_owner):
    with pipe_owner("version-only") as (owner, requests, _):
        start = time.monotonic()
        result = owner.wait_ready(timeout=0.4)
        elapsed = time.monotonic() - start
        assert not result.ready
        assert 0.3 <= elapsed < 0.75
        assert _count(requests) == 1


@pytest.mark.parametrize("timeout", [0, -1, True, math.inf, math.nan])
def test_invalid_ready_timeout_sends_nothing(pipe_owner, timeout):
    with pipe_owner("ready") as (owner, requests, _):
        with pytest.raises(ValidationFailed):
            owner.wait_ready(timeout=timeout)
        assert _count(requests) == 0
