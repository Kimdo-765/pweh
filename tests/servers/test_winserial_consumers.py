"""Linux fake helper로 UART/JTAG의 route·gate·guard·포트 소유 수명을 검증한다."""
from __future__ import annotations

import asyncio
import hashlib
import json
import os
from pathlib import Path
import select
import struct
import subprocess
import sys
import time
from types import SimpleNamespace

import anyio
import pytest
from mcp.server.mcpserver.exceptions import ToolError

from pweh import instrument_guard as G, ports, serialtransport
from pweh.portidentity import PortIdentity
from uart_mcp import server as U
from jtagulator_mcp import server as J

SOURCE = "1" * 40
TOKEN = "2" * 32
ENV = {"kind": "WSL2_INTEROP", "wsl": {"interop": {"usable": True}}, "windows": {}}


@pytest.fixture
def anyio_backend():
    return "asyncio"


def make_fake(root: Path, **config) -> Path:
    """시험 상수를 복사본에 고정한다. 운영 환경변수로 fake 동작을 선택하지 않는다."""
    path = root / "pweh-serial-helper.exe"
    source = Path(__file__).with_name("fake_serial_helper.py").read_text(encoding="utf-8")
    path.write_text("FAKE_CONFIG = " + repr({"source_commit": SOURCE, **config}) + "\n" + source, encoding="utf-8")
    path.chmod(0o755)
    return path


def read_frame(child, timeout=3):
    deadline = time.monotonic() + timeout
    def exact(length):
        result = bytearray()
        while len(result) < length:
            remaining = deadline - time.monotonic()
            assert remaining > 0, "합성 helper frame 시간 초과"
            assert select.select([child.stdout], [], [], remaining)[0]
            chunk = os.read(child.stdout.fileno(), length - len(result))
            assert chunk, "합성 helper frame 중간 EOF"
            result.extend(chunk)
        return bytes(result)
    kind, length = struct.unpack("<cH", exact(3))
    return kind, exact(length)


def write_frame(child, kind, payload):
    child.stdin.write(kind + struct.pack("<H", len(payload)) + payload)
    child.stdin.flush()


def test_fake_independent_wire_roundtrip(workspace, tmp_path):
    """운영 codec과 무관한 고정 bytes로 fake 자체의 기대값을 먼저 확인한다."""
    exe = make_fake(tmp_path, fragment=1)
    with subprocess.Popen([sys.executable, "-I", str(exe), "--echo", "--token", TOKEN], stdin=subprocess.PIPE,
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE, bufsize=0) as child:
        kind, hello = read_frame(child)
        assert kind == b"H" and hello == struct.pack("<HHBBBB20sHH", 1, 0, 0, 1, 0, 1, bytes.fromhex(SOURCE), 16384, 0)
        write_frame(child, b"O", struct.pack("<IIBBBBBB", 1, 115200, 8, 0, 0, 0, 1, 0))
        assert read_frame(child) == (b"o", struct.pack("<IBIBI", 1, 0, 0, 0, 1))
        data = bytes(range(256))
        write_frame(child, b"D", struct.pack("<II", 2, 1000) + data)
        assert read_frame(child) == (b"D", struct.pack("<I", 1) + data)
        assert read_frame(child) == (b"A", struct.pack("<IBBIIII", 2, ord("D"), 0, 0, 256, 1, 0))
        write_frame(child, b"P", struct.pack("<IBI", 3, 0, 1000))
        assert read_frame(child) == (b"A", struct.pack("<IBBIIII", 3, ord("P"), 0, 0, 0, 2, 0))
        write_frame(child, b"Q", struct.pack("<I", 4))
        assert read_frame(child) == (b"A", struct.pack("<IBBIIII", 4, ord("Q"), 0, 0, 0, 2, 0))
        assert child.wait(timeout=3) == 0 and child.stdout.read() == b""


@pytest.mark.parametrize("args", [["--version"], ["--port", "COM0", "--token", TOKEN],
                                  ["--port", "COM4097", "--token", TOKEN],
                                  ["--port", r"\\.\PhysicalDrive0", "--token", TOKEN]])
def test_fake_refuses_non_contract_argv(workspace, tmp_path, args):
    exe = make_fake(tmp_path)
    result = subprocess.run([sys.executable, "-I", str(exe), *args], stdin=subprocess.DEVNULL, capture_output=True, timeout=3)
    assert result.returncode == 2 and result.stdout == b""


@pytest.fixture
def helper_env(workspace, tmp_path, monkeypatch, isolated_ports):
    from pweh.winserial import pin
    from pweh.winserial.binary import resolve_helper
    from pweh.winserial.serial import HelperSerial

    log = tmp_path / "frames.jsonl"
    children, helpers, launches = [], [], []
    identity = ["fixture-a"]
    lifecycle = SimpleNamespace(confirmed=True, checks=0, terminations=0)
    def check_port(port, deadline):
        lifecycle.checks += 1
    def terminate_and_confirm(token, image_path, deadline):
        lifecycle.terminations += 1
        return lifecycle.confirmed
    lifecycle.check_port = check_port
    lifecycle.terminate_and_confirm = terminate_and_confirm

    def configure(**options):
        path = make_fake(tmp_path, log=str(log), **options)
        monkeypatch.setattr(pin, "PINNED_SHA256", hashlib.sha256(path.read_bytes()).hexdigest())
        monkeypatch.setattr(pin, "EXPECTED_SOURCE_COMMIT", SOURCE)
        monkeypatch.setattr(pin, "HELPER_VERSION", (0, 1, 0))
        monkeypatch.setenv("PWEH_SERIAL_HELPER", str(path))
        return path

    exe = configure()
    def process_factory(argv, **kwargs):
        launches.append(tuple(argv))
        child = subprocess.Popen([sys.executable, "-I", argv[0], *argv[1:]], **kwargs)
        children.append(child)
        if context.on_launch is not None:
            context.on_launch()
        return child

    def factory(*, port, before_open=None, **settings):
        helper = resolve_helper(configured=str(exe), env_value=None, tools_root=tmp_path)
        raw = HelperSerial(helper=helper, port=None, environment_provider=lambda: ENV,
                           process_factory=process_factory, windows_lifecycle=lifecycle,
                           runtime_root=tmp_path / "helper-runtime", before_open=before_open, **settings)
        raw.port = port
        helpers.append(raw)
        return raw

    def observe(ref, **kwargs):
        parent = "USB\\VID_10C4&PID_EA60\\" + identity[0]
        return PortIdentity(str(ref), "known", present=True, backend="windows", vid="10c4", pid="ea60",
                            serial=identity[0], serial_basis="instance-tail",
                            device_instance=parent, usb_ancestor=parent, parent_instance=parent)

    monkeypatch.setattr(serialtransport, "_make_helper", factory)
    monkeypatch.setattr(U, "_port_environment", lambda: ENV)
    monkeypatch.setattr(J, "_port_environment", lambda: ENV)
    monkeypatch.setattr(ports, "_probe_identity", observe)
    tags = G.InstrumentTagStore(tmp_path / "instrument-tags")
    monkeypatch.setattr(G, "InstrumentTagStore", lambda: tags)
    monkeypatch.setattr(G, "probe_identity", lambda *a, **k: pytest.fail("실제 PnP 호출 금지"))
    import serial
    monkeypatch.setattr(serial, "serial_for_url", lambda *a, **k: pytest.fail("COM이 POSIX serial factory에 도달함"))
    def records():
        return [json.loads(line) for line in log.read_text().splitlines()] if log.exists() else []
    context = SimpleNamespace(configure=configure, records=records, launches=launches, children=children,
                              helpers=helpers, identity=identity, lifecycle=lifecycle, exe=exe, log=log,
                              runtime_root=tmp_path / "helper-runtime", manager=isolated_ports["manager"], on_launch=None)
    yield context
    lifecycle.confirmed = True
    U.shutdown_all("합성 Windows helper 시험 종료")
    J._shutdown_all()
    for raw in helpers:
        raw.close()
    for child in children:
        if child.poll() is None:
            child.kill()
        child.wait(timeout=3)


async def wait_until(predicate, timeout=5):
    with anyio.fail_after(timeout):
        while not predicate():
            await anyio.sleep(0.005)


@pytest.mark.anyio
async def test_uart_helper_framing_signals_and_close(workspace, auth, helper_env):
    case = U.rt().cases.create(title="합성 COM UART", authorization=auth)
    opened = await U.uart_open(case.id, "COM31", None, dtr=True, rts=False)
    assert opened["route"]["backend"] == "win-helper"
    assert helper_env.manager.held_by("win:COM31") is not None
    session = U._SESSIONS[opened["session_id"]]
    await U.uart_sync(session.id, None)
    assert await U.uart_set_signals(session.id, None, dtr=False, rts=True)
    records = helper_env.records()
    o = next(row for row in records if row["event"] == "open")
    assert (o["dtr"], o["rts"], o["baud"]) == (1, 0, 115200)
    assert [row for row in records if row["event"] == "signals"][-1]["rts"] == 1
    assert records.index(o) < next(i for i, row in enumerate(records) if row["event"] == "write")
    assert len(helper_env.launches) == 1
    await U.uart_close(session.id)
    assert helper_env.manager.held_by("win:COM31") is None
    assert all(child.poll() == 0 for child in helper_env.children)


@pytest.mark.anyio
async def test_jtag_helper_connection_reuses_one_process(workspace, auth, helper_env):
    helper_env.configure(app="jtag", fragment=1)
    case = J.rt().cases.create(title="합성 COM JTAG", authorization=auth)
    first = await J.jtagulator_connect(case.id, "COM32")
    assert first["ok"] and first["firmware"] == "1.12"
    conn = J._CONNS[case.id]
    assert conn.route.backend == "win-helper"
    second = await J.jtagulator_connect(case.id, "COM32")
    assert second["reused"] and J._CONNS[case.id].lease is conn.lease
    assert len(helper_env.launches) == 1
    await J.jtagulator_disconnect(case.id)
    assert helper_env.manager.held_by("win:COM32") is None


@pytest.mark.anyio
async def test_uart_helper_one_open_baud(workspace, auth, helper_env):
    helper_env.configure(baud_text=False)
    case = U.rt().cases.create(title="합성 COM 속도 탐지", authorization=auth)
    result = await U.uart_detect_baud(case.id, "COM33", None, candidates=[9600, 19200, 38400], listen_seconds=0.1, probe="none")
    assert result["ok"]
    records = helper_env.records()
    assert len([row for row in records if row["event"] == "open"]) == 1
    assert [row["baud"] for row in records if row["event"] == "baud"] == [19200, 38400]
    assert len(helper_env.launches) == 1 and helper_env.manager.held_by("win:COM33") is None


@pytest.mark.anyio
@pytest.mark.parametrize("consumer", ["uart", "jtag"])
@pytest.mark.parametrize("change", ["none", "before-gate", "after-gate"])
async def test_helper_approval_is_bound_to_fresh_route(workspace, auth, helper_env, monkeypatch, consumer, change):
    from dataclasses import replace
    workspace["set_safety"](modify_policy="approve", approval_methods=["cli"])
    server = U if consumer == "uart" else J
    runtime = server.rt()
    helper_env.configure(app=consumer)
    case = runtime.cases.create(title="합성 COM 승인 결속", authorization=auth)
    original_resolve = ports.resolve
    monkeypatch.setattr(ports, "resolve", lambda *a, **k: replace(original_resolve(*a, **k), reset_risk="wired"))
    async def connect(approval_id=None):
        if consumer == "uart":
            return await U.uart_open(case.id, "COM34", None, approval_id=approval_id)
        return await J.jtagulator_connect(case.id, "COM34", approval_id=approval_id)
    first = await connect()
    assert first["status"] == "approval_required" and not helper_env.launches
    assert helper_env.manager.held_by("win:COM34") is None
    approval = runtime.approvals.get(first["approval_id"])
    assert approval["action"]["route"]["backend"] == "win-helper"
    assert approval["action"]["route"]["device_id"] is not None
    runtime.approvals.decide(approval["id"], approve=True, code=approval["code"], via="test")
    if change == "before-gate":
        helper_env.identity[0] = "fixture-b"
    elif change == "after-gate":
        original_authorize = runtime.authorize
        async def authorize(**kwargs):
            decision = await original_authorize(**kwargs)
            helper_env.identity[0] = "fixture-b"
            return decision
        monkeypatch.setattr(runtime, "authorize", authorize)
    if change == "after-gate":
        with pytest.raises(ToolError, match="route_changed"):
            await connect(approval["id"])
    else:
        result = await connect(approval["id"])
        if change == "before-gate":
            assert not result["ok"] and not helper_env.launches
        else:
            assert result["ok"] and len(helper_env.launches) == 1
            if consumer == "uart":
                await U.uart_close(result["session_id"])
            else:
                await J.jtagulator_disconnect(case.id)
    if change != "none":
        assert not helper_env.launches
    assert helper_env.manager.held_by("win:COM34") is None


def pin_instrument(runtime):
    mac = "020000000001"
    subject = {"schema": G.PIN_SCHEMA, "base_mac": mac, "native_usb": {"serial": mac},
               "boot_usb": [{"serial": "rom-fixture"}], "aux_usb": [{"serial": "aux-fixture"}]}
    row = runtime.attestations.request("instrument-pin", subject, {"scope": "instrument", "instrument_id": mac}, G.PIN_QUESTIONS)
    runtime.attestations.decide(row["id"], {q["id"]: "yes" for q in G.PIN_QUESTIONS}, via="cli-tty", by="synthetic")


@pytest.mark.anyio
@pytest.mark.parametrize("consumer", ["uart", "jtag"])
async def test_pinned_instrument_is_denied_before_helper_launch(workspace, auth, helper_env, monkeypatch, consumer):
    server = U if consumer == "uart" else J
    runtime = server.rt()
    case = runtime.cases.create(title="합성 COM 계측기 보호", authorization=auth)
    pin_instrument(runtime)
    identity = PortIdentity("COM35", "known", present=True, backend="windows-pnp", vid="303a", pid="4001", serial="020000000001")
    monkeypatch.setattr(G, "probe_identity", lambda *a, **k: identity)
    monkeypatch.setattr(runtime, "authorize", lambda **kwargs: pytest.fail("계측기 거부 전에 승인 호출"))
    with pytest.raises(ToolError, match="instrument_port"):
        if consumer == "uart":
            await U.uart_open(case.id, "COM35", None)
        else:
            await J.jtagulator_connect(case.id, "COM35")
    assert not helper_env.launches and helper_env.manager.held_by("win:COM35") is None


@pytest.mark.anyio
async def test_new_instrument_pin_prevents_helper_data_frame(workspace, auth, helper_env, monkeypatch):
    runtime = U.rt()
    case = runtime.cases.create(title="합성 COM 추가 고정", authorization=auth)
    result = await U.uart_open(case.id, "COM36", None)
    session = U._SESSIONS[result["session_id"]]
    before = [row for row in helper_env.records() if row["event"] == "write"]
    pin_instrument(runtime)
    identity = PortIdentity("COM36", "known", present=True, backend="windows-pnp", vid="303a", pid="4001", serial="020000000001")
    monkeypatch.setattr(G, "probe_identity", lambda *a, **k: identity)
    with pytest.raises(ToolError, match="instrument_port"):
        await U.uart_sync(session.id, None)
    assert [row for row in helper_env.records() if row["event"] == "write"] == before
    assert helper_env.manager.held_by("win:COM36") is not None
    await U.uart_close(session.id)
    assert helper_env.manager.held_by("win:COM36") is None


@pytest.mark.anyio
async def test_helper_target_role_blocks_probe_after_uart_close(workspace, auth, helper_env):
    case = U.rt().cases.create(title="합성 COM 역할 표지", authorization=auth)
    opened = await U.uart_open(case.id, "COM37", None)
    await U.uart_close(opened["session_id"])
    with pytest.raises(ToolError, match="port_role_conflict"):
        await J.jtagulator_connect(case.id, "COM37")
    assert len(helper_env.launches) == 1
    assert helper_env.manager.held_by("win:COM37") is None


@pytest.mark.anyio
@pytest.mark.parametrize("consumer", ["uart", "jtag"])
async def test_helper_hash_mismatch_does_not_launch_or_leave_lease(workspace, auth, helper_env, consumer):
    runtime = U.rt() if consumer == "uart" else J.rt()
    case = runtime.cases.create(title="합성 helper 핀 불일치", authorization=auth)
    with helper_env.exe.open("a") as stream:
        stream.write("\n# 합성 변조\n")
    with pytest.raises(ToolError, match="serial_helper_hash_mismatch"):
        if consumer == "uart":
            await U.uart_open(case.id, "COM38", None)
        else:
            await J.jtagulator_connect(case.id, "COM38")
    assert not helper_env.launches and helper_env.manager.held_by("win:COM38") is None


@pytest.mark.anyio
@pytest.mark.parametrize("consumer", ["uart", "jtag"])
async def test_raw_cancel_during_helper_open_keeps_worker_owner(workspace, auth, helper_env, tmp_path, consumer):
    release = tmp_path / "open-release"
    helper_env.configure(app=consumer, open_release=str(release))
    runtime = U.rt() if consumer == "uart" else J.rt()
    case = runtime.cases.create(title="합성 helper open 취소", authorization=auth)
    request = U.uart_open(case.id, "COM39", None) if consumer == "uart" else J.jtagulator_connect(case.id, "COM39")
    task = asyncio.create_task(request)
    try:
        await wait_until(lambda: any(row["event"] == "open" for row in helper_env.records()))
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        assert helper_env.manager.held_by("win:COM39") is not None
        assert helper_env.children[0].poll() is None
    finally:
        release.touch()
    await wait_until(lambda: helper_env.manager.held_by("win:COM39") is None, timeout=8)
    assert all(child.poll() == 0 for child in helper_env.children)
    assert not any(s.case_id == case.id for s in U._SESSIONS.values()) and case.id not in J._CONNS


@pytest.mark.anyio
@pytest.mark.parametrize("consumer", ["uart", "jtag"])
async def test_helper_disconnect_retains_lease_until_explicit_close(workspace, auth, helper_env, tmp_path, consumer):
    trigger = tmp_path / "disconnect"
    helper_env.configure(app=consumer, disconnect_file=str(trigger))
    runtime = U.rt() if consumer == "uart" else J.rt()
    case = runtime.cases.create(title="합성 helper 단절", authorization=auth)
    if consumer == "uart":
        result = await U.uart_open(case.id, "COM40", None)
        session = U._SESSIONS[result["session_id"]]
    else:
        await J.jtagulator_connect(case.id, "COM40")
    trigger.touch()
    with pytest.raises(ToolError):
        if consumer == "uart":
            await U.uart_sync(session.id, None)
        else:
            await J.jtagulator_version(case.id)
    assert helper_env.manager.held_by("win:COM40") is not None
    if consumer == "uart":
        await U.uart_close(session.id)
    else:
        await J.jtagulator_disconnect(case.id)
    assert helper_env.manager.held_by("win:COM40") is None


@pytest.mark.anyio
async def test_unknown_helper_cleanup_keeps_lease_for_retry(workspace, auth, helper_env):
    helper_env.configure(fault="drop-quit-ack")
    case = U.rt().cases.create(title="합성 helper 종료 미확인", authorization=auth)
    result = await U.uart_open(case.id, "COM41", None)
    session = U._SESSIONS[result["session_id"]]
    helper_env.lifecycle.confirmed = False
    with pytest.raises(ToolError):
        await U.uart_close(session.id)
    assert not session.ser.closed and helper_env.manager.held_by("win:COM41") is not None
    assert session.id in U._SESSIONS
    helper_env.lifecycle.confirmed = True
    await U.uart_close(session.id)
    assert session.ser.closed and helper_env.manager.held_by("win:COM41") is None


@pytest.mark.anyio
@pytest.mark.parametrize("consumer", ["uart", "jtag"])
async def test_helper_open_rejection_is_cleaned_without_orphan(workspace, auth, helper_env, consumer):
    helper_env.configure(fault="open-busy", app=consumer)
    runtime = U.rt() if consumer == "uart" else J.rt()
    case = runtime.cases.create(title="합성 helper OPEN 거부", authorization=auth)
    with pytest.raises(ToolError):
        if consumer == "uart":
            await U.uart_open(case.id, "COM42", None)
        else:
            await J.jtagulator_connect(case.id, "COM42")
    assert len(helper_env.launches) == 1
    assert helper_env.manager.held_by("win:COM42") is None
    assert not any(s.case_id == case.id for s in U._SESSIONS.values()) and case.id not in J._CONNS
    assert all(child.poll() == 0 for child in helper_env.children)


@pytest.mark.anyio
@pytest.mark.parametrize("consumer", ["uart", "jtag"])
async def test_route_change_after_helper_launch_blocks_open_frame(workspace, auth, helper_env, consumer):
    helper_env.configure(app=consumer)
    runtime = U.rt() if consumer == "uart" else J.rt()
    case = runtime.cases.create(title="합성 helper OPEN 직전 경로 변경", authorization=auth)
    helper_env.on_launch = lambda: helper_env.identity.__setitem__(0, "fixture-b")
    with pytest.raises(ToolError, match="route_changed"):
        if consumer == "uart":
            await U.uart_open(case.id, "COM43", None)
        else:
            await J.jtagulator_connect(case.id, "COM43")
    assert len(helper_env.launches) == 1
    assert not [row for row in helper_env.records() if row["event"] in ("open", "write")]
    assert helper_env.manager.held_by("win:COM43") is None
    assert all(child.poll() == 0 for child in helper_env.children)
