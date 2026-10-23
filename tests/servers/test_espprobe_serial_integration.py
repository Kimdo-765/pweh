"""실제 admission/owner/공통 transport를 합성 POSIX·Linux helper에 연결한다."""
from __future__ import annotations

import asyncio
from dataclasses import asdict, replace
import hashlib
import json
from pathlib import Path
import stat
import subprocess
import sys
import termios
import threading
import time
from types import SimpleNamespace

import anyio
import pytest

from pweh import serialtransport as T
from pweh.portlock import PortOwner
from pweh.errors import PwehError
from pweh.procutil import child_exited
from pweh.winserial import pin
from pweh.winserial.binary import resolve_helper
from pweh.winserial.serial import HelperSerial

from .fake_espprobe_serial import Peer, SOURCE_COMMIT, TOKEN

ENV = {"kind": "WSL2_INTEROP", "wsl": {"interop": {"usable": True}}, "windows": {}}
SENTINEL = "PRIVATE-CALLBACK-RAW-COM4096"


@pytest.fixture
def anyio_backend():
    return "asyncio"


def fields_for(admission):
    release = admission.release
    fields = {key: getattr(release, key) for key in (
        "fw_name", "fw_version", "build_profile", "board", "git_commit", "idf_version",
        "image_sha256", "app_elf_sha256")}
    return {**fields, "base_mac": admission.base_mac, "chip_revision": admission.chip_revision,
            "usb_vid": release.usb.vid, "usb_pid": release.usb.pid, "usb_product": release.usb.product}


class MemoryRaw:
    """fake POSIX fd를 사용하는 작은 raw. frame 원문은 시험 메모리에만 보유한다."""

    def __init__(self, peer, events, settings):
        self.peer, self.events = peer, events
        self.condition = threading.Condition()
        self.rx = bytearray()
        self.is_open = False
        self.dtr = self.rts = True
        self.__dict__.update(settings)
        self.read_chunk = 7
        self.write_chunk = 11
        self.write_timeouts = []
        self.io_threads = set()

    def open(self):
        assert self.dtr is self.rts is False
        self.io_threads.add(threading.get_ident())
        self.events.append("raw-open")
        self.is_open = True

    def close(self):
        self.io_threads.add(threading.get_ident())
        self.events.append("raw-close")
        with self.condition:
            self.is_open = False
            self.condition.notify_all()

    def fileno(self):
        return 911

    @property
    def in_waiting(self):
        with self.condition:
            return len(self.rx)

    def read(self, size):
        assert 0 < size <= 16384
        self.io_threads.add(threading.get_ident())
        with self.condition:
            if not self.rx and self.is_open:
                self.condition.wait(self.timeout)
            size = min(size, self.read_chunk, len(self.rx))
            result = bytes(self.rx[:size])
            del self.rx[:size]
            return result

    def write(self, data):
        self.io_threads.add(threading.get_ident())
        assert 0 < self.write_timeout <= 5
        self.write_timeouts.append(self.write_timeout)
        data = bytes(data[:self.write_chunk])
        response = self.peer.feed(data)
        with self.condition:
            self.rx.extend(response)
            self.condition.notify_all()
        return len(data)

    def cancel_read(self):
        with self.condition:
            self.condition.notify_all()


@pytest.fixture
def connected(workspace, tmp_path, monkeypatch, isolated_ports):
    """모든 실제 포트 factory를 막고 공통 함수에만 명시 fake를 넘긴다."""
    from pweh import espprobe_admission as A
    from espprobe_mcp import serial_owner as B
    from core.test_espprobe_admission import make_inputs
    import serial
    from pweh.winserial import process as helper_process
    from pweh.winserial import windows

    contexts = []

    def forbidden(*_args, **_kwargs):
        raise AssertionError("실제 포트/Windows 환경 조회 금지")

    monkeypatch.setattr(serial, "serial_for_url", forbidden)
    monkeypatch.setattr(serial, "Serial", forbidden)
    monkeypatch.setattr(T, "_make_helper", forbidden)
    monkeypatch.setattr(helper_process, "_environment", forbidden)
    monkeypatch.setattr(windows.WindowsLifecycle, "check_port", forbidden)
    monkeypatch.setattr(windows.WindowsLifecycle, "terminate_and_confirm", forbidden)

    def build(backend="win-helper", *, fault="", fragment=17, delayed_open=False):
        root = tmp_path / ("fixture-" + str(len(contexts)))
        root.mkdir()
        endpoint = "COM4096" if backend == "win-helper" else "/dev/ttyACM4096"
        inputs = make_inputs(backend=backend, case_id="i5-serial-" + str(len(contexts)), endpoint=endpoint)
        admission = A.validate_probe_admission(**inputs)
        manager = isolated_ports["manager"]
        lease = manager.acquire(admission.claim_keys, owner=PortOwner("espprobe-test", admission.case_id, endpoint))
        owner = B.reserve_probe_owner(admission.case_id, admission, lease)
        log, barrier = root / "events.jsonl", root / "open-release"
        events, children, helpers, raws = [], [], [], []
        life = SimpleNamespace(confirmed=True, checks=0, terminations=0, ordered=[])

        def check_port(port, deadline):
            assert port == "COM4096" and deadline > time.monotonic()
            life.checks += 1

        def terminate(_token, _path, _deadline):
            life.terminations += 1
            life.ordered.append(all(child_exited(child.pid) for child in children))
            return life.confirmed

        life.check_port, life.terminate_and_confirm = check_port, terminate
        config = {"peer": fields_for(admission), "log": str(log), "fault": fault, "fragment": fragment}
        if delayed_open:
            config["open_release"] = str(barrier)
        exe = root / "pweh-serial-helper.exe"
        exe.write_text("FAKE_CONFIG = " + repr(config) + "\n" +
                       Path(__file__).with_name("fake_espprobe_serial.py").read_text(encoding="utf-8"), encoding="utf-8")
        exe.chmod(0o755)
        monkeypatch.setattr(pin, "PINNED_SHA256", hashlib.sha256(exe.read_bytes()).hexdigest())
        monkeypatch.setattr(pin, "EXPECTED_SOURCE_COMMIT", SOURCE_COMMIT)
        monkeypatch.setattr(pin, "HELPER_VERSION", (0, 1, 0))

        def launch(argv, **kwargs):
            assert argv[1:3] == ["--port", "COM4096"] and argv[3] == "--token"
            child = subprocess.Popen([sys.executable, "-I", argv[0], *argv[1:]], **kwargs)
            children.append(child)
            return child

        def helper_factory(*, port, before_open, **settings):
            raw = HelperSerial(helper=resolve_helper(configured=str(exe), env_value=None, tools_root=root),
                               port=None, before_open=before_open, environment_provider=lambda: ENV,
                               process_factory=launch, windows_lifecycle=life,
                               runtime_root=root / "helper-runtime", **settings)
            raw.port = port
            helpers.append(raw)
            return raw

        def serial_factory(path, **settings):
            assert path == endpoint and settings.pop("do_not_open") and settings.pop("exclusive")
            raw = MemoryRaw(Peer(fields_for(admission), fault=fault), events, settings)
            raws.append(raw)
            return raw

        def before():
            lease.assert_held(admission.claim_keys)
            if backend == "win-helper" and "before" in events:
                observed = records()
                assert any(row["event"] == "hello" for row in observed)
                assert not any(row["event"] in ("open", "probe") for row in observed)
            events.append("before")

        def after():
            lease.assert_held(admission.claim_keys)
            if backend == "win-helper":
                observed = records()
                assert sum(row["event"] == "opened" for row in observed) == 1
                assert not any(row["event"] == "probe" for row in observed)
            events.append("after")

        def records():
            if not log.exists():
                return []
            text = log.read_text(encoding="utf-8")
            lines = text.splitlines()
            if text and not text.endswith("\n"):
                lines = lines[:-1]
            return [json.loads(line) for line in lines]

        context = SimpleNamespace(owner=owner, admission=admission, inputs=inputs, lease=lease,
                                  manager=manager, events=events, children=children, helpers=helpers,
                                  raws=raws, life=life, records=records, barrier=barrier,
                                  before=before, after=after, root=root, backend=backend)

        def common_open(route, settings, **kwargs):
            kwargs.update(serial_factory=serial_factory, helper_factory=helper_factory,
                          ioctl_fn=lambda fd, op: events.append(op))
            if backend == "posix-tty":
                dev, ino, rdev = route.node_identity
                kwargs["fstat_fn"] = lambda _fd: SimpleNamespace(st_dev=dev, st_ino=ino, st_rdev=rdev,
                                                                st_mode=stat.S_IFCHR | 0o600)
            return T.open_serial(route, settings, **kwargs)

        monkeypatch.setattr(B, "open_serial", common_open)
        context.start = lambda: owner.start(before_open=context.before, after_open=context.after,
                                           deadline=time.monotonic() + 5)
        contexts.append(context)
        return context

    yield build
    for context in contexts:
        context.barrier.touch()
        context.life.confirmed = True
        context.owner.close(deadline=time.monotonic() + 10)
        for raw in context.helpers:
            raw.close()
        for child in context.children:
            if child.poll() is None:
                child.kill()
            child.wait(timeout=3)
        assert context.lease.closed


def assert_busy(context):
    for key in context.admission.claim_keys:
        with pytest.raises(PwehError) as error:
            context.manager.acquire([key], owner=PortOwner("rival", "other", "synthetic"))
        assert error.value.code == "busy"  # 공통 manager 오류이며 owner의 고정 오류와 구분한다.


def assert_released(context):
    assert context.lease.closed
    lease = context.manager.acquire(context.admission.claim_keys, owner=PortOwner("rival", "other", "synthetic"))
    lease.close()


@pytest.mark.parametrize("backend", ["posix-tty", "win-helper"])
@pytest.mark.parametrize("operation,opcode", [("release", 2), ("close", 3)])
def test_registered_admission_through_real_transport(connected, backend, operation, opcode):
    context = connected(backend, fragment=1)
    hello = context.start()
    assert hello.release == context.admission.release and hello.session_token == TOKEN
    assert_busy(context)
    status = context.owner.self_test(deadline=time.monotonic() + 5)
    assert status.hello_verified and status.self_tests == 1 and status.heartbeat_acked >= 1
    result = getattr(context.owner, operation)(deadline=time.monotonic() + 5)
    assert result.protocol_released and result.cleanup_confirmed
    assert result.workers_stopped and result.transport_closed and result.lease_closed
    assert_released(context)
    if backend == "posix-tty":
        raw = context.raws[0]
        assert len(raw.io_threads) == 1
        assert context.events[:4] == ["before", "raw-open", termios.TIOCEXCL, "after"]
        assert context.events[-2:] == [termios.TIOCNXCL, "raw-close"]
        assert raw.write_timeouts
        assert raw.peer.frames[-1][:3] == (1, opcode, 2)
    else:
        records = context.records()
        assert context.events == ["before", "before", "after"]
        assert context.life.checks == 1 and len(context.children) == 1
        assert {r["kind"] for r in records if r["event"] == "helper"} == {"O", "D", "Q"}
        assert [r for r in records if r["event"] == "open"] == [
            {"event": "open", "baud": 115200, "bits": 8, "dtr": 0, "rts": 0}]
        assert [r["op"] for r in records if r["event"] == "probe" and r["type"] == 1] == [1, opcode]
        assert all(1 <= r["timeout_ms"] <= 5000 for r in records if r["event"] == "write")
        assert context.helpers[0].cleanup_verified
    assert context.owner.close(deadline=time.monotonic() + 2).cleanup_confirmed


@pytest.mark.parametrize("when", ["first", "helper-open", "after"])
def test_fresh_callback_refusal_keeps_expected_io_zero(connected, when):
    context = connected()
    count = 0

    def before():
        nonlocal count
        count += 1
        if (when == "first" and count == 1) or (when == "helper-open" and count == 2):
            raise RuntimeError(SENTINEL)

    def after():
        if when == "after":
            raise RuntimeError(SENTINEL)

    context.before, context.after = before, after
    with pytest.raises(PwehError) as error:
        context.start()
    assert SENTINEL not in str(error.value.to_dict()) and error.value.data == {}
    assert error.value.__suppress_context__
    records = context.records()
    assert not any(r["event"] == "probe" for r in records)
    assert sum(r["event"] == "open" for r in records) == int(when == "after")
    assert len(context.children) == int(when != "first")
    assert context.owner.close(deadline=time.monotonic() + 5).cleanup_confirmed
    assert_released(context)


def test_protocol_ack_does_not_replace_helper_process_cleanup(connected):
    context = connected(fault="drop-quit-ack")
    context.start()
    context.life.confirmed = False
    result = context.owner.close(deadline=time.monotonic() + 5)
    assert result.protocol_released and not result.cleanup_confirmed
    assert result.workers_stopped and not result.transport_closed and not result.lease_closed
    assert context.owner.snapshot().state == "orphan"
    assert_busy(context)
    raw = context.helpers[0]
    assert not raw.cleanup_verified and raw._run.copy.path.exists()
    assert context.life.terminations >= 1 and all(context.life.ordered)
    assert len(context.children) == 1
    context.life.confirmed = True
    result = context.owner.close(deadline=time.monotonic() + 5)
    assert result.cleanup_confirmed and raw.cleanup_verified
    assert_released(context)
    assert len(context.children) == 1
    assert sum(r["event"] == "open" for r in context.records()) == 1


@pytest.mark.parametrize("fault,ack", [("drop-first-cleanup", True), ("drop-cleanup", False)])
def test_missing_protocol_ack_and_physical_cleanup_are_independent(connected, fault, ack):
    context = connected(fault=fault)
    context.start()
    result = context.owner.release(deadline=time.monotonic() + 2)
    assert result.protocol_released is ack
    # ACK 시간 상한에 도달한 뒤의 물리 정리는 같은 worker를 다시 기다려 확인한다.
    if not result.cleanup_confirmed:
        assert_busy(context)
        result = context.owner.close(deadline=time.monotonic() + 5)
    assert result.protocol_released is ack and result.cleanup_confirmed
    requests = [r for r in context.records() if r["event"] == "probe" and r["op"] == 2]
    assert requests == [{"event": "probe", "type": 1, "op": 2, "seq": 2}] * 2
    assert_released(context)


@pytest.mark.anyio
async def test_late_helper_open_after_raw_cancel_keeps_lease_until_physical_close(connected):
    from espprobe_mcp import serial_owner as B
    context = connected(delayed_open=True)
    task = asyncio.create_task(B.start_probe_worker(context.owner, before_open=context.before,
                                                   after_open=context.after, deadline=time.monotonic() + 5))
    with anyio.fail_after(5):
        while not any(r["event"] == "open" for r in context.records()):
            await anyio.sleep(.005)
    task.cancel()
    await anyio.sleep(.02)
    assert_busy(context)
    assert not context.lease.closed
    assert not any(r["event"] == "probe" for r in context.records())
    context.barrier.touch()
    with pytest.raises(asyncio.CancelledError):
        await task
    result = await asyncio.to_thread(context.owner.close, deadline=time.monotonic() + 5)
    assert result.cleanup_confirmed
    assert not any(r["event"] == "probe" for r in context.records())
    assert_released(context)


def test_status_and_fixed_errors_do_not_publish_identity_or_wire(connected):
    context = connected(fault="wrong-hb-token")
    with pytest.raises(PwehError) as error:
        context.start()
        context.owner.self_test(deadline=time.monotonic() + 5)
    snapshot = asdict(context.owner.snapshot())
    rendered = json.dumps({"error": error.value.to_dict(), "status": snapshot})
    for private in (context.admission.base_mac, context.admission.pin_id,
                    context.admission.release.image_sha256, "COM4096", str(TOKEN), "a5" * 16):
        assert private not in rendered
    # start 반환 직후 이미 terminal이 됐다면 새 self_test는 busy로 거부할 수 있다.
    # 어느 순서에서도 실제 취소가 없던 protocol 원인이 cancelled로 바뀌면 안 된다.
    assert error.value.code in {"espprobe_protocol", "port_busy"}
    assert snapshot["terminal_reason"] == "espprobe_protocol"
    assert context.owner.close(deadline=time.monotonic() + 5).cleanup_confirmed
    assert len(context.children) == 1


@pytest.mark.parametrize("missing", ["pin", "observation", "scope_keys"])
def test_missing_admission_facts_never_acquire_or_open(workspace, monkeypatch, isolated_ports, missing):
    from pweh.espprobe_admission import validate_probe_admission
    from core.test_espprobe_admission import make_inputs
    inputs = make_inputs(endpoint="COM4096")
    if missing == "pin":
        inputs["authority"] = replace(inputs["authority"], pin=None)
    elif missing == "scope_keys":
        inputs[missing] = inputs[missing][:-1]
    else:
        inputs[missing] = None
    monkeypatch.setattr(isolated_ports["manager"], "acquire", lambda *_a, **_k: pytest.fail("입장 전 lease 금지"))
    monkeypatch.setattr(T, "open_serial", lambda *_a, **_k: pytest.fail("입장 전 open 금지"))
    with pytest.raises(PwehError) as error:
        validate_probe_admission(**inputs)
    assert error.value.code in {"firmware_not_pinned", "instrument_identity_unknown", "route_changed"}
    assert error.value.data == {}
