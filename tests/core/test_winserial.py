"""장치 없는 helper codec·핀·수명 시험. 별도 Linux child와 명시 provider만 쓴다."""
from __future__ import annotations

import hashlib
import io
import json
import os
from pathlib import Path
import struct
import subprocess
import sys
import threading
import time
from types import SimpleNamespace

import pytest

from pweh.errors import DeviceError, ToolMissing, ValidationFailed
from pweh.winserial import pin
from pweh.winserial import protocol as P
from pweh.winserial.binary import resolve_helper, snapshot
from pweh.winserial.process import HelperRun, HelperCleanupError, check_environment, probe_version, _RUNS
from pweh.winserial.serial import HelperSerial
from pweh.winserial.windows import WindowsLifecycle, split_command

ENV = {"kind": "WSL2_INTEROP", "wsl": {"interop": {"usable": True}}, "windows": {}}
SOURCE = "1" * 40


@pytest.fixture
def fake(tmp_path, monkeypatch):
    path = tmp_path / "pweh-serial-helper.exe"
    source = (Path(__file__).parents[1] / "servers" / "fake_serial_helper.py").read_text()
    log = tmp_path / "frames.jsonl"
    children = []; raws = []
    life = SimpleNamespace(confirmed=True, checks=0, terminated=0, order=[])
    def check_port(port, deadline): life.checks += 1
    def terminate(token, image_path, deadline):
        life.terminated += 1
        # Windows 부재 확인 전에 POSIX spawn 가능성을 끝내야 한다.
        from pweh.procutil import child_exited
        life.order.append(all(child_exited(c.pid) for c in children if c.returncode is None))
        return life.confirmed
    life.check_port = check_port; life.terminate_and_confirm = terminate
    def factory(argv, **kwargs):
        p = subprocess.Popen([sys.executable, "-I", argv[0], *argv[1:]], **kwargs)
        children.append(p); return p
    def configure(**config):
        path.write_text("FAKE_CONFIG=" + repr({"log": str(log), "source_commit": SOURCE, "app": "echo", **config}) + "\n" + source)
        path.chmod(0o755)
        monkeypatch.setattr(pin, "PINNED_SHA256", hashlib.sha256(path.read_bytes()).hexdigest())
        monkeypatch.setattr(pin, "EXPECTED_SOURCE_COMMIT", SOURCE)
        return resolve_helper(configured=str(path), tools_root=tmp_path)
    helper = configure()
    kwargs = dict(environment_provider=lambda: ENV, process_factory=factory, windows_lifecycle=life,
                  runtime_root=tmp_path / "runtime")
    def serial(**settings):
        settings.setdefault("baudrate", 115200)
        raw = HelperSerial(helper=configure(**settings.pop("fake_config", {})), port="COM3", timeout=.2,
                           write_timeout=1, **kwargs, **settings)
        raws.append(raw); return raw
    ctx = SimpleNamespace(helper=helper, path=path, configure=configure, kwargs=kwargs, serial=serial,
                          life=life, children=children, log=log, tmp=tmp_path)
    yield ctx
    life.confirmed = True
    for raw in raws:
        raw.close()
    for run in list(_RUNS.values()):
        if str(run.runtime_root).startswith(str(tmp_path)):
            run.close()
    for c in children:
        if c.poll() is None: c.kill(); c.wait(timeout=2)


HOST = {
    "O": struct.pack("<IIBBBBBB", 1, 115200, 8, 0, 0, 0, 1, 0),
    "B": struct.pack("<IIBBBB", 2, 9600, 8, 0, 0, 0),
    "L": struct.pack("<IBB", 3, 0, 255),
    "K": struct.pack("<IBI", 4, 2, 250),
    "P": struct.pack("<IBI", 5, 0, 1000),
    "S": struct.pack("<I", 6),
    "D": struct.pack("<II", 7, 1000) + b"\0D\xffQ",
    "Q": struct.pack("<I", 8),
}
HELPER = {
    "H": struct.pack("<HHBBBB20sHH", 1, 0, 0, 1, 0, 0, bytes.fromhex(SOURCE), 16384, 0),
    "o": struct.pack("<IBIBI", 1, 0, 0, 0, 1),
    "A": struct.pack("<IBBIIII", 2, ord("D"), 0, 0, 4, 1, 0),
    "s": struct.pack("<IBIBIII", 3, 0, 0, 15, 0, 0, 0),
    "D": struct.pack("<I", 1) + b"\0D\xffQ",
    "E": struct.pack("<IBBII", 4, ord("D"), 7, 0, 2),
}


@pytest.mark.parametrize("direction,frames", [("host", HOST), ("helper", HELPER)])
def test_wire_every_split_coalescing_and_eof(direction, frames):
    stream = b"".join(k.encode() + struct.pack("<H", len(p)) + p for k, p in frames.items())
    expected = [P.Frame(k, p) for k, p in frames.items()]
    for split in range(len(stream) + 1):
        decoder = P.Decoder(direction)
        assert decoder.feed(stream[:split]) + decoder.feed(stream[split:]) == expected
        decoder.eof()
    for kind, payload in frames.items():
        frame = P.encode(kind, payload)
        for prefix in range(1, len(frame)):
            decoder = P.Decoder(direction); decoder.feed(frame[:prefix])
            with pytest.raises(P.ProtocolError): decoder.eof()


@pytest.mark.parametrize("direction,kind,payload", [
    ("host", "H", HELPER["H"]), ("helper", "O", HOST["O"]),
    ("host", "O", HOST["O"][:-1] + b"\1"), ("host", "L", struct.pack("<IBB", 1, 255, 255)),
    ("host", "D", struct.pack("<II", 1, 0) + b"x"), ("host", "Q", b"\0" * 4),
    ("helper", "A", struct.pack("<IBBIIII", 1, ord("D"), 1, 0, 1, 1, 0)),
    ("helper", "D", b"\0" * 4 + b"x"), ("helper", "H", HELPER["H"][:-1] + b"\1"),
    ("helper", "E", struct.pack("<IBBII", 1, ord("D"), 0, 0, 0)),
])
def test_wire_rejects_wrong_direction_reserved_ranges(direction, kind, payload):
    with pytest.raises(P.ProtocolError): P.Decoder(direction).feed(P.encode(kind, payload))


def test_wire_size_before_allocation():
    decoder = P.Decoder("helper")
    with pytest.raises(P.ProtocolError): decoder.feed(b"D\x01\x40")
    assert len(decoder.buffer) == 3
    payload = struct.pack("<I", 1) + bytes(P.MAX_RX)
    assert P.Decoder().feed(P.encode("D", payload)) == [P.Frame("D", payload)]


def test_binary_unpinned_mismatch_and_explicit_no_fallback(fake, monkeypatch):
    monkeypatch.setattr(pin, "PINNED_SHA256", None)
    with pytest.raises(ToolMissing): resolve_helper(configured=str(fake.path), tools_root=fake.tmp)
    fake.configure()
    with pytest.raises(ToolMissing): resolve_helper(configured=str(fake.tmp / "missing" / fake.path.name), env_value=str(fake.path), tools_root=fake.tmp)
    fake.path.write_bytes(b"changed")
    with pytest.raises(DeviceError, match="hash_mismatch"): resolve_helper(configured=str(fake.path), tools_root=fake.tmp)
    assert fake.children == []


def test_binary_link_and_snapshot_replacement(fake):
    linkdir = fake.tmp / "link"; linkdir.symlink_to(fake.tmp, target_is_directory=True)
    with pytest.raises(ValidationFailed): resolve_helper(configured=str(linkdir / fake.path.name), tools_root=fake.tmp)
    helper = fake.configure()
    snap = snapshot(helper, runtime_root=fake.tmp / "runtime")
    original = snap.path.read_bytes()
    fake.path.write_bytes(b"swapped source")
    assert snap.path.read_bytes() == original and snap.path.stat().st_mode & 0o777 == 0o500
    snap.remove()
    assert not snap.directory.exists()


@pytest.mark.parametrize("flag", ["interop", "serial_helper", "windows_tools"])
def test_environment_disable_and_native_no_popen(fake, flag):
    env = {**ENV, "overridden": ["hostenv.disable." + flag]}
    with pytest.raises(DeviceError): check_environment(lambda: env)
    with pytest.raises(DeviceError): check_environment(lambda: {"kind": "NATIVE_LINUX"})
    assert fake.children == []


def test_version_uses_pin_and_no_com_and_cleans_snapshot(fake):
    result = probe_version(fake.helper, **fake.kwargs)
    assert result == {"protocol": [1, 0], "version": [0, 1, 0], "mode": "version", "source_commit": SOURCE,
                      "sha256": fake.helper.sha256, "cleanup_verified": True}
    assert fake.life.checks == fake.life.terminated == 0
    assert fake.children[0].returncode == 0
    assert not list((fake.tmp / "runtime" / "serial-helper-runs").iterdir())
    assert [json.loads(x)["mode"] for x in fake.log.read_text().splitlines()] == [2]


@pytest.mark.parametrize("replacement", ["time.sleep(.03); return 7", "send('H', hello); return 0",
                                       "os.write(2, b'x' * 9000); time.sleep(.03); return 0",
                                       "os.write(1, b'D\\x05'); return 0"])
def test_version_cleanup_success_is_not_protocol_success(fake, monkeypatch, replacement):
    source = fake.path.read_text().replace("if mode == 2:\n        return 0", "if mode == 2:\n        " + replacement)
    fake.path.write_text(source)
    monkeypatch.setattr(pin, "PINNED_SHA256", hashlib.sha256(fake.path.read_bytes()).hexdigest())
    helper = resolve_helper(configured=str(fake.path), tools_root=fake.tmp)
    with pytest.raises(Exception): probe_version(helper, **fake.kwargs)
    assert all(c.returncode is not None for c in fake.children)
    assert not any(str(run.runtime_root).startswith(str(fake.tmp)) for run in _RUNS.values())


def test_changed_source_after_resolve_never_launches(fake):
    fake.path.write_bytes(b"swapped after resolve")
    with pytest.raises(DeviceError, match="hash_mismatch"):
        probe_version(fake.helper, **fake.kwargs)
    assert fake.children == []


def test_open_failure_closes_without_false_lost_fd(fake):
    raw = fake.serial(fake_config={"fault": "open-busy"})
    with pytest.raises(DeviceError): raw.open()
    assert raw.cleanup_verified and not raw.is_open


def test_reader_thread_start_failure_owns_and_cleans_child(fake, monkeypatch):
    original = threading.Thread.start
    def fail(thread):
        if thread.name == "pweh-serial-helper-rx":
            raise RuntimeError("합성 reader start 실패")
        return original(thread)
    monkeypatch.setattr(threading.Thread, "start", fail)
    with pytest.raises(RuntimeError, match="reader start"):
        probe_version(fake.helper, **fake.kwargs)
    assert fake.life.terminated == 1 and all(fake.life.order)
    assert fake.children[0].returncode is not None


def test_blocked_stdin_deadline_then_posix_before_windows(fake, monkeypatch):
    hello = b"H\x20\0" + struct.pack("<HHBBBB20sHH", 1, 0, 0, 1, 0, 1, bytes.fromhex(SOURCE), 16384, 0)
    fake.path.write_text("import os,time\nos.write(1," + repr(hello) + ")\ntime.sleep(20)\n")
    monkeypatch.setattr(pin, "PINNED_SHA256", hashlib.sha256(fake.path.read_bytes()).hexdigest())
    helper = resolve_helper(configured=str(fake.path), tools_root=fake.tmp)
    run = HelperRun(helper, mode="echo", **fake.kwargs)
    run.start(deadline=time.monotonic() + 2)
    start = time.monotonic()
    with pytest.raises(TimeoutError):
        run.request("D", struct.pack("<I", 50) + bytes(P.MAX_WRITE), deadline=start + .05)
    assert time.monotonic() - start < .5
    run.close(send_quit=False)
    assert run.cleanup_verified and fake.life.order == [True]


def test_serial_roundtrip_chunking_settings_and_epoch(fake):
    raw = fake.serial(fake_config={"fragment": 1})
    raw.dtr = False; raw.rts = True
    raw.open()
    data = bytes(range(256)) * 100
    assert raw.write(data) == len(data)
    assert raw.read(len(data)) == data
    raw.timeout = .1; raw.write_timeout = 2
    raw.baudrate = 9600
    raw.dtr = True; raw.rts = False; raw.send_break(.01)
    raw.reset_input_buffer(); raw.flush(); raw.reset_output_buffer()
    assert raw.write(b"after reset") == 11 and raw.read(11) == b"after reset"
    assert raw.cts is False and raw.out_waiting == 0
    with pytest.raises(io.UnsupportedOperation): raw.fileno()
    with pytest.raises(Exception): raw.port = "COM4"
    raw.port = "COM3"
    assert raw.is_open
    raw.close(); raw.close()
    records = [json.loads(x) for x in fake.log.read_text().splitlines()]
    assert sum(x.get("kind") == "O" for x in records) == 1
    assert sum(x.get("kind") == "B" for x in records) == 1  # timeout setters는 B가 아니다.
    assert raw.cleanup_verified and not raw.is_open and fake.life.terminated == 0


def test_cancel_read_is_local_and_close_wakes_forever_read(fake):
    raw = fake.serial(); raw.timeout = None; raw.open()
    result = []
    worker = threading.Thread(target=lambda: result.append(raw.read(20)))
    worker.start(); time.sleep(.02); raw.cancel_read(); worker.join(1)
    assert result == [b""] and not worker.is_alive()
    raw.cancel_read(); assert raw.read(1) == b""
    errors = []
    def read_forever():
        try: raw.read(1)
        except Exception as e: errors.append(type(e).__name__)
    worker = threading.Thread(target=read_forever); worker.start(); time.sleep(.02); raw.close(); worker.join(1)
    assert errors and not worker.is_alive()
    records = [json.loads(x) for x in fake.log.read_text().splitlines()]
    assert not any(x.get("kind") == "P" for x in records)


def test_missing_q_ack_uses_windows_after_posix_exit(fake):
    raw = fake.serial(fake_config={"fault": "drop-quit-ack"}); raw.open(); raw.close()
    assert raw.cleanup_verified and fake.life.terminated >= 1
    assert all(fake.life.order)


def test_unverified_exit_preserves_run_snapshot_retry(fake):
    raw = fake.serial(fake_config={"fault": "drop-quit-ack"}); raw.open()
    fake.life.confirmed = False
    with pytest.raises(HelperCleanupError) as error: raw.close()
    run = raw._run
    assert not raw.cleanup_verified and run.token in _RUNS and run.copy.path.exists()
    assert "run" not in error.value.to_dict() and run.token not in json.dumps(error.value.to_dict())
    fake.life.confirmed = True; raw.close()
    assert raw.cleanup_verified and run.token not in _RUNS


def test_before_open_denial_sends_no_O(fake):
    def denied(): raise DeviceError("합성 거부")
    raw = fake.serial(before_open=denied)
    with pytest.raises(DeviceError): raw.open()
    assert raw.cleanup_verified
    records = [json.loads(x) for x in fake.log.read_text().splitlines()]
    assert not any(x.get("kind") == "O" for x in records)


def test_windows_query_missing_fields_not_absent():
    lifecycle = WindowsLifecycle(runner=lambda *a: b'{"complete":true,"items":[{}]}')
    with pytest.raises(DeviceError): lifecycle.check_port("COM1", time.monotonic() + 1)
    assert not lifecycle.terminate_and_confirm("2" * 32, "/tmp/x", time.monotonic() + 1)


def test_windows_exact_token_and_handle_script():
    row = {"pid": 123, "image": r"C:\fixed\pweh-serial-helper.exe", "creation": "123456780",
           "cmd": r'"C:\fixed\pweh-serial-helper.exe" --port COM3 --token ' + "2" * 32}
    calls = []
    def runner(script, deadline):
        calls.append(script)
        if "__REQUEST__" in script: pytest.fail("요청 인코딩 누락")
        if "OpenProcess" in script: return b'{"terminated":true}'
        return json.dumps({"complete": True, "items": [row] if len(calls) == 1 else []}).encode()
    life = WindowsLifecycle(runner=runner, path_converter=lambda *a: row["image"])
    assert life.terminate_and_confirm("2" * 32, "/tmp/fixed", time.monotonic() + 1)
    assert len(calls) == 3 and "GetProcessTimes" in calls[1] and "WaitForSingleObject" in calls[1]
    assert "Stop-Process" not in calls[1]
    assert split_command(row["cmd"])[-2:] == ["--token", "2" * 32]
