"""실제 합성 C dispatcher부터 주입 collector·같은 FD 두 패스까지 검증한다."""
from __future__ import annotations

import ast
from contextlib import contextmanager
import hashlib
import os
from pathlib import Path
import select
import shutil
import struct
import subprocess
import time

import pytest

from pweh import espprobe_protocol as P
from pweh import espprobe_bus_wire as W
from pweh.espprobe_bus_collect import BusCollector

ROOT = Path(__file__).resolve().parents[2]
SOURCES = (
    "firmware/common/cobs.c", "firmware/common/crc32.c", "firmware/common/protocol.c",
    "firmware/common/tlv.c", "firmware/common/session.c", "firmware/espprobe/bus/probe_bus.c",
    "firmware/espprobe/bus/probe_spi.c", "firmware/espprobe/bus/probe_sfdp.c",
    "firmware/espprobe/bus/probe_i2c.c", "firmware/espprobe/bus/probe_bus_wire.c",
)
STAT_KEYS = ("state", "credit", "deadline", "last_hb", "transactions", "spi_bytes", "reads",
             "deliveries", "aborts", "claims", "emits", "data", "done", "nested", "stops", "nacks")
pytestmark = pytest.mark.external


@pytest.fixture(scope="module")
def wire_host(tmp_path_factory):
    zig = os.environ.get("PWEH_ZIG") or shutil.which("zig")
    if not zig:
        candidate = Path.home() / "pweh-tools/zig/zig-x86_64-linux-0.17.0/zig"
        if candidate.is_file():
            zig = str(candidate)
    if not zig:
        pytest.skip("host C 시험용 기존 Zig 없음")
    target = tmp_path_factory.mktemp("bus-wire-host") / "host"
    command = [zig, "cc", "-std=c11", "-Wall", "-Wextra", "-Werror", "-O1",
               "-I" + str(ROOT / "firmware/common/include"),
               "-I" + str(ROOT / "firmware/espprobe/bus"),
               *(str(ROOT / name) for name in SOURCES),
               str(ROOT / "tests/fixtures/espprobe_bus_wire_host.c"), "-o", str(target)]
    completed = subprocess.run(command, capture_output=True, timeout=90)
    assert completed.returncode == 0, completed.stderr.decode("utf-8", "replace")
    return target


def frames(data):
    if not data:
        return []
    assert data.endswith(b"\0")
    return [P.decode(piece + b"\0") for piece in data[:-1].split(b"\0")]


class Driver:
    """유한 시험 제어봉투를 실제 C wire byte와 분리하는 단일 child 소유자."""

    def __init__(self, executable, *, kind="spi", width=2, mode=0, fault_delivery=0):
        self.process = subprocess.Popen([str(executable), str(int(kind == "i2c")), str(width),
                                         str(mode), str(fault_delivery)], stdin=subprocess.PIPE,
                                        stdout=subprocess.PIPE, stderr=subprocess.PIPE, bufsize=0)
        self.controls = 0
        self.total_output = 0
        self.closed = False
        self.now = 100
        code, hello_wire = self._reply(time.monotonic() + 5)
        assert code == 0
        self.hello = P.decode(hello_wire)
        self.facts = P.decode_hello(self.hello.payload)
        assert self.facts["session_token"] == self.hello.session
        self.binding = W.BusWireBinding(self.hello.session, self.facts["usb_session"],
                                       self.hello.seq, 0, self.facts["limits"]["hb_ms"],
                                       bytes.fromhex(self.facts["boot_id"]))

    def _read(self, count, deadline):
        chunks = bytearray()
        while len(chunks) < count:
            left = deadline - time.monotonic()
            assert left > 0, "합성 child 응답 시간 초과"
            ready, _, _ = select.select([self.process.stdout], [], [], left)
            assert ready, "합성 child 응답 시간 초과"
            data = os.read(self.process.stdout.fileno(), count - len(chunks))
            if not data:
                self.process.wait(timeout=2)
                error = self.process.stderr.read(4097)
                assert False, (self.process.returncode, error)
            chunks.extend(data)
        self.total_output += len(chunks)
        assert self.total_output <= 2 * 1024 * 1024
        return bytes(chunks)

    def _reply(self, deadline):
        code, size = struct.unpack("<II", self._read(8, deadline))
        assert size <= 65536
        return code, self._read(size, deadline)

    def command(self, command, data=b"", *, now=None, deadline=None):
        assert command in (b"W", b"P", b"S", b"H", b"Q") and len(data) <= 16384
        assert not self.closed and self.controls < 8192
        self.controls += 1
        if now is not None:
            self.now = now
        end = time.monotonic() + 3 if deadline is None else deadline
        packet = command + struct.pack("<QI", self.now, len(data)) + data
        written = 0
        while written < len(packet):
            left = end - time.monotonic()
            assert left > 0
            _, ready, _ = select.select([], [self.process.stdin], [], left)
            assert ready
            wrote = os.write(self.process.stdin.fileno(), packet[written:])
            assert wrote > 0
            written += wrote
        return self._reply(end)

    def send(self, data, **kwargs):
        code, result = self.command(b"W", data, **kwargs)
        return code, frames(result)

    def poll(self, **kwargs):
        code, result = self.command(b"P", **kwargs)
        return code, frames(result)

    def stats(self):
        code, values = self.command(b"S")
        assert code == 0 and len(values) == 128
        return dict(zip(STAT_KEYS, struct.unpack("<16Q", values)))

    def close(self, *, deadline=None):
        if self.closed:
            return True
        end = time.monotonic() + 3 if deadline is None else deadline
        if self.process.poll() is None:
            try:
                self.command(b"Q", deadline=end)
            except (AssertionError, OSError):
                self.process.kill()
        self.process.wait(timeout=max(0.01, min(3, end - time.monotonic())))
        for stream in (self.process.stdin, self.process.stdout):
            stream.close()
        stderr = self.process.stderr.read(4097)
        self.process.stderr.close()
        self.closed = True
        assert self.process.returncode == 0 and not stderr, (self.process.returncode, stderr)
        return True


@pytest.fixture
def drivers(wire_host):
    opened = []

    def create(**kwargs):
        owner = Driver(wire_host, **kwargs)
        opened.append(owner)
        return owner

    yield create
    for owner in opened:
        owner.close()


def response_status(result):
    assert result.type == P.RSP
    return struct.unpack_from("<H", result.payload)[0]


def req(owner, seq, *, op=0x77, payload=b"", session=None):
    return P.encode(P.Frame(type=P.REQ, op=op, seq=seq,
                            session=owner.binding.session if session is None else session,
                            payload=payload))


def begin(owner, *, length=1, passes=2, offset=0, kind="spi"):
    if kind == "spi":
        code, responses = owner.send(W.build_spi_probe(owner.binding, seq=2))
        assert code == 0 and response_status(responses[0]) == 0
    seq = 3 if kind == "spi" else 2
    plan = W.BusReadPlan(kind, offset, length, passes)
    encoded = W.build_read_begin(owner.binding, plan, seq=seq)
    code, responses = owner.send(encoded)
    assert code == 0 and response_status(responses[0]) == 0
    return plan, seq, encoded


def test_actual_hello_is_binding_source_and_no_preprobe(drivers):
    owner = drivers()
    assert owner.facts["caps"] == owner.facts["spi_read_opcodes"] == []
    assert owner.facts["limits"]["max_credit"] == 0
    assert owner.facts["pins_allowed"] == {"H0": [], "H1": [], "H1a": []}
    stats = owner.stats()
    assert stats["claims"] == 1 and stats["state"] == 2
    assert stats["transactions"] == stats["spi_bytes"] == stats["deliveries"] == 0
    code, raw = owner.command(b"H", req(owner, 2, op=0x10, payload=struct.pack("<I", owner.binding.usb_session)))
    assert code == 0 and response_status(frames(raw)[0]) == 2
    hb = W.build_bus_heartbeat(owner.binding, seq=1, credit=1)
    code, raw = owner.command(b"H", hb)
    assert code == 0 and response_status(frames(raw)[0]) == 1
    assert owner.stats()["transactions"] == 0


def test_global_cache_eviction_changed_duplicate_and_rejected_seq_consumption(drivers):
    owner = drivers()
    probe = W.build_spi_probe(owner.binding, seq=2)
    original = owner.send(probe)
    assert response_status(original[1][0]) == 0
    reads = owner.stats()["spi_bytes"]
    assert owner.send(probe) == original
    assert owner.stats()["spi_bytes"] == reads
    unknown = req(owner, 3)
    invalid = req(owner, 4, op=0x11, payload=b"bad")
    rejected = owner.send(invalid)
    assert response_status(rejected[1][0]) == 7
    # 3은 이미 소비한 4보다 작고 cache에 없으므로 replay다.
    assert response_status(owner.send(unknown)[1][0]) == 8
    assert owner.send(invalid) == rejected
    assert response_status(owner.send(req(owner, 4, op=0x78))[1][0]) == 5
    for seq in range(5, 9):
        value = req(owner, seq)
        first = owner.send(value)
        assert response_status(first[1][0]) == 2
        assert owner.send(value) == first
    assert response_status(owner.send(probe)[1][0]) == 8
    assert owner.stats()["spi_bytes"] == reads


@pytest.mark.parametrize("split", [1, 2, 7, 16])
def test_split_and_coalesced_requests_use_actual_decoder(drivers, split):
    owner = drivers()
    encoded = W.build_spi_probe(owner.binding, seq=2)
    for at in range(0, len(encoded), split):
        code, responses = owner.send(encoded[at:at + split])
        assert code == 0
        if at + split < len(encoded):
            assert responses == []
        else:
            assert response_status(responses[0]) == 0
    code, responses = owner.send(req(owner, 3) + req(owner, 4))
    assert code == 0 and [response_status(row) for row in responses] == [2, 2]


def test_heartbeat_highwater_credit_ack_and_single_step(drivers):
    owner = drivers()
    begin(owner, length=257)
    grant = W.build_bus_heartbeat(owner.binding, seq=1, credit=4)
    code, ack = owner.send(grant, now=110)
    assert code == 0 and len(ack) == 1 and ack[0].type == P.HB
    before = owner.stats()
    assert before["credit"] == 4 and before["deliveries"] == 0
    assert owner.send(grant, now=111) == (0, [])
    assert owner.stats()["deadline"] == before["deadline"]
    code, rejected = owner.send(W.build_bus_heartbeat(owner.binding, seq=2, credit=1), now=112)
    assert code == 0 and response_status(rejected[0]) == 1
    assert owner.stats()["deadline"] == before["deadline"]
    assert owner.stats()["credit"] == 4
    code, data = owner.poll(now=113)
    assert code == 0 and [row.type for row in data] == [P.DATA]
    assert owner.stats()["deliveries"] == 1 and owner.stats()["credit"] == 3
    code, data = owner.poll(now=114)
    assert code == 0 and [row.type for row in data] == [P.DATA]
    assert owner.stats()["deliveries"] == 2


def test_one_begin_per_generation_and_cleanup_tombstone(drivers):
    owner = drivers()
    plan, seq, encoded = begin(owner)
    ack = owner.send(encoded)
    assert response_status(ack[1][0]) == 0
    owner.send(W.build_bus_heartbeat(owner.binding, seq=1, credit=2))
    first = owner.poll()[1]
    last = owner.poll()[1]
    assert [x.type for x in first] == [P.DATA]
    assert [x.type for x in last] == [P.DATA, P.EVT]
    before = owner.stats()
    assert before["done"] == 1 and before["deliveries"] == 2
    assert owner.send(encoded) == ack
    assert owner.poll() == (0, [])
    new_begin = W.build_read_begin(owner.binding, plan, seq=seq + 1)
    assert response_status(owner.send(new_begin)[1][0]) == 6
    cleanup = W.build_bus_cleanup(owner.binding, seq=seq + 2)
    response = owner.send(cleanup)
    assert response_status(response[1][0]) == 0
    released = owner.stats()
    assert released["aborts"] == 1 and released["credit"] == 0
    assert owner.send(cleanup, now=10000) == response
    assert owner.stats()["aborts"] == 1
    assert owner.stats()["deliveries"] == 2


@pytest.mark.parametrize("broken", [b"\0", b"\0\0", b"\x01\0", b"\xff" * 4134,
                                   b"\x02\x01\0"],
                         ids=["bare", "double-bare", "short", "oversize", "malformed"])
def test_malformed_is_terminal_without_resynchronization(drivers, broken):
    owner = drivers()
    code, _ = owner.send(broken)
    assert code != 0
    stopped = owner.stats()
    assert stopped["aborts"] == 1 and stopped["transactions"] == 0
    code, output = owner.send(W.build_spi_probe(owner.binding, seq=2))
    assert code != 0 and output == []
    assert owner.stats()["aborts"] == 1


def test_crc_failure_discards_following_valid_request(drivers):
    owner = drivers()
    good = W.build_spi_probe(owner.binding, seq=2)
    raw = bytearray(P._raw(P.decode(good)))
    raw[-1] ^= 1
    bad = P._cobs_encode(bytes(raw)) + b"\0"
    code, output = owner.send(bad + good)
    assert code != 0 and output == []
    assert owner.stats()["transactions"] == 0


def test_partial_eof_releases_once(drivers):
    owner = drivers()
    assert owner.send(W.build_spi_probe(owner.binding, seq=2)[:-1]) == (0, [])
    assert owner.stats()["transactions"] == 0
    owner.process.stdin.close()
    owner.process.wait(timeout=3)
    owner.close()
    assert owner.closed and owner.process.returncode == 0


@pytest.mark.parametrize("mode", [2, 3, 4, 5])
def test_actual_deliver_postguard_emit_failure_and_reentry(drivers, mode):
    owner = drivers(mode=mode, fault_delivery=2)
    begin(owner)
    owner.send(W.build_bus_heartbeat(owner.binding, seq=1, credit=2))
    assert [x.type for x in owner.poll()[1]] == [P.DATA]
    code, output = owner.poll()
    stats = owner.stats()
    if mode == 5:
        assert code == 0 and [x.type for x in output] == [P.DATA, P.EVT]
        assert stats["nested"] == 4 and stats["done"] == 1
    else:
        assert code != 0 and stats["aborts"] == 1 and stats["done"] == 0
        assert [x.type for x in output] == ([] if mode == 4 else [P.DATA])
        delivered = stats["deliveries"]
        assert owner.poll()[0] != 0
        assert owner.stats()["deliveries"] == delivered


class ChildTransport:
    """기본 factory가 없는 합성 child adapter. 실제 emit bytes만 전달한다."""

    def __init__(self, driver, *, read_chunk=4096, write_chunk=16384, coalesce=False,
                 close_unknown=False, corrupt=False):
        self.driver = driver
        self.pending = bytearray()
        self.read_chunk = read_chunk
        self.write_chunk = write_chunk
        self.coalesce = coalesce
        self.close_unknown = close_unknown
        self.corrupt = corrupt
        self.terminal = False
        self.close_calls = 0
        self.writes = []
        self.final_stats = None
        self.clock_start = time.monotonic()
        self.on_read = None

    def _now(self):
        return 100 + int((time.monotonic() - self.clock_start) * 1000)

    def write(self, data, *, deadline):
        assert 0 < len(data) <= P.MAX_WIRE and not self.driver.closed
        take = min(len(data), self.write_chunk)
        actual = data[:take]
        self.writes.append(actual)
        code, emitted = self.driver.command(b"W", actual, now=self._now(), deadline=deadline)
        self.pending.extend(emitted)
        self.terminal |= code != 0
        return take

    def read(self, max_bytes, *, deadline):
        assert 1 <= max_bytes <= 4096
        if self.on_read is not None:
            self.on_read(self)
        if not self.pending and self.terminal:
            return b""
        if (not self.pending or self.coalesce) and not self.terminal:
            code, emitted = self.driver.command(b"P", now=self._now(), deadline=deadline)
            self.pending.extend(emitted)
            self.terminal |= code != 0
        if self.pending:
            take = min(len(self.pending), max_bytes, self.read_chunk)
            data = bytes(self.pending[:take])
            del self.pending[:take]
            if self.corrupt:
                self.corrupt = False
                return b"\0" + data if len(data) < max_bytes else b"\0" + data[1:]
            return data
        if self.terminal:
            return b""
        time.sleep(min(0.001, max(0, deadline - time.monotonic())))
        return None

    def close(self, *, deadline):
        self.close_calls += 1
        if self.final_stats is None and not self.driver.closed:
            self.final_stats = self.driver.stats()
        if self.close_unknown:
            return False
        return self.driver.close(deadline=deadline)


@contextmanager
def pass_files(tmp_path):
    descriptors = tuple(os.open(tmp_path / f"pass-{i}.bin", os.O_RDWR | os.O_CREAT | os.O_EXCL, 0o600)
                        for i in range(2))
    try:
        yield descriptors
    finally:
        for fd in descriptors:
            os.close(fd)


def expected_bytes(offset, length, *, flip=False):
    expected = bytearray((offset + index) & 255 for index in range(length))
    if flip:
        expected[0] ^= 1
    return bytes(expected)


@pytest.mark.parametrize("kind,width,offset,length", [
    ("spi", 2, 0, 1), ("spi", 2, 17, 257), ("spi", 2, 0x1000003, 513),
    ("i2c", 1, 19, 33), ("i2c", 2, 300, 65),
])
@pytest.mark.parametrize("fragmented", [False, True])
def test_actual_c_to_collector_two_pass_bytes_and_final_sha(drivers, tmp_path, kind, width,
                                                          offset, length, fragmented):
    driver = drivers(kind=kind, width=width)
    transport = ChildTransport(driver, read_chunk=7 if fragmented else 4096,
                               write_chunk=3 if fragmented else 16384, coalesce=not fragmented)
    plan = W.BusReadPlan(kind, offset, length)
    with pass_files(tmp_path) as fds:
        owner = BusCollector(transport, driver.binding, plan, fds, deadline=time.monotonic() + 5)
        result = owner.run().to_dict()
        assert result["operation_complete"] and result["match"] is True and result["reason"] is None
        assert result["done_received"] and result["protocol_released"] and result["transport_closed"]
        assert result["simulator_only"] is True
        assert result["hardware_verified"] is result["device_sha256_verified"] is False
        wanted = expected_bytes(offset, length)
        for fd, row in zip(fds, result["pass_results"]):
            assert os.pread(fd, length + 1, 0) == wanted
            assert row["received"] == row["stored"] == length
            assert row["sha256"] == hashlib.sha256(wanted).hexdigest()
        stats = transport.final_stats
        chunks = 2 * ((length + (31 if kind == "i2c" else 255)) // (32 if kind == "i2c" else 256))
        assert stats["deliveries"] == stats["data"] == chunks
        assert stats["done"] == stats["aborts"] == 1
        if kind == "i2c":
            assert stats["stops"] == stats["nacks"] == chunks


def test_two_complete_different_passes_are_not_deleted(drivers, tmp_path):
    driver = drivers(mode=1)
    transport = ChildTransport(driver, coalesce=True)
    with pass_files(tmp_path) as fds:
        owner = BusCollector(transport, driver.binding, W.BusReadPlan("spi", 31, 257), fds,
                             deadline=time.monotonic() + 5)
        result = owner.run().to_dict()
        assert result["operation_complete"] and result["match"] is False
        for index, fd in enumerate(fds):
            wanted = expected_bytes(31, 257, flip=index == 1)
            assert os.pread(fd, 258, 0) == wanted
            assert result["pass_results"][index]["sha256"] == hashlib.sha256(wanted).hexdigest()


@pytest.mark.parametrize("mode", [2, 3])
def test_last_data_after_guard_failure_is_incomplete_even_at_full_size(drivers, tmp_path, mode):
    driver = drivers(mode=mode, fault_delivery=2)
    transport = ChildTransport(driver, coalesce=True)
    with pass_files(tmp_path) as fds:
        owner = BusCollector(transport, driver.binding, W.BusReadPlan("spi", 9, 1), fds,
                             deadline=time.monotonic() + 5)
        result = owner.run().to_dict()
        assert not result["operation_complete"] and result["match"] is None
        assert not result["done_received"] and result["reason"] is not None
        assert [os.pread(fd, 2, 0) for fd in fds] == [b"\x09", b"\x09"]
        assert all(row["sha256"] is None for row in result["pass_results"])
        assert transport.final_stats["done"] == 0 and transport.final_stats["data"] == 2


def test_unknown_close_retains_owner_and_receipt_then_only_retries_close(drivers, tmp_path):
    driver = drivers()
    transport = ChildTransport(driver, close_unknown=True)
    with pass_files(tmp_path) as fds:
        owner = BusCollector(transport, driver.binding, W.BusReadPlan("spi", 0, 1), fds,
                             deadline=time.monotonic() + 5)
        receipt = owner.run()
        original = receipt.to_dict()
        assert not original["operation_complete"] and not original["transport_closed"]
        assert original["protocol_released"] and original["match"] is None
        assert not driver.closed and driver.process.poll() is None
        assert [os.pread(fd, 1, 0) for fd in fds] == [b"\0", b"\0"]
        writes = tuple(transport.writes)
        transport.close_unknown = False
        assert owner.close(deadline=time.monotonic() + 2)
        assert tuple(transport.writes) == writes and owner.receipt is receipt
        assert receipt.to_dict() == original


def test_actual_response_framing_error_closes_without_more_wire_tx(drivers, tmp_path):
    driver = drivers()
    transport = ChildTransport(driver, corrupt=True)
    with pass_files(tmp_path) as fds:
        owner = BusCollector(transport, driver.binding, W.BusReadPlan("spi", 0, 1), fds,
                             deadline=time.monotonic() + 5)
        result = owner.run().to_dict()
        assert not result["operation_complete"] and result["reason"] == "espprobe_bus_protocol"
        assert len(transport.writes) == 1
        assert transport.final_stats["deliveries"] == 0


@pytest.mark.parametrize("failure", ["cancel", "timeout", "seal"])
def test_actual_pending_read_failure_preserves_partial_fd_and_fixed_reason(drivers, tmp_path,
                                                                          monkeypatch, failure):
    import pweh.espprobe_bus_collect as collection

    driver = drivers()
    transport = ChildTransport(driver)
    cancelled = False
    injected = False
    advance = 0.0
    monkeypatch.setattr(collection, "_clock", lambda: time.monotonic() + advance)
    with pass_files(tmp_path) as fds:
        end = time.monotonic() + 5

        def fault(adapter):
            nonlocal cancelled, injected, advance
            if injected or os.fstat(fds[0]).st_size == 0:
                return
            injected = True
            if failure == "cancel":
                cancelled = True
            elif failure == "timeout":
                # 처리 시각만 같은 end 너머로 옮겨 scheduler 속도에 의존하지 않는다.
                advance = 10.0
            else:
                os.pwrite(fds[0], b"X", 0)

        transport.on_read = fault
        owner = collection.BusCollector(transport, driver.binding, W.BusReadPlan("spi", 0, 257),
                                       fds, deadline=end, cancel=lambda: cancelled)
        result = owner.run().to_dict()
        assert injected and not result["operation_complete"] and result["match"] is None
        expected = {"cancel": "cancelled", "timeout": "time_limit", "seal": "espprobe_bus_output_changed"}
        assert result["reason"] == expected[failure]
        assert os.fstat(fds[0]).st_size >= 256
        assert result["pass_results"][0]["sha256"] is None


def test_explicit_build_sources_and_python310_are_kept_local():
    assert len(SOURCES) == len(set(SOURCES)) == 10
    for name in SOURCES:
        assert (ROOT / name).is_file()
    for name in ("firmware/espprobe/CMakeLists.txt", "firmware/espprobe/main/CMakeLists.txt"):
        text = (ROOT / name).read_text(encoding="utf-8")
        assert "probe_bus" not in text and "GLOB" not in text
    ast.parse(Path(__file__).read_text(encoding="utf-8"), feature_version=(3, 10))
