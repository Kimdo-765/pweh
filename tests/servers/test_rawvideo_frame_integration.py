"""실제 queue와 owner의 RGB24·late read·정리 회계를 barrier로 연결한다."""
from __future__ import annotations

import ast
from pathlib import Path
import threading

import pytest

from play_mcp.frame_owner import start_frame_owner
from pweh.rawvideo_frames import RawFrame

from .fake_rawvideo_source import ManualClock, MemorySource


QUEUE_KEYS = {
    "pixel_format", "width", "height", "frame_bytes", "bytes_accepted", "frames_completed",
    "frames_taken", "frames_dropped", "pending_frames", "tail_bytes", "last_index",
    "last_receipt_ns", "stop_reason", "eof_observed", "framing_complete",
}
OWNER_KEYS = QUEUE_KEYS | {"late_read_bytes", "worker_stopped", "source_closed"}


def wait(event):
    assert event.wait(5), "합성 worker barrier 시간 초과"


def accounting(snapshot):
    assert set(snapshot) == OWNER_KEYS
    assert snapshot["pixel_format"] == "rgb24"
    assert snapshot["frame_bytes"] == snapshot["width"] * snapshot["height"] * 3
    assert snapshot["bytes_accepted"] == (snapshot["frames_completed"] * snapshot["frame_bytes"]
                                          + snapshot["tail_bytes"])
    assert snapshot["frames_completed"] == (snapshot["frames_taken"] + snapshot["frames_dropped"]
                                            + snapshot["pending_frames"])
    assert 0 <= snapshot["frames_completed"] <= 16
    assert snapshot["pending_frames"] in (0, 1)
    assert 0 <= snapshot["tail_bytes"] < snapshot["frame_bytes"]
    assert 0 <= snapshot["late_read_bytes"] <= 65536
    assert snapshot["bytes_accepted"] + snapshot["late_read_bytes"] <= 16777216
    if snapshot["frames_completed"] == 0:
        assert snapshot["last_index"] is snapshot["last_receipt_ns"] is None
    else:
        assert snapshot["last_index"] == snapshot["frames_completed"] - 1
    return snapshot


def closed(result, *, confirmed=True):
    assert set(result) == {"confirmed", "snapshot", "error"}
    snapshot = accounting(result["snapshot"])
    assert result["confirmed"] is confirmed
    assert result["confirmed"] is (snapshot["worker_stopped"] and snapshot["source_closed"])
    assert result["error"] == (None if confirmed else "frame_cleanup_incomplete")
    assert "RAWVIDEO_PRIVATE_SOURCE_SENTINEL" not in repr(result)
    return snapshot


@pytest.fixture
def running():
    owners = []
    gates = []

    def start(source, *, width=1, height=1, clock=None, deadline_ns=None, cancel=None):
        clock = ManualClock() if clock is None else clock
        owner = start_frame_owner(width=width, height=height, source=source,
                                  deadline_ns=(clock.value + 1_000_000_000
                                               if deadline_ns is None else deadline_ns),
                                  cancel=cancel, clock_ns=clock)
        owners.append((owner, source))
        return owner, clock

    start.gates = gates
    yield start
    for gate in gates:
        gate.set()
    for owner, source in owners:
        source.release_gates()
        closed(owner.close())


def test_split_frame_receipt_and_coalesced_latest_index_use_actual_queue(running):
    first_entered, second_entered = threading.Event(), threading.Event()
    first_release, second_release, close_release = (threading.Event() for _ in range(3))
    running.gates.extend((first_release, second_release, close_release))
    clock = ManualClock(10)

    def step(payload, stamp, entered, release):
        def read(source, maximum):
            assert maximum >= len(payload)
            entered.set()
            wait(release)
            clock.set(stamp)
            return payload
        return read

    source = MemorySource([b"ab", step(b"cdef", 20, first_entered, first_release),
                           step(b"ghijklmnopqr", 30, second_entered, second_release), b""],
                          close_gate=close_release)
    owner, _ = running(source, width=2, clock=clock)
    wait(first_entered)
    assert accounting(owner.snapshot())["tail_bytes"] == 2
    assert owner.take() is None
    first_release.set()
    wait(second_entered)
    first = owner.take()
    assert type(first) is RawFrame
    assert (first.index, first.receipt_ns, first.pixels) == (0, 20, b"abcdef")
    second_release.set()
    wait(source.close_entered)
    snapshot = accounting(owner.snapshot())
    assert (snapshot["frames_completed"], snapshot["frames_taken"],
            snapshot["frames_dropped"], snapshot["pending_frames"]) == (3, 1, 1, 1)
    latest = owner.take()
    assert (latest.index, latest.receipt_ns, latest.pixels) == (2, 30, b"mnopqr")
    assert owner.take() is None
    assert first.pixels == b"abcdef" and type(latest.pixels) is bytes
    assert "mnopqr" not in repr(latest)
    close_release.set()
    result = closed(owner.close())
    assert result["stop_reason"] == "eof" and result["framing_complete"]


def test_sixteen_small_frames_stop_without_eof_probe(running):
    source = MemorySource([bytes(range(51))])
    owner, _ = running(source)
    wait(source.closed_event)
    before = accounting(owner.snapshot())
    assert before["bytes_accepted"] == 48
    assert before["frames_completed"] == 16 and before["frames_dropped"] == 15
    assert before["pending_frames"] == 1 and before["tail_bytes"] == 0
    assert before["stop_reason"] == "frame_limit"
    assert not before["eof_observed"] and not before["framing_complete"]
    assert source.read_calls == [(48, 0.05)]
    assert source.script[0] == bytes(range(48, 51))
    frame = owner.take()
    assert (frame.index, frame.pixels) == (15, bytes(range(45, 48)))
    assert not owner.snapshot()["worker_stopped"]
    closed(owner.close())


def test_max_geometry_two_frames_and_unpadded_tail_reach_byte_cap(running):
    source = MemorySource(pattern_size=16777217)
    owner, clock = running(source, width=1600, height=1600)
    wait(source.closed_event)
    snapshot = accounting(owner.snapshot())
    assert snapshot["frame_bytes"] == 7680000
    assert snapshot["bytes_accepted"] == 16777216
    assert snapshot["frames_completed"] == 2
    assert snapshot["tail_bytes"] == 1417216
    assert snapshot["frames_dropped"] == 1 and snapshot["pending_frames"] == 1
    assert snapshot["stop_reason"] == "byte_limit" and not snapshot["eof_observed"]
    assert source.pattern_offset == 16777216
    assert len(source.read_calls) == 256
    assert all(size == 65536 for size, _ in source.read_calls)
    frame = owner.take()
    assert frame.index == 1 and frame.receipt_ns == clock.value
    # 기대값은 queue나 source 구현의 반환값에서 유도하지 않는다.
    period = bytes(range(251))
    shift = 7680000 % 251
    expected = (period * ((7680000 + shift + 250) // 251))[shift:shift + 7680000]
    assert frame.pixels == expected and len(frame.pixels) == 7680000
    after = closed(owner.close())
    assert after["frames_taken"] == 1 and after["tail_bytes"] == 1417216


@pytest.mark.parametrize("payload,frames,tail,reason", [
    (b"", 0, 0, "eof"), (bytes(6), 2, 0, "eof"), (b"RGBxy", 1, 2, "partial_eof"),
])
def test_eof_and_black_pixels_keep_framing_distinct_from_cleanup(running, payload, frames, tail, reason):
    source = MemorySource([payload, b""] if payload else [b""])
    owner, _ = running(source)
    wait(source.closed_event)
    snapshot = accounting(owner.snapshot())
    assert snapshot["stop_reason"] == reason and snapshot["eof_observed"]
    assert snapshot["framing_complete"] is (tail == 0)
    assert snapshot["frames_completed"] == frames and snapshot["tail_bytes"] == tail
    assert not snapshot["worker_stopped"]
    frame = owner.take()
    if frames:
        assert frame.index == frames - 1 and frame.pixels == payload[(frames - 1) * 3:frames * 3]
    else:
        assert frame is None
    assert owner.take() is None
    assert closed(owner.close())["stop_reason"] == reason


@pytest.mark.parametrize("choice", ["take", "close"])
def test_eof_pending_is_taken_or_dropped_once_at_close_barrier(running, choice):
    gate = threading.Event()
    source = MemorySource([b"RGB", b""], close_gate=gate)
    owner, _ = running(source)
    wait(source.close_entered)
    assert accounting(owner.snapshot())["pending_frames"] == 1
    if choice == "take":
        assert owner.take().pixels == b"RGB"
    first = closed(owner.close(), confirmed=False)
    assert first["stop_reason"] == "eof" and first["pending_frames"] == 0
    assert first["frames_taken"] == int(choice == "take")
    assert first["frames_dropped"] == int(choice == "close")
    assert len(source.close_threads) == 1 and not source.closed_event.is_set()
    gate.set()
    final = closed(owner.close())
    assert final["stop_reason"] == "eof"
    assert owner.take() is None and len(source.close_threads) == 1


@pytest.mark.parametrize("late", [b"RGB", b"", "raw-private-sentinel", "overlong"])
def test_cancelled_inflight_read_never_publishes_or_upgrades_late_eof(running, late):
    gate = threading.Event()
    # callable은 의도적인 잘못된 source 반환을 잘라 정상화하지 않는다.
    def result(source, maximum):
        return b"x" * (maximum + 1) if late == "overlong" else late

    source = MemorySource([result], read_gate=gate, wake_reads=False)
    owner, _ = running(source)
    wait(source.read_entered)
    owner.cancel()
    pending = accounting(owner.snapshot())
    assert pending["bytes_accepted"] == 0 and source.close_threads == []
    gate.set()
    wait(source.closed_event)
    final = closed(owner.close())
    assert final["stop_reason"] == "cancelled"
    assert final["bytes_accepted"] == final["frames_completed"] == final["tail_bytes"] == 0
    assert final["late_read_bytes"] == (3 if late == b"RGB" else 0)
    assert not final["eof_observed"] and not final["framing_complete"]
    assert owner.take() is None and len(source.read_calls) == 1


def test_blocked_read_close_unknown_keeps_same_worker_until_gate_returns(running):
    gate = threading.Event()
    source = MemorySource([b"RGB"], read_gate=gate, wake_reads=False)
    owner, _ = running(source)
    wait(source.read_entered)
    first = closed(owner.close(), confirmed=False)
    assert not first["worker_stopped"] and not first["source_closed"]
    assert source.close_threads == [] and not gate.is_set()
    assert source.cancel_threads
    gate.set()
    wait(source.closed_event)
    final = closed(owner.close())
    assert final["late_read_bytes"] == 3 and final["bytes_accepted"] == 0
    assert final["stop_reason"] == "cancelled"
    assert source.read_threads == source.close_threads == source.closed_threads


def test_worker_self_close_never_joins_itself_or_publishes_returned_bytes(running):
    gate = threading.Event()
    results = []
    holder = {}

    def callback(source, maximum):
        results.append(holder["owner"].close())
        return b"RGB"

    source = MemorySource([callback], read_gate=gate, wake_reads=False)
    owner, _ = running(source)
    holder["owner"] = owner
    wait(source.read_entered)
    gate.set()
    wait(source.closed_event)
    assert len(results) == 1
    closed(results[0], confirmed=False)
    final = closed(owner.close())
    assert final["late_read_bytes"] == 3 and final["frames_completed"] == 0
    assert len(source.close_threads) == 1
    assert source.read_threads == source.close_threads == source.closed_threads


def test_deadline_crossed_during_read_uses_late_count_without_new_end(running):
    gate = threading.Event()
    clock = ManualClock(100)
    source = MemorySource([b"RGB"], read_gate=gate, wake_reads=False)
    owner, _ = running(source, clock=clock, deadline_ns=200)
    wait(source.read_entered)
    clock.set(200)
    gate.set()
    wait(source.closed_event)
    final = closed(owner.close())
    assert final["stop_reason"] == "time_limit" and final["late_read_bytes"] == 3
    assert final["bytes_accepted"] == 0 and owner.take() is None
    assert len(source.read_calls) == 1


def test_consumer_calls_do_not_sample_clock_or_cancel_and_snapshot_is_detached(running):
    gate = threading.Event()
    clock = ManualClock(12345)
    cancel_calls = []

    def cancel():
        cancel_calls.append(threading.get_ident())
        return False

    source = MemorySource([b"RGB"], read_gate=gate, wake_reads=False)
    owner, _ = running(source, clock=clock, cancel=cancel)
    wait(source.read_entered)
    clocks, cancels = tuple(clock.calls), tuple(cancel_calls)
    for _ in range(3):
        snapshot = accounting(owner.snapshot())
        snapshot["frames_completed"] = 900
        assert owner.take() is None
    assert owner.snapshot()["frames_completed"] == 0
    assert tuple(clock.calls) == clocks and tuple(cancel_calls) == cancels
    closed(owner.close(), confirmed=False)
    assert tuple(clock.calls) == clocks and tuple(cancel_calls) == cancels
    gate.set()
    wait(source.closed_event)
    closed(owner.close())
    assert set(clock.calls) == set(cancel_calls) == set(source.read_threads)
    assert threading.get_ident() not in clock.calls
    assert source.close_threads == source.closed_threads == source.read_threads


def test_new_internal_owner_is_not_registered_in_existing_public_tools():
    root = Path(__file__).resolve().parents[2]
    paths = (root / "mcp-servers/play-mcp/play_mcp/server.py",
             root / "src/pweh/vision_sequence.py", root / "src/pweh/vision_template.py")
    for path in paths:
        tree = ast.parse(path.read_text(encoding="utf-8"), feature_version=(3, 10))
        imports = [node.module or "" for node in ast.walk(tree) if isinstance(node, ast.ImportFrom)]
        imports.extend(alias.name for node in ast.walk(tree) if isinstance(node, ast.Import) for alias in node.names)
        assert not any("rawvideo_frames" in module or "frame_owner" in module for module in imports)
    for name in ("fake_rawvideo_source.py", "test_rawvideo_frame_integration.py"):
        ast.parse(Path(__file__).with_name(name).read_text(encoding="utf-8"), feature_version=(3, 10))
