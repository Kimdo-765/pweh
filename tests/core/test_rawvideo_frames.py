"""고정 RGB24 순수 queue의 유한 경계·시간·폐기 회계를 확인한다."""

from dataclasses import FrozenInstanceError

import pytest

from pweh import rawvideo_frames as R


KEYS = {
    "pixel_format", "width", "height", "frame_bytes", "bytes_accepted", "frames_completed",
    "frames_taken", "frames_dropped", "pending_frames", "tail_bytes", "last_index", "last_receipt_ns",
    "stop_reason", "eof_observed", "framing_complete",
}
REASONS = ("eof", "frame_limit", "byte_limit", "time_limit", "cancelled", "source_failed", "clock_regression")


def queue(width=2, height=1, *, start=100, end=1000):
    return R.RawFrameQueue(width, height, started_ns=start, deadline_ns=end)


def check(q):
    s = q.snapshot()
    assert set(s) == KEYS
    assert s["pixel_format"] == "rgb24"
    for key in ("width", "height", "frame_bytes", "bytes_accepted", "frames_completed", "frames_taken",
                "frames_dropped", "pending_frames", "tail_bytes"):
        assert type(s[key]) is int and s[key] >= 0
    assert 1 <= s["width"] <= 1600 and 1 <= s["height"] <= 1600
    assert s["frame_bytes"] == s["width"] * s["height"] * 3
    assert s["bytes_accepted"] == s["frames_completed"] * s["frame_bytes"] + s["tail_bytes"]
    assert s["frames_completed"] == s["frames_taken"] + s["frames_dropped"] + s["pending_frames"]
    assert s["bytes_accepted"] <= 16 << 20 and s["frames_completed"] <= 16
    assert s["pending_frames"] in (0, 1) and 0 <= s["tail_bytes"] < s["frame_bytes"]
    if s["frames_completed"]:
        assert s["last_index"] == s["frames_completed"] - 1
        assert type(s["last_receipt_ns"]) is int
    else:
        assert s["last_index"] is None and s["last_receipt_ns"] is None
    assert type(s["eof_observed"]) is bool and type(s["framing_complete"]) is bool
    assert s["eof_observed"] == (s["stop_reason"] in ("eof", "partial_eof"))
    assert s["framing_complete"] == (s["stop_reason"] == "eof")
    if s["stop_reason"] == "eof":
        assert s["tail_bytes"] == 0
    elif s["stop_reason"] == "partial_eof":
        assert s["tail_bytes"] > 0
    assert all(not isinstance(value, bytes) for value in s.values())
    if s["stop_reason"] is not None:
        assert q.read_size == 0
    else:
        assert q.read_size == min(65536, (16 << 20) - s["bytes_accepted"],
                                  (16 - s["frames_completed"]) * s["frame_bytes"] - s["tail_bytes"])
    return s


def failure(call, code="frame_input_invalid"):
    with pytest.raises(R.FrameError) as caught:
        call()
    exc = caught.value
    assert exc.code == code
    assert exc.data == {} and exc.hint is None
    assert "PRIVATE" not in str(exc) and "PRIVATE" not in repr(exc.to_dict())
    assert exc.__cause__ is None


def without_stop(s):
    return {key: value for key, value in s.items() if key not in ("stop_reason", "eof_observed", "framing_complete")}


@pytest.mark.parametrize("width,height", [(1, 1), (1, 1600), (1600, 1), (1600, 1600), (37, 19)])
def test_geometry_and_initial_read_budget(width, height):
    q = queue(width, height)
    assert check(q)["frame_bytes"] == width * height * 3
    assert q.take() is None


@pytest.mark.parametrize("name", ["width", "height"])
@pytest.mark.parametrize("value", [True, False, 1.0, "PRIVATE", None, 0, -1, 1601, 1 << 1000])
def test_invalid_geometry(name, value):
    args = dict(width=1, height=1, started_ns=0, deadline_ns=1)
    args[name] = value
    failure(lambda: R.RawFrameQueue(**args))


@pytest.mark.parametrize("name", ["started_ns", "deadline_ns"])
@pytest.mark.parametrize("value", [True, False, 1.0, "PRIVATE", None, -1, 1 << 63, 1 << 1000])
def test_constructor_exact_time(name, value):
    args = dict(width=1, height=1, started_ns=0, deadline_ns=100)
    args[name] = value
    failure(lambda: R.RawFrameQueue(**args))


@pytest.mark.parametrize("start,end", [(0, 0), (2, 1), (0, 5_000_000_001), (10, 5_000_000_011)])
def test_constructor_time_window_rejected(start, end):
    failure(lambda: queue(start=start, end=end))


@pytest.mark.parametrize("start,end", [(0, 1), (0, 5_000_000_000),
                                     (R.MAX_TIME_NS - 1, R.MAX_TIME_NS),
                                     (R.MAX_TIME_NS - 5_000_000_000, R.MAX_TIME_NS)])
def test_constructor_time_window_extremes(start, end):
    q = queue(start=start, end=end)
    q.feed(b"", receipt_ns=start)
    assert check(q)["stop_reason"] is None


def test_one_byte_splits_use_completion_receipt():
    q = queue()
    for index, byte in enumerate(b"abcdef"):
        q.feed(bytes([byte]), receipt_ns=100 + index)
        s = check(q)
        assert s["last_receipt_ns"] == (105 if index == 5 else None)
    f = q.take()
    assert (f.index, f.receipt_ns, f.pixels) == (0, 105, b"abcdef")
    assert q.take() is None
    assert check(q)["frames_taken"] == 1


def test_coalesced_frames_and_tail_keep_only_latest():
    q = queue()
    q.feed(b"abcdefABCDEF123456!", receipt_ns=123)
    s = check(q)
    assert (s["frames_completed"], s["frames_dropped"], s["pending_frames"], s["tail_bytes"]) == (3, 2, 1, 1)
    f = q.take()
    assert (f.index, f.receipt_ns, f.pixels) == (2, 123, b"123456")
    q.feed(b"HELLO", receipt_ns=124)
    f2 = q.take()
    assert (f2.index, f2.receipt_ns, f2.pixels) == (3, 124, b"!HELLO")
    assert f.pixels == b"123456"
    assert check(q)["frames_taken"] == 2


def test_ties_across_feeds_and_tail_sample_not_last_frame():
    q = queue()
    q.feed(b"abcdef", receipt_ns=200)
    f = q.take()
    q.feed(b"ABCDEF", receipt_ns=200)
    f2 = q.take()
    assert (f.receipt_ns, f2.receipt_ns) == (200, 200)
    q.feed(b"x", receipt_ns=300)
    assert check(q)["last_receipt_ns"] == 200
    failure(lambda: q.feed(b"y", receipt_ns=299), "frame_clock_regression")
    s = check(q)
    assert (s["tail_bytes"], s["last_receipt_ns"], s["stop_reason"]) == (1, 200, "clock_regression")


def test_empty_feed_is_not_eof_but_samples_time():
    q = queue()
    before = q.snapshot()
    q.feed(b"", receipt_ns=200)
    assert check(q) == before
    failure(lambda: q.feed(b"", receipt_ns=199), "frame_clock_regression")
    assert not check(q)["eof_observed"]


@pytest.mark.parametrize("receipt", [0, 99])
def test_receipt_before_start(receipt):
    q = queue()
    failure(lambda: q.feed(b"abc", receipt_ns=receipt), "frame_clock_regression")
    s = check(q)
    assert s["bytes_accepted"] == 0 and s["stop_reason"] == "clock_regression"


@pytest.mark.parametrize("receipt", [True, False, 100.0, "PRIVATE", None, -1, 1 << 63])
@pytest.mark.parametrize("action", ["feed", "finish"])
def test_invalid_time_keeps_prior_data(receipt, action):
    q = queue()
    q.feed(b"abcdef!", receipt_ns=100)
    before = q.snapshot()
    if action == "feed":
        failure(lambda: q.feed(b"X", receipt_ns=receipt))
    else:
        failure(lambda: q.finish("eof", at_ns=receipt))
    after = check(q)
    assert without_stop(after) == without_stop(before)
    assert after["stop_reason"] == "source_failed"
    assert q.take().pixels == b"abcdef"


@pytest.mark.parametrize("receipt", [1000, 1001, R.MAX_TIME_NS])
@pytest.mark.parametrize("data", [b"", b"X", b"ABCDEF"])
def test_deadline_rejects_all_new_bytes_without_late_counter(receipt, data):
    q = queue()
    q.feed(b"abcdef!", receipt_ns=999)
    before = q.snapshot()
    assert q.feed(data, receipt_ns=receipt) is None
    after = check(q)
    assert without_stop(after) == without_stop(before)
    assert after["stop_reason"] == "time_limit"
    assert q.take().pixels == b"abcdef"


@pytest.mark.parametrize("data", [None, "PRIVATE", bytearray(b"PRIVATE"), memoryview(b"PRIVATE"), [1], 3, True])
def test_feed_exact_bytes_and_atomic_failure(data):
    q = queue()
    q.feed(b"abcdef!", receipt_ns=100)
    before = q.snapshot()
    failure(lambda: q.feed(data, receipt_ns=101))
    assert without_stop(check(q)) == without_stop(before)
    assert q.snapshot()["stop_reason"] == "source_failed"


def test_read_chunk_overrun_is_not_sliced():
    q = queue(1600, 1600)
    q.feed(b"123", receipt_ns=100)
    before = q.snapshot()
    failure(lambda: q.feed(bytes(65537), receipt_ns=101))
    assert without_stop(check(q)) == without_stop(before)


@pytest.mark.parametrize("tail", [0, 1, 2])
def test_remaining_frame_budget_and_overrun(tail):
    q = queue(1, 1)
    q.feed(bytes(45 + tail), receipt_ns=100)
    assert q.read_size == 3 - tail
    before = q.snapshot()
    failure(lambda: q.feed(bytes(4 - tail), receipt_ns=101))
    assert without_stop(check(q)) == without_stop(before)


@pytest.mark.parametrize("pixel", [b"\0\0\0", b"xxx", b"\xff\x00\xff"])
@pytest.mark.parametrize("take_each", [False, True])
def test_sixteen_frames_and_repeated_pixels_are_normal(pixel, take_each):
    q = queue(1, 1)
    for index in range(16):
        q.feed(pixel, receipt_ns=100)
        if take_each:
            f = q.take()
            assert (f.index, f.receipt_ns, f.pixels) == (index, 100, pixel)
        check(q)
    s = check(q)
    assert (s["frames_completed"], s["bytes_accepted"], s["stop_reason"]) == (16, 48, "frame_limit")
    assert s["frames_dropped"] == (0 if take_each else 15)
    assert not s["eof_observed"] and not s["framing_complete"]
    q.finish("eof", at_ns=1000)
    assert check(q) == s


def test_sixteen_coalesced_frames_have_one_receipt():
    q = queue(1, 1)
    q.feed(b"abc" * 16, receipt_ns=321)
    s = check(q)
    assert (s["last_index"], s["last_receipt_ns"], s["frames_dropped"]) == (15, 321, 15)
    f = q.take()
    assert (f.index, f.receipt_ns, f.pixels) == (15, 321, b"abc")


def test_actual_max_geometry_byte_cap_and_tail():
    q = queue(1600, 1600)
    chunk = bytes(range(256)) * 256
    calls = 0
    while q.read_size:
        size = q.read_size
        q.feed(chunk[:size], receipt_ns=100)
        calls += 1
        check(q)
    s = check(q)
    assert calls == 256
    assert s["frame_bytes"] == 7_680_000
    assert (s["bytes_accepted"], s["frames_completed"], s["tail_bytes"]) == (16_777_216, 2, 1_417_216)
    assert (s["frames_dropped"], s["pending_frames"], s["stop_reason"]) == (1, 1, "byte_limit")
    assert not s["eof_observed"]
    f = q.take()
    assert f.index == 1 and f.receipt_ns == 100 and len(f.pixels) == 7_680_000
    assert f.pixels[:256] == bytes(range(256))
    q.finish("eof", at_ns=1000)
    assert check(q)["stop_reason"] == "byte_limit"


def test_byte_cap_remaining_not_only_full_read_size():
    q = queue(1600, 1600)
    q.feed(b"X", receipt_ns=100)
    while q.snapshot()["bytes_accepted"] < (16 << 20) - 65535:
        q.feed(bytes(q.read_size), receipt_ns=100)
    assert q.read_size == 65535
    before = q.snapshot()
    failure(lambda: q.feed(bytes(65536), receipt_ns=100))
    assert without_stop(check(q)) == without_stop(before)
    assert q.snapshot()["stop_reason"] == "source_failed"


@pytest.mark.parametrize("data,reason,complete", [(b"", "eof", True), (b"abcdef", "eof", True),
                                                (b"a", "partial_eof", False), (b"abcdef!", "partial_eof", False)])
def test_empty_complete_partial_eof(data, reason, complete):
    q = queue()
    q.feed(data, receipt_ns=100)
    q.finish("eof", at_ns=1000)
    s = check(q)
    assert s["stop_reason"] == reason and s["framing_complete"] is complete and s["eof_observed"]
    f = q.take()
    assert (f is not None) == (len(data) >= 6)
    if f is not None:
        assert f.pixels == b"abcdef"
    assert q.take() is None
    check(q)


@pytest.mark.parametrize("first", REASONS)
@pytest.mark.parametrize("second", REASONS)
def test_first_finish_preserves_counts_and_eof(first, second):
    q = queue()
    q.feed(b"abcdef!", receipt_ns=200)
    q.finish(first, at_ns=201)
    before = check(q)
    q.finish(second, at_ns=R.MAX_TIME_NS)
    assert check(q) == before
    assert q.take().pixels == b"abcdef"


@pytest.mark.parametrize("reason", ["partial_eof", "PRIVATE", "", None, 1, True, b"eof"])
def test_finish_reason_closed(reason):
    q = queue()
    q.feed(b"abcdef!", receipt_ns=100)
    before = q.snapshot()
    failure(lambda: q.finish(reason, at_ns=101))
    assert without_stop(check(q)) == without_stop(before)
    assert q.snapshot()["stop_reason"] == "source_failed"


def test_finish_clock_regression_keeps_tail_and_pending():
    q = queue()
    q.feed(b"abcdef!", receipt_ns=200)
    failure(lambda: q.finish("eof", at_ns=199), "frame_clock_regression")
    assert (check(q)["tail_bytes"], q.snapshot()["stop_reason"]) == (1, "clock_regression")
    assert q.take().pixels == b"abcdef"


@pytest.mark.parametrize("reason", REASONS)
@pytest.mark.parametrize("data", [b"", b"PRIVATE", None])
def test_terminal_feed_never_changes_any_observation(reason, data):
    q = queue()
    q.feed(b"abcdef!", receipt_ns=200)
    q.finish(reason, at_ns=201)
    before = q.snapshot()
    failure(lambda: q.feed(data, receipt_ns=0))
    assert check(q) == before


def test_discard_pending_is_idempotent_before_and_after_terminal():
    q = queue()
    before = q.snapshot()
    q.discard_pending()
    assert check(q) == before
    q.feed(b"abcdef!", receipt_ns=100)
    q.discard_pending()
    s = check(q)
    assert (s["frames_dropped"], s["pending_frames"], s["tail_bytes"], s["last_index"]) == (1, 0, 1, 0)
    q.discard_pending()
    assert check(q) == s
    q.feed(b"HELLO", receipt_ns=101)
    q.finish("eof", at_ns=102)
    q.discard_pending()
    after = check(q)
    assert (after["frames_dropped"], after["frames_taken"], after["last_index"], after["stop_reason"]) == (2, 0, 1, "eof")
    assert q.take() is None
    q.discard_pending()
    assert check(q) == after


def test_taken_frame_is_immutable_and_raw_repr_hidden():
    q = queue(7, 1)
    private = b"PRIVATE_PIXEL_CONTENT"
    assert len(private) == 21
    q.feed(private, receipt_ns=100)
    frame = q.take()
    assert type(frame) is R.RawFrame and type(frame.pixels) is bytes
    assert not hasattr(frame, "__dict__") and "PRIVATE" not in repr(frame)
    with pytest.raises(FrozenInstanceError):
        frame.pixels = b"different"
    with pytest.raises(TypeError):
        frame.pixels[0] = 0
    q.feed(bytes(21), receipt_ns=101)
    q.discard_pending()
    assert frame.pixels == private
    assert "PRIVATE" not in repr(check(q))


def test_snapshot_is_fresh_copy_and_has_no_source_keys():
    q = queue()
    q.feed(b"abcdef!", receipt_ns=100)
    expected = check(q)
    changed = q.snapshot()
    changed["bytes_accepted"] = -1
    changed["pixels"] = b"PRIVATE"
    assert q.snapshot() == expected
    assert not {"source_closed", "worker_stopped", "late_read_bytes"} & set(expected)


class BadInt(int):
    def __lt__(self, other):
        raise AssertionError("호출하면 안 되는 비교")


class BadBytes(bytes):
    def __len__(self):
        raise AssertionError("호출하면 안 되는 길이")


class BadStr(str):
    def __eq__(self, other):
        raise AssertionError("호출하면 안 되는 비교")


def test_subclass_and_hostile_values_are_not_coerced():
    failure(lambda: queue(width=BadInt(1)))
    failure(lambda: queue(start=BadInt(100)))
    q = queue()
    failure(lambda: q.feed(BadBytes(b"PRIVATE"), receipt_ns=100))
    q = queue()
    failure(lambda: q.feed(b"", receipt_ns=BadInt(100)))
    q = queue()
    failure(lambda: q.finish(BadStr("eof"), at_ns=100))


@pytest.mark.parametrize("code", ["frame_input_invalid", "frame_source_failed", "frame_clock_regression",
                                  "frame_cleanup_incomplete", "PRIVATE", None, {}, BadStr("PRIVATE")])
def test_error_vocabulary_contains_no_caller_text(code):
    exc = R.FrameError(code)
    assert exc.code in ("frame_input_invalid", "frame_source_failed", "frame_clock_regression", "frame_cleanup_incomplete")
    assert exc.data == {} and exc.hint is None
    assert "PRIVATE" not in str(exc) and "PRIVATE" not in repr(exc.to_dict())
