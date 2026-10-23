"""저장 PNG 비교: 순수 수치·격리 PNG·닫힌 wire·자식 정리의 합성 시험."""

from __future__ import annotations

import io
import json
import os
from pathlib import Path
import struct
import sys
import sysconfig
import threading
import time
import zlib

import pytest
from PIL import Image

from pweh import imagehints as H
from pweh import vision_template as V
from pweh.errors import PwehError
from pweh.procutil import pid_alive


def chunk(kind, data=b""):
    return struct.pack(">I", len(data)) + kind + data + struct.pack(">I", zlib.crc32(kind + data) & 0xffffffff)


def png(size=(2, 2), pixels=None, *, ihdr=None, idat=None, tail=b""):
    """Pillow와 독립된 filter 0의 작은 합성 RGB PNG."""
    width, height = size
    pixels = pixels if pixels is not None else bytes([20, 40, 60]) * width * height
    scan = b"".join(b"\x00" + pixels[y * width * 3:(y + 1) * width * 3] for y in range(height))
    ihdr = ihdr if ihdr is not None else struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0)
    return (b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", ihdr)
            + chunk(b"IDAT", zlib.compress(scan) if idat is None else idat) + chunk(b"IEND") + tail)


def match(reference=None, candidate=None, **options):
    defaults = dict(reference_size=(2, 2), candidate_size=(2, 2), reference_roi=(0, 0, 2, 2),
                    candidate_roi=(0, 0, 2, 2), max_mean_error=0, deadline=time.monotonic() + 5)
    defaults.update(options)
    return H.match_png_rois(png() if reference is None else reference,
                            png() if candidate is None else candidate, **defaults)


def assert_error(code, call):
    with pytest.raises(PwehError) as caught:
        call()
    assert caught.value.code == code
    assert caught.value.data == {}
    assert "SYNTHETIC_PRIVATE" not in str(caught.value)
    assert caught.value.__suppress_context__


@pytest.mark.parametrize("other,threshold,total,matched", [
    (b"\0\0\0", 0, 0, True), (b"\1\1\1", 1, 3, True),
    (b"\1\1\2", 1, 4, False), (b"\xff\xff\xff", 255, 765, True),
])
def test_pure_integer_threshold(other, threshold, total, matched):
    result = V.compare_rgb_bytes(b"\0\0\0", other, width=1, height=1,
                                 max_mean_error=threshold, deadline=time.monotonic() + 5)
    assert result == {"sum_abs": total, "samples": 3, "mean_abs_error": total / 3, "matched": matched}
    assert type(result["mean_abs_error"]) is float


@pytest.mark.parametrize("field,value", [
    ("width", True), ("width", 0), ("width", 1601), ("width", "1"), ("width", 1.0),
    ("height", False), ("height", -1), ("height", 1601),
    ("max_mean_error", True), ("max_mean_error", -1), ("max_mean_error", 256),
    ("max_mean_error", 1.0), ("max_mean_error", "0"),
    ("deadline", True), ("deadline", float("nan")), ("deadline", float("inf")),
    ("deadline", 10 ** 1000), ("deadline", "SYNTHETIC_PRIVATE"),
])
def test_pure_exact_types_and_limits(field, value):
    opts = dict(width=1, height=1, max_mean_error=0, deadline=time.monotonic() + 5)
    opts[field] = value
    assert_error("template_input_invalid", lambda: V.compare_rgb_bytes(b"123", b"123", **opts))


@pytest.mark.parametrize("data", [b"", b"12", b"1234", bytearray(b"123"), memoryview(b"123"), "123"])
def test_pure_exact_bytes(data):
    for side in (0, 1):
        inputs = [b"123", b"123"]
        inputs[side] = data
        assert_error("template_input_invalid", lambda: V.compare_rgb_bytes(*inputs, width=1, height=1,
                     max_mean_error=0, deadline=time.monotonic() + 5))


def test_pure_chunk_deadline(monkeypatch):
    # 첫 청크를 처리한 직후 만료되며 두 번째 청크의 결과는 반환하지 않는다.
    with monkeypatch.context() as patch:
        clock = iter([0, 0, 2])
        patch.setattr(V.time, "monotonic", lambda: next(clock))
        assert_error("time_limit", lambda: V.compare_rgb_bytes(b"a" * 90000, b"b" * 90000,
                     width=300, height=100, max_mean_error=1, deadline=1))


def test_real_worker_equal_roi_and_offset():
    ref = png((3, 2), bytes(range(18)))
    # 첫 행의 ref x=1 두 픽셀과 cand의 연속 두 픽셀을 별도로 선택한다.
    cand = png((2, 2), bytes(range(3, 9)) + b"abcdef")
    result = match(ref, cand, reference_size=(3, 2), candidate_size=(2, 2),
                   reference_roi=(1, 0, 2, 1), candidate_roi=(0, 0, 2, 1))
    assert result == {"sum_abs": 0, "samples": 6, "mean_abs_error": 0.0, "matched": True}


def test_real_worker_difference_and_threshold():
    result = match(png(pixels=b"\0" * 12), png(pixels=b"\1" * 11 + b"\2"), max_mean_error=1)
    assert result == {"sum_abs": 13, "samples": 12, "mean_abs_error": 13 / 12, "matched": False}


def test_real_producer_png_and_maximum_geometry_cost():
    out = io.BytesIO()
    Image.new("RGB", (1600, 1600), (10, 30, 50)).save(out, format="PNG")
    data = out.getvalue()
    before = time.monotonic()
    result = match(data, data, reference_size=(1600, 1600), candidate_size=(1600, 1600),
                   reference_roi=(0, 0, 1600, 1600), candidate_roi=(0, 0, 1600, 1600),
                   deadline=before + 5)
    assert time.monotonic() - before < 5
    assert result == {"sum_abs": 0, "samples": 1600 * 1600 * 3, "mean_abs_error": 0.0, "matched": True}


@pytest.mark.parametrize("field,value", [
    ("reference_size", [2, 2]), ("reference_size", (True, 2)), ("reference_size", (2,)),
    ("reference_size", (1601, 2)), ("candidate_size", (0, 2)),
    ("reference_roi", [0, 0, 2, 2]), ("reference_roi", (0, 0, 2, True)),
    ("reference_roi", (0, 0, 0, 1)), ("reference_roi", (-1, 0, 2, 2)),
    ("reference_roi", (1, 0, 2, 2)), ("reference_roi", (0, 1, 2, 2)),
    ("reference_roi", (0, 0, 1, 2)), ("reference_roi", (0.0, 0, 2, 2)),
    ("candidate_roi", (0, 0, 2, 3)), ("candidate_roi", (0, 0, 1, 1, 1)),
    ("max_mean_error", False), ("max_mean_error", 256), ("cancel_event", lambda: False),
])
def test_parent_input_rejected_before_spawn(monkeypatch, field, value):
    monkeypatch.setattr(H, "_exchange", lambda *a, **k: pytest.fail("spawn"))
    assert_error("template_input_invalid", lambda: match(**{field: value}))


@pytest.mark.parametrize("data", [b"", b"x" * ((1 << 20) + 1), bytearray(b"x"), "SYNTHETIC_PRIVATE"])
def test_parent_bytes_cap(monkeypatch, data):
    monkeypatch.setattr(H, "_exchange", lambda *a, **k: pytest.fail("spawn"))
    for side in (0, 1):
        inputs = [b"x", b"x"]
        inputs[side] = data
        assert_error("template_input_invalid", lambda: match(*inputs))


def test_parent_deadline_cancel_before_spawn(monkeypatch):
    monkeypatch.setattr(H, "_exchange", lambda *a, **k: pytest.fail("spawn"))
    assert_error("time_limit", lambda: match(deadline=time.monotonic() - 1))
    assert_error("template_input_invalid", lambda: match(deadline=time.monotonic() + 10))
    event = threading.Event()
    event.set()
    assert_error("cancelled", lambda: match(cancel_event=event))


def png_mutations():
    original = png()
    header = original[8:33]
    body = original[33:-12]
    signature = original[:8]
    for name, value in [
        ("signature", b"bad_____" + original[8:]),
        ("crc", original[:-1] + bytes([original[-1] ^ 1])),
        ("repeat_ihdr", signature + header + header + body + chunk(b"IEND")),
        ("no_ihdr", signature + body + chunk(b"IEND")),
        ("ihdr_short", signature + chunk(b"IHDR", b"x" * 12) + body + chunk(b"IEND")),
        ("no_idat", signature + header + chunk(b"IEND")),
        ("no_iend", original[:-12]), ("iend_data", original[:-12] + chunk(b"IEND", b"x")),
        ("tail", original + b"SYNTHETIC_PRIVATE"), ("truncated", original[:-1]),
        ("text", original[:-12] + chunk(b"tEXt", b"x\0SYNTHETIC_PRIVATE") + chunk(b"IEND")),
        ("animation", signature + header + chunk(b"acTL", b"\0" * 8) + body + chunk(b"IEND")),
        ("unknown", signature + header + chunk(b"AAAA") + body + chunk(b"IEND")),
        ("idat_after_iend", original + body),
        ("beyond_input", signature + struct.pack(">I", 0xffffffff) + b"IHDR" + b"x" * 8),
    ]:
        yield name, value
    for field, value in [(0, 3), (1, 3), (2, 16), (3, 3), (3, 6), (4, 1), (5, 1), (6, 2)]:
        fields = [2, 2, 8, 2, 0, 0, 0]
        fields[field] = value
        yield f"ihdr_{field}_{value}", png(ihdr=struct.pack(">IIBBBBB", *fields))


@pytest.mark.parametrize("name,data", list(png_mutations()))
def test_real_worker_rejects_invalid_png(name, data):
    assert_error("template_input_invalid", lambda: match(data))


@pytest.mark.parametrize("compressed", [b"SYNTHETIC_PRIVATE", zlib.compress(b""), zlib.compress(b"\0\0")])
def test_decode_failure_is_fixed(compressed):
    assert_error("template_failed", lambda: match(png(idat=compressed)))


def test_multiple_consecutive_idat_and_last_pixel():
    data = png()
    n = struct.unpack_from(">I", data, 33)[0]
    compressed = data[41:41 + n]
    split = data[:33] + chunk(b"IDAT", compressed[:3]) + chunk(b"IDAT", compressed[3:]) + chunk(b"IEND")
    assert match(split, reference_roi=(1, 1, 1, 1), candidate_roi=(1, 1, 1, 1))["matched"]


def response():
    return {"op": V.OP, "reference_size": [2, 2], "candidate_size": [2, 2],
            "reference_roi": [0, 0, 2, 2], "candidate_roi": [0, 0, 2, 2], "max_mean_error": 0,
            "result": {"sum_abs": 0, "samples": 12, "mean_abs_error": 0.0, "matched": True}}


@pytest.mark.parametrize("field,value", [
    ("op", "SYNTHETIC_PRIVATE"), ("reference_size", [True, 2]), ("candidate_size", [2, 3]),
    ("reference_roi", [False, 0, 2, 2]), ("candidate_roi", [0, 0, 2, 2.0]),
    ("max_mean_error", False), ("result", []), ("extra", "SYNTHETIC_PRIVATE"),
])
def test_response_envelope_forgery(monkeypatch, field, value):
    row = response()
    row[field] = value
    monkeypatch.setattr(H, "_exchange", lambda *a, **k: (json.dumps(row).encode(), None))
    assert_error("template_failed", match)


@pytest.mark.parametrize("field,value", [
    ("sum_abs", True), ("sum_abs", -1), ("sum_abs", 3061), ("sum_abs", 0.0),
    ("samples", 12.0), ("samples", False), ("samples", 13),
    ("mean_abs_error", 0), ("mean_abs_error", float("nan")),
    ("mean_abs_error", float("inf")), ("mean_abs_error", 0.1),
    ("matched", 1), ("matched", False), ("raw", "SYNTHETIC_PRIVATE"),
])
def test_response_integer_relations(monkeypatch, field, value):
    row = response()
    row["result"][field] = value
    monkeypatch.setattr(H, "_exchange", lambda *a, **k: (json.dumps(row).encode(), None))
    assert_error("template_failed", match)


@pytest.mark.parametrize("raw", [
    b"", b"[]", b"null", b"SYNTHETIC_PRIVATE", b"x" * ((1 << 16) + 1),
    b'{"op":"template-match-v1","error":"template_failed","error":"time_limit"}',
    b'{"op":"template-match-v1","error":"SYNTHETIC_PRIVATE"}',
    b'{"op":"template-match-v1","error":[]}',
    b'{"op":"template-match-v1","error":"template_failed","raw":"SYNTHETIC_PRIVATE"}',
    b"[" * 2000 + b"]" * 2000,
])
def test_response_invalid_json_and_error_envelope(monkeypatch, raw):
    monkeypatch.setattr(H, "_exchange", lambda *a, **k: (raw, None))
    assert_error("template_failed", match)


@pytest.mark.parametrize("code", ["template_input_invalid", "template_failed", "time_limit"])
def test_fixed_worker_error(monkeypatch, code):
    monkeypatch.setattr(H, "_exchange", lambda *a, **k: (json.dumps({"op": V.OP, "error": code}).encode(), None))
    assert_error(code, match)


@pytest.mark.parametrize("reason,code", [("cancelled", "cancelled"), ("wall_timeout", "time_limit"),
                                      ("worker_output_limit", "template_failed"), ("worker_stderr_limit", "template_failed")])
def test_exchange_reason_fixed(monkeypatch, reason, code):
    monkeypatch.setattr(H, "_exchange", lambda *a, **k: (b"SYNTHETIC_PRIVATE", reason))
    assert_error(code, match)


def test_parent_wire_and_shared_deadline(monkeypatch):
    end = time.monotonic() + 5
    event = threading.Event()
    first, second = png(), png(pixels=b"\0" * 12)
    def exchange(argv, payload, **kwargs):
        assert argv == [sys.executable, "-I", "-S", str(Path(H.__file__).with_name("_image_worker.py"))]
        assert kwargs == {"deadline": end, "cancel_event": event, "max_output_bytes": 65536}
        header_size, data_size = struct.unpack_from(">IQ", payload)
        opts = json.loads(payload[12:12 + header_size])
        assert len(opts) == 11 and opts["parent_pid"] == os.getpid()
        assert 0 < opts["max_seconds"] <= 5
        assert opts["reference_length"] == len(first) and opts["candidate_length"] == len(second)
        assert data_size == len(first) + len(second)
        assert payload[12 + header_size:] == first + second
        return json.dumps(response()).encode(), None
    monkeypatch.setattr(H, "_exchange", exchange)
    assert match(first, second, deadline=end, cancel_event=event) == response()["result"]


def test_cancel_after_response_validation(monkeypatch):
    event = threading.Event()
    monkeypatch.setattr(H, "_exchange", lambda *a, **k: (json.dumps(response()).encode(), None))
    original = V._validate_result
    def validate(*args, **kwargs):
        original(*args, **kwargs)
        event.set()
    monkeypatch.setattr(V, "_validate_result", validate)
    assert_error("cancelled", lambda: match(cancel_event=event))


@pytest.mark.parametrize("exception", [OSError("SYNTHETIC_PRIVATE"), RuntimeError("SYNTHETIC_PRIVATE"),
                                       PwehError("SYNTHETIC_PRIVATE", code="other")])
def test_exchange_cleanup_error_never_success(monkeypatch, exception):
    def exchange(*args, **kwargs):
        raise exception
    monkeypatch.setattr(H, "_exchange", exchange)
    assert_error("template_failed", match)


def worker_options():
    return {**{k: v for k, v in response().items() if k != "result"}, "parent_pid": os.getpid(),
            "site_paths": list(dict.fromkeys(sysconfig.get_path(n) for n in ("purelib", "platlib"))),
            "max_seconds": 5, "reference_length": len(png()), "candidate_length": len(png())}


def worker_wire(opts, *, header=None, body=None):
    header = json.dumps(opts, allow_nan=True).encode() if header is None else header
    body = png() * 2 if body is None else body
    raw, reason = H._exchange([sys.executable, "-I", "-S", str(Path(H.__file__).with_name("_image_worker.py"))],
                              struct.pack(">IQ", len(header), len(body)) + header + body,
                              deadline=time.monotonic() + 5, cancel_event=None, max_output_bytes=65536)
    assert reason is None
    return json.loads(raw)


@pytest.mark.parametrize("field,value", [
    ("op", "SYNTHETIC_PRIVATE"), ("parent_pid", True), ("site_paths", []), ("site_paths", ["relative"]),
    ("max_seconds", True), ("max_seconds", 0), ("max_seconds", 6), ("max_seconds", float("nan")),
    ("reference_length", True), ("reference_length", 1 << 21), ("candidate_length", 1),
    ("reference_size", [True, 2]), ("candidate_roi", [0, 0, 1, 1]),
    ("max_mean_error", False), ("extra", "SYNTHETIC_PRIVATE"),
])
def test_worker_options_closed(field, value):
    opts = worker_options()
    opts[field] = value
    assert worker_wire(opts) == {"op": V.OP, "error": "template_input_invalid"}


def test_worker_duplicate_options():
    opts = worker_options()
    header = json.dumps(opts).encode()[:-1] + b',"max_mean_error":0}'
    assert worker_wire(opts, header=header) == {"op": V.OP, "error": "template_input_invalid"}


def test_optional_exchange_limit_preserves_default():
    argv = [sys.executable, "-I", "-S", "-c", "import os;os.write(1,b'x'*70000)"]
    raw, reason = H._exchange(argv, b"", deadline=time.monotonic() + 5, cancel_event=None)
    assert reason is None and len(raw) == 70000
    raw, reason = H._exchange(argv, b"", deadline=time.monotonic() + 5, cancel_event=None, max_output_bytes=65536)
    assert reason == "worker_output_limit" and len(raw) <= 65536


@pytest.mark.parametrize("cancel", [False, True])
def test_new_call_waits_for_child_cleanup(monkeypatch, tmp_path, cancel):
    pid_path = tmp_path / "child.pid"
    code = "import os,time,pathlib;pathlib.Path(" + repr(str(pid_path)) + ").write_text(str(os.getpid()));time.sleep(30)"
    original = H._exchange
    event = threading.Event()
    def exchange(argv, payload, **kwargs):
        return original([sys.executable, "-I", "-S", "-c", code], payload, **kwargs)
    monkeypatch.setattr(H, "_exchange", exchange)
    def cancellation():
        end = time.monotonic() + 3
        while not pid_path.exists() and time.monotonic() < end:
            time.sleep(.005)
        event.set()
    thread = threading.Thread(target=cancellation) if cancel else None
    if thread:
        thread.start()
    try:
        assert_error("cancelled" if cancel else "time_limit",
                     lambda: match(deadline=time.monotonic() + (4 if cancel else .25), cancel_event=event))
    finally:
        if thread:
            thread.join(4)
    assert pid_path.exists()
    assert not pid_alive(int(pid_path.read_text()))
