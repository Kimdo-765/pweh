"""pweh.fs.reader: 일반 파일만 열기, 범위 검사, 구간 보기."""

from __future__ import annotations

import os
import time

import pytest

from pweh.errors import ValidationFailed
from pweh.fs import BytesReader, FsError, ImageReader, SliceReader


def _reason(excinfo: pytest.ExceptionInfo) -> str:
    return excinfo.value.data["reason"]


def test_reads_regular_file_with_bounds(tmp_path):
    p = tmp_path / "card.img"
    p.write_bytes(bytes(range(256)) * 16)
    with ImageReader(p) as r:
        assert r.size == 4096
        assert r.read(0, 4) == b"\x00\x01\x02\x03"
        assert r.read(4092, 4) == bytes([252, 253, 254, 255])
        assert r.read(10, 0) == b""
        assert r.read_clamped(4090, 100) == bytes([250, 251, 252, 253, 254, 255])
        assert r.read_clamped(5000, 10) == b""
        for off, n in ((4093, 4), (-1, 2), (0, -1), (4096, 1)):
            with pytest.raises(FsError) as ei:
                r.read(off, n)
            assert _reason(ei) == "out_of_bounds"
        with pytest.raises(FsError) as ei:
            r.read(0, 1 << 30)
        assert _reason(ei) == "too_large"
    assert r.closed
    with pytest.raises(FsError):
        r.read(0, 1)


def test_fserror_is_validation_failed():
    e = FsError("x", reason="malformed")
    assert isinstance(e, ValidationFailed)
    assert e.code == "validation_failed"
    assert e.to_dict()["data"]["reason"] == "malformed"


def test_refuses_fifo_quickly(tmp_path):
    fifo = tmp_path / "pipe"
    os.mkfifo(fifo)
    t0 = time.monotonic()
    with pytest.raises(FsError) as ei:
        ImageReader(fifo)
    assert _reason(ei) == "not_regular_file"
    assert time.monotonic() - t0 < 10.0


@pytest.mark.parametrize("path", ["/dev/null", "/dev/zero", "/proc/self/status", "\\\\.\\PhysicalDrive0"])
def test_refuses_device_and_kernel_paths(path):
    with pytest.raises(FsError) as ei:
        ImageReader(path)
    assert _reason(ei) in ("not_regular_file", "not_found")


def test_refuses_directory_and_symlink_to_device(tmp_path):
    with pytest.raises(FsError) as ei:
        ImageReader(tmp_path)
    assert _reason(ei) == "not_regular_file"
    link = tmp_path / "evil.img"
    link.symlink_to("/dev/null")
    t0 = time.monotonic()
    with pytest.raises(FsError) as ei:
        ImageReader(link)
    assert _reason(ei) == "not_regular_file"
    assert time.monotonic() - t0 < 10.0


def test_missing_file(tmp_path):
    with pytest.raises(FsError) as ei:
        ImageReader(tmp_path / "nope.img")
    assert _reason(ei) == "not_found"


def test_symlink_to_regular_file_is_fine(tmp_path):
    real = tmp_path / "real.img"
    real.write_bytes(b"abc")
    link = tmp_path / "link.img"
    link.symlink_to(real)
    with ImageReader(link) as r:
        assert r.read(0, 3) == b"abc"


def test_slice_reader_truncated_and_offsets():
    base = BytesReader(bytes(range(100)))
    s = SliceReader(base, 90, 20)
    assert s.size == 10 and s.declared_size == 20 and s.truncated
    assert s.base_offset == 90
    assert s.read(0, 10) == bytes(range(90, 100))
    with pytest.raises(FsError):
        s.read(5, 6)
    nested = SliceReader(SliceReader(base, 10, 50), 5, 10)
    assert nested.base_offset == 15 and nested.read(0, 2) == bytes([15, 16])
    with pytest.raises(FsError):
        SliceReader(base, -1, 5)


def test_bytes_reader_sees_live_bytearray():
    buf = bytearray(16)
    r = BytesReader(buf)
    buf[3] = 7
    assert r.read(3, 1) == b"\x07"
