"""논리 아카이브는 합성 바이트만 사용한다. 폭탄·헤더·이름·CRC 경계를 시험한다."""
import hashlib
import io
import os
import struct
import tarfile
import time
import zipfile

import pytest

from pweh.archive import Archive, kind
from pweh.fs import FsError


def archive(tmp_path, data, **kwargs):
    p = tmp_path / "synthetic.arc"
    p.write_bytes(data)
    fd = os.open(p, os.O_RDONLY)
    try:
        yield Archive(fd, deadline=time.monotonic() + 10, cancel=lambda: False, **kwargs)
    finally:
        os.close(fd)


def zip_bytes(members, compression=zipfile.ZIP_DEFLATED):
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w", compression=compression) as z:
        for name, data in members:
            z.writestr(name, data)
    return out.getvalue()


def tar_bytes(members, fmt=tarfile.PAX_FORMAT):
    out = io.BytesIO()
    with tarfile.open(fileobj=out, mode="w", format=fmt) as t:
        for name, data in members:
            ti = tarfile.TarInfo(name)
            ti.size, ti.mtime = len(data), 1700000000
            t.addfile(ti, io.BytesIO(data))
    return out.getvalue()


@pytest.mark.parametrize("compression", [zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED])
def test_zip_bytes_hash_times(tmp_path, compression):
    data = b"synthetic sqlite content" * 12345
    for arc in archive(tmp_path, zip_bytes([("app/db.sqlite", data), ("empty", b"")], compression)):
        assert not arc.reasons
        result = arc.inventory(hash_members=True, max_hash_bytes=len(data))
        assert not result["truncated"]
        assert result["entries"][0]["sha256"] == hashlib.sha256(data).hexdigest()
        assert b"".join(arc.chunks(arc.select("arc:0", None), max_bytes=len(data))) == data
        assert result["entries"][0]["times"]["modified"]["time_basis"] == "local-unknown-tz"


@pytest.mark.parametrize("fmt", [tarfile.USTAR_FORMAT, tarfile.PAX_FORMAT, tarfile.GNU_FORMAT])
def test_tar_pax_gnu_times(tmp_path, fmt):
    name = "app/" + "long-name-" * (15 if fmt != tarfile.USTAR_FORMAT else 1)
    for arc in archive(tmp_path, tar_bytes([(name, b"hello")], fmt)):
        assert not arc.reasons
        e = arc.select(None, name)
        assert b"".join(arc.chunks(e, max_bytes=10)) == b"hello"
        assert e["times"]["modified"]["time_basis"] == "utc"
        assert e["times"]["modified"]["utc"].endswith("Z")


@pytest.mark.parametrize("builder", [zip_bytes, tar_bytes])
def test_duplicate_paths_require_ordinal(tmp_path, builder):
    with pytest.warns(UserWarning) if builder is zip_bytes else __import__('contextlib').nullcontext():
        data = builder([("same", b"one"), ("same", b"two")])
    for arc in archive(tmp_path, data):
        with pytest.raises(FsError, match="확정"):
            arc.select(None, "same")
        assert b"".join(arc.chunks(arc.select("arc:1", None), max_bytes=10)) == b"two"


@pytest.mark.parametrize("name", ["../outside", "/absolute", "C:/host", "a/../../host", "a\\host"])
def test_path_traversal_blocked(tmp_path, name):
    for arc in archive(tmp_path, zip_bytes([(name, b"x")])):
        assert arc.entries[0]["blocked_reason"] == "unsafe_path"
        with pytest.raises(FsError):
            arc.select("arc:0", None)


def test_tar_link_not_followed(tmp_path):
    out = io.BytesIO()
    with tarfile.open(fileobj=out, mode="w") as t:
        ti = tarfile.TarInfo("linked")
        ti.type, ti.linkname = tarfile.SYMTYPE, "/outside"
        t.addfile(ti)
    for arc in archive(tmp_path, out.getvalue()):
        assert arc.entries[0]["blocked_reason"] == "unsupported_member_type"
        assert arc.inventory(hash_members=True, max_hash_bytes=100)["truncated"]


def test_crc_and_false_declared_size(tmp_path):
    data = bytearray(zip_bytes([("file", b"x" * 200000)]))
    cd = data.index(b"PK\x01\x02")
    struct.pack_into("<I", data, cd + 16, 1)
    for arc in archive(tmp_path, data):
        with pytest.raises(FsError) as err:
            list(arc.chunks(arc.select("arc:0", None), max_bytes=300000))
        assert err.value.reason == "crc_mismatch"
    struct.pack_into("<I", data, cd + 24, 1)
    struct.pack_into("<I", data, 22, 1)
    for arc in archive(tmp_path, data):
        with pytest.raises(FsError) as err:
            list(arc.chunks(arc.select("arc:0", None), max_bytes=10))
        assert err.value.reason == "max_bytes"


def test_bounded_hashing_unverified_and_entry_limit(tmp_path):
    data = zip_bytes([("large", b"x" * 1000000), ("small", b"ok")])
    for arc in archive(tmp_path, data):
        result = arc.inventory(hash_members=True, max_hash_bytes=10)
        assert result["entries"][0]["sha256"] is None
        assert result["entries"][0]["status"] == "unverified"
        assert result["entries"][1]["sha256"] == hashlib.sha256(b"ok").hexdigest()
        assert "max_hash_bytes" in result["truncated_reasons"]
    for arc in archive(tmp_path, data, max_entries=1):
        assert len(arc.entries) == 1 and "max_entries" in arc.reasons
        with pytest.raises(FsError):
            arc.select(None, "large")


def test_zip_central_size_preflight(tmp_path):
    data = bytearray(zip_bytes([("file", b"abc")]))
    end = data.index(b"PK\x05\x06")
    struct.pack_into("<I", data, end + 12, 64 << 20)
    for arc in archive(tmp_path, data):
        assert arc.reasons == {"max_metadata"}
        assert arc.entries == []


def test_pax_size_preflight_without_allocation(tmp_path):
    p = tmp_path / "large-header.tar"
    ti = tarfile.TarInfo("pax")
    ti.type, ti.size = tarfile.XHDTYPE, 64 << 20
    with p.open("wb") as f:
        f.write(ti.tobuf())
        f.truncate((64 << 20) + 2048)
    fd = os.open(p, os.O_RDONLY)
    try:
        a = Archive(fd, deadline=time.monotonic() + 1, cancel=lambda: False)
        assert a.reasons == {"max_metadata"} and a.entries == []
    finally:
        os.close(fd)


def test_compressed_archive_explicit_unsupported_and_cancel(tmp_path):
    for arc in archive(tmp_path, b"\x1f\x8b" + b"\x00" * 1024):
        assert arc.reasons == {"unsupported_archive_compression"}
    p = tmp_path / "cancel.zip"
    p.write_bytes(zip_bytes([("file", b"abc")]))
    fd = os.open(p, os.O_RDONLY)
    try:
        a = Archive(fd, deadline=time.monotonic() + 10, cancel=lambda: True)
        assert a.reasons == {"cancelled"}
    finally:
        os.close(fd)
