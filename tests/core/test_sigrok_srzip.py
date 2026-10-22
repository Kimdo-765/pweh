"""합성 srzip만으로 동일 fd 검사·CRC·상한·원문 비노출 경계를 확인한다."""

from dataclasses import replace
import io
import json
import os
import stat
import struct
import time
import zipfile
import zlib

import pytest

from pweh import sigrok_srzip as S
from pweh.sigrok_capture import CaptureCommand, PROFILE_ID, normalize_channels


def command(**changes):
    values = dict(profile_id=PROFILE_ID, conn="COM31", samplerate_hz=3_000_000,
                  samples=12, channels=normalize_channels(["0=RX", "1"]))
    return CaptureCommand(**(values | changes))


def metadata(c=None, **changes):
    c = c or command()
    data = {"capturefile": "logic-1", "total probes": "32", "samplerate": "3.030303 MHz",
            "total analog": "0", "unitsize": "4"}
    data.update({f"probe{ch.index + 1}": ch.name for ch in c.channels})
    data.update(changes)
    return ("[global]\nsigrok version=0.5.2\n\n[device 1]\n"
            + "".join(f"{key}={value}\n" for key, value in data.items())).encode()


def archive(*, c=None, meta=None, data=None, chunks=None, extras=(), compression=zipfile.ZIP_DEFLATED,
            descriptor=False, version=b"2"):
    class Nonseekable(io.BytesIO):
        def seek(self, *args):
            raise io.UnsupportedOperation()
    output = Nonseekable() if descriptor else io.BytesIO()
    if chunks is None:
        chunks = [("logic-1-1", data if data is not None else b"\0\0\0\0" * 12)]
    with zipfile.ZipFile(output, "w", compression=compression) as z:
        z.writestr("metadata", metadata(c) if meta is None else meta)
        for name, payload in chunks:
            z.writestr(name, payload)
        z.writestr("version", version)
        for name, payload in extras:
            z.writestr(name, payload)
    return output.getvalue()


def inspect(tmp_path, raw=None, *, c=None, **kwargs):
    path = tmp_path / "capture.sr"
    path.write_bytes(archive() if raw is None else raw)
    with path.open("rb") as f:
        return S.inspect_capture_fd(f.fileno(), size=path.stat().st_size, command=c or command(),
                                    deadline=time.monotonic() + 30, **kwargs)


@pytest.mark.parametrize("compression", [zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED])
@pytest.mark.parametrize("descriptor", [False, True])
def test_complete_crc_fixed_metadata_roundtrip(tmp_path, compression, descriptor):
    raw = archive(compression=compression, descriptor=descriptor)
    result = inspect(tmp_path, raw)
    assert result.samples == 12 and result.samplerate_hz == 3_030_303
    assert result.unitsize == 4 and result.crc_verified and result.entries == 3
    assert result.logic_bytes == 48 and result.archive_bytes == len(raw)
    assert result.notes == ("rate_quantized",) and result.activity_complete
    value = result.to_dict()
    assert "path" not in value and "metadata" not in value
    assert len(json.dumps(value).encode()) < 16 * 1024


def test_same_fd_offset_no_reopen_and_borrowed_lifetime(tmp_path, monkeypatch):
    path = tmp_path / "capture.sr"
    path.write_bytes(archive())
    with path.open("rb") as f:
        fd = f.fileno()
        os.lseek(fd, 7, os.SEEK_SET)
        with monkeypatch.context() as m:
            m.setattr(os, "open", lambda *a, **k: pytest.fail("경로 재open 금지"))
            result = S.inspect_capture_fd(fd, size=path.stat().st_size, command=command(), deadline=time.monotonic() + 30)
        assert result.crc_verified and os.lseek(fd, 0, os.SEEK_CUR) == 7
        assert os.pread(fd, 2, 0) == b"PK"


def test_numeric_chunk_order_streamed_activity_and_prefix_limit(tmp_path):
    samples = [0, 1, 3, 2, 0, 1, 3, 2, 0, 1, 3, 2]
    chunks = [(f"logic-1-{i+1}", struct.pack("<I", n)) for i, n in enumerate(samples)]
    raw = archive(chunks=list(reversed(chunks)))
    result = inspect(tmp_path, raw, limits=replace(S.CaptureZipLimits(), max_activity_channel_samples=10, block_bytes=4))
    assert result.samples == 12 and result.activity_samples == 5 and not result.activity_complete
    assert result.activity_reason == "activity_limit" and result.crc_verified
    for ch, activity in zip(command().channels, result.activity):
        bits = [(n >> ch.index) & 1 for n in samples[:5]]
        assert activity.edges == sum(a != b for a, b in zip(bits, bits[1:]))
        assert activity.high_count == sum(bits)
        assert activity.initial_level == bits[0] and activity.final_level == bits[-1]


def test_shortfall_and_full_channel_output_bound(tmp_path):
    result = inspect(tmp_path, archive(data=b"\0" * 16))
    assert result.samples == 4 and result.notes == ("rate_quantized", "fewer_samples")
    c = command(channels=normalize_channels([f"{i}=" + chr(65+i%26) * 30 + str(i % 10) for i in range(32)]))
    result = inspect(tmp_path, archive(c=c), c=c)
    assert len(result.channels) == 32 and len(json.dumps(result.to_dict()).encode()) <= 16 * 1024


@pytest.mark.parametrize("changes", [{"unitsize": "1"}, {"unitsize": "0"}, {"total probes": "1"},
    {"total probes": "33"}, {"total analog": "1"}, {"capturefile": "secret/path"},
    {"samplerate": "3 MHz"}, {"samplerate": "3.0303031 MHz"}, {"samplerate": "1e100 Hz"},
    {"probe1": "secret/private"}, {"probe3": "2"}])
def test_metadata_must_match_profile_request_without_raw_values(tmp_path, changes):
    with pytest.raises(S.CaptureZipError) as exc:
        inspect(tmp_path, archive(meta=metadata(**changes)))
    assert exc.value.code == "sigrok_capture_metadata_mismatch"
    assert "secret" not in json.dumps(exc.value.to_dict())


@pytest.mark.parametrize("meta", [metadata() + b"probe1=RX\n", metadata() + b"[device 1]\n",
    metadata().replace(b"[device 1]", b"[device 2]"), metadata() + b"secret=private/path\n",
    metadata() + b"\xff", metadata() + b"\x00", metadata().replace(b"unitsize=4\n", b"")])
def test_bad_or_unknown_metadata_is_fixed_error(tmp_path, meta):
    with pytest.raises(S.CaptureZipError) as exc:
        inspect(tmp_path, archive(meta=meta))
    assert exc.value.code in ("sigrok_capture_metadata_mismatch", "sigrok_capture_unsupported")
    assert "secret" not in str(exc.value) and "private" not in str(exc.value)


@pytest.mark.parametrize("kwargs", [{"version": b"1"}, {"version": b"2\n"},
    {"extras": [("secret/private", b"data")]}, {"chunks": [("logic-1-2", b"\0" * 16)]},
    {"chunks": [("logic-1", b"\0" * 16), ("logic-1-1", b"\0" * 16)]},
    {"data": b"\0" * 49}, {"data": b"\0" * 52}])
def test_unsupported_names_gaps_version_alignment_and_excess_samples(tmp_path, kwargs):
    with pytest.raises(S.CaptureZipError):
        inspect(tmp_path, archive(**kwargs))


def test_crc_failure_after_activity_prefix_is_still_rejected(tmp_path):
    raw = bytearray(archive(compression=zipfile.ZIP_STORED))
    with zipfile.ZipFile(io.BytesIO(raw)) as z:
        info = z.getinfo("logic-1-1")
    data_offset = info.header_offset + 30 + len(info.filename)
    raw[data_offset + 44] ^= 1
    with pytest.raises(S.CaptureZipError, match="sigrok_capture_bad_zip"):
        inspect(tmp_path, raw, limits=replace(S.CaptureZipLimits(), max_activity_channel_samples=1))


def test_deflate_actual_size_cannot_hide_behind_smaller_declared_size_and_crc(tmp_path):
    raw = bytearray(archive())
    with zipfile.ZipFile(io.BytesIO(raw)) as z:
        info = z.getinfo("logic-1-1")
    crc = zlib.crc32(b"\0" * 16)
    struct.pack_into("<I", raw, info.header_offset + 14, crc)
    struct.pack_into("<I", raw, info.header_offset + 22, 16)
    central = raw.find(b"PK\x01\x02")
    while raw[central+46:central+46+len(info.filename)] != info.filename.encode():
        central = raw.find(b"PK\x01\x02", central + 4)
    struct.pack_into("<I", raw, central + 16, crc)
    struct.pack_into("<I", raw, central + 24, 16)
    with pytest.raises(S.CaptureZipError, match="sigrok_capture_(?:bad_zip|limit)"):
        inspect(tmp_path, raw)


def test_deflate_must_reach_stream_end_even_when_archive_headers_are_complete(tmp_path):
    raw = bytearray(archive())
    with zipfile.ZipFile(io.BytesIO(raw)) as z:
        info = z.getinfo("logic-1-1")
    struct.pack_into("<I", raw, info.header_offset + 18, info.compress_size - 1)
    central = raw.find(b"PK\x01\x02")
    while raw[central+46:central+46+len(info.filename)] != info.filename.encode():
        central = raw.find(b"PK\x01\x02", central + 4)
    struct.pack_into("<I", raw, central + 20, info.compress_size - 1)
    with pytest.raises(S.CaptureZipError, match="sigrok_capture_bad_zip"):
        inspect(tmp_path, raw)


@pytest.mark.parametrize("field,limit", [("max_archive_bytes", 20), ("max_entries", 2),
    ("max_central_bytes", 20), ("max_metadata_bytes", 16), ("max_uncompressed_bytes", 16),
    ("max_logic_bytes", 16), ("max_metadata_lines", 2), ("max_line_bytes", 10),
    ("max_name_bytes", 3), ("max_output_bytes", 32)])
def test_resource_bounds(tmp_path, field, limit):
    with pytest.raises(S.CaptureZipError, match="sigrok_capture_limit"):
        inspect(tmp_path, limits=replace(S.CaptureZipLimits(), **{field: limit}))


def test_entry_limit_preflight_before_zipfile_object_allocation(tmp_path, monkeypatch):
    raw = bytearray(archive())
    pos = raw.rfind(b"PK\x05\x06")
    struct.pack_into("<HH", raw, pos + 8, 5000, 5000)
    monkeypatch.setattr(S.zipfile, "ZipFile", lambda *a, **k: pytest.fail("preflight 전에 ZIP 객체 생성 금지"))
    with pytest.raises(S.CaptureZipError, match="sigrok_capture_limit"):
        inspect(tmp_path, raw)


@pytest.mark.parametrize("change", ["truncated", "trailing", "multi_disk", "zip64", "encrypted", "overlap"])
def test_zip_structure_boundaries(tmp_path, change):
    raw = bytearray(archive())
    end = raw.rfind(b"PK\x05\x06")
    central = raw.find(b"PK\x01\x02")
    if change == "truncated":
        raw = raw[:-1]
    elif change == "trailing":
        raw += b"secret/private"
    elif change == "multi_disk":
        struct.pack_into("<H", raw, end + 4, 1)
    elif change == "zip64":
        struct.pack_into("<I", raw, end + 12, 0xffffffff)
    elif change == "encrypted":
        struct.pack_into("<H", raw, central + 8, 1)
    else:
        second = raw.find(b"PK\x01\x02", central + 4)
        struct.pack_into("<I", raw, second + 42, 0)
    with pytest.raises(S.CaptureZipError) as exc:
        inspect(tmp_path, raw)
    assert exc.value.code in ("sigrok_capture_bad_zip", "sigrok_capture_unsupported")


def test_symlink_member_and_duplicate_name(tmp_path):
    link = zipfile.ZipInfo("logic-1-1")
    link.create_system = 3
    link.external_attr = (stat.S_IFLNK | 0o777) << 16
    with pytest.raises(S.CaptureZipError, match="sigrok_capture_unsupported"):
        inspect(tmp_path, archive(chunks=[(link, b"data")]))
    with pytest.warns(UserWarning):
        raw = archive(extras=[("metadata", metadata())])
    with pytest.raises(S.CaptureZipError, match="sigrok_capture_bad_zip"):
        inspect(tmp_path, raw)


def test_fd_change_callback_errors_cancel_and_deadline(tmp_path):
    raw = archive()
    path = tmp_path / "capture.sr"
    path.write_bytes(raw)
    with path.open("r+b") as f:
        fd = f.fileno()
        def changed():
            os.pwrite(fd, b"X", 0)
        with pytest.raises(S.CaptureZipError, match="sigrok_capture_check_failed"):
            S.inspect_capture_fd(fd, size=len(raw), command=command(), deadline=time.monotonic()+10, check=changed)
    def private_error():
        raise S.CaptureZipError("secret/private")
    for key, callback in (("check", private_error), ("cancel", lambda: "secret")):
        with pytest.raises(S.CaptureZipError) as exc:
            inspect(tmp_path, raw, **{key: callback})
        assert exc.value.code == "sigrok_capture_check_failed" and "secret" not in str(exc.value)
    with pytest.raises(S.CaptureZipError, match="sigrok_capture_cancelled"):
        inspect(tmp_path, raw, cancel=lambda: True)
    with path.open("rb") as f:
        with pytest.raises(S.CaptureZipError, match="sigrok_capture_timeout"):
            S.inspect_capture_fd(f.fileno(), size=len(raw), command=command(), deadline=time.monotonic()-1)


@pytest.mark.parametrize("deadline", [None, True, "10", float("nan"), float("inf"), 10**400])
def test_bad_deadline_never_leaks_builtin_errors(tmp_path, deadline):
    path = tmp_path / "capture.sr"
    path.write_bytes(archive())
    with path.open("rb") as f, pytest.raises(S.CaptureZipError, match="sigrok_capture_invalid"):
        S.inspect_capture_fd(f.fileno(), size=path.stat().st_size, command=command(), deadline=deadline)


def test_empty_result_requires_fd_identity_and_zero_sample_is_not_artifact(tmp_path):
    with pytest.raises(S.CaptureZipError, match="sigrok_capture_empty"):
        inspect(tmp_path, b"")
    with pytest.raises(S.CaptureZipError, match="sigrok_capture_empty"):
        inspect(tmp_path, archive(data=b""))
    path = tmp_path / "capture.sr"
    path.write_bytes(archive())
    with path.open("rb") as f:
        with pytest.raises(S.CaptureZipError, match="sigrok_capture_check_failed"):
            S.inspect_capture_fd(f.fileno(), size=0, command=command(), deadline=time.monotonic()+10)


def test_lowered_limits_are_valid_but_cannot_expand_or_be_boolean(tmp_path):
    for limit in (replace(S.CaptureZipLimits(), max_archive_bytes=65*1024*1024),
                  replace(S.CaptureZipLimits(), block_bytes=3),
                  replace(S.CaptureZipLimits(), max_entries=True)):
        with pytest.raises(S.CaptureZipError, match="sigrok_capture_invalid"):
            inspect(tmp_path, limits=limit)
