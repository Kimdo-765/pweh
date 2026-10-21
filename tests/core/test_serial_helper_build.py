"""합성 PE와 릴리스 자료로 정적 검사·핀 결속을 검증한다."""
from __future__ import annotations

import copy
import importlib.util
import json
from pathlib import Path
import struct

import pytest

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("pweh_serial_build_test", ROOT / "scripts/build_serial_helper.py")
B = importlib.util.module_from_spec(spec)
spec.loader.exec_module(B)


def synthetic_pe() -> bytes:
    """실행하지 않는 AMD64 fixture: imports는 명세상 정확한 집합, code는 RET 하나다."""
    data = bytearray(8192)
    data[:2] = b"MZ"; struct.pack_into("<I", data, 60, 128)
    data[128:132] = b"PE\0\0"
    struct.pack_into("<HHIIIHH", data, 132, 0x8664, 3, 0, 0, 0, 240, 0x22)
    opt = 152
    struct.pack_into("<H", data, opt, 0x20B)
    struct.pack_into("<I", data, opt + 16, 0x1000)
    struct.pack_into("<I", data, opt + 60, 512)
    struct.pack_into("<HH", data, opt + 68, 3, 0x160)
    struct.pack_into("<I", data, opt + 108, 16)
    struct.pack_into("<II", data, opt + 112 + 8, 0x2000, 40)
    struct.pack_into("<II", data, opt + 112 + 8 * 12, 0x2300, 8 * (len(B.ALLOWED_IMPORTS) + 1))
    for i, (name, rva, raw, size, flags) in enumerate([
        (b".text", 0x1000, 512, 512, 0x60000020),
        (b".rdata", 0x2000, 1024, 4096, 0x40000040),
        (b".pweh", 0x4000, 5120, 512, 0x40000040),
    ]):
        struct.pack_into("<8sIIIIIIHHI", data, opt + 240 + i * 40, name, size, rva, size, raw, 0, 0, 0, 0, flags)
    data[512] = 0xC3
    struct.pack_into("<IIIII", data, 1024, 0x2100, 0, 0, 0x2050, 0x2300)
    data[1104:1117] = b"KERNEL32.dll\0"
    pos = 0x2500
    for i, function in enumerate(sorted(B.ALLOWED_IMPORTS)):
        struct.pack_into("<Q", data, 1024 + 0x100 + 8 * i, pos)
        struct.pack_into("<Q", data, 1024 + 0x300 + 8 * i, pos)
        encoded = function.encode() + b"\0"
        start = 1024 + pos - 0x2000
        data[start + 2:start + 2 + len(encoded)] = encoded
        pos += len(encoded) + 2
    data[5120:5160] = b"PWEHWIN1" + bytes.fromhex("ab" * 20) + bytes((0,1,0,1,0,0,64,0,0,0,0,0))
    return bytes(data)


def test_synthetic_pe_and_four_byte_normalization():
    data = bytearray(synthetic_pe()); pe = 128
    assert B.check_pe(bytes(data))["source_commit"] == "ab" * 20
    struct.pack_into("<I", data, pe + 8, 12345)
    with pytest.raises(B.BuildError, match="timestamp"):
        B.check_pe(bytes(data))
    normalized = B.normalize_pe(bytes(data))
    assert normalized == synthetic_pe()


@pytest.mark.parametrize("mutate", [
    lambda d: struct.pack_into("<H", d, 132, 0x14C),
    lambda d: struct.pack_into("<H", d, 152 + 70, 0),
    lambda d: struct.pack_into("<II", d, 152 + 112 + 13 * 8, 0x2000, 40),
    lambda d: struct.pack_into("<Q", d, 1024 + 0x100, 1 << 63),
    lambda d: d.__setitem__(slice(1104,1117), b"WS2_32.dll\0\0\0"),
    lambda d: struct.pack_into("<I", d, 152 + 240 + 40 + 20, 512),
    lambda d: d.__setitem__(5120, 0),
    lambda d: d.__setitem__(slice(7000,7006), b"/home/"),
])
def test_pe_rejects_incomplete_or_dangerous_metadata(mutate):
    data = bytearray(synthetic_pe()); mutate(data)
    with pytest.raises(B.BuildError):
        B.check_pe(bytes(data))


def release_fixture(root):
    for name in B.INPUTS:
        p = root / name; p.parent.mkdir(parents=True, exist_ok=True); p.write_text("synthetic input " + name)
    pin = root / "src/pweh/winserial/pin.py"; pin.parent.mkdir(parents=True)
    data = synthetic_pe(); report = B.check_pe(data); digest = B.sha(data); commit = "ab" * 20
    pin.write_text(f'PINNED_SHA256 = "{digest}"\nEXPECTED_SOURCE_COMMIT = "{commit}"\nHELPER_VERSION=(0,1,0)\nPROTOCOL_VERSION=(1,0)\n')
    hashes = {k:B.sha(v) for k,v in B.inputs_at(root).items()}
    zig = {"version": B.ZIG_VERSION, "archive_sha256": B.ZIG_ARCHIVE_SHA256}
    runs = [{"schema":"pweh.winserial-build-run/v1", "run_id": ch*32, "preliminary":False,
             "source_commit":commit, "sha256":digest, "raw_sha256":digest, "inputs":hashes,
             "zig":zig, "flags":list(B.FLAGS), "normalization":"coff-timestamp-zero-4bytes", "pe":report}
            for ch in "12"]
    lock = {"schema":"pweh.winserial-build/v1", "inputs":hashes, "zig":zig, "flags":list(B.FLAGS),
            "artifact":{"source_commit":commit, "sha256":digest, "runs":2,"reproducibility":"matched", "builds":runs}}
    (root / B.LOCK).write_text(json.dumps(lock))
    (root / "tools/winserial/SHA256SUMS").write_text(f"{digest}  pweh-serial-helper.exe\n")
    binary = root / B.REL_BINARY; binary.parent.mkdir(); binary.write_bytes(data)
    return lock


def test_release_exact_runtime_pin_inputs_and_binary(tmp_path):
    release_fixture(tmp_path)
    assert B.verify_release(tmp_path)["status"] == "verified"
    (tmp_path / B.INPUTS[0]).write_text("changed")
    with pytest.raises(B.BuildError, match="inputs"):
        B.verify_release(tmp_path)


@pytest.mark.parametrize("kind", ["unprepared", "digest", "source", "runs", "preliminary", "duplicate"])
def test_release_rejects_bad_build_evidence(tmp_path, kind):
    lock = release_fixture(tmp_path)
    if kind == "unprepared": lock["artifact"] = None
    elif kind == "digest": lock["artifact"]["sha256"] = "0" * 64
    elif kind == "source": lock["artifact"]["source_commit"] = "0" * 40
    elif kind == "runs": lock["artifact"]["runs"] = 1
    elif kind == "preliminary": lock["artifact"]["builds"][0]["preliminary"] = True
    else: lock["artifact"]["builds"][1] = copy.deepcopy(lock["artifact"]["builds"][0])
    (tmp_path / B.LOCK).write_text(json.dumps(lock))
    with pytest.raises(B.BuildError):
        B.verify_release(tmp_path)


def test_static_verifier_does_not_execute_binary_or_open_symlink(tmp_path):
    release_fixture(tmp_path)
    binary = tmp_path / B.REL_BINARY
    target = tmp_path / "not-the-helper.exe"; binary.rename(target); binary.symlink_to(target)
    with pytest.raises(OSError):
        B.verify_release(tmp_path)


def test_source_stage_is_explicitly_unprepared():
    lock = json.loads((ROOT / B.LOCK).read_text())
    if lock["artifact"] is not None:
        pytest.skip("artifact R에서는 release 검증 시험을 사용")
    with pytest.raises(B.BuildError, match="미준비"):
        B.verify_release(ROOT)
