"""fwtriage-mcp 단위 테스트: 해시, 시그니처 검증, ELF, 패턴 로더, mtdparts, rootfs 경로 해석, 프로세스 실행."""

from __future__ import annotations

import bz2
import gzip
import hashlib
import lzma
import os
import random
import re
import string
import struct
import subprocess
import sys
import threading
import time
import warnings
import zlib
from pathlib import Path

from pweh.toolsdir import tools_dir

import pytest

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "mcp-servers" / "fwtriage-mcp"))

from fwtriage.builders import (  # noqa: E402
    build_min_elf,
    find_tool,
    jffs2_image,
    strip_section_headers,
    ubi_crc,
    ubi_image,
    zig_build,
)
from fwtriage_mcp import elfinfo, hashes  # noqa: E402
from fwtriage_mcp.common import Cancelled, Ctl  # noqa: E402
from fwtriage_mcp.fswalk import resolve_in_root  # noqa: E402
from fwtriage_mcp.hunt import RootfsLocator, hunt  # noqa: E402
from fwtriage_mcp.patterns import custom_id, glob_to_regex, load_default_passwords, load_patterns, required_literals  # noqa: E402
from fwtriage_mcp.procutil import run_process  # noqa: E402
from fwtriage_mcp.signatures import (  # noqa: E402
    ScanCtx,
    find_env_blocks,
    jffs2_crc,
    padding_runs,
    parse_squashfs_superblock,
    scan_regions,
    xxh32,
)
from fwtriage_mcp.squashfs import check_listing, mode_from_ls, parse_listing  # noqa: E402
from fwtriage_mcp.uboot import parse_mtd, resolve_layout  # noqa: E402

with warnings.catch_warnings():
    warnings.simplefilter("ignore", DeprecationWarning)
    try:
        import crypt as _crypt  # type: ignore
    except Exception:  # pragma: no cover
        _crypt = None

ALPHA = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"


def scan(data: bytes, **kw):
    ctx = ScanCtx(Ctl(max_seconds=120))
    return scan_regions(data, 0, len(data), ctx, **kw), ctx


def kinds_at(regions):
    return {(r.offset, r.kind) for r in regions}


# ---------------------------------------------------------------------------
# 해시
# ---------------------------------------------------------------------------


def test_md5crypt_known_vectors():
    # Kojenov (cctv-vuln-patterns.md 부록 B): J-Tech 인코더 root 해시 = neworangetech
    assert hashes.md5_crypt("neworangetech", "/5bWggz/") == "$1$/5bWggz/$JkbAnqFTv7HwEWr3DFJiC0"
    # passlib 문서 예시 벡터
    assert hashes.md5_crypt("password", "3azHgidD") == "$1$3azHgidD$SrJPt7B.9rekpmwJwtON31"
    # salt 는 8자로 잘리고 '$' 에서 끝난다
    assert hashes.md5_crypt("x", "abcdefghijkl") == hashes.md5_crypt("x", "abcdefgh")
    assert hashes.md5_crypt("x", "abc$def") == hashes.md5_crypt("x", "abc")


def test_des_crypt_known_vectors():
    assert hashes.des_encrypt_block(0x133457799BBCDFF1, 0x0123456789ABCDEF) == 0x85E813540F0AB405  # 표준 DES 벡터
    assert hashes.des_crypt("xc3511", "ab") == "absxcfbgXtb3o"  # tothi: XiongMai root
    assert hashes.des_crypt("unisheen", "9y") == "9yVwSCpfKcYJg"  # Kojenov
    assert hashes.des_crypt("neworang", "qi") == "qiYX370VaJ3u."  # YAML known-hash-hienc-root-neworang
    # 앞 8자만 유효
    assert hashes.des_crypt("neworange88888888", "qi") == "qiYX370VaJ3u."


def test_sha_crypt_spec_vectors():
    assert hashes.sha_crypt("Hello world!", "saltstring", None, "5") == "$5$saltstring$5B8vYYiY.CVt1RlTTf8KbXBH3hsxY/GNooZaBBGWEc5"
    assert hashes.sha_crypt("Hello world!", "saltstring", None, "6") == (
        "$6$saltstring$svn8UoSVapNtMuq1ukKS4tPQd8iKwSMHWjl/O817G3uBnIFNjnQJuesI68u4OTLiBFdcbYEdFCoEOfaS35inz1"
    )
    h = hashes.sha_crypt("pw", "abc", 1234, "6")
    assert h.startswith("$6$rounds=1234$abc$")
    assert hashes.check_password("sha512crypt", h, "pw", prefer_crypt_module=False) is True
    assert hashes.check_password("sha512crypt", h, "nope", prefer_crypt_module=False) is False


def test_sofia_hash_empty_password():
    assert hashes.sofia_hash("") == "tlJwpbo6"  # tothi / NVD CVE-2022-45045
    assert re.fullmatch(r"[0-9A-Za-z]{8}", hashes.sofia_hash("admin"))


@pytest.mark.skipif(_crypt is None, reason="crypt 모듈 없음 (Python 3.13+)")
def test_crypt_crosscheck_random():
    rnd = random.Random(20261018)
    for _ in range(150):
        n = rnd.choice([0, 1, 7, 8, 9, 15, 16, 17, 31, 64])
        pw = "".join(rnd.choice(string.printable[:94]) for _ in range(n))
        salt = "".join(rnd.choice(ALPHA) for _ in range(rnd.choice([0, 1, 2, 5, 8, 9])))
        assert hashes.md5_crypt(pw, salt) == _crypt.crypt(pw, "$1$" + salt + "$")
        s2 = "".join(rnd.choice(ALPHA) for _ in range(2))
        assert hashes.des_crypt(pw, s2) == _crypt.crypt(pw, s2)
    for pw in ("비밀번호", "pässwörd", "ÿþ"):
        assert hashes.md5_crypt(pw, "abcdefgh") == _crypt.crypt(pw, "$1$abcdefgh$")
        assert hashes.des_crypt(pw, "Zz") == _crypt.crypt(pw, "Zz")
    for v in "56":
        for rounds in (None, 1000, 5001):
            setting = f"${v}$" + (f"rounds={rounds}$" if rounds else "") + "Salt.Salt/1234"
            assert hashes.sha_crypt("pass word", "Salt.Salt/1234", rounds, v) == _crypt.crypt("pass word", setting)


@pytest.mark.external
def test_apr1_against_openssl():
    openssl = find_tool("PWEH_OPENSSL", "openssl")
    if not openssl:
        pytest.skip("openssl 없음")
    out = subprocess.run([openssl, "passwd", "-apr1", "-salt", "Qs0x3V1r", "secret"], capture_output=True, text=True, timeout=10)
    if out.returncode != 0 or not out.stdout.startswith("$apr1$"):
        pytest.skip("openssl 이 apr1 을 지원하지 않음")
    assert hashes.md5_crypt("secret", "Qs0x3V1r", "$apr1$") == out.stdout.strip()


def test_identify_hash():
    assert hashes.identify_hash("")["algorithm"] == "empty"
    assert hashes.identify_hash("x")["algorithm"] == "locked"
    assert hashes.identify_hash("*")["algorithm"] == "locked"
    assert hashes.identify_hash("absxcfbgXtb3o")["algorithm"] == "des"
    assert hashes.identify_hash("$1$abc$" + "a" * 22)["algorithm"] == "md5crypt"
    i = hashes.identify_hash("!$6$salt$" + "b" * 86)
    assert i["algorithm"] == "sha512crypt" and i["locked"] is True
    assert hashes.identify_hash("$2b$10$" + "c" * 53)["algorithm"] == "bcrypt"
    assert hashes.identify_hash("$y$j9T$abc$def")["algorithm"] == "yescrypt"
    assert hashes.identify_hash(hashlib.md5(b"a").hexdigest())["algorithm"] == "md5-hex"
    assert hashes.identify_hash("tlJwpbo6")["algorithm"] == "xm-sofia?"
    assert hashes.identify_hash("tlJwpbo6", "xm-sofia")["algorithm"] == "xm-sofia"


def test_crack_entries_statuses():
    entries = [
        {"user": "root", "hash": "absxcfbgXtb3o"},
        {"user": "user", "hash": "$1$/5bWggz/$JkbAnqFTv7HwEWr3DFJiC0"},
        {"user": "admin", "hash": ""},
        {"user": "daemon", "hash": "*"},
        {"user": "xm", "hash": "tlJwpbo6", "hint": "xm-sofia"},
        {"user": "web", "hash": hashlib.md5(b"888888").hexdigest()},
        {"user": "strong", "hash": hashes.md5_crypt("Q9!very-unlikely-pass", "saltsalt")},
        {"user": "odd", "hash": "zz$$unknown"},
    ]
    words, _ = load_default_passwords()
    known = load_patterns().known_hashes
    res = {r["user"]: r for r in hashes.crack_entries(entries, words, deadline=time.monotonic() + 60, known_hashes=known)}
    assert res["root"]["status"] == "cracked" and res["root"]["password"] == "xc3511"
    assert res["root"]["known_hash"]["id"] == "known-hash-xm-root-xc3511"
    assert res["user"]["status"] == "cracked" and res["user"]["password"] == "neworangetech"
    assert res["admin"]["status"] == "empty"
    assert res["daemon"]["status"] == "not_checked"
    assert res["xm"]["status"] == "cracked" and res["xm"]["password"] == ""
    assert res["web"]["status"] == "cracked" and res["web"]["password"] == "888888"
    assert res["strong"]["status"] == "not_cracked" and res["strong"]["candidates_tried"] > 50
    assert res["odd"]["status"] == "not_checked"
    # 시간 예산
    slow = [{"user": "s", "hash": hashes.sha_crypt("zzz-not-in-list", "abcd", 50000, "6")}]
    r = hashes.crack_entries(slow, words, deadline=time.monotonic() + 0.3)
    assert r[0]["status"] in ("partial", "not_cracked")


def test_default_password_file_has_sources():
    p = REPO / "src" / "pweh" / "data" / "default-passwords.txt"
    text = p.read_text(encoding="utf-8")
    assert "SecLists" in text and "cctv-vuln-patterns.md" in text
    words, _ = load_default_passwords()
    for w in ("xc3511", "xmhdipc", "vizxv", "888888", "unisheen", "neworangetech", "tluafed"):
        assert w in words
    assert len(words) < 1000  # '작은' 내장 사전


# ---------------------------------------------------------------------------
# 시그니처
# ---------------------------------------------------------------------------


def test_random_data_has_no_false_positives():
    data = random.Random(7).randbytes(16 << 20)
    regions, ctx = scan(data)
    assert regions == [], [(hex(r.offset), r.kind, r.description) for r in regions]


def test_compressed_streams_exact_sizes():
    rnd = random.Random(1)
    payload = b"camera firmware text block " * 3000 + rnd.randbytes(5000)
    gz = gzip.compress(payload, mtime=0)
    xz = lzma.compress(payload, format=lzma.FORMAT_XZ)
    lz = lzma.compress(payload, format=lzma.FORMAT_ALONE)
    bz = bz2.compress(payload)
    blob = bytearray(rnd.randbytes(0x1000))
    offs = {}
    for name, b in (("gzip", gz), ("xz", xz), ("lzma", lz), ("bzip2", bz)):
        offs[name] = len(blob)
        blob += b + rnd.randbytes(0x777)
    regions, _ = scan(bytes(blob))
    by = {r.kind: r for r in regions}
    assert by["gzip"].offset == offs["gzip"] and by["gzip"].size == len(gz)
    assert by["xz"].offset == offs["xz"] and by["xz"].size == len(xz)
    assert by["lzma"].offset == offs["lzma"] and by["lzma"].size == len(lz)
    assert by["bzip2"].offset == offs["bzip2"] and by["bzip2"].size == len(bz)
    assert by["gzip"].details["decompressed_bytes"] == len(payload)
    # 손상된 gzip(가운데 바이트 변경)은 거부
    bad = bytearray(gz)
    bad[len(bad) // 2] ^= 0xFF
    r2, _ = scan(bytes(rnd.randbytes(100)) + bytes(bad))
    assert not any(r.kind == "gzip" and r.confidence == "high" for r in r2)


def test_zstd_and_lz4_handbuilt_frames():
    data = b"Z" * 200  # single-segment + FCS 1바이트(0~255)
    # zstd: single segment, 1바이트 FCS, raw 블록 1개(last)
    zstd = b"\x28\xb5\x2f\xfd" + bytes([0x20]) + bytes([len(data)]) + (1 | (0 << 1) | (len(data) << 3)).to_bytes(3, "little") + data
    # lz4 frame: FLG=0x60(버전 01, 블록 독립), BD=0x40(64KB), 비압축 블록 + EndMark
    desc = bytes([0x60, 0x40])
    lz4 = b"\x04\x22\x4d\x18" + desc + bytes([(xxh32(desc) >> 8) & 0xFF]) + struct.pack("<I", len(data) | 0x80000000) + data + b"\0\0\0\0"
    blob = os.urandom(512) + zstd + os.urandom(333) + lz4 + os.urandom(100)
    regions, _ = scan(blob)
    by = {r.kind: r for r in regions}
    assert by["zstd"].offset == 512 and by["zstd"].size == len(zstd)
    assert by["lz4"].offset == 512 + len(zstd) + 333 and by["lz4"].size == len(lz4)
    # 헤더 체크섬이 틀린 lz4 는 거부
    bad = bytearray(lz4)
    bad[6] ^= 0x55
    r2, _ = scan(os.urandom(64) + bytes(bad))
    assert not any(r.kind == "lz4" for r in r2)


def test_xxh32_vectors():
    assert xxh32(b"") == 0x02CC5D05
    assert xxh32(b"", 1) != xxh32(b"")


@pytest.mark.external
def test_lz4_cli_frame_detected(tmp_path):
    lz4 = find_tool("PWEH_LZ4", "lz4") or (str(tools_dir() / "extractors" / "bin" / "lz4") if (tools_dir() / "extractors" / "bin" / "lz4").exists() else None)
    if not lz4:
        pytest.skip("lz4 CLI 없음")
    src = tmp_path / "in.bin"
    src.write_bytes(b"lz4 frame test " * 20000 + os.urandom(1000))
    out = tmp_path / "in.bin.lz4"
    res = subprocess.run([lz4, "-q", "-f", str(src), str(out)], capture_output=True, timeout=30)
    if res.returncode != 0 or not out.exists():
        pytest.skip("lz4 실행 실패")
    frame = out.read_bytes()
    regions, _ = scan(os.urandom(100) + frame + os.urandom(50))
    lz = [r for r in regions if r.kind == "lz4"]
    assert lz and lz[0].offset == 100 and lz[0].size == len(frame)


def test_uimage_crc_validation_and_payload_nesting():
    from pweh.formats import build_uimage_header

    payload = gzip.compress(os.urandom(2000) + b"A" * 5000, mtime=0)
    hdr = build_uimage_header(payload, name="Linux-4.9.37", load=0x80008000, entry=0x80008000, arch="mips", comp="gzip")
    blob = b"\xff" * 1024 + hdr + payload + b"\xff" * 1024
    regions, _ = scan(blob)
    ui = [r for r in regions if r.kind == "uimage"][0]
    assert ui.offset == 1024 and ui.size == 64 + len(payload) and ui.details["arch"] == "mips"
    assert ui.details["header_crc_ok"] and ui.details["data_crc_ok"]
    assert ui.details["payload"]["kind"] == "gzip"
    gz = [r for r in regions if r.kind == "gzip"][0]
    assert gz.parent == 1024 and gz.parent_kind == "uimage"
    # 헤더 CRC 가 틀리면 보고하지 않음 (우연한 매직)
    bad = bytearray(blob)
    bad[1024 + 32] ^= 0x01
    r2, _ = scan(bytes(bad))
    assert not any(r.kind == "uimage" for r in r2)
    # 잘린 이미지
    r3, _ = scan(blob[: 1024 + 64 + 100])
    t = [r for r in r3 if r.kind == "uimage"][0]
    assert t.truncated


def _fdt(root_props: dict, children: list) -> bytes:
    """작은 FDT 작성기 (테스트용)."""
    strings = bytearray()
    soff: dict[str, int] = {}

    def sref(n: str) -> int:
        if n not in soff:
            soff[n] = len(strings)
            strings.extend(n.encode() + b"\0")
        return soff[n]

    def node(name: str, props: dict, kids: list) -> bytes:
        out = bytearray(struct.pack(">I", 1) + name.encode() + b"\0")
        out += b"\0" * ((-len(out)) % 4)
        for k, v in props.items():
            if isinstance(v, str):
                v = v.encode() + b"\0"
            elif isinstance(v, int):
                v = struct.pack(">I", v)
            out += struct.pack(">III", 3, len(v), sref(k)) + v + b"\0" * ((-len(v)) % 4)
        for kn, kp, kk in kids:
            out += node(kn, kp, kk)
        out += struct.pack(">I", 2)
        return bytes(out)

    struct_blk = node("", root_props, children) + struct.pack(">I", 9)
    rsv = b"\0" * 16
    off_rsv = 40
    off_struct = off_rsv + len(rsv)
    off_strings = off_struct + len(struct_blk)
    total = off_strings + len(strings)
    hdr = struct.pack(">10I", 0xD00DFEED, total, off_struct, off_strings, off_rsv, 17, 16, 0, len(strings), len(struct_blk))
    return hdr + rsv + struct_blk + bytes(strings)


def test_fit_and_dtb_parsing():
    kernel = os.urandom(3000)
    fit = _fdt(
        {"description": "test FIT", "timestamp": 1700000000},
        [
            ("images", {}, [
                ("kernel-1", {"description": "Linux", "type": "kernel", "arch": "arm", "os": "linux", "compression": "none", "load": 0x80008000, "entry": 0x80008000, "data": kernel},
                 [("hash-1", {"algo": "crc32", "value": struct.pack(">I", zlib.crc32(kernel))}, [])]),
            ]),
            ("configurations", {"default": "conf-1"}, [("conf-1", {"kernel": "kernel-1"}, [])]),
        ],
    )
    dtb = _fdt({"model": "Acme IPC", "compatible": "acme,ipc\0hisilicon,hi3516ev300"},
               [("chosen", {"bootargs": "console=ttyAMA0 mtdparts=hi_sfc:256k(boot),-(rootfs)"}, []),
                ("flash", {}, [("partitions", {}, [("partition@0", {"label": "boot", "reg": b"\0\0\0\0\0\x04\0\0"}, [])])])])
    blob = os.urandom(200) + fit + os.urandom(64) + dtb + os.urandom(64)
    regions, _ = scan(blob)
    f = [r for r in regions if r.kind == "fit"][0]
    assert f.offset == 200 and f.details["images"][0]["data_size"] == 3000 and f.details["images"][0]["arch"] == "arm"
    assert f.details["default_configuration"] == "conf-1"
    d = [r for r in regions if r.kind == "dtb"][0]
    assert d.details["model"] == "Acme IPC" and "mtdparts=" in d.details["bootargs"]
    assert d.details["dt_partitions"] == [{"name": "boot", "offset": 0, "size": 0x40000, "ro": False}]


def test_jffs2_ubi_ubifs_cramfs_romfs_ext_cpio_zimage_pem():
    rnd = random.Random(3)
    parts = []
    j_le = jffs2_image(big=False)
    j_be = jffs2_image(big=True)
    ubi = ubi_image(volume_name="rootfs")
    # UBIFS superblock 노드 (4096 바이트, CRC)
    sb = bytearray(4096)
    struct.pack_into("<IIQIBB", sb, 0, 0x06101831, 0, 1, 4096, 6, 0)
    struct.pack_into("<IIIII", sb, 28, 0, 2048, 0x1F000, 100, 200)
    struct.pack_into("<I", sb, 4, ubi_crc(bytes(sb[8:])))
    # cramfs (flags 1 → CRC 검증)
    cr = bytearray(4096)
    struct.pack_into("<IIII", cr, 0, 0x28CD3D45, 4096, 1, 0)
    cr[16:32] = b"Compressed ROMFS"
    struct.pack_into("<IIII", cr, 36, 0, 1, 3, 0)
    cr[48:64] = b"testcram".ljust(16, b"\0")
    struct.pack_into("<I", cr, 32, zlib.crc32(bytes(cr[:32]) + b"\0\0\0\0" + bytes(cr[36:])) & 0xFFFFFFFF)
    # romfs
    rom = bytearray(1024)
    rom[0:8] = b"-rom1fs-"
    struct.pack_into(">I", rom, 8, 1024)
    rom[16:32] = b"romvol".ljust(16, b"\0")
    s = sum(struct.unpack(">128I", bytes(rom[:512]))) & 0xFFFFFFFF
    struct.pack_into(">I", rom, 12, (-s) & 0xFFFFFFFF)
    # ext2 superblock (블록 1024, 64블록, inode 16, 그룹 1)
    ext = bytearray(64 * 1024)
    sbo = 1024
    struct.pack_into("<13I", ext, sbo, 16, 64, 0, 10, 5, 1, 0, 0, 8192, 8192, 16, 0, 0)
    struct.pack_into("<HHHHH", ext, sbo + 0x34, 0, 20, 0xEF53, 1, 1)
    struct.pack_into("<II", ext, sbo + 0x48, 0, 1)
    ext[sbo + 0x78 : sbo + 0x78 + 8] = b"rootfs\0\0"
    # cpio newc (파일 1개 + TRAILER)
    def cpio_entry(name: str, data: bytes, mode: int = 0o100644) -> bytes:
        nm = name.encode() + b"\0"
        hdr = b"070701" + b"".join(f"{v:08X}".encode() for v in (1, mode, 0, 0, 1, 0, len(data), 0, 0, 0, 0, len(nm), 0))
        out = hdr + nm
        out += b"\0" * ((-len(out)) % 4)
        out += data + b"\0" * ((-len(data)) % 4)
        return out
    cpio = cpio_entry("init", b"#!/bin/sh\n") + cpio_entry("bin/busybox", b"\x7fELF...") + cpio_entry("TRAILER!!!", b"", 0)
    # ARM zImage 헤더
    zi = bytearray(b"\x00\x00\xa0\xe1" * 8 + b"\x00" * 0x200)
    zi[0x24:0x28] = b"\x18\x28\x6f\x01"
    struct.pack_into("<II", zi, 0x28, 0, len(zi))
    struct.pack_into("<I", zi, 0x30, 0x04030201)
    tag = b"EC PRIVATE" + b" KEY"  # 가짜 키: 비밀값 스캐너 오탐을 피하려고 머리글을 이어 붙인다
    pem = b"-----BEGIN " + tag + b"-----\nMHcCAQEE...fake...\n-----END " + tag + b"-----\n"
    layout = []
    blob = bytearray(rnd.randbytes(256))
    for name, b in (("jffs2", j_le), ("jffs2", j_be), ("ubi", ubi), ("ubifs", bytes(sb)), ("cramfs", bytes(cr)), ("romfs", bytes(rom)), ("ext", bytes(ext)), ("cpio", cpio), ("zimage", bytes(zi)), ("pem-private-key", pem)):
        layout.append((len(blob), name, len(b)))
        blob += b + rnd.randbytes(512)
    regions, ctx = scan(bytes(blob))
    found = {(r.offset, r.kind): r for r in regions}
    for off, name, size in layout:
        assert (off, name) in found, (name, hex(off), [(hex(r.offset), r.kind) for r in regions])
    jl = found[(layout[0][0], "jffs2")]
    assert jl.details["endianness"] == "little" and jl.details["nodes"] == 9
    assert found[(layout[1][0], "jffs2")].details["endianness"] == "big"
    u = found[(layout[2][0], "ubi")]
    assert u.details["peb_count"] == 4 and u.details["volumes"][0]["name"] == "rootfs"
    ubifs = found[(layout[3][0], "ubifs")]
    assert ubifs.details["leb_size"] * ubifs.details["leb_count"] == 0x1F000 * 100
    assert ubifs.truncated  # 볼륨 크기 > 남은 데이터: 뒤쪽 영역을 숨기지 않아야 한다 (romfs 등이 모두 발견됨)
    assert found[(layout[4][0], "cramfs")].details["crc_ok"] is True
    assert found[(layout[6][0], "ext")].details["volume_name"] == "rootfs"
    c = found[(layout[7][0], "cpio")]
    assert c.details["entries"] == 2 and c.details["has_trailer"]
    assert found[(layout[8][0], "zimage")].details["nop_sled"]


def test_uboot_env_le_be_redundant_and_markers():
    from pweh.formats import build_uboot_env

    env = {"bootcmd": "bootm 0x82000000", "bootargs": "console=ttyAMA0 mtdparts=xm_sfc:256k(boot),-(app)", "baudrate": "115200"}
    le = build_uboot_env(env, size=0x4000)
    red = build_uboot_env(env, size=0x4000, redundant=True, flags=1)
    # 빅엔디안 CRC (mkenvimage -b 와 같은 배치)
    payload = le[4:]
    be = struct.pack(">I", zlib.crc32(payload) & 0xFFFFFFFF) + payload
    blob = b"\xff" * 0x1000 + le + b"\xff" * 0x1000 + red + be + b"\xff" * 0x1000 + b"U-Boot 2013.07 (Oct 10 2019)\0PWEH SYNTHETIC test\0"
    hits = find_env_blocks(blob)
    assert [(h["offset"], h["crc_endian"], h["redundant"]) for h in hits] == [(0x1000, "little", False), (0x6000, "little", True), (0xA000, "big", False)]
    regions, _ = scan(blob)
    ks = {r.kind for r in regions}
    assert {"uboot-env", "uboot-version", "pweh-synthetic-marker"} <= ks


def test_padding_runs():
    blob = b"\x00" * 0x10000 + os.urandom(0x3000) + b"\xff" * 0x30000 + os.urandom(100)
    runs = padding_runs(blob, 0, len(blob), Ctl())
    assert runs[0]["kind"] == "zero-0x00" and runs[0]["offset"] == 0 and runs[0]["size"] == 0x10000
    assert runs[1]["kind"] == "erased-0xff" and runs[1]["size"] >= 0x2F000


def test_squashfs_superblock_validation():
    sb = bytearray(96)
    struct.pack_into("<IIIIIHHHHHHQQQQQQQQ", sb, 0, 0x73717368, 10, 0, 131072, 1, 4, 17, 0, 1, 4, 0, 0, 5000, 4900, 0xFFFFFFFFFFFFFFFF, 96, 2000, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF)
    info = parse_squashfs_superblock(bytes(sb), 6000)
    assert info and info["compression"] == "xz" and info["bytes_used"] == 5000 and not info["truncated"]
    assert parse_squashfs_superblock(bytes(sb), 4000)["truncated"] is True
    bad = bytearray(sb)
    struct.pack_into("<H", bad, 22, 16)  # block_log 불일치
    assert parse_squashfs_superblock(bytes(bad), 6000) is None
    bad2 = bytearray(sb)
    struct.pack_into("<Q", bad2, 64, 6000)  # inode_table_start > bytes_used
    assert parse_squashfs_superblock(bytes(bad2), 7000) is None


def test_safe_find_mmap_matches_bytes_find(tmp_path):
    """gh-105235 우회용 mmap.find 가 bytes.find 와 같은 결과를 내는지 (끝에 붙은 일치 포함, 모든 Python 에서 검사)."""
    import mmap

    from fwtriage_mcp.common import _SafeFindMmap

    rng = random.Random(105235)
    for size in (mmap.PAGESIZE, mmap.PAGESIZE * 2, mmap.PAGESIZE + 7):
        data = bytes(rng.choice(b"\x01\x02") for _ in range(size))
        p = tmp_path / f"f{size}"
        p.write_bytes(data)
        with open(p, "rb") as fh, _SafeFindMmap(fh.fileno(), 0, access=mmap.ACCESS_READ) as mm:
            needles = [data[-n:] for n in (1, 2, 3, 8)] + [data[:4], b"\x01\x01\x01\x01\x01\x01\x01\x01\x03", b"", b"\x02\x01\x02"]
            for sub in needles:
                for args in ((0, size), (size - 9, size), (size - len(sub), size), (5, size - 1), (-20,), ()):
                    assert mm.find(sub, *args) == data.find(sub, *args), (size, sub, args)


def test_open_mmap_find_does_not_read_past_mapping(tmp_path):
    """페이지 배수 크기 파일, 매핑 바로 뒤 페이지가 빈 상태에서 끝까지 find 해도 프로세스가 죽지 않아야 한다 (gh-105235)."""
    code = r"""
import mmap, sys
from pathlib import Path
sys.path.insert(0, sys.argv[2])
from fwtriage_mcp.common import open_mmap
p = Path(sys.argv[1])
p.write_bytes(b"\x01" * (mmap.PAGESIZE * 4))
def unmapped_after(mm_end):
    for ln in open("/proc/self/maps"):
        a, b = (int(x, 16) for x in ln.split()[0].split("-"))
        if a <= mm_end < b:
            return False
    return True
tested = 0
for _ in range(20):
    guard = mmap.mmap(-1, mmap.PAGESIZE * 16)
    with open_mmap(p) as mm:
        guard.close()
        end = max(int(ln.split()[0].split("-")[1], 16) for ln in open("/proc/self/maps") if ln.rstrip().endswith(str(p)))
        if unmapped_after(end):
            assert mm.find(b"\x01\x01\x02", 0, len(mm)) == -1
            assert mm.find(b"\x01\x01", 0, len(mm)) == 0
            tested += 1
print("tested", tested)
"""
    if not Path("/proc/self/maps").exists():
        pytest.skip("/proc/self/maps 없음")
    out = subprocess.run([sys.executable, "-c", code, str(tmp_path / "pagefile.bin"), str(REPO / "mcp-servers" / "fwtriage-mcp")],
                         capture_output=True, text=True, timeout=60)
    assert out.returncode == 0, (out.returncode, out.stderr[-800:])
    if "tested 0" in out.stdout:
        pytest.skip("매핑 배치상 '바로 뒤 페이지가 빈' 조건을 만들지 못함")


# ---------------------------------------------------------------------------
# ELF
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("with_sections", [True, False])
def test_handbuilt_elf_imports(with_sections):
    elf = build_min_elf(with_sections=with_sections)
    if not with_sections:
        elf = strip_section_headers(build_min_elf())
    info = elfinfo.parse_elf(elf, len(elf))
    assert info["machine"] == "arm" and info["flags"]["eabi_version"] == 5 and "soft-float" in info["flags"]["flags"]
    assert info["interpreter"] == "/lib/ld-uClibc.so.0" and info["needed"] == ["libc.so.0"]
    assert set(info["imports"]) == {"system", "strcpy", "popen", "sprintf"}
    assert info["symbol_source"] == ("section(.dynsym)" if with_sections else "dynamic(DT_SYMTAB)")
    assert info["hardening"]["nx"] is True and info["libc_guess"] == "uClibc"
    risk = elfinfo.risky_analysis(info, load_patterns().function_heuristics)
    assert risk["builtin"]["command-exec"]["functions"] == ["popen", "system"]
    assert "fn-command-exec" in risk["heuristics"]


def test_mips_flags_decode_and_exec_stack():
    elf = build_min_elf(machine=8, little=False, flags=0x70001005, gnu_stack_exec=True)
    info = elfinfo.parse_elf(elf, len(elf))
    assert info["endianness"] == "big" and info["flags"]["isa"] == "mips32r2" and info["flags"]["abi"] == "o32"
    assert {"noreorder", "cpic"} <= set(info["flags"]["flags"])
    assert info["hardening"]["nx"] is False
    n32 = elfinfo.decode_flags(8, 0x20 | 0x80000000, 32)
    assert n32["abi"] == "n32" and n32["isa"] == "mips64r2"


def test_elf_garbage_and_truncation():
    assert elfinfo.describe_elf_header(b"\x7fELF" + os.urandom(60)) is None or True
    elf = build_min_elf()
    with pytest.raises(elfinfo.ElfError):
        elfinfo.parse_elf(b"\x7fELF\x01\x01\x01" + b"\0" * 20, 27)
    trunc = elf[:200]
    info = elfinfo.parse_elf(trunc, len(trunc))  # 손상돼도 예외 없이 경고와 함께
    assert info["warnings"]


@pytest.mark.external
@pytest.mark.parametrize("target", ["arm-linux-musleabi", "mipsel-linux-musleabi"])
def test_zig_elf_against_readelf(tmp_path, target):
    prog = zig_build(tmp_path, target, dynamic=True)
    if prog is None:
        pytest.skip("zig 없음 또는 빌드 실패")
    data = prog.read_bytes()
    info = elfinfo.parse_elf(data, len(data))
    assert {"system", "popen", "strcpy", "sscanf", "bind"} <= {elfinfo._norm_sym(n) for n in info["imports"]}
    assert info["interpreter"].startswith("/lib/ld-musl-")
    if target.startswith("mips"):
        assert info["flags"]["isa"] == "mips32r2" and info["flags"]["abi"] == "o32"
        assert info["mips_abiflags"]["fp_abi"] == "soft-float"
    else:
        assert info["flags"]["eabi_version"] == 5
    stripped = strip_section_headers(data)
    info2 = elfinfo.parse_elf(stripped, len(stripped))
    assert info2["symbol_source"] == "dynamic(DT_SYMTAB)" and set(info2["imports"]) == set(info["imports"])
    readelf = find_tool("PWEH_READELF", "readelf")
    if readelf:
        out = subprocess.run([readelf, "--dyn-syms", "-W", str(prog)], capture_output=True, text=True, timeout=30).stdout
        und = {ln.split()[-1].split("@")[0] for ln in out.splitlines() if " UND " in ln and ln.split()[-1] not in ("UND",)}
        assert und == set(info["imports"])
    risk = elfinfo.risky_analysis(info, load_patterns().function_heuristics, ["%[^:]:%s"])
    assert risk["unbounded_scanf_formats"] == ["%[^:]:%s"] and risk["network_facing_hint"]
    static = zig_build(tmp_path / "s", target, dynamic=False)
    if static is not None:
        sd = static.read_bytes()
        si = elfinfo.parse_elf(sd, len(sd))
        assert si["static"] is True and si["imports"] == []


# ---------------------------------------------------------------------------
# 패턴 로더
# ---------------------------------------------------------------------------


def test_patterns_file_loads_without_errors():
    ps = load_patterns()
    assert ps.errors == []
    assert len(ps.string_heuristics) >= 50 and ps.function_heuristics and ps.interesting_paths
    ids = {h.id for h in ps.string_heuristics}
    for must in ("xm-opentelnet-cmd", "gen-telnetd-launch", "gen-inittab-console-shell", "hik-sdk-weblanguage", "dh-login-netkeyboard"):
        assert must in ids
    assert ps.known_hashes["absxcfbgXtb3o"]["id"] == "known-hash-xm-root-xc3511"
    assert "$1$/5bWggz/$JkbAnqFTv7HwEWr3DFJiC0" in ps.known_hashes
    assert "xc3511" in ps.candidate_passwords
    for h in ps.string_heuristics:
        assert (h.rx is not None) or (h.rx_bytes is not None)


def test_patterns_data_synced_with_reference():
    ref = REPO / "docs" / "references" / "cctv-hunt-patterns.yaml"
    if not ref.exists():
        pytest.skip("참조 YAML 없음")
    data = REPO / "src" / "pweh" / "data" / "cctv-hunt-patterns.yaml"
    assert hashlib.sha256(ref.read_bytes()).hexdigest() == hashlib.sha256(data.read_bytes()).hexdigest(), (
        "src/pweh/data/cctv-hunt-patterns.yaml 이 docs/references 원본과 다릅니다: cp docs/references/cctv-hunt-patterns.yaml src/pweh/data/"
    )


def test_required_literals_cases():
    assert required_literals(r"\bNetKeyboard\b") == (["NetKeyboard"], False)
    assert required_literals(r"(?i)\bGoAhead") == (["goahead"], True)
    lits, _ = required_literals(r"\b(?:macGuarder|dvrHelper)\b")
    assert set(lits) == {"macGuarder", "dvrHelper"}
    assert required_literals(r"x?ab")[0] is None  # 3자 미만
    assert required_literals(r"(?:abc)?defg")[0] == ["defg"]
    assert required_literals(r"[a-z]+")[0] is None


def test_required_literals_soundness_random():
    """무작위 정규식/문자열: 정규식이 일치하면 리터럴 사전 필터도 반드시 통과해야 한다."""
    rnd = random.Random(99)
    alphabet = "abcAB"

    def gen(depth: int = 0) -> str:
        parts = []
        for _ in range(rnd.randint(1, 4)):
            c = rnd.random()
            if c < 0.45 or depth > 2:
                parts.append("".join(rnd.choice(alphabet) for _ in range(rnd.randint(1, 4))))
            elif c < 0.6:
                parts.append(f"(?:{gen(depth + 1)}|{gen(depth + 1)})")
            elif c < 0.7:
                parts.append(f"(?:{gen(depth + 1)})?")
            elif c < 0.8:
                parts.append(f"(?:{gen(depth + 1)})+")
            elif c < 0.9:
                parts.append("[ab]")
            else:
                parts.append(r"\b")
        return "".join(parts)

    checked = 0
    for _ in range(3000):
        pat = gen()
        if rnd.random() < 0.3:
            pat = "(?i)" + pat
        rx = re.compile(pat)
        lits, ic = required_literals(pat)
        for _ in range(4):
            s = "".join(rnd.choice(alphabet + " ") for _ in range(rnd.randint(0, 30)))
            if rx.search(s):
                checked += 1
                if lits:
                    hay = s.lower() if ic else s
                    assert any(lit in hay for lit in lits), (pat, s, lits)
    assert checked > 100


def test_glob_to_regex():
    assert glob_to_regex("**/passwd").match("passwd") and glob_to_regex("**/passwd").match("a/b/passwd")
    rx = glob_to_regex("etc/init.d/*")
    assert rx.match("etc/init.d/rcS") and not rx.match("etc/init.d/x/y")
    assert glob_to_regex("**/*.cgi").match("var/www/cgi-bin/a.cgi")
    assert glob_to_regex("etc/rc[0-9S].d/*").match("etc/rcS.d/S01x")


def test_pattern_selection():
    ps = load_patterns()
    sel, _ = ps.select(["xm-*"])
    assert sel and all(h.id.startswith("xm-") for h in sel)
    sel, _ = ps.select(["dahua"])
    assert sel and all(h.vendor == "dahua" for h in sel)
    sel, notes = ps.select(["re:fooBar\\d+", "lit:SecretToken", "raw:\\xde\\xad\\xbe\\xef", "unknownword"])
    assert [h.id for h in sel] == [custom_id("re", "fooBar\\d+"), custom_id("lit", "SecretToken"), custom_id("raw", "\\xde\\xad\\xbe\\xef"), custom_id("lit", "unknownword")] and notes
    assert [h.id.split("-")[1] for h in sel] == ["re", "lit", "raw", "lit"]
    sel, _ = ps.select("cctv", min_severity="critical")
    assert sel and all(h.severity == "critical" for h in sel)


def test_custom_pattern_ids_are_stable_across_calls():
    """회귀: 사용자 패턴 check id 가 호출 순서 번호(custom-1, custom-2 ...)라서 실행마다 다른 패턴이 같은 id 로 겹쳤다."""
    ps = load_patterns()
    a, _ = ps.select(["lit:127.0.0.1", "re:ping -c \\d %s", "raw:\\x00PWEH"])
    b, _ = ps.select(["raw:\\x00PWEH", "xm-*", "re:ping -c \\d %s", "lit:127.0.0.1"])
    ida = {h.rationale: h.id for h in a}  # rationale = '사용자 지정 <종류>: <원문>'
    idb = {h.rationale: h.id for h in b if h.custom}
    assert ida == idb and len(set(ida.values())) == 3
    # 다른 패턴은 다른 id, 같은 본문이라도 종류가 다르면 다른 id
    assert custom_id("lit", "foo") != custom_id("re", "foo") != custom_id("lit", "bar")
    # lit 은 대소문자 무시 검색이므로 대소문자만 다른 리터럴, 리터럴로 바뀐 일반 단어는 같은 id
    w, notes = ps.select(["NoSuchSelectorWord"])
    assert w[0].id == custom_id("lit", "nosuchselectorword") == ps.select(["lit:nosuchselectorword"])[0][0].id and notes
    # 같은 패턴을 두 번 주면 check 하나
    d, _ = ps.select(["lit:dup", "lit:DUP"])
    assert len(d) == 1
    # id 가 불투명하므로 checks[].description(= rationale)에 패턴 원문이 들어간다
    assert "127.0.0.1" in [h for h in a if h.id == custom_id("lit", "127.0.0.1")][0].rationale
    assert re.fullmatch(r"custom-(?:lit|re|raw)-[0-9a-f]{8}", a[0].id)


def test_empty_matching_custom_patterns_are_skipped(tmp_path):
    """회귀: 'lit:' / 're:a*' 처럼 빈 문자열과 일치하는 패턴이 모든 바이트 위치를 히트로 기록했다 (1.8MB 에 74만 건)."""
    ps = load_patterns()
    sel, notes = ps.select(["lit:", "re:a*", "re:.*", "raw:x?", "lit:PWEH-OK"])
    assert [h.id for h in sel] == [custom_id("lit", "PWEH-OK")]
    assert sum("빈 문자열" in n for n in notes) == 4
    # 빈 문자열과는 일치하지 않지만 길이 0 으로 일치하는 패턴(전방 탐색)도 히트를 만들지 않는다
    f = tmp_path / "case" / "dumps" / "blob.bin"
    f.parent.mkdir(parents=True)
    f.write_bytes(b"\x00\x01PWEH-OK PWEH-OK\x00" * 50 + b"line PWEH-OK\n")
    zw, _ = ps.select(["re:(?=PWEH)", "raw:(?=PWEH)"])
    assert len(zw) == 2
    res = hunt(f, False, tmp_path / "case", Ctl(max_seconds=60), zw, max_hits=1000, per_pattern_cap=1000, max_file_size=1 << 20)
    assert res["summary"]["hits_total"] == 0
    ok, _ = ps.select(["lit:PWEH-OK"])
    res = hunt(f, False, tmp_path / "case", Ctl(max_seconds=60), ok, max_hits=1000, per_pattern_cap=1000, max_file_size=1 << 20)
    assert res["summary"]["hits_total"] == 101


def test_rootfs_locator(tmp_path):
    """fw_strings_hunt 의 hits[].file 계산: 매니페스트 트리 > 가장 바깥 rootfs 모양 디렉터리 > 없음(None)."""
    case = tmp_path / "case"
    sq = case / "extract" / "rootfs-001"
    for d in ("etc", "bin", "usr/bin", "usr/etc"):
        (sq / d).mkdir(parents=True)
    (case / "extract" / "rootfs-001.manifest.json").write_text("{}")
    (sq / "usr" / "bin" / "httpd").write_bytes(b"x")
    # 매니페스트 없는 REA/unblob 식 중첩 트리: 바깥 디렉터리들은 rootfs 모양이 아니다
    rea = case / "extract" / "rea-001" / "flash.bin_extract" / "2424832-3268608.squashfs_v4_le_extract"
    for d in ("etc", "sbin", "usr/bin", "usr/etc"):
        (rea / d).mkdir(parents=True)
    (rea / "usr" / "bin" / "httpd").write_bytes(b"x")
    (case / "extract" / "parts-001").mkdir(parents=True)
    (case / "extract" / "parts-001" / "03-rootfs.bin").write_bytes(b"x")
    (case / "dumps").mkdir()
    (case / "dumps" / "flash.bin").write_bytes(b"x")
    # etc 가 바깥(호스트) 링크인 트리도 lstat 로만 판단 (따라가지 않음)
    lk = case / "extract" / "tree-001"
    (lk / "bin").mkdir(parents=True)
    os.symlink("/etc", lk / "etc")
    (lk / "bin" / "app").write_bytes(b"x")
    # 펌웨어 안의 '<dir>.manifest.json' 이름은 펌웨어가 정한다: extract/ 바로 아래가 아니면 루트 근거로 쓰지 않는다
    (sq / "usr.manifest.json").write_text("{}")
    (rea / "usr.manifest.json").write_text("{}")
    loc = RootfsLocator(case)
    assert loc.locate(str(sq / "usr" / "bin" / "httpd")) == ("extract/rootfs-001/usr/bin/httpd", "/usr/bin/httpd")
    assert loc.locate(str(rea / "usr" / "bin" / "httpd"))[1] == "/usr/bin/httpd"  # /usr(etc+bin) 를 루트로 오인하지 않음
    assert loc.locate(str(case / "extract" / "parts-001" / "03-rootfs.bin")) == ("extract/parts-001/03-rootfs.bin", None)
    assert loc.locate(str(case / "dumps" / "flash.bin")) == ("dumps/flash.bin", None)
    assert loc.locate(str(lk / "bin" / "app"))[1] == "/bin/app"
    assert {loc.case_rel(r) for r in loc.roots_used} == {"extract/rootfs-001", rea.relative_to(case).as_posix(), "extract/tree-001"}


# ---------------------------------------------------------------------------
# mtdparts / 레이아웃
# ---------------------------------------------------------------------------


def test_parse_mtd_octal_warning_and_errors():
    parts, warns = parse_mtd("mtdparts=nor:0100k(boot),-(rest)", 0x100000)
    assert parts and any("8진수" in w for w in warns)
    assert parts[0]["size"] == 64 * 1024  # 리눅스 memparse: 0100k = 8진 0100 KiB = 64 KiB
    # 0x 접두 + 접미사도 커널처럼 해석 (장치 끝을 넘으면 잘림)
    parts, warns = parse_mtd("mtdparts=nor:0x100k(boot),-(rest)", 0x100000)
    assert parts and parts[0]["size"] == 0x40000
    # 해석 불가 토큰은 예외 없이 None + 경고
    parts, warns = parse_mtd("mtdparts=nor:12zz(bad)", 0x100000)
    assert parts is None and warns


def test_resolve_layout_multi_device_and_partitions_arg():
    blob = b"\xff" * 0x100000
    lay = resolve_layout(blob, len(blob), Ctl(), mtdparts="nor:256k(boot),-(rootfs);nand:-(data)", partitions=None, mtd_device=None)
    assert lay["device"] == "nor" and [p["name"] for p in lay["partitions"]] == ["boot", "rootfs"]
    assert any("장치가 2개" in w for w in lay["warnings"])
    lay2 = resolve_layout(blob, len(blob), Ctl(), mtdparts="nor:256k(boot),-(rootfs);nand:-(data)", partitions=None, mtd_device="nand")
    assert [p["name"] for p in lay2["partitions"]] == ["data"]
    lay3 = resolve_layout(blob, len(blob), Ctl(), mtdparts=None, partitions=[{"name": "k", "offset": "0x10000", "size": "64k"}, {"name": "r", "offset": 0x20000}], mtd_device=None)
    assert lay3["partitions"][0]["size"] == 0x10000 and lay3["partitions"][1]["size"] == 0x100000 - 0x20000
    from pweh.errors import ValidationFailed

    with pytest.raises(ValidationFailed):
        resolve_layout(blob, len(blob), Ctl(), mtdparts=None, partitions=None, mtd_device=None)


# ---------------------------------------------------------------------------
# rootfs 경로 해석 / squashfs 목록 / 프로세스
# ---------------------------------------------------------------------------


def test_resolve_in_root_never_escapes(tmp_path):
    root = tmp_path / "root"
    (root / "etc").mkdir(parents=True)
    (root / "bin").mkdir()
    (root / "bin" / "busybox").write_text("x")
    os.symlink("/bin/busybox", root / "bin" / "sh")  # 절대 링크 → rootfs 기준
    os.symlink("../../../../../../etc/shadow", root / "etc" / "up")  # .. 는 루트에서 멈춤
    os.symlink("loop2", root / "etc" / "loop1")
    os.symlink("loop1", root / "etc" / "loop2")
    os.symlink("/etc/passwd", root / "etc" / "hostpw")  # 이미지 안에 없는 대상
    assert resolve_in_root(root, "/bin/sh") == "/bin/busybox"
    assert resolve_in_root(root, "/etc/up") is None  # /etc/shadow 는 이미지에 없음 (호스트 파일을 보지 않음)
    assert resolve_in_root(root, "/etc/loop1") is None
    assert resolve_in_root(root, "/etc/hostpw") is None


def _audit_tree(root: Path, profile: dict | None = None) -> dict:
    from fwtriage_mcp.rootfs import Auditor

    words, _ = load_default_passwords()
    return Auditor(root, Ctl(max_seconds=120), load_patterns(), persistent_paths=[], profile=profile, max_file_size=16 << 20,
                   crack=False, crack_seconds=5, words=words, max_entries=10000).run()


def _tree(tmp_path: Path, name: str, files: dict[str, bytes]) -> Path:
    root = tmp_path / name
    (root / "etc").mkdir(parents=True)
    (root / "etc" / "passwd").write_text("root:x:0:0:root:/root:/bin/sh\n")
    for rel, data in files.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(data)
    return root


def test_vendor_family_generic_web_server_and_profile_fallback(tmp_path):
    """회귀: 일반 웹 서버(boa 등)만 있는 rootfs 의 vendor.family 가 'unknown' 이었다 (→ generic).

    파일 근거가 없을 때는 프로필의 구체적인 hunt.vendor_family 를 쓰고(family_source=profile), votes/vendor 는 파일 근거만 담는다.
    """
    boa = _tree(tmp_path, "boa", {"usr/sbin/boa": build_min_elf(imports=("system", "bind", "listen"))})
    for prof in (None, {}, {"hunt": {"vendor_family": "generic"}}, {"hunt": {"vendor_family": "not-a-family"}}):
        v = _audit_tree(boa, prof)["vendor"]
        assert (v["family"], v["family_source"], v["votes"], v["vendor"]) == ("generic", "generic-web-server", {}, None), (prof, v)
        assert any("/usr/sbin/boa" in e for e in v["evidence"])
    v = _audit_tree(boa, {"hunt": {"vendor_family": "hisilicon-oem"}})["vendor"]
    assert (v["family"], v["family_source"], v["votes"], v["vendor"], v["profile_vendor_family"]) == ("hisilicon-oem", "profile", {}, None, "hisilicon-oem")
    # 웹 서버도 벤더 근거도 없으면 unknown
    empty = _tree(tmp_path, "empty", {"etc/hostname": b"cam\n"})
    v = _audit_tree(empty)["vendor"]
    assert (v["family"], v["family_source"]) == ("unknown", "none")
    # 파일 근거가 있으면 프로필보다 우선
    sofia = _tree(tmp_path, "sofia", {"usr/bin/Sofia": build_min_elf() + b"\0uc-httpd 1.0.0\0"})
    v = _audit_tree(sofia, {"hunt": {"vendor_family": "hisilicon-oem"}})["vendor"]
    assert (v["family"], v["family_source"], v["vendor"]) == ("xiongmai-like", "evidence", "xiongmai") and v["votes"]["xiongmai"] >= 5


def test_lighttpd_is_not_foscam_evidence(tmp_path):
    """회귀: YAML web_server_binaries 에서 lighttpd 가 foscam 목록에 먼저 나와 모든 lighttpd 가 foscam +3 표였다."""
    lt = _tree(tmp_path, "lighttpd", {"usr/sbin/lighttpd": build_min_elf(imports=("bind", "listen", "accept"))})
    res = _audit_tree(lt)
    assert [s["vendor"] for s in res["web"]["servers"]] == ["generic"]
    v = res["vendor"]
    assert v["votes"] == {} and v["vendor"] is None and (v["family"], v["family_source"]) == ("generic", "generic-web-server")
    assert "foscam" not in " ".join(b["reason"] for b in res["binaries_of_interest"])
    # foscam 고유 바이너리는 여전히 foscam 근거
    fo = _tree(tmp_path, "foscam", {"usr/sbin/lighttpd": build_min_elf(), "usr/bin/webService": build_min_elf()})
    assert _audit_tree(fo)["vendor"]["votes"] == {"foscam": 3}


def test_squashfs_listing_parser_and_safety_checks():
    listing = (
        "drwxr-xr-x 0/0                      59 2026-10-18 16:05 squashfs-root\n"
        "-rwsr-xr-x 0/0                       2 2026-10-18 16:05 squashfs-root/bin/busybox\n"
        "lrwxrwxrwx 0/0                      12 2026-10-18 16:05 squashfs-root/bin/sh -> /bin/busybox\n"
        "crw------- 0/0                   5,  1 2026-10-18 16:05 squashfs-root/dev/console\n"
        "-rw-r--r-- 0/0                       1 2026-10-18 16:05 squashfs-root/www/new\n"
        "line.txt\n"
    )
    p = parse_listing(listing)
    assert len(p["entries"]) == 5 and p["anomalies"] == ["line.txt"]
    bb = p["entries"][1]
    assert bb["path"] == "/bin/busybox" and bb["mode"] == "0o4755"
    assert p["entries"][2]["target"] == "/bin/busybox" and p["entries"][3]["rdev"] == "5,1"
    assert mode_from_ls("-rwsr-sr-t") == 0o107755 and mode_from_ls("drwxr-xr-x") == 0o40755
    assert check_listing(p["entries"]) == []
    # 구버전 -lls 형식(소유자 이름)도 해석
    lls = parse_listing("-rwsr-xr-x root/root                 2 2026-10-18 16:05 squashfs-root/bin/busybox\n-rw-r--r-- admin/users 3 2026-10-18 16:05 squashfs-root/x\n")
    assert lls["anomalies"] == [] and lls["entries"][0]["uid"] == 0 and lls["entries"][1]["uid"] == "admin"
    evil = p["entries"] + [{"path": "/bin/sh/evil", "type": "file", "mode": "0o644"}, {"path": "/a/../b", "type": "file", "mode": "0o644"}]
    probs = check_listing(evil)
    assert len(probs) == 2


def test_run_process_timeout_and_cancel(tmp_path):
    t0 = time.monotonic()
    r = run_process([sys.executable, "-c", "import time; time.sleep(30)"], ctl=Ctl(), timeout=0.5)
    assert r.timed_out and time.monotonic() - t0 < 10
    ev = threading.Event()
    threading.Timer(0.4, ev.set).start()
    with pytest.raises(Cancelled):
        run_process([sys.executable, "-c", "import time; time.sleep(30)"], ctl=Ctl(ev), timeout=60)
    r2 = run_process([sys.executable, "-c", "import sys; print(sys.stdin.read()=='')"], ctl=Ctl(), timeout=20)
    assert r2.stdout.strip() == b"True"  # stdin 은 DEVNULL
    r3 = run_process([sys.executable, "-c", "import sys; sys.stdout.write('x'*100000)"], ctl=Ctl(), timeout=20, max_stdout=1000)
    assert len(r3.stdout) == 1000 and r3.stdout_truncated
