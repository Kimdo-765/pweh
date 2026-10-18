"""공용 형식 파서 테스트."""

from __future__ import annotations

import os
import struct
import zlib

import pytest

from pweh.formats import (
    build_uboot_env,
    build_uimage_header,
    crc32,
    find_uboot_env,
    format_md_b,
    parse_crc32_line,
    parse_md_b_output,
    parse_mtdparts,
    parse_proc_mtd,
    parse_uboot_env,
    parse_uimage_header,
)


def test_mtdparts_basic_and_bootargs():
    parts = parse_mtdparts("mem=64M console=ttyAMA0,115200 root=/dev/mtdblock3 mtdparts=hi_sfc:256k(boot),64k(env),2560k(kernel),-(rootfs)", total_size=16 * 1024 * 1024)
    assert [p["name"] for p in parts] == ["boot", "env", "kernel", "rootfs"]
    assert parts[1]["offset"] == 0x40000 and parts[1]["size"] == 0x10000
    assert parts[3]["offset"] == 0x40000 + 0x10000 + 2560 * 1024
    assert parts[3]["size"] == 16 * 1024 * 1024 - parts[3]["offset"]
    p2 = parse_mtdparts("mtdparts=nor:0x40000@0(uboot)ro,1M@0x50000(kernel);nand:-(data)")
    assert p2[0]["ro"] and p2[1]["offset"] == 0x50000 and p2[2]["device"] == "nand" and p2[2]["size"] is None


def test_proc_mtd():
    text = 'dev:    size   erasesize  name\nmtd0: 00040000 00010000 "boot"\nmtd1: 00010000 00010000 "env"\nmtd2: 00280000 00010000 "kernel"\n'
    rows = parse_proc_mtd(text)
    assert rows[2] == {"dev": "mtd2", "size": 0x280000, "erasesize": 0x10000, "name": "kernel", "offset_estimate": 0x50000}


def test_uimage_roundtrip():
    payload = os.urandom(1000)
    hdr = build_uimage_header(payload, name="Linux-3.18.20", load=0x80008000, entry=0x80008000, arch="arm")
    info = parse_uimage_header(hdr + payload)
    assert info["header_crc_ok"] and info["data_crc_ok"] and info["arch"] == "arm" and info["name"] == "Linux-3.18.20"
    bad = bytearray(hdr + payload)
    bad[100] ^= 0xFF
    assert parse_uimage_header(bytes(bad))["data_crc_ok"] is False


@pytest.mark.parametrize("redundant", [False, True])
def test_env_roundtrip_and_find(redundant):
    env = {"bootcmd": "sf probe 0; sf read 0x82000000 0x50000 0x280000; bootm 0x82000000", "bootdelay": "1", "baudrate": "115200"}
    blk = build_uboot_env(env, size=0x10000, redundant=redundant)
    res = parse_uboot_env(blk)
    assert res and res["env"] == env and res["redundant"] is redundant
    blob = b"\xff" * 0x40000 + blk + b"\xff" * 0x1000
    hits = find_uboot_env(blob)
    assert hits and hits[0]["offset"] == 0x40000 and hits[0]["env"]["bootdelay"] == "1"


def test_md_b_format_and_parse():
    data = bytes(range(256)) * 2 + b"tail"
    text = "md.b 82000000 204\n" + format_md_b(0x82000000, data) + "\nhisilicon # "
    out, problems = parse_md_b_output(text, 0x82000000, len(data))
    assert out == data and problems == []
    # 손상된 줄
    lines = text.splitlines()
    lines[5] = lines[5][:20]
    out2, problems2 = parse_md_b_output("\n".join(lines), 0x82000000, len(data))
    assert problems2


def test_crc32_line():
    r = parse_crc32_line("crc32 for 82000000 ... 8200ffff ==> 1a2b3c4d\n")
    assert r == {"start": 0x82000000, "end": 0x8200FFFF, "crc32": 0x1A2B3C4D}
    assert crc32(b"123456789") == 0xCBF43926


def test_memparse_linux_rules():
    from pweh.formats import memparse

    assert memparse("0x100k") == 0x100 << 10
    assert memparse("0100k") == 64 * 1024  # 선행 0 = 8진
    assert memparse("2M") == 2 << 20 and memparse("1g") == 1 << 30 and memparse("1T") == 1 << 40
    assert memparse("0") == 0


def test_mtdparts_kernel_semantics():
    parts = parse_mtdparts("mtdparts=sfc:256k(boot),64k,1M(kernel)", total_size=0x100000)
    assert parts[1]["name"] == "Partition_001"  # 이름 없는 파티션
    assert parts[2]["truncated"] and parts[2]["offset"] + parts[2]["size"] == 0x100000
    with pytest.raises(Exception):
        parse_mtdparts("mtdparts=sfc:256k(boot),-(rootfs),64k(after)")
    assert [p["name"] for p in parse_mtdparts("mtdparts=sfc:0(empty),256k(boot)")] == ["boot"]


def test_env_big_endian_crc():
    env = {"bootcmd": "bootm", "baudrate": "115200"}
    blk = build_uboot_env(env, size=0x2000, big_endian=True)
    res = parse_uboot_env(blk)
    assert res and res["crc_endian"] == "big" and res["env"] == env


def test_parse_size_hex_suffix():
    from pweh.fsutil import parse_size

    assert parse_size("0x100k") == 0x40000
    assert parse_size("16MiB") == 16 << 20


def test_crc32_line_uppercase_variant():
    r = parse_crc32_line("CRC32 for 82000000 ... 8200FFFF ==> 1A2B3C4D\r\n")
    assert r == {"start": 0x82000000, "end": 0x8200FFFF, "crc32": 0x1A2B3C4D}
