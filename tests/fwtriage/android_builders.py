"""실제 기기 자료 없이 struct/hashlib로 만드는 작은 Android 합성 fixture."""

import hashlib
import struct


def boot(version=4, *, kernel=32, cmdline=b"", page=4096):
    hs = (1632, 1648, 1660, 1580, 1584)[version]
    out = bytearray(page * 3)
    out[:8] = b"ANDROID!"
    struct.pack_into("<I", out, 8, kernel)
    struct.pack_into("<I", out, 16 if version < 3 else 12, 32)
    struct.pack_into("<I", out, 40, version)
    if version < 3:
        struct.pack_into("<I", out, 36, page)
        out[64:64 + len(cmdline)] = cmdline
        if version:
            struct.pack_into("<I", out, 1644, hs)
    else:
        struct.pack_into("<I", out, 20, hs)
        out[44:44 + len(cmdline)] = cmdline
    return out


def vendor_boot(version=4, *, config=b"androidboot.selinux=permissive\n"):
    hs = 2112 if version == 3 else 2128
    out = bytearray(4096 * (5 if version == 4 else 3))
    out[:8] = b"VNDRBOOT"
    struct.pack_into("<II", out, 8, version, 4096)
    struct.pack_into("<I", out, 24, 16)
    struct.pack_into("<II", out, 2096, hs, 16)
    if version == 4:
        struct.pack_into("<4I", out, 2112, 108, 1, 108, len(config))
        struct.pack_into("<3I", out, 12288, 16, 0, 1)
        out[12288 + 12:12288 + 16] = b"test"
        out[16384:16384 + len(config)] = config
    return out


def vbmeta(flags=0):
    out = bytearray(256)
    out[:4] = b"AVB0"
    struct.pack_into(">I", out, 4, 1)
    struct.pack_into(">I", out, 120, flags)
    return out


def sparse():
    chunks = [struct.pack("<2H2I", 0xCAC1, 0, 1, 28) + b"PWEH SYNTHETIC! ",
              struct.pack("<2H2I", 0xCAC2, 0, 1, 16) + b"ABCD",
              struct.pack("<2H2I", 0xCAC3, 0, 1, 12),
              struct.pack("<2H2I", 0xCAC4, 0, 0, 16) + bytes(4)]
    return bytearray(struct.pack("<I4H4I", 0xED26FF3A, 1, 0, 28, 12, 16, 3, 4, 0) + b"".join(chunks))


def lp(*, minor=2, attr=0, external=False, metadata_only=False):
    size, meta, slots, first = 65536, 4096, 2, 64
    geo = bytearray(52)
    struct.pack_into("<II", geo, 0, 0x616C4467, 52)
    struct.pack_into("<3I", geo, 40, meta, slots, 4096)
    geo[8:40] = hashlib.sha256(geo).digest()
    part = struct.pack("<36s4I", b"system", attr, 0, 3, 0)
    extent = b"".join(struct.pack("<QIQI", *x) for x in ((8, 0, first, int(external)), (8, 1, 0, 0), (8, 0, 80, 0)))
    group = struct.pack("<36sIQ", b"default", 0, 0)
    dev = struct.pack("<QIIQ36sI", first, 4096, 0, size, b"super", 0)
    if external:
        dev += struct.pack("<QIIQ36sI", first, 4096, 0, size, b"vendor", 0)
    arrays = (part, extent, group, dev)
    hs = 256 if minor == 2 else 128
    header = bytearray(hs)
    struct.pack_into("<I2HI", header, 0, 0x414C5030, 10, minor, hs)
    tables = b"".join(arrays)
    struct.pack_into("<I", header, 44, len(tables))
    header[48:80] = hashlib.sha256(tables).digest()
    pos = 0
    for i, (data, es) in enumerate(zip(arrays, (52, 24, 48, 64))):
        struct.pack_into("<3I", header, 80 + i * 12, pos, len(data) // es, es)
        pos += len(data)
    header[12:44] = hashlib.sha256(header).digest()
    metadata = header + tables
    if metadata_only:
        return bytearray(geo + bytes(4096 - len(geo)) + metadata), b""
    out = bytearray(size)
    for pos in (4096, 8192):
        out[pos:pos + len(geo)] = geo
    for pos in (12288, 16384, 20480, 24576):
        out[pos:pos + len(metadata)] = metadata
    out[first * 512:(first + 8) * 512] = b"A" * 4096
    out[80 * 512:88 * 512] = b"B" * 4096
    return out, b"A" * 4096 + bytes(4096) + b"B" * 4096


def rehash_metadata(out, off=12288):
    hs = struct.unpack_from("<I", out, off + 8)[0]
    ts = struct.unpack_from("<I", out, off + 44)[0]
    out[off + 48:off + 80] = hashlib.sha256(out[off + hs:off + hs + ts]).digest()
    out[off + 12:off + 44] = bytes(32)
    out[off + 12:off + 44] = hashlib.sha256(out[off:off + hs]).digest()


def f2fs(log_block=12):
    out = bytearray(4096)
    struct.pack_into("<I2H4I", out, 1024, 0xF2F52010, 1, 0, 9, log_block - 9, log_block, 9)
    struct.pack_into("<Q", out, 1024 + 36, 1024)
    return out
