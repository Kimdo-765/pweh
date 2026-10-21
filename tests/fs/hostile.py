"""적대적(조작·손상) 카드 이미지 빌더 — 예산·검증 회귀 시험용 (작고 빠른 합성 이미지, 외부 도구 없음).

- `fat32_long_chain`: FAT32(512 바이트 클러스터) 루트에 볼륨만 한 크기의 파일 n 개가 모두 긴 체인 하나에서 시작한다.
  데이터 영역은 루트 뒤에서 잘린다(체인은 FAT 만 따라가므로 데이터가 없어도 된다).
- `exfat_chain_sets`: exFAT(512 바이트 클러스터) 루트에 같은 긴 FAT 체인에서 시작하는 파일 집합 k 개(삭제 또는 살아 있음).
- `fat16_lfn_bomb`: FAT16 고정 루트를 (삭제 LFN, 삭제 SFN) 쌍으로 채운다(첫 바이트 되찾기 계산을 최대로).
- `fat32_all_allocated`: 모든 FAT 항목이 할당(EOC)된 FAT32 에 볼륨만 한 크기의 삭제 파일 — 건너뛰기 탐색 비용.

체크섬·배치는 builders.py 처럼 라이브러리와 독립적으로 계산한다. 값은 모두 합성이다.
"""

from __future__ import annotations

import struct
from array import array

from fs.builders import (
    ceil_div,
    exfat_boot_checksum,
    exfat_name_hash,
    exfat_set_checksum,
    lfn_checksum,
    lfn_slots,
    minimal_upcase_table,
    upcase_checksum,
)


def sfn_entry(name11: bytes, attr: int, cluster: int, size: int) -> bytes:
    return struct.pack("<11sBBBHHHHHHHI", name11, attr, 0, 0, 0, 0, 0, (cluster >> 16) & 0xFFFF, 0, 0,
                       cluster & 0xFFFF, size)


def fat32_boot(*, bps: int, spc: int, rsvd: int, nfats: int, fatsz: int, totsec: int, root_cluster: int) -> bytes:
    bs = bytearray(bps)
    bs[0:3] = b"\xeb\x58\x90"
    bs[3:11] = b"PWEHHOST"
    struct.pack_into("<HBHBHHBHHHII", bs, 11, bps, spc, rsvd, nfats, 0, 0, 0xF8, 0, 63, 255, 0, totsec)
    struct.pack_into("<IHHIHH12sBBBI11s8s", bs, 36, fatsz, 0, 0, root_cluster, 0, 0, bytes(12), 0x80, 0, 0x29,
                     0x1234ABCD, b"HOSTILE    ", b"FAT32   ")
    bs[510:512] = b"\x55\xaa"
    return bytes(bs)


def fat32_long_chain(n_entries: int, count: int = 200_000, size: int | None = None, *, deleted: bool = False) -> bytes:
    """FAT32 루트에 크기 size 인 파일 n_entries 개 — 모두 클러스터 S 에서 시작하는 긴 체인(S..count+1)을 가리킨다.

    size 기본값은 볼륨 데이터 영역 전체(최대 0xFFFFFFFF) — 그보다 큰 크기는 디렉터리 검증(size_range)이 거른다."""
    bps, spc, rsvd, nfats = 512, 1, 32, 1
    if size is None:
        size = min(0xFFFFFFFF, count * bps * spc)
    fatsz = ceil_div((count + 2) * 4, bps)
    totsec = rsvd + nfats * fatsz + count * spc
    fat_off = rsvd * bps
    data_off = (rsvd + nfats * fatsz) * bps
    root_n = ceil_div((n_entries + 1) * 32, bps)
    root = list(range(2, 2 + root_n))
    start = 2 + root_n + 10
    fat = array("I", bytes(4 * (count + 2)))
    fat[0], fat[1] = 0x0FFFFFF8, 0x0FFFFFFF
    for a, b in zip(root, root[1:]):
        fat[a] = b
    fat[root[-1]] = 0x0FFFFFFF
    fat[start:count + 1] = array("I", range(start + 1, count + 2))
    fat[count + 1] = 0x0FFFFFFF
    img = bytearray(data_off + root_n * bps)
    img[0:bps] = fat32_boot(bps=bps, spc=spc, rsvd=rsvd, nfats=nfats, fatsz=fatsz, totsec=totsec, root_cluster=2)
    img[fat_off:fat_off + len(fat) * 4] = fat.tobytes()[:fatsz * bps]
    d = bytearray(root_n * bps)
    d[0:32] = sfn_entry(b"CHAINBOMB  ", 0x08, 0, 0)
    for i in range(n_entries):
        e = bytearray(sfn_entry(f"F{i:07d}MP4".encode(), 0x20, start, size))
        if deleted:
            e[0] = 0xE5
        d[(i + 1) * 32:(i + 2) * 32] = e
    img[data_off:data_off + len(d)] = d
    return bytes(img)


def fat32_all_allocated(count: int = 300_000, deleted_firsts: tuple[int, ...] = (100, 200)) -> bytes:
    """모든 FAT 항목이 EOC(할당)인 FAT32 루트에 볼륨 데이터 영역만 한 크기의 삭제 파일들 — skip-allocated 탐색이 끝까지 할당만 만난다."""
    bps, spc, rsvd, nfats = 512, 1, 32, 1
    size = min(0xFFFFFFFF, count * bps * spc)
    fatsz = ceil_div((count + 2) * 4, bps)
    totsec = rsvd + nfats * fatsz + count * spc
    fat_off = rsvd * bps
    data_off = (rsvd + nfats * fatsz) * bps
    img = bytearray(data_off + bps)
    img[0:bps] = fat32_boot(bps=bps, spc=spc, rsvd=rsvd, nfats=nfats, fatsz=fatsz, totsec=totsec, root_cluster=2)
    img[fat_off:fat_off + fatsz * bps] = b"\xff\xff\xff\x0f" * (fatsz * bps // 4)
    img[fat_off:fat_off + 4] = b"\xf8\xff\xff\x0f"
    d = bytearray(bps)
    d[0:32] = sfn_entry(b"DELSCAN    ", 0x08, 0, 0)
    for i, fc in enumerate(deleted_firsts):
        e = bytearray(sfn_entry(f"_ECORD{i:02d}MP4".encode(), 0x20, fc, size))
        e[0] = 0xE5
        d[(i + 1) * 32:(i + 2) * 32] = e
    img[data_off:data_off + bps] = d
    return bytes(img)


def fat16_lfn_bomb(root_ent: int = 4096) -> bytes:
    """FAT16 고정 루트 root_ent 슬롯을 (삭제 LFN, 삭제 SFN) 쌍으로 채운다. SFN 첫 바이트는 0xFF 였다(되찾기 계산 최대)."""
    bps, spc, rsvd, nfats = 512, 1, 1, 1
    count = 5000
    fatsz = ceil_div((count + 2) * 2, bps)
    root_secs = ceil_div(root_ent * 32, bps)
    totsec = rsvd + nfats * fatsz + root_secs + count
    img = bytearray(totsec * bps)
    bs = bytearray(bps)
    bs[0:3] = b"\xeb\x3c\x90"
    bs[3:11] = b"PWEHHOST"
    struct.pack_into("<HBHBHHBHHHII", bs, 11, bps, spc, rsvd, nfats, root_ent, totsec, 0xF8, fatsz, 63, 255, 0, 0)
    struct.pack_into("<BBBI11s8s", bs, 36, 0x80, 0, 0x29, 0x1234ABCD, b"LFNBOMB    ", b"FAT16   ")
    bs[510:512] = b"\x55\xaa"
    img[0:bps] = bs
    img[rsvd * bps:rsvd * bps + 4] = b"\xf8\xff\xff\xff"
    root_off = (rsvd + nfats * fatsz) * bps
    for i in range(root_ent // 2):
        name11 = b"\xff" + f"{i:07d}".encode() + b"MP4"
        lfn = bytearray(lfn_slots(f"x{i:06d}.mp4", lfn_checksum(name11))[0])
        lfn[0] = 0xE5
        s = bytearray(sfn_entry(name11, 0x20, 0, 0))
        s[0] = 0xE5
        o = root_off + 64 * i
        img[o:o + 32] = lfn
        img[o + 32:o + 64] = s
    return bytes(img)


def _exfat_file_set(name: str, *, first_cluster: int, data_length: int, no_fat_chain: bool, deleted: bool,
                    attrs: int = 0x20) -> list[bytes]:
    enc = name.encode("utf-16-le")
    nl = len(enc) // 2
    n_names = ceil_div(nl, 15)
    f = bytearray(32)
    f[0] = 0x85
    f[1] = 1 + n_names
    struct.pack_into("<H", f, 4, attrs)
    s = bytearray(32)
    s[0] = 0xC0
    s[1] = 0x01 | (0x02 if no_fat_chain else 0)
    s[3] = nl
    struct.pack_into("<H", s, 4, exfat_name_hash(name))
    struct.pack_into("<Q", s, 8, data_length)
    struct.pack_into("<I", s, 20, first_cluster)
    struct.pack_into("<Q", s, 24, data_length)
    out = [f, s]
    for i in range(n_names):
        ne = bytearray(32)
        ne[0] = 0xC1
        chunk = enc[i * 30:(i + 1) * 30]
        ne[2:2 + len(chunk)] = chunk
        out.append(ne)
    struct.pack_into("<H", f, 2, exfat_set_checksum([bytes(x) for x in out]))
    if deleted:
        for x in out:
            x[0] &= 0x7F
    return [bytes(x) for x in out]


def exfat_chain_sets(k: int, chain_len: int = 65_536, count: int = 100_000, *, deleted: bool = True,
                     data_length: int | None = None) -> bytes:
    """exFAT(512 바이트 클러스터) 루트에 FAT 체인 파일 집합 k 개 — 모두 클러스터 CH 에서 시작하는 chain_len 클러스터 체인.

    삭제 집합이면 체인 클러스터는 비트맵에서 비어 있다(복구 후보가 그럴듯하게). 이미지는 루트 뒤에서 잘린다.
    """
    bps = cs = 512
    fat_off = 24
    fat_len = ceil_div((count + 2) * 4, bps)
    heap_off = fat_off + fat_len + 8
    bitmap_len = ceil_div(count, 8)
    bm = list(range(2, 2 + ceil_div(bitmap_len, cs)))
    up = minimal_upcase_table()
    up_c = bm[-1] + 1
    root_slots = 3 + 3 * k
    root_n = ceil_div(root_slots, cs // 32)
    root = list(range(up_c + 1, up_c + 1 + root_n))
    ch = root[-1] + 100
    assert ch + chain_len - 1 <= count + 1
    fat = array("I", bytes(4 * (count + 2)))
    fat[0], fat[1] = 0xFFFFFFF8, 0xFFFFFFFF
    for chain in (bm, [up_c], root):
        for a, b in zip(chain, chain[1:]):
            fat[a] = b
        fat[chain[-1]] = 0xFFFFFFFF
    fat[ch:ch + chain_len - 1] = array("I", range(ch + 1, ch + chain_len))
    fat[ch + chain_len - 1] = 0xFFFFFFFF
    bitmap = bytearray(bitmap_len)
    for c in bm + [up_c] + root:
        bitmap[(c - 2) >> 3] |= 1 << ((c - 2) & 7)
    if not deleted:
        for c in range(ch, ch + chain_len):
            bitmap[(c - 2) >> 3] |= 1 << ((c - 2) & 7)
    vol_len = heap_off + count
    img = bytearray((heap_off + (root[-1] - 2 + 1)) * bps)
    reg = bytearray(12 * bps)
    reg[0:3] = b"\xeb\x76\x90"
    reg[3:11] = b"EXFAT   "
    struct.pack_into("<QQIIIIIIHHBBBBB", reg, 64, 0, vol_len, fat_off, fat_len, heap_off, count, root[0], 0xC0FFEE11, 0x0100,
                     0, 9, 0, 1, 0x80, 0xFF)
    reg[510:512] = b"\x55\xaa"
    for j in range(1, 9):
        reg[(j + 1) * bps - 4:(j + 1) * bps] = b"\x00\x00\x55\xaa"
    cks = exfat_boot_checksum(bytes(reg), bps)
    for i in range(bps // 4):
        struct.pack_into("<I", reg, 11 * bps + 4 * i, cks)
    img[0:len(reg)] = reg
    img[len(reg):2 * len(reg)] = reg
    fb = fat.tobytes()
    img[fat_off * bps:fat_off * bps + len(fb)] = fb

    def coff(c: int) -> int:
        return (heap_off + c - 2) * bps

    img[coff(bm[0]):coff(bm[0]) + bitmap_len] = bitmap
    img[coff(up_c):coff(up_c) + len(up)] = up
    slots = []
    lab = bytearray(32)
    lab[0], lab[1] = 0x83, 3
    lab[2:8] = "ADV".encode("utf-16-le")
    slots.append(bytes(lab))
    bme = bytearray(32)
    bme[0] = 0x81
    struct.pack_into("<IQ", bme, 20, bm[0], bitmap_len)
    slots.append(bytes(bme))
    upe = bytearray(32)
    upe[0] = 0x82
    struct.pack_into("<I", upe, 4, upcase_checksum(up))
    struct.pack_into("<IQ", upe, 20, up_c, len(up))
    slots.append(bytes(upe))
    dl = chain_len * cs if data_length is None else data_length
    for i in range(k):
        slots += _exfat_file_set(f"d{i:05d}.mp4", first_cluster=ch, data_length=dl, no_fat_chain=False, deleted=deleted)
    data = b"".join(slots)
    img[coff(root[0]):coff(root[0]) + len(data)] = data
    return bytes(img)
