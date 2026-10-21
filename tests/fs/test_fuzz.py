"""강건성: 만든 이미지의 메타데이터 영역(부트 섹터, FAT, 비트맵, 디렉터리, MBR/EBR/GPT)을 고정 시드로 변조하고
감지 → 열기 → info → walk → 후보 → 읽기 → 볼륨 점검 전체를 돌린다.

통과 조건: 파이썬 예외가 새어 나오지 않고(FsError 만), FsError 의 reason 이 internal_error 가 아니며(감싸기 안전망이
버그를 가리지 않게), 반복 한 번이 시간 상한 안에 끝난다.
"""

from __future__ import annotations

import random
import time
from typing import Any, Callable

import pytest

from fs.builders import (
    GptPart,
    exfat_small,
    fat12_small,
    fat16_small,
    fat32_small,
    pattern,
    put_ebr,
    put_gpt,
    put_mbr,
)
from pweh.fs import BytesReader, FsError, Limits, detect_partitions, open_volume, partition_source

LIMITS = Limits(max_seconds=None, max_entries=2000, max_dir_slots=1 << 15, max_total_slots=1 << 17,
                max_scan_clusters=1 << 18, max_read_bytes=1 << 14, max_orphans=200, max_warnings=20)
ITER_TIME_CAP = 15.0  # 초 (관찰한 최댓값은 약 0.3초 — 다른 작업으로 CPU 가 바쁠 때를 위한 넉넉한 여유)
BOUNDARY32 = [0, 1, 2, 3, 0x7F, 0x80, 0xFF, 0xFFFF, 0x7FFFFFFF, 0x0FFFFFF7, 0x0FFFFFF8, 0x0FFFFFFF, 0xFFFFFFF7,
              0xFFFFFFF8, 0xFFFFFFFF, 0x10000, 0xFFF7, 0xFFF8]


class Internal(AssertionError):
    pass


def call(fn: Callable[..., Any], *a: Any, **k: Any) -> Any:
    try:
        return fn(*a, **k)
    except FsError as e:
        if e.reason == "internal_error":
            raise Internal(f"{getattr(fn, '__name__', fn)}: {e.message}") from e
        return None


def exercise(vol: Any, deep: bool) -> None:
    call(vol.info)
    w = call(vol.walk)
    call(vol.list_dir)
    call(vol.lookup, "/DCIM/clip0001.mp4")
    if not w:
        return
    for e in w["entries"][:6]:
        call(vol.entry, e["ref"])
        call(vol.candidates, e["ref"])
        call(vol.read_content, e["ref"], max_bytes=4096)
        call(lambda r: b"".join(vol.iter_content(r, max_bytes=2048)), e["ref"])
        if e.get("is_dir") and e.get("child_dir"):
            call(vol.list_dir, e["ref"])
        if e.get("residual_bytes"):
            call(vol.read_content, e["ref"], region="residual", max_bytes=2048)
    if deep:
        call(vol.cluster_report)


def surface(buf: bytearray, deep: bool) -> None:
    src = BytesReader(buf)
    layout = call(detect_partitions, src, limits=LIMITS)
    if not layout:
        return
    for p in layout["partitions"][:4]:
        part = call(partition_source, src, p)
        if part is None:
            continue
        vol = call(open_volume, part, limits=LIMITS, fs_hint=p["fs_hint"] if p["fs_hint"] else None)
        if vol is not None:
            exercise(vol, deep)


Region = tuple  # (start, end[, slot, hot]) — hot: [(slot 안 오프셋, 너비)], slot: 필드 묶음 크기(0 = 구간 시작 기준)

VALUES = {
    1: [0, 1, 2, 0x0F, 0x40, 0x7F, 0x80, 0x85, 0xC0, 0xC1, 0xE5, 0xFF],
    2: [0, 1, 2, 0x1F, 0x200, 0x1000, 0x7FFF, 0x8000, 0xFFF7, 0xFFFF],
    4: BOUNDARY32,
    8: [0, 1, 0xFFFFFFFF, 1 << 32, (1 << 40) + 7, (1 << 63) - 1, (1 << 64) - 1],
}


def mutate(buf: bytearray, regions: list, rng: random.Random, n: int) -> list[tuple[int, bytes]]:
    saved: list[tuple[int, bytes]] = []
    for _ in range(n):
        reg = rng.choice(regions)
        start, end = reg[0], min(reg[1], len(buf))
        if end - start < 8:
            continue
        r = rng.random()
        if len(reg) > 2 and r < 0.55:  # 구조를 아는 필드에 경계값
            slot, hot = reg[2], reg[3]
            off, width = rng.choice(hot)
            base = start if slot == 0 else start + rng.randrange(0, max(1, (end - start) // slot)) * slot
            pos = base + off
            if pos + width > end:
                continue
            saved.append((pos, bytes(buf[pos:pos + width])))
            v = rng.choice(VALUES[width]) if rng.random() < 0.8 else rng.getrandbits(8 * width)
            buf[pos:pos + width] = v.to_bytes(width, "little")
        elif r < 0.75:
            pos = rng.randrange(start, end)
            saved.append((pos, bytes(buf[pos:pos + 1])))
            buf[pos] = rng.randrange(256)
        elif r < 0.85:
            pos = rng.randrange(start, end)
            saved.append((pos, bytes(buf[pos:pos + 1])))
            buf[pos] ^= 1 << rng.randrange(8)
        elif r < 0.95:
            pos = rng.randrange(start, end - 4) & ~1
            saved.append((pos, bytes(buf[pos:pos + 4])))
            buf[pos:pos + 4] = rng.choice(BOUNDARY32).to_bytes(4, "little")
        else:
            if end - start < 64:
                continue
            a = start + (rng.randrange(0, end - start - 32) & ~31)
            b = start + (rng.randrange(0, end - start - 32) & ~31)
            saved.append((b, bytes(buf[b:b + 32])))
            buf[b:b + 32] = buf[a:a + 32]
    return saved


def restore(buf: bytearray, saved: list[tuple[int, bytes]]) -> None:
    for pos, old in reversed(saved):
        buf[pos:pos + len(old)] = old


# ---------------------------------------------------------------------------
# 기준 이미지와 변조 영역
# ---------------------------------------------------------------------------

BPB_HOT = [(11, 2), (13, 1), (14, 2), (16, 1), (17, 2), (19, 2), (21, 1), (22, 2), (32, 4), (36, 4), (37, 1),
           (40, 2), (44, 4), (48, 2), (50, 2), (65, 1), (0, 1), (510, 1)]
FAT_DIRENT_HOT = [(0, 1), (11, 1), (12, 1), (13, 1), (14, 2), (16, 2), (18, 2), (20, 2), (22, 2), (24, 2),
                  (26, 2), (28, 4), (1, 2)]
EXFAT_BOOT_HOT = [(64, 8), (72, 8), (80, 4), (84, 4), (88, 4), (92, 4), (96, 4), (104, 2), (106, 2), (108, 1),
                  (109, 1), (110, 1), (112, 1)]
EXFAT_DIRENT_HOT = [(0, 1), (1, 1), (2, 2), (3, 1), (4, 2), (8, 4), (8, 8), (12, 4), (20, 4), (22, 1), (24, 8),
                    (2, 4)]
MBR_HOT = [(446 + 16 * i + o, w) for i in range(4) for o, w in ((0, 1), (4, 1), (8, 4), (12, 4))]
GPT_HDR_HOT = [(8, 4), (12, 4), (16, 4), (24, 8), (32, 8), (40, 8), (48, 8), (72, 8), (80, 4), (84, 4), (88, 4)]
GPT_ENT_HOT = [(0, 4), (32, 8), (40, 8), (48, 8), (56, 2)]

def _fat_tree(b: Any) -> None:
    b.mkdir("/DCIM")
    b.mkdir("/DCIM/100CAM")
    b.add_file("/DCIM/clip0001.mp4", pattern(3000, 1))
    b.add_file("/DCIM/100CAM/Long recording name 0002.mp4", pattern(5000, 2))
    b.add_file("/DCIM/100CAM/frag.bin", pattern(4000, 3), clusters=None)
    b.add_file("/README.TXT", b"readme")
    b.add_file("/deleted file.bin", pattern(2500, 4))
    b.delete("/deleted file.bin")
    b.mkdir("/old dir")
    b.add_file("/old dir/inner.bin", pattern(900, 5))
    b.delete("/old dir/inner.bin")
    b.delete("/old dir")


def fat_case(maker: Any) -> tuple[bytearray, list[tuple[int, int]]]:
    b = maker()
    _fat_tree(b)
    img = bytearray(b.image())
    width = {12: 2, 16: 2, 32: 4}[b.fat_type]
    fat_used = (b.fat_off, b.fat_off + max(64, (max(b.used | {2}) + 2) * 4))
    regions: list = [(0, 512, 0, BPB_HOT), (0, b.fat_off), fat_used + (width, [(0, width)])]
    if b.fat_type != 32:
        regions.append((b.root_off, b.root_off + min(b.root_secs * b.bps, 32 * 40), 32, FAT_DIRENT_HOT))
    else:
        regions.append((b.fat_off + b.fatsz * b.bps, b.fat_off + b.fatsz * b.bps + 256))  # FAT 사본 2
    dir_clusters = {c for d in b.dirs.values() for c in d.clusters}
    for rec in b.files.values():
        if rec.is_dir:
            dir_clusters.update(rec.clusters)
    for c in sorted(dir_clusters):
        regions.append((b.coff(c), b.coff(c) + min(b.cs, 32 * 40), 32, FAT_DIRENT_HOT))
    return img, regions


def exfat_case() -> tuple[bytearray, list[tuple[int, int]]]:
    b = exfat_small()
    b.mkdir("/DCIM", nclusters=2)
    b.add_file("/DCIM/clip0001.mp4", pattern(9000, 1), offsets=(540, 540, 540))
    base = max(b.used) + 1
    b.add_file("/DCIM/frag.mp4", pattern(3 * 4096, 2), contiguous=False, clusters=[base, base + 2, base + 4])
    b.add_file("/DCIM/pre.mp4", pattern(3000, 3), residual=pattern(5000, 4))
    b.add_file("/DCIM/a very long recording name for entries.bin", pattern(100, 5))
    b.delete("/DCIM/frag.mp4")
    b.mkdir("/old", nclusters=1)
    b.add_file("/old/x.bin", pattern(500, 6))
    b.delete("/old/x.bin")
    b.delete("/old")
    img = bytearray(b.image())
    bps = b.bps
    regions: list = [(0, 512, 0, EXFAT_BOOT_HOT), (0, 24 * bps),
                     (b.fat_off * bps, b.fat_off * bps + (max(b.used) + 2) * 4, 4, [(0, 4)])]
    for c in b.bitmap_clusters + b.upcase_clusters:
        regions.append((b.coff(c), b.coff(c) + min(b.cs, 512)))
    dir_clusters = {c for d in b.dirs.values() for c in d.clusters} | set(b.root_clusters)
    for rec in b.files.values():
        if rec.is_dir:
            dir_clusters.update(rec.clusters)
    for c in sorted(dir_clusters):
        regions.append((b.coff(c), b.coff(c) + min(b.cs, 32 * 48), 32, EXFAT_DIRENT_HOT))
    return img, regions


def mbr_case() -> tuple[bytearray, list[tuple[int, int]]]:
    f = fat12_small()
    _fat_tree(f)
    v1 = f.image()
    e = exfat_small()
    e.add_file("/x.bin", pattern(5000, 9))
    v2 = e.image()
    p1 = 64
    ext = p1 + len(v1) // 512
    l1 = ext + 63
    total = l1 + len(v2) // 512 + 8
    img = bytearray(total * 512)
    img[p1 * 512:p1 * 512 + len(v1)] = v1
    img[l1 * 512:l1 * 512 + len(v2)] = v2
    put_mbr(img, [(0x01, p1, len(v1) // 512), (0x0F, ext, total - ext)])
    put_ebr(img, ext, (0x07, 63, len(v2) // 512), None)
    regions: list = [(0, 512, 0, MBR_HOT), (ext * 512, ext * 512 + 512, 0, MBR_HOT),
                     (p1 * 512, p1 * 512 + 512, 0, BPB_HOT), (l1 * 512, l1 * 512 + 512, 0, EXFAT_BOOT_HOT),
                     (p1 * 512, p1 * 512 + 4096), (l1 * 512, l1 * 512 + 8192)]
    return img, regions


def gpt_case() -> tuple[bytearray, list[tuple[int, int]]]:
    e = exfat_small()
    e.add_file("/DCIM.bin", pattern(4000, 7))
    vol = e.image()
    first = 2048
    total = first + len(vol) // 512 + 64
    img = bytearray(total * 512)
    img[first * 512:first * 512 + len(vol)] = vol
    put_gpt(img, [GptPart(first, first + len(vol) // 512 - 1), GptPart(first + len(vol) // 512, total - 40)])
    regions: list = [(0, 512, 0, MBR_HOT), (512, 1024, 0, GPT_HDR_HOT), (1024, 1024 + 4 * 128, 128, GPT_ENT_HOT),
                     ((total - 1) * 512, total * 512, 0, GPT_HDR_HOT), (0, 34 * 512),
                     ((total - 33) * 512, total * 512), (first * 512, first * 512 + 512, 0, EXFAT_BOOT_HOT),
                     (first * 512, first * 512 + 12 * 512)]
    return img, regions


CASES = {
    "fat12": (lambda: fat_case(fat12_small), 1500),
    "fat16": (lambda: fat_case(fat16_small), 1000),
    "fat32": (lambda: fat_case(fat32_small), 500),
    "exfat": (exfat_case, 1500),
    "mbr": (mbr_case, 800),
    "gpt": (gpt_case, 800),
}


@pytest.mark.parametrize("name", list(CASES))
def test_mutation_fuzz(name):
    build, iterations = CASES[name]
    buf, regions = build()
    original = bytes(buf)
    surface(buf, deep=True)  # 손상 전에도 깨끗해야 한다
    rng = random.Random(f"pweh-fs-{name}")
    slowest = 0.0
    for i in range(iterations):
        saved = mutate(buf, regions, rng, rng.randint(1, 12))
        t0 = time.monotonic()
        try:
            surface(buf, deep=(i % 3 == 0))
        except Internal as e:
            raise AssertionError(f"{name} 반복 {i}: internal_error — {e}") from e
        dt_ = time.monotonic() - t0
        slowest = max(slowest, dt_)
        assert dt_ < ITER_TIME_CAP, f"{name} 반복 {i} 이 {dt_:.1f}s 걸렸습니다"
        restore(buf, saved)
    assert bytes(buf) == original


@pytest.mark.parametrize("name", ["fat12", "fat16", "exfat", "mbr", "gpt"])
def test_truncation_fuzz(name):
    build, _ = CASES[name]
    buf, _regions = build()
    rng = random.Random(f"pweh-fs-trunc-{name}")
    cuts = sorted({rng.randrange(0, len(buf)) for _ in range(25)} | {0, 1, 511, 512, 4096})
    for cut in cuts:
        piece = bytearray(buf[:cut])
        t0 = time.monotonic()
        try:
            surface(piece, deep=True)
        except Internal as e:
            raise AssertionError(f"{name} 길이 {cut}: internal_error — {e}") from e
        assert time.monotonic() - t0 < ITER_TIME_CAP


def test_guard_converts_unexpected_exceptions():
    """안전망: 예상하지 못한 예외는 FsError(internal_error) 로 바뀐다 (제너레이터 포함)."""
    from pweh.fs.common import guard, guard_gen

    @guard
    def boom() -> None:
        raise IndexError("x")

    @guard_gen
    def gen():
        yield 1
        raise KeyError("y")

    with pytest.raises(FsError) as ei:
        boom()
    assert ei.value.reason == "internal_error"
    it = gen()
    assert next(it) == 1
    with pytest.raises(FsError) as ei:
        next(it)
    assert ei.value.reason == "internal_error"
