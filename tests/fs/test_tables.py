"""pweh.fs.tables: 체인 따라가기(상수 메모리 순환 검사, 구간 수 상한), FAT12 항목 풀기, 비트맵 범위 세기."""

from __future__ import annotations

import struct
import tracemalloc

from fs.builders import fat12_small, fat16_small, pattern
from pweh.fs import BytesReader, FatVolume
from pweh.fs.tables import BitSet, ClusterBitmap, FatTable, follow_chain

EOC = 0xFFFFFFFF


def classify(v):
    if v is None:
        return "unreadable"
    if v == EOC:
        return "eoc"
    if v == 0:
        return "free"
    return "next"


def linear(start: int, n: int, back_to: int | None = None):
    """start..start+n-1 을 차례로 잇는 체인. back_to 가 있으면 마지막이 그 클러스터로 돌아간다(순환)."""
    last = start + n - 1

    def get(c: int) -> int | None:
        if c < start or c > last:
            return None
        if c < last:
            return c + 1
        return EOC if back_to is None else back_to

    return get


def test_long_chain_does_not_allocate_by_claimed_cluster_count():
    """헤더가 클러스터 2^32 개를 주장해도 순환 검사 메모리는 체인 길이와 무관하게 작다 (예전 BitSet(max_cluster) 대체)."""
    get = linear(10, 70_000)
    tracemalloc.start()
    try:
        ch = follow_chain(get, classify, 10, 10_000_000, 2 ** 32)
        _cur, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    assert ch.status == "ok" and ch.count == 70_000 and list(ch.starts) == [10] and list(ch.lens) == [70_000]
    assert peak < 16 << 20, peak


def test_cycle_entirely_after_exact_window_is_trimmed():
    start = 100
    get = linear(start, 70_000, back_to=start + 66_000)  # μ=66000, λ=4000 (둘 다 정확 검사 창 밖)
    ch = follow_chain(get, classify, start, 10_000_000, 2 ** 32)
    assert ch.status == "cycle"
    assert ch.count == 70_000 and list(ch.lens) == [70_000]  # 반복된 꼬리는 잘려 서로 다른 클러스터만 남는다


def test_cycle_back_into_exact_window_and_small_cycle():
    ch = follow_chain(linear(5, 70_000, back_to=105), classify, 5, 10_000_000, 2 ** 20)
    assert ch.status == "cycle" and ch.count == 70_000
    ch = follow_chain(linear(5, 10, back_to=8), classify, 5, 1000, 1000)
    assert ch.status == "cycle" and ch.count == 10


def test_limit_and_max_runs():
    ch = follow_chain(linear(2, 50), classify, 2, 20, 1000)
    assert ch.status == "limit" and ch.count == 20
    frag = {2 + 2 * i: (2 + 2 * (i + 1) if i < 99 else EOC) for i in range(100)}  # 1칸씩 띄운 단편화 체인
    ch = follow_chain(frag.get, classify, 2, 10_000, 1000, max_runs=5)
    assert ch.status == "too_fragmented" and len(ch.starts) == 5 and ch.count == 5
    ch = follow_chain(frag.get, classify, 2, 10_000, 1000)
    assert ch.status == "ok" and ch.count == 100
    assert follow_chain(frag.get, classify, 0, 10, 1000).status == "empty"
    assert follow_chain(frag.get, classify, 5000, 10, 1000).status == "out-of-range"


def test_fat12_entries_unpacked_like_builder():
    b = fat12_small()
    b.add_file("/A.BIN", pattern(9000, 1), clusters=[7, 8, 30, 31, 2040])
    img = b.image()
    t = FatTable(BytesReader(img), b.fat_off, b.fatsz * b.bps, 12, b.max_cluster)
    assert [t.get(c) for c in (7, 8, 30, 31, 2040)] == [8, 30, 31, 2040, 0xFFF]
    assert t.get(9) == 0 and t.get(b.max_cluster + 1) is None


def test_bitmap_count_range_and_bitset():
    data = bytes([0b10110001, 0xFF, 0x00, 0b00000001])
    bm = ClusterBitmap(BytesReader(data), [(0, 4)], 30)
    assert bm.count_range(0, 8) == (4, 8)
    assert bm.count_range(3, 13) == (8, 10)  # 비트 3..12: 0,1,1,0,1 + 1×5
    assert bm.count_range(16, 30) == (1, 14)
    assert bm.get(0) is True and bm.get(1) is False and bm.get(29) is False and bm.get(30) is None
    bs = BitSet(10)
    assert bs.set(3) is False and bs.set(3) is True and bs.test(3) and not bs.test(4)
    assert bs.set(99) is False and bs.count() == 1


def test_fat_chain_candidate_crossing_into_live_file_is_low():
    b = fat16_small()
    live = b.add_file("/LIVE.BIN", pattern(3 * 1024, 1), clusters=[300, 301, 302])
    rec = b.add_file("/OLD.BIN", pattern(3 * 1024, 2), clusters=[200, 201, 202])
    d = b.dirs["/"]
    s = rec.slots[-1]
    d.slots[s] = b"\xe5" + d.slots[s][1:]  # 항목만 지우고 FAT 은 남김
    b.files.pop("/OLD.BIN")
    b.set_fat(201, 301)  # 남은 체인이 중간에 살아 있는 파일 체인으로 들어간다 (200 → 201 → 301 → 302)
    v = FatVolume(BytesReader(b.image()))
    e = next(x for x in v.list_dir()["entries"] if x["deleted"])
    fc = {c["method"]: c for c in v.candidates(e["ref"])}["fat-chain"]
    assert fc["confidence"] == "low" and fc["conflicts"]["live_owned"] == 1
    assert live.clusters == [300, 301, 302]


def test_bitmap_scan_free_matches_naive_loop():
    """빈 비트 모으기(바이트 통째 건너뛰기)가 비트마다 도는 단순 구현과 같은 결과를 낸다."""
    import random

    rng = random.Random(7)
    for trial in range(300):
        nbytes = rng.randrange(1, 300)
        style = trial % 3
        if style == 0:
            data = bytes(rng.randrange(256) for _ in range(nbytes))
        elif style == 1:
            data = bytes(rng.choice((0, 0xFF, rng.randrange(256))) for _ in range(nbytes))
        else:
            data = bytes([0xFF] * (nbytes // 2) + [0] * (nbytes - nbytes // 2))
        nbits = rng.randrange(1, nbytes * 8 + 1)
        bm = ClusterBitmap(BytesReader(data), [(0, nbytes)], nbits)
        first = rng.randrange(0, nbits)
        need = rng.randrange(1, nbits + 2)
        max_scan = rng.randrange(1, nbits * 2)
        got = bm.scan_free(first, need, max_scan)
        runs: list[list[int]] = []
        n_got = skipped = 0
        pos = first
        end = min(nbits, first + max_scan)
        while pos < end and n_got < need:
            if data[pos >> 3] >> (pos & 7) & 1:
                skipped += 1
            else:
                if runs and runs[-1][0] + runs[-1][1] == pos:
                    runs[-1][1] += 1
                else:
                    runs.append([pos, 1])
                n_got += 1
            pos += 1
        assert (got["runs"], got["got"], got["skipped"], got["scanned"]) == (runs, n_got, skipped, pos - first), trial


def test_fat_skip_allocated_matches_naive_free_walk():
    """FAT skip-allocated(array.index 로 할당 구간 건너뛰기)가 클러스터마다 도는 단순 구현과 같은 구간을 고른다."""
    import random

    rng = random.Random(11)
    for trial in range(25):
        b = fat16_small()
        cs = b.cs
        live = sorted(rng.sample(range(150, 900), rng.randrange(0, 300)))
        if live:
            b.add_file("/LIVE.BIN", b"x" * cs * len(live), clusters=live)
        n = rng.randrange(1, 200)
        start = rng.randrange(100, 140)
        while start in live:
            start += 1
        rec = b.add_file("/DEL.BIN", pattern(n * cs, trial), clusters=[c for c in range(1000, 1000 + n)])
        d = b.dirs["/"]
        s = rec.slots[-1]
        raw = bytearray(d.slots[s])
        raw[0] = 0xE5
        struct.pack_into("<H", raw, 26, start)  # 삭제 항목이 start 에서 시작했다고 가정 (FAT 체인은 지움)
        d.slots[s] = bytes(raw)
        for c in rec.clusters:
            b.set_fat(c, 0)
        v = FatVolume(BytesReader(b.image()))
        e = next(x for x in v.list_dir()["entries"] if x["deleted"])
        plans = {p["method"]: p for p in v.candidates(e["ref"])}
        alloc = set(live) | {b.dirs["/"].clusters[0]} if b.dirs["/"].clusters else set(live)
        runs: list[list[int]] = []
        got = skipped = 0
        c = start
        while got < n and c <= b.max_cluster:
            if c in alloc:
                skipped += 1
            else:
                if runs and runs[-1][0] + runs[-1][1] == c:
                    runs[-1][1] += 1
                else:
                    runs.append([c, 1])
                got += 1
            c += 1
        sk = plans["skip-allocated"]
        assert sk["runs"] == runs[:64] and sk["conflicts"]["skipped_allocated"] == skipped, trial
