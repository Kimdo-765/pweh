"""FAT 항목 배열·exFAT 할당 비트맵 읽기와 메모리 비트 집합.

- `FatTable`: FAT12/16 은 표 전체(클러스터 수로 묶여 최대 약 128 KiB)를 읽어 배열로 풀고,
  FAT32·exFAT 는 항목 65536 개(256 KiB) 조각을 LRU 로 읽는다. FAT12 항목은 바이트 경계에 걸치므로 반드시 전체를 읽는다.
  FAT32 항목의 상위 4비트는 예약이라 읽을 때 지운다. 읽을 수 없는 항목(표나 이미지 끝 너머)은 None.
- `ClusterBitmap`: exFAT 할당 비트맵(비트 i = 클러스터 i+2). 비트맵 자체가 클러스터 체인에 흩어질 수 있어 구간 목록으로 찾는다.
- `BitSet`: 클러스터 참조 표시용 bytearray 비트 집합.
- `follow_chain`: 체인 따라가기. 호출의 예산(Budget)을 4096 걸음마다 세고, 다 되면(또는 취소되면) status='limit', capped='time'|'steps'|'cancelled' 로 멈춘다.
"""

from __future__ import annotations

import bisect
import re
import sys
from array import array
from collections import OrderedDict
from typing import Any, Iterator

__all__ = ["FatTable", "ClusterBitmap", "BitSet", "Chain", "follow_chain"]

_LITTLE = sys.byteorder == "little"
_MASK_TOP_NIBBLE = bytes(b & 0x0F for b in range(256))


class FatTable:
    """FAT 항목 읽기 (값 해석은 호출자가 한다)."""

    CHUNK_ENTRIES = 65536
    MAX_CHUNKS = 64  # FAT32/exFAT: 최대 16 MiB 캐시

    def __init__(self, src: Any, offset: int, length_bytes: int, width: int, max_entry: int, *,
                 mask_top_nibble: bool = False) -> None:
        if width not in (12, 16, 32):
            raise ValueError("width")
        self.src = src
        self.offset = offset
        self.width = width
        self.max_entry = max(0, max_entry)
        self.mask_top_nibble = mask_top_nibble
        capacity = (max(0, length_bytes) * 8) // width
        self.entries = min(self.max_entry + 1, capacity)  # 표가 담을 수 있는 항목 수
        self._cache: "OrderedDict[int, array]" = OrderedDict()
        self._whole: array | None = None
        if width in (12, 16):
            self._whole = self._load_small()
            self.readable = len(self._whole)
        else:
            avail = max(0, min(self.entries * 4, src.size - offset)) if offset < src.size else 0
            self.readable = avail // 4  # 이미지 안에 실제로 있는 항목 수

    # -- 적재 --
    def _load_small(self) -> array:
        if self.width == 16:
            need = self.entries * 2
            data = self.src.read_clamped(self.offset, need) if self.offset < self.src.size else b""
            data = data[: len(data) // 2 * 2]
            arr = array("H")
            arr.frombytes(data)
            if not _LITTLE:  # pragma: no cover
                arr.byteswap()
            return arr
        # FAT12: 항목 n 은 바이트 n*3/2 에서 시작하는 12비트
        need = (self.entries * 3 + 1) // 2
        data = self.src.read_clamped(self.offset, need) if self.offset < self.src.size else b""
        arr = array("H")
        n_ok = (len(data) * 2) // 3
        n_ok = min(n_ok, self.entries)
        for n in range(n_ok):
            o = n + (n >> 1)
            if o + 1 >= len(data):
                break
            v = data[o] | (data[o + 1] << 8)
            arr.append((v >> 4) if (n & 1) else (v & 0x0FFF))
        return arr

    def _chunk(self, k: int) -> array:
        arr = self._cache.get(k)
        if arr is not None:
            self._cache.move_to_end(k)
            return arr
        first = k * self.CHUNK_ENTRIES
        count = max(0, min(self.CHUNK_ENTRIES, self.readable - first))
        data = self.src.read_clamped(self.offset + first * 4, count * 4) if count else b""
        data = data[: len(data) // 4 * 4]
        if self.mask_top_nibble and data:
            buf = bytearray(data)
            buf[3::4] = buf[3::4].translate(_MASK_TOP_NIBBLE)
            data = bytes(buf)
        arr = array("I") if array("I").itemsize == 4 else array("L")
        arr.frombytes(data)
        if not _LITTLE:  # pragma: no cover
            arr.byteswap()
        self._cache[k] = arr
        if len(self._cache) > self.MAX_CHUNKS:
            self._cache.popitem(last=False)
        return arr

    # -- 조회 --
    def get(self, n: int) -> int | None:
        if n < 0 or n >= self.entries:
            return None
        if self._whole is not None:
            return self._whole[n] if n < len(self._whole) else None
        if n >= self.readable:
            return None
        arr = self._chunk(n // self.CHUNK_ENTRIES)
        i = n % self.CHUNK_ENTRIES
        return arr[i] if i < len(arr) else None

    def slices(self, a: int, b: int) -> Iterator[tuple[int, array]]:
        """[a, b) 범위를 (첫 항목 번호, 값 배열 조각) 으로. 읽을 수 없는 꼬리는 빠진다."""
        a = max(0, a)
        b = min(b, self.entries)
        if a >= b:
            return
        if self._whole is not None:
            end = min(b, len(self._whole))
            if a < end:
                yield a, self._whole[a:end]
            return
        b = min(b, self.readable)
        n = a
        while n < b:
            k = n // self.CHUNK_ENTRIES
            arr = self._chunk(k)
            base = k * self.CHUNK_ENTRIES
            i0 = n - base
            i1 = min(len(arr), b - base)
            if i1 <= i0:
                return
            yield n, arr[i0:i1]
            n = base + i1

    def count_value(self, a: int, b: int, value: int) -> int:
        return sum(sl.count(value) for _, sl in self.slices(a, b))


class ClusterBitmap:
    """exFAT 할당 비트맵 읽기. extents: [(볼륨 오프셋, 길이)] 비트맵 바이트가 놓인 순서대로."""

    CHUNK = 64 * 1024
    MAX_CHUNKS = 64

    def __init__(self, src: Any, extents: list[tuple[int, int]], nbits: int) -> None:
        self.src = src
        self.nbits = max(0, nbits)
        self._starts: list[int] = []  # 논리 바이트 시작
        self._offs: list[int] = []
        self._lens: list[int] = []
        pos = 0
        for off, length in extents:
            if length <= 0:
                continue
            self._starts.append(pos)
            self._offs.append(off)
            self._lens.append(length)
            pos += length
        self.nbytes = pos
        self._cache: "OrderedDict[int, bytes]" = OrderedDict()

    def _read_logical(self, start: int, length: int) -> bytes:
        out = bytearray()
        pos = start
        end = min(start + length, self.nbytes)
        while pos < end:
            i = bisect.bisect_right(self._starts, pos) - 1
            if i < 0:
                break
            within = pos - self._starts[i]
            take = min(self._lens[i] - within, end - pos)
            if take <= 0:
                break
            data = self.src.read_clamped(self._offs[i] + within, take)
            out += data
            if len(data) < take:
                break
            pos += take
        return bytes(out)

    def _chunk(self, k: int) -> bytes:
        data = self._cache.get(k)
        if data is not None:
            self._cache.move_to_end(k)
            return data
        data = self._read_logical(k * self.CHUNK, self.CHUNK)
        self._cache[k] = data
        if len(self._cache) > self.MAX_CHUNKS:
            self._cache.popitem(last=False)
        return data

    def get(self, bit: int) -> bool | None:
        """비트 값. 범위 밖이거나 읽을 수 없으면 None."""
        if bit < 0 or bit >= self.nbits:
            return None
        byte = bit >> 3
        data = self._chunk(byte // self.CHUNK)
        i = byte % self.CHUNK
        if i >= len(data):
            return None
        return bool(data[i] & (1 << (bit & 7)))

    def readable_bits(self) -> int:
        return min(self.nbits, self.nbytes * 8)

    def count_range(self, a: int, b: int) -> tuple[int, int]:
        """비트 [a, b) 중 켜진 비트 수와 실제로 읽은 비트 수."""
        a = max(0, a)
        b = min(b, self.nbits)
        if a >= b:
            return 0, 0
        ones = 0
        seen = 0
        for bit0, data in self.iter_bytes(a, b):
            lo = max(a, bit0)
            hi = min(b, bit0 + 8 * len(data))
            if lo >= hi:
                continue
            sb, eb = (lo - bit0) >> 3, (hi - bit0 - 1) >> 3
            if sb == eb:
                mask = ((1 << (hi - lo)) - 1) << ((lo - bit0) & 7)
                ones += bin(data[sb] & mask).count("1")
            else:
                ones += bin(data[sb] >> ((lo - bit0) & 7)).count("1")
                hi_bits = ((hi - bit0) & 7) or 8
                ones += bin(data[eb] & ((1 << hi_bits) - 1)).count("1")
                if eb > sb + 1:
                    ones += sum(data[sb + 1:eb].translate(_POPCOUNT))
            seen += hi - lo
        return ones, seen

    def scan_free(self, first: int, need: int, max_scan: int, *, max_runs: int | None = None,
                  budget: Any = None) -> dict[str, Any]:
        """비트 first 부터 최대 max_scan 비트 안에서 0 비트(빈 클러스터)를 need 개까지 모은다 (건너뛰기 후보용).

        반환: {runs: [[시작 비트, 길이]…], got, skipped(건너뛴 1 비트), scanned, stop: None | 'unreadable' | 'max_runs' | 'budget'}.
        바이트가 통째로 0xFF·0x00 인 구간은 정규식으로 한 번에 넘긴다(C 수준) — 비트마다 파이썬을 돌지 않는다.
        예산은 64 비트를 1 단계로 센다.
        """
        runs: list[list[int]] = []
        got = skipped = 0
        stop: str | None = None
        first = max(0, int(first))
        end = min(self.nbits, first + max(0, int(max_scan)))
        pos = first

        def add(start: int, k: int) -> bool:
            nonlocal got
            if runs and runs[-1][0] + runs[-1][1] == start:
                runs[-1][1] += k
            else:
                if max_runs is not None and len(runs) >= max_runs:
                    return False
                runs.append([start, k])
            got += k
            return True

        while pos < end and got < need and stop is None:
            k = (pos >> 3) // self.CHUNK
            data = self._chunk(k)
            cbase = k * self.CHUNK * 8
            cend = min(end, cbase + 8 * len(data))
            if pos >= cend:
                stop = "unreadable"
                break
            if budget is not None:
                budget.tick(((cend - pos) >> 6) + 1)
                if budget.expired():
                    stop = "budget"
                    break
            while pos < cend and got < need:
                j = (pos - cbase) >> 3
                b = data[j]
                boff = pos & 7
                if boff == 0 and pos + 8 <= cend and b in (0x00, 0xFF):
                    m = (_NOT_FF if b == 0xFF else _NOT_00).search(data, j)
                    npos = min(cend, cbase + 8 * (m.start() if m else len(data)))
                    if b == 0xFF:
                        skipped += npos - pos
                        pos = npos
                    else:
                        take = min(npos - pos, need - got)
                        if not add(pos, take):
                            stop = "max_runs"
                            break
                        pos += take
                    continue
                if (b >> boff) & 1:
                    skipped += 1
                elif not add(pos, 1):
                    stop = "max_runs"
                    break
                pos += 1
        return {"runs": runs, "got": got, "skipped": skipped, "scanned": pos - first, "stop": stop}

    def iter_bytes(self, first_bit: int = 0, last_bit: int | None = None) -> Iterator[tuple[int, bytes]]:
        """(첫 비트 번호(8의 배수), 바이트 조각) — 비트 수 세기·훑기용."""
        last = self.nbits if last_bit is None else min(last_bit, self.nbits)
        byte = max(0, first_bit) >> 3
        end_byte = (last + 7) >> 3
        while byte < end_byte:
            k = byte // self.CHUNK
            data = self._chunk(k)
            i0 = byte - k * self.CHUNK
            i1 = min(len(data), end_byte - k * self.CHUNK)
            if i1 <= i0:
                return
            yield byte * 8, data[i0:i1]
            byte = k * self.CHUNK + i1


_POPCOUNT = bytes(bin(i).count("1") for i in range(256))
_NOT_FF = re.compile(rb"[^\xff]")
_NOT_00 = re.compile(rb"[^\x00]")
_TICK = 4096  # follow_chain 이 예산을 세는 걸음 단위


class Chain:
    """클러스터 체인 (연속 구간으로 압축, 구간은 array 로 보관)과 끝난 이유."""

    __slots__ = ("starts", "lens", "count", "status", "end_value", "capped")

    def __init__(self) -> None:
        self.starts = array("Q")
        self.lens = array("Q")
        self.count = 0
        self.status = "ok"
        self.end_value: int | None = None
        self.capped: str | None = None  # 예산 때문에 멈췄으면 'time' | 'steps' | 'cancelled' (status 는 'limit')

    def extends(self, c: int) -> bool:
        return bool(self.lens) and self.starts[-1] + self.lens[-1] == c

    def add(self, c: int) -> None:
        if self.extends(c):
            self.lens[-1] += 1
        else:
            self.starts.append(c)
            self.lens.append(1)
        self.count += 1

    def truncate(self, n: int) -> None:
        """앞의 n 개 클러스터만 남긴다."""
        if n >= self.count:
            return
        keep = max(0, n)
        for i in range(len(self.lens)):
            if keep <= self.lens[i]:
                if keep:
                    self.lens[i] = keep
                    del self.starts[i + 1:]
                    del self.lens[i + 1:]
                else:
                    del self.starts[i:]
                    del self.lens[i:]
                break
            keep -= self.lens[i]
        self.count = max(0, n)

    def clusters(self) -> Iterator[int]:
        for s, n in zip(self.starts, self.lens):
            yield from range(s, s + n)


_STATUS_BY_KIND = {"free": "zeroed", "bad": "broken", "unreadable": "unreadable"}
_EXACT_SEEN = 65536  # 처음 이만큼은 set 으로 정확히 순환 검사 (메모리 수 MB 상한)


def _cycle_start(get: Any, start: int, lam: int) -> int:
    """순환 길이 lam 을 알 때 체인에서 순환이 시작하는 위치 μ (같은 체인을 다시 따라감, 추가 메모리 없음)."""
    hare = start
    for _ in range(lam):
        nxt = get(hare)
        if nxt is None:
            return 0
        hare = nxt
    tort = start
    mu = 0
    while tort != hare:
        a, b = get(tort), get(hare)
        if a is None or b is None:
            break
        tort, hare = a, b
        mu += 1
    return mu


def follow_chain(get: Any, classify: Any, start: int, limit: int, max_cluster: int, *,
                 max_runs: int | None = None, budget: Any = None) -> Chain:
    """FAT 체인을 따라간다. get(n) → 항목 값|None, classify(v) → eoc/next/free/bad/unreadable/invalid.

    상태: ok(끝 표시), limit(한도 도달 — 크기보다 김, 또는 예산이 다 됨: capped='time'|'steps'), zeroed(빈 항목),
    broken(불량 표시), unreadable(FAT 이 이미지 밖), out-of-range(범위 밖 값), cycle(이미 지난 클러스터),
    too_fragmented(구간 수가 max_runs 를 넘음), empty(시작 0).
    순환 검사: 처음 65536 클러스터는 set 으로 정확히, 그 뒤는 Brent 알고리즘(상수 메모리)으로 찾고 반복된 꼬리를 잘라
    체인에는 서로 다른 클러스터만 남긴다. 이미지가 주장하는 클러스터 수에 비례하는 메모리를 쓰지 않는다.
    budget 을 주면 걸음 수를 세고(4096 걸음마다 확인) 다 되면 멈춘다 — 긴 체인 하나가 호출 전체의 예산을 넘기지 못한다.
    """
    ch = Chain()
    if start == 0:
        ch.status = "empty"
        return ch
    if not 2 <= start <= max_cluster:
        ch.status = "out-of-range"
        ch.end_value = start
        return ch
    if budget is not None and budget.expired():
        ch.status = "limit"
        ch.capped = budget.reason
        return ch
    seen: set[int] = set()
    tortoise = -1
    power = 1
    lam = 0
    c = start
    pending = 0
    while True:
        if ch.count >= limit:
            ch.status = "limit"
            break
        if budget is not None:
            pending += 1
            if pending >= _TICK:
                budget.tick(pending)
                pending = 0
                if budget.expired():
                    ch.status = "limit"
                    ch.capped = budget.reason
                    break
        if c in seen:
            ch.status = "cycle"
            break
        if ch.count < _EXACT_SEEN:
            seen.add(c)
        elif tortoise < 0:
            tortoise, power, lam = c, 1, 0
        else:
            lam += 1
            if c == tortoise:
                ch.truncate(_cycle_start(get, start, lam) + lam)
                ch.status = "cycle"
                break
            if lam == power:
                tortoise, power, lam = c, power << 1, 0
        if max_runs is not None and len(ch.starts) >= max_runs and not ch.extends(c):
            ch.status = "too_fragmented"
            break
        ch.add(c)
        v = get(c)
        k = classify(v)
        if k == "eoc":
            ch.status = "ok"
            break
        if k == "next":
            c = v
            continue
        ch.status = _STATUS_BY_KIND.get(k, "out-of-range")
        ch.end_value = v
        break
    if budget is not None and pending:
        budget.tick(pending)
    return ch


class BitSet:
    """0..n-1 비트 집합."""

    __slots__ = ("n", "buf")

    def __init__(self, n: int) -> None:
        self.n = max(0, n)
        self.buf = bytearray((self.n + 7) >> 3)

    def test(self, i: int) -> bool:
        return 0 <= i < self.n and bool(self.buf[i >> 3] & (1 << (i & 7)))

    def set(self, i: int) -> bool:
        """비트를 켜고, 이미 켜져 있었으면 True."""
        if not 0 <= i < self.n:
            return False
        m = 1 << (i & 7)
        j = i >> 3
        old = self.buf[j] & m
        self.buf[j] |= m
        return bool(old)

    def count(self) -> int:
        return sum(self.buf.translate(_POPCOUNT))

    def count_range(self, a: int, b: int) -> int:
        """비트 [a, b) 중 켜진 비트 수 (바이트 단위 popcount — 클러스터마다 파이썬을 돌지 않는다)."""
        a = max(0, a)
        b = min(b, self.n)
        if a >= b:
            return 0
        sb, eb = a >> 3, (b - 1) >> 3
        buf = self.buf
        if sb == eb:
            return bin(buf[sb] & (((1 << (b - a)) - 1) << (a & 7))).count("1")
        ones = bin(buf[sb] >> (a & 7)).count("1")
        ones += bin(buf[eb] & ((1 << ((b & 7) or 8)) - 1)).count("1")
        if eb > sb + 1:
            ones += sum(buf[sb + 1:eb].translate(_POPCOUNT))
        return ones
