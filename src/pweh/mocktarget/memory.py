"""시뮬레이터 메모리 모델: 희소 RAM, SPI NOR 플래시, U-Boot 숫자 파싱 헬퍼."""

from __future__ import annotations

import hashlib
import threading
from typing import Callable

ADDR_MASK = 0xFFFFFFFF


def simple_strtoul(text: str, base: int = 16) -> tuple[int, str]:
    """U-Boot ``simple_strtoul`` 과 같은 규칙으로 앞부분 숫자를 해석한다.

    반환: (값, 소비하지 못한 나머지 문자열). 값은 32비트로 잘린다 (unsigned long, 32비트 SoC).
    - ``0x`` 접두어는 base 16/0 일 때 허용 (소문자 x 만 — 2010.06~2016.11 lib/vsprintf.c 동작).
    - base 0 이면 ``0`` 접두어 → 8진수, 그 외 10진수.
    - 숫자가 하나도 없으면 0 과 원문 전체를 돌려준다.
    """
    s = text
    i = 0
    if base == 0:
        if s[:1] == "0":
            if s[1:2] == "x" and len(s) > 2 and s[2] in "0123456789abcdefABCDEF":
                base = 16
                i = 2
            else:
                base = 8
        else:
            base = 10
    elif base == 16 and s[:2] == "0x" and len(s) > 2 and s[2] in "0123456789abcdefABCDEF":
        i = 2
    value = 0
    start = i
    while i < len(s):
        ch = s[i]
        if ch.isdigit():
            d = ord(ch) - 48
        elif "a" <= ch.lower() <= "z":
            d = ord(ch.lower()) - 87
        else:
            break
        if d >= base:
            break
        value = value * base + d
        i += 1
    if i == start and start == 0:
        return 0, s
    return value & ADDR_MASK, s[i:]


def parse_hex_strict(text: str) -> int | None:
    """``simple_strtoul(argv, &endp, 16)`` 후 ``*endp != 0`` 이면 실패로 보는 cmd_sf.c 스타일 검사."""
    if not text:
        return None
    value, rest = simple_strtoul(text, 16)
    if rest:
        return None
    return value


class SparseMemory:
    """희소 32비트 주소 공간.

    - 쓴 적 없는 주소는 (seed, 페이지 번호)로 결정되는 의사난수 바이트를 돌려준다 (전원 투입 직후 DRAM 잔상과 비슷).
    - ``add_window`` 로 읽기 전용 창(예: 플래시 메모리 매핑)을 붙일 수 있다.
    - 전원이 꺼지면 ``clear()`` 로 내용이 사라진다.
    """

    PAGE = 4096

    def __init__(self, seed: int = 0) -> None:
        self.seed = int(seed)
        self._pages: dict[int, bytearray] = {}
        self._windows: list[tuple[int, int, Callable[[int, int], bytes]]] = []
        self._lock = threading.RLock()
        self.generation = 0  # 전원 사이클마다 증가 (잔상 패턴이 바뀜)

    def add_window(self, start: int, size: int, reader: Callable[[int, int], bytes]) -> None:
        self._windows.append((start & ADDR_MASK, size, reader))

    def clear(self) -> None:
        with self._lock:
            self._pages.clear()
            self.generation += 1

    def _noise_page(self, page: int) -> bytes:
        key = f"{self.seed}:{self.generation}:{page}".encode()
        out = bytearray()
        counter = 0
        while len(out) < self.PAGE:
            out += hashlib.blake2b(key + counter.to_bytes(4, "little"), digest_size=64).digest()
            counter += 1
        return bytes(out[: self.PAGE])

    def _window_for(self, addr: int) -> tuple[int, int, Callable[[int, int], bytes]] | None:
        for start, size, reader in self._windows:
            if start <= addr < start + size:
                return start, size, reader
        return None

    def read(self, addr: int, length: int) -> bytes:
        addr &= ADDR_MASK
        out = bytearray()
        with self._lock:
            while length > 0:
                win = self._window_for(addr)
                if win is not None:
                    start, size, reader = win
                    n = min(length, start + size - addr)
                    out += reader(addr - start, n)
                    addr = (addr + n) & ADDR_MASK
                    length -= n
                    continue
                page, off = divmod(addr, self.PAGE)
                n = min(length, self.PAGE - off)
                data = self._pages.get(page)
                if data is None:
                    out += self._noise_page(page)[off : off + n]
                else:
                    out += data[off : off + n]
                addr = (addr + n) & ADDR_MASK
                length -= n
        return bytes(out)

    def write(self, addr: int, data: bytes) -> None:
        addr &= ADDR_MASK
        view = memoryview(bytes(data))
        with self._lock:
            while len(view):
                if self._window_for(addr) is not None:
                    # 읽기 전용 창에 대한 쓰기는 무시 (실제 FMC 매핑 영역은 쓰기 불가)
                    n = 1
                    view = view[n:]
                    addr = (addr + n) & ADDR_MASK
                    continue
                page, off = divmod(addr, self.PAGE)
                n = min(len(view), self.PAGE - off)
                buf = self._pages.get(page)
                if buf is None:
                    buf = bytearray(self._noise_page(page))
                    self._pages[page] = buf
                buf[off : off + n] = view[:n]
                view = view[n:]
                addr = (addr + n) & ADDR_MASK

    def read_uint(self, addr: int, width: int, little: bool = True) -> int:
        return int.from_bytes(self.read(addr, width), "little" if little else "big")

    def write_uint(self, addr: int, width: int, value: int, little: bool = True) -> None:
        self.write(addr, (value & ((1 << (8 * width)) - 1)).to_bytes(width, "little" if little else "big"))


class FlashChip:
    """SPI NOR 플래시 모델. 쓰기는 NOR 의미(1→0 만 가능: 기존 & 새 값), 지우기는 블록 단위 0xFF."""

    def __init__(self, data: bytes | bytearray, *, erase_size: int, page_size: int = 256) -> None:
        self.data = bytearray(data)
        self.erase_size = int(erase_size)
        self.page_size = int(page_size)
        self._lock = threading.RLock()

    @property
    def size(self) -> int:
        return len(self.data)

    def read(self, offset: int, length: int) -> bytes:
        with self._lock:
            if offset < 0 or length < 0 or offset + length > len(self.data):
                raise ValueError("flash read out of range")
            return bytes(self.data[offset : offset + length])

    def program(self, offset: int, data: bytes) -> None:
        with self._lock:
            if offset < 0 or offset + len(data) > len(self.data):
                raise ValueError("flash program out of range")
            seg = self.data[offset : offset + len(data)]
            self.data[offset : offset + len(data)] = bytes(a & b for a, b in zip(seg, data))

    def erase(self, offset: int, length: int) -> None:
        with self._lock:
            if offset < 0 or offset + length > len(self.data):
                raise ValueError("flash erase out of range")
            start = offset - offset % self.erase_size
            end = offset + length
            if end % self.erase_size:
                end += self.erase_size - end % self.erase_size
            end = min(end, len(self.data))
            self.data[start:end] = b"\xff" * (end - start)

    def snapshot(self) -> bytes:
        with self._lock:
            return bytes(self.data)


__all__ = ["ADDR_MASK", "FlashChip", "SparseMemory", "parse_hex_strict", "simple_strtoul"]
