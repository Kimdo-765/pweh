#!/usr/bin/env python3
"""합성 AVR 펌웨어 픽스처 생성기 — UART 에코 (avr-gcc 없이 손으로 어셈블).

대상: ATmega328P (Arduino Uno), 16 MHz. USART0 을 115200 baud(U2X0=1, UBRR0=16, 8N1. ``--baud 9600`` 이면
U2X0=0, UBRR0=103)로 초기화하고, RXEN 직후 UDR0 를 한 번 읽어 수신 버퍼를 비운 뒤(실제 칩에서는 무해)
``OK\\r\\n`` 을 보내고 받은 바이트를 그대로 돌려준다(에코). 0x04(EOT)를 받으면 돌려주지 않고 ``cli; sleep; rjmp .-2``
로 멈춘다 — simavr 는 "인터럽트를 끈 sleep" 으로 보고 정상 종료한다(pweh_avr_run 종료 코드 0).

출력: ``<이름>.hex`` (Intel HEX, 데이터 레코드 16 바이트 + EOF). ``--listing`` 이면 ``<이름>.lst`` (주소·기계어·소스)도.
기본 출력(``avr_uart_echo_m328p.hex``)은 저장소에 커밋되어 있고, 시험이 이 생성기의 출력과 같은지 확인한다
(sha256 473124e258f7a86313fdb251e198a9ffaa5cbe9280c6da970eb86681ae31fafa).

이 파일의 ``Asm``·``intel_hex`` 는 ``make_avr_oob_probe.py`` 도 쓴다. 표준 라이브러리만 쓰고, 같은 인자면 늘 같은
바이트를 만든다. 다시 만들기: ``python3 -I make_avr_uart_echo.py --out-dir <디렉터리>``.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Callable, Iterable

# ATmega328P 레지스터 (데이터 공간 주소. OUT/IN 은 I/O 주소 = 데이터 주소 - 0x20)
SPL_IO, SPH_IO = 0x3D, 0x3E
UCSR0A, UCSR0B, UCSR0C = 0xC0, 0xC1, 0xC2
UBRR0L, UBRR0H, UDR0 = 0xC4, 0xC5, 0xC6
RXC0, UDRE0, U2X0 = 7, 5, 1
RXEN0, TXEN0 = 4, 3
UCSZ01, UCSZ00 = 2, 1
RAMEND = 0x08FF
F_CPU = 16_000_000
EOT = 0x04

BAUD_TABLE = {  # baud -> (U2X0, UBRR0)
    115200: (1, 16),   # 117647 bps, +2.1 % (Arduino 부트로더와 같은 설정)
    9600: (0, 103),    # 9615 bps, +0.2 %
}

Encoder = Callable[[int], list[int]]


def _reg(r: int, lo: int = 0) -> int:
    if not lo <= r <= 31:
        raise ValueError(f"레지스터 범위 밖: r{r}")
    return r


def _imm8(k: int) -> int:
    if not 0 <= k <= 0xFF:
        raise ValueError(f"8비트 상수 범위 밖: {k}")
    return k


def _io6(a: int) -> int:
    if not 0 <= a <= 63:
        raise ValueError(f"I/O 주소 범위 밖(0..63): {a}")
    return a


class Asm:
    """두 단계(레이블 수집 → 인코딩) 미니 어셈블러. 명령 하나 = (워드 수, 인코더, 소스 문자열).

    인코딩은 AVR Instruction Set Manual 을 따른다. 주소·PC 는 워드 단위다.
    """

    def __init__(self) -> None:
        self.items: list[tuple[int, Encoder, str]] = []
        self.labels: dict[str, int] = {}
        self.pc = 0

    # --- 구성 ---
    def label(self, name: str) -> None:
        if name in self.labels:
            raise ValueError(f"중복 레이블: {name}")
        self.labels[name] = self.pc

    def _emit(self, size: int, enc: Encoder, src: str) -> None:
        self.items.append((size, enc, src))
        self.pc += size

    def _word(self, word: int, src: str) -> None:
        self._emit(1, lambda pc: [word], src)

    # --- 명령 ---
    def ldi(self, d: int, k: int) -> None:
        _reg(d, 16)
        _imm8(k)
        self._word(0xE000 | ((k & 0xF0) << 4) | ((d - 16) << 4) | (k & 0x0F), f"ldi r{d}, 0x{k:02x}")

    def cpi(self, d: int, k: int) -> None:
        _reg(d, 16)
        _imm8(k)
        self._word(0x3000 | ((k & 0xF0) << 4) | ((d - 16) << 4) | (k & 0x0F), f"cpi r{d}, 0x{k:02x}")

    def out(self, a: int, r: int) -> None:
        _io6(a)
        _reg(r)
        self._word(0xB800 | ((a & 0x30) << 5) | (r << 4) | (a & 0x0F), f"out 0x{a:02x}, r{r}")

    def in_(self, d: int, a: int) -> None:
        _reg(d)
        _io6(a)
        self._word(0xB000 | ((a & 0x30) << 5) | (d << 4) | (a & 0x0F), f"in r{d}, 0x{a:02x}")

    def mov(self, d: int, r: int) -> None:
        _reg(d)
        _reg(r)
        self._word(0x2C00 | ((r & 0x10) << 5) | (d << 4) | (r & 0x0F), f"mov r{d}, r{r}")

    def sts(self, k: int, r: int) -> None:
        _reg(r)
        self._emit(2, lambda pc: [0x9200 | (r << 4), k & 0xFFFF], f"sts 0x{k:04x}, r{r}")

    def lds(self, d: int, k: int) -> None:
        _reg(d)
        self._emit(2, lambda pc: [0x9000 | (d << 4), k & 0xFFFF], f"lds r{d}, 0x{k:04x}")

    def sbrs(self, r: int, b: int) -> None:
        _reg(r)
        self._word(0xFE00 | (r << 4) | (b & 7), f"sbrs r{r}, {b}")

    def lpm(self, d: int, post_inc: bool = False) -> None:
        """LPM Rd, Z / LPM Rd, Z+ (16비트 Z)."""
        _reg(d)
        self._word((0x9005 if post_inc else 0x9004) | (d << 4), f"lpm r{d}, Z{'+' if post_inc else ''}")

    def elpm(self, d: int, post_inc: bool = False) -> None:
        """ELPM Rd, Z / ELPM Rd, Z+ (RAMPZ:Z, 24비트)."""
        _reg(d)
        self._word((0x9007 if post_inc else 0x9006) | (d << 4), f"elpm r{d}, Z{'+' if post_inc else ''}")

    def spm(self) -> None:
        self._word(0x95E8, "spm")

    def _rel12(self, op: int, target: str, name: str) -> None:
        def enc(pc: int) -> list[int]:
            off = self.labels[target] - (pc + 1)
            if not -2048 <= off <= 2047:
                raise ValueError(f"{name}: 범위 밖 {off}")
            return [op | (off & 0x0FFF)]
        self._emit(1, enc, f"{name} {target}")

    def rjmp(self, target: str) -> None:
        self._rel12(0xC000, target, "rjmp")

    def rcall(self, target: str) -> None:
        self._rel12(0xD000, target, "rcall")

    def rjmp_self(self) -> None:
        """rjmp .-2 (자기 자신으로 점프 — simavr 가 인터럽트를 끈 무한 루프로 보고 끝낸다)."""
        self._word(0xCFFF, "rjmp .-2")

    def breq(self, target: str) -> None:
        def enc(pc: int) -> list[int]:
            off = self.labels[target] - (pc + 1)
            if not -64 <= off <= 63:
                raise ValueError(f"breq: 범위 밖 {off}")
            return [0xF001 | ((off & 0x7F) << 3)]
        self._emit(1, enc, f"breq {target}")

    def ret(self) -> None:
        self._word(0x9508, "ret")

    def cli(self) -> None:
        self._word(0x94F8, "cli")

    def sleep(self) -> None:
        self._word(0x9588, "sleep")

    # --- 결과 ---
    def assemble(self) -> tuple[list[int], list[str]]:
        words: list[int] = []
        listing: list[str] = []
        pc = 0
        names = {v: k for k, v in self.labels.items()}
        for size, enc, src in self.items:
            ws = enc(pc)
            if len(ws) != size:
                raise AssertionError(src)
            if pc in names:
                listing.append(f"{names[pc]}:")
            listing.append(f"  {pc * 2:04x}: {' '.join(f'{w:04x}' for w in ws):<10} {src}")
            words.extend(ws)
            pc += size
        return words, listing


def words_to_bytes(words: Iterable[int]) -> bytes:
    """AVR 플래시는 워드 리틀 엔디언."""
    return b"".join(w.to_bytes(2, "little") for w in words)


def intel_hex(segments: list[tuple[int, bytes]] | bytes, rec_len: int = 16) -> str:
    """Intel HEX 텍스트: 데이터 레코드(00) + 상위 16비트 주소가 바뀔 때만 확장 선형 주소(04) + EOF(01).

    segments: [(주소, 바이트)] (주소 오름차순) 또는 0 번지부터의 바이트 하나. 주소 0 의 64 KiB 안쪽 이미지는 유형 04
    없이 나온다 (커밋한 에코 HEX 와 같은 모양).
    """
    if isinstance(segments, (bytes, bytearray)):
        segments = [(0, bytes(segments))]
    lines: list[str] = []
    upper = 0

    def record(rtype: int, addr16: int, data: bytes) -> str:
        rec = bytes([len(data), (addr16 >> 8) & 0xFF, addr16 & 0xFF, rtype]) + data
        return ":" + (rec + bytes([(-sum(rec)) & 0xFF])).hex().upper()

    last_end = -1
    for base, data in segments:
        if base < last_end:
            raise ValueError("구간이 겹치거나 주소 오름차순이 아님")
        last_end = base + len(data)
        off = 0
        while off < len(data):
            addr = base + off
            if addr >> 16 != upper:
                upper = addr >> 16
                if upper > 0xFFFF:
                    raise ValueError("32비트 주소 범위 밖")
                lines.append(record(0x04, 0, upper.to_bytes(2, "big")))
            # 한 레코드가 64 KiB 경계를 넘지 않게 자른다
            n = min(rec_len, len(data) - off, 0x10000 - (addr & 0xFFFF))
            lines.append(record(0x00, addr & 0xFFFF, data[off:off + n]))
            off += n
    lines.append(":00000001FF")
    return "\n".join(lines) + "\n"


def build_program(baud: int = 115200) -> Asm:
    u2x, ubrr = BAUD_TABLE[baud]
    a = Asm()
    a.label("reset")
    a.ldi(16, RAMEND >> 8); a.out(SPH_IO, 16)          # 스택 포인터 (모든 시뮬레이터가 RAMEND 로 리셋한다고 가정하지 않음)
    a.ldi(16, RAMEND & 0xFF); a.out(SPL_IO, 16)
    a.ldi(16, ubrr >> 8); a.sts(UBRR0H, 16)
    a.ldi(16, ubrr & 0xFF); a.sts(UBRR0L, 16)
    a.ldi(16, u2x << U2X0); a.sts(UCSR0A, 16)
    a.ldi(16, (1 << UCSZ01) | (1 << UCSZ00)); a.sts(UCSR0C, 16)   # 8N1
    a.ldi(16, (1 << RXEN0) | (1 << TXEN0)); a.sts(UCSR0B, 16)
    a.lds(16, UDR0)                                                # 수신 버퍼 비우기 (값은 버림)
    for ch in b"OK\r\n":
        a.ldi(24, ch); a.rcall("putc")
    a.label("loop")
    a.lds(16, UCSR0A); a.sbrs(16, RXC0); a.rjmp("loop")              # RXC0 대기 (폴링)
    a.lds(24, UDR0)
    a.cpi(24, EOT); a.breq("halt")
    a.rcall("putc"); a.rjmp("loop")
    a.label("halt")
    a.cli(); a.sleep(); a.rjmp_self()
    a.label("putc")
    a.lds(16, UCSR0A); a.sbrs(16, UDRE0); a.rjmp("putc")             # UDRE0 대기
    a.sts(UDR0, 24)
    a.ret()
    return a


def build_hex(baud: int = 115200) -> str:
    """에코 펌웨어의 Intel HEX 텍스트 (시험이 커밋한 파일과 비교한다)."""
    words, _listing = build_program(baud).assemble()
    return intel_hex(words_to_bytes(words))


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=(__doc__ or "").splitlines()[0])
    ap.add_argument("--baud", type=int, default=115200, choices=sorted(BAUD_TABLE))
    ap.add_argument("--out-dir", type=Path, default=Path("."))
    ap.add_argument("--name", default="avr_uart_echo_m328p")
    ap.add_argument("--listing", action="store_true", help="주소·기계어·소스 목록(.lst)도 쓴다")
    args = ap.parse_args(argv)

    words, listing = build_program(args.baud).assemble()
    data = words_to_bytes(words)
    args.out_dir.mkdir(parents=True, exist_ok=True)
    stem = args.out_dir / args.name
    stem.with_suffix(".hex").write_text(intel_hex(data), encoding="ascii", newline="\n")
    if args.listing:
        head = [f"; ATmega328P @ {F_CPU} Hz, USART0 {args.baud} baud, {len(data)} bytes", "; 생성: make_avr_uart_echo.py"]
        stem.with_suffix(".lst").write_text("\n".join(head + listing) + "\n", encoding="utf-8", newline="\n")
    sys.stderr.write(f"{len(data)} bytes -> {stem}.hex\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
