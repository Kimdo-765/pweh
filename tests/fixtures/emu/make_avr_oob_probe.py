#!/usr/bin/env python3
"""합성 AVR 펌웨어 픽스처 생성기 — 플래시 범위 밖 접근(OOB) 탐침 (avr-gcc 없이 손으로 어셈블).

고정 커밋의 simavr 는 LPM·ELPM·SPM 에서 ``avr->flash[z]`` 를 범위 검사 없이 쓴다. pweh_avr_run 은 avr_init 바로
뒤에 플래시 버퍼를 24비트 색인 전체 + SPM 한 페이지까지 넓혀(0xFF) 이것을 막는다 (native/emu/pweh_avr_run.c).
이 펌웨어들은 그 범위 밖 주소를 읽고 지우고, 읽은 바이트를 USART0(115200 8N1, U2X, 16 MHz)으로 그대로 보낸 뒤
``cli; sleep; rjmp .-2`` 로 멈춘다. 기대 결과: 충돌 없음, 범위 밖은 모두 0xFF, 종료 코드 0 (``EXPECTED`` 와 같은 출력).

avr_oob_probe_m328p.hex (ATmega328P, 플래시 32 KiB, RAMPZ 없음):
  ``L`` + LPM Z=0xFFFF (16비트 Z 의 끝)                                → FF
  ``B`` + LPM Z=0xC000..0xC003 (플래시 끝 0x7FFF 너머, 지우기 전)        → FF FF FF FF
  SPM 페이지 지우기 Z=0xC000 (플래시 끝 너머)
  ``S`` + LPM Z=0xC000..0xC003 (지운 뒤)                                → FF FF FF FF
  ``E`` + ELPM r24, Z (r0=0xFF, Z=0xFFFF) — RAMPZ 가 없는 MCU 에서 simavr 는 "잘못된 명령" 로그만 남기고
        RAMPZ 대신 r0 으로 색인 0xFFFFFF 를 읽는다                     → FF
  ``R`` + EEPROM 0x10..0x13 읽기 — HEX 의 EEPROM 레코드(0x810010, "EEOK")가 시뮬레이션 EEPROM 에 적재됐는지 → EEOK
  ``\\r\\n``
avr_oob_probe_m2560.hex (ATmega2560, 플래시 256 KiB, RAMPZ 있음):
  ``E`` + ELPM Z+ RAMPZ=0xFF Z=0xFF00..0xFF03 (색인 0xFFFF00, 버퍼보다 약 16 MiB 위)   → FF FF FF FF
  SPM 페이지 지우기 RAMPZ:Z = 0xFF:0xFF00
  ``S`` + ELPM Z+ 같은 주소 (지운 뒤)                                   → FF FF FF FF
  ``F`` + ELPM Z+ RAMPZ=0x01 Z=0xFFFC..0xFFFF — 유형 04 레코드로 0x1FFFC 에 둔 표식 "PWEH"   → PWEH
  ``\\r\\n``

넓히기가 없던 연구 단계의 실행기에서는 328p 의 ``L``·``B`` 에 0xFF 가 아닌 호스트 힙 내용이 보이고 ``E`` 에서 SIGSEGV 로
끝났고, 2560 은 첫 ELPM 에서 SIGSEGV 였다. ``E``(328p) 는 RAMPZ 유무로 버퍼 크기를 고르면 남는 구멍을 확인한다
(그렇게 고른 실행기는 여기서 SIGSEGV).

표준 라이브러리만 쓰고 결정적이다. 다시 만들기: ``python3 -I make_avr_oob_probe.py --out-dir <디렉터리>``.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))   # -I 로 실행해도 같은 디렉터리의 어셈블러를 쓴다
from make_avr_uart_echo import Asm, intel_hex, words_to_bytes  # noqa: E402

# I/O 주소 (OUT/IN), 데이터 공간 주소 (LDS/STS) — ATmega328P 와 ATmega2560 이 같다
SPL_IO, SPH_IO, SPMCSR_IO, RAMPZ_IO = 0x3D, 0x3E, 0x37, 0x3B
EECR_IO, EEDR_IO, EEARL_IO, EEARH_IO = 0x1F, 0x20, 0x21, 0x22
UCSR0A, UCSR0B, UCSR0C, UBRR0L, UBRR0H, UDR0 = 0xC0, 0xC1, 0xC2, 0xC4, 0xC5, 0xC6
UDRE0, U2X0, TXEN0, UCSZ01, UCSZ00 = 5, 1, 3, 2, 1
EERE = 0
PGERS_SELFPRGEN = 0x03   # SPMCSR: 페이지 지우기 + SPM 허용
EEPROM_ADDR, EEPROM_DATA = 0x10, b"EEOK"
MARKER_ADDR, MARKER_DATA = 0x1FFFC, b"PWEH"
AVR_SEGMENT_OFFSET_EEPROM = 0x810000

#: 실행기가 내야 하는 UART 출력 (시험이 단언한다)
EXPECTED = {
    "m328p": b"L\xff" + b"B" + b"\xff" * 4 + b"S" + b"\xff" * 4 + b"E\xff" + b"R" + EEPROM_DATA + b"\r\n",
    "m2560": b"E" + b"\xff" * 4 + b"S" + b"\xff" * 4 + b"F" + MARKER_DATA + b"\r\n",
}
#: (MCU, 주파수, 파일 이름)
TARGETS = {
    "m328p": ("atmega328p", 16_000_000, "avr_oob_probe_m328p.hex"),
    "m2560": ("atmega2560", 16_000_000, "avr_oob_probe_m2560.hex"),
}


def _prologue(a: Asm, ramend: int) -> None:
    a.label("reset")
    a.ldi(16, ramend >> 8); a.out(SPH_IO, 16)
    a.ldi(16, ramend & 0xFF); a.out(SPL_IO, 16)
    a.ldi(16, 0); a.sts(UBRR0H, 16)
    a.ldi(16, 16); a.sts(UBRR0L, 16)                                 # 115200 baud (U2X0)
    a.ldi(16, 1 << U2X0); a.sts(UCSR0A, 16)
    a.ldi(16, (1 << UCSZ01) | (1 << UCSZ00)); a.sts(UCSR0C, 16)      # 8N1
    a.ldi(16, 1 << TXEN0); a.sts(UCSR0B, 16)                         # 송신만


def _putc_const(a: Asm, ch: str) -> None:
    a.ldi(24, ord(ch)); a.rcall("putc")


def _z(a: Asm, z: int) -> None:
    a.ldi(30, z & 0xFF); a.ldi(31, (z >> 8) & 0xFF)


def _rampz(a: Asm, value: int) -> None:
    a.ldi(16, value); a.out(RAMPZ_IO, 16)


def _epilogue(a: Asm) -> None:
    _putc_const(a, "\r"); _putc_const(a, "\n")
    a.label("halt")
    a.cli(); a.sleep(); a.rjmp_self()
    a.label("putc")                                                   # r24 를 보낸다 (r16 사용)
    a.lds(16, UCSR0A); a.sbrs(16, UDRE0); a.rjmp("putc")
    a.sts(UDR0, 24)
    a.ret()


def build_m328p() -> list[tuple[int, bytes]]:
    a = Asm()
    _prologue(a, 0x08FF)
    _putc_const(a, "L")
    _z(a, 0xFFFF); a.lpm(24); a.rcall("putc")
    _putc_const(a, "B")
    _z(a, 0xC000)
    for _ in range(4):
        a.lpm(24, post_inc=True); a.rcall("putc")
    _z(a, 0xC000); a.ldi(16, PGERS_SELFPRGEN); a.out(SPMCSR_IO, 16); a.spm()
    _putc_const(a, "S")
    _z(a, 0xC000)
    for _ in range(4):
        a.lpm(24, post_inc=True); a.rcall("putc")
    _putc_const(a, "E")
    a.ldi(16, 0xFF); a.mov(0, 16)                                     # RAMPZ 가 없으면 simavr 는 r0 을 쓴다
    _z(a, 0xFFFF); a.elpm(24); a.rcall("putc")
    _putc_const(a, "R")
    for i in range(len(EEPROM_DATA)):
        a.ldi(16, 0); a.out(EEARH_IO, 16)
        a.ldi(16, EEPROM_ADDR + i); a.out(EEARL_IO, 16)
        a.ldi(16, 1 << EERE); a.out(EECR_IO, 16)
        a.in_(24, EEDR_IO); a.rcall("putc")
    _epilogue(a)
    words, _ = a.assemble()
    return [(0, words_to_bytes(words)), (AVR_SEGMENT_OFFSET_EEPROM + EEPROM_ADDR, EEPROM_DATA)]


def build_m2560() -> list[tuple[int, bytes]]:
    a = Asm()
    _prologue(a, 0x21FF)
    _putc_const(a, "E")
    _rampz(a, 0xFF); _z(a, 0xFF00)
    for _ in range(4):
        a.elpm(24, post_inc=True); a.rcall("putc")
    _rampz(a, 0xFF); _z(a, 0xFF00); a.ldi(16, PGERS_SELFPRGEN); a.out(SPMCSR_IO, 16); a.spm()
    _putc_const(a, "S")
    _rampz(a, 0xFF); _z(a, 0xFF00)
    for _ in range(4):
        a.elpm(24, post_inc=True); a.rcall("putc")
    _putc_const(a, "F")
    _rampz(a, MARKER_ADDR >> 16); _z(a, MARKER_ADDR & 0xFFFF)
    for _ in range(4):
        a.elpm(24, post_inc=True); a.rcall("putc")
    _epilogue(a)
    words, _ = a.assemble()
    return [(0, words_to_bytes(words)), (MARKER_ADDR, MARKER_DATA)]


BUILDERS = {"m328p": build_m328p, "m2560": build_m2560}


def build_hex(target: str) -> str:
    """대상('m328p'|'m2560')의 Intel HEX 텍스트 (시험이 커밋한 파일과 비교한다)."""
    return intel_hex(BUILDERS[target]())


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=(__doc__ or "").splitlines()[0])
    ap.add_argument("--out-dir", type=Path, default=Path("."))
    args = ap.parse_args(argv)
    args.out_dir.mkdir(parents=True, exist_ok=True)
    for target, (_mcu, _freq, name) in TARGETS.items():
        (args.out_dir / name).write_text(build_hex(target), encoding="ascii", newline="\n")
        sys.stderr.write(f"{target} -> {args.out_dir / name}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
