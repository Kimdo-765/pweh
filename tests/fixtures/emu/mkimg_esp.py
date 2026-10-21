#!/usr/bin/env python3
"""합성 ESP32 계열 플래시 이미지 생성기 (ESP-IDF·툴체인 없이 손으로 인코딩한 아주 작은 2단계 이미지).

칩: esp32 (Xtensa), esp32s3 (Xtensa), esp32c3 (RISC-V). 변형:
  hello  UART0 에 ``PWEH-QEMU-OK\\r\\n`` 을 쓰고 제자리에서 돈다
  echo   ``PWEH-ECHO>\\r\\n`` 을 쓴 뒤 UART0 수신 FIFO(UART_STATUS +0x1C 의 RXFIFO_CNT)를 폴링해 받은 바이트를 돌려준다
  reset  hello 와 같이 쓴 뒤 RTC_CNTL_OPTIONS0 bit 31(SW_SYS_RESET)로 소프트웨어 리셋 (QEMU -no-reboot 면 종료 코드 0)

이미지: 8바이트 헤더(매직 0xE9, 세그먼트 1, DIO, 플래시 크기·40 MHz, 엔트리) + 16바이트 확장 헤더(WP 0xEE, chip_id 0/9/5,
최대 리비전 0xFFFF, hash_appended=1) + IRAM 세그먼트 하나 + XOR 체크섬(시작 0xEF, 16바이트 경계) + 이미지 SHA-256.
ROM 이 2단계 부트로더를 찾는 플래시 오프셋(esp32 0x1000, s3·c3 0x0)에 두고 나머지를 0xFF(지운 NOR)로 채운 것이 전체 덤프다.
Espressif QEMU(esp_develop_9.2.2_20260417)에서 세 칩 모두 부팅이 확인된 인코딩이다 (바꾸면 실제 에뮬레이터로 다시 확인).

4 MiB 플래시 이미지는 커밋하지 않는다 — 시험이 ``build_flash()`` 로 그때그때 만든다. 표준 라이브러리만 쓰고 결정적이다.
직접 쓰기: ``python3 -I mkimg_esp.py --out-dir <디렉터리> [--flash]``.
"""

from __future__ import annotations

import argparse
import hashlib
import struct
import sys
from dataclasses import dataclass
from pathlib import Path

ESP_IMAGE_MAGIC = 0xE9
ESP_CHECKSUM_MAGIC = 0xEF
SW_SYS_RESET = 0x80000000            # RTC_CNTL_OPTIONS0 bit 31
HELLO_TEXT = b"PWEH-QEMU-OK\r\n"
ECHO_BANNER = b"PWEH-ECHO>\r\n"
VARIANTS = ("hello", "echo", "reset")
#: 헤더 3번째 바이트 상위 니블 (플래시 크기) — QEMU 머신이 받는 크기만
FLASH_SIZE_NIBBLE = {1 << 20: 0x0, 2 << 20: 0x1, 4 << 20: 0x2, 8 << 20: 0x3, 16 << 20: 0x4}


@dataclass(frozen=True)
class Chip:
    chip_id: int          # 이미지 확장 헤더의 chip_id
    uart_fifo: int        # UART0 FIFO 레지스터 (= UART0 기준 주소)
    iram_load: int        # 세그먼트 적재 주소 (IRAM)
    boot_offset: int      # ROM 이 2단계 부트로더를 읽는 플래시 오프셋
    isa: str              # "xtensa" | "riscv"
    rtc_options0: int     # RTC_CNTL_OPTIONS0 (소프트웨어 리셋)


CHIPS: dict[str, Chip] = {
    "esp32": Chip(0, 0x3FF40000, 0x40080400, 0x1000, "xtensa", 0x3FF48000),
    "esp32s3": Chip(9, 0x60000000, 0x40380000, 0x0000, "xtensa", 0x60008000),
    "esp32c3": Chip(5, 0x60000000, 0x40380000, 0x0000, "riscv", 0x60008000),
}


# --- Xtensa (손 인코딩) --------------------------------------------------------

def _xt_l32r(at: int, pos: int, lit_index: int) -> bytes:
    """L32R at, literal[lit_index] — 리터럴은 코드 앞(base + 4*i), 명령은 base + pos."""
    off = 4 * lit_index - ((pos + 3) & ~3)
    if off >= 0 or off % 4:
        raise ValueError("L32R 리터럴은 명령 앞, 4바이트 정렬이어야 한다")
    imm16 = (off // 4) & 0xFFFF
    return bytes([(at << 4) | 0x1, imm16 & 0xFF, imm16 >> 8])


def _xt_put_text(code: bytearray, text: bytes) -> None:
    for c in text:
        code += bytes([0x32, 0xA0, c & 0xFF])            # movi a3, c      (RRI8 op0=2 r=0xA)
        code += bytes([0x32, 0x62, 0x00])                # s32i a3, a2, 0  (RRI8 op0=2 r=6)


def xtensa_hello(chip: Chip, text: bytes, reset: bool) -> tuple[bytes, int]:
    """리터럴 [FIFO, RTC_OPTIONS0, SW_SYS_RESET] + l32r ×3, (movi; s32i)×글자, [s32i a5,a4,0 — 리셋], j ."""
    lits = [chip.uart_fifo, chip.rtc_options0 if reset else 0, SW_SYS_RESET]
    code = bytearray(b"".join(struct.pack("<I", v) for v in lits))
    entry = len(code)
    code += _xt_l32r(2, len(code), 0)                    # l32r a2, FIFO
    code += _xt_l32r(4, len(code), 1)                    # l32r a4, RTC_CNTL_OPTIONS0
    code += _xt_l32r(5, len(code), 2)                    # l32r a5, 0x80000000
    _xt_put_text(code, text)
    if reset:
        code += bytes([0x52, 0x64, 0x00])                # s32i a5, a4, 0  → 소프트웨어 시스템 리셋
    code += bytes([0x06, 0xFF, 0xFF])                    # j .             (CALL op0=6 n=0 off=-4)
    return bytes(code), entry


def xtensa_echo(chip: Chip, banner: bytes) -> tuple[bytes, int]:
    """배너 후 loop: l32i a6,a2,0x1C; extui a6,a6,0,8; beqz a6,loop; l32i a7,a2,0; s32i a7,a2,0; j loop."""
    code = bytearray(struct.pack("<I", chip.uart_fifo))
    entry = len(code)
    code += _xt_l32r(2, len(code), 0)                    # l32r a2, UART0 기준 (= FIFO)
    _xt_put_text(code, banner)
    loop = len(code)
    code += bytes([0x62, 0x22, 0x07])                    # l32i a6, a2, 0x1C   (UART_STATUS)
    code += bytes([0x60, 0x60, 0x74])                    # extui a6, a6, 0, 8  (RXFIFO_CNT)
    b = len(code)
    imm12 = (loop - (b + 4)) & 0xFFF
    w = (imm12 << 12) | (6 << 8) | (0 << 6) | (1 << 4) | 0x6   # beqz a6, loop (BRI12 n=1 m=0)
    code += bytes([w & 0xFF, (w >> 8) & 0xFF, w >> 16])
    code += bytes([0x72, 0x22, 0x00])                    # l32i a7, a2, 0      (RX FIFO 꺼내기)
    code += bytes([0x72, 0x62, 0x00])                    # s32i a7, a2, 0      (TX FIFO 넣기)
    j = len(code)
    off18 = (loop - (j + 4)) & 0x3FFFF
    w = (off18 << 6) | (0 << 4) | 0x6                    # j loop
    code += bytes([w & 0xFF, (w >> 8) & 0xFF, w >> 16])
    return bytes(code), entry


# --- RISC-V RV32I ---------------------------------------------------------------

def _rv_lui(rd: int, imm20: int) -> int:
    return (imm20 << 12) | (rd << 7) | 0x37


def _rv_addi(rd: int, rs1: int, imm12: int) -> int:
    return ((imm12 & 0xFFF) << 20) | (rs1 << 15) | (0 << 12) | (rd << 7) | 0x13


def _rv_andi(rd: int, rs1: int, imm12: int) -> int:
    return ((imm12 & 0xFFF) << 20) | (rs1 << 15) | (7 << 12) | (rd << 7) | 0x13


def _rv_lw(rd: int, rs1: int, imm12: int) -> int:
    return ((imm12 & 0xFFF) << 20) | (rs1 << 15) | (2 << 12) | (rd << 7) | 0x03


def _rv_sw(rs2: int, rs1: int, imm12: int) -> int:
    imm = imm12 & 0xFFF
    return ((imm >> 5) << 25) | (rs2 << 20) | (rs1 << 15) | (2 << 12) | ((imm & 0x1F) << 7) | 0x23


def _rv_beq(rs1: int, rs2: int, off: int) -> int:
    i = off & 0x1FFF
    return ((((i >> 12) & 1) << 31) | (((i >> 5) & 0x3F) << 25) | (rs2 << 20) | (rs1 << 15) | (0 << 12)
            | (((i >> 1) & 0xF) << 8) | (((i >> 11) & 1) << 7) | 0x63)


def _rv_jal(rd: int, off: int) -> int:
    i = off & 0x1FFFFF
    return ((((i >> 20) & 1) << 31) | (((i >> 1) & 0x3FF) << 21) | (((i >> 11) & 1) << 20) | (((i >> 12) & 0xFF) << 12)
            | (rd << 7) | 0x6F)


A0, A1, A2, A3 = 10, 11, 12, 13


def riscv_hello(chip: Chip, text: bytes, reset: bool) -> tuple[bytes, int]:
    """lui a0,FIFO>>12; (addi a1,x0,c; sw a1,0(a0))×글자; [lui a2,RTC>>12; lui a3,0x80000; sw a3,0(a2)]; j ."""
    words = [_rv_lui(A0, chip.uart_fifo >> 12)]
    for c in text:
        words += [_rv_addi(A1, 0, c), _rv_sw(A1, A0, 0)]
    if reset:
        words += [_rv_lui(A2, chip.rtc_options0 >> 12), _rv_lui(A3, SW_SYS_RESET >> 12), _rv_sw(A3, A2, 0)]
    words.append(0x0000006F)                             # jal x0, 0  (j .)
    return b"".join(struct.pack("<I", w) for w in words), 0


def riscv_echo(chip: Chip, banner: bytes) -> tuple[bytes, int]:
    words = [_rv_lui(A0, chip.uart_fifo >> 12)]
    for c in banner:
        words += [_rv_addi(A1, 0, c), _rv_sw(A1, A0, 0)]
    loop = len(words)
    words += [_rv_lw(A1, A0, 0x1C), _rv_andi(A1, A1, 0xFF)]
    words.append(_rv_beq(A1, 0, (loop - len(words)) * 4))         # beq a1, x0, loop
    words += [_rv_lw(A2, A0, 0), _rv_sw(A2, A0, 0)]
    words.append(_rv_jal(0, (loop - len(words)) * 4))             # j loop
    return b"".join(struct.pack("<I", w) for w in words), 0


# --- 이미지 ---------------------------------------------------------------------

def esp_image(chip_id: int, load_addr: int, code: bytes, entry_offset: int, *, flash_size: int = 4 << 20,
              flash_mode: int = 2, append_digest: bool = True) -> bytes:
    """세그먼트 하나짜리 ESP 이미지 (헤더 + 확장 헤더 + 세그먼트 + 체크섬 [+ SHA-256])."""
    if flash_size not in FLASH_SIZE_NIBBLE:
        raise ValueError(f"플래시 크기는 {sorted(FLASH_SIZE_NIBBLE)} 중 하나")
    data = bytes(code) + b"\x00" * (-len(code) % 4)      # 세그먼트 길이는 4의 배수
    size_freq = FLASH_SIZE_NIBBLE[flash_size] << 4      # 하위 니블 0 = 40 MHz
    hdr = struct.pack("<BBBBI", ESP_IMAGE_MAGIC, 1, flash_mode, size_freq, load_addr + entry_offset)
    # 확장 헤더: wp_pin, 구동 세기 ×3, chip_id, min_rev, min_rev_full, max_rev_full, 예약 ×4, hash_appended
    ext = struct.pack("<BBBBHBHH4BB", 0xEE, 0, 0, 0, chip_id, 0, 0, 0xFFFF, 0, 0, 0, 0, 1 if append_digest else 0)
    img = bytearray(hdr + ext)
    img += struct.pack("<II", load_addr, len(data)) + data
    csum = ESP_CHECKSUM_MAGIC
    for b in data:
        csum ^= b
    img += b"\x00" * (15 - (len(img) % 16))
    img.append(csum)
    if append_digest:
        img += hashlib.sha256(img).digest()
    return bytes(img)


def build_image(chip: str, variant: str, text: bytes | None = None, *, flash_size: int = 4 << 20) -> bytes:
    """칩·변형의 2단계 이미지. text 는 hello·reset 의 출력 (기본 PWEH-QEMU-OK\\r\\n)."""
    spec = CHIPS[chip]
    if variant not in VARIANTS:
        raise ValueError(f"변형은 {VARIANTS} 중 하나")
    if variant == "echo":
        code, entry = (xtensa_echo if spec.isa == "xtensa" else riscv_echo)(spec, ECHO_BANNER)
    else:
        code, entry = (xtensa_hello if spec.isa == "xtensa" else riscv_hello)(spec, text or HELLO_TEXT, variant == "reset")
    return esp_image(spec.chip_id, spec.iram_load, code, entry, flash_size=flash_size)


def build_flash(chip: str, variant: str, size: int = 4 << 20, text: bytes | None = None) -> bytes:
    """전체 플래시 덤프 모양: 0xFF 로 채운 size 바이트에 ROM 부트 오프셋의 이미지 (헤더의 플래시 크기도 size)."""
    img = build_image(chip, variant, text, flash_size=size)
    off = CHIPS[chip].boot_offset
    flash = bytearray(b"\xff" * size)
    flash[off:off + len(img)] = img
    return bytes(flash)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=(__doc__ or "").splitlines()[0])
    ap.add_argument("--out-dir", type=Path, required=True)
    ap.add_argument("--marker", default=HELLO_TEXT.decode(), help="hello·reset 의 출력 (기본 PWEH-QEMU-OK\\r\\n)")
    ap.add_argument("--flash", action="store_true", help="4 MiB 플래시 이미지(<칩>-<변형>-4M.bin)도 쓴다")
    args = ap.parse_args(argv)
    text = args.marker.encode()
    args.out_dir.mkdir(parents=True, exist_ok=True)
    for chip in CHIPS:
        for variant in VARIANTS:
            img = build_image(chip, variant, text)
            (args.out_dir / f"{chip}-{variant}.img").write_bytes(img)
            if args.flash:
                (args.out_dir / f"{chip}-{variant}-4M.bin").write_bytes(build_flash(chip, variant, text=text))
            sys.stderr.write(f"{chip} {variant}: 이미지 {len(img)} 바이트, 플래시 0x{CHIPS[chip].boot_offset:x}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
