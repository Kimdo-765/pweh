"""기존 JTAGulator 경로 호환 — 구현은 pweh.jtag.jep106에 있다."""

from pweh.jtag.jep106 import JEP106_SUBSET, decode_idcode, openocd_target_hints

__all__ = ["JEP106_SUBSET", "decode_idcode", "openocd_target_hints"]
