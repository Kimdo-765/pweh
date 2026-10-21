"""emu-mcp argv 분류기·게이트 분류 시험 (서버·에뮬레이터 없음).

- 세 칩 × PSRAM·워치독·리셋 조합과 AVR 보드의 템플릿은 통과한다(MODIFY emu.start).
- 설계 §5.5 의 각 금지 토큰·순서 변경·추가 토큰은 DESTRUCTIVE + 그 규칙 id (승인 경로 없음).
- -drive 형태, 실행 파일 basename, AVR 입력·MCU·주파수·USART·옵션.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
if str(REPO / "mcp-servers" / "emu-mcp") not in sys.path:
    sys.path.insert(0, str(REPO / "mcp-servers" / "emu-mcp"))

from pweh.safety import Risk  # noqa: E402

from emu_mcp import backends as B  # noqa: E402
from emu_mcp import policy as P  # noqa: E402

XT = "/x/qemu-esp/xtensa/qemu/bin/qemu-system-xtensa"
RV = "/x/qemu-esp/riscv32/qemu/bin/qemu-system-riscv32"
AVR = "/x/simavr/bin/pweh_avr_run"
FLASH_FD, EFUSE_FD, HEX_FD = 5, 6, 7


def _exe(chip: str) -> str:
    return XT if B.CHIPS[chip].exe == B.EXE_XTENSA else RV


def _psram_options(chip: str) -> list[tuple[str, int | None]]:
    spec = B.CHIPS[chip]
    return [("none", None)] + [("quad", m) for m in spec.quad_sizes] + [("octal", m) for m in spec.octal_sizes]


def _esp(chip: str = "esp32s3", psram: tuple[str, int | None] = ("octal", 8), watchdog: str = "disabled", on_reset: str = "exit") -> list[str]:
    return B.build_esp_argv(_exe(chip), B.esp_target(chip, psram=psram, watchdog=watchdog, on_reset=on_reset), FLASH_FD, EFUSE_FD)


def _avr(board: str = "uno") -> list[str]:
    spec = B.BOARDS[board]
    return B.build_avr_argv(AVR, B.avr_target(board, spec.mcu, spec.freq_hz, spec.uart), HEX_FD)


def _rule(argv: list[str], expected: list[str] | None = None) -> str:
    c = P.classify_emu_argv(argv, expected=expected)
    if c.rule_id == P.RULE_START:
        assert c.risk == Risk.MODIFY
    else:
        assert c.risk == Risk.DESTRUCTIVE, c
    return c.rule_id


# ---------------------------------------------------------------------------
# 템플릿 통과
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("chip", list(B.CHIP_NAMES))
def test_esp_templates_pass_for_every_option_combination(chip: str) -> None:
    n = 0
    for psram in _psram_options(chip):
        for watchdog in B.WATCHDOG_MODES:
            for on_reset in B.ON_RESET_MODES:
                argv = _esp(chip, psram, watchdog, on_reset)
                assert _rule(argv) == P.RULE_START, (chip, psram, watchdog, on_reset)
                assert _rule(argv, expected=list(argv)) == P.RULE_START
                n += 1
    assert n >= 4


def test_esp_template_shape_is_the_design_argv() -> None:
    argv = _esp("esp32s3", ("octal", 8))
    assert argv == [
        XT, "-no-user-config", "-nodefaults", "-machine", "esp32s3", "-accel", "tcg,tb-size=64", "-display", "none",
        "-monitor", "none", "-nic", "none", "-serial", "stdio",
        "-drive", "file=/proc/self/fd/5,if=mtd,format=raw",
        "-drive", "file=/proc/self/fd/6,if=none,format=raw,id=efuse",
        "-global", "driver=nvram.esp32s3.efuse,property=drive,value=efuse",
        "-global", "driver=timer.esp32s3.timg,property=wdt_disable,value=true",
        "-m", "8M", "-global", "driver=ssi_psram,property=is_octal,value=true",
        "-snapshot", "-no-reboot",
    ]
    c3 = _esp("esp32c3", ("none", None), "emulated", "reboot")
    assert c3[0] == RV and "-m" not in c3 and "-no-reboot" not in c3 and "-snapshot" in c3
    assert not any("timg" in t for t in c3)


@pytest.mark.parametrize("board", [b for b, s in B.BOARDS.items() if s.mcu is not None])
def test_avr_board_templates_pass(board: str) -> None:
    argv = _avr(board)
    spec = B.BOARDS[board]
    assert argv == [AVR, "--mcu", spec.mcu, "--freq", str(spec.freq_hz), "--uart", str(spec.uart), "--realtime", "--hex-fd", "7"]
    assert _rule(argv) == P.RULE_START
    assert _rule(argv, expected=list(argv)) == P.RULE_START


@pytest.mark.parametrize("mcu", list(B.MCUS))
def test_avr_custom_mcus_pass_with_their_uarts(mcu: str) -> None:
    spec = B.MCUS[mcu]
    for uart in spec.uarts:
        for freq in (B.FREQ_MIN_HZ, 16_000_000, B.FREQ_MAX_HZ):
            argv = B.build_avr_argv(AVR, B.avr_target("custom", mcu, freq, uart), HEX_FD)
            assert _rule(argv) == P.RULE_START


def test_gate_classifications() -> None:
    s = P.classify_start("x")
    assert (s.risk, s.rule_id) == (Risk.MODIFY, "emu.start")
    w = P.classify_write(3, True)
    assert (w.risk, w.rule_id) == (Risk.INTERACT, "emu.write")
    assert "3" in (w.matched or "")


# ---------------------------------------------------------------------------
# 금지 토큰 (설계 §5.5)
# ---------------------------------------------------------------------------


def _insert(argv: list[str], extra: list[str], at: int = 3) -> list[str]:
    return argv[:at] + extra + argv[at:]


def _replace_value(argv: list[str], opt: str, value: str) -> list[str]:
    out = list(argv)
    i = out.index(opt)
    out[i + 1] = value
    return out


FORBIDDEN_INSERTS = [
    (["-monitor", "stdio"], P.RULE_MONITOR),
    (["-mon", "chardev=c"], P.RULE_MONITOR),
    (["-qmp", "unix:q.sock,server=on"], P.RULE_MONITOR),
    (["-qmp-pretty", "stdio"], P.RULE_MONITOR),
    (["-nographic"], P.RULE_MONITOR),
    (["-S"], P.RULE_MONITOR),
    (["-preconfig"], P.RULE_MONITOR),
    (["-qtest", "stdio"], P.RULE_MONITOR),
    (["-qtest-log", "q.log"], P.RULE_MONITOR),
    (["-chardev", "stdio,id=c,mux=on"], P.RULE_MONITOR),
    (["-gdb", "tcp::1234"], P.RULE_GDB),
    (["-s"], P.RULE_GDB),
    (["--gdb", "tcp::1234"], P.RULE_GDB),
    (["-netdev", "user,id=n0"], P.RULE_NETWORK),
    (["-nic", "user"], P.RULE_NETWORK),
    (["-net", "nic"], P.RULE_NETWORK),
    (["-vnc", ":0"], P.RULE_NETWORK),
    (["-spice", "port=5900"], P.RULE_NETWORK),
    (["-incoming", "tcp:0:4444"], P.RULE_NETWORK),
    (["-semihosting"], P.RULE_SEMIHOSTING),
    (["-semihosting-config", "enable=on"], P.RULE_SEMIHOSTING),
    (["-blockdev", "driver=file,filename=x"], P.RULE_HOST_FILE),
    (["-mtdblock", "x.bin"], P.RULE_HOST_FILE),
    (["-sd", "x.img"], P.RULE_HOST_FILE),
    (["-pflash", "x.bin"], P.RULE_HOST_FILE),
    (["-hda", "x.img"], P.RULE_HOST_FILE),
    (["-cdrom", "x.iso"], P.RULE_HOST_FILE),
    (["-fda", "x.img"], P.RULE_HOST_FILE),
    (["-bios", "x.bin"], P.RULE_HOST_FILE),
    (["-kernel", "x.elf"], P.RULE_HOST_FILE),
    (["-initrd", "x"], P.RULE_HOST_FILE),
    (["-dtb", "x.dtb"], P.RULE_HOST_FILE),
    (["-append", "console=ttyS0"], P.RULE_HOST_FILE),
    (["-L", "/tmp"], P.RULE_HOST_FILE),
    (["-option-rom", "x"], P.RULE_HOST_FILE),
    (["-fw_cfg", "name=x,file=y"], P.RULE_HOST_FILE),
    (["-smbios", "file=x"], P.RULE_HOST_FILE),
    (["-acpitable", "file=x"], P.RULE_HOST_FILE),
    (["-boot", "menu=on"], P.RULE_HOST_FILE),
    (["-mem-path", "/dev/shm"], P.RULE_HOST_FILE),
    (["-D", "qemu.log"], P.RULE_HOST_FILE),
    (["-d", "in_asm"], P.RULE_HOST_FILE),
    (["-dfilter", "0x0..0xff"], P.RULE_HOST_FILE),
    (["-trace", "events=x"], P.RULE_HOST_FILE),
    (["-pidfile", "q.pid"], P.RULE_HOST_FILE),
    (["-dump-vmstate", "x.json"], P.RULE_HOST_FILE),
    (["-perfmap"], P.RULE_HOST_FILE),
    (["-jitdump"], P.RULE_HOST_FILE),
    (["-icount", "shift=7,rr=record,rrfile=x"], P.RULE_HOST_FILE),
    (["-audiodev", "none,id=a"], P.RULE_HOST_FILE),
    (["-tpmdev", "passthrough,id=t"], P.RULE_HOST_FILE),
    (["-chardev", "file,id=f,path=x"], P.RULE_HOST_FILE),
    (["-parallel", "file:x"], P.RULE_HOST_FILE),
    (["-debugcon", "file:x"], P.RULE_HOST_FILE),
    (["-device", "loader,file=x"], P.RULE_DEVICE),
    (["-object", "memory-backend-file,id=m,mem-path=x"], P.RULE_DEVICE),
    (["-global", "driver=esp32.foo,property=x,value=y"], P.RULE_DEVICE),
    (["-virtfs", "local,path=/,mount_tag=r"], P.RULE_DEVICE),
    (["-fsdev", "local,id=f,path=/"], P.RULE_DEVICE),
    (["-plugin", "x.so"], P.RULE_DEVICE),
    (["-add-fd", "fd=3,set=1"], P.RULE_DEVICE),
    (["-display", "sdl"], P.RULE_DEVICE),
    (["-readconfig", "x.cfg"], P.RULE_CONFIG),
    (["-set", "drive.d.file=x"], P.RULE_CONFIG),
    (["-daemonize"], P.RULE_DETACH),
    (["-runas", "nobody"], P.RULE_DETACH),
    (["-run-with", "chroot=/tmp"], P.RULE_DETACH),
]


@pytest.mark.parametrize("extra,rule", FORBIDDEN_INSERTS, ids=[" ".join(e) for e, _ in FORBIDDEN_INSERTS])
@pytest.mark.parametrize("at", [3, -2])
def test_forbidden_tokens_are_destructive_with_rule_id(extra: list[str], rule: str, at: int) -> None:
    base = _esp("esp32s3", ("octal", 8))
    assert _rule(_insert(base, extra, at=at)) == rule


@pytest.mark.parametrize("chip", list(B.CHIP_NAMES))
def test_forbidden_tokens_for_every_chip(chip: str) -> None:
    base = _esp(chip, ("none", None))
    assert _rule(_insert(base, ["-gdb", "tcp::1234"])) == P.RULE_GDB
    assert _rule(_insert(base, ["-netdev", "user,id=n"])) == P.RULE_NETWORK
    assert _rule(_insert(base, ["-semihosting-config", "enable=on"])) == P.RULE_SEMIHOSTING


def test_value_changes_in_the_template() -> None:
    base = _esp()
    assert _rule([("mon:stdio" if t == "stdio" else t) for t in base]) == P.RULE_MONITOR
    assert _rule(_replace_value(base, "-monitor", "stdio")) == P.RULE_MONITOR
    assert _rule(_replace_value(base, "-monitor", "telnet::4444,server")) == P.RULE_MONITOR
    assert _rule(_replace_value(base, "-nic", "user,hostfwd=tcp::2222-:22")) == P.RULE_NETWORK
    assert _rule(_replace_value(base, "-display", "gtk")) == P.RULE_DEVICE
    assert _rule(_replace_value(base, "-serial", "file:out.txt")) == P.RULE_HOST_FILE
    assert _rule(_replace_value(base, "-serial", "unix:s.sock,server=on")) == P.RULE_HOST_FILE
    assert _rule(_replace_value(base, "-machine", "esp32s3,firmware=x.bin")) == P.RULE_DEVICE
    assert _rule(_replace_value(base, "-accel", "kvm")) == P.RULE_UNEXPECTED
    # --opt 는 -opt 와 같다
    assert _rule([("--monitor" if t == "-monitor" else t) for t in _replace_value(base, "-monitor", "stdio")]) == P.RULE_MONITOR


def test_missing_defaults_is_config_rule() -> None:
    base = _esp()
    assert _rule([t for t in base if t != "-no-user-config"]) == P.RULE_CONFIG
    assert _rule([t for t in base if t != "-nodefaults"]) == P.RULE_CONFIG


def test_order_changes_and_extra_tokens_are_unexpected() -> None:
    base = _esp("esp32s3", ("quad", 4), "disabled", "exit")
    i_disp, i_mon = base.index("-display"), base.index("-monitor")
    swapped = base[:i_disp] + base[i_mon:i_mon + 2] + base[i_disp:i_disp + 2] + base[i_mon + 2:]
    assert _rule(swapped) == P.RULE_UNEXPECTED
    snap = base.index("-snapshot")
    assert _rule(base[:snap] + ["-no-reboot", "-snapshot"]) == P.RULE_UNEXPECTED
    assert _rule(base + ["-snapshot"]) == P.RULE_UNEXPECTED
    assert _rule(_insert(base, ["-name", "x"])) == P.RULE_UNEXPECTED
    assert _rule(_insert(base, ["-cpu", "max"])) == P.RULE_UNEXPECTED
    assert _rule(_insert(base, ["-M", "esp32s3"])) == P.RULE_UNEXPECTED
    assert _rule(base + ["extra"]) == P.RULE_UNEXPECTED
    # 머신이 실행 파일과 맞지 않음, PSRAM 크기·모드가 칩에서 허용되지 않음
    assert _rule(_replace_value(base, "-machine", "esp32c3")) == P.RULE_UNEXPECTED
    esp32 = _esp("esp32", ("quad", 4))
    assert _rule(_replace_value(esp32, "-m", "8M")) == P.RULE_UNEXPECTED
    c3 = _esp("esp32c3", ("none", None))
    snap = c3.index("-snapshot")
    assert _rule(c3[:snap] + ["-m", "4M"] + c3[snap:]) == P.RULE_UNEXPECTED
    octal = _esp("esp32s3", ("octal", 8))
    assert _rule(_replace_value(octal, "-m", "2M")) == P.RULE_UNEXPECTED
    snap = esp32.index("-snapshot")
    assert _rule(esp32[:snap] + ["-global", B.GLOBAL_OCTAL] + esp32[snap:]) == P.RULE_UNEXPECTED
    # 칩과 맞지 않는 eFuse·WDT 드라이버
    assert _rule([t.replace("nvram.esp32s3.efuse", "nvram.esp32.efuse") for t in base]) == P.RULE_UNEXPECTED


def test_expected_argv_must_match_exactly() -> None:
    a = _esp("esp32s3", ("quad", 4), "disabled", "exit")
    b = _esp("esp32s3", ("quad", 4), "emulated", "exit")
    assert _rule(a, expected=b) == P.RULE_UNEXPECTED
    assert _rule(a, expected=a) == P.RULE_START


DRIVE_FORMS = [
    "file=flash.bin,if=mtd,format=raw",
    "file=json:{\"driver\":\"file\"},if=mtd,format=raw",
    "file=nbd:127.0.0.1:10809,if=mtd,format=raw",
    "file=/proc/self/fd/5,if=mtd",
    "file=/proc/self/fd/5,if=mtd,format=qcow2",
    "file=/proc/self/fd/5,if=pflash,format=raw",
    "file=/proc/self/fd/5,if=mtd,format=raw,readonly=on",
    "file=/proc/self/fd/5,if=mtd,format=raw,file.locking=off",
    "file=/etc/passwd,if=mtd,format=raw",
    "if=mtd,format=raw,file=/proc/self/fd/5",
]


@pytest.mark.parametrize("value", DRIVE_FORMS)
def test_drive_forms_outside_the_allowlist_are_host_file(value: str) -> None:
    base = _esp()
    i = base.index("-drive")
    assert _rule(base[:i + 1] + [value] + base[i + 2:]) == P.RULE_HOST_FILE


def test_drive_fd_numbers_must_be_distinct_memfds() -> None:
    same = B.build_esp_argv(XT, B.esp_target("esp32s3"), 5, 5)
    assert _rule(same) == P.RULE_UNEXPECTED
    low = B.build_esp_argv(XT, B.esp_target("esp32s3"), 1, 6)
    assert _rule(low) == P.RULE_UNEXPECTED


@pytest.mark.parametrize("exe", [
    "/usr/bin/qemu-system-x86_64", "qemu-system-xtensa", "./qemu-system-xtensa", "/x/qemu-system-xtensa.real", "/x/qemu-system-arm",
    "/bin/sh",
])
def test_exe_basename_allowlist(exe: str) -> None:
    base = _esp()
    assert _rule([exe] + base[1:]) == P.RULE_EXE


def test_exe_check_after_forbidden_scan() -> None:
    assert _rule(["/usr/bin/qemu-system-x86_64", "-gdb", "tcp::1"]) == P.RULE_GDB
    assert _rule([]) == P.RULE_EXE


# ---------------------------------------------------------------------------
# AVR
# ---------------------------------------------------------------------------


def test_avr_input_must_be_sealed_memfd() -> None:
    a = _avr()
    assert _rule(a[:-2] + ["fw.hex"]) == P.RULE_AVR_INPUT
    assert _rule(a + ["fw.elf"]) == P.RULE_AVR_INPUT
    assert _rule(a[:-1] + ["/tmp/fw.hex"]) == P.RULE_AVR_INPUT
    assert _rule(a[:-1] + ["2"]) == P.RULE_AVR_INPUT
    assert _rule(a[:-1] + ["0"]) == P.RULE_AVR_INPUT
    assert _rule(a[:-2]) == P.RULE_AVR_INPUT
    assert _rule(a[:-1]) == P.RULE_AVR_INPUT


def test_avr_target_values() -> None:
    a = _avr()
    assert _rule(_replace_value(a, "--mcu", "attiny85")) == P.RULE_AVR_TARGET
    assert _rule(_replace_value(a, "--mcu", "atmega328p;rm")) == P.RULE_AVR_TARGET
    assert _rule(_replace_value(a, "--freq", "99000000")) == P.RULE_AVR_TARGET
    assert _rule(_replace_value(a, "--freq", "999")) == P.RULE_AVR_TARGET
    assert _rule(_replace_value(a, "--freq", "16e6")) == P.RULE_AVR_TARGET
    assert _rule(_replace_value(a, "--uart", "1")) == P.RULE_AVR_TARGET  # atmega328p 에는 USART1 이 없다
    leo = _avr("leonardo")
    assert _rule(_replace_value(leo, "--uart", "0")) == P.RULE_AVR_TARGET  # atmega32u4 는 USART1 만


def test_avr_options_outside_allowlist_and_order() -> None:
    a = _avr()
    assert _rule(a + ["--max-cycles", "1000"]) == P.RULE_UNEXPECTED
    assert _rule(a + ["-g"]) == P.RULE_UNEXPECTED
    assert _rule(a + ["--gdb", "1234"]) == P.RULE_UNEXPECTED
    assert _rule(a + ["--version"]) == P.RULE_UNEXPECTED
    assert _rule([t for t in a if t != "--realtime"]) == P.RULE_UNEXPECTED
    assert _rule(a + ["--mcu", "atmega328p"]) == P.RULE_UNEXPECTED
    reordered = [a[0]] + a[3:5] + a[1:3] + a[5:]
    assert _rule(reordered) == P.RULE_UNEXPECTED
    assert _rule(["/x/run_avr"] + a[1:]) == P.RULE_EXE
    assert _rule(["pweh_avr_run"] + a[1:]) == P.RULE_EXE
    other = B.build_avr_argv(AVR, B.avr_target("mega2560", "atmega2560", 16_000_000, 0), HEX_FD)
    assert _rule(a, expected=other) == P.RULE_UNEXPECTED


def test_every_rule_id_is_used_by_the_tests() -> None:
    seen = {r for _, r in FORBIDDEN_INSERTS} | {P.RULE_EXE, P.RULE_UNEXPECTED, P.RULE_AVR_INPUT, P.RULE_AVR_TARGET}
    assert set(P.ARGV_RULES) <= seen
