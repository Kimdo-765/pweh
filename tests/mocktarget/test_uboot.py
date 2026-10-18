"""U-Boot 콘솔 흉내 테스트 (pyserial 로 PTY 를 실제 클라이언트처럼 구동)."""

from __future__ import annotations

import re
import zlib

import pytest

from pweh.formats import parse_crc32_line, parse_md_b_output, parse_mtdparts, parse_uboot_env
from pweh.safety import Risk, UBootContext, classify_uboot


CRC_ANY_CASE = re.compile(r"(?i)crc32 for ([0-9a-f]+) \.\.\. ([0-9a-f]+) ==> ([0-9a-f]{8})")


def ram_addr(dev) -> int:
    return int(dev.profile["uboot"]["loadaddr"])


def test_banner_and_autoboot_interrupt(device_factory, profile_name):
    dev, con = device_factory(profile_name)
    con.interrupt_autoboot()
    text = con.text()
    ub = dev.profile["uboot"]
    assert ub["version"] in text
    assert re.search(r"DRAM:\s+64 MiB", text)
    assert "In:    serial\nOut:   serial\nErr:   serial" in text.replace("\r\n", "\n")
    if profile_name == "ingenic-like":
        assert "SF: Detected BY25Q128AS" in text and "U-Boot SPL 2013.07" in text
    else:
        assert 'Name:"W25Q128(B/F)V"' in text
    # common/autoboot.c: "Hit any key to stop autoboot: %2d " + "\b\b\b%2d " 갱신 + 개행
    raw = bytes(con.buf)
    delay = int(ub["env"]["bootdelay"])
    m = re.search(rb"Hit any key to stop autoboot: (\s?\d) ((?:\x08\x08\x08\s?\d )*)", raw)
    assert m, raw[-300:]
    assert m.group(1) == b"%2d" % delay
    assert raw.endswith(ub["prompt"].encode())
    assert dev.state == "uboot"
    assert any(e["type"] == "autoboot_interrupted" for e in dev.events)


def test_any_key_interrupts_and_extra_keys_reach_prompt(device_factory):
    dev, con = device_factory("hisilicon-like")
    con.interrupt_autoboot(key=b" ")
    # 첫 키만 abortboot 가 소비하고 나머지 공백은 명령 줄 편집기로 간다 → 공백 줄은 아무 일도 안 한다
    out = con.cmd("version")
    assert dev.profile["uboot"]["version"] in out


def test_version_printenv_bdinfo_formats_hisilicon(device_factory):
    dev, con = device_factory("hisilicon-like")
    con.interrupt_autoboot()
    out = con.cmd("version")
    assert out.startswith("\nU-Boot 2016.11 (Mar 23 2020 - 14:58:03 +0800)hi3516ev300\n")
    assert "arm-himix100-linux-gcc" in out and "GNU ld" in out

    env_out = con.cmd("printenv")
    lines = env_out.strip("\n").split("\n")
    m = re.match(r"Environment size: (\d+)/(\d+) bytes", lines[-1])
    assert m and int(m.group(2)) == 0x10000 - 4
    assert lines[-2] == ""
    kv = [ln.split("=", 1) for ln in lines[:-2]]
    names = [k for k, _ in kv]
    assert names == sorted(names)  # 해시테이블 env 는 정렬 출력
    env = dict(kv)
    parts = parse_mtdparts(env["bootargs"], total_size=16 << 20)
    assert [p["name"] for p in parts] == ["boot", "env", "kernel", "rootfs", "app"]
    assert env["stdin"] == "serial"
    # 2013.07~2016.11 hexport_r 크기 계산 (항목당 len(k)+len(v)+4, +1)
    assert int(m.group(1)) == sum(len(k) + len(v) + 4 for k, v in kv) + 1

    bd = con.cmd("bdinfo")
    assert re.search(r"^DRAM bank   = 0x00000000$", bd, re.M)
    assert re.search(r"^-> start    = 0x40000000$", bd, re.M)
    assert re.search(r"^-> size     = 0x04000000$", bd, re.M)
    assert re.search(r"^relocaddr   = 0x43F9E000$", bd, re.M)
    assert re.search(r"^baudrate    = 115200 bps$", bd, re.M)

    one = con.cmd("printenv bootdelay nosuchvar")
    assert one == 'bootdelay=2\n## Error: "nosuchvar" not defined\n'


def test_version_printenv_bdinfo_formats_ingenic(device_factory):
    dev, con = device_factory("ingenic-like")
    con.interrupt_autoboot()
    out = con.cmd("version")
    assert out.startswith("\nU-Boot 2013.07 (Dec 09 2020 - 11:32:38)\n")
    env_out = con.cmd("printenv")
    assert re.search(r"\nEnvironment size: \d+/65532 bytes\n$", env_out)
    bd = con.cmd("bdinfo")
    assert re.search(r"^memstart    = 0x80000000$", bd, re.M)
    assert re.search(r"^memsize     = 0x04000000$", bd, re.M)
    assert "relocaddr" not in bd  # MIPS 2013.07 bdinfo 에는 relocaddr 가 없다


@pytest.mark.parametrize("length", [0x40, 0x123])
def test_sf_read_md_b_matches_flash(device_factory, profile_name, length):
    dev, con = device_factory(profile_name)
    con.interrupt_autoboot()
    probe = con.cmd("sf probe 0")
    assert "SF: Detected" in probe
    addr = ram_addr(dev)
    kern = next(p for p in dev.profile["partitions"] if p["name"] == "kernel")
    rd = con.cmd(f"sf read 0x{addr:x} 0x{kern['offset']:x} 0x{length:x}")
    assert f"SF: {length} bytes @ 0x{kern['offset']:x} Read: OK" in rd
    out = con.cmd(f"md.b 0x{addr:x} 0x{length:x}")
    data, problems = parse_md_b_output(out, addr, length)
    assert problems == []
    expected = dev.flash.read(kern["offset"], length)
    assert data == expected == dev.ram.read(addr, length)
    assert data[:4] == b"\x27\x05\x19\x56"  # uImage 매직
    # 줄 형식: 주소: 바이트들 + 4칸 + ASCII (마지막 짧은 줄도 ASCII 열 정렬)
    first = out.split("\n")[0]
    assert re.fullmatch(r"[0-9a-f]{8}:( [0-9a-f]{2}){16}    .{16}", first)


def test_crc32_matches_zlib(device_factory, profile_name):
    dev, con = device_factory(profile_name)
    con.interrupt_autoboot()
    con.cmd("sf probe 0")
    addr = ram_addr(dev)
    con.cmd(f"sf read 0x{addr:x} 0x0 0x10000")
    out = con.cmd(f"crc32 0x{addr:x} 0x10000")
    # 실제 카메라 빌드(SHA256/CMD_HASH 미설정)는 hash.c 의 대문자 "CRC32 for" 경로를 쓴다
    assert out.startswith("CRC32 for ")
    m = CRC_ANY_CASE.search(out)
    assert m and int(m.group(1), 16) == addr and int(m.group(2), 16) == addr + 0xFFFF
    assert int(m.group(3), 16) == zlib.crc32(dev.flash.read(0, 0x10000)) & 0xFFFFFFFF


def test_crc32_lowercase_style_override(device_factory):
    dev, con = device_factory("hisilicon-like", overrides={"uboot": {"crc32_style": "lower"}})
    con.interrupt_autoboot()
    con.cmd("sf probe 0")
    con.cmd("sf read 0x42000000 0x40000 0x1000")
    out = con.cmd("crc32 0x42000000 0x1000")
    r = parse_crc32_line(out)  # pweh.formats 파서는 소문자 형식만 인식
    assert r == {"start": 0x42000000, "end": 0x42000FFF, "crc32": zlib.crc32(dev.flash.read(0x40000, 0x1000)) & 0xFFFFFFFF}


def test_md_formats_words_little_endian(device_factory):
    dev, con = device_factory("ingenic-like")
    con.interrupt_autoboot()
    dev.ram.write(0x80600000, bytes(range(1, 33)))
    out_l = con.cmd("md.l 0x80600000 5")
    assert out_l.split("\n")[0] == "80600000: 04030201 08070605 0c0b0a09 100f0e0d    ................"
    assert out_l.split("\n")[1] == "80600010: 14131211" + " " * 27 + "    ...."
    out_w = con.cmd("md.w 0x80600000 3")
    assert out_w == "80600000: 0201 0403 0605" + " " * 25 + "    ......\n"
    # 크기 접미사가 없으면 .l, 개수를 생략하면 직전 md 의 개수(3)를 이어 쓴다 (dp_last_length)
    out = con.cmd("md 0x80600000")
    assert out == "80600000: 04030201 08070605 0c0b0a09" + " " * 9 + "    ............\n"


def test_md_default_length_is_0x40(device_factory):
    dev, con = device_factory("hisilicon-like")
    con.interrupt_autoboot()
    out = con.cmd("md.b 0x42000000")
    assert len(out.strip("\n").split("\n")) == 4  # 0x40 바이트 = 16바이트 4줄
    out = con.cmd("md 0x42000000")
    assert len(out.strip("\n").split("\n")) == 16  # 0x40 개의 .l = 256 바이트


def test_empty_line_repeats_md_at_next_address(device_factory, profile_name):
    dev, con = device_factory(profile_name)
    con.interrupt_autoboot()
    base = ram_addr(dev)
    dev.ram.write(base, bytes(range(256)) * 4)
    first = con.cmd(f"md.b 0x{base:x} 0x20")
    rep = con.cmd("")
    rep2 = con.cmd("")
    d1, p1 = parse_md_b_output(first, base, 0x20)
    d2, p2 = parse_md_b_output(rep, base + 0x20, 0x20)
    d3, p3 = parse_md_b_output(rep2, base + 0x40, 0x20)
    assert p1 == p2 == p3 == []
    assert d1 + d2 + d3 == (bytes(range(256)) * 4)[:0x60]
    reps = [e for e in dev.events if e["type"] == "uboot_exec" and e.get("repeat")]
    assert len(reps) == 2 and reps[0]["command"] == "md"


def test_ctrl_c_interrupt_and_repeat_semantics_simple_parser(device_factory):
    dev, con = device_factory("ingenic-like")
    con.interrupt_autoboot()
    start = len(con.buf)
    con.write(b"md.b 0x80600000 0x10")
    con.read_until(r"md\.b 0x80600000 0x10", start=start)
    con.write(b"\x03")  # 입력 중 Ctrl-C: 줄 버림, 에코 없이 <INTERRUPT>
    con.read_until(r"<INTERRUPT>\r\n" + re.escape(con.prompt) + "$", start=start)
    assert "md.b 0x80600000 0x10<INTERRUPT>" in con.text(start)
    con.mark = len(con.buf)
    con.cmd("md.b 0x80600000 0x10")
    con.write(b"\x03")
    con.read_until(r"<INTERRUPT>\r\n" + re.escape(con.prompt) + "$")
    con.mark = len(con.buf)
    # simple 파서(main.c): Ctrl-C 뒤에도 lastcommand 가 남아 빈 Enter 가 md 를 이어서 반복한다
    rep = con.cmd("")
    assert rep.startswith("80600010:")


def test_hush_parser_ctrl_c_clears_repeat_and_nonrepeatable(device_factory):
    dev, con = device_factory("hisilicon-like")
    con.interrupt_autoboot()
    con.cmd("md.b 0x42000000 0x10")
    con.write(b"\x03")
    con.read_until(r"<INTERRUPT>\r\n" + re.escape(con.prompt) + "$")
    con.mark = len(con.buf)
    assert con.cmd("") == ""  # hush: Ctrl-C 가 flag_repeat 를 지운다
    con.cmd("md.b 0x42000000 0x10")
    assert con.cmd("").startswith("42000010:")
    con.cmd("setenv pweh_x 1")  # setenv 는 반복 불가 명령
    assert con.cmd("") == ""
    n_set = [e for e in dev.events if e["type"] == "uboot_exec" and e["command"] == "setenv"]
    assert len(n_set) == 1


def test_abbreviations_unknown_and_ambiguous(device_factory, profile_name):
    dev, con = device_factory(profile_name)
    con.interrupt_autoboot()
    assert con.cmd("pri bootdelay").startswith("bootdelay=")
    assert con.cmd("ver").startswith("\nU-Boot")
    assert con.cmd("xyzzy") == "Unknown command 'xyzzy' - try 'help'\n"
    assert con.cmd("s") == "Unknown command 's' - try 'help'\n"  # sf/setenv/saveenv/sleep → 모호
    helptext = con.cmd("help")
    assert re.search(r"^printenv- print environment variables$", helptext, re.M)
    assert re.search(r"^md      - memory display$", helptext, re.M)


def test_semicolons_quotes_and_variables(device_factory, profile_name):
    dev, con = device_factory(profile_name)
    con.interrupt_autoboot()
    out = con.cmd("setenv pw 'echo one; echo two'; printenv pw")
    assert out == "pw=echo one; echo two\n"
    assert con.cmd("run pw") == "one\ntwo\n"
    assert con.cmd("echo a; xyzzy; echo b") == "a\nUnknown command 'xyzzy' - try 'help'\nb\n"
    if profile_name == "ingenic-like":
        assert con.cmd("echo $(bootdelay) ${bootdelay}") == "1 1\n"
    else:
        assert con.cmd('echo "$bootdelay" ${bootdelay} \'$bootdelay\'') == "2 2 $bootdelay\n"


def test_hush_continuation_prompt(device_factory):
    dev, con = device_factory("hisilicon-like")
    con.interrupt_autoboot()
    start = len(con.buf)
    con.write(b'echo "abc\r')
    con.read_until(r"\r\n> $", start=start)
    con.write(b'def"\r')
    con.read_until(re.escape(con.prompt) + "$", start=start + 8)
    assert "abc\r\ndef\r\n" in con.text(start)
    con.mark = len(con.buf)
    assert con.cmd("if test 1 = 1; then echo yes; else echo no; fi") == "yes\n"
    assert con.cmd("true && echo ok || echo bad") == "ok\n"


def test_sf_errors_and_usage(device_factory):
    dev, con = device_factory("hisilicon-like")
    con.interrupt_autoboot()
    assert con.cmd("sf read 0x42000000 0 0x10") == "No SPI flash selected. Please run `sf probe'\n"
    con.cmd("sf probe")
    assert con.cmd("sf read 0x42000000 0xfff000 0x2000") == "ERROR: attempting read past flash size (0x1000000)\n"
    usage = con.cmd("md")
    assert usage.startswith("md - memory display\n\nUsage:\nmd [.b, .w, .l] address [# of objects]")


def test_destructive_commands_reach_device_are_recorded(device_factory):
    dev, con = device_factory("hisilicon-like")
    con.interrupt_autoboot()
    assert dev.destructive_events == []
    con.cmd("printenv")
    con.cmd("sf probe 0")
    con.cmd("sf read 0x42000000 0x0 0x100")
    con.cmd("md.b 0x42000000 0x10")
    con.cmd("crc32 0x42000000 0x100")
    assert dev.destructive_events == []  # INTERACT 수준 명령은 기록되지 않는다
    before = dev.flash.read(0x40000, 0x10000)
    con.cmd("setenv pweh_marker 1")
    out = con.cmd("saveenv")
    assert out.startswith("Saving Environment to SPI Flash...\n")
    assert "Writing to SPI flash...done" in out
    after = dev.flash.read(0x40000, 0x10000)
    assert before != after and parse_uboot_env(after)["env"]["pweh_marker"] == "1"
    con.cmd("mw.l 0x42000000 0xdeadbeef 4")
    assert dev.ram.read(0x42000000, 4) == bytes.fromhex("efbeadde")
    con.cmd("sf erase 0x7f0000 0x10000")
    assert dev.flash.read(0x7F0000, 16) == b"\xff" * 16
    con.cmd("sf write 0x42000000 0x7f0000 0x10")
    assert dev.flash.read(0x7F0000, 4) == bytes.fromhex("efbeadde")
    con.cmd("cp.b 0x42000000 0x42100000 0x10")
    con.cmd("env save")
    ops = [e["op"] for e in dev.destructive_events]
    assert ops == ["saveenv", "mw", "sf erase", "sf write", "cp", "saveenv"]
    # 시뮬레이터가 파괴적이라고 기록한 명령은 코어 분류기도 DESTRUCTIVE 로 본다
    for cmdline in ("saveenv", "mw.l 0x42000000 0xdeadbeef 4", "sf erase 0x7f0000 0x10000",
                    "sf write 0x42000000 0x7f0000 0x10", "cp.b 0x42000000 0x42100000 0x10", "env save"):
        assert classify_uboot(cmdline).risk == Risk.DESTRUCTIVE, cmdline
    for cmdline in ("printenv", "sf probe 0", "sf read 0x42000000 0x0 0x100", "md.b 0x42000000 0x10",
                    "crc32 0x42000000 0x100"):
        assert classify_uboot(cmdline).risk <= Risk.INTERACT, cmdline


def test_empty_enter_repeats_destructive_command(device_factory):
    """빈 Enter 가 직전 mw 를 다시 실행한다 — 안전 설계(빈 줄 = 직전 명령 위험도 상속)의 근거."""
    dev, con = device_factory("ingenic-like")
    con.interrupt_autoboot()
    con.cmd("mw.b 0x80600000 0x55 1")
    con.cmd("")
    assert [e.get("repeat") for e in dev.destructive_events] == [False, True]
    ctx = UBootContext(last_command="mw.b 0x80600000 0x55 1")
    assert classify_uboot("", ctx=ctx).risk == Risk.DESTRUCTIVE


def test_saveenv_persists_and_bad_crc_falls_back(device_factory):
    dev, con = device_factory("ingenic-like")
    con.interrupt_autoboot()
    con.cmd("setenv bootdelay 3")
    con.cmd("saveenv")
    dev.power_cycle()
    con.interrupt_autoboot()
    assert con.cmd("printenv bootdelay") == "bootdelay=3\n"
    # env 블록을 망가뜨리면 다음 부팅에서 기본 env + 경고
    dev.flash.erase(0x40000, 0x10000)
    con.mark = len(con.buf)
    dev.power_cycle()
    con.interrupt_autoboot()
    assert "*** Warning - bad CRC, using default environment" in con.text()
    assert con.cmd("printenv bootcmd") == "bootcmd=" + dev.profile["uboot"]["default_env"]["bootcmd"] + "\n"


def test_bootm_rejects_corrupted_image(device_factory):
    dev, con = device_factory("hisilicon-like")
    con.interrupt_autoboot()
    con.cmd("sf probe 0")
    con.cmd("sf read 0x42000000 0x50000 0x200000")
    dev.ram.write(0x42000000 + 0x1000, b"\x00\x11\x22\x33")  # 데이터 손상
    con.cmd("setenv verify y")  # 프로필 env 는 verify=n (검사 생략) — 켜서 데이터 CRC 를 확인하게 한다
    out = con.cmd("bootm 0x42000000")
    assert "## Booting kernel from Legacy Image at 42000000 ..." in out
    assert "Image Name:   Linux-4.9.37" in out
    assert "Image Type:   ARM Linux Kernel Image (uncompressed)" in out
    assert out.endswith("   Verifying Checksum ... Bad Data CRC\nERROR: can't get kernel image!\n")
    out2 = con.cmd("bootm 0x43000000")
    assert out2 == "Wrong Image Format for bootm command\nERROR: can't get kernel image!\n"
    assert dev.state == "uboot"


def test_iminfo_and_tftp_simulated_failure(device_factory):
    dev, con = device_factory("hisilicon-like")
    con.interrupt_autoboot()
    con.cmd("sf probe 0")
    con.cmd("sf read 0x42000000 0x50000 0x200000")
    out = con.cmd("iminfo 0x42000000")
    assert "Legacy image found" in out and out.endswith("Verifying Checksum ... OK\n")
    start = len(con.buf)
    con.write(b"tftpboot 0x42000000 uImage\r")
    con.read_until(r"Loading: (T )+", start=start, timeout=10)
    con.write(b"\x03")
    con.read_until(r"\r\nAbort\r\n" + re.escape(con.prompt) + "$", start=start)
    assert any(e["type"] == "network" and e["simulated"] for e in dev.events)


def test_reset_restarts_boot(device_factory):
    dev, con = device_factory("ingenic-like")
    con.interrupt_autoboot()
    start = len(con.buf)
    con.write(b"reset\r")
    con.read_until(r"resetting \.\.\.", start=start)
    con.read_until(r"U-Boot SPL 2013\.07", start=start, timeout=10)
    con.interrupt_autoboot()
    assert dev.boot_count == 2


def test_rx_fifo_overrun_while_busy(device_factory):
    """명령 실행 중 보낸 긴 입력은 RX FIFO 크기만큼만 남는다 (실제 UART 처럼)."""
    dev, con = device_factory("ingenic-like")
    con.interrupt_autoboot()
    con.cmd("sf probe")
    start = len(con.buf)
    # sf read 16MiB 는 시뮬레이션 시간으로 수 초 걸린다 → 그 사이에 보낸 200바이트 중 64바이트만 남음
    con.write(b"sf read 0x80600000 0 0x1000000\r" + b"x" * 200)
    con.read_until(r"Read: OK", start=start, timeout=20)
    con.read_until(re.escape(con.prompt) + "x+$", start=start, timeout=5)
    con.drain()
    tail = con.text(start).rsplit(con.prompt, 1)[1]
    assert 0 < len(tail) <= dev.profile["uart"]["rx_fifo"]
    assert dev.rx_overruns > 0


DESTRUCTIVE_LINES = [
    "saveenv",
    "env save",
    "sf write 0x{ram:x} 0x7f0000 0x10",      # sf probe 전 → "No SPI flash selected" 로 끝나도 기록
    "sf erase 0x7f0000 0x10000",
    "sf update 0x{ram:x} 0x7f0000 0x10",
    "mw.b 0x{ram:x} 0 1",
    "mw.x 1 2",                              # 잘못된 크기 접미사 → 조용히 실패해도 기록
    "mw",                                    # 인자 부족 → 사용법 출력이어도 기록
    "cp.b 0x{ram:x} 0x{ram2:x} 4",
    "nand erase 0 0x10000",                  # 이 기기에 없는 명령 → Unknown command 여도 기록
    "nand write 0x{ram:x} 0 0x100",
    "nan e 0 0x10000",                       # 약어
    "erase 0x0 0x1000",
    "protect off all",
    "mmc write 0x{ram:x} 0 1",
    "fatwrite mmc 0 0x{ram:x} x 4",
    "source 0x{ram:x}",
    "s",                                     # saveenv/setenv/sf/sleep 모호 약어 → 가장 위험한 후보 기준
]


@pytest.mark.parametrize("profile", ["hisilicon-like", "ingenic-like", "hisilicon-legacy"])
def test_every_classifier_destructive_line_is_recorded(device_factory, profile):
    """분류기가 DESTRUCTIVE 로 보는 줄은 (구현/인자 오류/알 수 없는 명령과 무관하게) 기기에 도달하면 기록된다."""
    dev, con = device_factory(profile)
    con.interrupt_autoboot()
    ram = ram_addr(dev)
    for template in DESTRUCTIVE_LINES:
        line = template.format(ram=ram, ram2=ram + 0x100000)
        assert classify_uboot(line).risk == Risk.DESTRUCTIVE, line
        before = len(dev.destructive_events)
        con.cmd(line, timeout=20)
        new = dev.destructive_events[before:]
        assert len(new) == 1, (line, new)
        assert new[0]["cmd"] == line
    # 대화형 mm 도 (입력 대기 중 Ctrl-C 로 빠져나와도) 기록된다
    before = len(dev.destructive_events)
    start = len(con.buf)
    con.write(f"mm.b 0x{ram:x}\r".encode())
    con.read_until(r" \? $", start=start)
    con.write(b"\x03")
    con.read_until(re.escape(con.prompt) + "$", start=start + 5)
    con.mark = len(con.buf)
    assert [e["cmd"] for e in dev.destructive_events[before:]] == [f"mm.b 0x{ram:x}"]
    # 실제로 상태를 바꾼 것만 applied
    applied = {e["cmd"]: e["applied"] for e in dev.destructive_events}
    assert applied["saveenv"] is True and applied["nand erase 0 0x10000"] is False and applied["mw"] is False
