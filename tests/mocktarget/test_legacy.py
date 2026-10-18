"""hisilicon-legacy 프로필 (HiSilicon V1~V3, U-Boot 2010.06 포크) 고유 동작 테스트."""

from __future__ import annotations

import re

from pweh.formats import parse_md_b_output, parse_uboot_env


def test_legacy_uboot_2010_formats(device_factory):
    dev, con = device_factory("hisilicon-legacy")
    con.interrupt_autoboot()
    text = con.text().replace("\r\n", "\n")
    assert "\n\nSystem startup\n\n\nU-Boot 2010.06 (Mar 05 2018 - 10:12:41)\n\n" in text
    assert con.cmd("version") == "\nU-Boot 2010.06 (Mar 05 2018 - 10:12:41)\n"  # CC/LD 줄 없음
    env = con.cmd("printenv").strip("\n").split("\n")
    names = [ln.split("=", 1)[0] for ln in env[:-2]]
    # 2010.06: 플래시 저장 순서 + 실행 중 setenv 된 stdin/stdout/stderr/ver 가 뒤에 붙는다
    assert names[:3] == ["bootargs", "bootcmd", "bootdelay"]
    assert names[-4:] == ["stdin", "stdout", "stderr", "ver"]
    kv = [ln.split("=", 1) for ln in env[:-2]]
    used = sum(len(k) + 1 + len(v) + 1 for k, v in kv)
    assert env[-1] == f"Environment size: {used}/262140 bytes"
    assert 'bootfile="uImage"' in env
    con.cmd("setenv bootdelay 2")
    names2 = [ln.split("=", 1)[0] for ln in con.cmd("printenv").strip("\n").split("\n")[:-2]]
    assert names2[-1] == "bootdelay"  # setenv 는 지우고 끝에 덧붙인다
    assert con.cmd("help md") == "md - memory display\n\n"  # CONFIG_SYS_LONGHELP 없음
    assert con.cmd("sf probe") == "Usage: sf probe [bus:]cs [hz] [mode]\n"
    assert con.cmd("sf probe 0") == "16384 KiB hi_fmc at 0:0 is now current device\n"
    assert con.cmd("sf read 0x82000000 0xc0000 0x13") == "\n"  # 성공 시 빈 줄 하나
    md = con.cmd("md.b 0x82000000 0x13")
    lines = md.strip("\n").split("\n")
    assert re.fullmatch(r"82000010: [0-9a-f]{2} [0-9a-f]{2} [0-9a-f]{2}    .{3}", lines[1])  # 패딩 없음
    data, problems = parse_md_b_output(md, 0x82000000, 0x13)
    assert problems == [] and data == dev.flash.read(0xC0000, 0x13)
    bd = con.cmd("bdinfo")
    assert "arch_number = 0x00001F40\nenv_t       = 0x00000000\n" in bd and "relocaddr" not in bd
    assert con.cmd("crc32 0x82000000 0x13").startswith("CRC32 for 82000000 ... 82000012 ==> ")
    assert "tftp    - tftp\t- download or upload image via network using TFTP protocol" in con.cmd("help")


def test_legacy_erased_env_is_rewritten_at_boot(device_factory):
    dev, con = device_factory("hisilicon-legacy", power=False)
    dev.flash.erase(0x80000, 0x40000)
    dev.power_on()
    con.interrupt_autoboot()
    text = con.text().replace("\r\n", "\n")
    assert ("*** Warning - bad CRC, using default environment\n\n*** Write default environment to flash\n"
            "Erasing SPI flash, offset 0x00080000 size 256K ...done\n"
            "Writing to SPI flash, offset 0x00080000 size 256K ...done\nIn:    serial\n") in text
    res = parse_uboot_env(dev.flash.read(0x80000, 0x40000))
    assert res is not None and res["env"]["bootcmd"] == "bootm 0x82000000"
    # 기기 스스로 한 기록은 콘솔 입력으로 인한 파괴적 작업 목록에 넣지 않는다
    assert dev.destructive_events == []
    assert any(e["type"] == "device_autonomous_write" for e in dev.events)


def test_legacy_linux_boot_and_login(device_factory):
    dev, con = device_factory("hisilicon-legacy")
    con.boot_to_shell()
    log = con.text().replace("\r\n", "\n")
    assert "16384 KiB hi_fmc at 0:0 is now current device\n\n## Booting kernel from Legacy Image at 82000000 ..." in log
    assert "   Loading Kernel Image ... OK\nOK\n\nStarting kernel ...\n" in log  # 2010.06: OK 두 번
    assert '0x0000000c0000-0x0000003c0000 : "kernel"' in log
    cpu = con.sh("cat /proc/cpuinfo")
    assert cpu.startswith("Processor\t: ARM926EJ-S rev 5 (v5l)\n")
    assert con.sh("uname -m") == "armv5tejl\n"


def test_login_without_password(device_factory):
    dev, con = device_factory("ingenic-like", overrides={"linux": {"login": {"password": ""}}})
    con.read_until(r"Please press Enter to activate this console\. $", timeout=20)
    con.write(b"\r")
    con.read_until(r"login: $")
    con.write(b"root\r")
    con.read_until(r"\r\n# $")
    assert dev.state == "linux-shell"
    assert "Password:" not in con.text()
