"""리눅스 부팅 로그 + BusyBox 로그인/셸 흉내 테스트."""

from __future__ import annotations

import base64
import hashlib
import re

import pytest

from pweh.formats import parse_mtdparts, parse_proc_mtd
from pweh.safety import Risk, classify_linux

from .helpers import parse_hexdump_c


def test_boot_log_login_and_identity(device_factory, profile_name):
    dev, con = device_factory(profile_name)
    con.boot_to_shell()
    log = con.text().replace("\r\n", "\n")
    kn = dev.profile["kernel"]
    assert "## Booting kernel from Legacy Image at" in log
    assert "Starting kernel ..." in log
    assert kn["version_line"] in log
    cmdline = dev.profile["uboot"]["env"]["bootargs"]
    assert f"Kernel command line: {cmdline}\n" in log
    parts = parse_mtdparts(cmdline, total_size=16 << 20)
    assert f'Creating {len(parts)} MTD partitions on "{parts[0]["device"]}":' in log
    for p in parts:
        assert f'0x{p["offset"]:012x}-0x{p["offset"] + p["size"]:012x} : "{p["name"]}"' in log
    assert re.search(r"VFS: Mounted root \(squashfs filesystem\) readonly on device 31:3\.", log)
    assert "\nPlease press Enter to activate this console. " in log
    assert dev.state == "linux-shell"

    mtd = con.sh("cat /proc/mtd")
    assert mtd.split("\n")[0] == "dev:    size   erasesize  name"
    rows = parse_proc_mtd(mtd)
    assert [r["name"] for r in rows] == [p["name"] for p in parts]
    assert all(re.fullmatch(r'mtd\d+: [0-9a-f]{8} 00010000 "[a-z_]+"', ln) for ln in mtd.strip().split("\n")[1:])
    assert con.sh("cat /proc/cmdline") == cmdline + "\n"
    uname = con.sh("uname -a")
    assert uname.startswith(f"Linux {dev.profile['linux']['hostname']} {kn['version']} ")
    assert uname.strip().endswith(f"{kn['machine']} GNU/Linux")
    assert con.sh("id") == "uid=0(root) gid=0(root) groups=0(root)\n"
    cpu = con.sh("cat /proc/cpuinfo")
    assert ("ARMv7 Processor" in cpu) if dev.profile["arch"] == "arm" else ("Ingenic Xburst" in cpu)
    assert con.sh("xyzzy") == "-sh: xyzzy: not found\n"
    assert con.sh("echo $?") == "127\n"
    ps = con.sh("ps")
    assert ps.split("\n")[0] == "  PID USER       VSZ STAT COMMAND"
    assert "/usr/sbin/telnetd" in ps and "-sh" in ps
    assert "/dev/root on / type squashfs (ro,relatime)" in con.sh("mount")
    assert "busybox" in con.sh("ls /bin")
    assert con.sh("pwd") == "/root\n"
    assert "Currently defined functions:" in con.sh("busybox")


@pytest.mark.parametrize("mtd,count,bs", [(1, 1, 65536), (2, 3, 4096), (4, 2, 65536)])
def test_dd_hexdump_reconstructs_partition(device_factory, profile_name, mtd, count, bs):
    dev, con = device_factory(profile_name)
    con.boot_to_shell()
    part = dev.profile["partitions"][mtd]
    out = con.sh(f"dd if=/dev/mtd{mtd} bs={bs} skip=0 count={count} 2>/dev/null | hexdump -C")
    data = parse_hexdump_c(out)
    assert data == dev.flash.read(part["offset"], bs * count)
    # skip 사용 + dd 통계(stderr)는 출력 사이에 끼어든다 → 파서는 통계 줄을 걸러야 한다
    bs2 = min(bs, part["size"] // 2)
    out2 = con.sh(f"dd if=/dev/mtd{mtd} bs={bs2} skip=1 count=1 | hexdump -C")
    assert f"1+0 records in\n1+0 records out\n{bs2} bytes (" in out2
    stats = [ln for ln in out2.split("\n") if "records" in ln or "copied" in ln]
    clean = "\n".join(ln for ln in out2.split("\n") if ln not in stats)
    assert parse_hexdump_c(clean) == dev.flash.read(part["offset"] + bs2, bs2)
    # 파티션 끝을 넘는 skip 은 0 레코드 (mtdchar read 가 0 을 돌려줌)
    beyond = part["size"] // bs2
    assert con.sh(f"dd if=/dev/mtd{mtd} bs={bs2} skip={beyond} count=1 | hexdump -C").startswith("0+0 records in\n0+0 records out\n")


def test_md5sum_and_base64(device_factory):
    dev, con = device_factory("hisilicon-like")
    con.boot_to_shell()
    part = dev.profile["partitions"][1]
    whole = dev.flash.read(part["offset"], part["size"])
    assert con.sh("md5sum /dev/mtd1") == f"{hashlib.md5(whole).hexdigest()}  /dev/mtd1\n"
    chunk = dev.flash.read(part["offset"] + 4096, 4096)
    assert con.sh("dd if=/dev/mtd1 bs=4096 skip=1 count=1 2>/dev/null | md5sum") == f"{hashlib.md5(chunk).hexdigest()}  -\n"
    b64 = con.sh("dd if=/dev/mtd1 bs=4096 skip=1 count=1 2>/dev/null | base64")
    lines = b64.strip("\n").split("\n")
    assert all(len(ln) == 76 for ln in lines[:-1]) and len(lines[-1]) <= 76
    assert base64.b64decode("".join(lines)) == chunk
    shadow = con.sh("cat /etc/shadow")
    assert re.match(r"root:\$1\$[./0-9A-Za-z]{1,8}\$[./0-9A-Za-z]{22}:", shadow)


def test_ingenic_has_no_base64(device_factory):
    dev, con = device_factory("ingenic-like")
    con.boot_to_shell()
    assert con.sh("base64 /etc/passwd") == "-sh: base64: not found\n"
    assert con.sh("which hexdump md5sum dd") == "/usr/bin/hexdump\n/usr/bin/md5sum\n/bin/dd\n"


def test_destructive_shell_commands_are_recorded(device_factory):
    dev, con = device_factory("ingenic-like")
    con.boot_to_shell()
    con.sh("cat /proc/mtd; dd if=/dev/mtd1 bs=64 count=1 | hexdump -C; md5sum /dev/mtd2")
    assert dev.destructive_events == []
    env_part = dev.profile["partitions"][1]
    con.sh("flash_erase /dev/mtd1 0 0")
    assert dev.flash.read(env_part["offset"], 64) == b"\xff" * 64
    con.sh("echo hello > /dev/mtd4")
    con.sh("dd if=/dev/zero of=/dev/mtd3 bs=64 count=1")
    con.sh("fw_setenv bootdelay 9")
    con.sh("echo x > /mnt/mtd/cfg")
    reasons = [e["reason"] for e in dev.destructive_events]
    assert reasons == ["flash_erase", "redirect > /dev/mtd4", "dd of=flash", "fw_setenv", "redirect > /mnt/mtd/cfg"]
    for line in ("flash_erase /dev/mtd1 0 0", "echo hello > /dev/mtd4", "dd if=/dev/zero of=/dev/mtd3 bs=64 count=1",
                 "fw_setenv bootdelay 9", "echo x > /mnt/mtd/cfg"):
        assert classify_linux(line, persistent_paths=["/mnt/mtd"]).risk == Risk.DESTRUCTIVE, line
    # read-only 루트 파일시스템
    assert con.sh("echo x > /etc/passwd") == "-sh: can't create /etc/passwd: Read-only file system\n"
    assert con.sh("echo ok > /tmp/f; cat /tmp/f") == "ok\n"


def test_wrong_password_logout_and_relogin(device_factory):
    dev, con = device_factory("hisilicon-like")
    con.read_until(r"Please press Enter to activate this console\. $", timeout=20)
    con.write(b"\r")
    con.read_until(r"login: $")
    con.write(b"root\r")
    con.read_until(r"Password: $")
    con.write(b"wrong\r")
    con.read_until(r"Login incorrect\r\n\(none\) login: $")
    con.write(b"root\r")
    con.read_until(r"Password: $")
    con.write(dev.profile["linux"]["login"]["password"].encode() + b"\r")
    con.read_until(r"\r\n# $")
    con.mark = len(con.buf)
    start = len(con.buf)
    con.write(b"exit\r")
    con.read_until(r"Please press Enter to activate this console\. $", start=start)
    assert dev.wait_for_state("linux-login", 2)
    logins = [e for e in dev.events if e["type"] == "login"]
    assert [e["ok"] for e in logins] == [False, True]
    # 비밀번호는 이벤트에 남지 않는다
    assert all(e.get("line") in ("<masked>", "<username>") for e in dev.events if e.get("context") in ("password", "login"))


def test_ctrl_c_and_line_editing_in_shell(device_factory):
    dev, con = device_factory("ingenic-like")
    con.boot_to_shell()
    start = len(con.buf)
    con.write(b"echo abc\x7f\x7fz")
    con.read_until(r"z", start=start)
    con.write(b"\x03")
    con.read_until(r"\r\n# $", start=start)
    con.mark = len(con.buf)
    assert con.sh("echo abc\x08d") == "abd\n"


def test_reboot_power_cycle_and_tcp(device_factory):
    dev, con = device_factory("hisilicon-like", tcp=True)
    con.boot_to_shell()
    start = len(con.buf)
    con.write(b"reboot\r")
    con.read_until(r"Requesting system reboot", start=start)
    con.read_until(r"System startup", start=start, timeout=10)
    assert dev.boot_count == 2
    dev.power_cycle()
    con.read_until(r"Please press Enter", start=start, timeout=20)
    assert dev.boot_count == 3
    assert [e["action"] for e in dev.events if e["type"] == "power"] == ["on", "off", "on"]
