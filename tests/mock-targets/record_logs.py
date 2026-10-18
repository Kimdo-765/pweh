#!/usr/bin/env python3
"""시뮬레이터를 실제로 돌려 ``recorded/`` 의 콘솔 로그를 만든다 (손으로 쓰지 않는다).

    .venv/bin/python tests/mock-targets/record_logs.py              # 모든 내장 프로필
    .venv/bin/python tests/mock-targets/record_logs.py ingenic-like

만드는 파일 (원시 콘솔 바이트 그대로: \\r\\n, autoboot 의 \\b 포함):
- ``<profile>-boot.log``          전원 투입 → U-Boot → (autoboot 진행) → 커널 → "Please press Enter ..." 까지
- ``<profile>-uboot-session.log`` autoboot 중단(Ctrl-C) → printenv/bdinfo/version/sf probe/sf read/md.b/빈 Enter 반복/crc32
- ``<profile>-shell-session.log`` 로그인 → cat /proc/mtd 등 → dd | hexdump -C → md5sum

부팅 로그는 결정적이므로 ``tests/mocktarget/test_recorded.py`` 가 다시 만들어 비교한다.
"""

from __future__ import annotations

import argparse
import re
import sys
import time
from pathlib import Path

from pweh.mocktarget import MockDevice, list_profiles
from pweh.mocktarget.firmware import build_image_bytes

HERE = Path(__file__).resolve().parent
OUT = HERE / "recorded"


def _wait(dev: MockDevice, pattern: str, start: int = 0, timeout: float = 30.0) -> int:
    rx = re.compile(pattern.encode())
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        data = dev.console_output
        m = rx.search(data, start)
        if m:
            return m.end()
        time.sleep(0.01)
    raise TimeoutError(f"{pattern!r} not seen; tail={dev.console_output[-300:]!r}")


def make_device(profile: str, *, full: bool = True, time_scale: float = 0.01) -> MockDevice:
    data, manifest = build_image_bytes(profile, fast=not full)
    dev = MockDevice(profile, flash_image=data, time_scale=time_scale, autostart=False, autoboot_floor=0.15)
    dev.firmware_manifest = manifest
    return dev


def record_boot(profile: str, *, full: bool = True, time_scale: float = 0.01) -> bytes:
    """전원 투입부터 BusyBox askfirst 메시지까지의 콘솔 바이트."""
    dev = make_device(profile, full=full, time_scale=time_scale)
    try:
        dev.power_on()
        end = _wait(dev, r"Please press Enter to activate this console\. ")
        return dev.console_output[:end]
    finally:
        dev.stop()


def _cmd(dev: MockDevice, line: str, prompt_re: str, timeout: float = 30.0) -> None:
    start = len(dev.console_output)
    dev.feed_input(line.encode() + b"\r")
    _wait(dev, prompt_re, start + 1, timeout)


def record_uboot_session(profile: str, *, full: bool = True) -> bytes:
    dev = make_device(profile, full=full)
    try:
        prompt = dev.profile["uboot"]["prompt"]
        pre = re.escape(prompt) + "$"
        dev.power_on()
        while dev.state in ("off", "bootrom", "uboot-autoboot"):
            dev.feed_input(b"\x03")
            time.sleep(0.01)
        _wait(dev, pre)
        time.sleep(0.2)
        addr = int(dev.profile["uboot"]["loadaddr"])
        kern = next(p for p in dev.profile["partitions"] if p["name"] == "kernel")
        for line in ("printenv", "bdinfo", "version", "sf probe 0", f"sf read 0x{addr:x} 0x{kern['offset']:x} 0x10000",
                     f"md.b 0x{addr:x} 0x40", "", f"md.l 0x{addr:x} 8", f"crc32 0x{addr:x} 0x10000", "pri bootcmd",
                     "xyzzy"):
            _cmd(dev, line, pre)
        start = len(dev.console_output)
        dev.feed_input(b"\x03")
        _wait(dev, r"<INTERRUPT>\r\n" + pre, start)
        return dev.console_output
    finally:
        dev.stop()


def record_shell_session(profile: str, *, full: bool = True) -> bytes:
    dev = make_device(profile, full=full)
    try:
        dev.power_on()
        _wait(dev, r"Please press Enter to activate this console\. $")
        start = len(dev.console_output)
        dev.feed_input(b"\r")
        _wait(dev, r"login: $", start)
        lg = dev.profile["linux"]["login"]
        dev.feed_input(lg["username"].encode() + b"\r")
        if lg.get("password"):
            _wait(dev, r"Password: $", start)
            dev.feed_input(lg["password"].encode() + b"\r")
        _wait(dev, r"\r\n# $", start)
        cmds = ["cat /proc/mtd", "cat /proc/cmdline", "uname -a", "cat /proc/cpuinfo", "mount", "ps",
                "dd if=/dev/mtd1 bs=256 count=1 | hexdump -C", "md5sum /dev/mtd1", "netstat -tln", "xyzzy"]
        if "base64" in dev.profile["linux"]["applets"]:
            cmds.insert(7, "dd if=/dev/mtd1 bs=114 count=1 2>/dev/null | base64")
        for line in cmds:
            _cmd(dev, line, r"\r\n# $")
        return dev.console_output
    finally:
        dev.stop()


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("profiles", nargs="*", help="프로필 이름 (기본: 내장 전체)")
    ap.add_argument("--fast", action="store_true", help="외부 도구 없이 빠른 이미지로 기록")
    args = ap.parse_args(argv)
    names = args.profiles or [p["name"] for p in list_profiles()]
    OUT.mkdir(parents=True, exist_ok=True)
    for name in names:
        for kind, fn in (("boot", record_boot), ("uboot-session", record_uboot_session),
                         ("shell-session", record_shell_session)):
            data = fn(name, full=not args.fast)
            path = OUT / f"{name}-{kind}.log"
            path.write_bytes(data)
            print(f"{path} ({len(data)} bytes)", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
