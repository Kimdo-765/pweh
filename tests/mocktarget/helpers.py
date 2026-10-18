"""pweh.mocktarget 테스트 헬퍼 (다른 테스트에서도 재사용: ``from mocktarget.helpers import Console, make_device``).

테스트는 실제 클라이언트처럼 pyserial 로 PTY(또는 socket://)를 열어 시뮬레이터와 대화한다.
- ``make_device(profile, **kw)``: 테스트용 기본값(time_scale=0.01, autostart=False, autoboot_floor=0.12)의 MockDevice
- ``Console``: read_until / interrupt_autoboot / cmd(U-Boot) / boot_to_shell / sh(리눅스) 헬퍼
- ``parse_hexdump_c``: BusyBox ``hexdump -C`` 출력 → 바이트 ('*' 와 끝 주소 처리)
- ``tool_path``: 외부 도구 경로 (환경변수 → ~/pweh-tools/bin → PATH)
"""

from __future__ import annotations

import os
import re
import shutil
import threading
import time
from pathlib import Path
from typing import Any

import serial

from pweh.mocktarget import MockDevice

TIME_SCALE = 0.01
AUTOBOOT_FLOOR = 0.12
TOOLS_BIN = Path.home() / "pweh-tools" / "bin"


def tool_path(env: str, name: str) -> str | None:
    """테스트는 env.sh 없이 돈다: 환경변수 → 고정 설치 경로 → PATH 순서."""
    val = os.environ.get(env)
    if val and Path(val).is_file():
        return val
    cand = TOOLS_BIN / name
    if cand.is_file():
        return str(cand)
    return shutil.which(name)


class Console:
    """pyserial 기반 콘솔 클라이언트 (테스트용)."""

    def __init__(self, port: serial.SerialBase, dev: MockDevice) -> None:
        self.port = port
        self.dev = dev
        self.buf = bytearray()
        self.mark = 0

    def pump(self, timeout: float = 0.02) -> bytes:
        old = self.port.timeout
        self.port.timeout = timeout
        try:
            data = self.port.read(65536)
        finally:
            self.port.timeout = old
        if data:
            self.buf.extend(data)
        return data

    def text(self, start: int = 0) -> str:
        return self.buf[start:].decode("utf-8", "replace")

    def read_until(self, pattern: str | bytes, timeout: float = 10.0, start: int | None = None) -> re.Match[bytes]:
        rx = re.compile(pattern.encode() if isinstance(pattern, str) else pattern)
        begin = self.mark if start is None else start
        deadline = time.monotonic() + timeout
        while True:
            m = rx.search(self.buf, begin)
            if m:
                return m
            if time.monotonic() > deadline:
                raise AssertionError(f"timeout waiting for {pattern!r}; tail={bytes(self.buf[-600:])!r} state={self.dev.state}")
            self.pump(0.02)

    def write(self, data: bytes | str) -> None:
        if isinstance(data, str):
            data = data.encode()
        self.port.write(data)
        self.port.flush()

    def drain(self, quiet: float = 0.08, max_time: float = 2.0) -> None:
        end = time.monotonic() + max_time
        last = time.monotonic()
        while time.monotonic() < end:
            if self.pump(0.02):
                last = time.monotonic()
            elif time.monotonic() - last > quiet:
                break

    # -- U-Boot -----------------------------------------------------------
    @property
    def prompt(self) -> str:
        return self.dev.profile["uboot"]["prompt"]

    def interrupt_autoboot(self, key: bytes = b"\x03", timeout: float = 15.0) -> None:
        """autoboot 메시지가 나오기 전부터 키를 반복 전송해 U-Boot 프롬프트를 얻는다."""
        stop = threading.Event()

        def spam() -> None:
            while not stop.is_set() and self.dev.state in ("off", "bootrom", "uboot-autoboot"):
                try:
                    self.port.write(key)
                except Exception:
                    return
                time.sleep(0.01)

        th = threading.Thread(target=spam, daemon=True)
        th.start()
        try:
            assert self.dev.wait_for_state("uboot", timeout), f"no uboot prompt (state={self.dev.state})"
        finally:
            stop.set()
            th.join(1.0)
        self.read_until(re.escape(self.prompt), timeout=5)
        self.drain()
        self.mark = len(self.buf)

    def cmd(self, line: str, timeout: float = 10.0) -> str:
        """명령 + CR 전송 후 다음 프롬프트까지의 출력(에코 줄과 프롬프트 제외, LF 정규화)을 돌려준다."""
        start = len(self.buf)
        self.write(line.encode() + b"\r")
        self.read_until(re.escape(self.prompt) + r"$", timeout=timeout, start=start + 1)
        self.mark = len(self.buf)
        out = self.text(start).replace("\r\n", "\n")
        nl = out.find("\n")
        body = out[nl + 1:] if nl >= 0 else ""
        assert body.endswith(self.prompt), body[-200:]
        return body[: -len(self.prompt)]

    # -- Linux --------------------------------------------------------------
    def boot_to_shell(self, timeout: float = 20.0) -> None:
        self.read_until(r"Please press Enter to activate this console\. $", timeout=timeout)
        self.write(b"\r")
        self.read_until(r"login: $", timeout=5)
        lg = self.dev.profile["linux"]["login"]
        self.write(lg["username"].encode() + b"\r")
        if lg.get("password"):
            self.read_until(r"Password: $", timeout=5)
            self.write(lg["password"].encode() + b"\r")
        self.read_until(r"\n# $", timeout=5)
        assert self.dev.wait_for_state("linux-shell", 5)
        self.mark = len(self.buf)

    def sh(self, line: str, timeout: float = 15.0) -> str:
        start = len(self.buf)
        self.write(line.encode() + b"\r")
        self.read_until(r"\r\n# $", timeout=timeout, start=start + len(line))
        self.mark = len(self.buf)
        out = self.text(start).replace("\r\n", "\n")
        first_nl = out.find("\n")
        body = out[first_nl + 1:]
        assert body.endswith("# "), body[-80:]
        return body[:-2]


def make_device(profile: str = "hisilicon-like", **kw: Any) -> MockDevice:
    kw.setdefault("time_scale", TIME_SCALE)
    kw.setdefault("autostart", False)
    kw.setdefault("autoboot_floor", AUTOBOOT_FLOOR)
    return MockDevice(profile, **kw)


def parse_hexdump_c(text: str) -> bytes:
    """BusyBox ``hexdump -C`` 출력 → 바이트 ('*' 반복 줄과 끝 주소 줄 처리)."""
    out = bytearray()
    prev: bytes | None = None
    pending_star = False
    end_addr = None
    for raw in text.splitlines():
        line = raw.rstrip("\r")
        if line == "*":
            pending_star = True
            continue
        if re.fullmatch(r"[0-9a-f]{8}", line):
            end_addr = int(line, 16)
            continue
        m = re.match(r"^([0-9a-f]{8})  (.*?)  \|", line)
        if not m:
            continue
        addr = int(m.group(1), 16)
        hexpart = m.group(2).replace("  ", " ")
        data = bytes(int(h, 16) for h in hexpart.split())
        if pending_star:
            assert prev is not None
            while len(out) < addr:
                out += prev
            pending_star = False
        assert len(out) == addr, (len(out), addr, line)
        out += data
        prev = data
    if pending_star and prev is not None and end_addr is not None:
        while len(out) < end_addr:
            out += prev
    if end_addr is not None:
        assert len(out) == end_addr, (len(out), end_addr)
    return bytes(out)
