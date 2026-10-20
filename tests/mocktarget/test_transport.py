"""전송 계층/전원/프로필/출력 형식 헬퍼 테스트."""

from __future__ import annotations

import time
from pathlib import Path

import pytest
import serial

from pweh.errors import ConfigError
from pweh.mocktarget import MockDevice, list_profiles, load_profile
from pweh.mocktarget.fmt import busybox_base64, hexdump_canonical, print_buffer_lines, print_size, ultohstr
from pweh.mocktarget.memory import simple_strtoul
from pweh.mocktarget.transport import uart_misread

from .helpers import make_device


def _printable_ratio(data: bytes) -> float:
    if not data:
        return 0.0
    return sum(1 for b in data if 32 <= b < 127 or b in (9, 10, 13)) / len(data)


def test_baud_mismatch_produces_garbage_and_correct_baud_produces_text():
    dev = make_device("hisilicon-like")
    try:
        path = dev.start_pty()
        wrong = serial.Serial(path, 57600, timeout=0.05)
        dev.power_on()
        got = bytearray()
        end = time.monotonic() + 3
        while time.monotonic() < end and dev.state in ("off", "bootrom", "uboot-autoboot"):
            got += wrong.read(65536)
        got += wrong.read(65536)
        assert len(got) > 200
        assert b"U-Boot" not in got and b"Hit any key" not in got
        assert _printable_ratio(bytes(got)) < 0.6
        # 잘못된 속도에서 보낸 키는 기기에 닿지 않는다 → autoboot 가 계속 진행
        assert any(e["type"] == "baud_mismatch" for e in dev.events)
        # 같은 PTY 를 올바른 속도로 다시 설정 → 깨끗한 텍스트
        wrong.baudrate = 115200
        dev.power_cycle()
        text = bytearray()
        end = time.monotonic() + 5
        while time.monotonic() < end and b"Hit any key" not in text:
            text += wrong.read(65536)
        assert b"U-Boot 2016.11" in text and _printable_ratio(bytes(text)) > 0.95
        wrong.close()
    finally:
        dev.stop()


def test_uart_misread_is_deterministic():
    data = b"U-Boot 2013.07 (Dec 09 2020 - 11:32:38)\r\n" * 4
    a = uart_misread(data, 115200, 9600)
    b = uart_misread(data, 115200, 9600)
    assert a == b and a != data
    assert uart_misread(data, 115200, 115200) == data
    fast = uart_misread(data, 115200, 921600)
    assert len(fast) > len(data) and _printable_ratio(fast) < 0.6


def test_tcp_transport_and_multiple_clients():
    dev = make_device("ingenic-like")
    try:
        host, port = dev.start_tcp()
        c1 = serial.serial_for_url(f"socket://{host}:{port}", timeout=0.05)
        c2 = serial.serial_for_url(f"socket://{host}:{port}", timeout=0.05)
        time.sleep(0.1)
        dev.power_on()
        buf1 = bytearray()
        buf2 = bytearray()
        end = time.monotonic() + 10
        while time.monotonic() < end and b"Hit any key" not in buf1:
            buf1 += c1.read(65536)
            buf2 += c2.read(65536)
        assert b"U-Boot SPL 2013.07" in buf1
        while dev.state != "uboot" and time.monotonic() < end:
            c2.write(b"\x03")
            time.sleep(0.01)
        assert dev.state == "uboot"
        time.sleep(0.1)
        buf1 += c1.read(65536)
        assert b"isvp_t31# " in buf1  # 출력은 모든 클라이언트에게
        c1.close()
        c2.close()
    finally:
        dev.stop()


@pytest.mark.parametrize("host", ["0.0.0.0", "", "192.0.2.10", "localhost.", "127.1", "::1", "::"])
def test_tcp_transport_refuses_non_loopback_bind(host):
    """루프백이 아닌 바인드는 allow_lan 없이는 소켓을 만들기 전에 거부한다 (G13). 시험은 실제로 LAN 에 바인드하지 않는다."""
    from pweh.errors import ValidationFailed
    from pweh.mocktarget.transport import TcpTransport

    t = TcpTransport(on_input=lambda data: None, host=host)
    with pytest.raises(ValidationFailed, match="루프백"):
        t.start()
    assert t._server is None and t._threads == [] and t.lan_exposed is False
    dev = make_device("ingenic-like")
    try:
        with pytest.raises(ValidationFailed):
            dev.start_tcp(host)
    finally:
        dev.stop()


def test_tcp_transport_ipv6_refused_cleanly_even_with_allow_lan():
    """리스너는 AF_INET 전용 — '::1' 은 bind 의 gaierror 대신 분명한 ValidationFailed (리뷰 F7)."""
    from pweh.errors import ValidationFailed
    from pweh.mocktarget.transport import TcpTransport

    for host in ("::1", "::"):
        t = TcpTransport(on_input=lambda data: None, host=host, allow_lan=True)
        with pytest.raises(ValidationFailed, match="IPv4"):
            t.start()
        assert t._server is None


def test_power_states_and_events():
    dev = make_device("hisilicon-like")
    try:
        dev.start_pty()
        assert dev.state == "off" and not dev.powered
        dev.power_on()
        assert dev.wait_for_state("uboot-autoboot", 5)
        dev.power_off()
        assert dev.wait_for_state("off", 5)
        dev.power_on()
        assert dev.wait_for_state(("kernel-boot", "linux-login"), 10)
        seen = [e["to"] for e in dev.events if e["type"] == "state"]
        assert seen[:3] == ["bootrom", "uboot-autoboot", "off"]
        assert dev.boot_count == 2
    finally:
        dev.stop()


def test_profiles_by_name_alias_path_and_overrides(tmp_path: Path):
    names = {p["name"] for p in list_profiles()}
    assert {"hisilicon-like", "ingenic-like"} <= names
    p = load_profile("mock-ingenic")
    assert p["name"] == "ingenic-like" and p["uboot"]["prompt"] == "isvp_t31# "
    src = Path(p["source"])
    copy = tmp_path / "custom.yaml"
    copy.write_text(src.read_text(encoding="utf-8").replace("isvp_t31# ", "custom# "), encoding="utf-8")
    p2 = load_profile(str(copy))
    assert p2["uboot"]["prompt"] == "custom# " and p2["name"] == "ingenic-like"
    p3 = load_profile("hisilicon-like", {"uboot": {"crc32_style": "lower", "autoboot": {"delay": 5}}})
    assert p3["uboot"]["crc32_style"] == "lower" and p3["uboot"]["autoboot"]["delay"] == 5
    assert p3["uboot"]["parser"] == "hush"  # 방언 기본값 유지
    with pytest.raises(ConfigError):
        load_profile("no-such-profile")
    with pytest.raises(ConfigError):
        MockDevice("hisilicon-like", flash_image=b"\xff" * 1024)


def test_fmt_helpers_match_reference_outputs():
    assert print_size(256) == "256 Bytes" and print_size(65536) == "64 KiB" and print_size(16 << 20) == "16 MiB"
    assert print_size(2976536) == "2.8 MiB"  # Foscam 부팅 로그: "Data Size: 2976536 Bytes = 2.8 MiB"
    assert ultohstr(0x40000) == "256K"
    assert simple_strtoul("0x1F", 16) == (0x1F, "")
    assert simple_strtoul("82000000xyz", 16) == (0x82000000, "xyz")
    assert simple_strtoul("garbage", 16) == (0, "garbage")
    # U-Boot 2010.06 print_buffer: 짧은 마지막 줄을 채우지 않음 / 2011+: 채움
    assert print_buffer_lines(0x10, b"ABC", 1, pad_last=False) == ["00000010: 41 42 43    ABC"]
    assert print_buffer_lines(0x10, b"ABC", 1, pad_last=True) == ["00000010: 41 42 43" + " " * 39 + "    ABC"]
    # BusyBox hexdump -C: 반복 줄 '*', 끝 주소, 부분 블록이 직전 블록 접두와 같으면 그것도 생략 (dump.c)
    assert hexdump_canonical(b"Hello\n") == (
        "00000000  48 65 6c 6c 6f 0a                                 |Hello.|\n00000006\n")
    z = hexdump_canonical(bytes(40))
    assert z.split("\n")[1:] == ["*", "00000020", ""]
    assert hexdump_canonical(b"") == ""
    lines = busybox_base64(bytes(range(256))).split("\n")
    assert len(lines[0]) == 76 and lines[-1] == ""
