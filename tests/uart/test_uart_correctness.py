"""uart-mcp 정확성 단위 테스트 (검토 단계 회귀): 방언별 help/has, hexdump·md.b 파서 견고성, sf read 확인 줄, 문맥 추적의
덤프 줄 꼬리, expect 미완성 줄 보류, 링 버퍼 커서, 보드레이트 기반 시간 초과.
"""

from __future__ import annotations

import re
import sys
import time
from pathlib import Path

import pytest
import serial

from pweh.formats import format_md_b
from pweh.mocktarget.fmt import hexdump_canonical
from uart_mcp import parsers as P
from uart_mcp.dumps import ChunkError, FatalChunkError, _check_load_output, _md_timeout
from uart_mcp.profile import build_profile
from uart_mcp.session import PortSettings, UartSession
from uart_mcp.tracker import ContextTracker

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from mocktarget.helpers import Console, make_device  # noqa: E402

GENERIC = build_profile("generic-ipcam", {})
MiB = 1 << 20


# ---------------------------------------------------------------------------
# help / has (실제 시뮬레이터 출력, 방언별)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("profile", ["hisilicon-like", "ingenic-like", "hisilicon-legacy"])
def test_help_parses_eight_char_names_per_dialect(profile):
    """U-Boot _do_help 는 '%-8s- %s' → 8자 이름은 'printenv- …' 처럼 공백 없이 붙는다 (이전 정규식은 놓쳤다)."""
    dev = make_device(profile)
    try:
        path = dev.start_pty()
        sp = serial.Serial(path, 115200, timeout=0.05)
        con = Console(sp, dev)
        dev.power_on()
        con.interrupt_autoboot()
        text = con.cmd("help", timeout=20)
        sp.close()
    finally:
        dev.stop()
    assert "printenv- print environment variables" in text
    cmds = P.parse_help(text)["commands"]
    assert {"printenv", "setenv", "saveenv", "sf", "md", "crc32", "?"} <= set(cmds), cmds
    assert all("-" not in c for c in cmds)
    has, via = P.uboot_has(cmds, ("printenv", "tftp", "tftpboot", "tftpput", "nand", "mtdparts"))
    assert has["printenv"] is True and has["nand"] is False
    if profile == "hisilicon-like":
        assert "tftpboot" in cmds and has["tftp"] is True and via == {"tftp": "tftpboot"}  # 약어
        assert has["tftpput"] is False and has["mtdparts"] is False
    elif profile == "ingenic-like":
        assert {"tftp", "tftpboot", "tftpput", "mtdparts"} <= set(cmds) and via == {}
    else:
        assert has["tftp"] is True and has["tftpboot"] is False and via == {}


def test_uboot_has_semantics():
    cmds = ["md", "mm", "mtest", "mw", "printenv", "sf", "tftpboot"]
    has, via = P.uboot_has(cmds, ("md", "m", "tftp", "md.b", "fatwrite"))
    assert has == {"md": True, "m": False, "tftp": True, "md.b": True, "fatwrite": False}  # 'm' 은 후보가 여럿 → 모호
    assert via == {"tftp": "tftpboot", "md.b": "md"}
    unknown, _ = P.uboot_has([], ("md",))
    assert unknown == {"md": None}  # help 를 파싱하지 못했으면 모름


# ---------------------------------------------------------------------------
# BusyBox hexdump -C
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("n", [1, 5, 15])
def test_hexdump_zero_partial_block_is_single_star(n):
    """BusyBox dump.c: savp 가 0 으로 초기화 → 16바이트 미만 0 데이터는 '*' 한 줄만, 끝 주소 없음."""
    out = hexdump_canonical(b"\0" * n)
    assert out == "*\n"
    data, problems = P.parse_hexdump_c(out, n)
    assert data == b"\0" * n and problems == []
    # 기대 길이를 모르거나 16 이상이면 받아들이지 않는다 (잘린 출력과 구별할 수 없음)
    assert P.parse_hexdump_c(out, None)[1]
    assert P.parse_hexdump_c(out, 16)[1]
    assert P.parse_hexdump_c("*\n00000005\n", 5)[1]


@pytest.mark.parametrize("data", [
    b"\0" * 32 + b"\0" * 5,          # 접힌 뒤 짧은 끝 블록 (DUP 상태)
    b"ABCDEFGHIJKLMNOP" + b"ABCDE",  # 앞 블록 앞부분과 같은 짧은 끝 블록 → '*' + 끝 주소가 블록 시작
    b"\xff" * 5,                     # 0 이 아닌 짧은 데이터는 그대로 찍힌다
    bytes(range(256)) * 3 + b"\x00\x01",
])
def test_hexdump_busybox_quirks_roundtrip(data):
    for text in (hexdump_canonical(data), hexdump_canonical(data).replace("\n", "\r\r\n")):
        got, problems = P.parse_hexdump_c(text, len(data))
        assert got == data and problems == [], (text, problems)


# ---------------------------------------------------------------------------
# md.b
# ---------------------------------------------------------------------------


def _md(addr: int, data: bytes, pad: bool = True) -> str:
    text = format_md_b(addr, data)
    if not pad:  # 2010.06: 짧은 마지막 줄 패딩 없음
        text = re.sub(r"^(\S+:(?: [0-9a-f]{2})+) +(    .*)$", r"\1\2", text, flags=re.M)
    return text


@pytest.mark.parametrize("pad", [True, False])
@pytest.mark.parametrize("eol", ["\n", "\r\n", "\r\r\n"])
def test_md_b_line_endings_and_short_tail(pad, eol):
    data = bytes((i * 7) & 0xFF for i in range(0x45))
    text = _md(0x82000000, data, pad).replace("\n", eol) + eol
    got, problems = P.parse_md_b(text, 0x82000000, len(data))
    assert got == data and problems == []


def test_md_b_garbage_and_partial_lines():
    data = bytes(range(64))
    lines = _md(0x42000000, data).split("\n")
    # 형식이 아닌 잡음 줄(프롬프트 조각·제어 문자)이 끼어도 주소가 이어지면 데이터는 그대로
    noisy = [lines[0], "\x1b[0m", "garbage 42000010", lines[1], "", lines[2], lines[3]]
    got, problems = P.parse_md_b("\n".join(noisy), 0x42000000, len(data))
    assert got == data and problems == []
    # 잘린 줄(문자 손실) → 주소 불연속/바이트 수 불일치로 보고
    cut = list(lines)
    cut[1] = cut[1][:30]
    got, problems = P.parse_md_b("\n".join(cut), 0x42000000, len(data))
    assert problems and got != data
    # 중간 바이트가 깨진 줄 → 그 줄은 파싱되지 않아 문제 보고
    bad = list(lines)
    bad[2] = bad[2].replace(bad[2][13:15], "g1", 1)
    assert P.parse_md_b("\n".join(bad), 0x42000000, len(data))[1]


def test_md_b_extra_token_from_ascii_column_is_rejected():
    """마지막 줄에서 ASCII 열 앞 공백이 줄어 ASCII 가 16진 토큰처럼 붙으면(17바이트) 코어 파서는 잘라 통과시킨다 → 형식 문제로 본다."""
    data = b"ab" * 8 + b"\x61\x62\x63\x64"
    lines = _md(0x42000000, data, pad=False).split("\n")
    lines[1] = lines[1].replace("    abcd", " ab cd", 1)  # '42000010: 61 62 63 64 ab cd'
    got, problems = P.parse_md_b("\n".join(lines), 0x42000000, len(data))
    assert any("줄 바이트 수" in p for p in problems), (lines[1], problems)


# ---------------------------------------------------------------------------
# sf read 확인 줄 (방언별) / 플래시 크기 facts
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("output", [
    "\nSF: 8192 bytes @ 0x40000 Read: OK",            # hisilicon-2016
    "SF: 8192 bytes @ 0x40000 Read: OK\n--->read spend 3 ms",  # ingenic-2013
    "",                                                # hisilicon-2010: 빈 줄만
])
def test_sf_read_output_accepted(output):
    _check_load_output("sf read 0x42000000 0x40000 0x2000", output, 0x40000, 0x2000)


def test_sf_read_output_rejected():
    ld = "sf read 0x42000000 0x40000 0x2000"
    with pytest.raises(ChunkError):
        _check_load_output(ld, "\nSF: 4096 bytes @ 0x40000 Read: OK", 0x40000, 0x2000)  # 바이트 수 다름
    with pytest.raises(ChunkError):
        _check_load_output(ld, "\nSF: 8192 bytes @ 0x50000 Read: OK", 0x40000, 0x2000)  # 오프셋 다름
    with pytest.raises(ChunkError):
        _check_load_output(ld, "SF: 8192 bytes @ 0x40000 Read: ERROR", 0x40000, 0x2000)
    _check_load_output("sf read 0x42000000 0x0 0x10", "\nSF: 16 bytes @ 0 Read: OK", 0, 0x10)  # C %#x: 0 → '0'
    for msg in ("ERROR: attempting read past flash size (0x1000000)", "ERROR: read/write area is out of range!"):
        with pytest.raises(FatalChunkError):  # 재시도해도 소용없음
            _check_load_output(ld, msg, 0x40000, 0x2000)
    with pytest.raises(FatalChunkError):
        _check_load_output(ld, "Unknown command 'sf' - try 'help'", 0x40000, 0x2000)
    with pytest.raises(FatalChunkError):  # 배드 블록을 건너뛴 nand read 는 재시도해도 1:1 이미지가 아니다
        _check_load_output("nand read 0x42000000 0x40000 0x20000",
                           "\nNAND read: device 0 offset 0x40000, size 0x20000\nSkipping bad block 0x00040000\n 131072 bytes read: OK",
                           0x40000, 0x20000)
    with pytest.raises(ChunkError):
        _check_load_output(ld, "No SPI flash selected. Please run `sf probe'", 0x40000, 0x2000)


def test_flash_size_from_boot_facts():
    assert P.flash_size_from_facts({"flash_total_mb": "16"}) == 16 * MiB
    assert P.flash_size_from_facts({"flash_chip": "8MB"}) == 8 * MiB
    assert P.flash_size_from_facts({"flash_current_kib": 16384}) == 16 * MiB
    assert P.flash_size_from_facts({"flash_detected": "W25Q128(B/F)V with page size 256 Bytes, erase size 64 KiB, total 16 MiB"}) == 16 * MiB
    assert P.flash_size_from_facts({"flash_detected": "BY25Q128AS"}) is None
    assert P.flash_size_from_facts({}) is None


def test_timeouts_scale_with_framing_and_baud():
    assert PortSettings(port="x").bits_per_char == 10
    assert PortSettings(port="x", parity="E").bits_per_char == 11
    assert PortSettings(port="x", stopbits=2).bits_per_char == 11
    t_8n1 = _md_timeout(0x10000, 115200, "md.b")
    assert 70 < t_8n1 < 90  # 64 KiB md.b ≈ 28초 × 2.5 + 10
    assert _md_timeout(0x10000, 115200, "md.b", 11) > t_8n1
    assert _md_timeout(0x10000, 9600, "md.b") > 10 * t_8n1
    assert _md_timeout(0x100, 3_000_000, "base64") == 15.0


# ---------------------------------------------------------------------------
# 문맥 추적: 덤프 줄 꼬리, 부팅 시작 커서
# ---------------------------------------------------------------------------


def test_partial_md_line_ending_like_prompt_is_not_a_prompt():
    """md.b ASCII 열이 'hisilicon # ' 처럼 끝나는 순간 수신이 끊겨도 프롬프트/문맥 변화로 보지 않는다."""
    tr = ContextTracker(GENERIC)
    end = 0
    for chunk in (b"<INTERRUPT>\r\nhisilicon # ", b"md.b 0x42000000 0x20\r\n"):
        tr.feed(chunk, end)
        end += len(chunk)
    assert tr.context == "uboot"
    tail = b"42000000: 68 69 73 69 6c 69 63 6f 6e 20 23 20 00 00 00 00    hisilicon # "
    tr.feed(tail, end)
    end += len(tail)
    assert tr.prompt is None and tr.context == "uboot", (tr.prompt, tr.context)
    chunk = b"....\r\n42000010: 50 61 73 73 77 6f 72 64 3a 20 00 00 00 00 00 00    Password: "
    tr.feed(chunk, end)
    end += len(chunk)
    assert tr.prompt is None and tr.context == "uboot"
    tr.feed(b"\r\n42000020: 0a3e2023 00000000 00000000 00000000    # >.............. # ", end)  # md.l 줄
    assert tr.prompt is None and tr.context == "uboot"


def test_partial_hexdump_line_ending_like_login_is_not_a_prompt():
    tr = ContextTracker(GENERIC)
    end = 0
    for chunk in (b"Please press Enter to activate this console. \r\n(none) login: root\r\nPassword: \r\n# ",
                  b"dd if=/dev/mtd1 bs=16 count=4 2>/dev/null | hexdump -C\r\n"):
        tr.feed(chunk, end)
        end += len(chunk)
    assert tr.context == "linux-shell" and tr.learned["linux-shell"] == "# "
    tr.feed(b"00000000  28 6e 6f 6e 65 29 20 6c  6f 67 69 6e 3a 20 00 00  |(none) login: ", end)
    assert tr.prompt is None and tr.context == "linux-shell"
    assert tr.learned["linux-shell"] == "# "  # 가짜 꼬리를 셸 프롬프트로 학습하지 않는다


def test_boot_start_cursor():
    tr = ContextTracker(GENERIC)
    assert tr.boot_start_at is None
    first = b"\r\nU-Boot 2016.11 (Mar 23 2020 - 14:58:03 +0800)hi3516ev300\r\n\r\nDRAM:  64 MiB\r\n"
    tr.feed(first, 0)
    assert tr.boot_seq == 1 and tr.boot_start_at == len(first)
    more = b"Relocating to 43f9e000\r\nHit any key to stop autoboot:  2 "
    tr.feed(more, len(first))
    assert tr.boot_seq == 1 and tr.boot_start_at == len(first)  # 같은 부팅의 autoboot 는 새 부팅이 아니다
    # 시작 줄 없이 autoboot 메시지만 보인 부팅도 새 부팅 커서를 남긴다
    tr2 = ContextTracker(GENERIC)
    msg = b"Linux version 4.9.37\r\n/ # reboot\r\n\r\nHit any key to stop autoboot:  1 \r\n"
    tr2.feed(msg, 100)
    assert tr2.boot_seq == 1 and tr2.boot_start_at == 100 + len(msg)


# ---------------------------------------------------------------------------
# 세션: expect 미완성 줄 보류, 링 버퍼 커서
# ---------------------------------------------------------------------------


@pytest.fixture
def session(workspace, auth):
    from pweh.runtime import get_runtime

    case = get_runtime("uart-mcp").cases.create(title="unit", authorization=auth)
    s = UartSession(session_id="unit-001", case=case, settings=PortSettings(port="loop://"), profile=GENERIC, label=None,
                    buffer_bytes=64 * 1024, persistent_paths=[], unknown_risk="modify")
    s.state = "open"  # 포트 없이 수신 콜백(_on_rx)만 쓴다
    yield s
    s.logs.close()


def test_search_provisional_until_line_ends(session):
    s = session
    rx = re.compile(r"^bootargs=(.*)$", re.M)
    s._on_rx(b"printenv bootargs\r\nbootargs=console=ttyAMA0,1152")
    m, base, provisional = s._search(rx, 0, 0)
    assert provisional and m.group(1) == "console=ttyAMA0,1152"
    s.last_rx_mono = time.monotonic()
    m2, _, pending, scan = s.search_stable(rx, 0, 0)
    assert m2 is None and pending and scan <= base + m.start()
    s._on_rx(b"00 mem=40M\r\n")
    m, base, provisional = s._search(rx, 0, scan)
    assert not provisional and m.group(1) == "console=ttyAMA0,115200 mem=40M"
    # greedy '.*' 가 줄 끝에 닿는 경우도 보류 (값이 잘리지 않게)
    s._on_rx(b"ver=1.2")
    m, _, provisional = s._search(re.compile(r"^ver=(\S+)", re.M), 0, 0)
    assert provisional and m.group(1) == "1.2"


def test_wait_response_accepts_quiet_tail_and_returns_pending_at_timeout(session):
    s = session
    s._on_rx(b"\r\n(none) login: ")
    s.last_rx_mono = time.monotonic() - 1.0  # 이미 조용함 → 프롬프트 같은 꼬리는 받아들인다
    r = s.wait_response(0, 1.0, expect=re.compile(r"login: $", re.M))
    assert r.kind == "expect" and r.match_text == "login: "
    start = s.total()
    s._on_rx(b"\r\nx=12")
    s.last_rx_mono = time.monotonic() + 60  # 계속 수신 중인 것처럼 (조용해지지 않음)
    t0 = time.monotonic()
    r = s.wait_response(start, 0.3, expect=re.compile(r"^x=(\d+)$", re.M))
    assert r.kind == "expect" and r.groups == ["12"] and time.monotonic() - t0 >= 0.25  # 시간이 끝날 때까지 기다렸다가 돌려준다


def test_resume_count_matches_prepare_resume(workspace, auth):
    """도구가 알려 주는 resume_from_chunk 는 job 의 prepare_resume 과 같은 규칙(.part 크기)으로 계산한다."""
    import json

    from pweh.runtime import get_runtime
    from uart_mcp.dumps import DumpFiles, check_resume_identity, prepare_resume

    case = get_runtime("uart-mcp").cases.create(title="unit", authorization=auth)
    files = DumpFiles(case, "r")
    ident = {"method": "uboot-md", "source": "sf", "offset": 0, "length": 0x10000, "chunk_size": 0x4000}
    files.state.write_text(json.dumps({"identity": ident, "completed_chunks": 3, "chunk_checks": [{}, {}, {}]}), encoding="utf-8")
    assert check_resume_identity(files, ident, resume=True) == 0  # .part 없음 → 처음부터
    assert check_resume_identity(files, ident, resume=False) is None
    files.part.write_bytes(b"\0" * 0x9000)  # 2.25 청크 분량
    assert check_resume_identity(files, ident, resume=True) == 2
    start, _ = prepare_resume(files, ident, resume=True, chunk_size=0x4000, length=0x10000)
    assert start == 2 and files.part.stat().st_size == 0x8000
    with pytest.raises(Exception, match="다른 인자"):
        check_resume_identity(files, {**ident, "length": 0x20000}, resume=True)


def test_ring_buffer_cursors(session):
    s = session
    s._on_rx(b"A" * (100 * 1024))
    total = s.total()
    assert total == 100 * 1024 and s.rx.start > 0
    r = s.read(0, 1 << 20, 0, False)
    assert r["lost_bytes"] == s.rx.start and r["cursor_start"] == s.rx.start and r["cursor_end"] == total and not r["more"]
    r = s.read(total + 500, 100, 0, False)
    assert r["bytes"] == 0 and r["cursor_start"] == total and r["cursor_end"] == total
    r = s.read(None, 100, 0, False)  # 에이전트 읽기 위치 = 직전 cursor_end
    assert r["cursor_start"] == total and r["bytes"] == 0
    s._on_rx("가나다".encode())
    r = s.read(total, 4, 0, False)  # 다중 바이트 문자를 자르지 않는다
    assert r["text"] == "가" and r["cursor_end"] == total + 3 and r["more"]
    r = s.read(None, 1 << 20, 0, False)
    assert r["text"] == "나다" and not r["more"]
    r = s.read(None, 10, 0, True)  # tail
    assert r["cursor_end"] == s.total() and r["bytes"] == 10
