"""pweh-emu 픽스처(tests/fixtures/emu)와 AVR 실행기(native/emu/pweh_avr_run.c) 시험.

- 항상: 생성기 출력 = 커밋한 HEX(에코 sha256 고정), HEX 레코드(체크섬·길이·유형·EOF), OOB 탐침의 EEPROM·유형 04 레코드,
  mkimg_esp 이미지가 유효한 ESP 이미지(pweh.espfmt.parse_app_image)이고 전체 플래시 모양이 맞는지.
- external(@pytest.mark.external): 실행기 ``pweh_avr_run`` 이 있으면 (``PWEH_AVR_RUN`` 또는 도구 디렉터리의 simavr/bin) 서버 없이
  직접 — ``--version``, 소켓 함수 없음, memfd(--hex-fd)로 에코·충돌·OOB 탐침, HEX 거부(종료 코드 1, 줄 번호만), 출력 닫힘(5),
  사용법 오류(2). 실행기가 없으면 건너뛴다. 서버를 거친 시험은 test_emu_external.py.
"""

from __future__ import annotations

import fcntl
import hashlib
import os
import re
import select
import shutil
import struct
import subprocess
import sys
import time
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
FIX = REPO / "tests" / "fixtures" / "emu"
RUNNER_SRC = REPO / "native" / "emu" / "pweh_avr_run.c"
SIMAVR_COMMIT = "5b08da60497f7564f50941f74a549fe2851db030"
ECHO_SHA256 = "473124e258f7a86313fdb251e198a9ffaa5cbe9280c6da970eb86681ae31fafa"
CRASH_HEX = ":040000000C94FF3F1E\n:00000001FF\n"

if str(FIX) not in sys.path:
    sys.path.insert(0, str(FIX))

import make_avr_oob_probe  # noqa: E402
import make_avr_uart_echo  # noqa: E402
import mkimg_esp  # noqa: E402

try:  # 코어로 옮긴 위치 (fwtriage_mcp.espfmt 는 재수출 shim)
    from pweh.espfmt import parse_app_image
except ImportError:  # pragma: no cover - 코어 이동 전 작업 트리
    sys.path.insert(0, str(REPO / "mcp-servers" / "fwtriage-mcp"))
    from fwtriage_mcp.espfmt import parse_app_image


def parse_hex(text: str) -> tuple[list[tuple[int, bytes]], list[int]]:
    """엄격한 Intel HEX 해석 (시험용 오라클): ([(절대 주소, 데이터)], 레코드 유형 목록). 형식이 틀리면 AssertionError."""
    lines = text.split("\n")
    assert lines[-1] == "", "마지막 줄도 줄바꿈으로 끝나야 한다"
    upper, data, types = 0, [], []
    for i, line in enumerate(lines[:-1], 1):
        assert re.fullmatch(r":(?:[0-9A-F]{2}){5,260}", line), (i, "형식")
        rec = bytes.fromhex(line[1:])
        assert rec[0] + 5 == len(rec), (i, "바이트 수")
        assert sum(rec) & 0xFF == 0, (i, "체크섬")
        rtype = rec[3]
        types.append(rtype)
        if rtype == 0:
            data.append(((upper << 16) | (rec[1] << 8 | rec[2]), rec[4:-1]))
        elif rtype == 4:
            assert rec[0] == 2
            upper = rec[4] << 8 | rec[5]
        elif rtype == 1:
            assert rec[0] == 0 and i == len(lines) - 1, (i, "EOF 는 마지막 레코드")
        else:
            raise AssertionError((i, f"쓰지 않는 유형 {rtype:02x}"))
    assert types and types[-1] == 1
    return data, types


# --- 생성기 = 커밋한 파일 -------------------------------------------------------

def test_echo_generator_matches_committed_hex():
    committed = (FIX / "avr_uart_echo_m328p.hex").read_bytes()
    assert hashlib.sha256(committed).hexdigest() == ECHO_SHA256
    assert make_avr_uart_echo.build_hex().encode("ascii") == committed
    assert make_avr_uart_echo.build_hex() == make_avr_uart_echo.build_hex()   # 결정적


@pytest.mark.parametrize("target", sorted(make_avr_oob_probe.TARGETS))
def test_oob_generator_matches_committed_hex(target):
    _mcu, _freq, name = make_avr_oob_probe.TARGETS[target]
    assert make_avr_oob_probe.build_hex(target).encode("ascii") == (FIX / name).read_bytes()


def test_generators_write_the_committed_files(tmp_path):
    """명령행 생성기(python -I)가 쓴 파일도 커밋한 파일과 같다 (같은 디렉터리의 어셈블러를 -I 로도 찾는다)."""
    env = dict(os.environ, PYTHONDONTWRITEBYTECODE="1")
    for script in ("make_avr_uart_echo.py", "make_avr_oob_probe.py"):
        r = subprocess.run([sys.executable, "-I", str(FIX / script), "--out-dir", str(tmp_path)], capture_output=True, text=True,
                           env=env, timeout=60)
        assert r.returncode == 0, r.stderr
    for name in ("avr_uart_echo_m328p.hex", "avr_oob_probe_m328p.hex", "avr_oob_probe_m2560.hex"):
        assert (tmp_path / name).read_bytes() == (FIX / name).read_bytes(), name


# --- HEX 레코드 -----------------------------------------------------------------

@pytest.mark.parametrize("name", ["avr_uart_echo_m328p.hex", "avr_oob_probe_m328p.hex", "avr_oob_probe_m2560.hex"])
def test_committed_hex_records_are_valid(name):
    data, types = parse_hex((FIX / name).read_text(encoding="ascii"))
    assert set(types) <= {0, 1, 4}
    assert all(len(d) <= 16 for _a, d in data)
    assert data[0][0] == 0   # 리셋 벡터부터


def test_echo_hex_is_one_flash_chunk_without_extended_records():
    data, types = parse_hex((FIX / "avr_uart_echo_m328p.hex").read_text(encoding="ascii"))
    assert 4 not in types
    flat = b"".join(d for _a, d in data)
    assert len(flat) == 98 and [a for a, _d in data] == list(range(0, 98, 16))
    assert flat.endswith(bytes.fromhex("0895"))   # ret


def test_oob_probe_hex_carries_eeprom_and_high_flash_records():
    data, _ = parse_hex((FIX / "avr_oob_probe_m328p.hex").read_text(encoding="ascii"))
    assert (0x810000 + make_avr_oob_probe.EEPROM_ADDR, make_avr_oob_probe.EEPROM_DATA) in data   # EEPROM (실행기가 적재)
    assert max(a for a, _d in data if a < 0x800000) < 0x8000                                    # 코드는 32 KiB 플래시 안
    data, _ = parse_hex((FIX / "avr_oob_probe_m2560.hex").read_text(encoding="ascii"))
    assert (make_avr_oob_probe.MARKER_ADDR, make_avr_oob_probe.MARKER_DATA) in data             # 유형 04 뒤 0x1FFFC
    assert make_avr_oob_probe.EXPECTED["m328p"].count(b"\xff") == 10 and b"EEOK" in make_avr_oob_probe.EXPECTED["m328p"]


def test_intel_hex_splits_at_64k_and_emits_extended_address_only_when_needed():
    text = make_avr_uart_echo.intel_hex([(0xFFF8, bytes(range(16))), (0x810000, b"\x01\x02")])
    data, types = parse_hex(text)
    assert types == [0, 4, 0, 4, 0, 1]
    assert data == [(0xFFF8, bytes(range(8))), (0x10000, bytes(range(8, 16))), (0x810000, b"\x01\x02")]
    assert make_avr_uart_echo.intel_hex(b"\x00\x00").splitlines()[0] == ":020000000000FE"
    with pytest.raises(ValueError):
        make_avr_uart_echo.intel_hex([(0x10, b"\x00" * 4), (0x12, b"\x00")])   # 겹침


def test_assembler_rejects_out_of_range_operands():
    a = make_avr_uart_echo.Asm()
    with pytest.raises(ValueError):
        a.ldi(15, 1)        # ldi 는 r16..r31
    with pytest.raises(ValueError):
        a.out(64, 16)       # I/O 0..63
    with pytest.raises(ValueError):
        a.ldi(16, 256)


# --- ESP 이미지 생성기 ------------------------------------------------------------

@pytest.mark.parametrize("chip", sorted(mkimg_esp.CHIPS))
@pytest.mark.parametrize("variant", mkimg_esp.VARIANTS)
def test_mkimg_esp_images_are_valid(chip, variant):
    spec = mkimg_esp.CHIPS[chip]
    img = mkimg_esp.build_image(chip, variant)
    assert img == mkimg_esp.build_image(chip, variant)   # 결정적
    info = parse_app_image(img, 0)
    assert info["ok"], info["errors"]
    assert info["chip_id"] == spec.chip_id and info["segment_count"] == 1 and info["hash_appended"] is True
    assert info["checksum"]["ok"] and info["sha256"]["ok"] and info["image_size"] == len(img)
    assert info["spi_size_name"] == "4MB"
    seg = info["segments"][0]
    assert seg["load_addr"] == spec.iram_load and seg["load_addr"] <= info["entry"] < seg["load_addr"] + seg["size"]
    assert not [w for w in info["warnings"] if "엔트리" in w], info["warnings"]
    assert 150 <= len(img) <= 260


@pytest.mark.parametrize("chip", sorted(mkimg_esp.CHIPS))
def test_mkimg_esp_flash_layout(chip):
    spec = mkimg_esp.CHIPS[chip]
    flash = mkimg_esp.build_flash(chip, "hello")
    img = mkimg_esp.build_image(chip, "hello")
    assert len(flash) == 4 << 20
    assert flash[spec.boot_offset:spec.boot_offset + len(img)] == img
    rest = flash[:spec.boot_offset] + flash[spec.boot_offset + len(img):]
    assert rest == b"\xff" * len(rest)
    info = parse_app_image(flash, spec.boot_offset)   # 서버가 읽는 위치 (esp32 0x1000, s3·c3 0x0)
    assert info["ok"] and info["chip_id"] == spec.chip_id
    for size, name in ((2 << 20, "2MB"), (8 << 20, "8MB"), (16 << 20, "16MB")):
        f = mkimg_esp.build_flash(chip, "echo", size)
        assert len(f) == size and parse_app_image(f, spec.boot_offset)["spi_size_name"] == name
    with pytest.raises(ValueError):
        mkimg_esp.build_flash(chip, "hello", 3 << 20)   # QEMU 가 받지 않는 크기


def test_mkimg_esp_variants_differ_and_reset_writes_sw_reset():
    for chip, spec in mkimg_esp.CHIPS.items():
        hello, reset, echo = (mkimg_esp.build_image(chip, v) for v in ("hello", "reset", "echo"))
        assert len({hello, reset, echo}) == 3
        if spec.isa == "xtensa":   # 리셋 변형만 리터럴에 RTC_CNTL_OPTIONS0 주소를 싣는다
            assert struct.pack("<I", spec.rtc_options0) in reset and struct.pack("<I", spec.rtc_options0) not in hello
    with pytest.raises(ValueError):
        mkimg_esp.build_image("esp32", "nope")
    with pytest.raises(KeyError):
        mkimg_esp.build_image("esp32s2", "hello")


def test_mkimg_esp_cli_writes_images(tmp_path):
    r = subprocess.run([sys.executable, "-I", str(FIX / "mkimg_esp.py"), "--out-dir", str(tmp_path)], capture_output=True, text=True,
                       env=dict(os.environ, PYTHONDONTWRITEBYTECODE="1"), timeout=60)
    assert r.returncode == 0, r.stderr
    assert sorted(p.name for p in tmp_path.iterdir()) == sorted(f"{c}-{v}.img" for c in mkimg_esp.CHIPS for v in mkimg_esp.VARIANTS)
    assert (tmp_path / "esp32s3-hello.img").read_bytes() == mkimg_esp.build_image("esp32s3", "hello")


# --- 실행기 (external) ------------------------------------------------------------

def _runner_source_version() -> str:
    m = re.search(r'^#define PWEH_AVR_RUN_VERSION "([^"]+)"', RUNNER_SRC.read_text(encoding="utf-8"), re.M)
    assert m, "PWEH_AVR_RUN_VERSION 을 찾지 못함"
    return m.group(1)


def _find_runner() -> str | None:
    from pweh.toolsdir import emu_binary_candidates, tools_dir

    for path, _source in emu_binary_candidates("pweh_avr_run", None, os.environ.get("PWEH_AVR_RUN"), tools_dir()):
        if os.path.isabs(path) and os.path.isfile(path) and os.access(path, os.X_OK):
            return path
    return None


@pytest.fixture
def runner():
    path = _find_runner()
    if not path:
        pytest.skip("pweh_avr_run 이 없음 (scripts/install.sh --only simavr, 또는 PWEH_AVR_RUN)")
    return path


def _sealed_memfd(data: bytes) -> int:
    fd = os.memfd_create("fw.hex", os.MFD_ALLOW_SEALING | os.MFD_CLOEXEC)
    os.write(fd, data)
    fcntl.fcntl(fd, fcntl.F_ADD_SEALS, fcntl.F_SEAL_WRITE | fcntl.F_SEAL_GROW | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_SEAL)
    return fd


class Run:
    """실행기 하나 (--hex-fd 봉인 memfd). 끝날 때 반드시 정리한다."""

    def __init__(self, runner: str, hex_text: str, mcu: str = "atmega328p", *, cwd: Path, extra: tuple[str, ...] = ()):
        fd = _sealed_memfd(hex_text.encode("ascii"))
        try:
            self.p = subprocess.Popen([runner, "--mcu", mcu, "--freq", "16000000", *extra, "--hex-fd", str(fd)], cwd=cwd,
                                      stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, pass_fds=(fd,),
                                      start_new_session=True)
        finally:
            os.close(fd)
        self.out = b""

    def read_until(self, want: bytes, timeout: float = 10.0) -> bytes:
        end = time.monotonic() + timeout
        while want not in self.out and time.monotonic() < end:
            r, _, _ = select.select([self.p.stdout], [], [], 0.05)
            if r:
                chunk = os.read(self.p.stdout.fileno(), 65536)
                if not chunk:
                    break
                self.out += chunk
        return self.out

    def finish(self, timeout: float = 10.0) -> tuple[int, bytes, str]:
        try:
            out, err = self.p.communicate(timeout=timeout)
        finally:
            if self.p.poll() is None:
                self.p.kill()
                self.p.wait()
        return self.p.returncode, self.out + (out or b""), (err or b"").decode("utf-8", "replace")


@pytest.mark.external
def test_runner_version_line(runner):
    r = subprocess.run([runner, "--version"], capture_output=True, text=True, timeout=10, stdin=subprocess.DEVNULL)
    assert r.returncode == 0 and r.stdout == f"pweh_avr_run {_runner_source_version()} simavr {SIMAVR_COMMIT}\n"


@pytest.mark.external
def test_runner_links_no_socket_functions(runner):
    nm = shutil.which("nm")
    if not nm:
        pytest.skip("nm 이 없음")
    syms = set()
    for args in (["-D", "--undefined-only"], []):
        r = subprocess.run([nm, *args, runner], capture_output=True, text=True, timeout=30)
        syms |= {ln.split()[-1].split("@")[0] for ln in r.stdout.splitlines() if ln.strip()}
    assert syms, "기호 표가 비어 있음"
    assert not syms & {"socket", "bind", "listen", "accept", "accept4", "connect"}


@pytest.mark.external
@pytest.mark.parametrize("realtime", [False, True])
def test_runner_echo_fixture(runner, tmp_path, realtime):
    run = Run(runner, (FIX / "avr_uart_echo_m328p.hex").read_text(encoding="ascii"), cwd=tmp_path,
              extra=("--uart", "0") + (("--realtime",) if realtime else ()))
    try:
        assert run.read_until(b"OK\r\n").startswith(b"OK\r\n")
        run.p.stdin.write(b"pweh\r")
        run.p.stdin.flush()
        assert run.read_until(b"pweh\r").endswith(b"pweh\r")
        run.p.stdin.write(b"\x04")   # EOT → cli; sleep → 정상 종료
        run.p.stdin.flush()
    finally:
        rc, out, err = run.finish()
    assert rc == 0, err
    assert out == b"OK\r\npweh\r"
    assert err.rstrip().splitlines()[-1].startswith("pweh_avr_run: state=done cycles=")


@pytest.mark.external
def test_runner_crash_hex_exits_3_without_listening(runner, tmp_path):
    run = Run(runner, CRASH_HEX, cwd=tmp_path)
    rc, out, err = run.finish()
    assert rc == 3 and out == b""
    assert err.rstrip().splitlines()[-1].startswith("pweh_avr_run: state=crashed")


@pytest.mark.external
@pytest.mark.parametrize("target", sorted(make_avr_oob_probe.TARGETS))
def test_runner_oob_probes_read_erased_padding(runner, tmp_path, target):
    mcu, _freq, name = make_avr_oob_probe.TARGETS[target]
    rc, out, err = Run(runner, (FIX / name).read_text(encoding="ascii"), mcu, cwd=tmp_path).finish()
    assert rc == 0, err   # 충돌(SIGSEGV)·호스트 힙 내용 없음
    assert out == make_avr_oob_probe.EXPECTED[target]
    assert err.rstrip().splitlines()[-1].startswith("pweh_avr_run: state=done")


def _hex_line(addr: int, rtype: int, data: bytes, *, bad_checksum: bool = False) -> str:
    rec = bytes([len(data), (addr >> 8) & 0xFF, addr & 0xFF, rtype]) + data
    cs = (-sum(rec) + (1 if bad_checksum else 0)) & 0xFF
    return ":" + (rec + bytes([cs])).hex().upper()


@pytest.mark.external
@pytest.mark.parametrize("case,why", [
    ("checksum", "체크섬"),
    ("no-eof", "EOF"),
    ("after-eof", "EOF 레코드 뒤"),
    ("not-hex", "16진"),
    ("count", "바이트 수"),
    ("eeprom-too-big", "EEPROM 크기"),
    ("flash-too-big", "플래시 크기"),
    ("data-space", "지원하지 않는 주소"),
    ("segment-02", "유형 02"),
])
def test_runner_rejects_bad_hex_with_line_numbers_only(runner, tmp_path, case, why):
    secret = bytes.fromhex("0C94DEADBEEF")
    good = _hex_line(0, 0, secret)
    text = {
        "checksum": good + "\n" + _hex_line(0x10, 0, b"\x01\x02", bad_checksum=True) + "\n:00000001FF\n",
        "no-eof": good + "\n",
        "after-eof": good + "\n:00000001FF\n" + good + "\n",
        "not-hex": good + "\n:02001000ZZ01ED\n:00000001FF\n",
        "count": good + "\n:0500100001020304E2\n:00000001FF\n",
        "eeprom-too-big": good + "\n" + _hex_line(0, 4, b"\x00\x81") + "\n" + _hex_line(0x03FE, 0, b"\x01\x02\x03\x04") + "\n:00000001FF\n",
        "flash-too-big": good + "\n" + _hex_line(0x7FFE, 0, b"\x01\x02\x03\x04") + "\n:00000001FF\n",
        "data-space": good + "\n" + _hex_line(0, 4, b"\x00\x80") + "\n" + _hex_line(0x0100, 0, b"\x01") + "\n:00000001FF\n",
        "segment-02": good + "\n" + _hex_line(0, 2, b"\x08\x00") + "\n" + _hex_line(0x10, 0, b"\x01") + "\n:00000001FF\n",
    }[case]
    rc, out, err = Run(runner, text, cwd=tmp_path).finish()
    assert rc == 1 and out == b"", (rc, err)
    assert why in err, err
    assert "DEADBEEF" not in err.upper() and secret.hex().upper() not in err.upper()   # 레코드 내용은 진단에 쓰지 않는다
    if case in ("checksum", "not-hex", "count", "after-eof"):
        assert re.search(r"HEX \d+ 번째 줄", err), err


@pytest.mark.external
def test_runner_ignores_fuse_records_and_loads_eeprom(runner, tmp_path):
    """퓨즈(0x820000) 레코드는 무시(알림), EEPROM 레코드는 적재 — OOB 탐침 328p 의 EEPROM 되읽기에 퓨즈 레코드를 더해 본다."""
    base = (FIX / "avr_oob_probe_m328p.hex").read_text(encoding="ascii").replace(":00000001FF\n", "")
    text = base + _hex_line(0, 4, b"\x00\x82") + "\n" + _hex_line(0, 0, b"\xff\xd9\xfd") + "\n:00000001FF\n"
    rc, out, err = Run(runner, text, cwd=tmp_path).finish()
    assert rc == 0 and out == make_avr_oob_probe.EXPECTED["m328p"], err
    assert "퓨즈·잠금·서명 레코드 3 바이트는 무시함" in err


@pytest.mark.external
def test_runner_exits_5_when_output_reader_is_gone(runner, tmp_path):
    run = Run(runner, (FIX / "avr_uart_echo_m328p.hex").read_text(encoding="ascii"), cwd=tmp_path)
    try:
        assert run.read_until(b"OK\r\n").startswith(b"OK\r\n")
        run.p.stdout.close()          # 서버가 사라진 것처럼 — SIGPIPE 가 아니라 EPIPE → 종료 코드 5
        run.p.stdin.write(b"x")
        run.p.stdin.flush()
        rc = run.p.wait(10)
    finally:
        if run.p.poll() is None:
            run.p.kill()
            run.p.wait()
    assert rc == 5


@pytest.mark.external
@pytest.mark.parametrize("argv", [
    [],
    ["--mcu", "atmega328p"],
    ["--mcu", "atmega328p", "--freq", "999", "x.hex"],
    ["--mcu", "atmega328p", "--freq", "16000000", "--uart", "4", "x.hex"],
    ["--mcu", "atmega328p", "--freq", "16000000", "x.elf"],
    ["--mcu", "atmega328p", "--freq", "16000000", "--hex-fd", "2"],
    ["--mcu", "atmega328p", "--freq", "16000000", "--hex-fd", "5", "x.hex"],
    ["--mcu", "ATMEGA328P", "--freq", "16000000", "x.hex"],
    ["--mcu", "atmega328p", "--freq", "16000000", "--gdb", "x.hex"],
    ["--version", "--mcu", "atmega328p"],
])
def test_runner_usage_errors_exit_2(runner, tmp_path, argv):
    r = subprocess.run([runner, *argv], capture_output=True, timeout=10, cwd=tmp_path, stdin=subprocess.DEVNULL)
    assert r.returncode == 2 and r.stdout == b""


@pytest.mark.external
def test_runner_unknown_mcu_and_missing_uart_exit_2(runner, tmp_path):
    hexfile = tmp_path / "fw.hex"
    hexfile.write_text(CRASH_HEX, encoding="ascii")
    for mcu, uart in (("atmega9999", "0"), ("atmega328p", "3")):   # 328p 에는 USART0 하나
        r = subprocess.run([runner, "--mcu", mcu, "--freq", "16000000", "--uart", uart, str(hexfile)], capture_output=True,
                           timeout=10, stdin=subprocess.DEVNULL)
        assert r.returncode == 2, (mcu, uart, r.stderr)
