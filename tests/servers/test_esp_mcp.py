"""esp-mcp 테스트: 가짜 esptool(v5.4.0 / v4.8.1 출력 흉내)로 기기 없이 도구·정책·작업을 검사한다 + stdio 스모크 + 실제 Windows esptool.exe(external).

포트는 절대 열지 않는다: 리눅스 포트 존재 확인·점유 확인은 monkeypatch 하고, Windows 백엔드는 interop 감지와 wslpath 변환을 바꿔 끼운다.
Windows 프로세스 조회·종료(winproc)는 가짜 esptool.exe(리눅스 프로세스, PyInstaller onefile 흉내)를 /proc 에서 찾는 FakeWinProcs 로 바꾼다.
"""

from __future__ import annotations

import hashlib
import json
import os
import signal
import socket
import subprocess
import sys
import threading
import time
from pathlib import Path
from types import SimpleNamespace

import anyio
import pytest
from mcp import Client

from mcp_helpers import call, stdio_params
from servers.esp_testutil import (
    FakeWinProcs,
    case_dir,
    fake_unc,
    kill_fake_processes,
    make_case,
    make_fake_esptool,
    pid_alive,
    read_log,
    real_linux_esptool,
    real_windows_esptool,
    remove_windows_mei_dirs,
    wait_until,
    windows_mei_dirs,
)

pytestmark = pytest.mark.anyio

REPO = Path(__file__).resolve().parents[2]


@pytest.fixture
def anyio_backend():
    return "asyncio"


@pytest.fixture
def fake(workspace, tmp_path, monkeypatch):
    from esp_mcp import esptool_cli, ports, winproc
    from esp_mcp.esptool_cli import clear_cache
    from pweh.runtime import reset_runtimes

    lin = make_fake_esptool(tmp_path / "bin", "esptool")
    win = make_fake_esptool(tmp_path / "bin", "esptool.exe")
    log = tmp_path / "fake.log"
    pidfile = tmp_path / "fake.pid"
    mei = tmp_path / "mei"
    mei.mkdir()
    monkeypatch.setenv("PWEH_ESPTOOL", str(lin))
    monkeypatch.setenv("PWEH_ESPTOOL_WIN", str(win))
    monkeypatch.setenv("FAKE_ESPTOOL_LOG", str(log))
    monkeypatch.setenv("FAKE_ESPTOOL_PIDFILE", str(pidfile))
    monkeypatch.setenv("FAKE_ESPTOOL_STATE", str(tmp_path / "fake.count"))
    monkeypatch.setenv("FAKE_ESPTOOL_MODE", "normal")
    monkeypatch.setenv("FAKE_ESPTOOL_ONEFILE", "1")  # 가짜 esptool.exe 는 PyInstaller onefile 처럼 부트로더 + 자식
    monkeypatch.setenv("FAKE_ESPTOOL_MEI_ROOT", str(mei))
    for k in ("FAKE_ESPTOOL_VERSION", "FAKE_ESPTOOL_CHIP", "FAKE_ESPTOOL_FOREIGN_CFG", "FAKE_ESPTOOL_CHIPSTATE",
              "FAKE_ESPTOOL_NO_AUTORESET", "FAKE_ESPTOOL_NATIVE_USB", "FAKE_ESPTOOL_CONNECT_MARK"):
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setenv("ESPTOOL_BAUD", "9600")  # 하위 프로세스 환경에서 지워지거나 중립값으로 덮여야 한다
    monkeypatch.setenv("ESPTOOL_STUB_VERSION", "1")  # 레거시 스텁 강제 시도 — 중립값으로 덮여야 한다
    # 기기 없이: 리눅스 장치 존재/점유 확인과 Windows interop/경로 변환을 바꿔 끼운다
    monkeypatch.setattr(ports, "path_exists", lambda p: True)
    monkeypatch.setattr(ports, "realpath", lambda p: p)
    monkeypatch.setattr(ports, "device_users", lambda p: [])
    monkeypatch.setattr(ports, "interop_status", lambda: {"wsl": True, "interop": True, "reason": None})
    monkeypatch.setattr(ports, "to_windows_path", fake_unc)
    fw = FakeWinProcs()
    monkeypatch.setattr(winproc, "query", fw.query)
    monkeypatch.setattr(winproc, "terminate", fw.terminate)
    monkeypatch.setattr(winproc, "windows_ansi_encoding", lambda: "cp949")
    monkeypatch.setattr(esptool_cli, "WIN_CHILD_WAIT_S", 1.0)
    monkeypatch.setattr(esptool_cli, "WIN_BOOT_EXIT_S", 3.0)
    monkeypatch.setattr(esptool_cli, "WIN_SETTLE_S", 2.0)
    reset_runtimes()
    clear_cache()

    def mode(m: str, version: str | None = None, chip: str | None = None) -> None:
        monkeypatch.setenv("FAKE_ESPTOOL_MODE", m)
        if version:
            monkeypatch.setenv("FAKE_ESPTOOL_VERSION", version)
        else:
            monkeypatch.delenv("FAKE_ESPTOOL_VERSION", raising=False)
        if chip:
            monkeypatch.setenv("FAKE_ESPTOOL_CHIP", chip)
        else:
            monkeypatch.delenv("FAKE_ESPTOOL_CHIP", raising=False)
        clear_cache()

    def calls(cmd: str | None = None) -> list[dict]:
        rows = [r for r in read_log(log) if r.get("phase") == "start"]
        if cmd:
            rows = [r for r in rows if any(a.replace("_", "-") == cmd for a in r["argv"])]
        return rows

    def ends(cmd: str | None = None) -> list[dict]:
        rows = [r for r in read_log(log) if r.get("phase") == "end"]
        if cmd:
            rows = [r for r in rows if any(a.replace("_", "-") == cmd for a in r["argv"])]
        return rows

    yield SimpleNamespace(lin=lin, win=win, log=log, pidfile=pidfile, mode=mode, calls=calls, ends=ends, workspace=workspace,
                          tmp=tmp_path, winprocs=fw, mei=mei)
    fw.deny = False
    kill_fake_processes()
    clear_cache()


async def _wait_job(c, job_id: str, timeout: float = 60.0) -> dict:
    deadline = time.monotonic() + timeout
    while True:
        st = await call(c, "esp_job_status", job_id=job_id, wait_seconds=2)
        if st.get("status") not in ("queued", "running", "cancelling"):
            return st
        if time.monotonic() > deadline:
            raise AssertionError(f"job did not finish: {st}")


def _sha(p: Path) -> str:
    return hashlib.sha256(p.read_bytes()).hexdigest()


def _after_of(argv: list[str]) -> str:
    return argv[argv.index("--after") + 1]


def _opt(argv: list[str], name: str) -> str:
    return argv[argv.index(name) + 1]


# ---------------------------------------------------------------------------
# 정책 단위 테스트
# ---------------------------------------------------------------------------


def _argv(cmd: str, *args: str, port: str = "COM3", exe: str = "/x/esptool.exe", **over) -> list[str]:
    opts = {"--chip": "esp32s3", "--port": port, "--baud": "115200", "--before": "default-reset", "--after": "hard-reset"}
    opts.update({f"--{k.replace('_', '-')}": v for k, v in over.items()})
    out = [exe]
    for k, v in opts.items():
        if v is None:
            continue
        out += [k, v]
    return out + ["--connect-attempts", "7", cmd, *args]


def test_policy_allows_only_read_only_commands(tmp_path):
    from esp_mcp.policy import classify_esptool_argv
    from pweh.safety import Risk

    dumps = tmp_path / "case" / "dumps"
    dumps.mkdir(parents=True)
    out = dumps / ".esp-flash.read1.partial"
    assert classify_esptool_argv(["/x/esptool.exe", "version"]).risk == Risk.OBSERVE
    for cmd in ("flash-id", "flash_id", "get-security-info", "get_security_info", "chip-id", "read-mac"):
        c = classify_esptool_argv(_argv(cmd), port="COM3")
        assert c.risk == Risk.MODIFY and c.rule_id.startswith("esp.info."), (cmd, c)
    c = classify_esptool_argv(_argv("read-flash", "0x0", "ALL", str(out)), port="COM3", allowed_output_dir=dumps)
    assert c.risk == Risk.MODIFY and c.rule_id == "esp.read-flash"
    unc = fake_unc(out)
    c = classify_esptool_argv(_argv("read_flash", "0x1000", "0x400000", unc, before="default_reset", after="no_reset_stub"), port="COM3",
                              allowed_output_dir=dumps, output_map={unc: str(out)})
    assert c.risk == Risk.MODIFY and "no-reset-stub" in c.reason, c
    c = classify_esptool_argv(_argv("read-flash", "0", "4096", str(out), port="/dev/ttyACM0", no_stub=None) + [],
                              port="/dev/ttyACM0", allowed_output_dir=dumps)
    assert c.risk == Risk.MODIFY


@pytest.mark.parametrize("argv_fn,rule", [
    (lambda o: _argv("write-flash", "0x0", "/tmp/fw.bin"), "esp.cmd.flash-write"),
    (lambda o: _argv("write_flash", "0x0", "/tmp/fw.bin"), "esp.cmd.flash-write"),
    (lambda o: _argv("erase-flash"), "esp.cmd.flash-write"),
    (lambda o: _argv("erase_region", "0x0", "0x1000"), "esp.cmd.flash-write"),
    (lambda o: _argv("write-flash-status", "--non-volatile", "0"), "esp.cmd.flash-write"),
    (lambda o: _argv("write-mem", "0x600", "1"), "esp.cmd.mem-write"),
    (lambda o: _argv("read-mem", "0x60008000"), "esp.cmd.mem-read"),
    (lambda o: _argv("dump-mem", "0x0", "16", "/tmp/x"), "esp.cmd.mem-read"),
    (lambda o: _argv("load-ram", "/tmp/x.bin"), "esp.cmd.ram-exec"),
    (lambda o: _argv("run"), "esp.cmd.ram-exec"),
    (lambda o: ["/x/esptool.exe", "--chip", "esp32s3", "merge-bin", "-o", "/tmp/m.bin", "0x0", "/tmp/a.bin"], "esp.cmd.offline"),
    (lambda o: _argv("image-info", "/tmp/a.bin"), "esp.cmd.offline"),
    (lambda o: _argv("frobnicate"), "esp.cmd.unknown"),
    (lambda o: ["/x/espefuse.exe", "--port", "COM3", "summary"], "esp.exe.forbidden"),
    (lambda o: ["/x/espsecure", "--help"], "esp.exe.forbidden"),
    (lambda o: _argv("flash-id") + ["@/tmp/args.txt"], "esp.argv.unparsed"),
    (lambda o: ["/x/esptool", "--chip", "esp32s3", "--port", "COM3", "--override-vddsdio", "1.9V", "flash-id"], "esp.opt.forbidden"),
    (lambda o: ["/x/esptool", "--chip", "esp32s3", "--port", "COM3", "--stub-version", "1", "flash-id"], "esp.opt.forbidden"),
    (lambda o: ["/x/esptool", "-p", "COM3", "flash-id"], "esp.opt.unknown"),
    (lambda o: _argv("flash-id", port=None), "esp.port.missing"),
    (lambda o: _argv("flash-id", port="COM4"), "esp.port.mismatch"),
    (lambda o: _argv("flash-id", port="rfc2217://h:1"), "esp.port.invalid"),
    (lambda o: _argv("flash-id", chip="esp99"), "esp.opt.value"),
    (lambda o: _argv("flash-id", before="no-reset-no-sync"), "esp.opt.value"),
    (lambda o: _argv("flash-id", baud="99999999"), "esp.opt.value"),
    (lambda o: _argv("flash-id") [:-3] + ["--connect-attempts", "0", "flash-id"], "esp.opt.value"),
    # --after no-reset 은 스텁을 빠져나가며 FLASH_BEGIN(레거시 스텁의 상태 레지스터 쓰기) — --no-stub 이어도(--chip auto 는 남은 스텁을 스텁으로 다룸)
    (lambda o: _argv("flash-id", after="no-reset"), "esp.after.no-reset"),
    (lambda o: _argv("flash_id", after="no_reset"), "esp.after.no-reset"),
    (lambda o: _argv("read-flash", "0x0", "ALL", str(o), after="no-reset"), "esp.after.no-reset"),
    (lambda o: _argv("flash-id", after="no-reset")[:-3] + ["--no-stub", "--connect-attempts", "7", "flash-id"], "esp.after.no-reset"),
    (lambda o: _argv("flash-id", after="soft-reset"), "esp.after.soft-reset"),
    (lambda o: _argv("flash_id", after="soft_reset"), "esp.after.soft-reset"),
    (lambda o: _argv("flash-id", "extra"), "esp.argv.extra"),
    (lambda o: _argv("read-flash", "0x0", "ALL", str(o), "--flash-size", "4MB"), "esp.argv.extra"),
    (lambda o: _argv("read-flash", "0x1000", "ALL", str(o)), "esp.read.size"),
    (lambda o: _argv("read-flash", "zz", "0x10", str(o)), "esp.read.address"),
    (lambda o: _argv("read-flash", "0x0", "0x10", "/etc/passwd"), "esp.output.outside"),
    (lambda o: _argv("read-flash", "0x0", "0x10", "\\\\wsl.localhost\\Ubuntu\\etc\\shadow"), "esp.output.outside"),
    (lambda o: _argv("read-flash", "0x0", "0x10", str(o.parent.parent / "x.bin")), "esp.output.outside"),
])
def test_policy_refuses_everything_else(tmp_path, argv_fn, rule):
    from esp_mcp.policy import classify_esptool_argv
    from pweh.safety import Risk

    dumps = tmp_path / "case" / "dumps"
    dumps.mkdir(parents=True)
    out = dumps / ".x.read1.partial"
    c = classify_esptool_argv(argv_fn(out), port="COM3", allowed_output_dir=dumps)
    assert c.risk == Risk.DESTRUCTIVE and c.rule_id == rule, c


def test_policy_version_specific_after_and_validators():
    from esp_mcp.policy import (AFTER_MODES, after_modes, classify_esptool_argv, stub_safe_after, validate_after, validate_offset,
                                validate_output_name, validate_size, validate_verify)
    from pweh.errors import ValidationFailed
    from pweh.safety import Risk

    # watchdog-reset: esptool v5 와 v4.12 이상
    assert classify_esptool_argv(_argv("flash-id", after="watchdog-reset"), port="COM3", esptool_major=5).risk == Risk.MODIFY
    assert classify_esptool_argv(_argv("flash_id", after="watchdog_reset"), port="COM3", esptool_major=4, esptool_minor=12).risk == Risk.MODIFY
    assert classify_esptool_argv(_argv("flash_id", after="watchdog_reset"), port="COM3", esptool_major=4, esptool_minor=8).risk == Risk.DESTRUCTIVE
    assert classify_esptool_argv(_argv("flash-id", after="watchdog-reset"), port="COM3", esptool_major=4).risk == Risk.DESTRUCTIVE
    assert validate_after("hard_reset", 4) == "hard-reset"
    assert validate_after("watchdog-reset", 4, 12) == "watchdog-reset" and validate_after("watchdog_reset", 5, 0) == "watchdog-reset"
    with pytest.raises(ValidationFailed, match="v4.12"):
        validate_after("watchdog-reset", 4, 8)
    # soft-reset 은 FLASH_BEGIN 을 보내므로 받지 않는다
    assert "soft-reset" not in AFTER_MODES and "soft-reset" not in after_modes(4, 8)
    with pytest.raises(ValidationFailed, match="FLASH_BEGIN"):
        validate_after("soft-reset", 5)
    # no-reset 은 받되 실행할 때는 언제나 no-reset-stub
    assert validate_after("no_reset", 4) == "no-reset" and stub_safe_after("no-reset") == "no-reset-stub"
    for a in ("hard-reset", "no-reset-stub", "watchdog-reset"):
        assert stub_safe_after(a) == a
    assert validate_size("all") == "all" and validate_size("4M") == 4 << 20 and validate_size("16MB") == 16 << 20
    assert validate_size("0x400000") == 4 << 20 and validate_size("512K") == 512 * 1024 and validate_size(4096) == 4096
    for bad in (0, -1, "lots", "1G"):
        with pytest.raises(ValidationFailed):
            validate_size(bad)
    assert validate_offset("0x10000") == 0x10000 and validate_offset(None) == 0
    with pytest.raises(ValidationFailed):
        validate_offset("0xFFFFFFFFF")
    assert validate_output_name("fw.bin") == "fw" and validate_output_name(None) is None
    for bad in ("../x", "a/b", "x.read2", ".hidden", "a b"):
        with pytest.raises(ValidationFailed):
            validate_output_name(bad)
    assert validate_verify("single") == "none"
    with pytest.raises(ValidationFailed):
        validate_verify("triple")


def test_no_plain_no_reset_in_any_built_argv():
    """서버가 조립할 수 있는 모든 argv(버전·스텁 여부·after 조합)에 plain no-reset/no_reset 이 없다 (v4 는 no_reset_stub 밑줄 이름)."""
    from esp_mcp.esptool_cli import build_argv
    from esp_mcp.policy import AFTER_MODES, classify_esptool_argv, stub_safe_after
    from pweh.safety import Risk

    for major, minor in ((5, 4), (4, 12), (4, 8), (None, None)):
        for after in AFTER_MODES:
            for no_stub in (False, True):
                eff = stub_safe_after(after)
                # --no-stub 은 ESP8266 이 아닌 칩을 명시할 때만 (auto + --no-stub 은 esp.nostub.esp8266)
                argv = build_argv("/x/esptool", major=major, chip="esp32s3" if no_stub else "auto", port="COM3", baud=115200,
                                  before="no-reset", after=eff, no_stub=no_stub, command="flash-id")
                assert _after_of(argv) not in ("no-reset", "no_reset"), argv
                if after == "no-reset":
                    assert _after_of(argv) == ("no-reset-stub" if major == 5 else "no_reset_stub")
                c = classify_esptool_argv(argv, port="COM3", esptool_major=major, esptool_minor=minor)
                if after == "watchdog-reset" and major == 4 and minor < 12:
                    assert c.risk == Risk.DESTRUCTIVE
                else:
                    assert c.risk == Risk.MODIFY, (major, after, no_stub, c)


def test_policy_refuses_nostub_with_esp8266_or_auto():
    """--no-stub + --chip esp8266|auto 는 DESTRUCTIVE(esp.nostub.esp8266): ESP8266 ROM 은 플래시 연결 때 FLASH_BEGIN(0, 0) 을 받는다.

    ESP8266 이 아닌 칩을 명시하면 --no-stub 도 MODIFY. 인자 검증(validate_no_stub)도 같은 조합을 거부한다.
    """
    from esp_mcp.policy import NOSTUB_REFUSED_CHIPS, classify_esptool_argv, validate_no_stub
    from pweh.errors import ValidationFailed
    from pweh.safety import Risk

    assert set(NOSTUB_REFUSED_CHIPS) == {"auto", "esp8266"}
    out = "/case/dumps/.x.read1.partial"
    for cmd, args in (("flash-id", ()), ("chip-id", ()), ("read-mac", ()), ("get-security-info", ()),
                      ("read-flash", ("0x0", "0x1000", out))):
        for chip in ("esp8266", "auto"):
            argv = _argv(cmd, *args, chip=chip)
            argv = argv[:-(len(args) + 3)] + ["--no-stub"] + argv[-(len(args) + 3):]
            c = classify_esptool_argv(argv, port="COM3", allowed_output_dir="/case/dumps")
            assert c.risk == Risk.DESTRUCTIVE and c.rule_id == "esp.nostub.esp8266", (cmd, chip, c)
            ok = classify_esptool_argv(_argv(cmd, *args, chip=chip), port="COM3", allowed_output_dir="/case/dumps")
            assert ok.risk == Risk.MODIFY, (cmd, chip, ok)  # 스텁을 쓰면(기본) 허용
        argv = _argv(cmd, *args, chip="esp32s3")
        argv = argv[:-(len(args) + 3)] + ["--no-stub"] + argv[-(len(args) + 3):]
        c = classify_esptool_argv(argv, port="COM3", allowed_output_dir="/case/dumps")
        assert c.risk == Risk.MODIFY, (cmd, c)
    for chip in ("auto", "esp8266"):
        with pytest.raises(ValidationFailed, match="ESP8266 이 아닌 칩"):
            validate_no_stub(True, chip)
        assert validate_no_stub(False, chip) is False
    assert validate_no_stub(True, "esp32s3") is True
    with pytest.raises(ValidationFailed):
        validate_no_stub("false", "esp32s3")  # 문자열 'false' 를 True 로 바꾸지 않는다


def test_port_validation(monkeypatch):
    from esp_mcp import ports
    from pweh.errors import ValidationFailed

    assert ports.validate_port("com3").port == "COM3" and ports.validate_port("COM256").backend == "windows"
    for bad in ("COM0", "COM257", "COM1000", "rfc2217://h:2217", "socket://h:1", "/dev/sda", "/tmp/x", "", "LPT1", "/dev/ttyACM0;rm"):
        with pytest.raises(ValidationFailed):
            ports.validate_port(bad)
    monkeypatch.setattr(ports, "path_exists", lambda p: False)
    with pytest.raises(ValidationFailed, match="usbipd"):
        ports.validate_port("/dev/ttyACM0")
    monkeypatch.setattr(ports, "path_exists", lambda p: True)
    monkeypatch.setattr(ports, "realpath", lambda p: "/dev/ttyACM0" if "by-id" in p else p)
    s = ports.validate_port("/dev/serial/by-id/usb-Espressif_USB_JTAG_serial_debug_unit_F4:12:FA:12:34:56-if00")
    assert s.backend == "linux" and s.lock_key == "linux:/dev/ttyACM0"
    monkeypatch.setattr(ports, "realpath", lambda p: "/home/x/evil")
    with pytest.raises(ValidationFailed, match="/dev 밖"):
        ports.validate_port("/dev/ttyUSB0")


def test_windows_path_trailing_dot_or_space_component_refused():
    """Win32 정규화는 경로 요소 끝의 '.'·공백을 지운다(…\\esp-lab.\\dumps → …\\esp-lab\\dumps, 다른 케이스) → 거부."""
    from esp_mcp import ports
    from pweh.errors import ValidationFailed

    ok = "\\\\wsl.localhost\\Ubuntu\\home\\u\\cases\\esp-lab\\dumps\\.esp-flash.read1.partial"
    assert ports.check_windows_path(ok) == ok
    assert ports.check_windows_path("C:\\Users\\u\\a.b\\x.partial")
    for bad in ("\\\\wsl.localhost\\Ubuntu\\home\\u\\cases\\esp-lab.\\dumps\\.esp-flash.read1.partial",
                "\\\\wsl.localhost\\Ubuntu\\home\\u\\cases\\esp-lab..\\dumps\\x",
                "\\\\wsl.localhost\\Ubuntu\\home\\u\\case \\dumps\\x",
                "C:\\work\\dir.\\x.bin",
                "\\\\wsl.localhost\\Ubuntu\\a\\b\\out."):
        with pytest.raises(ValidationFailed, match="'.' 또는 공백"):
            ports.check_windows_path(bad)


def test_output_parsers_v5_v4_and_progress():
    from esp_mcp.esptool_cli import OutputCollector, parse_connect, parse_progress, parse_read_flash, versioned

    v5 = "Reading from 0x00001000 ━╸                              1.6% 4.00kB/256.00kB [0s] "
    p = parse_progress(v5)
    assert p and p.percent == 1.6 and p.address == 0x1000 and p.done == 4096 and p.total == 262144
    p = parse_progress("Reading from 0x00002000 [>          ]   0.8% 8192/1048576 bytes... ")  # v5.0~5.3
    assert p and p.done == 8192 and p.total == 1048576
    p = parse_progress("Reading from 0x00080000 ====>                    50.0% 512.00kB/1.00MB [3s] ")  # Windows ASCII 막대
    assert p and p.percent == 50.0
    col = OutputCollector()
    col.feed("1024 (0 %)\b\b\b\b\b\b\b\b\b\b2048 (0 %)\b\b\b\b\b\b\b\b\b\b26")
    col.feed("2144 (100 %)\nRead 262144 bytes at 0x00000000 in 2.9 seconds (723.1 kbit/s)...\r\n")
    col.close()
    assert col.progress and col.progress.percent == 100.0 and col.progress.done == 262144 and col.progress_lines == 3
    assert parse_read_flash(col.text)["bytes_read"] == 262144
    assert versioned("read-flash", 5) == "read-flash" and versioned("read-flash", 4) == "read_flash" and versioned("default-reset", None) == "default_reset"
    assert versioned("no-reset-stub", 4) == "no_reset_stub" and versioned("no-reset-stub", 5) == "no-reset-stub"
    c4 = parse_connect("Detecting chip type... ESP32-S3\nChip is ESP32-S3 (QFN56) (revision v0.2)\nFeatures: WiFi, BLE\nCrystal is 40MHz\nMAC: f4:12:fa:12:34:56\nStub running...\n")
    assert c4["chip"] == "ESP32-S3" and c4["chip_revision"] == "v0.2" and c4["mac"] == "f4:12:fa:12:34:56" and c4["stub"] and c4["crystal_mhz"] == 40
    assert c4["base_mac"] == "f4:12:fa:12:34:56" and c4["mac_ext"] is None  # 6 바이트 MAC 이면 base_mac 도 같은 값
    sdm = parse_connect("Connected to ESP32-S3 on COM3:\nChip type:          ESP32-S3 in Secure Download Mode\n")
    assert sdm["secure_download_mode"] and sdm["chip"] == "ESP32-S3"
    # C6/H2/C5: MAC 은 8 바이트 EUI-64, BASE MAC 은 6 바이트, MAC_EXT 는 2 바이트 (esptool 5.4.0 read_mac 출력)
    c6 = parse_connect("Connected to ESP32-C6 on COM5:\nChip type:          ESP32-C6 (QFN40) (revision v0.1)\n"
                       "MAC:                60:55:f9:ff:fe:f7:2c:a2\nBASE MAC:           60:55:f9:f7:2c:a2\nMAC_EXT:            ff:fe\n")
    assert c6["mac"] == "60:55:f9:ff:fe:f7:2c:a2" and c6["base_mac"] == "60:55:f9:f7:2c:a2" and c6["mac_ext"] == "ff:fe"
    cfg = parse_connect("esptool v5.4.0\nLoaded custom configuration from /tmp/run-1/esptool.cfg (set with ESPTOOL_CFGFILE)\n")
    assert cfg["custom_config"] == "/tmp/run-1/esptool.cfg" and cfg["custom_config_via_env"] is True
    reuse = parse_connect("Stub flasher is already running. No upload is necessary.\n")
    assert reuse["stub"] and reuse["stub_reused"]
    assert parse_connect("Stub is already running. No upload is necessary.\n")["stub_reused"]  # v4


# 실제 esptool 5.4.0 CLI 코드(prepare_esp_object → 명령 → teardown)를 포트 없는 가짜 칩 객체로 돌려 파이프로 받은 출력
# (venv 의 esptool 5.4.0 + esp-pylib 1.2.0 + rich 15, 비대화형). 진행률 줄은 일부만 남겼다.
REAL_540_FLASH_ID = """esptool v5.4.0
Connected to ESP32-S3 on COM3:
Chip type:          ESP32-S3 (QFN56) (revision v0.0)
Features:           Wi-Fi, BT 5 (LE), Dual Core + LP Core, 240MHz
Crystal frequency:  40MHz
USB mode:           USB-Serial/JTAG
MAC:                00:00:00:00:00:00

Uploading stub flasher...
Running stub flasher...
Stub flasher running.
Changing baud rate to 921600...
Changed.

Flash Memory Information:
=========================
Manufacturer: c8
Device: 4012
Detected flash size: 256KB
Flash type set in eFuse: quad (4 data lines)
Flash voltage set by a strapping pin: 3.3V

Hard resetting via RTS pin...
"""
REAL_540_SECURITY_SDM = """esptool v5.4.0
Connected to ESP32-S3 on COM3:
Chip type:          ESP32-S3 in Secure Download Mode

WARNING: Stub flasher is not supported in Secure Download Mode, it has been disabled. Set --no-stub to suppress this warning.
Changing baud rate to 921600...
Changed.

Security Information:
=====================
Flags: 0x00000005 (0b101)
Key Purposes: (4, 9, 0, 0, 0, 0, 0)
  BLOCK_KEY0 - XTS_AES_128_KEY
  BLOCK_KEY1 - SECURE_BOOT_DIGEST0
  BLOCK_KEY2 - USER/EMPTY
  BLOCK_KEY3 - USER/EMPTY
  BLOCK_KEY4 - USER/EMPTY
  BLOCK_KEY5 - USER/EMPTY
Chip ID: 9
API Version: 0
Secure Boot: Enabled
Flash Encryption: Enabled
SPI Boot Crypt Count (SPI_BOOT_CRYPT_CNT): 0x1

Hard resetting via RTS pin...
"""
REAL_540_READ = """esptool v5.4.0
Connected to ESP32-S3 on COM3:
Chip type:          ESP32-S3 (QFN56) (revision v0.0)
MAC:                00:00:00:00:00:00

Stub flasher running.

Detected flash size: 256KB
Configuring flash size...
Reading from 0x00001000                                  1.6% 4.00kB/256.00kB [0s]
Reading from 0x00002000 \u2578                                3.1% 8.00kB/256.00kB [0s]
Reading from 0x0003f000 \u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2578  98.4% 252.00kB/256.00kB [0s]
Reading from 0x00040000 \u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501 100.0% 256.00kB/256.00kB [0s]
Read 262144 bytes from 0x00000000 in 0.0 seconds (404176.5 kbit/s) to '/tmp/out.bin'.

Staying in flasher stub.
"""
REAL_540_FLASH_ID_SDM = """esptool v5.4.0
Connected to ESP32-S3 on COM3:
Chip type:          ESP32-S3 in Secure Download Mode


ERROR: A fatal error occurred: The 'flash-id' command is not available in Secure Download Mode.
"""
# 실제 esptool 5.4.0 CLI: 스텁이 CHANGE_BAUDRATE 에 응답한 뒤 포트가 조용해짐 (921600 을 못 버티는 브리지)
REAL_540_BAUD_STALL = """esptool v5.4.0
Connected to ESP32-S3 on COM3:
Chip type:          ESP32-S3 (QFN56) (revision v0.0)
MAC:                00:00:00:00:00:00

Uploading stub flasher...
Running stub flasher...
Stub flasher running.
Changing baud rate to 921600...
Changed.


Staying in bootloader.

ERROR: A fatal error occurred: Unable to verify flash chip connection (No more data to read from the serial port. This can have many causes, for troubleshooting steps visit: https://docs.espressif.com/projects/esptool/en/latest/troubleshooting.html).
"""
# 실제 esptool 4.12.0 CLI: Secure Download Mode 의 flash_id 거부는 RuntimeError 계열이라 traceback(rc=1)으로 끝난다
REAL_412_FLASH_ID_SDM = """esptool.py v4.12.0
Chip is ESP32-S3 in Secure Download Mode
WARNING: Stub loader is not supported in Secure Download Mode, setting --no-stub
Enabling default SPI flash mode...
Traceback (most recent call last):
  File "/x/esptool/__init__.py", line 1382, in _main
    main()
  File "/x/esptool/cmds.py", line 1301, in detect_flash_id
    flash_id = esp.flash_id()
esptool.util.UnsupportedCommandError: This command (0xa) is not supported in Secure Download Mode
"""
# 원조 ESP32 의 get-security-info (5.4.0 / 4.8.1 실측): 새 스텁은 0xFF00
REAL_540_ESP32_SEC = """esptool v5.4.0
Connected to ESP32 on COM3:
Chip type:          ESP32-D0WDQ6 (revision v0.0)
MAC:                00:00:00:00:00:00

Stub flasher running.


Hard resetting via RTS pin...

ERROR: A fatal error occurred: Failed to get security info (result was FF00: Command not implemented)
"""


def _collect(text: str):
    from esp_mcp.esptool_cli import OutputCollector

    c = OutputCollector()
    c.feed(text)
    c.close()
    return c


def test_parsers_on_real_esptool_540_rendering():
    from esp_mcp.esptool_cli import detect_problems, parse_connect, parse_flash_id, parse_read_flash, parse_security_info

    t = _collect(REAL_540_FLASH_ID).text
    conn = parse_connect(t)
    assert conn["chip"] == "ESP32-S3" and conn["chip_revision"] == "v0.0" and conn["usb_mode"] == "USB-Serial/JTAG"
    assert conn["stub"] and conn["baud_changed_to"] == 921600 and conn["crystal_mhz"] == 40
    f = parse_flash_id(t)
    assert f["manufacturer_id"] == "c8" and f["device_id"] == "4012" and f["size_bytes"] == 262144 and f["voltage"] == "3.3V"
    t = _collect(REAL_540_SECURITY_SDM).text
    s = parse_security_info(t)
    assert s["secure_download_mode"] and s["secure_boot"] and s["flash_encryption"] and s["crypt_cnt"] == 1
    assert [b["purpose"] for b in s["key_blocks"]][:2] == ["XTS_AES_128_KEY", "SECURE_BOOT_DIGEST0"] and parse_connect(t)["secure_download_mode"]
    c = _collect(REAL_540_READ)
    assert c.progress_lines == 4 and c.progress.percent == 100.0 and c.progress.done == 262144 and c.progress.address == 0x40000
    rf = parse_read_flash(c.text)
    assert rf["bytes_read"] == 262144 and rf["address"] == 0 and rf["detected_flash_size"] == "256KB"
    t = _collect(REAL_540_FLASH_ID_SDM).text
    assert detect_problems(t)[0]["code"] == "esp_secure_download_mode" and parse_connect(t)["secure_download_mode"]


def test_error_mapping_on_real_esptool_output():
    """실제 esptool 5.4.0 출력(Windows esptool.exe 의 COM99, 리눅스 esptool 의 /dev/ttyACM9 — 포트 없음)으로 오류 매핑을 검사한다."""
    from esp_mcp.esptool_cli import EsptoolFailed, RunResult, raise_for_result

    win = (b"esptool v5.4.0\r\nSerial port COM99:\r\n\r\nERROR: A fatal error occurred: Could not open COM99, the port is busy or doesn't exist.\r\n"
           b"(could not open port 'COM99': FileNotFoundError(2, '" + "지정된 파일을 찾을 수 없습니다.".encode("cp949") + b"', None, 2))\r\n\r\n"
           b"Hint: Check if the port is correct and ESP connected\r\n\r\n")
    lin = (b"esptool v5.4.0\nSerial port /dev/ttyACM9:\n\nERROR: A fatal error occurred: Could not open /dev/ttyACM9, the port is busy or doesn't exist.\n"
           b"([Errno 2] could not open port /dev/ttyACM9: [Errno 2] No such file or directory: '/dev/ttyACM9')\n\n"
           b"Hint: Check if the port is correct and ESP connected\n\n")
    busy = (b"ERROR: A fatal error occurred: Could not open COM3, the port is busy or doesn't exist.\r\n(could not open port 'COM3': "
            b"PermissionError(13, '" + "액세스가 거부되었습니다.".encode("cp949") + b"', None, 5))\r\n")
    for raw, code in ((win, "esp_port_not_found"), (lin, "esp_port_not_found"), (busy, "esp_port_busy")):
        col = _collect(raw.decode("utf-8", "replace"))
        with pytest.raises(EsptoolFailed) as ei:
            raise_for_result(RunResult(argv=["esptool"], returncode=2), col.text, "flash-id", log_path="uart/x.log")
        assert ei.value.code == code, (code, str(ei.value))
        assert "uart/x.log" in str(ei.value)


def test_error_mapping_compat_cases():
    """호환성 리뷰의 오류 매핑: baud 변경 뒤 끊김, v4 traceback, v4 문구(wrong chip·stub), ROM read-flash 힌트, 보안 정보 미지원, BOOT 핀 문구."""
    from esp_mcp.esptool_cli import (BOOT_PIN_KO, EsptoolFailed, RunResult, detect_problems, fatal_message, is_classic_chip,
                                     raise_for_result, security_info_unsupported)

    t = _collect(REAL_540_BAUD_STALL).text
    p = detect_problems(t)[0]
    assert p["code"] == "esp_baud_switch_failed" and "460800" in p["hint"] and "115200" in p["hint"]
    # 'Changed.' 없이 끊기면(연결 단계) 기존 코드
    assert detect_problems("Connecting...\nA fatal error occurred: Failed to connect to ESP32: No serial data received.")[0]["code"] == "esp_no_serial_data"
    assert detect_problems("Changed.\nA fatal error occurred: Serial data stream stopped: Possible serial noise or corruption.")[0]["code"] == "esp_baud_switch_failed"
    assert detect_problems("A fatal error occurred: Serial data stream stopped: Possible serial noise or corruption.")[0]["code"] == "esp_serial_noise"
    # v4 Secure Download Mode: fatal_message 가 traceback 마지막 줄로
    t = _collect(REAL_412_FLASH_ID_SDM).text
    assert fatal_message(t) == "UnsupportedCommandError: This command (0xa) is not supported in Secure Download Mode"
    assert detect_problems(t)[0]["code"] == "esp_secure_download_mode"
    with pytest.raises(EsptoolFailed) as ei:
        raise_for_result(RunResult(argv=["esptool"], returncode=1), t, "flash-id")
    assert ei.value.code == "esp_secure_download_mode" and "UnsupportedCommandError" in str(ei.value)
    # 4.8.1 의 wrong chip(쉼표 없음)·stub 실패 문구, 5.x 문구
    assert detect_problems("A fatal error occurred: This chip is ESP32-S3 not ESP32. Wrong --chip argument?")[0]["code"] == "esp_wrong_chip"
    assert detect_problems("ERROR: A fatal error occurred: This chip is ESP32-S3, not ESP32. Wrong --chip argument?")[0]["code"] == "esp_wrong_chip"
    assert detect_problems("A fatal error occurred: Failed to start stub. There was no response.")[0]["code"] == "esp_stub_failed"
    assert detect_problems("A fatal error occurred: Failed to start stub flasher. There was no response.")[0]["code"] == "esp_stub_failed"
    # ROM read-flash: ESP8266 만 못 한다
    rom = detect_problems("A fatal error occurred: ROM does not support function read_flash_slow.")[0]
    assert rom["code"] == "esp_rom_unsupported" and "ESP8266" in rom["hint"] and "ESP32-S3" not in rom["hint"]
    # 보안 정보 미지원 판정
    assert security_info_unsupported(_collect(REAL_540_ESP32_SEC).text, "ESP32")
    assert security_info_unsupported("A fatal error occurred: This command (0x14) is not supported in the current download mode", "ESP32")
    assert security_info_unsupported("esptool.util.UnsupportedCommandError: Invalid (unsupported) command 0x14", None)
    assert security_info_unsupported("A fatal error occurred: Failed to get security info (result was 01C0: x)", "ESP32-D0WDQ6")
    assert not security_info_unsupported("A fatal error occurred: Failed to get security info (Timed out waiting for packet header)", "ESP32-S3")
    assert is_classic_chip("ESP32") and is_classic_chip("ESP32-D0WD-V3") and is_classic_chip("ESP32-PICO-D4") and is_classic_chip("ESP8266EX")
    assert not is_classic_chip("ESP32-S3") and not is_classic_chip("ESP32-C3") and not is_classic_chip("ESP32-S2")
    # BOOT 스트랩 핀 문구 (C3·C6·H2 는 GPIO9)
    assert BOOT_PIN_KO == "BOOT(부트 스트랩 핀: ESP32·S2·S3 는 GPIO0, C3·C6·H2 는 GPIO9 — 그 밖은 데이터시트)"
    for code in ("esp_no_serial_data", "esp_wrong_boot_mode", "esp_connect_failed"):
        hint = next(h for rx, c, s, h, req in __import__("esp_mcp.esptool_cli", fromlist=["x"])._ERROR_PATTERNS if c == code)
        assert BOOT_PIN_KO in hint and "BOOT(GPIO0)" not in hint


def test_windows_decoder_utf8_then_ansi(monkeypatch):
    """Windows esptool.exe 출력: 엄격한 UTF-8(조각 경계의 미완성 문자 이어 붙임), 실패하면 ANSI 코드 페이지(cp949)."""
    from esp_mcp import winproc
    from esp_mcp.esptool_cli import _WindowsDecoder

    monkeypatch.setattr(winproc, "windows_ansi_encoding", lambda: "cp949")
    d = _WindowsDecoder()
    s = "진행 ━━ 100%".encode("utf-8")
    assert d.decode(s[:4]) + d.decode(s[4:]) + d.decode(b"", final=True) == "진행 ━━ 100%"
    cp = b"FileNotFoundError(2, '" + "지정된 파일을 찾을 수 없습니다.".encode("cp949") + b"', None, 2)"
    assert d.decode(cp) == "FileNotFoundError(2, '지정된 파일을 찾을 수 없습니다.', None, 2)"
    assert d.decode(b"ascii again\r\n") == "ascii again\r\n"


def test_child_env_neutralises_config_and_esptool_vars(tmp_path, monkeypatch):
    """실행 환경: 빈 [esptool] 설정을 ESPTOOL_CFGFILE 로, 리눅스는 HOME=run dir, Windows 는 WSLENV 로 중립 ESPTOOL_* 를 넘긴다."""
    from esp_mcp.esptool_cli import CONFIG_NAME, child_env, prepare_run_dir, stub_version_for

    monkeypatch.setenv("ESPTOOL_OPEN_PORT_ATTEMPTS", "0")
    monkeypatch.setenv("ESPTOOL_FS", "1MB")
    monkeypatch.setenv("ESPTOOL_CFGFILE", "/home/u/evil.cfg")
    monkeypatch.setenv("ESP_IDE_WS", "ws://127.0.0.1:1")
    monkeypatch.setenv("WSLENV", "USERPROFILE/p:FOO")
    cfg = prepare_run_dir(tmp_path)
    assert Path(cfg) == tmp_path / CONFIG_NAME and Path(cfg).read_text() == "[esptool]\n"
    assert stub_version_for(5, 4) == "2" and stub_version_for(5, 3) == "2" and stub_version_for(5, 2) == "1"
    assert stub_version_for(4, 12) == "1" and stub_version_for(None, None) == "1" and stub_version_for(6, 0) == "2"
    lin = child_env(windows=False, run_dir=tmp_path, stub_version="2")
    assert lin["HOME"] == str(tmp_path) and lin["ESPTOOL_CFGFILE"] == cfg and lin["ESPTOOL_OPEN_PORT_ATTEMPTS"] == "1"
    assert lin["ESPTOOL_FS"] == "keep" and lin["ESPTOOL_STUB_VERSION"] == "2" and "ESP_IDE_WS" not in lin
    assert lin["PYTHONIOENCODING"] == "utf-8" and lin["NO_COLOR"] == "1"
    win = child_env(windows=True, run_dir=tmp_path, stub_version="1")
    names = win["WSLENV"].split(":")
    assert "ESPTOOL_CFGFILE/p" in names and "USERPROFILE/p" not in names and "FOO" not in names  # WSLENV 는 새로 만든다
    for k in ("ESPTOOL_OPEN_PORT_ATTEMPTS", "ESPTOOL_FS", "ESPTOOL_STUB_VERSION", "ESPTOOL_ENV_FPGA", "NO_COLOR", "TTY_INTERACTIVE"):
        assert k in names and win[k], k
    assert "PYTHONIOENCODING" not in names and "PYTHONUNBUFFERED" not in names  # 얼린 파이썬은 무시한다
    assert all(win[n.split("/")[0]] for n in names)  # 빈 값은 WSLENV 로 넘어가지 않으므로 모두 비어 있지 않다
    assert win["HOME"] == os.environ["HOME"]


def test_config_watch():
    from esp_mcp.esptool_cli import ConfigWatch

    w = ConfigWatch(["/tmp/run-1/esptool.cfg", "\\\\wsl.localhost\\Ubuntu\\tmp\\run-1\\esptool.cfg"])
    w.line("Loaded custom configuration from \\\\wsl.localhost\\Ubuntu\\tmp\\run-1\\esptool.cfg (set with ESPTOOL_CFGFILE)")
    w.line("Loaded custom configuration from /tmp/run-1/esptool.cfg (set with ESPTOOL_CFGFILE)")
    assert w.foreign is None and len(w.loaded) == 2
    w.line("Loaded custom configuration from C:\\Users\\u\\AppData\\Local\\esptool\\esptool.cfg")
    assert w.foreign == "C:\\Users\\u\\AppData\\Local\\esptool\\esptool.cfg"


# ---------------------------------------------------------------------------
# MCP 도구
# ---------------------------------------------------------------------------


async def test_tool_list_version_and_cache(fake):
    from esp_mcp.server import server

    async with Client(server) as c:
        tools = {t.name: t for t in (await c.list_tools()).tools}
        for n in ("esp_version", "esp_list_ports", "esp_chip_info", "esp_security_info", "esp_read_flash_start",
                  "esp_job_status", "esp_job_cancel", "esp_jobs"):
            assert n in tools, n
        assert tools["esp_version"].annotations.read_only_hint and tools["esp_list_ports"].annotations.read_only_hint
        assert not tools["esp_read_flash_start"].annotations.read_only_hint
        for n in ("esp_chip_info", "esp_security_info", "esp_read_flash_start"):
            schema = getattr(tools[n], "input_schema", None) or getattr(tools[n], "inputSchema", None)
            assert "approval_id" in schema["properties"], n
        v = await call(c, "esp_version")
        assert v["ok"] and v["recommended"] == "windows"
        assert v["backends"]["windows"]["available"] and v["backends"]["windows"]["version"] == "5.4.0"
        assert v["backends"]["windows"]["path"] == str(fake.win) and v["backends"]["windows"]["interop"] is True
        assert v["backends"]["linux"]["version"] == "5.4.0" and v["backends"]["linux"]["path"] == str(fake.lin)
        assert any("COM3" in h for h in v["hints"]) and any("install.sh --only esptool" in h for h in v["hints"])
        n_before = len(fake.calls("version"))
        await call(c, "esp_version")
        assert len(fake.calls("version")) == n_before  # 버전은 경로·mtime·크기별로 캐시
    assert sorted(os.listdir(fake.mei)) == []  # onefile 부트로더가 _MEI 를 지웠다


async def test_version_reports_missing_tools(fake, monkeypatch):
    from esp_mcp import ports
    from esp_mcp.server import server

    monkeypatch.setenv("PWEH_ESPTOOL_WIN", str(fake.tmp / "nope" / "esptool.exe"))
    monkeypatch.setenv("PWEH_ESPTOOL", str(fake.tmp / "nope" / "esptool"))
    monkeypatch.setenv("PATH", str(fake.tmp / "empty-path"))
    monkeypatch.setenv("PWEH_TOOLS_DIR", str(fake.tmp / "no-tools"))
    from pweh.runtime import reset_runtimes
    reset_runtimes()
    async with Client(server) as c:
        v = await call(c, "esp_version")
        assert v["ok"] and v["recommended"] is None
        assert not v["backends"]["windows"]["available"] and "tool_missing" in v["backends"]["windows"]["error"]
        assert not v["backends"]["linux"]["available"] and "tool_missing" in v["backends"]["linux"]["error"]
        monkeypatch.setattr(ports, "interop_status", lambda: {"wsl": True, "interop": False, "reason": "interop off"})
        v = await call(c, "esp_version")
        assert "interop off" in v["backends"]["windows"]["error"] and v["backends"]["windows"]["interop"] is False


async def test_list_ports_windows_and_linux(fake, monkeypatch):
    import serial.tools.list_ports as lp
    from esp_mcp import ports
    from esp_mcp.server import server

    ps_json = json.dumps([
        {"Name": "USB 직렬 장치(COM3)", "PNPDeviceID": "USB\\VID_303A&PID_1001&MI_00\\7&2A9A1C3E&0&0000", "Manufacturer": "Microsoft",
         "Status": "OK", "Service": "usbser"},
        {"Name": "Silicon Labs CP210x USB to UART Bridge (COM7)", "PNPDeviceID": "USB\\VID_10C4&PID_EA60\\0001", "Manufacturer": "Silicon Labs",
         "Status": "OK", "Service": "silabser"},
        {"Name": "USB 직렬 장치(COM9)", "PNPDeviceID": "USB\\VID_303A&PID_0009\\0", "Manufacturer": "Microsoft", "Status": "OK",
         "Service": "usbser"},
        {"Name": "USB 직렬 장치(COM5)", "PNPDeviceID": "USB\\VID_303A&PID_4001&MI_00\\1&ABCDEF&0&0000", "Manufacturer": "Microsoft",
         "Status": "OK", "Service": "usbser"},
        {"Name": "USB Audio", "PNPDeviceID": "USB\\VID_1234&PID_5678\\X", "Manufacturer": "x", "Status": "OK", "Service": "x"},
    ])
    seen = {}

    def fake_ps(script, timeout=45.0):
        seen["script"] = script
        return 0, ps_json, ""

    monkeypatch.setattr(ports, "run_powershell", fake_ps)

    class P(SimpleNamespace):
        pass

    monkeypatch.setattr(lp, "comports", lambda include_links=False: [
        P(device="/dev/ttyACM0", description="USB JTAG/serial debug unit", hwid="USB VID:PID=303A:1001 SER=F4:12:FA LOCATION=1-1:1.0",
          vid=0x303A, pid=0x1001, serial_number="F4:12:FA:12:34:56", manufacturer="Espressif"),
        P(device="/dev/ttyS0", description="n/a", hwid="n/a", vid=None, pid=None, serial_number=None, manufacturer=None),
    ])
    monkeypatch.setattr(ports, "device_users", lambda p: [4242] if p == "/dev/ttyACM0" else [])
    async with Client(server) as c:
        r = await call(c, "esp_list_ports")
    assert "Win32_PnPEntity" in seen["script"] and "(COM" in seen["script"]
    w = {p["port"]: p for p in r["windows"]["ports"]}
    assert list(w) == ["COM3", "COM5", "COM7", "COM9"] and r["windows"]["available"]
    assert w["COM3"]["usb_id"] == "303a:1001" and w["COM3"]["kind"] == "esp-usb-serial-jtag" and "USB-Serial/JTAG" in w["COM3"]["description_ko"]
    assert w["COM7"]["kind"] == "usb-uart-bridge" and "CP210x" in w["COM7"]["description_ko"] and w["COM7"]["serial_number"] == "0001"
    assert w["COM9"]["kind"] == "esp-usb-otg-rom"
    lin = r["linux"]["ports"]
    assert [p["port"] for p in lin] == ["/dev/ttyACM0"] and r["linux"]["hidden_legacy_ports"] == 1
    assert lin[0]["kind"] == "esp-usb-serial-jtag" and lin[0]["in_use_by"] == [4242]
    # 종류별 힌트: USB-Serial/JTAG 는 자동 리셋, ROM USB-OTG 는 이미 다운로드 모드(before/after no-reset, 끝나면 사람이 RESET)
    jtag = next(h for h in r["hints"] if "USB-Serial/JTAG" in h)
    otg = next(h for h in r["hints"] if "USB-OTG" in h)
    assert "COM3" in jtag and "/dev/ttyACM0" in jtag and "COM9" not in jtag and "usb-reset" in jtag
    assert "COM9" in otg and "before='no-reset'" in otg and "after='no-reset'" in otg and "no-reset-stub" in otg and "RESET" in otg
    # 앱이 내장 USB 로 만든 포트(TinyUSB CDC): 자동 리셋이 안 될 수 있다 → UART 커넥터로 옮기거나 BOOT+RESET 뒤 새 포트(번호가 바뀜)
    assert w["COM5"]["usb_id"] == "303a:4001" and w["COM5"]["kind"] == "esp-usb"
    app = next(h for h in r["hints"] if "TinyUSB" in h)
    assert "COM5" in app and "COM3" not in app and "UART" in app and "BOOT" in app and "esp_list_ports" in app and "COM 번호" in app
    # interop/powershell 이 없으면 리눅스 목록 + note
    monkeypatch.setattr(ports, "interop_status", lambda: {"wsl": False, "interop": False, "reason": "WSL 이 아님"})
    async with Client(server) as c:
        r = await call(c, "esp_list_ports")
    assert r["windows"]["available"] is False and "WSL" in r["windows"]["note"] and len(r["linux"]["ports"]) == 1


async def test_hardware_tools_need_authorized_case(fake):
    from esp_mcp.server import server

    noauth = make_case("noauth", authorized=False)
    async with Client(server) as c:
        for tool, extra in (("esp_chip_info", {}), ("esp_security_info", {}), ("esp_read_flash_start", {"size": "all"})):
            r = await call(c, tool, case_id=noauth, port="COM3", **extra)
            assert "_error" in r and "authorization_required" in r["_error"], (tool, r)
            r = await call(c, tool, case_id="no-such-case", port="COM3", **extra)
            assert "_error" in r and "not_found" in r["_error"], (tool, r)
    assert fake.calls() == []  # esptool 을 한 번도 실행하지 않음


async def test_chip_info_v5_windows_backend(fake):
    from esp_mcp.server import server

    cid = make_case()
    async with Client(server) as c:
        r = await call(c, "esp_chip_info", case_id=cid, port="com3")
    assert r["ok"] and r["status"] == "ok", r
    assert r["backend"] == "windows" and r["port"] == "COM3" and r["esptool_version"] == "5.4.0"
    assert r["chip"] == "ESP32-S3" and r["chip_description"] == "ESP32-S3 (QFN56) (revision v0.2)" and r["chip_revision"] == "v0.2"
    assert r["crystal_mhz"] == 40 and r["usb_mode"] == "USB-Serial/JTAG" and r["mac"] == "f4:12:fa:12:34:56" and r["stub"] is True
    assert r["base_mac"] == "f4:12:fa:12:34:56" and r["after"] == "hard-reset" and "after_requested" not in r
    assert "Wi-Fi" in r["features"] and r["secure_download_mode"] is False
    f = r["flash"]
    assert f["manufacturer_id"] == "c8" and f["manufacturer"] == "GigaDevice" and f["device_id"] == "4017"
    assert f["size"] == "256KB" and f["size_bytes"] == 262144 and f["type_efuse"] == "quad (4 data lines)" and f["voltage"] == "3.3V"
    assert r["classification"]["risk"] == "modify" and r["classification"]["rule_id"] == "esp.info.flash-id"
    assert r["log_path"] == "uart/esptool-chip-info-001.log"
    log = (case_dir(cid) / r["log_path"]).read_text(encoding="utf-8")
    assert "Flash Memory Information:" in log and "esptool.exe --chip auto --port COM3" in log
    call_ = fake.calls("flash-id")[-1]
    assert call_["exe"] == "esptool.exe"
    assert call_["argv"] == ["--chip", "auto", "--port", "COM3", "--baud", "115200", "--before", "default-reset", "--after", "hard-reset",
                             "--connect-attempts", "7", "flash-id"]
    # 빈 작업 디렉터리 + 빈 [esptool] 설정(ESPTOOL_CFGFILE), 중립 환경변수 (서버 환경의 ESPTOOL_BAUD=9600·STUB_VERSION=1 이 새지 않음)
    assert call_["cwd_files"] == ["esptool.cfg"] and "esp-mcp" in call_["cwd"] and str(case_dir(cid)) not in call_["cwd"]
    env = call_["env"]["ESPTOOL"]
    assert env["ESPTOOL_CFGFILE"] == os.path.join(call_["cwd"], "esptool.cfg") and env["ESPTOOL_BAUD"] == "115200"
    assert env["ESPTOOL_STUB_VERSION"] == "2" and env["ESPTOOL_OPEN_PORT_ATTEMPTS"] == "1" and env["ESPTOOL_FS"] == "keep"
    assert call_["env"]["NO_COLOR"] == "1"
    names = call_["env"]["WSLENV"].split(":")
    assert "NO_COLOR" in names and "ESPTOOL_CFGFILE/p" in names and "ESPTOOL_STUB_VERSION" in names and "PYTHONIOENCODING" not in names
    assert "Loaded custom configuration from" in log and "(set with ESPTOOL_CFGFILE)" in log  # 서버가 만든 설정만 읽음
    arts = json.loads((case_dir(cid) / "case.json").read_text(encoding="utf-8"))["artifacts"]
    assert any(a["path"] == r["log_path"] and a["extra"]["type"] == "esptool-log" for a in arts)
    audit = (case_dir(cid) / "audit.jsonl").read_text(encoding="utf-8")
    assert "esp_flash_id" in audit and "safety_decision" in audit
    assert sorted(os.listdir(fake.mei)) == []


async def test_chip_info_v4_linux_backend_uses_underscore_names(fake):
    from esp_mcp.server import server

    fake.mode("v4")
    cid = make_case()
    async with Client(server) as c:
        r = await call(c, "esp_chip_info", case_id=cid, port="/dev/ttyACM0", chip="esp32s3", baud=230400)
    assert r["ok"], r
    assert r["backend"] == "linux" and r["esptool_version"] == "4.8.1"
    assert r["chip"] == "ESP32-S3" and r["chip_revision"] == "v0.2" and r["mac"] == "f4:12:fa:12:34:56" and r["usb_mode"] is None
    assert r["flash"]["size_bytes"] == 262144 and r["flash"]["voltage"] == "3.3V" and r["flash"]["voltage_source"] == "a strapping pin"
    call_ = fake.calls("flash-id")[-1]
    assert call_["argv"] == ["--chip", "esp32s3", "--port", "/dev/ttyACM0", "--baud", "230400", "--before", "default_reset", "--after",
                             "hard_reset", "--connect-attempts", "7", "flash_id"]
    assert call_["exe"] == "esptool"
    # 리눅스 백엔드: HOME = run dir (홈의 esptool 설정을 찾지 않음), 4.x 는 레거시 스텁("1")이 중립값
    assert call_["env"]["HOME"] == call_["cwd"] and call_["env"]["ESPTOOL"]["ESPTOOL_STUB_VERSION"] == "1"
    # v4.12 미만에 없는 after 는 실행 전에 거부
    async with Client(server) as c:
        r = await call(c, "esp_chip_info", case_id=cid, port="/dev/ttyACM0", after="watchdog-reset")
    assert "_error" in r and "watchdog-reset" in r["_error"] and "v4.12" in r["_error"]


async def test_security_info_v5_v4_encrypted_and_sdm(fake):
    from esp_mcp.server import server

    cid = make_case()
    async with Client(server) as c:
        r = await call(c, "esp_security_info", case_id=cid, port="COM3")
        assert r["ok"] and r["status"] == "ok", r
        assert r["secure_boot"] is False and r["flash_encryption"] is False and r["secure_download_mode"] is False
        assert r["read_flash_possible"] is True and r["ciphertext_expected"] is False and r["crypt_cnt"] == 0
        assert r["crypt_cnt_field"] == "SPI_BOOT_CRYPT_CNT" and r["flags_hex"] == "0x00000000" and r["chip_id"] == 9
        assert len(r["key_blocks"]) == 6 and r["key_blocks"][0] == {"block": "BLOCK_KEY0", "purpose": "USER/EMPTY"}
        assert r["log_path"] == "uart/esptool-security-info-001.log"
        assert r["raw_fields"]["Secure Boot"] == "Disabled" and r["raw_fields"]["SPI Boot Crypt Count (SPI_BOOT_CRYPT_CNT)"] == "0x0"
        assert r["raw_fields"]["Flags"] == "0x00000000 (0b0)" and "BLOCK_KEY0 - USER/EMPTY" not in r["raw_fields"]
        fake.mode("encrypted")
        r = await call(c, "esp_security_info", case_id=cid, port="COM3")
        assert r["secure_boot"] is True and r["flash_encryption"] is True and r["ciphertext_expected"] is True and r["read_flash_possible"]
        assert r["key_blocks"][0]["purpose"] == "XTS_AES_128_KEY" and r["key_blocks"][1]["purpose"] == "SECURE_BOOT_DIGEST0"
        assert any("암호문" in a for a in r["assessment"])
        fake.mode("sdm")
        r = await call(c, "esp_security_info", case_id=cid, port="COM3")
        assert r["ok"] and r["status"] == "ok" and r["secure_download_mode"] is True and r["read_flash_possible"] is False
        assert r["parsed_flags"]["SECURE_DOWNLOAD_ENABLE"] is True and r["chip"] == "ESP32-S3"
        assert any("Secure Download Mode 켜짐" in a and "우회" in a for a in r["assessment"])
        assert any("Stub flasher is not supported" in w for w in r["warnings"])
        fake.mode("sdm", "4.8.1")
        r = await call(c, "esp_security_info", case_id=cid, port="/dev/ttyUSB0")
        assert r["ok"] and r["secure_download_mode"] is True and r["esptool_version"] == "4.8.1" and r["backend"] == "linux"
        assert fake.calls("get-security-info")[-1]["argv"][-1] == "get_security_info"


async def test_security_info_classic_esp32_unsupported(fake):
    """원조 ESP32 는 get-security-info 를 지원하지 않는다: ok=true, status='unsupported', 보안 필드·read_flash_possible 은 null (미확인)."""
    from esp_mcp.server import server

    cid = make_case()
    async with Client(server) as c:
        for version, port, no_stub in ((None, "COM3", False), (None, "COM3", True), ("4.8.1", "/dev/ttyUSB0", False),
                                       ("4.8.1", "/dev/ttyUSB0", True)):
            fake.mode("normal", version, chip="esp32")
            r = await call(c, "esp_security_info", case_id=cid, port=port, no_stub=no_stub, chip="esp32" if no_stub else "auto")
            assert r.get("ok") is True and r["status"] == "unsupported", (version, no_stub, r)
            assert r["chip"] in ("ESP32", "ESP32-D0WDQ6") and r["read_flash_possible"] is None and r["secure_download_mode"] is None
            assert r["secure_boot"] is None and r["flash_encryption"] is None and r["key_blocks"] is None and r["flags_hex"] is None
            assert any("미확인" in n for n in r["notes"]) and any("미확인" in a for a in r["assessment"])
            assert r["error"] and ("Command not implemented" in r["error"] or "0x14" in r["error"])
        # 같은 칩의 flash-id 는 정상
        fake.mode("normal", chip="esp32")
        r = await call(c, "esp_chip_info", case_id=cid, port="COM3")
        assert r["ok"] and r["chip"] == "ESP32" and r["chip_description"].startswith("ESP32-D0WD")


async def test_chip_info_secure_download_mode_returns_partial(fake):
    from esp_mcp.server import server

    cid = make_case()
    for version in (None, "4.8.1"):
        fake.mode("sdm", version)
        async with Client(server) as c:
            r = await call(c, "esp_chip_info", case_id=cid, port="COM3")
        assert r["ok"] and r["status"] == "secure_download_mode", r
        assert r["secure_download_mode"] is True and r["read_flash_possible"] is False and r["flash"] is None
        assert r["chip"] == "ESP32-S3" and "Secure Download Mode" in (r["error"] or "")
        assert any("우회" in n for n in r["notes"])
        if version == "4.8.1":  # v4 는 traceback(rc=1)으로 끝난다 → traceback 마지막 줄을 error 로
            assert r["error"].startswith("UnsupportedCommandError:") and "(0xa)" in r["error"]


async def test_error_mapping_busy_noconn_wrongboot(fake):
    from esp_mcp.server import server

    cid = make_case()
    async with Client(server) as c:
        fake.mode("busy")
        r = await call(c, "esp_chip_info", case_id=cid, port="COM3")
        assert "_error" in r and "[esp_port_busy]" in r["_error"] and "시리얼 모니터" in r["_error"], r
        assert "액세스가 거부되었습니다" in r["_error"]  # Windows 출력(cp949)을 ANSI 코드 페이지로 풀었다
        assert "uart/esptool-chip-info-" in r["_error"]  # 실패해도 로그를 남기고 경로를 알려준다
        r = await call(c, "esp_chip_info", case_id=cid, port="/dev/ttyACM0")
        assert "[esp_port_busy]" in r["_error"], r
        fake.mode("noconn")
        r = await call(c, "esp_security_info", case_id=cid, port="COM3")
        assert "[esp_no_serial_data]" in r["_error"] and "BOOT" in r["_error"] and "GPIO9" in r["_error"], r
        fake.mode("wrongboot")
        r = await call(c, "esp_chip_info", case_id=cid, port="COM3", chip="esp32s3")
        assert "[esp_wrong_boot_mode]" in r["_error"] and "no-reset" in r["_error"], r
    logs = sorted(p.name for p in (case_dir(cid) / "uart").iterdir())
    assert len(logs) == 4


async def test_baud_switch_stall_maps_to_retry_hint(fake):
    """'Changed.' 뒤 끊김(921600 을 못 버티는 브리지) → esp_baud_switch_failed + baud=460800 → 115200 재시도 힌트."""
    from esp_mcp.server import server

    fake.mode("baudstall")
    cid = make_case()
    async with Client(server) as c:
        r = await call(c, "esp_chip_info", case_id=cid, port="COM3", baud=921600)
        assert "[esp_baud_switch_failed]" in r["_error"] and "460800" in r["_error"] and "115200" in r["_error"], r
        st = await _wait_job(c, (await call(c, "esp_read_flash_start", case_id=cid, port="COM3"))["job_id"])
    assert st["status"] == "failed" and st["error"]["code"] == "esp_baud_switch_failed" and "baud=460800" in st["error"]["hint"], st
    assert sorted(os.listdir(case_dir(cid) / "dumps")) == []


async def test_wrong_chip_and_stub_failure_v4(fake):
    from esp_mcp.server import server

    cid = make_case()
    async with Client(server) as c:
        for version in (None, "4.8.1"):
            fake.mode("normal", version)
            r = await call(c, "esp_chip_info", case_id=cid, port="COM3", chip="esp32")
            assert "[esp_wrong_chip]" in r["_error"], (version, r)
            fake.mode("stubfail", version)
            r = await call(c, "esp_chip_info", case_id=cid, port="COM3")
            assert "[esp_stub_failed]" in r["_error"], (version, r)


async def test_mac_eui64_chip(fake):
    from esp_mcp.server import server

    fake.mode("normal", chip="esp32c6")
    cid = make_case()
    async with Client(server) as c:
        r = await call(c, "esp_chip_info", case_id=cid, port="COM3")
    assert r["chip"] == "ESP32-C6" and r["mac"] == "60:55:f9:ff:fe:f7:2c:a2"
    assert r["base_mac"] == "60:55:f9:f7:2c:a2" and r["mac_ext"] == "ff:fe"


async def test_read_flash_double_success_windows_backend(fake):
    from esp_mcp.server import server
    from pweh import schemas

    cid = make_case()
    cdir = case_dir(cid)
    async with Client(server) as c:
        r = await call(c, "esp_read_flash_start", case_id=cid, port="COM3")
        assert r["ok"] and r["status"] == "started", r
        assert r["planned_path"] == "dumps/esp-flash.bin" and r["planned_read2_path"] == "dumps/esp-flash.read2.bin" and r["reads"] == 2
        assert r["classification"]["rule_id"] == "esp.read-flash" and r["read1_after"] == "no-reset-stub" and r["read1_baud"] == 921600
        st = await _wait_job(c, r["job_id"])
    assert st["status"] == "succeeded", st
    assert st["progress"] == 1.0 and "읽기 2/2" in st["message"]
    res = st["result"]
    primary, read2, meta_p = cdir / "dumps" / "esp-flash.bin", cdir / "dumps" / "esp-flash.read2.bin", cdir / "dumps" / "esp-flash.json"
    assert primary.stat().st_size == 262144 and read2.stat().st_size == 262144
    assert res["sha256"] == _sha(primary) == res["sha256_read2"] == _sha(read2) and res["match"] is True
    assert sorted(p.name for p in (cdir / "dumps").iterdir()) == ["esp-flash.bin", "esp-flash.json", "esp-flash.read2.bin"]  # 예약 파일 없음
    meta = json.loads(meta_p.read_text(encoding="utf-8"))
    assert meta["method"] == "esptool-read-flash" and meta["source"]["type"] == "esptool" and meta["source"]["device_path"] == "COM3"
    assert meta["source"]["chip"] == "ESP32-S3" and meta["source"]["mac"] == "f4:12:fa:12:34:56" and meta["source"]["base_mac"] == "f4:12:fa:12:34:56"
    assert meta["source"]["flash_size"] == 262144 and meta["source"]["offset"] == 0 and meta["source"]["length"] == 262144
    assert meta["output"] == {"path": "dumps/esp-flash.bin", "sha256": _sha(primary), "size": 262144}
    assert meta["verification"]["method"] == "double-read" and meta["verification"]["match"] is True
    assert meta["verification"]["expected"] == meta["verification"]["actual"] == _sha(primary)
    assert "no-reset-stub" in meta["verification"]["detail"] and "스텁은 읽기마다 전송 MD5" in meta["verification"]["detail"]
    assert meta["reads"][0]["after"] == "no-reset-stub" and meta["reads"][1]["after"] == "hard-reset" and "partial" not in meta["reads"][0]
    assert meta["tool"]["esptool_version"] == "5.4.0" and meta["tool"]["backend"] == "windows" and len(meta["tool"]["argv"]) == 2
    # firmware-dump 스키마 (method enum 에 esptool-read-flash 가 있다) — 메타데이터와 summary_hint 를 그대로 검증
    assert meta["method"] == res["summary_hint"]["method"] == "esptool-read-flash"
    schemas.validate("firmware-dump", meta, label="esp dump metadata")
    schemas.validate("firmware-dump", res["summary_hint"], label="summary hint")
    arts = json.loads((cdir / "case.json").read_text(encoding="utf-8"))["artifacts"]
    kinds = {a["path"]: a for a in arts}
    assert kinds["dumps/esp-flash.bin"]["kind"] == "flash-dump" and kinds["dumps/esp-flash.bin"]["extra"]["role"] == "primary"
    assert kinds["dumps/esp-flash.read2.bin"]["kind"] == "flash-dump" and kinds["dumps/esp-flash.read2.bin"]["extra"]["role"] == "verification-read"
    assert kinds["dumps/esp-flash.json"]["extra"]["type"] == "dump-metadata"
    assert all((cdir / p).exists() for p in res["log_paths"])
    reads = fake.calls("read-flash")
    assert len(reads) == 2
    a1, a2 = reads[0]["argv"], reads[1]["argv"]
    assert _after_of(a1) == "no-reset-stub" and _after_of(a2) == "hard-reset"
    assert _opt(a1, "--baud") == "921600" and a1[-3:-1] == ["0x0", "ALL"]
    # Windows 백엔드: 가짜 esptool.exe 가 받은 출력 경로 = 서버의 to_windows_path 변환 결과
    assert a1[-1] == fake_unc(cdir / "dumps" / ".esp-flash.read1.partial") and a1[-1].startswith("\\\\wsl.localhost\\Ubuntu\\")
    assert a2[-1] == fake_unc(cdir / "dumps" / ".esp-flash.read2.partial")
    assert not any(e["flash_begin"] for e in fake.ends())  # 스텁을 빠져나가는 FLASH_BEGIN 이 한 번도 없었다
    audit = (cdir / "audit.jsonl").read_text(encoding="utf-8")
    assert "esp_read_flash_started" in audit and "esp_read_flash_completed" in audit
    # 자동 번호: 두 번째 덤프는 esp-flash-002
    async with Client(server) as c:
        r2 = await call(c, "esp_read_flash_start", case_id=cid, port="COM3", verify="none", size="64K", offset="0x1000")
        st2 = await _wait_job(c, r2["job_id"])
    assert st2["status"] == "succeeded" and st2["result"]["path"] == "dumps/esp-flash-002.bin" and st2["result"]["size"] == 65536
    assert st2["result"]["verification"]["method"] == "none" and st2["result"]["read2_path"] is None
    last = fake.calls("read-flash")[-1]["argv"]
    assert last[-3:-1] == ["0x1000", "0x10000"] and _after_of(last) == "hard-reset"
    assert sorted(os.listdir(fake.mei)) == []


async def test_read_flash_v4_linux_and_explicit_name(fake):
    from esp_mcp.server import server

    fake.mode("v4")
    cid = make_case()
    async with Client(server) as c:
        r = await call(c, "esp_read_flash_start", case_id=cid, port="/dev/ttyUSB0", output_name="fw-v4.bin", baud=460800)
        st = await _wait_job(c, r["job_id"])
        assert st["status"] == "succeeded", st
        assert st["result"]["path"] == "dumps/fw-v4.bin" and st["result"]["match"] is True and st["result"]["backend"] == "linux"
        a1 = fake.calls("read-flash")[0]["argv"]
        # v4 는 밑줄 이름 no_reset_stub (plain no_reset 은 절대 없음)
        assert "read_flash" in a1 and _after_of(a1) == "no_reset_stub" and "no_reset" not in a1
        assert a1[-1] == str(case_dir(cid) / "dumps" / ".fw-v4.read1.partial")
        # 같은 이름은 덮어쓰지 않는다 (esptool 실행 전에 거부)
        n = len(fake.calls())
        dup = await call(c, "esp_read_flash_start", case_id=cid, port="/dev/ttyUSB0", output_name="fw-v4")
        assert "_error" in dup and "덮어쓰지" in dup["_error"]
        assert len(fake.calls()) == n
        bad = await call(c, "esp_read_flash_start", case_id=cid, port="/dev/ttyUSB0", size="all", offset="0x1000")
        assert "_error" in bad and "offset=0" in bad["_error"]


async def test_read_flash_mismatch_keeps_both(fake):
    from esp_mcp.server import server

    fake.mode("mismatch")
    cid = make_case()
    async with Client(server) as c:
        r = await call(c, "esp_read_flash_start", case_id=cid, port="COM3")
        st = await _wait_job(c, r["job_id"])
    assert st["status"] == "succeeded", st
    res = st["result"]
    assert res["match"] is False and res["sha256"] != res["sha256_read2"]
    assert any("다르다" in w for w in res["warnings"])
    d = case_dir(cid) / "dumps"
    assert (d / "esp-flash.bin").exists() and (d / "esp-flash.read2.bin").exists()
    meta = json.loads((d / "esp-flash.json").read_text(encoding="utf-8"))
    assert meta["verification"]["match"] is False


async def test_read_flash_secure_download_mode_fails_cleanly(fake):
    from esp_mcp.server import server

    cid = make_case()
    for version, size, port in ((None, "all", "COM3"), ("4.8.1", "64K", "/dev/ttyUSB0"), ("4.8.1", "all", "/dev/ttyUSB0")):
        fake.mode("sdm", version)
        n0 = len(fake.calls("read-flash"))
        async with Client(server) as c:
            r = await call(c, "esp_read_flash_start", case_id=cid, port=port, size=size)
            st = await _wait_job(c, r["job_id"])
        assert st["status"] == "failed", st
        assert st["error"]["code"] == "esp_secure_download_mode" and "우회" in st["error"]["hint"], (version, size, st["error"])
        assert sorted(p.name for p in (case_dir(cid) / "dumps").iterdir()) == []  # 예약 파일 모두 정리
        assert len(fake.calls("read-flash")) == n0 + 1
    audit = (case_dir(cid) / "audit.jsonl").read_text(encoding="utf-8")
    assert "esp_read_flash_failed" in audit


async def test_read_flash_digest_errors(fake, monkeypatch):
    """전송 MD5 불일치: 한 번 읽기면 파일을 남기지 않고, 이중 읽기의 2차에서 나면 1차 결과를 검증 없음으로 보존한다."""
    from esp_mcp.server import server

    cid = make_case()
    d = case_dir(cid) / "dumps"
    async with Client(server) as c:
        fake.mode("digest")
        r = await call(c, "esp_read_flash_start", case_id=cid, port="COM3", output_name="broken", verify="none")
        st = await _wait_job(c, r["job_id"])
        assert st["status"] == "failed" and st["error"]["code"] == "esp_digest_mismatch" and "baud" in st["error"]["hint"], st
        assert sorted(p.name for p in d.iterdir()) == []
        (fake.tmp / "fake.count").unlink(missing_ok=True)
        monkeypatch.setenv("FAKE_ESPTOOL_FAIL_CALL", "2")
        r = await call(c, "esp_read_flash_start", case_id=cid, port="COM3", output_name="half")
        st = await _wait_job(c, r["job_id"])
    assert st["status"] == "failed" and st["error"]["code"] == "esp_digest_mismatch", st
    res = st["result"]  # set_partial 로 남긴 부분 결과
    assert res["status"] == "failed" and res["path"] == "dumps/half.bin" and res["verification"]["method"] == "none"
    assert any("2차 읽기 실패" in n for n in res["notes"])
    assert sorted(p.name for p in d.iterdir()) == ["half.bin", "half.json"]
    meta = json.loads((d / "half.json").read_text(encoding="utf-8"))
    assert meta["status"] == "failed" and meta["verification"]["match"] is None


async def test_read_flash_cancel_first_read_removes_reservations(fake, monkeypatch):
    """취소: Windows esptool.exe(onefile)는 자식부터 끝내 부트로더가 _MEI 를 지우게 하고, 남은 프로세스가 없을 때만 cancelled."""
    from esp_mcp.server import server

    fake.mode("slow")
    monkeypatch.setenv("FAKE_ESPTOOL_DELAY", "0.3")
    cid = make_case()
    async with Client(server) as c:
        r = await call(c, "esp_read_flash_start", case_id=cid, port="COM3")
        for _ in range(200):
            if fake.pidfile.exists():
                break
            await anyio.sleep(0.05)
        pid = int(fake.pidfile.read_text())  # onefile 자식(실제 esptool)
        busy = await call(c, "esp_chip_info", case_id=cid, port="COM3")
        assert "_error" in busy and "busy" in busy["_error"], busy
        busy2 = await call(c, "esp_read_flash_start", case_id=cid, port="COM3")
        assert "_error" in busy2 and "busy" in busy2["_error"]
        await anyio.sleep(0.4)
        mid = await call(c, "esp_job_status", job_id=r["job_id"])
        assert mid["status"] == "running" and (mid["progress"] or 0) < 0.5, mid
        # 읽는 동안 dumps/ 에는 숨은 예약 파일만 있다 (최종 이름은 끝날 때 만든다)
        assert sorted(os.listdir(case_dir(cid) / "dumps")) == [".esp-flash.owner.partial", ".esp-flash.read1.partial",
                                                                 ".esp-flash.read2.partial"]
        owner = json.loads((case_dir(cid) / "dumps" / ".esp-flash.owner.partial").read_text())
        assert owner["pid"] == os.getpid() and owner["server"] == "esp-mcp" and owner["job_id"] == r["job_id"]
        cr = await call(c, "esp_job_cancel", job_id=r["job_id"])
        assert cr["ok"]
        st = await _wait_job(c, r["job_id"])
    assert st["status"] == "cancelled", st
    assert st["result"]["status"] == "cancelled" and "부분 데이터는 없다" in st["result"]["message"]
    assert "남은 것이 없음을 확인" in st["result"]["message"]
    assert not pid_alive(pid)  # 자식(PyInstaller child)까지 끝났다
    assert pid in fake.winprocs.terminated  # 자식을 먼저 끝냈다
    assert sorted(os.listdir(fake.mei)) == []  # 부트로더가 스스로 _MEI 를 지웠다 (부트로더를 죽이면 남는다)
    assert fake.winprocs.query("esptool.exe") == []
    assert sorted(p.name for p in (case_dir(cid) / "dumps").iterdir()) == []


async def test_read_flash_cancel_second_read_keeps_first(fake, monkeypatch):
    from esp_mcp.server import server

    fake.mode("slow")
    monkeypatch.setenv("FAKE_ESPTOOL_SLOW_CALL", "2")
    monkeypatch.setenv("FAKE_ESPTOOL_DELAY", "0.3")
    cid = make_case()
    async with Client(server) as c:
        r = await call(c, "esp_read_flash_start", case_id=cid, port="COM3")
        for _ in range(400):
            if len(fake.calls("read-flash")) >= 2:
                break
            await anyio.sleep(0.05)
        await anyio.sleep(0.5)
        await call(c, "esp_job_cancel", job_id=r["job_id"])
        st = await _wait_job(c, r["job_id"])
    assert st["status"] == "cancelled", st
    res = st["result"]
    assert res["status"] == "cancelled" and res["path"] == "dumps/esp-flash.bin" and res["verification"]["method"] == "none"
    assert res["read2_path"] is None and any("1차 읽기는 완료되어 보존" in n for n in res["notes"])
    d = case_dir(cid) / "dumps"
    assert sorted(p.name for p in d.iterdir()) == ["esp-flash.bin", "esp-flash.json"]
    assert fake.winprocs.query("esptool.exe") == [] and sorted(os.listdir(fake.mei)) == []


async def test_no_plain_no_reset_ever_reaches_esptool(fake):
    """어떤 after·no_stub·버전·백엔드 조합에서도 esptool 이 plain --after no-reset/no_reset 을 받지 않고 FLASH_BEGIN 이 없다."""
    from esp_mcp.server import server

    cid = make_case()
    async with Client(server) as c:
        for version in (None, "4.8.1"):
            fake.mode("normal", version)
            for port in ("COM3", "/dev/ttyACM0"):
                for after in ("hard-reset", "no-reset", "no-reset-stub", "watchdog-reset"):
                    for no_stub in (False, True):
                        r = await call(c, "esp_chip_info", case_id=cid, port=port, after=after, no_stub=no_stub,
                                       chip="esp32s3" if no_stub else "auto")
                        if after == "watchdog-reset" and version == "4.8.1":
                            assert "_error" in r and "v4.12" in r["_error"]
                            continue
                        assert r.get("ok"), (version, port, after, no_stub, r)
                        if after == "no-reset":
                            assert r["after"] == "no-reset-stub" and r["after_requested"] == "no-reset"
            for no_stub in (False, True):
                r = await call(c, "esp_read_flash_start", case_id=cid, port="COM3", after="no-reset", no_stub=no_stub, size="16K",
                               chip="esp32s3" if no_stub else "auto")
                st = await _wait_job(c, r["job_id"])
                assert st["status"] == "succeeded", st
    argvs = [x["argv"] for x in fake.calls() if "--after" in x["argv"]]
    assert argvs and all(_after_of(a) not in ("no-reset", "no_reset") for a in argvs)
    assert any(_after_of(a) == "no_reset_stub" for a in argvs) and any(_after_of(a) == "no-reset-stub" for a in argvs)
    assert not any(e["flash_begin"] for e in fake.ends())


async def test_after_no_reset_mapping_reported(fake):
    from esp_mcp.server import server

    cid = make_case()
    async with Client(server) as c:
        r = await call(c, "esp_chip_info", case_id=cid, port="COM3", after="no-reset", before="no-reset")
    assert r["ok"] and r["after"] == "no-reset-stub" and r["after_requested"] == "no-reset", r
    assert any("after='no-reset' 를 'no-reset-stub' 로 바꿔" in n and "FLASH_BEGIN" in n for n in r["notes"])
    assert "no-reset-stub" in r["classification"]["reason"] and _after_of(r["command"]) == "no-reset-stub"
    audit = (case_dir(cid) / "audit.jsonl").read_text(encoding="utf-8")
    assert '"after_requested": "no-reset"' in audit  # 게이트 action 에 매핑을 남김


async def test_soft_reset_refused_and_watchdog_versions(fake):
    from esp_mcp.server import server

    cid = make_case()
    async with Client(server) as c:
        r = await call(c, "esp_chip_info", case_id=cid, port="COM3", after="soft-reset")
        assert "_error" in r and "validation_failed" in r["_error"] and "FLASH_BEGIN" in r["_error"]
        fake.mode("normal", "4.12.0")
        r = await call(c, "esp_chip_info", case_id=cid, port="/dev/ttyACM0", after="watchdog-reset")
        assert r["ok"] and r["after"] == "watchdog-reset", r
        assert _after_of(fake.calls("flash-id")[-1]["argv"]) == "watchdog_reset"
        fake.mode("normal", "4.8.1")
        r = await call(c, "esp_chip_info", case_id=cid, port="/dev/ttyACM0", after="watchdog-reset")
        assert "_error" in r and "v4.12" in r["_error"]
    assert not any(_after_of(x["argv"]) in ("soft-reset", "soft_reset") for x in fake.calls() if "--after" in x["argv"])


async def test_manual_download_mode_double_read_reconnects_to_stub(fake, monkeypatch):
    """수동 다운로드 모드(before='no-reset') 이중 읽기: 1차는 115200 + no-reset-stub → 2차 연결이 실행 중인 스텁을 찾는다."""
    from esp_mcp.server import server

    monkeypatch.setenv("FAKE_ESPTOOL_CHIPSTATE", str(fake.tmp / "chip.json"))  # 칩은 사람이 BOOT+RESET 으로 ROM 다운로드 모드
    cid = make_case()
    async with Client(server) as c:
        r = await call(c, "esp_read_flash_start", case_id=cid, port="COM3", before="no-reset")
        assert r["read1_baud"] == 115200 and any("115200" in n for n in r["notes"]), r
        st = await _wait_job(c, r["job_id"])
    assert st["status"] == "succeeded", st
    a1, a2 = (x["argv"] for x in fake.calls("read-flash"))
    assert _opt(a1, "--baud") == "115200" and _after_of(a1) == "no-reset-stub" and _opt(a1, "--before") == "no-reset"
    assert _opt(a2, "--baud") == "921600" and _after_of(a2) == "hard-reset" and _opt(a2, "--before") == "no-reset"
    e1, e2 = fake.ends("read-flash")
    assert e1["stub"] and not e1["stub_reused"] and e2["stub_reused"]  # 2차는 남아 있던 스텁에 다시 연결
    assert any("115200" in n for n in st["result"]["notes"]) and "115200 baud" in st["result"]["verification"]["detail"]
    assert st["result"]["match"] is True


async def test_double_read_without_autoreset_explains_read2_failure(fake, monkeypatch):
    """자동 리셋이 없는 보드에 before='default-reset': 1차 뒤 스텁이 921600 에 남아 2차 동기화 실패 → 1차 보존 + 수동 모드 안내."""
    from esp_mcp.server import server

    monkeypatch.setenv("FAKE_ESPTOOL_CHIPSTATE", str(fake.tmp / "chip.json"))
    monkeypatch.setenv("FAKE_ESPTOOL_NO_AUTORESET", "1")
    cid = make_case()
    async with Client(server) as c:
        st = await _wait_job(c, (await call(c, "esp_read_flash_start", case_id=cid, port="COM3"))["job_id"])
    assert st["status"] == "failed" and st["error"]["code"] == "esp_no_serial_data", st
    res = st["result"]
    assert res["path"] == "dumps/esp-flash.bin" and res["verification"]["method"] == "none"
    assert any("2차 연결 실패" in n and "before='no-reset'" in n for n in res["notes"])


async def test_foreign_config_aborts_before_connect(fake, monkeypatch):
    """서버가 만든 설정이 아닌 esptool 설정을 읽으면 연결(리셋) 전에 멈추고 esp_foreign_config."""
    from esp_mcp.server import server

    mark = fake.tmp / "connect.mark"
    monkeypatch.setenv("FAKE_ESPTOOL_FOREIGN_CFG", "C:\\Users\\u\\AppData\\Local\\esptool\\esptool.cfg")
    monkeypatch.setenv("FAKE_ESPTOOL_CONNECT_MARK", str(mark))
    cid = make_case()
    async with Client(server) as c:
        for port in ("COM3", "/dev/ttyACM0"):
            t0 = time.monotonic()
            r = await call(c, "esp_chip_info", case_id=cid, port=port)
            assert "[esp_foreign_config]" in r["_error"] and "AppData" in r["_error"], r
            assert time.monotonic() - t0 < 8
        st = await _wait_job(c, (await call(c, "esp_read_flash_start", case_id=cid, port="COM3"))["job_id"])
    assert st["status"] == "failed" and st["error"]["code"] == "esp_foreign_config", st
    assert not mark.exists()  # 연결 단계에 들어가기 전에 끝냈다
    assert sorted(os.listdir(case_dir(cid) / "dumps")) == [] and fake.winprocs.query("esptool.exe") == []


async def test_windows_onefile_timeout_and_orphan_handling(fake, monkeypatch):
    """시간 초과: 자식부터 끝내 남은 프로세스·_MEI 가 없다. Windows 프로세스를 끝내지 못하면 PID 를 담은 오류, 다음 호출은 busy."""
    from esp_mcp.server import server

    fake.mode("hang")
    cid = make_case()
    async with Client(server) as c:
        r = await call(c, "esp_chip_info", case_id=cid, port="COM3", timeout_s=5)
        assert "[timeout]" in r["_error"], r
        assert fake.winprocs.query("esptool.exe") == [] and sorted(os.listdir(fake.mei)) == []
        # Windows 쪽 종료가 막힌 경우(접근 거부 흉내): 자식이 남는다 → esp_orphan_process(PID)
        fake.pidfile.unlink(missing_ok=True)
        fake.winprocs.deny = True
        r = await call(c, "esp_chip_info", case_id=cid, port="COM3", timeout_s=5)
        assert "[esp_orphan_process]" in r["_error"], r
        child = int(fake.pidfile.read_text())
        assert str(child) in r["_error"] and pid_alive(child) and "taskkill" in r["_error"]
        fake.winprocs.deny = False
        # 남은 esptool.exe 가 COM3 을 잡고 있으면 busy — 사용 중 확인은 버전 확인(esptool 실행)보다 먼저라, 버전 확인이 실패하는
        # 상태(해석할 수 없는 버전 출력)에서도 busy 가 가려지지 않는다
        fake.mode("normal", version="not-a-version")
        r = await call(c, "esp_chip_info", case_id=cid, port="COM3")
        assert "[busy]" in r["_error"] and str(child) in r["_error"], r
        fake.mode("normal")
        os.kill(child, signal.SIGKILL)
        assert wait_until(lambda: not pid_alive(child), 5)
        r = await call(c, "esp_chip_info", case_id=cid, port="COM3")
        assert r["ok"], r


async def test_read_flash_orphan_keeps_reservation_until_gone(fake, monkeypatch):
    """덤프 취소 때 Windows 자식이 남으면 cancelled 대신 PID 를 담은 오류, 예약 파일은 그 프로세스가 사라질 때까지 남긴다."""
    from esp_mcp import server as srv
    from esp_mcp.server import server

    fake.mode("slow")
    monkeypatch.setenv("FAKE_ESPTOOL_DELAY", "0.3")
    cid = make_case()
    dumps = case_dir(cid) / "dumps"
    async with Client(server) as c:
        r = await call(c, "esp_read_flash_start", case_id=cid, port="COM3", verify="none")
        assert wait_until(fake.pidfile.exists, 10)
        child = int(fake.pidfile.read_text())
        fake.winprocs.deny = True
        await call(c, "esp_job_cancel", job_id=r["job_id"])
        st = await _wait_job(c, r["job_id"])
    assert st["status"] == "failed" and st["error"]["code"] == "esp_orphan_process", st
    assert str(child) in st["error"]["message"]
    left = sorted(os.listdir(dumps))
    assert left == [".esp-flash.owner.partial", ".esp-flash.read1.partial"], left
    owner = json.loads((dumps / ".esp-flash.owner.partial").read_text())
    assert child in owner["windows_pids"]
    fake.winprocs.deny = False
    assert srv._sweep_dumps_dir(dumps.resolve(), cid) == []  # 남은 프로세스가 살아 있는 동안은 지우지 않는다
    os.kill(child, signal.SIGKILL)
    assert wait_until(lambda: not pid_alive(child), 5)
    removed = srv._sweep_dumps_dir(dumps.resolve(), cid)
    assert removed and removed[0]["stem"] == "esp-flash" and sorted(os.listdir(dumps)) == []


async def test_windows_output_tokens_recorded_before_first_spawn(fake, monkeypatch):
    """Windows 백엔드 덤프는 첫 esptool.exe 를 띄우기 전에 출력 UNC 경로(windows_tokens)·이미지 이름을 소유 표식에 적는다 (리눅스 백엔드는 적지 않음)."""
    from esp_mcp import server as srv
    from esp_mcp.server import server

    seen: list[dict] = []
    real_run = srv.run_streaming

    def spy(argv, **kw):
        if "read-flash" in [a.replace("_", "-") for a in argv]:
            owners = list((case_dir(cid) / "dumps").glob(".*.owner.partial"))
            seen.append({"argv": list(argv), "owner": json.loads(owners[0].read_text()) if owners else None})
        return real_run(argv, **kw)

    monkeypatch.setattr(srv, "run_streaming", spy)
    cid = make_case()
    async with Client(server) as c:
        st = await _wait_job(c, (await call(c, "esp_read_flash_start", case_id=cid, port="COM3", size="16K"))["job_id"])
        assert st["status"] == "succeeded", st
        assert len(seen) == 2
        tokens = [srv_argv[-1] for srv_argv in (x["argv"] for x in seen)]
        for x in seen:
            assert x["owner"]["windows_tokens"] == tokens and x["owner"]["windows_images"] == ["esptool.exe"], x
            assert x["owner"]["pid"] == os.getpid()
        assert all(t.startswith("\\\\wsl.localhost\\") and t.endswith(".partial") for t in tokens), tokens
        seen.clear()
        st = await _wait_job(c, (await call(c, "esp_read_flash_start", case_id=cid, port="/dev/ttyACM0", size="16K",
                                            verify="none"))["job_id"])
        assert st["status"] == "succeeded", st
        assert len(seen) == 1 and "windows_tokens" not in seen[0]["owner"], seen


def test_sweep_keeps_reservation_written_by_orphan_after_server_kill(fake, monkeypatch):
    """서버가 SIGKILL 로 죽어 windows_pids 를 적지 못해도, 명령줄에 예약 경로가 있는 esptool.exe 가 살아 있으면 정리하지 않는다.

    (검증에서 찾은 문제: 재시작한 서버가 남은 PyInstaller 자식이 아직 쓰는 .partial 을 지웠다.) powershell 조회가 실패해도 지우지 않는다.
    """
    from esp_mcp import server as srv
    from esp_mcp import winproc

    cid = make_case()
    dumps = Path(os.path.realpath(case_dir(cid) / "dumps"))
    dead = subprocess.Popen(["true"])
    dead.wait()
    read1 = dumps / ".k.read1.partial"
    read1.write_bytes(b"partial data")
    token = fake_unc(read1)
    base = {"server": "esp-mcp", "host": socket.gethostname(), "boot_id": srv._boot_id(), "pid": dead.pid, "start_ticks": 1}
    (dumps / ".k.owner.partial").write_text(json.dumps({**base, "windows_tokens": [token], "windows_images": ["esptool.exe"]}))
    monkeypatch.setenv("FAKE_ESPTOOL_MODE", "hang")
    orphan = subprocess.Popen([str(fake.win), "--chip", "esp32s3", "--port", "COM3", "--baud", "921600", "--before", "default-reset",
                               "--after", "no-reset-stub", "read-flash", "0x0", "0x1000", token],
                              stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        assert wait_until(lambda: len(fake.winprocs.query("esptool.exe")) == 2, 10)  # 부트로더 + 자식
        assert srv._reservation_state(dumps / ".k.owner.partial")[0] == "held"
        assert srv._sweep_dumps_dir(dumps, cid) == []
        assert sorted(os.listdir(dumps)) == [".k.owner.partial", ".k.read1.partial"]
        assert srv._startup_sweep()["removed"] == 0 and read1.exists()

        def broken(image):
            raise RuntimeError("powershell.exe 없음")

        monkeypatch.setattr(winproc, "query", broken)
        assert srv._reservation_state(dumps / ".k.owner.partial")[0] == "held"  # 확인 불가 → 지우지 않음
        monkeypatch.setattr(winproc, "query", fake.winprocs.query)
    finally:
        kill_fake_processes()
        orphan.wait(10)
    assert wait_until(lambda: fake.winprocs.query("esptool.exe") == [], 5)
    removed = srv._sweep_dumps_dir(dumps, cid)
    assert [r["stem"] for r in removed] == ["k"] and sorted(os.listdir(dumps)) == []


def test_kill_all_live_stops_windows_children(fake, monkeypatch):
    """서버 종료(atexit) 정리도 Windows esptool.exe 를 자식부터 끝낸다."""
    from esp_mcp import esptool_cli
    from esp_mcp.esptool_cli import OutputCollector, info_win_match, prepare_run_dir, run_streaming

    monkeypatch.setenv("FAKE_ESPTOOL_MODE", "hang")
    rd = fake.tmp / "run"
    rd.mkdir()
    prepare_run_dir(rd)
    argv = [str(fake.win), "--chip", "auto", "--port", "COM3", "--baud", "115200", "--before", "default-reset", "--after", "hard-reset",
            "--connect-attempts", "7", "flash-id"]
    out: dict = {}
    th = threading.Thread(target=lambda: out.setdefault("res", run_streaming(
        argv, timeout=60, on_text=OutputCollector().feed, cwd=rd, env=esptool_cli.child_env(windows=True, run_dir=rd),
        win_match=info_win_match(str(fake.win), "COM3", "flash-id", 5))))
    th.start()
    assert wait_until(lambda: fake.pidfile.exists() and len(fake.winprocs.query("esptool.exe")) == 2, 10)
    child = int(fake.pidfile.read_text())
    esptool_cli._kill_all_live()
    th.join(20)
    assert not th.is_alive() and not pid_alive(child) and fake.winprocs.query("esptool.exe") == []
    assert child in fake.winprocs.terminated and sorted(os.listdir(fake.mei)) == []


async def test_finals_created_exclusively_never_overwrite_evidence(fake, monkeypatch):
    """최종 파일은 끝날 때 O_EXCL 로 만든다: 덤프 도중 같은 이름이 생기면 덮어쓰지 않고 <name>-<job_id> 로 저장."""
    from esp_mcp.server import server

    fake.mode("slow")
    monkeypatch.setenv("FAKE_ESPTOOL_DELAY", "0.15")
    cid = make_case()
    dumps = case_dir(cid) / "dumps"
    async with Client(server) as c:
        r = await call(c, "esp_read_flash_start", case_id=cid, port="COM3", verify="none", size="64K")
        assert wait_until(lambda: (dumps / ".esp-flash.read1.partial").exists(), 10)
        assert not (dumps / "esp-flash.bin").exists() and not (dumps / "esp-flash.json").exists()
        (dumps / "esp-flash.bin").write_bytes(b"other evidence")
        st = await _wait_job(c, r["job_id"])
    assert st["status"] == "succeeded", st
    res = st["result"]
    jid = r["job_id"]
    assert res["path"] == f"dumps/esp-flash-{jid}.bin" and res["metadata_path"] == f"dumps/esp-flash-{jid}.json"
    assert (dumps / "esp-flash.bin").read_bytes() == b"other evidence"
    assert any("덮어쓰지 않음" in w for w in res["warnings"])
    assert sorted(os.listdir(dumps)) == sorted(["esp-flash.bin", f"esp-flash-{jid}.bin", f"esp-flash-{jid}.json"])


async def test_stale_reservations_swept_and_abandoned_jobs_marked(fake):
    """서버 시작 정리: 주인 프로세스가 죽은 예약·소유 표식 없는 예약을 지우고, 죽은 프로세스의 'running' 작업 기록을 abandoned 로."""
    from esp_mcp import server as srv

    cid = make_case()
    cdir = case_dir(cid)
    dumps = cdir / "dumps"
    dead = subprocess.Popen(["true"])
    dead.wait()
    live = subprocess.Popen(["sleep", "60"])
    try:
        base = {"server": "esp-mcp", "host": socket.gethostname(), "boot_id": srv._boot_id()}
        (dumps / ".old.owner.partial").write_text(json.dumps({**base, "pid": dead.pid, "start_ticks": 1}))
        (dumps / ".old.read1.partial").write_bytes(b"x" * 10)
        (dumps / ".old.read2.partial").write_bytes(b"")
        (dumps / ".noowner.read1.partial").write_bytes(b"")
        (dumps / ".live.owner.partial").write_text(json.dumps({**base, "pid": live.pid, "start_ticks": srv._proc_stat(live.pid)[1]}))
        (dumps / ".live.read1.partial").write_bytes(b"")
        (dumps / "keep.bin").write_bytes(b"evidence")
        (dumps / ".unrelated.part").write_bytes(b"uart dump state")
        jobs = cdir / "jobs"
        for jid, owner_pid, server_name in (("job-dead", dead.pid, "esp-mcp"), ("job-live", live.pid, "esp-mcp"),
                                            ("job-uart", dead.pid, "uart-mcp")):
            owner = {**base, "pid": owner_pid, "start_ticks": srv._proc_stat(owner_pid)[1] if owner_pid == live.pid else 1}
            (jobs / f"{jid}.json").write_text(json.dumps({"job_id": jid, "server": server_name, "status": "running",
                                                          "meta": {"owner": owner}}))
        out = srv._startup_sweep()
        assert out["removed"] == 2 and out["abandoned"] == ["job-dead"], out
        assert sorted(os.listdir(dumps)) == [".live.owner.partial", ".live.read1.partial", ".unrelated.part", "keep.bin"]
        st = {p.stem: json.loads(p.read_text())["status"] for p in jobs.glob("*.json")}
        assert st == {"job-dead": "abandoned", "job-live": "running", "job-uart": "running"}
        audit = (cdir / "audit.jsonl").read_text(encoding="utf-8")
        assert "esp_stale_reservations_removed" in audit and "esp_jobs_abandoned" in audit
    finally:
        live.kill()
        live.wait()


def test_owner_update_after_release_does_not_recreate_reservation(fake):
    """작업이 이미 예약을 풀었으면(즉시 실패 등) 시작 직후의 job_id 갱신이 소유 표식을 다시 만들지 않는다."""
    from esp_mcp import server as srv

    cid = make_case()
    dumps = Path(os.path.realpath(case_dir(cid) / "dumps"))
    stem, partials, owner = srv._reserve_dump(dumps, "x", 1)
    srv._update_owner(owner, only_if_active=True, job_id="job-1")
    assert json.loads(owner.read_text())["job_id"] == "job-1"
    with srv._RESERVE_LOCK:
        for p in partials:
            srv._unlink(p)
        srv._unlink(owner)
        srv._ACTIVE_RESERVATIONS.discard(str(owner))
    srv._update_owner(owner, only_if_active=True, job_id="job-2")
    assert sorted(os.listdir(dumps)) == []


def _plan_for(srv, cid, backend, spec, argv_for, *, name="t"):
    """워커 단위 테스트용 계획 (esp_read_flash_start 와 같은 예약·경로)."""
    from pweh.runtime import get_runtime

    case = get_runtime("esp-mcp").cases.get(cid)
    dumps = case.subdir("dumps")
    real = Path(os.path.realpath(dumps))
    stem, partials, owner = srv._reserve_dump(real, name, 1)
    argv, omap = argv_for(partials[0])
    step = srv.ReadStep(index=1, after="hard-reset", baud=115200, timeout_s=30, partial=partials[0], argv=argv, output_token=argv[-1],
                        output_map=omap)
    return srv.DumpPlan(case_id=cid, case_dir=case.dir, case_real=os.path.realpath(case.dir), dumps_dir=dumps, dumps_real=str(real),
                        stem=stem, owner_path=owner, port=spec, backend=backend, chip="auto", baud=115200, before="default-reset",
                        after="hard-reset", after_requested="hard-reset", no_stub=False, offset=0, size=4096, verify="none",
                        steps=[step], exclusive_key=srv._port_key(spec))


class _J:
    cancelled = False
    job = SimpleNamespace(id="job-test")

    def log(self, m):
        pass

    def update_meta(self, **k):
        pass

    def progress(self, *a, **k):
        pass

    def set_partial(self, r):
        pass


def test_job_worker_rechecks_argv_and_authorization(fake):
    """백그라운드 읽기는 실행 직전마다 argv 를 다시 분류하고 소유/허가 증명을 다시 확인한다."""
    from esp_mcp import ports
    from esp_mcp import server as srv
    from pweh.errors import AuthorizationRequired, SafetyDenied
    from pweh.runtime import get_runtime

    cid = make_case()
    case = get_runtime("esp-mcp").cases.get(cid)
    dumps = case.subdir("dumps")
    spec = ports.validate_port("COM3")
    backend = srv.Backend(name="windows", exe=str(fake.win), source="config", version="5.4.0", major=5, minor=4)
    head = [str(fake.win), "--chip", "auto", "--port", "COM3", "--baud", "115200", "--before", "default-reset", "--after", "hard-reset",
            "--connect-attempts", "7"]

    def tampered(part):
        return head + ["write-flash", "0x0", str(part)], {}

    def outside(part):
        return head + ["read-flash", "0x0", "0x1000", "\\\\wsl.localhost\\Ubuntu\\etc\\x"], {"\\\\wsl.localhost\\Ubuntu\\etc\\x": "/etc/x"}

    def ok(part):
        return head + ["read-flash", "0x0", "0x1000", fake_unc(part)], {fake_unc(part): str(part)}

    with pytest.raises(SafetyDenied):
        srv._read_flash_worker(_plan_for(srv, cid, backend, spec, tampered), _J())
    with pytest.raises(SafetyDenied):
        srv._read_flash_worker(_plan_for(srv, cid, backend, spec, outside), _J())
    meta = json.loads(case.meta_path.read_text(encoding="utf-8"))
    meta["authorization"] = None
    case.meta_path.write_text(json.dumps(meta), encoding="utf-8")
    with pytest.raises(AuthorizationRequired):
        srv._read_flash_worker(_plan_for(srv, cid, backend, spec, ok), _J())
    assert fake.calls("read-flash") == [] and fake.calls("write-flash") == []
    assert sorted(p.name for p in dumps.iterdir()) == []  # 예약(소유 표식 포함)도 정리


def test_worker_refuses_symlinked_dumps(fake):
    """실행 직전 재확인: dumps/ 가 심볼릭 링크로 바뀌면(계획 때 realpath 와 다름) esptool 을 띄우지 않고 거부한다."""
    from esp_mcp import ports
    from esp_mcp import server as srv
    from pweh.errors import SafetyDenied

    cid = make_case()
    cdir = case_dir(cid)
    spec = ports.validate_port("/dev/ttyACM0")
    backend = srv.Backend(name="linux", exe=str(fake.lin), source="config", version="5.4.0", major=5, minor=4)
    head = [str(fake.lin), "--chip", "auto", "--port", "/dev/ttyACM0", "--baud", "115200", "--before", "default-reset", "--after",
            "hard-reset", "--connect-attempts", "7"]
    plan = _plan_for(srv, cid, backend, spec, lambda part: (head + ["read-flash", "0x0", "0x1000", str(part)], {str(part): str(part)}))
    elsewhere = fake.tmp / "elsewhere"
    elsewhere.mkdir()
    (cdir / "dumps").rename(cdir / "dumps.moved")
    os.symlink(elsewhere, cdir / "dumps")
    with pytest.raises(SafetyDenied, match="심볼릭 링크"):
        srv._read_flash_worker(plan, _J())
    assert fake.calls("read-flash") == [] and sorted(os.listdir(elsewhere)) == []
    # 같은 이름의 새 디렉터리로 바뀐 경우(realpath 는 같음)도 예약 파일 확인으로 거부
    os.unlink(cdir / "dumps")
    (cdir / "dumps.moved").rename(cdir / "dumps.orig")
    (cdir / "dumps").mkdir()
    plan.steps[0].partial.parent.mkdir(exist_ok=True)
    with pytest.raises(SafetyDenied):
        srv._recheck_dump_paths(plan, plan.steps[0])


async def test_linux_port_held_by_other_process_is_refused(fake, monkeypatch):
    from esp_mcp import ports
    from esp_mcp.server import server

    monkeypatch.setattr(ports, "device_users", lambda p: [31337])
    cid = make_case()
    async with Client(server) as c:
        r = await call(c, "esp_chip_info", case_id=cid, port="/dev/ttyACM0")
    assert "_error" in r and "31337" in r["_error"] and "busy" in r["_error"]
    assert fake.calls("flash-id") == []


async def test_windows_port_held_by_orphan_esptool_is_refused(fake, monkeypatch):
    """그 COM 포트를 인자로 받은 esptool.exe 가 Windows 에 남아 있으면 busy(PID + 정리 방법)."""
    from esp_mcp.server import server

    env = dict(os.environ, FAKE_ESPTOOL_MODE="hang", FAKE_ESPTOOL_ONEFILE="0")
    orphan = subprocess.Popen([str(fake.win), "--chip", "auto", "--port", "COM3", "--baud", "921600", "--before", "default-reset",
                               "--after", "no-reset-stub", "--connect-attempts", "7", "read-flash", "0x0", "ALL", "x"],
                              stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, env=env, start_new_session=True)
    try:
        assert wait_until(lambda: len(fake.winprocs.query("esptool.exe")) == 1, 10)
        cid = make_case()
        async with Client(server) as c:
            r = await call(c, "esp_chip_info", case_id=cid, port="COM3")
            assert "[busy]" in r["_error"] and str(orphan.pid) in r["_error"] and "taskkill" in r["_error"], r
            r = await call(c, "esp_read_flash_start", case_id=cid, port="COM3")
            assert "[busy]" in r["_error"] and str(orphan.pid) in r["_error"]
            r = await call(c, "esp_chip_info", case_id=cid, port="COM4")  # 다른 포트는 괜찮다
            assert r["ok"], r
        assert fake.calls("flash-id")[-1]["argv"][3] == "COM4"
    finally:
        orphan.kill()
        orphan.wait()


async def test_gate_approve_policy_and_retry(fake):
    from esp_mcp.server import server
    from pweh.runtime import get_runtime

    fake.workspace["set_safety"](modify_policy="approve", approval_methods=["cli"])
    cid = make_case()
    async with Client(server) as c:
        r = await call(c, "esp_read_flash_start", case_id=cid, port="COM3", size="64K", verify="none")
        assert r["ok"] is False and r["status"] == "approval_required" and r["approval_id"], r
        assert fake.calls("read-flash") == [] and sorted(p.name for p in (case_dir(cid) / "dumps").iterdir()) == []
        rt = get_runtime("esp-mcp")
        ap = r["approval_id"]
        rt.approvals.decide(ap, approve=True, code=rt.approvals.get(ap)["code"], via="test")
        r2 = await call(c, "esp_read_flash_start", case_id=cid, port="COM3", size="64K", verify="none", approval_id=ap)
        assert r2["ok"] and r2["status"] == "started", r2
        st = await _wait_job(c, r2["job_id"])
        assert st["status"] == "succeeded"
        ci = await call(c, "esp_chip_info", case_id=cid, port="COM3")
        assert ci["status"] == "approval_required" and ci["gate"]["classification"]["rule_id"] == "esp.info.flash-id"
    fake.workspace["set_safety"](modify_policy="deny")
    async with Client(server) as c:
        d = await call(c, "esp_security_info", case_id=cid, port="COM3")
        assert d["status"] == "denied" and "modify_policy" in d["message"]


async def test_destructive_argv_never_reaches_gate(fake, monkeypatch):
    """서버가 만든 argv 가 (버그로) 쓰기 명령이 되어도 게이트/승인 없이 바로 거부되고 esptool 은 실행되지 않는다."""
    from esp_mcp import server as srv
    from esp_mcp.server import server

    fake.workspace["set_safety"](destructive_policy="approve", approval_methods=["cli"])
    real_build = srv.build_argv

    def evil_build(exe, **kw):
        kw["command"] = "write-flash"
        kw["args"] = ["0x0", "/tmp/evil.bin"]
        return real_build(exe, **kw)

    monkeypatch.setattr(srv, "build_argv", evil_build)
    cid = make_case()
    async with Client(server) as c:
        r = await call(c, "esp_chip_info", case_id=cid, port="COM3")
        assert r["ok"] is False and r["status"] == "denied" and r["gate"]["via"] == "esp-policy", r
        assert "approval_id" not in r and r["gate"]["classification"]["rule_id"] == "esp.cmd.flash-write"
        r = await call(c, "esp_read_flash_start", case_id=cid, port="COM3")
        assert r["status"] == "denied" and r["gate"]["via"] == "esp-policy"
    assert fake.calls("write-flash") == [] and not any(e["argv"][-1:] != ["version"] for e in fake.calls())
    assert sorted(os.listdir(case_dir(cid) / "dumps")) == []


async def test_verification_detail_no_stub(fake):
    """--no-stub(ROM 직접 읽기)에는 스텁 전송 MD5 검증이 없다 — detail 이 그렇게 적는다."""
    from esp_mcp.server import server

    cid = make_case()
    async with Client(server) as c:
        st = await _wait_job(c, (await call(c, "esp_read_flash_start", case_id=cid, port="COM3", chip="esp32s3", size="16K",
                                            no_stub=True))["job_id"])
        st1 = await _wait_job(c, (await call(c, "esp_read_flash_start", case_id=cid, port="COM3", chip="esp32s3", size="16K", no_stub=True,
                                             verify="none"))["job_id"])
    detail = st["result"]["verification"]["detail"]
    assert "ROM 직접 읽기(--no-stub): 전송 MD5 검증 없음" in detail and "스텁은 읽기마다" not in detail, detail
    d1 = st1["result"]["verification"]["detail"]
    assert "ROM 직접 읽기(--no-stub): 전송 MD5 검증 없음" in d1 and "스텁의 전송 MD5" not in d1


async def test_no_stub_with_esp8266_or_auto_never_reaches_esptool(fake):
    """no_stub=True + chip auto/esp8266 은 모든 기기 도구에서 validation_failed — esptool 을 띄우지 않는다 (v5·v4).

    실행된 모든 기기 argv 를 모아 --no-stub 과 --chip esp8266|auto 가 함께 나오지 않음을 확인한다. chip 을 명시하면 no_stub 이 동작한다.
    """
    from esp_mcp.server import server

    cid = make_case()
    tools = (("esp_chip_info", {}), ("esp_security_info", {}), ("esp_read_flash_start", {"size": "16K", "verify": "none"}))
    async with Client(server) as c:
        for version in (None, "4.8.1"):
            fake.mode("v4" if version else "normal", version)
            for tool, extra in tools:
                for chip in ("auto", "esp8266", "ESP8266", "Auto"):
                    n0 = len(fake.calls())
                    r = await call(c, tool, case_id=cid, port="COM3", chip=chip, no_stub=True, **extra)
                    assert "[validation_failed]" in r.get("_error", ""), (version, tool, chip, r)
                    assert "ESP8266 이 아닌 칩" in r["_error"]
                    assert len(fake.calls()) == n0, (version, tool, chip)  # esptool 을 띄우지 않음
                for no_stub in (False, True):
                    r = await call(c, tool, case_id=cid, port="COM3", chip="esp32s3", no_stub=no_stub, **extra)
                    assert r.get("ok") is True, (version, tool, no_stub, r)
                    if r.get("job_id"):
                        st = await _wait_job(c, r["job_id"])
                        assert st["status"] == "succeeded", st
                r = await call(c, tool, case_id=cid, port="COM3", chip="auto", **extra)  # 스텁(기본)이면 auto 그대로
                assert r.get("ok") is True, (version, tool, r)
                if r.get("job_id"):
                    await _wait_job(c, r["job_id"])
    device = [e["argv"] for e in fake.calls() if "--port" in e["argv"]]
    assert device
    for argv in device:
        chip = _opt(argv, "--chip")
        assert not ("--no-stub" in argv and chip in ("auto", "esp8266")), argv
    assert any("--no-stub" in a and _opt(a, "--chip") == "esp32s3" for a in device)


async def test_esp_mcp_stdio(fake):
    env = {"PWEH_CONFIG": str(fake.workspace["config"]), "PWEH_ESPTOOL": str(fake.lin), "PWEH_ESPTOOL_WIN": str(fake.win),
           "FAKE_ESPTOOL_LOG": str(fake.log), "FAKE_ESPTOOL_MODE": "normal"}
    params = stdio_params("esp_mcp", env=env)
    async with Client(params, read_timeout_seconds=60) as c:
        tools = {t.name for t in (await c.list_tools()).tools}
        assert {"esp_version", "esp_read_flash_start", "esp_job_status"} <= tools
        v = await call(c, "esp_version")
        assert v["ok"] and v["backends"]["linux"]["version"] == "5.4.0"


_SHIM = """import os
try:
    from esp_mcp import ports as _p
    _p.path_exists = lambda p: True
    _p.realpath = lambda p: p
    _p.device_users = lambda p: []
except Exception as e:  # pragma: no cover
    import sys
    print("shim failed", e, file=sys.stderr)
"""


@pytest.mark.parametrize("how", ["sigterm", "stdin-close"])
def test_server_exit_cancels_job_and_cleans_reservations(fake, tmp_path, how):
    """서버가 덤프 도중 끝나도(SIGTERM / stdin 닫힘) 작업을 취소해 esptool 을 끝내고 예약 파일을 지우며 작업 기록은 cancelled."""
    shim = tmp_path / "shim"
    shim.mkdir()
    (shim / "sitecustomize.py").write_text(_SHIM)
    cid = make_case()
    pidfile = tmp_path / "srv-fake.pid"
    env = dict(os.environ)
    env.update({"PWEH_CONFIG": str(fake.workspace["config"]), "PWEH_ESPTOOL": str(fake.lin), "FAKE_ESPTOOL_MODE": "slow",
                "FAKE_ESPTOOL_DELAY": "0.25", "FAKE_ESPTOOL_PIDFILE": str(pidfile), "FAKE_ESPTOOL_LOG": str(fake.log),
                "PYTHONPATH": os.pathsep.join([str(shim), str(REPO / "mcp-servers" / "esp-mcp"), str(REPO / "src")])})
    py = str(REPO / ".venv" / "bin" / "python") if (REPO / ".venv" / "bin" / "python").exists() else sys.executable
    srvp = subprocess.Popen([py, "-m", "esp_mcp"], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, env=env,
                            cwd=str(REPO))

    def send(obj):
        srvp.stdin.write((json.dumps(obj) + "\n").encode())
        srvp.stdin.flush()

    def recv(want):
        while True:
            line = srvp.stdout.readline()
            if not line:
                raise AssertionError("server closed")
            msg = json.loads(line)
            if msg.get("id") == want:
                return msg

    try:
        send({"jsonrpc": "2.0", "id": 1, "method": "initialize",
              "params": {"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "t", "version": "0"}}})
        recv(1)
        send({"jsonrpc": "2.0", "method": "notifications/initialized"})
        send({"jsonrpc": "2.0", "id": 2, "method": "tools/call",
              "params": {"name": "esp_read_flash_start", "arguments": {"case_id": cid, "port": "/dev/ttyACM0"}}})
        res = recv(2)["result"]
        data = res.get("structuredContent") or json.loads(res["content"][0]["text"])
        assert data["status"] == "started", data
        assert wait_until(lambda: pidfile.exists() and pidfile.read_text().strip(), 20)
        pid = int(pidfile.read_text())
        time.sleep(0.5)
        if how == "sigterm":
            srvp.send_signal(signal.SIGTERM)
        else:
            srvp.stdin.close()
        srvp.wait(60)
        assert srvp.returncode == (-signal.SIGTERM if how == "sigterm" else 0)
        assert wait_until(lambda: not pid_alive(pid), 10)
        assert sorted(os.listdir(case_dir(cid) / "dumps")) == []  # 숨은 예약도 남지 않음
        jobs = sorted((case_dir(cid) / "jobs").glob("*.json"))
        assert jobs and json.loads(jobs[-1].read_text())["status"] == "cancelled"
    finally:
        if srvp.poll() is None:
            srvp.kill()
            srvp.wait()
        for s in (srvp.stdout,):
            s.close()


# ---------------------------------------------------------------------------
# 실제 Windows esptool.exe (WSL interop) — 기기 없이
# ---------------------------------------------------------------------------


@pytest.mark.external
async def test_real_windows_esptool_version(workspace, monkeypatch):
    from esp_mcp.esptool_cli import clear_cache
    from esp_mcp.server import server
    from pweh.runtime import reset_runtimes

    exe = real_windows_esptool()
    if not exe:
        pytest.skip("Windows esptool.exe 또는 WSL interop 이 없음")
    monkeypatch.setenv("PWEH_ESPTOOL_WIN", exe)
    reset_runtimes()
    clear_cache()
    async with Client(server) as c:
        v = await call(c, "esp_version")
    w = v["backends"]["windows"]
    assert w["available"] and w["version"] == "5.4.0" and w["major"] == 5 and w["interop"] is True, w
    assert v["recommended"] == "windows"


@pytest.mark.external
def test_real_windows_esptool_writes_into_case_via_wslpath(workspace, tmp_path):
    """방법 A 경로 처리 (기기 없이): 케이스 dumps/ 경로를 서버의 to_windows_path 로 바꿔 실제 esptool.exe merge-bin 이 그 경로에 쓰는지.

    merge-bin 은 서버가 DESTRUCTIVE 로 분류하므로 서버를 거치지 않고 exe 를 직접 실행한다(포트 미사용, 파일만 다룸).
    서버가 미리 O_EXCL 로 만든 빈 예약 파일을 esptool.exe 가 덮어쓰는 경우(read-flash 와 같은 상황)도 확인한다.
    """
    from esp_mcp import ports
    from esp_mcp.esptool_cli import OutputCollector, child_env, prepare_run_dir, run_streaming

    exe = real_windows_esptool()
    if not exe:
        pytest.skip("Windows esptool.exe 또는 WSL interop 이 없음")
    cid = make_case("esp merge-bin path check")
    dumps = case_dir(cid) / "dumps"
    src = dumps / "input image.bin"  # 공백 포함 경로
    payload = os.urandom(8192)
    src.write_bytes(payload)
    out_new = dumps / "merged.bin"
    out_reserved = dumps / ".reserved.read1.partial"
    fd = os.open(out_reserved, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o644)
    os.close(fd)
    rd = tmp_path / "run"
    rd.mkdir()
    prepare_run_dir(rd)
    for out in (out_new, out_reserved):
        win_out = ports.to_windows_path(out) if out.exists() else ports.to_windows_path(out.parent) + "\\" + out.name
        win_in = ports.to_windows_path(src)
        assert win_in.startswith("\\\\wsl") and "input image.bin" in win_in
        col = OutputCollector()
        res = run_streaming([exe, "--chip", "esp32s3", "merge-bin", "-o", win_out, "0x0", win_in], timeout=120, on_text=col.feed,
                            cwd=str(rd), env=child_env(windows=True, run_dir=rd, stub_version="2"), windows_output=True)
        col.close()
        assert res.returncode == 0, col.text
        assert out.read_bytes() == payload, col.text


@pytest.mark.external
def test_real_windows_esptool_cancel_kills_onefile_child(workspace, tmp_path):
    """실제 esptool.exe(onefile): 없는 COM99 를 ESPTOOL_OPEN_PORT_ATTEMPTS=0 으로 끝없이 재시도시키고 run_streaming 으로 취소 →
    부트로더·자식 모두 끝나고 새 %TEMP%\\_MEI* 가 남지 않는다. 그동안 port_holders 가 COM99 를 잡은 esptool.exe 를 찾는다."""
    from esp_mcp import winproc
    from esp_mcp.esptool_cli import (OutputCollector, build_argv, child_env, info_win_match, prepare_run_dir, run_streaming)

    exe = real_windows_esptool()
    if not exe:
        pytest.skip("Windows esptool.exe 또는 WSL interop 이 없음")
    before_mei = windows_mei_dirs()
    rd = tmp_path / "run"
    rd.mkdir()
    prepare_run_dir(rd)
    env = child_env(windows=True, run_dir=rd, stub_version="2")
    env["ESPTOOL_OPEN_PORT_ATTEMPTS"] = "0"  # 포트 열기를 끝없이 재시도 (이름은 이미 WSLENV 에 있다)
    argv = build_argv(exe, major=5, chip="esp32", port="COM99", baud=115200, before="default-reset", after="hard-reset", no_stub=False,
                      command="flash-id")
    holders: list = []
    t0 = time.monotonic()

    def cancel() -> bool:
        if time.monotonic() - t0 > 6 and not holders:
            holders.extend(winproc.port_holders("COM99", ["esptool.exe"]) or [None])
            return True
        return False

    col = OutputCollector()
    try:
        res = run_streaming(argv, timeout=120, on_text=col.feed, cancel=cancel, cwd=rd, env=env,
                            win_match=info_win_match(exe, "COM99", "flash-id", 5))
        col.close()
        assert res.cancelled and res.orphans == [] and not res.orphan_check_failed, (res, col.text)
        assert "Could not open COM99" in col.text and "Retrying failed connection" in col.text, col.text
        assert len([h for h in holders if h is not None]) == 2, holders  # 부트로더 + PyInstaller 자식
        assert not [p for p in winproc.query("esptool.exe") if "COM99" in p.command_line]
        assert windows_mei_dirs() - before_mei == set()
    finally:
        left = [p.pid for p in winproc.query("esptool.exe") if "COM99" in p.command_line]
        if left:
            winproc.terminate(left)
        time.sleep(1.0)
        remove_windows_mei_dirs(windows_mei_dirs() - before_mei)


@pytest.mark.external
def test_real_windows_trailing_dot_path_is_rewritten_and_refused(workspace, tmp_path):
    """실제 esptool.exe 로 확인: '…\\x.\\out.bin' 은 Windows 가 '…\\x\\out.bin' 에 쓴다 → 서버의 경로 검사가 그런 경로를 거부한다."""
    from esp_mcp import ports
    from esp_mcp.esptool_cli import OutputCollector, child_env, prepare_run_dir, run_streaming
    from pweh.errors import ValidationFailed

    exe = real_windows_esptool()
    if not exe:
        pytest.skip("Windows esptool.exe 또는 WSL interop 이 없음")
    base = tmp_path / "td"
    (base / "x.").mkdir(parents=True)
    (base / "x").mkdir()
    src = base / "in.bin"
    src.write_bytes(os.urandom(4096))
    with pytest.raises(ValidationFailed, match="'.' 또는 공백"):
        ports.to_windows_path(base / "x.")
    raw = ports.to_windows_path(base) + "\\x.\\out.bin"  # 서버 검사를 거치지 않은 토큰
    rd = tmp_path / "run"
    rd.mkdir()
    prepare_run_dir(rd)
    col = OutputCollector()
    res = run_streaming([exe, "--chip", "esp32s3", "merge-bin", "-o", raw, "0x0", ports.to_windows_path(src)], timeout=120,
                        on_text=col.feed, cwd=str(rd), env=child_env(windows=True, run_dir=rd, stub_version="2"), windows_output=True)
    col.close()
    assert res.returncode == 0, col.text
    assert (base / "x" / "out.bin").read_bytes() == src.read_bytes()  # 다른 디렉터리에 쓰였다
    assert not (base / "x." / "out.bin").exists()


@pytest.mark.external
def test_real_esptool_loads_only_server_config(workspace, tmp_path, monkeypatch):
    """실제 esptool 5.4.0: 홈(리눅스 ~/.config/esptool, Windows %USERPROFILE%\\AppData\\Local\\esptool)에 설정이 있어도
    서버 환경(child_env)에서는 run dir 의 빈 설정만 읽는다. 대조 실행(ESPTOOL_CFGFILE 없음)은 홈 설정을 읽는다."""
    from esp_mcp import ports
    from esp_mcp.esptool_cli import ConfigWatch, OutputCollector, child_env, prepare_run_dir, run_streaming

    cfg_text = "[esptool]\ntimeout = 3\n"
    ran = 0
    lin = real_linux_esptool()
    if lin:
        home = tmp_path / "home"
        (home / ".config" / "esptool").mkdir(parents=True)
        (home / ".config" / "esptool" / "esptool.cfg").write_text(cfg_text)
        monkeypatch.setenv("HOME", str(home))
        rd = tmp_path / "run-lin"
        rd.mkdir()
        cfg = prepare_run_dir(rd)
        w = ConfigWatch([cfg])
        col = OutputCollector(on_line=w.line)
        res = run_streaming([lin, "version"], timeout=120, on_text=col.feed, cwd=rd, env=child_env(windows=False, run_dir=rd, stub_version="2"))
        assert res.returncode == 0 and w.loaded == [cfg] and w.foreign is None, col.text
        ctl_env = {k: v for k, v in os.environ.items() if not k.startswith("ESPTOOL_")}
        empty = tmp_path / "empty-lin"
        empty.mkdir()
        col2 = OutputCollector()
        run_streaming([lin, "version"], timeout=120, on_text=col2.feed, cwd=empty, env=ctl_env)
        assert str(home / ".config" / "esptool" / "esptool.cfg") in col2.text  # 대조: 홈 설정을 읽는 환경이었다
        ran += 1
    exe = real_windows_esptool()
    if exe:
        winhome = tmp_path / "winhome"
        (winhome / "AppData" / "Local" / "esptool").mkdir(parents=True)
        (winhome / "AppData" / "Local" / "esptool" / "esptool.cfg").write_text(cfg_text)
        rd = tmp_path / "run-win"
        rd.mkdir()
        cfg = prepare_run_dir(rd)
        env = child_env(windows=True, run_dir=rd, stub_version="2")
        env["USERPROFILE"] = str(winhome)
        env["WSLENV"] += ":USERPROFILE/p"
        w = ConfigWatch([cfg, ports.to_windows_path(cfg)])
        col = OutputCollector(on_line=w.line)
        res = run_streaming([exe, "version"], timeout=120, on_text=col.feed, cwd=rd, env=env, windows_output=True)
        assert res.returncode == 0 and w.foreign is None and len(w.loaded) == 1, col.text
        ctl = dict(env)
        del ctl["ESPTOOL_CFGFILE"]
        ctl["WSLENV"] = ":".join(n for n in env["WSLENV"].split(":") if not n.startswith("ESPTOOL_CFGFILE"))
        empty = tmp_path / "empty-win"
        empty.mkdir()
        w2 = ConfigWatch([cfg, ports.to_windows_path(cfg)])
        col2 = OutputCollector(on_line=w2.line)
        run_streaming([exe, "version"], timeout=120, on_text=col2.feed, cwd=empty, env=ctl, windows_output=True)
        assert w2.foreign and w2.foreign.endswith("AppData\\Local\\esptool\\esptool.cfg"), col2.text  # 대조
        ran += 1
    if not ran:
        pytest.skip("실제 esptool(리눅스/Windows)이 없음")


# ---------------------------------------------------------------------------
# 출처 원장 훅 (pweh.provenance): 성공한 덤프 = device-read, 칩·보안 정보 = device-fact
# ---------------------------------------------------------------------------


async def test_provenance_records_dump_reads_and_device_facts(fake):
    from esp_mcp.server import server
    from pweh.runtime import get_runtime

    cid = make_case()
    async with Client(server) as c:
        chip = await call(c, "esp_chip_info", case_id=cid, port="COM3")
        sec = await call(c, "esp_security_info", case_id=cid, port="COM3")
        r = await call(c, "esp_read_flash_start", case_id=cid, port="COM3")
        st = await _wait_job(c, r["job_id"])
    assert chip["ok"] and chip["provenance"] == {"recorded": True, "kind": "device-fact", "fact_kind": "esp-chip-info", "seq": 1}, chip
    assert sec["provenance"] == {"recorded": True, "kind": "device-fact", "fact_kind": "esp-security-info", "seq": 2}, sec
    assert st["status"] == "succeeded", st
    res = st["result"]
    assert res["provenance"]["recorded"] is True and res["provenance"]["kind"] == "device-read"
    assert [e["path"] for e in res["provenance"]["entries"]] == ["dumps/esp-flash.bin", "dumps/esp-flash.read2.bin"]
    assert [e["sha256"] for e in res["provenance"]["entries"]] == [res["sha256"], res["sha256_read2"]]
    rt = get_runtime("esp-mcp")
    case = rt.cases.get(cid)
    for rel, role in (("dumps/esp-flash.bin", "primary"), ("dumps/esp-flash.read2.bin", "verification-read")):
        v = rt.provenance.verify(case, rel)
        assert v["trusted"] is True and v["kind"] == "device-read", (rel, v)
        src = v["record"]["source"]
        assert src["server"] == "esp-mcp" and src["tool"] == "esp_read_flash_start" and src["port"] == "COM3"
        assert src["chip"] == "ESP32-S3" and src["mac"] == "f4:12:fa:12:34:56" and src["esptool_version"] == "5.4.0"
        assert src["backend"] == "windows" and src["verify"] == "double-read" and src["match"] is True
        assert v["record"]["extra"]["role"] == role and v["record"]["extra"]["job_id"] == r["job_id"]
    facts = {f["fact_kind"]: f for f in rt.provenance.facts(case)}
    cf, sf = facts["esp-chip-info"], facts["esp-security-info"]
    assert cf["data"]["status"] == "ok" and cf["data"]["chip"] == "ESP32-S3" and cf["data"]["mac"] == "f4:12:fa:12:34:56"
    assert cf["data"]["flash"]["size_bytes"] == 262144 and cf["source"]["tool"] == "esp_chip_info"
    assert cf["source"]["log_path"] == chip["log_path"] and cf["source"]["port"] == "COM3"
    assert sf["data"]["status"] == "ok" and sf["data"]["flash_encryption"] is False and sf["data"]["secure_boot"] is False
    assert sf["data"]["secure_download_mode"] is False and sf["data"]["read_flash_possible"] is True
    assert sf["data"]["key_blocks"][0] == {"block": "BLOCK_KEY0", "purpose": "USER/EMPTY"} and sf["source"]["tool"] == "esp_security_info"
    # 덤프를 고치면 더는 기기에서 읽은 것으로 신뢰하지 않는다
    p = case.dir / "dumps" / "esp-flash.bin"
    data = bytearray(p.read_bytes())
    data[0] ^= 0xFF
    os.chmod(p, 0o644)
    p.write_bytes(bytes(data))
    assert rt.provenance.verify(case, "dumps/esp-flash.bin")["reason"] == "sha256-mismatch"
    assert rt.provenance.verify(case, "dumps/esp-flash.json")["reason"] == "not-recorded"  # 서버가 만든 메타데이터는 기기 읽기가 아니다


async def test_provenance_security_facts_for_encrypted_sdm_and_unsupported(fake):
    from esp_mcp.server import server
    from pweh.runtime import get_runtime

    cid = make_case()
    async with Client(server) as c:
        fake.mode("encrypted")
        assert (await call(c, "esp_security_info", case_id=cid, port="COM3"))["provenance"]["recorded"]
        fake.mode("sdm")
        sdm = await call(c, "esp_chip_info", case_id=cid, port="COM3")
        assert sdm["status"] == "secure_download_mode" and sdm["provenance"]["recorded"]
        fake.mode("normal", chip="esp32")
        uns = await call(c, "esp_security_info", case_id=cid, port="COM3")
        assert uns["status"] == "unsupported" and uns["provenance"]["recorded"]
    facts = get_runtime("esp-mcp").provenance.facts(get_runtime("esp-mcp").cases.get(cid))
    assert [(f["fact_kind"], f["data"]["status"]) for f in facts] == [
        ("esp-security-info", "ok"), ("esp-chip-info", "secure_download_mode"), ("esp-security-info", "unsupported")]
    enc, sdm_f, uns_f = (f["data"] for f in facts)
    assert enc["flash_encryption"] is True and enc["secure_boot"] is True and enc["ciphertext_expected"] is True
    assert sdm_f["secure_download_mode"] is True and sdm_f["read_flash_possible"] is False and sdm_f["flash"] is None
    assert uns_f["flash_encryption"] is None and uns_f["read_flash_possible"] is None and uns_f["chip"] in ("ESP32", "ESP32-D0WDQ6")


async def test_provenance_only_for_fully_succeeded_dumps(fake, monkeypatch):
    """실패(Secure Download Mode)·취소(1차만 보존)한 덤프는 device-read 로 기록하지 않는다. 불일치(match=false)도 성공한 덤프면 match 와 함께 기록하지만
    verify 는 신뢰하지 않는다(device-read-mismatch)."""
    from esp_mcp.server import server
    from pweh.runtime import get_runtime

    cid = make_case()
    rt = get_runtime("esp-mcp")
    async with Client(server) as c:
        fake.mode("sdm")
        st = await _wait_job(c, (await call(c, "esp_read_flash_start", case_id=cid, port="COM3"))["job_id"])
        assert st["status"] == "failed", st
        assert rt.provenance.entries(rt.cases.get(cid), "device-read") == []
        # 2차 읽기 도중 취소 → 1차 읽기는 보존되지만 기기 읽기로 기록하지 않는다
        fake.mode("slow")
        monkeypatch.setenv("FAKE_ESPTOOL_SLOW_CALL", "2")
        monkeypatch.setenv("FAKE_ESPTOOL_DELAY", "0.3")
        (fake.tmp / "fake.count").unlink(missing_ok=True)  # 읽기 호출 번호를 1부터 다시 센다 (2 = 이 덤프의 2차 읽기)
        n0 = len(fake.calls("read-flash"))
        r = await call(c, "esp_read_flash_start", case_id=cid, port="COM3")
        for _ in range(400):
            if len(fake.calls("read-flash")) >= n0 + 2:
                break
            await anyio.sleep(0.05)
        await anyio.sleep(0.5)
        await call(c, "esp_job_cancel", job_id=r["job_id"])
        st = await _wait_job(c, r["job_id"])
        assert st["status"] == "cancelled" and st["result"]["path"] == "dumps/esp-flash.bin", st
        assert st["result"]["provenance"]["recorded"] is False and "cancelled" in st["result"]["provenance"]["reason"]
        case = rt.cases.get(cid)
        assert rt.provenance.entries(case, "device-read") == []
        assert rt.provenance.verify(case, "dumps/esp-flash.bin")["reason"] == "not-recorded"
        monkeypatch.delenv("FAKE_ESPTOOL_SLOW_CALL")
        fake.mode("mismatch")
        (fake.tmp / "fake.count").unlink(missing_ok=True)  # 짝수 번째 읽기가 달라진다 → 이 덤프의 2차 읽기
        st = await _wait_job(c, (await call(c, "esp_read_flash_start", case_id=cid, port="COM3"))["job_id"])
    assert st["status"] == "succeeded" and st["result"]["match"] is False, st
    prov = st["result"]["provenance"]
    assert prov["recorded"] is True and len(prov["entries"]) == 2
    for e in rt.provenance.entries(case, "device-read"):
        assert e["source"]["match"] is False and e["source"]["verify"] == "double-read"
        # 기록은 하지만 이중 읽기가 어긋난 덤프는 출처 확인에서 신뢰하지 않는다 (출처 ≠ 무결성)
        v = rt.provenance.verify(case, e["path"])
        assert v["trusted"] is False and v["reason"] == "device-read-mismatch", v


async def test_provenance_failure_never_fails_the_dump(fake):
    """원장이 깨져 있으면 덤프는 그대로 끝나고 provenance.recorded=false + 경고만 남는다(깨진 원장에는 덧붙이지 않음)."""
    from esp_mcp.server import server

    cid = make_case()
    ledger = fake.workspace["state_dir"] / "provenance" / f"{cid}.jsonl"
    ledger.parent.mkdir(parents=True, exist_ok=True)
    ledger.write_text('{"seq": 1}\n', encoding="utf-8")
    async with Client(server) as c:
        chip = await call(c, "esp_chip_info", case_id=cid, port="COM3")
        st = await _wait_job(c, (await call(c, "esp_read_flash_start", case_id=cid, port="COM3", verify="none", size="64K"))["job_id"])
    assert chip["ok"] and chip["provenance"]["recorded"] is False and "provenance_ledger_broken" in chip["provenance"]["reason"]
    assert st["status"] == "succeeded", st
    res = st["result"]
    assert res["provenance"]["recorded"] is False and any("출처 원장" in w for w in res["warnings"])
    assert (case_dir(cid) / "dumps" / "esp-flash.bin").stat().st_size == 65536
    assert ledger.read_text(encoding="utf-8") == '{"seq": 1}\n'
