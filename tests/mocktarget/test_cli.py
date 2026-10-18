"""``pweh-mock-device`` CLI 테스트 (e2e 테스트처럼 프로세스 밖에서 구동)."""

from __future__ import annotations

import json
import subprocess
import sys
import time
from pathlib import Path

import serial

REPO = Path(__file__).resolve().parents[2]
PY = str(REPO / ".venv" / "bin" / "python") if (REPO / ".venv" / "bin" / "python").exists() else sys.executable


def _start(*args: str) -> tuple[subprocess.Popen, dict]:
    proc = subprocess.Popen([PY, "-m", "pweh.mocktarget.cli", *args], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, text=True, cwd=str(REPO))
    assert proc.stdout is not None
    line = proc.stdout.readline()
    info = json.loads(line)
    return proc, info


def _ctl(proc: subprocess.Popen, cmd: str) -> dict:
    assert proc.stdin is not None and proc.stdout is not None
    proc.stdin.write(cmd + "\n")
    proc.stdin.flush()
    return json.loads(proc.stdout.readline())


def test_cli_pty_control_loop():
    proc, info = _start("--profile", "hisilicon-like", "--pty", "--fast-firmware", "--time-scale", "0.02")
    try:
        assert info["ok"] is True and info["pty"].startswith("/dev/pts/")
        assert info["profile"] == "hisilicon-like" and info["uboot_prompt"] == "hisilicon # "
        port = serial.Serial(info["pty"], 115200, timeout=0.05)
        buf = bytearray()
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline and b"hisilicon # " not in buf:
            port.write(b"\x03")
            buf += port.read(4096)
        assert b"hisilicon # " in buf
        st = _ctl(proc, "status")
        assert st["ok"] and st["state"] == "uboot" and st["profile"] == "hisilicon-like"
        port.write(b"saveenv\r")
        time.sleep(0.5)
        d = _ctl(proc, "destructive")
        assert [e["op"] for e in d["destructive_events"]] == ["saveenv"]
        r = _ctl(proc, "power-cycle")
        assert r["ok"]
        w = _ctl(proc, "wait linux-login 20")
        assert w["ok"] and w["state"] == "linux-login"
        off = _ctl(proc, "power-off")
        assert off["state"] == "off"
        bad = _ctl(proc, "frobnicate")
        assert bad["ok"] is False and "commands" in bad
        q = _ctl(proc, "quit")
        assert q["quit"] is True
        assert proc.wait(timeout=10) == 0
        port.close()
    finally:
        if proc.poll() is None:
            proc.kill()


def test_cli_tcp_no_autostart_and_eof_quits():
    proc, info = _start("--profile", "ingenic-like", "--tcp", "--port", "0", "--fast-firmware", "--no-autostart",
                        "--time-scale", "0.02")
    try:
        assert info["ok"] and info["url"].startswith("socket://127.0.0.1:") and info["powered"] is False
        s = serial.serial_for_url(info["url"], timeout=0.05)
        assert _ctl(proc, "status")["state"] == "off"
        _ctl(proc, "power-on")
        buf = bytearray()
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline and b"U-Boot SPL" not in buf:
            buf += s.read(4096)
        assert b"U-Boot SPL 2013.07" in buf
        s.close()
        assert proc.stdin is not None
        proc.stdin.close()  # EOF → 종료
        assert proc.wait(timeout=10) == 0
    finally:
        if proc.poll() is None:
            proc.kill()


def test_cli_build_firmware(tmp_path):
    out = tmp_path / "fw.bin"
    res = subprocess.run([PY, "-m", "pweh.mocktarget.cli", "--profile", "ingenic-like", "--fast-firmware",
                          "--build-firmware", str(out)], capture_output=True, text=True, timeout=120, cwd=str(REPO))
    assert res.returncode == 0, res.stderr
    info = json.loads(res.stdout.strip().splitlines()[-1])
    assert info["ok"] and info["image"]["size"] == 16 * 1024 * 1024
    assert out.stat().st_size == 16 * 1024 * 1024
    manifest = json.loads(Path(str(out) + ".manifest.json").read_text(encoding="utf-8"))
    assert manifest["profile"] == "ingenic-like" and len(manifest["planted_issues"]) == 6
    assert info["planted_issues"] == [p["id"] for p in manifest["planted_issues"]]
