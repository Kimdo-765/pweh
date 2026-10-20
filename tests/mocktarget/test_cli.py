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


# ---------------------------------------------------------------------------
# --tcp 바인드 주소: 루프백만 (port-routing 설계 G13). 시험은 루프백이 아닌 주소에 실제로 바인드하지 않는다.
# ---------------------------------------------------------------------------


def test_cli_tcp_refuses_non_loopback_host_subprocess():
    """실제 CLI: --host 0.0.0.0 은 펌웨어를 만들거나 바인드하기 전에 JSON ok=false·종료 코드 2."""
    res = subprocess.run([PY, "-m", "pweh.mocktarget.cli", "--tcp", "--host", "0.0.0.0", "--port", "0", "--fast-firmware"],
                         capture_output=True, text=True, timeout=60, cwd=str(REPO), stdin=subprocess.DEVNULL)
    assert res.returncode == 2, (res.stdout, res.stderr)
    info = json.loads(res.stdout.strip().splitlines()[-1])
    assert info["ok"] is False and info["error"]["code"] == "validation_failed"
    assert "루프백" in info["error"]["message"] and "--allow-lan" in info["error"]["hint"]


def test_cli_tcp_refuses_non_loopback_hosts_in_process(monkeypatch, capsys):
    from pweh.mocktarget import cli

    def device_reached(*a, **kw):
        raise RuntimeError("DEVICE-REACHED")  # 기기 생성 단계에 도달했는지 보는 표지

    monkeypatch.setattr(cli, "MockDevice", device_reached)
    for host in ("0.0.0.0", "", "192.0.2.10", "localhost.", "::"):
        rc = cli.main(["--tcp", "--host", host, "--fast-firmware"])
        info = json.loads(capsys.readouterr().out.strip().splitlines()[-1])
        assert rc == 2 and info["ok"] is False and info["error"]["code"] == "validation_failed", (host, info)
    # PTY 모드는 --host 를 쓰지 않으므로 검사하지 않고 기기 생성까지 간다
    rc = cli.main(["--pty", "--host", "0.0.0.0", "--fast-firmware"])
    info = json.loads(capsys.readouterr().out.strip().splitlines()[-1])
    assert rc == 2 and "DEVICE-REACHED" in info["error"]["message"]


class _FakeDevice:
    calls: dict = {}

    def __init__(self, profile, **kw):
        self.profile = {"name": profile, "linux": {"login": {"user": "root"}}, "uboot": {"prompt": "x # "}}
        self.baud, self.time_scale, self.powered, self.firmware_manifest = 115200, 1.0, False, None

    def start_tcp(self, host, port, *, allow_lan=False):
        type(self).calls.update(host=host, port=port, allow_lan=allow_lan)
        return host or "0.0.0.0", 4321

    def stop(self):
        type(self).calls["stopped"] = True


def _run_fake_cli(monkeypatch, capsys, *argv: str) -> tuple[int, dict, str]:
    from pweh.mocktarget import cli

    _FakeDevice.calls = {}
    monkeypatch.setattr(cli, "MockDevice", _FakeDevice)
    monkeypatch.setattr(cli, "_control_loop", lambda dev, stop: None)
    monkeypatch.setattr(cli.signal, "signal", lambda *a: None)  # pytest 의 SIGINT 처리기를 바꾸지 않게
    rc = cli.main(list(argv))
    out, err = capsys.readouterr()
    return rc, json.loads(out.strip().splitlines()[0]), err


def test_cli_tcp_ipv6_host_refused_cleanly(monkeypatch, capsys):
    """리스너는 IPv4 전용 — '--host ::1' 은 traceback 대신 JSON validation_failed·종료 코드 2 (--allow-lan 이어도, 리뷰 F7)."""
    from pweh.mocktarget import cli

    def device_reached(*a, **kw):
        raise RuntimeError("DEVICE-REACHED")

    monkeypatch.setattr(cli, "MockDevice", device_reached)
    for extra in ([], ["--allow-lan"]):
        rc = cli.main(["--tcp", "--host", "::1", "--fast-firmware", *extra])
        info = json.loads(capsys.readouterr().out.strip().splitlines()[-1])
        assert rc == 2 and info["error"]["code"] == "validation_failed" and "IPv4" in info["error"]["message"], info


def test_cli_tcp_allow_lan_warns_on_stderr(monkeypatch, capsys):
    rc, info, err = _run_fake_cli(monkeypatch, capsys, "--tcp", "--host", "0.0.0.0", "--port", "0", "--allow-lan",
                                  "--fast-firmware")
    assert rc == 0 and info["ok"] and info["url"] == "socket://0.0.0.0:4321"
    assert _FakeDevice.calls == {"host": "0.0.0.0", "port": 0, "allow_lan": True, "stopped": True}
    assert "경고" in err and "0.0.0.0:4321" in err and "LAN" in err and "socket://127.0.0.1:4321" in err


def test_cli_tcp_loopback_does_not_warn(monkeypatch, capsys):
    rc, info, err = _run_fake_cli(monkeypatch, capsys, "--tcp", "--port", "0", "--fast-firmware")
    assert rc == 0 and info["ok"] and _FakeDevice.calls["host"] == "127.0.0.1" and _FakeDevice.calls["allow_lan"] is False
    assert "경고" not in err
    rc, info, err = _run_fake_cli(monkeypatch, capsys, "--tcp", "--host", "127.0.0.2", "--allow-lan", "--fast-firmware")
    assert rc == 0 and "경고" not in err  # 루프백이면 --allow-lan 이 있어도 경고하지 않는다
