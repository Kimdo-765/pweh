"""sigrok-mcp MCP 도구 테스트 (가짜 sigrok-cli 사용 — 외부 도구/하드웨어 불필요) + stdio 스모크 테스트."""

from __future__ import annotations

import json
import os
import subprocess
import time
from pathlib import Path
from types import SimpleNamespace

import anyio
import pytest
from mcp import Client

from mcp_helpers import call, stdio_params
from servers.sigrok_testutil import (
    case_dir,
    make_case,
    make_fake_sigrok,
    pid_alive,
    read_log,
    write_uart_sr,
    write_uart_vcd,
)
from sigrok_mcp.synth import BOOT_BANNER

pytestmark = pytest.mark.anyio


@pytest.fixture
def anyio_backend():
    return "asyncio"


@pytest.fixture
def fake(workspace, tmp_path, monkeypatch):
    from pweh.runtime import reset_runtimes
    from sigrok_mcp.cli import clear_cache

    exe = make_fake_sigrok(tmp_path / "fakebin")
    log = tmp_path / "fake.log"
    pidfile = tmp_path / "fake.pid"
    monkeypatch.setenv("PWEH_SIGROK_CLI", str(exe))
    monkeypatch.setenv("FAKE_SIGROK_LOG", str(log))
    monkeypatch.setenv("FAKE_SIGROK_PIDFILE", str(pidfile))
    monkeypatch.setenv("FAKE_SIGROK_MODE", "normal")
    reset_runtimes()
    clear_cache()

    def mode(m: str) -> None:
        monkeypatch.setenv("FAKE_SIGROK_MODE", m)

    def calls(kind: str | None = None) -> list[list[str]]:
        out = [e["argv"] for e in read_log(log)]
        if kind == "capture":
            out = [a for a in out if any(x.startswith("--samples=") or x.startswith("--time=") for x in a)]
        elif kind == "decode":
            out = [a for a in out if any(x.startswith("--input-file=") for x in a) and any(x.startswith("--protocol-decoders=") for x in a)
                   and "--show" not in a]
        return out

    yield SimpleNamespace(exe=exe, log=log, pidfile=pidfile, mode=mode, calls=calls, workspace=workspace)
    clear_cache()


async def _wait_job(c, job_id: str, timeout: float = 30.0) -> dict:
    deadline = time.monotonic() + timeout
    while True:
        st = await call(c, "sigrok_job_status", job_id=job_id, wait_seconds=2)
        if st.get("status") not in ("queued", "running", "cancelling"):
            return st
        if time.monotonic() > deadline:
            raise AssertionError(f"job did not finish: {st}")


async def test_info_tools(fake):
    from sigrok_mcp.server import server

    async with Client(server) as c:
        names = {t.name for t in (await c.list_tools()).tools}
        for n in ("sigrok_version", "sigrok_scan", "sigrok_list", "sigrok_decoder_help", "sigrok_capture", "sigrok_decode",
                  "sigrok_export", "sigrok_estimate_baud", "sigrok_uart_autodecode", "sigrok_file_info", "sigrok_device_info",
                  "sigrok_job_status", "sigrok_job_cancel", "sigrok_jobs"):
            assert n in names
        v = await call(c, "sigrok_version")
        assert v["ok"] and v["sigrok_cli"] == "0.7.2" and v["path"] == str(fake.exe)
        assert v["counts"]["drivers"] == 7 and v["libsigrokdecode"]["version"] == "0.5.3"
        lst = await call(c, "sigrok_list", kind="drivers")
        by = {d["id"]: d for d in lst["items"]}
        assert by["demo"]["capture_allowed"] and by["fx2lafw"]["capture_allowed"]
        assert by["korad-kaxxxxp"]["output_capable"] and not by["korad-kaxxxxp"]["capture_allowed"]
        assert by["arachnid-labs-re-load-pro"]["policy"] == "denied"
        assert by["uni-t-ut61e"]["policy"] == "not-allowlisted"
        dec = await call(c, "sigrok_list", kind="decoders", query="uart")
        assert [d["id"] for d in dec["items"]] == ["uart"]
        assert "_error" in await call(c, "sigrok_list", kind="bogus")
        h = await call(c, "sigrok_decoder_help", decoder="uart")
        assert h["ok"] and h["decoder"]["id"] == "uart" and h["example_stack"].startswith("uart:rx=")
        assert "_error" in await call(c, "sigrok_decoder_help", decoder="uart;rm")
        missing = await call(c, "sigrok_decoder_help", decoder="nosuchpd")
        assert "_error" in missing and "nosuchpd" in missing["_error"]
        # 캐시: 두 번째 버전 조회는 sigrok-cli 를 다시 실행하지 않는다
        n_before = len(fake.calls())
        await call(c, "sigrok_version")
        assert len(fake.calls()) == n_before


async def test_scan_and_device_info(fake):
    from sigrok_mcp.server import server

    cid = make_case()
    noauth = make_case("noauth", authorized=False)
    async with Client(server) as c:
        r = await call(c, "sigrok_scan")
        assert r["ok"] and r["count"] == 2
        fx = next(d for d in r["devices"] if d["driver"] == "fx2lafw")
        assert fx["conn"] == "1.6" and fx["serial_number"] == "1234" and fx["capture_allowed"]
        assert fake.calls()[-1] == ["--scan"]
        r = await call(c, "sigrok_scan", driver="demo")
        assert r["count"] == 1 and fake.calls()[-1] == ["--driver=demo", "--dont-scan", "--scan"]
        # 출력 장치 드라이버 스캔 거부 (sigrok-cli 미실행)
        n = len(fake.calls())
        d = await call(c, "sigrok_scan", driver="korad-kaxxxxp")
        assert d["ok"] is False and d["status"] == "denied" and "출력" in d["message"]
        assert len(fake.calls()) == n
        # 시리얼 conn 은 case_id 필수, 인가되지 않은 케이스 거부
        e = await call(c, "sigrok_scan", driver="ols", conn="/dev/ttyACM0")
        assert "_error" in e and "case_id" in e["_error"]
        e = await call(c, "sigrok_scan", driver="ols", conn="/dev/null", case_id=noauth)
        assert "_error" in e and "authorization" in e["_error"]
        e = await call(c, "sigrok_scan", driver="fx2lafw", conn="1.6:samplerate=1")
        assert "_error" in e and "conn" in e["_error"]
        info = await call(c, "sigrok_device_info", case_id=cid, driver="demo")
        assert info["ok"] and info["samplerate_range"]["max"] == "1 GHz" and info["triggers"] == ["0", "1", "r", "f", "e"]
        info = await call(c, "sigrok_device_info", case_id=cid, driver="fx2lafw", conn="1.6")
        assert info["samplerates"] == ["20 kHz", "1 MHz", "24 MHz"]
        assert fake.calls()[-1] == ["--driver=fx2lafw:conn=1.6", "--dont-scan", "--show"]
        fake.mode("nodevice")
        nd = await call(c, "sigrok_device_info", case_id=cid, driver="fx2lafw")
        assert nd["ok"] is False and nd["status"] == "no_device" and nd["driver_functions"] == ["Logic analyzer"]
        r = await call(c, "sigrok_scan", driver="fx2lafw")
        assert r["ok"] and r["count"] == 0 and "usbipd" in r["note"]
    audit = (case_dir(cid) / "audit.jsonl").read_text(encoding="utf-8")
    assert "sigrok_device_info" in audit


async def test_scan_serial_port_in_use_is_refused(fake):
    """다른 프로세스가 연 시리얼 포트(UART 콘솔일 수 있음)에는 드라이버 식별 바이트를 보내지 않는다."""
    from sigrok_mcp.server import server

    cid = make_case()
    master, slave = os.openpty()
    pts = os.ttyname(slave)
    holder = subprocess.Popen(["sleep", "30"], stdin=slave, stdout=subprocess.DEVNULL)
    try:
        async with Client(server) as c:
            r = await call(c, "sigrok_scan", driver="ols", conn=pts, case_id=cid)
            assert "_error" in r and "사용 중" in r["_error"], r
            assert not any("--scan" in a for a in fake.calls())
            holder.kill()
            holder.wait(5)
            r = await call(c, "sigrok_scan", driver="ols", conn=pts, case_id=cid)
            assert r["ok"] and r["devices"][0]["driver"] == "ols" and r["classification"]["risk"] == "modify"
    finally:
        if holder.poll() is None:
            holder.kill()
        os.close(master)
        os.close(slave)


async def test_capture_argument_construction_and_artifacts(fake):
    from sigrok_mcp.server import server
    from sigrok_mcp import signals as sig

    cid = make_case()
    cdir = case_dir(cid)
    async with Client(server) as c:
        r = await call(c, "sigrok_capture", case_id=cid, driver="demo", samplerate="1.5m", samples=30000,
                       channels=["D0=RX", "D1"], triggers=None)
        assert r["ok"] and r["status"] == "succeeded", r
        argv = fake.calls("capture")[-1]
        assert argv[:3] == ["--driver=demo", "--dont-scan", "--config=samplerate=1500000"]
        assert "--channels=D0=RX,D1" in argv and "--samples=30000" in argv and "--output-format=srzip" in argv
        out = [a for a in argv if a.startswith("--output-file=")][0].split("=", 1)[1]
        assert Path(out).parent == cdir / "signals" and Path(out).name.startswith(".capture-demo-001")
        assert r["path"] == "signals/capture-demo-001.sr" and (cdir / r["path"]).exists()
        assert not Path(out).exists()  # 임시 파일은 최종 이름으로 이동
        assert r["samples"] == 30000 and r["samplerate"] == 1_500_000 and r["channels"] == ["RX", "D1"]
        assert r["artifact"]["kind"] == "signal-capture" and r["artifact"]["extra"]["driver"] == "demo"
        assert r["classification"]["risk"] == "observe"
        act = {a["name"]: a for a in r["activity"]}
        assert act["RX"]["edges"] > 10 and act["D1"]["edges"] == 0 and "RX" in r["next_steps"]
        info = sig.read_srzip_info(cdir / r["path"])
        assert info.total_samples == 30000
        # 자동 번호 증가, 명시 이름 충돌 거부, 트리거·captureratio·time
        r2 = await call(c, "sigrok_capture", case_id=cid, driver="demo", duration_ms=5, output_name="boot.sr",
                        channels="D0=RX", triggers="RX=f", capture_ratio=1, background=False)
        assert r2["ok"] and r2["path"] == "signals/boot.sr"
        argv2 = fake.calls("capture")[-1]
        assert "--triggers=RX=f" in argv2 and "--config=captureratio=1" in argv2 and "--time=5" in argv2
        dup = await call(c, "sigrok_capture", case_id=cid, driver="demo", duration_ms=5, output_name="boot")
        assert "_error" in dup and "이미" in dup["_error"]
        r3 = await call(c, "sigrok_capture", case_id=cid, driver="demo", samples=1000)
        assert r3["path"] == "signals/capture-demo-002.sr"
        # 검증 오류들 (sigrok-cli 미실행)
        n = len(fake.calls("capture"))
        for bad in (
            dict(driver="demo"),  # 제한 없음
            dict(driver="demo", samples=10, duration_ms=10),  # 둘 다
            dict(driver="demo", samples=10, samplerate="fast"),
            dict(driver="demo", samples=10, channels=["D0", "D0"]),
            dict(driver="demo", samples=10, channels=["D0=RX"], triggers="D0=f"),  # rename 후 이름 아님
            dict(driver="demo", samples=10, output_name="../escape"),
            dict(driver="demo:conn=1.6", samples=10),
            dict(driver="demo", samples=10, conn="1.6,2"),
        ):
            e = await call(c, "sigrok_capture", case_id=cid, **bad)
            assert "_error" in e, (bad, e)
        assert len(fake.calls("capture")) == n
    arts = json.loads((cdir / "case.json").read_text(encoding="utf-8"))["artifacts"]
    assert {a["path"] for a in arts} >= {"signals/capture-demo-001.sr", "signals/boot.sr", "signals/capture-demo-002.sr"}
    audit = (cdir / "audit.jsonl").read_text(encoding="utf-8")
    assert '"tool": "sigrok_capture"' in audit and '"event": "sigrok_capture"' in audit


async def test_capture_refusals_never_invoke_cli(fake):
    from sigrok_mcp.server import server

    cid = make_case()
    noauth = make_case("x", authorized=False)
    async with Client(server) as c:
        for drv in ("korad-kaxxxxp", "scpi-pps", "rdtech-dps", "maynuo-m97", "rigol-dg", "icstation-usbrelay", "baylibre-acme"):
            r = await call(c, "sigrok_capture", case_id=cid, driver=drv, samples=100)
            assert r["ok"] is False and r["status"] == "denied", (drv, r)
            assert r["gate"]["classification"]["rule_id"] == "sigrok.driver.output_capable"
        r = await call(c, "sigrok_capture", case_id=cid, driver="uni-t-ut61e", samples=100)
        assert r["status"] == "denied" and r["gate"]["classification"]["rule_id"] == "sigrok.driver.not_allowlisted"
        e = await call(c, "sigrok_capture", case_id=noauth, driver="demo", samples=100)
        assert "_error" in e and "authorization" in e["_error"]
    assert fake.calls("capture") == []
    audit = (case_dir(cid) / "audit.jsonl").read_text(encoding="utf-8").splitlines()
    denials = [json.loads(l) for l in audit if '"safety_decision"' in l]
    assert any(d.get("status") == "denied" and d.get("via") == "sigrok-policy" for d in denials)


async def test_capture_destructive_policy_approve_still_refuses_output_devices(fake):
    """운영자가 destructive_policy=approve 로 바꿔도 출력 장치 캡처는 승인 경로 없이 거부된다."""
    from pweh.runtime import reset_runtimes
    from sigrok_mcp.server import server

    fake.workspace["set_safety"](destructive_policy="approve", modify_policy="approve")
    reset_runtimes()
    cid = make_case()
    async with Client(server) as c:
        r = await call(c, "sigrok_capture", case_id=cid, driver="korad-kaxxxxp", samples=100)
        assert r["status"] == "denied" and "approval_id" not in r
    assert fake.calls("capture") == []


async def test_capture_failures_timeout_and_kill(fake):
    from sigrok_mcp.server import server

    cid = make_case()
    cdir = case_dir(cid)
    async with Client(server) as c:
        fake.mode("fail")
        e = await call(c, "sigrok_capture", case_id=cid, driver="demo", samples=10)
        assert "_error" in e and "samplerate" in e["_error"] and "sigrok_device_option_failed" in e["_error"]
        fake.mode("nodevice")
        e = await call(c, "sigrok_capture", case_id=cid, driver="fx2lafw", samples=10)
        assert "_error" in e and "No devices found" in e["_error"] and "usbipd" in e["_error"]
        fake.mode("hang")
        t0 = time.monotonic()
        r = await call(c, "sigrok_capture", case_id=cid, driver="demo", samples=10, timeout_s=2, background=False)
        assert r["ok"] is False and r["status"] == "timeout", r
        assert time.monotonic() - t0 < 15
        pid = int(fake.pidfile.read_text())
        for _ in range(50):
            if not pid_alive(pid):
                break
            time.sleep(0.05)
        assert not pid_alive(pid), "타임아웃 후 sigrok-cli 프로세스 그룹이 종료되어야 함"
        # 트리거 + 시간초과 + 데이터 없음 → '트리거 미발생' 메시지
        fake.pidfile.unlink()
        r = await call(c, "sigrok_capture", case_id=cid, driver="demo", samples=10, triggers="D0=f", timeout_s=2, background=False)
        assert r["status"] == "timeout" and "트리거" in r["message"]
    assert not list((cdir / "signals").glob(".*partial*"))


async def test_background_capture_job_and_cancel(fake, monkeypatch):
    from sigrok_mcp.server import server

    cid = make_case()
    async with Client(server) as c:
        fake.mode("slow")
        monkeypatch.setenv("FAKE_SIGROK_SLEEP", "0.5")
        r = await call(c, "sigrok_capture", case_id=cid, driver="demo", samples=2000, background=True)
        assert r["ok"] and r["status"] == "started" and r["planned_path"] == "signals/capture-demo-001.sr"
        st = await _wait_job(c, r["job_id"])
        assert st["status"] == "succeeded", st
        assert st["result"]["path"] == "signals/capture-demo-001.sr" and st["result"]["artifact"]["kind"] == "signal-capture"
        jobs = await call(c, "sigrok_jobs")
        assert any(j["job_id"] == r["job_id"] for j in jobs["jobs"])
        # 취소: hang 모드 캡처를 작업으로 시작 → 같은 장치 동시 캡처는 busy → 취소 → 프로세스 종료
        fake.mode("hang")
        fake.pidfile.unlink(missing_ok=True)
        r = await call(c, "sigrok_capture", case_id=cid, driver="demo", samples=10, triggers="D0=r")
        assert r["status"] == "started"
        for _ in range(100):
            if fake.pidfile.exists():
                break
            await anyio.sleep(0.05)
        pid = int(fake.pidfile.read_text())
        busy = await call(c, "sigrok_capture", case_id=cid, driver="demo", samples=10)
        assert "_error" in busy and "실행 중" in busy["_error"]
        cr = await call(c, "sigrok_job_cancel", job_id=r["job_id"])
        assert cr["ok"]
        st = await _wait_job(c, r["job_id"])
        assert st["status"] == "cancelled", st
        for _ in range(50):
            if not pid_alive(pid):
                break
            await anyio.sleep(0.05)
        assert not pid_alive(pid)
        assert st["result"]["status"] == "cancelled"


def test_job_worker_rechecks_argv(fake):
    """백그라운드 작업은 실행 직전에 argv 를 다시 분류한다: 변조된 명령(--config=voltage_target=5, --set)은 실행 거부."""
    from pweh.errors import SafetyDenied
    from sigrok_mcp import server as srv
    from sigrok_mcp.policy import DriverPolicy

    cid = make_case()
    cdir = case_dir(cid)
    sigdir = cdir / "signals"
    base = [str(fake.exe), "--driver=demo", "--dont-scan", "--config=samplerate=1000000", "--samples=10",
            "--output-format=srzip", f"--output-file={sigdir}/.t.partial.sr"]
    for tamper in (["--config=voltage_target=5"], ["--set"], ["--channel-group=PWM1"]):
        argv = base[:4] + tamper + base[4:]
        plan = srv.CapturePlan(case_id=cid, case_dir=cdir, sig_dir=sigdir, driver="demo", conn=None, samplerate=1_000_000,
                               duration_ms=None, samples=10, channels=None, triggers=None, capture_ratio=None,
                               final_path=sigdir / "t.sr", part_path=sigdir / ".t.partial.sr", argv=argv, expected_s=0.0,
                               timeout_s=10, policy=DriverPolicy(), exclusive_key="k")
        with pytest.raises(SafetyDenied):
            srv._capture_worker(plan, cancel=lambda: False)
    plan.argv = [str(fake.exe), "--driver=korad-kaxxxxp"] + base[2:]
    with pytest.raises(SafetyDenied):
        srv._capture_worker(plan, cancel=lambda: False)
    assert fake.calls("capture") == []


async def test_decode_validation_and_output(fake):
    from sigrok_mcp.server import server

    cid = make_case()
    cdir = case_dir(cid)
    write_uart_sr(cdir / "signals" / "boot.sr", BOOT_BANNER, baud=115200, samplerate=2_000_000)
    async with Client(server) as c:
        r = await call(c, "sigrok_decode", case_id=cid, input_path="signals/boot.sr", decoders="uart:rx=RX:baudrate=115200",
                       annotations="uart=rx-data", samplenum=True, max_lines=10)
        assert r["ok"], r
        assert r["lines_total"] == len(BOOT_BANNER) and len(r["lines"]) == 10 and r["truncated"]
        assert r["lines"][0].endswith("uart-1: 0D") and r["instances"] == {"uart-1": len(BOOT_BANNER)}
        assert r["output_path"] == "signals/boot.uart.txt" and (cdir / r["output_path"]).exists()
        assert r["artifact"]["kind"] == "signal-decode" and r["sample_range"][0] > 0
        argv = fake.calls("decode")[-1]
        assert argv == [f"--input-file={cdir / 'signals' / 'boot.sr'}", "--protocol-decoders=uart:rx=RX:baudrate=115200",
                        "--protocol-decoder-annotations=uart=rx-data", "--protocol-decoder-samplenum"]
        # 입력 경로는 signals/ 생략 가능, 두 번째 결과는 번호 증가
        r2 = await call(c, "sigrok_decode", case_id=cid, input_path="boot.sr", decoders=["uart:rx=RX:baudrate=115200"])
        assert r2["output_path"] == "signals/boot.uart-002.txt" and any("annotations" in w for w in r2["warnings"])
        n = len(fake.calls("decode"))
        bad_cases = {
            "no mapping": "uart:baudrate=115200",
            "wrong channel": "uart:rx=D7:baudrate=115200",
            "unknown key": "uart:rx=RX:bogus=1",
            "injection": "uart:rx=RX:baudrate=115200 --set",
            "colon in value": "uart:rx=RX:format=a=b",
            "spi missing clk": "spi:mosi=RX",
            "stacked channel": "uart:rx=RX,uart:rx=TX",
        }
        for why, d in bad_cases.items():
            e = await call(c, "sigrok_decode", case_id=cid, input_path="signals/boot.sr", decoders=d)
            assert "_error" in e, (why, e)
        assert len(fake.calls("decode")) == n
        outside = await call(c, "sigrok_decode", case_id=cid, input_path="/etc/passwd", decoders="uart:rx=RX")
        assert "_error" in outside
        missing = await call(c, "sigrok_decode", case_id=cid, input_path="signals/none.sr", decoders="uart:rx=RX")
        assert "_error" in missing and "not_found" in missing["_error"]
        # rc=0 인데 실패 (없는 채널 / SamplerateError) → 오류로 판정, 결과 파일 남기지 않음
        for m, code in (("nochannel", "no_channel"), ("traceback", "no_samplerate")):
            fake.mode(m)
            e = await call(c, "sigrok_decode", case_id=cid, input_path="signals/boot.sr", decoders="uart:rx=RX:baudrate=115200")
            assert "_error" in e and code in e["_error"], (m, e)
        assert not list((cdir / "signals").glob(".*partial"))


async def test_export_and_file_info(fake):
    from sigrok_mcp.server import server

    cid = make_case()
    cdir = case_dir(cid)
    write_uart_sr(cdir / "signals" / "cap.sr", BOOT_BANNER[:30], baud=115200, samplerate=1_000_000)
    async with Client(server) as c:
        fi = await call(c, "sigrok_file_info", case_id=cid, input_path="signals/cap.sr")
        assert fi["ok"] and fi["format"] == "srzip" and fi["samplerate"] == 1_000_000
        assert fi["uart_candidates"] == ["RX"] and {a["name"] for a in fi["activity"]} == {"RX", "TX"}
        r = await call(c, "sigrok_export", case_id=cid, input_path="signals/cap.sr", output_format="vcd")
        assert r["ok"] and r["output_path"] == "signals/cap.vcd", r
        assert r["output_info"]["channels"] == ["RX", "TX"] and r["artifact"]["kind"] == "signal-capture"
        argv = fake.calls()[-1]
        assert "--output-format=vcd" in argv and any(a.startswith("--output-file=") for a in argv)
        r2 = await call(c, "sigrok_export", case_id=cid, input_path="signals/cap.vcd", output_format="srzip")
        assert r2["ok"] and r2["output_path"] == "signals/cap-002.sr" and r2["output_info"]["total_samples"] > 0
        assert "--input-format=vcd" in fake.calls()[-1]
        for bad in ("nosuchfmt", "null", "vcd:bad value", "../vcd"):
            e = await call(c, "sigrok_export", case_id=cid, input_path="signals/cap.sr", output_format=bad)
            assert "_error" in e, bad


async def test_estimate_and_autodecode(fake):
    from sigrok_mcp.server import server

    cid = make_case()
    cdir = case_dir(cid)
    write_uart_sr(cdir / "signals" / "inv.sr", BOOT_BANNER, baud=57600, samplerate=1_000_000, idle_level=0)
    write_uart_vcd(cdir / "signals" / "u.vcd", BOOT_BANNER, baud=9600, samplerate=100_000)
    async with Client(server) as c:
        e = await call(c, "sigrok_estimate_baud", case_id=cid, input_path="signals/inv.sr", channel="RX")
        assert e["ok"] and e["baudrate"] == 57600 and e["idle_level"] == 0 and e["inverted"] is True
        assert e["confidence"] >= 0.8 and e["recommended_samplerate"]
        auto = await call(c, "sigrok_estimate_baud", case_id=cid, input_path="signals/inv.sr")
        assert auto["channel"] == "RX" and auto["auto_selected_channel"] and auto["per_channel"][0]["channel"] == "RX"
        v = await call(c, "sigrok_estimate_baud", case_id=cid, input_path="signals/u.vcd", channel=0)
        assert v["baudrate"] == 9600 and v["channel"] == "RX"
        bad = await call(c, "sigrok_estimate_baud", case_id=cid, input_path="signals/inv.sr", channel="NOPE")
        assert "_error" in bad and "RX" in bad["_error"]
        # 자동 디코드 (sigrok-cli 경로: 반전 라인 → invert_rx=yes)
        a = await call(c, "sigrok_uart_autodecode", case_id=cid, input_path="signals/inv.sr", channel="RX")
        assert a["ok"] and a["engine"] == "sigrok-cli" and a["baudrate"] == 57600 and a["inverted"], a
        assert "U-Boot 2016.11" in a["text_preview"] and a["bytes_decoded"] == len(BOOT_BANNER)
        assert "invert_rx=yes" in a["decoder"] and "format=hex" in a["decoder"]
        assert any(h["kind"] == "uboot_banner" for h in a["boot_hints"])
        assert (cdir / a["bytes_path"]).read_bytes() == BOOT_BANNER
        assert a["uart_estimate"]["baudrate"] == 57600
        dargv = fake.calls("decode")[-1]
        assert "--protocol-decoder-annotations=uart=rx-data:rx-warnings" in dargv
        # VCD 는 input_format=vcd 자동
        a2 = await call(c, "sigrok_uart_autodecode", case_id=cid, input_path="signals/u.vcd")
        assert a2["ok"] and a2["baudrate"] == 9600 and "Linux version" in a2["text_preview"]
        assert "--input-format=vcd" in fake.calls("decode")[-1]
        # 순수 Python 엔진
        p = await call(c, "sigrok_uart_autodecode", case_id=cid, input_path="signals/inv.sr", engine="python")
        assert p["ok"] and p["engine"] == "python" and "login:" in p["text_preview"]
        # 보드레이트 강제
        f = await call(c, "sigrok_uart_autodecode", case_id=cid, input_path="signals/inv.sr", baudrate=115200, engine="python")
        assert f["baudrate_source"] == "user" and f["printable_ratio"] < 0.9


async def test_garbage_output_is_handled(fake):
    from sigrok_mcp.server import server

    fake.mode("garbage")
    async with Client(server) as c:
        r = await call(c, "sigrok_version")
        assert "_error" in r and "sigrok_bad_output" in r["_error"]
        r = await call(c, "sigrok_scan")
        assert r["ok"] and r["count"] == 0


async def test_tool_missing_and_python_fallback(workspace, tmp_path, monkeypatch):
    from pweh.runtime import reset_runtimes
    from sigrok_mcp.server import server

    monkeypatch.setenv("PWEH_SIGROK_CLI", str(tmp_path / "does-not-exist"))
    monkeypatch.setenv("PATH", str(tmp_path / "emptybin"))
    reset_runtimes()
    cid = make_case()
    write_uart_sr(case_dir(cid) / "signals" / "b.sr", BOOT_BANNER, baud=115200, samplerate=1_000_000)
    async with Client(server) as c:
        r = await call(c, "sigrok_version")
        assert "_error" in r and "tool_missing" in r["_error"] and "PWEH_SIGROK_CLI" in r["_error"]
        e = await call(c, "sigrok_estimate_baud", case_id=cid, input_path="signals/b.sr", channel="RX")
        assert e["baudrate"] == 115200
        a = await call(c, "sigrok_uart_autodecode", case_id=cid, input_path="signals/b.sr")
        assert a["ok"] and a["engine"] == "python" and "U-Boot" in a["text_preview"]
        assert any("순수 Python" in w for w in a["warnings"])
        a = await call(c, "sigrok_uart_autodecode", case_id=cid, input_path="signals/b.sr", engine="sigrok")
        assert "_error" in a and "tool_missing" in a["_error"]
        fi = await call(c, "sigrok_file_info", case_id=cid, input_path="signals/b.sr")
        assert fi["ok"] and fi["total_samples"] > 0


async def test_sigrok_mcp_stdio(fake, tmp_path):
    cid = make_case()
    write_uart_sr(case_dir(cid) / "signals" / "s.sr", BOOT_BANNER, baud=115200, samplerate=1_000_000)
    env = {"PWEH_CONFIG": str(fake.workspace["config"]), "PWEH_SIGROK_CLI": str(fake.exe), "FAKE_SIGROK_LOG": str(fake.log),
           "FAKE_SIGROK_MODE": "normal"}
    params = stdio_params("sigrok_mcp", env=env)
    async with Client(params, read_timeout_seconds=60) as c:
        tools = {t.name for t in (await c.list_tools()).tools}
        assert {"sigrok_capture", "sigrok_estimate_baud", "sigrok_job_status"} <= tools
        v = await call(c, "sigrok_version")
        assert v["ok"] and v["sigrok_cli"] == "0.7.2"
        e = await call(c, "sigrok_estimate_baud", case_id=cid, input_path="signals/s.sr", channel="RX")
        assert e["baudrate"] == 115200
        r = await call(c, "sigrok_capture", case_id=cid, driver="demo", samples=500)
        assert r["ok"] and r["path"].startswith("signals/capture-demo-")


async def test_decode_and_autodecode_background_jobs(fake):
    from sigrok_mcp.server import server

    cid = make_case()
    cdir = case_dir(cid)
    write_uart_sr(cdir / "signals" / "bg.sr", BOOT_BANNER, baud=115200, samplerate=1_000_000)
    async with Client(server) as c:
        r = await call(c, "sigrok_decode", case_id=cid, input_path="signals/bg.sr", decoders="uart:rx=RX:baudrate=115200",
                       annotations="uart=rx-data", background=True)
        assert r["status"] == "started" and r["planned_output"] == "signals/bg.uart.txt"
        st = await _wait_job(c, r["job_id"])
        assert st["status"] == "succeeded", st
        assert st["result"]["lines_total"] == len(BOOT_BANNER) and (cdir / "signals" / "bg.uart.txt").stat().st_size > 0
        a = await call(c, "sigrok_uart_autodecode", case_id=cid, input_path="signals/bg.sr", background=True)
        assert a["status"] == "started"
        st = await _wait_job(c, a["job_id"])
        assert st["status"] == "succeeded", st
        assert "U-Boot 2016.11" in st["result"]["text_preview"] and st["result"]["uart_estimate"]["baudrate"] == 115200
        # 지원하지 않는 형식
        (cdir / "signals" / "x.bin").write_bytes(b"\x00" * 100)
        e = await call(c, "sigrok_uart_autodecode", case_id=cid, input_path="signals/x.bin")
        assert "_error" in e and "srzip" in e["_error"]


async def test_decode_output_cap_keeps_truncated_output(fake, monkeypatch):
    """출력 상한에 도달하면 프로세스를 멈추되 앞부분 결과는 보존·등록하고 경고한다 (rc 가 실패값이어도)."""
    from sigrok_mcp import server as srv

    monkeypatch.setattr(srv, "MAX_DECODE_OUTPUT", 300)
    cid = make_case()
    cdir = case_dir(cid)
    write_uart_sr(cdir / "signals" / "cap.sr", BOOT_BANNER, baud=115200, samplerate=1_000_000)
    async with Client(srv.server) as c:
        r = await call(c, "sigrok_decode", case_id=cid, input_path="signals/cap.sr", decoders="uart:rx=RX:baudrate=115200",
                       annotations="uart=rx-data", samplenum=True)
        assert r["ok"] and r["output_truncated"] is True, r
        assert any("상한" in w for w in r["warnings"])
        data = (cdir / r["output_path"]).read_bytes()
        assert 0 < len(data) <= 300 and data.endswith(b"\n")
        assert r["lines_total"] == data.count(b"\n") and r["artifact"]["extra"]["truncated"] is True
        assert all(" uart-1: " in ln for ln in r["lines"])


async def test_file_info_refuses_case_forensics(fake):
    """자동 허용 sigrok 도구는 케이스의 증거 폴더(forensics/ — 카드 이미지·복구한 녹화)를 읽지 않는다."""
    from sigrok_mcp.server import server

    cid = make_case()
    cdir = case_dir(cid)
    write_uart_sr(cdir / "forensics" / "recovered" / "x-001" / "cap.sr", BOOT_BANNER[:30], baud=115200, samplerate=1_000_000)
    async with Client(server) as c:
        r = await call(c, "sigrok_file_info", case_id=cid, input_path="forensics/recovered/x-001/cap.sr")
        assert "validation_failed" in r["_error"] and "forensics" in r["_error"], r


async def test_sigrok_inputs_refuse_emu_session_files(fake):
    """자동 허용 sigrok 도구는 에뮬레이터 세션 파일(emu/ — 마스킹하지 않은 원시 콘솔)도 읽지 않는다(콘솔은 emu_read 로만).
    signals/ 의 링크로 가리켜도, signals/ 기본 위치로 찾는 짧은 이름이어도 막는다. 다른 케이스의 emu/ 는 케이스 경계에서 막힌다."""
    from sigrok_mcp.server import server

    cid = make_case()
    cdir = case_dir(cid)
    target = cdir / "emu" / "emu-001" / "cap.sr"
    write_uart_sr(target, BOOT_BANNER[:30], baud=115200, samplerate=1_000_000)
    (cdir / "signals").mkdir(exist_ok=True)
    (cdir / "signals" / "innocent.sr").symlink_to(target)
    other = case_dir(make_case("other"))
    theirs = other / "emu" / "emu-001" / "cap.sr"
    write_uart_sr(theirs, BOOT_BANNER[:30], baud=115200, samplerate=1_000_000)
    (cdir / "signals" / "theirs.sr").symlink_to(theirs)
    async with Client(server) as c:
        for path in ("emu/emu-001/cap.sr", str(target), "signals/innocent.sr", "innocent.sr"):
            r = await call(c, "sigrok_file_info", case_id=cid, input_path=path)
            assert "validation_failed" in r["_error"] and "emu/" in r["_error"] and "emu_read" in r["_error"], (path, r)
        r = await call(c, "sigrok_decode", case_id=cid, input_path="signals/innocent.sr", decoders="uart:rx=RX:baudrate=115200")
        assert "validation_failed" in r["_error"] and "emu/" in r["_error"], r
        for path in ("signals/theirs.sr", str(theirs)):
            r = await call(c, "sigrok_file_info", case_id=cid, input_path=path)
            assert "_error" in r, (path, r)
    assert not any("emu-001" in a or "innocent" in a or "theirs" in a for argv in fake.calls() for a in argv), fake.calls()
