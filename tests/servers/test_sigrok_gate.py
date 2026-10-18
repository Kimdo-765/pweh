"""sigrok-mcp 게이트 회귀 테스트 (검토 단계).

- ftdi-la 는 범용 FTDI VID/PID 만으로 장치를 잡아(제품 문자열 확인 없음) 같은 칩의 USB-UART/JTAG 어댑터·JTAGulator 를
  LA 로 열고 커널 드라이버를 떼며 핀을 bitbang 입력으로 바꾼다. 수정 전에는 기본 허용 목록에 있어 '입력 전용(OBSERVE)'
  캡처로 그대로 실행되었다 → 기본 거부, 운영자 설정(sigrok.capture_drivers_allow)으로만 허용.
- 디코드 경로(디코드 job, uart 자동 디코드)는 sigrok-cli 를 띄우기 직전에 argv 를 분류하지 않았다 → 오프라인 명령만 실행.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest
from mcp import Client

from mcp_helpers import call
from servers.sigrok_testutil import case_dir, make_case, make_fake_sigrok, read_log
from sigrok_mcp.policy import DriverPolicy, classify_sigrok_argv
from pweh.safety import Risk

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
    monkeypatch.setenv("PWEH_SIGROK_CLI", str(exe))
    monkeypatch.setenv("FAKE_SIGROK_LOG", str(log))
    monkeypatch.setenv("FAKE_SIGROK_PIDFILE", str(tmp_path / "fake.pid"))
    monkeypatch.setenv("FAKE_SIGROK_MODE", "normal")
    reset_runtimes()
    clear_cache()
    yield SimpleNamespace(exe=exe, calls=lambda: [e["argv"] for e in read_log(log)], workspace=workspace)
    clear_cache()


def _capture_argv(exe, driver: str, out) -> list[str]:
    return [str(exe), f"--driver={driver}", "--dont-scan", "--config=samplerate=1000000", "--samples=10",
            "--output-format=srzip", f"--output-file={out}"]


def test_ftdi_la_not_allowed_by_default(tmp_path):
    pol = DriverPolicy()
    d = pol.describe("ftdi-la")
    assert d["capture_allowed"] is False and d["policy"] == "not-allowlisted" and "FTDI" in d["reason"]
    c = classify_sigrok_argv(_capture_argv("sigrok-cli", "ftdi-la", tmp_path / "x.sr"), policy=pol, allowed_output_dir=tmp_path)
    assert c.risk == Risk.DESTRUCTIVE and c.rule_id == "sigrok.driver.not_allowlisted" and "FTDI" in c.reason
    # 운영자가 명시적으로 허용하면 일반 USB LA 캡처와 같다
    ok = classify_sigrok_argv(_capture_argv("sigrok-cli", "ftdi-la", tmp_path / "x.sr"),
                              policy=DriverPolicy(extra_allow=frozenset({"ftdi-la"})), allowed_output_dir=tmp_path)
    assert ok.risk == Risk.OBSERVE
    # 제품 문자열을 확인하는 FTDI 기반 LA 드라이버는 그대로 허용
    for drv in ("chronovu-la", "ikalogic-scanaplus", "p-ols"):
        assert pol.is_allowed(drv), drv


async def test_ftdi_la_capture_and_device_info_never_invoke_cli(fake):
    from sigrok_mcp.server import server

    cid = make_case()
    async with Client(server) as c:
        r = await call(c, "sigrok_capture", case_id=cid, driver="ftdi-la", samples=100)
        assert r["ok"] is False and r["status"] == "denied" and r["gate"]["via"] == "sigrok-policy", r
        assert "approval_id" not in r
        r = await call(c, "sigrok_device_info", case_id=cid, driver="ftdi-la")
        assert r["status"] == "denied", r
        r = await call(c, "sigrok_scan", driver="ftdi-la")
        assert r["status"] == "denied", r
    assert fake.calls() == []  # 프로세스를 띄우지 않음


async def test_ftdi_la_operator_opt_in(fake, monkeypatch):
    from conftest import write_config
    from pweh.runtime import reset_runtimes
    from sigrok_mcp.server import server

    write_config(fake.workspace["root"], extra={"sigrok": {"capture_drivers_allow": ["ftdi-la"]}})
    reset_runtimes()
    cid = make_case()
    async with Client(server) as c:
        r = await call(c, "sigrok_capture", case_id=cid, driver="ftdi-la", samples=100)
        assert r["ok"], r
    assert any("--driver=ftdi-la" in a for a in fake.calls())


def test_decode_worker_refuses_non_offline_argv(fake):
    from pweh.errors import SafetyDenied
    from pweh.runtime import get_runtime
    from sigrok_mcp import server as srv

    cid = make_case()
    case = get_runtime("sigrok-mcp").cases.get(cid)
    sig = case_dir(cid) / "signals"
    sig.mkdir(parents=True, exist_ok=True)
    out, tmp = sig / "d.txt", sig / ".d.txt.partial"
    for argv in (
        _capture_argv(fake.exe, "demo", sig / "x.sr"),  # 허용 드라이버 캡처(OBSERVE)라도 디코드 경로에서는 거부
        [str(fake.exe), "--driver=korad-kaxxxxp", "--dont-scan", "--scan"],
        [str(fake.exe), "--scan"],
        [str(fake.exe), f"--input-file={sig}/x.sr", "--protocol-decoders=uart:rx=D0", "--set"],
    ):
        with pytest.raises(SafetyDenied):
            srv._decode_worker(argv, out, tmp, 10.0, lambda: False, 10, case, {})
    assert fake.calls() == []
