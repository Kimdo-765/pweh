"""jtagulator 드라이버 ↔ 시뮬레이터 테스트 (MCP 없이).

시뮬레이터는 펌웨어 문자열을 드라이버와 독립적으로 옮겨 적었으므로, 이 테스트는 드라이버의 프롬프트 판별·대화·
결과 파싱·안전 가드가 실제 펌웨어 형식에서 동작하는지 확인한다.
"""

from __future__ import annotations

import threading
import time

import pytest

from pweh.errors import DeviceError, SafetyDenied
from pweh.safety import Risk

from jtagulator_mcp import protocol as P
from jtagulator_mcp.driver import (
    JTAGulatorDriver,
    ScanSpec,
    SerialLink,
    VoltageNotDefined,
    build_known_pins_plan,
    build_scan_plan,
    build_voltage_plan,
)
from jtagulator_mcp.parsers import (
    parse_bypass_test,
    parse_device_id_listing,
    parse_gpio_reads,
    parse_jtag_blocks,
    parse_status,
    parse_txd_hits,
    parse_uart_hits,
    summarize_gpio,
    summarize_jtag,
    summarize_txd,
    summarize_uart,
)
from jtagulator_mcp.sim import JTAGulatorSim, SimConfig, SimJTAGTarget, SimPTY, SimTCPServer, SimUARTTarget


def _target_jtag() -> SimJTAGTarget:
    return SimJTAGTarget(tdi=3, tdo=2, tck=0, tms=1, trst=5, idcodes=[0x4BA00477])


def _target_uart() -> SimUARTTarget:
    return SimUARTTarget(txd=6, rxd=7, baud=115200, response=b"\r\nlogin: ")


@pytest.fixture
def make_device():
    created = []

    def factory(transport: str = "tcp", sim_cls=JTAGulatorSim, **kw):
        kw.setdefault("jtag", _target_jtag())
        kw.setdefault("uart", _target_uart())
        sim = sim_cls(SimConfig(**kw)).start()
        srv = SimPTY(sim) if transport == "pty" else SimTCPServer(sim)
        url = srv.path if transport == "pty" else srv.url
        link = SerialLink(url)
        drv = JTAGulatorDriver(link)
        created.append((sim, srv, link))
        return sim, srv, drv

    yield factory
    for sim, srv, link in created:
        link.close()
        srv.close()
        sim.stop()


def authorized(plan):
    plan.authorize(plan.worst().risk)
    return plan


def set_voltage(drv: JTAGulatorDriver, volts: str = "3.3") -> dict:
    return drv.set_voltage(volts, authorized(build_voltage_plan(volts)))


def run_scan(drv: JTAGulatorDriver, spec: ScanSpec, **kw):
    run = drv.start_scan(spec, authorized(build_scan_plan(spec)))
    kw.setdefault("should_cancel", lambda: False)
    out = drv.monitor_scan(run, **kw)
    return run, out


def uart_spec(**kw) -> ScanSpec:
    text = kw.pop("text", "\r")
    ans, probe = P.uart_probe_answer(text)
    return ScanSpec(kind="uart", uart_text=text, uart_answer=ans, uart_probe=probe, **kw)


# ---------------------------------------------------------------------------


def test_wake_banner_version_and_voltage(make_device):
    sim, _, drv = make_device()
    info = drv.resync()
    assert info["menu"] == "main" and info["banner_seen"] is True
    v = drv.version()
    assert v["firmware"] == "1.12" and v["supported"] is True
    assert "Designed by Joe Grand, Grand Idea Studio, Inc." in v["lines"]
    res = set_voltage(drv, "3.3")
    assert res["volts"] == "3.3" and res["previous"] == "Undefined" and res["vadj_warning"]
    assert sim.voltage == "3.3" and drv.voltage == "3.3"
    res = set_voltage(drv, "1.8")
    assert res["previous"] == "3.3" and sim.voltage == "1.8"
    res = set_voltage(drv, "0")
    assert res["volts"] == "0" and sim.voltage is None


def test_full_flow_over_pty(make_device):
    sim, _, drv = make_device(transport="pty")
    drv.resync()
    assert drv.version()["firmware"] == "1.12"
    set_voltage(drv, "3.3")
    run, out = run_scan(drv, ScanSpec(kind="idcode", start=0, end=7))
    assert out.ended and out.reason is None and run.permutations == 336
    best = summarize_jtag(parse_jtag_blocks(out.scan_text), "idcode")["best"]
    assert (best["tdo"], best["tck"], best["tms"]) == (2, 0, 1) and best["trst_candidates"] == [5]


@pytest.mark.parametrize("fw", ["1.12", "1.11.1", "1.10"])
def test_firmware_dialects(make_device, fw):
    sim, _, drv = make_device(firmware=fw)
    drv.resync()
    assert drv.version()["firmware"] == fw
    set_voltage(drv, "3.3")
    # IDCODE
    run, out = run_scan(drv, ScanSpec(kind="idcode", start=0, end=7))
    assert parse_status(out.scan_text, "idcode")["completed"]
    assert summarize_jtag(parse_jtag_blocks(out.scan_text), "idcode")["best"]["tdo"] == 2
    # Combined: 완료 문구가 1.12 는 'JTAG combined', 이전은 'JTAG'
    run, out = run_scan(drv, ScanSpec(kind="jtag", start=0, end=5))
    assert parse_status(out.scan_text, "jtag")["completed"]
    best = summarize_jtag(parse_jtag_blocks(out.scan_text), "jtag")["best"]
    assert (best["tdi"], best["tdo"], best["tck"], best["tms"]) == (3, 2, 0, 1)
    assert best["devices"][0]["manufacturer"] == "ARM Ltd"
    # BYPASS (알려진 핀)
    run, out = run_scan(drv, ScanSpec(kind="bypass", start=0, end=7, known_pins={"tdo": 2, "tck": 0, "tms": 1}))
    assert run.permutations == 5
    assert summarize_jtag(parse_jtag_blocks(out.scan_text), "bypass")["best"]["tdi"] == 3
    # UART: 1.10 에는 '채널 LOW' 질문이 없다
    run, out = run_scan(drv, uart_spec(start=4, end=7, known_pins={"txd": 6}, pins_low=True, pins_low_ms=1, pins_high_ms=1))
    assert run.permutations == 3
    assert ("pins_low" in run.asked) == (fw != "1.10")
    best = summarize_uart(parse_uart_hits(out.scan_text))["best"]
    assert (best["txd"], best["rxd"], best["baud"]) == (6, 7, 115200)


def test_unsupported_firmware_reported(make_device):
    _, _, drv = make_device(firmware="1.9")
    drv.resync()
    v = drv.version()
    assert v["firmware"] == "1.9" and v["supported"] is False


def test_guard_blocks_unplanned_voltage_and_desync(make_device):
    sim, _, drv = make_device()
    drv.resync()
    with pytest.raises(SafetyDenied) as ei:
        drv.send("V\r")
    assert ei.value.code == "jtagulator_key_blocked"
    assert sim.voltage is None
    # 시험용: 가드를 우회해 장치를 전압 프롬프트에 둔다 (드라이버가 상태를 잘못 안 상황을 흉내)
    mark = drv.link.end
    drv.link.write(b"V\r")
    _, ctx = drv.wait_settled(mark, 3.0)
    assert ctx.state == "voltage"
    scan_plan = authorized(build_scan_plan(ScanSpec(kind="idcode", start=0, end=7)))
    assert scan_plan.ceiling == Risk.MODIFY
    for keys in ("0\r", "3\r", "3.3\r"):
        with pytest.raises(SafetyDenied):
            drv.send(keys, plan=scan_plan)  # 스캔 답(숫자)이 전압 프롬프트로 가는 일을 막음
    # 드라이버는 메뉴로 안전하게 복귀(Ctrl-X → 범위 밖 입력)하고 전압은 그대로
    drv.ensure_menu("jtag")
    assert drv.context().menu == "jtag"
    assert sim.voltage is None
    assert not any(e.startswith("voltage:") for e in sim.events)


def test_guard_block_mid_dialog_cancels_cleanly(make_device):
    sim, _, drv = make_device()
    drv.resync()
    set_voltage(drv)
    spec = ScanSpec(kind="idcode", start=0, end=7)
    plan = build_scan_plan(spec)
    plan.steps = [s for s in plan.steps if s.state != "space"]  # 스캔 시작 단계가 계획에 없음
    plan.authorize(Risk.MODIFY)
    with pytest.raises(SafetyDenied):
        drv.start_scan(spec, plan)
    assert drv.context().state == "menu"  # 스페이스바 대기에 남겨 두지 않음
    assert not any(e.startswith("scan_start") for e in sim.events)
    assert sim.voltage == "3.3"


def test_scan_refused_by_device_without_voltage(make_device):
    sim, _, drv = make_device()
    drv.resync()
    with pytest.raises(VoltageNotDefined):
        drv.start_scan(ScanSpec(kind="idcode", start=0, end=7), authorized(build_scan_plan(ScanSpec(kind="idcode", start=0, end=7))))
    assert not any(e.startswith("scan_start") for e in sim.events)
    assert drv.context().state == "menu"


class _ExtraQuestionSim(JTAGulatorSim):
    def _get_settings(self) -> None:
        self._emit("\r\nEnter favorite color [red]: ")
        self._str_in_max(12)
        super()._get_settings()


class _WrongPermsSim(JTAGulatorSim):
    def _display_permutations(self, n: int, r: int) -> None:
        super()._display_permutations(n + 1, r)


def test_unexpected_question_is_cancelled(make_device):
    sim, _, drv = make_device(sim_cls=_ExtraQuestionSim)
    drv.resync()
    set_voltage(drv)
    with pytest.raises(DeviceError) as ei:
        drv.start_scan(ScanSpec(kind="idcode", start=0, end=7), authorized(build_scan_plan(ScanSpec(kind="idcode", start=0, end=7))))
    assert "favorite color" in str(ei.value)
    assert drv.context().state == "menu"
    assert not any(e.startswith("scan_start") for e in sim.events)


def test_permutation_mismatch_cancels_before_start(make_device):
    sim, _, drv = make_device(sim_cls=_WrongPermsSim)
    drv.resync()
    set_voltage(drv)
    with pytest.raises(DeviceError) as ei:
        drv.start_scan(ScanSpec(kind="idcode", start=0, end=7), authorized(build_scan_plan(ScanSpec(kind="idcode", start=0, end=7))))
    assert "순열" in str(ei.value)
    assert not any(e.startswith("scan_start") for e in sim.events)
    assert drv.context().state == "menu"


def test_cancel_long_bypass_scan(make_device):
    sim, _, drv = make_device(perm_delay=0.0005)
    drv.resync()
    set_voltage(drv)
    spec = ScanSpec(kind="bypass", start=0, end=23)
    t0 = time.monotonic()
    progress = []
    run, out = run_scan(drv, spec, should_cancel=lambda: time.monotonic() - t0 > 0.6, on_progress=progress.append)
    assert run.permutations == 255024
    assert out.reason == "cancelled" and out.ended
    assert parse_status(out.scan_text, "bypass")["aborted"]
    assert "scan_aborted:bypass" in sim.events
    assert progress and progress[-1]["total"] == 255024
    assert any(s["keys"] == "\n" and s["risk"] == "interact" for s in out.sent)
    # 장치는 메뉴로 돌아와 계속 응답한다
    assert drv.version()["firmware"] == "1.12"


def test_txd_scan_runs_for_duration(make_device):
    sim, _, drv = make_device()
    drv.resync()
    set_voltage(drv)
    run, out = run_scan(drv, ScanSpec(kind="uart_txd", start=0, end=7), duration=0.8)
    assert out.reason == "duration" and out.ended
    assert parse_status(out.scan_text, "uart_txd")["completed"]
    best = summarize_txd(parse_txd_hits(out.scan_text))["best"]
    assert best["txd"] == 6 and best["baud"] == 115200


def test_device_reset_mid_scan_is_detected(make_device):
    sim, _, drv = make_device(perm_delay=0.001)
    drv.resync()
    set_voltage(drv)
    spec = ScanSpec(kind="idcode", start=0, end=23)
    run = drv.start_scan(spec, authorized(build_scan_plan(spec)))
    timer = threading.Timer(0.3, sim.reset)
    timer.start()
    try:
        out = drv.monitor_scan(run, should_cancel=lambda: False, idle_timeout=1.0)
    finally:
        timer.cancel()
    assert out.reason == "stalled"
    # 중단 키(LF)가 리셋된 장치를 깨워 배너가 보인다 → 서버는 전압 상태를 버려야 함
    assert parse_status(out.scan_text, "idcode")["banner_seen"]
    assert sim.voltage is None


def test_link_drop_mid_scan(make_device):
    sim, srv, drv = make_device(perm_delay=0.001)
    drv.resync()
    set_voltage(drv)
    spec = ScanSpec(kind="idcode", start=0, end=23)
    run = drv.start_scan(spec, authorized(build_scan_plan(spec)))
    timer = threading.Timer(0.3, srv.drop_client)
    timer.start()
    try:
        out = drv.monitor_scan(run, should_cancel=lambda: False, idle_timeout=30.0)
    finally:
        timer.cancel()
    assert out.reason == "disconnected" and not out.ended
    with pytest.raises(DeviceError):
        drv.link.check()


def test_known_pin_commands(make_device):
    sim, _, drv = make_device()
    drv.resync()
    set_voltage(drv)
    pins = {"tdo": 2, "tck": 0, "tms": 1}
    text = drv.run_known_pins("D", pins, authorized(build_known_pins_plan("D", pins)))
    devs = parse_device_id_listing(text)
    assert devs and devs[0]["idcode"] == "0x4BA00477"
    assert devs[0]["firmware_detail"]["manufacturer_id"] == "0x23B"
    pins_t = {"tdi": 3, "tdo": 2, "tck": 0, "tms": 1}
    bt = parse_bypass_test(drv.run_known_pins("T", pins_t, authorized(build_known_pins_plan("T", pins_t))))
    assert bt["match"] is True and bt["device_count"] == 1
    wrong = {"tdi": 4, "tdo": 2, "tck": 0, "tms": 1}
    text = drv.run_known_pins("T", wrong, authorized(build_known_pins_plan("T", wrong)))
    assert parse_status(text)["no_device_found"]


def test_uart_printable_filter(make_device):
    sim, _, drv = make_device()
    drv.resync()
    set_voltage(drv)
    _, out_all = run_scan(drv, uart_spec(start=6, end=7))
    _, out_print = run_scan(drv, uart_spec(start=6, end=7, printable_only=True))
    all_hits = parse_uart_hits(out_all.scan_text)
    print_hits = parse_uart_hits(out_print.scan_text)
    assert len(all_hits) > len(print_hits) >= 1
    assert 115200 in {h["baud"] for h in print_hits}
    for h in print_hits:  # 남은 응답은 모두 출력 가능 문자(+CR/LF)
        data = bytes.fromhex(h["data_hex"])
        assert all(0x20 <= b <= 0x7E or b in (10, 13) for b in data)
    assert summarize_uart(print_hits)["best"]["baud"] == 115200
    assert "uart_probe:0d" in sim.events  # 프로브는 정확히 CR 1바이트


def test_gpio_read_detects_activity(make_device):
    sim, _, drv = make_device(gpio_value=0xFFFFFE)  # CH0 은 LOW 로 고정
    drv.resync()
    set_voltage(drv)
    vals = parse_gpio_reads(drv.read_gpio() + drv.read_gpio() + drv.read_gpio())
    s = summarize_gpio(vals)
    assert s["samples"] == 3 and 0 in s["low_channels"]
    assert s["toggling_channels"] == [6]  # 가상 UART 타깃의 TXD(CH6)가 송신 중


def test_resync_cancels_all_scan_chain(make_device):
    sim, _, drv = make_device()
    drv.resync()
    set_voltage(drv)
    # 시험용: 가드를 우회해 메인 'A'(전체 스캔)를 시작 — 하위 스캔마다 질문이 이어지는 최악의 대화 상태
    mark = drv.link.end
    drv.link.write(b"A\r")
    _, ctx = drv.wait_settled(mark, 3.0)
    assert ctx.kind == "start_channel"
    info = drv.resync()
    assert info["menu"] == "main"
    assert not any(e.startswith("scan_start") for e in sim.events)
    assert sim.voltage == "3.3"


def test_persistent_openocd_mode_is_exited(make_device):
    sim, _, drv = make_device(start_state="ocd", mode_exit_delay=0.3)
    info = drv.resync()
    assert info["persistent_mode_exited"] == "openocd" and info["menu"] == "jtag"
    assert drv.version()["firmware"] == "1.12"
    assert sim.voltage is None  # Set_Config_Defaults → Undefined


def test_resync_from_dialog_and_running_scan(make_device):
    sim, _, drv = make_device(perm_delay=0.001)
    drv.resync()
    set_voltage(drv)
    # 대화 도중(채널 질문)에 멈춘 상태
    mark = drv.link.end
    drv.link.write(b"J\r")
    drv.wait_settled(mark, 3.0)
    mark = drv.link.end
    drv.link.write(b"I\r")
    _, ctx = drv.wait_settled(mark, 3.0)
    assert ctx.kind == "start_channel"
    info = drv.resync()
    assert info["menu"] == "jtag"
    assert sim.voltage == "3.3"
    # 실행 중인 스캔
    spec = ScanSpec(kind="bypass", start=0, end=23)
    drv.start_scan(spec, authorized(build_scan_plan(spec)))
    time.sleep(0.3)
    info = drv.resync()
    assert info.get("aborted_running_scan") == "BYPASS"
    assert drv.context().state == "menu"


# ---------------------------------------------------------------------------
# 시뮬레이터 바인드 주소: 루프백만 (port-routing 설계 G13). 시험은 루프백이 아닌 주소에 실제로 바인드하지 않는다.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("host", ["0.0.0.0", "", "192.0.2.10", "localhost.", "[::1]", "::1", "::", "127.1"])
def test_sim_tcp_server_refuses_non_loopback_bind(host):
    sim = JTAGulatorSim(SimConfig())  # 시작하지 않음 — 검사는 소켓을 만들기 전에 끝난다
    with pytest.raises(ValueError, match="루프백"):
        SimTCPServer(sim, host)


def test_sim_tcp_server_default_is_loopback():
    sim = JTAGulatorSim(SimConfig()).start()
    srv = SimTCPServer(sim)
    try:
        assert srv.host == "127.0.0.1" and srv.lan_exposed is False and srv.url.startswith("socket://127.0.0.1:")
    finally:
        srv.close()
        sim.stop()


def _fake_sim_cli(monkeypatch):
    """main() 을 실제 바인드·대기 없이 돌리는 가짜 (SimTCPServer 인자 기록)."""
    from jtagulator_mcp import sim as simmod

    made: dict = {}

    class FakeSim:
        def __init__(self, cfg):
            made["sim_created"] = True

        def start(self):
            return self

        def stop(self):
            made["sim_stopped"] = True

    class FakeServer:
        def __init__(self, sim, host, port, *, reset_on_connect=False, allow_lan=False):
            made.update(host=host, port=port, allow_lan=allow_lan)
            self.host, self.port = host, 4321
            self.url = f"socket://{host}:4321"

        def close(self):
            made["closed"] = True

    monkeypatch.setattr(simmod, "JTAGulatorSim", FakeSim)
    monkeypatch.setattr(simmod, "SimTCPServer", FakeServer)
    monkeypatch.setattr(simmod, "_serve_until_interrupted", lambda: None)
    return simmod, made


@pytest.mark.parametrize("tcp", ["0.0.0.0:7777", "192.0.2.10:7777", "0.0.0.0:0"])
def test_sim_cli_refuses_lan_tcp_without_allow_lan(tcp, monkeypatch, capsys):
    simmod, made = _fake_sim_cli(monkeypatch)
    with pytest.raises(SystemExit) as ei:
        simmod.main(["--tcp", tcp])
    assert ei.value.code == 2
    err = capsys.readouterr().err
    assert "루프백" in err and "--allow-lan" in err
    assert made == {}  # 시뮬레이터도 서버도 만들지 않았다


@pytest.mark.parametrize("tcp", ["::1:0", "[::1]:7777", ":::0"])
def test_sim_cli_refuses_ipv6_listener_even_with_allow_lan(tcp, monkeypatch, capsys):
    """리스너는 IPv4 전용 — IPv6 주소는 bind 의 gaierror(traceback) 대신 종료 코드 2 와 분명한 메시지 (리뷰 F7)."""
    simmod, made = _fake_sim_cli(monkeypatch)
    for extra in ([], ["--allow-lan"]):
        with pytest.raises(SystemExit) as ei:
            simmod.main(["--tcp", tcp, *extra])
        assert ei.value.code == 2
        err = capsys.readouterr().err
        assert "IPv4" in err and "127.0.0.1" in err
    assert made == {}


def test_sim_cli_allow_lan_warns_on_stderr(monkeypatch, capsys):
    simmod, made = _fake_sim_cli(monkeypatch)
    assert simmod.main(["--tcp", "0.0.0.0:0", "--allow-lan"]) == 0
    out, err = capsys.readouterr()
    assert made["host"] == "0.0.0.0" and made["allow_lan"] is True and made["closed"] and made["sim_stopped"]
    assert "socket://0.0.0.0:4321" in out
    assert "경고" in err and "0.0.0.0:4321" in err and "LAN" in err and "socket://127.0.0.1:4321" in err


def test_sim_cli_loopback_does_not_warn(monkeypatch, capsys):
    simmod, made = _fake_sim_cli(monkeypatch)
    assert simmod.main(["--tcp", "127.0.0.1:0"]) == 0
    assert simmod.main([]) == 0  # 기본값도 127.0.0.1
    out, err = capsys.readouterr()
    assert made["host"] == "127.0.0.1" and made["allow_lan"] is False
    assert "경고" not in err
