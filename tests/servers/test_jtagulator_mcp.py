"""jtagulator-mcp 서버 테스트: in-memory MCP 클라이언트 + stdio 1개, 하드웨어 대신 시뮬레이터(TCP)."""

from __future__ import annotations

import json
import time

import pytest
from mcp import Client

from mcp_helpers import call, stdio_params
from pweh.runtime import get_runtime

from jtagulator_mcp.sim import JTAGulatorSim, SimConfig, SimJTAGTarget, SimTCPServer, SimUARTTarget

pytestmark = pytest.mark.anyio

SERVER = "jtagulator-mcp"


@pytest.fixture
def anyio_backend():
    return "asyncio"


@pytest.fixture
def sim_env():
    created = []

    def factory(**kw):
        kw.setdefault("jtag", SimJTAGTarget(tdi=3, tdo=2, tck=0, tms=1, trst=5, idcodes=[0x4BA00477]))
        kw.setdefault("uart", SimUARTTarget(txd=6, rxd=7, baud=115200, response=b"\r\nlogin: "))
        sim = JTAGulatorSim(SimConfig(**kw)).start()
        srv = SimTCPServer(sim)
        created.append((sim, srv))
        return sim, srv

    yield factory
    from jtagulator_mcp import server as js

    js._shutdown_all()
    for sim, srv in created:
        srv.close()
        sim.stop()


@pytest.fixture(autouse=True)
def _close_connections():
    yield
    from jtagulator_mcp import server as js

    js._shutdown_all()


def make_case(auth=None, title="JTAGulator 랩 테스트") -> str:
    return get_runtime(SERVER).cases.create(title=title, authorization=auth).id


def approve(approval_id: str) -> None:
    r = get_runtime(SERVER)
    rec = r.approvals.get(approval_id)
    r.approvals.decide(approval_id, approve=True, code=rec["code"], via="test")


async def set_voltage_approved(c, cid: str, volts: float = 3.3) -> dict:
    first = await call(c, "jtagulator_set_voltage", case_id=cid, volts=volts)
    assert first.get("status") == "approval_required", first
    approve(first["approval_id"])
    res = await call(c, "jtagulator_set_voltage", case_id=cid, volts=volts, approval_id=first["approval_id"])
    assert res.get("ok"), res
    return res


async def wait_job(c, job_id: str, timeout: float = 60.0) -> dict:
    deadline = time.monotonic() + timeout
    while True:
        st = await call(c, "jtagulator_job_status", job_id=job_id, wait_seconds=10)
        assert "_error" not in st, st
        if st["status"] not in ("queued", "running", "cancelling"):
            return st
        assert time.monotonic() < deadline, st


def case_artifacts(cid: str) -> list[dict]:
    return get_runtime(SERVER).cases.get(cid).artifacts()


# ---------------------------------------------------------------------------


async def test_tools_listed(workspace):
    from jtagulator_mcp.server import server

    async with Client(server) as c:
        names = {t.name for t in (await c.list_tools()).tools}
    for n in (
        "jtagulator_connect", "jtagulator_disconnect", "jtagulator_version", "jtagulator_set_voltage",
        "jtagulator_idcode_scan", "jtagulator_bypass_scan", "jtagulator_uart_scan", "jtagulator_job_status",
        "jtagulator_job_cancel", "jtagulator_jobs", "jtagulator_jtag_scan", "jtagulator_uart_txd_scan",
        "jtagulator_get_device_ids", "jtagulator_bypass_test", "jtagulator_status",
    ):
        assert n in names


async def test_connect_requires_authorization(workspace, sim_env):
    from jtagulator_mcp.server import server

    _, srv = sim_env()
    cid = make_case(auth=None)
    async with Client(server) as c:
        r = await call(c, "jtagulator_connect", case_id=cid, port=srv.url)
    assert "_error" in r and "authorization_required" in r["_error"]


async def test_connect_version_status_disconnect(workspace, auth, sim_env):
    from jtagulator_mcp.server import server

    sim, srv = sim_env()
    cid = make_case(auth)
    cid2 = make_case(auth, title="다른 케이스")
    async with Client(server) as c:
        r = await call(c, "jtagulator_connect", case_id=cid, port=srv.url)
        assert r["ok"] and r["firmware"] == "1.12" and r["reused"] is False, r
        assert r["resync"]["banner_seen"] is True
        assert r["connection"]["voltage"]["scans_allowed"] is False
        assert r["connection"]["transcript"] == "jtag/jtagulator-001.log"
        v = await call(c, "jtagulator_version", case_id=cid)
        assert v["firmware"] == "1.12" and v["supported"] is True
        st = await call(c, "jtagulator_status", case_id=cid)
        assert st["connected"] and st["connections"][0]["firmware"] == "1.12"
        again = await call(c, "jtagulator_connect", case_id=cid, port=srv.url)
        assert again["ok"] and again["reused"] is True
        busy = await call(c, "jtagulator_connect", case_id=cid2, port=srv.url)
        assert "_error" in busy and "busy" in busy["_error"]
        # 연결이 끊기면(USB 분리) 다른 포트로 다시 연결할 수 있다 (끊긴 연결은 정리·기록)
        sim2, srv2 = sim_env()
        srv.drop_client()
        for _ in range(50):
            if (await call(c, "jtagulator_status", case_id=cid))["connections"][0]["link_error"]:
                break
            time.sleep(0.05)
        moved = await call(c, "jtagulator_connect", case_id=cid, port=srv2.url)
        assert moved["ok"] and moved["reused"] is False and moved["connection"]["transcript"] == "jtag/jtagulator-002.log"
        d = await call(c, "jtagulator_disconnect", case_id=cid)
        assert d["ok"] and d["transcript"] == "jtag/jtagulator-002.log"
        st = await call(c, "jtagulator_status", case_id=cid)
        assert st["connected"] is False
        v = await call(c, "jtagulator_version", case_id=cid)
        assert "_error" in v and "not_found" in v["_error"]
    arts = {a["path"]: a for a in case_artifacts(cid)}
    assert "jtag/jtagulator-001.log" in arts
    log_text = (get_runtime(SERVER).cases.get(cid).dir / "jtag" / "jtagulator-001.log").read_text(encoding="utf-8")
    assert " TX " in log_text and " RX " in log_text and "JTAGulator FW 1.12" in log_text
    for line in log_text.splitlines()[1:]:
        ts, tag, payload = line.split(" ", 2)
        assert tag in ("RX", "TX", "--")
        json.loads(payload)  # 손실 없는 JSON 이스케이프


async def test_set_voltage_denied_by_default_and_scans_refused(workspace, auth, sim_env):
    from jtagulator_mcp.server import server

    sim, srv = sim_env()
    cid = make_case(auth)
    async with Client(server) as c:
        assert (await call(c, "jtagulator_connect", case_id=cid, port=srv.url))["ok"]
        r = await call(c, "jtagulator_set_voltage", case_id=cid, volts=3.3)
        assert r["ok"] is False and r["status"] == "denied", r
        assert "destructive_policy" in r["message"] and r["operator_checklist"]
        assert r["gate"]["classification"]["risk"] == "destructive"
        assert sim.voltage is None
        for tool, args in (
            ("jtagulator_idcode_scan", {"start_channel": 0, "end_channel": 7}),
            ("jtagulator_bypass_scan", {"start_channel": 0, "end_channel": 7}),
            ("jtagulator_jtag_scan", {"start_channel": 0, "end_channel": 7}),
            ("jtagulator_uart_scan", {"start_channel": 0, "end_channel": 7}),
            ("jtagulator_uart_txd_scan", {"start_channel": 0, "end_channel": 7}),
            ("jtagulator_get_device_ids", {"tdo": 2, "tck": 0, "tms": 1}),
            ("jtagulator_gpio_read", {}),
        ):
            res = await call(c, tool, case_id=cid, **args)
            assert "_error" in res and "voltage_not_set" in res["_error"], (tool, res)
    assert not any(e.startswith("scan_start") or e.startswith("voltage:") for e in sim.events)
    audit = (workspace["state_dir"] / "audit.jsonl").read_text(encoding="utf-8").splitlines()
    assert any(json.loads(l).get("tool") == "jtagulator_set_voltage" and json.loads(l).get("status") == "denied" for l in audit)


async def test_voltage_approval_flow(workspace, auth, sim_env):
    workspace["set_safety"](destructive_policy="approve", approval_methods=["cli"])
    from jtagulator_mcp.server import server

    sim, srv = sim_env()
    cid = make_case(auth)
    r = get_runtime(SERVER)
    async with Client(server) as c:
        assert (await call(c, "jtagulator_connect", case_id=cid, port=srv.url))["ok"]
        bad = await call(c, "jtagulator_set_voltage", case_id=cid, volts=1.85)
        assert "_error" in bad and "0.1 V" in bad["_error"]
        assert r.approvals.list("pending") == []  # 잘못된 값으로는 승인 레코드가 생기지 않음
        first = await call(c, "jtagulator_set_voltage", case_id=cid, volts=3.3)
        assert first["status"] == "approval_required" and first["approval_id"]
        ap = first["approval_id"]
        early = await call(c, "jtagulator_set_voltage", case_id=cid, volts=3.3, approval_id=ap)
        assert early["status"] == "approval_required"
        assert sim.voltage is None
        approve(ap)
        other = await call(c, "jtagulator_set_voltage", case_id=cid, volts=1.8, approval_id=ap)
        assert other["ok"] is False and other["status"] == "denied" and "다릅니다" in other["message"]
        assert sim.voltage is None
        ok = await call(c, "jtagulator_set_voltage", case_id=cid, volts=3.3, approval_id=ap)
        assert ok["ok"] and ok["volts"] == "3.3" and ok["previous"] == "Undefined" and ok["scans_allowed"]
        assert ok["approved_via"].startswith("approval")
        assert sim.voltage == "3.3"
        reuse = await call(c, "jtagulator_set_voltage", case_id=cid, volts=3.3, approval_id=ap)
        assert reuse["ok"] is False
        st = await call(c, "jtagulator_status", case_id=cid)
        assert st["connections"][0]["voltage"]["confirmed_volts"] == "3.3"
        # 재연결하면 서버 전압 상태는 초기화된다
        await call(c, "jtagulator_disconnect", case_id=cid)
        assert (await call(c, "jtagulator_connect", case_id=cid, port=srv.url))["connection"]["voltage"]["scans_allowed"] is False
    events = [json.loads(l) for l in (r.cases.get(cid).dir / "audit.jsonl").read_text(encoding="utf-8").splitlines()]
    assert any(e.get("event") == "jtagulator_voltage_set" and e.get("volts") == "3.3" for e in events)


async def test_voltage_approval_invalidated_by_reconnect(workspace, auth, sim_env):
    """승인했지만 아직 쓰지 않은 전압 승인은 다시 연결(재사용 포함)하면 쓸 수 없다 — 타깃이 바뀌었을 수 있음."""
    workspace["set_safety"](destructive_policy="approve", approval_methods=["cli"])
    from jtagulator_mcp.server import server

    sim, srv = sim_env()
    cid = make_case(auth)
    async with Client(server) as c:
        first = await call(c, "jtagulator_connect", case_id=cid, port=srv.url)
        token1 = first["connection"]["connection_token"]
        req = await call(c, "jtagulator_set_voltage", case_id=cid, volts=3.3)
        assert req["status"] == "approval_required"
        approve(req["approval_id"])
        again = await call(c, "jtagulator_connect", case_id=cid, port=srv.url)  # 같은 포트 재사용
        assert again["reused"] is True and again["connection"]["connection_token"] != token1
        stale = await call(c, "jtagulator_set_voltage", case_id=cid, volts=3.3, approval_id=req["approval_id"])
        assert stale["ok"] is False and stale["status"] == "denied" and "다릅니다" in stale["message"], stale
        assert sim.voltage is None
        fresh = await set_voltage_approved(c, cid, 3.3)  # 새 승인은 정상 동작
        assert fresh["volts"] == "3.3" and sim.voltage == "3.3"


async def test_scan_approval_path(workspace, auth, sim_env):
    """modify_policy=approve 일 때 스캔도 사람 승인 → 같은 인자 + approval_id 로 재호출."""
    workspace["set_safety"](destructive_policy="approve", modify_policy="approve", approval_methods=["cli"])
    from jtagulator_mcp.server import server

    sim, srv = sim_env()
    cid = make_case(auth)
    async with Client(server) as c:
        await call(c, "jtagulator_connect", case_id=cid, port=srv.url)
        await set_voltage_approved(c, cid, 3.3)
        req = await call(c, "jtagulator_idcode_scan", case_id=cid, start_channel=0, end_channel=7)
        assert req["status"] == "approval_required" and req["gate"]["classification"]["risk"] == "modify", req
        assert any(step["keys"] == " " for step in req["plan"])  # 승인 화면용 키 계획
        approve(req["approval_id"])
        other = await call(c, "jtagulator_idcode_scan", case_id=cid, start_channel=0, end_channel=6, approval_id=req["approval_id"])
        assert other["ok"] is False and other["status"] == "denied"
        assert not any(e.startswith("scan_start") for e in sim.events)
        ok = await call(c, "jtagulator_idcode_scan", case_id=cid, start_channel=0, end_channel=7, approval_id=req["approval_id"])
        assert ok["ok"] and ok["job_id"], ok
        st = await wait_job(c, ok["job_id"])
        assert st["status"] == "succeeded" and st["result"]["summary"]["best"]["tdo"] == 2


async def test_idcode_scan_job_and_artifacts(workspace, auth, sim_env):
    workspace["set_safety"](destructive_policy="approve", approval_methods=["cli"])
    from jtagulator_mcp.server import server

    sim, srv = sim_env()
    cid = make_case(auth)
    async with Client(server) as c:
        await call(c, "jtagulator_connect", case_id=cid, port=srv.url)
        await set_voltage_approved(c, cid)
        bad = await call(c, "jtagulator_idcode_scan", case_id=cid, start_channel=0, end_channel=1)
        assert "_error" in bad and "end_channel" in bad["_error"]
        r = await call(c, "jtagulator_idcode_scan", case_id=cid, start_channel=0, end_channel=7)
        assert r["ok"] and r["permutations"] == 336 and r["lower_bound_seconds"] > 0, r
        st = await wait_job(c, r["job_id"])
        assert st["status"] == "succeeded", st
        res = st["result"]
        assert res["status"] == "completed" and res["scan"] == "idcode" and res["target_voltage"] == "3.3"
        best = res["summary"]["best"]
        assert (best["tdi"], best["tdo"], best["tck"], best["tms"]) == (None, 2, 0, 1)
        assert best["trst_candidates"] == [5]
        assert best["devices"][0]["manufacturer"] == "ARM Ltd" and best["devices"][0]["idcode"] == "0x4BA00477"
        assert st["progress"] == 1.0
        assert any(t["keys"] == " " and t["risk"] == "modify" for t in res["tx"])
    case = get_runtime(SERVER).cases.get(cid)
    arts = {a["path"]: a for a in case.artifacts()}
    raw, js = res["artifacts"]["raw_log"], res["artifacts"]["result_json"]
    assert raw == "jtag/jtagulator-001-idcode-1.log" and js == "jtag/jtagulator-001-idcode-1.json"
    assert raw in arts and js in arts and "jtag/jtagulator-001.log" in arts
    raw_text = (case.dir / raw).read_bytes().decode("latin-1")
    assert "Enter starting channel" in raw_text and "IDCODE scan complete." in raw_text
    saved = json.loads((case.dir / js).read_text(encoding="utf-8"))
    assert saved["summary"]["best"]["tdo"] == 2 and saved["schema"] == "pweh.jtagulator-scan/v1"


async def test_jtag_bypass_and_known_pin_tools(workspace, auth, sim_env):
    workspace["set_safety"](destructive_policy="approve", approval_methods=["cli"])
    from jtagulator_mcp.server import server

    sim, srv = sim_env()
    cid = make_case(auth)
    async with Client(server) as c:
        await call(c, "jtagulator_connect", case_id=cid, port=srv.url)
        await set_voltage_approved(c, cid, 1.8)
        r = await call(c, "jtagulator_jtag_scan", case_id=cid, start_channel=0, end_channel=5)
        st = await wait_job(c, r["job_id"])
        best = st["result"]["summary"]["best"]
        assert (best["tdi"], best["tdo"], best["tck"], best["tms"]) == (3, 2, 0, 1)
        bad = await call(c, "jtagulator_bypass_scan", case_id=cid, start_channel=0, end_channel=7, known_pins={"tdo": 9})
        assert "_error" in bad
        r = await call(c, "jtagulator_bypass_scan", case_id=cid, start_channel=0, end_channel=7,
                       known_pins={"tdo": 2, "tck": 0, "tms": 1})
        assert r["permutations"] == 5
        st = await wait_job(c, r["job_id"])
        best = st["result"]["summary"]["best"]
        assert best["tdi"] == 3 and best["device_count"] == 1
        g = await call(c, "jtagulator_gpio_read", case_id=cid, samples=4, interval_ms=10)
        assert g["ok"] and g["samples"] == 4 and g["toggling_channels"] == [6], g
        assert g["artifacts"]["result_json"].endswith(".json")
        d = await call(c, "jtagulator_get_device_ids", case_id=cid, tdo=2, tck=0, tms=1)
        assert d["ok"] and d["count"] == 1 and d["devices"][0]["manufacturer"] == "ARM Ltd"
        t = await call(c, "jtagulator_bypass_test", case_id=cid, tdi=3, tdo=2, tck=0, tms=1)
        assert t["ok"] and t["match"] is True and t["device_count"] == 1
        dup = await call(c, "jtagulator_bypass_test", case_id=cid, tdi=3, tdo=3, tck=0, tms=1)
        assert "_error" in dup and "겹칩니다" in dup["_error"]
    arts = {a["path"] for a in case_artifacts(cid)}
    for kind in ("-device-ids-", "-bypass-test-", "-gpio-"):
        assert any(kind in p and p.endswith(".json") for p in arts), (kind, arts)
        assert any(kind in p and p.endswith(".log") for p in arts), (kind, arts)


async def test_uart_scans_and_dangerous_probe(workspace, auth, sim_env):
    workspace["set_safety"](destructive_policy="approve", approval_methods=["cli"])
    from jtagulator_mcp.server import server

    sim, srv = sim_env()
    cid = make_case(auth)
    async with Client(server) as c:
        await call(c, "jtagulator_connect", case_id=cid, port=srv.url)
        await set_voltage_approved(c, cid)
        r = await call(c, "jtagulator_uart_txd_scan", case_id=cid, start_channel=0, end_channel=7, duration_seconds=1.0)
        st = await wait_job(c, r["job_id"])
        assert st["status"] == "succeeded" and st["result"]["status"] == "completed"
        assert st["result"]["summary"]["best"]["txd"] == 6 and st["result"]["summary"]["best"]["baud"] == 115200
        r = await call(c, "jtagulator_uart_scan", case_id=cid, start_channel=4, end_channel=7, text="\\r")
        assert r["permutations"] == 12 and r["text_hex"] == "0D"  # 이중 이스케이프된 '\r' 도 CR 로 해석
        st = await wait_job(c, r["job_id"])
        best = st["result"]["summary"]["best"]
        assert (best["txd"], best["rxd"], best["baud"], best["confidence"]) == (6, 7, 115200, "high")
        assert st["result"]["options"]["text_hex"] == "0D"
        before = list(sim.events)
        danger = await call(c, "jtagulator_uart_scan", case_id=cid, start_channel=4, end_channel=7, text="sf erase 0 1000\r")
        assert "_error" in danger and "DESTRUCTIVE" in danger["_error"]
        assert sim.events == before  # 장치에 아무것도 보내지 않음
        assert get_runtime(SERVER).approvals.list("pending") == []
        long_text = await call(c, "jtagulator_uart_scan", case_id=cid, start_channel=4, end_channel=7, text="x" * 17)
        assert "_error" in long_text


async def test_cancel_busy_and_disconnect(workspace, auth, sim_env):
    workspace["set_safety"](destructive_policy="approve", approval_methods=["cli"])
    from jtagulator_mcp.server import server

    sim, srv = sim_env(perm_delay=0.0005)
    cid = make_case(auth)
    async with Client(server) as c:
        await call(c, "jtagulator_connect", case_id=cid, port=srv.url)
        await set_voltage_approved(c, cid)
        r = await call(c, "jtagulator_bypass_scan", case_id=cid, start_channel=0, end_channel=23)
        assert r["ok"] and r["permutations"] == 255024 and r["lower_bound_seconds"] > 3600
        job_id = r["job_id"]
        time.sleep(0.3)
        for tool, args in (
            ("jtagulator_version", {}),
            ("jtagulator_set_voltage", {"volts": 3.3}),
            ("jtagulator_idcode_scan", {"start_channel": 0, "end_channel": 7}),
        ):
            res = await call(c, tool, case_id=cid, **args)
            assert "_error" in res and "busy" in res["_error"], (tool, res)
        st = await call(c, "jtagulator_status", case_id=cid)
        assert st["connections"][0]["active_job_id"] == job_id
        cancel = await call(c, "jtagulator_job_cancel", job_id=job_id)
        assert cancel["ok"]
        st = await wait_job(c, job_id)
        assert st["status"] == "cancelled" and st["result"]["status"] == "cancelled"
        assert st["result"]["device"]["aborted"] is True
        assert "scan_aborted:bypass" in sim.events
        v = await call(c, "jtagulator_version", case_id=cid)
        assert v["firmware"] == "1.12"
        # 실행 중 스캔이 있는 상태에서 disconnect → 먼저 중단
        r = await call(c, "jtagulator_bypass_scan", case_id=cid, start_channel=0, end_channel=23)
        time.sleep(0.3)
        d = await call(c, "jtagulator_disconnect", case_id=cid)
        assert d["ok"] and d["cancelled_job"] == r["job_id"] and d["cancelled_job_status"] == "cancelled"
    saved = json.loads((get_runtime(SERVER).cases.get(cid).dir / st["result"]["artifacts"]["result_json"]).read_text(encoding="utf-8"))
    assert saved["status"] == "cancelled"


async def test_jtagulator_mcp_stdio(workspace, auth, sim_env):
    sim, srv = sim_env()
    cid = make_case(auth)
    params = stdio_params("jtagulator_mcp", env={"PWEH_CONFIG": str(workspace["config"])})
    async with Client(params, read_timeout_seconds=60) as c:
        names = {t.name for t in (await c.list_tools()).tools}
        assert "jtagulator_connect" in names and "jtagulator_set_voltage" in names
        r = await call(c, "jtagulator_connect", case_id=cid, port=srv.url)
        assert r["ok"] and r["firmware"] == "1.12", r
        v = await call(c, "jtagulator_set_voltage", case_id=cid, volts=3.3)
        assert v["status"] == "denied"
        d = await call(c, "jtagulator_disconnect", case_id=cid)
        assert d["ok"]
    assert sim.voltage is None
