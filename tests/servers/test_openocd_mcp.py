"""openocd-mcp 서버 테스트: 가짜 OpenOCD(TCL 서버/실행 파일)로 모든 도구, 작업(job), 안전 게이트를 검증한다."""

from __future__ import annotations

import hashlib
import json
import os
import sys
import time
from pathlib import Path

import pytest
from mcp import Client

from .fake_openocd import FakeOpenOCD
from mcp_helpers import call, stdio_params

pytestmark = pytest.mark.anyio

FAKE_PATH = Path(__file__).resolve().parent / "fake_openocd.py"


@pytest.fixture
def anyio_backend():
    return "asyncio"


@pytest.fixture(autouse=True)
def _cleanup_sessions():
    yield
    from openocd_mcp.session import REGISTRY

    REGISTRY.shutdown_all()


@pytest.fixture
def fake():
    srv = FakeOpenOCD()
    srv.start()
    yield srv
    srv.stop()


def _new_case(auth, title="lab camera") -> str:
    from pweh.runtime import get_runtime

    return get_runtime("openocd-mcp").cases.create(title=title, authorization=auth).id


def _case(case_id: str):
    from pweh.runtime import get_runtime

    return get_runtime("openocd-mcp").cases.get(case_id)


async def _wait_job(c, job_id: str, timeout: float = 30.0) -> dict:
    deadline = time.monotonic() + timeout
    while True:
        st = await call(c, "openocd_job_status", job_id=job_id, wait_seconds=1)
        assert "_error" not in st, st
        if st["status"] not in ("queued", "running", "cancelling"):
            return st
        assert time.monotonic() < deadline, st


def _executed_names(fake: FakeOpenOCD) -> list[str]:
    return [" ".join(x) for x in fake.dev.executed]


# ---------------------------------------------------------------------------
# 연결 + 조회 + 실행 제어
# ---------------------------------------------------------------------------


async def test_attach_and_readonly_tools(workspace, auth, fake):
    from openocd_mcp.server import server

    cid = _new_case(auth)
    async with Client(server) as c:
        r = await call(c, "openocd_attach", case_id=cid, tcl_port=fake.port)
        assert r["ok"] and r["mode"] == "attached" and "xPack" in r["version"]
        assert r["targets"][0]["name"] == "cam.cpu" and r["targets"][0]["state"] == "running"

        sc = await call(c, "openocd_scan_chain", case_id=cid)
        assert sc["ok"] and sc["count"] == 1
        tap = sc["taps"][0]
        assert tap["tap_name"] == "cam.cpu" and tap["idcode"] == "0x07926f0f" and tap["irlen"] == 4 and not tap["mismatch"]

        tg = await call(c, "openocd_targets", case_id=cid)
        assert tg["current"] == "cam.cpu" and tg["targets"][0]["type"] == "arm926ejs"

        st = await call(c, "openocd_status", case_id=cid)
        assert st["active"] and st["alive"] and st["target_state"] == "running" and st["mode"] == "attached"

        regs = await call(c, "openocd_read_registers", case_id=cid)
        assert regs["ok"] and regs["registers"][0]["value"] is None and regs["notes"]

        h = await call(c, "openocd_halt", case_id=cid)
        assert h["ok"] and h["state"] == "halted" and "target halted" in h["messages"]

        regs = await call(c, "openocd_read_registers", case_id=cid)
        by = {x["name"]: x for x in regs["registers"]}
        assert by["pc"]["value"] == "0x80008000" and by["cpsr"]["value"] == "0x600001d3"
        snap = _case(cid).dir / regs["snapshot_path"]
        assert snap.exists() and json.loads(snap.read_text())["registers"]

        one = await call(c, "openocd_read_registers", case_id=cid, names=["pc", "nosuch"], save=False)
        assert one["registers"][0]["value"] == "0x80008000" and one["registers"][1]["value"] is None

        mem = await call(c, "openocd_read_memory", case_id=cid, address="0x80000000", count=8)
        expect = bytes(fake.dev.regions[0].data[:32])
        assert mem["ok"] and mem["bytes_hex"] == expect.hex() and mem["endian"] == "little"
        assert mem["values"][0] == "0x" + expect[:4][::-1].hex() and mem["hexdump"][0].startswith("80000000")
        mb = await call(c, "openocd_read_memory", case_id=cid, address=0x80000001, count=5, width=8)
        assert mb["bytes_hex"] == bytes(fake.dev.regions[0].data[1:6]).hex()
        too_big = await call(c, "openocd_read_memory", case_id=cid, address=0x80000000, count=4096)
        assert "_error" in too_big and "dump_memory_start" in too_big["_error"]
        bad = await call(c, "openocd_read_memory", case_id=cid, address=0x10, count=4)
        assert bad["ok"] is False and bad["status"] == "tcl_error" and any(d["code"] == "memory_read_failed" for d in bad["diagnosis"])

        fb = await call(c, "openocd_flash_banks", case_id=cid, info=True)
        assert fb["count"] == 1 and fb["banks"][0]["name"] == "cam.flash" and fb["banks"][0]["size"] == 256 * 1024
        assert fb["banks"][0]["target"] == "cam.cpu" and len(fb["banks"][0]["info"]["sectors"]) == 4

        cmd = await call(c, "openocd_command", case_id=cid, command="targets")
        assert cmd["ok"] and "cam.cpu" in cmd["output"] and cmd["classification"]["risk"] == "interact"
        err = await call(c, "openocd_command", case_id=cid, command="no_such_cmd")
        assert err["ok"] is False and err["status"] == "tcl_error" and "invalid command name" in err["error"]
        cap = await call(c, "openocd_command", case_id=cid, command="capture {echo hello}")
        assert cap["ok"] and cap["output"] == "hello"  # 끝 개행은 0.12.0 호환을 위해 제거

        rs = await call(c, "openocd_reset", case_id=cid, mode="init")
        assert rs["ok"] and rs["state"] == "halted" and "tap/device found" in rs["messages"]
        rr = await call(c, "openocd_resume", case_id=cid)
        assert rr["ok"] and rr["state"] == "running"

        stop = await call(c, "openocd_stop", case_id=cid)
        assert stop["ok"] and stop["mode"] == "attached" and stop["method"] == "disconnect"
        assert not fake.shutdown_requested.is_set()
        st2 = await call(c, "openocd_status", case_id=cid)
        assert st2["active"] is False

    audit = (_case(cid).dir / "audit.jsonl").read_text(encoding="utf-8")
    assert '"tool": "openocd_halt"' in audit and '"tool": "openocd_scan_chain"' in audit


async def test_requires_session_and_authorization(workspace, auth, fake):
    from openocd_mcp.server import server
    from pweh.runtime import get_runtime

    cid = _new_case(auth)
    noauth = get_runtime("openocd-mcp").cases.create(title="no auth").id
    async with Client(server) as c:
        r = await call(c, "openocd_targets", case_id=cid)
        assert "_error" in r and "openocd_start" in r["_error"]
        r = await call(c, "openocd_attach", case_id=noauth, tcl_port=fake.port)
        assert "_error" in r and "authorization_required" in r["_error"]
        r = await call(c, "openocd_attach", case_id=cid, tcl_port=fake.port)
        assert r["ok"]
        r = await call(c, "openocd_attach", case_id=cid, tcl_port=fake.port)
        assert "_error" in r and "busy" in r["_error"]


# ---------------------------------------------------------------------------
# 안전 게이트
# ---------------------------------------------------------------------------


async def test_gate_denies_destructive_by_default(workspace, auth, fake):
    from openocd_mcp.server import server

    cid = _new_case(auth)
    img = _case(cid).dir / "dumps" / "fw.bin"
    img.write_bytes(b"\x01" * 64)
    before = bytes(fake.dev.regions[0].data[:64])
    async with Client(server) as c:
        assert (await call(c, "openocd_attach", case_id=cid, tcl_port=fake.port))["ok"]
        denied_cmds = [
            "mww 0x80000000 0",
            "flash write_image erase /tmp/x.bin 0x0 bin",
            "flash read_bank 0 /etc/passwd 0 16",
            "dump_image /tmp/x.bin 0x80000000 4",
            "::mww 0x80000000 0",
            "m\\ww 0x80000000 0",
            'capture "mww 0x80000000 0"',
            "popen {id}",
        ]
        for cmd in denied_cmds:
            r = await call(c, "openocd_command", case_id=cid, command=cmd)
            assert r.get("ok") is False and r.get("status") == "denied", (cmd, r)
            assert "destructive_policy" in r["message"]
        names = _executed_names(fake)
        assert not any(n.startswith(("mww", "flash write_image", "flash read_bank", "dump_image")) for n in names), names
        assert bytes(fake.dev.regions[0].data[:64]) == before  # 메모리 그대로

        w = await call(c, "openocd_write_memory", case_id=cid, address=0x80000000, values=[1, 2])
        assert w["status"] == "denied"
        fw = await call(c, "openocd_flash_write", case_id=cid, path="dumps/fw.bin", address=0)
        assert fw["status"] == "denied"
        assert bytes(fake.dev.banks[0].data[:4]) != b"\x01\x01\x01\x01"

        bad = await call(c, "openocd_command", case_id=cid, command="echo }} ; mww 0 0 ; list {{")
        assert "_error" in bad and "중괄호" in bad["_error"]
        out_of_case = await call(c, "openocd_flash_write", case_id=cid, path="/etc/passwd", address=0)
        assert "_error" in out_of_case


async def test_modify_policy_deny_blocks_halt(workspace, auth, fake):
    from openocd_mcp.server import server

    workspace["set_safety"](modify_policy="deny")
    cid = _new_case(auth)
    async with Client(server) as c:
        assert (await call(c, "openocd_attach", case_id=cid, tcl_port=fake.port))["ok"]
        h = await call(c, "openocd_halt", case_id=cid)
        assert h["status"] == "denied" and "modify_policy" in h["message"]
        assert fake.dev.targets[0].state == "running"
        # 조회 도구는 INTERACT 만 쓰므로 modify_policy=deny 에서도 동작해야 한다
        assert (await call(c, "openocd_targets", case_id=cid))["ok"]
        assert (await call(c, "openocd_scan_chain", case_id=cid))["ok"]
        assert (await call(c, "openocd_status", case_id=cid))["target_state"] == "running"


async def test_approval_flow_write_memory(workspace, auth, fake):
    from openocd_mcp.server import server
    from pweh.runtime import get_runtime

    workspace["set_safety"](destructive_policy="approve", approval_methods=["cli"])
    cid = _new_case(auth)
    async with Client(server) as c:
        assert (await call(c, "openocd_attach", case_id=cid, tcl_port=fake.port))["ok"]
        await call(c, "openocd_halt", case_id=cid)
        args = dict(case_id=cid, address="0x80000010", values=["0xdeadbeef", 0x11223344])
        r1 = await call(c, "openocd_write_memory", **args)
        assert r1["status"] == "approval_required" and r1["approval_id"]
        ap = r1["approval_id"]
        rt = get_runtime("openocd-mcp")
        rec = rt.approvals.get(ap)
        rt.approvals.decide(ap, approve=True, code=rec["code"], via="test")
        # 다른 값으로는 승인 재사용 불가
        other = await call(c, "openocd_write_memory", case_id=cid, address="0x80000010", values=[1], approval_id=ap)
        assert other["ok"] is False
        r2 = await call(c, "openocd_write_memory", **args, approval_id=ap)
        assert r2["ok"] and r2["verified"] is True, r2
        assert bytes(fake.dev.regions[0].data[0x10:0x18]) == bytes.fromhex("efbeadde44332211")
        r3 = await call(c, "openocd_write_memory", **args, approval_id=ap)
        assert r3["ok"] is False  # 1회용


async def test_custom_cfg_and_extra_commands_are_classified(workspace, auth, tmp_path, monkeypatch):
    from openocd_mcp.server import server
    from pweh.runtime import reset_runtimes

    fake_bin = _fake_bin(tmp_path)
    monkeypatch.setenv("PWEH_OPENOCD", str(fake_bin))
    reset_runtimes()
    cid = _new_case(auth)
    evil = tmp_path / "evil.cfg"
    evil.write_text("adapter driver dummy\ninit\nflash erase_sector 0 0 last\n")
    async with Client(server) as c:
        r = await call(c, "openocd_start", case_id=cid, interface_cfg=str(evil), tcl_port=0)
        assert r["status"] == "denied" and r["custom_cfgs"][0]["classification"]["risk"] == "destructive", r
        r = await call(c, "openocd_start", case_id=cid, interface_cfg="interface/dummy.cfg", extra_commands=["init", "mww 0 0"], tcl_port=0)
        assert r["status"] == "denied"
        assert not list((_case(cid).dir / "jtag").glob("openocd-*.log"))  # 프로세스가 뜨지 않음
        bad = await call(c, "openocd_start", case_id=cid, interface_cfg="interface/dummy.cfg", transport="usb")
        assert "_error" in bad and "transport" in bad["_error"]
        # 서버 cwd 기준 상대 경로로 존재하는 사용자 cfg 도 내용 분류 대상 (OpenOCD 는 상대 경로를 cwd 에서 먼저 찾는다)
        (tmp_path / "target").mkdir()
        (tmp_path / "target" / "cam.cfg").write_text("flash erase_sector 0 0 last\n")
        monkeypatch.chdir(tmp_path)
        r = await call(c, "openocd_start", case_id=cid, interface_cfg="interface/dummy.cfg", target_cfg="target/cam.cfg", tcl_port=0)
        assert r["status"] == "denied" and r["custom_cfgs"][0]["path"] == str((tmp_path / "target" / "cam.cfg").resolve()), r


# ---------------------------------------------------------------------------
# 덤프 작업
# ---------------------------------------------------------------------------


async def test_dump_memory_job_dump_image(workspace, auth, fake):
    from openocd_mcp.server import server

    cid = _new_case(auth)
    async with Client(server) as c:
        assert (await call(c, "openocd_attach", case_id=cid, tcl_port=fake.port))["ok"]
        await call(c, "openocd_halt", case_id=cid)
        r = await call(c, "openocd_dump_memory_start", case_id=cid, address="0x80000000", length="256k", chunk_size="64k")
        assert r["ok"] and r["output"] == "jtag/mem-80000000-40000.bin" and r["classification"]["risk"] == "interact"
        st = await _wait_job(c, r["job_id"])
        assert st["status"] == "succeeded", st
        res = st["result"]
        case = _case(cid)
        data = (case.dir / res["path"]).read_bytes()
        assert data == bytes(fake.dev.regions[0].data[: 256 * 1024])
        assert res["sha256"] == hashlib.sha256(data).hexdigest() and res["transfer"] == "dump_image" and res["chunks"] == 4
        meta = json.loads((case.dir / res["metadata_path"]).read_text())
        assert meta["method"] == "jtag-openocd" and meta["output"]["sha256"] == res["sha256"] and meta["source"]["address"] == "0x80000000"
        assert not (case.dir / "jtag" / "mem-80000000-40000.state.json").exists()
        assert not (case.dir / "jtag" / "mem-80000000-40000.part").exists()
        arts = [a for a in case.artifacts() if a["path"] == res["path"]]
        assert arts and arts[0]["kind"] == "memory-dump" and arts[0]["sha256"] == res["sha256"]
        dumps_sent = [f for f in fake.frames if "dump_image" in f]
        assert len(dumps_sent) == 4 and all(str(case.dir / "jtag") in f for f in dumps_sent)
        # 같은 이름으로 다시 → 덮어쓰지 않음
        again = await call(c, "openocd_dump_memory_start", case_id=cid, address="0x80000000", length="256k")
        assert "_error" in again and "이미 같은 이름" in again["_error"]
        lst = await call(c, "openocd_jobs")
        assert any(j["job_id"] == r["job_id"] for j in lst["jobs"])


async def test_dump_cancel_and_resume(workspace, auth, fake):
    from openocd_mcp.server import server

    cid = _new_case(auth)
    total = 2 * 1024 * 1024
    fake.dev.dump_delay_per_kib = 0.002  # 64 KiB 청크당 ~0.13초 → 2 MiB 는 ~4초
    async with Client(server) as c:
        assert (await call(c, "openocd_attach", case_id=cid, tcl_port=fake.port))["ok"]
        await call(c, "openocd_halt", case_id=cid)
        r = await call(c, "openocd_dump_memory_start", case_id=cid, address=0x80000000, length=total, output_name="ram.bin")
        jid = r["job_id"]
        deadline = time.monotonic() + 20
        while True:
            st = await call(c, "openocd_job_status", job_id=jid)
            if (st.get("done") or 0) >= 128 * 1024:
                break
            assert time.monotonic() < deadline, st
            time.sleep(0.05)
        # 작업 중에는 MODIFY 도구 차단, 조회 도구는 허용
        h = await call(c, "openocd_halt", case_id=cid)
        assert "_error" in h and "busy" in h["_error"]
        raw = await call(c, "openocd_command", case_id=cid, command="reset halt")
        assert "_error" in raw and "busy" in raw["_error"]
        dup = await call(c, "openocd_dump_memory_start", case_id=cid, address=0x80000000, length=4096, output_name="other")
        assert "_error" in dup and "busy" in dup["_error"]
        assert (await call(c, "openocd_targets", case_id=cid))["ok"]
        cancel = await call(c, "openocd_job_cancel", job_id=jid)
        assert cancel["ok"]
        st = await _wait_job(c, jid)
        assert st["status"] == "cancelled"
        case = _case(cid)
        state = json.loads((case.dir / "jtag" / "ram.state.json").read_text())
        part_size = (case.dir / "jtag" / "ram.part").stat().st_size
        assert state["done"] == part_size and 0 < part_size < total
        # 다른 파라미터로 같은 이름 → 거부, resume=false 가 아니면 진행분 보호
        clash = await call(c, "openocd_dump_memory_start", case_id=cid, address=0x80001000, length=total, output_name="ram")
        assert "_error" in clash and "진행 중인 다른 덤프" in clash["_error"]
        fake.dev.dump_delay_per_kib = 0.0
        r2 = await call(c, "openocd_dump_memory_start", case_id=cid, address=0x80000000, length=total, output_name="ram")
        assert r2["ok"] and r2["resume_from"] == part_size
        st2 = await _wait_job(c, r2["job_id"])
        assert st2["status"] == "succeeded" and st2["result"]["resumed_from"] == part_size
        data = (case.dir / "jtag" / "ram.bin").read_bytes()
        assert data == bytes(fake.dev.regions[0].data[:total])


async def test_dump_fallback_to_read_memory_when_file_not_visible(workspace, auth, fake):
    from openocd_mcp.server import server

    cid = _new_case(auth)
    fake.dev.dump_image_writes_file = False  # 원격 OpenOCD 처럼 파일이 보이지 않음
    async with Client(server) as c:
        assert (await call(c, "openocd_attach", case_id=cid, tcl_port=fake.port))["ok"]
        await call(c, "openocd_halt", case_id=cid)
        r = await call(c, "openocd_dump_memory_start", case_id=cid, address=0x80000002, length=10000, chunk_size=4096, output_name="unaligned")
        st = await _wait_job(c, r["job_id"])
        assert st["status"] == "succeeded", st
        res = st["result"]
        assert res["transfer"] == "read_memory" and res["transfer_switches"]
        data = (_case(cid).dir / res["path"]).read_bytes()
        assert data == bytes(fake.dev.regions[0].data[2 : 2 + 10000])


async def test_dump_retry_verify_and_failure_modes(workspace, auth, fake):
    from openocd_mcp.server import server

    cid = _new_case(auth)
    async with Client(server) as c:
        assert (await call(c, "openocd_attach", case_id=cid, tcl_port=fake.port))["ok"]
        # 1) 타깃이 실행 중 → 재시도 없이 실패 + halt 힌트, 부분 결과 위치 안내
        r = await call(c, "openocd_dump_memory_start", case_id=cid, address=0x80000000, length=8192, output_name="running")
        st = await _wait_job(c, r["job_id"])
        assert st["status"] == "failed" and "halt" in st["error"]["hint"] and st["error"]["data"]["partial"].endswith("running.part")
        await call(c, "openocd_halt", case_id=cid)
        # 2) 일시적 읽기 실패 → 재시도 후 성공
        fake.dev.transient_read_failures = 1
        r = await call(c, "openocd_dump_memory_start", case_id=cid, address=0x80000000, length=8192, chunk_size=4096, output_name="retry")
        st = await _wait_job(c, r["job_id"])
        assert st["status"] == "succeeded" and st["result"]["retries"] == 1
        # 3) verify: 첫 읽기 손상 → 재읽기 불일치 감지 → 재시도 → 정상
        fake.dev.corrupt_next_reads = 1
        r = await call(c, "openocd_dump_memory_start", case_id=cid, address=0x80000000, length=4096, chunk_size=4096, output_name="verified", verify=True)
        st = await _wait_job(c, r["job_id"])
        assert st["status"] == "succeeded" and st["result"]["retries"] >= 1
        assert (_case(cid).dir / "jtag" / "verified.bin").read_bytes() == bytes(fake.dev.regions[0].data[:4096])
        # 4) 영구 읽기 실패 → 재시도 소진 후 실패, 진단 포함
        fake.dev.fail_read_ranges = [(0x80002000, 0x80003000)]
        r = await call(c, "openocd_dump_memory_start", case_id=cid, address=0x80000000, length=16384, chunk_size=4096, output_name="hole", retries=1)
        st = await _wait_job(c, r["job_id"])
        assert st["status"] == "failed" and st["error"]["data"]["done"] == 0x2000
        assert any(d["code"] == "memory_read_failed" for d in st["error"]["data"]["diagnosis"])


async def test_dump_job_refuses_unsafe_planned_commands(workspace, auth, fake, monkeypatch):
    from openocd_mcp import dumps
    from openocd_mcp.server import server

    cid = _new_case(auth)
    monkeypatch.setattr(dumps, "_dump_image_cmd", lambda path, addr, n: f"dump_image {{/tmp/outside-case.bin}} 0x{addr:x} 0x{n:x}")
    async with Client(server) as c:
        assert (await call(c, "openocd_attach", case_id=cid, tcl_port=fake.port))["ok"]
        r = await call(c, "openocd_dump_memory_start", case_id=cid, address=0x80000000, length=4096)
        assert "_error" in r and "safety_denied" in r["_error"]
        assert not any("dump_image" in f for f in fake.frames)


async def test_flash_read_job(workspace, auth, fake):
    from openocd_mcp.server import server

    cid = _new_case(auth)
    async with Client(server) as c:
        assert (await call(c, "openocd_attach", case_id=cid, tcl_port=fake.port))["ok"]
        r = await call(c, "openocd_flash_read_start", case_id=cid, bank=0, verify=True, chunk_size="64k")
        assert r["ok"] and r["output"] == "dumps/flash-cam.flash-0-40000.bin" and r["flash"]["driver"] == "fake_spi"
        st = await _wait_job(c, r["job_id"])
        assert st["status"] == "succeeded", st
        case = _case(cid)
        data = (case.dir / st["result"]["path"]).read_bytes()
        assert data == bytes(fake.dev.banks[0].data)
        meta = json.loads((case.dir / st["result"]["metadata_path"]).read_text())
        assert meta["kind"] == "flash-dump" and meta["source"]["type"] == "flash" and meta["verification"]["reread"] is True
        arts = [a for a in case.artifacts() if a["path"] == st["result"]["path"]]
        assert arts[0]["kind"] == "flash-dump"
        assert sum("flash verify_bank" in f for f in fake.frames) == 4
        # 범위 지정 + 범위 밖
        r = await call(c, "openocd_flash_read_start", case_id=cid, bank="cam.flash", offset="0x1000", length=4096, output_name="part")
        st = await _wait_job(c, r["job_id"])
        assert (case.dir / "dumps" / "part.bin").read_bytes() == bytes(fake.dev.banks[0].data[0x1000:0x2000])
        bad = await call(c, "openocd_flash_read_start", case_id=cid, bank=0, offset="0x40000")
        assert "_error" in bad and "offset" in bad["_error"]
        nob = await call(c, "openocd_flash_read_start", case_id=cid, bank=5)
        assert nob["ok"] is False


async def test_version_profiles_v012_and_v011(workspace, auth):
    from openocd_mcp.server import server

    for profile in ("v0.12.0", "v0.11.0"):
        with FakeOpenOCD(profile=profile) as fk:
            cid = _new_case(auth, title=f"p-{profile}")
            async with Client(server) as c:
                r = await call(c, "openocd_attach", case_id=cid, tcl_port=fk.port)
                assert r["ok"] and r["version"].startswith("Open On-Chip Debugger 0.1"), r
                assert (await call(c, "openocd_scan_chain", case_id=cid))["taps"][0]["idcode"] == "0x07926f0f"
                assert (await call(c, "openocd_targets", case_id=cid))["targets"][0]["state"] == "running"
                await call(c, "openocd_halt", case_id=cid)
                mem = await call(c, "openocd_read_memory", case_id=cid, address=0x80000000, count=4)
                assert mem["ok"] and mem["bytes_hex"] == bytes(fk.dev.regions[0].data[:16]).hex(), mem
                if profile == "v0.11.0":
                    assert mem["method"] == "mdw"
                err = await call(c, "openocd_command", case_id=cid, command="mdw 0x10 1")
                assert err["ok"] is False and err["code"] != 0
                fb = await call(c, "openocd_flash_banks", case_id=cid)
                assert fb["banks"][0]["target"] == "cam.cpu"
                fk.dev.dump_image_writes_file = False
                r = await call(c, "openocd_dump_memory_start", case_id=cid, address=0x80000000, length=8192, chunk_size=4096)
                st = await _wait_job(c, r["job_id"])
                assert st["status"] == "succeeded", st
                assert st["result"]["transfer"] == ("md" if profile == "v0.11.0" else "read_memory")
                assert (_case(cid).dir / st["result"]["path"]).read_bytes() == bytes(fk.dev.regions[0].data[:8192])
                await call(c, "openocd_stop", case_id=cid)


# ---------------------------------------------------------------------------
# 프로세스 관리 (가짜 실행 파일)
# ---------------------------------------------------------------------------


def _fake_bin(tmp_path: Path) -> Path:
    d = tmp_path / "fakebin"
    d.mkdir(exist_ok=True)
    p = d / "openocd"
    p.write_text(f'#!/bin/sh\nexec "{sys.executable}" "{FAKE_PATH}" "$@"\n')
    p.chmod(0o755)
    return p


@pytest.fixture
def fake_bin(tmp_path, monkeypatch):
    from pweh.runtime import reset_runtimes

    p = _fake_bin(tmp_path)
    monkeypatch.setenv("PWEH_OPENOCD", str(p))
    monkeypatch.delenv("FAKE_OPENOCD_MODE", raising=False)
    reset_runtimes()
    return p


async def test_start_status_stop_spawned(workspace, auth, fake_bin):
    from openocd_mcp.server import server

    cid = _new_case(auth)
    async with Client(server) as c:
        r = await call(c, "openocd_start", case_id=cid, interface_cfg="interface/dummy.cfg", transport="jtag", adapter_speed_khz=1000,
                       extra_commands=["jtag newtap cam cpu -irlen 4"], tcl_port=0)
        assert r["ok"] and r["health"] == "ok", r
        assert r["log_path"] == "jtag/openocd-1.log" and r["tcl_port"] > 0 and r["pid"]
        assert r["scan_chain"][0]["decoded"]["manufacturer"] == "ARM Ltd" and r["targets"][0]["name"] == "cam.cpu"
        argv = r["argv"]
        assert argv[-2:] == ["-c", "init"] and "transport select jtag" in argv and "jtag newtap cam cpu -irlen 4" in argv
        assert r["classification"]["risk"] == "modify"
        case = _case(cid)
        assert (case.dir / "jtag" / "openocd-1.json").exists()
        st = await call(c, "openocd_status", case_id=cid)
        assert st["alive"] and st["process"]["running"] and any("Listening on port" in ln for ln in st["log_tail"])
        h = await call(c, "openocd_halt", case_id=cid)
        assert h["state"] == "halted"
        dup = await call(c, "openocd_start", case_id=cid, interface_cfg="interface/dummy.cfg", tcl_port=0)
        assert "_error" in dup and "busy" in dup["_error"]
        assert len(list((case.dir / "jtag").glob(".openocd-1-cwd-*"))) == 1  # 실행 전용 빈 작업 디렉터리
        stop = await call(c, "openocd_stop", case_id=cid)
        assert stop["ok"] and stop["method"] == "shutdown" and stop["process"]["exit_code"] == 0, stop
        assert stop["log_artifact"]["path"] == "jtag/openocd-1.log"
        assert not list((case.dir / "jtag").glob(".openocd-1-cwd-*"))  # 비었으면 정리
        doc = json.loads((case.dir / "jtag" / "openocd-1.json").read_text())
        assert doc["stopped_at"] and doc["exit"]["exit_code"] == 0


async def test_start_failure_modes(workspace, auth, fake_bin, monkeypatch):
    from openocd_mcp.server import server

    cid = _new_case(auth)
    async with Client(server) as c:
        monkeypatch.setenv("FAKE_OPENOCD_MODE", "adapter_fail")
        r = await call(c, "openocd_start", case_id=cid, interface_cfg="interface/ftdi/tigard.cfg", tcl_port=0)
        assert r["ok"] is False and r["status"] == "start_failed" and r["reason"].startswith("process-exited")
        assert any(d["code"] == "usb_open_failed" for d in r["diagnosis"]) and r["process"]["exit_code"] == 1

        monkeypatch.setenv("FAKE_OPENOCD_MODE", "ok")
        r = await call(c, "openocd_start", case_id=cid, interface_cfg="interface/missing.cfg", tcl_port=0)
        assert r["status"] == "start_failed" and any(d["code"] == "cfg_not_found" for d in r["diagnosis"])

        monkeypatch.setenv("FAKE_OPENOCD_MODE", "hang")
        t0 = time.monotonic()
        r = await call(c, "openocd_start", case_id=cid, interface_cfg="interface/dummy.cfg", tcl_port=0, ready_timeout=3)
        assert r["status"] == "start_failed" and r["reason"] == "timeout" and time.monotonic() - t0 < 15
        assert r["process"]["running"] is False

        monkeypatch.setenv("FAKE_OPENOCD_MODE", "jtag_all_ones")
        r = await call(c, "openocd_start", case_id=cid, interface_cfg="interface/dummy.cfg", tcl_port=0)
        assert r["ok"] and r["health"] == "degraded"
        codes = {d["code"] for d in r["diagnosis"]}
        assert {"jtag_all_ones", "examine_failed"} <= codes
        assert r["scan_chain"][0]["decoded"]["valid"] is False
        assert (await call(c, "openocd_stop", case_id=cid))["method"] == "shutdown"


async def test_crash_detection_and_port_busy(workspace, auth, fake_bin, monkeypatch, fake):
    from openocd_mcp.server import server

    cid = _new_case(auth)
    async with Client(server) as c:
        busy = await call(c, "openocd_start", case_id=cid, interface_cfg="interface/dummy.cfg", tcl_port=fake.port)
        assert "_error" in busy and "openocd_attach" in busy["_error"]
        monkeypatch.setenv("FAKE_OPENOCD_MODE", "crash_after_first")
        r = await call(c, "openocd_start", case_id=cid, interface_cfg="interface/dummy.cfg", tcl_port=0)
        assert r["ok"]
        h = await call(c, "openocd_halt", case_id=cid)
        assert "_error" in h and "SIGSEGV" in h["_error"]
        st = await call(c, "openocd_status", case_id=cid)
        assert st["alive"] is False and st["process"]["signal"] == "SIGSEGV"
        stop = await call(c, "openocd_stop", case_id=cid)
        assert stop["method"] == "already-exited"
        # 죽은 세션은 새 start 를 막지 않는다
        monkeypatch.setenv("FAKE_OPENOCD_MODE", "ok")
        r2 = await call(c, "openocd_start", case_id=cid, interface_cfg="interface/dummy.cfg", tcl_port=0)
        assert r2["ok"] and r2["log_path"] == "jtag/openocd-2.log"


async def test_attach_adopts_previous_process(workspace, auth, fake_bin):
    from openocd_mcp.server import server
    from openocd_mcp.session import REGISTRY

    cid = _new_case(auth)
    async with Client(server) as c:
        r = await call(c, "openocd_start", case_id=cid, interface_cfg="interface/dummy.cfg", tcl_port=0)
        port, pid = r["tcl_port"], r["pid"]
        # 서버 재시작 흉내: 세션만 잊어버림 (프로세스는 살아 있음)
        sess = REGISTRY.remove(cid)
        sess.client.close()
        st = await call(c, "openocd_status", case_id=cid)
        assert st["active"] is False and st["previous_runs"][0]["still_running"] and st["hint"]
        a = await call(c, "openocd_attach", case_id=cid, tcl_port=port)
        assert a["ok"] and a["mode"] == "adopted" and a["session"]["process"]["pid"] == pid
        stop = await call(c, "openocd_stop", case_id=cid)
        assert stop["method"] == "shutdown"
        from openocd_mcp.process import pid_alive

        deadline = time.monotonic() + 5
        while pid_alive(pid):  # 테스트 프로세스가 실제 부모라 좀비로 남을 수 있음 → 좀비는 종료로 본다
            assert time.monotonic() < deadline, "adopted process still alive"
            time.sleep(0.05)


async def test_list_configs(workspace, tmp_path, monkeypatch):
    from openocd_mcp.server import server
    from pweh.runtime import reset_runtimes

    scripts = tmp_path / "scripts"
    for rel in ("interface/ftdi/tigard.cfg", "interface/jlink.cfg", "target/at91sam9.cfg", "board/x.cfg"):
        (scripts / rel).parent.mkdir(parents=True, exist_ok=True)
        (scripts / rel).write_text("# cfg\n")
    monkeypatch.setenv("PWEH_OPENOCD_SCRIPTS", str(scripts))
    reset_runtimes()
    async with Client(server) as c:
        r = await call(c, "openocd_list_configs", kind="interface", pattern="ftdi")
        assert r["configs"] == ["interface/ftdi/tigard.cfg"] and r["scripts_dir"] == str(scripts.resolve())
        r = await call(c, "openocd_list_configs", kind="all")
        assert r["count"] == 4


# ---------------------------------------------------------------------------
# stdio
# ---------------------------------------------------------------------------


async def test_openocd_mcp_stdio(workspace, auth, fake):
    cid = _new_case(auth)
    params = stdio_params("openocd_mcp", env={"PWEH_CONFIG": str(workspace["config"])})
    async with Client(params, read_timeout_seconds=60) as c:
        tools = {t.name for t in (await c.list_tools()).tools}
        for name in ("openocd_start", "openocd_attach", "openocd_stop", "openocd_status", "openocd_command", "openocd_scan_chain",
                     "openocd_targets", "openocd_halt", "openocd_resume", "openocd_reset", "openocd_read_registers", "openocd_read_memory",
                     "openocd_dump_memory_start", "openocd_flash_banks", "openocd_flash_read_start", "openocd_flash_write",
                     "openocd_write_memory", "openocd_job_status", "openocd_job_cancel", "openocd_jobs"):
            assert name in tools, name
        r = await call(c, "openocd_attach", case_id=cid, tcl_port=fake.port)
        assert r["ok"], r
        tg = await call(c, "openocd_targets", case_id=cid)
        assert tg["current"] == "cam.cpu"
        d = await call(c, "openocd_command", case_id=cid, command="mww 0x80000000 1")
        assert d["status"] == "denied"
        assert (await call(c, "openocd_stop", case_id=cid))["ok"]
