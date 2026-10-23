"""실제 MCP 입구와 합성 Flipper의 승인·전송·취소·원문 비노출 연결."""
from __future__ import annotations

import asyncio
import hashlib
import json
import stat
import threading
from dataclasses import replace

import pytest
from mcp import Client

from mcp_helpers import call
from pweh.errors import PwehError
from pweh.safety import GateDecision, Risk
from flipper_mcp import server as S, session as T
from .fake_flipper_cli import FakeFlipper, configure, setup

pytestmark = pytest.mark.anyio
PRIVATE = "PRIVATE_FLIPPER_INPUT_1a71"
TOOLS = {
    "flipper_connect": {"case_id", "port", "approval_id"},
    "flipper_close": {"case_id"}, "flipper_device_info": {"case_id"},
    "flipper_storage_list": {"case_id", "path"},
    "flipper_storage_pull_start": {"case_id", "flipper_path", "dest_name"},
    "flipper_job_status": {"job_id", "wait_seconds", "case_id"},
    "flipper_job_cancel": {"job_id"}, "flipper_jobs": {"active_only", "case_id"},
}


@pytest.fixture
def anyio_backend():
    return "asyncio"


@pytest.fixture
def env(setup, workspace):
    setup.workspace = workspace
    return setup


def arguments(env, tool):
    args = {"case_id": env.case.id}
    if tool == "flipper_connect":
        args["port"] = env.port
    elif tool == "flipper_storage_list":
        args["path"] = f"/ext/pweh/{env.case.id}/"
    elif tool == "flipper_storage_pull_start":
        args["flipper_path"] = f"/ext/pweh/{env.case.id}/fixture.sub"
    elif tool in ("flipper_job_status", "flipper_job_cancel"):
        args = {"job_id": "job-not-present"}
    return args


async def invoke(client, env, tool, **updates):
    args = arguments(env, tool)
    args.update(updates)
    return await call(client, tool, **args)


async def connected(client, env):
    result = await invoke(client, env, "flipper_connect")
    assert result.get("ok") and result["state"] == "ready", result
    return result


async def completed(client, env, job_id):
    for _ in range(5):
        result = await call(client, "flipper_job_status", job_id=job_id, case_id=env.case.id, wait_seconds=1)
        assert result.get("ok"), result
        if result["status"] not in ("queued", "running", "cancelling"):
            return result
    pytest.fail("합성 Flipper job이 끝나지 않음")


async def until(check):
    for _ in range(200):
        if check():
            return
        await asyncio.sleep(.01)
    pytest.fail("합성 worker의 유한 종료를 확인하지 못함")


@pytest.mark.parametrize("setup", ["posix-tty", "win-helper"], indirect=True)
async def test_actual_client_connect_list_pull_close(env, isolated_ports, caplog):
    env.fake.payload = b"PRIVATE_BINARY\0\x03\x1b[31m\r\n>: \r\nSize: 900\r\n"
    async with Client(S.server) as client:
        result = await connected(client, env)
        assert result["profile"] == "flipper-cli-1.5.1-read-v1"
        assert result["handshake"] == {"banner_seen": True, "prompt_seen": True,
            "firmware_claim_verified": False, "tx_before_banner": 0}
        assert result["route"]["backend"] == env.route.backend
        assert result["route"]["whole_device_locked"] is True
        assert env.opens[0].dtr is True and env.opens[0].rts is False
        assert env.fake.commands == [b"loader info", b"info device"]
        info = await invoke(client, env, "flipper_device_info")
        assert info["device"] == result["device"]
        listed = await invoke(client, env, "flipper_storage_list")
        assert listed["entries"] == [{"name": "fixture.sub", "type": "file", "size": len(env.fake.payload)}]
        assert listed["count"] == 1 and listed["listing_complete"] is True
        assert listed["filesystem_completeness_verified"] is False
        start = await invoke(client, env, "flipper_storage_pull_start", dest_name="captured.bin")
        done = await completed(client, env, start["job_id"])
        assert done["status"] == "succeeded", done
        copied = done["result"]
        art, transfer = copied["artifact"], copied["transfer"]
        assert art["path"] == "flipper/captured.bin"
        path = env.case.dir / art["path"]
        assert path.read_bytes() == env.fake.payload and stat.S_IMODE(path.stat().st_mode) == 0o444
        assert art["size"] == transfer["declared_size"] == transfer["received_size"] == len(env.fake.payload)
        assert art["sha256"] == hashlib.sha256(env.fake.payload).hexdigest()
        assert transfer["device_md5"] == transfer["host_md5"] == hashlib.md5(env.fake.payload).hexdigest()
        assert transfer["complete"] and transfer["md5_match"]
        assert not transfer["snapshot_atomic"] and not transfer["device_file_origin_verified"]
        stored = next(a for a in env.case.load()["artifacts"] if a["id"] == art["id"])
        assert stored["producer"] == "flipper-mcp" and stored["kind"] == "other"
        assert stored["extra"]["type"] == "flipper-storage-copy"
        jobs = await invoke(client, env, "flipper_jobs")
        assert len(jobs["jobs"]) == 1 and jobs["jobs"][0]["job_id"] == start["job_id"]
        closed = await invoke(client, env, "flipper_close")
        assert closed["state"] == "closed" and closed["lease_released"] and closed["worker_finished"]
        assert closed["device_command_termination_verified"] is False
        again = await invoke(client, env, "flipper_close")
        assert again["ok"] and again["already_closed"]
    visible = json.dumps([result, info, listed, done, jobs, closed]) + caplog.text
    assert "PRIVATE_BINARY" not in visible and "PRIVATE_UID" not in visible and "PRIVATE_NAME" not in visible
    assert not isolated_ports["manager"]._leases
    assert len(env.fresh_calls) >= len(env.fake.commands)


async def test_pull_artifact_is_accepted_by_existing_raw_analysis(env):
    from sdr_mcp import server as R
    env.fake.payload = (b"Filetype: Flipper SubGhz RAW File\nVersion: 1\nFrequency: 315000000\n"
        b"Preset: FuriHalSubGhzPresetOok270Async\nProtocol: RAW\nRAW_Data: 100 -200 300 -400\n")
    async with Client(S.server) as client, Client(R.server) as raw:
        await connected(client, env)
        start = await invoke(client, env, "flipper_storage_pull_start")
        done = await completed(client, env, start["job_id"])
        art = done["result"]["artifact"]
        analyzed = await call(raw, "sdr_analyze", case_id=env.case.id, artifact_id=art["id"],
                              profile="flipper-subghz-raw-v1-strict")
        assert analyzed.get("ok"), analyzed
        assert analyzed["report"]["status"] == "complete"
        assert analyzed["report"]["source"]["artifact_id"] == art["id"]
        assert analyzed["report"]["source"]["sha256"] == art["sha256"]
        for flag in ("capture_verified", "device_association_verified", "decoded", "transmitted"):
            assert analyzed["report"]["inspection"]["coverage"][flag] is False
        assert (await invoke(client, env, "flipper_close"))["ok"]


async def test_exact_public_tool_schema_and_annotations(env):
    async with Client(S.server) as client:
        tools = {tool.name: tool for tool in (await client.list_tools()).tools}
    assert set(tools) == set(TOOLS)
    for name, keys in TOOLS.items():
        schema = tools[name].input_schema
        assert set(schema["properties"]) == keys and schema["additionalProperties"] is False
        assert "ctx" not in schema["properties"]
        assert tools[name].annotations.open_world_hint is (name in ("flipper_connect", "flipper_storage_pull_start"))
    for name in ("flipper_device_info", "flipper_storage_list"):
        assert tools[name].annotations.read_only_hint is True
    assert tools["flipper_close"].annotations.read_only_hint is False


@pytest.mark.parametrize("tool", TOOLS)
@pytest.mark.parametrize("extra", ["command", PRIVATE])
async def test_all_sdk_extra_keys_are_rejected_without_raw_input(env, tool, extra, caplog):
    async with Client(S.server) as client:
        result = await invoke(client, env, tool, **{extra: PRIVATE})
    assert "flipper_invalid_input" in result.get("_error", ""), result
    assert PRIVATE not in json.dumps(result) + caplog.text
    assert not env.opens and not env.fake.writes


@pytest.mark.parametrize("tool,field,value", [
    ("flipper_connect", "case_id", 1), ("flipper_connect", "case_id", "x/" + PRIVATE),
    ("flipper_connect", "port", False), ("flipper_connect", "port", None),
    ("flipper_connect", "port", "\0" + PRIVATE), ("flipper_connect", "approval_id", 3),
    ("flipper_connect", "approval_id", "x"*129), ("flipper_close", "case_id", None),
    ("flipper_device_info", "case_id", True), ("flipper_storage_list", "path", {}),
    ("flipper_storage_list", "path", "x"*513), ("flipper_storage_pull_start", "flipper_path", []),
    ("flipper_storage_pull_start", "dest_name", False), ("flipper_storage_pull_start", "dest_name", "x"*97),
    ("flipper_job_status", "job_id", 3), ("flipper_job_status", "wait_seconds", "1"),
    ("flipper_job_status", "wait_seconds", True), ("flipper_job_cancel", "job_id", None),
    ("flipper_jobs", "active_only", "false"), ("flipper_jobs", "active_only", 0),
])
async def test_sdk_strict_types_and_lengths(env, tool, field, value, caplog):
    async with Client(S.server) as client:
        result = await invoke(client, env, tool, **{field: value})
    assert "flipper_invalid_input" in result.get("_error", ""), result
    assert PRIVATE not in json.dumps(result) + caplog.text and not env.opens


@pytest.mark.parametrize("tool", ["flipper_job_status", "flipper_job_cancel"])
async def test_common_job_missing_errors_do_not_return_id(env, tool, caplog):
    async with Client(S.server) as client:
        result = await invoke(client, env, tool, job_id="job-" + PRIVATE)
    assert "not_found" in result.get("_error", ""), result
    assert PRIVATE not in json.dumps(result) + caplog.text


@pytest.mark.parametrize("policy", ["deny", "approve"])
async def test_gate_precedes_physical_open_and_releases_pending_lease(env, isolated_ports, policy):
    env.workspace["set_safety"](modify_policy=policy)
    async with Client(S.server) as client:
        result = await invoke(client, env, "flipper_connect")
    assert result["status"] == ("denied" if policy == "deny" else "approval_required")
    assert result["gate"]["classification"]["risk"] == "modify"
    assert not env.opens and not env.fake.writes
    assert not isolated_ports["manager"]._leases and env.case.id not in T._REGISTRY


async def test_approval_exact_scope_and_signals_are_bound_then_consumed(env, isolated_ports):
    env.workspace["set_safety"](modify_policy="approve")
    async with Client(S.server) as client:
        pending = await invoke(client, env, "flipper_connect")
        aid = pending["approval_id"]
        record = S.rt().approvals.get(aid)
        S.rt().approvals.decide(aid, approve=True, code=record["code"], via="cli-tty")
        result = await invoke(client, env, "flipper_connect", approval_id=aid)
        assert result.get("ok"), result
        assert (await invoke(client, env, "flipper_close"))["ok"]
        again = await invoke(client, env, "flipper_connect", approval_id=aid)
        assert again["status"] == "denied" and len(env.opens) == 1
    assert not isolated_ports["manager"]._leases


async def test_approval_does_not_allow_changed_whole_scope(env, isolated_ports):
    env.workspace["set_safety"](modify_policy="approve")
    async with Client(S.server) as client:
        pending = await invoke(client, env, "flipper_connect")
        aid = pending["approval_id"]
        record = S.rt().approvals.get(aid)
        S.rt().approvals.decide(aid, approve=True, code=record["code"], via="cli-tty")
        env.keys = tuple(sorted((*env.keys, "synthetic-added-sibling")))
        out = await invoke(client, env, "flipper_connect", approval_id=aid)
    assert out["status"] == "denied" and not env.opens
    assert not isolated_ports["manager"]._leases


@pytest.mark.parametrize("tool", ["flipper_device_info", "flipper_storage_list", "flipper_storage_pull_start"])
async def test_read_commands_use_observe_gate_and_denial_returns_reservation(env, monkeypatch, tool):
    async with Client(S.server) as client:
        await connected(client, env)
        before = list(env.fake.commands)
        seen = []
        async def deny(**kwargs):
            seen.append(kwargs)
            assert kwargs["classification"].risk == Risk.OBSERVE
            return GateDecision(False, "denied", kwargs["classification"], "deny")
        monkeypatch.setattr(S.rt(), "authorize", deny)
        out = await invoke(client, env, tool)
        assert out["status"] == "denied" and len(seen) == 1
        assert env.fake.commands == before and not T.get_session(env.case.id)._uses
        assert (await invoke(client, env, "flipper_close"))["ok"]


async def test_revoked_case_blocks_read_but_close_still_works(env, monkeypatch):
    async with Client(S.server) as client:
        await connected(client, env)
        before = list(env.fake.commands)
        def revoked(*args, **kwargs):
            raise PwehError(PRIVATE, code="authorization_required")
        monkeypatch.setattr(S.rt(), "case", revoked)
        out = await invoke(client, env, "flipper_device_info")
        assert "authorization_required" in out["_error"] and PRIVATE not in out["_error"]
        assert env.fake.commands == before
        assert (await invoke(client, env, "flipper_close"))["ok"]


@pytest.mark.parametrize("tool", ["flipper_storage_list", "flipper_storage_pull_start"])
@pytest.mark.parametrize("path", ["/ext/other/file", "/ext/pweh/other/file", "/ext/pweh/X/../x", PRIVATE + "\n", ""])
async def test_remote_path_rejected_before_any_command(env, tool, path):
    async with Client(S.server) as client:
        await connected(client, env)
        before = list(env.fake.commands)
        out = await invoke(client, env, tool, **{"path" if tool.endswith("list") else "flipper_path": path})
        assert "flipper_invalid_input" in out.get("_error", ""), out
        assert env.fake.commands == before and not T.get_session(env.case.id)._uses
        await invoke(client, env, "flipper_close")


async def test_loader_busy_leaves_no_followup_storage_and_hides_app_name(env):
    async with Client(S.server) as client:
        await connected(client, env)
        before = len(env.fake.commands)
        env.fake.responses[b"loader info"] = b"loader info\r\nApplication: " + PRIVATE.encode() + b"\r\n\r\n>: "
        out = await invoke(client, env, "flipper_storage_list")
        assert "flipper_app_busy" in out.get("_error", ""), out
        assert PRIVATE not in out["_error"]
        assert env.fake.commands[before:] == [b"loader info"]
        assert (await invoke(client, env, "flipper_close"))["ok"]


@pytest.mark.parametrize("failure", ["md5", "generic"])
async def test_failed_job_never_registers_partial_or_exposes_exception(env, monkeypatch, failure):
    from flipper_mcp import storage
    async with Client(S.server) as client:
        await connected(client, env)
        if failure == "md5":
            env.fake.responses[b"storage md5"] = lambda command: command + b"\r\n" + b"0"*32 + b"\r\n\r\n>: "
        else:
            def bad(*a, **kw):
                raise ValueError(PRIVATE)
            monkeypatch.setattr(storage, "pull", bad)
        out = await invoke(client, env, "flipper_storage_pull_start")
        done = await completed(client, env, out["job_id"])
        assert done["status"] == "failed", done
        assert done["error"]["code"] == ("flipper_checksum_mismatch" if failure == "md5" else "flipper_failed")
        assert "traceback" not in done["error"] and PRIVATE not in json.dumps(done)
        assert env.case.load()["artifacts"] == []
        await invoke(client, env, "flipper_close")


async def test_job_start_failure_returns_reserved_use(env, monkeypatch):
    async with Client(S.server) as client:
        await connected(client, env)
        before = list(env.fake.commands)
        def failed(*a, **kw):
            raise OSError(PRIVATE)
        monkeypatch.setattr(S.rt().jobs, "start", failed)
        out = await invoke(client, env, "flipper_storage_pull_start")
        assert "flipper_failed" in out["_error"] and PRIVATE not in out["_error"]
        assert not T.get_session(env.case.id)._uses and env.fake.commands == before
        assert (await invoke(client, env, "flipper_close"))["ok"]


async def test_prepare_raw_cancel_late_owner_is_cleaned(env, monkeypatch, isolated_ports):
    entered, release, prepared = threading.Event(), threading.Event(), threading.Event()
    original = T.prepare_session
    def blocked(*args):
        entered.set()
        assert release.wait(5)
        result = original(*args)
        prepared.set()
        return result
    monkeypatch.setattr(T, "prepare_session", blocked)
    task = asyncio.create_task(S.flipper_connect(env.case.id, env.port))
    assert await asyncio.to_thread(entered.wait, 2)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    release.set()
    assert await asyncio.to_thread(prepared.wait, 2)
    await until(lambda: not T._PREPARING and env.case.id not in T._REGISTRY)
    assert not env.opens and not isolated_ports["manager"]._leases


async def test_raw_cancel_running_read_keeps_lease_until_worker_finishes(env, isolated_ports):
    entered, release = threading.Event(), threading.Event()
    async with Client(S.server) as client:
        await connected(client, env)
        def block(size):
            entered.set()
            assert release.wait(5)
        env.fake.before_read = block
        task = asyncio.create_task(S.flipper_device_info(env.case.id))
        assert await asyncio.to_thread(entered.wait, 2)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        owner = T.get_session(env.case.id)
        assert owner._uses and isolated_ports["manager"]._leases and not env.fake.closed
        release.set()
        await until(lambda: not owner._uses)
        env.fake.before_read = None
        assert (await invoke(client, env, "flipper_close"))["ok"]
    assert not isolated_ports["manager"]._leases


async def test_job_cancel_then_close_releases_after_worker(env, isolated_ports):
    entered, release = threading.Event(), threading.Event()
    async with Client(S.server) as client:
        await connected(client, env)
        def block(size):
            entered.set()
            assert release.wait(5)
        env.fake.before_read = block
        start = await invoke(client, env, "flipper_storage_pull_start")
        assert await asyncio.to_thread(entered.wait, 2)
        cancelled = await call(client, "flipper_job_cancel", job_id=start["job_id"])
        assert cancelled["status"] == "cancelling" and isolated_ports["manager"]._leases
        release.set()
        done = await completed(client, env, start["job_id"])
        assert done["status"] == "cancelled" and env.case.load()["artifacts"] == []
        env.fake.before_read = None
        assert (await invoke(client, env, "flipper_close"))["ok"]
    assert not isolated_ports["manager"]._leases


async def test_unknown_close_keeps_owner_and_lease_for_retry(env, monkeypatch, isolated_ports):
    monkeypatch.setattr(T, "CLOSE_SECONDS", .05)
    async with Client(S.server) as client:
        await connected(client, env)
        env.fake.close_verified = False
        pending = await invoke(client, env, "flipper_close")
        assert pending["state"] == "cleanup_pending" and not pending["physical_close_verified"]
        assert not pending["lease_released"] and isolated_ports["manager"]._leases
        denied = await invoke(client, env, "flipper_connect")
        assert "flipper_busy" in denied.get("_error", "")
        env.fake.close_verified = True
        closed = await invoke(client, env, "flipper_close")
        assert closed["ok"] and closed["state"] == "closed"
    assert not isolated_ports["manager"]._leases
