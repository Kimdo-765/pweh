"""Linux child와 실제 Windows owner·Job·Case·lease의 내부 파일 출력 통합."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import stat
import subprocess
import sys
import threading
import time
from types import SimpleNamespace

import pytest

from openocd_mcp import process_windows as PW, server as S, windows_output as O
from openocd_mcp import windows_file_job as J, windows_start as W
from openocd_mcp.session import OcdSession, REGISTRY
from pweh.case import Case
from pweh.portlock import PortOwner

from .test_openocd_windows_process import setup as windows_setup

pytestmark = pytest.mark.skipif(not sys.platform.startswith("linux"), reason="Linux 합성 파일 pipe")
FAKE = Path(__file__).with_name("fake_openocd_pipe_file.py")
KEYS = ("win:COM4095", "win:COM4096")
RESULT_KEYS = {"path", "metadata_path", "size", "sha256", "artifact", "source", "transfer",
               "chunks", "resumed_from", "warnings"}


def end(seconds=10):
    return time.monotonic() + seconds


def pattern(start, size):
    return bytes((start + i) & 255 for i in range(size))


def wait_for(check, timeout=5):
    limit = end(timeout)
    while not check():
        assert time.monotonic() < limit, "합성 child 경계 대기 시간 초과"
        time.sleep(.005)


@pytest.fixture
def lab(windows_setup, workspace, auth, isolated_ports):
    base, runtime = windows_setup, S.rt()
    case = runtime.cases.create(title="내부 파일 pipe 합성 통합", authorization=auth)
    made, baseline = [], set(O._OUTPUTS)

    def make(mode="ready", *, style="drive"):
        index, pairs = len(made), []
        manifest = base.tmp / f"pairs-{index}.json"
        requests = base.tmp / f"file-requests-{index}.txt"
        manifest.write_text("[]", encoding="utf-8")

        def converter(path, deadline):
            assert time.monotonic() < deadline
            # spawn 계획의 bundle/config/run 변환은 원 fixture와 정확히 같다.
            if not path.parent.name.startswith("output-"):
                return base.converter(path, deadline)
            prefix = "C:/SYNTHETIC" if style == "drive" else "//wsl.localhost/Synthetic"
            if style == "special":
                prefix = "C:/SYNTHETIC space $; 한글"
            win = prefix + "/" + "/".join(path.relative_to(base.tmp).parts)
            row = {"windows_path": win, "local_path": str(path)}
            assert row not in pairs and len(pairs) < 32
            pairs.append(row)
            raw = json.dumps(pairs, ensure_ascii=False).encode("utf-8")
            assert len(raw) <= 65536
            temporary = manifest.with_suffix(".tmp")
            temporary.write_bytes(raw)
            temporary.replace(manifest)
            return win.replace("/", "\\")

        def factory(argv, **kwargs):
            return subprocess.Popen([sys.executable, "-I", str(FAKE), "--mode", mode,
                                     "--pairs-file", str(manifest), "--requests-file", str(requests)], **kwargs)

        owner = base.spawn(path_converter=converter, process_factory=factory)
        assert owner.wait_ready(timeout=3).ready
        lease = isolated_ports["manager"].acquire(
            KEYS, owner=PortOwner("openocd-mcp", case.id, "synthetic-file"))
        sess = OcdSession(case_id=case.id, mode="spawned", host="", port=None, client=owner.client,
                          transport="windows-pipe", windows_owner=owner, windows_bundle=base.bundle,
                          windows_profile=base.profile.profile_id, windows_layout=owner.plan.layout,
                          windows_lease=lease)
        REGISTRY.add(sess)
        env = SimpleNamespace(owner=owner, sess=sess, client=owner.client, lease=lease, requests=requests,
                              manifest=manifest, pairs=pairs, unknown_files=[])
        made.append(env)
        return env

    yield SimpleNamespace(base=base, case=case, runtime=runtime, make=make,
                          manager=isolated_ports["manager"])
    for job in runtime.jobs.list(active_only=True):
        runtime.jobs.cancel(job["job_id"])
        runtime.jobs.wait(job["job_id"], 5)
    base.life.unknown, base.life.confirm = False, True
    for env in made:
        # 시험이 만든 미등록 항목만 지운다. 제품의 보존 규칙은 완화하지 않는다.
        for path in env.unknown_files:
            path.unlink(missing_ok=True)
        if REGISTRY.find(case.id) is env.sess:
            assert W.close_session(env.sess, timeout=5)["stopped"]
        assert env.sess._uses == 0 and env.lease.closed
        assert env.owner._confirmed is not None and env.owner._pipe._leader_reaped
        assert not env.owner.plan.layout.root.exists()
        assert PW._OWNED.get(env.owner.token) is not env.owner
    assert set(O._OUTPUTS) == baseline


def spec_for(lab, *, kind="memory", **changes):
    values = dict(case=lab.case, kind=kind, output_name="synthetic", length=768, chunk_size=256,
                  verify=False, resume=True)
    values.update(address=0x1023) if kind == "memory" else values.update(bank=0, bank_size=4096, offset=35)
    values.update(changes)
    return O.PipeFileSpec(**values)


def start(lab, env, spec=None, *, seconds=10):
    return J.start_pipe_file_job(spec or spec_for(lab), env.sess, runtime=lab.runtime, deadline=end(seconds))


def finish(lab, job):
    lab.runtime.jobs.wait(job.id, 8)
    assert job._thread is not None and not job._thread.is_alive(), "합성 job이 끝나지 않았습니다"
    return job


def request_kinds(env):
    return env.requests.read_text().splitlines()


def paths(lab, spec):
    root = lab.case.subdir("jtag" if spec.kind == "memory" else "dumps")
    return SimpleNamespace(part=root / f"{spec.output_name}.part", state=root / f"{spec.output_name}.state.json",
                           final=root / f"{spec.output_name}.bin", meta=root / f"{spec.output_name}.json")


def no_private(value, env):
    raw = json.dumps(value, ensure_ascii=False)
    for sentinel in ("PIPE_FILE_PRIVATE_SENTINEL", "dump_image {", "flash read_bank", "flash verify_bank",
                     str(env.owner.plan.layout.root), "SYNTHETIC", "wsl.localhost"):
        assert sentinel not in raw


@pytest.mark.parametrize("kind,verify", [("memory", False), ("memory", True), ("flash", False), ("flash", True)])
def test_real_file_job_confirmed_owner_before_checked_registration(lab, monkeypatch, kind, verify):
    env = lab.make()
    spec, checks, events = spec_for(lab, kind=kind, verify=verify), [], []
    real_register, real_finish, real_run, real_lease = Case.register_artifact, env.sess.finish_use, env.owner.release_run, env.lease.close

    def register(case, path, **kwargs):
        if case.id != lab.case.id or kwargs.get("kind") not in ("memory-dump", "flash-dump"):
            return real_register(case, path, **kwargs)
        check = kwargs["check"]
        def observe(entry):
            assert env.owner._confirmed is not None and env.owner._confirmed.confirmed
            assert env.owner._pipe._leader_reaped and env.sess.closing and env.sess._uses == 1
            assert not env.lease.closed and env.owner.plan.layout.root.exists()
            env.lease.assert_held(KEYS)
            checks.append(entry.copy())
            events.append("check")
            return check(entry)
        kwargs["check"] = observe
        return real_register(case, path, **kwargs)

    def returned():
        events.append("use-return")
        return real_finish()

    def release_run(**kwargs):
        if env.owner._run_released:
            return real_run(**kwargs)
        assert env.sess._uses == 0 and env.owner.token not in O._OUTPUTS
        assert not env.lease.closed
        events.append("run-release")
        return real_run(**kwargs)

    def release_lease():
        assert not env.owner.plan.layout.root.exists() and env.sess._uses == 0
        events.append("lease-release")
        return real_lease()

    monkeypatch.setattr(Case, "register_artifact", register)
    monkeypatch.setattr(env.sess, "finish_use", returned)
    monkeypatch.setattr(env.owner, "release_run", release_run)
    monkeypatch.setattr(env.lease, "close", release_lease)
    job = finish(lab, start(lab, env, spec))
    assert job.status == "succeeded", job.error
    assert set(job.result) == RESULT_KEYS and job.result["warnings"] == []
    expected = pattern(spec.address if kind == "memory" else spec.offset, spec.length)
    out = paths(lab, spec)
    assert out.final.read_bytes() == expected and not out.part.exists() and not out.state.exists()
    assert job.result["size"] == len(expected) and job.result["sha256"] == hashlib.sha256(expected).hexdigest()
    assert job.result["chunks"] == 3 and job.result["resumed_from"] == 0
    assert stat.S_IMODE(out.final.stat().st_mode) == stat.S_IMODE(out.meta.stat().st_mode) == 0o444
    meta = json.loads(out.meta.read_text())
    assert meta["output"]["sha256"] == job.result["sha256"]
    assert meta["verification"] == {"double_read": kind == "memory" and verify, "flash_verify": kind == "flash" and verify}
    assert lab.case.artifacts(kind + "-dump") == [job.result["artifact"]]
    assert len(checks) == 1 and events[:4] == ["check", "use-return", "run-release", "lease-release"]
    commands = ["dump_image"] * (6 if verify else 3) if kind == "memory" else (["read_bank", "verify_bank"] * 3 if verify else ["read_bank"] * 3)
    assert request_kinds(env) == ["version"] + commands
    no_private(job.result, env)
    no_private(meta, env)


@pytest.mark.parametrize("style", ["drive", "unc", "special"])
def test_exact_pair_paths_roundtrip_as_one_tcl_word(lab, style):
    env = lab.make(style=style)
    spec = spec_for(lab, length=257, verify=True)
    job = finish(lab, start(lab, env, spec))
    assert job.status == "succeeded", job.error
    assert paths(lab, spec).final.read_bytes() == pattern(spec.address, 257)
    assert len(env.pairs) == 4 and len({p["windows_path"] for p in env.pairs}) == 4
    assert request_kinds(env) == ["version"] + ["dump_image"] * 4
    no_private(job.result, env)


@pytest.mark.parametrize("mode", ["short-second", "long-second", "tcl-error-second", "eof-second", "malformed-second"])
def test_second_write_failure_preserves_checkpoint_without_retry(lab, mode):
    env, spec = lab.make(mode), spec_for(lab)
    job = finish(lab, start(lab, env, spec))
    assert job.status == "failed" and job.error["code"] in {"openocd_output_changed", "openocd_output_invalid", "openocd_pipe_terminal"}, job.error
    out = paths(lab, spec)
    assert out.part.read_bytes() == pattern(spec.address, 256)
    state = json.loads(out.state.read_text())
    assert state["done"] == 256 and state["prefix_sha256"] == hashlib.sha256(out.part.read_bytes()).hexdigest()
    assert not out.final.exists() and not out.meta.exists() and lab.case.artifacts("memory-dump") == []
    assert job.result["done"] == 256 and request_kinds(env) == ["version", "dump_image", "dump_image"]
    assert env.owner._confirmed is not None and env.lease.closed
    no_private(job.error, env)


def test_first_open_error_has_zero_checkpoint_and_no_fallback(lab):
    env, spec = lab.make("open-error"), spec_for(lab)
    job = finish(lab, start(lab, env, spec))
    assert job.status == "failed", job.error
    out = paths(lab, spec)
    assert out.part.read_bytes() == b"" and json.loads(out.state.read_text())["done"] == 0
    assert request_kinds(env) == ["version", "dump_image"] and not lab.case.artifacts("memory-dump")


@pytest.mark.parametrize("cancel", [False, True])
def test_stalled_second_write_timeout_or_cancel_preserves_first_chunk(lab, cancel):
    env, spec = lab.make("stall-second"), spec_for(lab)
    job = start(lab, env, spec, seconds=5 if cancel else 2)
    wait_for(lambda: request_kinds(env).count("dump_image") == 2)
    if cancel:
        lab.runtime.jobs.cancel(job.id)
    finish(lab, job)
    assert job.status == ("cancelled" if cancel else "failed"), job.error
    if not cancel:
        assert job.error["code"] in {"timeout", "openocd_pipe_terminal"}
    assert paths(lab, spec).part.read_bytes() == pattern(spec.address, 256)
    assert not lab.case.artifacts("memory-dump") and request_kinds(env) == ["version", "dump_image", "dump_image"]


def test_explicit_stop_during_rpc_keeps_lease_until_worker_returns(lab, monkeypatch):
    env, spec = lab.make("stall-second"), spec_for(lab)
    returned = threading.Event()
    real_finish, real_lease = env.sess.finish_use, env.lease.close
    def finish_use():
        # 통지 뒤 깨어난 close thread와 시험 표식의 경쟁을 만들지 않는다.
        returned.set()
        real_finish()
    def close_lease():
        assert returned.is_set() and env.sess._uses == 0
        assert env.owner._confirmed is not None and env.owner.token not in O._OUTPUTS
        return real_lease()
    monkeypatch.setattr(env.sess, "finish_use", finish_use)
    monkeypatch.setattr(env.lease, "close", close_lease)
    job = start(lab, env, spec)
    wait_for(lambda: request_kinds(env).count("dump_image") == 2)
    assert env.sess._uses == 1 and not env.lease.closed
    # 공개 stop과 같은 순서로 작업 취소를 표시한 뒤 실제 session을 닫는다.
    lab.runtime.jobs.cancel(job.id)
    stopped = W.close_session(env.sess, timeout=5)
    finish(lab, job)
    assert stopped["stopped"] and job.status == "cancelled", job.error
    assert paths(lab, spec).part.read_bytes() == pattern(spec.address, 256)
    assert not lab.case.artifacts("memory-dump") and env.lease.closed


@pytest.mark.parametrize("unknown", ["observe", "terminate"])
def test_unknown_windows_cleanup_requires_explicit_stop_and_never_publishes(lab, unknown):
    env, spec = lab.make(), spec_for(lab)
    if unknown == "observe":
        lab.base.life.unknown = True
    else:
        lab.base.life.confirm = False
    job = finish(lab, start(lab, env, spec))
    assert job.status == "failed" and job.error["code"] == "openocd_output_cleanup_unknown"
    assert env.owner._pipe._leader_reaped and env.owner._confirmed is None
    assert env.sess._uses == 0 and env.sess.cleanup_pending and not env.lease.closed
    assert REGISTRY.find(lab.case.id) is env.sess and O._OUTPUTS[env.owner.token].done == 768
    assert PW._OWNED[env.owner.token] is env.owner and env.owner.plan.layout.root.exists()
    assert paths(lab, spec).part.read_bytes() == pattern(spec.address, spec.length)
    assert not lab.case.artifacts("memory-dump")
    before = request_kinds(env)
    lab.base.life.unknown, lab.base.life.confirm = False, True
    assert W.close_session(env.sess, timeout=5)["stopped"]
    assert env.owner.token not in O._OUTPUTS and env.lease.closed
    assert not paths(lab, spec).final.exists() and not lab.case.artifacts("memory-dump")
    assert request_kinds(env) == before


def test_unknown_output_entry_is_preserved_until_explicit_stop(lab, monkeypatch):
    env, spec = lab.make(), spec_for(lab)
    real_close, injected = env.owner.close, False
    def close(**kwargs):
        nonlocal injected
        if not injected:
            unknown = O._OUTPUTS[env.owner.token].output.path / "unregistered.txt"
            unknown.write_bytes(b"SYNTHETIC unknown output")
            env.unknown_files.append(unknown)
            injected = True
        return real_close(**kwargs)
    monkeypatch.setattr(env.owner, "close", close)
    job = finish(lab, start(lab, env, spec))
    assert job.status == "failed" and job.error["code"] == "openocd_output_cleanup_unknown"
    assert env.owner._confirmed.confirmed and not env.lease.closed and env.sess.cleanup_pending
    assert env.unknown_files[0].read_bytes() == b"SYNTHETIC unknown output"
    assert not W.close_session(env.sess, timeout=1)["stopped"]
    assert not paths(lab, spec).final.exists() and not lab.case.artifacts("memory-dump")
    env.unknown_files.pop().unlink()
    assert W.close_session(env.sess, timeout=5)["stopped"]


@pytest.mark.parametrize("callback_failure", [False, True])
def test_commit_latch_retains_artifact_on_late_cancel_and_callback_error(lab, monkeypatch, callback_failure):
    env, spec = lab.make(), spec_for(lab)
    real_register, observed = Case.register_artifact, []
    def register(case, path, **kwargs):
        if case.id != lab.case.id or kwargs.get("kind") != "memory-dump":
            return real_register(case, path, **kwargs)
        committed = kwargs["on_commit"]
        def late(entry):
            committed(entry)
            jobs = lab.runtime.jobs.list(active_only=True)
            assert len(jobs) == 1
            job = lab.runtime.jobs.cancel(jobs[0]["job_id"])
            observed.append(job._committed)
            assert not job._cancel.is_set()
            if callback_failure:
                raise RuntimeError("PIPE_FILE_PRIVATE_SENTINEL")
        kwargs["on_commit"] = late
        return real_register(case, path, **kwargs)
    monkeypatch.setattr(Case, "register_artifact", register)
    job = finish(lab, start(lab, env, spec))
    assert job.status == "succeeded" and observed == [True], job.error
    assert job.result["warnings"] == (["post_commit_callback_failed"] if callback_failure else [])
    assert lab.case.artifacts("memory-dump") == [job.result["artifact"]]
    assert paths(lab, spec).final.read_bytes() == pattern(spec.address, spec.length)
    no_private(job.result, env)


def test_postcommit_cleanup_failure_preserves_receipt_then_explicit_stop(lab, monkeypatch):
    env = lab.make()
    real_release = O.release_outputs
    blocked = True
    def release(owner, **kwargs):
        if owner is env.owner and blocked:
            assert O._OUTPUTS[owner.token].receipt is not None
            return False
        return real_release(owner, **kwargs)
    monkeypatch.setattr(O, "release_outputs", release)
    job = finish(lab, start(lab, env))
    assert job.status == "succeeded" and job.result["warnings"] == ["output_close_unconfirmed"], job.error
    assert lab.case.artifacts("memory-dump") == [job.result["artifact"]]
    assert env.sess.cleanup_pending and not env.lease.closed and env.owner.plan.layout.root.exists()
    blocked = False
    assert W.close_session(env.sess, timeout=5)["stopped"]
    assert lab.case.artifacts("memory-dump") == [job.result["artifact"]]


@pytest.mark.parametrize("changes", [{"offset": 2**32}, {"bank_size": 2**32}, {"length": 2**32},
                                      {"offset": 2**32 - 100, "bank_size": 2**32 - 1, "length": 256}])
def test_flash_u32_overflow_is_rejected_before_first_rpc(lab, changes):
    env = lab.make()
    with pytest.raises(O.PipeOutputError) as caught:
        start(lab, env, spec_for(lab, kind="flash", **changes))
    assert caught.value.code == "openocd_output_invalid"
    assert lab.runtime.jobs.list() == [] and env.sess._uses == 0
    assert request_kinds(env) == ["version"] and not lab.case.artifacts("flash-dump")
