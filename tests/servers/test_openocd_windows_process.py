"""고정 Windows owner의 합성 bundle·Linux 자식·주입된 Windows 수명 시험."""
from dataclasses import replace
import base64
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time
from types import SimpleNamespace

import pytest

from openocd_mcp import process_windows as W, windows_plan as P
from openocd_mcp.dummy_profile import DUMMY_PROFILE
from pweh import windows_bundle as B, wininterop as WI

pytestmark = pytest.mark.skipif(not sys.platform.startswith("linux"), reason="Linux 합성 interop wrapper")
FAKE = Path(__file__).with_name("fake_openocd_pipe.py")
CFG = (b"# SPDX-License-Identifier: GPL-2.0-or-later\n\n"
       b"#\n# Dummy interface (for testing purposes)\n#\n\nadapter driver dummy\n")


def end(seconds=10):
    return time.monotonic() + seconds


def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


class Lifecycle:
    def __init__(self):
        self.calls = []
        self.unknown = False
        self.confirm = True

    def observe(self, launch, *, deadline):
        self.calls.append("observe")
        if self.unknown:
            raise ValueError("PRIVATE Windows cmdline")
        return ()

    def terminate_and_confirm(self, launch, observed, *, deadline):
        self.calls.append("terminate")
        return self.confirm


@pytest.fixture
def setup(tmp_path, monkeypatch):
    rid = DUMMY_PROFILE.release_id
    data = {"bin/openocd.exe": b"SYNTHETIC NONEXECUTABLE", "openocd/scripts/interface/dummy.cfg": CFG}
    doc = {"schema_version": 1, "tool": "openocd", "release_id": rid, "platform": "windows-amd64",
           "source": {"artifact_url": "https://example.invalid/synthetic.zip", "artifact_name": "synthetic.zip",
                      "artifact_size": 1, "artifact_sha256": "a" * 64, "digest_basis": "supplier-checksum",
                      "checksum_metadata": {"repository": "https://example.invalid/repo", "ref": "v1", "path": "package.json"},
                      "extractor": None},
           "payload": {"archive_root": "synthetic/", "recipe": "zip-strip-fixed-root-v1", "entrypoint": "bin/openocd.exe",
                       "search_dirs": ["openocd/scripts"], "python_zip": None, "file_count": 2,
                       "total_bytes": sum(map(len, data.values())),
                       "excluded": {"installer_plugins": 0, "usb_driver_installers": 0, "example_captures": 0, "uninstaller": 0}},
           "files": [{"path": p, "size": len(v), "sha256": hashlib.sha256(v).hexdigest()} for p, v in sorted(data.items())],
           "known_limitations": ["authenticode_unverified"]}
    raw = canonical(doc)
    index = {"schema_version": 1, "tools": {"openocd": {"preferred_release_id": rid, "releases": [
        {"release_id": rid, "manifest": f"windows-bundles/openocd-{rid}.json", "sha256": hashlib.sha256(raw).hexdigest()}]}}}
    index["tools"]["sigrok"] = json.loads(B._read_registry_bytes())["tools"]["sigrok"]
    monkeypatch.setattr(B, "_read_registry_bytes", lambda: canonical(index))
    monkeypatch.setattr(B, "_read_registered_manifest_bytes", lambda _: raw)
    root = tmp_path / "release"
    for name, value in data.items():
        target = root / "payload" / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(value)
        target.chmod(0o555 if name.endswith(".exe") else 0o444)
    manifest = B.load_registered_manifest("openocd", deadline=end())
    (root / "release.json").write_bytes(manifest.receipt_bytes)
    (root / "release.json").chmod(0o444)
    for directory in [p for p in root.rglob("*") if p.is_dir()] + [root]:
        directory.chmod(0o555)
    bundle = B.verify_release(root, "openocd", deadline=end())
    layouts, owners, spawns = [], [], []
    baseline = W.owned_process_count()
    life = Lifecycle()
    def converter(path, deadline):
        return "C:\\SYNTHETIC\\" + "\\".join(path.relative_to(tmp_path).parts)
    def plan():
        layout = W.prepare_windows_run(tmp_path, deadline=end())
        layouts.append(layout)
        inputs = P.PipeStartInputs(P.observe_file(bundle.entrypoint, max_bytes=P.MAX_FILE_BYTES, deadline=end()), bundle.search_dirs,
                    P.CfgInput("standard", P.observe_file(bundle.root / DUMMY_PROFILE.interface_relative_path, max_bytes=P.MAX_CFG_BYTES, deadline=end())),
                    targets=(), extras=(), extra_commands=(), transport="jtag", adapter_speed_khz=1000)
        return P.build_dummy_plan(inputs, layout, ambient_env=(), path_converter=converter, deadline=end())
    def spawn(mode="ready", *, supplied_plan=None, **updates):
        p = supplied_plan or plan()
        def factory(argv, **kwargs):
            spawns.append((argv, kwargs))
            return subprocess.Popen([sys.executable, "-I", str(FAKE), "--mode", mode,
                                     "--requests-file", str(tmp_path / "requests")], **kwargs)
        kw = dict(bundle=bundle, log_path=tmp_path / "synthetic.log", deadline=end(),
                  lifecycle=life, path_converter=converter, process_factory=factory)
        kw.update(updates)
        try:
            owner = W.spawn_windows(p, **kw)
        except W.WindowsSpawnError as exc:
            owners.append(exc.owner)
            raise
        owners.append(owner)
        return owner
    fixture = SimpleNamespace(bundle=bundle, plan=plan, spawn=spawn, life=life, converter=converter,
                              owners=owners, layouts=layouts, spawns=spawns, tmp=tmp_path)
    yield fixture
    life.unknown = False
    life.confirm = True
    for owner in owners:
        assert owner.close(timeout=5).confirmed
        assert owner.release_run(deadline=end())
    for layout in layouts:
        if layout.root.exists():
            assert W.release_prepared_run(layout, deadline=end())
    assert W.owned_process_count() == baseline


def test_ready_once_noinit_and_no_verify_rpc(setup):
    owner = setup.spawn()
    ready = owner.wait_ready(timeout=3)
    assert ready.ready and ready.transport == "windows-pipe"
    assert owner.wait_ready(timeout=3) == ready
    assert (setup.tmp / "requests").read_bytes() == b"request\n"
    argv, kwargs = setup.spawns[0]
    assert "noinit" in argv and "init" not in argv
    assert "env" in kwargs and kwargs["shell"] is False and kwargs["text"] is False
    assert owner.diagnostics()["cleanup_confirmed"] is False
    result = owner.close(timeout=3)
    assert result.confirmed and result.wrapper_exit_code == 0
    assert setup.life.calls == ["observe", "terminate"]
    assert owner.plan.layout.root.exists() and W.owned_process_count() >= 1
    assert owner.release_run(deadline=end())
    assert owner.release_run(deadline=end()) and not owner.plan.layout.root.exists()


@pytest.mark.parametrize("mode", ["ready-bare", "ready-crlf", "ready-debug", "delayed-marker"])
def test_canonical_marker_forms(setup, mode):
    assert setup.spawn(mode).wait_ready(timeout=3).ready


@pytest.mark.parametrize("mode", ["marker-only", "version-only", "unquoted-marker", "bad-version", "version-error"])
def test_bad_readiness_does_not_retry(setup, mode):
    owner = setup.spawn(mode)
    assert not owner.wait_ready(timeout=.15).ready
    assert not owner.wait_ready(timeout=.15).ready
    assert (setup.tmp / "requests").read_bytes() == b"request\n"


def test_ready_callback_failure_is_fixed_without_private_chain(setup):
    owner = setup.spawn()
    def fail():
        raise ValueError("PRIVATE callback")
    with pytest.raises(W.WindowsOwnerError) as caught:
        owner.wait_ready(timeout=1, cancel_check=fail)
    assert "PRIVATE" not in str(caught.value) and caught.value.__cause__ is None


def test_windows_unknown_keeps_owner_and_run_after_wrapper_reaped(setup):
    owner = setup.spawn()
    assert owner.wait_ready(timeout=3).ready
    setup.life.unknown = True
    assert not owner.close(timeout=3).confirmed
    assert owner._pipe._leader_reaped and owner.plan.layout.root.exists()
    assert not owner.release_run(deadline=end())
    assert W._OWNED[owner.token] is owner
    setup.life.unknown = False
    assert owner.close(timeout=3).confirmed


def test_windows_termination_false_is_not_confirmation(setup):
    owner = setup.spawn()
    setup.life.confirm = False
    assert not owner.close(timeout=3).confirmed
    assert owner.plan.layout.root.exists() and not owner.release_run(deadline=end())


def test_wrapper_unknown_does_not_run_windows_probe(setup, monkeypatch):
    owner = setup.spawn()
    with monkeypatch.context() as m:
        m.setattr(owner._pipe, "_observe_group", lambda *_: None)
        assert owner.close(timeout=.2).reason == "wrapper_cleanup_unknown"
        assert setup.life.calls == []


@pytest.mark.parametrize("mode", ["term-only", "kill-only"])
def test_forced_wrapper_cleanup_still_requires_windows_proof(setup, mode):
    owner = setup.spawn(mode)
    assert owner.wait_ready(timeout=3).ready
    result = owner.close(timeout=4)
    assert result.confirmed and result.wrapper_exit_code < 0
    assert setup.life.calls == ["observe", "terminate"]


def test_cancel_before_spawn_is_fixed_owned_failure(setup):
    with pytest.raises(W.WindowsSpawnError) as caught:
        setup.spawn(cancel_check=lambda: True)
    assert setup.spawns == []
    assert caught.value.owner.close(timeout=1).confirmed
    assert "PRIVATE" not in str(caught.value)


def test_raw_cancel_after_spawn_preserves_owner(setup):
    import asyncio
    calls = 0
    def cancel():
        nonlocal calls
        calls += 1
        if setup.spawns:
            raise asyncio.CancelledError()
        return False
    with pytest.raises(W.WindowsSpawnError) as caught:
        setup.spawn(cancel_check=cancel)
    assert len(setup.spawns) == 1
    assert W._OWNED[caught.value.owner.token] is caught.value.owner


def test_bundle_mutation_is_spawn_zero(setup):
    p = setup.plan()
    file = setup.bundle.entrypoint
    original = file.read_bytes()
    file.chmod(0o755)
    file.write_bytes(b"PRIVATE changed bytes")
    try:
        with pytest.raises(W.WindowsSpawnError):
            setup.spawn(supplied_plan=p)
        assert not setup.spawns
    finally:
        file.write_bytes(original)
        file.chmod(0o555)


def test_plan_mutation_is_spawn_zero(setup):
    p = setup.plan()
    with pytest.raises(W.WindowsSpawnError):
        setup.spawn(supplied_plan=replace(p, argv=(*p.argv, "-c", "PRIVATE")))
    assert not setup.spawns


def test_run_cannot_be_double_claimed_or_released_while_owner_active(setup):
    p = setup.plan()
    owner = setup.spawn(supplied_plan=p)
    assert not W.release_prepared_run(p.layout, deadline=end())
    with pytest.raises(W.WindowsOwnerError):
        setup.spawn(supplied_plan=p)
    assert len(setup.spawns) == 1
    assert owner.close(timeout=3).confirmed


def test_unexpected_run_content_is_retained(setup):
    owner = setup.spawn()
    assert owner.close(timeout=3).confirmed
    unknown = owner.plan.layout.root / "PRIVATE"
    unknown.write_bytes(b"synthetic")
    assert not owner.release_run(deadline=end())
    assert unknown.read_bytes() == b"synthetic"
    unknown.unlink()


def test_replaced_run_name_is_not_deleted(setup):
    owner = setup.spawn()
    assert owner.close(timeout=3).confirmed
    root = owner.plan.layout.root
    moved = root.with_name(root.name + "-moved")
    root.rename(moved)
    root.mkdir()
    assert not owner.release_run(deadline=end()) and root.exists()
    root.rmdir()
    moved.rename(root)


def test_prepared_only_run_cleanup(setup):
    p = setup.plan()
    assert W.release_prepared_run(p.layout, deadline=end())
    assert not p.layout.root.exists()


def test_prepare_marker_write_failure_removes_only_recorded_inode(tmp_path, monkeypatch):
    baseline = set(W._RUNS)
    with monkeypatch.context() as m:
        m.setattr(os, "write", lambda *a: (_ for _ in ()).throw(OSError("PRIVATE write failure")))
        with pytest.raises(W.WindowsRunError) as caught:
            W.prepare_windows_run(tmp_path, deadline=end())
    assert caught.value.prepared_run is None
    assert set(W._RUNS) == baseline and list(tmp_path.iterdir()) == []
    assert "PRIVATE" not in str(caught.value)


def test_prepare_failure_never_deletes_replaced_marker(tmp_path, monkeypatch):
    saved = tmp_path / "saved-marker"
    replacement = None
    def fail_snapshot(path, **kwargs):
        nonlocal replacement
        replacement = path
        path.rename(saved)
        path.write_bytes(b"SYNTHETIC REPLACEMENT MUST REMAIN")
        raise OSError("PRIVATE snapshot failure")
    with monkeypatch.context() as m:
        m.setattr(P, "observe_file", fail_snapshot)
        with pytest.raises(W.WindowsRunError) as caught:
            W.prepare_windows_run(tmp_path, deadline=end())
    record = caught.value.prepared_run
    assert record is not None and W._RUNS[record.root] is record
    assert replacement.read_bytes() == b"SYNTHETIC REPLACEMENT MUST REMAIN"
    assert not W.release_prepared_run(record, deadline=end())
    replacement.unlink()
    saved.rename(replacement)
    assert W.release_prepared_run(record, deadline=end())
    assert not record.root.exists()


def test_prepare_failure_keeps_unknown_extra_entries(tmp_path, monkeypatch):
    extra = None
    def fail_snapshot(path, **kwargs):
        nonlocal extra
        extra = path.parent / "unexpected"
        extra.write_bytes(b"SYNTHETIC")
        raise ValueError("failed")
    with monkeypatch.context() as m:
        m.setattr(P, "observe_file", fail_snapshot)
        with pytest.raises(W.WindowsRunError) as caught:
            W.prepare_windows_run(tmp_path, deadline=end())
    record = caught.value.prepared_run
    assert record is not None and extra.read_bytes() == b"SYNTHETIC"
    extra.unlink()
    assert W.release_prepared_run(record, deadline=end())


@pytest.mark.parametrize("value", [0, -1, True, float("nan"), float("inf"), 10**400])
def test_invalid_deadline_no_run(tmp_path, value):
    with pytest.raises((W.WindowsOwnerError, W.ValidationFailed)):
        W.prepare_windows_run(tmp_path, deadline=value)
    assert list(tmp_path.iterdir()) == []


def test_fixed_control_runner_argv_and_utf8_bytes(tmp_path):
    calls = []
    def factory(argv, **kwargs):
        calls.append(argv)
        return subprocess.Popen([sys.executable, "-I", "-c", "import os;os.write(1,b'{\"complete\":true,\"items\":[]}')"], **kwargs)
    runner = W.FixedWindowsRunner(process_factory=factory, powershell_provider=lambda: "/synthetic/powershell.exe")
    assert runner(WI.QUERY_SCRIPT, end()) == b'{"complete":true,"items":[]}'
    assert not runner.pending
    assert calls[0][1:5] == ["-NoLogo", "-NoProfile", "-NonInteractive", "-EncodedCommand"]
    assert base64.b64decode(calls[0][-1]).decode("utf-16le") == WI.QUERY_SCRIPT


@pytest.mark.parametrize("script", ["Get-Process", "Stop-Process -Id 1", WI.QUERY_SCRIPT + " ", None, 123,
                                     WI.TERMINATE_SCRIPT_TEMPLATE.replace("__REQUEST__", "e30=")])
def test_runner_rejects_nonfixed_script_without_process(script):
    runner = W.FixedWindowsRunner(process_factory=lambda *a, **kw: pytest.fail("임의 script 실행"),
                                  powershell_provider=lambda: "/synthetic/powershell.exe")
    with pytest.raises(W.WindowsOwnerError):
        runner(script, end())


def test_control_pending_preserved_and_no_second_spawn():
    calls = []
    def factory(argv, **kwargs):
        calls.append(argv)
        return subprocess.Popen([sys.executable, "-I", "-c", "import time;time.sleep(.2);print('{}')"], **kwargs)
    runner = W.FixedWindowsRunner(process_factory=factory, powershell_provider=lambda: "/synthetic/powershell.exe")
    try:
        with pytest.raises(W.WindowsOwnerError):
            runner(WI.QUERY_SCRIPT, end(.03))
        assert runner.pending
        with pytest.raises(W.WindowsOwnerError):
            runner(WI.QUERY_SCRIPT, end(.03))
        assert len(calls) == 1 and runner.pending
    finally:
        assert runner.settle(deadline=end(2))
        assert not runner.pending


@pytest.mark.parametrize("fd,count", [(1, (1 << 20) + 1), (2, 65537)])
def test_control_output_limit_drains_and_reaps_without_leaking(fd, count):
    def factory(argv, **kwargs):
        return subprocess.Popen([sys.executable, "-I", "-c", f"import os;os.write({fd},b'X'*{count})"], **kwargs)
    runner = W.FixedWindowsRunner(process_factory=factory, powershell_provider=lambda: "/synthetic/powershell.exe")
    with pytest.raises(W.WindowsOwnerError) as caught:
        runner(WI.QUERY_SCRIPT, end(3))
    assert not runner.pending and "XXX" not in str(caught.value)


def test_control_nonzero_is_fixed_error():
    runner = W.FixedWindowsRunner(process_factory=lambda argv, **kw: subprocess.Popen(
        [sys.executable, "-I", "-c", "import sys;sys.stderr.write('PRIVATE');sys.exit(1)"], **kw),
        powershell_provider=lambda: "/synthetic/powershell.exe")
    with pytest.raises(W.WindowsOwnerError) as caught:
        runner(WI.QUERY_SCRIPT, end(3))
    assert not runner.pending and "PRIVATE" not in str(caught.value)


def test_terminate_template_payload_is_typed():
    request = {"pid": 7, "image": r"C:\synthetic\openocd.exe", "creation": "100000",
               "cmd": '"C:\\synthetic\\openocd.exe"', "wait_ms": 50}
    encoded = base64.b64encode(canonical(request)).decode()
    assert W._script_cap(WI.TERMINATE_SCRIPT_TEMPLATE.replace("__REQUEST__", encoded), end()) == 1024
    request["wait_ms"] = True
    encoded = base64.b64encode(canonical(request)).decode()
    with pytest.raises(W.WindowsOwnerError):
        W._script_cap(WI.TERMINATE_SCRIPT_TEMPLATE.replace("__REQUEST__", encoded), end())
