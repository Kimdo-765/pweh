"""고정 dummy 입력과 무초기화 계획. 합성 파일만 쓰며 외부 프로그램은 실행하지 않는다."""

from dataclasses import FrozenInstanceError, asdict, replace
import hashlib
import json
from pathlib import Path
import time
from types import SimpleNamespace

import pytest

from openocd_mcp import dummy_profile as D, process, semihosting, windows_plan as W
from pweh.errors import ValidationFailed


# 등록 upstream의 공개 112바이트 설정을 fixture로 복제한다. 실제 설치/장치에는 접근하지 않는다.
INTERFACE_BYTES = (
    b"# SPDX-License-Identifier: GPL-2.0-or-later\n\n"
    b"#\n# Dummy interface (for testing purposes)\n#\n\n"
    b"adapter driver dummy\n"
)


def _request(**updates):
    args = dict(windows_profile="dummy-noinit-v1", interface_cfg="interface/dummy.cfg", tcl_port=0)
    args.update(updates)
    return D.validate_dummy_start(**args)


@pytest.mark.parametrize("empty", [None, []])
@pytest.mark.parametrize("transport", [None, "jtag"])
@pytest.mark.parametrize("speed", [None, 1000])
def test_fixed_request_canonicalizes_without_io(empty, transport, speed, monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError("순수 profile 검증에서 파일/환경/프로세스에 접근했다")

    import builtins
    import os
    import subprocess
    monkeypatch.setattr(builtins, "open", forbidden)
    monkeypatch.setattr(os, "open", forbidden)
    monkeypatch.setattr(os, "getenv", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)
    monkeypatch.setattr(Path, "mkdir", forbidden)
    monkeypatch.setattr(Path, "resolve", forbidden)
    profile = _request(target_cfg=empty, extra_cfgs=empty, extra_commands=empty,
                       transport=transport, adapter_speed_khz=speed)
    assert profile is D.DUMMY_PROFILE
    assert profile.transport == "jtag" and profile.adapter_speed_khz == 1000


@pytest.mark.parametrize("field,value", [
    ("windows_profile", None), ("windows_profile", False),
    ("windows_profile", "private-USB-profile"),
    ("interface_cfg", "/private/interface/dummy.cfg"), ("interface_cfg", " interface/dummy.cfg"),
    ("interface_cfg", "interface/DUMMY.cfg"), ("interface_cfg", Path("interface/dummy.cfg")),
    ("interface_cfg", None),
    ("target_cfg", ""), ("target_cfg", "target/testee.cfg"), ("target_cfg", ["private-target"]),
    ("extra_cfgs", ()), ("extra_cfgs", False), ("extra_cfgs", ["private-extra"]),
    ("extra_commands", ""), ("extra_commands", ["init"]), ("extra_commands", ["noinit"]),
    ("extra_commands", ["private-command"]), ("extra_commands", {}),
    ("transport", "JTAG"), ("transport", "swd"), ("transport", False),
    ("adapter_speed_khz", True), ("adapter_speed_khz", 1000.0), ("adapter_speed_khz", "1000"),
    ("adapter_speed_khz", 0), ("adapter_speed_khz", 10**400),
    ("tcl_port", None), ("tcl_port", False), ("tcl_port", "0"), ("tcl_port", 0.0),
    ("tcl_port", 6666),
])
def test_nonfixed_or_mistyped_request_has_fixed_error(field, value):
    with pytest.raises(ValidationFailed) as caught:
        _request(**{field: value})
    expected = ("openocd_windows_profile_unsupported"
                if field == "windows_profile" and type(value) is str else "openocd_dummy_profile_invalid")
    assert caught.value.code == expected
    assert "private-" not in str(caught.value) and "/private/" not in str(caught.value)


def test_profile_digest_is_stable_and_cfg_matches_registered_public_data():
    from importlib.resources import files

    profile = _request()
    record = asdict(profile)
    expected = record.pop("profile_sha256")
    raw = (json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n").encode("ascii")
    assert hashlib.sha256(raw).hexdigest() == expected
    assert hashlib.sha256(INTERFACE_BYTES).hexdigest() == profile.interface_sha256
    assert len(INTERFACE_BYTES) == profile.interface_size == 112
    manifest = json.loads(files("pweh.data").joinpath(
        "windows-bundles/openocd-xpack-0.12.0-7-win32-x64.json").read_text(encoding="utf-8"))
    assert manifest["release_id"] == profile.release_id
    selected = [item for item in manifest["files"] if item["path"] == profile.interface_relative_path]
    assert selected == [{"path": profile.interface_relative_path,
                         "sha256": profile.interface_sha256, "size": profile.interface_size}]
    with pytest.raises(FrozenInstanceError):
        profile.commands = ("init",)


@pytest.fixture
def sample(tmp_path):
    deadline = time.monotonic() + 10

    def snapshot(path, data):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        return W.observe_file(path, max_bytes=W.MAX_FILE_BYTES, deadline=deadline)

    root = tmp_path / "run"
    root.mkdir()
    dirs = tuple(root / name for name in ("cwd", "home", "config", "appdata"))
    for path in dirs:
        path.mkdir()
    marker = snapshot(root / ("owner-" + "a" * 32 + ".cfg"), W.OWNER_CONTENT)
    layout = W.RunLayout(root, *dirs, marker)
    scripts = tmp_path / "합성 bundle" / "openocd" / "scripts"
    interface = snapshot(scripts / "interface" / "dummy.cfg", INTERFACE_BYTES)
    binary = snapshot(tmp_path / "합성 bundle" / "bin" / "openocd.exe", b"synthetic executable snapshot only\n")
    cfg = W.freeze_cfg(process.CfgRef(str(interface.path), "standard", interface.path), interface)
    inputs = W.PipeStartInputs(binary, (scripts,), cfg, (), (), "jtag", 1000, ())
    converted = []

    def windows(path):
        return "C:\\PWEH fixture\\" + "\\".join(path.relative_to(tmp_path).parts)

    def convert(path, end):
        assert end == deadline
        converted.append(path)
        return (windows(path) + "\r\n").encode("utf-8")

    def build(**kwargs):
        args = dict(inputs=inputs, layout=layout, ambient_env=(), path_converter=convert, deadline=deadline)
        args.update(kwargs)
        return W.build_dummy_plan(**args)

    return SimpleNamespace(inputs=inputs, layout=layout, deadline=deadline, convert=convert,
                           windows=windows, converted=converted, build=build)


def test_dummy_plan_has_exact_noinit_argv_identity_and_environment(sample):
    plan = sample.build(ambient_env=(("HOME", "private-parent-home"), ("Path", r"C:\Windows")))
    expected = (
        str(sample.inputs.executable.path), "-d3", "-s", sample.windows(sample.inputs.search_dirs[0]),
        "-c", "if {[catch {tcl port pipe}]} {tcl_port pipe}",
        "-c", "if {[catch {telnet port disabled}]} {telnet_port disabled}",
        "-c", "if {[catch {gdb port disabled}]} {gdb_port disabled}",
        "-f", sample.windows(sample.inputs.interface.file.path),
        "-c", "transport select jtag", "-c", "adapter speed 1000",
        "-c", "jtag newtap tst cpu -irlen 4 -expected-id 0x5ba00477",
        "-c", "target create tst.cpu testee -chain-position tst.cpu",
        "-f", sample.windows(sample.layout.owner_cfg.path), "-c", "noinit",
    )
    assert plan.argv == expected
    assert plan.argv.count("noinit") == 1 and "init" not in plan.argv
    for guard in (semihosting.EARLY_CHECK_SCRIPT, semihosting.PRE_INIT_SCRIPT, semihosting.POST_INIT_SCRIPT):
        assert guard not in plan.argv
    assert plan.launch.image == sample.windows(sample.inputs.executable.path)
    assert plan.launch.argv_tail == plan.argv[1:]
    assert plan.launch.path_arg_indices == (2, 10, 20)
    assert [plan.launch.argv_tail[i] for i in plan.launch.path_arg_indices] == [
        sample.windows(sample.inputs.search_dirs[0]), sample.windows(sample.inputs.interface.file.path),
        sample.windows(sample.layout.owner_cfg.path),
    ]
    assert all(plan.launch.argv_tail[i - 1] in ("-s", "-f") for i in plan.launch.path_arg_indices)
    env = dict(plan.env_items)
    assert env["HOME"] == env["USERPROFILE"] == sample.windows(sample.layout.home)
    assert env["OPENOCD_SCRIPTS"] == sample.windows(sample.inputs.search_dirs[0])
    assert env["WSLENV"] == W.WSLENV and "/p" not in env["WSLENV"]
    assert env["Path"] == r"C:\Windows" and "private-parent-home" not in env.values()
    assert len(sample.converted) == len(set(sample.converted))
    assert sorted(p.name for p in sample.layout.root.iterdir()) == [
        "appdata", "config", "cwd", "home", sample.layout.owner_cfg.path.name,
    ]
    assert sample.build(ambient_env=(("HOME", "private-parent-home"), ("Path", r"C:\Windows"))) == plan


@pytest.mark.parametrize("change", [
    "extra-commands", "target", "extra-cfg", "transport", "speed", "speed-bool", "searches", "custom",
    "cfg-path", "cfg-hash", "cfg-size",
])
def test_dummy_plan_rejects_nonfixed_inputs_before_file_io(sample, change, monkeypatch):
    inp = sample.inputs
    if change == "extra-commands":
        inp = replace(inp, extra_commands=("noinit",))
    elif change == "target":
        inp = replace(inp, targets=(inp.interface,))
    elif change == "extra-cfg":
        inp = replace(inp, extras=(inp.interface,))
    elif change == "transport":
        inp = replace(inp, transport=None)
    elif change == "speed":
        inp = replace(inp, adapter_speed_khz=None)
    elif change == "speed-bool":
        inp = replace(inp, adapter_speed_khz=True)
    elif change == "searches":
        inp = replace(inp, search_dirs=(*inp.search_dirs, inp.search_dirs[0].parent))
    elif change == "custom":
        inp = replace(inp, interface=replace(inp.interface, kind="custom"))
    else:
        old = inp.interface.file
        edits = {"cfg-path": {"path": old.path.with_name("private.cfg")},
                 "cfg-hash": {"sha256": "0" * 64}, "cfg-size": {"size": old.size + 1}}[change]
        inp = replace(inp, interface=replace(inp.interface, file=replace(old, **edits)))

    def forbidden(*args, **kwargs):
        raise AssertionError("잘못된 profile 입력에서 파일을 읽었다")

    monkeypatch.setattr(W, "observe_file", forbidden)
    monkeypatch.setattr(W, "_open_dir", forbidden)
    with pytest.raises(W.WindowsPlanError):
        sample.build(inputs=inp)
    assert not sample.converted


@pytest.mark.parametrize("target", ["interface", "owner"])
def test_dummy_fresh_build_detects_same_content_replacement(sample, target):
    sample.build()
    observed = sample.inputs.interface.file if target == "interface" else sample.layout.owner_cfg
    tmp = observed.path.with_name("replacement")
    tmp.write_bytes(observed.path.read_bytes())
    tmp.replace(observed.path)
    with pytest.raises(W.WindowsPlanError) as caught:
        sample.build()
    assert caught.value.code == "openocd_plan_changed"


def test_converter_cannot_change_cfg_while_plan_is_built(sample):
    changed = False

    def convert(path, end):
        nonlocal changed
        if not changed:
            changed = True
            sample.inputs.interface.file.path.write_bytes(b"init\n")
        return sample.convert(path, end)

    with pytest.raises(W.WindowsPlanError):
        sample.build(path_converter=convert)


def test_dummy_plan_preserves_environment_and_deadline_limits(sample):
    for values in ((("Path", "one"), ("PATH", "two")), (("A", "x" * (W.MAX_PATH_BYTES + 1)),)):
        with pytest.raises(W.WindowsPlanError):
            sample.build(ambient_env=values)
    for value in (True, float("nan"), float("inf"), 10**400, time.monotonic() - 1):
        with pytest.raises(W.WindowsPlanError):
            sample.build(deadline=value)


def test_dummy_plan_rejects_extra_run_cfg_and_no_builder_exposes_skip_init(sample):
    import inspect

    for func in (W.build_plan, W.build_dummy_plan, process.build_argv,
                 process.build_pipe_argv, process.build_dummy_pipe_argv):
        assert "skip_init" not in inspect.signature(func).parameters
    (sample.layout.root / "extra.cfg").write_bytes(b"adapter driver dummy\n")
    with pytest.raises(W.WindowsPlanError):
        sample.build()


def test_dummy_plan_feeds_existing_exact_launch_probe(sample):
    import subprocess
    from pweh import wininterop

    plan = sample.build()
    row = {"pid": 4545, "image": plan.launch.image, "creation": "133000000000000000",
           "cmd": subprocess.list2cmdline(plan.argv)}
    called = []

    def runner(script, end):
        assert script == wininterop.QUERY_SCRIPT and end <= sample.deadline
        called.append(script)
        return json.dumps({"complete": True, "items": [row]}).encode("utf-8")

    observed = wininterop.WindowsOwnedProcessProbe(runner=runner).observe(plan.launch, deadline=sample.deadline)
    assert len(observed) == 1 and len(called) == 1
    assert wininterop.matches_launch(observed[0], plan.launch, deadline=sample.deadline)
