"""Tigard 고정 profile·계획. 공개 cfg의 합성 사본만 사용하고 장치를 조회하지 않는다."""

from dataclasses import FrozenInstanceError, asdict, replace
import hashlib
import json
from pathlib import Path
import time
from types import SimpleNamespace

import pytest

from openocd_mcp import process, semihosting, tigard_profile as T, windows_plan as W
from pweh.errors import ValidationFailed


# 고정 upstream의 공개 설정을 그대로 재현한다. 설치된 payload를 읽지 않는다.
INTERFACE_BYTES = b'''# SPDX-License-Identifier: GPL-2.0-or-later
#
# Tigard: An FTDI FT2232H-based multi-protocol tool for hardware hacking.
# https://github.com/tigard-tools/tigard

adapter driver ftdi

ftdi device_desc "Tigard V1.1"
ftdi vid_pid 0x0403 0x6010

ftdi channel 1

ftdi layout_init 0x0038 0x003b
ftdi layout_signal nTRST -data 0x0010
ftdi layout_signal nSRST -data 0x0020

# This board doesn't support open-drain reset modes since its output buffer is
# always enabled.
reset_config srst_push_pull trst_push_pull
'''


def _request(**changes):
    args = dict(windows_profile="tigard-jtag-v1", interface_cfg="interface/ftdi/tigard.cfg", tcl_port=0)
    args.update(changes)
    return T.validate_tigard_start(**args)


@pytest.mark.parametrize("empty", [None, []])
@pytest.mark.parametrize("transport", [None, "jtag"])
@pytest.mark.parametrize("speed", [None, 100])
def test_fixed_request_canonicalizes_without_io(empty, transport, speed, monkeypatch):
    import builtins
    import os
    import subprocess

    def forbidden(*args, **kwargs):
        raise AssertionError("순수 profile 검증에서 파일·환경·프로세스에 접근했다")

    monkeypatch.setattr(builtins, "open", forbidden)
    monkeypatch.setattr(os, "open", forbidden)
    monkeypatch.setattr(os, "getenv", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)
    monkeypatch.setattr(Path, "mkdir", forbidden)
    monkeypatch.setattr(Path, "resolve", forbidden)
    assert _request(target_cfg=empty, extra_cfgs=empty, extra_commands=empty,
                    transport=transport, adapter_speed_khz=speed) is T.TIGARD_PROFILE


@pytest.mark.parametrize("field,value", [
    ("windows_profile", None), ("windows_profile", False), ("windows_profile", "private-profile"),
    ("windows_profile", "dummy-noinit-v1"),
    ("interface_cfg", "/private/interface/ftdi/tigard.cfg"),
    ("interface_cfg", " interface/ftdi/tigard.cfg"), ("interface_cfg", "interface/ftdi/Tigard.cfg"),
    ("interface_cfg", Path("interface/ftdi/tigard.cfg")), ("interface_cfg", None),
    ("target_cfg", ""), ("target_cfg", ["private-target"]), ("target_cfg", ()),
    ("extra_cfgs", False), ("extra_cfgs", ["private-extra"]), ("extra_cfgs", ()),
    ("extra_commands", ""), ("extra_commands", ["init"]), ("extra_commands", ["noinit"]),
    ("extra_commands", ["private-command"]), ("extra_commands", {}),
    ("transport", "JTAG"), ("transport", "swd"), ("transport", False),
    ("adapter_speed_khz", True), ("adapter_speed_khz", 100.0), ("adapter_speed_khz", "100"),
    ("adapter_speed_khz", 0), ("adapter_speed_khz", 1000), ("adapter_speed_khz", 10**400),
    ("tcl_port", None), ("tcl_port", False), ("tcl_port", "0"), ("tcl_port", 0.0),
    ("tcl_port", 6666),
])
def test_nonfixed_or_mistyped_request_has_fixed_error(field, value):
    with pytest.raises(ValidationFailed) as caught:
        _request(**{field: value})
    expected = ("openocd_windows_profile_unsupported" if field == "windows_profile" and type(value) is str
                else "openocd_tigard_profile_invalid")
    assert caught.value.code == expected
    assert "private-" not in str(caught.value) and "/private/" not in str(caught.value)


def test_profile_digest_binds_scope_effect_and_registered_cfg():
    from importlib.resources import files

    profile = _request()
    record = asdict(profile)
    expected = record.pop("profile_sha256")
    raw = (json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n").encode("ascii")
    assert hashlib.sha256(raw).hexdigest() == expected
    assert (profile.vid, profile.pid, profile.device_desc, profile.channel) == ("0403", "6010", "Tigard V1.1", 1)
    assert profile.whole_device is True
    assert profile.initialization == "guarded-init" and profile.effect == "active-jtag-init-autoprobe"
    assert profile.queries == ("version", "scan_chain", "targets")
    assert (profile.transport, profile.adapter_speed_khz) == ("jtag", 100)
    assert hashlib.sha256(INTERFACE_BYTES).hexdigest() == profile.interface_sha256
    assert len(INTERFACE_BYTES) == profile.interface_size == 506
    manifest = json.loads(files("pweh.data").joinpath(
        "windows-bundles/openocd-xpack-0.12.0-7-win32-x64.json").read_text(encoding="utf-8"))
    assert manifest["release_id"] == profile.release_id
    assert [item for item in manifest["files"] if item["path"] == profile.interface_relative_path] == [
        {"path": profile.interface_relative_path, "sha256": profile.interface_sha256, "size": 506}]
    with pytest.raises(FrozenInstanceError):
        profile.adapter_speed_khz = 1000


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
    marker = snapshot(root / ("owner-" + "b" * 32 + ".cfg"), W.OWNER_CONTENT)
    layout = W.RunLayout(root, *dirs, marker)
    scripts = tmp_path / "합성 bundle" / "openocd" / "scripts"
    interface = snapshot(scripts / "interface" / "ftdi" / "tigard.cfg", INTERFACE_BYTES)
    binary = snapshot(tmp_path / "합성 bundle" / "bin" / "openocd.exe", b"synthetic executable snapshot only\n")
    cfg = W.freeze_cfg(process.CfgRef(str(interface.path), "standard", interface.path), interface)
    inputs = W.PipeStartInputs(binary, (scripts,), cfg, (), (), "jtag", 100, ())
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
        return W.build_tigard_plan(**args)

    return SimpleNamespace(inputs=inputs, layout=layout, deadline=deadline, convert=convert,
                           windows=windows, converted=converted, build=build)


def test_tigard_plan_preserves_exact_guarded_argv_identity_and_environment(sample):
    env = (("HOME", "private-parent-home"), ("Path", r"C:\Windows"))
    plan = sample.build(ambient_env=env)
    assert plan.argv == (
        str(sample.inputs.executable.path), "-d3", "-s", sample.windows(sample.inputs.search_dirs[0]),
        "-c", "if {[catch {tcl port pipe}]} {tcl_port pipe}",
        "-c", "if {[catch {telnet port disabled}]} {telnet_port disabled}",
        "-c", "if {[catch {gdb port disabled}]} {gdb_port disabled}",
        "-f", sample.windows(sample.inputs.interface.file.path), "-c", semihosting.EARLY_CHECK_SCRIPT,
        "-c", "transport select jtag", "-f", sample.windows(sample.layout.owner_cfg.path),
        "-c", semihosting.EARLY_CHECK_SCRIPT,
        "-c", "if {[catch {adapter speed 100}]} {adapter_khz 100}",
        "-c", semihosting.PRE_INIT_SCRIPT, "-c", "init", "-c", semihosting.POST_INIT_SCRIPT,
    )
    assert plan.argv.count("init") == 1 and "noinit" not in plan.argv
    assert not any(arg.startswith(("jtag newtap ", "target create ")) for arg in plan.argv)
    assert plan.launch.image == sample.windows(sample.inputs.executable.path)
    assert plan.launch.argv_tail == plan.argv[1:] and plan.launch.path_arg_indices == (2, 10, 16)
    assert [plan.launch.argv_tail[i] for i in plan.launch.path_arg_indices] == [
        sample.windows(sample.inputs.search_dirs[0]), sample.windows(sample.inputs.interface.file.path),
        sample.windows(sample.layout.owner_cfg.path),
    ]
    values = dict(plan.env_items)
    assert values["HOME"] == values["USERPROFILE"] == sample.windows(sample.layout.home)
    assert values["OPENOCD_SCRIPTS"] == sample.windows(sample.inputs.search_dirs[0])
    assert values["WSLENV"] == W.WSLENV and "/p" not in values["WSLENV"]
    assert values["Path"] == r"C:\Windows" and "private-parent-home" not in values.values()
    assert len(sample.converted) == len(set(sample.converted))
    assert sample.build(ambient_env=env) == plan
    assert W.build_plan(sample.inputs, sample.layout, ambient_env=env,
                        path_converter=sample.convert, deadline=sample.deadline) == plan


@pytest.mark.parametrize("change", [
    "extra-commands", "target", "extra-cfg", "transport", "speed", "speed-bool", "searches", "custom",
    "cfg-path", "cfg-hash", "cfg-size",
])
def test_tigard_plan_rejects_nonfixed_inputs_before_file_io(sample, change, monkeypatch):
    inp = sample.inputs
    changes = {
        "extra-commands": {"extra_commands": ("noinit",)}, "target": {"targets": (inp.interface,)},
        "extra-cfg": {"extras": (inp.interface,)}, "transport": {"transport": None},
        "speed": {"adapter_speed_khz": 1000}, "speed-bool": {"adapter_speed_khz": True},
        "searches": {"search_dirs": (*inp.search_dirs, inp.search_dirs[0].parent)},
        "custom": {"interface": replace(inp.interface, kind="custom")},
    }
    if change in changes:
        inp = replace(inp, **changes[change])
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
def test_fresh_tigard_plan_rejects_same_content_replacement(sample, target):
    sample.build()
    observed = sample.inputs.interface.file if target == "interface" else sample.layout.owner_cfg
    other = observed.path.with_name("replacement")
    other.write_bytes(observed.path.read_bytes())
    other.replace(observed.path)
    with pytest.raises(W.WindowsPlanError) as caught:
        sample.build()
    assert caught.value.code == "openocd_plan_changed"


def test_converter_cannot_change_tigard_cfg_while_plan_is_built(sample):
    def convert(path, end):
        sample.inputs.interface.file.path.write_bytes(b"init\n")
        return sample.convert(path, end)

    with pytest.raises(W.WindowsPlanError):
        sample.build(path_converter=convert)


def test_tigard_plan_does_not_enter_dummy_exception(sample):
    with pytest.raises(W.WindowsPlanError):
        W.build_dummy_plan(sample.inputs, sample.layout, ambient_env=(),
                           path_converter=sample.convert, deadline=sample.deadline)
    assert not sample.converted
