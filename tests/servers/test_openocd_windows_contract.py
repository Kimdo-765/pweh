"""합성 경로 계획과 주입된 Windows 신원 probe 사이의 얇은 통합 계약."""
from __future__ import annotations

import json
from pathlib import Path
import subprocess
import time

import pytest

from openocd_mcp import process, windows_plan as P
from pweh import wininterop as W


@pytest.fixture
def contract(tmp_path):
    deadline = time.monotonic() + 15
    bundle = tmp_path / "합성 bundle"
    scripts = bundle / "scripts"
    scripts.mkdir(parents=True)
    executable = bundle / "openocd.exe"
    executable.write_bytes(b"synthetic executable snapshot only\n")
    interface = scripts / "interface.cfg"
    interface.write_bytes(b"# synthetic interface snapshot\n")
    target = scripts / "target.cfg"
    target.write_bytes(b"# synthetic target snapshot\n")
    root = tmp_path / "run"
    root.mkdir()
    dirs = tuple(root / name for name in ("cwd", "home", "config", "appdata"))
    for directory in dirs:
        directory.mkdir()
    marker = root / ("owner-" + "a" * 32 + ".cfg")
    marker.write_bytes(P.OWNER_CONTENT)

    def snapshot(path):
        return P.observe_file(path, max_bytes=65536, deadline=deadline)

    def cfg(path):
        observed = snapshot(path)
        return P.freeze_cfg(process.CfgRef(str(path), "custom", path), observed,
                            classified_sha256=observed.sha256)

    inputs = P.PipeStartInputs(snapshot(executable), (scripts,), cfg(interface), (cfg(target),), (),
                               "jtag", 100, ("set pweh_test_name {MixedCase}",))
    layout = P.RunLayout(root, *dirs, snapshot(marker))
    converted = []

    def converter(path: Path, remaining_deadline: float) -> str:
        assert remaining_deadline == deadline
        converted.append(path)
        return "C:\\PWEH 합성\\" + "\\".join(path.relative_to(tmp_path).parts) + "\r\n"

    ambient = (("Path", r"C:\Windows"), ("home", "/ambient-home"),
               ("Home", "/ambient-home-duplicate"), ("wslenv", "UNTRUSTED/p"))

    def build():
        return P.build_plan(inputs, layout, ambient_env=ambient, path_converter=converter,
                            deadline=deadline)

    return build, converted, interface, deadline


def _row(plan, *, creation="133000000000000000"):
    # list2cmdline은 순수 문자열 함수이며 프로세스를 실행하지 않는다.
    return {"pid": 4321, "image": plan.launch.image, "creation": creation,
            "cmd": subprocess.list2cmdline(plan.argv)}


def _snapshot(row):
    return json.dumps({"complete": True, "items": [row]}, ensure_ascii=True).encode("ascii")


def test_projected_plan_is_exact_identity_even_with_local_argv_zero(contract):
    build, converted, _, deadline = contract
    plan = build()
    assert len(converted) == len(set(converted))
    env = dict(plan.env_items)
    assert env["WSLENV"] == P.WSLENV and "/p" not in env["WSLENV"]
    assert env["HOME"] == env["USERPROFILE"]
    assert {key for key in env if key.lower() == "home"} == {"HOME"}
    assert plan.argv[0] == plan.executable and plan.argv[0].startswith("/")
    assert plan.launch.image.startswith("C:\\")
    assert plan.launch.marker_cfg in plan.launch.argv_tail
    assert all(plan.launch.argv_tail[index - 1] in ("-f", "-s") for index in plan.launch.path_arg_indices)
    calls = []

    def runner(script, end):
        assert script == W.QUERY_SCRIPT
        assert 0 < end <= deadline
        calls.append(script)
        return _snapshot(_row(plan))

    observed = W.WindowsOwnedProcessProbe(runner=runner).observe(plan.launch, deadline=deadline)
    assert len(observed) == 1
    assert W.matches_launch(observed[0], plan.launch, deadline=deadline)
    assert len(calls) == 1


def test_new_creation_cannot_be_cleaned_with_old_plan_observation(contract):
    build, _, _, deadline = contract
    plan = build()
    current = [_row(plan)]
    calls = []

    def runner(script, end):
        calls.append(script)
        assert script == W.QUERY_SCRIPT, "오래된 관찰로 종료 요청을 보냈다"
        return _snapshot(current[0])

    probe = W.WindowsOwnedProcessProbe(runner=runner)
    observed = probe.observe(plan.launch, deadline=deadline)
    current[0] = _row(plan, creation="133000000000000010")
    assert probe.terminate_and_confirm(plan.launch, observed, deadline=deadline) is False
    assert calls == [W.QUERY_SCRIPT, W.QUERY_SCRIPT]


def test_changed_cfg_cannot_rebuild_a_plan_from_the_old_snapshot(contract):
    build, converted, interface, _ = contract
    original = build()
    calls_before = len(converted)
    interface.write_bytes(b"# changed after snapshot\n")
    with pytest.raises(P.WindowsPlanError) as caught:
        build()
    assert caught.value.code.startswith("openocd_plan_")
    assert len(converted) == calls_before
    assert str(interface) not in str(caught.value)
    # 만들어 둔 계획은 실행 권한이나 마지막 snapshot 검사 후 경로 잠금이 아니다.
    assert original.inputs.interface.file.path == interface
