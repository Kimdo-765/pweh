"""Windows OpenOCD 계획의 합성 파일·환경·경로 경계. 외부 프로그램은 실행하지 않는다."""

from dataclasses import FrozenInstanceError, replace
import hashlib
import os
from pathlib import Path
from types import SimpleNamespace
import time

import pytest

from openocd_mcp import process, semihosting, windows_plan as W


def _deadline():
    return time.monotonic() + 10


def _file(path, data=b"# synthetic\n"):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    return W.observe_file(path, max_bytes=W.MAX_FILE_BYTES, deadline=_deadline())


@pytest.fixture
def sample(tmp_path):
    binary = _file(tmp_path / "bundle" / "openocd.exe", b"SYNTHETIC PE PLACEHOLDER")
    scripts = tmp_path / "bundle" / "scripts"
    scripts.mkdir()
    extra_scripts = tmp_path / "more scripts"
    extra_scripts.mkdir()

    def cfg(name, kind):
        observed = _file(scripts / name)
        ref = process.CfgRef(str(observed.path), kind, observed.path)
        return W.freeze_cfg(ref, observed, classified_sha256=observed.sha256 if kind == "custom" else None)

    interface = cfg("interface.cfg", "standard")
    target = cfg("대상 with spaces.cfg", "standard")
    extra = cfg("extra.cfg", "custom")
    inputs = W.PipeStartInputs(binary, (scripts, extra_scripts), interface, (target,), (extra,),
                               "jtag", 500, ("reset_config none", "set PWEH_CASE KeEpCase"))
    root = tmp_path / "run"
    root.mkdir()
    for name in ("cwd", "home", "config", "appdata"):
        (root / name).mkdir()
    owner = _file(root / ("owner-" + "a" * 32 + ".cfg"), W.OWNER_CONTENT)
    layout = W.RunLayout(root, root / "cwd", root / "home", root / "config", root / "appdata", owner)
    calls = []

    def windows(path):
        return "C:\\PWEH\\" + "\\".join(path.relative_to(tmp_path).parts)

    def converter(path, deadline):
        assert type(path) is type(tmp_path)
        assert deadline > time.monotonic()
        calls.append(path)
        return windows(path)

    def plan(**kwargs):
        params = dict(inputs=inputs, layout=layout, ambient_env=(), path_converter=converter, deadline=_deadline())
        params.update(kwargs)
        return W.build_plan(**params)

    return SimpleNamespace(inputs=inputs, layout=layout, calls=calls, converter=converter,
                           windows=windows, plan=plan, tmp=tmp_path)


def test_plan_preserves_local_identity_and_exact_windows_guard_order(sample):
    p = sample.plan()
    i = sample.inputs
    assert p.executable == str(i.executable.path) == p.argv[0]
    assert p.cwd == sample.layout.cwd
    assert p.launch.image == sample.windows(i.executable.path)
    assert p.launch.argv_tail == p.argv[1:]
    assert p.launch.path_arg_indices == (2, 4, 12, 18, 22, 26)
    assert [p.launch.argv_tail[n] for n in p.launch.path_arg_indices] == [
        *(sample.windows(d) for d in i.search_dirs), sample.windows(i.interface.file.path),
        sample.windows(i.targets[0].file.path), sample.windows(i.extras[0].file.path),
        sample.windows(sample.layout.owner_cfg.path),
    ]
    assert p.argv[:14] == (
        str(i.executable.path), "-d3", "-s", sample.windows(i.search_dirs[0]),
        "-s", sample.windows(i.search_dirs[1]),
        "-c", "if {[catch {tcl port pipe}]} {tcl_port pipe}",
        "-c", "if {[catch {telnet port disabled}]} {telnet_port disabled}",
        "-c", "if {[catch {gdb port disabled}]} {gdb_port disabled}",
        "-f", sample.windows(i.interface.file.path),
    )
    assert p.argv[-6:] == ("-c", semihosting.PRE_INIT_SCRIPT, "-c", "init", "-c", semihosting.POST_INIT_SCRIPT)
    for n, arg in enumerate(p.argv):
        if arg == "-f":
            assert p.argv[n + 2:n + 4] == ("-c", semihosting.EARLY_CHECK_SCRIPT)
    assert "set PWEH_CASE KeEpCase" in p.argv
    assert not any("bindto" in x for x in p.argv)
    assert len(sample.calls) == len(set(sample.calls))
    assert sample.calls.count(sample.layout.home) == 1
    assert not hasattr(p, "approved") and not hasattr(p, "bundle_verified")
    with pytest.raises(FrozenInstanceError):
        p.argv = ()


@pytest.mark.parametrize("transport", [None, *process.TRANSPORTS])
@pytest.mark.parametrize("counts", [(0, 0), (1, 0), (0, 1), (1, 1)])
def test_path_indices_cover_only_generated_path_positions(sample, transport, counts):
    nt, ne = counts
    i = replace(sample.inputs, search_dirs=sample.inputs.search_dirs[:1], transport=transport,
                targets=sample.inputs.targets[:nt], extras=sample.inputs.extras[:ne], extra_commands=("-f",))
    p = sample.plan(inputs=i)
    # -c 인자 '-f'는 경로 옵션으로 해석하면 안 된다.
    expected = [2, 10]
    start = 14 + (2 if transport else 0)
    expected.extend(start + n * 4 for n in range(nt + ne + 1))
    assert p.launch.path_arg_indices == tuple(expected)


def test_converter_runs_once_and_preserves_utf8_unc_and_newline(sample):
    calls = []

    def convert(path, _):
        calls.append(path)
        return ("\\\\wsl.localhost\\Ubuntu\\합성 폴더\\" + "/".join(path.relative_to(sample.tmp).parts) + "\r\n").encode()

    plan = sample.plan(path_converter=convert)
    assert len(calls) == len(set(calls))
    assert all("\n" not in plan.launch.argv_tail[n] for n in plan.launch.path_arg_indices)
    assert "대상 with spaces.cfg" in " ".join(plan.argv)
    assert "\\\\wsl.localhost\\Ubuntu\\합성 폴더\\bundle/scripts" in plan.argv


def test_environment_has_one_canonical_nonempty_control_and_does_not_mutate(sample):
    ambient = (("PATH", "/synthetic/bin"), ("HOME", "bad"), ("Home", "also bad"),
               ("WSLENV", "INJECT/p"), ("wslenv", "HOME/p"), ("APPDATA", ""), ("USERPROFILE", "wrong"))
    before = tuple(ambient)
    env = dict(sample.plan(ambient_env=ambient).env_items)
    assert ambient == before
    assert env == {
        "PATH": "/synthetic/bin", "OPENOCD_SCRIPTS": sample.windows(sample.inputs.search_dirs[0]),
        "HOME": sample.windows(sample.layout.home), "USERPROFILE": sample.windows(sample.layout.home),
        "XDG_CONFIG_HOME": sample.windows(sample.layout.config_home), "APPDATA": sample.windows(sample.layout.appdata),
        "WSLENV": "OPENOCD_SCRIPTS/w:HOME/w:XDG_CONFIG_HOME/w:APPDATA/w:USERPROFILE/w",
    }
    assert "/p" not in env["WSLENV"] and all(env[k] for k in env)


@pytest.mark.parametrize("ambient", [
    (("PATH", "a"), ("Path", "a")), (("bad=name", "v"),), (("x", "a\x00b"),),
    (("이름", "v"),), (("", "v"),), (("x", "\ud800"),), (("x", 1),),
    (("x", "x" * 8193),), tuple((f"V{i}", "") for i in range(257)),
    tuple((f"V{i}", "x" * 8192) for i in range(33)), [["x", "y"]], (("x",),),
])
def test_ambient_is_bounded_and_unambiguous(sample, ambient):
    with pytest.raises(W.WindowsPlanError):
        sample.plan(ambient_env=ambient)
    assert sample.calls == []


@pytest.mark.parametrize("projection", [
    b"\xff", b"x" * 8193, "C:\\good\\bad.cfg\n\n", "C:relative", "C:\\a:stream", "C:\\bad. ",
    "C:\\NUL.cfg", "\\\\server\\share\\x", "C:\\..\\x", "C:\\x\x00", " C:\\x", None,
])
def test_bad_converter_result_is_fixed_failure_without_fallback(sample, projection):
    calls = []

    def bad(path, deadline):
        calls.append(path)
        return projection

    with pytest.raises(W.WindowsPlanError) as caught:
        sample.plan(path_converter=bad)
    assert len(calls) == 1
    assert str(sample.tmp) not in str(caught.value)


def test_converter_exception_does_not_leak_and_never_retries(sample):
    def bad(path, deadline):
        raise ValueError("PRIVATE /real/path token=SECRET")

    with pytest.raises(W.WindowsPlanError) as caught:
        sample.plan(path_converter=bad)
    assert "PRIVATE" not in str(caught.value) and "SECRET" not in str(caught.value)


def test_distinct_local_paths_cannot_collapse_to_one_windows_projection(sample):
    with pytest.raises(W.WindowsPlanError):
        sample.plan(path_converter=lambda p, d: r"C:\same\openocd.exe")


@pytest.mark.parametrize("change", ["bytes", "replace", "symlink", "growth", "mode"])
def test_snapshot_change_is_rejected_before_converter(sample, change):
    p = sample.inputs.extras[0].file.path
    if change == "bytes":
        p.write_bytes(b"# SYNTHETIC\n")
    elif change == "replace":
        data = p.read_bytes()
        p.unlink()
        p.write_bytes(data)
    elif change == "symlink":
        original = p.with_suffix(".original")
        p.rename(original)
        p.symlink_to(original)
    elif change == "growth":
        p.write_bytes(b"x" * 100)
    else:
        p.chmod(0o600 if p.stat().st_mode & 0o077 else 0o644)
    with pytest.raises(W.WindowsPlanError):
        sample.plan()
    assert sample.calls == []


@pytest.mark.parametrize("place", ["cwd", "home", "config_home", "appdata", "root"])
def test_run_directories_require_exact_shape(sample, place):
    (getattr(sample.layout, place) / "unexpected.cfg").write_bytes(b"# wrong")
    with pytest.raises(W.WindowsPlanError):
        sample.plan()


@pytest.mark.parametrize("change", ["owner-content", "owner-name", "aliased-dir", "symlink-dir"])
def test_run_marker_and_directory_roles_are_fixed(sample, change):
    layout = sample.layout
    if change == "owner-content":
        p = layout.owner_cfg.path
        p.write_bytes(b"reset run\n")
        layout = replace(layout, owner_cfg=W.observe_file(p, max_bytes=100, deadline=_deadline()))
    elif change == "owner-name":
        p = layout.owner_cfg.path.with_name("arbitrary.cfg")
        layout.owner_cfg.path.rename(p)
        layout = replace(layout, owner_cfg=W.observe_file(p, max_bytes=100, deadline=_deadline()))
    elif change == "aliased-dir":
        layout = replace(layout, home=layout.cwd)
    else:
        layout.home.rmdir()
        layout.home.symlink_to(layout.cwd)
    with pytest.raises(W.WindowsPlanError):
        sample.plan(layout=layout)


@pytest.mark.parametrize("mutation", ["cfg", "cwd", "root", "scripts"])
def test_converter_side_mutation_is_not_returned_as_valid_plan(sample, mutation):
    changed = False

    def convert(path, deadline):
        nonlocal changed
        if not changed:
            changed = True
            if mutation == "cfg":
                sample.inputs.interface.file.path.write_bytes(b"changed")
            elif mutation == "scripts":
                (sample.inputs.search_dirs[1] / "changed.cfg").write_bytes(b"changed")
            else:
                (getattr(sample.layout, mutation) / "changed.cfg").write_bytes(b"changed")
        return sample.windows(path)

    with pytest.raises(W.WindowsPlanError):
        sample.plan(path_converter=convert)


@pytest.mark.parametrize("deadline", [None, True, float("nan"), float("inf"), -1, 10**400])
def test_invalid_or_expired_deadline_has_fixed_error(sample, deadline):
    with pytest.raises(W.WindowsPlanError):
        sample.plan(deadline=deadline)
    assert sample.calls == []


def test_future_deadline_and_converter_overrun_are_rejected(sample, monkeypatch):
    with pytest.raises(W.WindowsPlanError):
        sample.plan(deadline=time.monotonic() + 31)
    clock = [100.0]
    monkeypatch.setattr(W.time, "monotonic", lambda: clock[0])

    def slow(path, deadline):
        clock[0] = 110.0
        return sample.windows(path)

    with pytest.raises(W.WindowsPlanError) as caught:
        sample.plan(deadline=105.0, path_converter=slow)
    assert caught.value.code == "openocd_plan_timeout"


def test_freeze_copies_cfg_and_binds_classified_bytes(sample):
    observed = sample.inputs.extras[0].file
    ref = process.CfgRef(str(observed.path), "custom", observed.path)
    with pytest.raises(W.WindowsPlanError):
        W.freeze_cfg(ref, observed)
    with pytest.raises(W.WindowsPlanError):
        W.freeze_cfg(ref, observed, classified_sha256="0" * 64)
    frozen = W.freeze_cfg(ref, observed, classified_sha256=observed.sha256)
    ref.arg = "other.cfg"
    assert frozen.file.path == observed.path
    assert frozen.file.sha256 == observed.sha256


@pytest.mark.parametrize("kind,arg,path", [("unresolved", "missing.cfg", None), ("unknown", "same", None)])
def test_unresolved_cfg_cannot_delegate_to_windows_search(sample, kind, arg, path):
    with pytest.raises(W.WindowsPlanError):
        W.freeze_cfg(process.CfgRef(arg, kind, path), sample.inputs.interface.file)


@pytest.mark.parametrize("field,value", [
    ("transport", "unknown"), ("adapter_speed_khz", True), ("adapter_speed_khz", -1),
    ("extra_commands", ["reset halt"]), ("extra_commands", ("x" * 8193,)),
    ("extra_commands", ("x\x00",)), ("extra_commands", (" ",)),
    ("extra_commands", tuple("x" for _ in range(65))), ("search_dirs", ()),
    ("targets", tuple(None for _ in range(64))),
])
def test_strict_request_shape_is_bounded_before_file_work(sample, field, value):
    with pytest.raises(W.WindowsPlanError):
        sample.plan(inputs=replace(sample.inputs, **{field: value}))
    assert sample.calls == []


def test_argv_total_limit_rejects_many_individually_valid_commands(sample):
    with pytest.raises(W.WindowsPlanError):
        sample.plan(inputs=replace(sample.inputs, extra_commands=("set x " + "x" * 8100,) * 4))


def test_file_observation_hashes_empty_and_regular_input(tmp_path):
    path = tmp_path / "sample"
    path.write_bytes(b"")
    empty = W.observe_file(path, max_bytes=0, deadline=_deadline())
    assert empty.size == 0 and empty.sha256 == hashlib.sha256(b"").hexdigest()
    path.write_bytes(b"PWEH SYNTHETIC")
    result = W.observe_file(path, max_bytes=14, deadline=_deadline())
    assert result.sha256 == hashlib.sha256(b"PWEH SYNTHETIC").hexdigest()
    assert result.identity[3] == result.size == 14


@pytest.mark.parametrize("kind", ["fifo", "directory", "symlink", "parent-symlink", "missing"])
def test_observation_never_reads_special_or_unresolved_input(tmp_path, kind):
    p = tmp_path / "input"
    if kind == "fifo":
        os.mkfifo(p)
    elif kind == "directory":
        p.mkdir()
    elif kind == "symlink":
        source = tmp_path / "source"
        source.write_bytes(b"synthetic")
        p.symlink_to(source)
    elif kind == "parent-symlink":
        source = tmp_path / "source"
        source.mkdir()
        (source / "file").write_bytes(b"synthetic")
        p.symlink_to(source)
        p = p / "file"
    with pytest.raises(W.WindowsPlanError):
        W.observe_file(p, max_bytes=1024, deadline=_deadline())


def test_observation_does_not_read_oversized_file_or_leak_fd(tmp_path, monkeypatch):
    p = tmp_path / "large"
    p.write_bytes(b"x" * 20)
    real_open, real_close = os.open, os.close
    opened = set()

    def open_fd(*args, **kwargs):
        fd = real_open(*args, **kwargs)
        opened.add(fd)
        return fd

    def close_fd(fd):
        opened.remove(fd)
        return real_close(fd)

    monkeypatch.setattr(W.os, "open", open_fd)
    monkeypatch.setattr(W.os, "close", close_fd)
    monkeypatch.setattr(W.os, "read", lambda *a: pytest.fail("상한 밖 파일을 읽으면 안 됩니다"))
    with pytest.raises(W.WindowsPlanError):
        W.observe_file(p, max_bytes=19, deadline=_deadline())
    assert opened == set()


def test_observation_detects_name_replacement_during_read(tmp_path, monkeypatch):
    p = tmp_path / "file"
    p.write_bytes(b"synthetic")
    real_read = os.read
    replaced = False

    def read(fd, count):
        nonlocal replaced
        data = real_read(fd, count)
        if not replaced:
            replaced = True
            p.rename(tmp_path / "old")
            p.write_bytes(b"synthetic")
        return data

    monkeypatch.setattr(W.os, "read", read)
    with pytest.raises(W.WindowsPlanError) as caught:
        W.observe_file(p, max_bytes=100, deadline=_deadline())
    assert caught.value.code == "openocd_plan_changed"
