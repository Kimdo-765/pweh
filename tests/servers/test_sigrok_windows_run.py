"""합성 등록 tree만 사용하는 sigrok 사본·고정 환경·신원 정리 시험."""
from contextlib import contextmanager
from dataclasses import FrozenInstanceError, replace
import hashlib
import json
import os
from pathlib import Path
import stat
import time
from types import SimpleNamespace

import pytest

from pweh import windows_bundle as B
from sigrok_mcp import windows_run as R

FILES = {"sigrok-cli.exe": b"PWEH SYNTHETIC EXE", "python34.dll": b"PWEH SYNTHETIC DLL",
         "python34.zip": b"PWEH SYNTHETIC ZIP", "helper.pyd": b"PWEH SYNTHETIC PYD",
         "share/libsigrokdecode/decoders/test/pd.py": b"# PWEH SYNTHETIC decoder\n",
         "share/sigrok-firmware/test.bin": b"PWEH SYNTHETIC firmware", "COPYING": b"SYNTHETIC"}


def end(seconds=10):
    return time.monotonic() + seconds


def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def registry(monkeypatch):
    """private 등록 bytes 입구만 바꾸고 운영 검증기는 그대로 통과한다."""
    index, raws = {"schema_version": 1, "tools": {}}, {}
    for tool in ("openocd", "sigrok"):
        rid = R.RELEASE_ID if tool == "sigrok" else "synthetic-v1"
        source = {"artifact_url": "https://example.invalid/synthetic.zip", "artifact_name": "synthetic.zip",
                  "artifact_size": 1, "artifact_sha256": "a" * 64, "digest_basis": "supplier-checksum",
                  "checksum_metadata": {"repository": "https://example.invalid/source", "ref": "v1", "path": "pin.json"},
                  "extractor": None}
        if tool == "sigrok":
            source.update(digest_basis="first-acquisition", checksum_metadata=None,
                          extractor={"version": "1", "artifact_url": "https://example.invalid/extractor",
                                     "artifact_size": 1, "artifact_sha256": "b" * 64, "executable_sha256": "c" * 64})
        doc = {"schema_version": 1, "tool": tool, "release_id": rid, "platform": "windows-amd64", "source": source,
               "payload": {"archive_root": "" if tool == "sigrok" else "synthetic/",
                           "recipe": "nsis-selected-v1" if tool == "sigrok" else "zip-strip-fixed-root-v1",
                           "entrypoint": "sigrok-cli.exe", "python_zip": "python34.zip",
                           "search_dirs": ["share/libsigrokdecode/decoders", "share/sigrok-firmware"],
                           "file_count": len(FILES), "total_bytes": sum(map(len, FILES.values())),
                           "excluded": {"installer_plugins": 0, "usb_driver_installers": 0,
                                        "example_captures": 0, "uninstaller": 0}},
               "files": [{"path": p, "size": len(d), "sha256": hashlib.sha256(d).hexdigest()} for p, d in sorted(FILES.items())],
               "known_limitations": ["python34_signature_decoder_unsupported"]}
        raw = canonical(doc)
        name = f"windows-bundles/{tool}-{rid}.json"
        raws[name] = raw
        index["tools"][tool] = {"preferred_release_id": rid,
                               "releases": [{"release_id": rid, "manifest": name, "sha256": hashlib.sha256(raw).hexdigest()}]}
    monkeypatch.setattr(B, "_read_registry_bytes", lambda: canonical(index))
    monkeypatch.setattr(B, "_read_registered_manifest_bytes", lambda name: raws[name])


@pytest.fixture
def sample(tmp_path, monkeypatch):
    registry(monkeypatch)
    root = tmp_path / "source"
    for name, data in FILES.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
    bundle = B.verify_payload(root, "sigrok", deadline=end())
    parent = tmp_path / "runs"
    parent.mkdir(mode=0o700)
    calls = []

    def converter(path, deadline):
        assert 0 < deadline - time.monotonic() <= 30
        calls.append(path)
        return "C:\\PWEH\\" + "\\".join(path.relative_to(tmp_path).parts)

    def prepare(**kw):
        args = dict(bundle=bundle, parent=parent, path_converter=converter, ambient_env=(), deadline=end())
        args.update(kw)
        return R.prepare_run(**args)

    yield SimpleNamespace(bundle=bundle, root=root, parent=parent, calls=calls, converter=converter,
                          prepare=prepare, tmp=tmp_path)
    # 보존 시험에서 남긴 합성 fd만 닫는다. 운영 unknown 정리 성공을 흉내 내지 않는다.
    for key, record in tuple(R._RUNS.items()):
        if key.is_relative_to(tmp_path):
            for entry in record.entries.values():
                if entry.fd is not None:
                    os.close(entry.fd)
                    entry.fd = None
                if entry.observed is not None and stat.S_ISDIR(entry.observed.st_mode):
                    try:
                        (key / entry.path).chmod(0o700)
                    except OSError:
                        pass
            if record.parent_fd >= 0:
                os.close(record.parent_fd)
                record.parent_fd = -1
            del R._RUNS[key]


def fixed(error):
    assert str(error).startswith("[sigrok_run_")
    assert str(error).endswith("sigrok Windows 실행 사본 또는 입력 검증을 완료하지 못했습니다.")
    assert "SYNTHETIC_PRIVATE" not in str(error)
    assert error.data == {} and error.hint is None


def test_full_copy_fixed_plans_environment_and_source_unchanged(sample):
    source_before = {p: ((sample.root / p).stat().st_ino, (sample.root / p).read_bytes()) for p in FILES}
    prepared = sample.prepare(ambient_env=(("PATH", "system path"), ("PYTHONPATH", "SYNTHETIC_PRIVATE"),
                                          ("Sigrokdecode_dir", "SYNTHETIC_PRIVATE"), ("WSLENV", "PYTHONPATH/p")))
    assert prepared.root.parent == sample.parent and prepared.root.name.startswith("sigrok-info-")
    assert {str(p.relative_to(prepared.payload)) for p in prepared.payload.rglob("*") if p.is_file()} == set(FILES)
    for p, data in FILES.items():
        path = prepared.payload / p
        assert path.read_bytes() == data and path.stat().st_ino != (sample.root / p).stat().st_ino
        assert path.stat().st_nlink == 1
        assert stat.S_IMODE(path.stat().st_mode) == (0o555 if p.endswith(".exe") else 0o444)
    assert all(stat.S_IMODE(p.stat().st_mode) == 0o555 for p in [prepared.payload, *prepared.payload.rglob("*")] if p.is_dir())
    assert source_before == {p: ((sample.root / p).stat().st_ino, (sample.root / p).read_bytes()) for p in FILES}
    env = dict(prepared.env_items)
    assert "SYNTHETIC_PRIVATE" not in str(env) and env["PATH"] == "system path"
    assert env["PYTHONPATH"].endswith("\\payload\\python34.zip")
    assert env["SIGROK_FIRMWARE_DIR"].endswith("\\payload\\share\\sigrok-firmware")
    assert env["SIGROKDECODE_DIR"].endswith("\\payload\\share\\libsigrokdecode\\decoders")
    assert env["PYTHONDONTWRITEBYTECODE"] == env["PYTHONNOUSERSITE"] == "1"
    assert env["HOME"] == env["USERPROFILE"] == env["XDG_CACHE_HOME"]
    assert all(x.endswith("/w") for x in env["WSLENV"].split(":"))
    assert len(sample.calls) == len(set(sample.calls))
    for mode, flag in (("version", "--version"), ("list", "--list-supported")):
        plan = R.plan_command(prepared, mode)
        assert plan.argv == (str(prepared.image), flag)
        assert plan.launch.image == prepared.windows_image and plan.launch.argv_tail == (flag,)
        assert plan.cwd == prepared.empty and plan.env_items == prepared.env_items
    with pytest.raises(FrozenInstanceError):
        prepared.windows_image = "changed"
    R.revalidate_run(prepared, deadline=end())
    assert R.release_run(prepared, deadline=end())
    assert not prepared.root.exists() and R.release_run(prepared, deadline=end())


@pytest.mark.parametrize("mode", ["scan", "--version", "VERSION", None, True, (), "SYNTHETIC_PRIVATE"])
def test_command_modes_are_closed(sample, mode):
    prepared = sample.prepare()
    with pytest.raises(R.WindowsRunError) as error:
        R.plan_command(prepared, mode)
    fixed(error.value)
    assert R.release_run(prepared, deadline=end())


@pytest.mark.parametrize("deadline", [True, None, "10", float("nan"), float("inf"), 10 ** 400, -1])
def test_bad_deadline_creates_no_run(sample, deadline):
    with pytest.raises(R.WindowsRunError) as error:
        sample.prepare(deadline=deadline)
    fixed(error.value)
    assert list(sample.parent.iterdir()) == [] and error.value.prepared_run is None


@pytest.mark.parametrize("cancel", [lambda: True, lambda: 1, lambda: (_ for _ in ()).throw(ValueError("SYNTHETIC_PRIVATE"))])
def test_cancel_boundaries_are_fixed(sample, cancel):
    with pytest.raises(R.WindowsRunError) as error:
        sample.prepare(cancel=cancel)
    fixed(error.value)
    assert list(sample.parent.iterdir()) == []


@pytest.mark.parametrize("env", [[("PATH", "x")], (("PATH", "x"), ("Path", "y")),
                                (("PYTHONPATH", "x"), ("Pythonpath", "y")), (("A", "x\x00"),),
                                (("A=B", "x"),), (("A", 1),), (("A", "x" * (256 << 10)),)])
def test_environment_invalid_before_copy(sample, env):
    with pytest.raises(R.WindowsRunError) as error:
        sample.prepare(ambient_env=env)
    fixed(error.value)
    assert list(sample.parent.iterdir()) == []


@pytest.mark.parametrize("output", ["relative", b"\xff", "C:\\one\n\n", "C:\\same", None, "C:\\" + "x" * 9000])
def test_converter_error_has_owned_partial_and_no_raw_leak(sample, output):
    with pytest.raises(R.WindowsRunError) as error:
        sample.prepare(path_converter=lambda p, d: output)
    fixed(error.value)
    assert error.value.prepared_run is not None
    assert R.release_run(error.value.prepared_run, deadline=end())
    assert list(sample.parent.iterdir()) == []


def test_converter_exception_and_directory_mode_change(sample):
    def converter(path, deadline):
        (path.parent.parent / "empty").chmod(0o777)
        raise ValueError("SYNTHETIC_PRIVATE")
    with pytest.raises(R.WindowsRunError) as error:
        sample.prepare(path_converter=converter)
    fixed(error.value)
    assert not R.release_run(error.value.prepared_run, deadline=end())


@pytest.mark.parametrize("area", ["source", "copy", "empty", "root"])
def test_changes_are_not_silently_adopted_or_deleted(sample, area):
    prepared = sample.prepare()
    if area == "source":
        path = sample.root / "python34.dll"
        path.write_bytes(b"SYNTHETIC_PRIVATE")
    elif area == "copy":
        path = prepared.payload / "python34.dll"
        path.chmod(0o644)
        path.write_bytes(b"SYNTHETIC_PRIVATE")
    else:
        path = (prepared.empty if area == "empty" else prepared.root) / "unknown"
        path.write_bytes(b"SYNTHETIC_PRIVATE")
    with pytest.raises(R.WindowsRunError) as error:
        R.revalidate_run(prepared, deadline=end())
    fixed(error.value)
    if area == "source":
        assert R.release_run(prepared, deadline=end())
    else:
        assert not R.release_run(prepared, deadline=end())
        assert path.read_bytes() == b"SYNTHETIC_PRIVATE"


@pytest.mark.parametrize("kind", ["regular", "symlink", "hardlink"])
def test_same_bytes_replacement_rejected_and_preserved(sample, kind):
    prepared = sample.prepare()
    path = prepared.payload / "python34.dll"
    prepared.payload.chmod(0o755)
    old = prepared.root / "saved"
    path.rename(old)
    if kind == "regular":
        path.write_bytes(FILES["python34.dll"])
        path.chmod(0o444)
    elif kind == "symlink":
        path.symlink_to(old)
    else:
        os.link(old, path)
    with pytest.raises(R.WindowsRunError):
        R.revalidate_run(prepared, deadline=end())
    assert not R.release_run(prepared, deadline=end()) and path.exists()


def test_pycache_is_unknown_not_a_cleanup_exception(sample):
    prepared = sample.prepare()
    directory = prepared.payload / "share/libsigrokdecode/decoders/test"
    directory.chmod(0o755)
    cache = directory / "__pycache__"
    cache.mkdir()
    (cache / "pd.pyc").write_bytes(b"SYNTHETIC_PRIVATE")
    assert not R.release_run(prepared, deadline=end())
    assert (cache / "pd.pyc").read_bytes() == b"SYNTHETIC_PRIVATE"


@pytest.mark.parametrize("which", ["parent", "root", "empty"])
def test_directory_name_swap_preserves_replacements(sample, which):
    prepared = sample.prepare()
    path = {"parent": sample.parent, "root": prepared.root, "empty": prepared.empty}[which]
    saved = path.with_name(path.name + "-saved")
    path.rename(saved)
    path.mkdir(mode=0o700)
    (path / "untouched").write_bytes(b"SYNTHETIC_PRIVATE")
    with pytest.raises(R.WindowsRunError):
        R.revalidate_run(prepared, deadline=end())
    assert not R.release_run(prepared, deadline=end())
    assert (path / "untouched").read_bytes() == b"SYNTHETIC_PRIVATE"


def test_source_changed_during_fd_copy_never_returns_prepared(sample, monkeypatch):
    original = B.open_verified_file

    @contextmanager
    def changed(bundle, relative, **kwargs):
        with original(bundle, relative, **kwargs) as fd:
            yield fd
            if relative == "python34.dll":
                (sample.root / relative).write_bytes(b"SYNTHETIC_PRIVATE")

    monkeypatch.setattr(B, "open_verified_file", changed)
    with pytest.raises(R.WindowsRunError) as error:
        sample.prepare()
    fixed(error.value)
    assert R.release_run(error.value.prepared_run, deadline=end())


def test_short_writes_copy_completely_and_failed_write_preserves_handle(sample, monkeypatch):
    original = os.write
    monkeypatch.setattr(R.os, "write", lambda fd, data: original(fd, data[:2]))
    prepared = sample.prepare()
    assert prepared.image.read_bytes() == FILES["sigrok-cli.exe"]
    assert R.release_run(prepared, deadline=end())
    monkeypatch.setattr(R.os, "write", lambda fd, data: 0)
    with pytest.raises(R.WindowsRunError) as error:
        sample.prepare()
    fixed(error.value)
    assert R.release_run(error.value.prepared_run, deadline=end())


def test_cancellation_mid_copy_is_cleanable_without_cancel_callback(sample, monkeypatch):
    stopped = False
    original = os.write

    def write(fd, data):
        nonlocal stopped
        result = original(fd, data)
        stopped = True
        return result

    monkeypatch.setattr(R.os, "write", write)
    with pytest.raises(R.WindowsRunError) as error:
        sample.prepare(cancel=lambda: stopped)
    assert error.value.prepared_run is not None
    assert R.release_run(error.value.prepared_run, deadline=end())


def test_modified_frozen_handle_cannot_change_environment_or_image(sample):
    prepared = sample.prepare()
    with pytest.raises(R.WindowsRunError):
        R.plan_command(replace(prepared, windows_image="C:\\other\\sigrok-cli.exe"))
    assert not R.release_run(replace(prepared, windows_image="C:\\other\\sigrok-cli.exe"), deadline=end())
    assert R.release_run(prepared, deadline=end())


def test_partial_cleanup_can_resume_after_unlink_failure(sample, monkeypatch):
    prepared = sample.prepare()
    original = os.unlink
    calls = 0

    def unlink(*args, **kwargs):
        nonlocal calls
        calls += 1
        if calls == 2:
            raise OSError("SYNTHETIC_PRIVATE")
        return original(*args, **kwargs)

    with monkeypatch.context() as patch:
        patch.setattr(R.os, "unlink", unlink)
        assert not R.release_run(prepared, deadline=end())
    assert R.release_run(prepared, deadline=end())


def test_caller_budget_is_clamped_for_converter_and_bundle(sample, monkeypatch):
    original = B.revalidate_bundle
    calls = []

    def check(bundle, *, deadline, **kwargs):
        assert 0 < deadline - time.monotonic() <= 45
        calls.append(deadline)
        return original(bundle, deadline=deadline, **kwargs)

    monkeypatch.setattr(B, "revalidate_bundle", check)
    prepared = sample.prepare(deadline=end(90))
    assert calls and len(sample.calls) == 7
    assert R.release_run(prepared, deadline=end())


@pytest.mark.parametrize("mode", [0o755, 0o777])
def test_existing_parent_permissions_and_late_change_are_rejected(sample, mode):
    sample.parent.chmod(mode)
    with pytest.raises(R.WindowsRunError) as error:
        sample.prepare()
    assert error.value.prepared_run is None and list(sample.parent.iterdir()) == []
    sample.parent.chmod(0o700)
    prepared = sample.prepare()
    sample.parent.chmod(mode)
    with pytest.raises(R.WindowsRunError):
        R.revalidate_run(prepared, deadline=end())
    assert not R.release_run(prepared, deadline=end())
    sample.parent.chmod(0o700)
    assert R.release_run(prepared, deadline=end())


def test_parent_symlink_and_profile_mismatch_create_no_run(sample):
    alias = sample.tmp / "alias"
    alias.symlink_to(sample.parent, target_is_directory=True)
    with pytest.raises(R.WindowsRunError):
        sample.prepare(parent=alias)
    with pytest.raises(R.WindowsRunError):
        sample.prepare(bundle=replace(sample.bundle, release_id="unknown-version"))
    assert list(sample.parent.iterdir()) == []


def test_fixed_cache_directories_are_preseeded_and_repeated_mkdir_does_not_mutate(sample):
    prepared = sample.prepare()
    relative = {"Microsoft", "Microsoft/Windows", "Microsoft/Windows/Caches"}
    assert {p.relative_to(prepared.empty).as_posix() for p in prepared.empty.rglob("*")} == relative
    paths = [prepared.empty, *(prepared.empty / name for name in sorted(relative))]
    before = {p: R._identity(p.stat()) for p in paths}
    assert all(p.is_dir() and stat.S_IMODE(p.stat().st_mode) == 0o700 for p in paths)
    # 기존 경로에 대한 mkdir 호출은 성공/이미 존재 결과 뒤 내용을 바꾸지 않는다.
    for _ in range(2):
        for path in paths:
            path.mkdir(parents=True, exist_ok=True)
        R.revalidate_run(prepared, deadline=end())
        assert {p: R._identity(p.stat()) for p in paths} == before
    assert R.release_run(prepared, deadline=end())
    assert not prepared.root.exists()


@pytest.mark.parametrize("kind", ["file", "directory"])
def test_unpredicted_cache_contents_stay_unverified_and_preserved(sample, kind):
    prepared = sample.prepare()
    extra = prepared.empty / "Microsoft/Windows/Caches/unregistered"
    if kind == "file":
        extra.write_bytes(b"SYNTHETIC_PRIVATE")
    else:
        extra.mkdir()
    with pytest.raises(R.WindowsRunError):
        R.revalidate_run(prepared, deadline=end())
    assert not R.release_run(prepared, deadline=end())
    assert extra.exists()
