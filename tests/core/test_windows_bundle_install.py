"""로컬 합성 번들의 fd 복사·덮어쓰기 없는 게시·installer 조기 분기 시험."""
from __future__ import annotations

from contextlib import contextmanager
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import threading
import time

import pytest
from pweh import windows_bundle as B

REPO = Path(__file__).resolve().parents[2]
_spec = importlib.util.spec_from_file_location("bundle_installer_test", REPO / "scripts/windows_bundle.py")
I = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(I)
FILES = {"bin/probe.exe": b"PWEH SYNTHETIC executable", "scripts/start.cfg": b"PWEH SYNTHETIC cfg"}


def end():
    return time.monotonic() + 30


def canonical(value):
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n").encode()


def registry(monkeypatch, preferred="v1", *, versions=("v1",)):
    """공개 pin 입구를 추가하지 않고 private 등록 reader만 주입한다."""
    index, raws = {"schema_version": 1, "tools": {}}, {}
    for tool in ("openocd", "sigrok"):
        group = {"preferred_release_id": preferred, "releases": []}
        index["tools"][tool] = group
        for rid in versions:
            source = {"artifact_url": "https://example.invalid/synthetic.zip", "artifact_name": "synthetic.zip",
                      "artifact_size": 100, "artifact_sha256": "a" * 64, "digest_basis": "supplier-checksum",
                      "checksum_metadata": {"repository": "https://example.invalid/source", "ref": "v1", "path": "package.json"},
                      "extractor": None}
            if tool == "sigrok":
                source.update(digest_basis="first-acquisition", checksum_metadata=None,
                              extractor={"version": "1", "artifact_url": "https://example.invalid/extractor.tar",
                                         "artifact_size": 1, "artifact_sha256": "b" * 64, "executable_sha256": "c" * 64})
            doc = {"schema_version": 1, "tool": tool, "release_id": rid, "platform": "windows-amd64", "source": source,
                   "payload": {"archive_root": "synthetic/" if tool == "openocd" else "",
                               "recipe": "zip-strip-fixed-root-v1" if tool == "openocd" else "nsis-selected-v1",
                               "entrypoint": "bin/probe.exe", "search_dirs": ["scripts"], "python_zip": None,
                               "file_count": len(FILES), "total_bytes": sum(map(len, FILES.values())),
                               "excluded": {"installer_plugins": 0, "usb_driver_installers": 0, "example_captures": 0, "uninstaller": 0}},
                   "files": [{"path": p, "size": len(d), "sha256": hashlib.sha256(d).hexdigest()} for p, d in sorted(FILES.items())],
                   "known_limitations": ["authenticode_unverified"]}
            raw = canonical(doc)
            name = f"windows-bundles/{tool}-{rid}.json"
            raws[name] = raw
            group["releases"].append({"release_id": rid, "manifest": name, "sha256": hashlib.sha256(raw).hexdigest()})
    monkeypatch.setattr(B, "_read_registry_bytes", lambda: canonical(index))
    monkeypatch.setattr(B, "_read_registered_manifest_bytes", lambda name: raws[name])
    return index


@pytest.fixture
def source(tmp_path, monkeypatch):
    registry(monkeypatch)
    root = tmp_path / "source"
    for path, data in FILES.items():
        file = root / path
        file.parent.mkdir(parents=True, exist_ok=True)
        file.write_bytes(data)
    return root


def final(prefix, tool="openocd"):
    return B.managed_release_root(prefix, B.load_registered_manifest(tool, deadline=end()))


def install(source, prefix, **kwargs):
    return I.install_bundle("openocd", prefix, source_tree=source, deadline=end(), **kwargs)


def no_pending(prefix):
    assert not list(prefix.glob("windows-bundles/*/.pending-*"))


@pytest.mark.parametrize("tool", ["openocd", "sigrok"])
def test_install_idempotent_check_and_modes(source, tmp_path, tool):
    prefix = tmp_path / "tools"
    (source / "bin/probe.exe").chmod(0o644)
    (source / "scripts/start.cfg").chmod(0o4755)
    result = I.install_bundle(tool, prefix, source_tree=source, deadline=end())
    assert result["status"] == "installed"
    root = final(prefix, tool)
    snapshot = {str(p.relative_to(root)): (p.stat().st_ino, p.read_bytes()) for p in root.rglob("*") if p.is_file()}
    assert I.install_bundle(tool, prefix, deadline=end())["status"] == "already-present"
    assert I.check_bundle(tool, prefix, deadline=end())["status"] == "verified"
    assert snapshot == {str(p.relative_to(root)): (p.stat().st_ino, p.read_bytes()) for p in root.rglob("*") if p.is_file()}
    assert stat.S_IMODE((root / "payload/bin/probe.exe").stat().st_mode) == 0o555
    for p in [root, *root.rglob("*")]:
        assert stat.S_IMODE(p.stat().st_mode) == (0o555 if p.is_dir() or p.name == "probe.exe" else 0o444)
    assert (source / "scripts/start.cfg").stat().st_mode & stat.S_ISUID
    assert set(prefix.iterdir()) == {prefix / "windows-bundles"}
    no_pending(prefix)


@pytest.mark.parametrize("check", [True, False])
def test_missing_without_source_creates_nothing(source, tmp_path, check):
    prefix = tmp_path / "absent"
    with pytest.raises(I.BundleInstallError) as error:
        (I.check_bundle if check else I.install_bundle)("openocd", prefix, deadline=end())
    assert error.value.code == "bundle_missing" and not prefix.exists()


@pytest.mark.parametrize("kind", ["empty", "file", "symlink", "corrupt"])
def test_existing_destination_is_never_replaced(source, tmp_path, kind):
    prefix = tmp_path / "tools"
    dest = final(prefix)
    dest.parent.mkdir(parents=True)
    if kind == "file": dest.write_bytes(b"sentinel")
    elif kind == "symlink": dest.symlink_to(source, target_is_directory=True)
    elif kind == "corrupt":
        install(source, prefix)
        p = dest / "payload/scripts/start.cfg"
        p.chmod(0o644); p.write_bytes(b"corrupt sentinel")
    else: dest.mkdir()
    identity = dest.lstat().st_ino
    with pytest.raises(I.BundleInstallError): install(source, prefix)
    assert dest.lstat().st_ino == identity
    no_pending(prefix)


@pytest.mark.parametrize("check", [True, False])
def test_other_registered_release_in_preferred_path_is_rejected(source, tmp_path, monkeypatch, check):
    prefix = tmp_path / "tools"
    install(source, prefix)
    old = final(prefix)
    registry(monkeypatch, preferred="v2", versions=("v1", "v2"))
    dest = final(prefix)
    old.rename(dest)
    with pytest.raises(I.BundleInstallError) as error:
        (I.check_bundle if check else I.install_bundle)("openocd", prefix, deadline=end())
    assert error.value.code == "bundle_tree_invalid"
    assert json.loads((dest / "release.json").read_bytes())["release_id"] == "v1"


def test_new_registered_release_preserves_old(source, tmp_path, monkeypatch):
    prefix = tmp_path / "tools"
    install(source, prefix); old = final(prefix); ino = old.stat().st_ino
    registry(monkeypatch, preferred="v2", versions=("v1", "v2"))
    install(source, prefix)
    assert old.stat().st_ino == ino and final(prefix) != old


@pytest.mark.parametrize("kind", ["changed", "missing", "extra", "symlink", "hardlink", "fifo"])
def test_bad_source_is_rejected_before_prefix_write(source, tmp_path, kind):
    p = source / "scripts/start.cfg"
    if kind == "changed": p.write_bytes(b"bad")
    elif kind == "missing": p.unlink()
    elif kind == "extra": (source / "extra").write_bytes(b"extra")
    elif kind == "symlink":
        p.unlink(); p.symlink_to(source / "bin/probe.exe")
    elif kind == "hardlink": os.link(p, tmp_path / "hardlink")
    else: p.unlink(); os.mkfifo(p)
    prefix = tmp_path / "tools"
    with pytest.raises(I.BundleInstallError): install(source, prefix)
    assert not prefix.exists()


@pytest.mark.parametrize("alias", [False, True])
def test_source_containment_rejected_before_source_mutation(source, tmp_path, alias):
    chosen = source
    if alias:
        chosen = tmp_path / "alias"; chosen.symlink_to(source, target_is_directory=True)
    prefix = source / "new-prefix"
    with pytest.raises(I.BundleInstallError): install(chosen, prefix)
    assert not prefix.exists() and set(source.iterdir()) == {source / "bin", source / "scripts"}


def test_same_prefix_sibling_source_allowed(source, tmp_path):
    prefix = source.parent
    assert install(source, prefix)["status"] == "installed"


def test_copy_uses_borrowed_verified_fd(source, tmp_path, monkeypatch):
    original, pread = B.open_verified_file, I.os.pread
    active, copied = set(), []
    @contextmanager
    def opened(*args, **kwargs):
        with original(*args, **kwargs) as fd:
            active.add(fd)
            try: yield fd
            finally: active.remove(fd)
    def read(fd, size, offset):
        if active:
            assert fd in active
            copied.append(fd)
        return pread(fd, size, offset)
    monkeypatch.setattr(B, "open_verified_file", opened)
    monkeypatch.setattr(I.os, "pread", read)
    install(source, tmp_path / "tools")
    assert len(copied) >= len(FILES)


@pytest.mark.parametrize("phase", ["before-copy", "after-copy", "extra-after-copy"])
def test_source_identity_changes_prevent_publish(source, tmp_path, monkeypatch, phase):
    prefix = tmp_path / "tools"
    opened, revalidate = B.open_verified_file, B.revalidate_bundle
    fired = False
    def change():
        nonlocal fired
        if fired: return
        fired = True
        if phase == "extra-after-copy": (source / "extra").write_bytes(b"new")
        else:
            p = source / "bin/probe.exe"; data = p.read_bytes()
            p.rename(source / "bin/old"); p.write_bytes(data); (source / "bin/old").unlink()
    @contextmanager
    def wrapper(*args, **kwargs):
        if phase == "before-copy": change()
        with opened(*args, **kwargs) as fd: yield fd
    count = 0
    def check(bundle, **kwargs):
        nonlocal count
        if bundle.release_root is None:
            count += 1
            if count == 2 and phase != "before-copy": change()
        return revalidate(bundle, **kwargs)
    monkeypatch.setattr(B, "open_verified_file", wrapper)
    monkeypatch.setattr(B, "revalidate_bundle", check)
    with pytest.raises(I.BundleInstallError): install(source, prefix)
    assert not final(prefix).exists(); no_pending(prefix)


@pytest.mark.parametrize("fault", ["short-read", "write", "receipt-corrupt", "fsync", "rename-unsupported", "pending-tamper"])
def test_copy_commit_faults_never_report_success(source, tmp_path, monkeypatch, fault):
    prefix = tmp_path / "tools"
    if fault == "short-read":
        original = B.open_verified_file
        @contextmanager
        def opened(*args, **kwargs):
            with original(*args, **kwargs) as fd:
                with monkeypatch.context() as patch:
                    patch.setattr(I.os, "pread", lambda *args: b"")
                    yield fd
        monkeypatch.setattr(B, "open_verified_file", opened)
    elif fault in ("write", "receipt-corrupt"):
        original = I.safeio.write_all
        def write(fd, data):
            if fault == "write": raise OSError("SYNTHETIC_PRIVATE")
            return original(fd, b"{}" if data.startswith(b'{"manifest_sha256"') else data)
        monkeypatch.setattr(I.safeio, "write_all", write)
    elif fault == "fsync":
        monkeypatch.setattr(I.os, "fsync", lambda fd: (_ for _ in ()).throw(OSError("SYNTHETIC_PRIVATE")))
    elif fault == "rename-unsupported":
        monkeypatch.setattr(I, "_rename_noreplace", lambda *a: (_ for _ in ()).throw(I.BundleInstallError("bundle_publish_unsupported")))
    else:
        original = B.revalidate_bundle
        def revalidate(bundle, **kwargs):
            if bundle.release_root is not None:
                p = bundle.root / "scripts/start.cfg"
                p.chmod(0o644); p.write_bytes(b"tampered")
            return original(bundle, **kwargs)
        monkeypatch.setattr(B, "revalidate_bundle", revalidate)
    with pytest.raises(I.BundleInstallError) as error: install(source, prefix)
    assert "SYNTHETIC_PRIVATE" not in str(error.value)
    assert not final(prefix).exists(); no_pending(prefix)


def test_empty_destination_race_not_overwritten(source, tmp_path, monkeypatch):
    original = I._rename_noreplace
    prefix = tmp_path / "tools"
    def race(parent, src, dest):
        os.mkdir(dest, dir_fd=parent)
        return original(parent, src, dest)
    monkeypatch.setattr(I, "_rename_noreplace", race)
    with pytest.raises(I.BundleInstallError): install(source, prefix)
    assert final(prefix).is_dir() and list(final(prefix).iterdir()) == []
    no_pending(prefix)


def test_two_publishers_one_install_one_idempotent(source, tmp_path):
    prefix = tmp_path / "tools"
    results, failures = [], []
    def run():
        try: results.append(install(source, prefix)["status"])
        except Exception as exc: failures.append(exc)
    threads = [threading.Thread(target=run) for _ in range(2)]
    for thread in threads: thread.start()
    for thread in threads: thread.join(10)
    assert not any(t.is_alive() for t in threads)
    assert not failures and sorted(results) == ["already-present", "installed"]
    no_pending(prefix)


def test_lock_deadline_and_cancel(source, tmp_path):
    prefix = tmp_path / "tools"; parent = final(prefix).parent
    parent.mkdir(parents=True)
    with (parent / ".publish.lock").open("wb") as lock:
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
        with pytest.raises(I.BundleInstallError) as error:
            I.install_bundle("openocd", prefix, source_tree=source, deadline=time.monotonic() + .05)
        assert error.value.code == "bundle_timeout"
    with pytest.raises(I.BundleInstallError) as error: install(source, prefix, cancel=lambda: True)
    assert error.value.code == "cancelled" and not final(prefix).exists()


def test_unknown_pending_file_preserved_on_failure(source, tmp_path, monkeypatch):
    prefix = tmp_path / "tools"
    def rename(parent, src, dest):
        root = prefix / "windows-bundles/openocd" / src
        root.chmod(0o755)
        (root / "unknown").write_bytes(b"foreign sentinel")
        raise OSError("SYNTHETIC_PRIVATE")
    monkeypatch.setattr(I, "_rename_noreplace", rename)
    with pytest.raises(I.BundleInstallError) as error: install(source, prefix)
    assert error.value.code == "bundle_cleanup_pending"
    dirs = list(prefix.glob("windows-bundles/openocd/.pending-*"))
    assert len(dirs) == 1 and (dirs[0] / "unknown").read_bytes() == b"foreign sentinel"


@pytest.mark.parametrize("args", [["SYNTHETIC_PRIVATE"], ["install", "--tool", "SYNTHETIC_PRIVATE"],
                                  ["check", "--tool", "openocd", "--prefix", "/SYNTHETIC_PRIVATE", "--unknown"]])
def test_cli_parse_errors_never_echo_values(args, capsys):
    with pytest.raises(SystemExit) as error: I.main(args)
    assert error.value.code == 2
    text = capsys.readouterr()
    assert "SYNTHETIC_PRIVATE" not in text.err + text.out


@pytest.fixture
def shell(tmp_path):
    repo = tmp_path / "repo"; (repo / "scripts").mkdir(parents=True)
    shutil.copyfile(REPO / "scripts/install.sh", repo / "scripts/install.sh")
    calls = tmp_path / "calls.jsonl"
    (repo / "scripts/windows_bundle.py").write_text(
        'import json,sys\nfrom pathlib import Path\n'
        f'with Path({str(calls)!r}).open("a") as f: f.write(json.dumps(sys.argv[1:])+"\\n")\n'
        'sys.exit(7 if "sigrok" in sys.argv else 0)\n')
    (repo / ".venv/bin").mkdir(parents=True)
    (repo / ".venv/bin/python").symlink_to(sys.executable)
    (repo / ".pweh").mkdir()
    pointer = repo / ".pweh/tools-env.path"; pointer.write_text("sentinel pointer\n")
    prefix = tmp_path / "tools"
    env = dict(os.environ, HOME=str(tmp_path / "home"), PWEH_TOOLS_DIR=str(prefix), PWEH_TOOLS_ENV="")
    def run(*args):
        return subprocess.run(["bash", str(repo / "scripts/install.sh"), "--prefix", str(prefix), *args],
                              stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=10, env=env)
    return run, prefix, calls, pointer


def test_shell_only_local_branch_and_two_tools_failure(shell):
    run, prefix, calls, pointer = shell
    r = run("--only", "openocd-win,sigrok-win", "--windows-bundle-source", "openocd=/synthetic/a", "--windows-bundle-source", "sigrok=/synthetic/b", "--force")
    assert r.returncode == 1
    rows = [json.loads(x) for x in calls.read_text().splitlines()]
    assert rows == [["install", "--tool", tool, "--prefix", str(prefix), "--source-tree", path]
                    for tool, path in (("openocd", "/synthetic/a"), ("sigrok", "/synthetic/b"))]
    assert not prefix.exists() and pointer.read_text() == "sentinel pointer\n"


@pytest.mark.parametrize("args", [
    ["--only", "openocd-win,python"], ["--only", "openocd-win,mcp"],
    ["--only", "openocd-win", "--windows-bundle-source", "other=/synthetic"],
    ["--only", "openocd-win", "--windows-bundle-source", "sigrok=/synthetic"],
    ["--only", "openocd-win", "--windows-bundle-source", "openocd=relative"],
    ["--only", "openocd-win", "--windows-bundle-source", "openocd=/synthetic", "--windows-bundle-source", "openocd=/other"],
    ["--only", "openocd-win", "--skip", "openocd-win", "--windows-bundle-source", "openocd=/synthetic"],
    ["--windows-bundle-source", "openocd=/synthetic"],
    ["--only", "openocd-win", "--check", "--windows-bundle-source", "openocd=/synthetic"],
    ["--only", "openocd-win", "--prefix", "relative"],
])
def test_shell_invalid_selection_fails_before_any_helper_or_write(shell, args):
    run, prefix, calls, pointer = shell
    r = run(*args)
    assert r.returncode == 2 and not calls.exists() and not prefix.exists()
    assert pointer.read_text() == "sentinel pointer\n"


def test_shell_dryrun_is_only_plan_and_check_uses_static_helper(shell):
    run, prefix, calls, pointer = shell
    r = run("--only", "openocd-win", "--dry-run")
    assert r.returncode == 0 and "아직 검증" in r.stdout and not calls.exists()
    r = run("--only", "openocd-win", "--check")
    assert r.returncode == 0 and json.loads(calls.read_text())[0] == "check"
    assert not prefix.exists() and pointer.read_text() == "sentinel pointer\n"


def test_existing_same_release_race_is_idempotent(source, tmp_path, monkeypatch):
    prefix = tmp_path / "tools"
    original = I._rename_noreplace
    def race(parent, src, dest):
        # 다른 게시자가 같은 등록 bytes를 완성한 경우만 성공한다.
        root = prefix / "windows-bundles/openocd"
        shutil.copytree(root / src, root / dest)
        original(parent, src, dest)
    monkeypatch.setattr(I, "_rename_noreplace", race)
    assert install(source, prefix)["status"] == "already-present"
    assert I.check_bundle("openocd", prefix, deadline=end())["status"] == "verified"
    no_pending(prefix)


def test_postpublish_verify_failure_preserves_published_root(source, tmp_path, monkeypatch):
    prefix = tmp_path / "tools"; target = final(prefix)
    original = B.verify_release
    def verify(root, *args, **kwargs):
        if root == target:
            raise OSError("SYNTHETIC_PRIVATE")
        return original(root, *args, **kwargs)
    monkeypatch.setattr(B, "verify_release", verify)
    with pytest.raises(I.BundleInstallError) as error: install(source, prefix)
    assert error.value.code == "bundle_io_failed" and target.is_dir()
    monkeypatch.setattr(B, "verify_release", original)
    assert I.check_bundle("openocd", prefix, deadline=end())["status"] == "verified"


def test_replaced_pending_child_is_not_unlinked(source, tmp_path, monkeypatch):
    prefix = tmp_path / "tools"
    foreign = b"do not delete"
    def fail(parent, src, dest):
        root = prefix / "windows-bundles/openocd" / src
        root.chmod(0o755)
        p = root / "release.json"
        p.rename(root / "former")
        p.write_bytes(foreign)
        raise OSError("SYNTHETIC_PRIVATE")
    monkeypatch.setattr(I, "_rename_noreplace", fail)
    with pytest.raises(I.BundleInstallError) as error: install(source, prefix)
    assert error.value.code == "bundle_cleanup_pending"
    pending = next(prefix.glob("windows-bundles/openocd/.pending-*"))
    assert (pending / "release.json").read_bytes() == foreign


def test_copy_cancel_preserves_existing_release_and_removes_owned_pending(source, tmp_path, monkeypatch):
    prefix = tmp_path / "tools"
    install(source, prefix); old = final(prefix)
    registry(monkeypatch, preferred="v2", versions=("v1", "v2"))
    original = I.safeio.write_all
    cancelled = False
    def write(fd, data):
        nonlocal cancelled
        original(fd, data)
        cancelled = True
    monkeypatch.setattr(I.safeio, "write_all", write)
    with pytest.raises(I.BundleInstallError) as error: install(source, prefix, cancel=lambda: cancelled)
    assert error.value.code == "cancelled" and old.is_dir() and not final(prefix).exists()
    no_pending(prefix)


def test_shell_python_fallback_ignores_sitecustomize(shell, tmp_path):
    run, prefix, calls, pointer = shell
    repo = pointer.parent.parent
    (repo / ".venv/bin/python").unlink()
    trap = tmp_path / "pythonpath"; trap.mkdir()
    sentinel = tmp_path / "sitecustomize-ran"
    (trap / "sitecustomize.py").write_text(f"from pathlib import Path; Path({str(sentinel)!r}).touch()")
    environment = dict(os.environ, HOME=str(tmp_path / "home"), PWEH_TOOLS_DIR=str(prefix), PYTHONPATH=str(trap))
    result = subprocess.run(["bash", str(repo / "scripts/install.sh"), "--only", "openocd-win", "--check"],
                            capture_output=True, text=True, env=environment, timeout=10)
    assert result.returncode == 0, result.stderr
    assert calls.exists() and not sentinel.exists() and not prefix.exists()
