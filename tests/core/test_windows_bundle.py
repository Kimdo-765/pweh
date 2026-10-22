"""합성 tree로만 검증하는 Windows 번들 등록·경로·신원·예산 계약."""
from __future__ import annotations

import copy
from dataclasses import FrozenInstanceError
import hashlib
import json
import os
from pathlib import Path
import stat
import time
import traceback

import pytest

from pweh import windows_bundle as W


def end():
    return time.monotonic() + 45


def canonical(value):
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n").encode()


def synthetic_manifest(tool="openocd", release_id="synthetic-v1", files=None):
    """같은 closed parser를 통과하는 작은 metadata. 실제 payload는 읽지 않는다."""
    files = files if files is not None else {"bin/probe.exe": b"synthetic executable bytes", "scripts/start.cfg": b"synthetic cfg"}
    source = {"artifact_url": "https://example.invalid/synthetic.zip", "artifact_name": "synthetic.zip",
              "artifact_size": 100, "artifact_sha256": "a" * 64, "digest_basis": "supplier-checksum",
              "checksum_metadata": {"repository": "https://example.invalid/source", "ref": "v1", "path": "package.json"},
              "extractor": None}
    if tool == "sigrok":
        source.update(digest_basis="first-acquisition", checksum_metadata=None,
                      extractor={"version": "1", "artifact_url": "https://example.invalid/extractor.tar",
                                 "artifact_size": 1, "artifact_sha256": "b" * 64, "executable_sha256": "c" * 64})
    return {"schema_version": 1, "tool": tool, "release_id": release_id, "platform": "windows-amd64",
            "source": source,
            "payload": {"archive_root": "synthetic/" if tool == "openocd" else "",
                        "recipe": "zip-strip-fixed-root-v1" if tool == "openocd" else "nsis-selected-v1",
                        "entrypoint": "bin/probe.exe", "search_dirs": ["scripts"], "python_zip": None,
                        "file_count": len(files), "total_bytes": sum(len(data) for data in files.values()),
                        "excluded": {"installer_plugins": 0, "usb_driver_installers": 0,
                                     "example_captures": 0, "uninstaller": 0}},
            "files": [{"path": path, "size": len(data), "sha256": hashlib.sha256(data).hexdigest()}
                      for path, data in sorted(files.items())],
            "known_limitations": ["authenticode_unverified"]}


def inject_registry(monkeypatch, documents=None):
    documents = documents or [synthetic_manifest(), synthetic_manifest("sigrok")]
    index = {"schema_version": 1, "tools": {}}
    raws = {}
    for doc in documents:
        tool, rid = doc["tool"], doc["release_id"]
        relative = f"windows-bundles/{tool}-{rid}.json"
        raw = canonical(doc)
        raws[relative] = raw
        group = index["tools"].setdefault(tool, {"preferred_release_id": rid, "releases": []})
        group["releases"].append({"release_id": rid, "manifest": relative, "sha256": hashlib.sha256(raw).hexdigest()})
    monkeypatch.setattr(W, "_read_registry_bytes", lambda: canonical(index))
    monkeypatch.setattr(W, "_read_registered_manifest_bytes", lambda name: raws[name])
    return index, raws


@pytest.fixture
def registry(monkeypatch):
    return inject_registry(monkeypatch)


@pytest.fixture
def source(tmp_path, registry):
    root = tmp_path / "source"
    (root / "bin").mkdir(parents=True)
    (root / "scripts").mkdir()
    (root / "bin/probe.exe").write_bytes(b"synthetic executable bytes")
    (root / "scripts/start.cfg").write_bytes(b"synthetic cfg")
    return root


def installed(source, tmp_path):
    """시험만의 복사. 실제 설치기는 독립 suite에서 검증한다."""
    root = tmp_path / "installed"
    payload = root / "payload"
    (payload / "bin").mkdir(parents=True)
    (payload / "scripts").mkdir()
    for relative in ("bin/probe.exe", "scripts/start.cfg"):
        target = payload / relative
        target.write_bytes((source / relative).read_bytes())
        target.chmod(0o555 if relative.endswith(".exe") else 0o444)
    manifest = W.load_registered_manifest("openocd", deadline=end())
    (root / "release.json").write_bytes(manifest.receipt_bytes)
    (root / "release.json").chmod(0o444)
    for directory in (payload / "bin", payload / "scripts", payload, root):
        directory.chmod(0o555)
    return root


def assert_fixed(error):
    assert error.code in W.ERROR_CODES
    assert error.data == {} and error.hint is None
    assert "SYNTHETIC_PRIVATE" not in str(error)


def test_registered_public_metadata_counts_provenance_and_no_private_fields():
    expected = {"openocd": (1132, 7965084, "supplier-checksum"), "sigrok": (290, 34159405, "first-acquisition")}
    for tool, (count, size, basis) in expected.items():
        manifest = W.load_registered_manifest(tool, deadline=end())
        assert len(manifest.files) == count and manifest.total_bytes == size and manifest.digest_basis == basis
        assert manifest.receipt_bytes == canonical({"schema_version": 1, "tool": tool,
                                                    "release_id": manifest.release_id, "manifest_sha256": manifest.manifest_sha256})
        assert manifest.manifest_sha256 == hashlib.sha256(W._read_registered_manifest_bytes(
            f"windows-bundles/{tool}-{manifest.release_id}.json")).hexdigest()
        assert isinstance(manifest.files, tuple) and isinstance(manifest.search_dirs, tuple)
        with pytest.raises(FrozenInstanceError):
            manifest.tool = "changed"
        raw = W._read_registered_manifest_bytes(f"windows-bundles/{tool}-{manifest.release_id}.json")
        assert canonical(json.loads(raw)) == raw
        for secret in (b"payload_path", b'"stderr"', b"/home/", b"/tmp/", b"Traceback"):
            assert secret not in raw


@pytest.mark.parametrize("tool", ["openocd", "sigrok"])
def test_synthetic_source_exact_tree_frozen_identity_and_fd_copy(source, tool):
    bundle = W.verify_payload(source, tool, deadline=end())
    assert bundle.root == source and bundle.release_root is None
    assert bundle.files_checked == 2 and bundle.bytes_checked == 39
    assert bundle.entrypoint == source / "bin/probe.exe"
    with W.open_verified_file(bundle, "bin/probe.exe", deadline=end()) as fd:
        assert os.read(fd, 100) == b"synthetic executable bytes"
    with pytest.raises(OSError):
        os.fstat(fd)
    W.revalidate_bundle(bundle, deadline=end())
    with pytest.raises(FrozenInstanceError):
        bundle.root = source.parent


def test_managed_path_is_pure_and_receipt_is_not_payload_verification(source, tmp_path):
    manifest = W.load_registered_manifest("openocd", deadline=end())
    root = W.managed_release_root(tmp_path / "absent", manifest)
    assert root == tmp_path / "absent/windows-bundles/openocd" / (manifest.release_id + "-" + manifest.manifest_sha256)
    assert not root.exists()
    root.mkdir(parents=True)
    (root / "release.json").write_bytes(manifest.receipt_bytes)
    receipt = W.read_release_receipt(root, "openocd", deadline=end())
    assert receipt.manifest_sha256 == manifest.manifest_sha256
    with pytest.raises(W.WindowsBundleError):
        W.verify_release(root, "openocd", deadline=end())


def test_installed_release_and_source_modes_are_separate(source, tmp_path):
    (source / "bin/probe.exe").chmod(0o4644)
    W.verify_payload(source, "openocd", deadline=end())
    root = installed(source, tmp_path)
    bundle = W.verify_release(root, "openocd", deadline=end())
    assert bundle.release_root == root and bundle.root == root / "payload"
    W.revalidate_bundle(bundle, deadline=end())


@pytest.mark.parametrize("target,mode", [(".", 0o755), ("payload", 0o755), ("payload/bin", 0o755),
                                         ("payload/bin/probe.exe", 0o444), ("payload/scripts/start.cfg", 0o644),
                                         ("release.json", 0o644), ("payload/bin/probe.exe", 0o4555)])
def test_installed_mode_mismatch_is_not_verified(source, tmp_path, target, mode):
    root = installed(source, tmp_path)
    (root / target).chmod(mode)
    with pytest.raises(W.WindowsBundleError):
        W.verify_release(root, "openocd", deadline=end())


@pytest.mark.parametrize("mutation", ["extra-file", "extra-dir", "missing", "content", "size", "symlink-file",
                                      "symlink-dir", "hardlink", "fifo", "case", "ads"])
def test_source_tree_mutations_fail_closed(source, tmp_path, mutation):
    target = source / "scripts/start.cfg"
    if mutation == "extra-file":
        (source / "unexpected.dll").write_bytes(b"foreign")
    elif mutation == "extra-dir":
        (source / "site").mkdir()
    elif mutation in ("missing", "symlink-file", "hardlink", "fifo"):
        target.unlink()
        outside = tmp_path / "foreign"
        outside.write_bytes(b"synthetic cfg")
        if mutation == "symlink-file":
            target.symlink_to(outside)
        elif mutation == "hardlink":
            os.link(outside, target)
        elif mutation == "fifo":
            os.mkfifo(target)
    elif mutation == "symlink-dir":
        (source / "scripts").rename(tmp_path / "other-dir")
        (source / "scripts").symlink_to(tmp_path / "other-dir")
    elif mutation in ("content", "size"):
        target.write_bytes(b"X" * (len(b"synthetic cfg") + (mutation == "size")))
    elif mutation == "case":
        target.rename(source / "scripts/START.cfg")
    elif mutation == "ads":
        (source / "extra:stream").write_bytes(b"foreign")
    with pytest.raises(W.WindowsBundleError) as exc:
        W.verify_payload(source, "openocd", deadline=end())
    assert_fixed(exc.value)


def test_root_alias_is_resolved_once_but_inner_alias_is_rejected(source, tmp_path):
    alias = tmp_path / "source-alias"
    alias.symlink_to(source)
    assert W.verify_payload(alias, "openocd", deadline=end()).root == source


def test_named_dangling_root_alias_is_invalid_not_optional_absence(source, tmp_path):
    alias = tmp_path / "dangling"
    alias.symlink_to(tmp_path / "absent-target")
    for action in (W.verify_payload, W.read_release_receipt, W.verify_release):
        with pytest.raises(W.WindowsBundleError) as exc:
            action(alias, "openocd", deadline=end())
        assert exc.value.code == "bundle_tree_invalid"


@pytest.mark.parametrize("path", ["../escape", "/absolute", "a//b", "a/./b", "a/../b", "a\\b", "a:b",
                                 "aux.cfg", "a/CON .txt", "a/LPT¹.txt", "a.", "a ", "a\0b", "a\nb",
                                 "a*", "a?", "a|", 'a"', "a<", "a>", "a/" + "x" * 1024,
                                 "/".join(["x"] * 33), "\ud800"])
def test_registry_rejects_unsafe_relative_path(monkeypatch, path):
    doc = synthetic_manifest()
    doc["files"][0]["path"] = path
    if "\ud800" in path:
        # 바이트 JSON에는 escape로 넣어 decode 뒤 surrogate를 검증한다.
        inject_registry(monkeypatch)
        raw = json.dumps(doc, ensure_ascii=True).encode()
        index = json.loads(W._read_registry_bytes())
        row = index["tools"]["openocd"]["releases"][0]
        row["sha256"] = hashlib.sha256(raw).hexdigest()
        monkeypatch.setattr(W, "_read_registry_bytes", lambda: canonical(index))
        monkeypatch.setattr(W, "_read_registered_manifest_bytes", lambda name: raw)
    else:
        inject_registry(monkeypatch, [doc, synthetic_manifest("sigrok")])
    with pytest.raises(W.WindowsBundleError) as exc:
        W.load_registered_manifest("openocd", deadline=end())
    assert exc.value.code == "bundle_registry_invalid"


@pytest.mark.parametrize("mutation", ["extra-key", "duplicate", "casefold", "file-parent", "count", "total", "size-bool",
                                      "big-file", "entry", "search", "duplicate-search", "unknown-limit", "source-basis",
                                      "checksum", "extractor", "recipe", "sha", "platform"])
def test_registry_manifest_shape_and_consistency(monkeypatch, mutation):
    doc = synthetic_manifest()
    if mutation == "extra-key":
        doc["host_path"] = "SYNTHETIC_PRIVATE"
    elif mutation == "duplicate":
        doc["files"].append(copy.deepcopy(doc["files"][0]))
    elif mutation == "casefold":
        doc["files"][1]["path"] = "BIN/another.cfg"
        doc["files"].sort(key=lambda row: row["path"])
    elif mutation == "file-parent":
        doc["files"][1]["path"] = "bin/probe.exe/child"
    elif mutation == "count":
        doc["payload"]["file_count"] += 1
    elif mutation == "total":
        doc["payload"]["total_bytes"] += 1
    elif mutation == "size-bool":
        doc["files"][0]["size"] = True
    elif mutation == "big-file":
        doc["files"][0]["size"] = W.MAX_FILE_BYTES + 1
    elif mutation == "entry":
        doc["payload"]["entrypoint"] = "unknown.exe"
    elif mutation == "search":
        doc["payload"]["search_dirs"] = ["empty"]
    elif mutation == "duplicate-search":
        doc["payload"]["search_dirs"] *= 2
    elif mutation == "unknown-limit":
        doc["known_limitations"].append("SYNTHETIC_PRIVATE")
    elif mutation == "source-basis":
        doc["source"]["digest_basis"] = "first-acquisition"
    elif mutation == "checksum":
        doc["source"]["checksum_metadata"] = None
    elif mutation == "extractor":
        doc["source"]["extractor"] = {}
    elif mutation == "recipe":
        doc["payload"]["recipe"] = "custom"
    elif mutation == "sha":
        doc["files"][0]["sha256"] = "A" * 64
    elif mutation == "platform":
        doc["platform"] = "unknown"
    inject_registry(monkeypatch, [doc, synthetic_manifest("sigrok")])
    with pytest.raises(W.WindowsBundleError) as exc:
        W.load_registered_manifest("openocd", deadline=end())
    assert exc.value.code == "bundle_registry_invalid"


@pytest.mark.parametrize("raw", [b'{"schema_version":1,"schema_version":1,"tools":{}}', b'\xff',
                                b'{"schema_version":NaN}', b'{"schema_version":1.0}', b'{"schema_version":1e999}',
                                b'[' * 17 + b'0' + b']' * 17, b'{"schema_version":' + b'9' * 1000 + b'}',
                                b' ' * (W.MAX_REGISTRY_BYTES + 1)])
def test_registry_json_is_bounded_and_closed(monkeypatch, raw):
    monkeypatch.setattr(W, "_read_registry_bytes", lambda: raw)
    with pytest.raises(W.WindowsBundleError) as exc:
        W.load_registered_manifest("openocd", deadline=end())
    assert exc.value.code == "bundle_registry_invalid"


@pytest.mark.parametrize("mutation", ["hash", "path", "preferred", "duplicate", "tool-extra", "extra"])
def test_registry_index_chain_is_not_replaceable(registry, mutation):
    index, _ = registry
    group = index["tools"]["openocd"]
    if mutation == "hash":
        group["releases"][0]["sha256"] = "0" * 64
    elif mutation == "path":
        group["releases"][0]["manifest"] = "../../SYNTHETIC_PRIVATE"
    elif mutation == "preferred":
        group["preferred_release_id"] = "missing"
    elif mutation == "duplicate":
        group["releases"] *= 2
    elif mutation == "tool-extra":
        index["tools"]["unknown"] = group
    else:
        index["override"] = "SYNTHETIC_PRIVATE"
    with pytest.raises(W.WindowsBundleError) as exc:
        W.load_registered_manifest("openocd", deadline=end())
    assert exc.value.code == "bundle_registry_invalid"


def test_registered_old_release_is_explicit_only(monkeypatch, tmp_path):
    docs = [synthetic_manifest(release_id="v2"), synthetic_manifest(release_id="v1"), synthetic_manifest("sigrok")]
    inject_registry(monkeypatch, docs)
    preferred = W.load_registered_manifest("openocd", deadline=end())
    old = W.load_registered_manifest("openocd", "v1", deadline=end())
    assert preferred.release_id == "v2" and old.release_id == "v1"
    assert W.managed_release_root(tmp_path, old) != W.managed_release_root(tmp_path, preferred)
    with pytest.raises(W.WindowsBundleError) as exc:
        W.load_registered_manifest("openocd", "v0", deadline=end())
    assert exc.value.code == "bundle_release_unregistered"


@pytest.mark.parametrize("mutation", ["missing", "malformed", "extra", "wrong-tool", "wrong-hash", "unregistered", "link", "hardlink", "huge"])
def test_receipt_invalid_is_not_missing_install(source, tmp_path, mutation):
    root = installed(source, tmp_path)
    receipt = root / "release.json"
    root.chmod(0o755)
    receipt.chmod(0o644)
    doc = json.loads(receipt.read_bytes())
    if mutation == "missing":
        receipt.unlink()
    elif mutation == "malformed":
        receipt.write_bytes(b'{"SYNTHETIC_PRIVATE":')
    elif mutation in ("link", "hardlink"):
        receipt.rename(tmp_path / "receipt")
        if mutation == "link":
            receipt.symlink_to(tmp_path / "receipt")
        else:
            os.link(tmp_path / "receipt", receipt)
    elif mutation == "huge":
        receipt.write_bytes(b" " * (W.MAX_RECEIPT_BYTES + 1))
    else:
        if mutation == "extra":
            doc["path"] = "SYNTHETIC_PRIVATE"
        elif mutation == "wrong-tool":
            doc["tool"] = "sigrok"
        elif mutation == "wrong-hash":
            doc["manifest_sha256"] = "0" * 64
        else:
            doc["release_id"] = "missing"
        receipt.write_bytes(canonical(doc))
    with pytest.raises(W.WindowsBundleError) as exc:
        W.read_release_receipt(root, "openocd", deadline=end())
    assert exc.value.code != "bundle_missing"
    assert_fixed(exc.value)


def test_root_absence_and_permission_unknown_are_distinct(source, monkeypatch):
    with pytest.raises(W.WindowsBundleError) as exc:
        W.verify_payload(source / "missing", "openocd", deadline=end())
    assert exc.value.code == "bundle_missing"
    def blocked(*args, **kwargs):
        raise PermissionError("SYNTHETIC_PRIVATE")
    monkeypatch.setattr(W.safeio, "_walk_directory", blocked)
    with pytest.raises(W.WindowsBundleError) as exc:
        W.verify_payload(source, "openocd", deadline=end())
    assert exc.value.code == "bundle_io_failed"
    assert "SYNTHETIC_PRIVATE" not in "".join(traceback.format_exception(exc.value))


@pytest.mark.parametrize("mutation", ["same-bytes-inode", "directory", "added", "chmod"])
def test_revalidation_keeps_original_snapshot(source, tmp_path, mutation):
    bundle = W.verify_payload(source, "openocd", deadline=end())
    target = source / "scripts/start.cfg"
    if mutation == "same-bytes-inode":
        target.rename(tmp_path / "original")
        target.write_bytes(b"synthetic cfg")
    elif mutation == "directory":
        (source / "scripts").rename(tmp_path / "scripts")
        (source / "scripts").mkdir()
        target.write_bytes(b"synthetic cfg")
    elif mutation == "added":
        (source / "site").mkdir()
    else:
        target.chmod(0o444)
    with pytest.raises(W.WindowsBundleError):
        W.revalidate_bundle(bundle, deadline=end())


@pytest.mark.parametrize("when", ["before", "during"])
def test_copy_fd_name_replacement_is_detected(source, tmp_path, when):
    bundle = W.verify_payload(source, "openocd", deadline=end())
    target = source / "scripts/start.cfg"
    def swap():
        target.rename(tmp_path / "old")
        target.write_bytes(b"synthetic cfg")
    if when == "before":
        swap()
    with pytest.raises(W.WindowsBundleError) as exc:
        with W.open_verified_file(bundle, "scripts/start.cfg", deadline=end()) as fd:
            assert when == "during"
            swap()
            assert os.read(fd, 100) == b"synthetic cfg"
    assert exc.value.code == "bundle_changed"


def test_hash_keeps_fd_but_rejects_name_replacement(source, tmp_path, monkeypatch):
    read = W.os.read
    target = source / "scripts/start.cfg"
    swapped = False
    def changing(fd, count):
        nonlocal swapped
        data = read(fd, count)
        if data == b"synthetic cfg" and not swapped:
            swapped = True
            target.rename(tmp_path / "old")
            target.write_bytes(data)
        return data
    monkeypatch.setattr(W.os, "read", changing)
    with pytest.raises(W.WindowsBundleError) as exc:
        W.verify_payload(source, "openocd", deadline=end())
    assert swapped and exc.value.code == "bundle_changed"


@pytest.mark.parametrize("deadline", [None, True, "1", float("inf"), float("nan"), 10 ** 400])
def test_deadline_invalid_is_fixed(registry, deadline):
    with pytest.raises(W.WindowsBundleError) as exc:
        W.load_registered_manifest("openocd", deadline=deadline)
    assert exc.value.code == "bundle_invalid_argument"


@pytest.mark.parametrize("answer,code", [(True, "cancelled"), (1, "bundle_cancel_failed"), (None, "bundle_cancel_failed")])
def test_cancel_result_is_closed(registry, answer, code):
    with pytest.raises(W.WindowsBundleError) as exc:
        W.load_registered_manifest("openocd", deadline=end(), cancel=lambda: answer)
    assert exc.value.code == code


def test_cancel_exception_does_not_leak(registry):
    def cancel():
        raise RuntimeError("SYNTHETIC_PRIVATE")
    with pytest.raises(W.WindowsBundleError) as exc:
        W.load_registered_manifest("openocd", deadline=end(), cancel=cancel)
    assert exc.value.code == "bundle_cancel_failed"
    assert "SYNTHETIC_PRIVATE" not in "".join(traceback.format_exception(exc.value))


def test_shared_deadline_does_not_restart_after_registry(registry, monkeypatch):
    clock = [100.0]
    read = W._read_registry_bytes
    monkeypatch.setattr(W.time, "monotonic", lambda: clock[0])
    def late():
        data = read()
        clock[0] = 101.0
        return data
    monkeypatch.setattr(W, "_read_registry_bytes", late)
    with pytest.raises(W.WindowsBundleError) as exc:
        W.load_registered_manifest("openocd", deadline=100.5)
    assert exc.value.code == "bundle_timeout"


def test_tree_entry_budget_is_checked(source, monkeypatch):
    monkeypatch.setattr(W, "MAX_ENTRIES", 3)
    # 등록 자체도 같은 상한을 따르므로 네 항목의 합성 tree는 성공으로 표시되지 않는다.
    with pytest.raises(W.WindowsBundleError):
        W.verify_payload(source, "openocd", deadline=end())


@pytest.mark.parametrize("root", ["relative", "C:\\bundle", "/tmp/a/../b", "/tmp/a\0b", None])
def test_local_root_argument_is_strict(registry, root):
    with pytest.raises(W.WindowsBundleError) as exc:
        W.verify_payload(root, "openocd", deadline=end())
    assert exc.value.code == "bundle_invalid_argument"
