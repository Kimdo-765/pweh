"""합성 release의 두 빌드 증거·설치 검증·실패 원복 계약. 외부 실행은 없다."""
from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
import stat
import struct

import pytest

from pweh import firmwarebuild as F
from .test_firmwarebuild import elf, image


COMMIT = "1" * 40
SOURCE_SHA256 = "2" * 64
VERSION = "0.1.0"


def _identity_elf() -> bytes:
    """정책·USB symbol과 크기 symbol을 가진 최소 합성 ELF를 만든다."""
    device, configuration = F.expected_usb()
    values = {
        "pweh_usb_device_descriptor": device,
        "pweh_usb_configuration_descriptor": configuration,
        "pweh_probe_policy_blob": F.policy_blob(),
    }
    payload = bytearray()
    entries = []
    for name, value in values.items():
        entries.append((name, len(payload), len(value), 1, 3))
        payload.extend(value)
        entries.append((name + "_size", len(payload), 4, 1, 3))
        payload.extend(struct.pack("<I", len(value)))
    for text in (COMMIT, VERSION, F.PROFILE, F.BOARD):
        payload.extend(text.encode() + b"\0")
    return elf(entries, payload=bytes(payload))


def _partition_table() -> bytes:
    """factory 항목 1개와 검증 가능한 MD5 항목만 만든다."""
    entry = struct.pack("<HBBII16sI", 0x50AA, 0, 0, 0x10000, 1024 * 1024, b"factory", 0)
    return entry + b"\xeb\xeb" + b"\xff" * 14 + hashlib.md5(entry, usedforsecurity=False).digest() + b"\xff" * 32


def _merged(files: dict[str, bytes]) -> bytes:
    result = bytearray()
    for offset, name in ((0, "bootloader.bin"), (0x8000, "partition-table.bin"), (0x10000, "pweh_espprobe.bin")):
        result.extend(b"\xff" * (offset - len(result)))
        result.extend(files[name])
    return bytes(result)


@pytest.fixture
def release():
    executable = _identity_elf()
    report = {"schema": "pweh.firmware-check/v1", "status": "passed", "git_commit": COMMIT}
    dependencies = {name: {"version": version} for name, version in F.COMPONENTS.items()}
    files = {
        "pweh_espprobe.bin": image(elf_data=executable),
        "bootloader.bin": image(b"PWEH SYNTHETIC BOOTLOADER"),
        "partition-table.bin": _partition_table(),
        "pweh_espprobe.elf": executable,
        "pweh_espprobe.map": b"PWEH SYNTHETIC MAP\n",
        "build-check.json": F.json_bytes(report),
        "dependencies-lock.json": F.json_bytes({"components": dependencies}),
    }
    files["merged.bin"] = _merged(files)
    meta = {"schema": "pweh.firmware-build/v1", "status": "built", "mode": "build",
            "git_commit": COMMIT, "source_archive_sha256": SOURCE_SHA256,
            "source_date_epoch": 1, "image": {"image": F.IMAGE, "os": "linux", "architecture": "amd64"}}
    reproducibility = F.compare_builds(files, dict(files), meta, copy.deepcopy(meta))
    entry = F.manifest_entry(commit=COMMIT, version=VERSION, files=files, report=report,
                             source_sha256=SOURCE_SHA256, dependencies=dependencies,
                             reproducibility=reproducibility)
    return {"entry": entry, "files": files, "meta": meta, "report": report,
            "dependencies": dependencies, "reproducibility": reproducibility}


def _replace_payload(entry, files, name, content):
    """외부 hash까지 갱신해 안쪽 계약 검사가 실제로 실행되게 한다."""
    files[name] = content
    row = next(row for row in entry["files"] if row["name"] == name)
    row.update(size=len(content), sha256=F.sha256(content))
    if row["role"] == "build-check":
        entry["verification"]["build_check_sha256"] = row["sha256"]


def _source(tmp_path, release):
    source = tmp_path / "source"
    directory = source / VERSION
    directory.mkdir(parents=True)
    for name, data in release["files"].items():
        (directory / name).write_bytes(data)
    catalog = tmp_path / "releases.json"
    catalog.write_bytes(F.json_bytes({"schema": "pweh.espprobe-releases/v1", "releases": [release["entry"]]}))
    return catalog, source, tmp_path / "tools"


def _tree(directory):
    return {str(path.relative_to(directory)): path.read_bytes() for path in directory.rglob("*") if path.is_file()}


def test_valid_release_checks_all_payloads_and_distinct_hashes(release):
    entry, files = release["entry"], release["files"]
    assert F.validate_release(entry, files) is entry
    assert entry["verification"] == {"reproducible": True, "runs": 2, "hardware_verified": False,
                                     "build_check_sha256": F.sha256(files["build-check.json"])}
    assert len({entry["image_sha256"], entry["app_elf_sha256"], F.sha256(files["pweh_espprobe.bin"])}) == 3


@pytest.mark.parametrize("name", F.RELEASE_NAMES)
def test_payload_corruption_is_rejected_for_every_release_role(release, name):
    files = dict(release["files"])
    changed = bytearray(files[name])
    changed[-1] ^= 1
    files[name] = bytes(changed)
    with pytest.raises(F.BuildError, match="payload hash"):
        F.validate_release(release["entry"], files)


@pytest.mark.parametrize("key,value", [
    ("build_profile", "probe-radio"), ("board", "unknown"), ("chip", "esp32"),
    ("caps", ["spi"]), ("radio", "wifi"), ("tx_caps", ["wifi"]), ("spi_read_opcodes", [3]),
    ("pins_allowed", {"H0": [1], "H1": [], "H1a": []}), ("pclk_pad", 21), ("pin_drive", "push-pull"),
    ("limits", {"max_payload": 4096, "hb_ms": 1000, "max_credit": 1}),
    ("protocol_version", 2), ("docker_image", "untrusted/image:latest"),
    ("git_commit", "unknown"), ("source_archive_sha256", "unknown"),
    ("fw_version", "../escape"),
])
def test_manifest_profile_and_identity_mismatch_rejected(release, key, value):
    release["entry"][key] = value
    with pytest.raises(F.BuildError):
        F.validate_release(release["entry"], release["files"])


@pytest.mark.parametrize("change", ["path", "duplicate-role", "duplicate-name", "missing", "offset", "bool-size", "large-boot"])
def test_manifest_file_contract_rejected(release, change):
    entry = release["entry"]
    rows = entry["files"]
    if change == "path":
        rows[0]["name"] = "../outside.bin"
    elif change == "duplicate-role":
        rows[1]["role"] = rows[0]["role"]
    elif change == "duplicate-name":
        rows[1]["name"] = rows[0]["name"]
    elif change == "missing":
        rows.pop()
    elif change == "offset":
        rows[0]["offset"] = 0x10001
    elif change == "bool-size":
        rows[0]["size"] = True
    else:
        next(row for row in rows if row["role"] == "bootloader")["size"] = 0x8001
    with pytest.raises(F.BuildError):
        F.validate_release(entry, release["files"])


@pytest.mark.parametrize("kind", ["boot-gap", "partition-gap", "tail", "app-bytes", "partition-md5"])
def test_rehashed_merged_layout_corruption_is_rejected(release, kind):
    entry, files = release["entry"], release["files"]
    merged = bytearray(files["merged.bin"])
    if kind == "boot-gap":
        merged[len(files["bootloader.bin"])] = 0
    elif kind == "partition-gap":
        merged[0x8000 + len(files["partition-table.bin"])] = 0
    elif kind == "tail":
        merged += b"\xff"
    elif kind == "app-bytes":
        merged[0x10000 + 1] ^= 1
    else:
        table = bytearray(files["partition-table.bin"])
        table[48] ^= 1
        _replace_payload(entry, files, "partition-table.bin", bytes(table))
        merged = bytearray(_merged(files))
    _replace_payload(entry, files, "merged.bin", bytes(merged))
    with pytest.raises(F.BuildError, match="merged|partition table"):
        F.validate_release(entry, files)


@pytest.mark.parametrize("field,value", [("status", "failed"), ("git_commit", "3" * 40)])
def test_rehashed_failed_or_foreign_report_rejected(release, field, value):
    report = dict(release["report"], **{field: value})
    _replace_payload(release["entry"], release["files"], "build-check.json", F.json_bytes(report))
    with pytest.raises(F.BuildError, match="검사 보고서"):
        F.validate_release(release["entry"], release["files"])


@pytest.mark.parametrize("name", F.RELEASE_NAMES)
def test_reproducibility_compares_every_output(release, name):
    second = dict(release["files"])
    second[name] += b"changed"
    with pytest.raises(F.BuildError, match="bytes 불일치"):
        F.compare_builds(release["files"], second, release["meta"], release["meta"])


@pytest.mark.parametrize("field,value", [("status", "failed"), ("status", "preliminary"),
                                          ("mode", "lock"), ("git_commit", "0" * 40),
                                          ("image", {"image": "untrusted/image:latest"})])
def test_two_identical_unfinished_or_unpinned_builds_are_not_reproducible(release, field, value):
    meta = dict(release["meta"], **{field: value})
    with pytest.raises(F.BuildError):
        F.compare_builds(release["files"], release["files"], meta, copy.deepcopy(meta))


def test_only_one_successful_build_is_insufficient(release):
    failed = dict(release["meta"], status="failed")
    with pytest.raises(F.BuildError):
        F.compare_builds(release["files"], release["files"], release["meta"], failed)
    missing = dict(release["files"])
    missing.pop("pweh_espprobe.map")
    with pytest.raises(F.BuildError):
        F.compare_builds(release["files"], missing, release["meta"], release["meta"])


@pytest.mark.parametrize("field,value", [("status", "failed"), ("runs", 1), ("git_commit", "3" * 40),
                                          ("source_archive_sha256", "4" * 64), ("files", {})])
def test_manifest_requires_matching_two_build_evidence(release, field, value):
    proof = dict(release["reproducibility"], **{field: value})
    with pytest.raises(F.BuildError, match="두 clean build"):
        F.manifest_entry(commit=COMMIT, version=VERSION, files=release["files"], report=release["report"],
                         source_sha256=SOURCE_SHA256, dependencies=release["dependencies"], reproducibility=proof)


def test_install_success_readonly_payloads_and_check_only(release, tmp_path):
    catalog, source, tools = _source(tmp_path, release)
    assert F.install_releases(catalog, source, tools) == 0
    destination = F.installed_directory(tools, release["entry"])
    for name, expected in release["files"].items():
        assert (destination / name).read_bytes() == expected
        assert stat.S_IMODE((destination / name).stat().st_mode) == 0o444
    assert json.loads((destination / "release.json").read_bytes()) == release["entry"]
    assert F.install_releases(catalog, tmp_path / "absent-source", tools, check=True) == 0


def test_check_only_never_installs_or_repairs(release, tmp_path):
    catalog, source, tools = _source(tmp_path, release)
    with pytest.raises(F.BuildError, match="설치된"):
        F.install_releases(catalog, source, tools, check=True)
    assert not tools.exists()
    assert F.install_releases(catalog, source, tools) == 0
    destination = F.installed_directory(tools, release["entry"])
    path = destination / "pweh_espprobe.bin"
    path.chmod(0o644)
    path.write_bytes(b"corrupt")
    original = _tree(destination)
    with pytest.raises(F.BuildError, match="설치된"):
        F.install_releases(catalog, source, tools, check=True)
    with pytest.raises(F.BuildError, match="force"):
        F.install_releases(catalog, source, tools)
    assert _tree(destination) == original
    assert F.install_releases(catalog, source, tools, force=True) == 0
    assert path.read_bytes() == release["files"][path.name]


@pytest.mark.parametrize("fault", ["hash", "file-link", "version-link"])
def test_bad_source_never_reports_installed(release, tmp_path, fault):
    catalog, source, tools = _source(tmp_path, release)
    version = source / VERSION
    if fault == "hash":
        (version / "pweh_espprobe.bin").write_bytes(b"changed")
    elif fault == "file-link":
        path = version / "pweh_espprobe.bin"
        blob = path.read_bytes()
        path.unlink()
        outside = tmp_path / "synthetic-app.bin"
        outside.write_bytes(blob)
        path.symlink_to(outside)
    else:
        relocated = tmp_path / "synthetic-release"
        version.rename(relocated)
        version.symlink_to(relocated, target_is_directory=True)
    with pytest.raises((F.BuildError, OSError)):
        F.install_releases(catalog, source, tools)
    assert not tools.exists()


@pytest.mark.parametrize("existing", [False, True])
def test_partial_stage_copy_failure_preserves_old_install(release, tmp_path, monkeypatch, existing):
    catalog, source, tools = _source(tmp_path, release)
    destination = F.installed_directory(tools, release["entry"])
    if existing:
        destination.mkdir(parents=True)
        (destination / "old.txt").write_bytes(b"PWEH SYNTHETIC OLD INSTALL")
    original = _tree(destination) if existing else None
    write = Path.write_bytes

    def fail_copy(path, data):
        if path.parent.name.startswith(".espprobe-stage-") and path.name == "bootloader.bin":
            raise OSError("합성 복사 실패")
        return write(path, data)

    monkeypatch.setattr(Path, "write_bytes", fail_copy)
    with pytest.raises(OSError, match="합성 복사 실패"):
        F.install_releases(catalog, source, tools, force=True)
    assert (_tree(destination) if destination.exists() else None) == original
    assert not list(destination.parent.glob(".espprobe-stage-*"))
    assert not list(destination.parent.glob(destination.name + ".old-*"))


def test_atomic_publish_failure_restores_old_install(release, tmp_path, monkeypatch):
    catalog, source, tools = _source(tmp_path, release)
    destination = F.installed_directory(tools, release["entry"])
    destination.mkdir(parents=True)
    (destination / "old.txt").write_bytes(b"PWEH SYNTHETIC OLD INSTALL")
    original = _tree(destination)
    rename = Path.rename

    def fail_publish(path, target):
        if path.name.startswith(".espprobe-stage-") and Path(target) == destination:
            raise OSError("합성 publish 실패")
        return rename(path, target)

    monkeypatch.setattr(Path, "rename", fail_publish)
    with pytest.raises(OSError, match="합성 publish 실패"):
        F.install_releases(catalog, source, tools, force=True)
    assert _tree(destination) == original
    assert not list(destination.parent.glob(".espprobe-stage-*"))
    assert not list(destination.parent.glob(destination.name + ".old-*"))


def test_corrupt_staged_bytes_are_rechecked_before_publish(release, tmp_path, monkeypatch):
    catalog, source, tools = _source(tmp_path, release)
    destination = F.installed_directory(tools, release["entry"])
    write = Path.write_bytes

    def corrupt_copy(path, data):
        if path.parent.name.startswith(".espprobe-stage-") and path.name == "bootloader.bin":
            data = data[:-1] + bytes([data[-1] ^ 1])
        return write(path, data)

    monkeypatch.setattr(Path, "write_bytes", corrupt_copy)
    with pytest.raises(F.BuildError, match="payload hash"):
        F.install_releases(catalog, source, tools)
    assert not destination.exists()
    assert not list(destination.parent.glob(".espprobe-stage-*"))


@pytest.mark.parametrize("level", ["destination", "parent"])
def test_existing_valid_install_through_symlink_is_not_accepted(release, tmp_path, level):
    catalog, source, tools = _source(tmp_path, release)
    assert F.install_releases(catalog, source, tools) == 0
    destination = F.installed_directory(tools, release["entry"])
    linked = destination if level == "destination" else destination.parent
    moved = tmp_path / "synthetic-linked-install"
    linked.rename(moved)
    linked.symlink_to(moved, target_is_directory=True)
    before = _tree(moved)
    with pytest.raises(F.BuildError):
        F.install_releases(catalog, source, tools, check=True)
    assert _tree(moved) == before


def test_corrupt_staged_manifest_is_not_reported_as_installed(release, tmp_path, monkeypatch):
    catalog, source, tools = _source(tmp_path, release)
    destination = F.installed_directory(tools, release["entry"])
    write = Path.write_bytes

    def corrupt_metadata(path, data):
        if path.parent.name.startswith(".espprobe-stage-") and path.name == "release.json":
            data = b"{}\n"
        return write(path, data)

    monkeypatch.setattr(Path, "write_bytes", corrupt_metadata)
    with pytest.raises(F.BuildError):
        F.install_releases(catalog, source, tools)
    assert not destination.exists()
    assert not list(destination.parent.glob(".espprobe-stage-*"))
