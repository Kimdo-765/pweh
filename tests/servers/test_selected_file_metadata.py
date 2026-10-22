"""합성 FAT/exFAT 선택의 부모 삭제 문맥과 명시적인 빈 파일 허용 회귀."""
from __future__ import annotations

import hashlib
import os
import time
from types import SimpleNamespace

import pytest

from fs.builders import exfat_small, fat16_small, fat32_small
from forensics_mcp import fsops
from pweh.fs import Budget, BytesReader, FsError, Limits, open_volume
from pweh.fs.base import DirResult, VolumeBase

DATA = b"PWEH SYNTHETIC SELECTED BYTES"


def selected(tmp_path, builder, *, path=None, ref=None, **kwargs):
    image = tmp_path / "synthetic-card.img"
    image.write_bytes(builder.image())
    fd = os.open(image, os.O_RDONLY)
    try:
        return fsops.read_selected_file(fd, path=path, ref=ref, max_bytes=1024,
                                       deadline=time.monotonic() + 30, cancel=lambda: False, **kwargs)
    finally:
        os.close(fd)


def volume(builder):
    return open_volume(BytesReader(builder.image()))


@pytest.mark.parametrize("builder", [fat16_small, fat32_small, exfat_small])
@pytest.mark.parametrize("depth", [0, 1, 2])
def test_ref_and_path_live_parent_context(tmp_path, builder, depth):
    b = builder()
    prefix = ""
    for i in range(depth):
        prefix += f"/dir{i}"
        b.mkdir(prefix)
    path = prefix + "/item.bin"
    b.add_file(path, DATA)
    ref = volume(b).lookup(path)["ref"]
    for selector in ({"path": path}, {"ref": ref}):
        data, source = selected(tmp_path, b, **selector)
        assert data == DATA and source["parent_deleted"] is False
        assert source["deleted"] is False
        assert source["sha256"] == hashlib.sha256(DATA).hexdigest()
        assert "container_truncated" not in source


@pytest.mark.parametrize("builder", [fat16_small, fat32_small, exfat_small])
@pytest.mark.parametrize("depth", [1, 2])
def test_live_file_under_deleted_ancestor_is_not_live_context(tmp_path, builder, depth):
    b = builder()
    b.mkdir("/gone")
    path = "/gone/item.bin"
    if depth == 2:
        b.mkdir("/gone/sub")
        path = "/gone/sub/item.bin"
    b.add_file(path, DATA)
    ref = volume(b).lookup(path)["ref"]
    b.delete("/gone")
    previous_ref = ref
    ref = next(e["ref"] for e in volume(b).walk()["entries"] if e["name"] == "item.bin")
    if ref != previous_ref:
        # 삭제 FAT 디렉터리는 연속 복구 dirspec이므로 이전 live ref를 허용하지 않는다.
        with pytest.raises(FsError):
            selected(tmp_path, b, ref=previous_ref)
    data, source = selected(tmp_path, b, ref=ref)
    assert data == DATA and source["deleted"] is False and source["parent_deleted"] is True
    with pytest.raises(FsError):
        selected(tmp_path, b, path=path)


@pytest.mark.parametrize("builder", [fat16_small, fat32_small, exfat_small])
def test_deleted_file_keeps_parent_context_separate(tmp_path, builder):
    b = builder()
    b.mkdir("/live")
    b.add_file("/live/item.bin", DATA)
    ref = volume(b).lookup("/live/item.bin")["ref"]
    b.delete("/live/item.bin")
    data, source = selected(tmp_path, b, ref=ref)
    assert data == DATA and source["deleted"] is True and source["parent_deleted"] is False


@pytest.mark.parametrize("builder", [fat16_small, fat32_small, exfat_small])
@pytest.mark.parametrize("deleted", [False, True])
def test_empty_fs_requires_explicit_option_and_complete_selection(tmp_path, builder, deleted):
    b = builder()
    b.add_file("/empty.bin", b"")
    ref = volume(b).lookup("/empty.bin")["ref"]
    if deleted:
        b.delete("/empty.bin")
    with pytest.raises(FsError):
        selected(tmp_path, b, ref=ref)
    data, source = selected(tmp_path, b, ref=ref, allow_empty=True)
    assert data == b"" and source["size"] == 0 and source["complete"] is True
    assert source["confidence"] == "high" and source["method"] in ("chain", "empty")
    assert source["sha256"] == hashlib.sha256(b"").hexdigest()
    assert source["parent_deleted"] is False


def test_empty_option_does_not_accept_preallocated_exfat(tmp_path):
    b = exfat_small()
    b.add_file("/allocated.bin", b"UNEXAMINED SYNTHETIC", valid_data_length=0)
    with pytest.raises(FsError):
        selected(tmp_path, b, path="/allocated.bin", allow_empty=True)


def test_parent_map_is_optional_and_target_root_still_stops_immediately(monkeypatch):
    v = volume(fat32_small())
    monkeypatch.setattr(v, "_parse_dir", lambda *a, **kw: pytest.fail("root 목표에 추가 디렉터리 읽기"))
    plain = v.reachable_dirspecs(targets=["root"])
    assert "parent_deleted" not in plain and plain["status"] == "targets_found"
    rich = v.reachable_dirspecs(targets=["root"], include_parent_deleted=True)
    assert rich["parent_deleted"] == {"root": False}
    assert rich["status"] == "targets_found"


def test_missing_parent_metadata_stays_unknown_without_relaxing_ref_validation(tmp_path, monkeypatch):
    b = fat32_small()
    b.mkdir("/dir")
    b.add_file("/dir/item.bin", DATA)
    entry = volume(b).lookup("/dir/item.bin")
    original = VolumeBase.reachable_dirspecs
    def no_context(self, *a, **kw):
        result = original(self, *a, **kw)
        result.pop("parent_deleted", None)
        return result
    monkeypatch.setattr(VolumeBase, "reachable_dirspecs", no_context)
    data, source = selected(tmp_path, b, ref=entry["ref"])
    assert data == DATA and source["parent_deleted"] is None
    with pytest.raises(FsError):
        selected(tmp_path, b, ref=f"c{entry['first_cluster']}/0")


def test_conflicting_observed_directory_context_is_unknown():
    root = DirResult("root")
    root.entries = [{"is_dir": True, "child_dir": "c2", "deleted": deleted, "display_name": str(i)}
                    for i, deleted in enumerate((False, True))]
    child = DirResult("c2")
    child.entries = [{"is_dir": True, "child_dir": "c3", "deleted": False, "display_name": "child"}]
    fake = SimpleNamespace(limits=Limits(), _budget=lambda lim, budget: Budget(None, 1000),
                           _spec_key=lambda spec: spec, _parse_dir=lambda spec, *a, **k: {"root": root, "c2": child, "c3": DirResult("c3")}[spec],
                           _deleted_dir_ok=lambda *a: True)
    result = VolumeBase.reachable_dirspecs(fake, include_parent_deleted=True)
    assert result["dirspecs"] == {"root", "c2", "c3"}
    assert result["parent_deleted"] == {"root": False, "c2": None, "c3": None}
    early = VolumeBase.reachable_dirspecs(fake, targets=["c2"], include_parent_deleted=True)
    assert early["status"] == "targets_found" and early["dirspecs"] == {"root", "c2"}
    assert early["parent_deleted"] == {"root": False, "c2": None}


def test_reachable_context_preserves_existing_budget_and_found_scope():
    b = fat32_small()
    b.mkdir("/dir")
    b.add_file("/dir/item.bin", DATA)
    spec = volume(b).lookup("/dir/item.bin")["ref"].rsplit("/", 1)[0]
    result = volume(b).reachable_dirspecs(targets=[spec], include_parent_deleted=True)
    assert result["status"] == "targets_found" and result["parent_deleted"][spec] is False
    cut = volume(b).reachable_dirspecs(budget=Budget(None, 0), targets=[spec], include_parent_deleted=True)
    assert spec not in cut["dirspecs"] and spec not in cut["parent_deleted"]
    assert cut["truncated"]


def test_zero_byte_ev_existing_default_behavior_is_unchanged(tmp_path):
    path = tmp_path / "synthetic-empty.bin"
    path.write_bytes(b"")
    fd = os.open(path, os.O_RDONLY)
    try:
        data, meta = fsops.read_selected_file(fd, max_bytes=1024, deadline=time.monotonic() + 10, cancel=lambda: False)
        assert data == b"" and meta["size"] == 0 and meta["method"] == "whole-file"
        with pytest.raises(FsError):
            fsops.read_selected_file(fd, max_bytes=1024, deadline=time.monotonic() + 10, cancel=lambda: False, allow_empty=1)
    finally:
        os.close(fd)


@pytest.mark.parametrize("broken", ["incomplete", "limit", "beyond", "extra_bytes"])
def test_empty_option_does_not_weaken_plan_or_actual_read(tmp_path, monkeypatch, broken):
    b = fat32_small()
    b.add_file("/empty.bin", b"")
    original = VolumeBase.content_plan
    def plan(self, *a, **kw):
        result = original(self, *a, **kw)
        if broken == "incomplete": result.extra["complete"] = False
        if broken == "limit": result.extra["limit_reason"] = "steps"
        if broken == "beyond": result.extra["bytes_beyond_image"] = 1
        return result
    monkeypatch.setattr(VolumeBase, "content_plan", plan)
    if broken == "extra_bytes":
        monkeypatch.setattr(VolumeBase, "iter_plan", lambda *a, **kw: iter([b"X"]))
    with pytest.raises(FsError) as exc:
        selected(tmp_path, b, path="/empty.bin", allow_empty=True)
    assert exc.value.reason == "incomplete_file"


def test_selected_reader_never_adds_a_whole_volume_walk(tmp_path, monkeypatch):
    b = fat32_small()
    b.mkdir("/dir")
    b.add_file("/dir/item.bin", DATA)
    ref = volume(b).lookup("/dir/item.bin")["ref"]
    monkeypatch.setattr(VolumeBase, "walk", lambda *a, **kw: pytest.fail("선택에 전체 walk 추가"))
    data, source = selected(tmp_path, b, ref=ref)
    assert data == DATA and source["parent_deleted"] is False
