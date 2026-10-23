"""기존 FAT/exFAT 진단의 실제 계수·phase·예산을 합성 이미지로 대조한다."""

from __future__ import annotations

import struct
import time

import pytest

from fs.builders import exfat_small, fat12_small, fat16_small, fat32_small
from pweh.fs import Budget, BytesReader, ExfatVolume, FsError, Limits, open_volume
from pweh.fs.common import Warnings
from pweh.fs.tables import ClusterBitmap

BUILDERS = [fat12_small, fat16_small, fat32_small, exfat_small]
KEYS = {"reference_walk_complete", "reference_map_complete", "allocation_complete", "rows_complete",
        "entries_observed", "allocation_clusters_examined", "allocation_free", "observed_referenced_clusters", "reasons"}


def volume(builder, **overrides):
    limits = Limits(max_follow_steps=1 << 20, **overrides)
    budget = Budget.for_limits(limits, deadline=time.monotonic() + 10)
    result = open_volume(BytesReader(builder.image()), limits=limits, budget=budget)
    return result, budget


def inspect(result):
    row = result["inspection"]
    assert set(row) == KEYS
    for key in ("reference_walk_complete", "reference_map_complete", "allocation_complete", "rows_complete"):
        assert type(row[key]) is bool
    for key in ("entries_observed", "allocation_clusters_examined", "allocation_free", "observed_referenced_clusters"):
        assert type(row[key]) is int and row[key] >= 0
    assert len(row["reasons"]) == len(set(row["reasons"]))
    return row


@pytest.mark.parametrize("make", BUILDERS)
def test_complete_counts_and_legacy_keys(make):
    b = make()
    b.add_file("/A.BIN", b"a" * (b.cs + 1))
    b.add_file("/B.BIN", b"b")
    vol, budget = volume(b)
    rep = vol.cluster_report(budget=budget)
    row = inspect(rep)
    assert all(row[key] for key in ("reference_walk_complete", "reference_map_complete", "allocation_complete", "rows_complete"))
    assert row["entries_observed"] == 2
    assert row["reasons"] == []
    assert row["allocation_clusters_examined"] == b.count
    assert row["allocation_free"] == rep["free"]
    assert row["observed_referenced_clusters"] == rep["referenced_by_live"]
    assert rep["allocated_unreferenced"] == 0 and not rep["truncated"]
    assert rep["allocated"] + rep["free"] + rep.get("bad", 0) == b.count


@pytest.mark.parametrize("make", BUILDERS)
def test_same_allocation_different_live_reference(make):
    b = make()
    b.reserve([500])
    if make is not exfat_small:
        b.write_chain([500])
    first, budget = volume(b)
    before = first.cluster_report(budget=budget)
    b.used.discard(500)
    b.add_file("/LINK.BIN", b"x", clusters=[500])
    after, budget = volume(b)
    after = after.cluster_report(budget=budget)
    assert before["allocated"] == after["allocated"]
    assert before["allocated_unreferenced"] == after["allocated_unreferenced"] + 1
    assert inspect(after)["reference_map_complete"]


@pytest.mark.parametrize("make", [fat16_small, exfat_small])
def test_complete_overlap_is_event_count(make):
    b = make()
    for i in range(3):
        b.used.discard(500)
        b.add_file(f"/F{i}.BIN", b"x", clusters=[500])
    vol, budget = volume(b)
    rep = vol.cluster_report(budget=budget)
    row = inspect(rep)
    assert rep["cross_linked"] == 2
    assert row["reference_map_complete"] and row["allocation_complete"]
    assert row["rows_complete"] and row["reasons"] == []


@pytest.mark.parametrize("make", [fat16_small, exfat_small])
@pytest.mark.parametrize("fault", ["zeroed", "broken", "cycle", "short", "long", "fragmented"])
def test_incomplete_chain_never_complete_map(make, fault):
    b = make()
    kwargs = {"contiguous": False} if make is exfat_small else {}
    b.add_file("/F.BIN", b"x" * (3 * b.cs), clusters=[500, 510, 520], **kwargs)
    eoc = 0xffffffff if make is exfat_small else b.eoc
    if fault == "zeroed":
        b.set_fat(500, 0)
    elif fault == "broken":
        b.set_fat(500, 0xfffffff7 if make is exfat_small else 0xfff7)
    elif fault == "cycle":
        b.set_fat(510, 500)
    elif fault == "short":
        b.set_fat(500, eoc)
    elif fault == "long":
        b.set_fat(520, 530)
        b.set_fat(530, 540)
        b.set_fat(540, eoc)
        b.reserve([530, 540])
    vol, budget = volume(b, **({"max_runs": 1} if fault == "fragmented" else {}))
    rep = vol.cluster_report(budget=budget)
    row = inspect(rep)
    assert row["reference_walk_complete"] and not row["reference_map_complete"]
    assert "reference_chain_incomplete" in row["reasons"]
    assert rep["chain_anomalies"]


@pytest.mark.parametrize("make", BUILDERS)
def test_cluster_limit_early_inspection(make):
    vol, budget = volume(make(), max_scan_clusters=1)
    rep = vol.cluster_report(budget=budget)
    row = inspect(rep)
    assert not rep["scanned"]
    assert row["allocation_clusters_examined"] == row["entries_observed"] == 0
    assert not row["allocation_complete"] and not row["reference_map_complete"]
    assert row["rows_complete"] and row["reasons"] == ["cluster_limit"]


@pytest.mark.parametrize("make", [fat16_small, exfat_small])
@pytest.mark.parametrize("limit", ["max_entries", "max_depth", "max_dir_slots", "max_total_slots", "max_path_chars"])
def test_walk_limits_are_separate_from_allocation(make, limit):
    b = make()
    b.mkdir("/A")
    b.mkdir("/A/B")
    for i in range(4):
        b.add_file(f"/A/B/F{i}.BIN", b"x")
    settings = {limit: 1 if limit not in ("max_dir_slots", "max_total_slots") else 16}
    if limit in ("max_dir_slots", "max_total_slots"):
        for i in range(80):
            b.add_file(f"/R{i}.BIN", b"x")
    vol, budget = volume(b, **settings)
    rep = vol.cluster_report(budget=budget)
    row = inspect(rep)
    assert not row["reference_walk_complete"]
    assert not row["reference_map_complete"]
    assert limit in row["reasons"] or "dir_unvalidated" in row["reasons"]


@pytest.mark.parametrize("make", [fat16_small, exfat_small])
def test_unvalidated_live_directory_is_not_complete_walk(make):
    b = make()
    b.mkdir("/A", clusters=[500])
    image = bytearray(b.image())
    off = b.coff(500)
    image[off:off + 32] = b"\xff" * 32
    vol = open_volume(BytesReader(bytes(image)))
    row = inspect(vol.cluster_report())
    assert not row["reference_walk_complete"] and not row["reference_map_complete"]
    assert "dir_unvalidated" in row["reasons"]


@pytest.mark.parametrize("make", [fat16_small, exfat_small])
@pytest.mark.parametrize("kind", ["overlap", "unreferenced", "anomaly", "unallocated"])
def test_samples_capped_without_losing_counts(make, kind):
    b = make()
    kwargs = {"contiguous": False} if make is exfat_small else {}
    if kind == "overlap":
        for i in range(4):
            b.used.discard(500)
            b.add_file(f"/F{i}.BIN", b"x", clusters=[500])
    elif kind == "unreferenced":
        for c in (500, 510, 520):
            b.reserve([c])
            if make is not exfat_small:
                b.write_chain([c])
    else:
        for i, c in enumerate((500, 510, 520)):
            b.add_file(f"/F{i}.BIN", b"x" * (2 * b.cs if kind == "anomaly" else 1),
                       clusters=[c, c + 1] if kind == "anomaly" else [c], **kwargs)
            if kind == "anomaly":
                b.set_fat(c, 0xffffffff if make is exfat_small else b.eoc)
            elif make is exfat_small:
                b.used.discard(c)
            else:
                b.set_fat(c, 0)
    vol, budget = volume(b, max_report_items=1)
    rep = vol.cluster_report(budget=budget)
    row = inspect(rep)
    assert not row["rows_complete"] and "rows_limit" in row["reasons"]
    keys = {"overlap": ("cross_linked", "cross_linked_samples"),
            "unreferenced": ("allocated_unreferenced", "allocated_unreferenced_runs"),
            "unallocated": ("unallocated_referenced", "unallocated_referenced_samples")}
    if kind in keys:
        count, sample = keys[kind]
        assert rep[count] >= 3 and len(rep[sample]) == 1
    else:
        assert len(rep["chain_anomalies"]) == 1


def bitmap_entry(b, *, flags=0, length=None, first=None):
    data = bytearray(b.dirs["/"].slots[1])
    data[1] = flags
    struct.pack_into("<IQ", data, 20, b.bitmap_clusters[0] if first is None else first,
                     b.bitmap_len if length is None else length)
    return bytes(data)


@pytest.mark.parametrize("fault", ["missing", "short", "duplicate", "inactive", "flags", "chain", "root"])
def test_exfat_constructor_observations_do_not_change_fallback(fault):
    b = exfat_small()
    if fault == "missing":
        del b.dirs["/"].slots[1]
    elif fault == "short":
        b.dirs["/"].slots[1] = bitmap_entry(b, length=1)
    elif fault == "duplicate":
        b.dirs["/"].slots.append(bitmap_entry(b))
    elif fault == "inactive":
        b.dirs["/"].slots[1] = bitmap_entry(b, flags=1)
    elif fault == "flags":
        b.dirs["/"].slots[1] = bitmap_entry(b, flags=2)
    elif fault == "chain":
        b.set_fat(b.bitmap_clusters[0], 0)
    else:
        b.set_fat(b.root_clusters[0], 0)
    vol, budget = volume(b)
    rep = vol.cluster_report(budget=budget)
    row = inspect(rep)
    assert not row["allocation_complete"]
    assert row["reasons"]
    if fault in ("duplicate", "inactive", "chain"):
        assert vol._bitmap is not None
    if fault == "short":
        assert row["allocation_clusters_examined"] == 8
        assert row["allocation_free"] + rep["allocated"] == 8
        assert rep["free"] > row["allocation_free"]


def test_exfat_unreadable_bitmap_tail_not_free(monkeypatch):
    vol, budget = volume(exfat_small())
    original = ClusterBitmap.iter_bytes
    def prefix(self, *args):
        for start, data in original(self, *args):
            yield start, data[:1]
            return
    monkeypatch.setattr(ClusterBitmap, "iter_bytes", prefix)
    rep = vol.cluster_report(budget=budget)
    row = inspect(rep)
    assert row["allocation_clusters_examined"] == 8
    assert row["allocation_free"] + rep["allocated"] == 8
    assert not row["allocation_complete"]


@pytest.mark.parametrize("case", ["different", "three", "inactive", "bad_active"])
def test_fat_copy_authority(case):
    b = fat32_small(num_fats=3 if case == "three" else 2,
                    ext_flags=0x81 if case == "inactive" else 0x8f if case == "bad_active" else 0)
    if case in ("different", "inactive"):
        b.set_fat_copy(0 if case == "inactive" else 1, 500, b.eoc)
    vol, budget = volume(b)
    rep = vol.cluster_report(budget=budget)
    row = inspect(rep)
    assert row["allocation_complete"] is (case == "inactive")
    assert ("metadata_inconsistent" in row["reasons"]) is (case != "inactive")


@pytest.mark.parametrize("make", BUILDERS)
@pytest.mark.parametrize("stop", ["time", "steps", "cancelled"])
def test_runtime_budget_early_stop(make, stop):
    vol, budget = volume(make())
    if stop == "time":
        budget.deadline = time.monotonic() - 1
    elif stop == "steps":
        budget.max_steps = budget.steps
        budget.tick()
    else:
        budget.cancel = lambda: True
    if stop == "cancelled":
        with pytest.raises(FsError) as err:
            vol.cluster_report(budget=budget)
        assert err.value.data["limit"] == "cancelled"
    else:
        row = inspect(vol.cluster_report(budget=budget))
        assert not row["allocation_complete"] and row["allocation_clusters_examined"] == 0
        assert ("time_limit" if stop == "time" else "step_limit") in row["reasons"]


def test_fat_cached_classification_stops_with_real_positive_count():
    vol, budget = volume(fat16_small())
    # live 지도 이후 첫 cached 조각까지만 허용한다.
    live = vol._live_map(budget)
    assert live["inspection"]["reference_map_complete"]
    budget.max_steps = budget.steps + 1
    rep = vol.cluster_report(budget=budget)
    row = inspect(rep)
    assert row["allocation_clusters_examined"] == 4096
    assert row["allocation_free"] + rep["allocated"] + rep["bad"] == 4096
    assert not row["allocation_complete"] and "step_limit" in row["reasons"]


def test_copy_read_chunks_and_default_semantics(monkeypatch):
    b = fat32_small()
    b.set_fat_copy(1, 500, b.eoc)
    vol, budget = volume(b)
    observed = []
    read = vol.src.read_clamped
    def record(offset, size):
        observed.append(size)
        return read(offset, size)
    monkeypatch.setattr(vol.src, "read_clamped", record)
    old = vol._compare_fat_copies(Warnings())
    observed.clear()
    new = vol._compare_fat_copies(Warnings(), budget=budget)
    assert new == old and max(observed) <= 65536


def test_exfat_constructor_budget_metadata_partial_retains_geometry():
    b = exfat_small()
    class Limited(BytesReader):
        def read(self, offset, length):
            if offset >= b.coff(b.root_clusters[0]):
                raise FsError("합성 상한", reason="budget_exceeded", data={"limit": "metadata_bytes"})
            return super().read(offset, length)
    vol = ExfatVolume(Limited(b.image()))
    row = inspect(vol.cluster_report())
    assert vol.cluster_count == b.count and vol.cluster_size == b.cs
    assert "metadata_bytes_limit" in row["reasons"]
    assert not row["allocation_complete"] and not row["reference_map_complete"]


def test_missing_bitmap_preserves_legacy_state():
    b = exfat_small()
    del b.dirs["/"].slots[1]
    vol, budget = volume(b)
    assert vol.cluster_report(budget=budget)["state"] == vol.info()["state"]


def test_short_fat_yield_counts_only_observed_entries(monkeypatch):
    vol, budget = volume(fat16_small())
    vol._live_map(budget)
    original = vol._fat.slices
    def prefix(*args):
        for base, values in original(*args):
            yield base, values[:7]
            return
    monkeypatch.setattr(vol._fat, "slices", prefix)
    rep = vol.cluster_report(budget=budget)
    row = inspect(rep)
    assert row["allocation_clusters_examined"] == row["allocation_free"] == 7
    assert rep["free"] == 7 and not row["allocation_complete"]
    assert "allocation_unreadable" in row["reasons"]


def test_fat_copy_budget_stop_preserves_classified_count(monkeypatch):
    b = fat16_small()
    vol, budget = volume(b)
    vol._live_map(budget)
    original = vol.src.read_clamped
    calls = []
    def cut(offset, length):
        data = original(offset, length)
        if offset == vol.fat_offset + vol.fat_bytes:
            calls.append(length)
            budget.max_steps = budget.steps
            budget.tick()
        return data
    monkeypatch.setattr(vol.src, "read_clamped", cut)
    rep = vol.cluster_report(budget=budget)
    row = inspect(rep)
    assert calls and max(calls) <= 65536
    assert row["allocation_clusters_examined"] == b.count
    assert row["allocation_free"] == b.count
    assert not row["allocation_complete"] and "step_limit" in row["reasons"]


def test_empty_chain_anomaly_samples_are_bounded(monkeypatch):
    vol, budget = volume(fat16_small(), max_report_items=1)
    # 파서와 독립된 live-map의 빈 체인 분기에서도 표본 상한을 적용한다.
    entries = [{"first_cluster": 0, "size": 1, "is_dir": False,
                "ref": f"root/{i}", "path": f"/F{i}.BIN"} for i in range(3)]
    monkeypatch.setattr(vol, "walk", lambda **kw: {"entries": entries, "truncated": False})
    rep = vol.cluster_report(budget=budget)
    row = inspect(rep)
    assert row["entries_observed"] == 3 and row["reference_walk_complete"]
    assert not row["reference_map_complete"] and not row["rows_complete"]
    assert len(rep["chain_anomalies"]) == 1
    assert "rows_limit" in row["reasons"] and "reference_chain_incomplete" in row["reasons"]
