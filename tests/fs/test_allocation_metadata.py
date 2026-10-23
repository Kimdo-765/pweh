"""할당 창 전용 exFAT metadata와 기존 full 해석의 분리 회귀."""

from __future__ import annotations

import struct
import time

import pytest

from fs.builders import exfat_small, fat12_small, exfat_boot_checksum
from pweh.fs import Budget, BytesReader, ExfatVolume, FsError, Limits, open_volume
from pweh.fs.tables import ClusterBitmap


def allocation(data, **kwargs):
    return ExfatVolume(BytesReader(data), metadata_mode="allocation", **kwargs)


def bitmap_entry(builder, *, flags=0, first=None, length=None):
    raw = bytearray(builder.dirs["/"].slots[1])
    raw[1] = flags
    struct.pack_into("<IQ", raw, 20,
                     builder.bitmap_clusters[0] if first is None else first,
                     builder.bitmap_len if length is None else length)
    return bytes(raw)


def patch_boot(data, offset, fmt, value):
    """양쪽 boot를 독립 checksum으로 함께 바꾼다."""
    result = bytearray(data)
    for base in (0, 12 * 512):
        struct.pack_into(fmt, result, base + offset, value)
        checksum = exfat_boot_checksum(bytes(result[base:base + 12 * 512]), 512)
        for pos in range(512 // 4):
            struct.pack_into("<I", result, base + 11 * 512 + pos * 4, checksum)
    return bytes(result)


def assert_unknown(vol, reason):
    assert vol.allocation_status == "unknown"
    assert vol.allocation_reason == reason
    assert vol._bitmap is None
    assert vol.allocated(2) is None
    assert vol.cluster_size > 0 and vol.cluster_count > 0


def assert_stopped(vol, reason):
    assert vol.allocation_status == "stopped"
    assert vol.allocation_reason == reason
    assert vol._bitmap is None
    assert vol.cluster_size > 0 and vol.cluster_count > 0


def test_metadata_only_never_names_upcase_popcount_or_object_fallback(monkeypatch):
    b = exfat_small(label="PRIVATE")
    b.add_file("/PRIVATE-NAME.txt", b"PRIVATE-CONTENT")
    image = b.image()

    def forbidden(*args, **kwargs):
        pytest.fail("full 메타데이터 경로를 호출했습니다")

    for name in ("_parse_dir", "_file_set", "_load_root_metadata", "_object_runs", "_decompress_upcase"):
        monkeypatch.setattr(ExfatVolume, name, forbidden)
    monkeypatch.setattr(ClusterBitmap, "count_range", forbidden)
    vol = allocation(image)
    assert vol.allocation_status == "ready" and vol.allocation_reason is None
    assert vol.allocated(b.bitmap_clusters[0]) is True
    assert vol.allocated(b.next_hint + 1) is False
    assert vol.label is None and vol.volume_guid is None and vol._upcase is None
    assert not vol._dir_cache and vol._live_cache is None
    assert vol.bitmap_info == {"present": False}


def test_full_default_and_explicit_are_identical():
    b = exfat_small()
    b.add_file("/a.txt", b"data")
    image = b.image()
    a = ExfatVolume(BytesReader(image))
    c = ExfatVolume(BytesReader(image), metadata_mode="full")
    assert a.info() == c.info()
    assert a.walk() == c.walk()
    assert a.read_content("root/3") == c.read_content("root/3")
    assert not hasattr(a, "allocation_status")


@pytest.mark.parametrize("value", [None, True, 1, "", "FULL", "unknown", [], b"full"])
@pytest.mark.parametrize("entry", ["exfat", "open", "fat"])
def test_bad_mode_is_fixed_before_read(value, entry):
    class NoRead:
        def read(self, *args):
            pytest.fail("잘못된 mode로 입력을 읽었습니다")
    with pytest.raises(FsError) as error:
        if entry == "exfat":
            ExfatVolume(NoRead(), metadata_mode=value)
        else:
            open_volume(NoRead(), fs_hint="fat12" if entry == "fat" else "exfat", metadata_mode=value)
    assert error.value.reason == "bad_argument"
    assert error.value.message == "메타데이터 모드가 올바르지 않습니다."


def test_open_volume_and_fsops_forward_mode_and_budget():
    from forensics_mcp.fsops import open_partition_volume
    image = exfat_small().image()
    limits = Limits(max_follow_steps=10000)
    budget = Budget.for_limits(limits)
    vol = open_volume(BytesReader(image), limits=limits, budget=budget, metadata_mode="allocation")
    assert vol.allocation_status == "ready" and budget.steps > 0
    old = budget.steps
    _, vol2 = open_partition_volume(BytesReader(image), None, limits=limits, budget=budget,
                                   metadata_mode="allocation")
    assert vol2.allocation_status == "ready" and budget.steps > old
    assert budget.max_steps == 10000


def test_fat_constructor_unchanged_by_allocation_keyword():
    image = fat12_small().image()
    full = open_volume(BytesReader(image))
    minimal = open_volume(BytesReader(image), metadata_mode="allocation")
    assert full.info() == minimal.info()
    assert not hasattr(minimal, "allocation_status")


@pytest.mark.parametrize("flags", [2, 4, 6, 8])
def test_information_flags_do_not_invalidate_allocation(flags):
    assert allocation(exfat_small(volume_flags=flags).image()).allocation_status == "ready"


@pytest.mark.parametrize("nfats,active", [(1, 1), (3, 0), (3, 1)])
def test_original_fat_number_and_active_are_not_fallback_authority(nfats, active):
    image = exfat_small(volume_flags=active).image()
    image = patch_boot(image, 110, "B", nfats)
    assert_unknown(allocation(image), "active_fat_invalid")


@pytest.mark.parametrize("mutation", ["count", "fat_small", "fat_overlap", "heap_overlap", "truncated",
                                      "checksum", "backup", "ext_signature", "signature"])
def test_geometry_and_boot_inconsistency(mutation):
    b = exfat_small()
    image = b.image()
    if mutation == "count":
        image = patch_boot(image, 92, "I", b.count + 1)
    elif mutation == "fat_small":
        image = patch_boot(image, 84, "I", 1)
    elif mutation == "fat_overlap":
        image = patch_boot(image, 80, "I", 23)
    elif mutation == "heap_overlap":
        image = patch_boot(image, 88, "I", b.fat_off)
    elif mutation == "truncated":
        image = image[:-512]
    elif mutation == "backup":
        raw = bytearray(image)
        raw[12 * 512 + 100] ^= 1
        image = bytes(raw)
    elif mutation == "ext_signature":
        image = patch_boot(image, 1020, "I", 0)
    elif mutation == "signature":
        image = patch_boot(image, 510, "H", 0)
    else:
        raw = bytearray(image)
        raw[11 * 512] ^= 1
        image = bytes(raw)
    assert_unknown(allocation(image), "volume_metadata_inconsistent")


@pytest.mark.parametrize("variant,reason", [("missing", "bitmap_missing"), ("mismatch", "bitmap_active_mismatch"),
                                           ("duplicate", "bitmap_ambiguous")])
def test_bitmap_admission(variant, reason):
    b = exfat_small()
    if variant == "missing":
        del b.dirs["/"].slots[1]
    elif variant == "mismatch":
        b.dirs["/"].slots[1] = bitmap_entry(b, flags=1)
    else:
        b.dirs["/"].slots.append(bitmap_entry(b))
    image = b.image()
    assert_unknown(allocation(image), reason)
    if variant == "mismatch":
        assert ExfatVolume(BytesReader(image))._bitmap is not None


def test_two_fats_choose_only_exact_active_bitmap():
    b = exfat_small(number_of_fats=2, volume_flags=1)
    b.dirs["/"].slots.append(bitmap_entry(b, flags=1))
    assert allocation(b.image()).allocation_status == "ready"


def test_short_declared_bitmap_keeps_unreadable_tail():
    b = exfat_small()
    b.dirs["/"].slots[1] = bitmap_entry(b, length=1)
    vol = allocation(b.image())
    assert vol.allocation_status == "ready"
    assert vol.allocated(2) is True
    assert vol.allocated(10) is None


@pytest.mark.parametrize("value", [0, 0xFFFFFFF7, 0xFFFFFFF0, 1, 2])
def test_bitmap_bad_last_fat_never_falls_back(value):
    b = exfat_small()
    first = b.bitmap_clusters[0]
    b.set_fat(first, value)
    assert_unknown(allocation(b.image()), "bitmap_chain_invalid")


@pytest.mark.parametrize("length", [0, 4097, 1 << 40])
def test_declared_bitmap_length_must_match_full_chain(length):
    b = exfat_small()
    b.dirs["/"].slots[1] = bitmap_entry(b, length=length)
    assert_unknown(allocation(b.image()), "bitmap_chain_invalid")


def fragmented_bitmap():
    b = exfat_small()
    first = b.bitmap_clusters[0]
    last = b.alloc(1)[0]
    b.set_fat(first, last)
    b.set_fat(last, 0xFFFFFFFF)
    b.dirs["/"].slots[1] = bitmap_entry(b, length=b.cs + 1)
    return b, first, last


def test_fragmented_bitmap_uses_actual_extents():
    b, first, last = fragmented_bitmap()
    vol = allocation(b.image())
    assert vol.allocation_status == "ready"
    assert vol._bitmap._offs == [b.coff(first), b.coff(last)]
    assert vol._bitmap._lens == [b.cs, 1]


def test_bitmap_cannot_use_known_root_extent():
    b = exfat_small()
    b.dirs["/"].slots[1] = bitmap_entry(b, first=b.root_clusters[0])
    assert_unknown(allocation(b.image()), "bitmap_chain_invalid")


def test_bitmap_reserved_flags_are_rejected_by_root_validation():
    b = exfat_small()
    b.dirs["/"].slots[1] = bitmap_entry(b, flags=2)
    assert_unknown(allocation(b.image()), "root_metadata_incomplete")


def test_bitmap_run_cap_is_stopped():
    b, _, _ = fragmented_bitmap()
    assert_stopped(allocation(b.image(), limits=Limits(max_runs=1)), "bitmap_runs_limit")


@pytest.mark.parametrize("value", [0, 0xFFFFFFF7, 1])
def test_root_end_marker_permits_unused_broken_chain_tail(value):
    b = exfat_small()
    b.set_fat(b.root_clusters[0], value)
    assert allocation(b.image()).allocation_status == "ready"


def no_end_root(b):
    padding = b"\xa1" + bytes(31)
    slots = b.dirs["/"].slots
    slots.extend([padding] * (b.cs // 32 * len(b.root_clusters) - len(slots)))


def test_root_valid_chain_eoc_without_zero_marker():
    b = exfat_small()
    no_end_root(b)
    assert allocation(b.image()).allocation_status == "ready"


@pytest.mark.parametrize("value", [0, 0xFFFFFFF7, 1])
def test_root_without_end_and_broken_chain_is_unknown(value):
    b = exfat_small()
    no_end_root(b)
    b.set_fat(b.root_clusters[0], value)
    assert_unknown(allocation(b.image()), "root_metadata_incomplete")


def test_unvalidated_unit_cannot_admit_earlier_bitmap():
    b = exfat_small()
    b.dirs["/"].slots.append(b"\xff" + bytes(31))
    assert_unknown(allocation(b.image()), "root_metadata_incomplete")


@pytest.mark.parametrize("slot_cap", [1, 127, 129])
def test_root_clipped_cluster_cannot_admit_bitmap(slot_cap):
    b = exfat_small(root_clusters=2)
    if slot_cap == 129:
        no_end_root(b)
    assert_stopped(allocation(b.image(), limits=Limits(max_dir_slots=slot_cap)), "root_slots_limit")


def test_root_run_limit_is_stopped_without_end():
    b = exfat_small()
    no_end_root(b)
    other = b.alloc(1)[0]
    b.alloc(1)
    distant = b.alloc(1)[0]
    b.set_fat(b.root_clusters[0], other)
    b.set_fat(other, distant)
    b.set_fat(distant, 0xFFFFFFFF)
    b.write_clusters([other], (b"\xa1" + bytes(31)) * (b.cs // 32))
    assert_stopped(allocation(b.image(), limits=Limits(max_runs=1)), "bitmap_runs_limit")


@pytest.mark.parametrize("reason,expected", [("time", "time_limit"), ("steps", "step_limit"),
                                           ("metadata_bytes", "metadata_bytes_limit")])
@pytest.mark.parametrize("phase", ["root", "bitmap"])
def test_root_bitmap_budget_stop_preserves_geometry(monkeypatch, reason, expected, phase):
    original = ExfatVolume._follow
    b = exfat_small()
    fail_cluster = b.root_clusters[0] if phase == "root" else b.bitmap_clusters[0]
    def follow(self, start, limit, budget=None):
        if start == fail_cluster:
            raise FsError("고정 합성 한도", reason="budget_exceeded", data={"limit": reason})
        return original(self, start, limit, budget)
    monkeypatch.setattr(ExfatVolume, "_follow", follow)
    assert_stopped(allocation(b.image()), expected)


def test_shared_budget_time_and_steps_after_geometry():
    image = exfat_small().image()
    assert_stopped(allocation(image, budget=Budget(deadline=time.monotonic() - 1)), "time_limit")
    assert_stopped(allocation(image, limits=Limits(max_follow_steps=0), budget=Budget(max_steps=0)), "step_limit")


def test_cancel_is_not_unknown_or_stopped():
    with pytest.raises(FsError) as error:
        allocation(exfat_small().image(), budget=Budget(cancel=lambda: True))
    assert error.value.reason == "budget_exceeded"
    assert error.value.data["limit"] == "cancelled"


def test_boot_budget_failure_has_no_fabricated_geometry():
    class Limited(BytesReader):
        def read_clamped(self, offset, size):
            raise FsError("고정 합성 한도", reason="budget_exceeded", data={"limit": "metadata_bytes"})
    with pytest.raises(FsError) as error:
        ExfatVolume(Limited(exfat_small().image()), metadata_mode="allocation")
    assert error.value.data["limit"] == "metadata_bytes"


def test_short_root_read_with_early_end_is_not_complete_unit():
    b = exfat_small()
    class ShortRoot(BytesReader):
        def read_clamped(self, offset, size):
            data = super().read_clamped(offset, size)
            return data[:128] if offset == b.coff(b.root_clusters[0]) else data
    vol = ExfatVolume(ShortRoot(b.image()), metadata_mode="allocation")
    assert_unknown(vol, "root_metadata_incomplete")


def test_root_metadata_byte_cap_is_caught_after_geometry():
    b = exfat_small()
    class RootCap(BytesReader):
        def read_clamped(self, offset, size):
            if offset == b.coff(b.root_clusters[0]):
                raise FsError("고정 합성 한도", reason="budget_exceeded", data={"limit": "metadata_bytes"})
            return super().read_clamped(offset, size)
    assert_stopped(ExfatVolume(RootCap(b.image()), metadata_mode="allocation"), "metadata_bytes_limit")


def test_cancel_during_root_does_not_publish_preceding_bitmap():
    b = exfat_small()
    stopped = [False]
    class CancelRoot(BytesReader):
        def read_clamped(self, offset, size):
            result = super().read_clamped(offset, size)
            if offset == b.coff(b.root_clusters[0]):
                stopped[0] = True
            return result
    with pytest.raises(FsError) as error:
        ExfatVolume(CancelRoot(b.image()), metadata_mode="allocation", budget=Budget(cancel=lambda: stopped[0]))
    assert error.value.data["limit"] == "cancelled"


def test_incomplete_file_set_does_not_hide_bitmap_uniqueness():
    b = exfat_small()
    b.add_file("/secret.txt", b"payload")
    b.dirs["/"].slots.pop()
    assert_unknown(allocation(b.image()), "root_metadata_incomplete")
