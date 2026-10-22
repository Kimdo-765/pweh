"""FAT 디렉터리 교차 연결의 합성 회귀: 파일 중간·첫 클러스터, FAT32 루트, 예산·색인 불완전성."""

from __future__ import annotations

import dataclasses

import pytest

from fs.builders import fat12_small, fat16_small, fat32_small
from pweh.fs import Budget, BytesReader, FsError, Limits, open_volume


MAKERS = [fat12_small, fat16_small, fat32_small]


def plausible_file_bytes(size: int) -> bytes:
    """엄격한 슬롯 검사도 통과하는 파일 내용. 디렉터리로 읽으면 LEAK.TXT 라는 가짜 항목이 생긴다."""
    slot = b"LEAK    TXT" + bytes([0x20]) + bytes(20)
    return (slot + bytes(512 - len(slot))) * (size // 512)


def full_first_cluster(builder, path="/DIR"):
    rec = builder.mkdir(path)
    count = builder.cs // 32 - 2
    for i in range(count):
        builder.add_file(f"{path}/F{i:03d}.TXT")
    assert len(builder.dirs[path].clusters) == 1
    assert len(builder.dirs[path].slots) * 32 == builder.cs
    return rec, count


@pytest.mark.parametrize("maker", MAKERS)
@pytest.mark.parametrize("target_index", [0, 1])
def test_directory_continuation_never_decodes_live_file_clusters(maker, target_index):
    builder = maker()
    directory, count = full_first_cluster(builder)
    # 파일의 소유 디렉터리는 손상된 디렉터리보다 뒤에 있다. 순회 순서에 기대면 첫 클러스터를 놓친다.
    builder.mkdir("/LATER")
    rec = builder.add_file("/LATER/RECORD.DAT", plausible_file_bytes(builder.cs * 3))
    builder.set_fat(directory.clusters[0], rec.clusters[target_index])
    volume = open_volume(BytesReader(builder.image()))
    listing = volume.walk()
    assert len([e for e in listing["entries"] if e["path"].startswith("/DIR/")]) == count
    assert not any("LEAK" in e["name"] for e in listing["entries"])
    cut = next(c for c in listing["unvalidated_dirs"] if c["path"] == "/DIR")
    assert cut["reason"] == "cross_linked"
    with pytest.raises(FsError) as exc:
        volume.lookup("/DIR/LEAK.TXT")
    assert exc.value.reason == "dir_unvalidated"
    with pytest.raises(FsError) as exc:
        volume.entry(f"c{directory.clusters[0]}/{builder.cs // 32}")
    assert exc.value.reason == "bad_ref"
    # 실제 파일은 바뀌지 않고, 파일 내용으로만 읽을 수 있다.
    file_entry = volume.lookup("/LATER/RECORD.DAT")
    assert volume.read_content(file_entry["ref"])["data"] == rec.data


@pytest.mark.parametrize("target_index", [0, 1])
def test_fat32_root_continuation_is_checked(target_index):
    builder = fat32_small()
    rec = builder.add_file("/RECORD.DAT", plausible_file_bytes(builder.cs * 3))
    while len(builder.dirs["/"].slots) < builder.cs // 32:
        builder.add_file(f"/F{len(builder.dirs['/'].slots):03d}.TXT")
    root = builder.dirs["/"].clusters[0]
    builder.set_fat(root, rec.clusters[target_index])
    listing = open_volume(BytesReader(builder.image())).walk()
    assert not any("LEAK" in e["name"] for e in listing["entries"])
    assert listing["unvalidated_dirs"][0]["dirspec"] == "root"
    assert listing["unvalidated_dirs"][0]["reason"] == "cross_linked"


@pytest.mark.parametrize("maker", MAKERS)
def test_fragmented_directories_and_deleted_file_heads_do_not_conflict(maker):
    builder = maker()
    stale = builder.add_file("/OLD.DAT", b"stale", clusters=[700])
    builder.delete("/OLD.DAT")
    rec = builder.mkdir("/DIR", clusters=[500, 700, 600])
    for i in range(builder.cs // 32 * 2):
        builder.add_file(f"/DIR/F{i:03d}.TXT")
    before = builder.image()
    volume = open_volume(BytesReader(before))
    listing = volume.walk()
    assert not listing["truncated"] and not listing["unvalidated_dirs"]
    assert len([e for e in listing["entries"] if e["path"].startswith("/DIR/")]) == builder.cs // 32 * 2
    assert rec.clusters[1] == stale.clusters[0]
    assert builder.image() == before


def two_cluster_volume(limits=None):
    builder = fat16_small()
    rec, count = full_first_cluster(builder)
    builder.add_file("/DIR/LAST.TXT")
    return builder, rec, count, open_volume(BytesReader(builder.image()), limits=limits)


def test_scan_cap_is_unknown_and_does_not_claim_cross_link():
    _, rec, count, volume = two_cluster_volume(Limits(max_scan_clusters=32))
    listing = volume.list_dir(f"c{rec.clusters[0]}")
    assert len(listing["entries"]) == count
    assert listing["unvalidated"]["reason"] == "cross_link_check_incomplete"
    assert listing["cross_link_check"] == {"status": "unknown", "reasons": ["max_scan_clusters"]}
    assert volume._preds_complete is False
    assert all(len(bits.buf) <= 5 for bits in volume._preds)


def test_expired_predecessor_scan_is_not_cached_as_complete():
    _, rec, count, volume = two_cluster_volume()
    spec = f"c{rec.clusters[0]}"
    listing = volume.list_dir(spec, budget=Budget(None, 160))
    assert listing["truncated"] and listing["truncated_reason"] == "steps"
    assert len(listing["entries"]) == count
    assert volume._preds_complete is False and volume._heads is None
    assert spec not in volume._dir_cache
    retry = volume.list_dir(spec)
    assert not retry["truncated"] and retry["unvalidated"] is None
    assert len(retry["entries"]) == count + 1


def test_incomplete_head_index_does_not_claim_directory_is_clean():
    builder, rec, count, _ = two_cluster_volume()
    builder.mkdir("/OUTSIDE")
    builder.mkdir("/OUTSIDE/DEEP")
    limits = dataclasses.replace(Limits(), max_depth=2)
    volume = open_volume(BytesReader(builder.image()), limits=limits)
    listing = volume.list_dir(f"c{rec.clusters[0]}")
    assert len(listing["entries"]) == count + 1
    assert listing["unvalidated"] is None
    assert listing["cross_link_check"] == {"status": "partial", "reasons": ["max_depth"]}
    assert any(w["code"] == "cross_link_check_partial" for w in listing["warnings"])
    assert volume._heads is None


def test_cancelled_reverse_scan_can_retry_with_a_new_budget():
    builder = fat32_small()
    rec, count = full_first_cluster(builder)
    builder.add_file("/DIR/LAST.TXT")
    volume = open_volume(BytesReader(builder.image()))
    budget = Budget(cancel=lambda: volume._preds is not None)
    listing = volume.list_dir(f"c{rec.clusters[0]}", budget=budget)
    assert listing["truncated"] and listing["truncated_reason"] == "cancelled"
    assert len(listing["entries"]) == count
    assert volume._preds_complete is False
    retry = volume.list_dir(f"c{rec.clusters[0]}")
    assert retry["unvalidated"] is None and len(retry["entries"]) == count + 1


def test_reverse_scan_uses_only_the_selected_fat_copy():
    builder = fat32_small(ext_flags=0x81)
    rec, count = full_first_cluster(builder)
    builder.add_file("/DIR/LAST.TXT")
    tail = builder.dirs["/DIR"].clusters[1]
    other = builder.add_file("/OTHER.DAT", b"x")
    builder.set_fat_copy(0, other.clusters[0], tail)
    # 비활성 FAT 0 에만 생긴 교차 연결 때문에 정상 활성 FAT 1 을 거부하면 안 된다.
    volume = open_volume(BytesReader(builder.image()))
    listing = volume.list_dir(f"c{rec.clusters[0]}")
    assert listing["unvalidated"] is None and len(listing["entries"]) == count + 1


def test_partial_head_index_is_reused_only_inside_the_same_budget(monkeypatch):
    builder, rec, _, _ = two_cluster_volume()
    builder.mkdir("/OUTSIDE")
    builder.mkdir("/OUTSIDE/DEEP")
    volume = open_volume(BytesReader(builder.image()), limits=Limits(max_depth=2))
    original = volume._parse_dir
    visits = []

    def counted(spec, *args, **kwargs):
        if volume._scanning_heads:
            visits.append(spec)
        return original(spec, *args, **kwargs)

    monkeypatch.setattr(volume, "_parse_dir", counted)
    budget = Budget()
    volume.list_dir(f"c{rec.clusters[0]}", budget=budget)
    count = len(visits)
    assert count > 0 and volume._heads is None
    volume._directory_heads(budget)
    assert len(visits) == count
    volume._directory_heads(Budget())
    assert len(visits) > count
