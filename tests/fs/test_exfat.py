"""pweh.fs.exfat: 부트 체크섬, 목록(이름·크기·속성·시각+UtcOffset), 삭제 집합 복구(NoFatChain·남은 체인),
ValidDataLength 자르기 + residual, 집합 체크섬, 고아 조각, 볼륨 점검."""

from __future__ import annotations

import datetime as dt
import struct

import pytest

from fs.builders import ExfatBuilder, exfat_set_checksum, exfat_small, pattern
from pweh.fs import BytesReader, ExfatVolume, FsError, ImageReader, open_volume

T_C = dt.datetime(2026, 3, 14, 15, 9, 27, 530000)
T_M = dt.datetime(2026, 3, 14, 16, 0, 0, 120000)
T_A = dt.datetime(2026, 3, 15, 1, 2, 4)


def vol_of(img: bytes) -> ExfatVolume:
    return ExfatVolume(BytesReader(img))


def by_path(walk: dict) -> dict[str, dict]:
    return {e["path"]: e for e in walk["entries"]}


def wcodes(res) -> list[str]:
    return [w["code"] for w in res["warnings"]]


def test_listing_times_offsets_attributes(tmp_path):
    b = exfat_small(label="CAMEXFAT")
    b.mkdir("/DCIM", nclusters=2)
    clip = pattern(10_000, 1)
    b.add_file("/DCIM/rec 0001 with a long name.mp4", clip, ctime=T_C, mtime=T_M, atime=T_A,
               offsets=(540, 540, -300))
    b.add_file("/README.TXT", b"readme", attrs=0x21)
    b.add_file("/카메라.ini", b"k=v", attrs=0x22)
    p = tmp_path / "ex.img"
    p.write_bytes(b.image())
    with ImageReader(p) as r:
        v = ExfatVolume(r)
        info = v.info()
        assert info["fs_type"] == "exfat" and info["volume_label"] == "CAMEXFAT"
        assert info["boot_region"]["main"]["checksum_ok"] and info["boot_region"]["backup_matches_main"]
        assert info["bitmap"]["present"] and info["upcase"]["checksum_ok"] is True
        assert info["volume_serial"] == "C0FF-EE11" and info["fs_revision"] == "1.00"
        assert info["warnings"] == [] and info["state"]["dirty"] is False
        w = v.walk()
        assert w["warnings"] == [] and w["orphans"] == []
        e = by_path(w)
        c = e["/DCIM/rec 0001 with a long name.mp4"]
        assert c["size"] == 10_000 and c["valid_data_length"] == 10_000 and c["residual_bytes"] == 0
        assert c["set_checksum_ok"] and c["name_hash_ok"] and c["name_status"] == "ok" and c["no_fat_chain"]
        assert c["attributes"] == {"raw": 0x20, "flags": ["archive"]}
        cr, mo, ac = c["times"]["created"], c["times"]["modified"], c["times"]["accessed"]
        assert cr["iso"] == "2026-03-14T15:09:27.53" and cr["time_basis"] == "local+offset"
        assert cr["utc_offset_minutes"] == 540 and cr["utc"] == "2026-03-14T06:09:27.53Z"
        assert mo["iso"] == "2026-03-14T16:00:00.12" and mo["utc"] == "2026-03-14T07:00:00.12Z"
        assert ac["iso"] == "2026-03-15T01:02:04" and ac["utc"] == "2026-03-15T06:02:04Z"
        assert ac["utc_offset_minutes"] == -300 and "ms10" not in ac["raw"]
        rd = e["/README.TXT"]
        assert rd["attributes"]["flags"] == ["readonly", "archive"]
        assert rd["times"]["created"]["time_basis"] == "local-unknown-tz" and rd["times"]["created"]["utc"] is None
        assert e["/카메라.ini"]["attributes"]["flags"] == ["hidden", "archive"]
        assert e["/DCIM"]["is_dir"] and e["/DCIM"]["child_dir"].startswith("n")
        assert v.read_content(c["ref"])["data"] == clip
        assert v.lookup("/dcim/REC 0001 WITH A LONG NAME.MP4")["ref"] == c["ref"]
        assert v.entry(c["ref"])["name"] == c["name"]


def test_boot_checksum_mismatch_and_dirty_flag():
    b = exfat_small(volume_flags=0x02)  # VolumeDirty — 체크섬에서 빠지는 바이트라 체크섬은 맞아야 한다
    b.add_file("/a.bin", b"a")
    img = bytearray(b.image())
    v = vol_of(bytes(img))
    info = v.info()
    assert info["boot_region"]["main"]["checksum_ok"] is True
    assert info["volume_flags"]["volume_dirty"] is True and info["state"]["dirty"] is True
    img[300] ^= 0xFF  # 주 부트 섹터의 부트 코드 한 바이트 (체크섬 다시 계산 안 함)
    v2 = vol_of(bytes(img))
    info2 = v2.info()
    assert info2["boot_region"]["main"]["checksum_ok"] is False
    assert info2["boot_region"]["backup"]["checksum_ok"] is True
    c = wcodes(info2)
    assert "boot_checksum_mismatch" in c and "backup_boot_differs" in c
    assert v2.lookup("/a.bin") is not None  # 해석은 계속된다


def test_deleted_nofatchain_exact():
    b = exfat_small()
    b.mkdir("/DCIM", nclusters=1)
    data = pattern(5 * 4096 - 17, 2)
    rec = b.add_file("/DCIM/clip_0007.mp4", data)
    b.delete("/DCIM/clip_0007.mp4")
    v = vol_of(b.image())
    w = v.walk()
    e = by_path(w)["/DCIM/clip_0007.mp4"]
    assert e["deleted"] and e["no_fat_chain"] and e["set_checksum_ok"] is True
    assert e["allocation_now"] == {"status": "free", "checked_clusters": 5, "allocated_now": 0}
    cands = v.candidates(e["ref"])
    assert len(cands) == 1 and cands[0]["method"] == "contiguous" and cands[0]["confidence"] == "high"
    assert cands[0]["runs"] == [[rec.clusters[0], 5]]
    assert v.read_content(e["ref"])["data"] == data


def test_deleted_chained_fragmented_stale_chain_exact():
    b = exfat_small()
    b.mkdir("/DCIM", nclusters=1)
    base = max(b.used) + 1
    b.add_file("/DCIM/g1.bin", pattern(4096, 90), clusters=[base + 1])
    b.add_file("/DCIM/g2.bin", pattern(4096, 91), clusters=[base + 3])
    data = pattern(3 * 4096 - 5, 3)
    b.add_file("/DCIM/frag.mp4", data, contiguous=False, clusters=[base, base + 2, base + 4])
    b.delete("/DCIM/frag.mp4")
    v = vol_of(b.image())
    e = by_path(v.walk())["/DCIM/frag.mp4"]
    assert not e["no_fat_chain"] and e["allocation_now"]["status"] == "free"
    cands = v.candidates(e["ref"])
    assert cands[0]["method"] == "stale-chain" and cands[0]["confidence"] == "high"
    assert cands[0]["runs"] == [[base, 1], [base + 2, 1], [base + 4, 1]]
    others = {c["method"]: c for c in cands[1:]}
    assert others["contiguous"]["confidence"] == "low" and others["skip-allocated"]["confidence"] == "low"
    assert v.read_content(e["ref"])["data"] == data
    assert v.read_content(e["ref"], method="contiguous")["data"] != data


def test_deleted_chain_with_reused_cluster_is_low_confidence():
    b = exfat_small()
    base = max(b.used) + 1
    data = pattern(3 * 4096, 4)
    b.add_file("/frag.mp4", data, contiguous=False, clusters=[base, base + 2, base + 4])
    b.delete("/frag.mp4")
    b.add_file("/new.bin", pattern(4096, 5), clusters=[base + 2])  # 지운 파일의 클러스터를 새 파일이 다시 씀
    v = vol_of(b.image())
    e = next(x for x in v.list_dir()["entries"] if x["deleted"])
    assert e["allocation_now"]["status"] == "partially_reused" and e["allocation_now"]["allocated_now"] == 1
    c = v.candidates(e["ref"])[0]
    assert c["method"] == "stale-chain" and c["confidence"] == "low" and c["conflicts"]["allocated"] == 1


def test_valid_data_length_truncation_and_residual():
    b = exfat_small()
    head = pattern(5000, 6)
    old = pattern(7000, 7)
    b.add_file("/pre.mp4", head, residual=old)
    b.add_file("/pool.dat", b"", residual=pattern(3 * 4096, 8))  # VDL 0: 미리 할당된 녹화 풀
    v = vol_of(b.image())
    e = v.lookup("/pre.mp4")
    assert e["size"] == 12_000 and e["valid_data_length"] == 5000 and e["residual_bytes"] == 7000
    r = v.read_content(e["ref"])
    assert r["data"] == head and r["plan"]["region"] == "data" and r["plan"]["size"] == 5000
    rr = v.read_content(e["ref"], region="residual")
    assert rr["data"] == old and rr["plan"]["skip"] == 5000
    pool = v.lookup("/pool.dat")
    d = v.candidates(pool["ref"])[0]
    assert d["method"] == "empty" and "residual" in d["note"]
    assert v.read_content(pool["ref"], region="residual")["data"] == pattern(3 * 4096, 8)
    b.delete("/pre.mp4")
    v2 = vol_of(b.image())
    de = next(x for x in v2.list_dir()["entries"] if x["deleted"])
    assert v2.read_content(de["ref"])["data"] == head
    assert v2.read_content(de["ref"], region="residual")["data"] == old


def test_name_hash_mismatch_is_a_warning_but_set_checksum_mismatch_stops_the_cluster():
    b = exfat_small()
    b.mkdir("/D", nclusters=1)
    b.add_file("/D/a.bin", b"a")
    rec = b.add_file("/D/clip.mp4", b"abc")
    b.add_file("/D/z.bin", b"z")
    d = b.dirs["/D"]
    raws = [bytearray(d.slots[s]) for s in rec.slots]
    raws[2][2] = ord("C")  # 'c' → 'C': up-case 뒤 NameHash 는 같다
    struct.pack_into("<H", raws[0], 2, exfat_set_checksum([bytes(r) for r in raws]))  # SetChecksum 은 다시 맞춘다
    for s, r in zip(rec.slots, raws):
        d.slots[s] = bytes(r)
    v = vol_of(b.image())
    e = by_path(v.walk())["/D/Clip.mp4"]
    assert e["set_checksum_ok"] is True and e["name_hash_ok"] is True
    raws[2][4] = ord("X")  # 둘째 글자 'l' → 'X', 체크섬도 맞춤 → NameHash 만 틀림: 목록에 남고 경고
    struct.pack_into("<H", raws[0], 2, exfat_set_checksum([bytes(r) for r in raws]))
    for s, r in zip(rec.slots, raws):
        d.slots[s] = bytes(r)
    w = vol_of(b.image()).walk()
    e = by_path(w)["/D/CXip.mp4"]
    assert e["name_hash_ok"] is False and "name_hash_mismatch" in {x["code"] for x in e["warnings"]}
    assert w["unvalidated_dirs"] == []
    # 완전한 집합의 SetChecksum 이 틀림 → 그 클러스터부터 디렉터리 데이터로 검증되지 않음: 같은 클러스터의 다른 항목도 내보내지 않는다
    raws[2][6] = ord("Q")  # 셋째 글자를 바꾸고 SetChecksum 은 그대로
    for s, r in zip(rec.slots, raws):
        d.slots[s] = bytes(r)
    v = vol_of(b.image())
    w = v.walk()
    paths = set(by_path(w))
    assert "/D" in paths and not any(p.startswith("/D/") for p in paths)  # 디렉터리 자체는 목록에 남는다
    child = by_path(w)["/D"]["child_dir"]
    assert w["unvalidated_dirs"] == [{"dirspec": child, "path": "/D", "reason": "set_checksum", "slots_skipped": b.cs // 32}]
    assert "dir_unvalidated" in wcodes(w)
    lst = v.list_dir(child)
    assert lst["entries"] == [] and lst["unvalidated"]["reason"] == "set_checksum"
    with pytest.raises(FsError) as ei:
        v.entry(f"{child}/{rec.slots[0]}")
    assert ei.value.data["reason"] == "bad_ref" and ei.value.data["unvalidated"] is True


def test_partially_overwritten_deleted_set_leaves_orphan_fragment():
    b = exfat_small()
    long = "recording-2026-03-14-150926-ch01.mp4"  # 이름 항목 3개 → 집합 5 슬롯
    x = b.add_file("/" + long, pattern(4096, 9))
    b.delete("/" + long)
    y = b.file_set("y.bin", attrs=0x20, first_cluster=0, data_length=0, valid_data_length=0, no_fat_chain=False,
                   ctime=T_C, mtime=T_C, atime=T_C)
    assert len(y) == 3
    for i, raw in enumerate(y):
        b.put_slot("/", x.slots[i], raw)
    v = vol_of(b.image())
    lst = v.list_dir()
    names = {e["name"]: e for e in lst["entries"]}
    assert "y.bin" in names and not names["y.bin"]["deleted"]
    frag = [o for o in lst["orphans"] if o.get("partial_name")]
    assert frag and frag[0]["deleted"] and frag[0]["partial_name"] in long and frag[0]["slot"] == x.slots[3]


def test_deleted_set_missing_stream_reported():
    b = exfat_small()
    x = b.add_file("/somefile.bin", pattern(100, 1))
    b.delete("/somefile.bin")
    d = b.dirs["/"]
    d.slots[x.slots[1]] = b"\x01" + bytes(31)  # 스트림 항목이 덮어써짐
    v = vol_of(b.image())
    lst = v.list_dir()
    e = next(e for e in lst["entries"] if e["deleted"])
    assert not e["set_complete"] and e["set_checksum_ok"] is None
    assert {w["code"] for w in e["warnings"]} >= {"stream_missing", "set_incomplete"}
    assert v.candidates(e["ref"])[0]["method"] == "empty"


def test_set_straddles_non_adjacent_directory_clusters():
    b = ExfatBuilder(total_sectors=8192, sectors_per_cluster=1)  # 512 바이트 클러스터 = 16 슬롯
    base = max(b.used) + 1
    b.mkdir("/D", clusters=[base, base + 5], contiguous=False)
    long = "a-name-needing-three-entries-x.bin"
    for i in range(3):
        b.add_file(f"/D/{i}-" + long, b"x")  # 각 5 슬롯 → 15 슬롯
    data = pattern(1500, 3)
    rec = b.add_file("/D/straddle-" + long, data)
    assert rec.slots[0] == 15 and rec.slots[-1] > 15
    v = vol_of(b.image())
    w = v.walk()
    e = by_path(w)["/D/straddle-" + long]
    assert e["set_checksum_ok"] and e["name_status"] == "ok" and e["ref"].startswith(f"c{base}+")
    assert v.read_content(e["ref"])["data"] == data
    assert w["warnings"] == []


def test_deleted_directory_walk():
    b = exfat_small()
    b.mkdir("/old", nclusters=1)
    data = pattern(2222, 4)
    b.add_file("/old/inside.bin", data)
    b.delete("/old/inside.bin")
    b.delete("/old")
    v = vol_of(b.image())
    e = by_path(v.walk())
    assert e["/old"]["deleted"] and e["/old/inside.bin"]["parent_deleted"]
    assert v.read_content(e["/old/inside.bin"]["ref"])["data"] == data


def test_cluster_report_unreferenced_and_unallocated():
    b = exfat_small(volume_flags=0x02)
    b.add_file("/ok.bin", pattern(4096, 1))
    lost = [max(b.used) + 3, max(b.used) + 4]
    b.reserve(lost)  # 비트맵에는 할당, 가리키는 항목 없음 (기록 중 분리)
    gone = b.add_file("/gone.bin", pattern(4096, 2))
    b.used.discard(gone.clusters[0])  # 항목은 있는데 비트맵은 비어 있음
    v = vol_of(b.image())
    rep = v.cluster_report()
    assert rep["scanned"] and rep["allocated_unreferenced"] == 2
    assert rep["allocated_unreferenced_runs"] == [[lost[0], 2]]
    assert rep["unallocated_referenced"] == 1 and rep["unallocated_referenced_samples"][0]["cluster"] == gone.clusters[0]
    assert rep["state"]["dirty"] is True and rep["cross_linked"] == 0


def test_exfat_4k_sectors_and_texfat_active_fat():
    b = ExfatBuilder(total_sectors=4096, bytes_per_sector=4096, sectors_per_cluster=1)
    data = pattern(9000, 5)
    b.add_file("/big sector.bin", data)
    v = vol_of(b.image())
    info = v.info()
    assert info["bytes_per_sector"] == 4096 and info["boot_region"]["main"]["checksum_ok"]
    assert v.read_content(v.lookup("/big sector.bin")["ref"])["data"] == data
    b2 = exfat_small(number_of_fats=2, volume_flags=0x01)
    b2.add_file("/t.bin", b"t")
    v2 = vol_of(b2.image())
    assert v2.info()["volume_flags"]["active_fat"] == 1
    assert "bitmap_active_mismatch" in wcodes(v2.info())
    assert v2.read_content(v2.lookup("/t.bin")["ref"])["data"] == b"t"


def test_upcase_checksum_mismatch_and_bad_refs():
    b = exfat_small()
    b.add_file("/x.bin", b"x")
    img = bytearray(b.image())
    up_off = b.coff(b.upcase_clusters[0])
    img[up_off + 10] ^= 0x01
    v = vol_of(bytes(img))
    assert "upcase_checksum_mismatch" in wcodes(v.info())
    for ref in ("root/x", "c0/1", "c1+10/0", "n5/0", "n5+0/0", "c99999999/0", "root/999999999"):
        with pytest.raises(FsError) as ei:
            v.entry(ref)
        assert ei.value.data["reason"] == "bad_ref", ref
    with pytest.raises(FsError):
        v.entry("root/0")  # 레이블 슬롯


def test_not_exfat_and_open_volume_dispatch():
    with pytest.raises(FsError) as ei:
        vol_of(bytes(4096))
    assert ei.value.data["reason"] == "not_exfat"
    img = bytearray(exfat_small().image())
    assert open_volume(BytesReader(bytes(img))).kind == "exfat"
    img[108] = 20  # BytesPerSectorShift
    with pytest.raises(FsError) as ei:
        vol_of(bytes(img))
    assert ei.value.data["reason"] == "not_exfat"
    img[108] = 9
    struct.pack_into("<I", img, 92, 0)  # ClusterCount 0
    with pytest.raises(FsError):
        vol_of(bytes(img))
