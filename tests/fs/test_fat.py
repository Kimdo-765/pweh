"""pweh.fs.fat: 목록(이름·크기·시각·속성), LFN, 삭제 파일 복구 후보, 상태 비트, 볼륨 점검, 손상 처리."""

from __future__ import annotations

import datetime as dt
import struct

import pytest

from fs.builders import (
    FatBuilder,
    fat12_small,
    fat16_small,
    fat32_small,
    lfn_checksum,
    pattern,
    sfn11,
)
from pweh.fs import BytesReader, FatVolume, FsError, ImageReader, Limits, SliceReader

MAKERS = {"fat12": fat12_small, "fat16": fat16_small, "fat32": fat32_small}


def vol_of(img: bytes, **kw) -> FatVolume:
    return FatVolume(BytesReader(img), **kw)


def by_path(walk: dict) -> dict[str, dict]:
    return {e["path"]: e for e in walk["entries"]}


def wcodes(res) -> list[str]:
    return [w["code"] for w in res["warnings"]]


# ---------------------------------------------------------------------------
# 목록
# ---------------------------------------------------------------------------

T_CREATE = dt.datetime(2025, 12, 31, 23, 59, 58, 990000)
T_CREATE_ODD = dt.datetime(2026, 3, 14, 15, 9, 27, 530000)
T_MODIFY = dt.datetime(2026, 1, 2, 3, 4, 6)
A_DATE = dt.date(2026, 1, 3)


@pytest.mark.parametrize("fat", ["fat12", "fat16", "fat32"])
def test_listing_names_sizes_times_attributes(tmp_path, fat):
    b = MAKERS[fat](label="CAMSD")
    b.mkdir("/DCIM", ctime=T_CREATE, mtime=T_MODIFY, adate=A_DATE)
    clip = pattern(5000, 1)
    b.add_file("/DCIM/Clip Long Name 0001.mp4", clip, ctime=T_CREATE, mtime=T_MODIFY, adate=A_DATE)
    b.add_file("/DCIM/odd.dat", b"odd", ctime=T_CREATE_ODD, mtime=T_CREATE_ODD, adate=None)
    b.add_file("/README.TXT", b"read me", attr=0x21)
    b.add_file("/lower.txt", b"lc", short="LOWER.TXT", lfn=False, nt_case=0x18)
    b.add_file("/HIDDEN.SYS", b"", attr=0x27)
    b.add_file("/카메라 설정.ini", b"k=v")
    path = tmp_path / f"{fat}.img"
    path.write_bytes(b.image())
    with ImageReader(path) as r:
        v = FatVolume(r)
        info = v.info()
        assert info["fs_type"] == fat and info["cluster_count"] == b.count
        assert info["volume_label"] == "CAMSD" and info["volume_label_root"] == "CAMSD"
        assert info["volume_id"] == "1234-ABCD" and info["warnings"] == []
        w = v.walk()
        assert w["warnings"] == [] and not w["truncated"] and w["orphans"] == []
        assert w["stats"] == {"files": 6, "dirs": 1, "deleted_files": 0, "deleted_dirs": 0, "orphans": 0, "dirs_read": 2}
        e = by_path(w)
        c = e["/DCIM/Clip Long Name 0001.mp4"]
        assert c["size"] == 5000 and c["lfn_status"] == "ok" and c["name_source"] == "lfn"
        assert c["short_name"] == "CLIPLO~1.MP4" and not c["deleted"] and not c["is_dir"]
        assert c["attributes"] == {"raw": 0x20, "flags": ["archive"]}
        assert c["times"]["created"]["iso"] == "2025-12-31T23:59:58.99"
        assert c["times"]["created"]["time_basis"] == "local-unknown-tz"
        assert c["times"]["modified"]["iso"] == "2026-01-02T03:04:06"
        assert c["times"]["accessed"] == {"raw": {"date": ((2026 - 1980) << 9) | (1 << 5) | 3}, "iso": "2026-01-03",
                                          "valid": True, "time_basis": "local-unknown-tz", "date_only": True}
        assert c["chain"]["status"] == "ok" and c["chain"]["size_check"] == "ok"
        odd = e["/DCIM/odd.dat"]
        assert odd["times"]["created"]["iso"] == "2026-03-14T15:09:27.53"
        assert odd["times"]["accessed"]["unset"] is True
        assert e["/README.TXT"]["attributes"]["flags"] == ["readonly", "archive"]
        assert e["/README.TXT"]["lfn_status"] == "none" and e["/README.TXT"]["name"] == "README.TXT"
        assert e["/lower.txt"]["name"] == "lower.txt" and e["/lower.txt"]["short_name"] == "lower.txt"
        assert e["/HIDDEN.SYS"]["attributes"]["flags"] == ["readonly", "hidden", "system", "archive"]
        assert e["/HIDDEN.SYS"]["size"] == 0 and e["/HIDDEN.SYS"]["chain"]["status"] == "empty"
        assert "/카메라 설정.ini" in e and e["/카메라 설정.ini"]["display_name"] == "카메라 설정.ini"
        assert e["/DCIM"]["is_dir"] and e["/DCIM"]["chain"]["status"] == "ok"
        # 내용·참조
        assert v.read_content(c["ref"])["data"] == clip
        again = v.entry(c["ref"])
        assert again["name"] == c["name"] and again["offset"] == c["offset"]
        assert c["image_offset"] == c["offset"]  # superfloppy: 볼륨 = 이미지
        assert v.lookup("/dcim/clip long name 0001.MP4")["ref"] == c["ref"]
        assert v.lookup("/DCIM/CLIPLO~1.MP4")["ref"] == c["ref"]
        assert v.lookup("/DCIM/nothing") is None
        lst = v.list_dir("/".join(["root", str(e["/DCIM"]["slot"])]))
        assert {x["name"] for x in lst["entries"]} == {"Clip Long Name 0001.mp4", "odd.dat"}
        assert lst["dot_entries"]["."]["cluster"] == e["/DCIM"]["first_cluster"]
        assert v.list_dir(e["/DCIM"]["child_dir"])["entries_total"] == 2


def test_streaming_read_and_max_bytes():
    b = fat16_small()
    data = pattern(10_000, 3)
    rec = b.add_file("/BIG.BIN", data)
    v = vol_of(b.image())
    ref = v.lookup("/BIG.BIN")["ref"]
    assert b"".join(v.iter_content(ref)) == data
    assert b"".join(v.iter_content(ref, max_bytes=1234)) == data[:1234]
    r = v.read_content(ref, max_bytes=100)
    assert r["data"] == data[:100] and r["truncated"] is True
    plan = v.content_plan(ref)
    d = plan.to_dict()
    assert d["method"] == "chain" and d["complete"] and d["runs"] == [[rec.clusters[0], len(rec.clusters)]]
    assert d["extents"][0]["image_offset"] == b.coff(rec.clusters[0])
    with pytest.raises(FsError):
        v.content_plan(ref, method="contiguous")
    with pytest.raises(FsError):
        v.content_plan(ref, region="residual")


def test_lfn_straddles_non_adjacent_directory_clusters():
    b = fat32_small()
    b.mkdir("/D", clusters=[200, 300])
    for i in range(13):  # '.' '..' + 13 = 15 슬롯
        b.add_file(f"/D/F{i:02d}.BIN", b"x")
    long = "straddling-name-over-boundary.mp4"  # LFN 3 슬롯 + SFN → 슬롯 15..18
    rec = b.add_file("/D/" + long, pattern(700, 5))
    assert rec.slots[0] == 15 and rec.slots[-1] == 18
    v = vol_of(b.image())
    w = v.walk()
    e = by_path(w)["/D/" + long]
    assert e["lfn_status"] == "ok" and e["slot"] == 18
    assert e["ref"] == "c200/18"
    assert v.read_content(e["ref"])["data"] == pattern(700, 5)
    assert w["warnings"] == []


def test_lfn_checksum_mismatch_and_broken_sequence():
    b = fat16_small()
    rec = b.add_file("/A long file name.txt", b"aaa")
    rec2 = b.add_file("/Second long name here.txt", b"bbb")
    d = b.dirs["/"]
    for s in rec.slots[:-1]:  # 순서는 맞지만 체크섬이 다른 LFN
        raw = bytearray(d.slots[s])
        raw[13] ^= 0x5A
        d.slots[s] = bytes(raw)
    raw = bytearray(d.slots[rec2.slots[0]])  # 두 번째 파일: 첫(가장 큰 ordinal) 슬롯만 체크섬 깨기
    raw[13] ^= 0x01
    d.slots[rec2.slots[0]] = bytes(raw)
    v = vol_of(b.image())
    lst = v.list_dir()
    e = {x["short_name"]: x for x in lst["entries"]}
    a = e[rec.short]
    assert a["lfn_status"] == "checksum_mismatch" and a["name"] == rec.short
    assert a["long_name_unverified"] == "A long file name.txt"
    s2 = e[rec2.short]
    assert s2["lfn_status"] == "none"  # 순서가 깨진 LFN 은 고아로 보고되고 SFN 이름을 쓴다
    assert s2["name"] == rec2.short
    reasons = {o["reason"] for o in lst["orphans"]}
    assert "checksum_mismatch" in reasons and "sequence_broken" in reasons
    assert any(o["partial_name"] == "A long file name.txt" for o in lst["orphans"])


# ---------------------------------------------------------------------------
# 삭제 파일
# ---------------------------------------------------------------------------

def test_deleted_contiguous_exact_and_name_recovery():
    b = fat16_small()
    b.mkdir("/DCIM")
    data = pattern(5 * 1024 + 100, 7)
    rec = b.add_file("/DCIM/rec_0001.mp4", data)
    b.delete("/DCIM/rec_0001.mp4")
    v = vol_of(b.image())
    w = v.walk()
    e = by_path(w)["/DCIM/rec_0001.mp4"]
    assert e["deleted"] and e["lfn_status"] == "recovered"
    assert e["first_char"] == {"known": True, "source": "lfn_checksum", "confidence": "high", "value": "R"}
    assert e["short_name"] == rec.short and e["size"] == len(data) and e["first_cluster"] == rec.clusters[0]
    assert w["stats"]["deleted_files"] == 1
    cands = v.candidates(e["ref"])
    assert [c["method"] for c in cands[:2]] == ["contiguous", "skip-allocated"]
    assert cands[0]["confidence"] == "medium" and cands[0]["conflicts"] == {"allocated": 0, "claimed": 0}
    assert cands[1]["same_as"] == "contiguous"
    assert v.read_content(e["ref"])["data"] == data
    assert v.read_content(e["ref"], method="skip-allocated")["data"] == data


def test_deleted_fragmented_gap_still_allocated_skip_allocated_exact():
    b = fat16_small()
    data_b = pattern(7 * 1024, 11)
    data_a = pattern(6 * 1024, 12)
    b.add_file("/B.BIN", data_b, clusters=list(range(103, 110)))
    b.add_file("/A.MP4", data_a, clusters=[100, 101, 102, 110, 111, 112])
    b.delete("/A.MP4")
    v = vol_of(b.image())
    e = v.lookup("/B.BIN")
    assert e is not None
    a = next(x for x in v.list_dir()["entries"] if x["deleted"])
    cands = {c["method"]: c for c in v.candidates(a["ref"])}
    first = v.candidates(a["ref"])[0]
    assert first["method"] == "skip-allocated" and first["confidence"] == "medium"
    assert first["runs"] == [[100, 3], [110, 3]] and first["conflicts"]["skipped_allocated"] == 7
    assert cands["contiguous"]["confidence"] == "low" and cands["contiguous"]["conflicts"]["allocated"] == 3
    assert "할당" in cands["contiguous"]["note"]
    assert v.read_content(a["ref"])["data"] == data_a
    assert v.read_content(a["ref"], method="contiguous")["data"] != data_a


def test_deleted_fragmented_gap_unallocated_candidates_explained():
    b = fat16_small()
    data_b = pattern(7 * 1024, 21)
    data_a = pattern(6 * 1024, 22)
    b.add_file("/B.BIN", data_b, clusters=list(range(103, 110)))
    b.add_file("/A.MP4", data_a, clusters=[100, 101, 102, 110, 111, 112])
    b.delete("/A.MP4")
    b.delete("/B.BIN")
    v = vol_of(b.image())
    dels = {x["first_cluster"]: x for x in v.list_dir()["entries"] if x["deleted"]}
    a, bb = dels[100], dels[103]
    assert a["first_char"]["known"] is False and a["name"] == "_.MP4"
    cands = v.candidates(a["ref"])
    by = {c["method"]: c for c in cands}
    # 연속 가정은 틀렸다: 다른 삭제 항목(B)의 범위와 겹친다고 설명하고 신뢰도를 낮춘다
    assert by["contiguous"]["confidence"] == "low" and by["contiguous"]["conflicts"]["claimed"] == 3
    assert "다른 삭제 항목" in by["contiguous"]["note"]
    assert by["skip-allocated"]["same_as"] == "contiguous" and by["skip-allocated"]["confidence"] == "low"
    assert v.read_content(a["ref"], method="contiguous")["data"] != data_a
    # 다른 삭제 항목의 구간을 건너뛰는 후보가 맨 앞이고 정확하다
    assert cands[0]["method"] == "skip-claimed" and cands[0]["confidence"] == "medium"
    assert cands[0]["runs"] == [[100, 3], [110, 3]]
    assert v.read_content(a["ref"])["data"] == data_a
    # B 쪽은 A 의 연속 가정에 깎이지 않는다(A 의 구간은 B 의 시작에서 잘림)
    cb = v.candidates(bb["ref"])
    assert cb[0]["method"] == "contiguous" and cb[0]["confidence"] == "medium"
    assert v.read_content(bb["ref"])["data"] == data_b


def test_deleted_fragmented_gap_unknown_is_a_documented_limit():
    b = fat16_small()
    data_a = pattern(6 * 1024, 31)
    b.add_file("/B.BIN", pattern(7 * 1024, 30), clusters=list(range(103, 110)))
    b.add_file("/A.MP4", data_a, clusters=[100, 101, 102, 110, 111, 112])
    b.delete("/A.MP4")
    rec_b = b.delete("/B.BIN")
    # B 의 디렉터리 항목이 새 파일로 덮어써져 흔적이 없다
    b.put_slot("/", rec_b.slots[-1], b.dirs["/"].slots[rec_b.slots[-1]][:0] + sfn11("NEW.TXT") + bytes([0x20]) + bytes(20))
    v = vol_of(b.image())
    a = next(x for x in v.list_dir()["entries"] if x["deleted"] and x["short_name"].endswith(".MP4"))
    cands = v.candidates(a["ref"])
    assert [c["method"] for c in cands] == ["contiguous", "skip-allocated"]
    assert cands[0]["confidence"] == "medium" and "단편화 여부는 알 수 없" in cands[0]["note"]
    assert v.read_content(a["ref"])["data"] != data_a  # FAT 만으로는 알 수 없는 경우 (한계)


def test_deleted_83_only_first_char_unknown():
    b = fat12_small()
    data = pattern(3000, 41)
    b.add_file("/NOLFN.TXT", data)
    b.delete("/NOLFN.TXT")
    v = vol_of(b.image())
    e = next(x for x in v.list_dir()["entries"] if x["deleted"])
    assert e["name"] == "_OLFN.TXT" and e["lfn_status"] == "none"
    assert e["first_char"] == {"known": False, "source": "unknown", "confidence": "none"}
    assert e["short_name_raw"] == ("e5" + sfn11("NOLFN.TXT")[1:].hex())
    assert v.read_content(e["ref"])["data"] == data


def test_deleted_sfn_after_stale_lfn_of_another_entry_is_not_associated():
    b = fat16_small()
    x = b.add_file("/xylophone recording.mp4", pattern(2000, 50))
    b.delete("/xylophone recording.mp4")
    y_name = sfn11("QZ.BIN")
    # 전제: X 의 LFN 체크섬을 거꾸로 푼 첫 바이트가 Y 에 그럴듯하게 맞지 않는다
    target = lfn_checksum(x.sfn)
    b0 = next(v for v in range(256) if lfn_checksum(bytes([v]) + y_name[1:]) == target)
    assert b0 != ord("X")
    d = b.dirs["/"]
    sfn_slot = x.slots[-1]
    raw = bytearray(d.slots[sfn_slot])
    raw[0:11] = b"\xe5" + y_name[1:]
    d.slots[sfn_slot] = bytes(raw)
    v = vol_of(b.image())
    lst = v.list_dir()
    e = next(x for x in lst["entries"] if x["deleted"])
    assert e["lfn_status"] == "unassociated" and e["first_char"]["known"] is False
    assert e["name"] == "_Z.BIN"
    assert any(o["partial_name"] == "xylophone recording.mp4" and o["deleted"] for o in lst["orphans"])


def test_deleted_directory_is_walked():
    b = fat32_small()
    b.mkdir("/old recordings")
    data = pattern(1500, 60)
    b.add_file("/old recordings/inner file.bin", data)
    b.delete("/old recordings/inner file.bin")
    b.delete("/old recordings")
    v = vol_of(b.image())
    w = v.walk()
    e = by_path(w)
    assert e["/old recordings"]["deleted"] and e["/old recordings"]["is_dir"]
    inner = e["/old recordings/inner file.bin"]
    assert inner["deleted"] and inner["parent_deleted"] and inner["lfn_status"] == "recovered"
    assert inner["ref"].startswith("n") and v.read_content(inner["ref"])["data"] == data
    assert w["stats"]["deleted_dirs"] == 1 and w["stats"]["deleted_files"] == 1
    assert not v.walk(include_deleted=False)["entries"]


def test_deleted_directory_cluster_reused_is_skipped():
    b = fat32_small()
    old = b.mkdir("/old dir")
    b.add_file("/old dir/a file.bin", b"a")
    b.delete("/old dir/a file.bin")
    b.delete("/old dir")
    b.add_file("/NEW.BIN", pattern(400, 1), clusters=[old.clusters[0]])
    v = vol_of(b.image())
    w = v.walk()
    assert "deleted_dir_reused" in wcodes(w)
    assert "/old dir" in by_path(w) and "/old dir/a file.bin" not in by_path(w)


def test_fat_chain_candidate_when_fat_not_cleared():
    b = fat16_small()
    data = pattern(3000, 70)
    rec = b.add_file("/KEEP.BIN", data, clusters=[400, 402, 404])
    d = b.dirs["/"]
    s = rec.slots[-1]
    d.slots[s] = b"\xe5" + d.slots[s][1:]  # 항목만 지우고 FAT 은 그대로 (일부 임베디드 구현)
    b.files.pop("/KEEP.BIN")
    v = vol_of(b.image())
    e = next(x for x in v.list_dir()["entries"] if x["deleted"])
    cands = {c["method"]: c for c in v.candidates(e["ref"])}
    assert cands["fat-chain"]["confidence"] == "medium" and cands["fat-chain"]["runs"] == [[400, 1], [402, 1], [404, 1]]
    assert v.read_content(e["ref"], method="fat-chain")["data"] == data


# ---------------------------------------------------------------------------
# 상태 비트·FSInfo·백업
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("fat", ["fat16", "fat32"])
def test_fat1_dirty_and_error_bits(fat):
    b = MAKERS[fat]()
    st = vol_of(b.image()).info()["state"]
    assert st["clean_shutdown"] is True and st["hard_error"] is False and st["dirty"] is False
    b.set_dirty(fat1_clean=False)
    st = vol_of(b.image()).info()["state"]
    assert st["clean_shutdown"] is False and st["dirty"] is True and st["hard_error"] is False
    b.set_dirty(fat1_clean=True, fat1_no_error=False)
    st = vol_of(b.image()).info()["state"]
    assert st["clean_shutdown"] is True and st["hard_error"] is True and st["dirty"] is False
    b.set_dirty(boot_state=0x01)
    st = vol_of(b.image()).info()["state"]
    assert st["boot_dirty"] is True and st["dirty"] is True
    assert st["boot_state_offset"] == (0x41 if fat == "fat32" else 0x25)


def test_fat12_has_no_fat1_flags():
    b = fat12_small()
    b.set_dirty(boot_state=0x03)
    st = vol_of(b.image()).info()["state"]
    assert st["clean_shutdown"] is None and st["hard_error"] is None
    assert st["boot_dirty"] and st["boot_surface_scan"] and st["dirty"]


def test_fat32_fsinfo_backup_and_extflags():
    b = fat32_small()
    rec = b.add_file("/F.BIN", pattern(2000, 2))
    img = bytearray(b.image())
    v = vol_of(bytes(img))
    f32 = v.info()["fat32"]
    assert f32["fsinfo"]["valid"] and f32["fsinfo"]["free_count"] == b.free_count()
    assert f32["backup_boot"]["matches_primary"] is True and f32["mirroring"] is True
    rep = v.cluster_report()
    assert rep["fsinfo_free_matches"] is True and rep["free"] == b.free_count()
    struct.pack_into("<I", img, 512 + 488, 5)  # FSInfo 빈 클러스터 수 변조
    img[6 * 512 + 3] ^= 0xFF  # 백업 부트 섹터 변조
    v2 = vol_of(bytes(img))
    info = v2.info()
    assert "backup_boot_differs" in wcodes(info)
    assert v2.cluster_report()["fsinfo_free_matches"] is False
    # ExtFlags: 미러링 끔 + 활성 FAT 1 → FAT 0 이 망가져도 FAT 1 로 읽는다
    b2 = fat32_small(ext_flags=0x81)
    rec2 = b2.add_file("/G.BIN", pattern(3000, 3))
    for c in rec2.clusters:
        b2.set_fat_copy(0, c, 0)
    v3 = vol_of(b2.image())
    assert v3.info()["fat32"]["active_fat"] == 1 and v3.info()["fat32"]["mirroring"] is False
    assert v3.read_content(v3.lookup("/G.BIN")["ref"])["data"] == pattern(3000, 3)
    assert rec.clusters


# ---------------------------------------------------------------------------
# 볼륨 점검·체인 이상
# ---------------------------------------------------------------------------

def test_cluster_report_lost_chain_unallocated_and_crosslink():
    b = fat16_small()
    b.add_file("/OK.BIN", pattern(2048, 1))
    # 기록 중 뽑힌 녹화: FAT 체인은 있는데 디렉터리 항목이 없다
    b.reserve(range(500, 510))
    b.write_chain(list(range(500, 510)))
    # 항목은 있는데 시작 클러스터의 FAT 이 비어 있다
    z = b.add_file("/ZERO.BIN", pattern(1024, 2), clusters=[600])
    b.set_fat(600, 0)
    # 교차 연결: 두 파일이 클러스터 701 을 같이 쓴다
    b.add_file("/X1.BIN", pattern(2048, 3), clusters=[700, 701])
    b.add_file("/X2.BIN", pattern(2048, 4), clusters=[710, 711])
    b.set_fat(710, 701)
    b.set_fat_copy(1, 50, 0x1234)
    v = vol_of(b.image())
    rep = v.cluster_report()
    assert rep["allocated_unreferenced"] == 10 + 1  # 잃어버린 체인 10 + X2 에서 떨어져 나간 711
    heads = {x["head"]: x for x in rep["lost_chains"]}
    assert heads[500]["clusters"] == 10 and heads[500]["status"] == "ok"
    assert rep["unallocated_referenced"] == 1 and rep["unallocated_referenced_samples"][0]["cluster"] == 600
    assert rep["cross_linked"] == 1 and rep["cross_linked_samples"][0]["cluster"] == 701
    assert rep["fat_copies"]["differing_bytes"] > 0 and "fat_copies_differ" in wcodes(rep)
    anomalies = {a["path"]: a for a in rep["chain_anomalies"]}
    assert anomalies["/ZERO.BIN"]["status"] == "zeroed"
    assert z.clusters == [600]


@pytest.mark.parametrize("kind", ["cycle", "out-of-range", "broken"])
def test_chain_status_reporting(kind):
    b = fat16_small()
    data = pattern(5 * 1024, 9)
    rec = b.add_file("/C.BIN", data, clusters=[800, 801, 802, 803, 804])
    if kind == "cycle":
        b.set_fat(802, 800)
    elif kind == "out-of-range":
        b.set_fat(802, b.max_cluster + 5)
    else:
        b.set_fat(802, 0xFFF7)
    v = vol_of(b.image())
    e = by_path(v.walk())["/C.BIN"]
    assert e["chain"]["status"] == kind and e["chain"]["size_check"] == "chain_shorter"
    r = v.read_content(e["ref"])
    assert r["data"] == data[:3 * 1024] and r["truncated"]
    assert r["plan"]["confidence"] == "low"
    assert rec.clusters


def test_truncated_image_still_lists_and_reads_partially(tmp_path):
    b = fat16_small()
    keep = pattern(3000, 1)
    b.add_file("/EARLY.BIN", keep)
    late = pattern(8 * 1024, 2)
    b.add_file("/LATE.BIN", late, clusters=list(range(b.max_cluster - 7, b.max_cluster + 1)))
    b.mkdir("/FAR", clusters=[b.max_cluster - 20])
    img = b.image()
    cut = b.coff(b.max_cluster - 21) + 2048 + 512  # LATE 일부, FAR 디렉터리는 잘림
    p = tmp_path / "trunc.img"
    p.write_bytes(img[:cut])
    with ImageReader(p) as r:
        v = FatVolume(r)
        info = v.info()
        assert info["truncated"] and "volume_truncated" in wcodes(info)
        w = v.walk()
        e = by_path(w)
        assert v.read_content(e["/EARLY.BIN"]["ref"])["data"] == keep
        res = v.read_content(e["/LATE.BIN"]["ref"])
        assert res["truncated"] and res["bytes"] < len(late)
        assert res["plan"]["bytes_beyond_image"] > 0
        assert "dir_beyond_image" in wcodes(w) or "/FAR" in e


def test_fat_4k_sectors():
    b = FatBuilder(16, total_sectors=8192, bytes_per_sector=4096, sectors_per_cluster=1)
    b.mkdir("/DIR")
    data = pattern(20_000, 5)
    b.add_file("/DIR/four k sector.bin", data)
    v = vol_of(b.image())
    info = v.info()
    assert info["bytes_per_sector"] == 4096 and info["fs_type"] == "fat16" and info["cluster_size"] == 4096
    e = by_path(v.walk())["/DIR/four k sector.bin"]
    assert v.read_content(e["ref"])["data"] == data


def test_bad_refs_are_rejected():
    b = fat16_small(label="LBL")
    b.add_file("/A.TXT", b"a")
    v = vol_of(b.image())
    for ref in ("x/1", "root/abc", "c1/0", "c99999999/0", "root/99999999", "n5/0", "root", "", "../root/1",
                "c5+3/1"):
        with pytest.raises(FsError) as ei:
            v.entry(ref)
        assert ei.value.data["reason"] == "bad_ref", ref
    with pytest.raises(FsError):
        v.entry(123)  # type: ignore[arg-type]
    with pytest.raises(FsError) as ei:
        v.entry("root/0")  # 볼륨 레이블 슬롯은 파일 항목이 아니다
    assert ei.value.data["reason"] == "bad_ref"
    with pytest.raises(FsError):
        v.list_dir("root/1")  # 파일은 디렉터리가 아니다


def test_not_fat_and_bpb_errors():
    with pytest.raises(FsError) as ei:
        vol_of(bytes(1024))
    assert ei.value.data["reason"] == "not_fat"
    img = bytearray(fat12_small().image())
    struct.pack_into("<H", img, 11, 1000)
    with pytest.raises(FsError) as ei:
        vol_of(bytes(img))
    assert ei.value.data["reason"] == "not_fat"


def test_limits_cap_outputs():
    b = fat16_small()
    for i in range(30):
        b.add_file(f"/F{i:03d}.BIN", b"z")
    v = vol_of(b.image(), limits=Limits(max_entries=10, max_list=5))
    w = v.walk()
    assert len(w["entries"]) == 10 and w["truncated"] and w["truncated_reason"] == "max_entries"
    lst = v.list_dir()
    assert len(lst["entries"]) == 5 and lst["truncated"] and lst["entries_total"] == 30


def test_slice_reader_base_offset_reported():
    b = fat12_small()
    b.add_file("/A.TXT", b"abc")
    vol = b.image()
    img = bytes(4096) + vol
    v = FatVolume(SliceReader(BytesReader(img), 4096, len(vol)))
    e = v.lookup("/A.TXT")
    assert e["image_offset"] == e["offset"] + 4096
    plan = v.content_plan(e["ref"]).to_dict()
    assert plan["extents"][0]["image_offset"] == plan["extents"][0]["offset"] + 4096
