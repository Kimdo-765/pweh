"""pweh.fs 강화 회귀 시험: 디렉터리 검증(교차 연결·위조 dirspec·초기화 안 된 클러스터), 호출 예산(시간·단계), 파티션 상한·중복,
LFN 첫 바이트 되찾기, 후보 계산의 메모리·예산, reachable_dirspecs, ImageReader.from_fd.

이미지는 작고 합성이다(tests/fs/builders.py, tests/fs/hostile.py). 시간 단언은 넉넉하게 두고, 결정적인 판정은 단계 상한으로 한다.
"""

from __future__ import annotations

import json
import os
import random
import struct
import time
import tracemalloc

import pytest

from fs import hostile as H
from fs.builders import (
    GptPart,
    exfat_set_checksum,
    exfat_small,
    fat12_small,
    fat16_small,
    fat32_small,
    lfn_checksum,
    pattern,
    put_gpt,
    put_mbr,
)
from pweh.fs import BytesReader, Budget, FsError, ImageReader, Limits, analyze_image, detect_partitions, open_volume
from pweh.fs.fat import _invert_first_byte

MAKERS = {"fat12": fat12_small, "fat16": fat16_small, "fat32": fat32_small}


def by_path(walk: dict) -> dict[str, dict]:
    return {e["path"]: e for e in walk["entries"]}


def wcodes(res: dict) -> list[str]:
    return [w["code"] for w in res["warnings"]]


def recording(n: int, seed: int = 7) -> bytes:
    """압축 영상처럼 고른 무작위 바이트 (슬롯 시작에 0x00 이 거의 없다 — 이름으로 잘못 읽히기 가장 쉬운 꼴)."""
    return random.Random(seed).randbytes(n)


def leaked_slots(obj: object, data: bytes) -> int:
    """data 의 32바이트 슬롯마다 앞 11바이트(이름 자리)의 hex 가 obj(JSON) 어디엔가 나오는 수 — 0 이어야 한다."""
    blob = json.dumps(obj, ensure_ascii=False, default=str)
    return sum(1 for j in range(0, len(data) - 31, 32) if data[j:j + 11].hex() in blob)


def patch_dirent(vol: bytearray, area: tuple[int, int], name11: bytes, cluster: int, *, fat32: bool) -> None:
    for o in range(area[0], area[0] + area[1], 32):
        if bytes(vol[o:o + 11]) == name11:
            struct.pack_into("<H", vol, o + 26, cluster & 0xFFFF)
            struct.pack_into("<H", vol, o + 20, (cluster >> 16) if fat32 else 0)
            return
    raise AssertionError("dirent not found")


# ---------------------------------------------------------------------------
# 디렉터리 검증 (FAT)
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("fat", ["fat16", "fat32"])
def test_live_subdir_cross_linked_into_recording_is_not_listed(fat):
    """살아 있는 /DCIM 항목이 녹화 중간 클러스터를 가리킨다(전원 차단 교차 연결) — '.'/'..' 가 없으니 해석하지 않는다."""
    b = MAKERS[fat](label="CAMSD")
    b.mkdir("/DCIM")
    b.mkdir("/record")
    data = recording(64 * b.cs)
    rec = b.add_file("/record/CH01_9999.MP4", data)
    b.add_file("/README.TXT", b"readme")
    target = rec.clusters[len(rec.clusters) // 2]
    vol = bytearray(b.image())
    area = (b.root_off, b.root_entries * 32) if fat == "fat16" else (b.coff(b.dirs["/"].clusters[0]), b.cs)
    patch_dirent(vol, area, b"DCIM       ", target, fat32=fat == "fat32")
    v = open_volume(BytesReader(bytes(vol)))
    w = v.walk()
    paths = by_path(w)
    assert {"/DCIM", "/record", "/record/CH01_9999.MP4", "/README.TXT"} <= set(paths)
    assert not any(p.startswith("/DCIM/") for p in paths)
    assert w["unvalidated_dirs"] == [{"dirspec": f"c{target}", "path": "/DCIM", "reason": "missing_dot",
                                      "slots_skipped": (len(rec.clusters) - len(rec.clusters) // 2) * (b.cs // 32)}]
    assert "dir_unvalidated" in wcodes(w) and w["unvalidated_dirs_total"] == 1
    assert leaked_slots(w, data) == 0
    lst = v.list_dir(f"c{target}")
    assert lst["entries"] == [] and lst["orphans"] == [] and lst["unvalidated"]["reason"] == "missing_dot"
    assert leaked_slots(lst, data) == 0
    with pytest.raises(FsError) as ei:
        v.entry(f"c{target}/3")
    assert ei.value.data["reason"] == "bad_ref"
    # 녹화 바이트에서 나온 이름으로는 경로를 찾지 못한다 (lookup 은 검증된 디렉터리만 지난다) — 검증하지 못한 디렉터리에서 못 찾으면
    # '없음'이 아니라 '알 수 없음'(dir_unvalidated)이다
    name = data[(len(rec.clusters) // 2) * b.cs:][:11].decode("cp437").strip()
    with pytest.raises(FsError) as ei:
        v.lookup("/DCIM/" + name)
    assert ei.value.reason == "dir_unvalidated" and ei.value.data["component"] == 2


def test_fat32_root_chain_cross_linked_into_recording_stops_at_that_cluster():
    """루트 마지막 클러스터가 꽉 찼고 FAT 항목이 녹화 중간을 가리킨다 — 첫 클러스터 항목은 그대로, 그 뒤는 해석하지 않는다."""
    b = fat32_small(label="CAMSD")
    b.mkdir("/record")
    for i in range(13):
        b.add_file(f"/CFG{i:02d}.BIN", bytes([i]) * 10)
    root = b.dirs["/"]
    assert len(root.clusters) == 1 and len(root.slots) == 16
    data = recording(64 * 1024, 77)
    rec = b.add_file("/record/20261001_130000.mp4", data)
    b.set_fat(root.clusters[-1], rec.clusters[5])
    v = open_volume(BytesReader(b.image()))
    w = v.walk()
    assert {f"/CFG{i:02d}.BIN" for i in range(13)} <= set(by_path(w))
    assert v.info()["volume_label"] == "CAMSD"
    (u,) = w["unvalidated_dirs"]
    assert u["dirspec"] == "root" and u["path"] == "/" and u["slots_skipped"] > 0
    assert leaked_slots(w, data) == 0
    assert "dir_unvalidated" in wcodes(v.info())


def test_uninitialised_follow_on_directory_cluster_is_not_listed():
    """디렉터리가 두 번째 클러스터로 자랐는데 그 클러스터가 0 으로 초기화되지 않아 지운 녹화가 남아 있다."""
    b = fat32_small()
    d = b.mkdir("/DCIM", clusters=[300, 301])
    for i in range(14):  # '.' '..' + 14 = 16 슬롯 = 첫 클러스터 가득
        b.add_file(f"/DCIM/C{i:03d}.MP4", b"x")
    img = bytearray(b.image())
    stale = recording(b.cs, 3)
    img[b.coff(301):b.coff(301) + b.cs] = stale
    v = open_volume(BytesReader(bytes(img)))
    w = v.walk()
    assert {f"/DCIM/C{i:03d}.MP4" for i in range(14)} <= set(by_path(w))
    assert w["unvalidated_dirs"] == [{"dirspec": "c300", "path": "/DCIM", "reason": w["unvalidated_dirs"][0]["reason"],
                                      "slots_skipped": b.cs // 32}]
    assert leaked_slots(w, stale) == 0 and d.clusters == [300, 301]


def test_text_log_cluster_as_directory_leaks_nothing():
    b = fat16_small()
    b.mkdir("/DCIM")
    log = (b"user=admin pass=Sup3rS3cret! wifi psk=CorpNet-5G plate=12GA3456 " * 64)[:4 * b.cs]
    rec = b.add_file("/LOG.TXT", log)
    vol = bytearray(b.image())
    patch_dirent(vol, (b.root_off, b.root_entries * 32), b"DCIM       ", rec.clusters[1], fat32=False)
    w = open_volume(BytesReader(bytes(vol))).walk()
    blob = json.dumps(w)
    for word in ("admin", "Sup3r", "CorpNet", "12GA"):
        assert word not in blob
    assert w["unvalidated_dirs"][0]["path"] == "/DCIM"


def test_forged_dirspecs_read_nothing_from_data_clusters():
    """지어낸 dirspec(c<녹화 클러스터>, n<녹화 클러스터>+<길이>)으로는 녹화 바이트가 이름으로 나오지 않는다."""
    b = fat32_small()
    data = recording(32 * b.cs, 11)
    rec = b.add_file("/record.mp4", data)
    v = open_volume(BytesReader(b.image()))
    for spec in (f"c{rec.clusters[0]}", f"c{rec.clusters[7]}", f"n{rec.clusters[3]}+{b.cs}", f"n{rec.clusters[3]}+65536"):
        lst = v.list_dir(spec)
        assert lst["entries"] == [] and lst["unvalidated"] is not None, spec
        assert leaked_slots(lst, data) == 0
        for slot in range(0, 16, 3):
            with pytest.raises(FsError) as ei:
                v.entry(f"{spec}/{slot}")
            assert ei.value.data["reason"] == "bad_ref"
    reach = v.reachable_dirspecs()
    assert reach["dirspecs"] == {"root"} and not reach["truncated"]


def test_dot_entries_must_point_to_own_cluster():
    b = fat16_small()
    b.mkdir("/A")
    b.add_file("/A/IN.TXT", b"in")
    d = b.dirs["/A"]
    raw = bytearray(d.slots[0])
    struct.pack_into("<H", raw, 26, d.clusters[0] + 1)  # '.' 가 다른 클러스터를 가리킨다
    d.slots[0] = bytes(raw)
    w = open_volume(BytesReader(b.image())).walk()
    assert "/A/IN.TXT" not in by_path(w) and w["unvalidated_dirs"][0]["reason"] == "dot_cluster"


@pytest.mark.parametrize("kind,patch", [
    ("attr_reserved", lambda r: r.__setitem__(11, 0x60)),
    ("name_char", lambda r: r.__setitem__(3, ord("*"))),
    ("cluster_range", lambda r: struct.pack_into("<H", r, 26, 0xFFF0)),
    ("lfn_type", lambda r: (r.__setitem__(11, 0x0F), r.__setitem__(12, 1))),
])
def test_single_bad_slot_rejects_its_cluster(kind, patch):
    b = fat16_small()
    b.mkdir("/A")
    for i in range(5):
        b.add_file(f"/A/F{i}.BIN", b"z")
    d = b.dirs["/A"]
    raw = bytearray(d.slots[4])
    patch(raw)
    d.slots[4] = bytes(raw)
    w = open_volume(BytesReader(b.image())).walk()
    assert not any(p.startswith("/A/") for p in by_path(w))
    assert w["unvalidated_dirs"][0]["reason"] == kind


def test_clean_rich_trees_have_no_unvalidated_dirs():
    """정상 배치(긴 이름, 삭제 항목·디렉터리, 비인접 디렉터리 클러스터, 2바이트 코드 페이지 둘째 바이트, 소문자 SFN)는 다 나온다."""
    for maker in (fat12_small, fat16_small, fat32_small):
        b = maker(label="RICH")
        b.mkdir("/DCIM")
        b.mkdir("/DCIM/100CAM")
        for i in range(40):
            b.add_file(f"/DCIM/100CAM/Recording number {i:03d} of the long day.mp4", pattern(700, i))
        b.add_file("/DCIM/deleted one.bin", pattern(900, 1))
        b.delete("/DCIM/deleted one.bin")
        b.mkdir("/old")
        b.add_file("/old/x.bin", b"x")
        b.delete("/old/x.bin")
        b.delete("/old")
        b.add_file("/lower.txt", b"lc", short="LOWER.TXT", lfn=False, nt_case=0x18)
        v = open_volume(BytesReader(b.image()))
        w = v.walk()
        assert w["unvalidated_dirs"] == [] and "dir_unvalidated" not in wcodes(w), maker
        assert w["stats"]["files"] == 41 and w["stats"]["deleted_dirs"] == 1
        reach = v.reachable_dirspecs()
        e = by_path(w)
        assert reach["dirspecs"] == {"root", e["/DCIM"]["child_dir"], e["/DCIM/100CAM"]["child_dir"], e["/old"]["child_dir"]}
        assert reach["paths"]["root"] == "/" and reach["paths"][e["/DCIM/100CAM"]["child_dir"]] == "/DCIM/100CAM"
        assert reach["paths"][e["/old"]["child_dir"]] == "/old" and reach["truncated"] is False
        for ent in w["entries"]:
            spec = ent["ref"].rsplit("/", 1)[0]
            assert spec in reach["dirspecs"]


def test_dbcs_trail_bytes_in_short_names_are_accepted():
    b = fat16_small()
    raw_name = "\u8868".encode("cp932") + b"ABC   TXT"  # 0x95 0x5C ('\\' 가 둘째 바이트)
    assert raw_name[1] == 0x5C and len(raw_name) == 11
    rec = b.add_file("/X.TXT", b"x")
    d = b.dirs["/"]
    raw = bytearray(d.slots[rec.slots[-1]])
    raw[0:11] = raw_name
    d.slots[rec.slots[-1]] = bytes(raw)
    w = open_volume(BytesReader(b.image())).walk()
    assert w["unvalidated_dirs"] == [] and len(w["entries"]) == 1


# ---------------------------------------------------------------------------
# 디렉터리 검증 (exFAT)
# ---------------------------------------------------------------------------

def _ex_put(b, path: str, raws: list[bytearray], img: bytearray) -> None:
    rec = b.files[path]
    d = b.dirs[rec.dir_path]
    per = b.cs // 32
    for s, x in zip(rec.slots, raws):
        o = b.coff(d.clusters[s // per]) + (s % per) * 32
        img[o:o + 32] = x


def test_exfat_subdir_pointing_into_recording_is_not_listed():
    b = exfat_small()
    b.mkdir("/DCIM", nclusters=1)
    data = recording(16 * b.cs, 5)
    rec = b.add_file("/clip.mp4", data)
    img = bytearray(b.image())
    d = b.dirs["/"]
    r = b.files["/DCIM"]
    raws = [bytearray(d.slots[s]) for s in r.slots]
    struct.pack_into("<I", raws[1], 20, rec.clusters[8])
    struct.pack_into("<H", raws[0], 2, exfat_set_checksum([bytes(x) for x in raws]))
    _ex_put(b, "/DCIM", raws, img)
    v = open_volume(BytesReader(bytes(img)))
    w = v.walk()
    assert set(by_path(w)) == {"/DCIM", "/clip.mp4"}
    assert w["unvalidated_dirs"][0]["path"] == "/DCIM"
    assert leaked_slots(w, data) == 0
    spec = by_path(w)["/DCIM"]["child_dir"]
    assert spec in v.reachable_dirspecs()["dirspecs"]
    with pytest.raises(FsError):
        v.entry(f"c{rec.clusters[2]}+4096/0")


def test_exfat_root_chain_cross_link_keeps_first_cluster_and_metadata():
    b = exfat_small(root_clusters=2)
    for i in range(30):
        b.add_file(f"/f{i:02d}.bin", b"x")  # 3 + 30*3 = 93 슬롯 < 128 (첫 클러스터)
    data = recording(8 * b.cs, 9)
    rec = b.add_file("/rec.mp4", data, contiguous=False, clusters=[60, 62, 64, 66, 68, 70, 72, 74])
    b.set_fat(b.root_clusters[0], rec.clusters[3])  # 루트 두 번째 클러스터 대신 녹화 중간
    v = open_volume(BytesReader(b.image()))
    info = v.info()
    assert info["bitmap"]["present"] and info["upcase"]["checksum_ok"] is True
    w = v.walk()
    assert {f"/f{i:02d}.bin" for i in range(30)} <= set(by_path(w))
    assert leaked_slots(w, data) == 0


def test_exfat_unknown_inuse_type_and_text_cluster():
    b = exfat_small()
    b.mkdir("/D", nclusters=1)
    b.add_file("/D/a.bin", b"a")
    b.put_slot("/D", 5, bytes([0x99]) + bytes(31))  # 사양에 없는 사용 중 형식
    w = open_volume(BytesReader(b.image())).walk()
    assert "/D/a.bin" not in by_path(w) and w["unvalidated_dirs"][0]["reason"] == "unknown_type"
    b2 = exfat_small()
    b2.mkdir("/D", nclusters=1)
    log = (b"A=user=admin pass=Sup3rS3cret! @wifi psk=CorpNet " * 200)[:b2.cs]
    img = bytearray(b2.image())
    c = b2.dirs["/D"].clusters[0]
    img[b2.coff(c):b2.coff(c) + b2.cs] = log
    w2 = open_volume(BytesReader(bytes(img))).walk()
    blob = json.dumps(w2)
    assert "admin" not in blob and "CorpNet" not in blob and "Sup3r" not in blob
    assert all("partial_name" not in o for o in w2["orphans"])


# ---------------------------------------------------------------------------
# 예산 (#1)
# ---------------------------------------------------------------------------

def test_budget_counts_steps_and_time():
    bud = Budget(None, 10)
    bud.tick(10)
    assert not bud.expired() and bud.reason is None
    bud.tick()
    assert bud.expired() and bud.reason == "steps"
    t = Budget(0.01, None)
    time.sleep(0.03)
    assert t.expired() and t.reason == "time"
    assert Budget.for_limits(Limits(max_seconds=None, max_follow_steps=5)).max_steps == 5
    e = Budget(None, 0)
    e.tick()
    err = e.error("시험")
    assert err.reason == "budget_exceeded" and err.data["limit"] == "steps"


def test_walk_stops_inside_one_directory_when_chain_summaries_exhaust_the_step_budget():
    img = H.fat32_long_chain(100, count=200_000)
    v = open_volume(BytesReader(img), limits=Limits(max_follow_steps=500_000))
    t0 = time.monotonic()
    w = v.walk()
    assert time.monotonic() - t0 < 30
    assert w["truncated"] and w["truncated_reason"] == "steps"
    # 디렉터리 하나 안에서 항목마다 예산을 본다: 이미 검증한 항목은 다 싣지만 체인은 예산이 남은 동안만 따라간다
    assert len(w["entries"]) == 100
    chains = [e["chain"] for e in w["entries"]]
    checked = [c for c in chains if c["size_check"] != "unknown"]
    assert 1 <= len(checked) <= 3
    assert chains[0]["status"] == "ok" and chains[0]["size_check"] == "chain_shorter"
    assert all(c["status"] == "limit" and c["size_check"] == "unknown" and c["limit_reason"] == "steps"
               for c in chains[len(checked):])


def test_walk_time_budget_bounds_a_single_directory():
    img = H.fat32_long_chain(100, count=2_000_000)
    v = open_volume(BytesReader(img), limits=Limits(max_seconds=0.3, max_follow_steps=1 << 40))
    t0 = time.monotonic()
    w = v.walk()
    elapsed = time.monotonic() - t0
    assert w["truncated_reason"] == "time"
    assert sum(1 for e in w["entries"] if e["chain"]["size_check"] != "unknown") < 100
    assert w["entries"][-1]["chain"]["limit_reason"] == "time"
    assert elapsed < 10, elapsed


def test_exfat_deleted_set_allocation_summary_is_capped_per_entry_and_budgeted():
    img = H.exfat_chain_sets(50, chain_len=20_000, count=60_000)
    v = open_volume(BytesReader(img))
    w = v.walk()
    assert not w["truncated"] and len(w["entries"]) == 50
    a = w["entries"][0]["allocation_now"]
    assert a == {"status": "free", "checked_clusters": 4096, "allocated_now": 0, "partial_check": True}
    v2 = open_volume(BytesReader(img), limits=Limits(max_follow_steps=30_000))
    w2 = v2.walk()
    assert w2["truncated"] and w2["truncated_reason"] == "steps" and 0 < len(w2["entries"]) < 50
    assert w2["entries"][-1]["allocation_now"]["status"] == "unknown"  # 예산 뒤에는 대조하지 않았다
    with pytest.raises(FsError) as ei:  # 예산이 다 되면 항목 하나를 돌려줘야 하는 호출은 budget_exceeded
        v2.entry("root/45", budget=Budget(None, 1000))
    assert ei.value.data["reason"] == "budget_exceeded" and ei.value.data["limit"] == "steps"


def test_list_dir_and_lookup_respect_the_budget():
    img = H.exfat_chain_sets(200, chain_len=5000, count=20_000)
    v = open_volume(BytesReader(img), limits=Limits(max_follow_steps=20_000))
    lst = v.list_dir()
    assert lst["truncated"] and lst["truncated_reason"] == "steps"
    with pytest.raises(FsError) as ei:
        v.lookup("/d00199.mp4")
    assert ei.value.data["reason"] == "budget_exceeded"
    assert open_volume(BytesReader(img)).lookup("/d00199.mp4") is None  # 삭제 항목은 lookup 대상이 아니다


# ---------------------------------------------------------------------------
# analyze_image (#2)
# ---------------------------------------------------------------------------

def _gpt_with(parts_vols: list[tuple[int, bytes]], extra: int) -> bytearray:
    total = max(lba + len(v) // 512 for lba, v in parts_vols) + extra
    img = bytearray(total * 512)
    for lba, v in parts_vols:
        img[lba * 512:lba * 512 + len(v)] = v
    return img


def test_analyze_image_deduplicates_identical_partitions():
    vol = fat12_small(label="ONE").image()
    first = 2048
    n = 300
    img = _gpt_with([(first, vol)], extra=4096)
    put_gpt(img, [GptPart(first, first + len(vol) // 512 - 1)] * n, num_entries=512)
    t0 = time.monotonic()
    lay = analyze_image(BytesReader(img))
    assert time.monotonic() - t0 < 20
    vols = lay["volumes"]
    assert len(vols) == n and "info" in vols[0] and vols[0]["info"]["volume_label"] == "ONE"
    assert all(x.get("duplicate_of") == 1 and "info" not in x for x in vols[1:])
    assert lay["partitions_omitted"] == 0 and lay["truncated"] is False and lay["truncated_reason"] is None
    assert sum(1 for x in lay["warnings"] if x["code"] == "partition_overlap") <= 32


def test_analyze_image_caps_distinct_partitions():
    vols = [(2048 + i * 9000, fat12_small(label=f"P{i}").image()) for i in range(5)]
    img = _gpt_with(vols, extra=4096)
    put_gpt(img, [GptPart(lba, lba + len(v) // 512 - 1) for lba, v in vols])
    lay = analyze_image(BytesReader(img), limits=Limits(max_partitions=2))
    items = lay["volumes"]
    assert [("info" in x) for x in items] == [True, True, False, False, False]
    assert [x.get("omitted") for x in items[2:]] == ["partitions"] * 3
    assert lay["partitions_omitted"] == 3 and lay["truncated"] and lay["truncated_reason"] == "partitions"
    assert len(lay["partitions"]) == 5


def test_analyze_image_step_budget_and_fast_lfn_inversion():
    vol = H.fat16_lfn_bomb(16384)
    t0 = time.monotonic()
    info = open_volume(BytesReader(vol)).info()
    assert time.monotonic() - t0 < 10 and info["warnings"] == []
    vols = [(2048 + i * (len(vol) // 512 + 64), vol) for i in range(3)]
    img = _gpt_with(vols, extra=4096)
    put_gpt(img, [GptPart(lba, lba + len(v) // 512 - 1) for lba, v in vols])
    lay = analyze_image(BytesReader(img), limits=Limits(max_follow_steps=20_000))
    assert lay["truncated"] and lay["truncated_reason"] == "steps"
    assert lay["partitions_omitted"] >= 1 and lay["volumes"][-1]["omitted"] == "steps"


def test_detect_partitions_identical_ranges_is_not_quadratic():
    vol = fat12_small().image()
    n = 8192  # 항목 배열 1 MiB
    first = 4096
    img = _gpt_with([(first, vol)], extra=4096)
    put_gpt(img, [GptPart(first, first + len(vol) // 512 - 1)] * n, num_entries=n)
    t0 = time.monotonic()
    lay = detect_partitions(BytesReader(img))
    assert time.monotonic() - t0 < 20
    assert len(lay["partitions"]) == n
    assert sum(1 for x in lay["warnings"] if x["code"] == "partition_overlap") == 32


def test_lfn_first_byte_inversion_matches_bruteforce():
    rng = random.Random(42)
    for _ in range(5000):
        name = bytes(rng.randrange(256) for _ in range(11))
        assert _invert_first_byte(name[1:], lfn_checksum(name)) == name[0]


# ---------------------------------------------------------------------------
# 후보 계산 (#3)
# ---------------------------------------------------------------------------

def test_exfat_stale_chain_candidate_counts_per_run_without_materialising():
    img = H.exfat_chain_sets(1, chain_len=600_000, count=700_000, data_length=1 << 62)
    v = open_volume(BytesReader(img))
    tracemalloc.start()
    try:
        cands = v.candidates("root/3")
        peak = tracemalloc.get_traced_memory()[1]
    finally:
        tracemalloc.stop()
    assert peak < 48 << 20, peak  # 예전: 클러스터마다 파이썬 int (~40 바이트 × 60만)
    stale = next(c for c in cands if c["method"] == "stale-chain")
    assert stale["clusters"] == 600_000 and stale["conflicts"] == {"allocated": 0}
    small = open_volume(BytesReader(img), limits=Limits(max_follow_steps=100_000))
    t0 = time.monotonic()
    plan = small.content_plan("root/3", method="stale-chain")
    assert time.monotonic() - t0 < 10
    assert plan.status == "limit" and plan.extra["limit_reason"] == "steps" and plan.confidence == "low"


def test_fat_skip_candidates_are_bounded_and_shared_budget_is_honoured():
    img = H.fat32_all_allocated(400_000)
    v = open_volume(BytesReader(img))
    t0 = time.monotonic()
    cands = {c["method"]: c for c in v.candidates("root/1")}
    assert time.monotonic() - t0 < 20
    sk = cands["skip-allocated"]
    assert sk["status"] == "incomplete" and sk["clusters"] == 0 and sk["conflicts"]["skipped_allocated"] > 300_000
    bud = Budget(None, 0)
    bud.tick()
    with pytest.raises(FsError) as ei:
        v.content_plan("root/2", budget=bud)  # 이미 다 쓴 공유 예산 — 계획을 만들지 않는다
    assert ei.value.data["reason"] == "budget_exceeded"
    few = Budget(None, 5000)  # 조금 남은 공유 예산 — 싼 후보(contiguous)는 만들고 비싼 탐색은 부분 후보로 표시
    plans = {c["method"]: c for c in v.candidates("root/2", budget=few)}
    assert plans["contiguous"]["status"] in ("ok", "beyond_volume")
    assert plans["skip-allocated"]["status"] == "limit" and plans["skip-allocated"]["limit_reason"] == "steps"


def test_fat_candidates_unchanged_on_clean_deleted_files():
    b = fat16_small()
    b.add_file("/B.BIN", pattern(7 * 1024, 30), clusters=list(range(103, 110)))
    b.add_file("/A.MP4", pattern(6 * 1024, 31), clusters=[100, 101, 102, 110, 111, 112])
    b.add_file("/C.BIN", pattern(3 * 1024, 32), clusters=[200, 202, 204])
    b.delete("/A.MP4")
    b.delete("/B.BIN")
    v = open_volume(BytesReader(b.image()))
    dels = {x["first_cluster"]: x for x in v.list_dir()["entries"] if x["deleted"]}
    by = {c["method"]: c for c in v.candidates(dels[100]["ref"])}
    assert by["skip-claimed"]["runs"] == [[100, 3], [110, 3]] and by["skip-claimed"]["conflicts"] == {
        "skipped_allocated": 0, "skipped_claimed": 7, "claimed_included": 0}
    assert by["contiguous"]["conflicts"] == {"allocated": 0, "claimed": 3}
    assert v.read_content(dels[100]["ref"])["data"] == pattern(6 * 1024, 31)


# ---------------------------------------------------------------------------
# ImageReader.from_fd (#14)
# ---------------------------------------------------------------------------

def test_image_reader_from_fd_reads_the_validated_object(tmp_path):
    from pweh.safeio import open_regular

    p = tmp_path / "card.img"
    b = fat12_small(label="FD")
    b.add_file("/A.TXT", b"hello")
    p.write_bytes(b.image())
    fd, st = open_regular(p)
    try:
        r = ImageReader.from_fd(fd, path=str(p))
    finally:
        os.close(fd)  # 호출자 fd 를 닫아도 dup 한 fd 로 계속 읽는다
    with r:
        assert r.size == st.st_size and r.identity["ino"] == st.st_ino and r.path == str(p)
        p.rename(tmp_path / "moved.img")  # 경로가 바뀌어도 같은 객체를 읽는다
        (tmp_path / "card.img").write_bytes(bytes(len(b.image())))
        v = open_volume(r)
        assert v.info()["volume_label"] == "FD" and v.lookup("/A.TXT")["size"] == 5
    assert r.closed


def test_image_reader_from_fd_refuses_fifo_and_directory(tmp_path):
    fifo = tmp_path / "pipe"
    os.mkfifo(fifo)
    fd = os.open(fifo, os.O_RDONLY | os.O_NONBLOCK)
    try:
        with pytest.raises(FsError) as ei:
            ImageReader.from_fd(fd)
        assert ei.value.data["reason"] == "not_regular_file"
    finally:
        os.close(fd)
    dfd = os.open(tmp_path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        with pytest.raises(FsError) as ei:
            ImageReader.from_fd(dfd)
        assert ei.value.data["reason"] == "not_regular_file"
    finally:
        os.close(dfd)
    with pytest.raises(FsError):
        ImageReader.from_fd(-1)


def test_reachable_dirspecs_respects_budget_and_mbr_partition(tmp_path):
    b = fat32_small()
    for i in range(10):
        b.mkdir(f"/D{i}")
        b.mkdir(f"/D{i}/S")
    vol = b.image()
    img = bytearray(2048 * 512 + len(vol))
    put_mbr(img, [(0x0C, 2048, len(vol) // 512)])
    img[2048 * 512:] = vol
    lay = detect_partitions(BytesReader(bytes(img)))
    from pweh.fs import partition_source

    v = open_volume(partition_source(BytesReader(bytes(img)), lay["partitions"][0]))
    reach = v.reachable_dirspecs()
    assert len(reach["dirspecs"]) == 21 and reach["truncated"] is False and reach["status"] == "complete"
    fresh = open_volume(partition_source(BytesReader(bytes(img)), lay["partitions"][0]))  # 디렉터리 캐시 없이
    cut = fresh.reachable_dirspecs(Limits(max_follow_steps=40))
    assert cut["truncated"] and cut["truncated_reason"] == "steps" and cut["status"] == "truncated"
    # 잘리기 전에 찾은 dirspec 은 검증된 것이다(루트의 검증된 항목이 가리킴) — 전체 집합의 부분 집합
    assert "root" in cut["dirspecs"] and cut["dirspecs"] < reach["dirspecs"]
    assert all(cut["paths"][d] == reach["paths"][d] for d in cut["dirspecs"])


def test_exfat_leftover_reserved_bytes_from_slot_reuse_are_accepted():
    """Linux exFAT(5.x)는 다시 쓰는 슬롯의 예약 바이트를 지우지 않는다 — 체크섬이 맞으면 정상 항목으로 본다."""
    b = exfat_small()
    b.mkdir("/D", nclusters=1)
    rec = b.add_file("/D/clip0001.mp4", pattern(3000, 1))
    d = b.dirs["/D"]
    raws = [bytearray(d.slots[s]) for s in rec.slots]
    raws[0][6:8] = b"\x41\x00"  # File Reserved1 (이전 이름 항목의 글자)
    raws[0][25:32] = b"\x10\x27\x00\x00\x00\x00\x00"  # File Reserved2 (이전 스트림의 DataLength 상위 바이트)
    raws[1][2] = 0x7A  # Stream Reserved1
    raws[1][16:20] = b"\x01\x02\x03\x04"  # Stream Reserved3
    struct.pack_into("<H", raws[0], 2, exfat_set_checksum([bytes(r) for r in raws]))
    for s, r in zip(rec.slots, raws):
        d.slots[s] = bytes(r)
    v = open_volume(BytesReader(b.image()))
    w = v.walk()
    e = by_path(w)["/D/clip0001.mp4"]
    assert w["unvalidated_dirs"] == [] and e["set_checksum_ok"] is True
    assert v.read_content(e["ref"])["data"] == pattern(3000, 1)


def test_lfn_padding_variants_are_accepted_but_garbage_after_padding_is_not():
    b = fat16_small()
    rec = b.add_file("/A long recording.mp4", b"abc")  # 20 글자 → LFN 2 슬롯, 마지막 슬롯 = 7 글자 + 종결자 + 0xFFFF 채움 5개
    d = b.dirs["/"]
    last = rec.slots[0]  # 물리 순서 첫 슬롯 = 마지막 ordinal (종결자·채움이 있는 슬롯)
    raw = bytes(d.slots[last])
    assert raw[18:20] == b"\x00\x00" and raw[20:26] == b"\xff" * 6 and raw[28:32] == b"\xff" * 4

    def walk_with(slot: bytes) -> dict:
        d.slots[last] = slot
        return open_volume(BytesReader(b.image())).walk()

    zero_pad = raw[:20] + b"\x00" * 6 + raw[26:28] + b"\x00" * 4  # 0x0000 채움 (일부 임베디드 구현)
    w = walk_with(zero_pad)
    assert w["unvalidated_dirs"] == [] and by_path(w)["/A long recording.mp4"]["lfn_status"] == "ok"
    no_term = raw[:18] + b"\xff\xff" + raw[20:]  # 종결자 없이 0xFFFF 채움만
    w = walk_with(no_term)
    assert w["unvalidated_dirs"] == [] and by_path(w)["/A long recording.mp4"]["lfn_status"] == "ok"
    garbage = raw[:30] + b"\x41\x00"  # 채움 뒤에 글자 → 디렉터리 데이터가 아니다
    w = walk_with(garbage)
    assert w["unvalidated_dirs"][0]["reason"] == "lfn_padding" and w["entries"] == []


def test_root_first_cluster_unvalidated_falls_back_cleanly():
    b = fat32_small(label="BOOTLBL")
    b.add_file("/A.TXT", b"a")
    root = b.dirs["/"]
    raw = bytearray(root.slots[0])  # 루트 레이블 항목에 클러스터 번호 → 레이블 검사 실패
    struct.pack_into("<H", raw, 26, 7)
    root.slots[0] = bytes(raw)
    v = open_volume(BytesReader(b.image()))
    info = v.info()
    assert info["volume_label_root"] is None and info["volume_label"] == "BOOTLBL"
    assert "dir_unvalidated" in wcodes(info)
    w = v.walk()
    assert w["entries"] == [] and w["unvalidated_dirs"][0]["reason"] == "label_fields"
    e = exfat_small()
    e.add_file("/x.bin", b"x")
    e.put_slot("/", 4, bytes([0x9F]) + bytes(31))
    ev = open_volume(BytesReader(e.image()))
    ei = ev.info()
    assert {"dir_unvalidated", "bitmap_missing"} <= set(wcodes(ei))
    assert ev.walk()["entries"] == [] and ev.cluster_report()["scanned"] is False


def test_walk_accepts_caller_limits():
    b = fat16_small()
    for i in range(30):
        b.add_file(f"/F{i:03d}.BIN", b"z")
    v = open_volume(BytesReader(b.image()))
    w = v.walk(limits=Limits(max_entries=7))
    assert len(w["entries"]) == 7 and w["truncated_reason"] == "max_entries"
    assert len(v.walk()["entries"]) == 30


def test_reachable_dirspecs_skips_allocation_summaries():
    """디렉터리만 따라가는 순회는 삭제 집합 할당 요약을 하지 않는다 — 삭제 항목이 많은 큰 카드에서도 단계 상한에 덜 닿는다."""
    img = H.exfat_chain_sets(200, chain_len=5000, count=20_000)
    v = open_volume(BytesReader(img), limits=Limits(max_follow_steps=20_000))
    reach = v.reachable_dirspecs()
    assert reach["dirspecs"] == {"root"} and reach["truncated"] is False
    assert v.list_dir()["truncated_reason"] == "steps"  # 목록은 요약을 하므로 같은 한도에서 잘린다
    full = open_volume(BytesReader(img)).list_dir()
    assert full["entries"][0]["allocation_now"]["checked_clusters"] == 4096  # 요약을 뺀 결과는 캐시하지 않았다
