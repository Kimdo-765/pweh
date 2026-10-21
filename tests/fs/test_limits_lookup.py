"""pweh.fs 2차 강화 회귀 시험: lookup 의 정확한 이름 우선·모호성(E1)·디스크 경로(S-2), 디렉터리별 한도의 정직한 잘림
(max_dir_slots E2, max_depth E4), 마지막 체인 요약에서 다 된 예산(A-N7), 볼륨별 단계 상한(E3), msdos 짧은 이름 바이트(E5),
크기·교차 연결 검사(A-N5/B-N3), 경로 글자 수 상한(A-N1), 취소 함수와 reachable_dirspecs(targets=)(B-N4), 요청한 후보만 만들기(A-N4).

이미지는 작고 합성이다(tests/fs/builders.py, tests/fs/hostile.py). 판정은 단계 상한·카운터로 결정적으로 한다.
"""

from __future__ import annotations

import dataclasses
import json
import random
import struct

import pytest

from fs import hostile as H
from fs.builders import DEFAULT_TIME, exfat_small, fat16_small, fat32_small, pattern
from pweh.fs import FOLLOW_STEPS_FLOOR, Budget, BytesReader, FsError, Limits, open_volume
from pweh.fs import base as fsbase


def by_path(walk: dict) -> dict[str, dict]:
    return {e["path"]: e for e in walk["entries"]}


def wcodes(res: dict) -> list[str]:
    return [w["code"] for w in res["warnings"]]


def vol_of(b, limits: Limits | None = None):
    return open_volume(BytesReader(b.image()), limits=limits)


# ---------------------------------------------------------------------------
# E1 · S-2 lookup
# ---------------------------------------------------------------------------

def test_lookup_exact_name_beats_case_fold_and_returns_the_right_bytes():
    """straße.txt 와 strasse.txt: 글자 수를 바꾸는 접기(ß→ss)를 하지 않고, 정확한 이름이 먼저다."""
    b = fat32_small()
    b.mkdir("/d")
    b.add_file("/d/straße.txt", b"sharp-s bytes")
    b.add_file("/d/strasse.txt", b"double-s bytes")
    b.add_file("/d/ﬁle.txt", b"ligature bytes")  # 'ﬁle.txt' (ﬁ 합자 — 대문자는 'FI' 두 글자)
    v = vol_of(b)
    for p, data in (("/d/strasse.txt", b"double-s bytes"), ("/d/straße.txt", b"sharp-s bytes"),
                    ("/D/STRASSE.TXT", b"double-s bytes"), ("/d/Strasse.TXT", b"double-s bytes"),
                    ("/d/STRAßE.TXT", b"sharp-s bytes"), ("/d/ﬁLE.TXT", b"ligature bytes")):
        e = v.lookup(p)
        assert e is not None, p
        assert v.read_content(e["ref"])["data"] == data, p
    assert v.lookup("/d/file.txt") is None and v.lookup("/d/FILE.TXT") is None  # ﬁ 를 'FI' 로 접지 않는다


def test_lookup_case_only_variants_are_ambiguous_without_an_exact_match():
    b = fat16_small()
    b.mkdir("/d")
    b.add_file("/d/Report.txt", b"one")
    b.add_file("/d/REPORT.txt", b"two")  # 짧은 이름은 서로 다르게 자동 생성된다
    b.add_file("/d/µ.txt", b"micro")  # µ (U+00B5) — 대문자는 Μ (U+039C)
    b.add_file("/d/μ.txt", b"mu")  # μ (U+03BC) — 대문자도 Μ
    v = vol_of(b)
    assert v.read_content(v.lookup("/d/Report.txt")["ref"])["data"] == b"one"
    assert v.read_content(v.lookup("/d/REPORT.txt")["ref"])["data"] == b"two"
    assert v.read_content(v.lookup("/d/μ.txt")["ref"])["data"] == b"mu"
    for p in ("/d/report.TXT", "/d/Μ.txt"):
        with pytest.raises(FsError) as ei:
            v.lookup(p)
        assert ei.value.reason == "ambiguous_path" and ei.value.data["component"] == 2 and ei.value.data["candidates"] == 2
        assert "Report" not in ei.value.message and "REPORT" not in ei.value.message  # 이미지의 이름을 되풀이하지 않는다


def test_lookup_exact_duplicates_are_ambiguous():
    """조작된 디렉터리: 이름이 정확히 같은 살아 있는 항목 둘 — 첫 것을 고르지 않는다."""
    b = fat16_small()
    r1 = b.add_file("/A.BIN", b"first")
    r2 = b.add_file("/B.BIN", b"second")
    d = b.dirs["/"]
    raw = bytearray(d.slots[r2.slots[-1]])
    raw[0:11] = r1.sfn
    d.slots[r2.slots[-1]] = bytes(raw)
    v = vol_of(b)
    with pytest.raises(FsError) as ei:
        v.lookup("/A.BIN")
    assert ei.value.reason == "ambiguous_path" and ei.value.data["component"] == 1


def test_lookup_returns_on_disk_path_and_display_path():
    """S-2: 8.3 별칭·대소문자 변형으로 찾아도 path/display_path 는 디스크의 긴 이름이다."""
    b = fat32_small()
    b.mkdir("/DCIM")
    b.mkdir("/DCIM/100Media")
    c = b.add_file("/DCIM/100Media/Clip Long Name 0001.MP4", pattern(700, 1))
    v = vol_of(b)
    for p in ("/dcim/100media/clip long name 0001.mp4", f"/DCIM/{b.files['/DCIM/100Media'].short}/{c.short}",
              "/DCIM/100Media/Clip Long Name 0001.MP4"):
        e = v.lookup(p)
        assert e["path"] == "/DCIM/100Media/Clip Long Name 0001.MP4", p
        assert e["display_path"] == "/DCIM/100Media/Clip Long Name 0001.MP4"
        assert e["depth"] == 3 and e["parent_deleted"] is False
        assert e["parent_ref"] == v.lookup("/DCIM/100Media")["ref"]
    assert v.lookup("/DCIM")["parent_ref"] is None and v.lookup("/DCIM")["display_path"] == "/DCIM"
    assert v.lookup("/") is None and v.lookup("") is None


def test_exfat_lookup_exact_first_with_upcase_table_and_ambiguity():
    b = exfat_small()
    b.mkdir("/d", nclusters=1)
    b.add_file("/d/Clip.mp4", b"mixed")
    b.add_file("/d/CLIP.MP4", b"upper")
    b.add_file("/d/only.bin", b"only")
    v = vol_of(b)
    assert v.read_content(v.lookup("/d/Clip.mp4")["ref"])["data"] == b"mixed"
    assert v.read_content(v.lookup("/d/CLIP.MP4")["ref"])["data"] == b"upper"
    assert v.lookup("/D/ONLY.BIN")["path"] == "/d/only.bin"
    with pytest.raises(FsError) as ei:
        v.lookup("/d/clip.MP4")
    assert ei.value.reason == "ambiguous_path"


# ---------------------------------------------------------------------------
# E2 max_dir_slots
# ---------------------------------------------------------------------------

def _exfat_big_dir(nsets: int, nclusters: int):
    b = exfat_small()
    b.mkdir("/BIG", nclusters=nclusters)
    for i in range(nsets):
        b.add_file(f"/BIG/f{i:04d}.bin", b"")  # 이름 9 글자 → 집합 3 슬롯
    b.mkdir("/AFTER", nclusters=1)
    b.add_file("/AFTER/tail.txt", b"tail")
    return b


def test_exfat_directory_over_slot_limit_is_cut_honestly():
    b = _exfat_big_dir(120, 3)  # 360 슬롯, 끝 표시는 360 (384 슬롯 중)
    lim = dataclasses.replace(Limits(), max_dir_slots=200)  # 슬롯 198~200 에 걸친 집합(66번째)이 잘린다
    v = vol_of(b, lim)
    w = v.walk()
    big = [e for e in w["entries"] if e["path"].startswith("/BIG/")]
    assert len(big) == 66 and all(e["set_complete"] and e["name_status"] == "ok" for e in big)  # 잘린 집합은 내지 않는다
    assert "/AFTER/tail.txt" in by_path(w)  # 나머지 나무는 계속 돈다
    spec = by_path(w)["/BIG"]["child_dir"]
    assert w["truncated"] and w["truncated_reason"] == "max_dir_slots" and w["truncated_reasons"] == ["max_dir_slots"]
    assert w["cut_dirs"] == [{"dirspec": spec, "path": "/BIG", "reason": "max_dir_slots"}] and w["cut_dirs_total"] == 1
    warn = next(x for x in w["warnings"] if x["code"] == "dir_slot_limit")
    assert warn["path"] == "/BIG" and warn["dirspec"] == spec and warn["slots_read"] == 200
    assert by_path(w)["/BIG"]["chain"]["cut"] == "max_dir_slots"
    ld = v.list_dir(spec)
    assert ld["truncated"] and ld["truncated_reason"] == "max_dir_slots" and ld["cut"]["boundary_slot"] == 198
    with pytest.raises(FsError) as ei:
        v.entry(f"{spec}/198")
    assert ei.value.reason == "bad_ref" and ei.value.data["dir_cut"] == "max_dir_slots"
    reach = v.reachable_dirspecs()
    assert reach["status"] == "truncated" and reach["truncated_reason"] == "max_dir_slots"
    assert reach["cut_dirs"][0]["dirspec"] == spec and spec in reach["dirspecs"]
    with pytest.raises(FsError) as ei:
        v.lookup("/BIG/f0119.bin")  # 잘린 뒤쪽에 있을 수 있다 — None(없음)이라고 하지 않는다
    assert ei.value.reason == "max_dir_slots"
    assert v.lookup("/BIG/f0010.bin")["name"] == "f0010.bin"


def test_end_marker_before_the_slot_limit_is_not_a_cut():
    b = _exfat_big_dir(50, 3)  # 150 슬롯 + 끝 표시 — 한도 200 안
    v = vol_of(b, dataclasses.replace(Limits(), max_dir_slots=200))
    w = v.walk()
    assert not w["truncated"] and w["cut_dirs"] == [] and "dir_slot_limit" not in wcodes(w)
    assert sum(1 for e in w["entries"] if e["path"].startswith("/BIG/")) == 50


def test_fat_directory_over_slot_limit_drops_the_straddling_lfn():
    b = fat32_small()  # 512 바이트 클러스터 = 16 슬롯
    b.mkdir("/BIG")
    for i in range(30):
        b.add_file(f"/BIG/long recording name {i:03d}.mp4", b"")  # 27 글자 → LFN 3 + SFN 1 = 4 슬롯
    b.mkdir("/Z")
    b.add_file("/Z/z.txt", b"z")
    lim = dataclasses.replace(Limits(), max_dir_slots=48)  # '.' '..' + 46 슬롯: 11 항목(44) + 12번째 항목의 LFN 2 슬롯
    v = vol_of(b, lim)
    w = v.walk()
    big = [e for e in w["entries"] if e["path"].startswith("/BIG/")]
    assert len(big) == 11 and all(e["lfn_status"] == "ok" for e in big)
    assert w["orphans"] == []  # 한도에 걸친 LFN 조각을 고아(부분 이름)로 내지 않는다
    assert w["truncated_reason"] == "max_dir_slots" and "/Z/z.txt" in by_path(w)
    assert next(x for x in w["warnings"] if x["code"] == "dir_slot_limit")["path"] == "/BIG"


def test_fat_chain_longer_than_spec_maximum_is_reported_as_cut():
    """FAT 디렉터리 체인이 사양 최대(65536 슬롯)보다 길면 앞부분만 읽고 잘림으로 보고한다(예전: dir_too_large 경고만)."""
    b = fat16_small()  # 1 KiB 클러스터 = 32 슬롯 → 사양 최대는 2048 클러스터
    d = b.mkdir("/LOOPDIR")
    for i in range(30):
        b.add_file(f"/LOOPDIR/F{i:03d}.BIN", b"")
    cl = list(range(5000, 5000 + 2100))
    b.reserve(cl)
    b.write_chain([d.clusters[0]] + cl)
    unit = b"".join(b._sfn_entry(f"X{i:07d}BIN".encode(), 0x20, 0, 0, ctime=DEFAULT_TIME, mtime=DEFAULT_TIME, adate=None)
                    for i in range(32))
    b.write_clusters(cl, unit * len(cl))
    v = vol_of(b)
    w = v.walk()
    assert w["truncated_reason"] == "max_dir_slots" and w["cut_dirs"][0]["path"] == "/LOOPDIR"
    assert "dir_too_large" not in wcodes(w) and "dir_slot_limit" in wcodes(w)


# ---------------------------------------------------------------------------
# E4 max_depth · A-N7
# ---------------------------------------------------------------------------

def _deep_tree():
    b = fat16_small()
    for p in ("/a", "/a/b", "/a/b/c", "/a/b/c/d", "/z"):
        b.mkdir(p)
    b.add_file("/a/b/c/d/deep.txt", b"deep")
    b.add_file("/a/b/c/at3.txt", b"3")
    b.add_file("/z/later.txt", b"later")
    return b


def test_max_depth_cut_is_reported_and_the_walk_continues():
    b = _deep_tree()
    lim = dataclasses.replace(Limits(), max_depth=3)
    v = vol_of(b, lim)
    w = v.walk()
    paths = set(by_path(w))
    # 깊이 3 의 디렉터리(/a/b/c) 항목은 싣지만 안으로 내려가지 않는다 — 다른 가지(/z)는 계속 돈다
    assert {"/a", "/a/b", "/a/b/c", "/z/later.txt"} <= paths and not any(p.startswith("/a/b/c/") for p in paths)
    spec = by_path(w)["/a/b/c"]["child_dir"]
    assert w["truncated"] and w["truncated_reason"] == "max_depth"
    assert w["cut_dirs"] == [{"dirspec": spec, "path": "/a/b/c", "reason": "max_depth"}]
    reach = v.reachable_dirspecs()
    assert reach["status"] == "truncated" and reach["truncated_reason"] == "max_depth" and spec not in reach["dirspecs"]
    assert reach["cut_dirs"] == [{"dirspec": spec, "path": "/a/b/c", "reason": "max_depth"}]
    for p, depth in (("/a/b/c/d/deep.txt", 5), ("/a/b/c/at3.txt", 4)):
        with pytest.raises(FsError) as ei:
            v.lookup(p)
        assert ei.value.reason == "max_depth" and ei.value.data["depth"] == depth and ei.value.data["max_depth"] == 3
    assert v.lookup("/a/b/c")["name"] == "c"


def test_global_stop_reason_wins_and_all_reasons_are_listed():
    b = _deep_tree()
    for i in range(20):
        b.add_file(f"/z/f{i:02d}.bin", b"x")
    w = vol_of(b).walk(limits=dataclasses.replace(Limits(), max_depth=3, max_entries=12))
    assert w["truncated_reason"] == "max_entries" and w["truncated_reasons"] == ["max_entries", "max_depth"]


def test_budget_expiring_inside_the_last_chain_summary_marks_truncated():
    """A-N7: 항목 하나의 체인 요약 안에서 예산이 다 되면 walk 는 truncated 다(예전: false)."""
    img = H.fat32_long_chain(1, count=400_000)
    v = open_volume(BytesReader(img))
    w = v.walk(budget=Budget(None, 10_000))
    (e,) = w["entries"]
    assert e["chain"]["status"] == "limit" and e["chain"]["limit_reason"] == "steps"
    assert w["truncated"] and w["truncated_reason"] == "steps"


# ---------------------------------------------------------------------------
# E3 볼륨별 단계 상한 · 볼륨 예산
# ---------------------------------------------------------------------------

def test_step_cap_scales_per_volume_and_explicit_caps_stay_fixed(monkeypatch):
    legit = H.fat32_long_chain(1, count=300_000)  # 볼륨만 한 파일 하나 (체인 30만 클러스터)
    v = open_volume(BytesReader(legit))
    n = v._chain_clusters()
    assert n == 300_000
    assert v.step_cap() == max(FOLLOW_STEPS_FLOOR, 2 * n + Limits().max_total_slots)
    assert v.step_cap(Limits(max_follow_steps=1234)) == 1234
    # 바닥값을 낮추면 볼륨 크기에 비례한 상한이 드러난다
    monkeypatch.setattr(fsbase, "FOLLOW_STEPS_FLOOR", 1000)
    lim = dataclasses.replace(Limits(), max_total_slots=1000)
    v2 = open_volume(BytesReader(legit), limits=lim)
    assert v2.step_cap() == 2 * n + 1000
    w = v2.walk()  # 정상(겹치지 않는) 체인은 끝까지 따라간다
    assert not w["truncated"] and w["entries"][0]["chain"]["size_check"] != "unknown"
    fixed = open_volume(BytesReader(legit), limits=dataclasses.replace(lim, max_follow_steps=200_000))
    assert fixed.walk()["truncated_reason"] == "steps"  # 정수 상한은 그대로 쓴다
    # 같은 긴 체인을 여러 항목이 가리키는 조작 이미지는 볼륨 크기에 비례한 상한에서 멈춘다
    hostile = open_volume(BytesReader(H.fat32_long_chain(4, count=300_000)), limits=lim)
    wh = hostile.walk()
    assert wh["truncated_reason"] == "steps"
    assert sum(1 for e in wh["entries"] if e["chain"]["size_check"] != "unknown") <= 3


def test_open_volume_scales_the_shared_budget_and_never_lowers_it():
    img = H.fat32_long_chain(2, count=20_000_000 // 1000)
    lim = Limits()
    bud = Budget.for_limits(lim)
    assert bud.max_steps == FOLLOW_STEPS_FLOOR
    v = open_volume(BytesReader(img), limits=lim, budget=bud)
    assert bud.max_steps == v.step_cap(lim) >= FOLLOW_STEPS_FLOOR
    big = Budget(None, 1 << 40)
    open_volume(BytesReader(img), limits=lim, budget=big)
    assert big.max_steps == 1 << 40  # 내리지 않는다
    fixed = Budget.for_limits(Limits(max_follow_steps=500))
    open_volume(BytesReader(img), limits=Limits(max_follow_steps=500), budget=fixed)
    assert fixed.max_steps == 500
    ex = exfat_small()
    ex.add_file("/a.bin", b"a")
    eb = Budget.for_limits(lim)
    ev = open_volume(BytesReader(ex.image()), limits=lim, budget=eb)
    assert eb.max_steps == ev.step_cap(lim) and eb.steps > 0  # exFAT 은 열 때 루트를 이 예산으로 읽었다
    walk = ev.walk(budget=eb)
    assert walk["entries"][0]["name"] == "a.bin"


def test_budget_deadline_and_raise_steps():
    import time

    b = Budget(100, 10, deadline=time.monotonic() - 1)  # 이른 쪽(이미 지난 절대 마감)이 이긴다
    assert b.expired() and b.reason == "time"
    b2 = Budget(None, 10)
    b2.raise_steps(5)
    assert b2.max_steps == 10
    b2.raise_steps(50)
    assert b2.max_steps == 50
    unlimited = Budget(None, None)
    unlimited.raise_steps(50)
    assert unlimited.max_steps is None


# ---------------------------------------------------------------------------
# E5 짧은 이름 바이트
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("short", ["A+B.TXT", "A,B.TXT", "A;B.TXT", "A=B.TXT", "[AB].TXT", "A]B[.TXT"])
def test_msdos_short_name_bytes_are_accepted(short):
    """Linux msdos 드라이버가 쓰고 fsck.fat 이 받는 + , ; = [ ] 는 디렉터리 검증을 통과한다."""
    b = fat16_small()
    b.mkdir("/SUB")
    b.add_file("/SUB/KEEP.TXT", b"keep")
    b.add_file(f"/SUB/{short}", b"msdos", short=short, lfn=False)
    b.add_file("/SUB/TAIL.TXT", b"tail")
    w = vol_of(b).walk()
    assert w["unvalidated_dirs"] == []
    assert {"/SUB/KEEP.TXT", f"/SUB/{short}", "/SUB/TAIL.TXT"} <= set(by_path(w))


def test_deliberately_strict_checks_stay_and_are_visible():
    """속성 예약 비트는 일부러 엄격하다 — 그 클러스터는 unvalidated_dirs(사유 포함)로 드러난다."""
    b = fat16_small()
    b.mkdir("/SUB")
    r = b.add_file("/SUB/X.TXT", b"x")
    d = b.dirs["/SUB"]
    raw = bytearray(d.slots[r.slots[-1]])
    raw[11] |= 0x40
    d.slots[r.slots[-1]] = bytes(raw)
    w = vol_of(b).walk()
    assert w["unvalidated_dirs"][0]["reason"] == "attr_reserved" and "dir_unvalidated" in wcodes(w)


# ---------------------------------------------------------------------------
# A-N5 / B-N3 크기·교차 연결
# ---------------------------------------------------------------------------

def _patch_size(b, path: str, size: int, cluster: int | None = None, deleted: bool = False) -> None:
    rec = b.files[path]
    d = b.dirs[rec.dir_path]
    raw = bytearray(d.slots[rec.slots[-1]])
    struct.pack_into("<I", raw, 28, size)
    if cluster is not None:
        struct.pack_into("<H", raw, 26, cluster & 0xFFFF)
        struct.pack_into("<H", raw, 20, 0)
    if deleted:
        raw[0] = 0xE5
    d.slots[rec.slots[-1]] = bytes(raw)


def test_entry_size_beyond_the_data_area_rejects_the_unit():
    b = fat16_small()  # 데이터 영역 약 16 MiB
    b.mkdir("/SUB")
    b.add_file("/SUB/A.BIN", b"a")
    b.add_file("/SUB/B.BIN", b"b")
    _patch_size(b, "/SUB/B.BIN", 900_000_000)
    w = vol_of(b).walk()
    assert w["unvalidated_dirs"][0]["reason"] == "size_range"
    b2 = fat16_small()
    b2.mkdir("/SUB")
    b2.add_file("/SUB/A.BIN", b"a")
    b2.add_file("/SUB/B.BIN", b"b")
    _patch_size(b2, "/SUB/B.BIN", 900_000_000, deleted=True)  # 삭제 항목도 끝 표시 앞이면 검사한다
    assert vol_of(b2).walk()["unvalidated_dirs"][0]["reason"] == "size_range"


def test_live_file_with_size_needs_a_first_cluster():
    b = fat16_small()
    b.mkdir("/SUB")
    b.add_file("/SUB/A.BIN", b"a")
    b.add_file("/SUB/B.BIN", b"b")
    _patch_size(b, "/SUB/B.BIN", 5000, cluster=0)
    assert vol_of(b).walk()["unvalidated_dirs"][0]["reason"] == "size_without_cluster"
    b2 = fat16_small()  # 삭제 항목·빈 파일은 클러스터 0 이어도 된다
    b2.mkdir("/SUB")
    b2.add_file("/SUB/EMPTY.BIN", b"")
    b2.add_file("/SUB/B.BIN", b"b")
    _patch_size(b2, "/SUB/B.BIN", 5000, cluster=0, deleted=True)
    w2 = vol_of(b2).walk()
    assert w2["unvalidated_dirs"] == [] and "/SUB/EMPTY.BIN" in by_path(w2)


def _records(n: int) -> bytes:
    """8.3 슬롯 모양의 고정 폭 ASCII 레코드 (11번 바이트 공백, 26~27 숫자) — 녹화기 이벤트 로그 흉내."""
    out = bytearray()
    for i in range(n):
        rec = f"R{i:07d}EVT PLATE{i % 10000:04d}AB12Z{i % 100:02d}{i % 10000:04d}".encode()
        out += rec
    return bytes(out)


@pytest.mark.parametrize("kind", ["records", "random"])
def test_fat16_follow_on_directory_cluster_cross_linked_into_file_data(kind):
    """디렉터리의 첫 클러스터는 정상이고 FAT 항목이 다른 파일 중간으로 이어진다 — 이어지는 클러스터를 해석하지 않는다."""
    b = fat16_small()
    data = _records(2048) if kind == "records" else random.Random(5).randbytes(64 * 1024)
    f = b.add_file("/EVENTS.DAT", data)
    d = b.mkdir("/bigC")
    for i in range(30):
        b.add_file(f"/bigC/F{i:02d}.MP4", pattern(300 + i, 70 + i))
    assert len(b.dirs["/bigC"].clusters) == 1 and len(b.dirs["/bigC"].slots) == 32
    b.set_fat(d.clusters[0], f.clusters[len(f.clusters) // 2])
    w = vol_of(b).walk()
    kids = [e for e in w["entries"] if e["path"].startswith("/bigC/")]
    assert len(kids) == 30
    assert w["unvalidated_dirs"][0]["path"] == "/bigC" and w["unvalidated_dirs"][0]["reason"] == "cross_linked"
    blob = json.dumps(w, ensure_ascii=False)
    assert "PLATE" not in blob and "R0001" not in blob


def test_legit_multi_cluster_fat16_directory_and_stale_bytes_after_end_marker_are_accepted():
    b = fat16_small()
    d = b.mkdir("/DCIM", clusters=[400, 405, 410])
    for i in range(70):  # '.' '..' + 70 = 72 슬롯 = 클러스터 3 개(32 슬롯)에 걸침
        b.add_file(f"/DCIM/C{i:03d}.MP4", b"")
    img = bytearray(b.image())
    # 마지막 클러스터: 끝 표시(0x00) 뒤의 남은 바이트는 정상 기기의 버릇으로 받는다
    o = b.coff(410) + (72 - 64) * 32
    img[o:o + 32] = bytes(32)
    img[o + 32:b.coff(410) + b.cs] = random.Random(1).randbytes(b.coff(410) + b.cs - o - 32)
    w = open_volume(BytesReader(bytes(img))).walk()
    assert w["unvalidated_dirs"] == [] and d.clusters == [400, 405, 410]
    assert sum(1 for e in w["entries"] if e["path"].startswith("/DCIM/")) == 70


# ---------------------------------------------------------------------------
# A-N1 경로 글자 수
# ---------------------------------------------------------------------------

def test_max_path_chars_stops_the_walk_and_counts_shared_strings_once():
    b = fat32_small()
    b.mkdir("/" + "D" * 200)
    for i in range(40):
        b.add_file("/" + "D" * 200 + f"/file number {i:03d} with a long name.mp4", b"")
    v = vol_of(b)
    full = v.walk()
    assert not full["truncated"]
    e0 = full["entries"][1]
    assert e0["path"] is e0["display_path"]  # 같은 문자열은 하나만 둔다
    used = full["path_chars"]
    assert used == sum(len(e["path"]) for e in full["entries"])
    cap = used // 2
    w = v.walk(limits=dataclasses.replace(Limits(), max_path_chars=cap))
    assert w["truncated"] and w["truncated_reason"] == "max_path_chars" and w["path_chars"] <= cap
    assert 0 < len(w["entries"]) < len(full["entries"])
    reach = v.reachable_dirspecs(dataclasses.replace(Limits(), max_path_chars=10))
    assert reach["status"] == "truncated" and reach["truncated_reason"] == "max_path_chars"


def test_display_path_that_differs_is_counted_too():
    b = exfat_small()
    b.add_file("/a\x07b.mp4", b"bell")  # exFAT 이름에는 제어 문자가 들어갈 수 있다 — 표시 경로는 이스케이프
    w = vol_of(b).walk()
    (e,) = w["entries"]
    assert e["path"] == "/a\x07b.mp4" and e["display_path"] == "/a\\x07b.mp4"
    assert w["path_chars"] == len(e["path"]) + len(e["display_path"])


# ---------------------------------------------------------------------------
# B-N4 취소 · reachable_dirspecs(targets=)
# ---------------------------------------------------------------------------

def test_budget_cancel_predicate():
    b = Budget(None, None, cancel=lambda: True)
    assert b.expired() and b.reason == "cancelled"
    err = b.error("시험")
    assert err.reason == "budget_exceeded" and err.data["limit"] == "cancelled" and "취소" in err.message

    def boom() -> bool:
        raise RuntimeError("x")

    assert Budget(cancel=boom).reason == "cancelled"  # 확인할 수 없으면 멈춘다
    with pytest.raises(TypeError):
        Budget(cancel=5)  # type: ignore[arg-type]


def _tree_with_dirs(n: int):
    b = fat32_small()
    for i in range(n):
        b.mkdir(f"/D{i:02d}")
        b.mkdir(f"/D{i:02d}/S")
        b.add_file(f"/D{i:02d}/S/f.txt", b"f")
    return b


def test_walk_and_reachable_stop_when_cancelled():
    b = _tree_with_dirs(10)
    calls = {"n": 0}

    def cancel_after_some() -> bool:
        calls["n"] += 1
        return calls["n"] > 25

    w = vol_of(b).walk(budget=Budget(None, None, cancel=cancel_after_some))
    assert w["truncated"] and w["truncated_reason"] == "cancelled"
    calls["n"] = 0
    r = vol_of(b).reachable_dirspecs(budget=Budget(None, None, cancel=cancel_after_some))
    assert r["status"] == "truncated" and r["truncated_reason"] == "cancelled" and "root" in r["dirspecs"]


def test_reachable_targets_early_stop_complete_and_truncated_are_distinct():
    b = _tree_with_dirs(10)
    v = vol_of(b)
    full = v.reachable_dirspecs()
    assert full["status"] == "complete" and len(full["dirspecs"]) == 21 and "targets_found" not in full
    nothing = Budget(None, 0)  # 아무 단계도 쓰면 안 되는 예산 — 루트는 읽지 않아도 찾음이다
    r = vol_of(b).reachable_dirspecs(budget=nothing, targets={"root"})
    assert r["status"] == "targets_found" and r["dirspecs"] == {"root"} and nothing.steps == 0 and not r["truncated"]
    e = v.walk()
    deep = next(x["child_dir"] for x in e["entries"] if x["path"] == "/D09/S")
    r2 = vol_of(b).reachable_dirspecs(targets=[deep, "root"])
    assert r2["status"] == "targets_found" and r2["targets_found"] == sorted([deep, "root"]) and r2["targets_missing"] == []
    assert r2["paths"][deep] == "/D09/S"
    r3 = vol_of(b).reachable_dirspecs(targets={"c60000"})
    assert r3["status"] == "complete" and r3["targets_missing"] == ["c60000"]
    r4 = vol_of(b).reachable_dirspecs(Limits(max_follow_steps=40), targets={"c60000"})
    assert r4["status"] == "truncated" and r4["truncated_reason"] == "steps" and r4["dirspecs"] <= full["dirspecs"]
    assert vol_of(b).reachable_dirspecs(targets=[])["status"] == "targets_found"


# ---------------------------------------------------------------------------
# A-N4 요청한 후보·limit_reason
# ---------------------------------------------------------------------------

def test_requested_method_is_built_without_other_candidates_using_the_budget():
    img = H.exfat_chain_sets(1, chain_len=600_000, count=700_000, data_length=1 << 62)
    small = open_volume(BytesReader(img), limits=Limits(max_follow_steps=100_000))
    p = small.content_plan("root/3", method="skip-allocated")  # 예전: 남은 체인이 예산을 먼저 써 '방법이 없습니다'
    assert p.method == "skip-allocated" and p.status != "limit"
    c = small.content_plan("root/3", method="contiguous")
    assert c.method == "contiguous"
    s = small.content_plan("root/3", method="stale-chain")
    assert s.status == "limit" and s.extra["limit_reason"] == "steps"
    with pytest.raises(FsError) as ei:
        small.content_plan("root/3", method="fat-chain")
    assert ei.value.reason == "bad_argument" and "stale-chain" in ei.value.data["available"]


def test_requested_method_skipped_for_budget_raises_budget_exceeded():
    b = fat16_small()
    b.add_file("/A.MP4", pattern(6 * 1024, 31), clusters=[100, 101, 102, 110, 111, 112])
    b.add_file("/B.BIN", pattern(7 * 1024, 30), clusters=list(range(103, 110)))
    b.mkdir("/D")
    for i in range(1000):
        b.add_file(f"/D/F{i:04d}.MP4", b"")  # 슬롯 1002 개 — 삭제 항목 목록(walk)이 작은 예산을 다 쓴다
    b.delete("/A.MP4")
    b.delete("/B.BIN")
    v = vol_of(b)
    ref = next(e["ref"] for e in v.list_dir()["entries"] if e["deleted"] and e["first_cluster"] == 100)
    for method in ("skip-claimed", "skip-allocated"):
        fresh = vol_of(b)
        with pytest.raises(FsError) as ei:
            fresh.content_plan(ref, method=method, budget=Budget(None, 600))  # 루트는 읽고 삭제 항목 목록(/D)에서 다 됨
        assert ei.value.reason == "budget_exceeded" and ei.value.data["limit"] == "steps", method
    assert vol_of(b).read_content(ref, method="skip-claimed")["data"] == pattern(6 * 1024, 31)


def test_plan_status_limit_is_only_for_budget_stops():
    """크기보다 긴 남은 체인은 status 'ok' + chain_status 'limit'. status 'limit' 은 예산 멈춤에만 쓰고 limit_reason 을 단다."""
    b = fat16_small()
    b.add_file("/A.MP4", pattern(3 * 1024, 2), clusters=[200, 201, 202])
    b.delete("/A.MP4")
    b.write_chain([200, 201, 202, 203, 204])  # 지울 때 FAT 을 지우지 않은 구현 + 크기보다 긴 체인
    b.reserve([203, 204])
    v = vol_of(b)
    ref = next(e["ref"] for e in v.list_dir()["entries"] if e["deleted"])
    pf = v.content_plan(ref, method="fat-chain")
    assert pf.status == "ok" and pf.extra["chain_status"] == "limit" and "limit_reason" not in pf.extra
    ev = open_volume(BytesReader(H.exfat_chain_sets(1, chain_len=5000, count=20_000, data_length=1000 * 512)))
    st = ev.content_plan("root/3", method="stale-chain")
    assert st.status == "ok" and st.extra["chain_status"] == "limit" and st.clusters == 1000
    # 취소로 멈춘 계획: status 'limit', limit_reason 'cancelled' (모은 클러스터가 있으면 돌려준다)
    lv = open_volume(BytesReader(H.fat32_long_chain(1, count=300_000)))
    e = lv.entry("root/1")
    calls = {"n": 0}

    def cancel_on_third() -> bool:
        calls["n"] += 1
        return calls["n"] >= 3  # follow_chain: 시작에서 한 번, 그 뒤 4096 걸음마다 확인

    (plan,) = lv._candidate_plans(e, "data", Budget(None, None, cancel=cancel_on_third))
    d = plan.to_dict()
    assert d["status"] == "limit" and d["limit_reason"] == "cancelled" and 0 < d["clusters"] < 300_000
    assert "취소" in d["note"]
    fresh = open_volume(BytesReader(H.fat32_long_chain(1, count=300_000)))
    state = {"planning": False}
    real = fresh._candidate_plans

    def planning(*a, **kw):
        state["planning"] = True  # 후보를 만들기 시작한 뒤 취소 — 체인 시작에서 멈춰 클러스터 0 개
        return real(*a, **kw)

    fresh._candidate_plans = planning  # type: ignore[method-assign]
    with pytest.raises(FsError) as ei:  # 클러스터를 하나도 모으지 못하면 계획 대신 budget_exceeded
        fresh.content_plan("root/1", budget=Budget(None, None, cancel=lambda: state["planning"]))
    assert ei.value.reason == "budget_exceeded" and ei.value.data["limit"] == "cancelled"


def test_auto_plan_skips_candidates_that_collected_nothing_for_budget():
    """method='auto': 예산 때문에 클러스터를 하나도 모으지 못한 후보(stale-chain)를 고르지 않고 다음 후보(contiguous)를 쓴다."""
    img = H.exfat_chain_sets(1, chain_len=5000, count=20_000)
    v = open_volume(BytesReader(img))
    state = {"planning": False}
    real = v._candidate_plans

    def planning(*a, **kw):
        state["planning"] = True  # 후보를 만들기 시작한 뒤에 취소된다 — stale-chain 은 체인 시작에서 멈춘다(0 클러스터)
        return real(*a, **kw)

    v._candidate_plans = planning  # type: ignore[method-assign]
    p = v.content_plan("root/3", budget=Budget(None, None, cancel=lambda: state["planning"]))
    assert p.method == "contiguous" and p.clusters == 5000
