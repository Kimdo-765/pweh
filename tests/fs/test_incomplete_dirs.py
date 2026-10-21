"""pweh.fs: 끝까지 읽지 못한 디렉터리의 정직한 보고.

- 잘린 이미지: 디렉터리 데이터가 이미지 끝 너머 → DirResult.incomplete='beyond_image'.
- 손상된 카드: 끝 표시 전에 클러스터 체인이 비정상으로 끝남 → 'dir_chain_broken' (exFAT 은 DataLength 보다 짧은 체인 포함).
- 읽지 못한 디렉터리 → 'dir_unreadable'.
- 살아 있는 디렉터리만 잘림(cut_dirs·truncated)으로 센다. 삭제된 디렉터리는 원래 최선 노력이라 경고만 남긴다.
- 끝 표시가 있었으면 체인이 그 뒤에서 망가져도 빠진 것이 없다.
- walk 의 unvalidated_dirs_live 는 살아 있는 디렉터리 중 검증하지 못한 것만 센다.

이미지는 작고 합성이다(tests/fs/builders.py).
"""

from __future__ import annotations

import pytest

from fs.builders import exfat_small, fat16_small, fat32_small
from pweh.fs import BytesReader, FsError, open_volume


def by_path(walk: dict) -> dict[str, dict]:
    return {e["path"]: e for e in walk["entries"]}


def wcodes(res: dict) -> list[str]:
    return [w["code"] for w in res["warnings"]]


def _far_dir_card():
    """FAT32: 앞쪽에 /A(파일 하나), 볼륨 끝쪽 클러스터에 /FAR(파일 하나), 루트에 /Z.TXT."""
    b = fat32_small(label="CAMSD")
    b.mkdir("/A")
    b.add_file("/A/a.txt", b"a")
    far = b.max_cluster - 10
    b.mkdir("/FAR", clusters=[far])
    b.add_file("/FAR/f.txt", b"f")
    b.add_file("/Z.TXT", b"z")
    return b, far


def test_live_directory_beyond_the_image_end_is_cut_and_the_walk_continues():
    b, far = _far_dir_card()
    full = b.image()
    w0 = open_volume(BytesReader(full)).walk()
    assert not w0["truncated"] and w0["cut_dirs"] == [] and "/FAR/f.txt" in by_path(w0)
    v = open_volume(BytesReader(full[:b.coff(far)]))  # /FAR 의 디렉터리 클러스터가 이미지 끝 너머
    assert v.info()["truncated"]
    w = v.walk()
    paths = by_path(w)
    spec = paths["/FAR"]["child_dir"]
    assert {"/A/a.txt", "/Z.TXT", "/FAR"} <= set(paths) and not any(p.startswith("/FAR/") for p in paths)
    assert w["truncated"] and w["truncated_reason"] == "beyond_image" and w["truncated_reasons"] == ["beyond_image"]
    assert w["cut_dirs"] == [{"dirspec": spec, "path": "/FAR", "reason": "beyond_image"}] and w["cut_dirs_total"] == 1
    assert paths["/FAR"]["chain"]["incomplete"] == "beyond_image" and "dir_beyond_image" in wcodes(w)
    reach = v.reachable_dirspecs()
    assert reach["status"] == "truncated" and reach["truncated_reasons"] == ["beyond_image"] and spec in reach["dirspecs"]
    with pytest.raises(FsError) as ei:
        v.lookup("/FAR/f.txt")
    assert ei.value.reason == "beyond_image" and ei.value.data["component"] == 2
    assert v.lookup("/A/a.txt")["name"] == "a.txt"
    with pytest.raises(FsError) as ei:  # 읽지 못한 뒤쪽을 가리키는 ref
        v.entry(f"{spec}/5")
    assert ei.value.data["dir_cut"] == "beyond_image"


def test_root_beyond_the_image_end_lists_nothing_and_says_so():
    """부트 섹터·FAT 뒤에서 잘린 이미지: 루트를 읽지 못했으니 빈 목록은 '완전'이 아니다."""
    b, _ = _far_dir_card()
    v = open_volume(BytesReader(b.image()[:b.data_off]))
    w = v.walk()
    assert w["entries"] == [] and w["truncated"] and w["cut_dirs"] == [{"dirspec": "root", "path": "/", "reason": "beyond_image"}]


def test_fat16_fixed_root_cut_by_the_image_end_is_reported():
    b = fat16_small(label="CAMSD")
    for i in range(40):
        b.add_file(f"/F{i:03d}.BIN", b"x")
    v = open_volume(BytesReader(b.image()[:b.root_off + 512]))  # 고정 루트의 첫 섹터(16 슬롯)만 이미지 안
    w = v.walk()
    assert len(w["entries"]) == 15 and w["truncated_reasons"] == ["beyond_image"]
    assert w["cut_dirs"] == [{"dirspec": "root", "path": "/", "reason": "beyond_image"}]


def test_live_directory_chain_broken_before_the_end_marker_is_cut():
    b = fat32_small(label="CAMSD")
    b.mkdir("/DCIM", clusters=[400, 405])
    for i in range(20):  # '.' '..' + 20 = 22 슬롯 > 클러스터 하나(16 슬롯)
        b.add_file(f"/DCIM/C{i:03d}.MP4", b"")
    b.add_file("/Z.TXT", b"z")
    b.set_fat(400, 0)  # 첫 클러스터 뒤 체인이 빈 항목 — 첫 클러스터에는 끝 표시가 없다
    v = open_volume(BytesReader(b.image()))
    w = v.walk()
    paths = by_path(w)
    assert sorted(p for p in paths if p.startswith("/DCIM/")) == [f"/DCIM/C{i:03d}.MP4" for i in range(14)]
    assert "/Z.TXT" in paths and "dir_chain_zeroed" in wcodes(w)
    spec = paths["/DCIM"]["child_dir"]
    assert w["truncated"] and w["cut_dirs"] == [{"dirspec": spec, "path": "/DCIM", "reason": "dir_chain_broken"}]
    reach = v.reachable_dirspecs()
    assert reach["status"] == "truncated" and reach["truncated_reasons"] == ["dir_chain_broken"]
    with pytest.raises(FsError) as ei:
        v.lookup("/DCIM/C019.MP4")
    assert ei.value.reason == "dir_chain_broken"
    assert v.lookup("/DCIM/C000.MP4")["name"] == "C000.MP4"


def test_broken_chain_after_the_end_marker_loses_nothing():
    b = fat32_small(label="CAMSD")
    b.mkdir("/LOG")
    b.add_file("/LOG/A.TXT", b"a")
    b.set_fat(b.dirs["/LOG"].clusters[0], 0)  # 체인은 망가졌지만 첫 클러스터 안에 끝 표시가 있다
    v = open_volume(BytesReader(b.image()))
    w = v.walk()
    assert "/LOG/A.TXT" in by_path(w) and not w["truncated"] and w["cut_dirs"] == []
    assert v.reachable_dirspecs()["status"] == "complete" and v.lookup("/LOG/NOPE.TXT") is None


@pytest.mark.parametrize("deleted", [False, True])
def test_only_live_directories_count_as_cut(deleted):
    """같은 자리(이미지 끝에 걸린 디렉터리 클러스터)라도 삭제된 디렉터리면 잘림이 아니다 — 경고만."""
    b = fat32_small(label="CAMSD")
    far = b.max_cluster - 10
    b.mkdir("/OLD", clusters=[far])
    b.add_file("/OLD/X.TXT", b"x")
    if deleted:
        b.delete("/OLD/X.TXT")
        b.delete("/OLD")
    b.add_file("/KEEP.TXT", b"k")
    v = open_volume(BytesReader(b.image()[:b.coff(far) + 64]))  # '.'·'..' 만 이미지 안
    w = v.walk()
    assert "/KEEP.TXT" in by_path(w) and "dir_beyond_image" in wcodes(w)  # 두 경우 모두 그 디렉터리를 읽었다
    if deleted:
        assert not w["truncated"] and w["cut_dirs"] == [] and v.reachable_dirspecs()["status"] == "complete"
    else:
        assert w["truncated_reasons"] == ["beyond_image"] and [c["path"] for c in w["cut_dirs"]] == ["/OLD"]
        assert v.reachable_dirspecs()["status"] == "truncated"


def test_unreadable_live_directory_is_cut(monkeypatch):
    b = fat32_small(label="CAMSD")
    b.mkdir("/A")
    b.add_file("/A/a.txt", b"a")
    b.add_file("/Z.TXT", b"z")
    v = open_volume(BytesReader(b.image()))
    spec = v.lookup("/A")["child_dir"]
    real = type(v)._parse_dir

    def boom(self, s, budget=None, **kw):
        if s == spec:
            raise FsError("읽기 오류(시험)", reason="io_error")
        return real(self, s, budget, **kw)

    monkeypatch.setattr(type(v), "_parse_dir", boom)
    v._dir_cache.clear()
    w = v.walk()
    assert "/Z.TXT" in by_path(w) and "dir_unreadable" in wcodes(w)
    assert w["cut_dirs"] == [{"dirspec": spec, "path": "/A", "reason": "dir_unreadable"}]
    assert v.reachable_dirspecs()["truncated_reasons"] == ["dir_unreadable"]


def test_unvalidated_dirs_live_counts_only_live_directories():
    b = fat32_small(label="CAMSD")
    b.mkdir("/OLD")
    b.add_file("/OLD/X.TXT", b"x")
    b.delete("/OLD/X.TXT")
    old = b.delete("/OLD")
    c = old.clusters[0]
    img = bytearray(b.image())
    img[b.coff(c) + 64:b.coff(c) + b.cs] = b"\xff" * (b.cs - 64)  # '.'·'..' 뒤가 디렉터리 데이터가 아니다(재사용 흉내)
    w = open_volume(BytesReader(bytes(img))).walk()
    assert w["unvalidated_dirs_total"] == 1 and w["unvalidated_dirs_live"] == 0 and not w["truncated"]
    b2 = fat32_small(label="CAMSD")
    b2.mkdir("/DCIM")
    b2.add_file("/DCIM/A.MP4", b"a")
    img2 = bytearray(b2.image())
    c2 = b2.dirs["/DCIM"].clusters[0]
    img2[b2.coff(c2) + 64:b2.coff(c2) + b2.cs] = b"\xff" * (b2.cs - 64)
    w2 = open_volume(BytesReader(bytes(img2))).walk()
    assert w2["unvalidated_dirs_total"] == 1 and w2["unvalidated_dirs_live"] == 1
    assert not w2["truncated"], "검증하지 못한 디렉터리는 엔진의 잘림 사유가 아니다(unvalidated_dirs 로 남는다)"


def test_exfat_directory_beyond_the_image_end_is_cut():
    b = exfat_small(label="CAMEX")
    b.mkdir("/A")
    b.add_file("/A/a.bin", b"a")
    far = b.max_cluster - 4
    b.mkdir("/FAR", clusters=[far])
    b.add_file("/FAR/f.bin", b"f")
    full = b.image()
    assert not open_volume(BytesReader(full)).walk()["truncated"]
    v = open_volume(BytesReader(full[:b.coff(far)]))
    w = v.walk()
    assert "/A/a.bin" in by_path(w) and w["truncated_reasons"] == ["beyond_image"]
    assert [c["path"] for c in w["cut_dirs"]] == ["/FAR"]


def test_exfat_directory_chain_shorter_than_its_data_length_is_cut():
    """FAT 체인으로 이은 두 클러스터 디렉터리의 체인이 첫 클러스터에서 끝난다(DataLength 보다 짧음) — 첫 클러스터가 꽉 차 끝 표시가
    없으면 뒤쪽 항목이 빠졌을 수 있다."""
    b = exfat_small(label="CAMEX")
    a, c = 300, 310
    b.mkdir("/D", clusters=[a, c], contiguous=False)
    slots_per_cluster = b.cs // 32
    names = [f"f{i:03d}.bin" for i in range(slots_per_cluster // 3 - 2)]  # 3 슬롯 집합(이름 15 자 이하)
    names += [f"long-name-{i:02d}-x.bin" for i in range(2)]  # 4 슬롯 집합(이름 16~30 자)
    assert 3 * (len(names) - 2) + 4 * 2 == slots_per_cluster
    for n in names + [f"g{i}.bin" for i in range(5)]:
        b.add_file(f"/D/{n}", b"")
    b.set_fat(a, 0xFFFFFFFF)  # 체인이 첫 클러스터에서 끝난다 — DataLength 는 두 클러스터
    v = open_volume(BytesReader(b.image()))
    w = v.walk()
    got = sorted(e["name"] for e in w["entries"] if e["path"].startswith("/D/"))
    assert got == sorted(names) and "dir_chain_short" in wcodes(w)
    assert w["truncated_reasons"] == ["dir_chain_broken"] and [c["path"] for c in w["cut_dirs"]] == ["/D"]
    with pytest.raises(FsError) as ei:
        v.lookup("/D/g0.bin")
    assert ei.value.reason == "dir_chain_broken"


def test_list_dir_reports_an_incomplete_directory():
    b, far = _far_dir_card()
    v = open_volume(BytesReader(b.image()[:b.coff(far)]))
    d = v.list_dir(v.lookup("/FAR")["child_dir"])
    assert d["truncated"] and d["truncated_reasons"] == ["beyond_image"] and d["chain"]["incomplete"] == "beyond_image"


def test_exfat_chain_that_covers_the_data_length_is_not_cut_even_if_its_last_entry_is_broken():
    """exFAT 디렉터리의 크기는 DataLength 다: 두 클러스터가 꽉 찼고(끝 표시 없음) 체인이 DataLength 를 다 덮었는데 마지막 FAT 항목만
    0 이면 빠진 것이 없다 — 경고(dir_chain_zeroed)만 남고 잘림이 아니다."""
    b = exfat_small(label="CAMEX")
    a, c = 300, 310
    b.mkdir("/D", clusters=[a, c], contiguous=False)
    per = 2 * (b.cs // 32)  # 두 클러스터의 슬롯
    names = [f"f{i:03d}.bin" for i in range((per - 4) // 3)] + ["long-name-00-x.bin"]  # 3 슬롯 집합들 + 4 슬롯 집합 하나
    assert 3 * (len(names) - 1) + 4 == per
    for n in names:
        b.add_file(f"/D/{n}", b"")
    b.set_fat(c, 0)  # 마지막 클러스터의 FAT 항목만 빈 항목(EOC 가 아님)
    v = open_volume(BytesReader(b.image()))
    w = v.walk()
    assert sorted(e["name"] for e in w["entries"] if e["path"].startswith("/D/")) == sorted(names)
    assert "dir_chain_zeroed" in wcodes(w) and not w["truncated"] and w["cut_dirs"] == []
    assert v.lookup("/D/nope.bin") is None


def test_case_folded_match_is_not_trusted_in_an_incomplete_directory():
    """끝까지 읽지 못한 디렉터리에서는 정확히 같은 이름만 믿는다: 읽은 부분의 C000.MP4(대소문자만 맞음)를 고르면, 읽지 못한 뒤쪽의
    c000.mp4(다른 파일)를 엉뚱한 파일로 내게 된다."""
    b = fat32_small(label="CAMSD")
    b.mkdir("/FAR", clusters=[400, 405])
    for i in range(13):
        b.add_file(f"/FAR/A{i:03d}.MP4", b"a")
    b.add_file("/FAR/C000.MP4", b"file A")  # '.' '..' + 14 = 16 슬롯 — 첫 클러스터가 꽉 찬다(끝 표시 없음)
    b.add_file("/FAR/c000.mp4", b"file B")  # LFN + 8.3 별칭 — 둘째 클러스터
    full = open_volume(BytesReader(b.image()))
    assert full.lookup("/FAR/c000.mp4")["name"] == "c000.mp4" and full.lookup("/FAR/C000.MP4")["name"] == "C000.MP4"
    b.set_fat(400, 0)  # 첫 클러스터 뒤 체인이 끊긴다 — 둘째 클러스터를 읽지 못한다
    v = open_volume(BytesReader(b.image()))
    assert v.lookup("/FAR/C000.MP4")["name"] == "C000.MP4"  # 정확히 같은 이름은 받는다
    with pytest.raises(FsError) as ei:
        v.lookup("/FAR/c000.mp4")
    assert ei.value.reason == "dir_chain_broken" and "대소문자만 맞는" in ei.value.message
    with pytest.raises(FsError) as ei:
        v.lookup("/FAR/a000.mp4")  # 대소문자만 맞는 것은 고르지 않는다(완전히 읽은 디렉터리였다면 A000.MP4)
    assert ei.value.reason == "dir_chain_broken"


def test_exfat_dir_longer_than_the_slot_cap_stays_cut_even_if_the_chain_breaks_at_the_cap():
    """DataLength 가 슬롯 한도보다 긴 FAT 체인 디렉터리에서 한도 자리 클러스터의 FAT 항목이 0 이어도(체인이 한도 자리에서 끊김) 한도에서
    잘린 디렉터리다 — '읽을 길이만큼 다 모았다'(covered)가 max_dir_slots 잘림을 가리지 않는다."""
    import dataclasses

    from pweh.fs import Limits

    b = exfat_small(label="CAMEX")
    a, m, z = 300, 310, 320
    b.mkdir("/D", clusters=[a, m, z], contiguous=False)
    per = b.cs // 32
    for i in range(per):  # 3 슬롯 집합 per 개 = 세 클러스터를 꽉 채운다(끝 표시 없음)
        b.add_file(f"/D/f{i:04d}.bin", b"")
    lim = dataclasses.replace(Limits(), max_dir_slots=2 * per)  # 한도 = 두 클러스터
    full = open_volume(BytesReader(b.image()), limits=lim).walk()
    assert full["truncated_reasons"] == ["max_dir_slots"] and [c["path"] for c in full["cut_dirs"]] == ["/D"]
    b.set_fat(m, 0)  # 한도 자리(둘째 클러스터)의 FAT 항목이 빈 항목 — 체인이 거기서 끊긴다
    v = open_volume(BytesReader(b.image()), limits=lim)
    w = v.walk()
    assert w["truncated_reasons"] == ["max_dir_slots"] and [c["path"] for c in w["cut_dirs"]] == ["/D"], w["truncated_reasons"]
    assert "dir_chain_zeroed" in wcodes(w)
    with pytest.raises(FsError) as ei:
        v.lookup("/D/nope.bin")
    assert ei.value.reason == "max_dir_slots"


def test_unreadable_directory_on_a_path_or_a_ref_is_dir_unreadable(monkeypatch):
    """경로·ref 의 디렉터리를 읽지 못하면(읽기 오류 등) 엔진의 날 사유(io_error)가 아니라 dir_unreadable 로 알린다 — 목록의 cut_dirs 와
    같은 사유라 추출 결과의 잘림 사유가 된다."""
    b = fat32_small(label="CAMSD")
    b.mkdir("/A")
    b.add_file("/A/a.txt", b"a")
    v = open_volume(BytesReader(b.image()))
    spec = v.lookup("/A")["child_dir"]
    ref = v.lookup("/A/a.txt")["ref"]
    real = type(v)._parse_dir

    def boom(self, s, budget=None, **kw):
        if s == spec:
            raise FsError("읽기 오류(시험)", reason="io_error")
        return real(self, s, budget, **kw)

    monkeypatch.setattr(type(v), "_parse_dir", boom)
    v._dir_cache.clear()
    with pytest.raises(FsError) as ei:
        v.lookup("/A/a.txt")
    assert ei.value.reason == "dir_unreadable" and ei.value.data["cause"] == "io_error" and ei.value.data["component"] == 2
    with pytest.raises(FsError) as ei:
        v.entry(ref)
    assert ei.value.reason == "bad_ref" and ei.value.data["dir_cut"] == "dir_unreadable"
