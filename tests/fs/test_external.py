"""외부 도구 교차 확인 (있을 때만): mkfs.fat(dosfstools) BPB·클러스터 수, sgdisk GPT + mkfs.fat --offset.

mkfs.fat -v 의 "FAT size is N sectors, and provides M clusters" 를 엔진의 fat_size_sectors / cluster_count 와 비교한다.
도구가 없으면 skip. 모든 하위 프로세스는 tmp_path 안의 일반 파일만 다루고 timeout 을 둔다.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
from pathlib import Path

import pytest

from pweh.fs import FatVolume, ImageReader, detect_partitions, open_volume, partition_source

pytestmark = pytest.mark.external


def tool(name: str) -> str | None:
    found = shutil.which(name)
    if found:
        return found
    for d in ("/usr/sbin", "/sbin"):
        p = Path(d) / name
        if p.is_file() and os.access(p, os.X_OK):
            return str(p)
    return None


def run(args: list[str]) -> str:
    out = subprocess.run(args, capture_output=True, text=True, timeout=60)
    assert out.returncode == 0, out.stdout + out.stderr
    return out.stdout + out.stderr


def blank(path: Path, size: int) -> None:
    with open(path, "wb") as fh:
        fh.truncate(size)


@pytest.mark.parametrize("fat,mib,extra", [(12, 4, []), (16, 32, []), (32, 64, []), (16, 64, ["-S", "4096"])])
def test_mkfs_fat_bpb_matches(tmp_path, fat, mib, extra):
    mkfs = tool("mkfs.fat")
    if not mkfs:
        pytest.skip("mkfs.fat 없음")
    img = tmp_path / f"f{fat}.img"
    blank(img, mib << 20)
    out = run([mkfs, "--invariant", "-v", "-F", str(fat), "-n", "PWEHLBL", *extra, str(img)])
    m = re.search(r"FAT size is (\d+) sectors, and provides (\d+) clusters", out)
    assert m, out
    with ImageReader(img) as r:
        v = FatVolume(r)
        info = v.info()
        assert info["fs_type"] == f"fat{fat}"
        assert info["fat_size_sectors"] == int(m.group(1))
        assert info["cluster_count"] == int(m.group(2))
        assert info["bytes_per_sector"] == (4096 if extra else 512)
        assert info["volume_id"] == "1234-ABCD" and info["volume_label"] == "PWEHLBL"
        assert info["oem_name"] == "mkfs.fat" and info["warnings"] == []
        assert info["state"]["dirty"] is False
        w = v.walk()
        assert w["entries"] == [] and w["warnings"] == []
        rep = v.cluster_report()
        assert rep["allocated_unreferenced"] == 0 and rep["fat_copies"]["differing_bytes"] == 0
        if fat == 32:
            assert info["fat32"]["fsinfo"]["valid"] and info["fat32"]["backup_boot"]["matches_primary"]
        lay = detect_partitions(r)
        assert lay["scheme"] == "superfloppy" and lay["partitions"][0]["fs_hint"] == f"fat{fat}"


def test_mkfs_fat_fake_mbr_is_superfloppy(tmp_path):
    mkfs = tool("mkfs.fat")
    if not mkfs:
        pytest.skip("mkfs.fat 없음")
    img = tmp_path / "mbr.img"
    blank(img, 32 << 20)
    run([mkfs, "--invariant", "--mbr=y", "-F", "16", str(img)])
    with ImageReader(img) as r:
        lay = detect_partitions(r)
        assert lay["scheme"] == "superfloppy"
        assert "superfloppy_partition_like_bytes" in [w["code"] for w in lay["warnings"]]
        assert open_volume(r).info()["fs_type"] == "fat16"


def test_sgdisk_gpt_with_fat32_partition(tmp_path):
    sgdisk, mkfs = tool("sgdisk"), tool("mkfs.fat")
    if not sgdisk or not mkfs:
        pytest.skip("sgdisk 또는 mkfs.fat 없음")
    img = tmp_path / "gpt.img"
    blank(img, 80 << 20)
    run([sgdisk, "-n", "1:2048:+40M", "-c", "1:SDDATA", "-t", "1:0700", str(img)])
    run([mkfs, "--invariant", "--offset=2048", "-F", "32", "-n", "GPTFAT", str(img), "40960"])
    with ImageReader(img) as r:
        lay = detect_partitions(r)
        assert lay["scheme"] == "gpt" and lay["sector_size"] == 512 and lay["warnings"] == []
        g = lay["gpt"]
        assert g["entries_crc_ok"] is True and g["backup"]["header_crc_ok"] is True
        (p,) = lay["partitions"]
        assert p["gpt_name"] == "SDDATA" and p["type_name"] == "Microsoft basic data"
        assert p["start_lba"] == 2048 and p["size_sectors"] == 40 * 2048 and p["fs_hint"] == "fat32"
        info = open_volume(partition_source(r, p)).info()
        assert info["fs_type"] == "fat32" and info["volume_label"] == "GPTFAT" and info["warnings"] == []
