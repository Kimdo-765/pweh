"""pweh.fs.volume: MBR/EBR/GPT/superfloppy 감지, CRC·순환·겹침·잘림 경고."""

from __future__ import annotations

import struct

import pytest

from fs.builders import (
    GUID_BASIC_DATA,
    GUID_LINUX,
    ExfatBuilder,
    FatBuilder,
    GptPart,
    exfat_small,
    fat12_small,
    put_ebr,
    put_gpt,
    put_mbr,
)
from pweh.fs import BytesReader, FsError, ImageReader, detect_partitions, open_volume, partition_source, sniff_fs


def codes(res) -> list[str]:
    return [w["code"] for w in res["warnings"]]


def fat12_volume(label: str = "VOL") -> bytes:
    b = fat12_small(label=label)
    b.add_file("/HELLO.TXT", b"hello " + label.encode())
    return b.image()


def place(img: bytearray, lba: int, data: bytes, ss: int = 512) -> None:
    img[lba * ss:lba * ss + len(data)] = data


def mbr_with_logicals() -> tuple[bytearray, dict]:
    vol = fat12_volume("P1")
    vsec = len(vol) // 512
    p1 = 2048
    ext = p1 + vsec
    ebr1 = ext
    l1 = ebr1 + 63
    ebr2 = l1 + vsec
    l2 = ebr2 + 63
    total = l2 + vsec + 100
    img = bytearray(total * 512)
    place(img, p1, vol)
    place(img, l1, fat12_volume("L1"))
    place(img, l2, fat12_volume("L2"))
    put_mbr(img, [(0x01, p1, vsec, True), (0x0F, ext, total - ext)])
    put_ebr(img, ebr1, (0x01, 63, vsec), (ebr2 - ext, 63 + vsec))
    put_ebr(img, ebr2, (0x01, 63, vsec), None)
    return img, {"p1": p1, "l1": l1, "l2": l2, "ext": ext, "ebr1": ebr1, "ebr2": ebr2}


def test_mbr_primary_and_logicals(tmp_path):
    img, lay = mbr_with_logicals()
    path = tmp_path / "card.img"
    path.write_bytes(img)
    with ImageReader(path) as r:
        res = detect_partitions(r)
        assert res["scheme"] == "mbr" and res["sector_size"] == 512
        parts = res["partitions"]
        assert [p["index"] for p in parts] == [1, 5, 6]
        assert [p["role"] for p in parts] == ["primary", "logical", "logical"]
        assert [p["start_lba"] for p in parts] == [lay["p1"], lay["l1"], lay["l2"]]
        assert all(p["fs_hint"] == "fat12" for p in parts)
        assert parts[0]["bootable"] and not parts[1]["bootable"]
        assert parts[0]["type_id"] == "0x01" and parts[0]["type_name"] == "FAT12"
        assert parts[1]["ebr_lba"] == lay["ebr1"]
        assert res["mbr"]["extended"][0]["start_lba"] == lay["ext"]
        assert codes(res) == []
        labels = []
        for p in parts:
            vol = open_volume(partition_source(r, p))
            info = vol.info()
            labels.append(info["volume_label"])
            assert vol.lookup("/HELLO.TXT")["size"] > 0
        assert labels == ["P1", "L1", "L2"]


def test_ebr_loop_is_detected():
    img, lay = mbr_with_logicals()
    # 두 번째 EBR 의 다음 링크가 첫 EBR 을 가리키게
    put_ebr(img, lay["ebr2"], (0x01, 63, 100), (0, 100))
    res = detect_partitions(BytesReader(img))
    assert "ebr_loop" in codes(res)
    assert [p["index"] for p in res["partitions"]] == [1, 5, 6]


def test_ebr_chain_count_limit():
    n = 140
    ext = 64
    total = ext + n * 2 + 16
    img = bytearray(total * 512)
    put_mbr(img, [(0x0F, ext, total - ext)])
    for i in range(n):
        lba = ext + 2 * i
        put_ebr(img, lba, (0x83, 1, 1), ((lba + 2 - ext), 2) if i < n - 1 else None)
    res = detect_partitions(BytesReader(img))
    assert "ebr_too_many" in codes(res)
    assert len(res["partitions"]) == 128


def test_ebr_link_outside_extended_stops():
    img, lay = mbr_with_logicals()
    put_ebr(img, lay["ebr1"], (0x01, 63, 100), (10_000_000, 100))
    res = detect_partitions(BytesReader(img))
    assert "ebr_link_outside" in codes(res)
    assert [p["index"] for p in res["partitions"]] == [1, 5]


def gpt_image(ss: int = 512, *, vol: bytes | None = None, name: str = "SDDATA") -> tuple[bytearray, int]:
    vol = vol if vol is not None else exfat_small().image()
    first = (1 << 20) // ss
    vsec = len(vol) // ss
    total = first + vsec + (1 << 20) // ss
    img = bytearray(total * ss)
    place(img, first, vol, ss)
    put_gpt(img, [GptPart(first, first + vsec - 1, name=name, attributes=(1 << 63) | 4),
                  GptPart(first + vsec, first + vsec + 7, type_guid=GUID_LINUX,
                          unique_guid="99999999-8888-7777-6666-555555555555", name="spare")], sector=ss)
    return img, first


def test_gpt_valid(tmp_path):
    img, first = gpt_image()
    p = tmp_path / "gpt.img"
    p.write_bytes(img)
    with ImageReader(p) as r:
        res = detect_partitions(r)
        assert res["scheme"] == "gpt" and res["sector_size"] == 512
        assert codes(res) == []
        g = res["gpt"]
        assert g["used"] == "primary" and g["entries_crc_ok"] is True and g["backup_entries_crc_ok"] is True
        assert g["primary"]["header_crc_ok"] and g["backup"]["header_crc_ok"]
        assert g["disk_guid"] == "A1B2C3D4-0000-4000-8000-000000000001"
        p1, p2 = res["partitions"]
        assert p1["gpt_name"] == "SDDATA" and p1["type_id"] == GUID_BASIC_DATA
        assert p1["type_name"] == "Microsoft basic data" and p1["fs_hint"] == "exfat"
        assert p1["start_offset"] == first * 512 and p1["bootable"] is True
        assert set(p1["gpt_attribute_flags"]) == {"legacy_bios_bootable", "no_drive_letter"}
        assert p1["alignment"]["aligned_4mib"] is False and p1["alignment"]["aligned_to"] == 1 << 20
        assert p2["type_name"] == "Linux filesystem" and p2["gpt_guid"] == "99999999-8888-7777-6666-555555555555"
        vol = open_volume(partition_source(r, p1))
        assert vol.info()["fs_type"] == "exfat"


def test_gpt_header_crc_mismatch_uses_backup():
    img, _ = gpt_image()
    struct.pack_into("<Q", img, 512 + 40, 40)  # FirstUsableLBA 를 바꾸고 CRC 는 그대로
    res = detect_partitions(BytesReader(img))
    c = codes(res)
    assert "gpt_header_crc_mismatch" in c and "gpt_using_backup" in c
    assert res["gpt"]["used"] == "backup"
    assert [p["gpt_name"] for p in res["partitions"]] == ["SDDATA", "spare"]


def test_gpt_entries_crc_mismatch_falls_back_to_backup_entries():
    img, _ = gpt_image()
    img[2 * 512 + 56] = ord("X")  # 주 항목 배열의 첫 이름 글자
    res = detect_partitions(BytesReader(img))
    c = codes(res)
    assert "gpt_entries_crc_mismatch" in c and "gpt_entries_from_other" in c
    assert res["partitions"][0]["gpt_name"] == "SDDATA"


def test_gpt_both_copies_damaged_still_lists_with_warnings():
    img, _ = gpt_image()
    total = len(img) // 512
    struct.pack_into("<Q", img, 512 + 40, 40)
    struct.pack_into("<Q", img, (total - 1) * 512 + 40, 40)
    res = detect_partitions(BytesReader(img))
    c = codes(res)
    assert "gpt_header_crc_mismatch" in c and "gpt_backup_header_crc_mismatch" in c
    assert res["scheme"] == "gpt" and len(res["partitions"]) == 2


def test_gpt_missing_backup_reported():
    vol = exfat_small().image()
    first = 2048
    img = bytearray((first + len(vol) // 512 + 64) * 512)
    place(img, first, vol)
    put_gpt(img, [GptPart(first, first + len(vol) // 512 - 1)], write_backup=False)
    res = detect_partitions(BytesReader(img))
    assert "gpt_backup_missing" in codes(res)
    assert res["partitions"][0]["fs_hint"] == "exfat"


def test_gpt_4k_sectors():
    vol = ExfatBuilder(total_sectors=2048, bytes_per_sector=4096, sectors_per_cluster=1).image()
    img, first = gpt_image(4096, vol=vol)
    res = detect_partitions(BytesReader(img))
    assert res["scheme"] == "gpt" and res["sector_size"] == 4096
    p1 = res["partitions"][0]
    assert p1["start_offset"] == first * 4096 and p1["fs_hint"] == "exfat"
    assert codes(res) == []
    v = open_volume(partition_source(BytesReader(img), p1))
    assert v.info()["bytes_per_sector"] == 4096


def test_superfloppy_fat_and_exfat():
    res = detect_partitions(BytesReader(fat12_volume()))
    assert res["scheme"] == "superfloppy"
    assert res["partitions"][0]["fs_hint"] == "fat12" and res["partitions"][0]["start_offset"] == 0
    ex = exfat_small().image()
    res = detect_partitions(BytesReader(ex))
    assert res["scheme"] == "superfloppy" and res["partitions"][0]["fs_hint"] == "exfat"
    assert res["partitions"][0]["size_bytes"] == len(ex)


def test_superfloppy_with_partition_like_bytes():
    vol = bytearray(fat12_volume())
    vol[446:462] = struct.pack("<B3sB3sII", 0x80, b"\0\0\0", 0x0C, b"\0\0\0", 0, len(vol) // 512)
    res = detect_partitions(BytesReader(vol))
    assert res["scheme"] == "superfloppy"
    assert "superfloppy_partition_like_bytes" in codes(res)


def test_overlap_and_beyond_image():
    vol = fat12_volume()
    vsec = len(vol) // 512
    img = bytearray((2048 + vsec) * 512)
    place(img, 2048, vol)
    put_mbr(img, [(0x01, 2048, vsec), (0x83, 2048 + 100, 50), (0x83, 2048 + vsec - 10, 5000)])
    res = detect_partitions(BytesReader(img))
    assert "partition_overlap" in codes(res)
    p3 = res["partitions"][2]
    assert p3["warnings"][0]["code"] == "partition_truncated" and p3["available_bytes"] == 10 * 512
    assert res["partitions"][1]["fs_hint"] in ("unknown", "zeroed")


def test_stale_gpt_behind_mbr():
    img, _ = gpt_image()
    vol = fat12_volume()
    place(img, 4096, vol)
    put_mbr(img, [(0x01, 4096, len(vol) // 512)])
    res = detect_partitions(BytesReader(img))
    assert res["scheme"] == "mbr"
    assert "stale_gpt_present" in codes(res)
    assert res["gpt"]["ignored"] is True


def test_protective_mbr_without_gpt_and_no_signature():
    img = bytearray(1 << 20)
    put_mbr(img, [(0xEE, 1, len(img) // 512 - 1)])
    res = detect_partitions(BytesReader(img))
    assert "protective_mbr_without_gpt" in codes(res)
    res = detect_partitions(BytesReader(bytes(1 << 16)))
    assert res["scheme"] == "none" and "no_signature" in codes(res)
    res = detect_partitions(BytesReader(b"\x00" * 100))
    assert res["scheme"] == "none" and "image_too_small" in codes(res)


def test_mbr_4k_sector_inference():
    vol = FatBuilder(16, total_sectors=8192, bytes_per_sector=4096, sectors_per_cluster=1).image()
    first = 256  # 4 KiB 단위 → 1 MiB
    img = bytearray((first + len(vol) // 4096 + 16) * 4096)
    img[first * 4096:first * 4096 + len(vol)] = vol
    put_mbr(img, [(0x06, first, len(vol) // 4096)])
    res = detect_partitions(BytesReader(img))
    assert res["sector_size"] == 4096 and "mbr_sector_size_4096" in codes(res)
    p = res["partitions"][0]
    assert p["start_offset"] == first * 4096 and p["fs_hint"] == "fat16"


def test_alignment_hint_and_sniff():
    vol = fat12_volume()
    img = bytearray((8192 + len(vol) // 512) * 512)
    place(img, 8192, vol)
    put_mbr(img, [(0x01, 8192, len(vol) // 512)])
    res = detect_partitions(BytesReader(img))
    assert res["partitions"][0]["alignment"] == {"aligned_to": 4 << 20, "aligned_4mib": True}
    assert sniff_fs(BytesReader(img), 8192 * 512) == "fat12"
    assert sniff_fs(BytesReader(img), len(img) + 10) is None


def test_partition_source_validation():
    with pytest.raises(FsError):
        partition_source(BytesReader(b"x" * 1024), {"index": 1})
    with pytest.raises(FsError) as ei:
        open_volume(BytesReader(bytes(4096)))
    assert ei.value.data["reason"] == "unsupported_fs"
