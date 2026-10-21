"""Android 형식 합성 시험: 구조/무결성/상한을 실제 장치 없이 확인."""

import struct
import time

import pytest

from fwtriage.android_builders import boot, vendor_boot, vbmeta, sparse, lp, f2fs, rehash_metadata
from fwtriage_mcp.androidformats import boot_info, vendor_boot_info, vbmeta_info, sparse_info, f2fs_info
from fwtriage_mcp.androidlayout import lp_layout, android_layout
from fwtriage_mcp.common import Ctl
from fwtriage_mcp.signatures import ScanCtx, scan_regions
from pweh.errors import ValidationFailed


@pytest.mark.parametrize("version", range(5))
def test_boot_versions(version):
    data = boot(version)
    result = boot_info(data, 0, len(data), Ctl())
    assert result["header_version"] == version and result["size"] == len(data)
    assert result["signature_status"] == "not-verified"


def test_init_boot_is_candidate_not_distinct_magic():
    data = boot(kernel=0)
    result = boot_info(data, 0, len(data), Ctl())
    assert result["kind"] == "android-boot" and result["role_hint"] == "init_boot-candidate"


@pytest.mark.parametrize("version", (3, 4))
def test_vendor_versions(version):
    data = vendor_boot(version)
    result = vendor_boot_info(data, 0, len(data), Ctl())
    assert result["size"] == len(data) and result["header_version"] == version
    if version == 4:
        assert "permissive" in result["bootconfig"] and result["ramdisk_entries"][0]["name"] == "test"


@pytest.mark.parametrize("flags", (0, 1, 2, 3, 0x100))
def test_vbmeta_flags_no_signature_claim(flags):
    data = vbmeta(flags)
    result = vbmeta_info(data, 0, len(data), Ctl())
    assert result["flags"] == flags and result["signature_status"] == "not-verified"


def test_vbmeta_bounds_and_byte_order():
    data = vbmeta()
    struct.pack_into(">Q", data, 32, 256)
    with pytest.raises(ValidationFailed):
        vbmeta_info(data, 0, len(data), Ctl())


def test_sparse_structure_does_not_verify_expanded_crc():
    data = sparse()
    result = sparse_info(data, 0, len(data), Ctl())
    assert result["size"] == len(data) and result["expanded_size"] == 48
    assert result["expanded_crc_status"] == "not-checked"
    with pytest.raises(ValidationFailed) as exc:
        android_layout(data, len(data), Ctl())
    assert exc.value.data["reason"] == "sparse_carve_unsupported"


@pytest.mark.parametrize("offset,value", ((8, 12), (12, 0), (20, 99999999), (36, 100)))
def test_sparse_bad_lengths(offset, value):
    data = sparse()
    struct.pack_into("<I", data, offset, value)
    with pytest.raises(ValidationFailed):
        sparse_info(data, 0, len(data), Ctl())


@pytest.mark.parametrize("minor", (0, 1, 2))
def test_lp_versions_and_noncontiguous_extent(minor):
    data, _ = lp(minor=minor)
    result = lp_layout(data, len(data), Ctl())
    assert result["header_version"] == f"10.{minor}"
    assert result["validation"] == {"geometry_sha256": True, "header_sha256": True, "tables_sha256": True, "extents": True}
    assert [e["target_type"] for e in result["partitions"][0]["mapping"]] == ["linear", "zero", "linear"]


def test_lp_fallback_records_failed_primary():
    data, _ = lp()
    data[12288 + 12] ^= 1
    result = lp_layout(data, len(data), Ctl())
    assert result["selected_copy"] == "backup" and any("primary metadata" in x for x in result["warnings"])


@pytest.mark.parametrize("where", (8, 12, 48))
def test_lp_checksums_fail_closed(where):
    data, _ = lp()
    offsets = (4096, 8192) if where == 8 else (12288, 20480)
    for off in offsets:
        data[off + where] ^= 1
    with pytest.raises(ValidationFailed):
        lp_layout(data, len(data), Ctl())


def test_lp_extent_outside_device_even_with_valid_checksums():
    data, _ = lp()
    for off in (12288, 20480):
        struct.pack_into("<Q", data, off + 256 + 52 + 12, 999999)
        rehash_metadata(data, off)
    with pytest.raises(ValidationFailed):
        lp_layout(data, len(data), Ctl())


@pytest.mark.parametrize("kwargs,reason", (({"external": True}, "missing_source"), ({"attr": 8}, "disabled"), ({"metadata_only": True}, "metadata_only")))
def test_lp_unsupported_payload_never_invented(kwargs, reason):
    data, _ = lp(**kwargs)
    result = lp_layout(data, len(data), Ctl())
    assert result["partitions"][0]["status"] == "skipped" and result["partitions"][0]["reason"] == reason


def test_lp_slot_name_and_truncated_payload():
    data, _ = lp(attr=2)
    assert lp_layout(data, len(data), Ctl(), slot=1)["partitions"][0]["name"] == "system_b"
    assert lp_layout(data, 32768, Ctl())["partitions"][0]["reason"] == "beyond_image"


@pytest.mark.parametrize("log_block", (12, 13, 14))
def test_f2fs_geometry_only(log_block):
    data = f2fs(log_block)
    result = f2fs_info(data, 0, len(data), Ctl())
    assert result["block_size"] == 1 << log_block and result["filesystem_supported"] is False


@pytest.mark.parametrize("builder,kind", ((boot, "android-boot"), (vendor_boot, "android-vendor-boot"), (vbmeta, "android-vbmeta"), (sparse, "android-sparse"), (f2fs, "f2fs")))
def test_registered_signatures(builder, kind):
    data = builder()
    regions = scan_regions(data, 0, len(data), ScanCtx(Ctl()), kinds={kind}, env_scan=False)
    assert any(x.offset == 0 and x.kind == kind for x in regions)


def test_lp_signature_and_expired_parser():
    data, _ = lp()
    regions = scan_regions(data, 0, len(data), ScanCtx(Ctl()), kinds={"android-lp"}, env_scan=False)
    assert regions and regions[0].offset == 0
    ctl = Ctl()
    ctl.deadline = time.monotonic() - 1
    with pytest.raises(ValidationFailed):
        sparse_info(sparse(), 0, len(sparse()), ctl)


@pytest.mark.parametrize("relative,fmt,value", ((80 + 8, "<I", 1), (256 + 40, "<I", 999), (256 + 52 + 12, "<Q", 1), (256 + 52 + 24 + 12, "<Q", 1)))
def test_lp_bad_table_or_extent_with_recomputed_hash(relative, fmt, value):
    data, _ = lp()
    for off in (12288, 20480):
        struct.pack_into(fmt, data, off + relative, value)
        rehash_metadata(data, off)
    with pytest.raises(ValidationFailed):
        lp_layout(data, len(data), Ctl())


def test_lp_physical_overlap_with_valid_metadata_hash():
    data, _ = lp()
    for off in (12288, 20480):
        struct.pack_into("<Q", data, off + 256 + 52 + 48 + 12, 64)
        rehash_metadata(data, off)
    with pytest.raises(ValidationFailed) as exc:
        lp_layout(data, len(data), Ctl())
    assert "겹" in str(exc.value)


def test_lp_two_valid_different_copies_primary_warning():
    data, _ = lp()
    struct.pack_into("<I", data, 20480 + 256 + 36, 1)
    rehash_metadata(data, 20480)
    result = lp_layout(data, len(data), Ctl())
    assert result["selected_copy"] == "primary" and any("다릅니다" in x for x in result["warnings"])


def test_header_secret_masking_preserves_regular_fields():
    data = boot(cmdline=b"console=ttyS0 password=" + b"SYNTHETIC_SECRET" * 20)
    result = boot_info(data, 0, len(data), Ctl())
    assert "console=ttyS0" in result["cmdline"] and "SYNTHETIC_SECRET" not in result["cmdline"]


def test_vbmeta_footer_signature():
    data = bytearray(1024)
    data[256:512] = vbmeta(2)
    data[-64:-60] = b"AVBf"
    struct.pack_into(">IIQQQ", data, len(data) - 60, 1, 0, 256, 256, 256)
    regions = scan_regions(data, 0, len(data), ScanCtx(Ctl()), kinds={"android-avb-footer"}, env_scan=False)
    assert regions[0].kind == "android-avb-footer" and regions[0].offset == 960
