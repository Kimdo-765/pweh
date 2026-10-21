"""raw GPT/LP 분할 및 기존 explicit/mtd 출력 예산 회귀."""

import hashlib
import json
import struct
import zlib

import pytest
from mcp import Client

from fs.builders import GptPart, put_gpt
from fwtriage.android_builders import lp, sparse
from fwtriage_mcp.androidlayout import android_layout
from fwtriage_mcp.common import Ctl
from mcp_helpers import call
from pweh.case import CaseStore
from pweh.errors import ValidationFailed


@pytest.fixture
def anyio_backend():
    return "asyncio"


@pytest.fixture
def acase(workspace, auth):
    return CaseStore(workspace["cases_dir"]).create(title="합성 Android 펌웨어", case_id="android", authorization=auth)


def gpt(sector=512):
    data = bytearray(sector * 256)
    put_gpt(data, [GptPart(40, 47, name="boot"), GptPart(48, 55, name="super")], sector=sector)
    data[40 * sector:48 * sector] = b"A" * (8 * sector)
    data[48 * sector:56 * sector] = b"B" * (8 * sector)
    return data


@pytest.mark.parametrize("sector", (512, 4096))
def test_gpt_valid_layout(sector):
    data = gpt(sector)
    result = android_layout(data, len(data), Ctl())
    assert result["source"] == "gpt" and result["sector_size"] == sector
    assert result["partitions"][0]["offset"] == 40 * sector


def test_gpt_bad_crc_refused_and_backup_reported():
    data = gpt()
    data[512 + 16] ^= 1
    result = android_layout(data, len(data), Ctl())
    assert result["selected_copy"] == "backup"
    data[-512 + 16] ^= 1
    with pytest.raises(ValidationFailed):
        android_layout(data, len(data), Ctl())


def test_gpt_overlap_refused():
    data = gpt()
    put_gpt(data, [GptPart(40, 47), GptPart(44, 49)])
    with pytest.raises(ValidationFailed) as exc:
        android_layout(data, len(data), Ctl())
    assert exc.value.data["reason"] == "overlapping_gpt_partitions"


@pytest.mark.parametrize("sector", (512, 4096))
def test_gpt_valid_crc_cannot_authorize_metadata_as_partition(sector):
    data = bytearray(sector * 256)
    put_gpt(data, [GptPart(2, 2, name="overlaps_partition_array")], sector=sector)
    for offset in (sector, len(data) - sector):
        struct.pack_into("<Q", data, offset + 40, 2)
        struct.pack_into("<I", data, offset + 16, 0)
        size = struct.unpack_from("<I", data, offset + 12)[0]
        struct.pack_into("<I", data, offset + 16, zlib.crc32(data[offset:offset + size]))
    with pytest.raises(ValidationFailed) as exc:
        android_layout(data, len(data), Ctl())
    assert exc.value.data["reason"] == "overlapping_gpt_metadata"


@pytest.mark.anyio
async def test_lp_mcp_noncontiguous_output(acase):
    from fwtriage_mcp.server import server
    data, expected = lp()
    (acase.subdir("dumps") / "super.bin").write_bytes(data)
    async with Client(server) as c:
        result = await call(c, "fw_carve", case_id=acase.id, path="dumps/super.bin")
    assert result["ok"], result
    assert result["layout"]["source"] == "lp"
    part = result["partitions"][0]
    assert (acase.dir / part["path"]).read_bytes() == expected
    assert part["sha256"] == hashlib.sha256(expected).hexdigest()
    index = json.loads((acase.dir / result["index_path"]).read_text())
    assert index["partitions"][0]["offset"] is None and len(index["partitions"][0]["mapping"]) == 3


@pytest.mark.anyio
async def test_gpt_mcp_output_and_hash(acase):
    from fwtriage_mcp.server import server
    data = gpt()
    (acase.subdir("dumps") / "gpt.bin").write_bytes(data)
    async with Client(server) as c:
        result = await call(c, "fw_carve", case_id=acase.id, path="dumps/gpt.bin")
    assert result["ok"], result
    assert [p["name"] for p in result["partitions"]] == ["boot", "super"]
    assert (acase.dir / result["partitions"][0]["path"]).read_bytes() == b"A" * 4096


@pytest.mark.anyio
@pytest.mark.parametrize("kind", ("lp", "gpt", "explicit", "mtd"))
async def test_output_budget_all_paths_no_partial_directory(acase, kind):
    from fwtriage_mcp.server import server
    data = lp()[0] if kind == "lp" else gpt() if kind == "gpt" else bytes(4096)
    (acase.subdir("dumps") / "input.bin").write_bytes(data)
    args = {"partitions": [{"name": "test", "offset": 0, "size": 4096}]} if kind == "explicit" else {"mtdparts": "flash:4k(test)"} if kind == "mtd" else {}
    async with Client(server) as c:
        result = await call(c, "fw_carve", case_id=acase.id, path="dumps/input.bin", max_output_bytes=1, **args)
    assert "_error" in result and "max_output_bytes" in str(result)
    assert not list(acase.subdir("extract").iterdir())


@pytest.mark.anyio
async def test_sparse_carve_explicitly_unsupported(acase):
    from fwtriage_mcp.server import server
    (acase.subdir("dumps") / "input.bin").write_bytes(sparse())
    async with Client(server) as c:
        result = await call(c, "fw_carve", case_id=acase.id, path="dumps/input.bin")
    assert "_error" in result and "sparse" in str(result)


@pytest.mark.anyio
async def test_metadata_only_no_fabricated_payload(acase):
    from fwtriage_mcp.server import server
    (acase.subdir("dumps") / "empty.bin").write_bytes(lp(metadata_only=True)[0])
    async with Client(server) as c:
        result = await call(c, "fw_carve", case_id=acase.id, path="dumps/empty.bin")
    assert result["ok"] and result["partitions"][0]["reason"] == "metadata_only"
    assert not list((acase.dir / result["output_dir"]).glob("*.bin"))
