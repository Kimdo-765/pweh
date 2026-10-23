"""합성 FAT/exFAT 창·전체 metadata 예산·닫힌 회계 검사. 실제 파일/장치 없음."""
from __future__ import annotations

from copy import deepcopy
from dataclasses import replace
import json
from pathlib import Path
import struct
import time
from types import SimpleNamespace

import jsonschema
import pytest

from pweh.fs import BytesReader, Budget, FsError
from pweh.fs import allocation as A
from .builders import FatBuilder, ExfatBuilder, GptPart, put_gpt, put_mbr


class RecordingSource(BytesReader):
    def __init__(self, data):
        super().__init__(data)
        self.reads = []
        self.hook = None

    def read(self, offset, size):
        self.reads.append((offset, size))
        if self.hook:
            self.hook(offset, size)
        return super().read(offset, size)


def fat(bits=12, **kwargs):
    return FatBuilder(bits, total_sectors={12: 2048, 16: 8192, 32: 67000}[bits], **kwargs)


def inspect(data, offset, length, **kwargs):
    source = data if isinstance(data, RecordingSource) else RecordingSource(data)
    args = {"partition": 1, "offset": offset, "length": length, "deadline": time.monotonic() + 20}
    args.update(kwargs)
    report = A.inspect_allocation_window(source, **args)
    report["source"] = {"kind": "evidence", "evidence_id": "EV-0001", "evidence_sha256": "a" * 64, "evidence_size": source.size}
    report["params"] = {"partition": args["partition"], "offset": offset, "length": length, "max_seconds": 20}
    A.validate_allocation_accounting(report)
    schema = json.loads((Path(A.__file__).parents[1] / "schemas/allocation-window.schema.json").read_text())
    jsonschema.Draft202012Validator(schema).validate(report)
    assert report["coverage"]["metadata_bytes_read"] == sum(n for _, n in source.reads)
    assert all(n <= 65536 for _, n in source.reads)
    return report


@pytest.mark.parametrize("bits", [12, 16, 32])
def test_actual_fat_states_partial_cluster_and_current_only(bits):
    b = fat(bits)
    b.set_fat(2, 0)
    b.set_fat(3, b.eoc)
    b.set_fat(4, {12: 0xFF7, 16: 0xFFF7, 32: 0x0FFFFFF7}[bits])
    b.set_fat(5, 1)
    out = inspect(b.image(), b.data_off + 3, 4 * b.cs - 7)
    assert [r["state"] for r in out["rows"]] == ["unallocated", "allocated", "bad", "unknown"]
    assert [r["length"] for r in out["rows"]] == [b.cs-3, b.cs, b.cs, b.cs-4]
    assert out["coverage"]["window_complete"] and not out["coverage"]["allocation_complete"]
    assert out["coverage"]["reasons"] == ["fat_entry_invalid"]
    assert all(out[key] is False for key in A.FALSE_FIELDS)


@pytest.mark.parametrize("bits", [12, 16, 32])
@pytest.mark.parametrize("which", [0, 6])
def test_reserved_marker_is_not_a_next_cluster_even_when_geometry_overlaps(bits, which):
    start = {12: 0xFF0, 16: 0xFFF0, 32: 0x0FFFFFF0}[bits]
    value = start + which
    vol = SimpleNamespace(fat_type=f"fat{bits}", bad_value=start+7, eoc_min=start+8, max_cluster=start+6)
    src = SimpleNamespace(check=lambda **kw: None)
    state = A._fat_state([SimpleNamespace(get=lambda c: value)], 2, vol, src)
    assert state == ("unknown", "fat_entry_invalid")


@pytest.mark.parametrize("bits", [12, 16, 32])
def test_free_coalesces_and_exact_heap_end(bits):
    b = fat(bits)
    out = inspect(b.image(), b.data_off + (b.count - 2) * b.cs, 2 * b.cs)
    assert out["rows"] == [{"offset": b.data_off + (b.count-2)*b.cs, "length": 2*b.cs, "state": "unallocated", "reason": None}]
    assert out["status"] == "ok" and out["coverage"]["next_offset"] is None


@pytest.mark.parametrize("bits", [16, 32])
def test_mirrors_must_agree_and_only_active_fat_has_authority(bits):
    b = fat(bits)
    b.set_fat_copy(1, 5, b.eoc)
    out = inspect(b.image(), b.data_off + 3*b.cs, b.cs)
    assert out["rows"][0]["reason"] == "fat_copies_disagree"
    if bits == 32:
        b.ext_flags = 0x81
        active = inspect(b.image(), b.data_off + 3*b.cs, b.cs)
        assert active["rows"][0]["state"] == "allocated"
        b.ext_flags = 0x82
        invalid = inspect(b.image(), b.data_off + 3*b.cs, b.cs)
        assert invalid["rows"][0]["reason"] == "active_fat_invalid"


def test_fat32_top_nibble_mask_does_not_create_disagreement():
    b = fat(32)
    b.set_fat_copy(0, 5, 0xF0000000)
    out = inspect(b.image(), b.data_off + 3*b.cs, b.cs)
    assert out["status"] == "ok" and out["summary"]["unallocated_bytes"] == b.cs


def test_fat12_odd_and_cross_byte_entries():
    b = fat()
    b.set_fat(341, b.eoc)
    b.set_fat(342, 0)
    out = inspect(b.image(), b.data_off + 339*b.cs, 2*b.cs)
    assert [r["state"] for r in out["rows"]] == ["allocated", "unallocated"]


def test_all_declared_fat_copies_are_checked():
    b = fat(16, num_fats=3)
    b.set_fat_copy(2, 5, b.eoc)
    out = inspect(b.image(), b.data_off+3*b.cs, b.cs)
    assert out["rows"][0]["reason"] == "fat_copies_disagree"


@pytest.mark.parametrize("limits,number,reason", [
    (A.AllocationLimits(), 128, "rows_limit"),
    (A.AllocationLimits(rows=1), 1, "rows_limit"),
    (A.AllocationLimits(output_bytes=8192), 16, "output_limit"),
])
def test_contiguous_prefix_limits_are_exact(limits, number, reason):
    b = fat()
    for cluster in range(2, 262):
        b.set_fat(cluster, b.eoc if cluster % 2 else 0)
    out = inspect(b.image(), b.data_off, 260*b.cs, limits=limits)
    assert len(out["rows"]) == number
    assert out["coverage"]["next_offset"] == b.data_off + number*b.cs
    assert out["coverage"]["reasons"] == [reason]
    assert out["coverage"]["unexamined_bytes"] == (260-number)*b.cs


def test_row_limit_does_not_stop_a_coalesced_run():
    b = fat()
    out = inspect(b.image(), b.data_off, 300*b.cs, limits=A.AllocationLimits(rows=1))
    assert len(out["rows"]) == 1 and out["status"] == "ok"


@pytest.mark.parametrize("wrapper", ["mbr", "gpt"])
def test_partition_offset_and_every_detection_read_count(wrapper):
    b = fat()
    data = b.image()
    start = 40*512
    image = bytearray(len(data) + 100*512)
    image[start:start+len(data)] = data
    if wrapper == "mbr":
        put_mbr(image, [(1,40,len(data)//512)])
    else:
        put_gpt(image, [GptPart(40,40+len(data)//512-1)])
    src = RecordingSource(bytes(image))
    out = inspect(src, start+b.data_off, b.cs)
    assert src.reads[0] == (0,512)
    assert out["geometry"]["partition_offset"] == start
    assert out["status"] == "ok"
    assert not any(start+b.data_off <= off < start+len(data) for off,n in src.reads)


@pytest.mark.parametrize("damage", ["overlap", "truncated", "gpt-crc", "fat32-version", "fat32-count"])
def test_metadata_authority_failure_stays_unknown(damage):
    b = fat(32) if damage.startswith("fat32") else fat()
    data = bytearray(b.image())
    start = 0
    if damage == "overlap":
        start = 40*512
        image = bytearray(len(data)+start)
        image[start:] = data
        put_mbr(image, [(1,40,len(data)//512), (1,40,len(data)//512)])
        data = image
    elif damage == "truncated":
        data = data[:-512]
    elif damage == "gpt-crc":
        start = 40*512
        image = bytearray(len(data)+100*512)
        image[start:start+len(data)] = data
        put_gpt(image,[GptPart(40,40+len(data)//512-1)],write_backup=False)
        image[512+16] ^= 1
        data = image
    elif damage == "fat32-version":
        struct.pack_into("<H",data,42,1)
    else:
        struct.pack_into("<I",data,32,60000)
    out = inspect(bytes(data), start+b.data_off+10*b.cs, b.cs)
    assert out["rows"][0]["reason"] == "volume_metadata_inconsistent"
    assert out["status"] == "partial" and out["coverage"]["window_complete"]


def test_verified_gpt_backup_selection_is_supported():
    b = fat()
    start = 40*512
    image = bytearray(len(b.buf)+100*512)
    image[start:start+len(b.buf)] = b.image()
    put_gpt(image,[GptPart(40,40+len(b.buf)//512-1)])
    image[512+16] ^= 1
    out = inspect(bytes(image), start+b.data_off, b.cs)
    assert out["status"] == "ok"


def test_metadata_limit_before_geometry_is_fatal_and_after_is_partial():
    b = fat(16)
    with pytest.raises(A.AllocationError) as exc:
        inspect(b.image(), b.data_off, b.cs, limits=A.AllocationLimits(metadata_bytes=511))
    assert exc.value.code == "allocation_limit"
    full = inspect(b.image(),b.data_off,b.cs)
    cap = full["coverage"]["metadata_bytes_read"]-1
    src = RecordingSource(b.image())
    out = inspect(src,b.data_off,b.cs,limits=A.AllocationLimits(metadata_bytes=cap))
    assert out["coverage"]["metadata_bytes_read"] == cap
    assert out["rows"] == [] and out["coverage"]["reasons"] == ["metadata_bytes_limit"]


def test_counting_large_reads_clamps_only_known_eof_and_recounts_actual_io():
    raw = RecordingSource(b"a"*(200000))
    counted = A._CountingSource(raw,A.AllocationLimits(metadata_bytes=150000),Budget(max_steps=100),None)
    with pytest.raises(FsError) as exc:
        counted.read(0,200000)
    assert exc.value.data["limit"] == "metadata_bytes"
    assert raw.reads == [(0,65536),(65536,65536),(131072,18928)]
    assert counted.bytes_read == 150000
    counted = A._CountingSource(raw,A.AllocationLimits(),Budget(max_steps=100),None)
    assert counted.read_clamped(199998,10) == b"aa"
    assert counted.read_clamped(200000,5) == b""
    assert counted.read(0,0) == b""
    counted.read(199998,2)
    assert counted.bytes_read == 4


@pytest.mark.parametrize("fault", ["short", "wrong-type", "exception"])
def test_leaf_failure_cannot_be_reported_as_unknown(fault):
    b=fat()
    class Broken(RecordingSource):
        def read(self, offset, size):
            if len(self.reads) > 0:
                if fault == "exception":
                    raise RuntimeError("SECRET-PATH")
                return b"x" if fault == "short" else bytearray(size)
            return super().read(offset,size)
    with pytest.raises(A.AllocationError) as exc:
        inspect(Broken(b.image()), b.data_off, b.cs)
    assert exc.value.code == "allocation_read_failed"
    assert "SECRET" not in str(exc.value) and not exc.value.data


def test_cancel_during_leaf_is_fatal_even_if_fs_catches_it():
    b=fat()
    src=RecordingSource(b.image())
    stop=[False]
    src.hook=lambda off,n: stop.__setitem__(0,True)
    with pytest.raises(A.AllocationError) as exc:
        inspect(src,b.data_off,b.cs,cancel=lambda:stop[0])
    assert exc.value.code == "cancelled"


def test_time_before_geometry_and_after_geometry(monkeypatch):
    b=fat()
    with pytest.raises(A.AllocationError) as exc:
        inspect(b.image(),b.data_off,b.cs,deadline=time.monotonic()-1)
    assert exc.value.code == "time_limit"
    real=A.open_volume
    def stopped(*args,**kwargs):
        result=real(*args,**kwargs)
        kwargs["budget"].deadline=time.monotonic()-1
        return result
    monkeypatch.setattr(A,"open_volume",stopped)
    out=inspect(b.image(),b.data_off,b.cs)
    assert out["rows"]==[] and out["coverage"]["reasons"]==["time_limit"]


def test_steps_remain_shared_and_unknown_does_not_mask_cutoff(monkeypatch):
    b=fat(32,ext_flags=0x82)
    real=A.open_volume
    def stopped(*args,**kwargs):
        result=real(*args,**kwargs)
        kwargs["budget"].tick(kwargs["budget"].max_steps+1)
        return result
    monkeypatch.setattr(A,"open_volume",stopped)
    out=inspect(b.image(),b.data_off,b.cs)
    assert out["rows"]==[] and out["coverage"]["reasons"]==["step_limit"]
    assert out["coverage"]["steps"]>A.AllocationLimits().steps


def test_real_exfat_bitmap_and_no_file_content_read():
    b=ExfatBuilder(total_sectors=4096)
    src=RecordingSource(b.image())
    out=inspect(src,b.heap*b.bps,b.cs*5)
    assert [r["state"] for r in out["rows"]]==["allocated","unallocated"]
    assert out["summary"]["allocated_bytes"]==3*b.cs
    assert out["status"]=="ok"
    assert all(off < b.coff(5) for off,n in src.reads)


@pytest.mark.parametrize("kind", ["missing","short","root-limit"])
def test_exfat_unknown_and_stopped_are_distinct(kind):
    b=ExfatBuilder(total_sectors=4096)
    limits=A.AllocationLimits()
    if kind=="missing":
        b.dirs["/"].slots=[s for s in b.dirs["/"].slots if s[0]!=0x81]
    elif kind=="short":
        item=bytearray(b.dirs["/"].slots[1]); struct.pack_into("<Q",item,24,1)
        b.dirs["/"].slots[1]=bytes(item)
    else:
        limits=replace(limits,root_slots=1)
    out=inspect(b.image(),b.coff(12),b.cs,limits=limits)
    expected={"missing":"bitmap_missing","short":"bitmap_bit_unreadable","root-limit":"root_slots_limit"}[kind]
    assert out["coverage"]["reasons"]==[expected]
    assert out["coverage"]["window_complete"] is (kind!="root-limit")


@pytest.mark.parametrize("key,value", [("partition",True),("partition",0),("partition",4097),("offset",False),("offset",-1),
    ("offset",1.0),("length",0),("length",True),("length",(64<<20)+1),("deadline",float("nan")),
    ("deadline",float("inf")),("deadline",10**1000),("cancel",True),("limits",{})])
def test_exact_input_rejects_before_read(key,value):
    b=fat(); src=RecordingSource(b.image())
    args=dict(partition=1,offset=b.data_off,length=b.cs,deadline=time.monotonic()+20)
    args[key]=value
    with pytest.raises(A.AllocationError):
        A.inspect_allocation_window(src,**args)
    assert src.reads==[]


@pytest.mark.parametrize("offset_kind", ["metadata","past-heap","past-ev"])
def test_window_must_be_in_data_and_image(offset_kind):
    b=fat(); off={"metadata":b.data_off-1,"past-heap":len(b.buf)-1,"past-ev":len(b.buf)}[offset_kind]
    with pytest.raises(A.AllocationError):
        inspect(b.image(),off,2)


@pytest.mark.parametrize("field", list(A.AllocationLimits.__dataclass_fields__))
@pytest.mark.parametrize("value", [0,True,1.5,"1",1<<30])
def test_exact_lower_limits(field,value):
    with pytest.raises(A.AllocationError):
        A.AllocationLimits(**{field:value})


def test_full_report_validator_and_schema_reject_tampering():
    b=fat(); valid=inspect(b.image(),b.data_off,b.cs)
    mutations=[("params","length",True),("params","partition",4097),("params","offset",b.data_off+1),
       ("source","evidence_size",1),("geometry","cluster_size",513),("geometry","data_length",1),
       ("coverage","processed_bytes",0),("coverage","next_offset",1),("coverage","window_complete",1),
       ("coverage","allocation_complete",False),("coverage","metadata_bytes_read",(4<<20)+1),
       ("summary","unallocated_bytes",0),("summary","rows_reported",True)]
    for section,key,value in mutations:
        bad=deepcopy(valid);bad[section][key]=value
        with pytest.raises(A.AllocationError):
            A.validate_allocation_accounting(bad)
    schema=json.loads((Path(A.__file__).parents[1]/"schemas/allocation-window.schema.json").read_text())
    for section in (None,"source","params","geometry","coverage","summary"):
        bad=deepcopy(valid);(bad if section is None else bad[section])["raw"]="SECRET"
        with pytest.raises(jsonschema.ValidationError):
            jsonschema.validate(bad,schema)
    bad=deepcopy(valid);bad.pop("source")
    with pytest.raises(A.AllocationError):
        A.validate_allocation_accounting(bad)


def test_reasons_order_merge_and_suffix_equations():
    b=fat(16)
    b.set_fat_copy(1,2,b.eoc); b.set_fat(3,1); b.set_fat(4,b.eoc)
    valid=inspect(b.image(),b.data_off,3*b.cs,limits=A.AllocationLimits(rows=2))
    assert valid["coverage"]["reasons"]==["fat_copies_disagree","fat_entry_invalid","rows_limit"]
    bad=deepcopy(valid);bad["coverage"]["reasons"].reverse()
    with pytest.raises(A.AllocationError): A.validate_allocation_accounting(bad)
    bad=deepcopy(valid);bad["rows"][1]["offset"]+=1
    with pytest.raises(A.AllocationError): A.validate_allocation_accounting(bad)
    bad=deepcopy(valid);bad["coverage"]["unexamined_bytes"]-=1
    with pytest.raises(A.AllocationError): A.validate_allocation_accounting(bad)


def test_closed_report_does_not_copy_raw_metadata():
    b=fat(label="SECRETLABEL",oem=b"RAWNAME!")
    out=inspect(b.image(),b.data_off,b.cs)
    encoded=json.dumps(out)
    assert "SECRET" not in encoded and "RAWNAME" not in encoded
    assert out["source"]["evidence_sha256"]=="a"*64


@pytest.mark.parametrize("identity", ["EV-123", "EV-1234567", "EV-0001\n", "raw-sentinel"])
def test_schema_closes_evidence_identifier(identity):
    b=fat()
    report=inspect(b.image(),b.data_off,b.cs)
    report["source"]["evidence_id"]=identity
    schema=json.loads((Path(A.__file__).parents[1]/"schemas/allocation-window.schema.json").read_text())
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(report,schema)
