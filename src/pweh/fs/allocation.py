"""명시 FAT/exFAT 데이터 창의 현재 할당 metadata. 파일 도달성·내용은 해석하지 않는다."""
from __future__ import annotations

from dataclasses import dataclass, fields
import math
import time

from pweh.errors import ValidationFailed
from . import open_volume
from .common import Budget, FsError, Limits
from .tables import FatTable
from .volume import detect_partitions, partition_source

SCHEMA = "pweh.allocation-window/v1"
PROFILE = "fat-exfat-allocation-window-v1"
MAX_COORD = (1 << 63) - 1
MAX_WINDOW = 64 << 20
LEAF_BYTES = 64 << 10
FALSE_FIELDS = ("whole_evidence_examined", "file_ownership_verified", "historical_allocation_verified",
                "media_decoded", "playback_verified", "payload_semantics_examined")
UNKNOWN_REASONS = (
    "active_fat_invalid", "fat_copies_disagree", "fat_entry_unreadable", "fat_entry_invalid",
    "bitmap_missing", "bitmap_ambiguous", "bitmap_active_mismatch", "bitmap_chain_invalid",
    "bitmap_bit_unreadable", "root_metadata_incomplete", "volume_metadata_inconsistent",
)
STOP_REASONS = ("time_limit", "step_limit", "metadata_bytes_limit", "root_slots_limit",
                "bitmap_runs_limit", "rows_limit", "output_limit")
STATES = ("unallocated", "allocated", "bad", "unknown")
_CUTOFF = {"time": "time_limit", "steps": "step_limit", "metadata_bytes": "metadata_bytes_limit"}


class AllocationError(ValidationFailed):
    """원시 FS 진단을 포함하지 않는 고정 실패."""


def _fail(code="allocation_input_invalid"):
    raise AllocationError("할당 구간 검사를 완료할 수 없습니다.", code=code) from None


def _integer(value, minimum=0, maximum=MAX_COORD):
    return type(value) is int and minimum <= value <= maximum


@dataclass(frozen=True)
class AllocationLimits:
    metadata_bytes: int = 4 << 20
    rows: int = 128
    output_bytes: int = 1 << 20
    steps: int = 1 << 20
    root_slots: int = 32768
    bitmap_runs: int = 8192

    def __post_init__(self):
        for field in fields(self):
            if not _integer(getattr(self, field.name), 8192 if field.name == "output_bytes" else 1, field.default):
                _fail()


class _CountingSource:
    """탐지 이전부터 공유하는 읽기 계수. FS가 오류를 흡수해도 원인을 유지한다."""

    def __init__(self, source, limits, budget, cancel):
        self.source, self.size, self.base_offset = source, source.size, 0
        self.limits, self.budget, self.cancel = limits, budget, cancel
        self.bytes_read = 0
        self.problem = False
        self.cutoff = None
        self.cancelled = False

    def check_cancel(self):
        if self.cancel is not None:
            try:
                stop = self.cancel()
                if type(stop) is not bool:
                    stop = True
            except Exception:
                stop = True
            self.cancelled |= stop
        if self.cancelled:
            _fail("cancelled")
        if self.problem:
            _fail("allocation_read_failed")

    def check(self, *, step=False):
        self.check_cancel()
        if step:
            self.budget.tick()
        if self.cutoff is not None:
            raise FsError("할당 metadata 읽기 한도", reason="budget_exceeded", data={"limit": self.cutoff})
        if self.budget.expired():
            raise self.budget.error("할당 metadata")

    def read(self, offset, size):
        self.check()
        if not _integer(offset) or not _integer(size) or offset + size > self.size:
            raise FsError("metadata 읽기 범위 오류", reason="out_of_bounds")
        pieces = []
        done = 0
        while done < size:
            self.check(step=True)
            remaining = self.limits.metadata_bytes - self.bytes_read
            if remaining == 0:
                self.cutoff = "metadata_bytes"
                self.check()
            amount = min(LEAF_BYTES, size - done, remaining)
            try:
                block = self.source.read(offset + done, amount)
            except Exception:
                self.problem = True
                self.check_cancel()
            if type(block) is not bytes or len(block) != amount:
                self.problem = True
                self.check_cancel()
            self.bytes_read += len(block)
            self.check()
            pieces.append(block)
            done += amount
        return b"".join(pieces)

    def read_clamped(self, offset, size):
        self.check()
        if not _integer(offset) or not _integer(size):
            raise FsError("metadata 읽기 범위 오류", reason="out_of_bounds")
        return self.read(offset, min(size, self.size - offset)) if offset < self.size else b""


def _stop(exc):
    return _CUTOFF.get(exc.data.get("limit")) if isinstance(exc, FsError) and exc.reason == "budget_exceeded" else None


def _geometry(vol, part, source_size, offset, length):
    kind = "exfat" if vol.kind == "exfat" else vol.fat_type
    start, size = part["start_offset"], part["size_bytes"]
    cluster_size, heap, maximum = vol.cluster_size, vol.heap_offset, vol.max_cluster
    if (kind not in ("fat12", "fat16", "fat32", "exfat")
            or not _integer(cluster_size, 512, 32 << 20) or cluster_size & (cluster_size - 1)
            or not _integer(heap) or not _integer(maximum, 2)
            or not _integer(vol.volume_size, 1)):
        _fail("allocation_unsupported")
    data_start = start + heap
    data_length = (maximum - 1) * cluster_size
    if data_start + data_length > MAX_COORD:
        _fail("allocation_unsupported")
    if offset < data_start or offset + length > min(data_start + data_length, source_size, start + size, start + vol.volume_size):
        _fail()
    return {"fs_type": kind, "partition_offset": start, "partition_size": size,
            "cluster_size": cluster_size, "data_offset": data_start, "data_length": data_length}


def _inconsistent(layout, part, vol, source):
    start, size = part["start_offset"], part["size_bytes"]
    if start + size > source.size or vol.volume_size > min(size, source.size - start):
        return True
    if part.get("warnings"):
        return True
    for other in layout["partitions"]:
        source.check(step=True)
        if other is not part and other.get("role") != "extended":
            a, n = other.get("start_offset"), other.get("size_bytes")
            if not _integer(a) or not _integer(n):
                return True
            if n and max(start, a) < min(start + size, a + n):
                return True
    if layout.get("scheme") == "gpt":
        gpt = layout.get("gpt") or {}
        header = gpt.get(gpt.get("used")) or {}
        if gpt.get("entries_crc_ok") is not True or header.get("header_crc_ok") is not True or header.get("my_lba_ok") is not True:
            return True
    if vol.kind == "fat":
        b = vol.bpb
        if (vol.max_cluster != b["cluster_count"] + 1 or b["fat_type"] != b["fat_type_by_count"]
                or b.get("fs_version", 0) != 0):
            return True
        codes = set(vol._w.codes())
        return bool(codes & {"bpb_bad_jump", "boot_signature_missing", "bpb_both_totsec",
                             "bpb_fat32_rootent", "bpb_rootent_align", "fat_too_small"})
    return vol.boot["cluster_count"] != vol.cluster_count


def _fat_tables(vol, source):
    b = vol.bpb
    flags = b.get("ext_flags", 0)
    if vol.fat_type == "fat32" and flags & 0x80:
        if (flags & 15) >= b["num_fats"]:
            return [], "active_fat_invalid"
        indexes = (flags & 15,)
    else:
        indexes = range(b["num_fats"])
    tables = []
    for index in indexes:
        source.check(step=True)
        tables.append(vol._fat if index == vol.active_fat else FatTable(
            vol.src, vol.fat_offset + index * vol.fat_bytes, vol.fat_bytes,
            {"fat12": 12, "fat16": 16, "fat32": 32}[vol.fat_type], vol.max_cluster,
            mask_top_nibble=vol.fat_type == "fat32"))
    return tables, None


def _fat_state(tables, cluster, vol, source):
    values = []
    for table in tables:
        source.check(step=True)
        values.append(table.get(cluster))
    if None in values:
        return "unknown", "fat_entry_unreadable"
    if len(set(values)) != 1:
        return "unknown", "fat_copies_disagree"
    value = values[0]
    if value == 0:
        return "unallocated", None
    # 예약 marker는 클러스터 상한과 겹쳐도 next로 해석하지 않는다.
    reserved = {"fat12": 0xFF0, "fat16": 0xFFF0, "fat32": 0x0FFFFFF0}[vol.fat_type]
    if reserved <= value < vol.bad_value:
        return "unknown", "fat_entry_invalid"
    if value == vol.bad_value:
        return "bad", None
    if value >= vol.eoc_min or 2 <= value <= vol.max_cluster:
        return "allocated", None
    return "unknown", "fat_entry_invalid"


def inspect_allocation_window(source, *, partition, offset, length,
                              limits=AllocationLimits(), deadline, cancel=None):
    """같은 Source의 명시 데이터 창을 검사한다. source/params 결속은 호출자가 붙인다."""
    if (type(limits) is not AllocationLimits or not _integer(partition, 1, 4096)
            or not _integer(offset) or not _integer(length, 1, MAX_WINDOW)
            or not _integer(getattr(source, "size", None), 1)
            or type(getattr(source, "base_offset", None)) is not int or source.base_offset != 0
            or not callable(getattr(source, "read", None)) or offset + length > source.size
            or type(deadline) not in (int, float) or cancel is not None and not callable(cancel)):
        _fail()
    try:
        end = min(float(deadline), time.monotonic() + 45)
        if not math.isfinite(float(deadline)):
            _fail()
    except (OverflowError, ValueError):
        _fail()
    budget = Budget(deadline=end, max_steps=limits.steps)
    counted = _CountingSource(source, limits, budget, cancel)
    # A가 순회 중 검사하는 Budget에도 같은 취소 callback을 연결한다.
    def cancelled():
        counted.check_cancel()
        return False
    budget.cancel = cancelled
    geometry = None
    rows = []
    cutoff = None
    try:
        counted.check()
        fs_limits = Limits(max_follow_steps=limits.steps, max_dir_slots=limits.root_slots,
                           max_total_slots=limits.root_slots, max_runs=limits.bitmap_runs)
        layout = detect_partitions(counted, limits=fs_limits)
        counted.check()
        selected = [p for p in layout["partitions"] if type(p.get("index")) is int and p["index"] == partition]
        if len(selected) != 1:
            _fail()
        part = selected[0]
        if not _integer(part.get("start_offset")) or not _integer(part.get("size_bytes"), 1):
            _fail()
        vol = open_volume(partition_source(counted, part), limits=fs_limits, budget=budget,
                          metadata_mode="allocation")
        counted.check_cancel()
        geometry = _geometry(vol, part, source.size, offset, length)
        counted.check()
        unknown = "volume_metadata_inconsistent" if _inconsistent(layout, part, vol, counted) else None
        tables = []
        if vol.kind == "fat" and unknown is None:
            tables, unknown = _fat_tables(vol, counted)
        elif vol.kind == "exfat":
            if vol.allocation_status == "stopped":
                cutoff = vol.allocation_reason
            elif vol.allocation_status == "unknown":
                unknown = unknown or vol.allocation_reason
            elif vol.allocation_status != "ready":
                _fail("allocation_failed")
        if unknown is not None and unknown not in UNKNOWN_REASONS or cutoff is not None and cutoff not in STOP_REASONS:
            _fail("allocation_failed")
        pos = offset
        while pos < offset + length and cutoff is None:
            counted.check(step=True)
            cluster = (pos - geometry["data_offset"]) // geometry["cluster_size"] + 2
            edge = geometry["data_offset"] + (cluster - 1) * geometry["cluster_size"]
            amount = min(offset + length, edge) - pos
            if unknown:
                state, reason = "unknown", unknown
            elif vol.kind == "fat":
                state, reason = _fat_state(tables, cluster, vol, counted)
            else:
                bit = vol.allocated(cluster)
                state, reason = (("allocated" if bit else "unallocated"), None) if type(bit) is bool else ("unknown", "bitmap_bit_unreadable")
            counted.check()
            merge = bool(rows and (rows[-1]["state"], rows[-1]["reason"]) == (state, reason))
            if not merge and len(rows) >= limits.rows:
                cutoff = "rows_limit"
            elif not merge and 4096 + (len(rows) + 1) * 256 > limits.output_bytes:
                cutoff = "output_limit"
            elif merge:
                rows[-1]["length"] += amount
            else:
                rows.append({"offset": pos, "length": amount, "state": state, "reason": reason})
            if cutoff is None:
                pos += amount
    except Exception as exc:
        counted.check_cancel()
        cutoff = _stop(exc)
        if cutoff is None or geometry is None:
            if cutoff:
                _fail("time_limit" if cutoff == "time_limit" else "allocation_limit")
            if isinstance(exc, AllocationError):
                raise exc from None
            if isinstance(exc, FsError) and exc.reason in ("unsupported_fs", "not_fat", "not_exfat"):
                _fail("allocation_unsupported")
            _fail("allocation_failed")
    counted.check_cancel()
    assert geometry is not None
    summary = {"rows_reported": len(rows), **{state + "_bytes": 0 for state in STATES}}
    for row in rows:
        summary[row["state"] + "_bytes"] += row["length"]
    done = sum(summary[state + "_bytes"] for state in STATES)
    unexamined = length - done
    complete = unexamined == 0
    reasons = [reason for reason in UNKNOWN_REASONS if any(row["reason"] == reason for row in rows)]
    if unexamined:
        if cutoff not in STOP_REASONS:
            _fail("allocation_failed")
        reasons.append(cutoff)
    allocation_complete = complete and summary["unknown_bytes"] == 0
    return {"schema": SCHEMA, "profile": PROFILE, "status": "ok" if allocation_complete else "partial",
            **{field: False for field in FALSE_FIELDS}, "geometry": geometry, "rows": rows, "summary": summary,
            "coverage": {"requested_bytes": length, "processed_bytes": done,
                         "unexamined_offset": None if complete else offset + done, "unexamined_bytes": unexamined,
                         "next_offset": None if complete else offset + done, "window_complete": complete,
                         "allocation_complete": allocation_complete, "metadata_bytes_read": counted.bytes_read,
                         "steps": budget.steps, "reasons": reasons}}


def validate_allocation_accounting(report):
    """완성 보고서의 숫자·prefix·완료 관계를 검증한다. 닫힌 schema 검사 뒤 호출한다."""
    try:
        _validate(report)
    except (KeyError, TypeError, ValueError, IndexError, OverflowError, AssertionError):
        _fail()


def _validate(report):
    if type(report) is not dict or report["schema"] != SCHEMA or report["profile"] != PROFILE:
        _fail()
    src, params, geo, cov, summary, rows = (report[k] for k in ("source", "params", "geometry", "coverage", "summary", "rows"))
    if any(type(item) is not dict for item in (src, params, geo, cov, summary)) or type(rows) is not list or len(rows) > 128:
        _fail()
    def integer(value, low=0, high=MAX_COORD):
        if not _integer(value, low, high):
            _fail()
    for field in FALSE_FIELDS:
        if report[field] is not False:
            _fail()
    if src["kind"] != "evidence":
        _fail()
    integer(src["evidence_size"], 1)
    integer(params["partition"], 1, 4096)
    integer(params["offset"])
    integer(params["length"], 1, MAX_WINDOW)
    seconds = params["max_seconds"]
    if type(seconds) not in (int, float) or not math.isfinite(seconds) or not 0 < seconds <= 45:
        _fail()
    for key in ("partition_offset", "data_offset"):
        integer(geo[key])
    for key in ("partition_size", "data_length"):
        integer(geo[key], 1)
    integer(geo["cluster_size"], 512, 32 << 20)
    cs = geo["cluster_size"]
    if cs & (cs - 1) or geo["data_length"] % cs or geo["fs_type"] not in ("fat12", "fat16", "fat32", "exfat"):
        _fail()
    begin, end = params["offset"], params["offset"] + params["length"]
    if (geo["data_offset"] < geo["partition_offset"] or geo["data_offset"] + geo["data_length"] > MAX_COORD
            or not geo["data_offset"] <= begin < end <= min(src["evidence_size"], geo["partition_offset"] + geo["partition_size"],
                                                            geo["data_offset"] + geo["data_length"])):
        _fail()
    sums = {state + "_bytes": 0 for state in STATES}
    pos, last = begin, None
    for row in rows:
        if type(row) is not dict:
            _fail()
        integer(row["offset"])
        integer(row["length"], 1, MAX_WINDOW)
        state, reason = row["state"], row["reason"]
        if (row["offset"] != pos or state not in STATES or (state == "unknown" and reason not in UNKNOWN_REASONS)
                or (state != "unknown" and reason is not None) or last == (state, reason)):
            _fail()
        pos += row["length"]
        if pos > end:
            _fail()
        sums[state + "_bytes"] += row["length"]
        last = (state, reason)
    integer(summary["rows_reported"], 0, 128)
    if summary["rows_reported"] != len(rows):
        _fail()
    for key, value in sums.items():
        integer(summary[key], 0, MAX_WINDOW)
        if summary[key] != value:
            _fail()
    for key in ("requested_bytes", "processed_bytes", "unexamined_bytes"):
        integer(cov[key], 0, MAX_WINDOW)
    integer(cov["metadata_bytes_read"], 0, 4 << 20)
    integer(cov["steps"])
    complete = pos == end
    if (cov["requested_bytes"] != params["length"] or cov["processed_bytes"] != pos - begin
            or cov["unexamined_bytes"] != end - pos or cov["window_complete"] is not complete
            or cov["allocation_complete"] is not (complete and sums["unknown_bytes"] == 0)
            or report["status"] != ("ok" if cov["allocation_complete"] else "partial")):
        _fail()
    for key in ("unexamined_offset", "next_offset"):
        if complete:
            if cov[key] is not None:
                _fail()
        else:
            integer(cov[key])
            if cov[key] != pos:
                _fail()
    reasons = cov["reasons"]
    expected = [reason for reason in UNKNOWN_REASONS if any(row["reason"] == reason for row in rows)]
    if type(reasons) is not list or any(type(reason) is not str for reason in reasons):
        _fail()
    if complete:
        if reasons != expected:
            _fail()
    elif len(reasons) != len(expected) + 1 or reasons[:-1] != expected or reasons[-1] not in STOP_REASONS:
        _fail()
