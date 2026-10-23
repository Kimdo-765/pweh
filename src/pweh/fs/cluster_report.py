"""FAT/exFAT의 현재 live 참조 일관성을 원문 없는 유한 보고서로 투영한다."""
from __future__ import annotations

from dataclasses import dataclass, fields
import json
import math
import re
import time

from pweh.errors import ValidationFailed
from . import open_volume
from .common import Budget, FsError, Limits
from .volume import detect_partitions, partition_source

SCHEMA = "pweh.cluster-report/v1"
PROFILE = "fat-exfat-live-reference-v1"
MAX_COORD = (1 << 63) - 1
LEAF_BYTES = 64 << 10
FALSE_FIELDS = ("whole_evidence_examined", "orphan_files_verified", "historical_allocation_verified",
                "file_ownership_verified", "media_decoded", "playback_verified", "payload_semantics_examined")
LIMITATIONS = ("current_live_reference_model_only", "observed_metadata_only", "incomplete_reference_map_not_orphan_evidence",
               "allocation_state_not_historical_ownership", "samples_are_bounded", "no_automatic_extraction",
               "no_media_decoding", "no_playback_or_complete_recording_verification")
REASONS = ("time_limit", "step_limit", "metadata_bytes_limit", "cluster_limit", "max_entries", "max_depth",
           "max_dir_slots", "max_total_slots", "max_path_chars", "beyond_image", "dir_chain_broken", "dir_unreadable",
           "dir_unvalidated", "reference_chain_incomplete", "allocation_unreadable", "metadata_inconsistent", "rows_limit")
KINDS = ("allocated-without-live-reference", "unallocated-reference", "overlap-reference", "chain-anomaly")
CHAIN_STATES = ("ok", "limit", "zeroed", "broken", "unreadable", "out-of-range", "cycle", "too_fragmented", "empty")
SIZE_CHECKS = ("ok", "no_clusters", "chain_shorter", "chain_longer")
FLAGS = ("reference_walk_complete", "reference_map_complete", "allocation_complete", "rows_complete")
INSPECTION_KEYS = (*FLAGS, "entries_observed", "allocation_clusters_examined", "allocation_free", "observed_referenced_clusters", "reasons")
COUNT_KEYS = ("allocation_examined", "allocated", "free", "bad", "invalid_values", "observed_referenced_clusters",
              "overlap_reference_events", "unallocated_reference_count", "unallocated_reference_basis", "allocated_without_live_reference")
ROW_KEYS = ("kind", "ref", "cluster", "clusters", "offset", "length", "chain_status", "size_check", "observed_clusters", "expected_clusters")
GEOMETRY_KEYS = ("fs_type", "partition_offset", "partition_size", "data_offset", "cluster_size", "cluster_count")
COVERAGE_KEYS = (*FLAGS, "entries_observed", "allocation_clusters_examined", "allocation_clusters_unexamined", "rows_reported", "metadata_bytes_read", "steps", "reasons")
REF_PATTERN = r"(?:root|c[0-9]+(?:\+[0-9]+)?|n[0-9]+\+[0-9]+)/[0-9]{1,9}"
_CUTOFF = {"time": "time_limit", "steps": "step_limit", "metadata_bytes": "metadata_bytes_limit"}


class ClusterReportError(ValidationFailed):
    """원시 이름·FS 예외를 포함하지 않는 고정 실패."""


def _fail(code="cluster_report_invalid"):
    raise ClusterReportError("클러스터 참조 검사를 완료할 수 없습니다.", code=code) from None


def _integer(value, minimum=0, maximum=MAX_COORD):
    return type(value) is int and minimum <= value <= maximum


@dataclass(frozen=True)
class ClusterReportLimits:
    metadata_bytes: int = 32 << 20
    scan_clusters: int = 1 << 20
    entries: int = 16384
    path_chars: int = 4 << 20
    directory_slots: int = 262144
    depth: int = 64
    runs: int = 8192
    steps: int = 1 << 20
    rows: int = 128
    output_bytes: int = 1 << 20

    def __post_init__(self):
        for field in fields(self):
            if not _integer(getattr(self, field.name), 8192 if field.name == "output_bytes" else 1, field.default):
                _fail()


class _CountingSource:
    """탐지부터 모든 성공 leaf 읽기를 세고 흡수된 오류의 첫 원인을 보존한다."""

    def __init__(self, source, limits, budget, cancel):
        self.source, self.size, self.base_offset = source, source.size, 0
        self.limits, self.budget, self.cancel = limits, budget, cancel
        self.bytes_read = 0
        self.problem = None
        self.cutoff = None
        self.archive_header = False

    def check_cancel(self):
        if self.problem:
            _fail(self.problem)
        if self.cancel is not None:
            try:
                stop = self.cancel()
            except Exception:
                stop = True
            if type(stop) is not bool or stop:
                self.problem = "cancelled"
                _fail(self.problem)

    def check(self, *, step=False):
        self.check_cancel()
        if step:
            self.budget.tick()
        if self.cutoff:
            raise FsError("metadata 예산 중단", reason="budget_exceeded", data={"limit": self.cutoff})
        if self.budget.expired():
            raise self.budget.error("클러스터 metadata")

    def read(self, offset, size):
        self.check()
        if not _integer(offset) or not _integer(size) or offset + size > self.size:
            raise FsError("metadata 범위 오류", reason="out_of_bounds")
        parts, done = [], 0
        while done < size:
            self.check(step=True)
            left = self.limits.metadata_bytes - self.bytes_read
            if not left:
                self.cutoff = "metadata_bytes"
                self.check()
            amount = min(LEAF_BYTES, size - done, left)
            try:
                block = self.source.read(offset + done, amount)
            except Exception:
                self.problem = "cluster_read_failed"
                self.check_cancel()
            if type(block) is not bytes or len(block) != amount:
                self.problem = "cluster_read_failed"
                self.check_cancel()
            if offset + done == 0:
                self.archive_header = (block[:4] in (b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08")
                                       or block[257:263] in (b"ustar\0", b"ustar "))
            self.bytes_read += amount
            self.check()
            parts.append(block)
            done += amount
        return b"".join(parts)

    def read_clamped(self, offset, size):
        self.check()
        if not _integer(offset) or not _integer(size):
            raise FsError("metadata 범위 오류", reason="out_of_bounds")
        return self.read(offset, min(size, self.size - offset)) if offset < self.size else b""


def _stop(exc):
    return _CUTOFF.get(exc.data.get("limit")) if isinstance(exc, FsError) and exc.reason == "budget_exceeded" else None


def _geometry(vol, part):
    kind = "exfat" if vol.kind == "exfat" else vol.fat_type
    count = (vol.boot if kind == "exfat" else vol.bpb)["cluster_count"]
    start, size, heap, cs = part["start_offset"], part["size_bytes"], vol.heap_offset, vol.cluster_size
    if (kind not in ("fat12", "fat16", "fat32", "exfat") or not _integer(start) or not _integer(size, 1)
            or not _integer(heap) or not _integer(count, 1) or not _integer(cs, 512, 32 << 20)
            or cs & (cs - 1) or not _integer(vol.volume_size, 1)
            or max(start + size, start + vol.volume_size, start + heap + count * cs) > MAX_COORD):
        _fail("cluster_report_unsupported")
    return dict(fs_type=kind, partition_offset=start, partition_size=size, data_offset=start + heap,
                cluster_size=cs, cluster_count=count)


def _inconsistent(layout, part, vol, geo, source):
    start, size = geo["partition_offset"], geo["partition_size"]
    end = geo["data_offset"] + geo["cluster_count"] * geo["cluster_size"]
    if (end > min(source.size, start + size, start + vol.volume_size)
            or start + size > source.size or vol.volume_size > size or part.get("warnings")):
        return True
    for other in layout["partitions"]:
        source.check(step=True)
        if other is part or other.get("role") == "extended":
            continue
        a, n = other.get("start_offset"), other.get("size_bytes")
        if not _integer(a) or not _integer(n) or n and max(start, a) < min(start + size, a + n):
            return True
    if layout.get("scheme") == "gpt":
        gpt = layout.get("gpt") or {}
        header = gpt.get(gpt.get("used")) or {}
        if any(x is not True for x in (gpt.get("entries_crc_ok"), header.get("header_crc_ok"), header.get("my_lba_ok"))):
            return True
    if vol.kind == "fat":
        b = vol.bpb
        flags = b.get("ext_flags", 0)
        if (vol.max_cluster != b["cluster_count"] + 1 or b["fat_type"] != b["fat_type_by_count"]
                or b.get("fs_version", 0) != 0 or vol.fat_type == "fat32" and flags & 128 and (flags & 15) >= b["num_fats"]):
            return True
        return bool(set(vol._w.codes()) & {"bpb_bad_jump", "boot_signature_missing", "bpb_both_totsec",
                                          "bpb_fat32_rootent", "bpb_rootent_align", "fat_too_small"})
    b = vol.boot
    return (b["cluster_count"] != vol.cluster_count or b["number_of_fats"] == 1 and vol.volume_flags & 1
            or b["fat_offset"] < 24
            or b["cluster_heap_offset"] < b["fat_offset"] + b["fat_length"] * b["number_of_fats"])


def _empty(reason):
    return {"inspection": {**dict.fromkeys(FLAGS, False), "rows_complete": True, "entries_observed": 0, "allocation_clusters_examined": 0,
                           "allocation_free": 0, "observed_referenced_clusters": 0, "reasons": [reason]}}


def _ref(value):
    if value in (None, "root", "bitmap", "upcase"):
        return None
    if type(value) is not str or len(value) > 96 or re.fullmatch(REF_PATTERN, value, flags=re.ASCII) is None:
        _fail("cluster_report_failed")
    return value


def _number(value, low=0, high=MAX_COORD):
    if not _integer(value, low, high):
        _fail("cluster_report_failed")
    return value


def _project(legacy, geo, counted, limits):
    ins = legacy["inspection"]
    if (type(ins) is not dict or set(ins) != set(INSPECTION_KEYS)
            or any(type(ins[k]) is not bool for k in FLAGS)):
        _fail("cluster_report_failed")
    for key in ("entries_observed", "allocation_clusters_examined", "allocation_free", "observed_referenced_clusters"):
        _number(ins[key])
    reasons = ins["reasons"]
    if type(reasons) is not list or any(type(x) is not str or x not in REASONS for x in reasons):
        _fail("cluster_report_failed")
    reasons = set(reasons)
    fat = geo["fs_type"] != "exfat"
    complete_map = ins["reference_map_complete"] and ins["allocation_complete"]
    counts = dict(allocation_examined=ins["allocation_clusters_examined"], allocated=_number(legacy.get("allocated", 0)),
                  free=ins["allocation_free"], bad=_number(legacy.get("bad", 0)) if fat else None,
                  invalid_values=_number(legacy.get("invalid_values", 0)) if fat else None,
                  observed_referenced_clusters=ins["observed_referenced_clusters"],
                  overlap_reference_events=_number(legacy.get("cross_linked", 0)),
                  unallocated_reference_count=_number(legacy.get("unallocated_referenced", 0)),
                  unallocated_reference_basis="fat-chain-heads" if fat else "exfat-clusters",
                  allocated_without_live_reference=_number(legacy["allocated_unreferenced"]) if complete_map else None)
    rows = []
    def add(kind, *, ref=None, cluster=None, clusters=None, chain_status=None, size_check=None, observed_clusters=None, expected_clusters=None):
        row = dict.fromkeys(ROW_KEYS)
        row.update(kind=kind, ref=_ref(ref), cluster=cluster, clusters=clusters, chain_status=chain_status,
                   size_check=size_check, observed_clusters=observed_clusters, expected_clusters=expected_clusters)
        if cluster is not None:
            _number(cluster, 2); _number(clusters, 1)
            row["offset"] = geo["data_offset"] + (cluster - 2) * geo["cluster_size"]
            row["length"] = clusters * geo["cluster_size"]
        _validate_row(row, geo, counted.size)
        if len(rows) < limits.rows:
            rows.append(row)
        else:
            reasons.add("rows_limit")
    if complete_map:
        for start, count in legacy.get("allocated_unreferenced_runs", []):
            counted.check_cancel()
            add(KINDS[0], cluster=start, clusters=count)
    for kind, key in ((KINDS[1], "unallocated_referenced_samples"), (KINDS[2], "cross_linked_samples")):
        for item in legacy.get(key, []):
            counted.check_cancel()
            add(kind, ref=item.get("ref"), cluster=item["cluster"], clusters=1)
    for item in legacy.get("chain_anomalies", []):
        counted.check_cancel()
        add(KINDS[3], ref=item.get("ref"), chain_status=item["status"], size_check=item.get("size_check"),
            observed_clusters=item.get("clusters"), expected_clusters=item.get("expected_clusters"))
    cov = {**{k: ins[k] for k in FLAGS}, "entries_observed": ins["entries_observed"],
           "allocation_clusters_examined": counts["allocation_examined"],
           "allocation_clusters_unexamined": geo["cluster_count"] - counts["allocation_examined"],
           "rows_reported": len(rows), "metadata_bytes_read": counted.bytes_read, "steps": counted.budget.steps, "reasons": []}
    out = dict(schema=SCHEMA, profile=PROFILE, status="partial", geometry=geo, counts=counts, rows=rows, coverage=cov,
               limitations=list(LIMITATIONS), **dict.fromkeys(FALSE_FIELDS, False))
    while True:
        counted.check_cancel()
        if "rows_limit" in reasons:
            cov["rows_complete"] = False
        cov["reasons"] = [x for x in REASONS if x in reasons]
        cov["rows_reported"] = len(rows)
        out["status"] = "ok" if all(cov[k] for k in FLAGS) and not cov["reasons"] else "partial"
        if len(json.dumps(out, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()) + 1 <= limits.output_bytes:
            break
        if not rows:
            _fail("cluster_report_failed")
        rows.pop()
        reasons.add("rows_limit")
    _validate(out, evidence_size=counted.size)
    return out


def inspect_cluster_report(source, *, partition, limits=ClusterReportLimits(), deadline, cancel=None):
    """하나의 Source·Budget에서 현재 live 참조를 검사한다. source/params는 adapter가 결속한다."""
    if (type(limits) is not ClusterReportLimits or not _integer(partition, 1, 4096)
            or not _integer(getattr(source, "size", None), 1) or type(getattr(source, "base_offset", None)) is not int
            or source.base_offset != 0 or not callable(getattr(source, "read", None))
            or type(deadline) not in (int, float) or cancel is not None and not callable(cancel)):
        _fail()
    try:
        if not math.isfinite(float(deadline)):
            _fail()
        end = min(float(deadline), time.monotonic() + 45)
    except (OverflowError, ValueError):
        _fail()
    budget = Budget(deadline=end, max_steps=limits.steps)
    counted = _CountingSource(source, limits, budget, cancel)
    def cancelled():
        counted.check_cancel()
        return False
    budget.cancel = cancelled
    geo = None
    try:
        counted.check()
        fs_limits = Limits(max_follow_steps=limits.steps, max_scan_clusters=limits.scan_clusters,
                           max_entries=limits.entries, max_list=limits.entries, max_path_chars=limits.path_chars,
                           max_dir_slots=limits.directory_slots, max_total_slots=limits.directory_slots,
                           max_depth=limits.depth, max_runs=limits.runs, max_report_items=limits.rows)
        layout = detect_partitions(counted, limits=fs_limits)
        counted.check()
        if not layout["partitions"] and counted.archive_header:
            _fail("cluster_report_unsupported")
        selected = [p for p in layout["partitions"] if type(p.get("index")) is int and p["index"] == partition]
        if len(selected) != 1:
            _fail("partition_unavailable")
        part = selected[0]
        if not _integer(part.get("start_offset")) or not _integer(part.get("size_bytes"), 1):
            _fail("cluster_report_failed")
        vol = open_volume(partition_source(counted, part), limits=fs_limits, budget=budget, metadata_mode="full")
        counted.check_cancel()
        geo = _geometry(vol, part)
        counted.check()
        if _inconsistent(layout, part, vol, geo, counted):
            legacy = _empty("metadata_inconsistent")
        elif geo["cluster_count"] > limits.scan_clusters:
            legacy = _empty("cluster_limit")
        else:
            legacy = vol.cluster_report(limits=fs_limits, budget=budget)
        counted.check_cancel()
        return _project(legacy, geo, counted, limits)
    except Exception as exc:
        counted.check_cancel()
        reason = _stop(exc)
        if reason and geo is not None:
            return _project(_empty(reason), geo, counted, limits)
        if isinstance(exc, ClusterReportError):
            raise exc from None
        if reason:
            _fail("time_limit" if reason == "time_limit" else "cluster_report_failed")
        if isinstance(exc, FsError) and exc.reason in ("unsupported_fs", "not_fat", "not_exfat"):
            _fail("cluster_report_unsupported")
        _fail("cluster_report_failed")


def _object(value, keys):
    if type(value) is not dict or set(value) != set(keys):
        _fail()


def _validate_row(row, geo, evidence_size):
    _object(row, ROW_KEYS)
    kind = row["kind"]
    if kind not in KINDS or row["ref"] is not None and (type(row["ref"]) is not str or len(row["ref"]) > 96
                                                     or re.fullmatch(REF_PATTERN, row["ref"], re.ASCII) is None):
        _fail()
    if kind == "chain-anomaly":
        if (any(row[k] is not None for k in ("cluster", "clusters", "offset", "length"))
                or row["chain_status"] not in CHAIN_STATES or row["size_check"] not in SIZE_CHECKS):
            _fail()
        for key in ("observed_clusters", "expected_clusters"):
            if row[key] is not None and not _integer(row[key]):
                _fail()
        return
    if any(row[k] is not None for k in ("chain_status", "size_check", "observed_clusters", "expected_clusters")):
        _fail()
    c, n, off, length = (row[k] for k in ("cluster", "clusters", "offset", "length"))
    if (not _integer(c, 2) or not _integer(n, 1) or not _integer(off) or not _integer(length, 1)
            or c + n > geo["cluster_count"] + 2 or off != geo["data_offset"] + (c - 2) * geo["cluster_size"]
            or length != n * geo["cluster_size"] or off + length > min(evidence_size, geo["partition_offset"] + geo["partition_size"])):
        _fail()
    if kind == KINDS[0] and row["ref"] is not None or kind != KINDS[0] and n != 1:
        _fail()
    if kind == KINDS[1] and geo["fs_type"] == "exfat" and row["ref"] is not None:
        _fail()


def _validate(report, *, evidence_size=None):
    keys = ("schema", "profile", "status", "geometry", "counts", "rows", "coverage", "limitations", *FALSE_FIELDS)
    full = evidence_size is None
    _object(report, (*keys, "source", "params") if full else keys)
    if report["schema"] != SCHEMA or report["profile"] != PROFILE or report["limitations"] != list(LIMITATIONS):
        _fail()
    if any(report[k] is not False for k in FALSE_FIELDS):
        _fail()
    if full:
        src, params = report["source"], report["params"]
        _object(src, ("kind", "evidence_id", "evidence_sha256", "evidence_size"))
        _object(params, ("partition", "max_seconds"))
        if (src["kind"] != "evidence" or type(src["evidence_id"]) is not str or re.fullmatch(r"EV-[0-9]{4,6}", src["evidence_id"]) is None
                or type(src["evidence_sha256"]) is not str or re.fullmatch(r"[0-9a-f]{64}", src["evidence_sha256"]) is None
                or not _integer(src["evidence_size"], 1) or not _integer(params["partition"], 1, 4096)
                or type(params["max_seconds"]) not in (int, float) or not math.isfinite(params["max_seconds"])
                or not 0 < params["max_seconds"] <= 45):
            _fail()
        evidence_size = src["evidence_size"]
    geo, cnt, cov, rows = (report[k] for k in ("geometry", "counts", "coverage", "rows"))
    _object(geo, GEOMETRY_KEYS); _object(cnt, COUNT_KEYS); _object(cov, COVERAGE_KEYS)
    if geo["fs_type"] not in ("fat12", "fat16", "fat32", "exfat"):
        _fail()
    for k in ("partition_offset", "data_offset"):
        if not _integer(geo[k]):
            _fail()
    for k in ("partition_size", "cluster_count"):
        if not _integer(geo[k], 1):
            _fail()
    cs, nc, start, size, data = (geo[k] for k in ("cluster_size", "cluster_count", "partition_offset", "partition_size", "data_offset"))
    if (not _integer(cs, 512, 32 << 20) or cs & (cs-1) or data < start
            or max(start + size, data + nc * cs) > MAX_COORD):
        _fail()
    for k in FLAGS:
        if type(cov[k]) is not bool:
            _fail()
    for k in ("entries_observed", "allocation_clusters_examined", "allocation_clusters_unexamined", "rows_reported", "metadata_bytes_read", "steps"):
        if not _integer(cov[k]):
            _fail()
    if cov["entries_observed"] > 16384 or cov["metadata_bytes_read"] > 32 << 20 or cov["rows_reported"] > 128:
        _fail()
    for k in COUNT_KEYS:
        if k not in ("unallocated_reference_basis", "bad", "invalid_values", "allocated_without_live_reference") and not _integer(cnt[k]):
            _fail()
    fat = geo["fs_type"] != "exfat"
    if fat:
        if (not _integer(cnt["bad"]) or not _integer(cnt["invalid_values"]) or cnt["invalid_values"] > cnt["allocated"]
                or cnt["allocation_examined"] != cnt["allocated"] + cnt["free"] + cnt["bad"]
                or cnt["unallocated_reference_basis"] != "fat-chain-heads"):
            _fail()
    elif (cnt["bad"] is not None or cnt["invalid_values"] is not None
          or cnt["allocation_examined"] != cnt["allocated"] + cnt["free"] or cnt["unallocated_reference_basis"] != "exfat-clusters"):
        _fail()
    if (cnt["observed_referenced_clusters"] > nc or cnt["allocation_examined"] != cov["allocation_clusters_examined"]
            or cov["allocation_clusters_examined"] + cov["allocation_clusters_unexamined"] != nc
            or cov["reference_map_complete"] and not cov["reference_walk_complete"]
            or cov["allocation_complete"] and cov["allocation_clusters_unexamined"] != 0):
        _fail()
    reasons = cov["reasons"]
    if (type(reasons) is not list or any(type(x) is not str or x not in REASONS for x in reasons)
            or reasons != [r for r in REASONS if r in reasons] or type(rows) is not list or len(rows) > 128
            or cov["rows_reported"] != len(rows) or "rows_limit" in reasons and cov["rows_complete"]):
        _fail()
    if report["status"] != ("ok" if all(cov[k] for k in FLAGS) and not reasons else "partial"):
        _fail()
    valid_extent = data + nc * cs <= min(evidence_size, start + size) and start + size <= evidence_size
    if not valid_extent and ("metadata_inconsistent" not in reasons or rows or cnt["allocation_examined"]
                             or any(cov[k] for k in FLAGS[:3])):
        _fail()
    unref = cnt["allocated_without_live_reference"]
    if cov["reference_map_complete"] and cov["allocation_complete"]:
        if not _integer(unref, 0, cnt["allocated"]):
            _fail()
    elif unref is not None:
        _fail()
    last_kind, last_end, run_sum = -1, 2, 0
    for row in rows:
        _validate_row(row, geo, evidence_size)
        kind = KINDS.index(row["kind"])
        if kind < last_kind:
            _fail()
        last_kind = kind
        if kind == 0:
            if unref is None or row["cluster"] < last_end:
                _fail()
            last_end = row["cluster"] + row["clusters"]
            run_sum += row["clusters"]
    if unref is not None and (run_sum > unref or cov["rows_complete"] and run_sum != unref):
        _fail()


def validate_cluster_report_accounting(report):
    """닫힌 schema 검사 뒤 전체 보고서의 exact 숫자와 완료도 관계를 검사한다."""
    try:
        _validate(report)
    except (KeyError, TypeError, ValueError, IndexError, OverflowError, AssertionError):
        _fail()
