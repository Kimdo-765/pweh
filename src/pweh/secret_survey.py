"""검증된 FAT/exFAT 목록의 자동 선정과 비밀값 검사 집계. 파일 I/O와 원문 출력은 없다."""
from __future__ import annotations

import copy
import json
import math
import re
import time
from dataclasses import asdict, dataclass, fields
from functools import lru_cache

from jsonschema import Draft202012Validator, validators

from .errors import PwehError
from .schemas import load
from .secretscan import KINDS, PATTERN_IDS, RULE_PACK, ScanLimits

SCHEMA = "pweh.secrets-survey/v1"
PROFILE = "fat-exfat-listed-text-v1"
FILESYSTEMS = ("fat12", "fat16", "fat32", "exfat")
LISTING_REASONS = ("listing_incomplete", "listing_coverage_unknown", "unsupported_volume", "volume_failed",
                   "partitions_unexamined", "cut_directories", "unvalidated_directories", "volume_incomplete",
                   "deleted_not_included", "partition_restricted")
READ_REASONS = ("refs_unverifiable", "metadata_unverifiable", "incomplete_file", "read_failed", "time_limit")
STOP_REASONS = ("hit_limit", "time_limit", "output_limit")
REASONS = LISTING_REASONS + ("file_limit", "total_bytes_limit") + STOP_REASONS + (
    "read_failed", "scanner_partial", "scanner_unsupported", "selection_uncertain")
LIMITATIONS = ("listed_files_only", "fat_exfat_only", "utf8_only", "policy_exclusions_apply",
               "unlisted_unallocated_and_residual_unexamined", "heuristic_candidates_only",
               "deleted_history_not_complete", "no_plaintext_output", "no_media_decoding",
               "no_authentication", "no_encryption_or_compromise_assessment")
SCANNER_MAX_RANGES = 128
SCANNER_MAX_OUTPUT_BYTES = 24 << 10
_TOP_RESERVE = 16 << 10
_ROW_RESERVE = 3072
_U64 = (1 << 64) - 1
_REF = re.compile(r"[0-9a-z+]{1,40}/[0-9]{1,9}\Z")


def _error(code="secret_survey_invalid"):
    return PwehError("저장 목록 비밀값 검사의 입력 또는 결과 계약을 확인하지 못했습니다.", code=code)


def _uint(value, maximum=_U64):
    return type(value) is int and 0 <= value <= maximum


def _cancel(cancel):
    if cancel is None:
        return
    try:
        value = cancel()
    except Exception:
        raise _error("secret_survey_callback_failed") from None
    if type(value) is not bool:
        raise _error("secret_survey_callback_failed")
    if value:
        raise PwehError("저장 목록 비밀값 검사가 취소되었습니다.", code="cancelled")


def _encoded(value):
    return json.dumps(value, ensure_ascii=True, separators=(",", ":"), allow_nan=False).encode("ascii")


@dataclass(frozen=True)
class SurveyLimits:
    """선정·읽기 계획·출력 상한은 기본값보다 낮출 수만 있다."""

    max_file_bytes: int = 4 << 20
    max_files: int = 32
    max_read_bytes: int = 16 << 20
    max_hits: int = 200
    max_entries: int = 200000
    max_output_bytes: int = 1 << 20


def _limits(limits):
    if type(limits) is not SurveyLimits:
        raise _error()
    defaults = SurveyLimits()
    for f in fields(limits):
        value = getattr(limits, f.name)
        minimum = _TOP_RESERVE if f.name == "max_output_bytes" else 1
        if type(value) is not int or not minimum <= value <= getattr(defaults, f.name):
            raise _error()


@dataclass(frozen=True)
class SurveyTarget:
    """저장 배열의 위치와 파일 신원. 이름·경로·시각·내용은 보유하지 않는다."""

    volume_index: int
    entry_index: int
    partition: int
    ref: str
    fs: str
    declared_size: int
    expected_size: int
    deleted: bool
    parent_deleted: bool | None
    name_lossy: bool


@dataclass(frozen=True)
class SurveyPlan:
    """원문 없는 확정 계수를 보관하며 외부에는 독립 사본만 제공한다."""

    targets: tuple[SurveyTarget, ...]
    limits: SurveyLimits
    _listing: bytes
    _selection: bytes
    _supported: int
    _uncertain: bool

    @property
    def listing(self):
        return json.loads(self._listing)

    @property
    def selection(self):
        return json.loads(self._selection)


def _listing_coverage(listing, partition):
    """호출 개수가 권위다. 오류 행/20개 표본을 건너뛴 파티션에 다시 더하지 않는다."""
    reasons = set()
    params, call = listing["params"], listing["call"]
    included = params.get("include_deleted")
    if included is not None and type(included) is not bool:
        raise _error()
    if included is not True:
        reasons.add("deleted_not_included")
    if "partition" not in params or included is None:
        reasons.add("listing_coverage_unknown")
    original = params.get("partition")
    if original is not None and (not _uint(original, 4096) or original == 0):
        raise _error()
    if original is not None or partition is not None:
        reasons.add("partition_restricted")
    skipped, unexamined, failed = (call.get(k) for k in (
        "partitions_skipped", "partitions_unexamined", "volumes_failed"))
    if type(skipped) is not dict or type(unexamined) is not list:
        missing = unsupported = None
        reasons.add("listing_coverage_unknown")
    else:
        missing = unsupported = 0
        for reason, record in skipped.items():
            if type(record) is not dict or not _uint(record.get("count"), 4096):
                raise _error()
            if reason != "duplicate":
                missing += record["count"]
            if reason == "unsupported_partitions":
                unsupported += record["count"]
        if missing > 4096 or len(unexamined) > missing:
            missing = unsupported = None
            reasons.add("listing_coverage_unknown")
    if type(failed) is dict and _uint(failed.get("count"), 4096):
        failed_count = failed["count"]
    else:
        failed_count = None
        reasons.add("listing_coverage_unknown")
    if missing:
        reasons.add("partitions_unexamined")
    if unsupported:
        reasons.add("unsupported_volume")
    if failed_count:
        reasons.add("volume_failed")
    return {"complete": False, "include_deleted": included, "selected_partitions": [],
            "partitions_listed": len(listing["volumes"]), "partitions_outside_selection": 0,
            "partitions_unsupported": unsupported, "partitions_unexamined": missing,
            "volumes_failed": failed_count, "cut_dirs": 0, "unvalidated_dirs": 0, "reasons": []}, reasons


def _volume_coverage(volume, cov, reasons):
    walk, info, part = volume["walk"], volume["info"], volume["partition"]
    for field, reason in (("cut_dirs", "cut_directories"), ("unvalidated_dirs", "unvalidated_directories")):
        value = walk.get(field + "_total")
        if value is not None and not _uint(value, 200000):
            raise _error()
        if value is None:
            cov[field] = None
            reasons.add("listing_coverage_unknown")
        elif cov[field] is not None:
            cov[field] += value
        if value:
            reasons.add(reason)
    for item in (walk, info):
        if type(item.get("truncated")) is not bool:
            reasons.add("listing_coverage_unknown")
    if (walk.get("truncated") is True or walk.get("truncated_reason") or walk.get("truncated_reasons")
            or walk.get("warnings") or walk.get("warnings_suppressed")):
        reasons.add("listing_incomplete")
    if (info.get("truncated") is True or info.get("warnings") or part.get("warnings")
            or _uint(info.get("volume_size")) and _uint(part.get("size_bytes"))
            and info["volume_size"] > part["size_bytes"]):
        reasons.add("volume_incomplete")


def plan_survey(listing, *, partition=None, is_media_name, limits=SurveyLimits(), deadline, cancel=None):
    """모든 정책 분류를 마친 뒤 예산에 맞는 앞부분만 정한다. 시간 부족 시 계수를 내지 않는다."""
    _limits(limits)
    try:
        valid_deadline = type(deadline) in (int, float) and math.isfinite(deadline)
    except (OverflowError, ValueError):
        valid_deadline = False
    if not valid_deadline or not callable(is_media_name):
        raise _error()
    if partition is not None and (not _uint(partition, 4096) or partition == 0):
        raise _error()
    end = min(deadline, time.monotonic() + 45)

    def tick():
        _cancel(cancel)
        if time.monotonic() >= end:
            raise PwehError("저장 목록의 정책 분류 시간 한도에 도달했습니다.", code="timeout")

    tick()
    if (type(listing) is not dict or listing.get("schema") != "pweh.forensics.fs-list/v1"
            or "archive" in listing or any(type(listing.get(k)) is not dict for k in ("params", "call"))
            or type(listing.get("volumes")) is not list or len(listing["volumes"]) > 4096):
        raise _error()
    cov, reasons = _listing_coverage(listing, partition)
    selection = {"complete": True, "entries_total": 0, "directories": 0, "regular_files": 0,
                 "excluded": dict.fromkeys(("media_name", "empty_data", "file_too_large"), 0),
                 "eligible_files": 0, "eligible_bytes": 0, "scheduled_files": 0, "scheduled_bytes": 0,
                 "deferred_eligible_files": 0, "deferred_eligible_bytes": 0, "cutoff_reason": None,
                 "residual_files": 0, "residual_bytes": 0}
    targets, seen_parts, total_entries = [], set(), 0
    supported = nonbudget_failures = 0
    uncertain = False
    for vi, volume in enumerate(listing["volumes"]):
        tick()
        if type(volume) is not dict:
            raise _error()
        part = volume.get("partition")
        index = part.get("index") if type(part) is dict else part
        if not _uint(index, 4096) or index == 0 or index in seen_parts:
            raise _error()
        seen_parts.add(index)
        if partition is not None and index != partition:
            cov["partitions_outside_selection"] += 1
            continue
        error = volume.get("error")
        if error is not None:
            if type(error) is not dict or type(error.get("data", {})) is not dict:
                raise _error()
            if error.get("data", {}).get("reason") != "budget_exceeded":
                nonbudget_failures += 1
                reasons.add("volume_failed")
            else:
                reasons.add("partitions_unexamined")
            reasons.add("listing_incomplete")
            continue
        info, walk = volume.get("info"), volume.get("walk")
        if type(part) is not dict or type(info) is not dict or type(walk) is not dict:
            raise _error()
        fs = info.get("fs_type")
        if fs not in FILESYSTEMS:
            reasons.add("unsupported_volume")
            continue
        if walk.get("fs", fs) != fs or type(walk.get("entries")) is not list:
            raise _error()
        supported += 1
        cov["selected_partitions"].append(index)
        _volume_coverage(volume, cov, reasons)
        seen_refs = set()
        for ei, entry in enumerate(walk["entries"]):
            tick()
            total_entries += 1
            if total_entries > limits.max_entries:
                raise _error("secret_survey_limit")
            if type(entry) is not dict:
                raise _error()
            ref = entry.get("ref")
            if (type(ref) is not str or not _REF.fullmatch(ref) or ref in seen_refs or entry.get("fs") != fs
                    or any(type(entry.get(k)) is not bool for k in ("is_dir", "deleted", "name_lossy"))
                    or entry.get("parent_deleted") is not None and type(entry["parent_deleted"]) is not bool
                    or not _uint(entry.get("size"))):
                raise _error()
            seen_refs.add(ref)
            selection["entries_total"] += 1
            if entry["is_dir"]:
                selection["directories"] += 1
                continue
            selection["regular_files"] += 1
            declared = entry["size"]
            expected = entry.get("valid_data_length") if fs == "exfat" else declared
            if not _uint(expected) or expected > declared:
                raise _error()
            if expected < declared:
                selection["residual_files"] += 1
                selection["residual_bytes"] += declared - expected
            name = entry.get("path", entry.get("name"))
            if type(name) is not str or not name or len(name) > 262144:
                raise _error()
            try:
                media = is_media_name(name)
            except Exception:
                raise _error("secret_survey_callback_failed") from None
            if type(media) is not bool:
                raise _error("secret_survey_callback_failed")
            tick()
            excluded = "media_name" if media else "empty_data" if not expected else (
                "file_too_large" if expected > limits.max_file_bytes else None)
            if excluded:
                selection["excluded"][excluded] += 1
                continue
            selection["eligible_files"] += 1
            selection["eligible_bytes"] += expected
            uncertain |= entry["deleted"] or entry.get("parent_deleted") is not False or entry["name_lossy"]
            if selection["cutoff_reason"] is None:
                if len(targets) >= limits.max_files:
                    selection["cutoff_reason"] = "file_limit"
                elif selection["scheduled_bytes"] + expected > limits.max_read_bytes:
                    selection["cutoff_reason"] = "total_bytes_limit"
                else:
                    targets.append(SurveyTarget(vi, ei, index, ref, fs, declared, expected, entry["deleted"],
                                                entry.get("parent_deleted"), entry["name_lossy"]))
                    selection["scheduled_bytes"] += expected
    tick()
    if partition is not None and partition not in seen_parts:
        raise _error("scope_unavailable")
    if cov["volumes_failed"] is not None and nonbudget_failures > cov["volumes_failed"]:
        cov["volumes_failed"] = None
        reasons.add("listing_coverage_unknown")
    selection["scheduled_files"] = len(targets)
    selection["deferred_eligible_files"] = selection["eligible_files"] - len(targets)
    selection["deferred_eligible_bytes"] = selection["eligible_bytes"] - selection["scheduled_bytes"]
    cov["complete"] = not (reasons - {"partition_restricted"})
    cov["reasons"] = [r for r in LISTING_REASONS if r in reasons]
    return SurveyPlan(tuple(targets), limits, _encoded(cov), _encoded(selection), supported, uncertain)


def _bounded_result(value, cancel):
    """스키마 검사/복사 전에 입력 객체 작업량과 스칼라 크기를 제한한다."""
    stack, nodes, chars = [(value, 0)], 0, 0
    while stack:
        item, depth = stack.pop()
        nodes += 1
        if nodes % 128 == 1:
            _cancel(cancel)
        if nodes > 12000 or depth > 16:
            raise _error()
        if type(item) is dict:
            if len(item) > 64 or any(type(k) is not str or len(k) > 64 for k in item):
                raise _error()
            chars += sum(len(k) for k in item)
            stack.extend((v, depth + 1) for v in item.values())
        elif type(item) is list:
            if len(item) > 200:
                raise _error()
            stack.extend((v, depth + 1) for v in item)
        elif type(item) is str:
            chars += len(item)
            if len(item) > 256:
                raise _error()
        elif type(item) is int:
            if not _uint(item, _U64):
                raise _error()
        elif item is not None and type(item) is not bool:
            raise _error()
        if chars > SCANNER_MAX_OUTPUT_BYTES:
            raise _error("secret_survey_limit")


@lru_cache(maxsize=2)
def _validator(name):
    root = load("secrets-survey")
    checker = Draft202012Validator.TYPE_CHECKER.redefine("integer", lambda _, v: type(v) is int)
    cls = validators.extend(Draft202012Validator, type_checker=checker)
    return cls({"$ref": "#/$defs/" + name, "$defs": root["$defs"]})


class SurveyCollector:
    """원문 없는 child 결과를 순서대로 원자 반영한다. 시간 partial도 취소/상한은 유지한다."""

    def __init__(self, plan, *, xor_key, limits=SurveyLimits(), cancel=None):
        _limits(limits)
        if type(plan) is not SurveyPlan or plan.limits != limits or (
                xor_key is not None and (type(xor_key) is not int or xor_key != 144)):
            raise _error()
        self.plan, self.limits, self.cancel, self.xor_key = plan, limits, cancel, xor_key
        self._files, self._hits, self._size = [], 0, _TOP_RESERVE
        self._stop = None
        self._finished = False
        _cancel(cancel)

    def scan_limits(self):
        _cancel(self.cancel)
        if self._finished:
            raise _error()
        if self._stop is not None:
            return None
        if self._hits >= self.limits.max_hits:
            self._stop = "hit_limit"
            return None
        if self._size + SCANNER_MAX_OUTPUT_BYTES + _ROW_RESERVE + 1 > self.limits.max_output_bytes:
            self._stop = "output_limit"
            return None
        return ScanLimits(max_bytes=self.limits.max_file_bytes, max_hits=self.limits.max_hits - self._hits,
                          max_ranges=SCANNER_MAX_RANGES, max_output_bytes=SCANNER_MAX_OUTPUT_BYTES)

    def _next(self, target):
        _cancel(self.cancel)
        pos = len(self._files)
        if (self._finished or self._stop is not None or type(target) is not SurveyTarget
                or pos >= len(self.plan.targets) or target != self.plan.targets[pos]):
            raise _error()

    def _append(self, row):
        size = len(_encoded(row))
        child_size = len(_encoded(row["scan"])) if row["scan"] is not None else 0
        if (child_size > SCANNER_MAX_OUTPUT_BYTES or size - child_size > _ROW_RESERVE
                or self._size + size + 1 > self.limits.max_output_bytes):
            raise _error("secret_survey_limit")
        _cancel(self.cancel)
        self._files.append(copy.deepcopy(row))
        self._size += size + 1

    def accept_file(self, target, fresh_source, scan_report):
        self._next(target)
        _bounded_result(fresh_source, self.cancel)
        _bounded_result(scan_report, self.cancel)
        if not _validator("fresh_source").is_valid(fresh_source) or not _validator("scan_result").is_valid(scan_report):
            raise _error()
        self._source(target, fresh_source)
        self._scan(target, scan_report)
        self._append({"target": asdict(target), "outcome": "scanned", "reason": None,
                      "source": fresh_source, "scan": scan_report})
        self._hits += len(scan_report["matches"])

    def _source(self, target, source):
        for name in ("partition", "ref", "fs", "declared_size", "expected_size", "deleted", "name_lossy"):
            if source[name] != getattr(target, name) or type(source[name]) is not type(getattr(target, name)):
                raise _error()
        if (source["complete"] is not True or type(source["parent_deleted"]) is not bool
                or target.parent_deleted is not None and source["parent_deleted"] is not target.parent_deleted
                or source["selected_size"] != target.expected_size
                or source["residual_unexamined"] is not (target.declared_size > target.expected_size)):
            raise _error()
        methods = ("chain", "nofatchain", "contiguous", "skip-allocated", "stale-chain") if target.fs == "exfat" else (
            "chain", "contiguous", "skip-allocated", "skip-claimed", "fat-chain")
        if source["method"] not in methods:
            raise _error()

    def _scan(self, target, report):
        cov, matches = report["coverage"], report["matches"]
        if (report["params"]["xor_key"] != self.xor_key
                or report["params"]["max_hits"] != self.limits.max_hits - self._hits
                or cov["input_bytes"] != target.expected_size or cov["read_bytes"] != target.expected_size
                or cov["scanned_bytes"] + cov["framing_bytes"] + cov["unscanned_bytes"] != target.expected_size
                or len(matches) > self.limits.max_hits - self._hits
                or len(cov["scanned_ranges"]) + len(cov["unscanned_ranges"]) > SCANNER_MAX_RANGES):
            raise _error()
        ranges = []
        scanned = framing = unscanned = 0
        for row in cov["scanned_ranges"]:
            if row["framing_bytes"] > row["length"]:
                raise _error()
            scanned += row["length"] - row["framing_bytes"]
            framing += row["framing_bytes"]
            ranges.append((row["offset"], row["length"]))
        for row in cov["unscanned_ranges"]:
            unscanned += row["length"]
            ranges.append((row["offset"], row["length"]))
        # BOM은 선두 3바이트의 framing이며 범위 행에는 포함되지 않는다.
        bom = cov["framing_bytes"] - framing
        pos = bom
        if bom not in (0, 3) or scanned != cov["scanned_bytes"] or unscanned != cov["unscanned_bytes"]:
            raise _error()
        for offset, length in sorted(ranges):
            if offset != pos or offset + length > target.expected_size:
                raise _error()
            pos += length
        if pos != target.expected_size or cov["lines_seen"] != cov["lines_scanned"] + cov["lines_skipped"]:
            raise _error()
        counts, digests = dict.fromkeys(KINDS, 0), set()
        for hit in matches:
            if hit["offset"] + hit["length"] > target.expected_size or hit["line"] > cov["lines_seen"]:
                raise _error()
            counts[hit["kind"]] += 1
            if hit["digest"] is not None:
                digests.add(hit["digest"])
        if report["summary"] != {"hits": len(matches), "by_kind": counts, "unique_digest_count": len(digests)}:
            raise _error()
        complete = not cov["reasons"]
        if (cov["analysis_complete"] is not complete or cov["hits_are_lower_bound"] is not (not complete)
                or report["status"] == "ok" and not complete
                or report["status"] != "ok" and complete
                or cov["container_examined"] is not False or cov["selection_uncertain"] is not False):
            raise _error()

    def skip_file(self, target, reason):
        self._next(target)
        if reason not in READ_REASONS:
            raise _error()
        self._append({"target": asdict(target), "outcome": "read_failed", "reason": reason,
                      "source": None, "scan": None})

    def finish(self, stop_reason=None):
        _cancel(self.cancel)
        if self._finished or stop_reason is not None and stop_reason not in STOP_REASONS:
            raise _error()
        if self._stop is not None and stop_reason is not None and self._stop != stop_reason:
            raise _error()
        stop_reason = stop_reason or self._stop
        remaining = len(self.plan.targets) - len(self._files)
        if remaining and stop_reason is None:
            raise _error()
        listing, selection = self.plan.listing, self.plan.selection
        reasons = set(listing["reasons"])
        if selection["cutoff_reason"]:
            reasons.add(selection["cutoff_reason"])
        if stop_reason:
            reasons.add(stop_reason)
        complete_rows = [r for r in self._files if r["outcome"] == "scanned"]
        statuses = {s: sum(r["scan"]["status"] == s for r in complete_rows) for s in ("ok", "partial", "unsupported")}
        failed = len(self._files) - len(complete_rows)
        if failed:
            reasons.add("read_failed")
        if statuses["partial"]:
            reasons.add("scanner_partial")
        if statuses["unsupported"]:
            reasons.add("scanner_unsupported")
        uncertain = self.plan._uncertain or any(r["source"]["confidence"] != "high" for r in complete_rows)
        if uncertain:
            reasons.add("selection_uncertain")
        analysis_complete = selection["eligible_files"] == statuses["ok"]
        read_bytes = sum(r["source"]["selected_size"] for r in complete_rows)
        cov = {"files_attempted": len(self._files), "files_read_complete": len(complete_rows), "files_read_failed": failed,
               "files_unattempted": remaining, "files_scanned_complete": statuses["ok"],
               "files_scanned_partial": statuses["partial"], "files_scan_unsupported": statuses["unsupported"],
               "read_complete_bytes": read_bytes,
               "scanned_bytes": sum(r["scan"]["coverage"]["scanned_bytes"] for r in complete_rows),
               "framing_bytes": sum(r["scan"]["coverage"]["framing_bytes"] for r in complete_rows),
               "unscanned_read_bytes": sum(r["scan"]["coverage"]["unscanned_bytes"] for r in complete_rows),
               "eligible_files_unread": selection["eligible_files"] - len(complete_rows),
               "eligible_bytes_unread": selection["eligible_bytes"] - read_bytes,
               "analysis_complete": analysis_complete, "selection_uncertain": uncertain,
               "hits_are_lower_bound": not analysis_complete or not listing["complete"] or uncertain,
               "whole_card_examined": False, "reasons": [r for r in REASONS if r in reasons]}
        counts, digests = dict.fromkeys(KINDS, 0), set()
        for row in complete_rows:
            for hit in row["scan"]["matches"]:
                counts[hit["kind"]] += 1
                if hit["digest"] is not None:
                    digests.add(hit["digest"])
        result = ("no_supported_volume" if not self.plan._supported else "no_eligible_files" if not selection["eligible_files"]
                  else "secret_candidates" if self._hits else "no_candidates_in_examined_scope" if statuses["ok"]
                  else "no_text_examined")
        status = "unsupported" if not self.plan._supported else (
            "ok" if listing["complete"] and analysis_complete and not uncertain and stop_reason is None else "partial")
        report = {"schema": SCHEMA, "profile": PROFILE, "status": status,
                  "rules": {"pack": RULE_PACK, "pattern_ids": list(PATTERN_IDS)},
                  "limits": {**asdict(self.limits), "scanner_max_ranges": SCANNER_MAX_RANGES,
                             "scanner_max_output_bytes": SCANNER_MAX_OUTPUT_BYTES},
                  "listing": listing, "selection": selection, "coverage": cov, "files": copy.deepcopy(self._files),
                  "summary": {"hits": self._hits, "by_kind": counts, "unique_digest_count": len(digests), "result": result},
                  "limitations": list(LIMITATIONS)}
        # source/params의 고정 예약은 최종 공개 어댑터가 독립적으로 다시 확인한다.
        if len(_encoded(report)) + 2048 > self.limits.max_output_bytes:
            raise _error("secret_survey_limit")
        _cancel(self.cancel)
        self._finished = True
        return report
