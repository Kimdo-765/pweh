"""검증된 펌웨어·FAT/exFAT 목록 dict의 문자 경로 대조. 원문과 파일 I/O는 반환하지 않는다."""
from __future__ import annotations

import json
import math
import re
import time
import unicodedata
from dataclasses import dataclass, fields
from typing import Callable

from .errors import PwehError, ValidationFailed

SCHEMA = "pweh.sd-ioc-scan/v1"
MAX_OUTPUT_BYTES = 2 << 20
ACTIONS = ("exec", "exec?", "flash", "update-file", "trigger", "serve", "read-config", "write-log", "write", "record", "reference")
CHECKS = tuple(f"SD-{i:02}" for i in range(1, 10))
KINDS = ("exact_live_name", "case_variant_candidate", "deleted_name_candidate", "uncertain_name")
REASONS = ("unsupported_container", "unsupported_volume", "firmware_incomplete", "firmware_coverage_unknown",
           "listing_incomplete", "listing_coverage_unknown", "deleted_not_included", "volume_incomplete",
           "unmatchable_path", "path_too_long", "path_chars_limit", "unknown_mount", "relative_path_mismatch",
           "unknown_metadata", "nonascii_case_unexamined", "uncertain_name", "parent_unknown", "deleted_name",
           "parent_deleted", "chain_unchecked", "chain_incomplete", "ambiguous_path", "ascii_case_variant",
           "entry_limit", "ref_limit", "match_limit", "step_limit", "time_limit", "output_limit")
LIMITATIONS = ("name_candidates_only", "no_content_comparison", "no_execution_or_compromise_verification",
               "no_device_association_verification", "no_short_name_aliases", "no_unicode_casefold",
               "no_path_expansion", "deleted_history_not_complete", "firmware_artifact_index_not_protected_origin")
CARD_REF_PATTERN = r"(?:root|c[0-9]{1,10}(?:\+[0-9]{1,10})?|n[0-9]{1,10}\+[0-9]{1,10})/[0-9]{1,9}"
_REF = re.compile(CARD_REF_PATTERN + r"\Z")
_ASCII = str.maketrans("ABCDEFGHIJKLMNOPQRSTUVWXYZ", "abcdefghijklmnopqrstuvwxyz")
_FS = ("fat12", "fat16", "fat32", "exfat")


@dataclass(frozen=True)
class IocLimits:
    """상한은 낮출 수만 있다. 호출자가 출처 봉투 공간을 따로 남긴다."""

    max_entries: int = 200_000
    max_firmware_refs: int = 5000
    max_path_length: int = 32768
    max_path_chars: int = 8 << 20
    max_matches: int = 200
    max_steps: int = 1_000_000
    max_output_bytes: int = MAX_OUTPUT_BYTES


class _Limit(Exception):
    pass


def _invalid() -> ValidationFailed:
    return ValidationFailed("SD 경로 비교 입력의 구조가 올바르지 않습니다.")


def _int(value: object) -> bool:
    return type(value) is int and value >= 0


def _reason(report: dict, reason: str, count: int = 1) -> None:
    cov = report["coverage"]
    if reason not in cov["reasons"]:
        cov["reasons"].append(reason)
    cov["reason_counts"][reason] = cov["reason_counts"].get(reason, 0) + count


def _new() -> dict:
    cov = {f"{prefix}_{suffix}": 0 for prefix, suffixes in (
        ("entries", ("total", "processed", "indexed", "unmatchable", "remaining")),
        ("firmware_refs", ("total", "processed", "matchable", "unmatchable", "remaining"))) for suffix in suffixes}
    cov.update(unprocessed_entry_ranges=[], unprocessed_ref_ranges=[], reasons=[], reason_counts={},
               comparison_complete=False, whole_card_examined=False, deleted_scope_complete=False,
               ascii_only_case_variants=True, short_name_aliases_compared=False,
               uncertain_names=0, deleted_entries=0, parent_deleted_entries=0, chain_unchecked=0, chain_incomplete=0,
               cut_dirs=0, unvalidated_dirs=0)
    return {"schema": SCHEMA, "status": "ok", "association_basis": "caller-selected-same-case",
            "device_association_verified": False, "volume_mapping": "caller-selected-or-single-volume",
            "selected_partition": None, "coverage": cov, "matches": [],
            "summary": {"matches": 0, "by_kind": dict.fromkeys(KINDS, 0), "directory_references": 0,
                        "ambiguous_matches": 0, "result": "no_name_match_in_examined_scope"},
            "limitations": list(LIMITATIONS)}


def _finish(report: dict, limits: IocLimits) -> dict:
    cov = report["coverage"]
    def counts() -> None:
        for prefix, range_key in (("entries", "unprocessed_entry_ranges"), ("firmware_refs", "unprocessed_ref_ranges")):
            done, total = cov[prefix + "_processed"], cov[prefix + "_total"]
            cov[prefix + "_remaining"] = total - done
            cov[range_key] = [{"start": done, "count": total - done}] if total > done else []
        kinds = dict.fromkeys(KINDS, 0)
        for match in report["matches"]:
            kinds[match["match_kind"]] += 1
        report["summary"].update(matches=len(report["matches"]), by_kind=kinds,
                                 ambiguous_matches=sum(m["ambiguous"] for m in report["matches"]),
                                 result="name_match_candidates" if report["matches"] else "no_name_match_in_examined_scope")
        cov["comparison_complete"] = not cov["reasons"]
        if report["status"] != "unsupported":
            report["status"] = "ok" if cov["comparison_complete"] else "partial"
    counts()
    size = lambda: len(json.dumps(report, ensure_ascii=True, separators=(",", ":")).encode())
    if size() > limits.max_output_bytes:
        _reason(report, "output_limit")
        # 제거한 후보의 ref를 완료로 세지 않는다. 남은 후보는 하한이며 중복 완료 범위는 없다.
        cov["firmware_refs_processed"] = 0
        counts()
        while report["matches"] and size() > limits.max_output_bytes:
            report["matches"].pop()
            counts()
    if size() > limits.max_output_bytes:
        raise ValidationFailed("SD 경로 비교의 고정 결과 필드를 담을 공간이 부족합니다.")
    return report


def _partition(volume: dict) -> int:
    value = volume.get("partition")
    value = value.get("index") if isinstance(value, dict) else value
    if type(value) is not int or not 1 <= value <= 4096:
        raise _invalid()
    return value


def _select(listing: dict, partition: int | None, report: dict) -> dict | None:
    if "archive" in listing:
        report["status"] = "unsupported"
        _reason(report, "unsupported_container")
        return None
    volumes = listing.get("volumes")
    if not isinstance(volumes, list) or len(volumes) > 128:
        raise _invalid()
    ids, supported = set(), []
    selected = None
    for volume in volumes:
        if not isinstance(volume, dict):
            raise _invalid()
        index = _partition(volume)
        if index in ids:
            raise _invalid()
        ids.add(index)
        info, walk = volume.get("info"), volume.get("walk")
        good = isinstance(info, dict) and isinstance(walk, dict) and info.get("fs_type") in _FS and "error" not in volume
        if good:
            supported.append(volume)
        if index == partition:
            selected = volume if good else None
    if partition is not None:
        if partition not in ids:
            raise ValidationFailed("선택한 파티션이 검증된 목록에 없습니다.")
        report["selected_partition"] = partition
    elif len(supported) > 1:
        raise ValidationFailed("비교할 FAT/exFAT 파티션 번호를 명시해야 합니다.",
                               data={"partitions": [_partition(v) for v in supported]})
    elif supported:
        selected = supported[0]
        report["selected_partition"] = _partition(selected)
    if selected is None:
        report["status"] = "unsupported"
        _reason(report, "unsupported_volume")
    return selected


def _input_coverage(fw: dict, listing: dict, volume: dict, report: dict) -> None:
    refs = fw["sd_paths_referenced"]
    required = ("sd_paths_total", "sd_paths_truncated", "timed_out", "checks", "phases", "limitations", "stats")
    if any(key not in fw for key in required):
        _reason(report, "firmware_coverage_unknown")
    phases, checks, stats = fw.get("phases", {}), fw.get("checks", []), fw.get("stats", {})
    if not isinstance(phases, dict) or not isinstance(checks, list) or not isinstance(stats, dict):
        raise _invalid()
    total = fw.get("sd_paths_total", len(refs))
    if not _int(total) or total < len(refs):
        raise _invalid()
    if (total > len(refs) or fw.get("sd_paths_truncated") is not False or fw.get("timed_out") is not False
            or any(v != "complete" for v in phases.values()) or fw.get("limitations")
            or any(not isinstance(c, dict) or c.get("status") not in ("found", "not-found") for c in checks)
            or any(stats.get(k) for k in ("skipped_large", "overlong_files", "hits_dropped_files"))):
        _reason(report, "firmware_incomplete")
    params, call = listing.get("params"), listing.get("call")
    if not isinstance(params, dict) or not isinstance(call, dict):
        raise _invalid()
    if params.get("include_deleted") is not True:
        _reason(report, "deleted_not_included")
    skipped = call.get("partitions_skipped", {})
    if not isinstance(skipped, dict):
        raise _invalid()
    if (call.get("partitions_unexamined") or call.get("unsupported_partitions")
            or call.get("volumes_failed", {}).get("count", 0)
            or any(k != "duplicate" and isinstance(v, dict) and v.get("count", 0) for k, v in skipped.items())):
        _reason(report, "listing_incomplete")
    walk, info = volume["walk"], volume["info"]
    if any(k not in walk for k in ("truncated", "cut_dirs_total", "unvalidated_dirs_total")):
        _reason(report, "listing_coverage_unknown")
    for name in ("cut_dirs", "unvalidated_dirs"):
        total = walk.get(name + "_total", len(walk.get(name, [])))
        if not _int(total):
            raise _invalid()
        report["coverage"][name] = total
    if (walk.get("truncated") is not False or walk.get("truncated_reasons") or walk.get("truncated_reason")
            or report["coverage"]["cut_dirs"] or report["coverage"]["unvalidated_dirs"]
            or walk.get("warnings") or walk.get("warnings_suppressed")):
        _reason(report, "listing_incomplete")
    part = volume.get("partition", {})
    if (info.get("truncated") or info.get("warnings") or isinstance(part, dict) and (
            part.get("warnings") or _int(part.get("size_bytes")) and _int(info.get("volume_size"))
            and info["volume_size"] > part["size_bytes"])):
        _reason(report, "volume_incomplete")


def _name_uncertain(node: dict) -> bool:
    """부모와 파일에 같은 판정을 적용하여 배열의 순서에 의존하지 않는다."""
    entry, value = node["entry"], node["path"]
    return bool(entry["name_lossy"] or value and "\ufffd" in value
                or entry.get("lfn_status", "none") not in ("none", "ok", "recovered")
                or entry.get("name_status", "ok") != "ok" or entry.get("name_hash_ok") is False
                or entry.get("set_checksum_ok") is False or entry.get("set_complete") is False
                or entry.get("long_name_unverified")
                or isinstance(entry.get("first_char"), dict) and entry["first_char"].get("known") is False
                or value is not None and entry.get("name") != value.rsplit("/", 1)[-1])


def compare_sd_paths(firmware: dict, listing: dict, *, partition: int | None = None,
                     limits: IocLimits = IocLimits(), deadline: float,
                     cancel: Callable[[], bool] | None = None) -> dict:
    """권위 검증을 마친 dict를 비교한다. 출력·오류는 입력 문자열을 복사하지 않는다."""
    try:
        return _compare(firmware, listing, partition, limits, deadline, cancel)
    except PwehError:
        raise
    except Exception:
        raise ValidationFailed("SD 경로 비교 입력을 안전하게 처리하지 못했습니다.") from None


def _compare(fw: dict, listing: dict, partition: int | None, limits: IocLimits,
             deadline: float, cancel: Callable[[], bool] | None) -> dict:
    if not isinstance(limits, IocLimits):
        raise _invalid()
    defaults = IocLimits()
    for field in fields(limits):
        value = getattr(limits, field.name)
        if type(value) is not int or not (4096 if field.name == "max_output_bytes" else 1) <= value <= getattr(defaults, field.name):
            raise ValidationFailed("SD 경로 비교 한도가 허용 범위 밖입니다.")
    if type(deadline) not in (int, float) or not math.isfinite(deadline):
        raise _invalid()
    if partition is not None and (type(partition) is not int or not 1 <= partition <= 4096):
        raise _invalid()
    if not isinstance(fw, dict) or not isinstance(listing, dict):
        raise _invalid()
    if fw.get("schema") != "pweh.fwtriage.sd-surface/v1" or fw.get("tool") != "fw_sd_surface" or listing.get("schema") != "pweh.forensics.fs-list/v1":
        raise _invalid()
    refs, mounts = fw.get("sd_paths_referenced"), fw.get("mount_points")
    if not isinstance(refs, list) or not isinstance(mounts, list) or len(mounts) > 5000:
        raise _invalid()
    report = _new()
    cov = report["coverage"]
    cov["firmware_refs_total"] = len(refs)
    steps, path_chars = 0, 0
    deadline = min(deadline, time.monotonic() + 45)
    def tick() -> None:
        nonlocal steps
        try:
            cancelled = cancel is not None and cancel()
        except Exception:
            raise ValidationFailed("SD 경로 비교의 취소 상태를 확인하지 못했습니다.") from None
        if cancelled:
            raise PwehError("SD 경로 비교가 취소되었습니다.", code="cancelled")
        if time.monotonic() >= deadline:
            raise _Limit("time_limit")
        steps += 1
        if steps > limits.max_steps:
            raise _Limit("step_limit")
    def path(value: object, *, root: bool = False) -> str | None:
        nonlocal path_chars
        tick()
        if not isinstance(value, str):
            return None
        if len(value) > limits.max_path_length:
            _reason(report, "path_too_long")
            return None
        path_chars += len(value)
        if path_chars > limits.max_path_chars:
            raise _Limit("path_chars_limit")
        if value == "/" and root:
            return value
        if not value.startswith("/") or any(s in ("", ".", "..") for s in value[1:].split("/")):
            return None
        if any(c in value for c in ("$", "`", "\\", "*", "?", "[", "]", '"', "'", "<", ">", "…")):
            return None
        for index, char in enumerate(value):
            if index % 1024 == 0:
                tick()
            if unicodedata.category(char).startswith("C"):
                return None
        if not value.isascii():
            _reason(report, "nonascii_case_unexamined")
        return value
    try:
        tick()
        volume = _select(listing, partition, report)
        if volume is None:
            return _finish(report, limits)
        entries = volume["walk"].get("entries")
        if not isinstance(entries, list):
            raise _invalid()
        cov["entries_total"] = len(entries)
        _input_coverage(fw, listing, volume, report)
        mount_set = set()
        for mount in mounts:
            tick()
            if not isinstance(mount, dict):
                raise _invalid()
            value = path(mount.get("path"), root=True)
            if value is not None:
                mount_set.add(value)
            else:
                _reason(report, "unmatchable_path")
        nodes, index = {}, {}
        for position, entry in enumerate(entries):
            tick()
            if position >= limits.max_entries:
                _reason(report, "entry_limit")
                break
            if not isinstance(entry, dict):
                raise _invalid()
            ref = entry.get("ref")
            if not isinstance(ref, str) or _REF.fullmatch(ref) is None or ref in nodes:
                raise _invalid()
            for boolean in ("is_dir", "deleted", "parent_deleted", "name_lossy"):
                if type(entry.get(boolean)) is not bool:
                    raise _invalid()
            rawpath = path(entry.get("path"))
            node = {"entry": entry, "path": rawpath, "reasons": [], "ref": ref}
            nodes[ref] = node
            if rawpath is None:
                cov["entries_unmatchable"] += 1
                _reason(report, "unmatchable_path")
            else:
                index.setdefault(rawpath.translate(_ASCII), []).append(node)
                cov["entries_indexed"] += 1
            cov["entries_processed"] += 1
        # 각 부모 연결은 최대 64개만 따라간다. 순환·누락·불일치를 이름 불확실성으로 분리한다.
        for node in nodes.values():
            tick()
            entry, ownpath, reasons = node["entry"], node["path"], node["reasons"]
            if _name_uncertain(node):
                reasons.append("uncertain_name")
            if entry["deleted"]:
                reasons.append("deleted_name")
                cov["deleted_entries"] += 1
            parent_deleted = entry["parent_deleted"]
            current, seen = node, set()
            for _ in range(65):
                tick()
                p = current["entry"].get("parent_ref")
                currentpath = current["path"]
                if p is None:
                    if currentpath is None or currentpath.count("/") != 1:
                        reasons.append("parent_unknown")
                    break
                if not isinstance(p, str) or p in seen or p not in nodes:
                    reasons.append("parent_unknown")
                    break
                seen.add(p)
                parent = nodes[p]
                if (not parent["entry"]["is_dir"] or parent["path"] is None or currentpath is None
                        or currentpath.rsplit("/", 1)[0] != parent["path"]):
                    reasons.append("parent_unknown")
                    break
                if _name_uncertain(parent):
                    reasons.append("uncertain_name")
                parent_deleted |= parent["entry"]["deleted"] or parent["entry"]["parent_deleted"]
                current = parent
            else:
                reasons.append("parent_unknown")
            if parent_deleted:
                reasons.append("parent_deleted")
                cov["parent_deleted_entries"] += 1
            if "uncertain_name" in reasons or "parent_unknown" in reasons:
                cov["uncertain_names"] += 1
            if not entry["is_dir"] and not entry["deleted"]:
                chain = entry.get("chain")
                if not isinstance(chain, dict):
                    reasons.append("chain_unchecked")
                    cov["chain_unchecked"] += 1
                elif chain.get("status") not in ("eoc", "nofatchain", "empty") or chain.get("size_check") != "ok":
                    reasons.append("chain_incomplete")
                    cov["chain_incomplete"] += 1
            node["reasons"] = list(dict.fromkeys(reasons))
            for reason in node["reasons"]:
                _reason(report, reason)
        for position, item in enumerate(refs):
            tick()
            if position >= limits.max_firmware_refs:
                raise _Limit("ref_limit")
            if not isinstance(item, dict):
                raise _invalid()
            full, mount, relative = path(item.get("path")), item.get("mount_point"), item.get("card_relative")
            reason = None
            if full is None or not isinstance(mount, str) or not isinstance(relative, str) or not relative:
                reason = "unmatchable_path"
            elif mount not in mount_set:
                reason = "unknown_mount"
            elif not full.startswith(mount.rstrip("/") + "/") or full[len(mount.rstrip("/")) + 1:] != relative:
                reason = "relative_path_mismatch"
            if reason:
                cov["firmware_refs_unmatchable"] += 1
                _reason(report, reason)
                cov["firmware_refs_processed"] += 1
                continue
            key = "/" + relative
            actions, checks = item.get("actions", []), item.get("checks", [])
            if not isinstance(actions, list) or not isinstance(checks, list):
                raise _invalid()
            if any(a not in ACTIONS for a in actions) or any(c not in CHECKS for c in checks):
                _reason(report, "unknown_metadata")
            actions = [a for a in ACTIONS if a in actions]
            checks = [c for c in CHECKS if c in checks]
            cov["firmware_refs_matchable"] += 1
            candidates = index.get(key.translate(_ASCII), [])
            ambiguous = len(candidates) > 1
            for node in candidates:
                tick()
                if node["entry"]["is_dir"]:
                    report["summary"]["directory_references"] += 1
                    continue
                if len(report["matches"]) >= limits.max_matches:
                    raise _Limit("match_limit")
                reasons = list(node["reasons"])
                exact = node["path"] == key
                if not exact:
                    reasons.append("ascii_case_variant")
                    _reason(report, "ascii_case_variant")
                if ambiguous:
                    reasons.append("ambiguous_path")
                    _reason(report, "ambiguous_path")
                kind = ("uncertain_name" if "uncertain_name" in reasons or "parent_unknown" in reasons else
                        "deleted_name_candidate" if "deleted_name" in reasons or "parent_deleted" in reasons else
                        "exact_live_name" if exact else "case_variant_candidate")
                report["matches"].append({"firmware_index": position, "card_ref": node["ref"],
                    "partition": report["selected_partition"], "match_kind": kind,
                    "comparison": "literal-exact" if exact else "ascii-case-variant",
                    "actions": actions, "checks": checks, "ambiguous": ambiguous,
                    "reasons": list(dict.fromkeys(reasons)), "confidence": "possible"})
            cov["firmware_refs_processed"] += 1
        tick()
    except _Limit as exc:
        _reason(report, str(exc))
    return _finish(report, limits)
