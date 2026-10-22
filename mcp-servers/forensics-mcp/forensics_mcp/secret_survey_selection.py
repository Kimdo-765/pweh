"""저장 목록의 항목을 같은 EV에서 다시 확인하고 완전한 data 영역만 읽는다.

목록 이름은 메모리 안의 신원 대조에만 사용한다. 원래 EV fd는 호출자가 소유하며,
ImageReader가 같은 open file의 dup를 문맥 안에서 소유·정리한다.
"""
from __future__ import annotations

import dataclasses
import hashlib
import os
import stat
import time
from typing import Any, Callable

from pweh import evidence as E
from pweh.errors import PwehError
from pweh.fs.common import FsError, Limits
from . import fsops

MAX_FILE_BYTES = 4 << 20
_READ_REASONS = frozenset({"refs_unverifiable", "metadata_unverifiable", "incomplete_file", "read_failed", "time_limit"})
_COMPARE_FIELDS = ("ref", "fs", "dir", "slot", "is_dir", "deleted", "size", "first_cluster",
                   "name", "display_name", "name_lossy", "name_source", "short_name", "short_name_raw",
                   "long_name", "lfn_status", "valid_data_length", "no_fat_chain", "name_status",
                   "name_hash_ok", "set_checksum_ok", "set_complete")


class SurveyReadError(PwehError):
    """내용 읽기의 알려진 미완료만 항목별 미검사로 바꾼다."""
    def __init__(self, reason: str):
        if reason not in _READ_REASONS:
            raise ValueError("허용하지 않는 읽기 상태입니다.")
        super().__init__("선택 항목의 완전한 내용을 읽지 못했습니다.", code="secret_survey_read_failed")
        self.reason = reason


def _changed() -> PwehError:
    return PwehError("저장 목록과 현재 선택 항목의 신원이 일치하지 않습니다.", code="secret_survey_input_changed")


def _tick(deadline: float, cancel: Callable[[], bool]) -> None:
    try:
        stopped = cancel()
        if type(stopped) is not bool:
            raise ValueError
    except Exception:
        raise PwehError("취소 상태를 확인하지 못했습니다.", code="secret_survey_callback_failed") from None
    if stopped:
        raise PwehError("목록 검사가 취소되었습니다.", code="cancelled")
    if time.monotonic() >= deadline:
        raise SurveyReadError("time_limit")


def check_opened(opened: E.OpenedEvidence) -> None:
    """처음 열린 EV fd의 seal을 비교한다. 전체 EV 재해시를 뜻하지 않는다."""
    try:
        now, before = os.fstat(opened.fd), opened.st
        keys = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns", "st_mode", "st_nlink")
        if (not stat.S_ISREG(now.st_mode) or now.st_nlink != 1
                or type(opened.intake["size"]) is not int or now.st_size != opened.intake["size"]
                or any(getattr(now, k) != getattr(before, k) for k in keys)):
            raise ValueError
    except Exception:
        raise E.IntegrityProblem("증거의 열린 파일 신원 또는 상태가 바뀌었습니다.", reason="source-changed") from None


def _stored(listing: dict, target: Any) -> tuple[dict, dict]:
    try:
        if type(target.volume_index) is not int or type(target.entry_index) is not int or min(target.volume_index, target.entry_index) < 0:
            raise ValueError
        volume = listing["volumes"][target.volume_index]
        entry = volume["walk"]["entries"][target.entry_index]
        if (volume["partition"]["index"] != target.partition or entry["ref"] != target.ref
                or entry["fs"] != target.fs or entry["is_dir"] is not False
                or entry["size"] != target.declared_size or entry["deleted"] is not target.deleted
                or entry.get("parent_deleted") is not target.parent_deleted
                or entry.get("name_lossy", False) is not target.name_lossy):
            raise ValueError
        expected = entry["valid_data_length"] if target.fs == "exfat" else entry["size"]
        if (type(expected) is not int or type(entry["size"]) is not int
                or not 0 < expected <= entry["size"] < 1 << 64 or expected != target.expected_size
                or expected > MAX_FILE_BYTES):
            raise ValueError
        return volume["partition"], entry
    except Exception:
        raise _changed() from None


def _compare(partition: dict, entry: dict, stored_part: dict, stored: dict, target: Any) -> None:
    # 목록의 시각·경로·체인 요약은 fresh entry의 원시 항목과 혼합하지 않는다.
    for key in ("index", "start_offset", "size_bytes"):
        if key not in stored_part or type(stored_part[key]) is not int or partition.get(key) != stored_part[key]:
            raise _changed()
    for key in _COMPARE_FIELDS:
        if key in stored and (key not in entry or type(entry[key]) is not type(stored[key]) or entry[key] != stored[key]):
            raise _changed()
    if "attributes" in stored and entry.get("attributes", {}).get("raw") != stored["attributes"].get("raw"):
        raise _changed()
    parent = entry.get("parent_deleted")
    if type(parent) is not bool:
        raise SurveyReadError("metadata_unverifiable")
    if type(target.parent_deleted) is bool and parent is not target.parent_deleted:
        raise _changed()
    if (entry.get("fs") != target.fs or entry.get("ref") != target.ref or entry.get("is_dir") is not False
            or entry.get("deleted") is not target.deleted or entry.get("name_lossy", False) is not target.name_lossy):
        raise _changed()
    expected = entry.get("valid_data_length") if target.fs == "exfat" else entry.get("size")
    if (type(expected) is not int or type(entry.get("size")) is not int
            or not 0 < expected <= entry["size"] < 1 << 64
            or entry["size"] != target.declared_size or expected != target.expected_size):
        raise _changed()


def _fs_failure(exc: FsError) -> PwehError:
    reason = exc.reason
    details = getattr(exc, "data", {}) or {}
    limit = details.get("limit") or details.get("truncated_reason")
    if reason == "cancelled" or limit == "cancelled":
        return PwehError("목록 검사가 취소되었습니다.", code="cancelled")
    if reason == "time" or limit == "time":
        return SurveyReadError("time_limit")
    if reason in {"bad_ref", "not_found", "bad_argument"}:
        return _changed()
    if reason == "refs_unverifiable":
        return SurveyReadError("refs_unverifiable")
    if reason in {"incomplete_file", "beyond_image"}:
        return SurveyReadError("incomplete_file")
    return SurveyReadError("read_failed")


def read_survey_target(opened: E.OpenedEvidence, target: Any, *, listing: dict,
                       deadline: float, cancel: Callable[[], bool]) -> tuple[bytes, dict]:
    """검증된 도달성→항목 신원→단일 복구 계획→읽기 순서로 최대4MiB를 반환한다."""
    _tick(deadline, cancel)
    check_opened(opened)
    stored_part, stored = _stored(listing, target)
    try:
        limits = dataclasses.replace(Limits(), max_seconds=max(0.001, deadline - time.monotonic()),
                                     max_read_bytes=MAX_FILE_BYTES)
        with fsops.image_reader(opened.fd) as img:
            partition, vol = fsops.open_partition_volume(
                img, target.partition, limits=limits,
                budget=fsops.engine_budget(None, limits, deadline=deadline, cancel=cancel))
            tick = lambda: _tick(deadline, cancel)
            tick()
            entries, unresolved = fsops.resolve_targets(
                vol, [target.ref], [], limits=limits, deadline=deadline,
                check=tick, cancel=cancel, include_parent_deleted=True)
            if unresolved or len(entries) != 1:
                reason = unresolved[0].get("code") if unresolved else "not_found"
                raise FsError("선택 항목을 확인하지 못했습니다.", reason=reason)
            entry = entries[0]
            _compare(partition, entry, stored_part, stored, target)
            tick()
            plan = vol.content_plan(target.ref, "auto", "data", limits=limits,
                                    budget=fsops.engine_budget(vol, limits, deadline=deadline, cancel=cancel))
            pd = plan.to_dict(max_runs=0)
            tick()
            if (pd.get("complete") is not True or pd.get("limit_reason") or pd.get("status") == "limit"
                    or pd.get("bytes_beyond_image")):
                raise SurveyReadError("incomplete_file")
            if type(plan.size) is not int or plan.size != target.expected_size:
                raise _changed()
            chunks, size, sha = [], 0, hashlib.sha256()
            for chunk in vol.iter_plan(plan, max_bytes=MAX_FILE_BYTES):
                tick()
                if type(chunk) is not bytes or size + len(chunk) > target.expected_size:
                    raise _changed()
                size += len(chunk)
                sha.update(chunk)
                chunks.append(chunk)
            if size != target.expected_size:
                raise SurveyReadError("incomplete_file")
            tick()
            check_opened(opened)
            source = {"partition": partition["index"], "ref": entry["ref"], "fs": entry["fs"],
                      "declared_size": target.declared_size, "expected_size": target.expected_size,
                      "selected_size": size, "selected_sha256": sha.hexdigest(), "complete": True,
                      "method": pd.get("method"), "confidence": pd.get("confidence"),
                      "deleted": entry["deleted"], "parent_deleted": entry["parent_deleted"],
                      "name_lossy": entry.get("name_lossy", False),
                      "residual_unexamined": target.declared_size > target.expected_size}
            return b"".join(chunks), source
    except FsError as exc:
        check_opened(opened)
        raise _fs_failure(exc) from None
    except OSError:
        check_opened(opened)
        raise SurveyReadError("read_failed") from None
    finally:
        # 미완료 읽기도 증거 신원 변경을 단순 항목 실패로 숨기지 않는다.
        check_opened(opened)
