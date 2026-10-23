"""후보 보고서의 닫힌 출처로 완전한 선택 bytes를 다시 읽는다. 새 탐색은 없다."""

from __future__ import annotations

import hashlib
import math
import os
import re
import stat
import time
from collections.abc import Callable

from pweh import evidence as E
from pweh.media_candidate_input import MAX_SELECTED_BYTES, check_budget, input_error

from . import fsops
from .media_tools import _source

_METHODS = {"chain", "nofatchain", "contiguous", "skip-allocated", "skip-claimed", "fat-chain", "stale-chain"}
_IDENTITY = ("kind", "evidence_id", "evidence_sha256", "container", "member_selected", "selected_sha256",
             "selected_size", "complete", "method", "partition", "ref", "deleted")
MAX_RANGE_END = (1 << 63) - 1
RANGE_CHUNK_BYTES = 64 << 10
RANGE_PROFILE = "ftyp-contiguous-ev-range-v1"
RANGE_LIMITATIONS = ("explicit_evidence_range_only", "outside_range_unexamined")
_RANGE_KEYS = frozenset((*_IDENTITY, "confidence", "parent_deleted", "container_truncated",
                        "container_truncated_reasons", "evidence_size", "offset"))
_SHA = re.compile(r"[0-9a-f]{64}\Z")


def _range_tick(deadline: float, cancel: Callable[[], bool], *, time_limit: bool = True) -> None:
    """마감을 새로 만들지 않고 취소 callback의 원문·비bool 반환을 닫는다."""
    try:
        if type(deadline) not in (int, float) or not math.isfinite(deadline) or type(time_limit) is not bool:
            raise ValueError
        stopped = cancel()
        if type(stopped) is not bool:
            raise ValueError
    except Exception:
        raise input_error() from None
    if stopped:
        raise input_error("cancelled")
    if time_limit and time.monotonic() >= deadline:
        raise input_error("timeout")


def _range_identity(st: os.stat_result) -> tuple[int, ...]:
    return st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns, st.st_ctime_ns, st.st_mode, st.st_nlink


def _range_state(opened: E.OpenedEvidence, offset: int, length: int) -> int:
    """구간 산술과 초기 열린 fd의 전체 seal을 대조한다. 경로·fd 소유권은 호출자에게 있다."""
    if (type(offset) is not int or type(length) is not int or offset < 0 or length < 1
            or offset > MAX_RANGE_END or length > MAX_RANGE_END - offset):
        raise input_error()
    if length > MAX_SELECTED_BYTES:
        raise input_error("media_prefix_input_limit")
    size = opened.intake["size"]
    if type(size) is not int or not 1 <= size <= MAX_RANGE_END or offset + length > size:
        raise input_error()
    before, now = opened.st, os.fstat(opened.fd)
    if (not stat.S_ISREG(before.st_mode) or not stat.S_ISREG(now.st_mode)
            or before.st_nlink != 1 or now.st_nlink != 1 or before.st_size != size
            or _range_identity(now) != _range_identity(before)):
        raise E.IntegrityProblem("구간을 읽는 동안 증거의 파일 신원 또는 상태가 변경되었습니다.",
                                 reason="source-changed")
    return size


def check_candidate_range(opened: E.OpenedEvidence, source: dict, *, deadline: float,
                          cancel: Callable[[], bool], time_limit: bool = True) -> None:
    """요청 구간과 같은 fd seal만 재확인한다. 구간 재해시·경로 재열기·close는 하지 않는다."""
    try:
        _range_tick(deadline, cancel, time_limit=time_limit)
        if (type(source) is not dict or set(source) != _RANGE_KEYS
                or source["kind"] != "evidence" or source["container"] != "file"
                or source["method"] != "byte-range" or source["confidence"] != "high"
                or source["member_selected"] is not False or source["complete"] is not True
                or any(source[k] is not None for k in ("partition", "ref", "deleted", "parent_deleted", "container_truncated"))
                or type(source["container_truncated_reasons"]) is not list or source["container_truncated_reasons"]
                or source["evidence_id"] != opened.evidence_id
                or type(source["evidence_id"]) is not str or re.fullmatch(r"EV-[0-9]{4,6}", source["evidence_id"]) is None
                or any(type(source[k]) is not str or _SHA.fullmatch(source[k]) is None
                       for k in ("evidence_sha256", "selected_sha256"))
                or source["evidence_sha256"] != opened.intake["hashes"]["sha256"]
                or type(source["evidence_size"]) is not int):
            raise input_error()
        size = _range_state(opened, source["offset"], source["selected_size"])
        if source["evidence_size"] != size:
            raise input_error("media_prefix_input_changed")
        _range_tick(deadline, cancel, time_limit=time_limit)
    except E.IntegrityProblem:
        raise
    except Exception as exc:
        code = getattr(exc, "code", None)
        raise input_error(code if type(code) is str else "media_prefix_input_invalid") from None


def read_candidate_range(opened: E.OpenedEvidence, offset: int, length: int, *, deadline: float,
                         cancel: Callable[[], bool]) -> tuple[bytes, dict]:
    """명시 EV 구간을 최대64KiB pread로 완전히 읽어 새 출처와 반환한다. 짧은 읽기는 거부한다."""
    try:
        _range_tick(deadline, cancel)
        size = _range_state(opened, offset, length)
        chunks, digest = [], hashlib.sha256()
        position = 0
        while position < length:
            _range_tick(deadline, cancel)
            need = min(RANGE_CHUNK_BYTES, length - position)
            chunk = os.pread(opened.fd, need, offset + position)
            if type(chunk) is not bytes or len(chunk) != need:
                raise input_error("media_prefix_input_changed")
            _range_tick(deadline, cancel)
            digest.update(chunk)
            chunks.append(chunk)
            position += len(chunk)
        data = b"".join(chunks)
        source = {"kind": "evidence", "evidence_id": opened.evidence_id,
                  "evidence_sha256": opened.intake["hashes"]["sha256"], "container": "file",
                  "member_selected": False, "selected_sha256": digest.hexdigest(), "selected_size": len(data),
                  "complete": True, "method": "byte-range", "confidence": "high", "partition": None,
                  "ref": None, "deleted": None, "parent_deleted": None, "container_truncated": None,
                  "container_truncated_reasons": [], "evidence_size": size, "offset": offset}
        check_candidate_range(opened, source, deadline=deadline, cancel=cancel)
        return data, source
    except E.IntegrityProblem:
        raise
    except Exception as exc:
        code = getattr(exc, "code", None)
        raise input_error(code if type(code) is str else "media_prefix_input_invalid") from None


def reselect_candidate_source(opened, candidate_input, *, deadline, cancel, min_selected_bytes=16):
    """같은 EV의 source.ref/partition/실제 method를 재사용하고 전체 SHA·크기를 대조한다."""
    try:
        check_budget(deadline, cancel)
        if type(min_selected_bytes) is not int or not 1 <= min_selected_bytes <= MAX_SELECTED_BYTES:
            raise input_error()
        source = candidate_input.source
        if (type(source) is not dict or source["evidence_id"] != opened.evidence_id
                or source["evidence_sha256"] != opened.intake["hashes"]["sha256"]
                or type(source["selected_size"]) is not int
                or not min_selected_bytes <= source["selected_size"] <= MAX_SELECTED_BYTES or source["complete"] is not True):
            raise input_error()
        kind = source["container"]
        if source["method"] == "byte-range":
            check_candidate_range(opened, source, deadline=deadline, cancel=cancel)
            data, fresh = read_candidate_range(opened, source["offset"], source["selected_size"],
                                                deadline=deadline, cancel=cancel)
            if fresh != source:
                raise input_error("media_prefix_input_changed")
            return data, fresh
        if kind == "file":
            if source["member_selected"] is not False or source["method"] != "whole-file":
                raise input_error()
            partition, ref, method = None, None, "auto"
        elif kind in {"tar", "zip"}:
            if source["member_selected"] is not True or source["method"] != "archive-member":
                raise input_error()
            partition, ref, method = None, source["ref"], "auto"
        elif kind == "filesystem" and source["method"] in _METHODS and source["member_selected"] is True:
            partition, ref, method = source["partition"], source["ref"], source["method"]
        else:
            raise input_error()
        data, member = fsops.read_selected_file(
            opened.fd, partition=partition, ref=ref, path=None, method=method,
            max_bytes=MAX_SELECTED_BYTES, deadline=deadline, cancel=cancel, allow_empty=False)
        check_budget(deadline, cancel)
        if type(data) is not bytes:
            raise input_error()
        fresh = _source(opened, opened.evidence_id, member, data)
        if any(fresh[k] != source[k] for k in _IDENTITY):
            raise input_error("media_prefix_input_changed")
        if (type(source["parent_deleted"]) is bool and type(fresh["parent_deleted"]) is bool
                and source["parent_deleted"] != fresh["parent_deleted"]):
            raise input_error("media_prefix_input_changed")
        check_budget(deadline, cancel)
        return data, fresh
    except E.IntegrityProblem:
        raise
    except Exception as exc:
        code, reason = getattr(exc, "code", None), getattr(exc, "reason", None)
        if reason == "budget_exceeded" and type(getattr(exc, "data", None)) is dict:
            reason = exc.data.get("limit")
        if reason == "cancelled":
            code = "cancelled"
        elif reason in {"time", "timeout", "time_limit"}:
            code = "timeout"
        elif reason == "max_bytes":
            code = "media_prefix_input_limit"
        raise input_error(code) from None
