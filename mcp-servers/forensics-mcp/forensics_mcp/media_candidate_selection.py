"""후보 보고서의 닫힌 출처로 완전한 선택 bytes를 다시 읽는다. 새 탐색은 없다."""

from __future__ import annotations

from pweh import evidence as E
from pweh.media_candidate_input import MAX_SELECTED_BYTES, check_budget, input_error

from . import fsops
from .media_tools import _source

_METHODS = {"chain", "nofatchain", "contiguous", "skip-allocated", "skip-claimed", "fat-chain", "stale-chain"}
_IDENTITY = ("kind", "evidence_id", "evidence_sha256", "container", "member_selected", "selected_sha256",
             "selected_size", "complete", "method", "partition", "ref", "deleted")


def reselect_candidate_source(opened, candidate_input, *, deadline, cancel):
    """같은 EV의 source.ref/partition/실제 method를 재사용하고 전체 SHA·크기를 대조한다."""
    try:
        check_budget(deadline, cancel)
        source = candidate_input.source
        if (type(source) is not dict or source["evidence_id"] != opened.evidence_id
                or source["evidence_sha256"] != opened.intake["hashes"]["sha256"]
                or type(source["selected_size"]) is not int
                or not 16 <= source["selected_size"] <= MAX_SELECTED_BYTES or source["complete"] is not True):
            raise input_error()
        kind = source["container"]
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
