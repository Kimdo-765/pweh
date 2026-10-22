"""저장 FAT/exFAT 목록을 같은 EV의 list 사건과 열린 fd에 결속한다.

파일 내용은 읽지 않는다. 목록의 이름은 내부 선정·재선택에만 쓰며 공개 출처에는
생성 보고서 식별자와 해시만 남긴다. 최종 전체 해시는 custody 잠금 안에서 한 번 한다.
"""

from __future__ import annotations

import contextlib
import hashlib
import math
import os
import re
import stat
import time
from collections.abc import Callable, Iterator
from dataclasses import asdict, dataclass

from . import evidence as E, safeio
from .case import Case
from .errors import PwehError, ValidationFailed
from .sdioc_input import load_json

MAX_REPORT_BYTES = 16 << 20
_CHUNK = 64 << 10
_UINT64 = (1 << 64) - 1
_SHA = re.compile(r"[0-9a-f]{64}\Z")
_SPEC = r"(?:root|c[0-9]{1,20}(?:\+[0-9]{1,20})?|n[0-9]{1,20}\+[0-9]{1,20})"
_REF = re.compile(_SPEC + r"/[0-9]{1,9}\Z")
_FS = frozenset({"fat12", "fat16", "fat32", "exfat"})
_REASONS = frozenset({
    "unknown", "time", "steps", "cancelled", "entries", "partitions", "path_chars", "duplicate",
    "unsupported_partitions", "max_entries", "max_partitions", "max_path_chars", "max_total_slots",
    "max_depth", "max_dir_slots", "beyond_image", "dir_chain_broken", "dir_unreadable", "dir_unvalidated",
    "image_truncated", "volume_exceeds_partition", "partition_beyond_image", "partition_truncated",
    "ebr_beyond_image", "budget_exceeded", "unsupported_fs", "not_fat", "not_exfat", "malformed",
    "open_failed", "out_of_bounds", "short_read", "io_error", "internal_error", "too_large",
    "not_found", "bad_argument", "bad_ref", "refs_unverifiable", "validation_failed",
})
_MESSAGES = {
    "secret_survey_input_invalid": "저장 목록의 형식·출처 또는 선택 메타데이터가 유효하지 않습니다.",
    "secret_survey_input_limit": "저장 목록의 크기·구조 상한을 넘었습니다.",
    "secret_survey_input_changed": "저장 목록 또는 보관 사건의 신원이 변경되었습니다.",
    "cancelled": "저장 목록 검증이 취소되었습니다.",
    "timeout": "저장 목록 검증 시간 상한에 도달했습니다.",
}


def input_error(code: str = "secret_survey_input_invalid") -> PwehError:
    """원문·경로·callback 오류를 포함하지 않는 고정 오류다."""
    if code not in _MESSAGES:
        code = "secret_survey_input_invalid"
    hint = ("forensics_fs_list에서 partition 또는 max_entries를 줄여 전체 목록을 다시 만드세요. "
            "잘린 목록의 coverage는 그대로 유지됩니다.") if code == "secret_survey_input_limit" else None
    return ValidationFailed(_MESSAGES[code], code=code, hint=hint)


def _tick(deadline: float, cancel: Callable[[], bool], *, timed: bool = True) -> None:
    try:
        valid = type(deadline) in (int, float) and math.isfinite(deadline)
        stopped = cancel() if valid else None
    except Exception:
        raise input_error() from None
    if not valid or type(stopped) is not bool:
        raise input_error()
    if stopped:
        raise input_error("cancelled")
    if timed and time.monotonic() >= deadline:
        raise input_error("timeout")


def _uint(value, maximum=_UINT64, minimum=0):
    if type(value) is not int or not minimum <= value <= maximum:
        raise input_error()
    return value


def _dict(value):
    if type(value) is not dict:
        raise input_error()
    return value


def _list(value):
    if type(value) is not list:
        raise input_error()
    return value


def _bool(value, *, nullable=False):
    if nullable and value is None:
        return None
    if type(value) is not bool:
        raise input_error()
    return value


def _text(value, *, nullable=False):
    if nullable and value is None:
        return None
    if type(value) is not str:
        raise input_error()
    return value


def _reason(value):
    return value if _text(value) in _REASONS else "unknown"


def _warnings(value):
    # 경고의 자유 문장·경로·이름은 버리고 존재와 개수만 보존한다.
    return [{"code": _reason(_dict(item).get("code", "unknown"))} for item in _list(value)]


def _coverage(raw):
    raw = _dict(raw)
    out = {}
    for key in ("truncated",):
        if key in raw:
            out[key] = _bool(raw[key])
    for key in ("volume_size", "cut_dirs_total", "unvalidated_dirs_total", "unvalidated_dirs_live",
                "warnings_suppressed", "path_chars"):
        if key in raw:
            out[key] = _uint(raw[key])
    if "truncated_reason" in raw:
        out["truncated_reason"] = None if raw["truncated_reason"] is None else _reason(raw["truncated_reason"])
    if "truncated_reasons" in raw:
        out["truncated_reasons"] = [_reason(r) for r in _list(raw["truncated_reasons"])]
    if "warnings" in raw:
        out["warnings"] = _warnings(raw["warnings"])
    for key in ("cut_dirs", "unvalidated_dirs"):
        if key in raw:
            out[key] = [{"reason": _reason(_dict(item).get("reason", "unknown"))} for item in _list(raw[key])]
    return out


def _partition(raw):
    raw = _dict(raw)
    out = {"index": _uint(raw.get("index"), 4096, 1)}
    for key in ("start_offset", "size_bytes"):
        if key in raw:
            out[key] = _uint(raw[key])
    if "fs_hint" in raw:
        hint = _text(raw["fs_hint"], nullable=True)
        out["fs_hint"] = hint if hint in _FS or hint == "exfat-invalid" else "unknown"
    if "warnings" in raw:
        out["warnings"] = _warnings(raw["warnings"])
    return out


def _entry(raw, fs):
    raw = _dict(raw)
    ref = raw.get("ref")
    if type(ref) is not str or len(ref) > 51 or not _REF.fullmatch(ref) or raw.get("fs") != fs:
        raise input_error()
    out = {"ref": ref, "fs": fs, "size": _uint(raw.get("size")), "name": _text(raw.get("name")),
           "first_cluster": _uint(raw.get("first_cluster")),
           "parent_deleted": _bool(raw.get("parent_deleted"), nullable=True)}
    for key in ("is_dir", "deleted", "name_lossy"):
        out[key] = _bool(raw.get(key))
    for key in ("dir", "slot"):
        if key in raw:
            value = _text(raw[key]) if key == "dir" else _uint(raw[key], 999999999)
            expected = ref.rsplit("/", 1)[0] if key == "dir" else int(ref.rsplit("/", 1)[1])
            if value != expected:
                raise input_error()
            out[key] = value
    if "parent_ref" in raw:
        parent = _text(raw["parent_ref"], nullable=True)
        if parent is not None and (len(parent) > 51 or not _REF.fullmatch(parent)):
            raise input_error()
        out["parent_ref"] = parent
    for key in ("display_name", "path", "name_source", "short_name", "short_name_raw",
                "long_name", "lfn_status", "name_status"):
        if key in raw:
            out[key] = _text(raw[key], nullable=key in {"long_name", "lfn_status", "name_status"})
    if "attributes" in raw:
        out["attributes"] = {"raw": _uint(_dict(raw["attributes"]).get("raw"), 65535)}
    if "warnings" in raw:
        out["warnings"] = _warnings(raw["warnings"])
    if fs == "exfat":
        out["valid_data_length"] = _uint(raw.get("valid_data_length"), out["size"])
        for key in ("no_fat_chain", "name_hash_ok", "set_checksum_ok", "set_complete"):
            if key in raw:
                out[key] = _bool(raw[key], nullable=key in {"name_hash_ok", "set_checksum_ok"})
    return out


def _call(raw):
    raw = _dict(raw)
    out = {}
    for key in ("max_entries", "entries_used", "max_partitions", "max_path_chars", "path_chars_used", "partitions_walked"):
        if key in raw:
            out[key] = _uint(raw[key])
    if "partitions_unexamined" in raw:
        out["partitions_unexamined"] = []
        for item in _list(raw["partitions_unexamined"]):
            part = _partition(item)
            part["reason"] = _reason(item.get("reason", "unknown"))
            out["partitions_unexamined"].append(part)
    if "partitions_skipped" in raw:
        skipped = {}
        for key, item in _dict(raw["partitions_skipped"]).items():
            reason, item = _reason(key), _dict(item)
            count = _uint(item.get("count"), 4096)
            examples = [_uint(p, 4096, 1) for p in _list(item.get("examples", []))]
            if len(examples) > min(count, 20):
                raise input_error()
            target = skipped.setdefault(reason, {"count": 0, "examples": []})
            target["count"] += count
            _uint(target["count"], 4096)
            target["examples"] = (target["examples"] + examples)[:20]
        out["partitions_skipped"] = skipped
    if "volumes_failed" in raw:
        failed = _dict(raw["volumes_failed"])
        count = _uint(failed.get("count"), 4096)
        examples = [{"partition": _uint(_dict(e).get("partition"), 4096, 1),
                     "reason": _reason(e.get("reason", "unknown"))} for e in _list(failed.get("examples", []))]
        if len(examples) > min(count, 20):
            raise input_error()
        out["volumes_failed"] = {"count": count, "examples": examples}
    return out


def _project(report, ev, intake_sha, check):
    """producer의 성공/실패 볼륨을 구분하고 내부 전용 선정 메타데이터만 남긴다."""
    report = _dict(report)
    if (report.get("schema") != "pweh.forensics.fs-list/v1" or report.get("evidence_id") != ev
            or "archive" in report or report.get("evidence_sha256", intake_sha) != intake_sha):
        raise input_error()
    params, volumes = _dict(report.get("params")), _list(report.get("volumes"))
    if len(volumes) > 4096:
        raise input_error("secret_survey_input_limit")
    out = {"schema": report["schema"], "evidence_id": ev, "params": {}, "call": _call(report.get("call")), "volumes": []}
    if "partition" in params:
        out["params"]["partition"] = None if params["partition"] is None else _uint(params["partition"], 4096, 1)
    if "include_deleted" in params:
        out["params"]["include_deleted"] = _bool(params["include_deleted"])
    seen_parts = set()
    total_entries = 0
    for volume in volumes:
        check()
        volume = _dict(volume)
        if "error" in volume:
            index = _uint(volume.get("partition"), 4096, 1)
            part = _partition(volume.get("partition_info"))
            if part["index"] != index:
                raise input_error()
            error = _dict(volume["error"])
            data = _dict(error.get("data", {}))
            projected = {"partition": index, "partition_info": part,
                         "error": {"code": _reason(error.get("code", "unknown")),
                                   "data": {k: _reason(data[k]) for k in ("reason", "limit") if k in data}}}
            if "fs" in volume:
                fs = _text(volume["fs"], nullable=True)
                projected["fs"] = fs if fs in _FS or fs == "exfat-invalid" else "unknown"
        else:
            part = _partition(volume.get("partition"))
            index = part["index"]
            info, walk = _dict(volume.get("info")), _dict(volume.get("walk"))
            fs = info.get("fs_type")
            if (fs not in _FS or walk.get("fs") != fs or part.get("fs_hint", fs) not in {fs, "exfat-invalid"}):
                raise input_error()
            entries = _list(walk.get("entries"))
            total_entries += len(entries)
            if total_entries > 200000:
                raise input_error("secret_survey_input_limit")
            new_info, new_walk = _coverage(info), _coverage(walk)
            new_info["fs_type"], new_walk["fs"] = fs, fs
            new_walk["entries"] = []
            refs = set()
            for n, entry in enumerate(entries):
                if n % 128 == 0:
                    check()
                item = _entry(entry, fs)
                if item["ref"] in refs:
                    raise input_error()
                refs.add(item["ref"])
                new_walk["entries"].append(item)
            projected = {"partition": part, "info": new_info, "walk": new_walk}
        if index in seen_parts:
            raise input_error()
        seen_parts.add(index)
        out["volumes"].append(projected)
    check()
    return out


def _identity(st):
    return st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns, st.st_ctime_ns, st.st_mode, st.st_nlink


def _directory_identity(st):
    # 새 분석 출력은 허용하므로 디렉터리 mtime/크기는 신원에 넣지 않는다.
    return st.st_dev, st.st_ino, st.st_mode, st.st_uid


def _event(entries, case_id, ev, path, check):
    entries = _list(entries)
    found = None
    for n, item in enumerate(entries):
        if n % 256 == 0:
            check()
        item = _dict(item)
        data = item.get("data")
        if (item.get("event") == "list" and item.get("evidence_id") == ev
                and type(data) is dict and data.get("result_path") == path):
            if found is not None:
                raise input_error()
            found = item
    if found is None or found.get("case_id") != case_id:
        raise input_error()
    seq, sha = found.get("seq"), found["data"].get("result_sha256")
    if (type(seq) is not int or not 1 <= seq <= len(entries) or entries[seq - 1] is not found
            or type(sha) is not str or not _SHA.fullmatch(sha)):
        raise input_error()
    check()
    return found


@dataclass(frozen=True)
class ListOrigin:
    """보고서 SHA와 list 사건 SHA를 구분하는 닫힌 출처."""

    path: str
    sha256: str
    size: int
    custody_seq: int
    custody_hash: str

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class ListInput:
    """context가 fd를 소유하며 공개 dict를 무결성 권위로 사용하지 않는다."""

    listing: dict
    source: dict
    origin: ListOrigin
    _case: Case
    _ev: str
    _dirs: tuple[int, ...]
    _dir_seals: tuple[tuple[int, ...], ...]
    _fd: int
    _seal: tuple[int, ...]
    _origin: ListOrigin
    _deadline: float
    _cancel: Callable[[], bool]

    def _tick(self, *, timed=False):
        _tick(self._deadline, self._cancel, timed=timed)

    def _names(self):
        current = safeio.open_dir_chain(self._case.dir)
        try:
            for n, part in enumerate((None, "forensics", "analysis")):
                if part is not None:
                    child = os.open(part, safeio.DIR_FLAGS, dir_fd=current)
                    os.close(current)
                    current = child
                if (_directory_identity(os.fstat(current)) != self._dir_seals[n]
                        or _directory_identity(os.fstat(self._dirs[n])) != self._dir_seals[n]):
                    raise input_error("secret_survey_input_changed")
            named = os.stat(self._origin.path.rsplit("/", 1)[1], dir_fd=current, follow_symlinks=False)
            if _identity(named) != self._seal or _identity(os.fstat(self._fd)) != self._seal:
                raise input_error("secret_survey_input_changed")
        finally:
            os.close(current)

    def _hash(self, *, collect=False, timed=False):
        digest, offset = hashlib.sha256(), 0
        data = bytearray() if collect else None
        self._tick(timed=timed)
        self._names()
        while offset < self._origin.size:
            self._tick(timed=timed)
            chunk = os.pread(self._fd, min(_CHUNK, self._origin.size - offset), offset)
            if not chunk:
                raise input_error("secret_survey_input_changed")
            offset += len(chunk)
            digest.update(chunk)
            if data is not None:
                data.extend(chunk)
        self._names()
        self._tick(timed=timed)
        if digest.hexdigest() != self._origin.sha256:
            raise input_error("secret_survey_input_changed")
        return bytes(data) if data is not None else None

    def check(self) -> None:
        """취소와 root/부모/이름/fd seal만 확인한다. 전체 해시나 시간 재적용은 없다."""
        try:
            self._tick()
            self._names()
            self._tick()
        except Exception as exc:
            code = "cancelled" if getattr(exc, "code", None) == "cancelled" else "secret_survey_input_changed"
            raise input_error(code) from None

    def check_entries(self, entries: list[dict]) -> None:
        """커밋 잠금의 검증 entries와 같은 fd 전체를 대조한다. 보관 로그는 열지 않는다."""
        try:
            event = _event(entries, self._case.id, self._ev, self._origin.path, self._tick)
            if (event["seq"] != self._origin.custody_seq or E.entry_hash(event) != self._origin.custody_hash
                    or event["data"]["result_sha256"] != self._origin.sha256):
                raise input_error("secret_survey_input_changed")
            self._hash()
        except Exception as exc:
            code = "cancelled" if getattr(exc, "code", None) == "cancelled" else "secret_survey_input_changed"
            raise input_error(code) from None


@contextlib.contextmanager
def open_list_input(case: Case, opened: E.OpenedEvidence, *, fs_list_path: str, entries: list[dict],
                    deadline: float, cancel: Callable[[], bool]) -> Iterator[ListInput]:
    """같은 EV의 유일 list 사건과 완전한 생성 목록 하나를 결속해 최종 커밋까지 연다."""
    dirs, fd = [], None
    try:
        _tick(deadline, cancel)
        ev = opened.evidence_id
        sha = opened.intake.get("hashes", {}).get("sha256")
        if (type(ev) is not str or E.EV_RE.fullmatch(ev) is None or opened.record.get("case_id") != case.id
                or type(sha) is not str or not _SHA.fullmatch(sha) or type(fs_list_path) is not str
                or re.fullmatch(r"forensics/analysis/fs-list-" + re.escape(ev) + r"-[0-9]{3,9}\.json", fs_list_path) is None):
            raise input_error()
        event = _event(entries, case.id, ev, fs_list_path, lambda: _tick(deadline, cancel))
        dirs.append(safeio.open_dir_chain(case.dir))
        for name in ("forensics", "analysis"):
            dirs.append(os.open(name, safeio.DIR_FLAGS, dir_fd=dirs[-1]))
        fd, st = safeio.open_regular(fs_list_path.rsplit("/", 1)[1], dir_fd=dirs[-1], reject_hardlinks=True)
        if not 0 < st.st_size <= MAX_REPORT_BYTES:
            raise input_error("secret_survey_input_limit")
        if st.st_mode & 0o222 or not stat.S_ISREG(st.st_mode):
            raise input_error()
        origin = ListOrigin(fs_list_path, event["data"]["result_sha256"], st.st_size, event["seq"], E.entry_hash(event))
        result = ListInput({}, {}, origin, case, ev, tuple(dirs),
                           tuple(_directory_identity(os.fstat(d)) for d in dirs), fd, _identity(st), origin, deadline, cancel)
        raw = result._hash(collect=True, timed=True)
        report = load_json(raw, deadline=deadline, cancel=cancel)
        result.listing = _project(report, ev, sha, lambda: _tick(deadline, cancel))
        result.source = {"kind": "evidence", "evidence_id": ev, "evidence_sha256": sha, "fs_list": origin.to_dict()}
        result._names()
        _tick(deadline, cancel)
    except BaseException as exc:
        for owned in ([fd] if fd is not None else []) + list(reversed(dirs)):
            with contextlib.suppress(OSError):
                os.close(owned)
        if not isinstance(exc, Exception):
            raise
        code = getattr(exc, "code", None)
        if code == "sdioc_input_limit":
            code = "secret_survey_input_limit"
        raise input_error(code) from None
    try:
        yield result
    finally:
        for owned in [fd, *reversed(dirs)]:
            with contextlib.suppress(OSError):
                os.close(owned)
