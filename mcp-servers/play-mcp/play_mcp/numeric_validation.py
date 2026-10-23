"""공급 숫자 관찰을 계산하고 닫힌 보고서 하나를 같은 FD로 등록한다."""
from __future__ import annotations

import hashlib
import json
import math
import os
import stat
import time

from pweh import safeio, schemas, vision_sequence as V
from pweh.errors import PwehError

SCHEMA = "pweh.numeric-validation/v1"
PROFILE = "supplied-numeric-observations-v1"
MAX_CANONICAL_BYTES = 65536
MAX_OUTPUT_BYTES = 65536
CHUNK = 64 << 10
LIMITATIONS = ("user_time_axis_only", "input_digest_not_acquisition_provenance",
               "raw_observations_not_stored")
_POLICY = ("window_size", "votes_required", "min_valid", "min_confidence", "ttl_seconds")
_COUNTS = ("received_count", "window_count", "recent_count", "valid_count",
           "winning_votes", "tied_leaders")
_FLAGS = ("frame_freshness_verified", "game_semantics_verified", "action_generated")
_CODES = frozenset(("invalid_policy", "invalid_observation", "observation_limit",
                    "numeric_input_invalid", "numeric_output_invalid", "time_limit",
                    "cancelled", "numeric_analysis_failed", "cleanup_incomplete"))


def _error(code: str) -> PwehError:
    """공급 값·경로·원래 예외를 새 오류에 옮기지 않는다."""
    return PwehError("공급 숫자 관찰의 분석을 완료하지 못했습니다.", code=code)


def _tick(deadline, cancel) -> None:
    if cancel is not None:
        try:
            stopped = cancel()
            if type(stopped) is not bool:
                raise ValueError
        except Exception:
            raise _error("numeric_analysis_failed") from None
        if stopped:
            raise _error("cancelled")
    if time.monotonic() >= deadline:
        raise _error("time_limit")


def _json(value) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False).encode("utf-8")


def _policy_dict(policy) -> dict:
    return {key: getattr(policy, key) for key in _POLICY}


def _validate_result(result, observations, now, policy) -> None:
    """투표를 다시 계산하지 않고 코어 반환형·수치·입력 연결만 검사한다."""
    def require(condition):
        if not condition:
            raise _error("numeric_output_invalid")

    require(type(result) is dict and set(result) == {
        "schema", "status", "reason", "value", "evidence", "policy", *_FLAGS})
    require(type(result["schema"]) is str and result["schema"] == V.SCHEMA)
    require(type(result["status"]) is str and type(result["reason"]) is str)
    require(all(result[key] is False for key in _FLAGS))
    settings = result["policy"]
    require(type(settings) is dict and set(settings) == set(_POLICY))
    expected = _policy_dict(policy)
    require(all(type(settings[key]) is type(expected[key]) and settings[key] == expected[key]
                for key in _POLICY))
    evidence = result["evidence"]
    require(type(evidence) is dict and set(evidence) == {*_COUNTS, "latest_age_seconds"})
    require(all(type(evidence[key]) is int and 0 <= evidence[key] <= V.MAX_OBSERVATIONS
                for key in _COUNTS))
    received, window, recent, valid, winning, leaders = (evidence[key] for key in _COUNTS)
    require(received == len(observations) and window == min(received, policy.window_size))
    require(0 <= valid <= recent <= window <= received)
    require(0 <= winning <= valid and 0 <= leaders <= valid)
    require((valid == 0) == (winning == 0) == (leaders == 0))
    require(leaders * winning <= valid)
    age = evidence["latest_age_seconds"]
    if received == 0:
        require(age is None)
    else:
        require(type(age) in (int, float) and 0 <= age <= now)
        require(age == now - observations[-1].timestamp)
        require((recent == 0) == (age > policy.ttl_seconds))

    if received == 0:
        status, reason = "unknown", "no_observations"
    elif recent == 0:
        status, reason = "stale", "no_recent_observations"
    elif valid < policy.min_valid:
        status, reason = "unknown", "insufficient_valid"
    elif leaders > 1:
        status, reason = "unknown", "tied_votes"
    elif winning < policy.votes_required:
        status, reason = "unknown", "insufficient_votes"
    else:
        status, reason = "stable", "vote_consensus"
    require(result["status"] == status and result["reason"] == reason)
    value = result["value"]
    require((type(value) is int and V.MIN_VALUE <= value <= V.MAX_VALUE)
            if status == "stable" else value is None)


def _file_seal(st) -> tuple:
    return (st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns,
            st.st_ctime_ns, st.st_mode, st.st_nlink)


def _dir_seal(st) -> tuple:
    return st.st_dev, st.st_ino, st.st_mode, st.st_uid


class _Directories:
    """case root와 analysis 부모 FD를 commit까지 보유한다."""

    def __init__(self, case, deadline, cancel):
        self.case = case
        self.fds = []
        self.root = self.analysis = None
        try:
            _tick(deadline, cancel)
            self.root = safeio._walk_directory(str(case.dir), deadline=deadline)
            self.fds.append(self.root)
            self.root_seal = _dir_seal(os.fstat(self.root))
            before = os.stat("analysis", dir_fd=self.root, follow_symlinks=False)
            if not stat.S_ISDIR(before.st_mode):
                raise _error("numeric_output_invalid")
            self.analysis = os.open("analysis", safeio.DIR_FLAGS, dir_fd=self.root)
            self.fds.append(self.analysis)
            self.analysis_seal = _dir_seal(os.fstat(self.analysis))
            if _dir_seal(before) != self.analysis_seal:
                raise _error("numeric_output_invalid")
            self.check(deadline, cancel)
        except Exception:
            if not self.close():
                raise _error("cleanup_incomplete") from None
            raise

    def check(self, deadline, cancel):
        _tick(deadline, cancel)
        root = os.stat(self.case.dir, follow_symlinks=False)
        analysis = os.stat("analysis", dir_fd=self.root, follow_symlinks=False)
        if (not stat.S_ISDIR(root.st_mode) or not stat.S_ISDIR(analysis.st_mode)
                or _dir_seal(root) != self.root_seal
                or _dir_seal(os.fstat(self.root)) != self.root_seal
                or _dir_seal(analysis) != self.analysis_seal
                or _dir_seal(os.fstat(self.analysis)) != self.analysis_seal):
            raise _error("numeric_output_invalid")

    def close(self) -> bool:
        ok = True
        for fd in reversed(self.fds):
            try:
                os.close(fd)
            except OSError:
                ok = False
        self.fds.clear()
        return ok


def _check_file(fd, parent, name, seal):
    actual = os.fstat(fd)
    named = os.stat(name, dir_fd=parent, follow_symlinks=False)
    if (not stat.S_ISREG(actual.st_mode) or actual.st_nlink != 1
            or actual.st_mode & 0o222 or _file_seal(actual) != seal or _file_seal(named) != seal):
        raise _error("numeric_output_invalid")


def _hash_fd(fd, size, deadline, cancel):
    digest = hashlib.sha256()
    offset = 0
    while offset < size:
        _tick(deadline, cancel)
        block = os.pread(fd, min(CHUNK, size - offset), offset)
        if not block:
            raise _error("numeric_output_invalid")
        digest.update(block)
        offset += len(block)
    _tick(deadline, cancel)
    return digest.hexdigest()


def validate_supplied_numeric(case, observations: tuple[V.NumericObservation, ...], *,
                              now: int | float, policy: V.NumericPolicy,
                              deadline: float, cancel) -> dict:
    """기존 숫자 코어를 한 번 호출하고 같은 5초 안에서 출력 FD를 등록한다."""
    directories = None
    output_fd = output_name = output_identity = None
    committed = None
    report = None
    path = digest = size = None
    failure = None
    warnings = []
    try:
        try:
            finite = type(deadline) in (int, float) and math.isfinite(deadline)
        except (ValueError, OverflowError):
            finite = False
        if (not finite or deadline - time.monotonic() > 5.0
                or type(observations) is not tuple or type(policy) is not V.NumericPolicy
                or cancel is not None and not callable(cancel)):
            raise _error("numeric_input_invalid")
        _tick(deadline, cancel)
        # 전체 입력 검증과 합의의 단일 권위다. 공급 now를 호스트 시각으로 바꾸지 않는다.
        analysis = V.summarize_numeric_observations(observations, now=now, policy=policy)
        _tick(deadline, cancel)
        _validate_result(analysis, observations, now, policy)
        canonical = _json({"schema": "pweh.numeric-input/v1", "input_kind": "numeric-observations",
                           "now": now, "policy": _policy_dict(policy),
                           "observations": [{"timestamp": row.timestamp, "value": row.value,
                                             "confidence": row.confidence} for row in observations]})
        if len(canonical) > MAX_CANONICAL_BYTES:
            raise _error("numeric_input_invalid")
        report = {"schema": SCHEMA, "profile": PROFILE,
                  "source": {"kind": "supplied-observations", "input_kind": "numeric-observations",
                             "observation_count": len(observations),
                             "canonicalization": "pweh-numeric-json-v1", "canonical_size": len(canonical),
                             "canonical_sha256": hashlib.sha256(canonical).hexdigest()},
                  "params": {"now": now}, "analysis": analysis, "limitations": list(LIMITATIONS)}
        schemas.validate("numeric-validation", report)
        encoded = _json(report) + b"\n"
        size = len(encoded)
        if size > MAX_OUTPUT_BYTES:
            raise _error("numeric_output_invalid")
        _tick(deadline, cancel)
        directories = _Directories(case, deadline, cancel)
        for number in range(1, 10001):
            _tick(deadline, cancel)
            name = f"numeric-observations-{number:03d}.json"
            try:
                fd = os.open(name, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                             0o600, dir_fd=directories.analysis)
            except FileExistsError:
                continue
            output_fd, output_name = fd, name
            output_identity = os.fstat(fd)
            path = f"analysis/{name}"
            break
        if output_fd is None:
            raise _error("numeric_output_invalid")
        position = 0
        while position < size:
            _tick(deadline, cancel)
            written = os.write(output_fd, encoded[position:position + CHUNK])
            if written <= 0:
                raise _error("numeric_output_invalid")
            position += written
        os.fchmod(output_fd, 0o444)
        os.fsync(output_fd)
        seal = _file_seal(os.fstat(output_fd))
        directories.check(deadline, cancel)
        _check_file(output_fd, directories.analysis, output_name, seal)
        digest = _hash_fd(output_fd, size, deadline, cancel)
        if digest != hashlib.sha256(encoded).hexdigest():
            raise _error("numeric_output_invalid")
        _check_file(output_fd, directories.analysis, output_name, seal)

        def check(entry):
            directories.check(deadline, cancel)
            _check_file(output_fd, directories.analysis, output_name, seal)
            if _hash_fd(output_fd, size, deadline, cancel) != digest:
                raise _error("numeric_output_invalid")
            if any(type(entry.get(key)) is not type(value) or entry.get(key) != value for key, value in
                   (("path", path), ("size", size), ("is_dir", False), ("sha256", digest))):
                raise _error("numeric_output_invalid")
            directories.check(deadline, cancel)
            _check_file(output_fd, directories.analysis, output_name, seal)
            _tick(deadline, cancel)

        def on_commit(entry):
            nonlocal committed
            # 원자 metadata 게시 뒤 첫 동작이다. 이후 취소/감사 오류는 등록을 되돌리지 않는다.
            committed = dict(entry)

        case.register_artifact(path, kind="other", producer="pweh-play",
                               extra={"type": "numeric-validation"}, compute_hash=False, sha256=digest,
                               check=check, on_commit=on_commit, deadline=deadline, replace_existing=False)
        if committed is None:
            raise _error("numeric_analysis_failed")
    except Exception as exc:
        if committed is not None:
            warnings.append("post_commit_audit_failed")
        else:
            code = getattr(exc, "code", "numeric_analysis_failed")
            if code in ("lock_timeout", "artifact_timeout"):
                code = "time_limit"
            elif isinstance(exc, safeio.UnsafeFile):
                code = "numeric_output_invalid"
            failure = code if code in _CODES else "numeric_analysis_failed"
    finally:
        if committed is None and output_fd is not None:
            try:
                directories.check(float("inf"), None)
                named = os.stat(output_name, dir_fd=directories.analysis, follow_symlinks=False)
                if (output_identity is None or not safeio.same_file(named, output_identity)
                        or not safeio.same_file(os.fstat(output_fd), output_identity)):
                    raise _error("cleanup_incomplete")
                os.unlink(output_name, dir_fd=directories.analysis)
            except Exception:
                failure = "cleanup_incomplete"
        closed = True
        if output_fd is not None:
            try:
                os.close(output_fd)
            except OSError:
                closed = False
        if directories is not None:
            closed = directories.close() and closed
        if not closed:
            # commit 여부와 관계없이 정리 실패는 고정 오류다. 이미 등록한 출력은 그대로 둔다.
            failure = "cleanup_incomplete"
    if failure is not None:
        raise _error(failure) from None
    return {"ok": True, "report": report, "artifact_id": committed["id"],
            "analysis_path": path, "sha256": digest, "size": size, "warnings": warnings}
