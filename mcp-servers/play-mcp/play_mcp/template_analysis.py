"""등록 image-hints의 저장 PNG 두 개를 같은 FD와 하나의 마감에 결속한다."""
from __future__ import annotations

import hashlib
import json
import math
import os
import re
import stat
import time
from pathlib import Path

from pweh import imagehints, safeio, schemas
from pweh.errors import PwehError
from pweh.evidence import under_any_case_protected

SCHEMA = "pweh.template-match/v1"
PROFILE = "stored-png-roi-rgb-mae-v1"
MAX_REPORT_BYTES = 8 << 20
MAX_PNG_BYTES = 1 << 20
MAX_OUTPUT_BYTES = 64 << 10
CHUNK = 64 << 10
LIMITATIONS = ("stored_preview_pixels_only", "equal_roi_dimensions_only", "rgb_mean_absolute_error_only",
               "no_frame_freshness_verification", "no_game_semantics_verification", "no_action_generation")
_FLAGS = ("frame_freshness_verified", "game_semantics_verified", "action_generated")
_CODES = frozenset(("template_input_invalid", "template_input_limit", "template_input_changed",
                    "template_output_invalid", "template_failed", "template_cleanup_incomplete",
                    "time_limit", "cancelled"))
_KEYS = ("id", "path", "is_dir", "size", "sha256", "kind", "producer")


def _error(code):
    return PwehError("저장 PNG 비교를 완료하지 못했습니다.", code=code)


def _tick(deadline, event):
    if event is not None:
        try:
            stopped = event.is_set()
            if type(stopped) is not bool:
                raise ValueError
        except Exception:
            raise _error("template_failed") from None
        if stopped:
            raise _error("cancelled")
    if time.monotonic() >= deadline:
        raise _error("time_limit")


def _integer(value, low, high):
    return type(value) is int and low <= value <= high


def _digest(value):
    return type(value) is str and re.fullmatch(r"[0-9a-f]{64}", value) is not None


def _id(value):
    return type(value) is str and re.fullmatch(r"A-[0-9]{4,8}", value) is not None


def _file_seal(st):
    return st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns, st.st_ctime_ns, st.st_mode, st.st_nlink


def _dir_seal(st):
    return st.st_dev, st.st_ino, st.st_mode, st.st_uid


class _Directories:
    """root/analysis 이름과 FD를 함께 고정한다. 날짜 변경은 자기 출력 생성도 일으킨다."""

    def __init__(self, case, deadline, event):
        self.case, self.fds = case, []
        try:
            _tick(deadline, event)
            self.root = safeio._walk_directory(str(case.dir), deadline=deadline)
            self.fds.append(self.root)
            self.root_seal = _dir_seal(os.fstat(self.root))
            named = os.stat("analysis", dir_fd=self.root, follow_symlinks=False)
            if not stat.S_ISDIR(named.st_mode):
                raise _error("template_input_invalid")
            self.analysis = os.open("analysis", safeio.DIR_FLAGS, dir_fd=self.root)
            self.fds.append(self.analysis)
            self.analysis_seal = _dir_seal(os.fstat(self.analysis))
            if _dir_seal(named) != self.analysis_seal:
                raise _error("template_input_changed")
            self.check(deadline, event)
        except Exception:
            if not self.close():
                raise _error("template_cleanup_incomplete") from None
            raise

    def check(self, deadline, event):
        _tick(deadline, event)
        root = os.stat(self.case.dir, follow_symlinks=False)
        named = os.stat("analysis", dir_fd=self.root, follow_symlinks=False)
        if (not stat.S_ISDIR(root.st_mode) or not stat.S_ISDIR(named.st_mode)
                or _dir_seal(root) != self.root_seal or _dir_seal(os.fstat(self.root)) != self.root_seal
                or _dir_seal(named) != self.analysis_seal
                or _dir_seal(os.fstat(self.analysis)) != self.analysis_seal):
            raise _error("template_input_changed")

    def close(self):
        ok = True
        for fd in reversed(self.fds):
            try:
                os.close(fd)
            except OSError:
                ok = False
        self.fds.clear()
        return ok


def _check_file(fd, parent, name, seal, *, code="template_input_changed"):
    try:
        actual = os.fstat(fd)
        named = os.stat(name, dir_fd=parent, follow_symlinks=False)
    except OSError:
        raise _error(code) from None
    if (not stat.S_ISREG(actual.st_mode) or actual.st_nlink != 1 or actual.st_mode & 0o222
            or _file_seal(actual) != seal or _file_seal(named) != seal):
        raise _error(code)


def _read_fd(fd, size, deadline, event, *, collect=False):
    digest, blocks, offset = hashlib.sha256(), [], 0
    while offset < size:
        _tick(deadline, event)
        block = os.pread(fd, min(CHUNK, size - offset), offset)
        if not block or len(block) > min(CHUNK, size - offset):
            raise _error("template_input_changed")
        digest.update(block)
        if collect:
            blocks.append(block)
        offset += len(block)
    _tick(deadline, event)
    return digest.hexdigest(), b"".join(blocks) if collect else None


def _projection(case, *, artifact_id=None, path=None, maximum, deadline, event):
    _tick(deadline, event)
    rows = case.load().get("artifacts")
    if type(rows) is not list:
        raise _error("template_input_invalid")
    matches = []
    for row in rows:
        _tick(deadline, event)
        if type(row) is dict and (row.get("id") == artifact_id if artifact_id is not None
                                 else row.get("path") == path):
            matches.append(row)
    if len(matches) != 1:
        raise _error("template_input_invalid")
    item = {key: matches[0].get(key) for key in _KEYS}
    if (not _id(item["id"]) or type(item["path"]) is not str or item["is_dir"] is not False
            or type(item["size"]) is not int or item["size"] < 1 or not _digest(item["sha256"])
            or item["kind"] != "image-hints" or item["producer"] != "pweh-case"):
        raise _error("template_input_invalid")
    if item["size"] > maximum:
        raise _error("template_input_limit")
    # ID로 골라도 경로 중복을 숨기지 않으며, 경로로 골라도 ID 중복을 허용하지 않는다.
    for key in ("id", "path"):
        count = 0
        for row in rows:
            _tick(deadline, event)
            count += type(row) is dict and row.get(key) == item[key]
        if count != 1:
            raise _error("template_input_invalid")
    return item


def _json_input(data, deadline, event):
    def pairs(items):
        _tick(deadline, event)
        result = {}
        for key, value in items:
            _tick(deadline, event)
            if key in result:
                raise ValueError
            result[key] = value
        return result

    def invalid(_):
        raise ValueError

    try:
        value = json.loads(data.decode("utf-8"), object_pairs_hook=pairs, parse_constant=invalid)
        stack = [value]
        while stack:
            _tick(deadline, event)
            item = stack.pop()
            if type(item) is dict:
                stack.extend(item.keys())
                stack.extend(item.values())
            elif type(item) is list:
                stack.extend(item)
            elif type(item) is str:
                item.encode("utf-8", "strict")
            elif type(item) is float and not math.isfinite(item):
                raise ValueError
        return value
    except PwehError:
        raise
    except Exception:
        raise _error("template_input_invalid") from None


def _open_input(case, row, directories, held, deadline, event):
    name = row["path"].split("/")[-1]
    fd, initial = safeio.open_regular(name, dir_fd=directories.analysis, reject_hardlinks=True)
    item = {"fd": fd, "name": name, "row": row, "seal": _file_seal(initial)}
    held.append(item)
    if initial.st_size != row["size"]:
        raise _error("template_input_changed")
    real = safeio.fd_real_path(fd)
    if real is None:
        raise _error("template_input_invalid")
    try:
        relative = Path(real).relative_to(case.dir)
    except ValueError:
        raise _error("template_input_invalid") from None
    if relative.as_posix() != row["path"] or under_any_case_protected(real, case.dir.parent) is not None:
        raise _error("template_input_invalid")
    directories.check(deadline, event)
    _check_file(fd, directories.analysis, name, item["seal"])
    digest, data = _read_fd(fd, row["size"], deadline, event, collect=True)
    if digest != row["sha256"]:
        raise _error("template_input_changed")
    _check_file(fd, directories.analysis, name, item["seal"])
    directories.check(deadline, event)
    return data


def _select(case, artifact_id, index, roi, directories, held, deadline, event):
    row = _projection(case, artifact_id=artifact_id, maximum=MAX_REPORT_BYTES, deadline=deadline, event=event)
    match = re.fullmatch(r"analysis/image-hints-([0-9]{3,5})\.json", row["path"])
    if not match or not 1 <= int(match[1]) <= 99999 or match[1] != f"{int(match[1]):03d}":
        raise _error("template_input_invalid")
    report = _json_input(_open_input(case, row, directories, held, deadline, event), deadline, event)
    if (type(report) is not dict or report.get("schema") != "pweh.image-hints/v1"
            or report.get("status") not in ("ok", "partial")):
        raise _error("template_input_invalid")
    source, original = report.get("source"), report.get("input")
    if (type(source) is not dict or type(original) is not dict or source.get("kind") != "case-file"
            or type(source.get("path")) is not str or not _integer(source.get("size"), 1, 64 << 20)
            or not _integer(original.get("size"), 1, 64 << 20) or not _digest(source.get("sha256"))
            or not _digest(original.get("sha256")) or source["size"] != original["size"]
            or source["sha256"] != original["sha256"]):
        raise _error("template_input_invalid")
    artifacts = report.get("artifacts")
    previews = artifacts.get("previews") if type(artifacts) is dict else None
    if type(previews) is not list or not 1 <= len(previews) <= 2 or index >= len(previews):
        raise _error("template_input_invalid")
    roles = []
    for preview in previews:
        if type(preview) is not dict or preview.get("role") not in ("overview", "crop"):
            raise _error("template_input_invalid")
        roles.append(preview["role"])
    if len(set(roles)) != len(roles):
        raise _error("template_input_invalid")
    p = previews[index]
    expected = f"analysis/image-hints-{match[1]}-{index + 1:02d}-{p['role']}.png"
    if (p.get("path") != expected or not _integer(p.get("size"), 1, MAX_PNG_BYTES)
            or not _digest(p.get("sha256")) or not _integer(p.get("width"), 1, 1600)
            or not _integer(p.get("height"), 1, 1600)
            or roi[0] + roi[2] > p["width"] or roi[1] + roi[3] > p["height"]):
        raise _error("template_input_invalid")
    png_row = _projection(case, path=expected, maximum=MAX_PNG_BYTES, deadline=deadline, event=event)
    if png_row["size"] != p["size"] or png_row["sha256"] != p["sha256"]:
        raise _error("template_input_changed")
    data = _open_input(case, png_row, directories, held, deadline, event)
    projected = {"report": {"artifact_id": row["id"], "size": row["size"], "sha256": row["sha256"]},
                 "preview": {"index": index, "artifact_id": png_row["id"],
                             **{key: p[key] for key in ("size", "sha256", "width", "height", "role")}}}
    return projected, data, (p["width"], p["height"])


def _validate_result(result, roi, threshold):
    if type(result) is not dict or set(result) != {"sum_abs", "samples", "mean_abs_error", "matched"}:
        raise _error("template_output_invalid")
    samples, total, mean = result["samples"], result["sum_abs"], result["mean_abs_error"]
    if (type(samples) is not int or samples != roi[2] * roi[3] * 3
            or not _integer(total, 0, 255 * samples) or type(mean) not in (int, float)
            or mean != total / samples or type(result["matched"]) is not bool
            or result["matched"] != (total <= threshold * samples)):
        raise _error("template_output_invalid")


def match_registered_previews(case, reference_artifact_id, reference_preview_index, reference_roi,
                              candidate_artifact_id, candidate_preview_index, candidate_roi,
                              max_mean_error, *, deadline, cancel_event):
    """저장 PNG 비교·최종 재해시·등록에 같은 5초 마감과 취소 Event를 사용한다."""
    directories, held = None, []
    output_fd = output_name = output_identity = committed = None
    report = path = digest = size = failure = None
    warnings = []
    try:
        try:
            finite = type(deadline) in (int, float) and math.isfinite(deadline)
        except (ValueError, OverflowError):
            finite = False
        if (not finite or deadline - time.monotonic() > 5 or not _id(reference_artifact_id)
                or not _id(candidate_artifact_id) or not _integer(reference_preview_index, 0, 1)
                or not _integer(candidate_preview_index, 0, 1) or not _integer(max_mean_error, 0, 255)
                or cancel_event is not None and not callable(getattr(cancel_event, "is_set", None))):
            raise _error("template_input_invalid")
        for roi in (reference_roi, candidate_roi):
            if (type(roi) is not tuple or len(roi) != 4
                    or any(not _integer(v, 0 if i < 2 else 1, 1600) for i, v in enumerate(roi))):
                raise _error("template_input_invalid")
        if reference_roi[2:] != candidate_roi[2:]:
            raise _error("template_input_invalid")
        _tick(deadline, cancel_event)
        directories = _Directories(case, deadline, cancel_event)
        ref, ref_data, ref_size = _select(case, reference_artifact_id, reference_preview_index, reference_roi,
                                        directories, held, deadline, cancel_event)
        cand, cand_data, cand_size = _select(case, candidate_artifact_id, candidate_preview_index, candidate_roi,
                                           directories, held, deadline, cancel_event)
        result = imagehints.match_png_rois(ref_data, cand_data, reference_size=ref_size, candidate_size=cand_size,
                                          reference_roi=reference_roi, candidate_roi=candidate_roi,
                                          max_mean_error=max_mean_error, deadline=deadline, cancel_event=cancel_event)
        _tick(deadline, cancel_event)
        _validate_result(result, reference_roi, max_mean_error)
        report = {"schema": SCHEMA, "profile": PROFILE, "sources": {"reference": ref, "candidate": cand},
                  "reference_roi": list(reference_roi), "candidate_roi": list(candidate_roi),
                  "max_mean_error": max_mean_error, "result": dict(result),
                  **{key: False for key in _FLAGS}, "limitations": list(LIMITATIONS)}
        schemas.validate("template-match", report)
        _validate_result(report["result"], reference_roi, max_mean_error)
        encoded = (json.dumps(report, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
                              allow_nan=False) + "\n").encode("ascii")
        size, digest = len(encoded), hashlib.sha256(encoded).hexdigest()
        if size > MAX_OUTPUT_BYTES:
            raise _error("template_output_invalid")
        for number in range(1, 10001):
            _tick(deadline, cancel_event)
            name = f"template-match-{number:03d}.json"
            try:
                fd = os.open(name, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                             0o600, dir_fd=directories.analysis)
            except FileExistsError:
                continue
            output_fd, output_name = fd, name
            output_identity = os.fstat(fd)
            path = f"analysis/{name}"
            break
        if output_fd is None:
            raise _error("template_output_invalid")
        position = 0
        while position < size:
            _tick(deadline, cancel_event)
            written = os.write(output_fd, encoded[position:position + CHUNK])
            if type(written) is not int or not 0 < written <= min(CHUNK, size - position):
                raise _error("template_output_invalid")
            position += written
        os.fchmod(output_fd, 0o444)
        os.fsync(output_fd)
        seal = _file_seal(os.fstat(output_fd))

        def seals():
            directories.check(deadline, cancel_event)
            for item in held:
                _check_file(item["fd"], directories.analysis, item["name"], item["seal"])
            _check_file(output_fd, directories.analysis, output_name, seal, code="template_output_invalid")

        def check(entry):
            seals()
            for item in held:
                row = item["row"]
                fresh = _projection(case, artifact_id=row["id"], maximum=MAX_REPORT_BYTES,
                                    deadline=deadline, event=cancel_event)
                if fresh != row:
                    raise _error("template_input_changed")
                _check_file(item["fd"], directories.analysis, item["name"], item["seal"])
                if _read_fd(item["fd"], row["size"], deadline, cancel_event)[0] != row["sha256"]:
                    raise _error("template_input_changed")
                _check_file(item["fd"], directories.analysis, item["name"], item["seal"])
            if _read_fd(output_fd, size, deadline, cancel_event)[0] != digest:
                raise _error("template_output_invalid")
            if any(type(entry.get(key)) is not type(value) or entry.get(key) != value for key, value in
                   (("path", path), ("size", size), ("is_dir", False), ("sha256", digest))):
                raise _error("template_output_invalid")
            seals()
            _tick(deadline, cancel_event)

        def on_commit(entry):
            nonlocal committed
            # 원자 게시 직후 첫 동작이며 그 뒤 실패가 파일/등록을 되돌리지 않는다.
            committed = dict(entry)

        case.register_artifact(path, kind="other", producer="pweh-play", extra={"type": "template-match"},
                               compute_hash=False, sha256=digest, check=check, on_commit=on_commit,
                               deadline=deadline, replace_existing=False)
        if committed is None:
            raise _error("template_failed")
    except Exception as exc:
        if committed is not None:
            warnings.append("post_commit_callback_failed")
        else:
            code = getattr(exc, "code", "template_failed")
            if code in ("lock_timeout", "artifact_timeout"):
                code = "time_limit"
            elif isinstance(exc, safeio.UnsafeFile):
                code = "template_input_invalid"
            failure = code if code in _CODES else "template_failed"
    finally:
        if committed is None and output_fd is not None:
            try:
                directories.check(float("inf"), None)
                named = os.stat(output_name, dir_fd=directories.analysis, follow_symlinks=False)
                if not safeio.same_file(named, output_identity) or not safeio.same_file(os.fstat(output_fd), output_identity):
                    raise _error("template_cleanup_incomplete")
                os.unlink(output_name, dir_fd=directories.analysis)
            except Exception:
                failure = "template_cleanup_incomplete"
        closed = True
        for fd in [output_fd, *(item["fd"] for item in reversed(held))]:
            if fd is not None:
                try:
                    os.close(fd)
                except OSError:
                    closed = False
        if directories is not None:
            closed = directories.close() and closed
        if not closed:
            if committed is not None:
                warnings.append("output_close_unconfirmed")
            else:
                failure = "template_cleanup_incomplete"
    if failure is not None:
        raise _error(failure) from None
    return {"ok": True, "report": report, "artifact_id": committed["id"], "analysis_path": path,
            "sha256": digest, "size": size, "warnings": warnings}
