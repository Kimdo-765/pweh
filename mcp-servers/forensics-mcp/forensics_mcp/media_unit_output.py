"""검증한 선택 bytes의 저장 미디어 후보 단위 하나를 같은 fd로 쓰고 보관 기록에 결속한다.

증거·보고서 fd는 호출자가 소유한다. 이 모듈은 새 출력 두 파일만 소유하며,
커밋 실패 시 기록한 inode만 정리한다. 녹화 내용을 해석하거나 반환하지 않는다.
"""

from __future__ import annotations

import hashlib
import json
import math
import os
import stat
import time
from dataclasses import dataclass, field
from typing import Any, Callable

from pweh import evidence as E, media_units as M, safeio, schemas
from pweh.jobs import JobCancelled

from . import outputs

MAX_SOURCE_BYTES = 64 << 20
MAX_MANIFEST_BYTES = 64 << 10
CHUNK_BYTES = 64 << 10
MAX_SECONDS = 45
PAYLOAD_NAME = "unit-000.bin"
MANIFEST_NAME = "manifest.json"
METHOD = "media_unit"
_ERRORS = {
    "media_unit_input_invalid": "미디어 후보 단위의 입력과 저장 범위를 확인하지 못했습니다.",
    "media_unit_input_limit": "미디어 단위 후보 입력의 크기·구조 상한을 넘었습니다.",
    "media_unit_input_changed": "선택 바이트 또는 기대 출력 해시가 달라 추출을 중단했습니다.",
    "output_limit": "미디어 후보 단위 산출물의 크기 한도를 넘었습니다.",
    "time_limit": "미디어 후보 단위 추출의 시간 한도에 닿았습니다.",
    "cancelled": "미디어 후보 단위 추출이 취소되었습니다.",
    "custody_broken": "보관 기록을 확인하지 못해 미디어 후보 단위를 기록하지 않았습니다.",
    "cleanup_incomplete": "미커밋 산출물의 신원 또는 정리를 확인하지 못해 남은 항목을 보존했습니다.",
    "media_unit_failed": "미디어 후보 단위의 작성 또는 최종 무결성 검사를 완료하지 못했습니다.",
}


def _error(code: str) -> E.EvidenceError:
    return E.EvidenceError(_ERRORS[code], code=code)


def _fixed_error(exc: Exception) -> E.EvidenceError:
    if isinstance(exc, E.IntegrityProblem):
        return E.IntegrityProblem("증거의 무결성을 확인하지 못했습니다.",
                                  reason="media-unit-integrity-check", record=exc.record)
    code = getattr(exc, "code", None)
    if isinstance(exc, JobCancelled):
        code = "cancelled"
    if code == "timeout":
        code = "time_limit"
    return _error(code if isinstance(code, str) and code in _ERRORS else "media_unit_failed")


def _deadline(value: Any) -> float:
    if type(value) not in (int, float):
        raise _error("media_unit_input_invalid")
    try:
        end = float(value)
        if not math.isfinite(end) or end > time.monotonic() + MAX_SECONDS:
            raise ValueError
    except (OverflowError, ValueError):
        raise _error("media_unit_input_invalid") from None
    return end


def _freeze_manifest(manifest: Any, tick: Callable[[], None]) -> tuple[dict, bytes]:
    """작은 JSON 트리만 받아 검증 후 동결한다. 오류에 원래 값이나 경로를 넣지 않는다."""
    if type(manifest) is not dict:
        raise _error("media_unit_input_invalid")
    stack, nodes, characters = [(manifest, 0)], 0, 0
    while stack:
        tick()
        value, depth = stack.pop()
        nodes += 1
        if nodes > 8192 or depth > 16:
            raise _error("output_limit")
        if type(value) is dict:
            if len(value) > 1024:
                raise _error("output_limit")
            for key, item in value.items():
                if type(key) is not str:
                    raise _error("media_unit_input_invalid")
                characters += len(key)
                stack.append((item, depth + 1))
        elif type(value) is list:
            if len(value) > 1024:
                raise _error("output_limit")
            stack.extend((item, depth + 1) for item in value)
        elif type(value) is str:
            characters += len(value)
        elif type(value) is int:
            if not -(1 << 63) <= value < (1 << 63):
                raise _error("media_unit_input_invalid")
        elif value is not None and type(value) is not bool:
            raise _error("media_unit_input_invalid")
        if characters > MAX_MANIFEST_BYTES:
            raise _error("output_limit")
    try:
        raw = (json.dumps(manifest, ensure_ascii=False, sort_keys=True,
                          separators=(",", ":"), allow_nan=False) + "\n").encode("utf-8")
        if len(raw) > MAX_MANIFEST_BYTES:
            raise _error("output_limit")
        frozen = json.loads(raw)
        schemas.validate("media-unit-extract", frozen)
    except E.EvidenceError:
        raise
    except Exception:
        raise _error("media_unit_input_invalid") from None
    tick()
    return frozen, raw


def _bytes_hash(data: memoryview, tick: Callable[[], None]) -> str:
    digest = hashlib.sha256()
    for start in range(0, len(data), CHUNK_BYTES):
        tick()
        digest.update(data[start:start + CHUNK_BYTES])
    tick()
    return digest.hexdigest()


def _validate_source(opened: E.OpenedEvidence, data: bytes, manifest: dict,
                     tick: Callable[[], None]) -> tuple[int, int, str]:
    format = manifest["format"]
    if type(data) is not bytes or not M.MIN_SELECTED_BYTES[format] <= len(data) <= MAX_SOURCE_BYTES:
        raise _error("media_unit_input_invalid")
    source, candidate, file = manifest["source"], manifest["candidate"], manifest["files"][0]
    sha = opened.intake["hashes"]["sha256"]
    ranged = source["method"] == "byte-range"
    if "region" in source:
        if source["region"] != "residual":
            raise _error("media_unit_input_invalid")
        profile = M.RESIDUAL_PROFILES[format]
    elif ranged:
        profile = M.RANGE_PROFILES[format]
    else:
        profile = M.FILE_PROFILES[format]
    if (manifest["source_profile"] != profile or candidate["format"] != format
            or manifest["evidence_id"] != opened.evidence_id or source["evidence_id"] != opened.evidence_id
            or manifest["evidence_sha256"] != sha or source["evidence_sha256"] != sha
            or source["selected_size"] != len(data)):
        raise _error("media_unit_input_invalid")
    if "region" in source:
        # schema 외에도 raw 길이의 exact 정수형·차이를 실제 선택 bytes와 대조한다.
        if (source["region"] != "residual"
                or any(type(source[key]) is not int for key in
                       ("data_length", "valid_data_length", "selected_size", "partition"))
                or not 0 <= source["valid_data_length"] < source["data_length"] <= (1 << 63) - 1
                or source["data_length"] - source["valid_data_length"] != len(data)
                or type(manifest["source_coverage"]["input_bytes"]) is not int):
            raise _error("media_unit_input_invalid")
    if ranged:
        offset, evidence_size = source["offset"], source["evidence_size"]
        if (any(type(v) is not int for v in (offset, evidence_size, source["selected_size"],
                                             opened.intake.get("size")))
                or not 0 <= offset <= (1 << 63) - 1 or not 0 < evidence_size <= (1 << 63) - 1
                or offset + len(data) > evidence_size
                or evidence_size != opened.intake["size"] or evidence_size != opened.st.st_size
                or evidence_size != os.fstat(opened.fd).st_size):
            raise _error("media_unit_input_invalid")
    index, start, size = candidate["index"], candidate["offset"], candidate["length"]
    # schema는 닫힌 형식/종료 분기를 검사하고 여기서는 선택 상대 산술을 독립 대조한다.
    if (any(type(n) is not int for n in (index, start, size, source["selected_size"], file["size"],
                                        manifest["bytes_total"], manifest["source_coverage"]["input_bytes"]))
            or not 0 <= index <= 127
            or start < 0 or size < M.MIN_UNIT_BYTES[format] or start + size > len(data)
            or candidate["confidence"] != "possible"
            or file["file"] != PAYLOAD_NAME or file["size"] != size
            or manifest["bytes_total"] != size or manifest["source_coverage"]["input_bytes"] != len(data)):
        raise _error("media_unit_input_invalid")
    if _bytes_hash(memoryview(data), tick) != source["selected_sha256"]:
        raise _error("media_unit_input_changed")
    return start, size, file["sha256"]


@dataclass
class _Output:
    """실패 정리에도 쓰는 비공개 신원 기록. 호스트 inode는 산출물에 싣지 않는다."""

    parent: int | None = None
    name: str | None = None
    directory: int | None = None
    made_directory: os.stat_result | None = None
    files: dict[str, int] = field(default_factory=dict)
    seals: dict[str, os.stat_result] = field(default_factory=dict)

    def claim(self, case: Any, tick: Callable[[], None]) -> None:
        self.parent = E.open_forensics(case, "recovered", create=True)
        for sequence in range(1, 100000):
            tick()
            name = f"media-unit-{sequence:03d}"
            try:
                os.mkdir(name, 0o700, dir_fd=self.parent)
            except FileExistsError:
                continue
            self.name = name
            self.made_directory = os.stat(name, dir_fd=self.parent, follow_symlinks=False)
            self.directory = os.open(name, safeio.DIR_FLAGS, dir_fd=self.parent)
            if (not stat.S_ISDIR(self.made_directory.st_mode)
                    or not safeio.same_file(self.made_directory, os.fstat(self.directory))):
                raise _error("media_unit_failed")
            return
        raise _error("output_limit")

    def create(self, name: str) -> int:
        flags = os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC
        fd = os.open(name, flags, 0o600, dir_fd=self.directory)
        self.files[name] = fd  # 그 뒤 fstat·쓰기 실패에도 생성한 fd가 소유권 기록이다.
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_nlink != 1:
            raise _error("media_unit_failed")
        return fd

    def seal(self, name: str) -> None:
        fd = self.files[name]
        os.fchmod(fd, 0o444)
        os.fsync(fd)
        self.seals[name] = outputs.seal_file(self.directory, name, fd)

    def discard(self) -> bool:
        """확인한 자기 inode만 제거한다. 교체물·알 수 없는 항목은 그대로 둔다."""
        if self.name is None:
            return True
        ok = True
        if self.directory is not None:
            try:
                if self.made_directory is None or not safeio.same_file(
                        self.made_directory, os.fstat(self.directory)):
                    return False
                os.fchmod(self.directory, 0o700)
            except OSError:
                return False
            for name, fd in self.files.items():
                try:
                    current = os.stat(name, dir_fd=self.directory, follow_symlinks=False)
                    if safeio.same_file(current, os.fstat(fd)):
                        os.unlink(name, dir_fd=self.directory)
                    else:
                        ok = False
                except FileNotFoundError:
                    pass
                except OSError:
                    ok = False
        try:
            current = os.stat(self.name, dir_fd=self.parent, follow_symlinks=False)
            if (self.made_directory is None or not stat.S_ISDIR(current.st_mode)
                    or not safeio.same_file(current, self.made_directory)):
                return False
            os.rmdir(self.name, dir_fd=self.parent)  # 비어 있지 않으면 보존한다. 재귀 삭제하지 않는다.
            os.fsync(self.parent)
        except OSError:
            ok = False
        return ok

    def close(self) -> bool:
        ok = True
        for fd in (*self.files.values(), self.directory, self.parent):
            if fd is not None:
                try:
                    os.close(fd)
                except OSError:
                    ok = False
        return ok


def _write(fd: int, data: memoryview, tick: Callable[[], None]) -> str:
    digest = hashlib.sha256()
    for start in range(0, len(data), CHUNK_BYTES):
        piece = data[start:start + CHUNK_BYTES]
        offset = 0
        while offset < len(piece):
            tick()
            count = os.write(fd, piece[offset:])
            if type(count) is not int or not 0 < count <= len(piece) - offset:
                raise _error("media_unit_failed")
            digest.update(piece[offset:offset + count])
            offset += count
    tick()
    return digest.hexdigest()


def _check_written(output: _Output, case: Any, hashes: dict[str, str],
                   tick: Callable[[], None]) -> None:
    if stat.S_IMODE(os.fstat(output.directory).st_mode) != 0o555:
        raise _error("media_unit_failed")
    outputs.check_tree(case, output.parent, output.name, output.directory, output.seals)
    for name, fd in output.files.items():
        tick()
        saved = output.seals[name]
        if outputs._identity(os.fstat(fd)) != outputs._identity(saved):
            raise _error("media_unit_failed")
        digest = hashlib.sha256()
        for start in range(0, saved.st_size, CHUNK_BYTES):
            tick()
            raw = os.pread(fd, min(CHUNK_BYTES, saved.st_size - start), start)
            if len(raw) != min(CHUNK_BYTES, saved.st_size - start):
                raise _error("media_unit_failed")
            digest.update(raw)
        if digest.hexdigest() != hashes[name] or outputs._identity(os.fstat(fd)) != outputs._identity(saved):
            raise _error("media_unit_failed")
    # 마지막 해시 검사 중 이름이 바뀐 경우도 같은 커밋 검사에서 거부한다.
    tick()
    if stat.S_IMODE(os.fstat(output.directory).st_mode) != 0o555:
        raise _error("media_unit_failed")
    outputs.check_tree(case, output.parent, output.name, output.directory, output.seals)


def store_media_unit(case: Any, opened: E.OpenedEvidence, data: bytes, *, manifest: dict,
                     custody_log: E.CustodyLog, reference_roots: Any, deadline: float,
                     check: Callable[[], None], check_entries: Callable[[list[dict]], None],
                     on_commit: Callable[[dict], None] | None = None) -> dict:
    """미디어 후보 단위 하나를 복사·seal하고 같은 custody 잠금에서 입력과 출력을 재확인한다."""
    output, committed, result = _Output(), False, None
    try:
        end = _deadline(deadline)
        if not callable(check) or not callable(check_entries) or (on_commit is not None and not callable(on_commit)):
            raise _error("media_unit_input_invalid")

        def tick() -> None:
            if time.monotonic() >= end:
                raise _error("time_limit")
            check()
            if time.monotonic() >= end:
                raise _error("time_limit")

        tick()
        frozen, raw = _freeze_manifest(manifest, tick)
        start, size, expected = _validate_source(opened, data, frozen, tick)
        output.claim(case, tick)
        payload_fd = output.create(PAYLOAD_NAME)
        actual = _write(payload_fd, memoryview(data)[start:start + size], tick)
        if actual != expected:
            raise _error("media_unit_input_changed")
        output.seal(PAYLOAD_NAME)
        manifest_fd = output.create(MANIFEST_NAME)
        manifest_sha = _write(manifest_fd, memoryview(raw), tick)
        output.seal(MANIFEST_NAME)
        os.fchmod(output.directory, 0o555)
        os.fsync(output.directory)
        os.fsync(output.parent)
        relative = f"forensics/recovered/{output.name}"

        def verify(entries: list[dict]) -> None:
            tick()
            E.recheck_opened(case, opened, entries, reference_roots=reference_roots)
            check_entries(entries)
            _check_written(output, case, {PAYLOAD_NAME: actual, MANIFEST_NAME: manifest_sha}, tick)
            tick()  # 마지막 출력 검사 중 도착한 취소도 커밋 전에 확인한다.

        entry = custody_log.append("extract", evidence_id=opened.evidence_id,
                                   data={"output_dir": relative, "manifest_sha256": manifest_sha,
                                         "files": 1, "bytes": size, "method": METHOD, "region": frozen["source"].get("region", "data"),
                                         "analysis": frozen["analysis"], "candidate_index": frozen["candidate"]["index"],
                                         "format": frozen["format"]},
                                   check=verify)
        committed = True  # append의 반환이 커밋이다. 보조 작업 전에 삭제 경로를 닫는다.
        warnings = []
        if on_commit is not None:
            try:
                on_commit(entry)
            except Exception:
                warnings.append("post_commit_callback_failed")
        result = {"ok": True, "evidence_id": opened.evidence_id, "status": frozen["status"],
                  "output_dir": relative, "manifest": relative + "/" + MANIFEST_NAME,
                  "manifest_sha256": manifest_sha, "custody_seq": entry["seq"], "custody_hash": entry["hash"],
                  "files": 1, "bytes_total": size, "warnings": warnings,
                  "note": "저장된 미디어 구조 후보의 단위 하나만 추출했다. 원래 파일 경계·완전 녹화·재생은 확인하지 않았으며 추출물은 직접 열지 않는다."}
        return result
    except Exception as exc:
        if not committed and not output.discard():
            raise _error("cleanup_incomplete") from None
        raise _fixed_error(exc) from None
    finally:
        if not output.close() and result is not None:
            result["warnings"].append("output_close_unconfirmed")
