"""케이스 생성 전용 ID 예약과 과거 보호 상태 검사.

생성 예약은 케이스를 지워도 남는다. 기존 승인·증명은 상태와 무관하게 참조만 읽고,
원장·솔트·custody는 이름만 본다. 감사 로그·작업 기록은 권한 재사용원이 아니므로
읽지 않는다. 구버전 상태 writer는 이 생성 잠금을 사용하지 않는다는 한계가 있다.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import os
import re
import stat
import time
from pathlib import Path
from typing import Pattern

from . import safeio
from .errors import CaseError, PwehError
from .fsutil import utcnow_iso

MAX_ENTRIES = 100_000
MAX_RECORD_BYTES = 1 << 20
MAX_TOTAL_BYTES = 64 << 20
MAX_SECONDS = 10.0
MAX_CANDIDATES = 100_000
REGISTRY = "case-ids"
CREATE_LOCK = ".create.lock"


def reservation_name(case_id: str) -> str:
    """대소문자 경로 별칭도 같은 예약으로 만든다(내용이 달라도 덮어쓰지 않는다)."""
    return hashlib.sha256(case_id.casefold().encode("ascii")).hexdigest() + ".json"


def _uncertain() -> CaseError:
    return CaseError(
        "보호 상태에서 사용하지 않은 케이스 ID인지 확인할 수 없습니다.",
        code="case_id_state_unverified",
        hint="보호 상태의 손상·링크·검사 한도를 사람이 확인하세요. 상태를 지우거나 자동으로 고치지 않습니다.",
    )


def _unique_object(pairs: list[tuple[str, object]]) -> dict:
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("중복 JSON 키")
        result[key] = value
    return result


class CreationGuard:
    """동일 cases/state의 생성 직렬화. 실제 I/O는 with 안에서만 한다.

    설정의 기준 경로 별칭은 한 번 풀되, 그 아래 디렉터리·파일은 링크를 따르지 않는다.
    디렉터리 fd를 고정하고 발행 전후 경로를 다시 확인한다. 같은 OS 계정이 보호 상태나
    잠금 자체를 삭제하는 행위까지 막는 권한 경계는 아니다.
    """

    def __init__(self, cases_dir: Path, state_dir: Path | None, id_pattern: Pattern[str]) -> None:
        self.requested_cases = Path(cases_dir).absolute()
        self.requested_state = Path(state_dir).absolute() if state_dir is not None else None
        self.id_pattern = id_pattern
        self._stack = contextlib.ExitStack()
        self.roots: list[tuple[Path, Path, int]] = []
        self.locks: list[tuple[int, str, int]] = []
        self.case_fd = -1
        self.state_fd = -1
        self.registry_fd = -1
        self.used: set[str] = set()

    def _keep(self, fd: int) -> int:
        self._stack.callback(os.close, fd)
        return fd

    def _root(self, requested: Path) -> tuple[Path, int]:
        resolved = requested.resolve()
        fd = self._keep(safeio.open_dir_chain(resolved.anchor, resolved.parts[1:], create=True, mode=0o700))
        self.roots.append((requested, resolved, fd))
        return resolved, fd

    def _lock(self, fd: int) -> None:
        # 사용자 설정의 두 루트가 같은 디렉터리를 가리켜도 자기 잠금을 다시 기다리지 않는다.
        if any(safeio.same_file(os.fstat(fd), os.fstat(held)) for held, _, _ in self.locks):
            return
        lock_fd = self._stack.enter_context(safeio.locked_at(fd, CREATE_LOCK))
        self.locks.append((fd, CREATE_LOCK, lock_fd))

    def __enter__(self) -> CreationGuard:
        try:
            self.cases_dir, self.case_fd = self._root(self.requested_cases)
            self._lock(self.case_fd)
            if self.requested_state is not None:
                _, self.state_fd = self._root(self.requested_state)
                self.registry_fd = self._keep(self._child(self.state_fd, REGISTRY, create=True))
                self._lock(self.registry_fd)
            self.recheck()
            self.deadline = time.monotonic() + MAX_SECONDS
            self.entries = 0
            self.bytes_read = 0
            self._collect()
            return self
        except (OSError, PwehError, ValueError, RuntimeError) as exc:
            self._stack.close()
            if isinstance(exc, CaseError):
                raise
            raise _uncertain() from exc
        except BaseException:
            self._stack.close()
            raise

    def __exit__(self, *args) -> None:
        self._stack.close()

    @staticmethod
    def _child(fd: int, name: str, *, create: bool = False) -> int:
        # /proc 경로를 다시 열지 않고 이미 확보한 부모 fd에서만 내려간다.
        if create:
            try:
                os.mkdir(name, 0o700, dir_fd=fd)
            except FileExistsError:
                pass
        return os.open(name, safeio.DIR_FLAGS, dir_fd=fd)

    def recheck(self) -> None:
        """기준 경로·예약 디렉터리·잠금의 교체를 발행 전에 확인한다."""
        try:
            for requested, resolved, fd in self.roots:
                st = os.lstat(resolved)
                if requested.resolve() != resolved or not stat.S_ISDIR(st.st_mode) or not safeio.same_file(st, os.fstat(fd)):
                    raise _uncertain()
            if self.registry_fd >= 0:
                st = os.stat(REGISTRY, dir_fd=self.state_fd, follow_symlinks=False)
                if not stat.S_ISDIR(st.st_mode) or not safeio.same_file(st, os.fstat(self.registry_fd)):
                    raise _uncertain()
            for fd, name, lock_fd in self.locks:
                st = os.stat(name, dir_fd=fd, follow_symlinks=False)
                if not stat.S_ISREG(st.st_mode) or not safeio.same_file(st, os.fstat(lock_fd)):
                    raise _uncertain()
        except OSError as exc:
            raise _uncertain() from exc

    def _tick(self) -> None:
        if self.entries > MAX_ENTRIES or self.bytes_read > MAX_TOTAL_BYTES or time.monotonic() > self.deadline:
            raise _uncertain()

    def _names(self, fd: int):
        with os.scandir(fd) as entries:
            for entry in entries:
                self.entries += 1
                self._tick()
                yield entry.name

    def _add(self, value: object) -> None:
        if value is None:
            return
        if not isinstance(value, str) or self.id_pattern.fullmatch(value) is None:
            raise _uncertain()
        self.used.add(value.casefold())

    def _named_state(self, fd: int, suffix: str) -> None:
        for name in self._names(fd):
            folded = name.casefold()
            candidate = None
            if folded.endswith(suffix):
                candidate = name[:-len(suffix)]
            elif name.startswith(".") and folded.endswith(".lock"):
                candidate = name[1:-5]
            elif name.startswith(".") and folded.endswith(".tmp"):
                # atomic_write_at/json의 .<id>.jsonl.<random>.tmp와 솔트의 .<id>.<random>.tmp.
                candidate = name[1:-4].rsplit(".", 1)[0]
                if suffix != ".key" and candidate.casefold().endswith(suffix):
                    candidate = candidate[:-len(suffix)]
            if candidate is not None:
                self._add(candidate)

    def _records(self, fd: int, prefix: str, schema: str) -> None:
        for name in self._names(fd):
            # 잠금은 케이스 참조를 담지 않는다. 미완성 JSON은 부재로 취급하지 않는다.
            if name == ".store.lock" or re.fullmatch(r"\." + prefix + r"[0-9a-f]{10}\.lock", name):
                continue
            if not re.fullmatch(prefix + r"[0-9a-f]{10}\.json", name):
                raise _uncertain()
            remaining = min(MAX_RECORD_BYTES, MAX_TOTAL_BYTES - self.bytes_read)
            raw = safeio.read_regular(name, max_bytes=remaining, dir_fd=fd, what="케이스 ID 참조 기록")
            self.bytes_read += len(raw)
            self._tick()
            try:
                rec = json.loads(raw, object_pairs_hook=_unique_object)
            except (ValueError, UnicodeError, RecursionError) as exc:
                raise _uncertain() from exc
            if not isinstance(rec, dict) or rec.get("schema") != schema or rec.get("id") != name[:-5] or "case_id" not in rec:
                raise _uncertain()
            self._add(rec["case_id"])
            binding = rec.get("binding", {})
            if not isinstance(binding, dict):
                raise _uncertain()
            self._add(binding.get("case_id"))

    def _collect(self) -> None:
        for name in self._names(self.case_fd):
            if self.id_pattern.fullmatch(name):
                self.used.add(name.casefold())
        if self.state_fd < 0:
            return
        for folder, suffix in (("provenance", ".jsonl"), ("salts", ".key"), ("custody", ".jsonl")):
            try:
                fd = self._child(self.state_fd, folder)
            except FileNotFoundError:
                continue
            try:
                self._named_state(fd, suffix)
            finally:
                os.close(fd)
        for folder, prefix, schema in (("approvals", "ap-", "pweh.approval/v1"), ("attestations", "att-", "pweh.attestation/v1")):
            try:
                fd = self._child(self.state_fd, folder)
            except FileNotFoundError:
                continue
            try:
                self._records(fd, prefix, schema)
            finally:
                os.close(fd)

    def occupied(self, case_id: str) -> bool:
        if case_id.casefold() in self.used:
            return True
        if self.registry_fd >= 0:
            try:
                os.stat(reservation_name(case_id), dir_fd=self.registry_fd, follow_symlinks=False)
                return True  # 빈 파일·손상·링크·서로 다른 ID도 덮어쓰지 않는다.
            except FileNotFoundError:
                pass
        return False

    def allocate(self, base: str, *, automatic: bool) -> tuple[str, int]:
        """예약 뒤 새 케이스 디렉터리를 배타 생성한다. 실패한 예약은 지우지 않는다."""
        for n in range(1, MAX_CANDIDATES + 1):
            self._tick()
            case_id = base if n == 1 else f"{base}-{n}"
            if self.occupied(case_id):
                if not automatic:
                    raise CaseError("이미 사용된 케이스 ID입니다: " + case_id, code="case_id_used",
                                    hint="기존 케이스는 case_get으로 여세요. 새 케이스에는 다른 ID를 사용하세요.")
                continue
            self.recheck()
            if self.registry_fd >= 0:
                record = {"schema": "pweh.case-id/v1", "case_id": case_id, "reserved_at": utcnow_iso()}
                safeio.write_new(self.registry_fd, reservation_name(case_id), (json.dumps(record) + "\n").encode(), final_mode=0o600)
                os.fsync(self.registry_fd)
            try:
                os.mkdir(case_id, dir_fd=self.case_fd)
            except FileExistsError:
                self.used.add(case_id.casefold())
                if automatic:
                    continue
                raise CaseError("생성 중 케이스 ID가 사용되었습니다: " + case_id, code="case_id_used") from None
            fd = self._keep(self._child(self.case_fd, case_id))
            self.check_case(case_id, fd)
            return case_id, fd
        raise _uncertain()

    def check_case(self, case_id: str, fd: int) -> None:
        self.recheck()
        st = os.stat(case_id, dir_fd=self.case_fd, follow_symlinks=False)
        if not stat.S_ISDIR(st.st_mode) or not safeio.same_file(st, os.fstat(fd)):
            raise _uncertain()
