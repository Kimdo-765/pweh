"""내부 pipe 파일 job의 경로 pair·같은 FD·checkpoint·checked 게시 수명.

공개 Windows target 지원이나 실제 타깃 동일성의 근거를 만들지 않는다.
출력의 강한 registry는 실제 owner 종료가 확인될 때까지 부분 생성물도 보존한다.
"""
from __future__ import annotations

import copy
import hashlib
import json
import math
import os
import stat
import threading
import time
import uuid
from dataclasses import dataclass
from pathlib import Path

from pweh import safeio, wininterop
from pweh.case import Case
from pweh.errors import DeviceError
from . import guard, process_windows as W
from .dumps import NAME_RE, MIN_CHUNK, MAX_CHUNK
from .tcl import brace_quote_path, split_list

CHUNK = 65536
UPSTREAM = "e5888bda38f4952e2ae92f7dc5b25fc9a2d1c2b3"
_LOCK = threading.Lock()
_OUTPUTS = {}


class PipeOutputError(DeviceError):
    """원문 없이 부분 출력의 내부 참조만 보존한다."""
    def __init__(self, code, output=None):
        super().__init__("내부 pipe 출력의 검증 또는 정리를 완료하지 못했습니다.", code=code)
        self.output = output


def _fail(code="openocd_output_invalid", output=None):
    raise PipeOutputError(code, output) from None


def _end(value):
    try:
        if type(value) not in (int, float) or not math.isfinite(value):
            raise ValueError
        if value - time.monotonic() > 3600:
            raise ValueError
    except (ValueError, OverflowError):
        _fail()
    return value


def _tick(end, cancel=None):
    if cancel is not None:
        try:
            value = cancel()
            if type(value) is not bool:
                raise ValueError
        except Exception:
            _fail()
        if value:
            _fail("cancelled")
    if time.monotonic() >= end:
        _fail("timeout")


def _key(st):
    return st.st_dev, st.st_ino, st.st_mode, st.st_nlink


def _seal(st):
    return _key(st) + (st.st_size, st.st_mtime_ns, st.st_ctime_ns)


def _uint(value, low, high):
    return type(value) is int and low <= value <= high


def _names(fd, expected, check):
    """허용 슬롯 수+1만 관찰하여 알 수 없는 출력은 보존한다."""
    seen = set()
    with os.scandir(fd) as rows:
        for row in rows:
            check()
            if len(seen) >= len(expected) or row.name not in expected:
                _fail("openocd_output_changed")
            seen.add(row.name)
    if seen != expected:
        _fail("openocd_output_changed")


@dataclass(frozen=True)
class PipeFileSpec:
    case: Case
    kind: str
    output_name: str
    length: int
    chunk_size: int
    verify: bool = False
    resume: bool = True
    address: int | None = None
    bank: int | None = None
    offset: int = 0
    bank_size: int | None = None


@dataclass(frozen=True)
class ChunkFile:
    local_path: Path
    windows_path: str
    expected_size: int


def _spec(spec):
    if (type(spec) is not PipeFileSpec or not isinstance(spec.case, Case)
            or type(spec.kind) is not str or spec.kind not in ("memory", "flash")
            or type(spec.output_name) is not str or not NAME_RE.fullmatch(spec.output_name)
            or spec.output_name.lower().endswith(".bin")
            or not _uint(spec.length, 1, 1 << 32) or not _uint(spec.chunk_size, MIN_CHUNK, MAX_CHUNK)
            or type(spec.verify) is not bool or type(spec.resume) is not bool):
        _fail()
    if spec.kind == "memory":
        if (not _uint(spec.address, 0, (1 << 64) - 1) or spec.address + spec.length > 1 << 64
                or spec.bank is not None or spec.bank_size is not None or type(spec.offset) is not int or spec.offset != 0):
            _fail()
    elif (spec.address is not None or not _uint(spec.bank, 0, (1 << 31) - 1)
          or not _uint(spec.offset, 0, (1 << 32) - 1) or not _uint(spec.bank_size, 1, (1 << 32) - 1)
          or spec.length > (1 << 32) - 1 or spec.offset + spec.length > spec.bank_size):
        _fail()


class _Dir:
    """절대 경로의 모든 부모 이름을 NOFOLLOW FD와 묶는다."""
    def __init__(self, path, check):
        self.path, self.chain = Path(path), []
        self.fd = None
        if not self.path.is_absolute() or ".." in self.path.parts or len(self.path.parts) > 256:
            _fail()
        fd = os.open("/", safeio.DIR_FLAGS)
        self.chain.append((None, None, fd, os.fstat(fd)))
        try:
            for name in self.path.parts[1:]:
                check()
                st = os.stat(name, dir_fd=fd, follow_symlinks=False)
                nxt = os.open(name, safeio.DIR_FLAGS, dir_fd=fd)
                self.chain.append((fd, name, nxt, os.fstat(nxt)))
                if _key(st) != _key(os.fstat(nxt)):
                    _fail("openocd_output_changed")
                fd = nxt
            self.fd = fd
        except BaseException:
            self.close()
            raise

    def check(self):
        for parent, name, fd, st in self.chain:
            current = os.fstat(fd)
            # 디렉터리 link count와 시각은 자기 파일 생성/삭제로 변할 수 있다.
            identity = lambda s: (s.st_dev, s.st_ino, s.st_mode)
            if not stat.S_ISDIR(current.st_mode) or identity(current) != identity(st):
                _fail("openocd_output_changed")
            if parent is not None and identity(os.stat(name, dir_fd=parent, follow_symlinks=False)) != identity(st):
                _fail("openocd_output_changed")

    def close(self):
        ok = True
        for i in range(len(self.chain) - 1, -1, -1):
            row = self.chain[i]
            if row[2] is None:
                continue
            try:
                os.close(row[2])
                self.chain[i] = (*row[:2], None, row[3])
            except OSError:
                ok = False
        if ok:
            self.chain.clear()
            self.fd = None
        return ok


class _File:
    def __init__(self, parent, name, fd, *, created):
        self.parent, self.name, self.fd, self.created = parent, name, fd, created
        self.initial = os.fstat(fd)
        self.seal = None
        self.removed = False
        self.check()

    def check(self, *, sealed=False):
        self.parent.check()
        st = os.fstat(self.fd)
        named = os.stat(self.name, dir_fd=self.parent.fd, follow_symlinks=False)
        if not stat.S_ISREG(st.st_mode) or st.st_nlink != 1 or _key(st) != _key(self.initial) or _key(named) != _key(st):
            _fail("openocd_output_changed")
        if sealed and (self.seal is None or _seal(st) != self.seal or _seal(named) != self.seal):
            _fail("openocd_output_changed")
        return st

    def freeze(self):
        self.seal = _seal(self.check())


def _json(value):
    raw = (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False) + "\n").encode("ascii")
    if len(raw) > CHUNK:
        _fail("openocd_output_limit")
    return raw


def _parse(raw):
    def pairs(rows):
        out = {}
        for k, v in rows:
            if k in out:
                raise ValueError
            out[k] = v
        return out
    def number(s):
        if len(s) > 32:
            raise ValueError
        return int(s)
    def invalid(_):
        raise ValueError
    return json.loads(raw, object_pairs_hook=pairs, parse_int=number, parse_float=invalid, parse_constant=invalid)


def _method(fn):
    """각 출력의 진행을 직렬화하며 원시 예외를 공개하지 않는다."""
    def run(self, *args, **kwargs):
        end = min(self.end, _end(kwargs.get("deadline", self.end)))
        if not self.lock.acquire(timeout=max(0, end - time.monotonic())):
            _fail("timeout", self)
        try:
            self._check(end, kwargs.get("cancel"))
            if self.failed or self.receipt is not None:
                _fail()
            return fn(self, *args, **kwargs)
        except PipeOutputError as exc:
            self.failed = True
            raise PipeOutputError(exc.code, self) from None
        except Exception:
            self.failed = True
            _fail("openocd_output_changed", self)
        finally:
            self.lock.release()
    return run


class PipeOutput:
    """한 owner의 고정 chunk 두 슬롯과 checkpoint를 보유한다."""
    def __init__(self, owner, spec, end, cancel):
        self.owner, self.spec, self.end, self.cancel = owner, spec, end, cancel
        self.client = owner.client
        self.lock = threading.Lock()
        self.failed = False
        self.receipt = None
        self._done = self._resumed = self._chunks = 0
        self.digest = hashlib.sha256()
        self.cwd = self.output = self.destination = None
        self.output_name = "output-" + uuid.uuid4().hex
        self.output_stat = None
        self.files = []
        self.active = {}
        self.part = self.state = self.final = self.meta = None
        self.binding = {"release_id": owner.bundle.release_id, "manifest_sha256": owner.bundle.manifest_sha256,
                        "executable_sha256": owner.plan.inputs.executable.sha256, "upstream_commit": UPSTREAM}

    @property
    def done(self):
        return self._done

    @property
    def resumed_from(self):
        return self._resumed

    @property
    def chunks(self):
        return self._chunks

    def _owner(self, *, live=False, confirmed=False):
        owner = self.owner
        with W._LOCK:
            if (type(owner) is not W.WindowsOpenOcdOwner or W._OWNED.get(owner.token) is not owner
                    or W._RUNS.get(owner.plan.layout.root) is not owner._run or owner._run_released):
                _fail("openocd_output_changed")
        with _LOCK:
            if _OUTPUTS.get(owner.token) is not self:
                _fail("openocd_output_changed")
        if owner.client is not self.client:
            _fail("openocd_output_changed")
        if confirmed and (type(owner._confirmed) is not W.WindowsCleanupResult or owner._confirmed.confirmed is not True):
            _fail("openocd_output_cleanup_unknown")
        if live and (owner._closing or not self.client.connected or self.client.terminal_reason is not None):
            _fail("openocd_pipe_terminal")

    def _check(self, end=None, cancel=None):
        end = min(self.end, end if end is not None else self.end)
        _tick(end, self.cancel)
        if cancel is not None and cancel is not self.cancel:
            _tick(end, cancel)
        self._owner()
        for directory in (self.cwd, self.output, self.destination):
            if directory is not None:
                directory.check()
        if self.output is not None:
            expected = {f.name for f in self.files if f.parent is self.output and not f.removed}
            _names(self.output.fd, expected, lambda: _tick(end, self.cancel))

    def _new(self, parent, name):
        fd = os.open(name, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=parent.fd)
        # 생성 직후부터 record에 묶어 이후 실패에서도 inode를 잃지 않는다.
        record = _File.__new__(_File)
        record.parent, record.name, record.fd, record.created = parent, name, fd, True
        record.initial, record.seal, record.removed = os.fstat(fd), None, False
        self.files.append(record)
        record.check()
        return record

    def _existing(self, parent, name):
        before = os.stat(name, dir_fd=parent.fd, follow_symlinks=False)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or stat.S_IMODE(before.st_mode) != 0o600:
            _fail("openocd_output_resume_invalid")
        fd = os.open(name, os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=parent.fd)
        record = _File.__new__(_File)
        record.parent, record.name, record.fd, record.created = parent, name, fd, False
        record.initial, record.seal, record.removed = os.fstat(fd), None, False
        self.files.append(record)
        if _seal(before) != _seal(record.initial):
            _fail("openocd_output_resume_invalid")
        record.freeze()
        return record

    def _hash(self, record, length, check):
        record.check(sealed=True)
        digest = hashlib.sha256()
        for offset in range(0, length, CHUNK):
            check()
            data = os.pread(record.fd, min(CHUNK, length - offset), offset)
            if len(data) != min(CHUNK, length - offset):
                _fail("openocd_output_changed")
            digest.update(data)
        check()
        record.check(sealed=True)
        return digest

    def _write(self, record, data, offset, check):
        for start in range(0, len(data), CHUNK):
            view = memoryview(data)[start:start + CHUNK]
            while view:
                check()
                n = os.pwrite(record.fd, view, offset)
                if n <= 0:
                    _fail("openocd_output_changed")
                offset += n
                view = view[n:]

    def _identity(self):
        s = self.spec
        return {k: getattr(s, k) for k in ("kind", "output_name", "length", "chunk_size", "verify", "address", "bank", "offset", "bank_size")}

    def _state_value(self, done, digest):
        return {"schema": "pweh.openocd-pipe-state/v2", "case_id": self.spec.case.id,
                "spec": self._identity(), "binding": self.binding, "done": done, "prefix_sha256": digest}

    def _checkpoint(self, done, digest, check):
        raw = _json(self._state_value(done, digest))
        name = self.spec.output_name + ".state.json"
        temp = self._new(self.destination, "." + self.spec.output_name + ".state-" + uuid.uuid4().hex)
        self._write(temp, raw, 0, check)
        os.fsync(temp.fd)
        temp.freeze()
        check()
        temp.check(sealed=True)
        if self.state is not None:
            self.state.check(sealed=True)
        elif _exists(self.destination.fd, name):
            _fail("openocd_output_changed")
        os.replace(temp.name, name, src_dir_fd=self.destination.fd, dst_dir_fd=self.destination.fd)
        old = self.state
        if old is not None:
            old.removed = True
        temp.name = name
        self.state = temp
        os.fsync(self.destination.fd)
        temp.freeze()
        if old is not None:
            self._close_file(old)

    def _close_file(self, record):
        if record.fd is not None:
            if _key(os.fstat(record.fd))[:3] != _key(record.initial)[:3]:
                _fail("openocd_output_cleanup_unknown")
            os.close(record.fd)
            record.fd = None
        if record.removed and record in self.files:
            self.files.remove(record)

    def _remove(self, record):
        if not record.removed:
            record.check(sealed=record.seal is not None)
            os.unlink(record.name, dir_fd=record.parent.fd)
            record.removed = True
        self._close_file(record)

    @_method
    def create_chunk(self, index, slot, expected_size, *, deadline):
        self._owner(live=True)
        if (type(index) is not int or index != self.chunks or type(slot) is not str
                or slot not in ("primary", "second") or slot in self.active
                or (slot == "second" and (self.spec.kind != "memory" or not self.spec.verify or "primary" not in self.active))
                or not _uint(expected_size, 1, MAX_CHUNK)
                or expected_size != min(self.spec.chunk_size, self.spec.length - self.done)):
            _fail()
        record = self._new(self.output, f"chunk-{index:08d}-{slot}-{uuid.uuid4().hex}.bin")
        path = self.output.path / record.name
        self._check(deadline)
        windows = self.owner._path_converter(path, deadline=min(self.end, deadline, time.monotonic() + 30))
        self._check(deadline)
        record.check()
        if type(windows) is not str:
            _fail()
        wininterop.validate_windows_path(windows)
        windows = windows.replace("\\", "/")
        brace_quote_path(windows)
        projection = ChunkFile(path, windows, expected_size)
        self.active[slot] = {"chunk": projection, "file": record, "issued": False, "verify": False, "hash": None}
        return projection

    def _slot(self, chunk):
        for slot, item in self.active.items():
            if item["chunk"] is chunk:
                return slot, item
        _fail()

    def _finish_chunk(self, item, check):
        record, n = item["file"], item["chunk"].expected_size
        record.check(sealed=record.seal is not None)
        os.fsync(record.fd)
        if record.check().st_size != n:
            _fail("openocd_output_changed")
        if record.seal is None:
            record.freeze()
        return self._hash(record, n, check).hexdigest()

    @_method
    def command(self, operation, chunk, *, address_or_offset):
        self._owner(live=True)
        slot, item = self._slot(chunk)
        expected = (self.spec.address if self.spec.kind == "memory" else self.spec.offset) + self.done
        if type(address_or_offset) is not int or address_or_offset != expected:
            _fail()
        if self.spec.kind == "flash" and not (0 <= expected <= (1 << 32) - 1 and expected + chunk.expected_size <= self.spec.bank_size <= (1 << 32) - 1):
            _fail()
        if operation == "verify_bank":
            if self.spec.kind != "flash" or not self.spec.verify or slot != "primary" or not item["issued"] or item["verify"]:
                _fail()
            item["hash"] = self._finish_chunk(item, self._check)
        elif (operation != ("dump_image" if self.spec.kind == "memory" else "read_bank") or item["issued"]):
            _fail()
        else:
            if item["file"].check().st_size != 0:
                _fail("openocd_output_changed")
        def build(path):
            quoted = brace_quote_path(path)
            if operation == "dump_image":
                return f"dump_image {quoted} 0x{expected:x} 0x{chunk.expected_size:x}"
            if operation == "read_bank":
                return f"flash read_bank {self.spec.bank} {quoted} 0x{expected:x} 0x{chunk.expected_size:x}"
            return f"flash verify_bank {self.spec.bank} {quoted} 0x{expected:x}"
        result = build(chunk.windows_path)
        words = split_list(result)
        path_index = 1 if operation == "dump_image" else 3
        if words[path_index] != chunk.windows_path:
            _fail()
        guard.ensure_job_commands_safe([build(str(chunk.local_path))], allowed_dirs=[self.output.path])
        self._check()
        item["file"].check(sealed=item["file"].seal is not None)
        item["verify" if operation == "verify_bank" else "issued"] = True
        return result

    @_method
    def accept_chunk(self, primary, second=None, *, deadline, cancel):
        self._owner(live=True)
        check = lambda: self._check(deadline, cancel)
        slot, first = self._slot(primary)
        expected_slots = {"primary", "second"} if self.spec.kind == "memory" and self.spec.verify else {"primary"}
        if slot != "primary" or set(self.active) != expected_slots or not first["issued"]:
            _fail()
        digest = self._finish_chunk(first, check)
        if self.spec.kind == "memory" and self.spec.verify:
            slot2, other = self._slot(second)
            if slot2 != "second" or not other["issued"] or self._finish_chunk(other, check) != digest:
                _fail("openocd_output_changed")
        elif second is not None:
            _fail()
        if self.spec.kind == "flash" and self.spec.verify and (not first["verify"] or first["hash"] != digest):
            _fail("openocd_output_changed")
        self.part.check(sealed=True)
        rolling = self.digest.copy()
        for off in range(0, primary.expected_size, CHUNK):
            check()
            data = os.pread(first["file"].fd, min(CHUNK, primary.expected_size - off), off)
            if len(data) != min(CHUNK, primary.expected_size - off):
                _fail("openocd_output_changed")
            if self.spec.kind == "memory" and self.spec.verify:
                if os.pread(other["file"].fd, len(data), off) != data:
                    _fail("openocd_output_changed")
            self._write(self.part, data, self.done + off, check)
            rolling.update(data)
        for item in self.active.values():
            item["file"].check(sealed=True)
        os.fsync(self.part.fd)
        self.part.freeze()
        done = self.done + primary.expected_size
        self._checkpoint(done, rolling.hexdigest(), check)
        self._done, self.digest = done, rolling
        self._chunks += 1
        for item in self.active.values():
            self._remove(item["file"])
        self.active.clear()
        check()

    def _source(self):
        s = self.spec
        if s.kind == "memory":
            return {"type": "memory", "address": s.address, "length": s.length}
        return {"type": "flash", "bank": s.bank, "offset": s.offset, "length": s.length, "bank_size": s.bank_size}

    @_method
    def publish(self, *, owner_confirmed, deadline, cancel, on_commit=None):
        self._owner(confirmed=True)
        if owner_confirmed is not True or self.done != self.spec.length or self.active or (on_commit is not None and not callable(on_commit)):
            _fail("openocd_output_cleanup_unknown")
        check = lambda: self._check(deadline, cancel)
        sha = self._hash(self.part, self.done, check).hexdigest()
        if sha != self.digest.hexdigest():
            _fail("openocd_output_changed")
        self.final = self._new(self.destination, self.spec.output_name + ".bin")
        copied = hashlib.sha256()
        for off in range(0, self.done, CHUNK):
            check()
            data = os.pread(self.part.fd, min(CHUNK, self.done - off), off)
            if len(data) != min(CHUNK, self.done - off):
                _fail("openocd_output_changed")
            self._write(self.final, data, off, check)
            copied.update(data)
        self.part.check(sealed=True)
        if copied.hexdigest() != sha:
            _fail("openocd_output_changed")
        path = str((self.destination.path / self.final.name).relative_to(self.spec.case.dir))
        transfer = "dump_image" if self.spec.kind == "memory" else "flash_read_bank"
        metadata = {"schema": "pweh.openocd-pipe-dump/v1", "source": self._source(), "binding": self.binding,
                    "output": {"path": path, "size": self.done, "sha256": sha},
                    "verification": {"double_read": self.spec.kind == "memory" and self.spec.verify,
                                     "flash_verify": self.spec.kind == "flash" and self.spec.verify}, "chunks": self.chunks}
        self.meta = self._new(self.destination, self.spec.output_name + ".json")
        metadata_path = str((self.destination.path / self.meta.name).relative_to(self.spec.case.dir))
        self._write(self.meta, _json(metadata), 0, check)
        for record in (self.final, self.meta):
            os.fchmod(record.fd, 0o444)
            os.fsync(record.fd)
            record.initial = os.fstat(record.fd)
            record.freeze()
        warnings = []
        def final_check(entry):
            check()
            self._owner(confirmed=True)
            if (entry.get("path") != path or entry.get("sha256") != sha or type(entry.get("size")) is not int
                    or entry["size"] != self.done or entry.get("is_dir") is not False):
                _fail("openocd_output_changed")
            for record in (self.part, self.state, self.final, self.meta):
                record.check(sealed=True)
            for record in (self.part, self.final):
                if self._hash(record, self.done, check).hexdigest() != sha:
                    _fail("openocd_output_changed")
            # 뒤 파일 해시 중 앞 파일이 바뀐 경우도 마지막에 모두 대조한다.
            for record in (self.part, self.state, self.final, self.meta):
                record.check(sealed=True)
            check()
        def committed(entry):
            self.receipt = copy.deepcopy(entry)
            if on_commit is not None:
                on_commit(copy.deepcopy(entry))
        try:
            self.spec.case.register_artifact(path, kind="memory-dump" if self.spec.kind == "memory" else "flash-dump",
                producer="pweh-openocd", compute_hash=False, sha256=sha, replace_existing=False,
                check=final_check, on_commit=committed, deadline=min(self.end, deadline))
        except Exception:
            if self.receipt is None:
                raise
            warnings.append("post_commit_callback_failed")
        # 커밋 뒤 취소는 다시 적용하지 않고 영수증을 먼저 보존한다.
        try:
            _tick(min(self.end, deadline))
            for record in (self.part, self.state):
                self._remove(record)
            for record in (self.final, self.meta):
                record.check(sealed=True)
                self._close_file(record)
        except Exception:
            warnings.append("output_close_unconfirmed")
        return {"path": path, "metadata_path": metadata_path,
                "size": self.done, "sha256": sha, "artifact": copy.deepcopy(self.receipt), "source": self._source(),
                "transfer": transfer, "chunks": self.chunks, "resumed_from": self.resumed_from, "warnings": warnings}


def _exists(fd, name):
    try:
        os.stat(name, dir_fd=fd, follow_symlinks=False)
        return True
    except FileNotFoundError:
        return False


def prepare_output(owner, spec, *, deadline, cancel):
    """실제 owner와 출력 목적지를 예약한 뒤 같은 FD checkpoint를 준비한다."""
    output = None
    try:
        end = _end(deadline)
        _tick(end, cancel)
        _spec(spec)
        with W._LOCK:
            if type(owner) is not W.WindowsOpenOcdOwner or W._OWNED.get(owner.token) is not owner:
                _fail()
        output = PipeOutput(owner, spec, end, cancel)
        destination = spec.case.dir / ("jtag" if spec.kind == "memory" else "dumps")
        with _LOCK:
            if owner.token in _OUTPUTS or any(o.spec.case.dir == spec.case.dir and o.spec.kind == spec.kind
                    and o.spec.output_name == spec.output_name for o in _OUTPUTS.values()):
                _fail()
            _OUTPUTS[owner.token] = output
        output._owner(live=True)
        check = output._check
        output.cwd = _Dir(owner.plan.layout.cwd, check)
        if (output.cwd.chain[-1][3].st_dev, output.cwd.chain[-1][3].st_ino) != (owner._run.children["cwd"].st_dev, owner._run.children["cwd"].st_ino):
            _fail("openocd_output_changed")
        run_st = output.cwd.chain[-2][3]
        if (run_st.st_dev, run_st.st_ino, run_st.st_mode) != (owner._run.root_stat.st_dev, owner._run.root_stat.st_ino, owner._run.root_stat.st_mode):
            _fail("openocd_output_changed")
        os.mkdir(output.output_name, 0o700, dir_fd=output.cwd.fd)
        output.output_stat = os.stat(output.output_name, dir_fd=output.cwd.fd, follow_symlinks=False)
        output.output = _Dir(output.cwd.path / output.output_name, check)
        output.destination = _Dir(destination, check)
        names = [spec.output_name + s for s in (".part", ".state.json", ".bin", ".json")]
        present = [_exists(output.destination.fd, n) for n in names]
        if any(present[2:]) or (not spec.resume and any(present)) or present[0] != present[1]:
            _fail("openocd_output_resume_invalid")
        if present[0]:
            output.part = output._existing(output.destination, names[0])
            output.state = output._existing(output.destination, names[1])
            if not 0 < output.state.initial.st_size <= CHUNK:
                _fail("openocd_output_resume_invalid")
            state = _parse(os.pread(output.state.fd, CHUNK, 0))
            done = state.get("done") if type(state) is dict else None
            digest = state.get("prefix_sha256") if type(state) is dict else None
            if (not _uint(done, 0, spec.length) or (done != spec.length and done % spec.chunk_size != 0)
                    or not done <= output.part.initial.st_size <= spec.length
                    or type(digest) is not str or len(digest) != 64
                    or _json(state) != _json(output._state_value(done, digest))):
                _fail("openocd_output_resume_invalid")
            output.digest = output._hash(output.part, done, check)
            if output.digest.hexdigest() != digest:
                _fail("openocd_output_resume_invalid")
            output.state.check(sealed=True)
            os.ftruncate(output.part.fd, done)
            os.fsync(output.part.fd)
            output.part.freeze()
            output._done = output._resumed = done
        else:
            output.part = output._new(output.destination, names[0])
            output.part.freeze()
            output._checkpoint(0, output.digest.hexdigest(), check)
        check()
        return output
    except PipeOutputError as exc:
        if output is not None:
            output.failed = True
        raise PipeOutputError(exc.code, output) from None
    except Exception:
        if output is not None:
            output.failed = True
        _fail("openocd_output_resume_invalid", output)


def release_outputs(owner, *, deadline):
    """사용권0을 확인한 session만 호출한다. 게시/재개 없이 자기 inode만 정리한다."""
    with _LOCK:
        output = _OUTPUTS.get(getattr(owner, "token", None))
    if output is None:
        return True
    if output.owner is not owner:
        return False
    try:
        end = _end(deadline)
        if not output.lock.acquire(timeout=max(0, end - time.monotonic())):
            return False
        try:
            output._owner(confirmed=True)
            _tick(end)
            for directory in (output.cwd, output.output, output.destination):
                if directory is not None:
                    directory.check()
            if output.output is not None:
                expected = {f.name for f in output.files if f.parent is output.output and not f.removed}
                _names(output.output.fd, expected, lambda: _tick(end))
            for record in tuple(output.files):
                _tick(end)
                # 미commit checkpoint는 재개를 위해 보존하고 나머지 자기 출력만 정리한다.
                preserve = record in (output.part, output.state) if output.receipt is None else record in (output.final, output.meta)
                if record.removed:
                    output._close_file(record)
                elif preserve:
                    if record.fd is not None:
                        record.check(sealed=record.seal is not None)
                        output._close_file(record)
                else:
                    output._remove(record)
            if output.output is not None:
                _names(output.output.fd, set(), lambda: _tick(end))
                output.output.check()
                if not output.output.close():
                    return False
                output.output = None
            if output.cwd is not None and output.output_stat is not None:
                current = os.stat(output.output_name, dir_fd=output.cwd.fd, follow_symlinks=False)
                if (current.st_dev, current.st_ino, current.st_mode) != (output.output_stat.st_dev, output.output_stat.st_ino, output.output_stat.st_mode):
                    return False
                os.rmdir(output.output_name, dir_fd=output.cwd.fd)
                output.output_stat = None
            for attr in ("destination", "cwd"):
                directory = getattr(output, attr)
                if directory is not None:
                    if not directory.close():
                        return False
                    setattr(output, attr, None)
            with _LOCK:
                if _OUTPUTS.get(owner.token) is output:
                    del _OUTPUTS[owner.token]
            return True
        finally:
            output.lock.release()
    except Exception:
        return False
