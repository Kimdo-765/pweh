"""등록 strict RAW를 OOK 두 파일로 변환하고 manifest만 원자 등록한다."""
from __future__ import annotations

import hashlib
import json
import math
import os
import re
import stat
import time
from pathlib import Path

from pweh import rf_ook, safeio, schemas
from pweh.errors import PwehError
from pweh.evidence import under_any_case_protected

MAX_INPUT_BYTES = 1 << 20
MAX_OUTPUT_BYTES = 64 << 10
CHUNK = 64 << 10
FINAL_SECONDS = 5.0
_CODES = frozenset({'rf_ook_input_invalid', 'rf_ook_input_limit', 'rf_ook_input_changed',
    'rf_ook_not_convertible', 'rf_ook_failed', 'rf_ook_cleanup_incomplete', 'cancelled', 'time_limit'})


def _error(code):
    return PwehError('등록 RAW의 로컬 OOK 변환을 완료하지 못했습니다.', code=code)


def _tick(deadline: float, cancel) -> None:
    if cancel is not None:
        try:
            stopped = cancel()
        except Exception:
            raise _error("rf_ook_failed") from None
        if type(stopped) is not bool:
            raise _error("rf_ook_failed")
        if stopped:
            raise _error("cancelled")
    if time.monotonic() >= deadline:
        raise _error("time_limit")


def _projection(case, artifact_id: str) -> dict:
    rows = case.load().get("artifacts", [])
    if type(rows) is not list:
        raise _error("rf_ook_input_invalid")
    matches = [row for row in rows if type(row) is dict and row.get("id") == artifact_id]
    if len(matches) != 1:
        raise _error("rf_ook_input_invalid")
    row = matches[0]
    projected = {key: row.get(key) for key in ("id", "path", "is_dir", "size", "sha256")}
    size, path, digest = projected["size"], projected["path"], projected["sha256"]
    if projected["is_dir"] is not False or type(size) is not int or size < 1:
        raise _error("rf_ook_input_invalid")
    if size > MAX_INPUT_BYTES:
        raise _error("rf_ook_input_limit")
    if type(digest) is not str or re.fullmatch(r"[0-9a-f]{64}", digest) is None:
        raise _error("rf_ook_input_invalid")
    if type(path) is not str or not path or len(os.fsencode(path)) > safeio.PATH_MAX_BYTES:
        raise _error("rf_ook_input_invalid")
    if sum(type(item) is dict and item.get("path") == path for item in rows) != 1:
        raise _error("rf_ook_input_invalid")
    parts = path.split("/")
    if (len(parts) > safeio.PATH_MAX_STEPS or any(p in ("", ".", "..") or "\x00" in p for p in parts)
            or parts[0] in ("forensics", "emu")):
        raise _error("rf_ook_input_invalid")
    return projected


def _file_seal(value) -> tuple:
    return (value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns,
            value.st_ctime_ns, value.st_mode, value.st_nlink)


def _dir_seal(value) -> tuple:
    return value.st_dev, value.st_ino, value.st_mode, value.st_uid


class _Directories:
    """기준 root와 각 하위 부모를 고정한다. 하위 링크를 따라가지 않는다."""

    def __init__(self, case, deadline: float, cancel):
        self.case = case
        self.fds = []
        self.edges = []
        _tick(deadline, cancel)
        fd = safeio._walk_directory(str(case.dir), deadline=deadline)
        self.fds.append(fd)
        try:
            self.root = fd
            self.root_seal = _dir_seal(os.fstat(fd))
            self.check(deadline, cancel)
        except Exception:
            if not self.close():
                raise _error("rf_ook_cleanup_incomplete") from None
            raise

    def descend(self, parts: list[str], deadline: float, cancel) -> int:
        fd = self.root
        for name in parts:
            _tick(deadline, cancel)
            before = os.stat(name, dir_fd=fd, follow_symlinks=False)
            if not stat.S_ISDIR(before.st_mode):
                raise _error("rf_ook_input_invalid")
            child = os.open(name, safeio.DIR_FLAGS, dir_fd=fd)
            self.fds.append(child)
            after = os.fstat(child)
            if _dir_seal(before) != _dir_seal(after):
                raise _error("rf_ook_input_changed")
            self.edges.append((fd, name, child, _dir_seal(after)))
            fd = child
        self.check(deadline, cancel)
        return fd

    def check(self, deadline: float, cancel) -> None:
        _tick(deadline, cancel)
        current = os.stat(self.case.dir, follow_symlinks=False)
        if (not stat.S_ISDIR(current.st_mode) or _dir_seal(current) != self.root_seal
                or _dir_seal(os.fstat(self.root)) != self.root_seal):
            raise _error("rf_ook_input_changed")
        for parent, name, child, seal in self.edges:
            _tick(deadline, cancel)
            named = os.stat(name, dir_fd=parent, follow_symlinks=False)
            if (not stat.S_ISDIR(named.st_mode) or _dir_seal(named) != seal
                    or _dir_seal(os.fstat(child)) != seal):
                raise _error("rf_ook_input_changed")

    def close(self) -> bool:
        ok = True
        for fd in reversed(self.fds):
            try:
                os.close(fd)
            except OSError:
                ok = False
        self.fds.clear()
        return ok


def _check_file(fd: int, parent: int, name: str, seal: tuple) -> None:
    try:
        actual = os.fstat(fd)
        named = os.stat(name, dir_fd=parent, follow_symlinks=False)
    except OSError:
        raise _error("rf_ook_input_changed") from None
    if (not stat.S_ISREG(actual.st_mode) or actual.st_nlink != 1
            or _file_seal(actual) != seal or _file_seal(named) != seal):
        raise _error("rf_ook_input_changed")


def _read_fd(fd: int, size: int, deadline: float, cancel, *, collect: bool = False):
    """처음 확인한 크기만 64KiB 이하 pread로 읽는다. 같은 FD를 다시 선택하지 않는다."""
    digest = hashlib.sha256()
    blocks = []
    offset = 0
    while offset < size:
        _tick(deadline, cancel)
        block = os.pread(fd, min(CHUNK, size - offset), offset)
        if type(block) is not bytes or not 0 < len(block) <= min(CHUNK, size - offset):
            raise _error("rf_ook_input_changed")
        digest.update(block)
        if collect:
            blocks.append(block)
        offset += len(block)
    _tick(deadline, cancel)
    return digest.hexdigest(), b"".join(blocks) if collect else None


class _Output:
    """자신이 만든 디렉터리와 두 inode만 소유한다. 불명확한 이름은 보존한다."""

    def __init__(self, directories):
        self.dirs = directories
        self.parent = self.fd = self.name = self.identity = None
        self.files = {}

    def prepare(self, deadline, cancel):
        self.parent = self.dirs.descend(["analysis"], deadline, cancel)
        for number in range(1, 65):
            _tick(deadline, cancel)
            name = f"rf-ook-{number:03d}"
            try:
                os.mkdir(name, 0o700, dir_fd=self.parent)
            except FileExistsError:
                continue
            self.name = name
            self.identity = os.stat(name, dir_fd=self.parent, follow_symlinks=False)
            self.fd = os.open(name, safeio.DIR_FLAGS, dir_fd=self.parent)
            self.check(deadline, cancel)
            return
        raise _error("rf_ook_failed")

    def path(self, name):
        return f"analysis/{self.name}/{name}"

    def check(self, deadline, cancel):
        self.dirs.check(deadline, cancel)
        named = os.stat(self.name, dir_fd=self.parent, follow_symlinks=False)
        if (self.identity is None or not stat.S_ISDIR(named.st_mode)
                or _dir_seal(named) != _dir_seal(self.identity)
                or self.fd is not None and _dir_seal(os.fstat(self.fd)) != _dir_seal(self.identity)):
            raise _error("rf_ook_input_changed")
        if self.fd is not None:
            names = set()
            with os.scandir(self.fd) as it:
                for item in it:
                    _tick(deadline, cancel)
                    names.add(item.name)
                    if len(names) > 2:
                        raise _error("rf_ook_input_changed")
            if names != set(self.files):
                raise _error("rf_ook_input_changed")

    def write(self, name, data, deadline, cancel):
        self.check(deadline, cancel)
        fd = os.open(name, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                     0o600, dir_fd=self.fd)
        row = self.files[name] = {"fd": fd, "identity": None}
        row["identity"] = os.fstat(fd)
        position = 0
        while position < len(data):
            _tick(deadline, cancel)
            n = os.write(fd, data[position:position + CHUNK])
            if type(n) is not int or not 0 < n <= min(CHUNK, len(data) - position):
                raise _error("rf_ook_failed")
            position += n
        os.fchmod(fd, 0o444)
        os.fsync(fd)
        final = os.fstat(fd)
        if (not safeio.same_file(final, row["identity"]) or final.st_size != len(data)
                or not stat.S_ISREG(final.st_mode) or final.st_nlink != 1 or stat.S_IMODE(final.st_mode) != 0o444):
            raise _error("rf_ook_input_changed")
        row.update(seal=_file_seal(final), size=len(data), sha256=hashlib.sha256(data).hexdigest())
        _check_file(fd, self.fd, name, row["seal"])
        if _read_fd(fd, row["size"], deadline, cancel)[0] != row["sha256"]:
            raise _error("rf_ook_input_changed")
        self.check(deadline, cancel)

    def seals(self, deadline, cancel):
        self.check(deadline, cancel)
        for name, row in self.files.items():
            _check_file(row["fd"], self.fd, name, row["seal"])

    def cleanup(self):
        if self.name is None:
            return True
        try:
            self.check(float("inf"), None)
            for name, row in self.files.items():
                named = os.stat(name, dir_fd=self.fd, follow_symlinks=False)
                if (row["identity"] is None or not stat.S_ISREG(named.st_mode) or named.st_nlink != 1
                        or not safeio.same_file(named, row["identity"])
                        or not safeio.same_file(os.fstat(row["fd"]), row["identity"])):
                    return False
            for name in tuple(self.files):
                os.unlink(name, dir_fd=self.fd)
            # FD 기록은 close가 독립적으로 모두 정리할 때까지 유지한다.
            named = os.stat(self.name, dir_fd=self.parent, follow_symlinks=False)
            if not safeio.same_file(named, self.identity):
                return False
            os.rmdir(self.name, dir_fd=self.parent)
            return True
        except Exception:
            return False

    def close(self):
        ok = True
        for fd in [*(row["fd"] for row in self.files.values()), self.fd]:
            if fd is not None:
                try:
                    os.close(fd)
                except OSError:
                    ok = False
        return ok


def _finite(value):
    try:
        return type(value) in (int, float) and math.isfinite(value)
    except OverflowError:
        return False


def _conversion(value, deadline, cancel):
    """코어의 닫힌 생성물만 독립 대조한다. 임의 OOK 파일 parser가 아니다."""
    if type(value) is not rf_ook.OokConversion:
        raise _error('rf_ook_failed')
    data = value.ook_bytes
    if type(data) is not bytes or not 47 <= len(data) <= 26443:
        raise _error('rf_ook_failed')
    if (type(value.declared_preset) is not str or value.declared_preset not in (
            'FuriHalSubGhzPresetOok270Async', 'FuriHalSubGhzPresetOok650Async')
            or type(value.declared_frequency_hz) is not int or not 0 <= value.declared_frequency_hz <= 0xffffffff
            or type(value.duration_count) is not int or not 2 <= value.duration_count <= 2400
            or type(value.pair_count) is not int or not 1 <= value.pair_count <= 1200
            or value.duration_count != value.pair_count * 2
            or type(value.total_duration_us) is not int
            or not value.duration_count <= value.total_duration_us <= value.duration_count * 2147483647):
        raise _error('rf_ook_failed')
    prefix = b';pulse data\n;version 1\n;timescale 1us\n'
    if not data.startswith(prefix) or not data.endswith(b';end\n'):
        raise _error('rf_ook_failed')
    pairs = data[len(prefix):-5].split(b'\n')
    if pairs[-1] != b'' or len(pairs) != value.pair_count + 1:
        raise _error('rf_ook_failed')
    total = 0
    for line in pairs[:-1]:
        _tick(deadline, cancel)
        if re.fullmatch(rb'[1-9][0-9]{0,9} [1-9][0-9]{0,9}', line) is None:
            raise _error('rf_ook_failed')
        left, right = map(int, line.split(b' '))
        if left > 2147483647 or right > 2147483647:
            raise _error('rf_ook_failed')
        total += left + right
    if total != value.total_duration_us:
        raise _error('rf_ook_failed')
    _tick(deadline, cancel)
    return data


def convert_registered_sub(case, artifact_id, *, max_seconds, deadline, cancel):
    """등록 입력 하나와 자기 출력 두 FD를 인수하고 manifest receipt를 우선 보존한다."""
    directories = output = None
    input_fd = None
    committed = report = None
    failure = None
    warnings = []
    try:
        if (type(artifact_id) is not str or re.fullmatch(r'A-[0-9]{4,8}', artifact_id) is None
                or not _finite(max_seconds) or not 0 < max_seconds <= 5 or not _finite(deadline)
                or cancel is not None and not callable(cancel)):
            raise _error('rf_ook_input_invalid')
        deadline = min(deadline, time.monotonic() + max_seconds)
        _tick(deadline, cancel)
        source = _projection(case, artifact_id)
        directories = _Directories(case, deadline, cancel)
        parts = source['path'].split('/')
        parent = directories.descend(parts[:-1], deadline, cancel)
        input_fd, initial = safeio.open_regular(parts[-1], dir_fd=parent, reject_hardlinks=True)
        input_seal = _file_seal(initial)
        if initial.st_size != source['size']:
            raise _error('rf_ook_input_changed')
        real = safeio.fd_real_path(input_fd)
        if real is None:
            raise _error('rf_ook_input_invalid')
        try:
            relative = Path(real).relative_to(case.dir)
        except ValueError:
            raise _error('rf_ook_input_invalid') from None
        if (not relative.parts or relative.parts[0] in ('forensics', 'emu')
                or under_any_case_protected(real, case.dir.parent) is not None):
            raise _error('rf_ook_input_invalid')
        directories.check(deadline, cancel)
        _check_file(input_fd, parent, parts[-1], input_seal)
        actual_hash, data = _read_fd(input_fd, source['size'], deadline, cancel, collect=True)
        if actual_hash != source['sha256']:
            raise _error('rf_ook_input_changed')
        directories.check(deadline, cancel)
        _check_file(input_fd, parent, parts[-1], input_seal)
        converted = rf_ook.convert_sub_raw_to_ook(data, deadline=deadline, cancel=cancel)
        ook_bytes = _conversion(converted, deadline, cancel)
        output = _Output(directories)
        output.prepare(deadline, cancel)
        generated = {'path': output.path('converted.ook'), 'size': len(ook_bytes),
                     'sha256': hashlib.sha256(ook_bytes).hexdigest()}
        report = {'schema': rf_ook.SCHEMA, 'profile': rf_ook.PROFILE, 'status': 'complete',
            'source': {'kind': 'case-artifact', 'artifact_id': artifact_id, 'size': len(data), 'sha256': actual_hash},
            'params': {'source_profile': rf_ook.SOURCE_PROFILE, 'max_seconds': max_seconds},
            'metadata': {'declared_preset': converted.declared_preset,
                         'declared_frequency_hz': converted.declared_frequency_hz},
            'conversion': {'format': rf_ook.FORMAT, 'unit': 'us', 'pairing': 'positive-negative',
                'duration_count': converted.duration_count, 'pair_count': converted.pair_count,
                'total_duration_us': converted.total_duration_us},
            'output': generated, **{key: False for key in rf_ook.FALSE_FIELDS},
            'limitations': list(rf_ook.LIMITATIONS)}
        # 스키마/회계 callback이 객체를 바꿔도 실제 선택·생성물의 결속을 유지한다.
        expected = json.dumps(report, sort_keys=True, ensure_ascii=True, separators=(',', ':'), allow_nan=False)
        schemas.validate('rf-ook-conversion', report)
        rf_ook.validate_ook_accounting(report)
        if json.dumps(report, sort_keys=True, ensure_ascii=True, separators=(',', ':'), allow_nan=False) != expected:
            raise _error('rf_ook_failed')
        encoded = (expected + '\n').encode('ascii')
        if len(encoded) > MAX_OUTPUT_BYTES:
            raise _error('rf_ook_input_limit')
        output.write('converted.ook', ook_bytes, deadline, cancel)
        output.write('manifest.json', encoded, deadline, cancel)
        output.seals(deadline, cancel)
        directories.check(deadline, cancel)
        _check_file(input_fd, parent, parts[-1], input_seal)
        _tick(deadline, cancel)
        final_end = time.monotonic() + FINAL_SECONDS
        manifest = output.files['manifest.json']
        manifest_path = output.path('manifest.json')

        def check(entry):
            directories.check(final_end, cancel)
            if _projection(case, artifact_id) != source:
                raise _error('rf_ook_input_changed')
            _check_file(input_fd, parent, parts[-1], input_seal)
            if _read_fd(input_fd, source['size'], final_end, cancel)[0] != actual_hash:
                raise _error('rf_ook_input_changed')
            _check_file(input_fd, parent, parts[-1], input_seal)
            output.seals(final_end, cancel)
            for row in output.files.values():
                if _read_fd(row['fd'], row['size'], final_end, cancel)[0] != row['sha256']:
                    raise _error('rf_ook_input_changed')
            directories.check(final_end, cancel)
            _check_file(input_fd, parent, parts[-1], input_seal)
            output.seals(final_end, cancel)
            if (type(entry) is not dict or any(type(entry.get(key)) is not type(value) or entry.get(key) != value
                    for key, value in (('path', manifest_path), ('size', manifest['size']),
                                      ('sha256', manifest['sha256']), ('is_dir', False)))):
                raise _error('rf_ook_input_changed')
            _tick(final_end, cancel)

        def on_commit(entry):
            nonlocal committed
            # 실제 metadata 게시 뒤 첫 동작. 이후 취소·감사 오류로 두 파일을 삭제하지 않는다.
            committed = dict(entry)

        case.register_artifact(manifest_path, kind='other', producer='pweh-sdr',
            extra={'type': 'rf-ook-conversion'}, sha256=manifest['sha256'], check=check,
            on_commit=on_commit, deadline=final_end, replace_existing=False)
        if committed is None:
            raise _error('rf_ook_failed')
    except Exception as exc:
        if committed is not None:
            warnings.append('post_commit_callback_failed')
        else:
            code = getattr(exc, 'code', 'rf_ook_failed')
            if type(code) is not str:
                code = 'rf_ook_failed'
            if code in ('lock_timeout', 'artifact_timeout'):
                code = 'time_limit'
            elif isinstance(exc, (safeio.UnsafeFile, FileNotFoundError)):
                code = 'rf_ook_input_invalid'
            failure = code if code in _CODES else 'rf_ook_failed'
    finally:
        if committed is None and output is not None and not output.cleanup():
            failure = 'rf_ook_cleanup_incomplete'
        closed = output.close() if output is not None else True
        if input_fd is not None:
            try:
                os.close(input_fd)
            except OSError:
                closed = False
        if directories is not None:
            closed = directories.close() and closed
        if not closed:
            if committed is not None:
                warnings.append('output_close_unconfirmed')
            else:
                failure = 'rf_ook_cleanup_incomplete'
    if failure is not None:
        raise _error(failure) from None
    return {'ok': True, 'report': report,
        'analysis': {'path': manifest_path, 'sha256': manifest['sha256'], 'size': manifest['size'],
                     'artifact_id': committed['id']},
        'output': dict(generated), 'warnings': warnings}
