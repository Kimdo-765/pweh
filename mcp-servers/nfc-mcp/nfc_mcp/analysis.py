"""등록 NFC 파일의 scan 결속·출처 증명·같은 FD 저장 경계."""
from __future__ import annotations

import hashlib
import json
import math
import os
import re
import stat
import time
from dataclasses import dataclass
from pathlib import Path

from pweh import nfc_formats, safeio, schemas
from pweh.errors import PwehError
from pweh.evidence import under_any_case_protected
from pweh.provenance import KIND_IMPORTED, PROVENANCE_IMPORT_QUESTIONS, provenance_import_target

MAX_INPUT_BYTES = 1 << 20
MAX_OUTPUT_BYTES = 128 << 10
CHUNK = 64 << 10
FINAL_SECONDS = 5.0
PROFILE = "flipper-ntag21x-inventory-v1"
LEDGER_BYTES = 16 << 20
LEDGER_ENTRIES = 10000
_CODES = frozenset({"nfc_input_invalid", "nfc_input_limit", "nfc_input_changed", "nfc_scan_required",
                    "nfc_scan_invalid", "nfc_family_unsupported", "nfc_identity_mismatch",
                    "nfc_provenance_required", "nfc_provenance_invalid", "nfc_failed",
                    "nfc_cleanup_pending", "cancelled", "time_limit"})


def _error(code: str) -> PwehError:
    return PwehError("NFC 파일 분석을 완료하지 못했습니다.", code=code)


def _fixed(exc: Exception) -> PwehError:
    code = getattr(exc, "code", "nfc_failed")
    if type(code) is not str:
        code = "nfc_failed"
    if code in ("lock_timeout", "artifact_timeout"):
        code = "time_limit"
    elif isinstance(exc, safeio.UnsafeFile):
        code = "nfc_input_invalid"
    elif code in ("provenance_bounded_invalid", "provenance_bounded_limit", "provenance_bounded_changed",
                  "provenance_ledger_broken", "provenance_error"):
        code = "nfc_provenance_invalid"
    return _error(code if code in _CODES else "nfc_failed")


def _tick(deadline: float, cancel) -> None:
    if cancel is not None:
        try:
            stopped = cancel()
        except Exception:
            raise _error("nfc_failed") from None
        if type(stopped) is not bool:
            raise _error("nfc_failed")
        if stopped:
            raise _error("cancelled")
    if time.monotonic() >= deadline:
        raise _error("time_limit")


def _arguments(artifact_ids, tag_ref, deadline, cancel) -> None:
    try:
        finite = type(deadline) in (int, float) and math.isfinite(deadline)
    except OverflowError:
        finite = False
    if (type(artifact_ids) is not tuple or len(artifact_ids) not in (1, 2)
            or any(type(x) is not str or re.fullmatch(r"A-[0-9]{4,8}", x) is None for x in artifact_ids)
            or type(tag_ref) is not str or re.fullmatch(r"NT-[0-9a-f]{32}", tag_ref) is None
            or not finite or cancel is not None and not callable(cancel)):
        raise _error("nfc_input_invalid")


def _projection(case, artifact_id: str) -> dict:
    rows = case.load().get("artifacts", [])
    if type(rows) is not list:
        raise _error("nfc_input_invalid")
    matches = [row for row in rows if type(row) is dict and row.get("id") == artifact_id]
    if len(matches) != 1:
        raise _error("nfc_input_invalid")
    row = matches[0]
    projected = {key: row.get(key) for key in ("id", "path", "is_dir", "size", "sha256")}
    size, path, digest = projected["size"], projected["path"], projected["sha256"]
    if projected["is_dir"] is not False or type(size) is not int or size < 0:
        raise _error("nfc_input_invalid")
    if size > MAX_INPUT_BYTES:
        raise _error("nfc_input_limit")
    if type(digest) is not str or re.fullmatch(r"[0-9a-f]{64}", digest) is None:
        raise _error("nfc_input_invalid")
    if type(path) is not str or not path or len(os.fsencode(path)) > safeio.PATH_MAX_BYTES:
        raise _error("nfc_input_invalid")
    parts = path.split("/")
    if (len(parts) > safeio.PATH_MAX_STEPS or any(p in ("", ".", "..") or "\x00" in p for p in parts)
            or parts[0] in ("forensics", "emu")):
        raise _error("nfc_input_invalid")
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
                raise _error("nfc_cleanup_pending") from None
            raise

    def descend(self, parts: list[str], deadline: float, cancel) -> int:
        fd = self.root
        for name in parts:
            _tick(deadline, cancel)
            before = os.stat(name, dir_fd=fd, follow_symlinks=False)
            if not stat.S_ISDIR(before.st_mode):
                raise _error("nfc_input_invalid")
            child = os.open(name, safeio.DIR_FLAGS, dir_fd=fd)
            self.fds.append(child)
            after = os.fstat(child)
            if _dir_seal(before) != _dir_seal(after):
                raise _error("nfc_input_changed")
            self.edges.append((fd, name, child, _dir_seal(after)))
            fd = child
        self.check(deadline, cancel)
        return fd

    def check(self, deadline: float, cancel) -> None:
        _tick(deadline, cancel)
        current = os.stat(self.case.dir, follow_symlinks=False)
        if (not stat.S_ISDIR(current.st_mode) or _dir_seal(current) != self.root_seal
                or _dir_seal(os.fstat(self.root)) != self.root_seal):
            raise _error("nfc_input_changed")
        for parent, name, child, seal in self.edges:
            _tick(deadline, cancel)
            named = os.stat(name, dir_fd=parent, follow_symlinks=False)
            if (not stat.S_ISDIR(named.st_mode) or _dir_seal(named) != seal
                    or _dir_seal(os.fstat(child)) != seal):
                raise _error("nfc_input_changed")

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
        raise _error("nfc_input_changed") from None
    if (not stat.S_ISREG(actual.st_mode) or actual.st_nlink != 1
            or _file_seal(actual) != seal or _file_seal(named) != seal):
        raise _error("nfc_input_changed")


def _read_fd(fd: int, size: int, deadline: float, cancel, *, collect: bool = False):
    """처음 확인한 크기만 64KiB 이하 pread로 읽는다. 같은 FD를 다시 선택하지 않는다."""
    digest = hashlib.sha256()
    blocks = []
    offset = 0
    while offset < size:
        _tick(deadline, cancel)
        block = os.pread(fd, min(CHUNK, size - offset), offset)
        if not block:
            raise _error("nfc_input_changed")
        digest.update(block)
        if collect:
            blocks.append(block)
        offset += len(block)
    _tick(deadline, cancel)
    return digest.hexdigest(), b"".join(blocks) if collect else None


@dataclass(frozen=True, repr=False)
class Admission:
    """사람 증명을 기다리는 동안 원문·경로·FD를 보유하지 않는 결속."""
    artifacts: tuple[tuple[str, str], ...]
    binding: tuple
    warnings: tuple[str, ...] = ()


def _binding(bound):
    return (bound.tag_ref, bound.scan_ref, bound.scan_seq, bound.scan_entry_sha256,
            bound.inventory_seq, bound.inventory_entry_sha256)


class _Inputs:
    def __init__(self, case, artifact_ids, deadline, cancel):
        self.case, self.rows = case, []
        self.dirs = _Directories(case, deadline, cancel)
        try:
            for aid in artifact_ids:
                row = _projection(case, aid)
                parts = row['path'].split('/')
                parent = self.dirs.descend(parts[:-1], deadline, cancel)
                fd, initial = safeio.open_regular(parts[-1], dir_fd=parent, reject_hardlinks=True)
                item = {'row': row, 'fd': fd, 'parent': parent, 'name': parts[-1],
                        'seal': _file_seal(initial)}
                self.rows.append(item)
                real = safeio.fd_real_path(fd)
                if real is None:
                    raise _error('nfc_input_invalid')
                try:
                    relative = Path(real).relative_to(case.dir)
                except ValueError:
                    raise _error('nfc_input_invalid') from None
                if (not relative.parts or relative.parts[0] in ('forensics', 'emu')
                        or under_any_case_protected(real, case.dir.parent) is not None):
                    raise _error('nfc_input_invalid')
                if initial.st_size != row['size']:
                    raise _error('nfc_input_changed')
                digest, data = _read_fd(fd, row['size'], deadline, cancel, collect=True)
                if digest != row['sha256']:
                    raise _error('nfc_input_changed')
                item['data'] = data
            self.check(deadline, cancel)
        except Exception:
            if not self.close():
                raise _error('nfc_cleanup_pending') from None
            raise

    def check(self, deadline, cancel, *, rehash=False):
        self.dirs.check(deadline, cancel)
        for item in self.rows:
            row = item['row']
            if _projection(self.case, row['id']) != row:
                raise _error('nfc_input_changed')
            _check_file(item['fd'], item['parent'], item['name'], item['seal'])
            if rehash and _read_fd(item['fd'], row['size'], deadline, cancel)[0] != row['sha256']:
                raise _error('nfc_input_changed')
            _check_file(item['fd'], item['parent'], item['name'], item['seal'])
        self.dirs.check(deadline, cancel)

    def identities(self, bound, deadline, cancel):
        from pweh.nfc_inventory import match_file_identity
        for item in self.rows:
            _, identity = nfc_formats._inspect_nfc_bound(item['data'], deadline=deadline, cancel=cancel)
            _tick(deadline, cancel)
            if identity is None:
                raise _error('nfc_identity_mismatch')
            match_file_identity(bound, identity)

    def close(self):
        ok = True
        for item in self.rows:
            try:
                os.close(item['fd'])
            except OSError:
                ok = False
        self.rows.clear()
        return self.dirs.close() and ok


def _entries(runtime, case, deadline, cancel):
    return runtime.provenance.entries(case, max_bytes=LEDGER_BYTES, max_entries=LEDGER_ENTRIES,
                                      deadline=deadline, check=lambda: _tick(deadline, cancel))


def _record(entries, row):
    paths = [e for e in entries if e.get('path') == row['path']]
    rec = next((e for e in reversed(paths) if e.get('kind') in ('device-read', KIND_IMPORTED)), None)
    if rec is None:
        if paths:
            raise _error('nfc_provenance_invalid')
        return None
    if (rec.get('kind') != KIND_IMPORTED or rec.get('sha256') != row['sha256']
            or type(rec.get('size')) is not int or rec['size'] != row['size']):
        raise _error('nfc_provenance_invalid')
    return rec


def _attestation(runtime, case, digest):
    kind, subject, binding = provenance_import_target(case.id, digest)
    value = runtime.attestations.require(kind, subject, binding, questions=list(PROVENANCE_IMPORT_QUESTIONS))
    if value is None:
        raise _error('nfc_provenance_required')
    return value['id']


def prepare_admission(runtime, case, artifact_ids, tag_ref, *, deadline, cancel=None):
    """두 단계 중 입구만 수행한다. 반환 전에 입력 FD를 모두 닫는다."""
    from pweh.nfc_inventory import resolve_inventory
    inputs = None
    failure = None
    result = None
    warnings = []
    try:
        _arguments(artifact_ids, tag_ref, deadline, cancel)
        _tick(deadline, cancel)
        bound = resolve_inventory(runtime, case, tag_ref, deadline=deadline, cancel=cancel)
        inputs = _Inputs(case, artifact_ids, deadline, cancel)
        inputs.identities(bound, deadline, cancel)
        for item in inputs.rows:
            row = item['row']
            rec = _record(_entries(runtime, case, deadline, cancel), row)
            if rec is None:
                def check_entries(entries):
                    if _record(entries, row) is not None:
                        raise _error('nfc_input_changed')
                    inputs.check(deadline, cancel, rehash=True)
                receipt = runtime.provenance.record_import(
                    case, row['path'], {'server': 'nfc-mcp', 'tool': 'nfc-file-admission'},
                    sha256=row['sha256'], max_bytes=LEDGER_BYTES, max_entries=LEDGER_ENTRIES,
                    deadline=deadline, check=lambda: inputs.check(deadline, cancel), check_entries=check_entries)
                if "provenance_close_unconfirmed" in getattr(receipt, "warnings", ()):
                    warnings.append("provenance_close_unconfirmed")
        inputs.check(deadline, cancel, rehash=True)
        result = Admission(tuple((i['row']['id'], i['row']['sha256']) for i in inputs.rows),
                           _binding(bound), tuple(dict.fromkeys(warnings)))
    except Exception as exc:
        failure = _fixed(exc)
    finally:
        if inputs is not None and not inputs.close():
            failure = _error('nfc_cleanup_pending')
    if failure:
        raise failure from None
    return result


def _validate_relations(report, sizes):
    """JSON Schema가 구분하지 않는 exact 정수와 입력/집계 등식을 확인한다."""
    def require(ok):
        if not ok:
            raise _error('nfc_failed')
    def integers(value):
        if type(value) is dict:
            for v in value.values():
                integers(v)
        elif type(value) is list:
            for v in value:
                integers(v)
        elif type(value) is float:
            raise _error('nfc_failed')
    inspection = report['inspection']
    integers(inspection)
    require(report['operation'] == inspection['operation'] and report['status'] == inspection['status'])
    cov = inspection['coverage']
    require(cov['input_bytes'] == sum(sizes))
    require(cov['consumed_bytes'] + cov['unexamined_bytes'] == cov['input_bytes'])
    if inspection['operation'] == 'diff':
        summary = inspection['summary']
        for key, size in zip(('before', 'after'), sizes):
            c = summary[key]['coverage']
            require(c['input_bytes'] == size and c['consumed_bytes'] + c['unexamined_bytes'] == size)
        require(summary['changes_returned'] == len(summary['changes']))
        changed, omitted = summary['changed_pages_count'], summary['changes_omitted']
        if changed is not None:
            require(omitted is not None and changed == summary['changes_returned'] + omitted)
        else:
            require(omitted is None and summary['changes_returned'] == 0)
        require(summary['pages_compared'] <= min(summary['before']['summary']['stored_valid_pages'],
                                                summary['after']['summary']['stored_valid_pages']))


def analyze_files(runtime, case, artifact_ids, tag_ref, admission, *, max_seconds=5, cancel=None):
    """증명 후 새 FD로 재선택하고 현재 증명·출처·같은 FD를 commit까지 확인한다."""
    from pweh.nfc_inventory import resolve_inventory
    inputs = None
    output_fd = output_parent = output_name = output_identity = None
    committed = None
    failure = None
    warnings = []
    report = None
    output_path = output_hash = output_size = None
    try:
        if type(max_seconds) not in (int, float) or not 0 < max_seconds <= 5 or type(admission) is not Admission:
            raise _error('nfc_input_invalid')
        if admission.warnings not in ((), ('provenance_close_unconfirmed',)):
            raise _error('nfc_input_invalid')
        warnings.extend(admission.warnings)
        deadline = time.monotonic() + max_seconds
        _arguments(artifact_ids, tag_ref, deadline, cancel)
        _tick(deadline, cancel)
        bound = resolve_inventory(runtime, case, tag_ref, deadline=deadline, cancel=cancel)
        if _binding(bound) != admission.binding:
            raise _error('nfc_input_changed')
        inputs = _Inputs(case, artifact_ids, deadline, cancel)
        if tuple((i['row']['id'], i['row']['sha256']) for i in inputs.rows) != admission.artifacts:
            raise _error('nfc_input_changed')
        inputs.identities(bound, deadline, cancel)
        entries = _entries(runtime, case, deadline, cancel)
        files = []
        for item in inputs.rows:
            row = item['row']
            rec = _record(entries, row)
            if rec is None:
                raise _error('nfc_provenance_invalid')
            files.append({'artifact_id': row['id'], 'size': row['size'], 'sha256': row['sha256'],
                          'provenance_kind': KIND_IMPORTED, 'ledger_seq': rec['seq'],
                          'attestation_id': _attestation(runtime, case, row['sha256'])})
        datas = [i['data'] for i in inputs.rows]
        inspection = (nfc_formats.inspect_nfc(datas[0], deadline=deadline, cancel=cancel) if len(datas) == 1
                      else nfc_formats.diff_nfc(*datas, deadline=deadline, cancel=cancel))
        final_end = time.monotonic() + FINAL_SECONDS
        report = {'schema': 'pweh.nfc-file-analysis/v1', 'operation': inspection['operation'],
                  'status': inspection['status'], 'source': {'kind': 'case-artifact', 'tag_ref': tag_ref,
                  'scan_ref': bound.scan_ref, 'scan_entry_sha256': bound.scan_entry_sha256,
                  'inventory_entry_sha256': bound.inventory_entry_sha256, 'files': files},
                  'params': {'profile': PROFILE, 'max_seconds': max_seconds}, 'inspection': inspection,
                  'inventory_binding_verified': True, 'physical_same_tag_verified': False}
        schemas.validate('nfc-file-analysis', report)
        _validate_relations(report, [len(d) for d in datas])
        encoded = json.dumps(report, ensure_ascii=True, separators=(',', ':'), allow_nan=False).encode('ascii')
        if len(encoded) > MAX_OUTPUT_BYTES:
            raise _error('nfc_failed')
        output_size, output_hash = len(encoded), hashlib.sha256(encoded).hexdigest()
        output_parent = inputs.dirs.descend(['analysis'], final_end, cancel)
        prefix = 'nfc-file' if len(datas) == 1 else 'nfc-diff'
        for seq in range(1, 10001):
            _tick(final_end, cancel)
            name = f'{prefix}-{seq:03d}.json'
            try:
                fd = os.open(name, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                             0o600, dir_fd=output_parent)
            except FileExistsError:
                continue
            output_fd, output_name = fd, name
            output_identity = os.fstat(fd)
            output_path = 'analysis/' + name
            break
        if output_fd is None:
            raise _error('nfc_failed')
        pos = 0
        while pos < len(encoded):
            _tick(final_end, cancel)
            n = os.write(output_fd, encoded[pos:pos + CHUNK])
            if n <= 0:
                raise _error('nfc_failed')
            pos += n
        os.fchmod(output_fd, 0o444)
        os.fsync(output_fd)
        output_seal = _file_seal(os.fstat(output_fd))

        def check(entry):
            inputs.check(final_end, cancel, rehash=True)
            current = resolve_inventory(runtime, case, tag_ref, deadline=final_end, cancel=cancel)
            if _binding(current) != admission.binding:
                raise _error('nfc_input_changed')
            current_entries = _entries(runtime, case, final_end, cancel)
            for item, src in zip(inputs.rows, files):
                rec = _record(current_entries, item['row'])
                if rec is None or rec['seq'] != src['ledger_seq']:
                    raise _error('nfc_provenance_invalid')
                if _attestation(runtime, case, src['sha256']) != src['attestation_id']:
                    raise _error('nfc_provenance_invalid')
            _check_file(output_fd, output_parent, output_name, output_seal)
            if _read_fd(output_fd, output_size, final_end, cancel)[0] != output_hash:
                raise _error('nfc_input_changed')
            if any(type(entry.get(k)) is not type(v) or entry.get(k) != v for k, v in
                   (('path', output_path), ('size', output_size), ('sha256', output_hash), ('is_dir', False))):
                raise _error('nfc_input_changed')
            inputs.check(final_end, cancel)
            _check_file(output_fd, output_parent, output_name, output_seal)

        def on_commit(entry):
            nonlocal committed
            committed = dict(entry)

        case.register_artifact(output_path, kind='other', producer='pweh-nfc', extra={'type': 'nfc-file-analysis'},
                               sha256=output_hash, check=check, on_commit=on_commit, deadline=final_end,
                               replace_existing=False)
        if committed is None:
            raise _error('nfc_failed')
    except Exception as exc:
        if committed is not None:
            warnings.append('post_commit_callback_failed')
        else:
            failure = _fixed(exc)
    finally:
        if committed is None and output_fd is not None:
            try:
                inputs.dirs.check(float('inf'), None)
                named = os.stat(output_name, dir_fd=output_parent, follow_symlinks=False)
                if not safeio.same_file(named, output_identity) or not safeio.same_file(os.fstat(output_fd), output_identity):
                    raise _error('nfc_cleanup_pending')
                os.unlink(output_name, dir_fd=output_parent)
            except Exception:
                failure = _error('nfc_cleanup_pending')
        close_ok = True
        if output_fd is not None:
            try:
                os.close(output_fd)
            except OSError:
                close_ok = False
        if inputs is not None:
            close_ok = inputs.close() and close_ok
        if not close_ok:
            if committed is not None:
                warnings.append('output_close_unconfirmed')
            else:
                failure = _error('nfc_cleanup_pending')
    if failure is not None:
        raise failure from None
    return {'ok': True, 'report': report,
            'analysis': {'path': output_path, 'sha256': output_hash, 'size': output_size,
                         'artifact_id': committed['id']}, 'warnings': warnings}
