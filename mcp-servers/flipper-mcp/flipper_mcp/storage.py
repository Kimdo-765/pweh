"""Flipper의 고정 read/MD5 결과를 한 FD에 받아 검증한 뒤 케이스에 등록한다."""
from __future__ import annotations

import hashlib
import os
import stat
import time

from pweh import safeio, flipper_cli as F
from pweh.jobs import JobCancelled
from .session import error, public_error, PULL_SECONDS

CHUNK = 65536
COMMIT_SECONDS = 5.0
# 닫기 실패 FD는 GC로 소유권을 잃지 않는다. 공개 결과에는 이 내부 객체를 싣지 않는다.
_PENDING_OUTPUTS = []


def _file_seal(st):
    return (st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns, st.st_ctime_ns,
            st.st_mode, st.st_nlink)


def _directory_seal(st):
    return st.st_dev, st.st_ino, st.st_mode, st.st_uid


class _Output:
    def __init__(self, case, name, tick, deadline):
        self.case, self.root, self.parent, self.fd = case, None, None, None
        self.name, self.made, self.root_seal, self.parent_seal = None, None, None, None
        try:
            tick()
            self.root = safeio._walk_directory(str(case.dir), follow_links=False, deadline=deadline)
            self.root_seal = _directory_seal(os.fstat(self.root))
            try:
                os.mkdir('flipper', 0o700, dir_fd=self.root)
            except FileExistsError:
                pass
            self.parent = os.open('flipper', safeio.DIR_FLAGS, dir_fd=self.root)
            self.parent_seal = _directory_seal(os.fstat(self.parent))
            self.check_dirs()
            candidates = (name,) if name is not None else (
                f'flipper-pull-{n:03d}.bin' for n in range(1, 100000))
            for candidate in candidates:
                tick()
                try:
                    self.fd = os.open(candidate, os.O_RDWR | os.O_CREAT | os.O_EXCL |
                                      os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=self.parent)
                except FileExistsError:
                    if name is not None:
                        raise error('flipper_storage_error') from None
                    continue
                self.name = candidate
                self.made = os.fstat(self.fd)
                break
            if self.fd is None:
                raise error('flipper_limit')
        except Exception:
            cleaned = self.name is None or (self.made is not None and self.rollback())
            if not self.close():
                _PENDING_OUTPUTS.append(self)
                cleaned = False
            if not cleaned:
                raise error('flipper_cleanup_pending') from None
            raise

    @property
    def path(self):
        return 'flipper/' + self.name

    def check_dirs(self):
        root = os.stat(self.case.dir, follow_symlinks=False)
        parent = os.stat('flipper', dir_fd=self.root, follow_symlinks=False)
        if (not stat.S_ISDIR(root.st_mode) or not stat.S_ISDIR(parent.st_mode)
                or _directory_seal(root) != self.root_seal
                or _directory_seal(os.fstat(self.root)) != self.root_seal
                or _directory_seal(parent) != self.parent_seal
                or _directory_seal(os.fstat(self.parent)) != self.parent_seal):
            raise error('flipper_storage_error')

    def check(self, size, seal=None):
        self.check_dirs()
        current = os.fstat(self.fd)
        named = os.stat(self.name, dir_fd=self.parent, follow_symlinks=False)
        if (not stat.S_ISREG(current.st_mode) or current.st_nlink != 1
                or not safeio.same_file(current, self.made) or current.st_size != size
                or _file_seal(named) != _file_seal(current)
                or (seal is not None and (_file_seal(current) != seal or current.st_mode & 0o222))):
            raise error('flipper_storage_error')

    def rollback(self):
        if self.name is None:
            return True
        try:
            self.check_dirs()
            named = os.stat(self.name, dir_fd=self.parent, follow_symlinks=False)
            actual = os.fstat(self.fd)
            if (not safeio.same_file(named, self.made) or not safeio.same_file(actual, self.made)
                    or named.st_nlink != 1 or actual.st_nlink != 1):
                return False
            os.unlink(self.name, dir_fd=self.parent)
            return True
        except FileNotFoundError:
            return False
        except Exception:
            return False

    def close(self):
        ok = True
        for attr in ('fd', 'parent', 'root'):
            fd = getattr(self, attr)
            if fd is not None:
                try:
                    os.close(fd)
                    setattr(self, attr, None)
                except OSError:
                    ok = False
        return ok


def _hash_output(output, size, tick):
    sha, md5 = hashlib.sha256(), hashlib.md5()
    pos = 0
    while pos < size:
        tick()
        block = os.pread(output.fd, min(CHUNK, size - pos), pos)
        if not block:
            raise error('flipper_storage_error')
        sha.update(block)
        md5.update(block)
        pos += len(block)
    tick()
    return sha.hexdigest(), md5.hexdigest()


def pull(use, case, path, dest_name, jctx):
    """caller가 use를 claim/finish한다. 이 worker만 출력 FD와 등록 receipt를 소유한다."""
    path = F.remote_path(case.id, path, file=True)
    if dest_name is not None:
        dest_name = F.destination_name(dest_name)
    owner = use.session
    deadline = time.monotonic() + PULL_SECONDS
    use._job_cancel = lambda: jctx.cancelled
    output, committed, problem = None, None, None
    received, stage, warnings = 0, 'prepare', []
    sha, md5 = hashlib.sha256(), hashlib.md5()
    transfer = None

    def tick():
        jctx.check_cancelled()
        use.check(deadline)

    def sink(block):
        nonlocal received
        tick()
        if type(block) is not bytes or received + len(block) > F.MAX_FILE_BYTES:
            raise error('flipper_limit')
        output.check(received)
        safeio.write_all(output.fd, block)
        received += len(block)
        sha.update(block)
        md5.update(block)
        tick()

    try:
        tick()
        if case.id != owner.case_id:
            raise error('flipper_invalid_input')
        output = _Output(case, dest_name, tick, deadline)
        stage = 'read'
        result = owner.request(use, 'read', path, sink=sink, deadline=deadline)
        if result != {'declared_size': received, 'received_size': received, 'complete': True}:
            raise error('flipper_protocol_error')
        stage = 'md5'
        remote = owner.request(use, 'md5', path, deadline=deadline)
        if remote != {'md5': md5.hexdigest()}:
            owner.terminal()
            raise error('flipper_checksum_mismatch')
        # 전송 예산과 별도로 한 번만 설정하는 최종 host 검증·등록 예산이다.
        deadline = time.monotonic() + COMMIT_SECONDS
        stage = 'commit'
        tick()
        output.check(received)
        os.fchmod(output.fd, 0o444)
        os.fsync(output.fd)
        seal = _file_seal(os.fstat(output.fd))
        output.check(received, seal)
        hashes = _hash_output(output, received, tick)
        if hashes != (sha.hexdigest(), md5.hexdigest()):
            raise error('flipper_storage_error')
        output.check(received, seal)
        transfer = {'declared_size': received, 'received_size': received, 'complete': True,
                    'md5_match': True, 'device_md5': remote['md5'], 'host_md5': hashes[1],
                    'snapshot_atomic': False, 'device_file_origin_verified': False}

        def check(entry):
            tick()
            output.check(received, seal)
            if (entry.get('path') != output.path or type(entry.get('size')) is not int
                    or entry['size'] != received or entry.get('is_dir') is not False
                    or entry.get('sha256') != hashes[0]):
                raise error('flipper_storage_error')
            if _hash_output(output, received, tick) != hashes:
                raise error('flipper_storage_error')
            output.check(received, seal)
            tick()

        def on_commit(entry):
            nonlocal committed
            committed = {key: entry[key] for key in ('id', 'path', 'size', 'sha256')}
            jctx.mark_committed()

        extra = {'type': 'flipper-storage-copy', 'profile': F.PROFILE,
                 'session_id': owner.session_id, 'device_id': owner.route.device_id,
                 'remote_path': path, 'declared_size': received, 'received_size': received,
                 'device_md5': remote['md5'], 'host_sha256': hashes[0],
                 'snapshot_atomic': False, 'device_file_origin_verified': False}
        case.register_artifact(output.path, kind='other', producer='flipper-mcp', extra=extra,
                               sha256=hashes[0], replace_existing=False, check=check,
                               on_commit=on_commit, deadline=deadline)
        if committed is None:
            raise error('flipper_storage_error')
    except Exception as exc:
        if committed is not None:
            warnings.append('post_commit_callback_or_audit_failed')
        else:
            problem = exc
    finally:
        if output is not None:
            if committed is None and not output.rollback():
                problem = error('flipper_cleanup_pending')
            if not output.close():
                _PENDING_OUTPUTS.append(output)
                if committed is not None:
                    warnings.append('output_close_unconfirmed')
                else:
                    problem = error('flipper_cleanup_pending')
    if committed is not None:
        return {'ok': True, 'case_id': case.id, 'session_id': owner.session_id,
                'profile': F.PROFILE, 'artifact': committed, 'transfer': transfer, 'warnings': warnings}
    jctx.set_partial({'stage': stage, 'received_size': received})
    if isinstance(problem, JobCancelled):
        raise problem from None
    if jctx.cancelled and getattr(problem, 'code', None) != 'flipper_cleanup_pending':
        jctx.check_cancelled()
    raise public_error(problem) from None
