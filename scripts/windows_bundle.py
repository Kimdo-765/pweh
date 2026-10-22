"""등록된 Windows 번들을 로컬 payload에서만 복사·정적 검증한다.

다운로드·압축 해제·Windows 실행·환경 파일 갱신은 없다. 게시한 릴리스는
덮어쓰지 않으며, 실패 정리는 이번 호출이 만든 inode에 한정한다.
"""
from __future__ import annotations

import argparse
from contextlib import contextmanager
import ctypes
import errno
import fcntl
import hashlib
import json
import math
import os
from pathlib import Path
import secrets
import stat
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from pweh import safeio
from pweh import windows_bundle as B
from pweh.errors import PwehError

MAX_SECONDS = 120
CHUNK = 65536
_MESSAGES = {
    "bundle_invalid_argument": "번들 설치 인자가 허용 범위가 아닙니다.",
    "bundle_registry_invalid": "등록된 번들 자료를 확인하지 못했습니다.",
    "bundle_release_unregistered": "등록된 번들 릴리스가 아닙니다.",
    "bundle_missing": "검증할 설치본 또는 명시한 소스가 없습니다.",
    "bundle_receipt_invalid": "번들 설치 기록이 유효하지 않습니다.",
    "bundle_tree_invalid": "번들 파일 집합 또는 내용이 등록 자료와 다릅니다.",
    "bundle_changed": "검사 또는 복사 중 번들 신원이 바뀌었습니다.",
    "bundle_limit": "번들 검사 상한을 넘었습니다.",
    "bundle_timeout": "번들 설치의 시간 한도에 닿았습니다.",
    "bundle_io_failed": "번들 파일 작업을 완료하지 못했습니다.",
    "bundle_cancel_failed": "번들 설치의 취소 상태를 확인하지 못했습니다.",
    "cancelled": "번들 설치가 취소되었습니다.",
    "bundle_publish_unsupported": "덮어쓰기 없는 원자 게시를 지원하지 않습니다.",
    "bundle_cleanup_pending": "이번 호출의 임시 출력 정리를 완료하지 못했습니다.",
}


class BundleInstallError(PwehError):
    """원시 경로·OS 오류를 포함하지 않는 설치 오류."""

    def __init__(self, code="bundle_io_failed"):
        super().__init__(_MESSAGES[code], code=code)


def _fixed(exc):
    code = getattr(exc, "code", None)
    return BundleInstallError(code if isinstance(code, str) and code in _MESSAGES else "bundle_io_failed")


def _tick(deadline, cancel=None):
    if type(deadline) not in (int, float) or not 0 < deadline < 1e15 or not math.isfinite(deadline):
        raise BundleInstallError("bundle_invalid_argument")
    if cancel is not None:
        try:
            value = cancel()
        except Exception:
            raise BundleInstallError("bundle_cancel_failed") from None
        if type(value) is not bool:
            raise BundleInstallError("bundle_cancel_failed")
        if value:
            raise BundleInstallError("cancelled")
    if time.monotonic() >= deadline:
        raise BundleInstallError("bundle_timeout")


def _absolute(value):
    if not isinstance(value, (str, Path)):
        raise BundleInstallError("bundle_invalid_argument")
    text = str(value)
    if (not text.startswith("/") or "\0" in text or len(os.fsencode(text)) > 4096
            or ".." in text.split("/") or len(text.split("/")) > 256):
        raise BundleInstallError("bundle_invalid_argument")
    return Path(os.path.normpath(text))


def _identity(st):
    return st.st_dev, st.st_ino, stat.S_IFMT(st.st_mode)


def _same(fd, parent, name):
    try:
        current = os.stat(name, dir_fd=parent, follow_symlinks=False)
    except FileNotFoundError:
        raise BundleInstallError("bundle_changed") from None
    if _identity(os.fstat(fd)) != _identity(current):
        raise BundleInstallError("bundle_changed")


class _Directory:
    """절대 디렉터리의 모든 부모 이름과 fd를 닫힐 때까지 결속한다."""

    def __init__(self, path, *, create, deadline, cancel):
        self.fds, self.names = [], []
        try:
            self.fds.append(os.open("/", safeio.DIR_FLAGS))
            for name in path.parts[1:]:
                _tick(deadline, cancel)
                parent = self.fds[-1]
                try:
                    before = os.stat(name, dir_fd=parent, follow_symlinks=False)
                except FileNotFoundError:
                    if not create:
                        raise
                    try:
                        os.mkdir(name, 0o755, dir_fd=parent)
                    except FileExistsError:
                        pass
                    before = os.stat(name, dir_fd=parent, follow_symlinks=False)
                if not stat.S_ISDIR(before.st_mode):
                    raise BundleInstallError("bundle_tree_invalid")
                fd = os.open(name, safeio.DIR_FLAGS, dir_fd=parent)
                self.fds.append(fd)
                self.names.append(name)
                if _identity(os.fstat(fd)) != _identity(before):
                    raise BundleInstallError("bundle_changed")
            self.check()
        except BaseException:
            self.close()
            raise

    @property
    def fd(self):
        return self.fds[-1]

    def check(self):
        for index, name in enumerate(self.names):
            _same(self.fds[index + 1], self.fds[index], name)

    def close(self):
        for fd in reversed(self.fds):
            os.close(fd)
        self.fds.clear()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()


@contextmanager
def _publish_lock(parent, deadline, cancel):
    """같은 tool의 게시를 직렬화하고 잠금 파일 이름을 유지한다."""
    name = ".publish.lock"
    try:
        before = os.stat(name, dir_fd=parent, follow_symlinks=False)
    except FileNotFoundError:
        before = None
    if before is not None and (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1):
        raise BundleInstallError("bundle_tree_invalid")
    fd = os.open(name, os.O_RDWR | os.O_CREAT | safeio.READ_FLAGS, 0o600, dir_fd=parent)
    try:
        current = os.fstat(fd)
        if (not stat.S_ISREG(current.st_mode) or current.st_nlink != 1
                or (before is not None and _identity(current) != _identity(before))):
            raise BundleInstallError("bundle_changed")
        while True:
            _tick(deadline, cancel)
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError:
                time.sleep(min(.02, max(0, deadline - time.monotonic())))
        _same(fd, parent, name)
        yield fd
    finally:
        os.close(fd)  # 잠금 이름을 지우면 동시 실행이 다른 inode를 잠글 수 있다.


def _rename_noreplace(parent, source, destination):
    """Linux의 같은 부모 안에서 목적지를 절대 교체하지 않고 게시한다."""
    if not sys.platform.startswith("linux"):
        raise BundleInstallError("bundle_publish_unsupported")
    try:
        call = ctypes.CDLL(None, use_errno=True).renameat2
    except (AttributeError, OSError):
        raise BundleInstallError("bundle_publish_unsupported") from None
    call.argtypes = (ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint)
    call.restype = ctypes.c_int
    if call(parent, os.fsencode(source), parent, os.fsencode(destination), 1) != 0:
        code = ctypes.get_errno()
        if code == errno.EEXIST:
            raise FileExistsError
        if code in (errno.ENOSYS, errno.EINVAL, errno.ENOTSUP):
            raise BundleInstallError("bundle_publish_unsupported")
        raise BundleInstallError("bundle_io_failed")


class _Pending:
    """이번 호출이 생성한 이름·inode만 추적한다. 기존 pending은 재사용하지 않는다."""

    def __init__(self, parent, deadline, cancel):
        self.parent, self.deadline, self.cancel = parent, deadline, cancel
        self.name = ".pending-" + secrets.token_hex(16)
        self.records = {}
        self.fd = None
        self.published = False
        os.mkdir(self.name, 0o700, dir_fd=parent)
        try:
            self.fd = os.open(self.name, safeio.DIR_FLAGS, dir_fd=parent)
            self.records[()] = _identity(os.fstat(self.fd))
            self.check()
        except BaseException:
            if self.fd is not None:
                try:
                    self.check()
                    os.rmdir(self.name, dir_fd=parent)
                except OSError:
                    pass
                finally:
                    os.close(self.fd)
            raise

    def check(self):
        _same(self.fd, self.parent, self.name)

    def directory(self, parts, *, create=False):
        fd = os.dup(self.fd)
        try:
            for index, name in enumerate(parts):
                _tick(self.deadline, self.cancel)
                key = tuple(parts[:index + 1])
                if key not in self.records:
                    if not create:
                        raise BundleInstallError("bundle_changed")
                    os.mkdir(name, 0o700, dir_fd=fd)
                    st = os.stat(name, dir_fd=fd, follow_symlinks=False)
                    if not stat.S_ISDIR(st.st_mode):
                        raise BundleInstallError("bundle_changed")
                    self.records[key] = _identity(st)
                expected = self.records[key]
                actual = os.stat(name, dir_fd=fd, follow_symlinks=False)
                if not stat.S_ISDIR(actual.st_mode) or _identity(actual) != expected:
                    raise BundleInstallError("bundle_changed")
                child = os.open(name, safeio.DIR_FLAGS, dir_fd=fd)
                if _identity(os.fstat(child)) != expected:
                    os.close(child)
                    raise BundleInstallError("bundle_changed")
                os.close(fd)
                fd = child
            self.check()
            return fd
        except BaseException:
            os.close(fd)
            raise

    @contextmanager
    def file(self, parts, *, mode):
        parent = self.directory(parts[:-1], create=True)
        fd = None
        try:
            fd = safeio.create_excl(parent, parts[-1], 0o600)
            self.records[tuple(parts)] = _identity(os.fstat(fd))
            yield fd
            _tick(self.deadline, self.cancel)
            os.fchmod(fd, mode)
            os.fsync(fd)
            _same(fd, parent, parts[-1])
            self.check()
        finally:
            if fd is not None:
                os.close(fd)
            os.close(parent)

    def seal(self):
        for parts, identity in sorted(self.records.items(), key=lambda row: len(row[0]), reverse=True):
            if identity[2] == stat.S_IFDIR:
                fd = self.directory(parts)
                try:
                    os.fchmod(fd, 0o555)
                    os.fsync(fd)
                finally:
                    os.close(fd)

    def cleanup(self):
        """시간이 남는 동안 자신이 만든 inode만 역순으로 정리한다."""
        self.cancel = None
        self.deadline = min(self.deadline, time.monotonic() + 5)
        try:
            self.check()
            # readonly 부모를 먼저 열되 바뀐 디렉터리에는 chmod하지 않는다.
            for parts, identity in sorted(self.records.items(), key=lambda row: len(row[0])):
                if identity[2] == stat.S_IFDIR:
                    fd = self.directory(parts)
                    try:
                        os.fchmod(fd, 0o700)
                    finally:
                        os.close(fd)
            for parts, identity in sorted(self.records.items(), key=lambda row: len(row[0]), reverse=True):
                _tick(self.deadline)
                if not parts:
                    continue
                parent = self.directory(parts[:-1])
                try:
                    st = os.stat(parts[-1], dir_fd=parent, follow_symlinks=False)
                    if _identity(st) != identity:
                        return False
                    if stat.S_ISDIR(st.st_mode):
                        os.rmdir(parts[-1], dir_fd=parent)
                    else:
                        os.unlink(parts[-1], dir_fd=parent)
                finally:
                    os.close(parent)
            self.check()
            os.rmdir(self.name, dir_fd=self.parent)
            return True
        except Exception:
            return False


def _exists(parent, name):
    try:
        os.stat(name, dir_fd=parent, follow_symlinks=False)
        return True
    except FileNotFoundError:
        return False


def _result(bundle, status):
    return {"ok": True, "status": status, "tool": bundle.tool,
            "release_id": bundle.release_id, "manifest_sha256": bundle.manifest_sha256}


def _existing(parent, final, manifest, deadline, cancel):
    if not _exists(parent.fd, final.name):
        return None
    before = os.stat(final.name, dir_fd=parent.fd, follow_symlinks=False)
    if not stat.S_ISDIR(before.st_mode):
        raise BundleInstallError("bundle_tree_invalid")
    result = B.verify_release(final, manifest.tool, deadline=deadline, cancel=cancel)
    if (result.manifest_sha256 != manifest.manifest_sha256
            or result.release_id != manifest.release_id):
        raise BundleInstallError("bundle_tree_invalid")
    parent.check()
    if _identity(before) != _identity(os.stat(final.name, dir_fd=parent.fd, follow_symlinks=False)):
        raise BundleInstallError("bundle_changed")
    return result


def check_bundle(tool, prefix, *, deadline, cancel=None):
    """선택된 관리 릴리스만 읽는다. lock이나 디렉터리를 만들지 않는다."""
    try:
        _tick(deadline, cancel)
        deadline = min(deadline, time.monotonic() + MAX_SECONDS)
        manifest = B.load_registered_manifest(tool, deadline=deadline, cancel=cancel)
        final = B.managed_release_root(_absolute(prefix), manifest)
        with _Directory(final.parent, create=False, deadline=deadline, cancel=cancel) as parent:
            bundle = _existing(parent, final, manifest, deadline, cancel)
            if bundle is None:
                raise BundleInstallError("bundle_missing")
            return _result(bundle, "verified")
    except FileNotFoundError:
        raise BundleInstallError("bundle_missing") from None
    except Exception as exc:
        raise _fixed(exc) from None


def install_bundle(tool, prefix, *, source_tree=None, deadline, cancel=None):
    """등록된 로컬 source를 새 root로 게시한다. 기존 root는 force 없이 항상 보존한다."""
    try:
        _tick(deadline, cancel)
        deadline = min(deadline, time.monotonic() + MAX_SECONDS)
        manifest = B.load_registered_manifest(tool, deadline=deadline, cancel=cancel)
        final = B.managed_release_root(_absolute(prefix), manifest)
        source = None if source_tree is None else _absolute(source_tree)
        if source is not None and (source == final or source in final.parents or final in source.parents):
            raise BundleInstallError("bundle_invalid_argument")
        try:
            with _Directory(final.parent, create=False, deadline=deadline, cancel=cancel) as parent:
                bundle = _existing(parent, final, manifest, deadline, cancel)
                if bundle is not None:
                    return _result(bundle, "already-present")
        except FileNotFoundError:
            pass
        if source is None:
            raise BundleInstallError("bundle_missing")
        original = B.verify_payload(source, tool, manifest.release_id, deadline=deadline, cancel=cancel)
        if original.root == final or original.root in final.parents or final in original.root.parents:
            raise BundleInstallError("bundle_invalid_argument")
        with _Directory(final.parent, create=True, deadline=deadline, cancel=cancel) as parent:
            with _publish_lock(parent.fd, deadline, cancel) as lock_fd:
                parent.check()
                bundle = _existing(parent, final, manifest, deadline, cancel)
                if bundle is not None:
                    return _result(bundle, "already-present")
                B.revalidate_bundle(original, deadline=deadline, cancel=cancel)
                pending = _Pending(parent.fd, deadline, cancel)
                try:
                    for item in manifest.files:
                        _tick(deadline, cancel)
                        mode = 0o555 if item.path == manifest.entrypoint else 0o444
                        with B.open_verified_file(original, item.path, deadline=deadline, cancel=cancel) as source_fd:
                            with pending.file(("payload", *item.path.split("/")), mode=mode) as output_fd:
                                digest, offset = hashlib.sha256(), 0
                                while offset < item.size:
                                    _tick(deadline, cancel)
                                    chunk = os.pread(source_fd, min(CHUNK, item.size - offset), offset)
                                    if not chunk:
                                        raise BundleInstallError("bundle_changed")
                                    digest.update(chunk)
                                    safeio.write_all(output_fd, chunk)
                                    offset += len(chunk)
                                if digest.hexdigest() != item.sha256:
                                    raise BundleInstallError("bundle_changed")
                    with pending.file(("release.json",), mode=0o444) as fd:
                        safeio.write_all(fd, manifest.receipt_bytes)
                    pending.seal()
                    pending_path = final.parent / pending.name
                    verified = B.verify_release(pending_path, tool, deadline=deadline, cancel=cancel)
                    B.revalidate_bundle(original, deadline=deadline, cancel=cancel)
                    B.revalidate_bundle(verified, deadline=deadline, cancel=cancel)
                    parent.check()
                    pending.check()
                    _same(lock_fd, parent.fd, ".publish.lock")
                    _tick(deadline, cancel)
                    try:
                        _rename_noreplace(parent.fd, pending.name, final.name)
                    except FileExistsError:
                        existing = _existing(parent, final, manifest, deadline, cancel)
                        if existing is None or existing.manifest_sha256 != manifest.manifest_sha256:
                            raise BundleInstallError("bundle_tree_invalid")
                        return _result(existing, "already-present")
                    pending.published = True
                    os.fsync(parent.fd)
                    final_bundle = _existing(parent, final, manifest, deadline, cancel)
                    if final_bundle is None or final_bundle.manifest_sha256 != verified.manifest_sha256:
                        raise BundleInstallError("bundle_changed")
                    return _result(final_bundle, "installed")
                finally:
                    try:
                        if not pending.published and not pending.cleanup():
                            raise BundleInstallError("bundle_cleanup_pending")
                    finally:
                        os.close(pending.fd)
    except Exception as exc:
        raise _fixed(exc) from None


class _Parser(argparse.ArgumentParser):
    def error(self, message):
        self.exit(2, str(BundleInstallError("bundle_invalid_argument")) + "\n")


def main(argv=None):
    """고정된 로컬 CLI만 해석한다. import 시에는 실행하지 않는다."""
    parser = _Parser(description=__doc__)
    parser.add_argument("action", choices=("install", "check"))
    parser.add_argument("--tool", choices=("openocd", "sigrok"), required=True)
    parser.add_argument("--prefix", required=True)
    parser.add_argument("--source-tree")
    args = parser.parse_args(argv)
    if args.action == "check" and args.source_tree is not None:
        parser.error("check에는 source-tree를 지정할 수 없습니다.")
    try:
        deadline = time.monotonic() + MAX_SECONDS
        if args.action == "check":
            result = check_bundle(args.tool, args.prefix, deadline=deadline)
        else:
            result = install_bundle(args.tool, args.prefix, source_tree=args.source_tree, deadline=deadline)
        print(json.dumps(result, ensure_ascii=False, sort_keys=True))
        return 0
    except KeyboardInterrupt:
        print(str(BundleInstallError("cancelled")), file=sys.stderr)
        return 1
    except Exception as exc:
        print(str(_fixed(exc)), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
