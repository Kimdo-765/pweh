"""열기 전 OS 포트 잠금과 uid별 표시 기록. 장치 핸들은 열지 않는다.

운영 경로/namespace는 고정이다. 별도 인자는 합성 시험의 명시 주입용이다.
owner와 role JSON은 권위 잠금이 아니며, 계측기 pin/tag 저장소와 분리한다.
"""
from __future__ import annotations

import errno
import hashlib
import json
import os
import secrets
import socket
import stat
import threading
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Callable, Iterable

from .errors import Busy, DeviceError, PwehError, ValidationFailed

MAX_KEYS = 64
MAX_RECORD = 16384
MAX_RECORDS = 1024


def _keys(values: Iterable[str]) -> tuple[str, ...]:
    if isinstance(values, str):
        values = (values,)
    out: set[str] = set()
    for index, key in enumerate(values):
        if index >= MAX_KEYS or not isinstance(key, str) or not key or len(key) > 4096 or any(ord(c) < 32 for c in key):
            raise ValidationFailed("포트 잠금 key 형식/개수 상한 오류")
        out.add(key)
    return tuple(sorted(out))


def _runtime_root() -> Path:
    return Path(f"/tmp/pweh-{os.getuid()}")


def _check(st: os.stat_result, *, directory: bool = False) -> None:
    if st.st_uid != os.getuid() or stat.S_IMODE(st.st_mode) != (0o700 if directory else 0o600):
        raise ValueError("port_record_permissions")
    if not (stat.S_ISDIR(st.st_mode) if directory else stat.S_ISREG(st.st_mode)):
        raise ValueError("port_record_type")
    if not directory and (st.st_size > MAX_RECORD or st.st_nlink != 1):
        raise ValueError("port_record_size_or_link")


class _Records:
    """보호 디렉터리 fd 아래에서만 bounded JSON을 읽고 교체한다."""
    def __init__(self, root: Path, subdir: str):
        self.root, self.subdir = root, subdir

    def directory(self, create: bool = False) -> int | None:
        if create:
            self.root.mkdir(mode=0o700, exist_ok=True)
        try:
            rootfd = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        except FileNotFoundError:
            return None
        try:
            _check(os.fstat(rootfd), directory=True)
            if create:
                try:
                    os.mkdir(self.subdir, 0o700, dir_fd=rootfd)
                except FileExistsError:
                    pass
            try:
                fd = os.open(self.subdir, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=rootfd)
            except FileNotFoundError:
                return None
            try:
                _check(os.fstat(fd), directory=True)
                return fd
            except BaseException:
                os.close(fd)
                raise
        finally:
            os.close(rootfd)

    @staticmethod
    def names(fd: int) -> list[str]:
        names = []
        with os.scandir(fd) as entries:
            for entry in entries:
                names.append(entry.name)
                if len(names) > MAX_RECORDS:
                    raise ValueError("port_record_count_limit")
        return names

    @staticmethod
    def read_at(fd: int, name: str) -> dict[str, Any]:
        f = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
        try:
            _check(os.fstat(f))
            raw = os.read(f, MAX_RECORD + 1)
            if len(raw) > MAX_RECORD:
                raise ValueError("port_record_size_limit")
            rec = json.loads(raw)
            if not isinstance(rec, dict):
                raise ValueError("port_record_schema")
            return rec
        finally:
            os.close(f)

    def get(self, name: str) -> dict[str, Any] | None:
        fd = self.directory()
        if fd is None:
            return None
        try:
            try:
                return self.read_at(fd, name)
            except FileNotFoundError:
                return None
        finally:
            os.close(fd)

    def put(self, name: str, rec: dict[str, Any]) -> None:
        raw = json.dumps(rec, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode()
        if len(raw) > MAX_RECORD:
            raise ValueError("port_record_size_limit")
        fd = self.directory(True)
        assert fd is not None
        tmp = ".port-" + secrets.token_hex(12)
        try:
            names = self.names(fd)
            if len(names) >= MAX_RECORDS and name not in names:
                raise ValueError("port_record_count_limit")
            f = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=fd)
            try:
                os.fchmod(f, 0o600)
                with os.fdopen(f, "wb", closefd=False) as stream:
                    stream.write(raw)
                    stream.flush()
                    os.fsync(f)
            finally:
                os.close(f)
            os.replace(tmp, name, src_dir_fd=fd, dst_dir_fd=fd)
        finally:
            try:
                os.unlink(tmp, dir_fd=fd)
            except FileNotFoundError:
                pass
            os.close(fd)

    def remove_owned(self, name: str, token: str) -> None:
        fd = self.directory()
        if fd is None:
            return
        try:
            try:
                if self.read_at(fd, name).get("token") == token:
                    os.unlink(name, dir_fd=fd)
            except FileNotFoundError:
                pass
        finally:
            os.close(fd)


@dataclass(frozen=True)
class PortOwner:
    server: str
    case_id: str
    ref: str
    role: str = "target"
    session_id: str | None = None
    job_id: str | None = None

    def __post_init__(self) -> None:
        for value in asdict(self).values():
            if value is not None and (not isinstance(value, str) or len(value) > 4096 or any(ord(c) < 32 for c in value)):
                raise ValidationFailed("포트 owner 필드 형식 오류")


class LeaseHandoff:
    """worker 시작과 caller 취소 사이 정리 책임을 한 번만 인계한다."""
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._owner = "pending"

    def claim_worker(self) -> bool:
        with self._lock:
            if self._owner != "pending":
                return False
            self._owner = "worker"
            return True

    def abandon_caller(self) -> bool:
        with self._lock:
            if self._owner != "pending":
                return False
            self._owner = "caller"
            return True


class PortLease:
    """manager가 강한 참조를 유지하는 OS lock. GC/timeout으로 해제하지 않는다."""
    def __init__(self, manager: PortLockManager, keys: tuple[str, ...], handles: list[Any], owner: PortOwner, state: str):
        self._manager, self._keys, self._handles = manager, keys, handles
        self._owner, self._state = asdict(owner), state
        self._token, self._since = secrets.token_hex(16), time.time()
        self._closed = False
        self._lock = threading.RLock()

    @property
    def keys(self) -> tuple[str, ...]:
        return self._keys

    @property
    def closed(self) -> bool:
        return self._closed

    def assert_held(self, keys: Iterable[str]) -> None:
        with self._lock:
            if self._closed or not set(_keys(keys)).issubset(self._keys):
                raise DeviceError("활성 포트 lease가 없거나 필요한 key를 보유하지 않습니다.", code="port_lease_invalid")

    def _write(self) -> None:
        for key in self._keys:
            self._manager._records.put(self._manager._name(key), {
                "schema": "pweh.port-owner/v1", **self._owner, "pid": os.getpid(), "key": key,
                "state": self._state, "since": self._since, "token": self._token,
            })

    def set_state(self, state: str, *, session_id: str | None = None, job_id: str | None = None) -> None:
        if state not in ("opening", "awaiting_approval", "open", "running", "disconnected", "orphan", "closing"):
            raise ValidationFailed("포트 lease 상태가 올바르지 않습니다.")
        with self._lock:
            self.assert_held(())
            for key, value in (("session_id", session_id), ("job_id", job_id)):
                if value is not None:
                    if not isinstance(value, str) or len(value) > 256 or any(ord(c) < 32 for c in value):
                        raise ValidationFailed("포트 owner 식별자 형식 오류")
                    self._owner[key] = value
            self._state = state
            self._write()

    def close(self) -> None:
        with self._lock:
            if self._closed:
                return
            errors = []
            remaining = []
            # owner 삭제를 먼저 한다. 잠금을 해제한 뒤 다음 소유자의 기록을 지우지 않는다.
            for key in self._keys:
                try:
                    self._manager._records.remove_owned(self._manager._name(key), self._token)
                except Exception as exc:
                    errors.append(type(exc).__name__)
            for handle in self._handles:
                try:
                    handle.close()
                except Exception as exc:
                    errors.append(type(exc).__name__)
                    remaining.append(handle)
            self._handles = remaining
            if not remaining:
                self._closed = True
                with self._manager._mutex:
                    self._manager._leases.pop(self._token, None)
            else:
                self._state = "orphan"
                try:
                    self._write()
                except Exception as exc:
                    errors.append(type(exc).__name__)
            if errors:
                raise DeviceError("포트 lease 정리 일부 실패", data={"closed": self._closed, "errors": errors})


class _FileLock:
    def __init__(self, fd: int):
        self.fd = fd

    def close(self) -> None:
        if self.fd is not None:
            import fcntl
            fd = self.fd
            try:
                fcntl.flock(fd, fcntl.LOCK_UN)
            finally:
                os.close(fd)
                self.fd = None


class PortLockManager:
    """같은 netns의 abstract 소켓. 플랫폼 미지원일 때만 보호 flock 파일로 대체한다."""
    def __init__(self, *, namespace: str | None = None, runtime_root: Path | None = None,
                 socket_factory: Callable | None = None):
        self.namespace = namespace if namespace is not None else "pweh/portlock/v1"
        if not isinstance(self.namespace, str) or not 1 <= len(self.namespace.encode()) <= 64 or "\0" in self.namespace:
            raise ValidationFailed("포트 잠금 namespace 형식 오류")
        self.runtime_root = Path(runtime_root) if runtime_root is not None else _runtime_root()
        self._socket_factory = socket_factory
        self._records = _Records(self.runtime_root, "port-owners")
        self._leases: dict[str, PortLease] = {}
        self._mutex = threading.RLock()

    @staticmethod
    def _name(key: str) -> str:
        return hashlib.sha256(key.encode()).hexdigest() + ".json"

    def _flock(self, key: str) -> _FileLock:
        import fcntl
        store = _Records(self.runtime_root, "port-locks")
        directory = store.directory(True)
        assert directory is not None
        fd = None
        try:
            name = self._name(self.namespace + ":" + key)[:-5] + ".lock"
            fd = os.open(name, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600, dir_fd=directory)
            before = os.fstat(fd)
            _check(before)
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            after = os.stat(name, dir_fd=directory, follow_symlinks=False)
            if (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino):
                raise ValueError("port_lock_replaced")
            os.set_inheritable(fd, False)
            result = _FileLock(fd)
            fd = None
            return result
        except OSError as exc:
            if exc.errno in (errno.EAGAIN, errno.EACCES):
                raise Busy("다른 프로세스가 포트를 사용 중입니다.", data={"lock_key": key}) from exc
            raise
        finally:
            if fd is not None:
                os.close(fd)
            os.close(directory)

    def _primitive(self, key: str) -> Any:
        factory = self._socket_factory or socket.socket
        sock = None
        try:
            sock = factory(socket.AF_UNIX, socket.SOCK_STREAM)
            sock.set_inheritable(False)
            name = "\0" + self.namespace + "/" + hashlib.sha256(key.encode()).hexdigest()[:32]
            sock.bind(name)
            return sock
        except BaseException as exc:
            if sock is not None:
                sock.close()
            if isinstance(exc, OSError) and exc.errno == errno.EADDRINUSE:
                raise Busy("다른 PWEH 작업이 포트를 사용 중입니다.", data={"lock_key": key}) from exc
            if isinstance(exc, OSError) and exc.errno in (errno.EAFNOSUPPORT, errno.EPROTONOSUPPORT, errno.EOPNOTSUPP, errno.EINVAL):
                return self._flock(key)
            raise

    def acquire(self, keys: Iterable[str], *, owner: PortOwner, state: str = "opening") -> PortLease:
        keys = _keys(keys)
        handles = []
        acquired = []
        lease = None
        try:
            for key in keys:
                try:
                    handles.append(self._primitive(key))
                    acquired.append(key)
                except Busy as exc:
                    exc.data["held_by"] = self._owner_record(key)
                    raise
            lease = PortLease(self, keys, handles, owner, state)
            with self._mutex:
                self._leases[lease._token] = lease
            lease.set_state(state)
            return lease
        except BaseException:
            if lease is not None:
                try:
                    lease.close()
                except Exception:
                    pass  # 정리 미확인은 manager의 강한 참조에 남긴다.
            else:
                remaining_keys, remaining_handles = [], []
                for key, handle in zip(acquired, handles):
                    try:
                        handle.close()
                    except Exception:
                        remaining_keys.append(key)
                        remaining_handles.append(handle)
                if remaining_handles:
                    orphan = PortLease(self, tuple(remaining_keys), remaining_handles, owner, "orphan")
                    with self._mutex:
                        self._leases[orphan._token] = orphan
                    try:
                        orphan._write()
                    except Exception:
                        pass  # 실패한 rollback fd는 strong reference로 계속 보존한다.
            raise

    def _owner_record(self, key: str) -> dict[str, Any]:
        try:
            rec = self._records.get(self._name(key))
            if rec and rec.get("schema") == "pweh.port-owner/v1" and rec.get("key") == key:
                return {k: v for k, v in rec.items() if k != "token"}
        except (OSError, ValueError, TypeError):
            pass
        return {"state": "unknown", "key": key, "note": "OS 잠금은 사용 중이나 소유 기록은 미확인"}

    def held_by(self, key: str) -> dict[str, Any] | None:
        _keys((key,))
        try:
            handle = self._primitive(key)
        except Busy:
            return self._owner_record(key)
        except (OSError, ValueError):
            return {"state": "unknown", "key": key, "note": "잠금 상태 조회 실패"}
        else:
            handle.close()
            return None


class PortRoleStore:
    """target/bridge 거부 표지. instrument tags와 파일 형식을 섞지 않는다."""
    def __init__(self, *, runtime_root: Path | None = None):
        self._records = _Records(Path(runtime_root) if runtime_root is not None else _runtime_root(), "port-roles")

    def mark_target(self, route: Any, *, case_id: str, server: str) -> None:
        if route.lock_key is None:
            return
        rec = {"schema": "pweh.port-role/v1", "role": "target", "lock_key": route.lock_key,
               "device_id": route.device_id, "identity": route.identity.to_dict(), "case_id": case_id, "server": server}
        self._records.put(PortLockManager._name(route.lock_key), rec)

    def assert_probe_allowed(self, route: Any) -> None:
        fd = None
        try:
            fd = self._records.directory()
            if fd is None:
                return
            for name in self._records.names(fd):
                if not name.endswith(".json"):
                    continue
                rec = self._records.read_at(fd, name)
                if (rec.get("schema") != "pweh.port-role/v1" or rec.get("role") not in ("target", "bridge")
                        or not isinstance(rec.get("lock_key"), str) or not rec["lock_key"]
                        or (rec.get("device_id") is not None and not isinstance(rec["device_id"], str))
                        or not isinstance(rec.get("identity"), dict)
                        or rec["identity"].get("status") not in ("known", "unknown")
                        or (rec["identity"].get("serial") is not None and not isinstance(rec["identity"]["serial"], str))):
                    raise ValueError("port_role_schema")
                same = rec["lock_key"] == route.lock_key or (route.device_id and rec.get("device_id") == route.device_id)
                if not same:
                    continue
                previous = rec["identity"]
                distinct = (route.identity.status == previous.get("status") == "known"
                            and route.identity.serial and previous.get("serial")
                            and route.identity.serial != previous["serial"] and route.device_id != rec.get("device_id"))
                if not distinct:
                    raise PwehError("대상 콘솔/브리지 표지가 있는 포트에 탐색 바이트를 보내지 않습니다.",
                                    code="port_role_conflict", data={"role": rec["role"], "lock_key": route.lock_key})
        except (OSError, ValueError, TypeError) as exc:
            raise PwehError("포트 역할 표지를 완전히 확인하지 못했습니다.", code="port_role_unknown") from exc
        finally:
            if fd is not None:
                os.close(fd)

    def assert_usb_scope_allowed(self, scope: Any) -> None:
        """전체 USB 키·부모·별명의 target/bridge 표지를 한 번 읽어 대조한다."""
        from .usb_binding import WindowsUsbScope
        fd = None
        try:
            if type(scope) is not WindowsUsbScope:
                raise ValueError("usb_scope_invalid")
            keys = {key.casefold() for key in scope.claim_keys}
            nodes = {row[0].casefold() for row in scope.binding_nodes}
            fd = self._records.directory()
            if fd is None:
                return
            for name in self._records.names(fd):
                if not name.endswith(".json"):
                    continue
                rec = self._records.read_at(fd, name)
                if (not isinstance(rec, dict) or rec.get("schema") != "pweh.port-role/v1"
                        or rec.get("role") not in ("target", "bridge")
                        or not isinstance(rec.get("identity"), dict)):
                    raise ValueError("port_role_schema")
                key, device_id, ident = rec.get("lock_key"), rec.get("device_id"), rec["identity"]
                if ident.get("status") not in ("known", "unknown"):
                    raise ValueError("port_role_schema")
                for value, required in ((key, True), (device_id, False),
                                        *((ident.get(field), False) for field in
                                          ("serial", "parent_instance", "usb_ancestor", "device_instance"))):
                    if value is None and not required:
                        continue
                    if (not isinstance(value, str) or not value or len(value) > 4096
                            or any(ord(char) < 32 for char in value)):
                        raise ValueError("port_role_schema")
                same = key.casefold() in keys or any(
                    ident.get(field) and ident[field].casefold() in nodes
                    for field in ("parent_instance", "usb_ancestor", "device_instance"))
                if device_id and device_id.casefold().startswith("win-pnp:"):
                    same |= device_id[8:].rsplit("/", 1)[0].casefold() in nodes
                # 새 관찰에 descriptor serial이 없으므로 distinct 예외를 만들지 않는다.
                if same:
                    raise PwehError("대상 콘솔/브리지 표지가 있는 USB 장치를 초기화하지 않습니다.",
                                    code="port_role_conflict", data={"role": rec["role"]})
        except (OSError, ValueError, TypeError, AttributeError):
            raise PwehError("USB 범위의 포트 역할 표지를 완전히 확인하지 못했습니다.",
                            code="port_role_unknown") from None
        finally:
            if fd is not None:
                os.close(fd)


_manager: PortLockManager | None = None
_roles: PortRoleStore | None = None
_singleton_lock = threading.Lock()


def get_manager() -> PortLockManager:
    """운영 기본 manager. 시험은 이 factory를 명시 주입한다."""
    global _manager
    with _singleton_lock:
        if _manager is None:
            _manager = PortLockManager()
        return _manager


def get_role_store() -> PortRoleStore:
    """운영 기본 role 저장소. 테스트 감지/환경변수 경로 변경은 없다."""
    global _roles
    with _singleton_lock:
        if _roles is None:
            _roles = PortRoleStore()
        return _roles
