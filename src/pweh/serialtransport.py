"""직렬 transport: lease를 빌려 열고 raw 핸들 또는 검증한 Windows helper만 소유한다."""
from __future__ import annotations

import errno
import os
import stat
import threading
from dataclasses import dataclass
from typing import Any, Callable

import serial

from .errors import DeviceError, ValidationFailed
from .portlock import PortLease
from .ports import PortRoute, validate_ref


@dataclass(frozen=True)
class SerialSettings:
    baudrate: int = 115200
    bytesize: int = 8
    parity: str = "N"
    stopbits: float = 1
    timeout: float = 0.05
    write_timeout: float = 5.0
    dtr: bool = False
    rts: bool = False


class SerialOpenError(DeviceError):
    """open 뒤 cleanup 미확인. transport는 내부 속성에만 남기며 JSON에 싣지 않는다."""
    code = "serial_open_cleanup_failed"

    def __init__(self, transport: SerialTransport, cause: BaseException):
        self.transport = transport
        super().__init__("직렬 open 실패 후 핸들 정리를 확인하지 못했습니다.",
                         data={"cause": type(cause).__name__, "closed": transport.closed,
                               "cleanup_errors": list(transport.cleanup_errors)})


class SerialTransport:
    """물리 핸들만 닫는다. disconnected/session lease는 caller가 유지한다."""
    def __init__(self, raw: Any, *, ioctl_fn: Callable | None = None):
        self._raw = raw
        self._ioctl_fn = ioctl_fn
        self._exclusive = False
        self._exclusive_status = "not-applicable"
        self._warnings: list[str] = []
        self._closed = False
        self._open_cleanup_unverified = False
        self._helper = False
        self._cleanup_errors: tuple[str, ...] = ()
        self._close_lock = threading.Lock()

    @property
    def closed(self) -> bool:
        return self._closed

    @property
    def cleanup_errors(self) -> tuple[str, ...]:
        return self._cleanup_errors

    @property
    def is_open(self) -> bool:
        return not self._closed and bool(self._raw.is_open)

    def metadata(self) -> dict[str, Any]:
        result = {"exclusive": self._exclusive_status, "warnings": list(self._warnings),
                  "closed": self._closed, "cleanup_errors": list(self._cleanup_errors)}
        if self._helper:
            result.update(self._raw.cleanup_metadata())
        return result

    def _ioctl(self, operation: int) -> Any:
        import fcntl
        return (self._ioctl_fn or fcntl.ioctl)(self._raw.fileno(), operation)

    def _set_exclusive(self) -> None:
        import termios
        operation = getattr(termios, "TIOCEXCL", None)
        if operation is None:
            self._exclusive_status = "unsupported"
            self._warnings.append("TIOCEXCL 상수가 없는 플랫폼")
            return
        try:
            self._ioctl(operation)
        except OSError as exc:
            if exc.errno != errno.ENOTTY:
                raise
            self._exclusive_status = "unsupported"
            self._warnings.append("드라이버가 TIOCEXCL을 지원하지 않음")
        else:
            self._exclusive = True
            self._exclusive_status = "tioc-excl"

    def close(self) -> None:
        with self._close_lock:
            if self._closed:
                return
            errors = []
            if self._exclusive:
                try:
                    import termios
                    self._ioctl(termios.TIOCNXCL)
                    self._exclusive = False
                except Exception as exc:
                    errors.append("TIOCNXCL:" + type(exc).__name__)
            try:
                self._raw.close()
            except Exception as exc:
                errors.append("close:" + type(exc).__name__)
            try:
                self._closed = self._raw.cleanup_verified is True if self._helper else self._raw.is_open is False
            except Exception:
                self._closed = False
            if self._open_cleanup_unverified:
                # pyserial open의 setup 실패는 os.close 오류를 무시하고 fd 참조를 지울 수 있다.
                # 이후 is_open=False/close() 정상 반환만으로 잃은 fd까지 회수됐다고 단정하지 않는다.
                self._closed = False
                errors.append("open_failed_handle_ownership_unknown")
            if not self._closed:
                errors.append("physical_close_unverified")
            self._cleanup_errors = tuple(errors)
            if errors:
                raise DeviceError("직렬 핸들 정리 일부 실패", data={"closed": self._closed, "errors": errors})

    def read(self, size: int = 1) -> bytes:
        return self._raw.read(size)

    def write(self, data: bytes) -> int:
        return self._raw.write(data)

    def flush(self) -> None:
        return self._raw.flush()

    def cancel_read(self) -> None:
        method = getattr(self._raw, "cancel_read", None)
        if method:
            method()

    def fileno(self) -> int:
        return self._raw.fileno()

    def reset_input_buffer(self) -> None:
        return self._raw.reset_input_buffer()

    def send_break(self, duration: float = 0.25) -> None:
        return self._raw.send_break(duration)

    @property
    def in_waiting(self) -> int:
        return self._raw.in_waiting

    # __getattr__만 쓰면 setter가 wrapper에 새 속성을 만들어 실제 설정이 바뀌지 않는다.
    @property
    def baudrate(self) -> int:
        return self._raw.baudrate

    @baudrate.setter
    def baudrate(self, value: int) -> None:
        self._raw.baudrate = value

    @property
    def timeout(self) -> float:
        return self._raw.timeout

    @timeout.setter
    def timeout(self, value: float) -> None:
        self._raw.timeout = value

    @property
    def write_timeout(self) -> float:
        return self._raw.write_timeout

    @write_timeout.setter
    def write_timeout(self, value: float) -> None:
        self._raw.write_timeout = value

    @property
    def dtr(self) -> bool:
        return self._raw.dtr

    @dtr.setter
    def dtr(self, value: bool) -> None:
        self._raw.dtr = value

    @property
    def rts(self) -> bool:
        return self._raw.rts

    @rts.setter
    def rts(self, value: bool) -> None:
        self._raw.rts = value


def _make_helper(*, port: str, before_open=None, **settings):
    """late factory seam. COM을 serial_for_url로 넘기지 않고 고정 핀을 먼저 검사한다."""
    from .config import load_config
    from .hostenv import detect
    from .toolsdir import tools_dir
    from .winserial.binary import resolve_helper
    from .winserial.serial import HelperSerial
    config = load_config()
    helper = resolve_helper(configured=config.tools.get("serial_helper"), env_value=os.environ.get("PWEH_SERIAL_HELPER"),
                            tools_root=tools_dir())
    raw = HelperSerial(helper=helper, port=None, before_open=before_open,
                       environment_provider=lambda: detect(smoke=False, config=config), **settings)
    raw.port = port
    return raw


def open_serial(route: PortRoute, settings: SerialSettings, *, lease: PortLease,
                before_io: Callable[[], Any] | None = None, serial_factory: Callable | None = None,
                helper_factory: Callable | None = None, ioctl_fn: Callable | None = None,
                fstat_fn: Callable | None = None) -> SerialTransport:
    """lease→callback→open→배타 확인. helper는 OPEN 직전에도 lease/guard를 다시 본다."""
    if route.backend not in ("posix-tty", "net-url", "loop", "win-helper") or route.purpose != "serial-session":
        raise ValidationFailed("이 route에는 직렬 transport가 없습니다.")
    canonical = validate_ref(route.device_path, purpose="serial-session")
    if (canonical != route.device_path or (route.backend == "posix-tty" and not canonical.startswith("/dev/"))
            or (route.backend == "net-url" and not canonical.startswith(("socket://", "rfc2217://")))
            or (route.backend == "loop" and canonical != "loop://")
            or (route.backend == "win-helper" and not canonical.startswith("COM"))):
        raise ValidationFailed("route backend와 정규 포트 경로가 일치하지 않습니다.")
    lease.assert_held((route.lock_key,) if route.lock_key else ())
    if before_io:
        before_io()
    kwargs = {"baudrate": settings.baudrate, "bytesize": settings.bytesize, "parity": settings.parity,
              "stopbits": settings.stopbits, "timeout": settings.timeout, "write_timeout": settings.write_timeout}
    if route.backend == "posix-tty":
        kwargs["exclusive"] = True
    def helper_guard():
        lease.assert_held((route.lock_key,) if route.lock_key else ())
        if before_io:
            before_io()
    if route.backend == "win-helper":
        raw = (helper_factory or _make_helper)(port=route.device_path, before_open=helper_guard, **kwargs)
    else:
        raw = (serial_factory or serial.serial_for_url)(route.device_path, do_not_open=True, **kwargs)
    transport = SerialTransport(raw, ioctl_fn=ioctl_fn)
    transport._helper = route.backend == "win-helper"
    open_started = open_completed = False
    try:
        raw.dtr, raw.rts = bool(settings.dtr), bool(settings.rts)
        open_started = True
        raw.open()
        open_completed = True
        if transport._helper:
            transport._exclusive_status = "windows-share-zero"
        if route.backend == "posix-tty":
            transport._set_exclusive()
            st = (fstat_fn or os.fstat)(raw.fileno())
            if not stat.S_ISCHR(st.st_mode) or (st.st_dev, st.st_ino, st.st_rdev) != route.node_identity:
                raise DeviceError("open한 fd가 승인된 tty와 다릅니다.", code="route_changed")
        return transport
    except BaseException as exc:
        if open_started and not open_completed and not transport._helper:
            transport._open_cleanup_unverified = True
        try:
            transport.close()
        except Exception:
            pass
        if not transport.closed:
            raise SerialOpenError(transport, exc) from exc
        raise
