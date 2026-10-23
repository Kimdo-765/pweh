"""공통 transport의 OS 배타/close 순서. synthetic fd와 시험용 PTY만 사용한다."""
import errno
import os
import pty
import stat
import termios
import uuid
from dataclasses import replace
from types import SimpleNamespace

import pytest

from pweh import ports as P, portlock as L, serialtransport as T
from pweh.errors import DeviceError
from pweh.portidentity import PortIdentity


@pytest.fixture
def setup(tmp_path):
    manager = L.PortLockManager(namespace="pweh-serial-" + uuid.uuid4().hex, runtime_root=tmp_path / "runtime")
    st = SimpleNamespace(st_dev=1, st_ino=2, st_rdev=os.makedev(166, 5), st_mode=stat.S_IFCHR | 0o600)
    route = P.resolve({"kind": "NATIVE_LINUX"}, "/dev/ttyACM5", "serial-session",
                      probe=P.PortProbe(stat=lambda _: st, realpath=lambda p: p, identity=lambda p: PortIdentity(p)))
    lease = manager.acquire([route.lock_key], owner=L.PortOwner("unit", "synthetic", route.ref))
    yield route, lease, st
    lease.close()


class Raw:
    def __init__(self, events):
        self.events = events; self.is_open = False; self.baudrate = 9600; self.timeout = .1
        self.in_waiting = 0; self.dtr = True; self.rts = True
    def open(self): self.events.append("open"); self.is_open = True
    def close(self): self.events.append("close"); self.is_open = False
    def fileno(self): return 91
    def read(self, n): return b""
    def write(self, value): return len(value)
    def flush(self): pass
    def reset_input_buffer(self): self.events.append("reset")
    def send_break(self, duration): self.events.append("break")


def test_order_setters_and_transport_does_not_own_lease(setup):
    route, lease, st = setup
    events = []; raw = Raw(events)
    def factory(path, **kwargs):
        assert kwargs["do_not_open"] and kwargs["exclusive"]
        events.append("factory"); return raw
    def ioctl(fd, op): events.append(op)
    tr = T.open_serial(route, T.SerialSettings(), lease=lease, serial_factory=factory, ioctl_fn=ioctl,
                       fstat_fn=lambda _: st, before_io=lambda: events.append("guard"))
    assert events == ["guard", "factory", "open", termios.TIOCEXCL]
    assert raw.dtr is raw.rts is False
    tr.baudrate = 115200; tr.timeout = 0; tr.dtr = True; tr.rts = True
    assert (raw.baudrate, raw.timeout, raw.dtr, raw.rts) == (115200, 0, True, True)
    tr.close(); tr.close()
    assert events[-2:] == [termios.TIOCNXCL, "close"] and not lease.closed


@pytest.mark.parametrize("backend", ["posix", "helper"])
def test_write_timeout_reaches_unopened_raw_transport(backend):
    """포트를 열지 않고 실제 두 backend의 timeout 위임과 shadow 부재를 확인한다."""
    if backend == "posix":
        raw = T.serial.Serial(port=None, write_timeout=5.0)
    else:
        from pweh.winserial.binary import HelperBinary
        from pweh.winserial.serial import HelperSerial
        raw = HelperSerial(helper=HelperBinary("/synthetic/helper.exe", "synthetic",
                                               "0" * 64, "0" * 40, (1, 0, 0)),
                           write_timeout=5.0)
    transport = T.SerialTransport(raw)
    try:
        assert transport.write_timeout == 5.0
        transport.write_timeout = 0.125
        assert raw.write_timeout == transport.write_timeout == 0.125
        assert "write_timeout" not in vars(transport)
        raw.write_timeout = 0.25
        assert transport.write_timeout == 0.25
        assert not raw.is_open
    finally:
        transport.close()


def test_guard_denial_and_closed_lease_factory_zero(setup):
    route, lease, st = setup
    def denied(): raise DeviceError("guard denied")
    with pytest.raises(DeviceError, match="guard denied"):
        T.open_serial(route, T.SerialSettings(), lease=lease, before_io=denied,
                      serial_factory=lambda *a, **k: pytest.fail("factory 금지"))
    lease.close()
    with pytest.raises(DeviceError, match="port_lease_invalid"):
        T.open_serial(route, T.SerialSettings(), lease=lease,
                      serial_factory=lambda *a, **k: pytest.fail("factory 금지"))


def test_fd_mismatch_closes_before_return(setup):
    route, lease, st = setup; events = []; raw = Raw(events)
    with pytest.raises(DeviceError, match="route_changed"):
        T.open_serial(route, T.SerialSettings(), lease=lease, serial_factory=lambda *a, **k: raw,
                      ioctl_fn=lambda fd, op: events.append(op), fstat_fn=lambda _: replace_stat(st, st_ino=999))
    assert events[-2:] == [termios.TIOCNXCL, "close"] and raw.is_open is False and not lease.closed


def replace_stat(st, **values): return SimpleNamespace(**(vars(st) | values))


def test_nxcl_failure_still_closes_and_reports(setup):
    route, lease, st = setup; raw = Raw([])
    def ioctl(fd, op):
        if op == termios.TIOCNXCL: raise OSError(errno.EIO, "synthetic")
    tr = T.open_serial(route, T.SerialSettings(), lease=lease, serial_factory=lambda *a, **k: raw,
                       ioctl_fn=ioctl, fstat_fn=lambda _: st)
    with pytest.raises(DeviceError): tr.close()
    assert tr.closed and tr.cleanup_errors and not lease.closed


def test_open_failure_with_unclosed_handle_preserves_internal_transport(setup):
    route, lease, st = setup; raw = Raw([])
    def broken_close(): raise OSError("synthetic close failure")
    raw.close = broken_close
    with pytest.raises(T.SerialOpenError) as err:
        T.open_serial(route, T.SerialSettings(), lease=lease, serial_factory=lambda *a, **k: raw,
                      ioctl_fn=lambda *a: None, fstat_fn=lambda _: replace_stat(st, st_ino=999))
    assert not err.value.transport.closed and not lease.closed
    assert "transport" not in err.value.to_dict() and "transport" not in err.value.to_dict()["data"]
    raw.close = lambda: setattr(raw, "is_open", False)
    err.value.transport.close()


def test_internal_open_failure_cannot_claim_lost_fd_closed(setup):
    route, lease, st = setup; raw = Raw([])
    def failed_open():
        raw.is_open = False
        raise OSError("setup failed after internal fd reference was lost")
    raw.open = failed_open
    with pytest.raises(T.SerialOpenError) as err:
        T.open_serial(route, T.SerialSettings(), lease=lease, serial_factory=lambda *a, **k: raw)
    tr = err.value.transport
    assert not tr.closed and not lease.closed
    assert "open_failed_handle_ownership_unknown" in tr.cleanup_errors
    with pytest.raises(DeviceError): tr.close()
    assert not tr.closed  # 보이지 않는 fd 회수를 재시도 성공으로 과장하지 않는다.


@pytest.mark.parametrize("code,succeeds", [(errno.ENOTTY, True), (errno.EBUSY, False), (errno.EACCES, False)])
def test_ioctl_only_explicit_unsupported_is_warning(setup, code, succeeds):
    route, lease, st = setup; raw = Raw([])
    def ioctl(*args): raise OSError(code, "synthetic")
    if succeeds:
        tr = T.open_serial(route, T.SerialSettings(), lease=lease, serial_factory=lambda *a, **k: raw,
                           ioctl_fn=ioctl, fstat_fn=lambda _: st)
        assert tr.metadata()["exclusive"] == "unsupported"; tr.close()
    else:
        with pytest.raises(OSError):
            T.open_serial(route, T.SerialSettings(), lease=lease, serial_factory=lambda *a, **k: raw,
                          ioctl_fn=ioctl, fstat_fn=lambda _: st)
        assert raw.is_open is False


def test_pty_nxcl_allows_reopen_with_keeper(tmp_path):
    master, keeper = pty.openpty()
    manager = L.PortLockManager(namespace="pweh-pty-" + uuid.uuid4().hex, runtime_root=tmp_path / "runtime")
    lease = None; tr = None
    try:
        route = P.resolve({"kind": "NATIVE_LINUX"}, os.ttyname(keeper), "serial-session",
                          probe=P.PortProbe(identity=lambda p: PortIdentity(p)))
        lease = manager.acquire([route.lock_key], owner=L.PortOwner("test", "synthetic", route.ref))
        tr = T.open_serial(route, T.SerialSettings(), lease=lease)
        try:
            extra = os.open(route.device_path, os.O_RDWR | os.O_NOCTTY | os.O_NONBLOCK)
        except OSError as exc:
            assert exc.errno == errno.EBUSY
        else:
            os.close(extra)  # CAP_SYS_ADMIN은 TIOCEXCL을 우회할 수 있다.
        tr.close()
        extra = os.open(route.device_path, os.O_RDWR | os.O_NOCTTY | os.O_NONBLOCK)
        os.close(extra)
    finally:
        if tr and not tr.closed: tr.close()
        if lease: lease.close()
        os.close(keeper); os.close(master)
