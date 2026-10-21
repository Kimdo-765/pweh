"""helper 위의 제한된 pySerial SerialBase. case·lease의 소유권은 소비자에 남긴다."""
from __future__ import annotations

import io
import math
import struct
import threading
import time

import serial

from .binary import HelperBinary
from .process import HelperRun, HelperError, HelperCleanupError
from .protocol import MAX_WRITE, ProtocolError

MAX_RX_BUFFER = 1 << 20
_PARITY = {"N": 0, "O": 1, "E": 2, "M": 3, "S": 4}
_STOP = {1: 0, 1.5: 1, 2: 2}


class HelperSerial(serial.SerialBase):
    """명시 open만 허용한다. is_open=False와 cleanup_verified는 서로 다른 상태다."""
    def __init__(self, *, helper: HelperBinary, port=None, environment_provider=None, process_factory=None,
                 windows_lifecycle=None, runtime_root=None, before_open=None, **serial_settings):
        self.helper = helper
        self._run_kwargs = dict(environment_provider=environment_provider, process_factory=process_factory,
                                windows_lifecycle=windows_lifecycle, runtime_root=runtime_root)
        self.before_open = before_open
        self._run: HelperRun | None = None
        self._rx = bytearray()
        self._condition = threading.Condition(threading.RLock())
        self._operation_lock = threading.RLock()
        self._lifetime_lock = threading.RLock()
        self._cancel_read = 0
        self._read_cancel_pending = False
        self._readers = 0
        self._disconnected = None
        self._epoch = 1
        self._reset_pending = False
        self._framing_snapshot = None
        self._ever_opened = False
        super().__init__(port=None, **serial_settings)
        self.port = port
        self._validate_settings()

    @property
    def port(self):
        return self._port

    @port.setter
    def port(self, value):
        if getattr(self, "is_open", False):
            if value == self._port:
                return  # SerialBase는 같은 값에도 close/open하므로 직접 no-op으로 끝낸다.
            raise serial.SerialException("열린 helper 포트는 바꿀 수 없습니다.")
        serial.SerialBase.port.fset(self, value)

    def _validate_settings(self):
        if (self._xonxoff or self._rtscts or self._dsrdtr or self._inter_byte_timeout is not None
                or self._rs485_mode is not None):
            raise ValueError("helper는 흐름제어/RS485/inter-byte timeout을 지원하지 않습니다.")
        if self._timeout is not None and (not math.isfinite(self._timeout) or self._timeout < 0):
            raise ValueError("read timeout 형식 오류")
        if self._write_timeout is not None and (not math.isfinite(self._write_timeout) or not 0 < self._write_timeout <= 30):
            raise ValueError("helper write_timeout은 0초 초과 30초 이하입니다.")
        if not 50 <= self._baudrate <= 20_000_000:
            raise ValueError("helper baudrate 범위 오류")
        return (self._baudrate, self._bytesize, _PARITY[self._parity], _STOP[self._stopbits])

    def _on_data(self, epoch, data):
        with self._condition:
            if epoch != self._epoch:
                raise ProtocolError("RX epoch 불일치")
            if self._reset_pending:
                return
            if len(self._rx) + len(data) > MAX_RX_BUFFER:
                raise ProtocolError("host RX 상한 초과")
            self._rx.extend(data); self._condition.notify_all()

    def _on_response(self, kind, result):
        if result["status"] or kind in ("S", "Q"):
            return
        with self._condition:
            epoch = result.get("epoch")
            wanted = self._epoch + 1 if kind == "P" and self._reset_pending else self._epoch
            if epoch != wanted or not 0 < epoch <= 0xffffffff:
                raise ProtocolError("ACK epoch 불일치")
            if kind == "P" and self._reset_pending:
                self._epoch = epoch; self._reset_pending = False

    def _on_error(self, error):
        with self._condition:
            self._disconnected = error
            self.is_open = False
            self._condition.notify_all()

    @property
    def cleanup_verified(self):
        return self._run is None or self._run.cleanup_verified

    def cleanup_metadata(self):
        return self._run.metadata() if self._run else {"cleanup_verified": True, "state": "closed"}

    def open(self):
        with self._lifetime_lock:
            if self.is_open or self._ever_opened:
                raise serial.SerialException("helper 객체는 한 번만 열 수 있습니다.")
            framing = self._validate_settings()
            if self._port is None:
                raise serial.SerialException("포트가 없습니다.")
            self._ever_opened = True
            self._run = HelperRun(self.helper, port=self._port, on_data=self._on_data, on_error=self._on_error,
                                  on_response=self._on_response, **self._run_kwargs)
            try:
                self._run.start(deadline=time.monotonic() + 5)
                if self.before_open:
                    self.before_open()
                body = struct.pack("<IBBBBBB", *framing, int(bool(self._dtr_state)), int(bool(self._rts_state)), 0)
                self._run.request("O", body, deadline=time.monotonic() + 5)
                self._framing_snapshot = framing
                with self._condition:
                    if self._disconnected:
                        raise self._disconnected
                    self.is_open = True
            except BaseException:
                self.is_open = False
                self._run.close()
                raise

    def close(self):
        with self._lifetime_lock:
            with self._condition:
                self.is_open = False
                self._disconnected = self._disconnected or serial.SerialException("helper 닫힘")
                self._condition.notify_all()
            if self._run:
                self._run.close()

    def _require_open(self):
        if not self.is_open or self._run is None:
            raise serial.PortNotOpenError()

    def _command(self, kind, body=b"", *, timeout=5.0):
        self._require_open()
        try:
            return self._run.request(kind, body, deadline=time.monotonic() + timeout)
        except BaseException:
            self.close()
            raise

    def read(self, size=1):
        if not isinstance(size, int) or not 0 <= size <= MAX_RX_BUFFER:
            raise ValueError("read 크기 오류")
        if size == 0:
            return b""
        with self._condition:
            if not self.is_open and not self._rx:
                raise serial.PortNotOpenError()
            if self._read_cancel_pending:
                self._read_cancel_pending = False
                return b""
            generation = self._cancel_read
            deadline = None if self._timeout is None else time.monotonic() + self._timeout
            result = bytearray()
            self._readers += 1
            try:
                while len(result) < size:
                    if self._rx:
                        count = min(size - len(result), len(self._rx))
                        result.extend(self._rx[:count]); del self._rx[:count]
                    if len(result) >= size or generation != self._cancel_read:
                        break
                    if self._disconnected or not self.is_open:
                        if not result:
                            raise serial.SerialException("helper 연결이 끊어졌습니다.")
                        break
                    remaining = None if deadline is None else deadline - time.monotonic()
                    if remaining is not None and remaining <= 0:
                        break
                    self._condition.wait(remaining)
                return bytes(result)
            finally:
                self._readers -= 1

    def cancel_read(self):
        with self._condition:
            self._cancel_read += 1
            if not self._readers:
                self._read_cancel_pending = True
            self._condition.notify_all()

    def write(self, data):
        data = serial.to_bytes(data)
        self._require_open()
        if len(data) > MAX_RX_BUFFER:
            raise ValueError("helper write 호출의 크기 상한은 1 MiB입니다.")
        if not data:
            return 0
        deadline = time.monotonic() + (5 if self._write_timeout is None else self._write_timeout)
        done = 0
        if not self._operation_lock.acquire(timeout=max(0, deadline - time.monotonic())):
            raise serial.SerialTimeoutException("helper write 잠금 시간 초과")
        try:
            try:
                while done < len(data):
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise serial.SerialTimeoutException("helper write 시간 초과")
                    chunk = data[done:done + MAX_WRITE]
                    milliseconds = max(1, min(30000, math.ceil(remaining * 1000)))
                    result = self._run.request("D", struct.pack("<I", milliseconds) + chunk, deadline=deadline)
                    if result["transferred"] != len(chunk):
                        raise ProtocolError("write ACK 길이 불일치")
                    done += len(chunk)
                return done
            except BaseException as exc:
                extra = getattr(exc, "data", {}).get("transferred", 0)
                if isinstance(extra, int) and 0 <= extra <= min(MAX_WRITE, len(data) - done):
                    done += extra
                exc.transferred = done
                self.close()
                raise
        finally:
            self._operation_lock.release()

    def _reconfigure_port(self):
        try:
            framing = self._validate_settings()
        except (ValueError, KeyError):
            if self.is_open:
                self.close()  # SerialBase setter가 이미 값을 바꿨으므로 모순된 열린 상태를 남기지 않는다.
            raise
        if self.is_open and framing != self._framing_snapshot:
            previous = self._framing_snapshot
            try:
                with self._operation_lock:
                    self._command("B", struct.pack("<IBBBB", *framing, 0))
                    self._framing_snapshot = framing
            except BaseException:
                if previous:
                    self._baudrate, self._bytesize = previous[:2]
                    self._parity = next(k for k, v in _PARITY.items() if v == previous[2])
                    self._stopbits = next(k for k, v in _STOP.items() if v == previous[3])
                raise

    def _update_dtr_state(self):
        with self._operation_lock:
            self._command("L", bytes((int(bool(self._dtr_state)), 255)))

    def _update_rts_state(self):
        with self._operation_lock:
            self._command("L", bytes((255, int(bool(self._rts_state)))))

    def _update_break_state(self):
        with self._operation_lock:
            self._command("K", struct.pack("<BI", int(bool(self._break_state)), 0))

    def send_break(self, duration=.25):
        if not isinstance(duration, (int, float)) or not math.isfinite(duration) or not 0 < duration <= 5:
            raise ValueError("helper break 길이는 0초 초과 5초 이하입니다.")
        with self._operation_lock:
            self._command("K", struct.pack("<BI", 2, math.ceil(duration * 1000)), timeout=min(6, duration + 1))

    def reset_input_buffer(self):
        with self._operation_lock:
            self._require_open()
            with self._condition:
                self._rx.clear(); self._reset_pending = True
            try:
                self._command("P", struct.pack("<BI", 0, 5000))
            finally:
                with self._condition:
                    self._reset_pending = False

    def reset_output_buffer(self):
        with self._operation_lock:
            self._command("P", struct.pack("<BI", 1, 5000))

    def flush(self):
        """Windows driver queue fence. 마지막 wire bit의 전송 완료를 뜻하지 않는다."""
        with self._operation_lock:
            self._command("P", struct.pack("<BI", 2, 5000))

    @property
    def in_waiting(self):
        with self._condition:
            return len(self._rx)

    def _status(self):
        with self._operation_lock:
            return self._command("S")

    @property
    def out_waiting(self): return self._status()["tx_pending"]
    @property
    def cts(self): return bool(self._status()["modem"] & 1)
    @property
    def dsr(self): return bool(self._status()["modem"] & 2)
    @property
    def ri(self): return bool(self._status()["modem"] & 4)
    @property
    def cd(self): return bool(self._status()["modem"] & 8)

    def fileno(self):
        raise io.UnsupportedOperation("Windows helper에는 POSIX tty fd가 없습니다.")
