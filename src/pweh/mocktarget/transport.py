"""시뮬레이터 전송 계층: PTY(원시 모드 + 보드레이트 에뮬레이션)와 TCP(pyserial ``socket://``).

- PTY: ``os.openpty()`` 로 만든 양쪽 끝을 모두 원시(raw) 모드로 둔다. 에코/CRLF 변환은 pty 계층이 아니라
  시뮬레이터(U-Boot/ash 흉내)가 직접 한다. 클라이언트가 슬레이브에 설정한 termios 속도가 기기 보드레이트와
  다르면, 출력은 실제 UART 수신기가 잘못된 속도로 샘플링했을 때와 같은 결정적 쓰레기 바이트로 바꾸고 입력은 버린다.
- TCP: 여러 클라이언트를 받아 출력은 모두에게 보내고 입력은 어느 쪽이든 받는다. 보드레이트 개념 없음.
  IPv4 루프백 주소(127.0.0.0/8, localhost)에만 바인드한다(IPv6 주소는 거부 — AF_INET 전용). 그 밖(0.0.0.0, 빈 문자열,
  LAN 주소)은 ``allow_lan=True`` 일 때만(인증 없는 콘솔이 LAN 에 열린다 — 브리지 모드 WSL 이면 LAN 전체; port-routing 설계 G13).
- 연결된 수신자가 없거나 너무 느리면 출력은 버려진다(실제 UART 와 같다). 버린 바이트 수는 통계로 남긴다.
"""

from __future__ import annotations

import contextlib
import errno
import fcntl
import logging
import os
import select
import socket
import struct
import termios
import threading
import time
import tty
from collections import deque
from typing import Callable

from ..ports import check_listen_host

log = logging.getLogger("pweh.mocktarget")

# termios 속도 상수 → 정수 보드레이트
BAUD_CONSTANTS: dict[int, int] = {}
for _name in dir(termios):
    if _name.startswith("B") and _name[1:].isdigit():
        BAUD_CONSTANTS[getattr(termios, _name)] = int(_name[1:])
BAUD_TO_CONSTANT = {v: k for k, v in BAUD_CONSTANTS.items()}


def uart_misread(data: bytes, tx_baud: int, rx_baud: int, *, frame_bits: int = 10) -> bytes:
    """``tx_baud`` 로 보낸 8N1 바이트열을 ``rx_baud`` 로 수신했을 때 받게 되는 바이트열 (결정적).

    비트 단위 시뮬레이션: 송신 신호(시작 비트 0, 데이터 8비트 LSB 먼저, 정지 비트 1, 버스트 앞뒤는 idle=1)를
    만들고, 수신기는 하강 에지에서 시작해 rx 비트 폭의 중앙에서 샘플링한다. 시작 비트 위치가 1 이면 잡음으로
    보고 다시 기다린다. 정지 비트 오류(프레이밍 오류)여도 리눅스 원시 모드처럼 바이트를 그대로 전달한다.
    """
    if not data or tx_baud <= 0 or rx_baud <= 0:
        return b""
    if tx_baud == rx_baud:
        return bytes(data)
    bits: list[int] = []
    for b in data:
        bits.append(0)
        bits.extend((b >> i) & 1 for i in range(8))
        bits.append(1)
    nbits = len(bits)
    t_tx = 1.0 / tx_baud
    t_rx = 1.0 / rx_baud
    end_time = nbits * t_tx

    def level(t: float) -> int:
        idx = int(t / t_tx)
        if idx < 0 or idx >= nbits:
            return 1
        return bits[idx]

    out = bytearray()
    t = 0.0
    idx = 0
    while True:
        # 다음 1→0 전이(비트 경계)를 찾는다
        idx = max(idx, int(t / t_tx + 1e-9))
        found = None
        while idx < nbits:
            prev = bits[idx - 1] if idx > 0 else 1
            if prev == 1 and bits[idx] == 0 and idx * t_tx >= t - 1e-12:
                found = idx * t_tx
                break
            idx += 1
        if found is None:
            break
        start = found
        if level(start + 0.5 * t_rx) != 0:
            t = start + t_tx * 0.999
            idx += 1
            continue
        value = 0
        for i in range(8):
            if level(start + (1.5 + i) * t_rx):
                value |= 1 << i
        out.append(value)
        stop_t = start + 9.5 * t_rx
        t = stop_t
        if stop_t > end_time + 10 * t_rx:
            break
    return bytes(out)


class _Writer:
    """출력 큐 → fd/소켓. 수신자가 막혀 있으면 ``drop_timeout`` 뒤 버린다."""

    def __init__(self) -> None:
        self.queue: deque[bytes] = deque()
        self.cond = threading.Condition()
        self.dropped = 0
        self.written = 0
        self.closed = False

    def put(self, data: bytes) -> None:
        if not data:
            return
        with self.cond:
            if self.closed:
                return
            self.queue.append(bytes(data))
            self.cond.notify()

    def get(self, timeout: float = 0.2) -> bytes | None:
        with self.cond:
            if not self.queue and not self.closed:
                self.cond.wait(timeout)
            if not self.queue:
                return None
            return self.queue.popleft()

    def pending(self) -> int:
        with self.cond:
            return sum(len(x) for x in self.queue)

    def close(self) -> None:
        with self.cond:
            self.closed = True
            self.cond.notify_all()


class PtyTransport:
    """원시 모드 PTY. ``start()`` 가 슬레이브 경로를 돌려준다."""

    kind = "pty"

    def __init__(self, *, on_input: Callable[[bytes], None], device_baud: Callable[[], int],
                 on_event: Callable[[dict], None] | None = None, link: str | None = None,
                 drop_timeout: float = 0.5, stale_timeout: float = 1.0) -> None:
        self._on_input = on_input
        self._device_baud = device_baud
        self._on_event = on_event or (lambda ev: None)
        self._link = link
        self._drop_timeout = drop_timeout
        self._stale_timeout = stale_timeout
        self._last_inq = 0
        self._last_progress = time.monotonic()
        self.master_fd: int | None = None
        self.slave_fd: int | None = None
        self.slave_path: str | None = None
        self._writer = _Writer()
        self._stop = threading.Event()
        self._threads: list[threading.Thread] = []
        self._last_mismatch_report = 0.0
        self.rx_dropped = 0

    # ------------------------------------------------------------------
    def start(self) -> str:
        master, slave = os.openpty()
        try:
            for fd in (master, slave):
                tty.setraw(fd, termios.TCSANOW)
            attrs = termios.tcgetattr(slave)
            const = BAUD_TO_CONSTANT.get(self._device_baud(), termios.B115200)
            attrs[4] = attrs[5] = const
            termios.tcsetattr(slave, termios.TCSANOW, attrs)
            os.set_blocking(master, False)
        except Exception:
            os.close(master)
            os.close(slave)
            raise
        self.master_fd, self.slave_fd = master, slave
        self.slave_path = os.ttyname(slave)
        if self._link:
            with contextlib.suppress(FileNotFoundError):
                if os.path.islink(self._link):
                    os.unlink(self._link)
            os.symlink(self.slave_path, self._link)
        for target, name in ((self._reader_loop, "pty-reader"), (self._writer_loop, "pty-writer")):
            th = threading.Thread(target=target, name=f"pweh-mock-{name}", daemon=True)
            th.start()
            self._threads.append(th)
        return self.slave_path

    def stop(self) -> None:
        self._stop.set()
        self._writer.close()
        for th in self._threads:
            th.join(timeout=2.0)
        for fd in (self.master_fd, self.slave_fd):
            if fd is not None:
                with contextlib.suppress(OSError):
                    os.close(fd)
        self.master_fd = self.slave_fd = None
        if self._link:
            with contextlib.suppress(OSError):
                if os.path.islink(self._link):
                    os.unlink(self._link)

    def write(self, data: bytes) -> None:
        self._writer.put(data)

    def pending(self) -> int:
        return self._writer.pending()

    # ------------------------------------------------------------------
    def client_baud(self) -> int | None:
        """클라이언트가 슬레이브에 설정한 출력 속도 (알 수 없으면 None)."""
        if self.slave_fd is None:
            return None
        try:
            attrs = termios.tcgetattr(self.slave_fd)
        except termios.error:
            return None
        return BAUD_CONSTANTS.get(attrs[5])

    def baud_matches(self) -> bool:
        cb = self.client_baud()
        return cb is None or cb == self._device_baud()

    def _report_mismatch(self, direction: str) -> None:
        now = time.monotonic()
        if now - self._last_mismatch_report > 1.0:
            self._last_mismatch_report = now
            self._on_event({"type": "baud_mismatch", "direction": direction,
                            "client_baud": self.client_baud(), "device_baud": self._device_baud()})

    def _reader_loop(self) -> None:
        assert self.master_fd is not None
        fd = self.master_fd
        while not self._stop.is_set():
            try:
                r, _, _ = select.select([fd], [], [], 0.1)
            except (OSError, ValueError):
                break
            if not r:
                continue
            try:
                data = os.read(fd, 4096)
            except BlockingIOError:
                continue
            except OSError as exc:
                if exc.errno == errno.EIO:
                    time.sleep(0.05)
                    continue
                break
            if not data:
                time.sleep(0.02)
                continue
            if not self.baud_matches():
                # 잘못된 속도로 보낸 입력은 기기 쪽에서 해석 불가 → 버림
                self.rx_dropped += len(data)
                self._report_mismatch("rx")
                continue
            try:
                self._on_input(data)
            except Exception:  # pragma: no cover - 기기 쪽 오류가 전송 스레드를 죽이지 않게
                log.exception("mock device input handler failed")

    def _slave_inq(self) -> int:
        """아직 클라이언트가 읽지 않은 바이트 수 (슬레이브 입력 큐)."""
        if self.slave_fd is None:
            return 0
        try:
            return struct.unpack("i", fcntl.ioctl(self.slave_fd, termios.FIONREAD, b"\0\0\0\0"))[0]
        except OSError:
            return 0

    def _check_stale(self) -> None:
        """읽는 사람이 없어 오래 쌓인 출력은 버린다 (닫힌 시리얼 포트로 들어온 데이터가 사라지는 것과 같다).

        그래서 나중에 포트를 연 클라이언트는 오래된 부팅 로그 대신 새 출력만 받는다 (최대 stale_timeout 초 분량).
        """
        now = time.monotonic()
        inq = self._slave_inq()
        if inq == 0 or inq < self._last_inq:
            self._last_progress = now
        self._last_inq = inq
        if inq > 0 and now - self._last_progress > self._stale_timeout:
            if self.slave_fd is not None:
                with contextlib.suppress(termios.error, OSError):
                    termios.tcflush(self.slave_fd, termios.TCIFLUSH)
            self._writer.dropped += inq
            self._last_inq = 0
            self._last_progress = now

    def _writer_loop(self) -> None:
        while not self._stop.is_set():
            chunk = self._writer.get()
            self._check_stale()
            if chunk is None:
                continue
            cb = self.client_baud()
            db = self._device_baud()
            if cb is not None and cb != db:
                chunk = uart_misread(chunk, db, cb)
                self._report_mismatch("tx")
            self._write_all(chunk)

    def _write_all(self, data: bytes) -> None:
        fd = self.master_fd
        if fd is None:
            return
        view = memoryview(data)
        deadline = time.monotonic() + self._drop_timeout
        while len(view) and not self._stop.is_set():
            try:
                n = os.write(fd, view)
                view = view[n:]
                self._writer.written += n
                deadline = time.monotonic() + self._drop_timeout
                continue
            except BlockingIOError:
                pass
            except OSError as exc:
                if exc.errno not in (errno.EAGAIN, errno.EIO):
                    log.debug("pty write error: %s", exc)
                    self._writer.dropped += len(view)
                    return
            if time.monotonic() > deadline:
                # 아무도 읽지 않음 → 실제 UART 처럼 데이터 손실. 오래된 수신 버퍼도 비운다.
                self._writer.dropped += len(view)
                if self.slave_fd is not None:
                    with contextlib.suppress(termios.error, OSError):
                        termios.tcflush(self.slave_fd, termios.TCIFLUSH)
                return
            try:
                select.select([], [fd], [], 0.05)
            except (OSError, ValueError):
                return

    def info(self) -> dict:
        return {"kind": "pty", "pty": self.slave_path, "link": self._link, "client_baud": self.client_baud(),
                "tx_written": self._writer.written, "tx_dropped": self._writer.dropped, "rx_dropped": self.rx_dropped}


class TcpTransport:
    """TCP 서버 (pyserial ``socket://host:port`` 로 접속)."""

    kind = "tcp"

    def __init__(self, *, on_input: Callable[[bytes], None], on_event: Callable[[dict], None] | None = None,
                 host: str = "127.0.0.1", port: int = 0, drop_timeout: float = 0.5, allow_lan: bool = False) -> None:
        self._on_input = on_input
        self._on_event = on_event or (lambda ev: None)
        self.host = host
        self.port = port
        self.allow_lan = allow_lan
        self.lan_exposed = False  # start() 가 루프백이 아닌 주소에 바인드하면 True
        self._drop_timeout = drop_timeout
        self._server: socket.socket | None = None
        self._clients: list[socket.socket] = []
        self._clients_lock = threading.Lock()
        self._writer = _Writer()
        self._stop = threading.Event()
        self._threads: list[threading.Thread] = []

    def start(self) -> tuple[str, int]:
        # 소켓을 만들기 전에: 루프백이 아니면 allow_lan 없이는 ValidationFailed (G13)
        self.lan_exposed = check_listen_host(self.host, allow_lan=self.allow_lan)
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind((self.host, self.port))
        srv.listen(4)
        srv.settimeout(0.2)
        self._server = srv
        self.host, self.port = srv.getsockname()[:2]
        for target, name in ((self._accept_loop, "tcp-accept"), (self._writer_loop, "tcp-writer")):
            th = threading.Thread(target=target, name=f"pweh-mock-{name}", daemon=True)
            th.start()
            self._threads.append(th)
        return self.host, self.port

    @property
    def url(self) -> str:
        return f"socket://{self.host}:{self.port}"

    def stop(self) -> None:
        self._stop.set()
        self._writer.close()
        if self._server is not None:
            with contextlib.suppress(OSError):
                self._server.close()
        with self._clients_lock:
            for c in self._clients:
                with contextlib.suppress(OSError):
                    c.shutdown(socket.SHUT_RDWR)
                with contextlib.suppress(OSError):
                    c.close()
            self._clients.clear()
        for th in self._threads:
            th.join(timeout=2.0)

    def write(self, data: bytes) -> None:
        self._writer.put(data)

    def pending(self) -> int:
        return self._writer.pending()

    def _accept_loop(self) -> None:
        assert self._server is not None
        while not self._stop.is_set():
            try:
                conn, addr = self._server.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            conn.settimeout(self._drop_timeout)
            with self._clients_lock:
                self._clients.append(conn)
            self._on_event({"type": "tcp_client_connected", "peer": f"{addr[0]}:{addr[1]}"})
            th = threading.Thread(target=self._client_loop, args=(conn,), name="pweh-mock-tcp-client", daemon=True)
            th.start()

    def _client_loop(self, conn: socket.socket) -> None:
        while not self._stop.is_set():
            try:
                r, _, _ = select.select([conn], [], [], 0.2)
                if not r:
                    continue
                data = conn.recv(4096)
            except (OSError, ValueError):
                break
            if not data:
                break
            try:
                self._on_input(data)
            except Exception:  # pragma: no cover
                log.exception("mock device input handler failed")
        self._drop_client(conn)

    def _drop_client(self, conn: socket.socket) -> None:
        with self._clients_lock:
            if conn in self._clients:
                self._clients.remove(conn)
                self._on_event({"type": "tcp_client_disconnected"})
        with contextlib.suppress(OSError):
            conn.close()

    def _writer_loop(self) -> None:
        while not self._stop.is_set():
            chunk = self._writer.get()
            if chunk is None:
                continue
            with self._clients_lock:
                clients = list(self._clients)
            if not clients:
                self._writer.dropped += len(chunk)
                continue
            for c in clients:
                try:
                    c.sendall(chunk)
                    self._writer.written += len(chunk)
                except (OSError, socket.timeout):
                    self._writer.dropped += len(chunk)
                    self._drop_client(c)

    def info(self) -> dict:
        with self._clients_lock:
            n = len(self._clients)
        return {"kind": "tcp", "url": self.url, "host": self.host, "port": self.port, "clients": n,
                "tx_written": self._writer.written, "tx_dropped": self._writer.dropped}


__all__ = ["BAUD_CONSTANTS", "PtyTransport", "TcpTransport", "uart_misread"]
