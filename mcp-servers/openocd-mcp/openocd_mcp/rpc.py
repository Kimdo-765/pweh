"""OpenOCD TCL RPC 클라이언트.

프로토콜 (src/server/tcl_server.c, 실측: INSTALL_REPORT.md / docs/references/openocd-tcl-rpc.md):
- 요청: UTF-8 Tcl 스크립트 + 0x1a. 응답: Jim 결과 문자열 + 0x1a. 오류 플래그/길이 헤더 없음.
- 한 연결에서 여러 명령을 순서대로 보낼 수 있고, 연결 수 제한은 없다 (모든 연결이 같은 인터프리터 공유).
- OpenOCD 는 단일 스레드라 긴 명령(dump_image 등)이 끝날 때까지 다른 연결에도 응답하지 않는다.
- 프로토콜 수준의 취소는 없다. 시간 초과 시 소켓을 닫아도 OpenOCD 쪽 명령은 계속 실행된다.
- ``tcl notifications on`` 이 켜진 연결에는 ``type target_... \\r\\n\\x1a`` 비동기 프레임이 끼어든다 → 건너뛴다.
- ``shutdown``/``exit`` 는 catch 로 잡히지 않고 빈 응답(0x1a) 후 연결이 닫힌다.

결과 문자열 안에 0x1a 가 섞이면(예: 대상 메모리 문자열을 echo) 프레임 경계가 어긋날 수 있다. 봉투 응답은 항상
완결된 Tcl 리스트이므로, 리스트가 완결되지 않았으면 0x1a 를 데이터로 보고 다음 0x1a 까지 더 읽는다.
그래도 남는 바이트가 있으면 연결을 버리고 다음 요청에서 다시 연결한다.
"""

from __future__ import annotations

import logging
import select
import socket
import threading
import time
from typing import Callable

from pweh.errors import DeviceError, TimeoutExpired

from . import tcl

log = logging.getLogger("pweh.openocd")

TERM = b"\x1a"
MAX_RESPONSE_BYTES = 64 * 1024 * 1024
_SLICE = 0.2  # 수신 대기 조각 (취소 확인 주기)


class TclConnectionClosed(DeviceError):
    """OpenOCD 가 연결을 닫음 (프로세스 종료, shutdown/exit 등)."""

    code = "connection_closed"


class RequestCancelled(Exception):
    """작업 취소로 응답 대기를 중단함 (OpenOCD 쪽 명령은 계속 실행될 수 있음)."""


class TclRpcClient:
    def __init__(self, host: str, port: int, *, connect_timeout: float = 5.0, name: str = "rpc") -> None:
        self.host = host
        self.port = int(port)
        self.connect_timeout = connect_timeout
        self.name = name
        self._sock: socket.socket | None = None
        self._buf = b""
        self._lock = threading.RLock()
        self._poisoned = False
        self.requests = 0
        self.last_error: str | None = None

    # ------------------------------------------------------------------
    @property
    def connected(self) -> bool:
        return self._sock is not None

    def connect(self) -> None:
        with self._lock:
            self._close_locked()
            try:
                s = socket.create_connection((self.host, self.port), timeout=self.connect_timeout)
            except OSError as exc:
                self.last_error = str(exc)
                raise DeviceError(
                    f"OpenOCD TCL 포트에 연결할 수 없습니다: {self.host}:{self.port} ({exc})",
                    hint="OpenOCD 가 실행 중인지, tcl 포트 번호가 맞는지 확인하세요 (openocd_status).",
                ) from exc
            s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            self._sock = s
            self._buf = b""
            self._poisoned = False

    def close(self) -> None:
        with self._lock:
            self._close_locked()

    def _close_locked(self) -> None:
        if self._sock is not None:
            try:
                self._sock.close()
            except OSError:
                pass
        self._sock = None
        self._buf = b""

    def _stale_or_closed(self) -> bool:
        """보내기 전에 소켓 상태 확인: 상대가 닫았거나(EOF) 알림이 아닌 늦은 바이트가 남아 있으면 True (→ 재연결).

        늦게 도착한 이전 응답 조각을 다음 요청의 응답으로 오인하지 않기 위해, 대기 중인 바이트를 모두 읽어
        ``type target_...`` 알림 프레임뿐이면 버리고, 그 밖의 데이터가 있으면 연결을 새로 만든다.
        """
        s = self._sock
        if s is None:
            return True
        pending = b""
        try:
            while True:
                r, _, _ = select.select([s], [], [], 0)
                if not r:
                    break
                data = s.recv(262144)
                if not data:
                    return True
                pending += data
                if len(pending) > MAX_RESPONSE_BYTES:
                    return True
        except OSError:
            return True
        if not pending:
            return False
        frames = pending.split(TERM)
        complete, tail = frames[:-1], frames[-1]
        if tail or not all(tcl.is_notification(f.decode("utf-8", errors="replace")) for f in complete):
            log.warning("[%s] %d stale bytes on socket before request; reconnecting", self.name, len(pending))
            return True
        return False

    # ------------------------------------------------------------------
    def request(
        self,
        script: str,
        *,
        timeout: float,
        cancel_check: Callable[[], bool] | None = None,
        expect_list: bool = True,
    ) -> str:
        """스크립트를 보내고 응답 프레임(0x1a 제외)을 돌려준다."""
        tcl.validate_request(script)
        with self._lock:
            if self._sock is None or self._poisoned or self._stale_or_closed():
                self.connect()
            assert self._sock is not None
            # 이전 요청이 남긴(알림 외) 찌꺼기는 버린다
            self._buf = b""
            try:
                self._sock.sendall(script.encode("utf-8") + TERM)
            except OSError as exc:
                self._close_locked()
                raise TclConnectionClosed(f"OpenOCD 로 명령을 보내지 못했습니다 ({exc})") from exc
            self.requests += 1
            deadline = time.monotonic() + max(0.1, float(timeout))
            parts: list[bytes] = []
            while True:
                frame = self._read_frame(deadline, cancel_check)
                text = frame.decode("utf-8", errors="replace")
                if not parts and tcl.is_notification(text):
                    log.debug("[%s] notification skipped: %r", self.name, text[:80])
                    continue
                parts.append(frame)
                joined = TERM.join(parts).decode("utf-8", errors="replace")
                if not expect_list or joined == "" or tcl.list_complete(joined):
                    break
                # 리스트가 덜 끝났다 → 0x1a 가 데이터 안에 있었던 것으로 보고 계속 읽는다
                if sum(len(p) for p in parts) > MAX_RESPONSE_BYTES:
                    self._close_locked()
                    raise DeviceError("OpenOCD 응답이 너무 큽니다 (64 MiB 초과)")
            if self._buf:
                # 같은 요청 뒤에 남은 바이트 = 프레임 경계 의심 → 연결을 버린다
                rest = self._buf.decode("utf-8", errors="replace")
                if not all(tcl.is_notification(x) for x in rest.split("\x1a") if x):
                    log.warning("[%s] unexpected trailing bytes after response (%d bytes); reconnecting next time", self.name, len(self._buf))
                    self._poisoned = True
                self._buf = b""
            return joined

    def _read_frame(self, deadline: float, cancel_check: Callable[[], bool] | None) -> bytes:
        assert self._sock is not None
        while True:
            idx = self._buf.find(TERM)
            if idx >= 0:
                frame = self._buf[:idx]
                self._buf = self._buf[idx + 1 :]
                return frame
            if len(self._buf) > MAX_RESPONSE_BYTES:
                self._close_locked()
                raise DeviceError("OpenOCD 응답이 너무 큽니다 (64 MiB 초과)")
            if cancel_check is not None and cancel_check():
                self._close_locked()
                raise RequestCancelled()
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                partial = len(self._buf)
                self._close_locked()
                raise TimeoutExpired(
                    f"OpenOCD 응답 시간 초과 (수신 {partial} 바이트)",
                    hint="OpenOCD 는 단일 스레드라 긴 명령이 끝날 때까지 응답하지 않습니다. 명령은 OpenOCD 안에서 계속 실행 중일 수 있으니 "
                    "잠시 후 openocd_status 로 상태를 확인하세요.",
                )
            self._sock.settimeout(min(_SLICE, max(0.01, remaining)))
            try:
                chunk = self._sock.recv(262144)
            except socket.timeout:
                continue
            except OSError as exc:
                self._close_locked()
                raise TclConnectionClosed(f"OpenOCD 연결 오류: {exc}") from exc
            if not chunk:
                partial = self._buf
                self._close_locked()
                if partial:
                    raise TclConnectionClosed(f"응답 도중 OpenOCD 가 연결을 닫았습니다 (부분 수신 {len(partial)} 바이트)")
                raise TclConnectionClosed("OpenOCD 가 연결을 닫았습니다 (프로세스 종료 또는 shutdown/exit)")
            self._buf += chunk

    # ------------------------------------------------------------------
    def call_raw(self, cmd: str, *, timeout: float, cancel_check: Callable[[], bool] | None = None) -> tcl.TclReply:
        """원시 명령을 ``list [catch {capture {CMD}} r] $r`` 봉투로 실행."""
        frame = self._request_allow_close(tcl.wrap_raw(cmd), timeout=timeout, cancel_check=cancel_check)
        return tcl.parse_raw_reply(frame)

    def call(self, cmd: str, *, timeout: float, cancel_check: Callable[[], bool] | None = None) -> tcl.TclReply:
        """데이터 봉투로 실행: 결과(output)와 capture 로그(log)를 분리해서 받는다."""
        frame = self._request_allow_close(tcl.wrap_data(cmd), timeout=timeout, cancel_check=cancel_check)
        return tcl.parse_data_reply(frame)

    def _request_allow_close(self, script: str, *, timeout: float, cancel_check: Callable[[], bool] | None) -> str:
        frame = self.request(script, timeout=timeout, cancel_check=cancel_check, expect_list=True)
        if frame == "":
            # shutdown/exit: 빈 응답 후 EOF — 다음 요청은 새로 연결한다
            with self._lock:
                self._close_locked()
        return frame

    def send_unwrapped(self, cmd: str, *, timeout: float) -> str:
        """봉투 없이 보낸다 (shutdown 처럼 catch 로 잡히지 않는 명령용)."""
        return self.request(cmd, timeout=timeout, expect_list=False)


__all__ = ["RequestCancelled", "TclConnectionClosed", "TclRpcClient"]
