"""Linux pipe 시험용 합성 자식. 장치·TCP·제품 Tcl 파서는 사용하지 않는다.

실제 OpenOCD처럼 첫 요청을 받은 뒤에만 quoted 준비 표식을 내보낸다.
고의 대기 모드도 30초 뒤 종료하며, 시험에서는 항상 owner.close로 먼저 회수한다.
"""

from __future__ import annotations

import argparse
import importlib.util
import os
from pathlib import Path
import signal
import socket
import subprocess
import sys
import time

TERM = b"\x1a"
MAX_REQUEST = 4 << 20
MARKER = b"accepting 'tcl' connection from pipe"
VERSION = "Open On-Chip Debugger 0.12.0"
MODES = (
    "ready", "ready-bare", "ready-debug", "ready-crlf", "delayed-marker",
    "marker-only", "version-only", "false-marker", "unquoted-marker", "tcp-marker",
    "partial-marker", "debug-marker", "trailing-marker", "bad-version", "version-error",
    "oversize-version", "exit-after-marker", "exit-after-version", "stderr-line-limit",
    "stderr-total-limit", "stderr-tail", "stderr-errors", "term-only", "kill-only",
    "leader-exit-child-holds", "pipe-holder",
)


def _no_network(*args, **kwargs):
    raise AssertionError("pipe fixture는 네트워크를 열지 않습니다")


socket.socket = _no_network
socket.create_connection = _no_network


def _load_interp():
    """기존 합성 서버의 독립 Jim 인코더/인터프리터만 가져온다."""
    spec = importlib.util.spec_from_file_location(
        "_pipe_fixture_tcl", Path(__file__).with_name("fake_openocd.py"),
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module.Interp, module.TclError


def _write(fd: int, value: bytes) -> None:
    view = memoryview(value)
    while view:
        count = os.write(fd, view)
        if count <= 0:
            raise BrokenPipeError("fixture output closed")
        view = view[count:]


def _hold() -> None:
    while True:
        signal.pause()


def _marker(mode: str) -> bytes:
    if mode == "ready-bare":
        return MARKER + b"\n"
    if mode == "ready-debug":
        return b"Info : 17 2 server.c:298 add_service(): " + MARKER + b"\n"
    if mode == "ready-crlf":
        return b"Info : " + MARKER + b"\r\n"
    if mode == "false-marker":
        return b"Info : prefix " + MARKER + b" suffix\n"
    if mode == "unquoted-marker":
        return b"Info : accepting tcl connection from pipe\n"
    if mode == "tcp-marker":
        return b"Info : Listening on port 6666 for tcl connections\n"
    if mode == "partial-marker":
        return b"Info : " + MARKER
    if mode == "debug-marker":
        return b"Debug : " + MARKER + b"\n"
    if mode == "trailing-marker":
        return b"Info : " + MARKER + b" \n"
    return b"Info : " + MARKER + b"\n"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--mode", choices=MODES, default="ready")
    parser.add_argument("--requests-file", type=Path)
    parser.add_argument("--pid-file", type=Path)
    args = parser.parse_args()
    signal.alarm(30)
    if args.mode in {"kill-only", "pipe-holder"}:
        signal.signal(signal.SIGTERM, signal.SIG_IGN)
    if args.mode == "pipe-holder":
        if args.pid_file:
            args.pid_file.write_text(str(os.getpid()), encoding="ascii")
        _hold()
    if args.mode == "leader-exit-child-holds":
        if args.pid_file is None:
            return 2
        # 새 session을 만들지 않아 owner가 같은 그룹 자식을 정리할 수 있다.
        subprocess.Popen([
            sys.executable, "-I", str(Path(__file__).resolve()), "--mode", "pipe-holder",
            "--pid-file", str(args.pid_file),
        ], close_fds=True)
        until = time.monotonic() + 5
        while not args.pid_file.exists() and time.monotonic() < until:
            time.sleep(0.01)
        return 0

    Interp, TclError = _load_interp()

    class Peer:
        def capture(self, fn):
            return fn()

        def command(self, name, values, interp):
            if name != "version" or values:
                raise TclError("unsupported fixture command")
            if args.mode == "version-error":
                raise TclError("fixture version failed")
            if args.mode == "bad-version":
                return "PWEH synthetic unknown version"
            if args.mode == "oversize-version":
                return VERSION + "x" * 4096
            return VERSION

    interp = Interp(Peer())
    pending = bytearray()
    requests = 0
    while True:
        chunk = os.read(0, 32768)
        if not chunk:
            if args.mode in {"term-only", "kill-only"}:
                _hold()
            return 0
        pending.extend(chunk)
        while TERM in pending:
            end = pending.index(TERM)
            if end > MAX_REQUEST:
                return 3
            script = bytes(pending[:end]).decode("utf-8", errors="strict")
            del pending[:end + 1]
            requests += 1
            if args.requests_file:
                with args.requests_file.open("ab") as record:
                    record.write(b"request\n")
            if requests == 1:
                if args.mode == "stderr-line-limit":
                    _write(2, b"x" * ((16 << 10) + 1) + b"\n")
                if args.mode == "stderr-total-limit":
                    for _ in range(4097):
                        _write(2, b"x" * 4095 + b"\n")
                if args.mode == "stderr-tail":
                    _write(2, (b"tail " + b"x" * 1018 + b"\n") * 600)
                if args.mode == "stderr-errors":
                    _write(2, (b"Error: " + b"x" * 600 + b"\n") * 60)
                if args.mode not in {"version-only", "delayed-marker"}:
                    _write(2, _marker(args.mode))
                if args.mode == "exit-after-marker":
                    return 7
            if args.mode == "marker-only":
                continue
            reply = interp.eval(script)
            _write(1, reply.encode("utf-8") + TERM)
            if requests == 1 and args.mode == "delayed-marker":
                time.sleep(0.08)
                _write(2, _marker("ready"))
            if args.mode == "exit-after-version":
                return 7
        if len(pending) > MAX_REQUEST:
            return 3


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (BrokenPipeError, ConnectionResetError):
        raise SystemExit(0)
