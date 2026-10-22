"""내부 덤프용 Linux 합성 pipe 자식. version/read_memory 이외 기기 명령은 실행하지 않는다."""

from __future__ import annotations

import argparse
import importlib.util
import os
from pathlib import Path
import signal
import socket
import sys

TERM = b"\x1a"
MAX_REQUEST = 4 << 20
MODES = ("ready", "stall-second", "eof-second", "malformed-second", "utf8-second",
         "oversize-second", "unsupported-read")


def _no_network(*args, **kwargs):
    raise AssertionError("합성 pipe 자식은 네트워크를 열지 않습니다")


socket.socket = _no_network
socket.create_connection = _no_network


def _load_interp():
    """제품 파서 대신 기존 시험의 독립 Jim 봉투 구현만 사용한다."""
    spec = importlib.util.spec_from_file_location(
        "_pipe_dump_fixture_tcl", Path(__file__).with_name("fake_openocd.py"),
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
            raise BrokenPipeError()
        view = view[count:]


class _Fault(Exception):
    """정상 Tcl 오류와 구별하는 고정 transport 장애."""


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--mode", choices=MODES, default="ready")
    parser.add_argument("--requests-file", type=Path, required=True)
    args = parser.parse_args()
    signal.alarm(30)
    Interp, TclError = _load_interp()

    def record(kind: str) -> None:
        # 주소·원문 script 없이 고정 요청 종류만 남긴다.
        with args.requests_file.open("ab") as output:
            output.write(kind.encode("ascii") + b"\n")

    class Peer:
        reads = 0
        ready = False

        def capture(self, fn):
            return fn()

        def command(self, name, values, interp):
            if name == "version" and not values:
                record("version")
                if not self.ready:
                    _write(2, b"Info : accepting 'tcl' connection from pipe\n")
                    self.ready = True
                return "Open On-Chip Debugger 0.12.0"
            if name in ("mdb", "mdh", "mdw", "mdd"):
                record("md")
                raise TclError("unsupported fixture command")
            if name != "read_memory":
                record("unsupported")
                raise TclError("unsupported fixture command")
            record("read_memory")
            if len(values) != 3:
                raise TclError("invalid fixture read")
            try:
                addr, width, count = (int(value, 0) for value in values)
            except ValueError:
                raise TclError("invalid fixture read") from None
            if not 0 <= addr <= (1 << 64) - 1 or width not in (8, 32) or not 1 <= count <= 16384:
                raise TclError("invalid fixture read")
            self.reads += 1
            if args.mode == "unsupported-read":
                raise TclError('invalid command name "read_memory"')
            if self.reads == 2 and args.mode.endswith("-second"):
                raise _Fault()
            step = width // 8
            data = bytes((addr + i) & 255 for i in range(count * step))
            return " ".join(hex(int.from_bytes(data[i:i + step], "little"))
                            for i in range(0, len(data), step))

    interp = Interp(Peer())
    pending = bytearray()
    while True:
        chunk = os.read(0, 32768)
        if not chunk:
            return 0
        pending.extend(chunk)
        while TERM in pending:
            end = pending.index(TERM)
            if end > MAX_REQUEST:
                return 3
            script = bytes(pending[:end]).decode("utf-8", errors="strict")
            del pending[:end + 1]
            try:
                reply = interp.eval(script)
            except _Fault:
                if args.mode == "eof-second":
                    return 0
                if args.mode == "stall-second":
                    while True:
                        signal.pause()
                raw = {
                    "malformed-second": b"0 {PIPE_RAW_SENTINEL}trailer {}",
                    "utf8-second": b"0 {PIPE_RAW_SENTINEL\xff} {}",
                    "oversize-second": b"x" * 8192,
                }[args.mode]
                _write(1, raw + TERM)
                continue
            _write(1, reply.encode("utf-8") + TERM)
        if len(pending) > MAX_REQUEST:
            return 3


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (BrokenPipeError, ConnectionResetError):
        raise SystemExit(0)
