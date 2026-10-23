"""명시 경로 쌍만 쓰는 Linux 합성 OpenOCD pipe. 실제 장치·네트워크는 없다."""
from __future__ import annotations

import argparse
import importlib.util
import json
import os
from pathlib import Path
import signal
import socket
import stat
import sys

TERM = b"\x1a"
MAX_REQUEST = MAX_MANIFEST = 64 << 10
MAX_PAIRS = 32
MODES = ("ready", "short-second", "long-second", "tcl-error-second", "eof-second",
         "stall-second", "malformed-second", "open-error")


def _no_network(*args, **kwargs):
    raise AssertionError("합성 파일 자식은 네트워크를 열지 않습니다")


socket.socket = _no_network
socket.create_connection = _no_network


def _load_interp():
    """제품 파서 대신 시험의 독립 Jim 봉투만 사용한다."""
    spec = importlib.util.spec_from_file_location(
        "_pipe_file_fixture_tcl", Path(__file__).with_name("fake_openocd.py"))
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module.Interp, module.TclError


def _write(fd, data):
    view = memoryview(data)
    while view:
        count = os.write(fd, view)
        if count <= 0:
            raise BrokenPipeError()
        view = view[count:]


def _pairs(manifest):
    """상한 있는 명시 목록만 읽고 Windows 값에서 local 경로를 추측하지 않는다."""
    with manifest.open("rb") as source:
        raw = source.read(MAX_MANIFEST + 1)
    if len(raw) > MAX_MANIFEST:
        raise ValueError()
    pairs = json.loads(raw)
    if type(pairs) is not list or len(pairs) > MAX_PAIRS:
        raise ValueError()
    found, locals_seen = {}, set()
    for row in pairs:
        if type(row) is not dict or set(row) != {"windows_path", "local_path"}:
            raise ValueError()
        win, local = row["windows_path"], row["local_path"]
        if type(win) is not str or type(local) is not str or not win or "\\" in win:
            raise ValueError()
        path = Path(local)
        if not path.is_absolute() or ".." in path.parts or path.resolve() != path:
            raise ValueError()
        path.relative_to(manifest.parent)
        if win in found or local in locals_seen:
            raise ValueError()
        found[win] = path
        locals_seen.add(local)
    return found


class _Fault(Exception):
    """완전 Tcl 오류와 구별하는 고정 transport 장애."""


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--mode", choices=MODES, default="ready")
    parser.add_argument("--pairs-file", type=Path, required=True)
    parser.add_argument("--requests-file", type=Path, required=True)
    args = parser.parse_args()
    signal.alarm(30)
    Interp, TclError = _load_interp()

    def record(kind):
        with args.requests_file.open("ab") as output:
            output.write(kind.encode("ascii") + b"\n")

    def known_path(value):
        try:
            return _pairs(args.pairs_file)[value]
        except (ValueError, KeyError, OSError, TypeError):
            raise TclError("invalid fixture path") from None

    def open_known(path, *, writing):
        try:
            before = path.lstat()
            if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
                raise ValueError()
            fd = os.open(path, (os.O_WRONLY if writing else os.O_RDONLY) | os.O_NOFOLLOW)
            try:
                after = os.fstat(fd)
                if (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino):
                    raise ValueError()
                if writing:
                    os.ftruncate(fd, 0)
                return fd
            except BaseException:
                os.close(fd)
                raise
        except (ValueError, OSError):
            raise TclError("fixture file open failed") from None

    class Peer:
        writes = 0
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
            operation = name
            if name == "flash" and values and values[0] in ("read_bank", "verify_bank"):
                operation, values = values[0], values[1:]
            if operation not in ("dump_image", "read_bank", "verify_bank"):
                record("unsupported")
                raise TclError("unsupported fixture command")
            record(operation)
            try:
                if operation == "dump_image" and len(values) == 3:
                    path_arg, address, length = values
                    address, length = int(address, 0), int(length, 0)
                    if not 0 <= address < 2**64 or address + length > 2**64:
                        raise ValueError()
                elif operation in ("read_bank", "verify_bank") and len(values) == (4 if operation == "read_bank" else 3):
                    bank, path_arg, address, *sizes = values
                    address = int(address, 0)
                    if int(bank, 0) != 0 or not 0 <= address < 4096:
                        raise ValueError()
                    length = int(sizes[0], 0) if sizes else None
                else:
                    raise ValueError()
                path = known_path(path_arg)
                if length is None:
                    length = path.stat().st_size
                if not 1 <= length <= 4096 or (operation != "dump_image" and address + length > 4096):
                    raise ValueError()
            except (ValueError, OSError):
                raise TclError("invalid fixture bounds") from None
            data = bytes((address + i) & 255 for i in range(length))
            if operation == "verify_bank":
                fd = open_known(path, writing=False)
                try:
                    actual = os.read(fd, 4097)
                finally:
                    os.close(fd)
                if actual != data:
                    raise TclError("fixture verify failed")
                return "verified"
            self.writes += 1
            if args.mode == "open-error":
                raise TclError("fixture file open failed")
            fault = self.writes == 2 and args.mode.endswith("-second")
            if fault and args.mode in ("eof-second", "stall-second", "malformed-second"):
                raise _Fault()
            if fault and args.mode == "short-second":
                data = data[:-1]
            elif fault and args.mode == "long-second":
                data += b"\x00"
            elif fault and args.mode == "tcl-error-second":
                data = data[:17]
            fd = open_known(path, writing=True)
            try:
                _write(fd, data)
            finally:
                os.close(fd)
            if fault and args.mode == "tcl-error-second":
                raise TclError("PIPE_FILE_PRIVATE_SENTINEL")
            return "written"

    interp, pending = Interp(Peer()), bytearray()
    while True:
        chunk = os.read(0, 16384)
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
                _write(1, b"0 {PIPE_FILE_PRIVATE_SENTINEL}trailer {}" + TERM)
                continue
            _write(1, reply.encode("utf-8") + TERM)
        if len(pending) > MAX_REQUEST:
            return 3


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (BrokenPipeError, ConnectionResetError):
        raise SystemExit(0)
