"""고정 argv를 확인하는 합성 전력 CSV 생산자. 실제 장치·라이브러리는 열지 않는다."""
from __future__ import annotations

import os
import signal
import sys
import time

CSV = (b"2026-01-01,00:00:00,100000000,101000000,10000.00,1,-22.50,-24.00\n"
       b"2026-01-01,00:00:01,100000000,101000000,10000.00,1,-inf,-20.25\n")
TAIL = ("-d", "0", "-f", "100000000:101000000:10000", "-i", "1", "-e", "2", "-")


def _write(fd: int, data: bytes) -> None:
    while data:
        count = os.write(fd, data)
        if count <= 0:
            raise RuntimeError("합성 출력 실패")
        data = data[count:]


def main() -> int:
    signal.alarm(20)
    if len(sys.argv) < 3 or tuple(sys.argv[2:]) != TAIL:
        return 3
    mode = sys.argv[1]
    if mode == "stall":
        time.sleep(15)
        return 0
    if mode == "ignore-term":
        signal.signal(signal.SIGTERM, signal.SIG_IGN)
        time.sleep(15)
        return 0
    if mode == "nonzero":
        _write(1, CSV)
        _write(2, b"PRIVATE synthetic failure\n")
        return 7
    if mode == "stdout-limit":
        _write(1, b"x" * ((1 << 20) + 1))
        return 0
    if mode == "stdout-exact":
        _write(1, b"x" * (1 << 20))
        return 0
    if mode == "stderr-limit":
        _write(1, CSV)
        _write(2, b"x" * ((16 << 10) + 1))
        return 0
    if mode == "stderr-exact":
        _write(1, CSV)
        _write(2, b"x" * (16 << 10))
        return 0
    if mode == "long-line":
        _write(1, b"x" * ((64 << 10) + 1) + b"\n")
        return 0
    if mode == "truncated":
        _write(1, CSV[:-1])
        return 0
    if mode == "fragmented":
        for byte in CSV:
            _write(1, bytes((byte,)))
        return 0
    if mode == "crlf":
        _write(1, CSV.replace(b"\n", b"\r\n"))
        return 0
    if mode == "stderr":
        _write(2, b"PRIVATE cancelled by timer\n")
        _write(1, CSV)
        return 0
    if mode == "fork-writer":
        _write(1, CSV)
        child = os.fork()
        if child == 0:
            signal.alarm(10)
            time.sleep(8)
            os._exit(0)
        return 0
    if mode == "normal":
        _write(1, CSV)
        return 0
    return 3


if __name__ == "__main__":
    raise SystemExit(main())
