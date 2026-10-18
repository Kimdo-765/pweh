"""pweh.mocktarget 테스트 fixture. 헬퍼는 helpers.py (다른 테스트 패키지에서도 import 가능)."""

from __future__ import annotations

from typing import Any, Iterator

import pytest
import serial

from pweh.mocktarget import MockDevice

from .helpers import Console, make_device, parse_hexdump_c, tool_path  # noqa: F401  (기존 import 경로 호환)


@pytest.fixture
def device_factory() -> Iterator[Any]:
    devices: list[MockDevice] = []
    ports: list[serial.SerialBase] = []

    def factory(profile: str = "hisilicon-like", *, baud: int = 115200, power: bool = True, tcp: bool = False,
                **kw: Any) -> tuple[MockDevice, Console]:
        dev = make_device(profile, **kw)
        devices.append(dev)
        if tcp:
            host, port = dev.start_tcp()
            sp = serial.serial_for_url(f"socket://{host}:{port}", timeout=0.05)
        else:
            path = dev.start_pty()
            sp = serial.Serial(path, baud, timeout=0.05)
        ports.append(sp)
        con = Console(sp, dev)
        if power:
            dev.power_on()
        return dev, con

    yield factory
    for sp in ports:
        try:
            sp.close()
        except Exception:
            pass
    for dev in devices:
        assert dev.crashed is None, dev.crashed
        dev.stop()


@pytest.fixture(params=["hisilicon-like", "ingenic-like"])
def profile_name(request: Any) -> str:
    return request.param


