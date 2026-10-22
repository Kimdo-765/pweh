"""Windows Tigard JTAG 시작의 고정 입력. 파일·환경·장치를 읽지 않는다."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json

from pweh.errors import ValidationFailed


@dataclass(frozen=True)
class TigardProfile:
    """고정 cfg와 실행 의미를 결속한다. bundle·OS 관찰·장치 권한을 증명하지 않는다."""

    profile_id: str
    profile_sha256: str
    release_id: str
    interface_ref: str
    interface_relative_path: str
    interface_sha256: str
    interface_size: int
    transport: str
    adapter_speed_khz: int
    vid: str
    pid: str
    device_desc: str
    channel: int
    whole_device: bool
    initialization: str
    effect: str
    queries: tuple[str, ...]


_SPEC = {
    "profile_id": "tigard-jtag-v1",
    "release_id": "xpack-0.12.0-7-win32-x64",
    "interface_ref": "interface/ftdi/tigard.cfg",
    "interface_relative_path": "openocd/scripts/interface/ftdi/tigard.cfg",
    "interface_sha256": "d463833c32a5abb7545d7c645ad6110a63366809f0f7960a63f0be9dcc587b73",
    "interface_size": 506,
    "transport": "jtag",
    "adapter_speed_khz": 100,
    "vid": "0403",
    "pid": "6010",
    "device_desc": "Tigard V1.1",
    "channel": 1,
    "whole_device": True,
    "initialization": "guarded-init",
    "effect": "active-jtag-init-autoprobe",
    "queries": ("version", "scan_chain", "targets"),
}
TIGARD_PROFILE = TigardProfile(
    **_SPEC,
    profile_sha256=hashlib.sha256(
        (json.dumps(_SPEC, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n").encode("ascii")
    ).hexdigest(),
)
del _SPEC


def _invalid() -> ValidationFailed:
    return ValidationFailed(
        "Windows Tigard profile에는 고정 interface·jtag·100kHz·tcl_port=0 및 빈 추가 입력만 허용합니다.",
        code="openocd_tigard_profile_invalid",
    )


def validate_tigard_start(*, windows_profile, interface_cfg, target_cfg=None,
                          extra_cfgs=None, extra_commands=None, transport=None,
                          adapter_speed_khz=None, tcl_port=6666) -> TigardProfile:
    """정확 타입·상수만 대조한다. 경로 정규화·장치 선택·프로세스 실행을 하지 않는다."""
    if type(windows_profile) is not str:
        raise _invalid()
    if windows_profile != TIGARD_PROFILE.profile_id:
        raise ValidationFailed("지원하지 않는 Windows OpenOCD profile입니다.",
                               code="openocd_windows_profile_unsupported")
    if type(interface_cfg) is not str or interface_cfg != TIGARD_PROFILE.interface_ref:
        raise _invalid()
    for items in (target_cfg, extra_cfgs, extra_commands):
        if items is not None and (type(items) is not list or len(items) != 0):
            raise _invalid()
    if transport is not None and (type(transport) is not str or transport != TIGARD_PROFILE.transport):
        raise _invalid()
    if adapter_speed_khz is not None and (
            type(adapter_speed_khz) is not int or adapter_speed_khz != TIGARD_PROFILE.adapter_speed_khz):
        raise _invalid()
    if type(tcl_port) is not int or tcl_port != 0:
        raise _invalid()
    return TIGARD_PROFILE
