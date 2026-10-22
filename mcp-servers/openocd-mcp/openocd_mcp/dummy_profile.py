"""무USB·무초기화 Windows dummy 시작의 고정 입력. 파일·환경·장치를 읽지 않는다."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json

from pweh.errors import ValidationFailed


@dataclass(frozen=True)
class DummyProfile:
    """공개 시작 입력과 실제 argv를 결속하는 상수. 승인·번들 검증을 대신하지 않는다."""

    profile_id: str
    profile_sha256: str
    release_id: str
    interface_ref: str
    interface_relative_path: str
    interface_sha256: str
    interface_size: int
    transport: str
    adapter_speed_khz: int
    commands: tuple[str, ...]


_SPEC = {
    "profile_id": "dummy-noinit-v1",
    "release_id": "xpack-0.12.0-7-win32-x64",
    "interface_ref": "interface/dummy.cfg",
    "interface_relative_path": "openocd/scripts/interface/dummy.cfg",
    "interface_sha256": "6ccdaf8c3f39cd457b9687791009f32db65064268088537e3c9066d391ef6ec7",
    "interface_size": 112,
    "transport": "jtag",
    "adapter_speed_khz": 1000,
    "commands": (
        "jtag newtap tst cpu -irlen 4 -expected-id 0x5ba00477",
        "target create tst.cpu testee -chain-position tst.cpu",
        "noinit",
    ),
}
DUMMY_PROFILE = DummyProfile(
    **_SPEC,
    profile_sha256=hashlib.sha256(
        (json.dumps(_SPEC, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n").encode("ascii")
    ).hexdigest(),
)
del _SPEC


def _invalid() -> ValidationFailed:
    return ValidationFailed(
        "Windows dummy profile에는 고정 interface·jtag·1000kHz·tcl_port=0 및 빈 추가 입력만 허용합니다.",
        code="openocd_dummy_profile_invalid",
    )


def validate_dummy_start(*, windows_profile, interface_cfg, target_cfg=None,
                         extra_cfgs=None, extra_commands=None, transport=None,
                         adapter_speed_khz=None, tcl_port=6666) -> DummyProfile:
    """순수 타입·상수 대조만 한다. 사용자 경로를 해석하거나 원문을 오류에 넣지 않는다."""
    if type(windows_profile) is not str:
        raise _invalid()
    if windows_profile != DUMMY_PROFILE.profile_id:
        raise ValidationFailed("지원하지 않는 Windows OpenOCD profile입니다.",
                               code="openocd_windows_profile_unsupported")
    if type(interface_cfg) is not str or interface_cfg != DUMMY_PROFILE.interface_ref:
        raise _invalid()
    for items in (target_cfg, extra_cfgs, extra_commands):
        if items is not None and (type(items) is not list or len(items) != 0):
            raise _invalid()
    if transport is not None and (type(transport) is not str or transport != DUMMY_PROFILE.transport):
        raise _invalid()
    if adapter_speed_khz is not None and (
            type(adapter_speed_khz) is not int or adapter_speed_khz != DUMMY_PROFILE.adapter_speed_khz):
        raise _invalid()
    if type(tcl_port) is not int or tcl_port != 0:
        raise _invalid()
    return DUMMY_PROFILE
