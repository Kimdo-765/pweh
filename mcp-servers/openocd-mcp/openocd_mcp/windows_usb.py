"""Tigard의 고정 Present graph 읽기와 전체 잠금 범위 재확인.

PnP 관찰은 USB claim/포트 open이나 실제 CLI 선택 성공을 증명하지 않는다.
순수 usb_binding 모듈은 그대로 두고 운영 질의는 이 좁은 접점에만 둔다.
"""
from __future__ import annotations

import time

from pweh import portidentity as I, usb_binding as U
from pweh.errors import PwehError

from .tigard_profile import TIGARD_PROFILE, TigardProfile


def _fail(code="usb_scope_unknown"):
    raise PwehError("Tigard USB 관찰 범위를 확인하지 못했습니다.", code=code) from None


def _reason(exc, *, fresh=False):
    reason = exc.reason if isinstance(exc, I._WindowsScopeError) else None
    if type(exc) is ValueError and len(exc.args) == 1 and type(exc.args[0]) is str:
        reason = exc.args[0]
    if reason in ("pnp_scope_time_limit", "pnp_timeout_windows_child_unverified"):
        return "usb_scope_timeout"
    if reason in ("pnp_scope_cancelled", "pnp_query_cancelled"):
        return "usb_scope_cancelled"
    return "usb_scope_changed" if fresh else "usb_scope_unknown"


def _read_scope(config, *, deadline, cancel):
    """시험은 이 접점을 교체한다. 운영에서는 두 complete graph 고정 질의만 허용한다."""
    return I._windows_output(config, script=I.PS_USB_SCOPE, deadline=deadline, cancel=cancel)


def _prepare(profile, deadline, cancel):
    if (type(profile) is not TigardProfile or profile != TIGARD_PROFILE
            or (cancel is not None and not callable(cancel))):
        _fail("usb_scope_invalid")
    try:
        end = I._windows_scope_deadline(deadline)
    except Exception:
        _fail("usb_scope_invalid")
    return end


def _tick(end, cancel):
    if time.monotonic() >= end:
        _fail("usb_scope_timeout")
    I._windows_scope_tick(end, cancel)
    if time.monotonic() >= end:
        _fail("usb_scope_timeout")


def _observe(profile, config, end, cancel, previous=None):
    fresh = previous is not None
    try:
        _tick(end, cancel)
        raw = _read_scope(config, deadline=end, cancel=cancel)
        _tick(end, cancel)
        if fresh:
            return U.revalidate_windows_usb_scope(previous, raw, deadline=end, cancel=cancel)
        return U.parse_windows_usb_scope(raw, vid=profile.vid, pid=profile.pid,
                                         deadline=end, cancel=cancel)
    except PwehError as exc:
        allowed = {"usb_scope_timeout", "usb_scope_cancelled"}
        if not fresh:
            allowed.update(("usb_scope_absent", "usb_scope_ambiguous", "usb_scope_unknown"))
        code = exc.code if exc.code in allowed else ("usb_scope_changed" if fresh else "usb_scope_unknown")
    except Exception as exc:
        code = _reason(exc, fresh=fresh)
    _fail(code)


def observe_tigard_scope(profile, config, *, deadline, cancel=None) -> U.WindowsUsbScope:
    """유일한 고정 VID/PID의 complete whole-device 관찰을 얻는다."""
    end = _prepare(profile, deadline, cancel)
    return _observe(profile, config, end, cancel)


def revalidate_tigard_scope(previous, profile, config, *, deadline, cancel=None) -> U.WindowsUsbScope:
    """이전 범위와 같은지 확인한다. 바뀐 key를 얻거나 다른 장치를 선택하지 않는다."""
    end = _prepare(profile, deadline, cancel)
    if (type(previous) is not U.WindowsUsbScope
            or (previous.vid, previous.pid) != (profile.vid, profile.pid)):
        _fail("usb_scope_invalid")
    return _observe(profile, config, end, cancel, previous)
