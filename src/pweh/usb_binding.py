"""이미 얻은 Windows Present graph의 유일 USB 부모와 전체 잠금 범위.

bytes만 해석하며 Windows/포트/환경/파일을 조회하지 않는다. 성공값은 OS 관찰의
결속이고 실제 CLI 선택·driver claim·하드웨어 인증·장치 사용 허가를 증명하지 않는다.
"""
from __future__ import annotations

from dataclasses import dataclass, field
import math
import re
import time

from . import portidentity as I
from .errors import PwehError
from .ports import parse_win_com

MAX_SECONDS = 5.0
_HEX = re.compile(r"[0-9a-fA-F]{4}\Z", re.ASCII)
_MESSAGES = {
    "usb_scope_invalid": "USB 관찰 입력 또는 결속 형식이 올바르지 않습니다.",
    "usb_scope_unknown": "완전한 USB 관찰 범위를 확인하지 못했습니다.",
    "usb_scope_absent": "완전한 관찰에서 지정 USB 후보를 찾지 못했습니다.",
    "usb_scope_ambiguous": "지정 USB 후보가 하나로 정해지지 않았습니다.",
    "usb_scope_changed": "USB 후보 또는 전체 잠금 범위가 바뀌었거나 재확인되지 않았습니다.",
    "usb_scope_timeout": "USB 관찰 범위의 시간 한도를 초과했습니다.",
    "usb_scope_cancelled": "USB 관찰 범위 확인이 취소되었습니다.",
}


def _fail(code="usb_scope_unknown"):
    raise PwehError(_MESSAGES[code], code=code) from None


def _end(deadline):
    try:
        if type(deadline) not in (int, float):
            _fail("usb_scope_invalid")
        value = float(deadline)
        if not math.isfinite(value):
            _fail("usb_scope_invalid")
    except OverflowError:
        _fail("usb_scope_invalid")
    now = time.monotonic()
    if value <= now:
        _fail("usb_scope_timeout")
    return min(value, now + MAX_SECONDS)


def _tick(end, cancel):
    if time.monotonic() >= end:
        _fail("usb_scope_timeout")
    if cancel is not None:
        try:
            answer = cancel()
        except Exception:
            _fail()
        if type(answer) is not bool:
            _fail()
        if answer:
            _fail("usb_scope_cancelled")
        if time.monotonic() >= end:
            _fail("usb_scope_timeout")


def _id(value):
    if type(value) is not str or _HEX.fullmatch(value) is None:
        _fail("usb_scope_invalid")
    return value.lower()


def _scalar(value, *, optional=False):
    return ((optional and value is None) or
            (type(value) is str and 0 < len(value) <= 4096
             and not any(ord(c) < 32 or ord(c) == 127 for c in value)))


@dataclass(frozen=True)
class WindowsUsbScope:
    """관찰한 subtree만 불변 값으로 보존한다. 실행 profile이나 승인 객체가 아니다."""
    vid: str
    pid: str
    usb_parent: str
    claim_keys: tuple[str, ...]
    com_aliases: tuple[tuple[str, str], ...]
    binding_nodes: tuple[tuple[str, str | None, str, str | None, str], ...]
    backend: str = field(default="windows", init=False)
    selector_kind: str = field(default="vid-pid", init=False)
    whole_device: bool = field(default=True, init=False)
    provider_basis: str = field(default="pweh.pnp-usb-scope/v1", init=False)

    def __post_init__(self):
        if self.vid != _id(self.vid) or self.pid != _id(self.pid):
            _fail("usb_scope_invalid")
        if (not _scalar(self.usb_parent) or self.usb_parent != self.usb_parent.upper()
                or type(self.claim_keys) is not tuple or not 1 <= len(self.claim_keys) <= 64
                or type(self.com_aliases) is not tuple or len(self.com_aliases) > 64
                or type(self.binding_nodes) is not tuple or not 1 <= len(self.binding_nodes) <= 256):
            _fail("usb_scope_invalid")
        match = I._USB.fullmatch(self.usb_parent)
        if not match or match[3] is not None or (match[1].lower(), match[2].lower()) != (self.vid, self.pid):
            _fail("usb_scope_invalid")
        keys, aliases, nodes = set(), [], set()
        for row in self.binding_nodes:
            if type(row) is not tuple or len(row) != 5:
                _fail("usb_scope_invalid")
            ident, parent, state, com, cls = row
            if (not _scalar(ident) or ident != ident.upper() or ident in nodes
                    or not _scalar(parent, optional=True) or (parent is not None and parent != parent.upper())
                    or type(state) is not str or state not in ("ok", "root")
                    or type(cls) is not str or len(cls) > 4096 or cls != cls.casefold()
                    or any(ord(c) < 32 or ord(c) == 127 for c in cls)):
                _fail("usb_scope_invalid")
            nodes.add(ident)
            keys.add("winif:" + ident)
            if com is not None:
                if type(com) is not str or parse_win_com(com) is None or com != f"COM{parse_win_com(com)}":
                    _fail("usb_scope_invalid")
                keys.add("win:" + com)
                aliases.append((com, ident))
        if (self.usb_parent not in nodes or tuple(sorted(self.binding_nodes)) != self.binding_nodes
                or tuple(sorted(keys)) != self.claim_keys or tuple(sorted(aliases)) != self.com_aliases
                or len({com for com, _ in aliases}) != len(aliases)):
            _fail("usb_scope_invalid")


def _could_match(ident, vid, pid):
    """지원하지 않는 USB 식별자를 버려 요청 VID/PID의 유일성을 만들지 않는다."""
    if not ident.startswith("USB\\"):
        return False
    hardware = ident.split("\\", 2)[1]
    if "VID" not in hardware and "PID" not in hardware:
        return False  # ROOT_HUB 등은 부모 관계로만 검증한다.
    for label, requested in (("VID", vid), ("PID", pid)):
        values = re.findall(r"(?:^|&)" + label + r"_([^&]*)", hardware)
        # 명확히 다른 한 필드가 있으면 요청 장치 후보는 아니다.
        if len(values) == 1 and _HEX.fullmatch(values[0]) and values[0].lower() != requested:
            return False
    return True


def _physical_parent(graph, ident, end, cancel):
    here = graph[ident][0]
    for _ in range(16):
        _tick(end, cancel)
        if here is None or here == "HTREE\\ROOT\\0":
            return None
        match = I._USB.fullmatch(here)
        if match and match[3] is None:
            return here
        here = graph[here][0]
    _fail()


def _parse(raw, vid, pid, end, cancel):
    _tick(end, cancel)
    graph = I._parse_windows_scope_graph(raw, deadline=end, cancel=cancel)
    parents, interfaces = [], []
    for ident in graph:
        _tick(end, cancel)
        match = I._USB.fullmatch(ident)
        if match:
            pair = (match[1].lower(), match[2].lower())
            if match[3] is not None:
                interfaces.append((ident, pair))
            elif pair == (vid, pid):
                parents.append(ident)
        elif _could_match(ident, vid, pid):
            _fail()
    # MI만 존재하거나 다른 물리 부모에 매달린 요청 MI는 absent/unique가 아니다.
    for ident, pair in interfaces:
        ancestor = _physical_parent(graph, ident, end, cancel)
        if pair == (vid, pid):
            if ancestor not in parents:
                _fail()
        elif ancestor in parents:
            _fail()
    if not parents:
        _fail("usb_scope_absent")
    if len(parents) != 1:
        _fail("usb_scope_ambiguous")
    parent = parents[0]
    nodes, keys, aliases = I._windows_scope_subtree(graph, parent, deadline=end, cancel=cancel)
    selected_aliases = {com: ident for com, ident in aliases}
    # subtree 밖에서 같은 COM을 사용하면 하나의 endpoint key로 결속할 수 없다.
    for ident, row in graph.items():
        _tick(end, cancel)
        com = row[2]
        if com in selected_aliases and selected_aliases[com] != ident:
            _fail()
    result = WindowsUsbScope(vid, pid, parent, keys, aliases,
                             tuple((ident, *graph[ident]) for ident in nodes))
    _tick(end, cancel)
    return result


def _helper_error(exc):
    if isinstance(exc, I._WindowsScopeError):
        if exc.reason == "pnp_scope_time_limit":
            return "usb_scope_timeout"
        if exc.reason == "pnp_scope_cancelled":
            return "usb_scope_cancelled"
    return "usb_scope_unknown"


def parse_windows_usb_scope(raw: bytes, *, vid: str, pid: str, deadline: float, cancel=None) -> WindowsUsbScope:
    """두 완전한 graph에서 유일 parent와 모든 기존 namespace key를 만든다."""
    end = _end(deadline)
    vid, pid = _id(vid), _id(pid)
    if type(raw) is not bytes or (cancel is not None and not callable(cancel)):
        _fail("usb_scope_invalid")
    try:
        return _parse(raw, vid, pid, end, cancel)
    except PwehError as exc:
        code = exc.code if exc.code in _MESSAGES else "usb_scope_unknown"
    except Exception as exc:
        code = _helper_error(exc)
    _fail(code)


def revalidate_windows_usb_scope(previous: WindowsUsbScope, raw: bytes, *, deadline: float,
                                 cancel=None) -> WindowsUsbScope:
    """새 전체 후보/범위를 다시 검사한다. 바뀐 key의 취득이나 자동 재선택은 하지 않는다."""
    end = _end(deadline)
    if type(previous) is not WindowsUsbScope or type(raw) is not bytes or (cancel is not None and not callable(cancel)):
        _fail("usb_scope_invalid")
    try:
        fresh = _parse(raw, previous.vid, previous.pid, end, cancel)
        _tick(end, cancel)
        if fresh != previous:
            _fail("usb_scope_changed")
        return fresh
    except PwehError as exc:
        code = exc.code if exc.code in ("usb_scope_timeout", "usb_scope_cancelled") else "usb_scope_changed"
    except Exception as exc:
        reason = _helper_error(exc)
        code = reason if reason in ("usb_scope_timeout", "usb_scope_cancelled") else "usb_scope_changed"
    _fail(code)
