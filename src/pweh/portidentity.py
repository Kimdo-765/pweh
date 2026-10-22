"""읽기 전용 포트 식별과 USB sibling 관찰. 포트 열기·USB control 질의는 하지 않는다.

OS 관찰 실패는 unknown이다. 시험은 Windows runner 또는 합성 sysfs/stat 함수를 명시한다.
"""
from __future__ import annotations

import json
import math
import os
import re
import signal
import select
import stat
import subprocess
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Callable

from .ports import parse_win_com

MAX_OUTPUT = 1024 * 1024
PNP_TIMEOUT_S = 5.0
MAX_PORTS = 512
MAX_PARENTS = 8
_USB = re.compile(r"^USB\\VID_([0-9A-F]{4})&PID_([0-9A-F]{4})(?:&MI_([0-9A-F]{2}))?\\([^\\]+)$", re.I)
_MAC = re.compile(r"(?:[0-9a-fA-F]{12}|(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}|(?:[0-9a-fA-F]{2}-){5}[0-9a-fA-F]{2})\Z")


def mac_text(value: Any) -> str | None:
    """정확한 MAC 표기만 정규화한다(임의 문자 제거 금지)."""
    return value.replace(":", "").replace("-", "").lower() if isinstance(value, str) and _MAC.fullmatch(value) else None


@dataclass(frozen=True)
class PortIdentity:
    endpoint_key: str
    status: str = "unknown"
    kind: str = "serial"
    present: bool = False
    backend: str | None = None
    device_instance: str | None = None
    parent_instance: str | None = None
    usb_ancestor: str | None = None
    vid: str | None = None
    pid: str | None = None
    interface_number: str | None = None
    serial: str | None = None
    serial_basis: str | None = None
    location_paths: tuple[str, ...] = ()
    tty_devnum: tuple[int, int] | None = None
    reasons: tuple[str, ...] = ()
    observed_at: float = field(default_factory=time.time)

    def __post_init__(self) -> None:
        for name in ("endpoint_key", "status", "kind", "backend", "device_instance", "parent_instance", "usb_ancestor",
                     "vid", "pid", "interface_number", "serial", "serial_basis"):
            value = getattr(self, name)
            if value is not None and (not isinstance(value, str) or len(value) > 4096):
                raise ValueError("identity_scalar_invalid")
        for name in ("location_paths", "reasons"):
            value = tuple(getattr(self, name))
            if len(value) > 64 or any(not isinstance(v, str) or len(v) > 4096 for v in value):
                raise ValueError("identity_tuple_invalid")
            object.__setattr__(self, name, value)
        if self.tty_devnum is not None:
            devnum = tuple(self.tty_devnum)
            if len(devnum) != 2 or any(type(v) is not int or v < 0 for v in devnum):
                raise ValueError("identity_devnum_invalid")
            object.__setattr__(self, "tty_devnum", devnum)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def unknown(endpoint: str | None, reason: str, *, kind: str = "unknown") -> PortIdentity:
    return PortIdentity(endpoint or "<automatic>", kind=kind, reasons=(reason,))


# 입력을 코드에 보간하지 않고 전체 present COM 목록을 정해진 상한 안에서 읽는다.
PS_IDENTITIES = r"""$ErrorActionPreference='Stop';[Console]::OutputEncoding=New-Object System.Text.UTF8Encoding($false);
$all=@(Get-PnpDevice -PresentOnly);if($all.Count -gt 8192){throw 'device limit'};
$ports=@($all | Where-Object {$_.FriendlyName -match '\(COM[1-9][0-9]{0,3}\)$'});
if($ports.Count -gt 512){throw 'port limit'};$out=@();
foreach($d in $ports){$id=$d.InstanceId;$nodes=@();$seen=@{};
for($i=0;$i -lt 8;$i++){if($seen.ContainsKey($id)){throw 'parent cycle'};$seen[$id]=$true;
$present=@($all | Where-Object {$_.InstanceId -eq $id});if($present.Count -ne 1){throw 'parent absent'};
$p=(Get-PnpDeviceProperty -InstanceId $id -KeyName 'DEVPKEY_Device_Parent').Data;
$loc=@((Get-PnpDeviceProperty -InstanceId $id -KeyName 'DEVPKEY_Device_LocationPaths' -ErrorAction SilentlyContinue).Data);
$nodes+=@{instance_id=$id;parent=$p;present=$true;location_paths=$loc};
if($id -match '^USB\\VID_[0-9A-F]{4}&PID_[0-9A-F]{4}\\'){break};
if(-not $p){break};$id=$p};
$out+=@{port=([regex]::Match($d.FriendlyName,'\((COM[1-9][0-9]{0,3})\)$').Groups[1].Value);nodes=$nodes}};
ConvertTo-Json -InputObject $out -Depth 6 -Compress"""


def _windows_output(config: Any = None, *, script: str | None = None) -> bytes:
    """검증된 System32 PowerShell로 고정 읽기 스크립트만 실행한다. 출력·시간 상한을 넘기면 실패."""
    from . import hostenv
    if hostenv.disabled_keys(config) & {"interop", "windows_tools", "serial_helper"}:
        raise ValueError("hostenv_disabled")
    exe = hostenv.powershell_path()
    if not exe or os.name != "posix":
        raise ValueError("pnp_backend_unavailable")
    # 임의 프로필·Python/PowerShell 모듈 환경을 전달하지 않는다. WSL interop 연결 정보만 유지한다.
    env = {"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"}
    for key in ("WSL_INTEROP", "WSL_DISTRO_NAME", "SystemRoot", "WINDIR"):
        if key in os.environ:
            env[key] = os.environ[key]
    script = PS_IDENTITIES if script is None else script
    if script not in (PS_IDENTITIES, PS_USB_SCOPE):
        raise ValueError("pnp_script_not_allowed")
    p = subprocess.Popen([exe, "-NoProfile", "-NonInteractive", "-Command", script],
                         stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                         env=env, cwd="/", start_new_session=True, bufsize=0)
    assert p.stdout is not None
    fd = p.stdout.fileno()
    os.set_blocking(fd, False)
    chunks = bytearray()
    deadline = time.monotonic() + PNP_TIMEOUT_S
    try:
        while True:
            left = deadline - time.monotonic()
            if left <= 0:
                # interop 자식의 Windows 쪽 수명까지 보장하지 않는다. 다음 도구는 unknown으로 거부한다.
                raise ValueError("pnp_timeout_windows_child_unverified")
            if not select.select([fd], [], [], min(left, 0.1))[0]:
                continue
            try:
                data = os.read(fd, min(65536, MAX_OUTPUT + 1 - len(chunks)))
            except BlockingIOError:
                continue
            if not data:
                break
            chunks.extend(data)
            if len(chunks) > MAX_OUTPUT:
                raise ValueError("pnp_output_limit")
        if p.wait(timeout=max(0.01, deadline - time.monotonic())) != 0:
            raise ValueError("pnp_query_failed")
        return bytes(chunks)
    finally:
        if p.poll() is None:
            try:
                os.killpg(p.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        # read thread나 buffered reader lock이 없으므로 자식이 pipe를 붙잡아도 종료가 막히지 않는다.
        p.stdout.close()
        p.wait(timeout=2)


def _text(v: Any, *, optional: bool = False) -> str | None:
    if optional and v in (None, ""):
        return None
    if not isinstance(v, str) or not v or len(v) > 4096 or any(ord(c) < 32 for c in v):
        raise ValueError("invalid_identity_string")
    return v


def parse_windows(endpoint: str, raw: bytes | str) -> PortIdentity:
    """고정 질의 결과를 순수 해석한다. 부모 완전성·현재 존재·중복 식별을 검사한다."""
    key = f"COM{parse_win_com(endpoint)}"
    try:
        if len(raw) > MAX_OUTPUT:
            raise ValueError("pnp_output_limit")
        rows = json.loads(raw)
        if not isinstance(rows, list) or len(rows) > MAX_PORTS:
            raise ValueError("pnp_port_limit")
        selected = [r for r in rows if isinstance(r, dict) and str(r.get("port", "")).upper() == key]
        if len(selected) != 1:
            return unknown(key, "absent_or_duplicate_com")
        nodes = selected[0].get("nodes")
        if not isinstance(nodes, list) or not 1 <= len(nodes) <= MAX_PARENTS:
            raise ValueError("pnp_parent_limit")
        seen: set[str] = set()
        locations: list[str] = []
        interface = None
        first = None
        for i, node in enumerate(nodes):
            if not isinstance(node, dict) or node.get("present") is not True:
                raise ValueError("pnp_parent_not_present")
            ident = _text(node.get("instance_id"))
            assert ident is not None
            if ident.upper() in seen:
                raise ValueError("pnp_parent_cycle")
            seen.add(ident.upper())
            first = first or ident
            if i and str(nodes[i - 1].get("parent", "")).upper() != ident.upper():
                raise ValueError("pnp_parent_gap")
            loc = node.get("location_paths", [])
            if not isinstance(loc, list) or len(loc) > 16:
                raise ValueError("pnp_locations_invalid")
            locations = [_text(x) for x in loc if x is not None]  # 현재 노드(USB 부모)의 위치만 사용
            m = _USB.fullmatch(ident)
            if not m:
                continue
            vid, pid, mi, tail = m.groups()
            if mi:
                interface = mi.lower()
                continue
            # '&'가 든 tail은 OS 위치형일 수 있다. 관찰한 parent exact-match는 별도로 보존한다.
            serial = tail if "&" not in tail else None
            duplicate = False
            for other in rows:
                if other is selected[0] or not isinstance(other, dict):
                    continue
                for n in other.get("nodes", []) if isinstance(other.get("nodes"), list) else []:
                    oi = n.get("instance_id") if isinstance(n, dict) else None
                    om = _USB.fullmatch(oi) if isinstance(oi, str) else None
                    if serial and om and not om.group(3) and om.group(4).casefold() == serial.casefold() and oi.upper() != ident.upper():
                        duplicate = True
            return PortIdentity(key, "unknown" if duplicate else "known", present=True, backend="windows", device_instance=first,
                                parent_instance=ident, usb_ancestor=ident, vid=vid.lower(), pid=pid.lower(),
                                interface_number=interface, serial=serial,
                                serial_basis="instance-tail" if serial else "location-derived",
                                location_paths=tuple(locations), reasons=("duplicate_usb_serial",) if duplicate else ())
        raise ValueError("usb_parent_unresolved")
    except (ValueError, TypeError, KeyError, RecursionError, UnicodeError) as exc:
        return unknown(key, str(exc)[:100])


def linux_identity(endpoint: str, *, sysfs_root: Path = Path("/sys"), stat_port: Callable = os.stat) -> PortIdentity:
    """tty를 열지 않고 devnum과 sysfs USB 부모를 읽는다. 임의 PTY/미확인 장치는 unknown."""
    try:
        before = stat_port(endpoint)
        if not stat.S_ISCHR(before.st_mode):
            raise ValueError("not_character_device")
        devnum = (os.major(before.st_rdev), os.minor(before.st_rdev))
        root = sysfs_root.resolve(strict=True)
        start = (root / "dev" / "char" / f"{devnum[0]}:{devnum[1]}" / "device").resolve(strict=True)
        if not start.is_relative_to(root):
            raise ValueError("sysfs_escape")
        deadline = time.monotonic() + 5
        used = 0

        def attr(parent: Path, name: str) -> str | None:
            nonlocal used
            p = parent / name
            if not p.exists():
                return None
            if time.monotonic() >= deadline or used > MAX_OUTPUT:
                raise ValueError("sysfs_limit")
            real = p.resolve(strict=True)
            if not real.is_relative_to(root):
                raise ValueError("sysfs_escape")
            with real.open("rb") as fh:
                raw = fh.read(4097)
            used += len(raw)
            if len(raw) > 4096:
                raise ValueError("sysfs_attribute_limit")
            return _text(raw.decode("utf-8").strip(), optional=True)

        parent = start
        interface = None
        interface_parent = None
        for _ in range(32):
            if time.monotonic() >= deadline:
                raise ValueError("sysfs_time_limit")
            if interface is None:
                interface = attr(parent, "bInterfaceNumber")
                if interface is not None:
                    interface_parent = parent
            vid, pid = attr(parent, "idVendor"), attr(parent, "idProduct")
            if vid is not None or pid is not None:
                if not vid or not pid or not re.fullmatch(r"[0-9a-fA-F]{4}", vid) or not re.fullmatch(r"[0-9a-fA-F]{4}", pid):
                    raise ValueError("sysfs_usb_ids_invalid")
                parent_before = parent.stat()
                serial = attr(parent, "serial")
                fingerprint = (vid, pid, serial, interface)
                check = (attr(parent, "idVendor"), attr(parent, "idProduct"), attr(parent, "serial"),
                         attr(interface_parent, "bInterfaceNumber") if interface_parent is not None else None)
                parent_after = parent.stat()
                if fingerprint != check or (parent_before.st_dev, parent_before.st_ino) != (parent_after.st_dev, parent_after.st_ino):
                    raise ValueError("usb_identity_changed")
                after = stat_port(endpoint)
                again = (root / "dev" / "char" / f"{devnum[0]}:{devnum[1]}" / "device").resolve(strict=True)
                if before.st_rdev != after.st_rdev or before.st_ino != after.st_ino or again != start:
                    raise ValueError("tty_identity_changed")
                rel = str(parent.relative_to(root))
                return PortIdentity(f"tty:{devnum[0]}:{devnum[1]}", "known", present=True, backend="linux",
                                    device_instance=str(start.relative_to(root)), parent_instance=rel, usb_ancestor=rel,
                                    vid=vid.lower(), pid=pid.lower(), serial=serial, serial_basis="sysfs" if serial else None,
                                    interface_number=interface, location_paths=(rel,), tty_devnum=devnum)
            if parent == root or parent.parent == parent:
                break
            parent = parent.parent
        raise ValueError("usb_parent_unresolved")
    except (OSError, ValueError, RuntimeError, UnicodeError) as exc:
        return unknown(endpoint, str(exc)[:100])


def probe_identity(endpoint: str | None, *, config: Any = None, runner: Callable[[], bytes | str] | None = None,
                   sysfs_root: Path | None = None, stat_port: Callable = os.stat) -> PortIdentity:
    """serial만 관찰한다. URL·자동 선택·USB selector는 실장치를 특정하지 못하므로 unknown."""
    if endpoint == "loop://":
        return PortIdentity(endpoint, "known", "memory", True)
    if not endpoint or "://" in endpoint or not (parse_win_com(endpoint) or endpoint.startswith("/")):
        return unknown(endpoint, "unresolved_endpoint", kind="forwarded" if endpoint and "://" in endpoint else "unknown")
    if parse_win_com(endpoint):
        try:
            return parse_windows(endpoint, runner() if runner is not None else _windows_output(config))
        except (OSError, ValueError, subprocess.SubprocessError) as exc:
            return unknown(endpoint, str(exc)[:100])
    return linux_identity(endpoint, sysfs_root=sysfs_root or Path("/sys"), stat_port=stat_port)


# COM 조상만 읽는 PS_IDENTITIES와 달리 비직렬 WinUSB/JTAG 형제를 포함한다.
# 두 전체 관찰의 모든 부모 관계를 Python에서 대조한다. 입력을 코드에 보간하지 않는다.
PS_USB_SCOPE = r"""$ErrorActionPreference='Stop';[Console]::OutputEncoding=New-Object System.Text.UTF8Encoding($false);
function Read-Scope {
 $all=@(Get-PnpDevice -PresentOnly | Select-Object -First 8193);
 if($all.Count -gt 8192){throw 'device limit'};
 $ids=@($all | Where-Object {$_.InstanceId -ne 'HTREE\ROOT\0'} | ForEach-Object {$_.InstanceId});
 $props=@(Get-PnpDeviceProperty -InstanceId $ids -KeyName DEVPKEY_Device_Parent | Select-Object -First 8193);
 if($props.Count -gt 8192){throw 'property limit'};
 $parents=@{};foreach($p in $props){if($parents.ContainsKey($p.InstanceId)){throw 'duplicate property'};$parents[$p.InstanceId]=$p};
 $nodes=@();foreach($d in $all){$id=$d.InstanceId;$par=$null;$state='ok';
 if($id -eq 'HTREE\ROOT\0'){$state='root'}else{
  if(-not $parents.ContainsKey($id)){throw 'missing parent property'};
  $par=$parents[$id].Data;if(-not ($par -is [string]) -or -not $par){throw 'invalid parent property'}};
 $com=$null;$m=[regex]::Match([string]$d.FriendlyName,'\((COM[1-9][0-9]{0,3})\)$','IgnoreCase');
 if($m.Success){$com=$m.Groups[1].Value.ToUpperInvariant()};
 $nodes+=@{instance_id=$id;parent=$par;parent_state=$state;com=$com;pnp_class=[string]$d.Class}};
 return @{present_count=$all.Count;nodes=$nodes;errors=@()}
};
$one=Read-Scope;$two=Read-Scope;
ConvertTo-Json -InputObject @{schema='pweh.pnp-usb-scope/v1';snapshots=@($one,$two)} -Depth 6 -Compress"""


_SCOPE_REASONS = frozenset({
    "pnp_scope_input_limit", "pnp_scope_json", "pnp_scope_schema", "pnp_scope_snapshots",
    "pnp_scope_query_failed", "pnp_scope_count", "pnp_scope_node", "pnp_scope_parent_unreadable",
    "pnp_scope_com_invalid", "pnp_scope_duplicate_node", "pnp_scope_parent_gap_cycle_depth",
    "pnp_scope_changed", "pnp_scope_usb_parent", "pnp_scope_selected_com", "pnp_scope_subtree_limit",
    "pnp_scope_serial_unmapped", "pnp_scope_duplicate_com", "pnp_scope_keys_invalid",
    "pnp_scope_time_limit", "pnp_scope_cancelled", "pnp_scope_callback_failed",
})
_ScopeGraph = dict[str, tuple[str | None, str, str | None, str]]


class _WindowsScopeError(ValueError):
    """공유 관찰 helper의 고정 사유. JSON·PnP·callback 원문을 담지 않는다."""

    def __init__(self, reason: str):
        self.reason = reason if type(reason) is str and reason in _SCOPE_REASONS else "pnp_scope_node"
        super().__init__(self.reason)


def _windows_scope_deadline(deadline: float) -> float:
    """caller의 남은 예산을 늘리지 않고 한 번의 관찰을 5초 이내로 제한한다."""
    try:
        valid = type(deadline) in (int, float) and math.isfinite(deadline)
    except (OverflowError, ValueError):
        valid = False
    if not valid:
        raise _WindowsScopeError("pnp_scope_input_limit")
    return min(deadline, time.monotonic() + PNP_TIMEOUT_S)


def _windows_scope_tick(deadline: float, cancel: Callable[[], bool] | None) -> None:
    if time.monotonic() > deadline:
        raise _WindowsScopeError("pnp_scope_time_limit")
    if cancel is not None:
        try:
            stopped = cancel()
            if type(stopped) is not bool:
                raise ValueError()
        except Exception:
            raise _WindowsScopeError("pnp_scope_callback_failed") from None
        if stopped:
            raise _WindowsScopeError("pnp_scope_cancelled")
        if time.monotonic() > deadline:
            raise _WindowsScopeError("pnp_scope_time_limit")


def _windows_scope_json(raw: bytes | str, deadline: float, cancel: Callable[[], bool] | None) -> Any:
    """1 MiB·깊이 16의 JSON만 해석하고 중복 key·비유한 수를 거부한다."""
    _windows_scope_tick(deadline, cancel)
    if type(raw) not in (bytes, str) or len(raw) > MAX_OUTPUT:
        raise _WindowsScopeError("pnp_scope_input_limit")
    try:
        text = raw.decode("utf-8") if type(raw) is bytes else raw
        if len(text.encode("utf-8")) > MAX_OUTPUT:
            raise _WindowsScopeError("pnp_scope_input_limit")
        depth = 0
        quoted = escaped = False
        for index, char in enumerate(text):
            if index % 4096 == 0:
                _windows_scope_tick(deadline, cancel)
            if quoted:
                if escaped:
                    escaped = False
                elif char == "\\":
                    escaped = True
                elif char == '"':
                    quoted = False
            elif char == '"':
                quoted = True
            elif char in "[{":
                depth += 1
                if depth > 16:
                    raise _WindowsScopeError("pnp_scope_json")
            elif char in "]}":
                depth -= 1
                if depth < 0:
                    raise _WindowsScopeError("pnp_scope_json")
        if depth or quoted:
            raise _WindowsScopeError("pnp_scope_json")

        def pairs(items):
            _windows_scope_tick(deadline, cancel)
            result = {}
            for index, (key, value) in enumerate(items):
                if index % 4096 == 0:
                    _windows_scope_tick(deadline, cancel)
                if key in result:
                    raise _WindowsScopeError("pnp_scope_json")
                result[key] = value
            return result

        def number(value, *, integer):
            # Python 3.10에서도 거대 정수 변환이 공통 예산을 독점하지 못하게 한다.
            if len(value) > 128:
                raise _WindowsScopeError("pnp_scope_json")
            result = int(value) if integer else float(value)
            if not integer and not math.isfinite(result):
                raise _WindowsScopeError("pnp_scope_json")
            return result

        def constant(_):
            raise _WindowsScopeError("pnp_scope_json")

        _windows_scope_tick(deadline, cancel)
        data = json.loads(text, object_pairs_hook=pairs, parse_constant=constant,
                          parse_int=lambda v: number(v, integer=True),
                          parse_float=lambda v: number(v, integer=False))
        _windows_scope_tick(deadline, cancel)
        return data
    except _WindowsScopeError:
        raise
    except (ValueError, TypeError, RecursionError, UnicodeError, OverflowError):
        raise _WindowsScopeError("pnp_scope_json") from None


def _parse_windows_scope_graph(raw: bytes | str, *, deadline: float,
                               cancel: Callable[[], bool] | None = None) -> _ScopeGraph:
    """두 complete Present graph의 전체 동등성을 검증한다. OS 조회는 하지 않는다."""
    deadline = _windows_scope_deadline(deadline)
    try:
        data = _windows_scope_json(raw, deadline, cancel)
        if not isinstance(data, dict) or data.get("schema") != "pweh.pnp-usb-scope/v1":
            raise _WindowsScopeError("pnp_scope_schema")
        snapshots = data.get("snapshots")
        if not isinstance(snapshots, list) or len(snapshots) != 2:
            raise _WindowsScopeError("pnp_scope_snapshots")
        graphs = []
        for snapshot in snapshots:
            if not isinstance(snapshot, dict) or snapshot.get("errors") != []:
                raise _WindowsScopeError("pnp_scope_query_failed")
            nodes = snapshot.get("nodes")
            if (not isinstance(nodes, list) or not 1 <= len(nodes) <= 8192
                    or type(snapshot.get("present_count")) is not int or snapshot["present_count"] != len(nodes)):
                raise _WindowsScopeError("pnp_scope_count")
            graph = {}
            for row in nodes:
                _windows_scope_tick(deadline, cancel)
                if not isinstance(row, dict):
                    raise _WindowsScopeError("pnp_scope_node")
                ident = _text(row.get("instance_id")).upper()
                par = _text(row.get("parent"), optional=True)
                par = par.upper() if par else None
                state = row.get("parent_state")
                if not ((state == "root" and ident == "HTREE\\ROOT\\0" and par is None)
                        or (state == "ok" and par)):
                    raise _WindowsScopeError("pnp_scope_parent_unreadable")
                com = row.get("com")
                if com is not None:
                    n = parse_win_com(com)
                    if n is None:
                        raise _WindowsScopeError("pnp_scope_com_invalid")
                    com = f"COM{n}"
                cls = _text(row.get("pnp_class"), optional=True) or ""
                # JSON의 surrogate escape를 OS 신원 문자열로 보존하지 않는다.
                for value in (ident, par or "", cls):
                    value.encode("utf-8")
                if ident in graph:
                    raise _WindowsScopeError("pnp_scope_duplicate_node")
                graph[ident] = (par, state, com, cls.casefold())
            for ident in graph:
                _windows_scope_tick(deadline, cancel)
                seen = set()
                here = ident
                for depth in range(17):
                    # 기존 관찰은 root sentinel 자체가 nodes에 없는 경우도 허용한다.
                    if here == "HTREE\\ROOT\\0":
                        break
                    if depth == 16 or here in seen or here not in graph:
                        raise _WindowsScopeError("pnp_scope_parent_gap_cycle_depth")
                    seen.add(here)
                    here = graph[here][0]
            graphs.append(graph)
        if graphs[0] != graphs[1]:
            raise _WindowsScopeError("pnp_scope_changed")
        _windows_scope_tick(deadline, cancel)
        return graphs[0]
    except _WindowsScopeError:
        raise
    except (ValueError, TypeError, KeyError, AttributeError, RecursionError, UnicodeError):
        raise _WindowsScopeError("pnp_scope_node") from None


def _windows_scope_subtree(graph: _ScopeGraph, parent: str, *, deadline: float,
                           cancel: Callable[[], bool] | None = None
                           ) -> tuple[tuple[str, ...], tuple[str, ...], tuple[tuple[str, str], ...]]:
    """검증한 graph에서 parent 전체 node/key/(COM,node)를 반환한다. 선택 COM은 요구하지 않는다."""
    deadline = _windows_scope_deadline(deadline)
    try:
        _windows_scope_tick(deadline, cancel)
        root = parent.upper()
        if root not in graph or not _USB.fullmatch(root) or _USB.fullmatch(root).group(3):
            raise _WindowsScopeError("pnp_scope_usb_parent")
        children: dict[str | None, list[str]] = {}
        for node, row in graph.items():
            _windows_scope_tick(deadline, cancel)
            children.setdefault(row[0], []).append(node)
        pending = [(root, 0)]
        subtree = set()
        keys = set()
        aliases = {}
        while pending:
            _windows_scope_tick(deadline, cancel)
            node, depth = pending.pop()
            if depth > 16 or len(subtree) >= 256 or node in subtree:
                raise _WindowsScopeError("pnp_scope_subtree_limit")
            subtree.add(node)
            row = graph[node]
            keys.add("winif:" + node)
            if row[3] == "ports" and not row[2]:
                raise _WindowsScopeError("pnp_scope_serial_unmapped")
            if row[2]:
                if row[2] in aliases:
                    raise _WindowsScopeError("pnp_scope_duplicate_com")
                aliases[row[2]] = node
                keys.add("win:" + row[2])
            pending.extend((child, depth + 1) for child in children.get(node, ()))
        if len(keys) > 64 or any(len(key) > 4096 for key in keys):
            raise _WindowsScopeError("pnp_scope_keys_invalid")
        _windows_scope_tick(deadline, cancel)
        return tuple(sorted(subtree)), tuple(sorted(keys)), tuple(sorted(aliases.items()))
    except _WindowsScopeError:
        raise
    except (ValueError, TypeError, KeyError, IndexError, AttributeError, RecursionError, UnicodeError):
        raise _WindowsScopeError("pnp_scope_node") from None


def parse_windows_scope(route: Any, raw: bytes | str, *, deadline: float | None = None) -> Any:
    """기존 serial wrapper: 선택 COM의 전역 유일성과 parent subtree 소속을 추가 확인한다."""
    from .ports import SiblingScope
    parent = route.identity.usb_ancestor
    try:
        if not parent:
            raise _WindowsScopeError("pnp_scope_input_limit")
        deadline = _windows_scope_deadline(deadline if deadline is not None else time.monotonic() + PNP_TIMEOUT_S)
        graph = _parse_windows_scope_graph(raw, deadline=deadline)
        selected = []
        for node, row in graph.items():
            _windows_scope_tick(deadline, None)
            if "win:" + str(row[2]) == route.lock_key:
                selected.append(node)
        if len(selected) != 1:
            raise _WindowsScopeError("pnp_scope_selected_com")
        subtree, keys, _ = _windows_scope_subtree(graph, parent, deadline=deadline)
        if selected[0] not in subtree or route.lock_key not in keys:
            raise _WindowsScopeError("pnp_scope_keys_invalid")
        _windows_scope_tick(deadline, None)
        return SiblingScope(keys, parent, True)
    except _WindowsScopeError as exc:
        return SiblingScope((), parent, False, (exc.reason,))
    except (ValueError, TypeError, KeyError, AttributeError, RecursionError, UnicodeError):
        return SiblingScope((), parent, False, ("pnp_scope_node",))


def linux_sibling_scope(route: Any, *, sysfs_root: Path | None = None, stat_port: Callable | None = None) -> Any:
    """active USB interface 전체와 tty class devnum을 두 번 대조한다. 장치를 열지 않는다."""
    from .ports import SiblingScope
    parent_id = route.identity.usb_ancestor
    try:
        if not parent_id:
            raise ValueError("usb_parent_unknown")
        root = (sysfs_root or Path("/sys")).resolve(strict=True)
        parent = (root / parent_id).resolve(strict=True)
        if not parent.is_relative_to(root) or parent == root:
            raise ValueError("sysfs_scope_escape")
        deadline = time.monotonic() + PNP_TIMEOUT_S
        budget = 0
        def spend(n: int = 0) -> None:
            nonlocal budget
            budget += n
            if budget > MAX_OUTPUT or time.monotonic() > deadline:
                raise ValueError("sysfs_scope_limit")
        def attr(path: Path, optional: bool = False) -> str | None:
            spend()
            try:
                real = path.resolve(strict=True)
            except FileNotFoundError:
                if optional:
                    return None
                raise
            if not real.is_relative_to(root):
                raise ValueError("sysfs_scope_escape")
            with real.open("rb") as stream:
                raw = stream.read(4097)
            spend(len(raw))
            if len(raw) > 4096:
                raise ValueError("sysfs_scope_attribute_limit")
            return _text(raw.decode("utf-8").strip(), optional=optional)
        def names(path: Path, limit: int) -> tuple[str, ...]:
            out = []
            with os.scandir(path) as entries:
                for entry in entries:
                    spend(len(entry.name.encode()))
                    out.append(entry.name)
                    if len(out) > limit:
                        raise ValueError("sysfs_scope_entries_limit")
            return tuple(sorted(out))
        stat_fn = stat_port or os.stat
        def snapshot() -> tuple[Any, set[str]]:
            st = stat_fn(route.device_path)
            if not stat.S_ISCHR(st.st_mode) or (st.st_dev, st.st_ino, st.st_rdev) != route.node_identity:
                raise ValueError("sysfs_scope_route_changed")
            pst = parent.stat()
            if not re.fullmatch(r"[0-9]+-[0-9]+(?:\.[0-9]+)*", parent.name):
                raise ValueError("sysfs_scope_usb_name")
            cfg_text, count_text = attr(parent / "bConfigurationValue"), attr(parent / "bNumInterfaces")
            if not re.fullmatch(r"[0-9]{1,3}", cfg_text) or not re.fullmatch(r"[0-9]{1,3}", count_text):
                raise ValueError("sysfs_scope_configuration")
            cfg, count = int(cfg_text), int(count_text)
            if not 1 <= cfg <= 255 or not 1 <= count <= 64:
                raise ValueError("sysfs_scope_configuration")
            ids = (attr(parent / "idVendor"), attr(parent / "idProduct"), attr(parent / "serial", True))
            if ids != (route.identity.vid, route.identity.pid, route.identity.serial):
                raise ValueError("sysfs_scope_identity_changed")
            direct = names(parent, 256)
            interfaces = {}
            keys = set()
            for name in direct:
                match = re.fullmatch(re.escape(parent.name) + r":([0-9]+)\.([0-9]+)", name)
                if not match:
                    continue
                path = (parent / name).resolve(strict=True)
                if path.parent != parent:
                    raise ValueError("sysfs_scope_interface_escape")
                mi = attr(path / "bInterfaceNumber")
                if not re.fullmatch(r"[0-9a-fA-F]{2}", mi):
                    raise ValueError("sysfs_scope_interface_number")
                number = int(mi, 16)
                if int(match[1]) != cfg or int(match[2]) != number or number in interfaces:
                    raise ValueError("sysfs_scope_interface_mismatch")
                ist = path.stat()
                interfaces[number] = (str(path.relative_to(root)), ist.st_dev, ist.st_ino)
                keys.add(f"usbif:{parent.name}:{cfg}.{number}")
            if len(interfaces) != count:
                raise ValueError("sysfs_scope_interface_count")
            ttys = names(root / "class" / "tty", 4096)
            targets = []
            for name in ttys:
                spend()
                target = (root / "class" / "tty" / name).resolve(strict=True)
                if not target.is_relative_to(root):
                    raise ValueError("sysfs_scope_tty_escape")
                targets.append((name, str(target.relative_to(root))))
                if not target.is_relative_to(parent):
                    continue
                if not any(target.is_relative_to(root / value[0]) for value in interfaces.values()):
                    raise ValueError("sysfs_scope_tty_interface")
                dev = attr(target / "dev")
                if not re.fullmatch(r"[0-9]{1,10}:[0-9]{1,10}", dev):
                    raise ValueError("sysfs_scope_tty_devnum")
                major, minor = map(int, dev.split(":"))
                if major > 0xffffffff or minor > 0xffffffff:
                    raise ValueError("sysfs_scope_tty_devnum")
                keys.add(f"tty:{major}:{minor}")
                targets[-1] += (major, minor)
            if route.lock_key not in keys or len(keys) > 64:
                raise ValueError("sysfs_scope_keys_invalid")
            spend()
            return ((pst.st_dev, pst.st_ino, cfg, count, ids, direct, tuple(sorted(interfaces.items())), tuple(targets)), keys)
        before, keys = snapshot()
        after, after_keys = snapshot()
        if before != after or keys != after_keys:
            raise ValueError("sysfs_scope_changed")
        spend()
        return SiblingScope(tuple(sorted(keys)), parent_id, True)
    except (OSError, ValueError, TypeError, AttributeError, RuntimeError, UnicodeError) as exc:
        return SiblingScope((), parent_id, False, (str(exc)[:100],))


def probe_siblings(route: Any, *, config: Any = None, windows_runner: Callable | None = None,
                   sysfs_root: Path | None = None, stat_port: Callable | None = None) -> Any:
    """기본 whole-device 관찰. 부분/지원하지 않는 관찰은 complete=False다."""
    from .ports import SiblingScope
    if route.side == "windows":
        try:
            deadline = time.monotonic() + PNP_TIMEOUT_S
            raw = windows_runner() if windows_runner else _windows_output(config, script=PS_USB_SCOPE)
            return parse_windows_scope(route, raw, deadline=deadline)
        except (OSError, ValueError, subprocess.SubprocessError) as exc:
            return SiblingScope((), route.identity.usb_ancestor, False, (str(exc)[:100],))
    if route.backend == "posix-tty":
        return linux_sibling_scope(route, sysfs_root=sysfs_root, stat_port=stat_port)
    return SiblingScope((), route.identity.usb_ancestor, False, ("scope_backend_unsupported",))
