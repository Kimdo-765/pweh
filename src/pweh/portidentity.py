"""계측기 거부용 읽기 전용 포트 식별. 포트 열기·USB 질의·전체 P1 resolve는 하지 않는다.

OS 관찰 실패는 unknown이다. 시험은 Windows runner 또는 합성 sysfs/stat 함수를 명시한다.
"""
from __future__ import annotations

import json
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


def _windows_output(config: Any = None) -> bytes:
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
    p = subprocess.Popen([exe, "-NoProfile", "-NonInteractive", "-Command", PS_IDENTITIES],
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
            for other in rows:
                if other is selected[0] or not isinstance(other, dict):
                    continue
                for n in other.get("nodes", []) if isinstance(other.get("nodes"), list) else []:
                    oi = n.get("instance_id") if isinstance(n, dict) else None
                    om = _USB.fullmatch(oi) if isinstance(oi, str) else None
                    if serial and om and not om.group(3) and om.group(4).casefold() == serial.casefold() and oi.upper() != ident.upper():
                        raise ValueError("duplicate_usb_serial")
            return PortIdentity(key, "known", present=True, backend="windows", device_instance=first,
                                parent_instance=ident, usb_ancestor=ident, vid=vid.lower(), pid=pid.lower(),
                                interface_number=interface, serial=serial,
                                serial_basis="instance-tail" if serial else "location-derived",
                                location_paths=tuple(locations))
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
