"""읽기 전용 포트 식별과 USB sibling 관찰. 포트 열기·USB control 질의는 하지 않는다.

OS 관찰 실패는 unknown이다. 시험은 Windows runner 또는 합성 sysfs/stat 함수를 명시한다.
"""
from __future__ import annotations

import atexit
import json
import math
import os
import re
import signal
import select
import stat
import subprocess
import threading
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


# Windows PnP 관찰은 cfgmgr32 를 Reflection.Emit P/Invoke 로 직접 부른다(C# 컴파일 없음, 입력을 코드에 보간하지 않음).
# CU 등은 명령 프레임마다 이 관찰을 다시 하므로(프레임 예산 2초, connect 5초 안에 5회) 빨라야 한다.
# Get-PnpDevice/Get-PnpDeviceProperty·장치별 CIM 호출은 정확하지만 장치 수백 개에서 관찰 한 번이 1~2.7초였고,
# 이 방식은 같은 장치 집합·이름의 COM·Class·부모·LocationPaths 를 내며 두 관찰 합계가 약 0.4초다.
# - 현재 장치: CM_Get_Device_ID_ListW(CM_GETIDLIST_FILTER_PRESENT=0x100) = Get-PnpDevice -PresentOnly 집합.
#   WMI 처럼 InstanceId 를 대문자로 정규화한다(목록은 저장된 대소문자 그대로라 그대로 쓰면 route 결속이 바뀐다).
# - 속성: CM_Get_DevNode_PropertyW 로 DEVPKEY_NAME(COM 추출용)·Device_Class·Device_Parent·Device_LocationPaths.
#   없는 값(CR_NO_SUCH_VALUE)만 null 이고 그 밖의 오류·예상 밖 형식은 throw 로 전체가 실패한다.
# - PowerShell 함수 호출은 호출당 약 0.1ms 라 장치 루프 안에서는 같은 고정 블록을 펼쳐 쓴다.
_PS_CM_LIB = r"""$ErrorActionPreference='Stop';[Console]::OutputEncoding=New-Object System.Text.UTF8Encoding($false);
$ab=[AppDomain]::CurrentDomain.DefineDynamicAssembly((New-Object Reflection.AssemblyName 'PwehCm'),[Reflection.Emit.AssemblyBuilderAccess]::Run);
$tb=$ab.DefineDynamicModule('PwehCm').DefineType('PwehCm.N','Public,Class,Sealed');
foreach($s in @(@('CM_Get_Device_ID_List_SizeW',@([UInt32].MakeByRefType(),[IntPtr],[UInt32])),@('CM_Get_Device_ID_ListW',@([IntPtr],[byte[]],[UInt32],[UInt32])),
 @('CM_Locate_DevNodeW',@([UInt32].MakeByRefType(),[string],[UInt32])),@('CM_Get_DevNode_PropertyW',@([UInt32],[byte[]],[UInt32].MakeByRefType(),[byte[]],[UInt32].MakeByRefType(),[UInt32])))){
 $m=$tb.DefinePInvokeMethod($s[0],'cfgmgr32.dll',[Reflection.MethodAttributes]'Public,Static,PinvokeImpl',[Reflection.CallingConventions]::Standard,[UInt32],[Type[]]$s[1],[Runtime.InteropServices.CallingConvention]::Winapi,[Runtime.InteropServices.CharSet]::Unicode);
 $m.SetImplementationFlags([Reflection.MethodImplAttributes]::PreserveSig)};
$CM=$tb.CreateType();$U=[Text.Encoding]::Unicode;$B=New-Object byte[] 2048;
$KN=New-Object byte[] 20;[Guid]::Parse('b725f130-47ef-101a-a5f1-02608c9eebac').ToByteArray().CopyTo($KN,0);$KN[16]=10;
$KP=New-Object byte[] 20;[Guid]::Parse('4340a6c5-93fa-4706-972c-7b648008a5a7').ToByteArray().CopyTo($KP,0);$KP[16]=8;
$KC=New-Object byte[] 20;[Guid]::Parse('a45c254e-df1c-4efd-8020-67d146a850e0').ToByteArray().CopyTo($KC,0);$KC[16]=9;
$KL=New-Object byte[] 20;[Guid]::Parse('a45c254e-df1c-4efd-8020-67d146a850e0').ToByteArray().CopyTo($KL,0);$KL[16]=37;
function Read-Ids {for($t=0;$t -lt 3;$t++){[uint32]$n=0;$r=$CM::CM_Get_Device_ID_List_SizeW([ref]$n,[IntPtr]::Zero,0x100);if($r -ne 0){throw "cm list size $r"};
 $L=New-Object byte[] ($n*2);$r=$CM::CM_Get_Device_ID_ListW([IntPtr]::Zero,$L,$n,0x100);if($r -eq 0x1A){continue};if($r -ne 0){throw "cm list $r"};
 $o=New-Object System.Collections.Generic.List[string];foreach($x in $U.GetString($L).Split([char]0)){if($x){$o.Add($x.ToUpperInvariant())}};return ,$o.ToArray()};throw 'cm list unstable'};
"""

# 전체 present COM 목록과 각 COM 의 부모 체인을 정해진 상한 안에서 읽는다.
PS_IDENTITIES = _PS_CM_LIB + r"""$ids=Read-Ids;if($ids.Count -gt 8192){throw 'device limit'};$present=@{};$ports=@();
foreach($id in $ids){if($present.ContainsKey($id)){throw 'duplicate device'};$present[$id]=$true;[uint32]$dn=0;$r=$CM::CM_Locate_DevNodeW([ref]$dn,$id,0);if($r -ne 0){throw "cm locate $r"};[uint32]$ty=0;[uint32]$sz=$B.Length;$r=$CM::CM_Get_DevNode_PropertyW($dn,$KN,[ref]$ty,$B,[ref]$sz,0);if($r -eq 0x1A){$B=New-Object byte[] $sz;[uint32]$sz=$B.Length;$r=$CM::CM_Get_DevNode_PropertyW($dn,$KN,[ref]$ty,$B,[ref]$sz,0)};if($r -eq 0x25){$nm=$null}elseif($r -ne 0){throw "cm prop $r"}elseif($ty -ne 0x12){throw "cm prop type $ty"}else{$nm=$U.GetString($B,0,$sz).TrimEnd([char]0)};
 if([string]$nm -match '\(COM[1-9][0-9]{0,3}\)$'){$ports+=,@($id,[string]$nm)}};
if($ports.Count -gt 512){throw 'port limit'};$out=@();
foreach($pt in $ports){$id=$pt[0];$nodes=@();$seen=@{};
for($i=0;$i -lt 8;$i++){if($seen.ContainsKey($id)){throw 'parent cycle'};$seen[$id]=$true;
if(-not $present.ContainsKey($id)){throw 'parent absent'};[uint32]$dn=0;$r=$CM::CM_Locate_DevNodeW([ref]$dn,$id,0);if($r -ne 0){throw "cm locate $r"};
[uint32]$ty=0;[uint32]$sz=$B.Length;$r=$CM::CM_Get_DevNode_PropertyW($dn,$KP,[ref]$ty,$B,[ref]$sz,0);if($r -eq 0x1A){$B=New-Object byte[] $sz;[uint32]$sz=$B.Length;$r=$CM::CM_Get_DevNode_PropertyW($dn,$KP,[ref]$ty,$B,[ref]$sz,0)};if($r -eq 0x25){$p=$null}elseif($r -ne 0){throw "cm prop $r"}elseif($ty -ne 0x12){throw "cm prop type $ty"}else{$p=$U.GetString($B,0,$sz).TrimEnd([char]0)};[uint32]$ty=0;[uint32]$sz=$B.Length;$r=$CM::CM_Get_DevNode_PropertyW($dn,$KL,[ref]$ty,$B,[ref]$sz,0);if($r -eq 0x1A){$B=New-Object byte[] $sz;[uint32]$sz=$B.Length;$r=$CM::CM_Get_DevNode_PropertyW($dn,$KL,[ref]$ty,$B,[ref]$sz,0)};if($r -eq 0x25){$loc=$null}elseif($r -ne 0){throw "cm prop $r"}elseif($ty -ne 0x2012){throw "cm prop type $ty"}else{$loc=@($U.GetString($B,0,$sz).Split([char]0) | Where-Object {$_})};
$nodes+=@{instance_id=$id;parent=$p;present=$true;location_paths=@($loc)};
if($id -match '^USB\\VID_[0-9A-F]{4}&PID_[0-9A-F]{4}\\'){break};
if(-not $p){break};$id=$p};
$out+=@{port=([regex]::Match($pt[1],'\((COM[1-9][0-9]{0,3})\)$').Groups[1].Value);nodes=$nodes}};
ConvertTo-Json -InputObject $out -Depth 6 -Compress"""


def _windows_output(config: Any = None, *, script: str | None = None,
                    deadline: float | None = None, cancel: Callable[[], bool] | None = None) -> bytes:
    """고정 읽기 질의 하나를 상주 작업자에 요청한다. caller 예산은 늘리지 않고 wrapper 수거는 별도 최대 2초다.

    요청마다 새 PnP 관찰이다(결과 캐시 없음). lock 대기도 같은 deadline·취소를 쓴다.
    """
    end = _windows_scope_deadline(time.monotonic() + PNP_TIMEOUT_S if deadline is None else deadline)
    if cancel is not None and not callable(cancel):
        raise ValueError("pnp_query_callback_failed")

    def tick():
        if time.monotonic() >= end:
            # POSIX wrapper 수거는 실제 Windows 질의 자식 종료의 증거가 아니다.
            raise ValueError("pnp_timeout_windows_child_unverified")
        if cancel is not None:
            try:
                stopped = cancel()
                if type(stopped) is not bool:
                    raise ValueError()
            except Exception:
                raise ValueError("pnp_query_callback_failed") from None
            if stopped:
                raise ValueError("pnp_query_cancelled")
            if time.monotonic() >= end:
                raise ValueError("pnp_timeout_windows_child_unverified")

    tick()
    from . import hostenv
    if hostenv.disabled_keys(config) & {"interop", "windows_tools", "serial_helper"}:
        _retire_idle_worker()
        raise ValueError("hostenv_disabled")
    exe = hostenv.powershell_path()
    if not exe or os.name != "posix":
        _retire_idle_worker()
        raise ValueError("pnp_backend_unavailable")
    # 임의 프로필·Python/PowerShell 모듈 환경을 전달하지 않는다. WSL interop 연결 정보만 유지한다.
    env = {"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"}
    for key in ("WSL_INTEROP", "WSL_DISTRO_NAME", "SystemRoot", "WINDIR"):
        if key in os.environ:
            env[key] = os.environ[key]
    script = PS_IDENTITIES if script is None else script
    # 허용 목록은 두 고정 상수뿐이다. 작업자에는 script 가 아니라 고정 토큰만 보낸다.
    if type(script) is not str or script not in (PS_IDENTITIES, PS_USB_SCOPE):
        raise ValueError("pnp_script_not_allowed")
    token = "IDENT" if script == PS_IDENTITIES else "SCOPE"
    tick()
    return _worker_manager().request(exe, env, token, end, tick)


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
# 부모 관계는 장치마다 같은 cfgmgr32 호출로 읽는다(위 _PS_CM_LIB 설명). 예전 Get-PnpDeviceProperty -InstanceId <여러 ID> 는
# 장치가 많으면 WQL 길이 한도로 '할당량 위반'(0x8004106c)을 냈고, 나눠 보내도 결과 장치 집합에 중복·누락이 생겼다.
# 한 관찰 안의 중복 장치·부모 없음은 throw, 그래프 간극·순환·두 관찰 불일치는 Python 쪽 검사가 거부한다.
# 실용 상한: 장치당 약 0.37ms(신원+두 관찰)·약 370B 라 CU 프레임 예산(2초)은 현재 장치 약 1,800개, 출력 상한 MAX_OUTPUT
# (1 MiB)은 약 2,800개에서 넘는다. 둘 다 time_limit/pnp_output_limit 으로 닫힌 쪽에서 실패한다('device limit' 8192 보다 먼저).
PS_USB_SCOPE = _PS_CM_LIB + r"""function Read-Scope {
 $ids=Read-Ids;if($ids.Count -gt 8192){throw 'device limit'};$seen=@{};
 $nodes=New-Object System.Collections.Generic.List[object];
 foreach($id in $ids){if($seen.ContainsKey($id)){throw 'duplicate device'};$seen[$id]=$true;[uint32]$dn=0;$r=$CM::CM_Locate_DevNodeW([ref]$dn,$id,0);if($r -ne 0){throw "cm locate $r"};
  $par=$null;$state='ok';if($id -eq 'HTREE\ROOT\0'){$state='root'}else{[uint32]$ty=0;[uint32]$sz=$B.Length;$r=$CM::CM_Get_DevNode_PropertyW($dn,$KP,[ref]$ty,$B,[ref]$sz,0);if($r -eq 0x1A){$B=New-Object byte[] $sz;[uint32]$sz=$B.Length;$r=$CM::CM_Get_DevNode_PropertyW($dn,$KP,[ref]$ty,$B,[ref]$sz,0)};if($r -eq 0x25){$par=$null}elseif($r -ne 0){throw "cm prop $r"}elseif($ty -ne 0x12){throw "cm prop type $ty"}else{$par=$U.GetString($B,0,$sz).TrimEnd([char]0)};if(-not ($par -is [string]) -or -not $par){throw 'invalid parent property'}};
  [uint32]$ty=0;[uint32]$sz=$B.Length;$r=$CM::CM_Get_DevNode_PropertyW($dn,$KN,[ref]$ty,$B,[ref]$sz,0);if($r -eq 0x1A){$B=New-Object byte[] $sz;[uint32]$sz=$B.Length;$r=$CM::CM_Get_DevNode_PropertyW($dn,$KN,[ref]$ty,$B,[ref]$sz,0)};if($r -eq 0x25){$nm=$null}elseif($r -ne 0){throw "cm prop $r"}elseif($ty -ne 0x12){throw "cm prop type $ty"}else{$nm=$U.GetString($B,0,$sz).TrimEnd([char]0)};[uint32]$ty=0;[uint32]$sz=$B.Length;$r=$CM::CM_Get_DevNode_PropertyW($dn,$KC,[ref]$ty,$B,[ref]$sz,0);if($r -eq 0x1A){$B=New-Object byte[] $sz;[uint32]$sz=$B.Length;$r=$CM::CM_Get_DevNode_PropertyW($dn,$KC,[ref]$ty,$B,[ref]$sz,0)};if($r -eq 0x25){$cl=$null}elseif($r -ne 0){throw "cm prop $r"}elseif($ty -ne 0x12){throw "cm prop type $ty"}else{$cl=$U.GetString($B,0,$sz).TrimEnd([char]0)};
  $com=$null;$m=[regex]::Match([string]$nm,'\((COM[1-9][0-9]{0,3})\)$','IgnoreCase');if($m.Success){$com=$m.Groups[1].Value.ToUpperInvariant()};
  $nodes.Add(@{instance_id=$id;parent=$par;parent_state=$state;com=$com;pnp_class=[string]$cl})};
 return @{present_count=$ids.Count;nodes=$nodes.ToArray();errors=@()}
};
$one=Read-Scope;$two=Read-Scope;
ConvertTo-Json -InputObject @{schema='pweh.pnp-usb-scope/v1';snapshots=@($one,$two)} -Depth 6 -Compress"""


# 상주 작업자: 위 두 고정 질의를 한 powershell.exe 안의 고정 scriptblock 으로 두고, stdin 한 줄의 고정 토큰으로만 고른다.
# 한 번 실행 방식은 질의마다 시작(약 0.12 s)과 Reflection.Emit 준비(약 0.06 s)를 반복해 CU connect 예산(5 s 안에 재관찰 6회)을 넘었다.
# 요청마다 새 PnP 관찰이며 결과를 캐시하지 않는다. 작업자 문자열은 import 때 고정 상수로만 만들고 입력을 코드에 넣지 않는다.
# - 한 줄이 서수 비교(`[StringComparison]::Ordinal`)로 정확히 `IDENT` → 신원 본문, `SCOPE` → 형제 본문, stdin EOF → exit 0,
#   그 밖의 줄 → exit 3. `-ceq` 는 문화권 비교라 NUL·soft hyphen 이 끼인 줄도 토큰과 같다고 보므로 쓰지 않는다.
# - 줄 끝은 .NET ReadLine 규칙(CR·LF·CRLF)이다. Python 은 `토큰 + LF` 만 보낸다. 한 번에 두 줄이 가면 두 번째 틀은
#   비동기화(틀 뒤 남는 바이트 또는 재사용 전 요청 없이 온 바이트)로 닫힌 쪽에서 실패한다.
# - 응답 틀: ASCII `OK <10진 바이트 수>\n` 다음 정확히 그만큼의 UTF-8 JSON. 본문의 throw 는 작업자를 끝낸다($ErrorActionPreference='Stop').
# - scriptblock 의 변수 대입은 자식 범위라 요청마다 라이브러리 초기값($B 2048 바이트 등)에서 시작한다.
_PS_WORKER_LOOP = (
    "$O=[Console]::OpenStandardOutput();$E=New-Object System.Text.UTF8Encoding($false);\n"
    "while($true){$l=[Console]::In.ReadLine();if($null -eq $l){exit 0};"
    "if([string]::Equals($l,'IDENT',[StringComparison]::Ordinal)){$j=[string](& $SBI)}"
    "elseif([string]::Equals($l,'SCOPE',[StringComparison]::Ordinal)){$j=[string](& $SBS)}else{exit 3};"
    "$p=$E.GetBytes($j);$h=$E.GetBytes('OK '+$p.Length+\"`n\");$O.Write($h,0,$h.Length);$O.Write($p,0,$p.Length);$O.Flush()}\n")


def _build_worker_script() -> str:
    """두 고정 질의의 본문(공통 라이브러리 뒤)을 scriptblock 으로 감싼다. 상수 밖의 값은 쓰지 않는다."""
    lib = _PS_CM_LIB
    if not (PS_IDENTITIES.startswith(lib) and PS_USB_SCOPE.startswith(lib)):
        raise RuntimeError("pnp_worker_script_invalid")
    return (lib + "\n$SBI={" + PS_IDENTITIES[len(lib):] + "};\n$SBS={" + PS_USB_SCOPE[len(lib):] + "};\n"
            + _PS_WORKER_LOOP)


_PS_WORKER = _build_worker_script()
_WORKER_IDLE_S = 120.0     # 이만큼 요청이 없으면 stdin 을 닫아 내린다.
_WORKER_GRACE_S = 1.0      # 유휴 종료에서 stdin EOF 뒤 스스로 끝나기를 기다리는 시간. 넘으면 SIGKILL.
_WORKER_REAP_S = 2.0       # SIGKILL 뒤 wrapper 수거 상한(caller deadline 과 별도).
_WORKER_HEADER_MAX = 16    # 'OK ' + 숫자 + 개행 앞까지의 상한. MAX_OUTPUT 은 7자리다.
_WORKER_HEADER = re.compile(rb"OK (0|[1-9][0-9]*)")
_WORKER_ERRORS = frozenset({
    "pnp_query_callback_failed", "pnp_query_cancelled", "pnp_timeout_windows_child_unverified",
    "pnp_output_limit", "pnp_query_failed",
})


def _current_pid() -> int:
    return os.getpid()


class _PnpWorker:
    """상주 powershell.exe 한 개(POSIX 쪽 interop wrapper). 요청은 manager lock 안에서만 주고받는다."""

    __slots__ = ("proc", "spawn_key", "used")

    def __init__(self, proc: Any, spawn_key: tuple, used: float):
        self.proc, self.spawn_key, self.used = proc, spawn_key, used


def _stop_proc(proc: Any, *, graceful: bool = False) -> None:
    """작업자 process group 을 끝내고 wrapper 를 최대 2초 수거한다. 예외를 내지 않는다.

    POSIX wrapper 수거는 Windows 쪽 작업자 종료의 증거가 아니다.
    graceful 이면 stdin 을 닫고(작업자는 EOF 에 exit 0) 잠시 기다린 뒤에만 SIGKILL 한다.
    """
    if graceful:
        try:
            proc.stdin.close()
        except (OSError, ValueError, AttributeError):
            pass
        try:
            proc.wait(timeout=_WORKER_GRACE_S)
        except (subprocess.TimeoutExpired, OSError):
            pass
    try:
        running = proc.poll() is None
    except OSError:
        running = False
    if running:
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            pass
    # read thread나 buffered reader lock이 없으므로 자식이 pipe를 붙잡아도 종료가 막히지 않는다.
    for stream in (proc.stdin, proc.stdout):
        try:
            if stream is not None:
                stream.close()
        except (OSError, ValueError):
            pass
    try:
        proc.wait(timeout=_WORKER_REAP_S)
    except (subprocess.TimeoutExpired, OSError):
        pass


def _read_frame(fd: int, end: float, tick: Callable[[], None]) -> bytes:
    """응답 틀 하나를 읽는다. 머리 형식·길이·남는 바이트·EOF 는 모두 실패이며 stream 을 다시 맞추지 않는다."""
    buf = bytearray()
    need = None
    while True:
        tick()
        left = end - time.monotonic()
        if not select.select([fd], [], [], max(0.0, min(left, 0.05)))[0]:
            continue
        try:
            chunk = os.read(fd, 65536 if need is None else max(1, min(65536, need + 1 - len(buf))))
        except BlockingIOError:
            continue
        if not chunk:
            raise ValueError("pnp_query_failed")
        buf.extend(chunk)
        if need is None:
            stop = buf.find(b"\n", 0, _WORKER_HEADER_MAX + 1)
            if stop < 0:
                if len(buf) > _WORKER_HEADER_MAX:
                    raise ValueError("pnp_query_failed")
                continue
            match = _WORKER_HEADER.fullmatch(bytes(buf[:stop]))
            if match is None:
                raise ValueError("pnp_query_failed")
            need = int(match.group(1))
            if need > MAX_OUTPUT:
                raise ValueError("pnp_output_limit")
            del buf[:stop + 1]
        if len(buf) > need:
            raise ValueError("pnp_query_failed")
        if len(buf) == need:
            # 틀 뒤에 이미 와 있는 바이트(또는 EOF)는 비동기화다.
            if select.select([fd], [], [], 0)[0]:
                raise ValueError("pnp_query_failed")
            tick()
            return bytes(buf)


class _WorkerManager:
    """프로세스당 하나. 동시에 요청 하나만 보낸다. fork 한 자식은 부모의 pipe 를 쓰지 않는다(pid 확인)."""

    def __init__(self) -> None:
        self.pid = _current_pid()
        self.lock = threading.Lock()
        self.worker: _PnpWorker | None = None
        self.reaper = False

    def abandon(self) -> None:
        """fork 한 자식에서 물려받은 pipe 사본만 닫는다. 부모의 작업자를 죽이거나 수거하지 않는다."""
        worker, self.worker = self.worker, None
        if worker is not None:
            for stream in (worker.proc.stdin, worker.proc.stdout):
                try:
                    if stream is not None:
                        stream.close()
                except (OSError, ValueError):
                    pass

    def request(self, exe: str, env: dict[str, str], token: str, end: float, tick: Callable[[], None]) -> bytes:
        while not self.lock.acquire(timeout=max(0.0, min(0.05, end - time.monotonic()))):
            tick()
        try:
            # 기다리다 끝난 caller 는 아직 토큰을 보내지 않았으므로 다른 caller 의 작업자를 건드리지 않는다.
            tick()
            worker = self._ready(exe, env)
            tick()
            return self._exchange(worker, token, end, tick)
        finally:
            self.lock.release()

    def _drop(self, worker: _PnpWorker) -> None:
        if self.worker is worker:
            self.worker = None
        _stop_proc(worker.proc)

    def _ready(self, exe: str, env: dict[str, str]) -> _PnpWorker:
        key = (exe, tuple(sorted(env.items())))
        worker = self.worker
        if worker is not None:
            try:
                # 유휴 중에 끝났거나(EOF) 요청 없이 바이트가 와 있으면(비동기화) 다시 쓰지 않고 새로 띄운다.
                stale = (worker.spawn_key != key or worker.proc.poll() is not None
                         or bool(select.select([worker.proc.stdout.fileno()], [], [], 0)[0]))
            except (OSError, ValueError):
                stale = True
            if not stale:
                return worker
            self._drop(worker)
        try:
            proc = subprocess.Popen([exe, "-NoProfile", "-NonInteractive", "-Command", _PS_WORKER],
                                    stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                    env=env, cwd="/", start_new_session=True, bufsize=0)
        except (OSError, ValueError, subprocess.SubprocessError):
            raise ValueError("pnp_query_failed") from None
        worker = _PnpWorker(proc, key, time.monotonic())
        try:
            os.set_blocking(proc.stdout.fileno(), False)
        except (OSError, ValueError, AttributeError):
            _stop_proc(proc)
            raise ValueError("pnp_query_failed") from None
        self.worker = worker
        if not self.reaper:
            self.reaper = True
            try:
                _start_reaper(self)
            except RuntimeError:
                # 감시 thread 를 못 띄워도 질의는 유효하다. 다음 spawn 이 다시 시도하고 atexit·stdin EOF 종료는 남는다.
                self.reaper = False
        return worker

    def _exchange(self, worker: _PnpWorker, token: str, end: float, tick: Callable[[], None]) -> bytes:
        try:
            line = token.encode("ascii") + b"\n"
            if worker.proc.stdin.write(line) != len(line):
                raise ValueError("pnp_query_failed")
            payload = _read_frame(worker.proc.stdout.fileno(), end, tick)
        except BaseException as exc:
            # 토큰을 보낸 뒤의 모든 실패: 작업자를 버리고 다음 호출이 새로 띄운다.
            self._drop(worker)
            if type(exc) is ValueError and len(exc.args) == 1 and exc.args[0] in _WORKER_ERRORS:
                raise
            if isinstance(exc, Exception):
                raise ValueError("pnp_query_failed") from None
            raise
        worker.used = time.monotonic()
        return payload

    def reap_idle(self) -> bool:
        """유휴 시간이 지난 작업자를 내린다. 더 지켜볼 작업자가 없으면 True(감시 thread 종료)."""
        if not self.lock.acquire(blocking=False):
            return False
        try:
            worker = self.worker
            if worker is None or self.pid != _current_pid():
                self.reaper = False
                return True
            if time.monotonic() - worker.used < _WORKER_IDLE_S:
                return False
            self.worker = None
            self.reaper = False
        finally:
            self.lock.release()
        _stop_proc(worker.proc, graceful=True)
        return True


def _reaper_loop(manager: _WorkerManager) -> None:
    while not manager.reap_idle():
        threading.Event().wait(max(0.01, _WORKER_IDLE_S / 4))


def _start_reaper(manager: _WorkerManager) -> None:
    """유휴 종료 감시 daemon thread. manager lock 안에서 한 번만 시작한다."""
    threading.Thread(target=_reaper_loop, args=(manager,), name="pweh-pnp-worker-idle", daemon=True).start()


_MANAGER = _WorkerManager()


def _worker_manager() -> _WorkerManager:
    global _MANAGER
    manager = _MANAGER
    if manager.pid != _current_pid():
        # fork 한 자식: 새 lock·새 작업자. 물려받은 lock 은 영원히 잡혀 있을 수 있다.
        _MANAGER = _WorkerManager()
        manager.abandon()
        manager = _MANAGER
    return manager


def _retire_idle_worker() -> None:
    """hostenv disable 키가 켜졌거나 PowerShell backend 가 사라졌을 때 이 프로세스의 유휴 작업자를 바로 내린다.

    lock 을 기다리지 않는다. 진행 중 요청이 있으면(그 요청은 꺼지기 전 검사를 통과했다) 건드리지 않고
    다음 호출이나 유휴 감시가 내린다. fork 한 자식은 새 manager 라 부모의 작업자를 건드리지 않는다. 예외를 내지 않는다.
    """
    manager = _worker_manager()
    if not manager.lock.acquire(blocking=False):
        return
    try:
        worker, manager.worker = manager.worker, None
    finally:
        manager.lock.release()
    if worker is not None:
        _stop_proc(worker.proc)


def _shutdown_worker() -> None:
    """프로세스 종료(atexit) 때 이 프로세스가 띄운 작업자만 끝낸다. fork 한 자식은 부모의 작업자를 건드리지 않는다."""
    manager = _MANAGER
    if manager.pid != _current_pid():
        return
    worker, manager.worker = manager.worker, None
    if worker is not None:
        _stop_proc(worker.proc)


def _after_fork_in_child() -> None:
    global _MANAGER
    manager, _MANAGER = _MANAGER, _WorkerManager()
    manager.abandon()


atexit.register(_shutdown_worker)
if hasattr(os, "register_at_fork"):
    os.register_at_fork(after_in_child=_after_fork_in_child)


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
