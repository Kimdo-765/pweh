"""Windows OpenOCD 실행 계획용 순수 검증과 명시 주입된 소유권 조회.

import나 기본 경로에서 외부 프로그램을 실행하지 않는다. 조회 실패는 부재가
아니며, 아래 스크립트의 실행/파이프 정리/강제 시간 제한은 주입 runner 책임이다.
"""
from __future__ import annotations

import base64
import json
import math
import re
import time
from dataclasses import dataclass

from .errors import DeviceError

MAX_SNAPSHOT_BYTES = 1 << 20
MAX_PROCESSES = 256
MAX_PATH_BYTES = 8192
MAX_COMMAND_CHARS = 32768
MAX_ARGS = 1024
MAX_SECONDS = 30.0
_PARSE_SECONDS = 5.0
_MARKER = re.compile(r"owner-[0-9a-f]{32}\.cfg\Z")
_RESERVED = re.compile(r"(?:CON|PRN|AUX|NUL|CLOCK\$|CONIN\$|CONOUT\$|COM[1-9¹²³]|LPT[1-9¹²³])\Z", re.I)


class WinInteropError(DeviceError):
    """원시 경로·명령줄·runner 오류를 싣지 않는 미확인 상태."""
    code = "windows_identity_unknown"


def _fail(code: str = "windows_identity_unknown") -> None:
    raise WinInteropError("Windows 실행 입력 또는 소유 신원을 확인하지 못했습니다.", code=code) from None


def _deadline(value: float | None, *, parser: bool = False) -> float:
    now = time.monotonic()
    if value is None and parser:
        return now + _PARSE_SECONDS
    if type(value) not in (int, float):
        _fail("windows_budget_invalid")
    try:
        result = float(value)
    except (OverflowError, ValueError):
        _fail("windows_budget_invalid")
    if not math.isfinite(result) or result <= now or result - now > MAX_SECONDS:
        _fail("windows_budget_invalid")
    return min(result, now + _PARSE_SECONDS) if parser else result


def _check(deadline: float) -> None:
    if time.monotonic() >= deadline:
        _fail("windows_deadline")


def _text(value: str, cap: int, *, command: bool = False) -> str:
    if type(value) is not str or not value or len(value) > cap:
        _fail()
    # 경로는 제어문자를 거부한다. 명령줄은 기존 다중 행 Tcl의 CR/LF와 분리용 TAB을 보존한다.
    if any((ord(c) < 32 and not (command and c in "\t\r\n")) or 127 <= ord(c) <= 159
           or 0xD800 <= ord(c) <= 0xDFFF for c in value):
        _fail()
    if command and len(value.encode("utf-16le")) // 2 > cap:
        _fail()
    return value


def validate_windows_path(value: str) -> str:
    """drive absolute/WSL UNC만 검증한다. 실제 파일 접근이나 alias 해석은 하지 않는다."""
    _text(value, MAX_PATH_BYTES)
    if len(value.encode("utf-8")) > MAX_PATH_BYTES or any(c in value for c in '<>"|?*'):
        _fail("windows_path_invalid")
    path = value.replace("/", "\\")
    if re.match(r"^[A-Za-z]:\\", path):
        rest = path[3:]
    elif path.startswith("\\\\"):
        pieces = path[2:].split("\\")
        if len(pieces) < 2 or not pieces[1] or pieces[0].lower() not in ("wsl$", "wsl.localhost"):
            _fail("windows_path_invalid")
        # WSL 배포 이름까지 검증하며 임의 SMB 서버/장치 namespace는 받지 않는다.
        rest = "\\".join(pieces[1:])
    else:
        _fail("windows_path_invalid")
    if ":" in rest:
        _fail("windows_path_invalid")
    if rest:
        for part in rest.split("\\"):
            if (not part or part in (".", "..") or part.endswith((".", " "))
                    or _RESERVED.fullmatch(part.split(".", 1)[0].rstrip(" "))):
                _fail("windows_path_invalid")
    return value


def _path_key(value: str) -> str:
    path = validate_windows_path(value).replace("/", "\\")
    # WSL UNC 및 case-sensitive NTFS를 잘못 동치로 만들지 않는다.
    return path[0].upper() + path[1:] if len(path) > 1 and path[1] == ":" else path


def split_command_line(value: str, *, deadline: float | None = None) -> tuple[str, ...]:
    """제한된 Windows CRT 인자 분리. 불완전/모호한 quote는 미확인으로 남긴다."""
    end = _deadline(deadline, parser=True)
    _text(value, MAX_COMMAND_CHARS, command=True)
    args: list[str] = []
    current: list[str] = []
    quoted = have = False
    i = 0
    while i < len(value):
        if i % 256 == 0:
            _check(end)
        c = value[i]
        if c == "\\":
            j = i
            while j < len(value) and value[j] == "\\":
                j += 1
            count = j - i
            if j < len(value) and value[j] == '"':
                current.append("\\" * (count // 2))
                if count % 2:
                    current.append('"')
                else:
                    # 연속 unescaped quote는 CRT 버전 차이 대신 보수적으로 실패한다.
                    if quoted and j + 1 < len(value) and value[j + 1] == '"':
                        _fail()
                    quoted = not quoted
                i = j + 1
            else:
                current.append("\\" * count)
                i = j
            have = True
            continue
        if c == '"':
            if quoted and i + 1 < len(value) and value[i + 1] == '"':
                _fail()
            quoted = not quoted
            have = True
        elif c in " \t" and not quoted:
            if have:
                args.append("".join(current))
                current = []
                have = False
                if len(args) > MAX_ARGS:
                    _fail()
        else:
            current.append(c)
            have = True
        i += 1
    if quoted:
        _fail()
    if have:
        args.append("".join(current))
    if not args or not args[0] or len(args) > MAX_ARGS:
        _fail()
    _check(end)
    return tuple(args)


@dataclass(frozen=True)
class WindowsIdentity:
    """한 complete snapshot의 신원. 공개 보고서로 자동 직렬화하지 않는다."""
    pid: int
    image: str
    creation_filetime: str
    command_line: str

    def __post_init__(self) -> None:
        if type(self.pid) is not int or not 1 <= self.pid <= 0xFFFFFFFF:
            _fail()
        validate_windows_path(self.image)
        if self.image.replace("/", "\\").rsplit("\\", 1)[-1].lower() != "openocd.exe":
            _fail()
        if (type(self.creation_filetime) is not str or not re.fullmatch(r"[1-9][0-9]{0,18}", self.creation_filetime)
                or int(self.creation_filetime) > 0x7FFFFFFFFFFFFFFF or int(self.creation_filetime) % 10):
            _fail()
        _text(self.command_line, MAX_COMMAND_CHARS, command=True)


@dataclass(frozen=True)
class OwnedWindowsLaunch:
    """계획한 image와 argv tail 및 고유 cfg 표식. path 위치는 tail 기준이다."""
    image: str
    argv_tail: tuple[str, ...]
    marker_cfg: str
    path_arg_indices: tuple[int, ...] = ()

    def __post_init__(self) -> None:
        validate_windows_path(self.image)
        if self.image.replace("/", "\\").rsplit("\\", 1)[-1] != "openocd.exe":
            _fail()
        validate_windows_path(self.marker_cfg)
        name = self.marker_cfg.replace("/", "\\").rsplit("\\", 1)[-1]
        if not _MARKER.fullmatch(name):
            _fail()
        if (type(self.argv_tail) is not tuple or not 1 <= len(self.argv_tail) < MAX_ARGS
                or type(self.path_arg_indices) is not tuple or len(self.path_arg_indices) > MAX_ARGS):
            _fail()
        total = 0
        for arg in self.argv_tail:
            if arg == "" and type(arg) is str:
                continue
            _text(arg, MAX_COMMAND_CHARS, command=True)
            total += len(arg) + 1
        if total > MAX_COMMAND_CHARS:
            _fail()
        if any(type(i) is not int for i in self.path_arg_indices):
            _fail()
        expected = []
        position = 0
        while position < len(self.argv_tail):
            option = self.argv_tail[position]
            if option in ("-s", "-f", "-c") and position + 1 < len(self.argv_tail):
                if option != "-c":
                    expected.append(position + 1)
                position += 2
            elif re.fullmatch(r"-d[0-4]", option):
                position += 1
            else:
                _fail()
        if self.path_arg_indices != tuple(expected):
            _fail()
        markers = 0
        for i in self.path_arg_indices:
            validate_windows_path(self.argv_tail[i])
            if _path_key(self.argv_tail[i]) == _path_key(self.marker_cfg):
                if self.argv_tail[i - 1] != "-f":
                    _fail()
                markers += 1
        if markers != 1 or self.argv_tail[-1] in ("-s", "-f"):
            _fail()


def _unique_object(pairs: list[tuple[str, object]]) -> dict:
    result = {}
    for key, value in pairs:
        if key in result:
            _fail()
        result[key] = value
    return result


def _json(raw: bytes, end: float, *, cap: int = MAX_SNAPSHOT_BYTES) -> object:
    if type(raw) is not bytes or not 0 < len(raw) <= cap:
        _fail()
    _check(end)
    # json.loads 전에 깊이/노드/문자 예산을 검사해 recursion/거대 정수를 막는다.
    depth = nodes = strings = 0
    quoted = escaped = False
    for i, c in enumerate(raw):
        if i % 4096 == 0:
            _check(end)
        if quoted:
            strings += 1
            if escaped:
                escaped = False
            elif c == 92:
                escaped = True
            elif c == 34:
                quoted = False
            continue
        if c == 34:
            quoted = True
            nodes += 1
        elif c in (91, 123):
            depth += 1
            nodes += 1
            if depth > 8:
                _fail()
        elif c in (93, 125):
            depth -= 1
            if depth < 0:
                _fail()
        elif c in (44, 58):
            nodes += 1
        if nodes > 8192 or strings > MAX_SNAPSHOT_BYTES:
            _fail()
    if quoted or depth:
        _fail()

    def integer(token: str) -> int:
        if len(token) > 20:
            _fail()
        return int(token)

    def invalid(token: str) -> None:
        _fail()

    try:
        result = json.loads(raw.decode("utf-8-sig", "strict"), object_pairs_hook=_unique_object,
                            parse_int=integer, parse_float=invalid, parse_constant=invalid)
    except Exception:
        _fail()
    _check(end)
    return result


def parse_process_snapshot(raw: bytes, *, deadline: float | None = None) -> tuple[WindowsIdentity, ...]:
    """엄격한 complete 응답만 읽는다. 잘못된 행을 건너뛰어 []로 만들지 않는다."""
    end = _deadline(deadline, parser=True)
    obj = _json(raw, end)
    if (type(obj) is not dict or set(obj) != {"complete", "items"} or obj["complete"] is not True
            or type(obj["items"]) is not list or len(obj["items"]) > MAX_PROCESSES):
        _fail()
    result = []
    seen = set()
    for row in obj["items"]:
        _check(end)
        if type(row) is not dict or set(row) != {"pid", "image", "creation", "cmd"}:
            _fail()
        item = WindowsIdentity(row["pid"], row["image"], row["creation"], row["cmd"])
        split_command_line(item.command_line, deadline=end)
        if item.pid in seen:
            _fail()
        seen.add(item.pid)
        result.append(item)
    _check(end)
    return tuple(result)


def matches_launch(identity: WindowsIdentity, launch: OwnedWindowsLaunch, *, deadline: float | None = None) -> bool:
    """정확 일치만 True. 후보 여부와 다르므로 False를 부재로 해석하지 않는다."""
    if type(identity) is not WindowsIdentity or type(launch) is not OwnedWindowsLaunch:
        _fail()
    args = split_command_line(identity.command_line, deadline=deadline)[1:]
    if _path_key(identity.image) != _path_key(launch.image) or len(args) != len(launch.argv_tail):
        return False
    for i, (actual, planned) in enumerate(zip(args, launch.argv_tail)):
        if i in launch.path_arg_indices:
            try:
                if _path_key(actual) != _path_key(planned):
                    return False
            except WinInteropError:
                return False
        elif actual != planned:
            return False
    return True


QUERY_SCRIPT = r"""$ErrorActionPreference='Stop';[Console]::OutputEncoding=New-Object System.Text.UTF8Encoding($false);
$items=@(Get-CimInstance Win32_Process -Filter "Name='openocd.exe'" -OperationTimeoutSec 2 | Select-Object -First 257);
if($items.Count -gt 256){throw 'count_limit'};
$out=@($items | ForEach-Object {if(!$_.CommandLine -or !$_.ExecutablePath -or !$_.CreationDate){throw 'incomplete'};
 [pscustomobject]@{pid=[uint32]$_.ProcessId;cmd=$_.CommandLine;image=$_.ExecutablePath;creation=$_.CreationDate.ToUniversalTime().ToFileTimeUtc().ToString()}});
ConvertTo-Json -InputObject ([pscustomobject]@{complete=$true;items=$out}) -Compress -Depth 4
"""

TERMINATE_SCRIPT_TEMPLATE = r"""$ErrorActionPreference='Stop';[Console]::OutputEncoding=New-Object System.Text.UTF8Encoding($false);
$r=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('__REQUEST__'))|ConvertFrom-Json;
Add-Type -TypeDefinition @'
using System; using System.Runtime.InteropServices;
public static class PwehOpenOcdProcess {
 [DllImport("kernel32.dll",SetLastError=true)] public static extern IntPtr OpenProcess(uint a,bool i,uint p);
 [DllImport("kernel32.dll",SetLastError=true)] public static extern bool GetProcessTimes(IntPtr p,out long c,out long e,out long k,out long u);
 [DllImport("kernel32.dll",SetLastError=true)] public static extern bool TerminateProcess(IntPtr p,uint e);
 [DllImport("kernel32.dll",SetLastError=true)] public static extern uint WaitForSingleObject(IntPtr p,uint ms);
 [DllImport("kernel32.dll")] public static extern bool CloseHandle(IntPtr p);
}
'@;
$h=[PwehOpenOcdProcess]::OpenProcess(0x101001,$false,[uint32]$r.pid);
if($h -eq [IntPtr]::Zero){throw 'open_process_unverified'};
try {
 [long]$c=0;[long]$e=0;[long]$k=0;[long]$u=0;
 if(![PwehOpenOcdProcess]::GetProcessTimes($h,[ref]$c,[ref]$e,[ref]$k,[ref]$u)){throw 'times_failed'};
 if(($c - ($c % 10)) -ne [long]$r.creation){throw 'identity_changed'};
 $p=Get-CimInstance Win32_Process -Filter ('ProcessId='+[uint32]$r.pid) -OperationTimeoutSec 2;
 if(!$p){if([PwehOpenOcdProcess]::WaitForSingleObject($h,0) -ne 0){throw 'missing_not_exited'}}
 else {
  if($p.CommandLine -cne $r.cmd -or $p.ExecutablePath -cne $r.image -or
     $p.CreationDate.ToUniversalTime().ToFileTimeUtc().ToString() -cne $r.creation){throw 'identity_changed'};
  if([PwehOpenOcdProcess]::WaitForSingleObject($h,0) -ne 0){
   if(![PwehOpenOcdProcess]::TerminateProcess($h,1)){throw 'terminate_failed'};
   if([PwehOpenOcdProcess]::WaitForSingleObject($h,[uint32]$r.wait_ms) -ne 0){throw 'still_running'}
  }
 }
} finally {if(![PwehOpenOcdProcess]::CloseHandle($h)){throw 'close_failed'}};
'{"terminated":true}'
"""


class WindowsOwnedProcessProbe:
    """필수 runner에 고정 script와 deadline만 전달한다. 기본 실행 fallback은 없다."""

    def __init__(self, *, runner):
        if not callable(runner):
            _fail()
        self._runner = runner

    def _run(self, script: str, end: float) -> bytes:
        _check(end)
        try:
            raw = self._runner(script, end)
        except Exception:
            _fail()
        _check(end)
        return raw

    def observe(self, launch: OwnedWindowsLaunch, *, deadline: float) -> tuple[WindowsIdentity, ...]:
        end = _deadline(deadline)
        if type(launch) is not OwnedWindowsLaunch:
            _fail()
        rows = parse_process_snapshot(self._run(QUERY_SCRIPT, end), deadline=end)
        marker = launch.marker_cfg.replace("/", "\\").rsplit("\\", 1)[-1].casefold()
        matches = []
        for row in rows:
            _check(end)
            # 다른 철자/인자 속 같은 basename은 부재가 아니라 불명확한 후보다.
            args = split_command_line(row.command_line, deadline=end)
            if marker in row.command_line.casefold() or any(marker in arg.casefold() for arg in args):
                if not matches_launch(row, launch, deadline=end):
                    _fail()
                matches.append(row)
        if len(matches) > 1:
            _fail()
        _check(end)
        return tuple(matches)

    def terminate_and_confirm(self, launch: OwnedWindowsLaunch, observed: tuple[WindowsIdentity, ...], *, deadline: float) -> bool:
        """관찰 세대 재대조 뒤 같은 핸들만 종료한다. 미확인/변경/실패는 False다."""
        try:
            end = _deadline(deadline)
            if (type(observed) is not tuple or len(observed) > 1
                    or any(type(row) is not WindowsIdentity or not matches_launch(row, launch, deadline=end) for row in observed)):
                return False
            fresh = self.observe(launch, deadline=end)
            if fresh != observed:
                return False
            for row in fresh:
                _check(end)
                remaining = end - time.monotonic()
                request = {"pid": row.pid, "image": row.image, "creation": row.creation_filetime,
                           "cmd": row.command_line, "wait_ms": max(1, min(2000, int(remaining * 1000)))}
                data = base64.b64encode(json.dumps(request, ensure_ascii=True, separators=(",", ":")).encode("ascii")).decode("ascii")
                result = _json(self._run(TERMINATE_SCRIPT_TEMPLATE.replace("__REQUEST__", data), end), end, cap=1024)
                if type(result) is not dict or set(result) != {"terminated"} or result["terminated"] is not True:
                    return False
            return not self.observe(launch, deadline=end)
        except Exception:
            return False
