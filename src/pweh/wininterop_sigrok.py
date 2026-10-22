"""sigrok 두 정보 명령의 고유 사본 신원 검증. 실행은 필수 주입 runner만 맡는다.

OpenOCD 표식/허용 범위와 독립이며, 잘못된 같은 image 신원은 부재가 아니다.
"""
from __future__ import annotations

import base64
import json
import re
import time
from dataclasses import dataclass

from . import wininterop as W

MAX_SNAPSHOT_BYTES = W.MAX_SNAPSHOT_BYTES
MAX_PROCESSES = W.MAX_PROCESSES
WinInteropError = W.WinInteropError
_fail = W._fail
_deadline = W._deadline
_check = W._check
_json = W._json
validate_windows_path = W.validate_windows_path
split_command_line = W.split_command_line


@dataclass(frozen=True)
class SigrokIdentity:
    """complete snapshot의 한 실행 세대. 원문 신원은 내부에서만 사용한다."""
    pid: int
    image: str
    creation_filetime: str
    command_line: str

    def __post_init__(self):
        if type(self.pid) is not int or not 1 <= self.pid <= 0xFFFFFFFF:
            _fail()
        validate_windows_path(self.image)
        if self.image.replace('/', '\\').rsplit('\\', 1)[-1].lower() != 'sigrok-cli.exe':
            _fail()
        if (type(self.creation_filetime) is not str
                or not re.fullmatch(r'[1-9][0-9]{0,18}', self.creation_filetime)
                or int(self.creation_filetime) > 0x7FFFFFFFFFFFFFFF
                or int(self.creation_filetime) % 10):
            _fail()
        W._text(self.command_line, W.MAX_COMMAND_CHARS, command=True)


@dataclass(frozen=True)
class SigrokLaunch:
    """고유 사본 image와 정확한 두 정보 명령만 계획한다."""
    image: str
    argv_tail: tuple[str, ...]

    def __post_init__(self):
        validate_windows_path(self.image)
        if self.image.replace('/', '\\').rsplit('\\', 1)[-1] != 'sigrok-cli.exe':
            _fail()
        if type(self.argv_tail) is not tuple or self.argv_tail not in (('--version',), ('--list-supported',)):
            _fail()


def parse_process_snapshot(raw: bytes, *, deadline: float | None = None) -> tuple[SigrokIdentity, ...]:
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
        item = SigrokIdentity(row["pid"], row["image"], row["creation"], row["cmd"])
        split_command_line(item.command_line, deadline=end)
        if item.pid in seen:
            _fail()
        seen.add(item.pid)
        result.append(item)
    _check(end)
    return tuple(result)


def matches_launch(identity: SigrokIdentity, launch: SigrokLaunch, *, deadline=None) -> bool:
    """argv0의 WSL 철자만 제외하며 image와 나머지 인자는 정확히 대조한다."""
    if type(identity) is not SigrokIdentity or type(launch) is not SigrokLaunch:
        _fail()
    args = split_command_line(identity.command_line, deadline=deadline)[1:]
    return W._path_key(identity.image) == W._path_key(launch.image) and args == launch.argv_tail


QUERY_SCRIPT = r"""$ErrorActionPreference='Stop';[Console]::OutputEncoding=New-Object System.Text.UTF8Encoding($false);
$items=@(Get-CimInstance Win32_Process -Filter "Name='sigrok-cli.exe'" -OperationTimeoutSec 2 | Select-Object -First 257);
if($items.Count -gt 256){throw 'count_limit'};
$out=@($items | ForEach-Object {if(!$_.CommandLine -or !$_.ExecutablePath -or !$_.CreationDate){throw 'incomplete'};
 [pscustomobject]@{pid=[uint32]$_.ProcessId;cmd=$_.CommandLine;image=$_.ExecutablePath;creation=$_.CreationDate.ToUniversalTime().ToFileTimeUtc().ToString()}});
ConvertTo-Json -InputObject ([pscustomobject]@{complete=$true;items=$out}) -Compress -Depth 4
"""

TERMINATE_SCRIPT_TEMPLATE = r"""$ErrorActionPreference='Stop';[Console]::OutputEncoding=New-Object System.Text.UTF8Encoding($false);
$r=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('__REQUEST__'))|ConvertFrom-Json;
Add-Type -TypeDefinition @'
using System; using System.Runtime.InteropServices;
public static class PwehSigrokProcess {
 [DllImport("kernel32.dll",SetLastError=true)] public static extern IntPtr OpenProcess(uint a,bool i,uint p);
 [DllImport("kernel32.dll",SetLastError=true)] public static extern bool GetProcessTimes(IntPtr p,out long c,out long e,out long k,out long u);
 [DllImport("kernel32.dll",SetLastError=true)] public static extern bool TerminateProcess(IntPtr p,uint e);
 [DllImport("kernel32.dll",SetLastError=true)] public static extern uint WaitForSingleObject(IntPtr p,uint ms);
 [DllImport("kernel32.dll")] public static extern bool CloseHandle(IntPtr p);
}
'@;
$h=[PwehSigrokProcess]::OpenProcess(0x101001,$false,[uint32]$r.pid);
if($h -eq [IntPtr]::Zero){throw 'open_process_unverified'};
try {
 [long]$c=0;[long]$e=0;[long]$k=0;[long]$u=0;
 if(![PwehSigrokProcess]::GetProcessTimes($h,[ref]$c,[ref]$e,[ref]$k,[ref]$u)){throw 'times_failed'};
 if(($c - ($c % 10)) -ne [long]$r.creation){throw 'identity_changed'};
 $p=Get-CimInstance Win32_Process -Filter ('ProcessId='+[uint32]$r.pid) -OperationTimeoutSec 2;
 if(!$p){if([PwehSigrokProcess]::WaitForSingleObject($h,0) -ne 0){throw 'missing_not_exited'}}
 else {
  if($p.CommandLine -cne $r.cmd -or $p.ExecutablePath -cne $r.image -or
     $p.CreationDate.ToUniversalTime().ToFileTimeUtc().ToString() -cne $r.creation){throw 'identity_changed'};
  if([PwehSigrokProcess]::WaitForSingleObject($h,0) -ne 0){
   if(![PwehSigrokProcess]::TerminateProcess($h,1)){throw 'terminate_failed'};
   if([PwehSigrokProcess]::WaitForSingleObject($h,[uint32]$r.wait_ms) -ne 0){throw 'still_running'}
  }
 }
} finally {if(![PwehSigrokProcess]::CloseHandle($h)){throw 'close_failed'}};
'{"terminated":true}'
"""


class SigrokOwnedProcessProbe:
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

    def observe(self, launch: SigrokLaunch, *, deadline: float) -> tuple[SigrokIdentity, ...]:
        end = _deadline(deadline)
        if type(launch) is not SigrokLaunch:
            _fail()
        rows = parse_process_snapshot(self._run(QUERY_SCRIPT, end), deadline=end)
        matches = []
        for row in rows:
            _check(end)
            # 같은 고유 image의 다른 argv/세대는 다른 작업으로 무시하지 않는다.
            if W._path_key(row.image).casefold() == W._path_key(launch.image).casefold():
                if not matches_launch(row, launch, deadline=end):
                    _fail()
                matches.append(row)
        if len(matches) > 1:
            _fail()
        _check(end)
        return tuple(matches)

    def terminate_and_confirm(self, launch: SigrokLaunch, observed: tuple[SigrokIdentity, ...], *, deadline: float) -> bool:
        """관찰 세대 재대조 뒤 같은 핸들만 종료한다. 미확인/변경/실패는 False다."""
        try:
            end = _deadline(deadline)
            if (type(observed) is not tuple or len(observed) > 1
                    or any(type(row) is not SigrokIdentity or not matches_launch(row, launch, deadline=end) for row in observed)):
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
