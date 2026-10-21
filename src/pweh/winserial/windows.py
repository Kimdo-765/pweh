"""고정 Windows helper만 조회/정리한다. import는 Windows를 실행하지 않는다."""
from __future__ import annotations

import base64
import json
import os
import re
import selectors
import subprocess
import time
from pathlib import Path

from ..errors import Busy, DeviceError
from .. import procutil
from .binary import BASENAME

_QUERY = r"""$ErrorActionPreference='Stop';[Console]::OutputEncoding=New-Object System.Text.UTF8Encoding($false);
$items=@(Get-CimInstance Win32_Process -Filter "Name='pweh-serial-helper.exe'" -OperationTimeoutSec 2 | Select-Object -First 257);
if($items.Count -gt 256){throw 'count_limit'};
$out=@($items | ForEach-Object {if(!$_.CommandLine -or !$_.ExecutablePath -or !$_.CreationDate){throw 'incomplete'};
  [pscustomobject]@{pid=[int]$_.ProcessId;cmd=$_.CommandLine;image=$_.ExecutablePath;creation=$_.CreationDate.ToUniversalTime().ToFileTimeUtc().ToString()}});
ConvertTo-Json -InputObject ([pscustomobject]@{complete=$true;items=$out}) -Compress -Depth 4
"""

_TERMINATE = r"""$ErrorActionPreference='Stop';[Console]::OutputEncoding=New-Object System.Text.UTF8Encoding($false);
$r=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('__REQUEST__'))|ConvertFrom-Json;
Add-Type -TypeDefinition @'
using System; using System.Runtime.InteropServices;
public static class PwehSerialProcess {
 [DllImport("kernel32.dll",SetLastError=true)] public static extern IntPtr OpenProcess(uint a,bool i,uint p);
 [DllImport("kernel32.dll",SetLastError=true)] public static extern bool GetProcessTimes(IntPtr p,out long c,out long e,out long k,out long u);
 [DllImport("kernel32.dll",SetLastError=true)] public static extern bool TerminateProcess(IntPtr p,uint e);
 [DllImport("kernel32.dll",SetLastError=true)] public static extern uint WaitForSingleObject(IntPtr p,uint ms);
 [DllImport("kernel32.dll")] public static extern bool CloseHandle(IntPtr p);
}
'@;
$h=[PwehSerialProcess]::OpenProcess(0x101001,$false,[uint32]$r.pid);
if($h -eq [IntPtr]::Zero){throw 'open_process_unverified'};
try {
 [long]$c=0;[long]$e=0;[long]$k=0;[long]$u=0;
 if(![PwehSerialProcess]::GetProcessTimes($h,[ref]$c,[ref]$e,[ref]$k,[ref]$u)){throw 'times_failed'};
 $p=Get-CimInstance Win32_Process -Filter ('ProcessId='+[int]$r.pid) -OperationTimeoutSec 2;
 if(!$p){if([PwehSerialProcess]::WaitForSingleObject($h,0) -ne 0){throw 'missing_not_exited'}}
 else {
  if($p.CommandLine -cne $r.cmd -or $p.ExecutablePath -ine $r.image -or
     $p.CreationDate.ToUniversalTime().ToFileTimeUtc().ToString() -cne $r.creation -or
     ($c - ($c % 10)) -ne [long]$r.creation){throw 'identity_changed'};
  if([PwehSerialProcess]::WaitForSingleObject($h,0) -ne 0){
   if(![PwehSerialProcess]::TerminateProcess($h,1)){throw 'terminate_failed'};
   if([PwehSerialProcess]::WaitForSingleObject($h,[uint32]$r.wait_ms) -ne 0){throw 'still_running'}
  }
 };
 '{"terminated":true}'
} finally {[void][PwehSerialProcess]::CloseHandle($h)}
"""


def _bounded(argv: list[str], deadline: float, *, cap: int = 1 << 20) -> bytes:
    """관찰용 고정 명령의 파이프를 상한 안에서 읽고 own POSIX 그룹을 회수한다."""
    if deadline <= time.monotonic():
        raise TimeoutError("Windows 조회 예산 없음")
    p = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                         start_new_session=True, close_fds=True, bufsize=0)
    st = procutil.proc_stat(p.pid)
    ticks = st[1] if st else None
    result = bytearray(); errors = bytearray()
    try:
        with selectors.DefaultSelector() as sel:
            for stream, target in ((p.stdout, result), (p.stderr, errors)):
                os.set_blocking(stream.fileno(), False); sel.register(stream, selectors.EVENT_READ, target)
            while sel.get_map():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError("Windows 조회 시간 초과")
                for key, _ in sel.select(min(.05, remaining)):
                    chunk = os.read(key.fd, 65536)
                    if not chunk:
                        sel.unregister(key.fileobj)
                    else:
                        key.data.extend(chunk)
                        if len(result) + len(errors) > cap:
                            raise ValueError("Windows 조회 출력 상한")
            while not procutil.child_exited(p.pid):
                if time.monotonic() >= deadline:
                    raise TimeoutError("Windows 조회 종료 시간 초과")
                time.sleep(.01)
        if procutil.process_group_empty(p.pid, expect_start_ticks=ticks) is not True:
            raise RuntimeError("Windows 조회 자식 정리 미확인")
        if p.wait(timeout=0) != 0:
            raise RuntimeError("Windows 조회 실패")
        return bytes(result)
    finally:
        if p.returncode is None:
            procutil.kill_process_group(p.pid, grace=0, expect_start_ticks=ticks)
            if procutil.process_group_empty(p.pid, expect_start_ticks=ticks) is True:
                p.wait(timeout=.1)
        p.stdout.close(); p.stderr.close()


def _run(script: str, deadline: float) -> bytes:
    from ..hostenv import powershell_path
    path = powershell_path()
    if not path:
        raise RuntimeError("고정 PowerShell 경로 없음")
    encoded = base64.b64encode(script.encode("utf-16le")).decode("ascii")
    return _bounded([path, "-NoLogo", "-NoProfile", "-NonInteractive", "-EncodedCommand", encoded], deadline)


def split_command(line: str) -> list[str]:
    """Windows 따옴표/백슬래시 규칙. 불완전 따옴표는 확인 불가로 처리한다."""
    if not isinstance(line, str) or len(line) > 32768 or "\0" in line:
        raise ValueError("명령줄 형식 오류")
    args = []; current = []; quoted = have = False; i = 0
    while i < len(line):
        c = line[i]
        if c == "\\":
            j = i
            while j < len(line) and line[j] == "\\": j += 1
            n = j - i
            if j < len(line) and line[j] == '"':
                current.append("\\" * (n // 2))
                if n % 2: current.append('"')
                else: quoted = not quoted
                i = j + 1
            else:
                current.append("\\" * n); i = j
            have = True; continue
        if c == '"': quoted = not quoted; have = True
        elif c in " \t" and not quoted:
            if have: args.append("".join(current)); current = []; have = False
        else: current.append(c); have = True
        i += 1
    if quoted:
        raise ValueError("불완전 명령줄")
    if have: args.append("".join(current))
    return args


def _args(row: dict) -> list[str]:
    argv = split_command(row["cmd"])
    if not argv or argv[0].replace("\\", "/").rsplit("/", 1)[-1].lower() != BASENAME:
        raise ValueError("helper 명령줄 이미지 불일치")
    return argv[1:]


class WindowsLifecycle:
    """관찰 실패는 부재가 아니다. 특정 launch token의 같은 프로세스 핸들만 종료한다."""
    def __init__(self, *, runner=None, path_converter=None):
        self.runner = runner or _run
        self.path_converter = path_converter or self._windows_path

    @staticmethod
    def _windows_path(path: str, deadline: float) -> str:
        out = _bounded(["/usr/bin/wslpath", "-w", path], deadline, cap=8192)
        return out.decode("utf-8", "strict").strip()

    def _query(self, deadline: float) -> list[dict]:
        raw = self.runner(_QUERY, deadline)
        if not isinstance(raw, bytes) or len(raw) > 1 << 20:
            raise ValueError("조회 출력 형식/상한")
        obj = json.loads(raw.decode("utf-8-sig"))
        if not isinstance(obj, dict) or obj.get("complete") is not True or not isinstance(obj.get("items"), list) or len(obj["items"]) > 256:
            raise ValueError("불완전 Windows 조회")
        seen = set()
        for row in obj["items"]:
            if (not isinstance(row, dict) or type(row.get("pid")) is not int or row["pid"] <= 0
                    or row["pid"] in seen or not isinstance(row.get("image"), str)
                    or row["image"].replace("\\", "/").rsplit("/", 1)[-1].lower() != BASENAME
                    or not isinstance(row.get("creation"), str) or not re.fullmatch(r"[0-9]{1,20}", row["creation"])):
                raise ValueError("Windows 프로세스 신원 오류")
            seen.add(row["pid"]); _args(row)
        return obj["items"]

    def check_port(self, port: str, deadline: float) -> None:
        try:
            rows = self._query(deadline)
            for row in rows:
                argv = _args(row)
                if len(argv) == 4 and argv[:2] == ["--port", port] and argv[2] == "--token":
                    raise Busy("같은 COM을 보유한 직렬 helper가 남아 있습니다.")
                if "--port" in argv and (len(argv) != 4 or argv[0] != "--port"):
                    raise ValueError("helper 인자 확인 불가")
        except Busy:
            raise
        except Exception as exc:
            raise DeviceError("Windows helper 점유 조회를 확인하지 못했습니다.", code="serial_helper_holders_unknown") from exc

    def terminate_and_confirm(self, token: str, image_path: str, deadline: float) -> bool:
        if not re.fullmatch(r"[0-9a-f]{32}", token):
            return False
        try:
            image = self.path_converter(image_path, deadline)
            rows = self._query(deadline)
            matches = []
            for row in rows:
                argv = _args(row)
                if len(argv) >= 2 and argv[-2:] == ["--token", token]:
                    if row["image"].casefold() != image.casefold():
                        return False
                    matches.append(row)
            if len(matches) > 1:
                return False
            for row in matches:
                remaining = deadline - time.monotonic()
                if remaining <= 0: return False
                request = {**row, "wait_ms": max(1, min(2000, int(remaining * 1000)))}
                encoded = base64.b64encode(json.dumps(request, separators=(",", ":")).encode()).decode()
                result = self.runner(_TERMINATE.replace("__REQUEST__", encoded), deadline)
                if json.loads(result).get("terminated") is not True:
                    return False
            return not any(_args(row)[-2:] == ["--token", token] for row in self._query(deadline))
        except Exception:
            return False
