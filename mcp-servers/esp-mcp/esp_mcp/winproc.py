"""Windows 쪽 프로세스 조회·종료와 ANSI 코드 페이지 (방법 A 의 esptool.exe 정리용).

공식 Windows esptool.exe 는 PyInstaller onefile 빌드다. 실행하면 부트로더 프로세스가 ``%TEMP%\\_MEI<번호>`` 에 압축을 풀고
같은 명령줄로 자식 프로세스(실제 esptool)를 띄운 뒤 기다리고, 자식이 끝나면 임시 디렉터리를 지우고 끝난다.
WSL interop 프로세스(리눅스 쪽)를 죽이면 부트로더만 끝나고 자식은 COM 포트를 잡은 채 계속 돈다(실측). 그래서 서버는
취소·시간 초과·종료 때 명령줄의 고유 표식으로 Windows 프로세스를 찾아 **자식부터** 끝낸다 — 그러면 부트로더가 임시
디렉터리를 지우고 스스로 끝난다.

이 모듈은 powershell.exe 로 읽기 전용 CIM 질의(Win32_Process)와 ``Stop-Process`` 만 한다. 테스트는 ``query`` /
``terminate`` / ``windows_ansi_encoding`` 을 바꿔 끼운다(실제 Windows 프로세스를 건드리지 않게).
"""

from __future__ import annotations

import codecs
import json
import logging
import re
import threading
from dataclasses import dataclass
from typing import Iterable, Sequence

from . import ports

log = logging.getLogger("pweh.esp")

#: 이름이 image 인 프로세스의 PID·부모·나이(초)·명령줄을 JSON 으로 (읽기 전용 CIM 질의)
_PS_QUERY = (
    "$ErrorActionPreference='Stop';"
    "[Console]::OutputEncoding=[System.Text.Encoding]::UTF8;"
    "$now=Get-Date;"
    "$p=@(Get-CimInstance -ClassName Win32_Process -Filter \"Name='{image}'\" | ForEach-Object {{"
    "[pscustomobject]@{{pid=$_.ProcessId;ppid=$_.ParentProcessId;name=$_.Name;"
    "age=$(if ($_.CreationDate) {{ [math]::Round(($now - $_.CreationDate).TotalSeconds,3) }} else {{ $null }});"
    "cmd=$_.CommandLine}} }});"
    "ConvertTo-Json -InputObject $p -Compress -Depth 3"
)
_IMAGE_RE = re.compile(r"^[A-Za-z0-9._+-]{1,64}\.exe$", re.I)


@dataclass(frozen=True)
class WinProc:
    pid: int
    ppid: int
    name: str
    age_s: float | None
    command_line: str

    def argv(self) -> list[str]:
        return split_cmdline(self.command_line)


def split_cmdline(s: str) -> list[str]:
    """Windows 명령줄 → 인자 목록 (CommandLineToArgvW 규칙: 큰따옴표, 따옴표 앞 백슬래시)."""
    args: list[str] = []
    cur: list[str] = []
    in_q = False
    have = False
    i, n = 0, len(s or "")
    while i < n:
        c = s[i]
        if c == "\\":
            j = i
            while j < n and s[j] == "\\":
                j += 1
            nb = j - i
            if j < n and s[j] == '"':
                cur.append("\\" * (nb // 2))
                if nb % 2:
                    cur.append('"')
                    i = j + 1
                else:
                    i = j
                have = True
                continue
            cur.append("\\" * nb)
            have = True
            i = j
            continue
        if c == '"':
            in_q = not in_q
            have = True
            i += 1
            continue
        if c in " \t" and not in_q:
            if have:
                args.append("".join(cur))
                cur, have = [], False
            i += 1
            continue
        cur.append(c)
        have = True
        i += 1
    if have:
        args.append("".join(cur))
    return args


def _has_seq(argv: Sequence[str], seq: Sequence[str], *, fold: bool) -> bool:
    if not seq:
        return True
    norm = (lambda x: x.lower()) if fold else (lambda x: x)
    a = [norm(x) for x in argv]
    want = [norm(x) for x in seq]
    k = len(want)
    return any(a[i:i + k] == want for i in range(len(a) - k + 1))


@dataclass(frozen=True)
class WinMatch:
    """이번 실행이 띄운 Windows esptool.exe 를 알아보는 표식.

    - ``image``: Win32_Process.Name (예 'esptool.exe')
    - ``sequences``: 명령줄 인자에 연속해서 모두 있어야 하는 토큰 묶음. read-flash 는 서버가 예약한 UNC 출력 경로(유일),
      정보 명령은 ``("--port", "COMn")`` + 명령 이름(같은 포트의 호출은 서버가 한 번에 하나만 돌린다).
    """

    image: str
    sequences: tuple[tuple[str, ...], ...]
    fold_case: bool = True

    def matches(self, p: WinProc) -> bool:
        if p.name.lower() != self.image.lower():
            return False
        argv = p.argv()
        return all(_has_seq(argv, seq, fold=self.fold_case) for seq in self.sequences)


def parse_query_output(text: str) -> list[WinProc]:
    data = json.loads((text or "").strip().lstrip("﻿") or "[]")
    if isinstance(data, dict):
        data = [data]
    out: list[WinProc] = []
    for d in data or []:
        if not isinstance(d, dict):
            continue
        try:
            age = d.get("age")
            out.append(WinProc(pid=int(d["pid"]), ppid=int(d.get("ppid") or 0), name=str(d.get("name") or ""),
                               age_s=None if age is None else float(age), command_line=str(d.get("cmd") or "")))
        except (KeyError, TypeError, ValueError):
            continue
    return out


def query(image: str) -> list[WinProc]:
    """이름이 image 인 Windows 프로세스 목록. powershell 이 없거나 실패하면 예외(호출하는 쪽이 '확인 불가'로 다룬다)."""
    if not _IMAGE_RE.match(image or ""):
        raise ValueError(f"잘못된 이미지 이름: {image!r}")
    rc, out, err = ports.run_powershell(_PS_QUERY.format(image=image), timeout=45.0)
    if rc != 0:
        raise RuntimeError(f"powershell.exe 오류(rc={rc}): {err.strip()[:300]}")
    return parse_query_output(out)


def terminate(pids: Iterable[int]) -> None:
    """Stop-Process -Force (TerminateProcess). 이미 끝난 PID 는 무시한다."""
    ids = sorted({int(p) for p in pids if int(p) > 0})
    if not ids:
        return
    script = "$ErrorActionPreference='SilentlyContinue';" + ";".join(f"Stop-Process -Id {i} -Force" for i in ids)
    try:
        ports.run_powershell(script, timeout=45.0)
    except Exception:  # noqa: BLE001 - 확인은 다음 query 가 한다
        log.warning("Windows 프로세스 종료 실패: %s", ids, exc_info=True)


def children_first(procs: Sequence[WinProc]) -> tuple[list[WinProc], list[WinProc]]:
    """(자식, 나머지). 부모가 같은 목록 안에 있는 프로세스가 PyInstaller 자식이다."""
    pids = {p.pid for p in procs}
    kids = [p for p in procs if p.ppid in pids]
    rest = [p for p in procs if p.ppid not in pids]
    return kids, rest


def port_holders(port: str, images: Iterable[str]) -> list[WinProc] | None:
    """그 COM 포트를 인자로 받은 esptool.exe 프로세스 (``--port COMn`` / ``--port=COMn`` / ``-p COMn``). 확인할 수 없으면 None."""
    found: dict[int, WinProc] = {}
    want = port.lower()
    for image in dict.fromkeys(i for i in images if i):
        try:
            procs = query(image)
        except Exception:  # noqa: BLE001
            log.debug("Windows 프로세스 조회 실패", exc_info=True)
            return None
        for p in procs:
            argv = [a.lower() for a in p.argv()]
            if (_has_seq(argv, ("--port", want), fold=False) or _has_seq(argv, ("-p", want), fold=False)
                    or f"--port={want}" in argv):
                found[p.pid] = p
    return sorted(found.values(), key=lambda p: p.pid)


def token_holders(tokens: Iterable[str], images: Iterable[str]) -> list[WinProc] | None:
    """명령줄 인자 중 하나가 tokens 의 값(예: 서버가 예약한 UNC 출력 경로)과 같은 프로세스 (대소문자 무시). 확인할 수 없으면 None.

    서버가 SIGKILL 로 죽으면 PyInstaller 자식(esptool.exe)이 남아 예약 파일에 계속 쓸 수 있다. 다음 서버는 소유 표식에 적힌 출력
    경로로 그 프로세스를 찾는다(남아 있으면 예약을 지우지 않는다).
    """
    want = {t.lower() for t in tokens if t}
    if not want:
        return []
    found: dict[int, WinProc] = {}
    for image in dict.fromkeys(i for i in images if i):
        try:
            procs = query(image)
        except Exception:  # noqa: BLE001
            log.debug("Windows 프로세스 조회 실패", exc_info=True)
            return None
        for p in procs:
            if any(a.lower() in want for a in p.argv()):
                found[p.pid] = p
    return sorted(found.values(), key=lambda p: p.pid)


def pids_alive(pids: Iterable[int], images: Iterable[str]) -> list[int] | None:
    """그 PID 중 아직 살아 있는 것 (이름이 images 인 것만). 확인할 수 없으면 None."""
    want = {int(p) for p in pids}
    if not want:
        return []
    alive: set[int] = set()
    for image in dict.fromkeys(i for i in images if i):
        try:
            alive |= {p.pid for p in query(image) if p.pid in want}
        except Exception:  # noqa: BLE001
            return None
    return sorted(alive)


# ---------------------------------------------------------------------------
# Windows ANSI 코드 페이지 (esptool.exe 는 파이프 출력을 이 인코딩으로 쓴다: 한국어 Windows 는 cp949)
# ---------------------------------------------------------------------------

_ANSI_LOCK = threading.Lock()
_ANSI: list[str] = []
_PS_ACP = "(Get-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Nls\\CodePage' -Name ACP).ACP"


def windows_ansi_encoding() -> str:
    """Windows ANSI 코드 페이지의 파이썬 코덱 이름 (한 번만 조회해 캐시). 알 수 없으면 'latin-1'(디코딩이 실패하지 않음)."""
    with _ANSI_LOCK:
        if _ANSI:
            return _ANSI[0]
        enc = "latin-1"
        try:
            rc, out, _err = ports.run_powershell(_PS_ACP, timeout=30.0)
            n = out.strip()
            if rc == 0 and n.isdigit():
                cand = "utf-8" if n == "65001" else f"cp{n}"
                codecs.lookup(cand)
                enc = cand
        except Exception:  # noqa: BLE001
            log.debug("Windows ANSI 코드 페이지 조회 실패", exc_info=True)
        _ANSI.append(enc)
        return enc


def reset_cache() -> None:
    with _ANSI_LOCK:
        _ANSI.clear()


__all__ = [
    "WinMatch",
    "WinProc",
    "children_first",
    "parse_query_output",
    "pids_alive",
    "port_holders",
    "query",
    "reset_cache",
    "split_cmdline",
    "terminate",
    "windows_ansi_encoding",
]
