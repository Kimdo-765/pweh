"""OpenOCD(Jim Tcl) 문자열 처리 유틸리티.

- Tcl 리스트 파싱(``split_list``): Jim 의 리스트 문자열 표현(단순/중괄호/백슬래시 인용)을 해석한다.
  OpenOCD TCL RPC 응답은 우리가 보낸 봉투(``list [catch ...]``)가 만든 Tcl 리스트이므로 이 파서로 분해한다.
- 봉투(envelope): OpenOCD TCL RPC 에는 오류 플래그가 없으므로 ``catch`` 로 감싸 반환 코드를 얻는다.
  * 원시 명령용(작업 지시서/INSTALL_REPORT 에서 실측): ``list [catch {capture {CMD}} _pweh_r] $_pweh_r``
    → ``0 {출력}`` 또는 ``1 {오류}`` (0.11/0.12.0 은 음수 OpenOCD 오류 코드).
  * 데이터 명령용: ``set _pweh_d {}; list [catch {capture {set _pweh_d [CMD]; list}} _pweh_l] $_pweh_d $_pweh_l``
    → ``rc 데이터 로그``. 0.12.0/0.11 의 ``capture`` 는 로그가 있으면 결과를 로그로 덮어쓰므로, 데이터는
    변수로 따로 빼서 로그와 섞이지 않게 한다 (xPack 0.12.0+dev 에서 실측).
- 중괄호 균형 검사: 원시 명령을 ``{...}`` 로 감쌀 때 봉투를 깨고 나오지 못하게 한다.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

WS = " \t\n\r\f\v"

# 원시 명령 봉투 (변수 이름은 사용자 스크립트와 겹치지 않게 _pweh_ 접두)
RAW_PREFIX = "list [catch {capture {"
RAW_SUFFIX = "}} _pweh_r] $_pweh_r"
DATA_PREFIX = "set _pweh_d {}; list [catch {capture {set _pweh_d ["
DATA_SUFFIX = "]; list}} _pweh_l] $_pweh_d $_pweh_l"

# TCL 서버 줄 버퍼 최대치(4 MiB)보다 충분히 작게 (src/server/tcl_server.c TCL_LINE_MAX)
MAX_REQUEST_BYTES = 4 * 1024 * 1024 - 64 * 1024


class TclParseError(ValueError):
    """Tcl 리스트/스크립트 문자열을 해석할 수 없음."""


# ---------------------------------------------------------------------------
# 백슬래시 치환 / 리스트 파싱
# ---------------------------------------------------------------------------

_SIMPLE_ESCAPES = {"a": "\a", "b": "\b", "f": "\f", "n": "\n", "r": "\r", "t": "\t", "v": "\v"}
_HEX = set("0123456789abcdefABCDEF")
_OCT = set("01234567")


def backslash_subst(s: str, i: int) -> tuple[str, int]:
    """s[i] == '\\' 일 때 Tcl 백슬래시 치환 결과와 다음 인덱스를 반환."""
    n = len(s)
    if i + 1 >= n:
        return "\\", i + 1
    c = s[i + 1]
    if c in _SIMPLE_ESCAPES:
        return _SIMPLE_ESCAPES[c], i + 2
    if c == "\n":
        # 백슬래시-개행 + 뒤따르는 공백/탭 → 공백 하나
        j = i + 2
        while j < n and s[j] in " \t":
            j += 1
        return " ", j
    if c == "x":
        j = i + 2
        while j < n and j < i + 4 and s[j] in _HEX:
            j += 1
        if j == i + 2:
            return "x", i + 2
        return chr(int(s[i + 2 : j], 16)), j
    if c in ("u", "U"):
        maxd = 4 if c == "u" else 8
        j = i + 2
        while j < n and j < i + 2 + maxd and s[j] in _HEX:
            j += 1
        if j == i + 2:
            return c, i + 2
        try:
            return chr(int(s[i + 2 : j], 16)), j
        except (ValueError, OverflowError):
            return "�", j
    if c in _OCT:
        j = i + 1
        while j < n and j < i + 4 and s[j] in _OCT:
            j += 1
        return chr(int(s[i + 1 : j], 8) & 0xFF), j
    return c, i + 2


def _find_close_brace(s: str, start: int) -> int:
    """s[start] == '{' 에 대응하는 '}' 의 인덱스. 백슬래시로 이스케이프된 중괄호는 세지 않는다."""
    depth = 0
    i = start
    n = len(s)
    while i < n:
        ch = s[i]
        if ch == "\\":
            i += 2
            continue
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return i
        i += 1
    raise TclParseError("짝이 맞지 않는 여는 중괄호")


def split_list(s: str) -> list[str]:
    """Tcl 리스트 문자열을 원소 목록으로 분해한다 (Tcl_SplitList 와 같은 규칙).

    - ``{...}`` 원소는 내용을 그대로(백슬래시 치환 없이) 돌려준다.
    - ``"..."`` 원소와 단순 원소는 백슬래시 치환을 적용한다.
    """
    out: list[str] = []
    i = 0
    n = len(s)
    while True:
        while i < n and s[i] in WS:
            i += 1
        if i >= n:
            break
        ch = s[i]
        if ch == "{":
            j = _find_close_brace(s, i)
            out.append(s[i + 1 : j])
            i = j + 1
            if i < n and s[i] not in WS:
                raise TclParseError("중괄호 원소 뒤에 공백이 아닌 문자가 있음")
        elif ch == '"':
            buf: list[str] = []
            i += 1
            while True:
                if i >= n:
                    raise TclParseError("짝이 맞지 않는 큰따옴표")
                c = s[i]
                if c == "\\":
                    sub, i = backslash_subst(s, i)
                    buf.append(sub)
                    continue
                if c == '"':
                    i += 1
                    break
                buf.append(c)
                i += 1
            out.append("".join(buf))
            if i < n and s[i] not in WS:
                raise TclParseError("따옴표 원소 뒤에 공백이 아닌 문자가 있음")
        else:
            buf = []
            while i < n and s[i] not in WS:
                c = s[i]
                if c == "\\":
                    sub, i = backslash_subst(s, i)
                    buf.append(sub)
                    continue
                buf.append(c)
                i += 1
            out.append("".join(buf))
    return out


def list_complete(s: str) -> bool:
    """s 가 완결된 Tcl 리스트로 해석되는지 (짝이 맞지 않는 중괄호/따옴표가 없는지)."""
    try:
        split_list(s)
        return True
    except TclParseError:
        return False


# ---------------------------------------------------------------------------
# 명령 조립 검증
# ---------------------------------------------------------------------------


def braces_balanced(script: str) -> bool:
    """``{`` + script + ``}`` 가 내용이 정확히 script 인 하나의 중괄호 단어가 되는지 검사.

    Tcl 규칙: 중괄호 안에서 백슬래시 다음 문자는 세지 않는다. 깊이가 음수가 되거나(봉투 탈출),
    끝에서 0 이 아니거나, 홀수 개의 백슬래시로 끝나면(닫는 중괄호를 이스케이프) 거짓.
    """
    depth = 0
    i = 0
    n = len(script)
    while i < n:
        ch = script[i]
        if ch == "\\":
            if i + 1 >= n:
                return False  # 끝 백슬래시가 봉투의 닫는 중괄호를 먹는다
            i += 2
            continue
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth < 0:
                return False
        i += 1
    return depth == 0


_PATH_FORBIDDEN = re.compile(r"[{}\\\x00-\x1f\x7f]")


def brace_quote_path(path: str) -> str:
    """호스트 경로를 Tcl 중괄호 단어로 인용. 중괄호/백슬래시/제어문자가 있으면 거부."""
    if not path or _PATH_FORBIDDEN.search(path):
        raise ValueError(f"Tcl 로 안전하게 인용할 수 없는 경로: {path!r}")
    return "{" + path + "}"


def validate_request(script: str) -> None:
    if "\x1a" in script:
        raise ValueError("명령에 0x1a(Ctrl-Z, TCL RPC 종결자)를 넣을 수 없습니다")
    if "\x00" in script:
        raise ValueError("명령에 NUL 문자를 넣을 수 없습니다")
    if len(script.encode("utf-8")) > MAX_REQUEST_BYTES:
        raise ValueError("명령이 너무 깁니다 (OpenOCD TCL 줄 최대 4 MiB)")


_STARTS_WITH_CAPTURE = re.compile(r"^\s*capture[\s{\"]")


def wrap_raw(cmd: str) -> str:
    """원시 명령 봉투. 명령이 이미 ``capture`` 로 시작하면 capture 를 겹치지 않는다
    (중첩 capture 는 같은 로그 줄을 두 번 돌려준다)."""
    if _STARTS_WITH_CAPTURE.match(cmd):
        return "list [catch {" + cmd + "} _pweh_r] $_pweh_r"
    return RAW_PREFIX + cmd + RAW_SUFFIX


def wrap_data(cmd: str) -> str:
    return DATA_PREFIX + cmd + DATA_SUFFIX


# ---------------------------------------------------------------------------
# 응답 해석
# ---------------------------------------------------------------------------


@dataclass
class TclReply:
    """봉투로 감싼 명령의 응답."""

    code: int | None  # catch 반환값 (0=성공, 1 또는 음수=실패, None=해석 불가)
    output: str  # 명령 결과 (원시 봉투에서는 capture 된 로그 + 결과)
    log: str = ""  # 데이터 봉투에서 capture 된 로그 (실패 시 오류 메시지 포함)
    raw: str = ""  # 응답 원문 (0x1a 제외)
    closed: bool = False  # 빈 응답 후 연결 종료 (shutdown/exit 는 catch 로 잡히지 않는다)
    notes: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return self.code == 0

    @property
    def error_text(self) -> str:
        """실패 시 사람이 읽을 오류 문자열 (로그 + 출력에서 추출)."""
        parts = [p.strip() for p in (self.log, self.output) if p and p.strip()]
        return "\n".join(parts)

    def to_dict(self) -> dict:
        out = {"code": self.code, "output": self.output}
        if self.log:
            out["log"] = self.log
        if self.closed:
            out["connection_closed"] = True
        if self.notes:
            out["notes"] = list(self.notes)
        return out


def _parse_code(text: str) -> int | None:
    t = text.strip()
    if re.fullmatch(r"-?\d+", t):
        return int(t)
    return None


def parse_raw_reply(frame: str) -> TclReply:
    """``list [catch {capture {CMD}} r] $r`` 응답 해석."""
    if frame == "":
        return TclReply(code=None, output="", raw=frame, closed=True, notes=["빈 응답 (shutdown/exit 로 연결이 닫혔을 수 있음)"])
    try:
        items = split_list(frame)
    except TclParseError:
        items = []
    if len(items) == 2 and _parse_code(items[0]) is not None:
        out = items[1]
        # 0.11/0.12.0 은 결과 끝의 개행을 남긴다
        return TclReply(code=_parse_code(items[0]), output=out.rstrip("\n"), raw=frame)
    return TclReply(code=None, output=frame, raw=frame, notes=["봉투 형식이 아닌 응답 — 원문을 그대로 돌려줌"])


def parse_data_reply(frame: str) -> TclReply:
    """``... list [catch {capture {set _pweh_d [CMD]; list}} _pweh_l] $_pweh_d $_pweh_l`` 응답 해석."""
    if frame == "":
        return TclReply(code=None, output="", raw=frame, closed=True, notes=["빈 응답 (shutdown/exit 로 연결이 닫혔을 수 있음)"])
    try:
        items = split_list(frame)
    except TclParseError:
        items = []
    if len(items) == 3 and _parse_code(items[0]) is not None:
        return TclReply(code=_parse_code(items[0]), output=items[1].rstrip("\n"), log=items[2].rstrip("\n"), raw=frame)
    if len(items) == 2 and _parse_code(items[0]) is not None:
        return TclReply(code=_parse_code(items[0]), output=items[1].rstrip("\n"), raw=frame)
    return TclReply(code=None, output=frame, raw=frame, notes=["봉투 형식이 아닌 응답 — 원문을 그대로 돌려줌"])


def is_notification(frame: str) -> bool:
    """``tcl notifications`` / ``tcl trace`` 비동기 프레임 (``type target_... \\r\\n``)."""
    return frame.startswith("type target_") and frame.endswith("\r\n")


__all__ = [
    "MAX_REQUEST_BYTES",
    "TclParseError",
    "TclReply",
    "backslash_subst",
    "brace_quote_path",
    "braces_balanced",
    "is_notification",
    "list_complete",
    "parse_data_reply",
    "parse_raw_reply",
    "split_list",
    "validate_request",
    "wrap_data",
    "wrap_raw",
]
