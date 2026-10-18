"""PWEH 종단(e2e) 흐름: 스크립트로 흉내 낸 에이전트가 실제 MCP 서버를 Skill 순서대로 호출한다.

tests/e2e/test_pipeline_e2e.py 와 scripts/run_example.py 가 같은 흐름을 쓴다.

- 서버: pweh-case / pweh-uart / pweh-fwtriage 는 in-memory ``mcp.Client``, REA 는 stdio ``rea --mcp``(선택).
- 기기: ``pweh.mocktarget.MockDevice`` (PTY) + 합성 펌웨어 (zig + mksquashfs 전체 빌드).
- 사람 역할(전원 재투입, 계정 알려 주기)은 ``Human`` 이 흉내 내고 타임라인에 남긴다.
- **원칙**: 에이전트의 판단은 도구 출력과 Skill 규칙에서만 나온다. 펌웨어 매니페스트(정답)는 읽지 않는다.
  정답 대조(``match_planted``)는 기록된 도구 출력(관찰)으로 테스트·예제 생성기가 따로 한다.
- 결과 기록: 모든 MCP 호출(인자 + 결과)을 ``Recorder`` 에 남긴다. 비밀값(토큰, 내장 자격증명, 크랙된 비밀번호)은
  도구 출력에서 알아낸 것을 ``Secrets`` 에 모아 발견사항 발췌와 예제 출력에서 마스킹한다.
"""

from __future__ import annotations

import base64
import binascii
import contextlib
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT / "tests") not in sys.path:
    sys.path.insert(0, str(REPO_ROOT / "tests"))

from mcp_helpers import result_data  # noqa: E402

TOOLS_ENV = Path(os.environ.get("PWEH_TOOLS_ENV", str(Path.home() / "pweh-tools" / "env.sh")))

# 시뮬레이터 프로필 → pipeline-config.yaml 프로필 (케이스 프로필)
PIPELINE_PROFILE = {
    "hisilicon-like": "mock-hisilicon",
    "ingenic-like": "mock-ingenic",
    "hisilicon-legacy": "hisilicon-ipcam",
    "hikvision-like": "hikvision-ipc",
    "dahua-like": "dahua-ipc",
}

AGENT_NAME = "pweh-e2e scripted agent (tests/e2e/agent_flow.py)"
AUTH_PROC_RX = "(?i)auth|login|passw|cred|session|token|verify|static|cgi|lang|local|config|dispatch"
# AH-05 (정적 파일/URL 접두사 allowlist) 대체 질의: 경로 접두사·확장자 리터럴 (REA 가 없을 때의 1차 근거)
AH05_PATTERNS = ["re:^/[A-Za-z0-9_.-]+/$", r"re:^\.(?:css|js|png|jpg|gif|html?)$"]
SEV_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
CONF_RANK = {"confirmed": 0, "likely": 1, "possible": 2}


# ---------------------------------------------------------------------------
# 환경: 외부 도구, 합성 펌웨어, REA
# ---------------------------------------------------------------------------
def tool_path(env: str, name: str) -> str | None:
    val = os.environ.get(env)
    if val and Path(val).is_file():
        return val
    cand = Path.home() / "pweh-tools" / "bin" / name
    if cand.is_file():
        return str(cand)
    return shutil.which(name)


def build_firmware(profile: str, out_dir: Path) -> tuple[Path, dict[str, Any]]:
    """전체 합성 펌웨어(zig httpd + squashfs)를 out_dir 에 만든다. 대체 빌드면 manifest['fallbacks'] 가 비어 있지 않다."""
    from pweh.mocktarget.firmware import build_image

    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / f"{profile}-firmware.bin"
    manifest = build_image(profile, path, zig=tool_path("PWEH_ZIG", "zig"), mksquashfs=tool_path("PWEH_MKSQUASHFS", "mksquashfs"))
    return path, manifest


def rea_env() -> dict[str, str]:
    """~/pweh-tools/env.sh 를 적용한 환경 (scripts/mcp-launch.sh 와 같은 방식)."""
    env = dict(os.environ)
    if TOOLS_ENV.is_file():
        try:
            out = subprocess.run(["bash", "-c", f". '{TOOLS_ENV}' >/dev/null 2>&1; env -0"], capture_output=True, check=True,
                                 timeout=30).stdout
            env = dict(kv.split("=", 1) for kv in out.decode("utf-8", "replace").split("\0") if "=" in kv)
        except (OSError, subprocess.SubprocessError):
            pass
    env.setdefault("REA_GHIDRA_STARTUP_TIMEOUT_MS", "600000")
    return env


def rea_command(env: dict[str, str] | None = None) -> str | None:
    env = env or os.environ
    for cand in (env.get("PWEH_REA"), shutil.which("rea", path=env.get("PATH")), str(Path.home() / ".local" / "bin" / "rea")):
        if cand and Path(cand).exists():
            return cand
    return None


def rea_available() -> tuple[bool, str]:
    env = rea_env()
    cmd = rea_command(env)
    if not cmd:
        return False, "rea 실행 파일 없음 (PWEH_REA / PATH / ~/.local/bin/rea)"
    gh = env.get("GHIDRA_INSTALL_DIR")
    if not gh or not Path(gh).is_dir():
        return False, "GHIDRA_INSTALL_DIR 없음 (~/pweh-tools/env.sh)"
    return True, cmd


def rea_params(cwd: Path) -> Any:
    from mcp import StdioServerParameters

    env = rea_env()
    cmd = rea_command(env)
    if not cmd:
        raise RuntimeError("rea 없음")
    return StdioServerParameters(command=cmd, args=["--mcp"], env=env, cwd=str(cwd))


# ---------------------------------------------------------------------------
# 비밀값 마스킹 / 결과 요약
# ---------------------------------------------------------------------------
class Secrets:
    """도구 출력에서 알아낸 비밀값(합성 토큰, 내장 자격증명, 크랙된 비밀번호). 발췌·예제 출력에서 마스킹한다."""

    def __init__(self) -> None:
        self.values: dict[str, str] = {}

    def add(self, value: str | None, label: str) -> None:
        if value and len(value) >= 4 and value not in self.values:
            self.values[value] = label

    def mask(self, text: Any) -> Any:
        if isinstance(text, str):
            out = text
            for v in sorted(self.values, key=len, reverse=True):
                if v in out:
                    out = out.replace(v, f"{v[:2]}…<마스킹:{self.values[v]},{len(v)}자>")
            return out
        if isinstance(text, list):
            return [self.mask(x) for x in text]
        if isinstance(text, dict):
            return {k: self.mask(v) for k, v in text.items()}
        return text


def abridge(obj: Any, *, depth: int = 0, max_str: int = 400, max_list: int = 8, max_depth: int = 5) -> Any:
    """긴 결과를 줄인다 (tool-calls.jsonl 용)."""
    if isinstance(obj, str):
        return obj if len(obj) <= max_str else obj[:max_str] + f"…(+{len(obj) - max_str}자)"
    if isinstance(obj, list):
        items = [abridge(x, depth=depth + 1, max_str=max_str, max_list=max_list, max_depth=max_depth) for x in obj[:max_list]]
        if len(obj) > max_list:
            items.append(f"…(+{len(obj) - max_list}개)")
        return items
    if isinstance(obj, dict):
        if depth >= max_depth:
            return f"{{…{len(obj)}키}}"
        return {k: abridge(v, depth=depth + 1, max_str=max_str, max_list=max_list, max_depth=max_depth) for k, v in obj.items()}
    return obj


REA_DROP = ("subject", "provider", "analysis_profile", "limitations", "raw_result", "environment", "authority", "predicate_type")


def abridge_result(server: str, tool: str, res: Any) -> Any:
    if server == "rea" and isinstance(res, dict):
        res = {k: v for k, v in res.items() if k not in REA_DROP}
        nr = res.get("normalized_result")
        if isinstance(nr, dict) and "files" in nr:  # extract_firmware: 파일 목록은 개수와 앞부분만
            nr = dict(nr)
            files = nr.get("files") or []
            nr["files"] = [{"relative_path": f.get("relative_path"), "size": f.get("size")} for f in files[:6]] + (
                [f"…(+{len(files) - 6}개)"] if len(files) > 6 else [])
            for k in ("unpublished_entries", "extraction_gaps", "extraction_continuations", "task_derivations"):
                if isinstance(nr.get(k), list):
                    nr[k] = f"{len(nr[k])}개"
            res["normalized_result"] = nr
        return abridge(res, max_str=1200, max_list=12)
    if tool in ("uart_read",):
        return abridge(res, max_str=600)
    return abridge(res)


# ---------------------------------------------------------------------------
# 기록: MCP 호출 / 사람 행동 / 에이전트 메모
# ---------------------------------------------------------------------------
@dataclass
class CallRecord:
    seq: int
    t: float
    phase: str
    server: str
    tool: str
    args: dict[str, Any]
    duration: float
    ok: bool | None
    status: str | None
    error: str | None
    result: Any
    note: str = ""


class Recorder:
    def __init__(self) -> None:
        self.t0 = time.monotonic()
        self.calls: list[CallRecord] = []
        self.timeline: list[dict[str, Any]] = []
        self.phase = "phase-0"
        self._lock = threading.Lock()

    def now(self) -> float:
        return round(time.monotonic() - self.t0, 3)

    def event(self, kind: str, text: str, **extra: Any) -> None:
        with self._lock:
            self.timeline.append({"kind": kind, "t": self.now(), "phase": self.phase, "text": text, **extra})

    def add_call(self, rec: CallRecord) -> None:
        with self._lock:
            self.calls.append(rec)
            self.timeline.append({"kind": "call", "t": rec.t, "phase": rec.phase, "seq": rec.seq, "server": rec.server, "tool": rec.tool})


class Human:
    """사람(운영자) 흉내: 물리 작업은 요청을 받은 뒤 수행하고 타임라인에 남긴다."""

    def __init__(self, dev: Any, rec: Recorder) -> None:
        self.dev = dev
        self.rec = rec

    def power_on_soon(self, delay: float = 0.4, why: str = "") -> threading.Timer:
        self.rec.event("human", f"[사람] 기기 전원을 켠다{(' — ' + why) if why else ''}")
        t = threading.Timer(delay, self.dev.power_on)
        t.start()
        return t

    def power_off(self, why: str = "") -> None:
        self.rec.event("human", f"[사람] 기기 전원을 끈다{(' — ' + why) if why else ''}")
        self.dev.power_off()
        self.dev.wait_for_state("off", 5.0)

    def say(self, text: str) -> None:
        self.rec.event("human", f"[사람] {text}")


class ToolError(RuntimeError):
    pass


class McpHub:
    """in-memory 서버 클라이언트 + 선택적 REA stdio 클라이언트."""

    def __init__(self, rec: Recorder, *, rea: bool = False, rea_cwd: Path | None = None) -> None:
        self.rec = rec
        self.want_rea = rea
        self.rea_cwd = rea_cwd or REPO_ROOT
        self.clients: dict[str, Any] = {}
        self._stack: contextlib.AsyncExitStack | None = None
        self.rea_error: str | None = None
        self._seq = 0

    async def __aenter__(self) -> "McpHub":
        from mcp import Client

        from case_mcp.server import server as case_server
        from fwtriage_mcp.server import server as fw_server
        from uart_mcp.server import server as uart_server

        self._stack = contextlib.AsyncExitStack()
        await self._stack.__aenter__()
        self.clients["pweh-case"] = await self._stack.enter_async_context(Client(case_server))
        self.clients["pweh-uart"] = await self._stack.enter_async_context(Client(uart_server))
        self.clients["pweh-fwtriage"] = await self._stack.enter_async_context(Client(fw_server))
        if self.want_rea:
            ok, why = rea_available()
            if ok:
                try:
                    self.clients["rea"] = await self._stack.enter_async_context(
                        Client(rea_params(self.rea_cwd), read_timeout_seconds=900))
                except Exception as exc:  # REA 기동 실패는 건너뛰고 기록
                    self.rea_error = f"{type(exc).__name__}: {exc}"
            else:
                self.rea_error = why
        return self

    async def __aexit__(self, *exc: Any) -> None:
        if self._stack is not None:
            await self._stack.__aexit__(*exc)

    @property
    def has_rea(self) -> bool:
        return "rea" in self.clients

    async def call(self, server: str, tool: str, /, *, _allow_error: bool = False, _note: str = "", **args: Any) -> Any:
        client = self.clients[server]
        self._seq += 1
        seq = self._seq
        t = self.rec.now()
        start = time.monotonic()
        res = await client.call_tool(tool, args)
        data = result_data(res)
        dur = round(time.monotonic() - start, 3)
        err = data.get("_error") if isinstance(data, dict) else None
        ok = data.get("ok") if isinstance(data, dict) else None
        status = data.get("status") if isinstance(data, dict) else None
        self.rec.add_call(CallRecord(seq, t, self.rec.phase, server, tool, dict(args), dur, ok, status, err, data, _note))
        if err and not _allow_error:
            raise ToolError(f"{server}.{tool} 오류: {err[:600]}")
        return data


# ---------------------------------------------------------------------------
# 관찰(평가용) — 도구 출력에서 뽑은 (파일, 함수, 분류, 텍스트) 항목
# ---------------------------------------------------------------------------
@dataclass
class Observation:
    seq: int
    server: str
    tool: str
    file: str | None
    function: str | None
    category: str | None
    id: str | None
    text: str
    ref: str | None = None

    def brief(self) -> str:
        where = self.file or "?"
        if self.function:
            where += f"::{self.function}"
        return f"#{self.seq} {self.tool}({self.id or ''}) {where}"


def derive_indicators(issue: dict[str, Any]) -> list[str]:
    """정답 항목 → 도구 출력에서 찾을 문자열. 평가 전용 (에이전트는 쓰지 않는다)."""
    if issue.get("indicators"):
        return [str(x) for x in issue["indicators"]]
    inds: list[str] = []
    if issue.get("token"):
        inds.append(str(issue["token"]))
    if issue.get("username") and issue.get("password") and issue.get("category") == "hardcoded-credential" and not issue.get("hash"):
        inds.append(base64.b64encode(f"{issue['username']}:{issue['password']}".encode()).decode())
        inds.append(str(issue["password"]))
    if issue.get("hash"):
        h = str(issue["hash"])
        parts = h.split("$")
        if len(parts) >= 4:
            inds.append("$".join(parts[:3]) + "$")  # $1$<salt>$
    pattern = str(issue.get("pattern") or "")
    quoted = [q for q in re.findall(r'"([^"]{4,})"', pattern)]
    inds.extend(quoted)
    if not quoted and pattern and "..." not in pattern and len(pattern) <= 60:
        inds.append(pattern)
    return list(dict.fromkeys(inds))


def match_planted(planted: list[dict[str, Any]], observations: list[Observation]) -> dict[str, list[Observation]]:
    """정답(planted_issues) → 그것을 드러낸 관찰 목록. 같은 파일이고 (같은 함수 또는 지표 문자열 포함)이면 드러난 것으로 본다."""
    out: dict[str, list[Observation]] = {}
    for issue in planted:
        inds = derive_indicators(issue)
        hits = []
        for o in observations:
            if not o.file or o.file != issue.get("file"):
                continue
            if issue.get("function") and o.function == issue["function"]:
                hits.append(o)
            elif any(ind and ind in o.text for ind in inds):
                hits.append(o)
        out[issue["id"]] = hits
    return out


# ---------------------------------------------------------------------------
# 발견사항 후보 (에이전트 판단)
# ---------------------------------------------------------------------------
@dataclass
class Candidate:
    key: str
    title: str
    category: str
    severity: str
    confidence: str
    file: str | None
    summary: str
    reasoning: str
    evidence: list[dict[str, Any]]
    ah: list[str] = field(default_factory=list)
    function: str | None = None
    address: str | None = None
    offset: str | None = None
    line: int | None = None
    interface: str | None = None
    references: list[str] = field(default_factory=list)
    verification_plan: str = ""
    remediation: str = ""
    skill: str = "firmware-static-analysis"
    tool: str = ""
    status: str | None = None
    finding_id: str | None = None
    recorded_hash: str | None = None

    def upgrade(self, *, confidence: str | None = None, severity: str | None = None, evidence: list[dict[str, Any]] | None = None,
                function: str | None = None, address: str | None = None, reasoning: str | None = None, tool: str | None = None,
                summary: str | None = None, title: str | None = None) -> None:
        if confidence and CONF_RANK[confidence] < CONF_RANK[self.confidence]:
            self.confidence = confidence
        if severity and SEV_RANK[severity] < SEV_RANK[self.severity]:
            self.severity = severity
        for ev in evidence or []:
            if ev not in self.evidence:
                self.evidence.append(ev)
        if function and not self.function:
            self.function = function
        if address and not self.address:
            self.address = address
        if reasoning:
            self.reasoning = reasoning
        if tool:
            self.tool = tool
        if summary:
            self.summary = summary
        if title:
            self.title = title


def _status_for(conf: str) -> str:
    return "static-confirmed" if conf == "confirmed" else "unverified"


VERIFY_GENERIC = ("격리 랩(인터넷과 분리된 VLAN)의 소유 기기에서만 확인한다. 1) 같은 빌드의 펌웨어로 정적 결과를 재현하고 2) 수정 빌드가 있으면 "
                  "해당 함수를 디컴파일 diff 한다. 3) 동적 확인은 정상 거부 동작을 보는 negative test 로 한정하고 우회·공격 요청은 만들지 않는다.")


# ---------------------------------------------------------------------------
# 디컴파일 판독 규칙 (스크립트 에이전트의 "읽기")
# ---------------------------------------------------------------------------
@dataclass
class CodeFinding:
    rule: str
    category: str
    function: str
    reason: str
    excerpt: str
    literals: list[str] = field(default_factory=list)


def _lines_with(code: str, needles: tuple[str, ...], limit: int = 6) -> str:
    keep = [ln.rstrip() for ln in code.splitlines() if any(n in ln for n in needles)]
    return "\n".join(keep[:limit])


def classify_pseudocode(name: str, code: str) -> list[CodeFinding]:
    """Ghidra 의사 C 한 함수 → 패턴 판정 목록 (휴리스틱)."""
    out: list[CodeFinding] = []
    c = code or ""
    # P11: snprintf(buf, …, "...%s...", 요청값); system(buf)
    m = re.search(r'snprintf\((\w+),[^;]*?"([^"]*%s[^"]*)"[^;]*\);\s*(?:\w+\s*=\s*)?system\(\s*(?:\([^)]*\))?\s*\1\s*\)', c, re.S)
    if m:
        out.append(CodeFinding("P11-format-to-system", "command-injection", name,
                               f"포맷 문자열 \"{m.group(2)}\" 의 %s 결과 버퍼가 필터 없이 system() 으로 간다",
                               _lines_with(c, ("snprintf(", "system(", "get_param(", "xml_value(")), [m.group(2)]))
    # 요청 값 ↔ 리터럴 비교 후 곧바로 성공 반환
    lits = re.findall(r'strcmp\(\(c_char \*\)([\w\->\[\]\.]+),\(c_char \*\)"([^"]+)"\)', c)
    has_ret1 = "return 1;" in c or "return (uint)(" in c
    if lits and has_ret1:
        long_token = [lit for _, lit in lits if len(lit) >= 16 and re.fullmatch(r"[A-Za-z0-9_\-]+", lit)]
        cred_pair = [lit for var, lit in lits if re.search(r"pass|pw", var, re.I)] and [lit for var, lit in lits if re.search(r"user|name", var, re.I)]
        if long_token and re.search(r"token", c, re.I):
            out.append(CodeFinding("P4-literal-token-success", "backdoor", name,
                                   "요청 토큰을 .rodata 의 고정 문자열과 strcmp 해 일치하면 자격증명 검사 전에 1(성공)을 반환한다",
                                   _lines_with(c, ("strcmp(", "return 1")), long_token))
        if cred_pair:
            out.append(CodeFinding("P5-literal-credential", "hardcoded-credential", name,
                                   "사용자 이름과 비밀번호를 각각 .rodata 리터럴과 strcmp 해 일치하면 1(성공)을 반환한다 (고정 계정)",
                                   _lines_with(c, ("strcmp(", "return 1")), [lit for _, lit in lits]))
    # P1: 경로 접두사/확장자 리터럴 비교 → 인증 생략(1 반환)
    if re.search(r'strncmp\(\(c_char \*\)\w*path\w*,\(c_char \*\)"/[^"]+/"', c) and re.search(r'strstr\([^;]*"\.(?:css|js|png|jpg)"', c) and has_ret1:
        out.append(CodeFinding("P1-static-allowlist", "auth-bypass", name,
                               "정규화 전 URI 원문을 접두사(strncmp)와 확장자 부분 문자열(strstr)로 비교해 1 을 반환한다 → 호출자가 인증을 생략",
                               _lines_with(c, ("strncmp(", "strstr(", "return"))))
    # P4: 클라이언트가 보낸 loginType / ipAddr 로 "로컬" 신뢰 판정
    if re.search(r'login_?type', c, re.I) and '"Loopback"' in c and '"127.0.0.1"' in c:
        out.append(CodeFinding("P4-client-supplied-local-trust", "auth-bypass", name,
                               "요청 구조체의 login_type == \"Loopback\" 과 ip_addr == \"127.0.0.1\"(클라이언트가 써 넣은 값)만으로 로컬 요청이라고 판정한다",
                               _lines_with(c, ("strcmp(", "return"))))
    if re.search(r"is_local_request\(", c) and "verify_password" in c and re.search(r"ok\s*=\s*1;", c):
        out.append(CodeFinding("P4-local-skips-password", "auth-bypass", name,
                               "is_local_request 가 참이면 verify_password 를 부르지 않고 성공(ok=1)으로 응답한다",
                               _lines_with(c, ("is_local_request(", "verify_password(", "ok = 1", "send_login_result("))))
    # P4: 쿼리 파라미터 존재 → base64 디코드한 사용자명만으로 성공 (비밀번호 비교 없음), 표준 검사는 그 뒤
    if "query_param(" in c and re.search(r"b(?:ase)?64_decode\(", c) and "return 1;" in c and "basic_auth_check(" in c \
            and "verify_password" not in c:
        out.append(CodeFinding("P4-param-presence-skips-password", "auth-bypass", name,
                               "쿼리 파라미터가 있으면 base64 디코드한 값의 ':' 앞 사용자 이름을 신원으로 쓰고 1 을 반환한다. 비밀번호 비교 호출이 없고 "
                               "표준 basic_auth_check 는 그 분기 뒤에만 있다",
                               _lines_with(c, ("query_param(", "b64_decode(", "snprintf(user", "return 1", "basic_auth_check("))))
    # P1/P8: 설정 디렉터리 매핑이 세션 확인보다 먼저
    m = re.search(r'strncmp\(\(c_char \*\)\w+,\(c_char \*\)"(/[\w_]*config[\w_]*/)"', c, re.I)
    if m and "serve_config_file(" in c and "session_valid(" in c and c.find("serve_config_file(") < c.find("session_valid("):
        out.append(CodeFinding("P1-preauth-config-route", "info-leak", name,
                               f"\"{m.group(1)}\" 접두사 요청을 session_valid 보다 먼저 serve_config_file 로 넘긴다 (인증 전 설정 파일 제공)",
                               _lines_with(c, ("strncmp(", "serve_config_file(", "session_valid("))))
    if re.search(r'snprintf\(\w+,[^;]*"/mnt/mtd/Config/%s"', c):
        out.append(CodeFinding("P8-config-dir-file", "info-leak", name, "요청 이름을 /mnt/mtd/Config/ 아래 파일 경로로 만들어 그대로 내려준다",
                               _lines_with(c, ("snprintf(", "send_file(", "strchr(", "strstr("))))
    # 인증 전에 디스패치되는 핸들러 (디스패처: 특정 경로 strcmp → 핸들러 호출이 인증 호출보다 앞)
    m = re.search(r'strcmp\(\(c_char \*\)\w+,\(c_char \*\)"(/[^"]+)"\);\s*if \(\w+ == 0\) \{\s*(\w+)\(', c)
    if m and re.search(r"->auth\)|check_auth\(|basic_auth_check\(|session_valid\(", c):
        handler = m.group(2)
        pos_handler = c.find(handler + "(")
        pos_auth = min([p for p in (c.find("->auth)"), c.find("check_auth("), c.find("session_valid(")) if p >= 0] or [10 ** 9])
        if 0 <= pos_handler < pos_auth:
            out.append(CodeFinding("preauth-dispatch", "auth-bypass", name,
                                   f"디스패처가 \"{m.group(1)}\" 를 인증 호출보다 먼저 {handler}() 로 넘긴다 (인증 전 도달)",
                                   _lines_with(c, ("strcmp(", handler + "(", "->auth)")), [m.group(1), handler]))
    return out


# ---------------------------------------------------------------------------
# 경로 도우미
# ---------------------------------------------------------------------------
def _count(v: Any) -> int:
    if isinstance(v, (list, tuple, dict)):
        return len(v)
    return int(v or 0)


def b64_decode_maybe(s: str) -> str | None:
    try:
        raw = base64.b64decode(s + "=" * (-len(s) % 4), validate=False)
        txt = raw.decode("utf-8")
    except (binascii.Error, UnicodeDecodeError):
        return None
    return txt if txt.isprintable() else None


# ---------------------------------------------------------------------------
# 흐름 본체
# ---------------------------------------------------------------------------
@dataclass
class Scenario:
    """예제 시나리오(합성). 사람이 말한 내용은 그대로 인용한다."""

    title: str
    owner: str = "PWEH 테스트 랩 (합성 시나리오)"
    statement: str = "이 카메라는 제가 직접 구매한 제 소유 기기이며, 하드웨어 보안 분석을 허가합니다. (합성 시나리오: pweh.mocktarget 시뮬레이터)"
    scope: str = "UART 콘솔 접속, 플래시 읽기 전용 덤프, 펌웨어 정적 분석. 영구 변경 금지."
    target: dict[str, Any] = field(default_factory=dict)


class AgentFlow:
    def __init__(self, hub: McpHub, human: Human, *, profile: str, port: str, scenario: Scenario,
                 case_profile: str | None = None, dump_scope: str = "needed", chunk_size: str = "256k",
                 case_id: str | None = None) -> None:
        self.hub = hub
        self.rec = hub.rec
        self.human = human
        self.profile = profile
        self.case_profile = case_profile or PIPELINE_PROFILE.get(profile, "generic-ipcam")
        self.port = port
        self.scenario = scenario
        self.dump_scope = dump_scope
        self.chunk_size = chunk_size
        self.case_id_wanted = case_id
        self.secrets = Secrets()
        self.obs: list[Observation] = []
        self.cands: dict[str, Candidate] = {}
        self.st: dict[str, Any] = {}  # 상태: 각 도구의 핵심 결과
        self.gaps: list[str] = []
        self.rea_bundles: list[str] = []
        self.rea_limitations: list[str] = []
        self.code_findings: dict[str, list[CodeFinding]] = {}  # rootfs 경로 → 판정
        self.rea_evidence: dict[tuple[str, str], str] = {}  # (rootfs 경로, 함수) → evidence_id

    # -- 공통 --------------------------------------------------------------
    async def call(self, server: str, tool: str, /, **kw: Any) -> Any:
        res = await self.hub.call(server, tool, **kw)
        self._observe(tool, server, kw, res)
        return res

    def phase(self, name: str, note: str = "") -> None:
        self.rec.phase = name
        self.rec.event("agent", f"[에이전트] {name} 시작" + (f" — {note}" if note else ""))

    def say(self, text: str) -> None:
        self.rec.event("agent", f"[에이전트] {text}")

    @property
    def case_id(self) -> str:
        return self.st["case_id"]

    @property
    def case_dir(self) -> Path:
        return Path(self.st["case_dir"])

    def to_rootfs(self, path: str | None) -> str | None:
        """케이스 상대/절대 경로 → rootfs 절대 경로 (추출 트리 안이면)."""
        if not path:
            return None
        p = str(path).split(":")[0] if re.search(r":\d+$", str(path)) else str(path)
        for base in self.st.get("rootfs_bases", []):
            for prefix in (base, str(self.case_dir / base)):
                if p == prefix:
                    return "/"
                if p.startswith(prefix + "/"):
                    return "/" + p[len(prefix) + 1:]
        return p

    def _observe(self, tool: str, server: str, args: dict[str, Any], res: Any) -> None:
        seq = self.hub._seq
        if not isinstance(res, dict) or res.get("_error"):
            return
        add = self.obs.append
        if tool == "fw_strings_hunt":
            for h in res.get("hits") or []:
                add(Observation(seq, server, tool, self.to_rootfs(h.get("file")), None, h.get("category"), h.get("pattern_id"),
                                f"{h.get('match', '')} {h.get('context', '')}", f"{res.get('result_path')}"))
        elif tool == "fw_rootfs_audit":
            for it in res.get("items") or []:
                add(Observation(seq, server, tool, it.get("file"), None, it.get("category"), it.get("id"),
                                f"{it.get('title', '')} {it.get('excerpt', '')}", res.get("result_path")))
        elif tool == "fw_crack_hashes":
            for r in res.get("results") or []:
                add(Observation(seq, server, tool, self.to_rootfs(r.get("source")), None, "hardcoded-credential", f"crack:{r.get('status')}",
                                f"'{r.get('user')}' {r.get('status')} {r.get('hash', '')} {r.get('algorithm', '')}", res.get("result_path")))
        elif tool == "fw_elf_info" and res.get("mode") == "file":
            heur = (res.get("risk") or {}).get("heuristics") or {}
            text = " ".join(f"{hid}:{','.join(v.get('functions') or [])}" for hid, v in heur.items())
            add(Observation(seq, server, tool, self.to_rootfs((res.get("input") or {}).get("path")), None, None, "elf-heuristics", text,
                            res.get("result_path")))
        elif server == "rea":
            nr = res.get("normalized_result")
            binp = self.st.get("rea_current")
            if tool == "trace_feature" and isinstance(nr, dict):
                vals = " ".join(str(m.get("value")) for m in nr.get("matches") or [])
                for ref in nr.get("references") or []:
                    cp = ref.get("containing_procedure") or {}
                    fn = (cp.get("procedure") or {}).get("name") if cp.get("found") else None
                    add(Observation(seq, server, tool, binp, fn, None, f"trace:{args.get('query')}", f"{args.get('query')} {vals}",
                                    res.get("evidence_id")))
                if not nr.get("references"):
                    add(Observation(seq, server, tool, binp, None, None, f"trace:{args.get('query')}", f"{args.get('query')} {vals}",
                                    res.get("evidence_id")))
            elif tool == "procedure_pseudo_code" and isinstance(nr, str):
                m = re.search(r"^\s*[\w\s\*]+?\b(\w+)\s*\(", nr, re.M)
                fn = m.group(1) if m else str(args.get("procedure"))
                add(Observation(seq, server, tool, binp, fn, None, "decompile", nr, res.get("evidence_id")))
            elif tool in ("search_procedures", "search_strings") and isinstance(nr, list):
                add(Observation(seq, server, tool, binp, None, None, tool, " ".join(str(x.get("value")) for x in nr), res.get("evidence_id")))

    def cand(self, key: str, **kw: Any) -> Candidate:
        if key in self.cands:
            c = self.cands[key]
            c.upgrade(confidence=kw.get("confidence"), severity=kw.get("severity"), evidence=kw.get("evidence"),
                      function=kw.get("function"), address=kw.get("address"))
            for a in kw.get("ah") or []:
                if a not in c.ah:
                    c.ah.append(a)
            return c
        c = Candidate(key=key, **kw)
        self.cands[key] = c
        return c

    # =====================================================================
    # Phase 0 — 접수 (master-prompt §3)
    # =====================================================================
    async def phase0_intake(self) -> None:
        self.phase("phase-0 접수", "소유/허가 확인 → 케이스 생성")
        self.human.say(f"소유 확인 답변: \"{self.scenario.statement}\"")
        profs = await self.call("pweh-case", "pipeline_profiles")
        names = {p.get("name") for p in profs.get("profiles", [])} if isinstance(profs.get("profiles"), list) else set(profs.get("profiles") or {})
        if self.case_profile not in names:
            self.say(f"프로필 {self.case_profile} 이 없어 generic-ipcam 사용")
            self.case_profile = "generic-ipcam"
        pol = await self.call("pweh-case", "pipeline_safety_policy")
        self.st["safety_policy"] = pol
        args: dict[str, Any] = dict(title=self.scenario.title,
                                    authorization={"basis": "owned", "owner": self.scenario.owner, "statement": self.scenario.statement,
                                                   "scope": self.scenario.scope},
                                    target=self.scenario.target or None, profile=self.case_profile)
        if self.case_id_wanted:
            args["case_id"] = self.case_id_wanted
        r = await self.call("pweh-case", "case_create", **{k: v for k, v in args.items() if v is not None})
        self.st["case_id"] = r["case"]["id"]
        self.st["case_dir"] = r["paths"]["case_dir"]
        self.st["paths"] = r["paths"]

    # =====================================================================
    # Phase A — uart-shell-acquisition (U-Boot 경로, skills/uart-shell-acquisition/SKILL.md §0~§7, §12)
    # =====================================================================
    async def phase_a_uboot(self) -> None:
        self.phase("uart-shell-acquisition", "포트 → 배선 → 보드레이트(프로필) → 부팅 로그 → U-Boot 진입 → env/보드 정보")
        cid = self.case_id
        await self.call("pweh-case", "case_get", case_id=cid)
        await self.call("pweh-case", "case_get_step_results", case_id=cid)
        prof = await self.call("pweh-case", "pipeline_profile", name=self.case_profile)
        self.st["pipeline_profile"] = prof
        await self.call("pweh-case", "case_set_phase", case_id=cid, phase="uart-shell-acquisition", status="in-progress")
        self.st["ports"] = await self.call("pweh-uart", "uart_list_ports", include_links=True)
        self.human.say(f"UART 배선 완료: GND–GND, 기기 TX → 어댑터 RX, 기기 RX → 어댑터 TX, VCC 미연결. TX 3.3V 측정. "
                       f"포트는 {self.port} (시뮬레이터 PTY — uart_list_ports 목록에는 없다)")
        op = await self.call("pweh-uart", "uart_open", case_id=cid, port=self.port, baudrate=115200, label="console")
        self.st["open"] = op
        self.st["session_id"] = sid = op["session_id"]
        # §5 부팅 로그 수집 (OBSERVE): 사람이 전원을 넣는 동안 감시
        self.say("부팅 로그를 감시하는 동안 전원을 넣어 달라고 요청 (H3)")
        t = self.human.power_on_soon(0.4, "에이전트 요청: uart_capture_boot 감시 시작 직후")
        boot = await self.call("pweh-uart", "uart_capture_boot", session_id=sid, duration=45)
        t.join()
        self.st["boot"] = boot
        if not boot.get("autoboot_message"):
            raise ToolError(f"autoboot 메시지 없음 — U-Boot 경로 불가: {boot.get('stopped_by')}")
        # §7 A1 autoboot 중단 (master §6 순서: 전원을 먼저 끔 → '준비' → 감시 시작 → 전원 투입)
        self.say(f"autoboot 메시지 확인 (bootdelay {boot.get('bootdelay')}) → 전원을 먼저 꺼 달라고 요청하고, "
                 "'준비' 뒤 uboot_interrupt 감시를 시작하면 전원을 넣어 달라고 안내")
        self.human.power_off("에이전트 요청: uboot_interrupt 전에 전원을 꺼 둠")
        self.human.say("전원을 껐습니다. 준비")
        t = self.human.power_on_soon(0.4, "에이전트 요청: uboot_interrupt 감시 시작 직후")
        ir = await self.call("pweh-uart", "uboot_interrupt", session_id=sid, window_seconds=30)
        t.join()
        self.st["interrupt"] = ir
        if not ir.get("interrupted"):
            raise ToolError(f"autoboot 중단 실패: {ir.get('explanation')}")
        self.say("U-Boot 에서 멈췄다. 전원은 그대로 두라고 안내")
        # §7 A2/A3: printenv 를 먼저 (safe_ram_addr 이 env 의 bootcmd 주소를 쓴다)
        self.st["printenv"] = env = await self.call("pweh-uart", "uboot_printenv", session_id=sid)
        self.st["uboot_info"] = info = await self.call("pweh-uart", "uboot_info", session_id=sid)
        fl = info.get("flash") or {}
        # §12 대상 정보 갱신과 메모
        tgt = {"soc": f"{(env.get('env') or {}).get('soc')} (U-Boot env soc)" if (env.get("env") or {}).get("soc") else None,
               "flash": f"{fl.get('model')} {fl.get('type')} {(fl.get('size_bytes') or 0) // (1 << 20)} MiB",
               "uboot_version": info.get("version"), "kernel_version": boot.get("kernel_version")}
        await self.call("pweh-case", "case_update_target", case_id=cid, target={k: v for k, v in tgt.items() if v})
        await self.call("pweh-case", "case_add_note", case_id=cid,
                        text="UART: GND-GND, 기기 TX-어댑터 RX, 기기 RX-어댑터 TX, VCC 미연결, TX 3.3V 측정 (사람 보고, 시뮬레이터 PTY)")

    async def record_recon_uboot(self) -> None:
        env = self.st["printenv"]
        info = self.st["uboot_info"]
        ir = self.st["interrupt"]
        boot = self.st.get("boot") or {}
        fl = info.get("flash") or {}
        size = fl.get("size_bytes")
        parts = []
        for p in env.get("partitions") or []:
            ent = {"name": p["name"], "offset": p["offset"], "size": p["size"]}
            if ent["size"] is None and size:
                ent["size"] = int(size) - int(p["offset"])
                ent["size_source"] = "mtdparts '-' → flash_size − offset"
            parts.append(ent)
        self.st["partitions"] = parts
        data = {
            "port": self.port,
            "baudrate": 115200,
            "framing": "8N1",
            "baud_detection": {"method": "profile", "candidates": [115200], "score": None},
            "console_type": "uboot",
            "access_level": "uboot",
            "uboot": {
                "version": info.get("version"),
                "prompt": ir.get("prompt"),
                "autoboot": {"message": ir.get("autoboot_message") or boot.get("autoboot_message") or "",
                             "interrupt_keys": ir.get("keys_used") or ["ctrl-c"], "bootdelay": ir.get("bootdelay")},
                "env": env.get("env") or {},
                "bootargs": env.get("bootargs"),
                "bootcmd": env.get("bootcmd"),
                "mtdparts": env.get("mtdparts"),
                "partitions": parts,
                "flash": {"type": fl.get("type") or "spi-nor", "model": fl.get("model") or "", "size_bytes": size},
                "ram_load_addr": info.get("safe_ram_addr"),
                "commands": info.get("commands") or [],
            },
            "linux": {"kernel_version": boot.get("kernel_version"), "cmdline": boot.get("cmdline"), "cpu": None, "mtd": [], "user": None,
                      "busybox": None, "login_required": True if str(boot.get("stopped_by") or "").find("login") >= 0 else None},
            "device_info": {"bdinfo": info.get("bdinfo"), "safe_ram_addr": info.get("safe_ram_addr"), "console": boot.get("console"),
                            "flash_write_warnings": boot.get("flash_write_warnings") or []},
            "session_log": self.st["open"].get("log_path"),
            "boot_log": boot.get("excerpt_path"),
            "contexts_reached": ["uboot"],
            "login_method": "not-attempted",
            "session": {"session_id": self.st["session_id"], "kept_open": True, "context_at_end": "uboot"},
            "notes": ["보드레이트는 프로필 후보 하나(115200)로 바로 접속, 부팅 로그가 읽혀 확정 (baud_detection profile)",
                      f"부팅 로그: {boot.get('stopped_by')} — 로그인 프롬프트까지 부팅됨, 리눅스 {boot.get('kernel_version')}",
                      "autoboot 를 Ctrl-C 로 중단, <INTERRUPT> 로 U-Boot 문맥 확정. 빈 Enter 는 보내지 않음 (master-prompt §1-4)",
                      "PTY 시뮬레이터 포트라 uart_list_ports 목록에는 나오지 않는다 (사람이 경로를 알려 줌)",
                      "영구 변경 없음 (saveenv/setenv 보내지 않음). 세션은 firmware-dump-via-uart 를 위해 열어 둔다"],
        }
        await self.call("pweh-case", "case_record_step", case_id=self.case_id, skill="uart-shell-acquisition", step="summary",
                        status="success",
                        summary=f"UART 115200 8N1({self.port}): U-Boot 진입({ir.get('prompt')!r}, Ctrl-C), env·플래시·safe RAM {info.get('safe_ram_addr')} 확보",
                        data=data, artifacts=[x for x in (self.st["open"].get("log_path"), boot.get("excerpt_path")) if x],
                        next_actions=["firmware-dump-via-uart: 세션 재사용, U-Boot md.b 덤프 (crc32 검증)"])

    # =====================================================================
    # Phase B — firmware-dump-via-uart (U-Boot md.b, skills/firmware-dump-via-uart/SKILL.md §1~§9)
    # =====================================================================
    async def _dump_job(self, *, offset: int, length: int, name: str, chunk_size: str | None, record_job: bool) -> dict[str, Any]:
        args: dict[str, Any] = dict(case_id=self.case_id, session_id=self.st["session_id"], offset=offset, length=length, output_name=name)
        if chunk_size:
            args["chunk_size"] = chunk_size
        st = await self.call("pweh-uart", "uboot_dump_start", **args)
        if not st.get("ok"):
            raise ToolError(f"덤프 시작 실패: {st}")
        job = st["job_id"]
        if record_job:
            await self.call("pweh-case", "case_record_step", case_id=self.case_id, skill="firmware-dump-via-uart", step=f"job-{name}",
                            status="in-progress", summary=f"U-Boot md.b 덤프 0x{offset:x}+0x{length:x} 시작 (실기기 예상 {int(st.get('estimated_seconds') or 0) // 60}분)",
                            data={"tool": "uboot_dump_start", "job_id": job,
                                  "args": {"source": "sf", "offset": offset, "length": hex(length), "chunk_size": chunk_size or "64k", "output_name": name}})
        while True:
            js = await self.call("pweh-uart", "uart_job_status", job_id=job, wait_seconds=50)
            if js.get("status") not in ("queued", "running", "cancelling"):
                break
        if js.get("status") != "succeeded":
            raise ToolError(f"덤프 실패: {js.get('status')} {js.get('error')}")
        res = js["result"]
        if record_job:
            await self.call("pweh-case", "case_record_step", case_id=self.case_id, skill="firmware-dump-via-uart", step=f"job-{name}",
                            status="success", summary=f"완료 {res['path']}", data={"job_id": job, "result_path": res["path"], "sha256": res["sha256"]})
        return {"start": st, "result": res}

    async def phase_b_dump(self, *, close_after: bool = True) -> None:
        self.phase("firmware-dump-via-uart", f"덤프 범위: {self.dump_scope}")
        cid = self.case_id
        # §1 권한·이전 결과
        await self.call("pweh-case", "case_get", case_id=cid, include_artifacts=True)
        await self.call("pweh-case", "case_get_step_results", case_id=cid)
        await self.call("pweh-case", "case_get_step_results", case_id=cid, skill="firmware-dump-via-uart", summaries_only=False)
        await self.call("pweh-case", "case_set_phase", case_id=cid, phase="firmware-dump-via-uart", status="in-progress")
        # §3 세션 준비: 열린 세션 재사용, printenv → info 를 다시 부른다
        await self.call("pweh-uart", "uart_sessions", case_id=cid)
        self.st["printenv"] = env = await self.call("pweh-uart", "uboot_printenv", session_id=self.st["session_id"])
        self.st["uboot_info"] = info = await self.call("pweh-uart", "uboot_info", session_id=self.st["session_id"])
        parts = self.st.get("partitions") or [{"name": p["name"], "offset": p["offset"], "size": p["size"]} for p in env.get("partitions") or []]
        size = (info.get("flash") or {}).get("size_bytes") or (info.get("flash") or {}).get("size_bytes_lower_bound")
        # §4 범위·청크·RAM 주소·예상 시간 → 사용자 동의
        if self.dump_scope == "full":
            offset, length, name = 0, int(size), "flash-full"
            why = "전체 플래시 (백업·복구·분석 겸용)"
        elif self.dump_scope == "needed":
            rootfs = next((p for p in parts if p["name"] in ("rootfs", "root")), None)
            if rootfs is None:
                raise ToolError("mtdparts 에 rootfs 가 없음")
            offset, length = 0, int(rootfs["offset"]) + int(rootfs["size"])
            name = f"flash-0-{length:x}"
            why = "우선 범위 boot·env·kernel·rootfs (설정 파티션 app 은 나중에)"
        else:  # 파티션 하나
            part = next((p for p in parts if p["name"] == self.dump_scope), None)
            if part is None:
                raise ToolError(f"mtdparts 에 {self.dump_scope} 파티션이 없음")
            offset, length, name = int(part["offset"]), int(part["size"]), f"part-{self.dump_scope}"
            why = f"{self.dump_scope} 파티션 하나"
        self.st["dump_plan"] = {"offset": offset, "length": length, "name": name, "why": why}
        eta_real = length * (79 / 16 + 60 / 65536) * 10 / 115200
        self.say(f"[확인 필요] 덤프 계획: U-Boot md.b, 0x{offset:x}+0x{length:x} ({why}), 청크 {self.chunk_size} "
                 f"(시뮬레이터 시간 단축용, 허용 최대), 실기기 115200bps 기준 약 {eta_real / 60:.0f}분. 대안: tftpput / SPI 클립 / 셸 base64")
        self.human.say(f"덤프 계획에 동의 ({why})")
        # §5 시험 덤프 (kernel 앞 64 KiB, 기본 청크) → 본 덤프
        kern = next((p for p in parts if p["name"] == "kernel"), None)
        if kern and self.dump_scope in ("full", "needed"):
            self.st["probe"] = (await self._dump_job(offset=int(kern["offset"]), length=0x10000, name="probe-kernel-head",
                                                     chunk_size=None, record_job=False))["result"]
            self.say(f"시험 덤프 정상 (sf read·md.b·crc32 동작, 재시도 {self.st['probe']['chunks'].get('retries')}회) → 본 덤프 시작")
        main = await self._dump_job(offset=offset, length=length, name=name, chunk_size=self.chunk_size, record_job=True)
        self.st["dump_start"] = main["start"]
        self.st["dump"] = main["result"]
        # §8 검증: 내용 확인(fw_identify) + 교차 확인(시험 덤프 ↔ 본 덤프의 같은 영역)
        if self.dump_scope in ("full", "needed"):
            ident = await self.call("pweh-fwtriage", "fw_identify", case_id=cid, path=main["result"]["path"])
            self.st["dump_identify"] = ident
            if self.st.get("probe") and kern:
                rel = int(kern["offset"]) - offset
                xc = await self.call("pweh-fwtriage", "fw_carve", case_id=cid, path=main["result"]["path"],
                                     partitions=[{"name": "xcheck", "offset": hex(rel), "size": "0x10000"}], output_label="xcheck")
                arts = await self.call("pweh-case", "case_get", case_id=cid, include_artifacts=True)
                xfile = (xc.get("partitions") or [{}])[0].get("file")
                xsha = next((a.get("sha256") for a in arts.get("artifacts") or [] if a.get("path") == xfile), None)
                self.st["cross_check"] = {"region": f"kernel 앞 0x{int(kern['offset']):x}+0x10000", "dump": self.st["probe"]["path"],
                                          "method": "시험 덤프(기본 64k 청크) ↔ 본 덤프를 fw_carve 로 자른 같은 영역",
                                          "sha256": self.st["probe"]["sha256"], "reference": xfile, "match": xsha == self.st["probe"]["sha256"]}
        # §9 마무리
        if close_after:
            await self.call("pweh-uart", "uart_close", session_id=self.st["session_id"])

    async def record_dump(self) -> None:
        res = self.st["dump"]
        meta = json.loads((self.case_dir / res["metadata_path"]).read_text(encoding="utf-8"))
        self.st["dump_meta"] = meta
        ver = meta.get("verification") or res.get("verification") or {}
        full = ver.get("full_range") or {}
        src = meta.get("source") or {}
        plan = self.st["dump_plan"]
        ident = self.st.get("dump_identify") or {}
        content = []
        for r in ident.get("regions") or []:
            d = r.get("details") or {}
            if r.get("kind") == "uimage":
                content.append(f"fw_identify: uImage '{d.get('name')}' @{r.get('offset_hex')} header_crc_ok={d.get('header_crc_ok')} data_crc_ok={d.get('data_crc_ok')}")
            elif r.get("kind") == "uboot-env":
                content.append(f"fw_identify: U-Boot env @{r.get('offset_hex')} CRC 정상 (변수 {d.get('variables')}개)")
            elif r.get("kind") == "squashfs":
                content.append(f"fw_identify: squashfs @{r.get('offset_hex')} {d.get('compression')} {r.get('size')} bytes")
        xc = self.st.get("cross_check")
        verification = {"method": ver.get("method", "crc32-chunks"), "match": ver.get("match"),
                        "expected": full.get("device_crc32"), "actual": full.get("host_crc32"),
                        "chunks_verified": ver.get("chunks_verified"), "full_range": full or None}
        if xc:
            verification["cross_check"] = xc
        if content:
            verification["content_checks"] = content
        whole = plan["offset"] == 0 and plan["length"] == (src.get("flash_size") or -1)
        ok = ver.get("match") is True and (xc is None or xc.get("match") is True)
        status = "success" if ok and (whole or self.dump_scope not in ("full", "needed")) else ("partial" if ok else "failed")
        data = {
            "method": meta.get("method", "uboot-md"),
            "source": {**{k: src.get(k) for k in ("type", "flash_type", "flash_model", "flash_size", "offset", "length", "partition", "ram_addr",
                                                  "device_path")},
                       "flash_model": src.get("flash_model") or (self.st["uboot_info"].get("flash") or {}).get("model")},
            "output": {"path": res["path"], "sha256": res["sha256"], "size": res["size"]},
            "verification": verification,
            "chunks": {k: v for k, v in (meta.get("chunks") or {}).items() if k != "checks"},
            "partitions": self.st.get("partitions") or [],
            "mtdparts": self.st["printenv"].get("mtdparts"),
            "duration_seconds": meta.get("duration_seconds"),
            "baudrate": meta.get("baudrate", 115200),
            "metadata_path": res["metadata_path"],
            "bootloader": self.st["uboot_info"].get("version"),
            "notes": [f"범위: {plan['why']}", f"청크 {self.chunk_size} (시뮬레이터 시간 단축용), 청크마다 기기 crc32 ↔ 호스트 crc32",
                      f"ram_addr 생략 → uboot_info safe_ram_addr {self.st['uboot_info'].get('safe_ram_addr')}",
                      "sf read → md.b 만 사용 (읽기 전용, 플래시 쓰기·saveenv 없음)",
                      f"시뮬레이터 실행 값: duration {meta.get('duration_seconds')}초. 실제 115200 bps 기기는 훨씬 오래 걸린다"],
        }
        nxt = ["firmware-static-analysis: " + res["path"] + " 분석 (env 의 mtdparts 로 fw_carve 자동 분할)"]
        if status == "partial":
            rest = plan["offset"] + plan["length"]
            nxt.append(f"나머지 범위 0x{rest:x}~ (app 등) 덤프 여부를 사용자에게 묻기")
        await self.call("pweh-case", "case_record_step", case_id=self.case_id, skill="firmware-dump-via-uart", step="summary",
                        status=status,
                        summary=f"U-Boot md.b 덤프 {res['size']} bytes ({plan['why']}). 청크 {(meta.get('chunks') or {}).get('count')}개 crc32 일치"
                                + (f", 전체 crc32 {full.get('device_crc32')} 일치" if full.get("match") else "")
                                + (", kernel 앞부분 교차 확인 일치" if xc and xc.get("match") else ""),
                        data=data, artifacts=[x for x in (res["path"], res["metadata_path"], (self.st.get("probe") or {}).get("path")) if x],
                        next_actions=nxt)

    # =====================================================================
    # Phase C — firmware-static-analysis
    # =====================================================================
    async def phase_c_static(self) -> None:
        self.phase("firmware-static-analysis", "지도 → 분할 → 추출 → 감사 → (REA) 디컴파일")
        cid = self.case_id
        await self.call("pweh-case", "case_get", case_id=cid)
        prev = await self.call("pweh-case", "case_get_step_results", case_id=cid)
        fw_path = prev["summaries"]["firmware-dump-via-uart"]["data"]["output"]["path"]
        self.st["fw_path"] = fw_path
        prof = await self.call("pweh-case", "pipeline_profile", name=self.case_profile)
        self.st["pipeline_profile"] = prof
        paths = await self.call("pweh-case", "case_paths", case_id=cid, purpose="extract", label="rea")
        self.st["rea_extract_dir"] = paths["new_output_dir"]
        await self.call("pweh-case", "case_set_phase", case_id=cid, phase="firmware-static-analysis", status="in-progress")

        ident = await self.call("pweh-fwtriage", "fw_identify", case_id=cid, path=fw_path)
        ent = await self.call("pweh-fwtriage", "fw_entropy", case_id=cid, path=fw_path)
        env = await self.call("pweh-fwtriage", "fw_uboot_env", case_id=cid, path=fw_path)
        carve = await self.call("pweh-fwtriage", "fw_carve", case_id=cid, path=fw_path)
        self.st.update(identify=ident, entropy=ent, uboot_env=env, carve=carve)
        if self.hub.has_rea:
            # 교차 확인(선택, static-analysis §1): REA binwalk 영역 식별. 가설이므로 fw_identify 를 기본 지도로 쓰고 차이만 적는다
            rr = await self.call("rea", "inspect_firmware_regions", path=str(self.case_dir / fw_path), _allow_error=True)
            if rr.get("_error"):
                self.rea_limitations.append(f"inspect_firmware_regions 실패: {rr['_error'][:160]}")
            else:
                regs = (rr.get("normalized_result") or {}).get("regions") or []
                rea_offs = {int(x["offset"]) for x in regs if isinstance(x, dict) and isinstance(x.get("offset"), int)}
                key = [r for r in ident.get("regions") or [] if r.get("kind") in ("uimage", "squashfs", "uboot-env")]

                def _off(r: dict[str, Any]) -> int | None:  # MCP 응답의 영역에는 offset_hex 만 있을 수 있다
                    if isinstance(r.get("offset"), int):
                        return r["offset"]
                    try:
                        return int(str(r.get("offset_hex")), 16)
                    except ValueError:
                        return None

                hit = [r["kind"] + "@" + r["offset_hex"] for r in key if _off(r) in rea_offs]
                miss = [r["kind"] + "@" + r["offset_hex"] for r in key if _off(r) not in rea_offs]
                self.st["rea_regions"] = {"count": len(regs), "agree": hit, "rea_missed": miss, "evidence_id": rr.get("evidence_id")}
        parts = {p["name"]: p for p in carve.get("partitions") or []}
        kern = next((p for p in carve["partitions"] if p.get("content") in ("uimage", "fit")), None)
        if kern:
            self.st["uimage"] = await self.call("pweh-fwtriage", "fw_uimage_info", case_id=cid, path=kern["file"])
        rootfs_part = next((p for p in carve["partitions"] if p.get("content") == "squashfs" and p["name"] in ("rootfs", "root")), None) \
            or next((p for p in carve["partitions"] if p.get("content") == "squashfs"), None)
        if rootfs_part is None:
            raise ToolError("squashfs rootfs 파티션을 찾지 못함")
        self.st["rootfs_part"] = rootfs_part
        ex = await self.call("pweh-fwtriage", "fw_extract_squashfs", case_id=cid, path=rootfs_part["file"])
        self.st["extract"] = ex
        rootfs = ex["output_dir"]
        self.st["rootfs"] = rootfs
        self.st["rootfs_bases"] = [rootfs]
        extra_parts = [p for p in carve["partitions"] if p.get("content") == "squashfs" and p is not rootfs_part]
        self.st["extract_extra"] = []
        for p in extra_parts:
            r = await self.call("pweh-fwtriage", "fw_extract_squashfs", case_id=cid, path=p["file"], output_label=p["name"])
            self.st["extract_extra"].append(r)
            self.st["rootfs_bases"].append(r["output_dir"])
        missing = [p["name"] for p in self.st["printenv"].get("partitions") or [] if p["name"] not in parts]
        self.st["missing_parts"] = missing
        if missing:
            self.gaps.append(f"덤프 범위 밖 파티션 미분석: {', '.join(missing)} (덤프 범위를 rootfs 까지로 정함)")

        if self.hub.has_rea:
            # 교차 확인용 REA unblob 추출. execution_failure 면 case_paths 로 새 경로를 받아 한 번만 다시 한다 (static-analysis §3)
            for attempt in (1, 2):
                r = await self.call("rea", "extract_firmware", path=str(self.case_dir / rootfs_part["file"]),
                                    output_directory=self.st["rea_extract_dir"], _allow_error=True)
                if not r.get("_error"):
                    break
                reason = re.search(r'"reason":"([^"]{0,160})', r["_error"])
                self.rea_limitations.append(f"extract_firmware 실패({attempt}회차): {reason.group(1) if reason else r['_error'][:160]}")
                if attempt == 1:
                    paths2 = await self.call("pweh-case", "case_paths", case_id=cid, purpose="extract", label="rea")
                    self.st["rea_extract_dir"] = paths2["new_output_dir"]
            if not r.get("_error"):
                nr = r.get("normalized_result") or {}
                self.st["rea_extract"] = {"coverage": nr.get("coverage"), "files": len(nr.get("files") or []),
                                          "unpublished": len(nr.get("unpublished_entries") or []), "evidence_id": r.get("evidence_id")}
                rel = os.path.relpath(self.st["rea_extract_dir"], self.case_dir)
                await self.call("pweh-case", "case_register_artifact", case_id=cid, path=rel, kind="extracted-tree", producer="rea",
                                description="REA unblob 교차 추출 (rootfs 파티션)")
            else:
                self.gaps.append("REA unblob 교차 추출 실패 (fwtriage 추출 결과만 사용)")

        audit = await self.call("pweh-fwtriage", "fw_rootfs_audit", case_id=cid, rootfs_dir=rootfs)
        hunt = await self.call("pweh-fwtriage", "fw_strings_hunt", case_id=cid, path_or_dir=rootfs)
        self.st.update(audit=audit, hunt=hunt)
        shadow = next((it["file"] for it in audit.get("items") or [] if it.get("file") in ("/etc/shadow", "/etc/passwd")), None)
        if shadow:
            self.st["crack"] = await self.call("pweh-fwtriage", "fw_crack_hashes", case_id=cid, source_path=f"{rootfs}{shadow}")
        elf_dir = await self.call("pweh-fwtriage", "fw_elf_info", case_id=cid, path=rootfs)
        self.st["elf_dir"] = elf_dir
        webs = [w for w in audit.get("web_servers") or [] if w.get("elf")]
        self.st["web_servers"] = webs
        self.st["elf"] = {}
        for w in webs[:4]:
            self.st["elf"][w["path"]] = await self.call("pweh-fwtriage", "fw_elf_info", case_id=cid, path=f"{rootfs}{w['path']}")

        self._triage_candidates()
        if self.hub.has_rea:
            generic = [w["path"] for w in webs if w.get("vendor") in ("generic", None, "profile")]
            for bpath in generic[:2]:
                await self._rea_binary(bpath, skill="firmware-static-analysis")
        else:
            self.rea_limitations.append(f"REA 미사용: {self.hub.rea_error or '요청하지 않음'} → 디컴파일 확인 없이 fwtriage 휴리스틱만으로 판정")
            self.gaps.append("REA/Ghidra 디컴파일 미실시 — 문자열·임포트 근거의 후보는 confidence possible/likely 로 남김")
        await self._record_candidates(skill="firmware-static-analysis")
        await self._record_static_summary()

    def _triage_candidates(self) -> None:
        """fwtriage 결과 → 발견사항 후보 (벤더 메인 앱의 벤더 지표는 cctv-auth-bypass-hunt 에서 다룬다)."""
        audit, hunt = self.st["audit"], self.st["hunt"]
        vendor_bins = {w["path"] for w in self.st.get("web_servers") or [] if w.get("vendor") not in ("generic", None, "profile")}
        self.st["vendor_bins"] = sorted(vendor_bins)
        crack_masked = {}
        for r in (self.st.get("crack") or {}).get("results") or []:
            crack_masked[r.get("user")] = r
        for it in audit.get("items") or []:
            iid, f = it.get("id", ""), it.get("file")
            ev_tri = {"type": "triage", "ref": audit["result_path"], "excerpt": self.secrets.mask(f"{iid} {f}:{it.get('line')} {it.get('excerpt') or it.get('title')}")}
            if iid == "gen-telnetd-launch" or (it.get("category") == "debug-interface" and "telnetd" in str(it.get("excerpt"))):
                self.cand(f"{f}|telnetd-launch", title="부팅 스크립트가 telnetd 를 무조건 기동 (디버그 인터페이스 상시 개방)",
                          category="debug-interface", severity="medium", confidence="confirmed", file=f, line=it.get("line"),
                          interface="telnet",
                          summary=f"{f} {it.get('line')}행이 조건 없이 telnetd 를 백그라운드로 실행한다. 네트워크에서 로그인 프롬프트가 항상 열린다.",
                          reasoning="시작 스크립트 원문 줄이 직접 증거다 (패턴 P6). 기본 비밀번호(별도 발견사항)와 결합하면 원격 셸 노출로 이어진다.",
                          evidence=[ev_tri, {"type": "file", "ref": f, "excerpt": str(it.get("excerpt"))}], ah=["AH-07"],
                          verification_plan="격리 랩의 소유 기기에서 부팅 뒤 23/tcp 리슨 여부만 확인한다 (로그인 시도 없음).",
                          remediation="telnetd 기동 줄을 제거하거나 개발 빌드 전용 플래그로 감싼다.", tool="fw_rootfs_audit")
            elif iid == "builtin-default-password" or iid.startswith("known-hash-"):
                user = re.search(r"'([^']+)'", it.get("title") or "")
                user = user.group(1) if user else "root"
                cr = crack_masked.get(user) or {}
                evs = [ev_tri]
                if cr:
                    evs.append({"type": "hash", "ref": (self.st.get("crack") or {}).get("result_path"),
                                "excerpt": f"{user}: {cr.get('algorithm')} {cr.get('hash')} → {cr.get('status')} ({cr.get('password')})"})
                self.cand(f"{f}|default-password|{user}", title=f"{user} 계정 비밀번호가 공개 기본 비밀번호 사전과 일치 (약한 MD5-crypt)",
                          category="hardcoded-credential", severity="high", confidence="confirmed" if cr.get("status") == "cracked" else "likely",
                          file=f, line=it.get("line"), interface="uart/telnet",
                          summary=f"{f} 의 {user} 해시가 공개 기본 비밀번호 사전 항목과 오프라인 대조로 일치한다 (평문은 케이스 analysis/ 에만 있음).",
                          reasoning="fw_rootfs_audit 와 fw_crack_hashes 가 같은 결과를 냈다. 같은 펌웨어의 모든 기기가 같은 비밀번호를 가질 가능성이 높다 (P5).",
                          evidence=evs, ah=["AH-08"],
                          verification_plan="소유 기기의 UART 콘솔에서 운영자가 이미 아는 계정으로만 확인한다. 무차별 대입은 하지 않는다.",
                          remediation="기기별 초기 비밀번호 또는 첫 부팅 시 변경 강제, sha512crypt 이상 사용.", tool="fw_rootfs_audit + fw_crack_hashes")
            elif iid == "passwd-md5-crypt":
                key = next((k for k in self.cands if k.startswith(f"{f}|default-password")), None)
                if key:
                    self.cands[key].upgrade(evidence=[ev_tri])
            elif SEV_RANK.get(it.get("severity", "info"), 4) <= SEV_RANK["medium"]:
                self.cand(f"{f}|audit|{iid}", title=f"rootfs 감사 항목: {it.get('title') or iid}", category=it.get("category", "other"),
                          severity=it.get("severity", "medium"), confidence="likely", file=f, line=it.get("line"),
                          summary=str(it.get("title") or iid), reasoning=str(it.get("rationale") or "fw_rootfs_audit 휴리스틱"),
                          evidence=[ev_tri], tool="fw_rootfs_audit")
        # 문자열 히트 (벤더 메인 앱 밖)
        for h in hunt.get("hits") or []:
            f = self.to_rootfs(h.get("file"))
            pid = h.get("pattern_id")
            if f in vendor_bins:
                continue
            ev_str = {"type": "string", "ref": f"{f}@{h.get('offset_hex')}", "excerpt": self.secrets.mask(f"{pid}: {h.get('context') or h.get('match')}")}
            ev_tri = {"type": "triage", "ref": hunt["result_path"], "excerpt": f"{pid} {f}@{h.get('offset_hex')}"}
            if pid == "gen-hardcoded-basic-auth":
                blob = (h.get("match") or "").split()[-1]
                dec = b64_decode_maybe(blob)
                self.secrets.add(blob, "Basic 자격증명")
                user = None
                if dec and ":" in dec:
                    user, pw = dec.split(":", 1)
                    self.secrets.add(pw, "내장 비밀번호")
                ev_str = {"type": "string", "ref": f"{f}@{h.get('offset_hex')}", "excerpt": self.secrets.mask(h.get("context") or h.get("match"))
                          + (f" (base64 디코드: {user}:<마스킹>)" if user else "")}
                self.cand(f"{f}|hardcoded-credential", title=f"{Path(f).name} 바이너리에 고정 관리자 자격증명 내장",
                          category="hardcoded-credential", severity="high", confidence="likely", file=f, offset=h.get("offset_hex"),
                          interface="http",
                          summary=f"{f} 에 base64 로 인코딩된 'Authorization: Basic' 헤더가 들어 있고, 디코드하면 사용자 '{user}' 와 고정 비밀번호다.",
                          reasoning="포맷 지정자 없는 Basic 헤더 리터럴은 바이너리에 박힌 자격증명이다 (gen-hardcoded-basic-auth). 어느 함수가 쓰는지는 디컴파일로 확인한다.",
                          evidence=[ev_str, ev_tri], ah=["AH-01", "AH-08"], verification_plan=VERIFY_GENERIC,
                          remediation="고정 계정·자가 점검용 자격증명을 제거하고 기기별 비밀값을 쓴다.", tool="fw_strings_hunt")
            elif pid in ("gen-shell-cmd-template", "gen-sh-c-template"):
                self.cand(f"{f}|cmd-template|{h.get('match')}", title=f"{Path(f).name} 의 셸 명령 템플릿에 요청 값 삽입 가능 (명령 주입 후보)",
                          category="command-injection", severity="medium", confidence="possible", file=f, offset=h.get("offset_hex"),
                          interface="http",
                          summary=f"{f} 에 '%s' 를 끼워 넣는 셸 명령 템플릿 \"{h.get('context')}\" 가 있다. system/popen 으로 이어지는지 확인이 필요하다.",
                          reasoning="명령 템플릿 문자열만으로는 싱크 연결을 알 수 없다 (P11 후보, gen-shell-cmd-template).",
                          evidence=[ev_str, ev_tri], ah=["AH-04"], verification_plan=VERIFY_GENERIC,
                          remediation="외부 입력을 셸에 넘기지 말고 execve 인자 배열 + 엄격한 화이트리스트(IP 형식 검증)를 쓴다.", tool="fw_strings_hunt")
            elif pid == "gen-backdoor-keywords":
                ctx = h.get("context") or ""
                tok = re.search(r"[A-Za-z0-9][A-Za-z0-9_\-]{15,}", ctx)
                if tok and f and not f.startswith("/etc/"):
                    self.secrets.add(tok.group(0), "고정 토큰")
                    self.cand(f"{f}|literal-token", title=f"{Path(f).name} 에 백도어 키워드를 포함한 고정 토큰 문자열",
                              category="backdoor", severity="high", confidence="possible", file=f, offset=h.get("offset_hex"), interface="http",
                              summary=f"{f} 에 'backdoor' 계열 키워드가 들어간 {len(tok.group(0))}자 고정 토큰 리터럴이 있다. 인증 경로에서 쓰이는지 확인이 필요하다.",
                              reasoning="키워드 히트(gen-backdoor-keywords, low)는 단서일 뿐이다. 토큰 비교가 인증 성공으로 직결되는지는 디컴파일로 확인한다.",
                              evidence=[{"type": "string", "ref": f"{f}@{h.get('offset_hex')}", "excerpt": self.secrets.mask(ctx)}, ev_tri],
                              ah=["AH-01"], verification_plan=VERIFY_GENERIC,
                              remediation="토큰 비교 분기를 제거하고 모든 경로가 정상 자격증명 검증을 거치게 한다.", tool="fw_strings_hunt")
            elif pid == "gen-telnetd-launch":
                key = next((k for k in self.cands if k.endswith("|telnetd-launch")), None)
                if key:
                    self.cands[key].upgrade(evidence=[ev_str])

    async def _rea_binary(self, bpath: str, *, skill: str) -> None:
        """REA + Ghidra: 열기 → 분석 → 앵커 추적 → 디컴파일 → 판독 → 증거 내보내기 → 닫기."""
        cid = self.case_id
        absp = str(self.case_dir / self.st["rootfs"]) + bpath
        name = Path(bpath).name
        self.st["rea_current"] = bpath
        self.say(f"REA/Ghidra 로 {bpath} 분석 (첫 질의에서 자동 분석 — 수십 초)")
        op = await self.call("rea", "open_binary", path=absp, provider_id="ghidra", _allow_error=True)
        if op.get("_error"):
            self.rea_limitations.append(f"{bpath}: open_binary 거부 — {op['_error'][:200]}")
            self.gaps.append(f"REA 거부: {bpath}")
            return
        await self.call("rea", "binary_overview")
        procs = await self.call("rea", "search_procedures", pattern=AUTH_PROC_RX, mode="regex")
        names = [p.get("value") for p in procs.get("normalized_result") or [] if p.get("value") and not p["value"].startswith(("static_init", "__"))]
        addr_of = {p.get("value"): p.get("address") for p in procs.get("normalized_result") or []}
        # 문자열 앵커: 이 바이너리의 fwtriage 히트 (patterns=cctv 실행). 비밀값 자체는 질의에 넣지 않는다.
        anchors: list[str] = []
        for h in self.st["hunt"].get("hits") or []:
            if self.to_rootfs(h.get("file")) != bpath:
                continue
            q = "Authorization: Basic" if h.get("pattern_id") == "gen-hardcoded-basic-auth" else str(h.get("match") or "")
            if q and q not in anchors and len(q) >= 4:
                anchors.append(q)
        targets: list[str] = []
        for q in anchors[:8]:
            tr = await self.call("rea", "trace_feature", query=q)
            for ref in (tr.get("normalized_result") or {}).get("references") or []:
                cp = ref.get("containing_procedure") or {}
                if cp.get("found"):
                    pr = cp.get("procedure") or {}
                    if pr.get("name") and pr["name"] not in targets:
                        targets.append(pr["name"])
                        addr_of.setdefault(pr["name"], pr.get("address"))
        sinks = await self.call("rea", "find_xrefs_to_name", name="system")
        if (sinks.get("normalized_result") or {}).get("status") == "resolved":
            callers = await self.call("rea", "procedure_callers", procedure="system")
            name_at = {v: k for k, v in addr_of.items() if v}
            for a in callers.get("normalized_result") or []:
                t = name_at.get(a, a) if isinstance(a, str) else None
                if t and t not in targets:
                    targets.append(t)
        for n in names:
            if n not in targets:
                targets.append(n)
        found: list[CodeFinding] = []
        seen_fn: set[str] = set()
        for t in targets[:14]:
            pc = await self.call("rea", "procedure_pseudo_code", procedure=t, _allow_error=True)
            code = pc.get("normalized_result") if isinstance(pc, dict) else None
            if not isinstance(code, str):
                continue
            m = re.search(r"^\s*[\w\s\*]+?\b(\w+)\s*\(", code, re.M)
            fn = m.group(1) if m else t
            if fn in seen_fn:
                continue
            seen_fn.add(fn)
            self.rea_evidence[(bpath, fn)] = pc.get("evidence_id")
            addr_of.setdefault(fn, t if t.startswith("0x") else None)
            for cf in classify_pseudocode(fn, code):
                found.append(cf)
        self.code_findings[bpath] = found
        self.st.setdefault("rea_addr", {})[bpath] = addr_of
        bundle_rel = f"analysis/rea-evidence-{name}-001.json"
        n = 1
        while (self.case_dir / bundle_rel).exists():
            n += 1
            bundle_rel = f"analysis/rea-evidence-{name}-{n:03d}.json"
        await self.call("rea", "export_evidence_bundle", path=str(self.case_dir / bundle_rel))
        await self.call("pweh-case", "case_register_artifact", case_id=cid, path=bundle_rel, kind="rea-evidence", producer="rea",
                        description=f"REA evidence ({bpath})")
        await self.call("rea", "close_binary")
        self.st["rea_current"] = None
        self.rea_bundles.append(bundle_rel)
        self._apply_code_findings(bpath, bundle_rel, skill=skill)

    def _confirm(self, key: str, *, skill: str, title: str, category: str, severity: str, confidence: str, file: str,
                 function: str | None, address: str | None, summary: str, reasoning: str, evidence: list[dict[str, Any]],
                 ah: list[str], references: list[str] | None = None, remediation: str = "", tool: str = "rea procedure_pseudo_code (ghidra)",
                 interface: str = "http") -> Candidate:
        """디컴파일로 판정한 내용을 후보에 반영한다. 기존 후보(문자열 단계)가 있으면 증거는 보존하고 제목·요약·추론은 확인된 내용으로 바꾼다."""
        c = self.cands.get(key)
        if c is None:
            c = Candidate(key=key, title=title, category=category, severity=severity, confidence=confidence, file=file, summary=summary,
                          reasoning=reasoning, evidence=list(evidence), ah=list(ah), function=function, address=address, interface=interface,
                          references=list(references or []), verification_plan=VERIFY_GENERIC, remediation=remediation, skill=skill, tool=tool)
            self.cands[key] = c
            return c
        stronger = CONF_RANK[confidence] <= CONF_RANK[c.confidence]
        c.upgrade(confidence=confidence, severity=severity, evidence=evidence)
        if stronger:
            c.title, c.summary, c.reasoning, c.category, c.tool = title, summary, reasoning, category, tool
            c.function, c.address = function, address
            if remediation:
                c.remediation = remediation
        for a in ah:
            if a not in c.ah:
                c.ah.append(a)
        for r in references or []:
            if r not in c.references:
                c.references.append(r)
        return c

    def _apply_code_findings(self, bpath: str, bundle_rel: str, *, skill: str) -> None:
        """디컴파일 판독 결과로 후보를 확정/추가한다."""
        found = self.code_findings.get(bpath) or []
        addr_of = (self.st.get("rea_addr") or {}).get(bpath) or {}
        name = Path(bpath).name
        by_rule: dict[str, list[CodeFinding]] = {}
        for cf in found:
            by_rule.setdefault(cf.rule, []).append(cf)

        def ev(cf: CodeFinding) -> dict[str, Any]:
            eid = self.rea_evidence.get((bpath, cf.function))
            return {"type": "decompilation", "ref": f"{bundle_rel}#{eid}" if eid else bundle_rel, "excerpt": self.secrets.mask(cf.excerpt)}

        common = dict(skill=skill, file=bpath)
        preauth_handlers = {cf.literals[1]: cf for cf in by_rule.get("preauth-dispatch", []) if len(cf.literals) > 1}

        for cf in by_rule.get("P4-literal-token-success", []):
            for lit in cf.literals:
                self.secrets.add(lit, "고정 토큰")
            self._confirm(f"{bpath}|literal-token", **common, title=f"{name} {cf.function} 의 하드코딩 토큰 비교로 인증 생략 (백도어)",
                          category="backdoor", severity="critical", confidence="confirmed", function=cf.function, address=addr_of.get(cf.function),
                          summary=f"{cf.function} 가 요청 토큰을 고정 문자열과 strcmp 해 일치하면 자격증명 검사 없이 1(인증 성공)을 반환한다.",
                          reasoning=f"{cf.reason}. 문자열 히트(백도어 키워드가 든 토큰)가 이 비교의 상수다. 같은 펌웨어를 쓰는 모든 기기에 같은 값이 있다 (P4/P6).",
                          evidence=[ev(cf)], ah=["AH-01"], remediation="토큰 분기를 제거하고 모든 경로가 정상 자격증명 검증을 거치게 한다.")
        for cf in by_rule.get("P5-literal-credential", []):
            for lit in cf.literals[1:]:
                self.secrets.add(lit, "내장 비밀번호")
            self._confirm(f"{bpath}|hardcoded-credential", **common, title=f"{name} {cf.function} 의 고정 관리자 계정 비교 (하드코딩 자격증명)",
                          category="hardcoded-credential", severity="high", confidence="confirmed", function=cf.function,
                          address=addr_of.get(cf.function),
                          summary=f"{cf.function} 가 사용자 이름·비밀번호를 고정 리터럴과 비교해 일치하면 로그인 성공으로 처리한다. 같은 자격증명이 Basic 헤더 리터럴로도 박혀 있다.",
                          reasoning=f"{cf.reason}. 문자열 단계의 Basic 헤더(디코드한 사용자:비밀번호)와 같은 값이다 (P5).",
                          evidence=[ev(cf)], ah=["AH-01", "AH-08"], remediation="고정 계정과 자가 점검용 자격증명을 제거하고 기기별 비밀값을 쓴다.")
        for cf in by_rule.get("P11-format-to-system", []):
            fmt = cf.literals[0] if cf.literals else ""
            pre = preauth_handlers.get(cf.function)
            route = pre.literals[0] if pre else ""
            key = next((k for k in self.cands if k.startswith(f"{bpath}|cmd-template|")
                        and ((route and k.split("|", 2)[2] in route) or fmt.startswith(k.split("|", 2)[2].split("%s")[0]))), None)
            key = key or f"{bpath}|cmd-template|{fmt.split('%s')[0].strip()} %s"
            self._confirm(key, **common, title=f"{name} {cf.function} 의 요청 값 → system() 명령 주입" + (" (인증 전 도달)" if pre else ""),
                          category="command-injection", severity="critical" if pre else "high", confidence="confirmed", function=cf.function,
                          address=addr_of.get(cf.function),
                          summary=f"{cf.function} 가 요청 값을 포맷 문자열 \"{fmt}\" 에 넣어 system() 으로 실행한다. 메타문자 필터나 화이트리스트가 없다."
                                  + (f" 디스패처가 \"{route}\" 를 인증 검사보다 먼저 이 함수로 넘긴다." if pre else ""),
                          reasoning=cf.reason + (f". {pre.reason}" if pre else ". 요청 처리 경로에서 도달한다 (인증 뒤)") + " (P11)",
                          evidence=[ev(cf)] + ([ev(pre)] if pre else []), ah=["AH-04"],
                          references=["docs/references/cctv-vuln-patterns.md#4.1"] if pre else [],
                          remediation="셸을 거치지 말고 execve 인자 배열과 입력 화이트리스트(고정 목록)를 쓴다.")
        for cf in by_rule.get("P1-static-allowlist", []):
            self._confirm(f"{bpath}|static-allowlist", **common, title=f"{name} {cf.function}: 정적 파일 접두어/확장자 부분 문자열이면 인증 생략",
                          category="auth-bypass", severity="high", confidence="confirmed", function=cf.function, address=addr_of.get(cf.function),
                          summary=f"{cf.function} 가 정규화 전 URI 에 정적 접두사나 확장자 부분 문자열이 있으면 1 을 돌려 호출자가 인증 검사를 건너뛴다. "
                                  "임의 경로에 확장자 문자열만 섞어도 인증 없이 처리될 수 있다.",
                          reasoning=cf.reason + " (P1)", evidence=[ev(cf)], ah=["AH-05"],
                          remediation="경로를 정규화한 뒤 정적 디렉터리 접두사만 정확히 비교하고, CGI/API 경로는 항상 인증한다.")
        trust = by_rule.get("P4-client-supplied-local-trust", [])
        skip = by_rule.get("P4-local-skips-password", [])
        if trust:
            cf = trust[0]
            self._confirm(f"{bpath}|client-local-trust", **common,
                          title=f"{name} {cf.function}: 로그인의 '로컬 요청' 신뢰를 클라이언트가 보낸 loginType/ipAddr 로 판정"
                                + (" (비밀번호 검증 생략)" if skip else ""),
                          category="auth-bypass", severity="critical" if skip else "high", confidence="confirmed" if skip else "likely",
                          function=cf.function, address=addr_of.get(cf.function),
                          summary=f"{cf.function} 가 요청 본문의 login_type/ip_addr 값만으로 로컬 요청 여부를 정한다."
                                  + (f" {skip[0].function} 는 그 결과가 참이면 verify_password 를 부르지 않고 성공으로 응답한다." if skip else ""),
                          reasoning=cf.reason + (f". {skip[0].reason}" if skip else "") + ". 소켓 peer 주소가 아니라 클라이언트가 주장한 값이다 (P4, CVE-2021-33045 계열).",
                          evidence=[ev(cf)] + ([ev(skip[0])] if skip else []), ah=["AH-02"],
                          references=["docs/references/cctv-vuln-patterns.md#4.2"],
                          remediation="로컬 판정은 getpeername 결과로 하고 모든 로그인 분기에서 비밀번호/다이제스트 검증을 강제한다.")
        for cf in by_rule.get("P4-param-presence-skips-password", []):
            self._confirm(f"{bpath}|param-presence-auth", **common,
                          title=f"{name} {cf.function}: 쿼리 파라미터만 있으면 비밀번호 확인 없이 인증 (핸들러 계열 간 비대칭)",
                          category="auth-bypass", severity="critical", confidence="confirmed", function=cf.function, address=addr_of.get(cf.function),
                          summary=f"{cf.function} 는 쿼리 파라미터가 있으면 base64 디코드한 사용자 이름만으로 신원을 정하고 비밀번호를 확인하지 않는다. "
                                  "다른 API 계열의 인증 함수는 같은 자리에서 표준 검사만 부른다.",
                          reasoning=cf.reason + ". 한 핸들러 계열에만 있는 '존재하면 생략' 분기는 CVE-2017-7921 계열의 가장 강한 신호다 (P4).",
                          evidence=[ev(cf)], ah=["AH-01"], references=["docs/references/cctv-vuln-patterns.md#4.1"],
                          remediation="디버그 분기를 제거하고 모든 계열이 같은 인증 함수를 거치게 한다.")
        route = by_rule.get("P1-preauth-config-route", [])
        cfgf = by_rule.get("P8-config-dir-file", [])
        if route or cfgf:
            cf = (cfgf or route)[0]
            both = bool(route and cfgf)
            self._confirm(f"{bpath}|preauth-config", **common, title=f"{name}: 세션 확인 전에 설정 디렉터리 파일을 내려줌 (계정 DB 노출)",
                          category="info-leak", severity="high", confidence="confirmed" if both else "likely", function=cf.function,
                          address=addr_of.get(cf.function),
                          summary="설정 파일 경로 접두사 요청이 세션 확인보다 먼저 처리되어, 같은 디렉터리의 계정 DB 를 포함한 설정 파일이 인증 없이 제공된다.",
                          reasoning=" / ".join(x.reason for x in (route + cfgf)[:2]) + " (P1/P8, CVE-2017-7925 계열)",
                          evidence=[ev(x) for x in (route + cfgf)[:2]], ah=["AH-03", "AH-05"],
                          references=["docs/references/cctv-vuln-patterns.md#4.2"],
                          remediation="설정 파일 제공 경로를 제거하거나 세션 확인 뒤로 옮기고, 공개 파일은 명시적 allowlist 로 한정한다.")

    async def _record_candidates(self, *, skill: str) -> None:
        for c in self.cands.values():
            if c.skill != skill and c.finding_id is None and skill == "firmware-static-analysis":
                continue
            body = self._finding_body(c)
            h = hashlib.sha256(json.dumps(body, sort_keys=True, ensure_ascii=False).encode()).hexdigest()
            if c.finding_id is None:
                r = await self.call("pweh-case", "case_add_finding", case_id=self.case_id, finding=body)
                c.finding_id = r["finding_id"]
                c.recorded_hash = h
            elif c.recorded_hash != h:
                patch = {k: body[k] for k in ("title", "severity", "confidence", "status", "summary", "location", "evidence", "reasoning",
                                               "produced_by") if k in body}
                await self.call("pweh-case", "case_update_finding", case_id=self.case_id, finding_id=c.finding_id, patch=patch)
                c.recorded_hash = h

    def _finding_body(self, c: Candidate) -> dict[str, Any]:
        loc = {"firmware": self.st.get("fw_path"), "file": c.file, "function": c.function, "address": c.address, "offset": c.offset,
               "line": c.line, "interface": c.interface}
        body = {
            "title": c.title, "category": c.category, "severity": c.severity, "confidence": c.confidence,
            "status": c.status or _status_for(c.confidence), "summary": self.secrets.mask(c.summary),
            "location": {k: v for k, v in loc.items() if v not in (None, "")},
            "evidence": [self.secrets.mask(e) for e in c.evidence], "reasoning": self.secrets.mask(c.reasoning),
            "produced_by": {"skill": c.skill, "tool": c.tool, "agent": AGENT_NAME},
        }
        if c.references:
            body["references"] = c.references
        if c.verification_plan:
            body["verification_plan"] = c.verification_plan
        if c.remediation:
            body["remediation"] = c.remediation
        return body

    async def _record_static_summary(self) -> None:
        ident, carve, ex, audit = self.st["identify"], self.st["carve"], self.st["extract"], self.st["audit"]
        dump = self.st["dump"]
        rf = audit.get("rootfs") or {}
        env = self.st["uboot_env"]
        layout = carve.get("layout") or {}
        um = (self.st.get("uimage") or {}).get("image") or {}
        bois = []
        for b in audit.get("binaries_of_interest") or []:
            entry = {"path": b["path"], "reason": b["reason"]}
            elf = self.st["elf"].get(b["path"])
            if elf:
                hard = (elf.get("elf") or {}).get("hardening") or {}
                entry["arch"] = (elf.get("elf") or {}).get("summary")
                entry["reason"] += f"; canary={hard.get('stack_canary')}, pie={hard.get('pie')}"
            if b["path"] in self.code_findings:
                entry["analyzed_with"] = "rea-ghidra"
                entry["evidence_bundle"] = next((x for x in self.rea_bundles if f"-{Path(b['path']).name}-" in x), None)
            elif b["path"] in self.st.get("vendor_bins", []):
                entry["analyzed_with"] = "deferred: cctv-auth-bypass-hunt"
            else:
                entry["analyzed_with"] = "fallback" if b["path"].endswith(".cgi") else "none"
            bois.append(entry)
        gaps = [{"region": "boot/env/uImage", "kind": "non-filesystem", "note": "부트로더·env·커널은 파일시스템이 아님 (예상된 gap)"}]
        if self.st.get("rea_extract"):
            gaps.append({"region": os.path.relpath(self.st["rea_extract_dir"], self.case_dir), "kind": "unpublished-entry",
                         "count": self.st["rea_extract"]["unpublished"], "note": "REA 교차 추출의 심볼릭 링크 (메타데이터로만 보존)"})
        data = {
            "firmware": {"path": self.st["fw_path"], "sha256": dump["sha256"], "size": dump["size"], "source": "uart-dump"},
            "identification": {
                **({"regions_crosscheck": (f"REA inspect_firmware_regions(binwalk): 영역 {self.st['rea_regions']['count']}개, "
                                           f"fw_identify 와 같은 오프셋 {', '.join(self.st['rea_regions']['agree']) or '없음'}"
                                           + (f", REA 가 놓친 영역 {', '.join(self.st['rea_regions']['rea_missed'])}" if self.st['rea_regions']['rea_missed'] else "")
                                           + " → fw_identify 를 기본 지도로 채택")} if self.st.get("rea_regions") else {}),
                "arch": rf.get("arch"), "endianness": rf.get("endianness"),
                "bootloader": ((ident.get("summary") or {}).get("uboot_versions") or [None])[0],
                "kernel": {"uimage_name": um.get("name"), "compression": um.get("compression"), "header_crc_ok": um.get("header_crc_ok"),
                           "data_crc_ok": um.get("data_crc_ok")},
                "uboot_env": {"crc_ok": True if env.get("envs") else None, "count": len(env.get("envs") or [])},
                "mtdparts": {"source": layout.get("source"), "text": layout.get("text")},
                "partitions": [{"name": p["name"], "offset": p.get("offset_hex"), "size": p.get("size"), "content": p.get("content"),
                                "file": p.get("file")} for p in carve.get("partitions") or []],
                "entropy": {"unexplained_high_entropy_runs": _count(self.st["entropy"].get("unexplained_high_entropy_runs")),
                            "profile": self.st["entropy"].get("profile")},
                "reports": [x for x in (ident.get("result_path"), self.st["entropy"].get("result_path"), env.get("result_path"),
                                        carve.get("result_path"), (self.st.get("uimage") or {}).get("result_path")) if x],
            },
            "extraction": {"tool": "fwtriage", "status": "partial" if self.st.get("missing_parts") else "complete",
                           "output_dir": ex.get("output_dir"), "gaps": gaps,
                           "runs": [{"tool": "fw_extract_squashfs", "input": self.st["rootfs_part"]["file"], "output_dir": ex.get("output_dir"),
                                     "status": ex.get("status"), "manifest": ex.get("manifest_path")}]
                           + [{"tool": "fw_extract_squashfs", "output_dir": r.get("output_dir"), "status": r.get("status")} for r in self.st["extract_extra"]]
                           + ([{"tool": "extract_firmware", "output_dir": os.path.relpath(self.st["rea_extract_dir"], self.case_dir),
                                "coverage": self.st["rea_extract"]["coverage"], "purpose": "교차 확인"}] if self.st.get("rea_extract") else [])},
            "rootfs": {"path": ex.get("output_dir"), "fs_type": rf.get("fs_type"), "arch": rf.get("arch"), "endianness": rf.get("endianness"),
                       "init_scripts": rf.get("init_scripts") or [], "services": rf.get("services") or [],
                       "web_servers": rf.get("web_servers") or []},
            "binaries_of_interest": bois,
            "rea": {"provider": "ghidra" if self.hub.has_rea else None,
                    "evidence_bundle": self.rea_bundles[0] if self.rea_bundles else None,
                    "limitations": list(self.rea_limitations)},
            "finding_ids": [c.finding_id for c in self.cands.values() if c.finding_id and c.skill == "firmware-static-analysis"],
            "notes": [f"펌웨어 출처: firmware-dump-via-uart ({self.st['dump_meta'].get('verification', {}).get('method')} 일치)",
                      f"triage: {audit.get('result_path')}, {self.st['hunt'].get('result_path')}, {self.st['elf_dir'].get('result_path')}"]
                     + list(self.gaps),
        }
        status = "success" if self.hub.has_rea else "partial"
        fids = data["finding_ids"]
        await self.call("pweh-case", "case_record_step", case_id=self.case_id, skill="firmware-static-analysis", step="summary", status=status,
                        summary=f"rootfs(squashfs) 추출·감사{', REA/Ghidra 디컴파일' if self.hub.has_rea else ' (REA 없음: 휴리스틱만)'}. 발견 {len(fids)}건",
                        data=data,
                        artifacts=[x for x in [ex.get("output_dir"), audit.get("result_path"), self.st["hunt"].get("result_path"),
                                               self.st["elf_dir"].get("result_path")] + self.rea_bundles if x],
                        next_actions=["cctv-auth-bypass-hunt: 벤더 메인 앱·웹 구성요소 AH-01..AH-12 판정"],
                        blockers=[])
        self.st["static_finding_ids"] = fids

    # =====================================================================
    # Phase D — cctv-auth-bypass-hunt
    # =====================================================================
    async def phase_d_auth_hunt(self) -> None:
        self.phase("cctv-auth-bypass-hunt", "벤더 계열 판정 → 벤더 지표 → AH-01..AH-12")
        cid = self.case_id
        await self.call("pweh-case", "case_get", case_id=cid)
        prev = await self.call("pweh-case", "case_get_step_results", case_id=cid)
        sa = prev["summaries"]["firmware-static-analysis"]["data"]
        rootfs = sa["rootfs"]["path"]
        await self.call("pweh-case", "pipeline_profile", name=self.case_profile)
        await self.call("pweh-case", "case_list_findings", case_id=cid)
        await self.call("pweh-case", "case_set_phase", case_id=cid, phase="cctv-auth-bypass-hunt", status="in-progress")
        audit = await self.call("pweh-fwtriage", "fw_rootfs_audit", case_id=cid, rootfs_dir=rootfs)
        vend = audit.get("vendor") or {}
        family = vend.get("family")
        # Skill 2단계: vendor.family_source(evidence / profile / generic-web-server / none)가 판정 근거다.
        # fw_rootfs_audit 가 프로필 대체까지 이미 적용하므로 family_source 가 있으면 family 를 그대로 쓴다.
        if vend.get("family_source") is None and family in (None, "unknown"):
            # family_source 가 없는 예전 fwtriage 응답만: 프로필 → 일반 웹 서버 → unknown 순서로 직접 대체
            family = (self.st["pipeline_profile"].get("profile") or {}).get("hunt", {}).get("vendor_family") or vend.get("profile_vendor_family") \
                or ("generic" if audit.get("web_servers") else "unknown")
        self.st["vendor_family"] = family or "unknown"
        vname = vend.get("vendor")
        if vname:
            self.st["hunt_patterns"] = await self.call("pweh-fwtriage", "fw_hunt_patterns", vendor=vname)
        webs = self.st.get("web_servers") or []
        vendor_bins = self.st.get("vendor_bins") or []
        # 문자열 트리아지: patterns=cctv 결과(phase C) 의 checks[] 를 그대로 쓴다 (전체 JSON 은 케이스 안 result_path)
        hunt_json = json.loads((self.case_dir / self.st["hunt"]["result_path"]).read_text(encoding="utf-8"))
        self.st["hunt_checks"] = hunt_json.get("checks") or []
        for vb in vendor_bins:
            await self.call("pweh-fwtriage", "fw_strings_hunt", case_id=cid, path_or_dir=f"{rootfs}{vb}",
                            patterns=[vname or "cctv", "lit:127.0.0.1"])
        ah05: dict[str, Any] = {}
        for w in webs:
            ah05[w["path"]] = await self.call("pweh-fwtriage", "fw_strings_hunt", case_id=cid, path_or_dir=f"{rootfs}{w['path']}",
                                              patterns=AH05_PATTERNS)
        self.st["ah05"] = ah05
        await self.call("pweh-case", "case_record_step", case_id=cid, skill="cctv-auth-bypass-hunt", step="triage", status="in-progress",
                        summary=f"fwtriage 완료: vendor {family}, 문자열 매치 {len([c for c in self.st['hunt_checks'] if c.get('result') == 'match'])}",
                        data={"strings_hunt": self.st["hunt"]["result_path"], "rootfs_audit": audit.get("result_path")})
        self._vendor_candidates(ah05)
        if self.hub.has_rea:
            for vb in vendor_bins[:2]:
                await self._rea_binary(vb, skill="cctv-auth-bypass-hunt")
        else:
            self.gaps.append("벤더 메인 앱 디컴파일 미실시 (REA 없음) — 벤더 지표 후보는 possible")
        await self._record_candidates(skill="cctv-auth-bypass-hunt")
        await self._record_auth_summary(audit)

    def _vendor_candidates(self, ah05: dict[str, Any]) -> None:
        hunt = self.st["hunt"]
        vendor_bins = set(self.st.get("vendor_bins") or [])
        hits_by_file: dict[str, list[dict[str, Any]]] = {}
        for h in hunt.get("hits") or []:
            hits_by_file.setdefault(self.to_rootfs(h.get("file")) or "", []).append(h)
        for f in sorted(vendor_bins):
            hs = hits_by_file.get(f, [])
            ids = {h["pattern_id"] for h in hs}
            name = Path(f).name

            def evs(pids: tuple[str, ...], f: str = f, hs: list[dict[str, Any]] = hs, ids: set[str] = ids) -> list[dict[str, Any]]:
                out = [{"type": "string", "ref": f"{f}@{h['offset_hex']}", "excerpt": f"{h['pattern_id']}: {h.get('context') or h.get('match')}"}
                       for h in hs if h["pattern_id"] in pids][:4]
                out.append({"type": "triage", "ref": hunt["result_path"], "excerpt": ", ".join(sorted(set(pids) & ids))})
                return out

            if "hik-sdk-weblanguage" in ids:
                self.cand(f"{f}|cmd-template|webLanguage", title=f"{name}: 언어 설정 핸들러(webLanguage)의 값이 셸 명령으로 갈 수 있음 (명령 주입 후보)",
                          category="command-injection", severity="high", confidence="possible", file=f, interface="http",
                          summary=f"{f} 에 언어 설정 엔드포인트 문자열이 있다. 공개 사례(CVE-2021-36260 계열)는 language 값이 검증 없이 셸 명령으로 실행됐다.",
                          reasoning="hik-sdk-weblanguage(high) 문자열 히트. 값 → sprintf → system 경로와 인증 전 디스패치 여부를 디컴파일로 확인해야 한다 (P11).",
                          evidence=evs(("hik-sdk-weblanguage",)), ah=["AH-04"], references=["docs/references/cctv-vuln-patterns.md#4.1"],
                          verification_plan=VERIFY_GENERIC + " 빌드 날짜를 벤더 공지 기준과 비교한다.",
                          remediation="language 값을 고정 목록으로 검증하고 셸을 거치지 않는다.", tool="fw_strings_hunt", skill="cctv-auth-bypass-hunt")
            if "hik-hikcgi-endpoints" in ids:
                self.cand(f"{f}|param-presence-auth", title=f"{name}: HikCGI 형 핸들러 계열의 인증 비대칭 후보 (매직 파라미터)",
                          category="auth-bypass", severity="high", confidence="possible", file=f, interface="http",
                          summary=f"{f} 에 HikCGI 형 엔드포인트와 여러 API 계열 경로가 있다. 한 계열에만 '파라미터가 있으면 인증 생략' 분기가 있는지 확인이 필요하다.",
                          reasoning="hik-hikcgi-endpoints/hik-handler-families 앵커. CVE-2017-7921 계열은 계열 간 인증 코드 비대칭이 핵심이다 (P4).",
                          evidence=evs(("hik-hikcgi-endpoints", "hik-handler-families")), ah=["AH-01"],
                          references=["docs/references/cctv-vuln-patterns.md#4.1"], verification_plan=VERIFY_GENERIC,
                          remediation="모든 계열이 같은 인증 함수를 거치게 한다.", tool="fw_strings_hunt", skill="cctv-auth-bypass-hunt")
            if "dh-current-config" in ids:
                self.cand(f"{f}|preauth-config", title=f"{name}: /current_config/ 매핑 — 인증 없는 설정·계정 DB 노출 후보",
                          category="info-leak", severity="high", confidence="possible", file=f, interface="http",
                          summary=f"{f} 에 설정 디렉터리 매핑 문자열과 계정 DB 경로가 있다. 세션 확인 전에 제공되는지 확인이 필요하다 (CVE-2017-7925 계열).",
                          reasoning="dh-current-config(high) + gen-mtd-config-accounts 앵커 (P8).",
                          evidence=evs(("dh-current-config", "gen-mtd-config-accounts")), ah=["AH-03", "AH-05"],
                          references=["docs/references/cctv-vuln-patterns.md#4.2"], verification_plan=VERIFY_GENERIC,
                          remediation="설정 파일 경로를 세션 확인 뒤로 옮기거나 제거한다.", tool="fw_strings_hunt", skill="cctv-auth-bypass-hunt")
            if ("dh-login-loopback-local" in ids or "dh-login-netkeyboard" in ids) and "dh-login-fields" in ids:
                self.cand(f"{f}|client-local-trust", title=f"{name}: 로그인 loginType/clientType 분기 — 클라이언트 주장 값 신뢰 후보",
                          category="auth-bypass", severity="high", confidence="possible", file=f, interface="http",
                          summary=f"{f} 의 로그인 처리에 loginType/clientType 필드와 Loopback 값이 함께 있다. 요청 값으로 로컬 신뢰를 정하는지 확인이 필요하다.",
                          reasoning="dh-login-loopback-local 은 dh-login-fields 와 같은 바이너리에서 날 때만 의미가 있다 (YAML 근거). CVE-2021-33044/33045 계열 (P4).",
                          evidence=evs(("dh-login-loopback-local", "dh-login-netkeyboard", "dh-login-fields", "gen-loopback-trust-anchors")),
                          ah=["AH-02"], references=["docs/references/cctv-vuln-patterns.md#4.2"], verification_plan=VERIFY_GENERIC,
                          remediation="로컬 판정은 소켓 peer 주소로 하고 모든 분기에서 비밀번호 검증을 강제한다.", tool="fw_strings_hunt",
                          skill="cctv-auth-bypass-hunt")
        # AH-05 대체 근거 (REA 없을 때): 웹 바이너리의 경로 접두사·확장자 리터럴 + fn-uri-substring-match
        for path, res in ah05.items():
            lits = [h.get("match") for h in res.get("hits") or []]
            elf = self.st["elf"].get(path) or {}
            heur = (elf.get("risk") or {}).get("heuristics") or {}
            has_ext = any(str(x).startswith(".") for x in lits)
            prefixes = [x for x in lits if str(x).startswith("/")]
            if has_ext and prefixes and "fn-uri-substring-match" in heur and f"{path}|static-allowlist" not in self.cands:
                self.cand(f"{path}|static-allowlist", title=f"{Path(path).name}: 정적 파일 접두어/확장자 allowlist 로 인증을 건너뛸 가능성",
                          category="auth-bypass", severity="medium", confidence="possible", file=path, interface="http",
                          summary=f"{path} 에 URI 접두사 리터럴({', '.join(map(str, prefixes[:3]))})과 확장자 리터럴이 함께 있고 strstr/strncmp 를 쓴다.",
                          reasoning="fn-uri-substring-match 함수 휴리스틱 + 경로 접두사·확장자 리터럴. 인증 함수 앞에서 부분 문자열로 분기하는지는 디컴파일이 필요하다 (P1).",
                          evidence=[{"type": "triage", "ref": res.get("result_path"), "excerpt": "리터럴: " + ", ".join(map(str, lits[:8]))},
                                    {"type": "triage", "ref": elf.get("result_path"),
                                     "excerpt": "fn-uri-substring-match: " + ",".join((heur.get("fn-uri-substring-match") or {}).get("functions") or [])}],
                          ah=["AH-05"], verification_plan=VERIFY_GENERIC,
                          remediation="경로 정규화 후 정적 디렉터리 접두사만 정확히 비교한다.", tool="fw_strings_hunt + fw_elf_info",
                          skill="cctv-auth-bypass-hunt")

    async def _record_auth_summary(self, audit: dict[str, Any]) -> None:
        cands = list(self.cands.values())

        def verdict(ah: str, default: str, default_desc: str) -> dict[str, Any]:
            cs = sorted([c for c in cands if ah in c.ah and c.finding_id], key=lambda c: (CONF_RANK[c.confidence], SEV_RANK[c.severity]))
            if cs:
                best = cs[0]
                res = "match" if best.confidence == "confirmed" else "inconclusive"
                ref = next((e["ref"] for e in best.evidence if e.get("type") in ("decompilation", "triage", "string", "file")), None)
                more = [c.finding_id for c in cs[1:]]
                return {"result": res, "evidence_ref": ref, "finding_id": best.finding_id, "confidence": best.confidence,
                        "description_suffix": f" — {best.title}" + (f" (관련: {', '.join(more)})" if more else "")}
            return {"result": default, "evidence_ref": None, "finding_id": None, "description_suffix": f" — {default_desc}"}

        AH = [
            ("AH-01", "매직/하드코딩 인증 토큰·파라미터 (P4/P5, CVE-2017-7921 계열)", "P4/P5", "inconclusive", "인증 함수 리터럴 비교를 찾지 못함"),
            ("AH-02", "클라이언트 주장 값(clientType/loginType/loopback)으로 인증 결정 (P4, CVE-2021-33044/33045 계열)", "P4", "not-applicable",
             "로그인 RPC 어휘(clientType/loginType) 없음"),
            ("AH-03", "무인증 핸들러의 설정·해시 유출 (P3/P8, CVE-2017-7925/7923 계열)", "P8", "inconclusive", "설정 export/파일 제공 경로 미확인"),
            ("AH-04", "요청 파라미터 → system()/popen() 명령 주입 (P11, CVE-2021-36260 계열)", "P11", "inconclusive", "명령 템플릿 없음"),
            ("AH-05", "정적 파일/URL 접두사 allowlist 가 인증을 건너뜀 (P1)", "P1", "inconclusive", "접두사 분기 미확인"),
            ("AH-06", "인증 전 경로 순회 (P2)", "P2", "inconclusive", "fn-path-ops-unnormalized 후보만 있음 — 파일 서빙 경로의 정규화 여부 미확인"),
            ("AH-07", "디버그·백도어 서비스 (P6, XiongMai 9530 계열)", "P6", "no-match", "시작 스크립트에 디버그 서비스 없음"),
            ("AH-08", "하드코딩·기본 계정 (P5)", "P5", "no-match", "약한/기본 계정 없음"),
            ("AH-09", "약하거나 예측 가능한 세션·nonce·토큰 (P7)", "P7", "inconclusive", "세션 생성 함수 미분석"),
            ("AH-10", "서명 없는 펌웨어 업데이트 경로 (P10)", "P10", "inconclusive", "업데이트 처리 문자열·바이너리를 rootfs 에서 찾지 못함 (다른 파티션일 수 있음)"),
            ("AH-11", "ONVIF/RTSP 인증 누락·약화 (P9)", "P9", "inconclusive", "RTSP/ONVIF 서버 바이너리를 rootfs 에서 찾지 못함"),
            ("AH-12", "인증 전 메모리 안전성 결함 기록 (P12, 보조)", "P12", "inconclusive", "elf-info: 스택 카나리 없음, 개별 함수 미분석"),
        ]
        checks = []
        for aid, desc, pclass, default, ddesc in AH:
            v = verdict(aid, default, ddesc)
            if aid == "AH-02" and v["finding_id"] is None and any(h.get("pattern_id", "").startswith("dh-login") for h in self.st["hunt"].get("hits") or []):
                v.update(result="inconclusive", description_suffix=" — 로그인 어휘는 있으나 분기 미확인")
            if aid == "AH-12":
                v["evidence_ref"] = self.st["elf_dir"].get("result_path")
            checks.append({"id": aid, "description": desc + v.pop("description_suffix"), "result": v["result"], "evidence_ref": v["evidence_ref"],
                           "finding_id": v["finding_id"], "pattern_class": pclass, **({"confidence": v["confidence"]} if v.get("confidence") else {})})
        checks.extend(self.st.get("hunt_checks") or [])
        gaps = list(dict.fromkeys(self.gaps + [f"{c['id']}: {c['description'].split(' — ', 1)[-1]}" for c in checks[:12] if c["result"] == "inconclusive"]))
        web_components = []
        for w in self.st.get("web_servers") or []:
            role = "main-app" if w.get("vendor") not in ("generic", None, "profile") else "http (generic)"
            web_components.append({"path": w["path"], "role": f"{role} ({w.get('vendor')})", "arch": w.get("elf")})
        for b in audit.get("binaries_of_interest") or []:
            if b["path"].endswith(".cgi"):
                web_components.append({"path": b["path"], "role": "cgi", "arch": None})
        fids = sorted({c.finding_id for c in cands if c.finding_id})
        data = {
            "vendor_family": self.st["vendor_family"],
            "web_components": web_components,
            "checks": checks,
            "finding_ids": fids,
            "coverage_gaps": gaps,
            "vendor_evidence": (audit.get("vendor") or {}).get("evidence") or [],
            "evidence_bundles": list(self.rea_bundles),
            "triage_reports": [audit.get("result_path"), self.st["hunt"].get("result_path"), self.st["elf_dir"].get("result_path")],
        }
        n_match = sum(1 for c in checks[:12] if c["result"] == "match")
        n_inc = sum(1 for c in checks[:12] if c["result"] == "inconclusive")
        status = "success" if n_inc == 0 and not gaps else "partial"
        await self.call("pweh-case", "case_record_step", case_id=self.case_id, skill="cctv-auth-bypass-hunt", step="summary", status=status,
                        summary=f"{self.st['vendor_family']}. AH-01~AH-12: match {n_match}, inconclusive {n_inc}. 발견 {len(fids)}건",
                        data=data, artifacts=[x for x in data["triage_reports"] + self.rea_bundles if x],
                        next_actions=["빌드 날짜를 벤더 공지 수정 빌드와 비교", "격리 랩에서 negative test (사용자 동의 후)"], blockers=[])

    # =====================================================================
    # Phase E — 보고
    # =====================================================================
    async def phase_e_report(self) -> dict[str, Any]:
        self.phase("report", "report_generate → 정리 확인")
        rep = await self.call("pweh-case", "report_generate", case_id=self.case_id)
        self.st["report"] = rep
        self.st["uart_jobs_active"] = await self.call("pweh-uart", "uart_jobs", active_only=True)
        self.st["uart_sessions_end"] = await self.call("pweh-uart", "uart_sessions", case_id=self.case_id)
        self.st["fw_jobs_active"] = await self.call("pweh-fwtriage", "fwtriage_jobs", active_only=True)
        self.st["findings_final"] = await self.call("pweh-case", "case_list_findings", case_id=self.case_id)
        return rep

    async def run_uboot_pipeline(self) -> None:
        await self.phase0_intake()
        await self.phase_a_uboot()
        await self.record_recon_uboot()
        await self.phase_b_dump()
        await self.record_dump()
        await self.phase_c_static()
        await self.phase_d_auth_hunt()
        await self.phase_e_report()

    # =====================================================================
    # 리눅스 셸 경로 (uart-shell-acquisition 경로 B/C → firmware-dump-via-uart 셸 경로)
    # =====================================================================
    async def run_shell_path(self, *, username: str, password: str, mtd: str = "/dev/mtd3") -> None:
        await self.phase0_intake()
        self.phase("uart-shell-acquisition", "포트 → 배선 → 부팅 로그 → 로그인(사용자가 준 계정) → 셸 식별")
        cid = self.case_id
        await self.call("pweh-case", "case_get", case_id=cid)
        await self.call("pweh-case", "case_get_step_results", case_id=cid)
        await self.call("pweh-case", "pipeline_profile", name=self.case_profile)
        await self.call("pweh-case", "case_set_phase", case_id=cid, phase="uart-shell-acquisition", status="in-progress")
        await self.call("pweh-uart", "uart_list_ports", include_links=True)
        self.human.say(f"UART 배선 완료 (GND/TX/RX, VCC 미연결, TX 3.3V). 포트 {self.port} (시뮬레이터 PTY)")
        op = await self.call("pweh-uart", "uart_open", case_id=cid, port=self.port, baudrate=115200, label="console")
        self.st["open"] = op
        sid = op["session_id"]
        self.st["session_id"] = sid
        t = self.human.power_on_soon(0.4, "에이전트 요청: uart_capture_boot 감시 시작 직후")
        boot = await self.call("pweh-uart", "uart_capture_boot", session_id=sid, duration=45)
        t.join()
        self.st["boot"] = boot
        self.say(f"부팅 로그: {boot.get('stopped_by')} → 로그인 필요. 사용자에게 계정을 물음 (H5, 추측·무차별 대입 금지)")
        self.human.say(f"콘솔 계정을 알려 줌: 사용자 {username} (비밀번호는 로그에 남기지 않음)")
        li = await self.call("pweh-uart", "shell_login", session_id=sid, username=username, password=password, timeout=20)
        if not li.get("logged_in"):
            raise ToolError(f"로그인 실패: {li}")
        ident = await self.call("pweh-uart", "shell_identify", session_id=sid)
        self.st["identify_shell"] = ident
        await self.call("pweh-case", "case_update_target", case_id=cid,
                        target={k: v for k, v in {"kernel_version": ident.get("kernel_version"), "arch": ident.get("arch")}.items() if v})
        data = {
            "port": self.port, "baudrate": 115200, "framing": "8N1",
            "baud_detection": {"method": "profile", "candidates": [115200], "score": None},
            "console_type": "linux-shell", "access_level": "root-shell" if (ident.get("user") or {}).get("uid") == 0 else "user-shell",
            "uboot": {"version": boot.get("uboot_version"), "prompt": None,
                      "autoboot": {"message": boot.get("autoboot_message") or "", "interrupt_keys": [], "bootdelay": boot.get("bootdelay")},
                      "mtdparts": boot.get("mtdparts"),
                      "partitions": [{"name": p["name"], "offset": p["offset"], "size": p["size"]} for p in boot.get("partitions") or []]},
            "linux": {"kernel_version": ident.get("kernel_version"), "cmdline": ident.get("cmdline"), "cpu": ident.get("arch"),
                      "mtd": [{"dev": m["dev"], "size": m["size"], "erasesize": m["erasesize"], "name": m["name"]} for m in ident.get("mtd") or []],
                      "user": (ident.get("user") or {}).get("name") or username, "busybox": ident.get("busybox_version"),
                      "login_required": True},
            "session_log": op.get("log_path"),
            "boot_log": boot.get("excerpt_path"),
            "contexts_reached": ["linux-shell"],
            "login_method": "user-credentials",
            "session": {"session_id": sid, "kept_open": True, "context_at_end": "linux-shell"},
            "notes": ["U-Boot 를 거치지 않고 부팅 로그 → 로그인 프롬프트 → 사용자가 준 계정으로 1회 로그인 (비밀번호 기록 안 함)",
                      f"셸 도구: base64={ident.get('has_base64')}, md5sum={ident.get('has_md5sum')}"],
        }
        await self.call("pweh-case", "case_record_step", case_id=cid, skill="uart-shell-acquisition", step="summary", status="success",
                        summary="리눅스 root 셸 확보 (사용자 제공 계정), /proc/mtd 수집", data=data,
                        artifacts=[x for x in (op.get("log_path"), boot.get("excerpt_path")) if x],
                        next_actions=["firmware-dump-via-uart: 셸 base64 덤프 (md5 청크 검증)"])

        self.phase("firmware-dump-via-uart", f"셸 dd 덤프 {mtd}")
        await self.call("pweh-case", "case_get", case_id=cid, include_artifacts=True)
        await self.call("pweh-case", "case_get_step_results", case_id=cid, skill="firmware-dump-via-uart", summaries_only=False)
        await self.call("pweh-case", "case_set_phase", case_id=cid, phase="firmware-dump-via-uart", status="in-progress")
        await self.call("pweh-uart", "uart_sessions", case_id=cid)
        part = next((m for m in ident.get("mtd") or [] if f"/dev/{m['dev']}" == mtd), {})
        name = f"{mtd.rsplit('/', 1)[-1]}-{part.get('name', 'part')}"
        self.say(f"[확인 필요] 셸 덤프 계획: {mtd} ({part.get('name')}, {part.get('size')} bytes), base64 + 청크별 md5. "
                 f"실기기 115200bps 기준 약 {int((part.get('size') or 0) * 1.37 * 10 / 115200 / 60)}분")
        self.human.say("셸 덤프 계획에 동의")
        await self.call("pweh-uart", "uart_send_command", session_id=sid, command="dmesg -n 1")
        st = await self.call("pweh-uart", "shell_dump_start", case_id=cid, session_id=sid, path=mtd, chunk_size=self.chunk_size, output_name=name)
        if not st.get("ok"):
            raise ToolError(f"셸 덤프 시작 실패: {st}")
        await self.call("pweh-case", "case_record_step", case_id=cid, skill="firmware-dump-via-uart", step=f"job-{name}", status="in-progress",
                        summary=f"셸 덤프 {mtd} 시작", data={"tool": "shell_dump_start", "job_id": st["job_id"],
                                                            "args": {"path": mtd, "chunk_size": self.chunk_size, "output_name": name}})
        while True:
            js = await self.call("pweh-uart", "uart_job_status", job_id=st["job_id"], wait_seconds=50)
            if js.get("status") not in ("queued", "running", "cancelling"):
                break
        if js.get("status") != "succeeded":
            raise ToolError(f"셸 덤프 실패: {js}")
        res = js["result"]
        self.st["dump"] = res
        await self.call("pweh-case", "case_record_step", case_id=cid, skill="firmware-dump-via-uart", step=f"job-{name}", status="success",
                        summary=f"완료 {res['path']}", data={"job_id": st["job_id"], "result_path": res["path"], "sha256": res["sha256"]})
        meta = json.loads((self.case_dir / res["metadata_path"]).read_text(encoding="utf-8"))
        self.st["dump_meta"] = meta
        ver = meta.get("verification") or {}
        src = meta.get("source") or {}
        await self.call("pweh-uart", "uart_close", session_id=sid)
        await self.call("pweh-case", "case_record_step", case_id=cid, skill="firmware-dump-via-uart", step="summary",
                        status="partial" if ver.get("match") else "failed",
                        summary=f"셸 {meta.get('method')} 덤프 {mtd} {res['size']} bytes, md5 청크 검증 {ver.get('match')} (파티션 하나만)",
                        data={"method": meta.get("method"), "source": {k: src.get(k) for k in ("flash_type", "flash_size", "offset", "length",
                                                                                                   "partition", "ram_addr", "device_path")},
                              "output": {"path": res["path"], "sha256": res["sha256"], "size": res["size"]},
                              "verification": {"method": ver.get("method"), "match": ver.get("match")},
                              "chunks": {k: v for k, v in (meta.get("chunks") or {}).items() if k != "checks"},
                              "partitions": [{"name": p["name"], "offset": p["offset"], "size": p["size"]} for p in boot.get("partitions") or []],
                              "duration_seconds": meta.get("duration_seconds"), "baudrate": 115200, "metadata_path": res["metadata_path"],
                              "notes": [f"파티션 하나만 덤프: {mtd}", "dmesg -n 1 로 커널 메시지 끼어듦을 줄인 뒤 덤프"]},
                        artifacts=[res["path"], res["metadata_path"]],
                        next_actions=["나머지 mtd 파티션 덤프 여부 확인", "firmware-static-analysis: rootfs 파티션 파일 분석"])
        await self.phase_e_report()

    # =====================================================================
    # 에이전트 실수 (안전 게이트 확인용) — 거부되어야 하고, 흐름은 계속된다
    # =====================================================================
    async def mistakes_uboot(self) -> list[dict[str, Any]]:
        sid = self.st["session_id"]
        self.say("의도적 실수 시연: 영구 변경 명령을 U-Boot 에 보내 본다 (서버 게이트가 막아야 한다)")
        out = []
        for cmd in ("saveenv", "sf erase 0x0 0x10000", "setenv bootdelay 0; saveenv", "env save"):
            r = await self.call("pweh-uart", "uart_send_command", session_id=sid, command=cmd)
            out.append({"command": cmd, "status": r.get("status"), "ok": r.get("ok")})
        w1 = await self.call("pweh-uart", "uart_write", session_id=sid, data="sa")
        w2 = await self.call("pweh-uart", "uart_write", session_id=sid, data="veenv\r")
        out.append({"command": "uart_write('sa') + uart_write('veenv\\r')", "status": w2.get("status"), "ok": w2.get("ok"),
                    "first": w1.get("ok")})
        s = await self.call("pweh-uart", "uart_sync", session_id=sid)
        out.append({"command": "uart_sync (Ctrl-C 로 미완성 입력 비움)", "status": s.get("evidence"), "ok": s.get("ok")})
        self.say("거부를 우회하지 않고 사용자에게 보고한 뒤 읽기 전용 작업을 계속한다")
        return out

    async def boot_linux_and_login(self, *, username: str, password: str) -> dict[str, Any]:
        """U-Boot 프롬프트에서 기본 bootcmd 로 부팅(MODIFY, 허용) → 로그인 → 식별."""
        sid = self.st["session_id"]
        self.say("U-Boot 에서 boot (bootcmd 그대로, env 변경 없음) → 리눅스 로그인")
        r = await self.call("pweh-uart", "uart_send_command", session_id=sid, command="boot", timeout=40,
                            expect=r"Please press Enter to activate this console")
        if not r.get("matched"):
            raise ToolError(f"부팅 실패: {r}")
        self.human.say(f"콘솔 계정을 알려 줌: 사용자 {username}")
        li = await self.call("pweh-uart", "shell_login", session_id=sid, username=username, password=password, timeout=20)
        if not li.get("logged_in"):
            raise ToolError(f"로그인 실패: {li}")
        ident = await self.call("pweh-uart", "shell_identify", session_id=sid)
        self.st["identify_shell"] = ident
        return ident

    async def mistakes_shell(self) -> list[dict[str, Any]]:
        sid = self.st["session_id"]
        out = []
        for cmd in ("flash_erase /dev/mtd1 0 0", "dd if=/dev/zero of=/dev/mtd1", "fw_setenv bootdelay 0"):
            r = await self.call("pweh-uart", "uart_send_command", session_id=sid, command=cmd)
            out.append({"command": cmd, "status": r.get("status"), "ok": r.get("ok")})
        return out


# ---------------------------------------------------------------------------
# 실행 도우미 (테스트·예제 공용)
# ---------------------------------------------------------------------------
@dataclass
class RunResult:
    flow: AgentFlow
    rec: Recorder
    manifest: dict[str, Any]
    image_path: Path
    dev_destructive: list[dict[str, Any]]
    coverage: dict[str, list[Observation]]
    rea_used: bool
    rea_error: str | None
    elapsed: float
    extra: dict[str, Any] = field(default_factory=dict)


def start_device(profile: str, image_path: Path, *, time_scale: float = 0.01) -> tuple[Any, str]:
    from pweh.mocktarget import MockDevice

    dev = MockDevice(profile, flash_image=image_path, time_scale=time_scale, autostart=False, autoboot_floor=0.12)
    port = dev.start_pty()
    return dev, port


async def run_pipeline(profile: str, image_path: Path, manifest: dict[str, Any], *, scenario: Scenario, use_rea: bool,
                       dump_scope: str = "needed", chunk_size: str = "256k", rea_cwd: Path | None = None,
                       mistakes: bool = False, case_id: str | None = None,
                       before_report: Callable[[AgentFlow], Any] | None = None) -> RunResult:
    """U-Boot 경로 전체 파이프라인을 실행한다. 반환 후 장치는 정지되어 있다."""
    from uart_mcp import server as us

    rec = Recorder()
    t0 = time.monotonic()
    dev, port = start_device(profile, image_path)
    extra: dict[str, Any] = {}
    try:
        async with McpHub(rec, rea=use_rea, rea_cwd=rea_cwd) as hub:
            flow = AgentFlow(hub, Human(dev, rec), profile=profile, port=port, scenario=scenario, dump_scope=dump_scope,
                             chunk_size=chunk_size, case_id=case_id)
            await flow.phase0_intake()
            await flow.phase_a_uboot()
            if mistakes:
                extra["mistakes"] = await flow.mistakes_uboot()
            await flow.record_recon_uboot()
            await flow.phase_b_dump()
            await flow.record_dump()
            await flow.phase_c_static()
            await flow.phase_d_auth_hunt()
            if before_report:
                before_report(flow)
            await flow.phase_e_report()
            rea_used, rea_err = hub.has_rea, hub.rea_error
    finally:
        us.shutdown_all("e2e flow end")
        destructive = list(dev.destructive_events)
        dev.stop()
    coverage = match_planted(manifest.get("planted_issues") or [], flow.obs)
    return RunResult(flow, rec, manifest, image_path, destructive, coverage, rea_used, rea_err, round(time.monotonic() - t0, 1), extra)


def flash_bytes(image_path: Path, offset: int, length: int) -> bytes:
    with open(image_path, "rb") as fh:
        fh.seek(offset)
        return fh.read(length)


__all__ = [
    "AgentFlow", "Candidate", "CodeFinding", "Human", "McpHub", "Observation", "PIPELINE_PROFILE", "Recorder", "RunResult", "Scenario",
    "Secrets", "ToolError", "abridge_result", "build_firmware", "classify_pseudocode", "derive_indicators", "flash_bytes", "match_planted",
    "rea_available", "run_pipeline", "start_device",
]
