"""MCP 클라이언트 설정 — Codex 설정 생성·병합·신뢰 등록과 서버 시작 점검.

``pweh mcp-config --client codex``, ``pweh codex-trust``, ``pweh mcp-check``, ``pweh doctor`` 의 Codex 줄이 이 모듈을 쓴다
(명령행 연결은 :mod:`pweh.cli`). MCP 서버 프로세스에서는 쓰지 않는다 — 사람이 실행하는 CLI 전용이라 결과를 stdout 에 쓴다.

Codex(0.162.0 기준) 사실:

- Codex 홈(``CODEX_HOME``)은 둘일 수 있고, 홈마다 자기 ``config.toml`` 을 읽는다.
  (1) WSL 의 Codex CLI: ``$CODEX_HOME`` 또는 ``~/.codex``.
  (2) Windows 의 Codex 데스크톱 앱이 ``[desktop] runCodexInWindowsSubsystemForLinux = true`` 일 때: 에이전트는 WSL 안에서 돌지만
  홈은 Windows 프로필의 ``.codex`` 다(WSLENV ``CODEX_HOME/p``). WSL 모드가 아니면 Windows 의 Codex 는 리눅스 경로의 서버를 실행할 수 없다.
- 프로젝트 설정 ``<저장소>/.codex/config.toml`` 은 쓰는 홈의 사용자 설정에 ``[projects."<저장소 실제 경로>"] trust_level = "trusted"``
  가 있을 때만 읽는다(정확한 경로 — 조상 디렉터리 항목은 저장소를 덮지 않는다). 프로젝트 설정 금지 목록
  (config/src/loader/mod.rs PROJECT_LOCAL_CONFIG_DENYLIST)에 ``mcp_servers``·``features``·``mcp_optional_startup_grace_ms`` 는 없다.
- 같은 표를 두 번 쓰면 Codex 가 시작하지 않는다(duplicate key). 표 뒤에 덧붙인 최상위 키는 마지막 표 안으로 들어간다.
  그래서 사람이 붙여 넣게 하지 않고 tomlkit 으로 고친다: 주석·서식 보존, CRLF·BOM 유지, 백업, 같은 디렉터리 임시 파일 → 원자적 교체
  (권한 유지), 바꾸기 전에 새 내용을 다시 읽어 의미(최상위 키 위치·pweh 표 내용·사용자 키 보존)까지 확인한다.
- ``mcp_optional_startup_grace_ms``(최상위, 기본 1000 ms): REA 는 시작에 약 1.5 s 걸려 첫 턴 도구 목록에서 빠진다 → 15000.
  첫 표보다 앞에 있어야 한다.
- 지금 모델은 code mode 전용 + 도구 검색이라 MCP 도구가 지연 노출된다(모델에 바로 보이지 않음).
  ``[features.code_mode] direct_only_tool_namespaces`` 에 이름공간(``mcp__`` + 서버 이름, '-' 는 '_')을 넣으면 바로 보인다.
  PWEH 9개를 전부 노출하면 요청마다 해당 도구 정의가 포함된다(크기는 도구 설명에 따라 달라진다). ``CodeModeConfigToml`` 은 deny_unknown_fields 라 ``enabled`` 와 이 키만 쓴다.
  ``features.code_mode = true/false``(불리언 형식)는 ``enabled = <값>`` 인 표로 바꾼다.
- REA 는 도구 207개(tools/list 3 MB)를 내놓는다 → ``.claude/settings.json`` 의 ``mcp__rea__*`` 허용/확인 항목으로 ``enabled_tools`` 를
  만든다. 항목이 없거나 와일드카드면 ``enabled_tools`` 를 쓰지 않는다(빈 목록은 도구를 모두 끈다).
- Codex 는 MCP 서버를 env_clear + 허용 목록(HOME, LOGNAME, PATH, SHELL, USER, LANG, LC_ALL, TERM, TMPDIR, TZ) + 설정의 env·env_vars
  로 띄운다(새 프로세스 그룹). ``WSL_INTEROP`` 은 필요 없다(interop 은 기본 소켓으로 동작). ``WSL_DISTRO_NAME`` 은 표시용이라
  ``env_vars`` 로만 넘긴다(없으면 Codex 가 건너뛴다).
- Codex 는 입력 스키마의 ``default`` 를 버린다(연결 문제 아님). ``codex exec`` 는 approval_policy=never 라 승인이 필요한 도구를
  거부한다 — 둘 다 문서로만 안내한다.

Windows 프로필은 실행할 때 찾는다(사용자 이름을 코드나 저장소에 남기지 않는다): ``PWEH_WINDOWS_PROFILE``(명시 지정, WSL 경로 또는
``C:\\Users\\…``) → ``USERPROFILE``(WSLENV 로 넘어온 WSL 경로) → interop: :mod:`pweh.hostenv` 가 실제 경로를 확인한 System32
``powershell.exe`` 로 코드에 박힌 고정 스크립트만 실행한다(port-routing §11 의 허용 목록 원칙 — ``cmd.exe`` 는 쓰지 않는다).
Codex 홈은 ``--codex-home`` 으로 직접 줄 수도 있다(이미 있는 디렉터리이거나 이름이 ``.codex`` 여야 한다 — 오타로 새 홈을 만들지 않게).

설정 파일에는 실행한 셸의 ``PATH`` 를 넣지 않는다(WSL 이면 Windows PATH 와 Windows 사용자 이름이 섞이고 셸마다 달라 다시 쓸 때마다
바뀐다). PATH 가 필요한 REA 는 ``scripts/mcp-launch.sh rea`` 로 등록해 런처가 실행할 때 env.sh 를 불러온다(:func:`pweh.cli.build_mcp_servers`).

파일 쓰기 규칙: 같은 디렉터리를 고치는 다른 pweh 와 겹치지 않게 읽기부터 바꾸기까지 디렉터리에 flock 을 잡고(잠글 수 없는 파일 시스템이면
건너뜀), 백업은 0600 으로 만든 뒤 원본 권한을 복사하고, 바꾸기 직전에 파일이 읽은 뒤 그대로인지·바꾼 뒤 쓴 내용과 같은지 다시 확인한다.
프로젝트 설정에는 내용 지문(``# pweh-sha256:``)을 넣어, 사람이 고친 파일은 다시 만들기 전에 백업한다.
사용자 설정의 diff 는 바뀌지 않는 줄의 값을 가리고 보여 준다(env 의 토큰 같은 비밀값이 화면·로그에 나오지 않게).

tomlkit 은 함수 안에서 import 한다(설치를 다시 하지 않은 가상환경에서도 ``pweh approve`` 같은 다른 명령은 돈다).
"""

from __future__ import annotations

import collections
import contextlib
import copy
import dataclasses
import datetime as _dt
import difflib
import json
import os
import queue
import re
import shutil
import signal
import stat
import subprocess
import tempfile
import threading
import time
from pathlib import Path
from typing import Any, Callable, Iterable, Iterator, Mapping, Sequence

from .errors import PwehError

#: 프로젝트 설정 파일의 첫 줄 (pweh 가 만든 파일인지 이 표식으로 안다)
PROJECT_MARKER = "# pweh-generated: codex-project-config v1"
#: 생성 옵션 줄 (doctor 가 같은 옵션으로 다시 만들어 비교하고, --write 가 주지 않은 옵션을 이어 쓴다)
OPTIONS_PREFIX = "# pweh-options: "
#: 내용 지문 줄: 이 줄을 뺀 파일 내용(LF)의 sha256. pweh 가 쓴 그대로면 다시 만들 때 백업하지 않고, 다르면(사람이 고침) 백업한다
DIGEST_PREFIX = "# pweh-sha256: "
#: pweh 가 관리하는 서버 표에서 사용자가 정한 값이라 다시 만들 때 옮겨 두는 키 (pweh 가 만들지 않는 키일 때만)
USER_SERVER_KEYS = ("enabled", "required", "enabled_tools", "disabled_tools", "tools")
#: diff 에서 값을 가리는 표·키 (비밀값이 흔한 곳)
SECRET_TABLE_KEYS = ("env", "http_headers", "env_http_headers")
#: 같은 Codex 홈을 고치는 다른 pweh 를 기다리는 시간 (초)
LOCK_TIMEOUT_S = 30.0
#: 사용자 설정에서 pweh 가 관리하는 표의 머리 주석 표식 ([mcp_servers.rea] 를 사용자 표와 구별한다)
MANAGED_MARK = "pweh-managed"
GRACE_KEY = "mcp_optional_startup_grace_ms"
GRACE_MS = 15000
STARTUP_TIMEOUT_SEC = 60
TOOL_TIMEOUT_SEC = 600
REA_TOOL_TIMEOUT_SEC = 900
#: PWEH 서버에 넘기는 환경 변수 이름 (Codex env_vars — 표시용)
PWEH_ENV_VARS = ("WSL_DISTRO_NAME",)
PWEH_PREFIX = "pweh-"
REA = "rea"
NAMESPACE_PREFIX = "mcp__pweh_"
DIRECT_CHOICES = ("all", "case", "none")
SCOPES = ("project", "global")
CLIENTS = ("codex", "claude", "all")
#: Codex 가 MCP 서버에 물려주는 환경 변수 (rmcp-client utils.rs DEFAULT_ENV_VARS — macOS 전용 __CF_USER_TEXT_ENCODING 제외)
CODEX_LIKE_ENV = ("HOME", "LOGNAME", "PATH", "SHELL", "USER", "LANG", "LC_ALL", "TERM", "TMPDIR", "TZ")
HOME_LABELS = ("cli", "desktop-wsl", "explicit")
WINDOWS_PROFILE_ENV = "PWEH_WINDOWS_PROFILE"
#: Codex 서버 이름 규칙
SERVER_NAME_RE = re.compile(r"^[a-zA-Z0-9_:@/.-]+$")
_TOOL_NAME_RE = re.compile(r"^[A-Za-z0-9_.-]+$")
_WIN_ABS_RE = re.compile(r"^[A-Za-z]:\\")
#: 데스크톱 앱 WSL 모드 설정 ([desktop] 표)
DESKTOP_WSL_KEY = "runCodexInWindowsSubsystemForLinux"
#: Windows 사용자 프로필을 읽는 고정 PowerShell 스크립트 (읽기만 한다. 출력은 UTF-8 — 한글 사용자 이름도 깨지지 않게)
PS_USER_PROFILE = ("$ProgressPreference='SilentlyContinue';$ErrorActionPreference='Stop';"
                   "[Console]::OutputEncoding=[System.Text.Encoding]::UTF8;"
                   "[Environment]::GetFolderPath('UserProfile')")
PS_TIMEOUT_S = 20.0
#: mcp-check 가 쓰는 MCP 프로토콜 버전 (Codex 0.162.0 의 rmcp 와 같음)
MCP_PROTOCOL = "2025-06-18"

Say = Callable[[str], None]


class ClientConfigError(PwehError):
    """설정 파일을 안전하게 고칠 수 없다 (올바르지 않은 TOML, 예상 밖 구조, 쓰기 실패). 아무것도 쓰지 않는다."""

    code = "client_config_error"


# ---------------------------------------------------------------------------
# 생성: 서버 표·이름공간·REA enabled_tools
# ---------------------------------------------------------------------------


def namespace(server: str) -> str:
    """Codex 의 MCP 도구 이름공간 (서버 이름의 '-' 는 '_' 로 바뀐다): 'pweh-case' → 'mcp__pweh_case'."""
    return "mcp__" + server.replace("-", "_")


def direct_namespaces(server_names: Iterable[str], direct: str) -> list[str]:
    """``--direct`` 값 → direct_only_tool_namespaces. all = PWEH 서버 전부, case = pweh-case 만, none = 없음 (REA 는 넣지 않는다)."""
    names = [n for n in server_names if n.startswith(PWEH_PREFIX)]
    if direct == "all":
        return [namespace(n) for n in names]
    if direct == "case":
        return [namespace("pweh-case")] if "pweh-case" in names else []
    if direct == "none":
        return []
    raise ClientConfigError(f"알 수 없는 --direct 값: {direct} (가능: {', '.join(DIRECT_CHOICES)})")


def rea_enabled_tools(settings_path: Path) -> tuple[list[str] | None, str | None]:
    """``.claude/settings.json`` 의 ``mcp__rea__*`` 허용(allow)·확인(ask) 항목 → REA ``enabled_tools`` (파일 순서, 중복 제거).

    돌려주는 값: (도구 이름 목록, 경고). 목록이 None 이면 enabled_tools 를 쓰지 않는다 — 파일이 없거나, 항목이 없거나,
    ``mcp__rea__*`` 같은 와일드카드가 있을 때(빈 목록은 REA 도구를 모두 끄므로 만들지 않는다). deny 항목은 뺀다.
    """
    try:
        data = json.loads(Path(settings_path).read_text(encoding="utf-8"))
    except FileNotFoundError:
        return None, f"{settings_path} 가 없어 REA enabled_tools 를 만들지 않았다 (REA 도구 207개가 모두 보인다)"
    except (OSError, ValueError) as exc:
        return None, f"{settings_path} 를 읽지 못해 REA enabled_tools 를 만들지 않았다: {exc}"
    perms = data.get("permissions") if isinstance(data, dict) else None
    perms = perms if isinstance(perms, dict) else {}
    prefix = "mcp__rea__"
    deny = {e[len(prefix):] for e in perms.get("deny") or [] if isinstance(e, str) and e.startswith(prefix)}
    out: list[str] = []
    for group in ("allow", "ask"):
        for entry in perms.get(group) or []:
            if not isinstance(entry, str):
                continue
            if entry in ("mcp__rea", "mcp__rea__*"):
                return None, f"{settings_path} 에 {entry} 가 있어 REA enabled_tools 를 쓰지 않는다 (모든 도구)"
            if not entry.startswith(prefix):
                continue
            tool = entry[len(prefix):]
            if tool and tool not in out and tool not in deny and _TOOL_NAME_RE.match(tool):
                out.append(tool)
    if not out:
        return None, f"{settings_path} 에 mcp__rea__* 항목이 없어 REA enabled_tools 를 만들지 않았다 (REA 도구 207개가 모두 보인다)"
    return out, None


def codex_server_specs(servers: Mapping[str, Mapping[str, Any]], repo: Path, *, rea_tools: Sequence[str] | None) -> dict[str, dict[str, Any]]:
    """``cli.build_mcp_servers`` 결과 → Codex ``[mcp_servers.<이름>]`` 표 내용 (키 순서 그대로 쓴다. env 는 마지막 — 하위 표가 된다)."""
    out: dict[str, dict[str, Any]] = {}
    for name, s in servers.items():
        if not SERVER_NAME_RE.match(name):
            raise ClientConfigError(f"Codex 서버 이름으로 쓸 수 없다: {name!r} (^[a-zA-Z0-9_:@/.-]+$)")
        spec: dict[str, Any] = {"command": str(s["command"]), "args": [str(a) for a in s.get("args") or []], "cwd": str(repo)}
        if name == REA:
            spec["startup_timeout_sec"] = STARTUP_TIMEOUT_SEC
            spec["tool_timeout_sec"] = REA_TOOL_TIMEOUT_SEC
            if rea_tools:
                spec["enabled_tools"] = list(rea_tools)
        else:
            spec["env_vars"] = list(PWEH_ENV_VARS)
            spec["startup_timeout_sec"] = STARTUP_TIMEOUT_SEC
            spec["tool_timeout_sec"] = TOOL_TIMEOUT_SEC
        env = {str(k): str(v) for k, v in (s.get("env") or {}).items()}
        if env:
            spec["env"] = env
        out[name] = spec
    return out


def _array(values: Sequence[Any], multiline: bool) -> Any:
    from tomlkit import array

    a = array()
    a.extend(list(values))
    if multiline:
        a.multiline(True)
    return a


def _server_table(spec: Mapping[str, Any]) -> Any:
    """서버 표 (머리 주석 ``# pweh-managed``, 목록은 길면 여러 줄, env 는 하위 표 ``[mcp_servers.<이름>.env]``)."""
    from tomlkit import nl, table

    t = table()
    t.comment(MANAGED_MARK)
    for k, v in spec.items():  # 값 먼저 (하위 표 뒤에 온 값은 그 하위 표에 속하게 되므로)
        if not isinstance(v, Mapping):
            t.add(k, _array(v, len(v) > 2) if isinstance(v, list) else v)
    subs = [(k, v) for k, v in spec.items() if isinstance(v, Mapping) and v]
    for k, v in subs:  # env 와 (읽어 온 설정의) tools 같은 하위 표
        sub = table()
        for kk, vv in v.items():
            sub.add(kk, vv)
        sub.add(nl())
        t.add(k, sub)
    if not subs:
        t.add(nl())
    return t


def _servers_only_text(specs: Mapping[str, Mapping[str, Any]]) -> str:
    """서버 표만 든 설정 (mcp-check --deep 의 임시 CODEX_HOME 용)."""
    import tomlkit

    doc = tomlkit.document()
    ms = tomlkit.table(True)
    for name, spec in specs.items():
        ms.add(name, _server_table(spec))
    doc.add("mcp_servers", ms)
    return tomlkit.dumps(doc).rstrip() + "\n"


def project_header(repo: Path, options: Mapping[str, Any], *, preview: bool) -> list[str]:
    """프로젝트 설정의 머리 주석 줄들 (생성 결과에 시각을 넣지 않는다 — 같은 입력이면 같은 바이트)."""
    opts = json.dumps(dict(options), ensure_ascii=False, sort_keys=True)
    if preview:
        return [
            "# Codex 프로젝트 설정 미리 보기 (pweh mcp-config --client codex)",
            f"# 쓰기: pweh mcp-config --client codex --write  → {repo}/.codex/config.toml (pweh 가 만들고 관리하는 파일)",
            "#       사용자 config.toml 에 병합: pweh mcp-config --client codex --write --scope global",
            "# Codex 는 이 저장소를 신뢰할 때만 프로젝트 설정을 읽는다 → pweh codex-trust",
            "# 이 내용을 기존 config.toml 끝에 손으로 덧붙이지 말 것: 같은 표가 두 번 생기면 Codex 가 시작하지 않고,",
            "# 표 뒤에 붙은 최상위 키는 앞 표 안으로 들어간다.",
            OPTIONS_PREFIX + opts,
        ]
    return [
        PROJECT_MARKER + " — pweh mcp-config --client codex --write 가 만든다. 고치면 다음 생성 때 백업 뒤 바뀐다.",
        f"# Codex 는 이 저장소를 신뢰할 때만 이 파일을 읽는다: pweh codex-trust ([projects.\"{repo}\"] trust_level = \"trusted\").",
        OPTIONS_PREFIX + opts,
    ]


def render_project_config(specs: Mapping[str, Mapping[str, Any]], direct_ns: Sequence[str], header: Sequence[str]) -> str:
    """프로젝트 설정 문서. 순서: 머리 주석 → 최상위 grace → [features.code_mode] → [mcp_servers.pweh-*] → [mcp_servers.rea]."""
    import tomlkit
    from tomlkit import nl, table

    doc = tomlkit.document()
    for line in header:
        doc.add(tomlkit.comment(line[1:].lstrip() if line.startswith("#") else line))
    doc.add(GRACE_KEY, GRACE_MS)
    doc.add(nl())
    if direct_ns:
        features = table(True)
        cm = table()
        cm.add("direct_only_tool_namespaces", _array(direct_ns, True))
        cm.add(nl())
        features.add("code_mode", cm)
        doc.add("features", features)
    ms = table(True)
    ordered = [n for n in specs if n != REA] + [n for n in specs if n == REA]
    for name in ordered:
        ms.add(name, _server_table(specs[name]))
    doc.add("mcp_servers", ms)
    return tomlkit.dumps(doc).rstrip() + "\n"


def expected_project_dict(specs: Mapping[str, Mapping[str, Any]], direct_ns: Sequence[str]) -> dict[str, Any]:
    out: dict[str, Any] = {GRACE_KEY: GRACE_MS}
    if direct_ns:
        out["features"] = {"code_mode": {"direct_only_tool_namespaces": list(direct_ns)}}
    out["mcp_servers"] = {n: copy.deepcopy(dict(s)) for n, s in specs.items()}
    return out


def read_options(text: str | None) -> dict[str, Any] | None:
    """프로젝트 설정의 ``# pweh-options: {...}`` 줄 (없거나 깨졌으면 None)."""
    for line in (text or "").splitlines()[:12]:
        if line.startswith(OPTIONS_PREFIX):
            try:
                v = json.loads(line[len(OPTIONS_PREFIX):])
            except ValueError:
                return None
            return v if isinstance(v, dict) else None
    return None


def is_pweh_project_file(text: str | None) -> bool:
    return bool(text) and str(text).startswith(PROJECT_MARKER)


def _digest(text: str) -> str:
    import hashlib

    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _split_digest(text: str) -> tuple[str, str | None]:
    """(지문 줄을 뺀 내용, 적힌 지문). 지문 줄은 머리 주석(앞 12줄) 안에서만 찾는다."""
    lines = text.split("\n")
    for i, line in enumerate(lines[:12]):
        if line.startswith(DIGEST_PREFIX):
            return "\n".join(lines[:i] + lines[i + 1:]), line[len(DIGEST_PREFIX):].strip()
    return text, None


def seal_project_text(text: str) -> str:
    """프로젝트 설정 내용(LF)의 둘째 줄에 내용 지문 줄을 넣는다 (같은 입력이면 같은 바이트)."""
    first, _, rest = text.partition("\n")
    return f"{first}\n{DIGEST_PREFIX}{_digest(text)}\n{rest}"


def project_file_state(text: str | None) -> str:
    """기존 프로젝트 설정의 상태: 'absent' | 'empty' | 'foreign'(pweh 표식 없음) | 'pweh'(pweh 가 쓴 그대로) | 'edited'(표식은 있으나
    지문이 없거나 맞지 않음 — 사람이 고쳤거나 지문 없이 만든 파일). 'foreign'·'edited' 는 다시 만들기 전에 백업한다."""
    if text is None:
        return "absent"
    if not text.strip():
        return "empty"
    if not is_pweh_project_file(text):
        return "foreign"
    body, recorded = _split_digest(text)
    return "pweh" if recorded is not None and _digest(body) == recorded else "edited"


def _missing_paths(old: Mapping[str, Any], new: Mapping[str, Any], prefix: str = "") -> list[str]:
    """old 에 있고 new 에 없는 표·키의 점 경로 (값은 넣지 않는다 — 비밀값이 출력에 나오지 않게)."""
    out: list[str] = []
    for k, v in old.items():
        path = f"{prefix}{k}"
        if k not in new:
            out.append(path)
        elif isinstance(v, Mapping) and isinstance(new[k], Mapping):
            out += _missing_paths(v, new[k], path + ".")
    return out


def _dropped_note(old_text: str | None, new_text: str, *, limit: int = 12) -> str | None:
    """새 내용에 없어 백업에만 남을 표·키 (경로만). 기존 내용이 올바른 TOML 이 아니면 그렇다고만 알린다."""
    import tomlkit
    from tomlkit.exceptions import TOMLKitError

    try:
        old = tomlkit.parse(old_text or "").unwrap()
    except (TOMLKitError, ValueError):
        return "기존 내용이 올바른 TOML 이 아니다 (백업에만 남는다)"
    gone = _missing_paths(old, tomlkit.parse(new_text).unwrap())
    if not gone:
        return None
    more = f" 외 {len(gone) - limit}개" if len(gone) > limit else ""
    return "새 내용에 없어 백업에만 남는 표·키: " + ", ".join(gone[:limit]) + more


# ---------------------------------------------------------------------------
# TOML 파일 읽기·쓰기 (계획 → 확인 → 적용)
# ---------------------------------------------------------------------------


@dataclasses.dataclass
class TomlFile:
    """읽은 설정 파일. ``text`` 는 줄 끝을 LF 로 바꾸고 BOM 을 뗀 내용(파일이 없으면 None)."""

    raw: bytes | None
    text: str | None
    crlf: bool = False
    bom: bool = False
    mode: int | None = None

    @property
    def exists(self) -> bool:
        return self.raw is not None


def read_toml_file(path: Path, *, strict: bool = True) -> TomlFile:
    """설정 파일을 읽는다. strict 면 UTF-8 이 아닐 때 ClientConfigError (고치지 않는다)."""
    try:
        raw = Path(path).read_bytes()
        mode = stat.S_IMODE(os.stat(path).st_mode)
    except FileNotFoundError:
        return TomlFile(None, None)
    except IsADirectoryError as exc:
        raise ClientConfigError(f"{path} 가 파일이 아니라 디렉터리다") from exc
    except OSError as exc:
        raise ClientConfigError(f"{path} 를 읽지 못함: {exc}") from exc
    body = raw[3:] if raw.startswith(b"\xef\xbb\xbf") else raw
    try:
        text = body.decode("utf-8")
    except UnicodeDecodeError as exc:
        if strict:
            raise ClientConfigError(f"{path} 가 UTF-8 이 아니라서 고치지 않는다 (TOML 은 UTF-8)", hint="파일을 UTF-8 로 저장한 뒤 다시 실행") from exc
        text = body.decode("utf-8", "replace")
    return TomlFile(raw, text.replace("\r\n", "\n"), crlf="\r\n" in text, bom=raw.startswith(b"\xef\xbb\xbf"), mode=mode)


def encode_text(text: str, *, crlf: bool, bom: bool) -> bytes:
    """LF 내용 → 파일 바이트 (원래 파일이 CRLF 면 CRLF, BOM 이 있었으면 BOM)."""
    if crlf:
        text = text.replace("\r\n", "\n").replace("\n", "\r\n")
    data = text.encode("utf-8")
    return b"\xef\xbb\xbf" + data if bom else data


def parse_toml(text: str, where: str) -> Any:
    """tomlkit 문서. 올바른 TOML 이 아니면 ClientConfigError (중복 표·중복 키도 거부한다 — Codex 와 같음)."""
    import tomlkit
    from tomlkit.exceptions import TOMLKitError

    try:
        return tomlkit.parse(text)
    except (TOMLKitError, ValueError) as exc:
        hint = "파일을 고친 뒤 다시 실행한다 (아무것도 쓰지 않았다)"
        if "already exists" in str(exc) or "Redefinition" in str(exc):
            hint = ("같은 표나 키가 두 번 있다 (Codex 도 이 파일로는 시작하지 않는다). 예전 안내대로 pweh mcp-config --client codex 출력을 "
                    "두 번 덧붙였다면 [mcp_servers.pweh-*]·[mcp_servers.rea] 한 벌을 지운 뒤 다시 실행한다 (아무것도 쓰지 않았다)")
        raise ClientConfigError(f"{where} 가 올바른 TOML 이 아니라서 고치지 않는다: {exc}", hint=hint) from exc


def _finish(text: str) -> str:
    return text.rstrip() + "\n"


def resolve_target(path: Path) -> Path:
    """심볼릭 링크면 실제 대상 파일 (dotfiles 링크를 일반 파일로 바꾸지 않는다)."""
    p = Path(path)
    return Path(os.path.realpath(p)) if p.is_symlink() else p


_HEADER_RE = re.compile(r"^\s*\[\[?\s*(.*?)\s*\]\]?\s*(?:#.*)?$")
_KEY_RE = re.compile(r"""^(\s*)((?:"(?:[^"\\]|\\.)*"|'[^']*'|[A-Za-z0-9_-]+)(?:\s*\.\s*(?:"(?:[^"\\]|\\.)*"|'[^']*'|[A-Za-z0-9_-]+))*)\s*=""")


def _key_parts(dotted: str) -> list[str]:
    """'mcp_servers."pweh-x".env' → ['mcp_servers', 'pweh-x', 'env'] (diff 가리기용 — 정확한 TOML 해석은 아니다)."""
    return [p.strip().strip("\"'") for p in re.findall(r'"(?:[^"\\]|\\.)*"|\'[^\']*\'|[^.]+', dotted)]


def _mask_line(line: str) -> str:
    """바뀌지 않는 줄의 값 가리기: 표 머리·빈 줄은 그대로, 주석은 '# …', 키는 이름만 남기고 값은 '…'."""
    s = line.strip()
    if not s or s.startswith("["):
        return line
    if s.startswith("#"):
        return line[: len(line) - len(line.lstrip())] + "# …"
    m = _KEY_RE.match(line)
    return f"{m.group(1)}{m.group(2)} = …" if m else line[: len(line) - len(line.lstrip())] + "…"


def _line_tables(lines: Sequence[str]) -> list[list[str]]:
    """줄마다 그 줄이 속한 표 경로 (마지막으로 본 표 머리)."""
    cur: list[str] = []
    out = []
    for line in lines:
        m = _HEADER_RE.match(line) if line.lstrip().startswith("[") else None
        if m:
            cur = _key_parts(m.group(1))
        out.append(cur)
    return out


def _secret_line(table: Sequence[str], line: str) -> bool:
    """env·http_headers 표 안의 줄이거나 그런 키(env = { … }, env.TOKEN = …)인가."""
    if any(p in SECRET_TABLE_KEYS for p in table):
        return True
    m = _KEY_RE.match(line)
    return bool(m) and any(p in SECRET_TABLE_KEYS for p in _key_parts(m.group(2)))


def _unified_range(start: int, stop: int) -> str:
    length = stop - start
    if length == 1:
        return f"{start + 1}"
    return f"{start + 1 if length else start},{length}"


def masked_diff(a: Sequence[str], b: Sequence[str], fromfile: str, tofile: str, n: int = 3) -> str:
    """사용자 설정용 unified diff: 바뀌지 않는 줄(문맥)은 값을 가리고(표 머리는 그대로), 지워지는 줄은 env·http_headers 안이면 값을 가린다.
    더해지는 줄은 pweh 가 만든 값이라 그대로 보여 준다. 사용자 config.toml 의 다른 서버 토큰 같은 값이 화면·로그에 나오지 않게 한다."""
    tables = _line_tables(a)
    out: list[str] = []
    for group in difflib.SequenceMatcher(None, list(a), list(b), autojunk=False).get_grouped_opcodes(n):
        if not out:
            out += [f"--- {fromfile}", f"+++ {tofile}"]
        first, last = group[0], group[-1]
        out.append(f"@@ -{_unified_range(first[1], last[2])} +{_unified_range(first[3], last[4])} @@")
        for tag, i1, i2, j1, j2 in group:
            if tag == "equal":
                out += [" " + _mask_line(line) for line in a[i1:i2]]
                continue
            if tag in ("replace", "delete"):
                out += ["-" + (_mask_line(a[i]) if _secret_line(tables[i], a[i]) else a[i]) for i in range(i1, i2)]
            if tag in ("replace", "insert"):
                out += ["+" + line for line in b[j1:j2]]
    return "\n".join(out)


@dataclasses.dataclass
class FileChange:
    """계획한 파일 변경 하나. ``apply_change`` 전에 새 내용은 이미 다시 읽어 확인했다."""

    path: Path            # 쓸 파일 (심볼릭 링크면 실제 대상)
    display: str          # 보여 줄 경로
    old: TomlFile
    new_text: str         # LF
    backup: bool          # 바꿀 때 백업할지
    new_mode: int         # 새 파일의 권한
    dir_mode: int = 0o755  # 디렉터리를 새로 만들 때의 권한 (Codex 홈은 0o700)
    out_crlf: bool = False
    out_bom: bool = False
    label: str = ""
    notes: list[str] = dataclasses.field(default_factory=list)
    mask: bool = True     # diff 의 문맥 값을 가린다 (사용자 설정). pweh 가 만드는 프로젝트 설정만 False

    @property
    def new_bytes(self) -> bytes:
        return encode_text(self.new_text, crlf=self.out_crlf, bom=self.out_bom)

    @property
    def changed(self) -> bool:
        return self.old.raw != self.new_bytes

    def diff(self) -> str:
        a = (self.old.text or "").splitlines()
        b = self.new_text.splitlines()
        src = f"{self.display} (현재)" if self.old.exists else "/dev/null"
        dst = f"{self.display} (pweh)"
        if self.mask:
            return masked_diff(a, b, src, dst)
        return "\n".join(difflib.unified_diff(a, b, fromfile=src, tofile=dst, lineterm=""))


def _utc_stamp() -> str:
    return _dt.datetime.now(_dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def backup_file(path: Path) -> Path:
    """``<이름>.bak-pweh-<UTC 시각>`` 으로 복사 (콜론 없음 — drvfs 에서도 된다. 이름이 있으면 -1, -2 …).

    처음부터 0600 으로 만든 뒤(비밀값이 든 0600 설정의 사본이 잠깐이라도 0644 로 보이지 않게) 원본의 권한·시각을 복사한다.
    권한 복사가 안 되는 곳(drvfs 등)이면 0600 그대로 둔다. 만들지 못하면 ClientConfigError (아무것도 바꾸지 않았다).
    """
    try:
        data = Path(path).read_bytes()
    except OSError as exc:
        raise ClientConfigError(f"{path} 를 백업하려고 읽지 못함: {exc} — 아무것도 바꾸지 않았다") from exc
    base = f"{Path(path).name}.bak-pweh-{_utc_stamp()}"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    for i in range(1000):
        cand = Path(path).with_name(base if i == 0 else f"{base}-{i}")
        try:
            fd = os.open(str(cand), flags, 0o600)
        except FileExistsError:
            continue
        except OSError as exc:
            raise ClientConfigError(f"{path} 의 백업을 만들지 못함: {exc} — 아무것도 바꾸지 않았다",
                                    hint="그 디렉터리에 쓸 수 있는지(읽기 전용 디렉터리, 심볼릭 링크가 가리키는 곳) 확인한다") from exc
        try:
            with os.fdopen(fd, "wb") as fh:
                fh.write(data)
                fh.flush()
                os.fsync(fh.fileno())
        except OSError as exc:
            with contextlib.suppress(OSError):
                os.unlink(cand)
            raise ClientConfigError(f"{path} 의 백업을 쓰지 못함: {exc} — 아무것도 바꾸지 않았다") from exc
        with contextlib.suppress(OSError):
            shutil.copystat(path, cand)
        return cand
    raise ClientConfigError(f"{path} 의 백업 이름을 만들지 못함")


def atomic_write(path: Path, data: bytes, mode: int, *, dir_mode: int = 0o755, before_replace: Callable[[], None] | None = None) -> None:
    """같은 디렉터리의 임시 파일에 쓰고 fsync 한 뒤 os.replace (권한 유지 — drvfs 처럼 chmod 가 안 되는 곳은 넘어간다).

    before_replace 는 임시 파일을 다 쓴 뒤 바꾸기 바로 전에 부른다(예외를 내면 임시 파일을 지우고 바꾸지 않는다).
    """
    path = Path(path)
    path.parent.mkdir(mode=dir_mode, parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=f".{path.name}.pweh-", suffix=".tmp", dir=str(path.parent))
    try:
        with contextlib.suppress(OSError):
            os.fchmod(fd, mode)
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
        if before_replace is not None:
            before_replace()
        os.replace(tmp, path)
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(tmp)
        raise
    with contextlib.suppress(OSError):
        dfd = os.open(str(path.parent), os.O_RDONLY)
        try:
            os.fsync(dfd)
        finally:
            os.close(dfd)


def _current_bytes(path: Path) -> bytes | None:
    try:
        return Path(path).read_bytes()
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise ClientConfigError(f"{path} 를 다시 읽지 못함: {exc} — 쓰지 않았다") from exc


def apply_change(ch: FileChange) -> dict[str, Any]:
    """계획한 변경을 쓴다. 바뀔 것이 없으면 쓰지 않는다.

    순서: 읽은 뒤 그대로인지 확인 → (필요하면) 백업 → 임시 파일 → 바꾸기 직전에 다시 확인 → 원자적 교체 → 다시 읽어 쓴 내용과 같은지 확인.
    바꾸기 전에 다른 프로그램(다른 pweh·설치 스크립트, Codex 의 trust 질문, 데스크톱 앱)이 파일을 고쳤으면 쓰지 않고 방금 만든 백업도 지운다.
    바꾼 뒤 내용이 다르면(바로 그때 다른 프로그램이 씀) ClientConfigError — 종료 코드가 0 이 아니게 하고 백업 위치를 알린다.
    """
    if not ch.changed:
        return {"path": str(ch.path), "display": ch.display, "written": False, "backup": None}
    if _current_bytes(ch.path) != ch.old.raw:
        raise ClientConfigError(f"{ch.display} 가 읽은 뒤에 바뀌었다 — 쓰지 않았다", hint="다시 실행한다")
    backup = backup_file(ch.path) if ch.old.exists and ch.backup else None
    mode = ch.old.mode if ch.old.mode is not None else ch.new_mode

    def still_unchanged() -> None:
        if _current_bytes(ch.path) != ch.old.raw:
            raise ClientConfigError(f"{ch.display} 가 읽은 뒤에 바뀌었다 (다른 프로그램이 동시에 고침) — 쓰지 않았다", hint="다시 실행한다")

    try:
        atomic_write(ch.path, ch.new_bytes, mode, dir_mode=ch.dir_mode, before_replace=still_unchanged)
    except BaseException as exc:
        if backup is not None:  # 바꾸지 않았으니 방금 만든 백업은 필요 없다 (출력에도 나오지 않는다)
            with contextlib.suppress(OSError):
                os.unlink(backup)
        if isinstance(exc, OSError):
            raise ClientConfigError(f"{ch.display} 를 바꾸지 못함: {exc} — 쓰지 않았다",
                                    hint="다른 프로그램(예: 실행 중인 Codex 데스크톱 앱)이 파일을 잡고 있으면 닫고 다시 실행한다") from exc
        raise
    if _current_bytes(ch.path) != ch.new_bytes:
        raise ClientConfigError(f"{ch.display}: 바꾼 뒤 다시 읽었더니 쓴 내용과 다르다 — 다른 프로그램이 동시에 고쳤을 수 있다"
                                + (f" (바꾸기 전 백업: {backup})" if backup else ""), hint="파일을 확인한 뒤 다시 실행한다")
    return {"path": str(ch.path), "display": ch.display, "written": True, "backup": str(backup) if backup else None}


@contextlib.contextmanager
def _dir_lock(d: Path, timeout: float | None = None) -> Iterator[None]:
    """디렉터리 하나에 배타적 flock (같은 설정을 고치는 다른 pweh·설치 스크립트와 읽기부터 바꾸기까지 겹치지 않게).

    디렉터리가 없거나(새 홈 — 아직 경쟁할 파일이 없다) flock 을 쓸 수 없는 파일 시스템(drvfs 의 ENOLCK·EOPNOTSUPP 등)이면 잠그지 않고
    진행한다(바꾸기 직전·직후 확인은 그대로). 잠금 파일을 따로 만들지 않는다(Codex 홈에 파일이 남지 않게).
    """
    import errno
    import fcntl

    limit = LOCK_TIMEOUT_S if timeout is None else timeout
    try:
        fd: int | None = os.open(str(d), os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0))
    except OSError:
        fd = None
    if fd is None:
        yield
        return
    try:
        deadline = time.monotonic() + limit
        while True:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except OSError as exc:
                if exc.errno not in (errno.EWOULDBLOCK, errno.EAGAIN):
                    break  # 잠글 수 없는 파일 시스템 — 잠그지 않고 진행
                if time.monotonic() >= deadline:
                    raise ClientConfigError(f"{d} 의 설정을 다른 pweh(또는 설치 스크립트)가 고치고 있다 — {limit:.0f}초 기다렸다. 쓰지 않았다",
                                            hint="다른 pweh 가 끝난 뒤 다시 실행한다") from exc
                time.sleep(0.1)
        yield
    finally:
        os.close(fd)  # 닫으면 잠금이 풀린다


@contextlib.contextmanager
def _locked_dirs(paths: Iterable[Path], enabled: bool = True) -> Iterator[None]:
    """여러 설정 파일의 디렉터리를 정해진 순서(실제 경로 순)로 잠근다 (서로 기다리다 멈추지 않게). enabled=False 면 아무것도 안 한다."""
    with contextlib.ExitStack() as stack:
        if enabled:
            for d in sorted({os.path.realpath(os.path.dirname(os.path.realpath(p))) for p in paths}):
                stack.enter_context(_dir_lock(Path(d)))
        yield


# ---------------------------------------------------------------------------
# 사용자 config.toml 병합 (--scope global) — tomlkit 편집 + 같은 규칙의 dict 계산으로 의미 확인
# ---------------------------------------------------------------------------


def _is_table(item: Any) -> bool:
    from tomlkit.container import OutOfOrderTableProxy
    from tomlkit.items import Table

    return isinstance(item, (Table, OutOfOrderTableProxy))


def _is_inline(item: Any) -> bool:
    from tomlkit.items import InlineTable

    return isinstance(item, InlineTable)


def has_managed_mark(item: Any) -> bool:
    """표의 머리 주석(``[mcp_servers.rea] # pweh-managed``)이나 본문 주석 줄에 pweh 표식이 있는가."""
    from tomlkit.items import Comment

    trivia = getattr(item, "trivia", None)
    if trivia is not None and MANAGED_MARK in (trivia.comment or ""):
        return True
    body = getattr(getattr(item, "value", None), "body", None) or []
    for k, v in body:
        if k is None and isinstance(v, Comment) and MANAGED_MARK in v.as_string():
            return True
    return False


def rea_state(doc: Any) -> str:
    """사용자 설정의 [mcp_servers.rea]: 'absent' | 'managed'(pweh 표식) | 'user'(사용자 표 — 건드리지 않는다)."""
    ms = doc.get("mcp_servers") if hasattr(doc, "get") else None
    if ms is None or not hasattr(ms, "get") or REA not in ms:
        return "absent"
    return "managed" if has_managed_mark(ms[REA]) else "user"


def _merge_direct_list(current: Sequence[Any], wanted: Sequence[str]) -> tuple[list[Any], list[Any], list[str]]:
    """(새 목록, 뺀 것, 더한 것). 사용자 항목은 두고 지금 원하지 않는 pweh 이름공간(mcp__pweh_*)만 뺀다."""
    removed = [x for x in current if isinstance(x, str) and x.startswith(NAMESPACE_PREFIX) and x not in wanted]
    kept = [x for x in current if x not in removed]
    added = [w for w in wanted if w not in kept]
    return kept + added, removed, added


def _direct_dict(d: dict[str, Any], wanted: Sequence[str]) -> None:
    """features.code_mode.direct_only_tool_namespaces 병합 (dict 판 — tomlkit 편집 결과와 비교할 기대값)."""
    feats = d.get("features")
    if feats is None:
        if wanted:
            d["features"] = {"code_mode": {"direct_only_tool_namespaces": list(wanted)}}
        return
    cm = feats.get("code_mode")
    if cm is None:
        if wanted:
            feats["code_mode"] = {"direct_only_tool_namespaces": list(wanted)}
        return
    if isinstance(cm, bool):
        if wanted:
            feats["code_mode"] = {"enabled": cm, "direct_only_tool_namespaces": list(wanted)}
        return
    arr = cm.get("direct_only_tool_namespaces")
    if arr is None:
        if wanted:
            cm["direct_only_tool_namespaces"] = list(wanted)
        return
    new, removed, added = _merge_direct_list(arr, wanted)
    if not removed and not added:
        return
    if new:
        cm["direct_only_tool_namespaces"] = new
    else:
        del cm["direct_only_tool_namespaces"]


def _direct_doc(doc: Any, wanted: Sequence[str], notes: list[str]) -> None:
    """features.code_mode.direct_only_tool_namespaces 병합 (tomlkit 판 — 사용자 항목·주석 보존)."""
    from tomlkit import nl, table

    feats = doc.get("features")
    if feats is None:
        if wanted:
            f = table(True)
            cm = table()
            cm.add("direct_only_tool_namespaces", _array(wanted, True))
            cm.add(nl())
            f.add("code_mode", cm)
            doc["features"] = f
            notes.append(f"[features.code_mode] direct_only_tool_namespaces 추가 ({len(wanted)}개)")
        return
    if not (_is_table(feats) or _is_inline(feats)):
        raise ClientConfigError("features 가 표가 아니라서 고치지 않는다")
    cm = feats.get("code_mode")
    if cm is None or isinstance(cm, bool):
        if not wanted:
            return
        if isinstance(cm, bool):
            notes.append(f"features.code_mode = {str(bool(cm)).lower()} → [features.code_mode] enabled = {str(bool(cm)).lower()} 로 바꿈")
        if _is_inline(feats):  # 인라인 표 안에는 인라인 값만 (dict → 인라인 표, 제자리 교체)
            val: dict[str, Any] = {"enabled": bool(cm)} if isinstance(cm, bool) else {}
            val["direct_only_tool_namespaces"] = list(wanted)
            feats["code_mode"] = val
        else:
            t = table()
            if isinstance(cm, bool):
                t.add("enabled", bool(cm))
                del feats["code_mode"]
            t.add("direct_only_tool_namespaces", _array(wanted, True))
            t.add(nl())
            feats["code_mode"] = t
        notes.append(f"[features.code_mode] direct_only_tool_namespaces 추가 ({len(wanted)}개)")
        return
    if not (_is_table(cm) or _is_inline(cm)):
        raise ClientConfigError("features.code_mode 가 표도 불리언도 아니라서 고치지 않는다")
    arr = cm.get("direct_only_tool_namespaces")
    if arr is None:
        if wanted:
            cm["direct_only_tool_namespaces"] = list(wanted) if _is_inline(cm) else _array(wanted, True)
            notes.append(f"features.code_mode.direct_only_tool_namespaces 추가 ({len(wanted)}개)")
        return
    from tomlkit.items import Array

    if not isinstance(arr, Array):
        raise ClientConfigError("features.code_mode.direct_only_tool_namespaces 가 목록이 아니라서 고치지 않는다")
    new, removed, added = _merge_direct_list(list(arr.unwrap()), wanted)
    if not removed and not added:
        return
    if not new:
        del cm["direct_only_tool_namespaces"]
    else:
        for i in reversed(range(len(arr))):
            if arr[i] in removed:
                del arr[i]
        for w in added:
            arr.append(w)
    notes.append(f"features.code_mode.direct_only_tool_namespaces: 사용자 항목 유지, pweh +{len(added)} -{len(removed)}")


def _user_keys(cur: Any, spec: Mapping[str, Any]) -> dict[str, Any]:
    """기존 pweh 서버 표에서 옮겨 둘 사용자 키 (:data:`USER_SERVER_KEYS` 중 pweh 가 만들지 않는 키 — 예: REA 의 enabled_tools 는 pweh 것).

    사람이 Codex 에서 끈 서버(enabled = false)·끈 도구(disabled_tools)·도구별 승인(tools.<도구>.approval_mode)이 다시 쓸 때마다
    사라지지 않게 한다. 빈 표는 옮기지 않는다.
    """
    if not isinstance(cur, Mapping):
        return {}
    return {k: copy.deepcopy(cur[k]) for k in USER_SERVER_KEYS
            if k in cur and k not in spec and not (isinstance(cur[k], Mapping) and not cur[k])}


def _merged_spec(cur: Any, spec: Mapping[str, Any]) -> dict[str, Any]:
    return {**copy.deepcopy(dict(spec)), **_user_keys(cur, spec)}


def _servers_dict(d: dict[str, Any], specs: Mapping[str, Mapping[str, Any]], include_rea: bool, rea: str) -> None:
    ms = d.setdefault("mcp_servers", {})
    old = {k: ms.pop(k) for k in [k for k in ms if k.startswith(PWEH_PREFIX)]}
    for name, spec in specs.items():
        if name.startswith(PWEH_PREFIX):
            ms[name] = _merged_spec(old.get(name), spec)
    if rea in ("absent", "managed"):
        cur_rea = ms.pop(REA, None)
        if include_rea and REA in specs:
            ms[REA] = _merged_spec(cur_rea, specs[REA])


def _put_server_table(ms: Any, name: str, spec: Mapping[str, Any], notes: list[str] | None = None) -> str:
    """서버 표 하나를 쓴다. 돌려주는 값: 'same'(그대로 둠) | 'replaced' | 'added'.

    이미 있는 (인라인이 아닌) 표는 제자리에서 바꾼다. 지우고 끝에 다시 더하면 tomlkit 이 그 표 앞에 빈 줄을 하나 넣어
    (지운 자리만 남은 표 묶음에 처음 더하는 표) 다시 실행할 때마다 파일이 바뀌고 백업이 쌓인다.
    내용이 같고 pweh 표식이 있으면 건드리지 않는다. 인라인 표·점 키는 제자리에 표를 넣으면 뒤따르는 키가 그 표에 속할 수 있어
    지우고 끝에 더한다. 사용자 키(:func:`_user_keys`)는 옮기고, 그 밖에 새 표에 없어 빠지는 키는 notes 에 이름만 적는다.
    """
    from tomlkit.items import Table

    if name not in ms:
        ms[name] = _server_table(spec)
        return "added"
    cur = ms[name]
    cur_val = cur.unwrap() if hasattr(cur, "unwrap") else None
    full = _merged_spec(cur_val, spec)
    if has_managed_mark(cur) and cur_val == full:
        return "same"
    if notes is not None and isinstance(cur_val, Mapping):
        kept = [k for k in full if k not in spec]
        gone = sorted(str(k) for k in cur_val if k not in full)
        if kept:
            notes.append(f"[mcp_servers.{name}] 사용자 키 유지: {', '.join(kept)}")
        if gone:
            notes.append(f"[mcp_servers.{name}] 새 표에 없어 빠지는 키: {', '.join(gone)} (백업에만 남는다)")
    if not isinstance(cur, Table):
        del ms[name]
    ms[name] = _server_table(full)
    return "replaced"


def _servers_doc(doc: Any, specs: Mapping[str, Mapping[str, Any]], include_rea: bool, rea: str, notes: list[str]) -> None:
    import tomlkit

    ms = doc.get("mcp_servers")
    if ms is None:
        doc["mcp_servers"] = tomlkit.table(True)
        ms = doc["mcp_servers"]
    elif not _is_table(ms):
        raise ClientConfigError("mcp_servers 가 (인라인 표가 아닌) 표가 아니라서 고치지 않는다",
                                hint="mcp_servers 를 [mcp_servers.<이름>] 표 형식으로 바꾼 뒤 다시 실행")
    old = [k for k in list(ms.keys()) if k.startswith(PWEH_PREFIX)]
    new = [n for n in specs if n.startswith(PWEH_PREFIX)]
    for k in old:
        if k not in new:
            del ms[k]
    details: list[str] = []
    for name in new:
        _put_server_table(ms, name, specs[name], details)
    stale = sorted(set(old) - set(new))
    notes.append(f"[mcp_servers.pweh-*] {len(new)}개 " + ("교체" if old else "추가") + (f" (예전 표 제거: {', '.join(stale)})" if stale else ""))
    notes.extend(details)
    if rea == "user":
        notes.append("[mcp_servers.rea] 는 사용자 설정이라 그대로 둔다 (pweh-managed 표식 없음)")
        user_rea = ms[REA]
        if hasattr(user_rea, "get") and user_rea.get("enabled_tools") is None and user_rea.get("disabled_tools") is None:
            notes.append("  그 표에는 enabled_tools 가 없어 REA 도구 207개(tools/list 3 MB)가 모두 보인다 — pweh 가 관리하게 하려면 "
                         "그 표를 지우고 다시 실행한다 (예전 pweh mcp-config 출력을 붙여 넣은 표라면 지워도 된다)")
        return
    if include_rea and REA in specs:
        rea_notes: list[str] = []
        how = _put_server_table(ms, REA, specs[REA], rea_notes)
        if how != "same":
            notes.append("[mcp_servers.rea] " + ("교체" if how == "replaced" else "추가") + " (pweh-managed)")
            notes.extend(rea_notes)
    elif rea == "managed":
        del ms[REA]
        notes.append("[mcp_servers.rea] 제거 (--no-rea, pweh-managed 표)")


def merge_user_config(text: str | None, specs: Mapping[str, Mapping[str, Any]], direct_ns: Sequence[str], *,
                      include_rea: bool, where: str) -> tuple[str, list[str]]:
    """사용자 config.toml 에 PWEH 설정을 병합한 새 내용(LF)과 변경 설명.

    - ``[mcp_servers.pweh-*]`` 는 모두 지우고 지금 것으로 바꾼다(중복 없음 — 예전 이름의 pweh 표도 지운다).
    - ``[mcp_servers.rea]`` 는 없거나 pweh 표식이 있을 때만 관리한다(``--no-rea`` 면 표식 있는 표를 지운다).
    - ``features.code_mode.direct_only_tool_namespaces`` 는 사용자 항목을 두고 pweh 항목만 맞춘다.
    - 최상위 ``mcp_optional_startup_grace_ms`` 는 없을 때만 넣는다(첫 표 앞).
    결과는 다시 읽어 같은 규칙으로 계산한 dict 와 비교한다(최상위 키가 표 안으로 들어가거나 사용자 키가 바뀌면 ClientConfigError).
    바뀔 것이 없으면 원래 내용을 그대로 돌려준다(다시 실행해도 같은 바이트 — 쓰기·백업 없음).
    """
    import tomlkit

    doc = parse_toml(text, where) if text is not None else tomlkit.document()
    before = doc.unwrap()
    state = rea_state(doc)
    # 예전에 붙여 넣은 표: 내용이 같아도 pweh-managed 표식을 달아 둔다 (doctor 가 pweh 가 관리하는 등록으로 안다)
    unmarked = [k for k in _unmarked_pweh_tables(doc) if k in specs]
    notes: list[str] = []
    if GRACE_KEY in doc:
        cur = doc[GRACE_KEY]
        if isinstance(cur, int) and not isinstance(cur, bool) and cur < GRACE_MS:
            notes.append(f"{GRACE_KEY} = {int(cur)} 유지 (사용자 값 — 권장 {GRACE_MS}: REA 가 첫 턴에 빠질 수 있다)")
    else:
        doc[GRACE_KEY] = GRACE_MS
        notes.append(f"{GRACE_KEY} = {GRACE_MS} 추가 (첫 표 앞)")
    misplaced = _nested_key_paths(before, GRACE_KEY)
    if misplaced:
        notes.append(f"표 안에 들어간 {GRACE_KEY} 가 있다 ({', '.join(misplaced)}) — 표 뒤에 덧붙인 최상위 키는 그 표에 속한다. "
                     "Codex 는 이 값을 쓰지 않으니 손으로 지운다 (pweh 는 사용자 표를 고치지 않는다)")
    _direct_doc(doc, direct_ns, notes)  # 고칠 수 없는 구조(표가 아닌 features·mcp_servers 등)는 여기서 거부한다
    _servers_doc(doc, specs, include_rea, state, notes)
    new_text = _finish(tomlkit.dumps(doc))
    expected = copy.deepcopy(before)
    expected.setdefault(GRACE_KEY, GRACE_MS)
    _direct_dict(expected, direct_ns)
    _servers_dict(expected, specs, include_rea, state)
    if text is not None and expected == before and not unmarked:
        return text, []
    if unmarked:
        notes.append("pweh-managed 표식이 없던 PWEH 서버 표(예전에 붙여 넣은 표)에 표식을 단다: " + ", ".join(unmarked))
    _verify(new_text, expected, where)
    return new_text, notes


def _unmarked_pweh_tables(doc: Any) -> list[str]:
    """사용자 설정의 ``[mcp_servers.pweh-*]`` 중 pweh-managed 표식이 없는 표 (예전 안내대로 붙여 넣은 표)."""
    ms = doc.get("mcp_servers") if hasattr(doc, "get") else None
    if ms is None or not hasattr(ms, "items"):
        return []
    return [str(k) for k, v in ms.items() if str(k).startswith(PWEH_PREFIX) and not has_managed_mark(v)]


def _nested_key_paths(d: Mapping[str, Any], key: str, prefix: str = "") -> list[str]:
    """최상위가 아닌 곳에 있는 key 의 표 경로들 (예: 'projects./x')."""
    out = []
    for k, v in d.items():
        if isinstance(v, Mapping):
            path = f"{prefix}{k}"
            if key in v:
                out.append(path)
            out += _nested_key_paths(v, key, path + ".")
    return out


def _verify(new_text: str, expected: Mapping[str, Any], where: str) -> None:
    """새 내용을 다시 읽어 기대한 dict 와 같은지 본다 (같지 않으면 쓰지 않는다)."""
    got = parse_toml(new_text, f"{where} (새 내용)").unwrap()
    if got != expected:
        keys = sorted(set(got) ^ set(expected)) or sorted(k for k in got if got.get(k) != expected.get(k))
        raise ClientConfigError(f"{where}: 고친 내용을 다시 읽었더니 예상과 달라서 쓰지 않는다 (다른 최상위 키: {', '.join(map(str, keys))})",
                                hint="파일 구조가 특이하면 --scope project 를 쓰거나 손으로 고친다")


# ---------------------------------------------------------------------------
# 신뢰 등록 ([projects."<저장소>"] trust_level = "trusted")
# ---------------------------------------------------------------------------


def trust_key(repo: Path) -> str:
    """Codex 가 찾는 신뢰 키: 저장소의 실제 경로 (Codex 는 정규화한 cwd·프로젝트 루트·git 루트를 정확히 비교한다)."""
    return os.path.realpath(str(repo))


def trust_level(text: str | None, key: str, where: str) -> str | None:
    """사용자 설정에서 저장소의 trust_level ('trusted' | 'untrusted' | …). 파일이나 항목이 없으면 None."""
    if text is None:
        return None
    doc = parse_toml(text, where).unwrap()
    proj = doc.get("projects")
    entry = proj.get(key) if isinstance(proj, dict) else None
    lvl = entry.get("trust_level") if isinstance(entry, dict) else None
    return str(lvl) if lvl is not None else None


def add_trust(text: str | None, key: str, where: str) -> tuple[str, str]:
    """신뢰 항목을 더한 새 내용(LF)과 설명. 이미 trusted 면 원래 내용을 그대로 돌려준다. untrusted 는 trusted 로 바꾼다."""
    import tomlkit

    doc = parse_toml(text, where) if text is not None else tomlkit.document()
    before = doc.unwrap()
    projects = doc.get("projects")
    if projects is None:
        doc["projects"] = tomlkit.table(True)
        projects = doc["projects"]
    elif not (_is_table(projects) or _is_inline(projects)):
        raise ClientConfigError(f"{where}: projects 가 표가 아니라서 고치지 않는다")
    entry = projects.get(key)
    if entry is None:
        if _is_inline(projects):
            projects[key] = {"trust_level": "trusted"}
        else:
            t = tomlkit.table()
            t.add("trust_level", "trusted")
            t.add(tomlkit.nl())
            projects[key] = t
        note = "신뢰 항목 추가"
    elif not (_is_table(entry) or _is_inline(entry)):
        raise ClientConfigError(f"{where}: projects.\"{key}\" 가 표가 아니라서 고치지 않는다")
    elif entry.get("trust_level") == "trusted":
        return (text if text is not None else ""), "이미 신뢰됨"
    else:
        old = entry.get("trust_level")
        entry["trust_level"] = "trusted"
        note = f"trust_level {old!s} → trusted"
    new_text = _finish(tomlkit.dumps(doc))
    expected = copy.deepcopy(before)
    exp_projects = expected.setdefault("projects", {})
    exp_projects.setdefault(key, {})["trust_level"] = "trusted"
    _verify(new_text, expected, where)
    return new_text, note


# ---------------------------------------------------------------------------
# Codex 홈 찾기 (cli | desktop-wsl | explicit)
# ---------------------------------------------------------------------------


@dataclasses.dataclass
class CodexHome:
    """Codex 홈 하나. skipped 이면 쓰지 않는 이유(데스크톱 앱이 WSL 모드가 아님 등).

    native_windows 는 이 홈이 WSL 모드가 아닌 Windows 데스크톱 앱 홈과 같은 디렉터리일 때 그 이유다(예: ~/.codex 가 Windows 프로필의
    .codex 를 가리키는 링크). trust 항목은 더해도 되지만, 리눅스 경로의 서버(--scope global)는 그 앱이 실행하지 못해 자동 감지로는 쓰지 않는다.
    """

    path: Path
    label: str
    source: str
    skipped: str | None = None
    native_windows: str | None = None

    @property
    def config(self) -> Path:
        return self.path / "config.toml"

    def as_dict(self) -> dict[str, Any]:
        return {"path": str(self.path), "config": str(self.config), "label": self.label, "source": self.source, "skipped": self.skipped,
                "native_windows": self.native_windows}


_PROFILE_CACHE: dict[str, tuple[Path | None, str]] = {}


def _as_wsl_dir(value: str) -> Path | None:
    v = value.strip()
    if _WIN_ABS_RE.match(v):
        from . import hostenv

        conv = hostenv.windows_path_to_wsl(v)
        v = conv or ""
    if not v.startswith("/"):
        return None
    p = Path(v)
    return p if p.is_dir() else None


def windows_profile(report: Mapping[str, Any] | None = None) -> tuple[Path | None, str]:
    """Windows 사용자 프로필 디렉터리(WSL 경로)와 출처(찾지 못하면 None 과 이유).

    순서: ``PWEH_WINDOWS_PROFILE``(명시 — WSL 경로 또는 ``C:\\Users\\…``) → ``USERPROFILE``(WSLENV 로 넘어온 WSL 경로) →
    interop: WSL 이고 interop 을 쓸 수 있을 때(설정 ``hostenv.disable: [interop]`` 을 따른다) hostenv 가 실제 경로를 확인한
    System32 powershell.exe 로 고정 스크립트 :data:`PS_USER_PROFILE` 만 실행한다(cwd 는 C: drvfs 마운트, 시간 제한).
    interop 결과는 프로세스 동안 기억한다. 시험은 이 함수를 monkeypatch 한다.
    """
    override = os.environ.get(WINDOWS_PROFILE_ENV, "").strip()
    if override:
        p = _as_wsl_dir(override)
        return (p, WINDOWS_PROFILE_ENV) if p else (None, f"{WINDOWS_PROFILE_ENV} 가 가리키는 디렉터리가 없음")
    up = os.environ.get("USERPROFILE", "").strip()
    if up.startswith("/") and os.path.isdir(up):
        return Path(up), "USERPROFILE"
    if "interop" not in _PROFILE_CACHE:
        _PROFILE_CACHE["interop"] = _interop_profile(report)
    return _PROFILE_CACHE["interop"]


def _interop_profile(report: Mapping[str, Any] | None) -> tuple[Path | None, str]:
    from . import hostenv

    try:
        rep = report if report is not None else hostenv.detect(smoke=False)
        if not hostenv.is_wsl(rep):
            return None, "WSL 이 아님"
        if not hostenv.interop_usable(rep):
            return None, "WSL interop 을 쓸 수 없어 Windows 프로필을 찾지 못함 (" + str(hostenv.interop_reason(rep) or "이유 모름") + \
                f") — {WINDOWS_PROFILE_ENV} 나 --codex-home 으로 지정"
        ps = hostenv.powershell_path()
        c_root = hostenv.drvfs_root("C")
        if not ps or not c_root:
            return None, "System32 powershell.exe 또는 C: 드라이브 마운트를 찾지 못해 Windows 프로필을 모름"
        out = subprocess.run([ps, "-NoProfile", "-NonInteractive", "-Command", PS_USER_PROFILE], cwd=c_root, stdin=subprocess.DEVNULL,
                             stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=PS_TIMEOUT_S, check=False)
    except subprocess.TimeoutExpired:
        return None, "powershell.exe 시간 초과 — Windows 프로필을 모름"
    except (OSError, ValueError, subprocess.SubprocessError) as exc:
        return None, f"Windows 프로필을 찾지 못함: {exc}"
    lines = out.stdout.decode("utf-8", "replace").strip().splitlines() if out.returncode == 0 else []
    win = lines[0].strip() if lines else ""
    if not _WIN_ABS_RE.match(win):
        return None, "powershell.exe 가 Windows 프로필 경로를 돌려주지 않음"
    wsl = hostenv.windows_path_to_wsl(win)
    if not wsl or not os.path.isdir(wsl):
        return None, "Windows 프로필을 WSL 경로로 바꾸지 못함"
    return Path(wsl), "interop (powershell.exe)"


def _same_dir(a: Path, b: Path) -> bool:
    try:
        if a.exists() and b.exists():
            return os.path.samefile(a, b)
    except OSError:
        pass
    return os.path.realpath(a) == os.path.realpath(b)


def desktop_home(report: Mapping[str, Any] | None = None) -> tuple[CodexHome | None, str | None]:
    """Windows 데스크톱 앱 홈(<Windows 프로필>/.codex). (홈 또는 None, 참고 문구).

    프로필에 ``.codex`` 가 없으면 (None, None). config.toml 이 없거나 깨졌거나 ``[desktop] runCodexInWindowsSubsystemForLinux = true``
    가 아니면 skipped 로 돌려준다(native Windows Codex 는 리눅스 경로의 PWEH 서버를 실행할 수 없다).
    """
    profile, why = windows_profile(report)
    if profile is None:
        return None, (why if why and why != "WSL 이 아님" else None)
    home = profile / ".codex"
    if not home.is_dir():
        return None, None
    src = f"Windows 프로필 ({why})"
    cfg = home / "config.toml"
    if not cfg.is_file():
        return CodexHome(home, "desktop-wsl", src, skipped="config.toml 없음 (Codex 데스크톱 앱 설정 전)"), None
    try:
        tf = read_toml_file(cfg)
        doc = parse_toml(tf.text or "", str(cfg)).unwrap()
    except ClientConfigError as exc:
        return CodexHome(home, "desktop-wsl", src, skipped=f"config.toml 을 읽지 못함 — {exc.message}"), None
    desk = doc.get("desktop")
    if not (isinstance(desk, dict) and desk.get(DESKTOP_WSL_KEY) is True):
        return CodexHome(home, "desktop-wsl", src,
                         skipped=f"데스크톱 앱이 WSL 모드가 아님 ([desktop] {DESKTOP_WSL_KEY} = true 아님) — "
                                 "native Windows Codex 는 리눅스 경로의 PWEH 서버를 실행할 수 없다"), None
    return CodexHome(home, "desktop-wsl", src), None


def scan_codex_homes(explicit: Sequence[str] | None = None, *, report: Mapping[str, Any] | None = None) -> tuple[list[CodexHome], list[str]]:
    """Codex 홈 목록(건너뛴 홈 포함)과 참고 문구.

    ``explicit``(``--codex-home``)이 있으면 그것만 쓴다(label explicit). 빈 값은 거부하고(지금 디렉터리를 홈으로 쓰지 않게), 없는 디렉터리는
    이름이 ``.codex`` 일 때만 받는다(오타로 새 홈을 만들지 않게 — 다른 이름의 새 홈은 먼저 mkdir 한다). 없으면(auto) 후보마다 따로 본다:
    $CODEX_HOME (설정돼 있으면) = cli, ``~/.codex`` = cli (디렉터리가 있으면. 아직 없으면 codex 가 PATH 에 있고 $CODEX_HOME 이 없거나
    데스크톱 홈일 때만), Windows 데스크톱 앱 홈 = desktop-wsl. 실제 경로가 같으면 하나로 친다. $CODEX_HOME 이 데스크톱 홈이면
    (데스크톱 에이전트 안에서 실행한 경우 — WSLENV 로 넘어온다) desktop-wsl 로 보고, 그때도 WSL 의 Codex CLI 가 쓰는 ``~/.codex`` 를 찾는다.
    CLI 홈이 건너뛴 데스크톱 홈(WSL 모드 아님)과 같은 디렉터리면 그 이유를 참고 문구와 ``native_windows`` 로 남긴다.
    """
    if explicit:
        out: list[CodexHome] = []
        for raw in explicit:
            if not str(raw).strip():
                raise ClientConfigError("--codex-home 값이 비어 있다 — 지금 디렉터리를 Codex 홈으로 쓰지 않는다",
                                        hint="Codex 홈 디렉터리 경로를 준다 (예: --codex-home ~/.codex)")
            p = Path(os.path.abspath(os.path.expanduser(str(raw))))
            if p.exists() and not p.is_dir():
                raise ClientConfigError(f"--codex-home {p} 가 디렉터리가 아니다")
            if not p.exists() and p.name != ".codex":
                raise ClientConfigError(f"--codex-home {p} 가 없다 — 경로에 오타가 없는지 확인한다",
                                        hint="새 Codex 홈이면 먼저 만든다 (mkdir -p <디렉터리>). 이름이 .codex 인 디렉터리는 없어도 만든다")
            if any(_same_dir(p, h.path) for h in out):
                continue
            out.append(CodexHome(p, "explicit", "--codex-home"))
        return out, []
    homes: list[CodexHome] = []
    notes: list[str] = []
    desk, note = desktop_home(report)
    if note:
        notes.append(note)
    env_home = os.environ.get("CODEX_HOME", "").strip()
    env_path = Path(os.path.abspath(os.path.expanduser(env_home))) if env_home else None
    env_is_desktop = env_path is not None and desk is not None and _same_dir(env_path, desk.path)
    if env_path is not None:
        homes.append(CodexHome(env_path, "cli", "$CODEX_HOME"))
    dflt = Path.home() / ".codex"
    if not any(_same_dir(dflt, h.path) for h in homes):
        if dflt.is_dir():
            homes.append(CodexHome(dflt, "cli", "~/.codex"))
        elif shutil.which("codex") and (env_path is None or env_is_desktop):
            # 아직 없는 ~/.codex 는 CLI 가 실제로 쓸 홈일 때만 (사용자가 셸에서 CODEX_HOME 을 따로 정했으면 CLI 는 ~/.codex 를 읽지 않는다)
            homes.append(CodexHome(dflt, "cli", "~/.codex (아직 없음 — codex 가 PATH 에 있음)"))
    if desk is not None:
        dup = [h for h in homes if _same_dir(h.path, desk.path)]
        if not dup:
            homes.append(desk)
        elif desk.skipped is None:
            homes = [h for h in homes if h not in dup]
            desk.source = f"{dup[0].source} = {desk.source}"
            homes.append(desk)
        else:  # 같은 디렉터리를 쓰는 데스크톱 앱이 WSL 모드가 아니다 — 이유를 버리지 않는다
            for h in dup:
                h.native_windows = desk.skipped
            notes.append(f"{dup[0].path} ({dup[0].source}) 는 Windows 데스크톱 앱의 Codex 홈({desk.path})과 같은 디렉터리다 — {desk.skipped}. "
                         "trust 항목은 더하지만 --scope global 은 자동 감지로 이 홈에 서버를 쓰지 않는다 (쓰려면 --codex-home 으로 직접 지정)")
    return homes, notes


# ---------------------------------------------------------------------------
# 계획 (모든 대상의 새 내용을 먼저 만든다 — 하나라도 실패하면 아무것도 쓰지 않는다)
# ---------------------------------------------------------------------------


def project_path(repo: Path) -> Path:
    return Path(repo) / ".codex" / "config.toml"


def _refuse_project_links(repo: Path, path: Path) -> None:
    """<저장소>/.codex 나 그 config.toml 이 심볼릭 링크이거나 실제 위치가 저장소의 .codex 밖이면 쓰지 않는다.

    링크를 따라가면 가리키는 다른 파일(예: 사용자 Codex 홈의 config.toml 전체)을 생성한 프로젝트 설정으로 통째로 바꾸게 된다.
    """
    for p in (path.parent, path):
        if p.is_symlink():
            raise ClientConfigError(f"{p} 가 심볼릭 링크라서 프로젝트 설정을 쓰지 않는다 (가리키는 곳: {os.path.realpath(p)})",
                                    hint=f"{p} 링크를 지운 뒤 다시 실행한다 — 프로젝트 설정은 pweh 가 <저장소>/.codex/config.toml 에 만드는 생성물이다")
    real, want = os.path.realpath(path), os.path.join(os.path.realpath(repo), ".codex", "config.toml")
    if real != want:
        raise ClientConfigError(f"{path} 의 실제 위치({real})가 저장소의 .codex 밖이라 쓰지 않는다")


def plan_project(repo: Path, text: str) -> FileChange:
    """프로젝트 설정 쓰기 계획. 생성한 내용은 다시 읽어 확인한다.

    기존 파일 백업: pweh 표식이 없는 파일, 그리고 표식은 있지만 내용 지문이 맞지 않는 파일(사람이 고친 파일 — 머리 주석이 약속한 대로).
    pweh 가 쓴 그대로인 파일과 빈 파일은 백업하지 않는다(다시 쓸 때마다 백업이 쌓이지 않게). 백업할 때는 새 내용에 없어
    백업에만 남을 표·키 이름을 notes 에 적는다(값은 적지 않는다).
    """
    path = project_path(repo)
    _refuse_project_links(repo, path)
    old = read_toml_file(path, strict=False)
    parse_toml(text, f"{path} (새 내용)")
    state = project_file_state(old.text)
    notes: list[str] = []
    if state == "foreign":
        notes.append("pweh 표식이 없는 기존 파일 — 쓰기 전에 백업한다")
    elif state == "edited":
        notes.append("pweh 가 만든 뒤 고친 내용이 있다(내용 지문이 맞지 않음) — 쓰기 전에 백업한다. 고친 내용은 새 파일에 남지 않는다")
    backup = state in ("foreign", "edited")
    if backup and old.text is not None and old.raw != encode_text(text, crlf=False, bom=False):
        dropped = _dropped_note(old.text, text)
        if dropped:
            notes.append(dropped)
    return FileChange(path=path, display=str(path), old=old, new_text=text, backup=backup, new_mode=0o644, label="project",
                      notes=notes, mask=False)


def plan_global(home: CodexHome, specs: Mapping[str, Mapping[str, Any]], direct_ns: Sequence[str], *, include_rea: bool) -> FileChange:
    target = resolve_target(home.config)
    old = read_toml_file(target)
    new, notes = merge_user_config(old.text, specs, direct_ns, include_rea=include_rea, where=str(home.config))
    return FileChange(path=target, display=str(home.config), old=old, new_text=new, backup=True, new_mode=0o600, dir_mode=0o700,
                      out_crlf=old.crlf, out_bom=old.bom, label=home.label, notes=notes)


def plan_trust(home: CodexHome, repo: Path) -> FileChange:
    target = resolve_target(home.config)
    old = read_toml_file(target)
    new, note = add_trust(old.text, trust_key(repo), str(home.config))
    return FileChange(path=target, display=str(home.config), old=old, new_text=new, backup=True, new_mode=0o600, dir_mode=0o700,
                      out_crlf=old.crlf, out_bom=old.bom, label=home.label, notes=[note])


def _print_changes(changes: Sequence[FileChange], say: Say, *, dry_run: bool) -> None:
    for ch in changes:
        tag = f" ({ch.label})" if ch.label else ""
        if not ch.changed:
            say(f"변경 없음: {ch.display}{tag}")
            continue
        for n in ch.notes:
            say(f"  · {n}")
        if dry_run:
            say(f"바뀔 파일: {ch.display}{tag}")
            say(ch.diff())


def apply_changes(changes: Sequence[FileChange], say: Say) -> list[dict[str, Any]]:
    results = []
    for ch in changes:
        if not ch.changed:
            continue
        r = apply_change(ch)
        results.append(r)
        tag = f" ({ch.label})" if ch.label else ""
        if r["backup"]:
            say(f"백업: {r['backup']}")
        say(f"작성: {ch.display}{tag}" + (f" → 실제 파일 {ch.path}" if str(ch.path) != ch.display else ""))
    return results


# ---------------------------------------------------------------------------
# 명령 (cli.py 가 인자를 넘긴다)
# ---------------------------------------------------------------------------


def codex_specs_for(servers: Mapping[str, Mapping[str, Any]], repo: Path, *, settings_path: Path, include_rea: bool, direct: str
                    ) -> tuple[dict[str, dict[str, Any]], list[str], list[str]]:
    """(서버 표 내용, direct 이름공간, 경고). REA enabled_tools 는 ``.claude/settings.json`` 에서 만든다."""
    warnings: list[str] = []
    rea_tools: list[str] | None = None
    if include_rea and REA in servers:
        rea_tools, warn = rea_enabled_tools(settings_path)
        if warn:
            warnings.append(warn)
    if not include_rea:
        servers = {k: v for k, v in servers.items() if k != REA}
    specs = codex_server_specs(servers, repo, rea_tools=rea_tools)
    return specs, direct_namespaces(specs, direct), warnings


def project_text(servers: Mapping[str, Mapping[str, Any]], repo: Path, *, settings_path: Path, include_rea: bool, direct: str,
                 tools_env: str | None, preview: bool = False) -> tuple[str, list[str]]:
    """프로젝트 설정 내용과 경고 (REA enabled_tools 를 만들지 못한 경우 등). 같은 입력이면 같은 바이트다."""
    specs, ns, warnings = codex_specs_for(servers, repo, settings_path=settings_path, include_rea=include_rea, direct=direct)
    options = {"direct": direct, "rea": bool(include_rea), "tools_env": tools_env}
    text = render_project_config(specs, ns, project_header(repo, options, preview=preview))
    if not preview:  # 파일로 쓰는 내용에만 지문 (사람이 고쳤는지 다음 생성 때 안다)
        text = seal_project_text(text)
    _verify(text, expected_project_dict(specs, ns), "생성한 프로젝트 설정")
    return text, warnings


def write_codex_config(*, repo: Path, servers: Mapping[str, Mapping[str, Any]], settings_path: Path, scope: str,
                       codex_homes: Sequence[str] | None, dry_run: bool, include_rea: bool, direct: str, tools_env: str | None,
                       say: Say = print, warn: Say | None = None) -> int:
    """``pweh mcp-config --client codex --write`` (scope project | global). 종료 코드를 돌려준다.

    project: ``<저장소>/.codex/config.toml`` 을 통째로 다시 만든다(같으면 쓰지 않음, pweh 표식 없는 다른 내용이면 백업).
    global: 대상 홈마다 config.toml 에 병합한다. 모든 대상의 새 내용을 먼저 만들고 하나라도 실패하면 아무것도 쓰지 않는다.
    dry_run: 바뀔 파일의 unified diff 만 보여 주고 아무것도 쓰지 않는다(디렉터리도 만들지 않는다).
    """
    warn = warn or say
    if scope not in SCOPES:
        raise ClientConfigError(f"알 수 없는 --scope: {scope}")
    if scope == "project":
        text, warnings = project_text(servers, repo, settings_path=settings_path, include_rea=include_rea, direct=direct, tools_env=tools_env)
        for w in warnings:
            warn(f"경고: {w}")
        with _locked_dirs([project_path(repo)], enabled=not dry_run):
            ch = plan_project(repo, text)
            if not ch.changed:
                say(f"변경 없음: {ch.display} (이미 최신)")
            elif dry_run:
                say(f"바뀔 파일: {ch.display}" + (" (기존 파일 — 쓰면 백업한다)" if ch.old.exists and ch.backup else ""))
                for n in ch.notes:
                    say(f"  · {n}")
                say(ch.diff())
            else:
                for n in ch.notes:
                    say(f"  · {n}")
                apply_changes([ch], say)
        _trust_hint(repo, codex_homes, say)
        return 0
    specs, ns, warnings = codex_specs_for(servers, repo, settings_path=settings_path, include_rea=include_rea, direct=direct)
    for w in warnings:
        warn(f"경고: {w}")
    homes, notes = scan_codex_homes(codex_homes)
    for n in notes:
        say(f"참고: {n}")
    for h in homes:
        if h.skipped:
            say(f"건너뜀: {h.path} ({h.label}) — {h.skipped}")
        elif h.native_windows:
            say(f"건너뜀: {h.path} ({h.label}) — Windows 데스크톱 앱 홈과 같은 디렉터리이고 {h.native_windows}. "
                "그래도 쓰려면 --codex-home 으로 직접 지정한다")
    targets = [h for h in homes if not h.skipped and not h.native_windows]
    if not targets:
        warn("Codex 홈을 찾지 못했다 — --codex-home DIR 로 지정한다 (아무것도 쓰지 않았다)")
        return 1
    with _locked_dirs([h.config for h in targets], enabled=not dry_run):  # 읽기부터 바꾸기까지
        changes: list[FileChange] = []
        errors: list[str] = []
        for h in targets:
            try:
                changes.append(plan_global(h, specs, ns, include_rea=include_rea))
            except ClientConfigError as exc:
                errors.append(str(exc))
        if errors:
            for e in errors:
                warn(f"거부: {e}")
            warn("하나라도 고칠 수 없어 아무 파일도 쓰지 않았다")
            return 1
        _print_changes(changes, say, dry_run=dry_run)
        if not dry_run:
            apply_changes(changes, say)
    return 0


def _trust_hint(repo: Path, codex_homes: Sequence[str] | None, say: Say) -> None:
    """프로젝트 설정을 쓴 뒤: 신뢰 항목이 없는 홈이 있으면 pweh codex-trust 를 안내한다 (읽기만)."""
    try:
        homes, _notes = scan_codex_homes(codex_homes)
    except Exception:  # noqa: BLE001 - 안내일 뿐이다
        return
    key = trust_key(repo)
    lacking = []
    for h in homes:
        if h.skipped:
            continue
        try:
            lvl = trust_level(read_toml_file(h.config).text, key, str(h.config))
        except ClientConfigError:
            lvl = None
        if lvl != "trusted":
            lacking.append(f"{h.config} ({h.label})")
    if lacking:
        say("참고: Codex 는 이 저장소를 신뢰할 때만 프로젝트 설정을 읽는다. 신뢰 항목이 없는 홈: " + ", ".join(lacking))
        say("      → pweh codex-trust")


def codex_trust(*, repo: Path, codex_homes: Sequence[str] | None, yes: bool, dry_run: bool, check: bool, interactive: bool,
                ask: Callable[[str], str] = input, say: Say = print, warn: Say | None = None) -> int:
    """``pweh codex-trust``. --yes 가 없으면 TTY 에서 묻고, TTY 가 아니면 아무것도 하지 않는다.

    --check 는 쓰지 않는다. 종료 코드: 0 = 대상 홈이 모두 신뢰함(또는 대상 홈 없음), 1 = 신뢰 항목이 없는 홈이 있음,
    2 = 읽지 못한 홈이 있어 확인하지 못함(설치 스크립트가 1 로 오해해 묻거나 더하지 않게 따로 둔다).
    """
    warn = warn or say
    key = trust_key(repo)
    homes, notes = scan_codex_homes(codex_homes)
    for n in notes:
        say(f"참고: {n}")
    for h in homes:
        if h.skipped:
            say(f"건너뜀: {h.path} ({h.label}) — {h.skipped}")
    targets = [h for h in homes if not h.skipped]
    if not targets:
        say("Codex 홈을 찾지 못했다 (Codex 를 쓰지 않으면 무시) — 직접 지정: pweh codex-trust --codex-home DIR")
        return 0
    if check:
        missing = unreadable = 0
        for h in targets:
            try:
                lvl = trust_level(read_toml_file(h.config).text, key, str(h.config))
            except ClientConfigError as exc:
                say(f"[!! ] {h.config} ({h.label}) — 읽지 못함: {exc.message}")
                unreadable += 1
                continue
            if lvl == "trusted":
                say(f"[OK ] {h.config} ({h.label}) — 신뢰됨: {key}")
            else:
                missing += 1
                say(f"[!! ] {h.config} ({h.label}) — " + ("신뢰 항목 없음" if lvl is None else f"trust_level = {lvl}") + " → pweh codex-trust")
        return 2 if unreadable else (1 if missing else 0)
    with _locked_dirs([h.config for h in targets], enabled=not dry_run):  # 읽기부터 바꾸기까지 (묻는 동안에도 — 보여 준 diff 그대로 쓴다)
        changes: list[FileChange] = []
        errors: list[str] = []
        for h in targets:
            try:
                changes.append(plan_trust(h, repo))
            except ClientConfigError as exc:
                errors.append(str(exc))
        if errors:
            for e in errors:
                warn(f"거부: {e}")
            warn("하나라도 고칠 수 없어 아무 파일도 쓰지 않았다")
            return 1
        todo = [c for c in changes if c.changed]
        if not todo:
            say(f"이미 신뢰됨: {key} — " + ", ".join(f"{c.display} ({c.label})" for c in changes))
            return 0
        if dry_run:
            _print_changes(todo, say, dry_run=True)
            return 0
        if not yes:
            if not interactive:
                say("Codex 신뢰 등록은 사람이 확인해야 한다 (대화형 터미널이 아니라 아무것도 바꾸지 않았다).")
                say(f"  대상: {key}  ←  " + ", ".join(f"{c.display} ({c.label})" for c in todo))
                say("  등록: pweh codex-trust --yes   (미리 보기: --dry-run)")
                return 0
            say(f"Codex 가 이 저장소({key})의 프로젝트 설정(.codex/config.toml)을 읽도록 신뢰 프로젝트로 등록한다.")
            for c in todo:
                say(f"  - {c.display} ({c.label}): {'; '.join(c.notes)}")
            try:
                answer = ask("등록할까요? [y/N] ").strip().lower()
            except (EOFError, KeyboardInterrupt):
                answer = ""
            if answer not in ("y", "yes", "예", "네"):
                say("취소했다 (아무것도 바꾸지 않았다).")
                return 0
        apply_changes(todo, say)
    return 0


# ---------------------------------------------------------------------------
# mcp-check — 클라이언트 설정대로 서버를 띄워 initialize + tools/list 만 (도구는 호출하지 않는다)
# ---------------------------------------------------------------------------


def _env_var_names(env_vars: Iterable[Any]) -> list[str]:
    """Codex env_vars 항목 → 이름. 항목은 이름 문자열이거나 {name, source} 표다 (source = "remote" 는 로컬 stdio 에서 쓰지 않는다)."""
    names = []
    for v in env_vars or ():
        if isinstance(v, str):
            names.append(v)
        elif isinstance(v, Mapping) and isinstance(v.get("name"), str) and v.get("source") != "remote":
            names.append(v["name"])
    return names


def codex_like_env(spec_env: Mapping[str, Any] | None = None, env_vars: Iterable[Any] = (), base: Mapping[str, str] | None = None) -> dict[str, str]:
    """Codex 가 MCP 서버에 주는 환경: 허용 목록(:data:`CODEX_LIKE_ENV`) + env_vars 이름 + 설정 env (설정 env 가 이긴다)."""
    src = os.environ if base is None else base
    env = {k: src[k] for k in CODEX_LIKE_ENV if k in src}
    for k in _env_var_names(env_vars):
        if k in src:
            env[k] = src[k]
    for k, v in (spec_env or {}).items():
        env[str(k)] = str(v)
    return env


#: 지금 떠 있는 점검 대상 프로세스 (Ctrl-C·SIGTERM 으로 중단될 때 메인 스레드가 프로세스 그룹째 정리한다)
_LIVE: set["_StdioClient"] = set()
_LIVE_LOCK = threading.Lock()


def _close_all_live(grace: float = 0.3) -> None:
    """떠 있는 점검 대상을 모두 정리한다 (서버는 각자 새 세션이라 터미널의 Ctrl-C 를 받지 않는다 — 남기지 않게)."""
    with _LIVE_LOCK:
        live = list(_LIVE)
    for c in live:
        with contextlib.suppress(Exception):
            c.close(grace=grace)


@contextlib.contextmanager
def _sigterm_as_interrupt() -> Iterator[None]:
    """SIGTERM(설치 스크립트의 시간 제한 등)을 KeyboardInterrupt 로 바꿔 finally 정리가 돌게 한다 (메인 스레드에서만)."""
    if threading.current_thread() is not threading.main_thread():
        yield
        return

    def handler(signum: int, frame: Any) -> None:
        raise KeyboardInterrupt(f"signal {signum}")

    old = signal.signal(signal.SIGTERM, handler)
    try:
        yield
    finally:
        signal.signal(signal.SIGTERM, old)


class _StdioClient:
    """줄 단위 JSON-RPC (MCP stdio). 새 프로세스 그룹으로 띄우고 끝에 그룹째 정리한다(Codex 와 같음)."""

    def __init__(self, argv: Sequence[str], cwd: str | None, env: Mapping[str, str]) -> None:
        self.q: queue.Queue[Any] = queue.Queue()
        self.stderr: collections.deque[str] = collections.deque(maxlen=20)
        self.nonjson: list[str] = []
        self.next_id = 0
        self.p = subprocess.Popen(list(argv), cwd=cwd or None, env=dict(env), stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                  stderr=subprocess.PIPE, start_new_session=True, close_fds=True)
        self._readers = (threading.Thread(target=self._read_out, daemon=True),
                         threading.Thread(target=self._read_err, daemon=True))
        with _LIVE_LOCK:
            _LIVE.add(self)
        for reader in self._readers:
            reader.start()

    def _exit_code(self, wait: float = 1.0) -> int | None:
        with contextlib.suppress(subprocess.TimeoutExpired):
            self.p.wait(timeout=wait)
        return self.p.poll()

    def _ended(self, method: str) -> EOFError:
        rc = self._exit_code()
        return EOFError(f"{method} 중에 서버가 끝남" + (f" (종료 코드 {rc})" if rc is not None else ""))

    def _read_out(self) -> None:
        assert self.p.stdout is not None
        with self.p.stdout:
            for line in self.p.stdout:
                s = line.strip()
                if not s:
                    continue
                try:
                    self.q.put(json.loads(s))
                except ValueError:
                    self.nonjson.append(s[:200].decode("utf-8", "replace"))
        self.q.put(None)

    def _read_err(self) -> None:
        assert self.p.stderr is not None
        with self.p.stderr:
            for line in self.p.stderr:
                text = line.decode("utf-8", "replace").rstrip()
                if text:
                    self.stderr.append(text[:300])

    def send(self, obj: Mapping[str, Any], method: str = "") -> None:
        assert self.p.stdin is not None
        try:
            self.p.stdin.write((json.dumps(obj, ensure_ascii=False) + "\n").encode("utf-8"))
            self.p.stdin.flush()
        except (BrokenPipeError, ValueError) as exc:  # 서버가 이미 끝남 — '[Errno 32] Broken pipe' 대신 종료 코드로 알린다
            raise self._ended(method or str(obj.get("method") or "요청")) from exc

    def request(self, method: str, params: Mapping[str, Any] | None, deadline: float) -> dict[str, Any]:
        rid = self.next_id
        self.next_id += 1
        msg: dict[str, Any] = {"jsonrpc": "2.0", "id": rid, "method": method}
        if params is not None:
            msg["params"] = dict(params)
        self.send(msg, method)
        while True:
            left = deadline - time.monotonic()
            if left <= 0:
                raise TimeoutError(f"{method} 응답 시간 초과")
            try:
                m = self.q.get(timeout=left)
            except queue.Empty:
                raise TimeoutError(f"{method} 응답 시간 초과") from None
            if m is None:
                raise self._ended(method)
            if not isinstance(m, dict):
                continue
            if "method" in m and "id" in m:  # 서버 → 클라이언트 요청: 지원하지 않는다고 답한다
                self.send({"jsonrpc": "2.0", "id": m["id"], "error": {"code": -32601, "message": "pweh mcp-check 는 이 요청을 처리하지 않는다"}})
                continue
            if m.get("id") == rid and ("result" in m or "error" in m):
                return m

    def _group_alive(self) -> bool:
        self.p.poll()  # 끝난 리더를 거둔다 (좀비가 그룹에 남아 살아 있는 것처럼 보이지 않게)
        try:
            os.killpg(self.p.pid, 0)
        except (ProcessLookupError, PermissionError):
            return False
        return True

    def close(self, grace: float = 3.0) -> None:
        """stdin 을 닫고(정상 종료 기회) grace 초 기다린 뒤, 프로세스 그룹에 남은 것을 SIGTERM → SIGKILL 로 정리한다."""
        with contextlib.suppress(OSError, ValueError):
            if self.p.stdin:
                self.p.stdin.close()
        with contextlib.suppress(subprocess.TimeoutExpired):
            self.p.wait(timeout=grace)
        for sig in (signal.SIGTERM, signal.SIGKILL):
            if not self._group_alive():
                break
            try:
                os.killpg(self.p.pid, sig)
            except (ProcessLookupError, PermissionError):
                break
            deadline = time.monotonic() + 2
            while time.monotonic() < deadline and self._group_alive():
                time.sleep(0.05)
        with contextlib.suppress(subprocess.TimeoutExpired):
            self.p.wait(timeout=2)
        # 자식 종료와 수신 완료는 별개다. stderr snapshot 전에 두 reader를 같은 예산으로 기다린다.
        # 미종료 reader의 stream은 여기서 닫지 않는다(다른 스레드의 read 잠금을 기다릴 수 있음).
        reader_deadline = time.monotonic() + 2
        for reader in self._readers:
            if reader.ident is not None and reader is not threading.current_thread():
                reader.join(max(0.0, reader_deadline - time.monotonic()))
        with _LIVE_LOCK:
            _LIVE.discard(self)


def check_server(name: str, spec: Mapping[str, Any], *, env: Mapping[str, str], timeout: float, client: str = "codex") -> dict[str, Any]:
    """서버 하나를 띄워 initialize → notifications/initialized → tools/list(nextCursor 따라감). 도구는 호출하지 않는다."""
    from . import __version__

    res: dict[str, Any] = {"client": client, "server": name, "ok": False, "command": str(spec.get("command")),
                           "t_initialize": None, "t_total": None, "tools": None, "server_info": None, "protocol": None,
                           "error": None, "stderr_tail": []}
    command = spec.get("command")
    if not isinstance(command, str) or not command:
        res["error"] = "command 가 없다"
        return res
    args = [str(a) for a in spec.get("args") or []]
    cwd = spec.get("cwd")
    if cwd and not os.path.isdir(str(cwd)):
        res["error"] = f"cwd 디렉터리가 없다: {cwd}"
        return res
    t0 = time.monotonic()
    deadline = t0 + float(timeout)
    cli: _StdioClient | None = None
    try:
        cli = _StdioClient([command, *args], spec.get("cwd"), env)
        init = cli.request("initialize", {"protocolVersion": MCP_PROTOCOL, "capabilities": {},
                                          "clientInfo": {"name": "pweh-mcp-check", "title": "pweh mcp-check", "version": __version__}}, deadline)
        res["t_initialize"] = round(time.monotonic() - t0, 3)
        if "error" in init:
            raise RuntimeError(f"initialize 오류: {init['error']}")
        result = init.get("result") or {}
        info = result.get("serverInfo") or {}
        res["server_info"] = f"{info.get('name', '?')} {info.get('version', '')}".strip()
        res["protocol"] = result.get("protocolVersion")
        cli.send({"jsonrpc": "2.0", "method": "notifications/initialized"})
        count, cursor = 0, None
        for _ in range(100):
            msg = cli.request("tools/list", {"cursor": cursor} if cursor else {}, deadline)
            if "error" in msg:
                raise RuntimeError(f"tools/list 오류: {msg['error']}")
            r = msg.get("result") or {}
            count += len(r.get("tools") or [])
            cursor = r.get("nextCursor")
            if not cursor:
                break
        res["tools"] = count
        res["t_total"] = round(time.monotonic() - t0, 3)
        if cli.nonjson:
            raise RuntimeError(f"stdout 에 JSON 이 아닌 줄이 있다 (stdout 은 MCP 채널): {cli.nonjson[0]!r}")
        res["ok"] = True
    except FileNotFoundError as exc:
        res["error"] = f"실행 파일 없음: {exc.filename or command}"
    except PermissionError as exc:
        res["error"] = f"실행 권한 없음: {exc.filename or command}"
    except (OSError, TimeoutError, EOFError, RuntimeError, ValueError) as exc:
        res["error"] = str(exc)
    finally:
        if cli is not None:
            cli.close()
            res["stderr_tail"] = list(cli.stderr)[-5:]
    return res


def check_servers(specs: Mapping[str, Mapping[str, Any]], *, client: str, timeout: float, repo: Path | None = None,
                  base_env: Mapping[str, str] | None = None) -> list[dict[str, Any]]:
    """여러 서버를 동시에 점검한다 (Codex 세션 시작처럼). claude 는 같은 최소 환경 + CLAUDE_PROJECT_DIR, cwd=저장소."""
    results: dict[str, dict[str, Any]] = {}

    def one(name: str, spec: Mapping[str, Any]) -> None:
        if client == "claude":
            env = codex_like_env(spec.get("env"), (), base_env)
            if repo is not None:
                env["CLAUDE_PROJECT_DIR"] = str(repo)
            spec = {**spec, "cwd": spec.get("cwd") or (str(repo) if repo is not None else None)}
        else:
            env = codex_like_env(spec.get("env"), spec.get("env_vars") or (), base_env)
        results[name] = check_server(name, spec, env=env, timeout=timeout, client=client)

    threads = [threading.Thread(target=one, args=(n, s), daemon=True) for n, s in specs.items()]
    try:
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout + 15)
    except BaseException:  # Ctrl-C·SIGTERM: 일하던 스레드는 데몬이라 그대로 끝나므로 띄운 서버를 여기서 정리한다
        _close_all_live()
        raise
    out = []
    for n in specs:
        out.append(results.get(n) or {"client": client, "server": n, "ok": False, "error": "점검이 끝나지 않음", "stderr_tail": []})
    return out


def _pick_servers(doc: Any) -> dict[str, dict[str, Any]]:
    ms = doc.get("mcp_servers") if isinstance(doc, Mapping) else None
    if not isinstance(ms, Mapping):
        return {}
    return {k: dict(v) for k, v in ms.items() if isinstance(v, Mapping) and (k.startswith(PWEH_PREFIX) or k == REA)}


def codex_check_targets(repo: Path, generated: Callable[[], Mapping[str, Mapping[str, Any]]], homes: Sequence[CodexHome] | None = None
                        ) -> list[dict[str, Any]]:
    """Codex 가 실제로 띄울 서버 설정들 — [{key, source, specs, error, notes}].

    - 프로젝트 설정이 있으면 점검한다(key 'codex'). 신뢰한 홈이 없으면 'Codex 는 아직 이 파일을 읽지 않는다'고 적는다(실패로 보지 않는다 —
      설치 스크립트는 신뢰를 거절해도 실패가 아니다).
    - 이 저장소를 신뢰하지 않는 홈에 ``[mcp_servers.pweh-*]`` 가 직접 있으면 Codex 는 그 표로 서버를 띄운다 → 따로 점검한다
      (key 'codex[<표시>]'. 예전에 붙여 넣은 낡은 표가 있으면 여기서 실패로 드러난다). 신뢰한 홈은 프로젝트 설정이 이기므로 넣지 않는다.
    - 둘 다 없으면 지금 생성할 값 (Codex 설정 파일 없음).
    """
    key = trust_key(repo)
    proj = project_path(repo)
    targets: list[dict[str, Any]] = []
    infos: list[tuple[CodexHome, bool, dict[str, dict[str, Any]]]] = []
    unreadable: list[str] = []
    for h in homes or ():
        if h.skipped:
            continue
        try:
            text = read_toml_file(h.config).text
            trusted = trust_level(text, key, str(h.config)) == "trusted"
            infos.append((h, trusted, _pick_servers(parse_toml(text or "", str(h.config)).unwrap())))
        except ClientConfigError as exc:
            unreadable.append(f"{h.config} ({h.label}): {exc.message}")
    if proj.is_file():
        notes: list[str] = []
        if infos and not any(t for _h, t, _s in infos):
            notes.append("이 저장소를 신뢰한 Codex 홈이 없어 Codex 는 아직 이 파일을 읽지 않는다 (pweh codex-trust) — 서버 시작만 미리 점검한다")
        try:
            specs, error = _pick_servers(parse_toml(read_toml_file(proj, strict=True).text or "", str(proj)).unwrap()), None
        except ClientConfigError as exc:
            specs, error = {}, exc.message
        targets.append({"key": "codex", "source": str(proj), "specs": specs, "error": error, "notes": notes})
    for h, trusted, found in infos:
        if trusted and proj.is_file():
            continue
        if any(k.startswith(PWEH_PREFIX) for k in found):
            notes = (["이 홈은 이 저장소를 신뢰하지 않아 프로젝트 설정 대신 이 표로 서버를 띄운다"] if proj.is_file() else [])
            targets.append({"key": f"codex[{h.label}]", "source": f"{h.config} ({h.label})", "specs": found, "error": None, "notes": notes})
    if not targets:
        targets.append({"key": "codex", "source": "생성값 (Codex 설정 파일 없음 → pweh mcp-config --client codex --write)",
                        "specs": {k: dict(v) for k, v in generated().items()}, "error": None, "notes": []})
    if unreadable:
        targets[0]["notes"].append("읽지 못한 Codex 홈 설정 (pweh doctor 참고): " + "; ".join(unreadable))
    if len(targets) == 1:
        targets[0]["key"] = "codex"
    else:  # 같은 표시(cli 둘 등)는 번호로 구별한다
        seen: dict[str, int] = {}
        for t in targets:
            seen[t["key"]] = seen.get(t["key"], 0) + 1
            if seen[t["key"]] > 1:
                t["key"] = f"{t['key'][:-1]}-{seen[t['key']]}]" if t["key"].endswith("]") else f"{t['key']}-{seen[t['key']]}"
    return targets


def codex_check_specs(repo: Path, generated: Callable[[], Mapping[str, Mapping[str, Any]]], homes: Sequence[CodexHome] | None = None
                      ) -> tuple[dict[str, dict[str, Any]], str, str | None]:
    """(호환용) :func:`codex_check_targets` 의 첫 대상: (서버 설정, 출처, 오류)."""
    t = codex_check_targets(repo, generated, homes)[0]
    return t["specs"], t["source"], t["error"]


def claude_check_specs(repo: Path) -> tuple[dict[str, dict[str, Any]], str, str | None, list[str]]:
    """Claude Code 의 <저장소>/.mcp.json 서버 (pweh-* 와 rea), 출처, 오류, 참고 문구(enabledMcpjsonServers 에 없는 서버 등)."""
    path = Path(repo) / ".mcp.json"
    notes: list[str] = []
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return {}, str(path), f"{path} 가 없다 → pweh mcp-config --client claude --write", notes
    except (OSError, ValueError) as exc:
        return {}, str(path), f"{path} 를 읽지 못함: {exc}", notes
    servers = data.get("mcpServers") if isinstance(data, dict) else None
    specs: dict[str, dict[str, Any]] = {}
    for name, s in (servers or {}).items():
        if not (name.startswith(PWEH_PREFIX) or name == REA) or not isinstance(s, dict):
            continue
        if s.get("type", "stdio") != "stdio":
            notes.append(f"{name}: stdio 가 아니라 건너뜀 ({s.get('type')})")
            continue
        specs[name] = {"command": s.get("command"), "args": list(s.get("args") or []), "env": dict(s.get("env") or {})}
    try:
        settings = json.loads((Path(repo) / ".claude" / "settings.json").read_text(encoding="utf-8"))
        enabled = settings.get("enabledMcpjsonServers")
    except (OSError, ValueError):
        enabled = None
    if isinstance(enabled, list):
        off = [n for n in specs if n not in enabled]
        if off:
            notes.append(".claude/settings.json 의 enabledMcpjsonServers 에 없는 서버: " + ", ".join(off))
    return specs, str(path), None, notes


def _unshare_works(unshare: str) -> bool:
    try:
        r = subprocess.run([unshare, "-c", "-n", "--", "true"], stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                           stderr=subprocess.DEVNULL, timeout=5, check=False)
    except (OSError, subprocess.SubprocessError):
        return False
    return r.returncode == 0


def _codex_version(codex: str, env: Mapping[str, str] | None = None) -> str | None:
    """``codex --version`` 첫 줄. codex 는 --version 에도 ``$CODEX_HOME/tmp`` 를 만들므로 부르는 쪽이 임시 홈 환경을 준다."""
    try:
        r = subprocess.run([codex, "--version"], stdin=subprocess.DEVNULL, capture_output=True, timeout=15, check=False,
                           env=dict(env) if env is not None else None)
    except (OSError, subprocess.SubprocessError):
        return None
    lines = r.stdout.decode("utf-8", "replace").strip().splitlines()
    return lines[0][:80] if r.returncode == 0 and lines else None


def deep_check(specs: Mapping[str, Mapping[str, Any]], *, codex: str | None = None, timeout: float = 60.0) -> dict[str, Any]:
    """Codex 자체 MCP 클라이언트로 점검 (``codex app-server`` + ``mcpServerStatus/list``) — 오프라인.

    임시 CODEX_HOME(이 서버 표만 든 config.toml)·임시 HOME, 인증 없음(모델 호출이 일어날 수 없다), 스레드·턴 요청 없음.
    ``unshare -c -n`` 이 되면 네트워크 이름공간을 따로 써서 네트워크도 막는다(안 되면 ``network_isolated: false`` 로 알린다).
    """
    codex = codex or shutil.which("codex")
    if not codex:
        return {"skipped": "codex 실행 파일이 없다 (PATH)", "ok": None, "servers": []}
    out: dict[str, Any] = {"codex": codex, "version": None, "network_isolated": False, "ok": False, "servers": [],
                           "error": None, "t": None}
    tmp = Path(tempfile.mkdtemp(prefix="pweh-mcp-deep-"))
    try:
        home, codex_home, work = tmp / "home", tmp / "codex-home", tmp / "work"
        for d in (home, codex_home, work):
            d.mkdir(mode=0o700)
        (codex_home / "config.toml").write_text(_servers_only_text(specs), encoding="utf-8")
        env = codex_like_env(None, PWEH_ENV_VARS)
        env.update({"HOME": str(home), "CODEX_HOME": str(codex_home)})
        out["version"] = _codex_version(codex, env)  # 사용자의 Codex 홈에 아무것도 만들지 않게 같은 임시 홈으로
        argv = [codex, "app-server", "--listen", "stdio://"]
        unshare = shutil.which("unshare")
        if unshare and _unshare_works(unshare):
            argv = [unshare, "-c", "-n", "--", *argv]
            out["network_isolated"] = True
        t0 = time.monotonic()
        cli = _StdioClient(argv, str(work), env)
        try:
            deadline = t0 + 30
            init = cli.request("initialize", {"clientInfo": {"name": "pweh_mcp_check", "title": "pweh mcp-check", "version": "1"},
                                              "capabilities": {"experimentalApi": True}}, deadline)
            if "error" in init:
                raise RuntimeError(f"app-server initialize 오류: {init['error']}")
            cli.send({"method": "initialized"})
            data: list[dict[str, Any]] = []
            cursor = None
            deadline = time.monotonic() + float(timeout) + 30
            for _ in range(20):
                params: dict[str, Any] = {"detail": "toolsAndAuthOnly"}
                if cursor:
                    params["cursor"] = cursor
                msg = cli.request("mcpServerStatus/list", params, deadline)
                if "error" in msg:
                    raise RuntimeError(f"mcpServerStatus/list 오류 (이 codex 버전이 지원하지 않을 수 있다): {msg['error']}")
                r = msg.get("result") or {}
                data += [x for x in r.get("data") or [] if isinstance(x, dict)]
                cursor = r.get("nextCursor")
                if not cursor:
                    break
            out["t"] = round(time.monotonic() - t0, 3)
        finally:
            cli.close(grace=10.0)  # app-server 는 stdin EOF 뒤 자기 MCP 서버를 정리하고 끝난다 (약 5 초) — 그동안 끊지 않는다
        by = {str(x.get("name")): x for x in data}
        rows = []
        for name in specs:
            s = by.get(name)
            if s is None:
                rows.append({"server": name, "ok": False, "tools": None, "server_info": None, "error": "Codex 가 이 서버를 보고하지 않았다"})
                continue
            tools = len(s.get("tools") or {})
            info = s.get("serverInfo") or {}
            err = s.get("toolsError")
            if not err and tools == 0:
                err = "도구 0개 (enabled_tools·서버 구현 확인)"
            rows.append({"server": name, "ok": not err, "tools": tools,
                         "server_info": f"{info.get('name', '?')} {info.get('version', '')}".strip() if info else None, "error": err})
        out["servers"] = rows
        out["ok"] = bool(rows) and all(r["ok"] for r in rows)
    except (OSError, TimeoutError, EOFError, RuntimeError, ValueError) as exc:
        out["error"] = str(exc)
        out["ok"] = False
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    return out


def _row_line(r: Mapping[str, Any]) -> list[str]:
    name = f"{r.get('client')}:{r.get('server')}"
    if r.get("ok"):
        return [f"[OK ] {name:<24} {r.get('t_total')}s  도구 {r.get('tools')}  {r.get('server_info') or ''}".rstrip()]
    if r.get("ok") is None:
        return [f"[-- ] {name:<24} {r.get('error') or ''}"]
    lines = [f"[!! ] {name:<24} {r.get('error')}" + ("  (선택 서버 — 종료 코드에 넣지 않음)" if r.get("optional") else "")]
    lines += [f"       stderr: {x}" for x in (r.get("stderr_tail") or [])[-3:]]
    return lines


def mcp_check(*, repo: Path, client: str, deep: bool, timeout: float, generated: Callable[[], Mapping[str, Mapping[str, Any]]],
              server_names: Sequence[str], as_json: bool, codex_homes: Sequence[CodexHome] | None = None,
              optional: Sequence[str] = (), say: Say = print) -> int:
    """``pweh mcp-check``. 점검한 서버가 모두 정상이면 0 — 단 optional 서버(예: REA 가 없을 때의 rea)의 실패는 보고만 하고 종료 코드에 넣지 않는다.

    Codex 는 :func:`codex_check_targets` 의 대상마다(프로젝트 설정, 이 저장소를 신뢰하지 않는 홈에 직접 등록된 표) 따로 점검한다.
    중단(Ctrl-C·SIGTERM)되면 띄운 서버를 프로세스 그룹째 정리하고 KeyboardInterrupt 를 다시 낸다.
    """
    if client not in CLIENTS:
        raise ClientConfigError(f"알 수 없는 --client: {client}")
    opt = set(optional or ())
    try:
        with _sigterm_as_interrupt():
            report = _mcp_check_report(repo=repo, client=client, deep=deep, timeout=timeout, generated=generated, server_names=server_names,
                                       codex_homes=codex_homes, opt=opt)
    except BaseException:
        _close_all_live()
        raise
    if as_json:
        say(json.dumps(report, ensure_ascii=False, indent=2))
        return 0 if report["ok"] else 1
    for c, entry in report["clients"].items():
        say(f"{c}: {entry['source']}")
        if entry.get("error"):
            say(f"[!! ] {c:<28} {entry['error']}")
        for n in entry.get("notes") or []:
            say(f"  참고: {n}")
        for r in entry["servers"]:
            for line in _row_line(r):
                say(line)
    d = report["deep"]
    if d:
        if d.get("skipped"):
            say(f"deep: 건너뜀 — {d['skipped']}")
        else:
            iso = "네트워크 격리(unshare -n)" if d.get("network_isolated") else "네트워크 격리 없음 (인증이 없어 모델 호출은 없다)"
            say(f"deep: {d.get('version') or d.get('codex')} app-server + mcpServerStatus/list, 임시 CODEX_HOME, {iso}")
            if d.get("error"):
                say(f"[!! ] deep                         {d['error']}")
            for r in d.get("servers") or []:
                mark = "OK " if r.get("ok") else "!! "
                say(f"[{mark}] deep:{r['server']:<19} " + (f"도구 {r.get('tools')}  {r.get('server_info') or ''}" if r.get("ok") else str(r.get("error")))
                    + ("  (선택 서버 — 종료 코드에 넣지 않음)" if not r.get("ok") and r.get("optional") else ""))
    total = [r for e in report["clients"].values() for r in e["servers"] if r.get("ok") is not None]
    good = sum(1 for r in total if r.get("ok"))
    soft = sorted({str(r.get("server")) for r in total if r.get("ok") is False and r.get("optional")})
    n_soft = sum(1 for r in total if r.get("ok") is False and r.get("optional"))
    say(f"결과: {good}/{len(total)} 정상" + ("" if report["ok"] else " — 실패가 있다")
        + (f" — 선택 서버 실패 {n_soft}개 (종료 코드에 넣지 않음: {', '.join(soft)})" if n_soft else ""))
    return 0 if report["ok"] else 1


def _mcp_check_report(*, repo: Path, client: str, deep: bool, timeout: float, generated: Callable[[], Mapping[str, Mapping[str, Any]]],
                      server_names: Sequence[str], codex_homes: Sequence[CodexHome] | None, opt: set[str]) -> dict[str, Any]:
    report: dict[str, Any] = {"ok": True, "clients": {}, "deep": None, "optional": sorted(opt)}
    codex_specs: dict[str, dict[str, Any]] = {}
    plans: list[tuple[str, str, dict[str, dict[str, Any]], str, str | None, list[str]]] = []  # (보고서 키, 클라이언트, 설정, 출처, 오류, 참고)
    for c in (("codex", "claude") if client == "all" else (client,)):
        if c == "codex":
            homes = codex_homes if codex_homes is not None else scan_codex_homes(None)[0]
            for t in codex_check_targets(repo, generated, homes):
                plans.append((t["key"], "codex", t["specs"], t["source"], t["error"], t["notes"]))
                if not codex_specs and t["specs"]:
                    codex_specs = t["specs"]
        else:
            specs, source, error, notes = claude_check_specs(repo)
            plans.append(("claude", "claude", specs, source, error, notes))
    for key, c, specs, source, error, notes in plans:
        entry: dict[str, Any] = {"source": source, "error": error, "notes": notes, "servers": []}
        if error:
            report["ok"] = False
        else:
            rows = check_servers(specs, client=c, timeout=timeout, repo=repo)
            missing = [n for n in server_names if n not in specs]
            rows += [{"client": c, "server": n, "ok": None, "error": "설정에 없음 (점검하지 않음)", "stderr_tail": []} for n in missing]
            for r in rows:
                r["client"] = key
                if r.get("server") in opt:
                    r["optional"] = True
            entry["servers"] = rows
            if not specs or any(r.get("ok") is False and not r.get("optional") for r in rows):
                report["ok"] = False
            if not specs:
                entry["error"] = "점검할 PWEH 서버가 설정에 없다"
        report["clients"][key] = entry
    if deep:
        if client == "claude":
            report["deep"] = {"skipped": "--deep 은 Codex 전용 (--client codex 또는 all)", "ok": None, "servers": []}
        elif codex_specs:
            report["deep"] = deep_check(codex_specs, timeout=timeout)
            for r in report["deep"].get("servers") or []:
                if r.get("server") in opt:
                    r["optional"] = True
            hard = [r for r in report["deep"].get("servers") or [] if not r.get("ok") and not r.get("optional")]
            if report["deep"].get("error") or (report["deep"].get("ok") is False and hard):
                report["ok"] = False
        else:
            report["deep"] = {"skipped": "점검할 Codex 서버 설정이 없다", "ok": None, "servers": []}
    return report


# ---------------------------------------------------------------------------
# doctor 의 Codex 줄 (순수 함수 — 시험은 값을 넣어 부른다)
# ---------------------------------------------------------------------------


def project_status(repo: Path, expected_text: str | None, server_names: Sequence[str]) -> dict[str, Any]:
    """프로젝트 설정 상태: 없음 / 읽지 못함 / 사용자 파일 / 문제(서버 빠짐·실행 파일 없음) / 다름 / 최신."""
    path = project_path(repo)
    try:
        tf = read_toml_file(path)
    except ClientConfigError as exc:
        return {"state": "unreadable", "path": str(path), "detail": exc.message}
    if not tf.exists:
        return {"state": "missing", "path": str(path)}
    try:
        doc = parse_toml(tf.text or "", str(path)).unwrap()
    except ClientConfigError as exc:
        return {"state": "invalid", "path": str(path), "detail": exc.message}
    if not is_pweh_project_file(tf.text):
        return {"state": "user", "path": str(path)}
    ms = doc.get("mcp_servers") if isinstance(doc.get("mcp_servers"), dict) else {}
    missing = [n for n in server_names if n not in ms]
    bad_cmd = [n for n, s in ms.items() if isinstance(s, dict) and isinstance(s.get("command"), str)
               and s["command"].startswith("/") and not os.path.exists(s["command"])]
    if missing or bad_cmd:
        detail = "; ".join(x for x in (f"서버 빠짐: {', '.join(missing)}" if missing else "",
                                        f"실행 파일 없음: {', '.join(bad_cmd)}" if bad_cmd else "") if x)
        return {"state": "broken", "path": str(path), "detail": detail}
    if expected_text is not None:
        try:
            same = _without_volatile(doc) == _without_volatile(parse_toml(expected_text, "생성값").unwrap())
        except ClientConfigError:
            same = False
        if same:
            return {"state": "current", "path": str(path)}
    return {"state": "stale", "path": str(path)}


def _without_volatile(doc: Mapping[str, Any]) -> dict[str, Any]:
    """비교용 사본: 서버 env 의 PATH 를 뺀다 (env.sh 를 그때 셸의 PATH 위에 불러 만든 값이라 셸마다 다르다)."""
    d = copy.deepcopy(dict(doc))
    for spec in (d.get("mcp_servers") or {}).values():
        if isinstance(spec, dict) and isinstance(spec.get("env"), dict):
            spec["env"].pop("PATH", None)
    return d


def _command_exists(cmd: Any) -> bool:
    if not isinstance(cmd, str) or not cmd:
        return False
    return os.path.exists(cmd) if os.path.isabs(cmd) else shutil.which(cmd) is not None


def home_registration(text: str | None, where: str) -> dict[str, list[str]]:
    """사용자 config.toml 에 직접 등록된 PWEH 서버 표(``[mcp_servers.pweh-*]``): {names, unmarked(pweh-managed 표식 없음 — 예전에 붙여 넣은 표),
    missing_cmd(command 가 없음 — 옮겼거나 지운 저장소·가상환경)}. 표식이 있고 실행 파일이 모두 있어야 pweh 가 관리하는 전역 등록으로 본다."""
    out: dict[str, list[str]] = {"names": [], "unmarked": [], "missing_cmd": []}
    if not text:
        return out
    ms = parse_toml(text, where).get("mcp_servers")
    if ms is None or not hasattr(ms, "items"):
        return out
    for k, v in ms.items():
        if not str(k).startswith(PWEH_PREFIX):
            continue
        out["names"].append(str(k))
        if not has_managed_mark(v):
            out["unmarked"].append(str(k))
        if not _command_exists(v.get("command") if hasattr(v, "get") else None):
            out["missing_cmd"].append(str(k))
    return out


def _registration_problem(reg: Mapping[str, list[str]]) -> str | None:
    parts = []
    if reg["missing_cmd"]:
        parts.append(f"실행 파일 없음: {', '.join(reg['missing_cmd'])}")
    if reg["unmarked"]:
        parts.append(f"pweh-managed 표식 없음(예전에 붙여 넣은 표): {', '.join(reg['unmarked'])}")
    return "; ".join(parts) or None


def codex_checks(repo: Path, *, project: Mapping[str, Any], homes: Sequence[CodexHome], home_notes: Sequence[str] = (),
                 codex_bin: str | None = None) -> list[dict[str, Any]]:
    """doctor 의 Codex 점검 줄 (check/ok/detail/hint). 값은 부르는 쪽이 모은다(파일 읽기는 홈의 config.toml 확인뿐).

    홈의 config.toml 에 pweh 가 관리하는 PWEH 서버 표가 직접 있고 실행 파일이 모두 있으면(전역 범위 등록) 그 홈은 신뢰 없이도 PWEH 도구가
    뜨므로 신뢰가 없는 것을 문제(!!)로 보지 않는다(설치 스크립트 --codex-global 과 같은 판단). 표식 없는 표(예전에 붙여 넣은 표)는
    실행 파일이 있으면 경고(--)와 옮기는 방법, 실행 파일이 없으면 — 그 홈의 Codex 가 그 표로 서버를 띄우다 실패한다 — 신뢰가 없을 때 문제(!!)다.
    프로젝트 설정이 없는 것은 감지한(건너뛰지 않은) 모든 홈이 실행 파일이 있는 직접 등록을 가질 때만 문제로 보지 않는다.
    """
    checks: list[dict[str, Any]] = []

    def add(name: str, ok: bool | None, detail: str, hint: str = "") -> None:
        checks.append({"check": name, "ok": ok, "detail": detail, "hint": hint})

    key = trust_key(repo)
    empty: dict[str, list[str]] = {"names": [], "unmarked": [], "missing_cmd": []}
    seen_homes: list[tuple[CodexHome, str | None, dict[str, list[str]], str | None]] = []  # (홈, trust_level, 직접 등록, 읽기 오류)
    for h in homes:
        if h.skipped:
            seen_homes.append((h, None, empty, None))
            continue
        try:
            text = read_toml_file(h.config).text
            seen_homes.append((h, trust_level(text, key, str(h.config)), home_registration(text, str(h.config)), None))
        except ClientConfigError as exc:
            seen_homes.append((h, None, empty, exc.message))
    active = [(h, reg) for h, _lvl, reg, _err in seen_homes if not h.skipped]
    global_homes = [h for h, reg in active if reg["names"] and not reg["missing_cmd"]]
    all_global = bool(active) and len(global_homes) == len(active)
    used = bool(codex_bin) or bool(active)
    write = "pweh mcp-config --client codex --write"
    st = project.get("state")
    path = project.get("path")
    if st == "current":
        add("codex:project-config", True, f"{path} (pweh 생성, 최신)")
    elif st == "missing" and all_global:
        add("codex:project-config", None, f"{path} 없음 — Codex 홈에 PWEH 서버가 직접 등록돼 있다(전역 범위): "
            + ", ".join(f"{h.config} ({h.label})" for h in global_homes), f"프로젝트 범위로 바꾸려면 {write}")
    elif st == "missing":
        add("codex:project-config", False if used else None, f"{path} 없음", write)
    elif st == "stale":
        add("codex:project-config", None, f"{path} (pweh 생성) — 지금 생성 결과와 다르다", f"{write} 로 다시 만든다")
    elif st == "user":
        add("codex:project-config", None, f"{path} — pweh 표식이 없는 파일 (사용자가 만든 파일)", f"{write} 는 백업한 뒤 바꾼다")
    else:
        add("codex:project-config", False, f"{path} — {project.get('detail') or st}", write)
    if not homes:
        add("codex:homes", None, "Codex 홈을 찾지 못함 (Codex 를 쓰지 않으면 무시)",
            "직접 지정: pweh codex-trust --codex-home DIR / pweh mcp-config --client codex --write --scope global --codex-home DIR")
    seen: dict[str, int] = {}
    for h, lvl, reg, err in seen_homes:
        seen[h.label] = seen.get(h.label, 0) + 1
        tag = h.label if seen[h.label] == 1 else f"{h.label}-{seen[h.label]}"
        name = f"codex:trust[{tag}]"
        if h.skipped:
            add(name, None, f"{h.path} — 건너뜀: {h.skipped}")
            continue
        if err is not None:
            add(name, False, f"{h.config} — {err}", "파일을 고친 뒤 pweh codex-trust")
            continue
        problem = _registration_problem(reg) if reg["names"] else None
        migrate = (f"pweh mcp-config --client codex --write --scope global --codex-home {h.path} 로 pweh 가 관리하는 표로 바꾸거나, "
                   "그 [mcp_servers.pweh-*] 표를 지운다 (이 저장소에서는 프로젝트 설정 + pweh codex-trust)")
        if lvl == "trusted":
            add(name, True, f"{h.config} — 신뢰됨 ({h.source})")
            if problem:
                add(f"codex:home-servers[{tag}]", None, f"{h.config} 에 직접 등록된 PWEH 서버 표 문제 — {problem}. 이 저장소에서는 프로젝트 설정이 "
                    "이기지만 다른 프로젝트의 Codex 세션에서는 이 표로 서버를 띄운다", migrate)
            continue
        why = "신뢰 항목 없음" if lvl is None else f"trust_level = {lvl}"
        if reg["names"] and reg["missing_cmd"]:
            add(name, False, f"{h.config} — {why}. 그리고 이 홈에 직접 등록된 PWEH 서버 표가 있어 Codex 는 프로젝트 설정 대신 그 표로 서버를 "
                f"띄우다 실패한다 — {problem} ({h.source})", migrate)
        elif reg["names"]:
            add(name, None, f"{h.config} — {why}, 그러나 이 홈에 PWEH 서버 {len(reg['names'])}개가 직접 등록돼 있어(전역 범위) 신뢰 없이도 "
                f"PWEH 도구가 뜬다. 프로젝트 설정(.codex/config.toml)은 읽지 않는다 ({h.source})"
                + (f" — {problem}" if problem else ""),
                migrate if problem else "프로젝트 설정을 쓰려면 pweh codex-trust")
        else:
            add(name, False, f"{h.config} — {why}: Codex 가 프로젝트 설정(.codex/config.toml)을 읽지 않는다 ({h.source})", "pweh codex-trust")
    for n in home_notes:
        add("codex:desktop", None, n)
    add("codex:mcp-check", None, "서버 시작 점검은 따로 한다",
        "pweh mcp-check (Codex 와 같은 환경으로 initialize·tools/list) / pweh mcp-check --deep (Codex 자체 클라이언트)")
    return checks


__all__ = [
    "ClientConfigError", "CodexHome", "FileChange", "TomlFile",
    "add_trust", "apply_change", "apply_changes", "atomic_write", "backup_file", "check_server", "check_servers", "claude_check_specs",
    "codex_check_specs", "codex_check_targets", "codex_checks", "codex_like_env", "codex_server_specs", "codex_specs_for", "codex_trust",
    "deep_check", "desktop_home", "direct_namespaces", "encode_text", "expected_project_dict", "has_managed_mark", "home_registration",
    "is_pweh_project_file", "masked_diff", "mcp_check", "merge_user_config", "namespace", "parse_toml", "plan_global", "plan_project",
    "plan_trust", "project_file_state", "project_header", "project_path", "project_status", "project_text", "rea_enabled_tools", "rea_state",
    "read_options", "read_toml_file", "render_project_config", "resolve_target", "scan_codex_homes", "seal_project_text", "trust_key",
    "trust_level", "windows_profile", "write_codex_config",
]
