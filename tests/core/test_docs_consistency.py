"""문서·권한 설정이 실제 MCP 도구 카탈로그와 맞는지 검사하는 회귀 테스트.

하드웨어·외부 도구 없이 돈다. 서버·도구 목록은 하드코딩하지 않고 카탈로그와 pweh.cli.SERVERS 에서 얻는다(정책 상수는 아래 한곳에).
- docs/references/pweh-mcp-tools.json 이 서버의 실제 list_tools 결과(이름·인자·annotation·_meta·설명)와 같다
- 서버 목록이 카탈로그 = pweh.cli.SERVERS = dump_tool_catalog.SERVERS = .mcp.json(+ rea) 로 같고, 서버 이름·모듈·디렉터리가 맞는다
- .claude/settings.json: allow = FULL_ALLOW_SERVERS 전체 + 나머지 pweh 서버의 readOnlyHint 도구 + REA 정적 분석,
  ask ⊇ 원시/기기 변경 도구 + requiresUserInteraction 도구, allow/ask 중복 없음
- requiresUserInteraction 도구 = destructiveHint 도구(카탈로그)이고, safety.md / mcp-setup.md 에 적힌 목록과 같다
- docs/architecture.md §6 에 모든 서버의 절과 모든 도구가 있고, FULL_SIGNATURE_SERVERS 의 시그니처에는 모든 인자가 있다
- 문서의 상대 링크·백틱 저장소 경로가 실제로 있다
- 문서의 `pweh <명령>` 이 실제 CLI 파서로 해석된다
- 문서가 주장하는 분류 결과(예시 명령 → 위험도·규칙 id)가 실제 분류기와 같고, 문서에 적힌 규칙 id 가 코드에 있다
- architecture §6.2·uart README 의 uart 도구 행이 코드의 상태값(shell_login status, uboot_interrupt outcome)과 새 반환 필드를 모두 적는다
- 전원 투입 순서(전원을 먼저 끄고 → 도구 호출 → 호출이 시작되면 켬)와 RAM 한정 init=/bin/sh 동의 정책이 문서마다 같다
"""

from __future__ import annotations

import argparse
import ast
import importlib.util
import json
import re
import shlex
import sys
from pathlib import Path

import anyio
import pytest

REPO = Path(__file__).resolve().parents[2]
CATALOG = REPO / "docs" / "references" / "pweh-mcp-tools.json"
REA = REPO / "docs" / "references" / "rea-mcp-tools.json"
DOCS = [REPO / "README.md", REPO / "AGENTS.md", *sorted((REPO / "docs").glob("*.md")),
        *sorted(REPO.glob("mcp-servers/*/README.md")), REPO / "tests" / "mock-targets" / "README.md"]
RAW_ASK = {
    "mcp__pweh-uart__uart_write", "mcp__pweh-uart__uart_set_signals", "mcp__pweh-uart__uart_send_break",
    "mcp__pweh-openocd__openocd_command", "mcp__pweh-openocd__openocd_flash_write", "mcp__pweh-openocd__openocd_write_memory",
    "mcp__pweh-jtagulator__jtagulator_set_voltage",
}
REA_RUNTIME_ASK = {"gdb_console", "cutter_command", "load_frida_script", "resume_frida_session", "start_gdb_session", "execute_rizin_command",
                   "start_frida_session", "instrument_with_frida", "rizin_debug_command", "push_adb_file", "install_adb_package"}

# --- 정책 상수 (서버·도구 목록 자체는 카탈로그에서 얻는다. 새 서버는 아래 상수에 해당할 때만 적는다) ---
#: .claude/settings.json 에서 서버 전체(`mcp__<server>__*`)를 자동 허용하는 서버(기기에 닿지 않는 서버).
#: 나머지 pweh 서버는 readOnlyHint와 아래에 명시한 로컬 기록 도구만 allow에 있다.
FULL_ALLOW_SERVERS = ("pweh-case", "pweh-fwtriage")
#: 정지 그림·앱 기록·선택 텍스트의 마스킹된 비밀값 후보 분석은 로컬 산출물을 쓰므로 readOnlyHint 는 false 다.
LOCAL_WRITE_ALLOW = {f"mcp__pweh-forensics__{name}" for name in (
    "forensics_image_hints", "forensics_scan_secrets", "forensics_sqlite_inventory", "forensics_android_artifacts", "forensics_timeline")}
# I5 1a는 서버 내부 모델과 로컬 JSON만 다루며 실제 전송 계층이 없다.
LOCAL_WRITE_ALLOW |= {f"mcp__pweh-espprobe__{name}" for name in (
    "espprobe_connect", "espprobe_self_test", "espprobe_release_all", "espprobe_disconnect")}
# 상태 조회의 기존 자동 허용을 유지한다. 선택 case_id의 종료 기록만 정리하며 기기·작업은 실행하지 않는다.
LOCAL_WRITE_ALLOW |= {f"mcp__pweh-{prefix}__{prefix}_{suffix}"
                      for prefix in ("uart", "openocd", "sigrok", "jtagulator", "esp", "forensics")
                      for suffix in ("job_status", "jobs")}
#: architecture §6 에 시그니처(모든 인자)까지 적어야 하는 서버. 다른 서버는 도구 이름만 있으면 된다.
FULL_SIGNATURE_SERVERS = ("pweh-uart", "pweh-case")
#: 서버 이름 → mcp-servers/ 아래 디렉터리. 기본 규칙('pweh-esp' → 'esp-mcp')을 벗어나는 서버만 적는다.
SERVER_DIR_OVERRIDES: dict[str, str] = {}
#: 문서에 백틱으로 적는 안전 규칙 id 의 접두(`linux.exec-nonsystem`, `esp.cmd.flash-write` 등). 분류기가 새 접두를 쓰면 여기에 더한다.
RULE_ID_PREFIXES = ("linux", "uboot", "uart", "openocd", "sigrok", "console", "jtagulator", "esp", "emu")


def _catalog() -> dict:
    return json.loads(CATALOG.read_text(encoding="utf-8"))


def _cli_servers() -> dict:
    """pweh.cli.SERVERS (mcp-config 가 .mcp.json 을 만드는 기준)."""
    sys.path.insert(0, str(REPO / "src"))
    from pweh.cli import SERVERS

    return SERVERS


def _server_dir(server: str) -> str:
    """서버 이름 → mcp-servers/ 아래 디렉터리 ('pweh-esp' → 'esp-mcp')."""
    return SERVER_DIR_OVERRIDES.get(server) or f"{server.removeprefix('pweh-')}-mcp"


def _load_dump_module():
    spec = importlib.util.spec_from_file_location("dump_tool_catalog", REPO / "scripts" / "dump_tool_catalog.py")
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(mod)
    return mod


def test_catalog_matches_live_servers():
    """카탈로그가 낡으면 Skill·문서·권한 규칙이 모두 낡은 기준을 따른다 → 서버를 바꾸면 dump_tool_catalog.py 를 다시 돌린다."""
    mod = _load_dump_module()
    sys.path.insert(0, str(REPO / "src"))
    live = anyio.run(mod.collect)
    saved = _catalog()
    assert set(live) == set(saved)
    for server, info in live.items():
        assert not info.get("error"), f"{server} 로드 실패: {info.get('error')}"
        lt = {t["name"]: t for t in info["tools"]}
        st = {t["name"]: t for t in saved[server]["tools"]}
        assert set(lt) == set(st), f"{server}: 도구 목록이 다름 → scripts/dump_tool_catalog.py 실행"
        for name, t in lt.items():
            # description 도 비교한다: Skill·문서는 카탈로그의 설명(예: 전원 투입 순서, 반환 필드)을 근거로 맞춘다
            for key in ("params", "annotations", "meta", "description"):
                assert t[key] == st[name][key], f"{server}.{name}.{key} 가 카탈로그와 다름 → scripts/dump_tool_catalog.py 실행"


def test_server_lists_agree():
    """서버 목록은 한 기준을 따른다: 카탈로그 = pweh.cli.SERVERS(mcp-config) = dump_tool_catalog.SERVERS = .mcp.json - rea.
    서버 이름 'pweh-<x>' 의 모듈은 '<x>_mcp.server', 디렉터리는 mcp-servers/<x>-mcp (예외는 SERVER_DIR_OVERRIDES)."""
    cat = _catalog()
    cli = _cli_servers()
    assert set(cat) == set(cli) == set(_load_dump_module().SERVERS), "서버를 더하면 cli.SERVERS·dump_tool_catalog.SERVERS·카탈로그를 함께"
    mcp = json.loads((REPO / ".mcp.json").read_text(encoding="utf-8"))["mcpServers"]
    assert set(mcp) == set(cli) | {"rea"}, ".mcp.json 은 pweh mcp-config 로 다시 만든다"
    assert set(FULL_ALLOW_SERVERS) <= set(cat) and set(FULL_SIGNATURE_SERVERS) <= set(cat)
    for server, info in cat.items():
        d = _server_dir(server)
        package = info["module"].split(".")[0]
        assert package == d.replace("-", "_"), f"{server}: 모듈 {info['module']} 와 디렉터리 {d} 가 맞지 않음 (SERVER_DIR_OVERRIDES)"
        assert (REPO / "mcp-servers" / d / package).is_dir(), f"{server}: mcp-servers/{d}/{package} 없음"


def test_settings_permissions_follow_catalog_rule():
    cat = _catalog()
    rea = {t["name"]: t for t in json.loads(REA.read_text(encoding="utf-8"))}
    settings = json.loads((REPO / ".claude" / "settings.json").read_text(encoding="utf-8"))
    allow, ask = settings["permissions"]["allow"], settings["permissions"]["ask"]
    assert set(FULL_ALLOW_SERVERS) <= set(cat)
    expected = {f"mcp__{server}__*" for server in FULL_ALLOW_SERVERS} | LOCAL_WRITE_ALLOW
    for server, info in cat.items():
        if server in FULL_ALLOW_SERVERS:
            continue
        for t in info["tools"]:
            if (t.get("annotations") or {}).get("readOnlyHint"):
                expected.add(f"mcp__{server}__{t['name']}")
    assert {r for r in allow if r.startswith("mcp__pweh-")} == expected
    rui = {f"mcp__{s}__{t['name']}" for s, info in cat.items() for t in info["tools"]
           if (t.get("meta") or {}).get("anthropic/requiresUserInteraction")}
    assert RAW_ASK | rui <= set(ask)
    assert not set(allow) & set(ask)
    for name in REA_RUNTIME_ASK:
        assert f"mcp__rea__{name}" in ask, name
    for rule in allow + ask:
        if rule.startswith("mcp__rea__"):
            assert rule.split("__", 2)[2] in rea, rule
    assert "mcp__rea__get_call_graph" in allow
    servers = json.loads((REPO / ".mcp.json").read_text(encoding="utf-8"))["mcpServers"]
    assert set(settings["enabledMcpjsonServers"]) == set(servers)


def test_requires_user_interaction_claims_match():
    cat = _catalog()
    tools = {t["name"]: t for info in cat.values() for t in info["tools"]}
    rui = sorted(n for n, t in tools.items() if (t.get("meta") or {}).get("anthropic/requiresUserInteraction"))
    destructive = sorted(n for n, t in tools.items() if (t.get("annotations") or {}).get("destructiveHint"))
    # 정책(pweh.mcpkit.META_REQUIRE_HUMAN): 항상 파괴적인 도구(ANN_DESTRUCTIVE)에만, 그리고 그런 도구에는 빠짐없이 붙인다.
    # 한쪽만 빠지면(메타를 지우거나, 파괴적 도구를 새로 만들며 메타를 잊음) 여기서 걸린다.
    assert rui and rui == destructive, f"requiresUserInteraction {rui} ≠ destructiveHint {destructive}"
    for doc in ("safety.md", "mcp-setup.md"):
        items: list[str] = []
        for line in (REPO / "docs" / doc).read_text(encoding="utf-8").splitlines():
            if re.match(r"^\s*- ", line) or not items:
                items.append(line)
            else:
                items[-1] += " " + line
        para = next(p for p in items if "requiresUserInteraction" in p)
        named = sorted({n for n in re.findall(r"`([a-z][a-z0-9_]*)`", para) if n in tools})  # 카탈로그의 도구 이름만
        assert named == rui, doc


def _arch_sections() -> dict[str, str]:
    arch = (REPO / "docs" / "architecture.md").read_text(encoding="utf-8")
    heads = list(re.finditer(r"^### 6\.\d+ (pweh-[a-z][a-z0-9-]*)", arch, re.M))
    out = {}
    for i, m in enumerate(heads):
        end = heads[i + 1].start() if i + 1 < len(heads) else arch.index("## 7.")
        out[m.group(1)] = arch[m.start():end]
    return out


def test_architecture_lists_every_tool_and_full_uart_signatures():
    cat = _catalog()
    sections = _arch_sections()
    for server, info in cat.items():
        assert server in sections, f"architecture §6 에 '### 6.N {server}' 절 없음"
        sec = sections[server]
        for t in info["tools"]:
            assert f"`{t['name']}(" in sec or f"`{t['name']}`" in sec, f"architecture §6 {server}: {t['name']} 없음"
            if server not in FULL_SIGNATURE_SERVERS:
                continue
            m = re.search(r"`" + re.escape(t["name"]) + r"\(([^`]*)\)", sec)
            if not m or "…" in m.group(1):
                continue
            for p in t["params"]:
                assert re.search(r"(?<![A-Za-z0-9_])" + re.escape(p["name"]) + r"(?![A-Za-z0-9_])", m.group(1)), \
                    f"{t['name']} 시그니처에 {p['name']} 없음"


def test_server_readmes_exist_and_list_tools():
    cat = _catalog()
    for server, info in cat.items():
        d = _server_dir(server)
        readme = (REPO / "mcp-servers" / d / "README.md").read_text(encoding="utf-8")
        for t in info["tools"]:
            assert f"`{t['name']}(" in readme or f"`{t['name']}`" in readme, f"{d}/README.md: {t['name']} 없음"


def test_doc_links_and_repo_paths_resolve():
    roots = ("docs/", "src/", "mcp-servers/", "tests/", "scripts/", "skills/", "orchestrator/", "schemas/", "examples/", ".claude/", ".agents/")
    problems = []
    for f in DOCS:
        text = f.read_text(encoding="utf-8")
        for m in re.finditer(r"\[[^\]]*\]\(([^)\s]+)\)", text):
            target = m.group(1)
            if re.match(r"[a-z]+://|mailto:", target):
                continue
            path = target.split("#", 1)[0]
            if path and not (f.parent / path).exists():
                problems.append(f"{f.relative_to(REPO)}: {target}")
        for m in re.finditer(r"`([^`\s]+)`", text):
            s = m.group(1)
            if not s.startswith(roots) or any(ch in s for ch in "<>*{}$…") or "NNN" in s:
                continue
            s = re.sub(r":\d+$", "", s.split("::")[0].split("#")[0].rstrip(".,)"))
            if not (REPO / s).exists():
                problems.append(f"{f.relative_to(REPO)}: `{s}`")
    assert not problems, problems


def test_documented_pweh_commands_parse():
    sys.path.insert(0, str(REPO / "src"))
    from pweh.cli import build_parser

    parser = build_parser()
    # 하위 명령 목록은 파서에서 얻는다(새 하위 명령의 문서 예시도 검사 대상이 된다)
    subcommands = next(a.choices for a in parser._actions if isinstance(a, argparse._SubParsersAction))
    assert {"doctor", "approve", "deny", "case", "mcp-config"} <= set(subcommands)
    alternation = "|".join(re.escape(c) for c in sorted(subcommands, key=len, reverse=True))
    cmd_re = re.compile(r"\bpweh ((?:" + alternation + r")\b[^`#|>&;)]*)")
    for f in DOCS:
        for line in f.read_text(encoding="utf-8").splitlines():
            for m in cmd_re.finditer(line):
                argv = [a for a in shlex.split(re.sub(r"<[^>]+>", "X", m.group(1).strip())) if a not in ("…", "...")]
                if argv in (["approve"], ["deny"]):  # 본문 속 명령 이름 언급
                    continue
                try:
                    parser.parse_args(argv)
                except SystemExit:  # pragma: no cover - 실패 메시지용
                    pytest.fail(f"{f.relative_to(REPO)}: pweh {' '.join(argv)} 를 해석하지 못함")


# ---------------------------------------------------------------------------
# 문서의 분류·반환값 주장 ↔ 코드 (기대값은 코드에서 얻는다)
# ---------------------------------------------------------------------------

ARCH = REPO / "docs" / "architecture.md"
SAFETY = REPO / "docs" / "safety.md"
UART_README = REPO / "mcp-servers" / "uart-mcp" / "README.md"
OPENOCD_README = REPO / "mcp-servers" / "openocd-mcp" / "README.md"
JTAG_README = REPO / "mcp-servers" / "jtagulator-mcp" / "README.md"
UBOOT_REF = REPO / "docs" / "references" / "uboot-and-boot-console.md"
UART_PKG = REPO / "mcp-servers" / "uart-mcp" / "uart_mcp"


def _text(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _word(name: str) -> str:
    return r"(?<![A-Za-z0-9_])" + re.escape(name) + r"(?![A-Za-z0-9_])"


def _table_row(path: Path, tool: str) -> str:
    """표에서 `tool(` 로 시작하는 행."""
    for line in _text(path).splitlines():
        if line.startswith(f"| `{tool}("):
            return line
    raise AssertionError(f"{path.relative_to(REPO)}: {tool} 행 없음")


def _function_source(path: Path, name: str) -> str:
    """모듈 최상위 함수의 소스 (문자열 리터럴에서 기대값을 뽑는다)."""
    src = _text(path)
    for node in ast.parse(src).body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == name:
            return ast.get_source_segment(src, node) or ""
    raise AssertionError(f"{path.name}: 함수 {name} 없음")


def _login_statuses() -> set[str]:
    """console.login 이 돌려줄 수 있는 status 값."""
    src = _function_source(UART_PKG / "console.py", "login")
    statuses = set(re.findall(r'result\(\s*"([a-z_]+)"', src))
    statuses |= set(re.findall(r'result\(\s*"[a-z_]+"\s+if\s+[^,]+?\s+else\s+"([a-z_]+)"', src))
    if re.search(r"result\(\s*res\.kind", src):  # 대기 결과(timeout/disconnected/cancelled)를 그대로 status 로 돌려준다
        kinds = set(re.findall(r'WaitResult\(\s*"([a-z_]+)"', _text(UART_PKG / "session.py")))
        statuses |= kinds - {"prompt", "expect"}
    return statuses


def _interrupt_outcomes() -> set[str]:
    """console.interrupt 가 돌려줄 수 있는 outcome 값."""
    src = _function_source(UART_PKG / "console.py", "interrupt")
    return set(re.findall(r'outcome\s*=\s*"([a-z_]+)"', src)) | set(re.findall(r'"outcome":\s*"([a-z_]+)"', src))


def test_uart_docs_list_every_login_status_and_interrupt_outcome():
    statuses, outcomes = _login_statuses(), _interrupt_outcomes()
    # 추출이 동작하는지부터 (console.py 구조가 바뀌면 추출식을 고친다)
    assert {"ok", "already_logged_in", "context_unknown", "uboot_password_prompt", "username_required", "timeout"} <= statuses, statuses
    assert {"prompt", "uboot_password", "window_expired", "kernel", "linux"} <= outcomes, outcomes
    for path in (ARCH, UART_README):
        login_row, intr_row = _table_row(path, "shell_login"), _table_row(path, "uboot_interrupt")
        missing = sorted(s for s in statuses if not re.search(_word(s), login_row))
        assert not missing, f"{path.relative_to(REPO)} shell_login 행에 status 없음: {missing}"
        missing = sorted(o for o in outcomes if not re.search(_word(o), intr_row))
        assert not missing, f"{path.relative_to(REPO)} uboot_interrupt 행에 outcome 없음: {missing}"


# uart 도구 → architecture §6.2 행에 반드시 적을 반환 필드. 필드 이름이 코드에서 바뀌면 문서와 이 목록을 함께 고친다.
UART_CONTRACT_FIELDS = {
    "uart_open": ("inherited_last_command",),
    "uart_sessions": ("device_ready", "device_busy_reason", "pending_uncertain", "last_uboot_command"),
    "uboot_interrupt": ("new_boot_seen", "already_at_prompt", "keys_sent"),
    "uboot_printenv": ("flash_size", "flash_size_source", "complete", "tracked"),
    "uboot_info": ("has", "has_via", "partitions", "safe_ram_addr"),
    "uboot_dump_start": ("estimated_seconds", "resume_from_chunk"),
    "shell_dump_start": ("resume_from_chunk",),
    "uart_capture_boot": ("excerpt_path", "stopped_by", "captured_bytes"),
}


def test_uart_rows_name_contract_fields_present_in_code():
    code = "\n".join(_text(p) for p in sorted(UART_PKG.glob("*.py")))
    for tool, fields in UART_CONTRACT_FIELDS.items():
        row = _table_row(ARCH, tool)
        for f in fields:
            assert f'"{f}"' in code, f"uart_mcp 코드에 {f!r} 필드가 없음 — 문서와 이 목록을 함께 고친다"
            assert re.search(_word(f), row), f"architecture §6.2 {tool} 행에 {f} 없음"
    sec = _arch_sections()["pweh-uart"]
    guard = _text(UART_PKG / "guard.py")
    for f in ("env_refs", "repeat_of"):  # 승인 지문에 들어가는 U-Boot 실행 의미
        assert f'"{f}"' in guard and f"`{f}`" in sec, f
    readme = _text(UART_README)
    for f in ("inherited_last_command", "device_ready", "device_busy_reason", "new_boot_seen", "flash_size_source", "has_via",
              "env_refs", "repeat_of"):
        assert re.search(_word(f), readme), f"uart-mcp README 에 {f} 없음"


def test_shell_dump_device_rule_matches_docs():
    from uart_mcp.server import SHELL_DEV_RE

    for ok in ("/dev/mtd3", "/dev/mtd3ro", "/dev/mtdblock2", "/dev/mmcblk0", "/dev/mmcblk0p1", "/dev/mmcblk0boot0",
               "/dev/ubi0_1", "/dev/ubiblock0_1", "/dev/sda", "/dev/sda1", "/dev/nand0"):
        assert SHELL_DEV_RE.match(ok), ok
    for bad in ("/dev/watchdog", "/dev/watchdog0", "/dev/mem", "/dev/kmem", "/dev/port", "/dev/ttyS0"):
        assert not SHELL_DEV_RE.match(bad), bad
    for path in (ARCH, UART_README):
        row = _table_row(path, "shell_dump_start")
        for form in ("mtdN", "mtdblockN", "mmcblkN", "ubiX_Y", "ubiblockX_Y", "sdX", "nand", "/dev/watchdog"):
            assert form in row, f"{path.relative_to(REPO)} shell_dump_start 행에 {form} 없음"


def _linux(cmd: str):
    from pweh.safety import classify_linux

    return classify_linux(cmd)


def _uboot(cmd: str, env: dict[str, str] | None = None, last: str | None = None):
    from pweh.safety import UBootContext, classify_uboot

    return classify_uboot(cmd, ctx=UBootContext(env=env, last_command=last))


def _uart(payload: str, ctx: str = "uboot", **state):
    """새 LineAssembler 로 페이로드 하나를 계획했을 때의 분류 (uart_mcp.guard)."""
    from pweh.safety import LineAssembler
    from uart_mcp.guard import GuardState, plan_payload

    return plan_payload(payload.encode("latin-1"), LineAssembler(), GuardState(context=ctx, **state)).classification


def _openocd(text: str):
    from openocd_mcp.guard import classify_command

    return classify_command(text)


def _probe(text: str):
    from jtagulator_mcp.classify import classify_uart_probe

    return classify_uart_probe(text.encode("latin-1"))


D_, M_, I_ = "destructive", "modify", "interact"
_MW = "mw.b 0x42000000 0 1"

# (문서, 문서에 있어야 할 예시, 분류 호출, 기대 위험도, 규칙 id 에 들어갈 문자열 또는 None).
# 분류기가 바뀌어 예시의 결과가 달라지면 문서를 고친다(한계로 적은 예시도 마찬가지 — 고쳐졌으면 한계에서 뺀다).
DOC_CLAIMS = [
    # Linux: 내용을 확인할 수 없는 실행
    (SAFETY, "`./x`", lambda: _linux("./x"), D_, "linux.exec-nonsystem"),
    (SAFETY, "`/bin/../tmp/x`", lambda: _linux("/bin/../tmp/x"), D_, "linux.exec-nonsystem"),
    (SAFETY, "`/tmp/nohup ls`", lambda: _linux("/tmp/nohup ls"), D_, "linux.exec-nonsystem"),
    (ARCH, "`/tmp/cat` 은 `cat` 이 아니다", lambda: _linux("/tmp/cat /etc/passwd"), D_, "linux.exec-nonsystem"),
    (SAFETY, "`PATH=/tmp:$PATH ls`", lambda: _linux("PATH=/tmp:$PATH ls"), D_, "linux.env-hijack"),
    (SAFETY, "`env LD_PRELOAD=/tmp/x.so ls`", lambda: _linux("env LD_PRELOAD=/tmp/x.so ls"), D_, "linux.env-hijack"),
    (SAFETY, "`export PATH=/tmp`", lambda: _linux("export PATH=/tmp"), D_, "linux.env-hijack"),
    (SAFETY, "`sh < f`", lambda: _linux("sh < f"), D_, "linux.script"),
    (SAFETY, "`ash -s < f`", lambda: _linux("ash -s < f"), D_, "linux.script-stdin"),
    (SAFETY, "`mount --bind`", lambda: _linux("mount --bind /tmp/x /bin/ls"), D_, "linux.mount.bind"),
    (SAFETY, "`chroot`", lambda: _linux("chroot /mnt /bin/sh"), D_, "linux.chroot"),
    (SAFETY, "`linux.write.system`", lambda: _linux("echo x > /etc/passwd"), D_, "linux.write.system"),
    (SAFETY, "일반 파일 쓰기는 MODIFY", lambda: _linux("echo x > /tmp/y"), M_, "linux.write.file"),
    (SAFETY, "`sh -c ls`", lambda: _linux("sh -c ls"), I_, None),
    # Linux: 여는 것만으로 부작용이 있는 장치, 조회 예외
    (SAFETY, "`/dev/watchdog*`", lambda: _linux("cat /dev/watchdog"), M_, "linux.read.side-effect-device"),
    (SAFETY, "`lsof`", lambda: _linux("lsof /dev/watchdog"), I_, None),
    (SAFETY, "`fdisk -l`", lambda: _linux("fdisk -l"), I_, "linux.fdisk.list"),
    (SAFETY, "`[ -e /dev/mtd0 ]`", lambda: _linux("[ -e /dev/mtd0 ]"), I_, None),
    # Linux: §3.4 cwd 추적 (같은 줄의 cd 반영, 세션 cd 는 uart guard 가 추적) — 시작 디렉터리를 모를 때만 MODIFY
    (SAFETY, "`cd /usr/bin && cp /tmp/x md5sum`", lambda: _linux("cd /usr/bin && cp /tmp/x md5sum"), D_, "linux.write.system"),
    (SAFETY, "`md5sum /dev/mtd3`", lambda: _linux("md5sum /dev/mtd3"), I_, None),
    (SAFETY, "`cd /bin; echo … > y`", lambda: _linux("cd /bin; echo x > y"), D_, "linux.write.system"),
    (SAFETY, "`linux_cwd`", lambda: _linux("echo x > y"), M_, "linux.write.file"),
    (SAFETY, "이름만 쓴 `y`", lambda: _linux("y"), M_, "linux.unknown"),
    # U-Boot
    (SAFETY, "`time sf erase …`", lambda: _uboot("time sf erase 0 100"), D_, "uboot.time>"),
    (SAFETY, "`env run <변수>`", lambda: _uboot("env run x", env={"x": "sf erase 0 100"}), D_, "uboot.env.run>"),
    (SAFETY, "`crc32 <주소> <크기> <대상>`", lambda: _uboot("crc32 0x42000000 0x10000 0x43000000"), M_, "uboot.crc32.store"),
    (SAFETY, "`uboot.empty`", lambda: _uboot(""), I_, "uboot.empty"),
    # 콘솔 송신 (uart_mcp.guard)
    (SAFETY, "`uart.repeat-unknown`", lambda: _uart("\r", last_command_known=False), D_, "uart.repeat-unknown"),
    (SAFETY, "`inherited_last_command`", lambda: _uart("\r", last_command="setenv baudrate 57600"), M_, None),
    (SAFETY, "`uart.device-busy`", lambda: _uart("printenv\rversion\r"), D_, "uart.device-busy"),
    (SAFETY, "`uart.high-bit`", lambda: _uart("pr\xe9ntenv\r"), D_, "uart.high-bit"),
    (SAFETY, "다음 호출의 `\\n`", lambda: _uart("\n", prev_char="\r", last_command=_MW), D_, None),
    # OpenOCD (openocd_mcp.guard.classify_command)
    (SAFETY, "`expr $x`", lambda: _openocd("expr $x"), D_, "expr-double-subst"),
    (SAFETY, "`if [catch {halt}] …`", lambda: _openocd("if [catch {halt}] {echo x}"), D_, None),
    (SAFETY, "`expr {1 + 2}`", lambda: _openocd("expr {1 + 2}"), I_, None),
    (SAFETY, "`if {[catch {halt}]} …`", lambda: _openocd("if {[catch {halt}]} {echo x}"), M_, None),
    (SAFETY, "`telnet port N`", lambda: _openocd("telnet port 4444"), D_, "command-server"),
    (ARCH, "값이 `disabled` 면 MODIFY", lambda: _openocd("telnet port disabled"), M_, None),
    (SAFETY, "`cpu0 mww …`", lambda: _openocd("cpu0 mww 0 0"), D_, None),
    (ARCH, "`cpu0 read_memory …` 는 MODIFY", lambda: _openocd("cpu0 read_memory 0x0 32 1"), M_, None),
    (SAFETY, "`lsort -command mww …`", lambda: _openocd("lsort -command mww {0 0}"), D_, None),
    (SAFETY, "`if {$x} {halt}`", lambda: _openocd("if {$x} {halt}"), D_, None),
    (SAFETY, "`reset mww …`", lambda: _openocd("reset mww 0x80000000 1"), M_, None),
    (SAFETY, "`cpu0 $x …`", lambda: _openocd("cpu0 $x 0 0"), M_, None),
    # JTAGulator UART 프로브
    (SAFETY, "`_erase X\\rflash`", lambda: _probe("_erase X\rflash"), D_, None),
    (SAFETY, "기본 프로브 `\\r`(CR)는 INTERACT", lambda: _probe("\r"), I_, None),
    (JTAG_README, "CR 하나는 코어 분류기에서 INTERACT(`uboot.empty`)", lambda: _probe("\r"), I_, "uboot.empty"),
    (JTAG_README, "`uart.repeat-unknown` 으로 거부한다", lambda: _uart("\r", last_command_known=False), D_, "uart.repeat-unknown"),
]


@pytest.mark.parametrize("doc,snippet,classify,risk,rule", DOC_CLAIMS, ids=[f"{d.name}:{s}" for d, s, *_ in DOC_CLAIMS])
def test_documented_classifier_claims_hold(doc, snippet, classify, risk, rule):
    assert snippet in _text(doc), f"{doc.relative_to(REPO)} 에 예시 {snippet} 가 없음 — 문서를 바꿨으면 이 표도 고친다"
    c = classify()
    assert c.risk.label == risk, (snippet, c)
    assert rule is None or rule in c.rule_id, (snippet, c)


def test_fixed_gaps_are_not_documented_as_open():
    # 시스템 디렉터리 밖 경로 실행은 이제 DESTRUCTIVE — '경로 실행은 MODIFY' 라는 옛 한계를 다시 적지 않는다
    assert _linux("./x").risk.label == D_ and _linux("nohup /tmp/x").risk.label == D_
    safety = _text(SAFETY)
    assert "경로로 직접 실행하는 프로그램은 예외" not in safety
    assert not re.search(r"경로로 직접 실행하는 프로그램[^\n]*\n?[^\n]*MODIFY\(기본 허용\)", safety)
    # 코어도 env run / time 을 안쪽 명령으로 분류한다
    assert _uboot("env run x", env={"x": "saveenv"}).risk.label == D_ and _uboot("time saveenv").risk.label == D_
    assert "코어는 각각 MODIFY" not in _text(UART_README)
    # 상대 경로 쓰기는 이제 cwd(같은 줄의 cd, 세션이 추적한 linux_cwd)를 반영한다
    assert _linux("cd /usr/bin && cp /tmp/x md5sum").risk.label == D_
    assert "현재 디렉터리(cwd)를 추적하지 않는다" not in safety
    # 코어 classify_openocd 는 이제 '\n' 으로만 줄을 나눈다
    assert "코어는 `splitlines()` 로 `#` 줄을 지우는데" not in _text(OPENOCD_README)


def test_documented_rule_ids_exist_in_code():
    sources = [REPO / "src" / "pweh" / "safety" / "classifiers.py", *sorted(REPO.glob("mcp-servers/*/*_mcp/*.py"))]
    code = "\n".join(_text(p) for p in sources)
    config = _text(REPO / "orchestrator" / "pipeline-config.yaml")
    pat = re.compile(r"`((?:" + "|".join(map(re.escape, RULE_ID_PREFIXES)) + r")\.[A-Za-z0-9_.\-]+)`")
    missing = []
    for doc in (SAFETY, ARCH, *sorted(REPO.glob("mcp-servers/*/README.md"))):
        for m in pat.finditer(_text(doc)):
            tok = m.group(1)
            if tok.endswith(".py"):
                continue
            if re.search(r"""["']""" + re.escape(tok) + r"""["']""", code):
                continue
            # 설정 키(`sigrok.capture_drivers_allow`, `uart.read_buffer_bytes`)는 pipeline-config.yaml 에 있어야 한다
            if re.search(r"(?m)^[#\s]*" + re.escape(tok.rsplit(".", 1)[1]) + r":", config):
                continue
            missing.append(f"{doc.relative_to(REPO)}: {tok}")
    assert not missing, f"문서의 규칙 id/설정 키가 코드에 없음: {missing}"


# 옛 전원 순서(도구를 부르고 사람이 그 뒤에 껐다 켬)의 표현. 지금 순서: 사람이 전원을 먼저 끄고 '준비' → 도구 호출 → 호출이 시작되면 켬.
OLD_POWER_ORDER = ("호출 직후 사람이", "직후 사람이 전원", "요청한 직후 호출", "요청 직후 →", "사람이 전원을 껐다 켜는 동안")


def test_power_on_order_is_off_first_then_call_then_on():
    bad = [f"{d.relative_to(REPO)}: {p}" for d in (*DOCS, UBOOT_REF) for p in OLD_POWER_ORDER if p in _text(d)]
    assert not bad, f"옛 전원 순서가 남아 있음: {bad}"
    for tool in ("uboot_interrupt", "uart_capture_boot", "uart_detect_baud"):
        row = _table_row(ARCH, tool)
        assert "먼저 꺼" in row and "호출이 시작되면" in row, f"architecture §6.2 {tool}: 전원 투입 순서"
    readme = _text(UART_README)
    calls = readme[readme.index("## 3. 일반적인 호출 순서"):readme.index("## 4.")]
    assert "먼저 꺼" in calls and "호출이 시작되면" in calls, "uart-mcp README §3: 전원 투입 순서"


def test_ram_only_init_sh_needs_explicit_consent_everywhere():
    ref = _text(UBOOT_REF)
    s12 = ref[ref.index("## 12."):ref.index("## 13.")]
    scope = next(line for line in ref.splitlines() if line.startswith("> **범위**"))
    safety = _text(SAFETY)
    rule7 = safety[safety.index("\n7. "):safety.index("\n8. ")]
    master = _text(REPO / "orchestrator" / "master-prompt.md")
    rules = master[master.index("\n## 1."):master.index("\n## 2.")]  # §1 절대 규칙 안의 규칙 3 만 (다른 절의 번호 목록과 섞지 않는다)
    rule3 = rules[rules.index("\n3. "):rules.index("\n4. ")]
    for where, text in (("uboot-and-boot-console.md §12", s12), ("uboot-and-boot-console.md 범위", scope),
                        ("safety.md §4 규칙 7", rule7), ("master-prompt.md §1 규칙 3", rule3)):
        assert "init=/bin/sh" in text and "동의" in text and "RAM" in text, where
    assert "saveenv" in s12 and "uart-shell-acquisition" in s12
