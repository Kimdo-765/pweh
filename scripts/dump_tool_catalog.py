#!/usr/bin/env python3
"""구현된 PWEH MCP 서버들의 실제 도구 목록을 수집해 카탈로그를 만든다.

  .venv/bin/python scripts/dump_tool_catalog.py            # docs/references/pweh-mcp-tools.{json,md} 갱신
  .venv/bin/python scripts/dump_tool_catalog.py --check    # .claude/settings.json 규칙과 Skill 문서의 도구 이름 검증

Skill/문서/권한 규칙은 이 카탈로그(=서버가 실제로 list_tools 로 내보내는 이름)를 기준으로 맞춘다.
"""

from __future__ import annotations

import argparse
import importlib
import json
import re
import sys
from pathlib import Path
from typing import Any

import anyio

REPO = Path(__file__).resolve().parents[1]
SERVERS = {
    "pweh-case": "case_mcp.server",
    "pweh-uart": "uart_mcp.server",
    "pweh-openocd": "openocd_mcp.server",
    "pweh-sigrok": "sigrok_mcp.server",
    "pweh-jtagulator": "jtagulator_mcp.server",
    "pweh-fwtriage": "fwtriage_mcp.server",
    "pweh-esp": "esp_mcp.server",
    "pweh-forensics": "forensics_mcp.server",
    "pweh-emu": "emu_mcp.server",
    "pweh-espprobe": "espprobe_mcp.server",
}


async def collect() -> dict[str, Any]:
    from mcp import Client

    out: dict[str, Any] = {}
    for name, module in SERVERS.items():
        try:
            mod = importlib.import_module(module)
            server = getattr(mod, "server")
        except Exception as exc:  # 아직 구현되지 않은 서버
            out[name] = {"error": f"{type(exc).__name__}: {exc}", "tools": []}
            continue
        async with Client(server) as c:
            tools = (await c.list_tools()).tools
        rows = []
        for t in tools:
            schema = getattr(t, "input_schema", None) or getattr(t, "inputSchema", None) or {}
            props = schema.get("properties", {})
            required = set(schema.get("required", []))
            params = []
            for pname, p in props.items():
                typ = p.get("type") or "/".join(x.get("type", "?") for x in p.get("anyOf", []) if isinstance(x, dict)) or "any"
                params.append({"name": pname, "type": typ, "required": pname in required, "default": p.get("default")})
            ann = t.annotations.model_dump(exclude_none=True, by_alias=True) if t.annotations else {}
            rows.append({
                "name": t.name,
                "description": (t.description or "").strip(),
                "params": params,
                "annotations": ann,
                "meta": getattr(t, "meta", None) or getattr(t, "_meta", None),
            })
        out[name] = {"module": module, "tools": rows}
    return out


def write_catalog(cat: dict[str, Any]) -> None:
    ref = REPO / "docs" / "references"
    (ref / "pweh-mcp-tools.json").write_text(json.dumps(cat, ensure_ascii=False, indent=1) + "\n", encoding="utf-8")
    lines = ["# PWEH MCP 도구 카탈로그 (자동 생성)", "",
             "`scripts/dump_tool_catalog.py` 가 각 서버의 list_tools 결과로 생성한다. 손으로 고치지 않는다.", ""]
    for server, info in cat.items():
        lines.append(f"## {server}")
        lines.append("")
        if info.get("error"):
            lines.append(f"(로드 실패: {info['error']})")
            lines.append("")
            continue
        for t in info["tools"]:
            sig = ", ".join(f"{p['name']}{'' if p['required'] else '?'}" for p in t["params"])
            hints = []
            ann = t.get("annotations") or {}
            if ann.get("readOnlyHint"):
                hints.append("읽기전용")
            if ann.get("destructiveHint"):
                hints.append("파괴적")
            if (t.get("meta") or {}).get("anthropic/requiresUserInteraction"):
                hints.append("매번 사람 확인")
            first = t["description"].split("\n")[0][:220]
            lines.append(f"- **`{t['name']}({sig})`**{' — [' + ', '.join(hints) + ']' if hints else ''}  ")
            lines.append(f"  {first}")
        lines.append("")
    (ref / "pweh-mcp-tools.md").write_text("\n".join(lines) + "\n", encoding="utf-8")


def check(cat: dict[str, Any]) -> int:
    """settings.json 의 mcp__ 규칙과 Skill/문서의 도구 이름이 실제 도구와 맞는지 검사."""
    problems: list[str] = []
    known: dict[str, set[str]] = {s: {t["name"] for t in info.get("tools", [])} for s, info in cat.items()}
    rea_path = REPO / "docs" / "references" / "rea-mcp-tools.json"
    if rea_path.exists():
        known["rea"] = {t["name"] for t in json.loads(rea_path.read_text(encoding="utf-8"))}
    settings = json.loads((REPO / ".claude" / "settings.json").read_text(encoding="utf-8"))
    for bucket in ("allow", "ask", "deny"):
        for rule in settings.get("permissions", {}).get(bucket, []):
            m = re.fullmatch(r"mcp__([A-Za-z0-9_-]+)__([A-Za-z0-9_*-]+)", rule)
            if not m:
                continue
            server, tool = m.group(1), m.group(2)
            if server not in known:
                problems.append(f"settings.{bucket}: 알 수 없는 서버 {server} ({rule})")
                continue
            if "*" in tool:
                pat = re.compile("^" + re.escape(tool).replace("\\*", ".*") + "$")
                if not any(pat.match(x) for x in known[server]):
                    problems.append(f"settings.{bucket}: 일치하는 도구 없음 {rule}")
            elif tool not in known[server]:
                problems.append(f"settings.{bucket}: 없는 도구 {rule}")
    # Skill/문서 안의 도구 이름 검사 (pweh 접두어를 가진 이름만).
    # - `name(` 형태는 도구 호출로 보고 반드시 실제 도구여야 한다.
    # - 백틱 단독 `name` 은 실제 인자/필드 이름이나 상태 값일 수 있으므로, 알려진 인자 이름·허용 단어는 건너뛴다.
    prefixes = ("uart_", "uboot_", "shell_", "openocd_", "sigrok_", "jtagulator_", "fw_", "case_", "report_", "pipeline_", "approval", "schema_get", "esp_", "forensics_", "emu_", "espprobe_")
    all_pweh = set().union(*[v for k, v in known.items() if k != "rea"])
    param_names: set[str] = set()
    for info in cat.values():
        for t in info.get("tools", []):
            param_names.update(p["name"] for p in t.get("params", []))
    allow_words = {"approval_required", "approval_id", "approval_pending", "approval_mismatch", "case_id", "case_dir", "fw_identify_result"}
    docs = list((REPO / "skills").glob("*/*.md")) + [REPO / "orchestrator" / "master-prompt.md"]
    for doc in docs:
        text = doc.read_text(encoding="utf-8")
        called = set(re.findall(r"(?<![A-Za-z0-9_.])([a-z][a-z0-9_]+)\(", text))
        backticked = set(re.findall(r"`([a-z][a-z0-9_]+)`", text))
        for name in sorted(called | backticked):
            if not name.startswith(prefixes) or name in all_pweh or name.endswith("_"):
                continue
            if name not in called and (name in param_names or name in allow_words):
                continue
            problems.append(f"{doc.relative_to(REPO)}: 존재하지 않는 도구 이름 `{name}`")
    for p in problems:
        print("✗", p)
    print(f"검사 완료: 문제 {len(problems)}건")
    return 1 if problems else 0


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--check", action="store_true")
    args = ap.parse_args()
    sys.path.insert(0, str(REPO / "src"))
    cat = anyio.run(collect)
    if args.check:
        return check(cat)
    write_catalog(cat)
    for s, info in cat.items():
        print(f"{s}: {len(info.get('tools', []))} tools" + (f"  (오류: {info['error']})" if info.get("error") else ""))
    return 0


if __name__ == "__main__":
    sys.exit(main())
