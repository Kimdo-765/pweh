"""Skill 문서와 마스터 프롬프트의 일관성 회귀 테스트.

skills/*/(SKILL.md, reference.md, checklist.md) 와 orchestrator/master-prompt.md 를 하나의 시스템으로 본다.
- 형식: frontmatter(YAML, 허용 키), SKILL.md 500줄 이하, 코드 펜스 짝, 빈 링크·깨진 앵커 없음.
- 도구: 문서의 도구 이름·키워드 인자가 실제 서버(list_tools)와 REA 도구 목록에 있다 (scripts/dump_tool_catalog.py --check 포함).
- 스키마: 요약 예시 JSON 과 finding 예시가 pweh.schemas 를 통과한다.
- 데이터 전달: 다음 Skill 이 읽는다고 적은 필드가 이전 Skill 의 요약 예시·스키마에 있다.
- 안전 규칙·사람 요청 템플릿: 태그 어휘, 전원 투입 순서, init=/bin/sh 동의, 증거 덮어쓰기 금지 등.
- 서버 동작과 맞춘 사실: 문서의 예시 명령·규칙 설명을 실제 분류기(uart_mcp.guard, openocd_mcp.guard)와 서버 소스로 대조한다.
문서만 읽고(서버 목록 수집·분류기 호출은 in-memory) 하드웨어·외부 도구가 필요 없다.
"""

from __future__ import annotations

import importlib.util
import json
import re
from pathlib import Path
from typing import Any

import anyio
import pytest
import yaml

from pweh import schemas

REPO = Path(__file__).resolve().parents[2]
SKILLS = REPO / "skills"
MASTER = REPO / "orchestrator" / "master-prompt.md"
SKILL_DIRS = sorted(p.parent for p in SKILLS.glob("*/SKILL.md"))
DOCS = sorted(SKILLS.glob("*/*.md")) + [MASTER]


def _read(p: Path) -> str:
    return p.read_text(encoding="utf-8")


def _skill_text(name: str) -> str:
    return _read(SKILLS / name / "SKILL.md")


def _section(text: str, heading_prefix: str) -> str:
    """'## 6.' 처럼 시작하는 절의 본문(다음 같은 수준 제목 전까지)."""
    level = heading_prefix.split(" ")[0]
    lines = text.split("\n")
    out: list[str] = []
    inside = False
    for line in lines:
        if line.startswith(heading_prefix):
            inside = True
            continue
        if inside and re.match(rf"^{re.escape(level)} \S", line):
            break
        if inside:
            out.append(line)
    assert out, f"절을 찾지 못함: {heading_prefix}"
    return "\n".join(out)


def _fenced_blocks(text: str) -> list[tuple[int, str, str]]:
    """(시작 줄 번호, 언어, 본문) 목록. 닫히지 않은 펜스는 AssertionError."""
    lines = text.split("\n")
    out: list[tuple[int, str, str]] = []
    i = 0
    while i < len(lines):
        m = re.match(r"^\s*```(\w*)\s*$", lines[i])
        if not m:
            i += 1
            continue
        j = i + 1
        while j < len(lines) and not re.match(r"^\s*```\s*$", lines[j]):
            j += 1
        assert j < len(lines), f"닫히지 않은 코드 펜스 (줄 {i + 1})"
        out.append((i + 1, m.group(1), "\n".join(lines[i + 1 : j])))
        i = j + 1
    return out


def _balanced(text: str, start: int) -> str | None:
    """text[start] 의 여는 괄호에 짝이 맞는 부분 문자열 (따옴표 안의 괄호는 무시)."""
    pairs = {"(": ")", "[": "]", "{": "}"}
    depth = 0
    quote: str | None = None
    esc = False
    for i in range(start, len(text)):
        c = text[i]
        if quote:
            if esc:
                esc = False
            elif c == "\\":
                esc = True
            elif c == quote:
                quote = None
            continue
        if c in "\"'":
            quote = c
        elif c in pairs:
            depth += 1
        elif c in pairs.values():
            depth -= 1
            if depth == 0:
                return text[start : i + 1]
        elif c == "\n" and text[i + 1 : i + 2] == "\n" and depth == 1 and text[start] == "(":
            return None  # 문단이 끝났는데 닫히지 않음 → 산문 속 괄호
    return None


def _top_level_args(body: str) -> list[str]:
    parts: list[str] = []
    depth = 0
    quote: str | None = None
    esc = False
    cur = ""
    for c in body:
        if quote:
            cur += c
            if esc:
                esc = False
            elif c == "\\":
                esc = True
            elif c == quote:
                quote = None
            continue
        if c in "\"'":
            quote = c
        elif c in "([{":
            depth += 1
        elif c in ")]}":
            depth -= 1
        if c == "," and depth == 0:
            parts.append(cur)
            cur = ""
        else:
            cur += c
    if cur.strip():
        parts.append(cur)
    return parts


def _guess_schema(obj: Any) -> str | None:
    if not isinstance(obj, dict):
        return None
    keys = set(obj)
    if {"port", "baudrate", "console_type"} <= keys:
        return "uart-recon"
    if {"method", "output", "verification"} <= keys:
        return "firmware-dump"
    if "capture" in keys:
        return "signal-capture"
    if {"firmware", "extraction"} <= keys:
        return "static-analysis"
    if {"vendor_family", "checks"} <= keys:
        return "auth-hunt"
    if {"title", "category", "evidence"} <= keys:
        return "finding"
    return None


def _json_examples(path: Path) -> list[tuple[int, str | None, Any]]:
    out = []
    for line, lang, body in _fenced_blocks(_read(path)):
        if lang != "json":
            continue
        obj = json.loads(body)
        out.append((line, _guess_schema(obj), obj))
    return out


def _finding_examples() -> list[tuple[str, dict[str, Any]]]:
    """문서 안의 모든 finding 예시: ```json 블록 + case_add_finding(finding={...}) 호출."""
    out: list[tuple[str, dict[str, Any]]] = []
    for doc in DOCS:
        text = _read(doc)
        rel = str(doc.relative_to(REPO))
        for line, sch, obj in _json_examples(doc):
            if sch == "finding":
                out.append((f"{rel}:{line}", obj))
        for m in re.finditer(r"finding=\{", text):
            body = _balanced(text, m.end() - 1)
            assert body is not None, f"{rel}: finding= 예시의 중괄호가 닫히지 않음"
            out.append((f"{rel}:{text[: m.start()].count(chr(10)) + 1}", json.loads(body)))
    return out


# ---------------------------------------------------------------------------
# 실제 도구 카탈로그 (scripts/dump_tool_catalog.py 의 수집 함수를 그대로 쓴다)
# ---------------------------------------------------------------------------


def _load_catalog_module():
    spec = importlib.util.spec_from_file_location("pweh_dump_tool_catalog", REPO / "scripts" / "dump_tool_catalog.py")
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture(scope="module")
def catalog_mod():
    return _load_catalog_module()


@pytest.fixture(scope="module")
def catalog(catalog_mod) -> dict[str, Any]:
    cat = anyio.run(catalog_mod.collect)
    errors = {s: info["error"] for s, info in cat.items() if info.get("error")}
    assert not errors, f"서버를 불러오지 못함: {errors}"
    return cat


@pytest.fixture(scope="module")
def pweh_params(catalog) -> dict[str, dict[str, dict[str, Any]]]:
    return {t["name"]: {p["name"]: p for p in t["params"]} for info in catalog.values() for t in info["tools"]}


@pytest.fixture(scope="module")
def rea_args() -> dict[str, set[str]]:
    rows = json.loads(_read(REPO / "docs" / "references" / "rea-mcp-tools.json"))
    return {r["name"]: set(r.get("args") or []) for r in rows}


# ---------------------------------------------------------------------------
# 1. 형식
# ---------------------------------------------------------------------------


def test_every_skill_has_frontmatter_with_allowed_keys():
    assert {d.name for d in SKILL_DIRS} >= {
        "pweh-start", "uart-shell-acquisition", "firmware-dump-via-uart", "logic-analyzer-protocol-decode",
        "firmware-static-analysis", "cctv-auth-bypass-hunt",
    }
    for d in SKILL_DIRS:
        text = _read(d / "SKILL.md")
        m = re.match(r"^---\n(.*?)\n---\n", text, re.S)
        assert m, f"{d.name}: frontmatter 없음"
        fm = yaml.safe_load(m.group(1))
        allowed = {"name", "description"} | ({"disable-model-invocation"} if d.name == "pweh-start" else set())
        assert set(fm) <= allowed, f"{d.name}: 허용되지 않은 frontmatter 키 {set(fm) - allowed}"
        assert fm["name"] == d.name
        assert isinstance(fm["description"], str) and 0 < len(fm["description"]) <= 1024
    fm = yaml.safe_load(re.match(r"^---\n(.*?)\n---\n", _skill_text("pweh-start"), re.S).group(1))
    assert fm.get("disable-model-invocation") is True


@pytest.mark.parametrize("doc", DOCS, ids=lambda p: str(p.relative_to(REPO)))
def test_doc_integrity(doc: Path):
    text = _read(doc)
    assert text.endswith("\n"), "파일 끝 줄바꿈 없음 (잘린 파일?)"
    fences = [ln for ln in text.split("\n") if re.match(r"^\s*```", ln)]
    assert len(fences) % 2 == 0, f"코드 펜스 수가 홀수: {len(fences)}"
    _fenced_blocks(text)  # 닫히지 않은 펜스 검사
    if doc.name == "SKILL.md":
        assert text.count("\n") <= 500, f"SKILL.md 가 500줄을 넘음: {text.count(chr(10))}"
    # `[](no-space)` 는 빈 링크로 렌더링되어 괄호 안 내용이 사라진다 (예: mtd[](dev/size/...)).
    prose = re.sub(r"```.*?```", "", text, flags=re.S)
    prose = re.sub(r"`[^`\n]*`", "", prose)
    assert not re.search(r"\[\]\(\S+\)", prose), "빈 텍스트 링크 '[](…)' — 괄호 안 내용이 렌더링되지 않는다"


def _slug(heading: str) -> str:
    h = re.sub(r"[^\w\- ]", "", heading.strip().lower(), flags=re.U)
    return h.replace(" ", "-")


@pytest.mark.parametrize("doc", DOCS, ids=lambda p: str(p.relative_to(REPO)))
def test_relative_links_and_anchors_resolve(doc: Path):
    text = re.sub(r"```.*?```", "", _read(doc), flags=re.S)
    for m in re.finditer(r"\]\(([^)\s]+)\)", text):
        target = m.group(1)
        if target.startswith(("http://", "https://")):
            continue
        path, _, frag = target.partition("#")
        dest = (doc.parent / path).resolve() if path else doc
        assert dest.exists(), f"링크 대상 없음: {target}"
        if frag and dest.suffix == ".md":
            body = re.sub(r"```.*?```", "", _read(dest), flags=re.S)
            anchors = {_slug(h) for h in re.findall(r"^#+\s+(.*)$", body, flags=re.M)}
            assert frag in anchors, f"앵커 없음: {target}"


# ---------------------------------------------------------------------------
# 2. 도구 이름과 인자
# ---------------------------------------------------------------------------


def test_dump_tool_catalog_check_has_zero_problems(catalog_mod, catalog, capsys):
    assert catalog_mod.check(catalog) == 0, capsys.readouterr().out


def test_tool_call_keyword_arguments_exist(pweh_params, rea_args):
    problems = []
    for doc in DOCS:
        text = _read(doc)
        for m in re.finditer(r"(?<![A-Za-z0-9_.])([a-z][a-z0-9_]+)\(", text):
            name = m.group(1)
            known = pweh_params.get(name)
            rea = rea_args.get(name)
            if known is None and rea is None:
                continue
            body = _balanced(text, m.end() - 1)
            if body is None:
                continue
            for part in _top_level_args(body[1:-1]):
                km = re.match(r"\s*([A-Za-z_][A-Za-z0-9_]*)\s*=", part)
                if not km:
                    continue
                key = km.group(1)
                ok = (known is not None and key in known) or (rea is not None and key in rea)
                if not ok:
                    line = text[: m.start()].count("\n") + 1
                    problems.append(f"{doc.relative_to(REPO)}:{line}: {name}({key}=…) — 없는 인자")
    assert not problems, "\n".join(problems)


def _backticked_names(text: str) -> set[str]:
    return set(re.findall(r"`([a-z][a-z0-9_]+)`", text))


def test_master_prompt_tool_map_matches_real_tools(catalog, pweh_params, rea_args):
    tool_map = _section(_read(MASTER), "## 2.")
    rows = [ln for ln in tool_map.split("\n") if ln.startswith("| `")]
    assert len(rows) == 7, "도구 지도 행 수 (서버 7개)"
    for row in rows:
        server = re.match(r"\| `([^`]+)`", row).group(1)
        names = _backticked_names(row.split("|")[2])
        assert names, f"{server}: 도구 없음"
        if server == "rea":
            missing = names - set(rea_args)
        else:
            assert server in catalog, f"알 수 없는 서버 {server}"
            missing = names - {t["name"] for t in catalog[server]["tools"]}
        assert not missing, f"{server} 행에 그 서버에 없는 도구: {sorted(missing)}"
    # Skill 들이 의존하는 핵심 도구는 지도에 있어야 한다 (회귀: uart_sync/schema_get/case_hash_file 누락)
    names = _backticked_names(tool_map)
    for must in ("uart_sync", "uart_job_cancel", "schema_get", "case_hash_file", "case_set_phase", "openocd_halt", "openocd_stop",
                 "jtagulator_uart_txd_scan", "jtagulator_disconnect", "fwtriage_job_status", "binary_overview", "trace_call_path"):
        assert must in names, f"마스터 프롬프트 도구 지도에 {must} 없음"
    # §9 완료 기준이 말하는 정리 도구도 실제 도구여야 한다
    done = _section(_read(MASTER), "## 9.")
    for n in ("uart_close", "openocd_stop", "jtagulator_disconnect"):
        assert n in done and n in pweh_params
    assert "close_binary" in done and "close_binary" in rea_args


def test_master_prompt_skill_schema_table_matches_core():
    table = _section(_read(MASTER), "## 5.")
    pairs = dict(re.findall(r"^\| ([a-z-]+) \| `([a-z-]+)` \|", table, flags=re.M))
    assert pairs == schemas.SKILL_DATA_SCHEMAS


def test_master_prompt_decision_tree_names_existing_skills():
    tree = _section(_read(MASTER), "## 4.")
    named = set(re.findall(r"skill: ([a-z-]+)", tree))
    assert named and named <= {d.name for d in SKILL_DIRS}
    assert {"uart-shell-acquisition", "logic-analyzer-protocol-decode", "firmware-dump-via-uart",
            "firmware-static-analysis", "cctv-auth-bypass-hunt"} <= named


# ---------------------------------------------------------------------------
# 3. 스키마 예시
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("doc", DOCS, ids=lambda p: str(p.relative_to(REPO)))
def test_json_examples_validate_against_schemas(doc: Path):
    for line, sch, obj in _json_examples(doc):
        if sch is None:
            continue
        inst = {"id": "F-001", **obj} if sch == "finding" else obj
        errs = schemas.errors(sch, inst)
        assert not errs, f"{doc.name}:{line} ({sch}): {errs}"


def test_every_data_skill_has_a_valid_summary_example():
    for skill, sch in schemas.SKILL_DATA_SCHEMAS.items():
        found = [obj for _, s, obj in _json_examples(SKILLS / skill / "SKILL.md") if s == sch]
        assert found, f"{skill}/SKILL.md 에 {sch} 요약 예시가 없음"
        for obj in found:
            assert not schemas.errors(sch, obj)


def test_finding_examples_validate_and_follow_evidence_convention():
    examples = _finding_examples()
    assert len(examples) >= 8
    for where, obj in examples:
        assert not schemas.errors("finding", {"id": "F-001", **obj}), where
        assert "id" not in obj, f"{where}: id 는 서버가 붙인다"
        for ev in obj["evidence"]:
            ref = ev["ref"]
            # 증거 규칙(firmware-static-analysis §8, checklist §0.3): triage = fwtriage result_path,
            # string = <rootfs 경로>@<파일 오프셋>, decompilation/rea-evidence = <번들>#<evidence_id>
            if ev["type"] == "string":
                assert not ref.startswith("analysis/"), f"{where}: string 증거의 ref 가 결과 JSON ({ref}) — type 은 triage"
            if ev["type"] == "triage":
                assert ref.startswith("analysis/") and ref.endswith(".json"), f"{where}: triage ref 는 result_path ({ref})"
            if ev["type"] in ("decompilation", "rea-evidence"):
                assert re.match(r"^analysis/rea-evidence-[^#]+\.json#ev_[0-9a-f]+$", ref), f"{where}: {ref}"


# ---------------------------------------------------------------------------
# 4. Skill 사이의 데이터 전달
# ---------------------------------------------------------------------------

# (읽는 Skill, 만드는 Skill, 요약 data 의 필드 경로). 읽는 Skill 의 SKILL.md 가 그 필드를 언급해야 하고,
# 만드는 Skill 의 요약 예시(SKILL.md/reference.md) 중 하나에 실제로 있어야 한다.
HANDOFF = [
    ("uart-shell-acquisition", "logic-analyzer-protocol-decode", "uart_estimate.baudrate"),
    ("uart-shell-acquisition", "logic-analyzer-protocol-decode", "uart_estimate.idle_level"),
    ("uart-shell-acquisition", "logic-analyzer-protocol-decode", "conclusions"),
    ("logic-analyzer-protocol-decode", "uart-shell-acquisition", "console_type"),
    ("logic-analyzer-protocol-decode", "uart-shell-acquisition", "baudrate"),
    ("logic-analyzer-protocol-decode", "uart-shell-acquisition", "notes"),
    ("firmware-dump-via-uart", "uart-shell-acquisition", "port"),
    ("firmware-dump-via-uart", "uart-shell-acquisition", "access_level"),
    ("firmware-dump-via-uart", "uart-shell-acquisition", "uboot.partitions"),
    ("firmware-dump-via-uart", "uart-shell-acquisition", "uboot.mtdparts"),
    ("firmware-dump-via-uart", "uart-shell-acquisition", "uboot.flash"),
    ("firmware-dump-via-uart", "uart-shell-acquisition", "uboot.ram_load_addr"),
    ("firmware-dump-via-uart", "uart-shell-acquisition", "uboot.commands"),
    ("firmware-dump-via-uart", "uart-shell-acquisition", "linux.mtd"),
    ("firmware-dump-via-uart", "uart-shell-acquisition", "linux.user"),
    ("firmware-dump-via-uart", "uart-shell-acquisition", "session.session_id"),
    ("firmware-static-analysis", "firmware-dump-via-uart", "output.path"),
    ("firmware-static-analysis", "firmware-dump-via-uart", "output.sha256"),
    ("firmware-static-analysis", "firmware-dump-via-uart", "verification.match"),
    ("firmware-static-analysis", "firmware-dump-via-uart", "method"),
    ("firmware-static-analysis", "firmware-dump-via-uart", "partitions[].path"),
    ("firmware-static-analysis", "firmware-dump-via-uart", "source.flash_type"),
    ("firmware-static-analysis", "uart-shell-acquisition", "linux.mtd"),
    ("firmware-static-analysis", "uart-shell-acquisition", "uboot.mtdparts"),
    ("firmware-static-analysis", "uart-shell-acquisition", "linux.cmdline"),
    ("firmware-static-analysis", "uart-shell-acquisition", "device_info.arch"),
    ("cctv-auth-bypass-hunt", "firmware-static-analysis", "rootfs.path"),
    ("cctv-auth-bypass-hunt", "firmware-static-analysis", "rootfs.arch"),
    ("cctv-auth-bypass-hunt", "firmware-static-analysis", "rootfs.web_servers"),
    ("cctv-auth-bypass-hunt", "firmware-static-analysis", "binaries_of_interest[].path"),
    ("cctv-auth-bypass-hunt", "firmware-static-analysis", "extraction.runs[].output_dir"),
    ("cctv-auth-bypass-hunt", "firmware-static-analysis", "rea.evidence_bundle"),
    ("cctv-auth-bypass-hunt", "firmware-static-analysis", "rea.limitations"),
    ("cctv-auth-bypass-hunt", "firmware-static-analysis", "finding_ids"),
]


def _resolve(obj: Any, path: str) -> bool:
    cur: list[Any] = [obj]
    for part in path.split("."):
        is_list = part.endswith("[]")
        key = part[:-2] if is_list else part
        nxt: list[Any] = []
        for c in cur:
            if isinstance(c, dict) and key in c:
                v = c[key]
                if is_list:
                    if isinstance(v, list):
                        nxt.extend(v)
                else:
                    nxt.append(v)
        if not nxt:
            return False
        cur = nxt
    return True


def _schema_allows(schema: dict[str, Any], path: str) -> bool:
    node = schema
    for part in path.split("."):
        key = part[:-2] if part.endswith("[]") else part
        props = node.get("properties", {})
        if key in props:
            node = props[key]
        elif node.get("additionalProperties", True) is False:
            return False
        else:
            return True  # 스키마 밖 필드는 additionalProperties 로 허용 (예시로 존재를 확인)
        if part.endswith("[]"):
            node = node.get("items", {})
    return True


@pytest.mark.parametrize("consumer,producer,path", HANDOFF, ids=lambda v: str(v))
def test_handoff_fields_are_produced(consumer: str, producer: str, path: str):
    sch = schemas.SKILL_DATA_SCHEMAS[producer]
    examples = []
    for doc in sorted((SKILLS / producer).glob("*.md")):
        examples += [obj for _, s, obj in _json_examples(doc) if s == sch]
    assert examples, f"{producer} 요약 예시 없음"
    assert any(_resolve(e, path) for e in examples), f"{producer} 요약 예시에 {path} 가 없음 ({consumer} 가 읽음)"
    assert _schema_allows(schemas.load(sch), path), f"{sch} 스키마가 {path} 를 허용하지 않음"
    leaf = path.split(".")[-1].removesuffix("[]")
    assert leaf in _skill_text(consumer), f"{consumer}/SKILL.md 가 {path} 를 언급하지 않음 (표와 문서가 어긋남)"


# ---------------------------------------------------------------------------
# 5. 안전 규칙과 사람 요청 템플릿
# ---------------------------------------------------------------------------


def _allowed_tags() -> set[str]:
    table = _section(_read(MASTER), "## 6.")
    tags = set(re.findall(r"`(\[[^\]`]+\])`", table))
    assert {"[사람 작업 필요]", "[확인 필요]", "[동의 필요]", "[승인 필요]", "[보고]", "[안내]"} <= tags
    return tags


def test_human_request_templates_use_master_tag_vocabulary():
    tags = _allowed_tags()
    seen = set()
    for doc in DOCS:
        text = _read(doc)
        for line, _, body in _fenced_blocks(text):
            first = body.split("\n", 1)[0].strip()
            m = re.match(r"^(\[[^\]]+\])", first)
            if not m or m.group(1).startswith("[Phase"):
                continue
            seen.add(m.group(1))
            assert m.group(1) in tags, f"{doc.relative_to(REPO)}:{line}: 정의되지 않은 템플릿 태그 {m.group(1)}"
        for m in re.finditer(r"`(\[[가-힣 ]+\]) ", text):  # 인라인 알림 예: `[진행] …` (오류 코드 `[busy]` 등은 제외)
            assert m.group(1) in tags, f"{doc.relative_to(REPO)}: 정의되지 않은 태그 {m.group(1)}"
    assert {"[사람 작업 필요]", "[확인 필요]", "[승인 필요]", "[보고]"} <= seen


def test_power_timing_templates_power_on_after_monitoring_starts():
    """감시 도구는 '전원을 꺼 둔 상태 → 호출 → 전원 투입' 순서 (켜진 기기에서 감시하면 이전 부팅 출력을 새 부팅으로 오인)."""
    master6 = _section(_read(MASTER), "## 6.")
    assert "먼저 꺼" in master6
    dump = _skill_text("firmware-dump-via-uart")
    template_c = dump[dump.index("**C. U-Boot 다시 잡기"): dump.index("**D. ")]
    assert "먼저 꺼" in template_c
    uart_h3 = _skill_text("uart-shell-acquisition")
    h3 = uart_h3[uart_h3.index("**H3."): uart_h3.index("**H5.")]
    assert "꺼 두세요" in h3
    for doc in DOCS:
        text = _read(doc)
        assert not re.search(r"시작하면 바로[^\n]*껐다 켜", text), f"{doc.relative_to(REPO)}: 감시 시작 뒤 전원을 껐다 켜라는 옛 순서"


def test_wiring_template_measures_voltage_before_connecting():
    tmpl = _section(_read(MASTER), "## 6.")
    block = tmpl[tmpl.index("[사람 작업 필요] UART 연결"):]
    assert block.index("전압") < block.index("어댑터 GND → 보드 GND"), "전압 측정이 배선보다 먼저여야 한다"
    assert "VCC 는 연결하지 않는다" in block


def test_init_sh_requires_explicit_consent_everywhere():
    master = _read(MASTER)
    rule3 = _section(master, "## 1.")
    assert re.search(r"동의[^\n]*init=/bin/sh|init=/bin/sh[^\n]*\n?[^\n]*동의", rule3)
    login_row = next(ln for ln in _section(master, "## 8.").split("\n") if ln.startswith("| 로그인 요구"))
    assert "동의" in login_row and "init=/bin/sh" in login_row
    assert "[동의 필요] RAM 한정 부트 인자 변경" in _skill_text("uart-shell-acquisition")


def test_bare_enter_rule_names_uart_sync_and_the_single_exception():
    rule = next(ln for ln in _section(_read(MASTER), "## 1.").split("\n") if ln.startswith("4. **U-Boot 프롬프트에서 빈 Enter"))
    assert "uart_sync" in rule
    uart = _skill_text("uart-shell-acquisition")
    assert "유일한 예외" in uart and "보드레이트 전환" in uart
    ref = _read(SKILLS / "firmware-dump-via-uart" / "reference.md")
    assert "유일한 예외가 이 확인 대기다" in ref


def test_no_self_approval_and_gate_rules_in_every_working_skill():
    for d in SKILL_DIRS:
        if d.name == "pweh-start":
            continue
        text = _skill_text(d.name)
        assert "denied" in text and "우회" in text, f"{d.name}: denied 우회 금지 규칙 없음"
        assert "pweh approve" in text, f"{d.name}: 승인 주체(사람의 pweh approve) 언급 없음"
        assert "소유" in text and "허가" in text, f"{d.name}: 소유/허가 선행 조건 없음"


def test_evidence_bundles_are_never_overwritten():
    for doc in DOCS:
        assert not re.search(r"overwrite\s*=\s*true", _read(doc)), f"{doc.relative_to(REPO)}: 증거 묶음 overwrite=true"
    hunt = _skill_text("cctv-auth-bypass-hunt")
    step7 = hunt[hunt.index("### 7."): hunt.index("### 8.")]
    assert "NNN 을 올린다" in step7


# ---------------------------------------------------------------------------
# 6. 현재 서버 동작과 맞춘 사실 (회귀)
# ---------------------------------------------------------------------------


def test_double_read_verification_is_recorded_as_double_read():
    enum = schemas.load("firmware-dump")["properties"]["verification"]["properties"]["method"]["enum"]
    assert "double-read" in enum
    skill = _skill_text("firmware-dump-via-uart")
    ref = _read(SKILLS / "firmware-dump-via-uart" / "reference.md")
    assert "double-read 값이 없다" not in skill + ref
    assert re.search(r"verify=double[^\n]*verification\.method 는 `double-read`", skill)
    spi = ref[ref.index("### 6.4"): ref.index("### 6.5")]
    assert 'verification.method="double-read"' in spi and "size-only" not in spi


def test_dump_cross_check_uses_case_hash_file(pweh_params):
    assert {"path", "offset", "length"} <= set(pweh_params["case_hash_file"])
    skill = _skill_text("firmware-dump-via-uart")
    verify = skill[skill.index("### 8. 검증"): skill.index("### 9.")]
    assert "case_hash_file(" in verify and "fw_carve(" not in verify
    ref = _read(SKILLS / "firmware-dump-via-uart" / "reference.md")
    assert "python3 -c" not in ref, "호스트 셸 해시 대신 case_hash_file 을 쓴다"
    assert ref.count("case_hash_file(") >= 3


def test_master_prompt_dump_time_formula_matches_server():
    s7 = _section(_read(MASTER), "## 7.")
    assert "79/16" in s7 and "estimated_seconds" in s7
    assert "4.7" not in s7 and "결과의 eta" not in s7
    # firmware-dump-via-uart 의 식(= uboot_dump_start 의 estimated_seconds 식)과 같은 식을 쓴다
    assert "79/16 + 60/청크" in _skill_text("firmware-dump-via-uart")
    assert "output_name" in s7 and "chunk_size" in s7, "재개 조건(같은 인자 + 같은 output_name)"


def test_static_analysis_doc_facts_match_tools():
    skill = _skill_text("firmware-static-analysis")
    ref = _read(SKILLS / "firmware-static-analysis" / "reference.md")
    assert '"ok" 필드 없음' not in skill, "case_paths 응답에도 ok 가 있다"
    assert "path 아님" not in skill + ref, "fw_carve partitions[] 의 파일 경로 키는 path (file 은 별칭)"
    assert "단일 파일 모드의 file 은 케이스 상대 경로" not in skill
    # 셸 경로·나눠 받은 덤프의 파티션 파일, 요약 없는 JTAG/SPI 덤프도 입력으로 찾는다
    step0 = skill[skill.index("### 0."): skill.index("### 1.")]
    assert "partitions[]" in step0 and "flash-dump" in step0


def test_uart_skill_handles_uboot_interrupt_outcomes():
    """uboot_interrupt 의 부트로더 잠금(uboot_password)·이전 부팅 출력(window_expired) 결과와 has.* 힌트를 문서가 다룬다."""
    uart = _skill_text("uart-shell-acquisition")
    a1 = uart[uart.index("**A1."): uart.index("**A2.")]
    outcomes = {"prompt", "kernel", "linux", "uboot_password", "window_expired"}
    # 서버 구현에서 outcome 값을 찾을 수 있으면 새로 생긴 값도 문서에 있어야 한다 (구현 형태가 바뀌어 못 찾으면 고정 목록만 본다)
    src = _read(REPO / "mcp-servers" / "uart-mcp" / "uart_mcp" / "console.py")
    outcomes |= set(re.findall(r'outcome = "([a-z_]+)"', src)) - {"cancelled", "disconnected"}
    for oc in sorted(outcomes):
        # uboot_ 로 시작하는 값은 따옴표로 쓴다 (백틱 단독이면 dump_tool_catalog --check 가 도구 이름으로 오인)
        assert re.search(rf"`{oc}`|\"{oc}\"", a1), f"A1 이 uboot_interrupt outcome {oc} 를 다루지 않음"
    assert "Password:" in a1 and "`shell_login` 을 부르지 않는다" in a1
    assert "이전 부팅" in a1
    master8 = _section(_read(MASTER), "## 8.")
    assert "부트로더 잠금" in master8
    a3 = uart[uart.index("**A3."): uart.index("**A4.")]
    assert "힌트로만" in a3 and "U-Boot 덤프가 불가능" not in a3
    dump = _skill_text("firmware-dump-via-uart")
    assert "힌트로만" in dump  # 두 Skill 이 has.* 를 같은 수준(힌트)으로 다룬다


def test_extracted_tree_handoff_and_blocked_records():
    """rootfs 밖 트리(app·config)의 바이너리는 tree 로 넘기고, 요약을 만들 수 없는 실패는 다른 step 으로 남긴다."""
    ref = _read(SKILLS / "firmware-static-analysis" / "reference.md")
    row = next(ln for ln in ref.split("\n") if ln.startswith("| binaries_of_interest |"))
    assert "tree" in row
    assert "<tree><path>" in _skill_text("firmware-static-analysis")
    assert "<tree><path>" in _skill_text("cctv-auth-bypass-hunt")
    for skill, step in (("uart-shell-acquisition", "port-discovery"), ("firmware-dump-via-uart", "attempt"),
                        ("firmware-static-analysis", "input")):
        text = _skill_text(skill) + "".join(_read(p) for p in (SKILLS / skill).glob("reference.md"))
        assert f'step="{step}"' in text, f"{skill}: 요약을 만들 수 없을 때의 step 기록 없음"
    la_ref = _read(SKILLS / "logic-analyzer-protocol-decode" / "reference.md")
    assert 'step="capture"' in la_ref


def test_custom_pattern_check_ids_documented_as_stable():
    for doc in DOCS:
        assert "custom-N" not in _read(doc), f"{doc.relative_to(REPO)}: custom check id 는 custom-<kind>-<해시>"


# ---------------------------------------------------------------------------
# 7. 마지막 검토 이후의 서버 동작 (family_source, OpenOCD Tcl 식, uart 송신 규칙, 리눅스 셸 규칙)
# ---------------------------------------------------------------------------


def _src(*parts: str) -> str:
    return _read(REPO.joinpath(*parts))


def _code_spans(text: str) -> list[str]:
    return re.findall(r"`([^`\n]+)`", text)


def test_auth_hunt_vendor_family_keys_on_family_source():
    """fw_rootfs_audit 가 프로필 대체까지 적용해 vendor.family_source 로 근거를 밝힌다 → 2단계 분기는 family_source 기준."""
    rootfs = _src("mcp-servers", "fwtriage-mcp", "fwtriage_mcp", "rootfs.py")
    # 구현에서 family_source 값을 찾을 수 있으면 새로 생긴 값도 문서에 있어야 한다 (형태가 바뀌어 못 찾으면 고정 목록만 본다)
    sources = {"evidence", "profile", "generic-web-server", "none"}
    sources |= set(re.findall(r'^\s*family, source = .*?"([a-z-]+)"\s*$', rootfs, flags=re.M))
    hunt = _skill_text("cctv-auth-bypass-hunt")
    step2 = hunt[hunt.index("### 2."): hunt.index("### 3.")]
    assert "family_source" in step2
    for src in sorted(sources):
        # 분기 표의 첫 열(값마다 한 행)
        assert re.search(rf"^\s*\| `{re.escape(src)}` \|", step2, flags=re.M), f"cctv-auth-bypass-hunt 2단계 분기 표에 family_source `{src}` 행 없음"
    # 서버가 이미 하는 프로필 대체를 문서가 다시 계산하라고 하지 않는다 (옛 문구)
    assert "votes 가 비어 있으면" not in hunt and "버전에 따라 다르다" not in hunt
    examples = [obj for _, s, obj in _json_examples(SKILLS / "cctv-auth-bypass-hunt" / "SKILL.md") if s == "auth-hunt"]
    assert examples and all(str((e.get("vendor_evidence") or [""])[0]).startswith("family_source=") for e in examples)


def test_agent_flow_vendor_family_uses_family_source():
    """e2e 스크립트 에이전트도 Skill 2단계처럼 family_source 가 있으면 vendor.family 를 그대로 쓴다."""
    flow = _src("tests", "e2e", "agent_flow.py")
    body = flow[flow.index("async def phase_d_auth_hunt"): flow.index("def _vendor_candidates")]
    assert "family_source" in body
    assert 'if family in (None, "unknown"):' not in body, "family_source 와 무관하게 프로필 대체를 다시 계산함"


def test_master_prompt_openocd_tcl_examples_match_guard():
    """JTAG 절의 Tcl 예시가 openocd-mcp 분류와 맞는다: 중괄호 예는 DESTRUCTIVE 미만, 중괄호 없는 치환 예·포트 재활성화는 DESTRUCTIVE."""
    from openocd_mcp.guard import classify_command

    from pweh.safety import Risk

    s4 = _section(_read(MASTER), "## 4.")
    jtag = s4[s4.index("**JTAG 순서**"):]
    assert "항상 중괄호로 감싼다" in jtag and "다른 문법으로 고쳐 다시 보내지 않는다" in jtag
    assert "openocd_command" in jtag and "extra_commands" in jtag
    good_line = next(ln for ln in jtag.split("\n") if "올바른 예:" in ln)
    bad_line = next(ln for ln in jtag.split("\n") if "거부되는 예:" in ln)
    good = _code_spans(good_line.split("올바른 예:", 1)[1])
    bad = _code_spans(bad_line.split("거부되는 예:", 1)[1])
    assert len(good) >= 2 and len(bad) >= 3
    for cmd in good:
        c = classify_command(cmd)
        assert c.risk < Risk.DESTRUCTIVE, f"'올바른 예' {cmd!r} 가 {c.risk.label} ({c.rule_id})"
    for cmd in bad:
        c = classify_command(cmd)
        assert c.risk == Risk.DESTRUCTIVE, f"'거부되는 예' {cmd!r} 가 {c.risk.label} ({c.rule_id})"
    for cmd in ("telnet port 4444", "gdb port 3333"):
        assert f"`{cmd}`" in jtag and classify_command(cmd).risk == Risk.DESTRUCTIVE
    assert classify_command("$_TARGETNAME configure -event reset-init {halt}").risk == Risk.DESTRUCTIVE  # 문서: 실제 타깃 이름을 쓴다
    assert "$_TARGETNAME" in jtag


def test_uart_skill_covers_every_shell_login_status():
    """shell_login 이 돌려주는 status 를 8단계 표가 모두 다룬다 (context_unknown·username_required·uboot_password_prompt 포함)."""
    console = _src("mcp-servers", "uart-mcp", "uart_mcp", "console.py")
    login = console[console.index("def login("): console.index("def not_found(")]
    statuses = set(re.findall(r'result\("([a-z_]+)"', login))
    assert {"context_unknown", "username_required", "uboot_password_prompt"} <= statuses, "구현 형태가 바뀌었다 — 테스트를 갱신"
    statuses |= {"timeout", "disconnected"}  # result(res.kind, …): 프롬프트를 기다리다 끝난 경우
    uart = _skill_text("uart-shell-acquisition")
    s8 = uart[uart.index("### 8."): uart.index("### 9.")]
    table = "\n".join(ln.split("|")[1] for ln in s8.split("\n") if ln.startswith("| "))  # status 열만
    for st in sorted(statuses):
        # uboot_ 로 시작하는 값은 따옴표로 쓴다 (백틱 단독이면 dump_tool_catalog --check 가 도구 이름으로 오인)
        assert re.search(rf"`{st}`|\"{st}\"", table), f"8단계 표에 shell_login status {st} 행 없음"
    # username 은 선택 인자다: 계정이 없으면 이름을 지어내지 않고 username 없이 부른다
    assert "username 없이" in s8 and "보통 root" not in uart


def test_uart_docs_cover_new_uboot_result_fields():
    """uboot_interrupt new_boot_seen, uboot_printenv flash_size/flash_size_source, uboot_info has/has_via/partitions."""
    srv = _src("mcp-servers", "uart-mcp", "uart_mcp", "server.py")
    console = _src("mcp-servers", "uart-mcp", "uart_mcp", "console.py")
    assert '"new_boot_seen"' in console
    for f in ("flash_size", "flash_size_source", "has", "has_via", "partitions"):
        assert f'"{f}"' in srv, f"서버 응답에 {f} 가 없다 — 문서와 테스트를 갱신"
    uart = _skill_text("uart-shell-acquisition")
    a1 = uart[uart.index("**A1."): uart.index("**A2.")]
    a2 = uart[uart.index("**A2."): uart.index("**A3.")]
    a3 = uart[uart.index("**A3."): uart.index("**A4.")]
    assert "new_boot_seen" in a1
    assert "flash_size_source" in a2
    assert "has_via" in a3 and "partitions" in a3 and "null" in a3
    dump = _skill_text("firmware-dump-via-uart")
    assert "has_via" in dump and "flash_size_source" in dump
    for doc in DOCS:
        # help 파서가 8자 이름('printenv- …')을 읽게 된 뒤로는 사실이 아니다
        assert "printenv 를 false" not in _read(doc), f"{doc.relative_to(REPO)}: 옛 has.printenv 설명"


def test_baud_switch_enter_requires_inherited_last_command():
    """보드레이트 전환 확인 대기의 `\\r` 은 uart_open 이 앞 세션의 setenv baudrate 를 이어 준 경우에만 통과한다."""
    from uart_mcp.guard import classify_line

    from pweh.safety import Risk

    assert 'out["inherited_last_command"]' in _src("mcp-servers", "uart-mcp", "uart_mcp", "server.py")
    kw = dict(env=None, persistent_paths=(), unknown_risk="modify")
    fresh = classify_line("", "unknown", last_command=None, last_command_known=False, **kw)
    assert fresh.risk == Risk.DESTRUCTIVE and fresh.rule_id.endswith("uart.repeat-unknown")
    inherited = classify_line("", "unknown", last_command="setenv baudrate 57600", **kw)
    assert inherited.risk == Risk.MODIFY
    ref = _read(SKILLS / "firmware-dump-via-uart" / "reference.md")
    s2 = ref[ref.index("## 2."): ref.index("## 3.")]
    assert "inherited_last_command" in s2 and "uart.repeat-unknown" in s2, "reference §2: 확인 Enter 를 보내는 조건(이어 받은 직전 명령)과 거부 규칙"
    assert "`\\r` 만 받" in s2, "U-Boot 는 이 대기에서 \\r 만 받는다 — uart_sync 로 대신할 수 없다는 설명"
    rule4 = _section(_read(MASTER), "## 1.")
    rule4 = rule4[rule4.index("4. **U-Boot 프롬프트에서 빈 Enter"): rule4.index("5. **")]
    uart = _skill_text("uart-shell-acquisition")
    rule3 = uart[uart.index("3. **U-Boot 와 unknown 문맥에서 빈 Enter"): uart.index("4. **")]
    for where, text in (("master §1-4", rule4), ("uart 안전 규칙 3", rule3)):
        assert "inherited_last_command" in text and "uart.repeat-unknown" in text, where


def test_console_send_rules_device_busy_and_multi_line():
    """프롬프트가 보일 때 한 줄씩: 실행 중·부팅 중 송신(uart.device-busy)과 여러 줄 uart_write 의 둘째 줄부터는 DESTRUCTIVE."""
    from uart_mcp.guard import GuardState, plan_payload

    from pweh.safety import LineAssembler, Risk

    multi = plan_payload(b"version\rprintenv\r", LineAssembler(), GuardState(context="uboot"))
    assert [ln.classification.risk for ln in multi.lines] == [Risk.INTERACT, Risk.DESTRUCTIVE]
    busy = plan_payload(b"printenv\r", LineAssembler(), GuardState(context="uboot", device_ready=False, busy_reason="부팅 중"))
    assert busy.classification.risk == Risk.DESTRUCTIVE and busy.classification.rule_id == "uart.device-busy"
    master1 = _section(_read(MASTER), "## 1.")
    uart = _skill_text("uart-shell-acquisition")
    dump = _skill_text("firmware-dump-via-uart")
    for where, text in (("master §1", master1), ("uart-shell-acquisition", uart), ("firmware-dump-via-uart", dump)):
        assert "uart.device-busy" in text, f"{where}: 실행 중·부팅 중 송신 거부 규칙 없음"
        assert re.search(r"uart_write[^\n]*여러 줄", text), f"{where}: 여러 줄 uart_write 금지 규칙 없음"
    # 거부 뒤의 정해진 복구(프롬프트를 기다렸다가 같은 명령 한 줄)를 우회와 구분해 적는다
    master8 = _section(_read(MASTER), "## 8.")
    assert re.search(r"`uart\.device-busy` 거부[^\n]*uart_wait_for", master8)
    assert re.search(r"uart\.repeat-unknown[^\n]*uart_sync", master8)
    s11 = uart[uart.index("### 11."): uart.index("### 12.")]
    assert "uart.device-busy" in s11 and "uart.repeat-unknown" in s11 and "approval_mismatch" in s11
    assert "inherited_last_command" in uart and "device_ready" in uart


_FORBIDDEN_LINUX_RULES = ("linux.exec-nonsystem", "linux.script", "linux.env-hijack", "linux.indirect-command")


def test_instructed_console_commands_respect_linux_shell_rules():
    """문서가 보내라고 하는 콘솔 명령은 시스템 밖 경로 실행·스크립트·PATH 변경이 아니고, 어느 문맥에서도 DESTRUCTIVE 가 아니다."""
    from uart_mcp.guard import classify_line

    from pweh.safety import Risk

    kw = dict(env=None, last_command=None, persistent_paths=("/mnt/mtd",), unknown_risk="modify")
    # 규칙 자체는 실제 분류기에서 DESTRUCTIVE 다 (문서가 이름을 대는 규칙 id 와 같다)
    for cmd, rule in (("/mnt/mtd/tool", "linux.exec-nonsystem"), ("./tool", "linux.exec-nonsystem"), ("sh /tmp/x.sh", "linux.script"),
                      ("export PATH=/tmp:$PATH", "linux.env-hijack")):
        c = classify_line(cmd, "linux-shell", **kw)
        assert c.risk == Risk.DESTRUCTIVE and rule in c.rule_id, (cmd, c)
    seen = 0
    for doc in DOCS:
        for m in re.finditer(r'uart_send_command\([^)]*?command="([^"]*)"', _read(doc)):
            cmd = m.group(1)
            if not cmd:
                continue  # 빈 명령 금지 규칙의 예시
            seen += 1
            lin = classify_line(cmd, "linux-shell", **kw)
            assert not any(r in lin.rule_id for r in _FORBIDDEN_LINUX_RULES), f"{doc.relative_to(REPO)}: {cmd!r} → {lin.rule_id}"
            unk = classify_line(cmd, "unknown", **kw)  # 두 분류기 중 엄격한 쪽
            assert unk.risk < Risk.DESTRUCTIVE, f"{doc.relative_to(REPO)}: 문서가 시키는 명령 {cmd!r} 가 {unk.risk.label} ({unk.rule_id})"
    assert seen >= 15
    rules = {
        "master §1": _section(_read(MASTER), "## 1."),
        "uart-shell-acquisition 안전 규칙": _section(_skill_text("uart-shell-acquisition"), "## 안전 규칙"),
        "firmware-dump-via-uart 안전 규칙": _section(_skill_text("firmware-dump-via-uart"), "## 안전 규칙"),
    }
    for where, text in rules.items():
        assert "/usr/sbin" in text and "PATH" in text, f"{where}: 리눅스 셸 실행 규칙 없음"
        for rule in _FORBIDDEN_LINUX_RULES[:3]:
            assert rule in text, f"{where}: {rule} 언급 없음"


def test_shell_dump_device_path_restriction_documented():
    """shell_dump_start 는 /dev 의 저장장치만 읽는다 (/dev/watchdog·/dev/mem 거부)."""
    srv = _src("mcp-servers", "uart-mcp", "uart_mcp", "server.py")
    assert "SHELL_DEV_RE" in srv and "이 장치는 덤프하지 않습니다" in srv
    ref = _read(SKILLS / "firmware-dump-via-uart" / "reference.md")
    assert "/dev/watchdog" in ref and "/dev/mem" in ref
    dump = _skill_text("firmware-dump-via-uart")
    s7 = dump[dump.index("### 7."): dump.index("### 8.")]
    assert "이 장치는 덤프하지 않습니다" in s7 and "job_command_denied" in s7 and "authorization_required" in s7
