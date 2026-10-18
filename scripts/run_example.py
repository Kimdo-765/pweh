#!/usr/bin/env python3
"""시뮬레이터로 PWEH 파이프라인을 실제로 돌려 examples/<name>/ 예제 디렉터리를 만든다.

  .venv/bin/python scripts/run_example.py --profile hikvision-like --name hikvision-sample
  .venv/bin/python scripts/run_example.py --profile dahua-like --name dahua-sample
  옵션: --dump-scope full|needed (기본 full), --no-rea, --no-gate-demo, --chunk-size 256k, --out DIR, --keep-workspace

하는 일
1. 임시 작업공간(케이스/상태 디렉터리 + pipeline-config 사본)을 만든다. 저장소의 cases/ 와 .pweh/ 는 건드리지 않는다.
2. pweh.mocktarget 로 합성 펌웨어(전체 빌드)를 만들고 MockDevice 를 PTY 로 띄운다.
3. tests/e2e/agent_flow.py 의 스크립트 에이전트가 실제 MCP 서버(pweh-case / pweh-uart / pweh-fwtriage, 가능하면 REA)를
   Skill 순서대로 호출한다 (테스트와 같은 흐름).
4. 결과를 examples/<name>/ 에 쓴다:
   - README.md        한국어 설명 (시나리오, 합성인 것, 재현 방법, 도구 호출 타임라인, 결과, 정답 대조)
   - tool-calls.jsonl 모든 MCP 호출 (인자 + 요약된 결과)
   - case/            케이스 디렉터리 사본 (큰 바이너리·추출 트리·원시 UART 바이트 제외, 목록은 case/excluded-files.json)
   비밀값(합성 토큰·내장 자격증명·크랙된 비밀번호)은 마스킹하고, 임시 작업공간 절대 경로는 <WORKSPACE> 로 바꾼다.
"""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import os
import re
import shutil
import sys
import tempfile
from collections import Counter
from pathlib import Path
from typing import Any

REPO = Path(__file__).resolve().parents[1]
for p in (REPO / "tests", REPO / "src"):
    if str(p) not in sys.path:
        sys.path.insert(0, str(p))

TEXT_EXT = {".json", ".jsonl", ".md", ".log", ".txt", ".yaml", ".yml"}
LOG_HEAD, LOG_TAIL = 300, 150
SEV_KO = {"critical": "치명", "high": "높음", "medium": "중간", "low": "낮음", "info": "정보"}
CONF_KO = {"confirmed": "확정", "likely": "유력", "possible": "가능성"}

SCENARIOS: dict[str, dict[str, Any]] = {
    "hikvision-like": {
        "title": "hikvision-like 합성 IP 카메라 — UART 덤프와 인증 우회 패턴 탐색 예제",
        "target": {"vendor": "pweh-synthetic (hikvision-like, 실제 벤더 아님)", "model": "SYNTH-HIK-IPC", "hardware_rev": "sim-1",
                   "firmware_version": "synthetic-2020-03-23", "serial": "SIM-HIK-0001"},
        "story": ("Hikvision 스타일 구성(메인 앱 davinci, ISAPI/PSIA/SDK/HikCGI 형 핸들러 계열)을 흉내 낸 합성 카메라다. "
                  "운영자는 자기 소유 카메라라고 확인했고, 보드의 UART 패드에 USB-UART 를 연결했다(여기서는 시뮬레이터 PTY)."),
    },
    "dahua-like": {
        "title": "dahua-like 합성 IP 카메라 — UART 덤프와 인증 우회 패턴 탐색 예제",
        "target": {"vendor": "pweh-synthetic (dahua-like, 실제 벤더 아님)", "model": "SYNTH-DH-IPC", "hardware_rev": "sim-1",
                   "firmware_version": "synthetic-2020-03-23", "serial": "SIM-DH-0001"},
        "story": ("Dahua 스타일 구성(메인 서비스 /usr/bin/sonia, JSON-RPC 로그인, /mnt/mtd/Config)을 흉내 낸 합성 카메라다. "
                  "운영자는 자기 소유 카메라라고 확인했고, 보드의 UART 패드에 USB-UART 를 연결했다(여기서는 시뮬레이터 PTY)."),
    },
}


# ---------------------------------------------------------------------------
# 임시 작업공간
# ---------------------------------------------------------------------------
def make_workspace(base: Path | None = None) -> Path:
    import yaml

    root = Path(tempfile.mkdtemp(prefix="pweh-example-", dir=str(base) if base else None))
    cfg = yaml.safe_load((REPO / "orchestrator" / "pipeline-config.yaml").read_text(encoding="utf-8")) or {}
    cfg.setdefault("workspace", {})
    cfg["workspace"]["cases_dir"] = "cases"
    cfg["workspace"]["state_dir"] = ".pweh/state"
    out = root / "orchestrator" / "pipeline-config.yaml"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(yaml.safe_dump(cfg, allow_unicode=True, sort_keys=False), encoding="utf-8")
    os.environ["PWEH_CONFIG"] = str(out)
    os.environ.pop("PWEH_CASES_DIR", None)
    os.environ.pop("PWEH_STATE_DIR", None)
    from pweh.runtime import reset_runtimes

    reset_runtimes()
    return root


# ---------------------------------------------------------------------------
# 마스킹 / 요약
# ---------------------------------------------------------------------------
class Scrubber:
    def __init__(self, secrets: Any, workspace_root: Path, case_dir: Path) -> None:
        self.secrets = secrets
        # 긴 경로부터: 케이스 → 임시 작업공간 → 저장소 → 홈 디렉터리
        self.repl = [(str(case_dir), "<CASE_DIR>"), (str(workspace_root), "<WORKSPACE>"), (str(REPO), "<REPO>"), (str(Path.home()), "~")]

    def text(self, s: str) -> str:
        for a, b in self.repl:
            s = s.replace(a, b)
        s = self.secrets.mask(s)
        return s

    def obj(self, o: Any) -> Any:
        if isinstance(o, str):
            return self.text(o)
        if isinstance(o, list):
            return [self.obj(x) for x in o]
        if isinstance(o, dict):
            out = {}
            for k, v in o.items():
                if k in ("password", "pass", "passwd") and isinstance(v, str) and v:
                    out[k] = "******"
                else:
                    out[k] = self.obj(v)
            return out
        return o


def mask_plaintext_passwords(obj: Any) -> Any:
    """crack/audit JSON 의 평문 password 필드를 마스킹 (password_masked 는 그대로)."""
    if isinstance(obj, list):
        return [mask_plaintext_passwords(x) for x in obj]
    if isinstance(obj, dict):
        out = {}
        for k, v in obj.items():
            if k == "password" and isinstance(v, str) and v:
                out[k] = (v[:2] + "*" * max(2, len(v) - 2)) if len(v) > 2 else "**"
            else:
                out[k] = mask_plaintext_passwords(v)
        return out
    return obj


def fmt_args(call: Any, scrub: "Scrubber | None" = None) -> str:
    a = scrub.obj(dict(call.args)) if scrub else dict(call.args)
    if call.tool == "case_add_finding":
        return f"finding={{title: {a.get('finding', {}).get('title')!r}, …}}"
    if call.tool == "case_update_finding":
        return f"finding_id={a.get('finding_id')}, patch={{{', '.join(sorted((a.get('patch') or {}).keys()))}}}"
    if call.tool == "case_record_step":
        return f"skill={a.get('skill')}, step={a.get('step')}, status={a.get('status')}, data={{…}}"
    if call.tool == "case_create":
        return f"title=…, authorization={{basis: {a.get('authorization', {}).get('basis')}, statement: …}}, profile={a.get('profile')}"
    parts = []
    for k, v in a.items():
        if k == "case_id":
            continue
        if k in ("password",):
            v = "******"
        sv = json.dumps(v, ensure_ascii=False) if not isinstance(v, str) else repr(v)
        if len(sv) > 70:
            sv = sv[:67] + "…"
        parts.append(f"{k}={sv}")
    return ", ".join(parts)


def brief(call: Any) -> str:
    """README 타임라인용 한 줄 결과 요약."""
    if call.error:
        return f"오류: {call.error[:140]}"
    r = call.result if isinstance(call.result, dict) else {}
    t = call.tool
    if r.get("status") in ("denied", "approval_required"):
        cls = (r.get("gate") or {}).get("classification") or {}
        return f"**{r['status']}** (위험도 {cls.get('risk')}, 규칙 `{cls.get('rule_id')}`)"
    nr = r.get("normalized_result")
    try:
        if t == "pipeline_profiles":
            return f"프로필 {len(r.get('profiles') or [])}개"
        if t == "pipeline_safety_policy":
            pol = r.get("policy") or r
            return f"destructive={pol.get('destructive_policy')}, modify={pol.get('modify_policy')}"
        if t == "case_create":
            return f"case_id={r['case']['id']}, authorized={r['case'].get('authorized')}"
        if t == "uart_list_ports":
            return f"포트 {len(r.get('ports') or [])}개 (PTY 시뮬레이터는 목록에 없음)"
        if t == "uart_open":
            return f"session_id={r.get('session_id')}, context={r.get('context')}, log={r.get('log_path')}"
        if t == "uboot_interrupt":
            return f"interrupted={r.get('interrupted')}, prompt={r.get('prompt')!r}, bootdelay={r.get('bootdelay')}"
        if t == "uboot_printenv":
            return f"변수 {len(r.get('env') or {})}개, 파티션 {[p['name'] for p in r.get('partitions') or []]}, bootcmd={r.get('bootcmd')!r}"
        if t == "uboot_info":
            fl = r.get("flash") or {}
            return f"{r.get('version')}; flash {fl.get('model')} {fl.get('size_bytes')} B; safe_ram_addr={r.get('safe_ram_addr')}"
        if t in ("uboot_dump_start", "shell_dump_start"):
            est = r.get("estimated_seconds") or r.get("eta_seconds")
            return (f"job_id={r.get('job_id')}, 청크 {r.get('chunks')}×{r.get('chunk_size')} B, ram_addr={r.get('ram_addr')}"
                    + (f", 실기기 예상 {est // 60}분" if isinstance(est, int) else ""))
        if t == "uart_job_status":
            res = r.get("result") or {}
            extra = f", sha256={str(res.get('sha256'))[:16]}…, verification={(res.get('verification') or {}).get('method')}" if res else ""
            return f"status={r.get('status')}, progress={r.get('progress')}{extra}"
        if t == "uart_send_command":
            out = (r.get("output") or "").strip().replace("\n", " ⏎ ")
            return f"matched={r.get('matched')}, output={out[:80]!r}"
        if t == "uart_write":
            return f"ok={r.get('ok')}, pending_input={r.get('pending_input')!r}"
        if t == "uart_sync":
            return f"evidence={r.get('evidence')}, context={r.get('context')}"
        if t == "uart_close":
            return f"닫음, 로그 아티팩트 {len(r.get('artifacts') or [])}개"
        if t == "uart_capture_boot":
            return f"{r.get('captured_bytes')} B, kernel={r.get('kernel_version')}, stopped_by={r.get('stopped_by')}"
        if t == "shell_login":
            return f"logged_in={r.get('logged_in')}, status={r.get('status')}"
        if t == "shell_identify":
            return f"kernel={r.get('kernel_version')}, mtd={[m['name'] for m in r.get('mtd') or []]}, uid={(r.get('user') or {}).get('uid')}"
        if t == "fw_identify":
            s = r.get("summary") or {}
            return f"영역 {s.get('region_count')}개 {s.get('kinds')}, arch {s.get('arch_hints')}"
        if t == "fw_entropy":
            return f"profile={str(r.get('profile'))[:60]!r}, 설명 안 되는 고엔트로피 {r.get('unexplained_high_entropy_runs')}"
        if t == "fw_uboot_env":
            lay = r.get("recommended_layout") or {}
            return f"env {len(r.get('envs') or [])}개, 레이아웃 {lay.get('source')}: {lay.get('text')}"
        if t == "fw_carve":
            return f"{r.get('output_dir')}: " + ", ".join(f"{p['name']}({p.get('content')})" for p in r.get("partitions") or [])
        if t == "fw_uimage_info":
            im = r.get("image") or {}
            return f"{im.get('name')} {im.get('arch')} comp={im.get('compression')} hcrc={im.get('header_crc_ok')} dcrc={im.get('data_crc_ok')}"
        if t == "fw_extract_squashfs":
            return f"{r.get('status')} → {r.get('output_dir')} ({(r.get('listing') or {}).get('entries')} 항목)"
        if t == "fw_rootfs_audit":
            v = r.get("vendor") or {}
            return f"항목 {len(r.get('items') or [])}개 {[(i.get('id'), i.get('severity')) for i in (r.get('items') or [])[:4]]}, vendor={v.get('family')}"
        if t == "fw_strings_hunt":
            s = r.get("summary") or {}
            ids = sorted({h.get("pattern_id") for h in r.get("hits") or []})
            return f"히트 {s.get('hits_total')}개 {s.get('by_severity')}: {', '.join(ids[:8])}"
        if t == "fw_elf_info":
            if r.get("mode") == "directory":
                return f"ELF {(r.get('summary') or {}).get('elf_count')}개, 1위 {((r.get('binaries') or [{}])[0]).get('path')}"
            e = r.get("elf") or {}
            return f"{e.get('summary')}, static={e.get('static')}, stripped={e.get('stripped')}, 휴리스틱 {sorted(((r.get('risk') or {}).get('heuristics') or {}).keys())[:5]}"
        if t == "fw_crack_hashes":
            return f"{r.get('counts')} " + ", ".join(f"{x.get('user')}:{x.get('status')}({x.get('password')})" for x in r.get("results") or [])
        if t == "fw_hunt_patterns":
            return f"휴리스틱 {len(r.get('string_heuristics') or [])}개"
        if t == "case_add_finding":
            return f"{r.get('finding_id')} (duplicate={r.get('duplicate')})"
        if t == "case_record_step":
            return f"seq={r.get('seq')}, status={r.get('status')} (스키마 통과)"
        if t == "report_generate":
            return f"{r.get('relative_path')}: 발견 {r.get('findings')}건 {r.get('by_severity')}"
        if t in ("case_get_step_results",):
            if "results" in r:
                return f"단계 기록 {len(r.get('results') or [])}개 (재개할 job 없음)" if not r.get("results") else f"단계 기록 {len(r['results'])}개"
            return f"summaries={sorted((r.get('summaries') or {}).keys())}"
        if t == "case_list_findings":
            return f"{r.get('count')}건"
        if t in ("uart_jobs", "fwtriage_jobs"):
            return f"실행 중 job {len(r.get('jobs') or [])}개"
        if t == "uart_sessions":
            return f"세션 {[(s.get('session_id'), s.get('state')) for s in r.get('sessions') or []]}"
        if call.server == "rea":
            if t == "open_binary":
                return f"{r.get('format')} {r.get('architecture')} sha256={str(r.get('sha256'))[:16]}…"
            if t == "binary_overview" and isinstance(nr, dict):
                return f"Ghidra 분석 완료 ({call.duration:.1f}s), 세그먼트 {len(nr.get('segments') or [])}개"
            if t == "extract_firmware" and isinstance(nr, dict):
                return f"coverage={nr.get('coverage')}, 파일 {len(nr.get('files') or [])}개"
            if t in ("search_procedures", "search_strings") and isinstance(nr, list):
                return ", ".join(str(x.get("value")) for x in nr[:10]) + (f" … (+{len(nr) - 10})" if len(nr) > 10 else "")
            if t == "trace_feature" and isinstance(nr, dict):
                procs = [((x.get("containing_procedure") or {}).get("procedure") or {}).get("name") for x in nr.get("references") or []]
                return f"참조 함수 {sorted({p for p in procs if p})}"
            if t == "procedure_pseudo_code" and isinstance(nr, str):
                return f"의사 C {len(nr.splitlines())}줄 (evidence {str(r.get('evidence_id'))[:15]}…)"
            if t == "find_xrefs_to_name" and isinstance(nr, dict):
                return f"{nr.get('status')} {nr.get('address') or ''} xrefs={len(nr.get('xrefs') or [])}"
            if t == "procedure_callers" and isinstance(nr, list):
                return f"호출자 {nr}"
            if t == "export_evidence_bundle":
                return f"{r.get('records')} 레코드, {r.get('bytes')} B"
            if t == "close_binary":
                return "세션 닫음"
        if r.get("ok") is True:
            return "ok"
    except Exception as exc:  # 요약 실패는 무시
        return f"(요약 실패: {exc})"
    return "ok" if r else str(call.result)[:80]


# ---------------------------------------------------------------------------
# 패키징
# ---------------------------------------------------------------------------
def trim_lines(text: str, head: int = LOG_HEAD, tail: int = LOG_TAIL) -> str:
    lines = text.splitlines()
    if len(lines) <= head + tail + 1:
        return text
    cut = len(lines) - head - tail
    return "\n".join(lines[:head] + [f"… ({cut}줄 생략: 예제 크기를 줄이려고 잘랐다. 원본은 케이스의 같은 파일) …"] + lines[-tail:]) + "\n"


def file_sha(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def copy_case(case_dir: Path, dest: Path, scrub: Scrubber) -> dict[str, Any]:
    """케이스 사본: 텍스트는 마스킹·경로 치환, 큰 바이너리·추출 트리·원시 바이트는 제외하고 목록에 남긴다."""
    excluded: list[dict[str, Any]] = []
    trimmed: list[str] = []
    for src in sorted(case_dir.rglob("*")):
        rel = src.relative_to(case_dir).as_posix()
        if rel.split("/", 1)[0] == "extract":
            continue  # 아래에서 디렉터리 단위로 요약
        if src.is_dir() or src.name.startswith(".case.lock"):
            continue
        if src.is_symlink():
            excluded.append({"path": rel, "reason": "symlink", "target": os.readlink(src)})
            continue
        size = src.stat().st_size
        if src.suffix in (".bin", ".raw", ".part") or src.suffix not in TEXT_EXT:
            excluded.append({"path": rel, "size": size, "sha256": file_sha(src), "reason": "바이너리 (덤프·원시 UART 바이트) — 크기와 sha256 만 기록"})
            continue
        text = src.read_text(encoding="utf-8", errors="replace")
        if rel.startswith("analysis/") and src.suffix == ".json" and ("crack-hashes" in src.name or "rootfs-audit" in src.name):
            text = json.dumps(mask_plaintext_passwords(json.loads(text)), ensure_ascii=False, indent=2) + "\n"
        if rel.startswith("uart/") and src.suffix in (".log", ".jsonl"):
            new = trim_lines(text)
            if new != text:
                trimmed.append(rel)
            text = new
        if rel == "audit.jsonl":
            new = trim_lines(text, 400, 200)
            if new != text:
                trimmed.append(rel)
            text = new
        out = dest / rel
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(scrub.text(text), encoding="utf-8")
    extract = case_dir / "extract"
    trees = []
    if extract.is_dir():
        for d in sorted(extract.iterdir()):
            files = [p for p in d.rglob("*") if p.is_file() and not p.is_symlink()] if d.is_dir() else [d]
            entry: dict[str, Any] = {"path": f"extract/{d.name}", "kind": "dir" if d.is_dir() else "file",
                                     "files": len(files), "bytes": sum(p.stat().st_size for p in files)}
            if d.is_dir() and len(files) <= 80:
                entry["file_sha256"] = {p.relative_to(case_dir).as_posix(): file_sha(p) for p in sorted(files)}
            elif d.is_file():
                entry["sha256"] = file_sha(d)
            trees.append(entry)
    manifest = {
        "note": "예제에 넣지 않은 파일 목록 (펌웨어 덤프·파티션·추출 트리·원시 UART 바이트). 같은 명령으로 다시 만들면 같은 sha256 이 나온다(덤프/추출물).",
        "excluded_files": excluded,
        "extract_trees": trees,
        "trimmed_text_files": trimmed,
        "path_placeholders": {"<CASE_DIR>": "케이스 디렉터리 절대 경로", "<WORKSPACE>": "임시 작업공간 절대 경로",
                              "<REPO>": "저장소 루트", "~": "실행한 사용자의 홈 디렉터리"},
    }
    (dest / "excluded-files.json").write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return manifest


def write_tool_calls(res: Any, path: Path, scrub: Scrubber) -> None:
    from e2e.agent_flow import abridge_result

    with path.open("w", encoding="utf-8") as fh:
        for c in res.rec.calls:
            row = {"seq": c.seq, "t": c.t, "phase": c.phase, "server": c.server, "tool": c.tool, "args": scrub.obj(c.args),
                   "duration_s": c.duration, "ok": c.ok, "status": c.status, "error": scrub.text(c.error) if c.error else None,
                   "result": scrub.obj(abridge_result(c.server, c.tool, c.result))}
            fh.write(json.dumps(row, ensure_ascii=False) + "\n")


def _md(s: Any) -> str:
    return str(s).replace("|", "\\|").replace("\n", " ")


def render_readme(res: Any, *, name: str, command: str, scrub: Scrubber, excluded: dict[str, Any], gate: list[dict[str, Any]] | None) -> str:
    flow = res.flow
    man = res.manifest
    st = flow.st
    findings = (st.get("findings_final") or {}).get("findings") or []
    sev = Counter(f["severity"] for f in findings)
    planted = man.get("planted_issues") or []
    cov = res.coverage
    surfaced = sum(1 for p in planted if cov.get(p["id"]))
    dump = st["dump"]
    plan = st["dump_plan"]
    meta = st["dump_meta"]
    img_ok = dump["sha256"] == (man["image"]["sha256"] if plan["length"] == man["image"]["size"] else None)
    prof = man.get("profile")
    scen = SCENARIOS.get(prof, {})
    L: list[str] = []
    add = L.append
    add(f"# {name}: {scen.get('title', prof)}")
    add("")
    add("> **합성 예제.** 기기는 `pweh.mocktarget` 시뮬레이터이고 펌웨어는 PWEH 가 만든 합성 테스트 펌웨어다 "
        "(`PWEH SYNTHETIC TEST FIRMWARE - NOT VENDOR CODE`). 실제 벤더 코드·키·자격증명·공격 요청은 없다. "
        "이 디렉터리의 모든 출력은 `scripts/run_example.py` 를 실제로 실행해 얻었다 (손으로 쓴 결과 없음).")
    add("")
    add("## 한 줄 결론")
    add("")
    parts = ", ".join(f"{SEV_KO[s]} {sev[s]}" for s in ("critical", "high", "medium", "low", "info") if sev.get(s))
    add(f"U-Boot 프롬프트 확보 → 플래시 {dump['size'] // (1024 * 1024)} MiB 덤프(청크별 crc32 일치) → rootfs 추출·감사"
        f"{' + REA/Ghidra 디컴파일' if res.rea_used else ''} → 발견사항 {len(findings)}건 ({parts}). "
        f"심어 둔 정답 {len(planted)}개 중 {surfaced}개가 도구 출력에 드러났고, 기기에 닿은 파괴적 명령은 {len(res.dev_destructive)}건이다.")
    add("")
    add("## 1. 시나리오")
    add("")
    add(f"- {scen.get('story', '')}")
    add(f"- 소유/허가 확인 (사람의 말 그대로 인용, 합성): \"{flow.scenario.statement}\"")
    add(f"- 케이스 프로필: `{flow.case_profile}` (orchestrator/pipeline-config.yaml), 시뮬레이터 프로필: `{prof}`")
    add("- 역할: **사람**은 배선·전원·동의를 맡고(타임라인의 `[사람]` 줄), **에이전트**는 MCP 도구만 쓴다. 에이전트 판단은 "
        "`tests/e2e/agent_flow.py` 에 스크립트로 들어 있고 Skill 순서(uart-shell-acquisition → firmware-dump-via-uart → "
        "firmware-static-analysis → cctv-auth-bypass-hunt → report)를 따른다.")
    add(f"- REA/Ghidra: {'사용함 (rea --mcp, Ghidra 12.1.x)' if res.rea_used else '건너뜀 — ' + str(res.rea_error or '요청하지 않음 (--no-rea)')}")
    add("")
    add("## 2. 무엇이 합성인가")
    add("")
    add("| 구성요소 | 실체 |")
    add("|---|---|")
    add("| 기기 | `pweh.mocktarget.MockDevice` (U-Boot 2016.11 포크 흉내, HiSilicon V4 유사 하드웨어, PTY 로 연결) |")
    add(f"| 펌웨어 | `pweh.mocktarget.firmware.build_image('{prof}')` 가 만든 16 MiB SPI NOR 이미지, sha256 `{man['image']['sha256']}` (빌드는 결정적) |")
    vend = [b for b in man.get("binaries") or [] if str(b.get("source", "")).startswith("profiles/")]
    for b in vend:
        add(f"| 벤더 스타일 메인 앱 | `{b['path']}` ← `src/pweh/mocktarget/{b['source']}` (zig {b['target']}, 합성 C 코드) |")
    add("| 공통 웹 서버 | `/usr/sbin/httpd` ← `src/pweh/mocktarget/firmware_src/httpd.c` (합성) |")
    add("| 벤더 이름·경로 | `docs/references/cctv-vuln-patterns.md` §3 에 공개된 펌웨어 쪽 지표(바이너리 이름, 배너, 핸들러·설정 경로)만 빌림 |")
    add("| 토큰·비밀번호 | 모두 합성 값. 이 예제에서는 마스킹(`<마스킹:…>`)했다 |")
    add("")
    add("심어 둔 정답(ground truth, 펌웨어 매니페스트 `planted_issues`). 에이전트 흐름은 이 목록을 읽지 않는다:")
    add("")
    add("| ID | 분류 | 심각도 | 파일 :: 함수 | 내용 | 모델로 삼은 공개 클래스 |")
    add("|---|---|---|---|---|---|")
    for p in planted:
        add(f"| {p['id']} | {p['category']} | {p['severity']} | `{p['file']}`{' :: `' + p['function'] + '`' if p.get('function') else ''} | "
            f"{_md(scrub.text(p['title']))} | {p.get('modelled_on') or '(공통 합성 httpd/rootfs)'} |")
    add("")
    add("## 3. 재현 방법")
    add("")
    add("```bash")
    add(f"cd {REPO.name} && {command}")
    add("```")
    add("")
    add("- 필요: `.venv` (pip install -e \".[dev]\"), `~/pweh-tools` 의 zig·mksquashfs·unsquashfs (전체 합성 펌웨어 빌드와 squashfs 추출).")
    add("- 선택: REA(`rea --mcp`) + Ghidra (`~/pweh-tools/env.sh`). 없으면 디컴파일 단계를 건너뛰고 README 에 그 사실을 적는다 (`--no-rea` 로 강제).")
    add(f"- 소요: 약 {int(res.elapsed)}초 (덤프는 시뮬레이터라 빠르다. 실기기 115200bps 에서 {dump['size'] // (1024 * 1024)} MiB md.b 덤프는 약 "
        f"{dump['size'] * 4.94 / 11520 / 3600:.1f}시간).")
    add(f"- 시각·job id·PTY 경로·evidence id 는 실행마다 다르다 (케이스 ID 는 `example-{name}` 로 고정). 같은 도구 버전이면 펌웨어·덤프·추출물의 sha256 은 같다.")
    add("- 같은 흐름이 `tests/e2e/test_pipeline_e2e.py` 의 테스트다 (`.venv/bin/python -m pytest tests/e2e -q`).")
    add("")
    add("## 4. 타임라인 (도구 호출과 요약 응답)")
    add("")
    add("전체 인자·응답(요약)은 [tool-calls.jsonl](tool-calls.jsonl). `[사람]` 은 사람이 한 일, `[에이전트]` 는 에이전트의 판단·안내다.")
    add("")
    add("| # | t(s) | 단계 | 서버 | 도구 / 행동 | 인자 | 응답 요약 |")
    add("|---|---|---|---|---|---|---|")
    calls = {c.seq: c for c in res.rec.calls}
    for ev in res.rec.timeline:
        if ev["kind"] == "call":
            c = calls[ev["seq"]]
            add(f"| {c.seq} | {c.t:.1f} | {_md(c.phase)} | {c.server} | `{c.tool}` | {_md(fmt_args(c, scrub))} | {_md(scrub.text(brief(c)))} |")
        else:
            add(f"|  | {ev['t']:.1f} | {_md(ev['phase'])} |  | *{_md(scrub.text(ev['text']))}* |  |  |")
    add("")
    add("## 5. 결과")
    add("")
    add("### 5.1 덤프 무결성")
    add("")
    ver = meta.get("verification") or {}
    add(f"- 방법 `{meta.get('method')}` (U-Boot `sf read` → `md.b`), 범위 0x{plan['offset']:x}+0x{plan['length']:x} ({scrub.text(plan['why'])}), 청크 {flow.chunk_size}")
    add(f"- 검증 `{ver.get('method')}` → match={ver.get('match')}, 청크 {(meta.get('chunks') or {}).get('count')}개, 재시도 {(meta.get('chunks') or {}).get('retries')}회")
    add(f"- 덤프 sha256 `{dump['sha256']}`" + (f" = 합성 펌웨어 이미지 sha256 (전체 일치: {img_ok})" if plan['length'] == man['image']['size'] else ""))
    add("")
    add("### 5.2 발견사항")
    add("")
    add("| ID | 심각도 | 신뢰도 | 분류 | 제목 | 위치 |")
    add("|---|---|---|---|---|---|")
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    for f in sorted(findings, key=lambda x: (order.get(x["severity"], 9), x["id"])):
        loc = f.get("location") or {}
        where = f"`{loc.get('file')}`" + (f" :: `{loc.get('function')}`" if loc.get("function") else "")
        add(f"| {f['id']} | {SEV_KO.get(f['severity'])} | {CONF_KO.get(f['confidence'])} | {f['category']} | {_md(scrub.text(f['title']))} | {where} |")
    add("")
    add("근거·증거 발췌·검증 계획·권고는 [case/report.md](case/report.md) 와 [case/findings.json](case/findings.json).")
    add("")
    add("### 5.3 정답 대조 (평가)")
    add("")
    add("테스트·예제 생성기가 **기록된 도구 출력**만으로 대조했다: 같은 파일이고, 같은 함수를 디컴파일했거나 정답의 지표 문자열이 출력에 있으면 '드러남'.")
    add("")
    add("| 정답 | 드러낸 도구 출력 (호출 #) | 대응 발견사항 |")
    add("|---|---|---|")
    for p in planted:
        obs = cov.get(p["id"]) or []
        tools: dict[str, list[int]] = {}
        for o in obs:
            tools.setdefault(o.tool, [])
            if o.seq not in tools[o.tool]:
                tools[o.tool].append(o.seq)
        tdesc = "; ".join(f"`{t}` #{','.join(map(str, s[:4]))}" for t, s in tools.items()) or "**드러나지 않음**"
        fids = [f["id"] for f in findings if (f.get("location") or {}).get("file") == p["file"] and f["category"] == p["category"]]
        add(f"| {p['id']} | {tdesc} | {', '.join(fids) or '-'} |")
    add("")
    ah = None
    for s in sorted((flow.case_dir / "steps").glob("*cctv-auth-bypass-hunt-summary.json")):
        ah = json.loads(s.read_text(encoding="utf-8"))
    if ah:
        add("### 5.4 cctv-auth-bypass-hunt 점검표 (AH-01 ~ AH-12)")
        add("")
        add(f"vendor_family: `{ah['data']['vendor_family']}` — 근거: {_md('; '.join(ah['data'].get('vendor_evidence') or []))}")
        add("")
        add("| 항목 | 판정 | 발견사항 | 설명 |")
        add("|---|---|---|---|")
        for c in ah["data"]["checks"][:12]:
            add(f"| {c['id']} | {c['result']} | {c.get('finding_id') or '-'} | {_md(scrub.text(c.get('description', '')))} |")
        add("")
    add("### 5.5 안전 게이트")
    add("")
    add(f"- 정책: destructive=`{(st.get('safety_policy') or {}).get('policy', st.get('safety_policy') or {}).get('destructive_policy')}` (기본 거부).")
    if gate:
        add("- **의도적 실수 시연**: 에이전트가 U-Boot 프롬프트에서 영구 변경 명령을 보내 보았다. 서버 게이트가 모두 거부했고 에이전트는 우회하지 않고 다음 단계로 갔다.")
        add("")
        add("| 시도 | 결과 |")
        add("|---|---|")
        for g in gate:
            add(f"| `{_md(g['command'])}` | {g.get('status')} (ok={g.get('ok')}) |")
        add("")
    audit = [json.loads(ln) for ln in (flow.case_dir / "audit.jsonl").read_text(encoding="utf-8").splitlines() if ln.strip()]
    dec = Counter(e.get("status") for e in audit if e.get("event") == "safety_decision")
    add(f"- 감사 기록(`case/audit.jsonl`)의 안전 결정: {dict(dec)}")
    add(f"- 시뮬레이터 오라클 `MockDevice.destructive_events` = {len(res.dev_destructive)}건 (기기에 닿은 파괴적 명령 없음). 영구 변경 없음.")
    add("")
    add("### 5.6 한계")
    add("")
    for g in dict.fromkeys(flow.gaps + flow.rea_limitations):
        add(f"- {scrub.text(g)}")
    add("- 정적 분석 결과다. 동적 확인은 격리 랩의 소유 기기에서 negative test 로만 한다 (각 발견사항의 verification_plan).")
    add("- **'확정(confirmed)' 의 의미**: 스크립트 에이전트의 디컴파일 판독 규칙(`tests/e2e/agent_flow.py: classify_pseudocode`)은 이 합성 소스의 "
        "함수 이름·구조(예: `query_param`, `basic_auth_check`, `is_local_request`, `session_valid`)를 알고 만든 휴리스틱이다. "
        "그래서 이 예제의 '확정' 은 서버·REA·Ghidra 파이프라인이 끝까지 동작하고 증거가 기록된다는 뜻이며, 구조를 모르는 실제·strip 된 펌웨어에서의 "
        "탐지 성능을 보여 주지 않는다. 실제 분석에서는 사람(또는 LLM 에이전트)이 디컴파일 결과를 직접 읽고 판정한다.")
    add("- 시뮬레이터의 리눅스 셸 화면은 공통 rootfs 로 만들어져 벤더 스타일 파일이 `ls` 에 보이지 않는다 (덤프한 플래시 바이트에는 있다).")
    add("")
    add("## 6. 파일")
    add("")
    add("| 경로 | 내용 |")
    add("|---|---|")
    add("| `summary.json` | 이 실행의 기계 판독용 요약 (REA 사용 여부, 덤프·이미지 sha256, 발견 수, 정답별 드러낸 도구 호출) |")
    add("| `tool-calls.jsonl` | MCP 호출 전체: seq, t, phase, server, tool, args, duration_s, ok/status/error, result(요약) |")
    add("| `case/case.json` | 케이스 메타데이터 (대상, 소유/허가, 단계 상태, 아티팩트 색인) |")
    add("| `case/steps/` | Skill 단계 결과 (summary 는 각 Skill 출력 스키마를 통과) |")
    add("| `case/findings.json`, `case/report.md` | 발견사항, `report_generate` 보고서 |")
    add("| `case/analysis/` | fwtriage 결과 JSON" + (", REA 증거 묶음 (`rea-evidence-*.json`)" if res.rea_used else "") + " |")
    add("| `case/dumps/*.json` | 덤프 메타데이터 (청크별 crc32 대조 기록) |")
    add("| `case/uart/` | UART 세션 로그·이벤트 (긴 로그는 앞뒤만 남김) |")
    add("| `case/audit.jsonl` | 안전 결정·기기 조작 감사 기록 |")
    add(f"| `case/excluded-files.json` | 넣지 않은 파일 {len(excluded['excluded_files'])}개와 추출 트리 {len(excluded['extract_trees'])}개의 크기·sha256 |")
    add("")
    add("텍스트 안의 `<CASE_DIR>`/`<WORKSPACE>`/`<REPO>`/`~` 는 실행 환경의 절대 경로를 바꾼 자리표시자다. 비밀값은 `<마스킹:…>` 으로 바꿨다 (safety.md §7).")
    add("")
    return "\n".join(L)


def package_example(res: Any, out_dir: Path, *, name: str, workspace_root: Path, command: str,
                    gate: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    """RunResult → 예제 디렉터리 (README.md, tool-calls.jsonl, case/)."""
    flow = res.flow
    out_dir = Path(out_dir)
    if out_dir.exists():
        shutil.rmtree(out_dir)
    out_dir.mkdir(parents=True)
    scrub = Scrubber(flow.secrets, Path(workspace_root), flow.case_dir)
    excluded = copy_case(flow.case_dir, out_dir / "case", scrub)
    write_tool_calls(res, out_dir / "tool-calls.jsonl", scrub)
    gate = gate if gate is not None else res.extra.get("mistakes")
    readme = render_readme(res, name=name, command=command, scrub=scrub, excluded=excluded, gate=gate)
    (out_dir / "README.md").write_text(readme, encoding="utf-8")
    summary = {
        "name": name, "profile": res.manifest.get("profile"), "case_id": flow.case_id, "rea_used": res.rea_used, "rea_error": res.rea_error,
        "image_sha256": res.manifest["image"]["sha256"], "dump_sha256": flow.st["dump"]["sha256"], "dump_size": flow.st["dump"]["size"],
        "findings": len((flow.st.get("findings_final") or {}).get("findings") or []),
        "planted": {p["id"]: list(dict.fromkeys(f"{o.tool}#{o.seq}" for o in res.coverage.get(p["id"], [])))[:12]
                    for p in res.manifest.get("planted_issues") or []},
        "destructive_events": len(res.dev_destructive), "calls": len(res.rec.calls), "elapsed_s": res.elapsed,
        "command": command,
    }
    (out_dir / "summary.json").write_text(json.dumps(scrub.obj(summary), ensure_ascii=False, indent=1) + "\n", encoding="utf-8")
    return summary


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
async def _run(args: argparse.Namespace) -> int:
    from e2e.agent_flow import Scenario, build_firmware, rea_available, run_pipeline

    ws = make_workspace(Path(args.workspace_base) if args.workspace_base else None)
    try:
        image, manifest = build_firmware(args.profile, ws / "firmware")
        if manifest.get("fallbacks"):
            print(f"전체 합성 펌웨어를 만들 수 없음 (대체 빌드: {manifest['fallbacks']}) — zig/mksquashfs 확인", file=sys.stderr)
            return 2
        use_rea = not args.no_rea
        if use_rea:
            ok, why = rea_available()
            if not ok:
                print(f"REA 없음 → 디컴파일 단계 건너뜀: {why}", file=sys.stderr)
        sc = SCENARIOS.get(args.profile, {})
        scenario = Scenario(title=sc.get("title", f"{args.profile} 예제"), target=sc.get("target") or {})
        res = await run_pipeline(args.profile, image, manifest, scenario=scenario, use_rea=use_rea, dump_scope=args.dump_scope,
                                 chunk_size=args.chunk_size, rea_cwd=ws, mistakes=not args.no_gate_demo,
                                 case_id=f"example-{args.name}")
        out = Path(args.out) if args.out else REPO / "examples" / args.name
        cmd = f".venv/bin/python scripts/run_example.py --profile {args.profile} --name {args.name}"
        if args.dump_scope != "full":
            cmd += f" --dump-scope {args.dump_scope}"
        if args.no_rea:
            cmd += " --no-rea"
        summary = package_example(res, out, name=args.name, workspace_root=ws, command=cmd)
        print(json.dumps(summary, ensure_ascii=False, indent=1))
        missing = [k for k, v in summary["planted"].items() if not v]
        if missing or summary["destructive_events"]:
            print(f"경고: 드러나지 않은 정답 {missing}, destructive {summary['destructive_events']}", file=sys.stderr)
            return 1
        return 0
    finally:
        if args.keep_workspace:
            print(f"작업공간 유지: {ws}", file=sys.stderr)
        else:
            shutil.rmtree(ws, ignore_errors=True)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="시뮬레이터로 PWEH 파이프라인을 돌려 examples/<name>/ 을 만든다.")
    ap.add_argument("--profile", required=True, help="시뮬레이터 프로필 (hikvision-like, dahua-like, hisilicon-like …)")
    ap.add_argument("--name", required=True, help="예제 이름 (examples/<name>/)")
    ap.add_argument("--out", help="출력 디렉터리 (기본 examples/<name>)")
    ap.add_argument("--dump-scope", default="full", help="full | needed | <파티션 이름> (기본 full)")
    ap.add_argument("--chunk-size", default="256k")
    ap.add_argument("--no-rea", action="store_true", help="REA/Ghidra 단계를 건너뛴다")
    ap.add_argument("--no-gate-demo", action="store_true", help="안전 게이트 실수 시연을 넣지 않는다")
    ap.add_argument("--keep-workspace", action="store_true")
    ap.add_argument("--workspace-base", help="임시 작업공간을 만들 부모 디렉터리 (기본: 시스템 임시 디렉터리)")
    args = ap.parse_args(argv)
    if not re.fullmatch(r"[A-Za-z0-9._-]+", args.name):
        ap.error("--name 은 [A-Za-z0-9._-] 만")
    return asyncio.run(_run(args))


if __name__ == "__main__":
    sys.exit(main())
