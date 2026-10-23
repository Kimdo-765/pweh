"""케이스 → Markdown 보고서."""

from __future__ import annotations

import json
from collections import Counter
from pathlib import Path
from typing import Any

from . import __version__
from .case import PIPELINE_PHASES, SEVERITY_ORDER, Case, phase_sort_key
from .fsutil import atomic_write_text, read_json, sha256_file, utcnow_iso

_SEV_LABEL = {"critical": "치명", "high": "높음", "medium": "중간", "low": "낮음", "info": "정보"}
_CONF_LABEL = {"confirmed": "확정", "likely": "유력", "possible": "가능성"}
_STATUS_LABEL = {
    "unverified": "미검증",
    "static-confirmed": "정적 확인",
    "dynamically-confirmed": "동적 확인",
    "false-positive": "오탐",
    "wont-verify": "검증 안 함",
}
_PHASE_LABEL = {
    "uart-shell-acquisition": "UART 셸/U-Boot 획득",
    "firmware-dump-via-uart": "펌웨어 덤프",
    "logic-analyzer-protocol-decode": "로직 애널라이저 디코딩",
    "firmware-static-analysis": "펌웨어 정적 분석",
    "cctv-auth-bypass-hunt": "CCTV 인증 우회 탐색",
    "report": "보고서",
    # 선택 단계(case.OPTIONAL_PHASES): 상태나 요약이 기록된 케이스에서만 §4 '선택 단계' 에 보인다
    "game-save-unlock-analysis": "게임 세이브·해금 분석",
    "numeric-observation-analysis": "공급 숫자 관측값 분석",
    "image-template-analysis": "저장 PNG 영역 비교",
    "nfc-behavior-analysis": "NFC 동작 분석",
    "game-play-automation": "게임 플레이 자동화",
    "flipper-rf-analysis": "Flipper·RF 분석",
    "sd-card-forensics": "SD 카드 포렌식",
    "firmware-emulation": "MCU 펌웨어 에뮬레이션",
    "android-forensics": "Android 논리 증거 분석",
    "image-hints-analysis": "정지 이미지 힌트 분석",
    "espprobe": "ESP32 계측기(espprobe)",
}


def _gap_text(g: Any) -> str:
    """추출 gap 한 줄. 문자열은 그대로, 객체({region, kind, count, note} — Skill 예시 형식)는 '영역 — 종류 ×개수: 메모'."""
    if not isinstance(g, dict):
        return str(g)
    head = " — ".join(f"`{g[k]}`" if k == "region" else str(g[k]) for k in ("region", "kind") if g.get(k))
    if g.get("count") not in (None, "", 1):
        head += f" ×{g['count']}"
    note = g.get("note")
    if head and note:
        return f"{head}: {note}"
    return head or str(note or "") or json.dumps(g, ensure_ascii=False)


def _md_escape(text: Any) -> str:
    s = "" if text is None else str(text)
    return s.replace("|", "\\|").replace("\n", " ")


def _code(text: str, lang: str = "") -> str:
    fence = "```"
    while fence in text:
        fence += "`"
    return f"{fence}{lang}\n{text.rstrip()}\n{fence}"


def _phase_row(phase: str, entry: dict[str, Any]) -> str:
    return f"| {_PHASE_LABEL.get(phase, phase)} | {entry.get('status', 'pending')} | {entry.get('updated_at', '')} |"


def _summary_block(s: dict[str, Any], heading: str) -> list[str]:
    """단계 요약 한 개 (상태·요약·차단 요인·다음 조치·산출물). data 는 싣지 않는다(비밀값 마스킹은 Skill 별 절이 맡는다)."""
    out = [f"{heading} {_PHASE_LABEL.get(s.get('skill'), s.get('skill'))} — {s.get('status')}", "", s.get("summary", ""), ""]
    if s.get("blockers"):
        out.append("- 차단 요인: " + "; ".join(s["blockers"]))
    if s.get("next_actions"):
        out.append("- 다음 조치: " + "; ".join(s["next_actions"]))
    if s.get("artifacts"):
        out.append("- 산출물: " + ", ".join(f"`{a}`" for a in s["artifacts"]))
    out.append("")
    return out


def _audit_stats(case: Case) -> dict[str, Any]:
    path = case.dir / "audit.jsonl"
    stats: Counter[str] = Counter()
    risky: list[dict[str, Any]] = []
    if path.exists():
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            try:
                ev = json.loads(line)
            except json.JSONDecodeError:
                continue
            if ev.get("event") == "safety_decision":
                stats[f"{ev.get('status')}"] += 1
                cls = ev.get("classification") or {}
                if cls.get("risk") in ("modify", "destructive") and len(risky) < 40:
                    risky.append({"ts": ev.get("ts"), "server": ev.get("server"), "tool": ev.get("tool"), "status": ev.get("status"),
                                  "risk": cls.get("risk"), "rule": cls.get("rule_id"), "matched": cls.get("matched"), "via": ev.get("via")})
    return {"counts": dict(stats), "risky": risky}


def _evidence_section(case: Case, anchor_dir: Path | None) -> list[str]:
    """SD 카드 증거 목록·보관 기록 상태·고지 (pweh.evidence). 녹화 내용은 넣지 않는다 — 개수·크기·해시만.

    상태 칸은 사람이 읽는 status_label(없으면 status)이다 — 지워진 증거에 앞선 무결성 실패가 있으면 'missing (integrity-failed)'."""
    from . import evidence

    if not evidence.forensics_dir(case).is_dir():
        return []
    items = evidence.evidence_items(case, anchor_dir)
    chain = items["custody"]
    out = ["## 8.1 SD 카드 증거", ""]
    state = "정상" if chain["ok"] else f"깨짐 — {_md_escape(chain.get('detail'))}"
    anchored = "보호 위치의 고정점과 대조함" if anchor_dir is not None else "고정점 대조 안 함"
    out.append(f"보관 기록(forensics/custody.jsonl): {state} (항목 {chain['count']}개, {anchored})")
    out.append("")
    if items["items"]:
        out.append("| 증거 | 라벨 | 크기 | sha256 | 상태 | 마지막 검증 | 쓰기 방지 장치 증명 |")
        out.append("|---|---|---|---|---|---|---|")
        for it in items["items"]:
            lv = it.get("last_verify") or {}
            att = it.get("attestation") or {}
            out.append(f"| {it['evidence_id']} | {_md_escape(it.get('label') or '')} | {it.get('size', '')} | "
                       f"`{((it.get('hashes') or {}).get('sha256') or '')[:16]}` | {_md_escape(it.get('status_label') or it.get('status'))} | "
                       f"{_md_escape(lv.get('result') or '없음')} | {_md_escape(att.get('status') or '증명 없음')} |")
    else:
        out.append("접수한 증거가 없다.")
    out.append("")
    out.append("전체 해시·해시값 확인서는 forensics/evidence-list.md (forensics_evidence_list) 에 있다.")
    out.append("")
    out.append(f"> {evidence.FORENSICS_NOTICE}")
    out.append("")
    return out


def render_report(case: Case, anchor_dir: Path | None = None) -> str:
    """보고서 Markdown. anchor_dir: SD 카드 보관 기록의 고정점 위치(<state_dir>/custody — 주면 대조한다)."""
    meta = case.load()
    findings = case.findings()
    sev_counts = Counter(f.get("severity", "info") for f in findings)
    lines: list[str] = []
    add = lines.append

    add(f"# 하드웨어 보안 분석 보고서 — {meta.get('title')}")
    add("")
    add(f"- 케이스 ID: `{meta['id']}`")
    add(f"- 프로필: `{meta.get('profile')}`")
    add(f"- 생성: {meta.get('created_at')} / 보고서 생성: {utcnow_iso()}")
    add(f"- 도구: pweh {__version__}")
    add("")
    add("> 이 보고서는 소유자이거나 서면 허가를 받은 기기에 대한 연구·방어 목적의 분석 결과다. "
        "결과를 제3자 시스템 공격에 사용해서는 안 된다.")
    add("")

    # 1. 요약
    add("## 1. 요약")
    add("")
    if findings:
        parts = [f"{_SEV_LABEL[s]} {sev_counts[s]}건" for s in SEVERITY_ORDER if sev_counts.get(s)]
        add(f"발견사항 총 {len(findings)}건 ({', '.join(parts)}).")
        add("")
        top = [f for f in findings if f.get("severity") in ("critical", "high")][:5]
        for f in top:
            add(f"- **[{_SEV_LABEL.get(f.get('severity'), f.get('severity'))}] {f['id']} {f['title']}** — {f.get('summary')}")
    else:
        add("기록된 발견사항이 없다.")
    add("")
    recon = case.latest_summary("uart-shell-acquisition")
    dump = case.latest_summary("firmware-dump-via-uart")
    if recon:
        d = recon.get("data", {})
        add(f"- 콘솔 접근: 포트 `{d.get('port')}` @ {d.get('baudrate')} bps, 콘솔 유형 `{d.get('console_type')}`, 접근 수준 `{d.get('access_level')}`")
    if dump:
        d = dump.get("data", {})
        out = d.get("output", {})
        ver = d.get("verification", {})
        add(f"- 펌웨어 확보: `{out.get('path')}` ({out.get('size')} bytes, sha256 `{out.get('sha256')}`), 방법 `{d.get('method')}`, 검증 `{ver.get('method')}` → {ver.get('match')}")
    add("")

    # 2. 권한
    add("## 2. 범위와 권한")
    add("")
    auth = meta.get("authorization")
    if auth:
        basis = {"owned": "본인 소유", "written-authorization": "서면 허가"}.get(auth.get("basis"), auth.get("basis"))
        add(f"- 근거: {basis}")
        add(f"- 소유자/허가 주체: {auth.get('owner')}")
        add(f"- 진술: \"{auth.get('statement')}\"")
        add(f"- 범위: {auth.get('scope')}")
        if auth.get("document_ref"):
            add(f"- 허가 문서: {auth.get('document_ref')}")
        add(f"- 기록: {auth.get('attested_at')} ({auth.get('attested_via')}, {auth.get('attested_by')})")
    else:
        add("**경고: 소유/허가 증명이 기록되지 않았다.**")
    add("")

    # 3. 대상
    add("## 3. 대상 기기")
    add("")
    target = meta.get("target") or {}
    if target:
        add("| 항목 | 값 |")
        add("|---|---|")
        for k, v in target.items():
            add(f"| {_md_escape(k)} | {_md_escape(v)} |")
    else:
        add("대상 정보가 기록되지 않았다.")
    add("")

    # 4. 단계
    add("## 4. 파이프라인 단계")
    add("")
    add("| 단계 | 상태 | 갱신 |")
    add("|---|---|---|")
    phases = meta.get("phases") or {}
    for p in PIPELINE_PHASES:
        add(_phase_row(p, phases.get(p) or {}))
    add("")
    # 스킬별 최신 summary 만 사용 (같은 스킬의 요약을 다시 저장해도 보고서가 중복되지 않게)
    latest: dict[str, dict[str, Any]] = {}
    for st in case.steps(load=True):
        if st.get("step") == "summary":
            latest[st.get("skill")] = st
    # 순서: 파이프라인 단계 → 선택 단계(레지스트리 순서) → 그 밖의 Skill (같은 순위에서는 기록 순서)
    summaries = sorted(latest.values(), key=lambda st: (phase_sort_key(str(st.get("skill") or "")), st.get("seq", 0)))
    for s in summaries:
        if s.get("skill") in PIPELINE_PHASES:
            lines.extend(_summary_block(s, "###"))
    # 선택 단계: 파이프라인 밖의 단계(목표별 Skill 등). 상태나 요약이 기록된 것만 싣고, 없으면 아무것도 쓰지 않는다
    # (선택 단계를 쓰지 않는 기존 케이스의 보고서는 그대로)
    extra_phases = sorted((p for p in phases if p not in PIPELINE_PHASES), key=phase_sort_key)
    extra_summaries = [s for s in summaries if s.get("skill") not in PIPELINE_PHASES]
    if extra_phases or extra_summaries:
        add("### 선택 단계")
        add("")
        add("보안 분석 파이프라인 밖의 단계(목표별 Skill). 상태나 요약이 기록된 단계만 싣는다.")
        add("")
        if extra_phases:
            add("| 단계 | 상태 | 갱신 |")
            add("|---|---|---|")
            for p in extra_phases:
                entry = phases.get(p)
                add(_phase_row(p, entry if isinstance(entry, dict) else {}))
            add("")
        for s in extra_summaries:
            lines.extend(_summary_block(s, "####"))

    # 5. 인터페이스
    if recon:
        d = recon.get("data", {})
        add("## 5. 콘솔/부트로더 정보")
        add("")
        ub = d.get("uboot") or {}
        lx = d.get("linux") or {}
        if ub:
            add(f"- U-Boot 버전: {ub.get('version')}")
            add(f"- 프롬프트: `{ub.get('prompt')}`")
            if ub.get("bootargs"):
                add(f"- bootargs: `{ub.get('bootargs')}`")
            if ub.get("mtdparts"):
                add(f"- mtdparts: `{ub.get('mtdparts')}`")
            if ub.get("flash"):
                add(f"- 플래시: {ub.get('flash')}")
        if lx:
            add(f"- 커널: {lx.get('kernel_version')}")
            if lx.get("cmdline"):
                add(f"- cmdline: `{lx.get('cmdline')}`")
            if lx.get("mtd"):
                add("")
                add("| mtd | size | erasesize | name |")
                add("|---|---|---|---|")
                for m in lx["mtd"]:
                    add(f"| {m.get('dev')} | {m.get('size')} | {m.get('erasesize')} | {m.get('name')} |")
        add("")

    # 6. 정적 분석
    sa = case.latest_summary("firmware-static-analysis")
    if sa:
        d = sa.get("data", {})
        add("## 6. 펌웨어 정적 분석 개요")
        add("")
        fw = d.get("firmware", {})
        ex = d.get("extraction", {})
        add(f"- 대상 펌웨어: `{fw.get('path')}` (sha256 `{fw.get('sha256')}`)")
        add(f"- 추출: 도구 `{ex.get('tool')}`, 상태 `{ex.get('status')}`, 출력 `{ex.get('output_dir')}`")
        rootfs = d.get("rootfs") or {}
        if rootfs:
            add(f"- rootfs: `{rootfs.get('path')}` ({rootfs.get('fs_type')}, {rootfs.get('arch')})")
            if rootfs.get("web_servers"):
                add(f"- 웹 서버/서비스: {', '.join(map(str, rootfs.get('web_servers')))}")
        boi = d.get("binaries_of_interest") or []
        if boi:
            add("")
            add("| 관심 바이너리 | 이유 |")
            add("|---|---|")
            for b in boi[:30]:
                add(f"| `{_md_escape(b.get('path'))}` | {_md_escape(b.get('reason'))} |")
        add("")

    # 7. 발견사항
    add("## 7. 발견사항")
    add("")
    if findings:
        add("| ID | 심각도 | 신뢰도 | 상태 | 분류 | 제목 | 위치 |")
        add("|---|---|---|---|---|---|---|")
        for f in findings:
            loc = f.get("location") or {}
            where = loc.get("file") or loc.get("firmware") or loc.get("interface") or ""
            if loc.get("function"):
                where += f" :: {loc.get('function')}"
            add(f"| {f['id']} | {_SEV_LABEL.get(f.get('severity'), f.get('severity'))} | {_CONF_LABEL.get(f.get('confidence'), f.get('confidence'))} | "
                f"{_STATUS_LABEL.get(f.get('status'), f.get('status'))} | {f.get('category')} | {_md_escape(f.get('title'))} | {_md_escape(where)} |")
        add("")
        for f in findings:
            add(f"### {f['id']}. {f['title']}")
            add("")
            add(f"- 심각도/신뢰도/상태: {_SEV_LABEL.get(f.get('severity'))} / {_CONF_LABEL.get(f.get('confidence'))} / {_STATUS_LABEL.get(f.get('status'), f.get('status'))}")
            add(f"- 분류: {f.get('category')}")
            loc = {k: v for k, v in (f.get("location") or {}).items() if v not in (None, "")}
            if loc:
                add("- 위치: " + ", ".join(f"{k}=`{v}`" for k, v in loc.items()))
            add("")
            add(f.get("summary", ""))
            add("")
            add("**근거와 추론**")
            add("")
            add(f.get("reasoning", ""))
            add("")
            ev = f.get("evidence") or []
            if ev:
                add("**증거**")
                add("")
                for e in ev:
                    add(f"- ({e.get('type')}) `{e.get('ref')}`" + (f" sha256 `{e.get('sha256')}`" if e.get("sha256") else ""))
                    if e.get("excerpt"):
                        add("")
                        add(_code(str(e["excerpt"])[:4000]))
                add("")
            if f.get("references"):
                add("**참고**: " + ", ".join(f.get("references")))
                add("")
            if f.get("verification_plan"):
                add("**검증 계획 (소유 기기·격리 랩)**")
                add("")
                add(f["verification_plan"])
                add("")
            if f.get("remediation"):
                add("**권고**")
                add("")
                add(f["remediation"])
                add("")
    else:
        add("기록된 발견사항이 없다.")
        add("")

    # 8. 아티팩트
    add("## 8. 아티팩트")
    add("")
    arts = meta.get("artifacts", [])
    if arts:
        add("| ID | 경로 | 종류 | 크기 | sha256 |")
        add("|---|---|---|---|---|")
        for a in arts:
            add(f"| {a.get('id')} | `{_md_escape(a.get('path'))}` | {a.get('kind')} | {a.get('size', '')} | `{(a.get('sha256') or '')[:16]}` |")
    else:
        add("등록된 아티팩트가 없다.")
    add("")

    # 8.1 SD 카드 증거 (forensics/ 가 있을 때만)
    lines.extend(_evidence_section(case, anchor_dir))

    # 9. 안전/감사
    stats = _audit_stats(case)
    add("## 9. 안전 게이트 및 감사 요약")
    add("")
    if stats["counts"]:
        add("안전 결정: " + ", ".join(f"{k} {v}건" for k, v in sorted(stats["counts"].items())))
    else:
        add("기록된 안전 결정이 없다.")
    add("")
    if stats["risky"]:
        add("| 시각 | 서버 | 도구 | 위험도 | 결정 | 규칙 | 명령 |")
        add("|---|---|---|---|---|---|---|")
        for r in stats["risky"]:
            add(f"| {r['ts']} | {r['server']} | {r['tool']} | {r['risk']} | {r['status']} | {r['rule']} | `{_md_escape(r['matched'])}` |")
        add("")

    # 10. 한계
    add("## 10. 한계 및 미확인 사항")
    add("")
    gaps: list[str] = []
    for s in summaries:
        gaps.extend(s.get("blockers") or [])
        data = s.get("data") or {}
        gaps.extend(data.get("coverage_gaps") or [])
        ex = data.get("extraction") or {}
        for g in ex.get("gaps") or []:
            gaps.append(_gap_text(g))
    gaps = list(dict.fromkeys(gaps))  # 순서를 유지하며 중복 제거
    unverified = [f["id"] for f in findings if f.get("status") == "unverified"]
    if unverified:
        gaps.append(f"미검증 발견사항: {', '.join(unverified)} — 정적 분석 정황이며 실제 동작 확인이 필요하다.")
    if gaps:
        for g in gaps:
            add(f"- {g}")
    else:
        add("- 기록된 한계 없음 (단, 정적 분석은 런타임 동작을 보장하지 않는다).")
    add("")
    return "\n".join(lines)


def write_report(case: Case, anchor_dir: Path | None = None) -> dict[str, Any]:
    case.set_phase("report", "done")  # 보고서 안의 단계 표에 반영되도록 렌더링 전에 갱신
    text = render_report(case, anchor_dir)
    path = case.dir / "report.md"
    atomic_write_text(path, text)
    art = case.register_artifact(path, kind="report", producer="case-mcp", description="최종 보고서")
    findings = case.findings()
    return {
        "path": str(path),
        "relative_path": case.rel(path),
        "sha256": art.get("sha256"),
        "findings": len(findings),
        "by_severity": dict(Counter(f.get("severity") for f in findings)),
    }
