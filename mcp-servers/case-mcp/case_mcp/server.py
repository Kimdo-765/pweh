"""case-mcp: PWEH 오케스트레이션 레이어의 MCP 서버.

케이스(분석 작업) 생성, 소유/허가 증명 기록, Skill 단계 결과 저장/조회, 아티팩트 등록,
발견사항 관리, 보고서 생성, 대상 프로필/안전 정책/승인 상태 조회를 제공한다.
Skill 사이의 데이터 전달은 이 서버가 관리하는 케이스 디렉터리의 파일로 이루어진다.

이 서버는 다른 PWEH 서버 구현의 기준(reference) 구현이기도 하다.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import threading
from pathlib import Path
from typing import Any

from mcp.types import CallToolResult, ImageContent, TextContent

from pweh import hostenv, safeio, schemas
from pweh.case import PIPELINE_PHASES, PHASE_STATUSES
from pweh.errors import NotFound, ValidationFailed
from pweh.fsutil import is_within
from pweh.mcpkit import ANN_LOCAL_WRITE, ANN_READ_ONLY, create_server, run_blocking, run_blocking_cancellable, safe_tool
from pweh.report import write_report
from pweh.runtime import Runtime, get_runtime

SERVER_NAME = "case-mcp"

server = create_server(
    SERVER_NAME,
    title="PWEH Case & Report",
    instructions=(
        "PWEH 케이스 작업공간 관리 서버. 분석을 시작할 때 case_create 로 케이스를 만들고(소유/허가 증명 필수), "
        "각 Skill 이 끝날 때 case_record_step(step='summary') 으로 구조화된 결과를 저장한다. 다음 Skill 은 "
        "case_get_step_results 로 이전 결과를 읽는다. 발견사항은 case_add_finding, 최종 보고서는 report_generate. "
        "case_paths 는 REA 같은 외부 도구에 넘길 절대 경로(새 출력 디렉터리 포함)를 알려준다."
    ),
)


_FORENSICS_HINT = "카드 이미지·복구 파일은 pweh-forensics 도구로만 다룬다(정지이미지는 forensics_image_hints, 해시는 forensics_evidence_list·forensics_extract)."


def _refuse_case_protected(path: str | Path, what: str) -> None:
    """어느 케이스든 보호 폴더(pweh.evidence.PROTECTED_DIRS) 아래면 거부한다 — 자동 허용 도구가 읽지 않게, 링크를 풀어 판단:
    증거 폴더(forensics/ — 카드 이미지·복구한 녹화)와 에뮬레이터 세션 폴더(emu/ — 마스킹하지 않은 원시 콘솔, 콘솔은 emu_read 로만)."""
    from pweh.evidence import EMU_REFUSAL_HINT, EMU_REFUSAL_MESSAGE, under_any_case_protected

    hit = under_any_case_protected(path, rt().config.cases_dir)
    if hit == "emu":
        raise ValidationFailed(EMU_REFUSAL_MESSAGE, hint=EMU_REFUSAL_HINT)
    if hit is not None:
        raise ValidationFailed(f"케이스의 증거 폴더(forensics/)에 있는 파일은 {what}.", hint=_FORENSICS_HINT)


def _open_case_regular(case, p: Path, refuse_what: str, verb: str) -> tuple[int, os.stat_result]:
    """케이스 안의 일반 파일만 연다(FIFO·장치에서 멈추지 않음) → (fd, stat). 호출자가 fd 를 닫는다.

    보호 폴더(forensics/·emu/) 여부는 실제로 연 객체의 경로로 다시 본다(확인한 뒤 바꿔치기한 링크 대비)."""
    try:
        fd, st = safeio.open_regular(p, what="파일", reject_hardlinks=True)
    except FileNotFoundError:
        raise NotFound(f"파일이 없습니다: {case.rel(p)}") from None
    except safeio.UnsafeFile as exc:
        raise ValidationFailed(f"일반 파일만 {verb}: {case.rel(p)} ({exc.message})") from exc
    try:
        real = safeio.fd_real_path(fd)
        if real is not None:
            _refuse_case_protected(real, refuse_what)
    except BaseException:
        os.close(fd)
        raise
    return fd, st


def _sha256_fd(fd: int) -> str:
    import hashlib

    h = hashlib.sha256()
    pos = 0
    while True:
        block = os.pread(fd, 1 << 20, pos)
        if not block:
            return h.hexdigest()
        h.update(block)
        pos += len(block)


def rt() -> Runtime:
    return get_runtime(SERVER_NAME)


@server.tool(
    description=(
        "케이스의 정지이미지 파일 1개를 오프라인 분석한다(소유/허가 확인 필수, 최대 64 MiB). "
        "메타데이터·구조·OCR(kor+eng 기본)·QR/바코드·스테가노그래피 단서를 JSON 으로, "
        "정규화 PNG 를 MCP 이미지 콘텐츠로 반환한다. OCR·코드는 마스킹하지 않으며 URL 을 열지 않는다. "
        "crop=[x,y,width,height] 는 EXIF 방향을 적용한 좌표; 원본 전체 메타데이터·구조와 별도로 확대 미리보기를 만든다. "
        "preview=false 면 이미지 콘텐츠 없음. 동영상·오디오·다중 프레임은 해독하지 않는다. "
        "선택·읽기·분석 전체 max_seconds 기본/최대 45초. JSON·PNG 는 analysis/ 에 0444 로 저장·해시 등록한다. "
        "forensics/·emu/ 는 받지 않는다(증거의 정지이미지는 forensics_image_hints)."
    ),
    annotations=ANN_LOCAL_WRITE,
)
@safe_tool
async def case_image_hints(case_id: str, path: str, ocr: bool = True, ocr_lang: str = "kor+eng", qr: bool = True,
                           preview: bool = True, crop: list[int] | None = None, max_seconds: float = 45.0) -> CallToolResult:
    from pweh import evidence as E
    from pweh.imagehints import MAX_INPUT_BYTES, analyze_image, resolve_image_tools

    deadline = E.image_hints_deadline(max_seconds)
    cancelled = threading.Event()

    def work() -> CallToolResult:
        case = rt().case(case_id, hardware=True)
        raw = Path(path) if Path(path).is_absolute() else case.dir / path
        _refuse_case_protected(raw, "분석할 수 없습니다")
        p = case.resolve_path(path)
        _refuse_case_protected(p, "분석할 수 없습니다")
        rel = p.relative_to(case.dir.resolve())
        dfd = safeio.open_dir_chain(case.dir, rel.parts[:-1])
        try:
            fd, _ = safeio.open_regular(rel.name, dir_fd=dfd, what="정지이미지", reject_hardlinks=True)
        finally:
            os.close(dfd)
        try:
            real = safeio.fd_real_path(fd)
            if real is not None:
                if not is_within(case.dir, real):
                    raise ValidationFailed("실제로 연 이미지가 케이스 밖에 있습니다.")
                _refuse_case_protected(real, "분석할 수 없습니다")
            data = E.read_image_bytes(fd, max_bytes=MAX_INPUT_BYTES, deadline=deadline, cancel=cancelled.is_set)
        finally:
            os.close(fd)
        options = {"ocr": ocr, "ocr_lang": ocr_lang, "qr": qr, "preview": preview, "crop": crop, "max_seconds": max_seconds}
        result = analyze_image(data, settings=resolve_image_tools(rt().config), **{**options, "max_seconds": E.image_hints_checkpoint(deadline, cancelled.is_set)},
                               cancel_event=cancelled)
        report = {**result["report"], "source": {"kind": "case-file", "path": rel.as_posix(), "size": len(data),
                                                "sha256": hashlib.sha256(data).hexdigest()}, "params": options}

        def check() -> None:
            if cancelled.is_set():
                raise E.EvidenceError("이미지 분석이 취소되었습니다.", code="cancelled")

        out = E.store_image_hints(case, report, result["previews"], check=check)
        return CallToolResult(content=[TextContent(type="text", text=json.dumps(out, ensure_ascii=False)), *[
            ImageContent(type="image", data=base64.b64encode(p["data"]).decode("ascii"), mime_type=p["mime_type"])
            for p in result["previews"]]], structured_content=out)

    return await run_blocking_cancellable(work, on_cancel=cancelled.set)


# ---------------------------------------------------------------------------
# 케이스
# ---------------------------------------------------------------------------


@server.tool(
    description=(
        "새 분석 케이스 생성. authorization 은 필수: {basis: 'owned'|'written-authorization', owner, statement(사용자가 "
        "소유/허가를 확인한 말을 그대로 인용), scope?, document_ref?(서면 허가 시 필수)}. target 예: {vendor, model, serial, "
        "hardware_rev, firmware_version, soc}. profile 은 pipeline_profiles 의 이름 (모르면 생략 → generic-ipcam). "
        "사용한 case_id 는 보호 상태에 예약해 재사용하지 않는다. 기존 경로나 보호 기록이 남은 ID는 거부하고, "
        "case_id 생략 시 충돌하지 않는 ID를 고른다. 케이스 폴더를 지워도 예약은 유지된다."
    ),
    annotations=ANN_LOCAL_WRITE,
)
@safe_tool
def case_create(
    title: str,
    authorization: dict[str, Any],
    target: dict[str, Any] | None = None,
    profile: str | None = None,
    case_id: str | None = None,
    notes: str | None = None,
) -> dict[str, Any]:
    r = rt()
    if profile:
        r.config.profile(profile)  # 존재 확인
    case = r.cases.create(title=title, target=target, authorization=authorization, profile=profile, case_id=case_id, notes=notes)
    r.audit({"event": "case_created", "title": title}, case.id)
    return {"ok": True, "case": case.summary(), "paths": _paths(case)}


@server.tool(
    description="케이스의 소유/허가 증명을 기록하거나 갱신한다 (case_create 와 같은 authorization 형식).",
    annotations=ANN_LOCAL_WRITE,
)
@safe_tool
def case_set_authorization(case_id: str, authorization: dict[str, Any]) -> dict[str, Any]:
    case = rt().cases.get(case_id)
    auth = case.set_authorization(authorization)
    return {"ok": True, "authorization": auth}


@server.tool(description="케이스 목록.", annotations=ANN_READ_ONLY)
@safe_tool
def case_list() -> dict[str, Any]:
    return {"ok": True, "cases": rt().cases.list()}


@server.tool(
    description="케이스 요약(대상, 권한 여부, 단계 상태, 아티팩트/단계/발견사항 수). include_artifacts=true 면 아티팩트 목록 포함.",
    annotations=ANN_READ_ONLY,
)
@safe_tool
def case_get(case_id: str, include_artifacts: bool = False, include_steps: bool = False) -> dict[str, Any]:
    case = rt().cases.get(case_id)
    out: dict[str, Any] = {"ok": True, "case": case.summary(), "paths": _paths(case)}
    meta = case.load()
    out["authorization"] = meta.get("authorization")
    if include_artifacts:
        out["artifacts"] = meta.get("artifacts", [])
    if include_steps:
        out["steps"] = meta.get("steps", [])
    return out


@server.tool(description="케이스의 대상 기기 정보 갱신 (예: UART 로 알아낸 SoC/플래시/펌웨어 버전).", annotations=ANN_LOCAL_WRITE)
@safe_tool
def case_update_target(case_id: str, target: dict[str, Any]) -> dict[str, Any]:
    case = rt().cases.get(case_id)
    return {"ok": True, "target": case.update_target(target)}


@server.tool(
    description=(f"파이프라인 단계 상태 수동 갱신. phase: {', '.join(PIPELINE_PHASES)}; status: {', '.join(PHASE_STATUSES)}. "
                 "다른 목표의 Skill 도 자기 이름을 phase 로 쓴다(예: game-save-unlock-analysis — 처음 기록할 때 생긴다. 이름은 검사하지 않는다)."),
    annotations=ANN_LOCAL_WRITE,
)
@safe_tool
def case_set_phase(case_id: str, phase: str, status: str, note: str | None = None) -> dict[str, Any]:
    case = rt().cases.get(case_id)
    return {"ok": True, "phase": phase, "entry": case.set_phase(phase, status, note)}


@server.tool(description="케이스에 자유 형식 메모 추가 (사람이 한 물리 작업, 관찰 등).", annotations=ANN_LOCAL_WRITE)
@safe_tool
def case_add_note(case_id: str, text: str, author: str = "agent") -> dict[str, Any]:
    case = rt().cases.get(case_id)
    return {"ok": True, "note": case.add_note(text, author)}


@server.tool(
    description=(
        "케이스 디렉터리의 표준 하위 경로(절대 경로)와, 외부 도구(REA extract_firmware 등)에 넘길 '아직 존재하지 않는' 새 출력 "
        "디렉터리 경로를 반환. purpose 예: 'extract', 'analysis', 'signals'."
    ),
    annotations=ANN_READ_ONLY,
)
@safe_tool
def case_paths(case_id: str, purpose: str = "extract", label: str = "run") -> dict[str, Any]:
    case = rt().cases.get(case_id)
    out = _paths(case)
    base = case.subdir(purpose if purpose in ("extract", "analysis", "signals", "dumps", "jtag", "uart", "notes") else "analysis")
    n = 1
    safe_label = "".join(c if c.isalnum() or c in "-_" else "-" for c in label)[:32] or "run"
    while (base / f"{safe_label}-{n:03d}").exists():
        n += 1
    out["new_output_dir"] = str(base / f"{safe_label}-{n:03d}")
    return {"ok": True, **out}


def _paths(case) -> dict[str, Any]:
    return {
        "case_dir": str(case.dir),
        **{f"{d}_dir": str(case.dir / d) for d in ("uart", "dumps", "extract", "analysis", "signals", "jtag", "steps", "patches")},
        "findings": str(case.findings_path),
        "report": str(case.dir / "report.md"),
    }


# ---------------------------------------------------------------------------
# 단계 결과 / 아티팩트
# ---------------------------------------------------------------------------


@server.tool(
    description=(
        "Skill 단계 결과 저장. 각 Skill 의 마지막에 step='summary' 로 호출해야 하며, 이때 data 는 해당 Skill 의 출력 스키마를 "
        "따라야 한다 (uart-shell-acquisition→uart-recon, firmware-dump-via-uart→firmware-dump, firmware-static-analysis→"
        "static-analysis, logic-analyzer-protocol-decode→signal-capture, cctv-auth-bypass-hunt→auth-hunt, "
        "game-save-unlock-analysis→save-analysis, sd-card-forensics→sd-forensics, firmware-emulation→emulation, image-hints-analysis→image-hints; schema_get 으로 확인). "
        "status: success|partial|failed|blocked|skipped|in-progress. artifacts 는 케이스 상대 경로 목록."
    ),
    annotations=ANN_LOCAL_WRITE,
)
@safe_tool
def case_record_step(
    case_id: str,
    skill: str,
    step: str,
    status: str,
    summary: str,
    data: dict[str, Any] | None = None,
    artifacts: list[str] | None = None,
    next_actions: list[str] | None = None,
    blockers: list[str] | None = None,
    started_at: str | None = None,
) -> dict[str, Any]:
    case = rt().cases.get(case_id)
    res = case.record_step(
        skill=skill, step=step, status=status, summary=summary, data=data, artifacts=artifacts,
        next_actions=next_actions, blockers=blockers, started_at=started_at,
    )
    return {"ok": True, "seq": res["seq"], "file": res["file"], "status": res["status"]}


@server.tool(
    description=(
        "이전 Skill 들의 단계 결과 조회 (다음 Skill 의 입력으로 사용). skill 을 지정하지 않으면 모든 Skill 의 최신 summary. "
        "missing 은 summary 가 없는 Skill 이다 — 보안 분석 파이프라인 Skill 과, 다른 목표의 Skill 은 이 케이스에서 시작한 것만 센다. "
        "summaries_only=false 면 해당 skill 의 모든 단계."
    ),
    annotations=ANN_READ_ONLY,
)
@safe_tool
def case_get_step_results(case_id: str, skill: str | None = None, summaries_only: bool = True) -> dict[str, Any]:
    case = rt().cases.get(case_id)
    if skill and not summaries_only:
        return {"ok": True, "results": case.steps(skill, load=True)}
    if skill:
        skills = [skill]
    else:
        # 선택 단계(다른 목표의 Skill)는 이 케이스에서 시작했을 때(phases 에 있을 때)만 — CCTV 케이스의 missing 에 게임 Skill 이 끼지 않게
        started = case.load().get("phases") or {}
        skills = [s for s in schemas.SKILL_DATA_SCHEMAS if s in PIPELINE_PHASES or s in started]
    out = {}
    for s in skills:
        summ = case.latest_summary(s)
        if summ is not None:
            out[s] = summ
    return {"ok": True, "summaries": out, "missing": [s for s in skills if s not in out]}


@server.tool(
    description=(
        "케이스 내부 파일/디렉터리를 아티팩트로 등록(sha256 계산). kind 예: uart-log, flash-dump, memory-dump, partition, "
        "extracted-tree, signal-capture, signal-decode, jtag-dump, triage-report, rea-evidence, decompilation, report, other."
    ),
    annotations=ANN_LOCAL_WRITE,
)
@safe_tool
def case_register_artifact(case_id: str, path: str, kind: str, description: str | None = None, producer: str = "agent") -> dict[str, Any]:
    case = rt().cases.get(case_id)
    p = case.resolve_path(path)
    _refuse_case_protected(p, "아티팩트로 등록하지 않습니다")
    sha256 = None
    if not p.is_dir():  # 디렉터리(추출 트리 등)는 해시하지 않는다
        # 일반 파일만 연다(FIFO·장치에서 멈추지 않음). 해시는 연 fd 에서 계산해 넘긴다(경로로 다시 읽지 않음)
        fd, _st = _open_case_regular(case, p, "아티팩트로 등록하지 않습니다", "등록합니다")
        try:
            sha256 = _sha256_fd(fd)
        finally:
            os.close(fd)
    return {"ok": True, "artifact": case.register_artifact(path, kind=kind, producer=producer, description=description, sha256=sha256)}


@server.tool(
    description=(
        "케이스 밖의 파일(예: 벤더 공식 펌웨어 다운로드, SPI 클립으로 읽은 덤프)을 케이스로 복사하고 등록. "
        "dest_subdir 기본 'dumps'."
    ),
    annotations=ANN_LOCAL_WRITE,
)
@safe_tool
def case_import_file(case_id: str, source_path: str, kind: str = "firmware-image", dest_subdir: str = "dumps", description: str | None = None) -> dict[str, Any]:
    case = rt().cases.get(case_id)
    if dest_subdir not in ("dumps", "extract", "analysis", "signals", "jtag", "notes", "uart"):
        raise ValidationFailed(f"허용되지 않은 dest_subdir: {dest_subdir}")
    # 보호 상태(승인·증명·출처 원장·솔트·감사 로그)와 케이스의 보호 폴더(forensics/·emu/)를 케이스로 복사해 읽어 내지 못하게 한다.
    # 링크를 푼 경로(src)와 풀기 전 경로(raw)를 모두 본다 — 보호 폴더 자체가 다른 곳을 가리키는 링크여도 그 아래 경로로 부르면 막는다.
    # 실제로 연 fd 의 경로도 다시 검사한 뒤 그 fd 를 복사한다. 확인 뒤 이름이 바뀌어도 다른 원본을 다시 열지 않는다.
    raw = Path(os.path.abspath(Path(source_path).expanduser()))
    src = raw.resolve()
    if is_within(rt().config.state_dir, src):
        raise ValidationFailed(
            "보호 상태 디렉터리(state_dir — 승인·증명·출처 원장·솔트·감사 로그)의 파일은 가져올 수 없습니다.",
            hint="케이스 밖의 원본 파일(벤더 펌웨어, 클립으로 읽은 덤프, 사람이 만든 이미지)만 가져온다.",
        )
    # 케이스의 증거 폴더(forensics/ — 카드 이미지·복구한 녹화)는 pweh-forensics 로만, 에뮬레이터 세션 폴더(emu/ — 마스킹하지 않은
    # 원시 콘솔)는 emu_read 로만 다룬다. 자동 허용 도구(pweh-fwtriage 등)가 읽는 dumps/ 로 복사하는 우회를 막는다(docs/safety.md).
    from pweh.evidence import EMU_REFUSAL_HINT, EMU_REFUSAL_MESSAGE, under_any_case_protected

    hit = under_any_case_protected(raw, rt().config.cases_dir) or under_any_case_protected(src, rt().config.cases_dir)
    if hit == "emu":
        raise ValidationFailed(EMU_REFUSAL_MESSAGE, hint=EMU_REFUSAL_HINT)
    if hit is not None:
        raise ValidationFailed(
            "케이스의 증거 폴더(forensics/)에 있는 파일은 가져올 수 없습니다.",
            hint="카드 이미지·복구 파일은 pweh-forensics 도구(forensics_*)로만 다룬다. 원본 이미지를 새로 접수하려면 forensics_intake_start 를 쓴다.",
        )
    try:
        fd, _ = safeio.open_regular(src, what="가져올 파일", reject_hardlinks=True)
    except FileNotFoundError:
        raise NotFound(f"가져올 파일이 없습니다: {src}") from None
    except safeio.UnsafeFile as exc:
        raise ValidationFailed(exc.message) from exc
    try:
        real = safeio.fd_real_path(fd)
        if real is None:
            raise ValidationFailed("실제로 연 원본 파일의 경로를 확인할 수 없어 가져오지 않습니다.")
        if is_within(rt().config.state_dir, real):
            raise ValidationFailed("보호 상태 디렉터리(state_dir)의 파일은 가져올 수 없습니다.")
        _refuse_case_protected(real, "가져올 수 없습니다")
        art = case.import_file(src, dest_subdir, kind=kind, producer="case-mcp", description=description, source_fd=fd)
    finally:
        os.close(fd)
    return {"ok": True, "artifact": art, "absolute_path": str(case.dir / art["path"]), "provenance": _record_import(case, art, kind)}


def _record_import(case, art: dict[str, Any], kind: str) -> dict[str, Any]:
    """가져온 파일을 출처 원장에 imported-unattested 로 기록한다(기기 읽기로 기록하는 경로는 이 서버에 없다).

    기록 실패는 가져오기를 막지 않는다 — 원장에 없는 파일은 출처 확인에서 신뢰되지 않으므로(fail closed) 결과만 알린다.
    """
    import logging

    source = {"server": SERVER_NAME, "tool": "case_import_file", "imported_from": (art.get("extra") or {}).get("imported_from"),
              "artifact_kind": kind}
    try:
        entry = rt().provenance.record_import(case, art["path"], source, sha256=art.get("sha256"))
    except Exception as exc:  # noqa: BLE001
        logging.getLogger("pweh.case").warning("출처 원장 기록 실패 (%s): %s", art.get("path"), exc)
        return {"recorded": False, "kind": "imported-unattested", "reason": f"{getattr(exc, 'code', type(exc).__name__)}: {exc}"[:300]}
    return {
        "recorded": True,
        "kind": entry["kind"],
        "seq": entry["seq"],
        "sha256": entry["sha256"],
        "note": ("가져온 파일은 기기에서 읽은 것으로 취급하지 않는다(imported-unattested). 출처가 중요한 작업(에뮬레이션·올리기·패치 base 등)에는 "
                 "사람의 provenance-import 증명(`pweh attest`)이 필요하다."),
    }


@server.tool(
    description=(
        "케이스 내부 파일(또는 offset/length 구간)의 해시 계산: sha256, md5, crc32. 덤프 교차 검증용 — 예: tftpput/SPI 클립으로 받은 "
        "파일과 UART 덤프의 같은 구간 비교, 기기 측 md5sum/crc32 와 대조. offset/length 는 정수 또는 '0x50000', '64k' 같은 문자열."
    ),
    annotations=ANN_READ_ONLY,
)
@safe_tool
def case_hash_file(case_id: str, path: str, offset: int | str = 0, length: int | str | None = None) -> dict[str, Any]:
    import hashlib
    import zlib

    from pweh.fsutil import parse_size

    case = rt().cases.get(case_id)
    p = case.resolve_path(path)
    _refuse_case_protected(p, "해시하지 않습니다")
    fd, st = _open_case_regular(case, p, "해시하지 않습니다", "해시합니다")
    try:
        size = st.st_size
        off = parse_size(offset)
        if off < 0 or off > size:
            raise ValidationFailed(f"offset 이 파일 범위를 벗어났습니다: {off} (파일 크기 {size})")
        remaining = size - off if length is None else parse_size(length)
        if remaining < 0 or off + remaining > size:
            raise ValidationFailed(f"구간이 파일 끝을 넘습니다: offset={off}, length={remaining}, 파일 크기={size}")
        sha, md5, crc = hashlib.sha256(), hashlib.md5(), 0
        pos, left = off, remaining
        while left > 0:
            block = os.pread(fd, min(1 << 20, left), pos)
            if not block:
                break
            sha.update(block)
            md5.update(block)
            crc = zlib.crc32(block, crc)
            pos += len(block)
            left -= len(block)
    finally:
        os.close(fd)
    return {
        "ok": True,
        "path": case.rel(p),
        "file_size": size,
        "offset": off,
        "length": remaining,
        "sha256": sha.hexdigest(),
        "md5": md5.hexdigest(),
        "crc32": f"{crc & 0xFFFFFFFF:08x}",
    }


# ---------------------------------------------------------------------------
# 발견사항 / 보고서
# ---------------------------------------------------------------------------


@server.tool(
    description=(
        "발견사항 추가 (schema_get('finding') 참고). 필수: title, category(auth-bypass|hardcoded-credential|backdoor|"
        "command-injection|debug-interface|weak-crypto|info-leak|insecure-update|memory-corruption|insecure-default|other), "
        "severity(critical|high|medium|low|info), confidence(confirmed|likely|possible), summary, location{file,function,address,...}, "
        "evidence[{type, ref, excerpt?}](1개 이상), reasoning. 선택: references(CVE/URL), verification_plan(소유 기기·격리 랩 기준, "
        "공격 페이로드 금지), remediation, status(unverified 기본). id 는 자동 부여."
    ),
    annotations=ANN_LOCAL_WRITE,
)
@safe_tool
def case_add_finding(case_id: str, finding: dict[str, Any]) -> dict[str, Any]:
    case = rt().cases.get(case_id)
    f = case.add_finding(finding)
    return {"ok": True, "finding_id": f["id"], "duplicate": bool(f.get("duplicate")), "finding": f}


@server.tool(description="발견사항 수정 (예: status 를 static-confirmed 로, 증거 추가). patch 는 덮어쓸 필드.", annotations=ANN_LOCAL_WRITE)
@safe_tool
def case_update_finding(case_id: str, finding_id: str, patch: dict[str, Any]) -> dict[str, Any]:
    case = rt().cases.get(case_id)
    return {"ok": True, "finding": case.update_finding(finding_id, patch)}


@server.tool(description="발견사항 목록 (심각도순). min_severity 로 필터 (critical|high|medium|low|info).", annotations=ANN_READ_ONLY)
@safe_tool
def case_list_findings(case_id: str, min_severity: str | None = None) -> dict[str, Any]:
    case = rt().cases.get(case_id)
    items = case.findings(min_severity)
    return {"ok": True, "count": len(items), "findings": items}


@server.tool(
    description="케이스의 모든 결과(단계 요약, 발견사항, 아티팩트, 안전 감사)를 모아 cases/<id>/report.md 를 생성한다.",
    annotations=ANN_LOCAL_WRITE,
)
@safe_tool
def report_generate(case_id: str) -> dict[str, Any]:
    r = rt()
    case = r.cases.get(case_id)
    res = write_report(case, Path(r.config.state_dir) / "custody")  # SD 카드 보관 기록은 보호 위치의 고정점과 대조한다
    r.audit({"event": "report_generated", **res}, case_id)
    return {"ok": True, **res}


# ---------------------------------------------------------------------------
# 설정 / 안전 / 스키마
# ---------------------------------------------------------------------------


@server.tool(description="pipeline-config.yaml 에 정의된 대상 기기 프로필 목록.", annotations=ANN_READ_ONLY)
@safe_tool
def pipeline_profiles() -> dict[str, Any]:
    cfg = rt().config
    return {"ok": True, "config_file": str(cfg.path) if cfg.path else None, "profiles": cfg.list_profiles()}


@server.tool(
    description="대상 기기 프로필 상세 (extends 해석 완료): 보드레이트 후보, U-Boot 프롬프트/autoboot 패턴, 인터럽트 키, 예상 인터페이스, 플래시/RAM 주소 힌트, 펌웨어 분석 힌트.",
    annotations=ANN_READ_ONLY,
)
@safe_tool
def pipeline_profile(name: str) -> dict[str, Any]:
    cfg = rt().config
    prof = cfg.profile(name)
    return {"ok": True, "profile": prof, "baud_candidates": cfg.baud_candidates(name)}


@server.tool(description="현재 적용 중인 안전 정책 (위험도별 allow/approve/deny, 승인 방법, 영구 경로 목록).", annotations=ANN_READ_ONLY)
@safe_tool
def pipeline_safety_policy() -> dict[str, Any]:
    cfg = rt().config
    return {
        "ok": True,
        "policy": cfg.safety.to_dict(),
        "effective": {
            "observe": "allow",
            "interact": "allow",
            "modify": cfg.safety.modify_policy,
            "destructive": cfg.safety.destructive_policy,
        },
        "config_file": str(cfg.path) if cfg.path else None,
    }


@server.tool(
    description=(
        "실행 환경 보고서와 장치 종류별 추천 경로 (기기 미접촉, OBSERVE, 읽기 전용). report(pweh.hostenv/v1): kind(WSL2_INTEROP | "
        "WSL2_NO_INTEROP | WSL1 | WSL_UNKNOWN | NATIVE_LINUX | MACOS | NATIVE_WINDOWS | CYGWIN | MSYS | CONTAINER), wsl{version, "
        "networking_mode, interop{usable, entry, smoke, reason}}, windows{build, uac_enabled, interop_elevated, smart_app_control, "
        "usbipd{present, version, autobind_policies}, tools.esptool_win}, linux{systemd, udevd, groups, brltty}, warnings, overridden. "
        "routes[]: {device(serial|esptool|openocd|sigrok|sdr|video|block), now{route, status, available, human_steps}(지금 되는 경로), "
        "target{route, phase}(다음 단계에서 생기는 경로), alternatives, notes}. 모르는 값은 null. 휘발 목록(COM 포트·usbipd attach 상태)은 "
        "넣지 않는다 — 포트는 각 서버의 *_list_ports. 첫 감지는 WSL 에서 powershell.exe smoke 로 몇 초 걸리고 이후 캐시(smoke 300 초). "
        "refresh=true 면 캐시를 버리고 다시 감지한다. Phase 0 장비 체크리스트에 쓴다(사람 단계의 [관리자]·[root] 표시)."
    ),
    annotations=ANN_READ_ONLY,
)
@safe_tool
async def pipeline_environment(refresh: bool = False) -> dict[str, Any]:
    cfg = rt().config
    report = await run_blocking(hostenv.detect, refresh=bool(refresh), config=cfg)
    return {"ok": True, "report": report, "routes": hostenv.recommend_routes(report)}


@server.tool(
    description="승인 요청 상태 조회 (pending|approved|denied|consumed|expired). 사람이 `pweh approve <id>` 를 했는지 확인할 때 사용.",
    annotations=ANN_READ_ONLY,
)
@safe_tool
def approval_status(approval_id: str) -> dict[str, Any]:
    rec = rt().approvals.get(approval_id)
    rec = {k: v for k, v in rec.items() if k != "code"}  # 확인 코드는 에이전트에게 노출하지 않음
    return {"ok": True, "approval": rec}


@server.tool(description="대기 중인 승인 요청 목록 (확인 코드는 제외).", annotations=ANN_READ_ONLY)
@safe_tool
def approvals_pending() -> dict[str, Any]:
    recs = [{k: v for k, v in r.items() if k != "code"} for r in rt().approvals.list("pending")]
    return {"ok": True, "pending": recs}


@server.tool(
    description="PWEH JSON 스키마 조회. name: case, step-result, finding, uart-recon, firmware-dump, static-analysis, signal-capture, auth-hunt, save-analysis, sd-forensics, emulation, image-hints, android-forensics, pinout-scan.",
    annotations=ANN_READ_ONLY,
)
@safe_tool
def schema_get(name: str) -> dict[str, Any]:
    try:
        return {"ok": True, "name": name, "schema": schemas.load(name)}
    except ValidationFailed:
        raise NotFound(f"알 수 없는 스키마: {name}", hint=f"사용 가능: {', '.join(schemas.list_schemas())}")


def main() -> None:
    server.run()


if __name__ == "__main__":
    main()
