"""케이스(분석 작업) 작업공간.

케이스 하나 = 대상 기기 하나에 대한 분석 세션. Skill 사이의 데이터 전달은 모두 케이스 디렉터리의
파일로 이루어진다::

    cases/<case_id>/
      case.json          메타데이터: 대상, 소유/허가 증명, 단계 상태(파이프라인 단계 + 기록된 선택 단계), 아티팩트 색인, 단계 결과 색인
      audit.jsonl        이 케이스의 모든 기기 조작/안전 결정 로그
      steps/NNNN-<skill>-<step>.json   단계 결과 (schemas/step-result.schema.json)
      uart/              UART 세션 로그 (*.log 텍스트, *.raw 원시 바이트, *.events.jsonl)
      dumps/             플래시/메모리 덤프 (*.bin + *.json 메타데이터)
      extract/           펌웨어 추출 결과 (REA extract_firmware, unsquashfs 등)
      analysis/          분석 산출물 (triage JSON, 디컴파일 발췌 등)
      signals/           로직 애널라이저 캡처(.sr/.vcd) 및 디코딩 결과
      jtag/              OpenOCD 덤프/레지스터 스냅샷
      nfc/               가져온 NFC 파일과 마스킹 inventory 조회 사본(권위는 보호 원장)
      jobs/              백그라운드 작업 상태
      findings.json      발견사항 (schemas/finding.schema.json 항목들의 목록)
      report.md          최종 보고서 (report_generate)
"""

from __future__ import annotations

import json
import math
import os
import re
import stat
import time
from pathlib import Path
from typing import Any, Callable, Iterable

from .audit import AuditLog
from .errors import AuthorizationRequired, CaseError, NotFound, ValidationFailed
from .fsutil import (
    atomic_write_json,
    file_lock,
    is_within,
    read_json,
    safe_join,
    sha256_file,
    utcnow,
    utcnow_iso,
)
from . import safeio, schemas
from .caseids import CreationGuard

#: 케이스 id: 영문/숫자로 시작하고 영문/숫자/._- 만, 최대 80자. '.' 으로 끝날 수 없다 — Windows 경로 정규화가 요소 끝의 '.'·공백을
#: 지워 다른 케이스 디렉터리를 가리키게 되기 때문이다(pweh-esp 방법 A 가 esptool.exe 에 \\wsl.localhost\… 경로를 넘긴다).
CASE_ID_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9._-]{0,78}[A-Za-z0-9_-])?$")
STANDARD_DIRS = ("steps", "uart", "dumps", "extract", "analysis", "signals", "jtag", "jobs", "notes", "patches", "nfc")

#: 보안 분석(기본 목표, CCTV/IoT) 파이프라인의 단계. 새 케이스는 모두 'pending' 으로 시작한다(case.json 의 phases).
#: case-mcp 의 case_set_phase 도구 설명이 이 값을 그대로 쓰므로, 바꾸면 도구 카탈로그도 다시 만든다.
PIPELINE_PHASES = (
    "uart-shell-acquisition",
    "firmware-dump-via-uart",
    "logic-analyzer-protocol-decode",
    "firmware-static-analysis",
    "cctv-auth-bypass-hunt",
    "report",
)
#: 선택 단계 레지스트리: 보안 분석 밖의 목표(게임 콘솔·RF·SD 포렌식)와 계측기용 Skill 의 단계 이름(= Skill 이름).
#: PIPELINE_PHASES 와 달리 새 케이스에 'pending' 항목을 만들지 않는다. 그 Skill 이 summary 를 기록하거나
#: case_set_phase 로 상태를 정할 때 처음 생기므로, 그 목표를 쓰지 않는 케이스의 case.json·보고서는 달라지지 않는다.
#: 순서는 보고서의 표시 순서다. Skill 을 추가하면 이름을 여기에, 라벨을 report._PHASE_LABEL 에,
#: 요약 스키마를 schemas.SKILL_DATA_SCHEMAS 에 함께 등록한다.
OPTIONAL_PHASES = (
    "game-save-unlock-analysis",
    "numeric-observation-analysis",
    "nfc-behavior-analysis",
    "game-play-automation",
    "flipper-rf-analysis",
    "sd-card-forensics",
    "firmware-emulation",
    "image-hints-analysis",
    "android-forensics",
    "espprobe",
)
PHASE_STATUSES = ("pending", "in-progress", "done", "partial", "failed", "skipped", "blocked")
#: summary 단계의 status → 단계(phase) 상태. 표에 없는 값(in-progress)은 'in-progress'.
SUMMARY_PHASE_STATUS = {"success": "done", "partial": "partial", "failed": "failed", "blocked": "blocked", "skipped": "skipped"}
AUTH_BASES = ("owned", "written-authorization")
SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def tracks_phase(skill: str) -> bool:
    """이 Skill 의 summary 가 case.json 의 단계 상태를 갱신하는지 (파이프라인 단계 또는 등록된 선택 단계)."""
    return skill in PIPELINE_PHASES or skill in OPTIONAL_PHASES


def phase_sort_key(name: str) -> tuple[int, int]:
    """단계 표시 순서: 파이프라인 단계 → 선택 단계(레지스트리 순서) → 그 밖의 이름(같은 값 — 안정 정렬로 기록 순서 유지)."""
    if name in PIPELINE_PHASES:
        return (0, PIPELINE_PHASES.index(name))
    if name in OPTIONAL_PHASES:
        return (1, OPTIONAL_PHASES.index(name))
    return (2, 0)


def _slug(text: str, maxlen: int = 24) -> str:
    s = re.sub(r"[^A-Za-z0-9]+", "-", text or "").strip("-").lower()
    return (s or "case")[:maxlen].strip("-") or "case"


class Case:
    def __init__(self, root: Path) -> None:
        self.dir = Path(root).resolve()
        self.id = self.dir.name

    # -- 경로 -----------------------------------------------------------------
    @property
    def meta_path(self) -> Path:
        return self.dir / "case.json"

    @property
    def findings_path(self) -> Path:
        return self.dir / "findings.json"

    @property
    def lock_path(self) -> Path:
        return self.dir / ".case.lock"

    def path(self, *parts: str) -> Path:
        """케이스 디렉터리 내부의 안전한 경로."""
        return safe_join(self.dir, *parts)

    def subdir(self, name: str) -> Path:
        p = self.path(name)
        p.mkdir(parents=True, exist_ok=True)
        return p

    def rel(self, p: Path | str) -> str:
        pp = Path(p).resolve()
        try:
            return str(pp.relative_to(self.dir))
        except ValueError:
            return str(pp)

    def resolve_path(self, p: str | Path) -> Path:
        """케이스 상대경로 또는 케이스 내부 절대경로를 절대경로로 (케이스 밖이면 오류)."""
        pp = Path(p)
        if not pp.is_absolute():
            return self.path(str(pp))
        if not is_within(self.dir, pp):
            raise CaseError(f"케이스 디렉터리 밖의 경로입니다: {pp}", hint=f"{self.dir} 내부 경로를 사용하세요.")
        return pp.resolve()

    # -- 메타데이터 -------------------------------------------------------------
    def load(self) -> dict[str, Any]:
        meta = read_json(self.meta_path)
        if meta is None:
            raise NotFound(f"케이스 메타데이터가 없습니다: {self.meta_path}")
        return meta

    def _update(self, fn) -> dict[str, Any]:
        with file_lock(self.lock_path):
            meta = self.load()
            result = fn(meta)
            meta["updated_at"] = utcnow_iso()
            atomic_write_json(self.meta_path, meta)
            return result if result is not None else meta

    @property
    def meta(self) -> dict[str, Any]:
        return self.load()

    def is_authorized(self) -> bool:
        auth = self.load().get("authorization") or {}
        return auth.get("basis") in AUTH_BASES and bool(auth.get("owner")) and bool(auth.get("statement"))

    def require_authorization(self) -> None:
        if not self.is_authorized():
            raise AuthorizationRequired(
                f"케이스 {self.id} 에 소유/허가 증명(authorization)이 기록되어 있지 않습니다.",
                hint=(
                    "하드웨어 도구를 쓰기 전에 사용자에게 기기 소유 또는 서면 허가 여부를 확인받고, "
                    "case_set_authorization(또는 `pweh case attest`)으로 기록하세요."
                ),
            )

    def set_phase(self, phase: str, status: str, note: str | None = None) -> dict[str, Any]:
        """단계 상태 수동 갱신. 선택 단계(OPTIONAL_PHASES)는 여기나 record_step 에서 처음 생긴다.
        단계 이름은 검사하지 않는다 — 레지스트리 밖의 이름도 기록되고 보고서의 '선택 단계' 표에 보인다."""
        if status not in PHASE_STATUSES:
            raise ValidationFailed(f"잘못된 단계 상태: {status!r}", hint=f"허용: {PHASE_STATUSES}")

        def fn(meta: dict[str, Any]) -> dict[str, Any]:
            phases = meta.setdefault("phases", {})
            entry = phases.setdefault(phase, {})
            entry["status"] = status
            entry["updated_at"] = utcnow_iso()
            if note:
                entry["note"] = note
            return entry

        return self._update(fn)

    def set_authorization(self, authorization: dict[str, Any]) -> dict[str, Any]:
        auth = normalize_authorization(authorization)

        def fn(meta: dict[str, Any]) -> dict[str, Any]:
            meta["authorization"] = auth
            return auth

        result = self._update(fn)
        self.audit({"event": "authorization_recorded", "authorization": auth})
        return result

    def update_target(self, patch: dict[str, Any]) -> dict[str, Any]:
        def fn(meta: dict[str, Any]) -> dict[str, Any]:
            tgt = meta.setdefault("target", {})
            for k, v in patch.items():
                if v is not None:
                    tgt[k] = v
            return tgt

        return self._update(fn)

    def add_note(self, text: str, author: str = "agent") -> dict[str, Any]:
        note = {"at": utcnow_iso(), "author": author, "text": text}

        def fn(meta: dict[str, Any]) -> dict[str, Any]:
            meta.setdefault("notes", []).append(note)
            return note

        return self._update(fn)

    # -- 아티팩트 ---------------------------------------------------------------
    def register_artifact(
        self,
        path: str | Path,
        *,
        kind: str,
        producer: str,
        description: str | None = None,
        extra: dict[str, Any] | None = None,
        compute_hash: bool = True,
        sha256: str | None = None,
        check: Callable[[dict[str, Any]], None] | None = None,
        on_commit: Callable[[dict[str, Any]], None] | None = None,
        deadline: float | None = None,
        replace_existing: bool = True,
    ) -> dict[str, Any]:
        """아티팩트 등록. 기본은 같은 경로 갱신, supplied sha256은 재해시하지 않는다.

        선택 check(entry)는 metadata lock 안에서 최종 경로/크기/해시 seal을 검증한다.
        on_commit(entry)는 원자 metadata 게시 직후 audit보다 먼저 호출된다. 그 뒤 오류는
        이미 등록한 파일을 되돌리지 않는다. deadline은 이 등록의 잠금 대기도 제한한다.
        """
        if (type(replace_existing) is not bool or (check is not None and not callable(check))
                or (on_commit is not None and not callable(on_commit))):
            raise ValidationFailed("아티팩트 등록 옵션이 올바르지 않습니다.")
        def remaining() -> float:
            if deadline is None:
                return 30.0
            try:
                if type(deadline) not in (int, float):
                    raise ValueError
                value = float(deadline)
                if not math.isfinite(value):
                    raise ValueError
            except (OverflowError, ValueError):
                raise ValidationFailed("아티팩트 등록 시간 상한이 올바르지 않습니다.") from None
            left = value - time.monotonic()
            if left <= 0:
                raise CaseError("아티팩트 등록 시간 상한을 넘었습니다.", code="artifact_timeout")
            return min(30.0, left)
        remaining()
        p = self.resolve_path(path)
        if not p.exists():
            raise NotFound(f"아티팩트 파일이 없습니다: {p}")
        is_dir = p.is_dir()
        entry: dict[str, Any] = {
            "path": self.rel(p),
            "kind": kind,
            "producer": producer,
            "is_dir": is_dir,
            "created_at": utcnow_iso(),
        }
        if description:
            entry["description"] = description
        if not is_dir:
            entry["size"] = p.stat().st_size
            if sha256:
                entry["sha256"] = sha256
            elif compute_hash:
                entry["sha256"] = sha256_file(p)
        if extra:
            entry["extra"] = extra

        def fn(meta: dict[str, Any]) -> dict[str, Any]:
            arts = meta.setdefault("artifacts", [])
            # 같은 경로는 갱신
            for i, a in enumerate(arts):
                if a.get("path") == entry["path"]:
                    if not replace_existing:
                        raise CaseError("이미 등록된 아티팩트 경로입니다.", code="artifact_exists")
                    entry["id"] = a.get("id")
                    arts[i] = entry
                    return entry
            entry["id"] = f"A-{len(arts) + 1:04d}"
            arts.append(entry)
            return entry

        if check is None and on_commit is None and deadline is None and replace_existing:
            result = self._update(fn)
        else:
            # 이 등록만의 선택 경계다. 공통 _update의 기존 호출 계약은 바꾸지 않는다.
            with file_lock(self.lock_path, timeout=remaining()):
                remaining()
                meta = self.load()
                result = fn(meta)
                if check is not None and check(dict(result)) is not None:
                    raise ValidationFailed("아티팩트 최종 검사가 완료되지 않았습니다.")
                remaining()
                meta["updated_at"] = utcnow_iso()
                atomic_write_json(self.meta_path, meta)
                if on_commit is not None:
                    on_commit(dict(result))
        self.audit({"event": "artifact_registered", "artifact": result})
        return result

    def import_file(self, src: str | Path, dest_subdir: str, *, kind: str, producer: str, description: str | None = None,
                    source_fd: int | None = None) -> dict[str, Any]:
        """케이스 밖의 파일(예: 공식 펌웨어 다운로드)을 케이스로 복사 후 등록.

        원본은 한 번 연 일반 파일 fd 에서 복사·해시한다. source_fd 는 호출자가 경로 가드를 끝낸 fd 이며
        여기서는 복제본만 닫는다. src 는 그 경우 이름·출처 표시용이고 다시 해석하거나 열지 않는다.
        원본 하드 링크는 거부하고, 대상은 디렉터리 fd 안에 O_EXCL 로 만든다(기존 파일·끊어진 링크도 거부).
        """
        srcp = Path(os.path.abspath(Path(src).expanduser())) if source_fd is not None else Path(src).expanduser().resolve()
        try:
            if source_fd is None:
                inp, st = safeio.open_regular(srcp, what="가져올 파일", reject_hardlinks=True)
            else:
                inp = os.dup(source_fd)
                try:
                    st = os.fstat(inp)
                    if not stat.S_ISREG(st.st_mode) or st.st_nlink != 1:
                        raise safeio.UnsafeFile("가져올 파일은 하드 링크가 없는 일반 파일이어야 합니다.")
                except BaseException:
                    os.close(inp)
                    raise
        except FileNotFoundError:
            raise NotFound(f"가져올 파일이 없습니다: {srcp}") from None
        except safeio.UnsafeFile as exc:
            raise ValidationFailed(exc.message) from exc
        try:
            dst_dir = self.subdir(dest_subdir)
            dst = dst_dir / srcp.name
            dfd = safeio.open_dir_chain(self.dir, dst_dir.relative_to(self.dir).parts)
            try:
                try:
                    out = safeio.create_excl(dfd, srcp.name)
                except FileExistsError:
                    raise CaseError(f"이미 같은 이름의 파일이 있습니다: {self.rel(dst)}") from None
                made = os.fstat(out)
                try:
                    digest = safeio.hash_fd(inp, st.st_size, algorithms=("sha256",), out_fd=out)["sha256"]
                    after = os.fstat(inp)
                    if after.st_nlink != 1 or (after.st_size, after.st_mtime_ns) != (st.st_size, st.st_mtime_ns):
                        raise safeio.UnsafeFile("가져올 파일의 크기·수정 시각·링크 수가 복사 중 바뀌었습니다.")
                    # 경로를 다시 읽는 copystat 대신 처음 고정한 원본의 속성만 쓴다.
                    os.fchmod(out, stat.S_IMODE(st.st_mode))
                    os.utime(out, ns=(st.st_atime_ns, st.st_mtime_ns))
                    named = os.stat(srcp.name, dir_fd=dfd, follow_symlinks=False)
                    if not safeio.same_file(named, made) or named.st_nlink != 1:
                        raise safeio.UnsafeFile("가져온 파일의 이름이 복사 중 바뀌었습니다.")
                except BaseException:
                    # 다른 파일로 교체된 이름은 지우지 않는다.
                    try:
                        named = os.stat(srcp.name, dir_fd=dfd, follow_symlinks=False)
                        if safeio.same_file(named, made):
                            os.unlink(srcp.name, dir_fd=dfd)
                    except FileNotFoundError:
                        pass
                    raise
                finally:
                    os.close(out)
            finally:
                os.close(dfd)
        finally:
            os.close(inp)
        return self.register_artifact(dst, kind=kind, producer=producer, description=description, extra={"imported_from": str(srcp)},
                                      sha256=digest)

    def artifacts(self, kind: str | None = None) -> list[dict[str, Any]]:
        arts = self.load().get("artifacts", [])
        return [a for a in arts if kind is None or a.get("kind") == kind]

    # -- 단계 결과 --------------------------------------------------------------
    def record_step(
        self,
        *,
        skill: str,
        step: str,
        status: str,
        summary: str,
        data: dict[str, Any] | None = None,
        artifacts: Iterable[str] | None = None,
        next_actions: Iterable[str] | None = None,
        blockers: Iterable[str] | None = None,
        started_at: str | None = None,
    ) -> dict[str, Any]:
        result = {
            "schema": "pweh.step-result/v1",
            "case_id": self.id,
            "skill": skill,
            "step": step,
            "status": status,
            "summary": summary,
            "started_at": started_at,
            "finished_at": utcnow_iso(),
            "data": data or {},
            "artifacts": [self.rel(self.resolve_path(a)) for a in (artifacts or [])],
            "next_actions": list(next_actions or []),
            "blockers": list(blockers or []),
        }
        schemas.validate("step-result", result)
        if step == "summary":
            data_schema = schemas.SKILL_DATA_SCHEMAS.get(skill)
            if data_schema:
                schemas.validate(data_schema, result["data"], label=f"{skill} 요약 data")

        def fn(meta: dict[str, Any]) -> dict[str, Any]:
            steps = meta.setdefault("steps", [])
            seq = len(steps) + 1
            fname = f"{seq:04d}-{_slug(skill, 40)}-{_slug(step, 32)}.json"
            rel = f"steps/{fname}"
            atomic_write_json(self.path("steps", fname), {**result, "seq": seq})
            steps.append({"seq": seq, "file": rel, "skill": skill, "step": step, "status": status, "at": result["finished_at"]})
            # 요약 단계는 단계(phase) 상태도 갱신. 선택 단계는 여기서 처음 생긴다(새 케이스에 pending 으로 만들지 않음)
            if step == "summary" and tracks_phase(skill):
                phases = meta.setdefault("phases", {})
                phases[skill] = {"status": SUMMARY_PHASE_STATUS.get(status, "in-progress"), "updated_at": result["finished_at"]}
            return {**result, "seq": seq, "file": rel}

        out = self._update(fn)
        self.audit({"event": "step_recorded", "skill": skill, "step": step, "status": status, "file": out["file"]})
        return out

    def steps(self, skill: str | None = None, *, load: bool = False) -> list[dict[str, Any]]:
        idx = self.load().get("steps", [])
        rows = [s for s in idx if skill is None or s.get("skill") == skill]
        if load:
            return [read_json(self.path(s["file"])) or s for s in rows]
        return rows

    def latest_summary(self, skill: str) -> dict[str, Any] | None:
        rows = [s for s in self.steps(skill) if s.get("step") == "summary"]
        if not rows:
            return None
        return read_json(self.path(rows[-1]["file"]))

    # -- 발견사항 ---------------------------------------------------------------
    def _load_findings(self) -> dict[str, Any]:
        doc = read_json(self.findings_path)
        if doc is None:
            doc = {"schema": "pweh.findings/v1", "case_id": self.id, "findings": []}
        return doc

    def findings(self, min_severity: str | None = None) -> list[dict[str, Any]]:
        items = self._load_findings()["findings"]
        if min_severity:
            limit = SEVERITY_ORDER.get(min_severity, 4)
            items = [f for f in items if SEVERITY_ORDER.get(f.get("severity", "info"), 4) <= limit]
        return sorted(items, key=lambda f: (SEVERITY_ORDER.get(f.get("severity", "info"), 4), f.get("id", "")))

    def add_finding(self, finding: dict[str, Any]) -> dict[str, Any]:
        f = dict(finding)
        f.setdefault("status", "unverified")
        f.setdefault("created_at", utcnow_iso())
        f.setdefault("evidence", [])
        f.setdefault("references", [])
        with file_lock(self.lock_path):
            doc = self._load_findings()
            items = doc["findings"]
            # 중복 방지: 같은 제목 + 같은 위치면 기존 항목 반환
            loc_key = (f.get("title"), str((f.get("location") or {}).get("file")), str((f.get("location") or {}).get("function")), str((f.get("location") or {}).get("address")))
            for existing in items:
                ek = (existing.get("title"), str((existing.get("location") or {}).get("file")), str((existing.get("location") or {}).get("function")), str((existing.get("location") or {}).get("address")))
                if ek == loc_key:
                    return {**existing, "duplicate": True}
            f["id"] = f"F-{len(items) + 1:03d}"
            schemas.validate("finding", f, label="finding")
            items.append(f)
            atomic_write_json(self.findings_path, doc)
        self.audit({"event": "finding_added", "id": f["id"], "title": f.get("title"), "severity": f.get("severity")})
        return f

    def update_finding(self, finding_id: str, patch: dict[str, Any]) -> dict[str, Any]:
        with file_lock(self.lock_path):
            doc = self._load_findings()
            for i, f in enumerate(doc["findings"]):
                if f.get("id") == finding_id:
                    updated = {**f, **{k: v for k, v in patch.items() if k != "id"}, "updated_at": utcnow_iso()}
                    schemas.validate("finding", updated, label="finding")
                    doc["findings"][i] = updated
                    atomic_write_json(self.findings_path, doc)
                    break
            else:
                raise NotFound(f"발견사항을 찾을 수 없습니다: {finding_id}")
        self.audit({"event": "finding_updated", "id": finding_id, "fields": sorted(patch)})
        return updated

    # -- 감사 -----------------------------------------------------------------
    def audit(self, event: dict[str, Any]) -> None:
        AuditLog(self.dir / "audit.jsonl").write(event)

    def summary(self) -> dict[str, Any]:
        meta = self.load()
        findings = self.findings()
        sev: dict[str, int] = {}
        for f in findings:
            sev[f.get("severity", "info")] = sev.get(f.get("severity", "info"), 0) + 1
        return {
            "id": meta["id"],
            "title": meta.get("title"),
            "status": meta.get("status"),
            "profile": meta.get("profile"),
            "target": meta.get("target", {}),
            "authorized": self.is_authorized(),
            "phases": meta.get("phases", {}),
            "artifact_count": len(meta.get("artifacts", [])),
            "step_count": len(meta.get("steps", [])),
            "findings_by_severity": sev,
            "dir": str(self.dir),
        }


def normalize_authorization(authorization: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(authorization, dict):
        raise ValidationFailed("authorization 은 객체여야 합니다.")
    basis = str(authorization.get("basis", "")).strip().lower()
    if basis not in AUTH_BASES:
        raise ValidationFailed(
            f"authorization.basis 는 {AUTH_BASES} 중 하나여야 합니다 (받은 값: {basis!r}).",
            hint="본인 소유 기기면 'owned', 서면 허가를 받은 기기면 'written-authorization'.",
        )
    owner = str(authorization.get("owner", "")).strip()
    statement = str(authorization.get("statement", "")).strip()
    if not owner or not statement:
        raise ValidationFailed(
            "authorization.owner 와 authorization.statement 는 필수입니다.",
            hint="statement 에는 사용자가 소유/허가를 확인한 말을 그대로 인용하세요.",
        )
    if basis == "written-authorization" and not str(authorization.get("document_ref", "")).strip():
        raise ValidationFailed(
            "서면 허가(written-authorization)인 경우 document_ref(허가서 식별자/경로)가 필요합니다.",
        )
    return {
        "basis": basis,
        "owner": owner,
        "statement": statement,
        "scope": str(authorization.get("scope", "")).strip() or "this device only, lab use",
        "document_ref": (str(authorization.get("document_ref")).strip() if authorization.get("document_ref") else None),
        "attested_by": str(authorization.get("attested_by", "")).strip() or "user (relayed by agent)",
        "attested_via": str(authorization.get("attested_via", "agent-relayed")),
        "attested_at": utcnow_iso(),
    }


class CaseStore:
    def __init__(self, cases_dir: Path, *, state_dir: Path | None = None) -> None:
        self.dir = Path(cases_dir)
        # Runtime은 반드시 보호 상태를 넘긴다. 단독 라이브러리 호출은 기존 인자를 유지한다.
        self.state_dir = Path(state_dir) if state_dir is not None else None

    def _case_dir(self, case_id: str) -> Path:
        if not CASE_ID_RE.match(case_id or ""):
            raise ValidationFailed(f"잘못된 case_id: {case_id!r}", hint="영문/숫자/._- 만 사용 (최대 80자, '.' 으로 끝나면 안 됨)")
        return safe_join(self.dir, case_id)

    def exists(self, case_id: str) -> bool:
        return (self._case_dir(case_id) / "case.json").exists()

    def get(self, case_id: str) -> Case:
        d = self._case_dir(case_id)
        if not (d / "case.json").exists():
            raise NotFound(
                f"케이스를 찾을 수 없습니다: {case_id}",
                hint="case_list 로 기존 케이스를 확인하거나 case_create 로 새로 만드세요.",
            )
        return Case(d)

    def list(self) -> list[dict[str, Any]]:
        if not self.dir.exists():
            return []
        rows = []
        for d in sorted(self.dir.iterdir()):
            meta = read_json(d / "case.json") if d.is_dir() else None
            if not meta:
                continue
            rows.append(
                {
                    "id": meta.get("id"),
                    "title": meta.get("title"),
                    "status": meta.get("status"),
                    "profile": meta.get("profile"),
                    "created_at": meta.get("created_at"),
                    "target": {k: meta.get("target", {}).get(k) for k in ("vendor", "model")},
                }
            )
        return rows

    def create(
        self,
        *,
        title: str,
        target: dict[str, Any] | None = None,
        authorization: dict[str, Any] | None = None,
        profile: str | None = None,
        case_id: str | None = None,
        notes: str | None = None,
    ) -> Case:
        target = dict(target or {})
        automatic = not case_id
        if not case_id:
            stamp = utcnow().strftime("%Y%m%d")
            base = _slug(" ".join(str(target.get(k, "")) for k in ("vendor", "model")).strip() or title)
            case_id = f"{stamp}-{base}"
        # 생성은 safe_join으로 링크를 풀기 전에 ID 자체를 확인해야 한다.
        if not isinstance(case_id, str) or CASE_ID_RE.fullmatch(case_id) is None:
            raise ValidationFailed("잘못된 case_id입니다.", hint="영문/숫자/._- 만 사용 (최대 80자, '.' 으로 끝나면 안 됨)")
        now = utcnow_iso()
        meta: dict[str, Any] = {
            "schema": "pweh.case/v1",
            "id": case_id,
            "title": title,
            "status": "open",
            "created_at": now,
            "updated_at": now,
            "profile": profile or "generic-ipcam",
            "target": target,
            "authorization": normalize_authorization(authorization) if authorization else None,
            "phases": {p: {"status": "pending"} for p in PIPELINE_PHASES},
            "artifacts": [],
            "steps": [],
            "notes": [{"at": now, "author": "agent", "text": notes}] if notes else [],
        }
        schemas.validate("case", meta, label="case.json")
        json.dumps(meta, ensure_ascii=False)  # 직렬화 실패도 예약·디렉터리 생성 전에 확인한다.
        with CreationGuard(self.dir, self.state_dir, CASE_ID_RE) as guard:
            case_id, fd = guard.allocate(case_id, automatic=automatic)
            meta["id"] = case_id
            for sub in STANDARD_DIRS:
                os.mkdir(sub, dir_fd=fd)
            guard.check_case(case_id, fd)
            safeio.write_new(fd, "case.json", (json.dumps(meta, ensure_ascii=False, indent=2) + "\n").encode(), final_mode=0o644)
            event = {"ts": utcnow_iso(), "pid": os.getpid(), "event": "case_created", "title": title,
                     "profile": meta["profile"], "authorized": bool(meta["authorization"])}
            safeio.write_new(fd, "audit.jsonl", (json.dumps(event, ensure_ascii=False) + "\n").encode(), final_mode=0o644)
            os.fsync(fd)
            guard.check_case(case_id, fd)
            return Case(guard.cases_dir / case_id)
