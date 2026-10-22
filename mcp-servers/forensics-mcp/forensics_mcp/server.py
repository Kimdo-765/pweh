"""forensics-mcp: SD 카드 이미지 증거 분석 MCP 서버 (pweh-forensics, docs/architecture.md §6.8, 설계 docs/design/sd-forensics.md §4).

원칙:
- PWEH 는 원시 디스크를 열지 않는다. 사람이 하드웨어 쓰기 방지 장치를 거쳐 이미징 도구로 만든 이미지 **파일**만 받는다.
- 접수(forensics_intake_start)는 케이스 소유/허가 확인 + 목적·법적 근거·설치 장소 유형·업무 목적·역할 기록을 요구하고,
  원본을 한 번 열어(일반 파일만 — pweh.safeio) 그 fd 로 확인한 크기만큼 읽으며 sha256·md5·sha1 을 계산해 케이스의
  forensics/images/EV-NNNN/ 로 복사한다(<이름>.partial 로 쓰고 끝나면 이름을 바꾼다, 파일 0444, 디렉터리 0555).
  커밋 지점은 보관 기록(forensics/custody.jsonl, 해시 체인 + 보호 위치 고정점)의 intake 사건이다 — 그 전에 실패·취소하면 만든
  파일을 지우고 번호를 돌려놓는다. 서버가 도중에 끝나 남은 디렉터리는 다음 접수·서버 시작 때 aborted-intakes/ 로 옮긴다 — 중단 흔적
  (풀린 .intake.lock·.partial 사본·빈 디렉터리)이 있는 것만 옮기고, 흔적 없는 디렉터리는 그대로 둔다(record-without-intake, pweh.evidence).
- 내용 도구는 열 때마다 접수 기록을 보관 기록의 intake 사건과 대조하고, 사본을 안전하게 연 fd 로 빠른 지문(크기·mtime·앞/뒤 1 MiB
  해시)을 확인한다. 다르면 무결성 실패로 기록하고 거부한다(fail closed). 해석·재해시는 지문을 본 바로 그 fd 로 한다.
- 파일 I/O 는 이벤트 루프 밖(워커 스레드·job)에서 한다. forensics/ 아래에는 링크를 따르지 않는 디렉터리 fd 로만 쓴다.
- 동영상 프레임·오디오는 에이전트 문맥으로 돌려주지 않는다. 정지이미지는 image-hints 전용 경로로만 분석·정규화하여 반환한다.
  추출물은 forensics/recovered/ 에만 쓰고 에이전트가 직접 열지 않는다.
- 이 서버는 기기에 아무것도 보내지 않는다. 사람 확인은 Claude Code 권한(쓰는 도구는 매번 확인)과 사람 증명(write-blocker)이다.
"""

from __future__ import annotations

import base64
import contextlib
import dataclasses
import functools
import hashlib
import json
import logging
import os
import shutil
import signal
import threading
import time
from pathlib import Path
from typing import Any

import anyio
from mcp.types import CallToolResult, ImageContent, TextContent
import anyio.to_thread

from pweh import evidence as E
from pweh import fs as pfs
from pweh import safeio
from pweh.case import CASE_ID_RE
from pweh.errors import PwehError, ValidationFailed
from pweh.fsutil import utcnow_iso
from pweh.jobs import JobCancelled
from pweh.mcpkit import ANN_LOCAL_WRITE, ANN_READ_ONLY, Context, create_server, register_job_tools, run_blocking, run_blocking_cancellable, safe_tool
from pweh.runtime import Runtime, get_runtime
from pweh.safety import attestation_response
from pweh.safety.attestations import display_text

from . import fsops, outputs

SERVER_NAME = "forensics-mcp"
PRODUCER = "pweh-forensics"
log = logging.getLogger("pweh.forensics")

#: 설치 장소 유형 (적용 법률이 달라진다 — 설계 §7). 접수 때 반드시 고른다.
SITE_TYPES = {
    "home": "개인 가정용(업무 목적 아님)",
    "public": "공개된 장소에 설치(개인정보 보호법 제25조①)",
    "business": "업무용 비공개 장소",
    "vehicle": "차량(블랙박스)",
    "mobile-business": "업무 목적의 이동형 기기(제25조의2)",
    "unknown": "모름",
}
#: PWEH 사용자의 역할
ROLES = {
    "owner": "기기·카드 소유자 본인",
    "processor": "소유자의 위탁을 받은 수탁자(위탁 문서 필요)",
    "investigator": "적법한 권한으로 의뢰받은 조사자",
    "other": "기타(notes 에 설명)",
}
TEXT_MIN, TEXT_MAX = 3, 500
FREE_SPACE_MARGIN = 256 << 20
WRITE_BLOCKER_QUESTIONS = (
    {"id": "blocker_used", "type": "yesno", "expected": "yes",
     "text": "이 이미지는 카드 리더 일체형 하드웨어 쓰기 방지 장치를 거쳐 만들었다(카드를 그 장치에만 넣었다)."},
    {"id": "blocker_model", "type": "value", "text": "쓰기 방지 장치의 제조사·모델"},
    {"id": "blocker_tested", "type": "yesno",
     "text": "그 장치를 희생용 카드로 먼저 시험했다(쓰기 방지 상태에서 폴더 만들기가 실패함을 확인). 아니면 '아니오'."},
    {"id": "imaging_tool", "type": "value", "text": "이미징 도구와 버전(예: FTK Imager 4.7)"},
)
WRITE_BLOCKER_VALID_S = 90 * 86400
NOTICE = E.FORENSICS_NOTICE
#: forensics_partitions 의 시간 예산과 응답에 싣는 파티션·볼륨 수 상한 (GPT 는 항목이 수만 개일 수 있다)
PARTITIONS_MAX_SECONDS = 60.0
RESPONSE_MAX_PARTITIONS = 128
#: forensics_image_check 의 호출 예산 (고정)
CHECK_MAX_SECONDS = 120.0
#: 증거 목록이 읽는 매니페스트 크기 상한
MANIFEST_MAX = 64 << 20
#: 목록 JSON의 직렬화 크기 상한(해석 예산과 별개)
LIST_MAX_OUTPUT_BYTES = 256 << 20
#: 서버 종료 때 실행 중인 job 을 기다리는 시간
SHUTDOWN_TIMEOUT_S = 10.0

server = create_server(
    SERVER_NAME,
    title="PWEH SD Card Forensics",
    instructions=(
        "SD 카드 이미지 증거 분석 서버. PWEH 는 카드나 원시 디스크를 열지 않는다 — 사람이 하드웨어 쓰기 방지 장치를 거쳐 이미징 도구로 만든 "
        "이미지 파일만 받는다. 권장 순서: forensics_intake_start(케이스 허가 + 목적·법적 근거·설치 장소 유형·역할, 해시·보관 기록) → "
        "forensics_job_status → forensics_verify_start(사본 전체 재해시) → forensics_acquisition_attest(사람 증명: 쓰기 방지 장치) → "
        "forensics_partitions → forensics_image_check(호스트 오염 흔적) → forensics_fs_list(목록·시각·삭제 항목) → "
        "필요한 것만 forensics_extract → forensics_evidence_list(증거 목록·해시값 확인서). 녹화 내용(프레임·썸네일·오디오)은 돌려주지 않고 "
        "추출물은 forensics/recovered/ 에만 쓴다. 정지이미지 1개는 forensics_image_hints 로 검증 후 분석·정규화하여 반환한다. "
        "앱 기록·SQLite·타임라인은 전용 도구로 검증한 선택 파일을 분석한다. 에이전트는 원본·추출물을 직접 열지 않으며, "
        "복구한 자격증명으로 어디에도 로그인하지 않는다."
    ),
)


def rt() -> Runtime:
    return get_runtime(SERVER_NAME)


register_job_tools(server, rt, "forensics")


# ---------------------------------------------------------------------------
# 공통 헬퍼
# ---------------------------------------------------------------------------


def _text_arg(value: Any, name: str, *, required: bool = True) -> str | None:
    if value is None or (isinstance(value, str) and not value.strip()):
        if required:
            raise ValidationFailed(f"{name} 가 필요합니다.", hint=f"{TEXT_MIN}~{TEXT_MAX}자로 적습니다.")
        return None
    if not isinstance(value, str):
        raise ValidationFailed(f"{name} 는 문자열이어야 합니다.")
    text = value.strip()
    if not TEXT_MIN <= len(text) <= TEXT_MAX:
        raise ValidationFailed(f"{name} 는 {TEXT_MIN}~{TEXT_MAX}자여야 합니다(지금 {len(text)}자).")
    if any(ord(c) < 0x20 and c not in "\t" for c in text):
        raise ValidationFailed(f"{name} 에 제어 문자가 있습니다.")
    return text


def _choice(value: Any, name: str, choices: dict[str, str]) -> str:
    if value not in choices:
        raise ValidationFailed(f"{name} 가 잘못되었습니다: {value!r}", hint="허용: " + ", ".join(f"{k}({v})" for k, v in choices.items()))
    return str(value)


def _label(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    if not text:
        return None
    if len(text) > 80 or any(ord(c) < 0x20 for c in text):
        raise ValidationFailed("label 은 제어 문자 없는 80자 이하여야 합니다.")
    return text


def _path_arg(value: Any, name: str) -> str:
    text = "" if value is None else str(value)
    if "\x00" in text:
        raise ValidationFailed(f"{name} 에 NUL 문자가 있습니다.")
    return text


def _safe_file_name(name: str) -> str:
    base = "".join(c if (c.isalnum() or c in "._-") else "_" for c in name)[:96].strip("._-")
    return base or "image.raw"


def _refuse_inside_pweh_dirs(path: Path) -> None:
    """케이스 폴더·상태 폴더 안의 파일은 접수하지 않는다 — 증거는 접수로만 케이스에 들어오고, 케이스 안의 다른 사본은 다른 도구가 읽을 수 있다."""
    r = rt()
    for root, what in ((r.config.cases_dir, "케이스 폴더"), (r.config.state_dir, "PWEH 상태 폴더")):
        try:
            base = Path(root).resolve()
        except (OSError, RuntimeError):  # pragma: no cover
            continue
        if path == base or base in path.parents:
            raise ValidationFailed(
                f"{what} 안의 파일은 접수하지 않습니다: {path.name}",
                hint="이미지를 케이스 밖의 증거 보관 폴더에 두고 그 경로로 접수하세요. 케이스 안(dumps/ 등)에 사본이 있으면 펌웨어 도구가 읽을 수 있으니 지우거나 옮기세요.",
            )


async def _case(case_id: str) -> Any:
    """케이스 로드 + 소유/허가 확인 (case.json 읽기 — 이벤트 루프 밖에서)."""
    return await run_blocking(rt().case, case_id, hardware=True)


def _audit_bg(event: dict[str, Any], case_id: str) -> None:
    try:
        rt().audit(event, case_id)
    except Exception:  # noqa: BLE001 - 감사 로그는 보조 기록이다
        log.warning("감사 로그 기록 실패: %s", event.get("event"), exc_info=True)


def _anchor_dir() -> Path:
    """보관 기록 고정점 위치 (보호 대상 상태 폴더 — 에이전트 수정 금지)."""
    return Path(rt().config.state_dir) / "custody"


def custody(case: Any) -> E.CustodyLog:
    return E.CustodyLog(case, _anchor_dir())


def _audit_custody(case: Any, entry: dict[str, Any]) -> None:
    """보관 기록 사건을 감사 로그에도 남긴다 (보조 기록 — 실패해도 이미 쓴 보관 기록을 되돌리지 않는다)."""
    try:
        rt().audit({"event": f"forensics_{str(entry.get('event')).replace('-', '_')}", "evidence_id": entry.get("evidence_id"),
                    "custody_seq": entry.get("seq"), "custody_hash": entry.get("hash")}, case.id)
    except Exception:  # noqa: BLE001
        log.warning("감사 로그 기록 실패 (case=%s, seq=%s)", getattr(case, "id", "?"), entry.get("seq"), exc_info=True)


def _custody_event(case: Any, event: str, evidence_id: str | None, data: dict[str, Any], *, check: Any = None) -> dict[str, Any]:
    entry = custody(case).append(event, evidence_id=evidence_id, data=data, actor="server", check=check)
    _audit_custody(case, entry)
    return entry


def _record_integrity_failure(case: Any, evidence_id: str, exc: E.IntegrityProblem, **extra: Any) -> None:
    if exc.record:
        _custody_event(case, "integrity-failed", evidence_id, {"reason": exc.reason, "problems": exc.problems[:20], **extra})


def _reference_roots() -> list[str]:
    """안전 정책과 분리된 현재 참조 허용 폴더. 잘못된 설정은 닫힌 상태로 처리한다."""
    value = (rt().config.raw.get("forensics") or {}).get("reference_roots", [])
    if not isinstance(value, list) or any(not isinstance(p, str) or not Path(p).is_absolute() for p in value):
        raise ValidationFailed("forensics.reference_roots 는 절대 경로 문자열 목록이어야 합니다.")
    return value


def _checked_evidence_event(case: Any, opened: E.OpenedEvidence, event: str, data: dict[str, Any], *,
                            check: Any = None) -> dict[str, Any]:
    """기존 목록·추출도 같은 EV 의 최종 재검증을 거쳐 커밋한다. 잠금 밖에서 무결성 실패를 기록한다."""
    def verify(entries: Any) -> None:
        E.recheck_opened(case, opened, entries, reference_roots=_reference_roots)
        if check is not None:
            check()

    try:
        return custody(case).append(event, evidence_id=opened.evidence_id, data=data, check=verify)
    except E.IntegrityProblem as exc:
        _record_integrity_failure(case, opened.evidence_id, exc)
        raise


def _open_evidence_sync(case: Any, evidence_id: str) -> E.OpenedEvidence:
    """내용 도구의 공통 입구 (워커 스레드): 보관 기록(깨짐이면 custody_broken) → 접수 기록과 intake 사건 대조 → 사본을 안전하게 열어
    그 fd 로 빠른 지문 대조. 문제가 있으면 무결성 실패로 기록하고 거부한다. 돌려준 fd 는 호출자가 닫는다(해석·재해시는 이 fd 로만)."""
    E.check_evidence_id(evidence_id)
    entries = custody(case).entries()
    try:
        return E.open_checked(case, evidence_id, entries, reference_roots=_reference_roots())
    except E.IntegrityProblem as exc:
        _record_integrity_failure(case, evidence_id, exc)
        raise


async def open_evidence(case: Any, evidence_id: str) -> E.OpenedEvidence:
    return await run_blocking(_open_evidence_sync, case, evidence_id)


@server.tool(
    description=(
        "증거의 정지이미지 1개를 오프라인 분석한다(소유/허가·보관 기록·open_checked 무결성 검사 필수). "
        "ref 또는 path 로 FAT/exFAT·TAR/ZIP 파일 1개를 선택한다(동시 지정 금지); 둘 다 없으면 EV 자체를 정지이미지로 읽는다. "
        "삭제 파일은 ref 와 복구 method(auto 기본)로 선택하며 방법·신뢰도·완전성을 출처에 기록한다. 불완전한 파일은 거부한다. "
        "최대 64 MiB, 선택·읽기·분석 전체 max_seconds 기본/최대 45초. OCR(kor+eng 기본)·QR/바코드·메타데이터·구조·"
        "스테가노그래피 단서를 JSON 으로, 정규화 PNG 를 MCP 이미지 콘텐츠로 반환한다. OCR·코드는 마스킹하지 않으며 URL 을 열지 않는다. "
        "crop=[x,y,width,height] 는 EXIF 방향 적용 후 좌표. preview=false 면 이미지 콘텐츠 없음. "
        "동영상·오디오·다중 프레임은 해독하지 않는다. JSON·PNG 를 forensics/analysis/ 에 0444 로 저장하고 image-hints 보관 기록에 "
        "입수 해시·선택한 파일 해시·출력 해시를 묶는다. 원본·복구 파일을 에이전트가 직접 열지 않는다."
    ),
    annotations=ANN_LOCAL_WRITE,
)
@safe_tool
async def forensics_image_hints(case_id: str, evidence_id: str, partition: int | None = None,
                                ref: str | None = None, path: str | None = None, method: str = "auto",
                                ocr: bool = True, ocr_lang: str = "kor+eng", qr: bool = True,
                                preview: bool = True, crop: list[int] | None = None, max_seconds: float = 45.0) -> CallToolResult:
    from pweh.imagehints import MAX_INPUT_BYTES, analyze_image, resolve_image_tools

    deadline = E.image_hints_deadline(max_seconds)
    cancelled = threading.Event()
    if ref is not None and path is not None:
        raise ValidationFailed("ref 또는 path 중 하나만 지정하세요.")
    if (ref is not None and not ref.strip()) or (path is not None and not path.strip()):
        raise ValidationFailed("ref·path 는 빈 문자열일 수 없습니다.")
    partition = _partition_arg(partition)
    if ref is None and path is None and (partition is not None or method != "auto"):
        raise ValidationFailed("EV 자체 이미지를 분석할 때는 partition·method 를 지정하지 않습니다.")

    def check_cancelled() -> None:
        if cancelled.is_set():
            raise PwehError("이미지 분석이 취소되었습니다.", code="cancelled")

    def work() -> CallToolResult:
        case = rt().case(case_id, hardware=True)
        with _open_evidence_sync(case, evidence_id) as opened:
            def check_source() -> None:
                after = os.fstat(opened.fd)
                problems = E.fingerprint_problems_fd(opened.intake.get("fingerprint") or {}, opened.fd, after,
                                                       require_readonly_mode=opened.intake.get("storage_mode") != "reference")
                if opened.st.st_ctime_ns != after.st_ctime_ns:
                    problems.append("읽기 시작 뒤 ctime 변경")
                if problems:
                    raise E.IntegrityProblem("이미지 분석 중 증거 사본이 변경되었습니다.", reason="fingerprint-mismatch", problems=problems)

            try:
                if ref is None and path is None:
                    data = E.read_image_bytes(opened.fd, max_bytes=MAX_INPUT_BYTES, deadline=deadline, cancel=cancelled.is_set)
                    member = {"partition": None, "ref": None, "path": None, "deleted": False, "method": "evidence-file",
                              "confidence": "exact", "complete": True, "size": len(data), "sha256": hashlib.sha256(data).hexdigest()}
                else:
                    data, member = fsops.read_selected_file(opened.fd, partition=partition, ref=ref, path=path, method=method,
                                                            max_bytes=MAX_INPUT_BYTES, deadline=deadline, cancel=cancelled.is_set)
            finally:
                try:
                    check_source()
                except E.IntegrityProblem as exc:
                    _record_integrity_failure(case, evidence_id, exc)
                    raise
            options = {"ocr": ocr, "ocr_lang": ocr_lang, "qr": qr, "preview": preview, "crop": crop, "max_seconds": max_seconds}
            result = analyze_image(data, settings=resolve_image_tools(rt().config),
                                   **{**options, "max_seconds": E.image_hints_checkpoint(deadline, cancelled.is_set)}, cancel_event=cancelled)
            source = {"kind": "evidence", "member_selected": ref is not None or path is not None,
                      "evidence_id": evidence_id, "evidence_sha256": (opened.intake.get("hashes") or {}).get("sha256"),
                      "selector": {"partition": partition, "ref": ref, "path": path, "method": method}, **member}
            if source.get("path") is None:
                source.pop("path", None)
            report = {**result["report"], "source": source, "params": options}

            def commit(event_data: dict[str, Any]) -> dict[str, Any]:
                def verify(entries: list[dict[str, Any]]) -> None:
                    check_cancelled()
                    check_source()
                    # commit 직전 상태·접수 기록·사본을 다시 확인한다. 원본 전체 재해시를 뜻하지는 않는다.
                    with E.open_checked(case, evidence_id, entries, reference_roots=_reference_roots()):
                        pass

                try:
                    event = custody(case).append("image-hints", evidence_id=evidence_id, data=event_data, check=verify)
                except E.IntegrityProblem as exc:
                    _record_integrity_failure(case, evidence_id, exc)
                    raise
                _audit_custody(case, event)
                return event

            out = E.store_image_hints(case, report, result["previews"], forensic=True, evidence_id=evidence_id,
                                      commit=commit, check=check_cancelled)
        return CallToolResult(content=[TextContent(type="text", text=json.dumps(out, ensure_ascii=False)), *[
            ImageContent(type="image", data=base64.b64encode(p["data"]).decode("ascii"), mime_type=p["mime_type"])
            for p in result["previews"]]], structured_content=out)

    return await run_blocking_cancellable(work, on_cancel=cancelled.set)


async def _run_job(kind: str, case_id: str, description: str, fn: Any, *, exclusive_key: str | None = None,
                   on_start_error: Any = None) -> dict[str, Any]:
    r = rt()

    def job_fn(jctx: Any) -> dict[str, Any]:
        try:
            return fn(jctx)
        except E.EvidenceError as exc:
            if exc.code == "cancelled":
                raise JobCancelled() from exc
            raise

    try:
        job = r.jobs.start(kind, job_fn, description=description, case_id=case_id, exclusive_key=exclusive_key)
    except BaseException:
        if on_start_error is not None:
            on_start_error()
        raise
    return {"ok": True, "job_id": job.id, "status": job.status,
            "message": "백그라운드 작업을 시작했습니다. forensics_job_status(job_id, wait_seconds=30) 으로 결과(result)를 확인하세요."}


def _dumps(obj: Any) -> str:
    return json.dumps(obj, ensure_ascii=False, default=str)


class _HashingWriter:
    """fd 로 버퍼링해 쓰면서 sha256 을 계산한다 (쓴 바이트 그대로의 해시 — 경로로 다시 읽지 않는다)."""

    def __init__(self, fd: int, check: Any = None) -> None:
        self.fd = fd
        self.h = hashlib.sha256()
        self.buf = bytearray()
        self.size = 0
        self.check = check

    def write(self, text: str | bytes) -> None:
        if self.check is not None:
            self.check()
        b = text.encode("utf-8") if isinstance(text, str) else text
        if self.size + len(b) > LIST_MAX_OUTPUT_BYTES:
            raise E.EvidenceError("목록 JSON이 256 MiB 상한을 넘습니다. 항목 수를 줄이거나 파티션별로 조회하세요.", code="output_limit")
        self.h.update(b)
        self.buf += b
        self.size += len(b)
        if len(self.buf) >= 1 << 20:
            self.flush()

    def flush(self) -> None:
        if self.check is not None:
            self.check()
        if self.buf:
            data, self.buf = bytes(self.buf), bytearray()
            safeio.write_all(self.fd, data)

    def finish(self) -> str:
        self.flush()
        os.fsync(self.fd)
        return self.h.hexdigest()


def _claim_output(case: Any, sub: str, prefix: str, suffix: str = ".json") -> tuple[int, str, int]:
    """forensics/<sub>/<prefix>-NNN<suffix> 를 디렉터리 fd 기준 O_CREAT|O_EXCL|O_NOFOLLOW 로 만든다 → (디렉터리 fd, 이름, 쓰기 fd).
    디렉터리는 링크를 따르지 않고 연다. 호출자가 두 fd 를 닫는다."""
    dfd = E.open_forensics(case, sub, create=True)
    try:
        for n in range(1, 100000):
            name = f"{prefix}-{n:03d}{suffix}"
            try:
                fd = safeio.create_excl(dfd, name, 0o644)
            except FileExistsError:
                continue
            return dfd, name, fd
        raise E.EvidenceError("출력 파일 번호를 확보하지 못했습니다.")  # pragma: no cover
    except BaseException:
        os.close(dfd)
        raise


def _claim_dir(case: Any, sub: str, prefix: str) -> tuple[int, str, int]:
    """forensics/<sub>/<prefix>-NNN/ 을 만든다(mkdir 은 원자적) → (부모 fd, 이름, 디렉터리 fd). 호출자가 두 fd 를 닫는다."""
    pfd = E.open_forensics(case, sub, create=True)
    try:
        for n in range(1, 100000):
            name = f"{prefix}-{n:03d}"
            try:
                os.mkdir(name, 0o755, dir_fd=pfd)
            except FileExistsError:
                continue
            try:
                return pfd, name, os.open(name, safeio.DIR_FLAGS, dir_fd=pfd)
            except OSError as exc:  # 만든 직후 링크·파일로 바뀜 — 따라가지 않는다
                raise E.EvidenceError(f"forensics/{sub}/{name} 이 실제 디렉터리가 아닙니다(바뀜): {exc.strerror or exc}",
                                      code="path_outside_base") from exc
        raise E.EvidenceError("출력 디렉터리 번호를 확보하지 못했습니다.")  # pragma: no cover
    except BaseException:
        os.close(pfd)
        raise


def _partition_arg(partition: Any) -> int | None:
    if partition is None:
        return None
    try:
        v = int(partition)
    except (TypeError, ValueError):
        raise ValidationFailed(f"partition 은 정수(forensics_partitions 의 index)여야 합니다: {partition!r}") from None
    if not 1 <= v <= 4096:
        raise ValidationFailed(f"partition 범위가 잘못되었습니다: {v}")
    return v


def _image(opened: E.OpenedEvidence) -> Any:
    return fsops.image_reader(opened.fd, path=(opened.intake.get("stored_path") or None))


# ---------------------------------------------------------------------------
# 접수
# ---------------------------------------------------------------------------


@dataclasses.dataclass
class _IntakeSource:
    """접수할 원본: 한 번 연 fd 와 그 fstat (복사·해시는 이 fd 로 이 크기만큼만), 실제로 연 파일의 경로."""

    fd: int
    st: os.stat_result
    real: Path
    stored_name: str
    log_info: dict[str, Any] | None
    log_text: str | None
    _closed: bool = False

    def close(self) -> None:
        if not self._closed:
            self._closed = True
            with contextlib.suppress(OSError):
                os.close(self.fd)

    def __del__(self) -> None:  # 요청이 취소돼 준비 결과를 버려도 원본 fd 가 새지 않게
        self.close()


def _prepare_intake(case: Any, image_path: str, imaging_log_path: str | None, storage_mode: str = "copy") -> _IntakeSource:
    """워커 스레드: 원본을 한 번 열어 검사하고(일반 파일·크기·E01·케이스/상태 폴더 밖), 이미징 로그를 거부 검사 뒤 fd 로 상한까지 읽고,
    여유 공간(디렉터리를 만들기 전)과 보관 기록 상태(복사 전)를 확인한다."""
    # 케이스 하위 폴더가 외부를 가리켜도 원래 입력 경로의 재접수 거부를 유지한다.
    _refuse_inside_pweh_dirs(Path(os.path.abspath(os.path.expanduser(image_path))))
    fd, st, real = E.open_image_source(image_path)
    try:
        _refuse_inside_pweh_dirs(real)
        if storage_mode == "reference":
            E.check_reference_fd(fd, real, _reference_roots())
        name = _safe_file_name(real.name)
        if E.RESERVED_NAME_RE.match(name):
            raise ValidationFailed(f"이미지 파일 이름이 증거 디렉터리의 예약 이름과 겹칩니다: {name}",
                                   hint="이미지 파일의 이름을 바꾼 뒤(예: card.img) 접수하세요. EV-NNNN.json·imaging-log.txt·*.partial 은 쓸 수 없다.")
        log_info = log_text = None
        if imaging_log_path:
            log_real, log_text = E.read_imaging_log(imaging_log_path, refuse=_refuse_inside_pweh_dirs)
            log_info = {"name": log_real.name, **E.parse_imaging_log(log_text)}
        free = shutil.disk_usage(case.dir).free
        need = (st.st_size if storage_mode == "copy" else 0) + FREE_SPACE_MARGIN
        if free < need:
            raise ValidationFailed(f"케이스 디스크의 여유 공간이 부족합니다(필요 {need} 바이트, 여유 {free}).",
                                   hint="여유 공간을 늘린 뒤 다시 접수하세요(WSL 가상 디스크도 그만큼 커진다).")
        custody(case).entries()  # 보관 기록이 깨졌으면 복사하기 전에 거부한다(custody_broken)
        return _IntakeSource(fd=fd, st=st, real=real, stored_name=name, log_info=log_info, log_text=log_text)
    except BaseException:
        os.close(fd)
        raise


@server.tool(
    description=(
        "증거 이미지·TAR/ZIP 논리 추출 파일 접수 (job). storage=copy(기본)는 사본을 만들고 reference 는 제자리 참조다. "
        "reference 는 비안전 설정 forensics.reference_roots(기본 []) 아래 실제 읽기 전용 마운트(ST_RDONLY)의 일반 파일만 받으며 "
        "매번 열 때 현재 정책·마운트를 확인한다. 원본을 chmod·마운트·삭제하지 않는다. 참조 기록 아티팩트 해시는 원본 EV 해시와 다르다. "
        "이미지 파일만 받는다 — 원시 디스크·장치·FIFO·빈 파일·E01, 케이스·상태 폴더 안의 파일, NUL 이 든 경로, "
        "증거 디렉터리 예약 이름(EV-NNNN.json·imaging-log.txt·*.partial)은 거부. 케이스 소유/허가와 purpose·legal_basis·"
        "site_type(home/public/business/vehicle/mobile-business/unknown — 적용 법률이 달라진다)·business_purpose(가정용이면 '없음')·"
        "role(owner/processor/investigator/other)을 기록한다. 보관 기록(forensics/custody.jsonl)을 먼저 확인해 깨졌으면 job 없이 바로 "
        "custody_broken. 원본을 한 번 연 fd 로 읽으며 sha256·md5·sha1 을 계산해 forensics/images/EV-NNNN/<이름>.partial 로 복사하고 끝나면 "
        "이름을 바꾼다(파일 0444, 디렉터리 0555). verify_copy=true(기본)면 사본을 다시 해시한다. imaging_log_path(FTK Imager·dc3dd·"
        "ewfacquire 로그)를 주면 해시를 대조하고 로그 사본을 보관한다. 커밋 지점은 보관 기록의 intake 사건이다: 그 전에 실패·취소하면 만든 "
        "파일을 지우고 번호를 돌려놓고, 그 뒤에 온 취소는 무시한다(succeeded). 서버가 도중에 끝나 남은 접수 디렉터리는 다음 접수·서버 시작 때 "
        "forensics/aborted-intakes/ 로 옮긴다(중단 흔적이 있는 것만, 번호는 다시 쓰지 않는다). 결과(forensics_job_status 의 result): "
        "evidence_id, hashes, copy_verified, imaging_log 대조, custody_seq, next_steps — 커밋 뒤 보조 기록(integrity-failed 사건·출처 원장·"
        "아티팩트 색인)과 같은 sha256 확인(보관 기록 읽기)의 실패는 post_commit_errors·note 로 알리고 접수는 그대로다(감사 로그 실패는 "
        "서버 로그에만 남는다)."
    ),
    annotations=ANN_LOCAL_WRITE,
)
@safe_tool
async def forensics_intake_start(
    case_id: str,
    image_path: str,
    purpose: str,
    legal_basis: str,
    site_type: str,
    business_purpose: str,
    role: str,
    imaging_log_path: str | None = None,
    label: str | None = None,
    verify_copy: bool = True,
    storage: str = "copy",
) -> dict[str, Any]:
    storage_mode = storage
    case = await _case(case_id)
    legal = {
        "purpose": _text_arg(purpose, "purpose"),
        "legal_basis": _text_arg(legal_basis, "legal_basis"),
        "site_type": _choice(site_type, "site_type", SITE_TYPES),
        "business_purpose": _text_arg(business_purpose, "business_purpose"),
        "role": _choice(role, "role", ROLES),
    }
    lbl = _label(label)
    img_arg = _path_arg(image_path, "image_path")
    log_arg = _path_arg(imaging_log_path, "imaging_log_path") if imaging_log_path else None
    if storage_mode not in ("copy", "reference"):
        raise ValidationFailed("storage 는 copy 또는 reference 입니다.")
    src = await run_blocking(_prepare_intake, case, img_arg, log_arg, storage_mode)
    size = src.st.st_size

    def work(jctx: Any) -> dict[str, Any]:
        claim: E.EvidenceClaim | None = None
        committed = False
        name = src.stored_name
        try:
            claim = E.claim_evidence_id(case, custody(case), on_event=lambda e: _audit_custody(case, e))
            ev = claim.evidence_id
            if storage_mode == "reference":
                jctx.progress(0, size, "참조 원본 해시 중")
                hashes = safeio.hash_fd(src.fd, size, algorithms=E.HASH_ALGORITHMS,
                                       progress=lambda d, t: jctx.progress(d, size), check=jctx.check_cancelled)
                now = os.fstat(src.fd)
                if (now.st_size, now.st_mtime_ns, now.st_ctime_ns) != (src.st.st_size, src.st.st_mtime_ns, src.st.st_ctime_ns):
                    raise E.EvidenceError("해시 중 참조 원본이 바뀌었습니다.", code="integrity_failed")
                E.check_reference_fd(src.fd, src.real, _reference_roots())
                fp = E.fingerprint_fd(src.fd, now)
                copy_verified = None
            else:
                jctx.progress(0, size, "복사·해시 중")
                tmp = name + E.PARTIAL_SUFFIX
                out_fd = safeio.create_excl(claim.dir_fd, tmp, 0o644)
                try:
                    try:
                        hashes = safeio.hash_fd(src.fd, size, algorithms=E.HASH_ALGORITHMS, out_fd=out_fd,
                                                progress=lambda d, t: jctx.progress(d, size), check=jctx.check_cancelled)
                    except safeio.UnsafeFile as exc:
                        raise E.EvidenceError(f"복사하는 동안 원본이 줄었습니다: {exc.message}", code="integrity_failed",
                                              hint="원본 이미지를 쓰는 다른 프로그램을 끝낸 뒤 다시 접수하세요.") from exc
                    os.fsync(out_fd)
                    os.fchmod(out_fd, 0o444)
                    copy_st = os.fstat(out_fd)
                finally:
                    os.close(out_fd)
                now = os.fstat(src.fd)
                if now.st_size != size or now.st_mtime_ns != src.st.st_mtime_ns:
                    raise E.EvidenceError(f"복사하는 동안 원본이 바뀌었습니다(크기 {size} → {now.st_size}"
                                          f"{', 수정 시각 바뀜' if now.st_mtime_ns != src.st.st_mtime_ns else ''}).", code="integrity_failed",
                                          hint="원본 이미지를 쓰는 다른 프로그램을 끝낸 뒤 다시 접수하세요.")
                copy_verified = None
                if verify_copy:
                    jctx.progress(0, size, "사본 재해시 중")
                    vfd, _ = safeio.open_regular(tmp, dir_fd=claim.dir_fd, expect=copy_st, what="사본", reject_hardlinks=True)
                    try:
                        again = safeio.hash_fd(vfd, size, algorithms=E.HASH_ALGORITHMS, progress=lambda d, t: jctx.progress(d, size),
                                               check=jctx.check_cancelled)
                    finally:
                        os.close(vfd)
                    copy_verified = all(again[a] == hashes[a] for a in E.HASH_ALGORITHMS)
                os.rename(tmp, name, src_dir_fd=claim.dir_fd, dst_dir_fd=claim.dir_fd)
                ffd, fst = safeio.open_regular(name, dir_fd=claim.dir_fd, expect=copy_st, what="사본", reject_hardlinks=True)
                try:
                    fp = E.fingerprint_fd(ffd, fst)
                finally:
                    os.close(ffd)
            comparison = E.compare_log_hashes(src.log_info, hashes) if src.log_info else None
            stored_log = None
            if src.log_text is not None:
                safeio.write_new(claim.dir_fd, E.IMAGING_LOG_NAME, src.log_text.encode("utf-8"), final_mode=0o444)
                stored_log = E.forensics_rel(E.IMAGES_DIR, ev, E.IMAGING_LOG_NAME)
            stored_rel = E.forensics_rel(E.IMAGES_DIR, ev, name) if storage_mode == "copy" else None
            log_info = src.log_info
            record = {
                "schema": E.SCHEMA_EVIDENCE,
                "evidence_id": ev,
                "case_id": case.id,
                "label": lbl,
                "source": {"name": src.real.name, "size": size, "mtime_ns": src.st.st_mtime_ns},
                "stored": {"path": stored_rel, "size": size, "mode": storage_mode},
                **({"reference": {"path": str(src.real)}} if storage_mode == "reference" else {}),
                "hashes": {a: hashes[a] for a in E.HASH_ALGORITHMS},
                "fingerprint": fp,
                "imaging_log": ({"name": log_info["name"], "tool": log_info["tool"], "hashes": log_info["hashes"],
                                 "conflicts": log_info["conflicts"], "comparison": comparison, "stored_path": stored_log} if log_info else None),
                "intake": {"ts": utcnow_iso(), "server": PRODUCER, "copy_verified": copy_verified, **legal},
            }
            rec_bytes = E.record_bytes(record)
            safeio.write_new(claim.dir_fd, f"{ev}.json", rec_bytes, final_mode=0o444)
            rec_sha = hashlib.sha256(rec_bytes).hexdigest()
            jctx.check_cancelled()  # 커밋 전 마지막 취소 지점
            def check_intake(entries: list[dict[str, Any]]) -> None:
                E.refuse_second_intake(ev)(entries)
                if storage_mode == "reference":
                    E.check_reference_fd(src.fd, src.real, _reference_roots())
                    now = os.fstat(src.fd)
                    if (now.st_size, now.st_mtime_ns, now.st_ctime_ns) != (src.st.st_size, src.st.st_mtime_ns, src.st.st_ctime_ns):
                        raise E.EvidenceError("커밋 전 참조 원본이 바뀌었습니다.", code="integrity_failed")

            entry = custody(case).append("intake", evidence_id=ev, actor="server", check=check_intake, data={
                "label": lbl, "source_name": src.real.name, "stored_path": stored_rel, "size": size,
                "hashes": record["hashes"], "fingerprint": fp, "record_sha256": rec_sha, "copy_verified": copy_verified,
                "imaging_log": ({"tool": log_info["tool"], "comparison": comparison, "stored_path": stored_log} if log_info else None),
                "legal": legal, "storage_mode": storage_mode,
                **({"reference": {"path": str(src.real)}} if storage_mode == "reference" else {}),
            })
            committed = True  # ← 커밋 지점 (보관 기록 intake). 이 뒤의 실패·취소는 접수를 되돌리지 않는다
            jctx.mark_committed()  # 늦은 취소는 무시하고 succeeded 로 끝난다
            try:
                claim.commit()
            except Exception:  # noqa: BLE001 - 디렉터리를 0555 로 못 바꿔도 접수는 커밋됐다(다음 서버 시작·접수의 정리가 마무리한다)
                log.warning("증거 디렉터리 권한 변경 실패: %s", ev, exc_info=True)
        except BaseException:
            if claim is not None and not committed:
                try:
                    left = claim.rollback()
                    if left:
                        log.warning("접수 정리에서 지우지 못한 항목: %s %s", claim.evidence_id, left)
                except Exception:  # noqa: BLE001 - 남은 디렉터리는 다음 접수·서버 시작 때 aborted-intakes/ 로 옮겨진다
                    log.warning("접수 정리 실패: %s", claim.evidence_id, exc_info=True)
            raise
        finally:
            if claim is not None:
                claim.close()
            src.close()
        # ↓ 커밋 뒤의 보조 기록(integrity-failed 사건·출처 원장·아티팩트 색인)과 중복 확인: 실패해도 커밋한 접수를 실패로 만들지
        #   않는다 — 로그를 남기고, 무엇을 남기지(하지) 못했는지 결과의 post_commit_errors 에 적는다(evidence_id 는 그대로 돌려준다).
        #   감사 로그 실패는 _audit_custody 가 스스로 삼키고 서버 로그에만 남긴다(post_commit_errors 에는 없다).
        post_errors: list[str] = []

        def after_commit(what: str, fn: Any) -> Any:
            try:
                return fn()
            except Exception as exc:  # noqa: BLE001 - 커밋한 접수를 보조 기록 실패로 실패 처리하지 않는다
                log.warning("접수 %s: 커밋 뒤 %s 실패", ev, what, exc_info=True)
                post_errors.append(f"{what}: {type(exc).__name__}: {exc}"[:300])
                return None

        _audit_custody(case, entry)  # 감사 로그 실패는 스스로 삼킨다(로그만)
        integrity_event = None
        if copy_verified is False:
            integrity_event = after_commit("보관 기록 integrity-failed 사건",
                                           lambda: _custody_event(case, "integrity-failed", ev, {"reason": "copy-verify-mismatch"}))
        prov = None
        try:
            prov = rt().provenance.record_import(case, case.dir / E.forensics_rel(E.IMAGES_DIR, ev, f"{ev}.json"),
                                                 {"server": PRODUCER, "tool": "forensics_intake_start", "evidence_id": ev},
                                                 {"image_sha256": hashes["sha256"], "image_size": size}, sha256=rec_sha)
        except PwehError as exc:  # 원장이 깨졌거나 기록 파일이 바뀌었으면 접수는 남기되 알린다
            prov = {"error": exc.to_dict()}
        except Exception as exc:  # noqa: BLE001 - 커밋한 접수를 보조 기록 실패로 실패 처리하지 않는다
            prov = {"error": {"code": "internal_error", "message": f"{type(exc).__name__}: {exc}"[:300]}}
        if isinstance(prov, dict) and isinstance(prov.get("error"), dict):
            log.warning("접수 %s: 출처 원장 기록 실패: %s", ev, prov["error"].get("message"))
            post_errors.append(f"출처 원장: {prov['error'].get('code')}: {prov['error'].get('message')}"[:300])
        after_commit("아티팩트 색인(case.json)", lambda: case.register_artifact(
            case.dir / (stored_rel or E.forensics_rel(E.IMAGES_DIR, ev, f"{ev}.json")),
            kind="evidence-image" if stored_rel else "evidence-reference", producer=PRODUCER,
            description=f"증거 {ev}" + (f" ({lbl})" if lbl else ""),
            extra={"evidence_id": ev}, sha256=hashes["sha256"] if stored_rel else rec_sha))
        entries_now = after_commit("같은 sha256 의 증거 확인(보관 기록 읽기)", lambda: custody(case).entries())
        dup = [e["evidence_id"] for e in entries_now or []
               if e.get("event") == "intake" and e.get("evidence_id") != ev
               and ((e.get("data") or {}).get("hashes") or {}).get("sha256") == hashes["sha256"]]
        steps = ["forensics_acquisition_attest(case_id, evidence_id) 로 사람에게 쓰기 방지 장치 사용을 증명받는다(pweh attest)."]
        if copy_verified is None:
            steps.insert(0, "forensics_verify_start(case_id, evidence_id) 로 사본 전체를 다시 해시한다.")
        steps.append("forensics_partitions → forensics_image_check → forensics_fs_list 순서로 본다.")
        out = {
            "ok": copy_verified is not False,
            "evidence_id": ev,
            "stored_path": stored_rel,
            "storage_mode": storage_mode,
            "size": size,
            "hashes": record["hashes"],
            "copy_verified": copy_verified,
            "imaging_log": record["imaging_log"] and {k: record["imaging_log"][k] for k in ("tool", "comparison", "conflicts")},
            "custody_seq": entry["seq"],
            "provenance": prov and {k: prov.get(k) for k in ("seq", "kind", "error") if prov.get(k) is not None},
            "next_steps": steps,
        }
        if dup:
            out["duplicate_of"] = dup
            out["warning"] = f"같은 sha256 의 증거가 이미 있습니다: {', '.join(dup)}"
        if comparison and comparison["status"] == "mismatch":
            # 같은 sha256 경고가 이미 있으면 덮지 않고 잇는다(둘 다 사람이 알아야 한다)
            mismatch = "이미징 로그의 해시와 다릅니다 — 사람에게 알리고, 원본 카드를 다시 이미징할지 결정하게 하세요."
            out["warning"] = f"{out['warning']} / {mismatch}" if out.get("warning") else mismatch
        if copy_verified is False:
            if integrity_event is not None:
                out["error"] = "사본 재해시가 원본 해시와 다릅니다 — 무결성 실패로 기록했습니다. 디스크 상태를 확인하고 다시 접수하세요."
            else:
                out["error"] = ("사본 재해시가 원본 해시와 다릅니다(copy verify mismatch) — 보관 기록의 intake 사건에 copy_verified=false 로 남아 "
                                "무결성 실패로 다룹니다(내용 도구는 거부). integrity-failed 사건은 기록하지 못했습니다(post_commit_errors). "
                                "디스크 상태를 확인하고 다시 접수하세요.")
        if post_errors:
            out["post_commit_errors"] = post_errors
            out["note"] = ("접수는 보관 기록에 커밋됐습니다(intake 사건, custody_seq). 커밋 뒤의 보조 기록·확인 일부를 하지 못했습니다"
                           "(post_commit_errors) — 디스크 상태를 확인하고 사람에게 알리세요.")
        return out

    key = hashlib.sha256(os.fsencode(str(src.real))).hexdigest()[:24]  # 원본 경로는 job 기록에 남기지 않는다
    return await _run_job("forensics-intake", case.id, f"증거 접수 {src.real.name} ({size} 바이트)", work, exclusive_key=f"intake:{key}",
                          on_start_error=src.close)


# ---------------------------------------------------------------------------
# 검증
# ---------------------------------------------------------------------------


@server.tool(
    description=(
        "증거 사본 전체 재해시 (job). 접수 때의 sha256·md5·sha1(보관 기록 intake 사건의 값)과 비교해 match/mismatch 를 보관 기록 verify "
        "사건으로 남긴다. 다르면 integrity-failed 로 표시되고 그 증거의 내용 도구는 모두 거부된다(되돌리지 않는다 — 원본에서 다시 접수). "
        "빠른 지문(크기·mtime·앞뒤 1 MiB 해시·쓰기 권한 없음)이 이미 다르면 재해시 없이 무결성 실패로 기록한다. 해시가 끝난 뒤 온 취소는 "
        "무시한다(기록하고 succeeded). verify 는 그 시점에 디스크에 있는 바이트만 증명한다."
    ),
    annotations=ANN_LOCAL_WRITE,
)
@safe_tool
async def forensics_verify_start(case_id: str, evidence_id: str) -> dict[str, Any]:
    case = await _case(case_id)
    opened = await open_evidence(case, evidence_id)
    size = int(opened.intake["size"])
    expected = opened.intake["hashes"]

    def work(jctx: Any) -> dict[str, Any]:
        try:
            jctx.progress(0, size, "재해시 중")
            try:
                again: dict[str, str] | None = safeio.hash_fd(opened.fd, size, algorithms=E.HASH_ALGORITHMS,
                                                              progress=lambda d, t: jctx.progress(d, size), check=jctx.check_cancelled)
            except safeio.UnsafeFile:  # 읽는 동안 사본이 줄었다
                again = None
            size_now = os.fstat(opened.fd).st_size
            if opened.intake.get("storage_mode") == "reference":
                E.check_reference_fd(opened.fd, Path(opened.record["reference"]["path"]), _reference_roots())
                if os.fstat(opened.fd).st_ctime_ns != opened.st.st_ctime_ns:
                    again = None
        finally:
            opened.close()
        # 재해시가 끝났다 — 이 결과는 기록한다. 이 뒤에 온 취소는 무시하고(succeeded), 기록한 verify 가 cancelled 로 보이지 않게 한다
        jctx.mark_committed()
        details = {a: ("match" if again is not None and again[a] == expected[a] else "mismatch") for a in E.HASH_ALGORITHMS}
        result = "match" if all(v == "match" for v in details.values()) and size_now == size else "mismatch"
        entry = _custody_event(case, "verify", evidence_id, {"result": result, "details": details, "size": size_now})
        out = {"ok": result == "match", "evidence_id": evidence_id, "result": result, "details": details, "custody_seq": entry["seq"]}
        if result != "match":
            try:
                _custody_event(case, "integrity-failed", evidence_id, {"reason": "verify-mismatch", "details": details})
            except Exception as exc:  # noqa: BLE001 - verify 불일치는 이미 기록됐다(상태는 그것만으로 integrity-failed)
                log.warning("verify %s: integrity-failed 사건 기록 실패", evidence_id, exc_info=True)
                out["post_commit_errors"] = [f"보관 기록 integrity-failed 사건: {type(exc).__name__}: {exc}"[:300]]
                out["note"] = ("verify 불일치는 보관 기록에 남았습니다(상태 integrity-failed, 내용 도구는 거부). integrity-failed 사건은 "
                               "기록하지 못했습니다 — 디스크 상태를 확인하고 사람에게 알리세요.")
        return out

    return await _run_job("forensics-verify", case.id, f"증거 재해시 {evidence_id}", work, exclusive_key=f"verify:{case.id}:{evidence_id}",
                          on_start_error=opened.close)


# ---------------------------------------------------------------------------
# 사람 증명: 쓰기 방지 장치
# ---------------------------------------------------------------------------


@server.tool(
    description=(
        "획득 방법의 사람 증명 (write-blocker). 사람이 별도 터미널에서 `pweh attest <id>` 로 '하드웨어 쓰기 방지 장치를 거쳐 이미징했다'와 "
        "장치 모델·희생용 카드 시험 여부·이미징 도구를 답한다(증거 id·sha256 에 묶임, 90일). 에이전트는 답하거나 증명을 대신 만들지 않는다. "
        "결과(승인·거부, 앞 증명의 철회·만료)는 보관 기록 attest 사건으로 남고 증거 목록에 표시된다. 쓰기 방지 장치를 쓰지 않았으면 "
        "증명하지 않는다 — 증거 목록에 '증명 없음'으로 남는다."
    ),
    annotations=ANN_LOCAL_WRITE,
)
@safe_tool
async def forensics_acquisition_attest(case_id: str, evidence_id: str, ctx: Context) -> dict[str, Any]:
    case = await _case(case_id)
    opened = await open_evidence(case, evidence_id)
    opened.close()
    sha, size = opened.intake["hashes"]["sha256"], opened.intake["size"]  # 보관 기록(고정점)의 값
    subject = {"evidence_id": evidence_id, "sha256": sha, "size": size}
    summary = display_text(f"증거 {evidence_id} (sha256 {sha[:16]}…, {size} 바이트)의 획득 방법 증명", 300)
    dec = await rt().attest("write-blocker", subject, {"scope": "case", "case_id": case.id}, [dict(q) for q in WRITE_BLOCKER_QUESTIONS],
                            case.id, ctx, summary, tool="forensics_acquisition_attest", valid_seconds=WRITE_BLOCKER_VALID_S)
    prev = (await run_blocking(lambda: E.replay_status(custody(case).entries(), evidence_id))).get("attestation") or {}
    if not dec.satisfied:
        # 사람이 거부했거나 앞 증명이 철회·만료됐으면 보관 기록에 남긴다(다시 부르면 새 요청이 생기고 앞 결과는 previous 로 온다)
        ended = None
        if dec.status == "denied" and dec.attestation_id:
            ended = (dec.attestation_id, "denied")
        elif isinstance(dec.previous, dict) and dec.previous.get("status") in ("denied", "revoked", "expired"):
            ended = (dec.previous.get("attestation_id"), dec.previous["status"])
        if ended and ended[0] and (prev.get("attestation_id"), prev.get("status")) != ended:
            await run_blocking(_custody_event, case, "attest", evidence_id, {"status": ended[1], "attestation_id": ended[0]})
        return attestation_response(dec, tool="forensics_acquisition_attest", evidence_id=evidence_id)
    answers = ((dec.record or {}).get("answers") or {}) if isinstance(dec.record, dict) else {}
    if prev.get("attestation_id") != dec.attestation_id or prev.get("status") != "approved":
        await run_blocking(_custody_event, case, "attest", evidence_id, {
            "status": "approved", "attestation_id": dec.attestation_id,
            "answers": {k: display_text(answers.get(k), 200) for k in ("blocker_model", "blocker_tested", "imaging_tool") if answers.get(k) is not None},
        })
    return {"ok": True, "evidence_id": evidence_id, "attestation_id": dec.attestation_id, "status": "approved",
            "blocker_tested": answers.get("blocker_tested"),
            "next_steps": ["forensics_partitions(case_id, evidence_id) 로 구조를 본다."]}


# ---------------------------------------------------------------------------
# 증거 목록
# ---------------------------------------------------------------------------


def _int_or_zero(v: Any) -> int:
    try:
        return max(0, int(v))
    except (TypeError, ValueError):
        return 0


def _image_hint_outputs(case: Any, entries: list[dict[str, Any]] | None) -> list[dict[str, Any]]:
    """image-hints 사건의 JSON·PNG 해시를 실제 바이트와 대조한다(해독하지 않음).

    출력 경로는 검증된 custody 사건에서만 받으며 analysis/ 바로 아래 파일만 연다. 미기록 JSON 의 경로 필드는 따라가지 않는다.
    """
    prefix = "forensics/analysis/"
    events: dict[str, dict[str, Any]] = {}
    for e in entries or []:
        if e.get("event") in ({"image-hints"} | E.ANALYSIS_EVENTS):
            a = (e.get("data") or {}).get("analysis") or {}
            if isinstance(a.get("path"), str):
                events[a["path"]] = e
    try:
        dfd = E.open_forensics(case, "analysis")
    except FileNotFoundError:
        dfd = None
    except PwehError as exc:
        return [{"path": prefix.rstrip("/"), "kind": "image-hints", "custody": "unknown", "error": exc.message}]
    names: set[str] = set()
    if dfd is not None:
        with os.scandir(dfd) as it:
            names = {prefix + d.name for d in it if any(d.name.startswith(prefix + "-") for prefix in ({"image-hints"} | E.ANALYSIS_EVENTS)) and d.name.endswith(".json")}
    out = []

    def read_output(path: str) -> bytes:
        if not isinstance(path, str) or not path.startswith(prefix) or "/" in path[len(prefix):] or path[len(prefix):] in ("", ".", ".."):
            raise ValidationFailed("이미지 분석 산출물 경로가 analysis/ 의 직접 자식이 아닙니다.")
        if dfd is None:
            raise FileNotFoundError(path)
        return safeio.read_regular(path[len(prefix):], dir_fd=dfd, max_bytes=MANIFEST_MAX, what="이미지 분석 산출물", reject_hardlinks=True)

    try:
        for rel in sorted(names | set(events)):
            event = events.get(rel)
            raw = None
            item: dict[str, Any] = {"path": rel, "kind": "image-hints", "custody": "unknown" if entries is None else "unrecorded"}
            try:
                raw = read_output(rel)
                item["manifest_sha256"] = hashlib.sha256(raw).hexdigest()
            except (OSError, PwehError) as exc:
                item["error"] = "분석 JSON 을 안전하게 읽지 못했습니다."
                if event:
                    item["custody"] = "missing" if isinstance(exc, FileNotFoundError) else "mismatch"
            if event:
                data = event.get("data") or {}
                analysis = data.get("analysis") or {}
                item.update({"evidence_id": event.get("evidence_id"), "custody_seq": event.get("seq"), "files": 1,
                             "bytes": _int_or_zero(analysis.get("size"))})
                item["kind"] = event.get("event")
                matches = item.get("manifest_sha256") == analysis.get("sha256") and raw is not None and len(raw) == analysis.get("size") and "error" not in item
                if matches and event.get("event") in E.ANALYSIS_EVENTS:
                    try:
                        report = json.loads(raw)
                        source = report.get("source") or {}
                        intake = E.latest_intake(entries or [], event.get("evidence_id"))
                        expected = (((intake or {}).get("data") or {}).get("hashes") or {}).get("sha256")
                        matches = source == data.get("source") and source.get("evidence_id") == event.get("evidence_id") and source.get("evidence_sha256") == expected
                    except (ValueError, TypeError, AttributeError):
                        matches = False
                checks = []
                previews = data.get("previews") or []
                if not isinstance(previews, list):
                    previews, matches = [], False
                for p in previews:
                    if not isinstance(p, dict):
                        matches = False
                        continue
                    pc = {"path": p.get("path"), "sha256": p.get("sha256")}
                    try:
                        blob = read_output(p["path"])
                        pc["actual_sha256"] = hashlib.sha256(blob).hexdigest()
                        pc["match"] = pc["actual_sha256"] == p.get("sha256") and len(blob) == p.get("size")
                    except (OSError, PwehError, TypeError, KeyError):
                        pc["match"] = False
                    matches = matches and pc["match"]
                    checks.append(pc)
                    item["files"] += 1
                    item["bytes"] += _int_or_zero(p.get("size"))
                item["previews"] = checks
                if item["custody"] != "missing":
                    item["custody"] = "recorded" if matches else "mismatch"
            out.append(item)
    finally:
        if dfd is not None:
            os.close(dfd)
    return out


def _derived_outputs(case: Any, entries: list[dict[str, Any]] | None) -> list[dict[str, Any]]:
    """forensics/recovered/*/manifest.json 요약 (개수·바이트·매니페스트 sha256)과 보관 기록 extract 사건 대조.

    custody: recorded(사건의 manifest_sha256 과 같음) / mismatch(다름 — 매니페스트가 바뀜) / unrecorded(사건 없음 — 서버가 만들지 않은 것)
    / missing(사건은 있는데 디렉터리·매니페스트가 없음) / unknown(보관 기록이 깨짐). 매니페스트가 객체가 아니면 error 항목으로 건너뛴다.
    링크는 따르지 않고, 매니페스트는 일반 파일만 상한까지 읽는다."""
    out: list[dict[str, Any]] = _image_hint_outputs(case, entries)
    extracts: dict[str, dict[str, Any]] = {}
    for e in entries or []:
        od = (e.get("data") or {}).get("output_dir") if e.get("event") == "extract" else None
        if isinstance(od, str):
            extracts[od] = e
    seen: set[str] = set()
    try:
        rfd = E.open_forensics(case, "recovered")
    except FileNotFoundError:
        rfd = None
    except E.EvidenceError as exc:
        return [{"path": "forensics/recovered", "error": exc.message, "custody": "unknown"}]
    if rfd is not None:
        try:
            with os.scandir(rfd) as it:
                names = sorted((d.name, d.is_dir(follow_symlinks=False)) for d in it)
            for name, is_dir in names:
                rel = f"{E.FORENSICS_DIR}/recovered/{name}"
                seen.add(rel)
                item: dict[str, Any] = {"path": rel}
                raw = None
                if not is_dir:
                    item["error"] = "디렉터리가 아님(링크·파일) — 열지 않음"
                else:
                    try:
                        dfd = os.open(name, safeio.DIR_FLAGS, dir_fd=rfd)
                    except OSError as exc:
                        item["error"] = f"디렉터리를 열 수 없음: {exc.strerror or exc}"
                    else:
                        try:
                            raw = safeio.read_regular("manifest.json", dir_fd=dfd, max_bytes=MANIFEST_MAX, what="manifest", reject_hardlinks=True)
                        except FileNotFoundError:
                            item["error"] = "manifest.json 없음"
                        except PwehError as exc:
                            item["error"] = f"manifest 를 읽을 수 없음: {exc.message}"
                        except OSError as exc:
                            item["error"] = f"manifest 를 읽을 수 없음: {exc.strerror or exc}"
                        finally:
                            os.close(dfd)
                if raw is not None:
                    item["manifest_sha256"] = hashlib.sha256(raw).hexdigest()
                    try:
                        data = json.loads(raw)
                    except (ValueError, UnicodeDecodeError):
                        data = None
                    if not isinstance(data, dict):
                        item["error"] = "manifest 가 JSON 객체가 아님 — 건너뜀"
                    else:
                        files = data.get("files") if isinstance(data.get("files"), list) else []
                        evid = data.get("evidence_id")
                        item.update({"evidence_id": evid if isinstance(evid, str) and E.EV_RE.match(evid) else None, "files": len(files),
                                     "bytes": sum(_int_or_zero(f.get("size")) for f in files if isinstance(f, dict))})
                ev = extracts.get(rel)
                if entries is None:
                    item["custody"] = "unknown"
                elif ev is None:
                    item["custody"] = "unrecorded"
                elif (ev.get("data") or {}).get("manifest_sha256") != item.get("manifest_sha256"):
                    item["custody"] = "mismatch"
                    item["custody_seq"] = ev.get("seq")
                else:
                    item["custody"] = "recorded"
                    item["custody_seq"] = ev.get("seq")
                    item["evidence_id"] = ev.get("evidence_id")
                out.append(item)
        finally:
            os.close(rfd)
    for rel, ev in extracts.items():
        if rel not in seen:
            out.append({"path": rel, "evidence_id": ev.get("evidence_id"), "custody": "missing", "custody_seq": ev.get("seq"),
                        "manifest_sha256": (ev.get("data") or {}).get("manifest_sha256")})
    return out


def _status_text(it: dict[str, Any]) -> str:
    """사람이 읽는 상태: evidence_items 의 status_label(예: 'missing (integrity-failed)'), 없으면 status."""
    return str(it.get("status_label") or it.get("status") or "")


def _evidence_markdown(case: Any, items: dict[str, Any], derived: list[dict[str, Any]]) -> str:
    lines = [f"# 증거 목록 — 케이스 {case.id}", "", f"작성: {utcnow_iso()} (pweh-forensics)", ""]
    chain = items["custody"]
    lines.append(f"보관 기록: {'정상' if chain['ok'] else '깨짐 — ' + str(chain.get('detail'))} (항목 {chain['count']}개"
                 + (f", 마지막 해시 {chain['head'][:16]}…" if chain.get("head") else "") + ")")
    lines += ["", "| 증거 | 라벨 | 크기(바이트) | sha256 | 상태 | 마지막 검증 | 쓰기 방지 장치 증명 |", "|---|---|---|---|---|---|---|"]
    for it in items["items"]:
        att = it.get("attestation") or {}
        lv = it.get("last_verify") or {}
        lines.append("| {ev} | {lb} | {sz} | `{sha}` | {st} | {lv} | {att} |".format(
            ev=it["evidence_id"], lb=display_text(it.get("label") or "", 60).replace("|", "/"), sz=it.get("size", ""),
            sha=(it.get("hashes") or {}).get("sha256", ""), st=_status_text(it),
            lv=f"{lv.get('result')} ({lv.get('ts')})" if lv else "없음", att=att.get("status") or "증명 없음"))
    if items.get("aborted"):
        lines += ["", "## 중단된 접수 (커밋하지 못함 — 증거가 아니다)", "", "| 번호 | 시각 | 옮긴 곳 |", "|---|---|---|"]
        for a in items["aborted"]:
            lines.append(f"| {a.get('evidence_id')} | {a.get('ts')} | {a.get('quarantine_path') or ''} |")
    if derived:
        lines += ["", "## 파생 산출물", "", "| 경로 | 증거 | 파일 수 | 바이트 | manifest sha256 | 보관 기록 |", "|---|---|---|---|---|---|"]
        for d in derived:
            lines.append(f"| {d['path']} | {d.get('evidence_id') or ''} | {d.get('files', '')} | {d.get('bytes', '')} | "
                         f"`{d.get('manifest_sha256', '')}` | {d.get('custody', '')}{(' — ' + d['error']) if d.get('error') else ''} |")
    lines += ["", "## 해시값 확인서", ""]
    anchored = [it for it in items["items"] if it.get("status") in E.ANCHORED_STATUSES and (it.get("hashes") or {}).get("sha256")]
    if not chain["ok"]:
        lines.append("보관 기록이 깨져 해시값을 확인할 수 없다 — 사람이 원인을 확인해야 한다.")
    elif not anchored:
        lines.append("보관 기록에 접수한 증거가 없다.")
    for it in anchored:
        h = it.get("hashes") or {}
        lines += [f"- {it['evidence_id']}: SHA-256 `{h.get('sha256', '')}`", f"  MD5 `{h.get('md5', '')}` / SHA-1 `{h.get('sha1', '')}`"
                  + (f" (상태: {_status_text(it)})" if it.get("status") != "ok" else "")]
    lines += ["", "위 해시값(보관 기록의 접수 사건에 남은 값)이 원본 매체에서 만든 이미지의 해시값과 같음을 확인합니다.", "",
              "확인 일시: ____________________", "", "소유자(또는 제출인) 성명·서명: ____________________", "",
              "입회인 성명·서명: ____________________", "", "분석자 성명·서명: ____________________", "", "## 고지", "", NOTICE, ""]
    return "\n".join(lines)


def _evidence_list_sync(case: Any, write_files: bool, reference_errors: dict[str, Any] | None = None) -> dict[str, Any]:
    log_ = custody(case)
    entries, broken = log_.read()
    rechecked: list[dict[str, Any]] = []
    reference_errors = dict(reference_errors or {})
    if broken is None:
        # 증명서를 쓰기 전에 커밋한 증거마다 접수 기록·사본 지문을 대조하고 새 문제는 무결성 실패로 남긴다
        for ev in sorted({e["evidence_id"] for e in entries if e.get("event") == "intake" and isinstance(e.get("evidence_id"), str)}):
            if E.replay_status(entries, ev)["status"] == "integrity-failed":
                continue
            try:
                E.open_checked(case, ev, entries, reference_roots=_reference_roots()).close()
            except E.IntegrityProblem as exc:
                if exc.record:
                    with contextlib.suppress(PwehError):
                        _record_integrity_failure(case, ev, exc, found_by="evidence-list")
                    rechecked.append({"evidence_id": ev, "reason": exc.reason})
            except PwehError as exc:
                if exc.code.startswith("reference_"):
                    reference_errors[ev] = exc.code
                continue
    items = E.evidence_items(case, _anchor_dir(), attestations=rt().attestations)
    for item in items["items"]:
        if item["evidence_id"] in reference_errors and item.get("status") != "integrity-failed":
            item.update(status="unverified", status_label="unverified", reference_error=reference_errors[item["evidence_id"]])
    if reference_errors:
        write_files = False  # 현재 참조를 검증하지 못한 확인서는 만들지 않는다.
    entries2, broken2 = log_.read()
    derived = _derived_outputs(case, None if broken2 else entries2)
    out: dict[str, Any] = {"ok": True, "custody": items["custody"], "items": items["items"], "aborted": items.get("aborted") or [],
                           "derived": derived, "notice": NOTICE}
    if reference_errors:
        out.update(ok=False, reference_errors=reference_errors, certificate_written=False)
    if rechecked:
        out["integrity_failures_recorded"] = rechecked
    if write_files:
        try:
            ffd = E.open_forensics(case)
        except FileNotFoundError:
            ffd = None
        except E.EvidenceError as exc:  # forensics/ 가 링크 등 — 따라가 쓰지 않는다(목록은 돌려준다)
            ffd = None
            out["files_error"] = exc.to_dict()
        if ffd is not None:
            try:
                jbytes = (json.dumps({"schema": "pweh.evidence-list/v1", "case_id": case.id, "generated_at": utcnow_iso(),
                                      **{k: out[k] for k in ("custody", "items", "aborted", "derived", "notice")}},
                                     ensure_ascii=False, indent=2, default=str) + "\n").encode("utf-8")
                safeio.atomic_write_at(ffd, "evidence-list.json", jbytes, 0o644)
                safeio.atomic_write_at(ffd, "evidence-list.md", _evidence_markdown(case, items, derived).encode("utf-8"), 0o644)
            finally:
                os.close(ffd)
            digest = hashlib.sha256(jbytes).hexdigest()
            if items["custody"]["ok"]:
                _custody_event(case, "evidence-list", None, {"json_sha256": digest, "items": len(items["items"])})
            out["files"] = {"json": E.forensics_rel("evidence-list.json"), "markdown": E.forensics_rel("evidence-list.md"), "json_sha256": digest}
    if not items["items"]:
        out["hint"] = "접수한 증거가 없습니다. forensics_intake_start 로 이미지를 접수하세요."
    return out


@server.tool(
    description=(
        "증거 목록과 해시값 확인서. reference 증거가 있으면 자동 job으로 전체 재해시하고 forensics_job_status로 폴링한다. "
        "참조 정책·읽기 전용 상태·전체 해시 확인이 끝나지 않으면 성공 확인서를 만들지 않는다. 사본만 있으면 즉시 반환한다. 항목마다 크기·해시·status(ok/unverified/integrity-failed/missing/record-invalid/custody-broken/"
        "record-without-intake/intake-in-progress)·status_label(사람이 읽는 표시, 예: 'missing (integrity-failed)')·마지막 검증·쓰기 방지 "
        "장치 증명, 보관 기록 체인 검증, 중단된 접수(aborted[] — 커밋하지 못해 aborted-intakes/ 로 옮긴 것, 증거가 아니다), 파생 산출물"
        "(recovered/ 매니페스트를 보관 기록 extract 사건과 대조한 custody: recorded/mismatch/unrecorded/missing/unknown). 확인서를 쓰기 전에 "
        "커밋한 증거마다 접수 기록·사본 지문을 다시 대조하고 새 문제는 무결성 실패로 남긴다(integrity_failures_recorded). write_files=true"
        "(기본)면 forensics/evidence-list.json·.md(해시값 확인서 서식·고지)를 쓰고 보관 기록에 남긴다."
    ),
    annotations=ANN_LOCAL_WRITE,
)
@safe_tool
async def forensics_evidence_list(case_id: str, write_files: bool = True) -> dict[str, Any]:
    case = await _case(case_id)
    entries, broken = await run_blocking(custody(case).read)
    references = sorted({e["evidence_id"] for e in entries if e.get("event") == "intake"
                         and (e.get("data") or {}).get("storage_mode") == "reference"})
    if broken or not references:
        return await run_blocking(_evidence_list_sync, case, write_files)

    def work(jctx: Any) -> dict[str, Any]:
        errors = {}
        for ev in references:
            jctx.check_cancelled()
            try:
                with _open_evidence_sync(case, ev) as opened:
                    size = int(opened.intake["size"])
                    hashes = safeio.hash_fd(opened.fd, size, algorithms=E.HASH_ALGORITHMS,
                                             progress=lambda d, t: jctx.progress(d, size, f"참조 증거 재해시 {ev}"), check=jctx.check_cancelled)
                    match = hashes == opened.intake["hashes"]
                    _custody_event(case, "verify", ev, {"result": "match" if match else "mismatch", "size": size, "kind": "reference-certificate"},
                                   check=lambda rows: E.recheck_opened(case, opened, rows, reference_roots=_reference_roots))
                    if not match:
                        errors[ev] = "integrity_failed"
            except E.IntegrityProblem as exc:
                _record_integrity_failure(case, ev, exc)
                errors[ev] = "integrity_failed"
            except PwehError as exc:
                errors[ev] = exc.code
        jctx.check_cancelled()
        out = _evidence_list_sync(case, write_files and not errors, errors)
        jctx.mark_committed()
        return out

    return await _run_job("forensics-evidence-list", case.id, "참조 증거 전체 재해시와 확인서", work,
                          exclusive_key=f"evidence-list:{case.id}")


# ---------------------------------------------------------------------------
# 이미지 해석 (pweh.fs — 읽기 전용, 깨끗한 재구현)
# ---------------------------------------------------------------------------


def _check_cancelled(cancelled: threading.Event) -> None:
    """동기 분석도 요청 취소를 계산·쓰기·커밋 직전에 확인한다."""
    if cancelled.is_set():
        raise JobCancelled()


@server.tool(
    description=(
        "증거 이미지의 파티션 구조 (읽기 전용, 호출 예산 60초): MBR/EBR·GPT(헤더·항목 CRC 검사, 512/4096 바이트 섹터)·파티션 표 없음"
        "(superfloppy) → partitions[{index, scheme, start_offset, size_bytes, type_name, name·guid(GPT), fs_hint(fat12/fat16/fat32/exfat/"
        "ntfs/ext…), warnings}]와 지원하는 파티션(FAT12/16/32·exFAT)마다 volumes[{volume: fs_type·volume_label·cluster_size·volume_size·"
        "dirty(깨끗하지 않게 분리된 흔적)}]. 같은 (시작, 크기) 구간은 한 번만 열고(duplicate_of), 서로 다른 구간은 64개까지만 연다 — 나머지는 "
        "omitted('partitions'|'time'|'steps')와 partitions_omitted. 응답은 파티션·볼륨 128개까지(넘으면 truncated, truncated_reason "
        "'response'), 경고는 50개까지 자른다(truncated 는 바뀌지 않음) — 이 truncated 는 예산·파티션 상한·응답 잘림만 뜻한다. 이미지 잘림은 partitions[].warnings(partition_beyond_image·"
        "partition_truncated)·레이아웃 warnings(ebr_beyond_image)·volume.truncated 로 보이고, 시작이 이미지 끝 너머인 파티션의 volumes[].error "
        "는 data.reason beyond_image 다('지원하지 않는 파일 시스템'이 아니다). 열 때마다 증거 사본의 빠른 지문을 확인한다(다르면 무결성 실패로 "
        "기록하고 거부)."
    ),
    annotations=ANN_READ_ONLY,
)
@safe_tool
async def forensics_partitions(case_id: str, evidence_id: str) -> dict[str, Any]:
    case = await _case(case_id)
    cancelled = threading.Event()

    def work() -> dict[str, Any]:
        _check_cancelled(cancelled)
        lim = fsops.limits_for(None, PARTITIONS_MAX_SECONDS)
        opened = _open_evidence_sync(case, evidence_id)
        try:
            _check_cancelled(cancelled)
            with _image(opened) as img:
                layout = pfs.analyze_image(img, limits=lim, budget=pfs.Budget.for_limits(lim, cancel=cancelled.is_set))
                _check_cancelled(cancelled)
        finally:
            opened.close()
        parts = layout.get("partitions") or []
        volumes = layout.get("volumes") or []
        beyond = {p.get("index") for p in parts if fsops.beyond_image(p)}
        vols = []
        for v in volumes[:RESPONSE_MAX_PARTITIONS]:
            item: dict[str, Any] = {"index": v.get("index"), "fs_hint": v.get("fs_hint")}
            if v.get("duplicate_of") is not None:
                item["duplicate_of"] = v.get("duplicate_of")
            if v.get("omitted"):
                item["omitted"] = v.get("omitted")  # 상한·예산 때문에 열지 않음('partitions'|'time'|'steps')
            if v.get("info"):
                item["volume"] = fsops.volume_brief(v["info"])
            if v.get("index") in beyond and not v.get("info"):
                # 시작이 이미지 끝 너머라 파일 시스템을 알아볼 수 없었다 — '지원하지 않는 파일 시스템'이 아니다
                item["error"] = {"code": "validation_failed", "message": "파티션 시작이 이미지 끝 너머라 볼 수 없습니다(잘린 이미지).",
                                 "data": {"reason": "beyond_image"}}
            elif v.get("error"):
                item["error"] = v["error"]
            vols.append(item)
        cut = len(parts) > RESPONSE_MAX_PARTITIONS or len(volumes) > RESPONSE_MAX_PARTITIONS
        truncated = bool(layout.get("truncated")) or cut
        return {"ok": True, "evidence_id": evidence_id, "scheme": layout.get("scheme"), "sector_size": layout.get("sector_size"),
                "image_size": layout.get("image_size"), "partitions": [fsops.partition_brief(p) for p in parts[:RESPONSE_MAX_PARTITIONS]],
                "partitions_total": len(parts), "volumes": vols, "volumes_total": len(volumes),
                "partitions_omitted": int(layout.get("partitions_omitted") or 0), "truncated": truncated,
                "truncated_reason": layout.get("truncated_reason") or ("response" if cut else None),
                "warnings": (layout.get("warnings") or [])[:50],
                "next_steps": ["forensics_image_check(case_id, evidence_id) 로 호스트 오염 흔적을 본다.",
                               "forensics_fs_list(case_id, evidence_id, partition=<index>) 로 목록·시각·삭제 항목을 본다."]}

    out = await run_blocking_cancellable(work, on_cancel=cancelled.set)
    await run_blocking(_audit_bg, {"event": "forensics_partitions", "evidence_id": evidence_id, "scheme": out.get("scheme")}, case.id)
    return out


@server.tool(
    description=(
        "호스트 오염 흔적 검사 (읽기 전용): 보관 기간에 분석 PC 가 카드에 남겼을 흔적 — strong: $RECYCLE.BIN, System Volume Information 의 "
        "IndexerVolumeGuid·WPSettings.dat, .DS_Store·._*(AppleDouble)·.Spotlight-V100·.fseventsd·.Trashes, Thumbs.db·desktop.ini, .Trash-<uid> / "
        "weak: System Volume Information 폴더만, 마지막 접근 날짜가 acquisition_date(YYYY-MM-DD, 생략 시 접수일)와 같은 파일 / ambiguous: dirty 비트. "
        "삭제된 항목도 본다. 호출 하나의 예산(고정): 120초·항목 200000개·경로 글자 수 268,435,456·파티션 64개(같은 구간은 한 번), 볼륨마다 "
        "엔진 예산 하나(열기·정보·순회). 볼륨마다 indicators, walk_truncated_reason(s)·cut_dirs(잘린 디렉터리), unvalidated_dirs(검증하지 못해 "
        "뺀 디렉터리 수). 해석하지 못한 볼륨(volumes[].error, call.volumes_failed), 한도로 잘린 순회·건너뛴 파티션, 끝까지 읽지 못한 살아 있는 "
        "디렉터리(beyond_image·dir_chain_broken·dir_unreadable), 검증하지 못한 살아 있는 디렉터리(dir_unvalidated), 이미지 끝 너머까지 이어지는 "
        "볼륨·통째로 이미지 끝 너머인 파티션(image_truncated — 잘린 이미징), 파티션 표 항목보다 큰 파일 시스템(volume_exceeds_partition)이 있으면 "
        "truncated=true(truncated_reasons, next_steps — volumes[].walk_truncated(_reason)·walk_truncated_reasons 도 이 사유를 포함)이고 "
        "'흔적 없음'이라 하지 않는다. 본 볼륨이 하나도 없으면 note 는 '보지 못했다'다. 흔적은 정황이다(카메라가 만들 수 없는 것은 아니다). "
        "요청 취소는 엔진 검사 지점에서 받아들이고 작업 스레드가 증거 fd를 닫는다."
    ),
    annotations=ANN_READ_ONLY,
)
@safe_tool
async def forensics_image_check(case_id: str, evidence_id: str, partition: int | None = None, acquisition_date: str | None = None) -> dict[str, Any]:
    case = await _case(case_id)
    part = _partition_arg(partition)
    if acquisition_date is not None and not fsops._DATE_RX.match(acquisition_date):
        raise ValidationFailed("acquisition_date 는 YYYY-MM-DD 형식이어야 합니다.")
    cancelled = threading.Event()

    def work() -> dict[str, Any]:
        _check_cancelled(cancelled)
        lim = fsops.limits_for(None, CHECK_MAX_SECONDS)
        budget = fsops.CallBudget.from_limits(lim)
        results = []
        opened = _open_evidence_sync(case, evidence_id)
        acq = acquisition_date or str(opened.intake_ts or (opened.record.get("intake") or {}).get("ts") or "")[:10] or None
        try:
            _check_cancelled(cancelled)
            with _image(opened) as img:
                image_size = int(getattr(img, "size", 0) or 0) or None
                layout = pfs.detect_partitions(img, limits=lim)
                layout_why = fsops.layout_reasons(layout, part)  # 파티션이 통째로 이미지 끝 너머(잘린 이미지)
                for v in fsops.iter_volumes(img, layout, part, lim, budget, include_deleted=True, cancel=cancelled.is_set):
                    _check_cancelled(cancelled)
                    item: dict[str, Any] = {"partition": v["partition"].get("index"), "fs": v["partition"].get("fs_hint")}
                    if v.get("error"):
                        item["error"] = v["error"]
                    else:
                        walk = v["walk"]
                        item["indicators"] = fsops.contamination(walk, v["info"], acq)
                        # 엔진 순회의 사유 + dir_unvalidated·image_truncated·volume_exceeds_partition (fs_list 의 volumes[] 와 같은 규칙)
                        why = fsops.walk_reasons(walk, v["info"], part=v["partition"], image_size=image_size)
                        item["walk_truncated"] = bool(walk.get("truncated")) or bool(why)
                        item["walk_truncated_reason"] = walk.get("truncated_reason") or (why[0] if why else None)
                        item["walk_truncated_reasons"] = why
                        item["cut_dirs"], item["cut_dirs_total"] = fsops.cut_dirs_brief(walk)
                        item["unvalidated_dirs"] = int(walk.get("unvalidated_dirs_total", len(walk.get("unvalidated_dirs") or [])) or 0)
                        del walk
                    results.append(item)
                    del v  # 볼륨 목록은 요약한 뒤 버린다
                _check_cancelled(cancelled)
        finally:
            opened.close()
        strong = sum(1 for r in results for i in r.get("indicators") or [] if i["strength"] == "strong")
        reasons = fsops.call_reasons(budget.limited, [r.get("walk_truncated_reasons") or [] for r in results] + [layout_why])
        walked = sum(1 for r in results if not r.get("error"))
        notes = []
        if strong:
            notes.append("strong 흔적은 사람에게 알리고 보고서 한계에 적는다 — 어느 PC·언제인지는 증거 목록·보관 기록과 함께 사람이 판단한다.")
        if budget.failed:  # 해석하지 못한 볼륨이 있으면 '흔적 없음'이라고 말하지 않는다
            notes.append(f"볼륨 {budget.failed}개를 해석하지 못해(volumes[].error, call.volumes_failed) 그 볼륨의 흔적은 보지 못했다 — "
                         "'흔적 없음'으로 보고하지 않는다. 사람에게 알리고, partition 을 지정해 다시 보거나 보고서 한계에 적는다.")
        elif not walked:  # 본 볼륨이 하나도 없다 — '찾지 못했다'가 아니라 '보지 못했다'
            notes.append("본 볼륨이 없어 흔적을 보지 못했다"
                         + (f"(사유 {', '.join(reasons)})" if reasons else "(지원하는 FAT/exFAT 파티션 없음)")
                         + " — '흔적 없음'으로 보고하지 않는다. forensics_partitions 로 파티션·경고를 확인하고 사람에게 알린다.")
        elif reasons and not strong:  # 순회가 잘렸거나 끝까지 읽지 못한 부분·보지 못한 파티션이 있다 — 본 범위에서만 없었다
            notes.append(f"본 범위에서는 호스트 OS 가 만드는 흔적을 찾지 못했지만, 보지 못한 부분(사유 {', '.join(reasons)})이 있어 "
                         "'흔적 없음'으로 보고하지 않는다(volumes[].walk_truncated_reasons·cut_dirs·unvalidated_dirs, call.partitions_skipped, "
                         "파티션 경고는 forensics_partitions).")
        elif not strong:
            notes.append("호스트 OS 가 만드는 흔적을 찾지 못했다(없음을 증명하지는 않는다).")
        if budget.limited:
            notes.append(f"한도({', '.join(budget.limited)}) 때문에 보지 못한 파티션이 있다 — partition 을 지정해 다시 본다.")
        out = {"ok": True, "evidence_id": evidence_id, "acquisition_date": acq, "volumes": results, "strong_indicators": strong,
               "call": budget.summary(),
               "truncated": bool(reasons) or budget.failed > 0 or any(r.get("walk_truncated") for r in results),
               "truncated_reasons": reasons,
               "note": " ".join(notes)}
        steps = fsops.limit_hints(reasons, tool="image_check")
        if steps:
            out["next_steps"] = steps
        return out

    out = await run_blocking_cancellable(work, on_cancel=cancelled.set)
    await run_blocking(_audit_bg, {"event": "forensics_image_check", "evidence_id": evidence_id, "strong": out["strong_indicators"]}, case.id)
    return out


def _store_archive_list(case: Any, opened: E.OpenedEvidence, inventory: dict[str, Any], *, check: Any = None) -> dict[str, Any]:
    """논리 아카이브 전체 목록은 JSON0444 로, 응답은 제한한 표본으로 남긴다."""
    ev = opened.evidence_id
    dfd, name, fd = _claim_output(case, "analysis", f"fs-list-{ev}")
    committed = False
    try:
        report = {"schema": "pweh.forensics.fs-list/v1", "evidence_id": ev, "evidence_sha256": opened.intake["hashes"]["sha256"],
                  "generated_at": utcnow_iso(), "archive": inventory}
        writer = _HashingWriter(fd, check)
        for chunk in json.JSONEncoder(ensure_ascii=False, allow_nan=False).iterencode(report):
            writer.write(chunk)
        writer.write("\n")
        digest = writer.finish()
        os.fchmod(fd, 0o444)
        sealed = outputs.seal_file(dfd, name, fd)
        rel = E.forensics_rel("analysis", name)
        def verify() -> None:
            outputs.check_root(case, "analysis", dfd)
            outputs.check_file(dfd, name, sealed)
            if check is not None:
                check()
        entry = _checked_evidence_event(case, opened, "list",
                               {"result_path": rel, "result_sha256": digest, "format": inventory["format"],
                                "members": len(inventory["entries"]), "truncated": inventory["truncated"]}, check=verify)
        committed = True
        _audit_custody(case, entry)
        sample = [{k: e.get(k) for k in ("ref", "display_path", "size", "times", "sha256", "status", "blocked_reason")}
                  for e in inventory["entries"][:20]]
        return {"ok": True, "evidence_id": ev, "format": inventory["format"], "result_path": rel, "result_sha256": digest,
                "custody_seq": entry["seq"], "members": len(inventory["entries"]), "sample": sample,
                "bytes_hashed": inventory["bytes_hashed"], "truncated": inventory["truncated"],
                "truncated_reasons": inventory["truncated_reasons"], "warnings": inventory["warnings"]}
    finally:
        if not committed:
            with contextlib.suppress(OSError):
                outputs.discard_file(dfd, name, fd)
        os.close(fd)
        os.close(dfd)


def _extract_archive_work(case: Any, opened: E.OpenedEvidence, refs: list[str], paths: list[str], *,
                          label: str, max_files: int, max_bytes: int, deadline: float, jctx: Any) -> dict[str, Any]:
    """아카이브 추출 산출물의 수명·custody 를 기존 recovered 경로와 같은 규칙으로 관리한다."""
    pfd, name, dfd = _claim_dir(case, "recovered", label)
    rel = E.forensics_rel("recovered", name)
    committed = False
    seals: dict[str, os.stat_result] = {}
    try:
        res = fsops.extract_archive(opened.fd, refs, paths, dfd, max_files=max_files, max_bytes_total=max_bytes,
                                    deadline=deadline, cancel=lambda: jctx.cancelled, seals=seals)
        manifest = {"schema": "pweh.forensics.recovered/v1", "evidence_id": opened.evidence_id,
                    "evidence_sha256": opened.intake["hashes"]["sha256"], "generated_at": utcnow_iso(), **res}
        raw = (json.dumps(manifest, ensure_ascii=False, allow_nan=False) + "\n").encode("utf-8")
        seals["manifest.json"] = outputs.write_sealed(dfd, "manifest.json", raw)
        digest = hashlib.sha256(raw).hexdigest()
        os.fchmod(dfd, 0o555)
        entry = _checked_evidence_event(case, opened, "extract",
                               {"output_dir": rel, "manifest_sha256": digest, "files": len(res["files"]), "bytes": res["bytes_total"],
                                "method": "archive-member", "region": "data", "truncated": res["truncated"]},
                               check=lambda: outputs.check_tree(case, pfd, name, dfd, seals))
        committed = True
        if "cancelled" not in res["truncated_reasons"]:
            jctx.mark_committed()
        _audit_custody(case, entry)
        return {"ok": True, "evidence_id": opened.evidence_id, "output_dir": rel, "manifest": f"{rel}/manifest.json",
                "manifest_sha256": digest, "custody_seq": entry["seq"], **res}
    finally:
        if not committed:
            with contextlib.suppress(OSError, PwehError):
                safeio.remove_dir_at(pfd, name, expect=os.fstat(dfd))
        os.close(dfd)
        os.close(pfd)


def _write_volume(w: _HashingWriter, v: dict[str, Any]) -> None:
    """목록 파일에 볼륨 하나를 쓴다 — 항목은 한 줄에 하나씩 이어서(전체 문서를 메모리에 만들지 않는다)."""
    if v.get("error"):
        w.write(_dumps({"partition": v["partition"].get("index"), "fs": v["partition"].get("fs_hint"), "error": v["error"],
                        "partition_info": v["partition"]}))
        return
    walk = v["walk"]
    meta = _dumps({k: val for k, val in walk.items() if k != "entries"})
    w.write('{"partition": ' + _dumps(v["partition"]) + ', "info": ' + _dumps(v["info"]) + ', "walk": ')
    w.write(meta[:-1] + (", " if meta != "{}" else "") + '"entries": [')
    for i, e in enumerate(walk.get("entries") or []):
        w.write(("," if i else "") + "\n" + _dumps(e))
    w.write("\n]}}")


@server.tool(
    description=(
        "파일 시스템·논리 TAR/ZIP 목록(FAT12/16/32·exFAT 삭제 항목 포함). TAR/ZIP 은 arc:<순번> ref, 멤버 sha256를 "
        "바이트 상한 1 GiB와 max_seconds 안에서 계산한다. 예산 밖 멤버는 sha256=null,status=unverified 이며 사유를 남긴다. "
        "비압축 TAR, ZIP stored/deflate만 지원하며 암호화·링크·sparse·다른 압축은 명시 미지원이다. "
        "해석하지 못한 파티션은 call.partitions_unexamined·unsupported_partitions로 표시한다.  전체 목록(경로·이름·크기·시각·삭제 여부·ref·체인·exFAT ValidDataLength 잔여)은 "
        "forensics/analysis/fs-list-<EV>-NNN.json(0444)에만 쓰고 보관 기록 list 사건에 sha256 을 남긴다. 응답은 볼륨마다 요약: stats, "
        "time_ranges(바탕별 — FAT 은 local-unknown-tz, exFAT 은 UtcOffset 이 있으면 local+offset — 장치 시간대는 가정하지 않는다), "
        "top_dirs·extensions(개수만), files_with_residual, 표본 20개(경로·크기·수정 시각·ref), truncated_reason(s)·cut_dirs(잘린 디렉터리), "
        "unvalidated_dirs(검증하지 못해 목록에서 뺀 디렉터리 수 — 카드 손상·교차 연결 의심). 호출 전체(파티션 합계) 한도: "
        "max_entries(1~200000, 기본 200000), max_seconds(1~600, 기본 180 — 해석 시간이며 목록 파일 쓰기는 들어가지 않는다), 파티션 64개"
        "(같은 구간은 한 번), 경로 글자 수 268,435,456 — 볼륨마다 엔진 예산 하나(열기·정보·순회). 잘림 사유: time·steps·max_entries·"
        "max_total_slots·max_path_chars 는 순회를 멈추고, max_depth(64)·max_dir_slots 와 끝까지 읽지 못한 살아 있는 디렉터리"
        "(beyond_image — 읽을 수 있는 범위 끝, dir_chain_broken — 체인 손상, dir_unreadable)는 그 디렉터리만 빼고 계속한다(cut_dirs). "
        "검증하지 못한 살아 있는 디렉터리(dir_unvalidated), 이미지 끝 너머까지 이어지는 볼륨·통째로 이미지 끝 너머인 파티션(image_truncated — "
        "잘린 이미징), 파티션 표 항목보다 큰 파일 시스템(volume_exceeds_partition)도 사유다 — truncated_reasons·next_steps 로 알린다. "
        "해석하지 못한 볼륨은 volumes[].error·call.volumes_failed 이고 truncated=true. 볼 수 있는 파티션이 없는데 파티션이 이미지 끝 너머면 "
        "validation_failed 가 그렇게 말하고, 그런 파티션을 partition 으로 고르면 beyond_image 다. "
        "목록 JSON은 최대 256 MiB이며 초과하면 output_limit로 실패한다. 요청 취소를 해석·쓰기·커밋 직전에 확인하고 "
        "커밋 전 작성 파일을 정리한다. 커밋 전에 출력 이름·파일 신원·링크 수를 재확인한다. "
        "녹화 내용은 읽지 않는다. 삭제 파일 복구·추출은 forensics_extract 에 ref 를 넘긴다."
    ),
    annotations=ANN_LOCAL_WRITE,
)
@safe_tool
async def forensics_fs_list(case_id: str, evidence_id: str, partition: int | None = None, include_deleted: bool = True,
                            max_entries: int = fsops.LIST_MAX_ENTRIES, max_seconds: float = fsops.LIST_MAX_SECONDS) -> dict[str, Any]:
    case = await _case(case_id)
    part = _partition_arg(partition)
    cancelled = threading.Event()
    check = functools.partial(_check_cancelled, cancelled)

    def work() -> dict[str, Any]:
        check()
        lim = fsops.limits_for(max_entries, max_seconds)
        budget = fsops.CallBudget.from_limits(lim)
        dfd = out_name = out_fd = None
        done = False
        summaries: list[dict[str, Any]] = []
        layout_why: list[str] = []
        opened = _open_evidence_sync(case, evidence_id)
        try:
            check()
            inventory = fsops.archive_inventory(opened.fd, max_entries=lim.max_entries, deadline=budget.deadline,
                                               cancel=cancelled.is_set, hash_members=True, max_hash_bytes=1 << 30)
            if inventory is not None:
                if part is not None:
                    raise ValidationFailed("논리 아카이브에는 partition 을 지정하지 않습니다.")
                check()
                return _store_archive_list(case, opened, inventory, check=check)
            with _image(opened) as img:
                image_size = int(getattr(img, "size", 0) or 0) or None
                layout = pfs.detect_partitions(img, limits=lim)
                layout_why = fsops.layout_reasons(layout, part)  # 파티션이 통째로 이미지 끝 너머(잘린 이미지)
                if not fsops.pick_partitions(layout, part):
                    if layout_why:
                        raise ValidationFailed("해석할 수 있는 FAT/exFAT 파티션이 없습니다 — 파티션이 이미지 끝 너머에 있습니다(잘린 이미지).",
                                               hint="이미징이 끝까지 됐는지 사람에게 확인하고, 필요하면 다시 이미징한다(forensics_partitions 의 "
                                                    "warnings: partition_beyond_image·ebr_beyond_image).")
                    raise ValidationFailed("해석할 수 있는 FAT/exFAT 파티션이 없습니다.", hint="forensics_partitions 로 fs_hint 를 확인하세요(ext4·NTFS 는 아직 없음).")
                dfd, out_name, out_fd = _claim_output(case, "analysis", f"fs-list-{evidence_id}")
                w = _HashingWriter(out_fd, check)
                head = _dumps({"schema": "pweh.forensics.fs-list/v1", "evidence_id": evidence_id, "generated_at": utcnow_iso(),
                               "params": {"partition": part, "include_deleted": include_deleted, "max_entries": lim.max_entries,
                                          "max_seconds": lim.max_seconds, "max_partitions": budget.max_partitions},
                               "scheme": layout.get("scheme")})
                w.write(head[:-1] + ', "volumes": [')
                n = 0
                for v in fsops.iter_volumes(img, layout, part, lim, budget, include_deleted=include_deleted, cancel=cancelled.is_set):
                    check()
                    item: dict[str, Any] = {"partition": v["partition"].get("index"), "fs": v["partition"].get("fs_hint")}
                    if v.get("error"):
                        item["error"] = v["error"]
                    else:
                        item["volume"] = fsops.volume_brief(v["info"])
                        item.update(fsops.summarize_walk(v["walk"], v["info"], part=v["partition"], image_size=image_size))
                    summaries.append(item)
                    w.write(("," if n else "") + "\n")
                    _write_volume(w, v)
                    n += 1
                    del v  # 쓴 볼륨의 목록은 버린다
                w.write('\n], "call": ' + _dumps(budget.summary()) + "}\n")
                digest = w.finish()
            os.fchmod(out_fd, 0o444)
            sealed = outputs.seal_file(dfd, out_name, out_fd)
            rel = E.forensics_rel("analysis", out_name)
            def verify() -> None:
                outputs.check_root(case, "analysis", dfd)
                outputs.check_file(dfd, out_name, sealed)
                check()
            entry = _checked_evidence_event(case, opened, "list", {"result_path": rel, "result_sha256": digest, "call": budget.summary(),
                                                               "volumes": [{"partition": s.get("partition"), "stats": s.get("stats")} for s in summaries[:64]]},
                                            check=verify)
            done = True
            _audit_custody(case, entry)
        finally:
            opened.close()
            if dfd is not None:
                if not done and out_name:
                    with contextlib.suppress(OSError):
                        outputs.discard_file(dfd, out_name, out_fd)
                os.close(dfd)
            if out_fd is not None:
                os.close(out_fd)
        steps = ["삭제 파일은 목적에 필요한 것만 forensics_extract 로 복구한다. 정지이미지 1개는 forensics_image_hints(ref=…) 로 분석하며 원본·추출물을 직접 열지 않는다."]
        reasons = fsops.call_reasons(budget.limited, [s.get("truncated_reasons") or [] for s in summaries] + [layout_why])
        limited = bool(reasons) or any(s.get("truncated") for s in summaries)
        truncated = limited or budget.failed > 0  # 해석하지 못한 볼륨이 있으면 목록은 불완전하다
        if limited:
            steps[0:0] = ([f"목록이 불완전하다(사유 {', '.join(reasons) or '?'} — volumes[].truncated_reasons·cut_dirs·unvalidated_dirs, "
                           "call.partitions_skipped, 파티션 경고는 forensics_partitions)."]
                          + fsops.limit_hints(reasons, tool="fs_list"))
        if budget.failed:
            steps.insert(0, f"볼륨 {budget.failed}개를 해석하지 못해 목록에서 빠졌다(volumes[].error, call.volumes_failed) — 사람에게 알리고, "
                            "partition 을 지정해 다시 보거나 보고서 한계에 적는다(예산이 다 돼 난 오류는 한도로 센다 — call.partitions_skipped).")
        if any(s.get("unvalidated_dirs") and not s.get("unvalidated_dirs_live") for s in summaries):
            steps.append("삭제된 디렉터리 중 검증하지 못한 것(unvalidated_dirs)은 목록에서 뺐다 — 삭제 디렉터리는 클러스터가 재사용되기 쉬워 "
                         "흔한 일이다. 삭제 흔적이 중요하면 사람에게 알린다.")
        return {"ok": True, "evidence_id": evidence_id, "result_path": rel, "result_sha256": digest, "custody_seq": entry["seq"],
                "volumes": summaries[:RESPONSE_MAX_PARTITIONS], "volumes_total": len(summaries), "truncated": truncated,
                "truncated_reasons": reasons, "call": budget.summary(), "next_steps": steps}

    return await run_blocking_cancellable(work, on_cancel=cancelled.set)


@server.tool(
    description=(
        "파일·삭제 파일·TAR/ZIP 멤버 추출 (job). 아카이브는 arc:<순번> ref 또는 정확한 path를 쓰며 중복 이름은 ref로 선택한다. "
        "경로 탈출·링크·특수파일·암호화는 거부하고 ZIP CRC 검증을 끝낸 파일만 보존한다. refs(forensics_fs_list 결과 JSON 의 ref) 또는 paths(살아 있는 파일 경로)로 고른 파일만 "
        "forensics/recovered/<label>-NNN/ 에 0444 파일로 쓴다(이름 정리·번호, 원래 경로는 manifest.json, 실행 비트·링크 없음). refs·paths 는 "
        "중복을 없앤다(같은 항목을 가리키면 하나). ref 는 루트에서 검증한 디렉터리만 따라가는 확인 순회가 그 디렉터리를 찾은 것만 받는다(요청한 "
        "디렉터리를 다 찾으면 멈춘다). 모양이 틀리거나 순회를 끝까지 돌았는데 없으면 bad_ref, 순회가 한도에서 잘렸거나 끝까지 읽지 못한 살아 "
        "있는 디렉터리(beyond_image·dir_chain_broken·dir_unreadable)가 있어 찾지 못했으면 그 ref 만 skipped 의 code refs_unverifiable(찾은 "
        "ref 는 받는다) — 검증된 ref 가 하나도 없고 paths 도 없을 때만 job 이 refs_unverifiable 로 실패한다. paths 는 이름이 정확히 같은 "
        "항목이 먼저, 없으면 대소문자 무시(글자 수를 바꾸는 접기 없음, FAT 은 8.3 이름도)로 찾고 여럿이 맞으면 code ambiguous_path 로 "
        "거부한다. 끝까지 읽지 못했거나 검증하지 못한 디렉터리에서는 대소문자까지 정확히 같은 이름만 받고(대소문자·8.3 별칭으로만 맞으면 "
        "고르지 않는다), 찾지 못하면 not_found 가 아니라 그 사유(max_dir_slots·beyond_image·dir_chain_broken·dir_unvalidated, 읽지 못한 "
        "디렉터리는 dir_unreadable)가 code 다 — manifest·응답의 path 는 디스크의 이름이고 호출자 철자가 다르면 requested_path. "
        "method: auto(가장 믿을 만한 후보) 또는 후보 이름(그 후보만 만든다) — 살아 있는 파일 chain·nofatchain, 삭제한 FAT 파일 contiguous·"
        "skip-allocated·skip-claimed·fat-chain, 삭제한 exFAT 파일 stale-chain·contiguous·skip-allocated. 파일마다 method·confidence·note·"
        "status(예산 때문에 덜 만든 계획은 'limit' + limit_reason)가 manifest 에 남는다. region='residual' 이면 exFAT ValidDataLength 뒤 잔여 "
        "영역(이전 녹화 흔적)만. 상한: max_files(기본 200, 최대 1000), max_bytes(기본 1 GiB, 최대 4 GiB), job 300초 — 덜 쓰면 truncated_reasons"
        "(max_files·max_bytes·time·steps·cancelled·refs_unverifiable·max_depth·max_dir_slots·beyond_image·dir_chain_broken·dir_unreadable·"
        "dir_unvalidated)와 next_steps. 내용이 이미지 끝 너머라 덜 읽은 파일은 상한이 아니라 파일 기록의 complete=false·bytes_beyond_image "
        "다. 취소는 엔진 계산 중에도 받아들인다: "
        "시도하지 않은 항목은 skipped('취소됨'), manifest 에 'cancelled', job 은 cancelled(보관 기록 extract 뒤에 온 취소는 무시). 실패한 추출은 "
        "작성한 출력 디렉터리를 지운다(다른 객체로 바뀐 이름은 건드리지 않음). 커밋 직전에 디렉터리·파일·매니페스트의 "
        "신원·링크 수·변경 여부를 확인해 교체된 출력은 기록하지 않는다. 응답·보관 기록에는 해시·크기·방법만 남고 내용은 돌려주지 않는다. 에이전트는 추출물을 직접 열지 않는다. "
        "정지이미지는 원래 ref/path 를 forensics_image_hints 에 넘겨 분석하고, 동영상·오디오는 사람이 자기 플레이어로 확인한다."
    ),
    annotations=ANN_LOCAL_WRITE,
)
@safe_tool
async def forensics_extract(case_id: str, evidence_id: str, refs: list[str] | None = None, paths: list[str] | None = None,
                            partition: int | None = None, method: str = "auto", region: str = "data", label: str | None = None,
                            max_files: int = 200, max_bytes: int | str = "1G") -> dict[str, Any]:
    from pweh.fsutil import parse_size

    case = await _case(case_id)
    part = _partition_arg(partition)
    if not refs and not paths:
        raise ValidationFailed("refs 또는 paths 가 필요합니다.", hint="forensics_fs_list 결과 JSON 의 ref 를 고르세요.")
    sel_refs = list(dict.fromkeys(str(r) for r in (refs or [])))
    sel_paths = list(dict.fromkeys(str(p) for p in (paths or [])))
    if len(sel_refs) + len(sel_paths) > fsops.EXTRACT_MAX_FILES:
        raise ValidationFailed(f"한 번에 고를 수 있는 항목은 {fsops.EXTRACT_MAX_FILES}개까지입니다.")
    if region not in ("data", "residual"):
        raise ValidationFailed("region 은 'data' 또는 'residual' 입니다.")
    if not isinstance(method, str) or not method.strip() or len(method) > 32:
        raise ValidationFailed("method 가 잘못되었습니다.")
    mf = max(1, min(int(max_files), fsops.EXTRACT_MAX_FILES))
    try:
        mb = parse_size(max_bytes)
    except (TypeError, ValueError, PwehError) as exc:
        raise ValidationFailed(f"max_bytes 가 잘못되었습니다: {max_bytes!r}") from exc
    mb = max(1, min(int(mb), fsops.EXTRACT_MAX_BYTES))
    lbl = fsops._SAFE_NAME_RX.sub("-", (label or "recovered")).strip("-")[:32] or "recovered"
    free = await run_blocking(lambda: shutil.disk_usage(case.dir).free)
    if free < mb + FREE_SPACE_MARGIN:
        raise ValidationFailed(f"여유 공간이 부족합니다(필요 {mb + FREE_SPACE_MARGIN}, 여유 {free}) — max_bytes 를 줄이세요.")
    opened = await open_evidence(case, evidence_id)

    def work(jctx: Any) -> dict[str, Any]:
        deadline = time.monotonic() + fsops.EXTRACT_MAX_SECONDS
        job_lim = fsops.limits_for(None, fsops.EXTRACT_MAX_SECONDS)

        def cancel() -> bool:  # 엔진 예산의 취소 함수 (JobContext.cancelled 는 속성이다 — 함수로 감싸 넘긴다)
            return jctx.cancelled

        try:
            from pweh.archive import kind as archive_kind
            if archive_kind(opened.fd) is not None:
                if part is not None or method != "auto" or region != "data":
                    raise ValidationFailed("아카이브 추출은 partition 없이 method=auto, region=data 만 지원합니다.")
                return _extract_archive_work(case, opened, sel_refs, sel_paths, label=lbl, max_files=mf, max_bytes=mb,
                                             deadline=deadline, jctx=jctx)
            with _image(opened) as img:
                p_info, vol = fsops.open_partition_volume(img, part, job_lim,
                                                          budget=fsops.engine_budget(None, job_lim, deadline=deadline, cancel=cancel))
                jctx.check_cancelled()
                targets, unresolved = fsops.resolve_targets(vol, sel_refs, sel_paths, limits=job_lim, deadline=deadline,
                                                            check=jctx.check_cancelled, cancel=cancel)
                pfd, out_name, dfd = _claim_dir(case, "recovered", lbl)
                rel = E.forensics_rel("recovered", out_name)
                recorded = False  # 보관 기록 extract 를 덧붙였다(커밋) — 그 뒤에는 무슨 일이 있어도 출력 디렉터리를 지우지 않는다
                seals: dict[str, os.stat_result] = {}
                try:
                    try:
                        res = fsops.extract_entries(vol, targets, dfd, method=method, region=region, max_bytes_total=mb, max_files=mf,
                                                    limits=job_lim, deadline=deadline, cancel=cancel, seals=seals)
                        skipped = res["skipped"] + unresolved
                        reasons = fsops.merge_reasons(res["truncated_reasons"], unresolved)
                        manifest = {"schema": "pweh.forensics.recovered/v1", "evidence_id": evidence_id,
                                    "evidence_sha256": opened.intake["hashes"]["sha256"], "partition": p_info.get("index"),
                                    "fs": p_info.get("fs_hint"), "generated_at": utcnow_iso(),
                                    "params": {"method": method, "region": region, "max_files": mf, "max_bytes": mb},
                                    "files": res["files"], "skipped": skipped, "bytes_total": res["bytes_total"],
                                    "truncated": bool(reasons), "truncated_reasons": reasons}
                        mbytes = (json.dumps(manifest, ensure_ascii=False, indent=1, default=str) + "\n").encode("utf-8")
                        seals["manifest.json"] = outputs.write_sealed(dfd, "manifest.json", mbytes)
                        digest = hashlib.sha256(mbytes).hexdigest()
                        os.fchmod(dfd, 0o555)
                        # 커밋 지점: append 는 사건이 남지 않았을 때만 예외를 던진다(고정점 확정 실패는 삼킨다 — pweh.evidence)
                        entry = _checked_evidence_event(case, opened, "extract", {
                            "output_dir": rel, "manifest_sha256": digest, "files": len(res["files"]), "bytes": res["bytes_total"],
                            "method": method, "region": region, "truncated": bool(reasons)},
                            check=lambda: outputs.check_tree(case, pfd, out_name, dfd, seals))
                        recorded = True
                        if "cancelled" not in reasons:
                            # 기록한 뒤(또는 다 쓴 뒤) 도착한 취소는 결과를 바꾸지 않는다(succeeded). 추출이 취소를 받아들여 멈췄으면
                            # (매니페스트 truncated_reasons 에 'cancelled') job 은 cancelled 로 끝나고 결과(부분 출력)는 그대로 남는다
                            jctx.mark_committed()
                        _audit_custody(case, entry)
                    except BaseException as exc:
                        if recorded:  # 보관 기록이 이 출력을 가리킨다 — 지우지 않는다
                            raise
                        # 실패한 추출은 출력 디렉터리를 남기지 않는다(기록 없는 부분 출력 방지 — 취소는 정상 종료로 매니페스트가 남는다)
                        with contextlib.suppress(Exception):
                            left = safeio.remove_dir_at(pfd, out_name, expect=os.fstat(dfd))
                            if left:
                                log.warning("추출 정리에서 지우지 못한 항목: %s %s", rel, left)
                        if isinstance(exc, FileExistsError):  # 새로 만든 출력 디렉터리에 서버가 만들지 않은 항목(링크 등)이 생김
                            raise E.EvidenceError(f"추출 출력 디렉터리에 서버가 만들지 않은 항목이 있습니다({exc.filename}) — 따라가 쓰지 않고 멈췄습니다.",
                                                  code="path_outside_base",
                                                  hint="다른 프로세스가 forensics/recovered/ 를 바꾸고 있지 않은지 사람이 확인한다. 출력 디렉터리는 지웠다.") from exc
                        raise
                finally:
                    os.close(dfd)
                    os.close(pfd)
        finally:
            opened.close()
        files = []
        for f in res["files"]:
            row = {k: f.get(k) for k in ("seq", "file", "path", "deleted", "method", "confidence", "status", "size", "complete", "sha256")}
            row.update({k: f[k] for k in ("limit_reason", "requested_path") if f.get(k)})
            files.append(row)
        out = {"ok": True, "evidence_id": evidence_id, "output_dir": rel, "manifest": f"{rel}/manifest.json",
               "manifest_sha256": digest, "custody_seq": entry["seq"], "bytes_total": res["bytes_total"], "truncated": bool(reasons),
               "truncated_reasons": reasons, "files": files, "skipped": skipped[:50], "skipped_total": len(skipped),
               "note": "원본·추출물을 직접 열지 않는다. 정지이미지는 원래 ref/path 를 forensics_image_hints 에 넘기고, 동영상·오디오는 사람이 자기 플레이어로 확인한다."}
        steps = fsops.limit_hints(reasons, tool="extract")
        if any(u.get("code") == "ambiguous_path" for u in unresolved):
            steps.append("경로가 여러 항목에 맞아(대소문자만 다른 이름 등) 고르지 않은 paths 가 있다(skipped 의 code ambiguous_path) — "
                         "대소문자까지 정확한 이름이나 forensics_fs_list 결과 JSON 의 ref 로 다시 고른다.")
        if steps:
            out["next_steps"] = steps
        return out

    return await _run_job("forensics-extract", case.id, f"추출 {evidence_id} ({len(sel_refs) + len(sel_paths)}개)", work,
                          exclusive_key=f"extract:{case.id}:{evidence_id}", on_start_error=opened.close)


# ---------------------------------------------------------------------------
# 서버 시작·종료
# ---------------------------------------------------------------------------


def _startup_reconcile() -> list[dict[str, Any]]:
    """서버 시작 때: 모든 케이스에서 커밋하지 못한 접수 디렉터리(서버가 복사 중 끝남 등 — 중단 흔적: 풀린 .intake.lock·.partial 사본·
    빈 디렉터리)를 aborted-intakes/ 로 옮긴다(다른 프로세스가 잠근 접수, 흔적 없는 디렉터리는 건드리지 않는다, 보관 기록이 깨진 케이스는
    건너뛴다). 규칙은 pweh.evidence.reconcile_orphans."""
    out: list[dict[str, Any]] = []
    cases_dir = Path(rt().config.cases_dir)
    if not cases_dir.is_dir():
        return out
    for d in sorted(cases_dir.iterdir()):
        try:
            if d.is_symlink() or not d.is_dir() or not CASE_ID_RE.match(d.name):
                continue
            images = d / E.FORENSICS_DIR / E.IMAGES_DIR
            if not images.is_dir():
                continue
            case = rt().cases.get(d.name)
            moved = E.reconcile_orphans(case, custody(case), on_event=functools.partial(_audit_custody, case))
            out += [{"case_id": d.name, **m} for m in moved]
        except Exception:  # noqa: BLE001 - 한 케이스의 문제로 시작을 막지 않는다
            log.warning("시작 정리 실패: %s", d, exc_info=True)
    return out


def _shutdown_cleanup() -> None:
    """실행 중인 job 을 취소하고 기다린다(접수는 커밋 전이면 만든 파일을 지운다)."""
    try:
        rt().jobs.shutdown(timeout=SHUTDOWN_TIMEOUT_S)
    except Exception:  # pragma: no cover
        log.exception("작업 종료 실패")


def _install_sigterm_handler() -> None:
    """SIGTERM: job 을 취소·정리한 뒤(별도 스레드, 최대 SHUTDOWN_TIMEOUT_S) 기본 동작으로 끝낸다. 두 번째 SIGTERM 은 바로 끝낸다."""

    def handler(signum: int, frame: Any) -> None:
        signal.signal(signal.SIGTERM, signal.SIG_DFL)
        log.warning("SIGTERM: 실행 중인 forensics 작업을 취소·정리한 뒤 끝낸다")
        t = threading.Thread(target=_shutdown_cleanup, name="pweh-forensics-shutdown", daemon=True)
        t.start()
        t.join(SHUTDOWN_TIMEOUT_S + 5.0)
        os.kill(os.getpid(), signal.SIGTERM)

    try:
        signal.signal(signal.SIGTERM, handler)
    except ValueError:  # pragma: no cover - 메인 스레드가 아님
        pass


def main() -> None:
    try:
        moved = _startup_reconcile()
        if moved:
            log.info("시작 정리: 커밋하지 못한 접수 %d 개를 aborted-intakes/ 로 옮김", len(moved))
    except Exception:  # noqa: BLE001
        log.warning("시작 정리 실패", exc_info=True)
    _install_sigterm_handler()
    try:
        server.run()
    finally:
        _shutdown_cleanup()


from .android_tools import register_android_tools
from .secrets_tools import register_secrets_tools
from .ioc_tools import register_ioc_tools
from .media_tools import register_media_tools
from .media_candidate_tools import register_media_candidate_tools

register_android_tools(server, globals())
register_secrets_tools(server, globals())
register_ioc_tools(server, globals())
register_media_tools(server, globals())
register_media_candidate_tools(server, globals())


if __name__ == "__main__":
    main()
