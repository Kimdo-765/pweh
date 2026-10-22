"""백그라운드 작업(Job) 관리.

UART md.b 덤프(16MiB @115200 ≈ 수 시간), Ghidra 분석, 긴 로직 캡처처럼 오래 걸리는 작업은
MCP 클라이언트의 도구 호출 타임아웃(예: Codex 기본 60초)을 넘기므로 즉시 job_id 를 돌려주고
에이전트가 ``<prefix>_job_status`` 로 폴링하게 한다.

작업 상태는 케이스 디렉터리의 ``jobs/<job_id>.json`` 에도 기록되어 서버가 재시작되어도 흔적이 남는다.
"""

from __future__ import annotations

import json
import os
import re
import threading
import time
import traceback
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from . import procutil, safeio
from .errors import NotFound, PwehError, ValidationFailed
from .fsutil import new_id, utcnow_iso

ACTIVE_STATES = ("queued", "running", "cancelling")
SAVED_STATES = (*ACTIVE_STATES, "succeeded", "failed", "cancelled", "abandoned")
JOB_ID_RE = re.compile(r"job-[A-Za-z0-9_-]{1,80}\Z")
MAX_RECORD_BYTES = 1 << 20
MAX_SCAN_BYTES = 8 << 20
MAX_SCAN_ENTRIES = 512
MAX_SAVED_JOBS = 256
RECOVERY_SECONDS = 2.0


def _owner_state(owner: Any) -> tuple[str, str]:
    """완전한 로컬 신원만 비교한다. 관찰 불가는 종료로 바꾸지 않는다."""
    if not isinstance(owner, dict):
        return "unknown", "owner_missing"
    pid, ticks = owner.get("pid"), owner.get("start_ticks")
    if (type(pid) is not int or not 0 < pid <= 0x7fffffff or type(ticks) is not int or ticks < 0
            or any(not isinstance(owner.get(k), str) or not owner[k] for k in ("host", "boot_id", "pid_ns"))):
        return "unknown", "owner_incomplete"
    try:
        current = procutil.owner_record("job-recovery")
        if not current.get("host") or owner["host"] != current["host"]:
            return "unknown", "different_host"
        if not current.get("boot_id") or not current.get("pid_ns"):
            return "unknown", "local_identity_unavailable"
        if owner["boot_id"] != current["boot_id"]:
            return "terminated", "boot_changed"
        if owner["pid_ns"] != current["pid_ns"]:
            return "unknown", "different_pid_namespace"
        st = procutil.proc_stat(pid)
        if st is not None:
            if st[1] != ticks:
                return "terminated", "pid_reused"
            if st[0] in ("Z", "X"):
                return "terminated", "process_exited"
            return "alive", "identity_matches"
        if not procutil.pid_alive(pid):
            return "terminated", "process_absent"
        return "unknown", "start_identity_unavailable"
    except (OSError, ValueError, PwehError):
        return "unknown", "process_check_unavailable"


def _public_record(record: dict[str, Any]) -> dict[str, Any]:
    """소유 프로세스의 호스트/PID 등 내부 식별자는 API 응답에서 뺀다."""
    out = {k: v for k, v in record.items() if k != "owner"}
    if isinstance(out.get("meta"), dict):
        out["meta"] = {k: v for k, v in out["meta"].items() if k != "owner"}
    return out


class JobCancelled(Exception):
    """작업이 취소 요청을 받아 중단됨."""


@dataclass
class Job:
    id: str
    kind: str
    description: str
    server: str
    case_id: str | None
    status: str = "queued"  # queued | running | cancelling | succeeded | failed | cancelled
    progress: float | None = None  # 0.0 ~ 1.0
    done: float | None = None
    total: float | None = None
    message: str = ""
    result: dict[str, Any] | None = None
    error: dict[str, Any] | None = None
    created_at: str = field(default_factory=utcnow_iso)
    started_at: str | None = None
    finished_at: str | None = None
    meta: dict[str, Any] = field(default_factory=dict)
    log: list[str] = field(default_factory=list)
    owner: dict[str, Any] = field(default_factory=dict, repr=False)
    _cancel: threading.Event = field(default_factory=threading.Event, repr=False)
    _committed: bool = field(default=False, repr=False)  # 되돌릴 수 없는 지점을 지남 → 이후 취소는 무시
    _thread: threading.Thread | None = field(default=None, repr=False)
    _t0: float = field(default_factory=time.monotonic, repr=False)

    def to_dict(self, include_log: int = 20, *, include_owner: bool = False) -> dict[str, Any]:
        out: dict[str, Any] = {
            "job_id": self.id,
            "kind": self.kind,
            "description": self.description,
            "server": self.server,
            "case_id": self.case_id,
            "status": self.status,
            "progress": None if self.progress is None else round(self.progress, 4),
            "done": self.done,
            "total": self.total,
            "message": self.message,
            "created_at": self.created_at,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "elapsed_seconds": round(time.monotonic() - self._t0, 1),
            "meta": self.meta,
        }
        if self.progress and self.status == "running" and self.progress > 0.001:
            elapsed = time.monotonic() - self._t0
            out["eta_seconds"] = round(elapsed * (1 - self.progress) / self.progress, 0)
        if self.result is not None:
            out["result"] = self.result
        if self.error is not None:
            out["error"] = self.error
        if include_log:
            out["log_tail"] = self.log[-include_log:]
        if include_owner:
            out["owner"] = self.owner
            return out
        return _public_record(out)


class JobContext:
    """작업 함수에 전달되는 핸들: 진행률 보고와 취소 확인."""

    def __init__(self, job: Job, manager: "JobManager") -> None:
        self.job = job
        self._mgr = manager
        self._last_persist = 0.0

    @property
    def cancelled(self) -> bool:
        return self.job._cancel.is_set()

    def check_cancelled(self) -> None:
        if self.job._cancel.is_set():
            raise JobCancelled()

    def progress(self, done: float, total: float | None = None, message: str | None = None) -> None:
        self.job.done = done
        if total is not None:
            self.job.total = total
        if self.job.total:
            self.job.progress = max(0.0, min(1.0, float(done) / float(self.job.total)))
        if message is not None:
            self.job.message = message
        now = time.monotonic()
        if now - self._last_persist > 1.0:
            self._last_persist = now
            self._mgr._persist(self.job)

    def log(self, message: str) -> None:
        self.job.log.append(f"{utcnow_iso()} {message}")
        if len(self.job.log) > 500:
            del self.job.log[:100]

    def update_meta(self, **kwargs: Any) -> None:
        self.job.meta.update(kwargs)

    def mark_committed(self) -> None:
        """되돌릴 수 없는 지점(예: 보관 기록에 커밋)을 지났다고 표시한다. 이 뒤에 온 취소 요청은 무시하고, 작업은 끝나면 succeeded 로 남는다
        (늦은 취소 = 이미 커밋된 결과). 커밋 직전에 온 취소도 지운다 — 작업은 그 앞의 check_cancelled() 에서 멈췄어야 했다."""
        with self._mgr._lock:
            self.job._committed = True
            self.job._cancel.clear()
            if self.job.status == "cancelling":
                self.job.status = "running"

    def set_partial(self, result: dict[str, Any]) -> None:
        """작업이 취소/실패로 끝나도 남길 부분 결과 (예: 지금까지 받은 청크 수, 찾은 핀아웃)."""
        self.job.meta["partial_result"] = result


class JobManager:
    def __init__(self, server: str, persist_dir: Callable[[Job], Path | None] | None = None, *,
                 owner_provider: Callable[..., dict[str, Any]] | None = None,
                 owner_probe: Callable[[Any], tuple[str, str]] | None = None) -> None:
        self.server = server
        self._jobs: dict[str, Job] = {}
        self._lock = threading.Lock()
        self._persist_dir = persist_dir
        self._owner_provider = owner_provider or procutil.owner_record
        self._owner_probe = owner_probe or _owner_state

    def _persist(self, job: Job) -> None:
        if self._persist_dir is None:
            return
        try:
            d = self._persist_dir(job)
            if d is not None:
                directory = Path(d)
                directory.parent.mkdir(parents=True, exist_ok=True)
                fd = safeio.open_dir_chain(directory.parent, [directory.name], create=True)
                try:
                    with safeio.locked_at(fd, ".jobs.lock", timeout=RECOVERY_SECONDS):
                        data = json.dumps(job.to_dict(include_log=50, include_owner=True), ensure_ascii=False).encode("utf-8")
                        safeio.atomic_write_at(fd, f"{job.id}.json", data)
                finally:
                    os.close(fd)
        except Exception:
            pass

    def start(
        self,
        kind: str,
        fn: Callable[[JobContext], dict[str, Any] | None],
        *,
        description: str,
        case_id: str | None = None,
        meta: dict[str, Any] | None = None,
        exclusive_key: str | None = None,
    ) -> Job:
        """fn(ctx) 를 백그라운드 스레드에서 실행. exclusive_key 가 같은 활성 작업이 있으면 거부."""
        with self._lock:
            if exclusive_key:
                for j in self._jobs.values():
                    if j.status in ACTIVE_STATES and j.meta.get("exclusive_key") == exclusive_key:
                        raise PwehError(
                            f"같은 리소스를 사용하는 작업이 이미 실행 중입니다: {j.id} ({j.description})",
                            code="busy",
                            hint=f"job_status 로 진행 상황을 확인하거나 job_cancel 로 취소하세요.",
                        )
            job = Job(id=new_id("job-", 4), kind=kind, description=description, server=self.server, case_id=case_id, meta=dict(meta or {}),
                      owner=self._owner_provider(self.server))
            if exclusive_key:
                job.meta["exclusive_key"] = exclusive_key
            self._jobs[job.id] = job
        ctx = JobContext(job, self)

        def runner() -> None:
            job.status = "running"
            job.started_at = utcnow_iso()
            job._t0 = time.monotonic()
            self._persist(job)
            try:
                result = fn(ctx)
                if job._cancel.is_set() and not job._committed:
                    job.status = "cancelled"
                    job.result = result if isinstance(result, dict) else None
                else:
                    job.status = "succeeded"
                    job.result = result if isinstance(result, dict) else {"value": result}
                    if job.total:
                        job.progress = 1.0
            except JobCancelled:
                job.status = "cancelled"
                job.message = job.message or "취소됨"
                if job.meta.get("partial_result") is not None:
                    job.result = job.meta["partial_result"]
            except PwehError as exc:
                job.status = "failed"
                job.error = exc.to_dict()
                if job.meta.get("partial_result") is not None:
                    job.result = job.meta["partial_result"]
            except Exception as exc:  # pragma: no cover - 예기치 못한 오류
                job.status = "failed"
                job.error = {"code": "internal_error", "message": f"{type(exc).__name__}: {exc}", "traceback": traceback.format_exc(limit=8)}
            finally:
                job.finished_at = utcnow_iso()
                self._persist(job)

        try:
            t = threading.Thread(target=runner, name=f"pweh-{job.id}", daemon=True)
            job._thread = t
            self._persist(job)
            t.start()
        except Exception:
            # 시작하지 못한 queued 항목이 exclusive_key를 영구 점유하지 않게 한다.
            # 이미 시작한 스레드는 호출자에게 예외가 돌아가도 등록을 유지한다.
            if job._thread is None or job._thread.ident is None:
                with self._lock:
                    if self._jobs.get(job.id) is job:
                        del self._jobs[job.id]
                job.status = "failed"
                job.finished_at = utcnow_iso()
                job.error = {"code": "job_start_failed", "message": "작업 스레드를 시작하지 못했습니다."}
                self._persist(job)
            raise
        return job

    def get(self, job_id: str) -> Job:
        job = self._jobs.get(job_id)
        if job is None:
            raise NotFound(f"작업을 찾을 수 없습니다: {job_id}", hint="앞 서버의 기록은 job_status/job 목록에 case_id를 지정해 조회하세요. 저장 기록은 취소하거나 재개할 수 없습니다.")
        return job

    def saved(self, case_dir: Path, case_id: str, *, job_id: str | None = None,
              active_only: bool = False) -> dict[str, Any]:
        """한 케이스의 이 서버 기록만 제한하여 확인한다. 저장 기록은 실행 큐에 넣지 않는다.

        소유 서버 종료가 확실한 활성 기록만 failed로 원자 갱신한다. 살아 있거나
        신원이 불완전하면 원본을 보존한다. 임의 파일/링크와 다른 케이스 기록은 거부한다.
        목록은 디렉터리 512항목·256작업·입력 8MiB·2초, 기록 하나는 1MiB가 상한이다.
        """
        if job_id is not None and not JOB_ID_RE.fullmatch(job_id):
            raise ValidationFailed("잘못된 job_id입니다.")
        if job_id is not None:
            local = self._jobs.get(job_id)
            if local is not None and local.case_id == case_id:
                return {"jobs": [local.to_dict()], "recovery": {"truncated": False, "reasons": []}}
        deadline = time.monotonic() + RECOVERY_SECONDS
        rows: list[dict[str, Any]] = []
        reasons: list[str] = []
        examined = total_bytes = 0
        try:
            fd = safeio.open_dir_chain(case_dir, ["jobs"])
        except FileNotFoundError:
            if job_id is not None:
                raise NotFound(f"저장된 작업을 찾을 수 없습니다: {job_id}") from None
            return {"jobs": [], "recovery": {"truncated": False, "reasons": []}}
        try:
            # 현재 기록자의 persist와 같은 잠금이다. 잠금을 얻은 뒤 다시 읽어 terminal 갱신을 보존한다.
            with safeio.locked_at(fd, ".jobs.lock", timeout=max(0.0, deadline - time.monotonic())):
                def visit(name: str) -> None:
                    nonlocal examined, total_bytes
                    if time.monotonic() >= deadline:
                        raise PwehError("작업 기록 확인 시간 상한", code="job_recovery_time")
                    if not name.endswith(".json") or not JOB_ID_RE.fullmatch(name[:-5]):
                        return
                    examined += 1
                    data = safeio.read_regular(name, dir_fd=fd, max_bytes=min(MAX_RECORD_BYTES, MAX_SCAN_BYTES - total_bytes), what="작업 기록")
                    total_bytes += len(data)
                    try:
                        record = json.loads(data)
                    except (ValueError, RecursionError) as exc:
                        raise ValidationFailed("작업 기록 JSON이 올바르지 않습니다.") from exc
                    if not isinstance(record, dict) or record.get("job_id") != name[:-5]:
                        raise ValidationFailed("작업 기록의 ID가 파일 이름과 다릅니다.")
                    if record.get("server") != self.server:
                        return
                    if record.get("case_id") != case_id or record.get("status") not in SAVED_STATES:
                        raise ValidationFailed("작업 기록의 케이스 또는 상태가 올바르지 않습니다.")
                    local = self._jobs.get(record["job_id"])
                    if local is not None and local.case_id == case_id:
                        public = local.to_dict()
                    else:
                        public = self._recover_record(fd, name, record, deadline)
                    if not active_only or public["status"] in ACTIVE_STATES:
                        rows.append(public)

                if job_id is not None:
                    try:
                        visit(job_id + ".json")
                    except FileNotFoundError:
                        raise NotFound(f"저장된 작업을 찾을 수 없습니다: {job_id}") from None
                    if not rows:
                        raise NotFound(f"이 서버의 저장된 작업을 찾을 수 없습니다: {job_id}")
                else:
                    with os.scandir(fd) as entries:
                        for count, entry in enumerate(entries):
                            if count >= MAX_SCAN_ENTRIES or examined >= MAX_SAVED_JOBS or total_bytes >= MAX_SCAN_BYTES:
                                reasons.append("scan_limit")
                                break
                            if time.monotonic() >= deadline:
                                reasons.append("time_limit")
                                break
                            try:
                                visit(entry.name)
                            except (OSError, PwehError, ValueError, RecursionError):
                                # 건너뛴 기록은 완료로 표시하지 않고 목록의 불완전성을 알린다.
                                if "record_unreadable" not in reasons:
                                    reasons.append("record_unreadable")
                    rows.sort(key=lambda row: str(row.get("created_at", "")))
        finally:
            os.close(fd)
        return {"jobs": rows, "recovery": {"truncated": bool(reasons), "reasons": reasons,
                                            "examined": examined, "bytes_read": total_bytes}}

    def _recover_record(self, fd: int, name: str, record: dict[str, Any], deadline: float) -> dict[str, Any]:
        """저장 스냅샷의 소유 신원을 확인한다. 파일/기기/외부 자식의 정리는 주장하지 않는다."""
        public = _public_record(record)
        if record["status"] not in ACTIVE_STATES:
            return public
        owner = record.get("owner")
        if not isinstance(owner, dict) or owner.get("server") != self.server:
            state, reason = "unknown", "owner_missing_or_invalid"
        else:
            state, reason = self._owner_probe(owner)
        if time.monotonic() >= deadline:
            raise PwehError("작업 기록 확인 시간 상한", code="job_recovery_time")
        assessment = {"owner_state": state, "reason": reason, "resumable": False,
                      "note": "저장 기록은 재개/취소할 수 없습니다. 파일·기기·외부 자식의 정리 여부는 이 확인으로 알 수 없습니다."}
        if state == "terminated":
            record["recovery"] = {**assessment, "previous_status": record["status"], "checked_at": utcnow_iso(),
                                  "finished_at_basis": "recovery_observation"}
            record["status"] = "failed"
            record["finished_at"] = record.get("finished_at") or utcnow_iso()
            record["error"] = {"code": "job_owner_terminated", "message": "소유 서버가 종료되어 작업 완료 여부를 확인할 수 없습니다."}
            record["message"] = "소유 서버 종료로 중단된 작업 기록입니다. 결과 파일과 보관 기록을 별도로 확인하세요."
            record.pop("eta_seconds", None)
            safeio.atomic_write_at(fd, name, json.dumps(record, ensure_ascii=False).encode("utf-8"))
            public = _public_record(record)
        else:
            public["recovery"] = assessment
            public.pop("eta_seconds", None)
        return public

    def list(self, active_only: bool = False) -> list[dict[str, Any]]:
        jobs = sorted(self._jobs.values(), key=lambda j: j.created_at)
        return [j.to_dict(include_log=0) for j in jobs if not active_only or j.status in ACTIVE_STATES]

    def cancel(self, job_id: str) -> Job:
        """취소 요청. 이미 끝났거나 되돌릴 수 없는 지점을 지난(mark_committed) 작업은 그대로 둔다."""
        job = self.get(job_id)
        with self._lock:
            if job.status not in ACTIVE_STATES or job._committed:
                return job
            job._cancel.set()
            job.status = "cancelling"
        self._persist(job)
        return job

    def wait(self, job_id: str, timeout: float | None = None) -> Job:
        job = self.get(job_id)
        if job._thread is not None:
            job._thread.join(timeout)
        return job

    def shutdown(self, timeout: float = 5.0) -> None:
        for job in list(self._jobs.values()):
            if job.status in ACTIVE_STATES:
                job._cancel.set()
        for job in list(self._jobs.values()):
            if job._thread is not None:
                job._thread.join(timeout)
