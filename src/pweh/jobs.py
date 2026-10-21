"""백그라운드 작업(Job) 관리.

UART md.b 덤프(16MiB @115200 ≈ 수 시간), Ghidra 분석, 긴 로직 캡처처럼 오래 걸리는 작업은
MCP 클라이언트의 도구 호출 타임아웃(예: Codex 기본 60초)을 넘기므로 즉시 job_id 를 돌려주고
에이전트가 ``<prefix>_job_status`` 로 폴링하게 한다.

작업 상태는 케이스 디렉터리의 ``jobs/<job_id>.json`` 에도 기록되어 서버가 재시작되어도 흔적이 남는다.
"""

from __future__ import annotations

import threading
import time
import traceback
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from .errors import NotFound, PwehError
from .fsutil import atomic_write_json, new_id, utcnow_iso

ACTIVE_STATES = ("queued", "running", "cancelling")


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
    _cancel: threading.Event = field(default_factory=threading.Event, repr=False)
    _committed: bool = field(default=False, repr=False)  # 되돌릴 수 없는 지점을 지남 → 이후 취소는 무시
    _thread: threading.Thread | None = field(default=None, repr=False)
    _t0: float = field(default_factory=time.monotonic, repr=False)

    def to_dict(self, include_log: int = 20) -> dict[str, Any]:
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
        return out


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
    def __init__(self, server: str, persist_dir: Callable[[Job], Path | None] | None = None) -> None:
        self.server = server
        self._jobs: dict[str, Job] = {}
        self._lock = threading.Lock()
        self._persist_dir = persist_dir

    def _persist(self, job: Job) -> None:
        if self._persist_dir is None:
            return
        try:
            d = self._persist_dir(job)
            if d is not None:
                atomic_write_json(Path(d) / f"{job.id}.json", job.to_dict(include_log=50))
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
            job = Job(id=new_id("job-", 4), kind=kind, description=description, server=self.server, case_id=case_id, meta=dict(meta or {}))
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

        t = threading.Thread(target=runner, name=f"pweh-{job.id}", daemon=True)
        job._thread = t
        t.start()
        return job

    def get(self, job_id: str) -> Job:
        job = self._jobs.get(job_id)
        if job is None:
            raise NotFound(f"작업을 찾을 수 없습니다: {job_id}", hint="이 서버 프로세스에서 시작한 작업만 조회할 수 있습니다 (서버 재시작 시 cases/<id>/jobs/ 의 기록 확인).")
        return job

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
