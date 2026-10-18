"""MCP 서버 공통 헬퍼 (공식 MCP Python SDK 2.x, ``mcp.server.mcpserver.MCPServer``).

규칙 (모든 PWEH 서버 공통):
- 도구는 ``@server.tool(...)`` + ``@safe_tool`` 로 등록한다. safe_tool 은 PwehError 를 ToolError 로 바꿔
  에이전트가 오류 메시지/힌트를 볼 수 있게 한다 (SDK 2.x 는 일반 예외 메시지를 숨긴다).
- 기기에 영향을 주는 도구는 async 로 작성하고 ``Context`` 를 받아 ``rt.authorize(...)`` 를 먼저 호출한다.
  블로킹 I/O(pyserial, 소켓, subprocess)는 ``run_blocking`` 으로 스레드에서 실행한다.
- 안전 게이트가 허용하지 않으면 ``gate_response(decision)`` 를 그대로 반환한다 (ok=false, status, approval_id).
- 오래 걸리는 작업은 ``rt.jobs.start(...)`` 로 시작하고 ``register_job_tools`` 가 만든
  ``<prefix>_job_status`` / ``<prefix>_job_cancel`` / ``<prefix>_jobs`` 로 폴링한다.
"""

from __future__ import annotations

import functools
import inspect
import logging
import sys
from typing import Any, Callable, TypeVar

import anyio
import anyio.to_thread
from mcp.server.mcpserver import Context, MCPServer
from mcp.server.mcpserver.exceptions import ToolError
from mcp.types import ToolAnnotations

from . import __version__
from .errors import PwehError
from .safety import GateDecision

log = logging.getLogger("pweh.mcp")

# 도구 어노테이션 프리셋 (클라이언트 UI 힌트일 뿐, 실제 차단은 서버 측 게이트가 한다)
ANN_READ_ONLY = ToolAnnotations(read_only_hint=True, destructive_hint=False, idempotent_hint=True, open_world_hint=False)
ANN_LOCAL_WRITE = ToolAnnotations(read_only_hint=False, destructive_hint=False, idempotent_hint=False, open_world_hint=False)
ANN_DEVICE = ToolAnnotations(read_only_hint=False, destructive_hint=False, idempotent_hint=False, open_world_hint=True)
ANN_DESTRUCTIVE = ToolAnnotations(read_only_hint=False, destructive_hint=True, idempotent_hint=False, open_world_hint=True)

# Claude Code 전용 보조 안전장치: 이 메타가 붙은 도구는 bypassPermissions 모드에서도 매 호출 사람 확인을 띄운다.
# 항상 파괴적인 도구(플래시 쓰기, 임의 메모리 쓰기, 전압 설정)에만 붙인다. 주 안전장치는 서버 측 게이트다.
META_REQUIRE_HUMAN: dict[str, Any] = {"anthropic/requiresUserInteraction": True}
# 큰 텍스트(디컴파일/로그 발췌)를 돌려주는 조회 도구용: Claude Code 가 파일로 빼는 임계값(기본 5만 자)을 올린다.
META_LARGE_OUTPUT: dict[str, Any] = {"anthropic/maxResultSizeChars": 200000}

F = TypeVar("F", bound=Callable[..., Any])

SAFETY_NOTICE = (
    "본인이 소유하거나 서면 허가를 받은 기기만 분석한다. 기기에 영향을 주는 모든 작업은 서버 측 안전 게이트를 거치며, "
    "응답의 status 가 approval_required 이면 사용자에게 설명하고 사람이 별도 터미널에서 `pweh approve <id>` 로 승인한 뒤에만 "
    "approval_id 를 붙여 재시도한다. denied 이면 우회하지 말고 사용자에게 보고한다."
)


def create_server(name: str, *, instructions: str, title: str | None = None, lifespan: Any = None) -> MCPServer:
    """PWEH 표준 MCP 서버 생성. lifespan 은 MCPServer 의 lifespan(async context manager factory) 그대로 전달."""
    _configure_logging()
    kwargs: dict[str, Any] = {}
    if lifespan is not None:
        kwargs["lifespan"] = lifespan
    return MCPServer(
        name=name,
        title=title,
        instructions=f"{instructions}\n\n[안전] {SAFETY_NOTICE}",
        version=__version__,
        log_level="WARNING",
        **kwargs,
    )


def _configure_logging() -> None:
    # stdio 서버는 stdout 이 프로토콜 채널이므로 로그는 반드시 stderr 로
    root = logging.getLogger("pweh")
    if not root.handlers:
        h = logging.StreamHandler(sys.stderr)
        h.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s"))
        root.addHandler(h)
        root.setLevel(logging.INFO)
        # MCP SDK 가 루트 로거에 핸들러를 달기 때문에 전파하면 같은 줄이 stderr 에 두 번 찍힌다
        root.propagate = False


def _convert(exc: BaseException) -> ToolError:
    if isinstance(exc, ToolError):
        return exc
    if isinstance(exc, PwehError):
        return ToolError(str(exc))
    log.exception("unexpected tool error")
    return ToolError(f"[internal_error] {type(exc).__name__}: {exc}")


def safe_tool(fn: F) -> F:
    """도구 함수 래퍼: 예외를 에이전트가 읽을 수 있는 ToolError 로 변환."""
    if inspect.iscoroutinefunction(fn):

        @functools.wraps(fn)
        async def awrapper(*args: Any, **kwargs: Any) -> Any:
            try:
                return await fn(*args, **kwargs)
            except anyio.get_cancelled_exc_class():
                raise
            except BaseException as exc:  # noqa: BLE001
                if isinstance(exc, (KeyboardInterrupt, SystemExit)):
                    raise
                raise _convert(exc) from exc

        return awrapper  # type: ignore[return-value]

    @functools.wraps(fn)
    def wrapper(*args: Any, **kwargs: Any) -> Any:
        try:
            return fn(*args, **kwargs)
        except BaseException as exc:  # noqa: BLE001
            if isinstance(exc, (KeyboardInterrupt, SystemExit)):
                raise
            raise _convert(exc) from exc

    return wrapper  # type: ignore[return-value]


async def run_blocking(fn: Callable[..., Any], *args: Any, **kwargs: Any) -> Any:
    """블로킹 함수를 워커 스레드에서 실행 (이벤트 루프를 막지 않게)."""
    return await anyio.to_thread.run_sync(functools.partial(fn, *args, **kwargs))


async def run_blocking_cancellable(fn: Callable[..., Any], *args: Any, on_cancel: Callable[[], None] | None = None, **kwargs: Any) -> Any:
    """취소 가능한 run_blocking.

    MCP 요청이 취소되면 즉시 반환하고(스레드는 버림) on_cancel() 을 호출한다.
    on_cancel 에서 Event 를 set 하거나 외부 프로세스 그룹을 종료해 워커가 스스로 끝나게 해야 한다.
    """
    try:
        return await anyio.to_thread.run_sync(functools.partial(fn, *args, **kwargs), abandon_on_cancel=True)
    except anyio.get_cancelled_exc_class():
        if on_cancel is not None:
            try:
                on_cancel()
            except Exception:  # pragma: no cover
                log.exception("on_cancel failed")
        raise


def gate_response(decision: GateDecision, **extra: Any) -> dict[str, Any]:
    """안전 게이트가 허용하지 않았을 때의 표준 응답."""
    out = {"ok": False, "gate": decision.to_dict(), "status": decision.status}
    if decision.approval_id:
        out["approval_id"] = decision.approval_id
    if decision.message:
        out["message"] = decision.message
    out.update(extra)
    return out


def register_job_tools(server: MCPServer, runtime_getter: Callable[[], Any], prefix: str) -> None:
    """``<prefix>_job_status``, ``<prefix>_job_cancel``, ``<prefix>_jobs`` 도구 등록."""

    @server.tool(
        name=f"{prefix}_job_status",
        description=(
            "백그라운드 작업 상태 조회. status(queued|running|cancelling|succeeded|failed|cancelled), "
            "progress(0~1), eta_seconds, message, result/error, 최근 로그를 반환한다. "
            "wait_seconds>0 이면 최대 그 시간만큼 완료를 기다린다(최대 50초)."
        ),
        annotations=ANN_READ_ONLY,
    )
    @safe_tool
    async def job_status(job_id: str, wait_seconds: float = 0.0) -> dict[str, Any]:
        rt = runtime_getter()
        job = rt.jobs.get(job_id)
        wait = max(0.0, min(float(wait_seconds), 50.0))
        if wait and job.status in ("queued", "running", "cancelling"):
            await run_blocking(rt.jobs.wait, job_id, wait)
        return {"ok": True, **rt.jobs.get(job_id).to_dict()}

    @server.tool(
        name=f"{prefix}_job_cancel",
        description="실행 중인 백그라운드 작업 취소 요청. 작업은 다음 안전 지점에서 멈추고, 부분 결과는 보존된다.",
        annotations=ANN_LOCAL_WRITE,
    )
    @safe_tool
    async def job_cancel(job_id: str) -> dict[str, Any]:
        rt = runtime_getter()
        job = rt.jobs.cancel(job_id)
        rt.audit({"event": "job_cancel_requested", "job_id": job_id}, job.case_id)
        return {"ok": True, **job.to_dict(include_log=5)}

    @server.tool(
        name=f"{prefix}_jobs",
        description="이 서버 프로세스의 백그라운드 작업 목록.",
        annotations=ANN_READ_ONLY,
    )
    @safe_tool
    def jobs(active_only: bool = False) -> dict[str, Any]:
        rt = runtime_getter()
        return {"ok": True, "jobs": rt.jobs.list(active_only=active_only)}


__all__ = [
    "ANN_DESTRUCTIVE",
    "ANN_DEVICE",
    "ANN_LOCAL_WRITE",
    "ANN_READ_ONLY",
    "Context",
    "META_LARGE_OUTPUT",
    "META_REQUIRE_HUMAN",
    "MCPServer",
    "SAFETY_NOTICE",
    "ToolError",
    "create_server",
    "gate_response",
    "register_job_tools",
    "run_blocking",
    "run_blocking_cancellable",
    "safe_tool",
]
