"""sigrok-mcp: 로직 애널라이저(sigrok-cli) MCP 서버.

REA 의 ``decode_signal_recording`` / ``inspect_signal_decoders`` 가 이미 녹화 파일 디코딩을 제공하므로,
이 서버는 REA 에 없는 것을 더한다:

- 장치 스캔/정보, **캡처(acquisition)** → ``cases/<id>/signals/<name>.sr`` + 아티팩트 등록
- 형식 변환(sigrok_export), 디코딩 래퍼(sigrok_decode: 결과를 파일로 저장하고 미리보기 반환)
- 순수 Python srzip/VCD 리더 기반 **오프라인 보드레이트 추정**(sigrok_estimate_baud)과 UART 자동 디코드

안전:
- 캡처/스캔처럼 장치를 건드리는 도구는 케이스 소유/허가 증명(hardware=True)을 요구하고, 실행할 argv 를
  ``policy.classify_sigrok_argv`` 로 분류한 뒤 ``rt().authorize`` 를 거친다.
- 출력(구동) 가능 장치(전원공급기·전자부하·신호발생기·릴레이), 허용 목록 밖 드라이버, 출력을 바꾸는 config 키,
  ``--set``/``--continuous`` 등은 게이트에 넘기지 않고 **무조건 거부**한다 (approve 정책으로도 승인 불가).
- 백그라운드 캡처 작업은 프로세스를 띄우기 직전에 같은 분류기로 argv 를 다시 검사한다.
"""

from __future__ import annotations

import functools
import logging
import math
import os
import re
import shutil
import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

import anyio
import anyio.to_thread

from pweh.case import Case
from pweh.errors import Busy, CaseError, NotFound, PwehError, SafetyDenied, TimeoutExpired, ToolMissing, ValidationFailed
from pweh.fsutil import utcnow_iso
from pweh.mcpkit import (
    ANN_DEVICE,
    ANN_LOCAL_WRITE,
    ANN_READ_ONLY,
    Context,
    create_server,
    gate_response,
    register_job_tools,
    safe_tool,
)
from pweh.runtime import Runtime, get_runtime
from pweh.instrument_guard import guard_target_port
from pweh.safety import Classification, GateDecision, Risk
from pweh import hostenv, ports, portlock, procutil

from . import baud as baudmod
from . import cli as cli_runner
from . import signals as sig
from .cli import (
    CliResult,
    SigrokCli,
    check_result,
    child_env,
    parse_annotation_line,
    parse_device_show,
    parse_scan,
    run_process,
    stderr_problems,
    tail_text,
)
from .policy import (
    ChannelSelection,
    DriverPolicy,
    classify_sigrok_argv,
    conn_kind,
    device_users,
    parse_samplerate,
    validate_capture_ratio,
    validate_channels,
    validate_conn,
    validate_driver,
    validate_duration_ms,
    validate_output_name,
    validate_samples,
    validate_triggers,
)

SERVER_NAME = "sigrok-mcp"
PRODUCER = "sigrok-mcp"
log = logging.getLogger("pweh.sigrok")

server = create_server(
    SERVER_NAME,
    title="PWEH Logic Analyzer (sigrok)",
    instructions=(
        "로직 애널라이저(sigrok-cli) 서버. 순서: sigrok_version → sigrok_scan(장치 확인) → 사람이 프로브 연결(GND 먼저, "
        "전압 레벨 확인) → sigrok_capture(case_id, driver, samplerate, duration_ms|samples) → sigrok_file_info(채널별 활동) → "
        "sigrok_estimate_baud(UART 보드레이트·idle 극성) → sigrok_uart_autodecode 또는 sigrok_decode(임의 디코더 스택). "
        "보드레이트 미상이면 첫 캡처는 8 MHz 이상으로. 부트 로그는 캡처를 먼저 시작한 뒤 사람이 전원을 넣는다. "
        "긴 캡처/트리거 캡처는 job 으로 실행되므로 sigrok_job_status 로 폴링한다. 결과 파일은 cases/<id>/signals/ 에 저장되고 "
        "아티팩트로 등록된다. Skill 요약은 schema signal-capture 형식으로 case_record_step 에 기록한다. "
        "전원공급기·전자부하·신호발생기·릴레이 등 출력 장치는 이 서버가 다루지 않는다(거부됨)."
    ),
)


def rt() -> Runtime:
    return get_runtime(SERVER_NAME)


def _port_environment() -> dict[str, Any]:
    return hostenv.detect(smoke=False, config=rt().config)


def _port_probe() -> ports.PortProbe:
    return ports.PortProbe()


_ORPHAN_PORTS: list["_SerialUse"] = []
_ORPHAN_LOCK = threading.Lock()


class _SerialUse:
    """명시 serial conn의 gate/worker 수명. 외부 실행 전에 tty를 따로 열지 않는다."""

    def __init__(self, case_id: str, conn: str):
        self.runtime = rt()
        self.route = ports.resolve(_port_environment(), conn, "sigrok-serial", probe=_port_probe(), config=self.runtime.config)
        self.whole = self.route.reset_risk == "wired"
        self.keys = ports.reset_scope(self.route, whole_device=self.whole, config=self.runtime.config)
        with _ORPHAN_LOCK:
            for old in list(_ORPHAN_PORTS):
                if old.lease.closed:
                    _ORPHAN_PORTS.remove(old)
                elif set(old.keys) & set(self.keys) and old.result is not None:
                    if (procutil.process_group_empty(old.result.pid, expect_start_ticks=old.result.start_ticks) is True
                            and cli_runner.cleanup_owned(old.result.pid, process_token=old.result.process_token)):
                        old.lease.close()
                        _ORPHAN_PORTS.remove(old)
        self.lease = portlock.get_manager().acquire(self.keys, owner=portlock.PortOwner(
            server=SERVER_NAME, case_id=case_id, ref=conn, role="bridge"))
        self.handoff = portlock.LeaseHandoff()
        self.accepted = False
        self.unverified = False
        self.result: CliResult | None = None

    def fresh(self) -> None:
        fresh = ports.revalidate(self.route, env=_port_environment(), probe=_port_probe(), config=self.runtime.config)
        keys = ports.reset_scope(fresh, whole_device=self.whole, config=self.runtime.config)
        if keys != self.keys:
            raise PwehError("승인 뒤 직렬 장치 범위가 바뀌었습니다.", code="route_changed")
        self.lease.assert_held(keys)
        portlock.get_role_store().assert_probe_allowed(fresh)

    def finish(self) -> None:
        if self.unverified:
            self.lease.set_state("orphan")
            with _ORPHAN_LOCK:
                if self not in _ORPHAN_PORTS:
                    _ORPHAN_PORTS.append(self)
        else:
            self.lease.close()


def _serial_use(case_id: str | None, conn: str | None) -> _SerialUse | None:
    if conn_kind(conn) != "serial":
        return None
    if not case_id:
        raise ValidationFailed("serial conn에는 case_id가 필요합니다.")
    case = rt().case(case_id, hardware=True)
    return _SerialUse(case.id, conn)


def _port_classification(use: _SerialUse | None, action: dict[str, Any], cls: Classification) -> Classification:
    if use is not None:
        action["route"] = use.route.approval_identity()
        portlock.get_role_store().assert_probe_allowed(use.route)
        use.lease.set_state("awaiting_approval")
        if use.route.reset_risk == "wired":
            return Classification(Risk.MODIFY, "serial.reset-wired", "내장 USB 직렬 장치를 열면 칩이 리셋될 수 있습니다.")
    return cls


def _port_run(use: _SerialUse | None, argv: list[str], **kwargs: Any) -> CliResult:
    if use is None:
        return run_process(argv, **kwargs)
    use.fresh()
    use.lease.set_state("running")
    use.unverified = True
    state: dict[str, Any] = {}
    try:
        result = run_process(argv, process_state=state, **kwargs)
    except BaseException:
        verified = not state
        if state:
            try:
                verified = cli_runner.cleanup_owned(state["pid"], process_token=state.get("process_token"))
            except Exception:
                verified = False
        use.unverified = not verified
        if not verified:
            use.result = CliResult([], None, b"", "", pid=state.get("pid"), start_ticks=state.get("start_ticks"), process_token=state.get("process_token"),
                                   cleanup_verified=False)
        raise
    use.result = result
    use.unverified = not result.cleanup_verified
    if use.unverified:
        check_result(result, "sigrok serial 실행")
    return result


def _port_worker(use: _SerialUse | None, work: Callable, finish: Callable, cancel_event: threading.Event) -> dict[str, Any]:
    if use is not None and not use.handoff.claim_worker():
        return {"ok": False, "status": "cancelled"}
    try:
        if cancel_event.is_set():
            return {"ok": False, "status": "cancelled"}
        result = finish(work(cancel_event))
        if use is not None:
            result["route"] = use.route.to_dict()
        return result
    finally:
        if use is not None:
            use.finish()


def _cli() -> SigrokCli:
    return SigrokCli.from_config(rt().config.tool_path("sigrok_cli"))


def _policy() -> DriverPolicy:
    return DriverPolicy.from_config_raw(rt().config.raw)


def _sigrok_cfg(key: str, default: Any) -> Any:
    sec = rt().config.raw.get("sigrok") or {}
    return sec.get(key, default) if isinstance(sec, dict) else default


SYNC_CAPTURE_LIMIT_S = 20.0
MAX_TIMEOUT_S = 6 * 3600.0
DECODE_SYNC_TIMEOUT_S = 55.0  # 일부 클라이언트(Codex/Cursor) 기본 도구 타임아웃 60초 고려
MAX_DECODE_OUTPUT = 512 * 1024 * 1024
LOGIC_ONLY_OUTPUTS = {"vcd", "bits", "hex", "ascii", "binary", "ols", "chronovu-la8", "wavedrom"}
OUTPUT_EXT = {"vcd": ".vcd", "srzip": ".sr", "csv": ".csv", "bits": ".bits.txt", "hex": ".hex.txt", "ascii": ".ascii.txt",
              "binary": ".bin", "wav": ".wav", "ols": ".ols", "chronovu-la8": ".kdt", "wavedrom": ".wavedrom.json",
              "analog": ".analog.txt"}
DECODER_ID_RE = re.compile(r"^[a-z0-9_]{1,40}$")
PD_KEY_RE = re.compile(r"^[a-z0-9_]{1,40}$")
PD_VAL_RE = re.compile(r"^[\x21-\x7e]{1,128}$")
FMT_ID_RE = re.compile(r"^[a-z0-9_-]{1,32}$")

_DEVICE_LOCKS: dict[str, threading.Lock] = {}
_DEVICE_LOCKS_GUARD = threading.Lock()


def _device_key(driver: str, conn: str | None) -> str:
    return f"sigrok-device:{driver}:{conn or 'auto'}"


def _device_lock(key: str) -> threading.Lock:
    with _DEVICE_LOCKS_GUARD:
        lk = _DEVICE_LOCKS.get(key)
        if lk is None:
            lk = _DEVICE_LOCKS[key] = threading.Lock()
        return lk


async def _acquire_port_use(factory: Callable[..., Any], *args: Any) -> Any:
    """raw Task.cancel로 thread 반환값을 잃어도 생성된 lease를 정확히 한 번 회수한다."""
    lock = threading.Lock()
    state: dict[str, Any] = {"cancelled": False, "use": None}

    def create() -> Any:
        use = factory(*args)
        with lock:
            if state["cancelled"]:
                if use is not None:
                    use.finish()
                return None
            state["use"] = use
        return use

    try:
        return await _offload(create)
    except BaseException:
        with lock:
            state["cancelled"] = True
            use, state["use"] = state["use"], None
            if use is not None:
                use.finish()
        raise


async def _run_cancellable(fn: Callable[..., Any], *args: Any, **kwargs: Any) -> Any:
    """블로킹 함수를 워커 스레드에서 실행. 요청이 취소되면 cancel 이벤트를 세워 하위 프로세스를 종료시킨다."""
    ev = threading.Event()
    try:
        return await anyio.to_thread.run_sync(functools.partial(fn, *args, cancel_event=ev, **kwargs), abandon_on_cancel=True)
    except anyio.get_cancelled_exc_class():
        ev.set()
        raise


async def _offload(fn: Callable[..., Any], *args: Any, **kwargs: Any) -> Any:
    return await anyio.to_thread.run_sync(functools.partial(fn, *args, **kwargs))


# ---------------------------------------------------------------------------
# 공통 헬퍼
# ---------------------------------------------------------------------------


def _policy_denied(tool: str, action: dict[str, Any], cls: Classification, case_id: str | None) -> dict[str, Any]:
    """정책상 무조건 거부 (게이트/승인 경로 없음). 감사 로그에 남긴다."""
    msg = (
        f"안전 정책에 의해 거부됨: {cls.reason} (규칙={cls.rule_id}). 이 서버는 로직 애널라이저/오실로스코프의 입력 전용 캡처만 "
        "수행하며 출력 장치 제어·장치 설정 변경은 범위 밖이다. 우회하지 말고 사용자에게 보고하라. 허용 목록 밖의 측정 전용 "
        "로직 애널라이저라면 사람(운영자)이 pipeline-config.yaml 의 sigrok.capture_drivers_allow 에 추가할 수 있다 "
        "(출력 가능 장치는 추가해도 거부된다)."
    )
    decision = GateDecision(False, "denied", cls, "deny", via="sigrok-policy", message=msg)
    try:
        rt().audit({"event": "safety_decision", "tool": tool, "action": action, **decision.to_dict()}, case_id)
    except Exception:  # pragma: no cover - 감사 실패가 거부를 막지 않게
        log.exception("audit failed")
    return gate_response(decision)


def _resolve_input(case: Case, input_path: str) -> Path:
    if not input_path or not str(input_path).strip():
        raise ValidationFailed("input_path 가 필요합니다.")
    p = case.resolve_path(str(input_path).strip())
    if not p.exists() and not Path(input_path).is_absolute() and not str(input_path).startswith("signals"):
        alt = case.path("signals", str(input_path).strip())
        if alt.exists():
            p = alt
    if not p.is_file():
        raise NotFound(
            f"입력 파일이 없습니다: {input_path}",
            hint="케이스 상대 경로(예: signals/capture-fx2lafw-001.sr)를 사용하라. case_get(include_artifacts=true) 로 확인.",
        )
    from pweh.evidence import EMU_REFUSAL_HINT, EMU_REFUSAL_MESSAGE, under_any_case_protected

    # 케이스의 보호 폴더는 자동 허용 도구가 읽지 않는다(링크를 풀어 판단): 에뮬레이터 세션 파일(마스킹하지 않은 원시 콘솔)은 emu_read 로만,
    # 카드 이미지·복구한 녹화는 pweh-forensics 로만
    hit = under_any_case_protected(p, rt().config.cases_dir)
    if hit == "emu":
        raise ValidationFailed(EMU_REFUSAL_MESSAGE, hint=EMU_REFUSAL_HINT)
    if hit is not None:
        raise ValidationFailed("케이스의 증거 폴더(forensics/)에 있는 파일은 읽지 않습니다.",
                               hint="sigrok 입력은 signals/ 의 캡처 파일이다. 카드 이미지는 pweh-forensics 도구로만 다룬다.")
    return p


def _safe_stem(text: str, maxlen: int = 60) -> str:
    s = re.sub(r"[^A-Za-z0-9._-]+", "-", text).strip("-.")
    return (s or "out")[:maxlen]


def _unique_path(directory: Path, stem: str, ext: str) -> Path:
    """존재하지 않는 경로를 골라 빈 파일로 선점(O_EXCL)해서 돌려준다 (동시 실행 이름 충돌 방지)."""
    stem = _safe_stem(stem)
    for n in range(1, 100000):
        p = directory / (f"{stem}{ext}" if n == 1 else f"{stem}-{n:03d}{ext}")
        if _reserve(p):
            return p
    raise CaseError(f"출력 파일 이름을 만들 수 없습니다: {stem}{ext}")


def _reserve_named(directory: Path, name: str, ext: str) -> Path:
    p = directory / f"{name}{ext}"
    if not _reserve(p):
        raise CaseError(f"이미 같은 이름의 파일이 있습니다: signals/{p.name}", hint="다른 output_name 을 쓰거나 생략하라 (덮어쓰지 않음).")
    return p


def _reserve(path: Path) -> bool:
    try:
        fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o644)
    except FileExistsError:
        return False
    os.close(fd)
    return True


def _reserve_capture_paths(sig_dir: Path, name: str | None, driver: str) -> tuple[Path, Path]:
    """최종 경로와 임시 경로(.<stem>.partial.sr)를 정하고 임시 파일을 O_EXCL 로 선점한다 (동시 캡처 이름 충돌 방지).

    sigrok-cli 의 srzip 출력은 파일을 먼저 지우고 새로 만들므로 빈 선점 파일은 그대로 넘겨도 된다.
    """
    if name:
        final = sig_dir / f"{name}.sr"
        if final.exists():
            raise CaseError(f"이미 같은 이름의 캡처가 있습니다: signals/{final.name}",
                            hint="다른 output_name 을 쓰거나 생략(자동 번호)하라. 기존 증거는 덮어쓰지 않는다.")
        part = sig_dir / f".{name}.partial.sr"
        if not _reserve(part):
            raise Busy(f"같은 이름({name})의 캡처가 진행 중이거나 비정상 종료로 임시 파일이 남아 있습니다: signals/{part.name}",
                       hint="다른 output_name 을 쓰거나 sigrok_jobs 로 진행 중인 캡처를 확인하라.")
        return final, part
    prefix = _safe_stem(f"capture-{driver}")
    for n in range(1, 100000):
        final = sig_dir / f"{prefix}-{n:03d}.sr"
        if final.exists():
            continue
        part = sig_dir / f".{final.stem}.partial.sr"
        if _reserve(part):
            return final, part
    raise CaseError(f"출력 파일 이름을 만들 수 없습니다: {prefix}")


def _clamp_timeout(value: Any, default: float, minimum: float = 1.0) -> float:
    if value is None:
        return default
    try:
        v = float(value)
    except (TypeError, ValueError):
        raise ValidationFailed(f"timeout_s 는 숫자여야 합니다: {value!r}")
    if not math.isfinite(v) or v < minimum:
        raise ValidationFailed(f"timeout_s 는 {minimum}초 이상이어야 합니다: {value!r}")
    return min(v, MAX_TIMEOUT_S)


def _display_argv(argv: list[str]) -> list[str]:
    return ["sigrok-cli", *argv[1:]]


# ---------------------------------------------------------------------------
# 정보 조회
# ---------------------------------------------------------------------------


@server.tool(
    description=("sigrok-cli / libsigrok / libsigrokdecode 버전, 실행 파일 경로, 지원 드라이버·디코더 수. "
        "backend 기본 linux; windows는 등록 번들·WSL interop의 무장치 정보 조회만 사용하며 Linux로 대체하지 않는다. "
        "Windows 버전 확인 뒤 목록에 decoder 로드 오류만 있으면 status=partial, counts=null이며 원시 traceback은 반환하지 않는다. "
        "정리·취소·시간·출력 상한 실패는 partial로 바꾸지 않는다. Linux sigrok-cli가 없으면 tool_missing 오류."),
    annotations=ANN_READ_ONLY,
)
@safe_tool
async def sigrok_version(backend: str = "linux") -> dict[str, Any]:
    if backend not in ("linux", "windows"):
        raise ValidationFailed("backend는 linux 또는 windows여야 합니다.")
    if backend == "windows":
        from .windows_info import run_info
        return await _run_cancellable(run_info, "version", rt().config)
    cli = _cli()
    info = await _offload(cli.version)
    out: dict[str, Any] = {"ok": True, "path": cli.path}
    out.update({k: v for k, v in info.items() if k != "raw"})
    try:
        sup = await _offload(cli.supported)
        out["counts"] = {k: len(v) for k, v in sup.items()}
    except PwehError as exc:
        out["counts"] = None
        out["warnings"] = [f"-L 목록 조회 실패: {exc}"]
    ver = info.get("sigrok_cli") or ""
    if ver and tuple(int(x) for x in re.findall(r"\d+", ver)[:3]) < (0, 7, 2):
        out.setdefault("warnings", []).append("sigrok-cli 0.7.2 미만: -A 행(row) 이름 지정/jsontrace 미지원")
    srd = (info.get("libsigrokdecode") or {}).get("version") or ""
    if srd and srd != "0.5.3":
        out.setdefault("warnings", []).append(
            f"libsigrokdecode {srd}: 디코더 annotation/옵션 이름이 0.5.3 과 다를 수 있음 → sigrok_decoder_help 로 확인")
    return out


@server.tool(
    description=(
        "sigrok 지원 목록. kind: drivers | decoders | input-formats | output-formats | transforms | all. "
        "query 로 id/설명 부분 문자열 필터. drivers 에는 이 서버의 캡처 정책(capture_allowed, output_capable, reason)이 붙는다. "
        "backend 기본 linux; windows는 등록 번들·WSL interop의 지원 목록 정보만 조회한다(COM/USB/캡처 미지원). "
        "Windows decoder 로드 오류는 kind와 관계없이 고정 오류이며 불완전 목록을 반환·캐시하지 않는다."
    ),
    annotations=ANN_READ_ONLY,
)
@safe_tool
async def sigrok_list(kind: str = "drivers", query: str | None = None, backend: str = "linux") -> dict[str, Any]:
    if backend not in ("linux", "windows"):
        raise ValidationFailed("backend는 linux 또는 windows여야 합니다.")
    alias = {"drivers": "drivers", "hardware": "drivers", "decoders": "decoders", "protocol-decoders": "decoders",
             "input-formats": "input_formats", "input_formats": "input_formats", "output-formats": "output_formats",
             "output_formats": "output_formats", "transforms": "transforms", "all": "all"}
    k = alias.get((kind or "").strip().lower())
    if not k:
        raise ValidationFailed(f"알 수 없는 kind: {kind!r}", hint="drivers | decoders | input-formats | output-formats | transforms | all")
    extra = {}
    if backend == "windows":
        from .windows_info import run_info
        result = await _run_cancellable(run_info, "list", rt().config)
        sup = result["supported"]
        extra = {key: value for key, value in result.items() if key != "supported"}
        extra["note"] = "Windows backend는 버전·목록 정보만 연결했습니다. capture_allowed는 정책 설명이며 Windows 캡처 지원을 뜻하지 않습니다."
    else:
        cli = _cli()
        sup = await _offload(cli.supported)
    pol = _policy()
    q = (query or "").strip().lower()

    def filt(items: list[dict[str, str]]) -> list[dict[str, Any]]:
        return [dict(i) for i in items if not q or q in i["id"].lower() or q in i["description"].lower()]

    def drivers() -> list[dict[str, Any]]:
        out = []
        for d in filt(sup["drivers"]):
            d.update(pol.describe(d["id"]))
            out.append(d)
        return out

    if k == "all":
        return {"ok": True, "kind": "all", "drivers": drivers(), "decoders": filt(sup["decoders"]),
                "input_formats": filt(sup["input_formats"]), "output_formats": filt(sup["output_formats"]),
                "transforms": filt(sup["transforms"]), **extra}
    items = drivers() if k == "drivers" else filt(sup[k])
    out: dict[str, Any] = {"ok": True, "kind": k.replace("_", "-"), "count": len(items), "items": items}
    if k == "drivers":
        out["note"] = ("capture_allowed=false 인 드라이버는 sigrok_capture/scan/device_info 에서 거부된다. "
                       "출력 가능 장치(전원공급기·전자부하·신호발생기·릴레이)는 설정으로도 허용할 수 없다.")
    out.update(extra)
    return out


@server.tool(
    description=(
        "프로토콜 디코더 상세(sigrok-cli -P <id> --show 파싱): 필수/선택 채널, 옵션(값 목록·기본값), annotation 클래스/행, "
        "바이너리 클래스, 문서. sigrok_decode 의 -P/-A 문자열을 만들 때 사용 (libsigrokdecode 버전마다 이름이 다르므로 하드코딩 금지)."
    ),
    annotations=ANN_READ_ONLY,
)
@safe_tool
async def sigrok_decoder_help(decoder: str) -> dict[str, Any]:
    d = (decoder or "").strip()
    if not DECODER_ID_RE.match(d):
        raise ValidationFailed(f"잘못된 디코더 ID: {decoder!r}", hint="sigrok_list(kind='decoders') 의 id (예: uart, spi, i2c, spiflash)")
    cli = _cli()
    info = await _offload(cli.decoder_info, d)
    chans = [c["id"] for c in info.get("required_channels", [])] + [c["id"] for c in info.get("optional_channels", [])]
    example = d + "".join(f":{c}=<채널이름>" for c in chans[:4])
    for opt in info.get("options", [])[:2]:
        if opt.get("default") not in (None, ""):
            example += f":{opt['id']}={opt['default']}"
    return {"ok": True, "decoder": info, "example_stack": example,
            "note": "채널 값은 입력 파일의 채널 이름(sigrok_file_info). 스택은 'spi:clk=CLK:...,spiflash' 처럼 쉼표로 쌓는다."}


# ---------------------------------------------------------------------------
# 장치 스캔 / 정보
# ---------------------------------------------------------------------------


def _hardware_prelude(case_id: str | None, conn: str | None) -> Case | None:
    case = rt().case(case_id, hardware=True) if case_id else None
    kind = conn_kind(conn)
    if kind in ("serial", "network") and case is None:
        raise ValidationFailed(
            "conn 으로 시리얼/네트워크 포트를 지정하면 드라이버가 그 포트로 식별 바이트를 보내므로 case_id(소유/허가 증명)가 필요하다.",
            hint="case_id 를 함께 전달하라. USB 장치는 conn 없이 sigrok_scan() 으로 찾을 수 있다.",
        )
    if kind == "serial" and conn:
        # 진입에서 공통 resolver가 문자장치와 rdev를 확인하고 lease를 확보했다.
        users = device_users(conn)
        if users:
            raise Busy(
                f"{conn} 을 다른 프로세스(pid {', '.join(map(str, users[:5]))})가 사용 중이다 — UART 콘솔 세션일 수 있어 "
                "드라이버 식별 바이트가 대상 콘솔에 들어갈 위험이 있으므로 거부한다.",
                hint="그 포트가 로직 애널라이저(OLS 등)인지 확인하고, uart 세션이면 uart_close 후 다시 시도하라.",
            )
    return case


@server.tool(
    description=(
        "연결된 sigrok 장치 스캔. 인자 없으면 모든 드라이버로 USB 등 자동 탐지(읽기 전용 식별). driver 로 한정 가능. "
        "conn(시리얼 /dev/ttyACM0, USB 'bus.addr'/'VID.PID', 'tcp-raw/host/port') 을 주면 그 포트로 식별 질의를 보내므로 "
        "시리얼/네트워크 conn 은 case_id(소유/허가 증명)가 필요하다. 명시 직렬 conn 은 공통 포트 잠금·route 재검증을 적용하고 target/bridge 표지가 있으면 거부한다. "
        "결과 각 장치에 capture_allowed 정책이 붙는다."
    ),
    annotations=ANN_DEVICE,
)
@safe_tool
async def sigrok_scan(
    driver: str | None = None,
    conn: str | None = None,
    case_id: str | None = None,
    timeout_s: float | None = None,
    ctx: Context = None,  # type: ignore[assignment]
) -> dict[str, Any]:
    r = rt()
    drv = validate_driver(driver) if driver else None
    conn_v = validate_conn(conn)
    await _offload(guard_target_port, r, conn_v, consumer="sigrok", driver=drv)
    if conn_v and not drv:
        raise ValidationFailed("conn 을 쓰려면 driver 도 지정해야 합니다.", hint="예: sigrok_scan(driver='ols', conn='/dev/ttyACM0', case_id=...)")
    use = await _acquire_port_use(_serial_use, case_id, conn_v)
    try:
        case = _hardware_prelude(case_id, conn_v)
        cli = _cli()
        pol = _policy()
        if drv:
            args = [f"--driver={drv}" + (f":conn={conn_v}" if conn_v else ""), "--dont-scan", "--scan"]
        else:
            args = ["--scan"]
        argv = [cli.path, *args]
        cls = classify_sigrok_argv(argv, policy=pol)
        action = {"driver": drv, "conn": conn_v}
        cid = case.id if case else None
        if cls.risk >= Risk.MODIFY:
            return _policy_denied("sigrok_scan", action, cls, cid)
        cls = _port_classification(use, action, cls)
        decision = await r.authorize(tool="sigrok_scan", action=action, classification=cls, case_id=cid, ctx=ctx)
        if not decision.allowed:
            return gate_response(decision)
        timeout = _clamp_timeout(timeout_s, 45.0)

        def work(cancel_event: threading.Event) -> CliResult:
            if not drv:
                guard_target_port(r, conn_v, consumer="sigrok", driver=drv, phase="pre-process")
                return _port_run(use, argv, timeout=timeout, cancel=cancel_event.is_set, env=child_env())
            lock = _device_lock(_device_key(drv, conn_v))
            if not lock.acquire(blocking=False):
                raise Busy(f"장치 {drv} 를 다른 작업(캡처 등)이 사용 중입니다.", hint="sigrok_jobs 로 실행 중인 캡처를 확인하라.")
            try:
                guard_target_port(r, conn_v, consumer="sigrok", driver=drv, phase="pre-process")
                return _port_run(use, argv, timeout=timeout, cancel=cancel_event.is_set, env=child_env())
            finally:
                lock.release()

        def finish(res: CliResult) -> dict[str, Any]:
            rep = check_result(res, "sigrok-cli --scan")
            devices = parse_scan(res.stdout_text)
            for d in devices:
                d.update(pol.describe(d["driver"]))
            out: dict[str, Any] = {"ok": True, "count": len(devices), "devices": devices, "classification": cls.to_dict()}
            if rep.warnings:
                out["stderr_warnings"] = rep.warnings
            noise = [ln for ln in res.stderr.splitlines() if ln.strip()]
            if noise:
                out["stderr"] = tail_text("\n".join(noise), 1500)
            if not devices:
                out["note"] = (
                    "장치를 찾지 못했다. USB 연결/케이블, (WSL2 이면) Windows 에서 usbipd attach --wsl, udev 권한, 시리얼 장치면 driver+conn 지정을 "
                    "확인하라. fx2lafw 장치는 첫 스캔에서 펌웨어 업로드 후 재열거되므로 몇 초 뒤 한 번 더 스캔하면 보일 수 있다."
                )
            elif not any(d["driver"] == "demo" for d in devices) or len(devices) > 1:
                out["note"] = "캡처에는 driver(필요하면 conn=결과의 conn 값)를 명시한다. demo 는 가상 장치다."
            if case:
                r.audit({"event": "sigrok_scan", "driver": drv, "conn": conn_v, "devices": len(devices)}, case.id)
            return out

        def wrapped(cancel_event: threading.Event) -> dict[str, Any]:
            return _port_worker(use, work, finish, cancel_event)

        return await _run_cancellable(wrapped)
    finally:
        if use is not None and use.handoff.abandon_caller():
            use.finish()


@server.tool(
    description=(
        "로직 애널라이저 상세(sigrok-cli -d <driver> --show 파싱): 드라이버 기능, 채널/채널 그룹, 지원 samplerate 목록 또는 범위, "
        "지원 트리거 문자, 최대 샘플 수. 장치를 열기만 하고 설정은 바꾸지 않는다(허용 목록 드라이버만). 캡처 전에 samplerate 를 고를 때 사용. "
        "명시 직렬 conn 은 공통 포트 잠금·route 재검증·target/bridge 거부를 적용한다."
    ),
    annotations=ANN_DEVICE,
)
@safe_tool
async def sigrok_device_info(
    case_id: str,
    driver: str,
    conn: str | None = None,
    timeout_s: float | None = None,
    ctx: Context = None,  # type: ignore[assignment]
) -> dict[str, Any]:
    r = rt()
    drv = validate_driver(driver)
    conn_v = validate_conn(conn)
    await _offload(guard_target_port, r, conn_v, consumer="sigrok", driver=drv)
    use = await _acquire_port_use(_serial_use, case_id, conn_v)
    try:
        case = _hardware_prelude(case_id, conn_v)
        assert case is not None
        cli = _cli()
        pol = _policy()
        argv = [cli.path, f"--driver={drv}" + (f":conn={conn_v}" if conn_v else ""), "--dont-scan", "--show"]
        cls = classify_sigrok_argv(argv, policy=pol)
        action = {"driver": drv, "conn": conn_v}
        if cls.risk >= Risk.MODIFY:
            return _policy_denied("sigrok_device_info", action, cls, case.id)
        cls = _port_classification(use, action, cls)
        decision = await r.authorize(tool="sigrok_device_info", action=action, classification=cls, case_id=case.id, ctx=ctx)
        if not decision.allowed:
            return gate_response(decision)
        timeout = _clamp_timeout(timeout_s, 60.0)

        def work(cancel_event: threading.Event) -> CliResult:
            lock = _device_lock(_device_key(drv, conn_v))
            if not lock.acquire(blocking=False):
                raise Busy(f"장치 {drv} 를 다른 작업(캡처 등)이 사용 중입니다.", hint="sigrok_jobs 로 실행 중인 캡처를 확인하라.")
            try:
                guard_target_port(r, conn_v, consumer="sigrok", driver=drv, phase="pre-process")
                return _port_run(use, argv, timeout=timeout, cancel=cancel_event.is_set, env=child_env())
            finally:
                lock.release()

        def finish(res: CliResult) -> dict[str, Any]:
            parsed = parse_device_show(res.stdout_text)
            rep = stderr_problems(res.stderr)
            if res.returncode != 0 or rep.fatal:
                # 장치가 없어도 드라이버 기능/스캔 옵션은 출력된다 → 함께 돌려준다
                if parsed["driver_functions"] and any(e["code"] == "no_device" for e in rep.errors):
                    return {"ok": False, "status": "no_device", "driver": drv, "conn": conn_v,
                            "driver_functions": parsed["driver_functions"], "scan_options": parsed["scan_options"],
                            "message": "장치를 찾지 못했다. USB/usbipd/udev 권한/conn 을 확인하라.", "stderr": tail_text(res.stderr, 1500)}
                check_result(res, "sigrok-cli --show")
            return {"ok": True, "driver": drv, "conn": conn_v, **parsed, **pol.describe(drv),
                    **({"stderr_warnings": rep.warnings} if rep.warnings else {})}

        def wrapped(cancel_event: threading.Event) -> dict[str, Any]:
            return _port_worker(use, work, finish, cancel_event)

        return await _run_cancellable(wrapped)
    finally:
        if use is not None and use.handoff.abandon_caller():
            use.finish()


# ---------------------------------------------------------------------------
# 캡처
# ---------------------------------------------------------------------------


@dataclass
class CapturePlan:
    case_id: str
    case_dir: Path
    sig_dir: Path
    driver: str
    conn: str | None
    samplerate: int
    duration_ms: int | None
    samples: int | None
    channels: ChannelSelection | None
    triggers: str | None
    capture_ratio: int | None
    final_path: Path
    part_path: Path
    argv: list[str]
    expected_s: float
    timeout_s: float
    policy: DriverPolicy
    exclusive_key: str
    warnings: list[str] = field(default_factory=list)
    runtime: Runtime | None = field(default=None, repr=False, compare=False)
    port_use: _SerialUse | None = field(default=None, repr=False, compare=False)

    def requested(self) -> dict[str, Any]:
        return {
            "driver": self.driver, "conn": self.conn, "samplerate": self.samplerate, "duration_ms": self.duration_ms,
            "samples": self.samples, "channels": self.channels.tokens if self.channels else None,
            "triggers": self.triggers, "capture_ratio": self.capture_ratio,
        }


def _capture_worker(plan: CapturePlan, cancel: Callable[[], bool], progress: Callable | None = None) -> dict[str, Any]:
    use = plan.port_use
    if use is not None and not use.handoff.claim_worker():
        return {"ok": False, "status": "cancelled"}
    try:
        if cancel():
            return {"ok": False, "status": "cancelled"}
        result = _capture_worker_inner(plan, cancel, progress)
        if use is not None:
            result["route"] = use.route.to_dict()
        return result
    finally:
        if use is not None:
            use.finish()


def _capture_worker_inner(plan: CapturePlan, cancel: Callable[[], bool], progress: Callable[[float, float, str], None] | None = None) -> dict[str, Any]:
    """캡처 실행 (동기 호출/백그라운드 작업 공용). 실행 직전에 argv 를 다시 분류한다."""
    cls = classify_sigrok_argv(plan.argv, policy=plan.policy, allowed_output_dir=plan.sig_dir)
    if cls.risk > Risk.INTERACT:
        raise SafetyDenied(
            f"캡처 명령이 안전 정책을 통과하지 못해 실행하지 않음: {cls.reason}",
            code="safety_denied",
            data={"classification": cls.to_dict()},
        )
    lock = _device_lock(plan.exclusive_key)
    if not lock.acquire(blocking=False):
        raise Busy(f"장치 {plan.driver} 를 다른 캡처가 사용 중입니다.", hint="sigrok_jobs / sigrok_job_status 로 확인하라.")
    t_start = utcnow_iso()
    try:
        guard_target_port(plan.runtime or rt(), plan.conn, consumer="sigrok", driver=plan.driver, phase="pre-process")

        def tick(elapsed: float) -> None:
            if progress is not None:
                total = plan.expected_s if plan.expected_s > 0 else 1.0
                progress(min(elapsed, total), total, f"캡처 중 {elapsed:.1f}s / 예상 {plan.expected_s:.1f}s"
                         + (" (트리거 대기 포함)" if plan.triggers else ""))

        res = _port_run(plan.port_use, plan.argv, timeout=plan.timeout_s, cancel=cancel, env=child_env(), on_tick=tick,
                          stdout_limit=1024 * 1024, cwd=plan.sig_dir)
    finally:
        lock.release()
    case = rt().cases.get(plan.case_id)
    base_result: dict[str, Any] = {"requested": plan.requested(), "command": _display_argv(plan.argv),
                                   "started_at": t_start, "duration_s": round(res.duration_s, 3)}
    if res.cancelled or res.timed_out:
        partial = _salvage_partial(case, plan)
        reason = "cancelled" if res.cancelled else "timeout"
        msg = ("취소됨" if res.cancelled else f"{plan.timeout_s:.0f}초 안에 끝나지 않아 종료함")
        if res.timed_out and plan.triggers and partial is None:
            msg = f"트리거 조건({plan.triggers})이 {plan.timeout_s:.0f}초 동안 발생하지 않음 (데이터 없음). 신호/채널/트리거 문자를 확인하라."
        rt().audit({"event": "sigrok_capture_aborted", "reason": reason, "partial": partial, **plan.requested()}, plan.case_id)
        if partial:
            msg += f" — 부분 캡처를 {partial['path']} 로 보존함"
        return {**base_result, "ok": False, "status": reason, "message": msg, "partial": partial,
                "stderr": tail_text(res.stderr, 1500),
                **({"hint": "timeout_s 를 늘리거나 트리거 없이 다시 캡처하라."} if res.timed_out else {})}
    rep = stderr_problems(res.stderr)
    if res.returncode != 0 or rep.fatal:
        _remove_quiet(plan.part_path)
        check_result(res, "sigrok-cli 캡처")  # PwehError 발생
    if not plan.part_path.exists():
        raise PwehError("sigrok-cli 가 성공으로 끝났지만 캡처 파일이 만들어지지 않았다.", code="sigrok_no_output",
                        hint="장치가 데이터를 보내지 않았을 수 있다 (트리거/채널 확인).", data={"stderr": tail_text(res.stderr, 2000)})
    try:
        info = sig.read_srzip_info(plan.part_path)
    except PwehError as exc:
        _remove_quiet(plan.part_path)
        raise PwehError(f"캡처 파일 검증 실패: {exc}", code="sigrok_bad_capture")
    if not info.total_samples:
        _remove_quiet(plan.part_path)
        raise PwehError("캡처 파일에 로직 샘플이 없다 (아날로그 전용이거나 데이터 없음).", code="sigrok_empty_capture",
                        hint="channels 에 로직 채널을 지정하라.", data={"warnings": info.warnings})
    os.replace(plan.part_path, plan.final_path)
    info.path = str(plan.final_path)
    act = sig.srzip_activity(plan.final_path, info, max_bytes=256 * 1024 * 1024)
    extra = {**plan.requested(), "samples_captured": info.total_samples, "unitsize": info.unitsize,
             "channels_in_file": [c.name for c in info.channels]}
    art = case.register_artifact(plan.final_path, kind="signal-capture", producer=PRODUCER,
                                 description=f"{plan.driver} 캡처 {info.samplerate and int(info.samplerate)} Hz, {info.total_samples} 샘플",
                                 extra=extra)
    warnings = list(plan.warnings) + list(info.warnings)
    warnings += [w["line"] for w in rep.warnings]
    want = plan.samples or (plan.samplerate * plan.duration_ms // 1000 if plan.duration_ms else None)
    if want and info.total_samples < want * 0.98:
        warnings.append(f"요청한 샘플({want})보다 적게 받음({info.total_samples}) — USB 대역폭/장치 버퍼 한계일 수 있음")
    active = sorted((c for c in act["channels"] if c.get("edges")), key=lambda c: -c["edges"])
    result = {
        **base_result,
        "ok": True,
        "status": "succeeded",
        "path": case.rel(plan.final_path),
        "absolute_path": str(plan.final_path),
        "artifact": art,
        "driver": plan.driver,
        "conn": plan.conn,
        "samplerate": int(info.samplerate) if info.samplerate else None,
        "samples": info.total_samples,
        "duration_s": round(info.duration_s or 0.0, 6),
        "unitsize": info.unitsize,
        "channels": [c.name for c in info.channels],
        "activity": act["channels"],
        "warnings": warnings,
    }
    if active:
        result["next_steps"] = (f"활동이 가장 많은 채널: {active[0]['name']} ({active[0]['edges']} 에지). UART 라면 "
                                f"sigrok_estimate_baud(case_id, '{result['path']}', channel='{active[0]['name']}')")
    else:
        result["next_steps"] = "모든 채널에 에지가 없다: 프로브/GND 연결, 캡처 시점(전원 투입 전에 캡처 시작), 전압 레벨을 확인하라."
    rt().audit({"event": "sigrok_capture", "path": result["path"], "samples": info.total_samples, **plan.requested()}, plan.case_id)
    return result


def _trim_partial_last_line(p: Path) -> None:
    """잘린 출력의 마지막 불완전한 줄 제거 (줄 단위 파서가 깨진 줄을 보지 않게)."""
    try:
        size = p.stat().st_size
        if size == 0:
            return
        with open(p, "r+b") as fh:
            back = min(size, 65536)
            fh.seek(size - back)
            tail = fh.read(back)
            if tail.endswith(b"\n"):
                return
            idx = tail.rfind(b"\n")
            fh.truncate((size - back + idx + 1) if idx >= 0 else (0 if back == size else size))
    except OSError:
        pass


def _remove_quiet_if_empty(p: Path) -> None:
    """작업이 끝났는데 선점용 빈 임시 파일만 남은 경우 정리."""
    try:
        if p.exists() and p.stat().st_size == 0:
            p.unlink()
    except OSError:
        pass


def _remove_quiet(p: Path) -> None:
    try:
        if p.exists():
            p.unlink()
    except OSError:
        pass


def _salvage_partial(case: Case, plan: CapturePlan) -> dict[str, Any] | None:
    """취소/시간초과 시 남은 .sr 이 유효하면 '<name>-partial.sr' 로 보존·등록."""
    p = plan.part_path
    if not p.exists():
        return None
    try:
        info = sig.read_srzip_info(p)
    except PwehError:
        _remove_quiet(p)
        return None
    if not info.total_samples:
        _remove_quiet(p)
        return None
    dest = _unique_path(plan.sig_dir, plan.final_path.stem + "-partial", ".sr")
    os.replace(p, dest)
    try:
        art = case.register_artifact(dest, kind="signal-capture", producer=PRODUCER, description="부분 캡처(취소/시간초과)",
                                     extra={**plan.requested(), "partial": True, "samples_captured": info.total_samples})
    except PwehError:
        art = None
    return {"path": case.rel(dest), "samples": info.total_samples, "artifact": art}


@server.tool(
    description=(
        "로직 애널라이저 캡처 → cases/<id>/signals/<name>.sr (srzip) 저장 + 아티팩트 등록. 입력 전용(OBSERVE)이지만 케이스 소유/허가 증명이 필요. "
        "driver 필수(sigrok_scan 결과), samplerate 예 '1m'/'8MHz'/'24m'(소문자 m=MHz, 정수 Hz 로 변환), duration_ms 와 samples 중 정확히 하나. "
        "channels 예 ['D0','D1'] 또는 ['D0=RX','D1=TX'](0번부터 연속 선택 권장), triggers 예 'RX=f'(rename 후 이름, 문자 0/1/r/f/e), "
        "capture_ratio=트리거 전 비율(%), conn=장치 지정. 전원공급기 등 출력 장치와 samplerate/captureratio 외 config 는 거부. "
        "예상 20초 초과 또는 트리거 사용 시 job 으로 실행되어 job_id 반환 → sigrok_job_status 로 폴링 (background 로 강제 가능). "
        "부트 로그는 캡처를 먼저 시작한 뒤 사람이 대상 전원을 넣도록 안내한다. "
        "명시 직렬 conn 의 공통 포트 잠금은 worker의 프로세스 정리가 확인될 때까지 유지하며, libusb 장치 선택은 이 직렬 잠금의 대상이 아니다."
    ),
    annotations=ANN_DEVICE,
)
@safe_tool
async def sigrok_capture(
    case_id: str,
    driver: str,
    samplerate: str | int = "1m",
    duration_ms: int | None = None,
    samples: int | str | None = None,
    channels: list[str] | str | None = None,
    triggers: list[str] | str | None = None,
    output_name: str | None = None,
    conn: str | None = None,
    capture_ratio: int | None = None,
    background: bool | None = None,
    timeout_s: float | None = None,
    ctx: Context = None,  # type: ignore[assignment]
) -> dict[str, Any]:
    r = rt()
    case = r.case(case_id, hardware=True)
    drv = validate_driver(driver)
    conn_v = validate_conn(conn)
    await _offload(guard_target_port, r, conn_v, consumer="sigrok", driver=drv)
    use = await _acquire_port_use(_serial_use, case_id, conn_v)
    part = None
    try:
        rate = parse_samplerate(samplerate)
        dur = validate_duration_ms(duration_ms)
        ns = validate_samples(samples)
        if (dur is None) == (ns is None):
            raise ValidationFailed(
                "duration_ms 와 samples 중 정확히 하나를 지정해야 합니다.",
                hint="예: duration_ms=5000 (5초) 또는 samples=1000000. 무한 캡처(--continuous)는 지원하지 않는다.",
            )
        chans = validate_channels(channels)
        trig = validate_triggers(triggers, chans)
        ratio = validate_capture_ratio(capture_ratio)
        name = validate_output_name(output_name)
        pol = _policy()
        sig_dir = case.subdir("signals")
        cli = _cli()
        final, part = _reserve_capture_paths(sig_dir, name, drv)
        handed_off = False
        try:
            args = [f"--driver={drv}" + (f":conn={conn_v}" if conn_v else ""), "--dont-scan", f"--config=samplerate={rate}"]
            if ratio is not None:
                args.append(f"--config=captureratio={ratio}")
            if chans:
                args.append(f"--channels={chans.arg}")
            if trig:
                args.append(f"--triggers={trig}")
            args.append(f"--time={dur}" if dur is not None else f"--samples={ns}")
            args += ["--output-format=srzip", f"--output-file={part}"]
            argv = [cli.path, *args]
            action = {"driver": drv, "conn": conn_v, "samplerate": rate, "duration_ms": dur, "samples": ns,
                      "channels": chans.tokens if chans else None, "triggers": trig, "capture_ratio": ratio, "output_name": name}
            cls = classify_sigrok_argv(argv, policy=pol, allowed_output_dir=sig_dir)
            if cls.risk >= Risk.MODIFY:
                return _policy_denied("sigrok_capture", action, cls, case.id)
            # 장치 사용 중 여부/시리얼 포트 점유 확인
            if conn_kind(conn_v) == "serial":
                _hardware_prelude(case.id, conn_v)
            exclusive_key = _device_key(drv, conn_v)
            for j in r.jobs.list(active_only=True):
                if (j.get("meta") or {}).get("exclusive_key") == exclusive_key:
                    raise Busy(f"같은 장치로 캡처 작업이 실행 중입니다: {j['job_id']}", hint="sigrok_job_status 로 확인하거나 sigrok_job_cancel 로 취소하라.")
            cls = _port_classification(use, action, cls)
            decision = await r.authorize(tool="sigrok_capture", action=action, classification=cls, case_id=case.id, ctx=ctx)
            if not decision.allowed:
                return gate_response(decision)

            expected = (dur / 1000.0) if dur is not None else (ns / rate)  # type: ignore[operator]
            margin = 60.0 if trig else 30.0
            timeout = _clamp_timeout(timeout_s, expected + margin)
            if timeout < expected + 1.0:
                raise ValidationFailed(f"timeout_s({timeout})가 예상 캡처 시간({expected:.1f}s)보다 짧습니다.")
            warnings = list(chans.warnings) if chans else []
            nch = len(chans.final_names) if chans else 8
            est_bytes = int((ns if ns is not None else rate * dur / 1000) * max(1, math.ceil(nch / 8)))  # type: ignore[operator]
            free = shutil.disk_usage(sig_dir).free
            if est_bytes > free:
                warnings.append(f"압축 전 최대 데이터 크기({est_bytes} bytes)가 남은 디스크({free} bytes)보다 큼 — 신호가 단조로우면 압축되지만 주의")
            if est_bytes > 2 * 1024**3:
                warnings.append(f"큰 캡처(압축 전 최대 {est_bytes / 1024**3:.1f} GiB) — 분석/디코드가 오래 걸릴 수 있음")
            if ratio is not None and not trig:
                warnings.append("capture_ratio 는 트리거와 함께일 때만 의미가 있다")
            plan = CapturePlan(case_id=case.id, case_dir=case.dir, sig_dir=sig_dir, driver=drv, conn=conn_v, samplerate=rate,
                               duration_ms=dur, samples=ns, channels=chans, triggers=trig, capture_ratio=ratio, final_path=final,
                               part_path=part, argv=argv, expected_s=expected, timeout_s=timeout, policy=pol,
                               exclusive_key=exclusive_key, warnings=warnings, runtime=r, port_use=use)
            bg = background if background is not None else (trig is not None or expected > SYNC_CAPTURE_LIMIT_S)
            if bg:
                def job_fn(jctx: Any) -> dict[str, Any]:
                    jctx.log(f"캡처 시작: {' '.join(_display_argv(argv))}")
                    try:
                        res = _capture_worker(plan, cancel=lambda: jctx.cancelled,
                                              progress=lambda d, t, m: jctx.progress(d, t, m))
                    finally:
                        if use is None or not use.unverified:
                            _remove_quiet_if_empty(plan.part_path)
                    if res.get("status") == "timeout":  # 작업 상태를 failed 로 (부분 결과는 error.data 에)
                        raise TimeoutExpired(res.get("message", "캡처 시간 초과"), hint=res.get("hint"), data=res)
                    return res

                job = r.jobs.start("sigrok-capture", job_fn, description=f"sigrok 캡처 {drv} {rate} Hz → {case.rel(final)}",
                                   case_id=case.id, meta={"planned_path": case.rel(final), "driver": drv,
                                                        **({"route": use.route.to_dict(), "port_keys": list(use.keys)} if use else {})},
                                   exclusive_key=exclusive_key)
                handed_off = True
                if use is not None:
                    use.accepted = True
                return {"ok": True, "status": "started", "job_id": job.id, "planned_path": case.rel(final),
                        "expected_duration_s": round(expected, 3), "timeout_s": timeout, "warnings": warnings,
                        **({"route": use.route.to_dict()} if use else {}),
                        "classification": cls.to_dict(),
                        "message": f"백그라운드 캡처 시작. sigrok_job_status(job_id='{job.id}', wait_seconds=30) 로 폴링하라. "
                                   + ("부트 로그라면 지금 사람에게 대상 전원을 넣도록 요청하라." if trig or expected > 2 else "")}
            handed_off = True
        finally:
            if not handed_off and (use is None or use.handoff.abandon_caller()):
                try:
                    _remove_quiet(part)
                finally:
                    if use is not None:
                        use.finish()

        def work(cancel_event: threading.Event) -> dict[str, Any]:
            try:
                return _capture_worker(plan, cancel=cancel_event.is_set)
            finally:
                if use is None or not use.unverified:
                    _remove_quiet_if_empty(plan.part_path)

        result = await _run_cancellable(work)
        result["classification"] = cls.to_dict()
        return result
    finally:
        if use is not None and not use.accepted and use.handoff.abandon_caller():
            if part is not None:
                _remove_quiet(part)
            use.finish()


# ---------------------------------------------------------------------------
# 디코드 / 변환
# ---------------------------------------------------------------------------


def _parse_stack(stack: str) -> list[tuple[str, dict[str, str]]]:
    parts = []
    for tok in stack.split(","):
        items = tok.split(":")
        pd = items[0].strip()
        if not DECODER_ID_RE.match(pd):
            raise ValidationFailed(f"잘못된 디코더 ID: {pd!r} (스택 {stack!r})", hint="sigrok_list(kind='decoders') 의 id 사용")
        kv: dict[str, str] = {}
        for it in items[1:]:
            k, sep, v = it.partition("=")
            if not sep or not PD_KEY_RE.match(k) or not PD_VAL_RE.match(v) or any(c in v for c in ":,="):
                raise ValidationFailed(
                    f"잘못된 디코더 옵션/채널 항목: {it!r} (스택 {stack!r})",
                    hint="형식: '<디코더>:<키>=<값>:...' (값에 ':' ',' '=' 공백 금지). 예: 'uart:rx=D0:baudrate=115200'",
                )
            if k in kv:
                raise ValidationFailed(f"디코더 {pd} 의 키가 중복됩니다: {k}")
            kv[k] = v
        parts.append((pd, kv))
    return parts


def _validate_decoders(decoders: Any) -> list[str]:
    if isinstance(decoders, str):
        stacks = [s.strip() for s in decoders.split(";") if s.strip()]
    elif isinstance(decoders, (list, tuple)):
        stacks = [str(s).strip() for s in decoders if str(s).strip()]
    else:
        raise ValidationFailed("decoders 는 문자열 또는 문자열 목록이어야 합니다.", hint="예: 'uart:rx=D0:baudrate=115200' 또는 ['uart:rx=D0:baudrate=115200', 'uart:rx=D1:baudrate=115200']")
    if not stacks:
        raise ValidationFailed("decoders 가 비어 있습니다.")
    if len(stacks) > 8:
        raise ValidationFailed("디코더 스택은 최대 8개까지")
    for s in stacks:
        _parse_stack(s)
    return stacks


def _validate_annotations(annotations: Any) -> str | None:
    if annotations is None or annotations == "" or annotations == []:
        return None
    items = annotations.split(",") if isinstance(annotations, str) else [str(a) for a in annotations]
    out = []
    for it in items:
        it = it.strip()
        pd, sep, rest = it.partition("=")
        if not DECODER_ID_RE.match(pd):
            raise ValidationFailed(f"잘못된 annotations 항목: {it!r}", hint="'<디코더ID>=<클래스>[:<클래스>...]' 예: 'uart=rx-data' 또는 'spi=mosi-data:miso-data'")
        if sep:
            classes = rest.split(":")
            if not classes or not all(re.fullmatch(r"[A-Za-z0-9_/-]{1,40}", c) for c in classes):
                raise ValidationFailed(f"잘못된 annotation 클래스: {it!r}")
        out.append(it)
    return ",".join(out)


def _validate_format_spec(spec: Any, what: str) -> str | None:
    if spec is None or spec == "":
        return None
    s = str(spec).strip()
    parts = s.split(":")
    if not FMT_ID_RE.match(parts[0]):
        raise ValidationFailed(f"잘못된 {what}: {spec!r}")
    for it in parts[1:]:
        k, sep, v = it.partition("=")
        if not PD_KEY_RE.match(k) or (sep and (not PD_VAL_RE.match(v) or any(c in v for c in ",="))):
            raise ValidationFailed(f"잘못된 {what} 옵션: {it!r}", hint="형식: '<형식>:<키>=<값>' (값은 정수 Hz 등, 단위 접미사 금지)")
    return s


def _input_channel_info(cli: SigrokCli | None, src: Path, fmt: str | None) -> dict[str, Any]:
    """입력 파일의 채널 이름/샘플레이트 (srzip/vcd 는 순수 Python, 그 외는 sigrok-cli -i --show)."""
    base_fmt = (fmt or "").split(":")[0]
    detected = sig.detect_format(src)
    if (detected == "srzip" and not base_fmt) or (detected == "vcd" and base_fmt in ("", "vcd")):
        info = sig.load_info(src)
        sr = info.tick_hz if detected == "vcd" else info.samplerate
        if detected == "vcd" and fmt and "downsample=" in fmt:
            m = re.search(r"downsample=(\d+)", fmt)
            if m and int(m.group(1)) > 1 and sr:
                sr = sr / int(m.group(1))
        return {"names": [c.name for c in info.channels], "samplerate": sr, "source": f"{detected}-reader",
                "format": detected, "info": info}
    if cli is None:
        return {"names": None, "samplerate": None, "source": None, "format": detected}
    props = cli.input_props(str(src), fmt)
    return {"names": [c["name"] for c in props["channels"] if c["type"] == "logic"], "samplerate": props["samplerate"],
            "source": "sigrok-cli", "format": base_fmt or detected, "props": props}


def _check_decoder_channels(cli: SigrokCli, stacks: list[str], names: list[str] | None) -> list[str]:
    warnings: list[str] = []
    for stack in stacks:
        parts = _parse_stack(stack)
        for idx, (pd, kv) in enumerate(parts):
            info = cli.decoder_info(pd)
            req = [c["id"] for c in info.get("required_channels", [])]
            opt = [c["id"] for c in info.get("optional_channels", [])]
            opts = {o["id"] for o in info.get("options", [])}
            chan_keys = [k for k in kv if k in req or k in opt]
            for k in kv:
                if k not in req and k not in opt and k not in opts:
                    raise ValidationFailed(
                        f"디코더 {pd} 에 없는 옵션/채널: {k!r}",
                        hint=f"채널: {req + opt}, 옵션: {sorted(opts)} (sigrok_decoder_help('{pd}') 참고)",
                    )
            if idx > 0:
                if chan_keys:
                    raise ValidationFailed(f"스택의 두 번째 이후 디코더({pd})에는 채널을 지정하지 않는다: {chan_keys}")
                continue
            if (req or opt) and not chan_keys:
                raise ValidationFailed(
                    f"디코더 {pd} 의 채널 매핑이 없습니다. sigrok 은 이때 입력의 첫 채널부터 순서대로 묶어 조용히 잘못 디코드할 수 있다.",
                    hint=f"예: '{pd}:" + ":".join(f"{c}=<채널이름>" for c in (req or opt[:1])) + f"' (입력 채널: {names})",
                )
            missing = [c for c in req if c not in kv]
            if missing:
                raise ValidationFailed(f"디코더 {pd} 의 필수 채널이 빠졌습니다: {missing}", hint=f"입력 채널: {names}")
            if names is not None:
                for k in chan_keys:
                    if kv[k] not in names:
                        raise ValidationFailed(
                            f"채널 {kv[k]!r} ({pd}:{k}) 이 입력 파일에 없습니다.",
                            hint=f"입력 채널: {names}. sigrok 은 없는 채널을 무시하고 기본 매핑으로 디코드하므로 사전에 거부한다.",
                        )
    return warnings


def _count_lines_and_preview(path: Path, max_lines: int, stats_lines: int = 2_000_000) -> dict[str, Any]:
    preview: list[str] = []
    total = 0
    inst: dict[str, int] = {}
    first_ss = last_es = None
    with open(path, "rb") as fh:
        for raw in fh:
            total += 1
            line = raw.rstrip(b"\r\n").decode("utf-8", "replace")
            if len(preview) < max_lines:
                preview.append(line)
            if total <= stats_lines:
                a = parse_annotation_line(line)
                if a:
                    inst[a["inst"]] = inst.get(a["inst"], 0) + 1
                    if a["ss"] is not None:
                        first_ss = a["ss"] if first_ss is None else min(first_ss, a["ss"])
                        last_es = a["es"] if last_es is None else max(last_es, a["es"])
    out: dict[str, Any] = {"lines_total": total, "lines": preview, "truncated": total > len(preview), "instances": inst}
    if first_ss is not None:
        out["sample_range"] = [first_ss, last_es]
    return out


def _auto_input_format(src: Path, fmt: str | None) -> str | None:
    if fmt:
        return fmt
    if sig.detect_format(src) == "vcd":
        return "vcd"
    return None


def _decode_worker(argv: list[str], out_path: Path, tmp_path: Path, timeout: float, cancel: Callable[[], bool],
                   max_lines: int, case: Case, extra: dict[str, Any], progress: Callable[[float, float, str], None] | None = None) -> dict[str, Any]:
    # 프로세스를 띄우기 직전에 argv 를 다시 분류한다 (디코드 job 과, 도구 단계 분류를 거치지 않는 uart 자동 디코드 경로 공통).
    # 디코드는 장치를 건드리지 않는 오프라인 명령(sigrok.offline)이어야만 한다 — 캡처·스캔 argv 는 OBSERVE 여도 거부.
    cls = classify_sigrok_argv(argv, policy=_policy())
    if cls.risk != Risk.OBSERVE or cls.rule_id != "sigrok.offline":
        raise SafetyDenied(
            f"디코드 명령이 오프라인 명령이 아니라 실행하지 않음: {cls.reason}",
            code="safety_denied",
            data={"classification": cls.to_dict()},
        )
    _remove_quiet(tmp_path)

    def tick(elapsed: float) -> None:
        if progress is not None:
            size = tmp_path.stat().st_size if tmp_path.exists() else 0
            progress(elapsed, timeout, f"디코드 중 {elapsed:.0f}s, 출력 {size} bytes")

    with open(tmp_path, "wb") as fh:
        res = run_process(argv, timeout=timeout, cancel=cancel, stdout_file=fh, stdout_limit=MAX_DECODE_OUTPUT,
                          env=child_env(), on_tick=tick)
    rep = stderr_problems(res.stderr)
    if res.cancelled or res.timed_out:
        kept = None
        _remove_quiet_if_empty(out_path)
        if tmp_path.exists() and tmp_path.stat().st_size > 0:
            dest = _unique_path(out_path.parent, out_path.stem + "-partial", out_path.suffix)
            os.replace(tmp_path, dest)
            kept = case.rel(dest)
        else:
            _remove_quiet(tmp_path)
        msg = "디코드 취소됨" if res.cancelled else f"디코드가 {timeout:.0f}초 안에 끝나지 않음"
        if kept:
            msg += f" (부분 출력: {kept})"
        if res.cancelled:
            return {"ok": False, "status": "cancelled", "message": msg, "partial_output": kept}
        raise TimeoutExpired(msg, hint="background=true 로 다시 실행하거나 timeout_s 를 늘려라 (긴 캡처는 job 권장).",
                             data={"partial_output": kept})
    # 출력 상한 도달: 우리가 프로세스를 종료했으므로 rc 는 실패값일 수 있다 → 잘린 결과를 보존하고 경고
    truncated = res.output_limit_hit
    if (res.returncode != 0 and not truncated) or rep.fatal:
        _remove_quiet(tmp_path)
        _remove_quiet_if_empty(out_path)
        check_result(res, "sigrok-cli 디코드", allow_rc=(0, res.returncode) if truncated else (0,))
    if truncated:
        _trim_partial_last_line(tmp_path)
    os.replace(tmp_path, out_path)
    stats = _count_lines_and_preview(out_path, max_lines)
    art = case.register_artifact(out_path, kind="signal-decode", producer=PRODUCER,
                                 description=f"sigrok 디코드 {extra.get('decoders')}" + (" (출력 상한에서 잘림)" if truncated else ""),
                                 extra={**extra, "lines": stats["lines_total"], **({"truncated": True} if truncated else {})})
    warnings = [w["line"] for w in rep.warnings]
    if truncated:
        warnings.append(
            f"디코드 출력이 상한({MAX_DECODE_OUTPUT} bytes)에 도달해 그 지점에서 중단하고 앞부분만 저장함 — annotations 를 좁히거나"
            " (예: 'uart=rx-data', 'spiflash=commands') 입력을 나눠 다시 디코드하라")
    if stats["lines_total"] == 0:
        warnings.append("디코드 결과 0줄 — 보드레이트/채널 매핑/디코더 옵션/annotations 를 확인하라")
    return {"ok": True, "status": "succeeded", "output_path": case.rel(out_path), "absolute_path": str(out_path),
            "artifact": art, **stats, "output_truncated": truncated, "warnings": warnings, "command": _display_argv(argv),
            "duration_s": round(res.duration_s, 3), **({"stderr": tail_text(res.stderr, 1000)} if res.stderr.strip() else {})}


@server.tool(
    description=(
        "sigrok-cli 로 신호 파일 디코드: -i <input_path> [-I input_format] -P <스택들> [-A annotations] [--protocol-decoder-samplenum]. "
        "결과 전체는 signals/<입력>.<디코더>.txt 로 저장(아티팩트 signal-decode)하고 앞 max_lines 줄 미리보기와 줄 수/인스턴스별 개수를 반환. "
        "decoders 예 'uart:rx=D0:baudrate=115200' 또는 스택 'spi:clk=CLK:mosi=MOSI:miso=MISO:cs=CS,spiflash', 여러 스택은 목록. "
        "채널 매핑은 필수이며 입력 파일의 채널 이름과 대조한다(sigrok 은 틀린 이름을 조용히 무시하므로 사전 거부). "
        "annotations 예 'uart=rx-data' (생략 시 모든 클래스 → 매우 장황). .vcd 는 input_format 자동 'vcd'. "
        "큰 파일은 background=true(자동 판단)로 job 실행."
    ),
    annotations=ANN_LOCAL_WRITE,
)
@safe_tool
async def sigrok_decode(
    case_id: str,
    input_path: str,
    decoders: str | list[str],
    annotations: str | list[str] | None = None,
    input_format: str | None = None,
    samplenum: bool = False,
    max_lines: int = 400,
    background: bool | None = None,
    timeout_s: float | None = None,
    output_name: str | None = None,
) -> dict[str, Any]:
    r = rt()
    case = r.case(case_id)
    src = _resolve_input(case, input_path)
    stacks = _validate_decoders(decoders)
    ann = _validate_annotations(annotations)
    fmt = _auto_input_format(src, _validate_format_spec(input_format, "input_format"))
    try:
        max_lines = max(1, min(int(max_lines), 5000))
    except (TypeError, ValueError):
        raise ValidationFailed(f"max_lines 는 정수여야 합니다: {max_lines!r}")
    name = validate_output_name(output_name)
    cli = _cli()
    chinfo = await _offload(_input_channel_info, cli, src, fmt)
    await _offload(_check_decoder_channels, cli, stacks, chinfo.get("names"))
    if not chinfo.get("samplerate") and not (fmt and "samplerate=" in fmt):
        raise ValidationFailed(
            "입력 파일에 samplerate 가 없어 디코드할 수 없습니다.",
            hint="raw/csv 입력이면 input_format 에 정수 Hz samplerate 를 넣어라 (예 'binary:numchannels=8:samplerate=1000000').",
        )
    sig_dir = case.subdir("signals")
    first_pd = _parse_stack(stacks[0])[0][0]
    out_path = _reserve_named(sig_dir, name, ".txt") if name else _unique_path(sig_dir, f"{src.stem}.{first_pd}", ".txt")
    tmp_path = sig_dir / f".{out_path.name}.partial"
    argv = [cli.path, f"--input-file={src}"]
    if fmt:
        argv.append(f"--input-format={fmt}")
    argv += [f"--protocol-decoders={s}" for s in stacks]
    if ann:
        argv.append(f"--protocol-decoder-annotations={ann}")
    if samplenum:
        argv.append("--protocol-decoder-samplenum")
    cls = classify_sigrok_argv(argv, policy=_policy())
    if cls.risk != Risk.OBSERVE:  # pragma: no cover - 방어 (디코드는 항상 오프라인)
        _remove_quiet_if_empty(out_path)
        return _policy_denied("sigrok_decode", {"input": case.rel(src), "decoders": stacks}, cls, case.id)
    est_samples = None
    info = chinfo.get("info")
    if info is not None:
        est_samples = info.total_samples if info.format == "srzip" else (info.end_tick - info.start_tick if info.end_tick else None)
    big = (est_samples or 0) > 50_000_000 or src.stat().st_size > 64 * 1024 * 1024
    bg = background if background is not None else big
    timeout = _clamp_timeout(timeout_s, MAX_TIMEOUT_S if bg else DECODE_SYNC_TIMEOUT_S)
    extra = {"input": case.rel(src), "decoders": stacks, "annotations": ann, "input_format": fmt, "samplenum": bool(samplenum)}
    warnings: list[str] = []
    if chinfo.get("format") == "vcd" and est_samples and est_samples > 200_000_000 and not (fmt and "downsample" in fmt):
        warnings.append(f"VCD timescale 이 미세해 샘플 수가 {est_samples} 로 펼쳐짐 — 느리면 input_format='vcd:downsample=<n>' 사용")
    if not ann:
        warnings.append("annotations 미지정 → 모든 annotation 클래스가 출력됨 (예: 'uart=rx-data' 로 줄일 수 있음)")
    if bg:
        def job_fn(jctx: Any) -> dict[str, Any]:
            res = _decode_worker(argv, out_path, tmp_path, timeout, lambda: jctx.cancelled, max_lines, case, extra,
                                 progress=lambda d, t, m: jctx.progress(d, t, m))
            res["warnings"] = warnings + res.get("warnings", [])
            return res

        try:
            job = r.jobs.start("sigrok-decode", job_fn, description=f"sigrok 디코드 {case.rel(src)} → {case.rel(out_path)}",
                               case_id=case.id, meta={"planned_output": case.rel(out_path)})
        except BaseException:
            _remove_quiet_if_empty(out_path)
            raise
        return {"ok": True, "status": "started", "job_id": job.id, "planned_output": case.rel(out_path), "warnings": warnings,
                "message": f"큰 입력이라 백그라운드로 디코드한다. sigrok_job_status(job_id='{job.id}', wait_seconds=30) 로 폴링하라."}

    def work(cancel_event: threading.Event) -> dict[str, Any]:
        try:
            return _decode_worker(argv, out_path, tmp_path, timeout, cancel_event.is_set, max_lines, case, extra)
        finally:
            _remove_quiet_if_empty(out_path)

    result = await _run_cancellable(work)
    result["warnings"] = warnings + result.get("warnings", [])
    result["input_path"] = case.rel(src)
    result["channels_source"] = chinfo.get("source")
    return result


@server.tool(
    description=(
        "신호 파일 형식 변환 (예: srzip(.sr) → vcd, vcd → srzip, csv). output_format 은 sigrok_list(kind='output-formats') 의 id "
        "(옵션 가능: 'csv:label=channel'). 결과는 signals/ 에 저장하고 아티팩트(signal-capture) 등록. .sr 에 아날로그 채널이 섞여 있고 "
        "로직 전용 형식(vcd 등)으로 변환하면 로직 채널만 선택해 출력이 오염되지 않게 한다."
    ),
    annotations=ANN_LOCAL_WRITE,
)
@safe_tool
async def sigrok_export(
    case_id: str,
    input_path: str,
    output_format: str = "vcd",
    output_name: str | None = None,
    input_format: str | None = None,
    timeout_s: float | None = None,
) -> dict[str, Any]:
    r = rt()
    case = r.case(case_id)
    src = _resolve_input(case, input_path)
    ofmt = _validate_format_spec(output_format, "output_format") or "vcd"
    oid = ofmt.split(":")[0]
    if oid == "null":
        raise ValidationFailed("null 출력은 의미가 없습니다.")
    cli = _cli()
    sup = await _offload(cli.supported)
    if oid not in {o["id"] for o in sup["output_formats"]}:
        raise ValidationFailed(f"지원하지 않는 출력 형식: {oid}", hint=f"사용 가능: {[o['id'] for o in sup['output_formats']]}")
    ifmt = _auto_input_format(src, _validate_format_spec(input_format, "input_format"))
    name = validate_output_name(output_name)
    sig_dir = case.subdir("signals")
    ext = OUTPUT_EXT.get(oid, f".{oid}")
    out_path = _reserve_named(sig_dir, name, ext) if name else _unique_path(sig_dir, src.stem, ext)
    tmp_path = sig_dir / f".{out_path.stem}.partial{ext}"
    warnings: list[str] = []
    channel_arg = None
    if sig.detect_format(src) == "srzip" and not ifmt:
        info = await _offload(sig.read_srzip_info, src)
        if info.analog_channels and oid in LOGIC_ONLY_OUTPUTS:
            logic = [c.name for c in info.channels]
            if logic and all(re.fullmatch(r"[A-Za-z0-9_.]+", n) for n in logic):
                channel_arg = ",".join(logic)
                warnings.append(f"아날로그 채널 {info.analog_channels} 은 {oid} 출력에서 제외함")
            else:
                warnings.append("아날로그 채널이 섞여 있어 출력에 아날로그 텍스트가 섞일 수 있음")
    argv = [cli.path, f"--input-file={src}"]
    if ifmt:
        argv.append(f"--input-format={ifmt}")
    if channel_arg:
        argv.append(f"--channels={channel_arg}")
    argv += [f"--output-format={ofmt}", f"--output-file={tmp_path}"]
    cls = classify_sigrok_argv(argv, policy=_policy(), allowed_output_dir=sig_dir)
    if cls.risk != Risk.OBSERVE:  # pragma: no cover - 방어
        _remove_quiet_if_empty(out_path)
        return _policy_denied("sigrok_export", {"input": case.rel(src), "output_format": ofmt}, cls, case.id)
    timeout = _clamp_timeout(timeout_s, 300.0)

    def work(cancel_event: threading.Event) -> dict[str, Any]:
        _remove_quiet(tmp_path)
        try:
            res = run_process(argv, timeout=timeout, cancel=cancel_event.is_set, env=child_env(), cwd=sig_dir)
            rep = check_result(res, "sigrok-cli 변환")
        except BaseException:
            _remove_quiet(tmp_path)
            _remove_quiet_if_empty(out_path)
            raise
        if not tmp_path.exists() or tmp_path.stat().st_size == 0:
            _remove_quiet(tmp_path)
            _remove_quiet_if_empty(out_path)
            raise PwehError("변환 결과 파일이 만들어지지 않았다 (입력에 데이터가 없거나 형식이 맞지 않음).", code="sigrok_no_output",
                            data={"stderr": tail_text(res.stderr, 1500)})
        os.replace(tmp_path, out_path)
        out: dict[str, Any] = {"stderr_warnings": [w["line"] for w in rep.warnings]}
        if oid in ("vcd", "srzip"):
            try:
                oinfo = sig.load_info(out_path)
                out["output_info"] = {"channels": [c.name for c in oinfo.channels], "samplerate": oinfo.samplerate,
                                      "total_samples": oinfo.total_samples, "duration_s": oinfo.duration_s, "warnings": oinfo.warnings}
            except PwehError as exc:
                out["output_info_error"] = str(exc)
        return out

    extra_out = await _run_cancellable(work)
    art = case.register_artifact(out_path, kind="signal-capture", producer=PRODUCER,
                                 description=f"{case.rel(src)} → {ofmt} 변환", extra={"source": case.rel(src), "output_format": ofmt})
    return {"ok": True, "output_path": case.rel(out_path), "absolute_path": str(out_path), "artifact": art,
            "output_format": ofmt, "input_path": case.rel(src), "warnings": warnings + extra_out.pop("stderr_warnings", []),
            **extra_out, "command": _display_argv(argv)}


# ---------------------------------------------------------------------------
# 순수 Python 분석
# ---------------------------------------------------------------------------


@server.tool(
    description=(
        "신호 파일 요약 (순수 Python, sigrok-cli 불필요 — srzip/VCD): 형식, samplerate, 채널, 샘플 수, 길이, 채널별 활동(에지 수, high 비율, "
        "처음/끝 레벨). 어느 채널에 신호가 있는지(UART 후보) 고를 때 사용. 그 밖의 형식은 sigrok-cli 로 요약."
    ),
    annotations=ANN_READ_ONLY,
)
@safe_tool
async def sigrok_file_info(case_id: str, input_path: str, input_format: str | None = None) -> dict[str, Any]:
    case = rt().case(case_id)
    src = _resolve_input(case, input_path)
    fmt = sig.detect_format(src)
    if fmt in ("srzip", "vcd") and not input_format:
        info, act = await _offload(sig.activity, src)
        d = info.to_dict()
        d["path"] = case.rel(src)
        chans = act["channels"]
        uart_like = [c["name"] for c in chans if c.get("edges", 0) >= 20 and (c.get("initial_level") == c.get("final_level"))]
        return {"ok": True, **d, "activity": chans, "activity_truncated": act.get("truncated", False),
                "uart_candidates": uart_like,
                "note": "에지가 많고 처음/끝 레벨이 같은(idle) 채널이 UART 후보다. sigrok_estimate_baud 로 확인."}
    cli = _cli()
    props = await _offload(cli.input_props, str(src), _validate_format_spec(input_format, "input_format"))
    return {"ok": True, "path": case.rel(src), "format": (input_format or "auto"), **props, "source": "sigrok-cli"}


def _estimate_auto(src: Path, data_bits: int, parity: str, max_channels: int = 4) -> dict[str, Any]:
    fmt = sig.detect_format(src)
    per: list[dict[str, Any]] = []
    results: list[dict[str, Any]] = []
    if fmt == "vcd":
        info, edges = sig.read_vcd(src, want=None, max_edges=300_000)
        cands = sorted(edges.values(), key=lambda e: (e.initial_level != e.level_at_end(), -len(e.edges)))[:max_channels]
        for ce in cands:
            if len(ce.edges) < 20:
                continue
            results.append(baudmod.estimate_baud(ce, data_bits=data_bits, parity=parity))
    elif fmt == "srzip":
        info = sig.read_srzip_info(src)
        act = sig.srzip_activity(src, info)
        cands_a = sorted((c for c in act["channels"] if c.get("edges", 0) >= 20),
                         key=lambda c: (c.get("initial_level") != c.get("final_level"), -c["edges"]))[:max_channels]
        for c in cands_a:
            ce = sig.srzip_channel_edges(src, info, info.channel(c["name"]), max_edges=300_000)
            results.append(baudmod.estimate_baud(ce, data_bits=data_bits, parity=parity))
    else:
        raise ValidationFailed(f"보드레이트 추정은 srzip(.sr)/VCD 만 지원: {src.name}", hint="sigrok_export 로 srzip 변환 후 다시 시도")
    for r_ in results:
        per.append({k: r_.get(k) for k in ("channel", "baudrate", "confidence", "idle_level", "samples_per_bit")}
                   | {"frame_error_rate": (r_.get("frame_check") or {}).get("error_rate")})
    if not results:
        return {"baudrate": None, "confidence": 0.0, "idle_level": None, "candidates": [], "channel": None,
                "warnings": ["에지가 20개 이상인 채널이 없음 — 라인이 idle 이거나 프로브/GND/캡처 시점 문제"], "per_channel": per,
                "samplerate": info.samplerate}
    best = max(results, key=lambda r_: (r_.get("confidence") or 0.0, (r_.get("frame_check") or {}).get("frames") or 0))
    best = dict(best)
    best["per_channel"] = per
    best["auto_selected_channel"] = True
    return best


def _parse_parity(parity: Any) -> str:
    p = str(parity or "none").strip().lower()
    p = {"n": "none", "e": "even", "o": "odd", "mark": "one", "space": "zero", "m": "one", "s": "zero"}.get(p, p)
    if p not in ("none", "even", "odd", "zero", "one", "ignore"):
        raise ValidationFailed(f"잘못된 parity: {parity!r}", hint="none | even | odd | zero(space) | one(mark) | ignore")
    return p


def _parse_data_bits(v: Any) -> int:
    try:
        n = int(v)
    except (TypeError, ValueError):
        raise ValidationFailed(f"data_bits 는 5~9 정수: {v!r}")
    if not 5 <= n <= 9:
        raise ValidationFailed(f"data_bits 는 5~9 정수: {v!r}")
    return n


@server.tool(
    description=(
        "순수 Python 오프라인 UART 보드레이트 추정 (.sr/.vcd, sigrok-cli 불필요). 펄스 폭 분포 → 비트 시간(근사 GCD) → 표준 보드레이트 "
        "(300~3000000, 1500000 포함)에 스냅, 8N1 프레임 검사로 T/2 모호성·idle 극성(반전 라인) 판정. 반환: baudrate, baudrate_raw, confidence(0~1), "
        "idle_level(1=정상, 0=반전→invert_rx=yes), candidates, samples_per_bit, frame_check, warnings(4배 미만 오버샘플링 등), "
        "segments(구간별 보드레이트 혼재), suggested_decoder. channel 생략 시 활동 채널을 모두 평가해 최선을 고른다."
    ),
    annotations=ANN_READ_ONLY,
)
@safe_tool
async def sigrok_estimate_baud(
    case_id: str,
    input_path: str,
    channel: str | int | None = None,
    data_bits: int = 8,
    parity: str = "none",
) -> dict[str, Any]:
    case = rt().case(case_id)
    src = _resolve_input(case, input_path)
    db = _parse_data_bits(data_bits)
    par = _parse_parity(parity)

    def work() -> dict[str, Any]:
        if channel is None or (isinstance(channel, str) and channel.strip().lower() in ("", "auto")):
            return _estimate_auto(src, db, par)
        info, ce = sig.load_channel_edges(src, channel)
        return baudmod.estimate_baud(ce, data_bits=db, parity=par)

    res = await _offload(work)
    out = {"ok": True, "input_path": case.rel(src), **res}
    if res.get("baudrate"):
        out["recommended_samplerate"] = baudmod.recommend_samplerate(res["baudrate"])
    return out


def _uart_sigrok(cli: SigrokCli, src: Path, case: Case, ch: str, b: int, inverted: bool, db: int, par: str,
                 timeout: float, cancel: Callable[[], bool], fmt: str | None) -> dict[str, Any]:
    stack = f"uart:rx={ch}:baudrate={b}:data_bits={db}:parity={par}:format=hex" + (":invert_rx=yes" if inverted else "")
    sig_dir = case.subdir("signals")
    out_txt = _unique_path(sig_dir, f"{src.stem}.{ch}.uart-{b}", ".txt")
    tmp = sig_dir / f".{out_txt.name}.partial"
    argv = [cli.path, f"--input-file={src}"]
    if fmt:
        argv.append(f"--input-format={fmt}")
    argv += [f"--protocol-decoders={stack}", "--protocol-decoder-annotations=uart=rx-data:rx-warnings", "--protocol-decoder-samplenum"]
    extra = {"decoders": [stack], "annotations": "uart=rx-data:rx-warnings", "input": case.rel(src), "input_format": fmt}
    try:
        res = _decode_worker(argv, out_txt, tmp, timeout, cancel, 20, case, extra)
    finally:
        _remove_quiet_if_empty(out_txt)
    if not res.get("ok"):
        return res
    data = bytearray()
    fe = 0
    starts: list[int] = []
    hexre = re.compile(r"^[0-9A-Fa-f]{2,3}$")
    with open(out_txt, "r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            a = parse_annotation_line(line)
            if not a:
                continue
            t = a["text"]
            if hexre.match(t):
                v = int(t, 16)
                if db > 8:
                    data += v.to_bytes(2, "big")
                else:
                    data.append(v & 0xFF)
                if a["ss"] is not None and len(starts) < 1_000_000:
                    starts.append(a["ss"])
            elif "error" in t.lower():
                fe += 1
    return {"engine": "sigrok-cli", "decoder": stack, "data": bytes(data), "framing_errors": fe,
            "decode_text_path": res["output_path"], "decode_artifact": res.get("artifact"), "command": res.get("command"),
            "sigrok_warnings": res.get("warnings", [])}


def _autodecode_run(case: Case, src: Path, *, channel: Any, forced_baud: int | None, db: int, par: str, preview_n: int,
                    cli: SigrokCli | None, timeout: float, cancel: Callable[[], bool]) -> dict[str, Any]:
    """추정 → 디코드(sigrok-cli 또는 순수 Python) → 결과 파일/미리보기. 동기 호출과 백그라운드 작업 공용."""
    if channel is None or (isinstance(channel, str) and channel.strip().lower() in ("", "auto")):
        est = _estimate_auto(src, db, par)
    else:
        _info, ce = sig.load_channel_edges(src, channel)
        est = baudmod.estimate_baud(ce, data_bits=db, parity=par)
    b = forced_baud or est.get("baudrate")
    ch = est.get("channel")
    if not b or ch is None:
        return {"ok": False, "status": "baud_not_determined", "input_path": case.rel(src),
                "message": "보드레이트를 추정하지 못했다 (estimate.warnings 참고). 채널/캡처를 확인하거나 baudrate 를 지정하라.",
                "estimate": est}
    idle = est.get("idle_level")
    inverted = idle == 0
    warnings = list(est.get("warnings", []))
    if (est.get("confidence") or 0) < 0.5 and not forced_baud:
        warnings.append(f"추정 신뢰도가 낮음({est.get('confidence')}) — 결과 텍스트가 깨지면 candidates 의 다른 보드레이트를 baudrate 로 지정")
    sig_dir = case.subdir("signals")
    if cli is not None:
        fmt = None
        if sig.detect_format(src) == "vcd":
            info = sig.load_info(src)
            fmt = "vcd"
            if info.tick_hz and info.tick_hz > b * 64:
                ds = int(info.tick_hz // (b * 32))
                if ds >= 2:
                    fmt = f"vcd:downsample={ds}"
        dec = _uart_sigrok(cli, src, case, str(ch), int(b), inverted, db, par, timeout, cancel, fmt)
        if dec.get("ok") is False:
            return {**dec, "estimate": est}
    else:
        _info, ce = sig.load_channel_edges(src, ch)
        d = baudmod.uart_decode(ce, ce.tick_hz / b, 1 if idle is None else int(idle), data_bits=db, parity=par,
                                max_frames=4_000_000)
        data_py = bytearray()
        for v in d.values:
            if db > 8:
                data_py += v.to_bytes(2, "big")
            else:
                data_py.append(v & 0xFF)
        dec = {"engine": "python", "decoder": f"python-uart {b} {db}{par[0].upper()}1" + (" inverted" if inverted else ""),
               "data": bytes(data_py), "framing_errors": d.framing_errors + d.parity_errors}
        warnings.append("sigrok-cli 가 없어 순수 Python 디코더를 사용함")
    data: bytes = dec.pop("data")
    bin_path = _unique_path(sig_dir, f"{src.stem}.{ch}.uart-{b}", ".bin")
    bin_path.write_bytes(data)
    bin_art = case.register_artifact(bin_path, kind="signal-decode", producer=PRODUCER,
                                     description=f"UART {b} baud 디코드 바이트 ({ch})",
                                     extra={"input": case.rel(src), "channel": ch, "baudrate": b, "engine": dec.get("engine")})
    text = baudmod.render_text(data, preview_n)
    hints = baudmod.boot_hints(data)
    printable = sum(1 for x in data if 0x20 <= x < 0x7F or x in (9, 10, 13))
    ratio = round(printable / len(data), 3) if data else None
    if data and ratio is not None and ratio < 0.7:
        warnings.append(f"출력 가능 문자 비율 {ratio * 100:.0f}% — 보드레이트/극성/데이터 형식이 틀렸거나 바이너리 데이터일 수 있음")
    if not data:
        warnings.append("디코드된 바이트가 없음")
    return {
        "ok": True,
        "input_path": case.rel(src),
        "channel": ch,
        "baudrate": b,
        "baudrate_source": "user" if forced_baud else "estimate",
        "inverted": inverted,
        "data_bits": db,
        "parity": par,
        "estimate": {k: est.get(k) for k in ("baudrate", "baudrate_raw", "confidence", "idle_level", "samples_per_bit",
                                              "candidates", "frame_check", "segments", "per_channel") if k in est},
        **dec,
        "bytes_decoded": len(data),
        "printable_ratio": ratio,
        "text_preview": text,
        "hex_preview": data[:256].hex(" "),
        "boot_hints": hints,
        "bytes_path": case.rel(bin_path),
        "bytes_artifact": bin_art,
        "warnings": warnings,
        "uart_estimate": {"channel": ch, "baudrate": b, "confidence": est.get("confidence"), "idle_level": idle},
    }


@server.tool(
    description=(
        "UART 자동 디코드: sigrok_estimate_baud 로 보드레이트/idle 극성을 추정한 뒤(또는 baudrate 지정) sigrok-cli uart 디코더"
        "(format=hex, 반전 시 invert_rx=yes)로 디코드해 ASCII 미리보기(text_preview), 16진 미리보기, 프레임 오류 수, 부트 로그 힌트(U-Boot 배너, "
        "autoboot 프롬프트, 커널 버전/cmdline, mtdparts, login 등)와 uart_estimate(signal-capture 스키마용)를 반환. 디코드 텍스트(.txt)와 "
        "바이트(.bin)는 signals/ 에 저장·등록. engine: auto(sigrok-cli 있으면 사용, 없으면 순수 Python) | sigrok | python. "
        "큰 입력은 background(자동 판단)로 job 실행."
    ),
    annotations=ANN_LOCAL_WRITE,
)
@safe_tool
async def sigrok_uart_autodecode(
    case_id: str,
    input_path: str,
    channel: str | int | None = None,
    baudrate: int | None = None,
    data_bits: int = 8,
    parity: str = "none",
    max_preview_bytes: int = 4096,
    engine: str = "auto",
    background: bool | None = None,
    timeout_s: float | None = None,
) -> dict[str, Any]:
    r = rt()
    case = r.case(case_id)
    src = _resolve_input(case, input_path)
    db = _parse_data_bits(data_bits)
    par = _parse_parity(parity)
    eng = (engine or "auto").strip().lower()
    if eng not in ("auto", "sigrok", "sigrok-cli", "python"):
        raise ValidationFailed(f"잘못된 engine: {engine!r}", hint="auto | sigrok | python")
    try:
        preview_n = max(64, min(int(max_preview_bytes), 65536))
    except (TypeError, ValueError):
        raise ValidationFailed("max_preview_bytes 는 정수")
    forced_baud = None
    if baudrate is not None:
        try:
            forced_baud = int(baudrate)
        except (TypeError, ValueError):
            raise ValidationFailed(f"baudrate 는 정수: {baudrate!r}")
        if not 50 <= forced_baud <= 50_000_000:
            raise ValidationFailed(f"baudrate 범위 밖: {forced_baud}")
    if sig.detect_format(src) not in ("srzip", "vcd"):
        raise ValidationFailed(f"UART 자동 디코드는 srzip(.sr)/VCD 만 지원: {src.name}", hint="sigrok_export 로 srzip 변환 후 다시 시도")
    cli: SigrokCli | None = None
    if eng in ("auto", "sigrok", "sigrok-cli"):
        try:
            cli = _cli()
        except ToolMissing:
            if eng != "auto":
                raise
            cli = None
    info = await _offload(sig.load_info, src)
    est_samples = info.total_samples if info.format == "srzip" else None
    big = (est_samples or 0) > 100_000_000 or src.stat().st_size > 128 * 1024 * 1024
    bg = background if background is not None else big
    timeout = _clamp_timeout(timeout_s, MAX_TIMEOUT_S if bg else DECODE_SYNC_TIMEOUT_S)
    kwargs = dict(channel=channel, forced_baud=forced_baud, db=db, par=par, preview_n=preview_n, cli=cli, timeout=timeout)
    if bg:
        def job_fn(jctx: Any) -> dict[str, Any]:
            jctx.log(f"UART 자동 디코드 시작: {case.rel(src)}")
            return _autodecode_run(case, src, cancel=lambda: jctx.cancelled, **kwargs)  # type: ignore[arg-type]

        job = r.jobs.start("sigrok-uart-autodecode", job_fn, description=f"UART 자동 디코드 {case.rel(src)}", case_id=case.id,
                           meta={"input": case.rel(src)})
        return {"ok": True, "status": "started", "job_id": job.id, "input_path": case.rel(src),
                "message": f"큰 입력이라 백그라운드로 실행한다. sigrok_job_status(job_id='{job.id}', wait_seconds=30) 로 폴링하라."}

    def work(cancel_event: threading.Event) -> dict[str, Any]:
        return _autodecode_run(case, src, cancel=cancel_event.is_set, **kwargs)  # type: ignore[arg-type]

    return await _run_cancellable(work)


register_job_tools(server, rt, "sigrok")


def main() -> None:
    server.run()


if __name__ == "__main__":
    main()
