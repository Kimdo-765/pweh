"""OpenOCD 덤프 작업 엔진 (백그라운드 job 안에서 실행).

메모리: 청크마다 ``dump_image {케이스/.이름.chunk} 주소 길이`` → 크기 확인 → ``.part`` 에 덧붙이고 ``.state.json`` 갱신.
        OpenOCD 가 쓴 파일이 보이지 않으면(원격 호스트의 OpenOCD 에 attach 한 경우 등) ``read_memory`` 루프로 전환.
        ``read_memory`` 가 없는 0.11 은 ``mdw``/``mdb`` 출력 파싱으로 전환.
플래시: 청크마다 ``flash read_bank 뱅크 {케이스/.이름.chunk} 오프셋 길이``.
공통: 재시도, 재개(resume), 선택적 재읽기 검증(verify), 완료 시 sha256 + 메타데이터 JSON + 아티팩트 등록.

안전: 작업 시작 전과 매 명령 전에 ``guard.ensure_job_commands_safe`` 로 모든 명령이 INTERACT 이하인지 확인한다.
호스트 파일을 쓰는 dump_image / flash read_bank 는 경로가 케이스 디렉터리(out_dir) 안일 때만 허용된다.
점 없는 타깃의 ``<타깃> read_memory …`` 는 시작 전에 서버가 ``target names`` 로 확인한 이름(``spec.trusted_targets``)일
때만 접두를 떼고 분류된다.
"""

from __future__ import annotations

import hashlib
import logging
import os
import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from pweh.case import Case
from pweh.errors import CaseError, DeviceError, PwehError, TimeoutExpired, ValidationFailed
from pweh.fsutil import atomic_write_json, read_json, utcnow_iso
from pweh.jobs import JobCancelled, JobContext

from . import guard
from .parsers import (
    diagnose,
    parse_dumped_bytes,
    parse_md,
    parse_read_bank_bytes,
    parse_read_memory,
    parse_verify_bank,
    values_to_bytes,
)
from .rpc import RequestCancelled, TclConnectionClosed, TclRpcClient
from .tcl import brace_quote_path

log = logging.getLogger("pweh.openocd")

NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,95}$")
MIN_CHUNK = 256
MAX_CHUNK = 16 * 1024 * 1024
READ_MEMORY_MAX_ELEMS = 16384  # 한 번의 read_memory 응답 크기 제한 (~180 KB 텍스트)
NO_RETRY_CODES = {"target_not_halted", "memory_unsupported", "target_not_examined"}


class ChunkError(Exception):
    def __init__(self, message: str, *, retry: bool = True) -> None:
        super().__init__(message)
        self.retry = retry


class FileNotVisible(Exception):
    """OpenOCD 가 기록했다고 하지만 이 서버에서 파일이 보이지 않음 (원격 OpenOCD 등)."""


def sanitize_name(name: str) -> str:
    n = (name or "").strip()
    if n.lower().endswith(".bin"):
        n = n[:-4]
    if not NAME_RE.match(n):
        raise ValidationFailed(f"잘못된 output_name: {name!r}", hint="영문/숫자/._- 만 사용 (최대 96자, 확장자 .bin 은 자동)")
    return n


@dataclass
class DumpSpec:
    kind: str  # memory | flash
    case: Case
    out_dir: Path
    name: str
    length: int
    chunk_size: int
    address: int | None = None
    bank: str | None = None
    offset: int = 0
    flash_info: dict[str, Any] | None = None
    target: str | None = None
    method: str = "auto"  # memory: auto | dump_image | read_memory
    verify: bool = False
    retries: int = 2
    chunk_timeout: float | None = None
    artifact_kind: str = "memory-dump"
    endian: str = "little"
    resume: bool = True
    remote: bool = False  # OpenOCD 가 다른 호스트에 있음 → dump_image 파일을 볼 수 없음
    openocd: dict[str, Any] = field(default_factory=dict)
    start_offset: int = 0
    # 시작 전에 서버가 OpenOCD 'target names' 로 확인한 타깃 (점 없는 '<타깃> read_memory …' 분류용, identity 에는 넣지 않음)
    trusted_targets: frozenset[str] = frozenset()

    # -- 경로 ---------------------------------------------------------------
    @property
    def final(self) -> Path:
        return self.out_dir / f"{self.name}.bin"

    @property
    def part(self) -> Path:
        return self.out_dir / f"{self.name}.part"

    @property
    def state(self) -> Path:
        return self.out_dir / f"{self.name}.state.json"

    @property
    def meta(self) -> Path:
        return self.out_dir / f"{self.name}.json"

    @property
    def tmp(self) -> Path:
        return self.out_dir / f".{self.name}.chunk"

    @property
    def tmp2(self) -> Path:
        return self.out_dir / f".{self.name}.chunk2"

    def identity(self) -> dict[str, Any]:
        """재개 가능 여부를 판단하는 파라미터."""
        if self.kind == "memory":
            return {"kind": "memory", "address": self.address, "length": self.length, "target": self.target}
        return {"kind": "flash", "bank": str(self.bank), "offset": self.offset, "length": self.length}

    def source(self) -> dict[str, Any]:
        if self.kind == "memory":
            assert self.address is not None
            return {"type": "memory", "address": f"0x{self.address:x}", "length": self.length, "target": self.target, "endian": self.endian}
        fi = self.flash_info or {}
        return {
            "type": "flash",
            "bank": self.bank,
            "bank_name": fi.get("name"),
            "driver": fi.get("driver"),
            "flash_base": fi.get("base"),
            "flash_size": fi.get("size"),
            "offset": self.offset,
            "length": self.length,
        }


# ---------------------------------------------------------------------------
# 준비 (도구 호출 시점, 동기)
# ---------------------------------------------------------------------------


def prepare(spec: DumpSpec) -> DumpSpec:
    """출력 경로 검사와 재개 지점 결정. 문제가 있으면 예외 (작업 시작 전)."""
    if spec.length <= 0:
        raise ValidationFailed("length 는 1 이상이어야 합니다")
    if not (MIN_CHUNK <= spec.chunk_size <= MAX_CHUNK):
        raise ValidationFailed(f"chunk_size 는 {MIN_CHUNK}~{MAX_CHUNK} 바이트여야 합니다")
    spec.out_dir.mkdir(parents=True, exist_ok=True)
    # 경로를 Tcl 로 안전하게 인용할 수 있어야 한다 (중괄호/백슬래시/제어문자 금지)
    try:
        brace_quote_path(str(spec.tmp))
    except ValueError as exc:
        raise CaseError(str(exc), hint="케이스 디렉터리 경로에 { } \\ 또는 제어문자가 없어야 dump_image/flash read_bank 를 쓸 수 있습니다.") from exc
    if spec.final.exists():
        raise CaseError(
            f"이미 같은 이름의 덤프가 있습니다: {spec.case.rel(spec.final)}",
            hint="다른 output_name 을 지정하세요 (기존 결과는 덮어쓰지 않습니다).",
        )
    state = read_json(spec.state) if spec.state.exists() else None
    if state is not None:
        same = state.get("identity") == spec.identity()
        if not spec.resume:
            _unlink(spec.part)
            _unlink(spec.state)
            spec.start_offset = 0
        elif not same:
            raise CaseError(
                f"같은 이름으로 진행 중인 다른 덤프가 있습니다: {spec.case.rel(spec.state)}",
                hint="다른 output_name 을 쓰거나, 기존 진행분을 버리려면 resume=false 로 호출하세요.",
                data={"existing": state.get("identity"), "requested": spec.identity()},
            )
        else:
            done = int(state.get("done", 0))
            part_size = spec.part.stat().st_size if spec.part.exists() else 0
            spec.start_offset = max(0, min(done, part_size, spec.length))
    elif spec.part.exists():
        if spec.resume:
            raise CaseError(
                f"상태 파일 없는 .part 파일이 있습니다: {spec.case.rel(spec.part)}",
                hint="재개할 수 없습니다. 처음부터 다시 받으려면 resume=false 로 호출하세요.",
            )
        _unlink(spec.part)
        spec.start_offset = 0
    return spec


def planned_commands(spec: DumpSpec) -> list[str]:
    """작업이 보낼 수 있는 명령 견본 (시작 전 안전 검사용)."""
    off = spec.start_offset if spec.start_offset < spec.length else 0
    n = min(spec.chunk_size, spec.length - off) or 1
    cmds: list[str] = []
    if spec.kind == "memory":
        assert spec.address is not None
        a = spec.address + off
        cmds.append(_target_prefix(spec) + _dump_image_cmd(spec.tmp, a, n))
        if spec.verify:
            cmds.append(_target_prefix(spec) + _dump_image_cmd(spec.tmp2, a, n))
        cmds.append(_read_memory_cmd(spec, a, 32, max(1, n // 4)))
        cmds.append(_read_memory_cmd(spec, a, 8, n))
        cmds.append(_md_cmd(spec, a, 4, max(1, n // 4)))
        cmds.append(_md_cmd(spec, a, 1, n))
    else:
        cmds.append(_read_bank_cmd(spec, spec.offset + off, n, spec.tmp))
        if spec.verify:
            cmds.append(_verify_bank_cmd(spec, spec.offset + off, spec.tmp))
    return cmds


def _target_prefix(spec: DumpSpec) -> str:
    return f"targets {spec.target}; " if spec.target else ""


def _dump_image_cmd(path: Path, addr: int, n: int) -> str:
    return f"dump_image {brace_quote_path(str(path))} 0x{addr:x} 0x{n:x}"


def _read_memory_cmd(spec: DumpSpec, addr: int, width: int, count: int) -> str:
    prefix = f"{spec.target} " if spec.target else ""
    return f"{prefix}read_memory 0x{addr:x} {width} {count}"


def _md_cmd(spec: DumpSpec, addr: int, width_bytes: int, count: int) -> str:
    name = {8: "mdd", 4: "mdw", 2: "mdh", 1: "mdb"}[width_bytes]
    prefix = f"{spec.target} " if spec.target else ""
    return f"{prefix}{name} 0x{addr:x} {count}"


def _read_bank_cmd(spec: DumpSpec, off: int, n: int, path: Path) -> str:
    return f"flash read_bank {spec.bank} {brace_quote_path(str(path))} 0x{off:x} 0x{n:x}"


def _verify_bank_cmd(spec: DumpSpec, off: int, path: Path) -> str:
    return f"flash verify_bank {spec.bank} {brace_quote_path(str(path))} 0x{off:x}"


def _unlink(p: Path) -> None:
    try:
        p.unlink()
    except FileNotFoundError:
        pass
    except OSError as exc:  # pragma: no cover
        log.warning("unlink failed %s: %s", p, exc)


# ---------------------------------------------------------------------------
# 실행 (job 스레드)
# ---------------------------------------------------------------------------


class DumpRunner:
    def __init__(
        self,
        spec: DumpSpec,
        jctx: JobContext,
        client: TclRpcClient,
        *,
        unknown_risk: str,
        process_alive: Callable[[], bool] | None = None,
        audit: Callable[[dict[str, Any]], None] | None = None,
    ) -> None:
        self.spec = spec
        self.j = jctx
        self.client = client
        self.unknown_risk = unknown_risk
        self.process_alive = process_alive or (lambda: True)
        self.audit = audit or (lambda ev: None)
        self.allowed_dirs = [spec.out_dir]
        self.method = spec.method
        if spec.kind == "memory" and self.method == "auto":
            self.method = "read_memory" if spec.remote else "dump_image"
        if spec.kind == "flash":
            self.method = "flash_read_bank"
        self.throughput: float | None = None  # bytes/s
        self.retries_used = 0
        self.chunks = 0
        self.method_switches: list[str] = []

    # -- 공통 -------------------------------------------------------------
    def _send(self, cmd: str, timeout: float):
        guard.ensure_job_commands_safe(
            [cmd], allowed_dirs=self.allowed_dirs, unknown_risk=self.unknown_risk, trusted_targets=self.spec.trusted_targets
        )
        try:
            return self.client.call(cmd, timeout=timeout, cancel_check=lambda: self.j.cancelled)
        except RequestCancelled:
            raise JobCancelled()
        except TclConnectionClosed as exc:
            if not self.process_alive():
                raise DeviceError("덤프 중 OpenOCD 프로세스가 종료되었습니다.", hint="openocd_status 로 로그 확인 후 다시 시작하고, 같은 output_name 으로 재개하세요.") from exc
            raise ChunkError(f"연결 끊김: {exc}") from exc

    def _timeout(self, n: int) -> float:
        if self.spec.chunk_timeout:
            return float(self.spec.chunk_timeout)
        if self.throughput:
            return max(15.0, min(900.0, 4.0 * n / self.throughput + 5.0))
        return max(30.0, min(900.0, n / 2048.0 + 30.0))

    def _write_state(self, done: int, started_at: str) -> None:
        atomic_write_json(
            self.spec.state,
            {
                "schema": "pweh.openocd-dump-state/v1",
                "identity": self.spec.identity(),
                "done": done,
                "length": self.spec.length,
                "chunk_size": self.spec.chunk_size,
                "method": self.method,
                "job_id": self.j.job.id,
                "started_at": started_at,
                "updated_at": utcnow_iso(),
            },
        )

    # -- 메모리 -----------------------------------------------------------
    def _mem_dump_image(self, addr: int, n: int, timeout: float) -> bytes:
        spec = self.spec
        data = self._dump_image_once(spec.tmp, addr, n, timeout)
        if spec.verify:
            again = self._dump_image_once(spec.tmp2, addr, n, timeout)
            if again != data:
                raise ChunkError(f"재읽기 검증 불일치 @0x{addr:x} (신호 품질/속도 문제 가능)")
        return data

    def _dump_image_once(self, path: Path, addr: int, n: int, timeout: float) -> bytes:
        _unlink(path)
        cmd = _target_prefix(self.spec) + _dump_image_cmd(path, addr, n)
        reply = self._send(cmd, timeout)
        if not reply.ok:
            _unlink(path)
            err = reply.error_text or "(OpenOCD 가 오류 메시지 없이 실패)"
            codes = {d["code"] for d in diagnose(err)}
            raise ChunkError(f"dump_image 실패 @0x{addr:x}: {err}", retry=not (codes & NO_RETRY_CODES))
        reported = parse_dumped_bytes(reply.output)
        if not path.exists():
            raise FileNotVisible(f"OpenOCD 가 기록한 파일이 보이지 않습니다: {path} (보고된 크기={reported})")
        data = path.read_bytes()
        _unlink(path)
        if len(data) != n:
            raise ChunkError(f"dump_image 크기 불일치 @0x{addr:x}: 기대 {n}, 실제 {len(data)} (보고 {reported})")
        return data

    def _mem_read_memory(self, addr: int, n: int, timeout: float) -> bytes:
        data = self._read_memory_once(addr, n, timeout)
        if self.spec.verify:
            if self._read_memory_once(addr, n, timeout) != data:
                raise ChunkError(f"재읽기 검증 불일치 @0x{addr:x}")
        return data

    def _read_memory_once(self, addr: int, n: int, timeout: float) -> bytes:
        width = 32 if (addr % 4 == 0 and n % 4 == 0) else 8
        wb = width // 8
        total = n // wb
        out = bytearray()
        pos = 0
        while pos < total:
            self.j.check_cancelled()
            cnt = min(READ_MEMORY_MAX_ELEMS, total - pos)
            a = addr + pos * wb
            reply = self._send(_read_memory_cmd(self.spec, a, width, cnt), timeout)
            if not reply.ok:
                err = reply.error_text
                if "invalid command name" in err and "read_memory" in err:
                    # 0.11 계열: read_memory 없음 → md 파싱으로 전환
                    self.method = "md"
                    self.method_switches.append("read_memory→md (read_memory 명령 없음)")
                    return self._md_once(addr, n, timeout)
                codes = {d["code"] for d in diagnose(err)}
                raise ChunkError(f"read_memory 실패 @0x{a:x}: {err}", retry=not (codes & NO_RETRY_CODES))
            vals, perr = parse_read_memory(reply.output)
            if perr or len(vals) != cnt:
                raise ChunkError(f"read_memory 응답 해석 실패 @0x{a:x}: 값 {len(vals)}/{cnt} ({perr or '개수 불일치'})")
            out += values_to_bytes(vals, wb, self.spec.endian)
            pos += cnt
        return bytes(out)

    def _md_once(self, addr: int, n: int, timeout: float) -> bytes:
        wb = 4 if (addr % 4 == 0 and n % 4 == 0) else 1
        total = n // wb
        out = bytearray()
        pos = 0
        while pos < total:
            self.j.check_cancelled()
            cnt = min(4096, total - pos)
            a = addr + pos * wb
            reply = self._send(_md_cmd(self.spec, a, wb, cnt), timeout)
            if not reply.ok:
                raise ChunkError(f"md 실패 @0x{a:x}: {reply.error_text}")
            pairs = parse_md(reply.output)
            if len(pairs) != cnt or (pairs and pairs[0][0] != a):
                raise ChunkError(f"md 응답 해석 실패 @0x{a:x}: {len(pairs)}/{cnt}")
            out += values_to_bytes([v for _, v in pairs], wb, self.spec.endian)
            pos += cnt
        return bytes(out)

    # -- 플래시 -----------------------------------------------------------
    def _flash_read(self, off: int, n: int, timeout: float) -> bytes:
        spec = self.spec
        _unlink(spec.tmp)
        reply = self._send(_read_bank_cmd(spec, off, n, spec.tmp), timeout)
        if not reply.ok:
            _unlink(spec.tmp)
            err = reply.error_text or "(OpenOCD 가 오류 메시지 없이 실패 — 범위 밖 오프셋/길이일 수 있음)"
            codes = {d["code"] for d in diagnose(err)}
            raise ChunkError(f"flash read_bank 실패 @+0x{off:x}: {err}", retry=not (codes & NO_RETRY_CODES))
        if not spec.tmp.exists():
            raise FileNotVisible(f"OpenOCD 가 기록한 파일이 보이지 않습니다: {spec.tmp}")
        data = spec.tmp.read_bytes()
        if len(data) != n:
            _unlink(spec.tmp)
            raise ChunkError(f"flash read_bank 크기 불일치 @+0x{off:x}: 기대 {n}, 실제 {len(data)} (보고 {parse_read_bank_bytes(reply.output)})")
        if spec.verify:
            vr = self._send(_verify_bank_cmd(spec, off, spec.tmp), timeout)
            match = parse_verify_bank(vr.output + "\n" + vr.log)
            if not vr.ok or match is not True:
                _unlink(spec.tmp)
                raise ChunkError(f"flash verify_bank 불일치/실패 @+0x{off:x}: {vr.error_text or vr.output}")
        _unlink(spec.tmp)
        return data

    # -- 청크 + 재시도 ------------------------------------------------------
    def _read_chunk(self, pos: int, n: int) -> bytes:
        spec = self.spec
        attempt = 0
        timeout = self._timeout(n)
        while True:
            self.j.check_cancelled()
            try:
                if spec.kind == "flash":
                    return self._flash_read(spec.offset + pos, n, timeout)
                assert spec.address is not None
                if self.method == "dump_image":
                    return self._mem_dump_image(spec.address + pos, n, timeout)
                if self.method == "md":
                    return self._md_once(spec.address + pos, n, timeout)
                return self._mem_read_memory(spec.address + pos, n, timeout)
            except FileNotVisible as exc:
                if spec.kind == "memory" and spec.method == "auto" and self.method == "dump_image":
                    self.method = "read_memory"
                    self.method_switches.append(f"dump_image→read_memory ({exc})")
                    self.j.log(f"dump_image 파일이 보이지 않아 read_memory 로 전환: {exc}")
                    continue
                raise DeviceError(
                    str(exc),
                    hint="OpenOCD 가 다른 호스트/컨테이너에서 실행 중이면 파일을 볼 수 없습니다. 메모리는 method='read_memory' 로, "
                    "플래시는 로컬에서 OpenOCD 를 실행(openocd_start)한 뒤 다시 시도하세요.",
                ) from exc
            except TimeoutExpired as exc:
                attempt += 1
                self.retries_used += 1
                self.j.log(f"청크 시간 초과 @+0x{pos:x} (시도 {attempt}): {exc.message}")
                if attempt > spec.retries:
                    raise
                timeout = min(1800.0, timeout * 2)
            except ChunkError as exc:
                attempt += 1
                self.retries_used += 1
                self.j.log(f"청크 실패 @+0x{pos:x} (시도 {attempt}): {exc}")
                if not exc.retry or attempt > spec.retries:
                    hint = "같은 output_name 으로 다시 호출하면 이어서 받습니다(resume)."
                    codes = {d["code"] for d in diagnose(str(exc))}
                    if "target_not_halted" in codes:
                        hint = "타깃을 먼저 halt 하세요(openocd_halt). Cortex-A 는 mem_ap 타깃을 target 인자로 지정하면 halt 없이 읽을 수 있습니다. " + hint
                    raise DeviceError(str(exc), hint=hint, data={"diagnosis": diagnose(str(exc))}) from exc
                time.sleep(min(2.0, 0.3 * attempt))

    def run(self) -> dict[str, Any]:
        spec = self.spec
        started_at = utcnow_iso()
        t0 = time.monotonic()
        done = spec.start_offset
        resumed_from = done
        mode = "r+b" if spec.part.exists() else "wb"
        self.j.update_meta(output=spec.case.rel(spec.final), method=self.method)
        self.j.progress(done, spec.length, message=f"시작 (재개 지점 {done} 바이트)" if done else "시작")
        self._write_state(done, started_at)
        try:
            with open(spec.part, mode) as out:
                out.seek(done)
                out.truncate()
                while done < spec.length:
                    self.j.check_cancelled()
                    n = min(spec.chunk_size, spec.length - done)
                    c0 = time.monotonic()
                    data = self._read_chunk(done, n)
                    dt = max(1e-3, time.monotonic() - c0)
                    rate = len(data) / dt
                    self.throughput = rate if self.throughput is None else 0.7 * self.throughput + 0.3 * rate
                    out.write(data)
                    out.flush()
                    os.fsync(out.fileno())
                    done += n
                    self.chunks += 1
                    self._write_state(done, started_at)
                    self.j.progress(done, spec.length, message=f"{done}/{spec.length} 바이트, {self.throughput / 1024:.1f} KiB/s ({self.method})")
        except JobCancelled:
            self.j.log(f"취소됨: {done}/{spec.length} 바이트 보존 ({spec.case.rel(spec.part)})")
            self.j.update_meta(partial=spec.case.rel(spec.part), done=done)
            raise
        except PwehError as exc:
            exc.data = {**(exc.data or {}), "done": done, "length": spec.length, "partial": spec.case.rel(spec.part), "state": spec.case.rel(spec.state)}
            raise
        finally:
            _unlink(spec.tmp)
            _unlink(spec.tmp2)
        # 완료
        os.replace(spec.part, spec.final)
        sha = _sha256(spec.final)
        size = spec.final.stat().st_size
        duration = time.monotonic() - t0
        meta = {
            "schema": "pweh.openocd-dump/v1",
            "case_id": spec.case.id,
            "kind": spec.artifact_kind,
            "method": "jtag-openocd",
            "transfer": self.method,
            "transfer_switches": self.method_switches,
            "source": spec.source(),
            "output": {"path": spec.case.rel(spec.final), "sha256": sha, "size": size},
            "verification": {
                "method": "size-only",
                "match": size == spec.length,
                "reread": bool(spec.verify),
                "detail": ("청크마다 두 번 읽어 비교" if spec.kind == "memory" else "청크마다 flash verify_bank") if spec.verify else "청크 크기만 확인",
            },
            "chunks": {"size": spec.chunk_size, "count": self.chunks, "retries": self.retries_used, "resumed_from": resumed_from},
            "openocd": spec.openocd,
            "duration_seconds": round(duration, 3),
            "throughput_kib_s": round((size - resumed_from) / 1024 / duration, 2) if duration > 0 else None,
            "started_at": started_at,
            "finished_at": utcnow_iso(),
            "job_id": self.j.job.id,
        }
        atomic_write_json(spec.meta, meta)
        _unlink(spec.state)
        art = spec.case.register_artifact(
            spec.final,
            kind=spec.artifact_kind,
            producer="openocd-mcp",
            description=_describe(spec),
            extra={"metadata": spec.case.rel(spec.meta), "source": spec.source(), "transfer": self.method},
        )
        self.audit({"event": "openocd_dump_completed", "output": spec.case.rel(spec.final), "sha256": sha, "size": size, "transfer": self.method})
        return {
            "path": spec.case.rel(spec.final),
            "absolute_path": str(spec.final),
            "metadata_path": spec.case.rel(spec.meta),
            "size": size,
            "sha256": sha,
            "transfer": self.method,
            "transfer_switches": self.method_switches,
            "chunks": self.chunks,
            "retries": self.retries_used,
            "resumed_from": resumed_from,
            "duration_seconds": round(duration, 3),
            "artifact": art,
            "source": spec.source(),
        }


def _describe(spec: DumpSpec) -> str:
    if spec.kind == "memory":
        return f"OpenOCD 메모리 덤프 0x{spec.address:x} +{spec.length} 바이트" + (f" (타깃 {spec.target})" if spec.target else "")
    fi = spec.flash_info or {}
    return f"OpenOCD 플래시 덤프 bank {spec.bank} ({fi.get('driver')}) 오프셋 0x{spec.offset:x} +{spec.length} 바이트"


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for block in iter(lambda: fh.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


__all__ = ["DumpRunner", "DumpSpec", "planned_commands", "prepare", "sanitize_name"]
