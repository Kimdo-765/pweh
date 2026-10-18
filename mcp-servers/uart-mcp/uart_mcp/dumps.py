"""UART 덤프 작업 엔진 (백그라운드 job 스레드에서 실행).

U-Boot (``uboot_dump_start``) — 청크마다:
    ``sf read <ram> <off> <len>`` (또는 ``nand read`` / ``mmc read``, source=ram 이면 생략)
    → ``md.b <ram> <len>`` → 코어 ``parse_md_b_output`` 으로 주소 연속성·바이트 수 검증
    → ``crc32 <ram> <len>`` → 호스트 zlib crc32 와 비교 (crc32 명령이 없으면 같은 범위를 두 번 읽어 비교)
리눅스 셸 (``shell_dump_start``) — 청크마다:
    ``dd if=<path> bs=<bs> skip=<n> count=<k> 2>/dev/null | base64`` (또는 ``| hexdump -C``) 파싱
    → 같은 범위 ``… | md5sum`` 과 호스트 md5 비교

공통: 실패한 청크는 retries 번 다시 시도하고, 그래도 실패하면 명확한 오류로 끝난다. 좋은 청크마다
``dumps/<name>.bin.part`` 와 ``dumps/<name>.state.json`` 을 갱신하므로 취소·실패·서버 재시작 뒤 같은 인자로 다시
시작하면(resume=True) 다음 청크부터 이어 받는다. 끝나면 ``dumps/<name>.bin`` + ``dumps/<name>.json``(firmware-dump
스키마 필드) + 아티팩트 등록.

안전: 시작 전에 모든 계획 명령이 INTERACT 이하인지 확인했고(도구), 작업은 명령마다 ``console.job_command`` 로
같은 분류기에 다시 넣어 INTERACT 를 넘거나 문맥이 바뀌면 멈춘다. 취소되면 Ctrl-C(INTERACT)로 출력을 끊고
프롬프트를 되찾은 뒤 끝낸다.
"""

from __future__ import annotations

import hashlib
import logging
import math
import os
import re
import time
import zlib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from pweh.case import Case
from pweh.errors import CaseError, DeviceError, PwehError, SafetyDenied, ValidationFailed
from pweh.fsutil import atomic_write_json, read_json, sha256_file, utcnow_iso
from pweh.jobs import JobCancelled, JobContext

from . import console
from .parsers import chars_per_byte, parse_base64, parse_crc32, parse_hexdump_c, parse_md5sum, parse_md_b, proc_mtd
from .session import UartSession

log = logging.getLogger("pweh.uart")

NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,95}$")
MIN_CHUNK = 256
MAX_CHUNK = 256 * 1024  # md.b 출력은 데이터의 약 4.9배 → 링 버퍼(4 MiB)보다 훨씬 작게
SHELL_PATH_RE = re.compile(r"^/[A-Za-z0-9_./+-]+$")
PROBE_TEXT = b"pweh\n"


class ChunkError(Exception):
    """재시도할 수 있는 청크 오류."""


class FatalChunkError(Exception):
    """재시도해도 소용없는 오류 (명령 없음, 사용법 오류 등)."""


def sanitize_name(name: str) -> str:
    n = (name or "").strip()
    if n.lower().endswith(".bin"):
        n = n[:-4]
    if not NAME_RE.match(n):
        raise ValidationFailed(f"잘못된 output_name: {name!r}", hint="영문/숫자/._- 만 사용 (최대 96자, .bin 은 자동)")
    return n


@dataclass
class DumpFiles:
    case: Case
    name: str

    @property
    def dir(self) -> Path:
        return self.case.subdir("dumps")

    @property
    def final(self) -> Path:
        return self.dir / f"{self.name}.bin"

    @property
    def part(self) -> Path:
        return self.dir / f"{self.name}.bin.part"

    @property
    def state(self) -> Path:
        return self.dir / f"{self.name}.state.json"

    @property
    def meta(self) -> Path:
        return self.dir / f"{self.name}.json"


def prepare_resume(files: DumpFiles, identity: dict[str, Any], *, resume: bool, chunk_size: int, length: int) -> tuple[int, dict[str, Any]]:
    """(시작 청크, 상태) — 기존 .part/.state.json 을 검사해 이어받을 위치를 정한다."""
    if files.final.exists():
        raise CaseError(f"이미 완료된 덤프가 있습니다: {files.case.rel(files.final)}",
                        hint="다른 output_name 을 쓰세요 (기존 결과는 덮어쓰지 않습니다).")
    st = read_json(files.state) if files.state.exists() else None
    if st and resume:
        if st.get("identity") != identity:
            raise ValidationFailed(
                "같은 이름의 진행 중 덤프(.state.json)가 다른 인자로 시작되었습니다.",
                hint="같은 인자로 다시 부르면 이어 받습니다. 처음부터 받으려면 resume=false, 따로 받으려면 다른 output_name.",
                data={"existing": st.get("identity"), "requested": identity})
        done = int(st.get("completed_chunks", 0))
        size = files.part.stat().st_size if files.part.exists() else 0
        done = min(done, size // chunk_size if chunk_size else 0, math.ceil(length / chunk_size))
        if done * chunk_size > length:
            done = math.ceil(length / chunk_size)
        keep = min(done * chunk_size, length)
        if files.part.exists():
            with open(files.part, "r+b") as fh:
                fh.truncate(keep)
        else:
            files.part.touch()
        st["completed_chunks"] = done
        st["chunk_checks"] = list(st.get("chunk_checks", []))[:done]
        return done, st
    for p in (files.part, files.state):
        if p.exists():
            p.unlink()
    files.part.touch()
    st = {"schema": "pweh.uart-dump-state/v1", "identity": identity, "completed_chunks": 0, "chunk_checks": [],
          "retries_total": 0, "runs": [], "created_at": utcnow_iso()}
    atomic_write_json(files.state, st)
    return 0, st


def check_resume_identity(files: DumpFiles, identity: dict[str, Any], *, resume: bool, partial: bool = False) -> int | None:
    """도구 단계 검사 (job 시작 전): 같은 이름의 진행 중 덤프(.state.json)가 다른 인자로 시작됐으면 ValidationFailed.

    반환: 이어 받을 청크 수 (진행 중 덤프가 없거나 resume=False 면 None — 그때는 job 이 처음부터 받는다).
    partial=True 면 identity 에 준 키만 대조한다 (셸 덤프의 length/method 는 job 안에서 정해질 수 있다).
    """
    if not resume or not files.state.exists():
        return None
    try:
        st = read_json(files.state) or {}
    except (OSError, ValueError) as exc:
        raise ValidationFailed(f"진행 중 덤프 상태 파일을 읽을 수 없습니다: {files.case.rel(files.state)} ({exc})",
                               hint="처음부터 받으려면 resume=false, 따로 받으려면 다른 output_name.")
    existing = st.get("identity") or {}
    keys = list(identity) if partial else sorted(set(existing) | set(identity))
    differs = [k for k in keys if existing.get(k) != identity.get(k)]
    if differs:
        raise ValidationFailed(
            "같은 이름의 진행 중 덤프(.state.json)가 다른 인자로 시작되었습니다 "
            f"(다른 값: {', '.join(f'{k}={existing.get(k)!r}→{identity.get(k)!r}' for k in differs)}).",
            hint="같은 인자로 다시 부르면 이어 받습니다. 처음부터 받으려면 resume=false, 따로 받으려면 다른 output_name.",
            data={"existing": existing, "requested": identity, "differs": differs})
    done = int(st.get("completed_chunks", 0))
    chunk = int(existing.get("chunk_size") or identity.get("chunk_size") or 0)
    if chunk:  # prepare_resume 과 같은 규칙: .part 가 없으면 0 부터
        size = files.part.stat().st_size if files.part.exists() else 0
        done = min(done, size // chunk)
    return done


def _write_chunk(files: DumpFiles, index: int, chunk_size: int, data: bytes) -> None:
    with open(files.part, "r+b") as fh:
        fh.seek(index * chunk_size)
        fh.write(data)
        fh.truncate(index * chunk_size + len(data))
        fh.flush()
        os.fsync(fh.fileno())


def _md_timeout(nbytes: int, baud: int, method: str, bits_per_char: float = 10.0) -> float:
    """덤프 출력 대기 시간: 예상 전송 시간(문자 수 × 문자당 비트 / baud) × 2.5 + 10초, 최소 15초."""
    chars = nbytes * chars_per_byte(method) + 400
    secs = chars * max(7.0, bits_per_char) / max(300, baud)
    return max(15.0, secs * 2.5 + 10.0)


def _end_run(files: DumpFiles, state: dict[str, Any], t0: float, status: str, error: str | None = None) -> None:
    """이번 실행의 끝(상태·소요 시간)을 state['runs'] 마지막 항목에 기록하고, 진행 중 파일이 남아 있으면 저장한다."""
    runs = state.get("runs") or []
    if runs:
        runs[-1].update({"finished_at": utcnow_iso(), "duration_seconds": round(time.monotonic() - t0, 2), "status": status,
                         "completed_chunks": state.get("completed_chunks", 0)})
        if error:
            runs[-1]["error"] = error[:300]
    if files.part.exists():  # 완료(.part → .bin) 뒤에는 state 를 다시 만들지 않는다
        try:
            atomic_write_json(files.state, state)
        except OSError as exc:  # pragma: no cover - 디스크 오류
            log.warning("dump state write failed: %s", exc)


def _runs_total_seconds(runs: list[dict[str, Any]]) -> float:
    """재개를 포함한 전체 실행 시간 합계 (각 실행의 duration_seconds)."""
    return round(sum(float(r.get("duration_seconds") or 0.0) for r in runs), 2)


_SF_READ_OK_RE = re.compile(r"SF: (\d+) bytes @ (0x[0-9a-fA-F]+|0) Read: (\S+)")


def _check_load_output(ld: str, output: str, off: int, n: int) -> None:
    """적재 명령(sf/nand/mmc read) 출력 검사. 확인 줄이 있으면 바이트 수·오프셋·OK 까지 맞아야 한다.

    방언: hisilicon-2016 은 빈 줄 + 'SF: N bytes @ 0x.. Read: OK', ingenic 은 그 줄 + '--->read spend N ms',
    hisilicon-2010(legacy)은 빈 줄만 → 확인 줄이 없으면 오류 문구만 본다. C 의 %#x 는 0 을 '0' 으로 찍는다.
    """
    if re.search(r"(?i)unknown command|usage:", output):
        raise FatalChunkError(f"적재 명령 실패: {output[-200:]!r}")
    if re.search(r"(?i)past flash size|out of range", output):
        raise FatalChunkError(f"범위가 플래시 크기를 넘습니다: {output[-200:]!r}")
    if re.search(r"(?i)bad block", output):
        # nand read 는 배드 블록을 건너뛰고 다음 블록에서 채운다 → 청크 단위로 읽으면 뒤 청크와 데이터가 겹쳐 이미지가 어긋난다
        raise FatalChunkError(f"NAND 배드 블록이 범위 안에 있습니다 (청크 단위 nand read 는 데이터가 밀려 1:1 이미지가 아님): {output[-200:]!r}")
    if _LOAD_ERROR_RE.search(output):
        raise ChunkError(f"적재 명령 오류: {output[-200:]!r}")
    if ld.startswith("sf "):
        m = _SF_READ_OK_RE.search(output)
        if m is not None:
            got_n, got_off, status = int(m.group(1)), int(m.group(2), 16) if m.group(2) != "0" else 0, m.group(3)
            if status != "OK" or got_n != n or got_off != off:
                raise ChunkError(f"sf read 확인 줄이 요청과 다름 (요청 {n} 바이트 @0x{off:x}): {m.group(0)!r}")


@dataclass
class UBootDumpSpec:
    case: Case
    files: DumpFiles
    source: str  # sf | nand | mmc | ram
    offset: int
    length: int
    chunk_size: int
    ram_addr: int | None
    verify: str  # crc32 | double | none
    retries: int
    resume: bool
    final_check: bool
    sf_probe: str | None
    ram_window_end: int | None
    dram: tuple[int, int] | None
    flash_size: int | None
    partition: str | None = None
    kind: str = "flash-dump"
    notes: list[str] = field(default_factory=list)

    def identity(self) -> dict[str, Any]:
        return {"method": "uboot-md", "source": self.source, "offset": self.offset, "length": self.length, "chunk_size": self.chunk_size}

    def chunks(self) -> int:
        return math.ceil(self.length / self.chunk_size)

    def chunk_range(self, i: int) -> tuple[int, int]:
        off = self.offset + i * self.chunk_size
        return off, min(self.chunk_size, self.offset + self.length - off)

    def load_line(self, off: int, n: int) -> str | None:
        ram = self.ram_addr
        if self.source == "sf":
            return f"sf read 0x{ram:x} 0x{off:x} 0x{n:x}"
        if self.source == "nand":
            return f"nand read 0x{ram:x} 0x{off:x} 0x{n:x}"
        if self.source == "mmc":
            return f"mmc read 0x{ram:x} 0x{off // 512:x} 0x{n // 512:x}"
        return None

    def mem_addr(self, off: int) -> int:
        return off if self.source == "ram" else int(self.ram_addr or 0)

    def planned_lines(self) -> list[str]:
        lines: list[str] = []
        if self.source == "sf" and self.sf_probe is not None:
            lines.append(f"sf probe {self.sf_probe}".strip())
        for i in range(self.chunks()):
            off, n = self.chunk_range(i)
            ld = self.load_line(off, n)
            if ld:
                lines.append(ld)
            a = self.mem_addr(off)
            lines.append(f"md.b 0x{a:x} 0x{n:x}")
            if self.verify == "crc32":
                lines.append(f"crc32 0x{a:x} 0x{n:x}")
        if self.final_check and self.source == "sf" and self.verify == "crc32":
            lines.append(f"sf read 0x{int(self.ram_addr or 0):x} 0x{self.offset:x} 0x{self.length:x}")
            lines.append(f"crc32 0x{int(self.ram_addr or 0):x} 0x{self.length:x}")
        return lines


_LOAD_ERROR_RE = re.compile(r"(?i)no spi flash selected|failed to initialize|attempting .* past flash size|out of range|"
                            r"\bERROR\b|bad block|is not aligned|usage:|unknown command|invalid")


class _Runner:
    """작업 공통: 명령 실행 + 취소 처리 + 진행률.

    check_auth: 명령마다 케이스 소유/허가 증명을 다시 확인하는 함수 (도구가 넘긴다 — 작업 도중 증명이 철회되면
    다음 명령을 보내지 않고 멈춘다). 출력을 끊는 Ctrl-C(abort_output)는 멈추는 동작이라 확인하지 않는다.
    """

    def __init__(self, jctx: JobContext, session: UartSession, contexts: tuple[str, ...],
                 check_auth: Callable[[], Any] | None = None) -> None:
        self.jctx = jctx
        self.session = session
        self.contexts = contexts
        self.check_auth = check_auth
        self.commands = 0

    def cancelled(self) -> bool:
        return self.jctx.cancelled

    def run(self, line: str, timeout: float) -> console.CommandResult:
        self.jctx.check_cancelled()
        if self.check_auth is not None:
            self.check_auth()
        self.commands += 1
        res = console.job_command(self.session, line, timeout=timeout, cancel=self.cancelled, contexts=self.contexts,
                                  source=f"job:{self.jctx.job.id}")
        if res.cancelled:
            self.abort_output()
            raise JobCancelled()
        if res.disconnected:
            raise DeviceError("작업 중 포트 연결이 끊어졌습니다.", code="disconnected",
                              hint="연결을 복구하고 uart_close → uart_open 후 같은 인자로 다시 시작하면 이어 받습니다.")
        return res

    def abort_output(self) -> None:
        """진행 중인 명령 출력을 Ctrl-C 로 끊고 프롬프트를 되찾는다 (U-Boot md 는 ctrlc() 를 폴링한다)."""
        try:
            cur = console.send_ctrl_c(self.session, source=f"job:{self.jctx.job.id}", note="cancel")
            self.session.wait_response(cur, 5.0)
        except Exception as exc:  # noqa: BLE001
            log.warning("cancel ctrl-c failed: %s", exc)


def _progress(jctx: JobContext, *, done_bytes: int, total_bytes: int, run_start_done: int, t_run: float, msg: str) -> None:
    remaining_at_start = max(1, total_bytes - run_start_done)
    done_run = max(0, done_bytes - run_start_done)
    elapsed = time.monotonic() - t_run
    eta = None
    if done_run > 0:
        eta = round(elapsed * (total_bytes - done_bytes) / done_run)
    jctx.update_meta(overall_done_bytes=done_bytes, overall_total_bytes=total_bytes,
                     overall_progress=round(done_bytes / max(1, total_bytes), 4), eta_seconds_estimate=eta)
    jctx.progress(done_run, remaining_at_start, f"{msg} — 전체 {100.0 * done_bytes / max(1, total_bytes):.1f}%"
                  + (f", 남은 시간 약 {eta}s" if eta is not None else ""))


def run_uboot_dump(jctx: JobContext, session: UartSession, spec: UBootDumpSpec, *, register: Callable[..., Any],
                   check_auth: Callable[[], Any] | None = None) -> dict[str, Any]:
    t0 = time.monotonic()
    started_at = utcnow_iso()
    files = spec.files
    start_chunk, state = prepare_resume(files, spec.identity(), resume=spec.resume, chunk_size=spec.chunk_size, length=spec.length)
    nchunks = spec.chunks()
    baud = session.settings.baudrate
    state.setdefault("runs", []).append({"started_at": started_at, "resumed_from": start_chunk, "session_id": session.id,
                                         "port": session.port, "baudrate": baud, "ram_addr": spec.ram_addr})
    atomic_write_json(files.state, state)
    runner = _Runner(jctx, session, ("uboot",), check_auth)
    retries_total = int(state.get("retries_total", 0))
    verify = spec.verify
    notes = list(spec.notes)
    jctx.log(f"U-Boot 덤프 시작: {spec.source} 0x{spec.offset:x}+0x{spec.length:x}, 청크 0x{spec.chunk_size:x} × {nchunks}, 시작 청크 {start_chunk}")

    def save_partial(status: str) -> dict[str, Any]:
        part = {"status": status, "part_path": files.case.rel(files.part), "state_path": files.case.rel(files.state),
                "completed_chunks": state["completed_chunks"], "total_chunks": nchunks,
                "completed_bytes": min(state["completed_chunks"] * spec.chunk_size, spec.length),
                "resume_hint": "같은 인자로 uboot_dump_start 를 다시 부르면 이어서 받습니다 (resume=true)."}
        jctx.set_partial(part)
        return part

    save_partial("running")
    try:
        # 1) U-Boot 프롬프트 확인 (Ctrl-C → <INTERRUPT> + 프롬프트)
        s = console.sync(session, timeout=3.0, cancel=runner.cancelled, source=f"job:{jctx.job.id}")
        if session.context != "uboot":
            raise DeviceError(f"U-Boot 프롬프트를 확인하지 못했습니다 (문맥 {session.context}, 응답 {s.get('reply')!r}).", code="context_changed")
        # 2) sf probe
        if spec.source == "sf" and spec.sf_probe is not None and start_chunk < nchunks:
            res = runner.run(f"sf probe {spec.sf_probe}".strip(), 20.0)
            if res.timed_out or re.search(r"(?i)failed|no spi|usage|unknown command|invalid", res.output):
                raise DeviceError(f"sf probe 실패: {res.output[-300:]!r}", code="sf_probe_failed",
                                  hint="SPI NOR 가 아닐 수 있습니다(NAND/eMMC → source=nand|mmc). uboot_info 로 flash 정보를 확인하세요.")
        t_run = time.monotonic()
        run_start_done = min(start_chunk * spec.chunk_size, spec.length)
        for i in range(start_chunk, nchunks):
            jctx.check_cancelled()
            off, n = spec.chunk_range(i)
            mem = spec.mem_addr(off)
            reasons: list[str] = []
            good: tuple[bytes, dict[str, Any]] | None = None
            for attempt in range(spec.retries + 1):
                try:
                    good = _uboot_chunk(runner, spec, off, n, mem, baud, verify)
                    break
                except FatalChunkError as exc:
                    if "crc32-unavailable" in str(exc) and verify == "crc32":
                        verify = "double"
                        notes.append("기기에 crc32 명령이 없어 같은 범위를 두 번 읽어 비교하는 방식(double)으로 바꿨습니다.")
                        jctx.log(notes[-1])
                        continue
                    save_partial("failed")
                    state["retries_total"] = retries_total
                    atomic_write_json(files.state, state)
                    raise DeviceError(f"청크 {i} (@0x{off:x}) 실패: {exc}", code="dump_failed")
                except ChunkError as exc:
                    reasons.append(f"시도 {attempt + 1}: {exc}")
                    retries_total += 1
                    jctx.log(f"청크 {i} @0x{off:x} 재시도 ({exc})")
                    session.event({"type": "dump_retry", "chunk": i, "offset": off, "reason": str(exc)[:300]})
                    # 다음 시도 전에 프롬프트를 확실히 되찾는다
                    if session.prompt_at_tail() is None:
                        runner.abort_output()
            if good is None:
                save_partial("failed")
                state["retries_total"] = retries_total
                atomic_write_json(files.state, state)
                raise DeviceError(
                    f"청크 {i} (@0x{off:x}, {n} 바이트)를 {spec.retries + 1}회 시도했지만 검증에 실패했습니다: {' / '.join(reasons[-3:])}",
                    code="dump_chunk_failed",
                    hint="배선 잡음/보드레이트 문제일 수 있습니다. chunk_size 를 줄이거나 연결을 점검한 뒤 같은 인자로 다시 시작하면 이 청크부터 이어 받습니다.")
            data, check = good
            _write_chunk(files, i, spec.chunk_size, data)
            state["completed_chunks"] = i + 1
            state["chunk_checks"].append(check)
            state["retries_total"] = retries_total
            state["updated_at"] = utcnow_iso()
            atomic_write_json(files.state, state)
            save_partial("running")
            _progress(jctx, done_bytes=min((i + 1) * spec.chunk_size, spec.length), total_bytes=spec.length,
                      run_start_done=run_start_done, t_run=t_run, msg=f"청크 {i + 1}/{nchunks} @0x{off:x} 검증 {check.get('method')}")
        # 3) 전체 crc32 대조 (RAM 창에 전체가 들어갈 때만)
        full_check: dict[str, Any] | None = None
        blob_crc = _file_crc32(files.part)
        if spec.final_check and spec.source == "sf" and verify == "crc32":
            ram = int(spec.ram_addr or 0)
            if spec.ram_window_end is not None and ram + spec.length <= spec.ram_window_end:
                try:
                    res = runner.run(f"sf read 0x{ram:x} 0x{spec.offset:x} 0x{spec.length:x}", 30.0 + spec.length / 200_000)
                    res2 = runner.run(f"crc32 0x{ram:x} 0x{spec.length:x}", 30.0 + spec.length / 2_000_000)
                    c = parse_crc32(res2.output)
                    full_check = {"device_crc32": f"{c['crc32']:08x}" if c else None, "host_crc32": f"{blob_crc:08x}",
                                  "match": bool(c and c["crc32"] == blob_crc and c["start"] == ram and c["end"] == ram + spec.length - 1)}
                except (DeviceError, SafetyDenied) as exc:
                    full_check = {"skipped": f"전체 검증 명령 실패: {exc}"}
                if full_check.get("match") is False:
                    raise DeviceError(f"청크는 모두 검증됐지만 전체 crc32 가 다릅니다 ({full_check}).", code="dump_full_crc_mismatch",
                                      hint="플래시 내용이 덤프 도중 바뀌었을 수 있습니다(기기가 스스로 쓰기?). resume=false 로 다시 받으세요.")
            else:
                full_check = {"skipped": "전체 범위가 확인된 RAM 창에 들어가지 않거나 RAM 창을 모름 (uboot_info 로 확인)"}
        source = {
            "type": spec.source,
            "flash_type": {"sf": "spi-nor", "nand": "nand", "mmc": "mmc", "ram": None}.get(spec.source),
            "flash_size": spec.flash_size,
            "offset": spec.offset,
            "length": spec.length,
            "partition": spec.partition,
            "ram_addr": None if spec.ram_addr is None else f"0x{spec.ram_addr:x}",
            "device_path": None,
        }
        return _finalize(jctx, session, files, state, length=spec.length, chunk_size=spec.chunk_size, kind=spec.kind, source=source,
                         started_at=started_at, t0=t0, method="uboot-md", verify=verify, retries_total=retries_total,
                         start_chunk=start_chunk, notes=notes, full_check=full_check, register=register)
    except BaseException as exc:
        # 취소·실패로 끝나도 부분 결과(partial_result)와 state 의 실행 기록에 최종 상태를 남긴다
        status = "cancelled" if isinstance(exc, JobCancelled) else "failed"
        state["retries_total"] = retries_total
        _end_run(files, state, t0, status, None if status == "cancelled" else f"{type(exc).__name__}: {exc}")
        save_partial(status)
        raise


def _uboot_chunk(runner: _Runner, spec: UBootDumpSpec, off: int, n: int, mem: int, baud: int, verify: str) -> tuple[bytes, dict[str, Any]]:
    bits = runner.session.settings.bits_per_char
    ld = spec.load_line(off, n)
    if ld:
        res = runner.run(ld, 15.0 + n / 50_000)
        if res.timed_out:
            raise ChunkError(f"{ld.split()[0]} read 응답 시간 초과")
        _check_load_output(ld, res.output, off, n)
    md_line = f"md.b 0x{mem:x} 0x{n:x}"
    res = runner.run(md_line, _md_timeout(n, baud, "md.b", bits))
    if res.timed_out:
        raise ChunkError("md.b 출력이 시간 안에 끝나지 않음 (프롬프트 없음)")
    if res.lost:
        raise ChunkError("md.b 출력이 링 버퍼보다 커서 일부를 잃었습니다 (chunk_size 를 줄이세요)")
    if re.search(r"(?i)unknown command 'md", res.output):
        raise FatalChunkError(f"md 명령이 없습니다: {res.output[-200:]!r}")
    data, problems = parse_md_b(res.output, mem, n)
    if problems:
        raise ChunkError("md.b 파싱 문제: " + "; ".join(problems[:3]))
    host_crc = zlib.crc32(data) & 0xFFFFFFFF
    check: dict[str, Any] = {"offset": off, "length": n, "host_crc32": f"{host_crc:08x}"}
    if verify == "crc32":
        res2 = runner.run(f"crc32 0x{mem:x} 0x{n:x}", 15.0 + n / 1_000_000)
        if res2.timed_out:
            raise ChunkError("crc32 응답 시간 초과")
        c = parse_crc32(res2.output)
        if c is None:
            if re.search(r"(?i)unknown command 'crc32'", res2.output):
                raise FatalChunkError("crc32-unavailable")
            raise ChunkError(f"crc32 출력을 해석할 수 없음: {res2.output[-120:]!r}")
        if c["start"] != mem or c["end"] != mem + n - 1:
            raise ChunkError(f"crc32 범위 불일치 0x{c['start']:x}..0x{c['end']:x}")
        if c["crc32"] != host_crc:
            raise ChunkError(f"crc32 불일치 (기기 {c['crc32']:08x}, 호스트 {host_crc:08x})")
        check.update({"method": "crc32", "device_crc32": f"{c['crc32']:08x}"})
    elif verify == "double":
        res3 = runner.run(md_line, _md_timeout(n, baud, "md.b", bits))
        if res3.timed_out:
            raise ChunkError("두 번째 md.b 출력이 시간 안에 끝나지 않음 (프롬프트 없음)")
        data2, problems2 = parse_md_b(res3.output, mem, n)
        if problems2 or data2 != data:
            raise ChunkError("두 번 읽은 md.b 결과가 다름" + (f" ({'; '.join(problems2[:2])})" if problems2 else ""))
        check["method"] = "double-read"
    else:
        check["method"] = "format-only"
    return data, check


def _file_crc32(path: Path) -> int:
    crc = 0
    with open(path, "rb") as fh:
        while True:
            block = fh.read(1 << 20)
            if not block:
                break
            crc = zlib.crc32(block, crc)
    return crc & 0xFFFFFFFF


def _finalize(jctx: JobContext, session: UartSession, files: DumpFiles, state: dict[str, Any], *, length: int, chunk_size: int,
              kind: str, source: dict[str, Any], started_at: str, t0: float, method: str, verify: str, retries_total: int,
              start_chunk: int, notes: list[str], full_check: dict[str, Any] | None, register: Callable[..., Any]) -> dict[str, Any]:
    size = files.part.stat().st_size
    if size != length:
        raise DeviceError(f"덤프 크기 불일치: {size} != {length}", code="dump_size_mismatch")
    os.replace(files.part, files.final)
    sha = sha256_file(files.final)
    duration = round(time.monotonic() - t0, 2)
    runs = state.setdefault("runs", [])
    if runs:
        runs[-1].update({"finished_at": utcnow_iso(), "duration_seconds": duration, "status": "succeeded",
                         "completed_chunks": state.get("completed_chunks", 0)})
    duration_total = _runs_total_seconds(runs) if runs else duration
    checks = state.get("chunk_checks", [])
    if method == "uboot-md":
        vmethod = "crc32-chunks" if verify == "crc32" else ("double-read" if verify == "double" else "none")
        detail = {"crc32": "청크마다 기기 crc32 와 호스트 crc32 비교", "double": "청크마다 md.b 를 두 번 읽어 비교 (기기 crc32 없음)",
                  "none": "md.b 형식(주소 연속성·바이트 수)만 검증"}[verify]
    else:
        vmethod = "md5-device"
        detail = "청크마다 기기 md5sum 과 호스트 md5 비교"
    meta = {
        "schema": "pweh.uart-dump/v1",
        "method": method,
        "source": source,
        "output": {"path": files.case.rel(files.final), "sha256": sha, "size": size},
        "verification": {"method": vmethod, "detail": detail, "match": True, "chunks_verified": len(checks),
                         **({"full_range": full_check} if full_check else {})},
        "chunks": {"size": chunk_size, "count": math.ceil(length / chunk_size), "retries": retries_total,
                   "resumed_from": start_chunk, "checks": checks},
        "baudrate": session.settings.baudrate,
        "port": session.port,
        "session_id": session.id,
        "duration_seconds": duration,
        "duration_seconds_total": duration_total,
        "runs": runs,
        "started_at": started_at,
        "finished_at": utcnow_iso(),
        "notes": notes,
    }
    if session.uboot_info.get("version"):
        meta["uboot_version"] = session.uboot_info.get("version")
    atomic_write_json(files.meta, meta)
    files.state.unlink(missing_ok=True)
    art = register(files.final, kind=kind, description=f"UART 덤프 ({method}, {source.get('device_path') or source.get('type')})",
                   extra={"metadata": files.case.rel(files.meta), "method": method, "sha256": sha})
    register(files.meta, kind="other", description="UART 덤프 메타데이터", extra={"type": "dump-metadata", "dump": files.case.rel(files.final)})
    jctx.log(f"덤프 완료: {files.case.rel(files.final)} sha256={sha}")
    return {
        "path": files.case.rel(files.final),
        "path_abs": str(files.final),
        "sha256": sha,
        "size": size,
        "metadata_path": files.case.rel(files.meta),
        "method": method,
        "verification": meta["verification"] | {"chunks_verified": len(checks)},
        "chunks": {k: v for k, v in meta["chunks"].items() if k != "checks"},
        "duration_seconds": duration,
        "duration_seconds_total": duration_total,
        "runs": len(runs),
        "artifact_id": art.get("id") if isinstance(art, dict) else None,
        "notes": notes,
    }


# ---------------------------------------------------------------------------
# 리눅스 셸 덤프
# ---------------------------------------------------------------------------


@dataclass
class ShellDumpSpec:
    case: Case
    files: DumpFiles
    path: str
    offset: int
    length: int | None
    chunk_size: int
    method: str  # auto | base64 | hexdump
    retries: int
    resume: bool
    kind: str = "partition"
    notes: list[str] = field(default_factory=list)

    @property
    def source(self) -> str:
        return "shell"

    def identity(self, length: int, method: str) -> dict[str, Any]:
        return {"method": f"linux-{method}", "path": self.path, "offset": self.offset, "length": length, "chunk_size": self.chunk_size}


def shell_dd(path: str, off: int, n: int, tail: str) -> str:
    bs = math.gcd(off, n) if off else n
    bs = max(1, min(bs, n))
    while bs > 65536 and bs % 2 == 0:
        bs //= 2
    return f"dd if={path} bs={bs} skip={off // bs} count={n // bs} 2>/dev/null | {tail}"


def representative_shell_lines(path: str) -> list[str]:
    return [shell_dd(path, 0, 65536, "base64"), shell_dd(path, 0, 65536, "hexdump -C"), shell_dd(path, 0, 65536, "md5sum"),
            "echo pweh | base64", "echo pweh | hexdump -C", "echo pweh | md5sum", "cat /proc/mtd", f"wc -c {path}"]


def run_shell_dump(jctx: JobContext, session: UartSession, spec: ShellDumpSpec, *, register: Callable[..., Any],
                   check_auth: Callable[[], Any] | None = None) -> dict[str, Any]:
    t0 = time.monotonic()
    started_at = utcnow_iso()
    runner = _Runner(jctx, session, ("linux-shell",), check_auth)
    notes = list(spec.notes)
    s = console.sync(session, timeout=3.0, cancel=runner.cancelled, source=f"job:{jctx.job.id}")
    if session.context != "linux-shell":
        raise DeviceError(f"리눅스 셸 프롬프트를 확인하지 못했습니다 (문맥 {session.context}, 응답 {s.get('reply')!r}).", code="context_changed",
                          hint="shell_login 으로 셸을 얻은 뒤 다시 시작하세요.")
    # 도구 확인 (출력 검증까지)
    want_md5 = hashlib.md5(PROBE_TEXT).hexdigest()
    r = runner.run("echo pweh | md5sum", 10.0)
    if parse_md5sum(r.output) != want_md5:
        raise DeviceError(f"기기의 md5sum 이 없거나 결과가 다릅니다: {r.output[-200:]!r}", code="md5sum_unavailable",
                          hint="청크 검증을 할 수 없습니다. U-Boot 덤프(uboot_dump_start)를 쓰세요.")
    method = spec.method
    if method in ("auto", "base64"):
        r = runner.run("echo pweh | base64", 10.0)
        ok = parse_base64(r.output)[0] == PROBE_TEXT
        if not ok and method == "base64":
            raise DeviceError(f"base64 애플릿을 쓸 수 없습니다: {r.output[-200:]!r}", code="base64_unavailable", hint="method=\"hexdump\" 또는 auto")
        method = "base64" if ok else "hexdump"
        if not ok:
            notes.append("base64 애플릿이 없어 hexdump -C 로 받았습니다 (약 3.6배 느림).")
    if method == "hexdump":
        r = runner.run("echo pweh | hexdump -C", 10.0)
        if parse_hexdump_c(r.output, len(PROBE_TEXT))[0] != PROBE_TEXT:
            raise DeviceError(f"hexdump -C 를 쓸 수 없습니다: {r.output[-200:]!r}", code="hexdump_unavailable")
    # 길이
    length = spec.length
    m = re.match(r"^/dev/mtd(?:block)?(\d+)$", spec.path)
    part_info = None
    if m:
        r = runner.run("cat /proc/mtd", 10.0)
        rows = proc_mtd(r.output)
        part_info = next((row for row in rows if row["dev"] == f"mtd{m.group(1)}"), None)
        if part_info is None:
            raise DeviceError(f"/proc/mtd 에 mtd{m.group(1)} 이 없습니다: {r.output[-300:]!r}", code="mtd_not_found")
        if length is None:
            length = part_info["size"] - spec.offset
        elif spec.offset + length > part_info["size"]:
            raise ValidationFailed(f"범위가 파티션 크기(0x{part_info['size']:x})를 넘습니다.")
    elif length is None:
        r = runner.run(f"wc -c {spec.path}", 15.0)
        mm = re.search(r"^\s*(\d+)\s", r.output + " ", re.M)
        if not mm:
            raise DeviceError(f"파일 크기를 알 수 없습니다: {r.output[-200:]!r}", code="size_unknown", hint="length 를 직접 주세요.")
        length = int(mm.group(1)) - spec.offset
    if not length or length <= 0:
        raise ValidationFailed(f"덤프할 길이가 없습니다 (length={length}).")
    files = spec.files
    identity = spec.identity(length, method)
    start_chunk, state = prepare_resume(files, identity, resume=spec.resume, chunk_size=spec.chunk_size, length=length)
    nchunks = math.ceil(length / spec.chunk_size)
    state.setdefault("runs", []).append({"started_at": started_at, "resumed_from": start_chunk, "session_id": session.id,
                                         "port": session.port, "baudrate": session.settings.baudrate})
    atomic_write_json(files.state, state)
    retries_total = int(state.get("retries_total", 0))
    baud = session.settings.baudrate
    tail = "base64" if method == "base64" else "hexdump -C"
    jctx.log(f"셸 덤프 시작: {spec.path} +0x{spec.offset:x} 길이 0x{length:x}, {method}, 청크 0x{spec.chunk_size:x} × {nchunks}, 시작 {start_chunk}")

    def save_partial(status: str) -> None:
        jctx.set_partial({"status": status, "part_path": files.case.rel(files.part), "state_path": files.case.rel(files.state),
                          "completed_chunks": state["completed_chunks"], "total_chunks": nchunks,
                          "completed_bytes": min(state["completed_chunks"] * spec.chunk_size, length),
                          "resume_hint": "같은 인자로 shell_dump_start 를 다시 부르면 이어서 받습니다."})

    save_partial("running")
    try:
        t_run = time.monotonic()
        run_start_done = min(start_chunk * spec.chunk_size, length)
        for i in range(start_chunk, nchunks):
            jctx.check_cancelled()
            off = spec.offset + i * spec.chunk_size
            n = min(spec.chunk_size, spec.offset + length - off)
            reasons: list[str] = []
            good = None
            for attempt in range(spec.retries + 1):
                try:
                    res = runner.run(shell_dd(spec.path, off, n, tail), _md_timeout(n, baud, method, session.settings.bits_per_char))
                    if res.timed_out:
                        raise ChunkError("출력이 시간 안에 끝나지 않음")
                    if res.lost:
                        raise ChunkError("출력이 링 버퍼보다 커서 일부를 잃었습니다")
                    if method == "base64":
                        data, problems = parse_base64(res.output, n)
                    else:
                        data, problems = parse_hexdump_c(res.output, n)
                    if problems:
                        raise ChunkError("; ".join(problems[:3]))
                    res2 = runner.run(shell_dd(spec.path, off, n, "md5sum"), 30.0 + n / 200_000)
                    dev_md5 = parse_md5sum(res2.output)
                    host_md5 = hashlib.md5(data).hexdigest()
                    if dev_md5 is None:
                        raise ChunkError(f"md5sum 출력을 해석할 수 없음: {res2.output[-120:]!r}")
                    if dev_md5 != host_md5:
                        raise ChunkError(f"md5 불일치 (기기 {dev_md5}, 호스트 {host_md5})")
                    good = (data, {"offset": off, "length": n, "method": "md5", "md5": host_md5})
                    break
                except ChunkError as exc:
                    reasons.append(f"시도 {attempt + 1}: {exc}")
                    retries_total += 1
                    jctx.log(f"청크 {i} @0x{off:x} 재시도 ({exc})")
                    session.event({"type": "dump_retry", "chunk": i, "offset": off, "reason": str(exc)[:300]})
                    if session.prompt_at_tail() is None:
                        runner.abort_output()
            if good is None:
                save_partial("failed")
                state["retries_total"] = retries_total
                atomic_write_json(files.state, state)
                raise DeviceError(f"청크 {i} (@0x{off:x})를 {spec.retries + 1}회 시도했지만 실패: {' / '.join(reasons[-3:])}", code="dump_chunk_failed",
                                  hint="커널 메시지가 섞였다면 사람이 `dmesg -n 1` 로 콘솔 로그 레벨을 낮춘 뒤 다시 시작하세요 (이어 받기 가능).")
            data, check = good
            _write_chunk(files, i, spec.chunk_size, data)
            state["completed_chunks"] = i + 1
            state["chunk_checks"].append(check)
            state["retries_total"] = retries_total
            state["updated_at"] = utcnow_iso()
            atomic_write_json(files.state, state)
            save_partial("running")
            _progress(jctx, done_bytes=min(off + n - spec.offset, length), total_bytes=length, run_start_done=run_start_done, t_run=t_run,
                      msg=f"청크 {i + 1}/{nchunks} @0x{off:x} md5 확인")
        source = {"type": "linux-shell", "flash_type": None, "flash_size": None, "offset": spec.offset, "length": length,
                  "partition": part_info.get("name") if part_info else None, "ram_addr": None, "device_path": spec.path}
        return _finalize(jctx, session, files, state, length=length, chunk_size=spec.chunk_size, kind=spec.kind, source=source,
                         started_at=started_at, t0=t0, method=f"linux-{method}", verify="md5", retries_total=retries_total,
                         start_chunk=start_chunk, notes=notes, full_check=None, register=register)
    except BaseException as exc:
        # 취소·실패로 끝나도 부분 결과(partial_result)와 state 의 실행 기록에 최종 상태를 남긴다
        status = "cancelled" if isinstance(exc, JobCancelled) else "failed"
        state["retries_total"] = retries_total
        _end_run(files, state, t0, status, None if status == "cancelled" else f"{type(exc).__name__}: {exc}")
        save_partial(status)
        raise

