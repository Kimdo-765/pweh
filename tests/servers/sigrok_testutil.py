"""sigrok-mcp 테스트 공용 도우미: 가짜 sigrok-cli 생성, 실제 sigrok-cli 탐지, 합성 UART 파일 작성."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from fractions import Fraction
from pathlib import Path

from pweh.toolsdir import tools_dir
from typing import Any

HERE = Path(__file__).resolve().parent
REPO_ROOT = HERE.parents[1]
FAKE_SRC = HERE / "sigrok_fake_cli.py"
VENV_PY = REPO_ROOT / ".venv" / "bin" / "python"
REAL_FALLBACK = str(tools_dir() / "bin" / "sigrok-cli")

AUTH = {"basis": "owned", "owner": "테스트 랩", "statement": "이 카메라는 제가 직접 구매한 제 소유 기기입니다."}


def make_fake_sigrok(dirpath: Path) -> Path:
    """venv python shebang 을 붙인 가짜 sigrok-cli 실행 파일을 만든다."""
    py = VENV_PY if VENV_PY.exists() else Path(sys.executable)
    dirpath.mkdir(parents=True, exist_ok=True)
    exe = dirpath / "sigrok-cli"
    exe.write_text(f"#!{py}\n" + FAKE_SRC.read_text(encoding="utf-8"), encoding="utf-8")
    exe.chmod(0o755)
    return exe


def read_log(path: Path) -> list[dict[str, Any]]:
    if not Path(path).exists():
        return []
    return [json.loads(l) for l in Path(path).read_text(encoding="utf-8").splitlines() if l.strip()]


def real_sigrok_cli() -> str | None:
    """실제 sigrok-cli 경로 (환경변수 → pweh-tools 기본 경로 → PATH). --version 이 동작해야 한다."""
    for cand in (os.environ.get("PWEH_SIGROK_CLI"), REAL_FALLBACK, shutil.which("sigrok-cli")):
        if not cand or not os.path.isfile(cand) or not os.access(cand, os.X_OK):
            continue
        try:
            out = subprocess.run([cand, "--version"], stdin=subprocess.DEVNULL, capture_output=True, timeout=30)
        except (OSError, subprocess.SubprocessError):
            continue
        if out.returncode == 0 and out.stdout.startswith(b"sigrok-cli "):
            return cand
    return None


def write_uart_sr(path: Path, payload: bytes, *, baud: float, samplerate: int, idle_level: int = 1,
                  names: tuple[str, ...] = ("RX", "TX"), tx_payload: bytes | None = None, chunk_bytes: int = 1 << 20,
                  **kw: Any):
    """RX(=비트0) 에 payload, TX(=비트1) 는 idle(또는 tx_payload) 인 srzip 파일."""
    from sigrok_mcp.synth import uart_waveform
    from sigrok_mcp.writers import lane_from_edges, pack_lanes, write_srzip

    w = uart_waveform(payload, baud=baud, samplerate=samplerate, idle_level=idle_level, **kw)
    total = w.total_samples
    lanes = [lane_from_edges(w.initial_level, w.edges, total)]
    if len(names) > 1:
        if tx_payload:
            w2 = uart_waveform(tx_payload, baud=baud, samplerate=samplerate, idle_level=idle_level, **kw)
            lanes.append(lane_from_edges(w2.initial_level, [e for e in w2.edges if e < total], total))
        else:
            lanes.append((b"\x01" if idle_level else b"\x00") * total)
    for _ in names[2:]:
        lanes.append(b"\x00" * total)
    data, us = pack_lanes(lanes)
    write_srzip(path, data, samplerate, list(names), unitsize=us, chunk_bytes=chunk_bytes)
    return w


def write_uart_vcd(path: Path, payload: bytes, *, baud: float, samplerate: int, idle_level: int = 1,
                   timescale: Fraction | None = None, style: str = "standard", name: str = "RX", **kw: Any):
    """payload 를 UART 로 보낸 VCD. timescale 기본 = 1/samplerate (표준 값이어야 함)."""
    from sigrok_mcp.synth import uart_waveform
    from sigrok_mcp.writers import write_vcd

    w = uart_waveform(payload, baud=baud, samplerate=samplerate, idle_level=idle_level, **kw)
    ts = timescale or Fraction(1, samplerate)
    scale = Fraction(1, samplerate) / ts  # 샘플당 tick (정수가 아니면 sigrok VCD 출력처럼 반올림)
    write_vcd(path, [(name, w.initial_level, [int(round(e * scale)) for e in w.edges])], timescale_s=ts,
              end_tick=int(round(w.total_samples * scale)), style=style)
    return w


def make_case(title: str = "sigrok test", authorized: bool = True) -> str:
    from pweh.runtime import get_runtime

    case = get_runtime("sigrok-mcp").cases.create(title=title, authorization=AUTH if authorized else None)
    return case.id


def case_dir(case_id: str) -> Path:
    from pweh.runtime import get_runtime

    return get_runtime("sigrok-mcp").cases.get(case_id).dir


def pid_alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:  # pragma: no cover
        return True
    # 좀비는 죽은 것으로 본다
    try:
        stat = Path(f"/proc/{pid}/stat").read_text()
        return stat.split(")")[-1].split()[0] != "Z"
    except OSError:
        return False
