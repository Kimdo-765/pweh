"""외부 도구 디렉터리(기본 ~/pweh-tools)와 그 env.sh 의 위치.

`scripts/install.sh` 와 `scripts/mcp-launch.sh` 와 같은 규칙을 쓴다 (우선순위 순):
1. 환경변수 `PWEH_TOOLS_ENV` (env.sh 경로) / `PWEH_TOOLS_DIR` (도구 디렉터리)
2. 설치 스크립트가 남긴 저장소의 `.pweh/tools-env.path` (`--prefix` 로 다른 곳에 설치했을 때, 한 줄짜리 env.sh 경로)
3. `~/pweh-tools`
"""

from __future__ import annotations

import os
from pathlib import Path

_REPO = Path(__file__).resolve().parents[2]
POINTER = _REPO / ".pweh" / "tools-env.path"


def _pointer() -> Path | None:
    """포인터의 첫 줄 (scripts/mcp-launch.sh 의 head -n 1 과 같음). 가리키는 env.sh 가 없으면 무시한다."""
    try:
        lines = POINTER.read_text(encoding="utf-8").splitlines()
    except OSError:
        return None
    text = lines[0].strip() if lines else ""
    p = Path(text).expanduser() if text else None
    return p if p is not None and p.is_file() else None


def tools_env() -> Path:
    """외부 도구 env.sh 경로 (있는지는 확인하지 않는다)."""
    v = os.environ.get("PWEH_TOOLS_ENV")
    if v:
        return Path(v).expanduser()
    if os.environ.get("PWEH_TOOLS_DIR"):
        return Path(os.environ["PWEH_TOOLS_DIR"]).expanduser() / "env.sh"
    return _pointer() or (Path.home() / "pweh-tools" / "env.sh")


def tools_dir() -> Path:
    """외부 도구 디렉터리 (있는지는 확인하지 않는다)."""
    v = os.environ.get("PWEH_TOOLS_DIR")
    if v:
        return Path(v).expanduser()
    return tools_env().parent


#: 도구 디렉터리 안의 Windows esptool.exe 후보 (scripts/install.sh --only esptool 이 푸는 위치)
ESPTOOL_WIN_RELPATHS = ("esptool-win/esptool-windows-amd64/esptool.exe", "esptool-win/esptool.exe")


def esptool_win_candidates(configured: str | None, env_value: str | None, tools_dir: Path | None) -> list[tuple[str, str]]:
    """Windows esptool.exe 후보 (경로, 출처) — 설정 ``tools.esptool_win`` → 환경 변수 ``PWEH_ESPTOOL_WIN`` → 도구 디렉터리.

    출처: config | env | pweh-tools. esp-mcp(``esptool_cli.windows_exe_candidates``)와 doctor·``pweh env``(``pweh.hostenv``)가
    같은 규칙을 쓰도록 여기에 둔다. 파일이 있는지는 보지 않는다.
    """
    out: list[tuple[str, str]] = []
    if configured and configured.strip():
        out.append((configured.strip(), "config"))
    env = (env_value or "").strip()
    if env and all(env != c for c, _ in out):
        out.append((env, "env"))
    if tools_dir is not None:
        for rel in ESPTOOL_WIN_RELPATHS:
            out.append((str(tools_dir / rel), "pweh-tools"))
    return out


#: 도구 디렉터리 안의 pweh-emu 실행 파일 (scripts/install.sh --only qemu_esp / --only simavr 가 두는 위치)
EMU_BINARY_RELPATHS: dict[str, str] = {
    "qemu-system-xtensa": "qemu-esp/xtensa/qemu/bin/qemu-system-xtensa",
    "qemu-system-riscv32": "qemu-esp/riscv32/qemu/bin/qemu-system-riscv32",
    "pweh_avr_run": "simavr/bin/pweh_avr_run",
}


def emu_binary_candidates(name: str, configured: str | None, env_value: str | None, tools_dir: Path | None) -> list[tuple[str, str]]:
    """pweh-emu 실행 파일 후보 (경로, 출처) — 설정 ``tools.*`` → 환경 변수 → 도구 디렉터리의 고정 상대 경로.

    name: ``qemu-system-xtensa`` | ``qemu-system-riscv32`` | ``pweh_avr_run`` (그 밖은 ValueError).
    설정 키·환경 변수: ``tools.qemu_xtensa``/``PWEH_QEMU_XTENSA``, ``tools.qemu_riscv32``/``PWEH_QEMU_RISCV32``,
    ``tools.avr_run``/``PWEH_AVR_RUN``. 출처: config | env | pweh-tools (``esptool_win_candidates`` 와 같은 모양, 같은 경로는 한 번만).
    파일이 있는지·절대 경로인지·basename 이 허용 목록에 맞는지는 보지 않는다 — 서버가 확인한다
    (설정·환경 값은 절대 경로여야 하고 PATH 이름 찾기는 하지 않는다. 배포판 QEMU 를 잘못 잡지 않게).
    """
    rel = EMU_BINARY_RELPATHS.get(name)
    if rel is None:
        raise ValueError(f"알 수 없는 pweh-emu 실행 파일 이름: {name!r} (허용: {', '.join(EMU_BINARY_RELPATHS)})")
    out: list[tuple[str, str]] = []

    def add(path: str, source: str) -> None:
        if path and all(path != p for p, _ in out):
            out.append((path, source))

    add((configured or "").strip(), "config")
    add((env_value or "").strip(), "env")
    if tools_dir is not None:
        add(str(tools_dir / rel), "pweh-tools")
    return out


__all__ = ["EMU_BINARY_RELPATHS", "ESPTOOL_WIN_RELPATHS", "POINTER", "emu_binary_candidates", "esptool_win_candidates",
           "tools_dir", "tools_env"]
