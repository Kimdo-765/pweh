"""emu-mcp 시험 공용 도우미: 가짜 에뮬레이터 설치·동작 선택, 케이스·출처 원장 시드, 합성 ESP 플래시, 프로세스 확인, stdio 서버(JSON-RPC).

test_emu_mcp.py(가짜 에뮬레이터)와 test_emu_external.py(실제 Espressif QEMU·pweh_avr_run)가 같이 쓴다. 실제 케이스·덤프는 쓰지 않는다 —
모든 펌웨어는 tests/fixtures/emu 의 생성기와 tests/fwtriage/esp_builders 로 만든 합성 이미지다.
"""

from __future__ import annotations

import importlib.util
import json
import os
import select
import signal
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Callable, Iterable

HERE = Path(__file__).resolve().parent
REPO_ROOT = HERE.parents[1]
EMU_PKG_DIR = REPO_ROOT / "mcp-servers" / "emu-mcp"
FIX_DIR = REPO_ROOT / "tests" / "fixtures" / "emu"
FAKE_SRC = HERE / "emu_fake_emulator.py"
VENV_PY = REPO_ROOT / ".venv" / "bin" / "python"

# 통합(편집 가능 설치) 전의 작업 트리에서도 emu_mcp 를 import 할 수 있게 (설치돼 있으면 그대로 쓴다)
if importlib.util.find_spec("emu_mcp") is None and str(EMU_PKG_DIR) not in sys.path:
    sys.path.insert(0, str(EMU_PKG_DIR))
if str(FIX_DIR) not in sys.path:
    sys.path.insert(0, str(FIX_DIR))

EXE_NAMES = ("qemu-system-xtensa", "qemu-system-riscv32", "pweh_avr_run")
ENV_KEYS = {"qemu-system-xtensa": "PWEH_QEMU_XTENSA", "qemu-system-riscv32": "PWEH_QEMU_RISCV32", "pweh_avr_run": "PWEH_AVR_RUN"}
SERVER = "emu-mcp"
AUTH = {"basis": "owned", "owner": "테스트 랩", "statement": "합성 펌웨어로 시험하는 제 소유 개발 보드입니다."}
SYNTH_MAC = "f4:12:fa:12:34:56"
LEDGER_CHIP = {"esp32": "ESP32-D0WD-V3", "esp32s3": "ESP32-S3", "esp32c3": "ESP32-C3"}
QEMU_EXE = {"esp32": "qemu-system-xtensa", "esp32s3": "qemu-system-xtensa", "esp32c3": "qemu-system-riscv32"}
VCPUS = {"esp32": 2, "esp32s3": 2, "esp32c3": 1}
#: 계약 [S] images.py — ESP-IDF qemu_ext.py 기본 eFuse 블롭의 sha256
EFUSE_SHA256 = {
    "esp32": "96405fb1e2f3ffa576ca85e08cf03a4be82153ac407ceb7eb9971d091b254fda",
    "esp32s3": "2054600a17c72426ac024ae851e7ea26f9cf612f31140b445ff713ba15ac09c8",
    "esp32c3": "2054600a17c72426ac024ae851e7ea26f9cf612f31140b445ff713ba15ac09c8",
}
SIMAVR_COMMIT = "5b08da60497f7564f50941f74a549fe2851db030"
ECHO_HEX = FIX_DIR / "avr_uart_echo_m328p.hex"
CRASH_HEX = b":040000000C94FF3F1E\n:00000001FF\n"
ATTEST_ANSWERS = {"source_known": "yes", "how_obtained": "avrdude 로 내 보드에서 읽음 (시험)"}
SEALS_ALL = 1 | 2 | 4 | 8  # F_SEAL_SEAL | F_SEAL_SHRINK | F_SEAL_GROW | F_SEAL_WRITE
MiB = 1 << 20


def cpu_limit(timeout_s: int, vcpus: int) -> tuple[int, int]:
    """계약: RLIMIT_CPU soft = ⌈timeout_s × vcpus × 1.1⌉ + 5, hard = soft + 5 (정수로 계산한 기대값)."""
    soft = -(-timeout_s * vcpus * 11 // 10) + 5
    return soft, soft + 5


# ---------------------------------------------------------------------------
# 가짜 에뮬레이터
# ---------------------------------------------------------------------------


def make_fake_emulator(tools_dir: Path) -> dict[str, Path]:
    """가짜 에뮬레이터를 qemu-system-xtensa·qemu-system-riscv32·pweh_avr_run 이름으로 만든다 (venv python shebang, 0755).

    shebang 에는 인터프리터 옵션을 붙이지 않는다 — 서버의 시작 정리가 cmdline[1](이 파일 경로)로 가짜를 알아본다.
    --version 의 드라이버 버전은 저장소 실행기 소스(native/emu/pweh_avr_run.c)의 PWEH_AVR_RUN_VERSION 이다."""
    from emu_mcp.backends import expected_avr_driver_version

    py = VENV_PY if VENV_PY.exists() else Path(sys.executable)
    tools_dir.mkdir(parents=True, exist_ok=True)
    src = FAKE_SRC.read_text(encoding="utf-8").replace("@AVR_DRIVER_VERSION@", expected_avr_driver_version() or "0.0")
    out: dict[str, Path] = {}
    for name in EXE_NAMES:
        exe = tools_dir / name
        exe.write_text(f"#!{py}\n" + src, encoding="utf-8")
        exe.chmod(0o755)
        out[name] = exe
    return out


def write_fake_mode(tools_dir: Path, mode: str = "boot", **cfg: Any) -> dict[str, Any]:
    """가짜 실행 파일 옆의 fake-mode.json 을 원자적으로 바꾼다 (가짜는 시작할 때마다 읽는다)."""
    data = {"mode": mode, **cfg}
    tmp = tools_dir / ".fake-mode.json.tmp"
    tmp.write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")
    os.replace(tmp, tools_dir / "fake-mode.json")
    return data


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    try:
        text = Path(path).read_text(encoding="utf-8")
    except FileNotFoundError:
        return []
    return [json.loads(line) for line in text.splitlines() if line.strip()]


def fake_starts(session_dir: Path) -> list[dict[str, Any]]:
    """세션 디렉터리의 fake.log 에서 시작 기록만."""
    return [r for r in read_jsonl(Path(session_dir) / "fake.log") if "argv" in r]


def wait_fake_start(session_dir: Path, timeout: float = 10.0) -> dict[str, Any]:
    assert wait_until(lambda: fake_starts(session_dir), timeout), f"가짜 에뮬레이터가 시작 기록을 남기지 않았다: {session_dir}"
    return fake_starts(session_dir)[-1]


def fake_logs_under(root: Path) -> list[Path]:
    return sorted(Path(root).rglob("fake.log"))


# ---------------------------------------------------------------------------
# 케이스·출처 원장
# ---------------------------------------------------------------------------


def rt():
    from pweh.runtime import get_runtime

    return get_runtime(SERVER)


def make_case(title: str = "emu test", authorized: bool = True) -> str:
    return rt().cases.create(title=title, authorization=AUTH if authorized else None).id


def case_dir(case_id: str) -> Path:
    return rt().cases.get(case_id).dir


def put_file(case_id: str, rel: str, data: bytes) -> Path:
    p = case_dir(case_id) / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_bytes(data)
    return p


def seed_device_read(case_id: str, rel: str, *, chip: str | None = "ESP32-S3", mac: str | None = SYNTH_MAC,
                     verify: str = "double-read", match: bool | None = True, offset: Any = 0) -> dict[str, Any]:
    """esp_read_flash_start 가 남기는 것과 같은 모양의 device-read 기록."""
    src: dict[str, Any] = {"server": "esp-mcp", "tool": "esp_read_flash_start", "verify": verify, "match": match}
    if chip is not None:
        src["chip"] = chip
    if mac is not None:
        src["mac"] = mac
    case = rt().cases.get(case_id)
    return rt().provenance.record_device_read(case, rel, src, {"offset": offset, "role": "primary"})


def seed_fact(case_id: str, kind: str, data: dict[str, Any], mac: str = SYNTH_MAC) -> dict[str, Any]:
    tool = "esp_security_info" if kind == "esp-security-info" else "esp_chip_info"
    return rt().provenance.record_device_fact(case_id, kind, data, {"server": "esp-mcp", "tool": tool, "mac": mac})


def decide_attestation(attestation_id: str, answers: dict[str, Any] | None = None) -> dict[str, Any]:
    """사람의 결정 (`pweh attest` 대신 저장소에 기록 — 시험 전용)."""
    return rt().attestations.decide(attestation_id, dict(answers or ATTEST_ANSWERS), via="cli-tty", by="tester")


# ---------------------------------------------------------------------------
# 합성 ESP 플래시
# ---------------------------------------------------------------------------


def esp_flash(chip: str = "esp32s3", variant: str = "hello", *, nvs: bool = True, text: bytes | None = None,
              size: int = 4 * MiB) -> bytes:
    """mkimg_esp 의 2단계 이미지(부트 오프셋) + 파티션 표(0x8000) + 비밀값이 든 NVS(0x9000, tests/fwtriage/esp_builders.rich_nvs).

    NVS 의 알려진 비밀값: nvs.net80211 sta.pswd = 'not-a-real-pass', cloud api_token = 'tok-synthetic-0000' (합성 값)."""
    import mkimg_esp

    flash = bytearray(mkimg_esp.build_flash(chip, variant, size=size, text=text))
    if nvs:
        from fwtriage.esp_builders import DEFAULT_PARTITIONS, build_partition_table, rich_nvs

        table = build_partition_table(DEFAULT_PARTITIONS)
        flash[0x8000:0x8000 + len(table)] = table
        nv, _recs = rich_nvs()
        data = nv.build(total_pages=6)
        flash[0x9000:0x9000 + len(data)] = data
    return bytes(flash)


NVS_SECRET = "not-a-real-pass"
NVS_TOKEN = "tok-synthetic-0000"


# ---------------------------------------------------------------------------
# 프로세스
# ---------------------------------------------------------------------------


def pid_alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:  # pragma: no cover
        return True
    try:
        state = Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()[0]
    except (OSError, IndexError):
        return False
    return state not in ("Z", "X")


def wait_until(pred: Callable[[], Any], timeout: float, interval: float = 0.05) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if pred():
            return True
        time.sleep(interval)
    return bool(pred())


def _proc_info(pid: int) -> dict[str, Any] | None:
    try:
        cwd = os.readlink(f"/proc/{pid}/cwd")
        exe = os.readlink(f"/proc/{pid}/exe")
        cmd = [a.decode("utf-8", "replace") for a in Path(f"/proc/{pid}/cmdline").read_bytes().split(b"\0") if a]
        fields = Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()
    except (OSError, IndexError):
        return None
    return {"pid": pid, "cwd": cwd, "exe": exe, "cmdline": cmd, "state": fields[0], "pgid": int(fields[2])}


def procs_under(root: Path | str, names: Iterable[str] | None = None) -> list[dict[str, Any]]:
    """cwd 가 root 아래인 (좀비가 아닌) 프로세스. names 를 주면 exe·cmdline 의 basename 이 그중 하나인 것만."""
    base = os.path.realpath(str(root))
    want = set(names) if names else None
    out: list[dict[str, Any]] = []
    me = os.getpid()
    for d in os.listdir("/proc"):
        if not d.isdigit() or int(d) == me:
            continue
        info = _proc_info(int(d))
        if info is None or info["state"] in ("Z", "X"):
            continue
        cwd = info["cwd"].removesuffix(" (deleted)")
        if not (cwd == base or cwd.startswith(base + os.sep)):
            continue
        if want is not None:
            bases = {os.path.basename(info["exe"].removesuffix(" (deleted)"))} | {os.path.basename(a) for a in info["cmdline"][:2]}
            if not bases & want:
                continue
        out.append(info)
    return out


def kill_procs_under(root: Path | str, names: Iterable[str] | None = None) -> list[dict[str, Any]]:
    """시험 정리: cwd 가 root 아래인 프로세스를 SIGKILL 한다(시험이 만든 것만 그 아래에 있다). 끝낸 목록을 돌려준다."""
    found = procs_under(root, names)
    for info in found:
        try:
            os.kill(info["pid"], signal.SIGKILL)
        except ProcessLookupError:
            pass
    return found


def group_members(pgid: int) -> list[int]:
    """프로세스 그룹의 (좀비가 아닌) 구성원."""
    out = []
    for d in os.listdir("/proc"):
        if not d.isdigit():
            continue
        info = _proc_info(int(d))
        if info and info["pgid"] == pgid and info["state"] not in ("Z", "X"):
            out.append(int(d))
    return out


def proc_status_hex(pid: int, key: str) -> int:
    for line in Path(f"/proc/{pid}/status").read_text().splitlines():
        if line.startswith(key + ":"):
            return int(line.split(":", 1)[1].strip(), 16)
    raise KeyError(key)


def proc_fd_targets(pid: int) -> list[str]:
    out = []
    for n in os.listdir(f"/proc/{pid}/fd"):
        try:
            out.append(os.readlink(f"/proc/{pid}/fd/{n}"))
        except OSError:
            pass
    return out


def proc_net_ifaces(pid: int) -> list[str]:
    return [ln.split(":", 1)[0].strip() for ln in Path(f"/proc/{pid}/net/dev").read_text().splitlines()[2:] if ":" in ln]


# ---------------------------------------------------------------------------
# stdio 서버 (JSON-RPC 를 직접 — 신호·stdin 닫기를 시험하려고)
# ---------------------------------------------------------------------------


def server_env(extra: dict[str, str] | None = None) -> dict[str, str]:
    """stdio 서버 환경: 지금 환경 + emu_mcp·코어를 찾을 PYTHONPATH (+ extra)."""
    env = dict(os.environ)
    parts = [str(EMU_PKG_DIR), str(REPO_ROOT / "src")]
    if env.get("PYTHONPATH"):
        parts.append(env["PYTHONPATH"])
    env["PYTHONPATH"] = os.pathsep.join(parts)
    env.update(extra or {})
    return env


class StdioServer:
    """`python -m emu_mcp` 를 띄워 JSON-RPC 로 다룬다 (stderr 는 버린다)."""

    def __init__(self, env: dict[str, str]) -> None:
        py = str(VENV_PY if VENV_PY.exists() else Path(sys.executable))
        self.proc = subprocess.Popen([py, "-m", "emu_mcp"], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                     env=env, cwd=str(REPO_ROOT))
        self._buf = b""
        self._id = 0

    def send(self, obj: dict[str, Any]) -> None:
        assert self.proc.stdin is not None
        self.proc.stdin.write((json.dumps(obj) + "\n").encode("utf-8"))
        self.proc.stdin.flush()

    def _readline(self, timeout: float) -> bytes:
        assert self.proc.stdout is not None
        fd = self.proc.stdout.fileno()
        deadline = time.monotonic() + timeout
        while b"\n" not in self._buf:
            left = deadline - time.monotonic()
            if left <= 0:
                raise AssertionError("stdio 서버 응답 시간 초과")
            r, _, _ = select.select([fd], [], [], left)
            if not r:
                continue
            chunk = os.read(fd, 65536)
            if not chunk:
                raise AssertionError("stdio 서버가 출력을 닫았다")
            self._buf += chunk
        line, _, self._buf = self._buf.partition(b"\n")
        return line

    def recv(self, want_id: int, timeout: float = 60.0) -> dict[str, Any]:
        deadline = time.monotonic() + timeout
        while True:
            msg = json.loads(self._readline(max(0.1, deadline - time.monotonic())))
            if msg.get("id") == want_id:
                return msg

    def initialize(self) -> None:
        self._id += 1
        self.send({"jsonrpc": "2.0", "id": self._id, "method": "initialize",
                   "params": {"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "emu-test", "version": "0"}}})
        self.recv(self._id)
        self.send({"jsonrpc": "2.0", "method": "notifications/initialized"})

    def call(self, name: str, timeout: float = 60.0, **arguments: Any) -> dict[str, Any]:
        self._id += 1
        self.send({"jsonrpc": "2.0", "id": self._id, "method": "tools/call", "params": {"name": name, "arguments": arguments}})
        res = self.recv(self._id, timeout)["result"]
        if res.get("isError"):
            return {"_error": "".join(c.get("text", "") for c in res.get("content") or [])}
        sc = res.get("structuredContent")
        if isinstance(sc, dict):
            return sc.get("result", sc) if set(sc) == {"result"} else sc
        return json.loads(res["content"][0]["text"])

    def close(self) -> None:
        if self.proc.poll() is None:
            self.proc.kill()
            self.proc.wait(10)
        for f in (self.proc.stdin, self.proc.stdout):
            try:
                if f is not None:
                    f.close()
            except OSError:
                pass
