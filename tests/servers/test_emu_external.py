"""emu-mcp 실제 에뮬레이터 시험 (@pytest.mark.external) — 고정 Espressif QEMU(esp_develop_9.2.2_20260417)와 PWEH 실행기 pweh_avr_run.

실행 파일은 PWEH_QEMU_XTENSA·PWEH_QEMU_RISCV32·PWEH_AVR_RUN 또는 도구 디렉터리(scripts/install.sh --only qemu_esp / --only simavr)에서
찾고, 없으면 그 시험만 건너뛴다. 펌웨어는 모두 합성이다(tests/fixtures/emu — mkimg_esp 의 hello·echo·reset, AVR 에코·충돌·OOB 탐침).

확인하는 것: 세 칩의 ROM 배너 + PWEH-QEMU-OK, 봉인한 memfd 넘김, 소켓 0, 빈 네트워크 네임스페이스(가능하면 lo 만), SigIgn = SIGPIPE 뿐
(shim 의 신호 복원 — 가짜로는 볼 수 없다), RLIMIT_AS 1 GiB 아래 부팅, 에코 왕복, 모니터 탈출 회귀(Ctrl-A 바이트가 게스트로 감),
리셋 → guest-reset, 리셋 루프 홍수의 접기·원시 로그 상한, AVR 에코·멈춤(guest-halt)·충돌(guest-crash rc 3)·OOB 탐침, 서버 SIGKILL 뒤
PDEATHSIG. 모든 시험은 세션을 멈추고, 끝나면 cwd 가 시험 디렉터리 아래인 qemu-system·pweh_avr_run 프로세스가 없어야 한다.
"""

from __future__ import annotations

import hashlib
import json
import os
import signal
import time
from pathlib import Path
from types import SimpleNamespace

import anyio
import pytest
from mcp import Client

from mcp_helpers import call
from servers.emu_testutil import (
    CRASH_HEX,
    ECHO_HEX,
    ENV_KEYS,
    EXE_NAMES,
    FIX_DIR,
    LEDGER_CHIP,
    QEMU_EXE,
    SIMAVR_COMMIT,
    SYNTH_MAC,
    MiB,
    StdioServer,
    case_dir,
    decide_attestation,
    kill_procs_under,
    make_case,
    pid_alive,
    proc_fd_targets,
    proc_net_ifaces,
    proc_status_hex,
    put_file,
    read_jsonl,
    seed_device_read,
    seed_fact,
    server_env,
    wait_until,
)


def _find(name: str) -> str | None:
    from pweh import toolsdir

    env = (os.environ.get(ENV_KEYS[name]) or "").strip() or None
    for path, _src in toolsdir.emu_binary_candidates(name, None, env, toolsdir.tools_dir()):
        if os.path.isabs(path) and os.path.basename(path) == name and os.path.isfile(path) and os.access(path, os.X_OK):
            return path
    return None


REAL = {name: _find(name) for name in EXE_NAMES}
EMU_NAMES = ("qemu-system-xtensa", "qemu-system-riscv32", "pweh_avr_run")
ROM_BANNER = {"esp32": "ets Jul 29 2019", "esp32s3": "ESP-ROM:esp32s3-20210327", "esp32c3": "ESP-ROM:esp32c3-api1-20210207"}
MONITOR_MARKERS = ("(qemu)", "QEMU 9.2.2 monitor", "9.2.2esp_develop")
SIGPIPE_ONLY = 1 << (signal.SIGPIPE - 1)

pytestmark = [pytest.mark.anyio, pytest.mark.external]


def _need(name: str):
    return pytest.mark.skipif(REAL[name] is None, reason=f"실제 {name} 가 없음 ({ENV_KEYS[name]} 또는 scripts/install.sh)")


def _chips(*chips: str) -> list:
    return [pytest.param(c, marks=_need(QEMU_EXE[c]), id=c) for c in chips]


@pytest.fixture
def anyio_backend():
    return "asyncio"


@pytest.fixture
def real(workspace, tmp_path, monkeypatch):
    """찾은 실제 실행 파일만 서버에 준다 (없는 것은 없는 경로로 — 다른 후보가 끼어들지 않게)."""
    from emu_mcp import backends as B
    from emu_mcp import limits
    from emu_mcp import server as srv
    from pweh.runtime import reset_runtimes

    for name in EXE_NAMES:
        monkeypatch.setenv(ENV_KEYS[name], REAL[name] or str(tmp_path / "absent" / name))
    reset_runtimes()
    B.clear_probe_cache()
    ns = SimpleNamespace(ws=workspace, tmp=tmp_path, srv=srv, B=B, limits=limits)
    try:
        yield ns
    finally:
        srv._shutdown_cleanup()
        live = [s.id for s in srv._live_sessions()]
        with srv._REG_LOCK:
            srv._SESSIONS.clear()
            srv._ENDED.clear()
        B.clear_probe_cache()
        leftovers = kill_procs_under(tmp_path, EMU_NAMES)
    assert not live, f"정리 뒤에도 살아 있는 세션: {live}"
    assert not leftovers, f"남은 에뮬레이터 프로세스: {[(p['pid'], p['exe']) for p in leftovers]}"


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def seed(chip: str, data: bytes, rel: str = "dumps/flash.bin") -> SimpleNamespace:
    cid = make_case(f"real {chip}")
    put_file(cid, rel, data)
    entry = seed_device_read(cid, rel, chip=LEDGER_CHIP[chip])
    seed_fact(cid, "esp-security-info", {"flash_encryption": False, "secure_download_mode": False}, mac=SYNTH_MAC)
    return SimpleNamespace(cid=cid, rel=rel, data=data, seq=entry["seq"], dir=case_dir(cid))


def flash(chip: str, variant: str, text: bytes | None = None) -> bytes:
    import mkimg_esp

    return mkimg_esp.build_flash(chip, variant, text=text)


async def start(c, s, **kw) -> dict:
    r = await call(c, "emu_start", case_id=s.cid, firmware=s.rel, **kw)
    assert r.get("ok") is True, r
    return r


async def ended(c, sid: str, timeout: float = 20.0) -> dict:
    deadline = time.monotonic() + timeout
    while True:
        row = next(r for r in (await call(c, "emu_sessions"))["sessions"] if r["session_id"] == sid)
        if row["state"] in ("ended", "failed"):
            return row
        assert time.monotonic() < deadline, row
        await anyio.sleep(0.05)


def child_pid(s, sid: str) -> int:
    m = json.loads((s.dir / "emu" / sid / "meta.json").read_text(encoding="utf-8"))
    return int(m["child"]["pid"])


def proc_limit(pid: int, name: str) -> tuple[str, str]:
    for line in Path(f"/proc/{pid}/limits").read_text().splitlines():
        if line.startswith(name):
            parts = line[len(name):].split()
            return parts[0], parts[1]
    raise KeyError(name)


async def _import(case_id: str, src: Path) -> str:
    from case_mcp.server import server as case_server

    async with Client(case_server) as cc:
        imp = await call(cc, "case_import_file", case_id=case_id, source_path=str(src), kind="firmware-image", dest_subdir="dumps")
    assert imp.get("ok"), imp
    return imp["artifact"]["path"]


async def _avr_start(c, real, name: str, data: bytes, board: str) -> tuple[str, dict]:
    """가져오기 → provenance-import 증명 → emu_start (AVR 은 늘 이 경로, D16)."""
    cid = make_case(f"real avr {name}")
    src = real.tmp / "outside" / name
    src.parent.mkdir(exist_ok=True)
    src.write_bytes(data)
    rel = await _import(cid, src)
    r1 = await call(c, "emu_start", case_id=cid, firmware=rel, board=board, timeout_s=60, idle_timeout_s=30)
    assert r1.get("status") == "attestation_required", r1
    decide_attestation(r1["attestation_id"])
    r = await call(c, "emu_start", case_id=cid, firmware=rel, board=board, timeout_s=60, idle_timeout_s=30)
    assert r.get("ok") is True, r
    return cid, r


# ---------------------------------------------------------------------------


@pytest.mark.skipif(not any(REAL.values()), reason="실제 에뮬레이터 실행 파일이 하나도 없음")
async def test_real_status_pinned_versions(real):
    async with Client(real.srv.server) as c:
        st = await call(c, "emu_status")
    esp, avr = st["backends"]["esp-qemu"], st["backends"]["avr-simavr"]
    for key, name in (("xtensa", "qemu-system-xtensa"), ("riscv32", "qemu-system-riscv32")):
        if REAL[name] is None:
            continue
        b = esp[key]
        assert b["version_ok"] is True and b["version"] == "QEMU emulator version 9.2.2 (esp_develop_9.2.2_20260417)", b
        assert b["sha256_ok"] is True, b  # 고정 릴리스의 실행 파일
        assert all(r["present"] and r["sha256_ok"] for r in b["roms"].values()), b["roms"]
    if REAL["qemu-system-xtensa"]:
        assert {"esp32", "esp32s3"} <= set(esp["xtensa"]["machines"])
    if REAL["qemu-system-riscv32"]:
        assert "esp32c3" in esp["riscv32"]["machines"]
    if REAL["pweh_avr_run"]:
        assert avr["version_ok"] is True and avr["simavr_commit"] == SIMAVR_COMMIT, avr
        assert avr["driver_version"] == avr["expected_driver_version"] and "warning" not in avr, avr
    assert st["isolation"]["seccomp"] is False


@pytest.mark.parametrize("chip", _chips("esp32", "esp32s3", "esp32c3"))
async def test_real_esp_hello_boot_and_process_view(real, chip):
    """hello 이미지: ROM 배너 + PWEH-QEMU-OK 가 emu_read 로. 프로세스: 실행 파일 = 고정 QEMU, 그룹 리더, 봉인한 memfd 두 개(경로 아님),
    소켓 0, 네임스페이스면 lo 만, SigIgn = SIGPIPE 뿐, RLIMIT_AS 1 GiB·RLIMIT_CORE 0. 정지 → agent-stop, rc 0."""
    s = seed(chip, flash(chip, "hello"))
    binary = REAL[QEMU_EXE[chip]]
    async with Client(real.srv.server) as c:
        r = await start(c, s, timeout_s=120, idle_timeout_s=60)
        sid = r["session_id"]
        assert not any(w.startswith(("binary_sha256_mismatch", "rom_")) for w in r["warnings"]), r["warnings"]
        pid = child_pid(s, sid)
        rd = await call(c, "emu_read", session_id=sid, wait_seconds=20, until="PWEH-QEMU-OK")
        assert rd["matched"] is True, rd
        text = rd["text"]
        assert ROM_BANNER[chip] in text and "rst:0x1 (POWERON" in text and "entry 0x" in text, text
        assert os.path.realpath(os.readlink(f"/proc/{pid}/exe")) == os.path.realpath(binary)
        assert os.getpgid(pid) == pid and os.getsid(pid) == pid
        targets = proc_fd_targets(pid)
        # 넘겨받은 fd 와 QEMU 가 /proc/self/fd/N 으로 다시 연 fd — 서로 다른 memfd 는 플래시·eFuse 둘뿐
        memfds = sorted({t.removesuffix(" (deleted)") for t in targets if t.startswith("/memfd:pweh-emu-")})
        assert memfds == ["/memfd:pweh-emu-efuse", "/memfd:pweh-emu-flash"], targets
        assert not any(t.startswith("socket:") for t in targets), targets
        assert not any(t.endswith((".bin", ".hex")) for t in targets), targets
        if r["isolation"]["netns"]:
            assert proc_net_ifaces(pid) == ["lo"]
        assert proc_status_hex(pid, "SigIgn") == SIGPIPE_ONLY, hex(proc_status_hex(pid, "SigIgn"))
        assert proc_limit(pid, "Max address space") == (str(1 << 30), str(1 << 30))
        assert proc_limit(pid, "Max core file size") == ("0", "0")
        names = {p.name for p in (s.dir / "emu" / sid).iterdir()}
        assert not names & {"flash.bin", "efuse.bin", "fw.hex"}, names
        sp = await call(c, "emu_stop", session_id=sid)
    assert sp["stopped_by"] == "agent-stop" and sp["exit"] == {"code": 0, "signal": None}, sp
    assert "terminating on signal 15" in sp["stderr_tail"] and "efuse" not in sp["stderr_tail"].lower(), sp["stderr_tail"]
    assert not pid_alive(pid)


@pytest.mark.parametrize("chip", _chips("esp32", "esp32s3", "esp32c3"))
async def test_real_echo_round_trip_and_monitor_escape_regression(real, chip):
    """echo 이미지: 에코 왕복. 모니터 탈출 회귀: Ctrl-A c/s/h/b/t/x + 'info version\\r' 은 게스트로 가서 에코되고, '(qemu)'·모니터 배너·
    QEMU 버전 응답은 콘솔·원시 기록·stderr 어디에도 없으며 QEMU 는 계속 돈다 (-monitor none -serial stdio)."""
    s = seed(chip, flash(chip, "echo"))
    escape = "\x01c\x01s\x01h\x01b\x01t\x01x"
    async with Client(real.srv.server) as c:
        r = await start(c, s, timeout_s=120, idle_timeout_s=60)
        sid = r["session_id"]
        pid = child_pid(s, sid)
        rd = await call(c, "emu_read", session_id=sid, wait_seconds=20, until="PWEH-ECHO>")
        assert rd["matched"] is True, rd
        w = await call(c, "emu_write", session_id=sid, data="hello-echo\r")
        assert w["bytes_written"] == 11 and w["partial"] is False
        rd = await call(c, "emu_read", session_id=sid, since_cursor=w["cursor"], wait_seconds=10, until="hello-echo")
        assert rd["matched"] is True, rd
        w = await call(c, "emu_write", session_id=sid, data=escape + "info version\r")
        assert w["bytes_written"] == len(escape) + 13 and w["partial"] is False
        rd = await call(c, "emu_read", session_id=sid, since_cursor=w["cursor"], wait_seconds=10, until="info version")
        assert rd["matched"] is True, rd
        await anyio.sleep(1.0)  # 모니터가 열렸다면 응답할 시간
        rd2 = await call(c, "emu_read", session_id=sid)
        blob = rd["text"] + (rd["pending_line"] or "") + rd2["text"] + (rd2["pending_line"] or "")
        assert rd2["state"] == "running" and pid_alive(pid)
        sp = await call(c, "emu_stop", session_id=sid)
    sdir = s.dir / "emu" / sid
    raw = (sdir / "console.bin").read_bytes()
    err = (sdir / "emulator.stderr.log").read_bytes()
    assert escape.encode() + b"info version" in raw  # 같은 바이트가 게스트로 갔다가 돌아왔다
    for marker in MONITOR_MARKERS:
        assert marker not in blob and marker.encode() not in raw and marker.encode() not in err, marker
    assert sp["stopped_by"] == "agent-stop"


@pytest.mark.parametrize("chip", _chips("esp32", "esp32s3", "esp32c3"))
async def test_real_reset_with_on_reset_exit_is_guest_reset(real, chip):
    s = seed(chip, flash(chip, "reset"))
    async with Client(real.srv.server) as c:
        r = await call(c, "emu_start", case_id=s.cid, firmware=s.rel, timeout_s=60, idle_timeout_s=30)
        assert r.get("ok") is True, r
        row = await ended(c, r["session_id"])
        assert row["stopped_by"] == "guest-reset", row
        rd = await call(c, "emu_read", session_id=r["session_id"])
        assert "PWEH-QEMU-OK" in rd["text"] and rd["exit"] == {"code": 0, "signal": None}, rd
        sp = await call(c, "emu_stop", session_id=r["session_id"])
        assert sp["already_stopped"] is True and sp["stopped_by"] == "guest-reset"


@_need("qemu-system-riscv32")
async def test_real_reset_loop_flood_collapses_and_caps_raw_log(real, monkeypatch):
    """ESP32-C3 리셋 루프(on_reset=reboot): 부팅마다 같은 줄 20개가 한 레코드로 접히고(⟪위 줄 ×20⟫) 원시 로그는 상한에서 멈춘다.

    계약의 'C3 빈(0xFF) 플래시 홍수'는 서버가 그 이미지를 부트로더 헤더가 없다고 emu_not_full_image 로 거부하므로 emu_start 로는 만들 수
    없다 — 그 거부를 확인하고, 홍수는 같은 줄을 반복하는 리셋 이미지로 만든다."""
    monkeypatch.setattr(real.limits, "RAW_LOG_CAP", 8192)
    erased = seed("esp32c3", b"\xff" * (4 * MiB), rel="dumps/erased.bin")
    s = seed("esp32c3", flash("esp32c3", "reset", text=b"PWEH-FLOOD-LINE\r\n" * 20))
    async with Client(real.srv.server) as c:
        r = await call(c, "emu_start", case_id=erased.cid, firmware=erased.rel)
        assert "[emu_not_full_image]" in r.get("_error", ""), r
        r = await start(c, s, on_reset="reboot", timeout_s=60, idle_timeout_s=30)
        sid = r["session_id"]
        deadline = time.monotonic() + 30
        while next(x for x in (await call(c, "emu_sessions"))["sessions"] if x["session_id"] == sid)["raw_bytes"] < 3 * 8192:
            assert time.monotonic() < deadline
            await anyio.sleep(0.1)
        rd = await call(c, "emu_read", session_id=sid, max_chars=65536)
        assert "PWEH-FLOOD-LINE  ⟪위 줄 ×20⟫" in rd["text"] and rd["collapsed"] >= 19, rd["collapsed"]
        assert rd["raw_dropped"] > 0 and rd["state"] == "running"
        assert any("rst:0x3" in h or "리셋 루프" in h for h in rd["hints"]), rd["hints"]
        sp = await call(c, "emu_stop", session_id=sid)
    sdir = s.dir / "emu" / sid
    assert sp["raw_dropped_bytes"] > 0 and sp["raw_bytes"] == sp["raw_dropped_bytes"] + 8192
    assert (sdir / "console.bin").stat().st_size == 8192
    assert any(e["type"] == "cap" and e["what"] == "raw" for e in read_jsonl(sdir / "events.jsonl"))


@_need("pweh_avr_run")
async def test_real_avr_echo_fixture_and_halt(real):
    """커밋한 에코 HEX(ATmega328P, uno): 'OK', 에코, 0x04 → cli; sleep → guest-halt rc 0. 실행기: memfd 하나(--hex-fd), 소켓 0,
    SigIgn = SIGPIPE 뿐(실행기가 직접 무시), RLIMIT_AS 64 MiB, 네임스페이스면 lo 만."""
    async with Client(real.srv.server) as c:
        cid, r = await _avr_start(c, real, "echo.hex", ECHO_HEX.read_bytes(), "uno")
        sid = r["session_id"]
        assert not any(w.startswith("avr_driver_version") for w in r["warnings"]), r["warnings"]
        s = SimpleNamespace(dir=case_dir(cid))
        pid = child_pid(s, sid)
        rd = await call(c, "emu_read", session_id=sid, wait_seconds=10, until="OK")
        assert rd["matched"] is True, rd
        assert os.path.realpath(os.readlink(f"/proc/{pid}/exe")) == os.path.realpath(REAL["pweh_avr_run"])
        targets = proc_fd_targets(pid)
        memfds = [t for t in targets if t.startswith("/memfd:pweh-emu-")]
        assert len(memfds) == 1 and memfds[0].startswith("/memfd:pweh-emu-hex"), targets
        assert not any(t.startswith("socket:") for t in targets), targets
        assert proc_status_hex(pid, "SigIgn") == SIGPIPE_ONLY, hex(proc_status_hex(pid, "SigIgn"))
        assert proc_limit(pid, "Max address space") == (str(64 * MiB), str(64 * MiB))
        if r["isolation"]["netns"]:
            assert proc_net_ifaces(pid) == ["lo"]
        w = await call(c, "emu_write", session_id=sid, data="abc\r\n")
        assert w["bytes_written"] == 5
        rd = await call(c, "emu_read", session_id=sid, since_cursor=w["cursor"], wait_seconds=10, until="abc")
        assert rd["matched"] is True and rd["text"] == "abc", rd
        await call(c, "emu_write", session_id=sid, data="04", encoding="hex")
        row = await ended(c, sid)
        assert row["stopped_by"] == "guest-halt", row
        sp = await call(c, "emu_stop", session_id=sid)
    assert sp["exit"] == {"code": 0, "signal": None} and "pweh_avr_run: state=done" in sp["stderr_tail"], sp
    assert not pid_alive(pid)


@_need("pweh_avr_run")
async def test_real_avr_crash_hex_is_guest_crash_without_listener(real):
    """지운 플래시로 점프하는 HEX → 실행기가 기다리지 않고(GDB 리스너 없음) rc 3 → guest-crash."""
    async with Client(real.srv.server) as c:
        t0 = time.monotonic()
        cid, r = await _avr_start(c, real, "crash.hex", CRASH_HEX, "uno")
        row = await ended(c, r["session_id"], timeout=10)
        assert row["stopped_by"] == "guest-crash" and time.monotonic() - t0 < 10, row
        sp = await call(c, "emu_stop", session_id=r["session_id"])
    assert sp["exit"] == {"code": 3, "signal": None} and "pweh_avr_run: state=crashed" in sp["stderr_tail"], sp
    pid = child_pid(SimpleNamespace(dir=case_dir(cid)), r["session_id"])
    assert not pid_alive(pid)


@_need("pweh_avr_run")
@pytest.mark.parametrize("key,board", [("m328p", "uno"), ("m2560", "mega2560")])
async def test_real_avr_oob_probes_do_not_crash(real, key, board):
    """플래시 범위 밖 LPM/ELPM/SPM 탐침(simavr OOB 수정 확인): 충돌 없이 0xFF 를 읽고 멈춘다(guest-halt rc 0). 328p 는 HEX 의 EEPROM
    레코드를 되읽는다(서버가 EEPROM 을 남겨 넘긴다)."""
    import make_avr_oob_probe

    _mcu, _freq, fname = make_avr_oob_probe.TARGETS[key]
    async with Client(real.srv.server) as c:
        cid, r = await _avr_start(c, real, fname, (FIX_DIR / fname).read_bytes(), board)
        row = await ended(c, r["session_id"], timeout=20)
        assert row["stopped_by"] == "guest-halt", row
        sp = await call(c, "emu_stop", session_id=r["session_id"])
    assert sp["exit"] == {"code": 0, "signal": None}, sp
    raw = (case_dir(cid) / "emu" / r["session_id"] / "console.bin").read_bytes()
    assert raw == make_avr_oob_probe.EXPECTED[key], raw


@_need("qemu-system-xtensa")
def test_real_orphan_server_sigkill_pdeathsig(real):
    """실제 QEMU 세션을 가진 stdio 서버를 SIGKILL 하면 PDEATHSIG 로 QEMU 도 끝나고(네임스페이스 안이어도), 다음 시작 정리가 reaped 로 고친다."""
    s = seed("esp32s3", flash("esp32s3", "hello"))
    srvp = StdioServer(server_env())
    try:
        srvp.initialize()
        r = srvp.call("emu_start", case_id=s.cid, firmware=s.rel, timeout_s=120, idle_timeout_s=60)
        assert r.get("ok") is True, r
        sid = r["session_id"]
        rd = srvp.call("emu_read", session_id=sid, wait_seconds=20, until="PWEH-QEMU-OK")
        assert rd["matched"] is True, rd
        qpid = child_pid(s, sid)
        assert pid_alive(qpid)
        srvp.proc.kill()
        srvp.proc.wait(10)
        assert wait_until(lambda: not pid_alive(qpid), 2.0), "PDEATHSIG 가 QEMU 를 끝내지 않았다"
        out = real.srv._startup_sweep(s.cid)
        assert [x["session_id"] for x in out["reaped"]] == [sid]
        m = json.loads((s.dir / "emu" / sid / "meta.json").read_text(encoding="utf-8"))
        assert m["state"] == "reaped" and m["stopped_by"] == "server-gone"
    finally:
        srvp.close()
