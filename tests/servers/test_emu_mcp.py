"""emu-mcp 서버 시험 — 가짜 에뮬레이터(tests/servers/emu_fake_emulator.py)로 실제 QEMU·simavr 없이 계약(설계 docs/design/emulation.md,
architecture §6.9)을 확인한다.

- 서버는 in-memory Client 로 부르고(stdio 는 스모크·종료 시험만), 케이스·출처 원장·증명·승인은 격리된 작업공간에 만든다.
- 가짜는 서버가 실제로 띄운 프로세스다: shim(rlimit·PDEATHSIG·네트워크 네임스페이스·신호 복원) → exec → fake.log 에 자기가 본 것
  (argv·환경·rlimit·그룹·fd·봉인한 memfd 의 내용 sha256)을 남긴다. 기대값은 서버 코드가 아니라 계약에서 만든다(정확한 argv 템플릿 §5.2·§5.4,
  rlimit 공식, eFuse sha256 …).
- 모든 시험은 세션을 멈추고, fixture 가 끝에 남은 세션·프로세스(cwd 가 시험 임시 디렉터리 아래)를 확인한다.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import signal
import stat
import subprocess
import sys
import time
from pathlib import Path
from types import SimpleNamespace

import anyio
import pytest
from mcp import Client

from mcp_helpers import call, stdio_params
from servers.emu_testutil import (
    ECHO_HEX,
    EFUSE_SHA256,
    ENV_KEYS,
    LEDGER_CHIP,
    NVS_SECRET,
    NVS_TOKEN,
    QEMU_EXE,
    SEALS_ALL,
    SIMAVR_COMMIT,
    SYNTH_MAC,
    VCPUS,
    MiB,
    StdioServer,
    case_dir,
    cpu_limit,
    decide_attestation,
    esp_flash,
    fake_logs_under,
    fake_starts,
    group_members,
    kill_procs_under,
    make_case,
    make_fake_emulator,
    pid_alive,
    put_file,
    read_jsonl,
    rt,
    seed_device_read,
    seed_fact,
    server_env,
    wait_fake_start,
    wait_until,
    write_fake_mode,
)

pytestmark = pytest.mark.anyio

QEMU_VERSION_LINE = "QEMU emulator version 9.2.2 (esp_develop_9.2.2_20260417)"
SIX_TOOLS = {"emu_status", "emu_start", "emu_read", "emu_write", "emu_stop", "emu_sessions"}
ROMS = {"esp32s3_rev0_rom.bin", "esp32-v3-rom.bin", "esp32-v3-rom-app.bin", "esp32c3-rom.bin"}
ARTIFACT_TYPES = {"console.bin": "emu-console-raw", "transcript.masked.txt": "emu-transcript", "events.jsonl": "emu-events",
                  "meta.json": "emu-session", "emulator.stderr.log": "emu-stderr"}


@pytest.fixture
def anyio_backend():
    return "asyncio"


@pytest.fixture
def emu(workspace, tmp_path, monkeypatch):
    """가짜 에뮬레이터 셋을 설치하고 서버가 그것만 쓰게 한다 (실제 QEMU 환경 변수가 있어도, 도구 디렉터리에 설치돼 있어도)."""
    from emu_mcp import backends as B
    from emu_mcp import limits
    from emu_mcp import server as srv
    from pweh.runtime import reset_runtimes

    tools = tmp_path / "fake-bin"
    fakes = make_fake_emulator(tools)
    for name, path in fakes.items():
        monkeypatch.setenv(ENV_KEYS[name], str(path))
    empty = tmp_path / "no-tools"
    empty.mkdir()
    monkeypatch.setenv("PWEH_TOOLS_DIR", str(empty))  # 도구 디렉터리의 실제 설치가 후보가 되지 않게
    reset_runtimes()
    B.clear_probe_cache()
    write_fake_mode(tools, "boot")
    for name, path in fakes.items():
        info, _rejected = B.locate(name, srv.rt().config)
        assert info is not None and info.path == str(path), (name, info)
    monkeypatch.setattr(limits, "STOP_GRACE_S", 1.0)  # SIGKILL 단계 시험을 빠르게

    def mode(m: str = "boot", **cfg):
        return write_fake_mode(tools, m, **cfg)

    ns = SimpleNamespace(tools=tools, fakes=fakes, mode=mode, ws=workspace, tmp=tmp_path, srv=srv, B=B, limits=limits)
    try:
        yield ns
    finally:
        srv._shutdown_cleanup()
        live = [s.id for s in srv._live_sessions()]
        with srv._REG_LOCK:
            srv._SESSIONS.clear()
            srv._ENDED.clear()
        B.clear_probe_cache()
        leftovers = kill_procs_under(tmp_path)
    assert not live, f"정리 뒤에도 살아 있는 세션: {live}"
    assert not leftovers, f"시험이 남긴 프로세스: {[(p['pid'], p['cmdline'][:3]) for p in leftovers]}"


# ---------------------------------------------------------------------------
# 도우미
# ---------------------------------------------------------------------------


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


_DEFAULT = object()


def seed_esp(chip: str = "esp32s3", *, rel: str | None = None, data: bytes | None = None, variant: str = "hello", nvs: bool = True,
             verify: str = "double-read", match: bool | None = True, offset=0, mac: str | None = SYNTH_MAC, ledger_chip=_DEFAULT,
             security: bool | None = False, psram_feature: str | None = None, case_id: str | None = None) -> SimpleNamespace:
    """합성 전체 플래시를 케이스에 두고 esp_read_flash_start 와 같은 device-read 기록(+ 같은 MAC 의 보안·칩 사실)을 남긴다."""
    cid = case_id or make_case(f"emu {chip}")
    rel = rel or f"dumps/{chip}-flash.bin"
    data = data if data is not None else esp_flash(chip, variant, nvs=nvs)
    put_file(cid, rel, data)
    entry = seed_device_read(cid, rel, chip=LEDGER_CHIP[chip] if ledger_chip is _DEFAULT else ledger_chip, mac=mac, verify=verify,
                             match=match, offset=offset)
    if security is not None:
        seed_fact(cid, "esp-security-info", {"flash_encryption": security, "secure_download_mode": False}, mac=mac or SYNTH_MAC)
    if psram_feature:
        seed_fact(cid, "esp-chip-info", {"chip": LEDGER_CHIP[chip], "features": ["Wi-Fi", "BT 5 (LE)", psram_feature]},
                  mac=mac or SYNTH_MAC)
    return SimpleNamespace(cid=cid, rel=rel, data=data, sha=_sha(data), seq=entry["seq"], dir=case_dir(cid))


def expected_esp_argv(exe: str, chip: str, flash_fd: int, efuse_fd: int, *, psram=("none", None), watchdog: str = "disabled",
                      on_reset: str = "exit") -> list[str]:
    """계약(설계 §5.2)의 정확한 ESP argv — 서버 코드로 만들지 않는다."""
    argv = [exe, "-no-user-config", "-nodefaults", "-machine", chip, "-accel", "tcg,tb-size=64", "-display", "none",
            "-monitor", "none", "-nic", "none", "-serial", "stdio",
            "-drive", f"file=/proc/self/fd/{flash_fd},if=mtd,format=raw",
            "-drive", f"file=/proc/self/fd/{efuse_fd},if=none,format=raw,id=efuse",
            "-global", f"driver=nvram.{chip}.efuse,property=drive,value=efuse"]
    if watchdog == "disabled":
        argv += ["-global", f"driver=timer.{chip}.timg,property=wdt_disable,value=true"]
    mode, mb = psram
    if mode in ("quad", "octal"):
        argv += ["-m", f"{mb}M"]
        if mode == "octal":
            argv += ["-global", "driver=ssi_psram,property=is_octal,value=true"]
    argv.append("-snapshot")
    if on_reset == "exit":
        argv.append("-no-reboot")
    return argv


def handoff(fake: dict, role: str) -> dict:
    hits = [h for h in fake["handoff"] if h["role"] == role]
    assert len(hits) == 1, fake["handoff"]
    return hits[0]


def sess_dir(s: SimpleNamespace, sid: str) -> Path:
    return s.dir / "emu" / sid


def events(sdir: Path) -> list[dict]:
    return read_jsonl(sdir / "events.jsonl")


def meta(sdir: Path) -> dict:
    return json.loads((sdir / "meta.json").read_text(encoding="utf-8"))


def err_code(r: dict) -> str | None:
    """도구 오류 글('Error executing tool …: [code] message')의 오류 코드."""
    m = re.search(r"\[([a-z_]+)\]", r.get("_error") or "")
    return m.group(1) if m else None


async def start(c, s: SimpleNamespace, **kw) -> dict:
    r = await call(c, "emu_start", case_id=s.cid, firmware=s.rel, **kw)
    assert r.get("ok") is True, r
    return r


async def poll_state(c, sid: str, want, timeout: float = 10.0) -> dict:
    """emu_sessions 로 상태를 본다 (무활동 시계를 건드리지 않는다)."""
    deadline = time.monotonic() + timeout
    while True:
        rows = {r["session_id"]: r for r in (await call(c, "emu_sessions"))["sessions"]}
        row = rows.get(sid)
        if row is not None and row["state"] in want:
            return row
        if time.monotonic() > deadline:
            raise AssertionError(f"{sid} 가 {want} 가 되지 않았다: {row}")
        await anyio.sleep(0.05)


# ---------------------------------------------------------------------------
# emu_status
# ---------------------------------------------------------------------------


async def test_status_reports_backends_probed_through_shim_and_cached(emu):
    from emu_mcp.backends import expected_avr_driver_version

    async with Client(emu.srv.server) as c:
        st = await call(c, "emu_status")
        st2 = await call(c, "emu_status")
    assert st["ok"] is True
    esp = st["backends"]["esp-qemu"]
    assert esp["available"] is True and esp["chips"] == ["esp32", "esp32s3", "esp32c3"]
    assert esp["chips_available"] == ["esp32", "esp32s3", "esp32c3"]
    for key, name in (("xtensa", "qemu-system-xtensa"), ("riscv32", "qemu-system-riscv32")):
        b = esp[key]
        assert b["path"] == str(emu.fakes[name]) and b["source"] in ("config", "env"), b
        assert b["version"] == QEMU_VERSION_LINE and b["expected_version"] == QEMU_VERSION_LINE and b["version_ok"] is True
        assert {"esp32", "esp32s3", "esp32c3"} <= set(b["machines"])
        # 가짜는 고정 릴리스의 실행 파일이 아니고 ROM 도 없다 — 경고만(가용성에는 영향 없음)
        assert b["sha256_ok"] is False and b["expected_sha256"]
        assert set(b["roms"]) == ROMS and not any(r["present"] for r in b["roms"].values())
    avr = st["backends"]["avr-simavr"]
    assert avr["available"] is True and avr["version_ok"] is True and avr["path"] == str(emu.fakes["pweh_avr_run"])
    assert avr["simavr_commit"] == SIMAVR_COMMIT and avr["expected_commit"] == SIMAVR_COMMIT
    assert avr["driver_version"] == expected_avr_driver_version() and "warning" not in avr
    assert set(avr["boards"]) == {"uno", "nano", "pro-mini-5v", "pro-mini-3v3", "mega2560", "leonardo", "micro", "custom"}
    assert set(avr["mcus"]) == {"atmega8", "atmega168", "atmega328p", "atmega32u4", "atmega644p", "atmega1280", "atmega1284p",
                                "atmega2560"}
    iso = st["isolation"]
    assert iso["netns"] in ("available", "unavailable", "unknown") and iso["seccomp"] is False
    assert isinstance(iso["core_pattern_piped"], bool)
    assert st["sessions"] == {"this_process": 0}
    assert not any("install.sh" in h for h in st["hints"]), st["hints"]
    # 결정 D13 한도 (코드 상수)
    lim = st["limits"]
    assert lim["max_sessions_per_case"] == 2 and lim["max_sessions_per_process"] == 4
    assert lim["timeout_s"] == {"min": 10, "max": 3600, "default": 600}
    assert lim["idle_timeout_s"] == {"min": 30, "max": 1800, "default": 300}
    assert lim["raw_log_cap"] == 32 * MiB and lim["stderr_log_cap"] == MiB and lim["transcript_cap"] == 16 * MiB
    assert lim["rlimit_as"] == {"esp-qemu": 1 << 30, "avr-simavr": 64 * MiB}
    assert lim["rlimit_fsize"] == {"esp-qemu": 64 * MiB, "avr-simavr": MiB}
    assert lim["rlimit_nofile"] == 256 and lim["rlimit_core"] == 0 and lim["write_max"] == 4096 and lim["write_timeout_s"] == 2
    assert lim["read_max_chars"] == {"min": 256, "max": 65536} and lim["read_wait_max_s"] == 50
    assert lim["until"] == {"max_literals": 8, "max_chars": 64}
    # 조회는 shim 아래(최소 환경·rlimit·cwd /)에서, 경로·크기·mtime·inode 로 캐시
    probes = read_jsonl(emu.tools / "probe.log")
    assert sorted((p["exe"], p["kind"]) for p in probes) == [
        ("pweh_avr_run", "version"), ("qemu-system-riscv32", "machines"), ("qemu-system-riscv32", "version"),
        ("qemu-system-xtensa", "machines"), ("qemu-system-xtensa", "version")]
    for p in probes:
        assert p["env"] == ["LANG", "LC_ALL", "PATH"] and p["cwd"] == "/" and p["pgid"] == p["pid"], p
        want_as = 64 * MiB if p["exe"] == "pweh_avr_run" else 1 << 30
        assert p["rlimit_as"] == [want_as, want_as], p
    assert st2["backends"] == st["backends"]


async def test_missing_binary_and_version_gates(emu, monkeypatch):
    """고정 버전만(D9): 다른 QEMU 버전·머신 목록 → emu_tool_version, simavr 커밋이 다르면 emu_tool_version, 드라이버 버전만 다르면 경고.
    실행 파일이 없거나 절대 경로가 아니거나 basename 이 허용 목록 밖이면 후보에서 빠지고 tool_missing."""
    from pweh.runtime import reset_runtimes

    s = seed_esp()
    async with Client(emu.srv.server) as c:
        emu.mode("boot", qemu_version="QEMU emulator version 9.2.2 (esp_develop_9.2.2_20250101)")
        emu.B.clear_probe_cache()
        r = await call(c, "emu_start", case_id=s.cid, firmware=s.rel)
        assert err_code(r) == "emu_tool_version" and "install.sh" in r["_error"], r
        st = await call(c, "emu_status")
        assert st["backends"]["esp-qemu"]["available"] is False and st["backends"]["esp-qemu"]["xtensa"]["version_ok"] is False
        assert any("--only qemu_esp" in h for h in st["hints"])

        emu.mode("boot", machines=["esp32", "esp32c3", "none"])
        emu.B.clear_probe_cache()
        r = await call(c, "emu_start", case_id=s.cid, firmware=s.rel)
        assert err_code(r) == "emu_tool_version", r

        emu.mode("boot", avr_commit="0" * 40)
        emu.B.clear_probe_cache()
        r = await call(c, "emu_start", case_id=s.cid, firmware="dumps/none.hex", board="uno")
        assert err_code(r) == "emu_tool_version" and "--only simavr" in r["_error"], r

        emu.mode("boot", avr_version="0.0-old")
        emu.B.clear_probe_cache()
        st = await call(c, "emu_status")
        avr = st["backends"]["avr-simavr"]
        assert avr["available"] is True and avr["version_ok"] is True and "0.0-old" in avr["version"] and avr.get("warning")

    # qemu-system-riscv32 만 있으면 ESP32-C3 는 되고 ESP32·S3 는 tool_missing (칩마다 실행 파일)
    monkeypatch.setenv("PWEH_QEMU_XTENSA", str(emu.tmp / "missing" / "qemu-system-xtensa"))
    reset_runtimes()
    emu.B.clear_probe_cache()
    emu.mode("boot")
    c3 = seed_esp("esp32c3")
    async with Client(emu.srv.server) as c:
        st = await call(c, "emu_status")
        assert st["backends"]["esp-qemu"]["available"] is True and st["backends"]["esp-qemu"]["chips_available"] == ["esp32c3"]
        r = await call(c, "emu_start", case_id=s.cid, firmware=s.rel)
        assert err_code(r) == "tool_missing", r
        r = await start(c, c3)
        assert r["target"]["chip"] == "esp32c3"
        await call(c, "emu_stop", session_id=r["session_id"])

    # 실행 파일 없음 / 상대 경로 / 허용 밖 basename (도구 디렉터리는 비어 있다)
    bad = emu.tmp / "bad-bin"
    bad.mkdir()
    os.symlink(emu.fakes["qemu-system-xtensa"], bad / "qemu-system-x86_64")
    monkeypatch.setenv("PWEH_QEMU_XTENSA", str(emu.tmp / "missing" / "qemu-system-xtensa"))
    monkeypatch.setenv("PWEH_QEMU_RISCV32", "qemu-system-riscv32")
    monkeypatch.setenv("PWEH_AVR_RUN", str(bad / "qemu-system-x86_64"))
    reset_runtimes()
    emu.B.clear_probe_cache()
    emu.mode("boot")
    async with Client(emu.srv.server) as c:
        st = await call(c, "emu_status")
        esp, avr = st["backends"]["esp-qemu"], st["backends"]["avr-simavr"]
        assert esp["available"] is False and avr["available"] is False
        reasons = {r["reason"] for b in (esp["xtensa"], esp["riscv32"], avr) for r in b.get("rejected", [])}
        assert any("없다" in x for x in reasons) and any("절대 경로" in x for x in reasons) and any("basename" in x for x in reasons), reasons
        assert any("--only qemu_esp" in h for h in st["hints"]) and any("--only simavr" in h for h in st["hints"])
        r = await call(c, "emu_start", case_id=s.cid, firmware=s.rel)
        assert err_code(r) == "tool_missing" and "install.sh" in r["_error"], r
        r = await call(c, "emu_start", case_id=s.cid, firmware="dumps/none.hex", board="uno")
        assert err_code(r) == "tool_missing", r
    assert fake_logs_under(s.dir) == []  # 이 케이스에서는 어느 경우에도 에뮬레이터를 띄우지 않았다


# ---------------------------------------------------------------------------
# ESP 흐름
# ---------------------------------------------------------------------------


async def test_esp_flow_start_read_write_stop(emu):
    """status → ESP32-S3 start(device-read, 이중 읽기, 오프셋 0, 같은 MAC 의 PSRAM 8MB 사실) → read(wait) → write → stop.

    가짜가 본 것(fake.log)으로 정확한 argv·봉인한 memfd 두 개의 내용·환경을 확인하고, 세션 파일·meta.json·아티팩트를 본다."""
    s = seed_esp(psram_feature="Embedded PSRAM 8MB (AP_3v3)")
    emu.mode("echo")
    async with Client(emu.srv.server) as c:
        st = await call(c, "emu_status")
        assert st["backends"]["esp-qemu"]["available"]
        r = await start(c, s, timeout_s=120, idle_timeout_s=60)
        sid = r["session_id"]
        sdir = sess_dir(s, sid)
        assert sid == "emu-001" and r["state"] == "running" and r["backend"] == "esp-qemu"
        assert r["target"] == {"chip": "esp32s3", "machine": "esp32s3", "vcpus": 2}
        fw = r["firmware"]
        assert fw["path"] == s.rel and fw["sha256"] == s.sha and fw["size"] == len(s.data)
        assert fw["provenance_reason"] == "device-read" and fw["verify"] == "double-read" and fw["ledger_seq"] == s.seq
        wc = r["working_copy"]
        assert "path" not in wc and wc["handoff"] == "memfd" and wc["size"] == 4 * MiB and wc["padded_from"] == 4 * MiB
        assert wc["sha256"] == s.sha  # 이미 4 MiB — 채울 것이 없다
        assert r["psram"] == {"mode": "octal", "mb": 8, "source": "device-fact"}
        assert r["efuse"] == {"sha256": EFUSE_SHA256["esp32s3"], "size": 1024}
        assert r["isolation"]["monitor"] == "none" and r["isolation"]["network"] == "none"
        assert r["isolation"]["snapshot"] is True and r["isolation"]["gdbstub"] is False and r["isolation"]["semihosting"] is False
        assert isinstance(r["isolation"]["netns"], bool)
        assert r["masking"]["patterns"] is True and r["masking"]["known_secrets"] >= 2 and r["masking"]["nvs_encrypted"] is False
        assert r["cursor"] == 0 and r["dir"] == f"emu/{sid}" and sid in r["next_steps"]
        assert r["limits"] == {"timeout_s": 120, "idle_timeout_s": 60, "rlimit_as": 1 << 30, "rlimit_cpu": list(cpu_limit(120, 2))}
        codes = [w.split(":", 1)[0] for w in r["warnings"]]
        assert "binary_sha256_mismatch" in codes and "single_read" not in codes and "security_state_unknown" not in codes, codes
        assert codes.count("rom_missing") == 4  # 가짜 옆에는 <bin>/../share/qemu 의 ROM 이 없다 — 경고만
        assert NVS_SECRET not in json.dumps(r, ensure_ascii=False)

        fake = wait_fake_start(sdir)
        exe = str(emu.fakes["qemu-system-xtensa"])
        fl, ef = handoff(fake, "flash"), handoff(fake, "efuse")
        assert fake["argv"] == expected_esp_argv(exe, "esp32s3", fl["fd"], ef["fd"], psram=("octal", 8))
        assert fl["sha256"] == wc["sha256"] and fl["size"] == 4 * MiB and fl["seals"] == SEALS_ALL and fl["write_blocked"] is True
        assert ef["sha256"] == EFUSE_SHA256["esp32s3"] and ef["size"] == 1024 and ef["seals"] == SEALS_ALL and ef["write_blocked"]
        assert fl["name"].startswith("/memfd:pweh-emu-flash") and ef["name"].startswith("/memfd:pweh-emu-efuse")
        assert len(fake["memfds"]) == 2 and fake["sockets"] == 0

        rd = await call(c, "emu_read", session_id=sid, wait_seconds=5, until="PWEH-ECHO>")
        assert rd["ok"] and rd["source"] == "live" and rd["matched"] is True and rd["match"] == "PWEH-ECHO>", rd
        assert "PWEH-ECHO>" in rd["text"] and rd["cursor_start"] == 0 and rd["cursor_end"] == len(b"PWEH-ECHO>\r\n")
        assert rd["state"] == "running" and rd["raw_total"] == len(b"PWEH-ECHO>\r\n") and rd["raw_dropped"] == 0
        w = await call(c, "emu_write", session_id=sid, data="hello-echo\r\n")
        assert w == {"ok": True, "session_id": sid, "bytes_written": 12, "bytes_requested": 12, "partial": False,
                     "cursor": rd["raw_total"], "state": "running"}, w
        rd2 = await call(c, "emu_read", session_id=sid, since_cursor=w["cursor"], wait_seconds=5, until="hello-echo")
        assert rd2["matched"] is True and rd2["text"] == "hello-echo" and rd2["cursor_start"] == w["cursor"], rd2
        # until 은 리터럴만(정규식 아님, D15) — 목록이면 처음 맞은 리터럴, until_ignore_case 는 casefold
        lit = await call(c, "emu_read", session_id=sid, since_cursor=0, until="PWEH.ECHO>")
        assert lit["matched"] is False and lit["match"] is None
        lit = await call(c, "emu_read", session_id=sid, since_cursor=0, until=["NOT-THERE", "hello-echo", "PWEH-ECHO>"])
        assert lit["matched"] is True and lit["match"] == "PWEH-ECHO>"  # 가장 앞선 줄
        lit = await call(c, "emu_read", session_id=sid, since_cursor=0, until="pweh-echo>", until_ignore_case=True)
        assert lit["matched"] is True and lit["match"] == "pweh-echo>"
        lit = await call(c, "emu_read", session_id=sid, since_cursor=0, until="pweh-echo>")
        assert lit["matched"] is False

        ss = await call(c, "emu_sessions")
        row = ss["sessions"][0]
        assert ss["count"] == 1 and row["session_id"] == sid and row["case_id"] == s.cid and row["state"] == "running"
        assert row["firmware"] == {"path": s.rel, "sha256": s.sha} and row["dir"] == f"emu/{sid}" and row["timeout_in_s"] <= 120
        assert "hello-echo" not in json.dumps(ss) and ss["other_process_live"] == {}

        m = meta(sdir)
        assert m["schema"] == "pweh.emu-session/v1" and m["state"] == "running" and m["session_id"] == sid and m["case_id"] == s.cid
        assert m["owner"]["server"] == "emu-mcp" and m["owner"]["pid"] == os.getpid()
        from pweh import procutil

        assert m["child"] == {"pid": fake["pid"], "start_ticks": procutil.proc_stat(fake["pid"])[1], "pgid": fake["pid"],
                              "exe_realpath": os.path.realpath(os.readlink(f"/proc/{fake['pid']}/exe"))}
        assert m["argv"] == fake["argv"] and m["env_keys"] == ["PATH", "LANG", "LC_ALL", "TMPDIR", "HOME"]
        assert m["firmware"]["sha256"] == s.sha and "path" not in m["working_copy"] and m["efuse"]["sha256"] == EFUSE_SHA256["esp32s3"]
        assert m["limits"]["rlimit_as"] == 1 << 30 and m["limits"]["rlimit_cpu"] == list(cpu_limit(120, 2))
        assert m["limits"]["rlimit_core"] == 0 and m["limits"]["rlimit_nofile"] == 256 and m["limits"]["rlimit_fsize"] == 64 * MiB
        assert m["isolation"]["netns"] == r["isolation"]["netns"] and m["masking"]["known_secrets"] == r["masking"]["known_secrets"]

        sp = await call(c, "emu_stop", session_id=sid)
        assert sp["ok"] and sp["already_stopped"] is False and sp["state"] == "ended" and sp["stopped_by"] == "agent-stop", sp
        assert sp["exit"] == {"code": 0, "signal": None}  # QEMU 는 SIGTERM 에 rc 0 으로 끝난다
        assert "terminating on signal 15" in sp["stderr_tail"] and sp["raw_bytes"] == len(b"PWEH-ECHO>\r\nhello-echo\r\n")
        assert sp["writes"] == 1 and sp["bytes_written"] == 12 and sp["meta_path"] == f"emu/{sid}/meta.json"
        assert {(a["path"], a["type"], a["kind"]) for a in sp["artifacts"]} == {
            (f"emu/{sid}/{n}", t, "other") for n, t in ARTIFACT_TYPES.items()}
        assert not pid_alive(fake["pid"]) and not group_members(fake["pid"])
        again = await call(c, "emu_stop", session_id=sid)
        assert again["already_stopped"] is True and again["stopped_by"] == "agent-stop"
        nw = await call(c, "emu_write", session_id=sid, data="x")
        assert err_code(nw) == "emu_not_running", nw
        rd3 = await call(c, "emu_read", session_id=sid)
        assert rd3["state"] == "ended" and rd3["stopped_by"] == "agent-stop" and rd3["exit"] == {"code": 0, "signal": None}

    # 세션 파일: 0700/0600, 펌웨어 사본 없음, emu/.lock 0600, meta ended
    assert stat.S_IMODE(os.stat(sdir).st_mode) == 0o700 and stat.S_IMODE(os.stat(sdir / "tmp").st_mode) == 0o700
    names = sorted(p.name for p in sdir.iterdir())
    assert names == sorted(["console.bin", "emulator.stderr.log", "events.jsonl", "fake.log", "meta.json", "tmp",
                            "transcript.masked.txt"]), names
    for n in ARTIFACT_TYPES:
        assert stat.S_IMODE(os.stat(sdir / n).st_mode) == 0o600, n
    assert stat.S_IMODE(os.stat(s.dir / "emu" / ".lock").st_mode) == 0o600
    assert (sdir / "console.bin").read_bytes() == b"PWEH-ECHO>\r\nhello-echo\r\n"
    m = meta(sdir)
    assert m["state"] == "ended" and m["stopped_by"] == "agent-stop" and m["ended_at"] and m["exit"] == {"code": 0, "signal": None}
    assert m["counters"]["raw_bytes"] == len(b"PWEH-ECHO>\r\nhello-echo\r\n") and m["counters"]["bytes_written"] == 12
    ev = events(sdir)
    types = [e["type"] for e in ev]
    assert types[:2] == ["start", "ready"] and "stop_request" in types and types[-1] == "exit", types
    assert ev[-1]["stopped_by"] == "agent-stop"
    ev_text = (sdir / "events.jsonl").read_text(encoding="utf-8")
    assert "PWEH-ECHO" not in ev_text and "hello-echo" not in ev_text  # 콘솔 글·입력 원문 없음
    # 아티팩트: kind other + extra{type, session_id, backend, target}, meta.json 의 sha256 = 마지막 파일
    arts = {a["path"]: a for a in rt().cases.get(s.cid).load()["artifacts"]}
    for n, typ in ARTIFACT_TYPES.items():
        a = arts[f"emu/{sid}/{n}"]
        assert a["kind"] == "other" and a["producer"] == "emu-mcp"
        assert a["extra"] == {"type": typ, "session_id": sid, "backend": "esp-qemu",
                              "target": {"chip": "esp32s3", "machine": "esp32s3", "vcpus": 2}}, a
        assert a["sha256"] == _sha((sdir / n).read_bytes()), n


@pytest.mark.parametrize("chip,kw,psram", [
    ("esp32", {}, ("quad", 4)),
    ("esp32c3", {}, ("none", None)),
    ("esp32s3", {}, ("quad", 32)),
    ("esp32s3", {"psram": "none", "watchdog": "emulated", "on_reset": "reboot"}, ("none", None)),
    ("esp32s3", {"psram": "quad", "psram_mb": 2}, ("quad", 2)),
    ("esp32s3", {"psram": "octal"}, ("octal", 32)),
    ("esp32", {"psram": "quad", "psram_mb": 2, "watchdog": "emulated"}, ("quad", 2)),
])
async def test_esp_targets_argv_template_and_rlimits(emu, chip, kw, psram):
    """칩마다 실행 파일·-machine·eFuse 블롭·PSRAM 자동(esp32 quad 4, s3 기본 quad 32, c3 없음)·옵션(watchdog·on_reset)이
    정확한 템플릿으로 가고, shim 이 계약의 rlimit 을 건다."""
    s = seed_esp(chip)
    timeout_s = 100
    async with Client(emu.srv.server) as c:
        r = await start(c, s, timeout_s=timeout_s, idle_timeout_s=50, **kw)
        sid = r["session_id"]
        fake = wait_fake_start(sess_dir(s, sid))
        await call(c, "emu_stop", session_id=sid)
    exe = str(emu.fakes[QEMU_EXE[chip]])
    fl, ef = handoff(fake, "flash"), handoff(fake, "efuse")
    assert fake["argv"] == expected_esp_argv(exe, chip, fl["fd"], ef["fd"], psram=psram, watchdog=kw.get("watchdog", "disabled"),
                                             on_reset=kw.get("on_reset", "exit"))
    assert r["target"] == {"chip": chip, "machine": chip, "vcpus": VCPUS[chip]}
    assert r["psram"]["mode"] == psram[0] and r["psram"]["mb"] == psram[1]
    assert r["psram"]["source"] == ("argument" if "psram" in kw else "default")
    assert ef["sha256"] == EFUSE_SHA256[chip] and ef["size"] == (124 if chip == "esp32" else 1024)
    assert fl["sha256"] == r["working_copy"]["sha256"] == s.sha
    rl = fake["rlimits"]
    soft, hard = cpu_limit(timeout_s, VCPUS[chip])
    assert rl["RLIMIT_CPU"] == [soft, hard], (rl["RLIMIT_CPU"], soft, hard)
    assert rl["RLIMIT_AS"] == [1 << 30, 1 << 30] and rl["RLIMIT_FSIZE"] == [64 * MiB, 64 * MiB]
    assert rl["RLIMIT_CORE"] == [0, 0] and rl["RLIMIT_NOFILE"] == [256, 256]
    assert r["limits"]["rlimit_cpu"] == [soft, hard]


async def test_shim_effects_seen_by_the_emulator(emu):
    """shim 효과 (fake.log): 프로세스 그룹·세션 리더, 부모 = 서버, 환경 변수 정확히 다섯, 표준 입출력 파이프, cwd = 세션, 소켓 0,
    네트워크 네임스페이스를 썼으면 lo 만."""
    s = seed_esp()
    async with Client(emu.srv.server) as c:
        r = await start(c, s)
        sid = r["session_id"]
        sdir = sess_dir(s, sid)
        fake = wait_fake_start(sdir)
        await call(c, "emu_stop", session_id=sid)
    real_sdir = os.path.realpath(sdir)
    assert fake["pgid"] == fake["pid"] == fake["sid"] and fake["ppid"] == os.getpid() and fake["uid"] == os.getuid()
    assert sorted(fake["env"]) == ["HOME", "LANG", "LC_ALL", "PATH", "TMPDIR"]
    assert fake["env"]["PATH"] == "/usr/bin:/bin" and fake["env"]["LANG"] == "C" and fake["env"]["LC_ALL"] == "C"
    assert os.path.realpath(fake["env"]["HOME"]) == real_sdir and os.path.realpath(fake["env"]["TMPDIR"]) == os.path.join(real_sdir, "tmp")
    assert os.path.isabs(fake["env"]["TMPDIR"])
    assert fake["cwd"] == real_sdir and fake["pipes"] == {"stdin": True, "stdout": True, "stderr": True}
    assert fake["sockets"] == 0 and len(fake["memfds"]) == 2
    fd_targets = [t for _n, t in fake["fds"]]
    assert not any(t.endswith((".bin", ".hex")) for t in fd_targets), fd_targets  # 펌웨어 파일을 경로로 받지 않는다
    if r["isolation"]["netns"]:
        assert fake["net"] == ["lo"], fake["net"]


@pytest.mark.parametrize("name,argv", [
    ("qemu-system-xtensa", ["-no-user-config", "-nodefaults", "-machine", "esp32s3", "-monitor", "stdio"]),
    ("qemu-system-xtensa", ["-no-user-config", "-nodefaults", "-machine", "esp32s3", "-serial", "mon:stdio"]),
    ("qemu-system-riscv32", ["-no-user-config", "-nodefaults", "-machine", "esp32c3", "-gdb", "tcp::1234"]),
    ("qemu-system-xtensa", ["-nodefaults", "-machine", "esp32"]),
    ("qemu-system-xtensa", ["-no-user-config", "-nodefaults", "-drive", "file=/etc/passwd,if=mtd,format=raw"]),
    ("qemu-system-xtensa", ["-no-user-config", "-nodefaults", "-netdev", "user,id=n0"]),
    ("pweh_avr_run", ["--mcu", "atmega328p", "--freq", "16000000", "--uart", "0", "--realtime", "fw.hex"]),
    ("pweh_avr_run", ["--mcu", "atmega328p", "--freq", "16000000", "--max-cycles", "100", "--hex-fd", "5"]),
])
def test_fake_emulator_refuses_forbidden_tokens(emu, tmp_path, name, argv):
    """시험 도구의 이중 확인: 가짜는 설계 §5.5 의 금지 토큰(또는 서버 템플릿 밖의 AVR 옵션)을 받으면 표식과 함께 99 로 끝나고
    시작 기록을 남기지 않는다 (위 시험들에서 가짜가 시작했다는 것은 서버의 argv 가 이 확인을 통과했다는 뜻이다)."""
    work = tmp_path / "direct"
    work.mkdir()
    cp = subprocess.run([str(emu.fakes[name]), *argv], cwd=str(work), stdin=subprocess.DEVNULL, capture_output=True, timeout=30)
    assert cp.returncode == 99 and b"FAKE-FORBIDDEN-TOKEN" in cp.stderr, (cp.returncode, cp.stderr)
    assert not (work / "fake.log").exists()


@pytest.mark.parametrize("backend,rc,reason,on_reset,want", [
    ("esp-qemu", 0, None, "exit", "guest-reset"),
    ("esp-qemu", 0, None, "reboot", "guest-exit"),
    ("esp-qemu", 1, None, "exit", "config-error"),
    ("esp-qemu", 2, None, "exit", "config-error"),
    ("esp-qemu", 0, "agent-stop", "exit", "agent-stop"),  # rc 0 만으로는 리셋과 서버의 SIGTERM 을 가릴 수 없다 — 먼저 기록한 이유
    ("esp-qemu", -signal.SIGTERM, "wall-timeout", "exit", "wall-timeout"),
    ("esp-qemu", 0, "idle-timeout", "exit", "idle-timeout"),
    ("esp-qemu", 0, "server-shutdown", "exit", "server-shutdown"),
    ("esp-qemu", -signal.SIGXCPU, None, "exit", "rlimit-cpu"),
    ("esp-qemu", -signal.SIGXFSZ, None, "exit", "rlimit-fsize"),
    ("esp-qemu", -signal.SIGKILL, None, "exit", "killed"),
    ("avr-simavr", 0, None, "exit", "guest-halt"),
    ("avr-simavr", 1, None, "exit", "config-error"),
    ("avr-simavr", 2, None, "exit", "config-error"),
    ("avr-simavr", 3, None, "exit", "guest-crash"),
    ("avr-simavr", 4, None, "exit", "max-cycles"),
    ("avr-simavr", 5, None, "exit", "server-gone"),
    ("avr-simavr", 5, "server-shutdown", "exit", "server-shutdown"),
    ("avr-simavr", -signal.SIGTERM, "agent-stop", "exit", "agent-stop"),
    ("avr-simavr", -signal.SIGSEGV, None, "exit", "killed"),
])
def test_stopped_by_mapping(backend, rc, reason, on_reset, want):
    """stopped_by (설계 §4.1·§5.4): 서버가 신호 전에 기록한 이유가 이기고, 그 밖에는 백엔드별 종료 코드·신호."""
    from emu_mcp import backends as B

    assert B.classify_exit(backend, rc, reason, on_reset=on_reset) == want


async def test_read_pages_with_max_chars_and_more(emu):
    """max_chars 는 text 의 글자 수 상한이다: more=true 면 cursor_end(레코드 경계)부터 이어 읽어 빠짐·겹침 없이 모든 줄을 받는다."""
    lines = [f"line-{i:02d}-" + "x" * 40 for i in range(20)]
    total = sum(len(line) + 2 for line in lines)
    emu.mode("boot", lines=lines)
    s = seed_esp()
    async with Client(emu.srv.server) as c:
        r = await start(c, s)
        sid = r["session_id"]
        deadline = time.monotonic() + 10
        while next(x for x in (await call(c, "emu_sessions"))["sessions"] if x["session_id"] == sid)["raw_bytes"] < total:
            assert time.monotonic() < deadline
            await anyio.sleep(0.05)
        got: list[str] = []
        cursor = 0
        pages = 0
        while True:
            page = await call(c, "emu_read", session_id=sid, max_chars=256)
            pages += 1
            assert page["cursor_start"] == cursor and len(page["text"]) <= 256, page
            new = page["text"].splitlines()
            assert page["lines"] == len(new) and page["cursor_end"] == cursor + sum(len(x) + 2 for x in new)
            got += new
            cursor = page["cursor_end"]
            if not page["more"]:
                break
            assert page["pending_line"] is None
        assert got == lines and pages >= 4 and cursor == total
        await call(c, "emu_stop", session_id=sid)


async def test_meta_written_as_starting_before_spawn(emu, monkeypatch):
    """띄우기 전에 meta.json 을 state starting·owner·argv·child null 로 쓴다 (서버가 그 사이 죽어도 시작 정리가 찾을 수 있게)."""
    from emu_mcp import session as sess_mod

    seen: dict = {}
    real_start = sess_mod.EmuSession.start

    def spy(self):
        seen.update(json.loads((Path(self.dir) / "meta.json").read_text(encoding="utf-8")))
        seen["_events"] = read_jsonl(Path(self.dir) / "events.jsonl")
        seen["_fake_started"] = bool(fake_starts(Path(self.dir)))
        return real_start(self)

    monkeypatch.setattr(sess_mod.EmuSession, "start", spy)
    s = seed_esp()
    async with Client(emu.srv.server) as c:
        r = await start(c, s)
        fake = wait_fake_start(sess_dir(s, r["session_id"]))
        await call(c, "emu_stop", session_id=r["session_id"])
    assert seen["state"] == "starting" and seen["child"] is None and seen["_fake_started"] is False, seen
    assert seen["owner"]["pid"] == os.getpid() and seen["owner"]["server"] == "emu-mcp" and seen["owner"]["start_ticks"]
    assert seen["argv"] == fake["argv"] and seen["session_id"] == r["session_id"]
    assert [e["type"] for e in seen["_events"]] == ["start"]


async def test_emu_start_sweeps_stale_sessions_of_that_case_only(emu):
    """emu_start 는 그 케이스만 시작 정리한다 (주인이 죽은 세션 → reaped). 다른 케이스는 서버 시작 때(모든 케이스) 정리된다."""
    s = seed_esp()
    other = make_case("other")
    stale_here = _seed_session(s.cid, "emu-040", _owner(), None)
    stale_there = _seed_session(other, "emu-041", _owner(), None, state="starting")
    async with Client(emu.srv.server) as c:
        r = await start(c, s)
        await call(c, "emu_stop", session_id=r["session_id"])
    assert meta(stale_here)["state"] == "reaped" and meta(stale_here)["stopped_by"] == "server-gone"
    assert meta(stale_there)["state"] == "starting"
    emu.srv._startup_sweep()
    assert meta(stale_there)["state"] == "reaped"


async def test_firmware_strings_in_response_are_escaped_and_masked(emu):
    """펌웨어에서 온 글(파티션 레이블·앱 설명)은 응답에 싣기 전에 제어·서식 문자를 이스케이프하고 자격증명을 가린다."""
    from fwtriage.esp_builders import build_app_desc, build_partition_table, s3_app_image

    flash = bytearray(esp_flash("esp32s3", nvs=False))
    table = build_partition_table([("nvs", 0x01, 0x02, 0x9000, 0x6000), ("ph\x1by‮", 0x01, 0x01, 0xF000, 0x1000),
                                   ("factory", 0x00, 0x00, 0x10000, 0x30000)])
    flash[0x8000:0x8000 + len(table)] = table
    app = s3_app_image(app_desc=build_app_desc(project_name="password=hunter2-app", version="1.0\x1b[31mred"))
    flash[0x10000:0x10000 + len(app)] = app
    s = seed_esp(data=bytes(flash))
    async with Client(emu.srv.server) as c:
        r = await start(c, s)
        await call(c, "emu_stop", session_id=r["session_id"])
    labels = [e["label"] for e in r["partition_table"]["entries"]]
    assert labels[0] == "nvs" and labels[2] == "factory", labels
    assert "\x1b" not in labels[1] and "‮" not in labels[1] and labels[1].startswith("ph"), labels
    blob = json.dumps(r["app"], ensure_ascii=False)
    assert "hunter2-app" not in blob and "\x1b" not in r["app"]["version"] and r["app"]["project_name"].startswith("password="), r["app"]


async def test_piped_core_pattern_is_a_warning_only(emu, monkeypatch):
    """결정 D18: core_pattern 이 파이프면 RLIMIT_CORE=0 이 지켜지지 않는다 — emu_status 가 알리고 emu_start 는 경고만 한다."""
    monkeypatch.setattr(emu.B, "core_pattern_piped", lambda: True)
    s = seed_esp()
    async with Client(emu.srv.server) as c:
        st = await call(c, "emu_status")
        assert st["isolation"]["core_pattern_piped"] is True and any("core_pattern" in h for h in st["hints"])
        r = await start(c, s)
        assert any(w.startswith("core_pattern_piped") for w in r["warnings"]), r["warnings"]
        await call(c, "emu_stop", session_id=r["session_id"])


async def test_padding_and_partial_dump_warning(emu):
    """덤프(1.5 MiB)가 헤더 선언(2 MiB)보다 작으면 0xFF 로 2 MiB 까지 채우고 partial_dump 경고. 원본·작업 이미지 sha256 을 둘 다."""
    import mkimg_esp

    data = mkimg_esp.build_flash("esp32s3", "hello", size=2 * MiB)[: 3 * MiB // 2]
    s = seed_esp(data=data, rel="dumps/short.bin")
    padded = data + b"\xff" * (2 * MiB - len(data))
    async with Client(emu.srv.server) as c:
        r = await start(c, s)
        fake = wait_fake_start(sess_dir(s, r["session_id"]))
        await call(c, "emu_stop", session_id=r["session_id"])
    assert r["firmware"]["sha256"] == s.sha and r["firmware"]["size"] == len(data)
    assert r["working_copy"] == {"sha256": _sha(padded), "size": 2 * MiB, "padded_from": len(data), "handoff": "memfd"}
    assert handoff(fake, "flash")["sha256"] == _sha(padded) and handoff(fake, "flash")["size"] == 2 * MiB
    assert any(w.startswith("partial_dump") for w in r["warnings"]), r["warnings"]


async def test_chip_evidence_and_image_refusals(emu):
    """칩은 증거로 정한다: 원장 칩과 헤더가 다르면 emu_machine_mismatch, chip 인자가 다르면 emu_machine_mismatch, 지원 밖 칩은
    emu_unsupported_chip, 부트로더 헤더 없음·오프셋 ≠ 0 은 emu_not_full_image, 16 MiB 초과는 emu_flash_too_large, ESP 경로의 HEX 는
    validation_failed. 어느 경우에도 에뮬레이터를 띄우지 않는다."""
    s3 = esp_flash("esp32s3", nvs=False)
    cases = [
        (dict(data=s3, ledger_chip="ESP32-C3"), {}, "emu_machine_mismatch"),
        (dict(data=s3), {"chip": "esp32"}, "emu_machine_mismatch"),
        (dict(data=s3, ledger_chip="ESP32-C6"), {}, "emu_unsupported_chip"),
        (dict(data=s3), {"chip": "ESP32-S2"}, "emu_unsupported_chip"),
        (dict(data=b"\xff" * (4 * MiB)), {}, "emu_not_full_image"),
        (dict(data=s3, offset=0x10000), {}, "emu_not_full_image"),
        (dict(data=s3, offset="0x1000"), {}, "emu_not_full_image"),
        (dict(data=s3 + s3 + s3 + s3 + b"\xff"), {}, "emu_flash_too_large"),
        (dict(data=ECHO_HEX.read_bytes()), {}, "validation_failed"),
    ]
    async with Client(emu.srv.server) as c:
        for i, (seed_kw, args, code) in enumerate(cases):
            s = seed_esp(rel=f"dumps/case{i}.bin", **seed_kw)
            r = await call(c, "emu_start", case_id=s.cid, firmware=s.rel, **args)
            assert err_code(r) == code, (i, code, r)
        # 원장 칩 'ESP32-S3R8' 같은 이름은 접두로 정규화(esp32s3), 'auto'·없음 → 헤더만
        for i, lc in enumerate(("ESP32-S3R8", "auto", None)):
            s = seed_esp(rel=f"dumps/norm{i}.bin", data=s3, ledger_chip=lc)
            r = await call(c, "emu_start", case_id=s.cid, firmware=s.rel)
            assert r.get("ok") and r["target"]["chip"] == "esp32s3", (lc, r)
            await call(c, "emu_stop", session_id=r["session_id"])
    assert len(fake_logs_under(emu.ws["cases_dir"])) == 3


async def test_provenance_refusals_never_start(emu):
    """출처 불신(not-recorded·sha256-mismatch·device-read-mismatch·ledger-chain-broken) → emu_provenance (reason 은 오류 글에).
    세션 디렉터리도 에뮬레이터도 만들지 않는다."""
    flash = esp_flash("esp32s3", nvs=False)
    async with Client(emu.srv.server) as c:
        cid = make_case("prov")
        put_file(cid, "dumps/norec.bin", flash)
        r = await call(c, "emu_start", case_id=cid, firmware="dumps/norec.bin")
        assert err_code(r) == "emu_provenance" and "reason=not-recorded" in r["_error"] and "우회" in r["_error"], r

        s = seed_esp(rel="dumps/changed.bin", data=flash, case_id=cid)
        put_file(cid, s.rel, flash[:-1] + b"\x00")
        r = await call(c, "emu_start", case_id=cid, firmware=s.rel)
        assert err_code(r) == "emu_provenance" and "reason=sha256-mismatch" in r["_error"], r

        s = seed_esp(rel="dumps/mismatch.bin", data=flash, match=False, case_id=cid)
        r = await call(c, "emu_start", case_id=cid, firmware=s.rel)
        assert err_code(r) == "emu_provenance" and "reason=device-read-mismatch" in r["_error"], r

        cid2 = make_case("broken ledger")
        s = seed_esp(rel="dumps/ok.bin", data=flash, case_id=cid2)
        ledger = rt().provenance.ledger_path(cid2)
        lines = ledger.read_text(encoding="utf-8").splitlines()
        rec = json.loads(lines[0])
        rec["size"] = rec["size"] + 1  # 기록을 바꾸면 해시 체인이 깨진다
        ledger.write_text("\n".join([json.dumps(rec)] + lines[1:]) + "\n", encoding="utf-8")
        r = await call(c, "emu_start", case_id=cid2, firmware=s.rel)
        assert err_code(r) == "emu_provenance" and "reason=ledger-chain-broken" in r["_error"], r
    for cdir in (case_dir(cid), case_dir(cid2)):
        assert not (cdir / "emu").exists() or not [p for p in (cdir / "emu").iterdir() if p.name != ".lock"]
    assert fake_logs_under(emu.ws["cases_dir"]) == []


async def test_single_read_and_security_state_warnings(emu):
    """단일 읽기 덤프는 허용 + 경고 single_read(D3). 같은 MAC 의 보안 사실이 없으면 security_state_unknown."""
    s = seed_esp(verify="none", match=None, security=None)
    other = seed_esp(rel="dumps/b.bin", case_id=s.cid, security=None, mac=SYNTH_MAC)
    seed_fact(s.cid, "esp-security-info", {"flash_encryption": True}, mac="aa:bb:cc:dd:ee:ff")  # 다른 기기 — 이 덤프와 무관
    async with Client(emu.srv.server) as c:
        r = await start(c, s)
        codes = [w.split(":", 1)[0] for w in r["warnings"]]
        assert "single_read" in codes and "security_state_unknown" in codes, codes
        assert r["firmware"]["verify"] == "none"
        await call(c, "emu_stop", session_id=r["session_id"])
        r = await start(c, other)
        assert "single_read" not in [w.split(":", 1)[0] for w in r["warnings"]]
        await call(c, "emu_stop", session_id=r["session_id"])


async def test_flash_encryption_fact_refuses(emu):
    """같은 MAC 의 esp-security-info 가 flash_encryption=true → emu_flash_encrypted (우회하지 않는다)."""
    s = seed_esp(security=None, mac="F4:12:FA:12:34:56")  # 원장의 MAC 은 대문자, 사실은 소문자 — 같은 기기로 본다
    seed_fact(s.cid, "esp-security-info", {"flash_encryption": True, "secure_download_mode": False}, mac=SYNTH_MAC)
    async with Client(emu.srv.server) as c:
        r = await call(c, "emu_start", case_id=s.cid, firmware=s.rel)
        assert err_code(r) == "emu_flash_encrypted" and "우회" in r["_error"], r
    assert fake_logs_under(emu.ws["cases_dir"]) == []


async def test_protected_and_outside_inputs_refused(emu):
    """forensics/·emu/(링크 포함)·디렉터리 → emu_input_rejected, 케이스 밖(.. ·절대 경로·다른 케이스로 가는 링크) → validation_failed,
    없는 파일 → not_found. 출처 기록이 있어도 경로 가드가 먼저다."""
    s = seed_esp()
    flash = s.data
    put_file(s.cid, "forensics/card.img", flash)
    seed_device_read(s.cid, "forensics/card.img")
    put_file(s.cid, "emu/emu-050/console.bin", flash)
    os.symlink("../emu/emu-050/console.bin", s.dir / "dumps" / "link-emu.bin")
    os.symlink("../forensics/card.img", s.dir / "dumps" / "link-forensics.bin")
    other = make_case("other")
    put_file(other, "emu/emu-001/console.bin", flash)
    os.symlink(case_dir(other) / "emu" / "emu-001" / "console.bin", s.dir / "dumps" / "link-other.bin")
    state_file = emu.ws["state_dir"] / "probe.bin"
    state_file.parent.mkdir(parents=True, exist_ok=True)
    state_file.write_bytes(flash)
    os.symlink(state_file, s.dir / "dumps" / "link-state.bin")
    want = {
        "forensics/card.img": "emu_input_rejected",
        "emu/emu-050/console.bin": "emu_input_rejected",
        "dumps/link-emu.bin": "emu_input_rejected",
        "dumps/link-forensics.bin": "emu_input_rejected",
        "dumps": "emu_input_rejected",
        "dumps/link-other.bin": "validation_failed",
        "dumps/link-state.bin": "validation_failed",
        "../other/x.bin": "validation_failed",
        "/etc/hostname": "validation_failed",
        "dumps/missing.bin": "not_found",
    }
    async with Client(emu.srv.server) as c:
        for fw, code in want.items():
            r = await call(c, "emu_start", case_id=s.cid, firmware=fw)
            assert err_code(r) == code, (fw, r)
            if fw.startswith(("emu/", "dumps/link-emu")):
                assert "emu/" in r["_error"]
    assert fake_logs_under(emu.ws["cases_dir"]) == []


async def test_toctou_changed_and_swapped_inputs(emu, monkeypatch):
    """바이트는 한 번 읽어 verify(data=…) 로 확인하고 그 바이트만 넘긴다:
    - 확인 결과의 sha256 이 읽은 바이트와 다르면 emu_changed,
    - 읽는 동안 파일이 자라면 emu_changed,
    - 확인 뒤 디스크의 파일을 바꿔도 에뮬레이터는 확인한 바이트를 받는다(가짜가 memfd 에서 잰 sha256)."""
    import pweh.safeio as safeio
    from pweh.provenance import ProvenanceLedger

    s = seed_esp()
    real_verify = ProvenanceLedger.verify
    real_read = safeio.read_fd

    def lying(self, case, path, *, data=None):
        v = real_verify(self, case, path, data=data)
        v["sha256"] = "0" * 64
        return v

    async with Client(emu.srv.server) as c:
        monkeypatch.setattr(ProvenanceLedger, "verify", lying)
        r = await call(c, "emu_start", case_id=s.cid, firmware=s.rel)
        assert err_code(r) == "emu_changed", r
        monkeypatch.setattr(ProvenanceLedger, "verify", real_verify)

        target = s.dir / s.rel

        def growing(fd, size, *a, **k):
            with open(target, "ab") as f:
                f.write(b"\xff" * 16)
            return real_read(fd, size, *a, **k)

        monkeypatch.setattr(safeio, "read_fd", growing)
        r = await call(c, "emu_start", case_id=s.cid, firmware=s.rel)
        assert err_code(r) == "emu_changed", r
        monkeypatch.setattr(safeio, "read_fd", real_read)

        s2 = seed_esp(rel="dumps/swap.bin", case_id=s.cid)
        other = esp_flash("esp32s3", "echo")
        assert _sha(other) != s2.sha

        def swapping(self, case, path, *, data=None):
            v = real_verify(self, case, path, data=data)
            if str(path).endswith("swap.bin"):
                (case.dir / "dumps" / "swap.bin").write_bytes(other)  # 확인 직후 같은 계정의 프로세스가 바꿔치기
            return v

        monkeypatch.setattr(ProvenanceLedger, "verify", swapping)
        r = await start(c, s2)
        fake = wait_fake_start(sess_dir(s2, r["session_id"]))
        await call(c, "emu_stop", session_id=r["session_id"])
    assert (s.dir / "dumps" / "swap.bin").read_bytes() == other
    assert r["firmware"]["sha256"] == s2.sha and handoff(fake, "flash")["sha256"] == s2.sha != _sha(other)


# ---------------------------------------------------------------------------
# 게이트·분류기
# ---------------------------------------------------------------------------


async def test_approval_fingerprint_binds_sha_and_ledger_seq(emu):
    """modify_policy=approve: approval_required → 승인 레코드의 지문(action)에 firmware_sha256·ledger_seq → 승인 뒤 같은 인자 + approval_id
    로 1회 실행. 승인 전에는 세션 디렉터리·에뮬레이터가 없다. 내용(sha256)이 바뀌면 같은 승인으로 실행되지 않는다."""
    emu.ws["set_safety"](modify_policy="approve", approval_methods=["cli"])
    s = seed_esp()
    async with Client(emu.srv.server) as c:
        r = await call(c, "emu_start", case_id=s.cid, firmware=s.rel, label="appr")
        assert r["ok"] is False and r["status"] == "approval_required" and r["approval_id"], r
        assert r["gate"]["classification"]["rule_id"] == "emu.start" and r["gate"]["classification"]["risk"] == "modify"
        assert "pweh approve" in r["message"]
        rec = rt().approvals.get(r["approval_id"])
        act = rec["action"]
        assert act["firmware"] == s.rel and act["firmware_sha256"] == s.sha and act["ledger_seq"] == s.seq, act
        assert act["provenance_reason"] == "device-read" and act["backend"] == "esp-qemu" and act["chip"] == "esp32s3"
        assert act["timeout_s"] == 600 and act["idle_timeout_s"] == 300 and act["flash_size"] == 4 * MiB
        assert act["psram"] == {"mode": "quad", "mb": 32} and act["watchdog"] == "disabled" and act["on_reset"] == "exit"
        assert "label" not in act and "approval_id" not in act
        assert not (s.dir / "emu").exists() or not [p for p in (s.dir / "emu").iterdir() if p.name != ".lock"]
        rt().approvals.decide(r["approval_id"], approve=True, code=rec["code"], via="test")
        r2 = await call(c, "emu_start", case_id=s.cid, firmware=s.rel, label="other-label", approval_id=r["approval_id"])
        assert r2.get("ok") is True and r2["state"] == "running", r2  # label 은 지문에 없다
        # MODIFY 를 막아도 emu_write(INTERACT, 늘 허용)와 emu_stop(정리, 게이트 없음)은 동작한다
        emu.ws["set_safety"](modify_policy="deny", approval_methods=["cli"])
        w = await call(c, "emu_write", session_id=r2["session_id"], data="x")
        assert w.get("ok") is True and w["bytes_written"] == 1, w
        sp = await call(c, "emu_stop", session_id=r2["session_id"])
        assert sp.get("ok") is True and sp["stopped_by"] == "agent-stop", sp
        d = await call(c, "emu_start", case_id=s.cid, firmware=s.rel)
        assert d["ok"] is False and d["status"] == "denied" and "modify_policy" in d["message"], d
        emu.ws["set_safety"](modify_policy="approve", approval_methods=["cli"])
        r3 = await call(c, "emu_start", case_id=s.cid, firmware=s.rel, approval_id=r["approval_id"])
        assert r3["ok"] is False and r3["status"] in ("denied", "approval_required"), r3  # 1회용
        # 새 덤프(내용·seq 가 다름)에 옛 승인을 쓰지 못한다
        r4 = await call(c, "emu_start", case_id=s.cid, firmware=s.rel)
        ap = r4["approval_id"]
        rt().approvals.decide(ap, approve=True, code=rt().approvals.get(ap)["code"], via="test")
        s2 = seed_esp(rel=s.rel, data=esp_flash("esp32s3", "echo"), case_id=s.cid)
        r5 = await call(c, "emu_start", case_id=s.cid, firmware=s.rel, approval_id=ap)
        assert r5["ok"] is False and r5["status"] == "denied" and s2.sha != s.sha, r5
    assert len(fake_logs_under(emu.ws["cases_dir"])) == 1


@pytest.mark.parametrize("inject,rule", [
    (["-monitor", "stdio"], "emu.argv.monitor"),
    (["-serial", "mon:stdio"], "emu.argv.monitor"),
    (["-gdb", "tcp::1234"], "emu.argv.gdb"),
    (["-s"], "emu.argv.gdb"),
    (["-netdev", "user,id=n0"], "emu.argv.network"),
    (["-nic", "user"], "emu.argv.network"),
    (["-semihosting"], "emu.argv.semihosting"),
    (["-chardev", "file,id=c0,path=/tmp/x"], "emu.argv.host-file"),
    (["-drive", "file=/etc/passwd,if=mtd,format=raw"], "emu.argv.host-file"),
    (["-device", "virtio-net"], "emu.argv.device"),
    (["-readconfig", "/tmp/q.conf"], "emu.argv.config"),
    (["-daemonize"], "emu.argv.detach"),
    (["-icount", "shift=1"], "emu.argv.unexpected"),
])
async def test_argv_outside_template_is_denied_without_approval_path(emu, monkeypatch, inject, rule):
    """서버가 (버그로) 템플릿 밖 argv 를 만들면 분류기가 DESTRUCTIVE emu.argv.* 로 막는다 — 승인 정책이 approve 여도 승인 경로 없이
    denied(gate.via emu-policy), 에뮬레이터를 띄우지 않고 감사에 남긴다."""
    emu.ws["set_safety"](modify_policy="approve", destructive_policy="approve", approval_methods=["cli"])
    real_build = emu.B.build_argv
    monkeypatch.setattr(emu.B, "build_argv", lambda exe, target, fds: real_build(exe, target, fds) + list(inject))
    s = seed_esp()
    async with Client(emu.srv.server) as c:
        r = await call(c, "emu_start", case_id=s.cid, firmware=s.rel)
    assert r["ok"] is False and r["status"] == "denied" and "approval_id" not in r, r
    assert r["gate"]["via"] == "emu-policy" and r["gate"]["rule_id"] == rule and r["gate"]["reason"], r["gate"]
    assert r["gate"]["classification"]["risk"] == "destructive" and "우회" in r["message"]
    assert rt().approvals.list() == []
    assert fake_logs_under(emu.ws["cases_dir"]) == []
    audit = read_jsonl(s.dir / "audit.jsonl")
    assert any(e.get("event") == "safety_decision" and e.get("via") == "emu-policy" for e in audit)


async def test_wrong_executable_basename_is_denied(emu, monkeypatch):
    real_build = emu.B.build_argv
    monkeypatch.setattr(emu.B, "build_argv", lambda exe, target, fds: ["/usr/bin/qemu-system-x86_64"] + real_build(exe, target, fds)[1:])
    s = seed_esp()
    async with Client(emu.srv.server) as c:
        r = await call(c, "emu_start", case_id=s.cid, firmware=s.rel)
    assert r["status"] == "denied" and r["gate"]["via"] == "emu-policy" and r["gate"]["rule_id"] == "emu.argv.exe", r
    assert fake_logs_under(emu.ws["cases_dir"]) == []


async def test_write_records_byte_counts_only(emu):
    """emu_write: 게이트 action·감사·events.jsonl 에는 {session_id, bytes, printable, data:'<given>'} 만 — 원문도 다이제스트도 없다."""
    s = seed_esp()
    emu.mode("echo")
    secret = "typed-s3cr3t-pass"
    async with Client(emu.srv.server) as c:
        r = await start(c, s)
        sid = r["session_id"]
        w = await call(c, "emu_write", session_id=sid, data=secret + "\r")
        assert w["bytes_written"] == len(secret) + 1 and w["partial"] is False
        w2 = await call(c, "emu_write", session_id=sid, data="01 02 1b 41", encoding="hex")
        assert w2["bytes_written"] == 4
        rd = await call(c, "emu_read", session_id=sid, wait_seconds=5, until=secret)
        assert rd["matched"] is True  # 게스트의 에코는 콘솔에 보인다 (설계상 — 원시 기록에도 남는다)
        await call(c, "emu_stop", session_id=sid)
    sdir = sess_dir(s, sid)
    digests = {rt().secret_digest(s.cid, secret + "\r"), rt().secret_digest(s.cid, (secret + "\r").encode())}
    files = [s.dir / "audit.jsonl", emu.ws["state_dir"] / "audit.jsonl", sdir / "events.jsonl", sdir / "meta.json",
             sdir / "transcript.masked.txt"]
    files += sorted((emu.ws["state_dir"] / "approvals").glob("*")) if (emu.ws["state_dir"] / "approvals").exists() else []
    for f in files:
        text = f.read_text(encoding="utf-8")
        if f.name != "transcript.masked.txt":
            assert secret not in text, f
        assert not any(d in text for d in digests) and "data_digest" not in text, f
    acts = [e["action"] for e in read_jsonl(s.dir / "audit.jsonl") if e.get("event") == "safety_decision" and e.get("tool") == "emu_write"]
    assert acts == [{"session_id": sid, "bytes": len(secret) + 1, "printable": True, "data": "<given>"},
                    {"session_id": sid, "bytes": 4, "printable": False, "data": "<given>"}], acts
    gates = [e for e in read_jsonl(s.dir / "audit.jsonl") if e.get("tool") == "emu_write"]
    assert all(e["classification"]["rule_id"] == "emu.write" and e["classification"]["risk"] == "interact" for e in gates)
    tx = [e for e in events(sdir) if e["type"] == "tx"]
    assert [{k: v for k, v in e.items() if k != "ts"} for e in tx] == [
        {"type": "tx", "session_id": sid, "bytes": len(secret) + 1, "requested": len(secret) + 1, "printable": True, "data": "<given>"},
        {"type": "tx", "session_id": sid, "bytes": 4, "requested": 4, "printable": False, "data": "<given>"}]
    assert secret.encode() in (sdir / "console.bin").read_bytes()


# ---------------------------------------------------------------------------
# 마스킹·커서·기다림
# ---------------------------------------------------------------------------

HEX_SECRET = " ".join(f"{b:02x}" for b in NVS_SECRET.encode())
BOOT_LINES = [
    "ESP-ROM:esp32s3-20210327",
    "I (31) boot: ESP-IDF v5.3.1 2nd stage bootloader",
    f"I (88) wifi: connecting with {NVS_SECRET}",
    f"I (90) cloud: token={NVS_TOKEN}",
    "I (95) app: password=hunter2pass-LONG-VALUE-1234567890",
    f"I (96) app: hexdump {HEX_SECRET} end",
    "\x1b[0;32mI (97) app: pass\x1b[0mword=ansi-split-secret-77\x1b[0m",
]
RAW_SECRETS = [NVS_SECRET, NVS_TOKEN, "hunter2pass-LONG-VALUE-1234567890", HEX_SECRET, "ansi-split-secret-77"]


async def test_masking_known_secrets_patterns_and_prompt(emu, caplog):
    """NVS 에서 거둔 비밀(원문·공백 hex)과 자격증명 패턴(password=·token=·ANSI 로 갈린 키)은 emu_read·transcript.masked.txt 에 없고
    console.bin 에는 있다. 줄 끝 없는 'login: ' 은 조용해지면 pending_line 으로 보이고 until 리터럴이 그것에 맞는다.
    서버 로그에도 콘솔 글·비밀이 없다."""
    import logging

    caplog.set_level(logging.DEBUG)
    s = seed_esp()
    emu.mode("boot", lines=BOOT_LINES, prompt="login: ")
    async with Client(emu.srv.server) as c:
        r = await start(c, s)
        sid = r["session_id"]
        assert r["masking"]["known_secrets"] >= 2
        rd = await call(c, "emu_read", session_id=sid, wait_seconds=5, until="login:")
        assert rd["matched"] is True and rd["match"] == "login:" and rd["pending_line"] == "login: ", rd
        text = rd["text"]
        for secret in RAW_SECRETS:
            assert secret not in text and secret not in rd["pending_line"], secret
        assert "hunter2pass" not in text and "\x1b" not in text
        assert f"⟪비밀 {len(NVS_SECRET)}바이트⟫" in text and "token=" in text and "password=" in text, text
        assert text.splitlines()[0] == "ESP-ROM:esp32s3-20210327" and rd["lines"] == len(BOOT_LINES)
        assert rd["cursor_end"] == sum(len(line.encode()) + 2 for line in BOOT_LINES)  # 커서는 열린 줄의 시작에 머문다
        await call(c, "emu_stop", session_id=sid)
    sdir = sess_dir(s, sid)
    raw = (sdir / "console.bin").read_bytes()
    transcript = (sdir / "transcript.masked.txt").read_text(encoding="utf-8")
    for secret in RAW_SECRETS:
        assert secret.encode() in raw, secret
        assert secret not in transcript, secret
    assert "⟪비밀" in transcript and "ESP-ROM:esp32s3-20210327" in transcript
    logged = caplog.text
    for secret in RAW_SECRETS + ["ESP-ROM:esp32s3-20210327", "2nd stage bootloader"]:
        assert secret not in logged, secret
    meta_text = (sdir / "meta.json").read_text(encoding="utf-8") + (sdir / "events.jsonl").read_text(encoding="utf-8")
    assert not any(secret in meta_text for secret in RAW_SECRETS)


async def test_split_secret_pending_line_and_prompt_wait(emu):
    """두 번에 나뉘어 오는 비밀: 틈 동안의 열린 줄은 비밀의 앞부분을 '⟪보류 N자⟫' 로 가리고, 완성되면 줄 전체를 마스킹한다.
    프롬프트에서 기다리면 새 바이트 없이 바로 돌아오지 않는다. 끝에 닿은 자격증명 값은 길이만('<가림 N자>').

    가짜의 split 모드: 'I (7) app: joining with not-a-r' → 1.2 s → 'eal-pass\\r\\n' + 'login: ' → 3 s → '\\r\\n' +
    'I (9) app: psk=hunter2-open-val' (줄 끝 없음)."""
    s = seed_esp()
    emu.mode("split")
    async with Client(emu.srv.server) as c:
        r = await start(c, s)
        sid = r["session_id"]
        rd = await call(c, "emu_read", session_id=sid, wait_seconds=0.6)
        assert rd["lines"] == 0 and rd["text"] == "" and rd["cursor_end"] == 0, rd
        assert rd["pending_line"] is not None and "⟪보류 7자⟫" in rd["pending_line"] and "not-a-r" not in rd["pending_line"], rd
        rd2 = await call(c, "emu_read", session_id=sid, wait_seconds=5, until="login:")
        assert rd2["matched"] is True and rd2["pending_line"] == "login: ", rd2
        assert rd2["text"] == f"I (7) app: joining with ⟪비밀 {len(NVS_SECRET)}바이트⟫" and rd2["cursor_start"] == 0, rd2
        t0 = time.monotonic()
        rd3 = await call(c, "emu_read", session_id=sid, wait_seconds=1.0)
        elapsed = time.monotonic() - t0
        assert elapsed >= 0.9, elapsed  # 이미 보인 프롬프트 — 새 바이트가 없으면 끝까지 기다린다
        assert rd3["lines"] == 0 and rd3["pending_line"] == "login: " and rd3["matched"] is False
        rd4 = await call(c, "emu_read", session_id=sid, wait_seconds=6, until="psk=")
        assert rd4["matched"] is True and rd4["text"] == "login: ", rd4
        pend = rd4["pending_line"] or ""
        assert pend.startswith("I (9) app: psk=") and "<가림" in pend and "hunter2" not in pend and "open-val" not in pend, rd4
        await call(c, "emu_stop", session_id=sid)
    transcript = (sess_dir(s, sid) / "transcript.masked.txt").read_text(encoding="utf-8")
    assert NVS_SECRET not in transcript and "not-a-r" not in transcript and "hunter2-open-val" not in transcript


async def test_mid_cursor_snaps_down_and_records_freeze(emu):
    """줄 중간 커서는 그 레코드의 시작으로 내린다(키 없이 값만 보이지 않게). 넘긴 레코드는 동결되어 뒤의 같은 줄은 '이어짐' 레코드가 된다."""
    s = seed_esp()
    first = "BOOT-LINE-ONE"
    emu.mode("boot", script=[{"out": first + "\r\n"}, {"out": "I (5) app: password=abcdefgh-12345-zz\r\n"},
                             {"out": "tick\r\ntick\r\ntick\r\n"}, {"sleep": 1.5}, {"out": "tick\r\ntick\r\n"}, {"out": "end\r\n"}])
    async with Client(emu.srv.server) as c:
        r = await start(c, s)
        sid = r["session_id"]
        rd = await call(c, "emu_read", session_id=sid, wait_seconds=3, until="tick")
        assert rd["text"].splitlines()[-1] == "tick  ⟪위 줄 ×3⟫" and rd["collapsed"] == 2, rd
        mid = len(first) + 2 + 5
        rd2 = await call(c, "emu_read", session_id=sid, since_cursor=mid)
        assert rd2["cursor_start"] == len(first) + 2 and rd2["text"].startswith("I (5) app: password="), rd2
        assert "abcdefgh-12345" not in rd2["text"]
        rd3 = await call(c, "emu_read", session_id=sid, wait_seconds=5, until="end")
        assert rd3["matched"] is True and rd3["text"].splitlines() == ["tick  ⟪위 줄 ×2 더⟫", "end"], rd3
        tail = await call(c, "emu_read", session_id=sid, tail=True, max_chars=256)
        assert tail["text"].endswith("end") and tail["source"] == "live"
        await call(c, "emu_stop", session_id=sid)


async def test_diagnostic_hints_from_masked_text(emu):
    s = seed_esp()
    emu.mode("boot", lines=["invalid header: 0xffffffff"] * 3 + [
        "E (210) psram: PSRAM ID read error: 0xffffffff, PSRAM chip not found or not supported",
        "Guru Meditation Error: Core  0 panic'ed (LoadProhibited). Exception was unhandled.",
        "I (305) wifi:wifi driver task: 3fca1234, prio:23, stack:6656, core=0"])
    async with Client(emu.srv.server) as c:
        r = await start(c, s)
        rd = await call(c, "emu_read", session_id=r["session_id"], wait_seconds=3, until="wifi driver")
        await call(c, "emu_stop", session_id=r["session_id"])
    hints = "\n".join(rd["hints"])
    assert "invalid header" in hints and "Guru Meditation" in hints and "PSRAM" in hints and "Wi-Fi" in hints, rd["hints"]
    psram_hints = [h for h in rd["hints"] if "PSRAM" in h and "Guru" not in h]
    assert len(psram_hints) == 1 and "2" in psram_hints[0], rd["hints"]  # 다른 psram 으로 다시 — PSRAM 재시작은 최대 2번
    assert "3fca1234" not in hints and "LoadProhibited" not in hints  # 힌트는 고정 문구 — 콘솔 글을 옮기지 않는다
    assert not any("USB" in h for h in rd["hints"])


async def test_usb_console_hint_after_silence_following_app_entry(emu, monkeypatch):
    """부트로더가 앱으로 넘어간 뒤('Loaded app'/'entry 0x') 조용하면: 앱 콘솔이 USB-Serial-JTAG·USB-CDC·UART1 일 수 있다는 힌트
    (PSRAM 문제가 아니다). 조용함 기준(10 s)은 시험에서 줄인다."""
    monkeypatch.setattr(emu.limits, "HINT_SILENCE_AFTER_BOOT_S", 0.5)
    s = seed_esp()
    emu.mode("boot", lines=["ESP-ROM:esp32s3-20210327", "I (60) esp_image: segment 0: paddr=00010020 vaddr=3c0a0020",
                            "I (73) boot: Loaded app from partition at offset 0x10000", "entry 0x40375a88"])
    async with Client(emu.srv.server) as c:
        r = await start(c, s)
        rd = await call(c, "emu_read", session_id=r["session_id"], wait_seconds=3, until="entry 0x")
        assert rd["matched"] and not any("USB" in h for h in rd["hints"]), rd["hints"]  # 아직 조용하지 않다
        await anyio.sleep(0.8)
        rd = await call(c, "emu_read", session_id=r["session_id"])
        usb = [h for h in rd["hints"] if "USB" in h]
        assert len(usb) == 1 and "USB-Serial-JTAG" in usb[0] and "PSRAM" in usb[0], rd["hints"]
        await call(c, "emu_stop", session_id=r["session_id"])


# ---------------------------------------------------------------------------
# 한도
# ---------------------------------------------------------------------------


async def test_session_caps_per_case_and_process(emu, monkeypatch):
    """케이스당 2 세션 — 다른 살아 있는 서버 프로세스(여기서는 sleep 이 주인인 meta.json)의 세션도 센다. 프로세스당 상한도."""
    from pweh import procutil

    s = seed_esp()
    sleeper = subprocess.Popen(["sleep", "120"])
    try:
        fdir = s.dir / "emu" / "emu-090"
        fdir.mkdir(parents=True)
        owner = procutil.owner_record("emu-mcp")
        owner.update(pid=sleeper.pid, start_ticks=procutil.proc_stat(sleeper.pid)[1])
        (fdir / "meta.json").write_text(json.dumps({"schema": "pweh.emu-session/v1", "session_id": "emu-090", "case_id": s.cid,
                                                    "state": "running", "owner": owner, "child": None}), encoding="utf-8")
        async with Client(emu.srv.server) as c:
            a = await start(c, s)
            b = await call(c, "emu_start", case_id=s.cid, firmware=s.rel)
            assert err_code(b) == "emu_session_limit" and "emu_stop" in b["_error"], b
            ss = await call(c, "emu_sessions", case_id=s.cid)
            assert ss["count"] == 1 and ss["other_process_live"] == {s.cid: 1}
            assert meta(fdir)["state"] == "running"  # 주인이 살아 있으면 정리하지 않는다
            await call(c, "emu_stop", session_id=a["session_id"])
            b = await start(c, s)  # 하나가 끝났으니 다시 된다
            await call(c, "emu_stop", session_id=b["session_id"])

            monkeypatch.setattr(emu.limits, "MAX_SESSIONS_PER_PROCESS", 1)
            s2 = seed_esp()
            a = await start(c, s2)
            x = await call(c, "emu_start", case_id=s.cid, firmware=s.rel)
            assert err_code(x) == "emu_session_limit", x
            await call(c, "emu_stop", session_id=a["session_id"])
    finally:
        sleeper.kill()
        sleeper.wait()
    # 다른 서버 프로세스의 세션으로 센 meta 는 그대로 (주인이 이제 죽었으니 다음 정리가 reaped 로 고친다)
    emu.srv._startup_sweep(s.cid)
    assert meta(fdir)["state"] == "reaped" and meta(fdir)["stopped_by"] == "server-gone"


async def test_concurrent_starts_respect_case_cap_under_lock(emu, monkeypatch):
    """동시에 두 emu_start: 사전 확인은 둘 다 통과해도 emu/.lock 안의 재확인이 케이스 상한을 지킨다."""
    import threading

    monkeypatch.setattr(emu.limits, "MAX_SESSIONS_PER_CASE", 1)
    real_create = emu.srv._create_session
    barrier = threading.Barrier(2, timeout=10)

    def gated(*a, **k):  # 두 호출이 모두 사전 확인을 지난 뒤에야 잠금으로 들어간다 (경쟁을 강제)
        barrier.wait()
        return real_create(*a, **k)

    monkeypatch.setattr(emu.srv, "_create_session", gated)
    s = seed_esp()
    results: list[dict] = []
    async with Client(emu.srv.server) as c:
        async def one(label: str) -> None:
            results.append(await call(c, "emu_start", case_id=s.cid, firmware=s.rel, label=label))

        async with anyio.create_task_group() as tg:
            tg.start_soon(one, "left")
            tg.start_soon(one, "right")
        ok = [r for r in results if r.get("ok")]
        busy = [r for r in results if err_code(r) == "emu_session_limit"]
        assert len(ok) == 1 and len(busy) == 1, results
        live = await call(c, "emu_read", session_id=ok[0]["session_id"], case_id=s.cid)
        assert live["source"] == "live"  # 이 프로세스의 세션은 case_id 를 줘도 메모리에서
        await call(c, "emu_stop", session_id=ok[0]["session_id"])
    dirs = [p.name for p in (s.dir / "emu").iterdir() if p.is_dir()]
    assert dirs == [ok[0]["session_id"]], dirs


async def test_wall_and_idle_timeouts(emu, monkeypatch):
    monkeypatch.setattr(emu.limits, "TIMEOUT_S_MIN", 1)
    monkeypatch.setattr(emu.limits, "IDLE_TIMEOUT_S_MIN", 1)
    s = seed_esp()
    async with Client(emu.srv.server) as c:
        # 벽시계 3 s, 무활동 1 s: 0.3 s 마다 emu_read 가 무활동 시계를 되돌리므로 벽시계 한도가 먼저 온다
        r = await start(c, s, timeout_s=3, idle_timeout_s=1, label="wall")
        sid = r["session_id"]
        sdir = sess_dir(s, sid)
        pid = wait_fake_start(sdir)["pid"]
        t0 = time.monotonic()
        while True:
            rd = await call(c, "emu_read", session_id=sid, wait_seconds=0.3)
            if rd["state"] not in ("running", "stopping") or time.monotonic() - t0 > 12:
                break
        assert rd["state"] == "ended" and rd["stopped_by"] == "wall-timeout", rd
        assert 2.5 <= time.monotonic() - t0 <= 7
        assert not pid_alive(pid) and not group_members(pid)
        ev = events(sdir)
        assert {"type": "timeout", "kind": "wall", "timeout_s": 3} in [{k: v for k, v in e.items() if k != "ts"} for e in ev]
        assert any(e["type"] == "stop_request" and e["reason"] == "wall-timeout" for e in ev)
        sp = await call(c, "emu_stop", session_id=sid)
        assert sp["already_stopped"] is True and sp["stopped_by"] == "wall-timeout"

        # 무활동 1 s: 1.5 s 동안 emu_write 로 무활동 시계를 되돌린 뒤 멈추면 그때부터 1 s 뒤에 끝난다
        r = await start(c, s, timeout_s=20, idle_timeout_s=1, label="idle")
        sid = r["session_id"]
        sdir = sess_dir(s, sid)
        pid = wait_fake_start(sdir)["pid"]
        t0 = time.monotonic()
        for _ in range(5):
            w = await call(c, "emu_write", session_id=sid, data="k")
            assert w["state"] == "running", w
            await anyio.sleep(0.3)
        row = await poll_state(c, sid, ("ended",), timeout=8)
        elapsed = time.monotonic() - t0
        assert row["stopped_by"] == "idle-timeout" and 2.0 <= elapsed <= 6, (row, elapsed)
        assert not pid_alive(pid)
        assert any(e["type"] == "timeout" and e["kind"] == "idle" and e["idle_timeout_s"] == 1 for e in events(sdir))
        await call(c, "emu_stop", session_id=sid)


async def test_flood_caps_raw_log_and_collapses_repeats(emu, monkeypatch):
    monkeypatch.setattr(emu.limits, "RAW_LOG_CAP", 16384)
    line = "I (1) flood: the same line again\r\n"
    total = 400_000
    emu.mode("flood", flood={"line": line, "bytes": total})
    s = seed_esp()
    async with Client(emu.srv.server) as c:
        r = await start(c, s)
        sid = r["session_id"]
        row = None
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            row = next(x for x in (await call(c, "emu_sessions"))["sessions"] if x["session_id"] == sid)
            if row["raw_bytes"] >= total:
                break
            await anyio.sleep(0.05)
        assert row["raw_bytes"] == total, row
        rd = await call(c, "emu_read", session_id=sid, max_chars=65536)
        assert rd["raw_total"] == total and rd["raw_dropped"] == total - 16384, rd
        n_lines = total // len(line)
        assert rd["lines"] <= 3 and rd["collapsed"] >= n_lines - 3 and "⟪위 줄 ×" in rd["text"], {k: rd[k] for k in ("lines", "collapsed")}
        sp = await call(c, "emu_stop", session_id=sid)
    sdir = sess_dir(s, sid)
    assert sp["raw_bytes"] == total and sp["raw_dropped_bytes"] == total - 16384
    raw = (sdir / "console.bin").read_bytes()
    assert len(raw) == 16384 and raw == (line.encode() * (16384 // len(line) + 1))[:16384]
    assert {"type": "cap", "what": "raw"} in [{k: v for k, v in e.items() if k != "ts"} for e in events(sdir)]
    assert meta(sdir)["counters"]["raw_dropped_bytes"] == total - 16384


async def test_noread_guest_gives_partial_write_without_blocking(emu, monkeypatch):
    monkeypatch.setattr(emu.limits, "WRITE_TIMEOUT_S", 0.3)
    emu.mode("noread")
    s = seed_esp()
    async with Client(emu.srv.server) as c:
        r = await start(c, s)
        sid = r["session_id"]
        results = []
        for _ in range(64):
            w = await call(c, "emu_write", session_id=sid, data="x" * 4096)
            results.append(w)
            if w["partial"]:
                break
        last = results[-1]
        assert last["partial"] is True and last["bytes_written"] < last["bytes_requested"] == 4096 and last["note"], last
        assert sum(w["bytes_written"] for w in results) >= 4096
        t0 = time.monotonic()
        rd = await call(c, "emu_read", session_id=sid)
        assert time.monotonic() - t0 < 1.0 and rd["state"] == "running"  # 감독 스레드는 막히지 않았다
        sp = await call(c, "emu_stop", session_id=sid)
        assert sp["stopped_by"] == "agent-stop"


# ---------------------------------------------------------------------------
# 종료 분류·띄우기 실패·정지
# ---------------------------------------------------------------------------


async def test_quick_exit1_is_spawn_failed_with_masked_allowlisted_stderr(emu):
    """emu_start 가 돌려주기 전에 rc 1 → emu_spawn_failed. stderr_tail 은 허용한 진단 줄만(마스킹·이스케이프), 나머지는 분류별 수."""
    s = seed_esp()
    emu.mode("exit1", stderr=["random noise line from the emulator",
                              "qemu-system-xtensa: warning: password=hunter2pass-LONG-VALUE \x1b[31mred\x1b[0m",
                              "another noise line"])
    async with Client(emu.srv.server) as c:
        r = await call(c, "emu_start", case_id=s.cid, firmware=s.rel)
        assert err_code(r) == "emu_spawn_failed" and "stderr_tail:" in r["_error"], r
        assert "qemu-system-xtensa: -drive file=/proc/self/fd/9,if=mtd,format=raw: fake configuration failure" in r["_error"]
        assert "qemu-system-xtensa: warning: password=" in r["_error"] and "\x1b" not in r["_error"]
        assert "noise" not in r["_error"] and "hunter2pass-LONG-VALUE" not in r["_error"]
        ss = (await call(c, "emu_sessions", case_id=s.cid))["sessions"]
        assert len(ss) == 1 and ss[0]["state"] == "failed" and ss[0]["stopped_by"] == "config-error", ss
        sid = ss[0]["session_id"]
        sp = await call(c, "emu_stop", session_id=sid)
        assert sp["already_stopped"] is True and sp["exit"] == {"code": 1, "signal": None}
        assert sp["stderr_suppressed"] == {"other": 2}, sp
    m = meta(sess_dir(s, sid))
    assert m["state"] == "failed" and "noise" not in json.dumps(m) and "hunter2pass" not in json.dumps(m)
    raw_err = (sess_dir(s, sid) / "emulator.stderr.log").read_bytes()
    assert b"random noise line" in raw_err and b"hunter2pass-LONG-VALUE" in raw_err  # 원시 stderr 는 케이스에만 (0600)


async def test_stderr_tail_is_bounded_and_cut_at_line_boundaries(emu):
    s = seed_esp()
    lines = [f"qemu-system-xtensa: diagnostic line {i:03d} " + "y" * 60 for i in range(80)]
    emu.mode("boot", script=[{"out": "PWEH-FAKE-BOOT\r\n"}] + [{"err": line} for line in lines])
    async with Client(emu.srv.server) as c:
        r = await start(c, s)
        await anyio.sleep(0.5)
        sp = await call(c, "emu_stop", session_id=r["session_id"])
    tail = sp["stderr_tail"]
    assert 0 < len(tail) <= 2000, len(tail)
    got = tail.splitlines()
    assert got[-1].startswith("qemu-system-xtensa: terminating on signal 15")
    assert all(line in lines for line in got[:-1]) and got[:-1] == lines[len(lines) - len(got) + 1:]  # 끝쪽 줄을 통째로


async def test_stderr_truncation_does_not_reveal_known_secret_prefix(emu):
    """진단 줄의 저장 상한이 NVS 비밀 중간에 걸려도 그 앞부분을 완결된 글로 내보내지 않는다."""
    s = seed_esp()
    prefix = "qemu-system-xtensa: "
    line = prefix + "z" * (500 - len(prefix)) + NVS_SECRET
    emu.mode("boot", script=[{"err": line + "\n"}])
    async with Client(emu.srv.server) as c:
        r = await start(c, s)
        await anyio.sleep(0.3)
        sp = await call(c, "emu_stop", session_id=r["session_id"])
    assert NVS_SECRET[:12] not in sp["stderr_tail"], sp["stderr_tail"]
    assert NVS_SECRET.encode() in (sess_dir(s, r["session_id"]) / "emulator.stderr.log").read_bytes()


async def test_long_open_stderr_keeps_credential_key_for_masking(emu):
    """긴 미완결 진단의 앞부분을 버리면 비밀번호 키가 사라진다. 다음 수신에도 처음 부분을 보존해 마스킹한다."""
    s = seed_esp()
    prefix = "qemu-system-xtensa: password="
    fragment = "invalid class name leaked-password-fragment "
    line = prefix + "a" * (1024 - len(prefix)) + fragment + "z" * (4096 - len(fragment))
    emu.mode("boot", script=[{"err": line}, {"sleep": 0.1}, {"err": "\n"}])
    async with Client(emu.srv.server) as c:
        r = await start(c, s)
        await anyio.sleep(0.3)
        sp = await call(c, "emu_stop", session_id=r["session_id"])
    assert "leaked-password-fragment" not in sp["stderr_tail"], sp["stderr_tail"]
    assert "password=" in sp["stderr_tail"]


async def test_exit_codes_map_to_stopped_by(emu):
    """ESP: rc 0 (리셋, -no-reboot) → guest-reset / on_reset=reboot 이면 guest-exit, 시작 뒤 rc 1 → config-error(ended),
    stderr 의 'invalid class name' → config-error."""
    s = seed_esp()
    async with Client(emu.srv.server) as c:
        emu.mode("exit0", exit_after=0.3)  # 게스트 리셋 흉내: 배너 → rc 0
        r = await start(c, s)
        row = await poll_state(c, r["session_id"], ("ended", "failed"))
        assert row["state"] == "ended" and row["stopped_by"] == "guest-reset", row
        sp = await call(c, "emu_stop", session_id=r["session_id"])
        assert sp["exit"] == {"code": 0, "signal": None} and sp["already_stopped"] is True
        # 서버가 보내지 않은 신호로 끝나면 killed
        emu.mode("boot")
        r = await start(c, s)
        pid = wait_fake_start(sess_dir(s, r["session_id"]))["pid"]
        os.kill(pid, signal.SIGKILL)
        row = await poll_state(c, r["session_id"], ("ended", "failed"))
        assert row["stopped_by"] == "killed", row
        sp = await call(c, "emu_stop", session_id=r["session_id"])
        assert sp["exit"]["signal"] == signal.SIGKILL and sp["exit"]["code"] is None
        for kw, script, want in [
            ({"on_reset": "reboot"}, [{"out": "PWEH-FAKE-BOOT\r\n"}, {"sleep": 0.3}, {"exit": 0}], "guest-exit"),
            ({}, [{"out": "PWEH-FAKE-BOOT\r\n"}, {"sleep": 0.8}, {"err": "qemu-system-xtensa: late failure"}, {"exit": 1}],
             "config-error"),
            ({}, [{"out": "PWEH-FAKE-BOOT\r\n"}, {"sleep": 0.3},
                  {"err": "qemu-system-xtensa: warning: -global driver=timer.esp32s3.timg,property=wdt_disable,value=true: "
                          "invalid class name"}], "config-error"),
        ]:
            emu.mode("boot", script=script)
            r = await start(c, s, **kw)
            assert r["state"] == "running", r
            sid = r["session_id"]
            row = await poll_state(c, sid, ("ended", "failed"))
            assert row["state"] == "ended" and row["stopped_by"] == want, (want, row)
            sp = await call(c, "emu_stop", session_id=sid)
            assert sp["already_stopped"] is True and sp["stopped_by"] == want
            if want == "config-error" and "late failure" in json.dumps(script):
                assert sp["exit"] == {"code": 1, "signal": None} and "late failure" in sp["stderr_tail"]


async def test_exec_failure_and_netns_retry(emu, monkeypatch, tmp_path):
    """shim 의 exec 실패(127) → emu_spawn_failed, 세션 failed/spawn-failed. 네트워크 네임스페이스를 못 쓰면(shim 94) --netns 없이 한 번
    다시 띄우고 isolation.netns=false 를 기록한다(D4)."""
    s = seed_esp()
    real_shim_argv = emu.B.shim_argv

    def broken(argv, **kw):
        return real_shim_argv([str(tmp_path / "missing" / "qemu-system-xtensa")] + list(argv[1:]), **kw)

    async with Client(emu.srv.server) as c:
        monkeypatch.setattr(emu.B, "shim_argv", broken)
        r = await call(c, "emu_start", case_id=s.cid, firmware=s.rel, label="noexec")
        assert err_code(r) == "emu_spawn_failed" and "shim-127" in r["_error"], r
        row = (await call(c, "emu_sessions", case_id=s.cid))["sessions"][0]
        assert row["state"] == "failed" and row["stopped_by"] == "spawn-failed"
        assert meta(sess_dir(s, row["session_id"]))["state"] == "failed"
        monkeypatch.setattr(emu.B, "shim_argv", real_shim_argv)

        src = Path(emu.B.SHIM_PATH).read_text(encoding="utf-8")
        patched = src.replace("def _netns(libc):\n", "def _netns(libc):\n    _fail(94, \"forced-for-test\")\n", 1)
        assert patched != src
        shim = tmp_path / "shim-no-netns" / "_exec_shim.py"
        shim.parent.mkdir()
        shim.write_text(patched, encoding="utf-8")
        monkeypatch.setattr(emu.B, "SHIM_PATH", shim)
        monkeypatch.setattr(emu.B, "netns_state", lambda refresh=False: "available")
        r = await start(c, s, label="nonetns")
        sid = r["session_id"]
        sdir = sess_dir(s, sid)
        assert r["isolation"]["netns"] is False
        assert meta(sdir)["isolation"]["netns"] is False
        assert any(e["type"] == "netns_unavailable" and e["retry"] is True for e in events(sdir))
        assert len(fake_starts(sdir)) == 1  # 첫 시도는 exec 전에 끝났다
        rd = await call(c, "emu_read", session_id=sid, wait_seconds=3, until="PWEH-FAKE-BOOT")
        assert rd["matched"] is True
        await call(c, "emu_stop", session_id=sid)


async def test_sigterm_ignoring_emulator_is_killed_after_grace(emu):
    s = seed_esp()
    emu.mode("hang", ignore_term=True)
    async with Client(emu.srv.server) as c:
        r = await start(c, s)
        sid = r["session_id"]
        sdir = sess_dir(s, sid)
        pid = wait_fake_start(sdir)["pid"]
        t0 = time.monotonic()
        sp = await call(c, "emu_stop", session_id=sid)
        elapsed = time.monotonic() - t0
    assert sp["stopped_by"] == "agent-stop" and sp["exit"]["signal"] == signal.SIGKILL, sp
    assert emu.limits.STOP_GRACE_S - 0.1 <= elapsed <= emu.limits.STOP_GRACE_S + 4, elapsed
    assert any(e["type"] == "kill" for e in events(sdir)) and not pid_alive(pid)


async def test_group_stop_kills_grandchildren(emu):
    s = seed_esp()
    emu.mode("grandchild")
    async with Client(emu.srv.server) as c:
        r = await start(c, s)
        sid = r["session_id"]
        sdir = sess_dir(s, sid)
        rd = await call(c, "emu_read", session_id=sid, wait_seconds=5, until="GRANDCHILD-STARTED")
        assert rd["matched"] is True
        fake = wait_fake_start(sdir)
        gc = next(x["grandchild"] for x in read_jsonl(sdir / "fake.log") if "grandchild" in x)
        assert pid_alive(gc) and gc in group_members(fake["pid"])
        await call(c, "emu_stop", session_id=sid)
    assert wait_until(lambda: not pid_alive(gc), 3) and not pid_alive(fake["pid"]) and group_members(fake["pid"]) == []


# ---------------------------------------------------------------------------
# AVR
# ---------------------------------------------------------------------------


async def _import(case_id: str, src: Path) -> str:
    from case_mcp.server import server as case_server

    async with Client(case_server) as cc:
        imp = await call(cc, "case_import_file", case_id=case_id, source_path=str(src), kind="firmware-image", dest_subdir="dumps")
    assert imp.get("ok") and imp["provenance"]["kind"] == "imported-unattested", imp
    return imp["artifact"]["path"]


async def test_avr_device_read_does_not_bypass_import_attestation(emu):
    """AVR 은 device-read 원장만으로 실행하지 않고 가져오기·출처 증명을 요구한다(D16)."""
    cid = make_case("avr provenance")
    rel = "dumps/avr.hex"
    put_file(cid, rel, ECHO_HEX.read_bytes())
    seed_device_read(cid, rel, chip="ATmega328P", mac=None)
    async with Client(emu.srv.server) as c:
        r = await call(c, "emu_start", case_id=cid, firmware=rel, board="uno")
    assert err_code(r) == "emu_provenance" and "avr-import-required" in r["_error"], r
    assert fake_logs_under(case_dir(cid)) == []


async def test_avr_import_attestation_and_session(emu, tmp_path):
    """AVR 은 늘 case_import_file + provenance-import 증명(D16): 첫 호출 attestation_required(아무것도 띄우지 않음) → 사람의 결정 →
    같은 인자로 다시 → 봉인한 memfd 하나(--hex-fd)의 정규화 HEX, 정확한 argv, AVR rlimit. 에코·0x04 멈춤(guest-halt)."""
    from emu_mcp import images

    emu.ws["set_safety"](approval_methods=["cli"])
    emu.mode("echo", avr_version="0.9")  # 드라이버 버전만 다름 → 경고
    emu.B.clear_probe_cache()
    cid = make_case("avr")
    outside = tmp_path / "outside"
    outside.mkdir()
    src = outside / "blink.hex"
    src.write_bytes(ECHO_HEX.read_bytes())
    rel = await _import(cid, src)
    n_att = len(rt().attestations.list())
    async with Client(emu.srv.server) as c:
        r1 = await call(c, "emu_start", case_id=cid, firmware=rel, board="uno", timeout_s=50, idle_timeout_s=30)
        assert r1["ok"] is False and r1["status"] == "attestation_required" and r1["attestation_id"], r1
        assert "pweh attest" in json.dumps(r1, ensure_ascii=False)
        assert len(rt().attestations.list()) == n_att + 1
        assert fake_logs_under(case_dir(cid)) == [] and not (case_dir(cid) / "emu").exists()
        decide_attestation(r1["attestation_id"])
        r = await call(c, "emu_start", case_id=cid, firmware=rel, board="uno", timeout_s=50, idle_timeout_s=30)
        assert r.get("ok") is True and r["state"] == "running", r
        sid = r["session_id"]
        sdir = case_dir(cid) / "emu" / sid
        assert r["backend"] == "avr-simavr"
        assert r["target"] == {"board": "uno", "mcu": "atmega328p", "freq_hz": 16_000_000, "uart": 0, "vcpus": 1}
        data = ECHO_HEX.read_bytes()
        norm = images.normalize_avr(data, "atmega328p")
        fw = r["firmware"]
        assert fw["sha256"] == _sha(data) and fw["provenance_reason"] == "imported-attested"
        assert fw["attestation_id"] == r1["attestation_id"]
        assert r["working_copy"] == {"sha256": _sha(norm.hex_bytes), "size": len(norm.hex_bytes), "padded_from": None, "handoff": "memfd"}
        assert r["avr"]["input_kind"] == "hex" and r["avr"]["flash_size"] == 32768 and r["avr"]["eeprom_bytes"] == 0
        assert r["isolation"]["snapshot"] is False and "efuse" not in r and "psram" not in r
        assert any(w.startswith("avr_driver_version") for w in r["warnings"]), r["warnings"]
        fake = wait_fake_start(sdir)
        hx = handoff(fake, "hex")
        assert fake["argv"] == [str(emu.fakes["pweh_avr_run"]), "--mcu", "atmega328p", "--freq", "16000000", "--uart", "0",
                                "--realtime", "--hex-fd", str(hx["fd"])]
        assert hx["sha256"] == r["working_copy"]["sha256"] and hx["seals"] == SEALS_ALL and hx["write_blocked"] is True
        assert hx["name"].startswith("/memfd:pweh-emu-hex") and len(fake["memfds"]) == 1 and fake["sockets"] == 0
        rl = fake["rlimits"]
        assert rl["RLIMIT_AS"] == [64 * MiB, 64 * MiB] and rl["RLIMIT_FSIZE"] == [MiB, MiB]
        assert rl["RLIMIT_CPU"] == list(cpu_limit(50, 1)) and rl["RLIMIT_CORE"] == [0, 0] and rl["RLIMIT_NOFILE"] == [256, 256]
        assert sorted(fake["env"]) == ["HOME", "LANG", "LC_ALL", "PATH", "TMPDIR"] and fake["pgid"] == fake["pid"]
        # meta.json 에는 입력·정규화 HEX·플래시 내용의 sha256 만 (사본 파일 없음)
        image = bytearray(b"\xff" * 32768)
        for line in data.decode("ascii").split():
            rec = bytes.fromhex(line[1:])
            if rec[3] == 0:
                addr = (rec[1] << 8) | rec[2]
                image[addr:addr + rec[0]] = rec[4:4 + rec[0]]
        m = meta(sdir)
        assert m["firmware"]["sha256"] == _sha(data) and m["working_copy"]["sha256"] == _sha(norm.hex_bytes)
        assert m["avr"]["hex_sha256"] == _sha(norm.hex_bytes) and m["avr"]["flash_sha256"] == _sha(bytes(image))
        assert m["avr"]["flash_used"] == 98 and r["avr"]["flash_used"] == 98 and "path" not in m["working_copy"]
        assert not {p.name for p in sdir.iterdir()} & {"fw.hex", "flash.bin", "efuse.bin"}

        rd = await call(c, "emu_read", session_id=sid, wait_seconds=5, until="OK")
        assert rd["matched"] and rd["hints"] == []
        await call(c, "emu_write", session_id=sid, data="abc\r\n")
        rd = await call(c, "emu_read", session_id=sid, wait_seconds=5, until="abc")
        assert rd["matched"] and rd["text"] == "abc"
        await call(c, "emu_write", session_id=sid, data="04", encoding="hex")
        row = await poll_state(c, sid, ("ended",))
        assert row["stopped_by"] == "guest-halt", row
        sp = await call(c, "emu_stop", session_id=sid)
        assert sp["already_stopped"] is True and sp["exit"] == {"code": 0, "signal": None}
        assert "pweh_avr_run: state=done" in sp["stderr_tail"]
        arts = {a["path"]: a for a in rt().cases.get(cid).load()["artifacts"]}
        assert arts[f"emu/{sid}/meta.json"]["extra"]["backend"] == "avr-simavr"
        assert arts[f"emu/{sid}/meta.json"]["extra"]["target"]["board"] == "uno"

        # 같은 파일(같은 sha256)은 증명을 다시 묻지 않는다. 종료 코드: 3 → guest-crash, 5 → server-gone, 정지 → 신호
        for mode, want, exit_ in (("crash3", "guest-crash", {"code": 3, "signal": None}),
                                  ("boot", "max-cycles", {"code": 4, "signal": None}),
                                  ("boot", "server-gone", {"code": 5, "signal": None})):
            script = [{"out": "OK\r\n"}, {"sleep": 0.3}, {"exit": exit_["code"]}]
            emu.mode(mode, **({} if mode == "crash3" else {"script": script}))
            r = await call(c, "emu_start", case_id=cid, firmware=rel, board="uno")
            assert r.get("ok") is True, r
            row = await poll_state(c, r["session_id"], ("ended", "failed"))
            assert row["stopped_by"] == want, (mode, row)
            sp = await call(c, "emu_stop", session_id=r["session_id"])
            assert sp["exit"] == exit_, sp
        emu.mode("echo")
        r = await call(c, "emu_start", case_id=cid, firmware=rel, board="uno")
        sp = await call(c, "emu_stop", session_id=r["session_id"])
        assert sp["stopped_by"] == "agent-stop" and sp["exit"]["signal"] == signal.SIGTERM, sp  # 실행기는 SIGTERM 의 기본 동작
    assert len(rt().attestations.list()) == n_att + 1


def _rec(rtype: int, addr: int, payload: bytes) -> str:
    """Intel HEX 레코드 한 줄 (체크섬 계산)."""
    body = bytes([len(payload), (addr >> 8) & 0xFF, addr & 0xFF, rtype]) + payload
    return ":" + (body + bytes([(-sum(body)) & 0xFF])).hex().upper() + "\n"


async def test_avr_refusals_before_attestation_and_argument_checks(emu, tmp_path):
    """ELF·깨진 HEX 는 증명을 묻기 전에 거부(emu_elf_refused·emu_bad_hex — 오류에는 줄 번호만, 레코드 글 없음). 보드·MCU·주파수 검증,
    AVR 에 ESP 인자 → validation_failed. EEPROM 레코드는 남기고(MCU EEPROM 크기 안) 퓨즈는 버린다."""
    emu.ws["set_safety"](approval_methods=["cli"])
    cid = make_case("avr refusals")
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "fw.elf").write_bytes(b"\x7fELF\x01\x01\x01" + b"\0" * 57)
    bad_line = ":040000000C94FF3F1F"
    (outside / "bad.hex").write_text(bad_line + "\n:00000001FF\n", encoding="ascii")
    elf = await _import(cid, outside / "fw.elf")
    bad = await _import(cid, outside / "bad.hex")
    n_att = len(rt().attestations.list())
    async with Client(emu.srv.server) as c:
        r = await call(c, "emu_start", case_id=cid, firmware=elf, board="uno")
        assert err_code(r) == "emu_elf_refused", r
        r = await call(c, "emu_start", case_id=cid, firmware=bad, board="uno")
        assert err_code(r) == "emu_bad_hex" and "줄 1" in r["_error"] and bad_line not in r["_error"], r
        assert len(rt().attestations.list()) == n_att  # 어차피 거부할 파일에 사람의 증명을 묻지 않았다
        for kw in ({"board": "custom"}, {"board": "custom", "mcu": "atmega328p"},
                   {"board": "custom", "mcu": "attiny85", "freq_hz": 8_000_000},
                   {"board": "custom", "mcu": "atmega328p", "freq_hz": 64_000_000}, {"board": "uno", "mcu": "atmega2560"},
                   {"board": "uno", "freq_hz": 8_000_000}, {"board": "uno", "chip": "esp32s3"}, {"board": "uno", "psram": "quad"},
                   {"board": "zero"}, {"backend": "avr"}):
            r = await call(c, "emu_start", case_id=cid, firmware=elf, **kw)
            assert err_code(r) == "validation_failed", (kw, r)
        # EEPROM 을 담은 HEX → 정규화 HEX 에 EEPROM 이 남는다, 퓨즈는 메모
        eeprom_hex = (ECHO_HEX.read_text(encoding="ascii").replace(":00000001FF\n", "")
                      + _rec(4, 0, b"\x00\x81") + _rec(0, 0, b"\x01\x02\x03\x04")      # EEPROM 0x810000: 4 바이트
                      + _rec(4, 0, b"\x00\x82") + _rec(0, 0, b"\xff") + ":00000001FF\n")  # 퓨즈 0x820000: 1 바이트
        (outside / "ee.hex").write_text(eeprom_hex, encoding="ascii")
        ee = await _import(cid, outside / "ee.hex")
        r1 = await call(c, "emu_start", case_id=cid, firmware=ee, board="uno")
        assert r1["status"] == "attestation_required", r1
        decide_attestation(r1["attestation_id"])
        emu.mode("echo")
        r = await call(c, "emu_start", case_id=cid, firmware=ee, board="uno")
        assert r.get("ok") is True and r["avr"]["eeprom_bytes"] == 4, r
        assert any("퓨즈" in n for n in r["notes"]) and any("EEPROM" in n for n in r["notes"]), r["notes"]
        fake = wait_fake_start(case_dir(cid) / "emu" / r["session_id"])
        assert handoff(fake, "hex")["sha256"] == r["working_copy"]["sha256"]
        await call(c, "emu_stop", session_id=r["session_id"])


async def test_imported_esp_image_needs_attestation_and_uses_header_only(emu, tmp_path):
    """가져온 ESP 전체 덤프: 증명 뒤에만 실행, 칩은 헤더로만, 보안 상태는 경고(security_state_unknown), PSRAM 기본값."""
    emu.ws["set_safety"](approval_methods=["cli"])
    cid = make_case("esp import")
    src = tmp_path / "outside" / "vendor-c3.bin"
    src.parent.mkdir()
    src.write_bytes(esp_flash("esp32c3", nvs=False))
    rel = await _import(cid, src)
    async with Client(emu.srv.server) as c:
        r1 = await call(c, "emu_start", case_id=cid, firmware=rel)
        assert r1["status"] == "attestation_required", r1
        decide_attestation(r1["attestation_id"])
        r = await call(c, "emu_start", case_id=cid, firmware=rel)
        assert r.get("ok") is True and r["target"]["chip"] == "esp32c3" and r["firmware"]["provenance_reason"] == "imported-attested"
        assert any(w.startswith("security_state_unknown") for w in r["warnings"]) and r["psram"]["source"] == "default"
        await call(c, "emu_stop", session_id=r["session_id"])
        r = await call(c, "emu_start", case_id=cid, firmware=rel, chip="esp32s3")
        assert err_code(r) == "emu_machine_mismatch", r


# ---------------------------------------------------------------------------
# 고아 정리 (시작 정리)
# ---------------------------------------------------------------------------


def _owner(pid: int | None = None) -> dict:
    """pid 를 주면 그 살아 있는 프로세스를 주인으로, 아니면 이미 끝난 프로세스를 주인으로 한 owner 기록."""
    from pweh import procutil

    rec = procutil.owner_record("emu-mcp")
    if pid is None:
        p = subprocess.Popen(["true"])
        p.wait()
        rec.update(pid=p.pid, start_ticks=1)
    else:
        rec.update(pid=pid, start_ticks=procutil.proc_stat(pid)[1])
    return rec


def _seed_session(cid: str, sid: str, owner: dict, child: dict | None, state: str = "running") -> Path:
    d = case_dir(cid) / "emu" / sid
    (d / "tmp").mkdir(parents=True)
    (d / "meta.json").write_text(json.dumps({"schema": "pweh.emu-session/v1", "session_id": sid, "case_id": cid, "state": state,
                                             "owner": owner, "child": child}), encoding="utf-8")
    (d / "events.jsonl").write_text("", encoding="utf-8")
    return d


ORPHAN_ARGV = ["-no-user-config", "-nodefaults", "-machine", "esp32s3", "-display", "none", "-monitor", "none", "-nic", "none",
               "-serial", "stdio"]


def _spawn_fake(emu, cwd: Path, *, leader: bool = True) -> subprocess.Popen:
    return subprocess.Popen([str(emu.fakes["qemu-system-xtensa"]), *ORPHAN_ARGV], cwd=str(cwd), stdin=subprocess.PIPE,
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=leader,
                            env={"PATH": "/usr/bin:/bin"})


def _child_rec(pid: int, ticks_delta: int = 0) -> dict:
    from pweh import procutil

    return {"pid": pid, "start_ticks": procutil.proc_stat(pid)[1] + ticks_delta, "pgid": pid,
            "exe_realpath": os.path.realpath(os.readlink(f"/proc/{pid}/exe"))}


async def test_startup_sweep_orphan_cases(emu, tmp_path):
    """시작 정리(설계 §6.2, 계약 [S]): 주인이 죽은 세션의 에뮬레이터를 신원(uid·start_ticks·그룹 리더·cwd = 세션·실행 파일)을 확인한 뒤
    끝내고 reaped/server-gone 으로 고친다. 입양하지 않는다.

    (a) 주인 죽음 + 기록한 자식 → 끝냄  (b) 주인 살아 있음 → 그대로  (c) 기록한 pid 가 재사용됨(start_ticks 다름, 다른 cwd) → 신호 없음
    (c2) start_ticks 기록이 틀려도 세션 디렉터리의 에뮬레이터는 cwd 훑기로 끝냄  (d) 그룹 리더가 아님 → 그대로
    (e) child=null + cwd 가 세션인 에뮬레이터 → 훑어서 끝냄  (f) cwd 는 같지만 실행 파일이 허용 밖(sleep) → 그대로
    (g) 표식 없는 파이썬 → 그대로  (h) shim 표식(exec 전 창)이 있는 파이썬 → 끝냄."""
    from emu_mcp import server as srv
    from pweh import procutil

    emu.mode("hang")
    cid = make_case("orphans")
    procs: dict[str, subprocess.Popen] = {}
    try:
        da = _seed_session(cid, "emu-101", _owner(), None)
        procs["a"] = _spawn_fake(emu, da)
        wait_fake_start(da)
        (da / "meta.json").write_text(json.dumps({**meta(da), "child": _child_rec(procs["a"].pid)}), encoding="utf-8")

        live_owner = subprocess.Popen(["sleep", "120"])
        procs["owner"] = live_owner
        db = _seed_session(cid, "emu-102", _owner(live_owner.pid), None)
        procs["b"] = _spawn_fake(emu, db)
        wait_fake_start(db)
        (db / "meta.json").write_text(json.dumps({**meta(db), "child": _child_rec(procs["b"].pid)}), encoding="utf-8")

        elsewhere = tmp_path / "elsewhere"
        elsewhere.mkdir()
        procs["c"] = _spawn_fake(emu, elsewhere)
        wait_fake_start(elsewhere)
        dc = _seed_session(cid, "emu-103", _owner(), _child_rec(procs["c"].pid, ticks_delta=1000))

        dc2 = _seed_session(cid, "emu-104", _owner(), None)
        procs["c2"] = _spawn_fake(emu, dc2)
        wait_fake_start(dc2)
        (dc2 / "meta.json").write_text(json.dumps({**meta(dc2), "child": _child_rec(procs["c2"].pid, ticks_delta=1000)}), encoding="utf-8")

        dd = _seed_session(cid, "emu-105", _owner(), None)
        procs["d"] = subprocess.Popen(["sh", "-c", '"$0" "$@" & echo $!; wait', str(emu.fakes["qemu-system-xtensa"]), *ORPHAN_ARGV],
                                      cwd=str(dd), stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                      start_new_session=True)
        d_child = int(procs["d"].stdout.readline())
        wait_fake_start(dd)
        assert os.getpgid(d_child) == procs["d"].pid != d_child

        de = _seed_session(cid, "emu-106", _owner(), None)
        procs["e"] = _spawn_fake(emu, de)
        wait_fake_start(de)

        df = _seed_session(cid, "emu-107", _owner(), None)
        procs["f"] = subprocess.Popen(["sleep", "120"], cwd=str(df), start_new_session=True)

        py = os.path.realpath(sys.executable)
        dg = _seed_session(cid, "emu-108", _owner(), None)
        procs["g"] = subprocess.Popen([py, "-c", "import time; time.sleep(120)"], cwd=str(dg), start_new_session=True)

        dh = _seed_session(cid, "emu-109", _owner(), None)
        procs["h"] = subprocess.Popen([py, "-c", "import time; time.sleep(120)", str(emu.B.SHIM_PATH), "--session-dir", str(dh)],
                                      cwd=str(dh), start_new_session=True)
        assert wait_until(lambda: all(pid_alive(p.pid) for p in procs.values()), 5)

        # start_ticks 확인은 자식 분기의 필수 조건이다 (다른 모든 것이 맞아도)
        emu_bins = srv._emulator_realpaths()
        allow = emu_bins | {os.path.realpath(sys.executable)}
        ident = procutil.proc_identity(procs["a"].pid)
        good = _child_rec(procs["a"].pid)
        assert srv._identity_ok(ident, procs["a"].pid, str(da), allow, emu_bins, good) is True
        assert srv._identity_ok(ident, procs["a"].pid, str(da), allow, emu_bins, {**good, "start_ticks": good["start_ticks"] + 1}) is False
        assert srv._identity_ok(ident, procs["a"].pid, str(db), allow, emu_bins, good) is False  # cwd 가 다른 세션

        out = srv._startup_sweep()
        reaped = {r["session_id"] for r in out["reaped"]}
        assert reaped == {"emu-101", "emu-103", "emu-104", "emu-105", "emu-106", "emu-107", "emu-108", "emu-109"}, out
        for key in ("a", "c2", "e", "h"):
            procs[key].wait(timeout=10)
        for key in ("b", "c", "d", "f", "g"):
            assert procs[key].poll() is None, key
        assert pid_alive(d_child)
        pids = {r["session_id"]: r["pids"] for r in out["reaped"]}
        assert pids["emu-101"] == [procs["a"].pid] and pids["emu-104"] == [procs["c2"].pid] and pids["emu-106"] == [procs["e"].pid]
        assert pids["emu-109"] == [procs["h"].pid]
        assert pids["emu-103"] == [] and pids["emu-105"] == [] and pids["emu-107"] == [] and pids["emu-108"] == []
        for d, want in ((da, "reaped"), (db, "running"), (dc, "reaped"), (de, "reaped"), (df, "reaped")):
            assert meta(d)["state"] == want, (d.name, meta(d))
        assert meta(da)["stopped_by"] == "server-gone" and meta(da)["sweep"]["results"][0]["pid"] == procs["a"].pid
        assert any(e["type"] == "sweep" for e in events(da))
        audit = [e for e in read_jsonl(case_dir(cid) / "audit.jsonl") if e.get("event") == "emu_orphans_reaped"]
        assert audit and {x["session_id"] for x in audit[0]["sessions"]} == reaped
        assert not any(sid in srv._SESSIONS for sid in reaped)  # 입양하지 않는다
        again = srv._startup_sweep()
        assert again["reaped"] == []  # 최종 상태는 다시 보지 않는다
    finally:
        for key, p in procs.items():
            if p.poll() is None:
                if key == "d":
                    os.killpg(p.pid, signal.SIGKILL)
                else:
                    p.kill()
            p.wait(timeout=10)
            if p.stdout:
                p.stdout.close()
            if p.stdin:
                p.stdin.close()


# ---------------------------------------------------------------------------
# 서버 종료 (stdio 서브프로세스)
# ---------------------------------------------------------------------------


def _stdio_start(emu, s) -> tuple[StdioServer, str, int, Path]:
    srvp = StdioServer(server_env())
    srvp.initialize()
    r = srvp.call("emu_start", case_id=s.cid, firmware=s.rel, timeout_s=120, idle_timeout_s=60)
    assert r.get("ok") is True, r
    sdir = sess_dir(s, r["session_id"])
    pid = wait_fake_start(sdir)["pid"]
    return srvp, r["session_id"], pid, sdir


@pytest.mark.parametrize("how", ["sigterm", "stdin-close"])
def test_server_shutdown_stops_sessions(emu, how):
    s = seed_esp()
    emu.mode("boot")
    srvp, sid, pid, sdir = _stdio_start(emu, s)
    try:
        if how == "sigterm":
            srvp.proc.send_signal(signal.SIGTERM)
        else:
            srvp.proc.stdin.close()
        srvp.proc.wait(60)
        assert srvp.proc.returncode == (-signal.SIGTERM if how == "sigterm" else 0)
        assert wait_until(lambda: not pid_alive(pid), 5) and group_members(pid) == []
        m = meta(sdir)
        assert m["state"] == "ended" and m["stopped_by"] == "server-shutdown", m
        arts = {a["path"] for a in rt().cases.get(s.cid).load().get("artifacts", [])}
        assert f"emu/{sid}/console.bin" in arts and f"emu/{sid}/meta.json" in arts
    finally:
        srvp.close()


def test_server_sigkill_kills_emulator_via_pdeathsig_and_sweep_reaps(emu):
    """서버 SIGKILL → 2 초 안에 에뮬레이터도 없음(PDEATHSIG) → 다음 시작 정리가 reaped. 서버는 시작할 때 모든 케이스를 정리한다."""
    stale = _seed_session(make_case("stale"), "emu-020", _owner(), None)
    s = seed_esp()
    emu.mode("boot")
    srvp, sid, pid, sdir = _stdio_start(emu, s)
    try:
        assert meta(stale)["state"] == "reaped" and meta(stale)["stopped_by"] == "server-gone"  # main() 의 _startup_sweep()
        srvp.proc.kill()
        srvp.proc.wait(10)
        t0 = time.monotonic()
        assert wait_until(lambda: not pid_alive(pid), 2.0), "PDEATHSIG 가 에뮬레이터를 끝내지 않았다"
        assert time.monotonic() - t0 <= 2.0
        assert meta(sdir)["state"] == "running"  # 서버가 정리하지 못했다 — 다음 시작 정리의 몫
        out = emu.srv._startup_sweep()
        assert [r["session_id"] for r in out["reaped"]] == [sid] and out["reaped"][0]["pids"] == []
        m = meta(sdir)
        assert m["state"] == "reaped" and m["stopped_by"] == "server-gone"
    finally:
        srvp.close()


# ---------------------------------------------------------------------------
# 끝난 세션의 기록·stdio 스모크·검증
# ---------------------------------------------------------------------------


async def test_ended_session_transcript_fallback(emu, monkeypatch):
    """메모리에서 밀려난 끝난 세션은 emu_read(session_id, case_id=…) 가 transcript.masked.txt(마스킹한 기록)로 돌려준다.
    다른 서버 프로세스가 아직 실행 중인 세션(살아 있는 주인)은 not_found."""
    monkeypatch.setattr(emu.limits, "ENDED_SESSIONS_KEPT", 1)
    s = seed_esp()
    emu.mode("boot", lines=["FIRST-LINE", "I (2) app: password=fallback-secret-123", "THIRD-LINE"])
    async with Client(emu.srv.server) as c:
        a = await start(c, s)
        rd = await call(c, "emu_read", session_id=a["session_id"], wait_seconds=3, until="THIRD-LINE")
        assert rd["matched"]
        await call(c, "emu_stop", session_id=a["session_id"])
        emu.mode("boot", lines=["OTHER"])
        b = await start(c, s)
        await call(c, "emu_stop", session_id=b["session_id"])
        assert a["session_id"] not in emu.srv._SESSIONS and b["session_id"] in emu.srv._SESSIONS
        sid = a["session_id"]
        r = await call(c, "emu_read", session_id=sid)
        assert err_code(r) == "not_found" and "case_id" in r["_error"], r
        r = await call(c, "emu_read", session_id=sid, case_id=s.cid, until="THIRD")
        assert r["source"] == "transcript" and r["state"] == "ended" and r["stopped_by"] == "agent-stop", r
        assert r["text"].splitlines()[0] == "FIRST-LINE" and r["text"].splitlines()[-1] == "THIRD-LINE"
        assert "fallback-secret-123" not in r["text"] and r["matched"] is True and r["match"] == "THIRD"
        assert r["cursor_start"] == 0 and r["more"] is False
        r = await call(c, "emu_read", session_id=sid, case_id=s.cid, since_cursor=len("FIRST-LINE\n") + 3)
        assert r["cursor_start"] == len("FIRST-LINE\n") and r["text"].startswith("I (2) app: password="), r
        r = await call(c, "emu_read", session_id=sid, case_id=s.cid, tail=True, max_chars=256)
        assert r["text"].endswith("THIRD-LINE")
        sp = await call(c, "emu_stop", session_id=sid, case_id=s.cid)
        assert sp["already_stopped"] is True and sp["stopped_by"] == "agent-stop" and sp["state"] == "ended", sp
        # 다른 서버 프로세스가 실행 중인 세션은 기록을 돌려주지 않는다
        sleeper = subprocess.Popen(["sleep", "60"])
        try:
            _seed_session(s.cid, "emu-077", _owner(sleeper.pid), None)
            r = await call(c, "emu_read", session_id="emu-077", case_id=s.cid)
            assert err_code(r) == "not_found", r
            r = await call(c, "emu_stop", session_id="emu-077", case_id=s.cid)
            assert err_code(r) == "not_found", r
        finally:
            sleeper.kill()
            sleeper.wait()


async def test_stdio_smoke_six_tools_and_status(emu):
    params = stdio_params("emu_mcp", env=server_env())
    async with Client(params, read_timeout_seconds=60) as c:
        tools = {t.name: t for t in (await c.list_tools()).tools}
        assert set(tools) == SIX_TOOLS, sorted(tools)
        read_only = {n for n, t in tools.items() if t.annotations is not None and t.annotations.read_only_hint}
        assert read_only == {"emu_status", "emu_read", "emu_sessions"}
        assert not any(t.annotations.destructive_hint or t.annotations.open_world_hint for t in tools.values())
        v = await call(c, "emu_status")
        assert v["ok"] and v["backends"]["esp-qemu"]["available"] and v["backends"]["avr-simavr"]["available"]


async def test_session_ids_labels_and_exclusive_dirs(emu):
    s = seed_esp()
    (s.dir / "emu" / "probe-001").mkdir(parents=True)  # 다른 프로세스가 먼저 만든 디렉터리 (이미 있으면 실패하는 mkdir)
    async with Client(emu.srv.server) as c:
        ids = []
        for label in ("probe", "probe", None):
            r = await start(c, s, **({"label": label} if label else {}))
            ids.append(r["session_id"])
            await call(c, "emu_stop", session_id=r["session_id"])
        assert ids == ["probe-002", "probe-003", "emu-001"], ids
        r = await call(c, "emu_start", case_id=s.cid, firmware=s.rel, label="Bad_Label")
        assert err_code(r) == "validation_failed"


async def test_argument_validation(emu):
    s = seed_esp()
    unauth = make_case("no auth", authorized=False)
    put_file(unauth, s.rel, s.data)
    bad_start = [
        {"timeout_s": 5}, {"timeout_s": 4000}, {"idle_timeout_s": 10}, {"timeout_s": 60, "idle_timeout_s": 120},
        {"psram": "huge"}, {"psram": "octal", "psram_mb": 3}, {"watchdog": "off"}, {"on_reset": "loop"}, {"backend": "x86"},
        {"chip": "esp99"}, {"board": "uno", "backend": "esp"},
    ]
    async with Client(emu.srv.server) as c:
        for kw in bad_start:
            r = await call(c, "emu_start", case_id=s.cid, firmware=s.rel, **kw)
            assert err_code(r) == "validation_failed", (kw, r)
        r = await call(c, "emu_start", case_id=unauth, firmware=s.rel)
        assert err_code(r) in ("authorization_required", "case_error"), r
        r = await call(c, "emu_start", case_id=s.cid, firmware=s.rel, chip="esp32c3", psram="octal")
        assert err_code(r) in ("validation_failed", "emu_machine_mismatch"), r
        r = await start(c, s)
        sid = r["session_id"]
        for kw in ({"max_chars": 100}, {"max_chars": 70000}, {"wait_seconds": 51}, {"wait_seconds": -1}, {"until": []},
                   {"until": ["a"] * 9}, {"until": "x" * 65}, {"until": "a\nb"}, {"since_cursor": -1}):
            rr = await call(c, "emu_read", session_id=sid, **kw)
            assert err_code(rr) == "validation_failed", (kw, rr)
        for kw in ({"data": ""}, {"data": "x" * 4097}, {"data": "zz", "encoding": "hex"}, {"data": "x", "encoding": "base64"}):
            rr = await call(c, "emu_write", session_id=sid, **kw)
            assert err_code(rr) == "validation_failed", (kw, rr)
        rr = await call(c, "emu_write", session_id=sid, data="00 " * 4096, encoding="hex")
        assert rr["bytes_written"] == 4096  # hex 는 공백을 빼고 센다
        for bad_sid in ("../x", "EMU-001", "emu", ""):
            rr = await call(c, "emu_read", session_id=bad_sid)
            assert err_code(rr) == "validation_failed", (bad_sid, rr)
        rr = await call(c, "emu_read", session_id="emu-999")
        assert err_code(rr) == "not_found"
        rr = await call(c, "emu_stop", session_id="emu-999")
        assert err_code(rr) == "not_found"
        rr = await call(c, "emu_write", session_id="emu-999", data="x")
        assert err_code(rr) == "not_found"
        await call(c, "emu_stop", session_id=sid)
