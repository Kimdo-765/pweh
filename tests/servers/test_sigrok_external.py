"""sigrok-mcp 통합 테스트 — 실제 sigrok-cli (0.7.2 기준) 필요. 없으면 skip.

PWEH_SIGROK_CLI → ~/pweh-tools/bin/sigrok-cli → PATH 순으로 찾는다 (env.sh 를 source 하지 않아도 됨).
"""

from __future__ import annotations

import subprocess
import time
from fractions import Fraction

import pytest
from mcp import Client

from mcp_helpers import call
from servers.sigrok_testutil import case_dir, make_case, real_sigrok_cli, write_uart_sr, write_uart_vcd
from sigrok_mcp.synth import BOOT_BANNER

REAL = real_sigrok_cli()
pytestmark = [
    pytest.mark.anyio,
    pytest.mark.external,
    pytest.mark.skipif(REAL is None, reason="실제 sigrok-cli 가 없음 (PWEH_SIGROK_CLI 또는 ~/pweh-tools/bin/sigrok-cli)"),
]


@pytest.fixture
def anyio_backend():
    return "asyncio"


@pytest.fixture
def real(workspace, monkeypatch):
    from pweh.runtime import reset_runtimes
    from sigrok_mcp.cli import clear_cache

    monkeypatch.setenv("PWEH_SIGROK_CLI", REAL)
    reset_runtimes()
    clear_cache()
    yield REAL
    clear_cache()


def _bits_from_cli(path, channels) -> dict[str, str]:
    """sigrok-cli -O bits 출력에서 채널별 비트 문자열 (독립 검증용)."""
    out = subprocess.run([REAL, f"--input-file={path}", f"--channels={','.join(channels)}", "--output-format=bits:width=64"],
                         stdin=subprocess.DEVNULL, capture_output=True, timeout=120, check=True).stdout.decode()
    bits: dict[str, list[str]] = {c: [] for c in channels}
    for line in out.splitlines():
        name, sep, rest = line.partition(":")
        if sep and name in bits:
            bits[name].append(rest.replace(" ", ""))
    return {k: "".join(v) for k, v in bits.items()}


async def test_real_version_scan_and_demo_device_info(real):
    from sigrok_mcp.server import server

    cid = make_case()
    async with Client(server) as c:
        v = await call(c, "sigrok_version")
        assert v["ok"] and v["sigrok_cli"] and v["counts"]["decoders"] > 50
        s = await call(c, "sigrok_scan", driver="demo")
        assert s["ok"] and s["devices"][0]["driver"] == "demo" and "D0" in s["devices"][0]["channels"]
        info = await call(c, "sigrok_device_info", case_id=cid, driver="demo")
        assert info["ok"] and "Logic analyzer" in info["driver_functions"] and info["triggers"]
        h = await call(c, "sigrok_decoder_help", decoder="uart")
        assert {c_["id"] for c_ in h["decoder"]["optional_channels"]} >= {"rx", "tx"}
        assert any(o["id"] == "baudrate" for o in h["decoder"]["options"])
        lst = await call(c, "sigrok_list", kind="drivers", query="korad")
        assert lst["items"] and lst["items"][0]["capture_allowed"] is False


async def test_real_decode_synthetic_vcd(real):
    from sigrok_mcp.cli import parse_annotation_line
    from sigrok_mcp.server import server

    cid = make_case()
    cdir = case_dir(cid)
    write_uart_vcd(cdir / "signals" / "boot.vcd", BOOT_BANNER, baud=115200, samplerate=1_000_000)
    async with Client(server) as c:
        r = await call(c, "sigrok_decode", case_id=cid, input_path="signals/boot.vcd",
                       decoders="uart:rx=RX:baudrate=115200:format=hex", annotations="uart=rx-data", samplenum=True, max_lines=5)
        assert r["ok"], r
        assert r["lines_total"] == len(BOOT_BANNER) and r["instances"] == {"uart-1": len(BOOT_BANNER)}
        data = bytearray()
        for line in (cdir / r["output_path"]).read_text().splitlines():
            a = parse_annotation_line(line)
            data.append(int(a["text"], 16))
        assert bytes(data) == BOOT_BANNER
        # 모든 annotation 클래스 (annotations 생략) 도 동작
        r2 = await call(c, "sigrok_decode", case_id=cid, input_path="signals/boot.vcd", decoders="uart:rx=RX:baudrate=115200")
        assert r2["ok"] and r2["lines_total"] > len(BOOT_BANNER) * 5


async def test_real_vcd_to_srzip_roundtrip(real):
    from sigrok_mcp import signals as sig
    from sigrok_mcp.server import server

    cid = make_case()
    cdir = case_dir(cid)
    w = write_uart_vcd(cdir / "signals" / "u.vcd", BOOT_BANNER, baud=57600, samplerate=1_000_000, style="sigrok")
    async with Client(server) as c:
        r = await call(c, "sigrok_export", case_id=cid, input_path="signals/u.vcd", output_format="srzip")
        assert r["ok"], r
        info, ce = sig.load_channel_edges(cdir / r["output_path"], "RX")
        assert info.samplerate == 1_000_000
        assert ce.initial_level == w.initial_level and list(ce.edges) == w.edges
        assert info.total_samples == w.total_samples
        # 다시 VCD 로 → 같은 에지
        r2 = await call(c, "sigrok_export", case_id=cid, input_path=r["output_path"], output_format="vcd")
        assert r2["ok"]
        _i, ce2 = sig.load_channel_edges(cdir / r2["output_path"], "RX")
        assert list(ce2.edges) == w.edges
        e = await call(c, "sigrok_estimate_baud", case_id=cid, input_path=r["output_path"], channel="RX")
        assert e["baudrate"] == 57600


async def test_real_demo_capture_and_reader_matches_sigrok_bits(real):
    from sigrok_mcp import signals as sig
    from sigrok_mcp.server import server

    cid = make_case()
    cdir = case_dir(cid)
    chans = [f"D{i}" for i in range(8)]
    async with Client(server) as c:
        r = await call(c, "sigrok_capture", case_id=cid, driver="demo", samplerate="1m", samples=20000, channels=chans)
        assert r["ok"] and r["status"] == "succeeded", r
        p = cdir / r["path"]
        assert r["samples"] == 20000 and r["samplerate"] == 1_000_000 and r["channels"] == chans
        assert r["artifact"]["sha256"] and r["classification"]["rule_id"] == "sigrok.capture"
        info = sig.read_srzip_info(p)
        assert info.total_samples == 20000 and info.unitsize == 1
        ref = _bits_from_cli(p, chans)
        for ch in chans:
            ce = sig.srzip_channel_edges(p, info, info.channel(ch))
            lvl = ce.initial_level
            mine = []
            prev = 0
            for e in list(ce.edges) + [ce.end_tick]:
                mine.append(str(lvl) * (e - prev))
                prev = e
                lvl ^= 1
            assert "".join(mine) == ref[ch][:20000], ch
        act = {a["name"]: a["edges"] for a in r["activity"]}
        for ch in chans:
            assert act[ch] == len(sig.srzip_channel_edges(p, info, info.channel(ch)).edges)
        # 변환·정보
        fi = await call(c, "sigrok_file_info", case_id=cid, input_path=r["path"])
        assert fi["total_samples"] == 20000
        ex = await call(c, "sigrok_export", case_id=cid, input_path=r["path"], output_format="vcd")
        assert ex["ok"] and ex["output_info"]["channels"] == chans


async def test_real_capture_time_limit_and_triggered_job(real):
    from sigrok_mcp.server import server

    cid = make_case()
    async with Client(server) as c:
        r = await call(c, "sigrok_capture", case_id=cid, driver="demo", samplerate="100k", duration_ms=50, channels="D0,D1")
        assert r["ok"] and 4000 <= r["samples"] <= 5100, r
        j = await call(c, "sigrok_capture", case_id=cid, driver="demo", samplerate="200k", samples=5000,
                       channels=["D0=RX", "D1"], triggers="RX=r", capture_ratio=10)
        assert j["status"] == "started"
        deadline = time.monotonic() + 60
        while True:
            st = await call(c, "sigrok_job_status", job_id=j["job_id"], wait_seconds=5)
            if st["status"] not in ("queued", "running"):
                break
            assert time.monotonic() < deadline
        assert st["status"] == "succeeded", st
        assert st["result"]["channels"] == ["RX", "D1"] and st["result"]["samples"] > 0


async def test_real_writer_compat_and_autodecode(real):
    from sigrok_mcp.server import server
    from sigrok_mcp.writers import lane_from_edges, pack_lanes, write_srzip
    from sigrok_mcp.synth import uart_waveform

    cid = make_case()
    cdir = case_dir(cid)
    # unitsize 2, 여러 청크, RX 를 비트 9 에 둔 파일 → sigrok-cli 가 같은 채널/샘플 수로 읽어야 함
    rate = 2_000_000
    w = uart_waveform(BOOT_BANNER, baud=115200, samplerate=rate)
    n = w.total_samples
    lanes = [b"\x00" * n] * 9 + [lane_from_edges(w.initial_level, w.edges, n)] + [b"\x01" * n] * 2
    data, us = pack_lanes(lanes)
    names = [f"P{i}" for i in range(9)] + ["RX", "P10", "P11"]
    p = write_srzip(cdir / "signals" / "w.sr", data, rate, names, unitsize=us, chunk_bytes=4099)
    props = subprocess.run([REAL, f"--input-file={p}", "--show"], stdin=subprocess.DEVNULL, capture_output=True, timeout=60, check=True)
    text = props.stdout.decode()
    assert f"Samplerate: {rate}" in text and f"Logic sample count: {n}" in text and "- RX: logic" in text
    async with Client(server) as c:
        a = await call(c, "sigrok_uart_autodecode", case_id=cid, input_path="signals/w.sr", channel="RX")
        assert a["ok"] and a["engine"] == "sigrok-cli" and a["baudrate"] == 115200, a
        assert a["bytes_decoded"] == len(BOOT_BANNER) and a["framing_errors"] == 0
        assert (cdir / a["bytes_path"]).read_bytes() == BOOT_BANNER
        # 반전 라인 + 자동 채널 선택
        write_uart_sr(cdir / "signals" / "inv.sr", BOOT_BANNER, baud=230400, samplerate=4_000_000, idle_level=0)
        b = await call(c, "sigrok_uart_autodecode", case_id=cid, input_path="signals/inv.sr")
        assert b["ok"] and b["channel"] == "RX" and b["inverted"] and "invert_rx=yes" in b["decoder"]
        assert "Starting kernel" in b["text_preview"]
        # 1 ns timescale VCD → downsample 자동 적용
        write_uart_vcd(cdir / "signals" / "ns.vcd", BOOT_BANNER, baud=115200, samplerate=2_000_000, timescale=Fraction(1, 10**9))
        v = await call(c, "sigrok_uart_autodecode", case_id=cid, input_path="signals/ns.vcd", channel="RX")
        assert v["ok"] and "U-Boot 2016.11" in v["text_preview"], v
        assert any(x.startswith("--input-format=vcd:downsample=") for x in v["command"])


async def test_real_rc0_failure_detection(real, tmp_path):
    """실제 sigrok-cli 가 rc=0 으로 끝나지만 실패인 경우(없는 채널 이름)를 stderr 로 판정한다."""
    from sigrok_mcp.cli import child_env, run_process, stderr_problems

    p = tmp_path / "u.vcd"
    write_uart_vcd(p, b"Hi", baud=9600, samplerate=100_000)
    res = run_process([REAL, f"--input-file={p}", "--input-format=vcd", "--protocol-decoders=uart:rx=NOPE:baudrate=9600"],
                      timeout=60, env=child_env())
    assert res.returncode == 0
    rep = stderr_problems(res.stderr)
    assert rep.fatal and rep.errors[0]["code"] == "no_channel"
