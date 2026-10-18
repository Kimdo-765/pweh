"""sigrok-mcp 순수 Python 부분 테스트: srzip/VCD 리더·라이터, 합성 UART 파형, 보드레이트 추정기, 정책/파서.

외부 도구 없이 동작한다.
"""

from __future__ import annotations

import random
import zipfile
from fractions import Fraction
from pathlib import Path

import pytest

from pweh.errors import ValidationFailed
from pweh.safety import Risk
from servers.sigrok_testutil import write_uart_sr, write_uart_vcd
from sigrok_mcp import baud as baudmod
from sigrok_mcp import cli as clim
from sigrok_mcp import policy as pol
from sigrok_mcp import signals as sig
from sigrok_mcp.synth import BOOT_BANNER, uart_waveform
from sigrok_mcp.writers import format_samplerate, lane_from_edges, pack_lanes, write_srzip, write_vcd


def _edges_of_lane(lane: bytes) -> tuple[int, list[int]]:
    edges = [i for i in range(1, len(lane)) if lane[i] != lane[i - 1]]
    return lane[0], edges


def _rand_lane(rng: random.Random, n: int, mean_run: int) -> bytes:
    out = bytearray()
    lvl = rng.randint(0, 1)
    while len(out) < n:
        out += bytes([lvl]) * rng.randint(1, 2 * mean_run)
        lvl ^= 1
    return bytes(out[:n])


# ---------------------------------------------------------------------------
# srzip
# ---------------------------------------------------------------------------


def test_format_samplerate_matches_libsigrok():
    assert format_samplerate(1_000_000) == "1 MHz"
    assert format_samplerate(1_500_000) == "1.5 MHz"
    assert format_samplerate(200_000) == "200 kHz"
    assert format_samplerate(12_345) == "12.345 kHz"
    assert format_samplerate(100) == "100 Hz"
    assert format_samplerate(24_000_000) == "24 MHz"
    for hz in (1, 999, 1000, 1_234_567, 48_000_000, 1_000_000_000):
        assert sig.parse_rate_text(format_samplerate(hz)) == hz


@pytest.mark.parametrize("nch,chunk", [(8, 997), (12, 4096), (3, 1 << 20)])
def test_srzip_roundtrip_edges(tmp_path, nch, chunk):
    rng = random.Random(nch)
    n = 20_000
    lanes = [_rand_lane(rng, n, 37 + 11 * i) for i in range(nch)]
    data, us = pack_lanes(lanes)
    assert us == (nch + 7) // 8
    names = [f"D{i}" for i in range(nch)]
    p = write_srzip(tmp_path / "rt.sr", data, 2_000_000, names, unitsize=us, chunk_bytes=chunk)
    info = sig.read_srzip_info(p)
    assert info.samplerate == 2_000_000 and info.unitsize == us and info.total_samples == n
    assert [c.name for c in info.channels] == names
    assert info.metadata["chunks"] >= 1
    for i, lane in enumerate(lanes):
        exp_init, exp_edges = _edges_of_lane(lane)
        ce = sig.srzip_channel_edges(p, info, info.channel(f"D{i}"))
        assert ce.initial_level == exp_init
        assert list(ce.edges) == exp_edges
        assert ce.end_tick == n and not ce.truncated
    act = sig.srzip_activity(p, info)
    for i, c in enumerate(act["channels"]):
        exp_init, exp_edges = _edges_of_lane(lanes[i])
        assert c["edges"] == len(exp_edges)
        assert c["initial_level"] == exp_init and c["final_level"] == lanes[i][-1]
        assert abs(c["high_ratio"] - lanes[i].count(1) / n) < 1e-3


def test_srzip_probe_gaps_and_odd_chunks(tmp_path):
    """비활성 채널(probe 키 없음), unitsize 배수가 아닌 청크 경계, 사전식이 아닌 청크 순서."""
    n = 5000
    rng = random.Random(7)
    lanes = [_rand_lane(rng, n, 20), None, _rand_lane(rng, n, 30), None, None, None, None, None, _rand_lane(rng, n, 25)]
    data, us = pack_lanes(lanes)
    assert us == 2
    p = tmp_path / "gaps.sr"
    meta = "\n".join(["[global]", "sigrok version=0.5.2", "", "[device 1]", "capturefile=logic-1", "total probes=16",
                      "samplerate=1 MHz", "total analog=0", "probe1=D0", "probe3=CLK", "probe9=D8", "unitsize=2", ""])
    with zipfile.ZipFile(p, "w") as z:
        z.writestr(zipfile.ZipInfo("version"), "2")
        z.writestr("metadata", meta)
        # 홀수 크기 청크 (샘플 경계를 가로지름), 12개 → logic-1-10 이 logic-1-2 보다 사전식으로 앞
        cuts = sorted(set([0, len(data)] + [rng.randrange(1, len(data)) for _ in range(11)]))
        for i in range(len(cuts) - 1):
            z.writestr(f"logic-1-{i + 1}", data[cuts[i]:cuts[i + 1]], compress_type=zipfile.ZIP_DEFLATED)
    info = sig.read_srzip_info(p)
    assert [(c.name, c.index) for c in info.channels] == [("D0", 0), ("CLK", 2), ("D8", 8)]
    assert info.total_samples == n
    for name, lane in (("D0", lanes[0]), ("CLK", lanes[2]), ("D8", lanes[8])):
        ce = sig.srzip_channel_edges(p, info, info.channel(name))
        assert (ce.initial_level, list(ce.edges)) == _edges_of_lane(lane)
    assert sig.resolve_channel(info, 2).name == "CLK"
    assert sig.resolve_channel(info, "clk").name == "CLK"
    with pytest.raises(ValidationFailed):
        sig.resolve_channel(info, "D1")


def test_srzip_legacy_single_file_and_errors(tmp_path):
    lane = bytes([1] * 10 + [0] * 5 + [1] * 10)
    data, _ = pack_lanes([lane])
    p = tmp_path / "legacy.sr"
    with zipfile.ZipFile(p, "w") as z:
        z.writestr("version", "1")
        z.writestr("metadata", "[device 1]\ncapturefile=logic-1\ntotal probes=1\nsamplerate=1000000 Hz\nprobe1=RX\nunitsize=1\n")
        z.writestr("logic-1", data)
    info = sig.read_srzip_info(p)
    ce = sig.srzip_channel_edges(p, info, info.channel("RX"))
    assert list(ce.edges) == [10, 15] and info.samplerate == 1_000_000
    # 손상된 zip / 세션 파일 아님
    bad = tmp_path / "bad.sr"
    bad.write_bytes(b"PK\x03\x04garbage" + bytes(100))
    with pytest.raises(ValidationFailed):
        sig.read_srzip_info(bad)
    notsession = tmp_path / "x.sr"
    with zipfile.ZipFile(notsession, "w") as z:
        z.writestr("hello", "x")
    with pytest.raises(ValidationFailed):
        sig.read_srzip_info(notsession)
    # samplerate 없음 → 경고, 에지 분석 거부
    nosr = tmp_path / "nosr.sr"
    with zipfile.ZipFile(nosr, "w") as z:
        z.writestr("version", "2")
        z.writestr("metadata", "[device 1]\ncapturefile=logic-1\ntotal probes=1\nprobe1=RX\nunitsize=1\n")
        z.writestr("logic-1-1", data)
    info = sig.read_srzip_info(nosr)
    assert any("samplerate" in w for w in info.warnings)
    with pytest.raises(ValidationFailed):
        sig.srzip_channel_edges(nosr, info, info.channel("RX"))
    # 손상된 청크 데이터(CRC 오류)
    crc = tmp_path / "crc.sr"
    write_srzip(crc, data * 100, 1_000_000, ["RX"])
    raw = bytearray(crc.read_bytes())
    idx = raw.find(b"logic-1-1") + 40
    raw[idx:idx + 8] = b"\x00" * 8
    crc.write_bytes(bytes(raw))
    with pytest.raises(ValidationFailed):
        info = sig.read_srzip_info(crc)
        sig.srzip_channel_edges(crc, info, info.channel("RX"))


def test_srzip_max_edges_truncation(tmp_path):
    lane = bytes([i % 2 for i in range(10_000)])  # 매 샘플 에지
    data, _ = pack_lanes([lane])
    p = write_srzip(tmp_path / "dense.sr", data, 1_000_000, ["CLK"])
    info = sig.read_srzip_info(p)
    ce = sig.srzip_channel_edges(p, info, info.channel("CLK"), max_edges=100)
    assert ce.truncated and len(ce.edges) == 100 and ce.end_tick == ce.edges[-1] + 1
    assert any("상한" in w for w in ce.warnings)


# ---------------------------------------------------------------------------
# VCD
# ---------------------------------------------------------------------------


def test_vcd_styles_dumpvars_xz_and_garbage(tmp_path):
    w = uart_waveform(b"Hi\r\n", baud=115200, samplerate=1_000_000)
    std = write_vcd(tmp_path / "std.vcd", [("RX", w.initial_level, w.edges), ("TX", 1, [])],
                    timescale_s=Fraction(1, 10**6), end_tick=w.total_samples)
    sgk = write_vcd(tmp_path / "sgk.vcd", [("RX", w.initial_level, w.edges), ("TX", 1, [])],
                    timescale_s=Fraction(1, 10**6), end_tick=w.total_samples, style="sigrok",
                    comment="Acquisition with 2/2 channels at 1 MHz")
    for p in (std, sgk):
        info, edges = sig.read_vcd(p)
        assert [c.name for c in info.channels] == ["RX", "TX"]
        assert list(edges["RX"].edges) == w.edges and edges["RX"].initial_level == 1
        assert edges["TX"].initial_level == 1 and len(edges["TX"].edges) == 0
        assert info.tick_hz == 1e6 and info.end_tick == w.total_samples
    assert sig.read_vcd(sgk)[0].metadata.get("original_samplerate") == 1_000_000
    # 손으로 쓴 VCD: $dumpvars, x/z, 2글자 식별자, 값과 식별자 사이 공백, 아날로그 텍스트 쓰레기, 역순 타임스탬프
    text = """$date today $end
$version other tool $end
$timescale 10ns $end
$scope module top $end
$var wire 1 !a rx $end
$var reg 1 # en $end
$var wire 8 % bus [7:0] $end
$upscope $end
$enddefinitions $end
$dumpvars
x!a
1#
b00000000 %
$end
#0
#100 1!a
#200
0!a
A4: 1.34 V DC
#150
#300 1 !a
#400 z!a
$comment whatever 1!a $end
#500
"""
    hp = tmp_path / "hand.vcd"
    hp.write_text(text)
    info, edges = sig.read_vcd(hp)
    assert info.tick_hz == pytest.approx(1e8)
    assert [c.name for c in info.channels] == ["rx", "en"]  # 8비트 버스는 건너뜀
    rx = edges["rx"]
    assert rx.initial_level == 0 and list(rx.edges) == [100, 200, 300, 400]
    assert rx.unknown_values >= 2
    assert edges["en"].initial_level == 1
    assert any("역순" in w for w in info.warnings)
    assert any("해석 불가" in w for w in info.warnings)
    assert info.metadata["skipped_vars"][0]["name"] == "bus[7:0]"
    # 헤더 정보만 빠르게
    fast = sig.load_info(hp)
    assert fast.end_tick == 500 and fast.start_tick == 0
    # 헤더 없는 파일
    broken = tmp_path / "broken.vcd"
    broken.write_text("$timescale 1 us $end\n$var wire 1 ! a $end\n#0 1!\n")
    with pytest.raises(ValidationFailed):
        sig.read_vcd(broken)


def test_vcd_resolution_from_gcd(tmp_path):
    w = uart_waveform(BOOT_BANNER[:40], baud=115200, samplerate=2_000_000)
    write_uart_vcd(tmp_path / "ns.vcd", BOOT_BANNER[:40], baud=115200, samplerate=2_000_000, timescale=Fraction(1, 10**9))
    info, ce = sig.load_channel_edges(tmp_path / "ns.vcd", "RX")
    assert ce.tick_hz == 1e9
    assert ce.samplerate == pytest.approx(2e6)  # 에지 간격의 최대공약수(500 tick)로 실제 해상도 추정
    assert len(ce.edges) == len(w.edges)


# ---------------------------------------------------------------------------
# 보드레이트 추정
# ---------------------------------------------------------------------------

EST_CASES = [
    # (baud, samplerate, idle, kwargs)
    (9600, 100_000, 1, {}),
    (115200, 1_000_000, 1, {}),
    (115200, 2_000_000, 1, {"jitter_samples": 1}),
    (115200, 1_000_000, 0, {}),  # 반전 라인
    (57600, 1_000_000, 1, {"line_gap_s": 0.005}),  # 줄 사이 긴 idle
    (74880, 1_000_000, 1, {}),  # ESP8266 ROM
    (921600, 8_000_000, 1, {"glitches": 5}),
    (1_500_000, 12_000_000, 1, {}),
    (1_500_000, 24_000_000, 1, {"jitter_samples": 1}),
    (3_000_000, 24_000_000, 1, {}),
    (230400, 3_000_000, 0, {"jitter_samples": 1, "line_gap_s": 0.001}),
]


@pytest.mark.parametrize("fmt", ["sr", "vcd"])
@pytest.mark.parametrize("baud,rate,idle,kw", EST_CASES)
def test_estimator_accuracy(tmp_path, fmt, baud, rate, idle, kw):
    if fmt == "sr":
        p = tmp_path / "u.sr"
        write_uart_sr(p, BOOT_BANNER, baud=baud, samplerate=rate, idle_level=idle, **kw)
    else:
        p = tmp_path / "u.vcd"
        ts = Fraction(1, rate) if rate in (100_000, 1_000_000) else Fraction(1, 10**9)
        if Fraction(1, rate) / ts != int(Fraction(1, rate) / ts):
            ts = Fraction(1, 10**12)
        write_uart_vcd(p, BOOT_BANNER, baud=baud, samplerate=rate, idle_level=idle, timescale=ts, **kw)
    _info, ce = sig.load_channel_edges(p, "RX")
    r = baudmod.estimate_baud(ce)
    assert r["baudrate"] == baud, r
    assert r["standard"] is True
    assert r["idle_level"] == idle and r["inverted"] == (idle == 0)
    assert r["confidence"] >= 0.8, r
    assert r["frame_check"]["error_rate"] <= 0.02
    assert r["candidates"][0]["baudrate"] == baud
    if idle == 0:
        assert "invert_rx=yes" in r["suggested_decoder"]
        assert any("LOW" in w for w in r["warnings"])
    # 추정값으로 순수 Python 디코드 → 원문 복원
    dec = baudmod.uart_decode(ce, ce.tick_hz / r["baudrate"], r["idle_level"])
    got = dec.data_bytes()
    if kw.get("glitches"):
        assert sum(a == b for a, b in zip(got, BOOT_BANNER)) >= len(BOOT_BANNER) - 10
    else:
        assert got == BOOT_BANNER


def test_estimator_low_oversampling_warns(tmp_path):
    p = tmp_path / "low.sr"
    write_uart_sr(p, BOOT_BANNER, baud=1_500_000, samplerate=4_000_000)
    _i, ce = sig.load_channel_edges(p, "RX")
    r = baudmod.estimate_baud(ce)
    assert r["samples_per_bit"] < 4
    assert any("4배 미만" in w for w in r["warnings"]), r["warnings"]
    assert r["confidence"] <= 0.6
    assert r["baudrate"] == 1_500_000  # 2.67 샘플/비트에서도 정수배 정제로 맞춤 (경고는 유지)


def test_estimator_even_runs_payload_resolved_by_framing(tmp_path):
    """모든 run 이 2T 의 배수인 데이터(0x80,0x86,...,0xFE + 2비트 간격) — 펄스 폭만으로는 T/2 와 구분 불가, 프레임 검사로 해결.

    (간격 없이 붙여 보내면 같은 파형이 57600 8N1 로도 오류 없이 해석되는 진짜 모호성이라 판정 불가 → 간격을 둔다.)
    """
    payload = bytes([0x80, 0x86, 0x98, 0x9E, 0xE0, 0xE6, 0xF8, 0xFE]) * 30
    p = tmp_path / "even.sr"
    write_uart_sr(p, payload, baud=115200, samplerate=2_000_000, char_gap_bits=2)
    _i, ce = sig.load_channel_edges(p, "RX")
    rs = baudmod.complete_runs(ce)
    t_true = 2_000_000 / 115200
    assert all(round(w / t_true) % 2 == 0 for w in rs.widths if w < 12 * t_true)  # 전제 확인
    r = baudmod.estimate_baud(ce)
    assert r["baudrate"] == 115200, r
    dec = baudmod.uart_decode(ce, ce.tick_hz / 115200, 1)
    assert dec.data_bytes() == payload


def test_estimator_zero_ff_heavy_payload(tmp_path):
    payload = b"\x00\xff" * 60 + b"\x00" * 30 + b"\xff" * 30
    p = tmp_path / "zf.sr"
    write_uart_sr(p, payload, baud=38400, samplerate=1_000_000, char_gap_bits=0.5)
    _i, ce = sig.load_channel_edges(p, "RX")
    r = baudmod.estimate_baud(ce)
    assert r["baudrate"] == 38400, r
    assert baudmod.uart_decode(ce, ce.tick_hz / 38400, 1).data_bytes() == payload


def test_estimator_mixed_baud_segments(tmp_path):
    from sigrok_mcp.synth import uart_waveform as uw

    rate = 4_000_000
    a = uw(b"BootROM v1.0 hello\r\n" * 3, baud=57600, samplerate=rate, tail_idle_s=0.0)
    b = uw(b"U-Boot 2019.04 console\r\n" * 3, baud=115200, samplerate=rate, lead_idle_s=0.0)
    gap = int(0.02 * rate)
    edges = list(a.edges) + [e + a.total_samples + gap for e in b.edges]
    total = a.total_samples + gap + b.total_samples
    data, us = pack_lanes([lane_from_edges(1, edges, total)])
    p = write_srzip(tmp_path / "mixed.sr", data, rate, ["RX"])
    _i, ce = sig.load_channel_edges(p, "RX")
    r = baudmod.estimate_baud(ce)
    segs = r.get("segments") or []
    assert {s["baudrate"] for s in segs} == {57600, 115200}, segs
    assert any("구간별" in w for w in r["warnings"])


def test_estimator_too_few_edges_and_noise(tmp_path):
    data, _ = pack_lanes([bytes([1] * 1000 + [0] * 3 + [1] * 1000)])
    p = write_srzip(tmp_path / "idle.sr", data, 1_000_000, ["RX"])
    _i, ce = sig.load_channel_edges(p, "RX")
    r = baudmod.estimate_baud(ce)
    assert r["baudrate"] is None and r["confidence"] == 0.0
    assert any("에지" in w for w in r["warnings"])
    rng = random.Random(3)
    lane = bytearray()
    lvl = 1
    while len(lane) < 200_000:
        lane += bytes([lvl]) * int(rng.expovariate(1 / 37.0) + 1)
        lvl ^= 1
    data, _ = pack_lanes([bytes(lane[:200_000])])
    p2 = write_srzip(tmp_path / "noise.sr", data, 1_000_000, ["N"])
    _i, ce2 = sig.load_channel_edges(p2, "N")
    r2 = baudmod.estimate_baud(ce2)
    assert r2["confidence"] < 0.5, r2


def test_render_text_and_boot_hints():
    data = BOOT_BANNER + b"\x00\x1b[0m#"
    text = baudmod.render_text(data, 4096)
    assert "U-Boot 2016.11" in text and "\\x00" in text and "\r" not in text
    kinds = [h["kind"] for h in baudmod.boot_hints(data)]
    for k in ("uboot_banner", "autoboot_prompt", "kernel_start", "linux_version", "login_prompt"):
        assert k in kinds
    assert baudmod.render_text(b"a" * 100, 10).endswith("(90 bytes 더 있음)")


# ---------------------------------------------------------------------------
# 정책 / 검증기
# ---------------------------------------------------------------------------


def _argv(*a: str) -> list[str]:
    return ["/opt/sigrok-cli", *a]


def test_classifier_capture_policy(tmp_path):
    sigdir = tmp_path / "signals"
    sigdir.mkdir()
    out = f"--output-file={sigdir}/a.sr"
    ok = pol.classify_sigrok_argv(_argv("--driver=demo", "--dont-scan", "--config=samplerate=1000000", "--samples=10",
                                        "--output-format=srzip", out), allowed_output_dir=sigdir)
    assert ok.risk == Risk.OBSERVE and ok.rule_id == "sigrok.capture"
    serial = pol.classify_sigrok_argv(_argv("--driver=ols:conn=/dev/ttyACM0", "--samples=10", "--output-format=srzip", out),
                                      allowed_output_dir=sigdir)
    assert serial.risk == Risk.INTERACT
    usb = pol.classify_sigrok_argv(_argv("--driver=fx2lafw:conn=1.6", "--time=100", "--output-format=srzip", out), allowed_output_dir=sigdir)
    assert usb.risk == Risk.OBSERVE
    refused = {
        "psu": _argv("--driver=korad-kaxxxxp", "--samples=10", "--output-format=srzip", out),
        "psu_dir_alias": _argv("--driver=motech-lps-30x", "--samples=10", "--output-format=srzip", out),
        "eload": _argv("--driver=maynuo-m97", "--scan"),
        "relay": _argv("--driver=icstation-usbrelay", "--scan"),
        "siggen": _argv("--driver=rigol-dg", "--show"),
        "dmm_not_allowlisted": _argv("--driver=uni-t-ut61e", "--samples=10", "--output-format=srzip", out),
        "voltage_key": _argv("--driver=demo", "--config=voltage_target=5", "--samples=10", "--output-format=srzip", out),
        "pattern_key": _argv("--driver=demo", "--config=samplerate=1000:pattern=sigrok", "--samples=10", "--output-format=srzip", out),
        "unit_value": _argv("--driver=demo", "--config=samplerate=1m", "--samples=10", "--output-format=srzip", out),
        "set": _argv("--driver=demo", "--config=samplerate=1000", "--set"),
        "continuous": _argv("--driver=demo", "--continuous", "--output-format=srzip", out),
        "channel_group": _argv("--driver=demo", "--channel-group=Logic", "--samples=1", "--output-format=srzip", out),
        "no_driver_capture": _argv("--samples=10", "--output-format=srzip", out),
        "driver_opt": _argv("--driver=demo:logic_channels=16", "--samples=10", "--output-format=srzip", out),
        "conn_injection": _argv("--driver=fx2lafw:conn=1.6:samplerate=1", "--samples=10", "--output-format=srzip", out),
        "outside": _argv("--driver=demo", "--samples=10", "--output-format=srzip", "--output-file=/tmp/x.sr"),
        "no_file": _argv("--driver=demo", "--samples=10"),
        "short_opt": _argv("-d", "demo", "--samples=10"),
        "mixed": _argv("--driver=demo", "--samples=10", "--protocol-decoders=uart", "--output-format=srzip", out),
        "loglevel": _argv("--driver=demo", "--loglevel=5", "--scan"),
    }
    for name, argv in refused.items():
        c = pol.classify_sigrok_argv(argv, allowed_output_dir=sigdir)
        assert c.risk == Risk.DESTRUCTIVE, (name, c)
    assert pol.classify_sigrok_argv(refused["psu"]).rule_id == "sigrok.driver.output_capable"
    offline = pol.classify_sigrok_argv(_argv("--input-file=/x.sr", "--protocol-decoders=uart:rx=D0", "--protocol-decoder-samplenum"))
    assert offline.risk == Risk.OBSERVE and offline.rule_id == "sigrok.offline"
    assert pol.classify_sigrok_argv(_argv("--scan")).rule_id == "sigrok.scan.all"
    assert pol.classify_sigrok_argv(_argv("--version")).risk == Risk.OBSERVE
    # 설정 확장: allow 추가 가능, 출력 장치는 deny 가 이김
    ext = pol.DriverPolicy.from_config_raw({"sigrok": {"capture_drivers_allow": ["uni-t-ut61e", "scpi-pps"],
                                                       "capture_drivers_deny": ["ols"]}})
    assert pol.classify_sigrok_argv(refused["dmm_not_allowlisted"], policy=ext, allowed_output_dir=sigdir).risk == Risk.OBSERVE
    assert not ext.is_allowed("scpi-pps") and ext.deny_reason("scpi-pps")
    assert not ext.is_allowed("ols")
    # 모든 출력 가능 드라이버는 허용 목록과 겹치지 않는다
    assert not set(pol.OUTPUT_CAPABLE_DRIVERS) & set(pol.CAPTURE_ALLOWED_DRIVERS)


def test_validators():
    assert pol.parse_samplerate("1m") == 1_000_000
    assert pol.parse_samplerate("1.5m") == 1_500_000  # sigrok-cli 0.7.2 의 '1.5m'→1 Hz 버그 회피
    assert pol.parse_samplerate("24MHz") == 24_000_000
    assert pol.parse_samplerate("500 kHz") == 500_000
    assert pol.parse_samplerate(2_000_000) == 2_000_000
    for bad in ("abc", "0", "1.5", "-1m", "1mm", True, "99G"):
        with pytest.raises(ValidationFailed):
            pol.parse_samplerate(bad)
    sel = pol.validate_channels(["D0=RX", "D1"])
    assert sel.arg == "D0=RX,D1" and sel.final_names == ["RX", "D1"]
    assert not sel.warnings
    sel2 = pol.validate_channels("D0,D3")
    assert any("연속" in w for w in sel2.warnings)
    assert pol.validate_channels("0-3").final_names == ["0", "1", "2", "3"]
    for bad in (["D0", "D0"], ["D0=1bad"], ["D0;rm"], ["D0-D3"], ["a b"], [""]):
        with pytest.raises(ValidationFailed):
            pol.validate_channels(bad)
    assert pol.validate_triggers("RX=f", sel) == "RX=f"
    with pytest.raises(ValidationFailed):
        pol.validate_triggers("D0=f", sel)  # rename 후에는 새 이름만
    with pytest.raises(ValidationFailed):
        pol.validate_triggers("RX=x", sel)
    assert pol.validate_triggers({"RX": "r0"}, None) == "RX=r0"
    for bad in ("1.6:samplerate=1", "a,b", "x=y", "/dev/tty USB0", "a" * 200):
        with pytest.raises(ValidationFailed):
            pol.validate_conn(bad)
    assert pol.validate_conn("0925.3881") == "0925.3881" and pol.conn_kind("0925.3881") == "usb"
    assert pol.conn_kind("/dev/ttyACM0") == "serial" and pol.conn_kind("tcp-raw/10.0.0.2/5555") == "network"
    assert pol.validate_output_name("boot.sr") == "boot"
    for bad in ("../x", "a/b", ".hidden", "x" * 100):
        with pytest.raises(ValidationFailed):
            pol.validate_output_name(bad)
    assert pol.validate_samples("2m") == 2_000_000
    with pytest.raises(ValidationFailed):
        pol.validate_duration_ms(0)
    with pytest.raises(ValidationFailed):
        pol.validate_capture_ratio(101)
    with pytest.raises(ValidationFailed):
        pol.validate_driver("demo:conn=1")


# ---------------------------------------------------------------------------
# sigrok-cli 출력 파서
# ---------------------------------------------------------------------------

VERSION_TEXT = (Path(__file__).parent / "sigrok_fake_cli.py").read_text(encoding="utf-8").split('VERSION = """', 1)[1].split('"""', 1)[0]


def test_parsers():
    v = clim.parse_version(VERSION_TEXT)
    assert v["sigrok_cli"] == "0.7.2" and v["libsigrok"]["version"] == "0.5.2"
    assert v["libsigrokdecode"]["version"] == "0.5.3" and v["python"] == "3.10.2"
    assert v["scpi_backends"] == ["TCP", "serial", "USBTMC"]
    sup = clim.parse_supported("Supported hardware drivers:\n  arachnid-labs-re-load-pro Arachnid Labs Re:load Pro\n"
                               "  demo                 Demo driver and pattern generator\n\nSupported protocol decoders:\n"
                               "  uart                 Universal Asynchronous Receiver/Transmitter\n"
                               "                       Asynchronous, serial bus.\n")
    assert [d["id"] for d in sup["drivers"]] == ["arachnid-labs-re-load-pro", "demo"]
    assert sup["drivers"][0]["description"] == "Arachnid Labs Re:load Pro"
    assert [d["id"] for d in sup["decoders"]] == ["uart"]
    devs = clim.parse_scan("The following devices were found:\n"
                           "demo - Demo device with 13 channels: D0 D1 D2 D3 D4 D5 D6 D7 A0 A1 A2 A3 A4\n"
                           "fx2lafw:conn=1.6 - Saleae Logic [S/N: 1234] with 8 channels: D0 D1 D2 D3 D4 D5 D6 D7\n"
                           "uni-t-ut61e:conn=hid/ch9325 - UNI-T UT61E with 1 channel: P1\n"
                           "odd - Weird device \n")
    assert devs[0]["driver"] == "demo" and devs[0]["channel_count"] == 13 and devs[0]["conn"] is None
    assert devs[1]["conn"] == "1.6" and devs[1]["serial_number"] == "1234" and devs[1]["description"] == "Saleae Logic"
    assert devs[2]["channels"] == ["P1"] and devs[2]["conn"] == "hid/ch9325"
    assert devs[3]["driver"] == "odd" and devs[3]["channels"] == []
    from servers.sigrok_fake_cli import DEMO_SHOW, FX2_SHOW, UART_SHOW

    pd = clim.parse_decoder_show(UART_SHOW)[0]
    assert pd["id"] == "uart" and pd["longname"].startswith("Universal")
    assert [c["id"] for c in pd["optional_channels"]] == ["rx", "tx"] and pd["required_channels"] == []
    opts = {o["id"]: o for o in pd["options"]}
    assert opts["baudrate"]["default"] == 115200 and opts["baudrate"]["values"] == []
    assert opts["parity"]["values"][:2] == ["none", "odd"] and opts["parity"]["default"] == "none"
    assert opts["rx_packet_delim"]["description"] == "RX packet delimiter (decimal)" and opts["rx_packet_delim"]["default"] == -1
    assert opts["data_bits"]["values"] == [5, 6, 7, 8, 9]
    assert pd["annotation_rows"][0] == {"id": "rx-data", "description": "RX", "classes": ["rx-data"]}
    assert pd["documentation"] == "UART fake doc."
    demo = clim.parse_device_show(DEMO_SHOW)
    assert demo["driver_functions"] == ["Demo device", "Logic analyzer", "Oscilloscope"]
    assert demo["samplerate_range"]["max"] == "1 GHz" and demo["triggers"] == ["0", "1", "r", "f", "e"]
    assert demo["device"]["driver"] == "demo" and demo["channel_groups"][0]["name"] == "Logic"
    fx2 = clim.parse_device_show(FX2_SHOW)
    assert fx2["samplerates"] == ["20 kHz", "1 MHz", "24 MHz"] and fx2["current"]["samplerate"] == "1 MHz"
    assert fx2["device"]["conn"] == "1.6"
    props = clim.parse_input_props("Samplerate: 1000000\nChannels: 2\n- D0: logic\n- A0: analog\nLogic unitsize: 1\nLogic sample count: 8608\n")
    assert props["samplerate"] == 1_000_000 and props["logic_samples"] == 8608 and props["channels"][1]["type"] == "analog"
    a = clim.parse_annotation_line("509-579 uart-1:  \n")
    assert a == {"ss": 509, "es": 579, "inst": "uart-1", "text": " "}  # 공백 바이트 보존
    assert clim.parse_annotation_line("40-180 i2c-1: Address write: 50")["text"] == "Address write: 50"
    assert clim.parse_annotation_line("uart-1: U")["ss"] is None
    rep = clim.stderr_problems('cli: No channel with name "D7" found.\nDevice only sent 15 samples.\n')
    assert rep.fatal and rep.errors[0]["code"] == "no_channel" and rep.warnings[0]["code"] == "short_capture"
    assert clim.stderr_problems("sr: bt-bluez: devid failed\n").fatal is False


def test_run_process_timeout_cancel_and_output_limit(tmp_path):
    """프로세스 그룹 종료(타임아웃/취소), 출력 상한, 자식 프로세스까지 정리되는지 (sh 로 손자 프로세스 생성)."""
    import sys
    import time as _t

    from sigrok_mcp.cli import live_process_count, run_process
    from servers.sigrok_testutil import pid_alive

    pidf = tmp_path / "child.pid"
    script = f"import os,subprocess,time; p=subprocess.Popen(['sleep','60']); open({str(pidf)!r},'w').write(str(p.pid)); time.sleep(60)"
    t0 = _t.monotonic()
    res = run_process([sys.executable, "-c", script], timeout=1.0)
    assert res.timed_out and _t.monotonic() - t0 < 10
    grandchild = int(pidf.read_text())
    for _ in range(50):
        if not pid_alive(grandchild):
            break
        _t.sleep(0.05)
    assert not pid_alive(grandchild), "타임아웃 시 손자 프로세스까지 종료되어야 함"
    flag = {"n": 0}

    def cancel() -> bool:
        flag["n"] += 1
        return flag["n"] > 3

    res = run_process([sys.executable, "-c", "import time; time.sleep(60)"], timeout=30, cancel=cancel)
    assert res.cancelled and not res.timed_out
    res = run_process([sys.executable, "-c", "import sys; sys.stdout.write('x' * 5_000_000); sys.stdout.flush(); import time; time.sleep(30)"],
                      timeout=30, stdout_limit=1000)
    assert res.output_limit_hit and len(res.stdout) == 1000
    res = run_process([sys.executable, "-c", "import sys; sys.stderr.write('e' * 300000); print('ok')"], timeout=30, stderr_limit=1000)
    assert res.returncode == 0 and res.stdout_text.strip() == "ok" and "생략" in res.stderr and res.stderr_bytes == 300000
    assert live_process_count() == 0
