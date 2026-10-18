"""가짜 sigrok-cli (테스트 전용). sigrok_testutil.make_fake_sigrok() 가 venv python shebang 을 붙여 실행 파일로 만든다.

환경변수:
  FAKE_SIGROK_LOG      호출마다 {"argv": [...], "pid": n} 한 줄(JSON)을 추가할 파일
  FAKE_SIGROK_MODE     normal | hang | nodevice | nochannel | traceback | garbage | slow | fail
  FAKE_SIGROK_PIDFILE  hang/slow 모드에서 자기 PID 를 쓸 파일
  FAKE_SIGROK_SLEEP    slow 모드에서 캡처 전 대기 초 (기본 1)
출력 형식은 sigrok-cli 0.7.2 실측(docs/references/sigrok-cli.md)을 따른다.
"""

import json
import os
import sys
import time
from pathlib import Path

VERSION = """sigrok-cli 0.7.2

Libraries and features:
- libsigrok 0.5.2/5:1:1 (rt: 0.5.2/5:1:1).
 - Libs:
  - glib 2.67.5 (rt: 2.72.4/7204:4)
  - libzip 1.7.3
  - libserialport 0.1.1/1:0:1 (rt: 0.1.1/1:0:1)
  - libusb-1.0 1.0.25.11696 API 0x01000108
  - Host: x86_64-pc-linux-gnu, little-endian.
  - SCPI backends: TCP, serial, USBTMC.
- libsigrokdecode 0.5.3/6:1:2 (rt: 0.5.3/6:1:2).
 - Libs:
  - glib 2.71.1 (rt: 2.72.4/7204:4)
  - Python 3.10.2 / 0x30a02f0 (API 1013, ABI 3)
  - Host: x86_64-pc-linux-gnu, little-endian.
"""

LIST = """Supported hardware drivers:
  arachnid-labs-re-load-pro Arachnid Labs Re:load Pro
  demo                 Demo driver and pattern generator
  fx2lafw              fx2lafw (generic driver for FX2 based LAs)
  korad-kaxxxxp        Korad KAxxxxP
  ols                  Openbench Logic Sniffer & SUMP compatibles
  scpi-pps             SCPI PPS
  uni-t-ut61e          UNI-T UT61E

Supported input formats:
  binary               Raw binary logic data
  csv                  Comma-separated values
  vcd                  Value Change Dump data

Supported output formats:
  bits                 0/1 digits logic data
  csv                  Comma-separated values
  null                 Null output (discards all data)
  srzip                srzip session file format data
  vcd                  Value Change Dump data

Supported transform modules:
  nop                  Do nothing

Supported protocol decoders:
  i2c                  Inter-Integrated Circuit
  spi                  Serial Peripheral Interface
  uart                 Universal Asynchronous Receiver/Transmitter

"""

UART_SHOW = """ID: uart
Name: UART
Long name: Universal Asynchronous Receiver/Transmitter
Description: Asynchronous, serial bus.
License: gplv2+
Possible decoder input IDs:
- logic
Possible decoder output IDs:
- uart
Decoder tags:
Annotation classes:
- rx-data: RX data
- tx-data: TX data
- rx-warnings: RX warnings
Annotation rows:
- rx-data (RX): rx-data
- rx-warnings (RX warnings): rx-warnings
Binary classes:
- rx: RX dump
Required channels:
None.
Optional channels:
- rx (RX): UART receive line
- tx (TX): UART transmit line
Options:
- baudrate: Baud rate (default 115200)
- data_bits: Data bits (5, 6, 7, 8, 9, default 8)
- parity: Parity ('none', 'odd', 'even', 'zero', 'one', 'ignore', default 'none')
- format: Data format ('ascii', 'dec', 'hex', 'oct', 'bin', default 'hex')
- invert_rx: Invert RX ('yes', 'no', default 'no')
- rx_packet_delim: RX packet delimiter (decimal) (default -1)
Documentation:
UART fake doc.
"""

SPI_SHOW = """ID: spi
Name: SPI
Long name: Serial Peripheral Interface
Description: Full-duplex, synchronous, serial bus.
License: gplv2+
Possible decoder input IDs:
- logic
Possible decoder output IDs:
- spi
Decoder tags:
Annotation classes:
- miso-data: MISO data
- mosi-data: MOSI data
Annotation rows:
- miso-data (MISO data): miso-data
- mosi-data (MOSI data): mosi-data
Binary classes:
- miso: MISO
- mosi: MOSI
Required channels:
- clk (CLK): Clock
Optional channels:
- miso (MISO): Master in, slave out
- mosi (MOSI): Master out, slave in
- cs (CS#): Chip-select
Options:
- cpol: Clock polarity (0, 1, default 0)
- cpha: Clock phase (0, 1, default 0)
Documentation:
SPI fake doc.
"""

DEMO_SHOW = """Driver functions:
    Demo device
    Logic analyzer
    Oscilloscope
Scan options:
    logic_channels
    analog_channels
    limit_frames
demo - Demo device with 13 channels: D0 D1 D2 D3 D4 D5 D6 D7 A0 A1 A2 A3 A4
Channel groups:
    Logic: channels D0 D1 D2 D3 D4 D5 D6 D7
    Analog: channels A0 A1 A2 A3 A4
Supported configuration options across all channel groups:
    continuous: on, off
    limit_samples: 0 (current)
    limit_time: 0 (current)
    samplerate (1 Hz - 1 GHz in steps of 1 Hz)
    Supported triggers: 0 1 r f e
    captureratio: 20 (current)
"""

FX2_SHOW = """Driver functions:
    Logic analyzer
Scan options:
    conn
fx2lafw:conn=1.6 - Saleae Logic with 8 channels: D0 D1 D2 D3 D4 D5 D6 D7
Supported configuration options:
    continuous: on, off
    limit_samples: 0 (current)
    conn: 1.6 (current)
    samplerate - supported samplerates:
      20 kHz
      1 MHz (current)
      24 MHz
    Supported triggers: 0 1 r f e
    captureratio: 0 (current)
"""


def main() -> int:
    args = sys.argv[1:]
    log = os.environ.get("FAKE_SIGROK_LOG")
    mode = os.environ.get("FAKE_SIGROK_MODE", "normal")
    if log:
        with open(log, "a", encoding="utf-8") as fh:
            fh.write(json.dumps({"argv": args, "pid": os.getpid(), "mode": mode}) + "\n")
    opts = {}
    flags = set()
    multi = {}
    for a in args:
        if not a.startswith("--"):
            sys.stderr.write(f'superfluous command line argument "{a}"\n')
            return 1
        body = a[2:]
        if "=" in body:
            k, _, v = body.partition("=")
            opts[k] = v
            multi.setdefault(k, []).append(v)
        else:
            flags.add(body)
    pidfile = os.environ.get("FAKE_SIGROK_PIDFILE")
    if mode == "garbage":
        sys.stdout.buffer.write(os.urandom(3000) + b"\n\xff\xfe garbage \x00\x01\n")
        sys.stderr.buffer.write(b"\xff\xfe\x00 weird stderr \x80\n")
        return 0
    if "version" in flags:
        sys.stdout.write(VERSION)
        return 0
    if "list-supported" in flags:
        sys.stdout.write(LIST)
        return 0
    if "show" in flags and "protocol-decoders" in opts:
        pd = opts["protocol-decoders"].split(":")[0].split(",")[0]
        if pd == "uart":
            sys.stdout.write(UART_SHOW)
            return 0
        if pd == "spi":
            sys.stdout.write(SPI_SHOW)
            return 0
        sys.stderr.write(f"srd: ModuleNotFoundError: Failed to load decoder {pd}: import by name failed: No module named '{pd}'\n")
        sys.stderr.write(f"Failed to load protocol decoder {pd}.\n")
        return 1
    drv = opts.get("driver", "")
    drv_name = drv.split(":")[0]
    if mode == "nodevice" and (drv or "scan" in flags):
        if "scan" in flags:
            return 0
        if "show" in flags:
            sys.stdout.write("Driver functions:\n    Logic analyzer\nScan options:\n    conn\n")
        sys.stderr.write("No devices found.\n")
        return 1
    if "scan" in flags:
        sys.stdout.write("The following devices were found:\n")
        if drv_name in ("", "demo"):
            sys.stdout.write("demo - Demo device with 13 channels: D0 D1 D2 D3 D4 D5 D6 D7 A0 A1 A2 A3 A4\n")
        if drv_name in ("", "fx2lafw"):
            sys.stdout.write("fx2lafw:conn=1.6 - Saleae Logic [S/N: 1234] with 8 channels: D0 D1 D2 D3 D4 D5 D6 D7\n")
        if drv_name == "ols":
            conn = drv.partition(":conn=")[2]
            sys.stdout.write(f"ols:conn={conn} - Openbench Logic Sniffer v1.01 with 32 channels: " + " ".join(str(i) for i in range(32)) + "\n")
        return 0
    if "show" in flags and drv:
        sys.stdout.write(DEMO_SHOW if drv_name == "demo" else FX2_SHOW)
        return 0
    if "show" in flags and "input-file" in opts:
        from sigrok_mcp import signals as sig

        info = sig.load_info(opts["input-file"])
        sys.stdout.write(f"Samplerate: {int(info.samplerate)}\nChannels: {len(info.channels)}\n")
        for c in info.channels:
            sys.stdout.write(f"- {c.name}: logic\n")
        sys.stdout.write(f"Logic unitsize: {info.unitsize or 1}\nLogic sample count: {info.total_samples}\n")
        return 0
    if drv and ("samples" in opts or "time" in opts):
        return capture(opts, multi, mode, pidfile)
    if "input-file" in opts and "protocol-decoders" in opts:
        return decode(opts, multi, mode)
    if "input-file" in opts and "output-format" in opts:
        return export(opts)
    sys.stderr.write("fake sigrok-cli: unsupported invocation\n")
    return 2


def _hold(pidfile, seconds):
    if pidfile:
        Path(pidfile).write_text(str(os.getpid()))
    time.sleep(seconds)


def capture(opts, multi, mode, pidfile) -> int:
    if mode == "hang":
        _hold(pidfile, 3600)
        return 0
    if mode == "fail":
        sys.stderr.write("Failed to set device option 'samplerate': not applicable.\n")
        return 1
    if mode == "slow":
        _hold(pidfile, float(os.environ.get("FAKE_SIGROK_SLEEP", "1")))
    from sigrok_mcp.synth import uart_waveform
    from sigrok_mcp.writers import lane_from_edges, pack_lanes, write_srzip

    rate = 1000000
    for c in multi.get("config", []):
        k, _, v = c.partition("=")
        if k == "samplerate":
            rate = int(v)
    n = int(opts["samples"]) if "samples" in opts else rate * int(opts["time"]) // 1000
    names = []
    if "channels" in opts:
        for tok in opts["channels"].split(","):
            src, _, new = tok.partition("=")
            names.append(new or src)
    else:
        names = [f"D{i}" for i in range(8)]
    w = uart_waveform(b"fake capture U-Boot\r\n" * 4, baud=max(rate / 10.0, 1.0), samplerate=rate, lead_idle_s=20 / rate)
    lane0 = lane_from_edges(w.initial_level, [e for e in w.edges if e < n], n)
    lanes = [lane0] + [b"\x01" * n for _ in names[1:]]
    data, us = pack_lanes(lanes)
    write_srzip(opts["output-file"], data, rate, names, unitsize=us)
    return 0


def decode(opts, multi, mode) -> int:
    from sigrok_mcp import baud, signals as sig

    if mode == "traceback":
        sys.stderr.write("srd: SamplerateError: Protocol decoder instance uart-1: : Cannot decode without samplerate.\n")
        sys.stderr.write("Traceback (most recent call last):\n  File x\n")
        return 0
    stacks = multi.get("protocol-decoders", [])
    samplenum = "--protocol-decoder-samplenum" in sys.argv[1:]
    inst_n = 0
    for st in stacks:
        first = st.split(",")[0]
        parts = first.split(":")
        pd = parts[0]
        kv = dict(p.split("=", 1) for p in parts[1:])
        inst_n += 1
        inst = f"{pd}-{inst_n}"
        if mode == "nochannel":
            sys.stderr.write(f'cli: No channel with name "{kv.get("rx", "?")}" found.\n')
            sys.stdout.write(f"{inst}: 55\n")
            continue
        if pd != "uart":
            sys.stdout.write(f"{inst}: fake\n")
            continue
        info, ce = sig.load_channel_edges(opts["input-file"], kv.get("rx", 0))
        b = int(kv.get("baudrate", "115200"))
        idle = 0 if kv.get("invert_rx") == "yes" else 1
        dec = baud.uart_decode(ce, ce.tick_hz / b, idle, data_bits=int(kv.get("data_bits", "8")))
        tps = ce.ticks_per_sample
        for start, val, ok in zip(dec.frame_starts, dec.values, dec.frame_ok):
            ss = int((start - ce.start_tick) / tps)
            es = ss + int(10 * (ce.tick_hz / b) / tps)
            pre = f"{ss}-{es} " if samplenum else ""
            sys.stdout.write(f"{pre}{inst}: {val:02X}\n")
            if not ok:
                sys.stdout.write(f"{pre}{inst}: Frame error\n")
    return 0


def export(opts) -> int:
    from fractions import Fraction

    from sigrok_mcp import signals as sig
    from sigrok_mcp.writers import lane_from_edges, pack_lanes, write_srzip, write_vcd

    src = opts["input-file"]
    info = sig.load_info(src)
    fmt = opts["output-format"].split(":")[0]
    chans = [c.name for c in info.channels]
    if "channels" in opts:
        chans = opts["channels"].split(",")
    edges = {}
    for name in chans:
        _i, ce = sig.load_channel_edges(src, name)
        edges[name] = ce
    end = max(ce.end_tick for ce in edges.values())
    if fmt == "vcd":
        write_vcd(opts["output-file"], [(n, e.initial_level, list(e.edges)) for n, e in edges.items()],
                  timescale_s=Fraction(1, int(info.samplerate)) if int(info.samplerate) in (1, 10, 100, 1000, 10**6, 10**5, 10**4) else Fraction(1, 10**9),
                  end_tick=end, style="sigrok")
        return 0
    if fmt == "srzip":
        lanes = [lane_from_edges(e.initial_level, [x - e.start_tick for x in e.edges], end - e.start_tick) for e in edges.values()]
        data, us = pack_lanes(lanes)
        write_srzip(opts["output-file"], data, int(info.samplerate), list(edges), unitsize=us)
        return 0
    Path(opts["output-file"]).write_text("fake export\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
