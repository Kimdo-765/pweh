"""합성 UART 파형 생성 (테스트/자가 점검용).

이상적인 비트 경계 시각을 샘플 격자에 맞춰(경계 이후 첫 샘플) 에지 목록으로 만든다.
선택적으로 ±지터, 1샘플 글리치, 줄 사이 idle 간격, 반전(idle-low) 라인을 넣을 수 있다.
"""

from __future__ import annotations

import math
import random
from dataclasses import dataclass, field
from typing import Iterable, Sequence


def uart_frame_bits(byte: int, *, data_bits: int = 8, parity: str = "none", stop_bits: int = 1) -> list[int]:
    """논리 비트열(1=mark/idle): start(0) + data(LSB first) + [parity] + stop(1)*n."""
    bits = [0]
    data = [(byte >> i) & 1 for i in range(data_bits)]
    bits += data
    ones = sum(data)
    if parity == "even":
        bits.append(ones & 1)
    elif parity == "odd":
        bits.append((ones & 1) ^ 1)
    elif parity == "mark":
        bits.append(1)
    elif parity == "space":
        bits.append(0)
    elif parity != "none":
        raise ValueError(f"알 수 없는 parity: {parity}")
    bits += [1] * stop_bits
    return bits


@dataclass
class Waveform:
    initial_level: int
    edges: list[int]
    total_samples: int
    samplerate: int
    baud: float
    idle_level: int
    meta: dict = field(default_factory=dict)


def uart_waveform(
    payload: bytes,
    *,
    baud: float,
    samplerate: int,
    idle_level: int = 1,
    data_bits: int = 8,
    parity: str = "none",
    stop_bits: int = 1,
    lead_idle_s: float = 0.0005,
    tail_idle_s: float = 0.0005,
    char_gap_bits: float = 0.0,
    line_gap_s: float = 0.0,
    jitter_samples: int = 0,
    glitches: int = 0,
    seed: int = 1,
) -> Waveform:
    """payload 를 UART 로 보낸 파형. line_gap_s 는 '\\n' 뒤에 넣는 추가 idle."""
    rng = random.Random(seed)
    bit_t = 1.0 / baud
    # (시작 시각, 길이, 논리값) 구간 목록을 만든 뒤 레벨 변화만 에지로
    t = lead_idle_s
    segments: list[tuple[float, int]] = []  # (경계 시각, 이 시각부터의 논리값)
    for b in payload:
        for bit in uart_frame_bits(b, data_bits=data_bits, parity=parity, stop_bits=stop_bits):
            segments.append((t, bit))
            t += bit_t
        if char_gap_bits:
            t += char_gap_bits * bit_t
        if b == 0x0A and line_gap_s:
            t += line_gap_s
    end_t = t + tail_idle_s
    total = int(math.ceil(end_t * samplerate))

    def level_of(logic: int) -> int:
        return logic if idle_level == 1 else 1 - logic

    edges: list[int] = []
    cur = 1  # idle(mark) 논리값
    for ts, logic in segments:
        if logic != cur:
            s = int(math.ceil(ts * samplerate - 1e-9))
            if edges and s <= edges[-1]:
                s = edges[-1] + 1
            edges.append(s)
            cur = logic
    if cur != 1:  # 마지막은 항상 stop(=idle) 이므로 오지 않음
        edges.append(int(math.ceil(end_t * samplerate)))
    if jitter_samples:
        jittered = []
        for i, e in enumerate(edges):
            lo = (jittered[-1] + 1) if jittered else 1
            hi = (edges[i + 1] - 1) if i + 1 < len(edges) else total - 1
            j = e + rng.randint(-jitter_samples, jitter_samples)
            jittered.append(min(max(j, lo), max(lo, hi)))
        edges = jittered
    if glitches:
        edges = add_glitches(edges, total, glitches, rng=rng, min_run=int(samplerate * bit_t * 12))
    init = level_of(1)
    return Waveform(init, edges, total, samplerate, baud, idle_level,
                    meta={"payload_len": len(payload), "frame_bits": 1 + data_bits + (0 if parity == "none" else 1) + stop_bits})


def add_glitches(edges: Sequence[int], total: int, count: int, *, rng: random.Random, min_run: int) -> list[int]:
    """긴 run(>= min_run 샘플) 한가운데에 1샘플 펄스를 넣는다."""
    out = list(edges)
    bounds = [0] + out + [total]
    runs = [(bounds[i], bounds[i + 1]) for i in range(len(bounds) - 1) if bounds[i + 1] - bounds[i] >= max(min_run, 8)]
    rng.shuffle(runs)
    added = []
    for a, b in runs[:count]:
        m = (a + b) // 2
        added += [m, m + 1]
    return sorted(set(out + added))


def combine_waveforms(waves: Iterable[Waveform]) -> int:
    """여러 파형을 한 캡처에 넣을 때의 공통 샘플 수."""
    return max(w.total_samples for w in waves)


BOOT_BANNER = (
    b"\r\nU-Boot 2016.11 (Jan 01 2020 - 00:00:00 +0000)\r\n\r\n"
    b"DRAM:  64 MiB\r\nHit any key to stop autoboot:  1 \r\n"
    b"Starting kernel ...\r\n\r\nLinux version 4.9.37 (pweh@lab) #1 SMP\r\n"
    b"Please press Enter to activate this console.\r\nlogin: "
)


__all__ = ["BOOT_BANNER", "Waveform", "add_glitches", "combine_waveforms", "uart_frame_bits", "uart_waveform"]
