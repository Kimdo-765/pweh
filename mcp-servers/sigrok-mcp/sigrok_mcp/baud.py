"""오프라인 UART 보드레이트 추정기와 순수 Python UART 프레임 디코더.

원리 (docs/references/sigrok-cli.md 12장):
  UART 신호의 모든 펄스 폭(같은 레벨이 이어지는 구간)은 비트 시간 T 의 정수배다 (프레임 안은 1..~10T,
  idle 은 그 이상). 1T 펄스는 거의 항상 존재한다 (start bit 뒤 LSB=1 이면 start bit 자체가 1T).

알고리즘:
  1. 완전한 run(첫/마지막 잘린 run 제외)의 폭 분포를 만든다 (같은 폭은 묶어서 계산).
  2. 1샘플 이하 run 은 글리치로 제외(전체의 20% 를 넘으면 신호가 너무 빠른 것으로 보고 유지).
  3. 짧은 쪽 10%(최소 3개)의 중앙값을 초기 T 로, ``k = round(w/T)`` (1≤k≤12) 이고 ``|w-kT| ≤ 0.3T`` 인
     run 으로 ``T = Σw/Σk`` 를 반복 정제한다 (긴 run 일수록 가중 → 양자화 오차 평균화).
  4. 모든 k 가 2(또는 3)의 배수면 T 를 2(3)배로, T/2 가 훨씬 더 많이 설명하면 T/2 로 보정.
  5. 표준 보드레이트 목록에 ±3% 이내면 스냅.
  6. **프레임 검사**: 추정 보드레이트와 그 2배를, 두 idle 극성으로 8N1 디코드해서 프레임 오류율이 가장
     낮은 조합을 고른다 (T 와 T/2 모호성, 반전(idle-low) 라인 판정). 오류율은 신뢰도에 반영한다.
  7. samplerate < 4×baud 이면 결과가 맞아도 경고한다.
"""

from __future__ import annotations

import re
from collections import Counter
from dataclasses import dataclass, field
from typing import Any, Sequence

from .signals import ChannelEdges

#: Linux termios 표준 보드레이트(300..3000000) + 흔한 비표준(14400, 28800, 74880=ESP8266 ROM, 250000).
#: 서로 6% 이상 떨어진 값만 둔다 (스냅 허용오차 3% 와 충돌하지 않게).
STANDARD_BAUDS: tuple[int, ...] = (
    300, 600, 1200, 1800, 2400, 4800, 9600, 14400, 19200, 28800, 38400, 57600, 74880, 115200,
    230400, 250000, 460800, 500000, 576000, 921600, 1000000, 1152000, 1500000, 2000000, 2500000, 3000000,
)
SNAP_TOL = 0.03
KMAX = 12
FIT_TOL = 0.3
MIN_OVERSAMPLE = 4.0


# ---------------------------------------------------------------------------
# run 추출
# ---------------------------------------------------------------------------

@dataclass
class RunSet:
    levels: list[int]  # 완전한 run 의 레벨
    widths: list[int]  # tick
    starts: list[int]
    first_level: int
    first_width: int  # 잘린 첫 run
    last_level: int
    last_width: int  # 잘린 마지막 run


def complete_runs(ce: ChannelEdges, max_runs: int = 400_000) -> RunSet:
    e = ce.edges
    n = len(e)
    init = ce.initial_level
    levels: list[int] = []
    widths: list[int] = []
    starts: list[int] = []
    lim = min(n - 1, max_runs)
    for i in range(lim):
        a, b = e[i], e[i + 1]
        levels.append(init ^ ((i + 1) & 1))
        widths.append(b - a)
        starts.append(a)
    first_w = (e[0] - ce.start_tick) if n else (ce.end_tick - ce.start_tick)
    last_level = init ^ (n & 1)
    last_w = (ce.end_tick - e[-1]) if n else 0
    return RunSet(levels, widths, starts, init, int(first_w), last_level, int(last_w))


def _refine(hist: Sequence[tuple[int, int]], t0: float, iters: int = 8, sample_ticks: float = 1.0) -> tuple[float, int, int] | None:
    """hist: (폭, 개수). → (T, 맞은 run 수, 프레임 내 후보 run 수).

    허용오차는 max(0.3T, 1샘플): 에지마다 최대 1샘플 양자화 오차가 생기므로 오버샘플링이 낮을 때도 1T run 을 놓치지 않게.
    """
    t = t0
    fit = cand = 0
    for _ in range(iters):
        sr = sk = 0.0
        fit = cand = 0
        tol = max(FIT_TOL * t, sample_ticks)
        for w, c in hist:
            k = int(w / t + 0.5)
            if 1 <= k <= KMAX:
                cand += c
                if abs(w - k * t) <= tol:
                    sr += w * c
                    sk += k * c
                    fit += c
        if sk == 0:
            return None
        t_new = sr / sk
        if abs(t_new - t) <= 1e-12 * t:
            t = t_new
            break
        t = t_new
    return t, fit, cand


def _k_stats(hist: Sequence[tuple[int, int]], t: float, sample_ticks: float = 1.0) -> tuple[float, float]:
    """T 기준 k 가 2의 배수가 아닌 비율, 3의 배수가 아닌 비율."""
    odd = not3 = tot = 0
    tol = max(FIT_TOL * t, sample_ticks)
    for w, c in hist:
        k = int(w / t + 0.5)
        if 1 <= k <= KMAX and abs(w - k * t) <= tol:
            tot += c
            if k % 2:
                odd += c
            if k % 3:
                not3 += c
    if not tot:
        return 1.0, 1.0
    return odd / tot, not3 / tot


def _explained(widths: Sequence[int], t: float, sample_ticks: float) -> float:
    """프레임 안 run(k<=KMAX) 중 T 의 정수배(허용오차 max(0.3T, 1샘플))로 설명되는 비율."""
    fit = cand = 0
    tol = max(FIT_TOL * t, sample_ticks)
    for w in widths:
        if w <= sample_ticks + 1e-9:
            continue
        k = int(w / t + 0.5)
        if 1 <= k <= KMAX:
            cand += 1
            if abs(w - k * t) <= tol:
                fit += 1
    return fit / cand if cand else 0.0


def estimate_bit_ticks(widths: Sequence[int], *, sample_ticks: float = 1.0) -> dict[str, Any]:
    """완전한 run 폭 목록(tick)에서 비트 시간(tick) 추정. 실패 시 bit_ticks=None.

    sample_ticks: 1 샘플의 tick 수 (srzip=1, VCD=tick_hz/samplerate). 1 샘플 이하 run 은 글리치로 본다.
    """
    res: dict[str, Any] = {"bit_ticks": None, "explained": 0.0, "glitches": 0, "runs_used": 0, "warnings": []}
    if not widths:
        return res
    cnt = Counter(widths)
    glitch_lim = sample_ticks * 1.0 + 1e-9
    glitch_n = sum(c for w, c in cnt.items() if w <= glitch_lim)
    if glitch_n and glitch_n <= 0.2 * len(widths):
        for w in [w for w in cnt if w <= glitch_lim]:
            del cnt[w]
        res["glitches"] = glitch_n
    hist = sorted(cnt.items())
    total = sum(c for _, c in hist)
    res["runs_used"] = total
    if total == 0:
        return res
    # 초기 T: 최소 "안정" 폭(개수 >= max(3, 1%))에서 시작하는 첫 클러스터 [w, 1.5w + 1샘플] 의 가중 평균
    need = max(3, int(total * 0.01))
    w_min = next((w for w, c in hist if c >= need), hist[0][0])
    hi = 1.5 * w_min + sample_ticks
    cl = [(w, c) for w, c in hist if w_min <= w <= hi]
    if cl:
        t0 = sum(w * c for w, c in cl) / sum(c for _, c in cl)
    else:  # 짧은 쪽 10% 의 중앙값 (참조 구현 방식)
        k = min(max(3, total // 10), total)
        acc, target, t0 = 0, (k + 1) // 2, float(hist[-1][0])
        for w, c in hist:
            acc += c
            if acc >= target:
                t0 = float(w)
                break
    r = _refine(hist, t0, sample_ticks=sample_ticks)
    if r is None:
        return res
    t, fit, cand = r
    # 정수배 보정: 모든 k 가 짝수(3의 배수)면 진짜 T 는 2배(3배)
    for _ in range(3):
        odd_frac, not3_frac = _k_stats(hist, t, sample_ticks)
        if odd_frac < 0.03:
            r2 = _refine(hist, t * 2, sample_ticks=sample_ticks)
            if r2 and r2[1] >= 0.9 * fit:
                t, fit, cand = r2
                continue
        if not3_frac < 0.03:
            r3 = _refine(hist, t * 3, sample_ticks=sample_ticks)
            if r3 and r3[1] >= 0.9 * fit:
                t, fit, cand = r3
                continue
        break
    # T/2 가 훨씬 더 많이 설명하면 (1T 펄스가 드물어 초기값이 2T 였던 경우) T/2
    if t / 2 >= 1.5 * sample_ticks:
        half = _refine(hist, t / 2, sample_ticks=sample_ticks)
        if half and half[2] and cand:
            if half[1] / half[2] - fit / cand > 0.1:
                t, fit, cand = half
    res["bit_ticks"] = t
    res["explained"] = (fit / cand) if cand else 0.0
    res["fit_runs"] = fit
    res["frame_runs"] = cand
    res["min_width"] = hist[0][0]
    return res


# ---------------------------------------------------------------------------
# 순수 Python UART 디코더
# ---------------------------------------------------------------------------

@dataclass
class UartDecode:
    frames: int = 0
    framing_errors: int = 0
    parity_errors: int = 0
    invalid_starts: int = 0
    breaks: int = 0
    values: list[int] = field(default_factory=list)
    frame_starts: list[int] = field(default_factory=list)
    frame_ok: list[bool] = field(default_factory=list)
    stopped_early: bool = False

    @property
    def error_rate(self) -> float | None:
        if self.frames == 0:
            return None
        return (self.framing_errors + self.parity_errors) / self.frames

    def data_bytes(self) -> bytes:
        return bytes(v & 0xFF for v in self.values)

    def summary(self) -> dict[str, Any]:
        return {
            "frames": self.frames,
            "framing_errors": self.framing_errors,
            "parity_errors": self.parity_errors,
            "invalid_starts": self.invalid_starts,
            "breaks": self.breaks,
            "error_rate": None if self.error_rate is None else round(self.error_rate, 4),
        }


def uart_decode(
    ce: ChannelEdges,
    bit_ticks: float,
    idle_level: int,
    *,
    data_bits: int = 8,
    parity: str = "none",
    stop_bits: int = 1,
    max_frames: int | None = None,
    keep_values: bool = True,
) -> UartDecode:
    """에지 목록을 커서로 훑으며 UART 프레임 디코드 (bisect 대신 단조 커서)."""
    out = UartDecode()
    edges = ce.edges
    n = len(edges)
    if n == 0 or bit_ticks <= 0:
        return out
    init = ce.initial_level
    active = 1 - idle_level
    tps = ce.ticks_per_sample
    half = (bit_ticks - tps) / 2.0 if bit_ticks > tps else bit_ticks / 2.0
    par_bits = 0 if parity in ("none", "ignore") else 1
    nbits = 1 + data_bits + par_bits + stop_bits
    j = 0  # 커서: edges[:j] <= t

    def level_at(t: float) -> int:
        nonlocal j
        while j < n and edges[j] <= t:
            j += 1
        while j > 0 and edges[j - 1] > t:
            j -= 1
        return init ^ (j & 1)

    k = 0
    pos = float(ce.start_tick)
    limit = max_frames if max_frames is not None else 1 << 62
    while out.frames < limit:
        # 다음 start 에지: idle → active 전이, pos 이후
        while k < n and (edges[k] < pos or (init ^ ((k + 1) & 1)) != active):
            k += 1
        if k >= n:
            break
        t0 = edges[k]
        k += 1
        if t0 + nbits * bit_ticks > ce.end_tick + tps:
            break  # 캡처 끝에서 잘린 프레임
        base = t0 + half
        if level_at(base) != active:
            out.invalid_starts += 1
            pos = t0 + tps
            continue
        val = 0
        ones = 0
        for i in range(data_bits):
            b = 1 if level_at(base + (1 + i) * bit_ticks) == idle_level else 0
            val |= b << i
            ones += b
        ok = True
        if par_bits:
            pb = 1 if level_at(base + (1 + data_bits) * bit_ticks) == idle_level else 0
            exp = {"even": ones & 1, "odd": (ones & 1) ^ 1, "mark": 1, "one": 1, "space": 0, "zero": 0}.get(parity, pb)
            if pb != exp:
                out.parity_errors += 1
                ok = False
        stop_ok = True
        for s in range(stop_bits):
            if level_at(base + (1 + data_bits + par_bits + s) * bit_ticks) != idle_level:
                stop_ok = False
        if not stop_ok:
            out.framing_errors += 1
            ok = False
            if val == 0:
                out.breaks += 1
        out.frames += 1
        if keep_values:
            out.values.append(val)
            out.frame_starts.append(t0)
            out.frame_ok.append(ok)
        pos = base + (nbits - 1) * bit_ticks  # 마지막 stop bit 중앙 이후부터 다음 start 탐색
    else:
        out.stopped_early = True
    return out


# ---------------------------------------------------------------------------
# 추정기
# ---------------------------------------------------------------------------

def snap_baud(raw: float, tol: float = SNAP_TOL) -> tuple[int | None, list[dict[str, Any]]]:
    ranked = sorted(STANDARD_BAUDS, key=lambda b: abs(raw / b - 1))
    cands = [{"baudrate": b, "rel_error": round(raw / b - 1, 5)} for b in ranked[:4]]
    best = ranked[0]
    return (best if abs(raw / best - 1) <= tol else None), cands


def _idle_votes(rs: RunSet, bit_ticks: float, ce: ChannelEdges) -> dict[str, Any]:
    long_dur = {0: 0, 1: 0}
    thr = 11.5 * bit_ticks
    for lv, w in zip(rs.levels, rs.widths):
        if w > thr:
            long_dur[lv] += w
    if rs.first_width > thr:
        long_dur[rs.first_level] += rs.first_width
    if rs.last_width > thr:
        long_dur[rs.last_level] += rs.last_width
    time_at = {0: 0, 1: 0}
    for lv, w in zip(rs.levels, rs.widths):
        time_at[lv] += w
    time_at[rs.first_level] += rs.first_width
    time_at[rs.last_level] += rs.last_width
    if long_dur[0] != long_dur[1]:
        guess = 1 if long_dur[1] > long_dur[0] else 0
        basis = "long-idle-runs"
    elif rs.first_level == rs.last_level and (rs.first_width > 0 or rs.last_width > 0):
        guess = rs.first_level
        basis = "first-last-level"
    else:
        guess = 1 if time_at[1] >= time_at[0] else 0
        basis = "time-majority"
    return {"guess": guess, "basis": basis, "long_idle_ticks": long_dur, "time_at_level": time_at}


def estimate_baud(ce: ChannelEdges, *, snap_tol: float = SNAP_TOL, check_frames: int = 3000,
                  data_bits: int = 8, parity: str = "none") -> dict[str, Any]:
    """채널 에지 → 보드레이트 추정 결과(dict). 실패 시 baudrate=None + warnings."""
    warnings: list[str] = list(ce.warnings)
    tps = ce.ticks_per_sample
    res: dict[str, Any] = {
        "channel": ce.channel.name,
        "channel_index": ce.channel.index,
        "baudrate": None,
        "baudrate_raw": None,
        "standard": False,
        "confidence": 0.0,
        "idle_level": None,
        "inverted": None,
        "candidates": [],
        "samplerate": ce.samplerate,
        "samples_per_bit": None,
        "bit_time_us": None,
        "frame_check": None,
        "stats": {
            "edges": len(ce.edges),
            "duration_s": round(ce.duration_s, 6),
            "truncated": ce.truncated,
        },
        "warnings": warnings,
    }
    if len(ce.edges) < 3:
        warnings.append("에지가 거의 없음 (라인이 idle 이거나 채널/GND 연결이 잘못됨, 또는 캡처 시점에 출력이 없었음)")
        res["idle_level"] = ce.initial_level if len(ce.edges) == 0 else None
        return res
    rs = complete_runs(ce)
    est = estimate_bit_ticks(rs.widths, sample_ticks=tps)
    res["stats"].update({k: est.get(k) for k in ("runs_used", "glitches")})
    if est.get("glitches"):
        warnings.append(f"{est['glitches']}개의 1샘플 글리치 run 을 제외함 (노이즈/링잉)")
    # 레벨별 추정: active 레벨 run(start bit + 0 비트들)은 항상 T 의 정수배지만, idle 레벨 run 은 stop bit + 임의
    # 길이의 idle 이 붙어 소수배가 될 수 있다 → 레벨별로도 후보를 만들고 프레임 검사로 고른다.
    w_by_level = {0: [w for lv, w in zip(rs.levels, rs.widths) if lv == 0],
                  1: [w for lv, w in zip(rs.levels, rs.widths) if lv == 1]}
    ests: dict[str, dict[str, Any]] = {}
    if est.get("bit_ticks"):
        ests["all"] = est
    for lv in (0, 1):
        if len(w_by_level[lv]) >= 4:
            e = estimate_bit_ticks(w_by_level[lv], sample_ticks=tps)
            if e.get("bit_ticks"):
                ests[f"level{lv}"] = e
    if not ests:
        warnings.append("펄스 폭에서 공통 비트 시간을 찾지 못함 (UART 가 아니거나 노이즈)")
        return res
    if est["runs_used"] < 8:
        warnings.append(f"분석에 쓸 수 있는 펄스가 너무 적음 ({est['runs_used']}개) — 더 길게 캡처")
    t_ref = (ests.get("all") or next(iter(ests.values())))["bit_ticks"]
    votes = _idle_votes(rs, t_ref, ce)
    cands: dict[float, str] = {}
    for key in ("all", "level0", "level1"):
        e = ests.get(key)
        if not e:
            continue
        for bt, tag in ((e["bit_ticks"], key), (e["bit_ticks"] / 2.0, key + "/2")):
            if bt / tps < 1.5:  # 1.5 샘플 미만은 평가 불가
                continue
            if any(abs(bt / x - 1) < 0.01 for x in cands):
                continue
            cands[bt] = tag
    evaluated = []
    for bt, tag in cands.items():
        for idle in (votes["guess"], 1 - votes["guess"]):
            dec = uart_decode(ce, bt, idle, data_bits=data_bits, parity=parity, max_frames=min(check_frames, 1500), keep_values=False)
            er = dec.error_rate if (dec.error_rate is not None and dec.frames >= 2) else 1.0
            ex = _explained(w_by_level[1 - idle], bt, tps)
            evaluated.append((er, ex, bt, idle, tag))
    if not evaluated:
        warnings.append("평가 가능한 비트 시간 후보가 없음 (샘플링이 너무 성김)")
        return res

    def sel_key(x: tuple[float, float, float, int, str]) -> tuple[float, float, int, float, int]:
        er, ex, bt, idle, tag = x
        # 1) 프레임 오류율 2) active run 설명 비율 3) 반으로 나눈 후보는 후순위 4) 긴 비트 시간 5) 추정 극성
        return (round(er, 2), -round(ex, 2), 1 if tag.endswith("/2") else 0, -bt, 0 if idle == votes["guess"] else 1)

    best = min(evaluated, key=sel_key)
    chosen_t, chosen_idle, chosen_tag = best[2], best[3], best[4]
    if chosen_tag.endswith("/2"):
        warnings.append("최소 펄스가 2T 로 보여 보드레이트를 2배로 보정함 (프레임 검사 결과)")
    # 선택한 극성의 active 레벨 run 으로 최종 정제 (idle 간격의 소수배 영향 제거)
    act = w_by_level[1 - chosen_idle]
    if len(act) >= 8:
        hist = sorted(Counter(w for w in act if w > tps + 1e-9).items())
        r2 = _refine(hist, chosen_t, sample_ticks=tps) if hist else None
        if r2 and abs(r2[0] / chosen_t - 1) < 0.05:
            chosen_t = r2[0]
    est = dict(est)
    est["explained"] = _explained(act if len(act) >= 4 else rs.widths, chosen_t, tps)
    res["stats"]["explained_basis"] = "active-level-runs" if len(act) >= 4 else "all-runs"
    t = chosen_t
    baud_raw = ce.tick_hz / t
    snapped, cands = snap_baud(baud_raw, snap_tol)
    spb = t / tps
    res.update({
        "baudrate_raw": round(baud_raw, 3),
        "baudrate": snapped if snapped else int(round(baud_raw)),
        "standard": snapped is not None,
        "idle_level": int(chosen_idle),
        "inverted": chosen_idle == 0,
        "samples_per_bit": round(spb, 3),
        "bit_time_us": round(t / ce.tick_hz * 1e6, 4),
    })
    res["stats"]["explained"] = round(est["explained"], 4)
    res["stats"]["min_pulse_samples"] = round(est.get("min_width", 0) / tps, 3) if est.get("min_width") else None
    res["stats"]["idle_basis"] = votes["basis"]
    # 스냅한 값으로 다시 프레임 검사 (보고용)
    final_bt = ce.tick_hz / snapped if snapped else t
    fc = uart_decode(ce, final_bt, chosen_idle, data_bits=data_bits, parity=parity, max_frames=check_frames, keep_values=False)
    res["frame_check"] = {"format": f"{data_bits}{'N' if parity == 'none' else parity[0].upper()}1", **fc.summary()}
    # 후보 목록 (오차 + 각 후보의 프레임 오류율)
    out_cands = []
    for c in cands[:3]:
        dec = uart_decode(ce, ce.tick_hz / c["baudrate"], chosen_idle, data_bits=data_bits, parity=parity,
                          max_frames=min(check_frames, 1000), keep_values=False)
        out_cands.append({**c, "framing_error_rate": None if dec.error_rate is None else round(dec.error_rate, 4), "frames": dec.frames})
    if snapped is None:
        out_cands.insert(0, {"baudrate": int(round(baud_raw)), "rel_error": 0.0, "nonstandard": True,
                             "framing_error_rate": None if fc.error_rate is None else round(fc.error_rate, 4), "frames": fc.frames})
    res["candidates"] = out_cands

    # 경고
    if spb < MIN_OVERSAMPLE:
        warnings.append(
            f"samplerate({ce.samplerate:.0f} Hz)가 보드레이트의 4배 미만(비트당 {spb:.2f} 샘플) — 추정/디코드가 부정확할 수 있음. "
            f"보드레이트의 10배 이상(예: {next_rate(baud_raw * 10)} 이상)으로 다시 캡처 권장"
        )
    elif spb < 8:
        warnings.append(f"비트당 {spb:.1f} 샘플 — 동작은 하지만 8~10배 이상 오버샘플링을 권장")
    if est["explained"] < 0.8:
        warnings.append(f"펄스의 {100 * est['explained']:.0f}% 만 단일 비트 시간의 정수배로 설명됨 (노이즈/잘못된 채널/비UART/보드레이트 혼재 가능)")
    if snapped is None:
        warnings.append(f"표준 보드레이트 ±{snap_tol * 100:.0f}% 안에 드는 값이 없음 → 비표준 {int(round(baud_raw))} 로 보고 (클럭 오차/비UART 가능)")
    if chosen_idle == 0:
        warnings.append("라인이 idle 에서 LOW — 반전된 신호(RS-232 레벨 변환 후 등). 디코드 시 invert_rx=yes 필요")
    er = fc.error_rate
    if fc.frames and er is not None and er > 0.05:
        warnings.append(f"8N1 프레임 오류율 {er * 100:.1f}% — 패리티/7비트(7E1 등) 또는 보드레이트 혼재 가능")
    if fc.frames < 5:
        warnings.append(f"검사 가능한 UART 프레임이 {fc.frames}개뿐임")

    # 보드레이트 혼재(구간별) 검사
    segs = _segments(ce, rs, t, chosen_idle)
    if segs:
        res["segments"] = segs
        distinct = sorted({s["baudrate"] for s in segs if s.get("baudrate")})
        if len(distinct) > 1:
            warnings.append(f"구간별 보드레이트가 다름: {distinct} (예: BootROM/부트로더/커널 속도가 다름) — segments 확인 후 구간별로 디코드")

    res["confidence"] = round(_confidence(est, snapped, baud_raw, spb, fc, snap_tol), 3)
    ch = ce.channel.name
    res["suggested_decoder"] = f"uart:rx={ch}:baudrate={res['baudrate']}" + (":invert_rx=yes" if chosen_idle == 0 else "")
    return res


def _confidence(est: dict[str, Any], snapped: int | None, raw: float, spb: float, fc: UartDecode, tol: float) -> float:
    e = max(0.0, min(1.0, est.get("explained", 0.0)))
    if snapped:
        snap_f = 1.0 - 0.3 * min(1.0, abs(raw / snapped - 1) / tol)
    else:
        snap_f = 0.45
    if spb >= 8:
        os_f = 1.0
    elif spb >= 4:
        os_f = 0.85 + 0.15 * (spb - 4) / 4
    elif spb >= 2.5:
        os_f = 0.5
    else:
        os_f = 0.2
    n = est.get("runs_used", 0)
    data_f = 1.0 if n >= 50 else 0.85 if n >= 20 else 0.6 if n >= 8 else 0.3
    if fc.frames >= 3 and fc.error_rate is not None:
        frame_f = max(0.1, 1.0 - 1.5 * fc.error_rate)
    else:
        frame_f = 0.5
    return e * snap_f * os_f * data_f * frame_f


def _segments(ce: ChannelEdges, rs: RunSet, t: float, idle: int, max_segments: int = 64) -> list[dict[str, Any]]:
    """idle 이 30T 이상인 곳에서 나눈 구간별 보드레이트 (run 40개 이상인 구간만)."""
    gap = 30.0 * t
    bursts: list[tuple[int, int]] = []
    start = 0
    for i, (lv, w) in enumerate(zip(rs.levels, rs.widths)):
        if lv == idle and w > gap:
            if i - start >= 1:
                bursts.append((start, i))
            start = i + 1
    if len(rs.widths) - start >= 1:
        bursts.append((start, len(rs.widths)))
    if len(bursts) < 2:
        return []
    out = []
    for a, b in bursts:
        widths = [w for lv, w in zip(rs.levels[a:b], rs.widths[a:b]) if w <= (KMAX + 0.5) * t * 4]
        if len(widths) < 40:
            continue
        est = estimate_bit_ticks(widths, sample_ticks=ce.ticks_per_sample)
        if not est["bit_ticks"]:
            continue
        raw = ce.tick_hz / est["bit_ticks"]
        snapped, _ = snap_baud(raw)
        out.append({
            "start_s": round((rs.starts[a] - ce.start_tick) / ce.tick_hz, 6),
            "end_s": round((rs.starts[b - 1] + rs.widths[b - 1] - ce.start_tick) / ce.tick_hz, 6),
            "runs": b - a,
            "baudrate": snapped or int(round(raw)),
            "baudrate_raw": round(raw, 2),
        })
        if len(out) >= max_segments:
            break
    return out


_FX2_RATES = (20_000, 25_000, 50_000, 100_000, 200_000, 250_000, 500_000, 1_000_000, 2_000_000, 3_000_000,
              4_000_000, 6_000_000, 8_000_000, 12_000_000, 16_000_000, 24_000_000)


def next_rate(min_hz: float) -> str:
    """fx2lafw 이산 samplerate 목록에서 min_hz 이상인 첫 값 (권장 캡처 속도 안내용)."""
    for r in _FX2_RATES:
        if r >= min_hz:
            return f"{r // 1_000_000} MHz" if r >= 1_000_000 else f"{r // 1000} kHz"
    return "24 MHz"


def recommend_samplerate(baud: float, factor: float = 10.0) -> str:
    return next_rate(baud * factor)


# ---------------------------------------------------------------------------
# 미리보기 / 힌트
# ---------------------------------------------------------------------------

def render_text(data: bytes, limit: int = 4096) -> str:
    """바이트 → 사람이 읽을 텍스트 (CRLF→LF, 출력 불가 문자는 \\xNN)."""
    out = []
    view = data[:limit]
    i = 0
    while i < len(view):
        b = view[i]
        if b == 0x0D:
            if i + 1 < len(view) and view[i + 1] == 0x0A:
                i += 1
            out.append("\n")
        elif b == 0x0A:
            out.append("\n")
        elif b == 0x09:
            out.append("\t")
        elif 0x20 <= b < 0x7F:
            out.append(chr(b))
        else:
            out.append(f"\\x{b:02x}")
        i += 1
    if len(data) > limit:
        out.append(f"\n…({len(data) - limit} bytes 더 있음)")
    return "".join(out)


_HINTS = [
    ("uboot_banner", re.compile(rb"U-Boot(?: SPL)? \d{4}\.\d{2}[^\r\n]{0,60}")),
    ("autoboot_prompt", re.compile(rb"(?i)(?:hit any key to stop autoboot|press .{0,20}(?:key|ctrl).{0,30}(?:stop|abort)|autoboot in \d+)[^\r\n]{0,40}")),
    ("uboot_prompt", re.compile(rb"(?m)^(?:=> ?|U-Boot ?> ?|[A-Za-z][\w.-]{1,31} ?# ?)$")),
    ("kernel_start", re.compile(rb"Starting kernel[^\r\n]{0,40}|Uncompressing Linux[^\r\n]{0,40}")),
    ("linux_version", re.compile(rb"Linux version \d+\.\d+[^\r\n]{0,80}")),
    ("kernel_cmdline", re.compile(rb"Kernel command line: [^\r\n]{0,300}")),
    ("mtdparts", re.compile(rb"mtdparts=[^\s\r\n]{1,300}")),
    ("busybox", re.compile(rb"BusyBox v[\d.]+[^\r\n]{0,40}")),
    ("console_activate", re.compile(rb"Please press Enter to activate this console")),
    ("login_prompt", re.compile(rb"(?i)[\w.-]* ?login: ?")),
    ("password_prompt", re.compile(rb"(?i)password: ?")),
]


def boot_hints(data: bytes, limit: int = 30) -> list[dict[str, str]]:
    out = []
    for kind, rx in _HINTS:
        for m in rx.finditer(data):
            out.append({"kind": kind, "match": m.group(0).decode("latin-1").strip()[:200], "offset": m.start()})
            if len(out) >= limit:
                return out
            if kind in ("login_prompt", "password_prompt", "uboot_prompt"):
                break
    out.sort(key=lambda h: h["offset"])
    return out


__all__ = [
    "STANDARD_BAUDS",
    "UartDecode",
    "boot_hints",
    "complete_runs",
    "estimate_baud",
    "estimate_bit_ticks",
    "next_rate",
    "recommend_samplerate",
    "render_text",
    "snap_baud",
    "uart_decode",
]
