"""블록 엔트로피 (fw_entropy).

- 블록별 Shannon 엔트로피(비트/바이트, 0~8)
- 높은 엔트로피 연속 구간 = 압축 또는 암호화 '후보'. 구간 전체 바이트 분포의 카이제곱으로
  '균일(무작위와 구분 불가: 암호화 또는 강한 압축)' / '비균일(일반적인 압축 데이터)' 을 함께 표시
- 낮은 엔트로피 구간 = 패딩/빈 영역(0xFF, 0x00) 후보
- (선택) 알려진 시그니처와 겹치는지 표시 → 알려진 형식이 없는 고엔트로피 구간은 암호화/난독화 의심
엔트로피만으로 압축과 암호화를 확정할 수 없다 (휴리스틱).
"""

from __future__ import annotations

import math
from collections import Counter
from typing import Any

from .common import Ctl, hexs
from .signatures import ScanCtx, scan_regions

PROFILE_CHARS = "_.:-=+*#%@"


def _entropy(counts: Counter, n: int) -> float:
    if n == 0:
        return 0.0
    h = 0.0
    for c in counts.values():
        p = c / n
        h -= p * math.log2(p)
    return h


def _chi2(counts: Counter, n: int) -> float:
    if n == 0:
        return 0.0
    e = n / 256.0
    s = sum((counts.get(b, 0) - e) ** 2 for b in range(256))
    return s / e


def entropy_scan(buf: Any, start: int, end: int, block_size: int, ctl: Ctl, *, high: float = 7.5, low: float = 1.0, annotate: bool = True, profile_width: int = 64) -> dict[str, Any]:
    blocks: list[float] = []
    runs_high: list[dict[str, Any]] = []
    runs_low: list[dict[str, Any]] = []
    cur: dict[str, Any] | None = None
    cur_low: dict[str, Any] | None = None
    total = max(1, (end - start + block_size - 1) // block_size)
    truncated = False
    i = 0
    for off in range(start, end, block_size):
        if (i & 0x3F) == 0:
            ctl.progress(i, total, "엔트로피 계산 중")
            if ctl.expired():
                truncated = True
                break
        chunk = bytes(buf[off : min(end, off + block_size)])
        n = len(chunk)
        cnt = Counter(chunk)
        h = _entropy(cnt, n)
        blocks.append(round(h, 4))
        if h >= high:
            if cur is None:
                cur = {"offset": off, "size": 0, "counts": Counter(), "hs": []}
            cur["size"] += n
            cur["counts"].update(cnt)
            cur["hs"].append(h)
        elif cur is not None:
            runs_high.append(cur)
            cur = None
        if h <= low:
            if cur_low is None:
                fill = max(cnt.items(), key=lambda kv: kv[1])[0] if cnt else 0
                cur_low = {"offset": off, "size": 0, "fill": fill}
            cur_low["size"] += n
        elif cur_low is not None:
            runs_low.append(cur_low)
            cur_low = None
        i += 1
    if cur is not None:
        runs_high.append(cur)
    if cur_low is not None:
        runs_low.append(cur_low)
    high_out = []
    for r in runs_high:
        n = r["size"]
        chi = _chi2(r["counts"], n)
        # 균일 분포의 카이제곱 기대값 255, 표준편차 sqrt(510) ≈ 22.6
        uniform = chi < 255 + 4 * 22.6
        high_out.append(
            {
                "offset": r["offset"],
                "offset_hex": hexs(r["offset"]),
                "size": n,
                "end_hex": hexs(r["offset"] + n),
                "mean_entropy": round(sum(r["hs"]) / len(r["hs"]), 4),
                "min_entropy": round(min(r["hs"]), 4),
                "chi_square": round(chi, 1),
                "distribution": "uniform" if uniform else "non-uniform",
                "interpretation": (
                    "무작위와 구분 불가 (암호화 또는 강한 압축 후보)" if uniform else "높은 엔트로피지만 비균일 (일반적인 압축 데이터 후보)"
                ),
            }
        )
    low_out = [{"offset": r["offset"], "offset_hex": hexs(r["offset"]), "size": r["size"], "dominant_byte": f"0x{r['fill']:02x}"} for r in runs_low]
    if annotate and high_out and not ctl.expired():
        ctx = ScanCtx(ctl, decompress_budget=96 << 20, max_stream_in=16 << 20, max_stream_out=32 << 20)
        try:
            regions = [r for r in scan_regions(buf, start, end, ctx, env_scan=False) if r.size and r.parent is None]
        except Exception:  # pragma: no cover - 방어
            regions = []
        for run in high_out:
            a, b = run["offset"], run["offset"] + run["size"]
            ov = []
            covered = 0
            for rg in regions:
                ra, rb = rg.offset, rg.offset + (rg.size or 0)
                lo, hi = max(a, ra), min(b, rb)
                if hi > lo:
                    covered += hi - lo
                    if len(ov) < 6:
                        ov.append({"kind": rg.kind, "offset_hex": hexs(rg.offset), "size": rg.size})
            run["known_regions"] = ov
            run["known_coverage"] = round(min(1.0, covered / max(1, run["size"])), 3)
            if run["known_coverage"] < 0.5:
                run["note"] = "알려진 압축/파일시스템 형식으로 설명되지 않는 고엔트로피 구간: 암호화·난독화(벤더 펌웨어 보호) 또는 미지원 형식 의심"
    # 압축된 프로파일 문자열
    profile = ""
    if blocks:
        width = min(profile_width, len(blocks))
        per = len(blocks) / width
        for k in range(width):
            seg = blocks[int(k * per) : max(int(k * per) + 1, int((k + 1) * per))]
            v = sum(seg) / len(seg)
            profile += PROFILE_CHARS[min(9, int(v / 8.0 * 10))]
    stats = {}
    if blocks:
        stats = {"mean": round(sum(blocks) / len(blocks), 4), "max": max(blocks), "min": min(blocks)}
    return {
        "block_size": block_size,
        "blocks_computed": len(blocks),
        "blocks_total": total,
        "truncated": truncated,
        "stats": stats,
        "profile": profile,
        "profile_legend": f"'{PROFILE_CHARS}' = 엔트로피 0→8 (한 글자 = {round(len(blocks) / max(1, len(profile)), 2)} 블록)",
        "high_runs": high_out,
        "low_runs": low_out,
        "blocks": blocks,
        "thresholds": {"high": high, "low": low},
    }
