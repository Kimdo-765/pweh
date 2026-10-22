"""세이브 파일 오프라인 분석 (fw_save_diff · fw_checksum_find 등이 감쌀 순수 라이브러리, I2a).

설계: docs/design/game-console-flipper-rf.md §3.5, §4 5단계
(점수·진행이 바뀔 때마다 스냅샷 ≥3 → 비교 → 인코딩·위치 → 체크섬 후보 → 디컴파일로 확인).

- 값 인코딩: u8/i8, u16·i16·u32·i32 (le/be), 압축 BCD 2·4바이트 (le/be)
- ``diff_snapshots``: 시간 순서 스냅샷의 바뀐 구간 + 구간을 덮는 창의 값 해석과 추세
- ``match_observations``: 사람이 화면에서 본 값(점수·레벨)이 모든 스냅샷에서 그대로 읽히는 (오프셋, 인코딩) 전수 탐색
- ``find_checksums``: 바뀐 바이트로 체크섬 위치 후보를 만들고, 위치 바로 앞 ``[s, 위치)`` / 바로 뒤 ``[위치+폭, e)``
  범위의 합계·XOR·Fletcher·Adler·CRC 가 **모든** 스냅샷에서 저장값과 같은지 찾는다
- ``find_seq_tables``: 치트 입력(버튼 시퀀스) 표 후보 (코나미형 AABBCDCDEF 등)
- ``apply_raw_edits``: 원시 편집 + 체크섬 검증·재계산 (fw_patch_build의 ESP raw-region 내부에서 사용, 일반 imported 파일용 공개 패치 API는 아님)

모든 결과는 사람·에이전트가 디컴파일과 실기로 확인해야 하는 **후보**다. 입력은 신뢰할 수 없는 데이터로 다루고,
길이 불일치·쓰레기 입력에는 예외 대신 ``warnings``/``notes`` 로 알린다 (인자 자체가 잘못되면 ``SaveFormatError``).
표준 라이브러리만 쓰고 stdout 에 쓰지 않는다. 오래 걸리는 함수는 선택 인자 ``ctl``(fwtriage ``Ctl`` 과 같은 덕 타입:
``check()`` 는 취소 시 예외, ``expired()`` 는 시간 예산 초과 여부)을 받아 주기적으로 확인한다.
"""

from __future__ import annotations

import binascii
import functools
import heapq
import math
import operator
import re
import struct
import sys
import zlib
from array import array
from bisect import bisect_left, bisect_right
from collections import Counter
from itertools import accumulate, chain, islice
from typing import Any, Callable, Iterable, Iterator, Sequence

__all__ = [
    "SaveFormatError",
    "ENCODINGS",
    "encoding_width",
    "decode_value",
    "encode_value",
    "diff_snapshots",
    "match_observations",
    "CHECKSUM_ALGORITHMS",
    "checksum_compute",
    "find_checksums",
    "find_seq_tables",
    "apply_raw_edits",
]


class SaveFormatError(ValueError):
    """세이브 분석 인자·형식 오류 (알 수 없는 인코딩·알고리즘, 표현할 수 없는 값, 거부된 편집 등)."""


# ---------------------------------------------------------------------------
# 공통 헬퍼
# ---------------------------------------------------------------------------

_HOST_LITTLE = sys.byteorder == "little"
_U32_CODE = next((c for c in ("I", "L") if array(c).itemsize == 4), None)


def _is_int(v: Any) -> bool:
    return isinstance(v, int) and not isinstance(v, bool)


def _tick(ctl: Any) -> bool:
    """취소면 예외(``ctl.check``/``ctl.expired`` 가 던짐), 시간 예산을 넘겼으면 True. ctl 이 없으면 False."""
    if ctl is None:
        return False
    expired = getattr(ctl, "expired", None)
    if callable(expired):
        return bool(expired())
    ctl.check()
    return False


def _progress(ctl: Any, done: float, total: float | None, message: str) -> None:
    fn = getattr(ctl, "progress", None) if ctl is not None else None
    if callable(fn):
        try:
            fn(done, total, message)
        except Exception:  # pragma: no cover - 진행률 보고 실패는 무시
            pass


def _to_bytes(obj: Any, what: str) -> bytes:
    if isinstance(obj, bytes):
        return obj
    try:
        return bytes(memoryview(obj))
    except TypeError:
        raise SaveFormatError(f"{what} 는 bytes 류여야 합니다 (받은 형식: {type(obj).__name__}).") from None


def _coerce_snapshots(snapshots: Any) -> list[bytes]:
    if not isinstance(snapshots, (list, tuple)):
        raise SaveFormatError("snapshots 는 bytes 의 목록(시간 순서)이어야 합니다.")
    return [_to_bytes(s, f"snapshots[{i}]") for i, s in enumerate(snapshots)]


def _common_length(snaps: Sequence[bytes], sink: list[str]) -> int:
    lengths = [len(s) for s in snaps]
    common = min(lengths) if lengths else 0
    if lengths and max(lengths) != common:
        sink.append(
            f"스냅샷 길이가 다릅니다 {lengths} — 공통 앞부분 {common} 바이트만 비교합니다 "
            "(같은 세이브 형식·같은 덤프 범위인지 확인하세요)."
        )
    return common


def _words(buf: bytes, ws: int, order: str) -> Sequence[int]:
    """길이가 ws 의 배수인 buf 를 ws 바이트 워드(부호 없음) 열로."""
    code = "H" if ws == 2 else _U32_CODE
    if code is not None and array(code).itemsize == ws:
        arr = array(code)
        arr.frombytes(buf)
        if (order == "little") != _HOST_LITTLE:
            arr.byteswap()
        return arr
    fmt = ("<" if order == "little" else ">") + ("H" if ws == 2 else "I")
    return [v for (v,) in struct.iter_unpack(fmt, buf)]


_DIFF_CHUNK = 1 << 20
_NONZERO_RUN = re.compile(rb"[^\x00]+")
_T_NONZERO = bytes([0] + [1] * 255)


def _diff_mask(snaps: Sequence[bytes], start: int, end: int, ctl: Any = None) -> bytes | None:
    """[start, end) 의 변화 마스크: 스냅샷 사이에 값이 하나라도 다른 위치는 0 이 아닌 바이트, 모두 같으면 0.

    청크(1 MiB)마다 첫 스냅샷과 나머지의 XOR 을 OR 로 모은다 (C 수준 정수 연산). 시간 예산을 넘기면 None.
    """
    parts: list[bytes] = []
    first = snaps[0]
    for c0 in range(start, end, _DIFF_CHUNK):
        if _tick(ctl):
            return None
        c1 = min(end, c0 + _DIFF_CHUNK)
        base = int.from_bytes(first[c0:c1], "little")
        acc = 0
        for s in snaps[1:]:
            acc |= base ^ int.from_bytes(s[c0:c1], "little")
        parts.append(acc.to_bytes(c1 - c0, "little"))
    return b"".join(parts)


def _iter_runs(mask: bytes, base: int) -> Iterator[tuple[int, int]]:
    """마스크의 0 이 아닌 연속 구간을 하나씩 낸다 (절대 오프셋 = base + 마스크 위치). 목록을 만들지 않는다."""
    for m in _NONZERO_RUN.finditer(mask):
        yield base + m.start(), base + m.end()


def _diff_runs(snaps: Sequence[bytes], start: int, end: int) -> list[tuple[int, int]]:
    """바뀐 바이트의 연속 구간 목록 (작은 입력·테스트용 — 큰 입력은 _diff_mask + _iter_runs 로 하나씩 본다)."""
    if end <= start or len(snaps) < 2:
        return []
    mask = _diff_mask(snaps, start, end)
    return list(_iter_runs(mask, start)) if mask else []


def _count_ranges(nz: bytes, gap: int) -> int:
    """0/1 바이트열 nz 의 병합 구간 수 = 1 + (길이 > gap 인 안쪽 0 구간 수).

    bytes.count/rfind 만 쓴다 (구간마다 파이썬 객체를 만들지 않음). ``b"\\x01" + b"\\x00" * (gap + 1)`` 은 서로 겹칠 수 없어
    겹치지 않게 세는 bytes.count 로 정확히 센다.
    """
    last1 = nz.rfind(b"\x01")
    if last1 < 0:
        return 0
    if gap + 1 > len(nz):
        return 1
    long_gaps = nz.count(b"\x01" + b"\x00" * (gap + 1))
    if len(nz) - 1 - last1 >= gap + 1:
        long_gaps -= 1  # 맨 끝의 긴 0 구간은 구간 사이가 아님
    return 1 + long_gaps


def _iter_merged(nz: bytes, gap: int, base: int) -> Iterator[tuple[int, int]]:
    """0/1 바이트열 nz 의 병합 구간을 앞에서부터 하나씩: 1 에서 시작해 길이 > gap 인 0 구간 바로 앞의 1 에서 끝난다.

    _count_ranges 와 같은 규칙이라 개수와 목록이 어긋나지 않는다. 구간 하나에 bytes.find 두 번이다.
    """
    last1 = nz.rfind(b"\x01")
    if last1 < 0:
        return
    sep = b"\x01" + b"\x00" * (gap + 1) if gap + 1 <= len(nz) else None
    pos = 0
    while pos <= last1:
        s = nz.find(b"\x01", pos)
        if s < 0:
            return
        k = nz.find(sep, s) if sep is not None else -1
        e = k + 1 if k >= 0 else last1 + 1
        yield base + s, base + e
        pos = e


# ---------------------------------------------------------------------------
# 값 인코딩
# ---------------------------------------------------------------------------

# 이름 → (폭, 종류, 바이트 순서, 부호)
_ENC: dict[str, tuple[int, str, str, bool]] = {
    "u8": (1, "int", "little", False),
    "i8": (1, "int", "little", True),
    "u16le": (2, "int", "little", False),
    "u16be": (2, "int", "big", False),
    "i16le": (2, "int", "little", True),
    "i16be": (2, "int", "big", True),
    "u32le": (4, "int", "little", False),
    "u32be": (4, "int", "big", False),
    "i32le": (4, "int", "little", True),
    "i32be": (4, "int", "big", True),
    "bcd2le": (2, "bcd", "little", False),
    "bcd2be": (2, "bcd", "big", False),
    "bcd4le": (4, "bcd", "little", False),
    "bcd4be": (4, "bcd", "big", False),
}
ENCODINGS: tuple[str, ...] = tuple(_ENC)
_ENC_INDEX = {e: i for i, e in enumerate(ENCODINGS)}


def _enc_info(encoding: Any) -> tuple[int, str, str, bool]:
    try:
        return _ENC[encoding]
    except (KeyError, TypeError):
        raise SaveFormatError(f"알 수 없는 인코딩: {encoding!r} (가능: {', '.join(ENCODINGS)})") from None


def encoding_width(encoding: str) -> int:
    """인코딩의 바이트 폭 (u8=1, *16/bcd2=2, *32/bcd4=4)."""
    return _enc_info(encoding)[0]


def _bcd_decode(chunk: bytes, order: str) -> int | None:
    v = 0
    for b in chunk if order == "big" else chunk[::-1]:
        hi, lo = b >> 4, b & 0x0F
        if hi > 9 or lo > 9:
            return None
        v = v * 100 + hi * 10 + lo
    return v


def decode_value(data: Any, offset: int, encoding: str) -> int | None:
    """``data[offset:]`` 를 ``encoding`` 으로 읽는다. 범위 밖이거나 BCD 자리가 9 를 넘으면 None.

    BCD 는 압축 10진수(바이트당 두 자리, 상위 니블이 높은 자리)다. ``bcd2be`` 1234 = ``12 34``, ``bcd2le`` 1234 = ``34 12``,
    ``bcd4be`` 12345678 = ``12 34 56 78``.
    """
    w, kind, order, signed = _enc_info(encoding)
    if isinstance(data, str) or not hasattr(data, "__len__"):
        raise SaveFormatError(f"data 는 bytes 류여야 합니다 (받은 형식: {type(data).__name__}).")
    if not _is_int(offset) or offset < 0:
        return None
    try:
        if offset + w > len(data):
            return None
        chunk = bytes(data[offset : offset + w])
    except (TypeError, ValueError, KeyError):
        raise SaveFormatError(f"data 는 bytes 류여야 합니다 (받은 형식: {type(data).__name__}).") from None
    if kind == "bcd":
        return _bcd_decode(chunk, order)
    return int.from_bytes(chunk, order, signed=signed)


def encode_value(value: int, encoding: str) -> bytes:
    """정수를 ``encoding`` 바이트열로. 정수가 아니거나 범위(부호 없음 0..2^n-1, 부호 있음 2의 보수, BCD 0..10^(2·폭)-1) 밖이면 SaveFormatError."""
    w, kind, order, signed = _enc_info(encoding)
    if not _is_int(value):
        raise SaveFormatError(f"값은 정수여야 합니다: {value!r}")
    if kind == "bcd":
        top = 10 ** (2 * w) - 1
        if not 0 <= value <= top:
            raise SaveFormatError(f"{encoding} 로 표현할 수 없는 값입니다 (0..{top}): {value}")
        pairs = []
        v = value
        for _ in range(w):
            v, pair = divmod(v, 100)
            pairs.append(((pair // 10) << 4) | (pair % 10))
        out = bytes(pairs)  # 낮은 자리 쌍부터 = little
        return out if order == "little" else out[::-1]
    bits = 8 * w
    lo, hi = (-(1 << (bits - 1)), (1 << (bits - 1)) - 1) if signed else (0, (1 << bits) - 1)
    if not lo <= value <= hi:
        raise SaveFormatError(f"{encoding} 로 표현할 수 없는 값입니다 ({lo}..{hi}): {value}")
    return value.to_bytes(w, order, signed=signed)


# ---------------------------------------------------------------------------
# 스냅샷 비교
# ---------------------------------------------------------------------------

_MAX_HEX_BYTES = 256
_TREND_RANK = {"increasing": 0, "decreasing": 0, "mixed": 1, "constant": 2}


def _labels(labels: Any, n: int, warnings: list[str]) -> list[str]:
    default = [f"s{i}" for i in range(n)]
    if labels is None:
        return default
    if not isinstance(labels, (list, tuple)):
        warnings.append("labels 는 목록이어야 합니다 — 기본 이름(s0, s1, …)을 씁니다.")
        return default
    out = [default[i] if x is None else str(x) for i, x in enumerate(labels[:n])]
    if len(labels) != n:
        warnings.append(f"labels 개수({len(labels)})가 스냅샷 수({n})와 다릅니다 — 모자란 이름은 기본값, 남는 이름은 버립니다.")
        out += default[len(out) :]
    return out


def _trend(values: Sequence[int]) -> str:
    if all(v == values[0] for v in values):
        return "constant"
    steps = list(zip(values, values[1:]))
    if all(b >= a for a, b in steps):
        return "increasing"
    if all(b <= a for a, b in steps):
        return "decreasing"
    return "mixed"


def _windows_for(s: int, e: int, w: int, size: int, order: str) -> list[int]:
    """[s, e) 를 덮는 폭 w 창의 시작 위치: 폭 정렬 창, 그리고 little 은 구간 시작에서·big 은 구간 끝에서 맞춘 창."""
    if e - s > w:
        return []
    out = []
    a = (s // w) * w
    if a + w >= e and a + w <= size:
        out.append(a)
    nat = s if order == "little" else e - w
    if 0 <= nat and nat + w <= size and nat not in out:
        out.append(nat)
    return out


def _interpretations(snaps: Sequence[bytes], s: int, e: int, size: int) -> list[dict[str, Any]]:
    out = []
    for enc in ENCODINGS:
        w, _kind, order, signed = _ENC[enc]
        for o in _windows_for(s, e, w, size, order):
            values = [decode_value(snap, o, enc) for snap in snaps]
            if any(v is None for v in values):
                continue  # 어느 스냅샷에서 BCD 가 아님
            if signed and min(values) >= 0:
                continue  # 부호 없는 해석과 같음
            out.append({"encoding": enc, "offset": o, "aligned": o % w == 0, "values": values, "trend": _trend(values)})
    out.sort(key=lambda d: (_TREND_RANK[d["trend"]], not d["aligned"], _ENC[d["encoding"]][0], _ENC_INDEX[d["encoding"]], d["offset"]))
    return out


def diff_snapshots(
    snapshots: list[bytes],
    *,
    labels: list[str] | None = None,
    merge_gap: int = 0,
    max_ranges: int = 2000,
    ctl: Any = None,
) -> dict[str, Any]:
    """시간 순서 스냅샷 사이에서 바뀐 구간과 그 해석 후보.

    - ``ranges[]``: 한 스냅샷이라도 다른 바이트의 연속 구간 (``merge_gap`` 이하의 같은 바이트를 사이에 둔 구간은 합침) 중
      앞에서부터 ``max_ranges`` 개. ``ranges_total`` 은 자르기 전 **전체** 병합 구간 수, ``changed_bytes`` 는 전체 바뀐 바이트 수다
      (구간 목록을 통째로 만들지 않고 0/1 마스크를 C 수준으로 세어 구하므로 메모리는 입력 크기 정도).
      ``values_hex`` 는 스냅샷별 구간 바이트(``_MAX_HEX_BYTES`` 를 넘으면 앞부분만, ``values_hex_truncated``).
    - ``interpretations[]``: 구간을 덮는 폭 1/2/4 창(폭 정렬 창 + little 은 구간 시작·big 은 구간 끝에 맞춘 창)을 각 인코딩으로 읽은 값.
      창 시작 ``offset`` 과 ``aligned`` 를 함께 준다. 모든 스냅샷에서 읽히는 해석만, 부호 있는 해석은 음수가 나올 때만 넣는다.
      ``trend``: 감소 없이 한 번 이상 증가 → increasing, 그 반대 → decreasing, 모두 같음 → constant, 나머지 → mixed.
      구간이 4바이트보다 길면 해석이 없다 (문자열·표 등).
    - 길이가 다르면 공통 앞부분만 비교하고 ``warnings`` 에 적는다.
    - ``ctl`` (선택): 시간 예산을 넘기면 그때까지 해석한 구간만 돌려주고 ``truncated`` + ``warnings``.
      마스크조차 끝내지 못하면 ``changed_bytes``/``ranges_total`` 은 None 이다.

    결과는 위치 **후보**다: 점수처럼 단조 증가하는 해석이 유력하지만 확정은 ``match_observations`` 와 디컴파일로 한다.
    """
    warnings: list[str] = []
    snaps = _coerce_snapshots(snapshots)
    n = len(snaps)
    names = _labels(labels, n, warnings)
    gap = merge_gap if _is_int(merge_gap) and merge_gap > 0 else 0
    cap = max_ranges if _is_int(max_ranges) and max_ranges >= 0 else 2000
    bad = [f"{k}={v!r}" for k, v in (("merge_gap", merge_gap), ("max_ranges", max_ranges)) if v is not None and not (_is_int(v) and v >= 0)]
    if bad:
        warnings.append(f"올바르지 않은 인자 {', '.join(bad)} — merge_gap={gap}, max_ranges={cap} 로 처리합니다.")
    out: dict[str, Any] = {
        "length": len(snaps[0]) if n == 1 else 0,
        "snapshot_count": n,
        "labels": names,
        "changed_bytes": 0,
        "ranges": [],
        "ranges_total": 0,
        "truncated": False,
        "warnings": warnings,
    }
    if n < 2:
        warnings.append("비교하려면 스냅샷이 2개 이상 필요합니다 (점수·진행이 바뀔 때마다 덤프, 3개 이상 권장).")
        return out
    size = _common_length(snaps, warnings)
    out["length"] = size
    mask = _diff_mask(snaps, 0, size, ctl)
    if mask is None:
        out.update({"changed_bytes": None, "ranges_total": None, "truncated": True})
        warnings.append("시간 예산을 넘겨 비교를 끝내지 못했습니다 — changed_bytes/ranges_total 을 모릅니다. 범위를 좁혀 다시 실행하세요.")
        return out
    nz = mask.translate(_T_NONZERO)
    del mask
    total = _count_ranges(nz, gap)
    out["changed_bytes"] = size - nz.count(0)
    out["ranges_total"] = total
    out["truncated"] = total > cap
    if total == 0:
        warnings.append("스냅샷이 모두 같습니다 (공통 길이 안에서) — 값이 바뀐 뒤에 다시 덤프하세요.")
    for i, (s, e) in enumerate(_iter_merged(nz, gap, 0)):
        if i >= cap:
            break
        if (i & 0xFF) == 0xFF and _tick(ctl):
            out["truncated"] = True
            warnings.append(f"시간 예산을 넘겨 앞쪽 {i}개 구간만 해석했습니다 (전체 {total}개).")
            break
        item: dict[str, Any] = {
            "offset": s,
            "length": e - s,
            "values_hex": [snap[s : min(e, s + _MAX_HEX_BYTES)].hex() for snap in snaps],
            "interpretations": _interpretations(snaps, s, e, size),
        }
        if e - s > _MAX_HEX_BYTES:
            item["values_hex_truncated"] = True
        out["ranges"].append(item)
    return out


# ---------------------------------------------------------------------------
# 관측값 대조
# ---------------------------------------------------------------------------


def _parse_obs_value(v: Any, label: str, i: int, warnings: list[str]) -> int | None:
    if v is None:
        return None
    if _is_int(v):
        return v
    if isinstance(v, float) and v.is_integer():
        return int(v)
    if isinstance(v, str):
        t = v.strip().replace("_", "").replace(",", "")
        if t.lower() in ("", "?", "-", "none", "null", "unknown"):
            return None
        for base in (0, 10):
            try:
                return int(t, base)
            except ValueError:
                continue
    warnings.append(f"관측 '{label}' 의 {i}번째 값 {v!r} 은 정수가 아니라서 '모름'(None)으로 처리합니다.")
    return None


def _search_observation(snaps: list[bytes], known: list[tuple[int, int]], cap: int, ctl: Any) -> tuple[list[tuple[int, str]], int, bool, bool]:
    """알려진 (스냅샷, 값) 이 모두 맞는 (오프셋, 인코딩). 인코딩마다 가장 드문 패턴의 출현 위치만 다른 스냅샷과 대조한다."""
    negative = any(v < 0 for _, v in known)
    found: list[tuple[int, str]] = []
    tested = 0
    capped = timed_out = False
    for enc in ENCODINGS:
        w, _kind, _order, signed = _ENC[enc]
        if signed and not negative:
            continue  # 음수가 없으면 부호 없는 인코딩과 같은 위치에서만 맞으므로 생략
        try:
            pats = [(i, encode_value(v, enc)) for i, v in known]
        except SaveFormatError:
            continue  # 이 인코딩으로 표현할 수 없는 값이 있음
        last = min(len(snaps[i]) for i, _ in known) - w
        if last < 0:
            continue
        tested += last + 1
        if _tick(ctl):
            timed_out = True
            break
        end = last + w
        piv_i, piv_pat = min(pats, key=lambda ip: snaps[ip[0]].count(ip[1], 0, end))
        others = [(i, p) for i, p in pats if i != piv_i]
        buf = snaps[piv_i]
        pos = buf.find(piv_pat, 0, end)
        hits = steps = 0
        while pos != -1:
            steps += 1
            if all(snaps[i][pos : pos + w] == p for i, p in others):
                found.append((pos, enc))
                hits += 1
                if hits > cap:
                    capped = True
                    break
            if (steps & 0xFFF) == 0 and _tick(ctl):
                timed_out = True
                break
            pos = buf.find(piv_pat, pos + 1, end)
        if timed_out:
            break
    return found, tested, capped, timed_out


def match_observations(snapshots: list[bytes], observations: list[dict], *, max_results: int = 200, ctl: Any = None) -> dict[str, Any]:
    """사람이 본 값이 모든 스냅샷에서 그대로 읽히는 (오프셋, 인코딩)을 전수 탐색한다.

    ``observations``: ``[{"label": "score", "values": [100, 250, None, 400]}]`` — 스냅샷마다 값 하나, None 은 모름.
    값은 정수(또는 ``"0x64"``/``"-3"`` 같은 정수 문자열)이고 음수도 된다. 알려진 값이 2개 이상이고 그중 서로 다른 값이 있어야
    탐색한다 (상수는 어디서나 맞으므로 경고 후 건너뜀). 음수가 하나라도 있으면 부호 있는 인코딩(i8/i16/i32)만 맞을 수 있고,
    알려진 값이 모두 0 이상이면 부호 있는 인코딩은 부호 없는 쪽과 같은 위치에서만 맞으므로 생략한다. 표현할 수 없는 값이
    있는 인코딩(예: 70000 의 u16, 음수의 BCD)도 건너뛴다.

    반환 ``matches[{label, offset, encoding, width, aligned, values}]`` 의 ``values`` 는 모든 스냅샷에서 읽은 값(모름 칸 포함)이다.
    관측마다 정렬 위치 우선 → 오프셋 → 인코딩 순이고, 여러 관측이면 ``max_results`` 를 관측끼리 번갈아 채운다.
    ``tested`` 는 탐색한 (오프셋, 인코딩) 조합 수, ``per_observation`` 은 관측별 찾은 수다.
    같은 오프셋에서 u16 과 u32 가 함께 맞는 것처럼 데이터만으로 구분할 수 없는 경우가 있다 — 모두 위치 **후보**다.
    """
    warnings: list[str] = []
    snaps = _coerce_snapshots(snapshots)
    n = len(snaps)
    cap = max_results if _is_int(max_results) and max_results >= 0 else 200
    out: dict[str, Any] = {"matches": [], "tested": 0, "truncated": False, "per_observation": [], "warnings": warnings}
    if n == 0:
        warnings.append("스냅샷이 없습니다.")
        return out
    if not isinstance(observations, (list, tuple)):
        raise SaveFormatError("observations 는 [{label, values}] 목록이어야 합니다.")
    lengths = [len(s) for s in snaps]
    if max(lengths) != min(lengths):
        warnings.append(f"스냅샷 길이가 다릅니다 {lengths} — 각 오프셋은 값이 알려진 모든 스냅샷 안에 있어야 합니다.")
    per_obs: list[tuple[str, list[dict[str, Any]], bool]] = []
    for idx, ob in enumerate(observations):
        if not isinstance(ob, dict):
            warnings.append(f"observations[{idx}] 는 사전이 아니라서 건너뜁니다.")
            continue
        label = str(ob.get("label") or f"obs{idx}")
        raw = ob.get("values")
        if not isinstance(raw, (list, tuple)):
            warnings.append(f"관측 '{label}' 에 values 목록이 없어 건너뜁니다.")
            continue
        if len(raw) != n:
            warnings.append(f"관측 '{label}' 의 값 개수({len(raw)})가 스냅샷 수({n})와 다릅니다 — 모자란 칸은 모름, 남는 값은 버립니다.")
        vals = [_parse_obs_value(raw[i] if i < len(raw) else None, label, i, warnings) for i in range(n)]
        known = [(i, v) for i, v in enumerate(vals) if v is not None]
        if len(known) < 2 or len({v for _, v in known}) < 2:
            warnings.append(
                f"관측 '{label}': 알려진 값이 2개 이상이고 서로 달라야 합니다 (상수·값 하나는 어디서나 맞음) — 건너뜁니다. "
                "값이 바뀐 스냅샷을 더 받으세요."
            )
            out["per_observation"].append({"label": label, "known": len(known), "found": 0, "skipped": True})
            continue
        found, tested, capped, timed_out = _search_observation(snaps, known, cap, ctl)
        out["tested"] += tested
        items = [
            {
                "label": label,
                "offset": off,
                "encoding": enc,
                "width": _ENC[enc][0],
                "aligned": off % _ENC[enc][0] == 0,
                "values": [decode_value(s, off, enc) for s in snaps],
            }
            for off, enc in found
        ]
        items.sort(key=lambda m: (not m["aligned"], m["offset"], _ENC_INDEX[m["encoding"]]))
        per_obs.append((label, items, capped))
        out["per_observation"].append({"label": label, "known": len(known), "found": len(items), "truncated": capped or len(items) > cap})
        if timed_out:
            warnings.append("시간 예산을 넘겨 탐색을 멈췄습니다 — 부분 결과입니다.")
            out["truncated"] = True
            break
    selected: list[tuple[int, int, dict[str, Any]]] = []
    pos = [0] * len(per_obs)
    while len(selected) < cap:
        progressed = False
        for k, (_label, items, _capped) in enumerate(per_obs):
            if pos[k] < len(items) and len(selected) < cap:
                selected.append((k, pos[k], items[pos[k]]))
                pos[k] += 1
                progressed = True
        if not progressed:
            break
    selected.sort(key=lambda t: (t[0], t[1]))
    out["matches"] = [m for _k, _i, m in selected]
    if any(pos[k] < len(items) or capped for k, (_l, items, capped) in enumerate(per_obs)):
        out["truncated"] = True
    return out


# ---------------------------------------------------------------------------
# 체크섬 알고리즘
# ---------------------------------------------------------------------------


def _crc_spec(width: int, poly: int, init: int, refin: bool, xorout: int, check: int, description: str) -> dict[str, Any]:
    return {
        "width": width,
        "kind": "crc",
        "bits": 8 * width,
        "poly": poly,
        "init": init,
        "refin": refin,
        "refout": refin,
        "xorout": xorout,
        "check": check,
        "description": description,
    }


# 이름 → 매개변수. poly/init/xorout 은 reveng 카탈로그 표기(poly 는 비반사 표기), check 는 b"123456789" 의 공개 검사값.
CHECKSUM_ALGORITHMS: dict[str, dict[str, Any]] = {
    "sum8": {"width": 1, "kind": "sum", "modulus": 1 << 8, "description": "바이트 합 mod 2^8"},
    "negsum8": {
        "width": 1,
        "kind": "sum",
        "modulus": 1 << 8,
        "transform": "neg",
        "description": "바이트 합의 2의 보수: (데이터 합 + 체크섬) mod 256 == 0",
    },
    "notsum8": {"width": 1, "kind": "sum", "modulus": 1 << 8, "transform": "not", "description": "바이트 합의 1의 보수: 0xFF - (합 mod 256)"},
    "xor8": {"width": 1, "kind": "xor", "description": "모든 바이트의 XOR"},
    "crc8": _crc_spec(1, 0x07, 0x00, False, 0x00, 0xF4, "CRC-8/SMBUS (poly 0x07, init 0)"),
    "crc8-maxim": _crc_spec(1, 0x31, 0x00, True, 0x00, 0xA1, "CRC-8/MAXIM-DOW (반사, poly 0x31 = 반사 0x8C, init 0, 1-Wire)"),
    "sum16": {"width": 2, "kind": "sum", "modulus": 1 << 16, "description": "바이트 합 mod 2^16 (워드 합이 아님)"},
    "sum16le": {
        "width": 2,
        "kind": "wordsum",
        "word_size": 2,
        "word_order": "little",
        "modulus": 1 << 16,
        "description": "u16le 워드 합 mod 2^16 (홀수 길이면 마지막 바이트를 0 으로 채움, 탐색은 워드 정렬 범위만)",
    },
    "sum16be": {
        "width": 2,
        "kind": "wordsum",
        "word_size": 2,
        "word_order": "big",
        "modulus": 1 << 16,
        "description": "u16be 워드 합 mod 2^16 (홀수 길이면 마지막 바이트를 0 으로 채움, 탐색은 워드 정렬 범위만)",
    },
    "fletcher16": {"width": 2, "kind": "fletcher16", "description": "Fletcher-16 (mod 255, 값 = sum2<<8 | sum1)"},
    "crc16-ccitt-false": _crc_spec(2, 0x1021, 0xFFFF, False, 0x0000, 0x29B1, "CRC-16/IBM-3740 (CCITT-FALSE, poly 0x1021, init 0xFFFF)"),
    "crc16-xmodem": _crc_spec(2, 0x1021, 0x0000, False, 0x0000, 0x31C3, "CRC-16/XMODEM (poly 0x1021, init 0)"),
    "crc16-kermit": _crc_spec(2, 0x1021, 0x0000, True, 0x0000, 0x2189, "CRC-16/KERMIT (반사, 0x1021 = 반사 0x8408, init 0)"),
    "crc16-x25": _crc_spec(2, 0x1021, 0xFFFF, True, 0xFFFF, 0x906E, "CRC-16/IBM-SDLC (X-25, 반사 0x8408, init·xorout 0xFFFF)"),
    "crc16-modbus": _crc_spec(2, 0x8005, 0xFFFF, True, 0x0000, 0x4B37, "CRC-16/MODBUS (반사, 0x8005 = 반사 0xA001, init 0xFFFF)"),
    "crc16-arc": _crc_spec(2, 0x8005, 0x0000, True, 0x0000, 0xBB3D, "CRC-16/ARC (반사 0xA001, init 0)"),
    "sum32": {"width": 4, "kind": "sum", "modulus": 1 << 32, "description": "바이트 합 mod 2^32 (워드 합이 아님)"},
    "sum32le": {
        "width": 4,
        "kind": "wordsum",
        "word_size": 4,
        "word_order": "little",
        "modulus": 1 << 32,
        "description": "u32le 워드 합 mod 2^32 (길이가 4 의 배수가 아니면 0 으로 채움, 탐색은 워드 정렬 범위만)",
    },
    "sum32be": {
        "width": 4,
        "kind": "wordsum",
        "word_size": 4,
        "word_order": "big",
        "modulus": 1 << 32,
        "description": "u32be 워드 합 mod 2^32 (길이가 4 의 배수가 아니면 0 으로 채움, 탐색은 워드 정렬 범위만)",
    },
    "adler32": {"width": 4, "kind": "adler32", "check": 0x091E01DE, "description": "Adler-32 (zlib.adler32)"},
    "crc32": _crc_spec(4, 0x04C11DB7, 0xFFFFFFFF, True, 0xFFFFFFFF, 0xCBF43926, "CRC-32/ISO-HDLC (zlib.crc32)"),
    "crc32-jamcrc": _crc_spec(4, 0x04C11DB7, 0xFFFFFFFF, True, 0x00000000, 0x340BC6D9, "CRC-32/JAMCRC (= crc32 ^ 0xFFFFFFFF)"),
    "crc32-mpeg2": _crc_spec(
        4, 0x04C11DB7, 0xFFFFFFFF, False, 0x00000000, 0x0376E6E7, "CRC-32/MPEG-2 (비반사, STM32 하드웨어 CRC 기본 매개변수 — 워드 입력 순서 주의)"
    ),
    "crc32-bzip2": _crc_spec(4, 0x04C11DB7, 0xFFFFFFFF, False, 0xFFFFFFFF, 0xFC891918, "CRC-32/BZIP2 (비반사, xorout 0xFFFFFFFF)"),
}
_ALG_INDEX = {a: i for i, a in enumerate(CHECKSUM_ALGORITHMS)}


def _alg_spec(name: Any) -> dict[str, Any]:
    try:
        return CHECKSUM_ALGORITHMS[name]
    except (KeyError, TypeError):
        raise SaveFormatError(f"알 수 없는 체크섬 알고리즘: {name!r} (가능: {', '.join(CHECKSUM_ALGORITHMS)})") from None


def _reflect(v: int, bits: int) -> int:
    r = 0
    for _ in range(bits):
        r = (r << 1) | (v & 1)
        v >>= 1
    return r


@functools.lru_cache(maxsize=None)
def _crc_table(bits: int, poly: int, refin: bool) -> tuple[int, ...]:
    mask = (1 << bits) - 1
    table = []
    if refin:
        rpoly = _reflect(poly, bits)
        for i in range(256):
            c = i
            for _ in range(8):
                c = (c >> 1) ^ rpoly if c & 1 else c >> 1
            table.append(c)
    else:
        top = 1 << (bits - 1)
        for i in range(256):
            c = i << (bits - 8)
            for _ in range(8):
                c = ((c << 1) ^ poly) & mask if c & top else (c << 1) & mask
            table.append(c)
    return tuple(table)


def _zlib_update(reg: int, data: Any) -> int:
    return zlib.crc32(data, reg)


def _hqx_update(reg: int, data: Any) -> int:
    return binascii.crc_hqx(data, reg)


@functools.lru_cache(maxsize=None)
def _crc_updater(bits: int, poly: int, refin: bool) -> Callable[[int, Any], int]:
    """(레지스터, 데이터) → 레지스터. refin 이면 레지스터는 반사된 형태다. CRC-16 0x1021 비반사는 binascii.crc_hqx(C)."""
    if (bits, poly, refin) == (16, 0x1021, False):
        return _hqx_update
    t = _crc_table(bits, poly, refin)
    if bits == 8:

        def upd8(reg: int, data: Any, t: tuple[int, ...] = t) -> int:
            for b in data:
                reg = t[reg ^ b]
            return reg

        return upd8
    if refin:

        def upd_r(reg: int, data: Any, t: tuple[int, ...] = t) -> int:
            for b in data:
                reg = (reg >> 8) ^ t[(reg ^ b) & 0xFF]
            return reg

        return upd_r
    sh = bits - 8
    mask = (1 << bits) - 1

    def upd_n(reg: int, data: Any, t: tuple[int, ...] = t, sh: int = sh, mask: int = mask) -> int:
        for b in data:
            reg = ((reg << 8) & mask) ^ t[(reg >> sh) ^ b]
        return reg

    return upd_n


def _crc_zero_step(bits: int, poly: int, refin: bool) -> Callable[[int], int]:
    """0 바이트 하나를 처리한 레지스터 (초기값 기여 표를 만들 때)."""
    t = _crc_table(bits, poly, refin)
    if bits == 8:
        return lambda z: t[z]
    if refin:
        return lambda z: (z >> 8) ^ t[z & 0xFF]
    sh = bits - 8
    mask = (1 << bits) - 1
    return lambda z: ((z << 8) & mask) ^ t[z >> sh]


def _crc_compute(spec: dict[str, Any], buf: Any) -> int:
    bits = spec["bits"]
    if (bits, spec["poly"], spec["refin"]) == (32, 0x04C11DB7, True):
        return zlib.crc32(buf) ^ 0xFFFFFFFF ^ spec["xorout"]
    init = _reflect(spec["init"], bits) if spec["refin"] else spec["init"]
    return _crc_updater(bits, spec["poly"], spec["refin"])(init, buf) ^ spec["xorout"]


def checksum_compute(algorithm: str, data: bytes) -> int:
    """``data`` 전체에 대한 ``algorithm`` 값 (정수). 알 수 없는 알고리즘이면 SaveFormatError.

    합계류: ``sum8/16/32`` 는 바이트 합, ``sum16le/be``·``sum32le/be`` 는 워드 합(남는 바이트는 0 으로 채운 워드),
    ``negsum8`` 은 2의 보수, ``notsum8`` 은 1의 보수. 저장 엔디언은 이 함수가 아니라 저장 위치를 읽을 때 정한다.
    """
    spec = _alg_spec(algorithm)
    buf = _to_bytes(data, "data")
    kind = spec["kind"]
    if kind == "sum":
        total = sum(buf)
        m = spec["modulus"]
        tr = spec.get("transform")
        if tr == "neg":
            return (-total) % m
        if tr == "not":
            return (m - 1 - total) % m
        return total % m
    if kind == "xor":
        return functools.reduce(operator.xor, buf, 0)
    if kind == "wordsum":
        ws = spec["word_size"]
        padded = buf + b"\x00" * ((-len(buf)) % ws)
        return sum(_words(padded, ws, spec["word_order"])) % spec["modulus"]
    if kind == "fletcher16":
        s1 = s2 = 0
        for b in buf:
            s1 = (s1 + b) % 255
            s2 = (s2 + s1) % 255
        return (s2 << 8) | s1
    if kind == "adler32":
        return zlib.adler32(buf)
    return _crc_compute(spec, buf)


def _stored_value(buf: Any, loc: int, w: int, endian: str | None) -> int:
    if w == 1:
        return buf[loc]
    return int.from_bytes(bytes(buf[loc : loc + w]), "little" if endian == "le" else "big")


def _pack_stored(value: int, w: int, endian: str | None) -> bytes:
    return value.to_bytes(w, "big" if endian == "be" else "little")


# ---------------------------------------------------------------------------
# 체크섬 후보 탐색
# ---------------------------------------------------------------------------

_CHECK_COST = 8  # CRC 체크포인트 비교 1회를 해시 바이트 몇 개로 칠지 (예산 계산)
_STRONG_EFP = 0.01  # 기대 오탐 수가 이 값 이상이면 weak
_MAX_LOCATIONS = 1 << 16  # 폭마다 위치 창 상한 (넘으면 폭 정렬 창만, 그래도 넘으면 앞쪽만)
_MAX_VARIANTS = 8  # (알고리즘, 엔디언, 위치) 마다 보관할 범위 변형 수
_STAGE2_CAP = 4096  # Fletcher/Adler 2단계 확인 상한 (조회 1회당)
_SHARE_INIT_MAX = 1 << 20  # 이보다 큰 영역은 CRC 레지스터를 초기값별로 따로 (0 바이트 표 메모리 상한)
_MAX_RAW_PER_WIDTH = 40_000  # 폭마다 (알고리즘, 엔디언, 위치) 묶음 수 상한 — 8비트 잡음이 넓은 체크섬 자리를 빼앗지 않게
_ADD_SCAN = 512  # 조회 한 번에서 대표 범위를 고를 때 보는 변형 수 (앞·뒤 각각; 개수는 따로 정확히 센다)
_PASS_CHUNK = 1 << 16  # CRC 패스를 이 크기로 나눠 계산하며 시간 예산을 확인
_TIERS = 7  # 패스 우선순위 등급 수 (_align_tier + 비정렬 위치)


def _min_range(w: int) -> int:
    """범위 최소 길이: 체크섬 폭의 2배 (값 하나의 사본을 체크섬으로 착각하지 않게)."""
    return 2 * w


def _endpoint_align(span: int) -> int:
    """자유 끝점 정렬: 끝점 수를 약 6만 개 이하로 유지 (사전 메모리)."""
    if span <= (256 << 10):
        return 4
    if span <= (1 << 20):
        return 16
    if span <= (4 << 20):
        return 64
    if span <= (16 << 20):
        return 256
    return 1024


def _endpoints(r0: int, r1: int, align: int) -> list[int]:
    pts = [r0]
    pts.extend(range((r0 // align + 1) * align, r1, align))
    if r1 > r0:
        pts.append(r1)
    return pts


def _align_tier(x: int, bound: int) -> int:
    if x == bound:
        return 0
    if x % 4096 == 0:
        return 1
    if x % 256 == 0:
        return 2
    if x % 16 == 0:
        return 3
    if x % 4 == 0:
        return 4
    return 5


def _collect_windows(mask: bytes, r0: int, r1: int, w: int, step: int, limit: int) -> tuple[list[int], bool]:
    """바뀐 바이트를 덮는 폭 w 창의 시작 위치를 앞에서부터(step 의 배수만). limit 개를 넘으면 (앞쪽 limit 개, True)."""
    out: list[int] = []
    last = r0 - 1
    for a, b in _iter_runs(mask, r0):
        lo = max(r0, a - w + 1, last + 1)
        hi = min(b - 1, r1 - w)
        if step > 1:
            lo += (-lo) % step
        if lo > hi:
            continue
        cnt = (hi - lo) // step + 1
        if len(out) + cnt > limit:
            out.extend(range(lo, lo + (limit - len(out)) * step, step))
            return out, True
        out.extend(range(lo, hi + 1, step))
        last = hi
    return out, False


def _location_windows(mask: bytes, r0: int, r1: int, w: int, notes: list[str]) -> list[int]:
    """바뀐 바이트를 하나 이상 덮는 폭 w 창의 시작 위치 (영역 안). 구간을 하나씩 보며 상한에 닿으면 멈춘다."""
    locs, over = _collect_windows(mask, r0, r1, w, 1, _MAX_LOCATIONS)
    if not over:
        return locs
    note = f"폭 {w} 위치 창이 {_MAX_LOCATIONS}개를 넘어"
    if w > 1:
        locs, over = _collect_windows(mask, r0, r1, w, w, _MAX_LOCATIONS)
        note += " 폭 정렬 창만 시험합니다"
    if over:
        note += f" (앞쪽 {_MAX_LOCATIONS}개만)"
    notes.append(note + " — 바뀐 바이트가 너무 많으면 세이브가 아니거나 암호화·압축된 영역일 수 있습니다.")
    return locs


class _ChangeCount:
    """영역 마스크에서 [s, e) 의 바뀐 바이트 수: 격자(step) 누적 + 격자 사이는 bytes.count (조회당 O(step), C 수준)."""

    def __init__(self, mask: bytes, r0: int, step: int) -> None:
        self.mask, self.r0, self.step = mask, r0, step
        grid = [0]
        acc = 0
        size = len(mask)
        for i in range(0, size, step):
            j = min(size, i + step)
            acc += (j - i) - mask.count(0, i, j)
            grid.append(acc)
        self.grid = array("q", grid)

    def _prefix(self, x: int) -> int:
        rel = x - self.r0
        i = rel // self.step
        base = i * self.step
        return self.grid[i] + (rel - base) - self.mask.count(0, base, rel)

    def count(self, s: int, e: int) -> int:
        return self._prefix(e) - self._prefix(s) if e > s else 0


class _RunIndex:
    """정렬된 (start, end) 구간 목록의 누적 길이 색인: [s, e) 와 겹치는 길이를 bisect 로."""

    def __init__(self, runs: Sequence[tuple[int, int]]) -> None:
        self.starts = [a for a, _ in runs]
        self.ends = [b for _, b in runs]
        self.cum = [0, *accumulate(b - a for a, b in runs)]

    def count(self, s: int, e: int) -> int:
        if e <= s:
            return 0
        i = bisect_right(self.ends, s)  # 끝이 s 보다 큰 첫 구간
        j = bisect_left(self.starts, e)  # 시작이 e 보다 작은 마지막 구간 다음
        if i >= j:
            return 0
        return self.cum[j] - self.cum[i] - max(0, s - self.starts[i]) - max(0, self.ends[j - 1] - e)


def _changed_in(runs: Sequence[tuple[int, int]], s: int, e: int) -> int:
    """구간 목록 runs 가 [s, e) 와 겹치는 길이 (호환용 — 탐색 안에서는 마스크 기반 _ChangeCount 를 쓴다)."""
    return _RunIndex(runs).count(s, e)


class _SnapSums:
    """한 스냅샷의 영역 [r0, r1) 누적값. 격자(r0 + i·step)마다 저장하고 나머지는 직접 더한다."""

    def __init__(self, snap: bytes, r0: int, r1: int, step: int) -> None:
        self.snap = snap
        self.mv = memoryview(snap)
        self.r0, self.r1, self.step = r0, r1, step
        self._b: array | None = None
        self._q: array | None = None
        self._x: bytes | None = None
        self._w: dict[tuple[int, str], tuple[int, array]] = {}

    def bsum(self, x: int) -> int:
        """Σ snap[r0:x]"""
        if self._b is None:
            self._b = array("q", islice(accumulate(self.mv[self.r0 : self.r1], initial=0), 0, None, self.step))
        i = (x - self.r0) // self.step
        base = self.r0 + i * self.step
        return self._b[i] + sum(self.snap[base:x])

    def qsum(self, x: int) -> int:
        """Σ (y - r0)·snap[y], r0 ≤ y < x"""
        if self._q is None:
            seg = self.mv[self.r0 : self.r1]
            self._q = array("q", islice(accumulate(map(operator.mul, range(len(seg)), seg), initial=0), 0, None, self.step))
        i = (x - self.r0) // self.step
        base = self.r0 + i * self.step
        return self._q[i] + sum((y - self.r0) * self.snap[y] for y in range(base, x))

    def xsum(self, x: int) -> int:
        """XOR snap[r0:x]"""
        if self._x is None:
            self._x = bytes(islice(accumulate(self.mv[self.r0 : self.r1], operator.xor, initial=0), 0, None, self.step))
        i = (x - self.r0) // self.step
        v = self._x[i]
        for b in self.snap[self.r0 + i * self.step : x]:
            v ^= b
        return v

    def wsum(self, ws: int, order: str, x: int) -> int:
        """ws 의 배수 위치에서 시작하는 워드의 합, 영역 안 첫 정렬 위치부터 x(ws 의 배수) 앞까지."""
        g = self._w.get((ws, order))
        if g is None:
            a = -(-self.r0 // ws) * ws
            cnt = max(0, (self.r1 - a) // ws)
            words = _words(self.snap[a : a + cnt * ws], ws, order)
            g = (a, array("q", islice(accumulate(words, initial=0), 0, None, self.step // ws)))
            self._w[(ws, order)] = g
        a, arr = g
        i = (x - a) // self.step
        base = a + i * self.step
        part = sum(_words(self.snap[base:x], ws, order)) if x > base else 0
        return arr[i] + part


class _Engine:
    """같은 (bits, poly, refin) 을 쓰는 CRC 들의 레지스터 하나. 다른 초기값은 0 바이트 표(선형성)로 보정한다."""

    def __init__(self, width: int, start: int, update: Callable[[int, Any], int], step0: Callable[[int], int] | None, algs: list[tuple[str, int, int]]) -> None:
        self.width = width
        self.start = start
        self.update = update
        self.step0 = step0
        self.algs = algs  # (이름, 초기값 보정, 최종 XOR)
        self.zero: dict[int, array] = {}

    def zero_missing(self, corr: int, upto: int) -> int:
        """zero_table(corr, upto) 가 새로 계산해야 하는 항목 수 (예산 미리 계산용)."""
        arr = self.zero.get(corr)
        return max(0, upto + 1 - (len(arr) if arr is not None else 1))

    def zero_table(self, corr: int, upto: int) -> array:
        """corr 를 초기 레지스터로 0 바이트 k 개를 처리한 값 (k = 0..upto). reg(I, d) = reg(0, d) ^ reg(I, 0^k)."""
        arr = self.zero.get(corr)
        if arr is None:
            arr = self.zero[corr] = array("Q", [corr])
        if len(arr) <= upto:
            step = self.step0
            z = arr[-1]
            ext = []
            for _ in range(upto + 1 - len(arr)):
                z = step(z)  # type: ignore[misc]
                ext.append(z)
            arr.extend(ext)
        return arr


def _build_engines(names: Sequence[str], share_init: bool = True) -> list[_Engine]:
    """CRC 엔진 묶음. share_init 이면 초기값만 다른 CRC 가 레지스터 하나를 쓰고 0 바이트 표(길이 = 패스 길이)로 보정한다."""
    groups: dict[tuple[int, ...], list[str]] = {}
    for name in names:
        spec = CHECKSUM_ALGORITHMS[name]
        key: tuple[int, ...] = (spec["bits"], spec["poly"], spec["refin"])
        if not share_init and key != (32, 0x04C11DB7, True):
            key += (spec["init"],)
        groups.setdefault(key, []).append(name)
    engines = []
    for gkey, algs in groups.items():
        bits, poly, refin = gkey[0], gkey[1], bool(gkey[2])
        mask = (1 << bits) - 1
        if (bits, poly, refin) == (32, 0x04C11DB7, True):
            # zlib.crc32 는 초기값·최종 XOR 0xFFFFFFFF 를 안에서 처리한다 → 레지스터 = zlib 값
            engines.append(_Engine(4, 0, _zlib_update, None, [(a, 0, mask ^ CHECKSUM_ALGORITHMS[a]["xorout"]) for a in algs]))
            continue
        inits = {a: (_reflect(CHECKSUM_ALGORITHMS[a]["init"], bits) if refin else CHECKSUM_ALGORITHMS[a]["init"]) for a in algs}
        base = inits[algs[0]]
        engines.append(
            _Engine(
                bits // 8,
                base,
                _crc_updater(bits, poly, refin),
                _crc_zero_step(bits, poly, refin),
                [(a, inits[a] ^ base, CHECKSUM_ALGORITHMS[a]["xorout"]) for a in algs],
            )
        )
    return engines


def _key(vals: Iterable[int], mod: int) -> int:
    """스냅샷별 값(0 ≤ v < mod)을 정수 하나로 묶은 사전 키 (튜플보다 메모리가 적다)."""
    k = 0
    for v in vals:
        k = k * mod + v
    return k


def _efp(tested: int, w: int, distinct: int) -> float:
    if tested <= 0:
        return 0.0
    v = math.ldexp(float(tested), -8 * w * max(1, distinct))
    return float(f"{v:.3g}")


def _sample(lst: Sequence[int], a: int, b: int) -> Sequence[int]:
    """lst[a:b] 가 길면 앞뒤 _ADD_SCAN 개씩만 (대표 범위 고르기용 — 맞은 범위 개수는 따로 센다)."""
    if b - a <= 2 * _ADD_SCAN:
        return lst[a:b]
    return [*lst[a : a + _ADD_SCAN], *lst[b - _ADD_SCAN : b]]


def _tget(table: dict[int, Any], key: int) -> Sequence[int]:
    """table() 사전 조회: 끝점 오름차순 열 (없으면 빈 튜플)."""
    v = table.get(key)
    if v is None:
        return ()
    return v if isinstance(v, list) else (v,)


def _table_key(spec: dict[str, Any]) -> tuple[Any, ...]:
    """합계류 알고리즘이 쓰는 끝점 사전의 키 (같은 키는 사전을 함께 쓴다)."""
    kind = spec["kind"]
    if kind == "wordsum":
        return ("w", spec["word_size"], spec["word_order"])
    if kind == "xor":
        return ("x",)
    if kind == "fletcher16":
        return ("b", 255)
    if kind == "adler32":
        return ("b", 65521)
    return ("b", spec["modulus"])


def _tagged(lst: Sequence[int], n: int, shape: int, ei: int) -> Iterator[tuple[int, int, int]]:
    """패스 계획용: lst 앞 n 개 위치에 (모양, 엔진 번호)를 붙인다 (생성기 식의 늦은 바인딩을 피하려고 함수로)."""
    for i in range(n):
        yield lst[i], shape, ei


def _cancel_check(ctl: Any) -> None:
    """취소만 확인한다 (시간 예산이 지나도 이미 찾은 결과의 마무리는 한다)."""
    fn = getattr(ctl, "check", None) if ctl is not None else None
    if callable(fn):
        fn()


class _Search:
    """find_checksums 의 탐색 상태. raw[(alg, endian, loc)] = [맞은 범위 수, 범위 목록(최대 variant_cap)].

    예산 불변식: CRC 패스(첫 스냅샷 선별, 나머지 스냅샷 확인, 0 바이트 표 확장)는 시작 전에 정확한 비용을 계산해
    ``hashed + checks × _CHECK_COST + 비용 ≤ max_bytes`` 일 때만 돌린다 — 예산을 넘기는 일이 없다.
    """

    def __init__(self, snaps: list[bytes], r0: int, r1: int, mask: bytes, names: list[str], max_bytes: int, ctl: Any, notes: list[str], variant_cap: int) -> None:
        self.snaps = snaps
        self.n = len(snaps)
        self.r0, self.r1 = r0, r1
        self.names = names
        self.max_bytes = max_bytes
        self.ctl = ctl
        self.notes = notes
        self.variant_cap = variant_cap
        self.align = _endpoint_align(r1 - r0)
        self.endpoints = _endpoints(r0, r1, self.align)
        widths = sorted({CHECKSUM_ALGORITHMS[a]["width"] for a in names})
        self.locs = {w: _location_windows(mask, r0, r1, w, notes) for w in widths}
        self.raw: dict[tuple[str, str | None, int], list[Any]] = {}
        self.raw_count: Counter = Counter()
        self.raw_capped = False
        self.tested: Counter = Counter()
        self.hashed = 0
        self.checks = 0
        self.timed_out = False
        self.budget_exhausted = False
        self.passes_run = 0
        self.passes_skipped = 0
        self.skipped_tiers: Counter = Counter()
        self.verify_dropped = 0
        self.stage2_capped = False
        self._t2 = 0
        self._sums: list[_SnapSums] | None = None
        self._tables: dict[Any, dict[int, list[int]]] = {}
        self._mvs = [memoryview(s) for s in snaps]
        self._st0: dict[int, tuple[array, array]] = {}
        self._engines: list[_Engine] | None = None
        self._plan_iter: Iterator[tuple[int, int, int, int]] | None = None
        self._plan_totals: Counter = Counter()
        self._plan_done: Counter = Counter()
        self._pending: tuple[int, int, int, int] | None = None

    # -- 공통 --------------------------------------------------------------

    def stored(self, w: int, loc: int, endian: str | None) -> tuple[int, ...]:
        return tuple(_stored_value(s, loc, w, endian) for s in self.snaps)

    def add(self, alg: str, endian: str | None, loc: int, ranges: Iterable[tuple[int, int]], count: int) -> None:
        """맞은 범위를 묶는다. 범위 변형은 대표 우선순위(_range_pref)가 높은 variant_cap 개만, 묶음 수는 폭마다 상한."""
        key = (alg, endian, loc)
        g = self.raw.get(key)
        if g is None:
            w = CHECKSUM_ALGORITHMS[alg]["width"]
            if self.raw_count[w] >= _MAX_RAW_PER_WIDTH:
                self.raw_capped = True
                return
            self.raw_count[w] += 1
            g = self.raw[key] = [0, []]
        g[0] += count
        pool = list(dict.fromkeys([*g[1], *ranges]))
        if len(pool) > self.variant_cap:
            r0, r1 = self.r0, self.r1
            pool = heapq.nsmallest(self.variant_cap, pool, key=lambda r: _range_pref(r, loc, r0, r1))
        g[1] = pool

    @property
    def sums(self) -> list[_SnapSums]:
        if self._sums is None:
            self._sums = [_SnapSums(s, self.r0, self.r1, self.align) for s in self.snaps]
        return self._sums

    def table(self, key: Any, pts: Sequence[int], fn: Callable[[_SnapSums, int], int], mod: int) -> dict[int, Any] | None:
        """끝점 x → (스냅샷별 fn(x) mod m) 을 묶은 키 사전. 조회 한 번에 모든 스냅샷을 확인한다. 시간 예산을 넘기면 None.

        값은 끝점 하나면 int, 여럿이면 오름차순 list (메모리). 조회는 _tget 으로.
        """
        t = self._tables.get(key)
        if t is None:
            t = {}
            sums = self.sums
            for i, x in enumerate(pts):
                if (i & 0xFFF) == 0xFFF and _tick(self.ctl):
                    self.timed_out = True
                    return None
                k = _key((fn(s, x) % mod for s in sums), mod)
                cur = t.get(k)
                if cur is None:
                    t[k] = x
                elif isinstance(cur, list):
                    cur.append(x)
                else:
                    t[k] = [cur, x]
            self._tables[key] = t
        return t

    # -- 합계류 (누적값 + 사전 조회, 끝점 전수) -------------------------------

    def run_sums(self) -> None:
        names = [a for a in self.names if CHECKSUM_ALGORITHMS[a]["kind"] != "crc"]
        last_use = {_table_key(CHECKSUM_ALGORITHMS[a]): i for i, a in enumerate(names)}
        for i, name in enumerate(names):
            spec = CHECKSUM_ALGORITHMS[name]
            if self.timed_out or _tick(self.ctl):
                self.timed_out = True
                break
            if spec["kind"] in ("fletcher16", "adler32"):
                self._two_stage(name, spec)
            else:
                self._separable(name, spec)
            for key, li in last_use.items():  # 더 쓰지 않는 끝점 사전은 바로 버린다 (최대 메모리)
                if li == i:
                    self._tables.pop(key, None)
        self._tables.clear()

    def _separable(self, name: str, spec: dict[str, Any]) -> None:
        """(F(e) - F(s)) mod M == T 또는 F(e) ^ F(s) == T 꼴: sum/negsum/notsum/xor/워드 합."""
        w = spec["width"]
        kind = spec["kind"]
        ml = _min_range(w)
        endians: tuple[str | None, ...] = (None,) if w == 1 else ("le", "be")
        if kind == "wordsum":
            ws, order, mod = spec["word_size"], spec["word_order"], spec["modulus"]
            pts = [x for x in self.endpoints if x % ws == 0]

            def fn(s: _SnapSums, x: int, ws: int = ws, order: str = order) -> int:
                return s.wsum(ws, order, x)

            xor = False
            locs = [x for x in self.locs[w] if x % ws == 0]
        elif kind == "xor":
            pts, mod, xor, locs = self.endpoints, 256, True, self.locs[w]
            fn = _SnapSums.xsum
        else:
            pts, mod, xor, locs = self.endpoints, spec["modulus"], False, self.locs[w]
            fn = _SnapSums.bsum
        tr = spec.get("transform")
        table = self.table(_table_key(spec), pts, fn, mod)
        if table is None:
            return
        sums = self.sums
        n = self.n
        for idx, loc in enumerate(locs):
            if (idx & 0xFF) == 0xFF and _tick(self.ctl):
                self.timed_out = True
                return
            b = loc + w
            fa = [fn(s, loc) for s in sums]
            fb = [fn(s, b) for s in sums]
            cnt = bisect_right(pts, loc - ml) + (len(pts) - bisect_left(pts, b + ml))
            for endian in endians:
                st = self.stored(w, loc, endian)
                if tr == "neg":
                    tgt = [(-v) % mod for v in st]
                elif tr == "not":
                    tgt = [(mod - 1 - v) % mod for v in st]
                else:
                    tgt = list(st)
                self.tested[w] += cnt
                if xor:
                    key_a = _key((fa[k] ^ tgt[k] for k in range(n)), mod)
                    key_b = _key((fb[k] ^ tgt[k] for k in range(n)), mod)
                else:
                    key_a = _key(((fa[k] - tgt[k]) % mod for k in range(n)), mod)
                    key_b = _key(((fb[k] + tgt[k]) % mod for k in range(n)), mod)
                lst = _tget(table, key_a)
                if lst:
                    c = bisect_right(lst, loc - ml)
                    if c:
                        self.add(name, endian, loc, [(s, loc) for s in _sample(lst, 0, c)], c)
                lst = _tget(table, key_b)
                if lst:
                    c0 = bisect_left(lst, b + ml)
                    if c0 < len(lst):
                        self.add(name, endian, loc, [(b, e) for e in _sample(lst, c0, len(lst))], len(lst) - c0)

    def _two_stage(self, name: str, spec: dict[str, Any]) -> None:
        """Fletcher-16 / Adler-32: 첫 성분(바이트 합)으로 사전 조회 → 둘째 성분(가중 합)을 누적값으로 확인."""
        w = spec["width"]
        ml = _min_range(w)
        fletcher = spec["kind"] == "fletcher16"
        m1, half, shift = (255, 0xFF, 8) if fletcher else (65521, 0xFFFF, 16)
        pts = self.endpoints
        table = self.table(_table_key(spec), pts, _SnapSums.bsum, m1)
        if table is None:
            return
        sums = self.sums
        n, r0 = self.n, self.r0

        def second_ok(s: int, e: int, seconds: list[int]) -> bool:
            for k, ss in enumerate(sums):
                d = ss.bsum(e) - ss.bsum(s)
                wsum = (e - r0) * d - (ss.qsum(e) - ss.qsum(s))  # Σ (e - y)·d_y
                v = wsum % 255 if fletcher else ((e - s) + wsum) % 65521
                if v != seconds[k]:
                    return False
            return True

        def verify(pairs: Iterable[tuple[int, int]], seconds: list[int]) -> list[tuple[int, int]] | None:
            ok = []
            for s, e in pairs:
                self._t2 += 1
                if (self._t2 & 0x1FF) == 0 and _tick(self.ctl):
                    self.timed_out = True
                    return None
                if second_ok(s, e, seconds):
                    ok.append((s, e))
            return ok

        for idx, loc in enumerate(self.locs[w]):
            if (idx & 0xFF) == 0xFF and _tick(self.ctl):
                self.timed_out = True
                return
            b = loc + w
            pa = [s.bsum(loc) for s in sums]
            pb = [s.bsum(b) for s in sums]
            cnt = bisect_right(pts, loc - ml) + (len(pts) - bisect_left(pts, b + ml))
            for endian in ("le", "be"):
                self.tested[w] += cnt
                st = self.stored(w, loc, endian)
                firsts = [v & half for v in st]
                seconds = [v >> shift for v in st]
                if max(firsts) >= m1 or max(seconds) >= m1:
                    continue  # mod m1 결과로 나올 수 없는 값
                if fletcher:
                    key_a = _key(((pa[k] - firsts[k]) % m1 for k in range(n)), m1)
                    key_b = _key(((pb[k] + firsts[k]) % m1 for k in range(n)), m1)
                else:
                    key_a = _key(((pa[k] + 1 - firsts[k]) % m1 for k in range(n)), m1)
                    key_b = _key(((pb[k] + firsts[k] - 1) % m1 for k in range(n)), m1)
                lst = _tget(table, key_a)
                if lst:
                    c = bisect_right(lst, loc - ml)
                    if c > _STAGE2_CAP:
                        self.stage2_capped = True
                    ok = verify(((s, loc) for s in lst[: min(c, _STAGE2_CAP)]), seconds)
                    if ok is None:
                        return
                    if ok:
                        self.add(name, endian, loc, ok, len(ok))
                lst = _tget(table, key_b)
                if lst:
                    c0 = bisect_left(lst, b + ml)
                    tail = lst[c0:]
                    if len(tail) > _STAGE2_CAP:
                        self.stage2_capped = True
                        tail = tail[-_STAGE2_CAP:]
                    ok = verify(((b, e) for e in reversed(tail)), seconds)
                    if ok is None:
                        return
                    if ok:
                        self.add(name, endian, loc, ok, len(ok))

    # -- CRC (패스 단위, 예산) ---------------------------------------------

    def _afford(self, cost: int) -> bool:
        return self.hashed + self.checks * _CHECK_COST + cost <= self.max_bytes

    def _st0_for(self, w: int) -> tuple[array, array]:
        """첫 스냅샷의 저장값 (le, be) 배열 — self.locs[w] 와 같은 순서 (폭 1 은 두 배열이 같다)."""
        d = self._st0.get(w)
        if d is None:
            mv0 = self._mvs[0]
            le = array("Q", (int.from_bytes(mv0[loc : loc + w], "little") for loc in self.locs[w]))
            be = le if w == 1 else array("Q", (int.from_bytes(mv0[loc : loc + w], "big") for loc in self.locs[w]))
            d = self._st0[w] = (le, be)
        return d

    def _plan(self, engines: list[_Engine]) -> tuple[Iterator[tuple[int, int, int, int]], Counter]:
        """패스 (등급, 위치, 모양, 엔진)를 우선순위 순서로 내는 생성기와 등급별 총 패스 수 (목록을 통째로 만들지 않음).

        모양 0 = [s, 위치) 를 시작 s 에서 한 번에, 1 = [위치+폭, e) 를 위치마다. 등급: 영역 경계 → 4096 → 256 → 16 → 4·폭 정렬 → 비정렬.
        """
        eps = self.endpoints
        r0 = self.r0
        ep_b: list[list[int]] = [[] for _ in range(_TIERS)]
        for s in eps[:-1]:  # 마지막 끝점은 r1
            ep_b[_align_tier(s, r0)].append(s)
        loc_b: dict[int, list[list[int]]] = {}
        for w in sorted({e.width for e in engines}):
            b: list[list[int]] = [[] for _ in range(_TIERS)]
            for loc in self.locs[w]:
                t = _align_tier(loc, r0)
                if t == 5:
                    t = 4 if loc % w == 0 else 6
                b[t].append(loc)
            loc_b[w] = b
        totals: Counter = Counter()
        streams: list[list[Iterator[tuple[int, int, int]]]] = [[] for _ in range(_TIERS)]
        for ei, eng in enumerate(engines):
            w = eng.width
            ml = _min_range(w)
            lw = self.locs[w]
            if not lw:
                continue
            amax = lw[-1] - ml  # 모양 0: s ≤ amax 여야 체크포인트(위치 ≥ s + ml)가 있다
            bmax = eps[-1] - w - ml  # 모양 1: 위치 ≤ bmax 여야 끝점(e ≥ 위치 + w + ml)이 있다
            for t in range(_TIERS):
                na = bisect_right(ep_b[t], amax)
                nb = bisect_right(loc_b[w][t], bmax)
                totals[t] += na + nb
                if na:
                    streams[t].append(_tagged(ep_b[t], na, 0, ei))
                if nb:
                    streams[t].append(_tagged(loc_b[w][t], nb, 1, ei))

        def gen() -> Iterator[tuple[int, int, int, int]]:
            for t in range(_TIERS):
                for pos, shape, ei in heapq.merge(*streams[t]):
                    yield t, pos, shape, ei

        return gen(), totals

    def _skip_rest(self) -> None:
        """남은 패스(보류 중인 패스 포함)를 건너뛴 것으로 센다."""
        for t in range(_TIERS):
            left = self._plan_totals[t] - self._plan_done[t]
            if left > 0:
                self.skipped_tiers[t] += left
                self.passes_skipped += left
        self._plan_iter = iter(())
        self._pending = None
        self._plan_totals = Counter()
        self._plan_done = Counter()

    def _run_pass(self, eng: _Engine, mv: memoryview, start: int, cps: Sequence[int]) -> list[int] | None:
        """start 에서 체크포인트까지 레지스터를 구한다. _PASS_CHUNK 마다·체크포인트 4096 개마다 시간 예산 확인 (넘기면 None)."""
        reg = eng.start
        upd = eng.update
        pos = start
        out: list[int] = []
        try:
            for i, cp in enumerate(cps):
                while cp - pos > _PASS_CHUNK:
                    reg = upd(reg, mv[pos : pos + _PASS_CHUNK])
                    pos += _PASS_CHUNK
                    if _tick(self.ctl):
                        self.timed_out = True
                        return None
                if cp > pos:
                    reg = upd(reg, mv[pos:cp])
                    pos = cp
                out.append(reg)
                if (i & 0xFFF) == 0xFFF and _tick(self.ctl):
                    self.timed_out = True
                    return None
            return out
        finally:
            self.hashed += pos - start
            self.checks += len(out)

    def run_crcs(self, max_tier: int = _TIERS) -> None:
        """우선순위 등급 max_tier 까지의 CRC 패스를 돌린다 (find_checksums 는 등급 0 을 합계류보다 먼저 돌린다)."""
        if self._engines is None:
            names = [a for a in self.names if CHECKSUM_ALGORITHMS[a]["kind"] == "crc"]
            self._engines = _build_engines(names, share_init=self.r1 - self.r0 <= _SHARE_INIT_MAX)
            self._plan_iter, self._plan_totals = self._plan(self._engines)
        if not self._engines or self._plan_iter is None:
            return
        if self.timed_out or self.budget_exhausted:
            self._skip_rest()  # 합계류 단계에서 시간이 끝났으면 남은 CRC 패스는 건너뛴 것으로 센다
            return
        eps = self.endpoints
        mv0 = self._mvs[0]
        total = sum(self._plan_totals.values())
        idx = 0
        while True:
            item = self._pending if self._pending is not None else next(self._plan_iter, None)
            self._pending = None
            if item is None:
                return
            tier, pos, shape, ei = item
            if tier > max_tier:
                self._pending = item
                return
            if (idx & 0x3F) == 0:
                _progress(self.ctl, sum(self._plan_done.values()), total, "CRC 후보 패스")
                if _tick(self.ctl):
                    self.timed_out = True
                    self._skip_rest()
                    return
            idx += 1
            eng = self._engines[ei]
            w = eng.width
            ml = _min_range(w)
            lw = self.locs[w]
            if shape == 0:
                start = pos
                i0 = bisect_left(lw, start + ml)
                cps = lw[i0:]
            else:
                start = pos + w
                i0 = bisect_left(lw, pos)  # 고정 위치의 저장값 색인
                cps = eps[bisect_left(eps, start + ml) :]
            span = cps[-1] - start
            corrs = sorted({corr for _a, corr, _x in eng.algs if corr})
            ext = sum(eng.zero_missing(c, span) for c in corrs)
            if not self._afford(span + len(cps) * _CHECK_COST + ext):
                self.budget_exhausted = True
                self._skip_rest()
                return
            for c in corrs:
                eng.zero_table(c, span)
            self.hashed += ext
            self._plan_done[tier] += 1
            regs = self._run_pass(eng, mv0, start, cps)
            if regs is None:
                self._skip_rest()
                return
            self.passes_run += 1
            self.tested[w] += len(cps) * len(eng.algs) * (1 if w == 1 else 2)
            st_le, st_be = self._st0_for(w)
            surv: list[tuple[int, int, str | None]] = []
            for i, (cp, reg) in enumerate(zip(cps, regs)):
                if (i & 0xFFF) == 0xFFF and _tick(self.ctl):
                    self.timed_out = True
                    self._skip_rest()
                    return
                k = cp - start
                j = i0 if shape == 1 else i0 + i
                le, be = st_le[j], st_be[j]
                for ai, (_alg, corr, xo) in enumerate(eng.algs):
                    v = reg ^ xo
                    if corr:
                        v ^= eng.zero[corr][k]
                    if v == le:
                        surv.append((cp, ai, None if w == 1 else "le"))
                    if w > 1 and v == be:  # le == be(대칭 바이트)여도 따로 확인한다
                        surv.append((cp, ai, "be"))
            if surv and not self._verify_batch(eng, start, shape, pos, surv):
                self._skip_rest()
                return

    def _verify_batch(self, eng: _Engine, start: int, shape: int, pos: int, surv: list[tuple[int, int, str | None]]) -> bool:
        """첫 스냅샷에서 맞은 체크포인트를 나머지 스냅샷마다 패스 한 번으로 확인한다 (예산·시간 초과면 False)."""
        w = eng.width
        for k in range(1, self.n):
            if not surv:
                return True
            vcps = sorted({cp for cp, _ai, _e in surv})
            if not self._afford((vcps[-1] - start) + len(vcps) * _CHECK_COST):
                self.budget_exhausted = True
                self.verify_dropped += len(surv)
                return False
            regs = self._run_pass(eng, self._mvs[k], start, vcps)
            if regs is None:
                self.verify_dropped += len(surv)
                return False
            reg_at = dict(zip(vcps, regs))
            keep = []
            for cp, ai, endian in surv:
                _alg, corr, xo = eng.algs[ai]
                v = reg_at[cp] ^ xo
                if corr:
                    v ^= eng.zero[corr][cp - start]
                loc = pos if shape == 1 else cp
                if v == _stored_value(self.snaps[k], loc, w, endian):
                    keep.append((cp, ai, endian))
            surv = keep
        for cp, ai, endian in surv:
            self.add(eng.algs[ai][0], endian, pos if shape == 1 else cp, ((start, cp),), 1)
        return True


_TIER_NAMES = {0: "영역 경계", 1: "4096 정렬", 2: "256 정렬", 3: "16 정렬", 4: "4·폭 정렬", 5: "비정렬", 6: "비정렬 위치"}


def _tz(x: int) -> int:
    """뒤쪽 0 비트 수 (0 은 가장 강한 경계로 본다)."""
    return (x & -x).bit_length() - 1 if x else 64


def _range_pref(r: tuple[int, int], loc: int, r0: int, r1: int) -> tuple[int, int, int, int, int]:
    """대표 범위 우선순위: 영역 경계에 닿음 → 자유 끝점이 큰 2의 거듭제곱 경계 → 긴 범위."""
    s, e = r
    free = s if e == loc else e
    return (0 if (s == r0 or e == r1) else 1, -_tz(free), -(e - s), s, e)


def find_checksums(
    snapshots: list[bytes],
    *,
    region: tuple[int, int] | None = None,
    algorithms: list[str] | None = None,
    max_bytes_hashed: int = 64 << 20,
    max_results: int = 50,
    ctl: Any = None,
) -> dict[str, Any]:
    """모든 스냅샷에서 ``저장값(위치) == 알고리즘(data[s:e])`` 이 성립하는 체크섬 **후보**를 찾는다.

    탐색 공간 (체크섬은 덮는 데이터가 바뀌면 같이 바뀐다는 점을 이용):

    - 위치: 스냅샷 사이에 바뀐 바이트를 하나 이상 덮는 폭 w(1/2/4) 창. 2바이트 이상은 le/be 두 저장 엔디언을 모두 시험한다
      (폭 1 은 ``endian=None``). 창이 폭마다 ``_MAX_LOCATIONS`` 를 넘으면 폭 정렬 창만, 그래도 넘으면 앞쪽만 본다.
    - 범위 모양: 위치 바로 앞 ``[s, 위치)`` 또는 바로 뒤 ``[위치+w, e)``. 자유 끝점 s/e 는 ``region`` 경계와 정렬 위치
      (영역 ≤256 KiB 면 4바이트, ≤1 MiB 16, ≤4 MiB 64, ≤16 MiB 256, 그 이상 1024 — 결과의 ``endpoint_align``).
      범위 길이 ≥ 2·w. 워드 합(``sum16le`` 등)은 워드 정렬 위치·범위만.
    - 합계류(sum/negsum/notsum/xor/워드 합/Fletcher/Adler)는 누적값과 사전 조회로 끝점을 **전수** 시험한다(해시 예산을 쓰지 않음).
    - CRC 는 패스 단위로 계산한다: ``[s, 위치)`` 는 시작 s 마다 한 번 지나가며 모든 위치를 확인하고, ``[위치+w, e)`` 는 위치마다
      한 번 지나가며 모든 끝점을 확인한다. 첫 스냅샷에서 맞은 체크포인트만 나머지 스냅샷마다 패스 한 번으로 확인한다.
      같은 (bits, poly, refin) 의 CRC 는 레지스터 하나를 함께 쓰고 초기값 차이는 0 바이트 표(선형성)로 보정한다
      (영역 ≤1 MiB, 더 크면 초기값별 레지스터). 패스는 영역 경계 → 4096 → 256 → 16 → 4 정렬 → 비정렬 순이고, 영역 경계
      패스는 합계류보다 먼저 돈다.
    - 예산: 모든 CRC 패스(선별·확인·0 바이트 표)는 시작 전에 정확한 비용을 계산해 ``해시 바이트 + 비교 횟수×8`` 이
      ``max_bytes_hashed`` 안일 때만 돈다 — ``budget_used`` 는 예산을 넘지 않는다. 다음 패스가 예산을 넘으면 거기서 멈춘다
      (``budget_exhausted``, ``truncated``, ``notes`` 에 등급별 건너뛴 수).
    - ``ctl``: 위치 수천 개·패스 조각(64 KiB)·체크포인트 수천 개마다 시간 예산을 확인하고, 넘기면 그때까지 찾은 후보로 마무리한다
      (``timed_out``, ``truncated``). 후보 정리 단계에서는 취소만 확인한다.
    - 후보 묶음은 폭마다 ``_MAX_RAW_PER_WIDTH`` 개까지 (넘으면 ``truncated`` + ``notes``).

    판정: ``distinct_values`` = 스냅샷 사이 서로 다른 저장값 수,
    ``expected_false_positives = tested_for_that_width / 2**(8 * width * distinct_values)`` (그 폭의 모든 시험이 우연히 맞을 기대 수).
    ``strength`` 는 (폭 1 이고 서로 다른 저장값 ≤ 2) 또는 (서로 다른 저장값 < 2) 또는 (기대 오탐 ≥ 0.01) 이면 weak, 아니면 strong.
    같은 (알고리즘, 엔디언, 위치)에 맞는 범위가 여럿이면(앞뒤 0 패딩 등) 하나로 묶고 영역 경계에 닿는 범위 → 자유 끝점이
    큰 2의 거듭제곱 경계(0x400 > 0x600)인 범위 → 긴 범위를 대표로, 개수는 ``range_variants``, 일부는 ``other_ranges`` 에 둔다
    (``range_variants`` > 1 이면 범위 끝을 데이터만으로 정할 수 없다는 뜻). 같은 범위의 더 넓은 후보 창 안에 들어가는 좁은 후보(예: sum16 의
    하위 바이트 = sum8)는 뺀다. 값의 사본(미러)이나 패딩만 다른 범위도 맞을 수 있으므로 디컴파일로 계산 루틴을 확인해야 한다.

    후보 항목은 ``apply_raw_edits(checksum=...)`` 에 그대로 넘길 수 있다.
    """
    notes: list[str] = []
    snaps = _coerce_snapshots(snapshots)
    n = len(snaps)
    if algorithms is None:
        names = list(CHECKSUM_ALGORITHMS)
    else:
        if not isinstance(algorithms, (list, tuple)) or not algorithms:
            raise SaveFormatError("algorithms 는 알고리즘 이름의 비어 있지 않은 목록이어야 합니다 (None 이면 전부).")
        names = []
        for a in algorithms:
            _alg_spec(a)
            if a not in names:
                names.append(a)
    budget = max_bytes_hashed if _is_int(max_bytes_hashed) and max_bytes_hashed >= 0 else 64 << 20
    cap = max_results if _is_int(max_results) and max_results >= 0 else 50
    out: dict[str, Any] = {
        "snapshot_count": n,
        "length": 0,
        "region": None,
        "algorithms": names,
        "changed_bytes": 0,
        "tested": 0,
        "tested_by_width": {},
        "bytes_hashed": 0,
        "budget_used": 0,
        "candidates": [],
        "candidates_total": 0,
        "truncated": False,
        "budget_exhausted": False,
        "timed_out": False,
        "notes": notes,
    }
    if n < 2:
        notes.append("체크섬을 찾으려면 스냅샷이 2개 이상 필요합니다 (값이 바뀔 때마다 덤프, 3개 이상 권장).")
        return out
    size = _common_length(snaps, notes)
    out["length"] = size
    if region is None:
        r0, r1 = 0, size
    else:
        if not isinstance(region, (list, tuple)) or len(region) != 2 or not all(_is_int(x) for x in region):
            raise SaveFormatError("region 은 [start, end) 정수 두 개여야 합니다.")
        r0, r1 = region
        if r0 < 0 or r1 <= r0:
            raise SaveFormatError(f"region 이 올바르지 않습니다: {list(region)} (0 ≤ start < end)")
        if r1 > size:
            notes.append(f"region 끝 {r1} 이 공통 길이 {size} 보다 커서 {size} 로 줄였습니다.")
            r1 = max(r0, size)
    out["region"] = [r0, r1]
    if r1 - r0 < 3:
        notes.append("영역이 너무 작습니다 (체크섬 + 범위가 들어갈 수 없음).")
        return out
    mask = _diff_mask(snaps, r0, r1, ctl)
    if mask is None:
        out["truncated"] = out["timed_out"] = True
        notes.append("시간 예산을 넘겨 스냅샷 비교도 끝내지 못했습니다 — 후보 없음. region 을 좁혀 다시 실행하세요.")
        return out
    out["changed_bytes"] = len(mask) - mask.count(0)
    if not out["changed_bytes"]:
        notes.append(
            "영역 안에서 스냅샷이 모두 같습니다 — 체크섬 위치는 바뀐 바이트에서만 찾으므로 후보가 없습니다. "
            "점수·진행이 바뀐 뒤의 스냅샷을 더 받으세요."
        )
        return out
    srch = _Search(snaps, r0, r1, mask, names, budget, ctl, notes, _MAX_VARIANTS)
    srch.run_crcs(max_tier=0)  # 영역 경계 CRC 패스 먼저 (시간 예산이 합계류에서 끝나도 가장 유력한 패스는 돈다)
    srch.run_sums()
    srch.run_crcs()

    # 후보 정리: 시간 예산이 지났어도 찾은 것은 마무리한다 (묶음 수 상한·O(1) 세기로 짧다). 취소만 확인.
    # 묶음마다 가벼운 튜플만 만들고, 결과 사전은 정렬 뒤 위쪽 max_results 개만 만든다 (메모리).
    light: list[tuple[Any, ...]] = []
    for gi, ((alg, endian, loc), (count, rngs)) in enumerate(srch.raw.items()):
        if (gi & 0x3FF) == 0x3FF:
            _cancel_check(ctl)
        w = CHECKSUM_ALGORITHMS[alg]["width"]
        s, e = min(rngs, key=lambda r, loc=loc: _range_pref(r, loc, r0, r1))
        distinct = len(set(srch.stored(w, loc, endian)))
        efp = _efp(srch.tested[w], w, distinct)
        weak = distinct < 2 or (w == 1 and distinct <= 2) or efp >= _STRONG_EFP
        light.append((weak, efp, -(e - s), _ALG_INDEX[alg], loc, alg, endian, w, s, e, distinct))
    # 같은 범위의 더 넓은 후보 창 안에 있는 좁은 후보 제거
    wider: dict[tuple[int, int], list[tuple[int, int]]] = {}
    for it in light:
        wider.setdefault((it[8], it[9]), []).append((it[4], it[7]))
    kept = []
    subsumed = 0
    for i, it in enumerate(light):
        if (i & 0xFFF) == 0xFFF:
            _cancel_check(ctl)
        lo, hi, w = it[4], it[4] + it[7], it[7]
        if any(w2 > w and l2 <= lo and hi <= l2 + w2 for l2, w2 in wider[(it[8], it[9])]):
            subsumed += 1
            continue
        kept.append(it)
    del light, wider
    kept.sort(key=lambda it: it[:5])
    changes = _ChangeCount(mask, r0, srch.align)
    top = []
    for weak, efp, _neg, _ai, loc, alg, endian, w, s, e, distinct in kept[:cap]:
        count, rngs = srch.raw[(alg, endian, loc)]
        uniq = sorted(set(rngs), key=lambda r, loc=loc: _range_pref(r, loc, r0, r1))
        top.append(
            {
                "algorithm": alg,
                "kind": CHECKSUM_ALGORITHMS[alg]["kind"],
                "width": w,
                "endian": endian,
                "location": loc,
                "range": [s, e],
                "shape": "before" if e == loc else "after",
                "matches": n,
                "distinct_values": distinct,
                "stored_values": list(srch.stored(w, loc, endian)),
                "strength": "weak" if weak else "strong",
                "expected_false_positives": efp,
                "range_variants": max(count, len(uniq)),
                "other_ranges": [list(r) for r in uniq[1:6]],
                "changed_in_range": changes.count(s, e),
            }
        )
    out["candidates_total"] = len(kept)
    out["candidates"] = top
    out["truncated"] = len(kept) > cap or srch.budget_exhausted or srch.timed_out or srch.raw_capped
    out["budget_exhausted"] = srch.budget_exhausted
    out["timed_out"] = srch.timed_out
    out["tested"] = sum(srch.tested.values())
    out["tested_by_width"] = {str(w): srch.tested[w] for w in sorted(srch.tested)}
    out["bytes_hashed"] = srch.hashed
    out["budget_used"] = srch.hashed + srch.checks * _CHECK_COST
    out["crc_passes"] = {"run": srch.passes_run, "skipped": srch.passes_skipped}
    out["endpoint_align"] = srch.align
    notes.append(
        f"위치 후보는 바뀐 바이트를 덮는 창에서만, 범위는 [s, 위치) 또는 [위치+폭, e) 이고 자유 끝점은 영역 경계와 {srch.align}바이트 정렬 위치, "
        "길이 ≥ 2×폭이다 (워드 합은 워드 정렬 범위만)."
    )
    if subsumed:
        notes.append(f"같은 범위의 더 넓은 후보로 설명되는 좁은 후보 {subsumed}개를 뺐습니다 (예: sum16 의 하위 바이트 = sum8).")
    if srch.stage2_capped:
        notes.append(f"Fletcher/Adler 2단계 확인이 조회당 {_STAGE2_CAP}개를 넘어 일부만 확인했습니다 (긴 상수 구간).")
    if srch.raw_capped:
        notes.append(
            f"후보 묶음이 폭마다 {_MAX_RAW_PER_WIDTH}개를 넘어 나머지는 버렸습니다 — 우연히 맞는 후보가 너무 많습니다. "
            "region 을 좁히거나 값이 다른 스냅샷을 더 받으세요."
        )
    tiers = ", ".join(f"{_TIER_NAMES.get(t, t)} {c}개" for t, c in sorted(srch.skipped_tiers.items()))
    dropped = f", 확인 중 버린 선별 통과 {srch.verify_dropped}개" if srch.verify_dropped else ""
    if srch.budget_exhausted:
        notes.append(
            f"CRC 예산(max_bytes_hashed={budget}, 비교 1회 = {_CHECK_COST}바이트) 소진 — 우선순위가 낮은 패스 {srch.passes_skipped}개를 "
            f"건너뜀 ({tiers}{dropped}). region 을 좁히거나 algorithms 를 줄이거나 예산을 늘리세요."
        )
    if srch.timed_out:
        notes.append(f"시간 예산을 넘겨 멈췄습니다 — 부분 결과입니다 (건너뛴 CRC 패스 {srch.passes_skipped}개{', ' + tiers if tiers else ''}{dropped}).")
    if kept and kept[0][0]:  # 정렬 첫 항목도 weak
        notes.append("strong 후보가 없습니다 — 값이 다른 스냅샷을 더 받으면(서로 다른 저장값이 늘면) 판정이 강해집니다.")
    return out


# ---------------------------------------------------------------------------
# 치트 입력(버튼 시퀀스) 표 후보
# ---------------------------------------------------------------------------

_SEQ_MAX_SCAN = 64 << 20
_SEQ_MAX_RUNS = 200_000
_SEQ_CHUNK = 1 << 18  # 원소 수

# 코나미형 AABBCDCDEF (위 위 아래 아래 왼 오 왼 오 B A), 글자끼리는 서로 다름. 겹치는 위치도 찾도록 전방 탐색으로 감싼다.
_KONAMI_RE = re.compile(
    rb"(?=((.)\2(?!\2)(.)\3(?!\2|\3)(.)(?!\2|\3|\4)(.)\4\5(?!\2|\3|\4|\5)(.)(?!\2|\3|\4|\5|\6)(.)))",
    re.DOTALL,
)
_T_ID = bytes(1 if b <= 0x0F else 0 for b in range(256))
_T_POW = bytes(1 if b and (b & (b - 1)) == 0 else 0 for b in range(256))
_T_ZERO = bytes([1] + [0] * 255)
# 원소의 k번째 바이트(lane)가 단일 비트면 전체 비트 번호 + 1 (1..32), 아니면 0 — 마스크 원소의 기호
_T_BITIDX = tuple(bytes((b.bit_length() + 8 * k) if b and (b & (b - 1)) == 0 else 0 for b in range(256)) for k in range(4))


@functools.lru_cache(maxsize=16)
def _seq_regexes(min_len: int) -> tuple[re.Pattern[bytes], re.Pattern[bytes], re.Pattern[bytes]]:
    return (
        re.compile(rb"[\x00-\x0f]{%d,}" % min_len),
        re.compile(rb"[\x01\x02\x04\x08\x10\x20\x40\x80]{%d,}" % min_len),
        re.compile(rb"\x01{%d,}" % min_len),
    )


@functools.lru_cache(maxsize=16)
def _piece_regex(lo: int, hi: int) -> re.Pattern[bytes]:
    """0 으로 나뉜 조각 중 길이 lo..hi 인 것만 (앞뒤가 0 또는 경계) — 길이가 맞지 않는 조각은 정규식 엔진이 건너뛴다."""
    return re.compile(rb"(?<![^\x00])[^\x00]{%d,%d}(?![^\x00])" % (lo, hi))


def _lane_members(buf: bytes, es: int, o0: int, count: int, ctl: Any = None) -> tuple[bytes, bytes] | None:
    """원소(es 바이트, little-endian)마다 1바이트: 버튼 번호(0..15) 여부, 단일 비트 마스크 여부. 시간 예산을 넘기면 None."""
    ids, pws = [], []
    for c0 in range(0, count, _SEQ_CHUNK):
        if _tick(ctl):
            return None
        c1 = min(count, c0 + _SEQ_CHUNK)
        m = c1 - c0
        seg = buf[o0 + c0 * es : o0 + c1 * es]
        lanes = [seg[k::es] for k in range(es)]  # lane 0 = 최하위 바이트
        z = [int.from_bytes(ln.translate(_T_ZERO), "little") for ln in lanes]
        p = [int.from_bytes(ln.translate(_T_POW), "little") for ln in lanes]
        idm = int.from_bytes(lanes[0].translate(_T_ID), "little")
        for k in range(1, es):
            idm &= z[k]
        pw = 0
        for k in range(es):
            t = p[k]
            for j in range(es):
                if j != k:
                    t &= z[j]
            pw |= t
        ids.append(idm.to_bytes(m, "little"))
        pws.append(pw.to_bytes(m, "little"))
    return b"".join(ids), b"".join(pws)


def _run_symbols(buf: bytes, es: int, o0: int, i0: int, i1: int, cls: str) -> bytes:
    """런의 원소를 1바이트 기호로 (같은 값 ⇔ 같은 기호, 버튼 번호 런은 기호 = 값). 원소 값 목록을 만들지 않는다 (C 수준 연산)."""
    seg = buf[o0 + i0 * es : o0 + i1 * es]
    if es == 1:
        return seg
    if cls == "id":
        return seg[0::es]  # 상위 바이트는 모두 0 → 하위 바이트 = 값
    acc = 0
    for k in range(es):
        acc |= int.from_bytes(seg[k::es].translate(_T_BITIDX[k]), "little")  # 원소마다 한 lane 만 0 이 아님
    return acc.to_bytes(i1 - i0, "little")


def _run_variants(sym: bytes, cls: str, head: int, lo: int, hi: int) -> Iterator[tuple[int, int]]:
    """런(기호열) 안의 시퀀스 후보 (a, b) 를 하나씩: 런 전체, 앞뒤 0 을 뗀 구간, 길이 접두, 코나미형 창, 0 으로 나뉜 조각.

    생성기라서 호출 쪽이 런마다 상한(_SEQ variant cap)에서 멈출 수 있다.
    """
    n = len(sym)
    seen: set[tuple[int, int]] = set()

    def fresh(a: int, b: int) -> bool:
        if (a, b) in seen:
            return False
        seen.add((a, b))
        return True

    if lo <= n <= hi and fresh(0, n):
        yield 0, n
    if cls == "id":
        a = n - len(sym.lstrip(b"\x00"))
        b = len(sym.rstrip(b"\x00"))
        if lo <= b - a <= hi and fresh(a, b):
            yield a, b
    if lo <= head <= hi and 1 + head <= n and fresh(1, 1 + head):  # 첫 원소가 뒤따르는 길이 (mask 런은 8·16 같은 값이 섞임)
        yield 1, 1 + head
    for m in _KONAMI_RE.finditer(sym):
        a = m.start()
        if fresh(a, a + 10):
            yield a, a + 10
    if cls == "id":
        for m in _piece_regex(lo, hi).finditer(sym):
            if fresh(m.start(), m.end()):
                yield m.start(), m.end()


def _symbols(seq: Sequence[int]) -> bytes:
    """처음 나온 순서대로 0, 1, 2 … 로 바꾼 기호열 (모양만 남김)."""
    m: dict[int, int] = {}
    return bytes(m.setdefault(v, len(m)) for v in seq)


def _score_seq(seq: Sequence[int], max_alpha: int, term: str | None, prefix: bool) -> dict[str, Any] | None:
    m = len(seq)
    alphabet = sorted(set(seq))
    k = len(alphabet)
    if k < 2 or k > max_alpha:
        return None
    sym = _symbols(seq)
    shape = "".join(chr(65 + i) for i in sym)
    is_mask = all(v > 0 and (v & (v - 1)) == 0 for v in alphabet)
    score = 0
    reasons: list[str] = []

    def add(points: int, why: str) -> None:
        nonlocal score
        score += points
        reasons.append(f"{why} ({points:+d})")

    km = _KONAMI_RE.search(sym)
    kpos = km.start() if km else -1
    if kpos == 0:
        add(50, "코나미형 AABBCDCDEF 로 시작")
    elif kpos > 0:
        add(30, f"코나미형 AABBCDCDEF 포함 (원소 {kpos}부터)")
    pairs = sum(1 for a, b in zip(seq, seq[1:]) if a == b)
    if pairs:
        add(min(12, 4 * pairs), f"같은 버튼 연속 {pairs}쌍")
    alts = sum(1 for i in range(m - 2) if seq[i] == seq[i + 2] != seq[i + 1])
    if alts:
        add(min(8, 2 * alts), f"교대 반복(ABAB) {alts}곳")
    if is_mask and k >= 3:
        add(10, f"단일 비트 마스크 알파벳 {k}종")
    elif k >= 3:
        add(4, f"작은 버튼 번호 알파벳 {k}종 (0..15)")
    if k == 2:
        add(-5, "버튼 2종뿐")
    if 4 <= k <= 7:
        add(5, "방향 4 + 버튼 몇 개 규모의 알파벳")
    if term in ("0", "all-ones"):
        add(6, f"종결자 {term}")
    elif term == "end":
        add(2, "데이터 끝에서 끝남")
    if prefix:
        add(8, "바로 앞 원소가 길이")
    if 8 <= m <= 16:
        add(4, "치트 코드다운 길이 (8..16)")
    steps = [b - a for a, b in zip(seq, seq[1:])]
    up = sum(1 for d in steps if d > 0)
    down = sum(1 for d in steps if d < 0)
    if up == len(steps) or down == len(steps):
        add(-40, "단조 증가/감소 (조회 테이블·카운터 의심)")
    elif max(up, down) >= 0.8 * len(steps):
        add(-20, "거의 단조 (표 의심)")
    if k == m:
        add(-15, "모든 원소가 다름 (표 의심)")
    top = Counter(seq).most_common(1)[0][1]
    if top > 0.7 * m:
        add(-30, "한 값이 70% 넘게 차지 (패딩·균일 데이터 의심)")
    elif top > 0.5 * m:
        add(-15, "한 값이 절반 넘게 차지")
    if not is_mask and sum(1 for v in seq if v == 0) > 0.4 * m:
        add(-15, "0 이 40% 넘음 (구조체 패딩 의심)")
    for p in range(2, 5):
        if m >= 3 * p and all(seq[i] == seq[i + p] for i in range(m - p)):
            add(-25, f"주기 {p} 반복 (구조체 배열 의심)")
            break
    return {
        "alphabet": alphabet,
        "alphabet_kind": "bitmask" if is_mask else "button-id",
        "shape": shape,
        "konami_like": kpos >= 0,
        "score": score,
        "reasons": reasons,
    }


def find_seq_tables(
    data: Any,
    *,
    base_addr: int = 0,
    min_len: int = 6,
    max_len: int = 32,
    max_alphabet: int = 8,
    max_results: int = 100,
    ctl: Any = None,
) -> dict[str, Any]:
    """치트 입력(버튼 시퀀스) 표 **후보**를 찾는다 (펌웨어 rodata, 세이브 등).

    - 원소: u8, u16le(2바이트 정렬), u32le(4바이트 정렬; 정렬은 ``base_addr + offset`` 기준).
    - 원소가 버튼 번호(0..15) 이거나 단일 비트 마스크(2의 거듭제곱)인 최대 연속 구간을 하나씩 보고(목록을 만들지 않음), 구간 전체
      (길이가 맞을 때), 앞뒤 0 을 뗀 구간, 첫 원소가 길이인 구간, 코나미형 창, 0 으로 나뉜 조각을 시퀀스 후보로 만든다.
    - 알파벳(서로 다른 값) 2..``max_alphabet`` 종, 길이 ``min_len``..``max_len`` 만.
    - 점수: 코나미형 ``AABBCDCDEF``(알파벳 대응 무관) +50(포함 +30), 같은 버튼 연속·교대 반복, 비트 마스크 알파벳,
      종결자(0 / 모두 1 / 데이터 끝), 길이 접두, 8..16 길이에 가점. 단조 증가·감소(0,1,2,3… 조회 테이블, 1,2,4,8… 비트 표),
      모든 원소가 다름, 한 값의 지배(패딩), 0 과다, 짧은 주기 반복(구조체 배열)에 감점. 점수 > 0 인 것만, 겹치는 후보는
      점수가 높은 쪽만(겹침 ≥ 작은 쪽의 절반) 남기고 점수 순으로 ``max_results`` 개.
    - 한도: 런 하나에서 보는 후보는 ``4 × max(1000, 10 × max_results)`` 개까지(넘으면 ``truncated`` + ``notes``), 들고 있는 후보도
      그만큼으로 수시로 줄인다(점수 상위만). 런 256개·후보 1024개마다 시간 예산을 확인하고 넘기면 부분 결과로 끝낸다.

    점수는 휴리스틱이다 — 후보 주소를 디컴파일에서 참조하는 입력 처리 루틴으로 확인해야 한다.
    """
    notes: list[str] = []
    buf = _to_bytes(data, "data")
    for name, v in (("base_addr", base_addr), ("min_len", min_len), ("max_len", max_len), ("max_alphabet", max_alphabet), ("max_results", max_results)):
        if not _is_int(v) or v < 0:
            raise SaveFormatError(f"{name} 는 0 이상의 정수여야 합니다: {v!r}")
    lo_len = max(3, min(64, min_len))
    hi_len = max(lo_len, min(256, max_len))
    alpha = max(2, min(16, max_alphabet))
    if (lo_len, hi_len, alpha) != (min_len, max_len, max_alphabet):
        notes.append(f"인자를 허용 범위로 조정했습니다: min_len={lo_len}, max_len={hi_len}, max_alphabet={alpha}")
    truncated = False
    if len(buf) > _SEQ_MAX_SCAN:
        notes.append(f"입력이 커서 앞 {_SEQ_MAX_SCAN} 바이트만 봅니다 — 앱 파티션·rodata 처럼 범위를 좁혀 다시 실행하세요.")
        buf = buf[:_SEQ_MAX_SCAN]
        truncated = True
    re_id, re_mask, re_member = _seq_regexes(lo_len)
    fmt_code = {1: "B", 2: "H", 4: "I"}
    keep_n = max(1000, 10 * max_results)  # NMS 전에 점수 상위만 들고 있는다 (메모리)
    var_cap = 4 * keep_n  # 런 하나에서 보는 후보 상한
    cands: list[dict[str, Any]] = []
    runs_seen = 0
    variants_seen = 0
    capped_runs = 0
    timed_out = False
    stop = False

    def prune() -> None:
        nonlocal cands
        if len(cands) > 4 * keep_n:
            cands = heapq.nlargest(keep_n, cands, key=lambda c: (c["score"], -c["offset"]))

    for es in (1, 2, 4):
        _progress(ctl, es, 4, f"원소 {es}바이트 시퀀스 탐색")
        if _tick(ctl):
            timed_out = True
            break
        o0 = (-base_addr) % es
        count = (len(buf) - o0) // es if len(buf) > o0 else 0
        if count < lo_len:
            continue
        all_ones = (1 << (8 * es)) - 1
        if es == 1:
            run_iter: Iterator[tuple[str, int, int]] = chain(
                (("id", m.start(), m.end()) for m in re_id.finditer(buf)),
                (("mask", m.start(), m.end()) for m in re_mask.finditer(buf)),
            )
        else:
            members = _lane_members(buf, es, o0, count, ctl)
            if members is None:
                timed_out = True
                break
            idb, pwb = members
            run_iter = chain(
                (("id", m.start(), m.end()) for m in re_member.finditer(idb)),
                (("mask", m.start(), m.end()) for m in re_member.finditer(pwb)),
            )

        def elem(i: int, es: int = es, o0: int = o0) -> int:
            return buf[o0 + i] if es == 1 else struct.unpack_from("<" + fmt_code[es], buf, o0 + i * es)[0]

        def elems(i: int, j: int, es: int = es, o0: int = o0) -> tuple[int, ...]:
            return tuple(buf[o0 + i : o0 + j]) if es == 1 else struct.unpack_from("<%d%s" % (j - i, fmt_code[es]), buf, o0 + i * es)

        for cls, i0, i1 in run_iter:
            runs_seen += 1
            if runs_seen > _SEQ_MAX_RUNS:
                notes.append(f"연속 구간이 {_SEQ_MAX_RUNS}개를 넘어 나머지는 보지 않았습니다.")
                truncated = stop = True
                break
            if (runs_seen & 0xFF) == 0 and _tick(ctl):
                timed_out = stop = True
                break
            n = i1 - i0
            sym = _run_symbols(buf, es, o0, i0, i1, cls)
            if sym.count(sym[0]) == n:
                continue  # 한 값뿐 (패딩)
            nv = 0
            for a, b in _run_variants(sym, cls, elem(i0), lo_len, hi_len):
                nv += 1
                if nv > var_cap:
                    capped_runs += 1
                    truncated = True
                    break
                variants_seen += 1
                if (variants_seen & 0x3FF) == 0 and _tick(ctl):
                    timed_out = stop = True
                    break
                seq = elems(i0 + a, i0 + b)
                gi = i0 + b  # 다음 원소 (전체 원소 번호)
                if gi >= count:
                    term = "end"
                else:
                    t = elem(gi)
                    term = "0" if t == 0 else ("all-ones" if t == all_ones else None)
                prefix = i0 + a > 0 and elem(i0 + a - 1) == b - a
                info = _score_seq(seq, alpha, term, prefix)
                if info is None or info["score"] <= 0:
                    continue
                off = o0 + (i0 + a) * es
                cands.append(
                    {
                        "offset": off,
                        "address": base_addr + off,
                        "element_size": es,
                        "length": b - a,
                        "values": list(seq),
                        **info,
                        "terminator": term,
                        "length_prefix": prefix,
                    }
                )
                prune()
            if stop:
                break
        if stop:
            break
    if capped_runs:
        notes.append(f"후보가 아주 많은 연속 구간 {capped_runs}개는 앞쪽 {var_cap}개 후보만 봤습니다 (반복 표·타일맵 같은 데이터).")
    if timed_out:
        truncated = True
        notes.append("시간 예산을 넘겨 멈췄습니다 — 부분 결과입니다.")
    cands.sort(key=lambda c: (-c["score"], c["offset"], c["element_size"]))
    kept: list[dict[str, Any]] = []
    spans_kept: list[tuple[int, int]] = []
    for c in cands:
        s = c["offset"]
        e = s + c["length"] * c["element_size"]
        if any(min(e, ke) - max(s, ks) >= min(e - s, ke - ks) / 2 for ks, ke in spans_kept):
            continue
        if len(kept) >= max_results:
            truncated = True
            break
        kept.append(c)
        spans_kept.append((s, e))
    if not kept:
        notes.append("후보가 없습니다 — 다른 원소 크기(빅엔디언 등)나 표가 압축·암호화되어 있을 수 있습니다.")
    return {"candidates": kept, "scanned_bytes": len(buf), "runs_examined": runs_seen, "truncated": truncated, "notes": notes}


# ---------------------------------------------------------------------------
# 원시 편집 (I2b 용 — 아직 도구로 노출하지 않음)
# ---------------------------------------------------------------------------


def _parse_checksum_spec(cs: Any, size: int) -> tuple[str, int, str | None, int, int, int]:
    if not isinstance(cs, dict):
        raise SaveFormatError("checksum 은 {algorithm, endian, location, range} 사전이어야 합니다.")
    alg = cs.get("algorithm")
    spec = _alg_spec(alg)
    w = spec["width"]
    if cs.get("width") is not None and cs.get("width") != w:
        raise SaveFormatError(f"checksum width {cs.get('width')!r} 가 {alg} 의 폭 {w} 와 다릅니다.")
    endian = cs.get("endian")
    if w == 1:
        endian = None
    elif endian not in ("le", "be"):
        raise SaveFormatError(f"{alg} 는 {w}바이트라서 endian 이 'le' 또는 'be' 여야 합니다: {endian!r}")
    loc = cs.get("location")
    if not _is_int(loc) or loc < 0 or loc + w > size:
        raise SaveFormatError(f"checksum location 이 데이터 범위(0..{size - w}) 밖입니다: {loc!r}")
    rng = cs.get("range")
    if not isinstance(rng, (list, tuple)) or len(rng) != 2 or not all(_is_int(x) for x in rng):
        raise SaveFormatError("checksum range 는 [start, end) 정수 두 개여야 합니다.")
    s, e = rng
    if not 0 <= s < e <= size:
        raise SaveFormatError(f"checksum range 가 데이터 범위(0..{size}) 밖이거나 비어 있습니다: {list(rng)}")
    if s < loc + w and loc < e:
        raise SaveFormatError("checksum range 가 체크섬 필드와 겹칩니다 — 자기 자신을 덮는 체크섬은 지원하지 않습니다.")
    return alg, w, endian, loc, s, e


def apply_raw_edits(data: bytes, edits: list[dict], *, checksum: dict | None = None) -> tuple[bytes, list[dict]]:
    """원시 편집을 적용한 새 바이트열과 변경 목록. 입력은 바꾸지 않는다 (bytearray 도 복사).

    ``edits``: ``[{offset, encoding, value}]`` — ``encode_value`` 로 바꿔 덮어쓴다. 범위 밖 오프셋, 표현할 수 없는 값,
    서로 겹치는 편집, 빈 목록은 SaveFormatError (아무것도 바꾸지 않음).
    ``checksum`` (선택, ``find_checksums`` 후보 그대로 가능): ``{algorithm, endian, location, range: [s, e]}``.
    편집 **전에** 원본에서 알고리즘이 저장값을 재현하는지 확인하고(아니면 SaveFormatError "이 base 에서 체크섬 규칙이 재현되지 않음"),
    체크섬 필드와 겹치는 편집을 거부하며, 편집 후 다시 계산해 저장한다. 체크섬 범위 밖 편집은 허용하되 변경 항목에
    ``in_checksum_range=False`` 로 표시한다.

    반환 변경 목록: 편집마다 ``{offset, encoding, before_hex, after_hex, before_value, after_value}``, 체크섬을 쓰면 마지막에
    ``{"checksum": {algorithm, endian, location, range, before, after, before_hex, after_hex}}``.
    """
    base = _to_bytes(data, "data")
    size = len(base)
    if not isinstance(edits, (list, tuple)) or not edits:
        raise SaveFormatError("edits 는 비어 있지 않은 [{offset, encoding, value}] 목록이어야 합니다.")
    plan: list[tuple[int, int, str, int, bytes]] = []
    for idx, ed in enumerate(edits):
        if not isinstance(ed, dict):
            raise SaveFormatError(f"edits[{idx}] 는 사전이어야 합니다.")
        off, enc, val = ed.get("offset"), ed.get("encoding"), ed.get("value")
        if not _is_int(off) or off < 0:
            raise SaveFormatError(f"edits[{idx}].offset 은 0 이상의 정수여야 합니다: {off!r}")
        raw = encode_value(val, enc)  # 인코딩·값 검증
        if off + len(raw) > size:
            raise SaveFormatError(f"edits[{idx}] 가 데이터 끝({size})을 넘습니다: offset {off} + {len(raw)}")
        plan.append((off, len(raw), enc, val, raw))
    order = sorted(range(len(plan)), key=lambda i: plan[i][0])
    for a, b in zip(order, order[1:]):
        if plan[a][0] + plan[a][1] > plan[b][0]:
            raise SaveFormatError(f"edits[{a}] 와 edits[{b}] 가 겹칩니다 (offset {plan[a][0]}, {plan[b][0]}).")
    cs = None
    if checksum is not None:
        alg, w, endian, loc, s, e = _parse_checksum_spec(checksum, size)
        before = _stored_value(base, loc, w, endian)
        computed = checksum_compute(alg, base[s:e])
        if before != computed:
            raise SaveFormatError(
                f"이 base 에서 체크섬 규칙이 재현되지 않음: {alg} [{s}, {e}) = 0x{computed:x}, 저장값(@{loc}, {endian or '1바이트'}) = 0x{before:x}"
            )
        for idx, (off, wl, _enc, _val, _raw) in enumerate(plan):
            if off < loc + w and loc < off + wl:
                raise SaveFormatError(f"edits[{idx}] 가 체크섬 필드(@{loc}, {w}바이트)와 겹칩니다 — 체크섬은 자동으로 다시 계산합니다.")
        cs = (alg, w, endian, loc, s, e, before)
    out = bytearray(base)
    changes: list[dict[str, Any]] = []
    for off, wl, enc, val, raw in plan:
        old = bytes(out[off : off + wl])
        out[off : off + wl] = raw
        item: dict[str, Any] = {
            "offset": off,
            "encoding": enc,
            "before_hex": old.hex(),
            "after_hex": raw.hex(),
            "before_value": decode_value(old, 0, enc),
            "after_value": val,
        }
        if cs is not None:
            item["in_checksum_range"] = off < cs[5] and cs[4] < off + wl
        changes.append(item)
    if cs is not None:
        alg, w, endian, loc, s, e, before = cs
        after = checksum_compute(alg, bytes(out[s:e]))
        old_hex = bytes(out[loc : loc + w]).hex()
        out[loc : loc + w] = _pack_stored(after, w, endian)
        changes.append(
            {
                "checksum": {
                    "algorithm": alg,
                    "endian": endian,
                    "location": loc,
                    "range": [s, e],
                    "before": before,
                    "after": after,
                    "before_hex": old_hex,
                    "after_hex": bytes(out[loc : loc + w]).hex(),
                }
            }
        )
    return bytes(out), changes
