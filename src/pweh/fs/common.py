"""pweh.fs 공통 요소: 예외, 한도, 경고 수집, 내부 오류 차단, 시각 해석, 이름 정리, 내용 읽기 계획.

이 패키지는 신뢰할 수 없는 카드 이미지를 해석한다. 그래서
- 모든 반복은 한도(`Limits`)나 자연 상한(클러스터 수, 사양의 최대 크기)으로 묶는다.
- 손상된 구조는 경고(`Warnings`)나 `FsError` 로만 드러나야 한다. 공개 함수는 `guard`/`guard_iter` 로 감싸
  예상하지 못한 파이썬 예외(IndexError, struct.error …)도 `FsError(reason="internal_error")` 로 바꾼다.
  (시험은 internal_error 가 나오면 실패로 본다 — 감싸기는 마지막 안전망이지 정상 경로가 아니다.)
- 시각은 원래 값과 함께 `time_basis` 를 둔다. 장치 시간대는 가정하지 않는다.
"""

from __future__ import annotations

import datetime as _dt
import functools
import re
import time
from array import array
from dataclasses import dataclass
from typing import Any, Callable, Iterable, Iterator, TypeVar

from ..errors import ValidationFailed

__all__ = [
    "FsError",
    "Limits",
    "Warnings",
    "Budget",
    "ContentPlan",
    "guard",
    "guard_iter",
    "guard_gen",
    "fat_timestamp",
    "fat_date_only",
    "exfat_timestamp",
    "display_name",
    "decode_utf16le",
    "ceil_div",
    "limit_text",
    "TIME_BASIS_LOCAL",
    "TIME_BASIS_OFFSET",
    "CONFIDENCE_ORDER",
    "FOLLOW_STEPS_FLOOR",
]

TIME_BASIS_LOCAL = "local-unknown-tz"  # 장치의 지역 시각, 시간대 모름 (FAT 전부, exFAT OffsetValid=0)
TIME_BASIS_OFFSET = "local+offset"  # 지역 시각 + 기록된 UTC 오프셋 (exFAT OffsetValid=1)

# 복구 후보 신뢰도 (정렬용, 작을수록 앞)
CONFIDENCE_ORDER = {"high": 0, "medium": 1, "low": 2, "none": 3}


class FsError(ValidationFailed):
    """카드 이미지 해석 실패 (손상, 범위 밖, 지원하지 않는 형식, 잘못된 참조 등).

    code 는 상위 클래스의 ``validation_failed`` 를 그대로 쓰고, 세부 사유는 ``reason``(data["reason"] 에도 들어감)으로 구분한다.
    reason 예: not_regular_file, not_found, open_failed, out_of_bounds, short_read, io_error, too_large,
    not_fat, not_exfat, unsupported_fs, bad_ref, bad_argument, not_deleted, internal_error, malformed,
    budget_exceeded(시간·단계 예산이 다 됐거나 취소됨 — data["limit"] = 'time' | 'steps' | 'cancelled'),
    ambiguous_path(lookup: 정확히 같은 이름은 없고 대소문자만 다른 살아 있는 항목이 둘 이상 — data["component"] = 몇 번째 이름),
    max_depth(lookup: 경로가 Limits.max_depth 보다 깊음), max_dir_slots(lookup: 슬롯 한도에서 잘린 디렉터리라 이름이 뒤쪽에 있는지 모름).
    """

    def __init__(self, message: str, *, reason: str = "malformed", hint: str | None = None,
                 data: dict[str, Any] | None = None) -> None:
        payload = dict(data or {})
        payload["reason"] = reason
        super().__init__(message, hint=hint, data=payload)
        self.reason = reason


#: 작업 단계 상한의 바닥값 (Limits.max_follow_steps=None 일 때 볼륨별 상한은 이보다 작아지지 않는다)
FOLLOW_STEPS_FLOOR = 1 << 24


@dataclass(frozen=True)
class Limits:
    """해석 한도. 신뢰할 수 없는 이미지가 메모리·시간을 무한히 쓰지 못하게 한다.

    max_follow_steps: None(기본)이면 볼륨마다 정한다 — ``VolumeBase.step_cap``:
    max(FOLLOW_STEPS_FLOOR, 2 × N + max_total_slots), N = min(클러스터 수, 이미지 안에서 읽을 수 있는 FAT 항목 수).
    근거: 정상 볼륨에서 클러스터 하나는 살아 있는 파일·디렉터리 체인 하나에만 속하므로 체인 따라가기는 다 합쳐 N 단계 이하이고,
    디렉터리 슬롯 읽기는 walk 전체가 max_total_slots 이하다. 두 번째 N 은 exFAT 삭제 집합의 할당 요약(항목당 최대 4096 클러스터)·
    비트맵 훑기(64 클러스터 = 1 단계)·체인 요약의 +1 걸음 같은 나머지 몫이다. 그래서 정상적으로 꽉 찬 볼륨은 이 상한에 닿지 않고,
    같은 긴 체인을 여러 항목이 가리키는 조작 이미지는 이미지 크기에 비례하는 단계 안에서 멈춘다. 정수를 주면 모든 볼륨에 그 값을 그대로 쓴다.

    max_path_chars: walk 한 번(reachable_dirspecs 도)이 만드는 경로 문자열의 글자 수 합계 상한. 항목마다 len(path)를 세고,
    display_path 가 path 와 다를 때만 len(display_path)를 더 센다(같으면 walk 가 문자열 하나를 함께 쓴다). 넘으면 walk 는
    truncated_reason='max_path_chars' 로 멈춘다. 호출자가 남은 몫을 이 값으로 넘길 수 있다(서버의 호출별 나머지).
    기본 2^28 글자: CPython 문자열은 가장 넓은 글자 기준 글자당 최대 4 바이트라 경로 메모리는 최악 약 1 GiB 이다.
    정상 배치 중 가장 큰 계산값(항목 20만 개, 이름 255 글자, 깊이 2 → 항목당 512 글자 = 1.02 억 글자)보다 2.6 배 크다.
    """

    max_entries: int = 200_000  # walk 한 번에 돌려줄 항목 수 (삭제 항목 포함)
    max_depth: int = 64  # 디렉터리 깊이
    max_dir_slots: int = 1 << 20  # 디렉터리 하나에서 읽을 32바이트 슬롯 수 (FAT 은 사양상 65536 으로 더 묶임)
    max_total_slots: int = 8 << 20  # walk 전체에서 읽을 슬롯 수
    max_list: int = 100_000  # list_dir 한 번에 돌려줄 항목 수
    max_warnings: int = 50  # 결과 하나에 담을 경고 수 (나머지는 개수만 센다)
    max_orphans: int = 1_000  # 고아 LFN·고아 보조 항목 보고 상한
    max_seconds: float | None = None  # 공개 호출 하나(walk·analyze_image·내용 계획·cluster_report …)의 시간 예산 (None = 제한 없음)
    max_scan_clusters: int = 1 << 26  # cluster_report·건너뛰기 탐색에서 훑을 클러스터 수
    max_runs: int = 1 << 20  # 내용 계획 하나의 클러스터 구간 수 (심한 단편화 방어)
    max_read_bytes: int = 256 << 20  # read_content 가 메모리로 돌려줄 최대 바이트
    max_report_items: int = 100  # 목록형 보고 항목(구간, 표본) 상한
    max_partitions: int = 64  # analyze_image 가 열어 볼 파티션 수 (같은 구간의 중복은 세지 않음)
    max_follow_steps: int | None = None  # 공개 호출 하나의 작업 단계 상한 (체인 클러스터 하나·디렉터리 슬롯 하나·비트맵 64 클러스터 = 1 단계). None = 볼륨별
    max_path_chars: int = 1 << 28  # walk 한 번의 경로 글자 수 합계 (위 설명)


class Warnings:
    """경고 수집기. 같은 (code, message) 는 한 번만, 상한을 넘으면 개수만 센다."""

    __slots__ = ("items", "suppressed", "limit", "_seen")

    def __init__(self, limit: int = 50) -> None:
        self.items: list[dict[str, Any]] = []
        self.suppressed = 0
        self.limit = max(0, int(limit))
        self._seen: set[tuple[str, str]] = set()

    def add(self, code: str, message: str, **ctx: Any) -> None:
        key = (code, message)
        if key in self._seen:
            self.suppressed += 1
            return
        if len(self.items) >= self.limit:
            self.suppressed += 1
            return
        self._seen.add(key)
        item: dict[str, Any] = {"code": code, "message": message}
        for k, v in ctx.items():
            if v is not None:
                item[k] = v
        self.items.append(item)

    def extend(self, other: "Warnings | Iterable[dict[str, Any]]") -> None:
        if isinstance(other, Warnings):
            for it in other.items:
                self.add(**it)
            self.suppressed += other.suppressed
            return
        for it in other:
            self.add(**it)

    def codes(self) -> list[str]:
        return [it["code"] for it in self.items]

    def export(self) -> dict[str, Any]:
        return {"warnings": [dict(it) for it in self.items], "warnings_suppressed": self.suppressed}

    def __bool__(self) -> bool:
        return bool(self.items) or self.suppressed > 0


def limit_text(reason: str | None) -> str:
    """예산 멈춤 사유('time' | 'steps' | 'cancelled')의 한국어 설명 (문장 앞부분)."""
    return {"time": "시간 예산이 다 돼", "steps": "작업 단계 예산이 다 돼", "cancelled": "작업이 취소돼"}.get(reason or "",
                                                                                                 "예산이 다 돼")


class Budget:
    """공개 호출 하나(또는 서버가 볼륨 하나에 함께 쓰는)의 예산: 시간 마감, 작업 단계 수, 취소 확인.

    - 단계는 체인을 따라간 클러스터 하나, 읽은 디렉터리 슬롯 하나, 훑은 비트맵 64 클러스터를 1 로 센다(`tick`).
    - deadline: time.monotonic() 기준 절대 마감. max_seconds 와 둘 다 주면 이른 쪽을 쓴다(0·None = 시간 제한 없음).
    - cancel: 인자 없는 싼 함수(예: threading.Event().is_set). `expired()` 를 부를 때마다 확인한다 — 디렉터리마다, walk 항목마다,
      검증하는 디렉터리 단위마다, 체인 4096 걸음마다, 비트맵 조각마다. True 를 돌려주면(또는 예외가 나면) 그때부터 계속 만료이고
      reason 은 'cancelled' 다.
    - `expired()` 는 한 번 True 가 되면 계속 True 다. `reason` 은 'cancelled' | 'steps' | 'time' | None.
    - `raise_steps(n)`: 단계 상한을 n 까지 올린다(내리지 않음). open_volume 이 넘겨받은 예산을 그 볼륨의 상한(step_cap)으로 올릴 때 쓴다.
    신뢰할 수 없는 이미지에서 반복 하나가 오래 걸려도 호출 전체가 이 예산 안에서 멈추게 한다.
    """

    __slots__ = ("deadline", "max_steps", "steps", "cancel", "_reason")

    def __init__(self, max_seconds: float | None = None, max_steps: int | None = None, *,
                 cancel: Callable[[], Any] | None = None, deadline: float | None = None) -> None:
        dl = None if not max_seconds else time.monotonic() + float(max_seconds)
        if deadline is not None:
            dl = float(deadline) if dl is None else min(dl, float(deadline))
        self.deadline = dl
        self.max_steps = None if max_steps is None else max(0, int(max_steps))
        self.steps = 0
        if cancel is not None and not callable(cancel):
            raise TypeError("cancel 은 인자 없는 함수여야 합니다")
        self.cancel = cancel
        self._reason: str | None = None

    @classmethod
    def for_limits(cls, limits: "Limits", *, cancel: Callable[[], Any] | None = None,
                   deadline: float | None = None) -> "Budget":
        """Limits 의 max_seconds·max_follow_steps 로 만든 예산 (max_follow_steps=None 이면 바닥값 FOLLOW_STEPS_FLOOR —
        볼륨에 넘기면 open_volume 이 그 볼륨의 상한으로 올린다)."""
        steps = limits.max_follow_steps if limits.max_follow_steps is not None else FOLLOW_STEPS_FLOOR
        return cls(limits.max_seconds, steps, cancel=cancel, deadline=deadline)

    def tick(self, n: int = 1) -> None:
        """작업 단계 n 개를 센다 (검사는 expired() 에서)."""
        self.steps += n

    def raise_steps(self, n: int | None) -> None:
        """단계 상한을 n 까지 올린다 (이미 더 크거나 상한이 없으면 그대로)."""
        if n is None or self.max_steps is None:
            return
        self.max_steps = max(self.max_steps, int(n))

    def expired(self) -> bool:
        if self._reason is not None:
            return True
        if self.cancel is not None:
            try:
                stop = bool(self.cancel())
            except Exception:  # noqa: BLE001 - 취소 여부를 알 수 없으면 멈춘다
                stop = True
            if stop:
                self._reason = "cancelled"
                return True
        if self.max_steps is not None and self.steps > self.max_steps:
            self._reason = "steps"
            return True
        if self.deadline is not None and time.monotonic() > self.deadline:
            self._reason = "time"
            return True
        return False

    @property
    def reason(self) -> str | None:
        """'cancelled' | 'steps' | 'time' | None (아직 남음)."""
        if self._reason is None:
            self.expired()
        return self._reason

    def error(self, what: str) -> "FsError":
        """예산이 다 됐거나 취소됐을 때 낼 FsError(reason="budget_exceeded", data["limit"] = 'time' | 'steps' | 'cancelled')."""
        r = self.reason or "time"
        hint = ("작업이 취소됐습니다." if r == "cancelled"
                else "max_seconds 를 늘리거나 범위를 줄여 다시 시도하세요(손상·조작된 이미지일 수 있음).")
        return FsError(f"{what}: {limit_text(r)} 멈췄습니다.", reason="budget_exceeded", data={"limit": r}, hint=hint)


# ---------------------------------------------------------------------------
# 내부 오류 차단
# ---------------------------------------------------------------------------

F = TypeVar("F", bound=Callable[..., Any])
T = TypeVar("T")


def _internal(e: Exception) -> FsError:
    msg = f"이미지 구조를 해석하는 중 예상하지 못한 오류가 났습니다: {type(e).__name__}: {e}"
    return FsError(msg[:400], reason="internal_error", data={"exception": type(e).__name__},
                   hint="이미지가 심하게 손상됐을 수 있습니다. 다른 부분(다른 파티션·디렉터리)은 계속 분석할 수 있습니다.")


def guard(fn: F) -> F:
    """일반 함수용: FsError 가 아닌 예외를 FsError(internal_error) 로 바꾼다."""

    @functools.wraps(fn)
    def wrapper(*args: Any, **kwargs: Any) -> Any:
        try:
            return fn(*args, **kwargs)
        except FsError:
            raise
        except Exception as e:  # noqa: BLE001 - 마지막 안전망
            raise _internal(e) from e

    return wrapper  # type: ignore[return-value]


def guard_iter(it: Iterable[T]) -> Iterator[T]:
    """반복자용: 반복 중에 난 예외도 바꾼다 (제너레이터 본문은 decorator 만으로는 감싸지지 않는다)."""
    try:
        yield from it
    except FsError:
        raise
    except Exception as e:  # noqa: BLE001
        raise _internal(e) from e


def guard_gen(fn: Callable[..., Iterable[T]]) -> Callable[..., Iterator[T]]:
    """제너레이터 함수용 decorator."""

    @functools.wraps(fn)
    def wrapper(*args: Any, **kwargs: Any) -> Iterator[T]:
        try:
            inner = fn(*args, **kwargs)
        except FsError:
            raise
        except Exception as e:  # noqa: BLE001
            raise _internal(e) from e
        return guard_iter(inner)

    return wrapper


def ceil_div(a: int, b: int) -> int:
    return -(-a // b)


# ---------------------------------------------------------------------------
# 시각 (FAT / exFAT)
# ---------------------------------------------------------------------------

def _decode_date(date: int) -> tuple[int, int, int] | None:
    year = 1980 + ((date >> 9) & 0x7F)
    month = (date >> 5) & 0x0F
    day = date & 0x1F
    try:
        _dt.date(year, month, day)
    except ValueError:
        return None
    return year, month, day


def _decode_time(t: int) -> tuple[int, int, int] | None:
    hour = (t >> 11) & 0x1F
    minute = (t >> 5) & 0x3F
    sec = (t & 0x1F) * 2
    if hour > 23 or minute > 59 or sec > 58:
        return None
    return hour, minute, sec


def _iso(y: int, mo: int, d: int, h: int, mi: int, s: int, cs: int | None) -> str:
    text = f"{y:04d}-{mo:02d}-{d:02d}T{h:02d}:{mi:02d}:{s:02d}"
    if cs is not None:
        text += f".{cs:02d}"
    return text


def fat_timestamp(date: int, time_: int, tenth: int | None = None) -> dict[str, Any]:
    """FAT 날짜·시각(+ 생성 시각의 10ms 단위 0~199). 시간대는 모른다(local-unknown-tz).

    반환: {raw:{date,time[,tenth]}, iso: 'YYYY-MM-DDTHH:MM:SS[.cc]' 또는 None, valid, time_basis[, unset][, problem]}
    """
    raw: dict[str, Any] = {"date": date, "time": time_}
    if tenth is not None:
        raw["tenth"] = tenth
    out: dict[str, Any] = {"raw": raw, "iso": None, "valid": False, "time_basis": TIME_BASIS_LOCAL}
    if date == 0 and time_ == 0 and not tenth:
        out["unset"] = True
        return out
    d = _decode_date(date)
    t = _decode_time(time_)
    if d is None or t is None:
        out["problem"] = "invalid_date" if d is None else "invalid_time"
        return out
    h, mi, s = t
    cs = None
    if tenth is not None:
        if 0 <= tenth <= 199:
            s += tenth // 100
            cs = tenth % 100
        else:
            out["problem"] = "invalid_tenth"
            cs = None
    out["iso"] = _iso(*d, h, mi, s, cs)
    out["valid"] = "problem" not in out
    return out


def fat_date_only(date: int) -> dict[str, Any]:
    """FAT 마지막 접근 날짜 (시각 없음)."""
    out: dict[str, Any] = {"raw": {"date": date}, "iso": None, "valid": False, "time_basis": TIME_BASIS_LOCAL,
                           "date_only": True}
    if date == 0:
        out["unset"] = True
        return out
    d = _decode_date(date)
    if d is None:
        out["problem"] = "invalid_date"
        return out
    out["iso"] = f"{d[0]:04d}-{d[1]:02d}-{d[2]:02d}"
    out["valid"] = True
    return out


def exfat_timestamp(ts: int, ms10: int | None, utc_offset: int | None) -> dict[str, Any]:
    """exFAT 32비트 시각 + 10ms 증분(0~199, 접근 시각에는 없음) + UtcOffset(비트7 OffsetValid, 하위 7비트 = 15분 단위 부호 있는 값).

    OffsetValid 면 time_basis=local+offset 이고 utc('...Z')와 utc_offset_minutes 를 계산한다. 아니면 local-unknown-tz.
    """
    raw: dict[str, Any] = {"timestamp": ts}
    if ms10 is not None:
        raw["ms10"] = ms10
    if utc_offset is not None:
        raw["utc_offset"] = utc_offset
    out: dict[str, Any] = {"raw": raw, "iso": None, "valid": False, "time_basis": TIME_BASIS_LOCAL,
                           "utc": None, "utc_offset_minutes": None}
    offset_min = None
    if utc_offset is not None and utc_offset & 0x80:
        v = utc_offset & 0x7F
        if v & 0x40:
            v -= 0x80
        offset_min = v * 15
        out["time_basis"] = TIME_BASIS_OFFSET
        out["utc_offset_minutes"] = offset_min
        if not (-12 * 60 <= offset_min <= 14 * 60):
            out["offset_out_of_range"] = True
    if ts == 0 and not ms10:
        out["unset"] = True
        return out
    d = _decode_date((ts >> 16) & 0xFFFF)
    t = _decode_time(ts & 0xFFFF)
    if d is None or t is None:
        out["problem"] = "invalid_date" if d is None else "invalid_time"
        return out
    h, mi, s = t
    cs = None
    if ms10 is not None:
        if 0 <= ms10 <= 199:
            s += ms10 // 100
            cs = ms10 % 100
        else:
            out["problem"] = "invalid_ms10"
    out["iso"] = _iso(*d, h, mi, s, cs)
    out["valid"] = "problem" not in out
    if offset_min is not None:
        try:
            local = _dt.datetime(d[0], d[1], d[2], h, mi, s, (cs or 0) * 10_000)
            utc = local - _dt.timedelta(minutes=offset_min)
            out["utc"] = _iso(utc.year, utc.month, utc.day, utc.hour, utc.minute, utc.second,
                              (utc.microsecond // 10_000) if cs is not None else None) + "Z"
        except (ValueError, OverflowError):
            out["utc"] = None
    return out


# ---------------------------------------------------------------------------
# 이름
# ---------------------------------------------------------------------------

_ESCAPE_U = frozenset(list(range(0x202A, 0x202F)) + list(range(0x2066, 0x206A))
                      + [0x200E, 0x200F, 0x061C, 0x2028, 0x2029, 0xFEFF])
# display_name 이 바꾸는 글자 (아래 반복과 같은 집합) — 하나도 없으면 원래 문자열을 그대로 돌려준다
_ESCAPE_RX = re.compile("[\x00-\x1f\x7f-\x9f/\\\\؜‎‏  ‪-‮⁦-⁩﻿"
                        "\ud800-\udfff]")


def display_name(name: str, max_len: int = 1024) -> str:
    """사람·에이전트에게 보여 줄 이름: 제어 문자(C0/C1, DEL), 양방향 제어 문자, 대리 쌍 조각, '/', '\\' 를 이스케이프한다.

    이스케이프 결과는 원래 이름이 아니다(표시 전용). 원래 이름은 `name`, 원래 바이트는 `*_raw` 필드에 있다.
    바꿀 글자가 없고 max_len 이하면 name 객체를 그대로 돌려준다(walk 가 path 와 display_path 문자열을 함께 쓰게 — 메모리 절반).
    """
    if len(name) <= max_len and _ESCAPE_RX.search(name) is None:
        return name
    out: list[str] = []
    for ch in name[:max_len]:
        o = ord(ch)
        if o < 0x20 or 0x7F <= o <= 0x9F or ch == "/" or ch == "\\":
            out.append(f"\\x{o:02x}")
        elif o in _ESCAPE_U or 0xD800 <= o <= 0xDFFF:
            out.append(f"\\u{o:04x}")
        else:
            out.append(ch)
    if len(name) > max_len:
        out.append("…")
    return "".join(out)


def decode_utf16le(raw: bytes) -> tuple[str, bool]:
    """UTF-16LE 해석. 짝 없는 대리 코드 등으로 깨졌으면 U+FFFD 로 바꾸고 lossy=True."""
    try:
        return raw.decode("utf-16-le"), False
    except UnicodeDecodeError:
        return raw.decode("utf-16-le", errors="replace"), True


# ---------------------------------------------------------------------------
# 디렉터리 슬롯 읽기 (FAT·exFAT 공용)
# ---------------------------------------------------------------------------

def iter_dir_slots(src: Any, runs: Iterable[tuple[int, int]], max_slots: int,
                   w: Warnings) -> Iterator[tuple[int, int, bytes]]:
    """디렉터리 바이트 구간들을 32바이트 슬롯 (슬롯 번호, 볼륨 오프셋, 원시 32바이트) 로 차례로 돌려준다.

    이미지 끝을 넘으면 경고하고 멈춘다(잘린 이미지에서도 앞부분 목록은 나오게). max_slots 에서 멈춘다.
    """
    idx = 0
    for off, length in runs:
        pos = 0
        while pos < length:
            if off + pos >= src.size:
                w.add("dir_beyond_image", "디렉터리 데이터가 읽을 수 있는 범위(이미지 또는 파티션) 끝 너머에 있습니다 — 거기서 멈춥니다.")
                return
            n = min(64 * 1024, length - pos)
            data = src.read_clamped(off + pos, n)
            for i in range(0, len(data) - 31, 32):
                if idx >= max_slots:
                    w.add("dir_slot_limit", f"디렉터리 슬롯 한도({max_slots})에 닿았습니다.")
                    return
                yield idx, off + pos + i, data[i:i + 32]
                idx += 1
            if len(data) < n:
                w.add("dir_beyond_image", "디렉터리 데이터가 읽을 수 있는 범위(이미지 또는 파티션) 끝 너머에 있습니다 — 거기서 멈춥니다.")
                return
            pos += n


def iter_dir_units(src: Any, runs: Iterable[tuple[int, int]], unit: int, max_slots: int,
                   w: Warnings) -> Iterator[tuple[int, int, bytes]]:
    """디렉터리 바이트 구간들을 검사 단위(보통 클러스터)로 나눠 (첫 슬롯 번호, 볼륨 오프셋, 바이트) 로 돌려준다.

    단위는 각 구간 시작부터 unit 바이트씩 자른다(마지막 조각은 짧을 수 있음). 바이트 길이는 32 의 배수다.
    이미지 끝을 넘으면 경고하고 거기까지만, max_slots 에 닿으면 경고하고 멈춘다.
    """
    unit = max(32, int(unit) // 32 * 32)
    idx = 0
    for off, length in runs:
        pos = 0
        while pos < length:
            if idx >= max_slots:
                w.add("dir_slot_limit", f"디렉터리 슬롯 한도({max_slots})에 닿았습니다.")
                return
            if off + pos >= src.size:
                w.add("dir_beyond_image", "디렉터리 데이터가 읽을 수 있는 범위(이미지 또는 파티션) 끝 너머에 있습니다 — 거기서 멈춥니다.")
                return
            n = min(unit, length - pos, (max_slots - idx) * 32)
            data = src.read_clamped(off + pos, n)
            usable = len(data) // 32 * 32
            if usable:
                yield idx, off + pos, data[:usable] if usable < len(data) else data
                idx += usable // 32
            if len(data) < n:
                w.add("dir_beyond_image", "디렉터리 데이터가 읽을 수 있는 범위(이미지 또는 파티션) 끝 너머에 있습니다 — 거기서 멈춥니다.")
                return
            pos += n


# ---------------------------------------------------------------------------
# 내용 읽기 계획
# ---------------------------------------------------------------------------

class ContentPlan:
    """파일 내용(또는 삭제 파일 복구 후보)을 읽을 위치.

    클러스터 구간(run_start/run_len) 순서대로 이어 붙인 바이트 흐름에서 앞의 ``skip`` 바이트를 건너뛰고 ``size`` 바이트를 돌려준다.
    (exFAT residual 영역은 ValidDataLength 위치부터 시작하므로 skip 이 0 이 아닐 수 있다.)
    오프셋은 볼륨 기준이며 ``to_dict`` 는 이미지 기준 오프셋(image_offset)도 함께 적는다.
    """

    def __init__(self, *, ref: str, method: str, region: str, cluster_size: int, heap_offset: int,
                 base_offset: int, expected_size: int) -> None:
        self.ref = ref
        self.method = method
        self.region = region
        self.cluster_size = cluster_size
        self.heap_offset = heap_offset  # 클러스터 2 의 볼륨 기준 오프셋
        self.base_offset = base_offset  # 볼륨 시작의 이미지 기준 오프셋
        self.expected_size = expected_size  # 디렉터리 항목이 말하는 이 영역의 크기
        self.size = expected_size  # 돌려줄 바이트 수 (skip 뒤)
        self.skip = 0
        self.run_start = array("Q")
        self.run_len = array("Q")
        self.clusters = 0
        self.status = "ok"
        self.confidence = "high"
        self.note = ""
        self.conflicts: dict[str, int] = {}
        self.extra: dict[str, Any] = {}
        self.warnings = Warnings()

    # -- 구성 --
    def add_cluster(self, c: int) -> None:
        if self.run_len and self.run_start[-1] + self.run_len[-1] == c:
            self.run_len[-1] += 1
        else:
            self.run_start.append(c)
            self.run_len.append(1)
        self.clusters += 1

    def add_run(self, start: int, count: int) -> None:
        if count <= 0:
            return
        if self.run_len and self.run_start[-1] + self.run_len[-1] == start:
            self.run_len[-1] += count
        else:
            self.run_start.append(start)
            self.run_len.append(count)
        self.clusters += count

    @property
    def run_count(self) -> int:
        return len(self.run_start)

    def cluster_list(self, limit: int | None = None) -> list[int]:
        out: list[int] = []
        for s, n in zip(self.run_start, self.run_len):
            for c in range(s, s + n):
                if limit is not None and len(out) >= limit:
                    return out
                out.append(c)
        return out

    @property
    def available(self) -> int:
        """구간이 실제로 담을 수 있는 바이트 수 (skip 뒤, size 이하)."""
        return max(0, min(self.size, self.clusters * self.cluster_size - self.skip))

    @property
    def complete(self) -> bool:
        return self.available >= self.size

    def iter_extents(self) -> Iterator[tuple[int, int]]:
        """(볼륨 기준 오프셋, 길이) — skip 과 size 를 반영한 실제 읽기 구간."""
        remaining = self.available
        skip = self.skip
        cs = self.cluster_size
        for s, n in zip(self.run_start, self.run_len):
            if remaining <= 0:
                return
            run_bytes = n * cs
            if skip >= run_bytes:
                skip -= run_bytes
                continue
            off = self.heap_offset + (s - 2) * cs + skip
            length = min(run_bytes - skip, remaining)
            skip = 0
            remaining -= length
            yield off, length

    def to_dict(self, max_runs: int = 64) -> dict[str, Any]:
        runs = [[int(s), int(n)] for s, n in zip(self.run_start[:max_runs], self.run_len[:max_runs])]
        extents = []
        for i, (off, length) in enumerate(self.iter_extents()):
            if i >= max_runs:
                break
            extents.append({"offset": off, "image_offset": self.base_offset + off, "length": length})
        out: dict[str, Any] = {
            "ref": self.ref,
            "method": self.method,
            "region": self.region,
            "expected_size": self.expected_size,
            "size": self.size,
            "available": self.available,
            "complete": self.complete,
            "skip": self.skip,
            "clusters": self.clusters,
            "runs": runs,
            "runs_total": self.run_count,
            "runs_truncated": self.run_count > max_runs,
            "extents": extents,
            "status": self.status,
            "confidence": self.confidence,
            "note": self.note,
            "conflicts": dict(self.conflicts),
        }
        if self.extra:
            out.update(self.extra)
        out.update(self.warnings.export())
        return out
