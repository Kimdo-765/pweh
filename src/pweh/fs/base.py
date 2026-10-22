"""FAT·exFAT 볼륨 공통 동작: 참조(ref) 검사, 디렉터리 검증, 목록·전체 순회, 경로 찾기, 내용 계획·읽기.

하위 클래스(FatVolume, ExfatVolume)는 디렉터리 해석(_parse_dir), 검사 단위 검증(_unit_problem), dirspec 해석(_parse_spec/_spec_key),
삭제 디렉터리 검사(_deleted_dir_ok), 체인 요약(_chain_summary), 복구 후보(_candidate_plans·_method_names), 이름 접기(_fold·_name_keys)를
구현한다.

ref 형식: ``"<dirspec>/<slot>"`` — dirspec 은 디렉터리를 어떻게 읽는지(root / c<클러스터>[+<바이트>] = FAT 체인 /
n<클러스터>+<바이트> = 연속), slot 은 그 디렉터리 안에서 항목(FAT SFN, exFAT File 0x85/0x05)의 슬롯 번호다.

디렉터리 검증
- 디렉터리 데이터는 검사 단위(클러스터 — FAT12/16 고정 루트는 섹터)마다 모든 슬롯이 엄격한 검사(속성 조합·예약 비트·이름 바이트·
  LFN 구조·클러스터 범위·크기 범위, exFAT 항목 형식·집합 체크섬, FAT 하위 디렉터리의 '.'·'..', FAT12/16/32 이어지는 클러스터의 교차 연결)를
  통과해야 해석한다.
- 처음으로 통과하지 못한 단위에서 그 디렉터리를 멈춘다. 그 단위와 뒤에서는 이름·크기·시각·원시 이름 바이트를 하나도 내보내지 않는다.
  경고 ``dir_unvalidated`` 와 ``DirResult.unvalidated``(walk 는 ``unvalidated_dirs``)에 남겨 디렉터리를 조용히 버리지 않는다.
- 체인이 다른 파일 클러스터로 교차 연결되거나 디렉터리 항목이 녹화 클러스터를 가리켜도 녹화 바이트가 이름·크기·시각으로 새지 않게 한다.

한도와 잘림
- 디렉터리 하나가 슬롯 한도(min(Limits.max_dir_slots, 사양 최대))보다 길고 그 안에 끝 표시가 없으면 앞부분만 읽는다:
  ``DirResult.cut`` = {reason: 'max_dir_slots', slots_read, slots_total, boundary_slot}, 경고 ``dir_slot_limit``.
  잘린 자리에 걸친 항목 집합(exFAT)·LFN 조각(FAT)은 내보내지 않는다(부분 이름을 내지 않는다).
- 끝 표시 없이 읽기가 끝난 디렉터리는 뒤쪽 항목이 빠졌을 수 있다: ``DirResult.incomplete`` = 'beyond_image'(데이터가 이미지 끝
  너머 — 잘린 이미지) | 'dir_chain_broken'(클러스터 체인이 끝 표시 전에 비정상으로 끝남 — 손상). 끝 표시가 있었으면 체인이 그 뒤에서
  망가져도 빠진 것이 없다.
- 디렉터리별 사유(max_depth, max_dir_slots, 그리고 살아 있는 디렉터리의 beyond_image·dir_chain_broken·dir_unreadable)에 닿아도
  walk·reachable_dirspecs 는 나머지 나무를 계속 돈다. 결과는 truncated=True, truncated_reason = 전역 멈춤 사유(있으면) 아니면 처음
  디렉터리별 사유, truncated_reasons = 모든 사유, cut_dirs = [{dirspec, path, reason}] (최대 max_report_items 개, cut_dirs_total 은
  전체 수). 삭제된 디렉터리(와 그 아래)는 원래 최선 노력이라 손상·이미지 끝을 잘림으로 세지 않는다(경고만).
- 전역 멈춤 사유: 'time' | 'steps' | 'cancelled'(예산), 'max_entries', 'max_total_slots', 'max_path_chars'.

예산
- 공개 호출마다 Budget 하나를 쓴다(호출자가 ``budget=`` 으로 넘기거나, 없으면 limits.max_seconds 와 이 볼륨의 단계 상한
  ``step_cap(limits)`` 로 새로 만든다). 체인 따라가기·슬롯 읽기·비트맵 훑기가 단계를 센다. 취소 함수(cancel)도 같은 자리에서 확인한다.
- 다 되면 walk·reachable_dirspecs 는 ``truncated_reason='time'|'steps'|'cancelled'`` 로 멈추고, 항목 하나를 돌려줘야 하는 호출
  (entry·lookup·content_plan …)은 ``FsError(reason="budget_exceeded", data={"limit": …})`` 를 낸다. 예산 때문에 끝까지 못 읽은
  디렉터리는 캐시하지 않는다.
"""

from __future__ import annotations

import re
from collections import OrderedDict, deque
from typing import Any, Callable, Iterable, Iterator

from .common import (
    FOLLOW_STEPS_FLOOR,
    Budget,
    ContentPlan,
    FsError,
    Limits,
    Warnings,
    guard,
    guard_gen,
    iter_dir_units,
    limit_text,
)

__all__ = ["VolumeBase", "DirResult", "DirCtx"]

_REF_RE = re.compile(r"^([0-9a-z+]{1,40})/(\d{1,9})$")
#: 디렉터리를 끝 표시 전에 더 따라갈 수 없게 한 체인 상태(손상) — 끝 표시를 못 봤으면 뒤쪽 항목이 빠졌을 수 있다
_DIR_CHAIN_BROKEN = frozenset({"zeroed", "broken", "unreadable", "out-of-range", "cycle", "too_fragmented", "empty"})


class _NameIndex:
    """디렉터리 하나의 살아 있는 항목 이름 색인 (lookup 용): 정확한 이름 → 항목들, 접은 이름 → 항목들."""

    __slots__ = ("exact", "folded")

    def __init__(self) -> None:
        self.exact: dict[str, list[dict[str, Any]]] = {}
        self.folded: dict[str, list[dict[str, Any]]] = {}


class DirResult:
    """디렉터리 하나를 해석한 결과."""

    __slots__ = ("spec", "entries", "orphans", "label", "end_slot", "slots", "chain", "warnings", "extra",
                 "unvalidated", "budget_stop", "cut", "incomplete", "scanned", "_index", "_names")

    def __init__(self, spec: str, max_warnings: int = 50) -> None:
        self.spec = spec
        self.entries: list[dict[str, Any]] = []
        self.orphans: list[dict[str, Any]] = []
        self.label: str | None = None
        self.end_slot: int | None = None
        self.slots = 0
        self.chain: dict[str, Any] = {}
        self.warnings = Warnings(max_warnings)
        self.extra: dict[str, Any] = {}
        #: 검증에 실패한 단위 {"reason", "first_slot", "slots_skipped"} (없으면 None) — 그 슬롯부터는 해석하지 않았다
        self.unvalidated: dict[str, Any] | None = None
        #: 예산이 다 돼 끝까지 읽지 못했으면 'time' | 'steps' | 'cancelled' (이 결과는 캐시하지 않는다)
        self.budget_stop: str | None = None
        #: 슬롯 한도에서 잘렸으면 {"reason": "max_dir_slots", "slots_read", "slots_total"(모르면 None), "boundary_slot"}
        #: (해석 중에는 '잘릴 수 있음' 표시, 끝에 끝 표시·검증 실패·예산 멈춤이 없을 때만 남는다)
        self.cut: dict[str, Any] | None = None
        #: 끝 표시 없이 읽기가 끝났으면 'beyond_image'(이미지 끝) | 'dir_chain_broken'(체인 손상) — scanned 뒤쪽은 읽지 못했다
        self.incomplete: str | None = None
        #: 검증을 통과해 내보낸 단위가 덮은 슬롯 수 (잘림 판단용)
        self.scanned = 0
        self._index: dict[int, dict[str, Any]] | None = None
        self._names: _NameIndex | None = None

    def find(self, slot: int) -> dict[str, Any] | None:
        """slot 에서 시작하는 항목 (없으면 None)."""
        if self._index is None:
            self._index = {e["slot"]: e for e in self.entries}
        return self._index.get(slot)

    def cut_hit(self) -> bool:
        """슬롯 한도 자리까지 읽었는데 끝 표시가 없었다 (= 정말 잘렸다)."""
        return (self.cut is not None and self.end_slot is None and self.unvalidated is None and self.budget_stop is None
                and self.scanned >= int(self.cut["slots_read"]))


class DirCtx:
    """검증 문맥: 루트인지, 디렉터리의 첫 클러스터(FAT '.' 확인용), 지금 검사하는 단위의 볼륨 오프셋(off — 없으면 None)."""

    __slots__ = ("spec", "spec_t", "is_root", "own", "off")

    def __init__(self, spec: str, spec_t: tuple[Any, ...]) -> None:
        self.spec = spec
        self.spec_t = spec_t
        self.is_root = spec_t[0] == "root"
        self.own = None if self.is_root else spec_t[1]
        self.off: int | None = None


class _Cuts:
    """디렉터리별 한도로 잘린 디렉터리 기록 (walk·reachable_dirspecs)."""

    __slots__ = ("items", "total", "reasons", "_limit")

    def __init__(self, limit: int) -> None:
        self.items: list[dict[str, Any]] = []
        self.total = 0
        self.reasons: list[str] = []
        self._limit = max(0, int(limit))

    def add(self, dirspec: str, path: str, reason: str) -> None:
        self.total += 1
        if reason not in self.reasons:
            self.reasons.append(reason)
        if len(self.items) < self._limit:
            self.items.append({"dirspec": dirspec, "path": path, "reason": reason})


def _clamp_runs(runs: Iterable[tuple[int, int]], nbytes: int) -> list[tuple[int, int]]:
    out: list[tuple[int, int]] = []
    left = max(0, int(nbytes))
    for off, length in runs:
        if left <= 0:
            break
        take = min(max(0, int(length)), left)
        if take:
            out.append((off, take))
            left -= take
    return out


Peek = Callable[[int], list[bytes]]


class VolumeBase:
    """읽기 전용 볼륨 공통부."""

    kind = "?"
    max_slot = 1 << 24
    src: Any
    limits: Limits
    base_offset: int
    cluster_size: int
    heap_offset: int  # 클러스터 2 의 볼륨 기준 오프셋
    max_cluster: int
    cluster_count: int
    _fat: Any

    # -- 하위 클래스가 구현 --
    def _fs_name(self) -> str:  # pragma: no cover - 추상
        raise NotImplementedError

    def _parse_spec(self, spec: str) -> tuple[Any, ...]:  # pragma: no cover - 추상
        raise NotImplementedError

    def _parse_dir(self, spec: str, budget: Budget | None = None, *,
                   summaries: bool = True) -> DirResult:  # pragma: no cover - 추상
        """summaries=False: 디렉터리만 따라가는 순회용 — 삭제 항목 할당 요약(exFAT allocation_now) 같은 비싼 일을 하지 않는다(캐시하지 않음)."""
        raise NotImplementedError

    def _unit_problem(self, ctx: DirCtx, first: int, data: bytes, peek: Peek) -> tuple[str | None, int | None]:
        """검사 단위 하나의 문제(없으면 None)와 끝 표시(0x00) 슬롯의 단위 안 위치(없으면 None). ctx.off = 단위의 볼륨 오프셋."""
        raise NotImplementedError  # pragma: no cover - 추상

    def _spec_key(self, spec: str) -> Any:  # pragma: no cover - 추상
        raise NotImplementedError

    def _deleted_dir_ok(self, e: dict[str, Any], w: Warnings, path: str) -> bool:  # pragma: no cover - 추상
        raise NotImplementedError

    def _chain_summary(self, e: dict[str, Any], budget: Budget) -> dict[str, Any]:  # pragma: no cover - 추상
        raise NotImplementedError

    def _candidate_plans(self, e: dict[str, Any], region: str, budget: Budget, *, want: str | None = None,
                         skipped: set[str] | None = None) -> list[ContentPlan]:  # pragma: no cover
        """want: 그 방법의 후보만(그리고 그것이 기대는 것만) 만든다. skipped: 예산이 다 돼 만들지 못한 방법 이름을 넣는다."""
        raise NotImplementedError

    def _method_names(self, e: dict[str, Any], region: str) -> list[str]:  # pragma: no cover - 추상
        """이 항목에 쓸 수 있는 후보 방법 이름 (예산을 쓰지 않는 빠른 판단 — 오류 메시지용)."""
        raise NotImplementedError

    def _fold(self, s: str) -> str:  # pragma: no cover - 추상
        """대소문자 무시 비교용으로 접은 이름 (글자 수를 바꾸는 접기는 하지 않는다)."""
        raise NotImplementedError

    def _name_keys(self, e: dict[str, Any]) -> tuple[str, ...]:
        """대소문자 무시 비교에 쓰는 항목의 이름들 (기본: 이름, 표시 이름)."""
        return (e["name"], e["display_name"])

    def _check_dir(self, spec: str, key: Any, res: DirResult, w: Warnings, path: str) -> None:
        """디렉터리를 읽은 뒤 추가 검사. 기본은 없음."""

    # -- 단계 상한 --
    def _chain_clusters(self) -> int:
        """체인 따라가기가 볼 수 있는 클러스터 수: min(클러스터 수, 이미지 안에서 읽을 수 있는 FAT 항목 수)."""
        readable = int(getattr(self._fat, "readable", 0) or 0)
        return max(0, min(int(getattr(self, "cluster_count", 0) or 0), readable - 2))

    def step_cap(self, limits: Limits | None = None) -> int:
        """이 볼륨에서 공개 호출 하나(또는 볼륨 하나에 함께 쓰는 예산)의 작업 단계 상한.

        limits.max_follow_steps 가 정수면 그 값. None(기본)이면 max(FOLLOW_STEPS_FLOOR, 2 × N + limits.max_total_slots),
        N = _chain_clusters() (근거는 Limits 설명). 정상적으로 꽉 찬 볼륨은 닿지 않고, 조작 이미지는 이미지 크기에 비례해 멈춘다.
        """
        lim = limits or self.limits
        if lim.max_follow_steps is not None:
            return max(0, int(lim.max_follow_steps))
        return max(FOLLOW_STEPS_FLOOR, 2 * self._chain_clusters() + max(0, int(lim.max_total_slots)))

    # -- 공통 도우미 --
    def _budget(self, limits: Limits | None = None, budget: Budget | None = None) -> Budget:
        if budget is not None:
            return budget
        lim = limits or self.limits
        return Budget(lim.max_seconds, self.step_cap(lim))

    def _cache_put(self, cache: "OrderedDict[str, DirResult]", spec: str, res: DirResult, *,
                   summaries: bool = True) -> None:
        if res.budget_stop is not None or not summaries:
            return  # 예산 때문에 덜 읽었거나 요약을 뺀 결과는 다음 호출이 다시 읽게 한다
        cache[spec] = res
        if len(cache) > 16:
            cache.popitem(last=False)

    def _finish_dir(self, cache: "OrderedDict[str, DirResult]", spec: str, res: DirResult, budget: Budget, *,
                    summaries: bool = True, runs: list[tuple[int, int]] | None = None) -> DirResult:
        """디렉터리 해석 마무리: 예산 멈춤 표시, 슬롯 한도 잘림 확정(+ 경고), 끝까지 읽지 못함(incomplete) 판정, 캐시.

        runs: 이 디렉터리를 읽은 바이트 구간(볼륨 오프셋) — 이미지 끝 너머까지 이어지는지 본다."""
        if res.budget_stop is None and budget.expired():
            res.budget_stop = budget.reason  # 이 디렉터리를 읽는 동안 예산이 다 됨(할당 요약 등이 덜 됨) — 캐시하지 않는다
        if res.cut is not None:
            if res.cut_hit():
                c = res.cut
                c.setdefault("boundary_slot", c["slots_read"])
                res.chain["cut"] = c["reason"]  # 디렉터리 항목의 chain 요약에도 잘림을 남긴다
                total = c.get("slots_total")
                res.warnings.add("dir_slot_limit",
                                 f"디렉터리 {spec} 를 슬롯 한도({c['slots_read']})에서 잘랐습니다"
                                 + (f"(전체 {total} 슬롯)" if total else "") + " — 그 뒤 항목은 목록에 없습니다.",
                                 dirspec=spec, slots_read=c["slots_read"], slots_total=total)
            else:
                res.cut = None  # 한도 전에 끝 표시가 있었거나(빈 자리뿐) 검증 실패·예산 멈춤으로 먼저 멈췄다
        if res.cut is None and res.end_slot is None and res.unvalidated is None and res.budget_stop is None:
            # 끝 표시 없이 읽기가 끝났다: 이미지 끝에서 멈췄거나(잘린 이미지) 체인이 손상돼 더 따라갈 수 없었다 — 뒤쪽 항목이 빠졌을
            # 수 있다. 끝 표시가 있었으면(end_slot) 체인이 그 뒤에서 망가져도 빠진 것이 없다.
            # (exFAT 은 DataLength 가 디렉터리 크기다: 체인이 DataLength 를 다 덮었으면(covered) 끝 항목이 망가져도 빠진 것이 없다 —
            # 경고 dir_chain_* 만 남는다)
            if runs and any(off + n > self.src.size for off, n in runs):
                res.incomplete = "beyond_image"
            elif ((res.chain.get("status") in _DIR_CHAIN_BROKEN and not res.chain.get("covered"))
                  or res.chain.get("short")):
                res.incomplete = "dir_chain_broken"
            if res.incomplete is not None:
                res.chain["incomplete"] = res.incomplete  # 디렉터리 항목의 chain 요약에도 남긴다
        self._cache_put(cache, spec, res, summaries=summaries)
        return res

    def _validated_slots(self, res: DirResult, ctx: DirCtx, runs: list[tuple[int, int]], unit: int, max_slots: int,
                         budget: Budget) -> Iterator[tuple[int, int, bytes]]:
        """검증을 통과한 단위의 슬롯만 (슬롯 번호, 볼륨 오프셋, 원시 32바이트) 로 내보낸다.

        단위마다 예산을 세고(슬롯 수), 다 되면 res.budget_stop 을 남기고 멈춘다. 단위가 검증에 실패하면 res.unvalidated 를 남기고
        그 단위의 슬롯은 하나도 내보내지 않는다. 끝 표시(0x00) 슬롯까지 내보내고 멈춘다(그 뒤는 빈 자리라 검사하지 않는다).
        exFAT 집합 체크섬처럼 단위 경계를 넘는 검사는 peek 로 다음 단위의 슬롯을 미리 본다(그 단위는 차례가 되면 따로 검증한다).
        구간이 max_slots 보다 길면 거기까지만 읽고 res.cut 을 '잘릴 수 있음'으로 둔다(_finish_dir 가 확정한다).
        """
        total = sum(max(0, int(n)) for _, n in runs) // 32
        if total > max_slots:
            runs = _clamp_runs(runs, max_slots * 32)
            if res.cut is None:
                res.cut = {"reason": "max_dir_slots", "slots_read": max_slots, "slots_total": total}
            total = max_slots
        units = iter_dir_units(self.src, runs, unit, max_slots, res.warnings)
        ahead: deque[tuple[int, int, bytes]] = deque()
        done = False

        def more() -> bool:
            nonlocal done
            if done:
                return False
            try:
                ahead.append(next(units))
                return True
            except StopIteration:
                done = True
                return False

        def peek(n: int) -> list[bytes]:
            out: list[bytes] = []
            k = 0
            while len(out) < n:
                if k >= len(ahead) and not more():
                    break
                d = ahead[k][2]
                for j in range(0, len(d), 32):
                    out.append(d[j:j + 32])
                    if len(out) >= n:
                        break
                k += 1
            return out

        while True:
            if not ahead and not more():
                return
            first, off, data = ahead.popleft()
            nslots = len(data) // 32
            budget.tick(nslots)
            if budget.expired():
                res.budget_stop = budget.reason
                return
            ctx.off = off
            problem, end = self._unit_problem(ctx, first, data, peek)
            if problem is not None:
                res.unvalidated = {"reason": problem, "first_slot": first, "slots_skipped": max(0, total - first)}
                res.warnings.add("dir_unvalidated",
                                 f"디렉터리 {res.spec} 의 슬롯 {first} 부터는 디렉터리 데이터로 검증되지 않아 읽지 않았습니다"
                                 f"({problem}, {max(0, total - first)} 슬롯).",
                                 dirspec=res.spec, count=max(0, total - first), reason=problem, first_slot=first)
                return
            res.scanned = first + nslots
            stop = nslots if end is None else end + 1
            for i in range(stop):
                yield first + i, off + 32 * i, data[32 * i:32 * i + 32]
            if end is not None:
                return

    def _parse_ref(self, ref: str) -> tuple[str, int]:
        if not isinstance(ref, str):
            raise FsError("항목 참조가 문자열이 아닙니다.", reason="bad_ref")
        m = _REF_RE.match(ref)
        if not m:
            raise FsError(f"항목 참조 형식이 잘못됐습니다: {ref[:60]!r}", reason="bad_ref",
                          hint="'<dirspec>/<slot>' 형식 (예: root/3, c5/2, n9+4096/0)")
        spec, slot = m.group(1), int(m.group(2))
        self._parse_spec(spec)
        if slot >= self.max_slot:
            raise FsError("슬롯 번호가 범위를 벗어났습니다.", reason="bad_ref")
        return spec, slot

    def _resolve_dir(self, ref: str | None, budget: Budget) -> str:
        if ref is None or ref == "" or ref == "/":
            return "root"
        if not isinstance(ref, str):
            raise FsError("디렉터리 참조가 문자열이 아닙니다.", reason="bad_ref")
        if "/" in ref:
            e = self.entry(ref, budget=budget)
            if not e["is_dir"] or not e.get("child_dir"):
                raise FsError("디렉터리 항목이 아니거나 읽을 수 있는 클러스터가 없습니다.", reason="bad_ref")
            return str(e["child_dir"])
        self._parse_spec(ref)
        return ref

    def _new_plan(self, ref: str, method: str, size: int, region: str = "data") -> ContentPlan:
        p = ContentPlan(ref=ref, method=method, region=region, cluster_size=self.cluster_size,
                        heap_offset=self.heap_offset, base_offset=self.base_offset, expected_size=size)
        p.warnings.limit = self.limits.max_warnings
        return p

    def _finish(self, p: ContentPlan) -> ContentPlan:
        beyond = 0
        for off, length in p.iter_extents():
            if off + length > self.src.size:
                beyond += min(length, off + length - self.src.size)
        if beyond:
            p.extra["bytes_beyond_image"] = beyond
            p.warnings.add("beyond_image", f"내용 중 {beyond} 바이트가 이미지 끝 너머에 있어 읽을 수 없습니다.")
        return p

    def _chain_unchecked(self, e: dict[str, Any], reason: str | None) -> dict[str, Any]:
        """예산이 다 돼 체인을 따라가지 않은 항목의 체인 요약 (status 'limit', size_check 'unknown')."""
        cs = self.cluster_size or 1
        return {"status": "limit", "clusters": 0, "expected_clusters": -(-int(e.get("size") or 0) // cs),
                "size_check": "unknown", "limit_reason": reason}

    @staticmethod
    def _mark_capped(p: ContentPlan, reason: str | None, what: str) -> None:
        """예산 때문에 후보를 끝까지 만들지 못함 — status 'limit', limit_reason('time'|'steps'|'cancelled'), 신뢰도 low."""
        p.status = "limit"
        p.confidence = "low"
        p.extra["limit_reason"] = reason or "time"
        msg = f"{what}: {limit_text(reason)} 후보를 끝까지 만들지 못했습니다(부분 후보)."
        p.note = (p.note + " " if p.note else "") + msg
        p.warnings.add("budget_exceeded", msg)

    def _name_index(self, res: DirResult) -> _NameIndex:
        """res 의 살아 있는 항목 이름 색인 (처음 쓸 때 만들고 DirResult 에 둔다)."""
        idx = res._names
        if idx is None:
            idx = _NameIndex()
            for e in res.entries:
                if e["deleted"]:
                    continue
                for k in {e["name"], e["display_name"]}:
                    idx.exact.setdefault(k, []).append(e)
                for k in {self._fold(n) for n in self._name_keys(e) if n}:
                    idx.folded.setdefault(k, []).append(e)
            res._names = idx
        return idx

    def _match_name(self, res: DirResult, part: str, component: int, *, exact_only: bool = False) -> dict[str, Any] | None:
        """경로 구성요소 하나에 맞는 살아 있는 항목: 정확히 같은 이름(이름·표시 이름)이 먼저, 없으면 대소문자 무시(글자 수를 바꾸는
        접기 없이). 정확히 같은 것이 둘 이상이거나, 정확한 것 없이 대소문자 무시로 둘 이상이면 FsError(ambiguous_path).
        exact_only: 정확히 같은 이름만 받는다(끝까지 읽지 못한 디렉터리 — 정확한 이름이 읽지 못한 뒤쪽에 있을 수 있다)."""
        idx = self._name_index(res)
        exact = idx.exact.get(part)
        if exact:
            if len(exact) > 1:
                raise self._ambiguous(component, len(exact))
            return exact[0]
        if exact_only:
            return None
        cands = idx.folded.get(self._fold(part)) or []
        if len(cands) > 1:
            raise self._ambiguous(component, len(cands))
        return cands[0] if cands else None

    @staticmethod
    def _ambiguous(component: int, n: int) -> FsError:
        return FsError(f"경로의 {component}번째 이름에 맞는 항목이 {n}개라(대소문자만 다르거나 같은 이름) 하나로 정할 수 없습니다.",
                       reason="ambiguous_path", data={"component": component, "candidates": n},
                       hint="대소문자까지 정확한 이름을 쓰거나 forensics_fs_list 결과의 ref 로 고르세요.")

    # ------------------------------------------------------------------
    # 공개
    # ------------------------------------------------------------------
    @guard
    def list_dir(self, ref: str | None = None, *, include_deleted: bool = True, max_entries: int | None = None,
                 limits: Limits | None = None, budget: Budget | None = None) -> dict[str, Any]:
        """디렉터리 하나의 항목. ref: None(루트), 디렉터리 항목의 ref, 또는 dirspec.

        잘림: truncated, truncated_reason(예산 'time'|'steps'|'cancelled' > 'max_dir_slots' > 끝까지 읽지 못함 'beyond_image'|
        'dir_chain_broken' > 'max_list'), truncated_reasons(해당하는 것 모두), cut(슬롯 한도에서 잘렸으면 {reason, slots_read, slots_total,
        boundary_slot}, 아니면 None). 검증하지 못한 단위에서 멈췄으면 unvalidated 에 남는다(잘림 사유는 아니다).
        """
        budget = self._budget(limits, budget)
        spec = self._resolve_dir(ref, budget)
        res = self._parse_dir(spec, budget)
        cap = min(max_entries or self.limits.max_list, self.limits.max_list)
        entries = [dict(e) for e in res.entries if include_deleted or not e["deleted"]]
        reasons: list[str] = []
        if res.budget_stop is not None:
            reasons.append(res.budget_stop)
        if res.cut is not None:
            reasons.append(str(res.cut["reason"]))
        if res.incomplete is not None:
            reasons.append(res.incomplete)
        if len(entries) > cap:
            reasons.append("max_list")
        out: dict[str, Any] = {
            "fs": self._fs_name(),
            "dir": spec,
            "entries": entries[:cap],
            "entries_total": len(entries),
            "truncated": bool(reasons),
            "truncated_reason": reasons[0] if reasons else None,
            "truncated_reasons": reasons,
            "cut": dict(res.cut) if res.cut is not None else None,
            "orphans": [dict(o) for o in res.orphans],
            "volume_label": res.label,
            "end_slot": res.end_slot,
            "slots": res.slots,
            "chain": dict(res.chain),
            "unvalidated": dict(res.unvalidated) if res.unvalidated is not None else None,
        }
        out.update(res.extra.get("public", {}))
        out.update(res.warnings.export())
        return out

    @guard
    def entry(self, ref: str, *, limits: Limits | None = None, budget: Budget | None = None) -> dict[str, Any]:
        """ref 가 가리키는 항목을 디렉터리를 다시 읽어(검증 포함) 돌려준다. 항목 시작 슬롯이 아니면 FsError(bad_ref).

        항목이 없을 때 그 까닭은 data 로 알린다: 검증되지 않은 영역(unvalidated), 슬롯 한도에서 잘린 뒤쪽(dir_cut='max_dir_slots'),
        끝까지 읽지 못한 뒤쪽(dir_cut='beyond_image'|'dir_chain_broken'), 디렉터리를 읽지 못함(dir_cut='dir_unreadable')."""
        spec, slot = self._parse_ref(ref)
        budget = self._budget(limits, budget)
        try:
            res = self._parse_dir(spec, budget)
        except FsError as exc:
            if exc.reason in ("budget_exceeded", "bad_ref", "bad_argument"):
                raise
            # 디렉터리를 읽지 못했다(읽기 오류 등) — 잘린 디렉터리처럼 data.dir_cut 로 알린다(추출의 code dir_unreadable)
            raise FsError(f"{ref} 의 디렉터리를 읽지 못했습니다: {exc.message}", reason="bad_ref",
                          data={"dir_cut": "dir_unreadable", "cause": exc.reason}) from None
        e = res.find(slot)
        if e is not None:
            return dict(e)
        if res.budget_stop is not None:
            raise budget.error(f"{ref} 찾기")
        if res.unvalidated is not None and slot >= res.unvalidated["first_slot"]:
            raise FsError(f"{ref} 는 디렉터리 데이터로 검증되지 않은 영역을 가리킵니다.", reason="bad_ref",
                          data={"unvalidated": True, "dir_reason": res.unvalidated["reason"]})
        if res.cut is not None and slot >= int(res.cut.get("boundary_slot", res.cut["slots_read"])):
            raise FsError(f"{ref} 는 디렉터리 슬롯 한도({res.cut['slots_read']}) 밖(잘린 뒤쪽)을 가리킵니다.", reason="bad_ref",
                          data={"dir_cut": res.cut["reason"]})
        if res.incomplete is not None and slot >= res.scanned:
            raise FsError(f"{ref} 는 끝까지 읽지 못한 디렉터리(사유 {res.incomplete})의 읽지 못한 뒤쪽을 가리킵니다.", reason="bad_ref",
                          data={"dir_cut": res.incomplete})
        raise FsError(f"{ref} 위치에 파일/디렉터리 항목이 없습니다.", reason="bad_ref")

    def _merge_dir_warnings(self, w: Warnings, res: DirResult, path: str) -> None:
        """디렉터리 경고를 walk 경고에 합친다 (슬롯 한도 경고에는 디렉터리 표시 경로를 붙인다)."""
        for it in res.warnings.items:
            if it["code"] == "dir_slot_limit" and "path" not in it:
                it = dict(it)
                it["path"] = path
            w.add(**it)
        w.suppressed += res.warnings.suppressed

    @guard
    def walk(self, *, include_deleted: bool = True, max_entries: int | None = None, max_depth: int | None = None,
             check_chains: bool = True, limits: Limits | None = None, budget: Budget | None = None) -> dict[str, Any]:
        """볼륨 전체 목록 (깊이 우선, 한도·예산 있음). 각 항목에 path/display_path/depth/parent_ref/parent_deleted 를 더한다.

        limits 를 주면 순회 한도(max_entries·max_depth·max_total_slots·max_path_chars·max_seconds·max_follow_steps …)를 그것으로
        한다. 예산은 디렉터리마다·항목마다·체인 따라가기 안에서 확인한다.
        반환: entries, orphans, stats, truncated, truncated_reason, truncated_reasons, cut_dirs([{dirspec, path, reason}],
        최대 max_report_items 개), cut_dirs_total, unvalidated_dirs([{dirspec, path, reason, slots_skipped}]), unvalidated_dirs_total,
        unvalidated_dirs_live(그중 살아 있는 디렉터리 — 삭제된 디렉터리와 그 아래가 아닌 것), path_chars(max_path_chars 에 센 글자
        수), warnings, warnings_suppressed.
        디렉터리별 사유(max_depth — 그 디렉터리 항목은 싣지만 안으로 내려가지 않음, max_dir_slots — 앞부분만, 그리고 살아 있는
        디렉터리를 끝까지 읽지 못한 beyond_image·dir_chain_broken·dir_unreadable)에 닿아도 나머지 나무는 계속 돈다. 전역 한도(예산·
        max_entries·max_total_slots·max_path_chars)는 순회를 멈춘다. 검증하지 못한 디렉터리는 잘림 사유가 아니라 unvalidated_dirs 로
        남긴다.
        """
        lim = limits or self.limits
        max_entries = min(max_entries or lim.max_entries, lim.max_entries)
        max_depth = min(max_depth or lim.max_depth, lim.max_depth)
        max_chars = max(0, int(lim.max_path_chars))
        budget = self._budget(lim, budget)
        w = Warnings(lim.max_warnings)
        out: list[dict[str, Any]] = []
        orphans: list[dict[str, Any]] = []
        stats = {"files": 0, "dirs": 0, "deleted_files": 0, "deleted_dirs": 0, "orphans": 0, "dirs_read": 0}
        visited: set[Any] = set()
        stop: str | None = None  # 전역 멈춤 사유
        cuts = _Cuts(lim.max_report_items)
        stack: list[tuple[str, str, str, int, str | None, bool]] = [("root", "", "", 0, None, False)]
        total_slots = 0
        chars = 0
        dir_entries: dict[str, dict[str, Any]] = {}
        unvalidated: list[dict[str, Any]] = []
        unvalidated_total = 0
        unvalidated_live = 0
        while stack:
            spec, path, dpath, depth, parent_ref, pdel = stack.pop()
            if budget.expired():
                stop = budget.reason
                break
            if total_slots >= lim.max_total_slots:
                stop = "max_total_slots"
                break
            try:
                key = self._spec_key(spec)
            except FsError as e:
                w.add("dir_unreadable", f"디렉터리 지정이 잘못됐습니다: {e.message}", path=dpath or "/")
                if not pdel:
                    cuts.add(spec, dpath or "/", "dir_unreadable")
                continue
            if key in visited:
                w.add("dir_loop", "이미 읽은 디렉터리를 다시 가리킵니다(순환·교차 연결) — 건너뜁니다.", path=dpath or "/")
                continue
            visited.add(key)
            try:
                res = self._parse_dir(spec, budget)
            except FsError as e:
                w.add("dir_unreadable", f"디렉터리를 읽을 수 없습니다: {e.message}", path=dpath or "/")
                if not pdel and e.reason != "budget_exceeded":
                    cuts.add(spec, dpath or "/", "dir_unreadable")
                continue
            stats["dirs_read"] += 1
            total_slots += res.slots
            self._merge_dir_warnings(w, res, dpath or "/")
            owner = dir_entries.pop(spec, None)
            if owner is not None:
                owner["chain"] = dict(res.chain)
            self._check_dir(spec, key, res, w, path)
            if res.unvalidated is not None:
                unvalidated_total += 1
                if not pdel:
                    unvalidated_live += 1
                if len(unvalidated) < lim.max_report_items:
                    unvalidated.append({"dirspec": spec, "path": dpath or "/", "reason": res.unvalidated["reason"],
                                        "slots_skipped": res.unvalidated["slots_skipped"]})
            if res.cut is not None:
                cuts.add(spec, dpath or "/", str(res.cut["reason"]))
            if res.incomplete is not None and not pdel:
                cuts.add(spec, dpath or "/", res.incomplete)  # 살아 있는 디렉터리를 끝까지 읽지 못함(이미지 끝·체인 손상)
            for o in res.orphans:
                stats["orphans"] += 1
                if len(orphans) < lim.max_orphans:
                    oo = dict(o)
                    oo["parent_path"] = path or "/"
                    orphans.append(oo)
            children: list[tuple[str, str, str, int, str | None, bool]] = []
            for e in res.entries:
                if e["deleted"] and not include_deleted:
                    continue
                if len(out) >= max_entries:
                    stop = stop or "max_entries"
                    break
                if stop is None and budget.expired():
                    # 예산이 다 됨: 이미 해석(검증)한 이 디렉터리의 남은 항목은 비싼 일(체인 요약) 없이 싣고 더 내려가지 않는다
                    stop = budget.reason
                name = e["name"]
                dname = e["display_name"]
                shared = dpath is path and dname == name
                cost = len(path) + 1 + len(name) + (0 if shared else len(dpath) + 1 + len(dname))
                if chars + cost > max_chars:
                    stop = stop or "max_path_chars"
                    break
                chars += cost
                ee = dict(e)
                p = path + "/" + name
                ee["path"] = p
                ee["display_path"] = p if shared else dpath + "/" + dname
                ee["depth"] = depth + 1
                ee["parent_ref"] = parent_ref
                ee["parent_deleted"] = pdel
                if e["is_dir"]:
                    stats["deleted_dirs" if e["deleted"] else "dirs"] += 1
                else:
                    stats["deleted_files" if e["deleted"] else "files"] += 1
                    if check_chains and not e["deleted"]:
                        ee["chain"] = (self._chain_summary(e, budget) if stop is None
                                       else self._chain_unchecked(e, stop))
                out.append(ee)
                if stop is None and e["is_dir"] and e.get("child_dir"):
                    if e["deleted"] and not self._deleted_dir_ok(e, w, ee["display_path"]):
                        continue
                    if depth + 1 >= max_depth:
                        w.add("max_depth", f"디렉터리 깊이 한도({max_depth})에 닿았습니다 — 그 안은 목록에 없습니다.",
                              path=ee["display_path"])
                        cuts.add(str(e["child_dir"]), ee["display_path"], "max_depth")
                        continue
                    dir_entries[e["child_dir"]] = ee
                    children.append((e["child_dir"], ee["path"], ee["display_path"], depth + 1, e["ref"],
                                     pdel or e["deleted"]))
            if stop is None and res.budget_stop is not None:
                stop = res.budget_stop
            if stop is None and budget.expired():
                stop = budget.reason  # 마지막 항목의 체인 요약 안에서 예산이 다 됨
            if stop:
                break
            stack.extend(reversed(children))
        reasons = ([stop] if stop else []) + [r for r in cuts.reasons if r != stop]
        result: dict[str, Any] = {
            "fs": self._fs_name(),
            "entries": out,
            "orphans": orphans,
            "stats": stats,
            "truncated": bool(reasons),
            "truncated_reason": reasons[0] if reasons else None,
            "truncated_reasons": reasons,
            "cut_dirs": cuts.items,
            "cut_dirs_total": cuts.total,
            "unvalidated_dirs": unvalidated,
            "unvalidated_dirs_total": unvalidated_total,
            "unvalidated_dirs_live": unvalidated_live,
            "path_chars": chars,
        }
        result.update(w.export())
        return result

    @guard
    def reachable_dirspecs(self, limits: Limits | None = None, *, budget: Budget | None = None,
                           targets: Iterable[str] | None = None,
                           include_parent_deleted: bool = False) -> dict[str, Any]:
        """walk 가 내려가 목록을 내는 디렉터리(검증된 살아 있는·삭제된 디렉터리)의 dirspec 과 표시 경로 — 디렉터리만 순회한다.

        바깥에서 온 ref 를 받는 쪽(forensics_extract)이 ref 의 dirspec 이 여기 있는지 확인해, 임의의 클러스터를 디렉터리로 읽게 하는
        위조 ref 를 거부하게 한다. walk 와 같은 규칙(검증, 삭제 디렉터리 검사, 깊이·방문·슬롯 한도, 경로 글자 수, 예산·취소)이지만
        max_entries 로는 멈추지 않는다. dirspec 은 루트에서 검증된 디렉터리의 검증된 디렉터리 항목이 가리키는 순간 '찾음'이다(루트는
        처음부터) — 그 디렉터리를 아직 읽지 않았어도, 순회가 나중에 잘려도 그때까지 찾은 dirspec 은 검증된 것이다(그 dirspec 의 ref 는
        entry() 가 디렉터리를 다시 읽으며 단위마다 다시 검증한다).

        targets: dirspec 문자열들. 주면 그것들을 모두 찾는 즉시 멈춘다(예: {"root"} 는 아무것도 읽지 않고 끝난다).
        반환: {dirspecs: set[str], paths: {dirspec: 표시 경로 ('/' = 루트)}, status, truncated, truncated_reason, truncated_reasons,
        cut_dirs, cut_dirs_total, unvalidated_dirs, path_chars[, targets_found, targets_missing]}.
        status: 'complete'(닿을 수 있는 디렉터리를 다 돌았다 — 없는 dirspec 은 검증되지 않은 것), 'targets_found'(targets 를 다 찾아
        일찍 멈춤), 'truncated'(한도·예산·취소로 잘렸거나 살아 있는 디렉터리를 끝까지 읽지 못함(beyond_image·dir_chain_broken·
        dir_unreadable) — 없는 dirspec 은 확인할 수 없음, truncated_reason 이 사유).
        truncated 는 한도에 걸린 일이 있었는지다(targets_found 이어도 그 전에 디렉터리별 한도에 걸렸으면 True).
        include_parent_deleted: 이 순회에서 확인한 디렉터리의 삭제 문맥 map을 parent_deleted로 추가한다. 루트는 False,
        해당 디렉터리 또는 조상이 삭제됐으면 True다. 모순된 문맥을 관찰하면 루트 외 문맥은 보수적으로 None이다.
        이 map은 선택 경로의 문맥이며 targets_found를 전체 컨테이너 검사 완료로 바꾸지 않는다.
        """
        lim = limits or self.limits
        budget = self._budget(lim, budget)
        want = None if targets is None else {str(t) for t in targets}
        left = None if want is None else set(want)
        max_chars = max(0, int(lim.max_path_chars))
        dirspecs: set[str] = set()
        paths: dict[str, str] = {}
        unvalidated: list[dict[str, Any]] = []
        visited: set[Any] = set()
        stop: str | None = None
        cuts = _Cuts(lim.max_report_items)
        total_slots = 0
        chars = 0
        sink = Warnings(0)

        parent_deleted: dict[str, bool | None] = {}
        contexts: dict[Any, bool | None] = {}
        ambiguous_context = False

        def found(spec: str, path: str, pdel: bool) -> bool:
            """기존 도달 가능성 판정과 독립적으로 같은 순회의 삭제 문맥만 덧붙인다."""
            nonlocal ambiguous_context
            dirspecs.add(spec)
            paths.setdefault(spec, path)
            if include_parent_deleted:
                try:
                    key = self._spec_key(spec)
                except FsError:
                    parent_deleted[spec] = None
                else:
                    previous = contexts.get(key, pdel)
                    if previous is None or previous != pdel:
                        ambiguous_context = True
                        contexts[key] = None
                    else:
                        contexts[key] = pdel
                    parent_deleted[spec] = contexts[key]
            if left is not None:
                left.discard(spec)
                return not left
            return False

        early = found("root", "/", False)
        # (dirspec, 표시 경로, 깊이, 삭제된 디렉터리이거나 그 아래인지)
        stack: list[tuple[str, str, int, bool]] = [] if early else [("root", "", 0, False)]
        while stack and not early:
            spec, dpath, depth, pdel = stack.pop()
            if budget.expired():
                stop = budget.reason
                break
            if total_slots >= lim.max_total_slots:
                stop = "max_total_slots"
                break
            try:
                key = self._spec_key(spec)
            except FsError:
                if not pdel:
                    cuts.add(spec, dpath or "/", "dir_unreadable")
                continue
            if key in visited:
                continue
            visited.add(key)
            try:
                res = self._parse_dir(spec, budget, summaries=False)
            except FsError as e:
                if not pdel and e.reason != "budget_exceeded":
                    cuts.add(spec, dpath or "/", "dir_unreadable")
                continue
            total_slots += res.slots
            if res.unvalidated is not None and len(unvalidated) < lim.max_report_items:
                unvalidated.append({"dirspec": spec, "path": dpath or "/", "reason": res.unvalidated["reason"],
                                    "slots_skipped": res.unvalidated["slots_skipped"]})
            if res.cut is not None:
                cuts.add(spec, dpath or "/", str(res.cut["reason"]))
            if res.incomplete is not None and not pdel:
                cuts.add(spec, dpath or "/", res.incomplete)
            children: list[tuple[str, str, int, bool]] = []
            for e in res.entries:
                if not e["is_dir"] or not e.get("child_dir"):
                    continue
                if e["deleted"] and not self._deleted_dir_ok(e, sink, dpath):
                    continue
                dname = e["display_name"]
                if depth + 1 >= lim.max_depth:
                    cuts.add(str(e["child_dir"]), dpath + "/" + dname, "max_depth")
                    continue
                cost = len(dpath) + 1 + len(dname)
                if chars + cost > max_chars:
                    stop = "max_path_chars"
                    break
                chars += cost
                cpath = dpath + "/" + dname
                children.append((e["child_dir"], cpath, depth + 1, pdel or bool(e["deleted"])))
                if found(str(e["child_dir"]), cpath, pdel or bool(e["deleted"])):
                    early = True
                    if include_parent_deleted:
                        # 같은 이미 검증된 디렉터리 결과 안의 모순도 본다. 새 디렉터리를 열거나 ref를 추가하지 않는다.
                        for other in res.entries:
                            budget.tick()
                            if budget.expired():
                                ambiguous_context = True
                                break
                            if (other["is_dir"] and other.get("child_dir") == e["child_dir"]
                                    and (pdel or bool(other["deleted"])) != (pdel or bool(e["deleted"]))):
                                ambiguous_context = True
                    break
            if stop is None and res.budget_stop is not None and not early:
                stop = res.budget_stop
            if stop or early:
                break
            stack.extend(reversed(children))
        reasons = ([stop] if stop else []) + [r for r in cuts.reasons if r != stop]
        status = "targets_found" if early else ("truncated" if reasons else "complete")
        out: dict[str, Any] = {"dirspecs": dirspecs, "paths": paths, "status": status, "truncated": bool(reasons),
                               "truncated_reason": reasons[0] if reasons else None, "truncated_reasons": reasons,
                               "cut_dirs": cuts.items, "cut_dirs_total": cuts.total, "unvalidated_dirs": unvalidated,
                               "path_chars": chars}
        if include_parent_deleted:
            # 별도 디스크 순회 없이 이미 찾은 map만 보수화한다. 자식의 이전 관찰도 live로 남기지 않는다.
            if ambiguous_context:
                parent_deleted = {spec: None for spec in parent_deleted}
            parent_deleted["root"] = False
            out["parent_deleted"] = parent_deleted
        if want is not None:
            out["targets_found"] = sorted(want & dirspecs)
            out["targets_missing"] = sorted(want - dirspecs)
        return out

    @guard
    def lookup(self, path: str, *, limits: Limits | None = None, budget: Budget | None = None) -> dict[str, Any] | None:
        """살아 있는 항목을 경로로 찾는다. 검증된 디렉터리만 지난다.

        구성요소마다: 이름(또는 표시 이름)이 정확히 같은 항목이 먼저다. 없으면 대소문자를 무시해 비교한다 — 글자 하나가 글자
        하나로 바뀌는 대소문자 변환만 쓴다(ß→SS·ﬁ→FI 처럼 글자 수를 바꾸는 접기는 하지 않는다). FAT 은 8.3 짧은 이름도 비교하고,
        exFAT 은 볼륨의 up-case 표를 쓴다. 정확히 같은 것이 둘 이상이거나 정확한 것 없이 둘 이상이 맞으면 FsError(ambiguous_path).
        끝까지 읽지 못한 디렉터리(예산·슬롯 한도·이미지 끝·체인 손상·검증 실패)에서는 정확히 같은 이름(이름·표시 이름)만 받는다 —
        대소문자 무시·8.3 별칭으로만 맞으면 그 디렉터리의 사유로 FsError 를 낸다(정확한 이름이 읽지 못한 뒤쪽에 있을 수 있다).
        반환: 항목 + path(실제로 맞은 항목들의 원래 이름을 이은 것), display_path(표시 이름을 이은 것, 루트 아래는 '/이름'),
        depth, parent_ref, parent_deleted(False). 호출자가 쓴 철자(8.3 별칭·대소문자 변형)가 아니라 디스크의 이름이다.
        없으면 None (검증된 디렉터리를 끝까지 읽었는데 없음, 중간 구성요소가 디렉터리가 아님, 빈 경로).
        FsError: max_depth(경로가 Limits.max_depth 보다 깊음), max_dir_slots(슬롯 한도에서 잘린 디렉터리에서 찾지 못함 — 뒤쪽에 있을 수
        있다), beyond_image·dir_chain_broken(끝까지 읽지 못한 디렉터리에서 찾지 못함), dir_unvalidated(검증하지 못한 단위에서 멈춘
        디렉터리에서 찾지 못함), budget_exceeded(찾기 전에 예산이 다 됨), ambiguous_path.
        """
        if not isinstance(path, str):
            raise FsError("경로가 문자열이 아닙니다.", reason="bad_argument")
        lim = limits or self.limits
        parts = [p for p in path.split("/") if p]
        if len(parts) > lim.max_depth:
            raise FsError(f"경로가 디렉터리 깊이 한도({lim.max_depth})보다 깊습니다({len(parts)} 단계) — 목록(walk)도 그 아래로는 "
                          "내려가지 않습니다.", reason="max_depth",
                          data={"limit": "max_depth", "max_depth": lim.max_depth, "depth": len(parts)})
        if not parts:
            return None
        budget = self._budget(lim, budget)
        spec = "root"
        found: dict[str, Any] | None = None
        names: list[str] = []
        dnames: list[str] = []
        parent_ref: str | None = None
        for i, part in enumerate(parts):
            try:
                res = self._parse_dir(spec, budget)
            except FsError as e:
                if e.reason == "budget_exceeded":
                    raise
                # 경로의 디렉터리를 읽지 못했다(읽기 오류·잘못된 지정) — 목록의 dir_unreadable 과 같은 사유로 낸다
                raise FsError(f"경로의 {i + 1}번째 디렉터리를 읽지 못했습니다: {e.message}", reason="dir_unreadable",
                              data={"limit": "dir_unreadable", "component": i + 1, "cause": e.reason}) from None
            # 끝까지 읽지 못한 디렉터리(예산·슬롯 한도·이미지 끝·체인 손상·검증 실패)에서는 정확히 같은 이름만 믿는다 — 대소문자만 맞는
            # 항목(8.3 별칭 포함)을 고르면, 정확히 같은 이름의 다른 파일이 읽지 못한 뒤쪽에 있을 때 엉뚱한 파일을 내게 된다
            degraded = (res.budget_stop is not None or res.cut is not None or res.incomplete is not None
                        or res.unvalidated is not None)
            found = self._match_name(res, part, i + 1, exact_only=degraded)
            if found is None:
                folded = False
                if degraded:
                    try:
                        folded = self._match_name(res, part, i + 1) is not None
                    except FsError:
                        folded = True  # 대소문자만 맞는 항목이 여럿 — 그래도 고르지 않는다
                why = (" 대소문자만 맞는 항목은 있지만 정확히 같은 이름이 뒤쪽에 있을 수 있어 고르지 않습니다 — 디스크의 이름 그대로(대소문자"
                       "까지) 쓰거나 ref 로 고르세요." if folded else "")
                if res.budget_stop is not None:
                    raise budget.error("경로 찾기")
                if res.cut is not None:
                    raise FsError(f"경로의 {i + 1}번째 디렉터리가 슬롯 한도({res.cut['slots_read']})에서 잘려 이 이름이 뒤쪽에 "
                                  "있는지 알 수 없습니다." + why, reason="max_dir_slots",
                                  data={"limit": "max_dir_slots", "component": i + 1})
                if res.incomplete is not None:
                    raise FsError(f"경로의 {i + 1}번째 디렉터리를 끝까지 읽지 못해(사유 {res.incomplete}) 이 이름이 뒤쪽에 있는지 알 수 "
                                  "없습니다." + why, reason=res.incomplete, data={"limit": res.incomplete, "component": i + 1})
                if res.unvalidated is not None:
                    raise FsError(f"경로의 {i + 1}번째 디렉터리가 검증하지 못한 단위에서 멈춰 이 이름이 뒤쪽에 있는지 알 수 없습니다." + why,
                                  reason="dir_unvalidated", data={"limit": "dir_unvalidated", "component": i + 1})
                return None
            names.append(found["name"])
            dnames.append(found["display_name"])
            if i < len(parts) - 1:
                if not found["is_dir"] or not found.get("child_dir"):
                    return None
                parent_ref = found["ref"]
                spec = found["child_dir"]
        if found is None:
            return None
        out = dict(found)
        out["path"] = "/" + "/".join(names)
        out["display_path"] = "/" + "/".join(dnames)
        out["depth"] = len(parts)
        out["parent_ref"] = parent_ref
        out["parent_deleted"] = False
        return out

    @guard
    def candidates(self, ref: str, region: str = "data", *, limits: Limits | None = None,
                   budget: Budget | None = None) -> list[dict[str, Any]]:
        """복구 후보(삭제 항목) 또는 할당 내용(살아 있는 항목) 계획 목록. 앞쪽이 더 믿을 만하다. 호출자의 한도·예산 안에서 만든다.

        예산이 중간에 다 되면 비싼 후보는 빠질 수 있다(만들다 멈춘 후보는 status 'limit' + limit_reason).
        """
        budget = self._budget(limits, budget)
        e = self.entry(ref, budget=budget)
        if budget.expired():
            raise budget.error("복구 후보 계산")
        return [p.to_dict() for p in self._candidate_plans(e, region, budget)]

    @guard
    def content_plan(self, ref: str, method: str = "auto", region: str = "data", *, limits: Limits | None = None,
                     budget: Budget | None = None) -> ContentPlan:
        """내용을 읽을 계획. method='auto' 는 가장 믿을 만한 후보. 호출자의 한도(limits)나 예산(budget) 안에서 만든다.

        method 를 고르면 그 후보(와 그것이 기대는 것)만 만든다 — 다른 후보가 예산을 먼저 쓰지 않는다. 그 후보를 예산(시간·단계·취소)
        때문에 만들지 못했거나 클러스터를 하나도 모으지 못했으면 FsError(budget_exceeded, data.limit), 이 항목에 없는 방법이면
        FsError(bad_argument, data.available). 만들다 예산이 다 된 계획(클러스터가 있음)은 status 'limit' 와 extra['limit_reason']
        ('time' | 'steps' | 'cancelled')를 달고 돌려준다. method='auto' 는 클러스터를 하나도 모으지 못한 'limit' 후보를 건너뛰고,
        모두 그렇다면 budget_exceeded.
        """
        if region not in ("data", "residual"):
            raise FsError("region 은 'data' 또는 'residual' 입니다.", reason="bad_argument")
        budget = self._budget(limits, budget)
        e = self.entry(ref, budget=budget)
        if budget.expired():
            raise budget.error("내용 계획")
        if method == "auto":
            plans = self._candidate_plans(e, region, budget)
            for p in plans:  # 예산 때문에 클러스터를 하나도 모으지 못한 후보는 건너뛰고 다음으로 믿을 만한 것
                if not (p.status == "limit" and p.clusters == 0 and p.size > 0):
                    return p
            return self._usable(plans[0], budget)
        skipped: set[str] = set()
        plans = self._candidate_plans(e, region, budget, want=method, skipped=skipped)
        for p in plans:
            if p.method == method:
                return self._usable(p, budget)
        if method in skipped:
            raise budget.error(f"'{method}' 후보 계산")
        avail = self._method_names(e, region)
        raise FsError(f"이 항목에는 '{method}' 방법이 없습니다(가능: {', '.join(avail)}).", reason="bad_argument",
                      data={"available": avail})

    @staticmethod
    def _usable(p: ContentPlan, budget: Budget) -> ContentPlan:
        """예산 때문에 클러스터를 하나도 모으지 못한 계획(status 'limit', 0 클러스터)은 돌려주지 않고 budget_exceeded 를 낸다."""
        if p.status == "limit" and p.clusters == 0 and p.size > 0:
            reason = p.extra.get("limit_reason") or budget.reason or "time"
            raise FsError(f"내용 계획: {limit_text(reason)} '{p.method}' 후보를 만들지 못했습니다.", reason="budget_exceeded",
                          data={"limit": reason},
                          hint=("작업이 취소됐습니다." if reason == "cancelled"
                                else "max_seconds 를 늘리거나 범위를 줄여 다시 시도하세요(손상·조작된 이미지일 수 있음)."))
        return p

    @guard_gen
    def iter_plan(self, plan: ContentPlan, *, max_bytes: int | None = None,
                  chunk_size: int = 1 << 20) -> Iterator[bytes]:
        """계획대로 바이트를 조각으로 돌려준다 (max_bytes 상한, 이미지 끝에서 멈춤)."""
        if not isinstance(plan, ContentPlan) or plan.cluster_size != self.cluster_size \
                or plan.heap_offset != self.heap_offset:
            raise FsError("이 볼륨의 계획이 아닙니다.", reason="bad_argument")
        chunk_size = max(4096, min(int(chunk_size), 16 << 20))
        remaining = plan.available if max_bytes is None else max(0, min(plan.available, int(max_bytes)))
        for off, length in plan.iter_extents():
            while length > 0 and remaining > 0:
                n = min(length, remaining, chunk_size)
                data = self.src.read_clamped(off, n)
                if data:
                    yield data
                if len(data) < n:
                    return
                off += n
                length -= n
                remaining -= n
            if remaining <= 0:
                return

    @guard_gen
    def iter_content(self, ref: str, method: str = "auto", region: str = "data", *,
                     max_bytes: int | None = None, limits: Limits | None = None,
                     budget: Budget | None = None) -> Iterator[bytes]:
        """content_plan(한도·예산 적용) + iter_plan (읽기는 max_bytes 로 묶인다)."""
        plan = self.content_plan(ref, method, region, limits=limits, budget=budget)
        yield from self.iter_plan(plan, max_bytes=max_bytes)

    @guard
    def read_content(self, ref: str, method: str = "auto", region: str = "data", *,
                     max_bytes: int | None = None, limits: Limits | None = None,
                     budget: Budget | None = None) -> dict[str, Any]:
        """내용을 메모리로 읽는다(작은 파일용, limits.max_read_bytes 상한). 반환: {data, bytes, truncated, plan}."""
        plan = self.content_plan(ref, method, region, limits=limits, budget=budget)
        cap = self.limits.max_read_bytes if max_bytes is None else max(0, min(int(max_bytes), self.limits.max_read_bytes))
        data = b"".join(self.iter_plan(plan, max_bytes=cap))
        return {"data": data, "bytes": len(data), "truncated": len(data) < plan.size, "plan": plan.to_dict()}
