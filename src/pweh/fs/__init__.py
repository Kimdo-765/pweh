"""pweh.fs — 카드 이미지용 순수 파이썬 파일 시스템 엔진 (읽기 전용, 깨끗한 재구현).

하드웨어 쓰기 방지 장치로 사람이 만든 SD 카드 이미지를 오프라인으로 해석한다(설계: docs/design/sd-forensics.md §4).
공개 형식 사양(Microsoft FAT32/exFAT 사양, UEFI GPT, 고전 MBR/EBR)만 바탕으로 새로 작성했다. GPL/AGPL 구현의 코드를
옮기지 않았다. 이미지에 쓰지 않고, 마운트하지 않고, 외부 도구를 부르지 않는다. 파일을 만들지 않는다(추출은 서버의 몫).

사용 예::

    from pweh.fs import ImageReader, detect_partitions, partition_source, open_volume

    with ImageReader("card.img") as img:
        layout = detect_partitions(img)
        part = layout["partitions"][0]
        vol = open_volume(partition_source(img, part))
        listing = vol.walk()                      # 삭제 항목 포함 전체 목록
        ref = listing["entries"][0]["ref"]        # "<dirspec>/<slot>"
        cands = vol.candidates(ref)               # 삭제 파일 복구 후보 (신뢰도·설명 포함)
        for chunk in vol.iter_content(ref, max_bytes=1 << 20):
            ...

신뢰할 수 없는 이미지를 다루므로 모든 반복은 `Limits` 로 묶이고, 공개 호출 하나는 `Budget`(시간 마감·작업 단계 상한·취소 함수) 안에서
끝난다. 단계 상한은 볼륨마다 정한다(`VolumeBase.step_cap` — 정상적으로 꽉 찬 볼륨은 닿지 않는다). 볼륨 하나에 예산 하나를 함께 쓰려면::

    budget = Budget.for_limits(lim, cancel=ev.is_set, deadline=call_deadline)
    vol = open_volume(src, limits=lim, budget=budget)   # 이 볼륨의 단계 상한까지 budget.max_steps 를 올린다
    info = vol.info(budget=budget)
    listing = vol.walk(limits=lim, budget=budget)

손상은 경고(warnings) 또는 `FsError` 로만 드러난다. 디렉터리 데이터는 클러스터마다 검증한 뒤에만 해석한다(base.py) — 검증되지 않은
클러스터의 바이트는 이름·크기·시각으로 내보내지 않는다. 시각은 원래 값 + ``time_basis``(local-unknown-tz / local+offset) — 장치
시간대는 가정하지 않는다.
"""

from __future__ import annotations

from typing import Any

from .common import FOLLOW_STEPS_FLOOR, Budget, ContentPlan, FsError, Limits, display_name, guard
from .exfat import ExfatVolume
from .fat import FatVolume
from .reader import BytesReader, ImageReader, SliceReader, open_image
from .volume import GPT_TYPES, MBR_TYPES, detect_partitions, partition_source, sniff_fs

__all__ = [
    "FsError",
    "Limits",
    "Budget",
    "ContentPlan",
    "ImageReader",
    "BytesReader",
    "SliceReader",
    "open_image",
    "detect_partitions",
    "sniff_fs",
    "partition_source",
    "FatVolume",
    "ExfatVolume",
    "open_volume",
    "analyze_image",
    "display_name",
    "MBR_TYPES",
    "GPT_TYPES",
    "SUPPORTED_FS",
    "FOLLOW_STEPS_FLOOR",
]

SUPPORTED_FS = ("fat12", "fat16", "fat32", "exfat")


@guard
def open_volume(src: Any, *, limits: Limits | None = None, fs_hint: str | None = None,
                budget: Budget | None = None) -> FatVolume | ExfatVolume:
    """구간(이미지 전체 또는 partition_source)의 파일 시스템을 연다. FAT12/16/32·exFAT 가 아니면 FsError(unsupported_fs).

    budget: 이 볼륨에 함께 쓸 예산. 부트 섹터를 읽은 뒤 budget.max_steps 를 이 볼륨의 단계 상한 vol.step_cap(limits) 까지 올린다
    (내리지 않는다 — 볼륨마다 새 Budget 을 만들어 넘긴다). exFAT 은 열 때 루트 디렉터리를 읽는다(비트맵·up-case·레이블) — 그 일을
    이 예산 안에서 한다(없으면 limits.max_seconds 와 step_cap 으로 새로 만든다). 같은 예산을 info·walk 에 넘기면 시간 마감·단계·취소를
    함께 쓴다.
    """
    hint = fs_hint or sniff_fs(src)
    if hint in ("fat12", "fat16", "fat32"):
        return FatVolume(src, limits=limits, budget=budget)
    if hint in ("exfat", "exfat-invalid"):
        return ExfatVolume(src, limits=limits, budget=budget)
    raise FsError(f"지원하지 않는 파일 시스템입니다: {hint}", reason="unsupported_fs", data={"fs_hint": hint},
                  hint="지원: FAT12/16/32, exFAT (ext4·NTFS 는 아직 없음)")


@guard
def analyze_image(src: Any, *, limits: Limits | None = None, budget: Budget | None = None) -> dict[str, Any]:
    """파티션 구조 + 지원하는 파티션마다 볼륨 정보(info). src 는 Source 또는 경로. 목록·복구는 하지 않는다(빠름).

    호출 전체가 예산 하나(``Budget.for_limits(lim)`` — 시간은 limits.max_seconds, 단계 상한은 limits.max_follow_steps 가 정수면 그 값이고
    None(기본)이면 FOLLOW_STEPS_FLOOR 에서 시작한다) 안에서 끝난다. 볼륨을 열 때마다 open_volume 이 그 예산의 단계 상한을 그 볼륨의
    상한(vol.step_cap(lim))까지 올리고 내리지 않는다 — 단계는 연 볼륨들에 걸쳐 쌓이고 상한은 그 볼륨들 상한의 최댓값이 된다. 시작·크기가 같은 파티션은 한 번만 연다
    (뒤의 것은 volumes 항목에 duplicate_of: <앞 파티션 index> 만 둔다). 서로 다른 구간은 limits.max_partitions 개까지만 연다.
    열지 않은 지원 파티션(상한·예산)은 volumes 항목에 omitted: 'partitions' | 'time' | 'steps' 를 두고 partitions_omitted 로 센다.
    반환에 partitions_omitted(int), truncated(bool), truncated_reason('time' | 'partitions' | 'steps' | None)를 더한다
    (info 가 예산 때문에 루트를 끝까지 못 읽은 경우도 truncated 로 본다).
    """
    own = False
    if isinstance(src, (str, bytes)) or hasattr(src, "__fspath__"):
        src = ImageReader(src)  # type: ignore[arg-type]
        own = True
    try:
        lim = limits or Limits()
        budget = budget or Budget.for_limits(lim)
        layout = detect_partitions(src, limits=lim)
        vols = []
        seen: dict[tuple[int, int], Any] = {}
        opened = 0
        omitted = 0
        reason: str | None = None
        for part in layout["partitions"]:
            item: dict[str, Any] = {"index": part["index"], "fs_hint": part["fs_hint"]}
            if not (part["fs_hint"] in SUPPORTED_FS or part["fs_hint"] == "exfat-invalid"):
                item["error"] = {"code": "validation_failed", "message": "지원하지 않는 파일 시스템",
                                 "data": {"reason": "unsupported_fs"}}
                vols.append(item)
                continue
            key = (int(part["start_offset"]), int(part["size_bytes"]))
            if key in seen:
                item["duplicate_of"] = seen[key]
                vols.append(item)
                continue
            why = None
            if budget.expired():
                why = budget.reason
            elif opened >= lim.max_partitions:
                why = "partitions"
            if why is not None:
                item["omitted"] = why
                omitted += 1
                reason = reason or why
                vols.append(item)
                continue
            seen[key] = part["index"]
            opened += 1
            try:
                vol = open_volume(partition_source(src, part), limits=lim, fs_hint=part["fs_hint"], budget=budget)
                item["info"] = vol.info(budget=budget)
            except FsError as e:
                item["error"] = e.to_dict()
            vols.append(item)
        if reason is None and budget.expired():
            reason = budget.reason  # 마지막으로 연 볼륨의 info 가 예산 때문에 덜 읽혔다
        layout["volumes"] = vols
        layout["partitions_omitted"] = omitted
        layout["truncated"] = reason is not None
        layout["truncated_reason"] = reason
        return layout
    finally:
        if own:
            src.close()
